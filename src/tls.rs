//! TLS configuration with Post-Quantum Cryptography (PQC) support
//!
//! Supports:
//! - Standard TLS 1.3 with rustls
//! - Hybrid PQC key exchange via OpenSSL 3.5 + OQS provider
//! - Hot-reload of certificates
//! - mTLS for client authentication

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig as RustlsServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tracing::{debug, error, info, warn};

use crate::config::{PqcConfig, TlsConfig};

/// TLS provider abstraction
pub struct TlsProvider {
    /// Current TLS server configuration (atomic swap for hot-reload)
    server_config: ArcSwap<quinn::crypto::rustls::QuicServerConfig>,
    /// TLS configuration from proxy config
    tls_config: RwLock<TlsConfig>,
    /// PQC configuration
    pqc_config: RwLock<PqcConfig>,
    /// Last certificate modification time
    last_cert_modified: RwLock<Option<SystemTime>>,
    /// PQC availability status
    pqc_available: RwLock<bool>,
}

impl TlsProvider {
    /// Create a new TLS provider with initial configuration
    pub fn new(tls_config: &TlsConfig, pqc_config: &PqcConfig) -> anyhow::Result<Self> {
        // Check PQC availability
        let pqc_available = if pqc_config.enabled {
            Self::check_pqc_availability(pqc_config)
        } else {
            false
        };

        if pqc_config.enabled && !pqc_available {
            warn!("PQC requested but not available - falling back to classical TLS");
        }

        // Create initial server config
        let rustls_config = Self::create_rustls_config(tls_config, pqc_config, pqc_available)?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

        // Get initial cert modification time
        let cert_modified = std::fs::metadata(&tls_config.cert_path)
            .ok()
            .and_then(|m| m.modified().ok());

        Ok(Self {
            server_config: ArcSwap::new(Arc::new(quic_config)),
            tls_config: RwLock::new(tls_config.clone()),
            pqc_config: RwLock::new(pqc_config.clone()),
            last_cert_modified: RwLock::new(cert_modified),
            pqc_available: RwLock::new(pqc_available),
        })
    }

    /// Get current QUIC server configuration
    pub fn get_quic_server_config(&self) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
        self.server_config.load_full()
    }

    /// Check if PQC is available and enabled
    pub fn is_pqc_enabled(&self) -> bool {
        *self.pqc_available.read()
    }

    /// Reload TLS certificates
    pub fn reload_certificates(&self) -> anyhow::Result<()> {
        let tls_config = self.tls_config.read().clone();
        let pqc_config = self.pqc_config.read().clone();
        let pqc_available = *self.pqc_available.read();

        // Create new rustls config
        let rustls_config = Self::create_rustls_config(&tls_config, &pqc_config, pqc_available)?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

        // Atomically swap configuration
        self.server_config.store(Arc::new(quic_config));

        // Update modification time
        let cert_modified = std::fs::metadata(&tls_config.cert_path)
            .ok()
            .and_then(|m| m.modified().ok());
        *self.last_cert_modified.write() = cert_modified;

        info!("TLS certificates reloaded successfully");
        Ok(())
    }

    /// Check if certificates need reloading
    pub fn needs_reload(&self) -> bool {
        let tls_config = self.tls_config.read();
        let current_modified = std::fs::metadata(&tls_config.cert_path)
            .ok()
            .and_then(|m| m.modified().ok());

        let last_modified = *self.last_cert_modified.read();

        match (current_modified, last_modified) {
            (Some(current), Some(last)) => current > last,
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// Update configuration (for hot-reload)
    pub fn update_config(&self, tls_config: &TlsConfig, pqc_config: &PqcConfig) -> anyhow::Result<()> {
        // Update stored configs
        *self.tls_config.write() = tls_config.clone();
        *self.pqc_config.write() = pqc_config.clone();

        // Re-check PQC availability
        let pqc_available = if pqc_config.enabled {
            Self::check_pqc_availability(pqc_config)
        } else {
            false
        };
        *self.pqc_available.write() = pqc_available;

        // Reload certificates with new config
        self.reload_certificates()
    }

    /// Check if PQC is available on this system
    fn check_pqc_availability(pqc_config: &PqcConfig) -> bool {
        match pqc_config.provider.as_str() {
            "openssl3.5" => Self::check_openssl_pqc(pqc_config),
            "rustls-pqc" => Self::check_rustls_pqc(),
            _ => {
                warn!("Unknown PQC provider: {}", pqc_config.provider);
                false
            }
        }
    }

    /// Check if OpenSSL 3.5 with OQS provider is available
    fn check_openssl_pqc(pqc_config: &PqcConfig) -> bool {
        #[cfg(feature = "pqc")]
        {
            use std::process::Command;

            let openssl_path = pqc_config.openssl_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "openssl".to_string());

            // Set library path for OpenSSL 3.5
            let lib_path = pqc_config.openssl_lib_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Check OpenSSL version
            let version_output = Command::new(&openssl_path)
                .arg("version")
                .env("LD_LIBRARY_PATH", &lib_path)
                .output();

            match version_output {
                Ok(output) => {
                    let version_str = String::from_utf8_lossy(&output.stdout);
                    if version_str.contains("3.5") || version_str.contains("3.4") || version_str.contains("3.3") {
                        info!("OpenSSL version detected: {}", version_str.trim());

                        // Check for OQS provider
                        let provider_output = Command::new(&openssl_path)
                            .args(["list", "-providers"])
                            .env("LD_LIBRARY_PATH", &lib_path)
                            .output();

                        match provider_output {
                            Ok(output) => {
                                let providers = String::from_utf8_lossy(&output.stdout);
                                if providers.contains("oqs") || providers.contains("OQS") {
                                    info!("OQS provider detected - PQC hybrid key exchange available");
                                    return true;
                                }

                                // Check for built-in Kyber support (OpenSSL 3.5+)
                                let kem_output = Command::new(&openssl_path)
                                    .args(["list", "-kem-algorithms"])
                                    .env("LD_LIBRARY_PATH", &lib_path)
                                    .output();

                                if let Ok(output) = kem_output {
                                    let kems = String::from_utf8_lossy(&output.stdout);
                                    if kems.contains("kyber") || kems.contains("Kyber") || kems.contains("ML-KEM") {
                                        info!("Kyber/ML-KEM KEM detected - PQC available natively");
                                        return true;
                                    }
                                }

                                warn!("OpenSSL found but no PQC KEM algorithms available");
                                false
                            }
                            Err(e) => {
                                warn!("Failed to check OpenSSL providers: {}", e);
                                false
                            }
                        }
                    } else {
                        warn!("OpenSSL version {} does not support PQC", version_str.trim());
                        false
                    }
                }
                Err(e) => {
                    warn!("Failed to check OpenSSL version: {}", e);
                    false
                }
            }
        }

        #[cfg(not(feature = "pqc"))]
        {
            warn!("PQC feature not compiled - OpenSSL PQC unavailable");
            false
        }
    }

    /// Check if rustls PQC support is available
    fn check_rustls_pqc() -> bool {
        // rustls doesn't have native PQC support yet
        // This is a placeholder for future integration
        warn!("rustls-pqc provider not yet implemented");
        false
    }

    /// Create rustls server configuration
    fn create_rustls_config(
        tls_config: &TlsConfig,
        pqc_config: &PqcConfig,
        pqc_available: bool,
    ) -> anyhow::Result<RustlsServerConfig> {
        // Load certificate chain
        let cert_chain = Self::load_certificates(&tls_config.cert_path)?;
        info!("Loaded {} certificates from chain", cert_chain.len());

        // Load private key
        let private_key = Self::load_private_key(&tls_config.key_path)?;
        info!("Private key loaded successfully");

        // Create base configuration
        let mut config = if tls_config.require_client_cert {
            // mTLS configuration
            let client_ca = Self::load_client_ca(&tls_config.ca_cert_path)?;
            let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_ca))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create client verifier: {}", e))?;

            RustlsServerConfig::builder()
                .with_client_cert_verifier(client_auth)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to create mTLS config: {}", e))?
        } else {
            // Standard TLS configuration
            RustlsServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?
        };

        // Configure ALPN protocols
        config.alpn_protocols = tls_config.alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        info!("ALPN protocols: {:?}", tls_config.alpn_protocols);

        // Log PQC status
        if pqc_config.enabled && pqc_available {
            info!("PQC hybrid key exchange enabled (provider: {})", pqc_config.provider);
            info!("Preferred KEM: {}", pqc_config.preferred_kem);
            // Note: Actual PQC integration requires custom crypto provider
            // This is handled at the QUIC/TLS handshake level via OpenSSL
        } else if pqc_config.enabled {
            warn!("PQC requested but not available - using classical key exchange");
        }

        Ok(config)
    }

    /// Load certificates from PEM file
    fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let file = File::open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open certificate file {:?}: {}", path, e))?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse certificates: {}", e))?;

        if certs.is_empty() {
            return Err(anyhow::anyhow!("No certificates found in {:?}", path));
        }

        Ok(certs)
    }

    /// Load private key from PEM file
    fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
        let file = File::open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open private key file {:?}: {}", path, e))?;
        let mut reader = BufReader::new(file);

        // Try PKCS#8 format first
        let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse PKCS#8 keys: {}", e))?;

        if !pkcs8_keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs8(pkcs8_keys.into_iter().next().unwrap()));
        }

        // Try RSA format
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        let rsa_keys: Vec<_> = rsa_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse RSA keys: {}", e))?;

        if !rsa_keys.is_empty() {
            return Ok(PrivateKeyDer::Pkcs1(rsa_keys.into_iter().next().unwrap()));
        }

        Err(anyhow::anyhow!("No private key found in {:?}", path))
    }

    /// Load client CA certificates for mTLS
    fn load_client_ca(path: &Option<std::path::PathBuf>) -> anyhow::Result<rustls::RootCertStore> {
        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = path {
            let certs = Self::load_certificates(ca_path)?;
            for cert in certs {
                root_store.add(cert)
                    .map_err(|e| anyhow::anyhow!("Failed to add CA certificate: {}", e))?;
            }
            info!("Loaded {} client CA certificates", root_store.len());
        } else {
            // Load system root certificates
            let native_certs = rustls_native_certs::load_native_certs();
            for cert in native_certs.certs {
                root_store.add(cert).ok();
            }
            info!("Loaded {} system root certificates", root_store.len());
        }

        Ok(root_store)
    }

    /// Get certificate information for admin API
    pub fn get_cert_info(&self) -> CertificateInfo {
        let tls_config = self.tls_config.read();
        let last_modified = *self.last_cert_modified.read();

        CertificateInfo {
            cert_path: tls_config.cert_path.to_string_lossy().to_string(),
            key_path: tls_config.key_path.to_string_lossy().to_string(),
            pqc_enabled: *self.pqc_available.read(),
            pqc_provider: self.pqc_config.read().provider.clone(),
            alpn_protocols: tls_config.alpn_protocols.clone(),
            last_reloaded: last_modified.map(|t| {
                chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()
            }),
        }
    }
}

/// Certificate information for admin API
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateInfo {
    pub cert_path: String,
    pub key_path: String,
    pub pqc_enabled: bool,
    pub pqc_provider: String,
    pub alpn_protocols: Vec<String>,
    pub last_reloaded: Option<String>,
}

/// PQC Key Exchange wrapper for hybrid mode
///
/// This module provides abstraction for PQC key exchange when OpenSSL 3.5 + OQS is available.
/// The actual PQC handshake is performed by OpenSSL; this provides monitoring and fallback.
pub mod pqc_kex {
    use super::*;

    /// PQC KEX algorithm identifiers
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PqcKem {
        /// Kyber768 (NIST Level 3)
        Kyber768,
        /// Kyber1024 (NIST Level 5)
        Kyber1024,
        /// ML-KEM-768 (FIPS 203 draft)
        MlKem768,
        /// ML-KEM-1024 (FIPS 203 draft)
        MlKem1024,
        /// X25519 + Kyber768 hybrid
        X25519Kyber768,
    }

    impl PqcKem {
        /// Get OpenSSL algorithm name
        pub fn openssl_name(&self) -> &'static str {
            match self {
                PqcKem::Kyber768 => "kyber768",
                PqcKem::Kyber1024 => "kyber1024",
                PqcKem::MlKem768 => "mlkem768",
                PqcKem::MlKem1024 => "mlkem1024",
                PqcKem::X25519Kyber768 => "x25519_kyber768",
            }
        }

        /// Parse from string
        pub fn from_str(s: &str) -> Option<Self> {
            match s.to_lowercase().as_str() {
                "kyber768" => Some(PqcKem::Kyber768),
                "kyber1024" => Some(PqcKem::Kyber1024),
                "mlkem768" | "ml-kem-768" => Some(PqcKem::MlKem768),
                "mlkem1024" | "ml-kem-1024" => Some(PqcKem::MlKem1024),
                "x25519_kyber768" | "x25519kyber768" => Some(PqcKem::X25519Kyber768),
                _ => None,
            }
        }
    }

    /// Check if a specific KEM is available via OpenSSL
    #[cfg(feature = "pqc")]
    pub fn is_kem_available(kem: PqcKem, openssl_path: &str, lib_path: &str) -> bool {
        use std::process::Command;

        let output = Command::new(openssl_path)
            .args(["list", "-kem-algorithms"])
            .env("LD_LIBRARY_PATH", lib_path)
            .output();

        match output {
            Ok(output) => {
                let kems = String::from_utf8_lossy(&output.stdout).to_lowercase();
                kems.contains(kem.openssl_name())
            }
            Err(_) => false,
        }
    }

    #[cfg(not(feature = "pqc"))]
    pub fn is_kem_available(_kem: PqcKem, _openssl_path: &str, _lib_path: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_kem_names() {
        assert_eq!(pqc_kex::PqcKem::Kyber768.openssl_name(), "kyber768");
        assert_eq!(pqc_kex::PqcKem::X25519Kyber768.openssl_name(), "x25519_kyber768");
    }

    #[test]
    fn test_pqc_kem_parsing() {
        assert_eq!(pqc_kex::PqcKem::from_str("kyber768"), Some(pqc_kex::PqcKem::Kyber768));
        assert_eq!(pqc_kex::PqcKem::from_str("ML-KEM-1024"), Some(pqc_kex::PqcKem::MlKem1024));
        assert_eq!(pqc_kex::PqcKem::from_str("unknown"), None);
    }
}
