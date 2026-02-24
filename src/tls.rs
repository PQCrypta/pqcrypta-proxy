//! TLS configuration with Post-Quantum Cryptography (PQC) support
//!
//! Supports:
//! - Standard TLS 1.3 with rustls
//! - Hybrid PQC key exchange via aws-lc-rs (X25519MLKEM768)
//! - Hot-reload of certificates
//! - mTLS for client authentication

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::server::ServerConfig as RustlsServerConfig;
use rustls::version::{TLS12, TLS13};
// L-1: Migrated from unmaintained rustls-pemfile to rustls-pki-types PEM parsing API
use rustls_pki_types::pem::PemObject;
use tracing::{debug, info, warn};

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
    pub fn update_config(
        &self,
        tls_config: &TlsConfig,
        pqc_config: &PqcConfig,
    ) -> anyhow::Result<()> {
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
        // Always try rustls-post-quantum first (preferred, native Rust implementation)
        if Self::check_rustls_pqc() {
            info!("Using rustls-post-quantum provider for PQC (X25519MLKEM768)");
            return true;
        }

        // Fallback to OpenSSL if configured
        match pqc_config.provider.as_str() {
            "openssl3.5" => Self::check_openssl_pqc(pqc_config),
            "rustls-pqc" => false, // Already tried above
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

            let openssl_path = pqc_config
                .openssl_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "openssl".to_string());

            // Set library path for OpenSSL 3.5
            let lib_path = pqc_config
                .openssl_lib_path
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
                    if version_str.contains("3.5")
                        || version_str.contains("3.4")
                        || version_str.contains("3.3")
                    {
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
                                    info!(
                                        "OQS provider detected - PQC hybrid key exchange available"
                                    );
                                    return true;
                                }

                                // Check for built-in Kyber support (OpenSSL 3.5+)
                                let kem_output = Command::new(&openssl_path)
                                    .args(["list", "-kem-algorithms"])
                                    .env("LD_LIBRARY_PATH", &lib_path)
                                    .output();

                                if let Ok(output) = kem_output {
                                    let kems = String::from_utf8_lossy(&output.stdout);
                                    if kems.contains("kyber")
                                        || kems.contains("Kyber")
                                        || kems.contains("ML-KEM")
                                    {
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
                        warn!(
                            "OpenSSL version {} does not support PQC",
                            version_str.trim()
                        );
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

    /// Check if rustls PQC support is available via aws-lc-rs
    fn check_rustls_pqc() -> bool {
        // Check if rustls-post-quantum provider is available
        // This uses aws-lc-rs which has X25519MLKEM768 support
        match rustls_post_quantum::provider().install_default() {
            Ok(_) => {
                info!("rustls-post-quantum provider installed - X25519MLKEM768 hybrid key exchange available");
                true
            }
            Err(_) => {
                // Provider might already be installed, check if it's available
                if CryptoProvider::get_default().is_some() {
                    info!("Default crypto provider already set - checking for PQC support");
                    true
                } else {
                    warn!("Failed to install rustls-post-quantum provider");
                    false
                }
            }
        }
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

        // Get the crypto provider - always use rustls-post-quantum provider
        // It's based on aws-lc-rs and includes X25519MLKEM768 hybrid key exchange
        let crypto_provider = if pqc_config.enabled && pqc_available {
            info!("Using rustls-post-quantum crypto provider with X25519MLKEM768 (PQC enabled)");
            Arc::new(rustls_post_quantum::provider())
        } else {
            // Still use rustls-post-quantum provider but PQC won't be negotiated
            // if the client doesn't support it
            info!("Using rustls-post-quantum crypto provider (PQC fallback to classical)");
            Arc::new(rustls_post_quantum::provider())
        };

        // Create base configuration with the appropriate crypto provider
        // SEC-01: Enforce the configured minimum TLS version instead of accepting
        // the rustls safe-default range (which includes TLS 1.2).
        let protocol_versions: &[&rustls::SupportedProtocolVersion] =
            if tls_config.min_version == "1.3" {
                info!("TLS min_version = 1.3 — disabling TLS 1.2");
                &[&TLS13]
            } else {
                info!("TLS min_version = 1.2 — allowing TLS 1.2 and 1.3");
                &[&TLS12, &TLS13]
            };

        let mut config = if tls_config.require_client_cert {
            // mTLS configuration
            let client_ca = Self::load_client_ca(&tls_config.ca_cert_path)?;
            let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_ca))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create client verifier: {}", e))?;

            RustlsServerConfig::builder_with_provider(crypto_provider)
                .with_protocol_versions(protocol_versions)
                .map_err(|e| anyhow::anyhow!("Failed to set protocol versions: {}", e))?
                .with_client_cert_verifier(client_auth)
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to create mTLS config: {}", e))?
        } else {
            // Standard TLS configuration with PQC support
            RustlsServerConfig::builder_with_provider(crypto_provider)
                .with_protocol_versions(protocol_versions)
                .map_err(|e| anyhow::anyhow!("Failed to set protocol versions: {}", e))?
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to create TLS config: {}", e))?
        };

        // Configure ALPN protocols
        config.alpn_protocols = tls_config
            .alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        info!("ALPN protocols: {:?}", tls_config.alpn_protocols);

        // Configure 0-RTT (early data)
        // L-5: 0-RTT is a replay-attack risk. The proxy forwards early data to
        // backends without deduplication. Only enable on routes whose backends
        // are safe to receive replayed requests, and restrict to idempotent methods
        // via `tls.zero_rtt_safe_methods` (default: GET, HEAD only).
        if tls_config.enable_0rtt {
            // Enable 0-RTT with 16KB max early data
            config.max_early_data_size = 16384;
            warn!(
                "⚠️  0-RTT (early data) ENABLED — replay-attack risk. \
                 Safe HTTP methods: {:?}. \
                 Non-idempotent requests (POST/PUT/DELETE/PATCH) forwarded via 0-RTT \
                 may be delivered TWICE to backends with no indication. \
                 Ensure routes serving non-GET/HEAD traffic have `allow_0rtt = false` \
                 (the default). Set `tls.zero_rtt_safe_methods` if your backends \
                 implement idempotency-key deduplication.",
                tls_config.zero_rtt_safe_methods
            );
        } else {
            // Disable 0-RTT for security
            config.max_early_data_size = 0;
            info!("0-RTT disabled (secure default)");
        }

        // Log PQC status
        if pqc_config.enabled && pqc_available {
            info!("🛡️  PQC hybrid key exchange ACTIVE via rustls-post-quantum");
            info!("🔐 Key Exchange: X25519MLKEM768 (hybrid classical + post-quantum)");
            info!("📊 Security Level: NIST Level 3 (192-bit equivalent)");
        } else if pqc_config.enabled {
            warn!("PQC requested but not available - using classical key exchange");
        }

        Ok(config)
    }

    /// Load certificates from PEM file.
    // L-1: Uses rustls-pki-types PEM API (replaces unmaintained rustls-pemfile)
    fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let file = File::open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open certificate file {:?}: {}", path, e))?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse certificates from {:?}: {}", path, e))?;

        if certs.is_empty() {
            return Err(anyhow::anyhow!("No certificates found in {:?}", path));
        }

        Ok(certs)
    }

    /// Load private key from PEM file.
    // L-1: Uses rustls-pki-types PEM API (replaces unmaintained rustls-pemfile).
    // Tries PKCS#8 first (most common for modern keys), then PKCS#1 (legacy RSA).
    fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
        // Try PKCS#8 format first (covers Ed25519, ECDSA, RSA wrapped in PKCS#8)
        {
            let file = File::open(path)
                .map_err(|e| anyhow::anyhow!("Failed to open key file {:?}: {}", path, e))?;
            let mut reader = BufReader::new(file);
            if let Some(key) = PrivatePkcs8KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok())
            {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
        }

        // Try PKCS#1 (legacy RSA) format
        {
            let file = File::open(path)
                .map_err(|e| anyhow::anyhow!("Failed to open key file {:?}: {}", path, e))?;
            let mut reader = BufReader::new(file);
            if let Some(key) = PrivatePkcs1KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok())
            {
                return Ok(PrivateKeyDer::Pkcs1(key));
            }
        }

        Err(anyhow::anyhow!(
            "No private key found in {:?} (tried PKCS#8 and PKCS#1 formats)",
            path
        ))
    }

    /// Load client CA certificates for mTLS
    fn load_client_ca(path: &Option<std::path::PathBuf>) -> anyhow::Result<rustls::RootCertStore> {
        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = path {
            let certs = Self::load_certificates(ca_path)?;
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| anyhow::anyhow!("Failed to add CA certificate: {}", e))?;
            }
            info!("Loaded {} client CA certificates", root_store.len());
        } else {
            // Load system root certificates
            let native_certs = rustls_native_certs::load_native_certs();
            let mut added = 0;
            let mut failed = 0;
            for cert in native_certs.certs {
                match root_store.add(cert) {
                    Ok(()) => added += 1,
                    Err(e) => {
                        debug!("Failed to add system root certificate: {}", e);
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                info!(
                    "Loaded {} system root certificates ({} failed - likely duplicates)",
                    added, failed
                );
            } else {
                info!("Loaded {} system root certificates", root_store.len());
            }
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
            last_reloaded: last_modified
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
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

// Note: PQC key exchange functionality is provided by pqc_tls::PqcKemAlgorithm
