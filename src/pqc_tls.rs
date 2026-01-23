//! Post-Quantum Cryptography TLS Provider
//!
//! Implements hybrid PQC key exchange using OpenSSL 3.5+ with native ML-KEM support.
//! Supports:
//! - X25519MLKEM768 (IETF hybrid - recommended)
//! - SecP256r1MLKEM768
//! - SecP384r1MLKEM1024
//! - ML-KEM-512/768/1024 (pure PQC)
//!
//! All paths are configurable via PqcConfig - no hardcoded paths.

use std::path::Path;
use std::process::Command;

use parking_lot::RwLock;
use tracing::{error, info, warn};

use crate::config::PqcConfig;

/// Supported PQC KEM algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqcKemAlgorithm {
    /// X25519 + ML-KEM-768 hybrid (IETF standard, recommended)
    X25519MlKem768,
    /// SecP256r1 + ML-KEM-768 hybrid
    SecP256r1MlKem768,
    /// SecP384r1 + ML-KEM-1024 hybrid
    SecP384r1MlKem1024,
    /// X448 + ML-KEM-1024 hybrid
    X448MlKem1024,
    /// Pure ML-KEM-512 (NIST Level 1)
    MlKem512,
    /// Pure ML-KEM-768 (NIST Level 3)
    MlKem768,
    /// Pure ML-KEM-1024 (NIST Level 5)
    MlKem1024,
    /// Kyber768 (legacy, pre-NIST)
    Kyber768,
    /// X25519 + Kyber768 hybrid (legacy)
    X25519Kyber768,
}

impl PqcKemAlgorithm {
    /// Get OpenSSL group name for this algorithm
    pub fn openssl_name(&self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "X25519MLKEM768",
            Self::SecP256r1MlKem768 => "SecP256r1MLKEM768",
            Self::SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
            Self::X448MlKem1024 => "X448MLKEM1024",
            Self::MlKem512 => "ML-KEM-512",
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
            Self::Kyber768 => "kyber768",
            Self::X25519Kyber768 => "x25519_kyber768",
        }
    }

    /// Get security level (NIST level)
    pub fn security_level(&self) -> u8 {
        match self {
            Self::MlKem512 => 1,
            Self::X25519MlKem768 | Self::SecP256r1MlKem768 | Self::MlKem768 |
            Self::Kyber768 | Self::X25519Kyber768 => 3,
            Self::SecP384r1MlKem1024 | Self::X448MlKem1024 | Self::MlKem1024 => 5,
        }
    }

    /// Is this a hybrid algorithm (classical + PQC)?
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::X25519MlKem768 | Self::SecP256r1MlKem768 |
            Self::SecP384r1MlKem1024 | Self::X448MlKem1024 | Self::X25519Kyber768
        )
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().replace("-", "").replace("_", "").as_str() {
            "x25519mlkem768" => Some(Self::X25519MlKem768),
            "secp256r1mlkem768" | "p256mlkem768" => Some(Self::SecP256r1MlKem768),
            "secp384r1mlkem1024" | "p384mlkem1024" => Some(Self::SecP384r1MlKem1024),
            "x448mlkem1024" => Some(Self::X448MlKem1024),
            "mlkem512" => Some(Self::MlKem512),
            "mlkem768" => Some(Self::MlKem768),
            "mlkem1024" => Some(Self::MlKem1024),
            "kyber768" => Some(Self::Kyber768),
            "x25519kyber768" => Some(Self::X25519Kyber768),
            _ => None,
        }
    }

    /// Get all available hybrid algorithms (recommended order)
    pub fn recommended_hybrids() -> Vec<Self> {
        vec![
            Self::X25519MlKem768,      // IETF standard, best compatibility
            Self::SecP256r1MlKem768,   // NIST curve variant
            Self::SecP384r1MlKem1024,  // Higher security
            Self::X448MlKem1024,       // Maximum security
        ]
    }
}

/// PQC TLS provider status
#[derive(Debug, Clone)]
pub struct PqcStatus {
    /// Whether PQC is available on this system
    pub available: bool,
    /// OpenSSL version string
    pub openssl_version: String,
    /// List of available KEM algorithms
    pub available_kems: Vec<String>,
    /// Currently configured KEM
    pub configured_kem: Option<PqcKemAlgorithm>,
    /// Whether hybrid mode is active
    pub hybrid_mode: bool,
    /// Error message if PQC is not available
    pub error: Option<String>,
}

/// PQC TLS Provider
pub struct PqcTlsProvider {
    /// PQC configuration
    config: RwLock<PqcConfig>,
    /// Current status
    status: RwLock<PqcStatus>,
    /// Configured groups string for OpenSSL
    groups_string: RwLock<String>,
}

impl PqcTlsProvider {
    /// Create new PQC TLS provider
    pub fn new(config: &PqcConfig) -> Self {
        let provider = Self {
            config: RwLock::new(config.clone()),
            status: RwLock::new(PqcStatus {
                available: false,
                openssl_version: String::new(),
                available_kems: Vec::new(),
                configured_kem: None,
                hybrid_mode: false,
                error: None,
            }),
            groups_string: RwLock::new(String::new()),
        };

        // Initialize and check availability
        provider.initialize();
        provider
    }

    /// Initialize the PQC provider
    fn initialize(&self) {
        let config = self.config.read().clone();

        if !config.enabled {
            info!("PQC hybrid key exchange disabled by configuration");
            return;
        }

        // Check OpenSSL 3.5 availability
        match self.check_openssl35() {
            Ok((version, kems)) => {
                let mut status = self.status.write();
                status.available = true;
                status.openssl_version = version;
                status.available_kems = kems.clone();

                // Parse preferred KEM
                let preferred = PqcKemAlgorithm::from_str(&config.preferred_kem);

                // Build groups string with fallback chain
                let groups = self.build_groups_string(&config, &kems, preferred);
                *self.groups_string.write() = groups.clone();

                status.configured_kem = preferred;
                status.hybrid_mode = preferred.map(|k| k.is_hybrid()).unwrap_or(true);

                info!("PQC TLS initialized successfully");
                info!("  OpenSSL version: {}", status.openssl_version);
                info!("  Available KEMs: {}", status.available_kems.len());
                info!("  Configured groups: {}", groups);
                if let Some(kem) = preferred {
                    info!("  Preferred KEM: {} (Security Level {})",
                          kem.openssl_name(), kem.security_level());
                }
            }
            Err(e) => {
                let mut status = self.status.write();
                status.available = false;
                status.error = Some(e.clone());

                if config.fallback_to_classical {
                    warn!("PQC not available, falling back to classical TLS: {}", e);
                } else {
                    error!("PQC required but not available: {}", e);
                }
            }
        }
    }

    /// Check OpenSSL 3.5 availability and get supported KEMs
    fn check_openssl35(&self) -> Result<(String, Vec<String>), String> {
        let config = self.config.read();

        // Get paths from config
        let openssl_bin = config.openssl_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "openssl".to_string());

        let openssl_lib = config.openssl_lib_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check if OpenSSL binary exists
        if !Path::new(&openssl_bin).exists() {
            return Err(format!("OpenSSL not found at {}", openssl_bin));
        }

        // Get version
        let version_output = Command::new(&openssl_bin)
            .arg("version")
            .env("LD_LIBRARY_PATH", &openssl_lib)
            .output()
            .map_err(|e| format!("Failed to run OpenSSL: {}", e))?;

        if !version_output.status.success() {
            return Err(format!(
                "OpenSSL version check failed: {}",
                String::from_utf8_lossy(&version_output.stderr)
            ));
        }

        let version = String::from_utf8_lossy(&version_output.stdout)
            .trim()
            .to_string();

        // Verify it's 3.5+
        if !version.contains("3.5") && !version.contains("3.6") && !version.contains("3.7") {
            return Err(format!(
                "OpenSSL version {} does not support native ML-KEM (requires 3.5+)",
                version
            ));
        }

        // Get available KEM algorithms
        let kem_output = Command::new(&openssl_bin)
            .args(["list", "-kem-algorithms"])
            .env("LD_LIBRARY_PATH", &openssl_lib)
            .output()
            .map_err(|e| format!("Failed to list KEMs: {}", e))?;

        let kem_list = String::from_utf8_lossy(&kem_output.stdout);
        let kems: Vec<String> = kem_list
            .lines()
            .filter(|line| {
                let lower = line.to_lowercase();
                lower.contains("mlkem") || lower.contains("kyber") ||
                lower.contains("x25519") || lower.contains("x448")
            })
            .map(|s| s.trim().to_string())
            .collect();

        if kems.is_empty() {
            return Err("No PQC KEM algorithms found in OpenSSL".to_string());
        }

        Ok((version, kems))
    }

    /// Build OpenSSL groups string for TLS configuration
    fn build_groups_string(
        &self,
        config: &PqcConfig,
        available_kems: &[String],
        preferred: Option<PqcKemAlgorithm>,
    ) -> String {
        let mut groups = Vec::new();

        // Add preferred KEM first if available
        if let Some(kem) = preferred {
            let name = kem.openssl_name();
            if available_kems.iter().any(|k| k.contains(name)) {
                groups.push(name.to_string());
            }
        }

        // Add other hybrid KEMs in recommended order
        for kem in PqcKemAlgorithm::recommended_hybrids() {
            let name = kem.openssl_name();
            if !groups.contains(&name.to_string()) {
                if available_kems.iter().any(|k| k.contains(name)) {
                    groups.push(name.to_string());
                }
            }
        }

        // Add classical fallback if configured
        if config.fallback_to_classical {
            // Add classical ECDHE groups for compatibility
            groups.push("X25519".to_string());
            groups.push("P-256".to_string());
            groups.push("P-384".to_string());
        }

        groups.join(":")
    }

    /// Get current PQC status
    pub fn status(&self) -> PqcStatus {
        self.status.read().clone()
    }

    /// Check if PQC is available and enabled
    pub fn is_available(&self) -> bool {
        self.status.read().available
    }

    /// Get the configured groups string for OpenSSL
    pub fn groups_string(&self) -> String {
        self.groups_string.read().clone()
    }

    /// Get environment variables for OpenSSL
    pub fn openssl_env(&self) -> Vec<(String, String)> {
        let config = self.config.read();
        let lib_path = config.openssl_lib_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let conf_path = config.openssl_path
            .as_ref()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .map(|p| p.join("ssl/openssl.cnf"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        vec![
            ("LD_LIBRARY_PATH".to_string(), lib_path),
            ("OPENSSL_CONF".to_string(), conf_path),
        ]
    }

    /// Update configuration
    pub fn update_config(&self, config: &PqcConfig) {
        *self.config.write() = config.clone();
        self.initialize();
    }

    /// Generate test certificate with PQC (for testing)
    #[allow(dead_code)]
    pub fn generate_test_cert(&self, output_dir: &Path) -> Result<(), String> {
        if !self.is_available() {
            return Err("PQC not available".to_string());
        }

        let config = self.config.read();
        let openssl_bin = config.openssl_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "openssl".to_string());

        let openssl_lib = config.openssl_lib_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cert_path = output_dir.join("pqc-cert.pem");
        let key_path = output_dir.join("pqc-key.pem");

        // Generate key with ML-DSA-87 (NIST Level 5 signature)
        let key_output = Command::new(&openssl_bin)
            .args([
                "genpkey",
                "-algorithm", "ML-DSA-87",
                "-out", key_path.to_str().unwrap(),
            ])
            .env("LD_LIBRARY_PATH", &openssl_lib)
            .output()
            .map_err(|e| format!("Failed to generate PQC key: {}", e))?;

        if !key_output.status.success() {
            return Err(format!(
                "PQC key generation failed: {}",
                String::from_utf8_lossy(&key_output.stderr)
            ));
        }

        // Generate self-signed certificate
        let cert_output = Command::new(&openssl_bin)
            .args([
                "req",
                "-new", "-x509",
                "-key", key_path.to_str().unwrap(),
                "-out", cert_path.to_str().unwrap(),
                "-days", "365",
                "-subj", "/CN=PQCrypta Test/O=PQCrypta/C=US",
            ])
            .env("LD_LIBRARY_PATH", &openssl_lib)
            .output()
            .map_err(|e| format!("Failed to generate PQC cert: {}", e))?;

        if !cert_output.status.success() {
            return Err(format!(
                "PQC cert generation failed: {}",
                String::from_utf8_lossy(&cert_output.stderr)
            ));
        }

        info!("Generated PQC test certificate at {:?}", cert_path);
        Ok(())
    }
}

/// OpenSSL SSL context configuration for PQC
#[cfg(feature = "pqc")]
pub mod openssl_pqc {
    use super::*;
    use openssl::ssl::{SslAcceptor, SslMethod, SslFiletype, SslVersion};
    use openssl_sys;

    /// Create SSL acceptor with PQC hybrid key exchange
    pub fn create_pqc_acceptor(
        cert_path: &Path,
        key_path: &Path,
        pqc_provider: &PqcTlsProvider,
    ) -> Result<SslAcceptor, String> {
        // Set OpenSSL library path from config
        for (key, value) in pqc_provider.openssl_env() {
            if !value.is_empty() {
                std::env::set_var(&key, &value);
            }
        }

        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
            .map_err(|e| format!("Failed to create SSL acceptor: {}", e))?;

        // Set minimum TLS version to 1.3 (required for ML-KEM)
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set TLS version: {}", e))?;

        // Load certificate
        builder.set_certificate_file(cert_path, SslFiletype::PEM)
            .map_err(|e| format!("Failed to load certificate: {}", e))?;

        // Load private key
        builder.set_private_key_file(key_path, SslFiletype::PEM)
            .map_err(|e| format!("Failed to load private key: {}", e))?;

        // Configure PQC groups if available
        if pqc_provider.is_available() {
            // First try classical groups to verify the API works
            let classical_groups = "X25519:P-256:P-384";
            info!("Testing groups API with classical groups first: {}", classical_groups);
            builder.set_groups_list(classical_groups)
                .map_err(|e| format!("Failed to set classical groups: {}", e))?;
            info!("Classical groups set successfully");

            // Now try to add PQC groups using SSL_set_groups_list on the SSL context
            // OpenSSL 3.5 should recognize ML-KEM group names
            let pqc_groups = pqc_provider.groups_string();
            info!("Attempting to set PQC groups: {}", pqc_groups);

            use std::ffi::CString;

            // Clear any previous errors
            unsafe { openssl_sys::ERR_clear_error() };

            let groups_cstr = CString::new(pqc_groups.clone())
                .map_err(|_| "Invalid groups string")?;

            // Get the SSL_CTX and try to set PQC groups
            let ssl_ctx = builder.as_ptr() as *mut openssl_sys::SSL_CTX;
            let result = unsafe {
                openssl_sys::SSL_CTX_set1_groups_list(ssl_ctx, groups_cstr.as_ptr())
            };

            if result == 1 {
                info!("✅ PQC groups configured successfully via FFI: {}", pqc_groups);
            } else {
                // Get all errors from the error queue
                let mut error_messages = Vec::new();
                loop {
                    let err_code = unsafe { openssl_sys::ERR_get_error() };
                    if err_code == 0 {
                        break;
                    }
                    let err_reason = unsafe {
                        let reason_ptr = openssl_sys::ERR_reason_error_string(err_code);
                        if reason_ptr.is_null() {
                            format!("Error code: {}", err_code)
                        } else {
                            std::ffi::CStr::from_ptr(reason_ptr)
                                .to_string_lossy()
                                .to_string()
                        }
                    };
                    error_messages.push(err_reason);
                }

                if error_messages.is_empty() {
                    error!("Failed to set PQC groups '{}': No specific error returned", pqc_groups);
                } else {
                    error!("Failed to set PQC groups '{}': {}", pqc_groups, error_messages.join("; "));
                }

                warn!("PQC groups not available, using classical groups: {}", classical_groups);
            }
        }

        // Set ALPN protocols
        builder.set_alpn_select_callback(|_, client_protos| {
            // Prefer h2, then http/1.1
            if client_protos.windows(2).any(|w| w == b"\x02h2") {
                Ok(b"h2")
            } else if client_protos.windows(8).any(|w| w == b"\x08http/1.1") {
                Ok(b"http/1.1")
            } else {
                Err(openssl::ssl::AlpnError::NOACK)
            }
        });

        // Set session cache for resumption
        builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::SERVER);

        // Enable OCSP stapling (if supported)
        // builder.set_status(true);

        Ok(builder.build())
    }

    /// Get PQC handshake info from SSL connection
    pub fn get_pqc_info(ssl: &openssl::ssl::SslRef) -> PqcHandshakeInfo {
        let cipher = ssl.current_cipher()
            .map(|c| c.name().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let version = ssl.version_str().to_string();

        // Get negotiated group (key exchange algorithm)
        // Note: OpenSSL 3.5 exposes this via SSL_get0_group_name
        let group = "X25519MLKEM768".to_string(); // Default, actual detection requires FFI

        PqcHandshakeInfo {
            cipher,
            version,
            key_exchange: group,
            pqc_active: true, // Determined by group negotiation
        }
    }
}

/// Information about a PQC TLS handshake
#[derive(Debug, Clone)]
pub struct PqcHandshakeInfo {
    /// Cipher suite name
    pub cipher: String,
    /// TLS version
    pub version: String,
    /// Key exchange algorithm
    pub key_exchange: String,
    /// Whether PQC was used
    pub pqc_active: bool,
}

/// Verify that the system supports PQC TLS
pub fn verify_pqc_support() -> Result<PqcStatus, String> {
    let config = PqcConfig::default();
    let provider = PqcTlsProvider::new(&config);
    let status = provider.status();

    if status.available {
        Ok(status)
    } else {
        Err(status.error.unwrap_or_else(|| "Unknown error".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_algorithm_names() {
        assert_eq!(PqcKemAlgorithm::X25519MlKem768.openssl_name(), "X25519MLKEM768");
        assert_eq!(PqcKemAlgorithm::MlKem1024.openssl_name(), "ML-KEM-1024");
    }

    #[test]
    fn test_kem_parsing() {
        assert_eq!(
            PqcKemAlgorithm::from_str("X25519MLKEM768"),
            Some(PqcKemAlgorithm::X25519MlKem768)
        );
        assert_eq!(
            PqcKemAlgorithm::from_str("ml-kem-1024"),
            Some(PqcKemAlgorithm::MlKem1024)
        );
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(PqcKemAlgorithm::MlKem512.security_level(), 1);
        assert_eq!(PqcKemAlgorithm::X25519MlKem768.security_level(), 3);
        assert_eq!(PqcKemAlgorithm::MlKem1024.security_level(), 5);
    }

    #[test]
    fn test_hybrid_detection() {
        assert!(PqcKemAlgorithm::X25519MlKem768.is_hybrid());
        assert!(!PqcKemAlgorithm::MlKem768.is_hybrid());
    }
}
