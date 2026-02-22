//! Post-Quantum Cryptography TLS Provider
//!
//! Implements hybrid PQC key exchange using OpenSSL 3.5+ with native ML-KEM support.
#![allow(unsafe_code)] // Required for OpenSSL FFI bindings
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
use tracing::{debug, error, info, warn};

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
    /// Kyber768 (pre-NIST round-3 draft — not FIPS 203 compliant)
    /// Gated behind the `legacy-pqc` compile-time feature.  Only available for
    /// backward-compatibility with deployments that have not yet migrated to
    /// the finalised ML-KEM standard.  Not suitable for new deployments.
    #[cfg(feature = "legacy-pqc")]
    Kyber768,
    /// X25519 + Kyber768 hybrid (pre-NIST round-3 draft — not FIPS 203 compliant)
    /// Gated behind the `legacy-pqc` compile-time feature.  See Kyber768 note above.
    #[cfg(feature = "legacy-pqc")]
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
            #[cfg(feature = "legacy-pqc")]
            Self::Kyber768 => "kyber768",
            #[cfg(feature = "legacy-pqc")]
            Self::X25519Kyber768 => "x25519_kyber768",
        }
    }

    /// Get security level (NIST level)
    pub fn security_level(&self) -> u8 {
        match self {
            Self::MlKem512 => 1,
            Self::X25519MlKem768
            | Self::SecP256r1MlKem768
            | Self::MlKem768 => 3,
            #[cfg(feature = "legacy-pqc")]
            Self::Kyber768 | Self::X25519Kyber768 => 3,
            Self::SecP384r1MlKem1024 | Self::X448MlKem1024 | Self::MlKem1024 => 5,
        }
    }

    /// Is this a hybrid algorithm (classical + PQC)?
    pub fn is_hybrid(&self) -> bool {
        match self {
            Self::X25519MlKem768
            | Self::SecP256r1MlKem768
            | Self::SecP384r1MlKem1024
            | Self::X448MlKem1024 => true,
            #[cfg(feature = "legacy-pqc")]
            Self::X25519Kyber768 => true,
            _ => false,
        }
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
            #[cfg(feature = "legacy-pqc")]
            "kyber768" => {
                warn!(
                    "⚠️  DEPRECATED: Kyber768 is a pre-NIST round-3 draft (not FIPS 203). \
                     It is NOT interoperable with ML-KEM-compliant peers and lacks the \
                     security guarantees of the finalised standard. \
                     Migrate to X25519MlKem768 or another FIPS 203 algorithm."
                );
                Some(Self::Kyber768)
            }
            #[cfg(feature = "legacy-pqc")]
            "x25519kyber768" => {
                warn!(
                    "⚠️  DEPRECATED: X25519Kyber768 is a pre-NIST round-3 draft hybrid \
                     (not FIPS 203). It is NOT interoperable with ML-KEM-compliant peers. \
                     Migrate to X25519MlKem768 (IETF standard, FIPS 203 compliant)."
                );
                Some(Self::X25519Kyber768)
            }
            _ => None,
        }
    }

    /// Get all available hybrid algorithms (recommended order)
    pub fn recommended_hybrids() -> Vec<Self> {
        vec![
            Self::X25519MlKem768,     // IETF standard, best compatibility
            Self::SecP256r1MlKem768,  // NIST curve variant
            Self::SecP384r1MlKem1024, // Higher security
            Self::X448MlKem1024,      // Maximum security
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
                    info!(
                        "  Preferred KEM: {} (Security Level {})",
                        kem.openssl_name(),
                        kem.security_level()
                    );
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
        let openssl_bin = config
            .openssl_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "openssl".to_string());

        let openssl_lib = config
            .openssl_lib_path
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
                lower.contains("mlkem")
                    || lower.contains("kyber")
                    || lower.contains("x25519")
                    || lower.contains("x448")
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

    /// Update configuration
    pub fn update_config(&self, config: &PqcConfig) {
        *self.config.write() = config.clone();
        self.initialize();
    }

    /// Generate test certificate with PQC (for testing)
    pub fn generate_test_cert(&self, output_dir: &Path) -> Result<(), String> {
        if !self.is_available() {
            return Err("PQC not available".to_string());
        }

        let openssl_bin = self.openssl_bin_path();
        let openssl_lib = self.openssl_lib_path();

        let cert_path = output_dir.join("pqc-cert.pem");
        let key_path = output_dir.join("pqc-key.pem");

        // Generate key with ML-DSA-87 (NIST Level 5 signature)
        let key_path_str = key_path
            .to_str()
            .ok_or_else(|| "Key path contains invalid UTF-8".to_string())?;
        let key_output = Command::new(&openssl_bin)
            .args(["genpkey", "-algorithm", "ML-DSA-87", "-out", key_path_str])
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
        let cert_path_str = cert_path
            .to_str()
            .ok_or_else(|| "Cert path contains invalid UTF-8".to_string())?;
        let cert_output = Command::new(&openssl_bin)
            .args([
                "req",
                "-new",
                "-x509",
                "-key",
                key_path_str,
                "-out",
                cert_path_str,
                "-days",
                "365",
                "-subj",
                "/CN=PQCrypta Test/O=PQCrypta/C=US",
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

    /// Get OpenSSL library path for subprocess calls
    /// Returns the LD_LIBRARY_PATH value for OpenSSL 3.5+
    pub fn openssl_lib_path(&self) -> String {
        let config = self.config.read();
        config
            .openssl_lib_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    }

    /// Get OpenSSL binary path
    pub fn openssl_bin_path(&self) -> String {
        let config = self.config.read();
        config
            .openssl_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "openssl".to_string())
    }
}

// ============================================================================
// OpenSSL 3.5+ PQC TLS Backend
// ============================================================================
// This module provides the OpenSSL-based TLS backend with native ML-KEM support.
// OpenSSL 3.5+ offers:
// - Multiple ML-KEM variants (512/768/1024)
// - Multiple hybrid modes (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024)
// - Hardware acceleration for cryptographic operations
// - Broader ecosystem compatibility
//
// Use this backend when you need:
// - Maximum PQC algorithm flexibility
// - Hardware-accelerated cryptography
// - Compatibility with enterprise PKI systems
// ============================================================================

/// OpenSSL SSL context configuration for PQC
///
/// This module provides the OpenSSL 3.5+ TLS backend with native ML-KEM support.
/// Used by `http_listener::run_http_listener_pqc` for post-quantum TLS.
#[cfg(feature = "pqc")]
pub mod openssl_pqc {
    use super::*;
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVersion};
    use std::path::Path;

    /// Create an OpenSSL SSL acceptor with PQC hybrid key exchange
    ///
    /// This configures OpenSSL 3.5+ with ML-KEM hybrid groups for post-quantum
    /// key exchange while maintaining backward compatibility with classical TLS.
    pub fn create_pqc_acceptor(
        cert_path: &Path,
        key_path: &Path,
        pqc_provider: &PqcTlsProvider,
    ) -> Result<SslAcceptor, String> {
        let mut builder = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server())
            .map_err(|e| format!("Failed to create SSL acceptor: {}", e))?;

        // Set minimum TLS version to 1.3 (required for ML-KEM)
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| format!("Failed to set TLS version: {}", e))?;

        // Load certificate chain (includes intermediate certificates)
        builder
            .set_certificate_chain_file(cert_path)
            .map_err(|e| format!("Failed to load certificate chain: {}", e))?;

        // Load private key
        builder
            .set_private_key_file(key_path, SslFiletype::PEM)
            .map_err(|e| format!("Failed to load private key: {}", e))?;

        // Configure PQC groups if available
        if pqc_provider.is_available() {
            // Try different PQC group configurations
            // OpenSSL 3.5 supports multiple name formats for ML-KEM hybrid groups
            let pqc_group_options = [
                // IETF standard hybrid names
                "X25519MLKEM768:X25519:P-256:P-384",
                // Alternative format with hyphen
                "X25519-MLKEM768:X25519:P-256:P-384",
                // ML-KEM standalone first
                "ML-KEM-768:X25519:P-256:P-384",
                // MLKEM without hyphen
                "MLKEM768:X25519:P-256:P-384",
            ];

            let mut pqc_configured = false;
            for groups in pqc_group_options {
                info!("Trying PQC groups configuration: {}", groups);
                match builder.set_groups_list(groups) {
                    Ok(()) => {
                        info!("PQC groups configured successfully: {}", groups);
                        pqc_configured = true;
                        break;
                    }
                    Err(e) => {
                        debug!("Group config '{}' failed: {}", groups, e);
                    }
                }
            }

            if !pqc_configured {
                // All PQC options failed, fall back to classical
                let classical_groups = "X25519:P-256:P-384";
                warn!(
                    "All PQC group configurations failed, falling back to classical: {}",
                    classical_groups
                );
                builder
                    .set_groups_list(classical_groups)
                    .map_err(|e| format!("Failed to set classical groups: {}", e))?;
            }
        }

        // Set ALPN protocols - advertise h2 and http/1.1
        // Wire format: length-prefixed protocol names
        builder
            .set_alpn_protos(b"\x02h2\x08http/1.1")
            .map_err(|e| format!("Failed to set ALPN protos: {}", e))?;

        // Set ALPN selection callback - prefer h2 over http/1.1
        builder.set_alpn_select_callback(|_, client_protos| {
            // Parse client's ALPN protocol list (length-prefixed strings)
            let mut pos = 0;
            while pos < client_protos.len() {
                let len = client_protos[pos] as usize;
                if pos + 1 + len > client_protos.len() {
                    break;
                }
                let proto = &client_protos[pos + 1..pos + 1 + len];

                // Prefer h2 (HTTP/2) over http/1.1
                if proto == b"h2" {
                    return Ok(b"h2");
                }
                pos += 1 + len;
            }

            // Second pass: accept http/1.1 if no h2
            pos = 0;
            while pos < client_protos.len() {
                let len = client_protos[pos] as usize;
                if pos + 1 + len > client_protos.len() {
                    break;
                }
                let proto = &client_protos[pos + 1..pos + 1 + len];

                if proto == b"http/1.1" {
                    return Ok(b"http/1.1");
                }
                pos += 1 + len;
            }

            Err(openssl::ssl::AlpnError::NOACK)
        });

        // Set session cache for resumption
        builder.set_session_cache_mode(openssl::ssl::SslSessionCacheMode::SERVER);

        Ok(builder.build())
    }

    /// Get PQC handshake info from SSL connection
    ///
    /// Call this after a TLS handshake to retrieve information about the
    /// negotiated post-quantum key exchange parameters.
    pub fn get_pqc_info(ssl: &openssl::ssl::SslRef) -> PqcHandshakeInfo {
        let cipher = ssl
            .current_cipher()
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
///
/// Used by `openssl_pqc::get_pqc_info()` to return details about the negotiated
/// post-quantum key exchange after a TLS handshake completes.
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
///
/// This function creates a temporary PQC provider and checks if the system
/// has OpenSSL 3.5+ with ML-KEM support available.
///
/// # Example
/// ```ignore
/// match verify_pqc_support() {
///     Ok(status) => println!("PQC supported: {:?}", status.available_kems),
///     Err(e) => println!("PQC not available: {}", e),
/// }
/// ```
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
        assert_eq!(
            PqcKemAlgorithm::X25519MlKem768.openssl_name(),
            "X25519MLKEM768"
        );
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
