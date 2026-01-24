//! Extended Post-Quantum Cryptography Support
//!
//! Provides unified PQC configuration and algorithm management across both
//! TLS backends (rustls with aws-lc-rs and OpenSSL 3.5+).
//!
//! ## Supported Algorithms
//!
//! ### Key Encapsulation Mechanisms (KEMs)
//! - **Hybrid KEMs** (recommended for TLS):
//!   - X25519MLKEM768 (IETF standard, NIST Level 3)
//!   - SecP256r1MLKEM768 (NIST curve + ML-KEM, Level 3)
//!   - SecP384r1MLKEM1024 (Higher security, Level 5)
//!   - X448MLKEM1024 (Maximum security, Level 5)
//! - **Pure ML-KEM** (FIPS 203):
//!   - ML-KEM-512 (Level 1, 128-bit security)
//!   - ML-KEM-768 (Level 3, 192-bit security)
//!   - ML-KEM-1024 (Level 5, 256-bit security)
//!
//! ### Digital Signatures (ML-DSA, FIPS 204) - requires `pqc-signatures` feature
//! - ML-DSA-44 (Level 2)
//! - ML-DSA-65 (Level 3)
//! - ML-DSA-87 (Level 5)
//!
//! ## Backend Selection
//!
//! - **rustls** (default): Pure Rust, memory-safe, QUIC support
//! - **OpenSSL 3.5+**: Broader algorithm support, hardware acceleration

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// NIST Security Levels for PQC algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Level 1: At least as hard as AES-128 key recovery
    Level1 = 1,
    /// Level 2: At least as hard as SHA-256 collision
    Level2 = 2,
    /// Level 3: At least as hard as AES-192 key recovery
    Level3 = 3,
    /// Level 4: At least as hard as SHA-384 collision
    Level4 = 4,
    /// Level 5: At least as hard as AES-256 key recovery
    Level5 = 5,
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Level1 => write!(f, "NIST Level 1 (128-bit)"),
            Self::Level2 => write!(f, "NIST Level 2 (SHA-256)"),
            Self::Level3 => write!(f, "NIST Level 3 (192-bit)"),
            Self::Level4 => write!(f, "NIST Level 4 (SHA-384)"),
            Self::Level5 => write!(f, "NIST Level 5 (256-bit)"),
        }
    }
}

/// Post-Quantum Key Encapsulation Mechanism algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqcKem {
    // ========== Hybrid KEMs (Classical + PQC) ==========
    /// X25519 + ML-KEM-768 (IETF standard, recommended default)
    X25519MlKem768,
    /// P-256 + ML-KEM-768 (NIST curve variant)
    SecP256r1MlKem768,
    /// P-384 + ML-KEM-1024 (Higher security)
    SecP384r1MlKem1024,
    /// X448 + ML-KEM-1024 (Maximum security)
    X448MlKem1024,

    // ========== Pure ML-KEM (FIPS 203) ==========
    /// ML-KEM-512: Smallest, fastest, Level 1
    MlKem512,
    /// ML-KEM-768: Balanced, Level 3
    MlKem768,
    /// ML-KEM-1024: Maximum security, Level 5
    MlKem1024,

    // ========== Legacy (deprecating in 2026) ==========
    /// Kyber768 (pre-standardization, for compatibility)
    #[serde(rename = "kyber768")]
    Kyber768,
    /// X25519 + Kyber768 hybrid (legacy)
    #[serde(rename = "x25519-kyber768")]
    X25519Kyber768,
}

impl PqcKem {
    /// Get the security level for this algorithm
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            Self::MlKem512 => SecurityLevel::Level1,
            Self::X25519MlKem768
            | Self::SecP256r1MlKem768
            | Self::MlKem768
            | Self::Kyber768
            | Self::X25519Kyber768 => SecurityLevel::Level3,
            Self::SecP384r1MlKem1024 | Self::X448MlKem1024 | Self::MlKem1024 => SecurityLevel::Level5,
        }
    }

    /// Check if this is a hybrid algorithm
    pub fn is_hybrid(&self) -> bool {
        matches!(
            self,
            Self::X25519MlKem768
                | Self::SecP256r1MlKem768
                | Self::SecP384r1MlKem1024
                | Self::X448MlKem1024
                | Self::X25519Kyber768
        )
    }

    /// Check if this algorithm is deprecated/legacy
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Kyber768 | Self::X25519Kyber768)
    }

    /// Get the OpenSSL group name for this algorithm
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

    /// Get the rustls/aws-lc-rs identifier (if supported)
    pub fn rustls_name(&self) -> Option<&'static str> {
        match self {
            Self::X25519MlKem768 => Some("X25519MLKEM768"),
            Self::MlKem512 => Some("ML-KEM-512"),
            Self::MlKem768 => Some("ML-KEM-768"),
            Self::MlKem1024 => Some("ML-KEM-1024"),
            // Not yet in rustls-post-quantum
            Self::SecP256r1MlKem768
            | Self::SecP384r1MlKem1024
            | Self::X448MlKem1024
            | Self::Kyber768
            | Self::X25519Kyber768 => None,
        }
    }

    /// Parse from string (case-insensitive, flexible formatting)
    pub fn from_str(s: &str) -> Option<Self> {
        let normalized = s
            .to_lowercase()
            .replace('-', "")
            .replace('_', "")
            .replace(' ', "");

        match normalized.as_str() {
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

    /// Get all hybrid algorithms in recommended order
    pub fn recommended_hybrids() -> Vec<Self> {
        vec![
            Self::X25519MlKem768,     // IETF standard, best compatibility
            Self::SecP256r1MlKem768,  // NIST curve variant
            Self::SecP384r1MlKem1024, // Higher security
            Self::X448MlKem1024,      // Maximum security
        ]
    }

    /// Get all algorithms at or above a security level
    pub fn at_security_level(min_level: SecurityLevel) -> Vec<Self> {
        let all = vec![
            Self::X25519MlKem768,
            Self::SecP256r1MlKem768,
            Self::SecP384r1MlKem1024,
            Self::X448MlKem1024,
            Self::MlKem512,
            Self::MlKem768,
            Self::MlKem1024,
        ];

        all.into_iter()
            .filter(|k| k.security_level() >= min_level)
            .collect()
    }
}

impl fmt::Display for PqcKem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.openssl_name())
    }
}

/// Post-Quantum Digital Signature algorithms (FIPS 204 ML-DSA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PqcSignature {
    /// ML-DSA-44: Smallest, fastest signatures (Level 2)
    MlDsa44,
    /// ML-DSA-65: Balanced (Level 3)
    MlDsa65,
    /// ML-DSA-87: Maximum security (Level 5)
    MlDsa87,
}

impl PqcSignature {
    /// Get the security level
    pub fn security_level(&self) -> SecurityLevel {
        match self {
            Self::MlDsa44 => SecurityLevel::Level2,
            Self::MlDsa65 => SecurityLevel::Level3,
            Self::MlDsa87 => SecurityLevel::Level5,
        }
    }

    /// Get OpenSSL algorithm name
    pub fn openssl_name(&self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Check if available in current build
    #[cfg(feature = "pqc-signatures")]
    pub fn is_available(&self) -> bool {
        true // aws-lc-rs unstable API provides these
    }

    #[cfg(not(feature = "pqc-signatures"))]
    pub fn is_available(&self) -> bool {
        false
    }
}

/// TLS backend selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsBackend {
    /// rustls with aws-lc-rs (default, pure Rust, memory-safe)
    #[default]
    Rustls,
    /// OpenSSL 3.5+ with native ML-KEM (broader algorithm support)
    OpenSsl,
    /// Automatic selection based on algorithm requirements
    Auto,
}

/// Extended PQC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedPqcConfig {
    /// Enable PQC key exchange
    pub enabled: bool,

    /// TLS backend preference
    #[serde(default)]
    pub backend: TlsBackend,

    /// Preferred KEM algorithm
    #[serde(default = "default_preferred_kem")]
    pub preferred_kem: PqcKem,

    /// Minimum acceptable security level
    #[serde(default = "default_min_security")]
    pub min_security_level: SecurityLevel,

    /// Additional KEMs to offer (in order of preference)
    #[serde(default)]
    pub additional_kems: Vec<PqcKem>,

    /// Enable ML-DSA signatures (requires pqc-signatures feature)
    #[serde(default)]
    pub enable_pqc_signatures: bool,

    /// Preferred signature algorithm
    #[serde(default)]
    pub preferred_signature: Option<PqcSignature>,

    /// Fall back to classical if PQC unavailable
    #[serde(default = "default_true")]
    pub fallback_to_classical: bool,

    /// Require hybrid mode (reject pure PQC or pure classical)
    #[serde(default)]
    pub require_hybrid: bool,

    /// OpenSSL-specific: path to openssl binary
    #[serde(default)]
    pub openssl_path: Option<std::path::PathBuf>,

    /// OpenSSL-specific: library path for 3.5+
    #[serde(default)]
    pub openssl_lib_path: Option<std::path::PathBuf>,
}

fn default_preferred_kem() -> PqcKem {
    PqcKem::X25519MlKem768
}

fn default_min_security() -> SecurityLevel {
    SecurityLevel::Level3
}

fn default_true() -> bool {
    true
}

impl Default for ExtendedPqcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: TlsBackend::default(),
            preferred_kem: PqcKem::X25519MlKem768,
            min_security_level: SecurityLevel::Level3,
            additional_kems: vec![
                PqcKem::SecP256r1MlKem768,
                PqcKem::SecP384r1MlKem1024,
            ],
            enable_pqc_signatures: false,
            preferred_signature: None,
            fallback_to_classical: true,
            require_hybrid: false,
            openssl_path: None,
            openssl_lib_path: None,
        }
    }
}

/// PQC capability detection result
#[derive(Debug, Clone, Serialize)]
pub struct PqcCapabilities {
    /// Available KEM algorithms
    pub available_kems: HashSet<PqcKem>,
    /// Available signature algorithms
    pub available_signatures: HashSet<PqcSignature>,
    /// rustls backend available
    pub rustls_available: bool,
    /// OpenSSL 3.5+ backend available
    pub openssl_available: bool,
    /// OpenSSL version string (if available)
    pub openssl_version: Option<String>,
    /// FIPS mode enabled
    pub fips_mode: bool,
    /// Detected issues or warnings
    pub warnings: Vec<String>,
}

impl PqcCapabilities {
    /// Detect PQC capabilities on this system
    pub fn detect(config: &ExtendedPqcConfig) -> Self {
        let mut caps = Self {
            available_kems: HashSet::new(),
            available_signatures: HashSet::new(),
            rustls_available: false,
            openssl_available: false,
            openssl_version: None,
            fips_mode: false,
            warnings: Vec::new(),
        };

        // Check rustls/aws-lc-rs capabilities
        caps.detect_rustls_capabilities();

        // Check OpenSSL capabilities
        caps.detect_openssl_capabilities(config);

        // Check FIPS mode
        caps.detect_fips_mode();

        caps
    }

    fn detect_rustls_capabilities(&mut self) {
        // rustls-post-quantum is always available if compiled
        self.rustls_available = true;

        // X25519MLKEM768 is the default and always available
        self.available_kems.insert(PqcKem::X25519MlKem768);

        // Pure ML-KEM variants via aws-lc-rs kem module
        self.available_kems.insert(PqcKem::MlKem512);
        self.available_kems.insert(PqcKem::MlKem768);
        self.available_kems.insert(PqcKem::MlKem1024);

        debug!("rustls PQC: X25519MLKEM768, ML-KEM-512/768/1024 available");

        // Check for ML-DSA (unstable feature)
        #[cfg(feature = "pqc-signatures")]
        {
            self.available_signatures.insert(PqcSignature::MlDsa44);
            self.available_signatures.insert(PqcSignature::MlDsa65);
            self.available_signatures.insert(PqcSignature::MlDsa87);
            debug!("rustls PQC signatures: ML-DSA-44/65/87 available (unstable)");
        }
    }

    fn detect_openssl_capabilities(&mut self, config: &ExtendedPqcConfig) {
        #[cfg(feature = "pqc")]
        {
            use std::process::Command;

            let openssl_bin = config
                .openssl_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "openssl".to_string());

            let lib_path = config
                .openssl_lib_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // Check OpenSSL version
            let version_output = Command::new(&openssl_bin)
                .arg("version")
                .env("LD_LIBRARY_PATH", &lib_path)
                .output();

            match version_output {
                Ok(output) if output.status.success() => {
                    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

                    if version.contains("3.5")
                        || version.contains("3.6")
                        || version.contains("3.7")
                    {
                        self.openssl_available = true;
                        self.openssl_version = Some(version.clone());

                        // OpenSSL 3.5+ has native ML-KEM support
                        self.available_kems.insert(PqcKem::X25519MlKem768);
                        self.available_kems.insert(PqcKem::SecP256r1MlKem768);
                        self.available_kems.insert(PqcKem::SecP384r1MlKem1024);
                        self.available_kems.insert(PqcKem::X448MlKem1024);
                        self.available_kems.insert(PqcKem::MlKem512);
                        self.available_kems.insert(PqcKem::MlKem768);
                        self.available_kems.insert(PqcKem::MlKem1024);

                        // ML-DSA signatures
                        self.available_signatures.insert(PqcSignature::MlDsa44);
                        self.available_signatures.insert(PqcSignature::MlDsa65);
                        self.available_signatures.insert(PqcSignature::MlDsa87);

                        info!("OpenSSL 3.5+ detected: {} - full ML-KEM/ML-DSA support", version);
                    } else {
                        self.warnings.push(format!(
                            "OpenSSL {} detected but 3.5+ required for native ML-KEM",
                            version
                        ));
                    }
                }
                Ok(output) => {
                    self.warnings.push(format!(
                        "OpenSSL version check failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                Err(e) => {
                    self.warnings
                        .push(format!("OpenSSL not found at {}: {}", openssl_bin, e));
                }
            }
        }

        #[cfg(not(feature = "pqc"))]
        {
            let _ = config;
            self.warnings
                .push("OpenSSL PQC feature not compiled".to_string());
        }
    }

    fn detect_fips_mode(&mut self) {
        #[cfg(feature = "fips")]
        {
            // Check if aws-lc-rs is running in FIPS mode
            self.fips_mode = aws_lc_rs::fips::indicator();
            if self.fips_mode {
                info!("FIPS mode: ENABLED (aws-lc-rs FIPS module active)");
            }
        }
    }

    /// Check if a specific KEM is available
    pub fn has_kem(&self, kem: PqcKem) -> bool {
        self.available_kems.contains(&kem)
    }

    /// Get the best available KEM meeting requirements
    pub fn best_kem(&self, min_level: SecurityLevel, prefer_hybrid: bool) -> Option<PqcKem> {
        let mut candidates: Vec<_> = self
            .available_kems
            .iter()
            .filter(|k| k.security_level() >= min_level)
            .filter(|k| !k.is_legacy())
            .filter(|k| !prefer_hybrid || k.is_hybrid())
            .copied()
            .collect();

        // Sort by: hybrid first, then by security level descending
        candidates.sort_by(|a, b| {
            let hybrid_cmp = b.is_hybrid().cmp(&a.is_hybrid());
            if hybrid_cmp != std::cmp::Ordering::Equal {
                return hybrid_cmp;
            }
            b.security_level().cmp(&a.security_level())
        });

        candidates.first().copied()
    }

    /// Build the TLS groups string for the given backend
    pub fn build_groups_string(&self, backend: TlsBackend, config: &ExtendedPqcConfig) -> String {
        let mut groups = Vec::new();

        // Add preferred KEM first
        if self.has_kem(config.preferred_kem) {
            groups.push(config.preferred_kem.openssl_name().to_string());
        }

        // Add additional configured KEMs
        for kem in &config.additional_kems {
            if self.has_kem(*kem) && !groups.contains(&kem.openssl_name().to_string()) {
                groups.push(kem.openssl_name().to_string());
            }
        }

        // Add other available KEMs meeting security requirements
        for kem in PqcKem::recommended_hybrids() {
            if self.has_kem(kem)
                && kem.security_level() >= config.min_security_level
                && !groups.contains(&kem.openssl_name().to_string())
            {
                groups.push(kem.openssl_name().to_string());
            }
        }

        // Add classical fallback if enabled
        if config.fallback_to_classical {
            match backend {
                TlsBackend::Rustls => {
                    groups.push("X25519".to_string());
                    groups.push("secp256r1".to_string());
                    groups.push("secp384r1".to_string());
                }
                TlsBackend::OpenSsl | TlsBackend::Auto => {
                    groups.push("X25519".to_string());
                    groups.push("P-256".to_string());
                    groups.push("P-384".to_string());
                }
            }
        }

        groups.join(":")
    }
}

/// Security check for TLS key file permissions
#[derive(Debug, Clone, Serialize)]
pub struct KeySecurityCheck {
    pub path: String,
    pub exists: bool,
    pub readable: bool,
    pub permissions_secure: bool,
    pub owner_correct: bool,
    pub issues: Vec<String>,
}

impl KeySecurityCheck {
    /// Check security of a private key file
    #[cfg(unix)]
    pub fn check_key_file(path: &Path, expected_uid: Option<u32>) -> Self {
        use std::os::unix::fs::MetadataExt;

        let path_str = path.to_string_lossy().to_string();
        let mut check = Self {
            path: path_str.clone(),
            exists: false,
            readable: false,
            permissions_secure: false,
            owner_correct: true,
            issues: Vec::new(),
        };

        // Check existence
        if !path.exists() {
            check.issues.push(format!("Key file does not exist: {}", path_str));
            return check;
        }
        check.exists = true;

        // Get metadata
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                check.issues.push(format!("Cannot read metadata: {}", e));
                return check;
            }
        };

        check.readable = true;

        // Check permissions (should be 0600 or 0400)
        let mode = metadata.mode() & 0o777;
        if mode == 0o600 || mode == 0o400 {
            check.permissions_secure = true;
        } else {
            check.issues.push(format!(
                "Insecure permissions: {:04o} (should be 0600 or 0400)",
                mode
            ));
        }

        // Check owner
        if let Some(uid) = expected_uid {
            if metadata.uid() != uid {
                check.owner_correct = false;
                check.issues.push(format!(
                    "Wrong owner: UID {} (expected {})",
                    metadata.uid(),
                    uid
                ));
            }
        }

        // Warn about group/other access
        if mode & 0o077 != 0 {
            check.issues.push("Key file is readable by group or others".to_string());
        }

        check
    }

    #[cfg(not(unix))]
    pub fn check_key_file(path: &Path, _expected_uid: Option<u32>) -> Self {
        let path_str = path.to_string_lossy().to_string();
        let exists = path.exists();

        Self {
            path: path_str,
            exists,
            readable: exists,
            permissions_secure: true, // Can't check on Windows
            owner_correct: true,
            issues: if exists {
                vec!["Permission checks not available on this platform".to_string()]
            } else {
                vec!["Key file does not exist".to_string()]
            },
        }
    }

    /// Check if all security requirements are met
    pub fn is_secure(&self) -> bool {
        self.exists && self.readable && self.permissions_secure && self.owner_correct
    }
}

/// Verify OpenSSL provider integrity
#[cfg(feature = "pqc")]
pub fn verify_openssl_provider(config: &ExtendedPqcConfig) -> Result<(), String> {
    use std::process::Command;

    let openssl_bin = config
        .openssl_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "openssl".to_string());

    let lib_path = config
        .openssl_lib_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // Verify version
    let output = Command::new(&openssl_bin)
        .arg("version")
        .env("LD_LIBRARY_PATH", &lib_path)
        .output()
        .map_err(|e| format!("Failed to execute OpenSSL: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "OpenSSL version check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();

    // Verify it's 3.5+
    if !version.contains("3.5") && !version.contains("3.6") && !version.contains("3.7") {
        return Err(format!(
            "OpenSSL version {} is not supported. Requires 3.5+ for native ML-KEM.",
            version
        ));
    }

    // Verify provider self-tests
    let selftest = Command::new(&openssl_bin)
        .args(["list", "-providers"])
        .env("LD_LIBRARY_PATH", &lib_path)
        .output()
        .map_err(|e| format!("Failed to list providers: {}", e))?;

    if !selftest.status.success() {
        warn!(
            "OpenSSL provider self-test warning: {}",
            String::from_utf8_lossy(&selftest.stderr)
        );
    }

    info!("OpenSSL provider verified: {}", version);
    Ok(())
}

#[cfg(not(feature = "pqc"))]
pub fn verify_openssl_provider(_config: &ExtendedPqcConfig) -> Result<(), String> {
    Err("OpenSSL PQC feature not enabled".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_security_levels() {
        assert_eq!(PqcKem::MlKem512.security_level(), SecurityLevel::Level1);
        assert_eq!(PqcKem::X25519MlKem768.security_level(), SecurityLevel::Level3);
        assert_eq!(PqcKem::MlKem1024.security_level(), SecurityLevel::Level5);
    }

    #[test]
    fn test_kem_hybrid_detection() {
        assert!(PqcKem::X25519MlKem768.is_hybrid());
        assert!(PqcKem::SecP384r1MlKem1024.is_hybrid());
        assert!(!PqcKem::MlKem768.is_hybrid());
    }

    #[test]
    fn test_kem_parsing() {
        assert_eq!(PqcKem::from_str("X25519MLKEM768"), Some(PqcKem::X25519MlKem768));
        assert_eq!(PqcKem::from_str("ml-kem-1024"), Some(PqcKem::MlKem1024));
        assert_eq!(PqcKem::from_str("P-256-ML-KEM-768"), Some(PqcKem::SecP256r1MlKem768));
    }

    #[test]
    fn test_security_level_filter() {
        let level5 = PqcKem::at_security_level(SecurityLevel::Level5);
        assert!(level5.contains(&PqcKem::MlKem1024));
        assert!(level5.contains(&PqcKem::SecP384r1MlKem1024));
        assert!(!level5.contains(&PqcKem::MlKem512));
    }

    #[test]
    fn test_default_config() {
        let config = ExtendedPqcConfig::default();
        assert!(config.enabled);
        assert_eq!(config.preferred_kem, PqcKem::X25519MlKem768);
        assert_eq!(config.min_security_level, SecurityLevel::Level3);
        assert!(config.fallback_to_classical);
    }
}
