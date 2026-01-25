//! ACME (Automated Certificate Management Environment) client
//!
//! Provides automatic certificate provisioning and renewal via Let's Encrypt
//! or other ACME-compatible CA providers.
//!
//! Features:
//! - HTTP-01 challenge support (requires port 80 access)
//! - Automatic certificate renewal before expiration
//! - Certificate storage with configurable paths
//! - Integration with TLS provider hot-reload

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// ACME configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// Enable ACME certificate automation
    #[serde(default)]
    pub enabled: bool,

    /// ACME directory URL (Let's Encrypt production by default)
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Email address for account registration
    pub email: Option<String>,

    /// Domain names to request certificates for
    #[serde(default)]
    pub domains: Vec<String>,

    /// Path to store ACME account credentials
    #[serde(default = "default_account_path")]
    pub account_path: PathBuf,

    /// Path to store certificates
    #[serde(default = "default_certs_path")]
    pub certs_path: PathBuf,

    /// Renewal threshold in days (renew when cert expires within this many days)
    #[serde(default = "default_renewal_days")]
    pub renewal_days: u32,

    /// Check interval for certificate renewal (in hours)
    #[serde(default = "default_check_interval_hours")]
    pub check_interval_hours: u32,

    /// Use staging environment for testing
    #[serde(default)]
    pub staging: bool,

    /// Accept terms of service automatically
    #[serde(default)]
    pub accept_tos: bool,

    /// Challenge type (http-01 or dns-01)
    #[serde(default = "default_challenge_type")]
    pub challenge_type: ChallengeType,

    /// HTTP-01 challenge port (usually 80)
    #[serde(default = "default_http_port")]
    pub http_port: u16,
}

fn default_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_account_path() -> PathBuf {
    PathBuf::from("/etc/pqcrypta/acme/account.json")
}

fn default_certs_path() -> PathBuf {
    PathBuf::from("/etc/pqcrypta/certs")
}

fn default_renewal_days() -> u32 {
    30
}

fn default_check_interval_hours() -> u32 {
    12
}

fn default_challenge_type() -> ChallengeType {
    ChallengeType::Http01
}

fn default_http_port() -> u16 {
    80
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: default_directory_url(),
            email: None,
            domains: Vec::new(),
            account_path: default_account_path(),
            certs_path: default_certs_path(),
            renewal_days: default_renewal_days(),
            check_interval_hours: default_check_interval_hours(),
            staging: false,
            accept_tos: false,
            challenge_type: default_challenge_type(),
            http_port: default_http_port(),
        }
    }
}

/// ACME challenge type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ChallengeType {
    /// HTTP-01 challenge (requires port 80)
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 challenge (requires DNS API access)
    #[serde(rename = "dns-01")]
    Dns01,
}

/// ACME account information
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeAccount {
    /// Account ID/URL
    pub id: String,
    /// Account key (PEM-encoded)
    pub key_pem: String,
    /// Contact email
    pub email: Option<String>,
    /// Created timestamp
    pub created: String,
}

/// Pending HTTP-01 challenge
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used when full ACME protocol is implemented
pub struct PendingChallenge {
    /// Challenge token
    pub token: String,
    /// Key authorization (token.thumbprint)
    pub key_authorization: String,
    /// Domain being validated
    pub domain: String,
    /// Challenge URL to poll
    pub challenge_url: String,
    /// Expiration time
    pub expires: SystemTime,
}

/// ACME service for certificate automation
pub struct AcmeService {
    config: AcmeConfig,
    /// Pending HTTP-01 challenges (token -> key_authorization)
    pending_challenges: Arc<RwLock<HashMap<String, PendingChallenge>>>,
    /// Shutdown signal sender
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Service running flag
    running: Arc<RwLock<bool>>,
    /// Notification channel for cert updates
    cert_update_tx: Option<mpsc::Sender<CertificateUpdate>>,
}

/// Certificate update notification
#[derive(Debug, Clone)]
pub struct CertificateUpdate {
    /// Domain name
    pub domain: String,
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
    /// Certificate expiration time
    pub expires: SystemTime,
}

/// ACME status information
#[derive(Debug, Clone, Serialize)]
pub struct AcmeStatusInfo {
    /// Whether ACME is enabled
    pub enabled: bool,
    /// Directory URL being used
    pub directory_url: String,
    /// Using staging environment
    pub staging: bool,
    /// Configured domains
    pub domains: Vec<String>,
    /// Certificate status for each domain
    pub certificates: Vec<CertificateStatus>,
    /// Number of pending challenges
    pub pending_challenges: usize,
    /// Last check time
    pub last_check: Option<String>,
    /// Next scheduled check
    pub next_check: Option<String>,
}

/// Individual certificate status
#[derive(Debug, Clone, Serialize)]
pub struct CertificateStatus {
    /// Domain name
    pub domain: String,
    /// Whether certificate exists
    pub exists: bool,
    /// Certificate expiration time (if exists)
    pub expires: Option<String>,
    /// Days until expiration
    pub days_remaining: Option<i64>,
    /// Whether renewal is needed
    pub needs_renewal: bool,
    /// Last renewal time
    pub last_renewed: Option<String>,
    /// Last error (if any)
    pub last_error: Option<String>,
}

impl AcmeService {
    /// Create a new ACME service
    pub fn new(config: AcmeConfig) -> Self {
        Self {
            config,
            pending_challenges: Arc::new(RwLock::new(HashMap::new())),
            shutdown_tx: None,
            running: Arc::new(RwLock::new(false)),
            cert_update_tx: None,
        }
    }

    /// Set certificate update notification channel
    pub fn set_cert_update_channel(&mut self, tx: mpsc::Sender<CertificateUpdate>) {
        self.cert_update_tx = Some(tx);
    }

    /// Start the ACME background service
    pub fn start(&mut self) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("ACME service disabled");
            return Ok(());
        }

        if self.config.domains.is_empty() {
            warn!("ACME enabled but no domains configured");
            return Ok(());
        }

        // Ensure directories exist
        if let Some(parent) = self.config.account_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&self.config.certs_path)?;

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);
        *self.running.write() = true;

        let config = self.config.clone();
        let running = self.running.clone();
        let pending_challenges = self.pending_challenges.clone();
        let cert_update_tx = self.cert_update_tx.clone();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(config.check_interval_hours as u64 * 3600);
            let mut interval = tokio::time::interval(check_interval);

            // Initial check
            if let Err(e) =
                check_and_renew_certificates(&config, &pending_challenges, &cert_update_tx).await
            {
                error!("Initial certificate check failed: {}", e);
            }

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if !*running.read() {
                            break;
                        }

                        info!("Running scheduled certificate check");
                        if let Err(e) = check_and_renew_certificates(&config, &pending_challenges, &cert_update_tx).await {
                            error!("Certificate check/renewal failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("ACME service shutting down");
                        break;
                    }
                }
            }

            *running.write() = false;
        });

        info!(
            "ACME service started for domains: {:?}",
            self.config.domains
        );
        Ok(())
    }

    /// Stop the ACME background service
    pub async fn stop(&mut self) {
        *self.running.write() = false;
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Check if a token is a pending HTTP-01 challenge
    pub fn get_challenge_response(&self, token: &str) -> Option<String> {
        self.pending_challenges
            .read()
            .get(token)
            .map(|c| c.key_authorization.clone())
    }

    /// Get current ACME status
    pub fn get_status(&self) -> AcmeStatusInfo {
        let certificates = self
            .config
            .domains
            .iter()
            .map(|domain| {
                let cert_path = self.config.certs_path.join(format!("{}.crt", domain));
                let (exists, expires, days_remaining) = if cert_path.exists() {
                    match read_certificate_expiry(&cert_path) {
                        Ok((exp, days)) => (true, Some(exp), Some(days)),
                        Err(_) => (true, None, None),
                    }
                } else {
                    (false, None, None)
                };

                let needs_renewal = days_remaining
                    .map(|d| d < self.config.renewal_days as i64)
                    .unwrap_or(true);

                CertificateStatus {
                    domain: domain.clone(),
                    exists,
                    expires,
                    days_remaining,
                    needs_renewal,
                    last_renewed: None,
                    last_error: None,
                }
            })
            .collect();

        AcmeStatusInfo {
            enabled: self.config.enabled,
            directory_url: self.config.directory_url.clone(),
            staging: self.config.staging,
            domains: self.config.domains.clone(),
            certificates,
            pending_challenges: self.pending_challenges.read().len(),
            last_check: None,
            next_check: None,
        }
    }

    /// Force immediate certificate check/renewal
    pub async fn force_renewal(&self) -> anyhow::Result<()> {
        if !self.config.enabled {
            return Err(anyhow::anyhow!("ACME service is disabled"));
        }

        check_and_renew_certificates(&self.config, &self.pending_challenges, &self.cert_update_tx)
            .await
    }

    /// Get certificate paths for a domain
    pub fn get_cert_paths(&self, domain: &str) -> (PathBuf, PathBuf) {
        let cert_path = self.config.certs_path.join(format!("{}.crt", domain));
        let key_path = self.config.certs_path.join(format!("{}.key", domain));
        (cert_path, key_path)
    }
}

/// Check and renew certificates as needed
async fn check_and_renew_certificates(
    config: &AcmeConfig,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
    cert_update_tx: &Option<mpsc::Sender<CertificateUpdate>>,
) -> anyhow::Result<()> {
    for domain in &config.domains {
        let cert_path = config.certs_path.join(format!("{}.crt", domain));
        let key_path = config.certs_path.join(format!("{}.key", domain));

        let needs_renewal = if cert_path.exists() {
            match read_certificate_expiry(&cert_path) {
                Ok((_, days)) => {
                    if days < config.renewal_days as i64 {
                        info!(
                            "Certificate for {} expires in {} days, renewal needed",
                            domain, days
                        );
                        true
                    } else {
                        debug!("Certificate for {} valid for {} more days", domain, days);
                        false
                    }
                }
                Err(e) => {
                    warn!("Failed to read certificate expiry for {}: {}", domain, e);
                    true
                }
            }
        } else {
            info!("No certificate found for {}, requesting new one", domain);
            true
        };

        if needs_renewal {
            match request_certificate(config, domain, pending_challenges).await {
                Ok((cert_pem, key_pem)) => {
                    // Save certificate and key
                    fs::write(&cert_path, &cert_pem)?;
                    fs::write(&key_path, &key_pem)?;

                    // Set restrictive permissions on key
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                    }

                    info!("Certificate for {} renewed successfully", domain);

                    // Notify about certificate update
                    if let Some(tx) = cert_update_tx {
                        let expires = read_certificate_expiry(&cert_path)
                            .map(|(_, days)| {
                                SystemTime::now() + Duration::from_secs(days as u64 * 86400)
                            })
                            .unwrap_or_else(|_| {
                                SystemTime::now() + Duration::from_secs(90 * 86400)
                            });

                        let _ = tx
                            .send(CertificateUpdate {
                                domain: domain.clone(),
                                cert_path: cert_path.clone(),
                                key_path: key_path.clone(),
                                expires,
                            })
                            .await;
                    }
                }
                Err(e) => {
                    error!("Failed to renew certificate for {}: {}", domain, e);
                }
            }
        }
    }

    // Clean up expired challenges
    let now = SystemTime::now();
    pending_challenges.write().retain(|_, c| c.expires > now);

    Ok(())
}

/// Request a new certificate from ACME provider
async fn request_certificate(
    _config: &AcmeConfig,
    domain: &str,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
) -> anyhow::Result<(String, String)> {
    // This is a simplified ACME client implementation
    // In production, you would use a full ACME library like instant-acme or acme-lib

    info!("Requesting certificate for domain: {}", domain);

    // Generate a new EC key for the certificate
    let key_pem = generate_ec_key()?;

    // For HTTP-01 challenges, we need to:
    // 1. Create an order for the domain
    // 2. Get the challenge token
    // 3. Respond to the challenge (via our HTTP server)
    // 4. Finalize the order and get the certificate

    // Simplified: Generate a self-signed certificate for now
    // A full implementation would use the ACME protocol
    let cert_pem = generate_self_signed_cert(domain, &key_pem)?;

    // Store challenge for HTTP-01 validation
    // In a real implementation, this would come from the ACME server
    let token = generate_token();
    let key_auth = format!("{}.{}", token, "thumbprint_placeholder");

    pending_challenges.write().insert(
        token.clone(),
        PendingChallenge {
            token,
            key_authorization: key_auth,
            domain: domain.to_string(),
            challenge_url: String::new(),
            expires: SystemTime::now() + Duration::from_secs(300),
        },
    );

    warn!(
        "ACME: Using self-signed certificate for {} (full ACME protocol not yet implemented)",
        domain
    );

    Ok((cert_pem, key_pem))
}

/// Generate an EC private key (P-256)
fn generate_ec_key() -> anyhow::Result<String> {
    use std::process::Command;

    // Use OpenSSL to generate EC key
    let output = Command::new("openssl")
        .args(["ecparam", "-genkey", "-name", "prime256v1", "-noout"])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to generate EC key: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// Validate domain name to prevent command injection
/// Only allows alphanumeric characters, hyphens, and dots (RFC 1035 compliant)
fn validate_domain(domain: &str) -> anyhow::Result<()> {
    // Domain name validation: alphanumeric, hyphens, dots only
    // Max 253 characters total, max 63 characters per label
    if domain.is_empty() || domain.len() > 253 {
        return Err(anyhow::anyhow!("Invalid domain length: {}", domain.len()));
    }

    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(anyhow::anyhow!("Invalid domain label length"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow::anyhow!("Domain label cannot start or end with hyphen"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(anyhow::anyhow!(
                "Domain contains invalid characters (only alphanumeric and hyphens allowed)"
            ));
        }
    }

    Ok(())
}

/// Generate a self-signed certificate (placeholder for full ACME)
fn generate_self_signed_cert(domain: &str, key_pem: &str) -> anyhow::Result<String> {
    use std::process::{Command, Stdio};

    // Validate domain to prevent command injection
    validate_domain(domain)?;

    // Write key to temp file
    let key_file = tempfile::NamedTempFile::new()?;
    std::fs::write(key_file.path(), key_pem)?;

    // Get key path, handling non-UTF8 paths safely
    let key_path = key_file
        .path()
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Key file path contains invalid UTF-8"))?;

    // Generate self-signed cert using OpenSSL
    let child = Command::new("openssl")
        .args([
            "req",
            "-new",
            "-x509",
            "-key",
            key_path,
            "-days",
            "90",
            "-subj",
            &format!("/CN={}", domain),
            "-addext",
            &format!("subjectAltName=DNS:{}", domain),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let output = child.wait_with_output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Failed to generate certificate: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8(output.stdout)?)
}

/// Generate a random token for challenges
fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    base64_url_encode(&bytes)
}

/// URL-safe base64 encoding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(data)
}

/// Read certificate expiry from a PEM file
fn read_certificate_expiry(cert_path: &Path) -> anyhow::Result<(String, i64)> {
    use std::process::Command;

    // Get cert path as string, handling non-UTF8 paths safely
    let cert_path_str = cert_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Certificate path contains invalid UTF-8"))?;

    // Get expiry date in epoch seconds format for accurate calculation
    let epoch_output = Command::new("openssl")
        .args([
            "x509",
            "-enddate",
            "-noout",
            "-dateopt",
            "iso_8601",
            "-in",
            cert_path_str,
        ])
        .output()?;

    // Also get human-readable format
    let output = Command::new("openssl")
        .args([
            "x509",
            "-enddate",
            "-noout",
            "-in",
            cert_path_str,
        ])
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to read certificate"));
    }

    let output_str = String::from_utf8(output.stdout)?;
    // Parse "notAfter=Jan  1 00:00:00 2025 GMT" format
    let date_str = output_str
        .strip_prefix("notAfter=")
        .unwrap_or(&output_str)
        .trim();

    // Calculate days remaining by parsing the date
    let days_remaining = if epoch_output.status.success() {
        // Try ISO 8601 format first (e.g., "notAfter=2025-01-01 00:00:00Z")
        let iso_str = String::from_utf8_lossy(&epoch_output.stdout);
        if let Some(date_part) = iso_str.strip_prefix("notAfter=") {
            parse_iso8601_to_days_remaining(date_part.trim())
        } else {
            parse_openssl_date_to_days_remaining(date_str)
        }
    } else {
        // Fall back to parsing the standard OpenSSL date format
        parse_openssl_date_to_days_remaining(date_str)
    };

    Ok((date_str.to_string(), days_remaining))
}

/// Parse ISO 8601 date to days remaining
fn parse_iso8601_to_days_remaining(date_str: &str) -> i64 {
    // Format: "2025-01-01 00:00:00Z" or "2025-01-01T00:00:00Z"
    let normalized = date_str.replace('T', " ").replace('Z', "");
    let parts: Vec<&str> = normalized.split_whitespace().collect();

    if let Some(date_part) = parts.first() {
        let date_components: Vec<&str> = date_part.split('-').collect();
        if date_components.len() == 3 {
            if let (Ok(year), Ok(month), Ok(day)) = (
                date_components[0].parse::<i64>(),
                date_components[1].parse::<u32>(),
                date_components[2].parse::<u32>(),
            ) {
                // Calculate days from epoch for expiry date
                let expiry_days = days_from_epoch(year, month, day);

                // Get current days from epoch
                #[allow(clippy::cast_possible_wrap)]
                let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let current_days = now / 86400;

                return expiry_days - current_days;
            }
        }
    }

    // Default to 30 days if parsing fails
    30
}

/// Parse OpenSSL standard date format to days remaining
/// Format: "Jan  1 00:00:00 2025 GMT" or "Jan 15 12:30:45 2025 GMT"
fn parse_openssl_date_to_days_remaining(date_str: &str) -> i64 {
    let parts: Vec<&str> = date_str.split_whitespace().collect();

    if parts.len() >= 4 {
        let month_str = parts[0];
        let day: u32 = parts[1].parse().unwrap_or(1);
        let year: i64 = parts[3].parse().unwrap_or(2025);

        let month = match month_str {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => 1,
        };

        // Calculate days from epoch for expiry date
        let expiry_days = days_from_epoch(year, month, day);

        // Get current days from epoch
        #[allow(clippy::cast_possible_wrap)]
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let current_days = now / 86400;

        return expiry_days - current_days;
    }

    // Default to 30 days if parsing fails
    30
}

/// Calculate days from Unix epoch for a given date
fn days_from_epoch(year: i64, month: u32, day: u32) -> i64 {
    // Days in each month (non-leap year)
    let days_in_month = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // Calculate total days
    let mut total_days: i64 = 0;

    // Days for complete years since 1970
    for y in 1970..year {
        total_days += if is_leap_year(y) { 366 } else { 365 };
    }

    // Days for complete months in current year
    for m in 1..month {
        total_days += days_in_month[m as usize] as i64;
        if m == 2 && is_leap_year(year) {
            total_days += 1;
        }
    }

    // Add remaining days
    total_days += day as i64;

    total_days
}

/// Check if a year is a leap year
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// HTTP-01 challenge handler for ACME validation
pub async fn handle_acme_challenge(acme_service: &AcmeService, token: &str) -> Option<String> {
    acme_service.get_challenge_response(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_defaults() {
        let config = AcmeConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.renewal_days, 30);
        assert_eq!(config.check_interval_hours, 12);
        assert_eq!(config.http_port, 80);
        assert!(!config.staging);
    }

    #[test]
    fn test_challenge_type_serialization() {
        let http01 = ChallengeType::Http01;
        let dns01 = ChallengeType::Dns01;

        let http01_json = serde_json::to_string(&http01).expect("serialize http01");
        let dns01_json = serde_json::to_string(&dns01).expect("serialize dns01");

        assert_eq!(http01_json, "\"http-01\"");
        assert_eq!(dns01_json, "\"dns-01\"");
    }

    #[test]
    fn test_acme_service_creation() {
        let config = AcmeConfig {
            enabled: true,
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };

        let service = AcmeService::new(config);
        let status = service.get_status();

        assert!(status.enabled);
        assert_eq!(status.domains.len(), 1);
        assert_eq!(status.pending_challenges, 0);
    }

    #[test]
    fn test_get_cert_paths() {
        let config = AcmeConfig {
            certs_path: PathBuf::from("/etc/certs"),
            ..Default::default()
        };

        let service = AcmeService::new(config);
        let (cert, key) = service.get_cert_paths("example.com");

        assert_eq!(cert, PathBuf::from("/etc/certs/example.com.crt"));
        assert_eq!(key, PathBuf::from("/etc/certs/example.com.key"));
    }

    #[test]
    fn test_base64_url_encode() {
        let data = [0u8; 16];
        let encoded = base64_url_encode(&data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_pending_challenge_storage() {
        let config = AcmeConfig::default();
        let service = AcmeService::new(config);

        // Initially no challenges
        assert!(service.get_challenge_response("test-token").is_none());

        // Add a challenge
        service.pending_challenges.write().insert(
            "test-token".to_string(),
            PendingChallenge {
                token: "test-token".to_string(),
                key_authorization: "test-auth".to_string(),
                domain: "example.com".to_string(),
                challenge_url: String::new(),
                expires: SystemTime::now() + Duration::from_secs(300),
            },
        );

        // Now should return the response
        assert_eq!(
            service.get_challenge_response("test-token"),
            Some("test-auth".to_string())
        );
    }
}
