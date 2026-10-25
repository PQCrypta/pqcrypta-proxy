//! ACME (Automated Certificate Management Environment) Client
//!
//! Fully functional ACME client implementing RFC 8555 for automatic certificate
//! provisioning and renewal. Works with any ACME-compatible CA:
//! - Let's Encrypt (production and staging)
//! - ZeroSSL
//! - Buypass
//! - Google Trust Services
//! - Private and internally hosted ACME servers
//!
//! Features:
//! - HTTP-01 challenge support
//! - IP address identifiers (RFC 8738) beside a domain, under an ACME profile
//! - Renewal when the CA's renewal information says (ARI, RFC 9773), else by
//!   the certificate's lifetime
//! - Account persistence and reuse
//! - Certificate storage with configurable paths
//! - Integration with TLS provider hot-reload

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;
use reqwest;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

#[cfg(feature = "acme")]
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier,
    ChallengeType as AcmeChallengeType, ExternalAccountKey, Identifier, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};

/// M-3: Validate a domain name for safe use in file-system paths.
///
/// Rejects any domain that contains characters that could escape the
/// configured `certs_path` directory:
///   - `/`  — path separator
///   - `..` — parent-directory component
///   - `\0` — null byte
///   - Non-ASCII bytes — not valid in RFC 1035 hostnames
///   - Empty string
///
/// Returns the domain unchanged if it passes validation, or an error message.
fn validate_domain_for_path(domain: &str) -> Result<String, &'static str> {
    if domain.is_empty() {
        return Err("domain is empty");
    }
    // Reject null bytes and non-ASCII
    if domain.contains('\0') || !domain.is_ascii() {
        return Err("domain contains non-ASCII or null bytes");
    }
    // Reject path separators (both Unix and Windows)
    if domain.contains('/') || domain.contains('\\') {
        return Err("domain contains path separators");
    }
    // Reject parent-directory escape
    if domain.split('.').any(|label| label == "..") || domain.starts_with("..") {
        return Err("domain contains parent-directory component");
    }
    // Reject labels that start/end with hyphens (RFC 1035) and
    // ensure only [A-Za-z0-9\-\.] are present
    let valid_chars = domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*');
    if !valid_chars {
        return Err("domain contains characters not allowed in RFC 1035 hostnames");
    }
    Ok(domain.to_string())
}

/// ACME configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// Enable ACME certificate automation
    #[serde(default)]
    pub enabled: bool,

    /// ACME directory URL (any ACME-compatible CA)
    /// Examples:
    /// - Let's Encrypt Production: <https://acme-v02.api.letsencrypt.org/directory>
    /// - Let's Encrypt Staging: <https://acme-staging-v02.api.letsencrypt.org/directory>
    /// - ZeroSSL: <https://acme.zerossl.com/v2/DV90>
    /// - Buypass: <https://api.buypass.com/acme/directory>
    /// - Google: <https://dv.acme-v02.api.pki.goog/directory>
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Email address for account registration (required by most CAs)
    pub email: Option<String>,

    /// Domain names to request certificates for
    #[serde(default)]
    pub domains: Vec<String>,

    /// IP addresses a domain's certificate also names (RFC 8738 identifiers),
    /// keyed by that domain, which must be in `domains`. A client connecting
    /// by address -- a DNS over HTTPS client given a name server's IP --
    /// verifies the certificate against the address, and both TLS stacks
    /// present a certificate that names addresses to a ClientHello with no
    /// server name. A CA validates an address by HTTP-01 or TLS-ALPN-01 only.
    #[serde(default)]
    pub ip_addresses: BTreeMap<String, Vec<IpAddr>>,

    /// ACME profile (draft-ietf-acme-profiles) for an order that carries IP
    /// addresses: Let's Encrypt issues them only under "shortlived", whose
    /// certificates last 160 hours.
    #[serde(default = "default_ip_profile")]
    pub ip_profile: String,

    /// Path to store ACME account credentials
    #[serde(default = "default_account_path")]
    pub account_path: PathBuf,

    /// Path to store certificates
    #[serde(default = "default_certs_path")]
    pub certs_path: PathBuf,

    /// Renewal threshold in days: renew when the certificate expires within
    /// this many days or within a third of its lifetime, whichever is less
    /// (a 160-hour certificate renews 53 hours early). Where the CA publishes
    /// renewal information (ARI, RFC 9773), its suggested window sets the time
    /// instead.
    #[serde(default = "default_renewal_days")]
    pub renewal_days: u32,

    /// Check interval for certificate renewal (in hours); a certificate whose
    /// renewal time comes sooner is checked then
    #[serde(default = "default_check_interval_hours")]
    pub check_interval_hours: u32,

    /// Use staging environment for testing (only applies to Let's Encrypt)
    #[serde(default)]
    pub staging: bool,

    /// Accept terms of service automatically
    #[serde(default = "default_true")]
    pub accept_tos: bool,

    /// Challenge type for domain names: http-01, or dns-01, whose TXT record
    /// is published by DNS UPDATE through `dns_update` (dns-account-01 where
    /// the CA offers it, so each node's account has its own record). An IP
    /// address is always validated by HTTP-01: RFC 8738 §7 allows no DNS
    /// challenge for one.
    #[serde(default = "default_challenge_type")]
    pub challenge_type: ChallengeType,

    /// Where dns-01 records are published: an UPDATE server and a TSIG key
    #[serde(default)]
    pub dns_update: Option<crate::acme_dns::DnsUpdateConfig>,

    /// HTTP-01 challenge port (usually 80)
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// External Account Binding (EAB) - required by some CAs like ZeroSSL
    #[serde(default)]
    pub eab_kid: Option<String>,

    /// External Account Binding HMAC key
    #[serde(default)]
    pub eab_hmac_key: Option<String>,

    /// RSA key size for certificates (2048 or 4096)
    #[serde(default = "default_key_size")]
    pub key_size: u32,

    /// Use ECDSA instead of RSA. When true, uses P-384 (secp384r1) by default.
    /// P-384 is 192-bit security (7680-bit RSA equivalent) and scores 100% on SSL Labs
    /// key exchange. P-256 is 128-bit and scores only 90%.
    #[serde(default)]
    pub use_ecdsa: bool,

    /// ECDSA curve to use when use_ecdsa = true.
    /// "P-384" (default, 192-bit, SSL Labs A+) or "P-256" (128-bit, SSL Labs A).
    #[serde(default = "default_ecdsa_curve")]
    pub ecdsa_curve: String,

    /// Submit issued certificates to Certificate Transparency logs (default true).
    #[serde(default = "default_true")]
    pub certificate_transparency: bool,

    /// CT logs to submit to (RFC 6962 base URLs, POST /ct/v1/add-chain).
    /// Empty (the default): from `ct_log_list`, one log per operator that
    /// accepts the certificate's expiry. A log takes only certificates that
    /// expire in its temporal interval, half a year a shard, so a fixed list
    /// goes stale: the Xenon 2025H1 shard that was the default answered 404.
    #[serde(default)]
    pub ct_logs: Vec<String>,

    /// The CT log list (v3 schema) that an empty `ct_logs` draws from
    #[serde(default = "default_ct_log_list")]
    pub ct_log_list: String,
}

fn default_ct_log_list() -> String {
    "https://www.gstatic.com/ct/log_list/v3/log_list.json".to_string()
}

fn default_ip_profile() -> String {
    "shortlived".to_string()
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

fn default_true() -> bool {
    true
}

fn default_key_size() -> u32 {
    2048
}

fn default_ecdsa_curve() -> String {
    "P-384".to_string()
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: default_directory_url(),
            email: None,
            domains: Vec::new(),
            ip_addresses: BTreeMap::new(),
            ip_profile: default_ip_profile(),
            account_path: default_account_path(),
            certs_path: default_certs_path(),
            renewal_days: default_renewal_days(),
            check_interval_hours: default_check_interval_hours(),
            staging: false,
            accept_tos: true,
            challenge_type: default_challenge_type(),
            dns_update: None,
            http_port: default_http_port(),
            eab_kid: None,
            eab_hmac_key: None,
            key_size: default_key_size(),
            use_ecdsa: false,
            ecdsa_curve: default_ecdsa_curve(),
            certificate_transparency: true,
            ct_logs: Vec::new(),
            ct_log_list: default_ct_log_list(),
        }
    }
}

impl AcmeConfig {
    /// The IP addresses `domain`'s certificate names besides the domain
    pub fn ip_addresses_for(&self, domain: &str) -> Vec<IpAddr> {
        self.ip_addresses
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(domain))
            .map(|(_, addresses)| addresses.clone())
            .unwrap_or_default()
    }
}

/// ACME challenge type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ChallengeType {
    /// HTTP-01 challenge (requires port 80)
    #[serde(rename = "http-01")]
    Http01,
    /// DNS-01 (or dns-account-01) challenge: a TXT record published by
    /// signed DNS UPDATE (`dns_update`)
    #[serde(rename = "dns-01")]
    Dns01,
}

/// Stored ACME account wrapper (for metadata)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StoredAccountWrapper {
    /// Directory URL this account was created with
    pub directory_url: String,
    /// Contact email
    pub email: Option<String>,
    /// Created timestamp
    pub created: String,
    /// The actual opaque credentials (serialized by instant-acme)
    pub credentials: serde_json::Value,
}

/// Pending HTTP-01 challenge
#[derive(Debug, Clone)]
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
    /// Last check timestamp
    last_check: Arc<RwLock<Option<SystemTime>>>,
    /// When the next scheduled check runs
    next_check: Arc<RwLock<Option<SystemTime>>>,
    /// Certificate status cache
    cert_status: Arc<RwLock<HashMap<String, CertificateStatus>>>,
    /// The CA's suggested renewal windows, by certificate
    renewal_windows: RenewalWindows,
}

/// A CA's suggested renewal window for one certificate (RFC 9773 §4.2), kept
/// until the CA's Retry-After says to ask again.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "acme"), allow(dead_code))]
struct RenewalWindow {
    /// Unix time the window opens
    start: i64,
    /// Unix time it closes
    end: i64,
    /// When to fetch it again
    refresh_after: SystemTime,
}

/// Suggested renewal windows by ARI certificate identifier (`aki.serial`)
type RenewalWindows = Arc<RwLock<HashMap<String, RenewalWindow>>>;

/// When a certificate renews.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenewalPlan {
    /// Unix time it renews at
    at: i64,
    /// The CA's suggested window `at` falls in (ARI); none when the time
    /// comes from the certificate's lifetime
    window: Option<(i64, i64)>,
}

impl RenewalPlan {
    /// What set the time, for the status and the log
    fn basis(&self) -> &'static str {
        if self.window.is_some() {
            "ari"
        } else {
            "lifetime"
        }
    }
}

/// Unix time a certificate valid from `not_before` to `not_after` renews at
/// without the CA's renewal information: `renewal_days` before it expires or
/// a third of its lifetime before, whichever is less. A 90-day certificate
/// renews 30 days early, a 160-hour one 53 hours early: renewing a 160-hour
/// certificate at every check, as a fixed 30 days would, spends the CA's
/// duplicate-certificate allowance (5 a week for one set of names).
fn lifetime_renewal_at(not_before: i64, not_after: i64, renewal_days: u32) -> i64 {
    let lifetime = not_after.saturating_sub(not_before).max(0);
    let lead = (lifetime / 3).min(i64::from(renewal_days) * 86_400);
    not_after - lead
}

/// The point in a suggested window `[start, end]` a certificate renews at.
/// RFC 9773 §4.2 has the client choose a uniformly random time in the window;
/// a hash of the certificate's serial chooses it, so certificates spread over
/// the window and each keeps its point across checks and restarts.
fn point_in_window(start: i64, end: i64, serial: &[u8]) -> i64 {
    use sha2::{Digest, Sha256};
    let Ok(span) = u64::try_from(end.saturating_sub(start)) else {
        return start;
    };
    if span == 0 {
        return start;
    }
    let digest = Sha256::digest(serial);
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    start + i64::try_from(u64::from_be_bytes(first) % span).unwrap_or(0)
}

/// How long until the next certificate check: the check interval, or less
/// when a certificate's renewal time comes first (a 160-hour certificate's
/// window can open and close inside a 12-hour interval).
fn next_check_wait(
    interval: Duration,
    next_renewal: Option<SystemTime>,
    now: SystemTime,
) -> Duration {
    match next_renewal {
        Some(at) => at
            .duration_since(now)
            .unwrap_or(Duration::ZERO)
            .min(interval),
        None => interval,
    }
}

/// A Unix time as the status and the log show it
fn utc(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// What renewal reads from an issued certificate.
#[derive(Debug, Clone)]
struct IssuedCertificate {
    /// Unix time it became valid
    not_before: i64,
    /// Unix time it expires
    not_after: i64,
    /// The DNS names it covers
    dns_names: Vec<String>,
    /// The IP addresses it covers
    ip_addresses: Vec<IpAddr>,
    /// The leaf, DER: its ARI identifier comes from its AKI and serial
    der: Vec<u8>,
    /// The serial number's octets
    serial: Vec<u8>,
}

impl IssuedCertificate {
    /// The leaf of a PEM certificate file
    fn read(cert_path: &Path) -> anyhow::Result<Self> {
        use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};
        let pem_bytes = fs::read(cert_path)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;
        let (_, cert) = X509Certificate::from_der(&pem.contents)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;
        let dns_names = match cert.subject_alternative_name() {
            Ok(Some(san)) => san
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
            dns_names,
            ip_addresses: crate::tls::certificate_ip_addresses(&pem.contents),
            serial: cert.raw_serial().to_vec(),
            der: pem.contents.clone(),
        })
    }

    /// Whether it names `domain` and exactly the addresses configured for
    /// it: an address added to the configuration, or one taken out, is a
    /// reason to reissue now rather than at the next renewal.
    fn covers(&self, domain: &str, addresses: &[IpAddr]) -> bool {
        let mut held = self.ip_addresses.clone();
        let mut wanted = addresses.to_vec();
        held.sort();
        held.dedup();
        wanted.sort();
        wanted.dedup();
        self.dns_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(domain))
            && held == wanted
    }
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
    /// Service running
    pub running: bool,
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
    /// IP addresses the certificate names besides its domain
    pub ip_addresses: Vec<String>,
    /// When it renews
    pub renews_at: Option<String>,
    /// What set that time: "ari" (the CA's suggested window, RFC 9773) or
    /// "lifetime" (renewal_days or a third of the lifetime before expiry)
    pub renewal_basis: Option<String>,
    /// Last renewal time
    pub last_renewed: Option<String>,
    /// Last error (if any)
    pub last_error: Option<String>,
}

impl CertificateStatus {
    /// The status of a certificate on disk that renews by `plan`
    fn of(
        domain: &str,
        cert: &IssuedCertificate,
        plan: RenewalPlan,
        now: i64,
        last_renewed: Option<String>,
    ) -> Self {
        Self {
            domain: domain.to_string(),
            exists: true,
            expires: Some(utc(cert.not_after)),
            days_remaining: Some((cert.not_after - now) / 86_400),
            needs_renewal: plan.at <= now,
            ip_addresses: cert.ip_addresses.iter().map(IpAddr::to_string).collect(),
            renews_at: Some(utc(plan.at)),
            renewal_basis: Some(plan.basis().to_string()),
            last_renewed,
            last_error: None,
        }
    }
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
            last_check: Arc::new(RwLock::new(None)),
            next_check: Arc::new(RwLock::new(None)),
            cert_status: Arc::new(RwLock::new(HashMap::new())),
            renewal_windows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get shared reference to pending challenges (for HTTP-01 server)
    pub fn pending_challenges(&self) -> Arc<RwLock<HashMap<String, PendingChallenge>>> {
        self.pending_challenges.clone()
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
        let last_check = self.last_check.clone();
        let next_check = self.next_check.clone();
        let cert_status = self.cert_status.clone();
        let renewal_windows = self.renewal_windows.clone();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(config.check_interval_hours as u64 * 3600);
            loop {
                *last_check.write() = Some(SystemTime::now());
                // A refused order waits a whole interval before it is placed
                // again: the CA allows 5 failed validations an hour per name.
                // Only certificates not yet due bring the next check forward.
                let next_renewal = match check_and_renew_certificates(
                    &config,
                    &pending_challenges,
                    &cert_update_tx,
                    &cert_status,
                    &renewal_windows,
                )
                .await
                {
                    Ok(next_renewal) => next_renewal,
                    Err(e) => {
                        error!("Certificate check/renewal failed: {}", e);
                        None
                    }
                };
                let now = SystemTime::now();
                let wait = next_check_wait(check_interval, next_renewal, now);
                *next_check.write() = Some(now + wait);

                tokio::select! {
                    _ = tokio::time::sleep(wait) => {
                        if !*running.read() {
                            break;
                        }
                        info!("Running scheduled certificate check");
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
            "ACME service started for domains: {:?} (CA: {})",
            self.config.domains, self.config.directory_url
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
        let cached_status = self.cert_status.read();
        let certificates: Vec<CertificateStatus> = self
            .config
            .domains
            .iter()
            .map(|domain| {
                if let Some(status) = cached_status.get(domain) {
                    status.clone()
                } else {
                    let safe_domain = validate_domain_for_path(domain)
                        .unwrap_or_else(|_| "invalid-domain".to_string());
                    let cert_path = self.config.certs_path.join(format!("{}.crt", safe_domain));
                    let now = chrono::Utc::now().timestamp();
                    match IssuedCertificate::read(&cert_path) {
                        // Before the first check: by lifetime, as the check
                        // decides where the CA publishes no window
                        Ok(cert) => {
                            let plan = RenewalPlan {
                                at: lifetime_renewal_at(
                                    cert.not_before,
                                    cert.not_after,
                                    self.config.renewal_days,
                                ),
                                window: None,
                            };
                            let mut status = CertificateStatus::of(domain, &cert, plan, now, None);
                            status.needs_renewal |=
                                !cert.covers(domain, &self.config.ip_addresses_for(domain));
                            status
                        }
                        Err(_) => CertificateStatus {
                            domain: domain.clone(),
                            exists: cert_path.exists(),
                            expires: None,
                            days_remaining: None,
                            needs_renewal: true,
                            ip_addresses: Vec::new(),
                            renews_at: None,
                            renewal_basis: None,
                            last_renewed: None,
                            last_error: None,
                        },
                    }
                }
            })
            .collect();

        let as_utc = |t: SystemTime| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| utc(i64::try_from(d.as_secs()).unwrap_or(i64::MAX)))
                .unwrap_or_else(|_| "unknown".to_string())
        };
        let last_check_str = self.last_check.read().map(as_utc);
        let next_check_str = self.next_check.read().map(as_utc);

        AcmeStatusInfo {
            enabled: self.config.enabled,
            directory_url: self.config.directory_url.clone(),
            staging: self.config.staging
                || self.config.directory_url.contains("staging")
                || self.config.directory_url.contains("test"),
            domains: self.config.domains.clone(),
            certificates,
            pending_challenges: self.pending_challenges.read().len(),
            last_check: last_check_str,
            next_check: next_check_str,
            running: *self.running.read(),
        }
    }

    /// Force immediate certificate check/renewal
    pub async fn force_renewal(&self) -> anyhow::Result<()> {
        self.renewal_task().await
    }

    /// The check and renewal `force_renewal` runs, as a future owning what it
    /// needs, so a caller that reaches the service through a lock can spawn it
    /// (the admin API's /acme/renew).
    pub fn renewal_task(
        &self,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send + 'static {
        let config = self.config.clone();
        let pending_challenges = self.pending_challenges.clone();
        let cert_update_tx = self.cert_update_tx.clone();
        let cert_status = self.cert_status.clone();
        let renewal_windows = self.renewal_windows.clone();
        async move {
            if !config.enabled {
                return Err(anyhow::anyhow!("ACME service is disabled"));
            }
            check_and_renew_certificates(
                &config,
                &pending_challenges,
                &cert_update_tx,
                &cert_status,
                &renewal_windows,
            )
            .await
            .map(|_| ())
        }
    }

    /// Get certificate paths for a domain.
    ///
    /// M-3: The domain is validated against RFC 1035 before being used in a
    /// `PathBuf::join()` call.  A domain containing `/`, `..`, or null bytes
    /// would resolve to an arbitrary path outside `certs_path`, enabling an
    /// attacker with config-write access to write files to arbitrary locations.
    /// We reject any domain that fails the safe-label check and return paths to
    /// a deterministic "invalid-domain" sentinel instead, causing downstream
    /// certificate checks to fail gracefully rather than operating on an
    /// attacker-controlled path.
    pub fn get_cert_paths(&self, domain: &str) -> (PathBuf, PathBuf) {
        let safe_domain = validate_domain_for_path(domain).unwrap_or_else(|_| {
            warn!(
                "M-3: Domain '{}' contains unsafe characters and cannot be used in a file path. \
                 Returning sentinel paths to prevent arbitrary file write.",
                domain
            );
            "invalid-domain".to_string()
        });
        let cert_path = self.config.certs_path.join(format!("{}.crt", safe_domain));
        let key_path = self.config.certs_path.join(format!("{}.key", safe_domain));
        (cert_path, key_path)
    }
}

/// Write a file atomically: write to a .tmp sibling then rename into place.
/// Prevents partial reads if two goroutines write simultaneously.
fn write_atomic(path: &std::path::Path, content: &str) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, content)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Check and renew certificates as needed, and say when the next renewal
/// falls due (the earliest renewal time of a certificate not yet due).
/// Issues one individual certificate per domain — no SAN bundling — naming
/// the domain and any IP addresses configured for it. Each domain gets its
/// own `{domain}.crt` / `{domain}.key` pair written atomically so concurrent
/// renewal of different domains cannot corrupt each other.
#[cfg(feature = "acme")]
async fn check_and_renew_certificates(
    config: &AcmeConfig,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
    cert_update_tx: &Option<mpsc::Sender<CertificateUpdate>>,
    cert_status: &Arc<RwLock<HashMap<String, CertificateStatus>>>,
    renewal_windows: &RenewalWindows,
) -> anyhow::Result<Option<SystemTime>> {
    if config.domains.is_empty() {
        return Ok(None);
    }

    // M-3: Validate all domains before touching the file system.
    for domain in &config.domains {
        if let Err(reason) = validate_domain_for_path(domain) {
            return Err(anyhow::anyhow!(
                "M-3: Domain '{}' is unsafe for use in file paths ({}). \
                 Fix the ACME domain configuration before proceeding.",
                domain,
                reason
            ));
        }
    }

    // Loaded on first use: ARI and orders need it, a check with nothing due
    // and a CA without ARI does not
    let mut account: Option<Account> = None;
    let mut next_renewal: Option<i64> = None;
    let mut current_windows = HashSet::new();

    // Issue one certificate per domain independently.
    for domain in &config.domains {
        let cert_path = config.certs_path.join(format!("{}.crt", domain));
        let key_path = config.certs_path.join(format!("{}.key", domain));
        let addresses = config.ip_addresses_for(domain);
        let now = chrono::Utc::now().timestamp();

        let existing = if cert_path.exists() {
            match IssuedCertificate::read(&cert_path) {
                Ok(cert) => Some(cert),
                Err(e) => {
                    warn!("[{}] Failed to read certificate: {}", domain, e);
                    None
                }
            }
        } else {
            info!("[{}] No certificate found, requesting new one", domain);
            None
        };

        // The certificate this order replaces, where the CA has renewal information
        let mut replaces = None;
        if let Some(cert) = &existing {
            let (plan, identifier) =
                renewal_plan(config, &mut account, renewal_windows, cert).await;
            if let Some(identifier) = &identifier {
                current_windows.insert(identifier.to_string());
            }
            let window = plan
                .window
                .map(|(start, end)| format!(", window {} to {}", utc(start), utc(end)))
                .unwrap_or_default();
            if !cert.covers(domain, &addresses) {
                info!(
                    "[{}] Certificate names {:?} {:?}, configured {:?}: reissuing",
                    domain, cert.dns_names, cert.ip_addresses, addresses
                );
            } else if plan.at <= now {
                info!(
                    "[{}] Certificate expires {}, renewal due since {} ({}{}), renewing",
                    domain,
                    utc(cert.not_after),
                    utc(plan.at),
                    plan.basis(),
                    window
                );
            } else {
                info!(
                    "[{}] Certificate valid until {}, renews at {} ({}{})",
                    domain,
                    utc(cert.not_after),
                    utc(plan.at),
                    plan.basis(),
                    window
                );
                next_renewal = Some(next_renewal.map_or(plan.at, |n| n.min(plan.at)));
                cert_status.write().insert(
                    domain.clone(),
                    CertificateStatus::of(domain, cert, plan, now, None),
                );
                continue;
            }
            // An expired certificate is renewed, not replaced
            if cert.not_after > now {
                replaces = identifier;
            }
        }

        let ordered = match loaded_account(config, &mut account).await {
            Ok(acct) => {
                request_san_certificate(
                    config,
                    acct,
                    domain,
                    &addresses,
                    replaces,
                    pending_challenges,
                )
                .await
            }
            Err(e) => Err(e),
        };
        match ordered {
            Ok((cert_pem, key_pem, chain_pem)) => {
                let full_chain = if chain_pem.is_empty() {
                    cert_pem.clone()
                } else {
                    // Ensure a clean newline between cert and chain
                    let sep = if cert_pem.ends_with('\n') { "" } else { "\n" };
                    format!("{}{}{}", cert_pem, sep, chain_pem)
                };

                // Atomic write: write to .tmp then rename — prevents partial reads
                write_atomic(&cert_path, &full_chain)
                    .map_err(|e| anyhow::anyhow!("Failed to write cert for {}: {}", domain, e))?;
                write_atomic(&key_path, &key_pem)
                    .map_err(|e| anyhow::anyhow!("Failed to write key for {}: {}", domain, e))?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
                }

                let issued = IssuedCertificate::read(&cert_path)?;
                if let Err(e) =
                    submit_to_ct_logs(&cert_pem, &chain_pem, config, issued.not_after).await
                {
                    warn!("[{}] CT log submission failed (non-fatal): {}", domain, e);
                }

                info!(
                    "[{}] Individual certificate obtained from {}, valid until {}",
                    domain,
                    config.directory_url,
                    utc(issued.not_after)
                );

                // Until the CA's window for it is known, at the next check
                let plan = RenewalPlan {
                    at: lifetime_renewal_at(
                        issued.not_before,
                        issued.not_after,
                        config.renewal_days,
                    ),
                    window: None,
                };
                next_renewal = Some(next_renewal.map_or(plan.at, |n| n.min(plan.at)));
                let now = chrono::Utc::now().timestamp();
                cert_status.write().insert(
                    domain.clone(),
                    CertificateStatus::of(domain, &issued, plan, now, Some(utc(now))),
                );

                // Notify listeners so they can reload the SNI cert resolver
                if let Some(tx) = cert_update_tx {
                    let expires = SystemTime::UNIX_EPOCH
                        + Duration::from_secs(u64::try_from(issued.not_after).unwrap_or(0));
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
                error!("[{}] Failed to obtain certificate: {}", domain, e);
                let now = chrono::Utc::now().timestamp();
                cert_status.write().insert(
                    domain.clone(),
                    CertificateStatus {
                        domain: domain.clone(),
                        exists: cert_path.exists(),
                        expires: existing.as_ref().map(|c| utc(c.not_after)),
                        days_remaining: existing.as_ref().map(|c| (c.not_after - now) / 86_400),
                        needs_renewal: true,
                        ip_addresses: existing
                            .as_ref()
                            .map(|c| c.ip_addresses.iter().map(IpAddr::to_string).collect())
                            .unwrap_or_default(),
                        renews_at: None,
                        renewal_basis: None,
                        last_renewed: None,
                        last_error: Some(e.to_string()),
                    },
                );
            }
        }
    } // end per-domain loop

    // Windows of certificates since replaced are not asked for again
    renewal_windows
        .write()
        .retain(|identifier, _| current_windows.contains(identifier));

    // Clean up expired challenges
    let now = SystemTime::now();
    pending_challenges.write().retain(|_, c| c.expires > now);

    Ok(next_renewal
        .map(|at| SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(at).unwrap_or(0))))
}

/// The ACME account, loaded into `slot` on first use.
#[cfg(feature = "acme")]
async fn loaded_account<'a>(
    config: &AcmeConfig,
    slot: &'a mut Option<Account>,
) -> anyhow::Result<&'a Account> {
    if slot.is_none() {
        *slot = Some(get_or_create_account(config).await?);
    }
    slot.as_ref()
        .ok_or_else(|| anyhow::anyhow!("the ACME account was not loaded"))
}

/// When `cert` renews: at its point in the CA's suggested window where the
/// CA publishes renewal information (ARI, RFC 9773), otherwise by its
/// lifetime. With the window comes the certificate's ARI identifier, for the
/// replacement order's `replaces` (RFC 9773 §5): the CA then knows the order
/// renews it, and Let's Encrypt exempts such an order from its rate limits.
/// A window is fetched again only once the CA's Retry-After has passed.
#[cfg(feature = "acme")]
async fn renewal_plan(
    config: &AcmeConfig,
    account: &mut Option<Account>,
    windows: &RenewalWindows,
    cert: &IssuedCertificate,
) -> (RenewalPlan, Option<CertificateIdentifier<'static>>) {
    let by_lifetime = RenewalPlan {
        at: lifetime_renewal_at(cert.not_before, cert.not_after, config.renewal_days),
        window: None,
    };
    let der = rustls::pki_types::CertificateDer::from(cert.der.as_slice());
    let identifier = match CertificateIdentifier::try_from(&der) {
        Ok(identifier) => identifier.into_owned(),
        Err(e) => {
            debug!("ARI: the certificate has no identifier ({e}); renewing by lifetime");
            return (by_lifetime, None);
        }
    };
    let key = identifier.to_string();
    let cached = windows
        .read()
        .get(&key)
        .filter(|w| w.refresh_after > SystemTime::now())
        .cloned();
    let window = match cached {
        Some(window) => window,
        None => {
            let acct = match loaded_account(config, account).await {
                Ok(acct) => acct,
                Err(e) => {
                    warn!("ARI: no ACME account ({e}); renewing by lifetime");
                    return (by_lifetime, None);
                }
            };
            match acct.renewal_info(&identifier).await {
                Ok((info, retry_after)) => {
                    let window = RenewalWindow {
                        start: info.suggested_window.start.unix_timestamp(),
                        end: info.suggested_window.end.unix_timestamp(),
                        refresh_after: SystemTime::now() + retry_after,
                    };
                    if let Some(why) = &info.explanation_url {
                        info!("ARI: the CA explains its window for {key} at {why}");
                    }
                    windows.write().insert(key, window.clone());
                    window
                }
                Err(instant_acme::Error::Unsupported(_)) => return (by_lifetime, None),
                Err(e) => {
                    warn!("ARI: renewal information not fetched ({e}); renewing by lifetime");
                    return (by_lifetime, None);
                }
            }
        }
    };
    (
        RenewalPlan {
            at: point_in_window(window.start, window.end, &cert.serial),
            window: Some((window.start, window.end)),
        },
        Some(identifier),
    )
}

/// Why the CA refused an order: the order's own problem and each failed
/// challenge's, whose detail says what the validators saw (a timeout, a wrong
/// response, a CAA record, a DNS failure). Without it every refusal read the
/// same, whatever caused it.
#[cfg(feature = "acme")]
async fn invalid_order_reasons(order: &mut instant_acme::Order) -> String {
    let mut reasons = Vec::new();
    if let Some(problem) = &order.state().error {
        reasons.push(problem.to_string());
    }
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        match result {
            Ok(authz) => {
                for challenge in &authz.challenges {
                    if let Some(problem) = &challenge.error {
                        reasons.push(format!("{}: {}", authz.identifier(), problem));
                    }
                }
            }
            Err(e) => reasons.push(format!("an authorization could not be read: {e}")),
        }
    }
    if reasons.is_empty() {
        "the CA gave no reason".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Answers each pending authorization of `order`: HTTP-01 by the responses
/// the port-80 listener serves, or for a domain name with `dns_updater`
/// set, a DNS challenge by its TXT record, published and waited for at
/// every name server of its zone before the CA is told to look.
/// dns-account-01 is taken where the CA offers it, dns-01 otherwise.
#[cfg(feature = "acme")]
async fn answer_challenges(
    order: &mut instant_acme::Order,
    account: &Account,
    dns_updater: Option<&crate::acme_dns::DnsUpdater>,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
    registered_tokens: &mut Vec<String>,
    published: &mut Vec<crate::acme_dns::ChallengeRecord>,
) -> anyhow::Result<()> {
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        let authz_domain = authz.identifier().to_string();

        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => {
                debug!("Authorization already valid for {}", authz_domain);
                continue;
            }
            ref other => {
                return Err(anyhow::anyhow!(
                    "Unexpected authorization status for {}: {:?}",
                    authz_domain,
                    other
                ));
            }
        }

        if let (Some(updater), Identifier::Dns(name)) = (dns_updater, authz.identifier().identifier)
        {
            let name = name.clone();
            let account_label = AcmeChallengeType::Unknown("dns-account-01".to_string());
            let (kind, owner) = if authz.challenges.iter().any(|c| c.r#type == account_label) {
                (
                    account_label,
                    crate::acme_dns::dns_account01_owner(&name, account.id()),
                )
            } else {
                (
                    AcmeChallengeType::Dns01,
                    crate::acme_dns::dns01_owner(&name),
                )
            };
            let kind_name = match &kind {
                AcmeChallengeType::Dns01 => "dns-01",
                _ => "dns-account-01",
            };
            let mut challenge = authz.challenge(kind).ok_or_else(|| {
                anyhow::anyhow!(
                    "No DNS challenge (dns-account-01 or dns-01) offered for {}",
                    authz_domain
                )
            })?;
            let value = challenge.key_authorization().dns_value();
            let record = updater.record(&owner, &value).await?;
            updater.publish(&record).await?;
            published.push(record.clone());
            updater.await_published(&record).await?;
            info!(
                "{} challenge ready for {} ({})",
                kind_name, authz_domain, owner
            );
            challenge.set_ready().await?;
            continue;
        }

        let mut challenge = authz
            .challenge(AcmeChallengeType::Http01)
            .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found for {}", authz_domain))?;

        let key_auth = challenge.key_authorization();
        let challenge_token = challenge.token.clone();
        let challenge_url = challenge.url.clone();

        {
            let mut challenges = pending_challenges.write();
            challenges.insert(
                challenge_token.clone(),
                PendingChallenge {
                    token: challenge_token.clone(),
                    key_authorization: key_auth.as_str().to_string(),
                    domain: authz_domain.clone(),
                    challenge_url,
                    expires: SystemTime::now() + Duration::from_mins(5),
                },
            );
        }

        info!(
            "HTTP-01 challenge ready for {} (token: {}...)",
            authz_domain,
            &challenge_token[..challenge_token.len().min(12)]
        );

        challenge.set_ready().await?;
        registered_tokens.push(challenge_token);
    }
    Ok(())
}

/// An order for `identifiers`, under `profile` if one is given, replacing
/// the certificate `replaces` identifies if one is given.
#[cfg(feature = "acme")]
fn new_order<'a>(
    identifiers: &'a [Identifier],
    profile: Option<&'a str>,
    replaces: Option<CertificateIdentifier<'a>>,
) -> NewOrder<'a> {
    let mut order = NewOrder::new(identifiers);
    if let Some(profile) = profile {
        order = order.profile(profile);
    }
    if let Some(replaces) = replaces {
        order = order.replaces(replaces);
    }
    order
}

/// Request a certificate for `domain` and `addresses` via ACME: one order,
/// the domain and each address (RFC 8738) as identifiers and as Subject
/// Alternative Names. An order with addresses is placed under
/// `config.ip_profile`. `replaces` names the certificate it renews (RFC 9773
/// §5); a CA that refuses the order on that account (the certificate already
/// replaced, say) gets it again without.
#[cfg(feature = "acme")]
async fn request_san_certificate(
    config: &AcmeConfig,
    account: &Account,
    domain: &str,
    addresses: &[IpAddr],
    replaces: Option<CertificateIdentifier<'static>>,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
) -> anyhow::Result<(String, String, String)> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};

    info!(
        "Requesting a certificate for {} {:?} from {}",
        domain, addresses, config.directory_url
    );

    let mut identifiers = vec![Identifier::Dns(domain.to_string())];
    identifiers.extend(addresses.iter().copied().map(Identifier::Ip));
    let profile = (!addresses.is_empty()).then_some(config.ip_profile.as_str());

    let mut order = match replaces {
        Some(replaced) => {
            let replacing = new_order(&identifiers, profile, Some(replaced));
            match account.new_order(&replacing).await {
                Ok(order) => order,
                Err(e) => {
                    warn!(
                        "[{}] The CA refused the order replacing the current certificate ({}); \
                         ordering without `replaces`",
                        domain, e
                    );
                    account
                        .new_order(&new_order(&identifiers, profile, None))
                        .await?
                }
            }
        }
        None => {
            account
                .new_order(&new_order(&identifiers, profile, None))
                .await?
        }
    };

    // DNS challenges' records, for domain names when challenge_type is dns-01
    let dns_updater = match config.challenge_type {
        ChallengeType::Dns01 => Some(crate::acme_dns::DnsUpdater::from_config(
            config.dns_update.as_ref().ok_or_else(|| {
                anyhow::anyhow!("acme.challenge_type is dns-01 but acme.dns_update is not set")
            })?,
        )?),
        ChallengeType::Http01 => None,
    };

    // Answer every pending authorization's challenge, then wait for the
    // order to validate. The HTTP-01 responses served and the DNS records
    // published are tracked so they are removed whichever way it ends.
    let mut registered_tokens: Vec<String> = Vec::new();
    let mut published: Vec<crate::acme_dns::ChallengeRecord> = Vec::new();
    let validated = match answer_challenges(
        &mut order,
        account,
        dns_updater.as_ref(),
        pending_challenges,
        &mut registered_tokens,
        &mut published,
    )
    .await
    {
        // RetryPolicy provides the exponential backoff the manual loop used to do.
        Ok(()) => order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(anyhow::Error::from),
        Err(e) => Err(e),
    };

    // Validation is complete (success or failure) — drop the served responses
    // and the records.
    {
        let mut challenges = pending_challenges.write();
        for token in &registered_tokens {
            challenges.remove(token);
        }
    }
    if let Some(updater) = &dns_updater {
        for record in &published {
            if let Err(e) = updater.withdraw(record).await {
                warn!(
                    "[{}] ACME DNS: {} TXT not removed: {}",
                    domain, record.owner, e
                );
            }
        }
    }
    let ready_status = validated?;

    match ready_status {
        OrderStatus::Ready => {}
        OrderStatus::Invalid => {
            return Err(anyhow::anyhow!(
                "Order became invalid during validation: {}",
                invalid_order_reasons(&mut order).await
            ))
        }
        other => {
            return Err(anyhow::anyhow!(
                "Order not ready after validation: {:?}",
                other
            ))
        }
    }

    // Generate certificate key pair.
    // P-384 (secp384r1) is the default ECDSA curve: 192-bit security = 7680-bit RSA
    // equivalent, scoring 100% on SSL Labs key exchange. P-256 (128-bit) scores only 90%.
    // Key generation: ECDSA (P-384 default) or RSA (via rcgen's generate_rsa_for,
    // which delegates to aws-lc-rs and supports up to RSA-4096).
    let key_pair = if config.use_ecdsa {
        match config.ecdsa_curve.to_uppercase().as_str() {
            "P-256" | "SECP256R1" => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?,
            _ => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?,
        }
    } else if config.key_size == 4096 {
        // aws-lc-rs backend supports RSA-4096; ring only supports up to 3072.
        KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_4096)?
    } else {
        KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?
    };

    // The CSR names the domain and each address (rcgen reads an address as
    // an iPAddress SAN)
    let mut names = vec![domain.to_string()];
    names.extend(addresses.iter().map(IpAddr::to_string));
    let mut params = CertificateParams::new(names)?;
    params.distinguished_name = DistinguishedName::new();

    let csr = params.serialize_request(&key_pair)?;
    let csr_der = csr.der();

    order.finalize_csr(csr_der).await?;

    // Poll until the certificate is issued; RetryPolicy handles the backoff.
    let cert_chain = order.poll_certificate(&RetryPolicy::default()).await?;

    // Split chain into leaf cert and intermediates
    let certs: Vec<&str> = cert_chain
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .map(|s| s.trim())
        .collect();

    let cert_pem = if !certs.is_empty() {
        format!("{}\n-----END CERTIFICATE-----\n", certs[0].trim_end())
    } else {
        cert_chain.clone()
    };

    let chain_pem = if certs.len() > 1 {
        certs[1..].iter().fold(String::new(), |mut acc, c| {
            acc.push_str(c.trim_end());
            acc.push_str("\n-----END CERTIFICATE-----\n");
            acc
        })
    } else {
        String::new()
    };

    let key_pem = key_pair.serialize_pem();

    info!(
        "Certificate obtained for {} {:?} ({} intermediates)",
        domain,
        addresses,
        certs.len().saturating_sub(1)
    );

    Ok((cert_pem, key_pem, chain_pem))
}

/// Get existing ACME account or create a new one
#[cfg(feature = "acme")]
async fn get_or_create_account(config: &AcmeConfig) -> anyhow::Result<Account> {
    // Try to load existing account
    if config.account_path.exists() {
        if let Ok(stored) = load_account_wrapper(&config.account_path) {
            // Verify the account is for the same directory
            if stored.directory_url == config.directory_url {
                info!(
                    "Loading existing ACME account from {:?}",
                    config.account_path
                );

                // Deserialize the credentials from the stored JSON
                let credentials: AccountCredentials = serde_json::from_value(stored.credentials)?;
                let account = Account::builder()?.from_credentials(credentials).await?;
                return Ok(account);
            }
            warn!(
                "Existing account is for different directory ({}), creating new account",
                stored.directory_url
            );
        }
    }

    // Create new account
    info!("Creating new ACME account with {}", config.directory_url);

    let contact = config
        .email
        .as_ref()
        .map(|e| vec![format!("mailto:{}", e)])
        .unwrap_or_default();

    let new_account = NewAccount {
        contact: &contact.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        terms_of_service_agreed: config.accept_tos,
        only_return_existing: false,
    };

    // Handle External Account Binding if configured (required by some CAs like ZeroSSL)
    let external_account =
        if let (Some(kid), Some(hmac_key)) = (&config.eab_kid, &config.eab_hmac_key) {
            info!("Using External Account Binding (EAB)");
            // Decode the base64 HMAC key
            let hmac_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hmac_key)
                    .or_else(|_| {
                        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, hmac_key)
                    })?;
            Some(ExternalAccountKey::new(kid.clone(), &hmac_bytes))
        } else {
            None
        };

    let (account, credentials) = Account::builder()?
        .create(
            &new_account,
            config.directory_url.clone(),
            external_account.as_ref(),
        )
        .await?;

    // Serialize credentials to JSON value for storage
    let credentials_json = serde_json::to_value(&credentials)?;

    // Save account with metadata wrapper
    let stored = StoredAccountWrapper {
        directory_url: config.directory_url.clone(),
        email: config.email.clone(),
        created: chrono::Utc::now()
            .format("%Y-%m-%d %H:%M:%S UTC")
            .to_string(),
        credentials: credentials_json,
    };

    if let Some(parent) = config.account_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&stored)?;
    fs::write(&config.account_path, json)?;

    // Set restrictive permissions on account file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config.account_path, fs::Permissions::from_mode(0o600))?;
    }

    info!(
        "ACME account created and saved to {:?}",
        config.account_path
    );

    Ok(account)
}

/// Load stored ACME account wrapper
#[cfg(feature = "acme")]
fn load_account_wrapper(path: &Path) -> anyhow::Result<StoredAccountWrapper> {
    let content = fs::read_to_string(path)?;
    let stored: StoredAccountWrapper = serde_json::from_str(&content)?;
    Ok(stored)
}

/// Stub implementation when ACME feature is disabled
#[cfg(not(feature = "acme"))]
async fn check_and_renew_certificates(
    config: &AcmeConfig,
    _pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
    _cert_update_tx: &Option<mpsc::Sender<CertificateUpdate>>,
    cert_status: &Arc<RwLock<HashMap<String, CertificateStatus>>>,
    _renewal_windows: &RenewalWindows,
) -> anyhow::Result<Option<SystemTime>> {
    warn!("ACME feature not enabled at compile time. Enable with --features acme");

    // Still check existing certificates
    for domain in &config.domains {
        // M-3: Validate domain before using in file path
        let safe_domain = match validate_domain_for_path(domain) {
            Ok(d) => d,
            Err(reason) => {
                warn!(
                    "M-3: Skipping unsafe domain '{}' in cert status check: {}",
                    domain, reason
                );
                continue;
            }
        };
        let cert_path = config.certs_path.join(format!("{}.crt", safe_domain));
        let now = chrono::Utc::now().timestamp();
        let status = match IssuedCertificate::read(&cert_path) {
            Ok(cert) => {
                let plan = RenewalPlan {
                    at: lifetime_renewal_at(cert.not_before, cert.not_after, config.renewal_days),
                    window: None,
                };
                let mut status = CertificateStatus::of(domain, &cert, plan, now, None);
                status.needs_renewal |= !cert.covers(domain, &config.ip_addresses_for(domain));
                status
            }
            Err(_) => CertificateStatus {
                domain: domain.clone(),
                exists: cert_path.exists(),
                expires: None,
                days_remaining: None,
                needs_renewal: true,
                ip_addresses: Vec::new(),
                renews_at: None,
                renewal_basis: None,
                last_renewed: None,
                last_error: (!cert_path.exists()).then(|| "ACME feature not enabled".to_string()),
            },
        };
        cert_status.write().insert(domain.clone(), status);
    }

    Ok(None)
}

/// HTTP-01 challenge handler for ACME validation
/// This should be called from the HTTP server when requests come to /.well-known/acme-challenge/
pub fn handle_acme_challenge(acme_service: &AcmeService, token: &str) -> Option<String> {
    acme_service.get_challenge_response(token)
}

/// Submit an issued certificate to configured Certificate Transparency logs.
///
/// CT logs expect a `POST /ct/v1/add-chain` request with the certificate chain
/// as base64-encoded DER in a JSON array.  PEM already contains base64-DER
/// between the `-----BEGIN/END CERTIFICATE-----` markers, so we extract it
/// directly without a re-encode step.
///
/// Failures are non-fatal: operators can still use the certificate even if
/// CT submission fails.  Errors are logged as warnings.
///
/// The logs are `config.ct_logs`, or when that is empty the ones the CT log
/// list has for the certificate's expiry, `not_after` ([`ct_logs_for_expiry`]).
async fn submit_to_ct_logs(
    cert_pem: &str,
    chain_pem: &str,
    config: &AcmeConfig,
    not_after: i64,
) -> anyhow::Result<()> {
    if !config.certificate_transparency {
        return Ok(());
    }

    let chain_b64 = extract_pem_base64_blocks(cert_pem, chain_pem);
    if chain_b64.is_empty() {
        warn!("CT: no certificate DER blocks found in PEM chain — skipping submission");
        return Ok(());
    }

    let body = serde_json::json!({ "chain": chain_b64 });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("CT: failed to build HTTP client: {}", e))?;

    let logs = if config.ct_logs.is_empty() {
        let list: CtLogList = client
            .get(&config.ct_log_list)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| anyhow::anyhow!("CT: log list {} not fetched: {}", config.ct_log_list, e))?
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("CT: log list {} not read: {}", config.ct_log_list, e))?;
        let logs = ct_logs_for_expiry(&list, not_after);
        if logs.is_empty() {
            warn!(
                "CT: the log list has no log accepting an expiry of {}",
                utc(not_after)
            );
        }
        logs
    } else {
        config.ct_logs.clone()
    };

    for log_url in &logs {
        let submit_url = {
            let base = log_url.trim_end_matches('/');
            format!("{}/ct/v1/add-chain", base)
        };

        match client.post(&submit_url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(sct) => {
                        let log_id = sct.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
                        let ts = sct.get("timestamp").and_then(|v| v.as_i64()).unwrap_or(0);
                        info!(
                            "CT log submission to {} succeeded (log_id={}, timestamp={}ms)",
                            log_url, log_id, ts
                        );
                    }
                    Err(e) => warn!("CT log {}: SCT parse error: {}", log_url, e),
                }
            }
            Ok(resp) => {
                warn!(
                    "CT log {}: submission rejected with status {}",
                    log_url,
                    resp.status()
                );
            }
            Err(e) => {
                warn!("CT log {}: HTTP request failed: {}", log_url, e);
            }
        }
    }

    Ok(())
}

/// The CT log list (the v3 schema Google and Apple publish), as far as
/// choosing a log needs.
#[derive(Debug, Deserialize)]
struct CtLogList {
    operators: Vec<CtOperator>,
}

#[derive(Debug, Deserialize)]
struct CtOperator {
    /// RFC 6962 logs. The list's `tiled_logs` (the static CT API) take no
    /// add-chain, so they are not read.
    #[serde(default)]
    logs: Vec<CtLog>,
}

#[derive(Debug, Deserialize)]
struct CtLog {
    url: String,
    /// One key naming the state: usable, qualified, readonly, retired, ...
    #[serde(default)]
    state: HashMap<String, serde_json::Value>,
    temporal_interval: Option<CtTemporalInterval>,
}

#[derive(Debug, Deserialize)]
struct CtTemporalInterval {
    start_inclusive: chrono::DateTime<chrono::Utc>,
    end_exclusive: chrono::DateTime<chrono::Utc>,
}

/// The logs in `list` that take a certificate expiring at `not_after`: per
/// operator, the first that accepts submissions (usable, or qualified and
/// on its way to usable) and whose temporal interval holds the expiry.
fn ct_logs_for_expiry(list: &CtLogList, not_after: i64) -> Vec<String> {
    list.operators
        .iter()
        .filter_map(|operator| {
            operator.logs.iter().find(|log| {
                let accepting =
                    log.state.contains_key("usable") || log.state.contains_key("qualified");
                let holds_expiry = log.temporal_interval.as_ref().is_none_or(|interval| {
                    interval.start_inclusive.timestamp() <= not_after
                        && not_after < interval.end_exclusive.timestamp()
                });
                accepting && holds_expiry
            })
        })
        .map(|log| log.url.clone())
        .collect()
}

/// Extract base64-encoded DER blocks from one or more PEM certificate strings.
///
/// PEM stores DER data as base64 with whitespace; we strip the whitespace so
/// the resulting strings are valid base64 for the CT JSON body.
fn extract_pem_base64_blocks(cert_pem: &str, chain_pem: &str) -> Vec<String> {
    let combined = format!("{}\n{}", cert_pem, chain_pem);
    combined
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .filter_map(|chunk| {
            let end = chunk.find("-----END CERTIFICATE-----")?;
            let raw = &chunk[..end];
            let cleaned: String = raw.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if cleaned.is_empty() {
                None
            } else {
                Some(cleaned)
            }
        })
        .collect()
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
        assert!(config.accept_tos);
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
    fn test_validate_domain_for_path() {
        // Valid domains
        assert!(validate_domain_for_path("example.com").is_ok());
        assert!(validate_domain_for_path("sub.example.com").is_ok());
        assert!(validate_domain_for_path("my-host.example.com").is_ok());
        assert!(validate_domain_for_path("*.example.com").is_ok());

        // Invalid: path traversal
        assert!(validate_domain_for_path("../etc/cron.d/evil").is_err());
        assert!(validate_domain_for_path("..").is_err());
        assert!(validate_domain_for_path("evil/etc/passwd").is_err());
        assert!(validate_domain_for_path("evil\\path").is_err());

        // Invalid: null byte
        assert!(validate_domain_for_path("evil\x00domain").is_err());

        // Invalid: non-ASCII
        assert!(validate_domain_for_path("ünïcödé.example.com").is_err());

        // Invalid: empty
        assert!(validate_domain_for_path("").is_err());
    }

    #[test]
    fn test_get_cert_paths_with_invalid_domain() {
        let config = AcmeConfig {
            certs_path: PathBuf::from("/etc/certs"),
            ..Default::default()
        };
        let service = AcmeService::new(config);
        // An invalid domain should return sentinel paths, not escape certs_path
        let (cert, key) = service.get_cert_paths("../etc/cron.d/evil");
        assert_eq!(cert, PathBuf::from("/etc/certs/invalid-domain.crt"));
        assert_eq!(key, PathBuf::from("/etc/certs/invalid-domain.key"));
    }

    /// Without the CA's window: 30 days early for a 90-day certificate, a
    /// third of the lifetime early for a 160-hour one, never later than
    /// renewal_days before expiry.
    #[test]
    fn a_certificate_renews_by_its_lifetime_without_ari() {
        let day = 86_400;
        assert_eq!(lifetime_renewal_at(0, 90 * day, 30), 60 * day);
        let hours_160 = 160 * 3600;
        assert_eq!(
            lifetime_renewal_at(0, hours_160, 30),
            hours_160 - hours_160 / 3
        );
        assert_eq!(lifetime_renewal_at(0, 90 * day, 1), 89 * day);
        // A malformed validity (not_after first) renews at expiry
        assert_eq!(lifetime_renewal_at(10, 5, 30), 5);
    }

    /// The point is inside the window, the same for the same serial, and
    /// different serials spread over it.
    #[test]
    fn the_renewal_point_falls_in_the_window() {
        let (start, end) = (1_000_000, 1_086_400);
        let mut points = HashSet::new();
        for serial in 0u32..64 {
            let at = point_in_window(start, end, &serial.to_be_bytes());
            assert!((start..end).contains(&at), "{at}");
            assert_eq!(at, point_in_window(start, end, &serial.to_be_bytes()));
            points.insert(at);
        }
        assert!(points.len() > 60, "spread: {} distinct of 64", points.len());
        assert_eq!(point_in_window(start, start, b"x"), start);
        assert_eq!(point_in_window(end, start, b"x"), end);
    }

    /// The next check comes at the interval, or sooner for a renewal point
    /// inside it; a point already past is checked at once.
    #[test]
    fn a_renewal_inside_the_interval_brings_the_check_forward() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let interval = Duration::from_hours(12);
        assert_eq!(next_check_wait(interval, None, now), interval);
        let soon = now + Duration::from_hours(1);
        assert_eq!(
            next_check_wait(interval, Some(soon), now),
            Duration::from_hours(1)
        );
        let later = now + Duration::from_hours(48);
        assert_eq!(next_check_wait(interval, Some(later), now), interval);
        let past = now - Duration::from_mins(1);
        assert_eq!(next_check_wait(interval, Some(past), now), Duration::ZERO);
    }

    /// A certificate's names and addresses are read back, and it covers a
    /// configuration only when the addresses match exactly.
    #[test]
    fn an_issued_certificate_covers_its_domain_and_exactly_its_addresses() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ns1.example.com.crt");
        let cert = rcgen::generate_simple_self_signed(vec![
            "ns1.example.com".to_string(),
            "1.1.1.1".to_string(),
            "2606:4700:4700::1111".to_string(),
        ])
        .expect("self-signed");
        fs::write(&path, cert.cert.pem()).expect("write");
        let issued = IssuedCertificate::read(&path).expect("read");
        assert_eq!(issued.dns_names, vec!["ns1.example.com"]);
        let v4: IpAddr = "1.1.1.1".parse().unwrap();
        let v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert_eq!(issued.ip_addresses, vec![v4, v6]);
        assert!(issued.not_after > issued.not_before);
        assert_ne!(issued.serial, Vec::<u8>::new());

        assert!(issued.covers("ns1.example.com", &[v6, v4]));
        assert!(issued.covers("NS1.example.com", &[v4, v6, v4]));
        assert!(
            !issued.covers("ns1.example.com", &[v4]),
            "an address taken out"
        );
        let extra: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(
            !issued.covers("ns1.example.com", &[v4, v6, extra]),
            "one added"
        );
        assert!(!issued.covers("ns2.example.com", &[v4, v6]), "another name");

        let plain = rcgen::generate_simple_self_signed(vec!["www.example.com".to_string()])
            .expect("self-signed");
        let plain_path = dir.path().join("www.example.com.crt");
        fs::write(&plain_path, plain.cert.pem()).expect("write");
        let plain = IssuedCertificate::read(&plain_path).expect("read");
        assert!(plain.covers("www.example.com", &[]));
        assert!(
            !plain.covers("www.example.com", &[v4]),
            "addresses configured since"
        );
    }

    /// An order with addresses carries them as IP identifiers under the
    /// profile, and names the certificate it replaces.
    #[cfg(feature = "acme")]
    #[test]
    fn an_order_carries_the_addresses_profile_and_replaced_certificate() {
        let identifiers = vec![
            Identifier::Dns("ns1.example.com".to_string()),
            Identifier::Ip("1.1.1.1".parse().unwrap()),
            Identifier::Ip("2606:4700:4700::1111".parse().unwrap()),
        ];
        let replaced = CertificateIdentifier::new(
            rustls::pki_types::Der::from_slice(&[1, 2, 3]),
            rustls::pki_types::Der::from_slice(&[4, 5]),
        );
        let order =
            serde_json::to_value(new_order(&identifiers, Some("shortlived"), Some(replaced)))
                .expect("serialize");
        assert_eq!(
            order,
            serde_json::json!({
                "identifiers": [
                    {"type": "dns", "value": "ns1.example.com"},
                    {"type": "ip", "value": "1.1.1.1"},
                    {"type": "ip", "value": "2606:4700:4700::1111"},
                ],
                "profile": "shortlived",
                "replaces": "AQID.BAU",
            })
        );
        let plain = serde_json::to_value(new_order(&identifiers[..1], None, None)).unwrap();
        assert_eq!(
            plain,
            serde_json::json!({"identifiers": [{"type": "dns", "value": "ns1.example.com"}]})
        );
    }

    /// From the log list: per operator, the first log that accepts
    /// submissions and whose shard holds the expiry; read-only, retired and
    /// other shards are passed over, and tiled logs are not read.
    #[test]
    fn ct_logs_are_chosen_for_the_certificate_expiry() {
        let list: CtLogList = serde_json::from_value(serde_json::json!({
            "version": "1",
            "operators": [
                {
                    "name": "A",
                    "logs": [
                        {"url": "https://a/2025h1/", "state": {"retired": {}},
                         "temporal_interval": {"start_inclusive": "2025-01-01T00:00:00Z", "end_exclusive": "2025-07-01T00:00:00Z"}},
                        {"url": "https://a/2026h2/", "state": {"usable": {}},
                         "temporal_interval": {"start_inclusive": "2026-07-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"}},
                        {"url": "https://a/2027h1/", "state": {"usable": {}},
                         "temporal_interval": {"start_inclusive": "2027-01-01T00:00:00Z", "end_exclusive": "2027-07-01T00:00:00Z"}}
                    ],
                    "tiled_logs": [{"submission_url": "https://a/tiled/", "state": {"usable": {}}}]
                },
                {
                    "name": "B",
                    "logs": [
                        {"url": "https://b/readonly/", "state": {"readonly": {}},
                         "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"}},
                        {"url": "https://b/qualified/", "state": {"qualified": {}},
                         "temporal_interval": {"start_inclusive": "2026-01-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"}}
                    ]
                },
                {"name": "C", "logs": [{"url": "https://c/any/", "state": {"usable": {}}}]},
                {"name": "D", "logs": []}
            ]
        }))
        .expect("log list");
        let nov_2026 = chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(
            ct_logs_for_expiry(&list, nov_2026),
            vec![
                "https://a/2026h2/",
                "https://b/qualified/",
                "https://c/any/"
            ]
        );
        let jan_2027 = chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .timestamp();
        assert_eq!(
            ct_logs_for_expiry(&list, jan_2027),
            vec!["https://a/2027h1/", "https://c/any/"],
            "end_exclusive: 2027-01-01 belongs to the next shard"
        );
    }

    #[test]
    fn test_stored_account_serialization() {
        let stored = StoredAccountWrapper {
            directory_url: "https://acme.example.com/directory".to_string(),
            email: Some("test@example.com".to_string()),
            created: "2024-01-01 00:00:00 UTC".to_string(),
            credentials: serde_json::json!({
                "id": "https://acme.example.com/account/123",
                "key_pkcs8": "dGVzdA=="
            }),
        };

        let json = serde_json::to_string(&stored).expect("serialize");
        let parsed: StoredAccountWrapper = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.directory_url, stored.directory_url);
        assert_eq!(parsed.email, stored.email);
    }
}
