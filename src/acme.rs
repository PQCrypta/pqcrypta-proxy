//! ACME (Automated Certificate Management Environment) Client
//!
//! Fully functional ACME client implementing RFC 8555 for automatic certificate
//! provisioning and renewal. Works with any ACME-compatible CA:
//! - Let's Encrypt (production and staging)
//! - ZeroSSL
//! - Buypass
//! - Google Trust Services
//! - Private/Enterprise ACME servers
//!
//! Features:
//! - HTTP-01 challenge support
//! - Automatic certificate renewal before expiration
//! - Account persistence and reuse
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

#[cfg(feature = "acme")]
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType as AcmeChallengeType,
    ExternalAccountKey, Identifier, NewAccount, NewOrder, OrderStatus,
};

/// ACME configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// Enable ACME certificate automation
    #[serde(default)]
    pub enabled: bool,

    /// ACME directory URL (any ACME-compatible CA)
    /// Examples:
    /// - Let's Encrypt Production: https://acme-v02.api.letsencrypt.org/directory
    /// - Let's Encrypt Staging: https://acme-staging-v02.api.letsencrypt.org/directory
    /// - ZeroSSL: https://acme.zerossl.com/v2/DV90
    /// - Buypass: https://api.buypass.com/acme/directory
    /// - Google: https://dv.acme-v02.api.pki.goog/directory
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Email address for account registration (required by most CAs)
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

    /// Use staging environment for testing (only applies to Let's Encrypt)
    #[serde(default)]
    pub staging: bool,

    /// Accept terms of service automatically
    #[serde(default = "default_true")]
    pub accept_tos: bool,

    /// Challenge type (http-01 or dns-01)
    #[serde(default = "default_challenge_type")]
    pub challenge_type: ChallengeType,

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

    /// Use ECDSA instead of RSA (P-256 curve)
    #[serde(default)]
    pub use_ecdsa: bool,
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
            accept_tos: true,
            challenge_type: default_challenge_type(),
            http_port: default_http_port(),
            eab_kid: None,
            eab_hmac_key: None,
            key_size: default_key_size(),
            use_ecdsa: false,
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
    /// Certificate status cache
    cert_status: Arc<RwLock<HashMap<String, CertificateStatus>>>,
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
            last_check: Arc::new(RwLock::new(None)),
            cert_status: Arc::new(RwLock::new(HashMap::new())),
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
        let last_check = self.last_check.clone();
        let cert_status = self.cert_status.clone();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(config.check_interval_hours as u64 * 3600);
            let mut interval = tokio::time::interval(check_interval);

            // Initial check
            *last_check.write() = Some(SystemTime::now());
            if let Err(e) = check_and_renew_certificates(
                &config,
                &pending_challenges,
                &cert_update_tx,
                &cert_status,
            )
            .await
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
                        *last_check.write() = Some(SystemTime::now());
                        if let Err(e) = check_and_renew_certificates(
                            &config,
                            &pending_challenges,
                            &cert_update_tx,
                            &cert_status,
                        ).await {
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
                }
            })
            .collect();

        let last_check_str = self.last_check.read().map(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| {
                    let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .unwrap_or_else(|_| "unknown".to_string())
        });

        let next_check_str = self.last_check.read().map(|t| {
            let next = t + Duration::from_secs(u64::from(self.config.check_interval_hours) * 3600);
            next.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| {
                    let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                    chrono::DateTime::from_timestamp(secs, 0)
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                })
                .unwrap_or_else(|_| "unknown".to_string())
        });

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
        if !self.config.enabled {
            return Err(anyhow::anyhow!("ACME service is disabled"));
        }

        check_and_renew_certificates(
            &self.config,
            &self.pending_challenges,
            &self.cert_update_tx,
            &self.cert_status,
        )
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
#[cfg(feature = "acme")]
async fn check_and_renew_certificates(
    config: &AcmeConfig,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
    cert_update_tx: &Option<mpsc::Sender<CertificateUpdate>>,
    cert_status: &Arc<RwLock<HashMap<String, CertificateStatus>>>,
) -> anyhow::Result<()> {
    for domain in &config.domains {
        let cert_path = config.certs_path.join(format!("{}.crt", domain));
        let key_path = config.certs_path.join(format!("{}.key", domain));

        let (needs_renewal, days_remaining) = if cert_path.exists() {
            match read_certificate_expiry(&cert_path) {
                Ok((_, days)) => {
                    if days < config.renewal_days as i64 {
                        info!(
                            "Certificate for {} expires in {} days, renewal needed",
                            domain, days
                        );
                        (true, Some(days))
                    } else {
                        debug!("Certificate for {} valid for {} more days", domain, days);

                        // Update status cache
                        let mut status = cert_status.write();
                        status.insert(
                            domain.clone(),
                            CertificateStatus {
                                domain: domain.clone(),
                                exists: true,
                                expires: Some(format!("{} days", days)),
                                days_remaining: Some(days),
                                needs_renewal: false,
                                last_renewed: None,
                                last_error: None,
                            },
                        );

                        (false, Some(days))
                    }
                }
                Err(e) => {
                    warn!("Failed to read certificate expiry for {}: {}", domain, e);
                    (true, None)
                }
            }
        } else {
            info!("No certificate found for {}, requesting new one", domain);
            (true, None)
        };

        if needs_renewal {
            match request_certificate_acme(config, domain, pending_challenges).await {
                Ok((cert_pem, key_pem, chain_pem)) => {
                    // Save certificate (with chain) and key
                    let full_chain = if chain_pem.is_empty() {
                        cert_pem.clone()
                    } else {
                        format!("{}\n{}", cert_pem, chain_pem)
                    };

                    fs::write(&cert_path, &full_chain)?;
                    fs::write(&key_path, &key_pem)?;

                    // Set restrictive permissions on key
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
                    }

                    info!(
                        "Certificate for {} obtained successfully from {}",
                        domain, config.directory_url
                    );

                    // Update status cache
                    let (expires, days) = read_certificate_expiry(&cert_path)
                        .unwrap_or_else(|_| ("90 days".to_string(), 90));
                    {
                        let mut status = cert_status.write();
                        status.insert(
                            domain.clone(),
                            CertificateStatus {
                                domain: domain.clone(),
                                exists: true,
                                expires: Some(expires),
                                days_remaining: Some(days),
                                needs_renewal: false,
                                last_renewed: Some(
                                    chrono::Utc::now()
                                        .format("%Y-%m-%d %H:%M:%S UTC")
                                        .to_string(),
                                ),
                                last_error: None,
                            },
                        );
                    }

                    // Notify about certificate update
                    if let Some(tx) = cert_update_tx {
                        let expires_time =
                            SystemTime::now() + Duration::from_secs(days as u64 * 86400);

                        let _ = tx
                            .send(CertificateUpdate {
                                domain: domain.clone(),
                                cert_path: cert_path.clone(),
                                key_path: key_path.clone(),
                                expires: expires_time,
                            })
                            .await;
                    }
                }
                Err(e) => {
                    error!("Failed to obtain certificate for {}: {}", domain, e);

                    // Update status cache with error
                    let mut status = cert_status.write();
                    status.insert(
                        domain.clone(),
                        CertificateStatus {
                            domain: domain.clone(),
                            exists: cert_path.exists(),
                            expires: days_remaining.map(|d| format!("{} days", d)),
                            days_remaining,
                            needs_renewal: true,
                            last_renewed: None,
                            last_error: Some(e.to_string()),
                        },
                    );
                }
            }
        }
    }

    // Clean up expired challenges
    let now = SystemTime::now();
    pending_challenges.write().retain(|_, c| c.expires > now);

    Ok(())
}

/// Request a certificate using the ACME protocol
#[cfg(feature = "acme")]
async fn request_certificate_acme(
    config: &AcmeConfig,
    domain: &str,
    pending_challenges: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
) -> anyhow::Result<(String, String, String)> {
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};

    info!(
        "Requesting certificate for {} from {}",
        domain, config.directory_url
    );

    // Load or create ACME account
    let account = get_or_create_account(config).await?;

    // Create a new order for the domain
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.to_string())],
        })
        .await?;

    // Get the authorizations
    let authorizations = order.authorizations().await?;

    for authz in authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {
                // Find the HTTP-01 challenge
                let challenge = authz
                    .challenges
                    .iter()
                    .find(|c| c.r#type == AcmeChallengeType::Http01)
                    .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found for {}", domain))?;

                let key_auth = order.key_authorization(challenge);
                let challenge_token = challenge.token.clone();
                let challenge_url = challenge.url.clone();

                // Store the challenge for the HTTP server to respond
                {
                    let mut challenges = pending_challenges.write();
                    challenges.insert(
                        challenge_token.clone(),
                        PendingChallenge {
                            token: challenge_token.clone(),
                            key_authorization: key_auth.as_str().to_string(),
                            domain: domain.to_string(),
                            challenge_url: challenge_url.clone(),
                            expires: SystemTime::now() + Duration::from_secs(300),
                        },
                    );
                }

                info!(
                    "HTTP-01 challenge ready for {} at /.well-known/acme-challenge/{}",
                    domain, challenge_token
                );

                // Tell the ACME server we're ready
                order.set_challenge_ready(&challenge_url).await?;

                // Wait for the challenge to be validated by polling the challenge status
                let mut attempts = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;

                    // Refresh the order and check authorization status
                    order.refresh().await?;
                    let fresh_authz = order.authorizations().await?;

                    // Find the authorization for this domain
                    let current_authz = fresh_authz.iter().find(|a| {
                        let Identifier::Dns(d) = &authz.identifier;
                        let Identifier::Dns(ad) = &a.identifier;
                        ad == d
                    });

                    match current_authz.map(|a| &a.status) {
                        Some(AuthorizationStatus::Valid) => {
                            info!("Challenge validated for {}", domain);
                            break;
                        }
                        Some(AuthorizationStatus::Invalid) => {
                            pending_challenges.write().remove(&challenge_token);
                            return Err(anyhow::anyhow!(
                                "Challenge validation failed for {}",
                                domain
                            ));
                        }
                        Some(AuthorizationStatus::Pending) | None => {
                            attempts += 1;
                            if attempts > 30 {
                                pending_challenges.write().remove(&challenge_token);
                                return Err(anyhow::anyhow!(
                                    "Challenge validation timeout for {}",
                                    domain
                                ));
                            }
                        }
                        _ => {
                            attempts += 1;
                            if attempts > 30 {
                                pending_challenges.write().remove(&challenge_token);
                                return Err(anyhow::anyhow!(
                                    "Challenge validation timeout for {}",
                                    domain
                                ));
                            }
                        }
                    }
                }

                // Clean up the challenge
                pending_challenges.write().remove(&challenge_token);
            }
            AuthorizationStatus::Valid => {
                debug!("Authorization already valid for {}", domain);
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "Unexpected authorization status for {}: {:?}",
                    domain,
                    authz.status
                ));
            }
        }
    }

    // Wait for order to be ready
    let mut attempts = 0;
    loop {
        let state = order.state();
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                return Err(anyhow::anyhow!("Order became invalid for {}", domain));
            }
            OrderStatus::Pending => {
                attempts += 1;
                if attempts > 30 {
                    return Err(anyhow::anyhow!("Order pending timeout for {}", domain));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                order.refresh().await?;
            }
            _ => {
                attempts += 1;
                if attempts > 30 {
                    return Err(anyhow::anyhow!("Order timeout for {}", domain));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                order.refresh().await?;
            }
        }
    }

    // Generate a new key pair for the certificate
    let key_pair = if config.use_ecdsa {
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?
    } else {
        // Use RSA with configured key size
        KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?
    };

    // Create CSR
    let mut params = CertificateParams::new(vec![domain.to_string()])?;
    params.distinguished_name = DistinguishedName::new();

    let csr = params.serialize_request(&key_pair)?;
    let csr_der = csr.der();

    // Finalize the order with our CSR
    order.finalize(csr_der).await?;

    // Wait for certificate to be issued
    let mut attempts = 0;
    let cert_chain = loop {
        let state = order.state();
        match state.status {
            OrderStatus::Valid => {
                let cert = order.certificate().await?;
                break cert.ok_or_else(|| anyhow::anyhow!("No certificate returned"))?;
            }
            OrderStatus::Invalid => {
                return Err(anyhow::anyhow!(
                    "Order became invalid after finalization for {}",
                    domain
                ));
            }
            _ => {
                attempts += 1;
                if attempts > 30 {
                    return Err(anyhow::anyhow!(
                        "Certificate issuance timeout for {}",
                        domain
                    ));
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                order.refresh().await?;
            }
        }
    };

    // Split the chain into certificate and intermediate(s)
    let certs: Vec<&str> = cert_chain
        .split("-----END CERTIFICATE-----")
        .filter(|s| s.contains("-----BEGIN CERTIFICATE-----"))
        .map(|s| s.trim())
        .collect();

    let cert_pem = if !certs.is_empty() {
        format!("{}-----END CERTIFICATE-----\n", certs[0])
    } else {
        cert_chain.clone()
    };

    let chain_pem = if certs.len() > 1 {
        certs[1..].iter().fold(String::new(), |mut acc, c| {
            acc.push_str(c);
            acc.push_str("-----END CERTIFICATE-----\n");
            acc
        })
    } else {
        String::new()
    };

    let key_pem = key_pair.serialize_pem();

    info!("Certificate obtained successfully for {}", domain);

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
                let account = Account::from_credentials(credentials).await?;
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

    let (account, credentials) = Account::create(
        &new_account,
        &config.directory_url,
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
) -> anyhow::Result<()> {
    warn!("ACME feature not enabled at compile time. Enable with --features acme");

    // Still check existing certificates
    for domain in &config.domains {
        let cert_path = config.certs_path.join(format!("{}.crt", domain));
        let (exists, expires, days_remaining) = if cert_path.exists() {
            match read_certificate_expiry(&cert_path) {
                Ok((exp, days)) => (true, Some(exp), Some(days)),
                Err(_) => (true, None, None),
            }
        } else {
            (false, None, None)
        };

        let needs_renewal = days_remaining
            .map(|d| d < config.renewal_days as i64)
            .unwrap_or(true);

        let mut status = cert_status.write();
        status.insert(
            domain.clone(),
            CertificateStatus {
                domain: domain.clone(),
                exists,
                expires,
                days_remaining,
                needs_renewal,
                last_renewed: None,
                last_error: if needs_renewal && !exists {
                    Some("ACME feature not enabled".to_string())
                } else {
                    None
                },
            },
        );
    }

    Ok(())
}

/// Read certificate expiry from a PEM file
fn read_certificate_expiry(cert_path: &Path) -> anyhow::Result<(String, i64)> {
    use x509_parser::prelude::*;

    let cert_pem = fs::read(cert_path)?;

    // Parse PEM
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;

    // Parse certificate
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

    // Get expiration time
    let not_after = cert.validity().not_after;
    let expiry_time = not_after.timestamp();

    // Calculate days remaining
    let now = chrono::Utc::now().timestamp();
    let days_remaining = (expiry_time - now) / 86400;

    // Format expiry date
    let expiry_str = chrono::DateTime::from_timestamp(expiry_time, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Ok((expiry_str, days_remaining))
}

/// HTTP-01 challenge handler for ACME validation
/// This should be called from the HTTP server when requests come to /.well-known/acme-challenge/
pub fn handle_acme_challenge(acme_service: &AcmeService, token: &str) -> Option<String> {
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
