//! OCSP stapling (RFC 6960, RFC 6066 section 8, RFC 8446 section 4.4.2.1)
//!
//! For every certificate chain the proxy serves (each domain's, and its
//! post-quantum companion's), the service asks the responder the end-entity
//! certificate names for its status, verifies the answer with OpenSSL's OCSP
//! implementation (the responder's signature, by the issuer or by a responder
//! the issuer delegated to; the certificate it is about; `thisUpdate` and
//! `nextUpdate`), and keeps a response that says *good* until it is refreshed,
//! halfway through its validity. Both TLS stacks staple from that one store:
//! the rustls listeners (QUIC, and TCP without OpenSSL) through
//! [`stapled`], the OpenSSL listeners through [`staple_for`].
//!
//! A chain whose certificate names no responder has nothing to staple: CAs
//! that retired OCSP (Let's Encrypt in 2025, Google Trust Services) issue
//! such certificates, and revocation then rests on short lifetimes and CRLs.
//! A certificate that requires stapling (TLS Feature `status_request`, RFC
//! 7633) without a responder, or without a good response, is reported.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use dashmap::DashMap;
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

/// The most of a responder's answer that is read
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Clock skew allowed on `thisUpdate` / `nextUpdate`, in seconds
const CLOCK_SKEW_SECS: u32 = 300;
/// How often the served chains are looked at again when nothing is due and
/// no reload said they changed
const RESCAN: Duration = Duration::from_mins(10);

/// A certificate's OCSP status, as last learned
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OcspStatus {
    /// A verified response says the certificate is good: it is stapled
    Good,
    /// A verified response says the certificate is revoked
    Revoked,
    /// The responder does not know the certificate
    Unknown,
    /// The responder could not be reached, or its answer did not verify
    FetchError,
    /// The certificate names no responder (or its chain has no issuer)
    NoResponder,
    /// Not yet asked
    Pending,
}

/// OCSP stapling configuration
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Enable OCSP stapling
    pub enabled: bool,
    /// How long a good response is stapled when the responder states no
    /// `nextUpdate`, and how long before a chain without a responder is
    /// looked at again. A stated `nextUpdate` always wins.
    pub cache_duration: Duration,
    /// Refresh no later than this long before `nextUpdate`
    pub refresh_before_expiry: Duration,
    /// Never ask one responder about one certificate more often than this
    pub min_refresh_interval: Duration,
    /// HTTP timeout for OCSP requests
    pub request_timeout: Duration,
    /// Attempts per refresh
    pub max_retries: u32,
    /// Delay between attempts
    pub retry_delay: Duration,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_duration: Duration::from_hours(1),
            refresh_before_expiry: Duration::from_hours(1),
            min_refresh_interval: Duration::from_mins(5),
            request_timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
        }
    }
}

// ── The staple store both TLS stacks read ─────────────────────────────────

/// A verified good response, stapled until `until`
struct Staple {
    der: Arc<[u8]>,
    until: SystemTime,
}

/// End-entity certificate (SHA-256 of its DER) → its staple
static STAPLES: LazyLock<DashMap<[u8; 32], Staple>> = LazyLock::new(DashMap::new);

/// Stapled rustls keys: end-entity digest → (the key it was made from, the
/// staple it carries, the stapled key)
type StapledKey = (
    Arc<rustls::sign::CertifiedKey>,
    Arc<[u8]>,
    Arc<rustls::sign::CertifiedKey>,
);
static STAPLED_KEYS: LazyLock<DashMap<[u8; 32], StapledKey>> = LazyLock::new(DashMap::new);

/// Woken when the certificates served may have changed
static CHANGED: LazyLock<Notify> = LazyLock::new(Notify::new);

fn digest(der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(der).into()
}

/// The response to staple for the end-entity certificate `der`, while it is
/// valid.
pub fn staple_for(der: &[u8]) -> Option<Arc<[u8]>> {
    if STAPLES.is_empty() {
        return None;
    }
    let staple = STAPLES.get(&digest(der))?;
    (SystemTime::now() < staple.until).then(|| Arc::clone(&staple.der))
}

/// Whether any certificate has a staple now (a handshake that asks for
/// one need not look further when none has).
pub fn has_staples() -> bool {
    !STAPLES.is_empty()
}

/// `key` with its staple, when it has one (rustls sends it only to a client
/// that asked, in the Certificate message's first entry).
pub fn stapled(key: Arc<rustls::sign::CertifiedKey>) -> Arc<rustls::sign::CertifiedKey> {
    if STAPLES.is_empty() {
        return key;
    }
    let Some(ee) = key.cert.first() else {
        return key;
    };
    let id = digest(ee);
    let staple = match STAPLES.get(&id) {
        Some(s) if SystemTime::now() < s.until => Arc::clone(&s.der),
        _ => return key,
    };
    if let Some(made) = STAPLED_KEYS.get(&id) {
        if Arc::ptr_eq(&made.0, &key) && Arc::ptr_eq(&made.1, &staple) {
            return Arc::clone(&made.2);
        }
    }
    let mut with = (*key).clone();
    with.ocsp = Some(staple.to_vec());
    let with = Arc::new(with);
    STAPLED_KEYS.insert(id, (key, staple, Arc::clone(&with)));
    with
}

/// The certificates served may have changed (a TLS reload): the service
/// looks at them again now.
pub fn certificates_changed() {
    CHANGED.notify_one();
}

// ── The service ───────────────────────────────────────────────────────────

/// Where the service finds the chains the proxy serves
pub type ChainSource = Arc<dyn Fn() -> Vec<Vec<CertificateDer<'static>>> + Send + Sync>;

/// What is known about one served chain
#[derive(Debug, Clone)]
struct Entry {
    /// The certificate's first DNS name, else its subject
    name: String,
    responder: Option<String>,
    must_staple: bool,
    status: OcspStatus,
    fetched_at: Option<SystemTime>,
    next_update: Option<SystemTime>,
    error: Option<String>,
    due: Instant,
}

struct Shared {
    config: OcspConfig,
    source: ChainSource,
    entries: DashMap<[u8; 32], Entry>,
    fetches: AtomicU64,
    failures: AtomicU64,
    running: AtomicBool,
    /// One refresh pass at a time (the task's and the admin API's)
    pass: tokio::sync::Mutex<()>,
}

/// OCSP stapling service
pub struct OcspService {
    shared: Arc<Shared>,
    shutdown_tx: Mutex<Option<mpsc::Sender<()>>>,
}

impl OcspService {
    /// A service for the chains `source` names.
    pub fn new(config: OcspConfig, source: ChainSource) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                source,
                entries: DashMap::new(),
                fetches: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                running: AtomicBool::new(false),
                pass: tokio::sync::Mutex::new(()),
            }),
            shutdown_tx: Mutex::new(None),
        }
    }

    /// Requests sent to responders, and how many of them failed or did not
    /// verify (for the metrics).
    pub fn fetch_counts(&self) -> (u64, u64) {
        (
            self.shared.fetches.load(Ordering::Relaxed),
            self.shared.failures.load(Ordering::Relaxed),
        )
    }

    /// Status for the admin API: overall, and per certificate.
    pub fn get_status(&self) -> OcspStatusInfo {
        let now = SystemTime::now();
        let mut certificates: Vec<CertificateOcsp> = self
            .shared
            .entries
            .iter()
            .map(|e| {
                let entry = e.value();
                let stapled = STAPLES.get(e.key()).is_some_and(|s| now < s.until);
                CertificateOcsp {
                    name: entry.name.clone(),
                    status: entry.status,
                    responder_url: entry.responder.clone(),
                    must_staple: entry.must_staple,
                    stapled,
                    fetched_at: entry.fetched_at.and_then(|t| now.duration_since(t).ok()),
                    expires_in: entry.next_update.and_then(|t| t.duration_since(now).ok()),
                    error: entry.error.clone(),
                }
            })
            .collect();
        certificates.sort_by(|a, b| a.name.cmp(&b.name));
        // The overall status is the worst a certificate has
        let rank = |s: OcspStatus| match s {
            OcspStatus::Revoked => 0,
            OcspStatus::FetchError => 1,
            OcspStatus::Unknown => 2,
            OcspStatus::Pending => 3,
            OcspStatus::Good => 4,
            OcspStatus::NoResponder => 5,
        };
        let status = certificates
            .iter()
            .map(|c| c.status)
            .min_by_key(|s| rank(*s))
            .unwrap_or(OcspStatus::Pending);
        let first_stapled = certificates.iter().find(|c| c.stapled);
        OcspStatusInfo {
            enabled: self.shared.config.enabled,
            status,
            responder_url: certificates.iter().find_map(|c| c.responder_url.clone()),
            fetched_at: first_stapled.and_then(|c| c.fetched_at),
            expires_in: first_stapled.and_then(|c| c.expires_in),
            is_valid: certificates
                .iter()
                .filter(|c| c.responder_url.is_some())
                .all(|c| c.stapled)
                && certificates.iter().any(|c| c.stapled),
            running: self.shared.running.load(Ordering::Relaxed),
            certificates,
        }
    }

    /// Start the refresh task.
    pub fn start(&self) -> anyhow::Result<()> {
        if !self.shared.config.enabled {
            info!("OCSP stapling is disabled");
            return Ok(());
        }
        if self.shared.running.swap(true, Ordering::AcqRel) {
            warn!("OCSP service already running");
            return Ok(());
        }
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        *self.shutdown_tx.lock() = Some(shutdown_tx);
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            info!("OCSP refresh service started");
            loop {
                let next = Self::pass(&shared, false).await;
                let wait = next.saturating_duration_since(Instant::now());
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = CHANGED.notified() => debug!("OCSP: certificates reloaded"),
                    _ = shutdown_rx.recv() => {
                        info!("OCSP service shutting down");
                        break;
                    }
                }
            }
            shared.running.store(false, Ordering::Release);
        });
        Ok(())
    }

    /// Stop the refresh task.
    pub async fn stop(&self) {
        let tx = self.shutdown_tx.lock().take();
        if let Some(tx) = tx {
            let _ = tx.send(()).await;
        }
    }

    /// Ask every responder again now. Errors when a certificate that names a
    /// responder has no good response afterwards.
    pub async fn force_refresh(&self) -> anyhow::Result<()> {
        Self::pass(&self.shared, true).await;
        let failed: Vec<String> = self
            .shared
            .entries
            .iter()
            .filter(|e| e.responder.is_some() && e.status != OcspStatus::Good)
            .map(|e| {
                format!(
                    "{}: {}",
                    e.name,
                    e.error.clone().unwrap_or_else(|| format!("{:?}", e.status))
                )
            })
            .collect();
        if failed.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(failed.join("; ")))
        }
    }

    /// One pass: follow the served chains, refresh what is due (everything
    /// when `all`), forget what is no longer served. Returns when the next
    /// refresh is due.
    async fn pass(shared: &Arc<Shared>, all: bool) -> Instant {
        let _one = shared.pass.lock().await;
        let chains = (shared.source)();
        let now = Instant::now();
        let mut served = std::collections::HashSet::new();
        for chain in &chains {
            let Some(ee) = chain.first() else { continue };
            let id = digest(ee);
            if !served.insert(id) {
                continue;
            }
            if !shared.entries.contains_key(&id) {
                shared.entries.insert(id, Self::describe(chain, now));
            }
            let due = shared.entries.get(&id).is_some_and(|e| all || e.due <= now);
            if due {
                Self::refresh(shared, &id, chain).await;
            }
        }
        shared.entries.retain(|id, _| served.contains(id));
        STAPLES.retain(|id, _| served.contains(id));
        STAPLED_KEYS.retain(|id, _| served.contains(id));
        shared
            .entries
            .iter()
            .map(|e| e.due)
            .min()
            .unwrap_or_else(|| Instant::now() + RESCAN)
            .min(Instant::now() + RESCAN)
    }

    /// A chain first seen: its name, responder and stapling requirement.
    fn describe(chain: &[CertificateDer<'static>], now: Instant) -> Entry {
        let parsed = X509Certificate::from_der(&chain[0]).ok().map(|(_, c)| c);
        let name = parsed
            .as_ref()
            .and_then(|c| {
                c.subject_alternative_name().ok().flatten().and_then(|san| {
                    san.value.general_names.iter().find_map(|n| match n {
                        GeneralName::DNSName(d) => Some((*d).to_string()),
                        _ => None,
                    })
                })
            })
            .or_else(|| parsed.as_ref().map(|c| c.subject().to_string()))
            .unwrap_or_else(|| "(unparsable certificate)".to_string());
        let responder = parsed.as_ref().and_then(|c| responder_url(c));
        let must_staple = parsed.as_ref().is_some_and(|c| requires_stapling(c));
        let issuer = chain.len() > 1;
        match (&responder, issuer) {
            (None, _) if must_staple => warn!(
                "OCSP: certificate for {} requires stapling but names no responder",
                name
            ),
            (None, _) => info!(
                "OCSP: certificate for {} names no responder: nothing to staple \
                 (expected of CAs that retired OCSP; revocation rests on short \
                 lifetimes and CRLs)",
                name
            ),
            (Some(_), false) => warn!(
                "OCSP: certificate for {} names a responder but its chain has no \
                 issuer certificate to ask about it with",
                name
            ),
            (Some(url), true) => info!("OCSP: {} is asked of {}", name, url),
        }
        Entry {
            status: if responder.is_some() && issuer {
                OcspStatus::Pending
            } else {
                OcspStatus::NoResponder
            },
            error: (responder.is_some() && !issuer)
                .then(|| "no issuer certificate in the chain".to_string()),
            name,
            responder: responder.filter(|_| issuer),
            must_staple,
            fetched_at: None,
            next_update: None,
            due: now,
        }
    }

    /// Ask the responder about one chain and keep what it says.
    async fn refresh(shared: &Arc<Shared>, id: &[u8; 32], chain: &[CertificateDer<'static>]) {
        let config = &shared.config;
        let Some(url) = shared.entries.get(id).and_then(|e| e.responder.clone()) else {
            if let Some(mut e) = shared.entries.get_mut(id) {
                e.due = Instant::now() + RESCAN.max(config.cache_duration);
            }
            return;
        };
        let request = match build_request(&chain[0], &chain[1]) {
            Ok(request) => request,
            Err(e) => {
                Self::failed(shared, id, format!("request: {e}"));
                return;
            }
        };
        let mut last = String::new();
        for attempt in 0..config.max_retries.max(1) {
            if attempt > 0 {
                tokio::time::sleep(config.retry_delay).await;
            }
            shared.fetches.fetch_add(1, Ordering::Relaxed);
            let answer = match fetch(&url, &request, config.request_timeout).await {
                Ok(answer) => answer,
                Err(e) => {
                    shared.failures.fetch_add(1, Ordering::Relaxed);
                    debug!("OCSP {} attempt {}: {}", url, attempt + 1, e);
                    last = e.to_string();
                    continue;
                }
            };
            match verify(&answer, &chain[0], &chain[1..]) {
                Ok(verdict) => {
                    Self::learned(shared, id, answer, verdict);
                    return;
                }
                Err(e) => {
                    // A response that does not verify is not asked again at once
                    shared.failures.fetch_add(1, Ordering::Relaxed);
                    Self::failed(shared, id, format!("response did not verify: {e}"));
                    return;
                }
            }
        }
        Self::failed(shared, id, last);
    }

    fn learned(shared: &Arc<Shared>, id: &[u8; 32], der: Vec<u8>, verdict: Verdict) {
        let config = &shared.config;
        let now = SystemTime::now();
        let until = verdict
            .next_update
            .unwrap_or_else(|| now + config.cache_duration);
        let left = until.duration_since(now).unwrap_or_default();
        // Halfway through the response's validity, and no later than
        // `refresh_before_expiry` before its end (RFC 5019 section 6)
        let refresh_in = (left / 2)
            .min(left.saturating_sub(config.refresh_before_expiry))
            .max(config.min_refresh_interval);
        let Some(mut entry) = shared.entries.get_mut(id) else {
            return;
        };
        entry.fetched_at = Some(now);
        entry.next_update = Some(until);
        entry.due = Instant::now() + refresh_in;
        entry.error = None;
        entry.status = verdict.status;
        match verdict.status {
            OcspStatus::Good => {
                STAPLES.insert(
                    *id,
                    Staple {
                        der: Arc::from(der),
                        until,
                    },
                );
                debug!("OCSP: {} good until {:?}", entry.name, until);
            }
            OcspStatus::Revoked => {
                STAPLES.remove(id);
                error!(
                    "OCSP: the responder says the certificate for {} is REVOKED; \
                     replace it",
                    entry.name
                );
            }
            _ => {
                STAPLES.remove(id);
                warn!(
                    "OCSP: the responder does not know the certificate for {}",
                    entry.name
                );
            }
        }
    }

    fn failed(shared: &Arc<Shared>, id: &[u8; 32], error: String) {
        let config = &shared.config;
        let Some(mut entry) = shared.entries.get_mut(id) else {
            return;
        };
        // The staple it has (if any) is served until its own nextUpdate
        let still_stapled = STAPLES.get(id).is_some_and(|s| SystemTime::now() < s.until);
        if entry.must_staple && !still_stapled {
            warn!(
                "OCSP: certificate for {} requires stapling and has no good response: {}",
                entry.name, error
            );
        } else {
            warn!("OCSP: {}: {}", entry.name, error);
        }
        entry.status = OcspStatus::FetchError;
        entry.error = Some(error);
        entry.due = Instant::now() + config.min_refresh_interval;
    }
}

/// The responder the certificate names (Authority Information Access,
/// id-ad-ocsp), when it is an http(s) URL.
fn responder_url(cert: &X509Certificate) -> Option<String> {
    cert.extensions().iter().find_map(|ext| {
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            return None;
        };
        aia.accessdescs.iter().find_map(|desc| {
            if desc.access_method.to_id_string() != "1.3.6.1.5.5.7.48.1" {
                return None;
            }
            match &desc.access_location {
                GeneralName::URI(uri)
                    if uri.starts_with("http://") || uri.starts_with("https://") =>
                {
                    Some((*uri).to_string())
                }
                _ => None,
            }
        })
    })
}

/// Whether the certificate carries the TLS Feature extension with
/// `status_request` (5): it must be served with a staple (RFC 7633).
fn requires_stapling(cert: &X509Certificate) -> bool {
    cert.extensions().iter().any(|ext| {
        if ext.oid.to_id_string() != "1.3.6.1.5.5.7.1.24" {
            return false;
        }
        // SEQUENCE OF INTEGER
        let v = ext.value;
        if v.len() < 2 || v[0] != 0x30 {
            return false;
        }
        let mut i = 2;
        while i + 1 < v.len() {
            let (tag, len) = (v[i], usize::from(v[i + 1]));
            if tag != 0x02 || i + 2 + len > v.len() {
                return false;
            }
            if len == 1 && v[i + 2] == 5 {
                return true;
            }
            i += 2 + len;
        }
        false
    })
}

/// What a verified response says about the certificate
#[derive(Debug, Clone, Copy)]
struct Verdict {
    status: OcspStatus,
    next_update: Option<SystemTime>,
}

/// POST the request (RFC 6960 appendix A.1), reading at most
/// [`MAX_RESPONSE_BYTES`] of the answer.
async fn fetch(url: &str, request: &[u8], timeout: Duration) -> anyhow::Result<Vec<u8>> {
    static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default()
    });
    let mut response = CLIENT
        .post(url)
        .timeout(timeout)
        .header("Content-Type", "application/ocsp-request")
        .header("Accept", "application/ocsp-response")
        .body(request.to_vec())
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "responder answered HTTP {}",
            response.status()
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err(anyhow::anyhow!(
            "response larger than {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow::anyhow!(
                "response larger than {MAX_RESPONSE_BYTES} bytes"
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(feature = "pqc")]
fn build_request(ee: &[u8], issuer: &[u8]) -> anyhow::Result<Vec<u8>> {
    use openssl::hash::MessageDigest;
    use openssl::ocsp::{OcspCertId, OcspRequest};
    use openssl::x509::X509;
    let ee = X509::from_der(ee)?;
    let issuer = X509::from_der(issuer)?;
    // SHA-1 CertID: what the lightweight profile (RFC 5019) has responders
    // answer; the hash only names the certificate, it secures nothing
    let id = OcspCertId::from_cert(MessageDigest::sha1(), &ee, &issuer)?;
    let mut request = OcspRequest::new()?;
    request.add_id(id)?;
    Ok(request.to_der()?)
}

#[cfg(not(feature = "pqc"))]
fn build_request(_ee: &[u8], _issuer: &[u8]) -> anyhow::Result<Vec<u8>> {
    Err(anyhow::anyhow!(
        "OCSP needs OpenSSL: this build has no `pqc` feature"
    ))
}

/// Verify `der` as the answer about `ee`, issued by `rest[0]`: a successful
/// response, signed by the issuer or by a responder the issuer certified for
/// OCSP signing, about this certificate, current within [`CLOCK_SKEW_SECS`].
#[cfg(feature = "pqc")]
fn verify(der: &[u8], ee: &[u8], rest: &[CertificateDer<'static>]) -> anyhow::Result<Verdict> {
    use openssl::hash::MessageDigest;
    use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspFlag, OcspResponse, OcspResponseStatus};
    use openssl::stack::Stack;
    use openssl::x509::store::X509StoreBuilder;
    use openssl::x509::verify::X509VerifyFlags;
    use openssl::x509::X509;

    let response = OcspResponse::from_der(der)?;
    if response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(anyhow::anyhow!(
            "responder status {}",
            response.status().as_raw()
        ));
    }
    let basic = response.basic()?;
    let ee = X509::from_der(ee)?;
    let issuer = X509::from_der(&rest[0])?;

    // The issuer is the trust anchor: the response is about a certificate
    // it issued, so it, or a responder it certified, must have signed it.
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(issuer.clone())?;
    store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    let store = store.build();
    let mut certs = Stack::new()?;
    certs.push(issuer.clone())?;
    basic
        .verify(&certs, &store, OcspFlag::TRUST_OTHER)
        .map_err(|e| anyhow::anyhow!("signature: {e}"))?;

    let id = OcspCertId::from_cert(MessageDigest::sha1(), &ee, &issuer)?;
    let status = basic
        .find_status(&id)
        .ok_or_else(|| anyhow::anyhow!("the response is not about this certificate"))?;
    status
        .check_validity(CLOCK_SKEW_SECS, None)
        .map_err(|e| anyhow::anyhow!("not current: {e}"))?;
    let next_update = status.next_update().and_then(system_time);
    Ok(Verdict {
        status: match status.status {
            OcspCertStatus::GOOD => OcspStatus::Good,
            OcspCertStatus::REVOKED => OcspStatus::Revoked,
            _ => OcspStatus::Unknown,
        },
        next_update,
    })
}

#[cfg(not(feature = "pqc"))]
fn verify(_der: &[u8], _ee: &[u8], _rest: &[CertificateDer<'static>]) -> anyhow::Result<Verdict> {
    Err(anyhow::anyhow!(
        "OCSP needs OpenSSL: this build has no `pqc` feature"
    ))
}

/// An ASN.1 GeneralizedTime as OpenSSL prints it ("Nov  2 15:00:00 2026 GMT",
/// fractional seconds allowed), as a `SystemTime`.
#[cfg(feature = "pqc")]
fn system_time(t: &openssl::asn1::Asn1GeneralizedTimeRef) -> Option<SystemTime> {
    let printed = t.to_string();
    let words: Vec<&str> = printed.split_whitespace().collect();
    let [month, day, clock, year, "GMT"] = words.as_slice() else {
        return None;
    };
    let normal = format!("{month} {day} {clock} {year}");
    let at = chrono::NaiveDateTime::parse_from_str(&normal, "%b %d %H:%M:%S%.f %Y").ok()?;
    let secs = u64::try_from(at.and_utc().timestamp()).ok()?;
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// One served certificate's OCSP state, for the admin API
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateOcsp {
    pub name: String,
    pub status: OcspStatus,
    pub responder_url: Option<String>,
    /// The certificate requires stapling (RFC 7633)
    pub must_staple: bool,
    /// A good response is being stapled now
    pub stapled: bool,
    #[serde(serialize_with = "serialize_duration_option")]
    pub fetched_at: Option<Duration>,
    #[serde(serialize_with = "serialize_duration_option")]
    pub expires_in: Option<Duration>,
    pub error: Option<String>,
}

/// OCSP status information for admin API
#[derive(Debug, Clone, serde::Serialize)]
pub struct OcspStatusInfo {
    pub enabled: bool,
    /// The worst status a served certificate has
    pub status: OcspStatus,
    /// The first responder any served certificate names
    pub responder_url: Option<String>,
    #[serde(serialize_with = "serialize_duration_option")]
    pub fetched_at: Option<Duration>,
    #[serde(serialize_with = "serialize_duration_option")]
    pub expires_in: Option<Duration>,
    /// Every certificate that names a responder is stapled, and one is
    pub is_valid: bool,
    pub running: bool,
    pub certificates: Vec<CertificateOcsp>,
}

fn serialize_duration_option<S>(
    duration: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match duration {
        Some(d) => serializer.serialize_str(&format!("{}s", d.as_secs())),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_defaults() {
        let config = OcspConfig::default();
        assert!(config.enabled);
        assert_eq!(config.refresh_before_expiry, Duration::from_hours(1));
        assert_eq!(config.min_refresh_interval, Duration::from_mins(5));
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_ocsp_status_info_serialization() {
        let info = OcspStatusInfo {
            enabled: true,
            status: OcspStatus::Good,
            responder_url: Some("http://ocsp.example.com".to_string()),
            fetched_at: Some(Duration::from_mins(1)),
            expires_in: Some(Duration::from_hours(1)),
            is_valid: true,
            running: true,
            certificates: Vec::new(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"is_valid\":true"));
    }

    /// Responses built and signed here: OpenSSL has no API that signs one.
    #[cfg(feature = "pqc")]
    mod signed {
        use super::super::*;
        use openssl::asn1::Asn1Time;
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::hash::MessageDigest;
        use openssl::nid::Nid;
        use openssl::pkey::{PKey, Private};
        use openssl::sign::Signer;
        use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage};
        use openssl::x509::{X509Name, X509};

        fn key() -> PKey<Private> {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
        }

        fn cert(
            cn: &str,
            serial: u32,
            key: &PKey<Private>,
            issuer: Option<(&X509, &PKey<Private>)>,
            ca: bool,
            ocsp_signing: bool,
        ) -> X509 {
            let mut name = X509Name::builder().unwrap();
            name.append_entry_by_text("CN", cn).unwrap();
            let name = name.build();
            let mut b = X509::builder().unwrap();
            b.set_version(2).unwrap();
            b.set_serial_number(&BigNum::from_u32(serial).unwrap().to_asn1_integer().unwrap())
                .unwrap();
            b.set_subject_name(&name).unwrap();
            b.set_issuer_name(issuer.map_or(&name, |(c, _)| c.subject_name()))
                .unwrap();
            b.set_pubkey(key).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
                .unwrap();
            if ca {
                b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                    .unwrap();
            }
            if ocsp_signing {
                b.append_extension(
                    ExtendedKeyUsage::new()
                        .other("OCSPSigning")
                        .build()
                        .unwrap(),
                )
                .unwrap();
            }
            let signer = issuer.map_or(key, |(_, k)| k);
            b.sign(signer, MessageDigest::sha256()).unwrap();
            b.build()
        }

        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let n = body.len();
            let [.., hi, lo] = u32::try_from(n).unwrap().to_be_bytes();
            if n < 0x80 {
                out.push(lo);
            } else if n < 0x100 {
                out.extend([0x81, lo]);
            } else {
                out.extend([0x82, hi, lo]);
            }
            out.extend_from_slice(body);
            out
        }

        fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
            tlv(0x30, &parts.concat())
        }

        fn time(offset_secs: i64) -> Vec<u8> {
            let at = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
            tlv(0x18, at.format("%Y%m%d%H%M%SZ").to_string().as_bytes())
        }

        /// A BasicOCSPResponse about `ee` (issued by `issuer`), `good` or
        /// revoked, signed by `signer` (whose certificate is included when
        /// it is not the issuer), wrapped in an OCSPResponse.
        fn response(
            ee: &X509,
            issuer: &X509,
            serial: u32,
            good: bool,
            signer: (&X509, &PKey<Private>),
            next_update_secs: i64,
        ) -> Vec<u8> {
            use sha1::{Digest, Sha1};
            let issuer_der = issuer.to_der().unwrap();
            let (_, parsed) = X509Certificate::from_der(&issuer_der).unwrap();
            let name_hash = Sha1::digest(issuer.subject_name().to_der().unwrap());
            let key_hash = Sha1::digest(&parsed.public_key().subject_public_key.data);
            let sha1 = seq(&[tlv(0x06, &[0x2B, 0x0E, 0x03, 0x02, 0x1A]), vec![0x05, 0x00]]);
            let _ = ee;
            let cert_id = seq(&[
                sha1,
                tlv(0x04, &name_hash),
                tlv(0x04, &key_hash),
                tlv(0x02, &BigNum::from_u32(serial).unwrap().to_vec()),
            ]);
            let status = if good {
                vec![0x80, 0x00]
            } else {
                tlv(0xA1, &time(-3600))
            };
            let single = seq(&[
                cert_id,
                status,
                time(-60),
                tlv(0xA0, &time(next_update_secs)),
            ]);
            let signer_der = signer.0.to_der().unwrap();
            let (_, signer_parsed) = X509Certificate::from_der(&signer_der).unwrap();
            let signer_key_hash = Sha1::digest(&signer_parsed.public_key().subject_public_key.data);
            let tbs = seq(&[
                tlv(0xA2, &tlv(0x04, &signer_key_hash)),
                time(-60),
                seq(&[single]),
            ]);
            let mut s = Signer::new(MessageDigest::sha256(), signer.1).unwrap();
            s.update(&tbs).unwrap();
            let signature = s.sign_to_vec().unwrap();
            let ecdsa_sha256 = seq(&[tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02])]);
            let mut bits = vec![0x00];
            bits.extend_from_slice(&signature);
            let mut basic = vec![tbs, ecdsa_sha256, tlv(0x03, &bits)];
            if signer.0.to_der().unwrap() != issuer.to_der().unwrap() {
                basic.push(tlv(0xA0, &seq(&[signer.0.to_der().unwrap()])));
            }
            let basic = seq(&basic);
            // id-pkix-ocsp-basic
            let bytes = seq(&[
                tlv(
                    0x06,
                    &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
                ),
                tlv(0x04, &basic),
            ]);
            seq(&[tlv(0x0A, &[0x00]), tlv(0xA0, &bytes)])
        }

        fn ders(chain: &[&X509]) -> Vec<CertificateDer<'static>> {
            chain
                .iter()
                .map(|c| CertificateDer::from(c.to_der().unwrap()))
                .collect()
        }

        /// What the issuer, or a responder it certified, says is believed;
        /// what anybody else says, about another certificate, or long past,
        /// is not; and the request names the certificate the way the
        /// response is matched.
        #[test]
        fn a_response_is_believed_only_from_the_issuer_and_about_the_certificate() {
            let ca_key = key();
            let ca = cert("Test CA", 1, &ca_key, None, true, false);
            let ee_key = key();
            let ee = cert(
                "ee.example",
                42,
                &ee_key,
                Some((&ca, &ca_key)),
                false,
                false,
            );
            let chain = ders(&[&ee, &ca]);
            // An OCSPRequest: a DER SEQUENCE
            assert_eq!(
                build_request(&chain[0], &chain[1]).unwrap().first(),
                Some(&0x30)
            );

            let good = response(&ee, &ca, 42, true, (&ca, &ca_key), 3 * 86_400);
            let verdict = verify(&good, &chain[0], &chain[1..]).unwrap();
            assert_eq!(verdict.status, OcspStatus::Good);
            let left = verdict
                .next_update
                .unwrap()
                .duration_since(SystemTime::now())
                .unwrap();
            assert!(left > Duration::from_mins(3 * 1_440 - 2));

            let revoked = response(&ee, &ca, 42, false, (&ca, &ca_key), 86_400);
            assert_eq!(
                verify(&revoked, &chain[0], &chain[1..]).unwrap().status,
                OcspStatus::Revoked
            );

            // A responder the CA certified for OCSP signing
            let responder_key = key();
            let responder = cert("OCSP", 7, &responder_key, Some((&ca, &ca_key)), false, true);
            let delegated = response(&ee, &ca, 42, true, (&responder, &responder_key), 86_400);
            assert_eq!(
                verify(&delegated, &chain[0], &chain[1..]).unwrap().status,
                OcspStatus::Good
            );

            // A certificate of the CA's that may not sign OCSP responses
            let other_key = key();
            let other = cert("Other", 8, &other_key, Some((&ca, &ca_key)), false, false);
            let usurped = response(&ee, &ca, 42, true, (&other, &other_key), 86_400);
            assert!(verify(&usurped, &chain[0], &chain[1..]).is_err());

            // Somebody else's CA
            let rogue_key = key();
            let rogue = cert("Test CA", 1, &rogue_key, None, true, false);
            let forged = response(&ee, &ca, 42, true, (&rogue, &rogue_key), 86_400);
            assert!(verify(&forged, &chain[0], &chain[1..]).is_err());

            // About another certificate
            let elsewhere = response(&ee, &ca, 43, true, (&ca, &ca_key), 86_400);
            assert!(verify(&elsewhere, &chain[0], &chain[1..]).is_err());

            // Long past its nextUpdate
            let stale = response(&ee, &ca, 42, true, (&ca, &ca_key), -86_400);
            assert!(verify(&stale, &chain[0], &chain[1..]).is_err());
        }

        /// A good response is stapled on the rustls key that serves the
        /// certificate, and on nothing else.
        #[test]
        fn a_good_response_is_stapled_on_its_certificate() {
            let ca_key = key();
            let ca = cert("Staple CA", 1, &ca_key, None, true, false);
            let ee_key = key();
            let ee = cert(
                "staple.example",
                9,
                &ee_key,
                Some((&ca, &ca_key)),
                false,
                false,
            );
            let chain = ders(&[&ee, &ca]);
            let id = digest(&chain[0]);
            STAPLES.insert(
                id,
                Staple {
                    der: Arc::from(vec![1u8, 2, 3]),
                    until: SystemTime::now() + Duration::from_hours(1),
                },
            );
            let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(
                &rustls::pki_types::PrivateKeyDer::Pkcs8(
                    ee_key.private_key_to_pkcs8().unwrap().into(),
                ),
            )
            .unwrap();
            let key = Arc::new(rustls::sign::CertifiedKey::new(chain.clone(), signing));
            let with = stapled(Arc::clone(&key));
            assert_eq!(with.ocsp.as_deref(), Some(&[1u8, 2, 3][..]));
            assert!(Arc::ptr_eq(&with, &stapled(Arc::clone(&key))), "made once");
            assert_eq!(staple_for(&chain[0]).as_deref(), Some(&[1u8, 2, 3][..]));
            assert!(staple_for(&chain[1]).is_none());
            STAPLES.remove(&id);
            assert!(stapled(key).ocsp.is_none());
        }
    }
}
