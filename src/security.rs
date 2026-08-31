//! Security middleware module
//!
//! Provides comprehensive security features:
//! - Rate limiting (per-IP, per-route, sliding window)
//! - DoS protection with automatic IP blocking
//! - Request validation (size limits, header validation)
//! - IP blocking (manual and automatic)
//! - JA3/JA4 TLS fingerprinting for bot detection
//! - Circuit breaker for backend protection
//! - GeoIP blocking (optional feature)
//!
//! # GeoIP
//! GeoIP blocking is an optional feature requiring MaxMind database integration
//! (enable with `--features geoip`). Active JA3/JA4 fingerprinting lives in `fingerprint.rs`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnet::IpNet;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

// ALT_SVC_HEADER constant removed — P3-fix: header now built dynamically from
// config ports and stored in SecurityState::alt_svc_header.

/// Maximum number of tracked IPs to prevent memory exhaustion DoS
/// When exceeded, oldest entries are evicted
const MAX_TRACKED_IPS: usize = 100_000;

/// Maximum number of tracked JA3 fingerprints
const MAX_JA3_FINGERPRINTS: usize = 50_000;

/// Distinct User-Agents retained per fingerprint.
///
/// Three is enough to name a client and to notice when one fingerprint is worn
/// by several very different agents (which is itself a finding). More would
/// just be a place for a UA-randomising client to write into.
const MAX_UA_PER_FINGERPRINT: usize = 3;

/// Longest User-Agent stored. Anything longer is truncated rather than dropped.
const MAX_UA_LEN: usize = 180;

/// Check if an IP is within the unconditionally trusted loopback range.
///
/// SEC-A05: Only loopback addresses (127.0.0.0/8 and ::1) are unconditionally
/// trusted.  RFC1918 private ranges are NOT implicitly trusted because an attacker
/// with LAN access could spoof any private-range address and bypass rate limiting
/// and IP blocking.  Operators who need to trust specific RFC1918 ranges (e.g. a
/// known internal load-balancer) must enumerate those CIDRs explicitly in the
/// `security.trusted_internal_cidrs` config list.
fn is_trusted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            // Loopback only (127.0.0.0/8)
            v4.is_loopback()
        }
        IpAddr::V6(v6) => {
            // Loopback (::1)
            v6.is_loopback() ||
            // IPv4-mapped loopback (::ffff:127.0.0.1)
            v6.to_ipv4_mapped().map(|v4| v4.is_loopback()).unwrap_or(false)
        }
    }
}

/// Canonicalize a peer socket address: unwrap IPv4-mapped IPv6
/// (`::ffff:a.b.c.d` → `a.b.c.d`), preserving the port.
///
/// The listeners bind `[::]` (dual-stack), so IPv4 clients arrive as
/// IPv4-mapped IPv6 addresses. Every IP comparison downstream — blocklists,
/// pentest bypass, fail2ban log parsing, X-Forwarded-For, backend API key
/// whitelists — expects the plain IPv4 form, so normalize once at the
/// accept boundary instead of at each consumer.
pub fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

/// Check if a CIDR block (IpNet) contains the given IP address.
/// Handles IPv4/IPv6 matching; mismatched address families return false.
fn cidr_contains_ip(net: &IpNet, addr: &IpAddr) -> bool {
    match (net, addr) {
        (IpNet::V4(n), IpAddr::V4(a)) => {
            let prefix = u32::from(n.prefix_len());
            if prefix == 0 {
                return true;
            }
            let mask: u32 = u32::MAX.wrapping_shl(32 - prefix);
            u32::from(n.addr()) & mask == u32::from(*a) & mask
        }
        (IpNet::V6(n), IpAddr::V6(a)) => {
            let prefix = u32::from(n.prefix_len());
            if prefix == 0 {
                return true;
            }
            let mask: u128 = u128::MAX.wrapping_shl(128 - prefix);
            u128::from(n.addr()) & mask == u128::from(*a) & mask
        }
        _ => false,
    }
}

/// Add Alt-Svc header to a response for HTTP/3 advertisement.
/// P3-fix: header value is now passed in from SecurityState::alt_svc_header
/// (built from config ports) rather than a hardcoded constant.
fn add_alt_svc(response: &mut Response, header: &str) {
    if let Ok(value) = HeaderValue::from_str(header) {
        response.headers_mut().insert("alt-svc", value);
    }
}
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::config::{CircuitBreakerConfig, ProxyConfig, RateLimitConfig, SecurityConfig};
use crate::crawler_verify::{CrawlerVerdict, CrawlerVerifier};
use crate::waf::{WafEngine, WafRequest, WafVerdict};

/// Entry in a JA3/JA4 fingerprint database JSON file.
/// Expected format: [{hash, classification, description}]
#[derive(serde::Deserialize, Clone, Debug)]
struct Ja3DbEntry {
    hash: String,
    classification: String,
}

/// JA3/JA4 fingerprint database loaded from a JSON file at startup.
/// Classification is advisory-only and never causes automatic blocking.
#[derive(Clone, Default, Debug)]
pub struct Ja3Database {
    entries: std::collections::HashMap<String, FingerprintClass>,
}

impl Ja3Database {
    /// Load fingerprints from a JSON file.
    /// Returns an error if the file cannot be read or the JSON is malformed.
    pub fn load_from_file(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let raw: Vec<Ja3DbEntry> = serde_json::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut entries = std::collections::HashMap::new();
        for entry in raw {
            let class = match entry.classification.as_str() {
                "browser" => FingerprintClass::Browser,
                "bot" | "legitimate_bot" => FingerprintClass::LegitimateBot,
                "malicious" => FingerprintClass::Malicious,
                "scanner" => FingerprintClass::Scanner,
                "api_client" => FingerprintClass::ApiClient,
                _ => FingerprintClass::Suspicious,
            };
            entries.insert(entry.hash.to_lowercase(), class);
        }
        Ok(Self { entries })
    }

    /// Classify a JA3/JA4 hash.
    /// Returns `Suspicious` for hashes not present in the database.
    pub fn classify(&self, hash: &str) -> FingerprintClass {
        self.entries
            .get(&hash.to_lowercase())
            .cloned()
            .unwrap_or(FingerprintClass::Suspicious)
    }

    /// Classify a client from both of its fingerprints, preferring whichever
    /// the database actually knows.
    ///
    /// JA3 alone is not sufficient for tools that vary their cipher list
    /// between probes: nmap's ssl-enum-ciphers produced a completely different
    /// JA3 on every run against this proxy while its JA4 stayed identical,
    /// because JA4 sorts and summarises where JA3 hashes the raw order. A
    /// database keyed only on JA3 therefore cannot recognise a scanner it has
    /// already met — which is why entries for such tools have to be JA4.
    pub fn classify_pair(&self, ja3: &str, ja4: Option<&str>) -> FingerprintClass {
        if let Some(class) = self.entries.get(&ja3.to_lowercase()) {
            return class.clone();
        }
        if let Some(ja4) = ja4 {
            if let Some(class) = self.entries.get(&ja4.to_lowercase()) {
                return class.clone();
            }
        }
        FingerprintClass::Suspicious
    }

    /// Number of entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the database contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Security state shared across all requests
#[derive(Clone)]
pub struct SecurityState {
    /// Per-IP rate limiters with last-access timestamp for LRU eviction (AUD-07).
    /// Tuple: (limiter, last_access_time).  The timestamp is updated on every
    /// call to get_ip_rate_limiter so that least-recently-used entries are
    /// evicted first when the map exceeds MAX_TRACKED_IPS.
    pub ip_rate_limiters: Arc<
        DashMap<
            IpAddr,
            (
                Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
                Instant,
            ),
        >,
    >,
    /// Per-IP connection counters
    pub ip_connections: Arc<DashMap<IpAddr, u32>>,
    /// Blocked IPs with expiration time
    pub blocked_ips: Arc<DashMap<IpAddr, BlockedIpInfo>>,
    /// Request count per IP for adaptive blocking
    pub request_counts: Arc<DashMap<IpAddr, RequestCounter>>,
    /// New-connection timestamps per IP, for `rate_limiting.connection_rate_limit`.
    /// Separate from `ip_connections`, which caps how many connections an IP may
    /// hold at once: this caps how fast it may open them.
    pub connection_rates: Arc<DashMap<IpAddr, ConnectionRateWindow>>,
    /// JA3 fingerprint cache (fingerprint -> classification)
    pub ja3_cache: Arc<DashMap<String, TlsFingerprint>>,
    /// Circuit breaker states per backend
    pub circuit_breakers: Arc<DashMap<String, CircuitBreakerState>>,
    /// Configuration
    pub config: Arc<RwLock<SecurityConfig>>,
    /// Rate limit configuration
    pub rate_config: Arc<RwLock<RateLimitConfig>>,
    /// Snapshot of the routing table, used only to resolve a request's route
    /// before the security checks run.
    ///
    /// The WAF and rate limiter sit in front of routing, so without this they
    /// cannot see per-route policy — which is why routes.skip_bot_blocking and
    /// the whole [routes.security] block did nothing. Snapshotting matches how
    /// rate_config and the security config are already held here; matching uses
    /// ProxyConfig::find_route so the route chosen is the same one the proxy
    /// will use downstream.
    pub route_index: Arc<ProxyConfig>,
    /// Circuit breaker configuration
    pub circuit_breaker_config: Arc<RwLock<CircuitBreakerConfig>>,
    /// Global rate limiter (fallback)
    pub global_rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// GeoIP database (optional)
    #[cfg(feature = "geoip")]
    pub geoip_db: Option<Arc<GeoIpDb>>,
    /// JA3/JA4 fingerprint database (advisory-only, never blocks)
    pub ja3_db: Arc<Ja3Database>,
    /// WAF engine (None if WAF disabled)
    pub waf_engine: Option<Arc<WafEngine>>,
    /// CIDR ranges from database-synced blocklist files.
    /// P2-fix: single-IP parsing previously ignored subnet notation; CIDRs now stored
    /// separately and checked in is_blocked() via cidr_contains_ip().
    pub blocked_cidrs: Arc<RwLock<Vec<(IpNet, BlockedIpInfo)>>>,
    /// Pre-built Alt-Svc header value derived from config ports at construction.
    /// P3-fix: previously a hardcoded constant listing ports 443/4433/4434.
    /// Now reflects the actual configured udp_port and additional_ports.
    pub alt_svc_header: Arc<str>,
    /// Forward-confirmed reverse-DNS cache for search-engine crawlers.
    ///
    /// A rendering crawler fetches a document and all its subresources at once,
    /// which the connection-rate limiter reads as a flood and answers with a
    /// 300s ban — that is what reduced Google to ~110 requests/day and made
    /// Search Console report 403 on healthy URLs. Verified crawlers are exempted
    /// from the rate limiters here, the same way pentest_bypass_ips are, and for
    /// the same reason: the limiter is aimed at abuse, not at these clients.
    pub crawler_verifier: Arc<CrawlerVerifier>,
}

/// Information about a blocked IP
#[derive(Clone, Debug)]
pub struct BlockedIpInfo {
    /// When the IP was blocked
    pub blocked_at: Instant,
    /// When the block expires (None = permanent)
    pub expires_at: Option<Instant>,
    /// Reason for blocking
    pub reason: BlockReason,
    /// Number of times this IP has been blocked
    pub block_count: u32,
}

/// Reason for IP block
#[derive(Clone, Debug)]
pub enum BlockReason {
    /// Manually configured in config
    Manual,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Too many connections
    ConnectionLimitExceeded,
    /// Suspicious TLS fingerprint
    SuspiciousFingerprint,
    /// Too many 4xx errors
    TooManyErrors,
    /// GeoIP blocked country
    GeoBlocked,
    /// Synced from database blocklist
    DatabaseSync,
}

/// Entry from the database-synced blocklist JSON file
#[derive(serde::Deserialize)]
struct BlocklistEntry {
    ip: String,
    expires_at: Option<String>,
}

/// Outcome of the transport-independent security evaluation.
///
/// Rendering differs between transports — axum builds a `Response`, the HTTP/3
/// handler builds an `http::Response<()>` and writes it to a stream — but the
/// decision itself must not. Returning a verdict rather than a response is what
/// lets both paths share one implementation of the rules.
#[derive(Debug, Clone)]
pub enum SecurityDecision {
    /// No rule matched; continue processing.
    Allow,
    /// Source IP is on the blocklist.
    Blocked(BlockedIpInfo),
    /// Source IP resolves to a blocked country.
    GeoBlocked,
    /// Request rate or connection rate exceeded; `limit` is the figure that applied.
    ///
    /// `kind` says which of the two fired. They are separate controls with separate
    /// thresholds, and the variant used to report only the number — so a caller seeing
    /// `limit: 10` against a config declaring `requests_per_second = 200` had no way to
    /// know it was looking at the connection limiter. The startup attestation reported
    /// "rate limiting enforced" for either, which was true but conflated two controls
    /// and would have hidden one of them failing while the other worked.
    RateLimited {
        limit: u32,
        retry_after_secs: u64,
        kind: RateLimitKind,
    },
    /// Route names a JA3 allowlist this client is not on.
    Ja3Rejected,
    /// Header block exceeds `security.max_header_size`.
    HeadersTooLarge { max: usize },
    /// WAF matched in block mode. `rule` identifies which.
    WafBlock { rule: String },
}

/// Which rate control refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitKind {
    /// New connections per second from one source.
    Connection,
    /// Requests per second from one source.
    Request,
}

impl RateLimitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection rate",
            Self::Request => "request rate",
        }
    }
}

/// A request reduced to what the security rules actually need.
///
/// Deliberately transport-agnostic: no axum, no h3, no body ownership. Anything
/// that cannot be expressed here does not belong in a shared rule.
pub struct SecurityRequestView<'a> {
    pub ip: IpAddr,
    pub method: &'a str,
    /// Lowercased path
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HeaderMap,
    /// Body bytes when already buffered, for WAF body inspection. None means
    /// the caller has not buffered a body — not that the body is empty.
    pub body: Option<&'a [u8]>,
}

/// Whether this path is one we publish *for* machines to fetch.
///
/// The bad-bot user-agent rules return 403 to curl, wget, python-requests, Go's
/// HTTP client and an empty UA alike. That is a reasonable default for pages,
/// and it leaves crawling untouched (Googlebot passes). It is the wrong answer
/// for the handful of paths whose entire purpose is programmatic access — and
/// our own documentation tells people to `curl` every one of these, so following
/// the instructions on the site produced a 403.
///
/// Invisible from the server itself: loopback, this host's egress and api3 are
/// all in `pentest_bypass_ips`, so a check run from any of them passes while
/// real visitors are blocked. Verify from a node with no bypass.
///
/// Deliberately a list of exact paths and narrow prefixes rather than whole page
/// directories: the aim is to unblock the published artefacts, not to switch the
/// protection off for the pages around them.
fn is_machine_readable_path(path: &str) -> bool {
    // Files that exist to be read by tools, by convention.
    const WELL_KNOWN: &[&str] = &[
        "/robots.txt",
        "/sitemap.xml",
        "/llms.txt",
        // Datasets and APIs our pages document with a curl command.
        "/ja4/api.php", // llms.txt calls this "machine-readable, no auth, CORS open"
        "/handshake/api.php",
    ];

    if WELL_KNOWN.contains(&path) {
        return true;
    }

    // Sitemaps, and the .well-known tree (security.txt and friends).
    if path.starts_with("/sitemaps/") || path.starts_with("/.well-known/") {
        return true;
    }

    // The published post-quantum certificate chain, which /pqc/ documents
    // fetching with curl. Extension-gated so this covers the artefacts and not
    // the page that describes them. `view.path` arrives lowercased, so a
    // lowercase match here is exact.
    if path.starts_with("/pqc/")
        && path
            .rsplit_once('.')
            .is_some_and(|(_, ext)| matches!(ext, "pem" | "crt" | "der" | "json"))
    {
        return true;
    }

    // The MASQUE reference client source, which /masque/ tells you to curl.
    path.starts_with("/masque/client/")
}

/// Whether `host` is the conformance suite's own vhost.
///
/// That host is answered in-process before route lookup, so it has no route
/// entry and cannot carry `skip_bot_blocking` the way an ordinary route can —
/// but it is the one host on this proxy whose entire purpose is non-browser
/// traffic. Its documented workflow is curl, its CI driver shells out to curl,
/// and the thing under test is an HTTP/3 *client library*, so the bad-bot
/// user-agent rules were rejecting exactly the traffic the service exists for.
///
/// This was invisible from the server itself: loopback and our own egress are
/// already bypassed, so every check run from here passed while every real
/// visitor got 403.
///
/// Takes the host rather than reading it from the request, because the two
/// callers resolve it differently and only they can do it correctly — HTTP/2
/// and HTTP/3 carry no `Host` header, only an `:authority` that hyper surfaces
/// through the URI.
pub fn is_conformance_host(config: &ProxyConfig, host: Option<&str>) -> bool {
    let conf = &config.conformance;
    conf.enabled
        && host.is_some_and(|h| {
            let h = h.split(':').next().unwrap_or(h);
            h.eq_ignore_ascii_case(&conf.host)
        })
}

/// Per-route security settings resolved for a single request.
///
/// Flattened out of `RouteConfig` and `RouteSecurityPolicy` so the middleware
/// does not hold a borrow on the route table while it works.
#[derive(Clone, Debug, Default)]
pub struct RequestPolicy {
    /// Route opts out of scanner/bot user-agent blocking
    pub skip_bot_blocking: bool,
    /// Only these JA3 hashes may reach this route
    pub allowed_ja3: Option<Vec<String>>,
    /// Per-route WAF on/off, overriding waf.enabled
    pub waf_enabled: Option<bool>,
    /// Per-route WAF mode ("block" | "detect"), overriding waf.mode
    pub waf_mode: Option<String>,
    /// Per-route rate limits, overriding `[rate_limiting]`
    pub rate_limit_override: Option<RateLimitConfig>,
}

/// One-second sliding window of new connections from a single IP.
#[derive(Clone, Debug)]
pub struct ConnectionRateWindow {
    /// Start of the current one-second window
    pub window_start: Instant,
    /// Connections accepted from this IP within the window
    pub count: u32,
}

/// Request counter for adaptive rate limiting
#[derive(Clone, Debug, Default)]
pub struct RequestCounter {
    /// Total requests in current window
    pub total_requests: u64,
    /// 4xx error count
    pub error_4xx: u32,
    /// 5xx error count
    pub error_5xx: u32,
    /// Window start time
    pub window_start: Option<Instant>,
    /// Suspicious request patterns detected
    pub suspicious_patterns: u32,
}

/// TLS fingerprint classification
#[derive(Clone, Debug)]
pub struct TlsFingerprint {
    /// JA3 hash
    pub ja3_hash: String,
    /// JA4 hash (if available)
    pub ja4_hash: Option<String>,
    /// The pre-hash JA3 input:
    /// `version,ciphers,extensions,curves,point_formats`.
    ///
    /// The extractor has always computed this and thrown it away, keeping only
    /// the MD5. Without it a JA3 is undecodable — which is why the public
    /// directory could show nothing at all for 160 of its 179 entries. Keeping
    /// it costs ~200 bytes per distinct fingerprint and makes them readable.
    pub ja3_string: String,
    /// Classification (browser, bot, scanner, etc.)
    pub classification: FingerprintClass,
    /// Which transport carried the ClientHello: 't' (TCP) or 'q' (QUIC).
    pub transport: char,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Most recent sighting. Drives eviction and the "last seen" the directory
    /// reports; `first_seen` alone cannot distinguish a fingerprint seen once a
    /// year ago from one arriving continuously.
    pub last_seen: Instant,
    /// Request count with this fingerprint
    pub request_count: u64,
    /// User-Agents seen on requests carrying this fingerprint, with counts.
    ///
    /// The fingerprint is computed at the TLS layer, where no HTTP request
    /// exists yet — which is why the corpus could say what connected but never
    /// what it called itself, and why almost everything in the public directory
    /// read "unclassified". The HTTP layer has both, so it reports back here.
    ///
    /// Bounded at `MAX_UA_PER_FINGERPRINT`: a client that randomises its
    /// User-Agent must not be able to grow this without limit.
    pub user_agents: HashMap<String, u64>,
}

/// One observed fingerprint, in a form that survives a restart.
///
/// Separate from [`TlsFingerprint`] because that holds `Instant`s, which are
/// monotonic-clock readings with no meaning across processes. Timestamps here
/// are Unix seconds, derived at flush time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObservedFingerprint {
    pub ja3_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_hash: Option<String>,
    #[serde(default)]
    pub ja3_string: String,
    pub classification: String,
    #[serde(default = "default_transport")]
    pub transport: char,
    pub first_seen: u64,
    pub last_seen: u64,
    pub request_count: u64,
    #[serde(default)]
    pub user_agents: HashMap<String, u64>,
}

fn default_transport() -> char {
    't'
}

impl SecurityState {
    /// Where observed fingerprints are persisted between restarts.
    pub const OBSERVED_PATH: &'static str = "/var/lib/pqcrypta-proxy/fingerprints/observed.json";

    /// Snapshot the observed-fingerprint corpus to disk.
    ///
    /// Written atomically through a temp file: the public directory reads this
    /// on a timer, and a half-written file would be a parse error served to
    /// visitors rather than a stale-but-valid one.
    ///
    /// `Instant` is a monotonic reading with no meaning to another process, so
    /// timestamps are converted to Unix seconds here by walking each elapsed
    /// duration back from the current wall clock.
    pub fn flush_observed_fingerprints(&self) -> std::io::Result<usize> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let to_unix = |i: Instant| now_unix.saturating_sub(i.elapsed().as_secs());

        let records: Vec<ObservedFingerprint> = self
            .ja3_cache
            .iter()
            .map(|e| {
                let v = e.value();
                ObservedFingerprint {
                    ja3_hash: v.ja3_hash.clone(),
                    ja4_hash: v.ja4_hash.clone(),
                    ja3_string: v.ja3_string.clone(),
                    classification: format!("{:?}", v.classification),
                    transport: v.transport,
                    first_seen: to_unix(v.first_seen),
                    last_seen: to_unix(v.last_seen),
                    request_count: v.request_count,
                    user_agents: v.user_agents.clone(),
                }
            })
            .collect();

        let path = std::path::Path::new(Self::OBSERVED_PATH);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(&records)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        // 0644: the export job feeding the public directory runs unprivileged.
        // These are observations, not policy — this file bans nobody by itself.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(&tmp, path)?;

        Ok(records.len())
    }

    /// Record the User-Agent a request carrying this fingerprint presented.
    ///
    /// Called from the HTTP layer, which is the only place both facts exist at
    /// once: the fingerprint comes off the TLS handshake, the User-Agent off the
    /// request that followed it. Correlating them is what turns a corpus of
    /// opaque hashes into named clients — it is how public JA4 databases are
    /// built, and without it the directory could only ever say "unclassified".
    ///
    /// A no-op when the fingerprint is unknown or the header is absent, and
    /// cheap in the common case: one `DashMap` lookup and a counter bump on an
    /// entry that already exists.
    pub fn note_user_agent(&self, ja3_hash: &str, user_agent: &str) {
        if ja3_hash.is_empty() || user_agent.is_empty() {
            return;
        }

        let Some(mut entry) = self.ja3_cache.get_mut(ja3_hash) else {
            return;
        };

        let ua: String = user_agent.chars().take(MAX_UA_LEN).collect();

        if let Some(count) = entry.user_agents.get_mut(&ua) {
            *count = count.saturating_add(1);
            return;
        }

        // New agent for this fingerprint. Evict the least-seen if full, so a
        // client rotating its User-Agent cannot push out the one real name.
        if entry.user_agents.len() >= MAX_UA_PER_FINGERPRINT {
            if let Some(weakest) = entry
                .user_agents
                .iter()
                .min_by_key(|(_, c)| **c)
                .map(|(k, _)| k.clone())
            {
                // Only displace an agent seen less often than once; a
                // one-off should not evict an established name.
                if entry.user_agents.get(&weakest).copied().unwrap_or(0) > 1 {
                    return;
                }
                entry.user_agents.remove(&weakest);
            }
        }

        entry.user_agents.insert(ua, 1);
    }

    /// Reload the corpus written by a previous run.
    ///
    /// Counts and first-seen dates are the point: without this, every restart
    /// resets the corpus to "nothing has ever been seen", and a proxy that
    /// restarts on config reload would never accumulate one at all.
    ///
    /// A missing or corrupt file is not an error — first boot is the normal
    /// case, and a bad file must not stop the proxy starting.
    pub fn load_observed_fingerprints(&self) -> usize {
        let Ok(bytes) = std::fs::read(Self::OBSERVED_PATH) else {
            return 0;
        };
        let Ok(records) = serde_json::from_slice::<Vec<ObservedFingerprint>>(&bytes) else {
            warn!("Observed fingerprint corpus is unreadable — starting empty");
            return 0;
        };

        let now = Instant::now();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Rebuild Instants by walking the wall-clock age backwards. A record
        // stamped in the future (clock moved) collapses to "just now" rather
        // than underflowing.
        let to_instant = |unix: u64| {
            now.checked_sub(Duration::from_secs(now_unix.saturating_sub(unix)))
                .unwrap_or(now)
        };

        let mut loaded = 0;
        for r in records {
            self.ja3_cache.insert(
                r.ja3_hash.clone(),
                TlsFingerprint {
                    ja3_hash: r.ja3_hash,
                    ja4_hash: r.ja4_hash,
                    ja3_string: r.ja3_string,
                    classification: FingerprintClass::from_label(&r.classification),
                    transport: r.transport,
                    first_seen: to_instant(r.first_seen),
                    last_seen: to_instant(r.last_seen),
                    request_count: r.request_count,
                    user_agents: r.user_agents,
                },
            );
            loaded += 1;
        }
        loaded
    }
}

/// Fingerprint classification
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintClass {
    /// Known browser fingerprint
    Browser,
    /// Known bot/crawler (legitimate)
    LegitimateBot,
    /// Suspicious/unknown fingerprint
    Suspicious,
    /// Known malicious fingerprint
    Malicious,
    /// Known scanner/security tool
    Scanner,
    /// API client (curl, etc.)
    ApiClient,
}

impl FingerprintClass {
    /// Parse back the `Debug` spelling written by the flush.
    ///
    /// Anything unrecognised becomes `Suspicious` — the same default a
    /// never-before-seen fingerprint gets, so a corpus written by a future
    /// version with new variants degrades instead of being discarded.
    fn from_label(label: &str) -> Self {
        match label {
            "Browser" => Self::Browser,
            "LegitimateBot" => Self::LegitimateBot,
            "Malicious" => Self::Malicious,
            "Scanner" => Self::Scanner,
            "ApiClient" => Self::ApiClient,
            _ => Self::Suspicious,
        }
    }
}

/// Circuit breaker state for backend protection
#[derive(Clone, Debug)]
pub struct CircuitBreakerState {
    /// Current state
    pub state: CircuitState,
    /// Failure count in current window
    pub failure_count: u32,
    /// Success count since last failure
    pub success_count: u32,
    /// Last state change
    pub last_state_change: Instant,
    /// Half-open test requests allowed
    pub half_open_requests: u32,
}

/// Circuit breaker states
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Failures detected, allowing limited requests
    HalfOpen,
    /// Too many failures, rejecting all requests
    Open,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_state_change: Instant::now(),
            half_open_requests: 0,
        }
    }
}

impl SecurityState {
    /// Create new security state from configuration
    pub fn new(config: &ProxyConfig) -> Self {
        // Create global rate limiter
        let rate_per_second = config.rate_limiting.requests_per_second;
        let burst = config.rate_limiting.burst_size;

        // Safe NonZeroU32 construction - use .max(1) to ensure non-zero, then unwrap_or(MIN) as fallback
        let rps = NonZeroU32::new(rate_per_second.max(1)).unwrap_or(NonZeroU32::MIN);
        let burst_nz = NonZeroU32::new(burst.max(1)).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(rps).allow_burst(burst_nz);

        let global_rate_limiter = Arc::new(RateLimiter::direct(quota));

        // Pre-populate blocked IPs from config
        let blocked_ips = Arc::new(DashMap::new());
        for ip_str in &config.security.blocked_ips {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                blocked_ips.insert(
                    ip,
                    BlockedIpInfo {
                        blocked_at: Instant::now(),
                        expires_at: None, // Permanent for manual blocks
                        reason: BlockReason::Manual,
                        block_count: 1,
                    },
                );
            }
        }

        // Load GeoIP database if configured
        #[cfg(feature = "geoip")]
        let geoip_db =
            config
                .security
                .geoip_db_path
                .as_ref()
                .and_then(|path| match GeoIpDb::new(path) {
                    Ok(db) => {
                        info!("✅ GeoIP database loaded from {:?}", path);
                        Some(Arc::new(db))
                    }
                    Err(e) => {
                        warn!("⚠️ Failed to load GeoIP database from {:?}: {}", path, e);
                        None
                    }
                });

        // Load JA3/JA4 fingerprint database (advisory-only)
        let ja3_db = if let Some(ref db_path) = config.fingerprint.fingerprint_db_path {
            match Ja3Database::load_from_file(db_path) {
                Ok(db) => {
                    if db.is_empty() {
                        warn!(
                            "JA3 fingerprint database at {:?} is empty - classification will return Suspicious for all hashes",
                            db_path
                        );
                    } else {
                        info!(
                            "Loaded {} JA3/JA4 fingerprints from {:?}",
                            db.len(),
                            db_path
                        );
                    }
                    db
                }
                Err(e) => {
                    warn!(
                        "Could not load JA3 fingerprint database from {:?}: {} - continuing with empty DB",
                        db_path, e
                    );
                    Ja3Database::default()
                }
            }
        } else {
            Ja3Database::default()
        };

        // Build WAF engine if enabled
        let waf_engine = if config.waf.enabled {
            Some(Arc::new(WafEngine::new(&config.waf)))
        } else {
            None
        };

        // P3-fix: Build the Alt-Svc header from the configured ports rather than
        // a hardcoded string.  Collect the primary UDP port + any additional ports.
        let alt_svc_header: Arc<str> = {
            let mut parts = vec![format!("h3=\":{}\"; ma=86400", config.server.udp_port)];
            for p in &config.server.additional_ports {
                parts.push(format!("h3=\":{}\"; ma=86400", p));
            }
            parts.join(", ").into()
        };

        let state = Self {
            ip_rate_limiters: Arc::new(DashMap::new()),
            ip_connections: Arc::new(DashMap::new()),
            connection_rates: Arc::new(DashMap::new()),
            blocked_ips,
            request_counts: Arc::new(DashMap::new()),
            ja3_cache: Arc::new(DashMap::new()),
            crawler_verifier: Arc::new(CrawlerVerifier::new()),
            circuit_breakers: Arc::new(DashMap::new()),
            config: Arc::new(RwLock::new(config.security.clone())),
            rate_config: Arc::new(RwLock::new(config.rate_limiting.clone())),
            route_index: Arc::new(config.clone()),
            circuit_breaker_config: Arc::new(RwLock::new(config.circuit_breaker.clone())),
            global_rate_limiter,
            #[cfg(feature = "geoip")]
            geoip_db,
            ja3_db: Arc::new(ja3_db),
            waf_engine,
            blocked_cidrs: Arc::new(RwLock::new(Vec::new())),
            alt_svc_header,
        };

        // Spawn background cleanup task
        state.spawn_cleanup_task();

        state
    }

    /// Check whether an IP should bypass security checks.
    ///
    /// SEC-A05: Unconditionally trusts loopback only.  RFC1918 private ranges are
    /// NOT implicitly trusted — they must be listed in `security.trusted_internal_cidrs`
    /// to receive bypass treatment, making the trust decision explicit and auditable.
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        if is_trusted_ip(ip) {
            return true;
        }
        let config = self.config.read();
        // DEPRECATED: trusted_internal_cidrs is deprecated in favour of mTLS
        // client certificate verification (tls.require_client_cert = true).
        // A startup warning is emitted in main.rs when any CIDRs are configured.
        // IP-based trust will be removed in a future release.
        for cidr in &config.trusted_internal_cidrs {
            if cidr_contains_ip(cidr, ip) {
                return true;
            }
        }
        false
    }

    /// Spawn a background task that periodically cleans up expired entries
    /// and reloads blocklists from database sync
    fn spawn_cleanup_task(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            loop {
                interval.tick().await;
                // Reload blocklists from database sync files
                state.reload_blocklist_from_files();
                // Cleanup expired entries
                state.cleanup();
                debug!("Security state cleanup and blocklist reload completed");
            }
        });
    }

    /// Check if an IP is from a blocked country
    #[cfg(feature = "geoip")]
    pub fn is_country_blocked(&self, ip: &IpAddr) -> bool {
        let config = self.config.read();
        if config.blocked_countries.is_empty() {
            return false;
        }

        if let Some(ref db) = self.geoip_db {
            return db.is_country_blocked(*ip, &config.blocked_countries);
        }
        false
    }

    #[cfg(not(feature = "geoip"))]
    pub fn is_country_blocked(&self, _ip: &IpAddr) -> bool {
        false
    }

    /// Get or create rate limiter for an IP.
    ///
    /// AUD-07: The last-access timestamp is updated on every call so that the
    /// cleanup task can perform LRU eviction rather than arbitrary eviction.
    pub fn get_ip_rate_limiter(
        &self,
        ip: IpAddr,
    ) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        let mut entry = self.ip_rate_limiters.entry(ip).or_insert_with(|| {
            let config = self.rate_config.read();
            // Safe NonZeroU32 construction - use .max(1) to ensure non-zero
            let rps = NonZeroU32::new(config.requests_per_second.max(1)).unwrap_or(NonZeroU32::MIN);
            let burst_nz = NonZeroU32::new(config.burst_size.max(1)).unwrap_or(NonZeroU32::MIN);
            let quota = Quota::per_second(rps).allow_burst(burst_nz);
            (Arc::new(RateLimiter::direct(quota)), Instant::now())
        });
        // Update last-access time for LRU eviction
        entry.1 = Instant::now();
        entry.0.clone()
    }

    /// Check if an IP is blocked (single-IP list or CIDR range).
    pub fn is_blocked(&self, ip: &IpAddr) -> Option<BlockedIpInfo> {
        // 1. Single-IP block list
        if let Some(info) = self.blocked_ips.get(ip) {
            if let Some(expires) = info.expires_at {
                if Instant::now() > expires {
                    drop(info);
                    self.blocked_ips.remove(ip);
                    // Fall through to CIDR check in case the IP also matches a range.
                } else {
                    return Some(info.clone());
                }
            } else {
                return Some(info.clone());
            }
        }

        // 2. P2-fix: CIDR range block list (skips expired entries inline).
        let cidrs = self.blocked_cidrs.read();
        for (net, info) in cidrs.iter() {
            if let Some(expires) = info.expires_at {
                if Instant::now() > expires {
                    continue; // expired entry — evicted during next cleanup()
                }
            }
            if cidr_contains_ip(net, ip) {
                return Some(info.clone());
            }
        }

        None
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr, reason: BlockReason, duration: Option<Duration>) {
        // Never block trusted IPs (loopback, or operator-configured trusted_internal_cidrs)
        if self.is_trusted(&ip) {
            debug!(
                "Skipping block for trusted IP {} (reason: {:?})",
                ip, reason
            );
            return;
        }

        let expires_at = duration.map(|d| Instant::now() + d);

        let block_count = self
            .blocked_ips
            .get(&ip)
            .map(|info| info.block_count + 1)
            .unwrap_or(1);

        warn!(
            "Blocked IP {} for {:?} (reason: {:?}, block count: {})",
            ip,
            duration
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "permanent".to_string()),
            reason,
            block_count
        );

        self.blocked_ips.insert(
            ip,
            BlockedIpInfo {
                blocked_at: Instant::now(),
                expires_at,
                reason,
                block_count,
            },
        );
    }

    /// Remove an IP from the in-memory blocklist, including any CIDR entry that
    /// covers it. Returns the number of entries dropped.
    ///
    /// This is the operator escape hatch behind `POST /blocklist/unblock/:ip`.
    /// Clearing the database row alone is not enough for an IP that is already
    /// blocked in memory: the row stops being synced, but the running proxy keeps
    /// the entry until it expires. Removing it here takes effect immediately.
    pub fn unblock_ip(&self, ip: IpAddr) -> usize {
        let mut removed = 0;
        if self.blocked_ips.remove(&ip).is_some() {
            removed += 1;
        }
        let mut cidrs = self.blocked_cidrs.write();
        let before = cidrs.len();
        cidrs.retain(|(net, _)| !cidr_contains_ip(net, &ip));
        removed += before - cidrs.len();
        if removed > 0 {
            info!("Unblocked IP {} ({} entry/entries removed)", ip, removed);
        }
        removed
    }

    /// Snapshot of currently blocked IPs and CIDRs, for the admin API.
    pub fn blocklist_snapshot(&self) -> (Vec<(IpAddr, String)>, Vec<(IpNet, String)>) {
        let ips = self
            .blocked_ips
            .iter()
            .map(|e| (*e.key(), format!("{:?}", e.value().reason)))
            .collect();
        let cidrs = self
            .blocked_cidrs
            .read()
            .iter()
            .map(|(n, i)| (*n, format!("{:?}", i.reason)))
            .collect();
        (ips, cidrs)
    }

    /// Reload blocklist from JSON files (synced from database).
    /// Uses the path configured in `security.blocklist_dir` (default: /var/lib/pqcrypta-proxy/blocklists).
    pub fn reload_blocklist_from_files(&self) {
        let blocklist_dir = self.config.read().blocklist_dir.clone();
        let blocked_ips_file = blocklist_dir.join("blocked_ips.json");

        if !blocked_ips_file.exists() {
            return;
        }

        // SR-07: Check that the blocklist file is not world-writable (Unix only).
        // A world-writable blocklist could let an attacker inject arbitrary block
        // entries (DoS on legitimate clients) or clear existing blocks (bypass).
        // Warn loudly so operators can fix the permissions before they cause a
        // security incident.  The recommended mode is 0640 (owner rw, group r).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = std::fs::metadata(&blocked_ips_file) {
                let mode = meta.mode();
                // Check other-write (bit 1) and other-read (bit 2) and group-write (bit 4)
                if mode & 0o002 != 0 {
                    warn!(
                        "SR-07: Blocklist file {} is world-writable (mode {:o}). \
                         This allows any local user to tamper with the blocklist. \
                         Run: chmod 640 {}",
                        blocked_ips_file.display(),
                        mode & 0o777,
                        blocked_ips_file.display(),
                    );
                } else if mode & 0o020 != 0 {
                    warn!(
                        "SR-07: Blocklist file {} is group-writable (mode {:o}). \
                         Restrict to mode 640 to prevent unauthorised modification.",
                        blocked_ips_file.display(),
                        mode & 0o777,
                    );
                }
            }
        }

        // SEC-05: Enforce a file size cap before reading to prevent memory exhaustion
        // if the blocklist file is unexpectedly large.
        const MAX_BLOCKLIST_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
        match std::fs::metadata(&blocked_ips_file) {
            Ok(meta) if meta.len() > MAX_BLOCKLIST_BYTES => {
                warn!(
                    "SEC-05: Blocklist file {} exceeds {} bytes ({} bytes) — skipping reload \
                     to prevent memory exhaustion. Reduce file size and retry.",
                    blocked_ips_file.display(),
                    MAX_BLOCKLIST_BYTES,
                    meta.len()
                );
                return;
            }
            _ => {}
        }

        match std::fs::read_to_string(&blocked_ips_file) {
            Ok(content) => {
                if let Ok(entries) = serde_json::from_str::<Vec<BlocklistEntry>>(&content) {
                    let mut loaded = 0;
                    // Entries present in this sync. Used below to reconcile: a
                    // DatabaseSync block that has disappeared from the file must be
                    // dropped from memory, or operator unblocks never take effect.
                    let mut present_ips: HashSet<IpAddr> = HashSet::new();
                    let mut present_nets: HashSet<IpNet> = HashSet::new();
                    for entry in entries {
                        // Calculate expiration from the expires_at field (shared logic)
                        let expires_at = entry.expires_at.as_ref().and_then(|exp| {
                            chrono::DateTime::parse_from_rfc3339(exp)
                                .ok()
                                .and_then(|dt| {
                                    let now = chrono::Utc::now();
                                    let exp_utc = dt.with_timezone(&chrono::Utc);
                                    if exp_utc > now {
                                        let duration = (exp_utc - now)
                                            .to_std()
                                            .unwrap_or(Duration::from_hours(1));
                                        Some(Instant::now() + duration)
                                    } else {
                                        None // Already expired
                                    }
                                })
                        });

                        // Skip entries that are already expired
                        if entry.expires_at.is_some() && expires_at.is_none() {
                            continue;
                        }

                        let block_info = BlockedIpInfo {
                            blocked_at: Instant::now(),
                            expires_at,
                            reason: BlockReason::DatabaseSync,
                            block_count: 1,
                        };

                        if entry.ip.contains('/') {
                            // P2-fix: CIDR entry — parse as IpNet and store in blocked_cidrs.
                            // The old code stripped the prefix length and only blocked the
                            // host address, ignoring the subnet entirely.
                            if let Ok(net) = entry.ip.parse::<IpNet>() {
                                present_nets.insert(net);
                                let mut cidrs = self.blocked_cidrs.write();
                                if !cidrs.iter().any(|(n, _)| n == &net) {
                                    cidrs.push((net, block_info));
                                    loaded += 1;
                                }
                            }
                        } else if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                            // Single-IP entry — existing behaviour.
                            // Record it as present BEFORE the contains_key short-circuit,
                            // otherwise the reconcile below would drop the very entries
                            // this sync just reaffirmed.
                            present_ips.insert(ip);
                            if self.blocked_ips.contains_key(&ip) {
                                continue;
                            }
                            self.blocked_ips.insert(ip, block_info);
                            loaded += 1;
                        }
                    }

                    // Reconcile: drop database-sourced blocks that are no longer in the
                    // file. Without this the reload only ever ADDED, so clearing a row in
                    // security_blocklist (or clicking unblock in the threat dashboard)
                    // left the live block in place until it expired or the proxy
                    // restarted. Only DatabaseSync entries are touched — blocks the proxy
                    // raised itself (rate limits, WAF, config `Manual`) are not managed by
                    // the sync file and must survive.
                    let mut dropped = 0;
                    self.blocked_ips.retain(|ip, info| {
                        let stale = matches!(info.reason, BlockReason::DatabaseSync)
                            && !present_ips.contains(ip);
                        if stale {
                            dropped += 1;
                        }
                        !stale
                    });
                    {
                        let mut cidrs = self.blocked_cidrs.write();
                        cidrs.retain(|(net, info)| {
                            let stale = matches!(info.reason, BlockReason::DatabaseSync)
                                && !present_nets.contains(net);
                            if stale {
                                dropped += 1;
                            }
                            !stale
                        });
                    }

                    if loaded > 0 {
                        info!("Loaded {} blocked IPs/CIDRs from database sync", loaded);
                    }
                    if dropped > 0 {
                        info!(
                            "Released {} blocked IPs/CIDRs no longer present in database sync",
                            dropped
                        );
                    }
                }
            }
            Err(e) => {
                debug!("Could not read blocklist file: {}", e);
            }
        }
    }

    /// Increment connection count for IP
    /// The WAF invocation, in one place.
    ///
    /// Called by [`Self::evaluate`] for headers/path/query and by
    /// [`Self::inspect_body`] once a body has been buffered. Keeping it a
    /// single function is the point: the header pass and the body pass used to
    /// build their own `WafRequest`, which is how the two drifted apart on
    /// skip_bot_ua handling.
    fn run_waf(
        &self,
        view: &SecurityRequestView<'_>,
        policy: &RequestPolicy,
        is_pentest: bool,
    ) -> SecurityDecision {
        let ip = view.ip;
        let (auto_block_threshold, auto_block_duration_secs) = {
            let c = self.config.read();
            (c.auto_block_threshold, c.auto_block_duration_secs)
        };
        if let Some(waf) = self
            .waf_engine
            .as_ref()
            .filter(|_| policy.waf_enabled != Some(false))
        {
            let skip_bot_ua = view
                .headers
                .get("x-health-check-bypass")
                .and_then(|v| v.to_str().ok())
                .map(|v| v == "1")
                .unwrap_or(false)
                || view.path.starts_with("/stream/downloads/")
                || is_machine_readable_path(view.path)
                || policy.skip_bot_blocking
                // pentest_bypass_ips covers the authorized red-team host plus this
                // server's own egress and loopback. Those addresses run curl-driven
                // self-checks that carry no browser User-Agent, so without this the
                // bad-bot-UA rules 403'd our own monitoring — the bypass list only
                // suppressed the auto-block counter below, never the Block verdict.
                || is_pentest;

            let waf_req = WafRequest {
                method: view.method,
                path: view.path,
                query: view.query,
                headers: view.headers,
                body: view.body,
                skip_bot_ua_check: skip_bot_ua,
                mode_override: policy.waf_mode.as_deref(),
            };
            match waf.inspect(&waf_req) {
                WafVerdict::Block { ref rule, .. } => {
                    warn!("WAF block: rule={} ip={} path={}", rule, ip, view.path);
                    if !is_pentest {
                        let mut counter = self.request_counts.entry(ip).or_default();
                        counter.suspicious_patterns += 1;
                        if counter.suspicious_patterns >= auto_block_threshold {
                            drop(counter);
                            self.block_ip(
                                ip,
                                BlockReason::TooManyErrors,
                                Some(Duration::from_secs(auto_block_duration_secs)),
                            );
                        }
                    }
                    return SecurityDecision::WafBlock { rule: rule.clone() };
                }
                WafVerdict::Detect { ref rule, .. } => {
                    warn!("WAF detect: rule={} ip={} path={}", rule, ip, view.path);
                }
                WafVerdict::Allow => {}
            }
        }
        SecurityDecision::Allow
    }

    /// WAF inspection for a request whose body has been buffered.
    ///
    /// Only the WAF runs: the rate limiters and blocklist already saw this
    /// request during [`Self::evaluate`], and charging them twice for one
    /// request would halve every configured limit.
    pub fn inspect_body(
        &self,
        view: &SecurityRequestView<'_>,
        policy: &RequestPolicy,
        is_pentest: bool,
    ) -> SecurityDecision {
        self.run_waf(view, policy, is_pentest)
    }

    /// Run every transport-independent security rule against a request.
    ///
    /// This is the single implementation of the proxy's request-security policy.
    /// It exists because there used to be two — the HTTP/3 handler carried its
    /// own copy, which silently omitted the WAF entirely, so every rule could be
    /// bypassed by connecting over QUIC. Two copies of a policy drift; this one
    /// cannot, because both transports call it.
    ///
    /// Returns a verdict rather than a response so each transport can render it
    /// in its own type. Side effects that belong to the rules themselves (adding
    /// an IP to the blocklist, incrementing the suspicious-pattern counter) do
    /// happen here — they are part of the decision, not part of the rendering.
    pub fn evaluate(
        &self,
        view: &SecurityRequestView<'_>,
        policy: &RequestPolicy,
    ) -> SecurityDecision {
        let ip = view.ip;

        // Trusted sources skip everything, as they do on both paths today.
        if self.is_trusted(&ip) {
            return SecurityDecision::Allow;
        }

        let (auto_block_threshold, auto_block_duration_secs, max_header_size, dos_protection) = {
            let c = self.config.read();
            (
                c.auto_block_threshold,
                c.auto_block_duration_secs,
                c.max_header_size,
                c.dos_protection,
            )
        };

        // Pentest sources are inspected but never rate-limited or auto-banned:
        // they send attack payloads by design and must get a 403 without being
        // banned mid-run.
        let is_pentest = {
            let c = self.config.read();
            let ip_str = ip.to_string();
            c.pentest_bypass_ips.iter().any(|p| p == &ip_str)
        };

        // Search-engine crawlers, verified by forward-confirmed reverse DNS.
        //
        // Verified  -> exempt from the rate limiters entirely. A render burst is
        //              normal crawler behaviour, not abuse.
        // Pending   -> the DNS check has not returned yet. Still rate-limited
        //              (a 429 is retryable and crawlers honour it), but never
        //              auto-banned, so an unproven claim cannot cost a genuine
        //              crawler a 300s blackout on a burst it will never repeat.
        // Rejected  -> a spoofed User-Agent. Treated as ordinary traffic.
        //
        // WAF, GeoIP and the blocklist all still apply: this exempts a client
        // from volumetric limits only, never from attack inspection.
        let crawler = self.crawler_verifier.classify(
            ip,
            view.headers
                .get(hyper::header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
        );
        let is_verified_crawler = crawler == CrawlerVerdict::Verified;
        let skip_auto_block = is_verified_crawler || crawler == CrawlerVerdict::Pending;

        // 1. Blocklist
        if let Some(info) = self.is_blocked(&ip) {
            return SecurityDecision::Blocked(info);
        }

        // 2. Per-route JA3 allowlist. A request with no captured fingerprint
        // cannot satisfy the list, so it is refused: an allowlist that fails
        // open is not an allowlist.
        if let Some(ref allowed) = policy.allowed_ja3 {
            let presented = view.headers.get("x-ja3-hash").and_then(|v| v.to_str().ok());
            if !presented.is_some_and(|h| allowed.iter().any(|a| a == h)) {
                warn!(
                    "JA3 allowlist rejected {} on {} (fingerprint: {})",
                    ip,
                    view.path,
                    presented.unwrap_or("none captured")
                );
                return SecurityDecision::Ja3Rejected;
            }
        }

        // 3. GeoIP country blocking
        if self.is_country_blocked(&ip) {
            warn!("GeoIP blocked request from {}", ip);
            let duration = self
                .config
                .read()
                .geoip_block_duration_secs
                .map(Duration::from_secs);
            self.block_ip(ip, BlockReason::GeoBlocked, duration);
            return SecurityDecision::GeoBlocked;
        }

        // 4. Rate limits — per-route override where the route names one.
        // 4. Rate limits — per-route override where the route names one.
        let (rate_enabled, rate_rps, conn_rate_enabled, conn_rate_per_sec) = {
            let rc = self.rate_config.read();
            let over = policy.rate_limit_override.as_ref();
            (
                over.map_or(rc.enabled, |o| o.enabled),
                over.map_or(rc.requests_per_second, |o| o.requests_per_second),
                over.map_or(rc.connection_rate_limit, |o| o.connection_rate_limit),
                over.map_or(rc.connections_per_second, |o| o.connections_per_second),
            )
        };

        if !is_pentest && !is_verified_crawler {
            if conn_rate_enabled && self.connection_rate_exceeded(ip, conn_rate_per_sec) {
                warn!(
                    "Connection rate limit exceeded for {} ({} conn/s)",
                    ip, conn_rate_per_sec
                );
                // This block fires on the first offence, with no counter to
                // cross first — which is exactly how a single Search Console
                // live test used to earn Google a 300s ban.
                if !skip_auto_block {
                    self.block_ip(
                        ip,
                        BlockReason::RateLimitExceeded,
                        Some(Duration::from_secs(auto_block_duration_secs)),
                    );
                }
                return SecurityDecision::RateLimited {
                    limit: conn_rate_per_sec,
                    retry_after_secs: 1,
                    kind: RateLimitKind::Connection,
                };
            }

            if rate_enabled && self.get_ip_rate_limiter(ip).check().is_err() {
                warn!("Rate limit exceeded for {}", ip);
                let mut counter = self.request_counts.entry(ip).or_default();
                counter.suspicious_patterns += 1;
                if counter.suspicious_patterns >= auto_block_threshold && !skip_auto_block {
                    drop(counter);
                    self.block_ip(
                        ip,
                        BlockReason::RateLimitExceeded,
                        Some(Duration::from_secs(auto_block_duration_secs)),
                    );
                }
                return SecurityDecision::RateLimited {
                    limit: rate_rps,
                    retry_after_secs: 1,
                    kind: RateLimitKind::Request,
                };
            }
        }

        let _ = dos_protection; // concurrency counters stay with the transports

        // 5. Header size
        let header_size: usize = view
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        if header_size > max_header_size {
            warn!("Headers too large from {}: {} bytes", ip, header_size);
            return SecurityDecision::HeadersTooLarge {
                max: max_header_size,
            };
        }

        // 6. WAF
        self.run_waf(view, policy, is_pentest)
    }

    /// Record a new connection from `ip` and report whether it exceeds
    /// `connections_per_second`.
    ///
    /// A one-second sliding window per IP. `max_connections_per_ip` already
    /// caps concurrency, but an attacker that opens and closes connections as
    /// fast as it can never trips it, so the accept rate needs its own bound.
    pub fn connection_rate_exceeded(&self, ip: IpAddr, per_second: u32) -> bool {
        if per_second == 0 {
            return false;
        }
        let now = Instant::now();
        let mut window = self
            .connection_rates
            .entry(ip)
            .or_insert_with(|| ConnectionRateWindow {
                window_start: now,
                count: 0,
            });
        if now.duration_since(window.window_start) >= Duration::from_secs(1) {
            window.window_start = now;
            window.count = 0;
        }
        window.count += 1;
        window.count > per_second
    }

    pub fn increment_connections(&self, ip: IpAddr) -> u32 {
        let mut count = self.ip_connections.entry(ip).or_insert(0);
        *count += 1;
        *count
    }

    /// Decrement connection count for IP
    pub fn decrement_connections(&self, ip: IpAddr) {
        if let Some(mut count) = self.ip_connections.get_mut(&ip) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    /// Record a request for adaptive rate limiting
    // Prometheus gauge values are f64; precision loss on large counter values is acceptable.
    #[allow(clippy::cast_precision_loss)]
    pub fn record_request(&self, ip: IpAddr, status: StatusCode) {
        // Skip tracking for trusted IPs (loopback, or operator-configured trusted_internal_cidrs)
        if self.is_trusted(&ip) {
            return;
        }

        // A crawler walking stale links legitimately accumulates 404s, which is
        // precisely the shape this error-rate heuristic bans for. Verified
        // crawlers are therefore not tracked here. The UA is not available at
        // this call site, so this reads the verdict established earlier in the
        // request by evaluate(); an unverified address is tracked as normal.
        if self.crawler_verifier.cached_verdict(ip) == Some(CrawlerVerdict::Verified) {
            return;
        }

        // Read config values
        let config = self.config.read();
        let window_duration = Duration::from_secs(config.error_window_secs);
        let error_4xx_threshold = config.error_4xx_threshold;
        let min_requests = config.min_requests_for_error_check;
        let error_rate_threshold = config.error_rate_threshold;
        let auto_block_threshold = config.auto_block_threshold;
        let auto_block_duration = Duration::from_secs(config.auto_block_duration_secs);
        drop(config);

        let mut counter = self.request_counts.entry(ip).or_default();

        // Reset window if needed (configurable window duration)
        if counter
            .window_start
            .map(|s| s.elapsed() > window_duration)
            .unwrap_or(true)
        {
            counter.total_requests = 0;
            counter.error_4xx = 0;
            counter.error_5xx = 0;
            counter.suspicious_patterns = 0;
            counter.window_start = Some(Instant::now());
        }

        counter.total_requests += 1;

        if status.is_client_error() {
            counter.error_4xx += 1;
        } else if status.is_server_error() {
            counter.error_5xx += 1;
        }

        // Check for suspicious patterns (configurable thresholds)
        if counter.error_4xx > error_4xx_threshold && counter.total_requests > min_requests {
            let error_rate = counter.error_4xx as f64 / counter.total_requests as f64;
            if error_rate > error_rate_threshold {
                counter.suspicious_patterns += 1;

                // Auto-block if too suspicious (configurable threshold)
                if counter.suspicious_patterns >= auto_block_threshold {
                    drop(counter);
                    self.block_ip(ip, BlockReason::TooManyErrors, Some(auto_block_duration));
                }
            }
        }
    }

    /// Record circuit breaker result
    pub fn record_backend_result(&self, backend: &str, success: bool) {
        let cb_config = self.circuit_breaker_config.read();
        let failure_threshold = cb_config.failure_threshold;
        let success_threshold = cb_config.success_threshold;
        drop(cb_config);

        let mut state = self
            .circuit_breakers
            .entry(backend.to_string())
            .or_default();

        if success {
            state.success_count += 1;
            state.failure_count = 0;

            // If half-open and enough successes, close the circuit
            if state.state == CircuitState::HalfOpen && state.success_count >= success_threshold {
                state.state = CircuitState::Closed;
                state.last_state_change = Instant::now();
                info!("Circuit breaker for {} closed (recovered)", backend);
            }
        } else {
            state.failure_count += 1;
            state.success_count = 0;

            match state.state {
                CircuitState::Closed => {
                    // Open circuit after configured consecutive failures
                    if state.failure_count >= failure_threshold {
                        state.state = CircuitState::Open;
                        state.last_state_change = Instant::now();
                        warn!(
                            "Circuit breaker for {} opened (failures: {})",
                            backend, state.failure_count
                        );
                    }
                }
                CircuitState::HalfOpen => {
                    // Back to open on any failure in half-open state
                    state.state = CircuitState::Open;
                    state.last_state_change = Instant::now();
                    warn!("Circuit breaker for {} re-opened from half-open", backend);
                }
                CircuitState::Open => {
                    // Already open, nothing to do
                }
            }
        }
    }

    /// Check if circuit breaker allows request to backend (using configurable settings)
    pub fn circuit_allows(&self, backend: &str) -> bool {
        let cb_config = self.circuit_breaker_config.read();
        let half_open_delay = Duration::from_secs(cb_config.half_open_delay_secs);
        let half_open_max = cb_config.half_open_max_requests;
        drop(cb_config);

        let mut state = self
            .circuit_breakers
            .entry(backend.to_string())
            .or_default();

        match state.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should try half-open (configurable delay)
                if state.last_state_change.elapsed() > half_open_delay {
                    state.state = CircuitState::HalfOpen;
                    state.half_open_requests = 0;
                    state.last_state_change = Instant::now();
                    info!("Circuit breaker for {} entering half-open state", backend);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state (configurable max)
                if state.half_open_requests < half_open_max {
                    state.half_open_requests += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Cleanup expired entries (call periodically, using configurable intervals)
    pub fn cleanup(&self) {
        let cb_config = self.circuit_breaker_config.read();
        let stale_cleanup_secs = cb_config.stale_counter_cleanup_secs;
        drop(cb_config);

        // Remove expired blocks (single-IP)
        self.blocked_ips
            .retain(|_, info| info.expires_at.map(|e| Instant::now() < e).unwrap_or(true));

        // Remove expired CIDR blocks
        {
            let mut cidrs = self.blocked_cidrs.write();
            cidrs.retain(|(_, info)| info.expires_at.map(|e| Instant::now() < e).unwrap_or(true));
        }

        // Remove old request counters (configurable age)
        self.request_counts.retain(|_, counter| {
            counter
                .window_start
                .map(|s| s.elapsed() < Duration::from_secs(stale_cleanup_secs))
                .unwrap_or(false)
        });

        // Evict oldest entries from blocked_ips if over limit (DoS prevention)
        let blocked_count = self.blocked_ips.len();
        if blocked_count > MAX_TRACKED_IPS {
            // Collect and sort by blocked_at time, evict oldest temporary blocks first
            let mut entries: Vec<_> = self
                .blocked_ips
                .iter()
                .filter(|e| e.value().expires_at.is_some()) // Only evict temporary blocks
                .map(|e| (*e.key(), e.value().blocked_at))
                .collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = blocked_count.saturating_sub(MAX_TRACKED_IPS);
            for (ip, _) in entries.into_iter().take(to_remove) {
                self.blocked_ips.remove(&ip);
            }
        }

        // AUD-07: Evict least-recently-used entries from ip_rate_limiters if over limit.
        // Sort by last-access timestamp (oldest first) and remove the least-recently-used
        // entries so that active legitimate clients are never evicted ahead of dormant ones.
        let rate_limiter_count = self.ip_rate_limiters.len();
        if rate_limiter_count > MAX_TRACKED_IPS {
            let mut entries: Vec<_> = self
                .ip_rate_limiters
                .iter()
                .map(|e| (*e.key(), e.value().1))
                .collect();
            // Sort oldest last-access time first (least-recently-used first)
            entries.sort_by_key(|(_, last_access)| *last_access);
            let to_remove = rate_limiter_count.saturating_sub(MAX_TRACKED_IPS);
            for (ip, _) in entries.into_iter().take(to_remove) {
                self.ip_rate_limiters.remove(&ip);
            }
        }

        // Evict least-recently-seen JA3 fingerprints if over limit.
        //
        // Was oldest-first-seen, which threw out long-lived regulars in favour
        // of whatever had sprayed the box most recently — backwards for a corpus
        // meant to describe normal traffic, and it meant a burst of one-shot
        // scanner fingerprints could evict every browser we knew about.
        let ja3_count = self.ja3_cache.len();
        if ja3_count > MAX_JA3_FINGERPRINTS {
            let mut entries: Vec<_> = self
                .ja3_cache
                .iter()
                .map(|e| (e.key().clone(), e.value().last_seen))
                .collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = ja3_count.saturating_sub(MAX_JA3_FINGERPRINTS);
            for (hash, _) in entries.into_iter().take(to_remove) {
                self.ja3_cache.remove(&hash);
            }
        }

        // Evict oldest request counters if over limit
        let request_count = self.request_counts.len();
        if request_count > MAX_TRACKED_IPS {
            let mut entries: Vec<_> = self
                .request_counts
                .iter()
                .filter_map(|e| e.value().window_start.map(|ws| (*e.key(), ws)))
                .collect();
            entries.sort_by_key(|(_, time)| *time);
            let to_remove = request_count.saturating_sub(MAX_TRACKED_IPS);
            for (ip, _) in entries.into_iter().take(to_remove) {
                self.request_counts.remove(&ip);
            }
        }
    }
}

/// Security middleware for rate limiting, IP blocking, and request validation
pub async fn security_middleware(
    State(security): State<SecurityState>,
    ConnectInfo(client_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_addr.ip();

    // Resolve the route before any check runs, so per-route policy can shape
    // what follows. None means no route matched, in which case the global
    // settings apply unchanged.
    let route_policy = {
        // Header first, URI authority second: HTTP/2 sends no `Host` header, so
        // reading only the header left every h2 request looking hostless here.
        let host = headers
            .get(hyper::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .or_else(|| request.uri().host().map(str::to_owned))
            .map(|h| h.split(':').next().unwrap_or(&h).to_ascii_lowercase());
        let req_path = request.uri().path().to_string();
        let on_conformance_host = is_conformance_host(&security.route_index, host.as_deref());
        security
            .route_index
            .find_route(host.as_deref(), &req_path, false)
            .map(|r| RequestPolicy {
                skip_bot_blocking: r.skip_bot_blocking,
                allowed_ja3: r.security.as_ref().and_then(|s| s.allowed_ja3.clone()),
                waf_enabled: r.security.as_ref().and_then(|s| s.waf_enabled),
                waf_mode: r.security.as_ref().and_then(|s| s.waf_mode.clone()),
                rate_limit_override: r
                    .security
                    .as_ref()
                    .and_then(|s| s.rate_limit_override.clone()),
            })
            .map(|mut p| {
                p.skip_bot_blocking |= on_conformance_host;
                p
            })
            .unwrap_or_else(|| RequestPolicy {
                skip_bot_blocking: on_conformance_host,
                ..RequestPolicy::default()
            })
    };

    // The body-scan paths below run after `request` is consumed, so take the
    // pieces they need while the policy is still in scope.
    let waf_mode_cl = route_policy.waf_mode.clone();
    let waf_enabled_cl = route_policy.waf_enabled;
    let waf_mode_body = route_policy.waf_mode.clone();
    let route_skip_bot = route_policy.skip_bot_blocking;

    // Fast path: skip all security checks for trusted IPs (loopback, or CIDRs listed in
    // security.trusted_internal_cidrs). RFC1918 ranges are no longer implicitly trusted
    // (SEC-A05) — this prevents an attacker with LAN access from bypassing rate limiting.
    if security.is_trusted(&ip) {
        debug!("Trusted IP {} - bypassing security checks", ip);
        return next.run(request).await;
    }

    // Error pages are public content — exempt from all blocks so geo-redirected users can
    // reach /error_pages/ even after their IP has been added to the temporary blocklist.
    {
        let path = request.uri().path();
        if path.starts_with("/error_pages/") {
            return next.run(request).await;
        }
    }

    // Authorized pentest bypass: skip rate-limiting and auto-block but still run WAF.
    // Pentest IPs get proper 403 for blocked attacks without being banned mid-run.
    let is_pentest_bypass = {
        let config = security.config.read();
        let ip_str = ip.to_string();
        config.pentest_bypass_ips.iter().any(|p| p == &ip_str)
    };

    // Read config values without cloning the entire struct - just read what we need
    let (
        dos_protection,
        max_connections_per_ip,
        max_request_size,
        max_header_size,
        auto_block_threshold,
        auto_block_duration_secs,
    ) = {
        let config = security.config.read();
        (
            config.dos_protection,
            config.max_connections_per_ip,
            config.max_request_size,
            config.max_header_size,
            config.auto_block_threshold,
            config.auto_block_duration_secs,
        )
    };
    // Rate-limit figures are read inside SecurityState::evaluate, which owns
    // the per-route override logic; the middleware keeps no second copy.

    // Pre-borrow alt_svc_header for use in all early-return helpers below.
    let alt_svc = security.alt_svc_header.as_ref();
    // Extract path once here so it's available to both WAF and size checks.
    let request_path = request.uri().path().to_ascii_lowercase();

    // Checks 1-5 (blocklist, JA3 allowlist, GeoIP, rate limits, header size,
    // WAF) live in SecurityState::evaluate, which the HTTP/3 handler calls too.
    //
    // This runs for EVERY source including pentest IPs: evaluate() exempts them
    // from the rate limiters and auto-block internally, but they are still WAF
    // inspected and still get a 403 for a blocked attack — which is the whole
    // contract of pentest_bypass_ips. Putting this call inside the non-pentest
    // branch silently disabled the WAF for those addresses.
    {
        let view = SecurityRequestView {
            ip,
            method: request.method().as_str(),
            path: &request_path,
            query: request.uri().query().unwrap_or(""),
            headers: request.headers(),
            body: None,
        };
        let decision = security.evaluate(&view, &route_policy);

        if !matches!(decision, SecurityDecision::Allow) {
            let request_origin = headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let response = render_decision(&decision, alt_svc, request_origin.as_deref());

            // Security refusals used to return without ever reaching the access
            // logger, so a blocked client saw a 403 while access.log stayed
            // silent and only the journal recorded it. That made a Search
            // Console "Blocked due to access forbidden (403)" impossible to
            // reconcile against the logs. Record them like any other response.
            let header_str = |name: hyper::header::HeaderName| {
                headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            log_access(&AccessLogEntry {
                remote_addr: client_addr,
                method: request.method().as_str().to_string(),
                path: request.uri().path().to_string(),
                protocol: format!("{:?}", request.version()),
                status: response.status().as_u16(),
                body_size: 0,
                referer: header_str(hyper::header::REFERER),
                user_agent: header_str(hyper::header::USER_AGENT),
                host: header_str(hyper::header::HOST),
                response_time_ms: 0,
            });

            return response;
        }

        // DoS concurrency limit — counted here because the matching decrement
        // happens once this middleware's response is built.
        //
        // A verified crawler is exempt from the *ban*, not from the limit: it
        // still gets 503'd when it exceeds the concurrency cap, but a rendering
        // burst must not cost it a multi-minute blackout.
        let crawler_exempt = security.crawler_verifier.classify(
            ip,
            headers
                .get(hyper::header::USER_AGENT)
                .and_then(|v| v.to_str().ok()),
        ) == CrawlerVerdict::Verified;

        if dos_protection && !is_pentest_bypass {
            let connections = security.increment_connections(ip);
            if connections > max_connections_per_ip {
                security.decrement_connections(ip);
                if !crawler_exempt {
                    security.block_ip(
                        ip,
                        BlockReason::ConnectionLimitExceeded,
                        Some(Duration::from_secs(auto_block_duration_secs)),
                    );
                }
                warn!(
                    "Too many connections from {}: {} (limit {})",
                    ip, connections, max_connections_per_ip
                );
                return too_many_connections_response(alt_svc);
            }
        }
        // Pentest IP: still track the DoS connection counter so cleanup runs
        // correctly, but never block on it.
        if dos_protection && is_pentest_bypass {
            security.increment_connections(ip);
            debug!("Pentest bypass IP {} — skipping rate-limit/auto-block", ip);
        }
    }

    // 6. Request size validation — covers both Content-Length and chunked bodies.
    //
    // Streaming speedtest upload endpoints are exempt: the proxy handler reads
    // and discards the body incrementally without buffering, so applying a size
    // limit here would reject legitimate high-throughput upload measurements.
    if request_path == "/speedtest/tcp-upload-stream" {
        return next.run(request).await;
    }
    //
    // F-02: The previous implementation checked only the Content-Length header, which
    // is absent for Transfer-Encoding: chunked requests.  Attackers could bypass the
    // 10 MB body limit by sending an arbitrarily large chunked body.
    //
    // Fix: if a Content-Length is present, use it for a fast pre-flight rejection.
    // If the request uses chunked encoding (or has no Content-Length at all), buffer
    // the actual body bytes up to max_request_size and reconstruct the request.
    // This enforces the limit on streamed bytes regardless of declared size.
    let is_chunked = headers
        .get("transfer-encoding")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let has_content_length = headers.get("content-length").is_some();

    if has_content_length && !is_chunked {
        // Fast path: validate declared size, then buffer up to scan limit for WAF.
        if let Some(content_length) = headers.get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<usize>() {
                    if length > max_request_size {
                        warn!("Request too large from {}: {} bytes", ip, length);
                        return payload_too_large_response(max_request_size, alt_svc);
                    }
                }
            }
        }
        // WAF body scan for Content-Length requests — previously skipped.
        // Buffer up to max_body_scan_bytes (65 KB) and inspect with WAF.
        if security.waf_engine.is_some() && route_policy.waf_enabled != Some(false) {
            let scan_limit = 65_536usize;
            let (parts, body) = request.into_parts();
            // Collect the ENTIRE body (matching the declared Content-Length) —
            // only the first `scan_limit` bytes are actually inspected by the WAF
            // below. Previously this loop broke out (and the request was
            // reconstructed) as soon as scan_limit was reached, silently
            // truncating any body over 64 KB while forwarding the original,
            // now-too-large Content-Length header. The backend would then wait
            // forever for the remaining bytes the proxy had already discarded,
            // hanging every request whose body crossed the 64 KB mark.
            let mut collected_bytes: Vec<u8> = Vec::new();
            let mut frame_stream = body.into_data_stream();
            while let Some(chunk_result) = {
                use futures_util::StreamExt;
                frame_stream.next().await
            } {
                match chunk_result {
                    Ok(chunk) => {
                        collected_bytes.extend_from_slice(&chunk);
                    }
                    Err(_) => break,
                }
            }
            if !collected_bytes.is_empty() {
                if security.waf_engine.is_some() && waf_enabled_cl != Some(false) {
                    let waf_path = parts.uri.path().to_string();
                    let waf_query = parts.uri.query().unwrap_or("").to_string();
                    let skip_bot_ua_cl = parts
                        .headers
                        .get("x-health-check-bypass")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v == "1")
                        .unwrap_or(false)
                        || route_skip_bot;
                    let scan_slice_end = collected_bytes.len().min(scan_limit);
                    let body_view = SecurityRequestView {
                        ip,
                        method: parts.method.as_str(),
                        path: &waf_path,
                        query: &waf_query,
                        headers: &parts.headers,
                        body: Some(&collected_bytes[..scan_slice_end]),
                    };
                    let body_policy = RequestPolicy {
                        skip_bot_blocking: skip_bot_ua_cl,
                        waf_mode: waf_mode_cl.clone(),
                        waf_enabled: waf_enabled_cl,
                        ..Default::default()
                    };
                    match security.inspect_body(&body_view, &body_policy, is_pentest_bypass) {
                        SecurityDecision::WafBlock { ref rule } => {
                            warn!(
                                "WAF body block (CL): rule={} ip={} path={}",
                                rule, ip, waf_path
                            );
                            if dos_protection {
                                security.decrement_connections(ip);
                            }
                            if !is_pentest_bypass {
                                let mut counter = security.request_counts.entry(ip).or_default();
                                counter.suspicious_patterns += 1;
                                if counter.suspicious_patterns >= auto_block_threshold {
                                    drop(counter);
                                    let block_duration =
                                        Duration::from_secs(auto_block_duration_secs);
                                    security.block_ip(
                                        ip,
                                        BlockReason::TooManyErrors,
                                        Some(block_duration),
                                    );
                                }
                            }
                            let mut resp =
                                (StatusCode::FORBIDDEN, "Request blocked by security policy")
                                    .into_response();
                            resp.headers_mut()
                                .insert("x-waf-block", HeaderValue::from_static("1"));
                            return resp;
                        }
                        #[allow(unreachable_patterns)]
                        #[allow(unreachable_patterns)]
                        SecurityDecision::WafBlock { ref rule } if false => {
                            warn!(
                                "WAF body detect (CL): rule={} ip={} path={}",
                                rule, ip, waf_path
                            );
                        }
                        _ => {}
                    }
                }
            }
            // Reconstruct request with buffered body for the backend.
            request = Request::from_parts(parts, Body::from(collected_bytes));
        }
    } else if is_chunked || !has_content_length {
        // Slow path: buffer the body and enforce the limit on actual bytes.
        let (parts, body) = request.into_parts();
        // Collect up to max_request_size + 1 bytes; excess triggers the error branch.
        let mut collected_bytes: Vec<u8> = Vec::new();
        let mut frame_stream = body.into_data_stream();
        let mut oversized = false;

        while let Some(chunk_result) = {
            use futures_util::StreamExt;
            frame_stream.next().await
        } {
            match chunk_result {
                Ok(chunk) => {
                    collected_bytes.extend_from_slice(&chunk);
                    if collected_bytes.len() > max_request_size {
                        oversized = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        if oversized {
            warn!(
                "Chunked request body exceeded limit from {}: >{} bytes",
                ip, max_request_size
            );
            if dos_protection {
                security.decrement_connections(ip);
            }
            return payload_too_large_response(max_request_size, alt_svc);
        }

        // P1-fix: WAF body inspection on the now-buffered bytes.
        // Step 5 above inspected path/query/headers without a body; this second
        // pass supplies the buffered bytes so that body-embedded payloads
        // (SQLi, XSS, command injection, etc.) are detected.
        if !collected_bytes.is_empty() {
            if security.waf_engine.is_some() && waf_enabled_cl != Some(false) {
                let waf_path = parts.uri.path().to_string();
                let waf_query = parts.uri.query().unwrap_or("").to_string();
                let skip_bot_ua_body = parts
                    .headers
                    .get("x-health-check-bypass")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v == "1")
                    .unwrap_or(false)
                    || route_skip_bot;
                let body_view_chunked = SecurityRequestView {
                    ip,
                    method: parts.method.as_str(),
                    path: &waf_path,
                    query: &waf_query,
                    headers: &parts.headers,
                    body: Some(collected_bytes.as_slice()),
                };
                let body_policy_chunked = RequestPolicy {
                    skip_bot_blocking: skip_bot_ua_body,
                    waf_mode: waf_mode_body.clone(),
                    waf_enabled: waf_enabled_cl,
                    ..Default::default()
                };
                match security.inspect_body(
                    &body_view_chunked,
                    &body_policy_chunked,
                    is_pentest_bypass,
                ) {
                    SecurityDecision::WafBlock { ref rule } => {
                        warn!("WAF body block: rule={} ip={} path={}", rule, ip, waf_path);
                        if dos_protection {
                            security.decrement_connections(ip);
                        }
                        // Same escalation as the header/path WAF block path above.
                        {
                            let mut counter = security.request_counts.entry(ip).or_default();
                            counter.suspicious_patterns += 1;
                            if counter.suspicious_patterns >= auto_block_threshold {
                                drop(counter);
                                let block_duration = Duration::from_secs(auto_block_duration_secs);
                                security.block_ip(
                                    ip,
                                    BlockReason::TooManyErrors,
                                    Some(block_duration),
                                );
                            }
                        }
                        let mut resp =
                            (StatusCode::FORBIDDEN, "Request blocked by security policy")
                                .into_response();
                        resp.headers_mut()
                            .insert("x-waf-block", HeaderValue::from_static("1"));
                        return resp;
                    }
                    #[allow(unreachable_patterns)]
                    SecurityDecision::WafBlock { ref rule } if false => {
                        warn!(
                            "WAF body detect (non-blocking): rule={} ip={} path={}",
                            rule, ip, waf_path
                        );
                    }
                    _ => {}
                }
            }
        }

        // Reconstruct the request with the buffered body and continue.
        let request = Request::from_parts(parts, Body::from(collected_bytes));

        // 6. Header size validation
        let header_size: usize = headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        if header_size > max_header_size {
            warn!("Headers too large from {}: {} bytes", ip, header_size);
            if dos_protection {
                security.decrement_connections(ip);
            }
            return headers_too_large_response(max_header_size, alt_svc);
        }

        // 7. Process request
        let response = next.run(request).await;
        let status = response.status();
        security.record_request(ip, status);
        if dos_protection {
            security.decrement_connections(ip);
        }
        return response;
    }

    // 6. Header size validation
    let header_size: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum();

    if header_size > max_header_size {
        warn!("Headers too large from {}: {} bytes", ip, header_size);
        // P1-fix: decrement the DoS counter that was incremented in step 3.
        if dos_protection {
            security.decrement_connections(ip);
        }
        return headers_too_large_response(max_header_size, alt_svc);
    }

    // 7. Process request
    let response = next.run(request).await;
    let status = response.status();

    // 8. Record request for adaptive rate limiting
    security.record_request(ip, status);

    // 9. Decrement connection count
    if dos_protection {
        security.decrement_connections(ip);
    }

    response
}

/// Generate blocked IP response
fn blocked_response(info: &BlockedIpInfo, alt_svc: &str) -> Response {
    // P1-fix: `duration_since` panics (in debug) / saturates (in release) when the
    // reference instant is in the past — a TOCTOU race between is_blocked() and here.
    // `saturating_duration_since` returns zero for expired blocks without panicking.
    let retry_after = info
        .expires_at
        .map(|e| e.saturating_duration_since(Instant::now()).as_secs())
        .unwrap_or(3600);

    let mut response = (StatusCode::FORBIDDEN, "Access denied - IP blocked").into_response();

    response.headers_mut().insert(
        "Retry-After",
        HeaderValue::from_str(&retry_after.to_string()).unwrap_or(HeaderValue::from_static("3600")),
    );
    add_alt_svc(&mut response, alt_svc);

    response
}

/// Generate GeoIP blocked response — redirects to the styled 403 error page.
/// The error page path is exempt from security checks so the redirect always resolves.
fn geo_blocked_response(alt_svc: &str) -> Response {
    let mut response = (
        StatusCode::FOUND,
        [(
            "Location",
            "https://pqcrypta.com/error_pages/pqcrypt_403.html",
        )],
        "",
    )
        .into_response();
    add_alt_svc(&mut response, alt_svc);
    response
}

/// Render a [`SecurityDecision`] as an axum response for the TCP path.
///
/// Companion to [`decision_to_h3_parts`]; the two exist because the transports
/// build different response types, not because they apply different rules.
fn render_decision(
    decision: &SecurityDecision,
    alt_svc: &str,
    request_origin: Option<&str>,
) -> Response {
    match decision {
        SecurityDecision::Allow => {
            // Callers check for Allow before calling; treat it as a no-op 200.
            let mut r = StatusCode::OK.into_response();
            add_alt_svc(&mut r, alt_svc);
            r
        }
        SecurityDecision::Blocked(info) => blocked_response(info, alt_svc),
        SecurityDecision::GeoBlocked => geo_blocked_response(alt_svc),
        SecurityDecision::RateLimited { limit, .. } => {
            rate_limit_response_simple(*limit, alt_svc, request_origin)
        }
        SecurityDecision::Ja3Rejected => ja3_forbidden_response(alt_svc),
        SecurityDecision::HeadersTooLarge { max } => headers_too_large_response(*max, alt_svc),
        SecurityDecision::WafBlock { .. } => {
            let mut r = (StatusCode::FORBIDDEN, "Forbidden").into_response();
            r.headers_mut()
                .insert("x-waf-block", HeaderValue::from_static("1"));
            add_alt_svc(&mut r, alt_svc);
            r
        }
    }
}

/// Render a [`SecurityDecision`] as an HTTP/3 status plus extra headers.
///
/// `None` means the request is allowed. Kept beside the decision type so a new
/// variant cannot be added without the HTTP/3 path being updated to render it —
/// the compiler will flag the missing arm.
pub fn decision_to_h3_parts(
    decision: &SecurityDecision,
) -> Option<(StatusCode, Vec<(&'static str, String)>)> {
    match decision {
        SecurityDecision::Allow => None,
        SecurityDecision::Blocked(_) | SecurityDecision::GeoBlocked => Some((
            StatusCode::FOUND,
            vec![(
                "location",
                "https://pqcrypta.com/error_pages/pqcrypt_403.html".to_string(),
            )],
        )),
        SecurityDecision::RateLimited {
            limit,
            retry_after_secs,
            kind: _,
        } => Some((
            StatusCode::TOO_MANY_REQUESTS,
            vec![
                ("retry-after", retry_after_secs.to_string()),
                ("x-ratelimit-limit", limit.to_string()),
                ("x-ratelimit-remaining", "0".to_string()),
            ],
        )),
        SecurityDecision::Ja3Rejected => Some((StatusCode::FORBIDDEN, Vec::new())),
        SecurityDecision::HeadersTooLarge { .. } => {
            Some((StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, Vec::new()))
        }
        SecurityDecision::WafBlock { .. } => Some((
            StatusCode::FORBIDDEN,
            vec![("x-waf-block", "1".to_string())],
        )),
    }
}

/// Refusal for a request that failed a route's JA3 allowlist.
///
/// Plain 403 rather than the redirect used for GeoIP blocks: the caller here
/// is an automated client that named itself by TLS fingerprint, so a
/// human-readable error page serves no one.
fn ja3_forbidden_response(alt_svc: &str) -> Response {
    let mut response = (StatusCode::FORBIDDEN, "Forbidden").into_response();
    add_alt_svc(&mut response, alt_svc);
    response
}

/// Generate rate limit exceeded response with just the RPS value
fn rate_limit_response_simple(
    requests_per_second: u32,
    alt_svc: &str,
    request_origin: Option<&str>,
) -> Response {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();

    // Add standard rate limit headers
    response
        .headers_mut()
        .insert("Retry-After", HeaderValue::from_static("1"));
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&requests_per_second.to_string())
            .unwrap_or(HeaderValue::from_static("100")),
    );
    response
        .headers_mut()
        .insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));

    // CORS headers on 429 so browsers see the status code instead of a CORS error
    const ALLOWED_ORIGINS: &[&str] = &["https://pqcrypta.com", "https://www.pqcrypta.com"];
    let origin = request_origin.unwrap_or("");
    if ALLOWED_ORIGINS.contains(&origin) {
        if let Ok(v) = HeaderValue::from_str(origin) {
            response
                .headers_mut()
                .insert("access-control-allow-origin", v);
        }
        response.headers_mut().insert(
            "access-control-allow-credentials",
            HeaderValue::from_static("true"),
        );
        response
            .headers_mut()
            .insert("vary", HeaderValue::from_static("Origin"));
    }

    add_alt_svc(&mut response, alt_svc);

    response
}

/// Generate too many connections response
fn too_many_connections_response(alt_svc: &str) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many connections from your IP",
    )
        .into_response();
    add_alt_svc(&mut response, alt_svc);
    response
}

/// Generate payload too large response
fn payload_too_large_response(max_size: usize, alt_svc: &str) -> Response {
    let mut response = (
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("Request body exceeds maximum size of {} bytes", max_size),
    )
        .into_response();

    response.headers_mut().insert(
        "X-Max-Request-Size",
        HeaderValue::from_str(&max_size.to_string())
            .unwrap_or(HeaderValue::from_static("10485760")),
    );
    add_alt_svc(&mut response, alt_svc);

    response
}

/// Generate headers too large response
fn headers_too_large_response(max_size: usize, alt_svc: &str) -> Response {
    let mut response = (
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        format!("Headers exceed maximum size of {} bytes", max_size),
    )
        .into_response();
    add_alt_svc(&mut response, alt_svc);
    response
}

/// Classify a JA3 fingerprint hash using the provided database.
///
/// Classification is **advisory-only** and MUST NOT cause automatic blocking.
/// Returns `Suspicious` for any hash not found in the database.
pub fn classify_ja3(ja3_hash: &str, db: &Ja3Database) -> FingerprintClass {
    db.classify(ja3_hash)
}

#[cfg(feature = "geoip")]
mod geoip {
    use maxminddb::Reader;
    use std::net::IpAddr;
    use std::path::Path;

    /// GeoIP lookup result
    #[derive(Debug, Clone)]
    pub struct GeoLocation {
        pub country_code: Option<String>,
        pub country_name: Option<String>,
        pub city: Option<String>,
        pub continent: Option<String>,
    }

    /// GeoIP database wrapper
    pub struct GeoIpDb {
        reader: Reader<Vec<u8>>,
    }

    impl GeoIpDb {
        /// Load GeoIP database from file
        pub fn new(path: impl AsRef<Path>) -> Result<Self, maxminddb::MaxMindDbError> {
            let reader = Reader::open_readfile(path)?;
            Ok(Self { reader })
        }

        /// Look up IP address
        pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
            #[derive(serde::Deserialize)]
            struct City {
                country: Option<Country>,
                city: Option<CityName>,
                continent: Option<Continent>,
            }

            #[derive(serde::Deserialize)]
            struct Country {
                iso_code: Option<String>,
                names: Option<std::collections::HashMap<String, String>>,
            }

            #[derive(serde::Deserialize)]
            struct CityName {
                names: Option<std::collections::HashMap<String, String>>,
            }

            #[derive(serde::Deserialize)]
            struct Continent {
                code: Option<String>,
            }

            let city: City = self.reader.lookup(ip).ok()?.decode().ok().flatten()?;

            Some(GeoLocation {
                country_code: city.country.as_ref().and_then(|c| c.iso_code.clone()),
                country_name: city
                    .country
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en").cloned()),
                city: city
                    .city
                    .and_then(|c| c.names)
                    .and_then(|n| n.get("en").cloned()),
                continent: city.continent.and_then(|c| c.code),
            })
        }

        /// Check if country is blocked
        pub fn is_country_blocked(&self, ip: IpAddr, blocked_countries: &[String]) -> bool {
            if let Some(location) = self.lookup(ip) {
                if let Some(country_code) = location.country_code {
                    return blocked_countries
                        .iter()
                        .any(|c| c.eq_ignore_ascii_case(&country_code));
                }
            }
            false
        }
    }
}

#[cfg(feature = "geoip")]
pub use geoip::*;

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: an operator unblock must take effect on the running proxy.
    ///
    /// `reload_blocklist_from_files` used to only ever INSERT, so once an IP was
    /// in the in-memory map, clearing its `security_blocklist` row (or clicking
    /// unblock in the threat dashboard) did nothing until the entry expired or
    /// the process restarted. On 2026-08-18 that left this platform's own web
    /// server locked out of api.pqcrypta.com for the full 72-hour block window.
    #[tokio::test]
    async fn test_reload_releases_ips_removed_from_sync_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocked_ips.json");

        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);
        security.config.write().blocklist_dir = dir.path().to_path_buf();

        let synced: IpAddr = "203.0.113.10".parse().unwrap();
        let self_raised: IpAddr = "203.0.113.20".parse().unwrap();

        // Sync file contains one IP; the proxy independently blocks another.
        std::fs::write(&file, r#"[{"ip":"203.0.113.10","expires_at":null}]"#).unwrap();
        security.reload_blocklist_from_files();
        security.block_ip(self_raised, BlockReason::TooManyErrors, None);

        assert!(security.is_blocked(&synced).is_some());
        assert!(security.is_blocked(&self_raised).is_some());

        // Operator clears the row → it disappears from the synced file.
        std::fs::write(&file, "[]").unwrap();
        security.reload_blocklist_from_files();

        assert!(
            security.is_blocked(&synced).is_none(),
            "IP removed from the sync file must be released from memory"
        );
        assert!(
            security.is_blocked(&self_raised).is_some(),
            "a block the proxy raised itself is not managed by the sync file \
             and must survive the reconcile"
        );
    }

    /// A CIDR entry that leaves the sync file must be released too.
    #[tokio::test]
    async fn test_reload_releases_cidrs_removed_from_sync_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocked_ips.json");

        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);
        security.config.write().blocklist_dir = dir.path().to_path_buf();

        let inside: IpAddr = "198.51.100.7".parse().unwrap();

        std::fs::write(&file, r#"[{"ip":"198.51.100.0/24","expires_at":null}]"#).unwrap();
        security.reload_blocklist_from_files();
        assert!(security.is_blocked(&inside).is_some());

        std::fs::write(&file, "[]").unwrap();
        security.reload_blocklist_from_files();
        assert!(
            security.is_blocked(&inside).is_none(),
            "CIDR removed from the sync file must be released from memory"
        );
    }

    /// `unblock_ip` is the immediate escape hatch behind the admin route: it must
    /// drop both a direct entry and any CIDR entry covering the address.
    #[tokio::test]
    async fn test_unblock_ip_removes_direct_and_cidr_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocked_ips.json");

        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);
        security.config.write().blocklist_dir = dir.path().to_path_buf();

        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        std::fs::write(
            &file,
            r#"[{"ip":"198.51.100.7","expires_at":null},{"ip":"198.51.100.0/24","expires_at":null}]"#,
        )
        .unwrap();
        security.reload_blocklist_from_files();
        assert!(security.is_blocked(&ip).is_some());

        assert_eq!(security.unblock_ip(ip), 2);
        assert!(
            security.is_blocked(&ip).is_none(),
            "unblock must clear the covering CIDR as well as the direct entry"
        );
    }

    #[tokio::test]
    async fn test_blocked_ip_expiration() {
        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);

        // Use a public IP (not private/trusted) so it can actually be blocked
        let ip: IpAddr = "8.8.8.8".parse().unwrap();

        // Block for 200ms (increased for CI reliability)
        security.block_ip(
            ip,
            BlockReason::RateLimitExceeded,
            Some(Duration::from_millis(200)),
        );

        // Should be blocked
        assert!(security.is_blocked(&ip).is_some());

        // Wait for expiration (increased margin for CI reliability)
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Should no longer be blocked
        assert!(security.is_blocked(&ip).is_none());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);

        let backend = "test-backend";

        // Initially closed
        assert!(security.circuit_allows(backend));

        // Record failures
        for _ in 0..5 {
            security.record_backend_result(backend, false);
        }

        // Should be open now
        assert!(!security.circuit_allows(backend));
    }

    #[test]
    fn test_ja3_classification_empty_db() {
        // With an empty database every hash classifies as Suspicious (advisory only).
        let db = Ja3Database::default();
        let hash = "e7d705a3286e19ea42f587b344ee6865";
        assert_eq!(classify_ja3(hash, &db), FingerprintClass::Suspicious);

        let unknown = "00000000000000000000000000000000";
        assert_eq!(classify_ja3(unknown, &db), FingerprintClass::Suspicious);
    }

    #[test]
    fn test_fingerprint_db_load() {
        // Write a temporary JSON fingerprint database and verify loading.
        let entries = r#"[
            {"hash": "aabbccddeeff00112233445566778899", "classification": "browser", "description": "Test Browser"},
            {"hash": "112233445566778899aabbccddeeff00", "classification": "malicious", "description": "Test Scanner"},
            {"hash": "deadbeefdeadbeefdeadbeefdeadbeef", "classification": "api_client", "description": "curl"},
            {"hash": "cafebabecafebabecafebabecafebabe", "classification": "bot", "description": "Googlebot"}
        ]"#;

        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("pqcrypta_proxy_test_ja3_db.json");
        std::fs::write(&test_file, entries).expect("write temp file");

        let db = Ja3Database::load_from_file(&test_file).expect("load db");
        assert_eq!(db.len(), 4, "all 4 entries loaded");
        assert!(!db.is_empty());

        assert_eq!(
            classify_ja3("aabbccddeeff00112233445566778899", &db),
            FingerprintClass::Browser
        );
        assert_eq!(
            classify_ja3("112233445566778899aabbccddeeff00", &db),
            FingerprintClass::Malicious
        );
        assert_eq!(
            classify_ja3("deadbeefdeadbeefdeadbeefdeadbeef", &db),
            FingerprintClass::ApiClient
        );
        assert_eq!(
            classify_ja3("cafebabecafebabecafebabecafebabe", &db),
            FingerprintClass::LegitimateBot
        );
        // Unknown hash still returns Suspicious
        assert_eq!(
            classify_ja3("ffffffffffffffffffffffffffffffff", &db),
            FingerprintClass::Suspicious
        );

        // Case-insensitive lookup
        assert_eq!(
            classify_ja3("AABBCCDDEEFF00112233445566778899", &db),
            FingerprintClass::Browser
        );

        let _ = std::fs::remove_file(&test_file);
    }

    #[test]
    fn test_trusted_ip_no_public_bypass() {
        // The server's former public IP must not bypass security checks.
        let public_ip: IpAddr = "66.179.95.51".parse().unwrap();
        assert!(
            !is_trusted_ip(&public_ip),
            "Public IP must NOT be unconditionally trusted"
        );

        // Loopback must still be trusted.
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_trusted_ip(&loopback), "Loopback must be trusted");

        // SEC-A05: RFC1918 private ranges are no longer unconditionally trusted.
        // Operators who need to trust specific RFC1918 CIDRs must list them in
        // security.trusted_internal_cidrs (tested via SecurityState::is_trusted).
        let private: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(
            !is_trusted_ip(&private),
            "RFC1918 must NOT be unconditionally trusted (SEC-A05)"
        );

        let private2: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(
            !is_trusted_ip(&private2),
            "RFC1918 must NOT be unconditionally trusted (SEC-A05)"
        );
    }
}
