//! HTTP response cache (RFC 9111)
//!
//! - Cache-Control parsing (max-age, s-maxage, no-cache, no-store, private,
//!   public), `Expires` and `Pragma`
//! - ETag / If-None-Match and Last-Modified / If-Modified-Since
//! - `Vary`: only a response that varies on nothing the key leaves out is kept
//! - A store bounded by size, counting an entry's key and headers with its
//!   body, with S3-FIFO admission and eviction: a new entry starts in a small
//!   queue and reaches the main one only if it is asked for again, so a run of
//!   URLs each requested once passes through without displacing what is in use
//! - Expired entries are removed as they are met and by a periodic sweep
//!
//! The cache stores the response as the route produced it, before
//! compression. A listener consults it once a request has passed its route's
//! gates, and every outer layer (security headers, Alt-Svc, compression)
//! applies to a stored response as to a new one.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use bytes::Bytes;
use dashmap::DashMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the shared response cache.
///
/// Add a `[cache]` section to `config.toml` to enable.  Cache is **disabled**
/// by default so that existing deployments are not affected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseCacheConfig {
    /// Enable response caching (default: false — must be opted in)
    pub enabled: bool,
    /// Maximum total cache size in MiB (default: 128)
    pub max_size_mb: usize,
    /// Default TTL in seconds when no Cache-Control directive is present (default: 60)
    pub default_ttl_secs: u64,
    /// Maximum response body size to cache in bytes (default: 2 MiB).
    /// Responses larger than this value are forwarded but never stored.
    pub max_body_size_bytes: usize,
    /// URL path prefixes that are never cached
    pub excluded_paths: Vec<String>,
    /// Hostnames that are never cached (exact match or subdomain suffix).
    /// Use this to exclude API subdomains whose backends do not set
    /// `Cache-Control: no-store`.  Example: `["api.example.com"]`
    pub excluded_hosts: Vec<String>,
    /// Do not cache responses that set cookies (default: true)
    pub no_cache_set_cookie: bool,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_size_mb: 128,
            default_ttl_secs: 60,
            max_body_size_bytes: 2 * 1024 * 1024,
            excluded_paths: vec![
                "/api/".to_string(),
                "/ws".to_string(),
                "/stream".to_string(),
                "/auth".to_string(),
                "/admin".to_string(),
            ],
            excluded_hosts: vec![],
            no_cache_set_cookie: true,
        }
    }
}

// ============================================================================
// Cache entry
// ============================================================================

struct CacheEntry {
    /// HTTP status code from backend
    status: u16,
    /// Response headers forwarded from the backend
    headers: Vec<(String, String)>,
    /// Response body bytes (uncompressed; compression is handled by outer middleware).
    /// `Bytes` rather than `Arc<Vec<u8>>` so serving a hit clones a refcount
    /// instead of copying the whole body.
    body: Bytes,
    /// ETag header value from backend (for If-None-Match comparison)
    etag: Option<String>,
    /// Last-Modified header value from backend (sent back on a 304)
    last_modified: Option<String>,
    /// That value as a time, for If-Modified-Since
    modified_at: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// Raw Cache-Control header from backend (forwarded on 304 responses)
    cache_control: Option<String>,
    /// When this entry was created (used to compute Age header)
    created_at: Instant,
    /// When this entry expires and must be evicted
    expires_at: Instant,
    /// The origin stated this response's freshness for a shared cache
    /// (`max-age`, `s-maxage`, `Expires` or `public`); otherwise it is kept
    /// for the default lifetime, and only for requests without credentials.
    explicit: bool,
    /// What the entry counts for against the cache's size
    cost: usize,
    /// Which insertion of its key this is; a queue slot names it, so a slot
    /// left behind by an entry since replaced or removed is recognised
    id: u64,
    /// Hits since eviction last considered it, to 3
    freq: AtomicU8,
    /// In the main queue rather than the small one
    in_main: AtomicBool,
}

/// What an entry costs beyond its strings: its place in the map and a queue.
const ENTRY_OVERHEAD: usize = 512;
/// What a stored header costs beyond its name and value.
const HEADER_OVERHEAD: usize = 48;
/// Keys remembered after leaving the small queue unrequested, as hashes.
const GHOST_MAX: usize = 100_000;
/// How often expired entries are swept out.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// The longest a response with an error status is kept on the default
/// lifetime (it was not stated to be cacheable, only allowed to be).
const NEGATIVE_TTL: Duration = Duration::from_secs(10);

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// The S3-FIFO queues, and the bytes each holds. A slot is a key and the id
/// of the entry it was pushed for.
#[derive(Default)]
struct Queues {
    small: VecDeque<(String, u64)>,
    main: VecDeque<(String, u64)>,
    small_bytes: usize,
    main_bytes: usize,
    ghost: VecDeque<u64>,
    ghost_set: HashSet<u64>,
}

impl Queues {
    /// Take `entry`'s cost off the queue it is in.
    fn forget(&mut self, entry: &CacheEntry) {
        if entry.in_main.load(Ordering::Relaxed) {
            self.main_bytes = self.main_bytes.saturating_sub(entry.cost);
        } else {
            self.small_bytes = self.small_bytes.saturating_sub(entry.cost);
        }
    }

    fn remember(&mut self, hash: u64) {
        if self.ghost_set.insert(hash) {
            self.ghost.push_back(hash);
        }
        while self.ghost.len() > GHOST_MAX {
            if let Some(old) = self.ghost.pop_front() {
                self.ghost_set.remove(&old);
            }
        }
    }
}

// ============================================================================
// Cache lookup result
// ============================================================================

/// Result of a cache lookup
pub enum CacheLookup {
    /// Cache hit — serve stored response
    Hit {
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
        /// Seconds elapsed since the entry was stored (for the `Age` header)
        age_secs: u64,
    },
    /// Conditional request — resource not modified, return 304
    NotModified {
        etag: Option<String>,
        last_modified: Option<String>,
        cache_control: Option<String>,
        age_secs: u64,
    },
    /// Cache miss — forward request to backend
    Miss,
}

// ============================================================================
// Cache-Control parser
// ============================================================================

#[derive(Default)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    is_private: bool,
    is_public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
}

impl CacheControlDirectives {
    /// Every `Cache-Control` field line of `headers` together.
    fn of(headers: &HeaderMap) -> Self {
        let mut d = Self::default();
        for value in headers.get_all(header::CACHE_CONTROL) {
            if let Ok(value) = value.to_str() {
                d.add(value);
            }
        }
        d
    }

    fn add(&mut self, header: &str) {
        for part in header.split(',') {
            let part = part.trim().to_lowercase();
            if part == "no-store" {
                self.no_store = true;
            } else if part == "no-cache" || part.starts_with("no-cache=") {
                self.no_cache = true;
            } else if part == "private" || part.starts_with("private=") {
                self.is_private = true;
            } else if part == "public" {
                self.is_public = true;
            } else if let Some(val) = part.strip_prefix("max-age=") {
                self.max_age = val.trim_matches('"').parse::<u64>().ok();
            } else if let Some(val) = part.strip_prefix("s-maxage=") {
                self.s_maxage = val.trim_matches('"').parse::<u64>().ok();
            }
        }
    }
}

/// An HTTP-date (RFC 9110 section 5.6.7) as a time.
fn http_date(value: &str) -> Option<chrono::DateTime<chrono::FixedOffset>> {
    chrono::DateTime::parse_from_rfc2822(value.trim()).ok()
}

/// A request the cache may answer and keep the answer to
/// ([`ResponseCache::plan`]).
#[derive(Debug, Clone)]
pub struct CachePlan {
    /// The entry's key
    pub key: String,
    /// The request carries a cookie: only a response the origin stated to be
    /// cacheable is kept for it or served to it
    pub credentialed: bool,
    /// The client did not ask for a response fresh from the origin
    pub lookup: bool,
}

// ============================================================================
// Response cache
// ============================================================================

/// One step of eviction, from one of the two queues; false when it is empty.
type Evict = fn(&ResponseCache, &mut Queues) -> bool;

/// Shared, concurrent response cache.
///
/// Entries live in a `DashMap`, so a lookup takes no lock of the cache's own.
/// Everything that adds or removes an entry holds `queues`, taken before any
/// lock of the map.
pub struct ResponseCache {
    store: DashMap<String, CacheEntry>,
    queues: Mutex<Queues>,
    size_bytes: AtomicUsize,
    next_id: AtomicU64,
    /// Public config reference (read by the listeners)
    pub config: ResponseCacheConfig,
    /// Misses being fetched, by key: what identical requests wait on
    inflight: Arc<DashMap<String, InFlight>>,
    /// How misses are collapsed (`http3.coalescing_*`), as last configured
    collapse: parking_lot::RwLock<CollapseSettings>,
}

/// A miss being fetched: the requests waiting on it watch `done`, which
/// closes when the fetch has stored its response or given up.
struct InFlight {
    done: tokio::sync::watch::Receiver<()>,
    waiting: Arc<AtomicUsize>,
}

/// How identical misses are collapsed onto one fetch (`[http3]`
/// `coalescing_enabled`, `coalescing_max_wait_ms`, `coalescing_max_subscribers`,
/// `coalescing_methods`, `coalescing_exclude_paths`).
#[derive(Debug, Clone)]
pub struct CollapseSettings {
    pub enabled: bool,
    /// How long a request waits for the fetch it joined
    pub wait: std::time::Duration,
    /// Requests that may wait on one fetch; one past them fetches for itself
    pub max_waiting: usize,
    /// Methods that wait (GET leads a fetch; HEAD only waits on one)
    pub methods: Vec<Method>,
    /// Path prefixes never collapsed
    pub exclude_paths: Vec<String>,
}

impl Default for CollapseSettings {
    fn default() -> Self {
        Self::of(&crate::config::Http3Config::default())
    }
}

impl CollapseSettings {
    pub fn of(config: &crate::config::Http3Config) -> Self {
        Self {
            enabled: config.coalescing_enabled,
            wait: std::time::Duration::from_millis(config.coalescing_max_wait_ms),
            max_waiting: config.coalescing_max_subscribers,
            methods: config
                .coalescing_methods
                .iter()
                .filter_map(|m| m.parse().ok())
                .collect(),
            exclude_paths: config.coalescing_exclude_paths.clone(),
        }
    }
}

/// The fetch of a miss, which identical requests wait on until this drops:
/// held until the response has been stored (or will not be).
pub struct Leading {
    inflight: Arc<DashMap<String, InFlight>>,
    key: String,
    _done: tokio::sync::watch::Sender<()>,
}

impl Drop for Leading {
    fn drop(&mut self) {
        // Out of the map first, so no request joins a fetch that has ended;
        // the sender drops after this and wakes every one that did.
        self.inflight.remove(&self.key);
    }
}

impl ResponseCache {
    /// Create a new cache with the given configuration.
    pub fn new(config: ResponseCacheConfig) -> Self {
        Self {
            store: DashMap::new(),
            queues: Mutex::new(Queues::default()),
            size_bytes: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
            config,
            inflight: Arc::new(DashMap::new()),
            collapse: parking_lot::RwLock::new(CollapseSettings::default()),
        }
    }

    fn max_bytes(&self) -> usize {
        self.config.max_size_mb.saturating_mul(1024 * 1024)
    }

    fn key_hash(key: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Build a cache key from the request method, host, and path (with query string).
    ///
    /// We do not include `Accept-Encoding` in the key because the cache stores
    /// uncompressed responses; the outer compression middleware re-encodes on
    /// every response, including cache hits.
    pub fn build_key(method: &str, host: &str, path_with_query: &str) -> String {
        format!(
            "{}|{}|{}",
            method.to_uppercase(),
            host.to_lowercase(),
            path_with_query
        )
    }

    /// Whether the cache may answer this request and keep its response, and
    /// under which key. `host` is lowercase without its port and `path` the
    /// canonical path: what the request is routed on.
    ///
    /// GET and HEAD only, a HEAD answered from the GET's entry. A range
    /// request goes to the backend (the cache keeps whole responses), and so
    /// does one carrying `Authorization` (RFC 9111 section 3.5) or asking not
    /// to be stored.
    pub fn plan(
        &self,
        method: &Method,
        headers: &HeaderMap,
        host: &str,
        path: &str,
        query: Option<&str>,
    ) -> Option<CachePlan> {
        if !self.config.enabled || !matches!(*method, Method::GET | Method::HEAD) {
            return None;
        }
        if headers.contains_key(header::RANGE) || headers.contains_key(header::AUTHORIZATION) {
            return None;
        }
        if self.is_excluded_path(path) || self.is_excluded_host(host) {
            return None;
        }
        let asked = CacheControlDirectives::of(headers);
        if asked.no_store {
            return None;
        }
        let pragma_no_cache = headers
            .get(header::PRAGMA)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-cache"));
        let key = match query {
            Some(q) => Self::build_key("GET", host, &format!("{path}?{q}")),
            None => Self::build_key("GET", host, path),
        };
        Some(CachePlan {
            key,
            credentialed: headers.contains_key(header::COOKIE),
            // RFC 9111 section 5.2.1: the client wants the origin's answer
            lookup: !(asked.no_cache || asked.max_age == Some(0) || pragma_no_cache),
        })
    }

    /// Apply `[http3]`'s collapse settings, at startup and on every reload.
    pub fn configure_collapse(&self, config: &crate::config::Http3Config) {
        *self.collapse.write() = CollapseSettings::of(config);
    }

    /// Look up `plan`'s response; on a miss, collapse identical requests onto
    /// one fetch. The first GET to miss leads: it fetches, and the returned
    /// [`Leading`] is held until its response has been stored. A request that
    /// misses while a fetch for the same key is under way waits for it (up to
    /// `coalescing_max_wait_ms`) and looks again, answered from the cache when
    /// the response could be kept, or fetching for itself when it could not.
    ///
    /// The key is the cache's own (host, path and query), and a request is
    /// answered from what was stored only by the cache's own rules (a request
    /// with a cookie only from an entry the origin stated to be cacheable), so
    /// no response reaches a request it would not have been served to from the
    /// cache anyway.
    pub async fn lookup(
        &self,
        plan: &CachePlan,
        method: &Method,
        path: &str,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> (CacheLookup, Option<Leading>) {
        let first = self.get_for(
            &plan.key,
            plan.credentialed,
            if_none_match,
            if_modified_since,
        );
        if !matches!(first, CacheLookup::Miss) {
            return (first, None);
        }
        let settings = self.collapse.read().clone();
        if !settings.enabled
            || !settings.methods.contains(method)
            || settings
                .exclude_paths
                .iter()
                .any(|p| path.starts_with(p.as_str()))
        {
            return (first, None);
        }
        let joined = match self.inflight.entry(plan.key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(fetch) => {
                let fetch = fetch.get();
                (fetch.waiting.load(Ordering::Relaxed) < settings.max_waiting)
                    .then(|| (fetch.done.clone(), Arc::clone(&fetch.waiting)))
            }
            dashmap::mapref::entry::Entry::Vacant(free) => {
                if *method != Method::GET {
                    // Only a GET's response is stored: a HEAD does not lead.
                    return (first, None);
                }
                let (done, watch) = tokio::sync::watch::channel(());
                free.insert(InFlight {
                    done: watch,
                    waiting: Arc::new(AtomicUsize::new(0)),
                });
                return (
                    first,
                    Some(Leading {
                        inflight: Arc::clone(&self.inflight),
                        key: plan.key.clone(),
                        _done: done,
                    }),
                );
            }
        };
        let Some((mut done, waiting)) = joined else {
            return (first, None);
        };
        waiting.fetch_add(1, Ordering::Relaxed);
        // `changed` ends with the fetch: the sender goes when it does.
        let _ = tokio::time::timeout(settings.wait, done.changed()).await;
        waiting.fetch_sub(1, Ordering::Relaxed);
        (
            self.get_for(
                &plan.key,
                plan.credentialed,
                if_none_match,
                if_modified_since,
            ),
            None,
        )
    }

    /// Look up a response for a request without credentials.
    pub fn get(
        &self,
        key: &str,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> CacheLookup {
        self.get_for(key, false, if_none_match, if_modified_since)
    }

    /// Look up a response.  Returns `Hit`, `NotModified`, or `Miss`.
    ///
    /// A `credentialed` request (one carrying a cookie) is answered only from
    /// an entry the origin stated to be cacheable.
    pub fn get_for(
        &self,
        key: &str,
        credentialed: bool,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> CacheLookup {
        if !self.config.enabled {
            return CacheLookup::Miss;
        }

        let Some(entry) = self.store.get(key) else {
            return CacheLookup::Miss;
        };

        if entry.is_expired() {
            // The map's guard goes before `queues` is taken (see the type).
            drop(entry);
            self.remove_expired(key);
            return CacheLookup::Miss;
        }
        if credentialed && !entry.explicit {
            return CacheLookup::Miss;
        }

        // Asked for again: what S3-FIFO keeps an entry on.
        let _ = entry
            .freq
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |f| {
                (f < 3).then_some(f + 1)
            });

        let age_secs = entry.created_at.elapsed().as_secs();

        // --- ETag conditional check (If-None-Match) ---
        // A list of validators, each compared weakly (RFC 9110 section 13.1.2).
        if let (Some(inm), Some(etag)) = (if_none_match, &entry.etag) {
            let opaque = |tag: &str| -> String {
                tag.trim()
                    .trim_start_matches("W/")
                    .trim_matches('"')
                    .to_string()
            };
            let cached = opaque(etag);
            if inm
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == "*" || opaque(candidate) == cached)
            {
                trace!("Cache 304 via ETag for {}", key);
                return CacheLookup::NotModified {
                    etag: entry.etag.clone(),
                    last_modified: entry.last_modified.clone(),
                    cache_control: entry.cache_control.clone(),
                    age_secs,
                };
            }
        }

        // --- Last-Modified conditional check (If-Modified-Since) ---
        // Only when no If-None-Match was sent (RFC 9110 §13.1.3), and only
        // where both dates read as dates.
        if if_none_match.is_none() {
            if let (Some(since), Some(modified)) =
                (if_modified_since.and_then(http_date), entry.modified_at)
            {
                if modified <= since {
                    trace!("Cache 304 via Last-Modified for {}", key);
                    return CacheLookup::NotModified {
                        etag: entry.etag.clone(),
                        last_modified: entry.last_modified.clone(),
                        cache_control: entry.cache_control.clone(),
                        age_secs,
                    };
                }
            }
        }

        debug!(
            "Cache HIT: {} (age {}s, {} bytes)",
            key,
            age_secs,
            entry.body.len()
        );
        CacheLookup::Hit {
            status: entry.status,
            headers: entry.headers.clone(),
            body: entry.body.clone(),
            age_secs,
        }
    }

    /// Store a backend response to a request without credentials.
    pub fn put(&self, key: &str, status: u16, response_headers: &[(String, String)], body: Bytes) {
        self.put_for(key, false, status, response_headers, body);
    }

    /// Store a backend response.  Respects Cache-Control directives, size limits,
    /// and the `no_cache_set_cookie` configuration flag.
    ///
    /// The response to a `credentialed` request (one carrying a cookie) is kept
    /// only when the origin stated it to be cacheable; one it said nothing
    /// about may be that visitor's own.
    pub fn put_for(
        &self,
        key: &str,
        credentialed: bool,
        status: u16,
        response_headers: &[(String, String)],
        body: Bytes,
    ) {
        if !self.config.enabled {
            return;
        }

        if body.len() > self.config.max_body_size_bytes {
            trace!("Not caching {}: body {} > limit", key, body.len());
            return;
        }

        // Parse headers we care about
        let mut directives = CacheControlDirectives::default();
        let mut cache_control_val: Option<String> = None;
        let mut etag: Option<String> = None;
        let mut last_modified: Option<String> = None;
        let mut expires: Option<String> = None;
        let mut vary: Option<String> = None;
        let mut has_set_cookie = false;
        let mut has_content_encoding = false;
        let mut has_content_range = false;
        let mut has_csp_nonce = false;
        let mut pragma_no_cache = false;

        for (name, value) in response_headers {
            match name.to_lowercase().as_str() {
                "cache-control" => {
                    directives.add(value);
                    cache_control_val = Some(match cache_control_val {
                        Some(held) => format!("{held}, {value}"),
                        None => value.clone(),
                    });
                }
                "etag" => etag = Some(value.clone()),
                "last-modified" => last_modified = Some(value.clone()),
                "expires" => expires = Some(value.clone()),
                "pragma" => pragma_no_cache |= value.to_ascii_lowercase().contains("no-cache"),
                "vary" => {
                    vary = Some(match vary {
                        Some(held) => format!("{held}, {value}"),
                        None => value.clone(),
                    });
                }
                "set-cookie" => has_set_cookie = true,
                "content-encoding" => has_content_encoding = true,
                "content-range" => has_content_range = true,
                "content-security-policy" | "content-security-policy-report-only"
                    if value.contains("'nonce-") =>
                {
                    has_csp_nonce = true;
                }
                _ => {}
            }
        }

        // Never cache a response carrying a CSP nonce.
        //
        // A nonce is the server stating that these exact script and style tags,
        // in this exact response, are the ones permitted to run. Storing that
        // response hands the same nonce to every subsequent visitor for the
        // life of the entry, and a nonce known to everyone authorises everyone:
        // an injected tag carrying it satisfies script-src, which is the one
        // thing the nonce existed to prevent. The header is the reliable signal
        // here: if the CSP names a nonce, the body is unique to one response by
        // construction and is not ours to replay.
        if has_csp_nonce {
            trace!("Not caching {}: response carries a CSP nonce", key);
            return;
        }

        // Never cache partial content. This cache keys on method+host+path with no
        // range component and has no range-recombination logic, so storing a 206 (or
        // any Content-Range response) would let one byte range be served for a
        // different range — corrupting media/video playback. Let range requests
        // always reach the backend.
        if status == 206 || status == 416 || has_content_range {
            trace!(
                "Not caching {}: partial/range response (status {})",
                key,
                status
            );
            return;
        }

        // Never cache responses that set cookies (opt-out via config)
        if has_set_cookie && self.config.no_cache_set_cookie {
            trace!("Not caching {}: Set-Cookie present", key);
            return;
        }

        // Never cache backend-compressed responses (we cache pre-compression bodies)
        if has_content_encoding {
            trace!("Not caching {}: Content-Encoding present", key);
            return;
        }

        // `Vary` names the request headers the body depends on.
        //
        // The cache key is METHOD|host|path and nothing else, so a stored entry
        // cannot tell apart two requests that differ only by a header. Anything
        // the response varies on that the key does not cover therefore means one
        // entry would answer requests that are supposed to get different bodies:
        //
        //   - `Vary: Cookie` or `Vary: Authorization` — one user's personalised
        //     response handed to another. A cross-user leak, not a staleness bug.
        //   - `Vary: Origin` — a stored `Access-Control-Allow-Origin` naming one
        //     origin, returned to a request from a different one, telling that
        //     origin's browser it may read the body.
        //   - `Vary: Accept-Language`, `Accept`, `User-Agent` — simply the wrong
        //     variant.
        //   - `Vary: *` — varies on things not expressible as headers at all.
        //
        // `Accept-Encoding` is the one safe exception, and only because of where
        // this cache sits: inside compression, so it only ever stores identity
        // bodies (backend-compressed responses are already refused above). The
        // stored entry is correct for every client, and the outer layer applies
        // the client's encoding to hits and misses alike.
        if let Some(varies_on) = vary.as_deref() {
            let unsupported: Vec<&str> = varies_on
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty() && !h.eq_ignore_ascii_case("accept-encoding"))
                .collect();
            if !unsupported.is_empty() {
                trace!(
                    "Not caching {key}: Vary on {unsupported:?}, which the cache key \
                     cannot distinguish"
                );
                return;
            }
        }

        if directives.no_store || directives.is_private || directives.no_cache {
            trace!("Not caching {}: no-store, private or no-cache", key);
            return;
        }

        // How long, and whether the origin said so. s-maxage takes precedence
        // over max-age for a shared cache, and either over Expires (RFC 9111
        // section 5.2.2.10, 5.3). A lifetime of zero is a response to
        // revalidate every time: there is nothing to keep.
        let stated = match directives.s_maxage.or(directives.max_age) {
            Some(0) => {
                trace!("Not caching {}: a lifetime of zero", key);
                return;
            }
            Some(secs) => Some(Duration::from_secs(secs)),
            None => match expires.as_deref() {
                Some(expires) => {
                    let left = http_date(expires)
                        .map(|at| at.signed_duration_since(chrono::Utc::now()).num_seconds())
                        .unwrap_or(0);
                    match u64::try_from(left) {
                        Ok(secs) if secs > 0 => Some(Duration::from_secs(secs)),
                        // In the past, or not a date: already stale
                        _ => {
                            trace!("Not caching {}: Expires is not in the future", key);
                            return;
                        }
                    }
                }
                None => None,
            },
        };
        let explicit = stated.is_some() || directives.is_public;
        let ttl = match stated {
            Some(ttl) => ttl,
            None => {
                // The origin stated no lifetime: only the status codes that are
                // heuristically cacheable (RFC 9110 §15.1), for the default one.
                if pragma_no_cache || !is_cacheable_by_default(status) {
                    trace!(
                        "Not caching {}: status {} with no stated lifetime",
                        key,
                        status
                    );
                    return;
                }
                let default = Duration::from_secs(self.config.default_ttl_secs);
                if status >= 400 {
                    default.min(NEGATIVE_TTL)
                } else {
                    default
                }
            }
        };
        if ttl.is_zero() {
            return;
        }
        if credentialed && !explicit {
            trace!(
                "Not caching {}: the request carried a cookie and the origin stated no lifetime",
                key
            );
            return;
        }

        let cost = ENTRY_OVERHEAD
            + key.len()
            + body.len()
            + response_headers
                .iter()
                .map(|(n, v)| n.len() + v.len() + HEADER_OVERHEAD)
                .sum::<usize>();
        let now = Instant::now();
        let body_size = body.len();
        self.insert(
            key,
            CacheEntry {
                status,
                headers: response_headers.to_vec(),
                body,
                etag,
                modified_at: last_modified.as_deref().and_then(http_date),
                last_modified,
                cache_control: cache_control_val,
                created_at: now,
                expires_at: now + ttl,
                explicit,
                cost,
                id: self.next_id.fetch_add(1, Ordering::Relaxed),
                freq: AtomicU8::new(0),
                in_main: AtomicBool::new(false),
            },
        );

        debug!("Cached {} (ttl {:?}, {} bytes)", key, ttl, body_size);
    }

    /// Add `entry` under `key`, replacing any it had, and evict until the
    /// cache is within its size.
    fn insert(&self, key: &str, entry: CacheEntry) {
        let max = self.max_bytes();
        if entry.cost > max {
            return;
        }
        let mut queues = self.queues.lock();
        if let Some((_, old)) = self.store.remove(key) {
            queues.forget(&old);
            self.size_bytes.fetch_sub(old.cost, Ordering::Relaxed);
        }
        // A key that left the small queue unrequested and is back goes
        // straight to the main one.
        let to_main = queues.ghost_set.remove(&Self::key_hash(key));
        entry.in_main.store(to_main, Ordering::Relaxed);
        let slot = (key.to_string(), entry.id);
        if to_main {
            queues.main_bytes += entry.cost;
            queues.main.push_back(slot);
        } else {
            queues.small_bytes += entry.cost;
            queues.small.push_back(slot);
        }
        self.size_bytes.fetch_add(entry.cost, Ordering::Relaxed);
        self.store.insert(key.to_string(), entry);
        self.evict_to_fit(&mut queues, max);
    }

    /// Evict until the queues hold no more than `max` bytes (S3-FIFO): from
    /// the small queue while it is over a tenth of the cache, else from the
    /// main one.
    fn evict_to_fit(&self, queues: &mut Queues, max: usize) {
        let small_target = max / 10;
        // Every step takes a slot off a queue, and puts one back at most
        // three times per entry: this many steps empty both.
        let mut steps = (queues.small.len() + queues.main.len()).saturating_mul(5) + 16;
        while queues.small_bytes + queues.main_bytes > max && steps > 0 {
            steps -= 1;
            let from_small = queues.small_bytes > small_target || queues.main.is_empty();
            // The queue to take from, and the other where that one is empty
            let (first, second): (Evict, Evict) = if from_small {
                (Self::evict_small, Self::evict_main)
            } else {
                (Self::evict_main, Self::evict_small)
            };
            if !first(self, queues) && !second(self, queues) {
                break;
            }
        }
    }

    /// Take the oldest slot of the small queue: an entry asked for more than
    /// once since it came moves to the main queue, any other leaves the cache
    /// and its key is remembered. False when the queue is empty.
    fn evict_small(&self, queues: &mut Queues) -> bool {
        let Some((key, id)) = queues.small.pop_front() else {
            return false;
        };
        // (cost, keep) of the entry this slot is for, if it is still there
        let live = self.store.get(&key).filter(|e| e.id == id).map(|e| {
            let keep = !e.is_expired() && e.freq.load(Ordering::Relaxed) > 1;
            if keep {
                e.in_main.store(true, Ordering::Relaxed);
                e.freq.store(0, Ordering::Relaxed);
            }
            (e.cost, keep)
        });
        match live {
            None => {}
            Some((cost, true)) => {
                queues.small_bytes = queues.small_bytes.saturating_sub(cost);
                queues.main_bytes += cost;
                queues.main.push_back((key, id));
            }
            Some((cost, false)) => {
                self.store.remove(&key);
                queues.small_bytes = queues.small_bytes.saturating_sub(cost);
                self.size_bytes.fetch_sub(cost, Ordering::Relaxed);
                queues.remember(Self::key_hash(&key));
            }
        }
        true
    }

    /// Take the oldest slot of the main queue: an entry asked for since it
    /// was last here goes to the back with one use fewer, any other leaves
    /// the cache. False when the queue is empty.
    fn evict_main(&self, queues: &mut Queues) -> bool {
        let Some((key, id)) = queues.main.pop_front() else {
            return false;
        };
        let live = self.store.get(&key).filter(|e| e.id == id).map(|e| {
            let freq = e.freq.load(Ordering::Relaxed);
            let keep = !e.is_expired() && freq > 0;
            if keep {
                e.freq.store(freq - 1, Ordering::Relaxed);
            }
            (e.cost, keep)
        });
        match live {
            None => {}
            Some((_, true)) => queues.main.push_back((key, id)),
            Some((cost, false)) => {
                self.store.remove(&key);
                queues.main_bytes = queues.main_bytes.saturating_sub(cost);
                self.size_bytes.fetch_sub(cost, Ordering::Relaxed);
            }
        }
        true
    }

    /// Remove `key`'s entry if it has expired.
    fn remove_expired(&self, key: &str) {
        let mut queues = self.queues.lock();
        if let Some((_, entry)) = self.store.remove_if(key, |_, e| e.is_expired()) {
            queues.forget(&entry);
            self.size_bytes.fetch_sub(entry.cost, Ordering::Relaxed);
        }
    }

    /// Return `true` if `path` matches any of the configured excluded prefixes.
    pub fn is_excluded_path(&self, path: &str) -> bool {
        self.config
            .excluded_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    /// Return `true` if `host` matches any entry in `excluded_hosts`.
    /// Matches exact hostname or any subdomain of an entry that starts with `.`
    /// (e.g., ".example.com" excludes "api.example.com" and "www.example.com").
    pub fn is_excluded_host(&self, host: &str) -> bool {
        let host = crate::config::host_without_port(host);
        self.config.excluded_hosts.iter().any(|h| {
            if h.starts_with('.') {
                host.ends_with(h.as_str()) || host == &h[1..]
            } else {
                host == h.as_str()
            }
        })
    }

    /// Remove the entries `gone` selects, then the queue slots that name no
    /// entry any more. Returns how many entries and bytes went.
    fn remove_where<F>(&self, mut gone: F) -> (usize, usize)
    where
        F: FnMut(&str, &CacheEntry) -> bool,
    {
        let mut queues = self.queues.lock();
        let (mut removed, mut bytes) = (0usize, 0usize);
        {
            let queues = &mut *queues;
            self.store.retain(|key, entry| {
                if gone(key, entry) {
                    removed += 1;
                    bytes += entry.cost;
                    queues.forget(entry);
                    false
                } else {
                    true
                }
            });
        }
        if bytes > 0 {
            self.size_bytes.fetch_sub(bytes, Ordering::Relaxed);
        }
        let store = &self.store;
        let live = |(key, id): &(String, u64)| store.get(key).is_some_and(|e| e.id == *id);
        queues.small.retain(live);
        queues.main.retain(live);
        (removed, bytes)
    }

    /// Evict all expired entries and reclaim their size accounting.
    pub fn evict_expired(&self) {
        let (removed, bytes) = self.remove_where(|_, entry| entry.is_expired());
        if removed > 0 {
            debug!("Evicted {removed} expired cache entries ({bytes} bytes)");
        }
    }

    /// Return `(entry_count, total_size_bytes)` for monitoring. The size is
    /// what the entries count for against `max_size_mb`: bodies, headers,
    /// keys and a fixed share each.
    pub fn stats(&self) -> (usize, usize) {
        (self.store.len(), self.size_bytes.load(Ordering::Relaxed))
    }

    /// Drop every entry. Returns how many were removed.
    pub fn purge_all(&self) -> usize {
        let mut queues = self.queues.lock();
        let removed = self.store.len();
        let bytes = self.size_bytes.swap(0, Ordering::Relaxed);
        self.store.clear();
        *queues = Queues::default();
        if removed > 0 {
            info!("Cache purged: {removed} entries, {bytes} bytes");
        }
        removed
    }

    /// Drop entries whose key matches `predicate`. Returns how many were
    /// removed.
    ///
    /// Keys are `METHOD|host|path_with_query` (see [`Self::build_key`]), so a
    /// caller can select by host, by path prefix, or by exact URL without the
    /// cache needing to know which.
    fn purge_where<F>(&self, predicate: F) -> usize
    where
        F: Fn(&str) -> bool,
    {
        self.remove_where(|key, _| predicate(key)).0
    }

    /// Drop every entry for one host, whatever the method or path.
    ///
    /// Matched case-insensitively because [`Self::build_key`] lowercases the
    /// host when building the key, and an operator typing `Example.com` should
    /// not silently purge nothing.
    pub fn purge_host(&self, host: &str) -> usize {
        let needle = format!("|{}|", host.to_lowercase());
        let n = self.purge_where(|key| key.contains(&needle));
        info!("Cache purged for host {host}: {n} entries");
        n
    }

    /// Drop every entry whose path starts with `prefix`, on any host.
    ///
    /// The common case after a deploy: one generated path changed and the rest
    /// of the cache is still good.
    pub fn purge_prefix(&self, prefix: &str) -> usize {
        let n = self.purge_where(|key| {
            // key is METHOD|host|path — take everything after the second bar.
            key.splitn(3, '|')
                .nth(2)
                .is_some_and(|path| path.starts_with(prefix))
        });
        info!("Cache purged for prefix {prefix}: {n} entries");
        n
    }

    /// Drop one host's entries whose path starts with `prefix`: a page and
    /// what hangs off it on one site, leaving every other host warm.
    pub fn purge_host_prefix(&self, host: &str, prefix: &str) -> usize {
        let host = host.to_lowercase();
        let n = self.purge_where(|key| {
            // key is METHOD|host|path
            let mut parts = key.splitn(3, '|');
            parts.next();
            parts.next() == Some(host.as_str())
                && parts.next().is_some_and(|path| path.starts_with(prefix))
        });
        info!("Cache purged for {host}{prefix}*: {n} entries");
        n
    }

    /// Drop one host's entry for one exact path, across every method.
    pub fn purge_url(&self, host: &str, path: &str) -> usize {
        let needle = format!("|{}|{}", host.to_lowercase(), path);
        let n = self.purge_where(|key| key.ends_with(&needle));
        info!("Cache purged {host}{path}: {n} entries");
        n
    }

    /// Answer a miss: keep `body` if the response may be stored and ends
    /// within the cache's per-entry limit, and pass it on either way.
    ///
    /// A response the cache could never store (`no-store`, `private`,
    /// `no-cache`, or a `Content-Length` over the limit) streams through
    /// untouched, and one that turns out longer than the limit streams on,
    /// the bytes already read first: a body is never held back that cannot be
    /// kept, and never lost. `per_request` names a header that belongs to
    /// this one response (its request ID) and is left out of what is stored.
    pub async fn store_or_stream(
        &self,
        plan: &CachePlan,
        per_request: Option<&HeaderName>,
        mut parts: axum::http::response::Parts,
        body: Body,
    ) -> Response<Body> {
        let limit = self.config.max_body_size_bytes;
        if !may_store(&parts.headers, limit) {
            parts
                .headers
                .insert("x-cache", HeaderValue::from_static("MISS"));
            return Response::from_parts(parts, body);
        }
        match buffer_within(body, limit).await {
            Ok(bytes) => {
                let kept: Vec<(String, String)> = parts
                    .headers
                    .iter()
                    .filter(|(name, _)| Some(*name) != per_request)
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                    .collect();
                self.put_for(
                    &plan.key,
                    plan.credentialed,
                    parts.status.as_u16(),
                    &kept,
                    bytes.clone(),
                );
                parts
                    .headers
                    .insert("x-cache", HeaderValue::from_static("MISS"));
                Response::from_parts(parts, Body::from(bytes))
            }
            Err(body) => {
                // Longer than the cache keeps: not stored, sent whole.
                parts
                    .headers
                    .insert("x-cache", HeaderValue::from_static("MISS"));
                Response::from_parts(parts, body)
            }
        }
    }
}

/// A stored response as the answer to a request; a HEAD gets the headers a
/// GET would have and no body (RFC 9110 section 9.3.2).
pub fn hit_response(
    is_head: bool,
    status: u16,
    headers: &[(String, String)],
    body: Bytes,
    age_secs: u64,
) -> Response<Body> {
    let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status_code);
    for (k, v) in headers {
        // Skip content-length — we set it precisely from the stored body
        if !k.eq_ignore_ascii_case("content-length") {
            if let Ok(val) = HeaderValue::from_str(v) {
                builder = builder.header(k.as_str(), val);
            }
        }
    }
    builder = builder
        .header("content-length", body.len().to_string())
        .header("age", age_secs.to_string())
        .header("x-cache", "HIT");
    let resp_body = if is_head {
        Body::empty()
    } else {
        Body::from(body)
    };
    builder
        .body(resp_body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// 304 for a conditional request the stored response satisfies.
pub fn not_modified_response(
    etag: Option<String>,
    last_modified: Option<String>,
    cache_control: Option<String>,
    age_secs: u64,
) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
    for (name, value) in [
        ("etag", etag),
        ("last-modified", last_modified),
        ("cache-control", cache_control),
    ] {
        if let Some(val) = value.and_then(|v| HeaderValue::from_str(&v).ok()) {
            builder = builder.header(name, val);
        }
    }
    builder
        .header("age", age_secs.to_string())
        .header("x-cache", "HIT")
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// The one response cache for this process.
///
/// Shared rather than built per listener. There were five instances — one per
/// HTTP listener variant and one per QUIC port — so the same URL was cached
/// separately for h2 and h3 and for each port, and a purge would have cleared
/// one of them while the others kept serving the old body. The cache key is
/// `METHOD|host|path` with no port or protocol in it, so sharing is not just
/// safe but what the key already assumed.
static SHARED: std::sync::OnceLock<Arc<ResponseCache>> = std::sync::OnceLock::new();

/// Fetch (building on first call) the process-wide response cache.
///
/// The first caller's config wins. Cache sizing cannot follow a hot reload
/// anyway without discarding everything, which is the opposite of what a reload
/// should do.
pub fn shared(config: &ResponseCacheConfig) -> Arc<ResponseCache> {
    SHARED
        .get_or_init(|| {
            let cache = Arc::new(ResponseCache::new(config.clone()));
            // Entries nobody asks for again leave on this timer rather than
            // waiting to be pushed out. Where there is no runtime (a unit
            // test) nothing is spawned and expiry happens on lookup alone.
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                let swept = Arc::clone(&cache);
                runtime.spawn(async move {
                    let mut tick = tokio::time::interval(SWEEP_INTERVAL);
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    loop {
                        tick.tick().await;
                        swept.evict_expired();
                    }
                });
            }
            cache
        })
        .clone()
}

// ============================================================================
// Status codes cacheable by default (RFC 9110 §15.1)
// ============================================================================

fn is_cacheable_by_default(status: u16) -> bool {
    matches!(
        status,
        200 | 203 | 204 | 206 | 300 | 301 | 404 | 405 | 410 | 414 | 501
    )
}

/// Could a response with these headers be stored? The cheap refusals only,
/// read before any of the body is: `put` still makes the full decision. A
/// response refused here is passed on as it streams.
pub(crate) fn may_store(headers: &axum::http::HeaderMap, max_body: usize) -> bool {
    let d = CacheControlDirectives::of(headers);
    let refused = d.no_store || d.is_private || d.no_cache;
    let too_long = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > max_body as u64);
    !refused && !too_long
}

/// The whole body when it ends within `limit` bytes; otherwise a body that
/// replays what was read and then the rest, as it arrives. A read error part
/// way is passed on after the bytes before it.
async fn buffer_within(mut body: Body, limit: usize) -> Result<Bytes, Body> {
    use futures_util::StreamExt as _;
    use http_body_util::BodyExt as _;
    let mut read: Vec<Bytes> = Vec::new();
    let mut total = 0usize;
    loop {
        match body.frame().await {
            None => {
                let mut whole = bytes::BytesMut::with_capacity(total);
                for b in read {
                    whole.extend_from_slice(&b);
                }
                return Ok(whole.freeze());
            }
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    total += data.len();
                    read.push(data);
                    if total > limit {
                        let head =
                            futures_util::stream::iter(read.into_iter().map(Ok::<_, axum::Error>));
                        return Err(Body::from_stream(head.chain(body.into_data_stream())));
                    }
                }
            }
            Some(Err(e)) => {
                let head = futures_util::stream::iter(read.into_iter().map(Ok::<_, axum::Error>));
                let fail = futures_util::stream::once(async move { Err::<Bytes, _>(e) });
                return Err(Body::from_stream(head.chain(fail)));
            }
        }
    }
}

#[cfg(test)]
mod miss_tests {
    use super::*;

    fn cache() -> ResponseCache {
        ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            max_body_size_bytes: 1024 * 1024,
            ..Default::default()
        })
    }

    fn plan() -> CachePlan {
        CachePlan {
            key: ResponseCache::build_key("GET", "pqcrypta.com", "/r"),
            credentialed: false,
            lookup: true,
        }
    }

    /// A response of `chunks` chunks of 64 KiB, as a stream, under `headers`,
    /// through `store_or_stream`; the length that came out.
    async fn body_len(
        c: &ResponseCache,
        chunks: usize,
        headers: &[(&'static str, &'static str)],
    ) -> usize {
        let stream = futures_util::stream::iter(
            (0..chunks).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![7u8; 64 * 1024]))),
        );
        let mut resp = Response::new(Body::from_stream(stream));
        for (k, v) in headers {
            resp.headers_mut().insert(*k, HeaderValue::from_static(v));
        }
        let (parts, body) = resp.into_parts();
        let resp = c.store_or_stream(&plan(), None, parts, body).await;
        assert_eq!(resp.headers().get("x-cache").unwrap(), "MISS");
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .len()
    }

    #[tokio::test]
    async fn a_body_longer_than_the_cache_keeps_arrives_whole_and_is_not_stored() {
        let c = cache();
        // 4 MiB, no Content-Length, cacheable headers: read past the limit.
        let len = body_len(&c, 64, &[("cache-control", "max-age=60")]).await;
        assert_eq!(len, 64 * 64 * 1024, "every byte reaches the client");
        assert_eq!(c.stats().0, 0, "nothing stored");
    }

    #[tokio::test]
    async fn a_no_store_body_streams_through() {
        let c = cache();
        let len = body_len(&c, 64, &[("cache-control", "no-store, no-cache")]).await;
        assert_eq!(len, 64 * 64 * 1024);
        assert_eq!(c.stats().0, 0);
    }

    #[tokio::test]
    async fn a_short_cacheable_body_is_stored_and_returned() {
        let c = cache();
        let len = body_len(&c, 4, &[("cache-control", "max-age=60")]).await;
        assert_eq!(len, 4 * 64 * 1024);
        assert_eq!(c.stats().0, 1, "stored");
    }

    #[tokio::test]
    async fn a_header_of_this_one_response_is_not_stored() {
        let c = cache();
        let name = HeaderName::from_static("x-request-id");
        let mut resp = Response::new(Body::from("body"));
        resp.headers_mut()
            .insert("cache-control", HeaderValue::from_static("max-age=60"));
        resp.headers_mut()
            .insert(name.clone(), HeaderValue::from_static("first"));
        let (parts, body) = resp.into_parts();
        let sent = c.store_or_stream(&plan(), Some(&name), parts, body).await;
        assert_eq!(sent.headers().get(&name).unwrap(), "first");
        let CacheLookup::Hit { headers, .. } = c.get(&plan().key, None, None) else {
            panic!("stored");
        };
        assert!(headers
            .iter()
            .all(|(k, _)| k != "x-request-id" && k != "x-cache"));
    }

    #[test]
    fn refusals_are_read_from_the_headers() {
        let mut h = axum::http::HeaderMap::new();
        assert!(may_store(&h, 1024));
        h.insert("content-length", HeaderValue::from_static("4096"));
        assert!(!may_store(&h, 1024), "longer than the cache keeps");
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            "cache-control",
            HeaderValue::from_static("private, max-age=60"),
        );
        assert!(!may_store(&h, 1024));
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;

    fn cache(max_size_mb: usize) -> ResponseCache {
        ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            max_size_mb,
            ..Default::default()
        })
    }

    fn fresh() -> Vec<(String, String)> {
        vec![("cache-control".to_string(), "max-age=60".to_string())]
    }

    fn key(n: usize) -> String {
        ResponseCache::build_key("GET", "pqcrypta.com", &format!("/page-{n}"))
    }

    /// Any number of distinct URLs leaves the cache within its size, with
    /// every byte of every entry counted.
    #[test]
    fn distinct_urls_never_take_the_cache_past_its_size() {
        let c = cache(1);
        for n in 0..20_000 {
            c.put(&key(n), 200, &fresh(), Bytes::from_static(b"tiny"));
        }
        let (entries, bytes) = c.stats();
        assert!(bytes <= 1024 * 1024, "{bytes} bytes held");
        assert!(entries <= 1024 * 1024 / ENTRY_OVERHEAD, "{entries} entries");
        assert!(entries > 0);
        let queues = c.queues.lock();
        assert_eq!(queues.small_bytes + queues.main_bytes, bytes);
        assert!(queues.small.len() + queues.main.len() <= entries + 1);
    }

    /// An entry in use outlives a run of URLs each asked for once.
    #[test]
    fn an_entry_in_use_survives_urls_requested_once() {
        let c = cache(1);
        let wanted = ResponseCache::build_key("GET", "pqcrypta.com", "/wanted");
        c.put(&wanted, 200, &fresh(), Bytes::from(vec![1u8; 2048]));
        for _ in 0..3 {
            assert!(matches!(
                c.get(&wanted, None, None),
                CacheLookup::Hit { .. }
            ));
        }
        for n in 0..20_000 {
            c.put(&key(n), 200, &fresh(), Bytes::from_static(b"tiny"));
            if n % 500 == 0 {
                assert!(
                    matches!(c.get(&wanted, None, None), CacheLookup::Hit { .. }),
                    "evicted after {n} one-off entries"
                );
            }
        }
    }

    #[test]
    fn replacing_an_entry_counts_it_once() {
        let c = cache(1);
        c.put(&key(1), 200, &fresh(), Bytes::from(vec![0u8; 1000]));
        let first = c.stats().1;
        c.put(&key(1), 200, &fresh(), Bytes::from(vec![0u8; 3000]));
        assert_eq!(c.stats(), (1, first + 2000));
        c.purge_all();
        assert_eq!(c.stats(), (0, 0));
    }

    #[test]
    fn expired_entries_are_swept_with_their_queue_slots() {
        let c = cache(1);
        // Expires a second from now: the shortest stated lifetime there is
        let soon = (chrono::Utc::now() + chrono::Duration::seconds(2)).to_rfc2822();
        for n in 0..50 {
            c.put(
                &key(n),
                200,
                &[("expires".to_string(), soon.clone())],
                Bytes::from_static(b"x"),
            );
        }
        c.put(&key(999), 200, &fresh(), Bytes::from_static(b"x"));
        assert_eq!(c.stats().0, 51);
        std::thread::sleep(Duration::from_millis(2100));
        c.evict_expired();
        assert_eq!(c.stats().0, 1);
        let queues = c.queues.lock();
        assert_eq!(queues.small.len() + queues.main.len(), 1);
    }
}

#[cfg(test)]
mod freshness_tests {
    use super::*;

    fn cache() -> ResponseCache {
        ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        })
    }

    fn stored(headers: &[(&str, &str)], status: u16, credentialed: bool) -> bool {
        let c = cache();
        let key = ResponseCache::build_key("GET", "pqcrypta.com", "/thing");
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        c.put_for(
            &key,
            credentialed,
            status,
            &headers,
            Bytes::from_static(b"body"),
        );
        c.stats().0 > 0
    }

    #[test]
    fn a_lifetime_of_zero_is_not_kept() {
        assert!(!stored(&[("cache-control", "max-age=0")], 200, false));
        assert!(!stored(
            &[("cache-control", "max-age=60, s-maxage=0")],
            200,
            false
        ));
        assert!(stored(
            &[("cache-control", "max-age=0, s-maxage=60")],
            200,
            false
        ));
    }

    #[test]
    fn expires_is_read_when_cache_control_states_no_lifetime() {
        let past = "Thu, 19 Nov 1981 08:52:00 GMT";
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc2822();
        assert!(!stored(&[("expires", past)], 200, false));
        assert!(!stored(&[("expires", "0")], 200, false));
        assert!(stored(&[("expires", &future)], 200, false));
        // max-age wins over Expires
        assert!(stored(
            &[("cache-control", "max-age=60"), ("expires", past)],
            200,
            false
        ));
        assert!(!stored(&[("pragma", "no-cache")], 200, false));
    }

    #[test]
    fn a_request_with_a_cookie_keeps_only_what_the_origin_called_cacheable() {
        assert!(stored(&[], 200, false), "the default lifetime, no cookie");
        assert!(!stored(&[], 200, true), "nothing stated, a cookie");
        assert!(stored(&[("cache-control", "max-age=60")], 200, true));
        assert!(stored(&[("cache-control", "public")], 200, true));
    }

    #[test]
    fn an_entry_on_the_default_lifetime_is_not_served_to_a_request_with_a_cookie() {
        let c = cache();
        let key = ResponseCache::build_key("GET", "pqcrypta.com", "/thing");
        c.put(&key, 200, &[], Bytes::from_static(b"body"));
        assert!(matches!(
            c.get_for(&key, false, None, None),
            CacheLookup::Hit { .. }
        ));
        assert!(matches!(
            c.get_for(&key, true, None, None),
            CacheLookup::Miss
        ));
    }

    #[test]
    fn if_modified_since_compares_dates() {
        let c = cache();
        let key = ResponseCache::build_key("GET", "pqcrypta.com", "/thing");
        c.put(
            &key,
            200,
            &[
                ("cache-control".to_string(), "max-age=60".to_string()),
                (
                    "last-modified".to_string(),
                    "Mon, 09 Nov 2026 10:00:00 GMT".to_string(),
                ),
            ],
            Bytes::from_static(b"body"),
        );
        // Earlier than the change, though "Wed" sorts after "Mon" as text
        assert!(matches!(
            c.get(&key, None, Some("Wed, 01 Jan 2020 00:00:00 GMT")),
            CacheLookup::Hit { .. }
        ));
        assert!(matches!(
            c.get(&key, None, Some("Mon, 09 Nov 2026 10:00:00 GMT")),
            CacheLookup::NotModified { .. }
        ));
        assert!(matches!(
            c.get(&key, None, Some("Tue, 10 Nov 2026 00:00:00 GMT")),
            CacheLookup::NotModified { .. }
        ));
        assert!(matches!(
            c.get(&key, None, Some("not a date")),
            CacheLookup::Hit { .. }
        ));
    }

    #[test]
    fn if_none_match_reads_a_list() {
        let c = cache();
        let key = ResponseCache::build_key("GET", "pqcrypta.com", "/thing");
        c.put(
            &key,
            200,
            &[
                ("cache-control".to_string(), "max-age=60".to_string()),
                ("etag".to_string(), "\"v2\"".to_string()),
            ],
            Bytes::from_static(b"body"),
        );
        assert!(matches!(
            c.get(&key, Some("\"v1\", W/\"v2\""), None),
            CacheLookup::NotModified { .. }
        ));
        assert!(matches!(
            c.get(&key, Some("\"v1\""), None),
            CacheLookup::Hit { .. }
        ));
    }

    #[test]
    fn the_plan_follows_the_request() {
        let c = ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            excluded_paths: vec!["/auth".to_string()],
            excluded_hosts: vec!["api.pqcrypta.com".to_string()],
            ..Default::default()
        });
        let h = |pairs: &[(&'static str, &'static str)]| {
            let mut map = HeaderMap::new();
            for (k, v) in pairs {
                map.insert(*k, HeaderValue::from_static(v));
            }
            map
        };
        let plan = |method: Method, headers: &HeaderMap, host: &str, path: &str| {
            c.plan(&method, headers, host, path, None)
        };
        let get = plan(Method::GET, &h(&[]), "pqcrypta.com", "/page").expect("cacheable");
        assert!(get.lookup && !get.credentialed);
        // A HEAD is answered from the GET's entry
        let head = plan(Method::HEAD, &h(&[]), "pqcrypta.com", "/page").expect("cacheable");
        assert_eq!(head.key, get.key);
        assert!(plan(Method::POST, &h(&[]), "pqcrypta.com", "/page").is_none());
        assert!(plan(Method::GET, &h(&[]), "pqcrypta.com", "/auth/login").is_none());
        assert!(plan(Method::GET, &h(&[]), "api.pqcrypta.com", "/page").is_none());
        for refused in [
            [("authorization", "Bearer x")],
            [("range", "bytes=0-1")],
            [("cache-control", "no-store")],
        ] {
            assert!(plan(Method::GET, &h(&refused), "pqcrypta.com", "/page").is_none());
        }
        let cookie = plan(
            Method::GET,
            &h(&[("cookie", "a=b")]),
            "pqcrypta.com",
            "/page",
        );
        assert!(cookie.expect("cacheable").credentialed);
        for fresh in [
            [("cache-control", "no-cache")],
            [("cache-control", "max-age=0")],
            [("pragma", "no-cache")],
        ] {
            let p = plan(Method::GET, &h(&fresh), "pqcrypta.com", "/page").expect("cacheable");
            assert!(!p.lookup, "{fresh:?} asks for the origin's answer");
        }
        // The query is part of the key
        let with_query = c
            .plan(&Method::GET, &h(&[]), "pqcrypta.com", "/page", Some("a=1"))
            .expect("cacheable");
        assert_ne!(with_query.key, get.key);
    }
}

#[cfg(test)]
mod vary_tests {
    use super::*;

    fn cache() -> ResponseCache {
        ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        })
    }

    /// Store one response carrying `vary`, and report whether it was kept.
    fn cached_with_vary(vary: &str) -> bool {
        let c = cache();
        let key = ResponseCache::build_key("GET", "pqcrypta.com", "/thing");
        let mut headers = vec![("cache-control".to_string(), "max-age=60".to_string())];
        if !vary.is_empty() {
            headers.push(("vary".to_string(), vary.to_string()));
        }
        c.put(&key, 200, &headers, Bytes::from_static(b"body"));
        c.stats().0 > 0
    }

    #[test]
    fn a_response_that_varies_on_nothing_is_cached() {
        assert!(cached_with_vary(""), "the ordinary case must still cache");
    }

    #[test]
    fn accept_encoding_is_the_one_safe_variance() {
        // This cache sits inside the compression layer and stores only identity
        // bodies, so one entry is correct for every client whatever encoding
        // they asked for. Refusing these would give up most of the cache for no
        // safety gain.
        assert!(cached_with_vary("Accept-Encoding"));
        assert!(cached_with_vary("accept-encoding"));
    }

    #[test]
    fn varying_on_a_user_identifying_header_is_never_cached() {
        // The failure this prevents is one user's personalised response being
        // handed to another, which is a leak rather than a staleness bug — the
        // key is METHOD|host|path and cannot tell the two requests apart.
        assert!(!cached_with_vary("Cookie"));
        assert!(!cached_with_vary("Authorization"));
    }

    #[test]
    fn varying_on_origin_is_never_cached() {
        // Routes reflecting an origin from an allowlist emit `Vary: Origin`.
        // Caching one would return an `Access-Control-Allow-Origin` naming one
        // origin to a request from another.
        assert!(!cached_with_vary("Origin"));
    }

    #[test]
    fn varying_on_a_content_negotiation_header_is_never_cached() {
        assert!(!cached_with_vary("Accept-Language"));
        assert!(!cached_with_vary("Accept"));
        assert!(!cached_with_vary("User-Agent"));
    }

    #[test]
    fn vary_star_is_never_cached() {
        assert!(!cached_with_vary("*"));
    }

    #[test]
    fn a_list_is_refused_when_any_member_is_unsupported() {
        // The safe member must not excuse the unsafe one.
        assert!(!cached_with_vary("Accept-Encoding, Cookie"));
        assert!(!cached_with_vary("Cookie, Accept-Encoding"));
        assert!(cached_with_vary("Accept-Encoding, accept-encoding"));
    }

    #[test]
    fn whitespace_and_case_do_not_smuggle_a_header_past_the_check() {
        assert!(!cached_with_vary("  cOoKiE  "));
        assert!(cached_with_vary("  Accept-Encoding  "));
    }
}

#[cfg(test)]
mod purge_tests {

    /// The first GET to miss fetches; an identical one waits for it and is
    /// answered from what it stored, and goes on alone when nothing was.
    #[tokio::test]
    async fn identical_misses_wait_for_one_fetch() {
        let cache = Arc::new(ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            ..ResponseCacheConfig::default()
        }));
        let http3 = crate::config::Http3Config {
            coalescing_max_wait_ms: 2_000,
            ..crate::config::Http3Config::default()
        };
        cache.configure_collapse(&http3);
        let headers = HeaderMap::new();
        let plan = cache
            .plan(&Method::GET, &headers, "example.com", "/page", None)
            .expect("a cacheable GET");

        let (first, leading) = cache.lookup(&plan, &Method::GET, "/page", None, None).await;
        assert!(matches!(first, CacheLookup::Miss));
        let leading = leading.expect("the first miss leads");

        let follower = {
            let cache = Arc::clone(&cache);
            let plan = plan.clone();
            tokio::spawn(
                async move { cache.lookup(&plan, &Method::GET, "/page", None, None).await },
            )
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!follower.is_finished(), "it waits for the fetch");
        cache.put_for(
            &plan.key,
            false,
            200,
            &[("cache-control".to_string(), "max-age=60".to_string())],
            Bytes::from_static(b"page"),
        );
        drop(leading);
        let (found, led) = follower.await.unwrap();
        assert!(matches!(found, CacheLookup::Hit { .. }));
        assert!(led.is_none());

        // Nothing stored: the waiting request goes on by itself, unled
        let other = cache
            .plan(&Method::GET, &headers, "example.com", "/private", None)
            .unwrap();
        let (_, leading) = cache
            .lookup(&other, &Method::GET, "/private", None, None)
            .await;
        let waiting = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move {
                cache
                    .lookup(&other, &Method::GET, "/private", None, None)
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(leading);
        let (found, led) = waiting.await.unwrap();
        assert!(matches!(found, CacheLookup::Miss));
        assert!(led.is_none());
    }

    use super::*;

    fn cache() -> ResponseCache {
        ResponseCache::new(ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        })
    }

    /// Seed one entry, going through `build_key` so the tests exercise the same
    /// key shape the purge selectors parse.
    fn seed(c: &ResponseCache, method: &str, host: &str, path: &str) {
        c.put(
            &ResponseCache::build_key(method, host, path),
            200,
            &[("cache-control".to_string(), "max-age=60".to_string())],
            Bytes::from_static(b"body"),
        );
    }

    fn seed_a_few(c: &ResponseCache) {
        seed(c, "GET", "pqcrypta.com", "/robots.txt");
        seed(c, "GET", "pqcrypta.com", "/sitemaps/sitemap.xml");
        seed(c, "GET", "pqcrypta.com", "/sitemaps/sitemap-ja4.xml");
        seed(c, "HEAD", "pqcrypta.com", "/robots.txt");
        seed(c, "GET", "pqpdf.com", "/robots.txt");
        seed(c, "GET", "pqpdf.com", "/sitemaps/sitemap.xml");
    }

    #[test]
    fn purging_everything_empties_the_store_and_the_byte_count() {
        let c = cache();
        seed_a_few(&c);
        let (before, bytes) = c.stats();
        assert_eq!(before, 6);
        assert!(bytes > 0);

        assert_eq!(c.purge_all(), 6);
        assert_eq!(c.stats(), (0, 0), "byte accounting must reset too");
    }

    #[test]
    fn purging_a_host_leaves_the_others_warm() {
        let c = cache();
        seed_a_few(&c);
        // Three entries for pqcrypta.com across two methods.
        assert_eq!(c.purge_host("pqcrypta.com"), 4);
        assert_eq!(c.stats().0, 2, "pqpdf.com must be untouched");
    }

    #[test]
    fn a_host_purge_is_case_insensitive() {
        // build_key lowercases the host, so an operator typing it differently
        // would otherwise purge nothing and be told "0 entries" for a host that
        // is plainly cached.
        let c = cache();
        seed_a_few(&c);
        assert_eq!(c.purge_host("PQCrypta.COM"), 4);
    }

    #[test]
    fn a_prefix_purge_crosses_hosts_but_respects_the_path() {
        let c = cache();
        seed_a_few(&c);
        // Two sitemaps on pqcrypta.com, one on pqpdf.com.
        assert_eq!(c.purge_prefix("/sitemaps/"), 3);
        let (left, _) = c.stats();
        assert_eq!(left, 3, "only the robots.txt entries remain");
    }

    #[test]
    fn a_host_prefix_purge_takes_that_path_on_that_host_only() {
        let c = cache();
        seed_a_few(&c);
        // pqcrypta.com's two sitemaps; pqpdf.com's sitemap and every
        // robots.txt stay cached.
        assert_eq!(c.purge_host_prefix("PQCrypta.com", "/sitemaps/"), 2);
        assert_eq!(c.stats().0, 4);
        assert_eq!(c.purge_url("pqpdf.com", "/sitemaps/sitemap.xml"), 1);
    }

    #[test]
    fn a_host_prefix_purge_does_not_take_a_host_that_ends_the_same() {
        let c = cache();
        seed(&c, "GET", "pqcrypta.com", "/entropy/");
        seed(&c, "GET", "api.pqcrypta.com", "/entropy/generate");
        assert_eq!(c.purge_host_prefix("pqcrypta.com", "/entropy/"), 1);
        assert_eq!(c.stats().0, 1, "api.pqcrypta.com is another host");
    }

    #[test]
    fn a_url_purge_takes_every_method_for_that_one_path() {
        let c = cache();
        seed_a_few(&c);
        // GET and HEAD are separate keys; purging the URL must take both, or
        // the operator fixes the page and the HEAD probe still sees the old one.
        assert_eq!(c.purge_url("pqcrypta.com", "/robots.txt"), 2);
        assert_eq!(c.stats().0, 4);
    }

    #[test]
    fn a_url_purge_does_not_match_a_longer_path() {
        let c = cache();
        seed(&c, "GET", "pqcrypta.com", "/sitemaps/sitemap.xml");
        seed(&c, "GET", "pqcrypta.com", "/sitemaps/sitemap-ja4.xml");
        // Suffix matching must not let /sitemap.xml also claim
        // /sitemap-ja4.xml, nor the reverse.
        assert_eq!(c.purge_url("pqcrypta.com", "/sitemaps/sitemap.xml"), 1);
        assert_eq!(c.stats().0, 1);
    }

    #[test]
    fn purging_something_absent_removes_nothing_and_says_so() {
        let c = cache();
        seed_a_few(&c);
        assert_eq!(c.purge_host("example.com"), 0);
        assert_eq!(c.purge_url("pqcrypta.com", "/nope"), 0);
        assert_eq!(c.purge_prefix("/nope/"), 0);
        assert_eq!(c.stats().0, 6, "a miss must not disturb the cache");
    }

    #[test]
    fn the_shared_cache_is_one_instance() {
        // The whole point: five listeners previously held five caches, so a
        // purge cleared one and the rest kept serving the old body.
        let cfg = ResponseCacheConfig {
            enabled: true,
            ..Default::default()
        };
        let a = shared(&cfg);
        let b = shared(&cfg);
        assert!(Arc::ptr_eq(&a, &b));

        seed(&a, "GET", "pqcrypta.com", "/robots.txt");
        assert_eq!(
            b.stats().0,
            1,
            "a write through one handle is visible in the other"
        );
        a.purge_all();
        assert_eq!(b.stats().0, 0);
    }
}
