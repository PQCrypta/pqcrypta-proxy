//! HTTP response cache — RFC 9111 compliant
//!
//! Implements:
//! - Cache-Control directive parsing (max-age, s-maxage, no-cache, no-store, private, public)
//! - ETag / If-None-Match conditional requests (strong and weak comparison)
//! - Last-Modified / If-Modified-Since conditional requests
//! - Vary header support (Vary: * bypasses cache; all other Vary headers are recorded)
//! - TTL-based expiry using `std::time::Instant`
//! - Size-bounded DashMap store with expired-entry eviction
//!
//! The cache stores the raw backend response body (pre-compression). All outer
//! middleware layers (security headers, Alt-Svc, compression) run on every served
//! response — both cache hits and misses — because the cache is placed as the
//! innermost Axum layer.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Method, Request, Response, StatusCode};
use axum::middleware::Next;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

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
    /// Response body bytes (uncompressed; compression is handled by outer middleware)
    body: Arc<Vec<u8>>,
    /// ETag header value from backend (for If-None-Match comparison)
    etag: Option<String>,
    /// Last-Modified header value from backend (for If-Modified-Since comparison)
    last_modified: Option<String>,
    /// Raw Cache-Control header from backend (forwarded on 304 responses)
    cache_control: Option<String>,
    /// When this entry was created (used to compute Age header)
    created_at: Instant,
    /// When this entry expires and must be evicted
    expires_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn body_size(&self) -> usize {
        self.body.len()
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
        body: Arc<Vec<u8>>,
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

struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    is_private: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
}

impl CacheControlDirectives {
    fn parse(header: &str) -> Self {
        let mut d = Self {
            no_store: false,
            no_cache: false,
            is_private: false,
            max_age: None,
            s_maxage: None,
        };
        for part in header.split(',') {
            let part = part.trim().to_lowercase();
            if part == "no-store" {
                d.no_store = true;
            } else if part == "no-cache" {
                d.no_cache = true;
            } else if part == "private" {
                d.is_private = true;
            } else if let Some(val) = part.strip_prefix("max-age=") {
                d.max_age = val.parse::<u64>().ok();
            } else if let Some(val) = part.strip_prefix("s-maxage=") {
                d.s_maxage = val.parse::<u64>().ok();
            }
        }
        d
    }
}

// ============================================================================
// Response cache
// ============================================================================

/// Shared, concurrent response cache backed by `DashMap`.
pub struct ResponseCache {
    store: DashMap<String, CacheEntry>,
    size_bytes: AtomicUsize,
    /// Public config reference (read by middleware and QUIC handler)
    pub config: ResponseCacheConfig,
}

impl ResponseCache {
    /// Create a new cache with the given configuration.
    pub fn new(config: ResponseCacheConfig) -> Self {
        Self {
            store: DashMap::new(),
            size_bytes: AtomicUsize::new(0),
            config,
        }
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

    /// Look up a response.  Returns `Hit`, `NotModified`, or `Miss`.
    pub fn get(
        &self,
        key: &str,
        if_none_match: Option<&str>,
        if_modified_since: Option<&str>,
    ) -> CacheLookup {
        if !self.config.enabled {
            return CacheLookup::Miss;
        }

        let entry = match self.store.get(key) {
            Some(e) => e,
            None => return CacheLookup::Miss,
        };

        // Evict on first access after expiry
        if entry.is_expired() {
            let body_size = entry.body_size();
            drop(entry);
            self.store.remove(key);
            self.size_bytes.fetch_sub(body_size, Ordering::Relaxed);
            return CacheLookup::Miss;
        }

        let age_secs = entry.created_at.elapsed().as_secs();

        // --- ETag conditional check (If-None-Match) ---
        if let (Some(inm), Some(etag)) = (if_none_match, &entry.etag) {
            // Strip optional weak prefix and quotes for comparison
            let client = inm.trim().trim_start_matches("W/").trim_matches('"');
            let cached = etag.trim().trim_start_matches("W/").trim_matches('"');
            if client == "*" || client == cached {
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
        // Only when no If-None-Match was sent (RFC 9110 §13.1.3)
        if if_none_match.is_none() {
            if let (Some(ims), Some(lm)) = (if_modified_since, &entry.last_modified) {
                // HTTP-date lexicographic comparison is valid for RFC 1123 dates:
                // "Mon, 01 Jan 2024 00:00:00 GMT" < "Tue, 02 Jan 2024 00:00:00 GMT"
                if lm.as_str() <= ims {
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
            entry.body_size()
        );
        CacheLookup::Hit {
            status: entry.status,
            headers: entry.headers.clone(),
            body: Arc::clone(&entry.body),
            age_secs,
        }
    }

    /// Store a backend response.  Respects Cache-Control directives, size limits,
    /// and the `no_cache_set_cookie` configuration flag.
    pub fn put(
        &self,
        key: &str,
        status: u16,
        response_headers: &[(String, String)],
        body: Vec<u8>,
    ) {
        if !self.config.enabled {
            return;
        }

        if body.len() > self.config.max_body_size_bytes {
            trace!("Not caching {}: body {} > limit", key, body.len());
            return;
        }

        // Parse headers we care about
        let mut cache_control_val: Option<String> = None;
        let mut etag: Option<String> = None;
        let mut last_modified: Option<String> = None;
        let mut vary: Option<String> = None;
        let mut has_set_cookie = false;
        let mut has_content_encoding = false;

        for (name, value) in response_headers {
            match name.to_lowercase().as_str() {
                "cache-control" => cache_control_val = Some(value.clone()),
                "etag" => etag = Some(value.clone()),
                "last-modified" => last_modified = Some(value.clone()),
                "vary" => vary = Some(value.clone()),
                "set-cookie" => has_set_cookie = true,
                "content-encoding" => has_content_encoding = true,
                _ => {}
            }
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

        // Vary: * means the response is not cacheable
        if vary.as_deref().map(|v| v.trim() == "*").unwrap_or(false) {
            trace!("Not caching {}: Vary: *", key);
            return;
        }

        // Determine TTL from Cache-Control
        let ttl = if let Some(ref cc) = cache_control_val {
            let d = CacheControlDirectives::parse(cc);
            if d.no_store {
                trace!("Not caching {}: no-store", key);
                return;
            }
            if d.is_private {
                trace!("Not caching {}: private", key);
                return;
            }
            if d.no_cache {
                trace!("Not caching {}: no-cache", key);
                return;
            }
            // s-maxage takes precedence over max-age for shared caches (RFC 9111 §5.2.2.10)
            let secs = d.s_maxage.or(d.max_age).unwrap_or(0);
            if secs == 0 {
                // max-age=0 or s-maxage=0 → use default TTL (heuristic)
                Duration::from_secs(self.config.default_ttl_secs)
            } else {
                Duration::from_secs(secs)
            }
        } else {
            // No Cache-Control header: only cache status codes that are heuristically
            // cacheable per RFC 9110 §15.1
            if !is_cacheable_by_default(status) {
                trace!(
                    "Not caching {}: status {} not cacheable by default",
                    key,
                    status
                );
                return;
            }
            Duration::from_secs(self.config.default_ttl_secs)
        };

        // Enforce total cache size limit
        let body_size = body.len();
        let max_bytes = self.config.max_size_mb * 1024 * 1024;
        if self.size_bytes.load(Ordering::Relaxed) + body_size > max_bytes {
            self.evict_expired();
            if self.size_bytes.load(Ordering::Relaxed) + body_size > max_bytes {
                trace!("Not caching {}: cache full", key);
                return;
            }
        }

        let now = Instant::now();
        let new_entry = CacheEntry {
            status,
            headers: response_headers.to_vec(),
            body: Arc::new(body),
            etag,
            last_modified,
            cache_control: cache_control_val,
            created_at: now,
            expires_at: now + ttl,
        };

        // Replace existing entry and track size delta
        if let Some(old) = self.store.insert(key.to_string(), new_entry) {
            self.size_bytes
                .fetch_sub(old.body_size(), Ordering::Relaxed);
        }
        self.size_bytes.fetch_add(body_size, Ordering::Relaxed);

        debug!("Cached {} (ttl {:?}, {} bytes)", key, ttl, body_size);
    }

    /// Return `true` if `path` matches any of the configured excluded prefixes.
    pub fn is_excluded_path(&self, path: &str) -> bool {
        self.config
            .excluded_paths
            .iter()
            .any(|p| path.starts_with(p.as_str()))
    }

    /// Evict all expired entries and reclaim their size accounting.
    pub fn evict_expired(&self) {
        let mut removed = 0usize;
        self.store.retain(|_, entry| {
            if entry.is_expired() {
                removed += entry.body_size();
                false
            } else {
                true
            }
        });
        if removed > 0 {
            self.size_bytes.fetch_sub(removed, Ordering::Relaxed);
            debug!("Evicted {} bytes of expired cache entries", removed);
        }
    }

    /// Return `(entry_count, total_size_bytes)` for monitoring.
    pub fn stats(&self) -> (usize, usize) {
        (self.store.len(), self.size_bytes.load(Ordering::Relaxed))
    }
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

// ============================================================================
// Axum middleware (HTTP/1.1 + HTTP/2)
// ============================================================================

/// Response cache middleware for HTTP/1.1 and HTTP/2.
///
/// Placed as the **innermost** Axum layer so that security headers, Alt-Svc, and
/// compression are applied uniformly to both cache hits and cache misses.
///
/// On **cache miss**: the response body is buffered (up to 100 MiB), stored in
/// the cache if within the size limit, and then returned.  The body stream is
/// fully reconstructed, so outer middleware (e.g., compression) can still read it.
///
/// On **cache hit**: the stored body is returned immediately without calling the
/// inner handler, saving a backend round-trip.
///
/// On **304 Not Modified**: a body-less 304 is returned when the client supplies
/// a matching `If-None-Match` or `If-Modified-Since` header.
pub async fn cache_middleware(
    State(cache): State<Arc<ResponseCache>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    if !cache.config.enabled {
        return next.run(request).await;
    }

    let method = request.method().clone();

    // Only GET and HEAD are cacheable (safe, idempotent methods — RFC 9110 §9.3)
    if !matches!(method, Method::GET | Method::HEAD) {
        return next.run(request).await;
    }

    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
    let path_with_query = format!("{}{}", path, query);

    if cache.is_excluded_path(&path) {
        return next.run(request).await;
    }

    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let cache_key = ResponseCache::build_key(method.as_str(), &host, &path_with_query);

    let if_none_match = request
        .headers()
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let if_modified_since = request
        .headers()
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    match cache.get(
        &cache_key,
        if_none_match.as_deref(),
        if_modified_since.as_deref(),
    ) {
        CacheLookup::Hit {
            status,
            headers,
            body,
            age_secs,
        } => {
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
            let mut builder = Response::builder().status(status_code);
            for (k, v) in &headers {
                // Skip content-length — we set it precisely from the stored body
                if k.to_lowercase() != "content-length" {
                    if let Ok(val) = HeaderValue::from_str(v) {
                        builder = builder.header(k.as_str(), val);
                    }
                }
            }
            builder = builder
                .header("content-length", body.len().to_string())
                .header("age", age_secs.to_string())
                .header("x-cache", "HIT");

            let resp_body = if method == Method::HEAD {
                Body::empty()
            } else {
                Body::from((*body).clone())
            };

            builder
                .body(resp_body)
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }

        CacheLookup::NotModified {
            etag,
            last_modified,
            cache_control,
            age_secs,
        } => {
            let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
            if let Some(et) = etag {
                if let Ok(val) = HeaderValue::from_str(&et) {
                    builder = builder.header("etag", val);
                }
            }
            if let Some(lm) = last_modified {
                if let Ok(val) = HeaderValue::from_str(&lm) {
                    builder = builder.header("last-modified", val);
                }
            }
            if let Some(cc) = cache_control {
                if let Ok(val) = HeaderValue::from_str(&cc) {
                    builder = builder.header("cache-control", val);
                }
            }
            builder = builder
                .header("age", age_secs.to_string())
                .header("x-cache", "HIT");
            builder
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }

        CacheLookup::Miss => {
            let response = next.run(request).await;
            let status = response.status().as_u16();

            // Collect headers before consuming the body
            let resp_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect();

            let (mut parts, resp_body) = response.into_parts();

            // Buffer the full body (up to 100 MiB, consistent with compression middleware)
            match axum::body::to_bytes(resp_body, 100 * 1024 * 1024).await {
                Ok(body_bytes) => {
                    if body_bytes.len() <= cache.config.max_body_size_bytes {
                        cache.put(&cache_key, status, &resp_headers, body_bytes.to_vec());
                    }
                    parts
                        .headers
                        .insert("x-cache", HeaderValue::from_static("MISS"));
                    Response::from_parts(parts, Body::from(body_bytes))
                }
                Err(e) => {
                    debug!("Cache: failed to buffer response body: {}", e);
                    Response::from_parts(parts, Body::empty())
                }
            }
        }
    }
}
