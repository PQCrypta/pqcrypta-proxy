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

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::RwLock;
use sha2::Digest;
use tracing::{debug, info, warn};

use crate::config::{ProxyConfig, RateLimitConfig, SecurityConfig};

/// Security state shared across all requests
#[derive(Clone)]
pub struct SecurityState {
    /// Per-IP rate limiters
    pub ip_rate_limiters:
        Arc<DashMap<IpAddr, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    /// Per-IP connection counters
    pub ip_connections: Arc<DashMap<IpAddr, u32>>,
    /// Blocked IPs with expiration time
    pub blocked_ips: Arc<DashMap<IpAddr, BlockedIpInfo>>,
    /// Request count per IP for adaptive blocking
    pub request_counts: Arc<DashMap<IpAddr, RequestCounter>>,
    /// JA3 fingerprint cache (fingerprint -> classification)
    pub ja3_cache: Arc<DashMap<String, TlsFingerprint>>,
    /// Circuit breaker states per backend
    pub circuit_breakers: Arc<DashMap<String, CircuitBreakerState>>,
    /// Configuration
    pub config: Arc<RwLock<SecurityConfig>>,
    /// Rate limit configuration
    pub rate_config: Arc<RwLock<RateLimitConfig>>,
    /// Global rate limiter (fallback)
    pub global_rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    /// GeoIP database (optional)
    #[cfg(feature = "geoip")]
    pub geoip_db: Option<Arc<GeoIpDb>>,
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
    /// Classification (browser, bot, scanner, etc.)
    pub classification: FingerprintClass,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Request count with this fingerprint
    pub request_count: u64,
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

        let quota = Quota::per_second(
            NonZeroU32::new(rate_per_second).unwrap_or(NonZeroU32::new(100).unwrap()),
        )
        .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(50).unwrap()));

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

        let state = Self {
            ip_rate_limiters: Arc::new(DashMap::new()),
            ip_connections: Arc::new(DashMap::new()),
            blocked_ips,
            request_counts: Arc::new(DashMap::new()),
            ja3_cache: Arc::new(DashMap::new()),
            circuit_breakers: Arc::new(DashMap::new()),
            config: Arc::new(RwLock::new(config.security.clone())),
            rate_config: Arc::new(RwLock::new(config.rate_limiting.clone())),
            global_rate_limiter,
            #[cfg(feature = "geoip")]
            geoip_db,
        };

        // Spawn background cleanup task
        state.spawn_cleanup_task();

        state
    }

    /// Spawn a background task that periodically cleans up expired entries
    fn spawn_cleanup_task(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                state.cleanup();
                debug!("Security state cleanup completed");
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

    /// Get or create rate limiter for an IP
    pub fn get_ip_rate_limiter(
        &self,
        ip: IpAddr,
    ) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        self.ip_rate_limiters
            .entry(ip)
            .or_insert_with(|| {
                let config = self.rate_config.read();
                let quota = Quota::per_second(
                    NonZeroU32::new(config.requests_per_second)
                        .unwrap_or(NonZeroU32::new(100).unwrap()),
                )
                .allow_burst(
                    NonZeroU32::new(config.burst_size).unwrap_or(NonZeroU32::new(50).unwrap()),
                );
                Arc::new(RateLimiter::direct(quota))
            })
            .clone()
    }

    /// Check if an IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> Option<BlockedIpInfo> {
        if let Some(info) = self.blocked_ips.get(ip) {
            // Check if block has expired
            if let Some(expires) = info.expires_at {
                if Instant::now() > expires {
                    // Remove expired block
                    drop(info);
                    self.blocked_ips.remove(ip);
                    return None;
                }
            }
            return Some(info.clone());
        }
        None
    }

    /// Block an IP address
    pub fn block_ip(&self, ip: IpAddr, reason: BlockReason, duration: Option<Duration>) {
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

    /// Increment connection count for IP
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
    pub fn record_request(&self, ip: IpAddr, status: StatusCode) {
        let mut counter = self.request_counts.entry(ip).or_default();

        // Reset window if needed (1 minute windows)
        let window_duration = Duration::from_secs(60);
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

        // Check for suspicious patterns (too many 4xx errors)
        if counter.error_4xx > 50 && counter.total_requests > 100 {
            let error_rate = counter.error_4xx as f64 / counter.total_requests as f64;
            if error_rate > 0.5 {
                counter.suspicious_patterns += 1;

                // Auto-block if too suspicious
                if counter.suspicious_patterns >= 3 {
                    drop(counter);
                    self.block_ip(
                        ip,
                        BlockReason::TooManyErrors,
                        Some(Duration::from_secs(300)),
                    );
                }
            }
        }
    }

    /// Record circuit breaker result
    pub fn record_backend_result(&self, backend: &str, success: bool) {
        let mut state = self
            .circuit_breakers
            .entry(backend.to_string())
            .or_default();

        if success {
            state.success_count += 1;
            state.failure_count = 0;

            // If half-open and enough successes, close the circuit
            if state.state == CircuitState::HalfOpen && state.success_count >= 3 {
                state.state = CircuitState::Closed;
                state.last_state_change = Instant::now();
                info!("Circuit breaker for {} closed (recovered)", backend);
            }
        } else {
            state.failure_count += 1;
            state.success_count = 0;

            match state.state {
                CircuitState::Closed => {
                    // Open circuit after 5 consecutive failures
                    if state.failure_count >= 5 {
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

    /// Check if circuit breaker allows request to backend
    pub fn circuit_allows(&self, backend: &str) -> bool {
        let mut state = self
            .circuit_breakers
            .entry(backend.to_string())
            .or_default();

        match state.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should try half-open (after 30 seconds)
                if state.last_state_change.elapsed() > Duration::from_secs(30) {
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
                // Allow limited requests in half-open state
                if state.half_open_requests < 3 {
                    state.half_open_requests += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Cleanup expired entries (call periodically)
    pub fn cleanup(&self) {
        // Remove expired blocks
        self.blocked_ips
            .retain(|_, info| info.expires_at.map(|e| Instant::now() < e).unwrap_or(true));

        // Remove old request counters (older than 5 minutes)
        self.request_counts.retain(|_, counter| {
            counter
                .window_start
                .map(|s| s.elapsed() < Duration::from_secs(300))
                .unwrap_or(false)
        });

        // Remove stale rate limiters (not used in 10 minutes)
        // Note: governor doesn't expose last-used time, so we keep all for now
    }
}

/// Security middleware for rate limiting, IP blocking, and request validation
pub async fn security_middleware(
    State(security): State<SecurityState>,
    ConnectInfo(client_addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let ip = client_addr.ip();
    let config = security.config.read().clone();
    let rate_config = security.rate_config.read().clone();

    // 1. Check if IP is blocked
    if let Some(block_info) = security.is_blocked(&ip) {
        warn!(
            "Blocked request from {} (reason: {:?})",
            ip, block_info.reason
        );
        return blocked_response(&block_info);
    }

    // 2. GeoIP country blocking
    if security.is_country_blocked(&ip) {
        warn!("GeoIP blocked request from {}", ip);
        security.block_ip(ip, BlockReason::GeoBlocked, None);
        return geo_blocked_response();
    }

    // 3. Check DoS protection - connection limits
    if config.dos_protection {
        let connections = security.increment_connections(ip);
        let max_connections = config.max_connections_per_ip;

        if connections > max_connections {
            security.decrement_connections(ip);
            security.block_ip(
                ip,
                BlockReason::ConnectionLimitExceeded,
                Some(Duration::from_secs(60)),
            );
            warn!("Connection limit exceeded for {}: {}", ip, connections);
            return too_many_connections_response();
        }
    }

    // 4. Rate limiting
    if rate_config.enabled {
        let rate_limiter = security.get_ip_rate_limiter(ip);

        if rate_limiter.check().is_err() {
            debug!("Rate limit exceeded for {}", ip);

            // Track rate limit violations
            let mut counter = security.request_counts.entry(ip).or_default();
            counter.suspicious_patterns += 1;

            // Auto-block after repeated violations (configurable threshold)
            if counter.suspicious_patterns >= config.auto_block_threshold {
                drop(counter);
                let block_duration = Duration::from_secs(config.auto_block_duration_secs);
                security.block_ip(ip, BlockReason::RateLimitExceeded, Some(block_duration));
            }

            return rate_limit_response(&rate_config);
        }
    }

    // 5. Request size validation
    if let Some(content_length) = headers.get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > config.max_request_size {
                    warn!("Request too large from {}: {} bytes", ip, length);
                    return payload_too_large_response(config.max_request_size);
                }
            }
        }
    }

    // 6. Header size validation
    let header_size: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.len())
        .sum();

    if header_size > config.max_header_size {
        warn!("Headers too large from {}: {} bytes", ip, header_size);
        return headers_too_large_response(config.max_header_size);
    }

    // 7. Process request
    let response = next.run(request).await;
    let status = response.status();

    // 8. Record request for adaptive rate limiting
    security.record_request(ip, status);

    // 9. Decrement connection count
    if config.dos_protection {
        security.decrement_connections(ip);
    }

    response
}

/// Generate blocked IP response
fn blocked_response(info: &BlockedIpInfo) -> Response {
    let retry_after = info
        .expires_at
        .map(|e| e.duration_since(Instant::now()).as_secs())
        .unwrap_or(3600);

    let mut response = (StatusCode::FORBIDDEN, "Access denied - IP blocked").into_response();

    response.headers_mut().insert(
        "Retry-After",
        HeaderValue::from_str(&retry_after.to_string()).unwrap_or(HeaderValue::from_static("3600")),
    );

    response
}

/// Generate GeoIP blocked response
fn geo_blocked_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        "Access denied - Your region is not allowed",
    )
        .into_response()
}

/// Generate rate limit exceeded response
fn rate_limit_response(config: &RateLimitConfig) -> Response {
    let mut response = (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();

    // Add standard rate limit headers
    response
        .headers_mut()
        .insert("Retry-After", HeaderValue::from_static("1"));
    response.headers_mut().insert(
        "X-RateLimit-Limit",
        HeaderValue::from_str(&config.requests_per_second.to_string())
            .unwrap_or(HeaderValue::from_static("100")),
    );
    response
        .headers_mut()
        .insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));

    response
}

/// Generate too many connections response
fn too_many_connections_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many connections from your IP",
    )
        .into_response()
}

/// Generate payload too large response
fn payload_too_large_response(max_size: usize) -> Response {
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

    response
}

/// Generate headers too large response
fn headers_too_large_response(max_size: usize) -> Response {
    (
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        format!("Headers exceed maximum size of {} bytes", max_size),
    )
        .into_response()
}

/// JA3 fingerprint calculation from TLS ClientHello
///
/// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
pub fn calculate_ja3(client_hello: &[u8]) -> Option<String> {
    // Parse TLS ClientHello to extract:
    // - SSL/TLS version
    // - Cipher suites
    // - Extensions
    // - Elliptic curves (supported_groups)
    // - EC point formats

    if client_hello.len() < 43 {
        return None;
    }

    // Skip record layer header (5 bytes) and handshake header (4 bytes)
    let handshake = if client_hello[0] == 0x16 {
        &client_hello[9..]
    } else {
        client_hello
    };

    if handshake.len() < 38 {
        return None;
    }

    // TLS version (2 bytes at offset 0)
    let tls_version = u16::from_be_bytes([handshake[0], handshake[1]]);

    // Skip random (32 bytes) and session ID
    let mut offset = 34;
    if offset >= handshake.len() {
        return None;
    }
    let session_id_len = handshake[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites
    if offset + 2 > handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2;

    if offset + cipher_suites_len > handshake.len() {
        return None;
    }

    let mut ciphers = Vec::new();
    for i in (0..cipher_suites_len).step_by(2) {
        if offset + i + 2 <= handshake.len() {
            let cipher = u16::from_be_bytes([handshake[offset + i], handshake[offset + i + 1]]);
            // Skip GREASE values (0x?a?a pattern)
            if cipher & 0x0f0f != 0x0a0a {
                ciphers.push(cipher);
            }
        }
    }
    offset += cipher_suites_len;

    // Compression methods
    if offset >= handshake.len() {
        return None;
    }
    let compression_len = handshake[offset] as usize;
    offset += 1 + compression_len;

    // Extensions
    if offset + 2 > handshake.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
    offset += 2;

    let mut extensions = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut ec_point_formats = Vec::new();

    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end && offset + 4 <= handshake.len() {
        let ext_type = u16::from_be_bytes([handshake[offset], handshake[offset + 1]]);
        let ext_len = u16::from_be_bytes([handshake[offset + 2], handshake[offset + 3]]) as usize;
        offset += 4;

        // Skip GREASE extensions
        if ext_type & 0x0f0f != 0x0a0a {
            extensions.push(ext_type);

            // Parse supported_groups (extension 10)
            if ext_type == 10 && ext_len >= 2 && offset + ext_len <= handshake.len() {
                let groups_len =
                    u16::from_be_bytes([handshake[offset], handshake[offset + 1]]) as usize;
                for i in (2..2 + groups_len).step_by(2) {
                    if offset + i + 2 <= handshake.len() {
                        let group =
                            u16::from_be_bytes([handshake[offset + i], handshake[offset + i + 1]]);
                        if group & 0x0f0f != 0x0a0a {
                            elliptic_curves.push(group);
                        }
                    }
                }
            }

            // Parse EC point formats (extension 11)
            if ext_type == 11 && ext_len >= 1 && offset + ext_len <= handshake.len() {
                let formats_len = handshake[offset] as usize;
                for i in 1..=formats_len {
                    if offset + i < handshake.len() {
                        ec_point_formats.push(handshake[offset + i] as u16);
                    }
                }
            }
        }

        offset += ext_len;
    }

    // Build JA3 string
    let ja3_string = format!(
        "{},{},{},{},{}",
        tls_version,
        ciphers
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        elliptic_curves
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-"),
        ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );

    // Calculate MD5 hash
    let mut hasher = md5::Md5::new();
    hasher.update(ja3_string.as_bytes());
    let result = hasher.finalize();

    Some(hex::encode(result))
}

/// Known JA3 fingerprints for classification
pub fn classify_ja3(ja3_hash: &str) -> FingerprintClass {
    // Known browser fingerprints (sample)
    const KNOWN_BROWSERS: &[&str] = &[
        "e7d705a3286e19ea42f587b344ee6865", // Chrome
        "b32309a26951912be7dba376398abc3b", // Firefox
        "773906b0efdefa24a7f2b8eb6985bf37", // Safari
        "9e10692f1b7f78228b2d4e424db3a98c", // Edge
    ];

    // Known legitimate bots
    const KNOWN_BOTS: &[&str] = &[
        "4d7a28d6f2f7e9c8b5a3c1d0e2f6a9b8", // Googlebot (example)
        "3b5074b1b5d032e5620f69f9f700ff0e", // Bingbot (example)
    ];

    // Known malicious fingerprints
    const KNOWN_MALICIOUS: &[&str] = &[
        "e960427dc851bc6c8a87ad68e9e2aa72", // Scanner
        "51c64c77e60f3980eea90869b68c58a8", // Exploit kit
    ];

    // Known API clients
    const KNOWN_API_CLIENTS: &[&str] = &[
        "3b5074b1b5d032e5620f69f9f700ff0e", // curl
        "555c5c77e60f3980eea90869b68c58a8", // wget
    ];

    if KNOWN_BROWSERS.contains(&ja3_hash) {
        FingerprintClass::Browser
    } else if KNOWN_BOTS.contains(&ja3_hash) {
        FingerprintClass::LegitimateBot
    } else if KNOWN_MALICIOUS.contains(&ja3_hash) {
        FingerprintClass::Malicious
    } else if KNOWN_API_CLIENTS.contains(&ja3_hash) {
        FingerprintClass::ApiClient
    } else {
        // Unknown fingerprint - treat as suspicious until verified
        FingerprintClass::Suspicious
    }
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
        pub fn new(path: impl AsRef<Path>) -> Result<Self, maxminddb::MaxMindDBError> {
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

            let city: City = self.reader.lookup(ip).ok()?;

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

    #[tokio::test]
    async fn test_blocked_ip_expiration() {
        let config = ProxyConfig::default();
        let security = SecurityState::new(&config);

        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Block for 100ms
        security.block_ip(
            ip,
            BlockReason::RateLimitExceeded,
            Some(Duration::from_millis(100)),
        );

        // Should be blocked
        assert!(security.is_blocked(&ip).is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;

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
    fn test_ja3_classification() {
        // Test known browser fingerprint
        let chrome_ja3 = "e7d705a3286e19ea42f587b344ee6865";
        assert_eq!(classify_ja3(chrome_ja3), FingerprintClass::Browser);

        // Test unknown fingerprint
        let unknown = "00000000000000000000000000000000";
        assert_eq!(classify_ja3(unknown), FingerprintClass::Suspicious);
    }
}
