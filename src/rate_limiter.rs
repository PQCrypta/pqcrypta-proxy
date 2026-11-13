//! Advanced Multi-Dimensional Rate Limiting Module
//!
//! Multi-dimensional rate limiting, with the approach of each borrowed from:
//! - Cloudflare: Composite keys, NAT-aware, JA3 fingerprinting
//! - Envoy: Hierarchical descriptors, external rate limit service
//! - HAProxy: Multiple stick tables, layered rate limits
//! - Traefik: Distributed buckets, IPv6 subnet grouping
//! - AWS API Gateway: 4-level hierarchy
//! - ML/AI Research: Adaptive baseline learning, anomaly detection
//!
//! Features:
//! - Multi-key rate limiting (IP, header, JA3, JWT, composite)
//! - Layered limits (global → route → client)
//! - Adaptive baseline learning with anomaly detection
//! - X-Forwarded-For trust chain
//! - IPv6 /64 subnet grouping
//! - JA3/JA4 fingerprint-based limiting (NAT-friendly)
//! - Sliding window + token bucket hybrid algorithm

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use parking_lot::RwLock;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock as AsyncRwLock;
use tracing::{debug, info, warn};

// ============================================================================
// CONFIGURATION
// ============================================================================

// ============================================================================
// REDIS DISTRIBUTED BACKEND CONFIGURATION
// ============================================================================

/// Redis configuration for distributed rate limiting.
///
/// When configured, all per-key counters (per-second token buckets,
/// per-minute and per-hour sliding windows) are stored in Redis so every
/// proxy instance in a cluster shares the same quotas.  The global token
/// bucket always remains in-process to provide fast local DDoS protection.
/// If Redis becomes unreachable any command that times out or errors falls
/// back transparently to the in-memory DashMap bucket for that request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL.
    /// Examples:
    ///   redis://127.0.0.1:6379
    ///   redis://:password@sentinel-host:26379/0
    ///   rediss://tls-host:6380
    pub url: String,

    /// Prefix for all rate-limit keys stored in Redis (avoids collisions with
    /// other applications that share the same Redis instance).
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,

    /// Initial connection timeout in milliseconds.
    #[serde(default = "default_redis_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Per-command timeout in milliseconds.  When a command exceeds this
    /// deadline the request falls back to the local in-memory bucket.
    #[serde(default = "default_redis_cmd_timeout_ms")]
    pub command_timeout_ms: u64,

    /// Also distribute per-second (token bucket) checks through Redis.
    /// Defaults to `true`.  Set to `false` to keep sub-millisecond
    /// per-second enforcement local while only synchronising longer
    /// per-minute/per-hour windows across the cluster.
    #[serde(default = "default_true")]
    pub distribute_per_second: bool,
}

fn default_redis_prefix() -> String {
    "pqcp".to_string()
}

fn default_redis_connect_timeout_ms() -> u64 {
    2_000
}

fn default_redis_cmd_timeout_ms() -> u64 {
    50
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: default_redis_prefix(),
            connect_timeout_ms: default_redis_connect_timeout_ms(),
            command_timeout_ms: default_redis_cmd_timeout_ms(),
            distribute_per_second: true,
        }
    }
}

// ============================================================================
// CONFIGURATION
// ============================================================================

/// Advanced rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedRateLimitConfig {
    /// Enable advanced rate limiting
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Rate limit key resolution strategy
    #[serde(default)]
    pub key_strategy: KeyResolutionStrategy,

    /// Global rate limits (DDoS protection layer)
    #[serde(default)]
    pub global_limits: GlobalLimits,

    /// Per-route rate limits
    #[serde(default)]
    pub route_limits: HashMap<String, RouteLimits>,

    /// Trusted proxies for X-Forwarded-For parsing
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Header names for rate limit key extraction
    #[serde(default)]
    pub headers: RateLimitHeaders,

    /// JA3/JA4 fingerprint-based limiting
    #[serde(default)]
    pub fingerprint_limiting: FingerprintLimitConfig,

    /// Adaptive rate limiting (ML-inspired)
    #[serde(default)]
    pub adaptive: AdaptiveConfig,

    /// IPv6 subnet grouping
    #[serde(default)]
    pub ipv6_subnet_bits: u8,

    /// Composite key configurations
    #[serde(default)]
    pub composite_keys: Vec<CompositeKeyConfig>,

    /// H-2: Optional HMAC-SHA256 secret for verifying JWT signatures before using
    /// the `sub` claim for per-subject rate limiting.
    ///
    /// When `None` (the default), JWT-based rate limiting is **disabled** because
    /// the JWT payload cannot be trusted without signature verification — an attacker
    /// could forge any `sub` claim to get elevated quotas.  Set this to a strong
    /// random secret (≥32 bytes, base64-encoded) that matches the secret used by
    /// the upstream token issuer.
    pub jwt_secret: Option<String>,

    /// F-10: Allowed JWT HMAC algorithms for rate-limit key extraction.
    ///
    /// Defaults to `["HS256"]`.  Only HMAC variants (HS256, HS384, HS512) are
    /// accepted; asymmetric algorithms (RS256, ES256, etc.) require a different
    /// key format and are rejected at startup if configured here.  Restricting
    /// to a single algorithm prevents algorithm-confusion attacks where a client
    /// substitutes a weaker or alternative signing scheme.
    ///
    /// Example (TOML):
    ///   `jwt_algorithms = ["HS256"]`
    #[serde(default = "default_jwt_algorithms")]
    pub jwt_algorithms: Vec<String>,

    /// Redis configuration for distributed (cluster-wide) rate limiting.
    ///
    /// When `None` (the default), all rate-limit state lives in-process.
    /// Provide a `[advanced_rate_limiting.redis]` section in the TOML config
    /// to enable cross-instance quota sharing.
    #[serde(default)]
    pub redis: Option<RedisConfig>,
}

fn default_true() -> bool {
    true
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["HS256".to_string()]
}

impl Default for AdvancedRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            key_strategy: KeyResolutionStrategy::default(),
            global_limits: GlobalLimits::default(),
            route_limits: HashMap::new(),
            trusted_proxies: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "127.0.0.1".to_string(),
            ],
            headers: RateLimitHeaders::default(),
            fingerprint_limiting: FingerprintLimitConfig::default(),
            adaptive: AdaptiveConfig::default(),
            ipv6_subnet_bits: 64,
            composite_keys: vec![],
            jwt_secret: None, // H-2: disabled by default; set to enable JWT-based rate limiting
            jwt_algorithms: default_jwt_algorithms(), // F-10: default HS256 only
            redis: None,      // Disabled by default; add [advanced_rate_limiting.redis] to enable
        }
    }
}

/// Key resolution strategy - waterfall order
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeyResolutionStrategy {
    /// Priority order for key resolution (first match wins)
    #[serde(default = "default_key_order")]
    pub order: Vec<RateLimitKeyType>,

    /// Fallback key if none of the priority keys are found
    #[serde(default = "default_fallback")]
    pub fallback: RateLimitKeyType,

    /// Use composite keys (combine multiple keys)
    #[serde(default)]
    pub use_composite: bool,
}

fn default_key_order() -> Vec<RateLimitKeyType> {
    vec![
        RateLimitKeyType::ApiKey,
        RateLimitKeyType::JwtSubject,
        RateLimitKeyType::Ja3Fingerprint,
        RateLimitKeyType::RealIp,
        RateLimitKeyType::SourceIp,
    ]
}

fn default_fallback() -> RateLimitKeyType {
    RateLimitKeyType::SourceIp
}

/// Types of rate limit keys
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyType {
    /// Source IP address
    SourceIp,
    /// Real IP from X-Forwarded-For (trusted proxies only)
    RealIp,
    /// API key from header
    ApiKey,
    /// JWT subject claim
    JwtSubject,
    /// JA3 TLS fingerprint (NAT-friendly)
    Ja3Fingerprint,
    /// JA4 TLS fingerprint
    Ja4Fingerprint,
    /// Custom header value
    Header(String),
    /// Cookie value
    Cookie(String),
    /// Query parameter
    QueryParam(String),
    /// Request path
    Path,
    /// HTTP method
    Method,
    /// ASN (Autonomous System Number)
    Asn,
    /// Composite key combining multiple dimensions
    /// The Vec contains the names of combined key types for identification
    Composite(Vec<String>),
}

impl Default for RateLimitKeyType {
    fn default() -> Self {
        Self::SourceIp
    }
}

impl RateLimitKeyType {
    /// Whether the client writes this key's value into each request as it
    /// likes: a header (the API key among them), a cookie, a query parameter
    /// or the path. Nothing here verifies such a value, so it names a
    /// bucket and never earns one.
    pub fn is_client_written(&self) -> bool {
        matches!(
            self,
            Self::ApiKey | Self::Header(_) | Self::Cookie(_) | Self::QueryParam(_) | Self::Path
        )
    }
}

/// Global rate limits (DDoS protection)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalLimits {
    /// Requests per second (entire proxy)
    #[serde(default = "default_global_rps")]
    pub requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_global_burst")]
    pub burst_size: u32,

    /// Per-IP default limits
    #[serde(default)]
    pub per_ip: PerKeyLimits,

    /// Per-fingerprint limits (for NAT scenarios)
    #[serde(default)]
    pub per_fingerprint: PerKeyLimits,

    /// Default limits applied when the rate-limit key resolves to an API key.
    /// These are intentionally higher than per-IP limits to reward authenticated
    /// callers.  Override per-key in `[advanced_rate_limiting.route_limits]`.
    #[serde(default = "default_per_api_key_limits")]
    pub per_api_key: PerKeyLimits,

    /// Default limits applied to composite (multi-dimension) keys.
    #[serde(default = "default_per_composite_limits")]
    pub per_composite: PerKeyLimits,

    /// Limits for a key resolved from a verified JWT's `sub` claim — one
    /// authenticated user, however many addresses they come from. Defaults to
    /// the per-IP values, which is what such a key received before it had its
    /// own block.
    #[serde(default = "default_per_jwt_subject_limits")]
    pub per_jwt_subject: PerKeyLimits,
}

fn default_per_jwt_subject_limits() -> PerKeyLimits {
    PerKeyLimits {
        requests_per_second: 1000,
        burst_size: 500,
        requests_per_minute: Some(30_000),
        requests_per_hour: Some(500_000),
    }
}

fn default_global_rps() -> u32 {
    100_000
}

fn default_global_burst() -> u32 {
    50_000
}

fn default_per_api_key_limits() -> PerKeyLimits {
    PerKeyLimits {
        requests_per_second: 500,
        burst_size: 250,
        requests_per_minute: Some(15_000),
        requests_per_hour: Some(250_000),
    }
}

fn default_per_composite_limits() -> PerKeyLimits {
    PerKeyLimits {
        requests_per_second: 200,
        burst_size: 100,
        requests_per_minute: Some(6_000),
        requests_per_hour: Some(100_000),
    }
}

impl Default for GlobalLimits {
    fn default() -> Self {
        Self {
            requests_per_second: 100_000,
            burst_size: 50_000,
            per_ip: PerKeyLimits {
                requests_per_second: 1000,
                burst_size: 500,
                requests_per_minute: Some(30_000),
                requests_per_hour: Some(500_000),
            },
            per_fingerprint: PerKeyLimits {
                requests_per_second: 100,
                burst_size: 50,
                requests_per_minute: Some(3_000),
                requests_per_hour: Some(50_000),
            },
            per_api_key: default_per_api_key_limits(),
            per_composite: default_per_composite_limits(),
            per_jwt_subject: default_per_jwt_subject_limits(),
        }
    }
}

/// Per-key rate limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerKeyLimits {
    /// Requests per second
    #[serde(default = "default_per_key_rps")]
    pub requests_per_second: u32,

    /// Burst size
    #[serde(default = "default_per_key_burst")]
    pub burst_size: u32,

    /// Requests per minute (sliding window)
    pub requests_per_minute: Option<u32>,

    /// Requests per hour (sliding window)
    pub requests_per_hour: Option<u32>,
}

fn default_per_key_rps() -> u32 {
    100
}

fn default_per_key_burst() -> u32 {
    50
}

impl Default for PerKeyLimits {
    fn default() -> Self {
        Self {
            requests_per_second: 100,
            burst_size: 50,
            requests_per_minute: None,
            requests_per_hour: None,
        }
    }
}

/// Per-route rate limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteLimits {
    /// Route pattern (path prefix or regex)
    pub pattern: String,

    /// Per-key limits for this route
    #[serde(default)]
    pub limits: PerKeyLimits,

    /// Override key resolution for this route
    pub key_override: Option<RateLimitKeyType>,

    /// Exempt certain keys from rate limiting
    #[serde(default)]
    pub exempt_keys: Vec<String>,
}

/// Header names for key extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitHeaders {
    /// API key header
    #[serde(default = "default_api_key_header")]
    pub api_key: String,

    /// User ID header (from auth gateway)
    #[serde(default = "default_user_id_header")]
    pub user_id: String,

    /// Tenant/Organization ID header
    #[serde(default = "default_tenant_header")]
    pub tenant_id: String,

    /// Real IP header (X-Forwarded-For alternative)
    #[serde(default = "default_real_ip_header")]
    pub real_ip: String,
}

fn default_api_key_header() -> String {
    "X-API-Key".to_string()
}

fn default_user_id_header() -> String {
    "X-User-ID".to_string()
}

fn default_tenant_header() -> String {
    "X-Tenant-ID".to_string()
}

fn default_real_ip_header() -> String {
    "X-Real-IP".to_string()
}

impl Default for RateLimitHeaders {
    fn default() -> Self {
        Self {
            api_key: default_api_key_header(),
            user_id: default_user_id_header(),
            tenant_id: default_tenant_header(),
            real_ip: default_real_ip_header(),
        }
    }
}

/// JA3/JA4 fingerprint-based limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintLimitConfig {
    /// Enable fingerprint-based limiting
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Use fingerprint as primary key for NAT scenarios
    #[serde(default)]
    pub prefer_over_ip: bool,

    /// Known good fingerprints (browsers) - higher limits
    #[serde(default)]
    pub trusted_fingerprints: HashMap<String, PerKeyLimits>,

    /// Known bad fingerprints (scanners/bots) - lower limits or block
    #[serde(default)]
    pub blocked_fingerprints: Vec<String>,

    /// Unknown fingerprint limits (more restrictive)
    #[serde(default)]
    pub unknown_limits: PerKeyLimits,
}

impl Default for FingerprintLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prefer_over_ip: false,
            trusted_fingerprints: HashMap::new(),
            blocked_fingerprints: vec![],
            unknown_limits: PerKeyLimits {
                requests_per_second: 50,
                burst_size: 25,
                requests_per_minute: Some(1500),
                requests_per_hour: Some(25_000),
            },
        }
    }
}

/// Adaptive rate limiting configuration (ML-inspired)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveConfig {
    /// Enable adaptive rate limiting
    #[serde(default)]
    pub enabled: bool,

    /// How long the baseline remembers (seconds): a sample this old weighs
    /// `1/e` of a new one, so the baseline follows a rate that changes
    #[serde(default = "default_baseline_window")]
    pub baseline_window_secs: u64,

    /// Anomaly detection sensitivity, 0.0 (laxest) to 1.0 (strictest).
    ///
    /// Scales `std_dev_multiplier`, which is the raw statistical knob: a
    /// request is anomalous once its rate exceeds `mean + multiplier * stddev`.
    /// Sensitivity is the same control expressed the way an operator thinks
    /// about it — turn it up to catch more, down to catch less — so the two
    /// compose rather than compete.
    ///
    /// The scale is anchored at the default 0.7, which yields exactly
    /// `std_dev_multiplier` and so reproduces the behaviour of every existing
    /// deployment unchanged.  See `effective_std_dev_multiplier`.
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f64,

    /// Tighten each key's minute and hour limits toward its own learned
    /// baseline.
    ///
    /// The configured limits are sized for the busiest plausible caller, so
    /// every quiet key carries the loudest key's headroom: an account that
    /// normally makes 5 requests a minute can make 3,000 before anything
    /// objects, which is all the room a credential-stuffing run needs.  With
    /// this on, once a key has enough samples its standing limits move down to
    /// its observed normal plus the anomaly margin.
    ///
    /// Adjustment is one-directional: the configured limit is a ceiling that is
    /// never exceeded, and `burst_size` is the floor, so a nearly-idle key
    /// cannot be tightened into limiting its own first legitimate burst.
    #[serde(default)]
    pub auto_adjust: bool,

    /// Samples before the baseline is used: a key's rate is sampled at
    /// most once a second while it is active, so the default 1000 is about
    /// 17 minutes of a key's activity (a key idle for 5 minutes is
    /// forgotten, its baseline with it)
    #[serde(default = "default_min_samples")]
    pub min_samples: u64,

    /// Standard deviation multiplier for anomaly detection
    #[serde(default = "default_std_dev_multiplier")]
    pub std_dev_multiplier: f64,
}

fn default_baseline_window() -> u64 {
    3600 // 1 hour
}

/// The sensitivity value at which the scale is anchored.  At this value
/// `effective_std_dev_multiplier` returns `std_dev_multiplier` untouched.
const ANCHOR_SENSITIVITY: f64 = 0.7;

/// Maximum sensitivity still requires a real deviation from the mean.  Without
/// a floor, `sensitivity = 1.0` collapses the threshold onto the mean itself,
/// and roughly half of all samples sit above their own mean.
const MIN_STD_DEV_MULTIPLIER: f64 = 0.25;

/// Fold `sensitivity` into `std_dev_multiplier` to get the multiplier the
/// baseline actually uses.
///
/// `sensitivity` was declared, defaulted, documented and read by nothing, so
/// the only thing that moved the anomaly threshold was the raw statistical
/// multiplier.  The mapping is linear and anchored at the default sensitivity,
/// so a deployment that never touched either knob sees no change at all:
///
/// | sensitivity | factor | multiplier at the 3.0 default |
/// |-------------|--------|-------------------------------|
/// | 0.0         | 3.33   | 10.0  — only gross outliers   |
/// | 0.7         | 1.00   | 3.0   — today's behaviour     |
/// | 1.0         | 0.00   | 0.25  — floored, see above    |
fn effective_std_dev_multiplier(config: &AdaptiveConfig) -> f64 {
    let sensitivity = config.sensitivity.clamp(0.0, 1.0);
    let factor = (1.0 - sensitivity) / (1.0 - ANCHOR_SENSITIVITY);
    (config.std_dev_multiplier * factor).max(MIN_STD_DEV_MULTIPLIER)
}

fn default_sensitivity() -> f64 {
    0.7
}

fn default_min_samples() -> u64 {
    1000
}

fn default_std_dev_multiplier() -> f64 {
    3.0
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            baseline_window_secs: 3600,
            sensitivity: 0.7,
            auto_adjust: false,
            min_samples: 1000,
            std_dev_multiplier: 3.0,
        }
    }
}

/// Composite key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeKeyConfig {
    /// Name for this composite key
    pub name: String,

    /// Keys to combine
    pub keys: Vec<RateLimitKeyType>,

    /// Limits for this composite key
    pub limits: PerKeyLimits,

    /// Routes this applies to (empty = all)
    #[serde(default)]
    pub routes: Vec<String>,
}

// ============================================================================
// REDIS BACKEND
// ============================================================================

/// Lua script: atomic token-bucket check-and-consume.
///
/// KEYS[1]  = hash key  (e.g. "pqcp:tb:SourceIp:1.2.3.4")
/// ARGV[1]  = max_tokens  (burst capacity, integer)
/// ARGV[2]  = tokens_per_ms  (rate as float string, e.g. "0.1" for 100 rps)
/// ARGV[3]  = now_ms  (current Unix time in milliseconds)
///
/// Returns: {1, remaining}  if allowed
///          {0, 0}          if denied
const TOKEN_BUCKET_LUA: &str = r"
local key        = KEYS[1]
local max_tokens = tonumber(ARGV[1])
local rate_ms    = tonumber(ARGV[2])
local now        = tonumber(ARGV[3])

local data       = redis.call('HMGET', key, 't', 'ts')
local tokens     = tonumber(data[1]) or max_tokens
local last_ts    = tonumber(data[2]) or now

local elapsed    = math.max(0, now - last_ts)
tokens           = math.min(max_tokens, tokens + elapsed * rate_ms)

-- TTL: time to refill from 0 to max_tokens plus a generous buffer
local ttl_ms = math.ceil(max_tokens / math.max(rate_ms, 0.000001)) + 5000

if tokens >= 1.0 then
    tokens = tokens - 1.0
    redis.call('HMSET', key, 't', tostring(tokens), 'ts', tostring(now))
    redis.call('PEXPIRE', key, ttl_ms)
    return {1, math.floor(tokens)}
else
    redis.call('HMSET', key, 't', tostring(tokens), 'ts', tostring(now))
    redis.call('PEXPIRE', key, ttl_ms)
    return {0, 0}
end
";

/// Lua script: atomic fixed-window counter.
///
/// KEYS[1]  = counter key  (e.g. "pqcp:sw:1m:SourceIp:1.2.3.4:28123456")
/// ARGV[1]  = limit  (integer)
/// ARGV[2]  = window_ttl  (seconds, integer)
///
/// Returns: {1, remaining}  if allowed
///          {0, 0}          if denied
const SLIDING_WINDOW_LUA: &str = r"
local key   = KEYS[1]
local limit = tonumber(ARGV[1])
local ttl   = tonumber(ARGV[2])

local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, ttl)
end

if count > limit then
    return {0, 0}
else
    return {1, limit - count}
end
";

/// Redis-backed distributed rate-limit counters.
///
/// One `RedisBackend` is shared (via `Arc`) across all requests on a single
/// proxy node.  `ConnectionManager` handles reconnection transparently.
pub struct RedisBackend {
    conn: ConnectionManager,
    prefix: String,
    cmd_timeout: Duration,
    distribute_per_second: bool,
}

impl RedisBackend {
    /// Establish a `ConnectionManager` to Redis.
    pub async fn connect(config: &RedisConfig) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(config.url.as_str())?;
        // redis 1.x gives async connections deadlines of its own (1 s to
        // connect, 500 ms per response); the configured ones are what apply.
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(Duration::from_millis(config.connect_timeout_ms)))
            .set_response_timeout(Some(Duration::from_millis(config.command_timeout_ms)));
        let conn = tokio::time::timeout(
            Duration::from_millis(config.connect_timeout_ms),
            ConnectionManager::new_with_config(client, manager_config),
        )
        .await
        .map_err(|_| redis::RedisError::from((redis::ErrorKind::Io, "Redis connect timeout")))??;

        Ok(Self {
            conn,
            prefix: config.key_prefix.clone(),
            cmd_timeout: Duration::from_millis(config.command_timeout_ms),
            distribute_per_second: config.distribute_per_second,
        })
    }

    // ── Key helpers ─────────────────────────────────────────────────────────

    fn tb_key(&self, key_str: &str) -> String {
        format!("{}:tb:{}", self.prefix, key_str)
    }

    fn sw_key(&self, label: &str, key_str: &str, bucket: u64) -> String {
        format!("{}:sw:{}:{}:{}", self.prefix, label, key_str, bucket)
    }

    // ── Token-bucket (per-second) ────────────────────────────────────────────

    /// Distributed token-bucket check.  Returns `None` on Redis error
    /// (caller should fall back to in-memory).
    pub async fn check_token_bucket(
        &self,
        key_str: &str,
        rps: u32,
        burst: u32,
    ) -> Option<RateLimitResult> {
        if !self.distribute_per_second {
            return None; // caller uses local governor
        }

        let redis_key = self.tb_key(key_str);
        let max_tokens = burst as f64;
        let tokens_per_ms = rps as f64 / 1000.0;
        // Milliseconds, as the script's refill rate is per millisecond: taken
        // in whole seconds, a bucket refilled in one lump a second.
        let now_ms: u64 = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);

        let mut conn = self.conn.clone();
        let result: Result<(i64, i64), _> = tokio::time::timeout(self.cmd_timeout, async {
            redis::Script::new(TOKEN_BUCKET_LUA)
                .key(&redis_key)
                .arg(max_tokens)
                .arg(tokens_per_ms)
                .arg(now_ms)
                .invoke_async(&mut conn)
                .await
        })
        .await
        .map_err(|_| ())
        .and_then(|r| r.map_err(|_| ()));

        match result {
            Ok((1, remaining)) => Some(RateLimitResult::Allowed {
                remaining: u32::try_from(remaining.max(0)).unwrap_or(0),
                limit: rps,
            }),
            Ok(_) => Some(RateLimitResult::Limited {
                reason: LimitReason::PerSecond,
                retry_after_ms: 1_000,
                limit: rps,
            }),
            Err(()) => {
                warn!(
                    "Redis token-bucket error for key '{}', falling back to local",
                    key_str
                );
                None
            }
        }
    }

    // ── Sliding-window (per-minute / per-hour) ───────────────────────────────

    /// Distributed sliding-window check.
    ///
    /// `window_secs` must be 60 (per-minute) or 3600 (per-hour).
    /// Returns `None` on Redis error.
    pub async fn check_sliding_window(
        &self,
        key_str: &str,
        limit: u32,
        window_secs: u64,
        label: &str,
    ) -> Option<RateLimitResult> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bucket = now_secs / window_secs;
        let redis_key = self.sw_key(label, key_str, bucket);

        // TTL = 2× window so the key expires cleanly even if there's clock skew.
        let ttl = window_secs * 2;

        let mut conn = self.conn.clone();
        let result: Result<(i64, i64), _> = tokio::time::timeout(self.cmd_timeout, async {
            redis::Script::new(SLIDING_WINDOW_LUA)
                .key(&redis_key)
                .arg(limit)
                .arg(ttl)
                .invoke_async(&mut conn)
                .await
        })
        .await
        .map_err(|_| ())
        .and_then(|r| r.map_err(|_| ()));

        let retry_after_ms: u64 = {
            // Time remaining until the current window expires.
            let window_start = bucket * window_secs;
            let window_end = window_start + window_secs;
            (window_end.saturating_sub(now_secs)) * 1_000
        };

        match result {
            Ok((1, remaining)) => Some(RateLimitResult::Allowed {
                remaining: u32::try_from(remaining.max(0)).unwrap_or(0),
                limit,
            }),
            Ok(_) => Some(RateLimitResult::Limited {
                reason: if window_secs <= 60 {
                    LimitReason::PerMinute
                } else {
                    LimitReason::PerHour
                },
                retry_after_ms,
                limit,
            }),
            Err(()) => {
                warn!(
                    "Redis sliding-window error for key '{}' ({}), falling back to local",
                    key_str, label
                );
                None
            }
        }
    }
}

/// One bucket a request is counted in: the key it is stored under and the
/// limits that apply there.
#[derive(Debug, Clone)]
struct Charge {
    key_string: String,
    limits: PerKeyLimits,
    /// The key is one the client cannot choose (`RateLimitKey::is_network_bound`)
    network_bound: bool,
}

/// How long a bucket goes unused before the cleanup lets it go.
const BUCKET_IDLE: Duration = Duration::from_mins(5);

/// The overflow bucket a network key is counted in when the map is full: its
/// route's, the key without its network.
fn overflow_key(key_string: &str) -> String {
    let scope = key_string.rsplit_once('#').map_or_else(
        || key_string.split(':').next().unwrap_or(key_string),
        |(route, _)| route,
    );
    format!("overflow:{scope}")
}

/// A fixed-length stand-in for a value the client wrote, for use in a bucket's
/// key: the first 128 bits of its SHA-256, in hex.
fn value_digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(value.as_bytes())[..16])
}

// ============================================================================
// RATE LIMIT KEY
// ============================================================================

/// Resolved rate limit key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    /// The key type used
    pub key_type: RateLimitKeyType,

    /// The resolved key value
    pub value: String,

    /// Optional composite key components
    pub components: Option<Vec<(RateLimitKeyType, String)>>,
}

impl RateLimitKey {
    pub fn new(key_type: RateLimitKeyType, value: String) -> Self {
        Self {
            key_type,
            value,
            components: None,
        }
    }

    pub fn composite(components: Vec<(RateLimitKeyType, String)>) -> Self {
        // Build composite value by joining all component values
        let value = components
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(":");

        // Extract key type names for the Composite variant identifier
        let key_type_names: Vec<String> =
            components.iter().map(|(k, _)| format!("{:?}", k)).collect();

        Self {
            key_type: RateLimitKeyType::Composite(key_type_names),
            value,
            components: Some(components),
        }
    }

    /// Whether every part of this key is something the client cannot choose:
    /// the address it connected from, or a subject whose token verified. Any
    /// other key is counted beside the address's own bucket, never instead of
    /// it (see `AdvancedRateLimiter::charges`).
    pub fn is_network_bound(&self) -> bool {
        let bound = |t: &RateLimitKeyType| {
            matches!(
                t,
                RateLimitKeyType::SourceIp
                    | RateLimitKeyType::RealIp
                    | RateLimitKeyType::JwtSubject
            )
        };
        match &self.components {
            Some(components) => components.iter().all(|(t, _)| bound(t)),
            None => bound(&self.key_type),
        }
    }

    /// Whether any part of this key is a value the client wrote (see
    /// [`RateLimitKeyType::is_client_written`]).
    pub fn is_client_written(&self) -> bool {
        match &self.components {
            Some(components) => components.iter().any(|(t, _)| t.is_client_written()),
            None => self.key_type.is_client_written(),
        }
    }

    /// The string this key's bucket is stored under, here and in Redis.
    ///
    /// A value the client wrote (a header, a cookie, a query parameter, the
    /// path) goes in as a digest: it may be a credential, and it may be as
    /// long as a header is allowed to be. A TLS fingerprint is counted per
    /// `network`: a fingerprint names a client build, which every user of
    /// that build shares, so on its own it would be one bucket for all of
    /// them.
    pub fn storage_key(&self, network: &str) -> String {
        let part = |t: &RateLimitKeyType, v: &str| -> String {
            match t {
                RateLimitKeyType::ApiKey
                | RateLimitKeyType::Header(_)
                | RateLimitKeyType::Cookie(_)
                | RateLimitKeyType::QueryParam(_)
                | RateLimitKeyType::Path => format!("{:?}:{}", t, value_digest(v)),
                RateLimitKeyType::Ja3Fingerprint | RateLimitKeyType::Ja4Fingerprint => {
                    format!("{:?}:{}@{}", t, v, network)
                }
                _ => format!("{:?}:{}", t, v),
            }
        };
        match &self.components {
            Some(components) => components
                .iter()
                .map(|(t, v)| part(t, v))
                .collect::<Vec<_>>()
                .join("|"),
            None => part(&self.key_type, &self.value),
        }
    }
}

// ============================================================================
// REQUEST CONTEXT
// ============================================================================

/// Request context for rate limit key resolution
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// Source IP address
    pub source_ip: IpAddr,

    /// Request headers
    pub headers: HashMap<String, String>,

    /// Request path
    pub path: String,

    /// HTTP method
    pub method: String,

    /// Query parameters
    pub query_params: HashMap<String, String>,

    /// Cookies
    pub cookies: HashMap<String, String>,

    /// JA3 fingerprint hash (if available)
    pub ja3_hash: Option<String>,

    /// JA4 fingerprint hash (if available)
    pub ja4_hash: Option<String>,

    /// Route name (for per-route limits)
    pub route_name: Option<String>,
}

impl RateLimitContext {
    /// Get header value (case-insensitive)
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }

    /// Get cookie value
    pub fn get_cookie(&self, name: &str) -> Option<&String> {
        self.cookies.get(name)
    }

    /// Get query parameter
    pub fn get_query_param(&self, name: &str) -> Option<&String> {
        self.query_params.get(name)
    }
}

// ============================================================================
// SLIDING WINDOW COUNTER
// ============================================================================

/// Sliding window rate counter for minute/hour limits
#[derive(Debug)]
pub struct SlidingWindowCounter {
    /// Number of buckets (granularity)
    num_buckets: usize,

    /// Bucket counts
    buckets: Vec<AtomicU64>,

    /// Current bucket index
    current_bucket: AtomicU64,

    /// Last update timestamp
    last_update: RwLock<Instant>,

    /// Bucket duration in seconds
    bucket_duration_secs: u64,
}

impl SlidingWindowCounter {
    pub fn new(window_secs: u64, num_buckets: usize) -> Self {
        let buckets = (0..num_buckets).map(|_| AtomicU64::new(0)).collect();
        let bucket_duration_secs = window_secs / num_buckets as u64;

        Self {
            num_buckets,
            buckets,
            current_bucket: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
            bucket_duration_secs,
        }
    }

    /// Increment counter and return current count
    pub fn increment(&self) -> u64 {
        self.rotate_buckets();

        let current = usize::try_from(self.current_bucket.load(Ordering::Relaxed))
            .unwrap_or(usize::MAX)
            % self.num_buckets;
        self.buckets[current].fetch_add(1, Ordering::Relaxed);

        self.get_count()
    }

    /// Get current count across all buckets
    pub fn get_count(&self) -> u64 {
        self.rotate_buckets();
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    /// Rotate buckets based on elapsed time
    fn rotate_buckets(&self) {
        let mut last_update = self.last_update.write();
        let elapsed = last_update.elapsed();
        let buckets_to_rotate =
            usize::try_from(elapsed.as_secs() / self.bucket_duration_secs).unwrap_or(usize::MAX);

        if buckets_to_rotate > 0 {
            let current =
                usize::try_from(self.current_bucket.load(Ordering::Relaxed)).unwrap_or(usize::MAX);

            // Clear old buckets
            for i in 1..=buckets_to_rotate.min(self.num_buckets) {
                let idx = (current + i) % self.num_buckets;
                self.buckets[idx].store(0, Ordering::Relaxed);
            }

            // Update current bucket
            self.current_bucket.store(
                ((current + buckets_to_rotate) % self.num_buckets) as u64,
                Ordering::Relaxed,
            );

            *last_update = Instant::now();
        }
    }
}

// ============================================================================
// ADAPTIVE BASELINE
// ============================================================================

/// How often a baseline takes a sample at most: a rate is read once a
/// second, however many requests arrive in it, so a burst is one sample and
/// not as many samples as it has requests.
const SAMPLE_EVERY: Duration = Duration::from_secs(1);

/// A count as a sample, saturating far above any rate a key can have.
fn sample_value(value: u64) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

/// What a request rate (one key's, or the proxy's) normally is, and how far
/// it strays.
///
/// The mean and standard deviation of its samples, each weighing less the
/// older it is, by `e^(-age / window)`, so the baseline follows the traffic
/// as it changes rather than averaging all the time there has been.
///
/// The moments are kept by a weighted Welford update: the mean and the sum
/// of squared deviations from it are carried as they are, so the variance is
/// never the difference of two large sums (rounding can take that below
/// zero, and a NaN threshold flags nothing), and every sample costs the
/// same, one short lock and no allocation.
#[derive(Debug)]
pub struct AdaptiveBaseline {
    moments: parking_lot::Mutex<Moments>,

    /// Samples taken, ever: what `min_samples` counts
    count: AtomicU64,

    /// The age at which a sample weighs `1/e` of a new one
    window: Duration,

    /// Samples before the baseline is used
    min_samples: u64,

    /// Standard deviations above the mean at which a rate is anomalous
    std_dev_multiplier: f64,
}

#[derive(Debug, Default)]
struct Moments {
    /// The samples' total weight
    weight: f64,
    mean: f64,
    /// The weighted sum of squared deviations from the mean
    m2: f64,
    last: Option<Instant>,
}

impl AdaptiveBaseline {
    pub fn new(window_secs: u64, min_samples: u64, std_dev_multiplier: f64) -> Self {
        Self {
            moments: parking_lot::Mutex::new(Moments::default()),
            count: AtomicU64::new(0),
            window: Duration::from_secs(window_secs.max(1)),
            min_samples,
            std_dev_multiplier,
        }
    }

    /// Take `value` as a sample now, unless one was taken within the last
    /// second.
    pub fn record(&self, value: u64) {
        self.record_at(value, Instant::now());
    }

    fn record_at(&self, value: u64, at: Instant) {
        let mut m = self.moments.lock();
        if let Some(last) = m.last {
            let since = at.saturating_duration_since(last);
            if since < SAMPLE_EVERY {
                return;
            }
            // What came before weighs less by the time since
            let decay = (-since.as_secs_f64() / self.window.as_secs_f64()).exp();
            m.weight *= decay;
            m.m2 *= decay;
        }
        let x = sample_value(value);
        m.weight += 1.0;
        let delta = x - m.mean;
        m.mean += delta / m.weight;
        m.m2 = delta.mul_add(x - m.mean, m.m2);
        m.last = Some(at);
        drop(m);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether enough samples have been seen for the mean to mean anything.
    pub fn is_established(&self) -> bool {
        self.count.load(Ordering::Relaxed) >= self.min_samples
    }

    fn mean_and_std_dev(&self) -> (f64, f64) {
        let m = self.moments.lock();
        if m.weight <= 0.0 {
            return (0.0, 0.0);
        }
        (m.mean, (m.m2 / m.weight).max(0.0).sqrt())
    }

    /// The rate above which a sample counts as anomalous: `mean + k * stddev`,
    /// where `k` already has `sensitivity` folded in.
    ///
    /// Exposed separately from `is_anomaly` because `auto_adjust` needs the
    /// number itself, not the verdict — the same threshold that flags a spike
    /// is the right resting place for the key's standing limits.  Returns
    /// `None` until the baseline is established.
    pub fn threshold(&self) -> Option<f64> {
        if !self.is_established() {
            return None;
        }
        let (mean, std_dev) = self.mean_and_std_dev();
        Some(self.std_dev_multiplier.mul_add(std_dev, mean))
    }

    /// Whether `value` is above the threshold; never before the baseline is
    /// established.
    pub fn is_anomaly(&self, value: u64) -> bool {
        self.threshold()
            .is_some_and(|threshold| sample_value(value) > threshold)
    }

    /// The mean rate
    pub fn get_mean(&self) -> f64 {
        self.mean_and_std_dev().0
    }

    /// The standard deviation of the rate; 0 before there are two samples
    pub fn get_std_dev(&self) -> f64 {
        if self.count.load(Ordering::Relaxed) < 2 {
            return 0.0;
        }
        self.mean_and_std_dev().1
    }
}

// ============================================================================
// RATE LIMIT BUCKET
// ============================================================================

/// Rate limit state for a single key
#[derive(Debug)]
pub struct RateLimitBucket {
    /// Token bucket rate limiter (per-second)
    pub token_bucket: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,

    /// Sliding window counter (per-minute)
    pub minute_counter: Option<Arc<SlidingWindowCounter>>,

    /// Sliding window counter (per-hour)
    pub hour_counter: Option<Arc<SlidingWindowCounter>>,

    /// Requests in current second (for burst detection)
    pub current_second_count: AtomicU64,

    /// Last request timestamp
    pub last_request: RwLock<Instant>,

    /// Created timestamp (for bucket age tracking)
    pub created_at: Instant,

    /// Total requests (for stats)
    pub total_requests: AtomicU64,

    /// Total blocked requests
    pub total_blocked: AtomicU64,

    /// Adaptive baseline (if enabled)
    pub baseline: Option<Arc<AdaptiveBaseline>>,
}

impl RateLimitBucket {
    pub fn new(limits: &PerKeyLimits, adaptive_config: Option<&AdaptiveConfig>) -> Self {
        // Use saturating values to prevent panics - MIN is 1
        let rps = NonZeroU32::new(limits.requests_per_second.max(1)).unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(limits.burst_size.max(1)).unwrap_or(NonZeroU32::MIN);

        let quota = Quota::per_second(rps).allow_burst(burst);

        let minute_counter = limits
            .requests_per_minute
            .map(|_| Arc::new(SlidingWindowCounter::new(60, 12))); // 5-second buckets

        let hour_counter = limits
            .requests_per_hour
            .map(|_| Arc::new(SlidingWindowCounter::new(3600, 60))); // 1-minute buckets

        let baseline = adaptive_config.and_then(|config| {
            if config.enabled {
                Some(Arc::new(AdaptiveBaseline::new(
                    config.baseline_window_secs,
                    config.min_samples,
                    effective_std_dev_multiplier(config),
                )))
            } else {
                None
            }
        });

        Self {
            token_bucket: Arc::new(RateLimiter::direct(quota)),
            minute_counter,
            hour_counter,
            current_second_count: AtomicU64::new(0),
            last_request: RwLock::new(Instant::now()),
            created_at: Instant::now(),
            total_requests: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            baseline,
        }
    }

    /// The limits this bucket actually enforces, after `auto_adjust`.
    ///
    /// Returns `limits` untouched unless auto-adjustment is on AND this key's
    /// baseline has reached `min_samples`.  Once established, the standing
    /// minute/hour ceilings move down to
    /// the key's own anomaly threshold, bounded by `burst_size` below and the
    /// operator's configured value above.  The per-second token bucket is not
    /// touched: `governor`'s quota is fixed when the bucket is built, and
    /// per-second bursts are what `burst_size` and the anomaly detector already
    /// answer.
    fn effective_limits(&self, limits: &PerKeyLimits, adaptive: &AdaptiveConfig) -> PerKeyLimits {
        if !adaptive.auto_adjust {
            return limits.clone();
        }
        let Some(ref baseline) = self.baseline else {
            return limits.clone();
        };
        // `threshold()` is None until the baseline reaches `min_samples`.  An
        // unestablished baseline has a meaningless mean, and tightening on it
        // would throttle a key for being new.
        let Some(threshold) = baseline.threshold() else {
            return limits.clone();
        };

        // The baseline records per-minute counts, so its threshold is already
        // in the units `requests_per_minute` is expressed in.
        #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let per_minute = threshold.ceil().clamp(0.0, f64::from(u32::MAX)) as u32;
        let per_minute = per_minute.max(limits.burst_size);

        PerKeyLimits {
            requests_per_second: limits.requests_per_second,
            burst_size: limits.burst_size,
            requests_per_minute: limits
                .requests_per_minute
                .map(|configured| per_minute.min(configured)),
            requests_per_hour: limits.requests_per_hour.map(|configured| {
                per_minute
                    .saturating_mul(60)
                    .max(limits.burst_size)
                    .min(configured)
            }),
        }
    }

    /// Check if request is allowed
    pub fn check(&self, limits: &PerKeyLimits, adaptive: &AdaptiveConfig) -> RateLimitResult {
        let adjusted = self.effective_limits(limits, adaptive);
        let limits = &adjusted;

        self.total_requests.fetch_add(1, Ordering::Relaxed);
        *self.last_request.write() = Instant::now();

        // 1. Check token bucket (per-second)
        if self.token_bucket.check().is_err() {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult::Limited {
                reason: LimitReason::PerSecond,
                retry_after_ms: 1000,
                limit: limits.requests_per_second,
            };
        }

        // 2. Check minute limit (if configured)
        if let Some(ref counter) = self.minute_counter {
            if let Some(limit) = limits.requests_per_minute {
                let count = counter.increment();
                if count > limit as u64 {
                    self.total_blocked.fetch_add(1, Ordering::Relaxed);
                    return RateLimitResult::Limited {
                        reason: LimitReason::PerMinute,
                        retry_after_ms: 60_000,
                        limit,
                    };
                }
            }
        }

        // 3. Check hour limit (if configured)
        if let Some(ref counter) = self.hour_counter {
            if let Some(limit) = limits.requests_per_hour {
                let count = counter.increment();
                if count > limit as u64 {
                    self.total_blocked.fetch_add(1, Ordering::Relaxed);
                    return RateLimitResult::Limited {
                        reason: LimitReason::PerHour,
                        retry_after_ms: 3_600_000,
                        limit,
                    };
                }
            }
        }

        // 4. Check adaptive baseline (if enabled)
        if let Some(ref baseline) = self.baseline {
            let recent_count = self
                .minute_counter
                .as_ref()
                .map(|c| c.get_count())
                .unwrap_or(0);

            baseline.record(recent_count);

            if baseline.is_anomaly(recent_count) {
                self.total_blocked.fetch_add(1, Ordering::Relaxed);
                return RateLimitResult::Limited {
                    reason: LimitReason::AnomalyDetected,
                    retry_after_ms: 60_000,
                    // clamp(0.0, u32::MAX as f64) ensures value is non-negative and within u32 range.
                    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    limit: baseline.get_mean().clamp(0.0, u32::MAX as f64) as u32,
                };
            }
        }

        RateLimitResult::Allowed {
            remaining: limits.requests_per_second.saturating_sub(1),
            limit: limits.requests_per_second,
        }
    }
}

/// Rate limit check result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed
    Allowed {
        /// Remaining requests in current window
        remaining: u32,
        /// Total limit
        limit: u32,
    },
    /// Request is rate limited
    Limited {
        /// Reason for limiting
        reason: LimitReason,
        /// Retry after milliseconds
        retry_after_ms: u64,
        /// The limit that was exceeded
        limit: u32,
    },
    /// Key is blocked (fingerprint block, etc.)
    Blocked {
        /// Reason for blocking
        reason: String,
    },
}

/// Reason for rate limiting
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitReason {
    /// Per-second limit exceeded
    PerSecond,
    /// Per-minute limit exceeded
    PerMinute,
    /// Per-hour limit exceeded
    PerHour,
    /// Global limit exceeded
    Global,
    /// Anomaly detected (adaptive)
    AnomalyDetected,
    /// Route-specific limit exceeded
    RouteLimit,
}

// ============================================================================
// ADVANCED RATE LIMITER
// ============================================================================

/// Advanced multi-dimensional rate limiter
pub struct AdvancedRateLimiter {
    /// Configuration
    config: Arc<RwLock<AdvancedRateLimitConfig>>,

    /// Global rate limiter (always in-process for fast DDoS protection)
    global_limiter: arc_swap::ArcSwap<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,

    /// Per-key rate limit buckets (in-memory fallback / local-only path)
    buckets: Arc<DashMap<String, Arc<RateLimitBucket>>>,

    /// Per-route rate limit buckets
    route_buckets: Arc<DashMap<String, Arc<DashMap<String, Arc<RateLimitBucket>>>>>,

    /// Where `buckets` is full of live ones: a client network that did not
    /// fit is counted in its route's overflow bucket, one per route, so it is
    /// still limited ([`Self::get_or_create_bucket`])
    overflow_buckets: Arc<DashMap<String, Arc<RateLimitBucket>>>,

    /// `buckets`' ceiling for network keys: a full map is swept of idle
    /// buckets at most once a gap where a new network arrives, as well as once
    /// a minute
    network_ceiling: Arc<crate::bounded::Ceiling>,

    /// Parsed trusted proxy CIDRs
    trusted_cidrs: Arc<RwLock<Vec<ipnet::IpNet>>>,

    /// The proxy's own request rate: requests a second, sampled each second
    global_baseline: arc_swap::ArcSwap<AdaptiveBaseline>,

    /// The second (since `started`) being counted for `global_baseline`, and
    /// the requests counted in it so far
    global_second: AtomicU64,
    global_count: AtomicU64,
    started: Instant,

    /// Statistics
    stats: Arc<RateLimiterStats>,

    /// Optional Redis backend for distributed rate limiting.
    ///
    /// `None` until the async connection task completes (or when Redis is not
    /// configured).  Falls back to `buckets` (in-memory) on every `None`.
    redis_backend: Arc<AsyncRwLock<Option<Arc<RedisBackend>>>>,

    /// Where a refused request is recorded, once the audit log exists
    audit: std::sync::OnceLock<Arc<crate::audit_logger::AuditLogger>>,

    /// The autonomous system announcing an address (the `asn` key), once
    /// the security layer's ASN database is attached
    asn_of: std::sync::OnceLock<AsnLookup>,
}

/// The node's own quota (`global_limits`).
fn global_limiter_of(limits: &GlobalLimits) -> RateLimiter<NotKeyed, InMemoryState, DefaultClock> {
    let rps = NonZeroU32::new(limits.requests_per_second.max(1)).unwrap_or(NonZeroU32::MIN);
    let burst = NonZeroU32::new(limits.burst_size.max(1)).unwrap_or(NonZeroU32::MIN);
    RateLimiter::direct(Quota::per_second(rps).allow_burst(burst))
}

/// The proxy's own request-rate baseline, as `adaptive` sets it.
fn baseline_of(adaptive: &AdaptiveConfig) -> AdaptiveBaseline {
    AdaptiveBaseline::new(
        adaptive.baseline_window_secs,
        adaptive.min_samples,
        effective_std_dev_multiplier(adaptive),
    )
}

/// The autonomous system announcing an address, if it is known.
pub type AsnLookup = Arc<dyn Fn(IpAddr) -> Option<u32> + Send + Sync>;

/// Rate limiter statistics
#[derive(Debug, Default)]
pub struct RateLimiterStats {
    pub total_requests: AtomicU64,
    pub total_allowed: AtomicU64,
    pub total_limited: AtomicU64,
    pub total_blocked: AtomicU64,
}

impl AdvancedRateLimiter {
    /// Create a new advanced rate limiter.
    ///
    /// If `config.redis` is present, a background task is spawned to establish
    /// the Redis connection.  Until that task completes (or if Redis is absent)
    /// all rate-limiting falls back to the in-memory DashMap buckets.
    pub fn new(config: AdvancedRateLimitConfig) -> Self {
        // Parse trusted proxy CIDRs
        let trusted_cidrs: Vec<ipnet::IpNet> = config
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                // First try CIDR notation (e.g., "10.0.0.0/8")
                match s.parse::<ipnet::IpNet>() {
                    Ok(net) => Some(net),
                    Err(_) => {
                        // Try parsing as single IP address
                        match s.parse::<IpAddr>() {
                            Ok(IpAddr::V4(v4)) => {
                                ipnet::Ipv4Net::new(v4, 32).ok().map(ipnet::IpNet::V4)
                            }
                            Ok(IpAddr::V6(v6)) => {
                                ipnet::Ipv6Net::new(v6, 128).ok().map(ipnet::IpNet::V6)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse trusted proxy '{}' as CIDR or IP: {}",
                                    s,
                                    e
                                );
                                None
                            }
                        }
                    }
                }
            })
            .collect();

        let global_limiter = global_limiter_of(&config.global_limits);
        let global_baseline = baseline_of(&config.adaptive);

        // Stash the Redis config before consuming `config`.
        let redis_cfg = config.redis.clone();

        let redis_backend = Arc::new(AsyncRwLock::new(None::<Arc<RedisBackend>>));

        let limiter = Self {
            config: Arc::new(RwLock::new(config)),
            global_limiter: arc_swap::ArcSwap::from_pointee(global_limiter),
            buckets: Arc::new(DashMap::new()),
            route_buckets: Arc::new(DashMap::new()),
            overflow_buckets: Arc::new(DashMap::new()),
            network_ceiling: Arc::new(crate::bounded::Ceiling::new(
                Self::MAX_TRACKED_KEYS,
                Duration::from_secs(5),
            )),
            trusted_cidrs: Arc::new(RwLock::new(trusted_cidrs)),
            global_baseline: arc_swap::ArcSwap::from_pointee(global_baseline),
            stats: Arc::new(RateLimiterStats::default()),
            redis_backend,
            audit: std::sync::OnceLock::new(),
            asn_of: std::sync::OnceLock::new(),
            global_second: AtomicU64::new(0),
            global_count: AtomicU64::new(0),
            started: Instant::now(),
        };

        // Spawn cleanup task
        limiter.spawn_cleanup_task();

        // Spawn Redis connection task (if configured)
        if let Some(rcfg) = redis_cfg {
            let slot = limiter.redis_backend.clone();
            tokio::spawn(async move {
                match RedisBackend::connect(&rcfg).await {
                    Ok(backend) => {
                        *slot.write().await = Some(Arc::new(backend));
                        info!("Distributed rate limiting: Redis connected at {}", rcfg.url);
                    }
                    Err(e) => {
                        warn!(
                            "Distributed rate limiting: could not connect to Redis at {} — \
                             falling back to in-memory rate limiting. Error: {}",
                            rcfg.url, e
                        );
                    }
                }
            });
        }

        limiter
    }

    /// Check if the request is allowed.
    ///
    /// When a Redis backend is connected the per-key token-bucket and
    /// sliding-window checks are performed against Redis so that all proxy
    /// instances in the cluster share the same counters.  On any Redis error
    /// (timeout, connection loss, etc.) the check falls back silently to the
    /// in-process `DashMap` bucket for that single request.
    ///
    /// The **global** token-bucket always runs in-process so that each node
    /// can protect itself from being overwhelmed even when Redis is down.
    pub async fn check(&self, ctx: &RateLimitContext) -> RateLimitResult {
        let result = self.decide(ctx).await;
        if let (RateLimitResult::Limited { limit, .. }, Some(audit)) = (&result, self.audit.get()) {
            audit.log_rate_limit(ctx.source_ip, &ctx.path, *limit);
        }
        result
    }

    /// Record refused requests in the audit log.
    pub fn set_audit_logger(&self, logger: Arc<crate::audit_logger::AuditLogger>) {
        let _ = self.audit.set(logger);
    }

    /// Resolve the `asn` key with `lookup` (once, at startup).
    pub fn set_asn_lookup(&self, lookup: AsnLookup) {
        let _ = self.asn_of.set(lookup);
    }

    /// Whether any limit is keyed on the autonomous system.
    pub fn uses_asn_key(&self) -> bool {
        let config = self.config.read();
        let named = |t: &RateLimitKeyType| matches!(t, RateLimitKeyType::Asn);
        config.key_strategy.order.iter().any(named)
            || named(&config.key_strategy.fallback)
            || config
                .composite_keys
                .iter()
                .any(|c| c.keys.iter().any(named))
    }

    async fn decide(&self, ctx: &RateLimitContext) -> RateLimitResult {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // ── SYNC PHASE ───────────────────────────────────────────────────────
        // `parking_lot::RwLockReadGuard` is `!Send`.  If it is alive when the
        // compiler encounters any `.await` point the resulting future becomes
        // `!Send`, which breaks axum's middleware requirement.
        //
        // Strategy: do ALL config access inside a scope block so the guard is
        // dropped before we enter the async phase below.
        struct SyncData {
            charges: Vec<Charge>,
            adaptive_enabled: bool,
            adaptive_cfg: AdaptiveConfig,
        }

        let sync_data: Option<SyncData> = {
            let config = self.config.read(); // !Send guard — dropped at end of block

            if !config.enabled {
                return RateLimitResult::Allowed {
                    remaining: u32::MAX,
                    limit: u32::MAX,
                };
            }

            // Global limit (in-process DDoS protection per node)
            if self.global_limiter.load().check().is_err() {
                self.stats.total_limited.fetch_add(1, Ordering::Relaxed);
                return RateLimitResult::Limited {
                    reason: LimitReason::Global,
                    retry_after_ms: 1000,
                    limit: config.global_limits.requests_per_second,
                };
            }

            // Blocked fingerprint check (config-driven, no I/O)
            if let Some(ref ja3) = ctx.ja3_hash {
                if config
                    .fingerprint_limiting
                    .blocked_fingerprints
                    .contains(ja3)
                {
                    self.stats.total_blocked.fetch_add(1, Ordering::Relaxed);
                    return RateLimitResult::Blocked {
                        reason: format!("Blocked fingerprint: {}", ja3),
                    };
                }
            }

            // Resolve key + limits; clone what we need for the async phase.
            let (key, limits) = self.resolve_key_and_limits(ctx, &config);

            // `route_limits.<route>.exempt_keys` names the key values that this
            // route does not rate-limit — a health-check API key, a monitoring
            // agent's fingerprint, an internal caller's IP.  The field was
            // parsed and stored and read by nothing, so every listed key was
            // limited exactly like an anonymous one.  Compare against the
            // resolved key's value, which is what the operator writes in the
            // list, rather than the internal `type:value` string.
            if let Some(route_name) = &ctx.route_name {
                if let Some(route_limits) = config.route_limits.get(route_name) {
                    let bare = key
                        .value
                        .split_once('#')
                        .map_or(key.value.as_str(), |(_, v)| v);
                    if route_limits.exempt_keys.iter().any(|k| k == bare) {
                        return RateLimitResult::Allowed {
                            remaining: u32::MAX,
                            limit: u32::MAX,
                        };
                    }
                }
            }

            Some(SyncData {
                charges: self.charges(ctx, &config, &key, limits),
                adaptive_enabled: config.adaptive.enabled,
                adaptive_cfg: config.adaptive.clone(),
            })
            // config guard is dropped here — safe to .await after this point
        };

        let Some(SyncData {
            charges,
            adaptive_enabled,
            adaptive_cfg,
        }) = sync_data
        else {
            // Every way out of the block above that is not a `Some` returned.
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                limit: u32::MAX,
            };
        };

        // ── ASYNC PHASE ──────────────────────────────────────────────────────
        // The parking_lot guard is gone; it is safe to `.await` here.

        // Clone the Redis backend Arc out from under the async RwLock before
        // any downstream `.await` so the tokio RwLockReadGuard is not held
        // across any subsequent await point either.
        let redis_backend: Option<Arc<RedisBackend>> = {
            let guard = self.redis_backend.read().await;
            guard.clone() // cheap Arc::clone; guard dropped immediately
        };

        // Each bucket in turn, the address's own first: a request it refuses
        // is counted nowhere else, so a refused client cannot make buckets.
        // An allowed request reports the tightest of what it was counted in.
        let mut result = RateLimitResult::Allowed {
            remaining: u32::MAX,
            limit: u32::MAX,
        };
        for charge in &charges {
            // Redis holds the buckets of keys a client cannot choose. One
            // keyed on a value the client wrote is counted here, where the
            // number kept is bounded: in Redis every new value would be a
            // new set of keys.
            let counted = match redis_backend.as_ref().filter(|_| charge.network_bound) {
                Some(backend) => self.check_distributed(backend, charge, &adaptive_cfg).await,
                // No Redis configured or not yet connected — use local bucket
                None => self.check_local(charge, &adaptive_cfg),
            };
            match (&result, counted) {
                (
                    RateLimitResult::Allowed {
                        remaining: held, ..
                    },
                    RateLimitResult::Allowed { remaining, limit },
                ) => {
                    if remaining <= *held {
                        result = RateLimitResult::Allowed { remaining, limit };
                    }
                }
                (_, refused) => {
                    result = refused;
                    break;
                }
            }
        }

        if adaptive_enabled {
            self.count_for_global_baseline();
        }

        match &result {
            RateLimitResult::Allowed { .. } => {
                self.stats.total_allowed.fetch_add(1, Ordering::Relaxed);
            }
            RateLimitResult::Limited { .. } => {
                self.stats.total_limited.fetch_add(1, Ordering::Relaxed);
            }
            RateLimitResult::Blocked { .. } => {
                self.stats.total_blocked.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

    // ── Internal: distributed Redis path ────────────────────────────────────

    async fn check_distributed(
        &self,
        backend: &RedisBackend,
        charge: &Charge,
        adaptive_cfg: &AdaptiveConfig,
    ) -> RateLimitResult {
        let (key_string, limits) = (charge.key_string.as_str(), &charge.limits);
        // Per-second token bucket via Redis (or local governor fallback)
        let tb_result = backend
            .check_token_bucket(key_string, limits.requests_per_second, limits.burst_size)
            .await;

        let token_result = match tb_result {
            Some(r) => r,
            // Redis failed → local governor
            None => self.check_local(charge, adaptive_cfg),
        };

        if !matches!(token_result, RateLimitResult::Allowed { .. }) {
            return token_result;
        }

        // Per-minute sliding window
        if let Some(rpm) = limits.requests_per_minute {
            let sw = backend
                .check_sliding_window(key_string, rpm, 60, "1m")
                .await;
            match sw {
                Some(r @ RateLimitResult::Limited { .. }) => return r,
                Some(_) => {} // allowed
                None => {
                    // Redis failed — check local minute counter
                    let local = self.get_or_create_bucket(charge, adaptive_cfg);
                    if let Some(ref counter) = local.minute_counter {
                        let count = counter.increment();
                        if count > u64::from(rpm) {
                            local.total_blocked.fetch_add(1, Ordering::Relaxed);
                            return RateLimitResult::Limited {
                                reason: LimitReason::PerMinute,
                                retry_after_ms: 60_000,
                                limit: rpm,
                            };
                        }
                    }
                }
            }
        }

        // Per-hour sliding window
        if let Some(rph) = limits.requests_per_hour {
            let sw = backend
                .check_sliding_window(key_string, rph, 3600, "1h")
                .await;
            match sw {
                Some(r @ RateLimitResult::Limited { .. }) => return r,
                Some(_) => {} // allowed
                None => {
                    // Redis failed — check local hour counter
                    let local = self.get_or_create_bucket(charge, adaptive_cfg);
                    if let Some(ref counter) = local.hour_counter {
                        let count = counter.increment();
                        if count > u64::from(rph) {
                            local.total_blocked.fetch_add(1, Ordering::Relaxed);
                            return RateLimitResult::Limited {
                                reason: LimitReason::PerHour,
                                retry_after_ms: 3_600_000,
                                limit: rph,
                            };
                        }
                    }
                }
            }
        }

        // Adaptive anomaly detection (always local — per-node baseline)
        self.check_adaptive(charge, adaptive_cfg)
    }

    // ── Internal: local in-memory path ──────────────────────────────────────

    fn check_local(&self, charge: &Charge, adaptive_cfg: &AdaptiveConfig) -> RateLimitResult {
        let bucket = self.get_or_create_bucket(charge, adaptive_cfg);
        bucket.check(&charge.limits, adaptive_cfg)
    }

    /// The bucket `charge` is counted in, made on first use.
    ///
    /// The map holds at most [`Self::MAX_TRACKED_KEYS`] buckets. Past the
    /// limit, a key the client chose is counted in a bucket of its own that is
    /// not kept, so the map's size does not follow the number of values
    /// clients send; the address's bucket is the one that holds such a
    /// client. A network's own bucket is kept while there is room: a full map
    /// is swept of buckets idle five minutes at most once a gap, and a network
    /// that still finds it full is counted in its route's overflow bucket, so
    /// the map does not follow the number of networks either (an IPv6 /48
    /// holds 65,536 /64s) and none of them goes unlimited.
    fn get_or_create_bucket(
        &self,
        charge: &Charge,
        adaptive_cfg: &AdaptiveConfig,
    ) -> Arc<RateLimitBucket> {
        if let Some(bucket) = self.buckets.get(&charge.key_string) {
            return Arc::clone(bucket.value());
        }
        if self.buckets.len() >= Self::MAX_TRACKED_KEYS {
            if !charge.network_bound {
                return Arc::new(RateLimitBucket::new(&charge.limits, Some(adaptive_cfg)));
            }
            let admitted = self.network_ceiling.admits(self.buckets.len(), || {
                self.buckets
                    .retain(|_, bucket| bucket.last_request.read().elapsed() < BUCKET_IDLE);
                self.buckets.len()
            });
            if !admitted {
                return self
                    .overflow_buckets
                    .entry(overflow_key(&charge.key_string))
                    .or_insert_with(|| {
                        Arc::new(RateLimitBucket::new(&charge.limits, Some(adaptive_cfg)))
                    })
                    .clone();
            }
        }
        self.buckets
            .entry(charge.key_string.clone())
            .or_insert_with(|| Arc::new(RateLimitBucket::new(&charge.limits, Some(adaptive_cfg))))
            .clone()
    }

    fn check_adaptive(&self, charge: &Charge, adaptive_cfg: &AdaptiveConfig) -> RateLimitResult {
        let limits = &charge.limits;
        if !adaptive_cfg.enabled {
            return RateLimitResult::Allowed {
                remaining: limits.requests_per_second.saturating_sub(1),
                limit: limits.requests_per_second,
            };
        }
        let bucket = self.get_or_create_bucket(charge, adaptive_cfg);
        if let Some(ref baseline) = bucket.baseline {
            let recent_count = bucket
                .minute_counter
                .as_ref()
                .map(|c| c.get_count())
                .unwrap_or(0);
            baseline.record(recent_count);
            if baseline.is_anomaly(recent_count) {
                bucket.total_blocked.fetch_add(1, Ordering::Relaxed);
                return RateLimitResult::Limited {
                    reason: LimitReason::AnomalyDetected,
                    retry_after_ms: 60_000,
                    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    limit: baseline.get_mean().clamp(0.0, f64::from(u32::MAX)) as u32,
                };
            }
        }
        RateLimitResult::Allowed {
            remaining: limits.requests_per_second.saturating_sub(1),
            limit: limits.requests_per_second,
        }
    }

    /// Resolve rate limit key and applicable limits
    /// The buckets one request is counted in.
    ///
    /// A key the client cannot choose (its address, a verified subject) is one
    /// bucket, as it always was. Any other key (an API key header, a TLS
    /// fingerprint, a cookie) is counted beside the bucket of the network the
    /// request came from, and that bucket first: a client that presents a new
    /// value with every request then gets a new bucket for the value and the
    /// same one for its address, which is the one that holds it. On a route
    /// with limits of its own, the address's bucket there is the route's.
    fn charges(
        &self,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
        key: &RateLimitKey,
        limits: PerKeyLimits,
    ) -> Vec<Charge> {
        let network = self.normalize_ip(ctx.source_ip, config.ipv6_subnet_bits);
        let mut charges = Vec::with_capacity(2);
        if !key.is_network_bound() {
            let route = ctx
                .route_name
                .as_ref()
                .filter(|name| config.route_limits.contains_key(name.as_str()));
            let floor = match route {
                Some(route) => Charge {
                    key_string: format!("{:?}:{route}#{network}", RateLimitKeyType::SourceIp),
                    limits: limits.clone(),
                    network_bound: true,
                },
                None => Charge {
                    key_string: format!("{:?}:{network}", RateLimitKeyType::SourceIp),
                    limits: self.get_limits_for_key(&RateLimitKeyType::SourceIp, &network, config),
                    network_bound: true,
                },
            };
            let floor_key = floor.key_string.clone();
            charges.push(floor);
            // A value the client wrote names a bucket of its own and never
            // replaces the one the request has without it: an unverified API
            // key cannot lift a client past its fingerprint's budget.
            if key.is_client_written() {
                if let Some((identity, identity_limits)) = self.unwritten_identity(ctx, config) {
                    let key_string = identity.storage_key(&network);
                    if key_string != floor_key {
                        charges.push(Charge {
                            key_string,
                            limits: identity_limits,
                            network_bound: identity.is_network_bound(),
                        });
                    }
                }
            }
        }
        charges.push(Charge {
            key_string: key.storage_key(&network),
            limits,
            network_bound: key.is_network_bound(),
        });
        charges
    }

    /// The key and limits a request resolves to when the values it wrote
    /// itself are set aside: the fingerprint keys first where
    /// `fingerprint_limiting.prefer_over_ip` asks for that, then the first
    /// key of `key_strategy.order` that is not client-written and resolves.
    fn unwritten_identity(
        &self,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
    ) -> Option<(RateLimitKey, PerKeyLimits)> {
        let preferred: &[RateLimitKeyType] =
            if config.fingerprint_limiting.enabled && config.fingerprint_limiting.prefer_over_ip {
                &[
                    RateLimitKeyType::Ja3Fingerprint,
                    RateLimitKeyType::Ja4Fingerprint,
                ]
            } else {
                &[]
            };
        preferred
            .iter()
            .chain(&config.key_strategy.order)
            .filter(|key_type| !key_type.is_client_written())
            .filter(|key_type| !matches!(key_type, RateLimitKeyType::Composite(_)))
            .find_map(|key_type| {
                let value = self.extract_key_value(key_type, ctx, config)?;
                let limits = self.get_limits_for_key(key_type, &value, config);
                Some((RateLimitKey::new(key_type.clone(), value), limits))
            })
    }

    fn resolve_key_and_limits(
        &self,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
    ) -> (RateLimitKey, PerKeyLimits) {
        // Check for route-specific overrides first.
        //
        // `key_override` used to be the only way a route's limits took effect:
        // without one this fell straight through to the waterfall, which
        // resolved the ordinary per-IP key AND the ordinary per-IP limits, so a
        // route configured at 2 rps was served at the global 1000 rps.  A
        // `[route_limits.*]` block with no `key_override` is the common shape —
        // it is how you say "this endpoint is stricter than the rest" — so it
        // has to work on its own.
        //
        // The key is namespaced with the route name either way.  Sharing the
        // unprefixed per-IP key would put the route's traffic in the same
        // bucket as everything else from that address, which both double-counts
        // ordinary requests and lets other traffic exhaust the route's budget.
        if let Some(route_name) = &ctx.route_name {
            if let Some(route_limits) = config.route_limits.get(route_name) {
                let key_type = route_limits
                    .key_override
                    .clone()
                    .unwrap_or_else(|| config.key_strategy.fallback.clone());
                let value = self
                    .extract_key_value(&key_type, ctx, config)
                    .unwrap_or_else(|| ctx.source_ip.to_string());
                return (
                    RateLimitKey::new(key_type, format!("{route_name}#{value}")),
                    route_limits.limits.clone(),
                );
            }
        }

        // Check composite keys first (if configured)
        if config.key_strategy.use_composite && !config.composite_keys.is_empty() {
            for composite in &config.composite_keys {
                // Check if applies to current route
                if !composite.routes.is_empty() {
                    if let Some(ref route) = ctx.route_name {
                        if !composite.routes.contains(route) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                // Try to extract all component keys
                let mut components = Vec::new();
                let mut all_found = true;

                for key_type in &composite.keys {
                    if let Some(value) = self.extract_key_value(key_type, ctx, config) {
                        components.push((key_type.clone(), value));
                    } else {
                        all_found = false;
                        break;
                    }
                }

                if all_found {
                    return (
                        RateLimitKey::composite(components),
                        composite.limits.clone(),
                    );
                }
            }
        }

        // `fingerprint_limiting.prefer_over_ip` exists for NAT: behind one
        // public address a TLS fingerprint separates clients that an IP cannot.
        // It was declared, defaulted and documented, and then never read — so
        // any deployment whose `key_strategy.order` listed an IP key first
        // (the common shape) rate-limited an entire NAT as a single client.
        // Honour it by trying the fingerprint keys ahead of the waterfall.
        if config.fingerprint_limiting.enabled && config.fingerprint_limiting.prefer_over_ip {
            for key_type in [
                RateLimitKeyType::Ja3Fingerprint,
                RateLimitKeyType::Ja4Fingerprint,
            ] {
                if let Some(value) = self.extract_key_value(&key_type, ctx, config) {
                    let limits = self.get_limits_for_key(&key_type, &value, config);
                    return (RateLimitKey::new(key_type, value), limits);
                }
            }
        }

        // Waterfall through key resolution order
        for key_type in &config.key_strategy.order {
            if let Some(value) = self.extract_key_value(key_type, ctx, config) {
                let limits = self.get_limits_for_key(key_type, &value, config);
                return (RateLimitKey::new(key_type.clone(), value), limits);
            }
        }

        // Fallback
        let fallback_value = self
            .extract_key_value(&config.key_strategy.fallback, ctx, config)
            .unwrap_or_else(|| ctx.source_ip.to_string());

        let limits =
            self.get_limits_for_key(&config.key_strategy.fallback, &fallback_value, config);

        (
            RateLimitKey::new(config.key_strategy.fallback.clone(), fallback_value),
            limits,
        )
    }

    /// Extract value for a key type
    fn extract_key_value(
        &self,
        key_type: &RateLimitKeyType,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
    ) -> Option<String> {
        match key_type {
            RateLimitKeyType::SourceIp => {
                Some(self.normalize_ip(ctx.source_ip, config.ipv6_subnet_bits))
            }

            RateLimitKeyType::RealIp => self
                .extract_real_ip(ctx, config)
                .map(|ip| self.normalize_ip(ip, config.ipv6_subnet_bits)),

            RateLimitKeyType::ApiKey => ctx.get_header(&config.headers.api_key).cloned(),

            RateLimitKeyType::JwtSubject => {
                // H-2: JWT subject extraction requires a configured signing secret.
                // Without signature verification the `sub` claim is attacker-controlled,
                // so we return None (disabling JWT-based rate limiting) when no secret is set.
                ctx.get_header("authorization").and_then(|auth| {
                    let algs: Vec<&str> =
                        config.jwt_algorithms.iter().map(String::as_str).collect();
                    self.extract_jwt_subject(auth, config.jwt_secret.as_deref(), &algs)
                })
            }

            RateLimitKeyType::Ja3Fingerprint => ctx.ja3_hash.clone(),

            RateLimitKeyType::Ja4Fingerprint => ctx.ja4_hash.clone(),

            RateLimitKeyType::Header(name) => ctx.get_header(name).cloned(),

            RateLimitKeyType::Cookie(name) => ctx.get_cookie(name).cloned(),

            RateLimitKeyType::QueryParam(name) => ctx.get_query_param(name).cloned(),

            RateLimitKeyType::Path => Some(ctx.path.clone()),

            RateLimitKeyType::Method => Some(ctx.method.clone()),

            // The network the address is announced from: one bucket for every
            // client a provider hosts (the security layer's ASN database)
            RateLimitKeyType::Asn => self
                .asn_of
                .get()
                .and_then(|lookup| lookup(ctx.source_ip))
                .map(|asn| format!("AS{asn}")),

            RateLimitKeyType::Composite(_) => {
                // Composite keys are not extracted directly - they are built
                // from individual components in resolve_key_and_limits
                None
            }
        }
    }

    /// Normalize IP address (apply IPv6 subnet grouping)
    fn normalize_ip(&self, ip: IpAddr, ipv6_subnet_bits: u8) -> String {
        match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => {
                // Apply subnet mask for IPv6
                if ipv6_subnet_bits < 128 {
                    let mask = !0u128 << (128 - ipv6_subnet_bits);
                    let masked = u128::from(v6) & mask;
                    Ipv6Addr::from(masked).to_string()
                } else {
                    v6.to_string()
                }
            }
        }
    }

    /// Extract real IP from X-Forwarded-For (only from trusted proxies)
    fn extract_real_ip(
        &self,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
    ) -> Option<IpAddr> {
        // Check if source IP is a trusted proxy
        let trusted_cidrs = self.trusted_cidrs.read();
        let is_trusted = trusted_cidrs
            .iter()
            .any(|cidr| cidr.contains(&ctx.source_ip));

        if !is_trusted {
            return None;
        }

        // Try X-Forwarded-For first
        if let Some(xff) = ctx.get_header("x-forwarded-for") {
            // Get the rightmost untrusted IP
            let ips: Vec<&str> = xff.split(',').map(|s| s.trim()).collect();
            for ip_str in ips.iter().rev() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !trusted_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                        return Some(ip);
                    }
                }
            }
            // If all are trusted, use the first one
            if let Some(first) = ips.first() {
                if let Ok(ip) = first.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        // Try X-Real-IP
        if let Some(real_ip) = ctx.get_header(&config.headers.real_ip) {
            if let Ok(ip) = real_ip.parse::<IpAddr>() {
                return Some(ip);
            }
        }

        None
    }

    /// Extract and verify the `sub` claim from a JWT Bearer token.
    ///
    /// H-2: Signature verification is mandatory.  If `jwt_secret` is `None` this
    /// function returns `None`, effectively disabling JWT-based rate limiting.
    /// This prevents an attacker from forging any `sub` value by crafting a JWT
    /// with an unsigned or differently-signed payload.
    ///
    /// F-10: Only algorithms listed in `allowed_algorithms` are accepted.
    /// The default is `["HS256"]`.  Non-HMAC algorithms (RS256, ES256, etc.) are
    /// silently rejected to prevent algorithm-confusion attacks where a client
    /// substitutes a different signing scheme.
    fn extract_jwt_subject(
        &self,
        auth_header: &str,
        jwt_secret: Option<&str>,
        allowed_algorithms: &[&str],
    ) -> Option<String> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};
        use serde::Deserialize;

        // H-2: No secret → refuse to extract (trust-only mode is insecure for rate limiting)
        let secret = jwt_secret?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))?;

        #[derive(Deserialize)]
        struct Claims {
            sub: String,
        }

        // SR-05: Pre-validate the JWT header before attempting signature
        // verification.  This explicitly catches algorithm confusion attacks
        // (including any `alg: none` variant) before the full decode path runs,
        // providing defense-in-depth on top of the algorithm whitelist below.
        let header = match jsonwebtoken::decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                debug!("SR-05: JWT header decode failed: {}", e);
                return None;
            }
        };
        // Only HMAC algorithms are accepted; everything else — including any
        // future `Algorithm::None` variant — is rejected here.
        if !matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            warn!(
                "SR-05: JWT with disallowed algorithm {:?} rejected (expected HMAC only)",
                header.alg
            );
            return None;
        }

        // F-10: Parse only the operator-configured HMAC algorithms.
        // Non-HMAC strings are silently skipped; if the list resolves to
        // empty the extraction is disabled (safe default).
        let parsed: Vec<Algorithm> = allowed_algorithms
            .iter()
            .filter_map(|alg| match *alg {
                "HS256" => Some(Algorithm::HS256),
                "HS384" => Some(Algorithm::HS384),
                "HS512" => Some(Algorithm::HS512),
                other => {
                    warn!(
                        "F-10: JWT algorithm '{}' is not an HMAC variant (HS256/HS384/HS512) \
                         and cannot be used with a shared secret; ignoring",
                        other
                    );
                    None
                }
            })
            .collect();

        if parsed.is_empty() {
            debug!("F-10: No valid HMAC algorithms configured for JWT rate-limit extraction");
            return None;
        }

        let key = DecodingKey::from_secret(secret.as_bytes());
        // Use the first algorithm as the primary for Validation::new, then
        // override the full list to accept exactly what was configured.
        let mut validation = Validation::new(parsed[0]);
        validation.algorithms = parsed;

        match jsonwebtoken::decode::<Claims>(token, &key, &validation) {
            Ok(token_data) => Some(token_data.claims.sub),
            Err(e) => {
                debug!("JWT verification failed for rate limiting: {}", e);
                None
            }
        }
    }

    /// Get limits for a specific key type and value
    fn get_limits_for_key(
        &self,
        key_type: &RateLimitKeyType,
        value: &str,
        config: &AdvancedRateLimitConfig,
    ) -> PerKeyLimits {
        // Check for fingerprint-specific limits.
        //
        // Two knobs used to be inert here.  `fingerprint_limiting.enabled` was
        // never consulted, so turning the subsystem off left its limits fully
        // in force; and `global_limits.per_fingerprint` — a complete limit
        // block sat alongside per_ip/per_api_key/per_composite — was read by
        // nothing at all, so an operator who tuned it got `unknown_limits`
        // regardless.  `per_fingerprint` is now the base for a fingerprint key,
        // which `fingerprint_limiting` refines when it is switched on.
        if matches!(
            key_type,
            RateLimitKeyType::Ja3Fingerprint | RateLimitKeyType::Ja4Fingerprint
        ) {
            if !config.fingerprint_limiting.enabled {
                return config.global_limits.per_fingerprint.clone();
            }
            if let Some(limits) = config.fingerprint_limiting.trusted_fingerprints.get(value) {
                return limits.clone();
            }
            return config.fingerprint_limiting.unknown_limits.clone();
        }

        // API key limits — configurable via [advanced_rate_limiting.global_limits.per_api_key]
        if matches!(key_type, RateLimitKeyType::ApiKey) {
            return config.global_limits.per_api_key.clone();
        }

        // A verified JWT subject is one user across however many addresses.
        if matches!(key_type, RateLimitKeyType::JwtSubject) {
            return config.global_limits.per_jwt_subject.clone();
        }

        // Composite keys get their limits from CompositeKeyConfig directly
        // in resolve_key_and_limits, but fall back to the configurable default here.
        if matches!(key_type, RateLimitKeyType::Composite(_)) {
            return config.global_limits.per_composite.clone();
        }

        // Default per-IP limits — configurable via [advanced_rate_limiting.global_limits.per_ip]
        config.global_limits.per_ip.clone()
    }

    /// Maximum number of tracked keys to prevent DoS through memory exhaustion
    const MAX_TRACKED_KEYS: usize = 100_000;

    /// Spawn background cleanup task
    fn spawn_cleanup_task(&self) {
        let buckets = self.buckets.clone();
        let route_buckets = self.route_buckets.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            loop {
                interval.tick().await;

                let idle_threshold = BUCKET_IDLE;

                // Clean up idle buckets
                // Buckets are added while this runs: the count is approximate
                let before_count = buckets.len();
                buckets.retain(|_, bucket| bucket.last_request.read().elapsed() < idle_threshold);
                let removed = before_count.saturating_sub(buckets.len());
                if removed > 0 {
                    debug!("Cleaned up {} idle rate limit buckets", removed);
                }

                // Enforce max size limit - remove oldest entries if over limit
                let current_count = buckets.len();
                if current_count > Self::MAX_TRACKED_KEYS {
                    // Collect entries with their last request times
                    let mut entries: Vec<_> = buckets
                        .iter()
                        .map(|e| (e.key().clone(), *e.value().last_request.read()))
                        .collect();

                    // Sort by last request time (oldest first)
                    entries.sort_by_key(|(_, time)| *time);

                    // Remove oldest entries to get back under limit
                    let to_remove = current_count - Self::MAX_TRACKED_KEYS;
                    for (key, _) in entries.into_iter().take(to_remove) {
                        buckets.remove(&key);
                    }
                    warn!(
                        "Rate limiter reached max capacity, evicted {} oldest entries",
                        to_remove
                    );
                }

                // Clean up route buckets
                for entry in route_buckets.iter() {
                    entry
                        .value()
                        .retain(|_, bucket| bucket.last_request.read().elapsed() < idle_threshold);
                }
            }
        });
    }

    /// Get current statistics (sync snapshot — does not await Redis).
    pub fn get_stats(&self) -> RateLimiterSnapshot {
        // Non-blocking peek at whether Redis is up.  We try_read() so this
        // method remains synchronous and can be called from non-async contexts.
        let redis_connected = self
            .redis_backend
            .try_read()
            .map(|g| g.is_some())
            .unwrap_or(false); // lock held → assume state unknown, report false

        RateLimiterSnapshot {
            total_requests: self.stats.total_requests.load(Ordering::Relaxed),
            total_allowed: self.stats.total_allowed.load(Ordering::Relaxed),
            total_limited: self.stats.total_limited.load(Ordering::Relaxed),
            total_blocked: self.stats.total_blocked.load(Ordering::Relaxed),
            keys_tracked: self.buckets.len(),
            global_baseline_mean: self.global_baseline.load().get_mean(),
            global_baseline_std_dev: self.global_baseline.load().get_std_dev(),
            redis_connected,
        }
    }

    /// Count one request toward the second it arrived in; the first request
    /// of a new second gives the one before to the global baseline.
    fn count_for_global_baseline(&self) {
        let second = self.started.elapsed().as_secs();
        if self.global_second.swap(second, Ordering::AcqRel) == second {
            self.global_count.fetch_add(1, Ordering::AcqRel);
        } else {
            let previous = self.global_count.swap(1, Ordering::AcqRel);
            self.global_baseline.load().record(previous);
        }
    }

    /// Drop every bucket, global or per-route, whose key is `key` or has a
    /// component equal to it, so a client's limits start fresh. `key` may be a
    /// whole key (`SourceIp:203.0.113.7`) or just its value (`203.0.113.7`),
    /// which also clears composite keys containing it. Returns buckets removed.
    pub fn reset_key(&self, key: &str) -> usize {
        // A value sits after its type's name; on a route it follows `route#`,
        // and a fingerprint is followed by `@network`.
        let matches = |k: &str| {
            k == key
                || k.split('|').any(|part| {
                    part == key
                        || part.split_once(':').is_some_and(|(_, v)| {
                            v == key || v.split(['#', '@']).any(|piece| piece == key)
                        })
                })
        };
        let mut removed = 0;
        self.buckets.retain(|k, _| {
            let hit = matches(k);
            removed += usize::from(hit);
            !hit
        });
        for route in self.route_buckets.iter() {
            route.value().retain(|k, _| {
                let hit = matches(k);
                removed += usize::from(hit);
                !hit
            });
        }
        removed
    }

    pub fn update_config(&self, config: AdvancedRateLimitConfig) {
        // Update trusted CIDRs with proper error logging
        let trusted_cidrs: Vec<ipnet::IpNet> = config
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                // First try CIDR notation (e.g., "10.0.0.0/8")
                match s.parse::<ipnet::IpNet>() {
                    Ok(net) => Some(net),
                    Err(_) => {
                        // Try parsing as single IP address
                        match s.parse::<IpAddr>() {
                            Ok(IpAddr::V4(v4)) => {
                                ipnet::Ipv4Net::new(v4, 32).ok().map(ipnet::IpNet::V4)
                            }
                            Ok(IpAddr::V6(v6)) => {
                                ipnet::Ipv6Net::new(v6, 128).ok().map(ipnet::IpNet::V6)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to parse trusted proxy '{}' as CIDR or IP: {}",
                                    s,
                                    e
                                );
                                None
                            }
                        }
                    }
                }
            })
            .collect();

        *self.trusted_cidrs.write() = trusted_cidrs;

        // What was built from the configuration is built again from the new
        // one where it changed: the node's quota and its baseline, and every
        // key's bucket (each carries its quota, counters and baseline from
        // when it was made, so a key that stayed busy kept the old limits)
        let previous = self.config.read().clone();
        let differs = |a: serde_json::Result<serde_json::Value>,
                       b: serde_json::Result<serde_json::Value>| {
            a.ok() != b.ok()
        };
        if differs(
            serde_json::to_value(&previous.global_limits),
            serde_json::to_value(&config.global_limits),
        ) {
            self.global_limiter
                .store(Arc::new(global_limiter_of(&config.global_limits)));
        }
        if differs(
            serde_json::to_value(&previous.adaptive),
            serde_json::to_value(&config.adaptive),
        ) {
            self.global_baseline
                .store(Arc::new(baseline_of(&config.adaptive)));
        }
        let rebuilt = differs(
            serde_json::to_value(&previous),
            serde_json::to_value(&config),
        );
        *self.config.write() = config;
        if rebuilt {
            self.buckets.clear();
            self.route_buckets.clear();
            self.overflow_buckets.clear();
            info!(
                "Rate limiter configuration updated: every key starts again under the new limits"
            );
        } else {
            info!("Rate limiter configuration updated");
        }
    }
}

/// Snapshot of rate limiter statistics
#[derive(Debug, Clone, Serialize)]
pub struct RateLimiterSnapshot {
    pub total_requests: u64,
    pub total_allowed: u64,
    pub total_limited: u64,
    pub total_blocked: u64,
    pub keys_tracked: usize,
    pub global_baseline_mean: f64,
    pub global_baseline_std_dev: f64,
    /// Whether the Redis distributed backend is currently connected.
    pub redis_connected: bool,
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Build context from HTTP request
pub fn build_context_from_request(
    source_ip: IpAddr,
    headers: &axum::http::HeaderMap,
    path: &str,
    method: &str,
    ja3_hash: Option<String>,
    ja4_hash: Option<String>,
    route_name: Option<String>,
) -> RateLimitContext {
    let mut header_map = HashMap::new();
    for (name, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(name.to_string(), v.to_string());
        }
    }

    // Parse cookies from Cookie header
    let mut cookies = HashMap::new();
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for cookie in cookie_header.split(';') {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 {
                cookies.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }

    // Parse query parameters from path
    let mut query_params = HashMap::new();
    if let Some(query_start) = path.find('?') {
        let query = &path[query_start + 1..];
        for param in query.split('&') {
            let parts: Vec<&str> = param.splitn(2, '=').collect();
            if parts.len() == 2 {
                query_params.insert(parts[0].to_string(), parts[1].to_string());
            }
        }
    }

    RateLimitContext {
        source_ip,
        headers: header_map,
        path: path.to_string(),
        method: method.to_string(),
        query_params,
        cookies,
        ja3_hash,
        ja4_hash,
        route_name,
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A network that does not fit a full map is counted in its route's
    /// overflow bucket, one per route whatever the network.
    #[test]
    fn overflow_buckets_are_one_per_route() {
        assert_eq!(
            overflow_key("SourceIp:2001:db8:1::/64"),
            "overflow:SourceIp"
        );
        assert_eq!(
            overflow_key("SourceIp:2001:db8:2::/64"),
            "overflow:SourceIp"
        );
        assert_eq!(
            overflow_key("SourceIp:api#2001:db8:1::/64"),
            "overflow:SourceIp:api"
        );
        assert_eq!(overflow_key("SourceIp:203.0.113.7"), "overflow:SourceIp");
    }
    use std::net::Ipv4Addr;

    #[test]
    fn test_sliding_window_counter() {
        let counter = SlidingWindowCounter::new(60, 12);

        // Increment 100 times
        for _ in 0..100 {
            counter.increment();
        }

        assert_eq!(counter.get_count(), 100);
    }

    #[test]
    fn test_adaptive_baseline() {
        let baseline = AdaptiveBaseline::new(3600, 10, 3.0);

        // Record some samples, a second apart
        let start = Instant::now();
        for i in 0..20 {
            baseline.record_at(100 + i, start + Duration::from_secs(i));
        }

        assert!(baseline.get_mean() > 100.0);
        assert!(baseline.get_std_dev() > 0.0);

        // Normal value should not be anomaly
        assert!(!baseline.is_anomaly(110));

        // Very high value should be anomaly
        assert!(baseline.is_anomaly(1000));
    }

    /// Samples within a second of the last are one sample; the moments never
    /// go negative however the samples fall; and the baseline follows a rate
    /// that has changed, older samples weighing less.
    #[test]
    fn the_baseline_samples_once_a_second_and_follows_the_rate() {
        let baseline = AdaptiveBaseline::new(60, 5, 3.0);
        let start = Instant::now();
        for i in 0..1000u64 {
            baseline.record_at(7, start + Duration::from_millis(i));
        }
        assert_eq!(
            baseline.count.load(Ordering::Relaxed),
            1,
            "one sample in the first second"
        );

        // A constant rate: no spread, and a NaN nowhere
        let steady = AdaptiveBaseline::new(60, 5, 3.0);
        for i in 0..100 {
            steady.record_at(1_000_000_007, start + Duration::from_secs(i));
        }
        assert!(steady.get_std_dev() >= 0.0 && steady.get_std_dev() < 1e-3);
        assert!(steady.threshold().is_some_and(f64::is_finite));

        // An hour at 10, then ten minutes at 100, with a one-minute window:
        // the baseline is the new rate's
        let shifted = AdaptiveBaseline::new(60, 5, 3.0);
        for i in 0..3600 {
            shifted.record_at(10, start + Duration::from_secs(i));
        }
        for i in 3600..4200 {
            shifted.record_at(100, start + Duration::from_secs(i));
        }
        assert!(
            (shifted.get_mean() - 100.0).abs() < 0.5,
            "{}",
            shifted.get_mean()
        );
    }

    #[test]
    fn test_rate_limit_key() {
        let key = RateLimitKey::new(RateLimitKeyType::SourceIp, "192.168.1.1".to_string());

        assert_eq!(key.storage_key("192.168.1.1"), "SourceIp:192.168.1.1");
    }

    #[test]
    fn test_composite_key() {
        let key = RateLimitKey::composite(vec![
            (RateLimitKeyType::SourceIp, "192.168.1.1".to_string()),
            (RateLimitKeyType::Path, "/api/v1".to_string()),
        ]);

        // Verify key_type is Composite with correct component names
        assert!(matches!(key.key_type, RateLimitKeyType::Composite(_)));
        if let RateLimitKeyType::Composite(ref names) = key.key_type {
            assert_eq!(names.len(), 2);
            assert!(names[0].contains("SourceIp"));
            assert!(names[1].contains("Path"));
        }

        // Verify value is joined
        assert_eq!(key.value, "192.168.1.1:/api/v1");

        // Verify components are stored
        assert!(key.components.is_some());
        let components = key.components.as_ref().unwrap();
        assert_eq!(components.len(), 2);

        // The stored form: the address as it is, the path the client wrote
        // as a digest
        assert_eq!(
            key.storage_key("192.168.1.1"),
            format!("SourceIp:192.168.1.1|Path:{}", value_digest("/api/v1"))
        );
    }

    #[test]
    fn test_composite_key_multi_dimension() {
        // Test composite key with IP + Method + Path (common for API rate limiting)
        let key = RateLimitKey::composite(vec![
            (RateLimitKeyType::SourceIp, "10.0.0.1".to_string()),
            (RateLimitKeyType::Method, "POST".to_string()),
            (RateLimitKeyType::Path, "/api/encrypt".to_string()),
        ]);

        assert!(matches!(key.key_type, RateLimitKeyType::Composite(_)));
        assert_eq!(key.value, "10.0.0.1:POST:/api/encrypt");
        assert_eq!(key.components.as_ref().unwrap().len(), 3);
    }

    #[test]
    fn test_composite_key_with_fingerprint() {
        // Test composite key with fingerprint + path (NAT-friendly API limiting)
        let key = RateLimitKey::composite(vec![
            (RateLimitKeyType::Ja3Fingerprint, "abc123def456".to_string()),
            (RateLimitKeyType::Path, "/api/v1/users".to_string()),
        ]);

        if let RateLimitKeyType::Composite(ref names) = key.key_type {
            assert!(names[0].contains("Ja3Fingerprint"));
            assert!(names[1].contains("Path"));
        }
        assert_eq!(key.value, "abc123def456:/api/v1/users");
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_normal_traffic() {
        let config = AdvancedRateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);

        let ctx = RateLimitContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            headers: HashMap::new(),
            path: "/test".to_string(),
            method: "GET".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: None,
            ja4_hash: None,
            route_name: None,
        };

        // First request should be allowed
        let result = limiter.check(&ctx).await;
        assert!(matches!(result, RateLimitResult::Allowed { .. }));
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_excess_traffic() {
        let mut config = AdvancedRateLimitConfig::default();
        config.global_limits.per_ip = PerKeyLimits {
            requests_per_second: 5,
            burst_size: 2,
            requests_per_minute: None,
            requests_per_hour: None,
        };

        let limiter = AdvancedRateLimiter::new(config);

        let ctx = RateLimitContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            headers: HashMap::new(),
            path: "/test".to_string(),
            method: "GET".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: None,
            ja4_hash: None,
            route_name: None,
        };

        // Make many requests
        let mut limited_count = 0;
        for _ in 0..20 {
            let result = limiter.check(&ctx).await;
            if matches!(result, RateLimitResult::Limited { .. }) {
                limited_count += 1;
            }
        }

        // Some requests should be rate limited
        assert!(limited_count > 0);
    }

    /// `sensitivity` was declared, defaulted, documented and read by nothing.
    /// The mapping must be monotonic, must be anchored at the default so no
    /// existing deployment changes behaviour, and must never collapse the
    /// threshold onto the mean.
    #[test]
    fn sensitivity_scales_the_std_dev_multiplier_around_the_default() {
        let at = |sensitivity: f64| {
            effective_std_dev_multiplier(&AdaptiveConfig {
                sensitivity,
                std_dev_multiplier: 3.0,
                ..AdaptiveConfig::default()
            })
        };

        // Anchored: the default sensitivity is exactly today's behaviour.
        assert!((at(0.7) - 3.0).abs() < 1e-9);

        // Monotonic: more sensitive means a lower bar to clear.
        assert!(at(0.0) > at(0.35));
        assert!(at(0.35) > at(0.7));
        assert!(at(0.7) > at(0.9));

        // Floored, so maximum sensitivity still needs a real deviation.
        assert!((at(1.0) - MIN_STD_DEV_MULTIPLIER).abs() < 1e-9);

        // Out-of-range input is clamped rather than producing a negative
        // multiplier, which would flag every sample below the mean.
        assert!(at(4.2) >= MIN_STD_DEV_MULTIPLIER);
        assert!((at(-1.0) - at(0.0)).abs() < 1e-9);
    }

    /// A more sensitive setting must actually flag a spike that a laxer one
    /// lets through — the mapping is only worth having if it reaches the
    /// verdict.
    #[test]
    fn sensitivity_changes_what_counts_as_an_anomaly() {
        let build = |sensitivity: f64| {
            let cfg = AdaptiveConfig {
                enabled: true,
                sensitivity,
                std_dev_multiplier: 3.0,
                min_samples: 10,
                ..AdaptiveConfig::default()
            };
            let baseline =
                AdaptiveBaseline::new(3600, cfg.min_samples, effective_std_dev_multiplier(&cfg));
            // A steady 100/min with a little jitter, a sample a second.
            let start = Instant::now();
            for i in 0..40 {
                baseline.record_at(
                    if i % 2 == 0 { 98 } else { 102 },
                    start + Duration::from_secs(i),
                );
            }
            baseline
        };

        // The samples give mean 100, stddev 2 (the newest weigh a hair more
        // than the oldest, a second against an hour's window).  Sensitivity
        // 0.95 maps to a multiplier of 0.5 (threshold 101); sensitivity 0.1
        // maps to 9.0 (threshold 118).  110 sits between them, so it
        // separates the two.
        let sensitive = build(0.95);
        let lax = build(0.1);
        assert!((sensitive.threshold().unwrap() - 101.0).abs() < 0.01);
        assert!((lax.threshold().unwrap() - 118.0).abs() < 0.05);

        assert!(
            sensitive.is_anomaly(110),
            "a high sensitivity should flag a modest excursion"
        );
        assert!(
            !lax.is_anomaly(110),
            "a low sensitivity should let the same excursion pass"
        );

        // Both agree on a gross outlier and on ordinary traffic.
        assert!(sensitive.is_anomaly(5000) && lax.is_anomaly(5000));
        assert!(!sensitive.is_anomaly(99) && !lax.is_anomaly(99));
    }

    /// `auto_adjust` was declared and read by nothing, so a key that normally
    /// makes a handful of requests a minute kept the whole configured budget.
    #[test]
    fn auto_adjust_tightens_a_quiet_key_toward_its_own_baseline() {
        let limits = PerKeyLimits {
            requests_per_second: 100,
            burst_size: 10,
            requests_per_minute: Some(3000),
            requests_per_hour: Some(100_000),
        };
        let adaptive = AdaptiveConfig {
            enabled: true,
            auto_adjust: true,
            min_samples: 10,
            ..AdaptiveConfig::default()
        };
        let bucket = RateLimitBucket::new(&limits, Some(&adaptive));
        let baseline = bucket.baseline.as_ref().expect("adaptive is enabled");

        // Before the baseline is established, nothing is touched — a new key
        // must not be throttled for being new.
        assert_eq!(
            bucket
                .effective_limits(&limits, &adaptive)
                .requests_per_minute,
            Some(3000)
        );

        // This key's normal is ~20 requests/minute.
        let start = Instant::now();
        for i in 0..40 {
            baseline.record_at(
                if i % 2 == 0 { 19 } else { 21 },
                start + Duration::from_secs(i),
            );
        }

        let adjusted = bucket.effective_limits(&limits, &adaptive);
        let per_minute = adjusted.requests_per_minute.expect("still set");
        assert!(
            per_minute < 3000,
            "an established quiet baseline must tighten the configured ceiling, got {per_minute}"
        );
        assert!(
            per_minute >= limits.burst_size,
            "must never tighten below burst_size, got {per_minute}"
        );
        assert!(
            adjusted.requests_per_hour.unwrap() <= 100_000,
            "the configured value stays a hard ceiling"
        );

        // The per-second quota is deliberately untouched.
        assert_eq!(adjusted.requests_per_second, 100);
        assert_eq!(adjusted.burst_size, 10);
    }

    /// Auto-adjustment is one-directional: a busy key whose baseline sits above
    /// the configured ceiling must not be handed a bigger budget than the
    /// operator wrote.
    #[test]
    fn auto_adjust_never_raises_a_limit_above_the_configured_value() {
        let limits = PerKeyLimits {
            requests_per_second: 100,
            burst_size: 10,
            requests_per_minute: Some(50),
            requests_per_hour: Some(1000),
        };
        let adaptive = AdaptiveConfig {
            enabled: true,
            auto_adjust: true,
            min_samples: 10,
            ..AdaptiveConfig::default()
        };
        let bucket = RateLimitBucket::new(&limits, Some(&adaptive));
        let baseline = bucket.baseline.as_ref().expect("adaptive is enabled");

        // A baseline far above the configured minute ceiling.
        let start = Instant::now();
        for i in 0..40 {
            baseline.record_at(5000, start + Duration::from_secs(i));
        }

        let adjusted = bucket.effective_limits(&limits, &adaptive);
        assert_eq!(adjusted.requests_per_minute, Some(50));
        assert_eq!(adjusted.requests_per_hour, Some(1000));
    }

    /// With `auto_adjust` off, the configured limits pass through untouched
    /// however much baseline has accumulated.
    #[test]
    fn auto_adjust_off_leaves_limits_alone() {
        let limits = PerKeyLimits {
            requests_per_second: 100,
            burst_size: 10,
            requests_per_minute: Some(3000),
            requests_per_hour: Some(100_000),
        };
        let adaptive = AdaptiveConfig {
            enabled: true,
            auto_adjust: false,
            min_samples: 10,
            ..AdaptiveConfig::default()
        };
        let bucket = RateLimitBucket::new(&limits, Some(&adaptive));
        let baseline = bucket.baseline.as_ref().unwrap();
        let start = Instant::now();
        for i in 0..40 {
            baseline.record_at(20, start + Duration::from_secs(i));
        }
        assert!(baseline.is_established());

        let adjusted = bucket.effective_limits(&limits, &adaptive);
        assert_eq!(adjusted.requests_per_minute, Some(3000));
        assert_eq!(adjusted.requests_per_hour, Some(100_000));
    }

    /// `route_limits.<route>.exempt_keys` was parsed and never read, so a key
    /// an operator had explicitly exempted was rate-limited like any other.
    #[tokio::test]
    async fn exempt_keys_bypass_the_route_limit() {
        let mut config = AdvancedRateLimitConfig::default();
        config.route_limits.insert(
            "health".to_string(),
            RouteLimits {
                pattern: "/health".to_string(),
                limits: PerKeyLimits {
                    requests_per_second: 1,
                    burst_size: 1,
                    requests_per_minute: None,
                    requests_per_hour: None,
                },
                key_override: None,
                exempt_keys: vec!["10.9.9.9".to_string()],
            },
        );
        let limiter = AdvancedRateLimiter::new(config);

        let ctx = |ip| RateLimitContext {
            source_ip: IpAddr::V4(ip),
            headers: HashMap::new(),
            path: "/health".to_string(),
            method: "GET".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: None,
            ja4_hash: None,
            route_name: Some("health".to_string()),
        };

        // The exempt monitoring agent is never limited, however hard it polls.
        let exempt = ctx(Ipv4Addr::new(10, 9, 9, 9));
        for _ in 0..50 {
            assert!(matches!(
                limiter.check(&exempt).await,
                RateLimitResult::Allowed { .. }
            ));
        }

        // A caller that is not on the list still hits the 1 rps route limit.
        let other = ctx(Ipv4Addr::new(10, 9, 9, 10));
        let mut limited = 0;
        for _ in 0..50 {
            if matches!(limiter.check(&other).await, RateLimitResult::Limited { .. }) {
                limited += 1;
            }
        }
        assert!(limited > 0, "non-exempt key should still be limited");
    }

    /// A `[route_limits.*]` block with no `key_override` used to fall straight
    /// through to the global per-IP limits, so the stricter number an operator
    /// wrote for a login endpoint was never applied.
    #[tokio::test]
    async fn route_limits_apply_without_a_key_override() {
        let mut config = AdvancedRateLimitConfig::default();
        config.route_limits.insert(
            "login".to_string(),
            RouteLimits {
                pattern: "/api/method/login".to_string(),
                limits: PerKeyLimits {
                    requests_per_second: 2,
                    burst_size: 2,
                    requests_per_minute: None,
                    requests_per_hour: None,
                },
                key_override: None,
                exempt_keys: Vec::new(),
            },
        );
        let limiter = AdvancedRateLimiter::new(config);

        let ctx = RateLimitContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
            headers: HashMap::new(),
            path: "/api/method/login".to_string(),
            method: "POST".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: None,
            ja4_hash: None,
            route_name: Some("login".to_string()),
        };

        let mut limited = 0;
        for _ in 0..40 {
            if matches!(limiter.check(&ctx).await, RateLimitResult::Limited { .. }) {
                limited += 1;
            }
        }
        assert!(
            limited > 0,
            "a 2 rps route limit must bite well inside 40 requests"
        );

        // The route bucket is namespaced, so the same IP on a route with no
        // limits block is unaffected by what it spent above.
        let elsewhere = RateLimitContext {
            route_name: None,
            path: "/".to_string(),
            ..ctx.clone()
        };
        assert!(matches!(
            limiter.check(&elsewhere).await,
            RateLimitResult::Allowed { .. }
        ));
    }

    /// `fingerprint_limiting.prefer_over_ip` is the NAT knob: it must beat an
    /// IP-first `key_strategy.order`, which is the configuration shape that
    /// makes it worth having.  It was never read.
    #[tokio::test]
    async fn prefer_over_ip_puts_the_fingerprint_ahead_of_an_ip_first_order() {
        let mut config = AdvancedRateLimitConfig::default();
        config.key_strategy.order = vec![RateLimitKeyType::SourceIp];
        config.fingerprint_limiting.enabled = true;
        config.fingerprint_limiting.prefer_over_ip = true;
        let limiter = AdvancedRateLimiter::new(config.clone());

        let ctx = RateLimitContext {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            headers: HashMap::new(),
            path: "/".to_string(),
            method: "GET".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: Some("cd08e31494f9531f560d64c695473da9".to_string()),
            ja4_hash: None,
            route_name: None,
        };

        let (key, _) = limiter.resolve_key_and_limits(&ctx, &config);
        assert_eq!(key.key_type, RateLimitKeyType::Ja3Fingerprint);

        // With the knob off, the configured IP-first order wins again.
        let mut ip_first = config;
        ip_first.fingerprint_limiting.prefer_over_ip = false;
        let (key, _) = limiter.resolve_key_and_limits(&ctx, &ip_first);
        assert_eq!(key.key_type, RateLimitKeyType::SourceIp);
    }

    /// `global_limits.per_fingerprint` was a fully-populated limit block that
    /// nothing read, and `fingerprint_limiting.enabled = false` did not turn
    /// fingerprint limiting off.  Switching the subsystem off now falls back to
    /// the global block instead of silently keeping `unknown_limits`.
    #[tokio::test]
    async fn disabling_fingerprint_limiting_falls_back_to_the_global_block() {
        let mut config = AdvancedRateLimitConfig::default();
        config.global_limits.per_fingerprint = PerKeyLimits {
            requests_per_second: 4242,
            burst_size: 99,
            requests_per_minute: None,
            requests_per_hour: None,
        };
        config.fingerprint_limiting.unknown_limits = PerKeyLimits {
            requests_per_second: 7,
            burst_size: 7,
            requests_per_minute: None,
            requests_per_hour: None,
        };
        let limiter = AdvancedRateLimiter::new(config.clone());

        config.fingerprint_limiting.enabled = true;
        let on = limiter.get_limits_for_key(&RateLimitKeyType::Ja3Fingerprint, "abc", &config);
        assert_eq!(on.requests_per_second, 7);

        config.fingerprint_limiting.enabled = false;
        let off = limiter.get_limits_for_key(&RateLimitKeyType::Ja3Fingerprint, "abc", &config);
        assert_eq!(off.requests_per_second, 4242);
    }

    #[tokio::test]
    async fn test_ipv6_subnet_normalization() {
        let config = AdvancedRateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);

        let ip1 = IpAddr::V6("2001:db8:85a3::8a2e:370:7334".parse().unwrap());
        let ip2 = IpAddr::V6("2001:db8:85a3::1".parse().unwrap());

        // Both should normalize to same /64 subnet
        let norm1 = limiter.normalize_ip(ip1, 64);
        let norm2 = limiter.normalize_ip(ip2, 64);

        assert_eq!(norm1, norm2);
    }

    #[tokio::test]
    async fn jwt_subject_keys_have_their_own_limits() {
        let mut config = AdvancedRateLimitConfig::default();
        config.global_limits.per_jwt_subject.requests_per_second = 7;
        let limiter = AdvancedRateLimiter::new(config.clone());
        let limits = limiter.get_limits_for_key(&RateLimitKeyType::JwtSubject, "user-1", &config);
        assert_eq!(limits.requests_per_second, 7);
        let ip = limiter.get_limits_for_key(&RateLimitKeyType::SourceIp, "203.0.113.1", &config);
        assert_eq!(
            ip.requests_per_second,
            config.global_limits.per_ip.requests_per_second
        );
    }

    #[tokio::test]
    async fn test_jwt_subject_extraction() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use serde::Serialize;

        let config = AdvancedRateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);

        // SEC-003: Build a token programmatically with a throwaway test key instead of
        // embedding a static literal that triggers secrets-scanner false positives.
        const TEST_SECRET: &[u8] = b"test-only-key-not-used-in-production";
        const WRONG_SECRET: &[u8] = b"wrong-key";

        #[derive(Serialize)]
        struct TestClaims {
            sub: String,
            iat: u64,
            // jsonwebtoken 9.x requires `exp` by default; set far in the future
            // so the token remains valid for the duration of any test run.
            exp: u64,
        }

        let claims = TestClaims {
            sub: "user123".to_string(),
            iat: 1_700_000_000,
            exp: 9_999_999_999,
        };

        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_SECRET),
        )
        .expect("test JWT encoding must not fail");

        // H-2: Without a configured jwt_secret, extraction must always return None
        // regardless of the JWT content (prevents trust-only mode).
        assert_eq!(
            limiter.extract_jwt_subject(&format!("Bearer {}", jwt), None, &["HS256"]),
            None,
            "JWT extraction must return None when no secret is configured"
        );

        // With the correct secret the sub claim is extracted successfully.
        assert_eq!(
            limiter.extract_jwt_subject(
                &format!("Bearer {}", jwt),
                Some(std::str::from_utf8(TEST_SECRET).unwrap()),
                &["HS256"],
            ),
            Some("user123".to_string()),
            "JWT extraction must return the sub claim on signature match"
        );

        // With a wrong secret the signature fails → None.
        assert_eq!(
            limiter.extract_jwt_subject(
                &format!("Bearer {}", jwt),
                Some(std::str::from_utf8(WRONG_SECRET).unwrap()),
                &["HS256"],
            ),
            None,
            "JWT extraction must return None on signature mismatch"
        );

        // Without Bearer prefix → None.
        assert_eq!(
            limiter.extract_jwt_subject(
                &jwt,
                Some(std::str::from_utf8(TEST_SECRET).unwrap()),
                &["HS256"],
            ),
            None,
            "JWT extraction must return None without Bearer prefix"
        );
    }

    fn layered_config(order: Vec<RateLimitKeyType>) -> AdvancedRateLimitConfig {
        let tight = PerKeyLimits {
            requests_per_second: 1,
            burst_size: 2,
            requests_per_minute: None,
            requests_per_hour: None,
        };
        let mut config = AdvancedRateLimitConfig::default();
        config.key_strategy.order = order;
        config.global_limits.per_ip = tight.clone();
        config.global_limits.per_fingerprint = tight.clone();
        config.fingerprint_limiting.unknown_limits = tight;
        config
    }

    fn ctx_from(ip: [u8; 4], api_key: Option<&str>, ja3: Option<&str>) -> RateLimitContext {
        let mut headers = HashMap::new();
        if let Some(k) = api_key {
            headers.insert("X-API-Key".to_string(), k.to_string());
        }
        RateLimitContext {
            source_ip: IpAddr::V4(Ipv4Addr::from(ip)),
            headers,
            path: "/".to_string(),
            method: "GET".to_string(),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: ja3.map(str::to_string),
            ja4_hash: None,
            route_name: None,
        }
    }

    /// The `asn` key is the network an address is announced from: two
    /// addresses of one provider are one key, another provider's another,
    /// and an address no database knows has none.
    #[tokio::test]
    async fn the_asn_key_is_the_announcing_network() {
        let limiter = AdvancedRateLimiter::new(layered_config(vec![RateLimitKeyType::Asn]));
        let config = limiter.config.read().clone();
        assert!(limiter.uses_asn_key());
        let key = |ip| {
            limiter.extract_key_value(&RateLimitKeyType::Asn, &ctx_from(ip, None, None), &config)
        };
        assert_eq!(key([192, 0, 2, 1]), None, "no database yet");
        limiter.set_asn_lookup(Arc::new(|ip| match ip {
            IpAddr::V4(v4) if v4.octets()[0] == 192 => Some(64_500),
            IpAddr::V4(v4) if v4.octets()[0] == 198 => Some(64_501),
            _ => None,
        }));
        assert_eq!(key([192, 0, 2, 1]).as_deref(), Some("AS64500"));
        assert_eq!(key([192, 0, 2, 200]), key([192, 0, 2, 1]));
        assert_eq!(key([198, 51, 100, 7]).as_deref(), Some("AS64501"));
        assert_eq!(key([203, 0, 113, 9]), None);
    }

    /// A key the client writes itself is counted beside its address, so a
    /// new value with every request is still one client.
    #[tokio::test]
    async fn a_new_api_key_with_every_request_is_still_one_address() {
        let limiter = AdvancedRateLimiter::new(layered_config(vec![
            RateLimitKeyType::ApiKey,
            RateLimitKeyType::SourceIp,
        ]));
        let mut refused = 0;
        for n in 0..6 {
            let key = format!("key-{n}");
            let ctx = ctx_from([203, 0, 113, 7], Some(&key), None);
            if !matches!(limiter.check(&ctx).await, RateLimitResult::Allowed { .. }) {
                refused += 1;
            }
        }
        assert!(refused >= 3, "{refused} of 6 refused at a burst of 2");
        // Another address is not held by the first one's requests
        let other = ctx_from([203, 0, 113, 8], Some("key-0"), None);
        assert!(matches!(
            limiter.check(&other).await,
            RateLimitResult::Allowed { .. }
        ));
    }

    /// Two addresses running the same client build each have their own
    /// budget: a fingerprint names the build, not the user.
    #[tokio::test]
    async fn one_fingerprint_from_two_addresses_is_two_clients() {
        let limiter = AdvancedRateLimiter::new(layered_config(vec![
            RateLimitKeyType::Ja3Fingerprint,
            RateLimitKeyType::SourceIp,
        ]));
        let ja3 = Some("e7d705a3286e19ea42f587b344ee6865");
        let first = ctx_from([198, 51, 100, 1], None, ja3);
        let mut refused = false;
        for _ in 0..6 {
            refused |= !matches!(limiter.check(&first).await, RateLimitResult::Allowed { .. });
        }
        assert!(refused, "the first address ran out");
        let second = ctx_from([198, 51, 100, 2], None, ja3);
        assert!(matches!(
            limiter.check(&second).await,
            RateLimitResult::Allowed { .. }
        ));
    }

    /// An API key the proxy cannot verify names a bucket of its own and never
    /// replaces the one the request has without it: a new key on every
    /// request is still held by the client's fingerprint bucket.
    #[tokio::test]
    async fn a_written_key_does_not_lift_a_client_past_its_fingerprint() {
        let mut config = layered_config(vec![
            RateLimitKeyType::ApiKey,
            RateLimitKeyType::Ja3Fingerprint,
            RateLimitKeyType::SourceIp,
        ]);
        // The address and the keys are generous; the fingerprint is not.
        let generous = PerKeyLimits {
            requests_per_second: 1000,
            burst_size: 1000,
            requests_per_minute: None,
            requests_per_hour: None,
        };
        config.global_limits.per_ip = generous.clone();
        config.global_limits.per_api_key = generous;
        let limiter = AdvancedRateLimiter::new(config);
        let ja3 = Some("e7d705a3286e19ea42f587b344ee6865");
        let mut refused = 0;
        for n in 0..6 {
            let key = format!("key-{n}");
            let ctx = ctx_from([198, 51, 100, 9], Some(&key), ja3);
            if !matches!(limiter.check(&ctx).await, RateLimitResult::Allowed { .. }) {
                refused += 1;
            }
        }
        assert!(
            refused >= 3,
            "{refused} of 6 refused at a fingerprint burst of 2"
        );

        // The same client without a fingerprint is held by its address alone.
        let other = ctx_from([198, 51, 100, 10], Some("key-x"), None);
        assert!(matches!(
            limiter.check(&other).await,
            RateLimitResult::Allowed { .. }
        ));
        assert!(RateLimitKeyType::ApiKey.is_client_written());
        assert!(!RateLimitKeyType::Ja3Fingerprint.is_client_written());
        assert!(!RateLimitKeyType::JwtSubject.is_client_written());
    }

    #[test]
    fn a_bucket_key_holds_no_value_the_client_wrote() {
        let written = "a-value-the-client-wrote-0123456789";
        let key = RateLimitKey::new(RateLimitKeyType::ApiKey, written.to_string());
        let stored = key.storage_key("203.0.113.7");
        assert!(!stored.contains(written));
        assert_eq!(stored.len(), "ApiKey:".len() + 32);
        assert!(!key.is_network_bound());

        let long = RateLimitKey::new(RateLimitKeyType::Path, "/x".repeat(4000));
        assert_eq!(long.storage_key("203.0.113.7").len(), "Path:".len() + 32);

        let ja3 = RateLimitKey::new(RateLimitKeyType::Ja3Fingerprint, "abc".to_string());
        assert_eq!(
            ja3.storage_key("203.0.113.7"),
            "Ja3Fingerprint:abc@203.0.113.7"
        );

        let ip = RateLimitKey::new(RateLimitKeyType::SourceIp, "203.0.113.7".to_string());
        assert!(ip.is_network_bound());
        assert_eq!(ip.storage_key("203.0.113.7"), "SourceIp:203.0.113.7");
    }

    /// Resetting an address clears what it was counted in under any key.
    #[tokio::test]
    async fn resetting_an_address_clears_its_fingerprint_bucket_too() {
        let limiter = AdvancedRateLimiter::new(layered_config(vec![
            RateLimitKeyType::Ja3Fingerprint,
            RateLimitKeyType::SourceIp,
        ]));
        let ctx = ctx_from([198, 51, 100, 9], None, Some("abc"));
        let _ = limiter.check(&ctx).await;
        assert_eq!(limiter.reset_key("198.51.100.9"), 2);
    }
}
