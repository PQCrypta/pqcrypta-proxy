//! Advanced Multi-Dimensional Rate Limiting Module
//!
//! Cutting-edge rate limiting inspired by industry leaders:
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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

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
}

fn default_true() -> bool {
    true
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
}

impl Default for RateLimitKeyType {
    fn default() -> Self {
        Self::SourceIp
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
}

fn default_global_rps() -> u32 {
    100_000
}

fn default_global_burst() -> u32 {
    50_000
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

    /// Baseline learning window (seconds)
    #[serde(default = "default_baseline_window")]
    pub baseline_window_secs: u64,

    /// Anomaly detection sensitivity (0.0 - 1.0)
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f64,

    /// Auto-adjust limits based on traffic patterns
    #[serde(default)]
    pub auto_adjust: bool,

    /// Minimum requests before baseline is established
    #[serde(default = "default_min_samples")]
    pub min_samples: u64,

    /// Standard deviation multiplier for anomaly detection
    #[serde(default = "default_std_dev_multiplier")]
    pub std_dev_multiplier: f64,
}

fn default_baseline_window() -> u64 {
    3600 // 1 hour
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
        let value = components
            .iter()
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(":");

        Self {
            key_type: RateLimitKeyType::SourceIp, // Placeholder for composite
            value,
            components: Some(components),
        }
    }

    /// Create key string for storage
    pub fn to_key_string(&self) -> String {
        if let Some(ref components) = self.components {
            components
                .iter()
                .map(|(t, v)| format!("{:?}:{}", t, v))
                .collect::<Vec<_>>()
                .join("|")
        } else {
            format!("{:?}:{}", self.key_type, self.value)
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
    /// Window size in seconds
    #[allow(dead_code)]
    window_secs: u64,

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
            window_secs,
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

        let current = self.current_bucket.load(Ordering::Relaxed) as usize % self.num_buckets;
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
        let buckets_to_rotate = (elapsed.as_secs() / self.bucket_duration_secs) as usize;

        if buckets_to_rotate > 0 {
            let current = self.current_bucket.load(Ordering::Relaxed) as usize;

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

/// Adaptive baseline tracker for anomaly detection
#[derive(Debug)]
pub struct AdaptiveBaseline {
    /// Sum of all values
    sum: AtomicU64,

    /// Sum of squared values (for variance)
    sum_squared: AtomicU64,

    /// Count of samples
    count: AtomicU64,

    /// Rolling window samples
    samples: RwLock<Vec<(Instant, u64)>>,

    /// Window duration
    window_duration: Duration,

    /// Minimum samples before baseline is valid
    min_samples: u64,

    /// Standard deviation multiplier for anomaly
    std_dev_multiplier: f64,
}

impl AdaptiveBaseline {
    pub fn new(window_secs: u64, min_samples: u64, std_dev_multiplier: f64) -> Self {
        Self {
            sum: AtomicU64::new(0),
            sum_squared: AtomicU64::new(0),
            count: AtomicU64::new(0),
            samples: RwLock::new(Vec::new()),
            window_duration: Duration::from_secs(window_secs),
            min_samples,
            std_dev_multiplier,
        }
    }

    /// Record a sample
    pub fn record(&self, value: u64) {
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.sum_squared.fetch_add(value * value, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        let mut samples = self.samples.write();
        samples.push((Instant::now(), value));

        // Trim old samples
        let cutoff = Instant::now()
            .checked_sub(self.window_duration)
            .unwrap_or_else(Instant::now);
        samples.retain(|(t, _)| *t > cutoff);
    }

    /// Check if value is anomalous
    pub fn is_anomaly(&self, value: u64) -> bool {
        let count = self.count.load(Ordering::Relaxed);
        if count < self.min_samples {
            return false; // Not enough data for baseline
        }

        let sum = self.sum.load(Ordering::Relaxed) as f64;
        let sum_sq = self.sum_squared.load(Ordering::Relaxed) as f64;
        let n = count as f64;

        let mean = sum / n;
        // variance = E[X²] - E[X]² (correct statistical formula)
        #[allow(clippy::suspicious_operation_groupings)]
        let variance = mean.mul_add(-mean, sum_sq / n);
        let std_dev = variance.sqrt();

        let threshold = self.std_dev_multiplier.mul_add(std_dev, mean);

        value as f64 > threshold
    }

    /// Get current mean
    pub fn get_mean(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0.0;
        }
        self.sum.load(Ordering::Relaxed) as f64 / count as f64
    }

    /// Get current standard deviation
    pub fn get_std_dev(&self) -> f64 {
        let count = self.count.load(Ordering::Relaxed);
        if count < 2 {
            return 0.0;
        }

        let sum = self.sum.load(Ordering::Relaxed) as f64;
        let sum_sq = self.sum_squared.load(Ordering::Relaxed) as f64;
        let n = count as f64;

        let mean = sum / n;
        // variance = E[X²] - E[X]² (correct statistical formula)
        #[allow(clippy::suspicious_operation_groupings)]
        let variance = mean.mul_add(-mean, sum_sq / n);
        variance.sqrt()
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

    /// Requests in current second
    #[allow(dead_code)]
    pub current_second_count: AtomicU64,

    /// Last request timestamp
    pub last_request: RwLock<Instant>,

    /// Created timestamp
    #[allow(dead_code)]
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
        let rps = NonZeroU32::new(limits.requests_per_second.max(1))
            .unwrap_or(NonZeroU32::MIN);
        let burst = NonZeroU32::new(limits.burst_size.max(1))
            .unwrap_or(NonZeroU32::MIN);

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
                    config.std_dev_multiplier,
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

    /// Check if request is allowed
    pub fn check(&self, limits: &PerKeyLimits) -> RateLimitResult {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        *self.last_request.write() = Instant::now();

        // 1. Check token bucket (per-second)
        if self.token_bucket.check().is_err() {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult::Limited {
                reason: LimitReason::PerSecond,
                retry_after_ms: 1000,
                limit: limits.requests_per_second,
                remaining: 0,
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
                        remaining: 0,
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
                        remaining: 0,
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
                    limit: baseline.get_mean() as u32,
                    remaining: 0,
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
        /// Remaining (always 0 when limited)
        #[allow(dead_code)]
        remaining: u32,
    },
    /// Key is blocked (fingerprint block, etc.)
    Blocked {
        /// Reason for blocking
        reason: String,
    },
}

/// Reason for rate limiting
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
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

    /// Global rate limiter
    global_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,

    /// Per-key rate limit buckets
    buckets: Arc<DashMap<String, Arc<RateLimitBucket>>>,

    /// Per-route rate limit buckets
    route_buckets: Arc<DashMap<String, Arc<DashMap<String, Arc<RateLimitBucket>>>>>,

    /// Parsed trusted proxy CIDRs
    trusted_cidrs: Arc<RwLock<Vec<ipnet::IpNet>>>,

    /// Global baseline (for overall traffic patterns)
    global_baseline: Arc<AdaptiveBaseline>,

    /// Statistics
    stats: Arc<RateLimiterStats>,
}

/// Rate limiter statistics
#[derive(Debug, Default)]
pub struct RateLimiterStats {
    pub total_requests: AtomicU64,
    pub total_allowed: AtomicU64,
    pub total_limited: AtomicU64,
    pub total_blocked: AtomicU64,
    pub keys_tracked: AtomicU64,
}

impl AdvancedRateLimiter {
    /// Create a new advanced rate limiter
    pub fn new(config: AdvancedRateLimitConfig) -> Self {
        // Parse trusted proxy CIDRs
        let trusted_cidrs: Vec<ipnet::IpNet> = config
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                s.parse().ok().or_else(|| {
                    // Try parsing as single IP - use safe defaults that can't fail
                    s.parse::<IpAddr>().ok().and_then(|ip| match ip {
                        IpAddr::V4(v4) => ipnet::Ipv4Net::new(v4, 32).ok().map(ipnet::IpNet::V4),
                        IpAddr::V6(v6) => ipnet::Ipv6Net::new(v6, 128).ok().map(ipnet::IpNet::V6),
                    })
                })
            })
            .collect();

        // Create global rate limiter with safe NonZeroU32 handling
        let global_rps = NonZeroU32::new(config.global_limits.requests_per_second.max(1))
            .unwrap_or(NonZeroU32::MIN);
        let global_burst = NonZeroU32::new(config.global_limits.burst_size.max(1))
            .unwrap_or(NonZeroU32::MIN);

        let global_quota = Quota::per_second(global_rps).allow_burst(global_burst);

        // Extract adaptive config values before moving config
        let adaptive_baseline_window = config.adaptive.baseline_window_secs;
        let adaptive_min_samples = config.adaptive.min_samples;
        let adaptive_std_dev_multiplier = config.adaptive.std_dev_multiplier;

        let limiter = Self {
            config: Arc::new(RwLock::new(config)),
            global_limiter: Arc::new(RateLimiter::direct(global_quota)),
            buckets: Arc::new(DashMap::new()),
            route_buckets: Arc::new(DashMap::new()),
            trusted_cidrs: Arc::new(RwLock::new(trusted_cidrs)),
            global_baseline: Arc::new(AdaptiveBaseline::new(
                adaptive_baseline_window,
                adaptive_min_samples,
                adaptive_std_dev_multiplier,
            )),
            stats: Arc::new(RateLimiterStats::default()),
        };

        // Spawn cleanup task
        limiter.spawn_cleanup_task();

        limiter
    }

    /// Check if request is allowed
    pub fn check(&self, ctx: &RateLimitContext) -> RateLimitResult {
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        let config = self.config.read();

        if !config.enabled {
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                limit: u32::MAX,
            };
        }

        // 1. Check global limit first (DDoS protection)
        if self.global_limiter.check().is_err() {
            self.stats.total_limited.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult::Limited {
                reason: LimitReason::Global,
                retry_after_ms: 1000,
                limit: config.global_limits.requests_per_second,
                remaining: 0,
            };
        }

        // 2. Check blocked fingerprints
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

        // 3. Resolve rate limit key
        let (key, limits) = self.resolve_key_and_limits(ctx, &config);

        // 4. Get or create bucket for this key
        let key_string = key.to_key_string();
        let bucket = self
            .buckets
            .entry(key_string)
            .or_insert_with(|| {
                self.stats.keys_tracked.fetch_add(1, Ordering::Relaxed);
                Arc::new(RateLimitBucket::new(&limits, Some(&config.adaptive)))
            })
            .clone();

        // 5. Check the bucket
        let result = bucket.check(&limits);

        // 6. Record global baseline
        if config.adaptive.enabled {
            self.global_baseline.record(1);
        }

        // 7. Update stats
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

    /// Resolve rate limit key and applicable limits
    fn resolve_key_and_limits(
        &self,
        ctx: &RateLimitContext,
        config: &AdvancedRateLimitConfig,
    ) -> (RateLimitKey, PerKeyLimits) {
        // Check for route-specific overrides first
        if let Some(route_name) = &ctx.route_name {
            if let Some(route_limits) = config.route_limits.get(route_name) {
                if let Some(ref key_override) = route_limits.key_override {
                    if let Some(value) = self.extract_key_value(key_override, ctx, config) {
                        return (
                            RateLimitKey::new(key_override.clone(), value),
                            route_limits.limits.clone(),
                        );
                    }
                }
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
                // Try to extract from Authorization header
                ctx.get_header("authorization")
                    .and_then(|auth| self.extract_jwt_subject(auth))
            }

            RateLimitKeyType::Ja3Fingerprint => ctx.ja3_hash.clone(),

            RateLimitKeyType::Ja4Fingerprint => ctx.ja4_hash.clone(),

            RateLimitKeyType::Header(name) => ctx.get_header(name).cloned(),

            RateLimitKeyType::Cookie(name) => ctx.get_cookie(name).cloned(),

            RateLimitKeyType::QueryParam(name) => ctx.get_query_param(name).cloned(),

            RateLimitKeyType::Path => Some(ctx.path.clone()),

            RateLimitKeyType::Method => Some(ctx.method.clone()),

            RateLimitKeyType::Asn => None, // Would require GeoIP/ASN lookup
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

    /// Extract subject claim from JWT (basic parsing)
    fn extract_jwt_subject(&self, auth_header: &str) -> Option<String> {
        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))?;

        // JWT format: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode payload (base64url)
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
        let payload_str = String::from_utf8(payload).ok()?;

        // Parse JSON and extract "sub" claim
        let json: serde_json::Value = serde_json::from_str(&payload_str).ok()?;
        json.get("sub")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Get limits for a specific key type and value
    fn get_limits_for_key(
        &self,
        key_type: &RateLimitKeyType,
        value: &str,
        config: &AdvancedRateLimitConfig,
    ) -> PerKeyLimits {
        // Check for fingerprint-specific limits
        if matches!(
            key_type,
            RateLimitKeyType::Ja3Fingerprint | RateLimitKeyType::Ja4Fingerprint
        ) {
            if let Some(limits) = config.fingerprint_limiting.trusted_fingerprints.get(value) {
                return limits.clone();
            }
            return config.fingerprint_limiting.unknown_limits.clone();
        }

        // Check for API key-specific limits (could be extended with database lookup)
        if matches!(key_type, RateLimitKeyType::ApiKey) {
            // Default API key limits (higher than fingerprint)
            return PerKeyLimits {
                requests_per_second: 500,
                burst_size: 250,
                requests_per_minute: Some(15_000),
                requests_per_hour: Some(250_000),
            };
        }

        // Default per-IP limits
        config.global_limits.per_ip.clone()
    }

    /// Maximum number of tracked keys to prevent DoS through memory exhaustion
    const MAX_TRACKED_KEYS: usize = 100_000;

    /// Spawn background cleanup task
    fn spawn_cleanup_task(&self) {
        let buckets = self.buckets.clone();
        let route_buckets = self.route_buckets.clone();
        let stats = self.stats.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;

                let idle_threshold = Duration::from_secs(300); // 5 minutes

                // Clean up idle buckets
                let before_count = buckets.len();
                buckets.retain(|_, bucket| bucket.last_request.read().elapsed() < idle_threshold);
                let removed = before_count - buckets.len();

                if removed > 0 {
                    stats
                        .keys_tracked
                        .fetch_sub(removed as u64, Ordering::Relaxed);
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

                    stats
                        .keys_tracked
                        .fetch_sub(to_remove as u64, Ordering::Relaxed);
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

    /// Get current statistics
    #[allow(dead_code)]
    pub fn get_stats(&self) -> RateLimiterSnapshot {
        RateLimiterSnapshot {
            total_requests: self.stats.total_requests.load(Ordering::Relaxed),
            total_allowed: self.stats.total_allowed.load(Ordering::Relaxed),
            total_limited: self.stats.total_limited.load(Ordering::Relaxed),
            total_blocked: self.stats.total_blocked.load(Ordering::Relaxed),
            keys_tracked: self.buckets.len(),
            global_baseline_mean: self.global_baseline.get_mean(),
            global_baseline_std_dev: self.global_baseline.get_std_dev(),
        }
    }

    /// Update configuration
    #[allow(dead_code)]
    pub fn update_config(&self, config: AdvancedRateLimitConfig) {
        // Update trusted CIDRs with safe parsing
        let trusted_cidrs: Vec<ipnet::IpNet> = config
            .trusted_proxies
            .iter()
            .filter_map(|s| {
                s.parse().ok().or_else(|| {
                    s.parse::<IpAddr>().ok().and_then(|ip| match ip {
                        IpAddr::V4(v4) => ipnet::Ipv4Net::new(v4, 32).ok().map(ipnet::IpNet::V4),
                        IpAddr::V6(v6) => ipnet::Ipv6Net::new(v6, 128).ok().map(ipnet::IpNet::V6),
                    })
                })
            })
            .collect();

        *self.trusted_cidrs.write() = trusted_cidrs;
        *self.config.write() = config;

        info!("Rate limiter configuration updated");
    }
}

/// Snapshot of rate limiter statistics
#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
pub struct RateLimiterSnapshot {
    pub total_requests: u64,
    pub total_allowed: u64,
    pub total_limited: u64,
    pub total_blocked: u64,
    pub keys_tracked: usize,
    pub global_baseline_mean: f64,
    pub global_baseline_std_dev: f64,
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

        // Record some samples
        for i in 0..20 {
            baseline.record(100 + i);
        }

        assert!(baseline.get_mean() > 100.0);
        assert!(baseline.get_std_dev() > 0.0);

        // Normal value should not be anomaly
        assert!(!baseline.is_anomaly(110));

        // Very high value should be anomaly
        assert!(baseline.is_anomaly(1000));
    }

    #[test]
    fn test_rate_limit_key() {
        let key = RateLimitKey::new(RateLimitKeyType::SourceIp, "192.168.1.1".to_string());

        assert_eq!(key.to_key_string(), "SourceIp:192.168.1.1");
    }

    #[test]
    fn test_composite_key() {
        let key = RateLimitKey::composite(vec![
            (RateLimitKeyType::SourceIp, "192.168.1.1".to_string()),
            (RateLimitKeyType::Path, "/api/v1".to_string()),
        ]);

        assert!(key.to_key_string().contains("SourceIp"));
        assert!(key.to_key_string().contains("Path"));
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
        let result = limiter.check(&ctx);
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
            let result = limiter.check(&ctx);
            if matches!(result, RateLimitResult::Limited { .. }) {
                limited_count += 1;
            }
        }

        // Some requests should be rate limited
        assert!(limited_count > 0);
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
    async fn test_jwt_subject_extraction() {
        let config = AdvancedRateLimitConfig::default();
        let limiter = AdvancedRateLimiter::new(config);

        // Create a simple JWT with sub claim
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"user123","iat":1234567890}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxMjM0NTY3ODkwfQ.signature";

        let subject = limiter.extract_jwt_subject(&format!("Bearer {}", jwt));
        assert_eq!(subject, Some("user123".to_string()));
    }
}
