//! Load balancer module for backend pool management
//!
//! Provides:
//! - Multiple algorithms (least_connections, round_robin, weighted, random, ip_hash, least_response_time)
//! - Health-aware routing (skip unhealthy backends)
//! - Session affinity (cookie-based and IP-based sticky sessions)
//! - `max_connections` per server, honoured by every algorithm
//! - Request queuing: a request that finds every server up but full waits for
//!   a place (`load_balancer.queue`, per pool `queue_max_size`/`queue_timeout_ms`)
//! - Slow start for a server that recovers (health check, breaker) or joins on
//!   a reload, through its weight or, for an algorithm that does not weigh
//!   servers, by passing it over in proportion to its ramp
//! - A half-open circuit breaker: one trial request at a time after
//!   `cb_half_open_delay_secs`, closed by `cb_success_threshold` successes
//! - Connection draining: a server a reload removes takes no new sessions and
//!   keeps its own until `connection_draining.timeout_secs`; by hand through
//!   the admin API (`/pools/{pool}/servers/{id}/drain`)
//! - Canary rollouts: a member made a canary through the admin API
//!   (`/pools/{pool}/servers/{id}/canary`) steps through `canary.ramp_percent`
//!   while its error rate holds, and is promoted at the end
//!   (`canary.auto_promote`, or `/promote`): the stable members it replaces drain
//! - Passive health: a member a request could not reach leaves rotation at once,
//!   and the request goes to another member

/// Maximum age of a sticky session mapping before it is silently evicted.
const SESSION_TTL: Duration = Duration::from_hours(1); // 1 hour

/// Sticky sessions a pool holds per affinity mode. The keys are what clients
/// send (a cookie, a header, an address), and an entry used to go only when
/// its own key came back after the TTL, so values sent once stayed for good.
/// A full table is swept of sessions past the TTL at most once a
/// [`SESSION_SWEEP_GAP`]; a session that still finds it full is not made
/// sticky, and its request is balanced as any other.
const MAX_SESSIONS: usize = 100_000;
const SESSION_SWEEP_GAP: Duration = Duration::from_secs(5);

/// Whether `key` may hold a sticky session in `sessions`.
fn session_admitted<K: Eq + std::hash::Hash>(
    sessions: &DashMap<K, (String, Instant)>,
    ceiling: &crate::bounded::Ceiling,
    key: &K,
) -> bool {
    sessions.contains_key(key)
        || ceiling.admits(sessions.len(), || {
            sessions.retain(|_, (_, at)| at.elapsed() <= SESSION_TTL);
            sessions.len()
        })
}

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tracing::{info, warn};

use crate::config::{
    AffinityMode, BackendPoolConfig, CanaryPoolConfig, LoadBalancerConfig, PoolServerConfig,
    TlsMode,
};

// ═══════════════════════════════════════════════════════════════
// Load Balancing Algorithm Trait
// ═══════════════════════════════════════════════════════════════

/// Trait for load balancing algorithm implementations
pub trait LoadBalancingAlgorithm: Send + Sync {
    /// Select a backend from the available servers
    fn select(&self, pool: &BackendPool, ctx: &SelectionContext) -> Option<Arc<BackendServer>>;

    /// Algorithm name for logging/metrics
    fn name(&self) -> &'static str;

    /// Record a completed request (for algorithms that track metrics)
    fn record_completion(&self, _server: &BackendServer, _response_time: Duration, _success: bool) {
        // Default: no-op
    }

    /// Whether the choice follows each server's `effective_weight`, which
    /// already ramps a server in slow start. One that does not has a server
    /// in slow start passed over in proportion to its ramp instead (see
    /// `BackendPool::select`).
    fn weighs_servers(&self) -> bool {
        false
    }
}

/// Context for backend selection
#[derive(Debug, Clone)]
pub struct SelectionContext {
    /// Client IP address (for ip_hash algorithm)
    pub client_ip: IpAddr,
    /// Sticky session cookie value (if present)
    pub session_cookie: Option<String>,
    /// Custom affinity header value (if configured)
    pub affinity_header: Option<String>,
    /// Request path
    pub path: String,
    /// Request host
    pub host: String,
    /// Value of the canary sticky cookie from the request (e.g. "PQCPROXY_CANARY=<server_id>").
    /// Extracted by http_listener using the pool's canary.sticky_cookie_name.
    pub canary_cookie: Option<String>,
    /// Value of the canary sticky header from the request (e.g. "X-Canary-Group: true").
    /// Present when the pool's canary.sticky_header matches a header in the request.
    pub canary_header: Option<String>,
    /// Raw query string without the leading `?`, for `url_param` hashing.
    pub query: Option<String>,
    /// Value of the header a `header:<name>` canary cohort hashes.
    pub cohort_header: Option<String>,
    /// Value of the header named by the pool's `header:<name>` algorithm.
    ///
    /// Extracted by the listener rather than handed the whole header map, the same
    /// way `affinity_header` already is: the pool knows which single header its
    /// algorithm needs (`BackendPool::hash_header_name`), so cloning the rest of
    /// them into every selection would be waste.
    pub hash_header: Option<String>,
}

impl SelectionContext {
    /// What `pool` chooses a member for this request by: the session and
    /// canary cookies, from every Cookie field (HTTP/2 and HTTP/3 may send
    /// each cookie in a field of its own, RFC 9113 section 8.2.3 and RFC 9114
    /// section 4.2.1), the affinity, canary and hash headers the pool names,
    /// and the request's address, path, host and query.
    ///
    /// One definition for both transports. HTTP/3 built its own, which took
    /// the first cookie of any name as the session cookie and never read the
    /// affinity header.
    pub fn for_request(
        pool: &BackendPool,
        session_cookie: &SessionCookieConfig,
        headers: &http::HeaderMap,
        client_ip: IpAddr,
        path: &str,
        host: &str,
        query: Option<&str>,
    ) -> Self {
        let cookies = headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("; ");
        let cookies = (!cookies.is_empty()).then_some(cookies.as_str());
        let header = |name: Option<&str>| {
            name.and_then(|n| headers.get(n))
                .and_then(|v| v.to_str().ok())
                .map(String::from)
        };
        let canary = pool.canary_config.as_ref();
        Self {
            client_ip,
            session_cookie: extract_session_cookie(cookies, session_cookie),
            affinity_header: header(pool.affinity_header.as_deref()),
            path: path.to_string(),
            host: host.to_string(),
            canary_cookie: extract_cookie_by_name(
                cookies,
                canary.map_or("PQCPROXY_CANARY", |c| c.sticky_cookie_name.as_str()),
            ),
            canary_header: header(canary.and_then(|c| c.sticky_header.as_deref())),
            cohort_header: header(canary.and_then(CanaryPoolConfig::cohort_header)),
            query: query.map(String::from),
            hash_header: header(pool.hash_header_name()),
        }
    }
}

/// Result of `BackendPool::select()`.
///
/// Carries the chosen server, the place taken on it, and an optional
/// `Set-Cookie` header value that the HTTP listener must inject into the
/// response to establish a sticky canary assignment for the client.
pub struct SelectionResult {
    /// The selected backend server.
    pub server: Arc<BackendServer>,
    /// The place this request holds on the server until it is dropped.
    pub slot: ConnectionSlot,
    /// If `Some(header_value)`, the listener should append this as a `Set-Cookie`
    /// response header (format: `PQCPROXY_CANARY=<id>; Path=/; …`).
    pub set_canary_cookie: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Backend Server
// ═══════════════════════════════════════════════════════════════

/// How many parts a rollback window is counted in.
const OUTCOME_BUCKETS: usize = 12;

/// Requests and errors over a rolling window, in buckets: the oldest leave one
/// bucket at a time, so a count never starts again from nothing.
#[derive(Debug)]
struct OutcomeWindow {
    origin: Instant,
    bucket_ms: u64,
    newest: u64,
    /// (requests, errors), in a ring one longer than the window
    buckets: [(u64, u64); OUTCOME_BUCKETS + 1],
}

impl OutcomeWindow {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            bucket_ms: 0,
            newest: 0,
            buckets: [(0, 0); OUTCOME_BUCKETS + 1],
        }
    }

    fn slot(bucket: u64) -> usize {
        usize::try_from(bucket % (OUTCOME_BUCKETS as u64 + 1)).unwrap_or(0)
    }

    /// Move to `now`, emptying the buckets that have left the window.
    fn roll(&mut self, now: Instant) {
        if self.bucket_ms == 0 {
            return;
        }
        let elapsed = u64::try_from(now.saturating_duration_since(self.origin).as_millis())
            .unwrap_or(u64::MAX);
        let bucket = elapsed / self.bucket_ms;
        if bucket > self.newest {
            let steps = (bucket - self.newest).min(OUTCOME_BUCKETS as u64 + 1);
            for step in 1..=steps {
                self.buckets[Self::slot(self.newest + step)] = (0, 0);
            }
            self.newest = bucket;
        }
    }

    /// Use a window of `window`, starting again if its length has changed.
    fn shape(&mut self, window: Duration, now: Instant) {
        let bucket_ms = u64::try_from(window.as_millis())
            .unwrap_or(u64::MAX)
            .div_ceil(OUTCOME_BUCKETS as u64)
            .max(1);
        if bucket_ms != self.bucket_ms {
            *self = Self::new();
            self.origin = now;
            self.bucket_ms = bucket_ms;
        }
        self.roll(now);
    }

    fn record(&mut self, failed: bool, window: Duration, now: Instant) {
        self.shape(window, now);
        let bucket = &mut self.buckets[Self::slot(self.newest)];
        bucket.0 += 1;
        bucket.1 += u64::from(failed);
    }

    /// An error in a request already counted: its body failed after its head.
    fn record_late_error(&mut self, window: Duration, now: Instant) {
        self.shape(window, now);
        self.buckets[Self::slot(self.newest)].1 += 1;
    }

    /// (requests, errors) in the window as of `now`.
    fn totals(&mut self, now: Instant) -> (u64, u64) {
        self.roll(now);
        self.buckets
            .iter()
            .fold((0, 0), |(requests, errors), (r, e)| {
                (requests + r, errors + e)
            })
    }
}

#[expect(clippy::cast_precision_loss)]
fn error_rate((requests, errors): (u64, u64)) -> f64 {
    if requests == 0 {
        0.0
    } else {
        (errors.min(requests)) as f64 / requests as f64
    }
}

/// The canary a roll in `0..span` lands on, of `(server, percent)` shares:
/// each canary has its own share of new traffic, and the rest is the stable
/// servers'. Shares that add up to more than 100 divide all of it.
/// A client's place in `0..range` for its canary cohort (`canary.cohort`):
/// a hash of its address or of the cohort header, salted with the canary's
/// id so each rollout draws its own cohort. Where the place is below the
/// canary's weight the client goes to it; a weight that rises keeps every
/// client already there. `None` for chance (`random`, or a header absent).
fn cohort_roll(
    cfg: &CanaryPoolConfig,
    ctx: &SelectionContext,
    salt: &str,
    range: u32,
) -> Option<u32> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update([0]);
    match cfg.cohort.as_str() {
        "ip" => match ctx.client_ip {
            IpAddr::V4(ip) => h.update(ip.octets()),
            IpAddr::V6(ip) => h.update(ip.octets()),
        },
        _ if cfg.cohort_header().is_some() => h.update(ctx.cohort_header.as_ref()?.as_bytes()),
        _ => return None,
    }
    let digest = h.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u32::try_from(u64::from_be_bytes(first) % u64::from(range)).ok()
}

fn canary_for_roll<T>(shares: &[(T, u32)], mut roll: u32) -> Option<&T> {
    shares.iter().find_map(|(canary, percent)| {
        if roll < *percent {
            Some(canary)
        } else {
            roll -= percent;
            None
        }
    })
}

/// One request in flight on a [`BackendServer`]; see
/// [`BackendServer::try_acquire_slot`].
pub struct ConnectionSlot {
    server: Arc<BackendServer>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let _ =
            self.server
                .active_connections
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1));
        // A place is free: one request queued for this pool tries again.
        if let Some(freed) = self.server.freed.read().as_ref() {
            freed.notify_one();
        }
    }
}

/// Individual backend server in a pool
pub struct BackendServer {
    /// Server ID (unique within pool)
    pub id: String,
    /// Server address
    pub address: SocketAddr,
    /// Weight for weighted algorithms (1-1000)
    pub weight: u32,
    /// Base weight (before slow start adjustment)
    pub base_weight: u32,
    /// Priority for failover (lower = higher priority)
    pub priority: u32,
    /// Maximum connections to this server
    pub max_connections: u32,
    /// Request timeout
    pub timeout: Duration,
    /// TLS mode
    pub tls_mode: TlsMode,
    /// CA to verify this server against when re-encrypting, beyond the native
    /// roots.
    pub tls_cert: Option<std::path::PathBuf>,
    /// Skip certificate verification (refused in production by config
    /// validation).
    pub tls_skip_verify: bool,
    /// Server name to present and verify, when it is not the address's host.
    pub tls_sni: Option<String>,
    /// A connection per request (`disable_pooling`)
    pub disable_pooling: bool,
    /// Its retry policy (`retries`, `retry_backoff_ms`, `retry_on`)
    pub retries: Option<u8>,
    pub retry_backoff_ms: Option<u64>,
    pub retry_on: Option<Vec<String>>,

    // === Circuit breaker thresholds (per-backend overrides) ===
    /// Consecutive failures before tripping the circuit breaker
    pub cb_failure_threshold: u32,
    /// Consecutive successes to close a tripped circuit breaker
    pub cb_success_threshold: u32,
    /// How long a tripped breaker stays open before trial requests go through
    pub cb_half_open_delay: Duration,

    // === Metrics ===
    /// Current active connections
    pub active_connections: AtomicU32,
    /// Total requests served
    pub total_requests: AtomicU64,
    /// Total failures
    pub total_failures: AtomicU64,
    /// Moving average response time (microseconds)
    pub avg_response_time_us: AtomicU64,

    // === State ===
    /// Health status
    pub health: RwLock<BackendHealth>,
    /// Slow start state
    pub slow_start: RwLock<Option<SlowStartState>>,
    /// Draining state
    pub draining: RwLock<Option<DrainingState>>,
    /// The pool's signal that a place has been given back (queued requests
    /// wait on it), set by the pool that holds this server
    freed: RwLock<Option<Arc<tokio::sync::Notify>>>,
    /// Slow start on recovery: (duration, initial weight percent), as the
    /// pool that holds this server was configured
    ramp: RwLock<Option<(Duration, u32)>>,

    // === Canary state ===
    /// Whether this server is a canary deployment target: set from its
    /// config, and changed at run time by a rollout (`BackendPool::start_canary`,
    /// `BackendPool::promote`)
    canary: AtomicBool,
    /// Fraction of *new* traffic to route here when it is the active canary (0–100)
    pub canary_weight_percent: AtomicU8,
    /// True when the canary has been suspended (manually or by auto-rollback)
    pub canary_suspended: AtomicBool,
    /// Requests and errors over the rollback window
    canary_window: Mutex<OutcomeWindow>,
}

/// Backend health status
#[derive(Clone, Debug)]
pub struct BackendHealth {
    /// Whether backend is healthy
    pub healthy: bool,
    /// Last health check time
    pub last_check: Instant,
    /// Consecutive failures
    pub consecutive_failures: u32,
    /// Consecutive successes
    pub consecutive_successes: u32,
    /// Circuit breaker open
    pub circuit_open: bool,
    /// When it opened: trial requests go through `cb_half_open_delay` later
    pub opened_at: Option<Instant>,
}

impl Default for BackendHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            last_check: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            circuit_open: false,
            opened_at: None,
        }
    }
}

/// Slow start state for recovering backends
#[derive(Clone, Debug)]
pub struct SlowStartState {
    /// When slow start began
    pub started_at: Instant,
    /// Duration of slow start
    pub duration: Duration,
    /// Initial weight factor (0.0 - 1.0)
    pub initial_weight_factor: f64,
}

/// Connection draining state
#[derive(Clone, Debug)]
pub struct DrainingState {
    /// When draining started
    pub started_at: Instant,
    /// Maximum drain duration
    pub timeout: Duration,
    /// Whether server should be removed after draining
    pub remove_after: bool,
}

impl BackendServer {
    /// This pool member as a [`BackendConfig`](crate::config::BackendConfig), for the backend client.
    ///
    /// One definition for both transports; each built its own, and they
    /// disagreed on nothing only by luck.
    pub fn backend_config(&self) -> crate::config::BackendConfig {
        crate::config::BackendConfig {
            name: self.id.clone(),
            backend_type: crate::config::BackendType::Http1,
            address: self.address.to_string(),
            tls_mode: self.tls_mode.clone(),
            tls: matches!(self.tls_mode, TlsMode::Reencrypt),
            // The pool member's own TLS settings. These were parsed from the
            // pool config and then dropped, so a pool of re-encrypting
            // servers was verified against the native roots only, whatever it
            // configured.
            tls_cert: self.tls_cert.clone(),
            tls_client_cert: None,
            tls_client_key: None,
            tls_skip_verify: self.tls_skip_verify,
            tls_sni: self.tls_sni.clone(),
            timeout_ms: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            max_connections: self.max_connections,
            health_check: None,
            health_check_interval_secs: 30,
            retries: self.retries,
            retry_backoff_ms: self.retry_backoff_ms,
            retry_on: self.retry_on.clone(),
            circuit_breaker: None,
            disable_pooling: self.disable_pooling,
        }
    }

    /// Create from configuration.
    ///
    /// F-06: Returns `Result` instead of panicking on an invalid address so that
    /// a hot-reload with a malformed config rejects the pool rather than aborting
    /// the process.  Callers (including `BackendPool::from_config`) log and skip
    /// invalid entries rather than crashing the proxy.
    pub fn from_config(config: &PoolServerConfig) -> anyhow::Result<Self> {
        let address: SocketAddr = config.address.parse().map_err(|e| {
            anyhow::anyhow!("Invalid backend server address '{}': {}", config.address, e)
        })?;

        Ok(Self {
            id: format!("{}:{}", address.ip(), address.port()),
            address,
            weight: config.weight,
            base_weight: config.weight,
            priority: config.priority,
            max_connections: config.max_connections,
            timeout: Duration::from_millis(config.timeout_ms),
            tls_mode: config.tls_mode.clone(),
            tls_cert: config.tls_cert.clone(),
            tls_skip_verify: config.tls_skip_verify,
            tls_sni: config.tls_sni.clone(),
            cb_failure_threshold: config.cb_failure_threshold.unwrap_or(5),
            cb_success_threshold: config.cb_success_threshold.unwrap_or(3),
            cb_half_open_delay: Duration::from_secs(config.cb_half_open_delay_secs.unwrap_or(30)),
            active_connections: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            health: RwLock::new(BackendHealth::default()),
            slow_start: RwLock::new(None),
            draining: RwLock::new(None),
            freed: RwLock::new(None),
            ramp: RwLock::new(None),
            disable_pooling: config.disable_pooling,
            retries: config.retries,
            retry_backoff_ms: config.retry_backoff_ms,
            retry_on: config.retry_on.clone(),
            canary: AtomicBool::new(config.canary),
            canary_weight_percent: AtomicU8::new(config.canary_weight_percent),
            canary_suspended: AtomicBool::new(false),
            canary_window: Mutex::new(OutcomeWindow::new()),
        })
    }

    /// Check if server is available for requests.
    ///
    /// Canary servers that have been suspended (manually or by auto-rollback)
    /// are treated as unavailable so they don't receive traffic via normal routing
    /// or sticky-session recovery paths either.
    pub fn is_available(&self) -> bool {
        let health = self.health.read();
        let draining = self.draining.read();

        health.healthy
            && (!health.circuit_open || self.is_half_open(&health))
            && draining.is_none()
            && !(self.is_canary() && self.canary_suspended.load(Ordering::Relaxed))
    }

    /// A tripped breaker past `cb_half_open_delay`: one trial request at a
    /// time goes through, and `cb_success_threshold` of them close it (see
    /// `record_result`). Without this a tripped server never had a request
    /// again, so it never had the successes that close the breaker.
    fn is_half_open(&self, health: &BackendHealth) -> bool {
        health.circuit_open
            && health
                .opened_at
                .is_some_and(|at| at.elapsed() >= self.cb_half_open_delay)
            && self.active_connections.load(Ordering::Relaxed) == 0
    }

    /// Whether the server has a place for one more request
    /// (`max_connections`, 0 = no limit).
    pub fn has_capacity(&self) -> bool {
        self.max_connections == 0
            || self.active_connections.load(Ordering::Relaxed) < self.max_connections
    }

    /// The share of its weight a server in slow start has now, if it is in
    /// slow start.
    pub fn ramp_factor(&self) -> Option<f64> {
        let slow_start = self.slow_start.read();
        let ss = slow_start.as_ref()?;
        let elapsed = ss.started_at.elapsed();
        (elapsed < ss.duration).then(|| {
            let progress = elapsed.as_secs_f64() / ss.duration.as_secs_f64();
            (1.0 - ss.initial_weight_factor).mul_add(progress, ss.initial_weight_factor)
        })
    }

    /// Slow start, where the pool holding this server has it configured.
    fn ramp_up(&self) {
        let ramp = *self.ramp.read();
        if let Some((duration, percent)) = ramp {
            self.start_slow_start(duration, percent);
        }
    }

    /// Give this server to `pool`: its freed-place signal and its slow start.
    fn join(&self, freed: &Arc<tokio::sync::Notify>, ramp: Option<(Duration, u32)>) {
        *self.freed.write() = Some(Arc::clone(freed));
        *self.ramp.write() = ramp;
    }

    /// Whether this server is a canary now.
    pub fn is_canary(&self) -> bool {
        self.canary.load(Ordering::Acquire)
    }

    /// Check if this canary server is available for canary-specific routing.
    pub fn is_canary_available(&self) -> bool {
        self.is_canary() && self.is_available()
    }

    /// A request could not reach this server (its connection was refused or
    /// never made): it is out of rotation at once, rather than after its
    /// breaker's run of failures or its next health check, which puts it back
    /// when it answers again.
    pub fn mark_unreachable(&self) {
        let mut health = self.health.write();
        if health.healthy {
            health.healthy = false;
            warn!(
                "Backend {} could not be reached: out of rotation until its health check finds it",
                self.id
            );
        }
    }

    /// Make this server a canary taking `weight`% of new requests: out of
    /// draining and suspension, its error window started afresh.
    fn make_canary(&self, weight: u8) {
        self.canary_weight_percent.store(weight, Ordering::Relaxed);
        *self.canary_window.lock() = OutcomeWindow::new();
        self.canary_suspended.store(false, Ordering::Relaxed);
        *self.draining.write() = None;
        self.canary.store(true, Ordering::Release);
        info!("Backend {} is a canary at {}%", self.id, weight);
    }

    /// Make this server a stable one: it takes its share of normal routing.
    fn make_stable(&self) {
        self.canary.store(false, Ordering::Release);
        self.canary_weight_percent.store(0, Ordering::Relaxed);
        self.canary_suspended.store(false, Ordering::Relaxed);
        *self.canary_window.lock() = OutcomeWindow::new();
        *self.draining.write() = None;
    }

    /// Whether this server keeps the sessions it has: it is draining, and up.
    fn keeps_sessions_while_draining(&self) -> bool {
        self.is_draining() && {
            let health = self.health.read();
            health.healthy && !health.circuit_open
        }
    }

    /// Take a place on this server, if it has one, until the returned slot
    /// drops. The check and the count are one atomic step, so the last place
    /// goes to one request however many arrive at once. `trial` is a request
    /// to a server whose breaker is open: one at a time.
    ///
    /// `active_connections` is what least-connections, least-response-time and
    /// first-available read, and what `max_connections` is enforced against.
    /// A slot cannot be released twice or not at all.
    pub fn try_acquire_slot(self: &Arc<Self>, trial: bool) -> Option<ConnectionSlot> {
        let ceiling = match (trial, self.max_connections) {
            (true, _) => 1,
            (false, 0) => u32::MAX,
            (false, most) => most,
        };
        self.active_connections
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < ceiling).then_some(active + 1)
            })
            .ok()?;
        Some(ConnectionSlot {
            server: Arc::clone(self),
        })
    }

    /// Get effective weight considering slow start
    pub fn effective_weight(&self) -> u32 {
        let slow_start = self.slow_start.read();
        if let Some(ref ss) = *slow_start {
            let elapsed = ss.started_at.elapsed();
            if elapsed < ss.duration {
                let progress = elapsed.as_secs_f64() / ss.duration.as_secs_f64();
                let factor =
                    (1.0 - ss.initial_weight_factor).mul_add(progress, ss.initial_weight_factor);
                // clamp(0.0, u32::MAX as f64) ensures value is non-negative and within u32 range.
                #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                return (self.base_weight as f64 * factor).clamp(0.0, u32::MAX as f64) as u32;
            }
        }
        self.base_weight
    }

    /// Record request result
    pub fn record_result(&self, success: bool, response_time: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if success {
            let mut health = self.health.write();
            health.consecutive_failures = 0;
            health.consecutive_successes += 1;

            // Recover from circuit breaker (use per-backend threshold)
            if health.circuit_open && health.consecutive_successes >= self.cb_success_threshold {
                health.circuit_open = false;
                health.opened_at = None;
                health.healthy = true;
                info!("Backend {} circuit breaker closed", self.id);
                drop(health);
                self.ramp_up();
            }
        } else {
            self.total_failures.fetch_add(1, Ordering::Relaxed);

            let mut health = self.health.write();
            health.consecutive_successes = 0;
            health.consecutive_failures += 1;

            // Open circuit breaker after per-backend failure threshold; a
            // trial that fails while half-open opens it for another delay.
            if health.circuit_open {
                health.opened_at = Some(Instant::now());
            } else if health.consecutive_failures >= self.cb_failure_threshold {
                health.circuit_open = true;
                health.opened_at = Some(Instant::now());
                warn!(
                    "Backend {} circuit breaker opened after {} failures",
                    self.id, health.consecutive_failures
                );
            }
        }

        // Update response time EMA (alpha = 0.3)
        let new_time = response_time.as_micros().try_into().unwrap_or(u64::MAX);
        let old_time = self.avg_response_time_us.load(Ordering::Relaxed);
        let ema = if old_time == 0 {
            new_time
        } else {
            ((new_time * 3) + (old_time * 7)) / 10
        };
        self.avg_response_time_us.store(ema, Ordering::Relaxed);
    }

    /// Start slow start phase
    pub fn start_slow_start(&self, duration: Duration, initial_weight_percent: u32) {
        let mut slow_start = self.slow_start.write();
        *slow_start = Some(SlowStartState {
            started_at: Instant::now(),
            duration,
            initial_weight_factor: initial_weight_percent as f64 / 100.0,
        });
        info!("Backend {} entering slow start ({:?})", self.id, duration);
    }

    /// Start draining
    pub fn start_draining(&self, timeout: Duration) {
        let mut draining = self.draining.write();
        *draining = Some(DrainingState {
            started_at: Instant::now(),
            timeout,
            remove_after: false,
        });
        info!(
            "Backend {} marked for draining ({:?} timeout)",
            self.id, timeout
        );
    }

    /// Take the server out of draining: it takes new requests again.
    pub fn stop_draining(&self) {
        *self.draining.write() = None;
        info!("Backend {} no longer draining", self.id);
    }

    /// Whether the server is draining and its time to do so has not run out.
    pub fn is_draining(&self) -> bool {
        self.draining
            .read()
            .as_ref()
            .is_some_and(|d| d.started_at.elapsed() < d.timeout)
    }

    // ── Canary helpers ────────────────────────────────────────────────────────

    /// Suspend this canary server so it receives no further traffic.
    pub fn suspend_canary(&self) {
        self.canary_suspended.store(true, Ordering::Relaxed);
        warn!("Canary server {} suspended", self.id);
    }

    /// Resume a suspended canary server and reset its error-rate window.
    pub fn resume_canary(&self) {
        self.canary_suspended.store(false, Ordering::Relaxed);
        *self.canary_window.lock() = OutcomeWindow::new();
        info!("Canary server {} resumed", self.id);
    }

    /// Return the current error rate in the sliding window (0.0–1.0).
    pub fn canary_error_rate(&self) -> f64 {
        error_rate(self.canary_window.lock().totals(Instant::now()))
    }

    /// Record a canary request outcome and potentially trigger auto-rollback.
    ///
    /// `stable_rate` is the stable servers' error rate, when it is to be
    /// compared. Returns `true` if auto-rollback was just triggered (i.e. the
    /// canary was suspended by this call). The caller should log a warning in
    /// that case.
    pub fn record_canary_result(
        &self,
        success: bool,
        config: &CanaryPoolConfig,
        stable_rate: Option<f64>,
    ) -> bool {
        if !config.auto_rollback {
            return false;
        }
        let now = Instant::now();
        let totals = {
            let mut window = self.canary_window.lock();
            window.record(
                !success,
                Duration::from_secs(config.rollback_window_secs),
                now,
            );
            window.totals(now)
        };
        self.rollback_if_due(totals, config, stable_rate)
    }

    /// Count a failure in the body of a response already counted by its head.
    fn record_canary_late_error(
        &self,
        config: &CanaryPoolConfig,
        stable_rate: Option<f64>,
    ) -> bool {
        if !config.auto_rollback {
            return false;
        }
        let now = Instant::now();
        let totals = {
            let mut window = self.canary_window.lock();
            window.record_late_error(Duration::from_secs(config.rollback_window_secs), now);
            window.totals(now)
        };
        self.rollback_if_due(totals, config, stable_rate)
    }

    fn rollback_if_due(
        &self,
        totals: (u64, u64),
        config: &CanaryPoolConfig,
        stable_rate: Option<f64>,
    ) -> bool {
        let (requests, errors) = totals;
        let rate = error_rate(totals);
        let worse_than_stable =
            stable_rate.is_none_or(|stable| rate - stable > config.rollback_error_rate);
        requests >= config.rollback_min_requests
            && errors >= config.rollback_min_errors
            && rate > config.rollback_error_rate
            && worse_than_stable
            // Compare-and-swap so only the first trigger reports it.
            && self
                .canary_suspended
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }
}

// ═══════════════════════════════════════════════════════════════
// Backend Pool
// ═══════════════════════════════════════════════════════════════

/// Pool of backend servers with load balancing
pub struct BackendPool {
    /// Pool name
    pub name: String,
    /// List of servers
    pub servers: RwLock<Vec<Arc<BackendServer>>>,
    /// Load balancing algorithm
    algorithm: Box<dyn LoadBalancingAlgorithm>,
    /// Request header the algorithm hashes on, when it is `header:<name>`.
    /// The listener reads this to extract that one header into the selection
    /// context rather than cloning the whole header map per request.
    hash_header_name: Option<String>,
    /// Session affinity mode
    pub affinity: AffinityMode,
    /// Custom affinity header name
    pub affinity_header: Option<String>,
    /// Enable health-aware routing
    pub health_aware: bool,
    /// Health check path
    pub health_check_path: Option<String>,
    /// Health check interval
    pub health_check_interval: Duration,

    // === Session tracking ===
    /// Cookie → (server_id, last_access) for cookie affinity with TTL eviction.
    cookie_sessions: DashMap<String, (String, Instant)>,
    /// IP → (server_id, last_access) for IP-hash affinity with TTL eviction.
    ip_sessions: DashMap<IpAddr, (String, Instant)>,
    /// Header-value → (server_id, last_access) for header-based affinity.
    /// P2-fix: previously used cookie_sessions (shared map), causing cross-mode confusion.
    header_sessions: DashMap<String, (String, Instant)>,
    /// The three session tables' ceilings
    session_ceilings: [crate::bounded::Ceiling; 3],

    // === Round-robin state ===
    rr_counter: AtomicU64,

    // === Weighted round-robin state ===
    wrr_state: RwLock<WeightedRoundRobinState>,

    // === Canary state ===
    /// Pool-level canary configuration (None when canary is not configured).
    pub canary_config: Option<CanaryPoolConfig>,
    /// Canary sticky-cookie → (server_id, last_access) with TTL eviction.
    canary_sessions: DashMap<String, (String, Instant)>,
    /// The stable servers' requests and errors, to compare the canary with
    stable_outcomes: Mutex<OutcomeWindow>,

    /// The configuration this pool was built from, so a reload can tell
    /// whether it changed.
    source: BackendPoolConfig,

    // === Lifecycle ===
    /// Woken when one of this pool's servers gives a place back
    freed: Arc<tokio::sync::Notify>,
    /// Requests waiting for a place: (most at once, longest wait), when the
    /// pool queues (`load_balancer.queue`, `queue_max_size`, `queue_timeout_ms`)
    queue: Option<(usize, Duration)>,
    /// Requests waiting now
    queued: AtomicUsize,
    /// Requests refused for want of a place: the queue full or the wait over
    queue_refused: AtomicU64,
    /// Slow start for a server that recovers or joins (`load_balancer.slow_start`)
    ramp: Option<(Duration, u32)>,
    /// How long a server removed by a reload drains (`load_balancer.connection_draining`)
    drain_for: Option<Duration>,
    /// The canary rollout under way, or the last one, when one was started
    /// through the admin API
    rollout: Mutex<Option<Rollout>>,
}

/// How often a rollout is looked at to move it on.
const ROLLOUT_TICK: Duration = Duration::from_secs(1);

/// A canary's progressive rollout (`canary.ramp_percent`): its weight steps
/// up while its error rate holds, and at the end it is promoted
/// (`canary.auto_promote`) or waits to be.
#[derive(Debug, Clone)]
struct Rollout {
    server: String,
    step: usize,
    started: Instant,
    step_started: Instant,
    /// The server's requests when the step began
    requests_at_step: u64,
    outcome: RolloutOutcome,
}

/// Where a rollout is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutOutcome {
    /// Stepping through the ramp
    Ramping,
    /// At the last step, for `promote` through the admin API
    AwaitingPromotion,
    /// The canary became a stable server
    Promoted,
    /// Its error rate suspended the canary
    RolledBack,
    /// The server stopped being this rollout's canary otherwise: made stable
    /// or given a fixed weight by hand, or removed by a reload
    Ended,
}

/// A rollout as the admin API shows it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RolloutStatus {
    pub server: String,
    pub outcome: RolloutOutcome,
    /// The step it is at, from 1
    pub step: usize,
    pub steps: Vec<u8>,
    pub weight_percent: u8,
    pub step_secs: u64,
    pub step_elapsed_secs: u64,
    /// The canary's requests in this step, and how many the step needs
    pub step_requests: u64,
    pub step_min_requests: u64,
    pub elapsed_secs: u64,
}

/// State for weighted round-robin algorithm
#[derive(Default)]
struct WeightedRoundRobinState {
    /// Current weight for each server
    current_weights: Vec<i64>,
}

impl BackendPool {
    /// Create pool from configuration
    pub fn from_config(config: &BackendPoolConfig, lb_config: &LoadBalancerConfig) -> Self {
        let algorithm = Self::create_algorithm(&config.algorithm);
        let hash_header_name = config
            .algorithm
            .strip_prefix("header:")
            .filter(|n| !n.is_empty())
            .map(String::from);

        let servers: Vec<Arc<BackendServer>> = config
            .servers
            .iter()
            .filter_map(|s| match BackendServer::from_config(s) {
                Ok(server) => Some(Arc::new(server)),
                Err(e) => {
                    // F-06: Log and skip rather than panic — preserves proxy liveness
                    // under a hot-reload that introduces a malformed address.
                    warn!("Skipping invalid backend server '{}': {}", s.address, e);
                    None
                }
            })
            .collect();

        info!(
            "Created backend pool '{}' with {} servers using {} algorithm",
            config.name,
            servers.len(),
            algorithm.name()
        );

        let freed = Arc::new(tokio::sync::Notify::new());
        let queue = lb_config.queue.enabled.then(|| {
            (
                config.queue_max_size.unwrap_or(lb_config.queue.max_size),
                Duration::from_millis(
                    config
                        .queue_timeout_ms
                        .unwrap_or(lb_config.queue.timeout_ms),
                ),
            )
        });
        let ramp = lb_config.slow_start.enabled.then(|| {
            (
                Duration::from_secs(lb_config.slow_start.duration_secs),
                lb_config.slow_start.initial_weight_percent,
            )
        });
        let drain_for = lb_config
            .connection_draining
            .enabled
            .then(|| Duration::from_secs(lb_config.connection_draining.timeout_secs));
        for server in &servers {
            server.join(&freed, ramp);
        }

        Self {
            name: config.name.clone(),
            servers: RwLock::new(servers),
            algorithm,
            affinity: config.affinity.clone(),
            affinity_header: config.affinity_header.clone(),
            health_aware: config.health_aware,
            health_check_path: config.health_check_path.clone(),
            health_check_interval: Duration::from_secs(config.health_check_interval_secs),
            cookie_sessions: DashMap::new(),
            ip_sessions: DashMap::new(),
            header_sessions: DashMap::new(),
            session_ceilings: std::array::from_fn(|_| {
                crate::bounded::Ceiling::new(MAX_SESSIONS, SESSION_SWEEP_GAP)
            }),
            rr_counter: AtomicU64::new(0),
            hash_header_name,
            wrr_state: RwLock::new(WeightedRoundRobinState::default()),
            canary_config: config.canary.clone(),
            canary_sessions: DashMap::new(),
            stable_outcomes: Mutex::new(OutcomeWindow::new()),
            source: config.clone(),
            freed,
            queue,
            queued: AtomicUsize::new(0),
            queue_refused: AtomicU64::new(0),
            ramp,
            drain_for,
            rollout: Mutex::new(None),
        }
    }

    /// Every algorithm name this build accepts.
    ///
    /// `url_param` and `header` take an argument after a colon
    /// (`url_param:sessionid`, `header:X-Tenant`), so they are listed here by
    /// prefix and matched separately.
    pub const ALGORITHMS: &'static [&'static str] = &[
        "least_connections",
        "round_robin",
        "weighted_round_robin",
        "random",
        "ip_hash",
        "least_response_time",
        "uri_hash",
        "url_param:<name>",
        "header:<name>",
        "first_available",
        "power_of_two_choices",
    ];

    /// Whether `name` is an algorithm this build implements.
    ///
    /// Used by config validation so a typo is refused at load rather than
    /// silently becoming `least_connections` — an operator who asked for
    /// `ip_hash` and got round-robin behaviour has no way to notice.
    pub fn is_known_algorithm(name: &str) -> bool {
        matches!(
            name,
            "least_connections"
                | "round_robin"
                | "weighted_round_robin"
                | "random"
                | "ip_hash"
                | "least_response_time"
                | "uri_hash"
                | "first_available"
                | "power_of_two_choices"
        ) || name
            .split_once(':')
            .is_some_and(|(kind, arg)| matches!(kind, "url_param" | "header") && !arg.is_empty())
    }

    /// Create algorithm by name
    fn create_algorithm(name: &str) -> Box<dyn LoadBalancingAlgorithm> {
        if let Some((kind, arg)) = name.split_once(':') {
            if !arg.is_empty() {
                match kind {
                    "url_param" => return Box::new(UrlParamHashAlgorithm::new(arg)),
                    "header" => return Box::new(HeaderHashAlgorithm::new(arg)),
                    _ => {}
                }
            }
        }

        match name {
            "round_robin" => Box::new(RoundRobinAlgorithm),
            "weighted_round_robin" => Box::new(WeightedRoundRobinAlgorithm),
            "random" => Box::new(RandomAlgorithm),
            "ip_hash" => Box::new(IpHashAlgorithm),
            "least_response_time" => Box::new(LeastResponseTimeAlgorithm),
            "uri_hash" => Box::new(UriHashAlgorithm),
            "first_available" => Box::new(FirstAvailableAlgorithm),
            "power_of_two_choices" => Box::new(PowerOfTwoChoicesAlgorithm),
            _ => Box::new(LeastConnectionsAlgorithm), // Default: least_connections
        }
    }

    /// Select a backend server and take a place on it.
    ///
    /// Canary routing is attempted first (when configured and enabled), then
    /// falls back to normal sticky-session / algorithm selection among non-canary
    /// servers.  Returns a `SelectionResult` that holds the place and may carry a
    /// `Set-Cookie` header value that the caller must inject into the HTTP
    /// response. A place another request took first sends this one back to
    /// choose again.
    pub fn select(&self, ctx: &SelectionContext) -> Option<SelectionResult> {
        let attempts = self.servers.read().len() + 1;
        for _ in 0..attempts {
            let (server, set_canary_cookie) = self.choose(ctx)?;
            let trial = self.health_aware && server.health.read().circuit_open;
            if let Some(slot) = server.try_acquire_slot(trial) {
                return Some(SelectionResult {
                    server,
                    slot,
                    set_canary_cookie,
                });
            }
        }
        None
    }

    /// The server this request should go to, and the canary cookie to set.
    fn choose(&self, ctx: &SelectionContext) -> Option<(Arc<BackendServer>, Option<String>)> {
        // Try canary routing first.
        if let Some(chosen) = self.try_canary_select(ctx) {
            return Some(chosen);
        }

        // Normal routing (canary servers are excluded from get_healthy_servers).
        // A session stays with its server while that server drains: draining
        // takes no new sessions and lets the ones it has finish.
        if let Some(server) = self.check_sticky_session(ctx) {
            if server.has_capacity() {
                return Some((server, None));
            }
        }

        let server = self.algorithm.select(self, ctx)?;
        let server = self.pass_over_ramping(server);
        self.record_sticky_session(ctx, &server);

        Some((server, None))
    }

    /// A server in slow start chosen by an algorithm that does not weigh
    /// servers is kept in proportion to its ramp; otherwise the least busy
    /// server that is not ramping takes the request, when there is one.
    fn pass_over_ramping(&self, chosen: Arc<BackendServer>) -> Arc<BackendServer> {
        if self.algorithm.weighs_servers() {
            return chosen;
        }
        let Some(factor) = chosen.ramp_factor() else {
            return chosen;
        };
        if rand::random::<f64>() < factor {
            return chosen;
        }
        self.get_healthy_servers()
            .into_iter()
            .filter(|s| !Arc::ptr_eq(s, &chosen) && s.ramp_factor().is_none())
            .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
            .unwrap_or(chosen)
    }

    /// [`Self::select`], waiting for a place when every server that could
    /// take the request is up but full: up to the queue's time, and only
    /// while fewer than its size wait. A pool with no server up does not
    /// queue; nothing would free a place.
    pub async fn select_queued(&self, ctx: &SelectionContext) -> Option<SelectionResult> {
        if let Some(chosen) = self.select(ctx) {
            return Some(chosen);
        }
        let (most, wait) = self.queue?;
        let any_up = self
            .servers
            .read()
            .iter()
            .any(|s| !s.is_canary() && s.is_available());
        if !any_up {
            return None;
        }
        if self.queued.fetch_add(1, Ordering::AcqRel) >= most {
            self.queued.fetch_sub(1, Ordering::AcqRel);
            self.queue_refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        struct Leave<'a>(&'a AtomicUsize);
        impl Drop for Leave<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::AcqRel);
            }
        }
        let _leave = Leave(&self.queued);
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Registered before looking again, so a place freed in between
            // is not missed.
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if let Some(chosen) = self.select(ctx) {
                return Some(chosen);
            }
            if tokio::time::timeout_at(deadline, freed).await.is_err() {
                self.queue_refused.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
    }

    /// Requests waiting for a place now.
    pub fn queued(&self) -> usize {
        self.queued.load(Ordering::Relaxed)
    }

    /// The pool's load (its members' requests, its queue) and how many of
    /// its members have their breaker open, for the metrics.
    pub fn load(&self) -> (crate::metrics::PoolLoad, u64) {
        let servers = self.servers.read();
        let load = crate::metrics::PoolLoad {
            total: servers
                .iter()
                .map(|s| s.total_requests.load(Ordering::Relaxed))
                .sum(),
            active: servers
                .iter()
                .map(|s| u64::from(s.active_connections.load(Ordering::Relaxed)))
                .sum(),
            waiting: self.queued.load(Ordering::Relaxed) as u64,
            refused: self.queue_refused.load(Ordering::Relaxed),
        };
        let open = servers
            .iter()
            .filter(|s| s.health.read().circuit_open)
            .count() as u64;
        (load, open)
    }

    /// Canary-specific selection logic.  Returns `None` if canary is not
    /// configured/enabled or no canary server has a place.
    fn try_canary_select(
        &self,
        ctx: &SelectionContext,
    ) -> Option<(Arc<BackendServer>, Option<String>)> {
        let canary_cfg = self.canary_config.as_ref()?;
        if !canary_cfg.enabled {
            return None;
        }

        // Collect the canary servers that can take a request.
        let available_canaries: Vec<Arc<BackendServer>> = {
            let servers = self.servers.read();
            servers
                .iter()
                .filter(|s| s.is_canary_available() && s.has_capacity())
                .cloned()
                .collect()
        };

        if available_canaries.is_empty() {
            return None;
        }

        // 1. Check canary sticky cookie from the request.
        if canary_cfg.sticky {
            if let Some(ref cookie_val) = ctx.canary_cookie {
                let ttl = Duration::from_secs(canary_cfg.sticky_cookie_ttl_secs);
                if let Some(mut entry) = self.canary_sessions.get_mut(cookie_val) {
                    if entry.1.elapsed() <= ttl {
                        entry.1 = Instant::now(); // refresh TTL
                        let id = entry.0.clone();
                        drop(entry);
                        if let Some(server) =
                            available_canaries.iter().find(|s| s.id == id).cloned()
                        {
                            // The cookie was set on a previous request.
                            return Some((server, None));
                        }
                    } else {
                        drop(entry);
                        self.canary_sessions.remove(cookie_val);
                    }
                }
            }
        }

        // 2. Check canary sticky-header pre-assignment.
        //    Any request carrying the configured header is routed to canary,
        //    and a sticky cookie is set so subsequent requests also land here.
        if ctx.canary_header.is_some() {
            if let Some(server) = available_canaries
                .iter()
                .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
                .cloned()
            {
                let set_cookie = if canary_cfg.sticky {
                    self.canary_sessions
                        .insert(server.id.clone(), (server.id.clone(), Instant::now()));
                    Some(self.build_canary_cookie(&server.id, canary_cfg))
                } else {
                    None
                };
                return Some((server, set_cookie));
            }
        }

        // 3. Probabilistic roll: each canary takes its own
        // `canary_weight_percent`% of new requests.
        let shares: Vec<(Arc<BackendServer>, u32)> = available_canaries
            .into_iter()
            .map(|s| {
                let percent = u32::from(s.canary_weight_percent.load(Ordering::Relaxed));
                (s, percent)
            })
            .collect();
        let total: u32 = shares.iter().map(|(_, percent)| percent).sum();
        if total == 0 {
            return None;
        }
        let range = total.max(100);
        let roll = cohort_roll(canary_cfg, ctx, &shares[0].0.id, range)
            .unwrap_or_else(|| rand::random_range(0..range));
        let server = canary_for_roll(&shares, roll)?.clone();

        let set_canary_cookie = if canary_cfg.sticky {
            self.canary_sessions
                .insert(server.id.clone(), (server.id.clone(), Instant::now()));
            Some(self.build_canary_cookie(&server.id, canary_cfg))
        } else {
            None
        };

        Some((server, set_canary_cookie))
    }

    /// Build a `Set-Cookie` header value for the canary sticky cookie.
    fn build_canary_cookie(&self, server_id: &str, cfg: &CanaryPoolConfig) -> String {
        format!(
            "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
            cfg.sticky_cookie_name, server_id, cfg.sticky_cookie_ttl_secs
        )
    }

    /// Check for existing sticky session.
    ///
    /// P2-fix: TTL eviction prevents cookie_sessions / ip_sessions / header_sessions
    /// from growing without bound.  Entries older than SESSION_TTL are treated as
    /// missing and removed inline so no separate eviction task is needed.
    ///
    /// P2-fix: Header affinity now uses a dedicated `header_sessions` map rather than
    /// sharing `cookie_sessions`, preventing cross-mode routing confusion.
    fn check_sticky_session(&self, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        match &self.affinity {
            AffinityMode::Cookie => {
                if let Some(ref cookie) = ctx.session_cookie {
                    if let Some(mut entry) = self.cookie_sessions.get_mut(cookie) {
                        if entry.1.elapsed() > SESSION_TTL {
                            drop(entry);
                            self.cookie_sessions.remove(cookie);
                            return None;
                        }
                        entry.1 = Instant::now(); // refresh TTL on access
                        let id = entry.0.clone();
                        drop(entry);
                        return self.find_server_by_id(&id);
                    }
                }
            }
            AffinityMode::IpHash => {
                if let Some(mut entry) = self.ip_sessions.get_mut(&ctx.client_ip) {
                    if entry.1.elapsed() > SESSION_TTL {
                        drop(entry);
                        self.ip_sessions.remove(&ctx.client_ip);
                        return None;
                    }
                    entry.1 = Instant::now();
                    let id = entry.0.clone();
                    drop(entry);
                    return self.find_server_by_id(&id);
                }
            }
            AffinityMode::Header => {
                if let Some(ref header_val) = ctx.affinity_header {
                    if let Some(mut entry) = self.header_sessions.get_mut(header_val) {
                        if entry.1.elapsed() > SESSION_TTL {
                            drop(entry);
                            self.header_sessions.remove(header_val);
                            return None;
                        }
                        entry.1 = Instant::now();
                        let id = entry.0.clone();
                        drop(entry);
                        return self.find_server_by_id(&id);
                    }
                }
            }
            AffinityMode::None => {}
        }
        None
    }

    /// Record sticky session mapping.
    fn record_sticky_session(&self, ctx: &SelectionContext, server: &BackendServer) {
        match &self.affinity {
            AffinityMode::Cookie => {
                if let Some(ref cookie) = ctx.session_cookie {
                    if session_admitted(&self.cookie_sessions, &self.session_ceilings[0], cookie) {
                        self.cookie_sessions
                            .insert(cookie.clone(), (server.id.clone(), Instant::now()));
                    }
                }
            }
            AffinityMode::IpHash => {
                if session_admitted(&self.ip_sessions, &self.session_ceilings[1], &ctx.client_ip) {
                    self.ip_sessions
                        .insert(ctx.client_ip, (server.id.clone(), Instant::now()));
                }
            }
            AffinityMode::Header => {
                if let Some(ref header_val) = ctx.affinity_header {
                    if session_admitted(
                        &self.header_sessions,
                        &self.session_ceilings[2],
                        header_val,
                    ) {
                        self.header_sessions
                            .insert(header_val.clone(), (server.id.clone(), Instant::now()));
                    }
                }
            }
            AffinityMode::None => {}
        }
    }

    /// The server a session is with, while it can still serve that session.
    fn find_server_by_id(&self, id: &str) -> Option<Arc<BackendServer>> {
        let servers = self.servers.read();
        servers
            .iter()
            .find(|s| s.id == id && (s.is_available() || s.keeps_sessions_while_draining()))
            .cloned()
    }

    /// Get healthy servers for normal (non-canary) routing.
    ///
    /// Canary servers (`is_canary = true`) are always excluded so normal load-
    /// balancing algorithms never accidentally pick them.  They are selected
    /// exclusively through the canary routing path in `select()`.
    pub fn get_healthy_servers(&self) -> Vec<Arc<BackendServer>> {
        let servers = self.servers.read();

        if !self.health_aware {
            // Still exclude canary servers even when health-checking is off,
            // and servers being drained or at `max_connections`.
            return servers
                .iter()
                .filter(|s| !s.is_canary() && s.draining.read().is_none() && s.has_capacity())
                .cloned()
                .collect();
        }

        // A server at `max_connections` takes no more, whichever algorithm
        // chooses: only first_available read the limit before.
        let takes =
            |s: &&Arc<BackendServer>| s.is_available() && !s.is_canary() && s.has_capacity();

        // First, try priority 1 healthy non-canary servers
        let priority_1: Vec<_> = servers
            .iter()
            .filter(|s| takes(s) && s.priority == 1)
            .cloned()
            .collect();

        if !priority_1.is_empty() {
            return priority_1;
        }

        // Failover to higher priority numbers (still excluding canary servers)
        servers.iter().filter(takes).cloned().collect()
    }

    /// Record a request that got no response from the server, or (`success`)
    /// one whose outcome has no status to read.
    pub fn record_completion(
        &self,
        server: &BackendServer,
        response_time: Duration,
        success: bool,
    ) {
        self.record_outcome(server, response_time, success, success);
    }

    /// Record a response from the server. The server answered, which is what
    /// its circuit breaker follows; whether the answer was an error is what a
    /// canary is rolled back on.
    pub fn record_response(&self, server: &BackendServer, response_time: Duration, status: u16) {
        let succeeded = self
            .canary_config
            .as_ref()
            .is_none_or(|canary| !canary.is_error_status(status));
        self.record_outcome(server, response_time, true, succeeded);
    }

    fn record_outcome(
        &self,
        server: &BackendServer,
        response_time: Duration,
        reachable: bool,
        succeeded: bool,
    ) {
        self.algorithm
            .record_completion(server, response_time, reachable);
        server.record_result(reachable, response_time);

        let Some(canary_cfg) = self.rollback_config() else {
            return;
        };
        if !server.is_canary() {
            self.stable_outcomes.lock().record(
                !succeeded,
                Duration::from_secs(canary_cfg.rollback_window_secs),
                Instant::now(),
            );
            return;
        }
        let stable_rate = self.stable_rate(canary_cfg);
        if server.record_canary_result(succeeded, canary_cfg, stable_rate) {
            self.warn_rolled_back(server, canary_cfg);
        }
    }

    /// Record a response whose body failed after its head was counted.
    pub fn record_body_failure(&self, server: &BackendServer) {
        let Some(canary_cfg) = self.rollback_config() else {
            return;
        };
        if !server.is_canary() {
            self.stable_outcomes.lock().record_late_error(
                Duration::from_secs(canary_cfg.rollback_window_secs),
                Instant::now(),
            );
            return;
        }
        let stable_rate = self.stable_rate(canary_cfg);
        if server.record_canary_late_error(canary_cfg, stable_rate) {
            self.warn_rolled_back(server, canary_cfg);
        }
    }

    fn rollback_config(&self) -> Option<&CanaryPoolConfig> {
        self.canary_config.as_ref().filter(|c| c.auto_rollback)
    }

    /// The stable servers' error rate, when it is to be compared and they have
    /// served enough requests to say.
    fn stable_rate(&self, canary_cfg: &CanaryPoolConfig) -> Option<f64> {
        if !canary_cfg.rollback_compare_stable {
            return None;
        }
        let totals = self.stable_outcomes.lock().totals(Instant::now());
        (totals.0 >= canary_cfg.rollback_min_requests).then(|| error_rate(totals))
    }

    fn warn_rolled_back(&self, server: &BackendServer, canary_cfg: &CanaryPoolConfig) {
        warn!(
            "Canary server {} in pool '{}' auto-suspended: error rate {:.1}% exceeded threshold {:.1}%",
            server.id,
            self.name,
            server.canary_error_rate() * 100.0,
            canary_cfg.rollback_error_rate * 100.0
        );
    }

    /// The single request header this pool's algorithm hashes on, if any.
    ///
    /// `None` for every algorithm except `header:<name>`, so the listeners pay
    /// nothing for this on the common path.
    pub fn hash_header_name(&self) -> Option<&str> {
        self.hash_header_name.as_deref()
    }

    /// Suspend a canary server by its ID.  Returns true if found and suspended.
    pub fn suspend_canary_server(&self, server_id: &str) -> bool {
        let servers = self.servers.read();
        if let Some(s) = servers.iter().find(|s| s.id == server_id && s.is_canary()) {
            s.suspend_canary();
            return true;
        }
        false
    }

    /// Resume a suspended canary server by its ID.  Returns true if found and resumed.
    pub fn resume_canary_server(&self, server_id: &str) -> bool {
        let servers = self.servers.read();
        if let Some(s) = servers.iter().find(|s| s.id == server_id && s.is_canary()) {
            s.resume_canary();
            return true;
        }
        false
    }

    /// Update `canary_weight_percent` for a canary server by its ID.
    /// Returns true if found and updated.
    pub fn set_canary_weight(&self, server_id: &str, percent: u8) -> bool {
        if percent > 100 {
            return false;
        }
        let servers = self.servers.read();
        for s in servers.iter() {
            if s.id == server_id && s.is_canary() {
                s.canary_weight_percent.store(percent, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// The member `server_id`, if the pool has it.
    pub fn member(&self, server_id: &str) -> Option<Arc<BackendServer>> {
        self.servers
            .read()
            .iter()
            .find(|s| s.id == server_id)
            .cloned()
    }

    /// How many members the pool has, those draining included.
    pub fn member_count(&self) -> usize {
        self.servers.read().len()
    }

    /// Make member `server_id` this pool's canary: at `weight`% of new
    /// requests, or, without a weight, through the pool's ramp
    /// (`canary.ramp_percent`) from its first step. Out of draining and
    /// suspension, its error window afresh. Returns the weight it starts at.
    pub fn start_canary(
        self: &Arc<Self>,
        server_id: &str,
        weight: Option<u8>,
    ) -> Result<u8, String> {
        let cfg = self
            .canary_config
            .as_ref()
            .filter(|c| c.enabled)
            .ok_or_else(|| format!("pool '{}' has no canary enabled", self.name))?;
        let server = self
            .member(server_id)
            .ok_or_else(|| format!("no server '{server_id}' in pool '{}'", self.name))?;
        let start = match weight {
            Some(w) if w > 100 => return Err(format!("weight {w} is more than 100")),
            Some(w) => w,
            None => *cfg.ramp_percent.first().ok_or_else(|| {
                format!(
                    "pool '{}' has no canary.ramp_percent: give a weight",
                    self.name
                )
            })?,
        };
        server.make_canary(start);
        let now = Instant::now();
        *self.rollout.lock() = weight.is_none().then(|| Rollout {
            server: server.id.clone(),
            step: 0,
            started: now,
            step_started: now,
            requests_at_step: server.total_requests.load(Ordering::Relaxed),
            outcome: RolloutOutcome::Ramping,
        });
        if weight.is_none() {
            Self::start_rollout_task(self);
        }
        Ok(start)
    }

    /// Promote canary `server_id`: it becomes a stable member, and the stable
    /// members it was compared with drain, being the version it replaces.
    /// False when it is not a canary of this pool.
    pub fn promote(&self, server_id: &str) -> bool {
        let Some(server) = self.member(server_id).filter(|s| s.is_canary()) else {
            return false;
        };
        server.make_stable();
        let drain_for = self.drain_for.unwrap_or_default();
        for other in self.servers.read().iter() {
            if !Arc::ptr_eq(other, &server) && !other.is_canary() {
                other.start_draining(drain_for);
            }
        }
        if let Some(rollout) = self.rollout.lock().as_mut() {
            if rollout.server == server.id {
                rollout.outcome = RolloutOutcome::Promoted;
            }
        }
        info!(
            "Canary {} in pool '{}' promoted: the members it replaces drain",
            server.id, self.name
        );
        true
    }

    /// Look at the rollout at `now` and move it on: a suspended canary ends
    /// it (rolled back); a step held for `ramp_step_secs` in which the canary
    /// answered `ramp_min_requests` goes to the next weight; the last step
    /// held promotes the canary (`auto_promote`) or waits for promotion.
    /// Whether the rollout is still stepping.
    fn advance_rollout(&self, now: Instant) -> bool {
        let Some(cfg) = self.canary_config.as_ref() else {
            return false;
        };
        let mut guard = self.rollout.lock();
        let Some(rollout) = guard
            .as_mut()
            .filter(|r| r.outcome == RolloutOutcome::Ramping)
        else {
            return false;
        };
        let Some(server) = self.member(&rollout.server).filter(|s| s.is_canary()) else {
            rollout.outcome = RolloutOutcome::Ended;
            return false;
        };
        if server.canary_suspended.load(Ordering::Relaxed) {
            rollout.outcome = RolloutOutcome::RolledBack;
            warn!(
                "Canary {} in pool '{}' rolled back at {}% after {:?}",
                server.id,
                self.name,
                server.canary_weight_percent.load(Ordering::Relaxed),
                now.saturating_duration_since(rollout.started)
            );
            return false;
        }
        let requests = server.total_requests.load(Ordering::Relaxed);
        let held = now.saturating_duration_since(rollout.step_started)
            >= Duration::from_secs(cfg.ramp_step_secs)
            && requests.saturating_sub(rollout.requests_at_step) >= cfg.ramp_min_requests;
        if !held {
            return true;
        }
        if let Some(next) = cfg.ramp_percent.get(rollout.step + 1) {
            rollout.step += 1;
            rollout.step_started = now;
            rollout.requests_at_step = requests;
            server.canary_weight_percent.store(*next, Ordering::Relaxed);
            info!(
                "Canary {} in pool '{}': step {} of {}, {}%",
                server.id,
                self.name,
                rollout.step + 1,
                cfg.ramp_percent.len(),
                next
            );
            return true;
        }
        if cfg.auto_promote {
            drop(guard);
            self.promote(&server.id);
        } else {
            rollout.outcome = RolloutOutcome::AwaitingPromotion;
            info!(
                "Canary {} in pool '{}' has held every step: promote it through the admin API",
                server.id, self.name
            );
        }
        false
    }

    /// Steps the rollout until it ends or the pool is replaced.
    fn start_rollout_task(pool: &Arc<Self>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let pool = Arc::downgrade(pool);
        runtime.spawn(async move {
            let mut ticker = tokio::time::interval(ROLLOUT_TICK);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let Some(pool) = pool.upgrade() else {
                    return;
                };
                if !pool.advance_rollout(Instant::now()) {
                    return;
                }
            }
        });
    }

    /// The rollout under way or last finished, for the admin API.
    pub fn rollout_status(&self) -> Option<RolloutStatus> {
        let cfg = self.canary_config.as_ref()?;
        let rollout = self.rollout.lock().clone()?;
        let server = self.member(&rollout.server);
        let now = Instant::now();
        Some(RolloutStatus {
            weight_percent: server
                .as_ref()
                .map_or(0, |s| s.canary_weight_percent.load(Ordering::Relaxed)),
            step_requests: server.as_ref().map_or(0, |s| {
                s.total_requests
                    .load(Ordering::Relaxed)
                    .saturating_sub(rollout.requests_at_step)
            }),
            server: rollout.server,
            outcome: rollout.outcome,
            step: rollout.step + 1,
            steps: cfg.ramp_percent.clone(),
            step_secs: cfg.ramp_step_secs,
            step_elapsed_secs: now
                .saturating_duration_since(rollout.step_started)
                .as_secs(),
            step_min_requests: cfg.ramp_min_requests,
            elapsed_secs: now.saturating_duration_since(rollout.started).as_secs(),
        })
    }

    /// Return a snapshot of canary server status for the admin API.
    pub fn canary_status(&self) -> Vec<CanaryServerStatus> {
        let servers = self.servers.read();
        servers
            .iter()
            .filter(|s| s.is_canary())
            .map(|s| {
                let (window_requests, window_errors) =
                    s.canary_window.lock().totals(Instant::now());
                CanaryServerStatus {
                    id: s.id.clone(),
                    canary_weight_percent: s.canary_weight_percent.load(Ordering::Relaxed),
                    suspended: s.canary_suspended.load(Ordering::Relaxed),
                    error_rate: s.canary_error_rate(),
                    window_requests,
                    window_errors,
                }
            })
            .collect()
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let servers = self.servers.read();
        let healthy = servers.iter().filter(|s| s.is_available()).count();
        let total_connections: u32 = servers
            .iter()
            .map(|s| s.active_connections.load(Ordering::Relaxed))
            .sum();
        let total_requests: u64 = servers
            .iter()
            .map(|s| s.total_requests.load(Ordering::Relaxed))
            .sum();

        PoolStats {
            name: self.name.clone(),
            algorithm: self.algorithm.name().to_string(),
            total_servers: servers.len(),
            healthy_servers: healthy,
            total_connections,
            total_requests,
            queued: self.queued(),
            queue_refused: self.queue_refused.load(Ordering::Relaxed),
            servers: servers
                .iter()
                .map(|s| {
                    let health = s.health.read();
                    ServerStats {
                        id: s.id.clone(),
                        healthy: health.healthy,
                        circuit_open: health.circuit_open,
                        draining: s.is_draining(),
                        canary: s.is_canary(),
                        slow_start_percent: s.ramp_factor().map(|f| (f * 100.0).round()),
                        active_connections: s.active_connections.load(Ordering::Relaxed),
                        max_connections: s.max_connections,
                        total_requests: s.total_requests.load(Ordering::Relaxed),
                        total_failures: s.total_failures.load(Ordering::Relaxed),
                        avg_response_time_us: s.avg_response_time_us.load(Ordering::Relaxed),
                    }
                })
                .collect(),
        }
    }

    /// Start a background health-check task for this pool.
    ///
    /// P2-fix: previously the pool only reacted to failures seen during real
    /// requests (`record_result`).  A backend could be completely unreachable
    /// yet still receive requests until one happened to land on it.  This task
    /// asks each server on the configured interval, with the probe the
    /// single backends use ([`crate::health::probe`]): a GET for the pool's
    /// `health_check_path` over the server's own transport, healthy on a 2xx,
    /// or, where the pool names no path, a TCP connect. It updates
    /// `BackendHealth::healthy` accordingly.
    ///
    /// # Arguments
    /// `pool` — the pool wrapped in `Arc` so the spawned task can hold a reference.
    ///
    /// The task holds the pool weakly and ends once the pool is dropped, which
    /// is what happens to a pool a reload replaces or removes. Nothing called
    /// this until 2026-10-09: `health_aware` pools were never checked.
    pub fn start_health_check_task(pool: &Arc<Self>) {
        if !pool.health_aware {
            return; // Health-check disabled for this pool
        }
        let interval = pool.health_check_interval;
        if interval.is_zero() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        // A reload that changes the path rebuilds the pool, so it is fixed here.
        let path = pool.health_check_path.clone();
        let pool = Arc::downgrade(pool);

        runtime.spawn(async move {
            // The first tick is at once: a member that is not running when
            // the pool is built (one half of a pair whose other half serves)
            // is known to be down before requests are sent to it, rather than
            // after an interval of them.
            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                let Some(pool) = pool.upgrade() else {
                    return; // replaced or removed by a reload
                };
                let servers: Vec<Arc<BackendServer>> = { pool.servers.read().clone() };
                drop(pool);

                for server in servers {
                    let addr = server.address;
                    let outcome = crate::health::probe(
                        &server.backend_config(),
                        path.as_deref(),
                        crate::health::probe_timeout(interval),
                    )
                    .await;
                    let reachable = outcome.is_up();

                    let mut health = server.health.write();
                    let was_healthy = health.healthy;

                    if reachable {
                        health.healthy = true;
                        health.last_check = Instant::now();
                        if !was_healthy {
                            info!(
                                "Health check: backend {} is now reachable — marking healthy",
                                addr
                            );
                            drop(health);
                            server.ramp_up();
                            continue;
                        }
                    } else {
                        if was_healthy {
                            warn!(
                                "Health check: backend {} is down ({}) — marking unhealthy",
                                addr,
                                outcome.describe()
                            );
                        }
                        health.healthy = false;
                        health.last_check = Instant::now();
                    }
                }
            }
        });
    }
}

/// Canary server status snapshot (used by admin API)
#[derive(Debug, Clone)]
pub struct CanaryServerStatus {
    pub id: String,
    pub canary_weight_percent: u8,
    pub suspended: bool,
    pub error_rate: f64,
    pub window_requests: u64,
    pub window_errors: u64,
}

/// Pool statistics (the admin API's `/pools`)
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolStats {
    pub name: String,
    pub algorithm: String,
    pub total_servers: usize,
    /// Servers taking new requests now
    pub healthy_servers: usize,
    pub total_connections: u32,
    pub total_requests: u64,
    /// Requests waiting for a place now
    pub queued: usize,
    /// Requests refused for want of a place
    pub queue_refused: u64,
    pub servers: Vec<ServerStats>,
}

/// One pool member's state
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerStats {
    pub id: String,
    pub healthy: bool,
    pub circuit_open: bool,
    pub draining: bool,
    pub canary: bool,
    /// Share of its weight it has now, while in slow start
    pub slow_start_percent: Option<f64>,
    pub active_connections: u32,
    pub max_connections: u32,
    pub total_requests: u64,
    pub total_failures: u64,
    pub avg_response_time_us: u64,
}

// ═══════════════════════════════════════════════════════════════
// Hashing for the hash-based algorithms
// ═══════════════════════════════════════════════════════════════

/// FNV-1a, 64-bit.
///
/// `DefaultHasher` is deterministic in the standard library as it stands, but it is
/// documented as making no stability guarantee across releases — and the entire
/// promise of a hash algorithm is that a given key keeps landing on the same
/// backend. A toolchain bump silently re-homing every session is not a risk worth
/// carrying for a hasher that fits in five lines.
fn fnv1a(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes
        .iter()
        .fold(OFFSET, |h, b| (h ^ u64::from(*b)).wrapping_mul(PRIME))
}

/// Final avalanche mix (the MurmurHash3 64-bit finalizer).
///
/// FNV-1a alone is not good enough here, and the rendezvous test caught it. The
/// last thing hashed is the server id, and ids in a pool differ only in their
/// final bytes — `127.0.0.1:9000` through `9004`. FNV-1a ends on
/// `(h ^ byte).wrapping_mul(PRIME)`, so two such ids differ by roughly
/// `small_delta * PRIME`, and since `PRIME` is about 2^40 that leaves the top
/// ~21 bits identical across every server in the pool. Those are exactly the bits
/// `rendezvous_score` leans on, so the ordering was decided by correlated low bits
/// and one backend took half the keyspace instead of a fifth.
///
/// This spreads every input bit across all 64 output bits, which is what the
/// construction assumes it is being handed.
const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x
}

/// Score one server for a key under weighted rendezvous hashing.
///
/// Maps the hash into `(0, 1)` and takes `-weight / ln(u)`. That is the standard
/// weighted-rendezvous construction: the maximum over servers is distributed in
/// proportion to weight, and the ordering for a given key is independent of which
/// other servers happen to be present.
fn rendezvous_score(key: &[u8], server: &BackendServer) -> f64 {
    let mut buf = Vec::with_capacity(key.len() + server.id.len() + 1);
    buf.extend_from_slice(key);
    buf.push(0xff); // domain separator, so ("ab","c") and ("a","bc") differ
    buf.extend_from_slice(server.id.as_bytes());

    // Never exactly 0 or 1, so the logarithm stays finite.
    #[expect(clippy::cast_precision_loss)]
    let u = (mix64(fnv1a(&buf)) as f64 + 0.5) / (u64::MAX as f64 + 1.0);
    let weight = f64::from(server.effective_weight().max(1));
    -weight / u.ln()
}

/// Pick a server for `key` by weighted rendezvous ("highest random weight") hashing.
///
/// The obvious way to write a hash algorithm is `hash(key) % healthy.len()`, and it
/// fails in the one case it exists for: when a backend goes unhealthy the modulus
/// changes and very nearly every key moves, so the affinity the algorithm promises
/// evaporates exactly when the pool is degraded and affinity matters most.
///
/// Rendezvous scores every server independently and takes the maximum, so losing a
/// server moves only the keys that were on it — the other `n - 1` servers keep
/// theirs. That is the property `ip_hash`, `uri_hash`, `url_param` and `header`
/// hashing are all bought for, and it costs an O(n) scan of a pool that is
/// realistically a handful of entries.
fn rendezvous_select(servers: &[Arc<BackendServer>], key: &[u8]) -> Option<Arc<BackendServer>> {
    servers
        .iter()
        .max_by(|a, b| {
            rendezvous_score(key, a)
                .partial_cmp(&rendezvous_score(key, b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// Extract one parameter's value from a raw query string.
///
/// Returns `None` when the parameter is absent, which the callers treat as "fall
/// back to round-robin" rather than hashing every such request onto one backend.
fn query_param<'a>(query: &'a str, name: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then_some(v)
    })
}

// ═══════════════════════════════════════════════════════════════
// Algorithm Implementations
// ═══════════════════════════════════════════════════════════════

/// Round-robin load balancing
pub struct RoundRobinAlgorithm;

impl LoadBalancingAlgorithm for RoundRobinAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        if healthy_servers.is_empty() {
            return None;
        }

        let idx =
            usize::try_from(pool.rr_counter.fetch_add(1, Ordering::Relaxed)).unwrap_or(usize::MAX);
        Some(healthy_servers[idx % healthy_servers.len()].clone())
    }

    fn name(&self) -> &'static str {
        "round_robin"
    }
}

/// Least connections load balancing (DEFAULT)
pub struct LeastConnectionsAlgorithm;

impl LoadBalancingAlgorithm for LeastConnectionsAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        healthy_servers
            .into_iter()
            .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
    }

    fn name(&self) -> &'static str {
        "least_connections"
    }
}

/// Weighted round-robin load balancing (nginx-style smooth)
pub struct WeightedRoundRobinAlgorithm;

impl LoadBalancingAlgorithm for WeightedRoundRobinAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        if healthy_servers.is_empty() {
            return None;
        }

        // Smooth weighted round-robin (nginx-style)
        let mut state = pool.wrr_state.write();

        // Initialize or resize weights
        if state.current_weights.len() != healthy_servers.len() {
            state.current_weights = healthy_servers.iter().map(|_| 0i64).collect();
        }

        let total_weight: i64 = healthy_servers
            .iter()
            .map(|s| s.effective_weight() as i64)
            .sum();

        // Find server with highest current weight
        let mut max_idx = 0;
        let mut max_weight = i64::MIN;

        for (i, server) in healthy_servers.iter().enumerate() {
            state.current_weights[i] += server.effective_weight() as i64;
            if state.current_weights[i] > max_weight {
                max_weight = state.current_weights[i];
                max_idx = i;
            }
        }

        // Reduce selected server's weight
        state.current_weights[max_idx] -= total_weight;

        Some(healthy_servers[max_idx].clone())
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "weighted_round_robin"
    }
}

/// Random load balancing
pub struct RandomAlgorithm;

impl LoadBalancingAlgorithm for RandomAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        if healthy_servers.is_empty() {
            return None;
        }

        let idx = rand::random_range(0..healthy_servers.len());
        Some(healthy_servers[idx].clone())
    }

    fn name(&self) -> &'static str {
        "random"
    }
}

/// IP hash load balancing (sticky by client IP)
pub struct IpHashAlgorithm;

impl LoadBalancingAlgorithm for IpHashAlgorithm {
    fn select(&self, pool: &BackendPool, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        if healthy_servers.is_empty() {
            return None;
        }

        // Rendezvous rather than `hash % len`: a backend going unhealthy must move
        // only the clients that were on it, not re-home the entire pool.
        rendezvous_select(&healthy_servers, ctx.client_ip.to_string().as_bytes())
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "ip_hash"
    }
}

/// Least response time load balancing
pub struct LeastResponseTimeAlgorithm;

impl LoadBalancingAlgorithm for LeastResponseTimeAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy_servers = pool.get_healthy_servers();

        // Select server with lowest (active_connections * response_time)
        healthy_servers.into_iter().min_by_key(|s| {
            let conns = s.active_connections.load(Ordering::Relaxed) as u64;
            let resp_time = s.avg_response_time_us.load(Ordering::Relaxed).max(1);
            conns.saturating_mul(resp_time)
        })
    }

    fn name(&self) -> &'static str {
        "least_response_time"
    }

    fn record_completion(&self, server: &BackendServer, response_time: Duration, _success: bool) {
        // Update EMA in server (already done in BackendServer::record_result)
        // This hook allows for algorithm-specific tracking if needed
        let _ = (server, response_time);
    }
}

/// URI hash — affinity by request path (HAProxy `uri`).
///
/// Sends every request for a given path to the same backend, which is what makes
/// a tier of caching backends useful: each one ends up owning a disjoint slice of
/// the URL space instead of all of them caching everything.
///
/// The query string is deliberately excluded. `?v=` cache-busters and analytics
/// parameters would otherwise scatter one resource across the whole pool, which is
/// the opposite of the point.
pub struct UriHashAlgorithm;

impl LoadBalancingAlgorithm for UriHashAlgorithm {
    fn select(&self, pool: &BackendPool, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy = pool.get_healthy_servers();
        if healthy.is_empty() {
            return None;
        }
        rendezvous_select(&healthy, ctx.path.as_bytes())
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "uri_hash"
    }
}

/// URL parameter hash — affinity by one query parameter (HAProxy `url_param`).
///
/// Configured as `url_param:<name>`. Used to pin a session to a backend when the
/// session identifier travels in the URL rather than a cookie.
///
/// A request that does not carry the parameter falls back to round-robin. Hashing
/// the empty string instead would pile every parameterless request — health checks,
/// crawlers, the front page — onto one backend.
pub struct UrlParamHashAlgorithm {
    param: String,
}

impl UrlParamHashAlgorithm {
    pub fn new(param: impl Into<String>) -> Self {
        Self {
            param: param.into(),
        }
    }
}

impl LoadBalancingAlgorithm for UrlParamHashAlgorithm {
    fn select(&self, pool: &BackendPool, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy = pool.get_healthy_servers();
        if healthy.is_empty() {
            return None;
        }

        match ctx
            .query
            .as_deref()
            .and_then(|q| query_param(q, &self.param))
        {
            Some(value) => rendezvous_select(&healthy, value.as_bytes()),
            None => {
                let idx = usize::try_from(pool.rr_counter.fetch_add(1, Ordering::Relaxed))
                    .unwrap_or(usize::MAX);
                Some(healthy[idx % healthy.len()].clone())
            }
        }
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "url_param_hash"
    }
}

/// Header hash — affinity by one request header (HAProxy `hdr(<name>)`).
///
/// Configured as `header:<name>`. The listener extracts the named header into
/// `SelectionContext::hash_header`, so a tenant identifier, an API key or a
/// device ID can pin traffic to a backend without a cookie.
///
/// As with `url_param`, a request missing the header falls back to round-robin
/// rather than collapsing onto a single server.
pub struct HeaderHashAlgorithm {
    header: String,
}

impl HeaderHashAlgorithm {
    pub fn new(header: impl Into<String>) -> Self {
        Self {
            header: header.into(),
        }
    }

    /// The header this instance needs the listener to extract.
    pub fn header_name(&self) -> &str {
        &self.header
    }
}

impl LoadBalancingAlgorithm for HeaderHashAlgorithm {
    fn select(&self, pool: &BackendPool, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy = pool.get_healthy_servers();
        if healthy.is_empty() {
            return None;
        }

        match ctx.hash_header.as_deref() {
            Some(value) if !value.is_empty() => rendezvous_select(&healthy, value.as_bytes()),
            _ => {
                let idx = usize::try_from(pool.rr_counter.fetch_add(1, Ordering::Relaxed))
                    .unwrap_or(usize::MAX);
                Some(healthy[idx % healthy.len()].clone())
            }
        }
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "header_hash"
    }
}

/// First available — fill servers in declared order (HAProxy `first`).
///
/// Saturates the first server up to its `max_connections` before touching the
/// second, and so on. The opposite of spreading load, and deliberately so: it is
/// how you keep spare capacity genuinely idle, so it can be powered down, scaled
/// in, or simply left cold as headroom.
///
/// A server with no connection limit would absorb everything and starve the rest,
/// so an unlimited server is treated as last in line rather than first.
pub struct FirstAvailableAlgorithm;

impl LoadBalancingAlgorithm for FirstAvailableAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy = pool.get_healthy_servers();
        if healthy.is_empty() {
            return None;
        }

        healthy
            .iter()
            .find(|s| {
                s.max_connections > 0
                    && s.active_connections.load(Ordering::Relaxed) < s.max_connections
            })
            .or_else(|| {
                // Everything with a limit is full, or nothing declares one: fall back
                // to the least loaded so the pool still serves rather than 503s.
                healthy
                    .iter()
                    .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
            })
            .cloned()
    }

    fn name(&self) -> &'static str {
        "first_available"
    }
}

/// Power of two choices — sample two at random, take the less loaded.
///
/// Envoy's default and NGINX's `random two least_conn`. It gets within a constant
/// factor of true least-connections while avoiding both of that algorithm's
/// problems: the O(n) scan on every request, and the herd effect where several
/// workers observe the same idle backend simultaneously and all pile onto it.
///
/// Weight is honoured by comparing load per unit of weight, so a server with twice
/// the weight is picked until it carries twice the connections.
pub struct PowerOfTwoChoicesAlgorithm;

impl LoadBalancingAlgorithm for PowerOfTwoChoicesAlgorithm {
    fn select(&self, pool: &BackendPool, _ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        let healthy = pool.get_healthy_servers();
        match healthy.len() {
            0 => return None,
            1 => return Some(healthy[0].clone()),
            _ => {}
        }

        let a = rand::random_range(0..healthy.len());
        // Draw the second from the remaining n-1 and shift, so the two are always
        // distinct without looping until they differ.
        let mut b = rand::random_range(0..healthy.len() - 1);
        if b >= a {
            b += 1;
        }

        let load = |s: &Arc<BackendServer>| {
            f64::from(s.active_connections.load(Ordering::Relaxed))
                / f64::from(s.effective_weight().max(1))
        };

        Some(if load(&healthy[a]) <= load(&healthy[b]) {
            healthy[a].clone()
        } else {
            healthy[b].clone()
        })
    }

    fn weighs_servers(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "power_of_two_choices"
    }
}

// ═══════════════════════════════════════════════════════════════
// Load Balancer Manager
// ═══════════════════════════════════════════════════════════════

/// Main load balancer manager
pub struct LoadBalancer {
    /// Backend pools by name
    pools: DashMap<String, Arc<BackendPool>>,
    /// Global configuration
    config: Arc<LoadBalancerConfig>,
    /// Session cookie settings
    pub cookie_config: SessionCookieConfig,
}

/// Session cookie configuration
#[derive(Clone, Debug)]
pub struct SessionCookieConfig {
    pub name: String,
    pub ttl: Duration,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: SameSite,
}

#[derive(Clone, Debug)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl LoadBalancer {
    /// Create new load balancer from configuration
    pub fn new(config: Arc<LoadBalancerConfig>) -> Self {
        let cookie_config = SessionCookieConfig {
            name: config.session_affinity.cookie_name.clone(),
            ttl: Duration::from_secs(config.session_affinity.cookie_ttl_secs),
            secure: config.session_affinity.cookie_secure,
            httponly: config.session_affinity.cookie_httponly,
            samesite: match config.session_affinity.cookie_samesite.as_str() {
                "strict" => SameSite::Strict,
                "none" => SameSite::None,
                _ => SameSite::Lax,
            },
        };

        Self {
            pools: DashMap::new(),
            cookie_config,
            config,
        }
    }

    /// Add a backend pool from configuration
    pub fn add_pool(&self, pool_config: &BackendPoolConfig) {
        let pool = Arc::new(BackendPool::from_config(pool_config, &self.config));
        BackendPool::start_health_check_task(&pool);
        self.pools.insert(pool_config.name.clone(), pool);
    }

    /// Bring the pools in line with `[backend_pools]` after a config reload.
    ///
    /// New pools are added and pools no longer configured are dropped. A pool
    /// whose settings changed is rebuilt, but every server it still lists with
    /// unchanged settings keeps its live object -- health, open connections,
    /// counters, slow-start and canary state -- rather than starting over.
    /// Pools were added once at startup and a reload changed none of them.
    pub fn reconcile_pools<S: std::hash::BuildHasher>(
        &self,
        configured: &std::collections::HashMap<String, BackendPoolConfig, S>,
    ) {
        self.pools.retain(|name, _| {
            let keep = configured.values().any(|c| &c.name == name);
            if !keep {
                info!("Backend pool '{}' removed by the reloaded config", name);
            }
            keep
        });
        for pool_config in configured.values() {
            let current = self.get_pool(&pool_config.name);
            if current
                .as_ref()
                .is_some_and(|p| crate::config::same_settings(&p.source, pool_config))
            {
                continue;
            }
            let rebuilt = Arc::new(BackendPool::from_config(pool_config, &self.config));
            if let Some(old) = current {
                let old_servers = old.servers.read().clone();
                let settings_for = |pool: &BackendPoolConfig, addr: SocketAddr| {
                    pool.servers
                        .iter()
                        .find(|c| c.address.parse::<SocketAddr>().ok() == Some(addr))
                        .cloned()
                };
                for slot in rebuilt.servers.write().iter_mut() {
                    let unchanged = match (
                        settings_for(&old.source, slot.address),
                        settings_for(pool_config, slot.address),
                    ) {
                        (Some(was), Some(now)) => crate::config::same_settings(&was, &now),
                        _ => false,
                    };
                    if unchanged {
                        if let Some(live) = old_servers.iter().find(|s| s.address == slot.address) {
                            *slot = live.clone();
                        }
                    }
                    // The rebuilt pool's queue and slow start, kept or new
                    slot.join(&rebuilt.freed, rebuilt.ramp);
                    // A server new to the pool starts slowly
                    if !old_servers.iter().any(|s| s.address == slot.address) {
                        slot.ramp_up();
                    }
                }
                // A server the reload removed drains: it takes no new session,
                // keeps the ones it has until the draining time is up, then
                // leaves the pool.
                if let Some(drain_for) = rebuilt.drain_for {
                    let removed: Vec<Arc<BackendServer>> = old_servers
                        .iter()
                        .filter(|old| {
                            !rebuilt
                                .servers
                                .read()
                                .iter()
                                .any(|s| s.address == old.address)
                        })
                        .cloned()
                        .collect();
                    for server in &removed {
                        server.start_draining(drain_for);
                        server.join(&rebuilt.freed, rebuilt.ramp);
                    }
                    if !removed.is_empty() {
                        rebuilt.servers.write().extend(removed.iter().cloned());
                        let pool = Arc::downgrade(&rebuilt);
                        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                            runtime.spawn(async move {
                                tokio::time::sleep(drain_for).await;
                                if let Some(pool) = pool.upgrade() {
                                    pool.servers.write().retain(|s| {
                                        !removed.iter().any(|gone| Arc::ptr_eq(s, gone))
                                    });
                                    info!(
                                        "Backend pool '{}': {} drained server(s) removed",
                                        pool.name,
                                        removed.len()
                                    );
                                }
                            });
                        }
                    }
                }
                // A rollout goes on in the rebuilt pool while its canary is
                // still there, the live object kept.
                let carried = old.rollout.lock().clone().filter(|r| {
                    rebuilt
                        .member(&r.server)
                        .is_some_and(|s| old.member(&r.server).is_some_and(|o| Arc::ptr_eq(&s, &o)))
                });
                let ramping = carried
                    .as_ref()
                    .is_some_and(|r| r.outcome == RolloutOutcome::Ramping);
                *rebuilt.rollout.lock() = carried;
                if ramping {
                    BackendPool::start_rollout_task(&rebuilt);
                }
                info!(
                    "Backend pool '{}' rebuilt from the reloaded config",
                    pool_config.name
                );
            } else {
                info!(
                    "Backend pool '{}' added by the reloaded config",
                    pool_config.name
                );
            }
            BackendPool::start_health_check_task(&rebuilt);
            self.pools.insert(pool_config.name.clone(), rebuilt);
        }
    }

    /// Get pool by name
    pub fn get_pool(&self, name: &str) -> Option<Arc<BackendPool>> {
        self.pools.get(name).map(|p| p.clone())
    }

    /// Iterate over all pool names and their Arc references.
    pub fn all_pools(&self) -> Vec<(String, Arc<BackendPool>)> {
        self.pools
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect()
    }

    /// Record request completion
    pub fn record_completion(
        &self,
        pool_name: &str,
        server: &BackendServer,
        response_time: Duration,
        success: bool,
    ) {
        if let Some(pool) = self.pools.get(pool_name) {
            pool.record_completion(server, response_time, success);
        }
    }

    /// Record a response from a pool's server, by its status
    pub fn record_response(
        &self,
        pool_name: &str,
        server: &BackendServer,
        response_time: Duration,
        status: u16,
    ) {
        if let Some(pool) = self.pools.get(pool_name) {
            pool.record_response(server, response_time, status);
        }
    }

    /// Record a response whose body failed after its head was counted
    pub fn record_body_failure(&self, pool_name: &str, server: &BackendServer) {
        if let Some(pool) = self.pools.get(pool_name) {
            pool.record_body_failure(server);
        }
    }

    /// Get all pool statistics
    pub fn all_stats(&self) -> Vec<PoolStats> {
        self.pools.iter().map(|p| p.stats()).collect()
    }

    /// The server `server_id` of pool `pool_name`, if both exist.
    fn server(&self, pool_name: &str, server_id: &str) -> Option<Arc<BackendServer>> {
        let pool = self.pools.get(pool_name)?;
        let servers = pool.servers.read();
        servers.iter().find(|s| s.id == server_id).cloned()
    }

    /// Make `server_id` the canary of `pool_name` (see
    /// [`BackendPool::start_canary`]).
    pub fn start_canary(
        &self,
        pool_name: &str,
        server_id: &str,
        weight: Option<u8>,
    ) -> Result<u8, String> {
        let pool = self
            .get_pool(pool_name)
            .ok_or_else(|| format!("no pool '{pool_name}'"))?;
        pool.start_canary(server_id, weight)
    }

    /// Promote canary `server_id` of `pool_name` (see [`BackendPool::promote`]).
    pub fn promote(&self, pool_name: &str, server_id: &str) -> bool {
        self.get_pool(pool_name)
            .is_some_and(|pool| pool.promote(server_id))
    }

    /// Drain a server: no new sessions, the ones it has kept for
    /// `connection_draining.timeout_secs`. False when there is no such server.
    pub fn drain_server(&self, pool_name: &str, server_id: &str) -> bool {
        self.server(pool_name, server_id).is_some_and(|server| {
            server.start_draining(Duration::from_secs(
                self.config.connection_draining.timeout_secs,
            ));
            true
        })
    }

    /// Take a server out of draining. False when there is no such server.
    pub fn undrain_server(&self, pool_name: &str, server_id: &str) -> bool {
        self.server(pool_name, server_id).is_some_and(|server| {
            server.stop_draining();
            true
        })
    }

    /// Take a server out of rotation by hand until it is marked healthy or
    /// its health check finds it again. False when there is no such server.
    pub fn mark_unhealthy(&self, pool_name: &str, server_id: &str) -> bool {
        self.server(pool_name, server_id).is_some_and(|server| {
            server.health.write().healthy = false;
            warn!(
                "Backend {} in pool {} marked unhealthy",
                server_id, pool_name
            );
            true
        })
    }

    /// Put a server back in rotation by hand: healthy, its breaker closed,
    /// and in slow start where the pool has it. False when there is no such
    /// server.
    pub fn mark_healthy(&self, pool_name: &str, server_id: &str) -> bool {
        self.server(pool_name, server_id).is_some_and(|server| {
            {
                let mut health = server.health.write();
                health.healthy = true;
                health.circuit_open = false;
                health.opened_at = None;
                health.consecutive_failures = 0;
            }
            server.ramp_up();
            info!("Backend {} in pool {} marked healthy", server_id, pool_name);
            true
        })
    }

    /// Check if load balancer is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get default algorithm name
    pub fn default_algorithm(&self) -> &str {
        &self.config.default_algorithm
    }
}

// ═══════════════════════════════════════════════════════════════
// Cookie Helpers
// ═══════════════════════════════════════════════════════════════

impl SessionCookieConfig {
    /// Generate Set-Cookie header value
    pub fn generate_cookie(&self, server_id: &str) -> String {
        let mut cookie = format!("{}={}", self.name, server_id);

        if self.ttl.as_secs() > 0 {
            cookie.push_str(&format!("; Max-Age={}", self.ttl.as_secs()));
        }

        cookie.push_str("; Path=/");

        if self.secure {
            cookie.push_str("; Secure");
        }

        if self.httponly {
            cookie.push_str("; HttpOnly");
        }

        match self.samesite {
            SameSite::Strict => cookie.push_str("; SameSite=Strict"),
            SameSite::Lax => cookie.push_str("; SameSite=Lax"),
            SameSite::None => cookie.push_str("; SameSite=None"),
        }

        cookie
    }
}

/// Extract session cookie from cookie header
pub fn extract_session_cookie(
    cookie_header: Option<&str>,
    config: &SessionCookieConfig,
) -> Option<String> {
    extract_cookie_by_name(cookie_header, &config.name)
}

/// Extract any named cookie value from a raw `Cookie:` header.
///
/// Looks for `<name>=<value>` (case-sensitive) in the semicolon-separated list.
pub fn extract_cookie_by_name(cookie_header: Option<&str>, name: &str) -> Option<String> {
    let header = cookie_header?;

    for cookie in header.split(';') {
        let cookie = cookie.trim();
        // Match "<name>=" prefix exactly.
        if let Some(rest) = cookie.strip_prefix(name) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    /// The README and docs/CONFIG.md name every algorithm this build accepts,
    /// and every count of them in the README is its count: both said six while
    /// eleven were implemented (2026-11-02)
    #[test]
    fn the_docs_name_every_algorithm_and_count_them() {
        let readme = include_str!("../README.md");
        let config = include_str!("../docs/CONFIG.md");
        for algorithm in BackendPool::ALGORITHMS {
            let name = algorithm.split(':').next().unwrap();
            assert!(
                readme.contains(&format!("`{name}")),
                "README.md does not name {algorithm}"
            );
            assert!(
                config.contains(&format!("`{name}")),
                "docs/CONFIG.md does not name {algorithm}"
            );
        }
        let n = BackendPool::ALGORITHMS.len();
        let mut counted = 0;
        for line in readme.lines().filter(|l| l.contains("Load Balancing")) {
            let words: Vec<&str> = line
                .split(|c: char| !c.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .collect();
            for (k, w) in words.iter().enumerate() {
                if w.eq_ignore_ascii_case("algorithms") {
                    if let Some(stated) = words[k.saturating_sub(3)..k]
                        .iter()
                        .find_map(|w| w.parse::<usize>().ok())
                    {
                        assert_eq!(stated, n, "README.md says {stated} algorithms: {line}");
                        counted += 1;
                    }
                }
            }
        }
        assert!(counted > 0, "README.md states no count of the algorithms");
    }

    use super::*;

    /// A full session table admits no new key until a sweep frees room, and
    /// a key already held is always admitted.
    #[test]
    fn a_full_session_table_admits_no_new_key() {
        let sessions: DashMap<String, (String, Instant)> = DashMap::new();
        let ceiling = crate::bounded::Ceiling::new(2, Duration::from_millis(1));
        for k in ["a", "b"] {
            assert!(session_admitted(&sessions, &ceiling, &k.to_string()));
            sessions.insert(k.to_string(), ("s1".into(), Instant::now()));
        }
        assert!(!session_admitted(&sessions, &ceiling, &"c".to_string()));
        assert!(session_admitted(&sessions, &ceiling, &"a".to_string()));
        // One session past the TTL: the next sweep frees its place
        if let Some(stale) = Instant::now().checked_sub(SESSION_TTL + Duration::from_secs(1)) {
            sessions.insert("b".into(), ("s1".into(), stale));
            std::thread::sleep(Duration::from_millis(5));
            assert!(session_admitted(&sessions, &ceiling, &"c".to_string()));
            assert!(!sessions.contains_key("b"));
        }
    }

    fn pool_config(toml_src: &str) -> BackendPoolConfig {
        toml::from_str(toml_src).unwrap()
    }

    /// A reload adds, rebuilds and drops pools, and a server whose settings did
    /// not change keeps its live state through the rebuild.
    #[tokio::test]
    async fn a_reload_reconciles_pools_and_keeps_unchanged_servers_live() {
        let lb = LoadBalancer::new(Arc::new(LoadBalancerConfig::default()));
        let mut configured = std::collections::HashMap::new();
        configured.insert(
            "api".to_string(),
            pool_config(
                r#"
                name = "api"
                [[servers]]
                address = "127.0.0.1:9001"
                [[servers]]
                address = "127.0.0.1:9002"
                "#,
            ),
        );
        lb.reconcile_pools(&configured);
        let first = lb.get_pool("api").expect("added");
        let kept = first.servers.read()[0].clone();
        kept.health.write().healthy = false;

        // One server's weight changes, a third server joins, another pool appears.
        configured.insert(
            "api".to_string(),
            pool_config(
                r#"
                name = "api"
                [[servers]]
                address = "127.0.0.1:9001"
                [[servers]]
                address = "127.0.0.1:9002"
                weight = 7
                [[servers]]
                address = "127.0.0.1:9003"
                "#,
            ),
        );
        configured.insert(
            "web".to_string(),
            pool_config("name = \"web\"\n[[servers]]\naddress = \"127.0.0.1:9100\"\n"),
        );
        lb.reconcile_pools(&configured);
        let rebuilt = lb.get_pool("api").unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt), "a changed pool is rebuilt");
        let servers = rebuilt.servers.read().clone();
        assert_eq!(servers.len(), 3);
        assert!(
            Arc::ptr_eq(&servers[0], &kept),
            "an unchanged server keeps its live object"
        );
        assert!(!servers[0].health.read().healthy, "and with it its health");
        assert_eq!(
            servers[1].weight, 7,
            "a changed server takes its new settings"
        );
        assert!(lb.get_pool("web").is_some(), "a new pool is added");

        // Unchanged settings: the pool itself is kept.
        lb.reconcile_pools(&configured);
        assert!(Arc::ptr_eq(&rebuilt, &lb.get_pool("api").unwrap()));

        configured.remove("web");
        lb.reconcile_pools(&configured);
        assert!(
            lb.get_pool("web").is_none(),
            "a pool no longer configured is dropped"
        );
    }

    fn create_test_server(address: &str, weight: u32) -> Arc<BackendServer> {
        create_test_server_full(address, weight, false, 0)
    }

    fn create_test_server_full(
        address: &str,
        weight: u32,
        canary: bool,
        canary_pct: u8,
    ) -> Arc<BackendServer> {
        let config = PoolServerConfig {
            address: address.to_string(),
            weight,
            priority: 1,
            max_connections: 100,
            timeout_ms: 30000,
            tls_mode: TlsMode::Terminate,
            tls_cert: None,
            tls_skip_verify: false,
            tls_sni: None,
            cb_failure_threshold: None,
            cb_half_open_delay_secs: None,
            cb_success_threshold: None,
            canary,
            canary_weight_percent: canary_pct,
            disable_pooling: false,
            retries: None,
            retry_backoff_ms: None,
            retry_on: None,
        };
        Arc::new(BackendServer::from_config(&config).expect("test address must be valid"))
    }

    fn make_pool_config(
        algorithm: &str,
        servers: Vec<PoolServerConfig>,
        canary: Option<CanaryPoolConfig>,
    ) -> BackendPoolConfig {
        BackendPoolConfig {
            name: "test-pool".to_string(),
            algorithm: algorithm.to_string(),
            health_aware: false,
            affinity: AffinityMode::None,
            affinity_header: None,
            queue_max_size: None,
            queue_timeout_ms: None,
            health_check_path: None,
            health_check_interval_secs: 10,
            servers,
            canary,
        }
    }

    /// Every algorithm honours `max_connections`; a request that finds every
    /// server full waits in the queue and takes the first place given back.
    #[tokio::test]
    async fn a_full_pool_queues_and_a_freed_place_is_taken() {
        let config = pool_config(
            r#"
            name = "q"
            algorithm = "least_connections"
            queue_max_size = 4
            queue_timeout_ms = 2000
            [[servers]]
            address = "127.0.0.1:9101"
            max_connections = 1
            "#,
        );
        let mut lb_config = LoadBalancerConfig::default();
        lb_config.queue.enabled = true;
        let pool = Arc::new(BackendPool::from_config(&config, &lb_config));
        let held = pool.select(&default_ctx()).unwrap();
        assert!(
            pool.select(&default_ctx()).is_none(),
            "full: least_connections skips it"
        );

        let waiting = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move {
                pool.select_queued(&default_ctx())
                    .await
                    .map(|r| r.server.id.clone())
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(pool.queued(), 1);
        drop(held);
        assert_eq!(waiting.await.unwrap().as_deref(), Some("127.0.0.1:9101"));
        assert_eq!(pool.queued(), 0);
    }

    /// A tripped breaker lets one trial through after its delay; enough
    /// successes close it, and the server ramps back up.
    #[test]
    fn a_tripped_server_comes_back_through_half_open_trials() {
        let config = pool_config(
            r#"
            name = "cb"
            [[servers]]
            address = "127.0.0.1:9102"
            cb_failure_threshold = 2
            cb_success_threshold = 2
            cb_half_open_delay_secs = 0
            "#,
        );
        let mut lb_config = LoadBalancerConfig::default();
        lb_config.slow_start.enabled = true;
        let pool = BackendPool::from_config(&config, &lb_config);
        let server = pool.servers.read()[0].clone();
        server.record_result(false, Duration::from_millis(1));
        server.record_result(false, Duration::from_millis(1));
        assert!(server.health.read().circuit_open);
        // Past the delay (0 s here): one trial at a time
        assert!(server.is_available());
        let trial = server.try_acquire_slot(true).unwrap();
        assert!(!server.is_available(), "one trial at a time");
        drop(trial);
        server.record_result(true, Duration::from_millis(1));
        server.record_result(true, Duration::from_millis(1));
        assert!(!server.health.read().circuit_open);
        assert!(server.ramp_factor().is_some(), "it ramps back up");
    }

    fn default_ctx() -> SelectionContext {
        SelectionContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            session_cookie: None,
            affinity_header: None,
            path: "/".to_string(),
            host: "localhost".to_string(),
            canary_cookie: None,
            canary_header: None,
            query: None,
            cohort_header: None,
            hash_header: None,
        }
    }

    /// Build a pool of `n` servers, all healthy, for the hash tests.
    /// A server that answers every request with `status`.
    async fn server_answering(status: &'static str) -> SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut head = [0u8; 2048];
                    let _ = stream.read(&mut head).await;
                    let answer = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                    );
                    let _ = stream.write_all(answer.as_bytes()).await;
                });
            }
        });
        addr
    }

    /// A health-aware pool asks each server its `health_check_path`: the one
    /// answering 503 is taken out of rotation, the one answering 200 stays,
    /// though both accept connections.
    #[tokio::test]
    async fn pool_health_checks_ask_the_path() {
        let ok = server_answering("200 OK").await;
        let failing = server_answering("503 Service Unavailable").await;
        let config: BackendPoolConfig = toml::from_str(&format!(
            r#"
            name = "h"
            health_aware = true
            health_check_path = "/health"
            health_check_interval_secs = 1
            [[servers]]
            address = "{ok}"
            [[servers]]
            address = "{failing}"
            "#
        ))
        .unwrap();
        let pool = Arc::new(BackendPool::from_config(
            &config,
            &LoadBalancerConfig::default(),
        ));
        BackendPool::start_health_check_task(&pool);
        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.get_healthy_servers().len() != 1 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let healthy = pool.get_healthy_servers();
        assert_eq!(healthy.len(), 1, "the 503 server is out, the 200 one stays");
        assert_eq!(healthy[0].address, ok);
    }

    fn hash_pool(algorithm: &str, n: usize) -> BackendPool {
        let servers: Vec<PoolServerConfig> = (0..n)
            .map(|i| PoolServerConfig {
                address: format!("127.0.0.1:{}", 9000 + i),
                weight: 100,
                priority: 1,
                max_connections: 100,
                timeout_ms: 30000,
                tls_mode: TlsMode::Terminate,
                tls_cert: None,
                tls_skip_verify: false,
                tls_sni: None,
                cb_failure_threshold: None,
                cb_half_open_delay_secs: None,
                cb_success_threshold: None,
                canary: false,
                canary_weight_percent: 0,
                disable_pooling: false,
                retries: None,
                retry_backoff_ms: None,
                retry_on: None,
            })
            .collect();
        let cfg = make_pool_config(algorithm, servers, None);
        BackendPool::from_config(&cfg, &LoadBalancerConfig::default())
    }

    #[test]
    fn uri_hash_is_stable_for_the_same_path() {
        let pool = hash_pool("uri_hash", 5);
        let mut ctx = default_ctx();
        ctx.path = "/assets/app.js".to_string();

        let first = pool.select(&ctx).unwrap().server.id.clone();
        for _ in 0..50 {
            assert_eq!(pool.select(&ctx).unwrap().server.id, first);
        }
    }

    #[test]
    fn uri_hash_spreads_distinct_paths() {
        let pool = hash_pool("uri_hash", 5);
        let mut seen = std::collections::HashSet::new();
        for i in 0..200 {
            let mut ctx = default_ctx();
            ctx.path = format!("/page/{i}");
            seen.insert(pool.select(&ctx).unwrap().server.id.clone());
        }
        assert_eq!(
            seen.len(),
            5,
            "every backend should own part of the URL space"
        );
    }

    #[test]
    fn url_param_hash_pins_by_parameter_and_ignores_the_rest() {
        let pool = hash_pool("url_param:sid", 4);

        let mut a = default_ctx();
        a.query = Some("page=1&sid=abc123&t=99".to_string());
        let mut b = default_ctx();
        b.query = Some("sid=abc123".to_string());

        assert_eq!(
            pool.select(&a).unwrap().server.id,
            pool.select(&b).unwrap().server.id,
            "same sid must pin to the same backend regardless of other parameters"
        );
    }

    #[test]
    fn url_param_hash_without_the_parameter_does_not_collapse_onto_one_backend() {
        let pool = hash_pool("url_param:sid", 4);
        let ctx = default_ctx(); // no query at all
        let mut seen = std::collections::HashSet::new();
        for _ in 0..40 {
            seen.insert(pool.select(&ctx).unwrap().server.id.clone());
        }
        assert_eq!(
            seen.len(),
            4,
            "requests without the parameter must round-robin, not pile onto one server"
        );
    }

    #[test]
    fn header_hash_pins_by_header_value() {
        let pool = hash_pool("header:X-Tenant", 4);
        assert_eq!(pool.hash_header_name(), Some("X-Tenant"));

        let mut ctx = default_ctx();
        ctx.hash_header = Some("tenant-42".to_string());
        let first = pool.select(&ctx).unwrap().server.id.clone();
        for _ in 0..25 {
            assert_eq!(pool.select(&ctx).unwrap().server.id, first);
        }
    }

    #[test]
    fn first_available_fills_in_order_then_moves_on() {
        let pool = hash_pool("first_available", 3);
        let servers = pool.servers.read().clone();

        // Nothing loaded: the first server takes it.
        let first_id = servers[0].id.clone();
        assert_eq!(pool.select(&default_ctx()).unwrap().server.id, first_id);

        // Saturate it; selection must move to the second, not spread.
        servers[0]
            .active_connections
            .store(servers[0].max_connections, Ordering::Relaxed);
        assert_eq!(
            pool.select(&default_ctx()).unwrap().server.id,
            servers[1].id
        );
    }

    #[test]
    fn power_of_two_choices_never_returns_the_most_loaded_of_a_pair() {
        // With two servers the sample is the whole pool, so the lighter one must
        // win every single time — this is the property, not a tendency.
        let pool = hash_pool("power_of_two_choices", 2);
        let servers = pool.servers.read().clone();
        servers[0].active_connections.store(50, Ordering::Relaxed);
        servers[1].active_connections.store(1, Ordering::Relaxed);

        for _ in 0..100 {
            assert_eq!(
                pool.select(&default_ctx()).unwrap().server.id,
                servers[1].id
            );
        }
    }

    #[test]
    fn rendezvous_moves_only_the_departed_servers_keys() {
        // The property modulo hashing does not have, and the reason these
        // algorithms use rendezvous: losing one backend of five must re-home
        // roughly a fifth of the keyspace, not nearly all of it.
        let five = hash_pool("uri_hash", 5);
        let all = five.servers.read().clone();

        let keys: Vec<String> = (0..2000).map(|i| format!("/k/{i}")).collect();
        let before: Vec<String> = keys
            .iter()
            .map(|k| {
                let mut c = default_ctx();
                c.path = k.clone();
                five.select(&c).unwrap().server.id.clone()
            })
            .collect();

        // Drop the last server and re-run the same keys against the survivors.
        let survivors: Vec<Arc<BackendServer>> = all[..4].to_vec();
        let departed = &all[4].id;

        let mut moved = 0usize;
        let mut moved_off_survivor = 0usize;
        for (k, was) in keys.iter().zip(&before) {
            let now = rendezvous_select(&survivors, k.as_bytes())
                .unwrap()
                .id
                .clone();
            if now != *was {
                moved += 1;
                if was != departed {
                    moved_off_survivor += 1;
                }
            }
        }

        assert_eq!(
            moved_off_survivor, 0,
            "a key on a surviving backend must not move; {moved_off_survivor} did"
        );
        assert!(
            moved < keys.len() / 3,
            "only the departed server's share should move, got {moved} of {}",
            keys.len()
        );
    }

    #[test]
    fn unknown_algorithm_names_are_rejected_not_silently_defaulted() {
        assert!(BackendPool::is_known_algorithm("least_connections"));
        assert!(BackendPool::is_known_algorithm("power_of_two_choices"));
        assert!(BackendPool::is_known_algorithm("url_param:sid"));
        assert!(BackendPool::is_known_algorithm("header:X-Tenant"));

        // HAProxy muscle memory, a stray space, and a parameterised form with no
        // parameter — each would previously have become least_connections in silence.
        assert!(!BackendPool::is_known_algorithm("leastconn"));
        assert!(!BackendPool::is_known_algorithm("ip_hash "));
        assert!(!BackendPool::is_known_algorithm("url_param:"));
        assert!(!BackendPool::is_known_algorithm("header:"));
    }

    #[test]
    fn test_least_connections_selection() {
        let server1 = create_test_server("127.0.0.1:8001", 100);
        let server2 = create_test_server("127.0.0.1:8002", 100);

        // server1 has more connections
        server1.active_connections.store(10, Ordering::Relaxed);
        server2.active_connections.store(5, Ordering::Relaxed);

        let servers = [server1, server2.clone()];

        // Least connections should pick server2
        let selected = servers
            .iter()
            .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
            .cloned();

        assert_eq!(selected.unwrap().id, server2.id);
    }

    #[test]
    fn test_effective_weight_with_slow_start() {
        let server = create_test_server("127.0.0.1:8001", 100);

        // Initial weight should be base weight
        assert_eq!(server.effective_weight(), 100);

        // Start slow start with 10% initial weight
        server.start_slow_start(Duration::from_secs(30), 10);

        // Weight should be reduced initially
        let weight = server.effective_weight();
        assert!(weight < 100);
        assert!(weight >= 10);
    }

    #[test]
    fn test_session_cookie_generation() {
        let config = SessionCookieConfig {
            name: "PQCPROXY_BACKEND".to_string(),
            ttl: Duration::from_hours(1),
            secure: true,
            httponly: true,
            samesite: SameSite::Lax,
        };

        let cookie = config.generate_cookie("127.0.0.1:8001");

        assert!(cookie.contains("PQCPROXY_BACKEND=127.0.0.1:8001"));
        assert!(cookie.contains("Max-Age=3600"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn test_extract_session_cookie() {
        let config = SessionCookieConfig {
            name: "PQCPROXY_BACKEND".to_string(),
            ttl: Duration::from_hours(1),
            secure: true,
            httponly: true,
            samesite: SameSite::Lax,
        };

        let cookie_header = "other=value; PQCPROXY_BACKEND=127.0.0.1:8001; another=test";
        let extracted = extract_session_cookie(Some(cookie_header), &config);

        assert_eq!(extracted, Some("127.0.0.1:8001".to_string()));
    }

    #[test]
    fn test_backend_health_tracking() {
        let server = create_test_server("127.0.0.1:8001", 100);

        assert!(server.is_available());

        // Simulate 5 failures - should open circuit breaker
        for _ in 0..5 {
            server.record_result(false, Duration::from_millis(100));
        }

        assert!(!server.is_available());

        // Simulate 3 successes - should close circuit breaker
        for _ in 0..3 {
            server.record_result(true, Duration::from_millis(50));
        }

        assert!(server.is_available());
    }

    // ── Canary tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_canary_probabilistic_routing() {
        // Pool: one stable server + one 50% canary server.
        let stable_cfg = PoolServerConfig {
            address: "127.0.0.1:9001".to_string(),
            weight: 100,
            priority: 1,
            max_connections: 100,
            timeout_ms: 30000,
            tls_mode: TlsMode::Terminate,
            tls_cert: None,
            tls_skip_verify: false,
            tls_sni: None,
            cb_failure_threshold: None,
            cb_half_open_delay_secs: None,
            cb_success_threshold: None,
            canary: false,
            canary_weight_percent: 0,
            disable_pooling: false,
            retries: None,
            retry_backoff_ms: None,
            retry_on: None,
        };
        let canary_cfg = PoolServerConfig {
            address: "127.0.0.1:9002".to_string(),
            weight: 100,
            priority: 1,
            max_connections: 100,
            timeout_ms: 30000,
            tls_mode: TlsMode::Terminate,
            tls_cert: None,
            tls_skip_verify: false,
            tls_sni: None,
            cb_failure_threshold: None,
            cb_half_open_delay_secs: None,
            cb_success_threshold: None,
            canary: true,
            canary_weight_percent: 50,
            disable_pooling: false,
            retries: None,
            retry_backoff_ms: None,
            retry_on: None,
        };

        let pool_cfg = make_pool_config(
            "random",
            vec![stable_cfg, canary_cfg],
            Some(CanaryPoolConfig {
                enabled: true,
                sticky: false,
                sticky_cookie_name: "PQCPROXY_CANARY".to_string(),
                sticky_cookie_ttl_secs: 3600,
                sticky_header: None,
                auto_rollback: false,
                rollback_error_rate: 0.05,
                rollback_window_secs: 60,
                rollback_min_requests: 10,
                ..CanaryPoolConfig::default()
            }),
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);
        let ctx = default_ctx();

        let mut canary_hits = 0u32;
        let iterations = 1000;
        for _ in 0..iterations {
            if let Some(result) = pool.select(&ctx) {
                if result.server.is_canary() {
                    canary_hits += 1;
                }
            }
        }

        // With 50% weight, expect roughly 40–60% canary hits.
        let ratio = canary_hits as f64 / iterations as f64;
        assert!(
            (0.35..=0.65).contains(&ratio),
            "Expected ~50% canary hits, got {:.1}%",
            ratio * 100.0
        );
    }

    #[test]
    fn test_canary_sticky_cookie() {
        let pool_cfg = make_pool_config(
            "round_robin",
            vec![
                PoolServerConfig {
                    address: "127.0.0.1:9001".to_string(),
                    weight: 100,
                    priority: 1,
                    max_connections: 100,
                    timeout_ms: 30000,
                    tls_mode: TlsMode::Terminate,
                    tls_cert: None,
                    tls_skip_verify: false,
                    tls_sni: None,
                    cb_failure_threshold: None,
                    cb_half_open_delay_secs: None,
                    cb_success_threshold: None,
                    canary: false,
                    canary_weight_percent: 0,
                    disable_pooling: false,
                    retries: None,
                    retry_backoff_ms: None,
                    retry_on: None,
                },
                PoolServerConfig {
                    address: "127.0.0.1:9002".to_string(),
                    weight: 100,
                    priority: 1,
                    max_connections: 100,
                    timeout_ms: 30000,
                    tls_mode: TlsMode::Terminate,
                    tls_cert: None,
                    tls_skip_verify: false,
                    tls_sni: None,
                    cb_failure_threshold: None,
                    cb_half_open_delay_secs: None,
                    cb_success_threshold: None,
                    canary: true,
                    canary_weight_percent: 100, // always canary for test
                    disable_pooling: false,
                    retries: None,
                    retry_backoff_ms: None,
                    retry_on: None,
                },
            ],
            Some(CanaryPoolConfig {
                enabled: true,
                sticky: true,
                sticky_cookie_name: "PQCPROXY_CANARY".to_string(),
                sticky_cookie_ttl_secs: 3600,
                sticky_header: None,
                auto_rollback: false,
                rollback_error_rate: 0.05,
                rollback_window_secs: 60,
                rollback_min_requests: 10,
                ..CanaryPoolConfig::default()
            }),
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);

        // First select — no cookie yet.
        let result1 = pool.select(&default_ctx()).expect("should select");
        assert!(result1.server.is_canary());
        let cookie_header = result1
            .set_canary_cookie
            .expect("should set canary cookie on first assignment");
        // Cookie value is the server ID.
        let server_id = result1.server.id.clone();
        assert!(cookie_header.contains(&server_id));
        assert!(cookie_header.contains("PQCPROXY_CANARY="));

        // Second select — send cookie back.
        let mut ctx2 = default_ctx();
        ctx2.canary_cookie = Some(server_id.clone());
        let result2 = pool.select(&ctx2).expect("should select");
        // Sticky: must return the same server.
        assert_eq!(result2.server.id, server_id);
        // Already assigned — no new Set-Cookie.
        assert!(result2.set_canary_cookie.is_none());
    }

    #[test]
    fn test_canary_auto_rollback() {
        let server = create_test_server_full("127.0.0.1:9003", 100, true, 50);
        let cfg = CanaryPoolConfig {
            enabled: true,
            sticky: false,
            sticky_cookie_name: "PQCPROXY_CANARY".to_string(),
            sticky_cookie_ttl_secs: 3600,
            sticky_header: None,
            auto_rollback: true,
            rollback_error_rate: 0.5, // 50% threshold for easy testing
            rollback_window_secs: 60,
            rollback_min_requests: 10,
            ..CanaryPoolConfig::default()
        };

        // Feed 15 failures — should trigger rollback.
        let mut triggered = false;
        for _ in 0..15 {
            if server.record_canary_result(false, &cfg, None) {
                triggered = true;
            }
        }

        assert!(triggered, "auto-rollback should have triggered");
        assert!(server.canary_suspended.load(Ordering::Relaxed));
        assert!(
            !server.is_available(),
            "suspended canary should be unavailable"
        );
    }

    #[test]
    fn test_canary_excluded_from_normal_routing() {
        // Canary server must not appear in get_healthy_servers().
        let pool_cfg = make_pool_config(
            "round_robin",
            vec![
                PoolServerConfig {
                    address: "127.0.0.1:9001".to_string(),
                    weight: 100,
                    priority: 1,
                    max_connections: 100,
                    timeout_ms: 30000,
                    tls_mode: TlsMode::Terminate,
                    tls_cert: None,
                    tls_skip_verify: false,
                    tls_sni: None,
                    cb_failure_threshold: None,
                    cb_half_open_delay_secs: None,
                    cb_success_threshold: None,
                    canary: false,
                    canary_weight_percent: 0,
                    disable_pooling: false,
                    retries: None,
                    retry_backoff_ms: None,
                    retry_on: None,
                },
                PoolServerConfig {
                    address: "127.0.0.1:9002".to_string(),
                    weight: 100,
                    priority: 1,
                    max_connections: 100,
                    timeout_ms: 30000,
                    tls_mode: TlsMode::Terminate,
                    tls_cert: None,
                    tls_skip_verify: false,
                    tls_sni: None,
                    cb_failure_threshold: None,
                    cb_half_open_delay_secs: None,
                    cb_success_threshold: None,
                    canary: true,
                    canary_weight_percent: 0, // 0% → no probabilistic routing
                    disable_pooling: false,
                    retries: None,
                    retry_backoff_ms: None,
                    retry_on: None,
                },
            ],
            None, // canary config disabled
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);

        let healthy = pool.get_healthy_servers();
        assert_eq!(healthy.len(), 1);
        assert!(!healthy[0].is_canary());
    }

    #[test]
    fn test_extract_cookie_by_name() {
        let hdr = "other=value; PQCPROXY_CANARY=127.0.0.1:9002; another=test";
        let extracted = extract_cookie_by_name(Some(hdr), "PQCPROXY_CANARY");
        assert_eq!(extracted, Some("127.0.0.1:9002".to_string()));

        // Not present
        let none = extract_cookie_by_name(Some(hdr), "NONEXISTENT");
        assert!(none.is_none());

        // Prefix match must not fire (PQCPROXY_CANARY_EXTRA is a different cookie)
        let hdr2 = "PQCPROXY_CANARY_EXTRA=yes; PQCPROXY_CANARY=target";
        let extracted2 = extract_cookie_by_name(Some(hdr2), "PQCPROXY_CANARY");
        assert_eq!(extracted2, Some("target".to_string()));
    }

    /// A slot counts exactly one request for exactly as long as it lives, and
    /// dropping one on a counter already at zero leaves it at zero instead of
    /// wrapping to `u32::MAX`.
    #[test]
    fn connection_slots_count_and_never_wrap() {
        let server = create_test_server("127.0.0.1:1", 1);
        {
            let _a = server.try_acquire_slot(false).unwrap();
            let _b = server.try_acquire_slot(false).unwrap();
            assert_eq!(server.active_connections.load(Ordering::Relaxed), 2);
        }
        assert_eq!(server.active_connections.load(Ordering::Relaxed), 0);
        let s = server.try_acquire_slot(false).unwrap();
        server.active_connections.store(0, Ordering::Relaxed);
        drop(s);
        assert_eq!(server.active_connections.load(Ordering::Relaxed), 0);
    }
}

#[cfg(test)]
mod reservation_and_rollback_tests {
    use super::*;

    fn pool(toml_src: &str) -> Arc<BackendPool> {
        let config: BackendPoolConfig = toml::from_str(toml_src).expect("pool config");
        Arc::new(BackendPool::from_config(
            &config,
            &LoadBalancerConfig::default(),
        ))
    }

    fn ctx() -> SelectionContext {
        SelectionContext {
            client_ip: "192.0.2.1".parse().unwrap(),
            session_cookie: None,
            affinity_header: None,
            path: "/".to_string(),
            host: "example.test".to_string(),
            canary_cookie: None,
            canary_header: None,
            query: None,
            cohort_header: None,
            hash_header: None,
        }
    }

    fn rollback() -> CanaryPoolConfig {
        CanaryPoolConfig {
            enabled: true,
            auto_rollback: true,
            rollback_error_rate: 0.05,
            rollback_min_requests: 10,
            ..CanaryPoolConfig::default()
        }
    }

    const CANARY_POOL: &str = r#"
        name = "c"
        algorithm = "round_robin"
        [canary]
        enabled = true
        sticky = false
        auto_rollback = true
        rollback_min_requests = 10
        [[servers]]
        address = "127.0.0.1:9201"
        canary = true
        canary_weight_percent = 100
        [[servers]]
        address = "127.0.0.1:9202"
    "#;

    fn member(pool: &BackendPool, canary: bool) -> Arc<BackendServer> {
        pool.servers
            .read()
            .iter()
            .find(|s| s.is_canary() == canary)
            .cloned()
            .unwrap()
    }

    #[test]
    fn the_last_place_goes_to_one_request_however_many_arrive_at_once() {
        let pool = pool(
            r#"
            name = "p"
            [[servers]]
            address = "127.0.0.1:9203"
            max_connections = 5
            "#,
        );
        let start = Arc::new(std::sync::Barrier::new(32));
        let mut threads = Vec::new();
        for _ in 0..32 {
            let (pool, start) = (Arc::clone(&pool), Arc::clone(&start));
            threads.push(std::thread::spawn(move || {
                start.wait();
                pool.select(&ctx())
            }));
        }
        let held: Vec<_> = threads
            .into_iter()
            .filter_map(|t| t.join().unwrap())
            .collect();
        assert_eq!(held.len(), 5);
        assert_eq!(
            pool.servers.read()[0]
                .active_connections
                .load(Ordering::Acquire),
            5
        );
        drop(held);
        assert_eq!(
            pool.servers.read()[0]
                .active_connections
                .load(Ordering::Acquire),
            0
        );
    }

    #[test]
    fn a_server_with_an_open_breaker_takes_one_trial_at_a_time() {
        let pool = pool(
            r#"
            name = "p"
            [[servers]]
            address = "127.0.0.1:9204"
            cb_failure_threshold = 1
            cb_half_open_delay_secs = 0
            "#,
        );
        pool.servers.read()[0].record_result(false, Duration::from_millis(1));
        let trial = pool.select(&ctx()).expect("the trial");
        assert!(pool.select(&ctx()).is_none(), "one at a time");
        drop(trial);
        assert!(pool.select(&ctx()).is_some());
    }

    #[test]
    fn a_full_canary_takes_no_more_and_the_stable_servers_do() {
        let pool = pool(
            r#"
            name = "c"
            algorithm = "round_robin"
            [canary]
            enabled = true
            sticky = false
            [[servers]]
            address = "127.0.0.1:9205"
            canary = true
            canary_weight_percent = 100
            max_connections = 1
            [[servers]]
            address = "127.0.0.1:9206"
            "#,
        );
        let first = pool.select(&ctx()).unwrap();
        assert!(first.server.is_canary());
        assert!(!pool.select(&ctx()).unwrap().server.is_canary());
    }

    #[test]
    fn each_canary_has_its_own_share_of_new_traffic() {
        let shares = [("a", 5), ("b", 50)];
        let landed: Vec<_> = (0..100)
            .map(|roll| canary_for_roll(&shares, roll))
            .collect();
        assert_eq!(landed.iter().filter(|c| **c == Some(&"a")).count(), 5);
        assert_eq!(landed.iter().filter(|c| **c == Some(&"b")).count(), 50);
        assert_eq!(landed.iter().filter(|c| c.is_none()).count(), 45);
    }

    #[test]
    fn shares_over_a_hundred_divide_all_of_the_traffic() {
        let shares = [("a", 80), ("b", 80)];
        let landed: Vec<_> = (0..160)
            .map(|roll| canary_for_roll(&shares, roll))
            .collect();
        assert_eq!(landed.iter().filter(|c| **c == Some(&"a")).count(), 80);
        assert_eq!(landed.iter().filter(|c| **c == Some(&"b")).count(), 80);
    }

    #[test]
    fn a_canary_answering_500_is_rolled_back_and_its_breaker_stays_closed() {
        let pool = pool(CANARY_POOL);
        let canary = member(&pool, true);
        for _ in 0..10 {
            pool.record_response(&canary, Duration::from_millis(1), 500);
        }
        assert!(canary.canary_suspended.load(Ordering::Acquire));
        assert!(!canary.health.read().circuit_open, "the server did answer");
    }

    #[test]
    fn a_canary_answering_200_is_kept() {
        let pool = pool(CANARY_POOL);
        let canary = member(&pool, true);
        for _ in 0..50 {
            pool.record_response(&canary, Duration::from_millis(1), 200);
        }
        assert!(!canary.canary_suspended.load(Ordering::Acquire));
    }

    #[test]
    fn a_status_the_operator_ignores_is_not_an_error() {
        let config = CanaryPoolConfig {
            rollback_ignored_statuses: vec![501],
            ..rollback()
        };
        assert!(config.is_error_status(500));
        assert!(!config.is_error_status(501));
        assert!(!config.is_error_status(404));
    }

    #[test]
    fn a_body_that_fails_counts_against_the_canary() {
        let pool = pool(CANARY_POOL);
        let canary = member(&pool, true);
        for _ in 0..10 {
            pool.record_response(&canary, Duration::from_millis(1), 200);
        }
        for _ in 0..3 {
            pool.record_body_failure(&canary);
        }
        assert!(canary.canary_suspended.load(Ordering::Acquire));
        assert_eq!(canary.canary_window.lock().totals(Instant::now()), (10, 3));
    }

    #[test]
    fn one_error_among_few_requests_does_not_roll_back() {
        let server = Arc::new(
            BackendServer::from_config(
                &toml::from_str(r#"address = "127.0.0.1:9207""#).expect("server config"),
            )
            .unwrap(),
        );
        let config = rollback();
        assert!(!server.record_canary_result(false, &config, None));
        for _ in 0..12 {
            assert!(!server.record_canary_result(true, &config, None));
        }
        assert!(
            !server.record_canary_result(false, &config, None),
            "two errors"
        );
        assert!(
            server.record_canary_result(false, &config, None),
            "the third"
        );
    }

    #[test]
    fn a_failure_the_stable_servers_share_does_not_roll_back_the_canary() {
        let pool = pool(CANARY_POOL);
        let (canary, stable) = (member(&pool, true), member(&pool, false));
        for _ in 0..20 {
            pool.record_response(&stable, Duration::from_millis(1), 503);
            pool.record_response(&canary, Duration::from_millis(1), 503);
        }
        assert!(!canary.canary_suspended.load(Ordering::Acquire));

        for _ in 0..200 {
            pool.record_response(&stable, Duration::from_millis(1), 200);
        }
        pool.record_response(&canary, Duration::from_millis(1), 503);
        assert!(
            canary.canary_suspended.load(Ordering::Acquire),
            "now it is the canary's"
        );
    }

    #[test]
    fn errors_leave_the_rollback_window_a_bucket_at_a_time() {
        let window_length = Duration::from_secs(60);
        let start = Instant::now();
        let mut window = OutcomeWindow::new();
        window.record(true, window_length, start);
        window.record(false, window_length, start + Duration::from_secs(30));
        assert_eq!(window.totals(start + Duration::from_secs(59)), (2, 1));
        // The first has gone; a window that reset as a whole would lose both.
        assert_eq!(window.totals(start + Duration::from_secs(66)), (1, 0));
        assert_eq!(window.totals(start + Duration::from_secs(96)), (0, 0));
    }

    #[test]
    fn a_draining_server_keeps_its_sessions_and_takes_no_new_ones() {
        let pool = pool(
            r#"
            name = "s"
            algorithm = "round_robin"
            affinity = "cookie"
            [[servers]]
            address = "127.0.0.1:9208"
            [[servers]]
            address = "127.0.0.1:9209"
            "#,
        );
        let session = SelectionContext {
            session_cookie: Some("kept".to_string()),
            ..ctx()
        };
        let first = pool.select(&session).unwrap().server;
        first.start_draining(Duration::from_secs(60));

        assert_eq!(
            pool.select(&session).unwrap().server.id,
            first.id,
            "it stays"
        );
        for number in 0..8 {
            let new = SelectionContext {
                session_cookie: Some(format!("new-{number}")),
                ..ctx()
            };
            assert_ne!(pool.select(&new).unwrap().server.id, first.id);
        }
    }

    #[test]
    fn a_session_leaves_a_draining_server_that_goes_down() {
        let pool = pool(
            r#"
            name = "s"
            algorithm = "round_robin"
            affinity = "cookie"
            [[servers]]
            address = "127.0.0.1:9210"
            [[servers]]
            address = "127.0.0.1:9211"
            "#,
        );
        let session = SelectionContext {
            session_cookie: Some("kept".to_string()),
            ..ctx()
        };
        let first = pool.select(&session).unwrap().server;
        first.start_draining(Duration::from_secs(60));
        first.health.write().healthy = false;
        assert_ne!(pool.select(&session).unwrap().server.id, first.id);
    }
}

#[cfg(test)]
mod rollout_tests {
    use super::*;

    /// A blue/green pair: one stable member, one stopped, a canary with a
    /// ramp of two steps.
    const PAIR: &str = r#"
        name = "api"
        algorithm = "least_connections"
        health_aware = true
        [canary]
        enabled = true
        sticky = false
        auto_rollback = true
        rollback_min_requests = 3
        rollback_min_errors = 2
        rollback_compare_stable = false
        ramp_percent = [10, 50]
        ramp_step_secs = 60
        ramp_min_requests = 2
        auto_promote = true
        [[servers]]
        address = "127.0.0.1:3013"
        [[servers]]
        address = "127.0.0.1:3023"
    "#;

    fn pool(toml_src: &str) -> Arc<BackendPool> {
        let config: BackendPoolConfig = toml::from_str(toml_src).expect("pool config");
        Arc::new(BackendPool::from_config(
            &config,
            &LoadBalancerConfig::default(),
        ))
    }

    fn ctx() -> SelectionContext {
        SelectionContext {
            client_ip: "192.0.2.1".parse().unwrap(),
            session_cookie: None,
            affinity_header: None,
            path: "/".to_string(),
            host: "example.test".to_string(),
            canary_cookie: None,
            canary_header: None,
            query: None,
            cohort_header: None,
            hash_header: None,
        }
    }

    /// `n` answered requests on `server`
    fn answered(pool: &BackendPool, server: &BackendServer, n: usize, status: u16) {
        for _ in 0..n {
            pool.record_response(server, Duration::from_millis(1), status);
        }
    }

    #[test]
    fn a_rollout_steps_up_with_time_and_answers_then_promotes() {
        let pool = pool(PAIR);
        let blue = pool.member("127.0.0.1:3013").unwrap();
        let green = pool.member("127.0.0.1:3023").unwrap();
        assert!(!green.is_canary(), "configured stable");

        assert_eq!(pool.start_canary(&green.id, None), Ok(10));
        assert!(green.is_canary());
        let t0 = Instant::now();
        let step = Duration::from_secs(60);

        // Time alone does not move it on: the canary has answered nothing
        assert!(pool.advance_rollout(t0 + step));
        assert_eq!(green.canary_weight_percent.load(Ordering::Relaxed), 10);

        answered(&pool, &green, 2, 200);
        // Answers alone do not either, before the step's time
        assert!(pool.advance_rollout(t0 + Duration::from_secs(1)));
        assert_eq!(green.canary_weight_percent.load(Ordering::Relaxed), 10);
        assert!(pool.advance_rollout(t0 + step));
        assert_eq!(green.canary_weight_percent.load(Ordering::Relaxed), 50);
        let status = pool.rollout_status().unwrap();
        assert_eq!((status.step, status.outcome), (2, RolloutOutcome::Ramping));

        answered(&pool, &green, 2, 200);
        assert!(
            !pool.advance_rollout(t0 + 3 * step),
            "the last step held: done"
        );
        assert!(!green.is_canary(), "promoted to stable");
        assert!(green.is_available());
        assert!(!blue.is_available(), "the member it replaces drains");
        assert_eq!(
            pool.rollout_status().unwrap().outcome,
            RolloutOutcome::Promoted
        );
        // Everything new goes to the promoted member
        for _ in 0..10 {
            assert!(Arc::ptr_eq(&pool.select(&ctx()).unwrap().server, &green));
        }
    }

    #[test]
    fn a_failing_canary_rolls_the_rollout_back() {
        let pool = pool(PAIR);
        let green = pool.member("127.0.0.1:3023").unwrap();
        pool.start_canary(&green.id, None).unwrap();
        answered(&pool, &green, 3, 503);
        assert!(green.canary_suspended.load(Ordering::Relaxed));
        assert!(!pool.advance_rollout(Instant::now() + Duration::from_secs(600)));
        assert_eq!(
            pool.rollout_status().unwrap().outcome,
            RolloutOutcome::RolledBack
        );
        // The stable member takes everything
        let blue = pool.member("127.0.0.1:3013").unwrap();
        for _ in 0..10 {
            assert!(Arc::ptr_eq(&pool.select(&ctx()).unwrap().server, &blue));
        }
    }

    #[test]
    fn a_fixed_weight_is_no_rollout_and_bad_requests_are_refused() {
        let pool = pool(PAIR);
        assert_eq!(pool.start_canary("127.0.0.1:3023", Some(30)), Ok(30));
        assert!(pool.rollout_status().is_none());
        assert!(pool.start_canary("127.0.0.1:3023", Some(101)).is_err());
        assert!(pool.start_canary("127.0.0.1:9", None).is_err());

        let off = self::pool(&PAIR.replace("enabled = true", "enabled = false"));
        assert!(off.start_canary("127.0.0.1:3023", Some(5)).is_err());
        let no_ramp = self::pool(
            &PAIR
                .replace("ramp_percent = [10, 50]", "")
                .replace("auto_promote = true", ""),
        );
        assert!(no_ramp.start_canary("127.0.0.1:3023", None).is_err());
    }

    #[test]
    fn without_auto_promote_the_canary_waits_for_promotion() {
        let pool = pool(&PAIR.replace("auto_promote = true", "auto_promote = false"));
        let green = pool.member("127.0.0.1:3023").unwrap();
        pool.start_canary(&green.id, None).unwrap();
        let t0 = Instant::now();
        answered(&pool, &green, 2, 200);
        pool.advance_rollout(t0 + Duration::from_secs(60));
        answered(&pool, &green, 2, 200);
        assert!(!pool.advance_rollout(t0 + Duration::from_secs(180)));
        assert!(green.is_canary());
        assert_eq!(
            pool.rollout_status().unwrap().outcome,
            RolloutOutcome::AwaitingPromotion
        );
        assert!(pool.promote(&green.id));
        assert!(!green.is_canary());
        assert!(!pool.promote(&green.id), "no longer a canary");
    }

    #[test]
    fn an_unreachable_member_leaves_rotation_until_it_answers() {
        let pool = pool(PAIR);
        let blue = pool.member("127.0.0.1:3013").unwrap();
        let green = pool.member("127.0.0.1:3023").unwrap();
        green.mark_unreachable();
        for _ in 0..10 {
            assert!(Arc::ptr_eq(&pool.select(&ctx()).unwrap().server, &blue));
        }
        // Made the canary while down: it takes nothing until it is up
        pool.start_canary(&green.id, Some(100)).unwrap();
        assert!(Arc::ptr_eq(&pool.select(&ctx()).unwrap().server, &blue));
        green.health.write().healthy = true;
        assert!(Arc::ptr_eq(&pool.select(&ctx()).unwrap().server, &green));
    }

    #[test]
    fn a_reload_that_keeps_the_canary_keeps_its_rollout() {
        let lb = LoadBalancer::new(Arc::new(LoadBalancerConfig::default()));
        let config: BackendPoolConfig = toml::from_str(PAIR).unwrap();
        let configured = std::collections::HashMap::from([("api".to_string(), config.clone())]);
        lb.reconcile_pools(&configured);
        assert_eq!(lb.start_canary("api", "127.0.0.1:3023", None), Ok(10));

        // A change to the pool's settings rebuilds it; the members keep their objects
        let mut changed = config;
        changed.queue_timeout_ms = Some(1234);
        lb.reconcile_pools(&std::collections::HashMap::from([(
            "api".to_string(),
            changed,
        )]));
        let status = lb.get_pool("api").unwrap().rollout_status().unwrap();
        assert_eq!(status.server, "127.0.0.1:3023");
        assert_eq!(status.outcome, RolloutOutcome::Ramping);
        assert!(lb.promote("api", "127.0.0.1:3023"));
    }

    /// An `ip` cohort keeps each client on its side while the weight holds,
    /// and a weight that rises moves clients only towards the canary.
    #[test]
    fn a_cohort_keeps_each_client_on_its_side_as_the_weight_rises() {
        let pool = pool(&PAIR.replace("sticky = false", "sticky = false\ncohort = \"ip\""));
        let green = pool.member("127.0.0.1:3023").unwrap();
        pool.start_canary(&green.id, Some(10)).unwrap();
        let from = |i: u32| SelectionContext {
            client_ip: IpAddr::V4(std::net::Ipv4Addr::from(0xC000_0200 + i)),
            ..ctx()
        };
        let side = |i: u32| {
            let chosen = pool.select(&from(i)).unwrap();
            chosen.server.is_canary()
        };
        let at_10: Vec<bool> = (0..400).map(side).collect();
        // The same clients, the same sides
        assert_eq!(at_10, (0..400).map(side).collect::<Vec<_>>());
        let share = at_10.iter().filter(|c| **c).count();
        assert!((15..=70).contains(&share), "about 10% of 400: {share}");

        green.canary_weight_percent.store(50, Ordering::Relaxed);
        let at_50: Vec<bool> = (0..400).map(side).collect();
        for (before, after) in at_10.iter().zip(&at_50) {
            assert!(!before || *after, "a client on the canary stays there");
        }
        assert!(at_50.iter().filter(|c| **c).count() > share);
    }

    #[test]
    fn selection_reads_every_cookie_field_and_the_affinity_header() {
        let pool = pool(
            r#"
            name = "s"
            affinity = "header"
            affinity_header = "x-tenant"
            [canary]
            enabled = true
            sticky_cookie_name = "CANARY"
            [[servers]]
            address = "127.0.0.1:3013"
            "#,
        );
        let mut headers = http::HeaderMap::new();
        headers.append(http::header::COOKIE, "a=1".parse().unwrap());
        headers.append(
            http::header::COOKIE,
            "SESSION=s1; CANARY=c1".parse().unwrap(),
        );
        headers.insert("x-tenant", "t9".parse().unwrap());
        let cookie = SessionCookieConfig {
            name: "SESSION".to_string(),
            ttl: Duration::from_secs(60),
            secure: true,
            httponly: true,
            samesite: SameSite::Lax,
        };
        let ctx = SelectionContext::for_request(
            &pool,
            &cookie,
            &headers,
            "192.0.2.7".parse().unwrap(),
            "/p",
            "h.test",
            Some("q=1"),
        );
        assert_eq!(ctx.session_cookie.as_deref(), Some("s1"));
        assert_eq!(ctx.canary_cookie.as_deref(), Some("c1"));
        assert_eq!(ctx.affinity_header.as_deref(), Some("t9"));
        assert_eq!(ctx.query.as_deref(), Some("q=1"));
    }
}
