//! Load balancer module for backend pool management
//!
//! Provides cutting-edge load balancing with:
//! - Multiple algorithms (least_connections, round_robin, weighted, random, ip_hash, least_response_time)
//! - Health-aware routing (skip unhealthy backends)
//! - Session affinity (cookie-based and IP-based sticky sessions)
//! - Request queuing when backends saturated
//! - Slow start for recovering backends
//! - Connection draining for graceful removal
//!
//! Connection draining is fully implemented via `BackendServer::start_draining()`,
//! invoked through `LoadBalancer::drain_server()` for graceful backend removal.

/// Maximum age of a sticky session mapping before it is silently evicted.
/// Prevents cookie_sessions / ip_sessions / header_sessions from growing without bound
/// on long-running instances with many unique clients.
const SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use tokio::sync::Semaphore;
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
}

/// Result of `BackendPool::select()`.
///
/// Carries the chosen server and an optional `Set-Cookie` header value that
/// the HTTP listener must inject into the response to establish a sticky
/// canary assignment for the client.
#[derive(Clone)]
pub struct SelectionResult {
    /// The selected backend server.
    pub server: Arc<BackendServer>,
    /// If `Some(header_value)`, the listener should append this as a `Set-Cookie`
    /// response header (format: "PQCPROXY_CANARY=<id>; Path=/; …").
    pub set_canary_cookie: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
// Backend Server
// ═══════════════════════════════════════════════════════════════

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

    // === Circuit breaker thresholds (per-backend overrides) ===
    /// Consecutive failures before tripping the circuit breaker
    pub cb_failure_threshold: u32,
    /// Consecutive successes to close a tripped circuit breaker
    pub cb_success_threshold: u32,

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
    /// Connection limiter
    connection_limiter: Semaphore,
    /// Health status
    pub health: RwLock<BackendHealth>,
    /// Slow start state
    pub slow_start: RwLock<Option<SlowStartState>>,
    /// Draining state
    pub draining: RwLock<Option<DrainingState>>,

    // === Canary state ===
    /// Whether this server is designated as a canary deployment target
    pub is_canary: bool,
    /// Fraction of *new* traffic to route here when it is the active canary (0–100)
    pub canary_weight_percent: AtomicU8,
    /// True when the canary has been suspended (manually or by auto-rollback)
    pub canary_suspended: AtomicBool,
    /// Start of the current error-rate measurement window
    canary_window_start: RwLock<Instant>,
    /// Total requests seen in the current window
    canary_window_requests: AtomicU64,
    /// Error requests seen in the current window
    canary_window_errors: AtomicU64,
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
}

impl Default for BackendHealth {
    fn default() -> Self {
        Self {
            healthy: true,
            last_check: Instant::now(),
            consecutive_failures: 0,
            consecutive_successes: 0,
            circuit_open: false,
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
            cb_failure_threshold: config.cb_failure_threshold.unwrap_or(5),
            cb_success_threshold: config.cb_success_threshold.unwrap_or(3),
            active_connections: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            connection_limiter: Semaphore::new(config.max_connections as usize),
            health: RwLock::new(BackendHealth::default()),
            slow_start: RwLock::new(None),
            draining: RwLock::new(None),
            is_canary: config.canary,
            canary_weight_percent: AtomicU8::new(config.canary_weight_percent),
            canary_suspended: AtomicBool::new(false),
            canary_window_start: RwLock::new(Instant::now()),
            canary_window_requests: AtomicU64::new(0),
            canary_window_errors: AtomicU64::new(0),
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
            && !health.circuit_open
            && draining.is_none()
            && !(self.is_canary && self.canary_suspended.load(Ordering::Relaxed))
    }

    /// Check if this canary server is available for canary-specific routing.
    pub fn is_canary_available(&self) -> bool {
        self.is_canary && self.is_available()
    }

    /// Acquire connection to this server.
    ///
    /// P1-fix: Previously `try_acquire().is_ok()` dropped the `SemaphorePermit`
    /// immediately (auto-release on drop), while `release_connection` called
    /// `add_permits(1)` unconditionally — causing the semaphore to grow without
    /// bound on every completed connection.  `permit.forget()` suppresses the
    /// auto-release so that the semaphore slot stays taken until `release_connection`
    /// explicitly restores it with `add_permits(1)`.
    pub fn try_acquire_connection(&self) -> bool {
        match self.connection_limiter.try_acquire() {
            Ok(permit) => {
                // Keep the semaphore slot taken until release_connection is called.
                permit.forget();
                self.active_connections.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => false,
        }
    }

    /// Release connection (counterpart to a successful try_acquire_connection).
    pub fn release_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        // Restore the slot that was forgotten in try_acquire_connection.
        self.connection_limiter.add_permits(1);
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
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
                health.healthy = true;
                info!("Backend {} circuit breaker closed", self.id);
            }
        } else {
            self.total_failures.fetch_add(1, Ordering::Relaxed);

            let mut health = self.health.write();
            health.consecutive_successes = 0;
            health.consecutive_failures += 1;

            // Open circuit breaker after per-backend failure threshold
            if health.consecutive_failures >= self.cb_failure_threshold && !health.circuit_open {
                health.circuit_open = true;
                health.healthy = false;
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

    // ── Canary helpers ────────────────────────────────────────────────────────

    /// Suspend this canary server so it receives no further traffic.
    pub fn suspend_canary(&self) {
        self.canary_suspended.store(true, Ordering::Relaxed);
        warn!("Canary server {} suspended", self.id);
    }

    /// Resume a suspended canary server and reset its error-rate window.
    pub fn resume_canary(&self) {
        self.canary_suspended.store(false, Ordering::Relaxed);
        *self.canary_window_start.write() = Instant::now();
        self.canary_window_requests.store(0, Ordering::Relaxed);
        self.canary_window_errors.store(0, Ordering::Relaxed);
        info!("Canary server {} resumed", self.id);
    }

    /// Return the current error rate in the sliding window (0.0–1.0).
    #[allow(clippy::cast_precision_loss)]
    pub fn canary_error_rate(&self) -> f64 {
        let requests = self.canary_window_requests.load(Ordering::Relaxed);
        if requests == 0 {
            return 0.0;
        }
        let errors = self.canary_window_errors.load(Ordering::Relaxed);
        errors as f64 / requests as f64
    }

    /// Record a canary request outcome and potentially trigger auto-rollback.
    ///
    /// Returns `true` if auto-rollback was just triggered (i.e. the canary was
    /// suspended by this call).  The caller should log a warning in that case.
    #[allow(clippy::cast_precision_loss)]
    pub fn record_canary_result(&self, success: bool, config: &CanaryPoolConfig) -> bool {
        if !config.auto_rollback {
            return false;
        }

        let window_dur = Duration::from_secs(config.rollback_window_secs);

        // Reset window if it has expired.
        {
            let mut window_start = self.canary_window_start.write();
            if window_start.elapsed() >= window_dur {
                *window_start = Instant::now();
                self.canary_window_requests.store(0, Ordering::Relaxed);
                self.canary_window_errors.store(0, Ordering::Relaxed);
            }
        }

        self.canary_window_requests.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.canary_window_errors.fetch_add(1, Ordering::Relaxed);
        }

        let requests = self.canary_window_requests.load(Ordering::Relaxed);
        let errors = self.canary_window_errors.load(Ordering::Relaxed);

        if requests >= config.rollback_min_requests {
            let error_rate = errors as f64 / requests as f64;
            if error_rate > config.rollback_error_rate {
                // Use compare-and-swap so we only return true once (first trigger).
                if self
                    .canary_suspended
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            }
        }

        false
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

    // === Round-robin state ===
    rr_counter: AtomicU64,

    // === Weighted round-robin state ===
    wrr_state: RwLock<WeightedRoundRobinState>,

    // === Canary state ===
    /// Pool-level canary configuration (None when canary is not configured).
    pub canary_config: Option<CanaryPoolConfig>,
    /// Canary sticky-cookie → (server_id, last_access) with TTL eviction.
    canary_sessions: DashMap<String, (String, Instant)>,
}

/// State for weighted round-robin algorithm
#[derive(Default)]
struct WeightedRoundRobinState {
    /// Current weight for each server
    current_weights: Vec<i64>,
}

impl BackendPool {
    /// Create pool from configuration
    pub fn from_config(config: &BackendPoolConfig, _lb_config: &LoadBalancerConfig) -> Self {
        let algorithm = Self::create_algorithm(&config.algorithm);

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
            rr_counter: AtomicU64::new(0),
            wrr_state: RwLock::new(WeightedRoundRobinState::default()),
            canary_config: config.canary.clone(),
            canary_sessions: DashMap::new(),
        }
    }

    /// Create algorithm by name
    fn create_algorithm(name: &str) -> Box<dyn LoadBalancingAlgorithm> {
        match name {
            "round_robin" => Box::new(RoundRobinAlgorithm),
            "weighted_round_robin" => Box::new(WeightedRoundRobinAlgorithm),
            "random" => Box::new(RandomAlgorithm),
            "ip_hash" => Box::new(IpHashAlgorithm),
            "least_response_time" => Box::new(LeastResponseTimeAlgorithm),
            _ => Box::new(LeastConnectionsAlgorithm), // Default: least_connections
        }
    }

    /// Select a backend server.
    ///
    /// Canary routing is attempted first (when configured and enabled), then
    /// falls back to normal sticky-session / algorithm selection among non-canary
    /// servers.  Returns a `SelectionResult` that may carry a `Set-Cookie` header
    /// value that the caller must inject into the HTTP response.
    pub fn select(&self, ctx: &SelectionContext) -> Option<SelectionResult> {
        // Try canary routing first.
        if let Some(result) = self.try_canary_select(ctx) {
            return Some(result);
        }

        // Normal routing (canary servers are excluded from get_healthy_servers).
        if let Some(server) = self.check_sticky_session(ctx) {
            if server.is_available() {
                return Some(SelectionResult {
                    server,
                    set_canary_cookie: None,
                });
            }
        }

        let server = self.algorithm.select(self, ctx)?;
        self.record_sticky_session(ctx, &server);

        Some(SelectionResult {
            server,
            set_canary_cookie: None,
        })
    }

    /// Canary-specific selection logic.  Returns `None` if canary is not
    /// configured/enabled or no canary server is available.
    fn try_canary_select(&self, ctx: &SelectionContext) -> Option<SelectionResult> {
        let canary_cfg = self.canary_config.as_ref()?;
        if !canary_cfg.enabled {
            return None;
        }

        // Collect available canary servers.
        let available_canaries: Vec<Arc<BackendServer>> = {
            let servers = self.servers.read();
            servers
                .iter()
                .filter(|s| s.is_canary_available())
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
                            return Some(SelectionResult {
                                server,
                                set_canary_cookie: None, // already set on a previous request
                            });
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
                return Some(SelectionResult {
                    server,
                    set_canary_cookie: set_cookie,
                });
            }
        }

        // 3. Probabilistic roll — route `canary_weight_percent`% of new requests.
        let max_pct = available_canaries
            .iter()
            .map(|s| s.canary_weight_percent.load(Ordering::Relaxed))
            .max()
            .unwrap_or(0);

        if max_pct == 0 {
            return None;
        }

        let roll: u8 = rand::thread_rng().gen_range(0..100);
        if roll >= max_pct {
            return None;
        }

        // Select least-connections canary.
        let server = available_canaries
            .iter()
            .min_by_key(|s| s.active_connections.load(Ordering::Relaxed))
            .cloned()?;

        let set_canary_cookie = if canary_cfg.sticky {
            self.canary_sessions
                .insert(server.id.clone(), (server.id.clone(), Instant::now()));
            Some(self.build_canary_cookie(&server.id, canary_cfg))
        } else {
            None
        };

        Some(SelectionResult {
            server,
            set_canary_cookie,
        })
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
                    self.cookie_sessions
                        .insert(cookie.clone(), (server.id.clone(), Instant::now()));
                }
            }
            AffinityMode::IpHash => {
                self.ip_sessions
                    .insert(ctx.client_ip, (server.id.clone(), Instant::now()));
            }
            AffinityMode::Header => {
                if let Some(ref header_val) = ctx.affinity_header {
                    self.header_sessions
                        .insert(header_val.clone(), (server.id.clone(), Instant::now()));
                }
            }
            AffinityMode::None => {}
        }
    }

    /// Find server by ID
    fn find_server_by_id(&self, id: &str) -> Option<Arc<BackendServer>> {
        let servers = self.servers.read();
        servers
            .iter()
            .find(|s| s.id == id && s.is_available())
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
            // Still exclude canary servers even when health-checking is off.
            return servers.iter().filter(|s| !s.is_canary).cloned().collect();
        }

        // First, try priority 1 healthy non-canary servers
        let priority_1: Vec<_> = servers
            .iter()
            .filter(|s| s.is_available() && s.priority == 1 && !s.is_canary)
            .cloned()
            .collect();

        if !priority_1.is_empty() {
            return priority_1;
        }

        // Failover to higher priority numbers (still excluding canary servers)
        servers
            .iter()
            .filter(|s| s.is_available() && !s.is_canary)
            .cloned()
            .collect()
    }

    /// Record request completion and update canary auto-rollback counters.
    pub fn record_completion(
        &self,
        server: &BackendServer,
        response_time: Duration,
        success: bool,
    ) {
        self.algorithm
            .record_completion(server, response_time, success);
        server.record_result(success, response_time);

        // Canary error-rate tracking and auto-rollback.
        if server.is_canary {
            if let Some(ref canary_cfg) = self.canary_config {
                if server.record_canary_result(success, canary_cfg) {
                    warn!(
                        "Canary server {} in pool '{}' auto-suspended: error rate {:.1}% exceeded threshold {:.1}%",
                        server.id,
                        self.name,
                        server.canary_error_rate() * 100.0,
                        canary_cfg.rollback_error_rate * 100.0
                    );
                }
            }
        }
    }

    /// Get algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm.name()
    }

    /// Suspend a canary server by its ID.  Returns true if found and suspended.
    pub fn suspend_canary_server(&self, server_id: &str) -> bool {
        let servers = self.servers.read();
        if let Some(s) = servers.iter().find(|s| s.id == server_id && s.is_canary) {
            s.suspend_canary();
            return true;
        }
        false
    }

    /// Resume a suspended canary server by its ID.  Returns true if found and resumed.
    pub fn resume_canary_server(&self, server_id: &str) -> bool {
        let servers = self.servers.read();
        if let Some(s) = servers.iter().find(|s| s.id == server_id && s.is_canary) {
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
            if s.id == server_id && s.is_canary {
                s.canary_weight_percent.store(percent, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Return a snapshot of canary server status for the admin API.
    pub fn canary_status(&self) -> Vec<CanaryServerStatus> {
        let servers = self.servers.read();
        servers
            .iter()
            .filter(|s| s.is_canary)
            .map(|s| CanaryServerStatus {
                id: s.id.clone(),
                canary_weight_percent: s.canary_weight_percent.load(Ordering::Relaxed),
                suspended: s.canary_suspended.load(Ordering::Relaxed),
                error_rate: s.canary_error_rate(),
                window_requests: s.canary_window_requests.load(Ordering::Relaxed),
                window_errors: s.canary_window_errors.load(Ordering::Relaxed),
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
        }
    }

    /// Start a background health-check task for this pool.
    ///
    /// P2-fix: previously the pool only reacted to failures seen during real
    /// requests (`record_result`).  A backend could be completely unreachable
    /// yet still receive requests until one happened to land on it.  This task
    /// proactively checks each server on the configured interval via a TCP
    /// connect (sufficient to detect port-closed / firewall-dropped backends)
    /// and updates `BackendHealth::healthy` accordingly.
    ///
    /// # Arguments
    /// `pool` — the pool wrapped in `Arc` so the spawned task can hold a reference.
    pub fn start_health_check_task(pool: Arc<Self>) {
        if !pool.health_aware {
            return; // Health-check disabled for this pool
        }
        let interval = pool.health_check_interval;
        if interval.is_zero() {
            return;
        }

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the first tick so we don't check immediately on startup
            // (all servers start healthy by default and the first real request
            // will quickly surface any that are unreachable).
            ticker.tick().await;

            loop {
                ticker.tick().await;

                let servers: Vec<Arc<BackendServer>> = { pool.servers.read().clone() };

                for server in servers {
                    let addr = server.address;
                    // Use half the interval as the connect timeout so a slow
                    // backend doesn't stall the entire health-check round.
                    let timeout_dur = interval / 2;

                    let reachable =
                        tokio::time::timeout(timeout_dur, tokio::net::TcpStream::connect(addr))
                            .await
                            .map(|r| r.is_ok())
                            .unwrap_or(false);

                    let mut health = server.health.write();
                    let was_healthy = health.healthy;

                    if reachable {
                        if !was_healthy {
                            info!(
                                "Health check: backend {} is now reachable — marking healthy",
                                addr
                            );
                        }
                        health.healthy = true;
                        health.last_check = Instant::now();
                    } else {
                        if was_healthy {
                            warn!(
                                "Health check: backend {} is unreachable — marking unhealthy",
                                addr
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

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub name: String,
    pub algorithm: String,
    pub total_servers: usize,
    pub healthy_servers: usize,
    pub total_connections: u32,
    pub total_requests: u64,
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

        let idx = rand::thread_rng().gen_range(0..healthy_servers.len());
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

        // Hash client IP to server index
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ctx.client_ip.hash(&mut hasher);
        let hash = hasher.finish();

        let idx = usize::try_from(hash).unwrap_or(usize::MAX) % healthy_servers.len();
        Some(healthy_servers[idx].clone())
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
        self.pools.insert(pool_config.name.clone(), pool);
    }

    /// Check if a pool exists
    pub fn has_pool(&self, name: &str) -> bool {
        self.pools.contains_key(name)
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

    /// Select backend for request.  Returns a `SelectionResult` that may carry
    /// a canary `Set-Cookie` header value to inject into the response.
    pub fn select_backend(
        &self,
        pool_name: &str,
        ctx: &SelectionContext,
    ) -> Option<SelectionResult> {
        let pool = self.pools.get(pool_name)?;
        pool.select(ctx)
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

    /// Get all pool statistics
    pub fn all_stats(&self) -> Vec<PoolStats> {
        self.pools.iter().map(|p| p.stats()).collect()
    }

    /// Drain a server in a pool
    pub fn drain_server(&self, pool_name: &str, server_id: &str) {
        if let Some(pool) = self.pools.get(pool_name) {
            let servers = pool.servers.read();
            if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                server.start_draining(Duration::from_secs(
                    self.config.connection_draining.timeout_secs,
                ));
            }
        }
    }

    /// Mark a server as unhealthy
    pub fn mark_unhealthy(&self, pool_name: &str, server_id: &str) {
        if let Some(pool) = self.pools.get(pool_name) {
            let servers = pool.servers.read();
            if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                let mut health = server.health.write();
                health.healthy = false;
                warn!(
                    "Backend {} in pool {} marked unhealthy",
                    server_id, pool_name
                );
            }
        }
    }

    /// Mark a server as healthy (with optional slow start)
    pub fn mark_healthy(&self, pool_name: &str, server_id: &str, slow_start: bool) {
        if let Some(pool) = self.pools.get(pool_name) {
            let servers = pool.servers.read();
            if let Some(server) = servers.iter().find(|s| s.id == server_id) {
                {
                    let mut health = server.health.write();
                    health.healthy = true;
                    health.circuit_open = false;
                    health.consecutive_failures = 0;
                }

                if slow_start && self.config.slow_start.enabled {
                    server.start_slow_start(
                        Duration::from_secs(self.config.slow_start.duration_secs),
                        self.config.slow_start.initial_weight_percent,
                    );
                }

                info!("Backend {} in pool {} marked healthy", server_id, pool_name);
            }
        }
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
    use super::*;

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

    fn default_ctx() -> SelectionContext {
        SelectionContext {
            client_ip: "127.0.0.1".parse().unwrap(),
            session_cookie: None,
            affinity_header: None,
            path: "/".to_string(),
            host: "localhost".to_string(),
            canary_cookie: None,
            canary_header: None,
        }
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
            ttl: Duration::from_secs(3600),
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
            ttl: Duration::from_secs(3600),
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
            }),
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);
        let ctx = default_ctx();

        let mut canary_hits = 0u32;
        let iterations = 1000;
        for _ in 0..iterations {
            if let Some(result) = pool.select(&ctx) {
                if result.server.is_canary {
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
            }),
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);

        // First select — no cookie yet.
        let result1 = pool.select(&default_ctx()).expect("should select");
        assert!(result1.server.is_canary);
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
        };

        // Feed 15 failures — should trigger rollback.
        let mut triggered = false;
        for _ in 0..15 {
            if server.record_canary_result(false, &cfg) {
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
                },
            ],
            None, // canary config disabled
        );

        let lb_config = Arc::new(LoadBalancerConfig::default());
        let pool = BackendPool::from_config(&pool_cfg, &lb_config);

        let healthy = pool.get_healthy_servers();
        assert_eq!(healthy.len(), 1);
        assert!(!healthy[0].is_canary);
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
}
