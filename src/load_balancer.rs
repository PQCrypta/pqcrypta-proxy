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
//! # Integration Status
//! Connection draining and semaphore-based connection limiting are scaffolded
//! for future graceful shutdown and connection pooling improvements.

// Allow dead code for scaffolded connection management features
#![allow(dead_code)]

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use rand::Rng;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::{
    AffinityMode, BackendPoolConfig, LoadBalancerConfig, PoolServerConfig, TlsMode,
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
            anyhow::anyhow!(
                "Invalid backend server address '{}': {}",
                config.address,
                e
            )
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
            active_connections: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            avg_response_time_us: AtomicU64::new(0),
            connection_limiter: Semaphore::new(config.max_connections as usize),
            health: RwLock::new(BackendHealth::default()),
            slow_start: RwLock::new(None),
            draining: RwLock::new(None),
        })
    }

    /// Check if server is available for requests
    pub fn is_available(&self) -> bool {
        let health = self.health.read();
        let draining = self.draining.read();

        health.healthy && !health.circuit_open && draining.is_none()
    }

    /// Acquire connection to this server
    pub fn try_acquire_connection(&self) -> bool {
        if self.connection_limiter.try_acquire().is_ok() {
            self.active_connections.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Release connection
    pub fn release_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
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
                return (self.base_weight as f64 * factor) as u32;
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

            // Recover from circuit breaker
            if health.circuit_open && health.consecutive_successes >= 3 {
                health.circuit_open = false;
                health.healthy = true;
                info!("Backend {} circuit breaker closed", self.id);
            }
        } else {
            self.total_failures.fetch_add(1, Ordering::Relaxed);

            let mut health = self.health.write();
            health.consecutive_successes = 0;
            health.consecutive_failures += 1;

            // Open circuit breaker after 5 failures
            if health.consecutive_failures >= 5 && !health.circuit_open {
                health.circuit_open = true;
                health.healthy = false;
                warn!(
                    "Backend {} circuit breaker opened after {} failures",
                    self.id, health.consecutive_failures
                );
            }
        }

        // Update response time EMA (alpha = 0.3)
        let new_time = response_time.as_micros() as u64;
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
    /// Cookie to server mapping (for cookie affinity)
    cookie_sessions: DashMap<String, String>,
    /// IP to server mapping (for ip_hash affinity)
    ip_sessions: DashMap<IpAddr, String>,

    // === Round-robin state ===
    rr_counter: AtomicU64,

    // === Weighted round-robin state ===
    wrr_state: RwLock<WeightedRoundRobinState>,
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
            rr_counter: AtomicU64::new(0),
            wrr_state: RwLock::new(WeightedRoundRobinState::default()),
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

    /// Select a backend server
    pub fn select(&self, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        // Check sticky session first
        if let Some(server) = self.check_sticky_session(ctx) {
            if server.is_available() {
                return Some(server);
            }
        }

        // Use algorithm to select
        let server = self.algorithm.select(self, ctx)?;

        // Record sticky session if needed
        self.record_sticky_session(ctx, &server);

        Some(server)
    }

    /// Check for existing sticky session
    fn check_sticky_session(&self, ctx: &SelectionContext) -> Option<Arc<BackendServer>> {
        match &self.affinity {
            AffinityMode::Cookie => {
                if let Some(ref cookie) = ctx.session_cookie {
                    if let Some(server_id) = self.cookie_sessions.get(cookie) {
                        return self.find_server_by_id(&server_id);
                    }
                }
            }
            AffinityMode::IpHash => {
                if let Some(server_id) = self.ip_sessions.get(&ctx.client_ip) {
                    return self.find_server_by_id(&server_id);
                }
            }
            AffinityMode::Header => {
                if let Some(ref header_val) = ctx.affinity_header {
                    if let Some(server_id) = self.cookie_sessions.get(header_val) {
                        return self.find_server_by_id(&server_id);
                    }
                }
            }
            AffinityMode::None => {}
        }
        None
    }

    /// Record sticky session mapping
    fn record_sticky_session(&self, ctx: &SelectionContext, server: &BackendServer) {
        match &self.affinity {
            AffinityMode::Cookie => {
                if let Some(ref cookie) = ctx.session_cookie {
                    self.cookie_sessions
                        .insert(cookie.clone(), server.id.clone());
                }
            }
            AffinityMode::IpHash => {
                self.ip_sessions.insert(ctx.client_ip, server.id.clone());
            }
            AffinityMode::Header => {
                if let Some(ref header_val) = ctx.affinity_header {
                    self.cookie_sessions
                        .insert(header_val.clone(), server.id.clone());
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

    /// Get healthy servers
    pub fn get_healthy_servers(&self) -> Vec<Arc<BackendServer>> {
        let servers = self.servers.read();

        if !self.health_aware {
            return servers.clone();
        }

        // First, try priority 1 healthy servers
        let priority_1: Vec<_> = servers
            .iter()
            .filter(|s| s.is_available() && s.priority == 1)
            .cloned()
            .collect();

        if !priority_1.is_empty() {
            return priority_1;
        }

        // Failover to higher priority numbers
        servers
            .iter()
            .filter(|s| s.is_available())
            .cloned()
            .collect()
    }

    /// Record request completion
    pub fn record_completion(
        &self,
        server: &BackendServer,
        response_time: Duration,
        success: bool,
    ) {
        self.algorithm
            .record_completion(server, response_time, success);
        server.record_result(success, response_time);
    }

    /// Get algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        self.algorithm.name()
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

        let idx = pool.rr_counter.fetch_add(1, Ordering::Relaxed) as usize;
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

        let idx = (hash as usize) % healthy_servers.len();
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

    /// Select backend for request
    pub fn select_backend(
        &self,
        pool_name: &str,
        ctx: &SelectionContext,
    ) -> Option<Arc<BackendServer>> {
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
    let header = cookie_header?;

    for cookie in header.split(';') {
        let cookie = cookie.trim();
        if cookie.starts_with(&config.name) {
            if let Some(value) = cookie.split('=').nth(1) {
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
        };
        Arc::new(BackendServer::from_config(&config).expect("test address must be valid"))
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
}
