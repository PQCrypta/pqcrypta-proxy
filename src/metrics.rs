//! Prometheus metrics for the proxy
//!
//! Provides comprehensive metrics for monitoring:
//! - Request/response metrics (per route, per backend)
//! - Connection pool metrics
//! - Rate limiter metrics
//! - TLS/PQC metrics
//! - System metrics

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::RwLock;
use serde::Serialize;

/// Global metrics registry
pub struct MetricsRegistry {
    /// Request metrics
    pub requests: RequestMetrics,
    /// Connection metrics
    pub connections: ConnectionMetrics,
    /// Route metrics (per-route)
    pub routes: RouteMetrics,
    /// Backend pool metrics
    pub pools: PoolMetrics,
    /// Rate limiter metrics
    pub rate_limiter: RateLimiterMetrics,
    /// TLS/PQC metrics
    pub tls: TlsMetrics,
    /// Server start time
    start_time: Instant,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            requests: RequestMetrics::new(),
            connections: ConnectionMetrics::new(),
            routes: RouteMetrics::new(),
            pools: PoolMetrics::new(),
            rate_limiter: RateLimiterMetrics::new(),
            tls: TlsMetrics::new(),
            start_time: Instant::now(),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut output = String::with_capacity(8192);

        // Server uptime
        output.push_str("# HELP pqcrypta_uptime_seconds Server uptime in seconds\n");
        output.push_str("# TYPE pqcrypta_uptime_seconds gauge\n");
        let _ = writeln!(output, "pqcrypta_uptime_seconds {}", self.uptime_secs());

        // Request metrics
        self.requests.export_prometheus(&mut output);

        // Connection metrics
        self.connections.export_prometheus(&mut output);

        // Route metrics
        self.routes.export_prometheus(&mut output);

        // Pool metrics
        self.pools.export_prometheus(&mut output);

        // Rate limiter metrics
        self.rate_limiter.export_prometheus(&mut output);

        // TLS metrics
        self.tls.export_prometheus(&mut output);

        output
    }

    /// Get metrics snapshot as JSON
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.uptime_secs(),
            requests: self.requests.snapshot(),
            connections: self.connections.snapshot(),
            routes: self.routes.snapshot(),
            pools: self.pools.snapshot(),
            rate_limiter: self.rate_limiter.snapshot(),
            tls: self.tls.snapshot(),
        }
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics snapshot for JSON serialization
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub requests: RequestMetricsSnapshot,
    pub connections: ConnectionMetricsSnapshot,
    pub routes: Vec<RouteMetricsSnapshot>,
    pub pools: Vec<PoolMetricsSnapshot>,
    pub rate_limiter: RateLimiterMetricsSnapshot,
    pub tls: TlsMetricsSnapshot,
}

// ============================================================================
// Request Metrics
// ============================================================================

/// Global request metrics
pub struct RequestMetrics {
    /// Total requests received
    total: AtomicU64,
    /// Successful requests (2xx)
    success: AtomicU64,
    /// Client errors (4xx)
    client_errors: AtomicU64,
    /// Server errors (5xx)
    server_errors: AtomicU64,
    /// Requests in progress
    in_progress: AtomicU64,
    /// Total request bytes received
    bytes_received: AtomicU64,
    /// Total response bytes sent
    bytes_sent: AtomicU64,
    /// Request latency histogram buckets (in ms)
    latency_histogram: LatencyHistogram,
}

impl RequestMetrics {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            client_errors: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            in_progress: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            latency_histogram: LatencyHistogram::new(),
        }
    }

    /// Record a request start
    pub fn request_start(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.in_progress.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request completion
    pub fn request_end(&self, status_code: u16, latency: Duration, bytes_in: u64, bytes_out: u64) {
        self.in_progress.fetch_sub(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);
        self.latency_histogram.observe(latency);

        match status_code {
            200..=299 => {
                self.success.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.client_errors.fetch_add(1, Ordering::Relaxed);
            }
            500..=599 => {
                self.server_errors.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str("# HELP pqcrypta_requests_total Total requests received\n");
        output.push_str("# TYPE pqcrypta_requests_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_requests_total {}",
            self.total.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_requests_success_total Successful requests (2xx)\n");
        output.push_str("# TYPE pqcrypta_requests_success_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_requests_success_total {}",
            self.success.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_requests_client_errors_total Client errors (4xx)\n");
        output.push_str("# TYPE pqcrypta_requests_client_errors_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_requests_client_errors_total {}",
            self.client_errors.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_requests_server_errors_total Server errors (5xx)\n");
        output.push_str("# TYPE pqcrypta_requests_server_errors_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_requests_server_errors_total {}",
            self.server_errors.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_requests_in_progress Current requests in progress\n");
        output.push_str("# TYPE pqcrypta_requests_in_progress gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_requests_in_progress {}",
            self.in_progress.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_bytes_received_total Total bytes received\n");
        output.push_str("# TYPE pqcrypta_bytes_received_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_bytes_received_total {}",
            self.bytes_received.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_bytes_sent_total Total bytes sent\n");
        output.push_str("# TYPE pqcrypta_bytes_sent_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_bytes_sent_total {}",
            self.bytes_sent.load(Ordering::Relaxed)
        );

        // Latency histogram
        self.latency_histogram
            .export_prometheus(output, "pqcrypta_request_latency_seconds");
    }

    fn snapshot(&self) -> RequestMetricsSnapshot {
        RequestMetricsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            success: self.success.load(Ordering::Relaxed),
            client_errors: self.client_errors.load(Ordering::Relaxed),
            server_errors: self.server_errors.load(Ordering::Relaxed),
            in_progress: self.in_progress.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            latency_p50_ms: self.latency_histogram.percentile(50),
            latency_p95_ms: self.latency_histogram.percentile(95),
            latency_p99_ms: self.latency_histogram.percentile(99),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestMetricsSnapshot {
    pub total: u64,
    pub success: u64,
    pub client_errors: u64,
    pub server_errors: u64,
    pub in_progress: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
}

// ============================================================================
// Connection Metrics
// ============================================================================

/// Connection metrics
pub struct ConnectionMetrics {
    /// Total connections accepted
    total: AtomicU64,
    /// Active connections
    active: AtomicU64,
    /// HTTP/3 (QUIC) connections
    http3: AtomicU64,
    /// HTTP/2 connections
    http2: AtomicU64,
    /// HTTP/1.1 connections
    http1: AtomicU64,
    /// WebTransport sessions
    webtransport: AtomicU64,
    /// TLS passthrough connections
    passthrough: AtomicU64,
    /// Failed handshakes
    handshake_failures: AtomicU64,
}

impl ConnectionMetrics {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            active: AtomicU64::new(0),
            http3: AtomicU64::new(0),
            http2: AtomicU64::new(0),
            http1: AtomicU64::new(0),
            webtransport: AtomicU64::new(0),
            passthrough: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
        }
    }

    /// Record a new connection
    pub fn connection_opened(&self, protocol: ConnectionProtocol) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);

        match protocol {
            ConnectionProtocol::Http3 => {
                self.http3.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionProtocol::Http2 => {
                self.http2.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionProtocol::Http1 => {
                self.http1.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionProtocol::WebTransport => {
                self.webtransport.fetch_add(1, Ordering::Relaxed);
            }
            ConnectionProtocol::Passthrough => {
                self.passthrough.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a connection close
    pub fn connection_closed(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Record a handshake failure
    pub fn handshake_failed(&self) {
        self.handshake_failures.fetch_add(1, Ordering::Relaxed);
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str("# HELP pqcrypta_connections_total Total connections accepted\n");
        output.push_str("# TYPE pqcrypta_connections_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_connections_total {}",
            self.total.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_connections_active Current active connections\n");
        output.push_str("# TYPE pqcrypta_connections_active gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_connections_active {}",
            self.active.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_connections_by_protocol Connections by protocol\n");
        output.push_str("# TYPE pqcrypta_connections_by_protocol counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_connections_by_protocol{{protocol=\"http3\"}} {}",
            self.http3.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "pqcrypta_connections_by_protocol{{protocol=\"http2\"}} {}",
            self.http2.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "pqcrypta_connections_by_protocol{{protocol=\"http1\"}} {}",
            self.http1.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "pqcrypta_connections_by_protocol{{protocol=\"webtransport\"}} {}",
            self.webtransport.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            output,
            "pqcrypta_connections_by_protocol{{protocol=\"passthrough\"}} {}",
            self.passthrough.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_handshake_failures_total TLS handshake failures\n");
        output.push_str("# TYPE pqcrypta_handshake_failures_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_handshake_failures_total {}",
            self.handshake_failures.load(Ordering::Relaxed)
        );
    }

    fn snapshot(&self) -> ConnectionMetricsSnapshot {
        ConnectionMetricsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            http3: self.http3.load(Ordering::Relaxed),
            http2: self.http2.load(Ordering::Relaxed),
            http1: self.http1.load(Ordering::Relaxed),
            webtransport: self.webtransport.load(Ordering::Relaxed),
            passthrough: self.passthrough.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
        }
    }
}

/// Connection protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionProtocol {
    Http3,
    Http2,
    Http1,
    WebTransport,
    Passthrough,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMetricsSnapshot {
    pub total: u64,
    pub active: u64,
    pub http3: u64,
    pub http2: u64,
    pub http1: u64,
    pub webtransport: u64,
    pub passthrough: u64,
    pub handshake_failures: u64,
}

// ============================================================================
// Route Metrics
// ============================================================================

/// Per-route metrics
pub struct RouteMetrics {
    routes: DashMap<String, RouteStats>,
}

struct RouteStats {
    requests: AtomicU64,
    success: AtomicU64,
    errors: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    latency: LatencyHistogram,
}

impl RouteMetrics {
    fn new() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }

    /// Record a request for a route
    pub fn record_request(
        &self,
        route_name: &str,
        status_code: u16,
        latency: Duration,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let stats = self
            .routes
            .entry(route_name.to_string())
            .or_insert_with(|| RouteStats {
                requests: AtomicU64::new(0),
                success: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                bytes_in: AtomicU64::new(0),
                bytes_out: AtomicU64::new(0),
                latency: LatencyHistogram::new(),
            });

        stats.requests.fetch_add(1, Ordering::Relaxed);
        stats.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        stats.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        stats.latency.observe(latency);

        if (200..400).contains(&status_code) {
            stats.success.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str("# HELP pqcrypta_route_requests_total Requests per route\n");
        output.push_str("# TYPE pqcrypta_route_requests_total counter\n");

        for entry in self.routes.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_route_requests_total{{route=\"{}\"}} {}",
                name,
                stats.requests.load(Ordering::Relaxed)
            );
        }

        output.push_str("# HELP pqcrypta_route_success_total Successful requests per route\n");
        output.push_str("# TYPE pqcrypta_route_success_total counter\n");

        for entry in self.routes.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_route_success_total{{route=\"{}\"}} {}",
                name,
                stats.success.load(Ordering::Relaxed)
            );
        }

        output.push_str("# HELP pqcrypta_route_errors_total Errors per route\n");
        output.push_str("# TYPE pqcrypta_route_errors_total counter\n");

        for entry in self.routes.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_route_errors_total{{route=\"{}\"}} {}",
                name,
                stats.errors.load(Ordering::Relaxed)
            );
        }

        output.push_str(
            "# HELP pqcrypta_route_latency_seconds_p95 95th percentile latency per route\n",
        );
        output.push_str("# TYPE pqcrypta_route_latency_seconds_p95 gauge\n");

        for entry in self.routes.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_route_latency_seconds_p95{{route=\"{}\"}} {:.6}",
                name,
                stats.latency.percentile(95) / 1000.0
            );
        }
    }

    fn snapshot(&self) -> Vec<RouteMetricsSnapshot> {
        self.routes
            .iter()
            .map(|entry| {
                let stats = entry.value();
                RouteMetricsSnapshot {
                    name: entry.key().clone(),
                    requests: stats.requests.load(Ordering::Relaxed),
                    success: stats.success.load(Ordering::Relaxed),
                    errors: stats.errors.load(Ordering::Relaxed),
                    bytes_in: stats.bytes_in.load(Ordering::Relaxed),
                    bytes_out: stats.bytes_out.load(Ordering::Relaxed),
                    latency_p50_ms: stats.latency.percentile(50),
                    latency_p95_ms: stats.latency.percentile(95),
                    latency_p99_ms: stats.latency.percentile(99),
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteMetricsSnapshot {
    pub name: String,
    pub requests: u64,
    pub success: u64,
    pub errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
}

// ============================================================================
// Pool Metrics
// ============================================================================

/// Backend pool metrics
pub struct PoolMetrics {
    pools: DashMap<String, PoolStats>,
}

struct PoolStats {
    /// Total connections to pool
    connections_total: AtomicU64,
    /// Active connections
    connections_active: AtomicU64,
    /// Idle connections
    connections_idle: AtomicU64,
    /// Connection errors
    connection_errors: AtomicU64,
    /// Requests queued
    queue_depth: AtomicU64,
    /// Requests dropped (queue full)
    queue_dropped: AtomicU64,
    /// Circuit breaker open
    circuit_open: AtomicU64,
    /// Backend latency
    latency: LatencyHistogram,
}

impl PoolMetrics {
    fn new() -> Self {
        Self {
            pools: DashMap::new(),
        }
    }

    fn get_or_create(
        &self,
        pool_name: &str,
    ) -> dashmap::mapref::one::RefMut<'_, String, PoolStats> {
        self.pools
            .entry(pool_name.to_string())
            .or_insert_with(|| PoolStats {
                connections_total: AtomicU64::new(0),
                connections_active: AtomicU64::new(0),
                connections_idle: AtomicU64::new(0),
                connection_errors: AtomicU64::new(0),
                queue_depth: AtomicU64::new(0),
                queue_dropped: AtomicU64::new(0),
                circuit_open: AtomicU64::new(0),
                latency: LatencyHistogram::new(),
            })
    }

    /// Record a new connection to pool
    pub fn connection_opened(&self, pool_name: &str) {
        let stats = self.get_or_create(pool_name);
        stats.connections_total.fetch_add(1, Ordering::Relaxed);
        stats.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    /// Record connection closed
    pub fn connection_closed(&self, pool_name: &str) {
        if let Some(stats) = self.pools.get(pool_name) {
            stats.connections_active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Record connection error
    pub fn connection_error(&self, pool_name: &str) {
        let stats = self.get_or_create(pool_name);
        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Update idle connection count
    pub fn set_idle_connections(&self, pool_name: &str, count: u64) {
        let stats = self.get_or_create(pool_name);
        stats.connections_idle.store(count, Ordering::Relaxed);
    }

    /// Update queue depth
    pub fn set_queue_depth(&self, pool_name: &str, depth: u64) {
        let stats = self.get_or_create(pool_name);
        stats.queue_depth.store(depth, Ordering::Relaxed);
    }

    /// Record request dropped from queue
    pub fn queue_dropped(&self, pool_name: &str) {
        let stats = self.get_or_create(pool_name);
        stats.queue_dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// Record circuit breaker state
    pub fn set_circuit_open(&self, pool_name: &str, open: bool) {
        let stats = self.get_or_create(pool_name);
        stats.circuit_open.store(u64::from(open), Ordering::Relaxed);
    }

    /// Record backend latency
    pub fn record_latency(&self, pool_name: &str, latency: Duration) {
        let stats = self.get_or_create(pool_name);
        stats.latency.observe(latency);
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str("# HELP pqcrypta_pool_connections_active Active connections per pool\n");
        output.push_str("# TYPE pqcrypta_pool_connections_active gauge\n");

        for entry in self.pools.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_pool_connections_active{{pool=\"{}\"}} {}",
                name,
                stats.connections_active.load(Ordering::Relaxed)
            );
        }

        output.push_str("# HELP pqcrypta_pool_connections_idle Idle connections per pool\n");
        output.push_str("# TYPE pqcrypta_pool_connections_idle gauge\n");

        for entry in self.pools.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_pool_connections_idle{{pool=\"{}\"}} {}",
                name,
                stats.connections_idle.load(Ordering::Relaxed)
            );
        }

        output
            .push_str("# HELP pqcrypta_pool_connection_errors_total Connection errors per pool\n");
        output.push_str("# TYPE pqcrypta_pool_connection_errors_total counter\n");

        for entry in self.pools.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_pool_connection_errors_total{{pool=\"{}\"}} {}",
                name,
                stats.connection_errors.load(Ordering::Relaxed)
            );
        }

        output.push_str("# HELP pqcrypta_pool_queue_depth Current queue depth per pool\n");
        output.push_str("# TYPE pqcrypta_pool_queue_depth gauge\n");

        for entry in self.pools.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_pool_queue_depth{{pool=\"{}\"}} {}",
                name,
                stats.queue_depth.load(Ordering::Relaxed)
            );
        }

        output.push_str(
            "# HELP pqcrypta_pool_circuit_open Circuit breaker state (1=open, 0=closed)\n",
        );
        output.push_str("# TYPE pqcrypta_pool_circuit_open gauge\n");

        for entry in self.pools.iter() {
            let name = entry.key();
            let stats = entry.value();
            let _ = writeln!(
                output,
                "pqcrypta_pool_circuit_open{{pool=\"{}\"}} {}",
                name,
                stats.circuit_open.load(Ordering::Relaxed)
            );
        }
    }

    fn snapshot(&self) -> Vec<PoolMetricsSnapshot> {
        self.pools
            .iter()
            .map(|entry| {
                let stats = entry.value();
                PoolMetricsSnapshot {
                    name: entry.key().clone(),
                    connections_total: stats.connections_total.load(Ordering::Relaxed),
                    connections_active: stats.connections_active.load(Ordering::Relaxed),
                    connections_idle: stats.connections_idle.load(Ordering::Relaxed),
                    connection_errors: stats.connection_errors.load(Ordering::Relaxed),
                    queue_depth: stats.queue_depth.load(Ordering::Relaxed),
                    queue_dropped: stats.queue_dropped.load(Ordering::Relaxed),
                    circuit_open: stats.circuit_open.load(Ordering::Relaxed) == 1,
                    latency_p50_ms: stats.latency.percentile(50),
                    latency_p95_ms: stats.latency.percentile(95),
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PoolMetricsSnapshot {
    pub name: String,
    pub connections_total: u64,
    pub connections_active: u64,
    pub connections_idle: u64,
    pub connection_errors: u64,
    pub queue_depth: u64,
    pub queue_dropped: u64,
    pub circuit_open: bool,
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
}

// ============================================================================
// Rate Limiter Metrics
// ============================================================================

/// Rate limiter metrics
pub struct RateLimiterMetrics {
    /// Total requests checked
    requests_checked: AtomicU64,
    /// Requests allowed
    requests_allowed: AtomicU64,
    /// Requests rate limited (429)
    requests_limited: AtomicU64,
    /// Requests blocked (by IP, fingerprint, etc.)
    requests_blocked: AtomicU64,
    /// Unique IPs seen
    unique_ips: AtomicU64,
    /// Unique fingerprints seen
    unique_fingerprints: AtomicU64,
    /// Current blocked IPs
    blocked_ips: AtomicU64,
}

impl RateLimiterMetrics {
    fn new() -> Self {
        Self {
            requests_checked: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_limited: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            unique_ips: AtomicU64::new(0),
            unique_fingerprints: AtomicU64::new(0),
            blocked_ips: AtomicU64::new(0),
        }
    }

    /// Record a rate limit check
    pub fn request_checked(&self, allowed: bool, blocked: bool) {
        self.requests_checked.fetch_add(1, Ordering::Relaxed);

        if blocked {
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
        } else if allowed {
            self.requests_allowed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_limited.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update unique IP count
    pub fn set_unique_ips(&self, count: u64) {
        self.unique_ips.store(count, Ordering::Relaxed);
    }

    /// Update unique fingerprint count
    pub fn set_unique_fingerprints(&self, count: u64) {
        self.unique_fingerprints.store(count, Ordering::Relaxed);
    }

    /// Update blocked IP count
    pub fn set_blocked_ips(&self, count: u64) {
        self.blocked_ips.store(count, Ordering::Relaxed);
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str(
            "# HELP pqcrypta_ratelimit_requests_total Total requests checked by rate limiter\n",
        );
        output.push_str("# TYPE pqcrypta_ratelimit_requests_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_requests_total {}",
            self.requests_checked.load(Ordering::Relaxed)
        );

        output
            .push_str("# HELP pqcrypta_ratelimit_allowed_total Requests allowed by rate limiter\n");
        output.push_str("# TYPE pqcrypta_ratelimit_allowed_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_allowed_total {}",
            self.requests_allowed.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ratelimit_limited_total Requests rate limited (429)\n");
        output.push_str("# TYPE pqcrypta_ratelimit_limited_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_limited_total {}",
            self.requests_limited.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ratelimit_blocked_total Requests blocked\n");
        output.push_str("# TYPE pqcrypta_ratelimit_blocked_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_blocked_total {}",
            self.requests_blocked.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ratelimit_unique_ips Unique IPs tracked\n");
        output.push_str("# TYPE pqcrypta_ratelimit_unique_ips gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_unique_ips {}",
            self.unique_ips.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ratelimit_blocked_ips Currently blocked IPs\n");
        output.push_str("# TYPE pqcrypta_ratelimit_blocked_ips gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_blocked_ips {}",
            self.blocked_ips.load(Ordering::Relaxed)
        );
    }

    fn snapshot(&self) -> RateLimiterMetricsSnapshot {
        RateLimiterMetricsSnapshot {
            requests_checked: self.requests_checked.load(Ordering::Relaxed),
            requests_allowed: self.requests_allowed.load(Ordering::Relaxed),
            requests_limited: self.requests_limited.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            unique_ips: self.unique_ips.load(Ordering::Relaxed),
            unique_fingerprints: self.unique_fingerprints.load(Ordering::Relaxed),
            blocked_ips: self.blocked_ips.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimiterMetricsSnapshot {
    pub requests_checked: u64,
    pub requests_allowed: u64,
    pub requests_limited: u64,
    pub requests_blocked: u64,
    pub unique_ips: u64,
    pub unique_fingerprints: u64,
    pub blocked_ips: u64,
}

// ============================================================================
// TLS Metrics
// ============================================================================

/// TLS and PQC metrics
pub struct TlsMetrics {
    /// Total TLS handshakes
    handshakes_total: AtomicU64,
    /// Successful TLS handshakes
    handshakes_success: AtomicU64,
    /// PQC hybrid handshakes
    pqc_handshakes: AtomicU64,
    /// Classical-only handshakes
    classical_handshakes: AtomicU64,
    /// Certificate reloads
    cert_reloads: AtomicU64,
    /// OCSP staple fetches
    ocsp_fetches: AtomicU64,
    /// OCSP fetch failures
    ocsp_failures: AtomicU64,
    /// PQC enabled flag
    pqc_enabled: RwLock<bool>,
    /// Active KEM algorithm
    active_kem: RwLock<String>,
}

impl TlsMetrics {
    fn new() -> Self {
        Self {
            handshakes_total: AtomicU64::new(0),
            handshakes_success: AtomicU64::new(0),
            pqc_handshakes: AtomicU64::new(0),
            classical_handshakes: AtomicU64::new(0),
            cert_reloads: AtomicU64::new(0),
            ocsp_fetches: AtomicU64::new(0),
            ocsp_failures: AtomicU64::new(0),
            pqc_enabled: RwLock::new(false),
            active_kem: RwLock::new("none".to_string()),
        }
    }

    /// Record a TLS handshake
    pub fn handshake_completed(&self, success: bool, pqc: bool) {
        self.handshakes_total.fetch_add(1, Ordering::Relaxed);

        if success {
            self.handshakes_success.fetch_add(1, Ordering::Relaxed);
            if pqc {
                self.pqc_handshakes.fetch_add(1, Ordering::Relaxed);
            } else {
                self.classical_handshakes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record certificate reload
    pub fn cert_reloaded(&self) {
        self.cert_reloads.fetch_add(1, Ordering::Relaxed);
    }

    /// Record OCSP fetch
    pub fn ocsp_fetched(&self, success: bool) {
        self.ocsp_fetches.fetch_add(1, Ordering::Relaxed);
        if !success {
            self.ocsp_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Update PQC status
    pub fn set_pqc_status(&self, enabled: bool, kem: &str) {
        *self.pqc_enabled.write() = enabled;
        *self.active_kem.write() = kem.to_string();
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        output.push_str("# HELP pqcrypta_tls_handshakes_total Total TLS handshakes\n");
        output.push_str("# TYPE pqcrypta_tls_handshakes_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_tls_handshakes_total {}",
            self.handshakes_total.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_tls_handshakes_success Successful TLS handshakes\n");
        output.push_str("# TYPE pqcrypta_tls_handshakes_success counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_tls_handshakes_success {}",
            self.handshakes_success.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_tls_pqc_handshakes PQC hybrid handshakes\n");
        output.push_str("# TYPE pqcrypta_tls_pqc_handshakes counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_tls_pqc_handshakes {}",
            self.pqc_handshakes.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_tls_classical_handshakes Classical-only handshakes\n");
        output.push_str("# TYPE pqcrypta_tls_classical_handshakes counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_tls_classical_handshakes {}",
            self.classical_handshakes.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_pqc_enabled PQC hybrid enabled (1=yes, 0=no)\n");
        output.push_str("# TYPE pqcrypta_pqc_enabled gauge\n");
        let enabled = i32::from(*self.pqc_enabled.read());
        let _ = writeln!(output, "pqcrypta_pqc_enabled {}", enabled);

        output.push_str("# HELP pqcrypta_cert_reloads_total Certificate reload count\n");
        output.push_str("# TYPE pqcrypta_cert_reloads_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_cert_reloads_total {}",
            self.cert_reloads.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ocsp_fetches_total OCSP staple fetch count\n");
        output.push_str("# TYPE pqcrypta_ocsp_fetches_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ocsp_fetches_total {}",
            self.ocsp_fetches.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ocsp_failures_total OCSP fetch failures\n");
        output.push_str("# TYPE pqcrypta_ocsp_failures_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_ocsp_failures_total {}",
            self.ocsp_failures.load(Ordering::Relaxed)
        );
    }

    fn snapshot(&self) -> TlsMetricsSnapshot {
        TlsMetricsSnapshot {
            handshakes_total: self.handshakes_total.load(Ordering::Relaxed),
            handshakes_success: self.handshakes_success.load(Ordering::Relaxed),
            pqc_handshakes: self.pqc_handshakes.load(Ordering::Relaxed),
            classical_handshakes: self.classical_handshakes.load(Ordering::Relaxed),
            cert_reloads: self.cert_reloads.load(Ordering::Relaxed),
            ocsp_fetches: self.ocsp_fetches.load(Ordering::Relaxed),
            ocsp_failures: self.ocsp_failures.load(Ordering::Relaxed),
            pqc_enabled: *self.pqc_enabled.read(),
            active_kem: self.active_kem.read().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsMetricsSnapshot {
    pub handshakes_total: u64,
    pub handshakes_success: u64,
    pub pqc_handshakes: u64,
    pub classical_handshakes: u64,
    pub cert_reloads: u64,
    pub ocsp_fetches: u64,
    pub ocsp_failures: u64,
    pub pqc_enabled: bool,
    pub active_kem: String,
}

// ============================================================================
// Latency Histogram
// ============================================================================

/// Simple latency histogram with fixed buckets
struct LatencyHistogram {
    /// Bucket counts (in milliseconds)
    /// Buckets: 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, +Inf
    buckets: [AtomicU64; 13],
    /// Sum of all observations (in microseconds)
    sum_us: AtomicU64,
    /// Count of all observations
    count: AtomicU64,
}

impl LatencyHistogram {
    const BUCKET_BOUNDS_MS: [u64; 12] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

    fn new() -> Self {
        Self {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, duration: Duration) {
        let ms = duration.as_millis() as u64;
        let us = duration.as_micros() as u64;

        self.sum_us.fetch_add(us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Find the right bucket
        let bucket_idx = Self::BUCKET_BOUNDS_MS
            .iter()
            .position(|&bound| ms <= bound)
            .unwrap_or(12);

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }

    fn percentile(&self, p: u32) -> f64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        let target = (total as f64 * p as f64 / 100.0).ceil() as u64;
        let mut cumulative = 0u64;

        for (i, bucket) in self.buckets.iter().enumerate() {
            cumulative += bucket.load(Ordering::Relaxed);
            if cumulative >= target {
                if i < Self::BUCKET_BOUNDS_MS.len() {
                    return Self::BUCKET_BOUNDS_MS[i] as f64;
                }
                // +Inf bucket, use sum/count as estimate
                let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1000.0;
                return sum / total as f64;
            }
        }

        0.0
    }

    fn export_prometheus(&self, output: &mut String, name: &str) {
        use std::fmt::Write;

        let _ = writeln!(output, "# HELP {} Request latency histogram", name);
        let _ = writeln!(output, "# TYPE {} histogram", name);

        let mut cumulative = 0u64;

        for (i, bound) in Self::BUCKET_BOUNDS_MS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                output,
                "{}_bucket{{le=\"{}\"}} {}",
                name,
                *bound as f64 / 1000.0,
                cumulative
            );
        }

        cumulative += self.buckets[12].load(Ordering::Relaxed);
        let _ = writeln!(output, "{}_bucket{{le=\"+Inf\"}} {}", name, cumulative);

        let sum = self.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(output, "{}_sum {:.6}", name, sum);
        let _ = writeln!(
            output,
            "{}_count {}",
            name,
            self.count.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_histogram() {
        let h = LatencyHistogram::new();

        h.observe(Duration::from_millis(5));
        h.observe(Duration::from_millis(10));
        h.observe(Duration::from_millis(50));
        h.observe(Duration::from_millis(100));
        h.observe(Duration::from_millis(500));

        assert_eq!(h.count.load(Ordering::Relaxed), 5);
        assert!(h.percentile(50) >= 10.0);
        assert!(h.percentile(99) >= 100.0);
    }

    #[test]
    fn test_request_metrics() {
        let m = RequestMetrics::new();

        m.request_start();
        m.request_end(200, Duration::from_millis(50), 100, 200);

        assert_eq!(m.total.load(Ordering::Relaxed), 1);
        assert_eq!(m.success.load(Ordering::Relaxed), 1);
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_route_metrics() {
        let m = RouteMetrics::new();

        m.record_request("api-route", 200, Duration::from_millis(25), 100, 500);
        m.record_request("api-route", 500, Duration::from_millis(100), 50, 0);

        let snapshot = m.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].requests, 2);
        assert_eq!(snapshot[0].success, 1);
        assert_eq!(snapshot[0].errors, 1);
    }

    #[test]
    fn test_pool_metrics() {
        let m = PoolMetrics::new();

        m.connection_opened("api-pool");
        m.connection_opened("api-pool");
        m.connection_closed("api-pool");
        m.connection_error("api-pool");

        let snapshot = m.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].connections_active, 1);
        assert_eq!(snapshot[0].connection_errors, 1);
    }

    #[test]
    fn test_rate_limiter_metrics() {
        let m = RateLimiterMetrics::new();

        m.request_checked(true, false); // allowed
        m.request_checked(false, false); // rate limited
        m.request_checked(false, true); // blocked

        let snapshot = m.snapshot();
        assert_eq!(snapshot.requests_checked, 3);
        assert_eq!(snapshot.requests_allowed, 1);
        assert_eq!(snapshot.requests_limited, 1);
        assert_eq!(snapshot.requests_blocked, 1);
    }

    #[test]
    fn test_metrics_registry() {
        let registry = MetricsRegistry::new();

        registry.requests.request_start();
        registry
            .requests
            .request_end(200, Duration::from_millis(50), 100, 200);
        registry
            .connections
            .connection_opened(ConnectionProtocol::Http3);

        let prometheus = registry.export_prometheus();
        assert!(prometheus.contains("pqcrypta_uptime_seconds"));
        assert!(prometheus.contains("pqcrypta_requests_total 1"));
        assert!(prometheus.contains("pqcrypta_connections_total 1"));
    }

    #[test]
    fn test_tls_metrics() {
        let m = TlsMetrics::new();

        m.handshake_completed(true, true);
        m.handshake_completed(true, false);
        m.handshake_completed(false, false);
        m.set_pqc_status(true, "X25519MLKEM768");

        let snapshot = m.snapshot();
        assert_eq!(snapshot.handshakes_total, 3);
        assert_eq!(snapshot.handshakes_success, 2);
        assert_eq!(snapshot.pqc_handshakes, 1);
        assert_eq!(snapshot.classical_handshakes, 1);
        assert!(snapshot.pqc_enabled);
        assert_eq!(snapshot.active_kem, "X25519MLKEM768");
    }
}
