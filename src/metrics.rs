//! Prometheus metrics for the proxy
//!
//! Provides comprehensive metrics for monitoring:
//! - Request/response metrics (per route, per backend)
//! - Connection pool metrics
//! - Rate limiter metrics
//! - TLS/PQC metrics
//! - System metrics

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

/// Maximum number of recent failures to keep
const FAILURE_LOG_SIZE: usize = 100;
/// How many failing paths the per-endpoint error table follows.
const MAX_ENDPOINT_ERRORS: usize = 2048;
/// The most of a failing path that is kept, in bytes.
const MAX_ERROR_PATH_LEN: usize = 256;

/// `value` as a Prometheus label value: backslash, double quote and line
/// feed escaped (text exposition format). Route, backend and pool names come
/// from the configuration, which does not forbid them.
fn label_value(value: &str) -> std::borrow::Cow<'_, str> {
    if value.contains(['\\', '"', '\n']) {
        std::borrow::Cow::Owned(
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n"),
        )
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

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
    /// Read the gauges whose values live elsewhere (blocked addresses, the
    /// fingerprint corpus, backend load) each time the metrics are exported
    samplers: RwLock<Vec<Sampler>>,
}

/// Reads values from where they live into the registry; see
/// [`MetricsRegistry::add_sampler`].
pub type Sampler = Box<dyn Fn(&MetricsRegistry) + Send + Sync>;

/// One backend's load, as [`PoolMetrics::set_load`] takes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoolLoad {
    /// Requests that have had a place, ever
    pub total: u64,
    /// Requests in flight now
    pub active: u64,
    /// Requests waiting for a place now
    pub waiting: u64,
    /// Requests refused for want of a place, ever
    pub refused: u64,
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
            samplers: RwLock::new(Vec::new()),
        }
    }

    /// Run `sampler` before every export: it sets the gauges whose values
    /// live in another part of the proxy, so they are read as they are when
    /// scraped rather than kept up to date on every change.
    pub fn add_sampler(&self, sampler: impl Fn(&Self) + Send + Sync + 'static) {
        self.samplers.write().push(Box::new(sampler));
    }

    fn sample(&self) {
        for sampler in self.samplers.read().iter() {
            sampler(self);
        }
    }

    /// A TLS handshake that failed: counted with the handshakes and with the
    /// connections that never became one.
    pub fn handshake_failed(&self) {
        self.tls.handshake_completed(false, false);
        self.connections.handshake_failed();
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Export metrics in Prometheus text format
    pub fn export_prometheus(&self) -> String {
        use std::fmt::Write;
        self.sample();
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

        // The process's memory against its cgroup's limits
        export_memory(&mut output, &crate::memory_pressure::snapshot());

        output
    }

    /// Return the current active connection count without a full snapshot allocation.
    ///
    /// SEC-A06: Used by the graceful-shutdown drain loop so it can exit early
    /// once all in-flight connections have closed instead of always sleeping for
    /// the full graceful_shutdown_timeout_secs duration.
    pub fn active_connections(&self) -> u64 {
        self.connections
            .counters
            .active
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get metrics snapshot as JSON
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.sample();
        MetricsSnapshot {
            uptime_secs: self.uptime_secs(),
            requests: self.requests.snapshot(),
            connections: self.connections.snapshot(),
            routes: self.routes.snapshot(),
            pools: self.pools.snapshot(),
            rate_limiter: self.rate_limiter.snapshot(),
            tls: self.tls.snapshot(),
            memory: crate::memory_pressure::snapshot(),
        }
    }
}

/// `pqcrypta_memory_*`: what [`crate::memory_pressure`] reads and does.
fn export_memory(output: &mut String, memory: &crate::memory_pressure::MemorySnapshot) {
    use std::fmt::Write;
    if !memory.watched {
        return;
    }
    let mut gauge = |name: &str, help: &str, value: String| {
        let _ = writeln!(output, "# HELP {name} {help}");
        let _ = writeln!(output, "# TYPE {name} gauge");
        let _ = writeln!(output, "{name} {value}");
    };
    gauge(
        "pqcrypta_memory_pressure_level",
        "How short memory is: 0 normal, 1 elevated, 2 critical",
        (memory.level as u8).to_string(),
    );
    gauge(
        "pqcrypta_memory_working_set_bytes",
        "Anonymous, unreclaimable kernel and socket memory of the process's cgroup",
        memory.working_set_bytes.to_string(),
    );
    gauge(
        "pqcrypta_memory_stalled_percent",
        "Share of the last 10 s the process was stalled on memory",
        memory.stalled_percent.to_string(),
    );
    for (name, help, value) in [
        (
            "pqcrypta_memory_high_bytes",
            "The cgroup's memory.high",
            memory.high_bytes,
        ),
        (
            "pqcrypta_memory_max_bytes",
            "The cgroup's memory.max",
            memory.max_bytes,
        ),
    ] {
        if let Some(value) = value {
            gauge(name, help, value.to_string());
        }
    }
    for (name, help, value) in [
        (
            "pqcrypta_memory_refused_connections_total",
            "Connections refused because memory was critically short",
            memory.refused_connections,
        ),
        (
            "pqcrypta_memory_shed_connections_total",
            "Idle connections closed because memory was short",
            memory.shed_connections,
        ),
    ] {
        let _ = writeln!(output, "# HELP {name} {help}");
        let _ = writeln!(output, "# TYPE {name} counter");
        let _ = writeln!(output, "{name} {value}");
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
    pub memory: crate::memory_pressure::MemorySnapshot,
}

// ============================================================================
// Request Metrics
// ============================================================================

/// A single failure entry with timestamp, path, and status code
#[derive(Debug, Clone, Serialize)]
pub struct FailureEntry {
    /// Unix timestamp in milliseconds
    pub ts: i64,
    /// Request path
    pub path: String,
    /// HTTP status code
    pub status: u16,
}

/// Per-endpoint error tracking (count + last status + last seen)
#[derive(Debug, Clone)]
struct EndpointErrorInfo {
    count: u64,
    last_status: u16,
    last_seen_ms: i64,
}

/// Per-endpoint error count snapshot
#[derive(Debug, Clone, Serialize)]
pub struct EndpointErrorEntry {
    pub path: String,
    pub count: u64,
    /// "client" (4xx) or "server" (5xx)
    pub error_type: String,
    pub last_status: u16,
    pub last_seen: i64,
}

/// One request counted in progress, from [`RequestMetrics::request_start`]
/// until this is dropped
#[must_use = "the request stops counting as in progress when this is dropped"]
pub struct InProgress(Arc<AtomicU64>);

impl Drop for InProgress {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

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
    /// Requests in progress: each request's [`InProgress`] holds one
    in_progress: Arc<AtomicU64>,
    /// Total request bytes received
    bytes_received: AtomicU64,
    /// Total response bytes sent
    bytes_sent: AtomicU64,
    /// Request latency histogram buckets (in ms)
    latency_histogram: LatencyHistogram,
    /// Per-endpoint error tracking keyed by "path\0error_type"
    endpoint_errors: Mutex<HashMap<String, EndpointErrorInfo>>,
    /// Recent failure log (ring buffer)
    failure_log: Mutex<std::collections::VecDeque<FailureEntry>>,
}

impl RequestMetrics {
    fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            success: AtomicU64::new(0),
            client_errors: AtomicU64::new(0),
            server_errors: AtomicU64::new(0),
            in_progress: Arc::new(AtomicU64::new(0)),
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            latency_histogram: LatencyHistogram::new(),
            endpoint_errors: Mutex::new(HashMap::new()),
            failure_log: Mutex::new(std::collections::VecDeque::with_capacity(FAILURE_LOG_SIZE)),
        }
    }

    /// Record a request start. The request counts as in progress until the
    /// returned guard is dropped, which a handler does on every way out of it:
    /// each return, an error, and a client resetting the stream, which drops
    /// the handler's future part way through. The count used to fall in
    /// `request_end_full`, which those last ways out never reached: it only
    /// grew between restarts (to 8000 on a node with a dozen requests open).
    pub fn request_start(&self) -> InProgress {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.in_progress.fetch_add(1, Ordering::Relaxed);
        InProgress(Arc::clone(&self.in_progress))
    }

    /// Record a request completion with full control over error tracking.
    /// Every request counts: the health checks call the API directly, not
    /// through the proxy, and a client's `x-health-check-bypass` is stripped
    /// (it used to let anyone keep requests out of these figures).
    pub fn request_end_full(
        &self,
        status_code: u16,
        latency: Duration,
        bytes_in: u64,
        bytes_out: u64,
        path: Option<&str>,
    ) {
        self.bytes_received.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);
        self.latency_histogram.observe(latency);

        match status_code {
            200..=299 => {
                self.success.fetch_add(1, Ordering::Relaxed);
            }
            400..=499 => {
                self.client_errors.fetch_add(1, Ordering::Relaxed);
                if let Some(p) = path {
                    self.record_failure(p, status_code);
                }
            }
            500..=599 => {
                self.server_errors.fetch_add(1, Ordering::Relaxed);
                if let Some(p) = path {
                    self.record_failure(p, status_code);
                }
            }
            _ => {}
        }
    }

    /// Record a failure entry for error tracking
    fn record_failure(&self, path: &str, status_code: u16) {
        let normalized = normalize_path(path);
        let error_type = if status_code < 500 {
            "client"
        } else {
            "server"
        };
        // A path is the client's to choose: what is kept of one is bounded.
        let normalized = bounded_path(normalized);
        // Update per-endpoint error tracking keyed by "path\0error_type"
        let key = format!("{}\0{}", normalized, error_type);
        let ts = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(i64::MAX);
        {
            let mut map = self.endpoint_errors.lock();
            // The table holds the MAX_ENDPOINT_ERRORS paths that fail most
            // (Space-Saving, Metwally et al. 2005): a path not in a full table
            // takes the place of the one with the fewest failures and starts
            // from that count, so a path that really is failing often is
            // never pushed out by ones that each fail once.
            let mut floor = 0;
            if !map.contains_key(&key) && map.len() >= MAX_ENDPOINT_ERRORS {
                let least = map
                    .iter()
                    .min_by_key(|(_, info)| info.count)
                    .map(|(k, info)| (k.clone(), info.count));
                if let Some((least_key, least_count)) = least {
                    map.remove(&least_key);
                    floor = least_count;
                }
            }
            let info = map.entry(key).or_insert(EndpointErrorInfo {
                count: floor,
                last_status: 0,
                last_seen_ms: 0,
            });
            info.count += 1;
            info.last_status = status_code;
            info.last_seen_ms = ts;
        }
        // Add to failure log ring buffer
        let entry = FailureEntry {
            ts,
            path: normalized,
            status: status_code,
        };
        let mut log = self.failure_log.lock();
        if log.len() >= FAILURE_LOG_SIZE {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Get per-endpoint error counts sorted by count descending, optionally filtered by type
    pub fn endpoint_error_counts_filtered(
        &self,
        filter_type: Option<&str>,
    ) -> Vec<EndpointErrorEntry> {
        let map = self.endpoint_errors.lock();
        let mut entries: Vec<EndpointErrorEntry> = map
            .iter()
            .filter_map(|(k, v)| {
                let parts: Vec<&str> = k.splitn(2, '\0').collect();
                let path = parts[0].to_string();
                let error_type = (*parts.get(1).unwrap_or(&"client")).to_string();
                if let Some(ft) = filter_type {
                    if error_type != ft {
                        return None;
                    }
                }
                Some(EndpointErrorEntry {
                    path,
                    count: v.count,
                    error_type,
                    last_status: v.last_status,
                    last_seen: v.last_seen_ms,
                })
            })
            .collect();
        entries.sort_by_key(|b| std::cmp::Reverse(b.count));
        entries
    }

    /// Get per-endpoint error counts sorted by count descending (all types)
    pub fn endpoint_error_counts(&self) -> Vec<EndpointErrorEntry> {
        self.endpoint_error_counts_filtered(None)
    }

    /// Get recent failure log entries
    pub fn recent_failures(&self) -> Vec<FailureEntry> {
        self.failure_log.lock().iter().cloned().collect()
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
            endpoint_errors: self.endpoint_error_counts(),
            recent_failures: self.recent_failures(),
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
    pub endpoint_errors: Vec<EndpointErrorEntry>,
    pub recent_failures: Vec<FailureEntry>,
}

// ============================================================================
// Connection Metrics
// ============================================================================

/// Connection metrics
pub struct ConnectionMetrics {
    counters: Arc<ConnectionCounters>,
}

/// The counts behind [`ConnectionMetrics`], shared with every
/// [`OpenConnection`] so a connection is counted closed wherever it ends.
#[derive(Default)]
struct ConnectionCounters {
    /// Connections accepted, all protocols
    total: AtomicU64,
    /// Open now, all protocols
    active: AtomicU64,
    /// Accepted, by protocol (`ConnectionProtocol::index`)
    opened: [AtomicU64; ConnectionProtocol::ALL.len()],
    /// Open now, by protocol
    open: [AtomicU64; ConnectionProtocol::ALL.len()],
    /// Failed handshakes
    handshake_failures: AtomicU64,
}

/// One open connection or session, counted closed when dropped: hold it for
/// as long as the connection lasts.
#[must_use = "the connection is counted open only while this is held"]
pub struct OpenConnection {
    counters: Arc<ConnectionCounters>,
    protocol: usize,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
        self.counters.open[self.protocol].fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConnectionMetrics {
    fn new() -> Self {
        Self {
            counters: Arc::new(ConnectionCounters::default()),
        }
    }

    /// Count a connection (or session) open until the returned guard drops.
    pub fn connection_opened(&self, protocol: ConnectionProtocol) -> OpenConnection {
        let c = &self.counters;
        let i = protocol.index();
        c.total.fetch_add(1, Ordering::Relaxed);
        c.active.fetch_add(1, Ordering::Relaxed);
        c.opened[i].fetch_add(1, Ordering::Relaxed);
        c.open[i].fetch_add(1, Ordering::Relaxed);
        OpenConnection {
            counters: Arc::clone(c),
            protocol: i,
        }
    }

    /// Record a handshake failure
    pub fn handshake_failed(&self) {
        self.counters
            .handshake_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;
        let c = &self.counters;

        output.push_str("# HELP pqcrypta_connections_total Total connections accepted\n");
        output.push_str("# TYPE pqcrypta_connections_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_connections_total {}",
            c.total.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_connections_active Current active connections\n");
        output.push_str("# TYPE pqcrypta_connections_active gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_connections_active {}",
            c.active.load(Ordering::Relaxed)
        );

        output.push_str(
            "# HELP pqcrypta_connections_by_protocol Connections accepted, by protocol\n",
        );
        output.push_str("# TYPE pqcrypta_connections_by_protocol counter\n");
        for protocol in ConnectionProtocol::ALL {
            let _ = writeln!(
                output,
                "pqcrypta_connections_by_protocol{{protocol=\"{}\"}} {}",
                protocol.label(),
                c.opened[protocol.index()].load(Ordering::Relaxed)
            );
        }

        output.push_str(
            "# HELP pqcrypta_connections_open_by_protocol Connections open now, by protocol\n",
        );
        output.push_str("# TYPE pqcrypta_connections_open_by_protocol gauge\n");
        for protocol in ConnectionProtocol::ALL {
            let _ = writeln!(
                output,
                "pqcrypta_connections_open_by_protocol{{protocol=\"{}\"}} {}",
                protocol.label(),
                c.open[protocol.index()].load(Ordering::Relaxed)
            );
        }

        output.push_str("# HELP pqcrypta_handshake_failures_total TLS handshake failures\n");
        output.push_str("# TYPE pqcrypta_handshake_failures_total counter\n");
        let _ = writeln!(
            output,
            "pqcrypta_handshake_failures_total {}",
            c.handshake_failures.load(Ordering::Relaxed)
        );
    }

    fn snapshot(&self) -> ConnectionMetricsSnapshot {
        let c = &self.counters;
        let opened = |p: ConnectionProtocol| c.opened[p.index()].load(Ordering::Relaxed);
        let open = |p: ConnectionProtocol| c.open[p.index()].load(Ordering::Relaxed);
        ConnectionMetricsSnapshot {
            total: c.total.load(Ordering::Relaxed),
            active: c.active.load(Ordering::Relaxed),
            http3: opened(ConnectionProtocol::Http3),
            http2: opened(ConnectionProtocol::Http2),
            http1: opened(ConnectionProtocol::Http1),
            webtransport: opened(ConnectionProtocol::WebTransport),
            connect_udp: opened(ConnectionProtocol::ConnectUdp),
            passthrough: opened(ConnectionProtocol::Passthrough),
            open_http3: open(ConnectionProtocol::Http3),
            open_http2: open(ConnectionProtocol::Http2),
            open_http1: open(ConnectionProtocol::Http1),
            open_webtransport: open(ConnectionProtocol::WebTransport),
            open_connect_udp: open(ConnectionProtocol::ConnectUdp),
            open_passthrough: open(ConnectionProtocol::Passthrough),
            handshake_failures: c.handshake_failures.load(Ordering::Relaxed),
        }
    }
}

/// Connection protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionProtocol {
    Http3,
    Http2,
    Http1,
    /// A WebTransport session
    WebTransport,
    /// A CONNECT-UDP (MASQUE) session
    ConnectUdp,
    Passthrough,
}

impl ConnectionProtocol {
    pub const ALL: [Self; 6] = [
        Self::Http3,
        Self::Http2,
        Self::Http1,
        Self::WebTransport,
        Self::ConnectUdp,
        Self::Passthrough,
    ];

    const fn index(self) -> usize {
        match self {
            Self::Http3 => 0,
            Self::Http2 => 1,
            Self::Http1 => 2,
            Self::WebTransport => 3,
            Self::ConnectUdp => 4,
            Self::Passthrough => 5,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Http3 => "http3",
            Self::Http2 => "http2",
            Self::Http1 => "http1",
            Self::WebTransport => "webtransport",
            Self::ConnectUdp => "connect_udp",
            Self::Passthrough => "passthrough",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMetricsSnapshot {
    /// Accepted, all protocols
    pub total: u64,
    /// Open now, all protocols
    pub active: u64,
    /// Accepted, by protocol
    pub http3: u64,
    pub http2: u64,
    pub http1: u64,
    pub webtransport: u64,
    pub connect_udp: u64,
    pub passthrough: u64,
    /// Open now, by protocol
    pub open_http3: u64,
    pub open_http2: u64,
    pub open_http1: u64,
    pub open_webtransport: u64,
    pub open_connect_udp: u64,
    pub open_passthrough: u64,
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
            let name = label_value(entry.key());
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
            let name = label_value(entry.key());
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
            let name = label_value(entry.key());
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
            let name = label_value(entry.key());
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

/// Backend metrics: one series per named backend, load-balancer pool member
/// (by its address) and load-balancer pool (its queue and breakers).
pub struct PoolMetrics {
    pools: DashMap<String, PoolStats>,
}

struct PoolStats {
    /// Requests that have had a place on the backend, ever
    connections_total: AtomicU64,
    /// Requests in flight on it now
    connections_active: AtomicU64,
    /// Idle connections the backend client holds for it
    connections_idle: AtomicU64,
    /// Requests the backend did not answer (connect, send or timeout)
    connection_errors: AtomicU64,
    /// Requests waiting for a place now
    queue_depth: AtomicU64,
    /// Requests refused for want of a place, ever
    queue_dropped: AtomicU64,
    /// Breakers open: 0 or 1 for a backend, its members' for a pool
    circuit_open: AtomicU64,
    /// Time to the backend's response head
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
        if let Some(stats) = self.pools.get_mut(pool_name) {
            return stats;
        }
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

    /// A request the backend did not answer
    pub fn connection_error(&self, pool_name: &str) {
        let stats = self.get_or_create(pool_name);
        stats.connection_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Idle connections held for the backend now
    pub fn set_idle_connections(&self, pool_name: &str, count: u64) {
        let stats = self.get_or_create(pool_name);
        stats.connections_idle.store(count, Ordering::Relaxed);
    }

    /// The backend's places: had, in flight, waiting, refused
    pub fn set_load(&self, pool_name: &str, load: PoolLoad) {
        let stats = self.get_or_create(pool_name);
        stats.connections_total.store(load.total, Ordering::Relaxed);
        stats
            .connections_active
            .store(load.active, Ordering::Relaxed);
        stats.queue_depth.store(load.waiting, Ordering::Relaxed);
        stats.queue_dropped.store(load.refused, Ordering::Relaxed);
    }

    /// Breakers open now
    pub fn set_circuit_open(&self, pool_name: &str, open: u64) {
        let stats = self.get_or_create(pool_name);
        stats.circuit_open.store(open, Ordering::Relaxed);
    }

    /// Time to the backend's response head
    pub fn record_latency(&self, pool_name: &str, latency: Duration) {
        let stats = self.get_or_create(pool_name);
        stats.latency.observe(latency);
    }

    fn export_prometheus(&self, output: &mut String) {
        use std::fmt::Write;

        type Field = fn(&PoolStats) -> u64;
        let series: [(&str, &str, &str, Field); 7] = [
            (
                "pqcrypta_pool_connections_total",
                "counter",
                "Requests that have had a place on the backend",
                |s| s.connections_total.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_connections_active",
                "gauge",
                "Requests in flight on the backend",
                |s| s.connections_active.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_connections_idle",
                "gauge",
                "Idle connections held for the backend",
                |s| s.connections_idle.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_connection_errors_total",
                "counter",
                "Requests the backend did not answer",
                |s| s.connection_errors.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_queue_depth",
                "gauge",
                "Requests waiting for a place on the backend",
                |s| s.queue_depth.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_queue_dropped_total",
                "counter",
                "Requests refused for want of a place on the backend",
                |s| s.queue_dropped.load(Ordering::Relaxed),
            ),
            (
                "pqcrypta_pool_circuit_open",
                "gauge",
                "Circuit breakers open (a backend: 0 or 1; a pool: its members')",
                |s| s.circuit_open.load(Ordering::Relaxed),
            ),
        ];
        for (name, kind, help, field) in series {
            let _ = writeln!(output, "# HELP {name} {help}");
            let _ = writeln!(output, "# TYPE {name} {kind}");
            for entry in self.pools.iter() {
                let _ = writeln!(
                    output,
                    "{name}{{pool=\"{}\"}} {}",
                    label_value(entry.key()),
                    field(entry.value())
                );
            }
        }

        let name = "pqcrypta_pool_latency_seconds";
        let _ = writeln!(output, "# HELP {name} Time to the backend's response head");
        let _ = writeln!(output, "# TYPE {name} histogram");
        for entry in self.pools.iter() {
            let labels = format!("pool=\"{}\"", label_value(entry.key()));
            entry.value().latency.write_series(output, name, &labels);
        }
    }

    fn snapshot(&self) -> Vec<PoolMetricsSnapshot> {
        self.pools
            .iter()
            .map(|entry| {
                let stats = entry.value();
                let circuit_open = stats.circuit_open.load(Ordering::Relaxed);
                PoolMetricsSnapshot {
                    name: entry.key().clone(),
                    connections_total: stats.connections_total.load(Ordering::Relaxed),
                    connections_active: stats.connections_active.load(Ordering::Relaxed),
                    connections_idle: stats.connections_idle.load(Ordering::Relaxed),
                    connection_errors: stats.connection_errors.load(Ordering::Relaxed),
                    queue_depth: stats.queue_depth.load(Ordering::Relaxed),
                    queue_dropped: stats.queue_dropped.load(Ordering::Relaxed),
                    circuit_open: circuit_open > 0,
                    circuits_open: circuit_open,
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
    /// Breakers open: 0 or 1 for a backend, its members' for a pool
    pub circuits_open: u64,
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

        output.push_str(
            "# HELP pqcrypta_ratelimit_unique_ips Client addresses with a live request counter\n",
        );
        output.push_str("# TYPE pqcrypta_ratelimit_unique_ips gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_unique_ips {}",
            self.unique_ips.load(Ordering::Relaxed)
        );

        output.push_str(
            "# HELP pqcrypta_ratelimit_unique_fingerprints TLS fingerprints the corpus holds\n",
        );
        output.push_str("# TYPE pqcrypta_ratelimit_unique_fingerprints gauge\n");
        let _ = writeln!(
            output,
            "pqcrypta_ratelimit_unique_fingerprints {}",
            self.unique_fingerprints.load(Ordering::Relaxed)
        );

        output.push_str("# HELP pqcrypta_ratelimit_blocked_ips Addresses and ranges blocked now\n");
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

    /// Certificate reloads that succeeded, as the TLS provider counts them
    pub fn set_cert_reloads(&self, reloads: u64) {
        self.cert_reloads.store(reloads, Ordering::Relaxed);
    }

    /// OCSP responses fetched and how many of those fetches failed, as the
    /// OCSP service counts them
    pub fn set_ocsp_fetches(&self, fetches: u64, failures: u64) {
        self.ocsp_fetches.store(fetches, Ordering::Relaxed);
        self.ocsp_failures.store(failures, Ordering::Relaxed);
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
// Latency Histogram (Sliding Window)
// ============================================================================

/// Rotation interval: every 150 seconds (2.5 minutes).
/// Two slots together give 2.5–5 minutes of recent data.
const ROTATION_INTERVAL_SECS: u64 = 150;

/// Number of histogram buckets (bounds + 1 for +Inf).
const NUM_BUCKETS: usize = 19;

/// A single histogram slot with atomic bucket counters.
struct HistogramSlot {
    /// Bucket counts — one per bound plus +Inf
    buckets: [AtomicU64; NUM_BUCKETS],
    /// Sum of all observations (in microseconds)
    sum_us: AtomicU64,
    /// Count of all observations
    count: AtomicU64,
}

impl HistogramSlot {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, duration: Duration) {
        let ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let us = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);

        self.sum_us.fetch_add(us, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        let bucket_idx = LatencyHistogram::BUCKET_BOUNDS_MS
            .iter()
            .position(|&bound| ms <= bound)
            .unwrap_or(NUM_BUCKETS - 1);

        self.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }

    fn reset(&self) {
        for bucket in &self.buckets {
            bucket.store(0, Ordering::Relaxed);
        }
        self.sum_us.store(0, Ordering::Relaxed);
        self.count.store(0, Ordering::Relaxed);
    }
}

/// Sliding-window latency histogram using double-buffered slots.
///
/// Every `ROTATION_INTERVAL_SECS` the active slot swaps and the newly
/// active slot is reset.  Percentiles are computed by merging both slots,
/// giving a window of approximately 2.5–5 minutes of recent data instead
/// of cumulative lifetime statistics.
struct LatencyHistogram {
    slots: [HistogramSlot; 2],
    /// Which slot is currently active (0 or 1)
    active: AtomicU64,
    /// Unix-epoch seconds of last rotation
    last_rotate: AtomicU64,
    /// Cumulative totals (for Prometheus export only — never reset)
    cumulative_count: AtomicU64,
    cumulative_sum_us: AtomicU64,
}

impl LatencyHistogram {
    /// Finer-grained bucket boundaries for accurate percentile interpolation.
    /// 18 bounds + 1 overflow = 19 buckets total.
    const BUCKET_BOUNDS_MS: [u64; 18] = [
        1, 5, 10, 25, 50, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 2500, 5000, 10000, 30000,
    ];

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn new() -> Self {
        Self {
            slots: [HistogramSlot::new(), HistogramSlot::new()],
            active: AtomicU64::new(0),
            last_rotate: AtomicU64::new(Self::now_secs()),
            cumulative_count: AtomicU64::new(0),
            cumulative_sum_us: AtomicU64::new(0),
        }
    }

    /// Rotate slots if enough time has elapsed. Only one thread performs the
    /// swap thanks to compare_exchange on `last_rotate`.
    fn maybe_rotate(&self) {
        let now = Self::now_secs();
        let last = self.last_rotate.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= ROTATION_INTERVAL_SECS {
            if self
                .last_rotate
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                let old =
                    usize::try_from(self.active.load(Ordering::Relaxed)).unwrap_or(usize::MAX);
                let new_slot = 1 - old;
                // Reset the slot we're about to make active
                self.slots[new_slot].reset();
                self.active.store(new_slot as u64, Ordering::Release);
            }
        }
    }

    fn observe(&self, duration: Duration) {
        self.maybe_rotate();
        let slot = usize::try_from(self.active.load(Ordering::Relaxed)).unwrap_or(usize::MAX);
        self.slots[slot].observe(duration);

        // Keep cumulative totals for Prometheus histogram export
        self.cumulative_count.fetch_add(1, Ordering::Relaxed);
        self.cumulative_sum_us.fetch_add(
            u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Compute a percentile from the merged recent window (both slots)
    /// using Prometheus-style linear interpolation within buckets for
    /// accurate sub-bucket estimates.
    // Prometheus gauge values are f64; precision loss on large counter values is acceptable.
    #[expect(clippy::cast_precision_loss)]
    fn percentile(&self, p: u32) -> f64 {
        let s0 = &self.slots[0];
        let s1 = &self.slots[1];

        let total = s0.count.load(Ordering::Relaxed) + s1.count.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }

        // Merge bucket counts from both slots
        let mut merged = [0u64; NUM_BUCKETS];
        for (bucket, (b0, b1)) in merged
            .iter_mut()
            .zip(s0.buckets.iter().zip(s1.buckets.iter()))
        {
            *bucket = b0.load(Ordering::Relaxed) + b1.load(Ordering::Relaxed);
        }

        // Target rank (fractional for interpolation)
        let rank = total as f64 * p as f64 / 100.0;
        let mut cumulative = 0u64;

        for (i, &bucket_val) in merged.iter().enumerate() {
            let prev_cum = cumulative;
            cumulative += bucket_val;

            if cumulative as f64 >= rank {
                if i >= Self::BUCKET_BOUNDS_MS.len() {
                    // +Inf bucket — estimate from sum/count
                    let sum = (s0.sum_us.load(Ordering::Relaxed)
                        + s1.sum_us.load(Ordering::Relaxed)) as f64
                        / 1000.0;
                    return sum / total as f64;
                }

                let upper = Self::BUCKET_BOUNDS_MS[i] as f64;
                let lower = if i == 0 {
                    0.0
                } else {
                    Self::BUCKET_BOUNDS_MS[i - 1] as f64
                };
                let bucket_count = bucket_val as f64;

                if bucket_count == 0.0 {
                    return upper;
                }

                // Linear interpolation: how far into this bucket does the
                // target rank fall?
                let fraction = (rank - prev_cum as f64) / bucket_count;
                return (upper - lower).mul_add(fraction, lower);
            }
        }

        0.0
    }

    /// Export windowed histogram in Prometheus format.
    fn export_prometheus(&self, output: &mut String, name: &str) {
        use std::fmt::Write;

        let _ = writeln!(output, "# HELP {} Request latency histogram", name);
        let _ = writeln!(output, "# TYPE {} histogram", name);
        self.write_series(output, name, "");
    }

    /// The histogram's buckets, sum and count, each with `labels` (written
    /// inside the braces, before `le`; empty for none).
    #[expect(clippy::cast_precision_loss)]
    fn write_series(&self, output: &mut String, name: &str, labels: &str) {
        use std::fmt::Write;

        let sep = if labels.is_empty() { "" } else { "," };
        let braces = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let s0 = &self.slots[0];
        let s1 = &self.slots[1];
        let mut cum = 0u64;
        let num_bounds = Self::BUCKET_BOUNDS_MS.len();

        for (i, bound) in Self::BUCKET_BOUNDS_MS.iter().enumerate() {
            cum += s0.buckets[i].load(Ordering::Relaxed) + s1.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                output,
                "{name}_bucket{{{labels}{sep}le=\"{}\"}} {cum}",
                *bound as f64 / 1000.0,
            );
        }

        // +Inf bucket (last index)
        cum += s0.buckets[num_bounds].load(Ordering::Relaxed)
            + s1.buckets[num_bounds].load(Ordering::Relaxed);
        let _ = writeln!(output, "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {cum}");

        let sum = self.cumulative_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(output, "{name}_sum{braces} {sum:.6}");
        let _ = writeln!(
            output,
            "{name}_count{braces} {}",
            self.cumulative_count.load(Ordering::Relaxed)
        );
    }
}

/// Normalize a request path for grouping: strip query strings and collapse
/// UUIDs/numeric IDs to placeholders so `/keys/abc-123` groups as `/keys/{id}`.
/// `path` cut to [`MAX_ERROR_PATH_LEN`] bytes, on a character boundary.
fn bounded_path(mut path: String) -> String {
    if path.len() > MAX_ERROR_PATH_LEN {
        let mut end = MAX_ERROR_PATH_LEN;
        while !path.is_char_boundary(end) {
            end -= 1;
        }
        path.truncate(end);
    }
    path
}

fn normalize_path(path: &str) -> String {
    let base = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = base.split('/').collect();
    let normalized: Vec<String> = segments
        .iter()
        .map(|s| {
            if (s.len() > 8 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
                || (!s.is_empty() && s.parse::<u64>().is_ok())
            {
                "{id}".to_string()
            } else {
                (*s).to_string()
            }
        })
        .collect();
    normalized.join("/")
}

#[cfg(test)]
mod tests {
    /// A connection is counted open by protocol while its guard is held, and
    /// closed when it drops however it ends; CONNECT-UDP is its own protocol.
    #[test]
    fn open_connections_are_counted_by_protocol_until_they_close() {
        let m = ConnectionMetrics::new();
        let h3 = m.connection_opened(ConnectionProtocol::Http3);
        let udp = m.connection_opened(ConnectionProtocol::ConnectUdp);
        let s = m.snapshot();
        assert_eq!((s.active, s.open_http3, s.open_connect_udp), (2, 1, 1));
        assert_eq!(s.open_webtransport, 0);
        drop(h3);
        let s = m.snapshot();
        assert_eq!((s.active, s.open_http3, s.http3), (1, 0, 1));
        drop(udp);
        let s = m.snapshot();
        assert_eq!((s.active, s.total, s.connect_udp), (0, 2, 1));
        let mut text = String::new();
        m.export_prometheus(&mut text);
        assert!(text.contains("pqcrypta_connections_open_by_protocol{protocol=\"connect_udp\"} 0"));
    }

    use super::*;

    #[test]
    fn test_latency_histogram() {
        let h = LatencyHistogram::new();

        h.observe(Duration::from_millis(5));
        h.observe(Duration::from_millis(10));
        h.observe(Duration::from_millis(50));
        h.observe(Duration::from_millis(100));
        h.observe(Duration::from_millis(500));

        assert_eq!(h.cumulative_count.load(Ordering::Relaxed), 5);
        assert!(h.percentile(50) >= 10.0);
        assert!(h.percentile(99) >= 100.0);
    }

    /// The failing-path table is bounded, and a path that fails often stays
    /// in it through any number of paths that fail once.
    #[test]
    fn the_failing_path_table_is_bounded_and_keeps_what_fails_most() {
        let m = RequestMetrics::new();
        for _ in 0..50 {
            m.request_end_full(500, Duration::from_millis(1), 0, 0, Some("/checkout"));
        }
        for n in 0..(MAX_ENDPOINT_ERRORS * 3) {
            let path = format!("/probe-{n}-{}", "x".repeat(1000));
            m.request_end_full(404, Duration::from_millis(1), 0, 0, Some(&path));
        }
        let table = m.endpoint_error_counts();
        assert!(
            table.len() <= MAX_ENDPOINT_ERRORS,
            "{} entries",
            table.len()
        );
        assert!(table.iter().all(|e| e.path.len() <= MAX_ERROR_PATH_LEN));
        assert!(
            table.iter().any(|e| e.path == "/checkout" && e.count >= 50),
            "the path that fails most was pushed out"
        );
        assert_eq!(m.recent_failures().len(), FAILURE_LOG_SIZE);
    }

    #[test]
    fn test_request_metrics() {
        let m = RequestMetrics::new();

        let request = m.request_start();
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 1);
        m.request_end_full(200, Duration::from_millis(50), 100, 200, None);
        drop(request);

        assert_eq!(m.total.load(Ordering::Relaxed), 1);
        assert_eq!(m.success.load(Ordering::Relaxed), 1);
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_request_that_never_ends_stops_counting_when_dropped() {
        let m = RequestMetrics::new();
        let finished = m.request_start();
        let abandoned = m.request_start();
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 2);
        m.request_end_full(200, Duration::from_millis(5), 0, 0, None);
        drop(finished);
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 1);
        // A handler's future dropped part way (the client reset the stream):
        // no request_end_full, and the count still falls
        drop(abandoned);
        assert_eq!(m.in_progress.load(Ordering::Relaxed), 0);
        assert_eq!(m.total.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_failure_tracking() {
        let m = RequestMetrics::new();

        let _request = m.request_start();
        m.request_end_full(404, Duration::from_millis(10), 0, 0, Some("/api/encrypt"));
        let _request = m.request_start();
        m.request_end_full(500, Duration::from_millis(20), 0, 0, Some("/api/encrypt"));
        let _request = m.request_start();
        m.request_end_full(403, Duration::from_millis(5), 0, 0, Some("/api/decrypt"));

        assert_eq!(m.client_errors.load(Ordering::Relaxed), 2);
        assert_eq!(m.server_errors.load(Ordering::Relaxed), 1);

        let errors = m.endpoint_error_counts();
        // Composite key: /api/encrypt has both client(404) and server(500) entries,
        // /api/decrypt has one client(403) entry = 3 total
        assert_eq!(errors.len(), 3);

        // Sorted by count desc; all counts are 1 so order is stable by sort
        let encrypt_total: u64 = errors
            .iter()
            .filter(|e| e.path == "/api/encrypt")
            .map(|e| e.count)
            .sum();
        assert_eq!(encrypt_total, 2);

        let decrypt_total: u64 = errors
            .iter()
            .filter(|e| e.path == "/api/decrypt")
            .map(|e| e.count)
            .sum();
        assert_eq!(decrypt_total, 1);

        // Verify error_type separation
        assert_eq!(
            errors.iter().filter(|e| e.error_type == "client").count(),
            2
        ); // /api/encrypt 404 + /api/decrypt 403
        assert_eq!(
            errors.iter().filter(|e| e.error_type == "server").count(),
            1
        ); // /api/encrypt 500

        let failures = m.recent_failures();
        assert_eq!(failures.len(), 3);
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

    /// A backend's gauges are read from their sources when the metrics are
    /// exported, its errors and latency recorded as they happen, and a name
    /// the configuration allows is still a valid label.
    #[test]
    fn backend_metrics_are_sampled_on_export() {
        let m = MetricsRegistry::new();
        let in_flight = Arc::new(AtomicU64::new(0));
        let source = Arc::clone(&in_flight);
        m.add_sampler(move |m| {
            m.pools.set_load(
                "api \"pool\"",
                PoolLoad {
                    total: 2,
                    active: source.load(Ordering::Relaxed),
                    waiting: 0,
                    refused: 0,
                },
            );
        });
        m.pools.connection_error("api \"pool\"");
        m.pools
            .record_latency("api \"pool\"", Duration::from_millis(3));

        in_flight.store(1, Ordering::Relaxed);
        let snapshot = m.snapshot();
        assert_eq!(snapshot.pools.len(), 1);
        assert_eq!(snapshot.pools[0].connections_active, 1);
        assert_eq!(snapshot.pools[0].connections_total, 2);
        assert_eq!(snapshot.pools[0].connection_errors, 1);

        in_flight.store(0, Ordering::Relaxed);
        let text = m.export_prometheus();
        assert!(text.contains("pqcrypta_pool_connections_active{pool=\"api \\\"pool\\\"\"} 0"));
        assert!(text.contains("pqcrypta_pool_latency_seconds_count{pool=\"api \\\"pool\\\"\"} 1"));
        assert!(text.contains(
            "pqcrypta_pool_latency_seconds_bucket{pool=\"api \\\"pool\\\"\",le=\"+Inf\"} 1"
        ));
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

        let _request = registry.requests.request_start();
        registry
            .requests
            .request_end_full(200, Duration::from_millis(50), 100, 200, None);
        let _open = registry
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
