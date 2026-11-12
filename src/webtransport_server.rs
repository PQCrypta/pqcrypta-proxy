//! Production WebTransport Server with proper ALPN negotiation
//!
//! Uses the wtransport crate for full WebTransport protocol support including:
//! - Automatic ALPN "h3" configuration
//! - SETTINGS_ENABLE_WEBTRANSPORT frame
//! - Proper session handling
//! - Bidirectional/unidirectional streams and datagrams

use dashmap::DashMap;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn, Instrument};
use wtransport::config::QuicTransportConfig;
use wtransport::{Connection, Endpoint, ServerConfig};

use crate::config::ProxyConfig;
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::proxy::BackendPool;
use crate::tls::{MultiDomainCertResolver, TlsProvider};

/// Production WebTransport server with proper ALPN protocol negotiation
pub struct WebTransportServer {
    server: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    addr: SocketAddr,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    metrics: Option<Arc<MetricsRegistry>>,
    /// Per-origin active session counter (origin string → count)
    origin_session_counts: Arc<DashMap<String, Arc<AtomicU32>>>,
    /// Shared security state for WAF inspection of proxied payloads.
    ///
    /// WebTransport stream and datagram payloads are forwarded to the same
    /// backends (/encrypt, /decrypt, …) as HTTP requests, so without this they
    /// are an uninspected path to those backends — the exact transport
    /// divergence the shared security layer exists to prevent, just one
    /// transport further out than HTTP/3. `None` leaves inspection off (the WAF
    /// is opt-in), matching the HTTP paths.
    security: Option<crate::security::SecurityState>,
    /// Fires when the process begins to shut down; `run` then closes the
    /// endpoint. Without it the server never heard about shutdown, and every
    /// open session -- a speed test, a telemetry wall -- held the connection
    /// drain in `main` to its full budget.
    shutdown: Option<tokio::sync::watch::Receiver<()>>,
    /// Reloaded configurations, the channel the TCP listeners follow.
    config_updates: Option<tokio::sync::watch::Receiver<Arc<ProxyConfig>>>,
}

impl WebTransportServer {
    /// Create new WebTransport server with TLS and ALPN configuration
    ///
    /// ALPN Protocol: "h3" (HTTP/3) is automatically configured by wtransport crate
    /// The crate handles SETTINGS_ENABLE_WEBTRANSPORT frame automatically
    #[allow(clippy::unused_async_trait_impl)] // public async API; callers .await it
    pub async fn new(
        addr: SocketAddr,
        cert_path: &str,
        key_path: &str,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("🚀 Initializing Production WebTransport Server (pqcrypta-proxy)");
        info!("📍 Binding address: {}", addr);
        info!("🔒 TLS Certificate: {}", cert_path);
        info!("🔑 Private Key: {}", key_path);
        info!("🔧 ALPN Protocol: h3 (HTTP/3) - automatically configured");

        // Build an SNI-based multi-cert resolver from the certs directory (the
        // parent of the configured cert_path) so the WebTransport server presents
        // the correct per-domain certificate for each SNI — matching the :443
        // HTTPS listener. Without this the dedicated WT server can only serve a
        // single static cert, breaking WebTransport for every other host on the box.
        let certs_dir = std::path::Path::new(cert_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("/etc/pqcrypta/certs"));
        let resolver = Arc::new(
            MultiDomainCertResolver::for_primary(std::path::Path::new(cert_path)).map_err(|e| {
                error!(
                    "❌ WebTransport SNI resolver build failed from {:?}: {}",
                    certs_dir, e
                );
                e
            })?,
        );
        // WebTransport is an HTTP/3 extended CONNECT: this listener serves h3
        let rustls_config = TlsProvider::create_rustls_config_with_resolver(
            &config.tls,
            &config.pqc,
            config.pqc.enabled,
            config.client_auth(),
            resolver,
            &[b"h3".to_vec()],
        )
        .map_err(|e| {
            error!("❌ WebTransport rustls config build failed: {}", e);
            e
        })?;

        info!(
            "✅ WebTransport SNI cert resolver loaded from {:?}",
            certs_dir
        );

        // Transport configuration — tuned for speedtest bulk data + concurrent datagrams.
        //
        // ExcessiveLoad root cause: during simultaneous download stream + datagram latency
        // probes, the 64KB datagram receive buffer fills and quinn aborts the connection
        // with ExcessiveLoad (QUIC error 0x4). Fix: large datagram buffers + flow-control
        // windows sized for ≥200 Mbps at ~50ms RTT (BDP ≈ 1.25 MB per stream).
        use quinn::VarInt;
        let mut transport_config = QuicTransportConfig::default();

        // Connection-level receive window — 64 MB (supports multiple concurrent streams)
        transport_config.receive_window(VarInt::from_u32(64 * 1024 * 1024));

        // Per-stream receive window — 32 MB
        transport_config.stream_receive_window(VarInt::from_u32(32 * 1024 * 1024));

        // Send window — 64 MB
        transport_config.send_window(64 * 1024 * 1024);

        // Congestion control: server.quic_congestion_control (BBRv3 by default),
        // the same controller the main QUIC listener runs.
        let congestion = config.server.quic_congestion_control;
        transport_config.congestion_controller_factory(congestion.factory());
        crate::speedtest::set_congestion_control(congestion.name());

        // Path MTU discovery to the byte, up to a 1500-byte link (see its docs).
        transport_config.mtu_discovery_config(Some(crate::config::quic_mtu_discovery()));

        // Concurrent streams
        // server.webtransport_max_streams_per_session, in each direction
        let max_streams = VarInt::from_u32(config.server.webtransport_max_streams_per_session);
        transport_config.max_concurrent_bidi_streams(max_streams);
        transport_config.max_concurrent_uni_streams(max_streams);

        // Datagram buffers — 4 MB each prevents ExcessiveLoad when datagrams
        // arrive during high-throughput download/upload streams.
        transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport_config.datagram_send_buffer_size(4 * 1024 * 1024);

        // ACK Frequency extension (draft-ietf-quic-ack-frequency): fewer batched
        // ACKs cut overhead during bulk speedtest transfers. Negotiated, so it is
        // inert against clients that do not support it.
        if config.server.enable_ack_frequency {
            transport_config.ack_frequency_config(Some(quinn::AckFrequencyConfig::default()));
            info!("🔧 QUIC ACK Frequency extension enabled");
        }

        info!(
            "🔧 Transport config: receive_window=64MB, stream_window=32MB, send_window=64MB, datagram_buf=4MB, congestion={}",
            congestion.name()
        );

        // Bind the UDP socket ourselves so we can size SO_RCVBUF/SO_SNDBUF
        // explicitly. wtransport/quinn-udp enable GSO/GRO automatically but never
        // set the kernel socket buffers — they inherit net.core.{r,w}mem_default,
        // which varies per host (e.g. 8 MB on the speedtest node vs 25 MB
        // elsewhere). On a speedtest server an undersized send/recv buffer caps
        // measured throughput, so request a fixed 16 MB; the kernel clamps to
        // net.core.{r,w}mem_max. with_bind_socket() takes the socket as-is, and
        // the address path sets no extra socket options, so this is equivalent.
        let socket = std::net::UdpSocket::bind(addr)?;
        {
            const UDP_BUFFER_BYTES: usize = 16 * 1024 * 1024;
            let sock_ref = socket2::SockRef::from(&socket);
            if let Err(e) = sock_ref.set_recv_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set WebTransport UDP SO_RCVBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            if let Err(e) = sock_ref.set_send_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set WebTransport UDP SO_SNDBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            // Linux reports ~2x the granted size; halve for an honest figure.
            let rcv = sock_ref.recv_buffer_size().map(|v| v / 2).unwrap_or(0);
            let snd = sock_ref.send_buffer_size().map(|v| v / 2).unwrap_or(0);
            info!(
                "WebTransport UDP socket buffers: SO_RCVBUF≈{} KB, SO_SNDBUF≈{} KB (requested {} KB each)",
                rcv / 1024,
                snd / 1024,
                UDP_BUFFER_BYTES / 1024
            );
        }

        // Create server configuration with WebTransport support
        // The wtransport crate automatically:
        // - Configures ALPN with "h3" protocol
        // - Sends SETTINGS_ENABLE_WEBTRANSPORT=1 frame
        // - Handles QUIC connection establishment
        let mut config_builder = ServerConfig::builder()
            .with_bind_socket(socket)
            .with_custom_tls_and_transport(rustls_config, transport_config)
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .max_idle_timeout(Some(Duration::from_mins(2)))
            .map_err(|e| format!("Invalid idle timeout: {}", e))?
            .build();

        // Advertise the same QUIC version list as the main listener: v1 (RFC 9000)
        // + v2 (RFC 9369). Without this the WebTransport endpoint would fall back to
        // noq's DEFAULT_SUPPORTED_VERSIONS (v1 + the obsolete draft-29..34), which
        // both omits v2 and misleadingly advertises dead drafts in Version Negotiation.
        config_builder
            .quic_endpoint_config_mut()
            .supported_versions(vec![0x0000_0001, 0x6b33_43cf]);

        info!("✅ Server configuration created");
        info!("🔧 ALPN Protocol: h3 (automatically configured by wtransport)");
        info!("🔧 Keep-alive interval: 15 seconds");
        info!("🔧 Max idle timeout: 120 seconds");

        // Create WebTransport endpoint
        let server = Endpoint::server(config_builder).map_err(|e| {
            error!("❌ WebTransport endpoint creation failed: {}", e);
            e
        })?;

        info!("✅ WebTransport server endpoint created");
        info!("🌟 WebTransport server ready - ALPN h3 configured automatically");
        info!("🔗 Endpoint: wss://{}:{}/", addr.ip(), addr.port());

        Ok(Self {
            server,
            addr,
            config,
            backend_pool,
            metrics: None,
            origin_session_counts: Arc::new(DashMap::new()),
            security: None,
            shutdown: None,
            config_updates: None,
        })
    }

    /// Set the metrics registry for connection tracking
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Attach shared security state so proxied WebTransport payloads are
    /// WAF-inspected before reaching a backend.
    #[must_use]
    pub fn with_security(mut self, security: crate::security::SecurityState) -> Self {
        self.security = Some(security);
        self
    }

    /// Close every session and stop accepting when `shutdown` fires.
    #[must_use]
    pub fn with_shutdown(mut self, shutdown: tokio::sync::watch::Receiver<()>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    /// Follow reloaded configurations: each new session uses the latest. This
    /// server was handed the startup config and kept it, so a reload changed
    /// nothing here -- allowed origins and per-origin session limits included.
    #[must_use]
    pub fn with_config_updates(
        mut self,
        updates: tokio::sync::watch::Receiver<Arc<ProxyConfig>>,
    ) -> Self {
        self.config_updates = Some(updates);
        self
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Run the WebTransport server and accept incoming connections
    pub async fn run(mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut config = self.config.clone();
        let mut backend_pool = self.backend_pool.clone();
        let metrics = self.metrics.clone();
        let origin_counts = Arc::clone(&self.origin_session_counts);
        let security = self.security.clone();

        info!("🌐 WebTransport server listening on {}", self.addr);
        info!("🔗 Ready to accept WebTransport connections");
        info!("🔄 Starting accept loop...");

        let mut shutdown = self.shutdown.clone();
        loop {
            // Accept incoming QUIC connection (returns IncomingSession future)
            let incoming_session = match shutdown.as_mut() {
                Some(rx) => tokio::select! {
                    incoming = self.server.accept() => incoming,
                    _ = rx.changed() => {
                        // Sessions cannot be drained -- a speed test runs for
                        // minutes -- so they are closed, with a reason the
                        // client can show, and the drain sees them go.
                        info!("🛑 WebTransport server shutting down: closing all sessions");
                        self.server.close(0u32.into(), b"server shutting down");
                        return Ok(());
                    }
                },
                None => self.server.accept().await,
            };

            debug!("📨 Received incoming WebTransport session");

            if let Some(updates) = self.config_updates.as_mut() {
                if updates.has_changed().unwrap_or(false) {
                    config = updates.borrow_and_update().clone();
                    // Its connect and pool timeouts are fixed when it is built.
                    backend_pool = Arc::new(BackendPool::new(config.clone()));
                    info!("WebTransport server: applying the reloaded configuration");
                }
            }

            // Spawn task to handle the session
            let config_clone = config.clone();
            let backend_clone = backend_pool.clone();
            let session_metrics = metrics.clone();
            let counts_clone = Arc::clone(&origin_counts);
            let security_clone = security.clone();
            let remote_addr = incoming_session.remote_address();
            // A place under the connection limits, held until the session ends
            let peer = crate::security::canonical_addr(remote_addr).ip();
            let exempt = security_clone
                .as_ref()
                .is_some_and(|sec| sec.is_limit_exempt(&peer));
            let Some(slot) = crate::conn_limits::admit(peer, exempt) else {
                debug!(
                    "WebTransport connection from {} refused: connection limit reached",
                    remote_addr
                );
                continue;
            };
            tokio::spawn(async move {
                let _slot = slot;
                if let Some(ref m) = session_metrics {
                    m.connections
                        .connection_opened(ConnectionProtocol::WebTransport);
                }
                if let Err(e) = handle_incoming_session(
                    incoming_session,
                    config_clone,
                    backend_clone,
                    counts_clone,
                    security_clone,
                )
                .await
                {
                    // A client that goes quiet or names a host with no certificate
                    // is ranked as the HTTP/3 listener ranks it, not as an error.
                    crate::quic_listener::log_quic_end(remote_addr, &e.to_string());
                }
                if let Some(ref m) = session_metrics {
                    m.connections.connection_closed();
                }
            });
        }
    }
}

/// Handle incoming session request
async fn handle_incoming_session(
    incoming_session: wtransport::endpoint::IncomingSession,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    origin_session_counts: Arc<DashMap<String, Arc<AtomicU32>>>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    debug!("📨 Processing incoming WebTransport session...");
    debug!("📍 Remote address: {}", incoming_session.remote_address());

    // Await the IncomingSession to get SessionRequest
    let session_request = incoming_session.await?;

    let path = session_request.path().to_string();
    let authority = session_request.authority().to_string();
    let remote_addr = crate::security::canonical_addr(session_request.remote_address());

    debug!("📥 WebTransport session request received");
    info!("   Path: {}", path);
    debug!("   Authority: {}", authority);

    // The session request is an HTTP request, and is held to what every other
    // one is: the blocklist, the location rules, the rate limits and the WAF
    // (`SecurityState::evaluate`). A WebTransport client is a program, so the
    // user-agent rules for unnamed clients do not apply to it.
    let host = crate::config::host_without_port(&authority).to_ascii_lowercase();
    let (raw_path, query) = path.split_once('?').unwrap_or((path.as_str(), ""));
    let route_path = crate::path_canon::canonical_path(
        raw_path,
        crate::path_canon::PathCanon::from(&config.server),
    )
    .into_owned();
    if let Some(sec) = &security {
        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in session_request.headers() {
            if let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                axum::http::HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
        let mut policy = crate::security::request_policy(
            &config,
            Some(&host),
            &route_path,
            &hyper::Method::CONNECT,
        );
        policy.skip_bot_blocking = true;
        let lowered = raw_path.to_ascii_lowercase();
        let view = crate::security::SecurityRequestView {
            ip: remote_addr.ip(),
            peer_port: Some(remote_addr.port()),
            method: "CONNECT",
            path: &lowered,
            query,
            headers: &headers,
            body: None,
        };
        match sec.evaluate(&view, &policy) {
            crate::security::SecurityDecision::Allow => {}
            crate::security::SecurityDecision::RateLimited { .. } => {
                warn!(
                    "WebTransport session from {} refused: rate limited",
                    remote_addr
                );
                session_request.too_many_requests().await;
                return Ok(());
            }
            decision => {
                warn!(
                    "WebTransport session from {} refused: {:?}",
                    remote_addr, decision
                );
                session_request.forbidden().await;
                return Ok(());
            }
        }
    }

    // The backend this session's requests go to: its own route's, by the host
    // and path it was opened for. None for the paths served here (the speed
    // test, the telemetry wall) and for a session no route covers, which is
    // answered only what the proxy answers itself.
    let session_backend: Option<String> = config
        .find_route(Some(&host), &route_path, true)
        .filter(|route| route.webtransport)
        .map(|route| route.backend.clone());

    // SR-02: Origin validation.
    //
    // The WebTransport spec requires servers to validate the `Origin` header
    // to prevent cross-origin abuse from arbitrary web pages.  We reject any
    // session whose origin is not listed in `server.webtransport_allowed_origins`.
    //
    // Behaviour matrix:
    //   allowed_origins is empty  → non-browser (no Origin header) passes;
    //                               browser sessions (have Origin) are rejected
    //                               until the operator configures the list.
    //   allowed_origins non-empty → Origin must match one of the listed values;
    //                               sessions without an Origin header are also
    //                               accepted (non-browser / native clients).
    let allowed_origins = &config.server.webtransport_allowed_origins;
    let origin_key = session_request
        .origin()
        .map(|o| o.to_string())
        .unwrap_or_else(|| "no-origin".to_string());

    if let Some(origin) = session_request.origin() {
        // Browser-sourced session: check against the allowlist.
        let is_allowed = if allowed_origins.is_empty() {
            // No origins configured — reject all browser cross-origin sessions.
            false
        } else {
            allowed_origins.iter().any(|o| o == origin)
        };

        if !is_allowed {
            warn!(
                "SR-02: WebTransport session from {} rejected — Origin '{}' not in allowed list",
                remote_addr, origin
            );
            session_request.forbidden().await;
            return Ok(());
        }
        debug!("   Origin: {} ✅", origin);
    } else {
        // No Origin header — non-browser / native client; always accepted.
        debug!("   Origin: (none — non-browser client)");
    }

    // WT-RL-02: per-client-address session limit.
    let client_ip = crate::speedtest::canonical_ip(remote_addr.ip());
    let max_client = config.server.webtransport_max_sessions_per_client;
    let Some(_client_slot) = ClientSlot::reserve(&CLIENT_SESSIONS, client_ip, max_client) else {
        warn!(
            "WT-RL-02: WebTransport session limit ({}) reached for {} — rejecting",
            max_client, remote_addr
        );
        session_request.forbidden().await;
        return Ok(());
    };

    // WT-RL-01: Per-origin session limit.
    let max_sessions = config.server.webtransport_max_sessions_per_origin;
    let Some(_slot) = OriginSlot::reserve(&origin_session_counts, &origin_key, max_sessions) else {
        warn!(
            "WT-RL-01: WebTransport session limit ({}) reached for origin '{}' — rejecting {}",
            max_sessions, origin_key, remote_addr
        );
        session_request.forbidden().await;
        return Ok(());
    };

    // The session's server span, stitched into the caller's trace from the
    // CONNECT request's headers. Its stream and datagram tasks inherit it, so
    // what they forward carries the caller's trace to the backend -- without
    // it they injected an empty context, whatever the docs said.
    let span = if config.otel.enabled || tracing::span_enabled!(tracing::Level::INFO) {
        let span = tracing::info_span!(
            "webtransport.session",
            url.path = %path,
            otel.kind = "server",
            trace_id = tracing::field::Empty,
        );
        crate::otel::set_parent_from_map(&span, session_request.headers());
        let trace_id = crate::otel::trace_id_of(&span);
        if !trace_id.is_empty() {
            span.record("trace_id", trace_id);
        }
        span
    } else {
        tracing::Span::none()
    };

    async move {
        // Accept the session
        let connection = session_request.accept().await?;

        debug!("✅ WebTransport connection established: {}", remote_addr);

        // The slot is given back when `_slot` drops: when the session ends,
        // and equally when this task panics or is cancelled.
        handle_connection(
            connection,
            remote_addr,
            path,
            session_backend,
            config,
            backend_pool,
            security,
        )
        .await
    }
    .instrument(span)
    .await
}

/// One origin's claim on a concurrent-session slot, given back on drop.
///
/// The counter is cloned out of the map in one expression, so the map's guard
/// is gone before anything awaits. It used to be read through the `RefMut`
/// that `entry` returns, bound to a name that was then shadowed -- and
/// shadowing drops nothing. That guard is a write lock on the map's shard, it
/// lived for the whole session, and it is not an async lock: the next session
/// from the same origin parked a worker thread waiting for it. Once every
/// worker was parked, nothing could poll the session holding the lock, and the
/// proxy stopped outright -- every listener, the admin port, SIGTERM -- until
/// the hang watchdog restarted it, twice on 2026-09-25.
struct OriginSlot(Arc<AtomicU32>);

impl OriginSlot {
    /// Take a slot for `origin`, or `None` when it already has `max` sessions.
    ///
    /// A compare-and-swap, not a load followed by an add: with the separate
    /// read, two sessions arriving together could both see room for one and
    /// both take it.
    fn reserve(counts: &DashMap<String, Arc<AtomicU32>>, origin: &str, max: u32) -> Option<Self> {
        let counter = Arc::clone(
            counts
                .entry(origin.to_string())
                .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                .value(),
        );
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(counter))
    }
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Sessions open per client address (`server.webtransport_max_sessions_per_client`).
static CLIENT_SESSIONS: LazyLock<DashMap<IpAddr, u32>> = LazyLock::new(DashMap::new);

/// One client address's claim on a concurrent-session slot, given back on drop.
///
/// The count is read and raised under the map shard's lock and nothing awaits
/// while it is held (see [`OriginSlot`] for what holding it across an await
/// did). An address's entry goes when its last session ends, so the map holds
/// only addresses with sessions open.
struct ClientSlot {
    counts: &'static DashMap<IpAddr, u32>,
    ip: IpAddr,
}

impl ClientSlot {
    /// Take a slot for `ip`, or `None` when it already has `max` sessions
    /// (0: no limit).
    fn reserve(counts: &'static DashMap<IpAddr, u32>, ip: IpAddr, max: u32) -> Option<Self> {
        let mut n = counts.entry(ip).or_insert(0);
        if max != 0 && *n >= max {
            return None;
        }
        *n += 1;
        drop(n);
        Some(Self { counts, ip })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        if let Some(mut n) = self.counts.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
        }
        self.counts.remove_if(&self.ip, |_, n| *n == 0);
    }
}

/// The path a session was opened for and the backend its route names.
struct SessionRoute {
    path: String,
    backend: Option<String>,
}

/// How long a stream's request may take to arrive.
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a stream's request was not read.
enum StreamRead {
    TooLarge,
    Failed(std::io::Error),
    TimedOut,
}

/// A stream's whole request, read no further than `max` bytes: what would not
/// be accepted is not held either.
async fn read_request(
    recv_stream: &mut wtransport::stream::RecvStream,
    max: usize,
) -> Result<Vec<u8>, StreamRead> {
    let mut buffer = Vec::new();
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let read = tokio::time::timeout(
        STREAM_READ_TIMEOUT,
        (&mut *recv_stream).take(limit).read_to_end(&mut buffer),
    )
    .await;
    match read {
        Ok(Ok(_)) if buffer.len() > max => Err(StreamRead::TooLarge),
        Ok(Ok(_)) => Ok(buffer),
        Ok(Err(e)) => Err(StreamRead::Failed(e)),
        Err(_) => Err(StreamRead::TimedOut),
    }
}

/// Handle an established WebTransport connection
async fn handle_connection(
    connection: Connection,
    remote_addr: SocketAddr,
    path: String,
    session_backend: Option<String>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "🔄 Handling WebTransport connection from {} (path: {})",
        remote_addr, path
    );

    let connection = Arc::new(connection);

    // Native speed test handler — serves /speedtest without backend proxying
    if path == "/speedtest" {
        return crate::speedtest::handle_speedtest_session(connection, remote_addr).await;
    }

    // Native telemetry wall handler — serves /telemetry without backend proxying
    if path == "/telemetry" {
        return crate::telemetry::handle_telemetry_session(connection, remote_addr).await;
    }

    // What every stream and datagram of this session is routed by.
    let session = Arc::new(SessionRoute {
        path,
        backend: session_backend,
    });

    // Per-session datagram budget window (see webtransport_max_datagrams_per_sec).
    let mut dg_window_start = std::time::Instant::now();
    let mut dg_count: u32 = 0;

    loop {
        tokio::select! {
            // Handle unidirectional streams (client -> server)
            stream_result = connection.accept_uni() => {
                match stream_result {
                    Ok(recv_stream) => {
                        debug!("📥 New unidirectional stream from {}", remote_addr);
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_uni_stream(
                            recv_stream, remote_addr, conn, session_clone, config_clone, backend_clone,
                            security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Unidirectional stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            // Handle bidirectional streams
            stream_result = connection.accept_bi() => {
                match stream_result {
                    Ok((send_stream, recv_stream)) => {
                        debug!("📥📤 New bidirectional stream from {}", remote_addr);
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_bi_stream(
                            send_stream, recv_stream, remote_addr, conn, session_clone, config_clone,
                            backend_clone, security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Bidirectional stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            // Handle datagrams
            datagram_result = connection.receive_datagram() => {
                match datagram_result {
                    Ok(datagram) => {
                        // server.webtransport_max_datagrams_per_sec was configured
                        // and never enforced, so a session could flood datagrams
                        // unbounded — each one spawning a task. Drop anything past
                        // the per-second budget: datagrams are unreliable by
                        // definition, so shedding is the correct response.
                        let dg_limit = config.server.webtransport_max_datagrams_per_sec;
                        if dg_limit > 0 {
                            let now = std::time::Instant::now();
                            if now.duration_since(dg_window_start) >= std::time::Duration::from_secs(1) {
                                dg_window_start = now;
                                dg_count = 0;
                            }
                            dg_count += 1;
                            if dg_count > dg_limit {
                                debug!("Datagram budget exceeded for {} ({}/s) — dropping", remote_addr, dg_limit);
                                continue;
                            }
                        }
                        debug!("📦 Datagram received from {} ({} bytes)", remote_addr, datagram.len());
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_datagram(
                            datagram.to_vec(), remote_addr, conn, session_clone, config_clone,
                            backend_clone, security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Datagram stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }
        }
    }

    debug!("🔚 WebTransport connection closed: {}", remote_addr);
    Ok(())
}

/// Handle unidirectional stream (client -> server)
async fn handle_uni_stream(
    mut recv_stream: wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
    _connection: Arc<Connection>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let max_size = config.security.max_request_size;
    let buffer = match read_request(&mut recv_stream, max_size).await {
        Ok(buffer) => buffer,
        Err(StreamRead::TooLarge) => {
            debug!(
                "Request from {} exceeds max size ({} bytes)",
                remote_addr, max_size
            );
            return Err("Request too large".into());
        }
        Err(StreamRead::Failed(e)) => {
            debug!("Read error from {}: {}", remote_addr, e);
            return Err(format!("Stream read error: {}", e).into());
        }
        Err(StreamRead::TimedOut) => {
            debug!("Request timeout from {}", remote_addr);
            return Err("Request timeout".into());
        }
    };

    debug!(
        "📥 Unidirectional data from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(
        &buffer,
        &session,
        remote_addr,
        &config,
        &backend_pool,
        &security,
    )
    .await
    {
        Ok(response) => {
            debug!("✅ Processed unidirectional request from {}", remote_addr);
            debug!("   Response: {} bytes", response.len());
        }
        Err(e) => {
            error!("❌ Failed to process request from {}: {}", remote_addr, e);
        }
    }

    Ok(())
}

/// Handle bidirectional stream
#[allow(clippy::too_many_arguments)] // WT handler: transport + routing + security
async fn handle_bi_stream(
    mut send_stream: wtransport::stream::SendStream,
    mut recv_stream: wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
    _connection: Arc<Connection>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let max_size = config.security.max_request_size;
    let buffer = match read_request(&mut recv_stream, max_size).await {
        Ok(buffer) => buffer,
        Err(why) => {
            // SEC-02: the detail is logged here; the client gets a generic
            // message, with no file path, OS error or library internals in it.
            let (message, error): (String, Box<dyn std::error::Error + Send + Sync>) = match why {
                StreamRead::TooLarge => (
                    format!("Request exceeds max size of {} bytes", max_size),
                    "Request too large".into(),
                ),
                StreamRead::Failed(e) => {
                    debug!("Stream read error for {}: {}", remote_addr, e);
                    (
                        "Stream error".to_string(),
                        format!("Stream read error: {}", e).into(),
                    )
                }
                StreamRead::TimedOut => ("Request timeout".to_string(), "Request timeout".into()),
            };
            let error_response = json!({
                "success": false,
                "error": message,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            let _ = send_stream.finish().await;
            return Err(error);
        }
    };

    debug!(
        "📥 Bidirectional request from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(
        &buffer,
        &session,
        remote_addr,
        &config,
        &backend_pool,
        &security,
    )
    .await
    {
        Ok(response) => {
            debug!(
                "📤 Sending response to {} ({} bytes)",
                remote_addr,
                response.len()
            );
            send_stream.write_all(&response).await?;
            send_stream.finish().await?;
            info!("✅ Bidirectional stream completed: {}", remote_addr);
        }
        Err(e) => {
            // SEC-02: Log full error server-side; send only a generic message to the client.
            error!("❌ Request processing failed for {}: {}", remote_addr, e);

            // Send error response
            let error_response = json!({
                "success": false,
                "error": "Request processing failed",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });

            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            send_stream.finish().await?;
        }
    }

    Ok(())
}

/// Handle datagram
#[allow(clippy::too_many_arguments)] // WT handler: transport + routing + security
async fn handle_datagram(
    datagram: Vec<u8>,
    remote_addr: SocketAddr,
    connection: Arc<Connection>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check datagram size limit (datagrams should be small, typically < 64KB)
    let max_datagram_size = 65535; // Max UDP datagram size
    if datagram.len() > max_datagram_size {
        error!(
            "Datagram from {} exceeds max size ({} > {})",
            remote_addr,
            datagram.len(),
            max_datagram_size
        );
        let error_response = json!({
            "success": false,
            "error": "Datagram too large",
            "timestamp": chrono::Utc::now().to_rfc3339()
        });
        let error_bytes = serde_json::to_vec(&error_response)?;
        connection.send_datagram(&error_bytes)?;
        return Ok(());
    }

    debug!(
        "📦 Processing datagram from {} ({} bytes)",
        remote_addr,
        datagram.len()
    );

    // Apply timeout for backend proxy call
    let timeout_duration = Duration::from_secs(30);
    let proxy_result = tokio::time::timeout(
        timeout_duration,
        proxy_request(
            &datagram,
            &session,
            remote_addr,
            &config,
            &backend_pool,
            &security,
        ),
    )
    .await;

    match proxy_result {
        Ok(Ok(response)) => {
            debug!(
                "📤 Sending datagram response to {} ({} bytes)",
                remote_addr,
                response.len()
            );
            connection.send_datagram(&response)?;
            debug!("✅ Datagram response sent to {}", remote_addr);
        }
        Ok(Err(e)) => {
            // SEC-02: Log full error server-side; send only a generic message to the client.
            error!("❌ Datagram processing failed for {}: {}", remote_addr, e);
            let error_response = json!({
                "success": false,
                "error": "Datagram processing failed",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            connection.send_datagram(&error_bytes)?;
        }
        Err(_) => {
            error!("❌ Datagram proxy timeout for {}", remote_addr);
            let error_response = json!({
                "success": false,
                "error": "Backend timeout",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            connection.send_datagram(&error_bytes)?;
        }
    }

    Ok(())
}

/// Proxy request to backend server via HTTP
async fn proxy_request(
    data: &[u8],
    session: &SessionRoute,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
    security: &Option<crate::security::SecurityState>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // WAF inspection. A WebTransport stream/datagram payload is proxied to the
    // same backends (/encrypt, /decrypt, …) as an HTTP request, so it is an
    // attack surface on those backends and must clear the same WAF the HTTP and
    // HTTP/3 paths run. The payload is treated as the request body; there are no
    // HTTP headers on a WT frame, so a minimal header map is synthesised. When
    // no security state is attached (WAF disabled) this is a no-op.
    let path = session.path.as_str();
    if let Some(sec) = security {
        if sec.waf().is_some() {
            let ip = crate::security::canonical_addr(remote_addr).ip();
            let is_pentest =
                crate::config::ip_list_contains(&sec.config.read().pentest_bypass_ips, &ip);
            let headers = axum::http::HeaderMap::new();
            let view = crate::security::SecurityRequestView {
                ip,
                peer_port: Some(remote_addr.port()),
                method: "POST",
                path,
                query: "",
                headers: &headers,
                body: Some(data),
            };
            let policy = crate::security::RequestPolicy::default();
            if let crate::security::SecurityDecision::WafBlock { rule } =
                sec.inspect_body(&view, &policy, is_pentest)
            {
                warn!(
                    "[WebTransport] WAF block: rule={} ip={} path={}",
                    rule, ip, path
                );
                let body = json!({
                    "success": false,
                    "error": "Request blocked by security policy",
                    "webtransport": true,
                });
                return Ok(serde_json::to_vec(&body)?);
            }
        }
    }

    // Try to parse as JSON
    if let Ok(request_str) = std::str::from_utf8(data) {
        if let Ok(request) = serde_json::from_str::<serde_json::Value>(request_str) {
            debug!("📋 Processing JSON request from {}", remote_addr);

            // Determine the operation to route to backend
            if let Some(operation) = request.get("operation").and_then(|v| v.as_str()) {
                let backend_path = match operation {
                    "encrypt" => "/encrypt",
                    "decrypt" => "/decrypt",
                    "generate_keys" | "keygen" => "/keys/generate",
                    "health" => "/health",
                    "ping" => {
                        // Handle ping locally
                        let response = json!({
                            "success": true,
                            "operation": "pong",
                            "server": "pqcrypta-proxy",
                            "webtransport": true,
                            "timestamp": chrono::Utc::now().to_rfc3339()
                        });
                        return Ok(serde_json::to_vec(&response)?);
                    }
                    _ => path,
                };

                // Forward to backend, with the request's own credential
                return forward_to_backend(
                    data,
                    backend_path,
                    session.backend.as_deref(),
                    request_credential(&request).as_deref(),
                    remote_addr,
                    config,
                    backend_pool,
                )
                .await;
            }
        }
    }

    // For non-JSON data, forward to the path directly
    forward_to_backend(
        data,
        path,
        session.backend.as_deref(),
        None,
        remote_addr,
        config,
        backend_pool,
    )
    .await
}

/// The API key a WebTransport request carries in its body ("api_key"),
/// to send on as `X-API-Key`. A WebTransport frame has no headers, and the
/// backend authenticates every request: `X-WebTransport-Proxy` only says the
/// proxy forwarded it (and its WAF already inspected it), it is not a
/// credential. Anything a header cannot carry is not a key.
fn request_credential(request: &serde_json::Value) -> Option<String> {
    request
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|k| !k.is_empty() && k.len() <= 512 && k.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_string)
}

/// Forward a request to the backend of the session's route.
///
/// A session no WebTransport route covers has no backend, and what it sends
/// is answered here: nothing is forwarded on a guess.
async fn forward_to_backend(
    data: &[u8],
    path: &str,
    backend_name: Option<&str>,
    api_key: Option<&str>,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(backend_name) = backend_name else {
        debug!(
            "WebTransport request from {} for {}: the session has no route",
            remote_addr, path
        );
        let body = json!({
            "success": false,
            "error": "No WebTransport route for this session",
            "webtransport": true,
        });
        return Ok(serde_json::to_vec(&body)?);
    };

    let backend = config.backends.get(backend_name).ok_or_else(|| {
        format!(
            "Backend '{}' of the session's route is not configured",
            backend_name
        )
    })?;

    debug!(
        "🔄 Forwarding WebTransport request to backend '{}': {}",
        backend_name, path
    );

    // Create headers for the request
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-Forwarded-For".to_string(), remote_addr.ip().to_string());
    headers.insert(
        "X-WebTransport-Proxy".to_string(),
        "pqcrypta-proxy".to_string(),
    );
    headers.insert("X-Real-IP".to_string(), remote_addr.ip().to_string());
    if let Some(key) = api_key {
        headers.insert("X-API-Key".to_string(), key.to_string());
    }

    // Use the BackendPool's proxy_http method
    let response = backend_pool
        .proxy_http(backend, "POST", path, headers, data)
        .await
        .map_err(|e| format!("Backend proxy error: {}", e))?;

    debug!("✅ Backend response received ({} bytes)", response.len());

    Ok(response)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_request_s_api_key_is_its_credential() {
        use super::request_credential;
        use serde_json::json;
        assert_eq!(
            request_credential(&json!({"operation": "encrypt", "api_key": " WebUI_key_123 "}))
                .as_deref(),
            Some("WebUI_key_123")
        );
        assert_eq!(request_credential(&json!({"operation": "encrypt"})), None);
        assert_eq!(request_credential(&json!({"api_key": ""})), None);
        // Nothing that could break out of a header
        assert_eq!(
            request_credential(&json!({"api_key": "key\r\nX-Admin: 1"})),
            None
        );
        assert_eq!(request_credential(&json!({"api_key": 42})), None);
    }

    use super::*;

    const ORIGIN: &str = "https://origin.test";

    /// A runtime whose workers can all be parked at once, so a stall shows.
    fn server_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    /// A WebTransport server on a free IPv6 loopback port, with a self-signed
    /// `localhost` certificate its clients trust.
    async fn server(
        dir: &std::path::Path,
        per_origin: u32,
    ) -> (
        WebTransportServer,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(dir.join("localhost.crt"), cert.cert.pem()).unwrap();
        std::fs::write(dir.join("localhost.key"), cert.signing_key.serialize_pem()).unwrap();
        // `localhost` resolves to ::1 first, so that is where the server listens.
        let port = std::net::UdpSocket::bind("[::1]:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut config = ProxyConfig::default();
        config.server.webtransport_allowed_origins = vec![ORIGIN.to_string()];
        config.server.webtransport_max_sessions_per_origin = per_origin;
        let config = Arc::new(config);
        let crt = dir.join("localhost.crt");
        let key = dir.join("localhost.key");
        let server = WebTransportServer::new(
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            crt.to_str().unwrap(),
            key.to_str().unwrap(),
            config.clone(),
            Arc::new(BackendPool::new(config)),
        )
        .await
        .unwrap();
        (server, cert.cert.der().clone())
    }

    fn client(
        root: rustls::pki_types::CertificateDer<'static>,
    ) -> wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(root).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = wtransport::ClientConfig::builder()
            .with_bind_default()
            .with_custom_tls(tls)
            .build();
        wtransport::Endpoint::client(config).unwrap()
    }

    async fn open(
        endpoint: &wtransport::Endpoint<wtransport::endpoint::endpoint_side::Client>,
        port: u16,
    ) -> Result<wtransport::Connection, wtransport::error::ConnectingError> {
        endpoint
            .connect(
                wtransport::endpoint::ConnectOptions::builder(format!(
                    "https://localhost:{port}/webtransport"
                ))
                .add_header("origin", ORIGIN)
                .build(),
            )
            .await
    }

    /// Sessions from one origin, open at once, must leave the runtime running.
    ///
    /// The per-origin counter used to be read through the `RefMut` that
    /// `DashMap::entry` returns, and rebinding the name did not drop it: the
    /// guard -- a write lock on the map's shard -- lived until the handler
    /// returned, which is when the session ended. The next session from the
    /// same origin then waited for that lock, and the lock is not async: it
    /// parks the worker thread. One parked worker per waiting session, and when
    /// every worker was parked nothing was left to poll the session that held
    /// the lock, so it never let go. The whole proxy stopped -- every listener,
    /// the admin port, even SIGTERM -- until the hang watchdog restarted it.
    ///
    /// Production has four workers, and it stopped twice on 2026-09-25, each
    /// time after one browser's speed test held a session and four more
    /// requests arrived from the same page. Two workers make the same stall
    /// with two.
    #[test]
    fn sessions_from_one_origin_cannot_stop_the_runtime() {
        let dir = tempfile::tempdir().unwrap();
        let server_rt = server_runtime();
        let (server, root) = server_rt.block_on(server(dir.path(), 100));
        let port = server.local_addr().port();
        let handle = server_rt.handle().clone();
        server_rt.spawn(server.run());

        // The clients run elsewhere, so a stalled server cannot stall them.
        let client_rt = tokio::runtime::Runtime::new().unwrap();
        client_rt.block_on(async move {
            let endpoint = client(root);
            let mut held = Vec::new();
            for n in 0..3 {
                let session = tokio::time::timeout(Duration::from_secs(10), open(&endpoint, port))
                    .await
                    .unwrap_or_else(|_| panic!("session {n} was never answered"))
                    .unwrap_or_else(|e| panic!("session {n} failed: {e}"));
                held.push(session);
            }
            // Anything at all must still run on the server's runtime.
            tokio::time::timeout(Duration::from_secs(5), handle.spawn(async {}))
                .await
                .expect("the server's runtime stopped running tasks")
                .unwrap();
            drop(held);
        });
        server_rt.shutdown_background();
    }

    /// The per-origin cap still holds, and a slot comes back when its
    /// session ends.
    #[test]
    fn a_client_address_holds_at_most_its_cap_and_leaves_no_entry() {
        static COUNTS: LazyLock<DashMap<IpAddr, u32>> = LazyLock::new(DashMap::new);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let a = ClientSlot::reserve(&COUNTS, ip, 2).expect("first session");
        let b = ClientSlot::reserve(&COUNTS, ip, 2).expect("second session");
        assert!(
            ClientSlot::reserve(&COUNTS, ip, 2).is_none(),
            "a third exceeded a cap of two"
        );
        drop(a);
        let c = ClientSlot::reserve(&COUNTS, ip, 2).expect("a slot given back");
        drop(b);
        drop(c);
        assert!(
            COUNTS.get(&ip).is_none(),
            "an address with no sessions keeps no entry"
        );
        assert!(
            ClientSlot::reserve(&COUNTS, ip, 0).is_some(),
            "0 is no limit"
        );
    }

    #[test]
    fn the_per_origin_cap_is_enforced_and_released() {
        let dir = tempfile::tempdir().unwrap();
        let server_rt = server_runtime();
        let (server, root) = server_rt.block_on(server(dir.path(), 1));
        let port = server.local_addr().port();
        server_rt.spawn(server.run());

        let client_rt = tokio::runtime::Runtime::new().unwrap();
        client_rt.block_on(async move {
            let endpoint = client(root);
            let first = open(&endpoint, port)
                .await
                .expect("the first session is within the cap");
            let second = tokio::time::timeout(Duration::from_secs(10), open(&endpoint, port))
                .await
                .expect("the refusal never came");
            assert!(second.is_err(), "a second session exceeded a cap of one");

            first.close(0u32.into(), b"done");
            let mut reopened = None;
            for _ in 0..50 {
                if let Ok(Ok(s)) =
                    tokio::time::timeout(Duration::from_secs(2), open(&endpoint, port)).await
                {
                    reopened = Some(s);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(reopened.is_some(), "the slot was never given back");
        });
        server_rt.shutdown_background();
    }
}
