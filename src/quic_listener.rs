//! QUIC/HTTP3/WebTransport listener
//!
//! Accepts QUIC connections, negotiates HTTP/3, and handles WebTransport sessions.
//! Routes streams and datagrams to configured backends.
//!
//! This listener handles QUIC/HTTP3 connections (h3/quinn stack) and runs alongside
//! `WebTransportServer` (wtransport stack), which handles the dedicated WebTransport port.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3_quinn::Connection as H3Connection;
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http1 as h1_client;
use hyper_util::rt::TokioIo;
use quinn::{
    AckFrequencyConfig, Connection as QuinnConnection, Endpoint, ServerConfig as QuinnServerConfig,
    TransportConfig, VarInt,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::cache::{CacheLookup, ResponseCache};
use crate::config::{BackendConfig, BackendType, ConfigReloadEvent, CorsConfig, ProxyConfig};
use crate::connect_udp::{self, DatagramRouter};
use crate::handlers::WebTransportHandler;
use crate::http3_features::EarlyHintsState;
use crate::load_balancer::{LoadBalancer, SelectionContext};
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::otel;
use crate::proxy::BackendPool;
use crate::rate_limiter::{build_context_from_request, AdvancedRateLimiter, RateLimitResult};
use crate::security::{BlockReason, SecurityState};
use crate::tls::TlsProvider;

const SERVER_HEADER: &str = "pqcrypta"; // SEC-08: no version disclosure

/// Build Alt-Svc header value from config ports.
/// Returns "clear" for hosts listed in `server.tcp_only_hosts` so browsers
/// evict any cached QUIC upgrade and fall back to TCP/TLS.
fn build_alt_svc_header(config: &ProxyConfig) -> String {
    let mut ports = vec![config.server.udp_port];
    ports.extend(&config.server.additional_ports);
    ports
        .iter()
        .map(|p| format!("h3=\":{}\"; ma=86400", p))
        .collect::<Vec<_>>()
        .join(", ")
}

fn alt_svc_for_host(config: &ProxyConfig, host: Option<&str>) -> String {
    if let Some(h) = host {
        if config.server.tcp_only_hosts.iter().any(|t| t == h) {
            return "clear".to_string();
        }
    }
    build_alt_svc_header(config)
}

/// QUIC/HTTP3/WebTransport listener
pub struct QuicListener {
    /// QUIC endpoint
    endpoint: Endpoint,
    /// TLS provider
    tls_provider: Arc<TlsProvider>,
    /// Backend connection pool
    backend_pool: Arc<BackendPool>,
    /// Configuration
    config: Arc<ProxyConfig>,
    /// Shutdown signal receiver
    shutdown_rx: mpsc::Receiver<()>,
    /// Config reload receiver
    reload_rx: mpsc::Receiver<ConfigReloadEvent>,
    /// Early Hints state for 103 responses
    early_hints_state: Arc<EarlyHintsState>,
    /// Metrics registry for recording request/connection stats
    metrics: Arc<MetricsRegistry>,
    /// Security state for IP blocking, GeoIP country blocking, and rate limiting
    security: SecurityState,
    /// Advanced multi-dimensional rate limiter (shared with TCP listeners)
    advanced_rate_limiter: Arc<AdvancedRateLimiter>,
    /// Shared load balancer for canary routing and pool-based selection
    load_balancer: Arc<LoadBalancer>,
    /// Shared response cache (HTTP/3 path)
    cache: Arc<ResponseCache>,
}

impl QuicListener {
    /// Create a new QUIC listener
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        config: Arc<ProxyConfig>,
        tls_provider: Arc<TlsProvider>,
        shutdown_rx: mpsc::Receiver<()>,
        reload_rx: mpsc::Receiver<ConfigReloadEvent>,
        metrics: Arc<MetricsRegistry>,
        security: SecurityState,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        early_hints_state: Arc<EarlyHintsState>,
    ) -> anyhow::Result<Self> {
        let addr = config.server.socket_addr()?;

        info!("Creating QUIC listener on {}", addr);

        // Create transport configuration
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(config.server.max_streams_per_connection.into());
        transport_config
            .max_concurrent_uni_streams(config.server.max_streams_per_connection.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(
            config.server.keepalive_interval_secs,
        )));
        // Match WebTransport server flow-control windows so HTTP/3 upload streams
        // achieve the same per-stream throughput as WebTransport streams.
        // Quinn defaults (~256 KB) cause 5 Mbps/stream; 8 MB raises that to ~100+ Mbps.
        transport_config.receive_window(VarInt::from_u32(16 * 1024 * 1024)); // 16 MB connection
        transport_config.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024)); // 8 MB per stream
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(config.server.max_idle_timeout_secs)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid idle timeout: {}", e))?,
        ));

        // ACK Frequency extension (draft-ietf-quic-ack-frequency): allow the peer
        // to request fewer, batched ACKs, reducing ACK traffic and CPU on
        // high-throughput connections. Negotiated — inert if the peer lacks it.
        if config.server.enable_ack_frequency {
            transport_config.ack_frequency_config(Some(AckFrequencyConfig::default()));
            info!("QUIC ACK Frequency extension enabled");
        }

        // Create QUIC server configuration
        let mut server_config =
            QuinnServerConfig::with_crypto(tls_provider.get_quic_server_config());
        server_config.transport = Arc::new(transport_config);

        // STEP 12: Gate connection migration on server config.
        // `migration()` is a method on ServerConfig, not TransportConfig.
        if !config.server.enable_quic_migration {
            server_config.migration(false);
            info!("QUIC connection migration disabled by configuration");
        }

        // Create endpoint. Built manually (rather than Endpoint::server) so we can
        // override quinn's advertised QUIC version list. quinn-proto's
        // DEFAULT_SUPPORTED_VERSIONS is v1 + draft-29..34, but this proxy only
        // handshakes v1 — advertising those obsolete drafts in Version Negotiation
        // is misleading (and a client that selected one would fail), so restrict the
        // list to v1 only. quinn still adds its reserved/GREASE version automatically.
        let socket = std::net::UdpSocket::bind(addr)?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime found for QUIC endpoint"))?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.supported_versions(vec![0x0000_0001]); // QUIC v1 (RFC 9000) only
        let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

        info!("QUIC endpoint created on {}", addr);
        info!("ALPN protocols: {:?}", config.tls.alpn_protocols);
        info!("PQC enabled: {}", tls_provider.is_pqc_enabled());

        // Create backend pool
        let backend_pool = Arc::new(BackendPool::new(config.clone()));

        // Early Hints state is created once in main() and shared across all QUIC
        // listeners so the config reload handler can update it live.
        if early_hints_state.is_enabled() {
            info!("HTTP/3 Early Hints (103) enabled");
        }

        Ok(Self {
            endpoint,
            tls_provider,
            backend_pool,
            config,
            shutdown_rx,
            reload_rx,
            early_hints_state,
            metrics,
            security,
            advanced_rate_limiter,
            load_balancer,
            cache,
        })
    }

    /// Run the QUIC listener
    pub async fn run(mut self) -> anyhow::Result<()> {
        info!(
            "QUIC/HTTP3/WebTransport listener running on {}",
            self.endpoint.local_addr()?
        );

        let mut accept_count = 0u64;

        loop {
            tokio::select! {
                // Handle incoming connections
                Some(incoming) = self.endpoint.accept() => {
                    accept_count += 1;
                    let remote_addr = incoming.remote_address();
                    let ip = remote_addr.ip();

                    // Connection-level security checks: IP blocklist and GeoIP country blocking.
                    // Evaluated before completing the QUIC/TLS handshake so blocked IPs never
                    // consume cryptographic handshake resources.
                    let should_refuse = if !self.security.is_trusted(&ip) {
                        if let Some(block_info) = self.security.is_blocked(&ip) {
                            warn!(
                                "[QUIC] Refusing connection from blocked IP {} (reason: {:?})",
                                ip, block_info.reason
                            );
                            true
                        } else if self.security.is_country_blocked(&ip) {
                            warn!("[QUIC] Refusing connection from GeoIP-blocked IP {}", ip);
                            self.security.block_ip(ip, BlockReason::GeoBlocked, None);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if should_refuse {
                        incoming.refuse();
                    } else {
                        info!("[{}] Incoming QUIC connection from {}", accept_count, remote_addr);

                        // Spawn connection handler
                        let config = self.config.clone();
                        let backend_pool = self.backend_pool.clone();
                        let early_hints_state = self.early_hints_state.clone();
                        let metrics = self.metrics.clone();
                        let security = self.security.clone();
                        let advanced_rate_limiter = self.advanced_rate_limiter.clone();
                        let load_balancer = self.load_balancer.clone();
                        let cache = self.cache.clone();

                        tokio::spawn(async move {
                            metrics.connections.connection_opened(ConnectionProtocol::Http3);
                            if let Err(e) = Self::handle_connection(
                                incoming,
                                remote_addr,
                                config,
                                backend_pool,
                                early_hints_state,
                                security,
                                metrics.clone(),
                                advanced_rate_limiter,
                                load_balancer,
                                cache,
                            ).await {
                                error!("Connection error from {}: {}", remote_addr, e);
                            }
                            metrics.connections.connection_closed();
                        });
                    }
                }

                // Handle config reload
                Some(event) = self.reload_rx.recv() => {
                    match event {
                        ConfigReloadEvent::ConfigReloaded(new_config) => {
                            info!("Applying configuration reload");
                            self.config = new_config;
                            // Note: Backend pool is thread-safe and will pick up new config
                        }
                        ConfigReloadEvent::TlsCertsReloaded => {
                            info!("TLS certificates reloaded");
                            // TLS provider handles cert reload internally
                            if let Err(e) = self.tls_provider.reload_certificates() {
                                error!("Failed to reload TLS certificates: {}", e);
                            }
                        }
                        ConfigReloadEvent::ReloadFailed(msg) => {
                            error!("Configuration reload failed: {}", msg);
                        }
                    }
                }

                // Handle shutdown
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping QUIC listener");
                    break;
                }
            }
        }

        // Graceful shutdown: wait for existing connections to drain
        info!("Waiting for existing connections to close...");
        self.endpoint.wait_idle().await;

        info!("QUIC listener stopped");
        Ok(())
    }

    /// Handle a single QUIC connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        incoming: quinn::Incoming,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: SecurityState,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
    ) -> anyhow::Result<()> {
        // Accept connection
        let connecting = incoming.accept()?;
        let connection = connecting.await?;

        info!("QUIC connection established: {}", remote_addr);

        // Log ALPN negotiation and record TLS handshake
        metrics.tls.handshake_completed(true, false);
        if let Some(handshake_data) = connection.handshake_data() {
            if let Some(crypto_data) =
                handshake_data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            {
                if let Some(protocol) = &crypto_data.protocol {
                    let alpn = String::from_utf8_lossy(protocol);
                    info!("ALPN negotiated: {} for {}", alpn, remote_addr);
                }
            }
        }

        // Create H3 connection
        let h3_conn = H3Connection::new(connection.clone());

        // Try to establish HTTP/3 connection with WebTransport support enabled
        // This advertises SETTINGS_ENABLE_WEBTRANSPORT=1 to clients
        match h3::server::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1000)
            .build(h3_conn)
            .await
        {
            Ok(mut h3) => {
                // HTTP/3 connection established
                Self::handle_h3_connection(
                    &mut h3,
                    connection,
                    remote_addr,
                    config,
                    backend_pool,
                    early_hints_state,
                    security,
                    metrics,
                    advanced_rate_limiter,
                    load_balancer,
                    cache,
                )
                .await?;
            }
            Err(e) => {
                // Fall back to raw QUIC streams (WebTransport without HTTP/3)
                warn!("HTTP/3 handshake failed, handling raw QUIC streams: {}", e);
                Self::handle_raw_quic(connection, remote_addr, config, backend_pool).await?;
            }
        }

        info!("Connection closed: {}", remote_addr);
        Ok(())
    }

    /// Handle HTTP/3 connection with WebTransport support
    #[allow(clippy::too_many_arguments)]
    async fn handle_h3_connection(
        h3: &mut h3::server::Connection<H3Connection, Bytes>,
        quic_connection: QuinnConnection,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: SecurityState,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
    ) -> anyhow::Result<()> {
        // Lazily created on the first CONNECT-UDP session so connections that
        // never use MASQUE pay nothing for the datagram reader task.
        let mut datagram_router: Option<Arc<DatagramRouter>> = None;
        loop {
            match h3.accept().await {
                Ok(Some(resolver)) => {
                    // Resolve the request
                    let (request, stream) = match resolver.resolve_request().await {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Failed to resolve request: {}", e);
                            continue;
                        }
                    };

                    let method = request.method().clone();
                    let uri = request.uri().clone();
                    let path = if config.server.normalize_paths {
                        uri.path().to_ascii_lowercase()
                    } else {
                        uri.path().to_string()
                    };
                    // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback to host header
                    let host = uri
                        .authority()
                        .map(|a| a.host().to_ascii_lowercase())
                        .or_else(|| {
                            request
                                .headers()
                                .get("host")
                                .and_then(|v| v.to_str().ok())
                                .map(String::from)
                        });

                    // Check for protocol extension (RFC 9220 Extended CONNECT)
                    // In h3 crate, the :protocol pseudo-header is accessed via extensions
                    let protocol_ext = request.extensions().get::<Protocol>();
                    debug!(
                        "HTTP/3 request: {} {} from {} (host: {:?}, :protocol: {:?})",
                        method, path, remote_addr, host, protocol_ext
                    );

                    // Check for WebTransport CONNECT (RFC 9220)
                    // WebTransport uses Extended CONNECT with :protocol = webtransport
                    let is_webtransport = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p == &Protocol::WEB_TRANSPORT)
                            .unwrap_or(false);

                    // RFC 9220: WebSocket over HTTP/3 uses Extended CONNECT with :protocol = websocket
                    let is_ws_h3 = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "websocket")
                            .unwrap_or(false);

                    // RFC 9298: CONNECT-UDP uses Extended CONNECT with :protocol = connect-udp
                    let is_connect_udp = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "connect-udp")
                            .unwrap_or(false);

                    if is_webtransport {
                        info!(
                            "WebTransport CONNECT request for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        // Reject WebTransport sessions for hosts/paths with no matching WT route.
                        // Without this check the proxy accepts every CONNECT unconditionally,
                        // leaving the session open until a 5-second idle timeout fires — which
                        // stalls scanners and health checks on non-WebTransport hosts.
                        // Note: find_route(is_webtransport=true) still returns non-WT routes
                        // (route_matches only prevents WT-only routes matching non-WT requests,
                        // not the reverse), so we must additionally check route.webtransport.
                        let has_wt_route = config
                            .find_route(host.as_deref(), &path, true)
                            .as_ref()
                            .is_some_and(|r| r.webtransport);
                        if !has_wt_route {
                            debug!(
                                "WebTransport CONNECT rejected (no WT route) for {} from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Send 200 OK to accept the WebTransport session
                        // IMPORTANT: Do NOT finish the stream - WebTransport sessions keep it open
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("sec-webtransport-http3-draft", "draft02")
                            .body(())?;

                        // Respond on the stream first
                        let mut stream = stream;
                        if let Err(e) = stream.send_response(response).await {
                            error!(
                                "Failed to send WebTransport response to {}: {}",
                                remote_addr, e
                            );
                            continue;
                        }

                        info!(
                            "WebTransport session accepted for {} on path {}",
                            remote_addr, path
                        );

                        // Track WebTransport session in metrics
                        metrics
                            .connections
                            .connection_opened(ConnectionProtocol::WebTransport);

                        // Handle WebTransport session - pass the stream to the handler
                        // The session handler will manage bidirectional streams and datagrams
                        let handler = WebTransportHandler::new(
                            config.clone(),
                            backend_pool.clone(),
                            remote_addr,
                        );

                        let wt_metrics = metrics.clone();
                        tokio::spawn(async move {
                            debug!(
                                "WebTransport session active for {} on path {}",
                                remote_addr, path
                            );
                            if let Err(e) = handler.handle_session().await {
                                error!("WebTransport session error for {}: {}", remote_addr, e);
                            }
                            wt_metrics.connections.connection_closed();
                        });

                        // NOTE: Stream is intentionally NOT finished here
                        // The WebTransport session keeps it open for bidirectional communication
                        // The session will be closed when the client disconnects or on error
                    } else if is_connect_udp {
                        // RFC 9298: CONNECT-UDP. Relay UDP datagrams between the
                        // client and an allowlisted target host:port.
                        let mut stream = stream;

                        if !config.masque.enabled {
                            debug!("CONNECT-UDP rejected (disabled) from {}", remote_addr);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        let Some((target_host, target_port)) = connect_udp::parse_target(&path)
                        else {
                            debug!(
                                "CONNECT-UDP bad target path '{}' from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        if !config.masque.is_target_allowed(&target_host, target_port) {
                            warn!(
                                "CONNECT-UDP target {}:{} not allowed (from {})",
                                target_host, target_port, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::FORBIDDEN)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Resolve target to a socket address.
                        let resolved = tokio::net::lookup_host((target_host.as_str(), target_port))
                            .await
                            .ok()
                            .and_then(|mut addrs| addrs.next());
                        let Some(target_addr) = resolved else {
                            warn!(
                                "CONNECT-UDP: cannot resolve {}:{} (from {})",
                                target_host, target_port, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        // Start (or reuse) the per-connection datagram router.
                        let router = datagram_router
                            .get_or_insert_with(|| DatagramRouter::new(quic_connection.clone()))
                            .clone();

                        if router.session_count().await >= config.masque.max_sessions_per_connection
                        {
                            warn!("CONNECT-UDP: session limit reached for {}", remote_addr);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Quarter Stream ID = request stream id / 4 (RFC 9297).
                        let quarter_id = stream.id().into_inner() / 4;
                        let from_client = router.register_session(quarter_id).await;

                        // Accept the session (RFC 9298 §3: 2xx).
                        let accept = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())?;
                        if let Err(e) = stream.send_response(accept).await {
                            error!("CONNECT-UDP: failed to accept for {}: {}", remote_addr, e);
                            router.unregister_session(quarter_id).await;
                            continue;
                        }

                        info!(
                            "CONNECT-UDP session opened: {} -> {} (qsid={})",
                            remote_addr, target_addr, quarter_id
                        );
                        metrics
                            .connections
                            .connection_opened(ConnectionProtocol::WebTransport);

                        let idle =
                            Duration::from_secs(config.masque.session_idle_timeout_secs.max(1));
                        let conn_clone = quic_connection.clone();
                        let metrics_clone = metrics.clone();
                        tokio::spawn(async move {
                            // The request stream stays open for the session; reading it
                            // to end (FIN/RESET) signals the client closed the tunnel.
                            let (_send, mut recv) = stream.split();
                            let stream_closed = async move {
                                // Drain any capsule data; FIN/RESET ends the loop.
                                while let Ok(Some(_)) = recv.recv_data().await {}
                            };
                            connect_udp::run_session(
                                router,
                                conn_clone,
                                quarter_id,
                                target_addr,
                                idle,
                                from_client,
                                stream_closed,
                            )
                            .await;
                            metrics_clone.connections.connection_closed();
                        });
                    } else if is_ws_h3 {
                        // RFC 9220: WebSocket-over-HTTP/3 extended CONNECT tunnel.
                        // Respond with 200 OK (not 101), then bridge the HTTP/3 bidi stream
                        // to a plain HTTP/1.1 WebSocket upgrade on the backend.
                        info!(
                            "WS/H3 extended CONNECT for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        let ws_route = config
                            .find_route(host.as_deref(), &path, false)
                            .filter(|r| r.supports_websocket);

                        let Some(route) = ws_route else {
                            debug!(
                                "WS/H3 CONNECT rejected (no ws route) for {} from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        let backend_address = match config.get_backend(&route.backend) {
                            Some(b) => b.address.clone(),
                            None => {
                                error!("WS/H3: backend not found: {}", route.backend);
                                let err_resp = http::Response::builder()
                                    .status(http::StatusCode::BAD_GATEWAY)
                                    .body(())?;
                                let mut stream = stream;
                                let _ = stream.send_response(err_resp).await;
                                continue;
                            }
                        };

                        let req_headers = request.headers().clone();
                        let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
                        let idle_secs = route.ws_idle_timeout_secs;
                        let path_ws = path.clone();
                        let host_ws = host.clone().unwrap_or_default();

                        tokio::spawn(async move {
                            if let Err(e) = ws_h3_tunnel(
                                stream,
                                backend_address,
                                req_headers,
                                path_ws,
                                query,
                                host_ws,
                                idle_secs,
                            )
                            .await
                            {
                                debug!("WS/H3 tunnel ended: {}", e);
                            }
                        });
                    } else {
                        // Regular HTTP/3 request
                        let config_clone = config.clone();
                        let backend_pool_clone = backend_pool.clone();
                        let early_hints_clone = early_hints_state.clone();
                        let metrics_clone = metrics.clone();
                        let security_clone = security.clone();
                        let rl_clone = advanced_rate_limiter.clone();
                        let lb_clone = load_balancer.clone();
                        let cache_clone = cache.clone();

                        tokio::spawn(async move {
                            // Note: health check detection happens inside handle_h3_request
                            if let Err(e) = Self::handle_h3_request(
                                stream,
                                request,
                                remote_addr,
                                config_clone,
                                backend_pool_clone,
                                early_hints_clone,
                                security_clone,
                                metrics_clone,
                                rl_clone,
                                lb_clone,
                                cache_clone,
                            )
                            .await
                            {
                                error!("HTTP/3 request error: {}", e);
                            }
                        });
                    }
                }
                Ok(None) => {
                    debug!("HTTP/3 connection closed by peer: {}", remote_addr);
                    break;
                }
                Err(e) => {
                    error!("HTTP/3 accept error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single HTTP/3 request
    #[allow(clippy::too_many_arguments)]
    async fn handle_h3_request<S>(
        mut stream: h3::server::RequestStream<S, Bytes>,
        request: http::Request<()>,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: SecurityState,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
    ) -> anyhow::Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let start_time = std::time::Instant::now();
        let uri = request.uri();
        let path = if config.server.normalize_paths {
            uri.path().to_ascii_lowercase()
        } else {
            uri.path().to_string()
        };
        let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
        let path_with_query = format!("{}{}", path, query);
        let method = request.method().to_string();
        // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback to host header
        let host = uri
            .authority()
            .map(|a| a.host().to_ascii_lowercase())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            });
        let user_agent = request
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let referer = request
            .headers()
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let is_health_check = request
            .headers()
            .get("x-health-check-bypass")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "1")
            .unwrap_or(false);

        if !is_health_check {
            metrics.requests.request_start();
        }

        info!(
            "HTTP/3 request: {} {} host={:?} from {}",
            method, path, host, remote_addr
        );

        // Per-request security checks: mirrors security_middleware applied on the TCP path.
        // Connection-level blocking (IP blocklist + GeoIP) is enforced at accept time, but
        // the blocklist may grow while a connection is live, so we re-check here.
        let ip = remote_addr.ip();
        if !security.is_trusted(&ip) {
            // 1. Re-check IP blocklist (IP may have been blocked after connection was accepted).
            if let Some(block_info) = security.is_blocked(&ip) {
                warn!(
                    "[QUIC/H3] Blocked request from {} (reason: {:?})",
                    ip, block_info.reason
                );
                metrics.requests.request_end_full(
                    403,
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                let retry_after = block_info
                    .expires_at
                    .map(|e| {
                        let now = std::time::Instant::now();
                        if e > now {
                            e.duration_since(now).as_secs()
                        } else {
                            0
                        }
                    })
                    .unwrap_or(3600);
                let response = http::Response::builder()
                    .status(http::StatusCode::FORBIDDEN)
                    .header("retry-after", retry_after.to_string())
                    .header("server", SERVER_HEADER)
                    .body(())?;
                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }

            // 2. Per-IP rate limiting.
            let (rate_enabled, rate_rps) = {
                let rc = security.rate_config.read();
                (rc.enabled, rc.requests_per_second)
            };
            let (auto_block_threshold, auto_block_duration_secs) = {
                let sc = security.config.read();
                (sc.auto_block_threshold, sc.auto_block_duration_secs)
            };
            if rate_enabled {
                let rate_limiter = security.get_ip_rate_limiter(ip);
                if rate_limiter.check().is_err() {
                    warn!("[QUIC/H3] Rate limit exceeded for {}", ip);
                    let mut counter = security.request_counts.entry(ip).or_default();
                    counter.suspicious_patterns += 1;
                    if counter.suspicious_patterns >= auto_block_threshold {
                        drop(counter);
                        security.block_ip(
                            ip,
                            BlockReason::RateLimitExceeded,
                            Some(Duration::from_secs(auto_block_duration_secs)),
                        );
                    }
                    metrics.requests.request_end_full(
                        429,
                        start_time.elapsed(),
                        0,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    // CORS headers on 429 so browsers see the status code
                    const CORS_ORIGINS: &[&str] =
                        &["https://pqcrypta.com", "https://www.pqcrypta.com"];
                    let req_origin = request
                        .headers()
                        .get("origin")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let mut builder = http::Response::builder()
                        .status(http::StatusCode::TOO_MANY_REQUESTS)
                        .header("retry-after", "1")
                        .header("x-ratelimit-limit", rate_rps.to_string())
                        .header("x-ratelimit-remaining", "0")
                        .header("server", SERVER_HEADER);
                    if CORS_ORIGINS.contains(&req_origin) {
                        builder = builder
                            .header("access-control-allow-origin", req_origin)
                            .header("access-control-allow-credentials", "true")
                            .header("vary", "Origin");
                    }
                    let response = builder.body(())?;
                    stream.send_response(response).await?;
                    stream.finish().await?;
                    return Ok(());
                }
            }

            // 3. Advanced multi-dimensional rate limiting (same logic as TCP path).
            {
                let ja3_hash = request
                    .headers()
                    .get("x-ja3-hash")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let ja4_hash = request
                    .headers()
                    .get("x-ja4-hash")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);
                let adv_ctx = build_context_from_request(
                    ip,
                    request.headers(),
                    &path,
                    &method,
                    ja3_hash,
                    ja4_hash,
                    None,
                );
                match advanced_rate_limiter.check(&adv_ctx).await {
                    RateLimitResult::Allowed { .. } => {}
                    RateLimitResult::Limited {
                        reason,
                        retry_after_ms,
                        limit,
                    } => {
                        warn!(
                            "[QUIC/H3] Advanced rate limit exceeded for {} (reason: {:?})",
                            ip, reason
                        );
                        metrics.requests.request_end_full(
                            429,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        // CORS headers on 429 so browsers see the status code
                        const CORS_ORIGINS_ADV: &[&str] =
                            &["https://pqcrypta.com", "https://www.pqcrypta.com"];
                        let req_origin_adv = request
                            .headers()
                            .get("origin")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let retry_secs = (retry_after_ms / 1000).max(1);
                        let mut builder_adv = http::Response::builder()
                            .status(http::StatusCode::TOO_MANY_REQUESTS)
                            .header("retry-after", retry_secs.to_string())
                            .header("x-ratelimit-limit", limit.to_string())
                            .header("x-ratelimit-remaining", "0")
                            .header(
                                "x-ratelimit-reason",
                                format!("{:?}", reason).to_ascii_lowercase(),
                            )
                            .header("server", SERVER_HEADER);
                        if CORS_ORIGINS_ADV.contains(&req_origin_adv) {
                            builder_adv = builder_adv
                                .header("access-control-allow-origin", req_origin_adv)
                                .header("access-control-allow-credentials", "true")
                                .header("vary", "Origin");
                        }
                        let response = builder_adv.body(())?;
                        stream.send_response(response).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                    RateLimitResult::Blocked { reason } => {
                        warn!(
                            "[QUIC/H3] Advanced rate limiter blocked {} (reason: {})",
                            ip, reason
                        );
                        metrics.requests.request_end_full(
                            403,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::FORBIDDEN)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        stream.send_response(response).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                }
            }

            // 4. Header size validation.
            let max_header_size = security.config.read().max_header_size;
            let header_size: usize = request
                .headers()
                .iter()
                .map(|(k, v)| k.as_str().len() + v.len())
                .sum();
            if header_size > max_header_size {
                warn!(
                    "[QUIC/H3] Headers too large from {}: {} bytes",
                    ip, header_size
                );
                metrics.requests.request_end_full(
                    431,
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                let response = http::Response::builder()
                    .status(http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
                    .header("server", SERVER_HEADER)
                    .body(())?;
                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }
        }

        // Send 103 Early Hints if enabled and we have hints for this path
        // This is a key HTTP/3 optimization - send resource hints before proxying to backend
        // Only send for GET/HEAD requests - 103 on POST/PUT/DELETE can break cookie handling
        if early_hints_state.is_enabled() && (method == "GET" || method == "HEAD") {
            let hints =
                early_hints_state.get_hints_for_request(host.as_deref().unwrap_or(""), &path);
            if !hints.is_empty() {
                // Build 103 Early Hints response with Link headers and alt-svc for QUIC advertisement
                let mut early_response_builder = http::Response::builder()
                    .status(http::StatusCode::EARLY_HINTS)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .header("server", SERVER_HEADER);

                for hint in &hints {
                    early_response_builder = early_response_builder.header("link", hint.as_str());
                }

                if let Ok(early_response) = early_response_builder.body(()) {
                    match tokio::time::timeout(
                        Duration::from_millis(50),
                        stream.send_response(early_response),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            debug!(
                                "Sent 103 Early Hints to {} with {} link hints",
                                remote_addr,
                                hints.len()
                            );
                        }
                        Ok(Err(e)) => {
                            debug!(
                                "Failed to send 103 Early Hints to {}: {} (continuing with request)",
                                remote_addr, e
                            );
                        }
                        Err(_) => {
                            debug!(
                                "103 Early Hints timed out for {} (QUIC window full, continuing)",
                                remote_addr
                            );
                        }
                    }
                }
            }
        }

        // ── Speedtest: direct download streaming (H3) ─────────────────────────
        // The default proxy path buffers the entire PHP response before sending —
        // for 12 parallel 100 MB streams that's 1.2 GB RAM and a ~10× throughput
        // hit. Intercept here and stream bytes directly over H3 without PHP.
        if path == "/speedtest/tcp-download.php" && (method == "GET" || method == "HEAD") {
            let bytes_requested: u64 = uri
                .query()
                .and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next()? == "bytes" {
                            parts.next()?.parse().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(10 * 1024 * 1024);
            let bytes_to_send: u64 = bytes_requested.clamp(65_536, 100 * 1024 * 1024);

            let dl_start = std::time::Instant::now();
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .header("content-length", bytes_to_send.to_string())
                .header("cache-control", "no-store")
                .header("x-content-type-options", "nosniff")
                .header("server", SERVER_HEADER)
                .body(())?;
            stream.send_response(response).await?;

            if method != "HEAD" {
                // 256 KB chunk — pseudo-random bytes (LCG); QUIC doesn't compress
                // data payloads so any pattern gives accurate bandwidth measurement.
                const CHUNK: usize = 256 * 1024;
                let mut chunk_buf = vec![0u8; CHUNK];
                let mut lcg: u64 = 0xdead_beef_cafe_babe;
                for b in chunk_buf.iter_mut() {
                    lcg = lcg
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    *b = u8::try_from(lcg >> 56 & 0xFF).unwrap_or(0);
                }
                let chunk_bytes = Bytes::from(chunk_buf);

                let mut remaining = bytes_to_send as usize;
                while remaining > 0 {
                    let n = remaining.min(CHUNK);
                    // Client cancels when the time limit hits — that's normal; just stop.
                    if stream
                        .send_data(if n == CHUNK {
                            chunk_bytes.clone()
                        } else {
                            chunk_bytes.slice(..n)
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                    remaining -= n;
                }
            }

            let _ = stream.finish().await; // ignore error if client already cancelled
            let elapsed = dl_start.elapsed();
            info!(
                "[speedtest-dl/h3] sent {} bytes in {:.2}s from {}",
                bytes_to_send,
                elapsed.as_secs_f64(),
                remote_addr
            );
            metrics.requests.request_end_full(
                200,
                elapsed,
                0,
                bytes_to_send,
                Some(&path),
                is_health_check,
            );
            return Ok(());
        }

        // ── Speedtest: server-side upload measurement ─────────────────────────
        // Chrome upgrades all pqcrypta.com:443 requests to HTTP/3 via cached Alt-Svc,
        // so the "TCP" upload stream arrives here. Count bytes received; the client
        // uses the known test duration as the time denominator — no server-side timing.
        if path == "/speedtest/tcp-upload-stream" && method == "POST" {
            let measure_start = std::time::Instant::now();
            let mut total_bytes: u64 = 0;
            let mut chunk_count: u64 = 0;

            loop {
                match stream.recv_data().await {
                    Ok(None) => break,
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        chunk.advance(n);
                        total_bytes += n as u64;
                        chunk_count += 1;
                    }
                    Err(_) => break,
                }
            }

            let total_elapsed = measure_start.elapsed();
            info!(
                "[speedtest-upload/h3] {} bytes in {:.2}s ({} chunks) from {}",
                total_bytes,
                total_elapsed.as_secs_f64(),
                chunk_count,
                remote_addr
            );
            // Return bytes_received only — client divides by the known test duration
            // for an accurate mbps figure with no server-side timing complexity.
            let steady_mbps = 0.0_f64; // unused; client computes from bytes + duration
            let duration_ms = total_elapsed.as_millis().try_into().unwrap_or(u64::MAX);

            info!(
                "[speedtest-upload/h3] result: bytes={} steady_mbps={:.2} duration_ms={} from {}",
                total_bytes, steady_mbps, duration_ms, remote_addr
            );
            let json = format!(
                r#"{{"ok":true,"bytes_received":{},"duration_ms":{},"steady_mbps":{:.2},"throughput_mbps":{:.2}}}"#,
                total_bytes, duration_ms, steady_mbps, steady_mbps,
            );
            let json_bytes = Bytes::from(json);
            let json_len = json_bytes.len();

            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/json")
                .header("content-length", json_len.to_string())
                .header("cache-control", "no-store")
                .header("server", SERVER_HEADER)
                .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                .body(())?;
            stream.send_response(response).await?;
            stream.send_data(json_bytes).await?;
            stream.finish().await?;

            metrics.requests.request_end_full(
                200,
                total_elapsed,
                total_bytes,
                json_len as u64,
                Some(&path),
                is_health_check,
            );
            return Ok(());
        }
        // ── End speedtest upload handler ───────────────────────────────────────

        // Find route first so we can use per-route CORS config
        let route = match config.find_route(host.as_deref(), &path, false) {
            Some(r) => {
                let route_name = r.name.as_deref().unwrap_or("unnamed");
                info!(
                    "HTTP/3 route matched: {} -> backend {}",
                    route_name, r.backend
                );
                r
            }
            None => {
                warn!("HTTP/3 no route found for host={:?} path={}", host, path);
                // Log 404 response
                log_access(&AccessLogEntry {
                    remote_addr,
                    method: method.clone(),
                    path: path.clone(),
                    protocol: "HTTP/3".to_string(),
                    status: 404,
                    body_size: 0,
                    referer: referer.clone(),
                    user_agent: user_agent.clone(),
                    host: host.clone(),
                    response_time_ms: start_time
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                });
                metrics.requests.request_end_full(
                    404,
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                // Return 404 — include Alt-Svc so tcp_only_hosts origins
                // receive "clear" and the browser stops upgrading to HTTP/3.
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .header("server", SERVER_HEADER)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .body(())?;

                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }
        };

        // Handle CORS preflight OPTIONS requests using route.cors
        if request.method() == http::Method::OPTIONS {
            if let Some(ref cors) = route.cors {
                let mut response_builder = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .header("server", SERVER_HEADER);

                // Access-Control-Allow-Origin — reflect when allow_origins list is set
                let req_origin_str = request
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                let resolved_origin = if !cors.allow_origins.is_empty() {
                    req_origin_str
                        .filter(|o| cors.allow_origins.iter().any(|a| a == *o))
                        .map(String::from)
                } else {
                    cors.allow_origin.clone()
                };
                if let Some(ref origin) = resolved_origin {
                    response_builder =
                        response_builder.header("access-control-allow-origin", origin);
                }

                // Access-Control-Allow-Methods
                if !cors.allow_methods.is_empty() {
                    let methods = cors.allow_methods.join(", ");
                    response_builder =
                        response_builder.header("access-control-allow-methods", methods);
                }

                // Access-Control-Allow-Headers
                if !cors.allow_headers.is_empty() {
                    let hdrs = cors.allow_headers.join(", ");
                    response_builder =
                        response_builder.header("access-control-allow-headers", hdrs);
                }

                // Access-Control-Allow-Credentials
                if cors.allow_credentials {
                    response_builder =
                        response_builder.header("access-control-allow-credentials", "true");
                }

                // Access-Control-Max-Age
                if cors.max_age > 0 {
                    response_builder =
                        response_builder.header("access-control-max-age", cors.max_age.to_string());
                }

                let response = response_builder.body(())?;
                stream.send_response(response).await?;
                stream.finish().await?;
                metrics.requests.request_end_full(
                    200,
                    start_time.elapsed(),
                    0,
                    0,
                    None,
                    is_health_check,
                );
                return Ok(());
            }
            // If no CORS config, fall through to normal handling / backend
        }

        // Pool-aware backend selection: supports canary routing and load balancing.
        // Falls back to direct backend config lookup if no matching pool is configured.
        let (backend, canary_cookie_to_set): (BackendConfig, Option<String>) = {
            // Extract cookies from request headers for sticky session / canary routing
            let cookie_str = request
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if let Some(pool) = load_balancer.get_pool(&route.backend) {
                // Determine canary sticky cookie name from pool config (default "PQCPROXY_CANARY")
                let canary_cookie_name = pool
                    .canary_config
                    .as_ref()
                    .map(|c| c.sticky_cookie_name.clone())
                    .unwrap_or_else(|| "PQCPROXY_CANARY".to_string());

                // Extract canary cookie value from cookie header
                let canary_cookie_val = cookie_str.split(';').find_map(|part| {
                    let part = part.trim();
                    part.strip_prefix(&format!("{}=", canary_cookie_name))
                        .map(|v| v.to_string())
                });

                // Extract canary sticky header value if pool has one configured
                let canary_header_val = pool
                    .canary_config
                    .as_ref()
                    .and_then(|c| c.sticky_header.as_deref())
                    .and_then(|hdr_name| {
                        request
                            .headers()
                            .get(hdr_name)
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string())
                    });

                // Extract session affinity cookie
                let session_cookie_val = cookie_str.split(';').find_map(|part| {
                    let part = part.trim();
                    // Generic session cookie extraction – key=value
                    if part.contains('=') {
                        let (k, v) = part.split_once('=').unwrap_or(("", ""));
                        if !k.starts_with("PQCPROXY_CANARY") {
                            return Some(v.to_string());
                        }
                    }
                    None
                });

                let ctx = SelectionContext {
                    client_ip: remote_addr.ip(),
                    session_cookie: session_cookie_val,
                    affinity_header: None,
                    path: path.clone(),
                    host: host.clone().unwrap_or_default(),
                    canary_cookie: canary_cookie_val,
                    canary_header: canary_header_val,
                };

                match pool.select(&ctx) {
                    Some(result) => {
                        let server = &result.server;
                        let tls = matches!(server.tls_mode, crate::config::TlsMode::Reencrypt);
                        let cfg = BackendConfig {
                            name: server.id.clone(),
                            backend_type: BackendType::Http1,
                            address: server.address.to_string(),
                            tls_mode: server.tls_mode.clone(),
                            tls,
                            tls_cert: None,
                            tls_client_cert: None,
                            tls_client_key: None,
                            tls_skip_verify: false,
                            tls_sni: None,
                            timeout_ms: u64::try_from(server.timeout.as_millis())
                                .unwrap_or(u64::MAX),
                            max_connections: server.max_connections,
                            health_check: None,
                            health_check_interval_secs: 30,
                            retries: None,
                            retry_backoff_ms: None,
                            retry_on: None,
                            circuit_breaker: None,
                        };
                        (cfg, result.set_canary_cookie)
                    }
                    None => {
                        error!("No healthy server available in pool: {}", route.backend);
                        metrics.requests.request_end_full(
                            503,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::SERVICE_UNAVAILABLE)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        stream.send_response(response).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                }
            } else {
                match config.get_backend(&route.backend) {
                    Some(b) => (b.clone(), None),
                    None => {
                        error!("Backend not found: {}", route.backend);
                        metrics.requests.request_end_full(
                            502,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::BAD_GATEWAY)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        stream.send_response(response).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                }
            }
        };

        // Read request body — handle recv_data errors gracefully so a single
        // stream error (e.g. QUIC flow-control exhaustion on large uploads) does
        // not propagate up and kill the entire QUIC connection.
        let mut body = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(None) => break, // body fully received
                Ok(Some(mut chunk)) => {
                    while chunk.has_remaining() {
                        let bytes = chunk.chunk();
                        body.extend_from_slice(bytes);
                        chunk.advance(bytes.len());
                    }
                    if body.len() > config.security.max_request_size {
                        metrics.requests.request_end_full(
                            413,
                            start_time.elapsed(),
                            body.len() as u64,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                            .body(())?;

                        stream.send_response(response).await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    // Stream-level error (flow-control, reset, etc.) — respond 500
                    // and return Ok so the QUIC connection stays alive for other streams.
                    debug!("QUIC recv_data error on {} {}: {}", method, path, e);
                    metrics.requests.request_end_full(
                        500,
                        start_time.elapsed(),
                        body.len() as u64,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    if let Ok(response) = http::Response::builder()
                        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(())
                    {
                        let _ = stream.send_response(response).await;
                        let _ = stream.finish().await;
                    }
                    return Ok(());
                }
            }
        }

        // --- Response cache lookup (GET / HEAD only, HTTP/3 path) ---
        // Range requests bypass the cache entirely: the cache stores whole responses
        // and must hand range requests to the backend so they get a correct 206 with
        // a matching Content-Range, rather than a cached full 200 body.
        let cache_host_str = host.as_deref().unwrap_or("");
        let is_range_request = request.headers().contains_key("range");
        if (method == "GET" || method == "HEAD")
            && !is_range_request
            && cache.config.enabled
            && !cache.is_excluded_path(&path)
            && !cache.is_excluded_host(cache_host_str)
        {
            let host_str = cache_host_str;
            let cache_key = ResponseCache::build_key(&method, host_str, &path_with_query);
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
                    headers: cached_headers,
                    body: cached_body,
                    age_secs,
                } => {
                    debug!(
                        "HTTP/3 cache HIT: {} {} (age {}s)",
                        method, path_with_query, age_secs
                    );
                    let status_code =
                        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
                    let mut response_builder = http::Response::builder()
                        .status(status_code)
                        .header("age", age_secs.to_string())
                        .header("x-cache", "HIT")
                        .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                        .header("server", SERVER_HEADER);
                    for (k, v) in &cached_headers {
                        // Skip headers the proxy sets itself in this block. The cached
                        // entry holds the raw backend headers, so replaying `server`
                        // would emit a second `server: <backend>` alongside our own
                        // SERVER_HEADER — duplicate `server` values that leak the backend
                        // identity and shadow ours for some HTTP/3 clients. Same for
                        // alt-svc/age/x-cache/content-length which are set above.
                        let lk = k.to_lowercase();
                        if matches!(
                            lk.as_str(),
                            "content-length" | "server" | "alt-svc" | "age" | "x-cache"
                        ) {
                            continue;
                        }
                        response_builder = response_builder.header(k.as_str(), v.as_str());
                    }
                    let body_bytes: Vec<u8> = if method == "HEAD" {
                        Vec::new()
                    } else {
                        (*cached_body).clone()
                    };
                    response_builder =
                        response_builder.header("content-length", body_bytes.len().to_string());
                    let response = response_builder.body(())?;
                    let body_size = body_bytes.len();
                    let latency = start_time.elapsed();
                    stream.send_response(response).await?;
                    if !body_bytes.is_empty() {
                        stream.send_data(Bytes::from(body_bytes)).await?;
                    }
                    stream.finish().await?;
                    metrics.requests.request_end_full(
                        status,
                        latency,
                        body.len() as u64,
                        body_size as u64,
                        Some(&path),
                        is_health_check,
                    );
                    log_access(&AccessLogEntry {
                        remote_addr,
                        method,
                        path,
                        protocol: "HTTP/3".to_string(),
                        status,
                        body_size,
                        referer,
                        user_agent,
                        host,
                        response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                    return Ok(());
                }

                CacheLookup::NotModified {
                    etag,
                    last_modified,
                    cache_control,
                    age_secs,
                } => {
                    debug!(
                        "HTTP/3 cache 304: {} {} (age {}s)",
                        method, path_with_query, age_secs
                    );
                    let mut response_builder = http::Response::builder()
                        .status(http::StatusCode::NOT_MODIFIED)
                        .header("age", age_secs.to_string())
                        .header("x-cache", "HIT")
                        .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                        .header("server", SERVER_HEADER);
                    if let Some(et) = etag {
                        response_builder = response_builder.header("etag", et);
                    }
                    if let Some(lm) = last_modified {
                        response_builder = response_builder.header("last-modified", lm);
                    }
                    if let Some(cc) = cache_control {
                        response_builder = response_builder.header("cache-control", cc);
                    }
                    let response = response_builder.body(())?;
                    let latency = start_time.elapsed();
                    stream.send_response(response).await?;
                    stream.finish().await?;
                    metrics.requests.request_end_full(
                        304,
                        latency,
                        body.len() as u64,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    log_access(&AccessLogEntry {
                        remote_addr,
                        method,
                        path,
                        protocol: "HTTP/3".to_string(),
                        status: 304,
                        body_size: 0,
                        referer,
                        user_agent,
                        host,
                        response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                    return Ok(());
                }

                CacheLookup::Miss => {}
            }
        }

        // Build headers map - start with route-specific headers
        let mut headers = route.add_headers.clone();

        // Forward original request headers (excluding hop-by-hop headers)
        for (name, value) in request.headers().iter() {
            let name_lower = name.as_str().to_lowercase();
            // Skip hop-by-hop headers and pseudo-headers
            if !matches!(
                name_lower.as_str(),
                "host"
                    | "connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
            ) && !name_lower.starts_with(':')
            {
                if let Ok(value_str) = value.to_str() {
                    if name_lower == "cookie" {
                        // HTTP/3 splits Cookie across multiple header fields (RFC 9114 §4.2.1).
                        // Combine them with "; " so the HTTP/1.1 backend sees one Cookie header.
                        headers
                            .entry("cookie".to_string())
                            .and_modify(|existing| {
                                *existing = format!("{}; {}", existing, value_str);
                            })
                            .or_insert_with(|| value_str.to_string());
                    } else {
                        headers.insert(name.as_str().to_string(), value_str.to_string());
                    }
                }
            }
        }

        // Forward Host header to backend (required for virtual host routing)
        if let Some(ref host_value) = host {
            headers.insert("Host".to_string(), host_value.clone());
        }

        // Extract distributed trace context from the incoming QUIC/HTTP3 request
        // headers and stitch this request into the caller's trace.  The current
        // span becomes a child of the caller's span; proxy.rs then injects the
        // new child span context into the upstream backend request.
        otel::set_parent_from_map(&tracing::Span::current(), &headers);

        // Forward X-Forwarded headers
        headers.insert("X-Forwarded-Proto".to_string(), "https".to_string());
        headers.insert("X-Forwarded-For".to_string(), remote_addr.ip().to_string());
        headers.insert("X-Real-IP".to_string(), remote_addr.ip().to_string());

        if route.forward_client_identity {
            let header_name = route
                .client_identity_header
                .as_deref()
                .unwrap_or("X-Client-IP");
            headers.insert(header_name.to_string(), remote_addr.ip().to_string());
        }

        // Traffic shadowing: fire-and-forget async copy to shadow backend (if configured)
        if let Some(ref shadow_cfg) = route.shadow {
            if !shadow_cfg.backend.is_empty() && shadow_cfg.percent > 0 {
                let roll: u8 = rand::random::<u8>() % 100;
                if roll < shadow_cfg.percent.min(100) {
                    if let Some(shadow_backend) = config.get_backend(&shadow_cfg.backend).cloned() {
                        let mut shadow_headers = headers.clone();
                        shadow_headers.insert(
                            shadow_cfg.shadow_header.clone(),
                            shadow_cfg.shadow_header_value.clone(),
                        );
                        let shadow_body = body.clone();
                        let shadow_method = method.clone();
                        let shadow_path = path_with_query.clone();
                        let shadow_bp = backend_pool.clone();
                        let shadow_timeout_ms = shadow_cfg.timeout_ms;
                        let shadow_log = shadow_cfg.log_responses;
                        let shadow_name = shadow_cfg.backend.clone();
                        tokio::task::spawn(async move {
                            let result = tokio::time::timeout(
                                Duration::from_millis(shadow_timeout_ms),
                                shadow_bp.proxy_http_full(
                                    &shadow_backend,
                                    &shadow_method,
                                    &shadow_path,
                                    shadow_headers,
                                    &shadow_body,
                                ),
                            )
                            .await;
                            match result {
                                Ok(Ok(resp)) if shadow_log => {
                                    info!("H3 Shadow → '{}' status={}", shadow_name, resp.status);
                                }
                                Ok(Ok(_)) => {}
                                Ok(Err(e)) => {
                                    warn!("H3 Shadow error for '{}': {}", shadow_name, e);
                                }
                                Err(_) => {
                                    warn!("H3 Shadow timeout for '{}'", shadow_name);
                                }
                            }
                        });
                    } else {
                        warn!(
                            "H3 Shadow backend '{}' not found in config",
                            shadow_cfg.backend
                        );
                    }
                }
            }
        }

        // Proxy to backend (include query string in path).
        // Use the streaming path for all requests: inspect content-type from response
        // headers to decide whether to pump chunks (SSE) or buffer (everything else).
        let (stream_status, stream_headers, stream_body) = backend_pool
            .proxy_http_stream(
                &backend,
                request.method().as_str(),
                &path_with_query,
                headers,
                &body,
            )
            .await?;

        let is_sse = stream_headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("content-type") && v.contains("text/event-stream")
        });

        // SSE fast path: send headers immediately, then pump body frames as they arrive.
        if is_sse {
            let mut sse_builder = http::Response::builder()
                .status(http::StatusCode::from_u16(stream_status).unwrap_or(http::StatusCode::OK));
            for (name, value) in &stream_headers {
                let lower = name.to_ascii_lowercase();
                // Skip content-length (SSE has no fixed length) and hop-by-hop headers
                if lower == "content-length" || lower == "transfer-encoding" {
                    continue;
                }
                sse_builder = sse_builder.header(name, value);
            }
            sse_builder = sse_builder.header("cache-control", "no-cache");
            sse_builder = sse_builder.header("server", SERVER_HEADER);
            sse_builder = sse_builder.header("alt-svc", alt_svc_for_host(&config, host.as_deref()));
            stream.send_response(sse_builder.body(())?).await?;

            let mut body_stream = stream_body;
            while let Some(frame_result) = body_stream.frame().await {
                match frame_result {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            if !data.is_empty() {
                                stream.send_data(data.clone()).await?;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            stream.finish().await?;

            metrics.requests.request_end_full(
                stream_status,
                start_time.elapsed(),
                body.len() as u64,
                0,
                Some(&path),
                is_health_check,
            );
            log_access(&AccessLogEntry {
                remote_addr,
                method,
                path,
                protocol: "HTTP/3".to_string(),
                status: stream_status,
                body_size: 0,
                referer,
                user_agent,
                host,
                response_time_ms: start_time
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            });
            return Ok(());
        }

        // Non-SSE: buffer the body we already started receiving.
        let body_bytes = stream_body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
            .to_bytes();
        let proxy_response = crate::proxy::ProxyResponse {
            status: stream_status,
            headers: stream_headers,
            body: body_bytes.to_vec(),
        };

        // Store response in cache (GET / HEAD only; cache.put() enforces all Cache-Control rules)
        if (method == "GET" || method == "HEAD")
            && cache.config.enabled
            && !cache.is_excluded_path(&path)
            && !cache.is_excluded_host(cache_host_str)
        {
            let host_str = cache_host_str;
            let cache_key = ResponseCache::build_key(&method, host_str, &path_with_query);
            cache.put(
                &cache_key,
                proxy_response.status,
                &proxy_response.headers,
                proxy_response.body.clone(),
            );
        }

        // Build HTTP/3 response with headers from backend
        let mut response_builder = http::Response::builder().status(
            http::StatusCode::from_u16(proxy_response.status).unwrap_or(http::StatusCode::OK),
        );

        // Forward selected headers from backend (including CORS if backend sets them)
        // Note: x-content-type-options excluded from whitelist since proxy adds its own
        // Note: set-cookie for /grafana is handled separately below with Domain rewriting
        let is_grafana = path.starts_with("/grafana");
        for (name, value) in &proxy_response.headers {
            let lower_name = name.to_lowercase();
            // Skip set-cookie for Grafana routes (handled below with Domain attribute)
            if is_grafana && lower_name == "set-cookie" {
                continue;
            }
            if matches!(
                lower_name.as_str(),
                "content-type"
                    | "cache-control"
                    | "etag"
                    | "last-modified"
                    | "content-language"
                    | "content-encoding"
                    | "content-range"
                    | "accept-ranges"
                    | "content-disposition"
                    | "vary"
                    | "set-cookie"
                    | "location"
                    | "access-control-allow-origin"
                    | "access-control-allow-methods"
                    | "access-control-allow-headers"
                    | "access-control-allow-credentials"
                    | "access-control-expose-headers"
                    | "access-control-max-age"
            ) {
                response_builder = response_builder.header(name, value);
            }
        }

        // Add content-length from known body size (helps browsers finalize responses)
        response_builder =
            response_builder.header("content-length", proxy_response.body.len().to_string());

        // For Grafana routes: rewrite set-cookie headers from backend
        // to work around browser H3 cookie handling by adding Domain attribute
        if path.starts_with("/grafana") {
            // Remove set-cookie from whitelist-forwarded headers (already added above)
            // and re-add with explicit Domain to help browser cookie storage
            let mut has_cookies = false;
            for (name, value) in &proxy_response.headers {
                if name.to_lowercase() == "set-cookie" {
                    has_cookies = true;
                    // Add Domain=pqcrypta.com to help browser store cookie
                    let with_domain = if !value.contains("Domain=") {
                        format!("{}; Domain=pqcrypta.com", value)
                    } else {
                        value.clone()
                    };
                    response_builder = response_builder.header("set-cookie", with_domain.as_str());
                }
            }
            if has_cookies {
                // Also add a simple proxy test cookie to verify H3 cookie delivery
                response_builder = response_builder.header(
                    "set-cookie",
                    "pqc_h3_test=1; Path=/; Secure; SameSite=None; Max-Age=3600",
                );
            }
        }

        // Inject canary sticky cookie if pool selection assigned one
        if let Some(ref cookie_header) = canary_cookie_to_set {
            response_builder = response_builder.header("set-cookie", cookie_header.as_str());
        }

        // Add Alt-Svc header to advertise HTTP/3 support
        response_builder =
            response_builder.header("alt-svc", alt_svc_for_host(&config, host.as_deref()));

        // Add Server header for branding (hide backend identity)
        response_builder = response_builder.header("server", SERVER_HEADER);

        // ═══════════════════════════════════════════════════════════════
        // HTTP/3 Performance & Monitoring Headers
        // ═══════════════════════════════════════════════════════════════

        // Server-Timing header - Performance metrics for DevTools
        if config.headers.server_timing_enabled {
            let processing_time = start_time.elapsed();
            let server_timing = format!(
                "proxy;dur={:.2};desc=\"PQ Crypta Processing\", quic;desc=\"QUIC v1\"",
                processing_time.as_secs_f64() * 1000.0
            );
            response_builder = response_builder.header("server-timing", server_timing);
        }

        // Accept-CH header - Client Hints for adaptive content
        if !config.headers.accept_ch.is_empty() {
            response_builder = response_builder.header("accept-ch", &config.headers.accept_ch);
        }

        // NEL header - Network Error Logging
        if !config.headers.nel.is_empty() {
            response_builder = response_builder.header("nel", &config.headers.nel);
        }

        // Report-To header - Reporting API endpoint
        if !config.headers.report_to.is_empty() {
            response_builder = response_builder.header("report-to", &config.headers.report_to);
        }

        // Priority header (RFC 9218) - HTTP/3 response prioritization
        if !config.headers.priority.is_empty() {
            response_builder = response_builder.header("priority", &config.headers.priority);
        }

        // Security headers
        response_builder = response_builder
            .header("strict-transport-security", &config.headers.hsts)
            .header("x-frame-options", &config.headers.x_frame_options)
            .header(
                "x-content-type-options",
                &config.headers.x_content_type_options,
            )
            .header("referrer-policy", &config.headers.referrer_policy)
            .header("permissions-policy", &config.headers.permissions_policy)
            .header(
                "cross-origin-opener-policy",
                &config.headers.cross_origin_opener_policy,
            )
            .header(
                "cross-origin-embedder-policy",
                &config.headers.cross_origin_embedder_policy,
            )
            .header(
                "cross-origin-resource-policy",
                &config.headers.cross_origin_resource_policy,
            )
            .header("x-quantum-resistant", &config.headers.x_quantum_resistant)
            .header("x-security-level", &config.headers.x_security_level);

        // Add CORS headers from route.cors (proxy-level CORS) if configured
        if let Some(ref cors) = route.cors {
            let req_origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok());
            response_builder = add_cors_headers_to_builder(response_builder, cors, req_origin);
        }

        // Apply route-specific header overrides (e.g., COEP/COOP for Grafana)
        for (key, value) in &route.headers_override {
            response_builder = response_builder.header(key.as_str(), value.as_str());
        }

        let response = response_builder.body(())?;
        let body_size = proxy_response.body.len();
        let response_status = proxy_response.status;

        stream.send_response(response).await?;
        stream.send_data(Bytes::from(proxy_response.body)).await?;
        stream.finish().await?;

        // Record metrics
        let latency = start_time.elapsed();
        metrics.requests.request_end_full(
            response_status,
            latency,
            body.len() as u64,
            body_size as u64,
            Some(&path),
            is_health_check,
        );

        // Log successful response
        log_access(&AccessLogEntry {
            remote_addr,
            method,
            path,
            protocol: "HTTP/3".to_string(),
            status: response_status,
            body_size,
            referer,
            user_agent,
            host,
            response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
        });

        Ok(())
    }

    /// Handle raw QUIC streams (fallback when HTTP/3 handshake fails)
    async fn handle_raw_quic(
        connection: quinn::Connection,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
    ) -> anyhow::Result<()> {
        let handler = WebTransportHandler::new(config.clone(), backend_pool, remote_addr);

        loop {
            tokio::select! {
                // Bidirectional streams
                bi_result = connection.accept_bi() => {
                    match bi_result {
                        Ok((send, recv)) => {
                            debug!("Bidirectional stream from {}", remote_addr);
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_bi_stream(send, recv, "/", None)
                                    .await
                                {
                                    error!("Bi-stream error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Bi-stream accept ended: {}", e);
                            break;
                        }
                    }
                }

                // Unidirectional streams
                uni_result = connection.accept_uni() => {
                    match uni_result {
                        Ok(recv) => {
                            debug!("Unidirectional stream from {}", remote_addr);
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_uni_stream(recv, "/", None)
                                    .await
                                {
                                    error!("Uni-stream error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Uni-stream accept ended: {}", e);
                            break;
                        }
                    }
                }

                // Datagrams
                datagram_result = connection.read_datagram() => {
                    match datagram_result {
                        Ok(datagram) => {
                            debug!("Datagram from {} ({} bytes)", remote_addr, datagram.len());
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            let conn = connection.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_datagram(&conn, datagram, "/", None)
                                    .await
                                {
                                    error!("Datagram error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Datagram read ended: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

/// Add CORS headers to an http::Response::builder from CorsConfig
fn add_cors_headers_to_builder(
    mut builder: http::response::Builder,
    cors: &CorsConfig,
    request_origin: Option<&str>,
) -> http::response::Builder {
    // Access-Control-Allow-Origin — reflect when allow_origins list is set
    let resolved_origin = if !cors.allow_origins.is_empty() {
        request_origin
            .filter(|o| cors.allow_origins.iter().any(|a| a == *o))
            .map(String::from)
    } else {
        cors.allow_origin.clone()
    };
    if let Some(ref origin) = resolved_origin {
        builder = builder.header("access-control-allow-origin", origin);
    }

    // Access-Control-Allow-Methods
    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        builder = builder.header("access-control-allow-methods", methods);
    }

    // Access-Control-Allow-Headers
    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        builder = builder.header("access-control-allow-headers", hdrs);
    }

    // Access-Control-Allow-Credentials
    if cors.allow_credentials {
        builder = builder.header("access-control-allow-credentials", "true");
    }

    // Access-Control-Max-Age
    if cors.max_age > 0 {
        builder = builder.header("access-control-max-age", cors.max_age.to_string());
    }

    builder
}

/// RFC 9220 WebSocket-over-HTTP/3 tunnel.
///
/// After the client sends an extended CONNECT with `:protocol: websocket`, we:
///  1. Connect to the backend and perform a plain HTTP/1.1 WebSocket upgrade
///  2. Confirm the backend accepted (101 Switching Protocols)
///  3. Accept the client with 200 OK (RFC 9220 §5 — not 101)
///  4. Bridge the HTTP/3 bidi stream ↔ HTTP/1.1 upgraded TCP connection
async fn ws_h3_tunnel(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    backend_address: String,
    req_headers: http::HeaderMap,
    path: String,
    query: String,
    host: String,
    idle_secs: u64,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect to backend TCP
    let tcp = TcpStream::connect(&backend_address)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {} failed: {}", backend_address, e))?;

    // HTTP/1.1 connection to backend — `.with_upgrades()` required for 101 support
    let (mut sender, conn) = h1_client::Builder::new()
        .handshake::<TokioIo<TcpStream>, Empty<Bytes>>(TokioIo::new(tcp))
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/1.1 handshake to {} failed: {}", backend_address, e))?;
    tokio::spawn(conn.with_upgrades());

    // Build the HTTP/1.1 WebSocket upgrade request for the backend
    let path_and_query = format!("{}{}", path, query);
    let mut req_builder = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&path_and_query)
        .version(hyper::Version::HTTP_11);

    if let Some(h) = req_builder.headers_mut() {
        if let Ok(v) = http::HeaderValue::from_str(&host) {
            h.insert(http::header::HOST, v);
        }
        h.insert("connection", http::HeaderValue::from_static("upgrade"));
        h.insert("upgrade", http::HeaderValue::from_static("websocket"));
        for name in &[
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        ] {
            if let (Ok(hn), Some(hv)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                req_headers.get(*name),
            ) {
                h.insert(hn, hv.clone());
            }
        }
        if let Some(origin) = req_headers.get(http::header::ORIGIN) {
            h.insert(http::header::ORIGIN, origin.clone());
        }
    }

    let backend_req = req_builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| anyhow::anyhow!("Failed to build backend request: {}", e))?;

    let backend_resp = sender
        .send_request(backend_req)
        .await
        .map_err(|e| anyhow::anyhow!("Upgrade request to {} failed: {}", backend_address, e))?;

    if backend_resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow::anyhow!(
            "Backend {} returned {} (expected 101)",
            backend_address,
            backend_resp.status()
        ));
    }

    // Await the HTTP/1.1 backend upgrade to get the raw TCP stream
    let backend_on_upgrade = hyper::upgrade::on(backend_resp);
    let upgraded = backend_on_upgrade
        .await
        .map_err(|e| anyhow::anyhow!("Backend upgrade failed: {}", e))?;
    let backend_io = TokioIo::new(upgraded);

    // Send 200 OK to accept the HTTP/3 WebSocket session (RFC 9220 §5)
    let h3_accept = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build 200 response: {}", e))?;
    stream
        .send_response(h3_accept)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send 200 to client: {}", e))?;

    // Split so send/recv halves can be used independently in the copy loop
    let (mut send_half, mut recv_half) = stream.split();
    let (mut backend_read, mut backend_write) = tokio::io::split(backend_io);

    let idle = Duration::from_secs(idle_secs.max(1));

    // H3 → backend: dedicated task reads DATA frames and writes raw WS bytes to backend
    tokio::spawn(async move {
        while let Ok(Some(buf)) = recv_half.recv_data().await {
            if backend_write.write_all(buf.chunk()).await.is_err() {
                break;
            }
        }
    });

    // Backend → H3: this task, idle timer resets on each received chunk
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let sleep = tokio::time::sleep(idle);
        tokio::pin!(sleep);
        tokio::select! {
            n = backend_read.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if send_half.send_data(data).await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = sleep => {
                debug!("WS/H3 tunnel: idle timeout ({:?}), closing", idle);
                break;
            }
        }
    }

    Ok(())
}
