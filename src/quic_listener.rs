//! QUIC/HTTP3/WebTransport listener
//!
//! Accepts QUIC connections, negotiates HTTP/3, and handles WebTransport sessions.
//! Routes streams and datagrams to configured backends.
//!
//! Note: This is an alternative to WebTransportServer using h3/quinn directly.
//! Currently scaffolded for future use - the wtransport-based WebTransportServer
//! is the primary implementation.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::ext::Protocol;
use h3_quinn::Connection as H3Connection;
use quinn::{Endpoint, ServerConfig as QuinnServerConfig, TransportConfig};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::config::{ConfigReloadEvent, CorsConfig, ProxyConfig};
use crate::handlers::WebTransportHandler;
use crate::http3_features::EarlyHintsState;
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::proxy::BackendPool;
use crate::tls::TlsProvider;

/// Build Alt-Svc header value from config ports
fn build_alt_svc_header(config: &ProxyConfig) -> String {
    let mut ports = vec![config.server.udp_port];
    ports.extend(&config.server.additional_ports);
    ports
        .iter()
        .map(|p| format!("h3=\":{}\"; ma=86400", p))
        .collect::<Vec<_>>()
        .join(", ")
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
}

impl QuicListener {
    /// Create a new QUIC listener
    pub async fn new(
        config: Arc<ProxyConfig>,
        tls_provider: Arc<TlsProvider>,
        shutdown_rx: mpsc::Receiver<()>,
        reload_rx: mpsc::Receiver<ConfigReloadEvent>,
        metrics: Arc<MetricsRegistry>,
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
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(config.server.max_idle_timeout_secs)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid idle timeout: {}", e))?,
        ));

        // Create QUIC server configuration
        let mut server_config =
            QuinnServerConfig::with_crypto(tls_provider.get_quic_server_config());
        server_config.transport = Arc::new(transport_config);

        // Create endpoint
        let endpoint = Endpoint::server(server_config, addr)?;

        info!("QUIC endpoint created on {}", addr);
        info!("ALPN protocols: {:?}", config.tls.alpn_protocols);
        info!("PQC enabled: {}", tls_provider.is_pqc_enabled());

        // Create backend pool
        let backend_pool = Arc::new(BackendPool::new(config.clone()));

        // Create early hints state from config
        let early_hints_state = Arc::new(EarlyHintsState::default());
        if config.http3.early_hints_enabled {
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

                    info!("[{}] Incoming QUIC connection from {}", accept_count, remote_addr);

                    // Spawn connection handler
                    let config = self.config.clone();
                    let backend_pool = self.backend_pool.clone();
                    let early_hints_state = self.early_hints_state.clone();
                    let metrics = self.metrics.clone();

                    tokio::spawn(async move {
                        metrics.connections.connection_opened(ConnectionProtocol::Http3);
                        if let Err(e) = Self::handle_connection(
                            incoming,
                            remote_addr,
                            config,
                            backend_pool,
                            early_hints_state,
                            metrics.clone(),
                        ).await {
                            error!("Connection error from {}: {}", remote_addr, e);
                        }
                        metrics.connections.connection_closed();
                    });
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
    async fn handle_connection(
        incoming: quinn::Incoming,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        metrics: Arc<MetricsRegistry>,
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
                    remote_addr,
                    config,
                    backend_pool,
                    early_hints_state,
                    metrics,
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
    async fn handle_h3_connection(
        h3: &mut h3::server::Connection<H3Connection, Bytes>,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        metrics: Arc<MetricsRegistry>,
    ) -> anyhow::Result<()> {
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
                    let path = uri.path().to_ascii_lowercase();
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

                    if is_webtransport {
                        info!(
                            "WebTransport CONNECT request for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

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
                    } else {
                        // Regular HTTP/3 request
                        let config_clone = config.clone();
                        let backend_pool_clone = backend_pool.clone();
                        let early_hints_clone = early_hints_state.clone();
                        let metrics_clone = metrics.clone();

                        tokio::spawn(async move {
                            // Note: health check detection happens inside handle_h3_request
                            if let Err(e) = Self::handle_h3_request(
                                stream,
                                request,
                                remote_addr,
                                config_clone,
                                backend_pool_clone,
                                early_hints_clone,
                                metrics_clone,
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
    async fn handle_h3_request<S>(
        mut stream: h3::server::RequestStream<S, Bytes>,
        request: http::Request<()>,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        metrics: Arc<MetricsRegistry>,
    ) -> anyhow::Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let start_time = std::time::Instant::now();
        let uri = request.uri();
        let path = uri.path().to_ascii_lowercase();
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

        // Send 103 Early Hints if enabled and we have hints for this path
        // This is a key HTTP/3 optimization - send resource hints before proxying to backend
        // Only send for GET/HEAD requests - 103 on POST/PUT/DELETE can break cookie handling
        if config.http3.early_hints_enabled && (method == "GET" || method == "HEAD") {
            let hints = early_hints_state.get_hints_for_path(&path);
            if !hints.is_empty() {
                // Build 103 Early Hints response with Link headers and alt-svc for QUIC advertisement
                let mut early_response_builder = http::Response::builder()
                    .status(http::StatusCode::EARLY_HINTS)
                    .header("alt-svc", build_alt_svc_header(&config))
                    .header("server", "PQCProxy v0.2.1");

                for hint in &hints {
                    early_response_builder = early_response_builder.header("link", hint.as_str());
                }

                if let Ok(early_response) = early_response_builder.body(()) {
                    if let Err(e) = stream.send_response(early_response).await {
                        debug!(
                            "Failed to send 103 Early Hints to {}: {} (continuing with request)",
                            remote_addr, e
                        );
                    } else {
                        debug!(
                            "Sent 103 Early Hints to {} with {} link hints",
                            remote_addr,
                            hints.len()
                        );
                    }
                }
            }
        }

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
                    response_time_ms: start_time.elapsed().as_millis() as u64,
                });
                metrics.requests.request_end_full(
                    404,
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                // Return 404
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .header("server", "PQCProxy v0.2.1")
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
                    .header("alt-svc", build_alt_svc_header(&config))
                    .header("server", "PQCProxy v0.2.1");

                // Access-Control-Allow-Origin
                if let Some(ref origin) = cors.allow_origin {
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

        let backend = match config.get_backend(&route.backend) {
            Some(b) => b,
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
                    .header("server", "PQCProxy v0.2.1")
                    .body(())?;

                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }
        };

        // Read request body
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            // Convert impl Buf to bytes
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
                    headers.insert(name.as_str().to_string(), value_str.to_string());
                }
            }
        }

        // Forward Host header to backend (required for virtual host routing)
        if let Some(ref host_value) = host {
            headers.insert("Host".to_string(), host_value.clone());
        }

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

        // Proxy to backend (include query string in path)
        let proxy_response = backend_pool
            .proxy_http_full(
                backend,
                request.method().as_str(),
                &path_with_query,
                headers,
                &body,
            )
            .await?;

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

        // Add Alt-Svc header to advertise HTTP/3 support
        response_builder = response_builder.header("alt-svc", build_alt_svc_header(&config));

        // Add Server header for branding (hide backend identity)
        response_builder = response_builder.header("server", "PQCProxy v0.2.1");

        // ═══════════════════════════════════════════════════════════════
        // HTTP/3 Performance & Monitoring Headers
        // ═══════════════════════════════════════════════════════════════

        // Server-Timing header - Performance metrics for DevTools
        if config.headers.server_timing_enabled {
            let processing_time = start_time.elapsed();
            let server_timing = format!(
                "proxy;dur={:.2};desc=\"PQCProxy Processing\", quic;desc=\"QUIC v1\"",
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
            response_builder = add_cors_headers_to_builder(response_builder, cors);
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
            response_time_ms: latency.as_millis() as u64,
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
) -> http::response::Builder {
    // Access-Control-Allow-Origin
    if let Some(ref origin) = cors.allow_origin {
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
