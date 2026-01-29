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

use crate::config::{ConfigReloadEvent, CorsConfig, ProxyConfig};
use crate::handlers::WebTransportHandler;
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
}

impl QuicListener {
    /// Create a new QUIC listener
    pub async fn new(
        config: Arc<ProxyConfig>,
        tls_provider: Arc<TlsProvider>,
        shutdown_rx: mpsc::Receiver<()>,
        reload_rx: mpsc::Receiver<ConfigReloadEvent>,
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

        Ok(Self {
            endpoint,
            tls_provider,
            backend_pool,
            config,
            shutdown_rx,
            reload_rx,
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

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            incoming,
                            remote_addr,
                            config,
                            backend_pool,
                        ).await {
                            error!("Connection error from {}: {}", remote_addr, e);
                        }
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
    ) -> anyhow::Result<()> {
        // Accept connection
        let connecting = incoming.accept()?;
        let connection = connecting.await?;

        info!("QUIC connection established: {}", remote_addr);

        // Log ALPN negotiation
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

        // Try to establish HTTP/3 connection
        match h3::server::Connection::new(h3_conn).await {
            Ok(mut h3) => {
                // HTTP/3 connection established
                Self::handle_h3_connection(&mut h3, remote_addr, config, backend_pool).await?;
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
                    let path = uri.path().to_string();
                    // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback to host header
                    let host = uri.authority().map(|a| a.host().to_string()).or_else(|| {
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
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("sec-webtransport-http3-draft", "draft02")
                            .body(())?;

                        // Handle WebTransport session
                        let handler = WebTransportHandler::new(
                            config.clone(),
                            backend_pool.clone(),
                            remote_addr,
                        );

                        tokio::spawn(async move {
                            debug!(
                                "WebTransport session started for {} on path {}",
                                remote_addr, path
                            );
                            if let Err(e) = handler.handle_session().await {
                                error!("WebTransport session error for {}: {}", remote_addr, e);
                            }
                        });

                        // Respond on the stream
                        let mut stream = stream;
                        stream.send_response(response).await.ok();
                        stream.finish().await.ok();
                    } else {
                        // Regular HTTP/3 request
                        let config_clone = config.clone();
                        let backend_pool_clone = backend_pool.clone();

                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_h3_request(
                                stream,
                                request,
                                remote_addr,
                                config_clone,
                                backend_pool_clone,
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
    ) -> anyhow::Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let uri = request.uri();
        let path = uri.path();
        // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback to host header
        let host = uri
            .authority()
            .map(|a| a.host())
            .or_else(|| request.headers().get("host").and_then(|v| v.to_str().ok()));

        info!(
            "HTTP/3 request: {} {} host={:?} from {}",
            request.method(),
            path,
            host,
            remote_addr
        );

        // Find route first so we can use per-route CORS config
        let route = match config.find_route(host, path, false) {
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
                // Return 404
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
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
                    .header("alt-svc", build_alt_svc_header(&config));

                // Access-Control-Allow-Origin
                if let Some(ref origin) = cors.allow_origin {
                    response_builder = response_builder.header("access-control-allow-origin", origin);
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
                    response_builder = response_builder.header(
                        "access-control-max-age",
                        cors.max_age.to_string(),
                    );
                }

                let response = response_builder.body(())?;
                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            }
            // If no CORS config, fall through to normal handling / backend
        }

        let backend = match config.get_backend(&route.backend) {
            Some(b) => b,
            None => {
                error!("Backend not found: {}", route.backend);
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_GATEWAY)
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
        if let Some(host_value) = host {
            headers.insert("Host".to_string(), host_value.to_string());
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

        // Proxy to backend
        let proxy_response = backend_pool
            .proxy_http_full(backend, request.method().as_str(), path, headers, &body)
            .await?;

        // Build HTTP/3 response with headers from backend
        let mut response_builder = http::Response::builder().status(
            http::StatusCode::from_u16(proxy_response.status).unwrap_or(http::StatusCode::OK),
        );

        // Forward selected headers from backend (including CORS if backend sets them)
        for (name, value) in &proxy_response.headers {
            let lower_name = name.to_lowercase();
            if matches!(
                lower_name.as_str(),
                "content-type"
                    | "cache-control"
                    | "etag"
                    | "last-modified"
                    | "content-language"
                    | "content-encoding"
                    | "vary"
                    | "x-content-type-options"
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

        // Add Alt-Svc header to advertise HTTP/3 support
        response_builder = response_builder.header("alt-svc", build_alt_svc_header(&config));

        // Add CORS headers from route.cors (proxy-level CORS) if configured
        if let Some(ref cors) = route.cors {
            response_builder = add_cors_headers_to_builder(response_builder, cors);
        }

        let response = response_builder.body(())?;

        stream.send_response(response).await?;
        stream.send_data(Bytes::from(proxy_response.body)).await?;
        stream.finish().await?;

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
