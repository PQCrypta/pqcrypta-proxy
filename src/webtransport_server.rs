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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, warn};
use wtransport::config::QuicTransportConfig;
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

use crate::config::ProxyConfig;
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::proxy::BackendPool;

/// Production WebTransport server with proper ALPN protocol negotiation
pub struct WebTransportServer {
    server: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    addr: SocketAddr,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    metrics: Option<Arc<MetricsRegistry>>,
    /// Per-origin active session counter (origin string → count)
    origin_session_counts: Arc<DashMap<String, Arc<AtomicU32>>>,
}

impl WebTransportServer {
    /// Create new WebTransport server with TLS and ALPN configuration
    ///
    /// ALPN Protocol: "h3" (HTTP/3) is automatically configured by wtransport crate
    /// The crate handles SETTINGS_ENABLE_WEBTRANSPORT frame automatically
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

        // Load TLS identity from PEM files
        let identity = Identity::load_pemfiles(cert_path, key_path)
            .await
            .map_err(|e| {
                error!("❌ TLS certificate load failed: {}", e);
                error!("   Certificate: {}", cert_path);
                error!("   Private key: {}", key_path);
                e
            })?;

        info!("✅ TLS identity loaded successfully");

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

        // Concurrent streams
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1000));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(1000));

        // Datagram buffers — 4 MB each prevents ExcessiveLoad when datagrams
        // arrive during high-throughput download/upload streams.
        transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        transport_config.datagram_send_buffer_size(4 * 1024 * 1024);

        // ACK Frequency extension (draft-ietf-quic-ack-frequency): fewer batched
        // ACKs cut overhead during bulk speedtest transfers. Negotiated, so it is
        // inert against clients that do not support it.
        if config.server.enable_ack_frequency {
            transport_config
                .ack_frequency_config(Some(quinn::AckFrequencyConfig::default()));
            info!("🔧 QUIC ACK Frequency extension enabled");
        }

        info!(
            "🔧 Transport config: receive_window=64MB, stream_window=32MB, send_window=64MB, datagram_buf=4MB"
        );

        // Create server configuration with WebTransport support
        // The wtransport crate automatically:
        // - Configures ALPN with "h3" protocol
        // - Sends SETTINGS_ENABLE_WEBTRANSPORT=1 frame
        // - Handles QUIC connection establishment
        let config_builder = ServerConfig::builder()
            .with_bind_address(addr)
            .with_custom_transport(identity, transport_config)
            .keep_alive_interval(Some(Duration::from_secs(15)))
            .max_idle_timeout(Some(Duration::from_mins(2)))
            .map_err(|e| format!("Invalid idle timeout: {}", e))?
            .build();

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
        })
    }

    /// Set the metrics registry for connection tracking
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<MetricsRegistry>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get local address
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Run the WebTransport server and accept incoming connections
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = self.config.clone();
        let backend_pool = self.backend_pool.clone();
        let metrics = self.metrics.clone();
        let origin_counts = Arc::clone(&self.origin_session_counts);

        info!("🌐 WebTransport server listening on {}", self.addr);
        info!("🔗 Ready to accept WebTransport connections");
        info!("🔄 Starting accept loop...");

        loop {
            // Accept incoming QUIC connection (returns IncomingSession future)
            let incoming_session = self.server.accept().await;

            info!("📨 Received incoming WebTransport session");

            // Spawn task to handle the session
            let config_clone = config.clone();
            let backend_clone = backend_pool.clone();
            let session_metrics = metrics.clone();
            let counts_clone = Arc::clone(&origin_counts);
            tokio::spawn(async move {
                if let Some(ref m) = session_metrics {
                    m.connections
                        .connection_opened(ConnectionProtocol::WebTransport);
                }
                if let Err(e) = handle_incoming_session(
                    incoming_session,
                    config_clone,
                    backend_clone,
                    counts_clone,
                )
                .await
                {
                    error!("❌ Session handler error: {}", e);
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("📨 Processing incoming WebTransport session...");
    info!("📍 Remote address: {}", incoming_session.remote_address());

    // Await the IncomingSession to get SessionRequest
    let session_request = incoming_session.await?;

    let path = session_request.path().to_string();
    let authority = session_request.authority().to_string();
    let remote_addr = session_request.remote_address();

    info!("📥 WebTransport session request received");
    info!("   Path: {}", path);
    info!("   Authority: {}", authority);

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
        info!("   Origin: {} ✅", origin);
    } else {
        // No Origin header — non-browser / native client; always accepted.
        info!("   Origin: (none — non-browser client)");
    }

    // WT-RL-01: Per-origin session limit.
    let max_sessions = config.server.webtransport_max_sessions_per_origin;
    let counter = origin_session_counts
        .entry(origin_key.clone())
        .or_insert_with(|| Arc::new(AtomicU32::new(0)));
    let counter = Arc::clone(counter.value());
    let current = counter.load(Ordering::Relaxed);
    if current >= max_sessions {
        warn!(
            "WT-RL-01: WebTransport session limit ({}) reached for origin '{}' — rejecting {}",
            max_sessions, origin_key, remote_addr
        );
        session_request.forbidden().await;
        return Ok(());
    }
    counter.fetch_add(1, Ordering::Relaxed);

    // Accept the session
    let connection = match session_request.accept().await {
        Ok(c) => c,
        Err(e) => {
            counter.fetch_sub(1, Ordering::Relaxed);
            return Err(e.into());
        }
    };

    info!("✅ WebTransport connection established: {}", remote_addr);

    // Handle the connection; decrement counter when it closes
    let result = handle_connection(connection, remote_addr, path, config, backend_pool).await;
    counter.fetch_sub(1, Ordering::Relaxed);
    result
}

/// Handle an established WebTransport connection
async fn handle_connection(
    connection: Connection,
    remote_addr: SocketAddr,
    path: String,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
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
                        let path_clone = path.clone();
                        tokio::spawn(handle_uni_stream(
                            recv_stream, remote_addr, conn, path_clone, config_clone, backend_clone
                        ));
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
                        let path_clone = path.clone();
                        tokio::spawn(handle_bi_stream(
                            send_stream, recv_stream, remote_addr, conn, path_clone, config_clone, backend_clone
                        ));
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
                        debug!("📦 Datagram received from {} ({} bytes)", remote_addr, datagram.len());
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let path_clone = path.clone();
                        tokio::spawn(handle_datagram(
                            datagram.to_vec(), remote_addr, conn, path_clone, config_clone, backend_clone
                        ));
                    }
                    Err(e) => {
                        debug!("Datagram stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }
        }
    }

    info!("🔚 WebTransport connection closed: {}", remote_addr);
    Ok(())
}

/// Handle unidirectional stream (client -> server)
async fn handle_uni_stream(
    mut recv_stream: wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
    _connection: Arc<Connection>,
    path: String,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply timeout for request reading
    let timeout_duration = Duration::from_secs(30);
    let max_size = config.security.max_request_size;

    let mut buffer = Vec::new();
    let read_result =
        tokio::time::timeout(timeout_duration, recv_stream.read_to_end(&mut buffer)).await;

    match read_result {
        Ok(Ok(_bytes_read)) => {
            if buffer.len() > max_size {
                error!(
                    "Request from {} exceeds max size ({} > {})",
                    remote_addr,
                    buffer.len(),
                    max_size
                );
                return Err("Request too large".into());
            }
        }
        Ok(Err(e)) => {
            error!("Read error from {}: {}", remote_addr, e);
            return Err(format!("Stream read error: {}", e).into());
        }
        Err(_) => {
            error!("Request timeout from {}", remote_addr);
            return Err("Request timeout".into());
        }
    }

    debug!(
        "📥 Unidirectional data from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(&buffer, &path, remote_addr, &config, &backend_pool).await {
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
async fn handle_bi_stream(
    mut send_stream: wtransport::stream::SendStream,
    mut recv_stream: wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
    _connection: Arc<Connection>,
    path: String,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply timeout for request reading
    let timeout_duration = Duration::from_secs(30);
    let max_size = config.security.max_request_size;

    let mut buffer = Vec::new();
    let read_result =
        tokio::time::timeout(timeout_duration, recv_stream.read_to_end(&mut buffer)).await;

    match read_result {
        Ok(Ok(_bytes_read)) => {
            if buffer.len() > max_size {
                let error_response = json!({
                    "success": false,
                    "error": format!("Request exceeds max size of {} bytes", max_size),
                    "timestamp": chrono::Utc::now().to_rfc3339()
                });
                let error_bytes = serde_json::to_vec(&error_response)?;
                send_stream.write_all(&error_bytes).await?;
                let _ = send_stream.finish().await;
                return Err("Request too large".into());
            }
        }
        Ok(Err(e)) => {
            // SEC-02: Log full error server-side; send only a generic message to the client
            // to prevent leaking internal details (file paths, OS errors, library internals).
            error!("Stream read error for {}: {}", remote_addr, e);
            let error_response = json!({
                "success": false,
                "error": "Stream error",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            let _ = send_stream.finish().await;
            return Err(format!("Stream read error: {}", e).into());
        }
        Err(_) => {
            let error_response = json!({
                "success": false,
                "error": "Request timeout",
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            let _ = send_stream.finish().await;
            return Err("Request timeout".into());
        }
    }

    debug!(
        "📥 Bidirectional request from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(&buffer, &path, remote_addr, &config, &backend_pool).await {
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
async fn handle_datagram(
    datagram: Vec<u8>,
    remote_addr: SocketAddr,
    connection: Arc<Connection>,
    path: String,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
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
        proxy_request(&datagram, &path, remote_addr, &config, &backend_pool),
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
    path: &str,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
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

                // Forward to backend
                return forward_to_backend(data, backend_path, remote_addr, config, backend_pool)
                    .await;
            }
        }
    }

    // For non-JSON data, forward to the path directly
    forward_to_backend(data, path, remote_addr, config, backend_pool).await
}

/// Forward request to HTTP backend using the BackendPool
async fn forward_to_backend(
    data: &[u8],
    path: &str,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Find the appropriate backend for this path
    let backend_name = find_backend_for_path(path, config);

    let backend = config.backends.get(&backend_name).ok_or_else(|| {
        format!(
            "No backend configured for path: {} (tried: {})",
            path, backend_name
        )
    })?;

    debug!(
        "🔄 Forwarding WebTransport request to backend '{}': {}{}",
        backend_name, backend.address, path
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

    // Use the BackendPool's proxy_http method
    let response = backend_pool
        .proxy_http(backend, "POST", path, headers, data)
        .await
        .map_err(|e| format!("Backend proxy error: {}", e))?;

    info!("✅ Backend response received ({} bytes)", response.len());

    Ok(response)
}

/// Find the appropriate backend name for a given path
fn find_backend_for_path(path: &str, config: &ProxyConfig) -> String {
    // Check routes for a match
    for route in &config.routes {
        // Check if this route handles WebTransport
        if !route.webtransport {
            continue;
        }

        // Check path prefix match
        if let Some(prefix) = &route.path_prefix {
            if path.starts_with(prefix) {
                return route.backend.clone();
            }
        }

        // Check exact path match
        if let Some(exact) = &route.path_exact {
            if path == exact {
                return route.backend.clone();
            }
        }
    }

    // Fallback: use the first backend (usually "main" or "api")
    config
        .backends
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "main".to_string())
}
