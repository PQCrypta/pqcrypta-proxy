//! Production WebTransport Server with proper ALPN negotiation
//!
//! Uses the wtransport crate for full WebTransport protocol support including:
//! - Automatic ALPN "h3" configuration
//! - SETTINGS_ENABLE_WEBTRANSPORT frame
//! - Proper session handling
//! - Bidirectional/unidirectional streams and datagrams

use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info};
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

        // Create custom transport configuration to prevent ExcessiveLoad errors
        // Increase buffer sizes for better handling of burst traffic
        use quinn::VarInt;
        let mut transport_config = QuicTransportConfig::default();

        // Increase receive window (connection-level) - 16MB
        transport_config.receive_window(VarInt::from_u32(16 * 1024 * 1024));

        // Increase stream receive window (per-stream) - 8MB
        transport_config.stream_receive_window(VarInt::from_u32(8 * 1024 * 1024));

        // Increase send window - 16MB
        transport_config.send_window(16 * 1024 * 1024);

        // Increase concurrent streams
        transport_config.max_concurrent_bidi_streams(VarInt::from_u32(1000));
        transport_config.max_concurrent_uni_streams(VarInt::from_u32(1000));

        // Datagram settings
        transport_config.datagram_receive_buffer_size(Some(65536));
        transport_config.datagram_send_buffer_size(65536);

        info!(
            "🔧 Custom transport config: receive_window=16MB, stream_window=8MB, send_window=16MB"
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
            .max_idle_timeout(Some(Duration::from_secs(120)))
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
        })
    }

    /// Set the metrics registry for connection tracking
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
            tokio::spawn(async move {
                if let Some(ref m) = session_metrics {
                    m.connections
                        .connection_opened(ConnectionProtocol::WebTransport);
                }
                if let Err(e) =
                    handle_incoming_session(incoming_session, config_clone, backend_clone).await
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("📨 Processing incoming WebTransport session...");
    info!("📍 Remote address: {}", incoming_session.remote_address());

    // Await the IncomingSession to get SessionRequest
    let session_request = incoming_session.await?;

    let path = session_request.path().to_string();
    let authority = session_request.authority().to_string();

    info!("📥 WebTransport session request received");
    info!("   Path: {}", path);
    info!("   Authority: {}", authority);

    // Accept the session
    let remote_addr = session_request.remote_address();
    let connection = session_request.accept().await?;

    info!("✅ WebTransport connection established: {}", remote_addr);

    // Handle the connection
    handle_connection(connection, remote_addr, path, config, backend_pool).await
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
            let error_response = json!({
                "success": false,
                "error": e.to_string(),
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
            error!("❌ Request processing failed for {}: {}", remote_addr, e);

            // Send error response
            let error_response = json!({
                "success": false,
                "error": e.to_string(),
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
            error!("❌ Datagram processing failed for {}: {}", remote_addr, e);
            let error_response = json!({
                "success": false,
                "error": e.to_string(),
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
