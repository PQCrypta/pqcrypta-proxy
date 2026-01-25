//! WebTransport stream and datagram handler
//!
//! Handles WebTransport sessions and routes them to backends based on configuration.
//!
//! Note: This handler is used by QuicListener (h3/quinn implementation).
//! Currently scaffolded for future use alongside the primary wtransport-based server.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use quinn::{Connection, RecvStream, SendStream};
use tracing::{debug, error, info, warn};

use crate::config::{BackendConfig, ProxyConfig, RouteConfig};
use crate::proxy::BackendPool;

/// WebTransport session handler
pub struct WebTransportHandler {
    /// Proxy configuration
    config: Arc<ProxyConfig>,
    /// Backend connection pool
    pub backend_pool: Arc<BackendPool>,
    /// Remote client address
    remote_addr: SocketAddr,
}

impl WebTransportHandler {
    /// Create a new WebTransport handler
    pub fn new(
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        remote_addr: SocketAddr,
    ) -> Self {
        Self {
            config,
            backend_pool,
            remote_addr,
        }
    }

    /// Handle the entire WebTransport session lifecycle
    ///
    /// This is called from the QUIC listener when a WebTransport CONNECT is received.
    /// Note: The actual WebTransport stream handling is done by the dedicated
    /// WebTransportServer (webtransport_server.rs) which uses the wtransport crate.
    /// This method is for HTTP/3 layer WebTransport handling via h3/quinn.
    pub async fn handle_session(&self) -> anyhow::Result<()> {
        info!(
            "WebTransport session handler started for client {}",
            self.remote_addr
        );

        // The HTTP/3 layer WebTransport session is handled here.
        // For full WebTransport support with streams and datagrams,
        // the dedicated WebTransportServer should be used.
        // This handler manages the session context for routing.

        debug!(
            "WebTransport session active for {} - backend pool has {} backends",
            self.remote_addr,
            self.config.backends.len()
        );

        // Session remains active until client disconnects
        // The actual stream/datagram handling happens through the
        // handle_bi_stream, handle_uni_stream, and handle_datagram methods
        // which are called when streams/datagrams arrive on the connection

        Ok(())
    }

    /// Handle a bidirectional stream
    pub async fn handle_bi_stream(
        &self,
        mut send: SendStream,
        mut recv: RecvStream,
        path: &str,
        host: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!(
            "Handling bidirectional stream from {} for path: {}",
            self.remote_addr, path
        );

        // Find matching route
        let route = match self.config.find_route(host, path, true) {
            Some(r) => r,
            None => {
                warn!("No route found for WebTransport path: {}", path);
                let error_response = serde_json::json!({
                    "error": "no_route",
                    "message": format!("No route configured for path: {}", path),
                });
                let response_bytes = serde_json::to_vec(&error_response)?;
                send.write_all(&response_bytes).await?;
                send.finish()?;
                return Ok(());
            }
        };
        let backend_name = &route.backend;

        // Get backend configuration
        let backend = match self.config.get_backend(backend_name) {
            Some(b) => b,
            None => {
                error!("Backend not found: {}", backend_name);
                return Err(anyhow::anyhow!("Backend not found: {}", backend_name));
            }
        };

        // Read request data from stream
        let request_data = recv
            .read_to_end(self.config.security.max_request_size)
            .await?;
        debug!(
            "Received {} bytes from client {}",
            request_data.len(),
            self.remote_addr
        );

        // Proxy to backend
        let response = self
            .proxy_to_backend(backend, route, &request_data, path)
            .await?;

        // Send response back to client
        send.write_all(&response).await?;
        send.finish()?;

        debug!(
            "Sent {} bytes response to client {}",
            response.len(),
            self.remote_addr
        );

        Ok(())
    }

    /// Handle a unidirectional stream (client -> server)
    pub async fn handle_uni_stream(
        &self,
        mut recv: RecvStream,
        path: &str,
        host: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!(
            "Handling unidirectional stream from {} for path: {}",
            self.remote_addr, path
        );

        // Find matching route
        let route = match self.config.find_route(host, path, true) {
            Some(r) => r,
            None => {
                warn!("No route found for unidirectional stream path: {}", path);
                return Ok(());
            }
        };

        let backend = match self.config.get_backend(&route.backend) {
            Some(b) => b,
            None => {
                error!("Backend not found: {}", route.backend);
                return Err(anyhow::anyhow!("Backend not found: {}", route.backend));
            }
        };

        // Read request data
        let request_data = recv
            .read_to_end(self.config.security.max_request_size)
            .await?;

        // Proxy to backend (fire-and-forget for unidirectional)
        let _ = self
            .proxy_to_backend(backend, route, &request_data, path)
            .await;

        Ok(())
    }

    /// Handle a datagram
    pub async fn handle_datagram(
        &self,
        connection: &Connection,
        datagram: Bytes,
        path: &str,
        host: Option<&str>,
    ) -> anyhow::Result<()> {
        debug!(
            "Handling datagram from {} ({} bytes) for path: {}",
            self.remote_addr,
            datagram.len(),
            path
        );

        // Find matching route
        let route = match self.config.find_route(host, path, true) {
            Some(r) => r,
            None => {
                // Echo back for paths without routes (for testing)
                connection.send_datagram(datagram)?;
                return Ok(());
            }
        };

        let backend = match self.config.get_backend(&route.backend) {
            Some(b) => b,
            None => {
                error!("Backend not found: {}", route.backend);
                return Err(anyhow::anyhow!("Backend not found: {}", route.backend));
            }
        };

        // Proxy to backend
        let response = self
            .proxy_to_backend(backend, route, &datagram, path)
            .await?;

        // Send response datagram
        connection.send_datagram(Bytes::from(response))?;

        Ok(())
    }

    /// Proxy request to backend
    async fn proxy_to_backend(
        &self,
        backend: &BackendConfig,
        route: &RouteConfig,
        data: &[u8],
        path: &str,
    ) -> anyhow::Result<Vec<u8>> {
        use crate::config::BackendType;

        info!(
            "Proxying {} bytes to backend '{}' ({:?})",
            data.len(),
            backend.name,
            backend.backend_type
        );

        // Build headers for backend request
        let mut headers = route.add_headers.clone();

        // Add client identity header if configured
        if route.forward_client_identity {
            let header_name = route
                .client_identity_header
                .as_deref()
                .unwrap_or("X-Client-IP");
            headers.insert(header_name.to_string(), self.remote_addr.ip().to_string());
        }

        // Determine HTTP method for stream-to-HTTP conversion
        let method = route.stream_to_method.as_deref().unwrap_or("POST");

        match backend.backend_type {
            BackendType::Http1 | BackendType::Http2 => {
                self.backend_pool
                    .proxy_http(backend, method, path, headers, data)
                    .await
            }
            BackendType::Unix => {
                self.backend_pool
                    .proxy_unix(backend, method, path, headers, data)
                    .await
            }
            BackendType::Http3 => {
                // HTTP/3 backend - forward over QUIC
                self.backend_pool
                    .proxy_http3(backend, method, path, headers, data)
                    .await
            }
            BackendType::Tcp => {
                // Raw TCP - just forward the bytes
                self.backend_pool.proxy_tcp(backend, data).await
            }
        }
    }
}
