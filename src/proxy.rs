//! Backend proxy module
//!
//! Handles connections to backend servers:
//! - HTTP/1.1 and HTTP/2 via hyper
//! - Unix sockets via hyperlocal (for PHP-FPM)
//! - HTTP/3 via quinn/h3
//! - Raw TCP

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::config::{BackendConfig, BackendType, ProxyConfig};

/// Backend connection pool manager
pub struct BackendPool {
    /// HTTP client for HTTP/1.1 and HTTP/2 backends
    http_client: Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    /// Connection limiters per backend
    limiters: DashMap<String, Arc<Semaphore>>,
    /// Configuration
    config: Arc<ProxyConfig>,
}

impl BackendPool {
    /// Create a new backend pool
    pub fn new(config: Arc<ProxyConfig>) -> Self {
        // Create HTTP client
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let http_client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build(connector);

        let pool = Self {
            http_client,
            limiters: DashMap::new(),
            config,
        };

        // Initialize limiters for each backend
        for (name, backend) in &pool.config.backends {
            pool.limiters.insert(
                name.clone(),
                Arc::new(Semaphore::new(backend.max_connections as usize)),
            );
        }

        pool
    }

    /// Update configuration (for hot-reload)
    pub fn update_config(&mut self, config: Arc<ProxyConfig>) {
        // Update limiters for new/changed backends
        for (name, backend) in &config.backends {
            if !self.limiters.contains_key(name) {
                self.limiters.insert(
                    name.clone(),
                    Arc::new(Semaphore::new(backend.max_connections as usize)),
                );
            }
        }

        self.config = config;
    }

    /// Proxy request to HTTP/1.1 or HTTP/2 backend
    pub async fn proxy_http(
        &self,
        backend: &BackendConfig,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // Acquire connection permit
        let _permit = self.acquire_permit(&backend.name).await?;

        // Build URI
        let uri = if backend.tls {
            format!("https://{}{}", backend.address, path)
        } else {
            format!("http://{}{}", backend.address, path)
        };

        debug!("Proxying to HTTP backend: {} {}", method, uri);

        // Build request
        let method = method.parse::<Method>()?;
        let mut request_builder = Request::builder()
            .method(method)
            .uri(&uri);

        // Add headers
        for (key, value) in headers {
            request_builder = request_builder.header(&key, &value);
        }

        // Add content-type if not specified
        if !headers.contains_key("content-type") && !headers.contains_key("Content-Type") {
            request_builder = request_builder.header("Content-Type", "application/octet-stream");
        }

        let request = request_builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request with timeout
        let timeout = Duration::from_millis(backend.timeout_ms);
        let response = tokio::time::timeout(timeout, self.http_client.request(request))
            .await
            .map_err(|_| anyhow::anyhow!("Backend request timeout"))?
            .map_err(|e| anyhow::anyhow!("Backend request failed: {}", e))?;

        // Check status
        let status = response.status();
        if !status.is_success() {
            warn!("Backend returned error status: {}", status);
        }

        // Read response body
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
            .to_bytes();

        debug!("Received {} bytes from HTTP backend", body_bytes.len());

        Ok(body_bytes.to_vec())
    }

    /// Proxy request to Unix socket backend (e.g., PHP-FPM)
    pub async fn proxy_unix(
        &self,
        backend: &BackendConfig,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // Acquire connection permit
        let _permit = self.acquire_permit(&backend.name).await?;

        // Parse Unix socket path
        let socket_path = backend
            .address
            .strip_prefix("unix:")
            .ok_or_else(|| anyhow::anyhow!("Invalid Unix socket address: {}", backend.address))?;

        debug!("Proxying to Unix socket: {} {}", socket_path, path);

        // Connect to Unix socket
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;

            let mut stream = UnixStream::connect(socket_path)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to connect to Unix socket: {}", e))?;

            // Build FastCGI-style HTTP request
            let http_request = self.build_http_request(method, path, &headers, body);

            // Send request
            stream.write_all(http_request.as_bytes()).await?;
            stream.write_all(body).await?;

            // Read response with timeout
            let timeout = Duration::from_millis(backend.timeout_ms);
            let mut response_buf = Vec::new();

            tokio::time::timeout(timeout, async {
                let mut buf = [0u8; 8192];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => response_buf.extend_from_slice(&buf[..n]),
                        Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await
            .map_err(|_| anyhow::anyhow!("Unix socket timeout"))??;

            // Parse HTTP response and extract body
            let response_body = self.extract_http_body(&response_buf)?;

            debug!("Received {} bytes from Unix socket", response_body.len());
            Ok(response_body)
        }

        #[cfg(not(unix))]
        {
            Err(anyhow::anyhow!("Unix sockets not supported on this platform"))
        }
    }

    /// Proxy request to HTTP/3 backend
    pub async fn proxy_http3(
        &self,
        backend: &BackendConfig,
        method: &str,
        path: &str,
        headers: HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // Acquire connection permit
        let _permit = self.acquire_permit(&backend.name).await?;

        debug!("Proxying to HTTP/3 backend: {} {}", backend.address, path);

        // Parse backend address
        let addr: std::net::SocketAddr = backend
            .address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend address: {}", e))?;

        // Create QUIC endpoint for client
        let mut roots = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            roots.add(cert).ok();
        }

        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"h3".to_vec()];

        // Skip verification if configured (dangerous)
        if backend.tls_skip_verify {
            warn!("TLS verification disabled for backend {} - INSECURE", backend.name);
        }

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| anyhow::anyhow!("Failed to create QUIC config: {}", e))?,
        ));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| anyhow::anyhow!("Failed to create endpoint: {}", e))?;
        endpoint.set_default_client_config(client_config);

        // Extract host for SNI
        let host = backend.address.split(':').next().unwrap_or("localhost");

        // Connect to backend
        let connection = endpoint
            .connect(addr, host)
            .map_err(|e| anyhow::anyhow!("Failed to connect: {}", e))?
            .await
            .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

        // Create HTTP/3 connection
        let quinn_conn = h3_quinn::Connection::new(connection);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP/3 client: {}", e))?;

        // Spawn driver
        tokio::spawn(async move {
            futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await
        });

        // Build request
        let mut request_builder = http::Request::builder()
            .method(method)
            .uri(format!("https://{}{}", host, path));

        for (key, value) in headers {
            request_builder = request_builder.header(&key, &value);
        }

        let request = request_builder
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request
        let mut stream = send_request
            .send_request(request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send request: {}", e))?;

        // Send body if present
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to send body: {}", e))?;
        }

        stream
            .finish()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to finish request: {}", e))?;

        // Receive response
        let response = stream
            .recv_response()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive response: {}", e))?;

        // Read response body
        let mut response_body = Vec::new();
        while let Some(chunk) = stream
            .recv_data()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to receive data: {}", e))?
        {
            response_body.extend_from_slice(&chunk);
        }

        debug!("Received {} bytes from HTTP/3 backend", response_body.len());
        Ok(response_body)
    }

    /// Proxy to raw TCP backend
    pub async fn proxy_tcp(&self, backend: &BackendConfig, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Acquire connection permit
        let _permit = self.acquire_permit(&backend.name).await?;

        debug!("Proxying {} bytes to TCP backend: {}", data.len(), backend.address);

        // Connect to backend
        let mut stream = TcpStream::connect(&backend.address)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to TCP backend: {}", e))?;

        // Send data
        stream.write_all(data).await?;

        // Read response with timeout
        let timeout = Duration::from_millis(backend.timeout_ms);
        let mut response_buf = Vec::new();

        tokio::time::timeout(timeout, async {
            let mut buf = [0u8; 8192];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => response_buf.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(anyhow::anyhow!("Read error: {}", e)),
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("TCP backend timeout"))??;

        debug!("Received {} bytes from TCP backend", response_buf.len());
        Ok(response_buf)
    }

    /// Acquire a connection permit for rate limiting
    async fn acquire_permit(&self, backend_name: &str) -> anyhow::Result<tokio::sync::OwnedSemaphorePermit> {
        let limiter = self
            .limiters
            .get(backend_name)
            .map(|r| r.clone())
            .ok_or_else(|| anyhow::anyhow!("No limiter for backend: {}", backend_name))?;

        limiter
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to acquire connection permit: {}", e))
    }

    /// Build HTTP request string for Unix socket
    fn build_http_request(
        &self,
        method: &str,
        path: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> String {
        let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

        for (key, value) in headers {
            request.push_str(&format!("{}: {}\r\n", key, value));
        }

        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("Connection: close\r\n");
        request.push_str("\r\n");

        request
    }

    /// Extract body from HTTP response
    fn extract_http_body(&self, response: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Find end of headers (double CRLF)
        let response_str = String::from_utf8_lossy(response);
        if let Some(header_end) = response_str.find("\r\n\r\n") {
            Ok(response[header_end + 4..].to_vec())
        } else if let Some(header_end) = response_str.find("\n\n") {
            Ok(response[header_end + 2..].to_vec())
        } else {
            // No headers found, return entire response
            Ok(response.to_vec())
        }
    }

    /// Check backend health
    pub async fn check_health(&self, backend: &BackendConfig) -> bool {
        if let Some(ref health_endpoint) = backend.health_check {
            match backend.backend_type {
                BackendType::Http1 | BackendType::Http2 => {
                    let uri = if backend.tls {
                        format!("https://{}{}", backend.address, health_endpoint)
                    } else {
                        format!("http://{}{}", backend.address, health_endpoint)
                    };

                    let request = match Request::builder()
                        .method(Method::GET)
                        .uri(&uri)
                        .body(Full::new(Bytes::new()))
                    {
                        Ok(r) => r,
                        Err(_) => return false,
                    };

                    let timeout = Duration::from_secs(5);
                    match tokio::time::timeout(timeout, self.http_client.request(request)).await {
                        Ok(Ok(response)) => response.status().is_success(),
                        _ => false,
                    }
                }
                BackendType::Unix => {
                    #[cfg(unix)]
                    {
                        use tokio::net::UnixStream;
                        let socket_path = backend.address.strip_prefix("unix:").unwrap_or(&backend.address);
                        UnixStream::connect(socket_path).await.is_ok()
                    }
                    #[cfg(not(unix))]
                    false
                }
                BackendType::Tcp | BackendType::Http3 => {
                    // Simple TCP connect check
                    TcpStream::connect(&backend.address).await.is_ok()
                }
            }
        } else {
            // No health check configured, assume healthy
            true
        }
    }
}
