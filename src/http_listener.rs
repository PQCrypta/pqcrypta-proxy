//! HTTP/1.1 and HTTP/2 reverse proxy with TLS termination, re-encryption, and passthrough
//!
//! This module provides a comprehensive TCP-based HTTP listener that supports:
//! - **TLS Terminate**: Decrypt at proxy, plain HTTP to backend (default)
//! - **TLS Re-encrypt**: Decrypt at proxy, re-encrypt HTTPS to backend
//! - **TLS Passthrough**: SNI-based routing without decryption
//! - Full HTTP/1.1 and HTTP/2 reverse proxy
//! - Alt-Svc advertisement for HTTP/3 and WebTransport
//! - Security headers injection
//! - CORS handling
//! - **PQC hybrid key exchange** via rustls-post-quantum with ML-KEM support

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    extract::{ConnectInfo, Host, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

#[cfg(feature = "pqc")]
use crate::pqc_tls::PqcTlsProvider;

use crate::compression::{compression_middleware, CompressionState};
use crate::config::{BackendConfig, CorsConfig, ProxyConfig, TlsMode};
use crate::fingerprint::FingerprintExtractor;
use crate::http3_features::{http3_features_middleware, Http3FeaturesState};
use crate::security::{security_middleware, SecurityState};

/// HTTP listener state
#[derive(Clone)]
pub struct HttpListenerState {
    pub config: Arc<ProxyConfig>,
    pub port: u16,
    pub http_client: Client<HttpConnector, Body>,
    pub https_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    pub security: SecurityState,
    pub fingerprint: Arc<FingerprintExtractor>,
}

/// Create and run the HTTP listener with TLS termination
#[allow(clippy::similar_names)]
pub async fn run_http_listener(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = addr.port();

    info!(
        "🌐 Starting HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .build_http();

    // Create HTTPS client for re-encrypt mode
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native root certificates")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let https_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https_connector);

    // Initialize security state from config (must be created before state)
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor,
    };

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::new();

    // Build router with full middleware stack
    // Order (outside to inside): security -> http3 -> compression -> headers -> handler
    let app = Router::new()
        .fallback(any(proxy_handler))
        // Response headers (innermost - runs last on response)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        // Alt-Svc header
        .layer(middleware::from_fn_with_state(
            state.clone(),
            alt_svc_middleware,
        ))
        // Response compression
        .layer(middleware::from_fn_with_state(
            compression_state,
            compression_middleware,
        ))
        // HTTP/3 features (Priority hints, Request coalescing)
        .layer(middleware::from_fn_with_state(
            http3_features_state,
            http3_features_middleware,
        ))
        // Security middleware (outermost - runs first)
        .layer(middleware::from_fn_with_state(
            security_state,
            security_middleware,
        ))
        .with_state(state);

    // Check if cert files exist
    if !std::path::Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !std::path::Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // Configure TLS
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| {
            error!("❌ TLS configuration error: {}", e);
            e
        })?;

    info!("✅ TLS configured for HTTP listener");
    info!("🔒 HTTPS reverse proxy ready on port {} (TCP)", port);
    info!("🔄 Routing: api.pqcrypta.com → 127.0.0.1:3003");
    info!("🔄 Routing: pqcrypta.com → 127.0.0.1:8080");

    // Run HTTPS server
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Create and run the HTTP listener with PQC-enabled OpenSSL TLS
/// Uses OpenSSL 3.5+ with ML-KEM hybrid key exchange for quantum-resistant connections
#[cfg(feature = "pqc")]
#[allow(clippy::similar_names)]
pub async fn run_http_listener_pqc(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    _pqc_provider: Arc<PqcTlsProvider>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
    use std::fs::File;
    use std::io::BufReader;

    let port = addr.port();

    info!(
        "🔐 Starting PQC-enabled HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .build_http();

    // Create HTTPS client for re-encrypt mode
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native root certificates")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let https_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(Duration::from_secs(90))
        .build(https_connector);

    // Initialize security state from config (must be created before state)
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor,
    };

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::new();

    // Build router with full middleware stack
    let app = Router::new()
        .fallback(any(proxy_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            alt_svc_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            compression_state,
            compression_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            http3_features_state,
            http3_features_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            security_state,
            security_middleware,
        ))
        .with_state(state);

    // Check if cert files exist
    if !std::path::Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !std::path::Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // Load certificates
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> =
        certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    if cert_chain.is_empty() {
        return Err("No certificates found in certificate file".into());
    }
    info!("📜 Loaded {} certificates", cert_chain.len());

    // Load private key - try multiple formats
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);

    // Try PKCS#8 format first
    let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;

    let private_key: PrivateKeyDer<'static> = if !pkcs8_keys.is_empty() {
        PrivateKeyDer::Pkcs8(pkcs8_keys.into_iter().next().unwrap())
    } else {
        // Try RSA format
        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let rsa_keys: Vec<_> = rsa_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;

        if !rsa_keys.is_empty() {
            PrivateKeyDer::Pkcs1(rsa_keys.into_iter().next().unwrap())
        } else {
            // Try EC format
            let key_file = File::open(key_path)?;
            let mut key_reader = BufReader::new(key_file);
            let ec_keys: Vec<_> =
                ec_private_keys(&mut key_reader).collect::<Result<Vec<_>, _>>()?;

            if !ec_keys.is_empty() {
                PrivateKeyDer::Sec1(ec_keys.into_iter().next().unwrap())
            } else {
                return Err("No valid private key found".into());
            }
        }
    };
    info!("🔑 Private key loaded successfully");

    // Create rustls config with PQC support via rustls-post-quantum
    // This provider includes X25519MLKEM768 hybrid key exchange
    let crypto_provider = std::sync::Arc::new(rustls_post_quantum::provider());

    // Determine TLS protocol versions from config
    let min_version = config.tls.min_version.as_str();
    let protocol_versions: Vec<&'static rustls::SupportedProtocolVersion> = match min_version {
        "1.3" => vec![&rustls::version::TLS13],
        "1.2" => vec![&rustls::version::TLS12, &rustls::version::TLS13],
        _ => {
            warn!(
                "Unknown min_version '{}' in config, defaulting to TLS 1.3 only",
                min_version
            );
            vec![&rustls::version::TLS13]
        }
    };

    let tls_version_info = if protocol_versions.len() == 1 {
        "TLS 1.3 ONLY - TLS 1.2 disabled to prevent downgrade attacks"
    } else {
        "TLS 1.2+ (TLS 1.3 preferred)"
    };

    let mut rustls_config = rustls::ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&protocol_versions)
        .map_err(|e| format!("Failed to set protocol versions: {}", e))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| format!("Failed to create TLS config: {}", e))?;

    // Configure ALPN for HTTP/1.1 and HTTP/2
    rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Create axum-server rustls config
    let tls_config = RustlsConfig::from_config(std::sync::Arc::new(rustls_config));

    info!("✅ PQC TLS configured via rustls-post-quantum");
    info!(
        "🔒 {} (config: min_version = \"{}\")",
        tls_version_info, min_version
    );
    info!(
        "🔒 Post-Quantum HTTPS reverse proxy ready on port {} (TCP)",
        port
    );
    info!("🛡️  PQC KEM: X25519MLKEM768 (hybrid classical + post-quantum)");
    info!("🛡️  Hybrid Mode: true");
    info!("📊 Security Level: NIST Level 3 (192-bit equivalent)");
    info!("🔄 Routing: api.pqcrypta.com → 127.0.0.1:3003");
    info!("🔄 Routing: pqcrypta.com → 127.0.0.1:8080");

    // Run HTTPS server with rustls (PQC-enabled via aws-lc-rs)
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

/// Run TLS passthrough server (SNI-based routing without termination)
/// Enabled when passthrough_routes are configured in proxy-config.toml
pub async fn run_tls_passthrough_server(
    addr: SocketAddr,
    config: Arc<ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.passthrough_routes.is_empty() {
        info!("📭 No passthrough routes configured, skipping passthrough server");
        return Ok(());
    }

    info!(
        "🔀 Starting TLS passthrough server on {} (SNI routing)",
        addr
    );
    for route in &config.passthrough_routes {
        info!("   {} → {}", route.sni, route.backend);
    }

    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, client_addr) = listener.accept().await?;
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_passthrough_connection(stream, client_addr, config).await {
                debug!("Passthrough connection error from {}: {}", client_addr, e);
            }
        });
    }
}

/// Handle a TLS passthrough connection by peeking at SNI
async fn handle_passthrough_connection(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    config: Arc<ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek at the TLS ClientHello to extract SNI
    let mut peek_buf = [0u8; 1024];
    let n = client_stream.peek(&mut peek_buf).await?;

    let sni = extract_sni_from_client_hello(&peek_buf[..n]);

    if sni.is_none() {
        warn!("No SNI in ClientHello from {}", client_addr);
        return Err("No SNI in ClientHello".into());
    }

    let sni = sni.unwrap();
    debug!("SNI from {}: {}", client_addr, sni);

    // Find matching passthrough route
    let route = config.passthrough_routes.iter().find(|r| {
        if r.sni.starts_with("*.") {
            // Wildcard match
            let suffix = &r.sni[1..]; // ".example.com"
            sni.ends_with(suffix) || sni == &r.sni[2..]
        } else {
            r.sni == sni
        }
    });

    if route.is_none() {
        warn!(
            "No passthrough route for SNI '{}' from {}",
            sni, client_addr
        );
        return Err(format!("No route for SNI: {}", sni).into());
    }

    let route = route.unwrap();
    info!(
        "Passthrough: {} → {} (SNI: {})",
        client_addr, route.backend, sni
    );

    // Connect to backend
    let backend_stream = tokio::time::timeout(
        Duration::from_millis(route.timeout_ms),
        TcpStream::connect(&route.backend),
    )
    .await
    .map_err(|_| "Backend connection timeout")?
    .map_err(|e| format!("Backend connection failed: {}", e))?;

    // Send PROXY protocol v2 header if enabled
    if route.proxy_protocol {
        // TODO: Implement PROXY protocol v2
        debug!("PROXY protocol v2 not yet implemented");
    }

    // Bidirectional copy
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut backend_read, mut backend_write) = backend_stream.into_split();

    let client_to_backend =
        tokio::spawn(async move { tokio::io::copy(&mut client_read, &mut backend_write).await });

    let backend_to_client =
        tokio::spawn(async move { tokio::io::copy(&mut backend_read, &mut client_write).await });

    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_backend => {},
        _ = backend_to_client => {},
    }

    Ok(())
}

/// Extract SNI from TLS ClientHello
fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // TLS record header: type (1) + version (2) + length (2)
    if data.len() < 5 {
        return None;
    }

    // Check it's a handshake record (0x16)
    if data[0] != 0x16 {
        return None;
    }

    // Skip record header
    let handshake = &data[5..];

    // Handshake header: type (1) + length (3)
    if handshake.len() < 4 {
        return None;
    }

    // Check it's a ClientHello (0x01)
    if handshake[0] != 0x01 {
        return None;
    }

    // Parse ClientHello
    let client_hello = &handshake[4..];
    if client_hello.len() < 38 {
        return None;
    }

    // Skip version (2) + random (32) = 34 bytes
    let mut offset = 34;

    // Session ID length
    if offset >= client_hello.len() {
        return None;
    }
    let session_id_len = client_hello[offset] as usize;
    offset += 1 + session_id_len;

    // Cipher suites length (2 bytes)
    if offset + 2 > client_hello.len() {
        return None;
    }
    let cipher_suites_len =
        u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Compression methods length
    if offset >= client_hello.len() {
        return None;
    }
    let compression_len = client_hello[offset] as usize;
    offset += 1 + compression_len;

    // Extensions length (2 bytes)
    if offset + 2 > client_hello.len() {
        return None;
    }
    let extensions_len =
        u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    if extensions_end > client_hello.len() {
        return None;
    }

    // Parse extensions to find SNI (type 0x0000)
    while offset + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]);
        let ext_len =
            u16::from_be_bytes([client_hello[offset + 2], client_hello[offset + 3]]) as usize;
        offset += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if offset + ext_len > client_hello.len() {
                return None;
            }

            let sni_data = &client_hello[offset..offset + ext_len];

            // SNI list length (2 bytes)
            if sni_data.len() < 2 {
                return None;
            }

            let mut sni_offset = 2; // Skip list length

            // Parse SNI entries
            while sni_offset + 3 <= sni_data.len() {
                let name_type = sni_data[sni_offset];
                let name_len =
                    u16::from_be_bytes([sni_data[sni_offset + 1], sni_data[sni_offset + 2]])
                        as usize;
                sni_offset += 3;

                if name_type == 0x00 && sni_offset + name_len <= sni_data.len() {
                    // Host name
                    if let Ok(hostname) =
                        std::str::from_utf8(&sni_data[sni_offset..sni_offset + name_len])
                    {
                        return Some(hostname.to_string());
                    }
                }

                sni_offset += name_len;
            }
        }

        offset += ext_len;
    }

    None
}

/// Middleware to add Alt-Svc header to all responses
async fn alt_svc_middleware(
    State(state): State<HttpListenerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;

    // Build Alt-Svc header with all ports
    let mut alt_svc_parts = vec![format!("h3=\":{}\"; ma=86400", state.port)];
    for port in &state.config.server.additional_ports {
        alt_svc_parts.push(format!("h3=\":{}\"; ma=86400", port));
    }
    let alt_svc_value = alt_svc_parts.join(", ");

    if let Ok(value) = HeaderValue::from_str(&alt_svc_value) {
        response.headers_mut().insert("alt-svc", value);
    }

    // Add WebTransport port header
    response.headers_mut().insert(
        "x-webtransport-port",
        HeaderValue::from_str(&state.port.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("443")),
    );

    response
}

/// Middleware to add security headers to all responses
async fn security_headers_middleware(
    State(state): State<HttpListenerState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let config = &state.config.headers;

    // HSTS
    if let Ok(v) = HeaderValue::from_str(&config.hsts) {
        headers.insert(header::STRICT_TRANSPORT_SECURITY, v);
    }

    // X-Frame-Options
    if let Ok(v) = HeaderValue::from_str(&config.x_frame_options) {
        headers.insert(header::X_FRAME_OPTIONS, v);
    }

    // X-Content-Type-Options
    if let Ok(v) = HeaderValue::from_str(&config.x_content_type_options) {
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, v);
    }

    // Referrer-Policy
    if let Ok(v) = HeaderValue::from_str(&config.referrer_policy) {
        headers.insert(header::REFERRER_POLICY, v);
    }

    // Permissions-Policy
    if let Ok(v) = HeaderValue::from_str(&config.permissions_policy) {
        headers.insert("permissions-policy", v);
    }

    // Cross-Origin headers
    if let Ok(v) = HeaderValue::from_str(&config.cross_origin_opener_policy) {
        headers.insert("cross-origin-opener-policy", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config.cross_origin_embedder_policy) {
        headers.insert("cross-origin-embedder-policy", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config.cross_origin_resource_policy) {
        headers.insert("cross-origin-resource-policy", v);
    }

    // Additional security headers
    if let Ok(v) = HeaderValue::from_str(&config.x_permitted_cross_domain_policies) {
        headers.insert("x-permitted-cross-domain-policies", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config.x_download_options) {
        headers.insert("x-download-options", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config.x_dns_prefetch_control) {
        headers.insert("x-dns-prefetch-control", v);
    }

    // PQC branding headers
    if let Ok(v) = HeaderValue::from_str(&config.x_quantum_resistant) {
        headers.insert("x-quantum-resistant", v);
    }
    if let Ok(v) = HeaderValue::from_str(&config.x_security_level) {
        headers.insert("x-security-level", v);
    }

    response
}

/// Main proxy handler - routes requests to appropriate backends
async fn proxy_handler(
    State(state): State<HttpListenerState>,
    Host(host): Host,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let path = uri.path();
    let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

    debug!(
        "Incoming request: {} {} {} from {}",
        method, host, path, client_addr
    );

    // Find matching route
    let route = state.config.find_route(Some(&host), path, false);

    if let Some(route) = route {
        // Handle redirect routes
        if let Some(ref redirect_to) = route.redirect {
            let new_path = if let Some(ref prefix) = route.path_prefix {
                // Replace prefix with redirect target, keeping the rest
                let suffix = path.strip_prefix(prefix).unwrap_or("");
                format!("{}{}{}", redirect_to, suffix, query)
            } else {
                format!("{}{}", redirect_to, query)
            };

            if route.redirect_permanent {
                return Redirect::permanent(&new_path).into_response();
            }
            return Redirect::temporary(&new_path).into_response();
        }

        // Handle OPTIONS preflight for CORS
        if method == Method::OPTIONS {
            if let Some(ref cors) = route.cors {
                return handle_cors_preflight(cors);
            }
        }

        // Get backend configuration
        let backend = state.config.get_backend(&route.backend);
        if backend.is_none() {
            error!("Backend not found: {}", route.backend);
            return (StatusCode::BAD_GATEWAY, "Backend not configured").into_response();
        }
        let backend = backend.unwrap();

        // Check circuit breaker - if backend is unhealthy, reject early
        if !state.security.circuit_allows(&route.backend) {
            warn!(
                "Circuit breaker open for backend '{}', rejecting request",
                route.backend
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Service temporarily unavailable",
            )
                .into_response();
        }

        // Determine TLS mode (use tls_mode, or legacy tls bool)
        let tls_mode = if backend.tls {
            TlsMode::Reencrypt
        } else {
            backend.tls_mode.clone()
        };

        // Build backend URL based on TLS mode
        let (backend_url, use_https) = match tls_mode {
            TlsMode::Terminate => (
                format!("http://{}{}{}", backend.address, path, query),
                false,
            ),
            TlsMode::Reencrypt => (
                format!("https://{}{}{}", backend.address, path, query),
                true,
            ),
            TlsMode::Passthrough => {
                // Passthrough mode shouldn't reach here - it's handled at TCP level
                error!("Passthrough mode backend reached HTTP handler - this is a config error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Invalid backend configuration",
                )
                    .into_response();
            }
        };

        debug!(
            "Proxying to backend: {} (TLS mode: {:?})",
            backend_url, tls_mode
        );

        // Build proxy request
        let mut proxy_req = Request::builder().method(method.clone()).uri(&backend_url);

        // Copy headers with modifications
        if let Some(h) = proxy_req.headers_mut() {
            // Copy original headers
            for (name, value) in headers.iter() {
                // Skip hop-by-hop headers
                let name_str = name.as_str().to_lowercase();
                if ![
                    "host",
                    "connection",
                    "transfer-encoding",
                    "upgrade",
                    "keep-alive",
                    "proxy-authenticate",
                    "proxy-authorization",
                    "te",
                    "trailer",
                ]
                .contains(&name_str.as_str())
                {
                    h.insert(name.clone(), value.clone());
                }
            }

            // Set correct host header for backend
            if let Ok(v) = HeaderValue::from_str(&host) {
                h.insert(header::HOST, v);
            }

            // Add X-Forwarded headers
            if let Ok(v) = HeaderValue::from_str(&client_addr.ip().to_string()) {
                h.insert("x-real-ip", v.clone());
                h.insert("x-forwarded-for", v);
            }
            h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
            if let Ok(v) = HeaderValue::from_str(&state.port.to_string()) {
                h.insert("x-forwarded-port", v);
            }

            // Add route-specific headers
            for (key, value) in &route.add_headers {
                if let (Ok(name), Ok(val)) = (
                    header::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    h.insert(name, val);
                }
            }

            // Forward client identity if configured
            if route.forward_client_identity {
                if let Some(ref header_name) = route.client_identity_header {
                    if let (Ok(name), Ok(val)) = (
                        header::HeaderName::from_bytes(header_name.as_bytes()),
                        HeaderValue::from_str(&client_addr.ip().to_string()),
                    ) {
                        h.insert(name, val);
                    }
                }
            }

            // Mobile detection header
            if let Some(user_agent) = headers.get(header::USER_AGENT) {
                if let Ok(ua_str) = user_agent.to_str() {
                    if is_mobile_user_agent(ua_str) {
                        h.insert("x-mobile-request", HeaderValue::from_static("mobile"));
                    }
                }
            }
        }

        // Build and send request
        let proxy_request = match proxy_req.body(body) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to build proxy request: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build request")
                    .into_response();
            }
        };

        // Send request to backend (using appropriate client)
        let result = if use_https {
            state.https_client.request(proxy_request).await
        } else {
            state.http_client.request(proxy_request).await
        };

        match result {
            Ok(backend_response) => {
                // Record success for circuit breaker
                state.security.record_backend_result(&route.backend, true);

                let (mut parts, incoming_body) = backend_response.into_parts();

                // Add CORS headers if configured
                if let Some(ref cors) = route.cors {
                    add_cors_headers(&mut parts.headers, cors);
                }

                // Add route-specific header overrides
                for (key, value) in &route.headers_override {
                    if let (Ok(name), Ok(val)) = (
                        header::HeaderName::from_bytes(key.as_bytes()),
                        HeaderValue::from_str(value),
                    ) {
                        parts.headers.insert(name, val);
                    }
                }

                // Handle Stripe compatibility (remove COEP/COOP)
                if route.stripe_compatibility {
                    parts.headers.remove("cross-origin-embedder-policy");
                    parts.headers.remove("cross-origin-opener-policy");
                }

                // Remove Upgrade header (problematic for HTTP/3)
                parts.headers.remove("upgrade");

                // Replace Server header with our own branding (hide backend identity)
                parts
                    .headers
                    .insert(header::SERVER, HeaderValue::from_static("PQCProxy v0.1.0"));

                // Convert Incoming body to axum Body
                let body = Body::new(incoming_body);
                Response::from_parts(parts, body)
            }
            Err(e) => {
                // Record failure for circuit breaker
                state.security.record_backend_result(&route.backend, false);

                error!("Backend request failed: {}", e);
                (StatusCode::BAD_GATEWAY, format!("Backend error: {}", e)).into_response()
            }
        }
    } else {
        // No route matched - return 404
        warn!("No route matched for {} {}", host, path);
        (StatusCode::NOT_FOUND, "Not Found").into_response()
    }
}

/// Handle CORS preflight OPTIONS request
fn handle_cors_preflight(cors: &CorsConfig) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;

    let headers = response.headers_mut();

    if let Some(ref origin) = cors.allow_origin {
        if let Ok(v) = HeaderValue::from_str(origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }

    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        if let Ok(v) = HeaderValue::from_str(&methods) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, v);
        }
    }

    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        if let Ok(v) = HeaderValue::from_str(&hdrs) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
        }
    }

    if cors.allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if cors.max_age > 0 {
        if let Ok(v) = HeaderValue::from_str(&cors.max_age.to_string()) {
            headers.insert(header::ACCESS_CONTROL_MAX_AGE, v);
        }
    }

    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    response
}

/// Add CORS headers to response
fn add_cors_headers(headers: &mut HeaderMap, cors: &CorsConfig) {
    if let Some(ref origin) = cors.allow_origin {
        if let Ok(v) = HeaderValue::from_str(origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }

    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        if let Ok(v) = HeaderValue::from_str(&methods) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, v);
        }
    }

    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        if let Ok(v) = HeaderValue::from_str(&hdrs) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
        }
    }

    if cors.allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if cors.max_age > 0 {
        if let Ok(v) = HeaderValue::from_str(&cors.max_age.to_string()) {
            headers.insert(header::ACCESS_CONTROL_MAX_AGE, v);
        }
    }
}

/// Check if user agent is a mobile device
fn is_mobile_user_agent(ua: &str) -> bool {
    let ua_lower = ua.to_lowercase();
    ua_lower.contains("mobile")
        || ua_lower.contains("android")
        || ua_lower.contains("webos")
        || ua_lower.contains("iphone")
        || ua_lower.contains("ipad")
        || ua_lower.contains("ipod")
        || ua_lower.contains("blackberry")
        || ua_lower.contains("iemobile")
        || ua_lower.contains("opera mini")
}

/// Run HTTP redirect server (port 80 → HTTPS)
pub async fn run_http_redirect_server(
    port: u16,
    https_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let https_port_clone = https_port;

    let app = Router::new().fallback(move |Host(host): Host, uri: Uri| async move {
        let path = uri.path();
        let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

        // Build HTTPS URL
        let https_url = if https_port_clone == 443 {
            format!("https://{}{}{}", host, path, query)
        } else {
            format!("https://{}:{}{}{}", host, https_port_clone, path, query)
        };

        Redirect::permanent(&https_url)
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("🔀 Starting HTTP→HTTPS redirect server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

/// Create TLS connector for re-encrypt mode with optional client cert
#[allow(dead_code)]
pub fn create_backend_tls_connector(
    backend: &BackendConfig,
) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::CertificateDer;
    use rustls::ClientConfig;
    use std::fs::File;
    use std::io::BufReader;

    let mut root_store = rustls::RootCertStore::empty();

    // Add native root certificates
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        root_store.add(cert).ok();
    }

    // Add custom CA cert if provided
    if let Some(ref ca_path) = backend.tls_cert {
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs = rustls_pemfile::certs(&mut ca_reader)
            .filter_map(|c| c.ok())
            .collect::<Vec<_>>();
        for cert in ca_certs {
            root_store.add(cert)?;
        }
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Add client certificate for mTLS if provided
    if let (Some(cert_path), Some(key_path)) = (&backend.tls_client_cert, &backend.tls_client_key) {
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|c| c.ok())
            .collect();

        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private key found")?;

        config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(certs, key)?;
    }

    // Optionally skip verification (dangerous!)
    if backend.tls_skip_verify {
        warn!(
            "⚠️ TLS verification disabled for backend {} - THIS IS DANGEROUS!",
            backend.name
        );
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Dangerous: No-verification TLS verifier (for testing only)
#[allow(dead_code)]
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
