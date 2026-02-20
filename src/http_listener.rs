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
//! - **PQC hybrid key exchange** via OpenSSL 3.5+ with native ML-KEM support
//!
//! ## TLS Backend Options
//!
//! - **OpenSSL 3.5+** (default when `pqc` feature enabled): Native ML-KEM support with
//!   multiple hybrid modes (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024),
//!   hardware acceleration, and broader algorithm choices
//! - **rustls-post-quantum** (fallback): Pure Rust implementation with X25519MLKEM768 hybrid

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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;
use tower::ServiceExt;
use tracing::{debug, error, info, trace, warn};

use crate::tls_acceptor::FingerprintingTlsAcceptor;

#[cfg(feature = "pqc")]
use crate::pqc_tls::{openssl_pqc, PqcTlsProvider};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::compression::{compression_middleware, CompressionState};
use crate::config::{BackendConfig, CorsConfig, ProxyConfig, TlsMode};
use crate::fingerprint::{
    fingerprint_middleware, FingerprintExtractor, FingerprintMiddlewareState,
};
use crate::http3_features::{http3_features_middleware, Http3FeaturesState};
use crate::load_balancer::{extract_session_cookie, LoadBalancer, SelectionContext};
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::rate_limiter::{
    build_context_from_request, AdvancedRateLimiter, LimitReason, RateLimitResult,
};
use crate::security::{security_middleware, SecurityState};

// ============================================================================
// PROXY Protocol v2 Implementation
// ============================================================================
// Reference: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
//
// PROXY protocol v2 allows the proxy to pass the original client connection
// information to the backend server. This is essential for TLS passthrough
// where the proxy cannot modify the TLS stream but the backend needs to know
// the real client IP address.

/// PROXY protocol v2 signature (12 bytes)
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// PROXY protocol v2 version and command byte
mod proxy_v2 {
    /// Version 2, PROXY command (connection was proxied)
    pub const VERSION_PROXY: u8 = 0x21;

    /// Version 2, LOCAL command (connection was not proxied, health check etc.)
    #[cfg(test)]
    pub const VERSION_LOCAL: u8 = 0x20;

    /// Address family and protocol
    #[cfg(test)]
    pub const AF_UNSPEC: u8 = 0x00; // Unspecified (used with LOCAL command)
    pub const AF_INET_STREAM: u8 = 0x11; // IPv4 + TCP
    pub const AF_INET6_STREAM: u8 = 0x21; // IPv6 + TCP
}

/// Build a PROXY protocol v2 header for the given connection
///
/// # Arguments
/// * `src_addr` - The original client address
/// * `dst_addr` - The proxy's local address (where client connected to)
///
/// # Returns
/// A byte vector containing the complete PROXY protocol v2 header
fn build_proxy_v2_header(src_addr: SocketAddr, dst_addr: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(16 + 36); // Max size for IPv6

    // 12-byte signature
    header.extend_from_slice(&PROXY_V2_SIGNATURE);

    match (src_addr, dst_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            // Version 2 + PROXY command
            header.push(proxy_v2::VERSION_PROXY);
            // IPv4 + TCP
            header.push(proxy_v2::AF_INET_STREAM);
            // Address length: 4 + 4 + 2 + 2 = 12 bytes
            header.extend_from_slice(&12u16.to_be_bytes());
            // Source IP (4 bytes)
            header.extend_from_slice(&src.ip().octets());
            // Destination IP (4 bytes)
            header.extend_from_slice(&dst.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&src.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            // Version 2 + PROXY command
            header.push(proxy_v2::VERSION_PROXY);
            // IPv6 + TCP
            header.push(proxy_v2::AF_INET6_STREAM);
            // Address length: 16 + 16 + 2 + 2 = 36 bytes
            header.extend_from_slice(&36u16.to_be_bytes());
            // Source IP (16 bytes)
            header.extend_from_slice(&src.ip().octets());
            // Destination IP (16 bytes)
            header.extend_from_slice(&dst.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&src.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        // Mixed IPv4/IPv6 - convert IPv4 to IPv4-mapped IPv6
        (SocketAddr::V4(src), SocketAddr::V6(dst)) => {
            let src_v6 = src.ip().to_ipv6_mapped();
            header.push(proxy_v2::VERSION_PROXY);
            header.push(proxy_v2::AF_INET6_STREAM);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src_v6.octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (SocketAddr::V6(src), SocketAddr::V4(dst)) => {
            let dst_v6 = dst.ip().to_ipv6_mapped();
            header.push(proxy_v2::VERSION_PROXY);
            header.push(proxy_v2::AF_INET6_STREAM);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst_v6.octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
    }

    header
}

/// Send PROXY protocol v2 header to the backend
async fn send_proxy_v2_header(
    stream: &TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
) -> std::io::Result<()> {
    let header = build_proxy_v2_header(client_addr, local_addr);

    // We need to write to the stream before it's split
    // This is a bit tricky - we'll use try_write which doesn't require &mut
    let mut written = 0;
    while written < header.len() {
        stream.writable().await?;
        match stream.try_write(&header[written..]) {
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }

    debug!(
        "Sent PROXY protocol v2 header ({} bytes) for {} -> {}",
        header.len(),
        client_addr,
        local_addr
    );

    Ok(())
}

/// HTTP listener state
#[derive(Clone)]
pub struct HttpListenerState {
    pub config: Arc<ProxyConfig>,
    pub port: u16,
    pub http_client: Client<HttpConnector, Body>,
    pub https_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    pub security: SecurityState,
    /// Fingerprint extractor for TLS client identification
    pub fingerprint: Arc<FingerprintExtractor>,
    pub load_balancer: Arc<LoadBalancer>,
    /// Metrics registry for request tracking
    pub metrics: Arc<MetricsRegistry>,
}

/// Create and run the HTTP listener with TLS termination
#[allow(clippy::similar_names)]
pub async fn run_http_listener(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    metrics: Arc<MetricsRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = addr.port();

    info!(
        "🌐 Starting HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    // Using configurable connection pool settings
    let pool_config = &config.connection_pool;
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
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
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(https_connector);

    // Initialize security state from config (must be created before state)
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize load balancer from config
    let lb_config = Arc::new(config.load_balancer.clone());
    let load_balancer = Arc::new(LoadBalancer::new(lb_config));

    // Add backend pools from configuration
    for (name, pool_config) in &config.backend_pools {
        load_balancer.add_pool(pool_config);
        info!(
            "⚖️  Added backend pool '{}' with {} servers ({})",
            name,
            pool_config.servers.len(),
            pool_config.algorithm
        );
    }

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter, metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
    };

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize fingerprint middleware state (if enabled)
    let fingerprint_state = if config.fingerprint.enabled {
        Some(FingerprintMiddlewareState::new(
            fingerprint_extractor,
            security_state.clone(),
            Arc::new(config.fingerprint.clone()),
        ))
    } else {
        None
    };

    // Build router with full middleware stack
    // Order (outside to inside): advanced_rate_limit -> fingerprint -> security -> http3 -> compression -> headers -> handler
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
        // Security middleware (basic IP checks, circuit breaker)
        .layer(middleware::from_fn_with_state(
            security_state,
            security_middleware,
        ));

    // Conditionally add fingerprint middleware (if enabled)
    let app = if let Some(fp_state) = fingerprint_state {
        info!("🔍 TLS fingerprinting middleware enabled");
        app.layer(middleware::from_fn_with_state(
            fp_state,
            fingerprint_middleware,
        ))
    } else {
        app
    };

    // Add rate limiting (outermost - runs first, multi-dimensional)
    let app = app
        .layer(middleware::from_fn_with_state(
            rl_state,
            advanced_rate_limit_middleware,
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
    pqc_provider: Arc<PqcTlsProvider>,
    metrics: Arc<MetricsRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = addr.port();

    info!(
        "🔐 Starting PQC-enabled HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    // Using configurable connection pool settings
    let pool_config = &config.connection_pool;
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
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
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(https_connector);

    // Initialize security state from config (must be created before state)
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize load balancer from config
    let lb_config = Arc::new(config.load_balancer.clone());
    let load_balancer = Arc::new(LoadBalancer::new(lb_config));

    // Add backend pools from configuration
    for (name, pool_config) in &config.backend_pools {
        load_balancer.add_pool(pool_config);
        info!(
            "⚖️  Added backend pool '{}' with {} servers ({})",
            name,
            pool_config.servers.len(),
            pool_config.algorithm
        );
    }

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter, metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
    };

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize fingerprint middleware state (if enabled)
    let fingerprint_state = if config.fingerprint.enabled {
        Some(FingerprintMiddlewareState::new(
            fingerprint_extractor,
            security_state.clone(),
            Arc::new(config.fingerprint.clone()),
        ))
    } else {
        None
    };

    // Build router with full middleware stack
    // Order (outside to inside): advanced_rate_limit -> fingerprint -> security -> http3 -> compression -> headers -> handler
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
        ));

    // Conditionally add fingerprint middleware (if enabled)
    let app = if let Some(fp_state) = fingerprint_state {
        info!("🔍 TLS fingerprinting middleware enabled (PQC mode)");
        app.layer(middleware::from_fn_with_state(
            fp_state,
            fingerprint_middleware,
        ))
    } else {
        app
    };

    // Add rate limiting (outermost - runs first, multi-dimensional)
    let app = app
        .layer(middleware::from_fn_with_state(
            rl_state,
            advanced_rate_limit_middleware,
        ))
        .with_state(state);

    // Check if cert files exist (OpenSSL will load them directly)
    if !std::path::Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !std::path::Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // =========================================================================
    // OpenSSL 3.5+ PQC TLS Backend
    // =========================================================================
    // Uses native ML-KEM support with multiple hybrid modes:
    // - X25519MLKEM768 (IETF standard, recommended)
    // - SecP256r1MLKEM768 (NIST curve variant)
    // - SecP384r1MLKEM1024 (higher security)
    // - X448MLKEM1024 (maximum security)
    // =========================================================================
    use axum_server::tls_openssl::OpenSSLConfig;

    // Create OpenSSL SSL acceptor with PQC hybrid key exchange
    let cert_path_buf = std::path::Path::new(cert_path);
    let key_path_buf = std::path::Path::new(key_path);

    let ssl_acceptor = openssl_pqc::create_pqc_acceptor(cert_path_buf, key_path_buf, &pqc_provider)
        .map_err(|e| format!("Failed to create PQC SSL acceptor: {}", e))?;

    // Create OpenSSL config from the PQC-enabled acceptor (requires Arc)
    let openssl_config = OpenSSLConfig::from_acceptor(Arc::new(ssl_acceptor));

    // Get PQC status for logging
    let pqc_status = pqc_provider.status();
    let kem_info = if let Some(kem) = pqc_status.configured_kem {
        format!(
            "{} (Security Level {})",
            kem.openssl_name(),
            kem.security_level()
        )
    } else {
        "X25519MLKEM768 (default)".to_string()
    };

    info!("✅ PQC TLS configured via OpenSSL 3.5+ (native ML-KEM)");
    info!("🔒 OpenSSL version: {}", pqc_status.openssl_version);
    info!("🔒 TLS 1.3 ONLY - required for ML-KEM key exchange");
    info!(
        "🔒 Post-Quantum HTTPS reverse proxy ready on port {} (TCP)",
        port
    );
    info!("🛡️  PQC KEM: {}", kem_info);
    info!("🛡️  Hybrid Mode: {}", pqc_status.hybrid_mode);
    info!(
        "🛡️  Available KEMs: {}",
        pqc_status.available_kems.join(", ")
    );
    info!("📊 Configured groups: {}", pqc_provider.groups_string());
    info!("🔄 Routing: api.pqcrypta.com → 127.0.0.1:3003");
    info!("🔄 Routing: pqcrypta.com → 127.0.0.1:8080");

    // Run HTTPS server with OpenSSL 3.5+ (PQC-enabled with native ML-KEM)
    axum_server::bind_openssl(addr, openssl_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}

// ============================================================================
// Custom TLS Accept Loop with Full Fingerprinting
// ============================================================================
// This implementation captures ClientHello before TLS handshake, extracts
// JA3/JA4 fingerprints, and blocks malicious clients before they can waste
// resources on a full handshake. This is the architecture used by Envoy,
// HAProxy, and other enterprise proxies.

/// Run HTTP listener with custom TLS accept loop and full fingerprinting
///
/// This is the preferred method for production deployments as it provides:
/// - Full JA3/JA4 fingerprint capture from ClientHello
/// - Early blocking of malicious fingerprints (before TLS handshake)
/// - Fingerprint data injected into request extensions
/// - Unified security posture across all connections
///
/// # Architecture
/// ```text
/// TcpListener
///    → FingerprintingTlsAcceptor (captures ClientHello)
///        → Early block if malicious fingerprint
///        → TLS Handshake
///            → Inject fingerprint into connection extensions
///                → Hyper HTTP/1.1 service
///                    → Axum router with middleware stack
/// ```
pub async fn run_http_listener_with_fingerprint(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<MetricsRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut shutdown_rx = shutdown_rx;
    let port = addr.port();

    info!(
        "🔐 Starting HTTP listener with custom TLS accept loop on {} (TCP)",
        addr
    );
    info!("🔍 Full JA3/JA4 fingerprinting enabled at TLS layer");
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    let pool_config = &config.connection_pool;
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
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
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(https_connector);

    // Initialize security state from config
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize load balancer from config
    let lb_config = Arc::new(config.load_balancer.clone());
    let load_balancer = Arc::new(LoadBalancer::new(lb_config));

    // Add backend pools from configuration
    for (name, pool_config) in &config.backend_pools {
        load_balancer.add_pool(pool_config);
        info!(
            "⚖️  Added backend pool '{}' with {} servers ({})",
            name,
            pool_config.servers.len(),
            pool_config.algorithm
        );
    }

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let conn_metrics = metrics.clone();
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter, metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
    };

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize fingerprint middleware state
    let fingerprint_state = FingerprintMiddlewareState::new(
        fingerprint_extractor.clone(),
        security_state.clone(),
        Arc::new(config.fingerprint.clone()),
    );

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
            security_state.clone(),
            security_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            fingerprint_state,
            fingerprint_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            rl_state,
            advanced_rate_limit_middleware,
        ))
        .with_state(state);

    // Check cert files
    if !std::path::Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !std::path::Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // Build rustls server config
    let rustls_config = build_rustls_server_config(cert_path, key_path)?;
    let rustls_config = Arc::new(rustls_config);

    // Create fingerprinting TLS acceptor
    let fingerprinting_acceptor = Arc::new(FingerprintingTlsAcceptor::new(
        rustls_config,
        fingerprint_extractor,
        security_state,
        config.fingerprint.clone(),
    ));

    // Bind TCP listener
    let listener = TcpListener::bind(addr).await?;

    info!("✅ Custom TLS accept loop configured");
    info!("🔒 HTTPS reverse proxy ready on port {} (TCP)", port);
    info!("🔍 JA3/JA4 fingerprinting active at TLS layer");
    info!("🔄 Routing: api.pqcrypta.com → 127.0.0.1:3003");
    info!("🔄 Routing: pqcrypta.com → 127.0.0.1:8080");

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                // Clone resources for the spawned task
                let acceptor = fingerprinting_acceptor.clone();
                let app = app.clone();

                // Spawn connection handler
                let conn_metrics_clone = conn_metrics.clone();
                tokio::spawn(async move {
                    handle_fingerprinted_connection(stream, remote_addr, acceptor, app, conn_metrics_clone).await;
                });
            }

            // Graceful shutdown signal
            _ = shutdown_rx.changed() => {
                info!("🛑 Received shutdown signal, stopping HTTP listener");
                break;
            }
        }
    }

    info!("✅ HTTP listener stopped gracefully");
    Ok(())
}

/// Handle a single connection with fingerprinting
async fn handle_fingerprinted_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    acceptor: Arc<FingerprintingTlsAcceptor>,
    app: Router,
    metrics: Arc<MetricsRegistry>,
) {
    trace!("New TCP connection from {}", remote_addr);

    // Accept TLS connection with fingerprint capture
    let tls_stream = match acceptor.accept(stream, remote_addr).await {
        Ok(Some(stream)) => stream,
        Ok(None) => {
            // Connection blocked by fingerprint policy
            debug!(
                "Connection from {} blocked by fingerprint policy",
                remote_addr
            );
            return;
        }
        Err(e) => {
            debug!("TLS accept failed for {}: {}", remote_addr, e);
            return;
        }
    };

    // Detect HTTP protocol from ALPN negotiation
    let protocol = {
        let (_, server_conn) = tls_stream.get_ref().get_ref();
        match server_conn.alpn_protocol() {
            Some(b"h2") => ConnectionProtocol::Http2,
            _ => ConnectionProtocol::Http1,
        }
    };
    metrics.connections.connection_opened(protocol);

    // Extract fingerprint info from the connection
    let conn_info = tls_stream.conn_info.clone();
    let ja3_hash = conn_info.ja3_hash.clone();
    let ja4_hash = conn_info.ja4_hash.clone();

    trace!(
        "TLS connection from {} established (JA3={:?}, JA4={:?}, client={:?})",
        remote_addr,
        ja3_hash,
        ja4_hash,
        conn_info.client_name
    );

    // Create service that injects fingerprint headers and routes to axum
    let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        // Clone data for async block
        let ja3 = ja3_hash.clone();
        let ja4 = ja4_hash.clone();
        let ci = conn_info.clone();
        let router = app.clone();

        async move {
            // Inject fingerprint headers for downstream middleware
            if let Some(ref hash) = ja3 {
                if let Ok(v) = HeaderValue::from_str(hash) {
                    req.headers_mut().insert("x-ja3-hash", v);
                }
            }
            if let Some(ref hash) = ja4 {
                if let Ok(v) = HeaderValue::from_str(hash) {
                    req.headers_mut().insert("x-ja4-hash", v);
                }
            }
            if let Some(ref name) = ci.client_name {
                if let Ok(v) = HeaderValue::from_str(name) {
                    req.headers_mut().insert("x-client-name", v);
                }
            }
            if ci.is_browser {
                req.headers_mut()
                    .insert("x-client-type", HeaderValue::from_static("browser"));
            }

            // Store connection info in extensions
            req.extensions_mut().insert(ci);
            req.extensions_mut().insert(ConnectInfo(remote_addr));

            // Convert hyper request to axum request
            let (parts, body) = req.into_parts();
            let body = Body::new(body);
            let req = Request::from_parts(parts, body);

            // Call the axum router
            let response = router.oneshot(req).await;

            match response {
                Ok(res) => {
                    // Convert axum response to hyper response
                    let (parts, body) = res.into_parts();
                    Ok::<_, std::convert::Infallible>(Response::from_parts(parts, body))
                }
                Err(infallible) => match infallible {},
            }
        }
    });

    // Serve HTTP/1.1 and HTTP/2 connections (via ALPN negotiation)
    let io = TokioIo::new(tls_stream);
    let auto_builder = AutoBuilder::new(TokioExecutor::new());

    if let Err(e) = auto_builder.serve_connection(io, service).await {
        if !e.to_string().contains("connection reset") {
            debug!("HTTP connection error for {}: {}", remote_addr, e);
        }
    }

    metrics.connections.connection_closed();
}

// ============================================================================
// PQC TLS Accept Loop with Full Fingerprinting (OpenSSL 3.5+)
// ============================================================================
// Combines post-quantum cryptography (ML-KEM) with TLS fingerprinting.
// Uses OpenSSL 3.5+ for PQC key exchange while maintaining ClientHello
// capture for JA3/JA4 fingerprint extraction.

/// Run PQC HTTP listener with custom TLS accept loop and full fingerprinting
///
/// This combines PQC (ML-KEM hybrid key exchange) with TLS-layer fingerprinting:
/// - Post-quantum resistant key exchange via OpenSSL 3.5+ ML-KEM
/// - Full JA3/JA4 fingerprint capture from ClientHello before handshake
/// - Early blocking of malicious fingerprints
/// - Unified security with both quantum resistance and bot detection
///
/// # Architecture
/// ```text
/// TcpListener
///    → Peek ClientHello (capture fingerprint)
///        → Early block if malicious fingerprint
///        → OpenSSL PQC TLS Handshake (ML-KEM)
///            → Inject fingerprint into request headers
///                → Hyper HTTP/1.1 service
///                    → Axum router with middleware stack
/// ```
#[cfg(feature = "pqc")]
pub async fn run_http_listener_pqc_with_fingerprint(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    pqc_provider: Arc<PqcTlsProvider>,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<MetricsRegistry>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut shutdown_rx = shutdown_rx;
    use openssl::ssl::SslContext;

    let port = addr.port();

    info!(
        "🔐🔍 Starting PQC HTTP listener with TLS-layer fingerprinting on {} (TCP)",
        addr
    );
    info!("🔍 Full JA3/JA4 fingerprinting enabled at TLS layer");
    info!("🛡️  PQC hybrid key exchange: ML-KEM via OpenSSL 3.5+");
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections
    let pool_config = &config.connection_pool;
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
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
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(https_connector);

    // Initialize security state
    let security_state = SecurityState::new(&config);

    // Initialize fingerprint extractor
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize load balancer
    let lb_config = Arc::new(config.load_balancer.clone());
    let load_balancer = Arc::new(LoadBalancer::new(lb_config));

    for (name, pool_config) in &config.backend_pools {
        load_balancer.add_pool(pool_config);
        info!(
            "⚖️  Added backend pool '{}' with {} servers ({})",
            name,
            pool_config.servers.len(),
            pool_config.algorithm
        );
    }

    // Initialize rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let conn_metrics = metrics.clone();
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter, metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        config: config.clone(),
        port,
        http_client,
        https_client,
        security: security_state.clone(),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
    };

    // Initialize middleware states
    let compression_state = CompressionState::default();
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);
    let fingerprint_state = FingerprintMiddlewareState::new(
        fingerprint_extractor.clone(),
        security_state.clone(),
        Arc::new(config.fingerprint.clone()),
    );

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
            security_state.clone(),
            security_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            fingerprint_state,
            fingerprint_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            rl_state,
            advanced_rate_limit_middleware,
        ))
        .with_state(state);

    // Check cert files
    if !std::path::Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !std::path::Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // Create OpenSSL PQC acceptor
    let cert_path_buf = std::path::Path::new(cert_path);
    let key_path_buf = std::path::Path::new(key_path);
    let ssl_acceptor = openssl_pqc::create_pqc_acceptor(cert_path_buf, key_path_buf, &pqc_provider)
        .map_err(|e| format!("Failed to create PQC SSL acceptor: {}", e))?;

    // Get SSL context for creating new SSL instances
    let ssl_context: SslContext = ssl_acceptor.into_context();
    let ssl_context = Arc::new(ssl_context);

    // Get PQC status for logging
    let pqc_status = pqc_provider.status();
    let kem_info = if let Some(kem) = pqc_status.configured_kem {
        format!(
            "{} (Security Level {})",
            kem.openssl_name(),
            kem.security_level()
        )
    } else {
        "X25519MLKEM768 (default)".to_string()
    };

    // Bind TCP listener
    let listener = TcpListener::bind(addr).await?;

    info!("✅ PQC TLS with fingerprinting configured");
    info!("🔒 OpenSSL version: {}", pqc_status.openssl_version);
    info!("🛡️  PQC KEM: {}", kem_info);
    info!(
        "🔒 Post-Quantum HTTPS reverse proxy ready on port {} (TCP)",
        port
    );
    info!("🔍 JA3/JA4 fingerprinting active at TLS layer");
    info!("🔄 Routing: api.pqcrypta.com → 127.0.0.1:3003");
    info!("🔄 Routing: pqcrypta.com → 127.0.0.1:8080");

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok(result) => result,
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                // Clone resources for spawned task
                let ssl_ctx = ssl_context.clone();
                let fp_extractor = fingerprint_extractor.clone();
                let sec_state = security_state.clone();
                let fp_config = config.fingerprint.clone();
                let router = app.clone();
                let conn_metrics_clone = conn_metrics.clone();

                tokio::spawn(async move {
                    handle_pqc_fingerprinted_connection(
                        stream,
                        remote_addr,
                        ssl_ctx,
                        fp_extractor,
                        sec_state,
                        fp_config,
                        router,
                        conn_metrics_clone,
                    )
                    .await;
                });
            }

            _ = shutdown_rx.changed() => {
                info!("🛑 Received shutdown signal, stopping PQC HTTP listener");
                break;
            }
        }
    }

    info!("✅ PQC HTTP listener stopped gracefully");
    Ok(())
}

/// Handle a single PQC connection with fingerprinting
#[cfg(feature = "pqc")]
#[allow(clippy::too_many_arguments)]
async fn handle_pqc_fingerprinted_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ssl_context: Arc<openssl::ssl::SslContext>,
    fingerprint_extractor: Arc<FingerprintExtractor>,
    security_state: SecurityState,
    fingerprint_config: crate::config::FingerprintConfig,
    app: Router,
    metrics: Arc<MetricsRegistry>,
) {
    use openssl::ssl::Ssl;
    use tokio_openssl::SslStream;

    trace!("New TCP connection from {} (PQC mode)", remote_addr);

    // Peek at the ClientHello before TLS handshake
    let mut peek_buf = vec![0u8; 4096];
    let fingerprint_result = match stream.peek(&mut peek_buf).await {
        Ok(n) if n > 0 => {
            trace!("Peeked {} bytes of ClientHello from {}", n, remote_addr);
            fingerprint_extractor.process_client_hello(
                &peek_buf[..n],
                remote_addr.ip(),
                &security_state,
                &fingerprint_config,
            )
        }
        Ok(_) => {
            debug!("Empty peek from {}", remote_addr);
            crate::fingerprint::FingerprintResult {
                allowed: true,
                ja3_hash: None,
                ja4_hash: None,
                classification: None,
                client_name: None,
            }
        }
        Err(e) => {
            debug!("Failed to peek ClientHello from {}: {}", remote_addr, e);
            crate::fingerprint::FingerprintResult {
                allowed: true,
                ja3_hash: None,
                ja4_hash: None,
                classification: None,
                client_name: None,
            }
        }
    };

    // Check if connection should be blocked
    if !fingerprint_result.allowed {
        warn!(
            "Blocking PQC connection from {} due to fingerprint {:?}",
            remote_addr, fingerprint_result.ja3_hash
        );
        return;
    }

    // Log fingerprint info
    if let Some(ref ja3) = fingerprint_result.ja3_hash {
        let client = fingerprint_result
            .client_name
            .as_deref()
            .unwrap_or("unknown");
        debug!(
            "PQC TLS fingerprint from {}: JA3={}, JA4={:?}, client={}",
            remote_addr, ja3, fingerprint_result.ja4_hash, client
        );
    }

    // Create SSL instance and perform handshake
    let ssl = match Ssl::new(&ssl_context) {
        Ok(ssl) => ssl,
        Err(e) => {
            debug!("Failed to create SSL instance for {}: {}", remote_addr, e);
            return;
        }
    };

    let mut ssl_stream = match SslStream::new(ssl, stream) {
        Ok(s) => s,
        Err(e) => {
            debug!("Failed to create SSL stream for {}: {}", remote_addr, e);
            return;
        }
    };

    // Perform async TLS handshake
    if let Err(e) = std::pin::Pin::new(&mut ssl_stream).accept().await {
        debug!("PQC TLS handshake failed for {}: {}", remote_addr, e);
        return;
    }

    // Detect HTTP protocol from ALPN negotiation (OpenSSL)
    let protocol = match ssl_stream.ssl().selected_alpn_protocol() {
        Some(b"h2") => ConnectionProtocol::Http2,
        _ => ConnectionProtocol::Http1,
    };
    metrics.connections.connection_opened(protocol);

    trace!(
        "PQC TLS connection from {} established (JA3={:?})",
        remote_addr,
        fingerprint_result.ja3_hash
    );

    // Extract fingerprint data for request injection
    let ja3_hash = fingerprint_result.ja3_hash.clone();
    let ja4_hash = fingerprint_result.ja4_hash.clone();
    let client_name = fingerprint_result.client_name.clone();
    let is_browser = fingerprint_result
        .classification
        .as_ref()
        .map(|c| matches!(c, crate::security::FingerprintClass::Browser))
        .unwrap_or(false);

    // Create connection info
    let conn_info = crate::tls_acceptor::FingerprintedConnection {
        remote_addr,
        ja3_hash: ja3_hash.clone(),
        ja4_hash: ja4_hash.clone(),
        client_name: client_name.clone(),
        is_browser,
    };

    // Create service that injects fingerprint headers
    let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        let ja3 = ja3_hash.clone();
        let ja4 = ja4_hash.clone();
        let cn = client_name.clone();
        let ci = conn_info.clone();
        let router = app.clone();

        async move {
            // Inject fingerprint headers
            if let Some(ref hash) = ja3 {
                if let Ok(v) = HeaderValue::from_str(hash) {
                    req.headers_mut().insert("x-ja3-hash", v);
                }
            }
            if let Some(ref hash) = ja4 {
                if let Ok(v) = HeaderValue::from_str(hash) {
                    req.headers_mut().insert("x-ja4-hash", v);
                }
            }
            if let Some(ref name) = cn {
                if let Ok(v) = HeaderValue::from_str(name) {
                    req.headers_mut().insert("x-client-name", v);
                }
            }
            if ci.is_browser {
                req.headers_mut()
                    .insert("x-client-type", HeaderValue::from_static("browser"));
            }

            // Add PQC indicator header
            req.headers_mut()
                .insert("x-pqc-enabled", HeaderValue::from_static("true"));

            // Store connection info in extensions
            req.extensions_mut().insert(ci);
            req.extensions_mut().insert(ConnectInfo(remote_addr));

            // Convert and route
            let (parts, body) = req.into_parts();
            let body = Body::new(body);
            let req = Request::from_parts(parts, body);

            let response = router.oneshot(req).await;

            match response {
                Ok(res) => {
                    let (parts, body) = res.into_parts();
                    Ok::<_, std::convert::Infallible>(Response::from_parts(parts, body))
                }
                Err(infallible) => match infallible {},
            }
        }
    });

    // Serve HTTP/1.1 and HTTP/2 connections over PQC TLS (via ALPN negotiation)
    let io = TokioIo::new(ssl_stream);
    let auto_builder = AutoBuilder::new(TokioExecutor::new());

    if let Err(e) = auto_builder.serve_connection(io, service).await {
        if !e.to_string().contains("connection reset") {
            debug!("PQC HTTP connection error for {}: {}", remote_addr, e);
        }
    }

    metrics.connections.connection_closed();
}

/// Build rustls server configuration from PEM files
fn build_rustls_server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::CertificateDer;
    use std::fs::File;
    use std::io::BufReader;

    // Load certificate chain
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|c| c.ok())
        .collect();

    if certs.is_empty() {
        return Err(format!("No certificates found in {}", cert_path).into());
    }

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| format!("No private key found in {}", key_path))?;

    // Build server config
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Set ALPN protocols for HTTP/2 and HTTP/1.1 negotiation
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
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

    // Find matching passthrough route (case-insensitive SNI matching)
    let sni_lower = sni.to_ascii_lowercase();
    let route = config.passthrough_routes.iter().find(|r| {
        let r_sni_lower = r.sni.to_ascii_lowercase();
        if r_sni_lower.starts_with("*.") {
            // Wildcard match
            let suffix = &r_sni_lower[1..]; // ".example.com"
            sni_lower.ends_with(suffix) || sni_lower == r_sni_lower[2..]
        } else {
            r_sni_lower == sni_lower
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

    // Send PROXY protocol v2 header if enabled (before stream split)
    if route.proxy_protocol {
        // Get local address (proxy address that client connected to)
        let local_addr = client_stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 0)));

        // Send PROXY protocol v2 header to backend
        if let Err(e) = send_proxy_v2_header(&backend_stream, client_addr, local_addr).await {
            warn!(
                "Failed to send PROXY protocol v2 header to {}: {}",
                route.backend, e
            );
            // Continue anyway - some backends may not require it
        } else {
            debug!(
                "Sent PROXY protocol v2 header: {} → {} (backend: {})",
                client_addr, local_addr, route.backend
            );
        }
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
    let alt_svc_value = build_alt_svc_header(state.port, &state.config.server.additional_ports);

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
    // Track request timing for Server-Timing header
    let start_time = std::time::Instant::now();

    let mut response = next.run(request).await;

    // Calculate processing time
    let processing_time = start_time.elapsed();

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

    // ═══════════════════════════════════════════════════════════════
    // HTTP/3 Performance & Monitoring Headers
    // ═══════════════════════════════════════════════════════════════

    // Server-Timing header (RFC 6797) - Performance metrics
    // Format: metric;dur=<ms>;desc="description"
    if config.server_timing_enabled {
        let server_timing = format!(
            "proxy;dur={:.2};desc=\"PQCProxy Processing\", quic;desc=\"QUIC v1\"",
            processing_time.as_secs_f64() * 1000.0
        );
        if let Ok(v) = HeaderValue::from_str(&server_timing) {
            headers.insert("server-timing", v);
        }
    }

    // Accept-CH header (Client Hints) - Enables responsive content delivery
    // Tells browsers which client hints to send on subsequent requests
    if !config.accept_ch.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.accept_ch) {
            headers.insert("accept-ch", v);
        }
    }

    // NEL header (Network Error Logging) - Client-side error reporting
    // Helps diagnose connection failures from client perspective
    if !config.nel.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.nel) {
            headers.insert("nel", v);
        }
    }

    // Report-To header - Defines endpoints for NEL and other reports
    if !config.report_to.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.report_to) {
            headers.insert("report-to", v);
        }
    }

    // Priority header (RFC 9218) - HTTP/3 response prioritization
    // u=0-7 (urgency, lower is more urgent), i (incremental delivery)
    if !config.priority.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&config.priority) {
            headers.insert("priority", v);
        }
    }

    response
}

// Advanced multi-dimensional rate limiting middleware
//
// Features:
// - Multi-key rate limiting (IP, API key, JA3 fingerprint, JWT, headers)
// - Layered limits (global → route → client)
// - Composite keys (IP + path, fingerprint + method)
// - X-Forwarded-For trust for clients behind proxies
// - IPv6 /64 subnet grouping
// - Adaptive baseline learning with anomaly detection

/// Build Alt-Svc header value for HTTP/3 advertisement.
fn build_alt_svc_header(port: u16, additional_ports: &[u16]) -> String {
    let mut parts = vec![format!("h3=\":{}\"; ma=86400", port)];
    for p in additional_ports {
        parts.push(format!("h3=\":{}\"; ma=86400", p));
    }
    parts.join(", ")
}

/// Add Alt-Svc header to a response (for early-return paths)
fn add_alt_svc_to_response(response: &mut Response, alt_svc: &str) {
    if let Ok(value) = HeaderValue::from_str(alt_svc) {
        response.headers_mut().insert("alt-svc", value);
    }
}

async fn advanced_rate_limit_middleware(
    State((rate_limiter, metrics)): State<(Arc<AdvancedRateLimiter>, Arc<MetricsRegistry>)>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_ascii_lowercase();

    // Pre-build Alt-Svc header for error responses (ports 443, 4433, 4434)
    let alt_svc = "h3=\":443\"; ma=86400, h3=\":4433\"; ma=86400, h3=\":4434\"; ma=86400";

    // Extract JA3/JA4 fingerprints from headers (set by TLS acceptor)
    let ja3_hash = headers
        .get("x-ja3-hash")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ja4_hash = headers
        .get("x-ja4-hash")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Build rate limit context
    let ctx = build_context_from_request(
        client_addr.ip(),
        &headers,
        &path,
        &method,
        ja3_hash,
        ja4_hash,
        None, // Route name resolved later
    );

    // Check rate limit
    match rate_limiter.check(&ctx) {
        RateLimitResult::Allowed { remaining, limit } => {
            metrics.rate_limiter.request_checked(true, false);
            // Add rate limit headers to response
            let mut response = next.run(request).await;
            let resp_headers = response.headers_mut();

            if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
                resp_headers.insert("x-ratelimit-limit", v);
            }
            if let Ok(v) = HeaderValue::from_str(&remaining.to_string()) {
                resp_headers.insert("x-ratelimit-remaining", v);
            }

            response
        }
        RateLimitResult::Limited {
            reason,
            retry_after_ms,
            limit,
        } => {
            metrics.rate_limiter.request_checked(false, false);
            debug!(
                "Rate limited {} {} from {} (reason: {:?})",
                method,
                path,
                client_addr.ip(),
                reason
            );

            let mut response = (
                StatusCode::TOO_MANY_REQUESTS,
                match reason {
                    LimitReason::PerSecond => "Rate limit exceeded (per second)",
                    LimitReason::PerMinute => "Rate limit exceeded (per minute)",
                    LimitReason::PerHour => "Rate limit exceeded (per hour)",
                    LimitReason::Global => "Global rate limit exceeded",
                    LimitReason::AnomalyDetected => "Anomalous traffic pattern detected",
                    LimitReason::RouteLimit => "Route rate limit exceeded",
                },
            )
                .into_response();

            let headers = response.headers_mut();

            // Standard rate limit headers
            if let Ok(v) = HeaderValue::from_str(&(retry_after_ms / 1000).to_string()) {
                headers.insert("retry-after", v);
            }
            if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
                headers.insert("x-ratelimit-limit", v);
            }
            headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));

            // Reset time (approximate)
            let reset_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + (retry_after_ms / 1000);
            if let Ok(v) = HeaderValue::from_str(&reset_time.to_string()) {
                headers.insert("x-ratelimit-reset", v);
            }

            // Add Alt-Svc header to advertise HTTP/3
            add_alt_svc_to_response(&mut response, alt_svc);

            response
        }
        RateLimitResult::Blocked { reason } => {
            metrics.rate_limiter.request_checked(false, true);
            warn!(
                "Blocked request {} {} from {} (reason: {})",
                method,
                path,
                client_addr.ip(),
                reason
            );

            let mut response = (StatusCode::FORBIDDEN, "Access denied").into_response();
            // Add Alt-Svc header to advertise HTTP/3
            add_alt_svc_to_response(&mut response, alt_svc);
            response
        }
    }
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
    let request_start = std::time::Instant::now();
    let is_health_check = headers
        .get("x-health-check-bypass")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);
    if !is_health_check {
        state.metrics.requests.request_start();
    }
    let path = uri.path().to_ascii_lowercase();
    let method_str = method.to_string();
    let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let host_str = host.clone();

    debug!(
        "Incoming request: {} {} {} from {}",
        method, host, path, client_addr
    );

    // Find matching route
    let route = state.config.find_route(Some(&host), &path, false);

    if let Some(route) = route {
        // Handle redirect routes
        if let Some(ref redirect_to) = route.redirect {
            let new_path = if let Some(ref prefix) = route.path_prefix {
                // Replace prefix with redirect target, keeping the rest (case-insensitive)
                let prefix_lower = prefix.to_ascii_lowercase();
                let suffix = if path.starts_with(&prefix_lower) {
                    &path[prefix_lower.len()..]
                } else {
                    ""
                };
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

        // Track request timing for load balancer
        let request_start = std::time::Instant::now();

        // Check if backend is a pool first, then fall back to single backend
        let (backend_address, tls_mode, pool_server, pool_name) =
            if let Some(pool) = state.load_balancer.get_pool(&route.backend) {
                // Extract session cookie for sticky sessions
                let session_cookie = headers
                    .get("cookie")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|cookies| {
                        extract_session_cookie(Some(cookies), &state.load_balancer.cookie_config)
                    });

                // Build selection context
                let ctx = SelectionContext {
                    client_ip: client_addr.ip(),
                    session_cookie,
                    affinity_header: pool.affinity_header.as_ref().and_then(|h| {
                        headers
                            .get(h)
                            .and_then(|v| v.to_str().ok().map(String::from))
                    }),
                    path: path.clone(),
                    host: host.clone(),
                };

                // Select backend from pool
                match pool.select(&ctx) {
                    Some(server) => {
                        let address = server.address.to_string();
                        let tls = server.tls_mode.clone();
                        (address, tls, Some(server), Some(route.backend.clone()))
                    }
                    None => {
                        warn!(
                            "No healthy backends in pool '{}' for request {}",
                            route.backend, path
                        );
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "No healthy backends available",
                        )
                            .into_response();
                    }
                }
            } else if let Some(backend) = state.config.get_backend(&route.backend) {
                // Fall back to single backend (backward compatibility)
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

                (backend.address.clone(), tls_mode, None, None)
            } else {
                error!("Backend or pool not found: {}", route.backend);
                return (StatusCode::BAD_GATEWAY, "Backend not configured").into_response();
            };

        // Build backend URL based on TLS mode
        let (backend_url, use_https) = match tls_mode {
            TlsMode::Terminate => (
                format!("http://{}{}{}", backend_address, path, query),
                false,
            ),
            TlsMode::Reencrypt => (
                format!("https://{}{}{}", backend_address, path, query),
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
                let response_time = request_start.elapsed();

                // Record success for circuit breaker (single backend)
                state.security.record_backend_result(&route.backend, true);

                // Record success for load balancer pool
                if let (Some(server), Some(ref pn)) = (&pool_server, &pool_name) {
                    state
                        .load_balancer
                        .record_completion(pn, server.as_ref(), response_time, true);
                    server.release_connection();
                }

                let (mut parts, incoming_body) = backend_response.into_parts();

                // Add CORS headers if configured
                if let Some(ref cors) = route.cors {
                    add_cors_headers(&mut parts.headers, cors);
                }

                // Add sticky session cookie if using pool with cookie affinity
                if let Some(server) = &pool_server {
                    if let Some(pool) = state.load_balancer.get_pool(&route.backend) {
                        if pool.affinity == crate::config::AffinityMode::Cookie {
                            let cookie = state
                                .load_balancer
                                .cookie_config
                                .generate_cookie(&server.id);
                            if let Ok(val) = HeaderValue::from_str(&cookie) {
                                parts.headers.insert(header::SET_COOKIE, val);
                            }
                        }
                    }
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
                    .insert(header::SERVER, HeaderValue::from_static("PQCProxy v0.2.1"));

                // Convert Incoming body to axum Body
                let response_body = Body::new(incoming_body);
                let response = Response::from_parts(parts, response_body);

                let resp_status = response.status().as_u16();

                // Record request metrics (skip error tracking for health check traffic)
                state.metrics.requests.request_end_full(
                    resp_status,
                    request_start.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );

                // Log successful response
                log_access(&AccessLogEntry {
                    remote_addr: client_addr,
                    method: method_str,
                    path,
                    protocol: "HTTP/1.1".to_string(),
                    status: resp_status,
                    body_size: 0, // Can't know body size for streaming response
                    referer,
                    user_agent,
                    host: Some(host_str),
                    response_time_ms: request_start.elapsed().as_millis() as u64,
                });

                response
            }
            Err(e) => {
                let response_time = request_start.elapsed();

                // Record failure for circuit breaker
                state.security.record_backend_result(&route.backend, false);

                // Record failure for load balancer pool
                if let (Some(server), Some(ref pn)) = (&pool_server, &pool_name) {
                    state.load_balancer.record_completion(
                        pn,
                        server.as_ref(),
                        response_time,
                        false,
                    );
                    server.release_connection();
                }

                error!("Backend request failed: {}", e);

                // Record request metrics (skip error tracking for health check traffic)
                state.metrics.requests.request_end_full(
                    502,
                    request_start.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );

                // Log backend error
                log_access(&AccessLogEntry {
                    remote_addr: client_addr,
                    method: method_str,
                    path,
                    protocol: "HTTP/1.1".to_string(),
                    status: 502,
                    body_size: 0,
                    referer,
                    user_agent,
                    host: Some(host_str),
                    response_time_ms: request_start.elapsed().as_millis() as u64,
                });

                (StatusCode::BAD_GATEWAY, format!("Backend error: {}", e)).into_response()
            }
        }
    } else {
        // No route matched - return 404
        warn!("No route matched for {} {}", host, path);

        // Record request metrics (skip error tracking for health check traffic)
        state.metrics.requests.request_end_full(
            404,
            request_start.elapsed(),
            0,
            0,
            Some(&path),
            is_health_check,
        );

        // Log 404
        log_access(&AccessLogEntry {
            remote_addr: client_addr,
            method: method_str,
            path,
            protocol: "HTTP/1.1".to_string(),
            status: 404,
            body_size: 0,
            referer,
            user_agent,
            host: Some(host_str),
            response_time_ms: request_start.elapsed().as_millis() as u64,
        });

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

/// Run HTTP redirect server (port 80 → HTTPS) with ACME HTTP-01 challenge support
pub async fn run_http_redirect_server<S: std::hash::BuildHasher + Send + Sync + 'static>(
    port: u16,
    https_port: u16,
    acme_challenges: Option<
        Arc<
            parking_lot::RwLock<
                std::collections::HashMap<String, crate::acme::PendingChallenge, S>,
            >,
        >,
    >,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let https_port_clone = https_port;

    let has_acme = acme_challenges.is_some();

    let app = Router::new().fallback(move |Host(host): Host, uri: Uri| {
        let challenges = acme_challenges.clone();
        async move {
            let path = uri.path();

            // Serve ACME HTTP-01 challenges before redirecting
            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                if let Some(ref ch) = challenges {
                    if let Some(challenge) = ch.read().get(token) {
                        info!(
                            "Serving ACME challenge for token: {}...",
                            &token[..token.len().min(12)]
                        );
                        return (
                            axum::http::StatusCode::OK,
                            [(axum::http::header::CONTENT_TYPE, "text/plain")],
                            challenge.key_authorization.clone(),
                        )
                            .into_response();
                    }
                }
            }

            let path = path.to_ascii_lowercase();
            let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

            // Build HTTPS URL
            let https_url = if https_port_clone == 443 {
                format!("https://{}{}{}", host.to_ascii_lowercase(), path, query)
            } else {
                format!(
                    "https://{}:{}{}{}",
                    host.to_ascii_lowercase(),
                    https_port_clone,
                    path,
                    query
                )
            };

            Redirect::permanent(&https_url).into_response()
        }
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!(
        "🔀 Starting HTTP→HTTPS redirect server on {} (ACME challenge support: {})",
        addr, has_acme
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}

/// Create TLS connector for re-encrypt mode with optional client cert
/// Used for TLS backend connections when tls_mode is set to reencrypt
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
    let mut added = 0;
    let mut failed = 0;
    for cert in native_certs.certs {
        match root_store.add(cert) {
            Ok(()) => added += 1,
            Err(e) => {
                debug!("Failed to add native root certificate: {}", e);
                failed += 1;
            }
        }
    }
    if failed > 0 {
        debug!(
            "Loaded {} native root certificates ({} failed - likely duplicates)",
            added, failed
        );
    }

    // Add custom CA cert if provided
    if let Some(ref ca_path) = backend.tls_cert {
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let mut ca_certs = Vec::new();
        let mut parse_errors = 0;
        for cert_result in rustls_pemfile::certs(&mut ca_reader) {
            match cert_result {
                Ok(cert) => ca_certs.push(cert),
                Err(e) => {
                    warn!(
                        "Failed to parse CA certificate from {}: {}",
                        ca_path.display(),
                        e
                    );
                    parse_errors += 1;
                }
            }
        }
        if parse_errors > 0 {
            warn!(
                "Loaded {} CA certificates from {} ({} failed to parse)",
                ca_certs.len(),
                ca_path.display(),
                parse_errors
            );
        }
        for cert in ca_certs {
            root_store.add(cert)?;
        }
    }

    // Build TLS config - use mTLS if client certs provided, otherwise no client auth
    let mut config = if let (Some(cert_path), Some(key_path)) =
        (&backend.tls_client_cert, &backend.tls_client_key)
    {
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let mut certs: Vec<CertificateDer<'static>> = Vec::new();
        let mut parse_errors = 0;
        for cert_result in rustls_pemfile::certs(&mut cert_reader) {
            match cert_result {
                Ok(cert) => certs.push(cert),
                Err(e) => {
                    warn!(
                        "Failed to parse client certificate from {}: {}",
                        cert_path.display(),
                        e
                    );
                    parse_errors += 1;
                }
            }
        }
        if parse_errors > 0 {
            warn!(
                "Loaded {} client certificates from {} ({} failed to parse)",
                certs.len(),
                cert_path.display(),
                parse_errors
            );
        }

        let key_file = File::open(key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or("No private key found")?;

        // Note: Using empty root store for mTLS (preserving original behavior)
        ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(certs, key)?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

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

/// Dangerous: No-verification TLS verifier for backends with tls_skip_verify
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // =========================================================================
    // PROXY Protocol v2 Header Builder Tests
    // =========================================================================

    #[test]
    fn test_proxy_v2_header_ipv4() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 54321));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));

        let header = build_proxy_v2_header(src, dst);

        // Total size: 12 (signature) + 4 (header) + 12 (addresses) = 28 bytes
        assert_eq!(header.len(), 28);

        // Verify signature (first 12 bytes)
        assert_eq!(&header[0..12], &PROXY_V2_SIGNATURE);

        // Version 2 + PROXY command
        assert_eq!(header[12], proxy_v2::VERSION_PROXY);

        // IPv4 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET_STREAM);

        // Address length (12 bytes for IPv4)
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);

        // Source IP: 192.168.1.100
        assert_eq!(&header[16..20], &[192, 168, 1, 100]);

        // Destination IP: 10.0.0.1
        assert_eq!(&header[20..24], &[10, 0, 0, 1]);

        // Source port: 54321 (0xD431)
        assert_eq!(u16::from_be_bytes([header[24], header[25]]), 54321);

        // Destination port: 443 (0x01BB)
        assert_eq!(u16::from_be_bytes([header[26], header[27]]), 443);
    }

    #[test]
    fn test_proxy_v2_header_ipv6() {
        let src = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            12345,
            0,
            0,
        ));
        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            8443,
            0,
            0,
        ));

        let header = build_proxy_v2_header(src, dst);

        // Total size: 12 (signature) + 4 (header) + 36 (addresses) = 52 bytes
        assert_eq!(header.len(), 52);

        // Verify signature
        assert_eq!(&header[0..12], &PROXY_V2_SIGNATURE);

        // Version 2 + PROXY command
        assert_eq!(header[12], proxy_v2::VERSION_PROXY);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Address length (36 bytes for IPv6)
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 36);

        // Source IP: 2001:db8::1
        let expected_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(&header[16..32], &expected_src);

        // Destination IP: fe80::1
        let expected_dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(&header[32..48], &expected_dst);

        // Source port: 12345
        assert_eq!(u16::from_be_bytes([header[48], header[49]]), 12345);

        // Destination port: 8443
        assert_eq!(u16::from_be_bytes([header[50], header[51]]), 8443);
    }

    #[test]
    fn test_proxy_v2_header_mixed_ipv4_to_ipv6() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000));
        let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));

        let header = build_proxy_v2_header(src, dst);

        // Should use IPv6 format (52 bytes)
        assert_eq!(header.len(), 52);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Source should be IPv4-mapped IPv6 (::ffff:127.0.0.1)
        let expected_src = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets();
        assert_eq!(&header[16..32], &expected_src);
    }

    #[test]
    fn test_proxy_v2_header_mixed_ipv6_to_ipv4() {
        let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5000, 0, 0));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80));

        let header = build_proxy_v2_header(src, dst);

        // Should use IPv6 format (52 bytes)
        assert_eq!(header.len(), 52);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Destination should be IPv4-mapped IPv6 (::ffff:10.0.0.1)
        let expected_dst = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets();
        assert_eq!(&header[32..48], &expected_dst);
    }

    #[test]
    fn test_proxy_v2_signature_constant() {
        // Verify the signature matches the PROXY protocol v2 spec
        let expected = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        assert_eq!(PROXY_V2_SIGNATURE, expected);
    }

    #[test]
    fn test_proxy_v2_constants() {
        // Version 2, PROXY command = 0x21
        assert_eq!(proxy_v2::VERSION_PROXY, 0x21);

        // Version 2, LOCAL command = 0x20
        assert_eq!(proxy_v2::VERSION_LOCAL, 0x20);

        // IPv4 + TCP = 0x11
        assert_eq!(proxy_v2::AF_INET_STREAM, 0x11);

        // IPv6 + TCP = 0x21
        assert_eq!(proxy_v2::AF_INET6_STREAM, 0x21);

        // Unspecified = 0x00
        assert_eq!(proxy_v2::AF_UNSPEC, 0x00);
    }

    // =========================================================================
    // ClientHello SNI Parser Tests
    // =========================================================================

    /// Build a minimal valid TLS 1.2 ClientHello with SNI extension
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + hostname_bytes.len(); // type(1) + len(2) + name
        let sni_list_len = sni_entry_len;
        let sni_ext_len = 2 + sni_list_len; // list_len(2) + list

        // Extensions: SNI only
        let extensions_len = 4 + sni_ext_len; // type(2) + len(2) + data

        // ClientHello body (minimal)
        let mut client_hello = Vec::new();

        // Version (TLS 1.2 = 0x0303)
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID length (0)
        client_hello.push(0);

        // Cipher suites (2 bytes length + 2 cipher suites)
        client_hello.extend_from_slice(&[0x00, 0x04]); // 4 bytes
        client_hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        client_hello.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // Compression methods (1 byte length + null)
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions length
        client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());

        // SNI extension (type 0x0000)
        client_hello.extend_from_slice(&[0x00, 0x00]); // Extension type
        client_hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Extension length
        client_hello.extend_from_slice(&(sni_list_len as u16).to_be_bytes()); // SNI list length
        client_hello.push(0x00); // Name type (host_name)
        client_hello.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(hostname_bytes);

        // Handshake header
        let handshake_len = client_hello.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(0x00); // Length high byte (always 0 for reasonable sizes)
        handshake.extend_from_slice(&(handshake_len as u16).to_be_bytes());
        handshake.extend(client_hello);

        // TLS record header
        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (legacy version in record)
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend(handshake);

        record
    }

    #[test]
    fn test_sni_extraction_simple() {
        let data = build_client_hello_with_sni("example.com");
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_sni_extraction_subdomain() {
        let data = build_client_hello_with_sni("api.pqcrypta.com");
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some("api.pqcrypta.com".to_string()));
    }

    #[test]
    fn test_sni_extraction_long_hostname() {
        let hostname = "very-long-subdomain.another-subdomain.example.domain.com";
        let data = build_client_hello_with_sni(hostname);
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_with_port_like_name() {
        // Some hostnames might look unusual
        let data = build_client_hello_with_sni("server-443.internal.local");
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some("server-443.internal.local".to_string()));
    }

    #[test]
    fn test_sni_extraction_empty_data() {
        let sni = extract_sni_from_client_hello(&[]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_too_short() {
        // Less than 5 bytes (TLS record header)
        let sni = extract_sni_from_client_hello(&[0x16, 0x03, 0x01]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_not_handshake() {
        // Application data record (0x17) instead of handshake (0x16)
        let data = [0x17, 0x03, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00];
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_not_client_hello() {
        // ServerHello (0x02) instead of ClientHello (0x01)
        let data = [
            0x16, 0x03, 0x03, 0x00, 0x05, // TLS record header
            0x02, 0x00, 0x00, 0x01, 0x00, // ServerHello header
        ];
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_truncated_handshake() {
        // Valid record header but truncated handshake
        let data = [
            0x16, 0x03, 0x03, 0x00, 0x02, // TLS record header (claims 2 bytes)
            0x01, 0x00, // Truncated ClientHello
        ];
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_no_extensions() {
        // ClientHello without extensions
        let mut data = Vec::new();

        // TLS record header
        data.push(0x16); // Handshake
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // We'll set length later
        let record_len_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // Placeholder

        // Handshake header
        data.push(0x01); // ClientHello
        let handshake_len_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // Placeholder (3 bytes)

        let client_hello_start = data.len();

        // Version
        data.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (0)
        data.push(0);

        // Cipher suites
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // 2 bytes, TLS_EMPTY_RENEGOTIATION_INFO_SCSV

        // Compression methods
        data.extend_from_slice(&[0x01, 0x00]);

        // NO extensions (0 length)
        data.extend_from_slice(&[0x00, 0x00]);

        // Fix lengths
        let client_hello_len = data.len() - client_hello_start;
        let handshake_len = client_hello_len + 4;
        let record_len = handshake_len;

        data[record_len_pos] = ((record_len >> 8) & 0xFF) as u8;
        data[record_len_pos + 1] = (record_len & 0xFF) as u8;

        data[handshake_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        data[handshake_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_with_grease_extensions() {
        // Build ClientHello with GREASE extension before SNI
        let hostname = "grease-test.example.com";
        let hostname_bytes = hostname.as_bytes();

        let mut client_hello = Vec::new();

        // Version
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID
        client_hello.push(0);

        // Cipher suites
        client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let mut extensions = Vec::new();

        // GREASE extension (0x0A0A)
        extensions.extend_from_slice(&[0x0A, 0x0A]); // GREASE type
        extensions.extend_from_slice(&[0x00, 0x01]); // Length 1
        extensions.push(0x00); // Data

        // SNI extension
        let sni_list_len = 3 + hostname_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
        extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0x00); // host_name type
        extensions.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(hostname_bytes);

        // Another GREASE extension (0xFAFA)
        extensions.extend_from_slice(&[0xFA, 0xFA]); // GREASE type
        extensions.extend_from_slice(&[0x00, 0x00]); // Length 0

        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend(extensions);

        // Build full record
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(0x00);
        handshake.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        handshake.extend(client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);

        let sni = extract_sni_from_client_hello(&record);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_long_session_id() {
        // ClientHello with maximum session ID (32 bytes)
        let hostname = "session-test.example.com";
        let hostname_bytes = hostname.as_bytes();

        let mut client_hello = Vec::new();

        // Version
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID (32 bytes - maximum)
        client_hello.push(32);
        client_hello.extend_from_slice(&[0xAB; 32]);

        // Cipher suites
        client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions (SNI only)
        let sni_list_len = 3 + hostname_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        let extensions_len = 4 + sni_ext_len;

        client_hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&[0x00, 0x00]); // SNI type
        client_hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        client_hello.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        client_hello.push(0x00);
        client_hello.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(hostname_bytes);

        // Build full record
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(0x00);
        handshake.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        handshake.extend(client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend(handshake);

        let sni = extract_sni_from_client_hello(&record);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_punycode_hostname() {
        // International domain name in ASCII-compatible encoding
        let hostname = "xn--n3h.example.com"; // Contains emoji in punycode
        let data = build_client_hello_with_sni(hostname);
        let sni = extract_sni_from_client_hello(&data);
        assert_eq!(sni, Some(hostname.to_string()));
    }
}
