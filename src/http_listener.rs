//! HTTP/1.1 and HTTP/2 listener with Alt-Svc advertisement
//!
//! This module provides a TCP-based HTTP listener that:
//! - Serves HTTP/1.1 and HTTP/2 requests
//! - Advertises HTTP/3 and WebTransport via Alt-Svc headers
//! - Enables standalone operation without nginx dependency
//!
//! Clients connect to TCP, receive Alt-Svc headers, then upgrade to QUIC/WebTransport.

use std::net::SocketAddr;
use std::sync::Arc;
use std::path::Path;

use axum::{
    Router,
    routing::get,
    response::{IntoResponse, Response},
    http::{header, StatusCode, HeaderValue},
    extract::State,
    Json,
};
use axum_server::tls_rustls::RustlsConfig;
use serde_json::json;
use tokio::net::TcpListener;
use tracing::{info, error};

use crate::config::ProxyConfig;

/// HTTP listener state
#[derive(Clone)]
pub struct HttpListenerState {
    pub config: Arc<ProxyConfig>,
    pub port: u16,
}

/// Create and run the HTTP listener
pub async fn run_http_listener(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let port = addr.port();

    info!("🌐 Starting HTTP/1.1 & HTTP/2 listener on {} (TCP)", addr);
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    let state = HttpListenerState {
        config: config.clone(),
        port,
    };

    // Build router with Alt-Svc middleware
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/info", get(info_handler))
        .route("/.well-known/webtransport", get(webtransport_info_handler))
        .fallback(fallback_handler)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            add_alt_svc_header,
        ))
        .with_state(state);

    // Check if cert files exist
    if !Path::new(cert_path).exists() {
        error!("❌ Certificate file not found: {}", cert_path);
        return Err(format!("Certificate file not found: {}", cert_path).into());
    }
    if !Path::new(key_path).exists() {
        error!("❌ Key file not found: {}", key_path);
        return Err(format!("Key file not found: {}", key_path).into());
    }

    // Configure TLS
    let tls_config = RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| {
            error!("❌ Failed to load TLS certificates: {}", e);
            e
        })?;

    info!("✅ TLS configured for HTTP listener");
    info!("🔒 HTTPS ready on port {} (TCP)", port);
    info!("📡 WebTransport discovery endpoint: /.well-known/webtransport");

    // Run HTTPS server
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| {
            error!("❌ HTTP listener error: {}", e);
            e
        })?;

    Ok(())
}

/// Middleware to add Alt-Svc header to all responses
async fn add_alt_svc_header(
    State(state): State<HttpListenerState>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;

    // Add Alt-Svc header advertising HTTP/3 and WebTransport on the same port
    let alt_svc_value = format!(
        "h3=\":{}\"; ma=86400, h3-29=\":{}\"; ma=86400",
        state.port, state.port
    );

    if let Ok(value) = HeaderValue::from_str(&alt_svc_value) {
        response.headers_mut().insert("alt-svc", value);
    }

    // Add other useful headers
    response.headers_mut().insert(
        "x-webtransport-port",
        HeaderValue::from_str(&state.port.to_string()).unwrap_or_else(|_| HeaderValue::from_static("4434")),
    );

    response
}

/// Root handler
async fn root_handler(State(state): State<HttpListenerState>) -> impl IntoResponse {
    let response = json!({
        "service": "pqcrypta-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "QUIC/HTTP3/WebTransport Proxy with PQC TLS",
        "protocols": {
            "http1": true,
            "http2": true,
            "http3": true,
            "webtransport": true
        },
        "webtransport": {
            "port": state.port,
            "path": "/",
            "endpoint": format!("https://{}:{}/",
                state.config.server.bind_address,
                state.port
            )
        },
        "upgrade": {
            "instructions": "Connect via HTTPS to receive Alt-Svc header, then upgrade to HTTP/3/WebTransport",
            "alt_svc": format!("h3=\":{}\"; ma=86400", state.port)
        }
    });

    Json(response)
}

/// Health check handler
async fn health_handler(State(state): State<HttpListenerState>) -> impl IntoResponse {
    let response = json!({
        "status": "healthy",
        "service": "pqcrypta-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "listeners": {
            "http_tcp": format!("0.0.0.0:{}", state.port),
            "quic_udp": format!("0.0.0.0:{}", state.port),
            "webtransport": true
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    Json(response)
}

/// Service info handler
async fn info_handler(State(state): State<HttpListenerState>) -> impl IntoResponse {
    let response = json!({
        "name": "pqcrypta-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Standalone QUIC/HTTP3/WebTransport Proxy with Hybrid PQC TLS",
        "repository": "https://github.com/PQCrypta/pqcrypta-proxy",
        "license": "MIT OR Apache-2.0",
        "features": [
            "HTTP/1.1 support",
            "HTTP/2 support",
            "HTTP/3 (QUIC) support",
            "WebTransport support",
            "Post-Quantum Cryptography (hybrid key exchange)",
            "Automatic Alt-Svc advertisement",
            "Standalone operation (no nginx required)"
        ],
        "configuration": {
            "port": state.port,
            "backends": state.config.backends.len(),
            "routes": state.config.routes.len(),
            "pqc_enabled": state.config.pqc.enabled
        }
    });

    Json(response)
}

/// WebTransport discovery endpoint
async fn webtransport_info_handler(State(state): State<HttpListenerState>) -> impl IntoResponse {
    let response = json!({
        "webtransport": {
            "supported": true,
            "version": "draft-ietf-webtrans-http3",
            "port": state.port,
            "paths": ["/", "/webtransport", "/encrypt", "/decrypt", "/keys"],
            "endpoint": format!("https://localhost:{}/", state.port),
            "alpn": ["h3"],
            "settings": {
                "SETTINGS_ENABLE_WEBTRANSPORT": 1,
                "SETTINGS_WEBTRANSPORT_MAX_SESSIONS": 100
            }
        },
        "connection_instructions": {
            "step1": "Connect to this endpoint via HTTPS (HTTP/1.1 or HTTP/2)",
            "step2": "Receive Alt-Svc header advertising HTTP/3",
            "step3": "Browser automatically upgrades to QUIC/HTTP/3",
            "step4": "Use WebTransport API to establish session",
            "example_js": "const transport = new WebTransport('https://host:port/');"
        }
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(response),
    )
}

/// Fallback handler for unmatched routes
async fn fallback_handler(State(state): State<HttpListenerState>) -> impl IntoResponse {
    let response = json!({
        "error": "Not Found",
        "message": "This endpoint is not available over HTTP. For WebTransport operations, upgrade to HTTP/3.",
        "available_endpoints": [
            "/",
            "/health",
            "/info",
            "/.well-known/webtransport"
        ],
        "webtransport": {
            "port": state.port,
            "upgrade": "Use Alt-Svc header to upgrade to HTTP/3/WebTransport"
        }
    });

    (StatusCode::NOT_FOUND, Json(response))
}
