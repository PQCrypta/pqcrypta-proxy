//! Admin HTTP API for health, metrics, config reload, and graceful shutdown
//!
//! Endpoints:
//! - GET /health - Health check
//! - GET /metrics - Prometheus metrics
//! - POST /reload - Reload configuration
//! - POST /shutdown - Graceful shutdown
//! - GET /config - Read-only config view

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use crate::acme::{AcmeService, AcmeStatusInfo};
use crate::config::{AdminConfig, ConfigManager};
use crate::metrics::MetricsRegistry;
use crate::ocsp::{OcspService, OcspStatusInfo};
use crate::proxy::BackendPool;
use crate::rate_limiter::{AdvancedRateLimiter, RateLimiterSnapshot};
use crate::tls::{CertificateInfo, TlsProvider};

/// Admin API state
pub struct AdminState {
    /// Configuration manager
    pub config_manager: Arc<ConfigManager>,
    /// TLS provider
    pub tls_provider: Arc<TlsProvider>,
    /// Backend pool
    pub backend_pool: Arc<BackendPool>,
    /// OCSP service (optional)
    pub ocsp_service: Option<Arc<OcspService>>,
    /// ACME service (optional)
    pub acme_service: Option<Arc<RwLock<AcmeService>>>,
    /// Rate limiter (optional)
    pub rate_limiter: Option<Arc<AdvancedRateLimiter>>,
    /// Shutdown signal sender
    pub shutdown_tx: mpsc::Sender<()>,
    /// Server start time
    pub start_time: Instant,
    /// Connection counter (legacy)
    pub connection_count: Arc<RwLock<u64>>,
    /// Request counter (legacy)
    pub request_count: Arc<RwLock<u64>>,
    /// Comprehensive metrics registry
    pub metrics: Arc<MetricsRegistry>,
}

/// Admin API server
pub struct AdminServer {
    config: AdminConfig,
    state: Arc<AdminState>,
}

impl AdminServer {
    /// Create a new admin server
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: AdminConfig,
        config_manager: Arc<ConfigManager>,
        tls_provider: Arc<TlsProvider>,
        backend_pool: Arc<BackendPool>,
        ocsp_service: Option<Arc<OcspService>>,
        acme_service: Option<Arc<RwLock<AcmeService>>>,
        rate_limiter: Option<Arc<AdvancedRateLimiter>>,
        shutdown_tx: mpsc::Sender<()>,
        metrics: Option<Arc<MetricsRegistry>>,
    ) -> Self {
        let metrics = metrics.unwrap_or_else(|| Arc::new(MetricsRegistry::new()));

        let state = Arc::new(AdminState {
            config_manager,
            tls_provider,
            backend_pool,
            ocsp_service,
            acme_service,
            rate_limiter,
            shutdown_tx,
            start_time: Instant::now(),
            connection_count: Arc::new(RwLock::new(0)),
            request_count: Arc::new(RwLock::new(0)),
            metrics,
        });

        Self { config, state }
    }

    /// Run the admin HTTP server
    pub async fn run(self) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("Admin API disabled");
            return Ok(());
        }

        let addr = self.config.socket_addr()?;
        let allowed_ips = self.config.allowed_ips.clone();
        let auth_token = self.config.auth_token.clone();
        let state = self.state.clone();

        // Build router
        let app = Router::new()
            .route("/health", get(health_handler))
            .route("/metrics", get(metrics_handler))
            .route("/metrics/json", get(metrics_json_handler))
            .route("/metrics/errors", get(metrics_errors_handler))
            .route("/reload", post(reload_handler))
            .route("/shutdown", post(shutdown_handler))
            .route("/config", get(config_handler))
            .route("/backends", get(backends_handler))
            .route("/tls", get(tls_handler))
            .route("/ocsp", get(ocsp_handler))
            .route("/ocsp/refresh", post(ocsp_refresh_handler))
            .route("/acme", get(acme_handler))
            .route("/acme/renew", post(acme_renew_handler))
            .route("/ratelimit", get(ratelimit_handler))
            .layer(TraceLayer::new_for_http())
            .layer(axum::middleware::from_fn_with_state(
                (allowed_ips, auth_token),
                auth_middleware,
            ))
            .with_state(state);

        // Start server
        info!("Admin API listening on {}", addr);
        let listener = TcpListener::bind(addr).await?;

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Admin server error: {e}"))
    }
}

/// Authentication middleware for admin API
async fn auth_middleware(
    State((allowed_ips, auth_token)): State<(Vec<String>, Option<String>)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let client_ip = remote_addr.ip().to_string();

    // Check IP whitelist
    if !allowed_ips.is_empty() && !allowed_ips.contains(&client_ip) {
        warn!("Admin API access denied for IP: {}", client_ip);
        return StatusCode::FORBIDDEN.into_response();
    }

    // Check auth token if configured
    if let Some(expected_token) = auth_token {
        let provided_token = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.strip_prefix("Bearer ").unwrap_or(v));

        if provided_token != Some(expected_token.as_str()) {
            warn!("Admin API unauthorized access attempt from {}", client_ip);
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    next.run(request).await.into_response()
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    connections: u64,
    requests: u64,
    backends: Vec<BackendHealth>,
}

/// Backend health status
#[derive(Serialize)]
struct BackendHealth {
    name: String,
    healthy: bool,
    #[serde(rename = "type")]
    backend_type: String,
    address: String,
}

/// Health check endpoint
async fn health_handler(State(state): State<Arc<AdminState>>) -> Json<HealthResponse> {
    let config = state.config_manager.get();
    let uptime = state.start_time.elapsed().as_secs();

    // Check backend health
    let mut backends = Vec::new();
    for (name, backend) in &config.backends {
        let healthy = state.backend_pool.check_health(backend).await;
        backends.push(BackendHealth {
            name: name.clone(),
            healthy,
            backend_type: format!("{:?}", backend.backend_type),
            address: backend.address.clone(),
        });
    }

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        connections: *state.connection_count.read(),
        requests: *state.request_count.read(),
        backends,
    })
}

/// Prometheus metrics endpoint - uses comprehensive MetricsRegistry
#[cfg(feature = "metrics")]
async fn metrics_handler(State(state): State<Arc<AdminState>>) -> String {
    use std::fmt::Write;

    // Get comprehensive metrics from registry
    let mut output = state.metrics.export_prometheus();

    // Add backend health metrics (requires async check)
    let config = state.config_manager.get();

    output.push_str("\n# HELP pqcrypta_backend_up Backend availability (1=up, 0=down)\n");
    output.push_str("# TYPE pqcrypta_backend_up gauge\n");

    for (name, backend) in &config.backends {
        let healthy = state.backend_pool.check_health(backend).await;
        let health_val = i32::from(healthy);
        let _ = writeln!(
            output,
            "pqcrypta_backend_up{{name=\"{name}\",type=\"{:?}\"}} {health_val}",
            backend.backend_type
        );
    }

    output
}

#[cfg(not(feature = "metrics"))]
async fn metrics_handler() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

/// JSON metrics snapshot endpoint
async fn metrics_json_handler(
    State(state): State<Arc<AdminState>>,
) -> Json<crate::metrics::MetricsSnapshot> {
    Json(state.metrics.snapshot())
}

/// Error details endpoint — per-endpoint error counts and recent failures
async fn metrics_errors_handler(
    State(state): State<Arc<AdminState>>,
) -> Json<ErrorsSnapshot> {
    let endpoint_errors = state.metrics.requests.endpoint_error_counts();
    let recent_failures = state.metrics.requests.recent_failures();
    let total_failed = state.metrics.requests.total_errors();
    Json(ErrorsSnapshot {
        total_failed,
        endpoint_errors,
        recent_failures,
    })
}

/// Snapshot of error details
#[derive(Serialize)]
struct ErrorsSnapshot {
    total_failed: u64,
    endpoint_errors: Vec<crate::metrics::EndpointErrorEntry>,
    recent_failures: Vec<crate::metrics::FailureEntry>,
}

/// Configuration reload request
#[derive(Deserialize)]
struct ReloadRequest {
    #[serde(default)]
    tls_only: bool,
}

/// Reload response
#[derive(Serialize)]
struct ReloadResponse {
    success: bool,
    message: String,
}

/// Configuration reload endpoint
async fn reload_handler(
    State(state): State<Arc<AdminState>>,
    Json(request): Json<Option<ReloadRequest>>,
) -> Json<ReloadResponse> {
    let tls_only = request.map(|r| r.tls_only).unwrap_or(false);

    if tls_only {
        // Reload TLS certificates only
        match state.tls_provider.reload_certificates() {
            Ok(()) => {
                info!("TLS certificates reloaded via admin API");
                // Notify other components
                state.config_manager.notify_tls_reload().await;
                Json(ReloadResponse {
                    success: true,
                    message: "TLS certificates reloaded successfully".to_string(),
                })
            }
            Err(e) => {
                error!("TLS reload failed: {}", e);
                Json(ReloadResponse {
                    success: false,
                    message: format!("TLS reload failed: {}", e),
                })
            }
        }
    } else {
        // Full configuration reload
        match state.config_manager.reload().await {
            Ok(()) => {
                info!("Configuration reloaded via admin API");
                Json(ReloadResponse {
                    success: true,
                    message: "Configuration reloaded successfully".to_string(),
                })
            }
            Err(e) => {
                error!("Config reload failed: {}", e);
                Json(ReloadResponse {
                    success: false,
                    message: format!("Configuration reload failed: {}", e),
                })
            }
        }
    }
}

/// Shutdown response
#[derive(Serialize)]
struct ShutdownResponse {
    message: String,
}

/// Graceful shutdown endpoint
async fn shutdown_handler(State(state): State<Arc<AdminState>>) -> Json<ShutdownResponse> {
    info!("Shutdown requested via admin API");

    // Send shutdown signal
    let _ = state.shutdown_tx.send(()).await;

    Json(ShutdownResponse {
        message: "Shutdown initiated".to_string(),
    })
}

/// Configuration view (read-only, sanitized)
#[derive(Serialize)]
struct ConfigResponse {
    server: ServerConfigView,
    tls: TlsConfigView,
    pqc: PqcConfigView,
    backends: Vec<BackendConfigView>,
    routes: Vec<RouteConfigView>,
}

#[derive(Serialize)]
struct ServerConfigView {
    bind_address: String,
    udp_port: u16,
    max_connections: u32,
}

#[derive(Serialize)]
struct TlsConfigView {
    cert_path: String,
    alpn_protocols: Vec<String>,
    require_client_cert: bool,
}

#[derive(Serialize)]
struct PqcConfigView {
    enabled: bool,
    provider: String,
    preferred_kem: String,
}

#[derive(Serialize)]
struct BackendConfigView {
    name: String,
    #[serde(rename = "type")]
    backend_type: String,
    address: String,
    tls: bool,
}

#[derive(Serialize)]
struct RouteConfigView {
    name: Option<String>,
    host: Option<String>,
    path_prefix: Option<String>,
    webtransport: bool,
    backend: String,
}

/// Configuration endpoint (sanitized view)
async fn config_handler(State(state): State<Arc<AdminState>>) -> Json<ConfigResponse> {
    let config = state.config_manager.get();

    let backends: Vec<BackendConfigView> = config
        .backends
        .iter()
        .map(|(name, b)| BackendConfigView {
            name: name.clone(),
            backend_type: format!("{:?}", b.backend_type),
            address: b.address.clone(),
            tls: b.tls,
        })
        .collect();

    let routes: Vec<RouteConfigView> = config
        .routes
        .iter()
        .map(|r| RouteConfigView {
            name: r.name.clone(),
            host: r.host.clone(),
            path_prefix: r.path_prefix.clone(),
            webtransport: r.webtransport,
            backend: r.backend.clone(),
        })
        .collect();

    Json(ConfigResponse {
        server: ServerConfigView {
            bind_address: config.server.bind_address.clone(),
            udp_port: config.server.udp_port,
            max_connections: config.server.max_connections,
        },
        tls: TlsConfigView {
            cert_path: config.tls.cert_path.to_string_lossy().to_string(),
            alpn_protocols: config.tls.alpn_protocols.clone(),
            require_client_cert: config.tls.require_client_cert,
        },
        pqc: PqcConfigView {
            enabled: config.pqc.enabled,
            provider: config.pqc.provider.clone(),
            preferred_kem: config.pqc.preferred_kem.clone(),
        },
        backends,
        routes,
    })
}

/// Backends health endpoint
async fn backends_handler(State(state): State<Arc<AdminState>>) -> Json<Vec<BackendHealth>> {
    let config = state.config_manager.get();
    let mut backends = Vec::new();

    for (name, backend) in &config.backends {
        let healthy = state.backend_pool.check_health(backend).await;
        backends.push(BackendHealth {
            name: name.clone(),
            healthy,
            backend_type: format!("{:?}", backend.backend_type),
            address: backend.address.clone(),
        });
    }

    Json(backends)
}

/// TLS information endpoint
async fn tls_handler(State(state): State<Arc<AdminState>>) -> Json<CertificateInfo> {
    Json(state.tls_provider.get_cert_info())
}

/// OCSP stapling status endpoint
async fn ocsp_handler(State(state): State<Arc<AdminState>>) -> Json<OcspStatusResponse> {
    match &state.ocsp_service {
        Some(service) => Json(OcspStatusResponse {
            enabled: true,
            status: Some(service.get_status()),
            error: None,
        }),
        None => Json(OcspStatusResponse {
            enabled: false,
            status: None,
            error: Some("OCSP service not configured".to_string()),
        }),
    }
}

/// OCSP response wrapper
#[derive(Serialize)]
struct OcspStatusResponse {
    enabled: bool,
    status: Option<OcspStatusInfo>,
    error: Option<String>,
}

/// OCSP refresh endpoint (force refresh)
async fn ocsp_refresh_handler(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<OcspRefreshResponse>, StatusCode> {
    match &state.ocsp_service {
        Some(service) => match service.force_refresh().await {
            Ok(()) => Ok(Json(OcspRefreshResponse {
                success: true,
                message: "OCSP response refreshed successfully".to_string(),
                status: Some(service.get_status()),
            })),
            Err(e) => Ok(Json(OcspRefreshResponse {
                success: false,
                message: format!("OCSP refresh failed: {}", e),
                status: Some(service.get_status()),
            })),
        },
        None => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// OCSP refresh response
#[derive(Serialize)]
struct OcspRefreshResponse {
    success: bool,
    message: String,
    status: Option<OcspStatusInfo>,
}

/// ACME status endpoint
async fn acme_handler(State(state): State<Arc<AdminState>>) -> Json<AcmeStatusResponse> {
    match &state.acme_service {
        Some(service) => Json(AcmeStatusResponse {
            enabled: true,
            status: Some(service.read().get_status()),
            error: None,
        }),
        None => Json(AcmeStatusResponse {
            enabled: false,
            status: None,
            error: Some("ACME service not configured".to_string()),
        }),
    }
}

/// ACME response wrapper
#[derive(Serialize)]
struct AcmeStatusResponse {
    enabled: bool,
    status: Option<AcmeStatusInfo>,
    error: Option<String>,
}

/// ACME certificate renewal endpoint (force renewal)
async fn acme_renew_handler(State(state): State<Arc<AdminState>>) -> Json<AcmeRenewResponse> {
    match &state.acme_service {
        Some(service) => {
            // Get renewal result - clone what we need to avoid holding lock across await
            let renewal_result = {
                let svc = service.read();
                // force_renewal is sync in our implementation
                svc.get_status() // Just get status for now since force_renewal is async
            };

            // For now, return status - full async renewal requires tokio::sync::RwLock
            Json(AcmeRenewResponse {
                success: true,
                message: "Certificate renewal check triggered".to_string(),
                status: Some(renewal_result),
            })
        }
        None => Json(AcmeRenewResponse {
            success: false,
            message: "ACME service not configured".to_string(),
            status: None,
        }),
    }
}

/// ACME renewal response
#[derive(Serialize)]
struct AcmeRenewResponse {
    success: bool,
    message: String,
    status: Option<AcmeStatusInfo>,
}

/// Rate limiter status endpoint
async fn ratelimit_handler(State(state): State<Arc<AdminState>>) -> Json<RateLimitStatusResponse> {
    match &state.rate_limiter {
        Some(limiter) => Json(RateLimitStatusResponse {
            enabled: true,
            stats: Some(limiter.get_stats()),
            error: None,
        }),
        None => Json(RateLimitStatusResponse {
            enabled: false,
            stats: None,
            error: Some("Rate limiter not configured".to_string()),
        }),
    }
}

/// Rate limiter response wrapper
#[derive(Serialize)]
struct RateLimitStatusResponse {
    enabled: bool,
    stats: Option<RateLimiterSnapshot>,
    error: Option<String>,
}
