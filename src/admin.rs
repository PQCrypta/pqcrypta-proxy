//! Admin HTTP API for health, metrics, config reload, and graceful shutdown
//!
//! Endpoints:
//! - GET /health - Health check
//! - GET /metrics - Prometheus metrics
//! - POST /reload - Reload configuration
//! - POST /shutdown - Graceful shutdown
//! - GET /config - Read-only config view

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use subtle::ConstantTimeEq;

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
use crate::audit_logger::{AuditEvent, AuditLogger};
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
    /// Structured audit logger for security-relevant events
    pub audit_logger: Option<Arc<AuditLogger>>,
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
        audit_logger: Option<Arc<AuditLogger>>,
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
            audit_logger,
        });

        Self { config, state }
    }

    /// Run the admin HTTP server
    pub async fn run(self) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("Admin API disabled");
            return Ok(());
        }

        // SEC-A03: The admin API does not yet implement mTLS.  Refuse to start
        // when require_mtls = true so that operators who set this option are not
        // silently left with an unprotected endpoint.
        if self.config.require_mtls {
            return Err(anyhow::anyhow!(
                "Admin API: require_mtls = true but mTLS is not supported on the admin \
                 listener.  Either set require_mtls = false and rely on the auth_token + \
                 allowed_ips controls, or disable the admin API.  Aborting startup to \
                 prevent operating without the expected security control."
            ));
        }

        let addr = self.config.socket_addr()?;

        // SEC-A02: Warn loudly when the admin API is bound to a non-loopback address
        // because all admin traffic — including the Bearer token — is transmitted as
        // plain HTTP.  Operators who need remote admin access should place the proxy
        // behind a TLS-terminating tunnel (e.g. SSH port-forward or WireGuard).
        let is_loopback = addr.ip().is_loopback();
        if !is_loopback {
            warn!(
                "⚠️  Admin API is bound to {} (non-loopback) without TLS. \
                 All admin traffic including auth tokens is transmitted in cleartext. \
                 Consider restricting bind_address to 127.0.0.1 or using a TLS tunnel \
                 for remote admin access.",
                addr
            );
        }

        // P1-fix: Refuse to start when require_loopback = true (default) and the
        // admin bind address is not loopback.  Operators who need remote admin
        // access must set [admin] require_loopback = false and accept the risk of
        // transmitting Bearer tokens in cleartext (or place a TLS tunnel in front).
        if self.config.require_loopback && !is_loopback {
            return Err(anyhow::anyhow!(
                "Admin API: bind address {} is not loopback and require_loopback = true. \
                 Set [admin] require_loopback = false to allow non-loopback binds, \
                 or restrict bind_address to 127.0.0.1 / ::1.",
                addr
            ));
        }

        // SR-03: If no auth_token is configured, generate a random 32-byte
        // session token and log it so the operator can copy it into the config
        // for persistence.  This ensures every startup always has token auth
        // active (the token changes each restart until the operator pins one).
        let effective_token: Option<String> = match &self.config.auth_token {
            Some(t) => Some(t.clone()),
            None => {
                // P3-fix: use OsRng (cryptographically secure) instead of thread_rng
                // (designed for simulation, not secret generation).
                use rand::Rng;
                use rand::rngs::OsRng;
                let token: String = OsRng
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(48)
                    .map(char::from)
                    .collect();
                // SEC-06: Print the token to stderr (bypasses structured log pipeline) so
                // it is not captured by log aggregators/SIEMs in plaintext. The warn!
                // entry records the event without exposing the secret value.
                eprintln!(
                    "[ADMIN] No auth_token configured. Copy the following line into your \
                     [admin] config section to persist it between restarts:\n  \
                     auth_token = \"{}\"",
                    token
                );
                warn!(
                    "Admin API: no auth_token configured — generated ephemeral session token. \
                     Token printed to stderr. Set auth_token in [admin] config to persist it."
                );
                Some(token)
            }
        };

        // SEC-005 / AUD-10 / F-08: Build the auth state with per-IP and global
        // failed-attempt trackers plus the exponential back-off counter.
        let auth_state = Arc::new(AdminAuthState {
            allowed_ips: self.config.allowed_ips.clone(),
            auth_token: effective_token,
            failed_attempts: Arc::new(DashMap::new()),
            global_failure_count: Arc::new(AtomicU32::new(0)),
            global_cooldown_until: Arc::new(RwLock::new(None)),
            global_cooldown_count: Arc::new(AtomicU32::new(0)),
        });

        // F-14: Endpoint-level cooldown state to prevent ACME/OCSP quota exhaustion.
        let endpoint_cooldowns = Arc::new(EndpointCooldowns {
            acme_renew_last: Arc::new(RwLock::new(None)),
            ocsp_refresh_last: Arc::new(RwLock::new(None)),
        });

        // SEC-007: Background eviction task — removes entries whose rate-limit
        // window has long expired so the map cannot grow without bound under a
        // rotating source-IP scan.  Runs every ADMIN_AUTH_WINDOW; removes entries
        // older than 2× the window (i.e. entries that have been idle for at least
        // two full windows and therefore have no active lockout effect).
        {
            let map = Arc::clone(&auth_state.failed_attempts);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(ADMIN_AUTH_WINDOW);
                loop {
                    interval.tick().await;
                    let cutoff = Instant::now()
                        .checked_sub(ADMIN_AUTH_WINDOW * 2)
                        .unwrap_or_else(Instant::now);
                    map.retain(|_, (_, window_start)| *window_start > cutoff);
                }
            });
        }

        let state = self.state.clone();

        // F-03: Split the router into a public tier and an authenticated tier.
        //
        // Public endpoints (no auth required):
        //   GET /health   — used by load balancer and container health probes.
        //                   Returns only {status, version, uptime} to avoid leaking
        //                   internal topology.
        //
        // All other endpoints require the Bearer token and are subject to per-IP
        // and global brute-force lockout via auth_middleware.
        let public_routes = Router::new()
            .route("/health", get(health_handler))
            .with_state(state.clone());

        let protected_routes = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/metrics/json", get(metrics_json_handler))
            .route("/metrics/errors", get(metrics_errors_handler))
            .route("/reload", post(reload_handler))
            .route("/shutdown", post(shutdown_handler))
            .route("/config", get(config_handler))
            .route("/backends", get(backends_handler))
            .route("/tls", get(tls_handler))
            .route("/ocsp", get(ocsp_handler))
            .route(
                "/ocsp/refresh",
                post({
                    let cd = Arc::clone(&endpoint_cooldowns);
                    move |s| ocsp_refresh_handler_with_cooldown(s, cd)
                }),
            )
            .route("/acme", get(acme_handler))
            .route(
                "/acme/renew",
                post({
                    let cd = Arc::clone(&endpoint_cooldowns);
                    move |s| acme_renew_handler_with_cooldown(s, cd)
                }),
            )
            .route("/ratelimit", get(ratelimit_handler))
            .route("/health/quic", get(health_quic_handler))
            .route("/health/webtransport", get(health_webtransport_handler))
            .layer(axum::middleware::from_fn_with_state(
                auth_state,
                auth_middleware,
            ))
            .with_state(state);

        let app = public_routes
            .merge(protected_routes)
            .layer(TraceLayer::new_for_http());

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

/// SEC-005 / AUD-10 / F-03 / F-08: Shared state for the admin authentication middleware.
///
/// Tracks per-IP failed attempt counts with a sliding 1-minute window so that
/// brute-force attacks against a weak or leaked token are rate-limited before
/// they can enumerate secrets.
///
/// AUD-10 adds a *global* failed-auth counter so that distributed attacks from
/// many IPs (each making fewer than ADMIN_AUTH_MAX_FAILURES attempts) are also
/// caught.  When the global counter reaches ADMIN_GLOBAL_MAX_FAILURES a global
/// cooldown is activated.
///
/// F-08: The cooldown doubles on each successive trigger (exponential back-off)
/// from 5 minutes up to 30 minutes.
#[derive(Clone)]
struct AdminAuthState {
    allowed_ips: Vec<String>,
    auth_token: Option<String>,
    /// Map from client IP string → (failure_count, window_start).
    /// Access is lock-free via DashMap.
    failed_attempts: Arc<DashMap<String, (u32, Instant)>>,
    /// AUD-10: Total failed authentication attempts across all IPs since the
    /// last successful auth or cooldown reset.
    global_failure_count: Arc<AtomicU32>,
    /// AUD-10: Optional point in time until which the global cooldown is active.
    global_cooldown_until: Arc<RwLock<Option<Instant>>>,
    /// F-08: Consecutive global cooldown trigger count for exponential back-off.
    /// Resets to 0 on a successful authentication.
    global_cooldown_count: Arc<AtomicU32>,
}

/// F-14: Per-endpoint cooldown state for operations that trigger external network
/// calls (ACME certificate renewal, OCSP refresh).  Prevents accidental quota
/// exhaustion through repeated admin API calls.
#[derive(Clone)]
struct EndpointCooldowns {
    /// Last time /acme/renew was triggered.
    acme_renew_last: Arc<RwLock<Option<Instant>>>,
    /// Last time /ocsp/refresh was triggered.
    ocsp_refresh_last: Arc<RwLock<Option<Instant>>>,
}

/// Maximum failed authentication attempts per IP per minute before lockout.
const ADMIN_AUTH_MAX_FAILURES: u32 = 10;
/// Length of the sliding rate-limit window.
const ADMIN_AUTH_WINDOW: Duration = Duration::from_secs(60);
/// AUD-10: Total failures across all IPs before a global cooldown is triggered.
const ADMIN_GLOBAL_MAX_FAILURES: u32 = 50;
/// AUD-10 / F-08: Base duration of the global cooldown once ADMIN_GLOBAL_MAX_FAILURES
/// is reached.  Set to 5 minutes (up from 30 s) to meaningfully deter distributed
/// brute-force attacks where each source IP stays below the per-IP threshold.
/// The cooldown doubles on each successive trigger (exponential back-off) up to
/// ADMIN_GLOBAL_COOLDOWN_MAX.
const ADMIN_GLOBAL_COOLDOWN_BASE: Duration = Duration::from_secs(300);
/// F-08: Maximum cooldown duration after repeated global threshold breaches.
const ADMIN_GLOBAL_COOLDOWN_MAX: Duration = Duration::from_secs(1800); // 30 minutes
/// F-14: Minimum interval between successive /acme/renew triggers.
/// Let's Encrypt rate-limits to 50 certs/domain/week; accidental hammering
/// could exhaust that quota.  One call per hour is a safe operational limit.
const ACME_RENEW_COOLDOWN: Duration = Duration::from_secs(3600);
/// F-14: Minimum interval between successive /ocsp/refresh triggers.
const OCSP_REFRESH_COOLDOWN: Duration = Duration::from_secs(300);

/// Authentication middleware for admin API
async fn auth_middleware(
    State(auth): State<Arc<AdminAuthState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let client_ip = remote_addr.ip().to_string();

    // Check IP whitelist
    if !auth.allowed_ips.is_empty() && !auth.allowed_ips.contains(&client_ip) {
        warn!("Admin API access denied for IP: {}", client_ip);
        return StatusCode::FORBIDDEN.into_response();
    }

    // Check auth token if configured
    if let Some(ref expected_token) = auth.auth_token {
        // AUD-10: Check global cooldown first — this catches distributed brute-force
        // attacks where each source IP stays below the per-IP threshold.
        {
            let cooldown_until = auth.global_cooldown_until.read();
            if let Some(until) = *cooldown_until {
                if Instant::now() < until {
                    warn!(
                        "Admin API: global auth cooldown active — rejecting request from {}",
                        client_ip
                    );
                    return StatusCode::TOO_MANY_REQUESTS.into_response();
                }
            }
        }

        // SEC-005: Check and enforce per-IP rate limit before doing any token work.
        {
            let now = Instant::now();
            let mut entry = auth
                .failed_attempts
                .entry(client_ip.clone())
                .or_insert((0, now));
            let (ref mut count, ref mut window_start) = *entry;

            // Reset the window if it has expired.
            if now.duration_since(*window_start) >= ADMIN_AUTH_WINDOW {
                *count = 0;
                *window_start = now;
            }

            if *count >= ADMIN_AUTH_MAX_FAILURES {
                warn!(
                    "Admin API: rate limit exceeded for {} ({} failures in 60s) — blocking",
                    client_ip, count
                );
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            }
        }

        let provided_token = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.strip_prefix("Bearer ").unwrap_or(v));

        // H-3: Constant-time comparison to prevent timing side-channel attacks
        let provided_bytes = provided_token.unwrap_or("").as_bytes();
        let authorized: bool = provided_bytes.ct_eq(expected_token.as_bytes()).into();

        if !authorized {
            // Record the failure against this IP.
            {
                let now = Instant::now();
                let mut entry = auth
                    .failed_attempts
                    .entry(client_ip.clone())
                    .or_insert((0, now));
                let (ref mut count, ref mut window_start) = *entry;
                if now.duration_since(*window_start) >= ADMIN_AUTH_WINDOW {
                    *count = 0;
                    *window_start = now;
                }
                *count += 1;
                warn!(
                    "Admin API unauthorized access attempt from {} ({}/{})",
                    client_ip, *count, ADMIN_AUTH_MAX_FAILURES
                );
            }

            // AUD-10 / F-08: Increment global failure counter and trigger cooldown
            // if threshold hit.  The cooldown duration doubles on each successive
            // trigger (exponential back-off) up to ADMIN_GLOBAL_COOLDOWN_MAX.
            let global = auth
                .global_failure_count
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            if global >= ADMIN_GLOBAL_MAX_FAILURES {
                let trigger_count = auth
                    .global_cooldown_count
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                // Exponential back-off: base * 2^(trigger_count-1), capped at max
                let backoff_secs = ADMIN_GLOBAL_COOLDOWN_BASE.as_secs()
                    * (1u64 << trigger_count.saturating_sub(1).min(5));
                let cooldown_duration =
                    Duration::from_secs(backoff_secs.min(ADMIN_GLOBAL_COOLDOWN_MAX.as_secs()));
                let mut cooldown_until = auth.global_cooldown_until.write();
                *cooldown_until = Some(Instant::now() + cooldown_duration);
                auth.global_failure_count.store(0, Ordering::Relaxed);
                warn!(
                    "Admin API: global failure threshold reached ({} total, trigger #{}) — \
                     activating {}s global cooldown (F-08 exponential back-off)",
                    global,
                    trigger_count,
                    cooldown_duration.as_secs()
                );
            }

            return StatusCode::UNAUTHORIZED.into_response();
        }

        // Successful auth: clear per-IP failure count and reset global counter.
        // F-08: Also reset the exponential back-off counter so a successful
        // authentication returns the system to the base cooldown duration.
        auth.failed_attempts.remove(&client_ip);
        auth.global_failure_count.store(0, Ordering::Relaxed);
        auth.global_cooldown_count.store(0, Ordering::Relaxed);
    }

    next.run(request).await.into_response()
}

/// Health check response (public endpoint — no topology disclosure)
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
    connections: u64,
    requests: u64,
    /// SR-01: Only name + healthy — address/type are omitted to prevent
    /// leaking internal backend topology to unauthenticated callers.
    backends: Vec<PublicBackendHealth>,
}

/// SR-01: Minimal backend status for the public /health endpoint.
///
/// Deliberately excludes `address` and `backend_type` so that internal service
/// topology (e.g. "127.0.0.1:3003") cannot be discovered by unauthenticated
/// clients or via SSRF pivots.  Full backend detail is available on the
/// authenticated /backends endpoint only.
#[derive(Serialize)]
struct PublicBackendHealth {
    name: String,
    healthy: bool,
}

/// Backend health status — full detail, used by the authenticated /backends endpoint only
#[derive(Serialize)]
struct BackendHealth {
    name: String,
    healthy: bool,
    #[serde(rename = "type")]
    backend_type: String,
    address: String,
}

/// Health check endpoint (public — no auth required)
async fn health_handler(State(state): State<Arc<AdminState>>) -> Json<HealthResponse> {
    let config = state.config_manager.get();
    let uptime = state.start_time.elapsed().as_secs();

    // SR-01: Collect only name + healthy status; omit addresses and types.
    let mut backends = Vec::new();
    for (name, backend) in &config.backends {
        let healthy = state.backend_pool.check_health(backend).await;
        backends.push(PublicBackendHealth {
            name: name.clone(),
            healthy,
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

/// Query parameters for the errors endpoint
#[derive(Deserialize)]
struct ErrorsQuery {
    /// Filter by error type: "client" (4xx) or "server" (5xx). Omit for all.
    #[serde(rename = "type")]
    error_type: Option<String>,
}

/// Error details endpoint — per-endpoint error counts and recent failures
async fn metrics_errors_handler(
    State(state): State<Arc<AdminState>>,
    axum::extract::Query(query): axum::extract::Query<ErrorsQuery>,
) -> Json<ErrorsSnapshot> {
    let filter = query.error_type.as_deref();
    let endpoint_errors = state
        .metrics
        .requests
        .endpoint_error_counts_filtered(filter);
    let all_failures = state.metrics.requests.recent_failures();
    let recent_failures = match filter {
        Some("client") => all_failures
            .into_iter()
            .filter(|f| f.status >= 400 && f.status < 500)
            .collect(),
        Some("server") => all_failures
            .into_iter()
            .filter(|f| f.status >= 500)
            .collect(),
        _ => all_failures,
    };
    let total_failed: u64 = endpoint_errors.iter().map(|e| e.count).sum();
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
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AdminState>>,
    Json(request): Json<Option<ReloadRequest>>,
) -> Json<ReloadResponse> {
    let tls_only = request.map(|r| r.tls_only).unwrap_or(false);
    let action = if tls_only {
        "tls_reload"
    } else {
        "config_reload"
    };

    if tls_only {
        // Reload TLS certificates only
        match state.tls_provider.reload_certificates() {
            Ok(()) => {
                info!("TLS certificates reloaded via admin API");
                // Notify other components
                state.config_manager.notify_tls_reload().await;
                if let Some(ref logger) = state.audit_logger {
                    logger.log(AuditEvent::AdminAction {
                        ip: remote_addr.ip().to_string(),
                        action: action.to_string(),
                        success: true,
                        detail: None,
                    });
                }
                Json(ReloadResponse {
                    success: true,
                    message: "TLS certificates reloaded successfully".to_string(),
                })
            }
            Err(e) => {
                error!("TLS reload failed: {}", e);
                if let Some(ref logger) = state.audit_logger {
                    logger.log(AuditEvent::AdminAction {
                        ip: remote_addr.ip().to_string(),
                        action: action.to_string(),
                        success: false,
                        detail: Some(e.to_string()),
                    });
                }
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
                if let Some(ref logger) = state.audit_logger {
                    logger.log(AuditEvent::AdminAction {
                        ip: remote_addr.ip().to_string(),
                        action: action.to_string(),
                        success: true,
                        detail: None,
                    });
                }
                Json(ReloadResponse {
                    success: true,
                    message: "Configuration reloaded successfully".to_string(),
                })
            }
            Err(e) => {
                error!("Config reload failed: {}", e);
                if let Some(ref logger) = state.audit_logger {
                    logger.log(AuditEvent::AdminAction {
                        ip: remote_addr.ip().to_string(),
                        action: action.to_string(),
                        success: false,
                        detail: Some(e.to_string()),
                    });
                }
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
async fn shutdown_handler(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<AdminState>>,
) -> Json<ShutdownResponse> {
    info!("Shutdown requested via admin API from {}", remote_addr);

    if let Some(ref logger) = state.audit_logger {
        logger.log(AuditEvent::AdminAction {
            ip: remote_addr.ip().to_string(),
            action: "shutdown".to_string(),
            success: true,
            detail: None,
        });
    }

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

/// OCSP refresh endpoint (force refresh) — F-14: rate-limited to OCSP_REFRESH_COOLDOWN.
async fn ocsp_refresh_handler_with_cooldown(
    State(state): State<Arc<AdminState>>,
    cooldowns: Arc<EndpointCooldowns>,
) -> Result<Json<OcspRefreshResponse>, (StatusCode, String)> {
    // F-14: Enforce cooldown to prevent hammering the OCSP responder.
    {
        let last = cooldowns.ocsp_refresh_last.read();
        if let Some(t) = *last {
            let elapsed = t.elapsed();
            if elapsed < OCSP_REFRESH_COOLDOWN {
                let retry_after = OCSP_REFRESH_COOLDOWN.as_secs() - elapsed.as_secs();
                warn!(
                    "Admin API: /ocsp/refresh rate-limited ({}s cooldown remaining)",
                    retry_after
                );
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    format!(
                        "Retry after {}s (F-14: OCSP refresh cooldown prevents CA flooding)",
                        retry_after
                    ),
                ));
            }
        }
    }
    // Record this invocation before triggering the refresh
    *cooldowns.ocsp_refresh_last.write() = Some(Instant::now());

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
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "OCSP service not configured".to_string(),
        )),
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

/// ACME certificate renewal endpoint — F-14: rate-limited to ACME_RENEW_COOLDOWN.
///
/// Let's Encrypt enforces a limit of 50 issued certificates per registered domain
/// per week.  A 1-hour cooldown between /acme/renew calls prevents accidental
/// exhaustion of that quota through scripted or repeated admin API invocations.
async fn acme_renew_handler_with_cooldown(
    State(state): State<Arc<AdminState>>,
    cooldowns: Arc<EndpointCooldowns>,
) -> Json<AcmeRenewResponse> {
    // F-14: Enforce per-call cooldown to protect Let's Encrypt rate limits.
    {
        let last = cooldowns.acme_renew_last.read();
        if let Some(t) = *last {
            let elapsed = t.elapsed();
            if elapsed < ACME_RENEW_COOLDOWN {
                let retry_after = ACME_RENEW_COOLDOWN.as_secs() - elapsed.as_secs();
                warn!(
                    "Admin API: /acme/renew rate-limited ({}s cooldown remaining, F-14)",
                    retry_after
                );
                return Json(AcmeRenewResponse {
                    success: false,
                    message: format!(
                        "Rate limited: retry after {}s. \
                         Prevents Let's Encrypt quota exhaustion (50 certs/domain/week).",
                        retry_after
                    ),
                    status: None,
                });
            }
        }
    }
    // Record this invocation before triggering the renewal
    *cooldowns.acme_renew_last.write() = Some(Instant::now());

    match &state.acme_service {
        Some(service) => {
            let renewal_result = {
                let svc = service.read();
                svc.get_status()
            };
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

/// QUIC health response
#[derive(Serialize)]
struct QuicHealthResponse {
    status: String,
    port: u16,
    migration_enabled: bool,
    connections: u64,
}

/// WebTransport health response
#[derive(Serialize)]
struct WebTransportHealthResponse {
    status: String,
    active_connections: u64,
    allowed_origins: Vec<String>,
    max_sessions_per_origin: u32,
    max_streams_per_session: u32,
}

/// QUIC protocol health endpoint (protected — requires auth)
async fn health_quic_handler(State(state): State<Arc<AdminState>>) -> Json<QuicHealthResponse> {
    let config = state.config_manager.get();
    let connections = *state.connection_count.read();

    Json(QuicHealthResponse {
        status: "ok".to_string(),
        port: config.server.udp_port,
        migration_enabled: config.server.enable_quic_migration,
        connections,
    })
}

/// WebTransport health endpoint (protected — requires auth)
async fn health_webtransport_handler(
    State(state): State<Arc<AdminState>>,
) -> Json<WebTransportHealthResponse> {
    let config = state.config_manager.get();
    let connections = *state.connection_count.read();

    Json(WebTransportHealthResponse {
        status: "ok".to_string(),
        active_connections: connections,
        allowed_origins: config.server.webtransport_allowed_origins.clone(),
        max_sessions_per_origin: config.server.webtransport_max_sessions_per_origin,
        max_streams_per_session: config.server.webtransport_max_streams_per_session,
    })
}
