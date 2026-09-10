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

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes;

use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Host, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode, Uri},
    middleware,
    response::{IntoResponse, Redirect, Response},
    Router,
};
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use hyper::upgrade::OnUpgrade;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tower::ServiceExt;
use tracing::{debug, error, info, trace, warn};

use crate::tls_acceptor::FingerprintingTlsAcceptor;

#[cfg(feature = "pqc")]
use crate::pqc_tls::{openssl_pqc, PqcTlsProvider};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::cache::cache_middleware;
use crate::compression::{compression_middleware, CompressionState};
use crate::config::{BackendConfig, ProxyConfig, ShadowConfig, TlsMode};
use crate::fingerprint::{
    fingerprint_middleware, FingerprintExtractor, FingerprintMiddlewareState,
};
use crate::http3_features::{http3_features_middleware, Http3FeaturesState};
use crate::load_balancer::{
    extract_cookie_by_name, extract_session_cookie, LoadBalancer, SelectionContext,
};
use crate::metrics::{ConnectionProtocol, MetricsRegistry};
use crate::rate_limiter::{build_context_from_request, AdvancedRateLimiter, RateLimitResult};
use crate::security::{security_middleware, SecurityState};

mod backend_tls;
mod cors;
mod layers;
mod passthrough;
mod proxy_protocol;
mod speedtest_tcp;
mod tls_config;
mod websocket;

pub use backend_tls::create_backend_tls_connector;
pub use passthrough::run_tls_passthrough_server;

use cors::{add_cors_headers, handle_cors_preflight, is_mobile_user_agent};
use layers::{
    advanced_rate_limit_middleware, alt_svc_middleware, security_headers_middleware,
    trace_context_middleware,
};
use speedtest_tcp::{tcp_upload_cors_preflight, tcp_upload_measure_handler};
use tls_config::{
    build_rustls_server_config, build_rustls_server_config_http11_only,
    build_rustls_server_config_http11_only_with_resolver, build_rustls_server_config_with_resolver,
};
use websocket::handle_websocket_tunnel;

/// HTTP listener state
#[derive(Clone)]
pub struct HttpListenerState {
    pub config: Arc<ProxyConfig>,
    pub port: u16,
    /// `alt-svc` and `x-webtransport-port`, built once at startup.
    ///
    /// Both are a function of `port` and `config.server.additional_ports`, so
    /// they cannot change while the listener is alive — but they were being
    /// rebuilt on every single response: a `Vec`, one `format!` per advertised
    /// port, a `join`, and then a `HeaderValue::from_str` to parse the result
    /// back, plus a second `to_string` + parse for the port header. Cloning a
    /// `HeaderValue` is a refcount bump on its backing `Bytes`, so holding the
    /// finished values costs nothing per request.
    ///
    /// Note this is deliberately NOT `SecurityState::alt_svc_header`, which is
    /// built from `config.server.udp_port`; this one advertises `port`, the
    /// port this listener actually terminates.
    pub alt_svc_value: Option<HeaderValue>,
    pub webtransport_port_value: HeaderValue,
    // Behind `Arc` for the same reason as `security`: axum clones the state per
    // request, and hyper's `Client::clone` copies its config, its HTTP/1 and
    // HTTP/2 builders and its connector — real struct copies, not refcounts.
    // Three of them per request came to 7.4 % of CPU in the profile.
    pub http_client: Arc<Client<HttpConnector, Body>>,
    pub https_client: Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>>,
    /// Dedicated client with connection pooling disabled (`pool_max_idle_per_host(0)`)
    /// — used instead of `http_client` when `BackendConfig::disable_pooling` is set.
    /// Every request opens a fresh connection rather than reusing a pooled one;
    /// for backends under sustained concurrent load that occasionally hang or
    /// reset on a *reused* pooled connection (root cause not yet isolated further
    /// upstream — see pqcrypta-api's connection handling), this trades a bit of
    /// per-request handshake overhead for reliability. Cheap on loopback backends.
    pub direct_client: Arc<Client<HttpConnector, Body>>,
    /// Behind an `Arc` because axum clones the whole `State<T>` for every
    /// request, and `SecurityState` holds 19 `Arc` fields — so cloning it by
    /// value cost 19 atomic increments and 19 decrements per request, on cache
    /// lines shared by every worker thread. A profile under load attributed
    /// **32 % of all CPU** to exactly that: 16.7 % in `drop_glue::<SecurityState>`
    /// and 15.7 % in its `clone`. One `Arc` makes it one increment and one
    /// decrement. Every other field here was already `Arc` for this reason;
    /// this one was the exception.
    pub security: Arc<SecurityState>,
    /// Fingerprint extractor for TLS client identification
    pub fingerprint: Arc<FingerprintExtractor>,
    pub load_balancer: Arc<LoadBalancer>,
    /// Metrics registry for request tracking
    pub metrics: Arc<MetricsRegistry>,
    /// Nonce store for per-route HMAC replay protection (shared across all routes).
    /// Rate limiter for per-route secondary rate limit checks.
    pub rate_limiter: Arc<AdvancedRateLimiter>,
    /// Client conformance suite, when enabled. Serves its own vhost's
    /// catalogue, sessions, reports and badge; the tests themselves live on
    /// their own UDP ports.
    pub conformance: Option<Arc<crate::conformance::Conformance>>,
}

// ============================================================================
// Request dispatch
// ============================================================================
// Every request used to go through an `axum::Router`. A Router matches the path
// and then hands the caller a *clone* of the matched endpoint, and that clone is
// not a refcount bump: `Route` wraps a `BoxCloneService`, so cloning it heap-
// allocates, and the `MethodRouter` behind a named route is boxed again. An
// HTTP/2 profile put 4.21% in `Route::clone`, 1.07% in `BoxedIntoRoute::clone`
// and 1.03% in `MethodRouter` drop glue — 6.3% of CPU rebuilding a routing table
// that has exactly one named entry in it.
//
// `ProxyDispatch` is that table written out longhand: one path comparison, then
// the proxy handler. Cloning it is an `Arc` bump. The middleware stack around it
// is unchanged, and so is what the client sees — including the 405 that axum's
// `MethodRouter` returned for a method the named route does not register.

/// The one path that is not proxied.
const TCP_UPLOAD_PATH: &str = "/speedtest/tcp-upload-stream";

/// The router replacement: the speedtest upload endpoint, or the proxy.
#[derive(Clone)]
struct ProxyDispatch {
    state: Arc<HttpListenerState>,
}

impl tower::Service<Request<Body>> for ProxyDispatch {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        Box::pin(async move { Ok(dispatch(state, req).await) })
    }
}

/// Route one request. `Host` and `ConnectInfo` were extractor arguments while
/// this went through the Router; they are run by hand here so `proxy_handler`
/// keeps its signature.
/// An `axum_server` acceptor that applies `TCP_NODELAY` when the configuration
/// asks for it.
///
/// `axum_server` ships `DefaultAcceptor` (never sets it) and `NoDelayAcceptor`
/// (always sets it) as two distinct types, which would make the choice a branch
/// over two different `Server` types at every call site. One type carrying the
/// flag keeps that to a value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConfigurableNoDelay(pub(crate) bool);

impl<S> Accept<tokio::net::TcpStream, S> for ConfigurableNoDelay {
    type Stream = tokio::net::TcpStream;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, Self::Service)>>;

    fn accept(&self, stream: Self::Stream, service: S) -> Self::Future {
        if self.0 {
            if let Err(e) = stream.set_nodelay(true) {
                warn!("Failed to set TCP_NODELAY on an accepted socket: {}", e);
            }
        }
        std::future::ready(Ok((stream, service)))
    }
}

async fn dispatch(state: Arc<HttpListenerState>, req: Request<Body>) -> Response {
    if req.uri().path() == TCP_UPLOAD_PATH {
        return match *req.method() {
            Method::POST => tcp_upload_measure_handler(req.into_body()).await,
            Method::OPTIONS => tcp_upload_cors_preflight().await,
            _ => (
                StatusCode::METHOD_NOT_ALLOWED,
                [(header::ALLOW, "POST,OPTIONS")],
            )
                .into_response(),
        };
    }

    let (mut parts, body) = req.into_parts();
    let host = match Host::from_request_parts(&mut parts, &()).await {
        Ok(host) => host,
        Err(rejection) => return rejection.into_response(),
    };
    let connect_info = match ConnectInfo::<SocketAddr>::from_request_parts(&mut parts, &()).await {
        Ok(info) => info,
        Err(rejection) => return rejection.into_response(),
    };

    proxy_handler(
        State(state),
        host,
        connect_info,
        Request::from_parts(parts, body),
    )
    .await
}

/// Static dispatch for the optional fingerprint layer.
///
/// `tower::util::Either` maps both branches onto `BoxError`, which would break
/// the `Error = Infallible` bound the surrounding axum layers require, and
/// boxing a branch would put back the per-request allocation this module exists
/// to remove. Both branches are `from_fn` services, and `FromFn::Future` is the
/// same non-generic type either way, so the enum needs no future of its own.
#[derive(Clone)]
enum MaybeFingerprint<A, B> {
    With(A),
    Without(B),
}

impl<A, B> tower::Service<Request<Body>> for MaybeFingerprint<A, B>
where
    A: tower::Service<Request<Body>, Response = Response, Error = Infallible>,
    B: tower::Service<Request<Body>, Response = Response, Error = Infallible, Future = A::Future>,
{
    type Response = Response;
    type Error = Infallible;
    type Future = A::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Infallible>> {
        match self {
            Self::With(svc) => svc.poll_ready(cx),
            Self::Without(svc) => svc.poll_ready(cx),
        }
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        match self {
            Self::With(svc) => svc.call(req),
            Self::Without(svc) => svc.call(req),
        }
    }
}

/// Adapts the server's body type to `axum::body::Body`.
///
/// `Router` did this conversion at its own boundary. The `from_fn` middleware
/// stack only speaks `Request<Body>`, so hyper's `Incoming` has to be converted
/// before it reaches the outermost layer.
#[derive(Clone)]
struct BodyShim<S>(S);

impl<S, B> tower::Service<Request<B>> for BodyShim<S>
where
    S: tower::Service<Request<Body>>,
    B: hyper::body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (parts, body) = req.into_parts();
        self.0.call(Request::from_parts(parts, Body::new(body)))
    }
}

/// Apply one layer, pinning the extractor-tuple type parameter that a bare
/// `Layer::layer` call leaves ambiguous — `Router::layer` carries the same
/// `L::Service: Service<_>` bound for the same reason.
fn wrap<L, I>(layer: L, inner: I) -> L::Service
where
    L: tower::Layer<I>,
    L::Service: tower::Service<Request<Body>, Response = Response, Error = Infallible>,
{
    layer.layer(inner)
}

/// Build the request-handling stack: the same middleware, in the same
/// outside-to-inside order the `Router` applied it, around `ProxyDispatch`.
///
/// Order (outside to inside): trace context -> advanced rate limit ->
/// fingerprint -> security -> http3 features -> compression -> Alt-Svc ->
/// security headers -> cache -> dispatch.
#[allow(clippy::too_many_arguments)]
fn build_proxy_service(
    state: Arc<HttpListenerState>,
    response_cache: Arc<crate::cache::ResponseCache>,
    compression_state: CompressionState,
    http3_features_state: Http3FeaturesState,
    security_state: Arc<SecurityState>,
    fingerprint_state: Option<FingerprintMiddlewareState>,
    rl_state: (Arc<AdvancedRateLimiter>, Arc<MetricsRegistry>),
) -> impl tower::Service<
    Request<Body>,
    Response = Response,
    Error = Infallible,
    Future = axum::middleware::future::FromFnResponseFuture,
> + Clone
       + Send
       + 'static {
    // MEASUREMENT ONLY: collapse the chain so the cost of the layering itself — a
    // boxed future and a clone per layer per request — can be measured instead of
    // inferred from a profile's share. NOT deployable: it removes the security
    // evaluator, both rate limiters, the response cache, and every response header
    // the chain adds. Never built by scripts/deploy.sh.
    #[cfg(feature = "bench-no-middleware")]
    let svc = {
        let _ = (
            &response_cache,
            &compression_state,
            &http3_features_state,
            &security_state,
            &fingerprint_state,
            &rl_state,
        );
        // The `With` variant is never constructed here, so name a type for it.
        MaybeFingerprint::<ProxyDispatch, ProxyDispatch>::Without(ProxyDispatch {
            state: state.clone(),
        })
    };

    #[cfg(not(feature = "bench-no-middleware"))]
    let svc = {
        // Cache is innermost: it stores pre-compression bodies, so every outer layer
        // applies to hits and misses alike.
        let svc = wrap(
            middleware::from_fn_with_state(response_cache, cache_middleware),
            ProxyDispatch {
                state: state.clone(),
            },
        );
        let svc = wrap(
            middleware::from_fn_with_state(state.clone(), security_headers_middleware),
            svc,
        );
        let svc = wrap(
            middleware::from_fn_with_state(state, alt_svc_middleware),
            svc,
        );
        let svc = wrap(
            middleware::from_fn_with_state(compression_state, compression_middleware),
            svc,
        );
        let svc = wrap(
            middleware::from_fn_with_state(http3_features_state, http3_features_middleware),
            svc,
        );
        // Arc: axum clones the layer's state per request, and this one holds 19 Arcs
        // of its own.
        let svc = wrap(
            middleware::from_fn_with_state(security_state, security_middleware),
            svc,
        );

        let svc = match fingerprint_state {
            Some(fp_state) => MaybeFingerprint::With(wrap(
                middleware::from_fn_with_state(fp_state, fingerprint_middleware),
                svc,
            )),
            None => MaybeFingerprint::Without(svc),
        };

        let svc = wrap(
            middleware::from_fn_with_state(rl_state, advanced_rate_limit_middleware),
            svc,
        );
        svc
    };

    // Trace context is the absolute outermost layer so the trace ID is available
    // to every inner middleware and to the access logger.
    wrap(middleware::from_fn(trace_context_middleware), svc)
}

/// Create and run the HTTP listener with TLS termination
#[allow(clippy::similar_names)]
pub async fn run_http_listener(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    metrics: Arc<MetricsRegistry>,
    load_balancer: Arc<LoadBalancer>,
    // The process-wide security state, constructed once in `main`. This used to be
    // built here, which meant every listener had its own blocklist, its own
    // suspicious-pattern counters and its own rate buckets — a source blocked on one
    // port began clean on the next — and the startup attestation could only ever probe
    // a further instance that served nobody. One instance, shared.
    security_state: SecurityState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read once here: `config` is moved into builders further down in
    // several of these functions.
    let nodelay = config.server.tcp_nodelay;
    let port = addr.port();

    info!(
        "🌐 Starting HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    // Using configurable connection pool settings
    let pool_config = &config.connection_pool;
    // TCP_NODELAY on backend connections. hyper's default connector leaves Nagle
    // enabled, which is the wrong trade for a reverse proxy: a proxied request is
    // a small write followed by a wait for the reply, so Nagle holds the write
    // looking for more data that is never coming while the backend's delayed ACK
    // holds the other side. Measured against a local backend, mean request
    // latency was 917us with it left on.
    let mut backend_connector = HttpConnector::new();
    backend_connector.set_nodelay(true);
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(backend_connector);

    // Client with pooling disabled, for backends configured with disable_pooling = true.
    // pool_max_idle_per_host(0) means a connection is never returned to the pool
    // after a response completes, so every request pays for a fresh connection.
    let mut direct_connector = HttpConnector::new();
    direct_connector.set_nodelay(true);
    let direct_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(direct_connector);

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

    // Security state is constructed once in main and shared across every listener and
    // the startup attestation; see the parameter's documentation.

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter.clone(), metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        conformance: crate::conformance::shared(&config.conformance),
        config: config.clone(),
        port,
        alt_svc_value: HeaderValue::from_str(&layers::build_alt_svc_header_with_override(
            port,
            &config.server.additional_ports,
            config.server.alt_svc_ports.as_deref(),
        ))
        .ok(),
        webtransport_port_value: HeaderValue::from_str(&port.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("443")),
        http_client: Arc::new(http_client),
        https_client: Arc::new(https_client),
        direct_client: Arc::new(direct_client),
        security: Arc::new(security_state.clone()),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
        rate_limiter,
    };

    // axum clones `State<T>` for the handler and again for every middleware
    // layer that takes it, so the struct was being copied field-by-field several
    // times per request. One `Arc` makes each of those a refcount bump; field
    // access is unchanged through `Deref`.
    let state = Arc::new(state);

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize response cache (innermost layer — security headers, alt-svc, and
    // compression all run on top of it for both cache hits and cache misses)
    let response_cache = crate::cache::shared(&config.cache);
    if config.cache.enabled {
        info!(
            "💾 Response cache enabled (max {}MiB, default TTL {}s)",
            config.cache.max_size_mb, config.cache.default_ttl_secs
        );
    }

    // Initialize fingerprint middleware state (if enabled)
    let fingerprint_state = if config.fingerprint.enabled {
        info!("🔍 TLS fingerprinting middleware enabled");
        Some(FingerprintMiddlewareState::new(
            fingerprint_extractor,
            security_state.clone(),
            Arc::new(config.fingerprint.clone()),
        ))
    } else {
        None
    };

    let app = build_proxy_service(
        state.clone(),
        response_cache,
        compression_state,
        http3_features_state,
        Arc::new(security_state),
        fingerprint_state,
        rl_state,
    );

    // Build TLS config using the per-domain SNI resolver (no single cert required)
    let rustls_server_config = build_rustls_server_config(cert_path, key_path).map_err(|e| {
        error!("❌ TLS configuration error: {}", e);
        e
    })?;
    let tls_config = RustlsConfig::from_config(Arc::new(rustls_server_config));

    info!("✅ TLS configured for HTTP listener (SNI per-domain resolver)");
    info!("🔒 HTTPS reverse proxy ready on port {} (TCP)", port);
    // SEC-A04: Hardcoded backend addresses removed from logs to prevent topology disclosure.

    // Run HTTPS server
    // Spelled out rather than `bind_rustls`, which composes the same acceptor
    // over `DefaultAcceptor` and so leaves Nagle on every accepted socket.
    axum_server::bind(addr)
        .acceptor(RustlsAcceptor::new(tls_config).acceptor(ConfigurableNoDelay(nodelay)))
        // Spelled out: `ServiceExt` is generic over the request type, and
        // hyper hands `axum_server` an `Incoming` body that only `BodyShim`
        // converts.
        .serve(
            axum::ServiceExt::<Request<hyper::body::Incoming>>::into_make_service_with_connect_info::<
                SocketAddr,
            >(BodyShim(app)),
        )
        .await?;

    Ok(())
}

/// Create and run the HTTP listener with PQC-enabled OpenSSL TLS
/// Uses OpenSSL 3.5+ with ML-KEM hybrid key exchange for quantum-resistant connections
#[cfg(feature = "pqc")]
#[allow(clippy::similar_names, clippy::too_many_arguments)]
pub async fn run_http_listener_pqc(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    pqc_provider: Arc<PqcTlsProvider>,
    metrics: Arc<MetricsRegistry>,
    load_balancer: Arc<LoadBalancer>,
    sni_map: openssl_pqc::PqcSniMap,
    // Shared with every other listener. Each of these built its own
    // `SecurityState` before, so a blocked IP, a rate-limit counter, an
    // observed fingerprint or a DB-synced blocklist entry existed only on
    // whichever listener happened to see it.
    security_state: SecurityState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read once here: `config` is moved into builders further down in
    // several of these functions.
    let nodelay = config.server.tcp_nodelay;
    let port = addr.port();

    info!(
        "🔐 Starting PQC-enabled HTTP/1.1 & HTTP/2 reverse proxy on {} (TCP)",
        addr
    );
    info!("📢 Will advertise Alt-Svc: h3=\":{}\"; ma=86400", port);

    // Create HTTP client for plain backend connections (terminate mode)
    // Using configurable connection pool settings
    let pool_config = &config.connection_pool;
    // TCP_NODELAY on backend connections. hyper's default connector leaves Nagle
    // enabled, which is the wrong trade for a reverse proxy: a proxied request is
    // a small write followed by a wait for the reply, so Nagle holds the write
    // looking for more data that is never coming while the backend's delayed ACK
    // holds the other side. Measured against a local backend, mean request
    // latency was 917us with it left on.
    let mut backend_connector = HttpConnector::new();
    backend_connector.set_nodelay(true);
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(backend_connector);

    // Client with pooling disabled, for backends configured with disable_pooling = true.
    // pool_max_idle_per_host(0) means a connection is never returned to the pool
    // after a response completes, so every request pays for a fresh connection.
    let mut direct_connector = HttpConnector::new();
    direct_connector.set_nodelay(true);
    let direct_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(direct_connector);

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

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter.clone(), metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        conformance: crate::conformance::shared(&config.conformance),
        config: config.clone(),
        port,
        alt_svc_value: HeaderValue::from_str(&layers::build_alt_svc_header_with_override(
            port,
            &config.server.additional_ports,
            config.server.alt_svc_ports.as_deref(),
        ))
        .ok(),
        webtransport_port_value: HeaderValue::from_str(&port.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("443")),
        http_client: Arc::new(http_client),
        https_client: Arc::new(https_client),
        direct_client: Arc::new(direct_client),
        security: Arc::new(security_state.clone()),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
        rate_limiter,
    };

    // axum clones `State<T>` for the handler and again for every middleware
    // layer that takes it, so the struct was being copied field-by-field several
    // times per request. One `Arc` makes each of those a refcount bump; field
    // access is unchanged through `Deref`.
    let state = Arc::new(state);

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state (Early Hints, Priority, Coalescing)
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize response cache
    let response_cache = crate::cache::shared(&config.cache);
    if config.cache.enabled {
        info!(
            "💾 Response cache enabled (max {}MiB, default TTL {}s)",
            config.cache.max_size_mb, config.cache.default_ttl_secs
        );
    }

    // Initialize fingerprint middleware state (if enabled)
    let fingerprint_state = if config.fingerprint.enabled {
        info!("🔍 TLS fingerprinting middleware enabled (PQC mode)");
        Some(FingerprintMiddlewareState::new(
            fingerprint_extractor,
            security_state.clone(),
            Arc::new(config.fingerprint.clone()),
        ))
    } else {
        None
    };

    let app = build_proxy_service(
        state.clone(),
        response_cache,
        compression_state,
        http3_features_state,
        Arc::new(security_state),
        fingerprint_state,
        rl_state,
    );

    // =========================================================================
    // OpenSSL 3.5+ PQC TLS Backend
    // =========================================================================
    // Uses native ML-KEM support with multiple hybrid modes:
    // - X25519MLKEM768 (IETF standard, recommended)
    // - SecP256r1MLKEM768 (NIST curve variant)
    // - SecP384r1MLKEM1024 (higher security)
    // - X448MLKEM1024 (maximum security)
    // =========================================================================
    use axum_server::tls_openssl::{OpenSSLAcceptor, OpenSSLConfig};

    // Create OpenSSL SSL acceptor with PQC hybrid key exchange + SNI multi-domain support.
    // `sni_map` is shared with the ACME handler so hot-reload works without restart.
    let cert_path_buf = std::path::Path::new(cert_path);
    let key_path_buf = std::path::Path::new(key_path);

    let ssl_acceptor = openssl_pqc::create_pqc_acceptor_with_sni(
        cert_path_buf,
        key_path_buf,
        &pqc_provider,
        sni_map,
    )
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
    // SEC-A04: Hardcoded backend addresses removed from logs to prevent topology disclosure.

    // Run HTTPS server with OpenSSL 3.5+ (PQC-enabled with native ML-KEM)
    // Spelled out rather than `bind_openssl`, for the reason above.
    axum_server::bind(addr)
        .acceptor(OpenSSLAcceptor::new(openssl_config).acceptor(ConfigurableNoDelay(nodelay)))
        // Spelled out: `ServiceExt` is generic over the request type, and
        // hyper hands `axum_server` an `Incoming` body that only `BodyShim`
        // converts.
        .serve(
            axum::ServiceExt::<Request<hyper::body::Incoming>>::into_make_service_with_connect_info::<
                SocketAddr,
            >(BodyShim(app)),
        )
        .await?;

    Ok(())
}

// ============================================================================
// Custom TLS Accept Loop with Full Fingerprinting
// ============================================================================
// This implementation captures ClientHello before TLS handshake, extracts
// JA3/JA4 fingerprints, and blocks malicious clients before they can waste
// resources on a full handshake. Envoy and HAProxy use the same architecture.

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
// Every argument is a distinct per-listener dependency with no natural
// grouping; bundling them into a struct purely to satisfy the lint would add an
// indirection none of the sibling listeners have.
#[allow(clippy::too_many_arguments)]
pub async fn run_http_listener_with_fingerprint(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<MetricsRegistry>,
    load_balancer: Arc<LoadBalancer>,
    security_state: SecurityState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_http_listener_with_fingerprint_and_resolver(
        addr,
        cert_path,
        key_path,
        config,
        shutdown_rx,
        metrics,
        load_balancer,
        None,
        security_state,
    )
    .await
}

/// Like `run_http_listener_with_fingerprint` but with a shared SNI cert resolver.
///
/// When `shared_resolver` is `Some`, the same `MultiDomainCertResolver` instance
/// used by the ACME subsystem is wired into the TLS config so that newly-issued
/// certificates are served immediately without restarting the listener.
#[allow(clippy::too_many_arguments)]
pub async fn run_http_listener_with_fingerprint_and_resolver(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<MetricsRegistry>,
    load_balancer: Arc<LoadBalancer>,
    shared_resolver: Option<std::sync::Arc<crate::tls::MultiDomainCertResolver>>,
    // Shared with every other listener. Each of these built its own
    // `SecurityState` before, so a blocked IP, a rate-limit counter, an
    // observed fingerprint or a DB-synced blocklist entry existed only on
    // whichever listener happened to see it.
    security_state: SecurityState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read once here: `config` is moved into builders further down in
    // several of these functions.
    let nodelay = config.server.tcp_nodelay;
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
    // TCP_NODELAY on backend connections. hyper's default connector leaves Nagle
    // enabled, which is the wrong trade for a reverse proxy: a proxied request is
    // a small write followed by a wait for the reply, so Nagle holds the write
    // looking for more data that is never coming while the backend's delayed ACK
    // holds the other side. Measured against a local backend, mean request
    // latency was 917us with it left on.
    let mut backend_connector = HttpConnector::new();
    backend_connector.set_nodelay(true);
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(backend_connector);

    // Client with pooling disabled, for backends configured with disable_pooling = true.
    // pool_max_idle_per_host(0) means a connection is never returned to the pool
    // after a response completes, so every request pays for a fresh connection.
    let mut direct_connector = HttpConnector::new();
    direct_connector.set_nodelay(true);
    let direct_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(direct_connector);

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

    // Initialize fingerprint extractor for JA3/JA4 tracking
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize advanced multi-dimensional rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let conn_metrics = metrics.clone();
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter.clone(), metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        conformance: crate::conformance::shared(&config.conformance),
        config: config.clone(),
        port,
        alt_svc_value: HeaderValue::from_str(&layers::build_alt_svc_header_with_override(
            port,
            &config.server.additional_ports,
            config.server.alt_svc_ports.as_deref(),
        ))
        .ok(),
        webtransport_port_value: HeaderValue::from_str(&port.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("443")),
        http_client: Arc::new(http_client),
        https_client: Arc::new(https_client),
        direct_client: Arc::new(direct_client),
        security: Arc::new(security_state.clone()),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
        rate_limiter: rate_limiter.clone(),
    };

    // axum clones `State<T>` for the handler and again for every middleware
    // layer that takes it, so the struct was being copied field-by-field several
    // times per request. One `Arc` makes each of those a refcount bump; field
    // access is unchanged through `Deref`.
    let state = Arc::new(state);

    // Initialize compression state
    let compression_state = CompressionState::default();

    // Initialize HTTP/3 features state
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize response cache
    let response_cache = crate::cache::shared(&config.cache);
    if config.cache.enabled {
        info!(
            "💾 Response cache enabled (max {}MiB, default TTL {}s)",
            config.cache.max_size_mb, config.cache.default_ttl_secs
        );
    }

    // Initialize fingerprint middleware state
    let fingerprint_state = FingerprintMiddlewareState::new(
        fingerprint_extractor.clone(),
        security_state.clone(),
        Arc::new(config.fingerprint.clone()),
    );

    let app = build_proxy_service(
        state.clone(),
        response_cache,
        compression_state,
        http3_features_state,
        Arc::new(security_state.clone()),
        Some(fingerprint_state),
        rl_state,
    );

    // Build rustls server config (h2 + http/1.1).
    // Use the shared resolver when provided so ACME-issued certs are hot-reloaded
    // without restarting the listener; fall back to a private resolver otherwise.
    let rustls_config = if let Some(ref resolver) = shared_resolver {
        build_rustls_server_config_with_resolver(std::sync::Arc::clone(resolver))?
    } else {
        build_rustls_server_config(cert_path, key_path)?
    };
    let rustls_config = Arc::new(rustls_config);

    // Build HTTP/1.1-only config for SNI-selected hosts that must not use HTTP/2.
    // Browsers that negotiate http/1.1 open independent TCP connections per stream
    // (up to 6 per origin) instead of coalescing all streams on one HTTP/2 pipe.
    let http11_only_config = if !config.server.http11_only_hosts.is_empty() {
        let cfg = if let Some(ref resolver) = shared_resolver {
            build_rustls_server_config_http11_only_with_resolver(std::sync::Arc::clone(resolver))?
        } else {
            build_rustls_server_config_http11_only(cert_path, key_path)?
        };
        Some(Arc::new(cfg))
    } else {
        None
    };

    // Create fingerprinting TLS acceptor
    let mut acceptor_builder = FingerprintingTlsAcceptor::new(
        rustls_config,
        fingerprint_extractor,
        security_state,
        config.fingerprint.clone(),
        // SEC-002: propagate 0-RTT enabled flag so the acceptor can detect
        // early data offered in ClientHello and tag the connection accordingly.
        config.tls.enable_0rtt,
    );
    // The acceptor defaulted to mode "strict" with a 60 s window regardless of
    // what the operator configured, so `tls.zero_rtt_replay_protection` and
    // `tls.zero_rtt_nonce_window_secs` were validated at startup and then
    // discarded.  Selecting "none" or "session" silently still got "strict",
    // and — worse for anyone who trusted the knob — shortening the window did
    // nothing.  Feed the acceptor the real values.
    acceptor_builder = acceptor_builder.with_zero_rtt_protection(
        &config.tls.zero_rtt_replay_protection,
        config.tls.zero_rtt_nonce_window_secs,
    );
    if let Some(h11_cfg) = http11_only_config {
        acceptor_builder = acceptor_builder
            .with_http11_only_acceptor(h11_cfg, config.server.http11_only_hosts.clone());
        info!(
            "🔒 HTTP/1.1-only ALPN active for: {:?}",
            config.server.http11_only_hosts
        );
    }
    let fingerprinting_acceptor = Arc::new(acceptor_builder);

    // Bind TCP listener
    let listener = TcpListener::bind(addr).await?;

    info!("✅ Custom TLS accept loop configured");
    info!("🔒 HTTPS reverse proxy ready on port {} (TCP)", port);
    info!("🔍 JA3/JA4 fingerprinting active at TLS layer");
    // SEC-A04: Hardcoded backend addresses removed from logs to prevent topology disclosure.

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            // Accept new connections
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok((stream, addr)) => (stream, crate::security::canonical_addr(addr)),
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                // Nagle has to go on a client-facing socket. A proxy writes a
                // response and then waits, so a small write left buffered waits
                // out the peer's delayed-ACK timer -- 40 ms, on every response
                // whose last segment is short. `axum_server` covers the
                // listeners it owns via `NoDelayAcceptor`; this accept loop is
                // ours, so it has to do it here.
                if nodelay {
                    if let Err(e) = stream.set_nodelay(true) {
                        warn!("Failed to set TCP_NODELAY on {}: {}", remote_addr, e);
                    }
                }

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
async fn handle_fingerprinted_connection<S>(
    stream: TcpStream,
    remote_addr: SocketAddr,
    acceptor: Arc<FingerprintingTlsAcceptor>,
    app: S,
    metrics: Arc<MetricsRegistry>,
) where
    S: tower::Service<Request<Body>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
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
    let is_http1 = protocol == ConnectionProtocol::Http1;

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
            // SEC-002: Strip any client-supplied x-tls-early-data header before
            // setting it from the TLS connection state.  This prevents external
            // callers from spoofing the flag by including it in their request.
            req.headers_mut().remove("x-tls-early-data");
            // Strip any client-supplied x-client-cert header before injecting
            // the authoritative value from the TLS handshake result.
            req.headers_mut().remove("x-client-cert");
            // Strip any client-supplied x-connection-protocol header before
            // injecting the authoritative value from ALPN negotiation.
            req.headers_mut().remove("x-connection-protocol");
            // Same for the classification headers. These are only inserted when
            // the fingerprinter has something to say, so without an
            // unconditional strip a caller could simply assert
            // `x-client-type: browser` and have it survive to the backend —
            // curl arriving labelled as a browser.
            req.headers_mut().remove("x-client-type");
            req.headers_mut().remove("x-client-name");

            // Inject the negotiated-handshake headers the Handshake Mirror
            // reads. Strips any client-supplied copies first (see
            // HandshakeFacts::inject_headers).
            ci.handshake.inject_headers(req.headers_mut());

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

            // SEC-002: Tag early-data connections so proxy_handler can enforce
            // per-route allow_0rtt policy and respond 425 Too Early when needed.
            if ci.is_early_data {
                req.headers_mut()
                    .insert("x-tls-early-data", HeaderValue::from_static("1"));
            }

            // Tag connections where the client presented a TLS certificate so
            // proxy_handler can enforce per-route internal mTLS requirements.
            if ci.client_cert_present {
                req.headers_mut()
                    .insert("x-client-cert", HeaderValue::from_static("1"));
            }

            // Tag HTTP/1.1 connections so proxy_handler can enforce per-route
            // allow_http11 policy and respond 426 Upgrade Required when needed.
            // The header is stripped above so it cannot be forged by clients.
            if is_http1 {
                req.headers_mut()
                    .insert("x-connection-protocol", HeaderValue::from_static("h1"));
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
    // HTTP/2 flow control windows set to 16 MB per stream / 64 MB per connection.
    // The hyper default (65535 bytes) caps all streams to ~8 Mbps at 60 ms RTT —
    // matching QUIC's initial window eliminates this bottleneck for download tests.
    let io = TokioIo::new(tls_stream);
    let mut auto_builder = AutoBuilder::new(TokioExecutor::new());
    auto_builder
        .http2()
        .initial_stream_window_size(16 * 1024 * 1024u32)
        .initial_connection_window_size(64 * 1024 * 1024u32);

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
#[allow(clippy::too_many_arguments)]
pub async fn run_http_listener_pqc_with_fingerprint(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    config: Arc<ProxyConfig>,
    pqc_provider: Arc<PqcTlsProvider>,
    shutdown_rx: watch::Receiver<()>,
    metrics: Arc<MetricsRegistry>,
    load_balancer: Arc<LoadBalancer>,
    sni_map: openssl_pqc::PqcSniMap,
    // Shared with every other listener. Each of these built its own
    // `SecurityState` before, so a blocked IP, a rate-limit counter, an
    // observed fingerprint or a DB-synced blocklist entry existed only on
    // whichever listener happened to see it.
    security_state: SecurityState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read once here: `config` is moved into builders further down in
    // several of these functions.
    let nodelay = config.server.tcp_nodelay;
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
    // TCP_NODELAY on backend connections. hyper's default connector leaves Nagle
    // enabled, which is the wrong trade for a reverse proxy: a proxied request is
    // a small write followed by a wait for the reply, so Nagle holds the write
    // looking for more data that is never coming while the backend's delayed ACK
    // holds the other side. Measured against a local backend, mean request
    // latency was 917us with it left on.
    let mut backend_connector = HttpConnector::new();
    backend_connector.set_nodelay(true);
    let http_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_secs))
        .build(backend_connector);

    // Client with pooling disabled, for backends configured with disable_pooling = true.
    // pool_max_idle_per_host(0) means a connection is never returned to the pool
    // after a response completes, so every request pays for a fresh connection.
    let mut direct_connector = HttpConnector::new();
    direct_connector.set_nodelay(true);
    let direct_client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(direct_connector);

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

    // Initialize fingerprint extractor
    let fingerprint_extractor = Arc::new(FingerprintExtractor::new());

    // Initialize rate limiter
    let rate_limiter = Arc::new(AdvancedRateLimiter::new(
        config.advanced_rate_limiting.clone(),
    ));
    let conn_metrics = metrics.clone();
    let state_metrics = metrics.clone();
    let rl_state = (rate_limiter.clone(), metrics);
    info!(
        "🚦 Advanced rate limiter enabled (key strategy: {:?})",
        config.advanced_rate_limiting.key_strategy.order.first()
    );

    let state = HttpListenerState {
        conformance: crate::conformance::shared(&config.conformance),
        config: config.clone(),
        port,
        alt_svc_value: HeaderValue::from_str(&layers::build_alt_svc_header_with_override(
            port,
            &config.server.additional_ports,
            config.server.alt_svc_ports.as_deref(),
        ))
        .ok(),
        webtransport_port_value: HeaderValue::from_str(&port.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("443")),
        http_client: Arc::new(http_client),
        https_client: Arc::new(https_client),
        direct_client: Arc::new(direct_client),
        security: Arc::new(security_state.clone()),
        fingerprint: fingerprint_extractor.clone(),
        load_balancer,
        metrics: state_metrics,
        rate_limiter,
    };

    // axum clones `State<T>` for the handler and again for every middleware
    // layer that takes it, so the struct was being copied field-by-field several
    // times per request. One `Arc` makes each of those a refcount bump; field
    // access is unchanged through `Deref`.
    let state = Arc::new(state);

    // Initialize middleware states
    let compression_state = CompressionState::default();
    let http3_features_state = Http3FeaturesState::from_proxy_config(&config.http3);

    // Initialize response cache
    let response_cache = crate::cache::shared(&config.cache);
    if config.cache.enabled {
        info!(
            "💾 Response cache enabled (max {}MiB, default TTL {}s)",
            config.cache.max_size_mb, config.cache.default_ttl_secs
        );
    }

    let fingerprint_state = FingerprintMiddlewareState::new(
        fingerprint_extractor.clone(),
        security_state.clone(),
        Arc::new(config.fingerprint.clone()),
    );

    let app = build_proxy_service(
        state.clone(),
        response_cache,
        compression_state,
        http3_features_state,
        Arc::new(security_state.clone()),
        Some(fingerprint_state),
        rl_state,
    );

    // Create OpenSSL PQC acceptor with SNI multi-domain support.
    // The `sni_map` was pre-built by the caller and is shared with the ACME
    // cert-update handler, so new certificates are hot-reloaded without restart.
    let cert_path_buf = std::path::Path::new(cert_path);
    let key_path_buf = std::path::Path::new(key_path);
    let ssl_acceptor = openssl_pqc::create_pqc_acceptor_with_sni(
        cert_path_buf,
        key_path_buf,
        &pqc_provider,
        sni_map,
    )
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
    // SEC-A04: Hardcoded backend addresses removed from logs to prevent topology disclosure.

    // Accept loop with graceful shutdown
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok((stream, addr)) => (stream, crate::security::canonical_addr(addr)),
                    Err(e) => {
                        warn!("Failed to accept TCP connection: {}", e);
                        continue;
                    }
                };

                // Nagle has to go on a client-facing socket. A proxy writes a
                // response and then waits, so a small write left buffered waits
                // out the peer's delayed-ACK timer -- 40 ms, on every response
                // whose last segment is short. `axum_server` covers the
                // listeners it owns via `NoDelayAcceptor`; this accept loop is
                // ours, so it has to do it here.
                if nodelay {
                    if let Err(e) = stream.set_nodelay(true) {
                        warn!("Failed to set TCP_NODELAY on {}: {}", remote_addr, e);
                    }
                }

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
/// Capture what the OpenSSL PQC listener's handshake negotiated.
///
/// The rustls path builds the same facts in `HandshakeFacts::from_connection`;
/// this is the OpenSSL equivalent, reading the group through the FFI binding in
/// `pqc_tls::openssl_pqc::negotiated_group` rather than assuming it.
///
/// ECH is reported as `not-supported` rather than `not-offered`: this listener
/// has no ECH keys at all, so "the client did not offer it" would be a claim
/// this code is in no position to make.
fn pqc_handshake_facts(ssl: &openssl::ssl::SslRef) -> crate::tls_acceptor::HandshakeFacts {
    crate::tls_acceptor::HandshakeFacts {
        tls_version: Some(ssl.version_str().to_string()),
        cipher_suite: ssl.current_cipher().map(|c| c.name().to_string()),
        kex_group: crate::pqc_tls::openssl_pqc::negotiated_group(ssl),
        alpn: ssl
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned()),
        ech: "not-supported",
    }
}

// Every argument is a distinct per-connection dependency with no natural
// grouping; bundling them into a struct purely to satisfy the lint would add an
// indirection this accept path does not otherwise need.
#[allow(clippy::too_many_arguments)]
async fn handle_pqc_fingerprinted_connection<S>(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ssl_context: Arc<openssl::ssl::SslContext>,
    fingerprint_extractor: Arc<FingerprintExtractor>,
    security_state: SecurityState,
    fingerprint_config: crate::config::FingerprintConfig,
    app: S,
    metrics: Arc<MetricsRegistry>,
) where
    S: tower::Service<Request<Body>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
{
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
    let is_http1 = protocol == ConnectionProtocol::Http1;

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

    // Detect whether client presented a certificate (for per-route mTLS enforcement).
    let client_cert_present = ssl_stream.ssl().peer_certificate().is_some();

    // Create connection info (OpenSSL PQC path does not use rustls 0-RTT)
    let conn_info = crate::tls_acceptor::FingerprintedConnection {
        remote_addr,
        ja3_hash: ja3_hash.clone(),
        ja4_hash: ja4_hash.clone(),
        client_name: client_name.clone(),
        is_browser,
        is_early_data: false,
        client_cert_present,
        handshake: pqc_handshake_facts(ssl_stream.ssl()),
    };

    // Create service that injects fingerprint headers
    let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        let ja3 = ja3_hash.clone();
        let ja4 = ja4_hash.clone();
        let cn = client_name.clone();
        let ci = conn_info.clone();
        let router = app.clone();

        async move {
            // SEC-002: Strip any client-supplied x-tls-early-data header.
            req.headers_mut().remove("x-tls-early-data");
            // Strip any client-supplied x-client-cert header before injecting
            // the authoritative value from the TLS handshake result.
            req.headers_mut().remove("x-client-cert");
            // Strip any client-supplied x-connection-protocol header before
            // injecting the authoritative value from ALPN negotiation.
            req.headers_mut().remove("x-connection-protocol");
            // Same for the classification headers. These are only inserted when
            // the fingerprinter has something to say, so without an
            // unconditional strip a caller could simply assert
            // `x-client-type: browser` and have it survive to the backend —
            // curl arriving labelled as a browser.
            req.headers_mut().remove("x-client-type");
            req.headers_mut().remove("x-client-name");

            // Inject the negotiated-handshake headers the Handshake Mirror
            // reads. Strips any client-supplied copies first (see
            // HandshakeFacts::inject_headers).
            ci.handshake.inject_headers(req.headers_mut());

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

            // Report whether *this handshake* was post-quantum, not whether the
            // listener supports it. The constant `true` this replaced was wrong
            // for every classical-only client that reached this port.
            req.headers_mut().remove("x-pqc-enabled");
            let pqc_negotiated = ci
                .handshake
                .kex_group
                .as_deref()
                .and_then(crate::pqc_tls::PqcKemAlgorithm::from_str)
                .is_some();
            req.headers_mut().insert(
                "x-pqc-enabled",
                if pqc_negotiated {
                    HeaderValue::from_static("true")
                } else {
                    HeaderValue::from_static("false")
                },
            );

            // Tag connections where the client presented a TLS certificate so
            // proxy_handler can enforce per-route internal mTLS requirements.
            if ci.client_cert_present {
                req.headers_mut()
                    .insert("x-client-cert", HeaderValue::from_static("1"));
            }

            // Tag HTTP/1.1 connections so proxy_handler can enforce per-route
            // allow_http11 policy and respond 426 Upgrade Required when needed.
            // The header is stripped above so it cannot be forged by clients.
            if is_http1 {
                req.headers_mut()
                    .insert("x-connection-protocol", HeaderValue::from_static("h1"));
            }

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
    // HTTP/2 flow control windows set to 16 MB per stream / 64 MB per connection
    // (same rationale as Rustls listener above).
    let io = TokioIo::new(ssl_stream);
    let mut auto_builder = AutoBuilder::new(TokioExecutor::new());
    auto_builder
        .http2()
        .initial_stream_window_size(16 * 1024 * 1024u32)
        .initial_connection_window_size(64 * 1024 * 1024u32);

    if let Err(e) = auto_builder.serve_connection(io, service).await {
        if !e.to_string().contains("connection reset") {
            debug!("PQC HTTP connection error for {}: {}", remote_addr, e);
        }
    }

    metrics.connections.connection_closed();
}

/// Main proxy handler - routes requests to appropriate backends
async fn proxy_handler(
    State(state): State<Arc<HttpListenerState>>,
    Host(host): Host,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    // The connection's real protocol, for the per-route HTTP/1.1 gate. Read here
    // rather than from `x-connection-protocol`: only two of the three TCP accept
    // loops injected that header, so the gate was inert on the third.
    let is_http11 = req.version() == http::Version::HTTP_11;
    let is_ws_upgrade = headers
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let request_start = std::time::Instant::now();
    let is_health_check = headers
        .get("x-health-check-bypass")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);
    if !is_health_check {
        state.metrics.requests.request_start();
    }
    // Strip port from host if present — axum's Host extractor includes the port
    // for non-standard ports (e.g. "tcp2.pqcrypta.com:4433"). All subsequent host
    // comparisons (tcp_only_hosts, route matching, etc.) expect bare hostnames.
    let host: String = {
        let h: &str = &host;
        if !h.starts_with('[') {
            if let Some(colon) = h.rfind(':') {
                if h[colon + 1..].bytes().all(|b| b.is_ascii_digit()) {
                    h[..colon].to_string()
                } else {
                    h.to_string()
                }
            } else {
                h.to_string()
            }
        } else {
            h.to_string()
        }
    };
    let path = if state.config.server.normalize_paths {
        uri.path().to_ascii_lowercase()
    } else {
        uri.path().to_string()
    };
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

    // ── Conformance vhost — catalogue, session, report, badge ───────────────
    //
    // Handled in-process before route lookup, like the speedtest hosts below,
    // so no backend is required. Only ever on its own hostname: a request that
    // lands here by misrouting is served normally rather than being handed a
    // page about a suite the caller never asked for.
    if let Some(conf) = state.conformance.as_ref() {
        if conf.owns_host(&host_str) {
            if let Some(resp) = crate::conformance::http::route(
                conf,
                &method,
                &path,
                crate::security::canonical_addr(client_addr).ip(),
            ) {
                return resp;
            }
        }
    }

    // ── TCP-only speedtest hosts — true TCP-only speedtest (no Alt-Svc, no QUIC) ─
    // Handled in-process before route lookup so no backend is required.
    // Covers tcp.pqcrypta.com (primary) and any host in tcp_only_hosts config.
    let is_native_tcp_speedtest = host == "tcp.pqcrypta.com"
        || state
            .config
            .server
            .tcp_only_hosts
            .iter()
            .any(|h| h == &host);
    if is_native_tcp_speedtest {
        // Echo the request's Origin when it is in the allowlist, so the TCP
        // speedtest works from any allowed front-end regardless of list order.
        // Fall back to the first allowed origin (then pqcrypta.com) when the
        // request has no Origin or it is not allowed.
        let allowed = &state.config.server.webtransport_allowed_origins;
        let req_origin = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let cors_origin: String = req_origin
            .filter(|o| allowed.iter().any(|a| a == o))
            .or_else(|| allowed.first().cloned())
            .unwrap_or_else(|| "https://pqcrypta.com".to_string());

        // CORS preflight
        if method == Method::OPTIONS {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::NO_CONTENT;
            let h = resp.headers_mut();
            h.insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(&cors_origin)
                    .unwrap_or_else(|_| HeaderValue::from_static("https://pqcrypta.com")),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                HeaderValue::from_static("GET, POST, OPTIONS"),
            );
            h.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_static("content-type"),
            );
            h.insert(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from_static("86400"),
            );
            return resp;
        }

        // Ping
        if method == Method::GET
            && (path == "/speedtest/tcp-ping" || path == "/speedtest/tcp-ping.php")
        {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            let mut resp = axum::Json(serde_json::json!({ "ok": true, "ts": ts })).into_response();
            resp.headers_mut().insert(
                "access-control-allow-origin",
                HeaderValue::from_str(&cors_origin)
                    .unwrap_or_else(|_| HeaderValue::from_static("https://pqcrypta.com")),
            );
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache"),
            );
            return resp;
        }

        // Download — stream LCG-generated random bytes directly over TCP/H2
        if method == Method::GET && path == "/speedtest/tcp-download.php" {
            let bytes_requested: u64 = uri
                .query()
                .and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        match (parts.next(), parts.next()) {
                            (Some("size"), Some(v)) => v.parse::<u64>().ok(),
                            _ => None,
                        }
                    })
                })
                .unwrap_or(10 * 1024 * 1024);
            let bytes_to_send: u64 = bytes_requested.clamp(65_536, 100 * 1024 * 1024);

            // Pre-compute a 256 KiB pseudo-random chunk via LCG
            const CHUNK: usize = 256 * 1024;
            let mut lcg: u64 = 0xdead_beef_cafe_babe;
            let chunk_data: Vec<u8> = (0..CHUNK)
                .map(|_| {
                    lcg = lcg
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    u8::try_from(lcg >> 33 & 0xFF).unwrap_or(0)
                })
                .collect();
            let chunk_bytes = bytes::Bytes::from(chunk_data);

            let data_stream = futures_util::stream::unfold(
                (bytes_to_send, chunk_bytes),
                move |(mut rem, chunk)| async move {
                    if rem == 0 {
                        return None;
                    }
                    let n = usize::try_from(rem.min(CHUNK as u64)).unwrap_or(CHUNK);
                    let data = chunk.slice(..n);
                    rem -= n as u64;
                    Some((Ok::<bytes::Bytes, std::io::Error>(data), (rem, chunk)))
                },
            );

            let mut resp = axum::response::Response::new(Body::from_stream(data_stream));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(v) = HeaderValue::from_str(&bytes_to_send.to_string()) {
                resp.headers_mut().insert(header::CONTENT_LENGTH, v);
            }
            resp.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, no-cache, must-revalidate"),
            );
            resp.headers_mut().insert(
                "access-control-allow-origin",
                HeaderValue::from_str(&cors_origin)
                    .unwrap_or_else(|_| HeaderValue::from_static("https://pqcrypta.com")),
            );
            resp.headers_mut()
                .insert("x-accel-buffering", HeaderValue::from_static("no"));
            info!(
                "[speedtest-dl/tcp] {} bytes → {}",
                bytes_to_send, client_addr
            );
            return resp;
        }

        // Upload POST is caught by the router before reaching proxy_handler;
        // all other paths on TCP-only speedtest hosts return 404.
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    // ─────────────────────────────────────────────────────────────────────────

    // Find matching route
    let route = state.config.find_route(Some(&host), &path, false);

    if let Some(route) = route {
        // Per-route secondary rate limit check.
        // The outer middleware checks rate limits before route resolution (route_name = None).
        // Routes listed in advanced_rate_limiting.route_limits get an additional targeted check
        // here, after route matching, using the route name as the limiter key.
        if let Some(ref route_name) = route.name {
            if state
                .config
                .advanced_rate_limiting
                .route_limits
                .contains_key(route_name.as_str())
            {
                let route_ctx = build_context_from_request(
                    client_addr.ip(),
                    &headers,
                    &path,
                    method.as_str(),
                    None,
                    None,
                    Some(route_name.clone()),
                );
                if let RateLimitResult::Limited {
                    retry_after_ms,
                    limit,
                    ..
                } = state.rate_limiter.check(&route_ctx).await
                {
                    let mut resp = (
                        StatusCode::TOO_MANY_REQUESTS,
                        "Rate limit exceeded for this endpoint",
                    )
                        .into_response();
                    let h = resp.headers_mut();
                    if let Ok(v) = HeaderValue::from_str(&(retry_after_ms / 1000).to_string()) {
                        h.insert("retry-after", v);
                    }
                    if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
                        h.insert("x-ratelimit-limit", v);
                    }
                    h.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
                    return resp;
                }
            }
        }

        // Handle redirect routes. Shared with the HTTP/3 path, which had no
        // redirect handling at all and answered 502 for these.
        if let Some((target, permanent)) = crate::route_gate::redirect_target(route, &path, &query)
        {
            if permanent {
                return Redirect::permanent(&target).into_response();
            }
            return Redirect::temporary(&target).into_response();
        }

        // Handle OPTIONS preflight for CORS
        if method == Method::OPTIONS {
            if let Some(ref cors) = route.cors {
                let req_origin = headers.get("origin").and_then(|v| v.to_str().ok());
                return handle_cors_preflight(cors, req_origin);
            }
        }

        // A WebSocket upgrade is always HTTP/1.1, so it bypasses the HTTP/1.1
        // gate below and later selects the tunnel path instead of a plain proxy.
        let ws_passthrough = is_ws_upgrade && route.supports_websocket;

        // Per-route gates: 0-RTT policy, the HTTP/1.1 restriction, internal-route
        // mTLS and HMAC proof-of-possession. Every one of these is the SAME
        // implementation the HTTP/3 path now runs — they used to live only here,
        // so a route protected by `mtls_required` or an `hmac_secret` was open
        // over HTTP/3. See `crate::route_gate`.
        {
            let path_and_query = uri
                .path_and_query()
                .map(|pq| pq.as_str())
                .unwrap_or_else(|| uri.path());
            let gate_cx = crate::route_gate::GateContext {
                route,
                method: method.as_str(),
                path_and_query,
                path: &path,
                headers: &headers,
                client_ip: client_addr.ip(),
                is_http11,
                is_websocket_upgrade: is_ws_upgrade,
                zero_rtt_safe_methods: &state.config.tls.zero_rtt_safe_methods,
                hmac_nonce_store: crate::route_gate::shared_nonce_store(
                    state.config.tls.zero_rtt_nonce_window_secs,
                ),
            };
            if let crate::route_gate::GateOutcome::Refuse {
                status,
                headers: extra,
            } = crate::route_gate::evaluate(&gate_cx)
            {
                let mut resp = status.into_response();
                for (k, v) in extra {
                    if let Ok(val) = HeaderValue::from_str(&v) {
                        resp.headers_mut().insert(k, val);
                    }
                }
                return resp;
            }
        }

        // Track request timing for load balancer
        let request_start = std::time::Instant::now();

        // Check if backend is a pool first, then fall back to single backend
        let mut canary_cookie_to_set: Option<String> = None;
        let (backend_address, tls_mode, pool_server, pool_name, backend_timeout, disable_pooling) =
            if let Some(pool) = state.load_balancer.get_pool(&route.backend) {
                // Extract session cookie for sticky sessions
                let cookie_header = headers.get("cookie").and_then(|v| v.to_str().ok());
                let session_cookie =
                    extract_session_cookie(cookie_header, &state.load_balancer.cookie_config);

                // Extract canary sticky cookie
                let canary_name = pool
                    .canary_config
                    .as_ref()
                    .map(|c| c.sticky_cookie_name.as_str())
                    .unwrap_or("PQCPROXY_CANARY");
                let canary_cookie = extract_cookie_by_name(cookie_header, canary_name);

                // Extract canary sticky header (pre-assigned group)
                let canary_header = pool
                    .canary_config
                    .as_ref()
                    .and_then(|c| c.sticky_header.as_ref())
                    .and_then(|h| {
                        headers
                            .get(h.as_str())
                            .and_then(|v| v.to_str().ok().map(String::from))
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
                    canary_cookie,
                    canary_header,
                    query: uri.query().map(String::from),
                    hash_header: pool.hash_header_name().and_then(|h| {
                        headers
                            .get(h)
                            .and_then(|v| v.to_str().ok().map(String::from))
                    }),
                };

                // Select backend from pool
                match pool.select(&ctx) {
                    Some(result) => {
                        let address = result.server.address.to_string();
                        let tls = result.server.tls_mode.clone();
                        let timeout = result.server.timeout;
                        canary_cookie_to_set = result.set_canary_cookie;
                        (
                            address,
                            tls,
                            Some(result.server),
                            Some(route.backend.clone()),
                            timeout,
                            // Pool servers don't carry a disable_pooling field today —
                            // no pool member currently needs it.
                            false,
                        )
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

                (
                    backend.address.clone(),
                    tls_mode,
                    None,
                    None,
                    Duration::from_millis(backend.timeout_ms),
                    backend.disable_pooling,
                )
            } else {
                error!("Backend or pool not found: {}", route.backend);
                return (StatusCode::BAD_GATEWAY, "Backend not configured").into_response();
            };

        // A route may raise or lower the backend's timeout for its own traffic —
        // one slow endpoint (an LLM chat completion, a large PDF conversion)
        // should not force every other route on that backend to wait as long.
        // Applies to pool members too: the override is a property of the route,
        // not of whichever server the pool happened to pick.
        let backend_timeout = match route.timeout_override_ms {
            Some(ms) => Duration::from_millis(ms),
            None => backend_timeout,
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

        // WebSocket upgrade passthrough — extract the OnUpgrade future from the request
        // extensions (inserted by hyper when it parses a Connection: Upgrade request) and
        // hand the raw TCP stream to the tunnel handler.  All paths inside this block return.
        if ws_passthrough {
            let on_upgrade = req.extensions_mut().remove::<OnUpgrade>();
            let Some(on_upgrade) = on_upgrade else {
                error!(
                    "WebSocket upgrade request on route {:?} has no OnUpgrade extension \
                     (hyper did not inject it — is the connection HTTP/1.1?)",
                    route.name
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            };
            return handle_websocket_tunnel(
                &backend_address,
                use_https,
                &headers,
                on_upgrade,
                &path,
                &query,
                &host,
                route.ws_idle_timeout_secs,
            )
            .await;
        }

        // Build proxy request
        let mut proxy_req = Request::builder().method(method.clone()).uri(&backend_url);

        // Copy headers with modifications
        if let Some(h) = proxy_req.headers_mut() {
            // Copy original headers
            for (name, value) in headers.iter() {
                // Skip hop-by-hop headers and internal proxy-only headers that
                // must not be forwarded to backends.
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
                    // SEC-002: internal 0-RTT tag — never forward to backends
                    "x-tls-early-data",
                    // SEC-03: strip client-supplied forwarding headers; the proxy injects
                    // trusted values from the actual socket address below.
                    "x-forwarded-for",
                    "x-forwarded-proto",
                    "x-forwarded-port",
                    "x-real-ip",
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

        // Consume the request body now — WebSocket upgrades were handled above and always
        // returned early, so `req` was not moved in that branch.
        let body = req.into_body();

        // Buffer request body when shadow mirroring is configured on this route.
        // Only incurs allocation cost when a shadow backend is configured with percent > 0.
        // Both shadow_body_bytes and forward_body are derived from a single move of `body`
        // so the borrow checker is satisfied regardless of which branch is taken.
        let needs_shadow = route
            .shadow
            .as_ref()
            .map(|s| !s.backend.is_empty() && s.percent > 0)
            .unwrap_or(false);
        let (shadow_body_bytes, forward_body) = if needs_shadow {
            match axum::body::to_bytes(body, usize::MAX).await {
                Ok(b) => {
                    let fwd = Body::from(b.clone());
                    (Some(b), fwd)
                }
                Err(e) => {
                    error!(
                        "Failed to buffer request body for shadow mirroring (shadow skipped): {}",
                        e
                    );
                    (None, Body::empty())
                }
            }
        } else {
            (None, body)
        };

        // Build and send request
        let proxy_request = match proxy_req.body(forward_body) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to build proxy request: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to build request")
                    .into_response();
            }
        };

        // Shadow mirroring: spawn fire-and-forget task concurrently with primary forward.
        // The client only receives the primary response; shadow response is logged + discarded.
        if let (Some(shadow_cfg), Some(shadow_bytes)) = (&route.shadow, &shadow_body_bytes) {
            let roll: u8 = rand::random::<u8>() % 100;
            if roll < shadow_cfg.percent.min(100) {
                if let Some(shadow_backend) = state.config.get_backend(&shadow_cfg.backend) {
                    spawn_shadow_request(
                        shadow_cfg,
                        shadow_bytes.clone(),
                        shadow_backend,
                        &method,
                        &headers,
                        &host,
                        &path,
                        &query,
                        client_addr,
                        state.port,
                        &route.add_headers,
                        (*state.http_client).clone(),
                        (*state.https_client).clone(),
                    );
                } else {
                    warn!(
                        "Shadow backend '{}' not found in config for route {:?}",
                        shadow_cfg.backend, route.name
                    );
                }
            }
        }

        // Send request to backend (using appropriate client), bounded by the
        // per-backend/pool-server timeout so a hung backend can't hold the
        // connection open indefinitely.
        let result = tokio::time::timeout(backend_timeout, async {
            if use_https {
                state.https_client.request(proxy_request).await
            } else if disable_pooling {
                state.direct_client.request(proxy_request).await
            } else {
                state.http_client.request(proxy_request).await
            }
        })
        .await;

        match result {
            Err(_) => {
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

                warn!(
                    "Backend request to '{}' timed out after {}ms",
                    route.backend,
                    backend_timeout.as_millis()
                );

                // Record request metrics (skip error tracking for health check traffic)
                state.metrics.requests.request_end_full(
                    504,
                    request_start.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );

                // Log backend timeout
                log_access(&AccessLogEntry {
                    remote_addr: client_addr,
                    method: &method_str,
                    path: &path,
                    protocol: "HTTP/1.1",
                    status: 504,
                    body_size: 0,
                    referer: referer.as_deref(),
                    user_agent: user_agent.as_deref(),
                    host: Some(&host_str),
                    response_time_ms: request_start
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                });

                (
                    StatusCode::GATEWAY_TIMEOUT,
                    format!("Backend timeout after {}ms", backend_timeout.as_millis()),
                )
                    .into_response()
            }
            Ok(Ok(backend_response)) => {
                let response_time = request_start.elapsed();

                // Record success for circuit breaker (single backend)
                state.security.record_backend_result(&route.backend, true);

                let (mut parts, incoming_body) = backend_response.into_parts();

                // The TLS-terminating proxy speaks plain HTTP to the backend, so the
                // backend's self-referential redirects (Apache mod_speling case-fixes,
                // DirectorySlash, etc.) come back as `Location: http://…`. Clients are
                // always on HTTPS, so an http:// redirect is unusable and is blocked by
                // the browser as mixed content. Upgrade the redirect scheme to https.
                if let Some(loc) = parts.headers.get(header::LOCATION) {
                    if let Some(rest) = loc.to_str().ok().and_then(|s| s.strip_prefix("http://")) {
                        if let Ok(fixed) = HeaderValue::from_str(&format!("https://{rest}")) {
                            parts.headers.insert(header::LOCATION, fixed);
                        }
                    }
                }

                // SSE / chunked-streaming fast path: skip buffering and pipe the body
                // directly to the client. Buffering an SSE stream would hold the entire
                // generation in memory and deliver it all at once when finished.
                let content_type = parts
                    .headers
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if content_type.contains("text/event-stream") {
                    // Release pool slot immediately — the streaming hyper connection keeps
                    // the underlying TCP socket open for as long as the body is live.
                    if let (Some(server), Some(ref pn)) = (&pool_server, &pool_name) {
                        state.load_balancer.record_completion(
                            pn,
                            server.as_ref(),
                            response_time,
                            true,
                        );
                        server.release_connection();
                    }
                    if let Some(ref cors) = route.cors {
                        let req_origin = headers.get("origin").and_then(|v| v.to_str().ok());
                        add_cors_headers(&mut parts.headers, cors, req_origin);
                    }
                    for (key, value) in &route.headers_override {
                        if let (Ok(name), Ok(val)) = (
                            header::HeaderName::from_bytes(key.as_bytes()),
                            HeaderValue::from_str(value),
                        ) {
                            parts.headers.insert(name, val);
                        }
                    }
                    // Strip headers the route does not want forwarded. Applied
                    // after the overrides so an override can reinstate one
                    // deliberately; previously routes.remove_headers was parsed
                    // and never acted on, so a backend header listed there was
                    // still sent to the client.
                    for key in &route.remove_headers {
                        if let Ok(name) = header::HeaderName::from_bytes(key.as_bytes()) {
                            parts.headers.remove(&name);
                        }
                    }
                    parts.headers.remove("connection");
                    parts.headers.remove("transfer-encoding");
                    parts.headers.remove("upgrade");
                    parts
                        .headers
                        .insert(header::SERVER, HeaderValue::from_static("pqcrypta"));
                    // Remove content-length — SSE has no fixed length
                    parts.headers.remove("content-length");
                    let resp_status = parts.status.as_u16();
                    state.metrics.requests.request_end_full(
                        resp_status,
                        request_start.elapsed(),
                        0,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    log_access(&AccessLogEntry {
                        remote_addr: client_addr,
                        method: &method_str,
                        path: &path,
                        protocol: "HTTP/1.1",
                        status: resp_status,
                        body_size: 0,
                        referer: referer.as_deref(),
                        user_agent: user_agent.as_deref(),
                        host: Some(&host_str),
                        response_time_ms: request_start
                            .elapsed()
                            .as_millis()
                            .try_into()
                            .unwrap_or(u64::MAX),
                    });
                    return Response::from_parts(parts, Body::new(incoming_body));
                }

                // Buffer the response body BEFORE releasing the backend connection.
                // For HTTP/1.1 streaming responses, releasing the connection closes the
                // socket — any subsequent to_bytes() call in cache/compression middleware
                // then fails and returns Body::empty() (0-byte response to client).
                let mut body_bytes =
                    axum::body::to_bytes(Body::new(incoming_body), 100 * 1024 * 1024)
                        .await
                        .unwrap_or_default();

                // Strip specified JSON fields from the response body (e.g. Frappe `exc` traces).
                // Only applied when Content-Type is application/json and the field list is non-empty.
                if !route.strip_response_json_fields.is_empty() {
                    let is_json = parts
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.contains("application/json"))
                        .unwrap_or(false);
                    if is_json {
                        if let Ok(mut json) =
                            serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        {
                            if let Some(obj) = json.as_object_mut() {
                                for field in &route.strip_response_json_fields {
                                    obj.remove(field.as_str());
                                }
                            }
                            if let Ok(stripped) = serde_json::to_vec(&json) {
                                if let Ok(v) = HeaderValue::from_str(&stripped.len().to_string()) {
                                    parts.headers.insert(header::CONTENT_LENGTH, v);
                                }
                                body_bytes = stripped.into();
                            }
                        }
                    }
                }

                // Record success for load balancer pool — safe to release now that body is buffered
                if let (Some(server), Some(ref pn)) = (&pool_server, &pool_name) {
                    state
                        .load_balancer
                        .record_completion(pn, server.as_ref(), response_time, true);
                    server.release_connection();
                }

                // Add CORS headers if configured
                if let Some(ref cors) = route.cors {
                    let req_origin = headers.get("origin").and_then(|v| v.to_str().ok());
                    add_cors_headers(&mut parts.headers, cors, req_origin);
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

                // Inject canary sticky cookie on first canary assignment
                if let Some(ref cookie_hdr) = canary_cookie_to_set {
                    if let Ok(val) = HeaderValue::from_str(cookie_hdr) {
                        parts.headers.append(header::SET_COOKIE, val);
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

                // Strip headers the route does not want forwarded (see above).
                for key in &route.remove_headers {
                    if let Ok(name) = header::HeaderName::from_bytes(key.as_bytes()) {
                        parts.headers.remove(&name);
                    }
                }

                // Enforce HttpOnly + Secure on all Set-Cookie headers from the backend.
                // Used for backends (e.g. Frappe/ERPNext) that intentionally omit HttpOnly
                // on informational cookies (user_id, full_name) but where the proxy should add it.
                if route.enforce_cookie_security {
                    let existing: Vec<String> = parts
                        .headers
                        .get_all(header::SET_COOKIE)
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .map(|cookie| {
                            let mut c = cookie.to_string();
                            let lower = c.to_lowercase();
                            if !lower.contains("httponly") {
                                c.push_str("; HttpOnly");
                            }
                            if !lower.contains("secure") {
                                c.push_str("; Secure");
                            }
                            c
                        })
                        .collect();
                    if !existing.is_empty() {
                        parts.headers.remove(header::SET_COOKIE);
                        for cookie in existing {
                            if let Ok(val) = HeaderValue::from_str(&cookie) {
                                parts.headers.append(header::SET_COOKIE, val);
                            }
                        }
                    }
                }

                // Handle Stripe compatibility (remove COEP/COOP)
                if route.stripe_compatibility {
                    parts.headers.remove("cross-origin-embedder-policy");
                    parts.headers.remove("cross-origin-opener-policy");
                }

                // Strip hop-by-hop headers that must not be forwarded (RFC 9110 §7.6.1).
                // Apache sends `Connection: Upgrade` on HTTP/1.1 responses (suggesting
                // h2 upgrade), which hyper interprets as a protocol-upgrade response and
                // omits the HTTP body, causing clients to receive "Empty reply".
                // `transfer-encoding` is also hop-by-hop and is irrelevant after we've
                // already buffered the full body above.
                parts.headers.remove("connection");
                parts.headers.remove("transfer-encoding");
                parts.headers.remove("upgrade");

                // SEC-08: Version-agnostic Server header — do not disclose product name or
                // build version to clients. Attackers use Server headers to fingerprint
                // software and target known CVEs.
                parts
                    .headers
                    .insert(header::SERVER, HeaderValue::from_static("pqcrypta"));

                // Build response from buffered body bytes.
                //
                // RFC 9110 §9.3.2: the headers on a HEAD response are the ones a
                // GET would have sent. These pages come off PHP-FPM chunked with
                // no Content-Length, and Apache correctly sends none on HEAD — but
                // `Body::from(Bytes::new())` reports an exact size of zero, so
                // hyper synthesised `content-length: 0` and every link checker,
                // uptime monitor, CDN probe and security scanner that uses HEAD
                // was told the page was empty.
                //
                // An empty *stream* has an unknown size hint, so hyper emits
                // whatever length headers the origin actually chose and nothing
                // more. Only applies when the origin sent no Content-Length; when
                // it did, that value is already correct and is passed through.
                let head_without_length =
                    method == Method::HEAD && !parts.headers.contains_key(header::CONTENT_LENGTH);
                let response_body = if head_without_length {
                    Body::from_stream(futures_util::stream::empty::<
                        Result<bytes::Bytes, std::io::Error>,
                    >())
                } else {
                    Body::from(body_bytes)
                };
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
                    method: &method_str,
                    path: &path,
                    protocol: "HTTP/1.1",
                    status: resp_status,
                    body_size: 0, // Can't know body size for streaming response
                    referer: referer.as_deref(),
                    user_agent: user_agent.as_deref(),
                    host: Some(&host_str),
                    response_time_ms: request_start
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                });

                response
            }
            Ok(Err(e)) => {
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

                error!(
                    "Backend request failed: {:?} (source: {:?})",
                    e,
                    std::error::Error::source(&e)
                );

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
                    method: &method_str,
                    path: &path,
                    protocol: "HTTP/1.1",
                    status: 502,
                    body_size: 0,
                    referer: referer.as_deref(),
                    user_agent: user_agent.as_deref(),
                    host: Some(&host_str),
                    response_time_ms: request_start
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
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
            method: &method_str,
            path: &path,
            protocol: "HTTP/1.1",
            status: 404,
            body_size: 0,
            referer: referer.as_deref(),
            user_agent: user_agent.as_deref(),
            host: Some(&host_str),
            response_time_ms: request_start
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        });

        (StatusCode::NOT_FOUND, "Not Found").into_response()
    }
}

/// Spawn a fire-and-forget shadow request to a secondary backend.
///
/// The spawned task runs independently of the caller; the client never sees the shadow
/// response.  All configurable values (timeout, marker header name/value, logging) come
/// from [`ShadowConfig`] — nothing is hardcoded.
#[allow(clippy::too_many_arguments)]
fn spawn_shadow_request(
    shadow_cfg: &ShadowConfig,
    body_bytes: bytes::Bytes,
    shadow_backend: &BackendConfig,
    method: &Method,
    headers: &HeaderMap,
    host: &str,
    path: &str,
    query: &str,
    client_addr: SocketAddr,
    proxy_port: u16,
    route_add_headers: &std::collections::HashMap<String, String>,
    http_client: Client<HttpConnector, Body>,
    https_client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
) {
    let shadow_use_https = shadow_backend.tls;
    let shadow_url = if shadow_use_https {
        format!("https://{}{}{}", shadow_backend.address, path, query)
    } else {
        format!("http://{}{}{}", shadow_backend.address, path, query)
    };

    // Clone all values needed inside the spawned task
    let timeout_ms = shadow_cfg.timeout_ms;
    let shdr_name = shadow_cfg.shadow_header.clone();
    let shdr_val = shadow_cfg.shadow_header_value.clone();
    let log_responses = shadow_cfg.log_responses;
    let backend_name = shadow_cfg.backend.clone();
    let method = method.clone();
    let headers = headers.clone();
    let host = host.to_owned();
    let add_headers = route_add_headers.clone();

    tokio::task::spawn(async move {
        let start = std::time::Instant::now();

        let mut req_builder = Request::builder().method(method).uri(&shadow_url);

        if let Some(h) = req_builder.headers_mut() {
            // Copy original headers, stripping hop-by-hop and internal proxy tags
            for (name, value) in headers.iter() {
                let n = name.as_str().to_lowercase();
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
                    "x-tls-early-data",
                    "x-forwarded-for",
                    "x-forwarded-proto",
                    "x-forwarded-port",
                    "x-real-ip",
                ]
                .contains(&n.as_str())
                {
                    h.insert(name.clone(), value.clone());
                }
            }
            // Correct Host for shadow backend
            if let Ok(v) = HeaderValue::from_str(&host) {
                h.insert(header::HOST, v);
            }
            // Forwarded-for headers
            if let Ok(v) = HeaderValue::from_str(&client_addr.ip().to_string()) {
                h.insert("x-real-ip", v.clone());
                h.insert("x-forwarded-for", v);
            }
            h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
            if let Ok(v) = HeaderValue::from_str(&proxy_port.to_string()) {
                h.insert("x-forwarded-port", v);
            }
            // Route add_headers
            for (key, value) in &add_headers {
                if let (Ok(hn), Ok(hv)) = (
                    header::HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    h.insert(hn, hv);
                }
            }
            // Shadow marker header — configurable name and value
            if let (Ok(hn), Ok(hv)) = (
                header::HeaderName::from_bytes(shdr_name.as_bytes()),
                HeaderValue::from_str(&shdr_val),
            ) {
                h.insert(hn, hv);
            }
        }

        let shadow_req = match req_builder.body(Body::from(body_bytes)) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Shadow request build failed for backend '{}': {}",
                    backend_name, e
                );
                return;
            }
        };

        let result = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
            if shadow_use_https {
                https_client.request(shadow_req).await
            } else {
                http_client.request(shadow_req).await
            }
        })
        .await;

        match result {
            Ok(Ok(resp)) => {
                if log_responses {
                    info!(
                        "Shadow → '{}' status={} latency={}ms",
                        backend_name,
                        resp.status().as_u16(),
                        start.elapsed().as_millis()
                    );
                }
            }
            Ok(Err(e)) => {
                warn!("Shadow request to '{}' failed: {}", backend_name, e);
            }
            Err(_) => {
                warn!(
                    "Shadow request to '{}' timed out after {}ms",
                    backend_name, timeout_ms
                );
            }
        }
    });
}

/// Run HTTP redirect server (port 80 → HTTPS) with ACME HTTP-01 challenge support
pub async fn run_http_redirect_server<S: std::hash::BuildHasher + Send + Sync + 'static>(
    port: u16,
    https_port: u16,
    // When false, plain-HTTP requests are refused instead of redirected. ACME
    // challenges are still answered either way, so certificate renewal does not
    // depend on this being on.
    redirect_to_https: bool,
    acme_challenges: Option<
        Arc<
            parking_lot::RwLock<
                std::collections::HashMap<String, crate::acme::PendingChallenge, S>,
            >,
        >,
    >,
    // AUD-02: Allowed hostnames for the HTTPS redirect.  Requests whose Host header
    // is not in this list receive 400 Bad Request rather than being blindly redirected,
    // preventing open-redirect attacks where an attacker supplies Host: evil.com.
    // An empty Vec disables the check (backward-compatible default).
    allowed_domains: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let https_port_clone = https_port;

    let has_acme = acme_challenges.is_some();
    let allowed_domains_lower: Vec<String> = allowed_domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();

    let app = Router::new().fallback(move |Host(host): Host, uri: Uri| {
        let challenges = acme_challenges.clone();
        let permitted = allowed_domains_lower.clone();
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

            // AUD-02: Validate Host header against allowed domains before redirecting.
            // This prevents open-redirect attacks where an attacker sends
            //   GET / HTTP/1.1
            //   Host: evil.com
            // and the server responds with Location: https://evil.com/...
            if !permitted.is_empty() {
                let host_lower = host.to_ascii_lowercase();
                // Strip port suffix if present (e.g. "example.com:80" → "example.com")
                let host_name = host_lower.split(':').next().unwrap_or(host_lower.as_str());
                if !permitted.iter().any(|d| d.as_str() == host_name) {
                    warn!(
                        "HTTP redirect: rejected request with unknown Host header: {} — \
                         not in allowed_domains list",
                        host_lower
                    );
                    return axum::http::StatusCode::BAD_REQUEST.into_response();
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

            if !redirect_to_https {
                // The operator has turned the redirect off. Answering with a 301
                // anyway would make the setting meaningless, and quietly serving
                // the request over plain HTTP would be worse — so refuse.
                return (
                    StatusCode::BAD_REQUEST,
                    "This server does not serve plain HTTP. Use HTTPS.",
                )
                    .into_response();
            }

            Redirect::permanent(&https_url).into_response()
        }
    });

    let addr: SocketAddr = format!("[::]:{}", port)
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], port)));
    info!(
        "🔀 Starting HTTP→HTTPS redirect server on {} (ACME challenge support: {})",
        addr, has_acme
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Unconditionally, unlike the proxy listeners' `server.tcp_nodelay`: this
    // server answers redirects and ACME challenges, so there is never a stream
    // for Nagle to coalesce and its only possible effect is a delayed-ACK wait.
    axum::serve(listener, app.into_make_service())
        .tcp_nodelay(true)
        .await?;

    Ok(())
}
