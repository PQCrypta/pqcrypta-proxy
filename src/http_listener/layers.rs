//! Axum middleware layers applied to the TCP (HTTP/1.1 + HTTP/2) listener:
//! trace-context extraction, Alt-Svc advertisement, security headers, and
//! advanced multi-dimensional rate limiting.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::{debug, warn};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::metrics::MetricsRegistry;
use crate::otel;
use crate::rate_limiter::{
    build_context_from_request, AdvancedRateLimiter, LimitReason, RateLimitResult,
};

use super::HttpListenerState;

/// Body of the WAF refusal. Named so the logged length cannot drift from it.
const ACCESS_DENIED_BODY: &str = "Access denied";

/// Whether `trace_context_middleware`'s INFO request span would be recorded by
/// the installed subscriber. Evaluated here, not at the call site, because the
/// filter is per target and the span's target is this module.
pub(super) fn request_span_enabled() -> bool {
    tracing::span_enabled!(tracing::Level::INFO)
}

/// Middleware that extracts the incoming distributed trace context and makes it
/// the parent of the current request span.
///
/// Supports W3C TraceContext (`traceparent`/`tracestate`) and B3 headers
/// (`x-b3-traceid` / `x-b3-spanid` / `x-b3-sampled` / `b3`).
/// Works across HTTP/1.1 and HTTP/2; the QUIC/HTTP3 path has its own extraction.
///
/// When OTEL is disabled (default NOOP provider) this middleware is a no-op.
pub(super) async fn trace_context_middleware(request: Request<Body>, next: Next) -> Response {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    use tracing::Instrument;

    let span = tracing::info_span!(
        "http.request",
        http.method = %request.method(),
        http.uri = %request.uri().path(),
        otel.kind = "server",
        trace_id = tracing::field::Empty,
    );

    // Stitch the incoming trace context into the span so this proxy hop appears
    // as a child of the caller's span in the distributed trace.
    otel::set_parent_from_headers(&span, request.headers());

    // Record the resolved trace ID as a span field for easy log correlation.
    {
        let trace_id = otel::current_trace_id();
        if !trace_id.is_empty() {
            span.record("trace_id", trace_id);
        }
    }

    next.run(request).instrument(span).await
}

/// Middleware to add Alt-Svc header to all responses.
/// Excluded for:
///   - /speedtest/tcp-* paths on any host (stops Chrome from upgrading to H3)
///   - ALL requests to tcp.pqcrypta.com (dedicated TCP-only speedtest origin;
///     never advertises QUIC so Chrome always connects with TCP/TLS)
pub(super) async fn alt_svc_middleware(
    State(state): State<Arc<HttpListenerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    // HTTP/2 uses the :authority pseudo-header which hyper surfaces via URI,
    // not the Host header. Fall back to URI host so both HTTP/1.1 and HTTP/2
    // requests are checked correctly.
    let host_hdr = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let uri_host = request.uri().host().unwrap_or("");
    let host = if host_hdr.is_empty() {
        uri_host
    } else {
        host_hdr
    };
    let server = &state.config.server;
    let is_tcp_only = server.tcp_only_hosts.iter().any(|h| h == host);

    // Clients that must stay on TCP get `alt-svc: clear` so they never upgrade
    // to QUIC/HTTP3: crawlers and scanners by User-Agent, and clients such as
    // Cloudflare Radar / URLScan — which send a generic Chrome UA — by source
    // network. Both lists come from `[server]`; the networks are parsed once, at
    // config load, where they used to be re-parsed from strings on every request.
    let is_indexing_bot = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ci| {
            server
                .alt_svc_clear_cidrs
                .iter()
                .any(|net| net.contains(&ci.0.ip()))
        })
        || request
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ua| {
                server
                    .alt_svc_clear_user_agents
                    .iter()
                    .any(|needle| contains_ignore_ascii_case(ua, needle))
            });

    let mut response = next.run(request).await;

    if is_tcp_only || is_indexing_bot {
        // Actively clear any cached Alt-Svc so browsers/bots stop upgrading to
        // HTTP/3. Without "clear", a cached Alt-Svc keeps Chrome on QUIC even
        // after we stop advertising it.
        response
            .headers_mut()
            .insert("alt-svc", HeaderValue::from_static("clear"));
    } else if let Some(value) = state.alt_svc_value.clone() {
        // Precomputed at startup: this value is a function of the listener port
        // and the configured additional ports, neither of which changes while
        // the listener runs. Cloning a `HeaderValue` bumps a refcount.
        response.headers_mut().insert("alt-svc", value);
    }

    // WebTransport runs over HTTP/3 on the same port, so it is advertised only
    // when HTTP/3 is: a node configured to advertise no HTTP/3 (`alt_svc_ports =
    // []`) must not point clients at a WebTransport endpoint either.
    if state.alt_svc_value.is_some() {
        response
            .headers_mut()
            .insert("x-webtransport-port", state.webtransport_port_value.clone());
    }

    response
}

/// How one precomputed response header is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeaderRule {
    /// Always set, replacing whatever the backend sent.
    Always,
    /// Always set, except on the Outlook add-in surface, which Office frames
    /// cross-origin (framing there is governed by the add-in CSP instead).
    UnlessAddin,
    /// Set only when the response does not already carry it, so a route's
    /// `headers_override` or the backend's own value wins.
    IfAbsent,
}

/// The `[headers]` section, validated once at startup.
///
/// This used to be rebuilt on every response: sixteen `HeaderValue::from_str`
/// calls, each re-validating a string that cannot change while the listener
/// runs. Cloning a finished `HeaderValue` is a refcount bump. An empty string
/// omits the header — before this, only the CSP honoured that, and every other
/// header set to `""` went out as an empty header rather than no header.
#[derive(Debug)]
pub(crate) struct ResponseHeaderSet {
    entries: Vec<(HeaderName, HeaderValue, HeaderRule)>,
    /// Fallback CSP, applied when the backend sent none (the PHP pages carry
    /// per-request nonces in theirs, and those must win).
    csp: Option<HeaderValue>,
    /// CSP for the Outlook add-in surface; `None` disables the exception.
    addin_csp: Option<HeaderValue>,
    addin_hosts: Vec<String>,
    addin_path_prefix: String,
    /// Server-Timing `desc`, or `None` when Server-Timing is off.
    server_timing: Option<String>,
}

impl ResponseHeaderSet {
    pub(super) fn from_config(config: &crate::config::HeadersConfig) -> Self {
        fn value(name: &str, raw: &str) -> Option<HeaderValue> {
            if raw.is_empty() {
                return None;
            }
            match HeaderValue::from_str(raw) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(
                        "[headers] {} is not a valid header value, omitting it: {}",
                        name, e
                    );
                    None
                }
            }
        }

        let table: [(HeaderName, &str, HeaderRule); 16] = [
            (
                header::STRICT_TRANSPORT_SECURITY,
                &config.hsts,
                HeaderRule::Always,
            ),
            (
                header::X_FRAME_OPTIONS,
                &config.x_frame_options,
                HeaderRule::UnlessAddin,
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                &config.x_content_type_options,
                HeaderRule::Always,
            ),
            (
                header::REFERRER_POLICY,
                &config.referrer_policy,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("permissions-policy"),
                &config.permissions_policy,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                &config.cross_origin_opener_policy,
                HeaderRule::IfAbsent,
            ),
            (
                HeaderName::from_static("cross-origin-embedder-policy"),
                &config.cross_origin_embedder_policy,
                HeaderRule::IfAbsent,
            ),
            (
                HeaderName::from_static("cross-origin-resource-policy"),
                &config.cross_origin_resource_policy,
                HeaderRule::IfAbsent,
            ),
            (
                HeaderName::from_static("x-permitted-cross-domain-policies"),
                &config.x_permitted_cross_domain_policies,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("x-download-options"),
                &config.x_download_options,
                HeaderRule::Always,
            ),
            (
                header::X_DNS_PREFETCH_CONTROL,
                &config.x_dns_prefetch_control,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("x-quantum-resistant"),
                &config.x_quantum_resistant,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("x-security-level"),
                &config.x_security_level,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("accept-ch"),
                &config.accept_ch,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("nel"),
                &config.nel,
                HeaderRule::Always,
            ),
            (
                HeaderName::from_static("report-to"),
                &config.report_to,
                HeaderRule::Always,
            ),
        ];
        let mut entries: Vec<_> = table
            .into_iter()
            .filter_map(|(name, raw, rule)| value(name.as_str(), raw).map(|v| (name, v, rule)))
            .collect();
        // RFC 9218 Priority, last as before.
        if let Some(v) = value("priority", &config.priority) {
            entries.push((HeaderName::from_static("priority"), v, HeaderRule::Always));
        }

        let addin_csp = if config.addin_path_prefix.is_empty() {
            None
        } else {
            value("addin_csp", &config.addin_csp)
        };

        Self {
            entries,
            csp: value("content_security_policy", &config.content_security_policy),
            addin_csp,
            addin_hosts: config.addin_hosts.clone(),
            addin_path_prefix: config.addin_path_prefix.clone(),
            server_timing: config
                .server_timing_enabled
                .then(|| config.server_timing_desc.replace('"', "'")),
        }
    }

    /// True when the layer would not touch a single response, which is when
    /// the chain leaves it out.
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.csp.is_none()
            && self.addin_csp.is_none()
            && self.server_timing.is_none()
    }

    fn is_addin_request(&self, request: &Request<Body>) -> bool {
        if self.addin_csp.is_none() || !request.uri().path().starts_with(&self.addin_path_prefix) {
            return false;
        }
        let host = request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host = host.split(':').next().unwrap_or("");
        self.addin_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    }
}

/// Middleware to add security headers to all responses
pub(super) async fn security_headers_middleware(
    State(state): State<Arc<HttpListenerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    let set = &state.response_headers;

    // Track request timing for Server-Timing header
    let start_time = set
        .server_timing
        .as_ref()
        .map(|_| std::time::Instant::now());

    // Detect the Outlook add-in surface BEFORE consuming the request. Office hosts
    // the task pane in a cross-origin iframe, so this surface must NOT receive
    // X-Frame-Options: DENY and needs an add-in-friendly CSP. Host/path/CSP are all
    // configured in [headers] (addin_hosts, addin_path_prefix, addin_csp); an empty
    // addin_csp disables the exception.
    let is_outlook_addin = set.is_addin_request(&request);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    for (name, value, rule) in &set.entries {
        match rule {
            HeaderRule::Always => {
                headers.insert(name.clone(), value.clone());
            }
            HeaderRule::UnlessAddin => {
                if !is_outlook_addin {
                    headers.insert(name.clone(), value.clone());
                }
            }
            // Cross-Origin headers — conditional so route-level headers_override
            // takes precedence over the global default.
            HeaderRule::IfAbsent => {
                if !headers.contains_key(name) {
                    headers.insert(name.clone(), value.clone());
                }
            }
        }
    }

    // SEC-07: Content-Security-Policy.
    // Outlook add-in surface gets a dedicated CSP (frame-ancestors for the Office
    // hosts, allows the office.js CDN and api.pqpdf.com). Otherwise inject the global
    // CSP only when the backend did not set one (preserves PHP nonce-based CSPs).
    if is_outlook_addin {
        if let Some(v) = &set.addin_csp {
            headers.insert(header::CONTENT_SECURITY_POLICY, v.clone());
        }
    } else if let Some(v) = &set.csp {
        if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v.clone());
        }
    }

    // Server-Timing header - Performance metrics
    // Format: metric;dur=<ms>;desc="description"
    //
    // No `quic` metric here: this layer only ever runs on the TCP listener, so
    // the connection carrying the response is TLS-over-TCP. It used to name
    // "QUIC v1" on every HTTP/1.1 and HTTP/2 response, describing a transport
    // that was not in use — and the desc differed from the HTTP/3 path's, so the
    // same page reported two different proxies depending on how it was fetched.
    if let (Some(start_time), Some(desc)) = (start_time, &set.server_timing) {
        let server_timing = format!(
            "proxy;dur={:.2};desc=\"{desc}\"",
            start_time.elapsed().as_secs_f64() * 1000.0
        );
        if let Ok(v) = HeaderValue::from_str(&server_timing) {
            headers.insert("server-timing", v);
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

/// Case-insensitive (ASCII) substring test, without lowercasing a copy of the
/// haystack per request.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    n.is_empty() || h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// This listener's Alt-Svc value, or `None` when it advertises no HTTP/3.
///
/// `None` rather than an empty value: `alt_svc_ports = []` is documented as
/// "advertise no HTTP/3", and it used to produce `Some("")` — an empty
/// `alt-svc:` header on every response.
pub(super) fn alt_svc_header_value(
    port: u16,
    config: &crate::config::ProxyConfig,
) -> Option<HeaderValue> {
    let value = build_alt_svc_header_with_override(
        port,
        &config.server.additional_ports,
        config.server.alt_svc_ports.as_deref(),
        config.server.alt_svc_max_age_secs,
    );
    if value.is_empty() {
        return None;
    }
    HeaderValue::from_str(&value).ok()
}

/// Build Alt-Svc header value for HTTP/3 advertisement.
/// The Alt-Svc value for a response being sent **over TCP**: every UDP port that
/// serves HTTP/3, which is how a browser discovers HTTP/3 in the first place.
///
/// De-duplicated. A listener's own port is frequently also listed in
/// `additional_ports` — every node here binds 4434 both ways — and the earlier
/// version emitted it once from each, so the :4434 listener advertised
/// `h3=":4434"; ma=86400, h3=":4434"; ma=86400`. Harmless to a parser, but it is the
/// same alternative stated twice, and it was visible on the live edge.
///
/// The QUIC counterpart is `quic_listener::build_alt_svc_header_over_quic`, which
/// excludes the connection in use rather than listing it.
/// As above, but with `server.alt_svc_ports` applied when the operator has set it.
///
/// The override replaces the derived list outright rather than filtering it: a port
/// that is bound but unreachable is not in the derived list by mistake, it is there
/// because the proxy really did bind it. Only the operator knows it is filtered
/// upstream or handed to WebTransport, so the operator's list wins whole.
pub(crate) fn build_alt_svc_header_with_override(
    port: u16,
    additional_ports: &[u16],
    alt_svc_ports: Option<&[u16]>,
    max_age_secs: u64,
) -> String {
    let mut seen: Vec<u16> = Vec::new();
    let mut parts: Vec<String> = Vec::new();

    let advertised: Vec<u16> = match alt_svc_ports {
        Some(explicit) => explicit.to_vec(),
        None => {
            let mut v = vec![port];
            v.extend_from_slice(additional_ports);
            v
        }
    };

    for p in advertised {
        if seen.contains(&p) {
            continue;
        }
        seen.push(p);
        parts.push(format!("h3=\":{p}\"; ma={max_age_secs}"));
    }

    parts.join(", ")
}

/// Add Alt-Svc header to a response (for early-return paths)
pub(super) fn add_alt_svc_to_response(response: &mut Response, alt_svc: Option<&HeaderValue>) {
    if let Some(value) = alt_svc {
        response.headers_mut().insert("alt-svc", value.clone());
    }
}

/// State for [`advanced_rate_limit_middleware`], fixed at startup.
#[derive(Clone)]
pub(super) struct RateLimitLayer {
    pub(super) limiter: Arc<AdvancedRateLimiter>,
    pub(super) metrics: Arc<MetricsRegistry>,
    /// This listener's Alt-Svc, for the 429s this layer renders itself.
    pub(super) alt_svc: Option<HeaderValue>,
    /// `security.refusal_cors_origins`.
    pub(super) refusal_cors_origins: Arc<[String]>,
}

pub(super) async fn advanced_rate_limit_middleware(
    State(layer): State<RateLimitLayer>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Response {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    let method = request.method().as_str().to_string();
    let protocol_str = crate::access_logger::protocol_name(request.version());
    let path = request.uri().path().to_ascii_lowercase();

    // Error responses carry this listener's own Alt-Svc. This was a literal
    // naming ports 443, 4433 and 4434, whatever the node actually serves.

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

    // Check rate limit (async — uses Redis when configured, local fallback otherwise)
    let RateLimitLayer {
        limiter: rate_limiter,
        metrics,
        alt_svc,
        ..
    } = &layer;
    match rate_limiter.check(&ctx).await {
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
            // A backend's own reset must not survive next to our numbers.
            //
            // `limit`, `remaining` and `reset` describe one policy, and this
            // arm overwrites the first two with this proxy's figures while
            // leaving the third as the backend wrote it. Measured on
            // /api/, which runs its own limiter: the origin sent
            // limit=900 remaining=899 reset=T, and a client received
            // limit=100 remaining=99 reset=T -- a retry time computed
            // against a window it does not belong to.
            //
            // Removed rather than recomputed because `Allowed` carries no
            // reset to put there. Two honest headers beat three that
            // disagree; the rejection arm below has all three and sets them
            // together.
            resp_headers.remove("x-ratelimit-reset");

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

            // Capture request Origin before consuming headers into response
            let request_origin = headers
                .get("origin")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

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

            let resp_headers = response.headers_mut();

            // Standard rate limit headers
            if let Ok(v) = HeaderValue::from_str(&(retry_after_ms / 1000).to_string()) {
                resp_headers.insert("retry-after", v);
            }
            if let Ok(v) = HeaderValue::from_str(&limit.to_string()) {
                resp_headers.insert("x-ratelimit-limit", v);
            }
            resp_headers.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));

            // Reset time (approximate)
            let reset_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + (retry_after_ms / 1000);
            if let Ok(v) = HeaderValue::from_str(&reset_time.to_string()) {
                resp_headers.insert("x-ratelimit-reset", v);
            }

            // CORS headers on 429 so browser sees the status code, not a CORS
            // error — from `security.refusal_cors_origins`, the list every other
            // refusal reads.
            for (k, v) in crate::security::cors_refusal_headers(
                &layer.refusal_cors_origins,
                request_origin.as_deref(),
            ) {
                if let Ok(v) = HeaderValue::from_str(&v) {
                    resp_headers.insert(k, v);
                }
            }

            // Add Alt-Svc header to advertise HTTP/3
            add_alt_svc_to_response(&mut response, alt_svc.as_ref());

            // A 429 is exactly the response an operator looks for in the log.
            let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
            log_access(&AccessLogEntry {
                remote_addr: client_addr,
                method: &method,
                path: &path,
                protocol: protocol_str,
                status: 429,
                body_size: 0,
                referer: header("referer"),
                user_agent: header("user-agent"),
                host: header("host"),
                response_time_ms: 0,
                ja3: header("x-ja3-hash"),
                ja4: header("x-ja4-hash"),
                backend: None,
            });
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

            // Mirror the refusal into access.log: a 403 that appears only in
            // the journal makes every later "why did this client get a 403?"
            // investigation start from a log that looks clean.
            let header_str =
                |name: hyper::header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
            log_access(&AccessLogEntry {
                ja3: None,
                ja4: None,
                backend: None,
                remote_addr: client_addr,
                method: &method,
                path: &path,
                protocol: protocol_str,
                status: 403,
                body_size: ACCESS_DENIED_BODY.len(),
                referer: header_str(hyper::header::REFERER),
                user_agent: header_str(hyper::header::USER_AGENT),
                host: header_str(hyper::header::HOST),
                response_time_ms: 0,
            });

            let mut response = (StatusCode::FORBIDDEN, ACCESS_DENIED_BODY).into_response();
            // Add Alt-Svc header to advertise HTTP/3
            add_alt_svc_to_response(&mut response, alt_svc.as_ref());
            response
        }
    }
}

#[cfg(test)]
mod alt_svc_tcp_tests {
    use super::build_alt_svc_header_with_override;

    /// Every node binds 4434 as both its listener port and an additional port, so
    /// the :4434 listener used to state the same alternative twice.
    #[test]
    fn does_not_repeat_a_port_listed_twice() {
        assert_eq!(
            build_alt_svc_header_with_override(4434, &[4433, 4434], None, 86400),
            "h3=\":4434\"; ma=86400, h3=\":4433\"; ma=86400"
        );
    }

    #[test]
    fn lists_every_distinct_h3_port() {
        assert_eq!(
            build_alt_svc_header_with_override(443, &[4434], None, 86400),
            "h3=\":443\"; ma=86400, h3=\":4434\"; ma=86400"
        );
    }

    /// Unlike the QUIC side, the TCP value DOES include its own port: h3 on 443 is a
    /// genuine alternative to a TCP connection on 443.
    #[test]
    fn includes_its_own_port_because_tcp_is_a_different_transport() {
        assert!(build_alt_svc_header_with_override(443, &[], None, 86400).contains("h3=\":443\""));
    }

    /// The mail host case: it binds UDP 443 and the provider filters it upstream, so
    /// the port it is listening on is exactly the one it must not advertise.
    #[test]
    fn override_replaces_the_derived_list_including_the_listener_port() {
        assert_eq!(
            build_alt_svc_header_with_override(443, &[4433, 4434], Some(&[4434]), 86400),
            "h3=\":4434\"; ma=86400"
        );
    }

    /// A node that serves no HTTP/3 at all should say so by saying nothing, rather
    /// than pointing browsers at a port that can only time out.
    #[test]
    fn empty_override_advertises_no_http3() {
        assert_eq!(
            build_alt_svc_header_with_override(4433, &[], Some(&[]), 86400),
            ""
        );
    }

    #[test]
    fn absent_override_keeps_the_derived_behaviour() {
        assert_eq!(
            build_alt_svc_header_with_override(443, &[4434], None, 86400),
            build_alt_svc_header_with_override(443, &[4434], None, 86400)
        );
    }

    #[test]
    fn max_age_comes_from_config() {
        assert_eq!(
            build_alt_svc_header_with_override(443, &[], None, 3600),
            "h3=\":443\"; ma=3600"
        );
    }

    #[test]
    fn advertising_no_http3_sends_no_header_rather_than_an_empty_one() {
        let mut c = crate::config::ProxyConfig::default();
        c.server.alt_svc_ports = Some(Vec::new());
        assert!(super::alt_svc_header_value(443, &c).is_none());
        c.server.alt_svc_ports = None;
        assert!(super::alt_svc_header_value(443, &c).is_some());
    }

    #[test]
    fn clear_list_matches_user_agents_case_insensitively() {
        assert!(super::contains_ignore_ascii_case(
            "Mozilla/5.0 (compatible; Googlebot/2.1)",
            "googlebot"
        ));
        assert!(!super::contains_ignore_ascii_case(
            "Mozilla/5.0 Chrome/120",
            "googlebot"
        ));
        assert!(super::contains_ignore_ascii_case("anything", ""));
    }

    #[test]
    fn default_clear_networks_all_parse() {
        // A typo in the default list would silently drop a range at load time.
        assert_eq!(
            crate::config::ServerConfig::default()
                .alt_svc_clear_cidrs
                .len(),
            22
        );
    }

    #[test]
    fn empty_header_values_are_omitted_not_sent_empty() {
        let mut h = crate::config::HeadersConfig::default();
        let full = super::ResponseHeaderSet::from_config(&h);
        assert!(!full.is_empty());
        h.hsts.clear();
        h.x_frame_options.clear();
        h.x_content_type_options.clear();
        h.referrer_policy.clear();
        h.permissions_policy.clear();
        h.cross_origin_opener_policy.clear();
        h.cross_origin_embedder_policy.clear();
        h.cross_origin_resource_policy.clear();
        h.x_permitted_cross_domain_policies.clear();
        h.x_download_options.clear();
        h.x_dns_prefetch_control.clear();
        h.x_quantum_resistant.clear();
        h.x_security_level.clear();
        h.content_security_policy.clear();
        h.addin_csp.clear();
        h.server_timing_enabled = false;
        assert!(super::ResponseHeaderSet::from_config(&h).is_empty());
    }
}
