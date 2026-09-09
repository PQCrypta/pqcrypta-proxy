//! Axum middleware layers applied to the TCP (HTTP/1.1 + HTTP/2) listener:
//! trace-context extraction, Alt-Svc advertisement, security headers, and
//! advanced multi-dimensional rate limiting.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
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
    let is_tcp_only = state.config.server.tcp_only_hosts.iter().any(|h| h == host);

    // Search engine indexing bots and security scanners must use HTTP/1.1 —
    // send alt-svc: clear so they never upgrade to QUIC/HTTP3, which causes
    // connection errors on crawl or empty MIME types on security scans.
    //
    // Cloudflare Radar / URLScan uses a generic Chrome UA so it cannot be
    // detected by user-agent alone — detect by source IP against Cloudflare's
    // published IPv4/IPv6 infrastructure ranges instead.
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let is_cloudflare_ip = client_ip
        .map(|ip| {
            use std::net::IpAddr;
            use std::str::FromStr;
            // Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips/)
            const CF_V4: &[&str] = &[
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "141.101.64.0/18",
                "108.162.192.0/18",
                "190.93.240.0/20",
                "188.114.96.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                "162.158.0.0/15",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/13",
                "131.0.72.0/22",
            ];
            // Cloudflare published IPv6 ranges
            const CF_V6: &[&str] = &[
                "2400:cb00::/32",
                "2606:4700::/32",
                "2803:f800::/32",
                "2405:b500::/32",
                "2405:8100::/32",
                "2a06:98c0::/29",
                "2c0f:f248::/32",
            ];
            match ip {
                IpAddr::V4(v4) => CF_V4.iter().any(|cidr| {
                    ipnet::Ipv4Net::from_str(cidr)
                        .map(|net| net.contains(&v4))
                        .unwrap_or(false)
                }),
                IpAddr::V6(v6) => CF_V6.iter().any(|cidr| {
                    ipnet::Ipv6Net::from_str(cidr)
                        .map(|net| net.contains(&v6))
                        .unwrap_or(false)
                }),
            }
        })
        .unwrap_or(false);

    let is_indexing_bot = is_cloudflare_ip
        || request
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|ua| {
                let ua = ua.to_lowercase();
                ua.contains("googlebot")
                || ua.contains("adsbot-google")
                || ua.contains("google-inspectiontool")
                || ua.contains("googleother")
                || ua.contains("bingbot")
                || ua.contains("msnbot")
                || ua.contains("yandexbot")
                || ua.contains("baiduspider")
                || ua.contains("duckduckbot")
                || ua.contains("slurp")
                || ua.contains("applebot")
                || ua.contains("semrushbot")
                || ua.contains("ahrefsbot")
                || ua.contains("dotbot")
                || ua.contains("sogou")
                || ua.contains("exabot")
                || ua.contains("facebot")
                || ua.contains("ia_archiver")
                // Security/TLS scanners — keep on TCP/TLS, not HTTP/3
                || ua.contains("ssllabs")
                || ua.contains("qualys")
                || ua.contains("ssl-pulse")
            })
            .unwrap_or(false);

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

    // Add WebTransport port header
    response
        .headers_mut()
        .insert("x-webtransport-port", state.webtransport_port_value.clone());

    response
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
    // Track request timing for Server-Timing header
    let start_time = std::time::Instant::now();

    // Detect the Outlook add-in surface BEFORE consuming the request. Office hosts
    // the task pane in a cross-origin iframe, so this surface must NOT receive
    // X-Frame-Options: DENY and needs an add-in-friendly CSP. Host/path/CSP are all
    // configured in [headers] (addin_hosts, addin_path_prefix, addin_csp); an empty
    // addin_csp disables the exception.
    let is_outlook_addin = {
        let hc = &state.config.headers;
        if hc.addin_csp.is_empty() || hc.addin_path_prefix.is_empty() {
            false
        } else {
            let path = request.uri().path();
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            path.starts_with(&hc.addin_path_prefix)
                && hc.addin_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host))
        }
    };

    let mut response = next.run(request).await;

    // Calculate processing time
    let processing_time = start_time.elapsed();

    let headers = response.headers_mut();
    let config = &state.config.headers;

    // HSTS
    if let Ok(v) = HeaderValue::from_str(&config.hsts) {
        headers.insert(header::STRICT_TRANSPORT_SECURITY, v);
    }

    // X-Frame-Options — skipped for the Outlook add-in surface, which is framed
    // cross-origin by Office (framing is governed there by CSP frame-ancestors).
    if !is_outlook_addin {
        if let Ok(v) = HeaderValue::from_str(&config.x_frame_options) {
            headers.insert(header::X_FRAME_OPTIONS, v);
        }
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

    // Cross-Origin headers — conditional so route-level headers_override takes precedence.
    // A route that sets COOP/COEP/CORP in headers_override will have already populated
    // these in the response; skip the global default to avoid overwriting per-route values.
    if !headers.contains_key("cross-origin-opener-policy") {
        if let Ok(v) = HeaderValue::from_str(&config.cross_origin_opener_policy) {
            headers.insert("cross-origin-opener-policy", v);
        }
    }
    if !headers.contains_key("cross-origin-embedder-policy") {
        if let Ok(v) = HeaderValue::from_str(&config.cross_origin_embedder_policy) {
            headers.insert("cross-origin-embedder-policy", v);
        }
    }
    if !headers.contains_key("cross-origin-resource-policy") {
        if let Ok(v) = HeaderValue::from_str(&config.cross_origin_resource_policy) {
            headers.insert("cross-origin-resource-policy", v);
        }
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

    // SEC-07: Content-Security-Policy.
    // Outlook add-in surface gets a dedicated CSP (frame-ancestors for the Office
    // hosts, allows the office.js CDN and api.pqpdf.com). Otherwise inject the global
    // CSP only when the backend did not set one (preserves PHP nonce-based CSPs).
    if is_outlook_addin {
        if let Ok(v) = HeaderValue::from_str(&config.addin_csp) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
    } else if !config.content_security_policy.is_empty()
        && !headers.contains_key(header::CONTENT_SECURITY_POLICY)
    {
        if let Ok(v) = HeaderValue::from_str(&config.content_security_policy) {
            headers.insert(header::CONTENT_SECURITY_POLICY, v);
        }
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
    //
    // No `quic` metric here: this layer only ever runs on the TCP listener, so
    // the connection carrying the response is TLS-over-TCP. It used to name
    // "QUIC v1" on every HTTP/1.1 and HTTP/2 response, describing a transport
    // that was not in use — and the desc differed from the HTTP/3 path's, so the
    // same page reported two different proxies depending on how it was fetched.
    if config.server_timing_enabled {
        let server_timing = format!(
            "proxy;dur={:.2};desc=\"PQ Crypta Processing\"",
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
pub(super) fn build_alt_svc_header(port: u16, additional_ports: &[u16]) -> String {
    let mut parts = vec![format!("h3=\":{}\"; ma=86400", port)];
    for p in additional_ports {
        parts.push(format!("h3=\":{}\"; ma=86400", p));
    }
    parts.join(", ")
}

/// Add Alt-Svc header to a response (for early-return paths)
pub(super) fn add_alt_svc_to_response(response: &mut Response, alt_svc: &str) {
    if let Ok(value) = HeaderValue::from_str(alt_svc) {
        response.headers_mut().insert("alt-svc", value);
    }
}

pub(super) async fn advanced_rate_limit_middleware(
    State((rate_limiter, metrics)): State<(Arc<AdvancedRateLimiter>, Arc<MetricsRegistry>)>,
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

    // Check rate limit (async — uses Redis when configured, local fallback otherwise)
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

            // CORS headers on 429 so browser sees the status code, not a CORS error
            const ALLOWED_ORIGINS: &[&str] = &[
                "https://pqcrypta.com",
                "https://www.pqcrypta.com",
                "https://pqpdf.com",
                "https://www.pqpdf.com",
            ];
            let origin_value = request_origin.as_deref().unwrap_or("");
            if ALLOWED_ORIGINS.contains(&origin_value) {
                if let Ok(v) = HeaderValue::from_str(origin_value) {
                    resp_headers.insert("access-control-allow-origin", v);
                }
                resp_headers.insert(
                    "access-control-allow-credentials",
                    HeaderValue::from_static("true"),
                );
                resp_headers.insert("vary", HeaderValue::from_static("Origin"));
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

            // Mirror the refusal into access.log: a 403 that appears only in
            // the journal makes every later "why did this client get a 403?"
            // investigation start from a log that looks clean.
            let header_str =
                |name: hyper::header::HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
            log_access(&AccessLogEntry {
                remote_addr: client_addr,
                method: &method,
                path: &path,
                protocol: "HTTP/1.1",
                status: 403,
                body_size: 0,
                referer: header_str(hyper::header::REFERER),
                user_agent: header_str(hyper::header::USER_AGENT),
                host: header_str(hyper::header::HOST),
                response_time_ms: 0,
            });

            let mut response = (StatusCode::FORBIDDEN, "Access denied").into_response();
            // Add Alt-Svc header to advertise HTTP/3
            add_alt_svc_to_response(&mut response, alt_svc);
            response
        }
    }
}
