//! The HTTP/3 request pipeline: everything that happens between accepting an
//! h3 stream and writing the response back to it.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http_body_util::BodyExt as _;
use tracing::{debug, error, info, trace, warn};

use crate::access_logger::{log_access, AccessLogEntry};
use crate::cache::{CacheLookup, ResponseCache};
use crate::config::{BackendConfig, BackendType, ProxyConfig};
use crate::http3_features::EarlyHintsState;
use crate::load_balancer::{LoadBalancer, SelectionContext};
use crate::metrics::MetricsRegistry;
use crate::otel;
use crate::proxy::BackendPool;
use crate::rate_limiter::{build_context_from_request, AdvancedRateLimiter, RateLimitResult};
use crate::security::SecurityState;

use super::cors::add_cors_headers_to_builder;
use super::{alt_svc_for_host, resolve_route_policy, QuicListener, SERVER_HEADER};

/// Take whatever the client already sent, so the receive side closes cleanly.
///
/// Used by the in-process responders that write their own body and so cannot
/// use [`respond_and_finish`]. Same reason: finishing a bidirectional stream
/// whose receive side is still open makes h3 reset it, and the client throws
/// away a response it already has.
async fn drain_request<S>(stream: &mut h3::server::RequestStream<S, Bytes>)
where
    S: h3::quic::BidiStream<Bytes>,
{
    while let Ok(Some(_)) = stream.recv_data().await {}
}

/// Send a body-less response and close the stream cleanly.
///
/// The drain is the point. An early return answers without ever reading the
/// request body, which leaves the receive side of the bidirectional stream open;
/// finishing and dropping it there makes h3 reset the stream, and the client
/// discards a response it had already received in full. Over HTTP/3 that made
/// every early return unusable — `curl -L` could not follow a 308 redirect and
/// reported `stream 0 reset by server` on a WAF 403, while the same verdicts on
/// TCP were fine. Proxied responses were never affected because forwarding
/// reads the request body first.
async fn respond_and_finish<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    response: http::Response<()>,
) -> anyhow::Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    stream.send_response(response).await?;
    // Whatever the client already sent, take it: a GET usually has nothing and
    // this returns immediately. Errors are ignored because a client that has
    // already gone away is not a failure of this response.
    while let Ok(Some(_)) = stream.recv_data().await {}
    stream.finish().await?;
    Ok(())
}

impl QuicListener {
    /// Handle a single HTTP/3 request
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_h3_request<S>(
        mut stream: h3::server::RequestStream<S, Bytes>,
        mut request: http::Request<()>,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: Arc<SecurityState>,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        handshake: Arc<crate::tls_acceptor::HandshakeFacts>,
        fingerprint: Arc<crate::fingerprint::FingerprintResult>,
        static_headers: Arc<HeaderMap>,
    ) -> anyhow::Result<()>
    where
        S: h3::quic::BidiStream<Bytes>,
    {
        let start_time = std::time::Instant::now();

        // Establish the connection-derived headers before anything reads them.
        //
        // This has to happen here, not at forwarding time. `security.evaluate`
        // enforces the per-route JA3 allowlist by reading `x-ja3-hash` off this
        // request, and on this path nothing ever set it — so the allowlist was
        // matching whatever the *client* chose to send, which a client wanting
        // past it would simply set to an allowed value. The TCP listeners avoid
        // that by overwriting these headers before the router runs; this does
        // the same.
        //
        // Strip first, then set: a field this path cannot observe must come out
        // absent rather than keep the client's value.
        {
            let h = request.headers_mut();
            for name in crate::tls_acceptor::HandshakeFacts::HEADER_NAMES {
                h.remove(name);
            }
            for name in [
                "x-ja3-hash",
                "x-ja4-hash",
                "x-client-name",
                "x-client-type",
                "x-client-cert",
                "x-tls-early-data",
                "x-connection-protocol",
                "x-pqc-enabled",
            ] {
                h.remove(name);
            }

            handshake.inject_headers(h);
            h.insert("x-connection-protocol", HeaderValue::from_static("h3"));

            if let Some(ref v) = fingerprint.ja3_hash {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.insert("x-ja3-hash", v);
                }
            }
            if let Some(ref v) = fingerprint.ja4_hash {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.insert("x-ja4-hash", v);
                }
            }
            if let Some(ref v) = fingerprint.client_name {
                if let Ok(v) = HeaderValue::from_str(v) {
                    h.insert("x-client-name", v);
                }
            }
            if matches!(
                fingerprint.classification,
                Some(crate::security::FingerprintClass::Browser)
            ) {
                h.insert("x-client-type", HeaderValue::from_static("browser"));
            }
        }

        let uri = request.uri();
        // `Cow`: the common request has no query and no path normalisation, and
        // then neither of these allocates at all. Before, every request built a
        // `path` String, an (often empty) `query` String, and a third String
        // concatenating them.
        let path: Cow<'_, str> = if config.server.normalize_paths {
            Cow::Owned(uri.path().to_ascii_lowercase())
        } else {
            Cow::Borrowed(uri.path())
        };
        let path_with_query: Cow<'_, str> = match uri.query() {
            Some(q) => Cow::Owned(format!("{path}?{q}")),
            None => match &path {
                Cow::Borrowed(p) => Cow::Borrowed(p),
                Cow::Owned(p) => Cow::Borrowed(p.as_str()),
            },
        };
        // Borrowed, not owned. `request` is `Request<()>` — the body lives on
        // `stream` — and nothing below mutates it, so these all outlive their
        // uses. Every one of them was an allocation on the hot path.
        let method = request.method().as_str();
        // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback
        // to host header. An authority host is almost always already lowercase,
        // so only pay for the copy when it actually needs changing.
        let host: Option<Cow<'_, str>> = uri
            .authority()
            .map(|a| {
                let h = a.host();
                if h.bytes().any(|b| b.is_ascii_uppercase()) {
                    Cow::Owned(h.to_ascii_lowercase())
                } else {
                    Cow::Borrowed(h)
                }
            })
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .map(Cow::Borrowed)
            });
        let user_agent = request
            .headers()
            .get("user-agent")
            .and_then(|v| v.to_str().ok());
        let referer = request
            .headers()
            .get("referer")
            .and_then(|v| v.to_str().ok());
        let is_health_check = request
            .headers()
            .get("x-health-check-bypass")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "1")
            .unwrap_or(false);

        if !is_health_check {
            metrics.requests.request_start();
        }

        info!(
            "HTTP/3 request: {} {} host={:?} from {}",
            method, path, host, remote_addr
        );

        // Per-request security checks, run from the same `SecurityState` the TCP
        // path uses. Connection-level blocking is enforced at accept time, but the
        // blocklist may grow while a connection is live, so `evaluate` re-checks it
        // per request.
        let ip = remote_addr.ip();
        // Cache for `resolve_route_policy`. The header-pass WAF evaluation and
        // the body-pass inspection both need the same per-route policy, and the
        // body pass used to rebuild it from scratch — repeating the host
        // derivation, an O(routes) `find_route` scan and a clone of every policy
        // field. Resolved lazily so a request that reaches neither pays nothing.
        let mut route_policy: Option<crate::security::RequestPolicy> = None;

        if !security.is_trusted(&ip) {
            // Correlate the connection's fingerprint with what the request calls
            // itself. This is the only layer that has both, and it is what lets the
            // directory name a client instead of listing an opaque hash.
            if let Some(ref ja3) = fingerprint.ja3_hash {
                if let Some(ua) = user_agent {
                    security.note_user_agent(ja3, ua);
                }
            }

            // 1. Advanced multi-dimensional rate limiting.
            //
            // The only limiter that is genuinely this path's own work: it is a
            // separate subsystem from the per-IP limiter and `evaluate` does not
            // call it. The blocklist, the per-IP rate limit (with its crawler
            // exemption and auto-block) and the header-size check used to be
            // open-coded here as well, immediately before the `evaluate` call
            // below re-ran every one of them — so an h3 request was charged
            // *two* tokens against the per-IP limiter, giving HTTP/3 clients
            // half the configured request rate of the same client on TCP.
            {
                // From the connection's own handshake, not from request
                // headers. These used to read `x-ja3-hash` / `x-ja4-hash` off
                // the incoming request — headers that nothing on this path ever
                // set, so both were always None and every fingerprint-keyed
                // rate limit rule silently matched nothing over HTTP/3. Worse,
                // a client could set them itself and choose which bucket to be
                // counted in.
                let ja3_hash = fingerprint.ja3_hash.clone();
                let ja4_hash = fingerprint.ja4_hash.clone();
                let adv_ctx = build_context_from_request(
                    ip,
                    request.headers(),
                    &path,
                    method,
                    ja3_hash,
                    ja4_hash,
                    None,
                );
                match advanced_rate_limiter.check(&adv_ctx).await {
                    RateLimitResult::Allowed { .. } => {}
                    RateLimitResult::Limited {
                        reason,
                        retry_after_ms,
                        limit,
                    } => {
                        warn!(
                            "[QUIC/H3] Advanced rate limit exceeded for {} (reason: {:?})",
                            ip, reason
                        );
                        metrics.requests.request_end_full(
                            429,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        // CORS headers on 429 so browsers see the status code
                        // rather than an opaque CORS failure. The allowlist is
                        // the one `security` renders its own refusals from.
                        let req_origin_adv = request
                            .headers()
                            .get("origin")
                            .and_then(|v| v.to_str().ok());
                        let retry_secs = (retry_after_ms / 1000).max(1);
                        let mut builder_adv = http::Response::builder()
                            .status(http::StatusCode::TOO_MANY_REQUESTS)
                            .header("retry-after", retry_secs.to_string())
                            .header("x-ratelimit-limit", limit.to_string())
                            .header("x-ratelimit-remaining", "0")
                            .header(
                                "x-ratelimit-reason",
                                format!("{:?}", reason).to_ascii_lowercase(),
                            )
                            .header("server", SERVER_HEADER);
                        for (k, v) in crate::security::cors_refusal_headers(req_origin_adv) {
                            builder_adv = builder_adv.header(k, v);
                        }
                        let response = builder_adv.body(())?;
                        respond_and_finish(&mut stream, response).await?;
                        return Ok(());
                    }
                    RateLimitResult::Blocked { reason } => {
                        warn!(
                            "[QUIC/H3] Advanced rate limiter blocked {} (reason: {})",
                            ip, reason
                        );
                        metrics.requests.request_end_full(
                            403,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::FORBIDDEN)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        respond_and_finish(&mut stream, response).await?;
                        return Ok(());
                    }
                }
            }

            // 2. Shared security evaluation.
            //
            // Every rule below is the SAME implementation the TCP path runs —
            // SecurityState::evaluate. This handler used to carry its own copy,
            // which omitted the WAF entirely and let every rule be bypassed over
            // QUIC; it also never enforced GeoIP blocking or per-route policy.
            // Only the rendering of the verdict is transport-specific.
            // Resolved at most once per request: the body-pass WAF inspection
            // below reuses this instead of repeating the host derivation, the
            // route scan and the policy-field clones.
            let h3_route_policy = route_policy
                .get_or_insert_with(|| resolve_route_policy(&security, &request, &path));

            {
                let view = crate::security::SecurityRequestView {
                    ip,
                    method,
                    path: &path,
                    query: request.uri().query().unwrap_or(""),
                    headers: request.headers(),
                    body: None,
                };
                let decision = security.evaluate(&view, &h3_route_policy);
                let request_origin = request
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                if let Some(rendering) =
                    crate::security::decision_rendering(&decision, request_origin)
                {
                    warn!(
                        "[QUIC/H3] security decision {:?} for {} {}",
                        decision, ip, path
                    );
                    metrics.requests.request_end_full(
                        rendering.status.as_u16(),
                        start_time.elapsed(),
                        0,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    let mut builder = http::Response::builder()
                        .status(rendering.status)
                        .header("server", SERVER_HEADER);
                    for (k, v) in rendering.headers {
                        builder = builder.header(k, v);
                    }
                    let response = builder.body(())?;
                    respond_and_finish(&mut stream, response).await?;
                    return Ok(());
                }
            }
        }

        // Send 103 Early Hints if enabled and we have hints for this path
        // This is a key HTTP/3 optimization - send resource hints before proxying to backend
        // Only send for GET/HEAD requests - 103 on POST/PUT/DELETE can break cookie handling
        if early_hints_state.is_enabled() && (method == "GET" || method == "HEAD") {
            let hints =
                early_hints_state.get_hints_for_request(host.as_deref().unwrap_or(""), &path);
            if !hints.is_empty() {
                // Build 103 Early Hints response with Link headers and alt-svc for QUIC advertisement
                let mut early_response_builder = http::Response::builder()
                    .status(http::StatusCode::EARLY_HINTS)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .header("server", SERVER_HEADER);

                for hint in &hints {
                    early_response_builder = early_response_builder.header("link", hint.as_str());
                }

                if let Ok(early_response) = early_response_builder.body(()) {
                    match tokio::time::timeout(
                        Duration::from_millis(50),
                        stream.send_response(early_response),
                    )
                    .await
                    {
                        Ok(Ok(())) => {
                            debug!(
                                "Sent 103 Early Hints to {} with {} link hints",
                                remote_addr,
                                hints.len()
                            );
                        }
                        Ok(Err(e)) => {
                            debug!(
                                "Failed to send 103 Early Hints to {}: {} (continuing with request)",
                                remote_addr, e
                            );
                        }
                        Err(_) => {
                            debug!(
                                "103 Early Hints timed out for {} (QUIC window full, continuing)",
                                remote_addr
                            );
                        }
                    }
                }
            }
        }

        // ── Conformance vhost, over HTTP/3 ────────────────────────────────────
        //
        // The TCP listener has served this vhost from the start; this path had
        // never heard of it, so `https://conformance.pqcrypta.com/` answered 200
        // over HTTP/1.1 and HTTP/2 and 404 over HTTP/3. Browsers upgrade on the
        // Alt-Svc header, which meant the one audience most likely to open the
        // page in the first place was the audience that could not.
        //
        // The instance comes from `conformance::shared`, so it is the *same*
        // registry the TCP path uses. A second instance here would have given a
        // session started over one transport no results from the other.
        if let Some(conf) = crate::conformance::shared(&config.conformance) {
            let conformance_host = request
                .headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
                .or_else(|| request.uri().host().map(str::to_ascii_lowercase))
                .unwrap_or_default();

            if conf.owns_host(&conformance_host) {
                if let Some(resp) = crate::conformance::http::route(
                    &conf,
                    request.method(),
                    &path,
                    crate::security::canonical_addr(remote_addr).ip(),
                ) {
                    let (parts, body) = resp.into_parts();
                    let bytes = http_body_util::BodyExt::collect(body)
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();

                    let mut builder = http::Response::builder().status(parts.status);
                    for (name, value) in parts.headers.iter() {
                        builder = builder.header(name, value);
                    }
                    let response = builder
                        .header("server", SERVER_HEADER)
                        .header(
                            "alt-svc",
                            alt_svc_for_host(&config, Some(&conformance_host)),
                        )
                        .body(())?;

                    stream.send_response(response).await?;
                    // HEAD carries the headers a GET would have and no body
                    // (RFC 9110 §9.3.2), which is also why the length above is
                    // taken from the response rather than from what is sent.
                    if request.method() != http::Method::HEAD && !bytes.is_empty() {
                        stream.send_data(bytes).await?;
                    }
                    drain_request(&mut stream).await;
                    stream.finish().await?;
                    return Ok(());
                }
            }
        }

        // ── Speedtest: direct download streaming (H3) ─────────────────────────
        // The default proxy path buffers the entire PHP response before sending —
        // for 12 parallel 100 MB streams that's 1.2 GB RAM and a ~10× throughput
        // hit. Intercept here and stream bytes directly over H3 without PHP.
        if path == "/speedtest/tcp-download.php" && (method == "GET" || method == "HEAD") {
            let bytes_requested: u64 = uri
                .query()
                .and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next()? == "bytes" {
                            parts.next()?.parse().ok()
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or(10 * 1024 * 1024);
            let bytes_to_send: u64 = bytes_requested.clamp(65_536, 100 * 1024 * 1024);

            let dl_start = std::time::Instant::now();
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .header("content-length", bytes_to_send.to_string())
                .header("cache-control", "no-store")
                .header("x-content-type-options", "nosniff")
                .header("server", SERVER_HEADER)
                .body(())?;
            stream.send_response(response).await?;

            if method != "HEAD" {
                // 256 KB chunk — pseudo-random bytes (LCG); QUIC doesn't compress
                // data payloads so any pattern gives accurate bandwidth measurement.
                const CHUNK: usize = 256 * 1024;
                let mut chunk_buf = vec![0u8; CHUNK];
                let mut lcg: u64 = 0xdead_beef_cafe_babe;
                for b in chunk_buf.iter_mut() {
                    lcg = lcg
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    *b = u8::try_from(lcg >> 56 & 0xFF).unwrap_or(0);
                }
                let chunk_bytes = Bytes::from(chunk_buf);

                let mut remaining = bytes_to_send as usize;
                while remaining > 0 {
                    let n = remaining.min(CHUNK);
                    // Client cancels when the time limit hits — that's normal; just stop.
                    if stream
                        .send_data(if n == CHUNK {
                            chunk_bytes.clone()
                        } else {
                            chunk_bytes.slice(..n)
                        })
                        .await
                        .is_err()
                    {
                        break;
                    }
                    remaining -= n;
                }
            }

            let _ = stream.finish().await; // ignore error if client already cancelled
            let elapsed = dl_start.elapsed();
            info!(
                "[speedtest-dl/h3] sent {} bytes in {:.2}s from {}",
                bytes_to_send,
                elapsed.as_secs_f64(),
                remote_addr
            );
            metrics.requests.request_end_full(
                200,
                elapsed,
                0,
                bytes_to_send,
                Some(&path),
                is_health_check,
            );
            return Ok(());
        }

        // ── Speedtest: server-side upload measurement ─────────────────────────
        // Chrome upgrades all pqcrypta.com:443 requests to HTTP/3 via cached Alt-Svc,
        // so the "TCP" upload stream arrives here. Count bytes received; the client
        // uses the known test duration as the time denominator — no server-side timing.
        if path == "/speedtest/tcp-upload-stream" && method == "POST" {
            let measure_start = std::time::Instant::now();
            let mut total_bytes: u64 = 0;
            let mut chunk_count: u64 = 0;

            loop {
                match stream.recv_data().await {
                    Ok(None) => break,
                    Ok(Some(mut chunk)) => {
                        let n = chunk.remaining();
                        chunk.advance(n);
                        total_bytes += n as u64;
                        chunk_count += 1;
                    }
                    Err(_) => break,
                }
            }

            let total_elapsed = measure_start.elapsed();
            info!(
                "[speedtest-upload/h3] {} bytes in {:.2}s ({} chunks) from {}",
                total_bytes,
                total_elapsed.as_secs_f64(),
                chunk_count,
                remote_addr
            );
            // Return bytes_received only — client divides by the known test duration
            // for an accurate mbps figure with no server-side timing complexity.
            let steady_mbps = 0.0_f64; // unused; client computes from bytes + duration
            let duration_ms = total_elapsed.as_millis().try_into().unwrap_or(u64::MAX);

            info!(
                "[speedtest-upload/h3] result: bytes={} steady_mbps={:.2} duration_ms={} from {}",
                total_bytes, steady_mbps, duration_ms, remote_addr
            );
            let json = format!(
                r#"{{"ok":true,"bytes_received":{},"duration_ms":{},"steady_mbps":{:.2},"throughput_mbps":{:.2}}}"#,
                total_bytes, duration_ms, steady_mbps, steady_mbps,
            );
            let json_bytes = Bytes::from(json);
            let json_len = json_bytes.len();

            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/json")
                .header("content-length", json_len.to_string())
                .header("cache-control", "no-store")
                .header("server", SERVER_HEADER)
                .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                .body(())?;
            stream.send_response(response).await?;
            stream.send_data(json_bytes).await?;
            drain_request(&mut stream).await;
            stream.finish().await?;

            metrics.requests.request_end_full(
                200,
                total_elapsed,
                total_bytes,
                json_len as u64,
                Some(&path),
                is_health_check,
            );
            return Ok(());
        }
        // ── End speedtest upload handler ───────────────────────────────────────

        // Find route first so we can use per-route CORS config
        let route = match config.find_route(host.as_deref(), &path, false) {
            Some(r) => {
                let route_name = r.name.as_deref().unwrap_or("unnamed");
                info!(
                    "HTTP/3 route matched: {} -> backend {}",
                    route_name, r.backend
                );
                r
            }
            None => {
                warn!("HTTP/3 no route found for host={:?} path={}", host, path);
                // Log 404 response
                log_access(&AccessLogEntry {
                    remote_addr,
                    method,
                    path: &path,
                    protocol: "HTTP/3",
                    status: 404,
                    body_size: 0,
                    referer,
                    user_agent,
                    host: host.as_deref(),
                    response_time_ms: start_time
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                });
                metrics.requests.request_end_full(
                    404,
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                // Return 404 — include Alt-Svc so tcp_only_hosts origins
                // receive "clear" and the browser stops upgrading to HTTP/3.
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .header("server", SERVER_HEADER)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .body(())?;

                respond_and_finish(&mut stream, response).await?;
                return Ok(());
            }
        };

        // Per-route rate limits, applied after route matching exactly as the TCP
        // path does.  This check did not exist here at all, so every
        // `[advanced_rate_limiting.route_limits.*]` block was enforced over
        // HTTP/1.1 and HTTP/2 and skipped over HTTP/3 — a login endpoint pinned
        // to 2 rps was served at the global per-IP rate to any client willing to
        // negotiate h3, which browsers do by default off the Alt-Svc header.
        // The two listeners are separate implementations; a control added to one
        // is not a control until it is added to both.
        if let Some(ref route_name) = route.name {
            if config
                .advanced_rate_limiting
                .route_limits
                .contains_key(route_name.as_str())
            {
                let route_ctx = build_context_from_request(
                    ip,
                    request.headers(),
                    &path,
                    method,
                    fingerprint.ja3_hash.clone(),
                    fingerprint.ja4_hash.clone(),
                    Some(route_name.clone()),
                );
                if let RateLimitResult::Limited {
                    retry_after_ms,
                    limit,
                    ..
                } = advanced_rate_limiter.check(&route_ctx).await
                {
                    warn!(
                        "HTTP/3 per-route rate limit exceeded for {} on route {}",
                        ip, route_name
                    );
                    let response = http::Response::builder()
                        .status(http::StatusCode::TOO_MANY_REQUESTS)
                        .header("server", SERVER_HEADER)
                        .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                        .header("retry-after", (retry_after_ms / 1000).to_string())
                        .header("x-ratelimit-limit", limit.to_string())
                        .header("x-ratelimit-remaining", "0")
                        .body(())?;
                    respond_and_finish(&mut stream, response).await?;
                    metrics.requests.request_end_full(
                        429,
                        start_time.elapsed(),
                        0,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    return Ok(());
                }
            }
        }

        // Redirect routes, before the CORS preflight below so a preflight to an
        // authenticated route is still answered — the order the TCP path uses.
        // This path had no redirect handling at all, so the six SEO redirects in
        // production answered 308 over TCP and 502 over HTTP/3.
        {
            let query = request
                .uri()
                .query()
                .map(|q| format!("?{}", q))
                .unwrap_or_default();
            if let Some((target, permanent)) =
                crate::route_gate::redirect_target(route, &path, &query)
            {
                let status = if permanent {
                    http::StatusCode::PERMANENT_REDIRECT
                } else {
                    http::StatusCode::TEMPORARY_REDIRECT
                };
                let response = http::Response::builder()
                    .status(status)
                    .header("location", &target)
                    .header("server", SERVER_HEADER)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .body(())?;
                respond_and_finish(&mut stream, response).await?;
                metrics.requests.request_end_full(
                    status.as_u16(),
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                return Ok(());
            }
        }

        // Handle CORS preflight OPTIONS requests using route.cors
        if request.method() == http::Method::OPTIONS {
            if let Some(ref cors) = route.cors {
                let mut response_builder = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                    .header("server", SERVER_HEADER);

                // Access-Control-Allow-Origin — reflect when allow_origins list is set
                let req_origin_str = request
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                let resolved_origin = if !cors.allow_origins.is_empty() {
                    req_origin_str
                        .filter(|o| cors.allow_origins.iter().any(|a| a == *o))
                        .map(String::from)
                } else {
                    cors.allow_origin.clone()
                };
                // `Vary: Origin` whenever the answer depends on the request's origin.
                //
                // Required by the Fetch standard, and load-bearing for anything in front of
                // this: without it a cache may hand one origin the header that names
                // another. Set only when reflecting from an allowlist — a fixed
                // `allow_origin` is the same for every caller and needs no Vary.
                if !cors.allow_origins.is_empty() {
                    response_builder = response_builder.header("vary", "Origin");
                }
                if let Some(ref origin) = resolved_origin {
                    response_builder =
                        response_builder.header("access-control-allow-origin", origin);
                }

                // Access-Control-Allow-Methods
                if !cors.allow_methods.is_empty() {
                    let methods = cors.allow_methods.join(", ");
                    response_builder =
                        response_builder.header("access-control-allow-methods", methods);
                }

                // Access-Control-Allow-Headers
                if !cors.allow_headers.is_empty() {
                    let hdrs = cors.allow_headers.join(", ");
                    response_builder =
                        response_builder.header("access-control-allow-headers", hdrs);
                }

                // Access-Control-Allow-Credentials
                if cors.allow_credentials {
                    response_builder =
                        response_builder.header("access-control-allow-credentials", "true");
                }

                // Access-Control-Max-Age
                if cors.max_age > 0 {
                    response_builder =
                        response_builder.header("access-control-max-age", cors.max_age.to_string());
                }

                let response = response_builder.body(())?;
                respond_and_finish(&mut stream, response).await?;
                metrics.requests.request_end_full(
                    200,
                    start_time.elapsed(),
                    0,
                    0,
                    None,
                    is_health_check,
                );
                return Ok(());
            }
            // If no CORS config, fall through to normal handling / backend
        }

        // Per-route gates: 0-RTT policy, the HTTP/1.1 restriction, internal-route
        // mTLS and HMAC proof-of-possession. The SAME implementation the TCP path
        // runs. None of these existed on this path: a route protected by
        // `mtls_required` or an `hmac_secret` was enforced over HTTP/1.1 and
        // HTTP/2 and wide open over HTTP/3.
        {
            let gate_cx = crate::route_gate::GateContext {
                route,
                method,
                path_and_query: &path_with_query,
                path: &path,
                headers: request.headers(),
                client_ip: ip,
                // HTTP/3 by construction, so the HTTP/1.1 gate never fires here.
                is_http11: false,
                is_websocket_upgrade: false,
                zero_rtt_safe_methods: &config.tls.zero_rtt_safe_methods,
                hmac_nonce_store: crate::route_gate::shared_nonce_store(
                    config.tls.zero_rtt_nonce_window_secs,
                ),
            };
            if let crate::route_gate::GateOutcome::Refuse {
                status,
                headers: extra,
            } = crate::route_gate::evaluate(&gate_cx)
            {
                let mut builder = http::Response::builder()
                    .status(status)
                    .header("server", SERVER_HEADER)
                    .header("alt-svc", alt_svc_for_host(&config, host.as_deref()));
                for (k, v) in extra {
                    builder = builder.header(k, v);
                }
                respond_and_finish(&mut stream, builder.body(())?).await?;
                metrics.requests.request_end_full(
                    status.as_u16(),
                    start_time.elapsed(),
                    0,
                    0,
                    Some(&path),
                    is_health_check,
                );
                return Ok(());
            }
        }

        // Pool-aware backend selection: supports canary routing and load balancing.
        // Falls back to direct backend config lookup if no matching pool is configured.
        let (backend, canary_cookie_to_set): (BackendConfig, Option<String>) = {
            // Extract cookies from request headers for sticky session / canary routing
            let cookie_str = request
                .headers()
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if let Some(pool) = load_balancer.get_pool(&route.backend) {
                // Determine canary sticky cookie name from pool config (default "PQCPROXY_CANARY")
                let canary_cookie_name = pool
                    .canary_config
                    .as_ref()
                    .map(|c| c.sticky_cookie_name.clone())
                    .unwrap_or_else(|| "PQCPROXY_CANARY".to_string());

                // Extract canary cookie value from cookie header
                let canary_cookie_val = cookie_str.split(';').find_map(|part| {
                    let part = part.trim();
                    part.strip_prefix(&format!("{}=", canary_cookie_name))
                        .map(|v| v.to_string())
                });

                // Extract canary sticky header value if pool has one configured
                let canary_header_val = pool
                    .canary_config
                    .as_ref()
                    .and_then(|c| c.sticky_header.as_deref())
                    .and_then(|hdr_name| {
                        request
                            .headers()
                            .get(hdr_name)
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string())
                    });

                // Extract session affinity cookie
                let session_cookie_val = cookie_str.split(';').find_map(|part| {
                    let part = part.trim();
                    // Generic session cookie extraction – key=value
                    if part.contains('=') {
                        let (k, v) = part.split_once('=').unwrap_or(("", ""));
                        if !k.starts_with("PQCPROXY_CANARY") {
                            return Some(v.to_string());
                        }
                    }
                    None
                });

                let ctx = SelectionContext {
                    client_ip: remote_addr.ip(),
                    session_cookie: session_cookie_val,
                    affinity_header: None,
                    path: path.clone().into_owned(),
                    host: host.clone().map(Cow::into_owned).unwrap_or_default(),
                    canary_cookie: canary_cookie_val,
                    canary_header: canary_header_val,
                    query: request.uri().query().map(String::from),
                    hash_header: pool.hash_header_name().and_then(|h| {
                        request
                            .headers()
                            .get(h)
                            .and_then(|v| v.to_str().ok().map(String::from))
                    }),
                };

                match pool.select(&ctx) {
                    Some(result) => {
                        let server = &result.server;
                        let tls = matches!(server.tls_mode, crate::config::TlsMode::Reencrypt);
                        let cfg = BackendConfig {
                            name: server.id.clone(),
                            backend_type: BackendType::Http1,
                            address: server.address.to_string(),
                            tls_mode: server.tls_mode.clone(),
                            tls,
                            tls_cert: None,
                            tls_client_cert: None,
                            tls_client_key: None,
                            tls_skip_verify: false,
                            tls_sni: None,
                            timeout_ms: u64::try_from(server.timeout.as_millis())
                                .unwrap_or(u64::MAX),
                            max_connections: server.max_connections,
                            health_check: None,
                            health_check_interval_secs: 30,
                            retries: None,
                            retry_backoff_ms: None,
                            retry_on: None,
                            circuit_breaker: None,
                            disable_pooling: false,
                        };
                        (cfg, result.set_canary_cookie)
                    }
                    None => {
                        error!("No healthy server available in pool: {}", route.backend);
                        metrics.requests.request_end_full(
                            503,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::SERVICE_UNAVAILABLE)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        respond_and_finish(&mut stream, response).await?;
                        return Ok(());
                    }
                }
            } else {
                match config.get_backend(&route.backend) {
                    Some(b) => (b.clone(), None),
                    None => {
                        error!("Backend not found: {}", route.backend);
                        metrics.requests.request_end_full(
                            502,
                            start_time.elapsed(),
                            0,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::BAD_GATEWAY)
                            .header("server", SERVER_HEADER)
                            .body(())?;
                        respond_and_finish(&mut stream, response).await?;
                        return Ok(());
                    }
                }
            }
        };

        // Read request body — handle recv_data errors gracefully so a single
        // stream error (e.g. QUIC flow-control exhaustion on large uploads) does
        // not propagate up and kill the entire QUIC connection.
        let mut body = Vec::new();
        loop {
            match stream.recv_data().await {
                Ok(None) => break, // body fully received
                Ok(Some(mut chunk)) => {
                    while chunk.has_remaining() {
                        let bytes = chunk.chunk();
                        body.extend_from_slice(bytes);
                        chunk.advance(bytes.len());
                    }
                    if body.len() > config.security.max_request_size {
                        metrics.requests.request_end_full(
                            413,
                            start_time.elapsed(),
                            body.len() as u64,
                            0,
                            Some(&path),
                            is_health_check,
                        );
                        let response = http::Response::builder()
                            .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                            .body(())?;

                        respond_and_finish(&mut stream, response).await?;
                        return Ok(());
                    }
                }
                Err(e) => {
                    // Stream-level error (flow-control, reset, etc.) — respond 500
                    // and return Ok so the QUIC connection stays alive for other streams.
                    debug!("QUIC recv_data error on {} {}: {}", method, path, e);
                    metrics.requests.request_end_full(
                        500,
                        start_time.elapsed(),
                        body.len() as u64,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    if let Ok(response) = http::Response::builder()
                        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                        .body(())
                    {
                        let _ = stream.send_response(response).await;
                        let _ = stream.finish().await;
                    }
                    return Ok(());
                }
            }
        }

        // WAF body inspection over HTTP/3.
        //
        // The header/path/query pass ran through `security.evaluate()` above
        // with `body: None` — the request body is only available here, once it
        // has been read. The TCP listener buffers and inspects the body the same
        // way; without this, a body-borne attack (SQLi/XXE/prototype pollution
        // in a POST body) was blocked over TCP but sailed through over QUIC,
        // exactly the transport divergence this proxy exists not to have. The
        // engine truncates to `max_body_scan_bytes` internally, so the whole
        // buffered body is passed by reference.
        if !body.is_empty() && security.waf_engine.is_some() {
            let is_pentest =
                crate::config::ip_list_contains(&security.config.read().pentest_bypass_ips, &ip);
            let body_query = request.uri().query().unwrap_or("").to_string();
            // Re-resolve the per-route policy here: the one built for the header
            // pass lives in a block that has since closed. Same idiom, so body
            // inspection honours the same per-route waf_mode / waf_enabled.
            // Same policy the header pass used. It used to be rebuilt here
            // because that one was scoped to a block that had closed; it is now
            // resolved once per request and shared.
            let body_route_policy = route_policy
                .get_or_insert_with(|| resolve_route_policy(&security, &request, &path));
            let body_view = crate::security::SecurityRequestView {
                ip,
                method,
                path: &path,
                query: &body_query,
                headers: request.headers(),
                body: Some(&body),
            };
            let decision = security.inspect_body(&body_view, &body_route_policy, is_pentest);
            let body_origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok());
            if let Some(rendering) = crate::security::decision_rendering(&decision, body_origin) {
                warn!(
                    "[QUIC/H3] WAF body decision {:?} for {} {}",
                    decision, ip, path
                );
                metrics.requests.request_end_full(
                    rendering.status.as_u16(),
                    start_time.elapsed(),
                    body.len() as u64,
                    0,
                    Some(&path),
                    is_health_check,
                );
                let mut builder = http::Response::builder()
                    .status(rendering.status)
                    .header("server", SERVER_HEADER);
                for (k, v) in rendering.headers {
                    builder = builder.header(k, v);
                }
                let response = builder.body(())?;
                respond_and_finish(&mut stream, response).await?;
                return Ok(());
            }
        }

        // --- Response cache lookup (GET / HEAD only, HTTP/3 path) ---
        // Range requests bypass the cache entirely: the cache stores whole responses
        // and must hand range requests to the backend so they get a correct 206 with
        // a matching Content-Range, rather than a cached full 200 body.
        let cache_host_str = host.as_deref().unwrap_or("");
        let is_range_request = request.headers().contains_key("range");
        if (method == "GET" || method == "HEAD")
            && !is_range_request
            && cache.config.enabled
            && !cache.is_excluded_path(&path)
            && !cache.is_excluded_host(cache_host_str)
        {
            let host_str = cache_host_str;
            let cache_key = ResponseCache::build_key(method, host_str, &path_with_query);
            let if_none_match = request
                .headers()
                .get("if-none-match")
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            let if_modified_since = request
                .headers()
                .get("if-modified-since")
                .and_then(|v| v.to_str().ok())
                .map(String::from);

            match cache.get(
                &cache_key,
                if_none_match.as_deref(),
                if_modified_since.as_deref(),
            ) {
                CacheLookup::Hit {
                    status,
                    headers: cached_headers,
                    body: cached_body,
                    age_secs,
                } => {
                    debug!(
                        "HTTP/3 cache HIT: {} {} (age {}s)",
                        method, path_with_query, age_secs
                    );
                    let status_code =
                        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
                    let mut response_builder = http::Response::builder()
                        .status(status_code)
                        .header("age", age_secs.to_string())
                        .header("x-cache", "HIT")
                        .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                        .header("server", SERVER_HEADER);
                    for (k, v) in &cached_headers {
                        // Skip headers the proxy sets itself in this block. The cached
                        // entry holds the raw backend headers, so replaying `server`
                        // would emit a second `server: <backend>` alongside our own
                        // SERVER_HEADER — duplicate `server` values that leak the backend
                        // identity and shadow ours for some HTTP/3 clients. Same for
                        // alt-svc/age/x-cache/content-length which are set above.
                        let lk = k.to_lowercase();
                        if matches!(
                            lk.as_str(),
                            "content-length" | "server" | "alt-svc" | "age" | "x-cache"
                        ) {
                            continue;
                        }
                        response_builder = response_builder.header(k.as_str(), v.as_str());
                    }
                    // HEAD sends no body but must report the length a GET would
                    // have (RFC 9110 §9.3.2). Deriving the header from the
                    // stripped body reported every cached HEAD as zero-length.
                    let content_length = cached_body.len();
                    // Refcount bump, not a copy: serving a cache hit used to
                    // clone the whole body out of the entry.
                    let body_bytes: Bytes = if method == "HEAD" {
                        Bytes::new()
                    } else {
                        cached_body.clone()
                    };
                    response_builder =
                        response_builder.header("content-length", content_length.to_string());
                    let response = response_builder.body(())?;
                    let body_size = body_bytes.len();
                    let latency = start_time.elapsed();
                    stream.send_response(response).await?;
                    if !body_bytes.is_empty() {
                        stream.send_data(body_bytes).await?;
                    }
                    stream.finish().await?;
                    metrics.requests.request_end_full(
                        status,
                        latency,
                        body.len() as u64,
                        body_size as u64,
                        Some(&path),
                        is_health_check,
                    );
                    log_access(&AccessLogEntry {
                        remote_addr,
                        method,
                        path: &path,
                        protocol: "HTTP/3",
                        status,
                        body_size,
                        referer,
                        user_agent,
                        host: host.as_deref(),
                        response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                    return Ok(());
                }

                CacheLookup::NotModified {
                    etag,
                    last_modified,
                    cache_control,
                    age_secs,
                } => {
                    debug!(
                        "HTTP/3 cache 304: {} {} (age {}s)",
                        method, path_with_query, age_secs
                    );
                    let mut response_builder = http::Response::builder()
                        .status(http::StatusCode::NOT_MODIFIED)
                        .header("age", age_secs.to_string())
                        .header("x-cache", "HIT")
                        .header("alt-svc", alt_svc_for_host(&config, host.as_deref()))
                        .header("server", SERVER_HEADER);
                    if let Some(et) = etag {
                        response_builder = response_builder.header("etag", et);
                    }
                    if let Some(lm) = last_modified {
                        response_builder = response_builder.header("last-modified", lm);
                    }
                    if let Some(cc) = cache_control {
                        response_builder = response_builder.header("cache-control", cc);
                    }
                    let response = response_builder.body(())?;
                    let latency = start_time.elapsed();
                    respond_and_finish(&mut stream, response).await?;
                    metrics.requests.request_end_full(
                        304,
                        latency,
                        body.len() as u64,
                        0,
                        Some(&path),
                        is_health_check,
                    );
                    log_access(&AccessLogEntry {
                        remote_addr,
                        method,
                        path: &path,
                        protocol: "HTTP/3",
                        status: 304,
                        body_size: 0,
                        referer,
                        user_agent,
                        host: host.as_deref(),
                        response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
                    });
                    return Ok(());
                }

                CacheLookup::Miss => {}
            }
        }

        // Build the header map the backend will receive.
        //
        // A `HeaderMap`, not a `HashMap<String, String>`: this used to allocate
        // two Strings per header on the way in and the forwarding code then
        // re-parsed and re-validated every name to rebuild a `HeaderMap` from
        // them. Cloning a `HeaderName` is cheap and a `HeaderValue` is
        // `Bytes`-backed, so carrying the real type costs no allocations at all.
        let mut headers = HeaderMap::with_capacity(request.headers().len() + 8);
        for (name, value) in &route.add_headers {
            if let (Ok(n), Ok(v)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(n, v);
            }
        }

        // Forward original request headers (excluding hop-by-hop headers)
        let mut cookie_parts: Vec<&str> = Vec::new();
        for (name, value) in request.headers() {
            // `HeaderName` is always lowercase, so this compares without
            // allocating the lowercased copy the old loop built per header.
            let name_str = name.as_str();
            if matches!(
                name_str,
                "host"
                    | "connection"
                    | "transfer-encoding"
                    | "upgrade"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailer"
            ) || name_str.starts_with(':')
            {
                continue;
            }
            if name_str == "cookie" {
                // HTTP/3 splits Cookie across multiple header fields
                // (RFC 9114 §4.2.1); collect them and join once below so the
                // HTTP/1.1 backend sees a single Cookie header.
                if let Ok(v) = value.to_str() {
                    cookie_parts.push(v);
                }
            } else {
                headers.insert(name.clone(), value.clone());
            }
        }
        if !cookie_parts.is_empty() {
            let joined = cookie_parts.join("; ");
            if let Ok(v) = HeaderValue::from_str(&joined) {
                headers.insert(header::COOKIE, v);
            }
        }

        // The connection-derived headers were established on `request` at entry
        // (see the top of this function) and copied verbatim by the forwarding
        // loop above, so they arrive at the backend already authoritative.
        // Stripping them again here would have discarded the real JA3/JA4 and
        // re-asserted only the subset this block knew about.

        // Forward Host header to backend (required for virtual host routing)
        if let Some(ref host_value) = host {
            if let Ok(v) = HeaderValue::from_str(host_value) {
                headers.insert(header::HOST, v);
            }
        }

        // Extract distributed trace context from the incoming QUIC/HTTP3 request
        // headers and stitch this request into the caller's trace.  The current
        // span becomes a child of the caller's span; proxy.rs then injects the
        // new child span context into the upstream backend request.
        otel::set_parent_from_headers(&tracing::Span::current(), &headers);

        // Forward X-Forwarded headers. The IP is formatted once and shared.
        headers.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
        let client_ip = remote_addr.ip().to_string();
        if let Ok(ip_value) = HeaderValue::from_str(&client_ip) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), ip_value.clone());
            headers.insert(HeaderName::from_static("x-real-ip"), ip_value.clone());

            if route.forward_client_identity {
                let header_name = route
                    .client_identity_header
                    .as_deref()
                    .unwrap_or("x-client-ip");
                if let Ok(n) = HeaderName::from_bytes(header_name.as_bytes()) {
                    headers.insert(n, ip_value);
                }
            }
        }

        // Traffic shadowing: fire-and-forget async copy to shadow backend (if configured)
        if let Some(ref shadow_cfg) = route.shadow {
            if !shadow_cfg.backend.is_empty() && shadow_cfg.percent > 0 {
                let roll: u8 = rand::random::<u8>() % 100;
                if roll < shadow_cfg.percent.min(100) {
                    if let Some(shadow_backend) = config.get_backend(&shadow_cfg.backend).cloned() {
                        // The shadow path still takes the older
                        // `HashMap<String, String>` interface. Converting here
                        // rather than upstream keeps the per-request path on
                        // `HeaderMap`: shadowing is off by default, so this
                        // allocation belongs on this branch.
                        let mut shadow_headers: std::collections::HashMap<String, String> = headers
                            .iter()
                            .filter_map(|(n, v)| {
                                v.to_str()
                                    .ok()
                                    .map(|v| (n.as_str().to_string(), v.to_string()))
                            })
                            .collect();
                        shadow_headers.insert(
                            shadow_cfg.shadow_header.clone(),
                            shadow_cfg.shadow_header_value.clone(),
                        );
                        let shadow_body = body.clone();
                        // Owned here and nowhere else: the spawned task is
                        // `'static`, and shadowing is off by default, so the
                        // allocation belongs on this branch rather than on every
                        // request.
                        let shadow_method = method.to_owned();
                        let shadow_path = path_with_query.clone().into_owned();
                        let shadow_bp = backend_pool.clone();
                        let shadow_timeout_ms = shadow_cfg.timeout_ms;
                        let shadow_log = shadow_cfg.log_responses;
                        let shadow_name = shadow_cfg.backend.clone();
                        tokio::task::spawn(async move {
                            let result = tokio::time::timeout(
                                Duration::from_millis(shadow_timeout_ms),
                                shadow_bp.proxy_http_full(
                                    &shadow_backend,
                                    &shadow_method,
                                    &shadow_path,
                                    shadow_headers,
                                    &shadow_body,
                                ),
                            )
                            .await;
                            match result {
                                Ok(Ok(resp)) if shadow_log => {
                                    info!("H3 Shadow → '{}' status={}", shadow_name, resp.status);
                                }
                                Ok(Ok(_)) => {}
                                Ok(Err(e)) => {
                                    warn!("H3 Shadow error for '{}': {}", shadow_name, e);
                                }
                                Err(_) => {
                                    warn!("H3 Shadow timeout for '{}'", shadow_name);
                                }
                            }
                        });
                    } else {
                        warn!(
                            "H3 Shadow backend '{}' not found in config",
                            shadow_cfg.backend
                        );
                    }
                }
            }
        }

        // Proxy to backend (include query string in path).
        // Use the streaming path for all requests: inspect content-type from response
        // headers to decide whether to pump chunks (SSE) or buffer (everything else).
        // `Bytes::from(Vec)` takes ownership without copying; the clone handed
        // to the forwarder below is then a refcount bump.
        let request_body = Bytes::from(body);
        let request_body_len = request_body.len() as u64;

        let (stream_status, stream_headers, stream_body) = backend_pool
            .proxy_stream(
                &backend,
                request.method(),
                &path_with_query,
                headers,
                request_body.clone(),
            )
            .await?;

        let is_sse = stream_headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/event-stream"));

        // SSE fast path: send headers immediately, then pump body frames as they arrive.
        if is_sse {
            let mut sse_builder = http::Response::builder().status(stream_status);
            for (name, value) in &stream_headers {
                // Skip content-length (SSE has no fixed length) and hop-by-hop
                // headers. `HeaderName` is already lowercase, so no copy here.
                if name == header::CONTENT_LENGTH || name == header::TRANSFER_ENCODING {
                    continue;
                }
                sse_builder = sse_builder.header(name, value);
            }
            sse_builder = sse_builder.header("cache-control", "no-cache");
            sse_builder = sse_builder.header("server", SERVER_HEADER);
            sse_builder = sse_builder.header("alt-svc", alt_svc_for_host(&config, host.as_deref()));
            // CORS headers must be present on the streamed response itself, not
            // just the preflight — otherwise browsers block the SSE fetch with
            // "No 'Access-Control-Allow-Origin' header". The non-SSE path adds
            // these below; the SSE fast path must do the same.
            if let Some(ref cors) = route.cors {
                let req_origin = request
                    .headers()
                    .get("origin")
                    .and_then(|v| v.to_str().ok());
                sse_builder = add_cors_headers_to_builder(sse_builder, cors, req_origin);
            }
            stream.send_response(sse_builder.body(())?).await?;

            let mut body_stream = stream_body;
            while let Some(frame_result) = body_stream.frame().await {
                match frame_result {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            if !data.is_empty() {
                                stream.send_data(data.clone()).await?;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            stream.finish().await?;

            metrics.requests.request_end_full(
                stream_status.as_u16(),
                start_time.elapsed(),
                request_body_len,
                0,
                Some(&path),
                is_health_check,
            );
            log_access(&AccessLogEntry {
                remote_addr,
                method,
                path: &path,
                protocol: "HTTP/3",
                status: stream_status.as_u16(),
                body_size: 0,
                referer,
                user_agent,
                host: host.as_deref(),
                response_time_ms: start_time
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
            });
            return Ok(());
        }

        // Only the cache needs the whole body in hand. Everything else can be
        // forwarded frame by frame as the backend produces it, which is what the
        // origin is already doing.
        //
        // Buffering was costing three things at once: `Collected::to_bytes()`
        // allocates and copies whenever a body arrives in more than one frame,
        // the full body stays resident until the last byte arrives (a hundred
        // concurrent 64 KB responses is 6.4 MB of live buffer), and nothing
        // reaches the client until the origin has finished.
        //
        // HEAD is buffered too, but its body is empty by definition, so that
        // costs nothing and keeps the length logic below in one place.
        let will_cache = method == "GET"
            && cache.config.enabled
            && !cache.is_excluded_path(&path)
            && !cache.is_excluded_host(cache_host_str);

        let mut streaming_body: Option<hyper::body::Incoming> = None;
        let buffered: Option<Bytes> = if will_cache || method == "HEAD" {
            Some(
                stream_body
                    .collect()
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
                    .to_bytes(),
            )
        } else {
            streaming_body = Some(stream_body);
            None
        };

        // Store response in cache (GET only; cache.put() enforces all Cache-Control
        // rules). HEAD is deliberately excluded: its body is empty by definition,
        // so the entry holds nothing worth serving, and the cache-hit arm derives
        // `content-length` from the stored body — which reported every cached HEAD
        // as a zero-length resource. The TCP cache middleware skips HEAD for the
        // same reason.
        if will_cache {
            let cache_key = ResponseCache::build_key(method, cache_host_str, &path_with_query);
            // The cache stores `Vec<(String, String)>`; converting here rather
            // than upstream keeps the forwarding path on `HeaderMap`, and this
            // runs only for cacheable GETs rather than every request.
            let cache_headers: Vec<(String, String)> = stream_headers
                .iter()
                .filter_map(|(n, v)| {
                    v.to_str()
                        .ok()
                        .map(|v| (n.as_str().to_string(), v.to_string()))
                })
                .collect();
            cache.put(
                &cache_key,
                stream_status.as_u16(),
                &cache_headers,
                buffered.clone().unwrap_or_default(),
            );
        }

        // Build HTTP/3 response with headers from backend
        let mut response_builder = http::Response::builder().status(stream_status);

        // Forward selected headers from backend (including CORS if backend sets them)
        // Note: x-content-type-options excluded from whitelist since proxy adds its own
        // Note: set-cookie for /grafana is handled separately below with Domain rewriting
        let is_grafana = path.starts_with("/grafana");
        for (name, value) in &stream_headers {
            // `HeaderName` is already lowercase; the old loop allocated a
            // lowercased String per response header to learn that.
            let lower_name = name.as_str();
            // Skip set-cookie for Grafana routes (handled below with Domain attribute)
            if is_grafana && lower_name == "set-cookie" {
                continue;
            }
            if matches!(
                lower_name,
                "content-type"
                    | "cache-control"
                    | "etag"
                    | "last-modified"
                    | "content-language"
                    | "content-encoding"
                    | "content-range"
                    | "accept-ranges"
                    | "content-disposition"
                    | "vary"
                    | "set-cookie"
                    | "location"
                    | "access-control-allow-origin"
                    | "access-control-allow-methods"
                    | "access-control-allow-headers"
                    | "access-control-allow-credentials"
                    | "access-control-expose-headers"
                    | "access-control-max-age"
            ) {
                response_builder = response_builder.header(name, value);
            }
        }

        // Add content-length from known body size (helps browsers finalize responses).
        //
        // Not on HEAD: the origin returns no body there, so the buffered length is
        // zero and synthesizing from it asserts an empty resource. RFC 9110 §9.3.2
        // wants the header a GET would have carried — forward the origin's own
        // value when it sent one, and otherwise send none, matching the chunked
        // GET these backends actually serve.
        if method == "HEAD" {
            if let Some(origin_len) = stream_headers.get(header::CONTENT_LENGTH) {
                response_builder = response_builder.header(header::CONTENT_LENGTH, origin_len);
            }
        } else if let Some(ref b) = buffered {
            response_builder = response_builder.header(header::CONTENT_LENGTH, b.len());
        } else if let Some(origin_len) = stream_headers.get(header::CONTENT_LENGTH) {
            // Streaming: the length is not known until the last frame, so forward
            // the origin's own value. When it sent none the response is chunked
            // and HTTP/3 needs no length at all.
            response_builder = response_builder.header(header::CONTENT_LENGTH, origin_len);
        }

        // For Grafana routes: rewrite set-cookie headers from backend
        // to work around browser H3 cookie handling by adding Domain attribute
        if path.starts_with("/grafana") {
            // Remove set-cookie from whitelist-forwarded headers (already added above)
            // and re-add with explicit Domain to help browser cookie storage
            let mut has_cookies = false;
            for value in stream_headers.get_all(header::SET_COOKIE) {
                let Ok(cookie) = value.to_str() else { continue };
                has_cookies = true;
                // Add Domain=pqcrypta.com to help browser store cookie
                if cookie.contains("Domain=") {
                    response_builder = response_builder.header(header::SET_COOKIE, value);
                } else {
                    response_builder = response_builder
                        .header(header::SET_COOKIE, format!("{cookie}; Domain=pqcrypta.com"));
                }
            }
            if has_cookies {
                // Also add a simple proxy test cookie to verify H3 cookie delivery
                response_builder = response_builder.header(
                    "set-cookie",
                    "pqc_h3_test=1; Path=/; Secure; SameSite=None; Max-Age=3600",
                );
            }
        }

        // Inject canary sticky cookie if pool selection assigned one
        if let Some(ref cookie_header) = canary_cookie_to_set {
            response_builder = response_builder.header("set-cookie", cookie_header.as_str());
        }

        // Add Alt-Svc header to advertise HTTP/3 support
        response_builder =
            response_builder.header("alt-svc", alt_svc_for_host(&config, host.as_deref()));

        // Server, Client-Hints, reporting and security headers: all fifteen are
        // fixed until the config reloads, so they are built once per connection
        // and applied here by cloning. See `build_static_response_headers`.
        if let Some(h) = response_builder.headers_mut() {
            h.reserve(static_headers.len());
            for (name, value) in static_headers.iter() {
                h.append(name.clone(), value.clone());
            }
        }

        // Server-Timing carries this request's elapsed time, so it cannot be
        // part of that set.
        if config.headers.server_timing_enabled {
            let processing_time = start_time.elapsed();
            let server_timing = format!(
                "proxy;dur={:.2};desc=\"PQ Crypta Processing\", quic;desc=\"QUIC v1\"",
                processing_time.as_secs_f64() * 1000.0
            );
            response_builder = response_builder.header("server-timing", server_timing);
        }

        // Add CORS headers from route.cors (proxy-level CORS) if configured
        if let Some(ref cors) = route.cors {
            let req_origin = request
                .headers()
                .get("origin")
                .and_then(|v| v.to_str().ok());
            response_builder = add_cors_headers_to_builder(response_builder, cors, req_origin);
        }

        // Apply route-specific header overrides (e.g., COEP/COOP for Grafana)
        for (key, value) in &route.headers_override {
            response_builder = response_builder.header(key.as_str(), value.as_str());
        }

        let response = response_builder.body(())?;
        let response_status = stream_status.as_u16();

        stream.send_response(response).await?;

        // Buffered only when the cache needed the whole body; otherwise each
        // frame goes out as the backend produces it.
        let body_size = match buffered {
            Some(body) => {
                let len = body.len();
                if !body.is_empty() {
                    stream.send_data(body).await?;
                }
                len
            }
            None => {
                let mut sent = 0usize;
                let mut frames = 0usize;
                let mut body = streaming_body
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("streaming body already consumed"))?;
                while let Some(frame_result) = body.frame().await {
                    let frame = frame_result
                        .map_err(|e| anyhow::anyhow!("Backend body stream failed: {}", e))?;
                    if let Some(data) = frame.data_ref() {
                        if !data.is_empty() {
                            sent += data.len();
                            frames += 1;
                            stream.send_data(data.clone()).await?;
                        }
                    }
                }
                trace!("HTTP/3 streamed {sent} bytes to client in {frames} frames");
                sent
            }
        };
        stream.finish().await?;

        // Record metrics
        let latency = start_time.elapsed();
        metrics.requests.request_end_full(
            response_status,
            latency,
            request_body_len,
            body_size as u64,
            Some(&path),
            is_health_check,
        );

        // Log successful response
        log_access(&AccessLogEntry {
            remote_addr,
            method,
            path: &path,
            protocol: "HTTP/3",
            status: response_status,
            body_size,
            referer,
            user_agent,
            host: host.as_deref(),
            response_time_ms: latency.as_millis().try_into().unwrap_or(u64::MAX),
        });

        Ok(())
    }
}
