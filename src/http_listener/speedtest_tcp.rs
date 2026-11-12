//! Server-measured TCP/HTTP-2 speedtest upload endpoints.

use axum::{
    body::Body,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::info;

/// Server-measured HTTP/2 upload throughput handler.
///
/// Receives a streaming POST body via HTTP/2, measures throughput from first byte
/// to stream EOF with a 2-second warmup phase excluded — identical methodology to
/// the WebTransport upload handler. Eliminates the client-side XHR send-buffer
/// illusion by counting bytes at the server as they arrive over the wire.
///
/// Wire: POST /speedtest/tcp-upload-stream[?test=ID]  (Content-Type: application/octet-stream)
/// Response: { ok, bytes_received, duration_ms, throughput_mbps, steady_mbps }
///
/// With `test`, the bytes are also counted, as they arrive, on that test's
/// shared meter (crate::speedtest_meter): a browser uploads over several
/// connections at once and aborts them at its time limit, so no one request's
/// own figures describe the upload. `GET /speedtest/tcp-upload-meter?test=ID`
/// (or the `meter` op on a WebTransport session to this node) reads it.
#[expect(clippy::cast_precision_loss)]
pub(super) async fn tcp_upload_measure_handler(
    body: Body,
    origin: &str,
    meter: Option<crate::speedtest_meter::MeterStream>,
    client: std::net::IpAddr,
) -> Response {
    use futures_util::StreamExt as _;
    use std::time::Instant;

    const WARMUP_SECS: f64 = 2.0;

    // The client network's place under its stream limit, held while the
    // upload is read (crate::speedtest_budget).
    let Some(_slot) = crate::speedtest_budget::enter_stream(client) else {
        return refusal(
            origin,
            None,
            serde_json::json!({
                "error": "too_many_streams",
                "max": crate::speedtest_budget::STREAMS_PER_NETWORK
            }),
        );
    };

    let mut stream = body.into_data_stream();
    let mut start: Option<Instant> = None;
    let mut total_bytes: u64 = 0;
    let mut post_warmup_bytes: u64 = 0;
    let mut exhausted: Option<std::time::Duration> = None;

    // Read for as long as the WebTransport upload may, and no more than it may
    // send; each piece is charged to the client's hourly upload allowance as
    // it arrives.
    let read = tokio::time::timeout(crate::speedtest::UPLOAD_TIME_LIMIT, async {
        while let Some(chunk) = stream.next().await {
            let Ok(data) = chunk else { break };
            let n = data.len() as u64;
            if n == 0 {
                continue;
            }
            match crate::speedtest_budget::reserve(
                client,
                crate::speedtest_budget::Direction::Upload,
                n,
            ) {
                Ok(mut charged) => charged.use_bytes(n),
                Err(refused) => {
                    exhausted = Some(refused.retry_after);
                    break;
                }
            }
            if start.is_none() {
                start = Some(Instant::now());
            }
            total_bytes += n;
            if let Some(m) = &meter {
                m.record(data.len());
            }
            if start.is_some_and(|s| s.elapsed().as_secs_f64() >= WARMUP_SECS) {
                post_warmup_bytes += n;
            }
            if total_bytes >= crate::speedtest::MAX_UPLOAD_BYTES as u64 {
                break;
            }
        }
    })
    .await;
    if read.is_err() {
        info!(
            "[speedtest-ul/tcp] time limit reached after {} bytes",
            total_bytes
        );
    }
    // The request has stopped receiving: the meter stops counting it as open.
    drop(meter);
    if let Some(retry_after) = exhausted {
        return refusal(
            origin,
            Some(retry_after),
            serde_json::json!({
                "error": "budget_exhausted",
                "bytes_received": total_bytes,
                "retry_after_secs": retry_after.as_secs().max(1)
            }),
        );
    }

    let elapsed_secs = start.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
    #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let elapsed_ms = (elapsed_secs * 1000.0).max(0.0) as u64;

    let throughput_mbps = if elapsed_secs > 0.0 {
        (total_bytes as f64 * 8.0) / (elapsed_secs * 1_000_000.0)
    } else {
        0.0
    };

    let steady_mbps = if elapsed_secs > WARMUP_SECS {
        let steady_secs = elapsed_secs - WARMUP_SECS;
        if steady_secs >= 0.5 && post_warmup_bytes > 0 {
            (post_warmup_bytes as f64 * 8.0) / (steady_secs * 1_000_000.0)
        } else {
            throughput_mbps
        }
    } else {
        throughput_mbps
    };

    info!(
        "[speedtest-ul/tcp] {} bytes in {}ms ({:.1} Mbps avg, {:.1} Mbps steady)",
        total_bytes, elapsed_ms, throughput_mbps, steady_mbps
    );

    let json_body = serde_json::json!({
        "ok": true,
        "bytes_received": total_bytes,
        "duration_ms": elapsed_ms,
        "throughput_mbps": (throughput_mbps * 100.0).round() / 100.0,
        "steady_mbps": (steady_mbps * 100.0).round() / 100.0,
    });

    let mut resp = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store, no-cache, must-revalidate"),
        ],
        axum::Json(json_body),
    )
        .into_response();
    super::speedtest_cross_origin_headers(resp.headers_mut(), origin);
    resp
}

/// A speed-test refusal (429), as JSON with the cross-origin headers the page
/// needs to read it, and `Retry-After` when there is a time to give.
fn refusal(
    origin: &str,
    retry_after: Option<std::time::Duration>,
    body: serde_json::Value,
) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body),
    )
        .into_response();
    if let Some(after) = retry_after {
        if let Ok(v) = HeaderValue::from_str(&after.as_secs().max(1).to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
    super::speedtest_cross_origin_headers(resp.headers_mut(), origin);
    resp
}

/// CORS preflight handler for the TCP upload route.
/// Browsers send OPTIONS before the POST because Content-Type: application/octet-stream
/// is not a "simple" request type. Without this, Axum returns 405 and the upload is blocked.
pub(super) async fn tcp_upload_cors_preflight(origin: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    let h = resp.headers_mut();
    super::speedtest_cross_origin_headers(h, origin);
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    h.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"),
    );
    resp
}
