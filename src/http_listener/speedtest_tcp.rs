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
/// Wire: POST /speedtest/tcp-upload-stream  (Content-Type: application/octet-stream)
/// Response: { ok, bytes_received, duration_ms, throughput_mbps, steady_mbps }
#[allow(clippy::cast_precision_loss)]
pub(super) async fn tcp_upload_measure_handler(body: Body) -> Response {
    use futures_util::StreamExt as _;
    use std::time::Instant;

    const WARMUP_SECS: f64 = 2.0;

    let mut stream = body.into_data_stream();
    let mut start: Option<Instant> = None;
    let mut total_bytes: u64 = 0;
    let mut post_warmup_bytes: u64 = 0;

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(data) => {
                let n = data.len() as u64;
                if n == 0 {
                    continue;
                }
                if start.is_none() {
                    start = Some(Instant::now());
                }
                total_bytes += n;
                if start.is_some_and(|s| s.elapsed().as_secs_f64() >= WARMUP_SECS) {
                    post_warmup_bytes += n;
                }
            }
            Err(_) => break,
        }
    }

    let elapsed_secs = start.map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
    // Add CORS header so tcp.pqcrypta.com cross-origin uploads work.
    if let Ok(v) = HeaderValue::from_str("https://pqcrypta.com") {
        resp.headers_mut().insert("access-control-allow-origin", v);
    }
    resp
}

/// CORS preflight handler for the TCP upload route.
/// Browsers send OPTIONS before the POST because Content-Type: application/octet-stream
/// is not a "simple" request type. Without this, Axum returns 405 and the upload is blocked.
pub(super) async fn tcp_upload_cors_preflight() -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    let h = resp.headers_mut();
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("https://pqcrypta.com"),
    );
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
