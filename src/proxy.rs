//! Backend proxy module
//!
//! Handles connections to backend servers:
//! - HTTP/1.1 and HTTP/2 via hyper
//! - Unix sockets via hyperlocal (for PHP-FPM)
//! - HTTP/3 via quinn/h3
//! - Raw TCP

use std::collections::HashMap;

use std::time::Duration;

use crate::backend_client::BackendClient;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderMap;
use hyper::{Method, Request, StatusCode};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::{BackendConfig, BackendType, ProxyConfig};
use crate::otel;

/// Response from backend proxy
/// Hop-by-hop headers, forbidden over HTTP/2 and HTTP/3 (RFC 9113 §8.2.2,
/// RFC 9114 §4.2). Was declared inline in each forwarding function.
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "proxy-authenticate",
    "proxy-authorization",
];

#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code
    pub status: u16,
    /// Response headers.
    ///
    /// `HeaderMap` rather than `Vec<(String, String)>`: it already supports
    /// repeated names (`Set-Cookie`), which was the reason for the Vec, and it
    /// is what both hyper and the HTTP/3 sender speak — so carrying it avoids
    /// three String allocations per header in each direction.
    pub headers: HeaderMap,
    /// Response body.
    ///
    /// `Bytes`, not `Vec<u8>`: hyper hands the body over as `Bytes` already and
    /// the HTTP/3 sender takes `Bytes`, so an owned `Vec` in between meant
    /// copying the entire body once per response for no reason -- 1.23 GB/s of
    /// pure memcpy at 64 KB. Cloning this for the cache is now a refcount bump.
    pub body: Bytes,
}

/// A backend did not answer within its timeout. Carried inside the
/// `anyhow::Error` so callers can answer 504 rather than 502 without matching
/// on message text.
#[derive(Debug)]
pub struct BackendTimeout(pub Duration);

impl std::fmt::Display for BackendTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backend did not respond within {}ms", self.0.as_millis())
    }
}

impl std::error::Error for BackendTimeout {}

/// The connection a streamed backend response arrived on; release it once the
/// body has been read to its end.
pub type BackendLease = crate::backend_client::Lease<Full<Bytes>>;

/// Backend connection pool manager
pub struct BackendPool {
    /// Pooled HTTP/1.1 connections to the backends; see [`crate::backend_client`].
    client: BackendClient<Full<Bytes>>,
}

impl BackendPool {
    /// Create a new backend pool
    pub fn new(config: &ProxyConfig) -> Self {
        // connect_timeout comes from security.connection_timeout_secs, which
        // once bounded nothing: a backend that accepted TCP but never completed
        // the connection could hold a request until the much longer
        // per-backend response timeout expired.
        let pool_config = &config.connection_pool;
        let client = BackendClient::new(
            Duration::from_secs(pool_config.idle_timeout_secs),
            pool_config.max_idle_per_host,
            Duration::from_secs(config.security.connection_timeout_secs),
        );

        Self { client }
    }

    /// Proxy request to HTTP/1.1 or HTTP/2 backend
    pub async fn proxy_http(
        &self,
        backend: &BackendConfig,
        method: &str,
        path: &str,
        mut headers: HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        // Inject W3C TraceContext + B3 headers so the backend can continue the trace
        otel::inject_current_context_into_map(&mut headers);

        debug!("Proxying to HTTP backend: {} {}", method, path);

        // Build request. Origin form: the connection is already to the backend.
        let method = method.parse::<Method>()?;
        let mut request_builder = Request::builder().method(method).uri(path);

        // Add headers
        for (key, value) in &headers {
            request_builder = request_builder.header(key, value);
        }

        // Add content-type if not specified
        if !headers.contains_key("content-type") && !headers.contains_key("Content-Type") {
            request_builder = request_builder.header("Content-Type", "application/octet-stream");
        }

        let request = request_builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request with timeout
        let timeout = Duration::from_millis(backend.timeout_ms);
        let (response, lease) = self
            .client
            .send_with_retry(backend, request, timeout)
            .await
            .map_err(|e| backend_error(e, "Backend request failed"))?;

        // Check status
        let status = response.status();
        if !status.is_success() {
            warn!("Backend returned error status: {}", status);
        }

        // Read response body
        let body_bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
            .to_bytes();
        lease.release();

        debug!("Received {} bytes from HTTP backend", body_bytes.len());

        Ok(body_bytes.to_vec())
    }

    /// Proxy request to HTTP backend and return full response including headers
    pub async fn proxy_http_full(
        &self,
        backend: &BackendConfig,
        method: &str,
        path: &str,
        mut headers: HashMap<String, String>,
        body: &[u8],
    ) -> anyhow::Result<ProxyResponse> {
        // Inject W3C TraceContext + B3 headers so the backend can continue the trace
        otel::inject_current_context_into_map(&mut headers);

        debug!("Proxying to HTTP backend (full): {} {}", method, path);

        // Build request. Origin form: the connection is already to the backend.
        let method = method.parse::<Method>()?;
        let mut request_builder = Request::builder().method(method).uri(path);

        // Add headers
        for (key, value) in &headers {
            request_builder = request_builder.header(key, value);
        }

        // Add content-type if not specified
        if !headers.contains_key("content-type") && !headers.contains_key("Content-Type") {
            request_builder = request_builder.header("Content-Type", "application/octet-stream");
        }

        let request = request_builder
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|e| anyhow::anyhow!("Failed to build request: {}", e))?;

        // Send request with timeout
        let timeout = Duration::from_millis(backend.timeout_ms);
        let (response, lease) = self
            .client
            .send_with_retry(backend, request, timeout)
            .await
            .map_err(|e| backend_error(e, "Backend request failed"))?;

        // Extract status and headers (use Vec to preserve multiple headers with same name).
        // Strip HTTP/1.1 hop-by-hop headers — these are connection-specific and forbidden
        // in HTTP/2 and HTTP/3 (RFC 9113 §8.2.2, RFC 9114 §4.2). Forwarding them over
        // QUIC/HTTP3 causes ERR_QUIC_PROTOCOL_ERROR in browsers.
        let status = response.status().as_u16();
        let (parts, body_part) = response.into_parts();
        let mut response_headers = parts.headers;
        for name in HOP_BY_HOP {
            response_headers.remove(*name);
        }

        // Read response body
        let body_bytes = body_part
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read response body: {}", e))?
            .to_bytes();
        lease.release();

        debug!(
            "Received {} bytes from HTTP backend (status {})",
            body_bytes.len(),
            status
        );

        Ok(ProxyResponse {
            status,
            headers: response_headers,
            body: body_bytes,
        })
    }

    /// Forward a request to a backend, carrying `HeaderMap` and `Bytes` through
    /// untouched.
    ///
    /// The older `proxy_http_stream` takes `HashMap<String, String>` headers and
    /// a `&[u8]` body, which forces the caller to dismantle a perfectly good
    /// `HeaderMap` into owned Strings, then forces this function to rebuild one —
    /// `Request::builder().header(k, v)` re-parses and re-validates every header
    /// name — and copies the body. The response then went the same way in
    /// reverse, three String allocations per header into a `Vec<(String, String)>`.
    /// Four conversions per request, all of them round trips to the same value.
    ///
    /// Here the caller's `HeaderMap` becomes the request's `HeaderMap` by move,
    /// the body is a `Bytes` clone (a refcount bump), and the response's
    /// `HeaderMap` is returned as-is with only the hop-by-hop entries removed.
    pub async fn proxy_stream(
        &self,
        backend: &BackendConfig,
        method: &Method,
        path: &str,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> anyhow::Result<(
        StatusCode,
        HeaderMap,
        crate::backend_client::BackendBody,
        BackendLease,
    )> {
        otel::inject_current_context_into_headers(&mut headers);

        let mut request = Request::new(Full::new(body));
        *request.method_mut() = method.clone();
        *request.uri_mut() = http::Uri::try_from(path)
            .map_err(|e| anyhow::anyhow!("Invalid backend request path {path}: {e}"))?;
        *request.headers_mut() = headers;

        let timeout = Duration::from_millis(backend.timeout_ms);
        let (response, lease) = self
            .client
            .send_with_retry(backend, request, timeout)
            .await
            .map_err(|e| backend_error(e, "Backend stream request failed"))?;

        let status = response.status();
        let (parts, body_part) = response.into_parts();
        let mut response_headers = parts.headers;
        // Connection-specific headers are forbidden over HTTP/2 and HTTP/3
        // (RFC 9113 §8.2.2, RFC 9114 §4.2); forwarding them makes browsers fail
        // the response with a protocol error.
        for name in HOP_BY_HOP {
            response_headers.remove(*name);
        }

        Ok((status, response_headers, body_part, lease))
    }

    /// Check backend health
    pub async fn check_health(&self, backend: &BackendConfig) -> bool {
        let Some(ref health_endpoint) = backend.health_check else {
            // No health check configured, assume healthy
            return true;
        };
        match backend.backend_type {
            // Every HTTP backend is asked its health endpoint over the
            // transport its requests take
            BackendType::Http1 | BackendType::Http2 | BackendType::Http3 | BackendType::Unix => {
                let request = match Request::builder()
                    .method(Method::GET)
                    .uri(health_endpoint.as_str())
                    .body(Full::new(Bytes::new()))
                {
                    Ok(r) => r,
                    Err(_) => return false,
                };

                let timeout = Duration::from_secs(5);
                match tokio::time::timeout(timeout, self.client.send(backend, request)).await {
                    Ok(Ok((response, lease))) => {
                        let healthy = response.status().is_success();
                        // Read to the end so the connection can be reused.
                        if response.into_body().collect().await.is_ok() {
                            lease.release();
                        }
                        healthy
                    }
                    Ok(Err(_)) => false,
                    Err(_) => {
                        self.client.timed_out(backend);
                        false
                    }
                }
            }
            // A raw TCP backend answers no HTTP: it is up when it accepts
            BackendType::Tcp => {
                tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&backend.address))
                    .await
                    .is_ok_and(|r| r.is_ok())
            }
        }
    }
}

/// A failed send as the pool reports it: a timeout as [`BackendTimeout`],
/// anything else under `context`.
fn backend_error(e: crate::backend_client::SendError, context: &str) -> anyhow::Error {
    match e {
        crate::backend_client::SendError::TimedOut(after) => {
            anyhow::Error::new(BackendTimeout(after))
        }
        crate::backend_client::SendError::Failed(e) => anyhow::anyhow!("{context}: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timed_out_send_is_reported_as_a_backend_timeout() {
        let e = backend_error(
            crate::backend_client::SendError::TimedOut(Duration::from_millis(5)),
            "x",
        );
        assert!(e.is::<BackendTimeout>());
        let e = backend_error(
            crate::backend_client::SendError::Failed(anyhow::anyhow!("refused")),
            "Backend request failed",
        );
        assert_eq!(e.to_string(), "Backend request failed: refused");
    }
}
