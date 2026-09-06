//! WebSocket passthrough tunnel over HTTP/1.1 upgrades.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::{IntoResponse, Response},
};
use hyper::client::conn::http1 as h1_client;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, warn};

// ============================================================================
// WebSocket Passthrough Tunnel
// ============================================================================

/// Proxy an HTTP/1.1 WebSocket upgrade request to a backend, then pipe the
/// raw upgraded TCP stream bidirectionally between client and backend.
///
/// Flow:
///   1. Open TCP (optionally TLS) connection to `backend_address`
///   2. HTTP/1.1 handshake with `.with_upgrades()` enabled
///   3. Forward the upgrade GET with all Sec-WebSocket-* headers
///   4. Verify the backend returns 101 Switching Protocols
///   5. Return 101 to the client; spawn a copy-loop that awaits both upgrade
///      futures and pipes bytes until one side closes or idle-timeout fires
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_websocket_tunnel(
    backend_address: &str,
    use_https: bool,
    req_headers: &HeaderMap,
    on_upgrade: OnUpgrade,
    path: &str,
    query: &str,
    host: &str,
    idle_timeout_secs: u64,
) -> Response {
    let tcp = match TcpStream::connect(backend_address).await {
        Ok(s) => s,
        Err(e) => {
            error!(
                "WS tunnel: TCP connect to {} failed: {}",
                backend_address, e
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let sni_host = backend_address
        .split(':')
        .next()
        .unwrap_or(host)
        .to_string();

    if use_https {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = root_store.add(cert);
        }
        let tls_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(tls_cfg));

        let server_name = match rustls::pki_types::ServerName::try_from(sni_host.as_str()) {
            Ok(n) => n.to_owned(),
            Err(e) => {
                error!("WS tunnel: invalid TLS server name '{}': {}", sni_host, e);
                return StatusCode::BAD_GATEWAY.into_response();
            }
        };
        match connector.connect(server_name, tcp).await {
            Ok(tls_stream) => {
                ws_run_tunnel(
                    tls_stream,
                    req_headers,
                    on_upgrade,
                    path,
                    query,
                    host,
                    backend_address,
                    idle_timeout_secs,
                )
                .await
            }
            Err(e) => {
                error!(
                    "WS tunnel: TLS handshake to {} failed: {}",
                    backend_address, e
                );
                StatusCode::BAD_GATEWAY.into_response()
            }
        }
    } else {
        ws_run_tunnel(
            tcp,
            req_headers,
            on_upgrade,
            path,
            query,
            host,
            backend_address,
            idle_timeout_secs,
        )
        .await
    }
}

/// Inner WebSocket tunnel — generic over the concrete stream type to avoid boxing.
/// Performs the HTTP/1.1 upgrade handshake with the backend and sets up the copy loop.
#[allow(clippy::too_many_arguments)]
async fn ws_run_tunnel<S>(
    stream: S,
    req_headers: &HeaderMap,
    on_upgrade: OnUpgrade,
    path: &str,
    query: &str,
    host: &str,
    backend_address: &str,
    idle_timeout_secs: u64,
) -> Response
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // HTTP/1.1 handshake — `.with_upgrades()` is required for 101 support
    let (mut sender, conn) = match h1_client::Builder::new()
        .handshake::<TokioIo<S>, Body>(TokioIo::new(stream))
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            error!(
                "WS tunnel: HTTP/1.1 handshake to {} failed: {}",
                backend_address, e
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };
    tokio::spawn(conn.with_upgrades());

    // Build upgrade request
    let path_and_query = format!("{}{}", path, query);
    let mut backend_req_builder = Request::builder()
        .method(Method::GET)
        .uri(&path_and_query)
        .version(hyper::Version::HTTP_11);

    if let Some(h) = backend_req_builder.headers_mut() {
        if let Ok(v) = HeaderValue::from_str(host) {
            h.insert(header::HOST, v);
        }
        h.insert("connection", HeaderValue::from_static("upgrade"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));

        for name in &[
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        ] {
            if let (Ok(hn), Some(hv)) = (
                header::HeaderName::from_bytes(name.as_bytes()),
                req_headers.get(*name),
            ) {
                h.insert(hn, hv.clone());
            }
        }
        if let Some(origin) = req_headers.get(header::ORIGIN) {
            h.insert(header::ORIGIN, origin.clone());
        }
    }

    let backend_req = match backend_req_builder.body(Body::empty()) {
        Ok(r) => r,
        Err(e) => {
            error!("WS tunnel: failed to build backend request: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let backend_resp = match sender.send_request(backend_req).await {
        Ok(r) => r,
        Err(e) => {
            error!(
                "WS tunnel: upgrade request to {} failed: {}",
                backend_address, e
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        warn!(
            "WS tunnel: backend {} returned {} (expected 101)",
            backend_address,
            backend_resp.status()
        );
        return (backend_resp.status(), "WebSocket backend rejected upgrade").into_response();
    }

    // Read response headers BEFORE consuming the response for the upgrade future
    let ws_accept = backend_resp.headers().get("sec-websocket-accept").cloned();
    let ws_protocol = backend_resp
        .headers()
        .get("sec-websocket-protocol")
        .cloned();
    let backend_on_upgrade = hyper::upgrade::on(backend_resp);

    // Build 101 response for the client
    let mut resp_builder = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "websocket");
    if let Some(v) = ws_accept {
        resp_builder = resp_builder.header("sec-websocket-accept", v);
    }
    if let Some(v) = ws_protocol {
        resp_builder = resp_builder.header("sec-websocket-protocol", v);
    }
    let client_resp = match resp_builder.body(Body::empty()) {
        Ok(r) => r,
        Err(e) => {
            error!("WS tunnel: failed to build 101 response: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Spawn the bidirectional copy loop.
    // `on_upgrade` resolves after hyper processes our 101 response and yields the raw socket.
    // `backend_on_upgrade` resolves immediately (the backend already sent 101).
    let idle = if idle_timeout_secs > 0 {
        Some(Duration::from_secs(idle_timeout_secs))
    } else {
        None
    };

    tokio::spawn(async move {
        let c = match on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                debug!("WS tunnel: client upgrade failed: {}", e);
                return;
            }
        };
        let b = match backend_on_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                debug!("WS tunnel: backend upgrade failed: {}", e);
                return;
            }
        };
        // `TokioIo` bridges hyper::rt::Read/Write ↔ tokio::io::AsyncRead/Write
        // in both directions, so wrapping Upgraded gives us tokio-compatible streams.
        let mut c = TokioIo::new(c);
        let mut b = TokioIo::new(b);

        if let Some(dur) = idle {
            ws_copy_idle(&mut c, &mut b, dur).await;
        } else {
            let _ = tokio::io::copy_bidirectional(&mut c, &mut b).await;
        }
    });

    client_resp
}

/// Bidirectional copy with per-idle-interval timeout.
/// The sleep is recreated each iteration so any activity resets the idle clock.
async fn ws_copy_idle<A, B>(client: &mut A, backend: &mut B, idle: Duration)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut c_buf = vec![0u8; 8 * 1024];
    let mut b_buf = vec![0u8; 8 * 1024];

    loop {
        tokio::select! {
            res = client.read(&mut c_buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if backend.write_all(&c_buf[..n]).await.is_err() { break; } }
                }
            }
            res = backend.read(&mut b_buf) => {
                match res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => { if client.write_all(&b_buf[..n]).await.is_err() { break; } }
                }
            }
            _ = tokio::time::sleep(idle) => {
                debug!("WS tunnel: idle timeout ({:?}), closing", idle);
                break;
            }
        }
    }
}
