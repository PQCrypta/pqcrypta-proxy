//! RFC 9220 WebSocket-over-HTTP/3 tunnelling.

use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::Empty;
use hyper::client::conn::http1 as h1_client;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::debug;

/// RFC 9220 WebSocket-over-HTTP/3 tunnel.
///
/// After the client sends an extended CONNECT with `:protocol: websocket`, we:
///  1. Connect to the backend and perform a plain HTTP/1.1 WebSocket upgrade
///  2. Confirm the backend accepted (101 Switching Protocols)
///  3. Accept the client with 200 OK (RFC 9220 §5 — not 101)
///  4. Bridge the HTTP/3 bidi stream ↔ HTTP/1.1 upgraded TCP connection
pub(super) async fn ws_h3_tunnel(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    backend_address: String,
    req_headers: http::HeaderMap,
    path: String,
    query: String,
    host: String,
    idle_secs: u64,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect to backend TCP
    let tcp = TcpStream::connect(&backend_address)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {} failed: {}", backend_address, e))?;

    // HTTP/1.1 connection to backend — `.with_upgrades()` required for 101 support
    let (mut sender, conn) = h1_client::Builder::new()
        .handshake::<TokioIo<TcpStream>, Empty<Bytes>>(TokioIo::new(tcp))
        .await
        .map_err(|e| anyhow::anyhow!("HTTP/1.1 handshake to {} failed: {}", backend_address, e))?;
    tokio::spawn(conn.with_upgrades());

    // Build the HTTP/1.1 WebSocket upgrade request for the backend
    let path_and_query = format!("{}{}", path, query);
    let mut req_builder = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(&path_and_query)
        .version(hyper::Version::HTTP_11);

    if let Some(h) = req_builder.headers_mut() {
        if let Ok(v) = http::HeaderValue::from_str(&host) {
            h.insert(http::header::HOST, v);
        }
        h.insert("connection", http::HeaderValue::from_static("upgrade"));
        h.insert("upgrade", http::HeaderValue::from_static("websocket"));
        for name in &[
            "sec-websocket-key",
            "sec-websocket-version",
            "sec-websocket-extensions",
            "sec-websocket-protocol",
        ] {
            if let (Ok(hn), Some(hv)) = (
                http::header::HeaderName::from_bytes(name.as_bytes()),
                req_headers.get(*name),
            ) {
                h.insert(hn, hv.clone());
            }
        }
        if let Some(origin) = req_headers.get(http::header::ORIGIN) {
            h.insert(http::header::ORIGIN, origin.clone());
        }
    }

    let backend_req = req_builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| anyhow::anyhow!("Failed to build backend request: {}", e))?;

    let backend_resp = sender
        .send_request(backend_req)
        .await
        .map_err(|e| anyhow::anyhow!("Upgrade request to {} failed: {}", backend_address, e))?;

    if backend_resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        return Err(anyhow::anyhow!(
            "Backend {} returned {} (expected 101)",
            backend_address,
            backend_resp.status()
        ));
    }

    // Await the HTTP/1.1 backend upgrade to get the raw TCP stream
    let backend_on_upgrade = hyper::upgrade::on(backend_resp);
    let upgraded = backend_on_upgrade
        .await
        .map_err(|e| anyhow::anyhow!("Backend upgrade failed: {}", e))?;
    let backend_io = TokioIo::new(upgraded);

    // Send 200 OK to accept the HTTP/3 WebSocket session (RFC 9220 §5)
    let h3_accept = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .map_err(|e| anyhow::anyhow!("Failed to build 200 response: {}", e))?;
    stream
        .send_response(h3_accept)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send 200 to client: {}", e))?;

    // Split so send/recv halves can be used independently in the copy loop
    let (mut send_half, mut recv_half) = stream.split();
    let (mut backend_read, mut backend_write) = tokio::io::split(backend_io);

    let idle = Duration::from_secs(idle_secs.max(1));

    // H3 → backend: dedicated task reads DATA frames and writes raw WS bytes to backend
    tokio::spawn(async move {
        while let Ok(Some(buf)) = recv_half.recv_data().await {
            if backend_write.write_all(buf.chunk()).await.is_err() {
                break;
            }
        }
    });

    // Backend → H3: this task, idle timer resets on each received chunk
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let sleep = tokio::time::sleep(idle);
        tokio::pin!(sleep);
        tokio::select! {
            n = backend_read.read(&mut buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if send_half.send_data(data).await.is_err() {
                            break;
                        }
                    }
                }
            }
            _ = sleep => {
                debug!("WS/H3 tunnel: idle timeout ({:?}), closing", idle);
                break;
            }
        }
    }

    Ok(())
}
