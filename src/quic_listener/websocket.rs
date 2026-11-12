//! RFC 9220 WebSocket-over-HTTP/3 tunnelling, to the backend through
//! [`crate::ws_tunnel`].

use std::time::Duration;

use bytes::{Buf, Bytes};
use tracing::debug;

use crate::config::BackendConfig;

/// RFC 9220 WebSocket-over-HTTP/3 tunnel.
///
/// After the client's extended CONNECT with `:protocol: websocket`:
///  1. the backend is opened (an HTTP/1.1 upgrade, its TLS settings, the
///     request's fields; within its `timeout_ms`) and its answer verified
///  2. the client is answered 200 (RFC 9220 section 5, not 101) with the
///     subprotocol and extensions the backend agreed to
///  3. the stream's DATA and the backend's bytes are relayed both ways until
///     either ends, or nothing moves either way for `idle_secs` (0: no limit)
pub(super) async fn ws_h3_tunnel(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    backend: BackendConfig,
    forwarded: http::HeaderMap,
    path_and_query: String,
    host: String,
    idle_secs: u64,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (backend_io, agreed) =
        match crate::ws_tunnel::open_backend(&backend, &path_and_query, &host, forwarded, None)
            .await
        {
            Ok(opened) => opened,
            Err(refused) => {
                let answer = http::Response::builder().status(refused.status).body(())?;
                let _ = stream.send_response(answer).await;
                let _ = stream.finish().await;
                return Err(anyhow::anyhow!("{}: {}", backend.name, refused.reason));
            }
        };

    let mut answer = http::Response::builder().status(http::StatusCode::OK);
    if let Some(protocol) = agreed.protocol {
        answer = answer.header(http::header::SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    if let Some(extensions) = agreed.extensions {
        answer = answer.header(http::header::SEC_WEBSOCKET_EXTENSIONS, extensions);
    }
    stream
        .send_response(answer.body(())?)
        .await
        .map_err(|e| anyhow::anyhow!("answering the client: {e}"))?;

    // Every byte either way passes through the backend's side, which keeps
    // the idle clock
    let backend_io = crate::ws_tunnel::Active::new(backend_io);
    let clock = backend_io.clock();
    let (mut send_half, mut recv_half) = stream.split();
    let (mut backend_read, mut backend_write) = tokio::io::split(backend_io);

    let upstream = async move {
        while let Ok(Some(mut data)) = recv_half.recv_data().await {
            while data.has_remaining() {
                let chunk = data.chunk();
                let n = chunk.len();
                if backend_write.write_all(chunk).await.is_err() {
                    return;
                }
                data.advance(n);
            }
        }
        let _ = backend_write.shutdown().await;
    };
    let downstream = async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match backend_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send_half
                        .send_data(Bytes::copy_from_slice(&buf[..n]))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
        let _ = send_half.finish().await;
    };
    let both = async move {
        tokio::join!(upstream, downstream);
    };
    tokio::pin!(both);

    match (idle_secs > 0).then(|| Duration::from_secs(idle_secs)) {
        None => both.await,
        Some(idle) => loop {
            let quiet_until = clock.last() + idle;
            tokio::select! {
                () = &mut both => break,
                () = tokio::time::sleep_until(quiet_until) => {
                    if clock.last() + idle <= tokio::time::Instant::now() {
                        debug!("WS/H3 tunnel idle for {idle:?}: closed");
                        break;
                    }
                }
            }
        },
    }
    Ok(())
}
