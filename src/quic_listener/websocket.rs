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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::zero_rtt::{throwaway_cert, OneCert, PinnedTo};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A WebSocket server on loopback: the HTTP/1.1 upgrade answered 101
    /// with the key's accept (RFC 6455 section 4.2.2), then every byte
    /// echoed.
    async fn echo_backend() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0u8; 1];
                tcp.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            let head = String::from_utf8(head).unwrap();
            let key = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_string())
                })
                .expect("a Sec-WebSocket-Key");
            let answer = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                crate::ws_tunnel::accept_for(key.as_bytes())
            );
            tcp.write_all(answer.as_bytes()).await.unwrap();
            let (mut r, mut w) = tcp.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        address
    }

    /// RFC 9220 end to end: an HTTP/3 extended CONNECT with `:protocol`
    /// `websocket` is answered 200 and its stream carries the WebSocket both
    /// ways to the backend's HTTP/1.1 upgrade. The h3 fork refused the token
    /// as malformed until it took every token, so this tunnel had never run.
    #[tokio::test]
    async fn a_websocket_over_http3_reaches_its_backend_and_back() {
        let backend: BackendConfig = toml::from_str(&format!(
            "name = \"ws\"\ntype = \"http1\"\naddress = \"{}\"\n",
            echo_backend().await
        ))
        .unwrap();

        let throwaway = throwaway_cert();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).expect("QUIC server"),
            )),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("a server port");
        let addr = server.local_addr().unwrap();
        let serving = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let mut h3: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
                .enable_extended_connect(true)
                .build(h3_quinn::Connection::new(conn))
                .await
                .unwrap();
            let resolver = h3.accept().await.unwrap().expect("the CONNECT");
            let (request, stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(
                request.extensions().get::<h3::ext::Protocol>(),
                Some(&h3::ext::Protocol::WEBSOCKET)
            );
            ws_h3_tunnel(
                stream,
                backend,
                http::HeaderMap::new(),
                "/ws".to_string(),
                "localhost".to_string(),
                30,
            )
            .await
            .unwrap();
            drop(h3);
        });

        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send) = h3::client::builder()
            .enable_extended_connect(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let mut connect = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://localhost/ws")
            .header("sec-websocket-version", "13")
            .body(())
            .unwrap();
        connect
            .extensions_mut()
            .insert(h3::ext::Protocol::WEBSOCKET);
        let mut stream = send.send_request(connect).await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(
            response.status(),
            http::StatusCode::OK,
            "RFC 9220: 200, not 101"
        );

        stream
            .send_data(Bytes::from_static(b"\x81\x05hello"))
            .await
            .unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < 7 {
            let mut data = tokio::time::timeout(Duration::from_secs(5), stream.recv_data())
                .await
                .expect("the echo")
                .unwrap()
                .expect("data");
            echoed.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        assert_eq!(&echoed[..], b"\x81\x05hello");
        stream.finish().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), serving).await;
    }
}
