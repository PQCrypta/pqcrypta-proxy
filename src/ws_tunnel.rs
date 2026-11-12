//! WebSocket tunnels to a backend, for every transport a client may use.
//!
//! A client opens a WebSocket over HTTP/1.1 (an `Upgrade` GET, RFC 6455), over
//! HTTP/2 (extended CONNECT, RFC 8441) or over HTTP/3 (extended CONNECT, RFC
//! 9220). The backend is always reached the way backends serve WebSockets: an
//! HTTP/1.1 upgrade, over TCP or over TLS with the backend's own TLS settings,
//! carrying the request's fields as an ordinary proxied request carries them.
//! The backend's answer is verified (`Sec-WebSocket-Accept`, RFC 6455 section
//! 4.1) before the client is told yes, and the client is told what the backend
//! agreed to (subprotocol, extensions such as permessage-deflate), so both
//! ends frame the same way.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::time::Instant;

use base64::Engine as _;
use http::{header, HeaderMap, HeaderValue, StatusCode};
use http_body_util::Empty;
use hyper::client::conn::http1;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::BackendConfig;

/// RFC 6455 section 1.3
const ACCEPT_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Why a backend did not open a tunnel, and what the client is answered
#[derive(Debug)]
pub struct Refused {
    pub status: StatusCode,
    pub reason: String,
}

impl Refused {
    fn gateway(reason: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            reason: reason.into(),
        }
    }
}

/// What the backend agreed to, for the client's answer
#[derive(Debug, Default)]
pub struct Agreed {
    /// `Sec-WebSocket-Accept` for the client's own key (HTTP/1.1 clients)
    pub accept: Option<HeaderValue>,
    pub protocol: Option<HeaderValue>,
    pub extensions: Option<HeaderValue>,
}

/// `Sec-WebSocket-Accept` for `key` (RFC 6455 section 4.2.2).
pub fn accept_for(key: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(ACCEPT_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

/// Open the backend's side of a WebSocket.
///
/// Connect (within its `timeout_ms`), upgrade with `headers` (the request's
/// forwardable fields and the forwarding fields the proxy sets), and verify
/// its answer. `client_key` is the HTTP/1.1 client's
/// `Sec-WebSocket-Key`; an HTTP/2 or HTTP/3 client sends none, and the proxy
/// makes one.
pub async fn open_backend(
    backend: &BackendConfig,
    path_and_query: &str,
    host: &str,
    mut headers: HeaderMap,
    client_key: Option<HeaderValue>,
) -> Result<(TokioIo<Upgraded>, Agreed), Refused> {
    let limit = Duration::from_millis(backend.timeout_ms.max(1));
    let opening = async {
        let tcp = TcpStream::connect(&backend.address)
            .await
            .map_err(|e| Refused::gateway(format!("connect to {}: {e}", backend.address)))?;
        let _ = tcp.set_nodelay(true);
        if backend.wants_tls() {
            let connector = crate::http_listener::create_backend_tls_connector(backend)
                .map_err(|e| Refused::gateway(format!("TLS setup for {}: {e}", backend.name)))?;
            let name = backend.tls_sni.clone().unwrap_or_else(|| {
                crate::config::host_without_port(&backend.address)
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_string()
            });
            let name = rustls::pki_types::ServerName::try_from(name)
                .map_err(|e| Refused::gateway(format!("server name of {}: {e}", backend.name)))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .map_err(|e| Refused::gateway(format!("TLS to {}: {e}", backend.address)))?;
            upgrade(
                TokioIo::new(tls),
                path_and_query,
                host,
                &mut headers,
                client_key,
            )
            .await
        } else {
            upgrade(
                TokioIo::new(tcp),
                path_and_query,
                host,
                &mut headers,
                client_key,
            )
            .await
        }
    };
    tokio::time::timeout(limit, opening)
        .await
        .map_err(|_| Refused {
            status: StatusCode::GATEWAY_TIMEOUT,
            reason: format!(
                "{} did not open a WebSocket within {limit:?}",
                backend.address
            ),
        })?
}

async fn upgrade<T>(
    io: TokioIo<T>,
    path_and_query: &str,
    host: &str,
    headers: &mut HeaderMap,
    client_key: Option<HeaderValue>,
) -> Result<(TokioIo<Upgraded>, Agreed), Refused>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = http1::handshake::<_, Empty<bytes::Bytes>>(io)
        .await
        .map_err(|e| Refused::gateway(format!("HTTP/1.1 to the backend: {e}")))?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("WebSocket backend connection ended: {e}");
        }
    });

    let made_key = client_key.is_none();
    let key = client_key.unwrap_or_else(|| {
        let mut nonce = [0u8; 16];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
        HeaderValue::from_str(&base64::engine::general_purpose::STANDARD.encode(nonce))
            .unwrap_or(HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="))
    });
    let expected = accept_for(key.as_bytes());

    if let Ok(v) = HeaderValue::from_str(host) {
        headers.insert(header::HOST, v);
    }
    headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(header::SEC_WEBSOCKET_KEY, key);
    headers
        .entry(header::SEC_WEBSOCKET_VERSION)
        .or_insert(HeaderValue::from_static("13"));

    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri(path_and_query)
        .version(http::Version::HTTP_11)
        .body(Empty::new())
        .map_err(|e| Refused::gateway(format!("upgrade request: {e}")))?;
    *request.headers_mut() = std::mem::take(headers);

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| Refused::gateway(format!("upgrade to the backend: {e}")))?;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Err(Refused {
            status: if response.status().is_client_error() || response.status().is_server_error() {
                response.status()
            } else {
                StatusCode::BAD_GATEWAY
            },
            reason: format!("the backend answered {} (expected 101)", response.status()),
        });
    }
    let answer = response.headers();
    let accept = answer.get(header::SEC_WEBSOCKET_ACCEPT).cloned();
    if accept.as_ref().map(HeaderValue::as_bytes) != Some(expected.as_bytes()) {
        return Err(Refused::gateway(
            "the backend's Sec-WebSocket-Accept does not answer the key",
        ));
    }
    let agreed = Agreed {
        accept: (!made_key).then_some(accept).flatten(),
        protocol: answer.get(header::SEC_WEBSOCKET_PROTOCOL).cloned(),
        extensions: answer.get(header::SEC_WEBSOCKET_EXTENSIONS).cloned(),
    };
    let upgraded = hyper::upgrade::on(response)
        .await
        .map_err(|e| Refused::gateway(format!("backend upgrade: {e}")))?;
    Ok((TokioIo::new(upgraded), agreed))
}

/// Relay `client` and `backend` both ways until either ends, or nothing moves
/// either way for `idle` (`None`: no limit). Returns the bytes moved each way.
pub async fn relay<C, S>(client: &mut C, backend: S, idle: Option<Duration>) -> (u64, u64)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut backend = Active::new(backend);
    let clock = backend.clock();
    let relay = tokio::io::copy_bidirectional(client, &mut backend);
    tokio::pin!(relay);
    let Some(idle) = idle else {
        return relay.await.unwrap_or_default();
    };
    loop {
        let quiet_until = clock.last() + idle;
        tokio::select! {
            done = &mut relay => return done.unwrap_or_default(),
            () = tokio::time::sleep_until(quiet_until) => {
                if clock.last() + idle <= Instant::now() {
                    debug!("WebSocket tunnel idle for {idle:?}: closed");
                    return (0, 0);
                }
            }
        }
    }
}

/// When bytes last moved through an [`Active`] stream
#[derive(Clone)]
pub struct ActivityClock {
    started: Instant,
    last_ms: Arc<AtomicU64>,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            last_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Bytes moved now.
    pub fn moved(&self) {
        let at = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(at, Ordering::Relaxed);
    }

    /// When bytes last moved.
    pub fn last(&self) -> Instant {
        self.started + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

/// A stream that notes on its [`ActivityClock`] when bytes move through it,
/// either way.
pub struct Active<T> {
    inner: T,
    clock: ActivityClock,
}

impl<T> Active<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            clock: ActivityClock::new(),
        }
    }

    pub fn clock(&self) -> ActivityClock {
        self.clock.clone()
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Active<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.clock.moved();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Active<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            this.clock.moved();
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 section 1.3's example
    #[test]
    fn the_accept_answers_the_key() {
        assert_eq!(
            accept_for(b"dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// A tunnel with nothing moving either way is closed; one carrying data
    /// is not.
    #[tokio::test(start_paused = true)]
    async fn an_idle_tunnel_closes() {
        let (mut client, _client_far) = tokio::io::duplex(64);
        let (backend, _backend_far) = tokio::io::duplex(64);
        let moved = relay(&mut client, backend, Some(Duration::from_secs(30))).await;
        assert_eq!(moved, (0, 0));
    }
}
