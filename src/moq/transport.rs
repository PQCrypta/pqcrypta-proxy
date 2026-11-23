//! What a MOQT session runs on.
//!
//! A QUIC connection that negotiated a MOQT
//! ALPN (native QUIC, draft-ietf-moq-transport section 6.2.2), or a
//! WebTransport session that negotiated a MOQT protocol (section 6.2.1), on
//! the HTTP/3 port or the WebTransport server's own. The session is written
//! once, against [`Transport`].
//!
//! Stream error codes are MOQT's (section 12.5); on WebTransport they are
//! carried in the WT_APPLICATION_ERROR range ([`crate::wt_session`]). The
//! session's own close is CONNECTION_CLOSE on native QUIC and
//! WT_CLOSE_SESSION on WebTransport (section 6.6).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::wt_session::WtSession;

/// The transport has ended.
#[derive(Debug, Clone)]
pub struct Closed(pub String);

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport closed: {}", self.0)
    }
}

/// A stream's sending half.
pub trait SendHalf: AsyncWrite + Send + Unpin + 'static {
    fn reset(&mut self, code: u32);
    /// Higher is sent first.
    fn set_priority(&self, priority: i32);
}

/// A stream's receiving half.
pub trait RecvHalf: AsyncRead + Send + Unpin + 'static {
    fn stop(&mut self, code: u32);
}

/// Streams and datagrams, whichever way the session arrived.
pub trait Transport: Send + Sync + 'static {
    type Send: SendHalf;
    type Recv: RecvHalf;

    fn accept_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), Closed>> + Send;
    fn accept_uni(&self) -> impl Future<Output = Result<Self::Recv, Closed>> + Send;
    fn open_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), Closed>> + Send;
    fn open_uni(&self) -> impl Future<Output = Result<Self::Send, Closed>> + Send;
    fn recv_datagram(&self) -> impl Future<Output = Result<Bytes, Closed>> + Send;
    fn send_datagram(&self, datagram: Bytes) -> Result<(), Closed>;
    /// The largest datagram the path carries now, if datagrams are on.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Close the session with a MOQT session error code (section 12.2).
    fn close(&self, code: u64, reason: &str);
    /// Resolves when the transport has closed for any reason.
    fn closed(&self) -> impl Future<Output = ()> + Send;
    fn peer(&self) -> SocketAddr;
    /// "quic" or "webtransport", for the admin view and metrics.
    fn kind(&self) -> &'static str;
    /// The QUIC connection underneath, for its path statistics.
    fn quic(&self) -> &quinn::Connection;
}

// ── Native QUIC ─────────────────────────────────────────────────────────────

/// A QUIC connection whose ALPN is a MOQT version, and its peer's address.
#[derive(Clone)]
pub struct QuicTransport(pub quinn::Connection, pub SocketAddr);

impl SendHalf for quinn::SendStream {
    fn reset(&mut self, code: u32) {
        let _ = quinn::SendStream::reset(self, quinn::VarInt::from_u32(code));
    }
    fn set_priority(&self, priority: i32) {
        let _ = quinn::SendStream::set_priority(self, priority);
    }
}

impl RecvHalf for quinn::RecvStream {
    fn stop(&mut self, code: u32) {
        let _ = quinn::RecvStream::stop(self, quinn::VarInt::from_u32(code));
    }
}

impl Transport for QuicTransport {
    type Send = quinn::SendStream;
    type Recv = quinn::RecvStream;

    async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), Closed> {
        self.0.accept_bi().await.map_err(|e| Closed(e.to_string()))
    }
    async fn accept_uni(&self) -> Result<Self::Recv, Closed> {
        self.0.accept_uni().await.map_err(|e| Closed(e.to_string()))
    }
    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv), Closed> {
        self.0.open_bi().await.map_err(|e| Closed(e.to_string()))
    }
    async fn open_uni(&self) -> Result<Self::Send, Closed> {
        self.0.open_uni().await.map_err(|e| Closed(e.to_string()))
    }
    async fn recv_datagram(&self) -> Result<Bytes, Closed> {
        self.0
            .read_datagram()
            .await
            .map_err(|e| Closed(e.to_string()))
    }
    fn send_datagram(&self, datagram: Bytes) -> Result<(), Closed> {
        self.0
            .send_datagram(datagram)
            .map_err(|e| Closed(e.to_string()))
    }
    fn max_datagram_size(&self) -> Option<usize> {
        self.0.max_datagram_size()
    }
    fn close(&self, code: u64, reason: &str) {
        let code = quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::from_u32(1));
        self.0.close(code, reason.as_bytes());
    }
    async fn closed(&self) {
        self.0.closed().await;
    }
    fn peer(&self) -> SocketAddr {
        self.1
    }
    fn kind(&self) -> &'static str {
        "quic"
    }
    fn quic(&self) -> &quinn::Connection {
        &self.0
    }
}

// ── WebTransport ────────────────────────────────────────────────────────────

/// A WebTransport session whose protocol is a MOQT version.
pub struct WtTransport<S: WtSession> {
    session: Arc<S>,
    peer: SocketAddr,
}

impl<S: WtSession> WtTransport<S> {
    pub fn new(session: Arc<S>, peer: SocketAddr) -> Self {
        Self { session, peer }
    }
}

/// A WebTransport stream half, with the session type that knows how to
/// reset it.
pub struct WtSend<S: WtSession>(S::Send, Arc<S>);
pub struct WtRecv<S: WtSession>(S::Recv, std::marker::PhantomData<fn() -> S>);

impl<S: WtSession> AsyncWrite for WtSend<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl<S: WtSession> AsyncRead for WtRecv<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: WtSession> SendHalf for WtSend<S> {
    fn reset(&mut self, code: u32) {
        self.1.reset(&mut self.0, code);
    }
    fn set_priority(&self, priority: i32) {
        S::set_priority(&self.0, priority);
    }
}

impl<S: WtSession> RecvHalf for WtRecv<S> {
    fn stop(&mut self, code: u32) {
        S::stop(&mut self.0, code);
    }
}

fn wrap<S: WtSession>(session: &Arc<S>, pair: (S::Send, S::Recv)) -> (WtSend<S>, WtRecv<S>) {
    (
        WtSend(pair.0, Arc::clone(session)),
        WtRecv(pair.1, std::marker::PhantomData),
    )
}

impl<S: WtSession> Transport for WtTransport<S> {
    type Send = WtSend<S>;
    type Recv = WtRecv<S>;

    async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), Closed> {
        self.session
            .accept_bi()
            .await
            .map(|p| wrap(&self.session, p))
            .map_err(|e| Closed(e.0))
    }
    async fn accept_uni(&self) -> Result<Self::Recv, Closed> {
        self.session
            .accept_uni()
            .await
            .map(|r| WtRecv(r, std::marker::PhantomData))
            .map_err(|e| Closed(e.0))
    }
    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv), Closed> {
        self.session
            .open_bi()
            .await
            .map(|p| wrap(&self.session, p))
            .map_err(|e| Closed(e.0))
    }
    async fn open_uni(&self) -> Result<Self::Send, Closed> {
        self.session
            .open_uni()
            .await
            .map(|s| WtSend(s, Arc::clone(&self.session)))
            .map_err(|e| Closed(e.0))
    }
    async fn recv_datagram(&self) -> Result<Bytes, Closed> {
        self.session
            .receive_datagram()
            .await
            .map_err(|e| Closed(e.0))
    }
    fn send_datagram(&self, datagram: Bytes) -> Result<(), Closed> {
        self.session
            .send_datagram(&datagram)
            .map_err(|e| Closed(e.0))
    }
    fn max_datagram_size(&self) -> Option<usize> {
        // The HTTP/3 datagram's Quarter Stream ID takes up to 8 bytes
        self.session
            .quic_connection()
            .max_datagram_size()
            .map(|m| m.saturating_sub(8))
    }
    fn close(&self, code: u64, reason: &str) {
        self.session
            .close(u32::try_from(code).unwrap_or(u32::MAX), reason);
    }
    async fn closed(&self) {
        // The session ends when its accepts do; the connection's end ends it too
        let conn = self.session.quic_connection().clone();
        conn.closed().await;
    }
    fn peer(&self) -> SocketAddr {
        self.peer
    }
    fn kind(&self) -> &'static str {
        "webtransport"
    }
    fn quic(&self) -> &quinn::Connection {
        self.session.quic_connection()
    }
}
