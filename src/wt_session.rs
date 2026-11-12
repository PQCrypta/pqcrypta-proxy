//! One WebTransport session, whichever listener accepted it.
//!
//! The WebTransport server (`webtransport_server.rs`, its own port) accepts
//! sessions through the wtransport crate; the HTTP/3 listener accepts them on
//! the HTTP/3 port itself, beside ordinary requests on the same connection
//! (draft-ietf-webtrans-http3). What a session does -- forward its streams and
//! datagrams to the route's backend, run a speed test, feed the telemetry
//! wall -- is written once, against [`WtSession`], and runs on either.
//!
//! On the HTTP/3 port the connection's accept loop owns the streams: it hands
//! each WebTransport stream and datagram to its session ([`H3SessionFeed`]),
//! and the session reads them from bounded queues ([`H3Session`]). A stream
//! for a session whose queue is full, or that has ended, is refused rather
//! than held.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;

/// The session has ended: no more streams or datagrams come from it.
#[derive(Debug, Clone)]
pub struct WtClosed(pub String);

impl std::fmt::Display for WtClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebTransport session closed: {}", self.0)
    }
}

impl std::error::Error for WtClosed {}

/// What a WebTransport session offers its handlers.
pub trait WtSession: Send + Sync + 'static {
    /// The sending half of a stream
    type Send: AsyncWrite + Send + Unpin + 'static;
    /// The receiving half of a stream
    type Recv: AsyncRead + Send + Unpin + 'static;

    /// The next bidirectional stream the client opens.
    fn accept_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), WtClosed>> + Send;

    /// The next unidirectional stream the client opens.
    fn accept_uni(&self) -> impl Future<Output = Result<Self::Recv, WtClosed>> + Send;

    /// Open a unidirectional stream to the client.
    fn open_uni(&self) -> impl Future<Output = Result<Self::Send, WtClosed>> + Send;

    /// The next datagram the client sends.
    fn receive_datagram(&self) -> impl Future<Output = Result<Bytes, WtClosed>> + Send;

    /// Send a datagram to the client.
    fn send_datagram(&self, payload: &[u8]) -> Result<(), WtClosed>;

    /// The smoothed round-trip time of the connection's initial path (noq
    /// keeps one per path); zero before it has an estimate.
    fn rtt(&self) -> Duration {
        self.quic_connection()
            .rtt(quinn::PathId::ZERO)
            .unwrap_or_default()
    }

    /// The QUIC connection the session runs on.
    fn quic_connection(&self) -> &quinn::Connection;
}

// ── The WebTransport server's sessions (wtransport) ─────────────────────────

impl WtSession for wtransport::Connection {
    type Send = wtransport::stream::SendStream;
    type Recv = wtransport::stream::RecvStream;

    async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        wtransport::Connection::accept_bi(self)
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    async fn accept_uni(&self) -> Result<Self::Recv, WtClosed> {
        wtransport::Connection::accept_uni(self)
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    async fn open_uni(&self) -> Result<Self::Send, WtClosed> {
        let opening = wtransport::Connection::open_uni(self)
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        opening.await.map_err(|e| WtClosed(e.to_string()))
    }

    async fn receive_datagram(&self) -> Result<Bytes, WtClosed> {
        wtransport::Connection::receive_datagram(self)
            .await
            .map(|d| d.payload())
            .map_err(|e| WtClosed(e.to_string()))
    }

    fn send_datagram(&self, payload: &[u8]) -> Result<(), WtClosed> {
        wtransport::Connection::send_datagram(self, payload).map_err(|e| WtClosed(e.to_string()))
    }

    fn rtt(&self) -> Duration {
        wtransport::Connection::rtt(self)
    }

    fn quic_connection(&self) -> &quinn::Connection {
        wtransport::Connection::quic_connection(self)
    }
}

// ── Sessions on the HTTP/3 port (h3) ─────────────────────────────────────────

/// Streams and datagrams waiting for a session's handlers
const STREAM_QUEUE: usize = 64;
const DATAGRAM_QUEUE: usize = 256;

/// The WebTransport unidirectional stream type (draft-ietf-webtrans-http3
/// section 4.1)
const WEBTRANSPORT_UNI_STREAM: u64 = 0x54;
/// WT_BUFFERED_STREAM_REJECTED: a stream refused because its session cannot
/// take it (draft-ietf-webtrans-http3 section 9.5)
pub const WT_BUFFERED_STREAM_REJECTED: u32 = 0x3994_bd84;

/// A stream's received bytes: what arrived with its header, then the rest.
pub struct Prefixed<R> {
    prefix: Bytes,
    inner: R,
}

impl<R> Prefixed<R> {
    pub const fn new(prefix: Bytes, inner: R) -> Self {
        Self { prefix, inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix.has_remaining() {
            let n = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..n]);
            this.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// A session on the HTTP/3 port, as its handlers see it.
pub struct H3Session {
    session_id: u64,
    connection: quinn::Connection,
    bi: Mutex<mpsc::Receiver<(quinn::SendStream, Prefixed<quinn::RecvStream>)>>,
    uni: Mutex<mpsc::Receiver<Prefixed<quinn::RecvStream>>>,
    datagrams: Mutex<mpsc::Receiver<Bytes>>,
    ended: CancellationToken,
}

/// The accept loop's side of an [`H3Session`]: where it delivers the
/// session's streams and datagrams.
#[derive(Clone)]
pub struct H3SessionFeed {
    bi: mpsc::Sender<(quinn::SendStream, Prefixed<quinn::RecvStream>)>,
    uni: mpsc::Sender<Prefixed<quinn::RecvStream>>,
    datagrams: mpsc::Sender<Bytes>,
    ended: CancellationToken,
}

impl H3Session {
    /// A session for the CONNECT that was stream `session_id` of
    /// `connection`, the feed the accept loop delivers to it through, and the
    /// receiver its datagrams are routed to.
    pub fn new(session_id: u64, connection: quinn::Connection) -> (Arc<Self>, H3SessionFeed) {
        let (bi_tx, bi_rx) = mpsc::channel(STREAM_QUEUE);
        let (uni_tx, uni_rx) = mpsc::channel(STREAM_QUEUE);
        let (dg_tx, dg_rx) = mpsc::channel(DATAGRAM_QUEUE);
        let ended = CancellationToken::new();
        (
            Arc::new(Self {
                session_id,
                connection,
                bi: Mutex::new(bi_rx),
                uni: Mutex::new(uni_rx),
                datagrams: Mutex::new(dg_rx),
                ended: ended.clone(),
            }),
            H3SessionFeed {
                bi: bi_tx,
                uni: uni_tx,
                datagrams: dg_tx,
                ended,
            },
        )
    }

    /// The Quarter Stream ID its datagrams carry (RFC 9297 section 2.1).
    pub const fn quarter_stream_id(&self) -> u64 {
        self.session_id / 4
    }

    /// End the session: its handlers' accepts return [`WtClosed`].
    pub fn end(&self) {
        self.ended.cancel();
    }

    async fn next<T>(&self, queue: &Mutex<mpsc::Receiver<T>>) -> Result<T, WtClosed> {
        let mut queue = queue.lock().await;
        tokio::select! {
            item = queue.recv() => item.ok_or_else(|| WtClosed("the connection ended".into())),
            () = self.ended.cancelled() => Err(WtClosed("the session ended".into())),
        }
    }
}

impl H3SessionFeed {
    /// Whether the session has ended (its feed can be dropped).
    pub fn has_ended(&self) -> bool {
        self.ended.is_cancelled() || self.bi.is_closed()
    }

    /// Hand a bidirectional stream to the session; refused with
    /// WT_BUFFERED_STREAM_REJECTED when it cannot take one now.
    pub fn deliver_bi(&self, send: quinn::SendStream, recv: Prefixed<quinn::RecvStream>) {
        if let Err(e) = self.bi.try_send((send, recv)) {
            let (mut send, mut recv) = e.into_inner();
            let code = quinn::VarInt::from_u32(WT_BUFFERED_STREAM_REJECTED);
            let _ = send.reset(code);
            let _ = recv.inner.stop(code);
        }
    }

    /// Hand a unidirectional stream to the session; refused as
    /// [`Self::deliver_bi`].
    pub fn deliver_uni(&self, recv: Prefixed<quinn::RecvStream>) {
        if let Err(e) = self.uni.try_send(recv) {
            let mut recv = e.into_inner();
            let _ = recv
                .inner
                .stop(quinn::VarInt::from_u32(WT_BUFFERED_STREAM_REJECTED));
        }
    }

    /// The sender the connection's datagram router delivers this session's
    /// datagrams to.
    pub fn datagram_sender(&self) -> mpsc::Sender<Bytes> {
        self.datagrams.clone()
    }
}

impl WtSession for H3Session {
    type Send = quinn::SendStream;
    type Recv = Prefixed<quinn::RecvStream>;

    async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        self.next(&self.bi).await
    }

    async fn accept_uni(&self) -> Result<Self::Recv, WtClosed> {
        self.next(&self.uni).await
    }

    async fn open_uni(&self) -> Result<Self::Send, WtClosed> {
        let mut send = self
            .connection
            .open_uni()
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        // The stream type and the session it belongs to, then its data
        let mut header = Vec::with_capacity(16);
        put_varint(&mut header, WEBTRANSPORT_UNI_STREAM);
        put_varint(&mut header, self.session_id);
        send.write_all(&header)
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        Ok(send)
    }

    async fn receive_datagram(&self) -> Result<Bytes, WtClosed> {
        self.next(&self.datagrams).await
    }

    fn send_datagram(&self, payload: &[u8]) -> Result<(), WtClosed> {
        let mut datagram = Vec::with_capacity(payload.len() + 8);
        put_varint(&mut datagram, self.quarter_stream_id());
        datagram.extend_from_slice(payload);
        self.connection
            .send_datagram(Bytes::from(datagram))
            .map_err(|e| WtClosed(e.to_string()))
    }

    fn quic_connection(&self) -> &quinn::Connection {
        &self.connection
    }
}

/// A QUIC variable-length integer (RFC 9000 section 16), in its shortest
/// form; `value` is below 2^62.
fn put_varint(out: &mut Vec<u8>, value: u64) {
    let (len, tag) = match value {
        0..=0x3f => (1, 0x00),
        0x40..=0x3fff => (2, 0x40),
        0x4000..=0x3fff_ffff => (4, 0x80),
        _ => (8, 0xc0),
    };
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - len..]);
    out[start] |= tag;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn varints_take_the_shortest_form() {
        let enc = |v| {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            out
        };
        assert_eq!(enc(0x25), [0x25]);
        assert_eq!(enc(WEBTRANSPORT_UNI_STREAM), [0x40, 0x54]);
        assert_eq!(enc(0x3fff), [0x7f, 0xff]);
        assert_eq!(enc(0x4000), [0x80, 0x00, 0x40, 0x00]);
        assert_eq!(enc(1 << 40), [0xc0, 0, 1, 0, 0, 0, 0, 0]);
    }

    /// What arrived with a stream's header is read before the rest.
    #[tokio::test]
    async fn a_prefix_is_read_first() {
        let mut stream = Prefixed::new(Bytes::from_static(b"head-"), &b"rest"[..]);
        let mut all = Vec::new();
        stream.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"head-rest");
    }
}
