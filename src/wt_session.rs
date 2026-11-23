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

    /// Open a bidirectional stream to the client.
    fn open_bi(&self) -> impl Future<Output = Result<(Self::Send, Self::Recv), WtClosed>> + Send;

    /// Reset a stream's sending half with a WebTransport application error
    /// code, carried in the WT_APPLICATION_ERROR range of HTTP/3's error
    /// space ([`wt_application_code`]). A stream this end opened is reset
    /// with RESET_STREAM_AT, its reliable size the WebTransport stream
    /// header, so the peer still learns which session the stream was for
    /// (draft-ietf-webtrans-http3 section 4.4); RESET_STREAM where the peer
    /// does not support it.
    fn reset(&self, send: &mut Self::Send, code: u32);

    /// Ask the peer to stop sending on a stream, as [`Self::reset`].
    fn stop(recv: &mut Self::Recv, code: u32);

    /// The sending half's scheduling priority (higher is sent first).
    fn set_priority(send: &Self::Send, priority: i32);

    /// End the session with an application error code and message: a
    /// WT_CLOSE_SESSION capsule on the CONNECT stream, then its FIN
    /// (draft-ietf-webtrans-http3 section 6).
    fn close(&self, code: u32, reason: &str);

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

    /// Resolves when the session has ended: closed by either end, its
    /// CONNECT stream finished or reset, or its connection closed. A session
    /// ends before its connection does wherever the connection carries other
    /// requests, so the connection's end alone is not the session's.
    fn ended(&self) -> impl Future<Output = ()> + Send {
        let connection = self.quic_connection().clone();
        async move {
            connection.closed().await;
        }
    }
}

/// Where WebTransport application error codes start in HTTP/3's error space
/// (draft-ietf-webtrans-http3 section 4.4)
const WT_APPLICATION_ERROR_FIRST: u64 = 0x52e4_a40f_a8db;
/// The WT_SESSION_GONE stream error (section 9.5)
pub const WT_SESSION_GONE: u32 = 0x170d_7b68;
/// The WT_CLOSE_SESSION capsule type (section 6)
const WT_CLOSE_SESSION: u64 = 0x2843;
/// Largest Application Error Message in WT_CLOSE_SESSION (section 6)
const WT_CLOSE_MESSAGE_MAX: usize = 1024;

/// A WebTransport application error code in HTTP/3's error space, skipping
/// the reserved code points of the form 0x1f * N + 0x21 (section 4.4).
pub const fn wt_application_code(n: u32) -> u64 {
    WT_APPLICATION_ERROR_FIRST + n as u64 + (n as u64 / 0x1e)
}

/// The application code an HTTP/3 error code carries, if it is one.
pub fn wt_code_from_http(h: u64) -> Option<u32> {
    if !(WT_APPLICATION_ERROR_FIRST..=0x52e5_ac98_3162).contains(&h)
        || (h - 0x21).is_multiple_of(0x1f)
    {
        return None;
    }
    let shifted = h - WT_APPLICATION_ERROR_FIRST;
    u32::try_from(shifted - shifted / 0x1f).ok()
}

/// The length of the WebTransport header a stream this end opened began
/// with: its signal value (0x54 unidirectional, 0x41 bidirectional, both two
/// bytes as varints) and the session ID; 0 for a stream the peer opened, whose
/// header was the peer's.
fn wt_header_len(id: quinn::StreamId, local: quinn::Side, session_id: u64) -> u64 {
    if id.initiator() != local {
        return 0;
    }
    let session = match session_id {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fff_ffff => 4,
        _ => 8,
    };
    2 + session
}

/// Reset `send` with WebTransport application error `code`, keeping its
/// first `header` bytes reliable when there are any and the peer supports
/// RESET_STREAM_AT.
fn reset_wt_stream(send: &mut quinn::SendStream, code: u32, header: u64) {
    let code = quinn::VarInt::from_u64(wt_application_code(code)).expect("below 2^62");
    if header > 0 && send.reset_at(code, header).is_ok() {
        return;
    }
    let _ = send.reset(code);
}

/// A WT_CLOSE_SESSION capsule, its message cut to 1024 bytes at a character.
pub fn close_session_capsule(code: u32, reason: &str) -> Bytes {
    let mut end = reason.len().min(WT_CLOSE_MESSAGE_MAX);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = Vec::with_capacity(end + 16);
    put_varint(&mut out, WT_CLOSE_SESSION);
    put_varint(&mut out, 4 + end as u64);
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&reason.as_bytes()[..end]);
    Bytes::from(out)
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

    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        let opening = wtransport::Connection::open_bi(self)
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        opening.await.map_err(|e| WtClosed(e.to_string()))
    }

    fn reset(&self, send: &mut Self::Send, code: u32) {
        let id = send.quic_stream().id();
        let session = self.session_id().into_u64();
        reset_wt_stream(
            send.quic_stream_mut(),
            code,
            wt_header_len(id, quinn::Side::Server, session),
        );
    }

    fn stop(recv: &mut Self::Recv, code: u32) {
        let _ = recv
            .quic_stream_mut()
            .stop(quinn::VarInt::from_u64(wt_application_code(code)).expect("below 2^62"));
    }

    fn set_priority(send: &Self::Send, priority: i32) {
        send.set_priority(priority);
    }

    fn close(&self, code: u32, reason: &str) {
        self.close_session(code, reason);
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

    async fn ended(&self) {
        let _ = wtransport::Connection::closed(self).await;
    }
}

// ── Sessions on the HTTP/3 port (h3) ─────────────────────────────────────────

/// Streams and datagrams waiting for a session's handlers
const STREAM_QUEUE: usize = 64;
const DATAGRAM_QUEUE: usize = 256;

/// The WebTransport unidirectional stream type (draft-ietf-webtrans-http3
/// section 4.1)
const WEBTRANSPORT_UNI_STREAM: u64 = 0x54;
/// WT_STREAM: a bidirectional stream's signal value (section 4.2)
const WEBTRANSPORT_BIDI_STREAM: u64 = 0x41;
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
    /// Where a close goes: the task holding the CONNECT stream writes the
    /// WT_CLOSE_SESSION capsule there
    closer: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<(u32, String)>>>,
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
                closer: std::sync::Mutex::new(None),
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

    /// Where [`WtSession::close`] sends the code and message: the task that
    /// holds the CONNECT stream writes them as WT_CLOSE_SESSION.
    pub fn close_requests(&self) -> tokio::sync::oneshot::Receiver<(u32, String)> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self
            .closer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tx);
        rx
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

    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        let (mut send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        // WT_STREAM and the session it belongs to (section 4.2)
        let mut header = Vec::with_capacity(16);
        put_varint(&mut header, WEBTRANSPORT_BIDI_STREAM);
        put_varint(&mut header, self.session_id);
        send.write_all(&header)
            .await
            .map_err(|e| WtClosed(e.to_string()))?;
        Ok((send, Prefixed::new(Bytes::new(), recv)))
    }

    fn reset(&self, send: &mut Self::Send, code: u32) {
        let header = wt_header_len(send.id(), quinn::Side::Server, self.session_id);
        reset_wt_stream(send, code, header);
    }

    fn stop(recv: &mut Self::Recv, code: u32) {
        let _ = recv
            .inner
            .stop(quinn::VarInt::from_u64(wt_application_code(code)).expect("below 2^62"));
    }

    fn set_priority(send: &Self::Send, priority: i32) {
        let _ = send.set_priority(priority);
    }

    fn close(&self, code: u32, reason: &str) {
        let closer = self
            .closer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        match closer {
            Some(tx) => {
                let _ = tx.send((code, reason.to_string()));
            }
            None => self.end(),
        }
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

    /// Its end ([`H3Session::end`], when the CONNECT stream ends or the
    /// session is closed), or its connection's
    fn ended(&self) -> impl Future<Output = ()> + Send {
        let ended = self.ended.clone();
        let connection = self.connection.clone();
        async move {
            tokio::select! {
                () = ended.cancelled() => {}
                _ = connection.closed() => {}
            }
        }
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

    /// Section 4.4's mapping, both ways, skipping the reserved code points.
    #[test]
    fn application_codes_map_into_http3_space() {
        assert_eq!(wt_application_code(0), 0x52e4_a40f_a8db);
        assert_eq!(wt_application_code(u32::MAX), 0x52e5_ac98_3162);
        for n in [0u32, 1, 0x1d, 0x1e, 0x1f, 0x3c, 1000, u32::MAX] {
            let h = wt_application_code(n);
            assert_ne!((h - 0x21) % 0x1f, 0, "{n} lands on a reserved code point");
            assert_eq!(wt_code_from_http(h), Some(n));
        }
        assert_eq!(wt_code_from_http(0x100), None);
    }

    #[test]
    fn header_lengths_count_the_signal_and_the_session() {
        let server_uni = quinn::StreamId::new(quinn::Side::Server, quinn::Dir::Uni, 0);
        let client_bi = quinn::StreamId::new(quinn::Side::Client, quinn::Dir::Bi, 0);
        assert_eq!(wt_header_len(server_uni, quinn::Side::Server, 0), 3);
        assert_eq!(wt_header_len(server_uni, quinn::Side::Server, 4000), 4);
        assert_eq!(wt_header_len(client_bi, quinn::Side::Server, 0), 0);
    }

    #[test]
    fn close_capsules_are_framed_and_cut() {
        let c = close_session_capsule(7, "bye");
        assert_eq!(&c[..], &[0x68, 0x43, 0x07, 0, 0, 0, 7, b'b', b'y', b'e']);
        let long = close_session_capsule(1, &"é".repeat(600));
        assert!(long.len() <= 2 + 2 + 4 + 1024);
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
