use crate::driver::streams::bilocal::StreamBiLocalQuic;
use crate::driver::streams::unilocal::StreamUniLocalQuic;
use crate::driver::streams::ProtoWriteError;
use crate::driver::streams::QuicRecvStream;
use crate::driver::streams::QuicSendStream;
use crate::error::ClosedStream;
use crate::error::StreamOpeningError;
use crate::error::StreamReadError;
use crate::error::StreamReadExactError;
use crate::error::StreamWriteError;
use crate::SessionId;
use crate::StreamId;
use crate::VarInt;
use std::future::Future;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use tokio::io::ReadBuf;
use wtransport_proto::stream_header::StreamHeader;

/// Where WebTransport application error codes start in HTTP/3's error
/// space (draft-ietf-webtrans-http3 section 4.4).
const WT_APPLICATION_ERROR_FIRST: u64 = 0x52e4_a40f_a8db;
const WT_APPLICATION_ERROR_LAST: u64 = 0x52e5_ac98_3162;

/// An application error code as it goes on the wire: in the
/// WT_APPLICATION_ERROR range, skipping the code points of the form
/// 0x1f * N + 0x21 that HTTP/3 reserves (section 4.4). Application codes are
/// 32 bits; a larger one is carried as the largest.
pub(crate) fn wt_code_to_http(code: VarInt) -> VarInt {
    let n = u64::from(u32::try_from(code.into_inner()).unwrap_or(u32::MAX));
    VarInt::try_from_u64(WT_APPLICATION_ERROR_FIRST + n + n / 0x1e).expect("below 2^62")
}

/// The application error code a received HTTP/3 code carries; one outside
/// the WT_APPLICATION_ERROR range is given as it came.
pub(crate) fn http_code_to_wt(code: VarInt) -> VarInt {
    let h = code.into_inner();
    if !(WT_APPLICATION_ERROR_FIRST..=WT_APPLICATION_ERROR_LAST).contains(&h) || (h - 0x21) % 0x1f == 0 {
        return code;
    }
    let shifted = h - WT_APPLICATION_ERROR_FIRST;
    VarInt::try_from_u64(shifted - shifted / 0x1f).expect("32 bits")
}

fn map_write_error(e: StreamWriteError) -> StreamWriteError {
    match e {
        StreamWriteError::Stopped(code) => StreamWriteError::Stopped(http_code_to_wt(code)),
        other => other,
    }
}

fn map_read_error(e: StreamReadError) -> StreamReadError {
    match e {
        StreamReadError::Reset(code) => StreamReadError::Reset(http_code_to_wt(code)),
        other => other,
    }
}

/// A stream that can only be used to send data.
#[derive(Debug)]
pub struct SendStream(QuicSendStream);

impl SendStream {
    #[inline(always)]
    pub(crate) fn new(stream: QuicSendStream) -> Self {
        Self(stream)
    }

    /// Writes bytes to the stream.
    ///
    /// On success, returns the number of bytes written.
    /// Congestion and flow control may cause this to be shorter than `buf.len()`,
    /// indicating that only a prefix of `buf` was written.
    #[inline(always)]
    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, StreamWriteError> {
        self.0.write(buf).await.map_err(map_write_error)
    }

    /// Convenience method to write an entire buffer to the stream.
    #[inline(always)]
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), StreamWriteError> {
        self.0.write_all(buf).await.map_err(map_write_error)
    }

    /// Shuts down the send stream gracefully.
    ///
    /// No new data may be written after calling this method. Completes when the peer has
    /// acknowledged all sent data, retransmitting data as needed.
    #[inline(always)]
    pub async fn finish(&mut self) -> Result<(), StreamWriteError> {
        self.0.finish().await.map_err(map_write_error)
    }

    /// Returns the [`StreamId`] associated.
    #[inline(always)]
    pub fn id(&self) -> StreamId {
        self.0.id()
    }

    /// Sets the priority of the send stream.
    ///
    /// Every send stream has an initial priority of 0. Locally buffered data from streams with
    /// higher priority will be transmitted before data from streams with lower priority. Changing
    /// the priority of a stream with pending data may only take effect after that data has been
    /// transmitted. Using many different priority levels per connection may have a negative
    /// impact on performance.
    #[inline(always)]
    pub fn set_priority(&self, priority: i32) {
        self.0.set_priority(priority);
    }

    /// Gets the priority of the send stream.
    ///
    /// # Panics
    ///
    /// If `reset` was called.
    #[inline(always)]
    pub fn priority(&self) -> i32 {
        self.0.priority()
    }

    /// Closes the send stream immediately.
    ///
    /// No new data can be written after calling this method. Locally buffered data is dropped, and
    /// previously transmitted data will no longer be retransmitted if lost. If an attempt has
    /// already been made to finish the stream, the peer may still receive all written data.
    ///
    /// If called more than once, subsequent calls will result in [`ClosedStream`] error.
    #[inline(always)]
    pub fn reset(&mut self, error_code: VarInt) -> Result<(), ClosedStream> {
        self.0.reset(wt_code_to_http(error_code))
    }

    /// Passively waits for the send stream to be stopped for any reason.
    ///
    /// Returns [`StreamWriteError::Closed`] if the stream was already `finish`ed or `reset`.
    ///
    /// Otherwise returns [`StreamWriteError::Stopped`] with an error code from the peer.
    #[inline(always)]
    pub async fn stopped(&mut self) -> StreamWriteError {
        map_write_error(self.0.stopped().await)
    }

    /// Returns a reference to the underlying QUIC stream.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_stream(&self) -> &quinn::SendStream {
        self.0.quic_stream()
    }

    /// Returns a mutable reference to the underlying QUIC stream.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_stream_mut(&mut self) -> &mut quinn::SendStream {
        self.0.quic_stream_mut()
    }
}

/// A stream that can only be used to receive data.
#[derive(Debug)]
pub struct RecvStream(QuicRecvStream);

impl RecvStream {
    #[inline(always)]
    pub(crate) fn new(stream: QuicRecvStream) -> Self {
        Self(stream)
    }

    /// Read data contiguously from the stream.
    ///
    /// On success, returns the number of bytes read into `buf`.
    #[inline(always)]
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, StreamReadError> {
        self.0.read(buf).await.map_err(map_read_error)
    }

    /// Reads an exact number of bytes contiguously from the stream.
    ///
    /// If the stream terminates before the entire length has been read, it
    /// returns [`StreamReadExactError::FinishedEarly`].
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), StreamReadExactError> {
        self.0.read_exact(buf).await.map_err(|e| match e {
            StreamReadExactError::Read(e) => StreamReadExactError::Read(map_read_error(e)),
            other => other,
        })
    }

    /// Stops accepting data on the stream.
    ///
    /// Discards unread data and notifies the peer to stop transmitting.
    pub fn stop(mut self, error_code: VarInt) {
        let _ = self.0.stop(wt_code_to_http(error_code));
    }

    /// Returns the [`StreamId`] associated.
    #[inline(always)]
    pub fn id(&self) -> StreamId {
        self.0.id()
    }

    /// Returns a reference to the underlying QUIC stream.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_stream(&self) -> &quinn::RecvStream {
        self.0.quic_stream()
    }

    /// Returns a mutable reference to the underlying QUIC stream.
    #[cfg(feature = "quinn")]
    #[cfg_attr(docsrs, doc(cfg(feature = "quinn")))]
    #[inline(always)]
    pub fn quic_stream_mut(&mut self) -> &mut quinn::RecvStream {
        self.0.quic_stream_mut()
    }
}

/// A bidirectional stream composed of [`SendStream`] and [`RecvStream`].
///
/// `BiStream` is a utility particularly useful in situations where a generic
/// function or method expects a single object that must implement both
/// [`AsyncRead`](tokio::io::AsyncRead) and [`AsyncWrite`](tokio::io::AsyncWrite).
///
/// # Examples
///
/// ```
/// use tokio::io::AsyncRead;
/// use tokio::io::AsyncWrite;
/// use wtransport::stream::BiStream;
///
/// async fn do_operation<T>(io: T)
/// where
///     T: AsyncRead + AsyncWrite,
/// {
///     // ...
/// }
///
/// # use wtransport::Connection;
/// # async fn run(connection: Connection) {
/// let bi_stream = BiStream::join(connection.accept_bi().await.unwrap());
/// do_operation(bi_stream).await;
/// # }
/// ```
#[derive(Debug)]
pub struct BiStream((SendStream, RecvStream));

impl BiStream {
    /// Joins a sending stream and a receiving stream into a single `BiStream` object.
    pub fn join(s: (SendStream, RecvStream)) -> Self {
        Self(s)
    }

    /// Splits the bidirectional stream into its sending and receiving stream handles.
    pub fn split(self) -> (SendStream, RecvStream) {
        self.0
    }

    /// Returns a reference to the inner [`SendStream`].
    pub fn send(&self) -> &SendStream {
        &self.0 .0
    }

    /// Returns a mutable reference to the inner [`SendStream`].
    pub fn send_mut(&mut self) -> &mut SendStream {
        &mut self.0 .0
    }

    /// Returns a reference to the inner [`RecvStream`].
    pub fn recv(&self) -> &RecvStream {
        &self.0 .1
    }

    /// Returns a mutable reference to the inner [`RecvStream`].
    pub fn recv_mut(&mut self) -> &mut RecvStream {
        &mut self.0 .1
    }
}

impl From<(SendStream, RecvStream)> for BiStream {
    fn from(value: (SendStream, RecvStream)) -> Self {
        Self::join(value)
    }
}

impl From<BiStream> for (SendStream, RecvStream) {
    fn from(value: BiStream) -> Self {
        value.split()
    }
}

impl tokio::io::AsyncWrite for SendStream {
    #[inline(always)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    #[inline(always)]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    #[inline(always)]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }

    #[inline(always)]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write_vectored(Pin::new(&mut self.0), cx, bufs)
    }

    #[inline(always)]
    fn is_write_vectored(&self) -> bool {
        tokio::io::AsyncWrite::is_write_vectored(&self.0)
    }
}

impl tokio::io::AsyncRead for RecvStream {
    #[inline(always)]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }
}

impl tokio::io::AsyncWrite for BiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.0 .0), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.0 .0), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.0 .0), cx)
    }
}

impl tokio::io::AsyncRead for BiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(Pin::new(&mut self.0 .1), cx, buf)
    }
}

type DynFutureUniStream = dyn Future<Output = Result<SendStream, StreamOpeningError>> + Send + Sync;

/// [`Future`] for an in-progress opening unidirectional stream.
///
/// See [`Connection::open_uni`](crate::Connection::open_uni).
pub struct OpeningUniStream(Pin<Box<DynFutureUniStream>>);

impl OpeningUniStream {
    pub(crate) fn new(session_id: SessionId, quic_stream: StreamUniLocalQuic) -> Self {
        Self(Box::pin(async move {
            match quic_stream
                .upgrade(StreamHeader::new_webtransport(session_id))
                .await
            {
                Ok(stream) => Ok(SendStream(stream.upgrade().into_stream())),
                Err(ProtoWriteError::NotConnected) => Err(StreamOpeningError::NotConnected),
                Err(ProtoWriteError::Stopped) => Err(StreamOpeningError::Refused),
            }
        }))
    }
}

impl Future for OpeningUniStream {
    type Output = Result<SendStream, StreamOpeningError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

type DynFutureBiStream =
    dyn Future<Output = Result<(SendStream, RecvStream), StreamOpeningError>> + Send + Sync;

/// [`Future`] for an in-progress opening bidirectional stream.
///
/// See [`Connection::open_bi`](crate::Connection::open_bi).
pub struct OpeningBiStream(Pin<Box<DynFutureBiStream>>);

impl OpeningBiStream {
    pub(crate) fn new(session_id: SessionId, quic_stream: StreamBiLocalQuic) -> Self {
        Self(Box::pin(async move {
            match quic_stream.upgrade().upgrade(session_id).await {
                Ok(stream) => {
                    let stream = stream.into_stream();
                    Ok((SendStream::new(stream.0), RecvStream::new(stream.1)))
                }
                Err(ProtoWriteError::NotConnected) => Err(StreamOpeningError::NotConnected),
                Err(ProtoWriteError::Stopped) => Err(StreamOpeningError::Refused),
            }
        }))
    }
}

impl Future for OpeningBiStream {
    type Output = Result<(SendStream, RecvStream), StreamOpeningError>;

    #[inline(always)]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Future::poll(self.0.as_mut(), cx)
    }
}

#[cfg(test)]
mod code_mapping_tests {
    use super::*;

    /// draft-ietf-webtrans-http3 section 4.4, both ways.
    #[test]
    fn application_codes_map_into_the_reserved_range() {
        for n in [0u32, 1, 0x1d, 0x1e, 0x1f, 1000, u32::MAX] {
            let h = wt_code_to_http(VarInt::from_u32(n));
            assert_ne!((h.into_inner() - 0x21) % 0x1f, 0, "{n}");
            assert_eq!(http_code_to_wt(h), VarInt::from_u32(n));
        }
        assert_eq!(wt_code_to_http(VarInt::from_u32(0)).into_inner(), 0x52e4_a40f_a8db);
        assert_eq!(wt_code_to_http(VarInt::from_u32(u32::MAX)).into_inner(), 0x52e5_ac98_3162);
        // An HTTP/3 code outside the range is given as it came
        assert_eq!(http_code_to_wt(VarInt::from_u32(0x100)), VarInt::from_u32(0x100));
    }
}
