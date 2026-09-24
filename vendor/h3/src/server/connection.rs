//! HTTP/3 server connection
//!
//! The [`Connection`] struct manages a connection from the side of the HTTP/3 server

use std::{
    future::poll_fn,
    option::Option,
    result::Result,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{ready, Context, Poll},
};

use bytes::Buf;
use futures_util::task::AtomicWaker;
use quic::RecvStream;
use quic::StreamId;

use crate::{
    connection::ConnectionInner,
    error::{internal_error::InternalConnectionError, Code, ConnectionError},
    frame::FrameStream,
    proto::{
        frame::{Frame, PayloadLen},
        push::PushId,
    },
    quic::{self, SendStream as _},
    shared_state::{ConnectionState, SharedState},
    stream::BufRecvStream,
};

#[cfg(feature = "tracing")]
use tracing::{instrument, trace, warn};

use super::request::RequestResolver;

/// Server connection driver
///
/// The [`Connection`] struct manages a connection from the side of the HTTP/3 server
///
/// Create a new Instance with [`Connection::new()`].
/// Accept incoming requests with [`Connection::accept()`].
/// And shutdown a connection with [`Connection::shutdown()`].
pub struct Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// TODO: temporarily break encapsulation for `WebTransportSession`
    pub inner: ConnectionInner<C, B>,
    pub(super) max_field_section_size: u64,
    // Requests accepted and not yet finished; see `Ongoing`.
    pub(super) ongoing: Arc<Ongoing>,
    // Accepts since the auxiliary streams were last polled; see
    // `poll_accept_request_stream_internal`.
    pub(super) accepts_since_aux: u32,
    // Has a GOAWAY frame been sent? If so, this StreamId is the last we are willing to accept.
    pub(super) sent_closing: Option<StreamId>,
    // Has a GOAWAY frame been received? If so, this is PushId the last the remote will accept.
    pub(super) recv_closing: Option<PushId>,
    // The id of the last stream received by this connection.
    pub(super) last_accepted_stream: Option<StreamId>,
}

impl<C, B> ConnectionState for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.inner.shared
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Create a new HTTP/3 server connection with default settings
    ///
    /// Use a custom [`super::builder::Builder`] with [`super::builder::builder()`] to create a connection
    /// with different settings.
    /// Provide a Connection which implements [`quic::Connection`].
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(conn: C) -> Result<Self, ConnectionError> {
        super::builder::builder().build(conn).await
    }
}

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
/// Impls for extension implementation which are not stable
impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    /// Create a [`RequestResolver`] to handle an incoming request.
    pub fn create_resolver(&self, stream: FrameStream<C::BidiStream, B>) -> RequestResolver<C, B> {
        self.create_resolver_internal(stream)
    }

    /// Polls the Connection and accepts an incoming request_streams
    #[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
    pub fn poll_accept_request_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        self.poll_accept_request_stream_internal(cx)
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// Accept an incoming request.
    ///
    /// This method returns a [`RequestResolver`] which can be used to read the request and send the response.
    /// This method will return `None` when the connection receives a GOAWAY frame and all requests have been completed.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn accept(&mut self) -> Result<Option<RequestResolver<C, B>>, ConnectionError> {
        // Accept the incoming stream
        let stream = match poll_fn(|cx| self.poll_accept_request_stream_internal(cx)).await? {
            Some(s) => FrameStream::new(BufRecvStream::new(s)),
            None => {
                // We always send a last GoAway frame to the client, so it knows which was the last
                // non-rejected request.
                self.shutdown(0).await?;
                return Ok(None);
            }
        };

        let resolver = self.create_resolver_internal(stream);

        // send the grease frame only once
        self.inner.send_grease_frame = false;

        Ok(Some(resolver))
    }

    fn create_resolver_internal(
        &self,
        stream: FrameStream<C::BidiStream, B>,
    ) -> RequestResolver<C, B> {
        RequestResolver {
            request_end: Arc::new(RequestEnd {
                ongoing: self.ongoing.clone(),
            }),
            frame_stream: stream,
            send_grease_frame: self.inner.send_grease_frame,
            max_field_section_size: self.max_field_section_size,
            shared: self.inner.shared.clone(),
        }
    }

    /// Initiate a graceful shutdown, accepting `max_request` potentially still in-flight
    ///
    /// See [connection shutdown](https://www.rfc-editor.org/rfc/rfc9114.html#connection-shutdown) for more information.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown(&mut self, max_requests: usize) -> Result<(), ConnectionError> {
        let max_id = self
            .last_accepted_stream
            .map(|id| id + max_requests)
            .unwrap_or(StreamId::FIRST_REQUEST);

        self.inner.shutdown(&mut self.sent_closing, max_id).await
    }

    /// Accepts an incoming bidirectional stream.
    ///
    /// This could be either a *Request* or a *WebTransportBiStream*, the first frame's type
    /// decides.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_accept_request_stream_internal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<C::BidiStream>, ConnectionError>> {
        // Read the client's QPACK encoder stream and flush our decoder
        // stream.
        //
        // This half was never driven. The consequence was not a wrong
        // answer but a stream nobody read: an encoder instruction sat in the
        // receive buffer forever, so the client got no flow-control credit
        // back on a stream RFC 9204 4.2 says is processed as it arrives, and
        // an instruction we are required to reject (2.2.3) was accepted by
        // being ignored. This endpoint advertises a table capacity of zero,
        // so a conformant client sends nothing here and nothing changes for
        // it; what changes is that a client which sends something now gets
        // an answer.
        // Requests already waiting are taken first. The auxiliary streams
        // below — QPACK encoder and decoder, control, request completions —
        // are polled when no request is waiting, which is when this task would
        // otherwise go to sleep, and at least every `AUX_EVERY` accepts so a
        // connection that always has a request queued still reads its control
        // stream. Polling all four before every accept cost each request of a
        // burst four polls of the QUIC connection for streams that almost never
        // have anything on them.
        const AUX_EVERY: u32 = 16;
        if self.accepts_since_aux < AUX_EVERY {
            self.accepts_since_aux += 1;
            while let Poll::Ready(s) = self.inner.poll_accept_bi(cx)? {
                if let Some(ready) = self.admit(s, cx) {
                    return ready;
                }
            }
        }
        self.accepts_since_aux = 0;

        if let Poll::Ready(err) = self.inner.poll_qpack_encoder(cx) {
            return Poll::Ready(Err(err));
        }
        self.inner.poll_qpack_decoder_send(cx);

        let _ = self.poll_control(cx)?;
        loop {
            let conn = self.inner.poll_accept_bi(cx)?;
            return match conn {
                Poll::Pending => {
                    let done =
                        self.recv_closing.is_some() && self.poll_requests_completion(cx).is_ready();

                    if done {
                        Poll::Ready(Ok(None))
                    } else {
                        // Wait for all the requests to be finished; the last
                        // one to finish wakes us.
                        Poll::Pending
                    }
                }
                Poll::Ready(s) => match self.admit(s, cx) {
                    Some(ready) => ready,
                    None => continue,
                },
            };
        }
    }

    /// Take an incoming request stream, or reject it during a graceful
    /// shutdown. `None` means it was rejected and the caller should look for
    /// the next one.
    fn admit(
        &mut self,
        mut s: C::BidiStream,
        cx: &mut Context<'_>,
    ) -> Option<Poll<Result<Option<C::BidiStream>, ConnectionError>>> {
        // When the connection is in a graceful shutdown procedure, reject all
        // incoming requests not belonging to the grace interval. It's possible that
        // some acceptable request streams arrive after rejected requests.
        if let Some(max_id) = self.sent_closing {
            if s.send_id() > max_id {
                s.stop_sending(Code::H3_REQUEST_REJECTED.value());
                s.reset(Code::H3_REQUEST_REJECTED.value());
                if self.poll_requests_completion(cx).is_ready() {
                    return Some(Poll::Ready(Ok(None)));
                }
                return None;
            }
        }
        self.last_accepted_stream = Some(s.send_id());
        self.ongoing.count.fetch_add(1, Ordering::AcqRel);
        Some(Poll::Ready(Ok(Some(s))))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        while (self.poll_next_control(cx)?).is_ready() {}
        Poll::Pending
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn poll_next_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        let frame = ready!(self.inner.poll_control(cx))?;

        match &frame {
            Frame::Settings(_setting) => {
                #[cfg(feature = "tracing")]
                trace!("Got settings > {:?}", _setting);
            }
            &Frame::Goaway(id) => self.inner.process_goaway(&mut self.recv_closing, id)?,
            _frame @ Frame::MaxPushId(_) | _frame @ Frame::CancelPush(_) => {
                #[cfg(feature = "tracing")]
                warn!("Control frame ignored {:?}", _frame);

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                //= type=TODO
                //# If a server receives a CANCEL_PUSH frame for a push
                //# ID that has not yet been mentioned by a PUSH_PROMISE frame, this MUST
                //# be treated as a connection error of type H3_ID_ERROR.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                //= type=TODO
                //# A MAX_PUSH_ID frame cannot reduce the maximum push
                //# ID; receipt of a MAX_PUSH_ID frame that contains a smaller value than
                //# previously received MUST be treated as a connection error of type
                //# H3_ID_ERROR.
            }

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
            //# A server MUST treat the
            //# receipt of a PUSH_PROMISE frame as a connection error of type
            //# H3_FRAME_UNEXPECTED.
            frame => {
                return Poll::Ready(Err(self.inner.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("on server control stream: {:?}", frame),
                    ),
                )));
            }
        }
        Poll::Ready(Ok(frame))
    }

    /// Ready once no accepted request is still running.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_requests_completion(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.ongoing.count.load(Ordering::Acquire) == 0 {
            return Poll::Ready(());
        }
        self.ongoing.waker.register(cx.waker());
        // Re-check: the last request may have finished between the load and
        // the registration.
        if self.ongoing.count.load(Ordering::Acquire) == 0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl<C, B> Drop for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn drop(&mut self) {
        self.inner.close_connection(
            Code::H3_NO_ERROR,
            "Connection was closed by the server".to_string(),
        );
    }
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# In order to
//# permit these streams to open, an HTTP/3 server SHOULD configure non-
//# zero minimum values for the number of permitted streams and the
//# initial stream flow-control window.

//= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
//= type=TODO
//# So as to not unnecessarily limit
//# parallelism, at least 100 request streams SHOULD be permitted at a
//# time.

/// How many accepted requests are still running.
///
/// This was a `HashSet<StreamId>` fed by a channel: an insert per request, a
/// message per completion, and — because the accept loop was the channel's
/// only reader — a wake of the connection task for every request that
/// finished, all to answer "is anything still running?" during a graceful
/// shutdown. A count answers the same question, and the connection is woken
/// only when it reaches zero.
pub(super) struct Ongoing {
    pub(super) count: AtomicUsize,
    pub(super) waker: AtomicWaker,
}

impl Ongoing {
    pub(super) fn new() -> Self {
        Self {
            count: AtomicUsize::new(0),
            waker: AtomicWaker::new(),
        }
    }
}

/// Created with the request's resolver, so a request is counted finished
/// however it ends — including a resolve that fails, which previously left
/// its stream counted as running for the life of the connection and kept a
/// graceful shutdown from ever completing.
pub(super) struct RequestEnd {
    pub(super) ongoing: Arc<Ongoing>,
}
