use bytes::Buf;
use futures_util::future;
use http::{HeaderMap, Response};
use quic::StreamId;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        connection_error_creators::{CloseStream, HandleFrameStreamErrorOnRequestStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::{self},
    shared_state::{ConnectionState, SharedState},
};
use std::{
    convert::TryFrom,
    task::{Context, Poll},
};

/// Manage request bodies transfer, response and trailers.
///
/// Once a request has been sent via [`crate::client::SendRequest::send_request()`], a response can be awaited by calling
/// [`RequestStream::recv_response()`]. A body for this request can be sent with [`RequestStream::send_data()`], then the request
/// shall be completed by either sending trailers with  [`RequestStream::finish()`].
///
/// After receiving the response's headers, it's body can be read by [`RequestStream::recv_data()`] until it returns
/// `None`. Then the trailers will eventually be available via [`RequestStream::recv_trailers()`].
///
/// TODO: If data is polled before the response has been received, an error will be thrown.
///
/// TODO: If trailers are polled but the body hasn't been fully received, an UNEXPECT_FRAME error will be
/// thrown
///
/// Whenever the client wants to cancel this request, it can call [`RequestStream::stop_sending()`], which will
/// put an end to any transfer concerning it.
///
/// # Examples
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # use tokio::io::AsyncWriteExt;
/// # async fn doc<T,B>(mut req_stream: RequestStream<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::RecvStream,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Receive the response
/// let response = req_stream.recv_response().await?;
/// // Receive the body
/// while let Some(mut chunk) = req_stream.recv_data().await? {
///     let mut out = tokio::io::stdout();
///     out.write_all_buf(&mut chunk).await?;
///     out.flush().await?;
/// }
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`recv_response()`]: #method.recv_response
/// [`recv_data()`]: #method.recv_data
/// [`send_data()`]: #method.send_data
/// [`send_trailers()`]: #method.send_trailers
/// [`recv_trailers()`]: #method.recv_trailers
/// [`finish()`]: #method.finish
/// [`stop_sending()`]: #method.stop_sending
pub struct RequestStream<S, B> {
    pub(super) inner: connection::RequestStream<S, B>,
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.inner.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive the HTTP/3 response
    ///
    /// This should be called before trying to receive any data with [`recv_data()`].
    ///
    /// [`recv_data()`]: #method.recv_data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        // Interim responses are skipped rather than returned.
        //
        // RFC 9110 §15.2 requires a client to be able to parse one or more 1xx
        // responses received prior to a final response, and RFC 8297 makes 103
        // Early Hints a thing a server may send before any of the work behind
        // the real response has finished. This read exactly one HEADERS frame
        // and called it the response, so a 103 was returned to the caller as if
        // it were final and the actual response that followed was an
        // unexpected second HEADERS -- reported as H3_FRAME_UNEXPECTED, which
        // is a connection error raised against a server doing nothing wrong.
        //
        // Measured, not theorised: this is `h-early-hints` in our own
        // conformance suite, which our own client failed while we were
        // publishing other implementations' failures on the same test.
        //
        // Skipping rather than surfacing them is the minimal correct fix and
        // not the complete one: a caller that wants the hints (to start a
        // preload, which is the entire point of 103) still cannot reach them.
        // That needs an API change, so it is deliberately not smuggled in here.
        //
        // 101 is not special-cased because HTTP/3 has no protocol upgrade:
        // RFC 9114 §4.4 removes it, and Extended CONNECT replaces it.
        loop {
            let resp = self.recv_one_response().await?;
            if !resp.status().is_informational() {
                return Ok(resp);
            }
        }
    }

    /// One HEADERS frame, decoded into a response, interim or final.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    async fn recv_one_response(&mut self) -> Result<Response<()>, StreamError> {
        let mut frame = future::poll_fn(|cx| self.inner.stream.poll_next(cx))
            .await
            .map_err(|e| self.handle_frame_stream_error_on_request_stream(e))?
            .ok_or_else(|| {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "Stream finished without receiving response headers".to_string(),
                ))
            })?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.

        // This client advertises no push ID at all: it never sends MAX_PUSH_ID,
        // and §7.2.7 leaves the maximum unset until it does, so a server
        // "cannot push until it receives a MAX_PUSH_ID frame". Every push ID
        // that arrives is therefore larger than the client has advertised, and
        // the clause above applies unconditionally.
        //
        // It was marked TODO and fell through to the "first response frame is
        // not headers" arm below, which answers H3_FRAME_UNEXPECTED. That is
        // the right instinct with the wrong code, and our own conformance
        // suite failed us for it.
        if matches!(frame, Frame::PushPromise(_)) {
            return Err(
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_ID_ERROR,
                    "PUSH_PROMISE received when no MAX_PUSH_ID has been sent".to_string(),
                )),
            );
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.

        let decoded = if let Frame::Headers(ref mut encoded) = frame {
            match qpack::decode_stateless(encoded, self.inner.max_field_section_size) {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
                //# An HTTP/3 implementation MAY impose a limit on the maximum size of
                //# the message header it will accept on an individual HTTP message.
                Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                    self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                    return Err(StreamError::HeaderTooBig {
                        actual_size: cancel_size,
                        max_size: self.inner.max_field_section_size,
                    });
                }
                Ok(decoded) => decoded,
                Err(_e) => {
                    return Err(
                        self.handle_connection_error_on_stream(InternalConnectionError {
                            code: Code::QPACK_DECOMPRESSION_FAILED,
                            message: "Failed to decode headers".to_string(),
                        }),
                    )
                }
            }
        } else {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            return Err(
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "First response frame is not headers".to_string(),
                )),
            );
        };

        let qpack::Decoded { fields, .. } = decoded;

        let (status, headers) = Header::try_from(fields)
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?
            .into_response_parts()
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?;
        let mut resp = Response::new(());
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        *resp.version_mut() = http::Version::HTTP_3;

        Ok(resp)
    }

    /// Receive some of the request body.
    // TODO what if called before recv_response ?
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_data(cx)).await
    }

    /// Receive request body
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_trailers(cx)).await
    }

    /// Poll receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let res = self.inner.poll_recv_trailers(cx);
        if let Poll::Ready(Err(e)) = &res {
            if let StreamError::HeaderTooBig { .. } = e {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            }
        }
        res
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        // TODO take by value to prevent any further call as this request is cancelled
        // rename `cancel()` ?
        self.inner.stream.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the request.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// End the request without trailers.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
    //= type=TODO
    //# Implementations SHOULD cancel requests by abruptly terminating any
    //# directions of a stream that are still open.  To do so, an
    //# implementation resets the sending parts of streams and aborts reading
    //# on the receiving parts of streams; see Section 2.4 of
    //# [QUIC-TRANSPORT].
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Split this stream into two halves that can be driven independently.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (RequestStream { inner: send }, RequestStream { inner: recv })
    }
}
