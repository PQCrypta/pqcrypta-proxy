//! Interim (1xx) responses from an HTTP/2 server's service: pqcrypta-proxy's
//! patch to hyper, which otherwise gives a service no way to send one.
//!
//! The HTTP/2 server puts an [`InformationalSender`] in each request's
//! extensions. A service sends a `103 Early Hints` (or any 1xx) through it
//! while it is still working on the final response, and the stream sends it
//! at once, ahead of that response, with `h2`'s `send_informational`. Once
//! the final response has gone, what is sent is dropped.

use futures_channel::mpsc;
use http::Response;

/// Sends interim (1xx) responses on the HTTP/2 stream of the request that
/// carries it. Present only on HTTP/2 requests (`Request::extensions`).
#[derive(Clone, Debug)]
pub struct InformationalSender(mpsc::UnboundedSender<Response<()>>);

/// The stream's end of the channel.
pub(crate) type InformationalReceiver = mpsc::UnboundedReceiver<Response<()>>;

/// A sender for a request's extensions and the receiver its stream polls.
pub(crate) fn informational_channel() -> (InformationalSender, InformationalReceiver) {
    let (tx, rx) = mpsc::unbounded();
    (InformationalSender(tx), rx)
}

impl InformationalSender {
    /// Queue an interim response; it goes out before the final response, as
    /// soon as the stream is next polled. Refused when the status is not 1xx,
    /// or when the final response has already been sent.
    pub fn send(&self, response: Response<()>) -> Result<(), Response<()>> {
        if !response.status().is_informational() {
            return Err(response);
        }
        self.0
            .unbounded_send(response)
            .map_err(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;

    fn with_status(status: u16) -> Response<()> {
        let mut response = Response::new(());
        *response.status_mut() = StatusCode::from_u16(status).unwrap();
        response
    }

    #[test]
    fn interim_responses_are_queued_in_order() {
        let (sender, mut receiver) = informational_channel();
        sender.send(with_status(103)).unwrap();
        sender.send(with_status(100)).unwrap();
        assert_eq!(receiver.try_recv().unwrap().status(), 103);
        assert_eq!(receiver.try_recv().unwrap().status(), 100);
    }

    #[test]
    fn a_final_status_is_handed_back() {
        let (sender, _receiver) = informational_channel();
        for status in [200, 204, 304, 404, 500] {
            let refused = sender.send(with_status(status)).unwrap_err();
            assert_eq!(refused.status(), status);
        }
    }

    #[test]
    fn nothing_is_accepted_once_the_stream_has_answered() {
        // The stream drops its receiver when the final response goes
        let (sender, receiver) = informational_channel();
        drop(receiver);
        let refused = sender.send(with_status(103)).unwrap_err();
        assert_eq!(refused.status(), 103);
    }
}
