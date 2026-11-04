//! Proof that `h-oversized-field-section` can see a client refuse the section.
//!
//! The listener used to write the section, the body and the end of the stream
//! in one go. A client then had the whole response before it had decided
//! anything, and refusing the section left nothing on the wire: STOP_SENDING
//! means nothing on a stream whose data has all arrived (RFC 9000 §3.5), so
//! quinn does not send it. Our own client and quiche refused the section,
//! exited non-zero, closed cleanly -- and were credited with having decoded
//! it, because a clean close after a completed exchange is what a decoding
//! client does too (2026-11-04).
//!
//! The body is now held back after the section. What is asserted here is that
//! the hold shows each answer for what it is: a real HTTP/3 client that
//! enforces its limit stops the stream, and is reset in answer; a client that
//! goes away under the held response is seen to have cut it short; and one
//! that waits gets its body once the window has passed.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::h3_frames as f;
use super::listener::{answer_probe, emit, reset_if_stopped, Answered, QpackLimits};
use super::qpack_dynamic::{client_endpoint, server_config};
use super::zero_rtt::throwaway_cert;

/// The SETTINGS_MAX_FIELD_SECTION_SIZE the client advertises.
const LIMIT: u64 = 16 * 1024;

/// What the server side of one run saw.
struct Served {
    answered: Answered,
    /// The code the response stream was reset with, where it was.
    reset_with: Option<u64>,
    /// The code of the last STOP_SENDING the connection received.
    stopped: Option<u64>,
}

/// Serve one `h-oversized-field-section` exchange through the listener's own
/// emission and answer, against a client advertising [`LIMIT`].
async fn serve(client: impl AsyncFnOnce(quinn::Connection)) -> Served {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    let test = super::catalog::find("h-oversized-field-section").expect("catalogue entry");
    let throwaway = throwaway_cert();

    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a loopback port");
    let server = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config(&throwaway)),
        socket,
        quinn::default_runtime().expect("a tokio runtime is running"),
    )
    .expect("building the server endpoint");
    let addr = server.local_addr().expect("the server is bound");

    let serving = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection arrives");
        let connection = incoming.await.expect("the handshake completes");
        let emitted = emit(&connection, test).await.expect("emitting the anomaly");

        // The limit the drainer would have read from the client's SETTINGS.
        let qpack = QpackLimits::default();
        qpack.observe(f::ClientQpackLimits {
            capacity: 0,
            blocked_streams: 0,
            max_field_section_size: Some(LIMIT),
        });

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .expect("the client opens a request stream");
        let _ = recv.read_to_end(4096).await;
        let answered = answer_probe(&mut send, test, &qpack, None, false)
            .await
            .expect("answering the probe");
        let reset_with = reset_if_stopped(&mut send).map(u64::from);
        let stopped = connection
            .last_stop_sending()
            .map(|(_, code)| u64::from(code));

        // Long enough for the client's side to finish with what it was sent.
        let _ = tokio::time::timeout(Duration::from_secs(3), connection.closed()).await;
        drop(emitted);
        drop(send);
        Served {
            answered,
            reset_with,
            stopped,
        }
    });

    let endpoint = client_endpoint(&throwaway);
    let connection = endpoint
        .connect(addr, "conformance.test")
        .expect("starting the connection")
        .await
        .expect("the handshake completes");
    client(connection).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;

    serving.await.expect("the server side completes")
}

/// Open a raw request stream and read until the whole HEADERS frame is in.
async fn read_section(connection: &quinn::Connection) -> (quinn::RecvStream, Vec<u8>) {
    let (mut send, mut recv) = connection.open_bi().await.expect("opening the probe");
    send.write_all(b"probe").await.expect("writing the request");
    send.finish().expect("finishing the request");
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf))
            .await
            .expect("the section arrives in time")
            .expect("reading the response")
            .expect("the response does not end inside its HEADERS frame");
        response.extend_from_slice(&buf[..n]);
        if headers_frame_len(&response).is_some_and(|len| response.len() >= len) {
            return (recv, response);
        }
    }
}

/// The length on the wire of the HEADERS frame at the start of `stream`, once
/// its header is in.
fn headers_frame_len(stream: &[u8]) -> Option<usize> {
    let (ty, a) = f::read_varint(stream)?;
    assert_eq!(ty, 0x01, "the response opens with HEADERS");
    let (len, b) = f::read_varint(&stream[a..])?;
    Some(a + b + usize::try_from(len).ok()?)
}

/// The vendored h3 client enforces its limit as RFC 9114 §4.2.2 has it: the
/// request fails, the stream is stopped with H3_REQUEST_CANCELLED, and the
/// connection carries on. With the body held back, that STOP_SENDING arrives
/// while the response is still being written -- and is answered with a reset.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_enforcing_its_limit_stops_the_held_response() {
    let served = serve(async |connection| {
        let watch = connection.clone();
        let (mut driver, mut send_request) = h3::client::builder()
            .max_field_section_size(LIMIT)
            .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection))
            .await
            .expect("opening the HTTP/3 connection");
        let driving = tokio::spawn(async move {
            futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await
        });
        let request = http::Request::get("https://conformance.test/")
            .body(())
            .expect("building the request");
        let mut stream = send_request
            .send_request(request)
            .await
            .expect("sending the request");
        stream.finish().await.expect("finishing the request");
        let refused = stream.recv_response().await;
        assert!(
            matches!(refused, Err(h3::error::StreamError::HeaderTooBig { max_size, .. }) if max_size == LIMIT),
            "{refused:?}"
        );
        // As h3-get does: dropping the last request handle closes the
        // connection, and a close discards the queued STOP_SENDING, so the
        // refusal has to be sent and acknowledged first.
        let until = Instant::now() + Duration::from_secs(2);
        while !watch.is_settled() && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert!(watch.is_settled(), "the refusal was sent and acknowledged");
        drop(stream);
        drop(send_request);
        let _ = tokio::time::timeout(Duration::from_secs(2), driving).await;
    })
    .await;

    assert_eq!(served.answered, Answered::CutShort);
    assert_eq!(served.stopped, Some(f::error_code::H3_REQUEST_CANCELLED));
    assert_eq!(
        served.reset_with,
        Some(f::error_code::H3_REQUEST_CANCELLED),
        "RFC 9000 §3.5: a stream stopped while being written is reset, with the same code"
    );
}

/// A client that closes the connection once it has the section, without
/// waiting for the body, has cut the response short.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_under_the_held_response_cuts_it_short() {
    let served = serve(async |connection| {
        let (_recv, _section) = read_section(&connection).await;
        connection.close(
            quinn::VarInt::from_u64(f::error_code::H3_NO_ERROR).expect("a varint"),
            b"",
        );
    })
    .await;

    assert_eq!(served.answered, Answered::CutShort);
    assert_eq!(served.stopped, None);
    assert_eq!(served.reset_with, None);
}

/// A client that accepts the section waits, and the body follows once the
/// window has passed: the hold is real, and it ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_waits_gets_the_body_after_the_window() {
    let served = serve(async |connection| {
        let (mut recv, section) = read_section(&connection).await;
        let section_at = Instant::now();
        let section_len = headers_frame_len(&section).expect("a whole HEADERS frame");
        assert!(
            u64::try_from(section_len).expect("fits") > LIMIT,
            "the section is past the advertised maximum"
        );
        let rest = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
            .await
            .expect("the body arrives in time")
            .expect("reading the body");
        let held = section_at.elapsed();
        assert!(
            held >= Duration::from_millis(900),
            "the body came {held:?} after the section"
        );
        let body = [&section[section_len..], &rest[..]].concat();
        let (ty, _) = f::read_varint(&body).expect("a frame follows the section");
        assert_eq!(ty, 0x00, "the body is a DATA frame");
        connection.close(
            quinn::VarInt::from_u64(f::error_code::H3_NO_ERROR).expect("a varint"),
            b"",
        );
    })
    .await;

    assert_eq!(served.answered, Answered::InFull);
    assert_eq!(served.stopped, None);
    assert_eq!(served.reset_with, None);
}
