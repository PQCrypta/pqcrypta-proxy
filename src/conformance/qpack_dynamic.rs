//! Proof that the two QPACK dynamic-table tests emit what they claim.
//!
//! Neither could be exercised from outside when this was written. Every HTTP/3
//! client within reach — curl/ngtcp2, quinn, aioquic, Chromium's QUICHE and
//! quic-go — advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY` of 0 and
//! `SETTINGS_QPACK_BLOCKED_STREAMS` of 0, which forbids the server's encoder
//! from touching the dynamic table at all. Both ports therefore reported
//! `unsupported` against every real client, for the right reason, and the
//! emission behind them was never run.
//!
//! Our own client now grants both (4096 bytes, 16 blocked streams), so one of
//! the twelve does reach these ports. That does not retire this module: a
//! single client exercising the path proves the path runs, not that the bytes
//! on it are the ones claimed, and the assertions below are about the bytes.
//!
//! An unrun path is not a working path. `h-qpack-dynamic-table` shipped for
//! months writing a field section whose Required Insert Count claimed two
//! entries while inserting neither, and nothing caught it: the literal fallback
//! is what every client actually received. So the anomaly is driven here, by a
//! client that grants what the specification requires before the dynamic table
//! may be used, and the bytes on the wire are checked.
//!
//! What is asserted is the part that is ours to get right:
//!
//! - the insertions the field section references are actually written
//! - the section references the dynamic table rather than falling back to
//!   literals
//! - `h-qpack-blocked-stream` holds its insertions back long enough that the
//!   stream genuinely blocks, instead of merely hoping to win a race
//!
//! What is deliberately *not* asserted is that `h-qpack-dynamic-table`'s
//! insertions arrive before the section referencing them. They are written
//! first, but the encoder stream and the response stream are separate QUIC
//! streams with no ordering between them, so arrival order is the network's to
//! decide and an assertion on it fails at random. That absence of a guarantee is
//! the whole reason both tests require the client to permit blocked streams
//! before they will run at all.
//!
//! Decoding QPACK is the client's job and is not reimplemented here. The
//! structure of what we send is the claim being tested.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::h3_frames as f;
use super::listener::{answer_probe, emit, write_capacity_overflow, QpackLimits};
use super::zero_rtt::{throwaway_cert, OneCert, PinnedTo, Throwaway};

/// A client that permits the dynamic table, which no real one does.
const CLIENT_LIMITS: f::ClientQpackLimits = f::ClientQpackLimits {
    capacity: 4096,
    blocked_streams: 16,
};

/// What one run of a test put on the wire.
struct Wire {
    /// Bytes written to the QPACK encoder stream, after its type prefix.
    encoder: Vec<u8>,
    /// Bytes written to the response stream.
    response: Vec<u8>,
    /// When the response HEADERS frame finished arriving.
    headers_at: Instant,
    /// When the encoder insertions finished arriving.
    insertions_at: Instant,
}

fn server_config(throwaway: &Throwaway) -> quinn::ServerConfig {
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(crate::tls::build_pqc_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .expect("building the QUIC config"),
    );
    let mut server_config = quinn::ServerConfig::with_crypto(crypto);
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .expect("10s is a valid idle timeout"),
    ));
    server_config.transport = Arc::new(transport);
    server_config
}

fn client_endpoint(throwaway: &Throwaway) -> quinn::Endpoint {
    let provider = Arc::new(crate::tls::build_pqc_provider());
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is available")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("building the QUIC client configuration"),
    ));
    let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a client port");
    client.set_default_client_config(client_config);
    client
}

/// Run one catalogue entry against a client that permits the dynamic table.
///
/// The server side is the real emission path: the same `emit` the listener
/// calls, and the same `answer_probe`, with the QPACK limits the drainer would
/// have learned from the client's SETTINGS.
async fn drive(test_id: &'static str) -> Wire {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    let test = super::catalog::find(test_id).expect("catalogue entry");
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

        let mut emitted = emit(&connection, test).await.expect("emitting the anomaly");

        // The limits the drainer would have read from the client's SETTINGS.
        let qpack = QpackLimits::default();
        qpack.observe(CLIENT_LIMITS);

        // Same order as the live listener: settings observed, the overflow
        // sized against them, then the probe answered.
        write_capacity_overflow(test, &qpack, Some(&mut emitted.encoder)).await;

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .expect("the client opens a request stream");
        let _ = recv.read_to_end(4096).await;
        // No early data here: these tests are about QPACK, and the flag only
        // decides whether the 0-RTT port answers 425.
        answer_probe(&mut send, test, &qpack, Some(&mut emitted.encoder), false)
            .await
            .expect("answering the probe");
        let _ = send.finish();

        // Held open past the response: finishing a QPACK encoder stream is
        // H3_CLOSED_CRITICAL_STREAM, exactly as in the live listener.
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(emitted);
        connection.close(0u32.into(), b"done");
    });

    let client = client_endpoint(&throwaway);
    let connection = client
        .connect(addr, "conformance.test")
        .expect("starting the connection")
        .await
        .expect("the handshake completes");

    // Collect the server's unidirectional streams, keeping the encoder's bytes
    // and noting when its insertions land.
    let encoder_bytes = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let insertions_at = Arc::new(tokio::sync::Mutex::new(None::<Instant>));
    let collecting = tokio::spawn({
        let connection = connection.clone();
        let encoder_bytes = encoder_bytes.clone();
        let insertions_at = insertions_at.clone();
        async move {
            while let Ok(mut uni) = connection.accept_uni().await {
                let encoder_bytes = encoder_bytes.clone();
                let insertions_at = insertions_at.clone();
                tokio::spawn(async move {
                    // Read incrementally: the encoder stream stays open for the
                    // life of the connection, so reading to the end would only
                    // return once the server had gone away — long after the
                    // ordering under test.
                    let mut buf = [0u8; 1024];
                    let mut seen = Vec::new();
                    while let Ok(Some(n)) = uni.read(&mut buf).await {
                        seen.extend_from_slice(&buf[..n]);
                        let Some((ty, off)) = f::read_varint(&seen) else {
                            continue;
                        };
                        if ty != f::stream_type::QPACK_ENCODER {
                            continue;
                        }
                        if seen.len() > off {
                            let payload = &seen[off..];
                            *encoder_bytes.lock().await = payload.to_vec();
                            // The first *insertion*, not the first byte.
                            //
                            // The stream now opens with Set Dynamic Table
                            // Capacity, which is written before the section
                            // rather than with the insertions behind it, so
                            // timestamping the first payload byte measured
                            // the capacity instruction and reported a gap of
                            // zero for a test whose whole subject is the gap.
                            let mut at = insertions_at.lock().await;
                            if at.is_none() && count_insertions(payload) > 0 {
                                *at = Some(Instant::now());
                            }
                        }
                    }
                });
            }
        }
    });

    let (mut send, mut recv) = connection.open_bi().await.expect("opening the probe");
    send.write_all(b"probe").await.expect("writing the request");
    send.finish().expect("finishing the request");

    // Read until a whole HEADERS frame has arrived, and note when.
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    let headers_at = loop {
        match tokio::time::timeout(Duration::from_secs(5), recv.read(&mut buf)).await {
            Ok(Ok(Some(n))) => {
                response.extend_from_slice(&buf[..n]);
                if headers_frame(&response).is_some() {
                    break Instant::now();
                }
            }
            _ => break Instant::now(),
        }
    };

    // Let the delayed insertions arrive before looking at them.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let encoder = encoder_bytes.lock().await.clone();
    let insertions_at = insertions_at.lock().await.unwrap_or(headers_at);

    collecting.abort();
    connection.close(0u32.into(), b"done");
    client.wait_idle().await;
    serving.abort();

    Wire {
        encoder,
        response,
        headers_at,
        insertions_at,
    }
}

/// The payload of the first HEADERS frame in `stream`, once it is complete.
fn headers_frame(stream: &[u8]) -> Option<&[u8]> {
    let mut off = 0usize;
    while off < stream.len() {
        let (ty, n) = f::read_varint(&stream[off..])?;
        off += n;
        let (len, n) = f::read_varint(&stream[off..])?;
        off += n;
        let len = usize::try_from(len).ok()?;
        let end = off.checked_add(len)?;
        if end > stream.len() {
            return None;
        }
        if ty == f::frame_type::HEADERS {
            return Some(&stream[off..end]);
        }
        off = end;
    }
    None
}

/// The Set Dynamic Table Capacity the encoder stream opens with, if any, and
/// how many bytes it took.
///
/// `001` then a 5-bit prefix integer (RFC 9204 §4.3.1). Returning `None` is
/// the finding this parser exists for: for months the stream opened straight
/// into an insertion, and §3.2.2 forbids inserting before the capacity has
/// been set.
fn set_capacity(encoder: &[u8]) -> Option<(u64, usize)> {
    let &first = encoder.first()?;
    if first & 0b1110_0000 != 0b0010_0000 {
        return None;
    }
    let mask = 0b0001_1111u64;
    let head = u64::from(first) & mask;
    if head < mask {
        return Some((head, 1));
    }
    let mut value = head;
    let mut shift = 0;
    for (i, &byte) in encoder[1..].iter().enumerate() {
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 2));
        }
        shift += 7;
    }
    None
}

/// How many "Insert With Literal Name" instructions the encoder stream carries.
///
/// The pattern is `01NH` then a 5-bit name length (RFC 9204 §4.3.3), so the two
/// top bits identify it without decoding the rest. Counting starts past the
/// Set Dynamic Table Capacity the stream must open with.
fn count_insertions(encoder: &[u8]) -> usize {
    let mut off = set_capacity(encoder).map_or(0, |(_, used)| used);
    let mut seen = 0usize;
    while off < encoder.len() {
        if encoder[off] & 0b1100_0000 != 0b0100_0000 {
            break;
        }
        let name_len = usize::from(encoder[off] & 0b0001_1111);
        off += 1 + name_len;
        let Some(&flags) = encoder.get(off) else {
            break;
        };
        let value_len = usize::from(flags & 0b0111_1111);
        off += 1 + value_len;
        seen += 1;
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dynamic_table_entries_a_section_references_are_actually_inserted() {
    let wire = drive("h-qpack-dynamic-table").await;

    let section = headers_frame(&wire.response).expect("a complete HEADERS frame");
    let (required_insert_count, _) = f::read_varint(section).expect("the field section prefix");
    assert_ne!(
        required_insert_count, 0,
        "the section must reference the dynamic table, not fall back to literals"
    );

    // RFC 9204 §3.2.2: "the encoder MUST NOT insert entries into the dynamic
    // table ... unless it has sent" a Set Dynamic Table Capacity instruction.
    // Without it the section's references are into a table the client was never told to allocate.
    let (capacity, _) = set_capacity(&wire.encoder)
        .expect("the encoder stream must open with Set Dynamic Table Capacity");
    assert!(
        capacity > 0,
        "a capacity of zero leaves no room to insert into"
    );

    assert_eq!(
        count_insertions(&wire.encoder),
        2,
        "both referenced entries must be inserted; the section claims two, and for months \
         neither was written"
    );

    // Nothing is asserted about arrival order here. The insertions are written
    // before the section, but they travel on a different stream, and the first
    // version of this test asserted they would arrive first — which failed, as
    // it should have. A client that permits blocked streams handles either
    // order; one that does not is why this test reports inconclusive rather
    // than running at all.
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_blocked_stream_test_sends_its_insertions_after_the_section() {
    let wire = drive("h-qpack-blocked-stream").await;

    let section = headers_frame(&wire.response).expect("a complete HEADERS frame");
    let (required_insert_count, _) = f::read_varint(section).expect("the field section prefix");
    assert_ne!(
        required_insert_count, 0,
        "a stream cannot block on a section that references nothing"
    );

    // RFC 9204 §3.2.2: "the encoder MUST NOT insert entries into the dynamic
    // table ... unless it has sent" a Set Dynamic Table Capacity instruction.
    // Without it a decoder cannot hold a reference into a table it has not been told to allocate.
    let (capacity, _) = set_capacity(&wire.encoder)
        .expect("the encoder stream must open with Set Dynamic Table Capacity");
    assert!(
        capacity > 0,
        "a capacity of zero leaves no room to insert into"
    );

    assert_eq!(
        count_insertions(&wire.encoder),
        2,
        "the insertions must still arrive, or the stream would block forever"
    );

    // The whole difference between this test and the one above, and the one
    // ordering that *is* ours to guarantee: the delay is deliberate, and far
    // longer than any scheduling noise that could reverse it.
    let gap = wire
        .insertions_at
        .saturating_duration_since(wire.headers_at);
    assert!(
        gap >= Duration::from_millis(200),
        "the section must arrive a clear interval before the insertions, or nothing is \
         blocked and the test measures ordinary decoding; the gap was {gap:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_overflow_test_asks_for_more_than_this_client_granted() {
    // The regression this exists for: the capacity was the constant 4096,
    // chosen because every client then advertised zero. `CLIENT_LIMITS` here
    // advertises 4096, which is what our own client now sends, and 4096 does
    // not exceed 4096 -- so the port would have sent a legal instruction and
    // the suite would have graded a client for accepting it.
    let wire = drive("h-qpack-encoder-overflow").await;

    let encoder = wire.encoder.as_slice();
    assert!(
        !encoder.is_empty(),
        "the port must write a Set Dynamic Table Capacity instruction"
    );

    // Set Dynamic Table Capacity: 001 prefix, 5-bit prefix integer.
    assert_eq!(
        encoder[0] & 0b1110_0000,
        0b0010_0000,
        "the first encoder instruction must be Set Dynamic Table Capacity, got {:#04x}",
        encoder[0]
    );
    let capacity = qpack_prefix_int(encoder, 5).expect("the capacity prefix integer");

    assert!(
        capacity > CLIENT_LIMITS.capacity,
        "the capacity asked for ({capacity}) must exceed the {} this client advertised, \
         or §3.2.3 permits it and there is no violation to reject",
        CLIENT_LIMITS.capacity
    );
}

/// Decode a QPACK prefix integer (RFC 7541 §5.1, which RFC 9204 inherits).
///
/// Not the QUIC varint `read_varint` reads: the first byte carries `n` value
/// bits under the instruction's own flag bits, and only overflows into
/// continuation bytes when those `n` bits are all ones.
fn qpack_prefix_int(buf: &[u8], prefix_bits: u32) -> Option<u64> {
    let mask = (1u64 << prefix_bits) - 1;
    let first = u64::from(*buf.first()?) & mask;
    if first < mask {
        return Some(first);
    }
    let mut value = first;
    let mut shift = 0;
    for &byte in &buf[1..] {
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}
