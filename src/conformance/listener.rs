//! One QUIC listener per test.
//!
//! Each listener binds its own UDP port, knows which test it serves from its
//! own `local_addr()`, and owns every connection that arrives there from the
//! first packet. That total ownership is what makes the awkward cases possible:
//! nothing else is managing the control stream, so the server can emit a
//! duplicate SETTINGS identifier or a reserved frame type without a
//! well-behaved HTTP/3 implementation getting in the way.
//!
//! # Shape of a run
//!
//! 1. the client connects to the port for the test it wants
//! 2. the server opens its control stream and emits the anomaly
//! 3. the server waits for the **liveness probe** — any stream the client opens
//!    afterwards
//! 4. what happened is recorded against the session and scored by
//!    [`session::judge`]
//!
//! Step 3 is the load-bearing one. A client that quietly died and a client that
//! correctly ignored the anomaly look identical up to that point.
//!
//! # Session correlation
//!
//! A client walks the catalogue by connecting to each port in turn, and the
//! results have to accumulate somewhere. The session id travels in the ALPN-
//! adjacent slot the client controls without needing a request: the **SNI**.
//! A client connecting with server name `<session>.conformance.pqcrypta.com`
//! has its verdicts filed under `<session>`; anything else gets a throwaway
//! session so a casual connection still works and still reports.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use tracing::{debug, info, warn};

use super::catalog::{self, Test, Tier};
use super::h3_frames as f;
use super::session::Observation;
use super::Conformance;
use crate::tls::TlsProvider;

/// A listener bound to one port, serving one test.
pub struct TestListener {
    endpoint: quinn::Endpoint,
    test: &'static Test,
    conformance: Arc<Conformance>,
}

impl TestListener {
    /// Bind the port for `test`.
    pub fn bind(
        test: &'static Test,
        addr: SocketAddr,
        tls_provider: &Arc<TlsProvider>,
        conformance: Arc<Conformance>,
    ) -> anyhow::Result<Self> {
        let mut server_config =
            quinn::ServerConfig::with_crypto(tls_provider.get_quic_server_config());

        let mut transport = quinn::TransportConfig::default();
        // Short idle timeout. These connections exist to run one test and stop;
        // the production default would hold a socket open long after a client
        // that failed a test has given up.
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("30s is a valid idle timeout"),
        ));

        // Per-test transport shaping. Several QUIC-layer anomalies are produced
        // by how the endpoint is configured rather than by bytes written after
        // the handshake, so they are set up here.
        match test.id {
            // Advertise windows small enough that any real request has to stop
            // and say so. A client that ignores them is overrunning a limit it
            // agreed to.
            "q-flow-control" => {
                transport.receive_window(quinn::VarInt::from_u32(1024));
                transport.stream_receive_window(quinn::VarInt::from_u32(512));
            }
            // Offer the extension and see whether the peer takes it up. Either
            // answer conforms; falling over does not.
            "q-ack-frequency" => {
                transport.ack_frequency_config(Some(quinn::AckFrequencyConfig::default()));
            }
            // Offer more than one path. Almost nothing on the public internet
            // will accept, which is the point of measuring it.
            "q-multipath" => {
                transport.max_concurrent_multipath_paths(4);
            }
            _ => {}
        }

        server_config.transport = Arc::new(transport);

        let socket = std::net::UdpSocket::bind(addr)
            .with_context(|| format!("binding conformance port {addr} for {}", test.id))?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime for conformance endpoint"))?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Same version list as the production listener, except where the test
        // is specifically about version negotiation.
        endpoint_config.supported_versions(vec![0x0000_0001, 0x6b33_43cf]);

        let endpoint = quinn::Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

        Ok(Self {
            endpoint,
            test,
            conformance,
        })
    }

    /// Accept connections until shut down.
    pub async fn run(self) {
        let port = self
            .endpoint
            .local_addr()
            .map(|a| a.port())
            .unwrap_or_default();
        debug!("conformance: {} listening on udp/{}", self.test.id, port);

        while let Some(incoming) = self.endpoint.accept().await {
            let test = self.test;
            let conformance = self.conformance.clone();

            // Source-address validation, on only for the test that measures it
            // (RFC 9000 §8.1.2). The client re-sends its Initial echoing the
            // token, and that second Incoming arrives already validated and is
            // handled normally. Every other test wants an ordinary handshake so
            // whatever the client does is attributable to the anomaly.
            if test.id == "q-retry" && !incoming.remote_address_validated() {
                if let Err(e) = incoming.retry() {
                    // retry() consumes the Incoming even when it fails, so
                    // there is nothing left to accept; the client will try
                    // again on its own.
                    debug!("conformance: q-retry could not send Retry: {e}");
                }
                continue;
            }

            tokio::spawn(async move {
                if let Err(e) = run_one(incoming, test, conformance).await {
                    // A client failing a test often means a broken connection,
                    // which surfaces here as an error. That is data, not a
                    // fault: the verdict has already been recorded.
                    debug!("conformance: {} connection ended: {}", test.id, e);
                }
            });
        }
    }
}

/// Drive one client through one test.
async fn run_one(
    incoming: quinn::Incoming,
    test: &'static Test,
    conformance: Arc<Conformance>,
) -> anyhow::Result<()> {
    let started = Instant::now();
    // Captured before the handshake: `Connection::remote_address` panics once
    // the connection is established, and this is the address that finds the
    // session anyway. Canonicalised so an IPv4-mapped IPv6 peer matches the
    // plain IPv4 address its /session call arrived from — the two spellings
    // have caused a lookup miss in this codebase before.
    let peer_ip = crate::security::canonical_addr(incoming.remote_address()).ip();
    let connecting = incoming.accept()?;
    let connection = connecting.await?;

    // Recover the session from the SNI, if the client offered one.
    let session_id = connection
        .handshake_data()
        .and_then(|d| {
            d.downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok()
                .and_then(|h| h.server_name)
        })
        .and_then(|sni| session_from_sni(&sni, &conformance.config.host))
        .filter(|id| conformance.sessions.exists(id))
        // SNI only works with a wildcard certificate for the session
        // subdomain; without one the handshake fails before a test can run.
        // The address that started the session is the channel that always
        // works.
        .or_else(|| conformance.sessions.for_source(peer_ip))
        .unwrap_or_else(|| conformance.sessions.create());

    // Held for the lifetime of this function, not just for the emit call.
    //
    // `Drop for SendStream` finishes the stream, and RFC 9114 §6.2.1 makes a
    // closed control stream H3_CLOSED_CRITICAL_STREAM. Holding these in the
    // helper meant they dropped the moment it returned — after the response was
    // written but before the client had read it — so a correct client saw our
    // violation, closed the connection, and reported an error on a test it had
    // just passed.
    let critical_streams = match emit(&connection, test).await {
        Ok(streams) => streams,
        Err(e) => {
            debug!("conformance: {} could not emit anomaly: {}", test.id, e);
            Vec::new()
        }
    };

    let observation = if critical_streams.is_empty() {
        classify_close(&connection)
    } else {
        watch_for_liveness(&connection, &conformance, test).await
    };

    // Some QUIC-layer tests are judged on what the connection did rather than
    // on whether a request arrived, so the transport's own account of it
    // supersedes the liveness result.
    let observation = quic_observation(&connection, test).unwrap_or(observation);

    // An unbuilt test served a correct control stream, so whatever the client
    // did says nothing about the anomaly — it never met one. Judging anyway
    // would fail a correctness test for "accepting a violation" we did not
    // send, which is exactly the false accusation this suite has to avoid to be
    // worth running at all.
    let observation = if test.implemented {
        observation
    } else {
        Observation::Signalled(format!(
            "the {} anomaly is not implemented yet; the client met a correct server",
            test.id
        ))
    };
    let elapsed = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);

    conformance.sessions.with(&session_id, |s| {
        s.record(test, &observation, expected_code(test), elapsed);
    });

    info!(
        "conformance: {} session={} observed={:?} close_reason={:?}",
        test.id,
        session_id,
        observation,
        connection.close_reason()
    );

    // Let the client close.
    //
    // `close()` sends CONNECTION_CLOSE immediately and discards anything still
    // queued, so calling it after writing the liveness response threw the
    // response body away: the client received the headers, waited for a body
    // that had just been dropped on the floor, and reported a transport error
    // on a test it had passed.
    //
    // The client closes as soon as it has read the response, so waiting for it
    // is both correct and quick. The window only has to be longer than a slow
    // read; the endpoint's 30s idle timeout is the real backstop for a client
    // that never closes at all, and CONNECTION_CLOSE here would just recreate
    // the original bug on a slower connection.
    let grace = Duration::from_secs(10);
    let _ = tokio::time::timeout(grace, connection.closed()).await;

    // Explicit, so nobody "tidies up" the binding above: these must outlive the
    // wait, or the control stream closes while the client is still reading and
    // our violation gets scored against them.
    drop(critical_streams);
    Ok(())
}

/// The leading label of `<session>.<conformance-host>`, when that is the shape.
fn session_from_sni(sni: &str, host: &str) -> Option<String> {
    let suffix = format!(".{host}");
    let label = sni.strip_suffix(&suffix)?;
    // A session id is 32 hex characters; anything else is somebody else's
    // subdomain and must not be treated as a session handle.
    if label.len() == 32 && label.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(label.to_string())
    } else {
        None
    }
}

/// The application error code a correct client must use to reject this test's
/// anomaly, where the specification names one.
fn expected_code(test: &Test) -> Option<u64> {
    use f::error_code as e;
    match test.id {
        "h-control-frame-unexpected" => Some(e::H3_FRAME_UNEXPECTED),
        "h-missing-settings" => Some(e::H3_MISSING_SETTINGS),
        "h-second-control-stream" => Some(e::H3_STREAM_CREATION_ERROR),
        "h-max-push-id" => Some(e::H3_FRAME_UNEXPECTED),
        _ => None,
    }
}

/// Write this test's anomaly onto the connection.
///
/// Tests not yet implemented open a well-formed control stream and nothing
/// else, so a client sees a correct server rather than a silent port. Their
/// verdict is whatever the liveness probe yields, which for an unimplemented
/// test means "the client can talk to us" — honest, and not a claim that the
/// anomaly was handled.
async fn emit(
    connection: &quinn::Connection,
    test: &'static Test,
) -> anyhow::Result<Vec<quinn::SendStream>> {
    // Streams the caller must hold for the life of the connection.
    //
    // `Drop for SendStream` calls `finish()`, so letting one fall out of scope
    // *closes* it — and RFC 9114 §6.2.1 makes closing a control stream
    // H3_CLOSED_CRITICAL_STREAM. That would be our violation, not the client's,
    // and a correct client would close the connection over it, failing a test it
    // had actually handled properly.
    let mut keep_open = Vec::new();

    let mut control = connection.open_uni().await?;
    control
        .write_all(&f::uni_stream_header(f::stream_type::CONTROL))
        .await?;

    // QPACK encoder and decoder streams. Nothing here uses the dynamic table —
    // every field section is literal with Required Insert Count 0 — but RFC 9204
    // §4.2 says an endpoint SHOULD create both, and clients that wait for them
    // before processing a field section would otherwise stall on a response and
    // be scored as having failed a test they never saw.
    for ty in [f::stream_type::QPACK_ENCODER, f::stream_type::QPACK_DECODER] {
        let mut s = connection.open_uni().await?;
        s.write_all(&f::uni_stream_header(ty)).await?;

        keep_open.push(s);
    }

    match test.id {
        // The client must ignore a SETTINGS identifier it does not know.
        "h-grease-settings" => {
            control.write_all(&f::settings_with_grease()).await?;
        }

        // Two entries with the same identifier: H3_SETTINGS_ERROR.
        "h-duplicate-setting" => {
            control
                .write_all(&f::settings(&[
                    (f::setting::MAX_FIELD_SECTION_SIZE, 16_384),
                    (f::setting::MAX_FIELD_SECTION_SIZE, 32_768),
                ]))
                .await?;
        }

        // The control stream's first frame must be SETTINGS.
        "h-missing-settings" => {
            control.write_all(&f::goaway(0)).await?;
        }

        // DATA is forbidden on the control stream: H3_FRAME_UNEXPECTED.
        "h-control-frame-unexpected" => {
            control.write_all(&f::settings_with_grease()).await?;
            control.write_all(&f::data(b"not allowed here")).await?;
        }

        // Only one control stream per direction is permitted.
        "h-second-control-stream" => {
            control.write_all(&f::settings_with_grease()).await?;
            let mut second = connection.open_uni().await?;
            second
                .write_all(&f::uni_stream_header(f::stream_type::CONTROL))
                .await?;
            second.write_all(&f::settings_with_grease()).await?;
            // Held open like the first: the violation under test is that a
            // second control stream exists at all, not that one was closed.
            keep_open.push(second);
        }

        // A unidirectional stream of a type the client does not know must be
        // ignored, not treated as fatal.
        "h-reserved-uni-stream" => {
            control.write_all(&f::settings_with_grease()).await?;
            let mut reserved = connection.open_uni().await?;
            reserved
                .write_all(&f::reserved_uni_stream_header(3))
                .await?;
            reserved.write_all(b"ignore me").await?;
            let _ = reserved.finish();
        }

        // GOAWAY mid-connection: stop starting new requests, finish the rest.
        "h-goaway" => {
            control.write_all(&f::settings_with_grease()).await?;
            control.write_all(&f::goaway(0)).await?;
        }

        // Push with no MAX_PUSH_ID granted is an H3_ID_ERROR.
        "h-max-push-id" => {
            control.write_all(&f::settings_with_grease()).await?;
            control.write_all(&f::max_push_id(0)).await?;
        }

        // Everything else gets a correct control stream. The anomaly for these
        // lives at the QUIC layer, or is not built yet; either way a client
        // meets a working server rather than an unexplained silence.
        _ => {
            control.write_all(&f::settings_with_grease()).await?;
        }
    }

    keep_open.push(control);
    Ok(keep_open)
}

/// Wait for the client to prove it survived, then answer it.
///
/// The probe must be a **bidirectional** stream — a request. Unidirectional
/// streams do not count and are drained in the background instead.
///
/// This distinction is the difference between a meaningful verdict and a
/// worthless one. Every HTTP/3 client opens its control and QPACK streams
/// immediately on connecting, before it has read a byte of our SETTINGS. Taking
/// any stream as the probe therefore passed every extensibility test the
/// instant a client connected, proving only that it speaks HTTP/3 at all. A
/// request, by contrast, can only be issued after the client has processed the
/// control stream carrying the anomaly.
///
/// When the probe is a request stream, it gets a real HTTP/3 response saying so
/// before the connection closes. Recording the verdict and hanging up would be
/// enough for us and useless for the person running the test: their client
/// would report a transport error on a run it had just *passed*, which is
/// exactly the confusing signal this suite exists to remove.
///
/// The receive half is drained rather than dropped. `Drop for RecvStream` sends
/// STOP_SENDING unless every byte has been read, which tells the client to
/// abandon the request it is in the middle of — the client then reports a write
/// error on a test it passed, and the response we were about to send never gets
/// read.
async fn watch_for_liveness(
    connection: &quinn::Connection,
    conformance: &Conformance,
    test: &'static Test,
) -> Observation {
    let timeout = Duration::from_millis(conformance.config.liveness_timeout_ms);

    // Drain the client's unidirectional streams for the life of this
    // connection. They are not the probe, but they must be read: dropping a
    // RecvStream with data outstanding sends STOP_SENDING, and doing that to a
    // client's control stream is a protocol violation of ours that would be
    // scored against the client.
    // Learn what the client permits while draining. SETTINGS_QPACK_MAX_TABLE_CAPACITY
    // governs whether *our* encoder may use the dynamic table (RFC 9204 §5);
    // the default is zero, and using it anyway would be our violation.
    let qpack_capacity = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let drainer = tokio::spawn({
        let connection = connection.clone();
        let capacity = qpack_capacity.clone();
        async move {
            while let Ok(mut uni) = connection.accept_uni().await {
                let capacity = capacity.clone();
                tokio::spawn(async move {
                    if let Ok(bytes) = uni.read_to_end(64 * 1024).await {
                        if let Some(c) = f::parse_qpack_capacity(&bytes) {
                            capacity.store(c, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    });

    let probe = tokio::time::timeout(timeout, connection.accept_bi()).await;
    drainer.abort();

    match probe {
        Ok(Ok(stream)) => {
            {
                let (mut send, mut recv) = stream;
                // Drain the request before replying. Bounded: a conformance
                // probe carries no body worth reading, and an unbounded read
                // would let a client hold the connection open indefinitely.
                const MAX_PROBE_REQUEST: usize = 64 * 1024;
                let drained = tokio::time::timeout(
                    Duration::from_secs(2),
                    recv.read_to_end(MAX_PROBE_REQUEST),
                )
                .await;
                if !matches!(drained, Ok(Ok(_))) {
                    debug!("conformance: probe request not fully drained");
                }

                let capacity = qpack_capacity.load(std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = answer_probe(&mut send, test, capacity).await {
                    debug!("conformance: could not answer liveness probe: {}", e);
                }
            }

            // A request stream arriving is not yet proof the client accepted
            // the anomaly. Clients open the request immediately on connecting,
            // before they have read our control stream, so the probe routinely
            // arrives *first* and the rejection lands a moment later. Deciding
            // at the probe recorded curl as having accepted an invalid frame
            // sequence it had in fact rejected correctly — the same class of
            // false accusation as scoring a MAY as a MUST.
            //
            // So settle: wait for the client to close, and let the reason
            // decide. Silence means it really did carry on.
            let settle = Duration::from_secs(2);
            match tokio::time::timeout(settle, connection.closed()).await {
                Ok(_) => match classify_close(connection) {
                    // A clean close after a completed request is exactly what a
                    // client that handled the anomaly does.
                    Observation::ClosedSilently => Observation::SurvivedAndContinued,
                    other => other,
                },
                Err(_) => Observation::SurvivedAndContinued,
            }
        }
        Ok(Err(_)) => classify_close(connection),
        Err(_) => {
            // Nothing arrived in time. If the peer had closed we would have
            // seen an error above, so distinguish a real stall from a close
            // that raced the timeout.
            match connection.close_reason() {
                Some(_) => classify_close(connection),
                None => Observation::TimedOut,
            }
        }
    }
}

/// What the transport itself can say about a QUIC-layer test.
///
/// `None` means this test is judged the ordinary way, on the liveness probe.
/// These read the connection's own frame counters, because the behaviour under
/// test happens below HTTP entirely and the client cannot be asked about it.
fn quic_observation(connection: &quinn::Connection, test: &'static Test) -> Option<Observation> {
    let rx = connection.stats().frame_rx;

    match test.id {
        // Getting here at all means the client echoed the token in a second
        // Initial: this port answers the first attempt with Retry and nothing
        // else, so there is no other route to a completed handshake.
        "q-retry" => Some(Observation::Signalled(
            "echoed the Retry token and completed the handshake".to_string(),
        )),

        // The windows on this port are far too small for a real request, so a
        // client that respects them has to say it is stuck. Announcing the
        // stall is the required behaviour; quietly overrunning a limit it
        // agreed to is the bug.
        "q-flow-control" => {
            let blocked = rx.data_blocked + rx.stream_data_blocked;
            Some(if blocked > 0 {
                Observation::Signalled(format!(
                    "respected the window and announced the stall ({} DATA_BLOCKED, \
                     {} STREAM_DATA_BLOCKED)",
                    rx.data_blocked, rx.stream_data_blocked
                ))
            } else {
                Observation::NotExercised(
                    "the request never approached the advertised window, so no \
                     DATA_BLOCKED was due"
                        .to_string(),
                )
            })
        }

        // Either answer conforms — the extension is optional — so this reports
        // which was chosen rather than scoring it.
        "q-ack-frequency" => Some(Observation::Signalled(if rx.ack_frequency > 0 {
            format!(
                "negotiated the extension and sent {} ACK_FREQUENCY frames",
                rx.ack_frequency
            )
        } else {
            "ignored the extension, which the specification permits".to_string()
        })),

        // quinn issues NEW_CONNECTION_ID on its own; what matters is whether
        // the client took them up and retired the old ones.
        "q-cid-rotation" => Some(if rx.retire_connection_id > 0 {
            Observation::Signalled(format!(
                "rotated connection IDs and retired {} of them",
                rx.retire_connection_id
            ))
        } else {
            Observation::NotExercised(
                "the connection was too short-lived to require a rotation".to_string(),
            )
        }),

        // A PATH_RESPONSE echoing our challenge is the whole requirement.
        "q-path-challenge" => Some(if rx.path_response > 0 {
            Observation::Signalled(format!("answered with {} PATH_RESPONSE", rx.path_response))
        } else {
            Observation::NotExercised(
                "no path validation was triggered, so no PATH_RESPONSE was due".to_string(),
            )
        }),

        // Almost nothing on the public internet speaks multipath, which is
        // precisely why it is worth measuring rather than assuming.
        "q-multipath" => Some(Observation::Signalled(if rx.max_path_id > 0 {
            format!(
                "negotiated multipath ({} MAX_PATH_ID frames)",
                rx.max_path_id
            )
        } else {
            "declined the multipath offer and stayed on one path, which is conformant".to_string()
        })),

        _ => None,
    }
}

/// Send an ordinary 200 on the client's request stream.
///
/// Deliberately plain HTTP/3 — this is the one part of the exchange that must
/// be completely unremarkable, because it is how the client learns it got
/// through the anomaly intact.
async fn answer_probe(
    send: &mut quinn::SendStream,
    test: &'static Test,
    qpack_capacity: u64,
) -> anyhow::Result<()> {
    const BODY: &[u8] = b"liveness probe received; this connection survived the test\n";

    match test.id {
        // A frame of a reserved type ahead of the response. The client must
        // skip it using its length and read the HEADERS that follow.
        "h-grease-frame" => {
            send.write_all(&f::reserved_frame(11, b"skip me by length"))
                .await?;
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "grease-frame-preceded-this"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // Values Huffman-coded, with the padding that legal encodings carry.
        "h-qpack-huffman" => {
            let section = f::qpack_huffman_headers(&[
                (":status", f::huffman::STATUS_200, 3),
                ("content-type", f::huffman::TEXT_PLAIN, 10),
                ("x-conformance", f::huffman::HUFFMAN_ENCODED, 15),
            ]);
            send.write_all(&f::headers_raw(&section)).await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // Field lines that reference entries inserted on the encoder stream.
        // The insertions themselves go out in `emit`, before the probe.
        "h-qpack-dynamic-table" => {
            // Only if the client granted capacity. Referencing the dynamic
            // table when it advertised zero — the default, and what curl sends
            // — is a violation by us, and the client would be right to reset
            // the stream. Falling back keeps the connection honest; the verdict
            // records that the test did not apply.
            let section = if qpack_capacity > 0 {
                f::qpack_dynamic_headers(
                    DYNAMIC_INSERTS,
                    &[(":status", "200"), ("content-type", "text/plain")],
                )
            } else {
                f::qpack_literal_headers(&[
                    (":status", "200"),
                    ("content-type", "text/plain"),
                    ("x-conformance", "client-granted-no-qpack-dynamic-capacity"),
                ])
            };
            send.write_all(&f::headers_raw(&section)).await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // A field section past any sane SETTINGS_MAX_FIELD_SECTION_SIZE. The
        // client should fail this one request, not the whole connection.
        "h-oversized-field-section" => {
            let filler = "x".repeat(32 * 1024);
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance-oversized", filler.as_str()),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // A trailing field section after the body.
        "h-trailers" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("trailer", "x-conformance-trailer"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
            send.write_all(&f::headers(&[(
                "x-conformance-trailer",
                "arrived-after-the-body",
            )]))
            .await?;
        }

        // 103 first, then the real response. A client that treats the interim
        // as final stops reading and never sees the 200.
        "h-early-hints" => {
            send.write_all(&f::headers(&[
                (":status", "103"),
                ("link", "</style.css>; rel=preload; as=style"),
            ]))
            .await?;
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "early-hints-preceded-this"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        _ => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "liveness-ok"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }
    }

    send.finish()?;
    Ok(())
}

/// How many entries `h-qpack-dynamic-table` inserts before referencing them.
const DYNAMIC_INSERTS: u64 = 2;

/// Turn a closed connection into an observation, preserving the error code the
/// client chose — which for the correctness tests is the entire point.
fn classify_close(connection: &quinn::Connection) -> Observation {
    use quinn::ConnectionError as Ce;
    match connection.close_reason() {
        // The client rejected the anomaly and named a code. For the correctness
        // tests this is the whole point of the exercise.
        Some(Ce::ApplicationClosed(app)) => Observation::ClosedWith {
            code: app.error_code.into_inner(),
        },
        // A QUIC-layer close. The client objected but at the transport layer,
        // so there is no HTTP/3 error code to compare against — say what it was
        // rather than flattening it to "silently", which reads as though the
        // client said nothing at all.
        Some(Ce::TransportError(e)) => {
            Observation::Signalled(format!("closed at the QUIC layer: {}", e.code))
        }
        // The common case in practice. curl/ngtcp2 rejects an HTTP/3 violation
        // by closing at the transport layer rather than with an application
        // close, so the discriminator is the code: NO_ERROR is a client that
        // finished normally, anything else is a client objecting.
        //
        // Note it does not carry the HTTP/3 code — H3_MISSING_SETTINGS arrives
        // as INTERNAL_ERROR — so the rejection is verifiable but the specific
        // code is not, for this client. Reported as a signal rather than as a
        // code, so the report never claims to have checked something it could
        // not see.
        Some(Ce::ConnectionClosed(close)) => {
            if close.error_code == quinn_proto::TransportErrorCode::NO_ERROR {
                Observation::ClosedSilently
            } else {
                Observation::Signalled(format!(
                    "rejected at the QUIC layer with {:?}",
                    close.error_code
                ))
            }
        }
        Some(Ce::Reset) => Observation::Signalled("connection reset".to_string()),
        Some(Ce::TimedOut) => Observation::TimedOut,
        Some(other) => {
            debug!("conformance: unclassified close reason: {other}");
            Observation::ClosedSilently
        }
        None => Observation::ClosedSilently,
    }
}

/// Bind every port the catalogue needs.
///
/// A port that cannot be bound is logged and skipped rather than aborting
/// startup: the suite is a side feature, and refusing to serve the site because
/// one test port is taken would be a poor trade.
pub fn spawn_all(conformance: &Arc<Conformance>, tls_provider: &Arc<TlsProvider>, bind_ip: &str) {
    let start = conformance.config.port_range.0;
    let mut bound = 0usize;

    for test in catalog::CATALOG {
        let Some(offset) = test.port_offset else {
            continue;
        };
        let port = start + offset;
        let addr: SocketAddr = match format!("{bind_ip}:{port}").parse() {
            Ok(a) => a,
            Err(e) => {
                warn!("conformance: bad bind address for {}: {}", test.id, e);
                continue;
            }
        };

        match TestListener::bind(test, addr, &tls_provider, conformance.clone()) {
            Ok(listener) => {
                bound += 1;
                tokio::spawn(listener.run());
            }
            Err(e) => warn!(
                "conformance: {} could not bind udp/{}: {}",
                test.id, port, e
            ),
        }
    }

    info!(
        "🧪 Conformance suite: {}/{} tests listening on udp/{}-{}",
        bound,
        catalog::CATALOG.len(),
        start,
        start + catalog::required_ports() - 1
    );
}

/// The catalogue as JSON, for the client driver to walk.
pub fn catalog_json(conformance: &Conformance) -> String {
    let start = conformance.config.port_range.0;
    let entries: Vec<_> = catalog::CATALOG
        .iter()
        .map(|t| {
            serde_json::json!({
                "id": t.id,
                "title": t.title,
                "spec": t.spec,
                "class": t.class.as_str(),
                "layer": match t.tier { Tier::Http3 => "http3", Tier::Quic => "quic" },
                "expectation": t.expectation,
                "port": t.port_offset.map(|o| start + o),
            })
        })
        .collect();

    serde_json::json!({
        "host": conformance.config.host,
        "tests": entries,
        "how": "Connect to each port in turn. To collect results under one session, \
                use SNI <session>.<host>; obtain a session from /session.",
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_is_recovered_from_the_sni() {
        let host = "conformance.pqcrypta.com";
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            session_from_sni(&format!("{id}.{host}"), host).as_deref(),
            Some(id)
        );
    }

    #[test]
    fn a_bare_host_carries_no_session() {
        let host = "conformance.pqcrypta.com";
        assert!(session_from_sni(host, host).is_none());
    }

    #[test]
    fn only_a_well_formed_id_is_treated_as_a_session() {
        let host = "conformance.pqcrypta.com";
        // Someone else's subdomain must not become a session handle.
        assert!(session_from_sni(&format!("www.{host}"), host).is_none());
        assert!(session_from_sni(&format!("short.{host}"), host).is_none());
        // Right length, wrong alphabet.
        let not_hex = "z".repeat(32);
        assert!(session_from_sni(&format!("{not_hex}.{host}"), host).is_none());
    }

    #[test]
    fn a_different_host_is_ignored() {
        assert!(session_from_sni(
            "0123456789abcdef0123456789abcdef.example.com",
            "conformance.pqcrypta.com"
        )
        .is_none());
    }

    #[test]
    fn correctness_tests_name_the_code_the_rfc_requires() {
        for t in catalog::CATALOG {
            let code = expected_code(t);
            if matches!(
                t.id,
                "h-control-frame-unexpected"
                    | "h-missing-settings"
                    | "h-second-control-stream"
                    | "h-max-push-id"
            ) {
                assert!(code.is_some(), "{} must name an expected code", t.id);
            }
            // A discretionary test must NOT name one: the specification permits
            // more than one response, so demanding a particular code would fail
            // conformant clients.
            if t.class == catalog::Class::Discretionary {
                assert!(
                    code.is_none(),
                    "{} is discretionary and must not require a code",
                    t.id
                );
            }
        }
        assert_eq!(
            expected_code(catalog::find("h-missing-settings").unwrap()),
            Some(f::error_code::H3_MISSING_SETTINGS)
        );
        // MAX_PUSH_ID is client-to-server only, so a client receiving one
        // rejects it as an unexpected frame, not as a bad identifier.
        assert_eq!(
            expected_code(catalog::find("h-max-push-id").unwrap()),
            Some(f::error_code::H3_FRAME_UNEXPECTED)
        );
    }
}
