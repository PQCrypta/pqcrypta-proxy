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
//!    [`judge`](super::session::judge)
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
use super::impairment::{Counters, ImpairedSocket, Impairments};
use super::session::Observation;
use super::Conformance;
use crate::tls::TlsProvider;

/// The unknown QUIC frame type `q-reserved-frame` emits.
///
/// Unassigned in the IANA QUIC Frame Types registry and nowhere near an assigned
/// range, so nothing can plausibly parse it.
const RESERVED_FRAME_TYPE: u64 = 0x2a2a;

/// `ack_delay_exponent` (RFC 9000 §18.2).
const ACK_DELAY_EXPONENT_ID: u64 = 0x0a;

/// One past the ceiling §18.2 sets for it: "Values above 20 are invalid."
///
/// Invalid by the parameter's own definition, so a peer needs no context to know
/// it — which is what makes the rejection a statement about §7.4 rather than
/// about anything this endpoint negotiated.
const INVALID_ACK_DELAY_EXPONENT: u64 = 21;

/// One datagram in this many is held back and released late on
/// `q-packet-reordering`'s port.
const REORDER_CADENCE: u64 = 6;

/// How many datagrams `q-connection-migration` copies out of a second socket.
const SHADOW_DATAGRAMS: u64 = 6;

/// How long that test holds the response, so datagrams are still flowing once
/// the copy window has opened.
const SHADOW_HOLD: Duration = Duration::from_millis(900);

/// How long before the copies begin. Past the handshake — a second address
/// appearing mid-handshake is a different question from one appearing on an
/// established connection, and §9.6 is about the latter.
const SHADOW_OPENS_AFTER: Duration = Duration::from_millis(150);

/// One datagram in this many is dropped on `q-loss-recovery`'s port.
///
/// Named once because both the impairment and the sentence explaining an
/// unexercised run quote it, and a report that describes a different rate from
/// the one the path applied is worse than one that gives no rate at all.
const LOSS_CADENCE: u64 = 12;

/// A listener bound to one port, serving one test.
pub struct TestListener {
    endpoint: quinn::Endpoint,
    test: &'static Test,
    conformance: Arc<Conformance>,
    /// What the socket saw. Two tests are judged from this rather than from
    /// anything the peer said — see [`impairment`](super::impairment).
    counters: Arc<Counters>,
}

impl TestListener {
    /// Bind the port for `test`.
    pub fn bind(
        test: &'static Test,
        addr: SocketAddr,
        tls_provider: &Arc<TlsProvider>,
        conformance: Arc<Conformance>,
    ) -> anyhow::Result<Self> {
        // One port needs a TLS configuration of its own: it must offer early
        // data (which production does not) and refuse it (which production has
        // no reason to). Everything else shares the edge's own configuration, so
        // a client meets the same TLS it would in production.
        let crypto = if test.id == "q-zero-rtt-reject" {
            tls_provider
                .build_zero_rtt_reject_config()
                .with_context(|| format!("building the TLS config for {}", test.id))?
        } else if test.id == "q-zero-rtt-replay" {
            // The only port that lets early data through. Everything this test
            // measures happens above it.
            tls_provider
                .build_zero_rtt_accept_config()
                .with_context(|| format!("building the TLS config for {}", test.id))?
        } else {
            tls_provider.get_quic_server_config()
        };
        let mut server_config = quinn::ServerConfig::with_crypto(crypto);

        let mut transport = quinn::TransportConfig::default();
        // Short idle timeout. These connections exist to run one test and stop;
        // the production default would hold a socket open long after a client
        // that failed a test has given up.
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("30s is a valid idle timeout"),
        ));

        // Keep a packet flowing, so a peer that has closed says so again.
        //
        // Every verdict here turns on how the connection ended, and the server
        // waits a couple of seconds after the anomaly to find out. A
        // CONNECTION_CLOSE is not retransmitted on a timer: RFC 9000 §10.2.1
        // has a closing endpoint re-send it only *in response to* an incoming
        // packet. So when the client's close was lost — and one in roughly a
        // dozen was, over a real network — an idle server heard nothing more,
        // the wait expired, and a client that had rejected the anomaly with
        // exactly the right error code was recorded as having accepted a
        // protocol violation and carried on.
        //
        // That is the false accusation this suite cannot afford, and it was
        // invisible from the same host: on loopback the close is never lost.
        // A keep-alive well inside the settle window means any peer still in its
        // closing period is prompted to repeat itself while we are listening.
        transport.keep_alive_interval(Some(Duration::from_millis(250)));

        // One port expects the handshake to be abandoned, so it must not wait
        // the full idle timeout to find out.
        //
        // A client that refuses the parameter stops there, and if it sends no
        // CONNECTION_CLOSE this endpoint can read, the only thing left is the
        // timeout. At thirty seconds that verdict arrives long after the run has
        // finished and the report has been read — which is how the test came
        // back as never having run at all, rather than as the inconclusive it
        // actually is.
        if test.id == "q-invalid-transport-param" {
            transport.max_idle_timeout(Some(
                Duration::from_secs(5)
                    .try_into()
                    .expect("5s is a valid idle timeout"),
            ));
        }

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
            // Exactly what one HTTP/3 request needs, and not one stream more.
            //
            // One bidirectional stream for the request; three unidirectional
            // for the control stream and the two QPACK streams every client
            // opens. A client that wants a fourth — a GREASE stream, an early
            // second request — meets the limit and has to wait for credit it
            // will not get.
            //
            // Set from what the protocol requires rather than to a round
            // number: a limit above what a request needs is never reached and
            // measures nothing, and one below it stalls the liveness probe and
            // fails every client for our configuration.
            "q-stream-limit" => {
                transport.max_concurrent_bidi_streams(1u32.into());
                transport.max_concurrent_uni_streams(3u32.into());
            }
            // Drive path-MTU discovery hard, so the path reaches a large size
            // before the hole opens underneath it.
            //
            // QUIC starts at 1200 and stays there unless something probes
            // upward, so with default settings the connection never rises above
            // the limit and the impairment measures nothing. Raising the upper
            // bound makes the one search at the start of every connection settle
            // at 1452 on the still-clean path, whatever the client sends — so
            // there is an established MTU for the hole to take away.
            //
            // The re-search interval is deliberately left at its long default.
            // Shortening it hides the very thing under test: a search that runs
            // while the hole is open finds the new ceiling gracefully and steps
            // the MTU down to just under it, so no ordinary packet is ever lost
            // and the black hole is never detected — the connection quietly
            // settles at 1293 and nothing looks wrong. One search, then a fixed
            // MTU, is what makes the loss visible.
            "q-pmtu-blackhole" => {
                let mut mtud = quinn::MtuDiscoveryConfig::default();
                mtud.upper_bound(1452);
                // Long enough that the recovery reads as a settled state rather
                // than an immediate re-probe straight back into the hole.
                mtud.black_hole_cooldown(Duration::from_secs(5));
                transport.mtu_discovery_config(Some(mtud));
                // Start at the floor the client can always fall back to.
                transport.initial_mtu(1200);
            }
            // Put a frame of unknown type in the first 1-RTT packet.
            //
            // RFC 9000 §12.4 makes an unknown frame type a connection error of
            // type FRAME_ENCODING_ERROR, with no ignorable range and no length
            // field to skip it by — unlike HTTP/3, where reserved frame types
            // exist precisely to be ignored. Two of this suite's tests therefore
            // look superficially alike and require opposite answers: ignoring
            // `h-grease-frame` is the pass, and ignoring this is the failure.
            //
            // 0x2a2a is unassigned in the QUIC frame type registry and far from
            // any assigned range, so a peer that recognises it has invented a
            // meaning for it.
            "q-reserved-frame" => {
                transport.send_unknown_frame_type(Some(RESERVED_FRAME_TYPE));
            }
            // Ask the path-validation question rather than waiting for it.
            //
            // A PATH_CHALLENGE is otherwise sent only while validating a path,
            // and a connection that never moves never validates one — so this
            // test spent its whole life reporting that no path validation had
            // been triggered.
            "q-path-challenge" => {
                transport.send_path_challenge(true);
            }
            // A parameter whose own definition rules its value out.
            //
            // §18.2 puts ack_delay_exponent's ceiling at 20, so 21 is invalid by
            // the parameter's own terms rather than by anything contextual — and
            // §7.4 makes that a MUST-level connection error. Chosen over a
            // duplicate parameter, which the same clause makes only a SHOULD and
            // which would therefore fail conformant clients for a legal choice,
            // exactly as `h-duplicate-setting` once did.
            "q-invalid-transport-param" => {
                transport.send_invalid_transport_param(Some((
                    ACK_DELAY_EXPONENT_ID,
                    INVALID_ACK_DELAY_EXPONENT,
                )));
            }
            _ => {}
        }

        server_config.transport = Arc::new(transport);

        let socket = std::net::UdpSocket::bind(addr)
            .with_context(|| format!("binding conformance port {addr} for {}", test.id))?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime for conformance endpoint"))?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        if test.id == "q-version-negotiation" {
            // Advertise only a reserved version, so a client offering QUIC v1
            // is answered with Version Negotiation listing nothing it can use.
            // Per RFC 9000 §6.2 a client supporting only this version MUST then
            // abandon the attempt — so no connection is ever established here,
            // and the verdict comes from the socket counters instead.
            //
            // This is why every test owns its own endpoint: `supported_versions`
            // is endpoint-wide, which is exactly the granularity needed when one
            // port is the whole test.
            endpoint_config.supported_versions(vec![0x1a2a_3a4a]);
        } else {
            endpoint_config.supported_versions(vec![0x0000_0001, 0x6b33_43cf]);
        }

        // A path that silently swallows anything large, for the black-hole test.
        //
        // The limit sits at 1300: above QUIC's 1200-byte minimum datagram (RFC
        // 9000 §14.1), so the client can always recover by dropping back to it,
        // and below the 1452 the path first establishes, so it is *carried*
        // traffic that starts disappearing.
        //
        // That gap is the whole test. A limit at 1200 only ever kills the
        // discovery probes, and a lost probe is not a black hole — it is how
        // discovery is supposed to work, which is why the detector ignores probe
        // losses entirely and only counts bursts of ordinary packets larger than
        // the minimum MTU. A black hole is a path that carried a size and then
        // stopped, so the port has to carry 1452 before it refuses it.
        let blackhole_above = (test.id == "q-pmtu-blackhole").then_some(1300);
        let counters = Arc::new(Counters::default());

        // Every port gets the counting socket, impaired or not.
        //
        // It used to be wrapped only for the two tests that need an impairment,
        // which quietly left `datagrams_in` reading zero on every other port —
        // and `q-stateless-reset`, which judges a client by whether it goes
        // quiet, read that permanent zero as silence and passed every client
        // that reached it. A counter that exists on some ports and not others is
        // worse than no counter at all, because it looks like an answer.
        //
        // With no threshold the wrapper is transparent: nothing is dropped and
        // segmentation is left to the inner socket.
        let inner = runtime.wrap_udp_socket(socket)?;

        // One datagram in twelve, once the connection is up.
        //
        // Enough loss that a response of any size meets several, and far short
        // of the rate at which QUIC's own congestion response would make the
        // transfer take longer than the test window. The clean second in front
        // of it is what keeps this a test of stream reassembly rather than of
        // handshake recovery: a handshake that loses packets is a different
        // requirement in a different part of the specification, and failing one
        // while reporting on the other would be a verdict about nothing.
        let loss_one_in = (test.id == "q-loss-recovery").then_some(LOSS_CADENCE);

        // A handful of datagrams from a second address, once the handshake is
        // done. Enough that a client which follows an unannounced server address
        // has plainly done so; few enough that one which correctly discards them
        // is not made to work for it.
        let shadow_datagrams = (test.id == "q-connection-migration").then_some(SHADOW_DATAGRAMS);

        // One datagram in six arrives behind the one that followed it. Frequent
        // enough that any response of a few packets meets several, and never so
        // frequent that the stream is more out of order than in.
        let reorder_one_in = (test.id == "q-packet-reordering").then_some(REORDER_CADENCE);

        // Open for the first four seconds, so discovery can raise the MTU to
        // 1452 on a path that genuinely carries it. Then the hole opens and
        // packets at that established size start disappearing — which is what a
        // black hole is, and what the detector looks for. The loss impairment
        // needs far less: one second is past the handshake on any path this
        // service can be reached over.
        let opens_after = match (
            blackhole_above,
            loss_one_in,
            shadow_datagrams,
            reorder_one_in,
        ) {
            (Some(_), _, _, _) => Some(Duration::from_secs(4)),
            (_, Some(_), _, _) => Some(Duration::from_millis(500)),
            (_, _, Some(_), _) => Some(SHADOW_OPENS_AFTER),
            // Past the handshake, which has its own ordering requirements and is
            // not what §2.2 is about.
            (_, _, _, Some(_)) => Some(Duration::from_millis(200)),
            _ => None,
        };
        let impaired = Box::new(ImpairedSocket::new(
            inner,
            Impairments {
                blackhole_above,
                loss_one_in,
                opens_after,
                reorder_one_in,
                shadow_datagrams,
            },
            counters.clone(),
        ));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            impaired,
            runtime,
        )?;

        Ok(Self {
            endpoint,
            test,
            conformance,
            counters,
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

        // Version negotiation never yields a connection, so its verdict cannot
        // come from the accept loop. A separate watcher reads the socket
        // counters instead: datagrams arrived, none became a connection, which
        // is a client abandoning the attempt as §6.2 requires.
        if self.test.id == "q-version-negotiation" {
            tokio::spawn(watch_version_negotiation(
                self.test,
                self.conformance.clone(),
                self.counters.clone(),
            ));
        }

        while let Some(incoming) = self.endpoint.accept().await {
            let test = self.test;
            let conformance = self.conformance.clone();
            let counters = self.counters.clone();
            // Cheap handle clone. `q-stateless-reset` reads the endpoint's reset
            // counter, which is the only place a Stateless Reset is observable.
            let endpoint = self.endpoint.clone();

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
                if let Err(e) = run_one(incoming, test, conformance, counters, endpoint).await {
                    // A client failing a test often means a broken connection,
                    // which surfaces here as an error. That is data, not a
                    // fault: the verdict has already been recorded.
                    debug!("conformance: {} connection ended: {}", test.id, e);
                }
            });
        }
    }
}

/// Judge the version-negotiation test from the socket.
///
/// This port advertises only a reserved version, so a client offering QUIC v1
/// gets a Version Negotiation packet and nothing else ever happens: no
/// handshake, no connection, no request. The RFC's requirement is precisely
/// that the client gives up, so "nothing happened" *is* the pass — but only if
/// the client actually tried, which is what the inbound datagram count proves.
///
/// Sampled rather than event-driven because there is no event to hook: the
/// stack answers the Initial and discards it without ever surfacing an
/// `Incoming`.
async fn watch_version_negotiation(
    test: &'static Test,
    conformance: Arc<Conformance>,
    counters: Arc<Counters>,
) {
    let mut last_seen = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let now = counters.datagrams_in();
        if now == last_seen {
            continue;
        }

        // Somebody tried since the last look. They were answered with Version
        // Negotiation and did not come back, because a connection on this port
        // is not possible.
        let arrived = now - last_seen;
        last_seen = now;

        // Filed against the session the client actually started, not a fresh
        // one.
        //
        // This used to call `create()`, which put every version-negotiation
        // verdict into a throwaway session nobody would ever ask for — so the
        // client that earned the result saw the test as never having run. There
        // is no SNI to recover a session from here, because there is no TLS
        // handshake, so the source address is the only handle. It is also the
        // one the rest of the suite falls back to.
        let session_id = counters
            .last_peer()
            .map(|peer| crate::security::canonical_addr(peer).ip())
            .and_then(|ip| conformance.sessions.for_source(ip))
            .unwrap_or_else(|| conformance.sessions.create());
        conformance.sessions.with(&session_id, |s| {
            s.record(
                test,
                &Observation::Signalled(format!(
                    "sent Version Negotiation for {arrived} datagram(s); the client did not \
                     persist with an unsupported version"
                )),
                None,
                0,
            );
        });
        info!(
            "conformance: {} observed {arrived} datagram(s), no connection followed",
            test.id
        );
    }
}

/// Drive one client through one test.
async fn run_one(
    incoming: quinn::Incoming,
    test: &'static Test,
    conformance: Arc<Conformance>,
    conformance_counters: Arc<Counters>,
    endpoint: quinn::Endpoint,
) -> anyhow::Result<()> {
    let started = Instant::now();
    // Captured before the handshake: `Connection::remote_address` panics once
    // the connection is established, and this is the address that finds the
    // session anyway. Canonicalised so an IPv4-mapped IPv6 peer matches the
    // plain IPv4 address its /session call arrived from — the two spellings
    // have caused a lookup miss in this codebase before.
    let peer_ip = crate::security::canonical_addr(incoming.remote_address()).ip();
    let mut connecting = incoming.accept()?;

    // Read the SNI before awaiting the handshake, not after.
    //
    // It is available as soon as the ClientHello has been processed, which is
    // earlier than the handshake completing — and that gap matters: a client can
    // reject an anomaly and close *during* the handshake, and reading the SNI
    // from the established connection means there is no established connection
    // to read it from. The session would be lost along with the verdict.
    let sni = connecting.handshake_data().await.ok().and_then(|d| {
        d.downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()
            .and_then(|h| h.server_name)
    });

    let mut early_data_accepted = false;
    let connection = match accept_connection(connecting, test, &mut early_data_accepted).await {
        Ok(connection) => connection,
        Err(e) => {
            // The client closed before the handshake finished. For most tests
            // that is a connection that failed; for one whose anomaly rides in
            // the first 1-RTT packet it is the client rejecting the anomaly at
            // the earliest possible moment — the correct answer, arriving before
            // this code used to be listening for it.
            //
            // `q-reserved-frame` is that test: the unknown frame is coalesced
            // with the server's handshake completion, so a conforming client
            // closes within a round trip and `accept()` never yields. Scored
            // here or not at all.
            let session_id = resolve_session(sni.as_deref(), peer_ip, &conformance);
            let observation = frame_encoding_verdict(test, &e)
                .or_else(|| transport_param_verdict(test, &e))
                .unwrap_or_else(|| {
                    // Anything else that dies in the handshake never met the
                    // anomaly, so there is nothing to score.
                    //
                    // `q-reserved-frame` is the only test whose anomaly rides early
                    // enough to be rejected here, and it is claimed above. For the
                    // rest the anomaly is written after the connection is
                    // established, so a handshake that failed is a client that never
                    // saw one — and the generic classification would have called
                    // that a signal, which for four of the five classes is a pass.
                    // A client whose key exchange had nothing in common with ours
                    // was being credited with recovering from a 0-RTT rejection it
                    // was never sent.
                    if test.id == "q-invalid-transport-param" {
                        // This one did reach the anomaly: the parameter travels
                        // in the handshake, so it is among the first things the
                        // client reads. What is missing is its answer.
                        Observation::NotExercised(format!(
                            "the client abandoned the handshake ({e}) without a \
                             CONNECTION_CLOSE this endpoint could read. It certainly saw \
                             the parameter — that travels in the handshake — but §7.4 \
                             asks for a rejection carrying TRANSPORT_PARAMETER_ERROR, and \
                             none was observed. A close that was sent and lost cannot be \
                             told apart from one that was never sent"
                        ))
                    } else {
                        Observation::NotExercised(format!(
                            "the connection failed during the handshake ({e}), so the \
                             client never reached the anomaly"
                        ))
                    }
                });
            let elapsed = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
            conformance.sessions.with(&session_id, |s| {
                s.record(test, &observation, expected_code(test), elapsed);
            });
            info!(
                "conformance: {} session={} observed={:?} (closed during the handshake: {})",
                test.id, session_id, observation, e
            );
            return Ok(());
        }
    };

    let session_id = resolve_session(sni.as_deref(), peer_ip, &conformance);

    // Held for the lifetime of this function, not just for the emit call.
    //
    // `Drop for SendStream` finishes the stream, and RFC 9114 §6.2.1 makes a
    // closed control stream H3_CLOSED_CRITICAL_STREAM. Holding these in the
    // helper meant they dropped the moment it returned — after the response was
    // written but before the client had read it — so a correct client saw our
    // violation, closed the connection, and reported an error on a test it had
    // just passed.
    let (critical_streams, mut encoder) = match emit(&connection, test).await {
        Ok(emitted) => (emitted.keep_open, Some(emitted.encoder)),
        Err(e) => {
            debug!("conformance: {} could not emit anomaly: {}", test.id, e);
            (Vec::new(), None)
        }
    };

    // The one anomaly that is not written to any stream.
    //
    // A key update is a transport event, not a frame: the next packet this
    // endpoint sends carries the opposite key phase, and RFC 9001 §6.2 requires
    // the client to update its own send keys in response. It goes here, after
    // the handshake, because `force_key_update` is ignored before the connection
    // is established — and the response the client is about to read is what
    // proves it followed.
    if test.id == "q-key-update" && test.implemented {
        connection.force_key_update();
    }

    // Streams that must stay open past the verdict. `Drop for SendStream`
    // finishes the stream it owns, so anything answered but not finished has to
    // be parked somewhere that outlives the wait.
    let mut held: Vec<quinn::SendStream> = Vec::new();
    let qpack = Arc::new(QpackLimits::default());
    let observation = if critical_streams.is_empty() {
        classify_close(&connection)
    } else {
        watch_for_liveness(
            &connection,
            &conformance,
            test,
            &mut held,
            encoder.as_mut(),
            &qpack,
            // Not just "0-RTT was possible" — `into_0rtt` succeeds whenever the
            // configuration offers early data, whether or not the client sent
            // any. The wire count is the same evidence the verdict is built on,
            // so the response and the verdict cannot disagree.
            early_data_accepted && conformance_counters.zero_rtt_in() > 0,
        )
        .await
    };

    // The stateless-reset test only begins once the client is established and
    // talking, so it runs here rather than in `emit`: the anomaly is the server
    // vanishing mid-conversation, which needs a conversation first.
    let observation = if test.id == "q-stateless-reset" && test.implemented {
        abandon_and_watch(&connection, &endpoint, &conformance_counters, &mut held).await
    } else {
        observation
    };

    // Some QUIC-layer tests are judged on what the connection did rather than
    // on whether a request arrived, so the transport's own account of it
    // supersedes the liveness result.
    let observation =
        quic_observation(&connection, test, &conformance_counters, &qpack).unwrap_or(observation);

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
    drop(held);
    // The encoder stream is critical too (RFC 9204 §4.2): dropping it finishes
    // it, and a closed QPACK encoder stream is H3_CLOSED_CRITICAL_STREAM. It
    // waits here with the rest.
    drop(encoder);
    Ok(())
}

/// Complete the handshake, accepting early data on the one port that offers it.
///
/// `into_0rtt` is what actually admits 0-RTT server-side: with it, the streams a
/// client opened in early data are delivered as soon as they arrive rather than
/// after the handshake confirms. Without calling it, a configuration that offers
/// early data still quietly discards the packets, and the port would be
/// indistinguishable from the one that refuses them.
///
/// It hands the `Connecting` back when 0-RTT is not possible — no ticket, or a
/// fresh client — and that is the ordinary case, so the fall-through is the
/// normal handshake rather than an error.
async fn accept_connection(
    connecting: quinn::Connecting,
    test: &'static Test,
    early_data_accepted: &mut bool,
) -> Result<quinn::Connection, quinn::ConnectionError> {
    if test.id == "q-zero-rtt-replay" && test.implemented {
        return match connecting.into_0rtt() {
            Ok((connection, _accepted)) => {
                *early_data_accepted = true;
                Ok(connection)
            }
            Err(connecting) => connecting.await,
        };
    }
    connecting.await
}

/// Vanish, and watch whether the client accepts being reset.
///
/// The endpoint is told to forget the connection while the client still believes
/// it is live. The client's next packet — an ACK for the response it has just
/// read, or a PTO probe when none comes — therefore carries a connection ID the
/// endpoint has never heard of, and RFC 9000 §10.3 has the endpoint answer it
/// with a Stateless Reset.
///
/// The verdict is read from the silence that should follow. §10.3.1 requires a
/// client recognising the token to "enter the draining period and not send any
/// further packets on this connection", so a conforming client goes quiet.
/// One that missed the reset keeps retransmitting into a connection that no
/// longer exists — which is precisely the wedged client this test is for, and
/// the reason the reset mechanism exists at all.
///
/// There is no other evidence available: the connection state is gone, so
/// nothing can be read from it. The socket counters are all that is left, which
/// is fitting — a stateless reset is by definition what an endpoint does when it
/// has no state.
async fn abandon_and_watch(
    connection: &quinn::Connection,
    endpoint: &quinn::Endpoint,
    counters: &Counters,
    held: &mut [quinn::SendStream],
) -> Observation {
    /// How long the body is allowed to flow before the connection is abandoned.
    const IN_FLIGHT: Duration = Duration::from_millis(200);
    /// How long to wait for the peer to say something that draws the reset.
    const UNTIL_RESET: Duration = Duration::from_secs(8);
    /// How often to look while waiting.
    const POLL: Duration = Duration::from_millis(100);
    /// How long silence has to hold to count. Longer than any reasonable PTO at
    /// these round-trip times, so a client that is still retransmitting will
    /// have done so at least once inside it.
    const SILENCE: Duration = Duration::from_secs(3);

    // Give the client something it is obliged to acknowledge, and keep giving it
    // until the moment of vanishing.
    //
    // Without this there is nothing to draw a reset out. The client is a
    // receiver: it has no data in flight, nothing to retransmit, and no reason
    // to speak until it is spoken to, so an endpoint that simply goes quiet is
    // met with equal quiet until an idle timeout that outlasts any sensible test
    // window. A body in progress puts packets in front of it that RFC 9000 §13.2
    // requires it to acknowledge — and those acknowledgements, arriving at an
    // endpoint that has just forgotten the connection, are what the Stateless
    // Reset answers.
    if let Some(send) = held.first_mut() {
        // Written under a deadline, and deliberately more than the peer can
        // finish.
        //
        // Size and pacing both decide whether this works. An earlier version
        // wrote a fixed 128 KiB and paused: some clients swallowed the lot in
        // under that pause, and a client that has read a complete response
        // closes — so by the time the endpoint forgot the connection there was
        // no peer left to speak, no reset was drawn, and the verdict turned on
        // how fast the client was rather than on anything about its conformance.
        // Writing until the deadline leaves the transfer unfinished by
        // construction.
        //
        // `write_all` returns when the data is accepted for sending, and the
        // peer's flow control decides how much that is, so the write is bounded
        // by time rather than by a byte count that a slow reader would stall on.
        let chunk = vec![b'.'; 64 * 1024];
        let deadline = Instant::now() + IN_FLIGHT;
        while Instant::now() < deadline {
            if tokio::time::timeout(IN_FLIGHT, send.write_all(&f::data(&chunk)))
                .await
                .is_err()
            {
                // Blocked on the peer's flow control, which means plenty is
                // already in flight — exactly the state being arranged.
                break;
            }
        }
    }

    let before_abandon = counters.datagrams_in();
    let resets_before = endpoint.stateless_resets_sent();
    connection.abandon();

    // Wait for the peer to say something, and watch rather than guess when.
    //
    // Sampling once after a fixed delay made the result depend on the client's
    // ACK and retransmission timers: a delay tuned for a prompt client scored a
    // slower one as though nothing had happened at all. The window bounds how
    // long this waits; it does not decide the answer.
    let deadline = Instant::now() + UNTIL_RESET;
    let resets_sent = loop {
        let sent = endpoint.stateless_resets_sent() - resets_before;
        if sent > 0 || Instant::now() >= deadline {
            break sent;
        }
        tokio::time::sleep(POLL).await;
    };
    let at_reset = counters.datagrams_in();

    // Nothing was reset, so there is nothing to judge.
    //
    // This is the distinction the first version of this test got wrong. It
    // inferred the reset from the silence that followed, and silence is exactly
    // what a client that had already finished its request produces — every
    // client passed, including ones that never saw a reset at all. The endpoint
    // counter is the only direct evidence, since a Stateless Reset belongs to no
    // connection and raises no event.
    if resets_sent == 0 {
        let arrived = at_reset - before_abandon;
        return Observation::NotExercised(format!(
            "no Stateless Reset was triggered in the {}s after the endpoint forgot the \
             connection, so there was nothing for the client to recognise: {arrived} \
             datagram(s) arrived in that time",
            UNTIL_RESET.as_secs()
        ));
    }

    tokio::time::sleep(SILENCE).await;
    let after = counters.datagrams_in() - at_reset;

    if after == 0 {
        Observation::Signalled(format!(
            "was sent a Stateless Reset and went quiet — nothing further arrived in the {} \
             seconds that followed, which is the draining period §10.3.1 requires",
            SILENCE.as_secs()
        ))
    } else {
        Observation::Violated(format!(
            "kept sending after the Stateless Reset: {after} more datagram(s) arrived in \
             the following {} seconds. RFC 9000 §10.3.1 requires a client that recognises \
             the token to enter the draining period and send nothing further, so this \
             connection is wedged against an endpoint that has forgotten it",
            SILENCE.as_secs()
        ))
    }
}

/// Whether the client rejected an unknown frame type with the code §12.4 names.
///
/// Kept apart from the generic close classification, which reads any non-NO_ERROR
/// transport close as an objection and every objection as a pass. RFC 9000 §12.4
/// names exactly one code, so "rejected it somehow" is not the requirement — and
/// this is a transport code, which `expected_code` cannot express since that
/// compares HTTP/3 application codes.
///
/// Returns `None` for tests this does not apply to, and for closes it cannot
/// read, leaving those to the generic path.
fn frame_encoding_verdict(test: &Test, err: &quinn::ConnectionError) -> Option<Observation> {
    use quinn::ConnectionError as Ce;
    use quinn_proto::TransportErrorCode as Tec;

    if test.id != "q-reserved-frame" {
        return None;
    }
    match err {
        Ce::ConnectionClosed(c) if c.error_code == Tec::FRAME_ENCODING_ERROR => {
            Some(Observation::Signalled(
                "closed with FRAME_ENCODING_ERROR, which is the code §12.4 requires for a \
                 frame of unknown type"
                    .to_string(),
            ))
        }
        Ce::ConnectionClosed(c) if c.error_code == Tec::NO_ERROR => Some(Observation::Violated(
            "closed cleanly after receiving a frame of unknown type. RFC 9000 §12.4 requires \
             a connection error of type FRAME_ENCODING_ERROR: QUIC reserves no ignorable \
             frame types, and an unknown frame carries no length, so nothing after it in the \
             packet can be parsed"
                .to_string(),
        )),
        Ce::ConnectionClosed(c) => Some(Observation::Violated(format!(
            "rejected the unknown frame type with {:?}, where RFC 9000 §12.4 requires \
             FRAME_ENCODING_ERROR. The violation was detected; the code reported is wrong",
            c.error_code
        ))),
        // Closed at the application layer, or for some other reason. Left to the
        // generic path, which reads "carried on regardless" as the failure it is
        // for a correctness test.
        _ => None,
    }
}

/// Whether the client rejected the out-of-range parameter with the code §7.4
/// names.
///
/// Kept apart from the generic close classification for the same reason
/// [`frame_encoding_verdict`] is: this is a *transport* error code, which
/// `expected_code` cannot express since that compares HTTP/3 application codes,
/// and §7.4 names exactly one — so "rejected it somehow" is not the requirement.
///
/// The rejection arrives during the handshake, because transport parameters are
/// read as part of it. There is no connection by then and never will be, so this
/// is scored from the handshake failure or not at all.
fn transport_param_verdict(test: &Test, err: &quinn::ConnectionError) -> Option<Observation> {
    use quinn::ConnectionError as Ce;
    use quinn_proto::TransportErrorCode as Tec;

    if test.id != "q-invalid-transport-param" {
        return None;
    }
    match err {
        Ce::ConnectionClosed(c) if c.error_code == Tec::TRANSPORT_PARAMETER_ERROR => {
            Some(Observation::Signalled(format!(
                "closed with TRANSPORT_PARAMETER_ERROR, which is the code §7.4 requires \
                 for a parameter carrying an invalid value (ack_delay_exponent = \
                 {INVALID_ACK_DELAY_EXPONENT}, where §18.2 permits at most 20)"
            )))
        }
        Ce::ConnectionClosed(c) => Some(Observation::Violated(format!(
            "rejected the out-of-range parameter with {:?}, where RFC 9000 §7.4 requires \
             TRANSPORT_PARAMETER_ERROR. The violation was detected; the code reported is \
             wrong",
            c.error_code
        ))),
        // Anything else is left to the caller, which reads a handshake that
        // failed for another reason as the test not having been exercised.
        _ => None,
    }
}

/// Which session this connection's result belongs to.
///
/// Shared by both arms of the handshake so a client that rejects an anomaly
/// mid-handshake files its verdict in the same place as one that completes:
/// the two used to resolve the session differently, which put a client's
/// fastest, most correct rejections into a session of their own.
fn resolve_session(
    sni: Option<&str>,
    peer_ip: std::net::IpAddr,
    conformance: &Conformance,
) -> String {
    sni.and_then(|sni| session_from_sni(sni, &conformance.config.host))
        .filter(|id| conformance.sessions.exists(id))
        // SNI only works with a wildcard certificate for the session
        // subdomain; without one the handshake fails before a test can run.
        // The address that started the session is the channel that always
        // works.
        .or_else(|| conformance.sessions.for_source(peer_ip))
        .unwrap_or_else(|| conformance.sessions.create())
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
/// The expected code, for the verdict tests in the sibling module.
#[cfg(test)]
pub(super) fn expected_code_for(test: &Test) -> Option<u64> {
    expected_code(test)
}

fn expected_code(test: &Test) -> Option<u64> {
    use f::error_code as e;
    match test.id {
        "h-control-frame-unexpected" => Some(e::H3_FRAME_UNEXPECTED),
        "h-missing-settings" => Some(e::H3_MISSING_SETTINGS),
        "h-second-control-stream" => Some(e::H3_STREAM_CREATION_ERROR),
        "h-max-push-id" => Some(e::H3_FRAME_UNEXPECTED),
        "h-settings-on-request-stream" => Some(e::H3_FRAME_UNEXPECTED),
        "h-data-before-headers" => Some(e::H3_FRAME_UNEXPECTED),
        "h-cancel-push-unsolicited" => Some(e::H3_ID_ERROR),
        "h-push-promise-unsolicited" => Some(e::H3_ID_ERROR),
        "h-goaway-increasing" => Some(e::H3_ID_ERROR),
        "h-datagram-setting-invalid" => Some(e::H3_SETTINGS_ERROR),
        "h-qpack-encoder-overflow" => Some(e::QPACK_ENCODER_STREAM_ERROR),
        "h-push-stream-unpromised" => Some(e::H3_ID_ERROR),
        "h-qpack-static-index-invalid" => Some(e::QPACK_DECOMPRESSION_FAILED),
        "h-qpack-encoder-bad-name-index" => Some(e::QPACK_ENCODER_STREAM_ERROR),
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
pub(super) async fn emit(
    connection: &quinn::Connection,
    test: &'static Test,
) -> anyhow::Result<Emitted> {
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

    // QPACK encoder and decoder streams. RFC 9204 §4.2 says an endpoint SHOULD
    // create both, and clients that wait for them before processing a field
    // section would otherwise stall on a response and be scored as having failed
    // a test they never saw.
    //
    // The encoder is handed back rather than parked here: the two dynamic-table
    // tests write to it after the client's SETTINGS have arrived, which is the
    // earliest moment either is permitted to.
    let mut encoder = connection.open_uni().await?;
    encoder
        .write_all(&f::uni_stream_header(f::stream_type::QPACK_ENCODER))
        .await?;

    let mut decoder = connection.open_uni().await?;
    decoder
        .write_all(&f::uni_stream_header(f::stream_type::QPACK_DECODER))
        .await?;
    keep_open.push(decoder);

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

        // A push stream for a push nobody allowed.
        //
        // §6.2.2 does not require the push to have been promised: the stream on
        // its own is the violation when no MAX_PUSH_ID has been sent, and none
        // is. Held open like the other critical streams — the objection under
        // test is that the stream exists, not that it was closed.
        "h-push-stream-unpromised" => {
            control.write_all(&f::settings_with_grease()).await?;
            let mut push = connection.open_uni().await?;
            push.write_all(&f::push_stream_header(UNPROMISED_PUSH_ID_ZERO))
                .await?;
            push.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
            ]))
            .await?;
            push.write_all(&f::data(b"a push nobody asked for\n"))
                .await?;
            keep_open.push(push);
        }

        // A push nobody permitted.
        //
        // The maximum push ID is unset until the client sends MAX_PUSH_ID
        // (§7.2.7), and no client under test sends one, so push ID 0 is already
        // larger than what has been advertised. The promised request is an
        // ordinary GET so the field section decodes cleanly and the only thing
        // left to object to is the push itself.
        "h-push-promise-unsolicited" => {
            control.write_all(&f::settings_with_grease()).await?;
            control
                .write_all(&f::push_promise(
                    UNPROMISED_PUSH_ID_ZERO,
                    &[
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", "conformance.pqcrypta.com"),
                        (":path", "/pushed"),
                    ],
                ))
                .await?;
        }

        // The one setting whose invalid-value handling the specification pins
        // down, rather than leaving to the receiver.
        "h-datagram-setting-invalid" => {
            control
                .write_all(&f::settings(&[
                    (f::setting::MAX_FIELD_SECTION_SIZE, 16_384),
                    (f::setting::H3_DATAGRAM, 2),
                ]))
                .await?;
        }

        // Two GOAWAYs, the second reaching further than the first.
        //
        // The identifier is a promise about what will still be processed, so
        // raising it takes that promise back — which is why §5.2 allows several
        // GOAWAYs but not an increasing one. The first is a legitimate frame;
        // only the second is the violation.
        "h-goaway-increasing" => {
            control.write_all(&f::settings_with_grease()).await?;
            control.write_all(&f::goaway(0)).await?;
            control.write_all(&f::goaway(GOAWAY_INCREASED_TO)).await?;
        }

        // A prioritisation signal travelling the wrong way.
        //
        // The frame itself is well formed and `u=3` is an ordinary urgency: the
        // violation is purely that a server sent it. RFC 9218 §7.2 makes that a
        // MUST NOT, and a client receiving one a connection error of type
        // H3_FRAME_UNEXPECTED — the same shape as `h-max-push-id`, one frame
        // registry apart.
        "h-priority-update" => {
            control.write_all(&f::settings_with_grease()).await?;
            control
                .write_all(&f::priority_update(PRIORITISED_REQUEST_STREAM, "u=3"))
                .await?;
        }

        // Extended CONNECT advertised with a value the setting cannot take.
        //
        // RFC 8441 §3 says the value MUST be 0 or 1 and RFC 9220 carries that
        // into HTTP/3 unchanged, but neither names what a receiver does with
        // anything else. So this is written into an otherwise ordinary SETTINGS
        // frame and either answer is accepted: what is being measured is that a
        // client which parses the setting — any WebTransport-capable one does —
        // neither stalls nor falls over.
        "h-extended-connect" => {
            control
                .write_all(&f::settings(&[
                    (f::setting::MAX_FIELD_SECTION_SIZE, 16_384),
                    (f::setting::ENABLE_CONNECT_PROTOCOL, 2),
                ]))
                .await?;
        }

        // CANCEL_PUSH naming a push the client never allowed.
        //
        // The frame itself is legal from a server; the identifier is not. A
        // client that has sent no MAX_PUSH_ID has permitted no push IDs at all,
        // so §7.2.3's "greater than currently allowed on the connection" covers
        // every value, and this is the smallest one that says so plainly.
        "h-cancel-push-unsolicited" => {
            control.write_all(&f::settings_with_grease()).await?;
            control
                .write_all(&f::cancel_push(UNPROMISED_PUSH_ID))
                .await?;
        }

        // Everything else gets a correct control stream. The anomaly for these
        // lives at the QUIC layer, or is not built yet; either way a client
        // meets a working server rather than an unexplained silence.
        _ => {
            control.write_all(&f::settings_with_grease()).await?;
        }
    }

    // One test's anomaly belongs on the encoder stream rather than the control
    // stream, and unlike the two dynamic-table tests it needs no permission from
    // the client: every capacity exceeds a limit of zero, which is what every
    // client in reach advertises.
    if test.id == "h-qpack-encoder-bad-name-index" {
        encoder
            .write_all(&f::qpack_insert_bad_name_index(
                INVALID_STATIC_INDEX,
                "bad-name-reference",
            ))
            .await?;
    }

    if test.id == "h-qpack-encoder-overflow" {
        encoder
            .write_all(&f::qpack_set_capacity(OVERSIZED_TABLE_CAPACITY))
            .await?;
    }

    keep_open.push(control);
    Ok(Emitted { keep_open, encoder })
}

/// What the client's SETTINGS allow our QPACK encoder to do, on this
/// connection.
///
/// Per connection, deliberately. The listener's [`Counters`] are shared by every
/// client that ever reaches that port, so a table capacity granted by one
/// developer's client would still be sitting there deciding another's verdict
/// minutes later — and the two QPACK tests are judged entirely on this value.
/// It is learned partway through, from the client's control stream, which is why
/// it is written by the drainer and read after the exchange.
#[derive(Debug, Default)]
pub(super) struct QpackLimits {
    capacity: std::sync::atomic::AtomicU64,
    blocked_streams: std::sync::atomic::AtomicU64,
}

impl QpackLimits {
    pub(super) fn observe(&self, limits: f::ClientQpackLimits) {
        use std::sync::atomic::Ordering::Relaxed;
        self.capacity.store(limits.capacity, Relaxed);
        self.blocked_streams.store(limits.blocked_streams, Relaxed);
    }

    fn capacity(&self) -> u64 {
        self.capacity.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn blocked_streams(&self) -> u64 {
        self.blocked_streams
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the dynamic table may be referenced at all.
    ///
    /// Both halves are required. A capacity of zero forbids insertions outright
    /// (RFC 9204 §3.2.2), and with no blocked streams permitted the encoder may
    /// only reference entries the decoder has already acknowledged — which,
    /// across two streams with no ordering between them, we cannot guarantee for
    /// a section written moments after the insertions. Referencing anyway would
    /// be our §2.1.2 violation, scored against the client.
    fn dynamic_table_usable(&self) -> bool {
        self.capacity() > 0 && self.blocked_streams() > 0
    }

    /// Why the dynamic table could not be used, in the words of the settings
    /// that forbade it.
    ///
    /// Names the actual value rather than saying "not permitted": the two
    /// halves are set independently and by different parts of a client's
    /// configuration, so a developer reading an inconclusive result needs to
    /// know which one to go and change.
    fn why_unusable(&self) -> String {
        match (self.capacity(), self.blocked_streams()) {
            (0, 0) => "the client advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY of 0 and \
                       SETTINGS_QPACK_BLOCKED_STREAMS of 0, which forbid the server's \
                       encoder from using the dynamic table at all"
                .to_string(),
            (0, blocked) => format!(
                "the client advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY of 0, which \
                 forbids the server's encoder from using the dynamic table at all, \
                 though it would have permitted {blocked} blocked stream(s)"
            ),
            (capacity, _) => format!(
                "the client granted a {capacity}-byte QPACK dynamic table but \
                 SETTINGS_QPACK_BLOCKED_STREAMS of 0, so the encoder may only reference \
                 entries the decoder has already acknowledged — which, across two \
                 streams with no ordering between them, cannot be guaranteed for a \
                 section written moments after its insertions"
            ),
        }
    }
}

/// The streams a test opened.
///
/// The encoder is named rather than left in `keep_open` because two tests write
/// to it long after the anomaly: the dynamic table may not be touched until the
/// client's SETTINGS say how much of it, if any, we are allowed to use, and
/// those arrive after this function has returned.
pub(super) struct Emitted {
    /// Streams that must stay open for the life of the connection.
    pub(super) keep_open: Vec<quinn::SendStream>,
    /// The QPACK encoder stream.
    pub(super) encoder: quinn::SendStream,
}

/// The push `h-push-promise-unsolicited` promises.
///
/// Zero, because the maximum push ID is unset until a client sends MAX_PUSH_ID
/// and none does: the smallest possible value already exceeds what was
/// advertised, which keeps the violation about the promise rather than about an
/// implausible identifier.
const UNPROMISED_PUSH_ID_ZERO: u64 = 0;

/// The identifier `h-goaway-increasing` raises its second GOAWAY to.
const GOAWAY_INCREASED_TO: u64 = 16;

/// The static table index `h-qpack-static-index-invalid` references.
///
/// The table has 99 entries, so anything from 99 up is invalid; 200 is well
/// clear of the boundary and cannot be mistaken for an off-by-one.
const INVALID_STATIC_INDEX: u64 = 200;

/// The dynamic table capacity `h-qpack-encoder-overflow` asks for.
///
/// Any non-zero value exceeds the limit every client in reach advertises, and a
/// round number makes the instruction obvious in a packet capture.
const OVERSIZED_TABLE_CAPACITY: u64 = 4096;

/// The request stream `h-priority-update` claims to reprioritise.
///
/// Stream 0 is the first client-initiated bidirectional stream, so it is the one
/// the probe arrives on and the identifier is a plausible one rather than a
/// second oddity for the client to trip over.
const PRIORITISED_REQUEST_STREAM: u64 = 0;

/// The push ID `h-cancel-push-unsolicited` cancels.
///
/// Any value would do — no MAX_PUSH_ID was granted, so none is allowed — and a
/// small one keeps the frame unambiguous: this is a reference to a push that was
/// never promised, not an overflow or a parsing accident.
const UNPROMISED_PUSH_ID: u64 = 3;

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
    hold: &mut Vec<quinn::SendStream>,
    encoder: Option<&mut quinn::SendStream>,
    qpack: &Arc<QpackLimits>,
    early_data_seen: bool,
) -> Observation {
    let timeout = Duration::from_millis(conformance.config.liveness_timeout_ms);

    // Drain the client's unidirectional streams for the life of this
    // connection. They are not the probe, but they must be read: dropping a
    // RecvStream with data outstanding sends STOP_SENDING, and doing that to a
    // client's control stream is a protocol violation of ours that would be
    // scored against the client.
    // Learn what the client permits while draining. SETTINGS_QPACK_MAX_TABLE_CAPACITY
    // and SETTINGS_QPACK_BLOCKED_STREAMS together govern whether *our* encoder
    // may use the dynamic table (RFC 9204 §5, §2.1.2); both default to zero, and
    // using it anyway would be our violation.
    let drainer = tokio::spawn({
        let connection = connection.clone();
        let qpack = qpack.clone();
        async move {
            while let Ok(mut uni) = connection.accept_uni().await {
                let qpack = qpack.clone();
                tokio::spawn(async move {
                    if let Ok(bytes) = uni.read_to_end(64 * 1024).await {
                        if let Some(limits) = f::parse_client_qpack_limits(&bytes) {
                            qpack.observe(limits);
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
                // NOTE: `send` is moved into `hold` at the end of this block for
                // tests that answer without finishing. Dropping it here would
                // finish the stream, which is the opposite of what they need.
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

                // Give a control-stream anomaly time to be read before the
                // response lets the client go.
                //
                // The anomaly was written before this request even arrived, so
                // the bytes are already at the client — but nothing obliges it
                // to read a unidirectional stream on any schedule, and a
                // one-shot client that is handed its response promptly will
                // finish and close without ever picking the stream up. The
                // server then sees a clean close and can conclude nothing,
                // which is the inconclusive band this narrows.
                //
                // Holding the response is what keeps the connection alive
                // through that window: the client is still waiting on us, so it
                // is still there to notice, and a conformant reader has the
                // room to emit its rejection. It does not close the window
                // entirely — whether a unidirectional stream was ever read is
                // not observable from this end — which is why the verdict model
                // still has to allow for not knowing.
                if let Some(hold) = probe_hold(test) {
                    tokio::select! {
                        () = tokio::time::sleep(hold) => {}
                        // Already objected: nothing to wait for.
                        _ = connection.closed() => {}
                    }
                }

                if let Err(e) = answer_probe(&mut send, test, qpack, encoder, early_data_seen).await
                {
                    debug!("conformance: could not answer liveness probe: {}", e);
                }
                // Handed to the caller rather than dropped. `Drop for SendStream`
                // finishes the stream, so letting it fall out of scope would end
                // the response the moment it was written — and a client that has
                // read a complete response closes, which is exactly the client
                // `q-stateless-reset` cannot use.
                hold.push(send);
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
                // The window closed with nothing seen. Not the same as a
                // clean close, and the difference decides a correctness test.
                Err(_) => Observation::NoCloseObserved,
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
fn quic_observation(
    connection: &quinn::Connection,
    test: &'static Test,
    counters: &Counters,
    qpack: &QpackLimits,
) -> Option<Observation> {
    let rx = connection.stats().frame_rx;

    match test.id {
        // §12.4 names one code, so any other rejection is still a failure —
        // which the generic close classification would let through, since it
        // reads any non-NO_ERROR transport close as an objection and every
        // objection as a pass. The code has to be checked here or not at all:
        // it is a transport code, and `expected_code` compares HTTP/3
        // application codes.
        "q-reserved-frame" => connection
            .close_reason()
            .and_then(|e| frame_encoding_verdict(test, &e)),

        // A client that got as far as an established connection accepted the
        // parameter: the rejection §7.4 requires happens during the handshake,
        // so reaching here at all is the failure.
        "q-invalid-transport-param" => Some(
            connection
                .close_reason()
                .and_then(|e| transport_param_verdict(test, &e))
                .unwrap_or_else(|| {
                    Observation::Violated(
                        "completed the handshake carrying a transport parameter whose value \
                         its own definition forbids. RFC 9000 §7.4 requires a connection \
                         error of type TRANSPORT_PARAMETER_ERROR, and §18.2 puts \
                         ack_delay_exponent's ceiling at 20"
                            .to_string(),
                    )
                }),
        ),

        // Getting here at all means the client echoed the token in a second
        // Initial: this port answers the first attempt with Retry and nothing
        // else, so there is no other route to a completed handshake.
        "q-retry" => Some(Observation::Signalled(
            "echoed the Retry token and completed the handshake".to_string(),
        )),

        // Respecting the window is required; announcing the stall with a
        // BLOCKED frame is a SHOULD (§4.1), not a MUST. So a silent client is
        // still conformant, and this reports which it did rather than scoring
        // it — getting that wrong would fail every client that simply never
        // filled the window.
        "q-flow-control" => {
            let blocked = rx.data_blocked + rx.stream_data_blocked;
            Some(if blocked > 0 {
                Observation::Signalled(format!(
                    "respected the window and announced the stall ({} DATA_BLOCKED, \
                     {} STREAM_DATA_BLOCKED)",
                    rx.data_blocked, rx.stream_data_blocked
                ))
            } else {
                Observation::Signalled(
                    "respected the window without sending a BLOCKED frame, which §4.1 \
                     permits"
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

        // Early data offered and structurally refused: this port answers with a
        // HelloRetryRequest, and RFC 8446 §4.2.10 rejects any 0-RTT whenever one
        // is sent.
        //
        // §4.6.2 of RFC 9001 requires the client to reset the state of every
        // stream when its early data is refused, including application state
        // bound to them, because a rejected 0-RTT means every characteristic the
        // client assumed about the connection may have been wrong. It does not
        // require retransmission — that is the application's concern, not
        // QUIC's — so the test is whether the client comes back and completes
        // the request on the 1-RTT keys, not how it got there.
        "q-zero-rtt-reject" => Some(if counters.zero_rtt_in() > 0 {
            // Whatever the liveness result was, it was reached after a genuine
            // rejection. Left to the generic path, which scores a completed
            // follow-up request as recovery and a stall or a give-up as failure.
            return None;
        } else {
            Observation::NotExercised(
                "the client sent no early data, so nothing was rejected. 0-RTT needs a \
                 session ticket from an earlier connection to this same port, and a \
                 client that connects once has none"
                    .to_string(),
            )
        }),

        // Every packet this endpoint sends is marked ECT(0), so a client with
        // access to the ECN field has something to report back.
        //
        // §13.4.1's requirement is conditional — "MUST provide feedback about
        // ECN markings it receives, if these are accessible" — and the paragraph
        // above it explicitly permits an endpoint without access to report
        // nothing. Neither the peer's platform nor the path is observable from
        // here, so silence cannot be scored: a network that stripped the
        // codepoint in transit looks exactly like a client declining to report.
        // Counts coming back is the only conclusion available, and it is the
        // useful one.
        "q-ecn" => {
            let path = connection.path_stats(quinn_proto::PathId::ZERO);
            Some(match path {
                Some(p) if p.ecn_feedback.any() => Observation::Signalled(format!(
                    "echoed ECN counts back in its ACKs: {} ECT(0), {} ECT(1), {} ECN-CE",
                    p.ecn_feedback.ect0, p.ecn_feedback.ect1, p.ecn_feedback.ce
                )),
                // We marked, and then stopped: ECN validation failed, which
                // clears the flag.
                //
                // Validation fails when packets sent with ECT(0) are
                // acknowledged without the counts that should accompany them
                // (§13.4.2). From this end that has two indistinguishable
                // causes — the peer did not report, or the path remarked the
                // codepoint in transit — and naming either would be a guess.
                // Whichever it was, the marking stopped, so the rest of the
                // connection carried nothing for the peer to report.
                Some(p) if !p.sending_ecn => Observation::NotExercised(
                    "ECN validation failed: packets sent marked ECT(0) came back \
                     acknowledged without ECN counts, so the marking was disabled. \
                     Whether the peer declined to report or the path rewrote the \
                     codepoint cannot be told apart from this end"
                        .to_string(),
                ),
                Some(_) => Observation::NotExercised(
                    "no ECN counts came back. §13.4.1 requires reporting only where the ECN \
                     field is accessible, and a path that stripped the codepoint in transit \
                     cannot be told apart from a client that does not report"
                        .to_string(),
                ),
                None => Observation::NotExercised(
                    "the path had already been discarded before its ECN counts could be read"
                        .to_string(),
                ),
            })
        }

        // The path carries 1452 bytes for four seconds, then starts swallowing
        // anything over 1300. A client that notices and drops back to a working
        // size keeps the connection; one that does not stalls. quinn's own path
        // statistics record both the detection and the MTU it settled on.
        "q-pmtu-blackhole" => {
            let swallowed = counters.dropped_oversize();
            let path = connection.path_stats(quinn_proto::PathId::ZERO);
            Some(match path {
                // Noticed and recovered: the requirement.
                Some(p) if p.black_holes_detected > 0 => Observation::Signalled(format!(
                    "detected the black hole {} time(s) and settled on a {}-byte path MTU \
                     ({swallowed} datagram(s) swallowed)",
                    p.black_holes_detected, p.current_mtu
                )),
                // The path ate something and the connection carried on anyway,
                // which is what recovery looks like from here even when the
                // detector did not name it.
                Some(p) if swallowed > 0 => Observation::Signalled(format!(
                    "the path swallowed {swallowed} datagram(s) and the transfer completed \
                     without the detector naming a black hole; MTU settled at {}, {} probe(s) \
                     lost",
                    p.current_mtu, p.lost_plpmtud_probes
                )),
                // Nothing large was ever sent, so the black hole never bit. A
                // plain GET does not reach the limit; this needs a client that
                // sends a body.
                Some(p) => Observation::NotExercised(format!(
                    "nothing over the limit was sent, so the path never swallowed anything; \
                     the MTU stayed at {}. This test needs a client that sends enough data \
                     to reach it",
                    p.current_mtu
                )),
                None => Observation::NotExercised(
                    "path statistics were unavailable for this connection".to_string(),
                ),
            })
        }

        // The client governs whether our encoder may use the dynamic table at
        // all (RFC 9204 §3.2.3, §2.1.2), so a client that grants no capacity —
        // or grants capacity but permits no blocked streams — cannot be tested
        // on it, and must not be recorded as having passed a test that never
        // ran. That its QPACK dynamic table is off is itself the useful finding.
        "h-qpack-dynamic-table" | "h-qpack-blocked-stream" if !qpack.dynamic_table_usable() => {
            Some(Observation::NotExercised(qpack.why_unusable()))
        }

        // Already sent on every connection: noq includes a reserved transport
        // parameter (31*N+27, RFC 9000 §18.1) in every handshake. Reaching this
        // point at all means the client completed a handshake carrying one, so
        // it ignored it as the specification requires.
        "q-reserved-transport-param" => Some(Observation::Signalled(
            "completed a handshake carrying a reserved transport parameter".to_string(),
        )),

        // Announcing the stall is a SHOULD, so only the announcement is
        // affirmative evidence; silence is left to the liveness probe.
        //
        // Reporting "respected the limit" from the frame counters alone would
        // override a client that stalled outright waiting for credit it was
        // never going to get — the counters cannot tell that apart from a
        // client that simply had no more streams to open, and a limit set to
        // exactly what a request needs makes stalling a real possibility rather
        // than a theoretical one.
        "q-stream-limit" => (rx.streams_blocked_bidi + rx.streams_blocked_uni > 0).then(|| {
            Observation::Signalled(format!(
                "stayed inside the stream limits and announced the stall ({} \
                 STREAMS_BLOCKED for bidirectional, {} for unidirectional), which §4.6 \
                 recommends but does not require",
                rx.streams_blocked_bidi, rx.streams_blocked_uni
            ))
        }),

        // Whether anything was actually lost decides only whether this ran.
        //
        // Deliberately not a verdict of its own: the requirement is that the
        // body arrives complete and in order, and the only evidence of that is
        // the liveness result — a client that stalled halfway through the
        // transfer has the same socket counters as one that finished. Returning
        // a signal here would override that and pass both.
        "q-loss-recovery" => {
            let lost = counters.dropped_loss();
            if lost > 0 {
                return None;
            }
            Some(Observation::NotExercised(format!(
                "nothing was dropped on this connection, so the client's recovery was \
                 never called on. The impairment begins half a second after a peer's \
                 first datagram and takes one datagram in {LOSS_CADENCE} after that; a \
                 connection that sends fewer than {LOSS_CADENCE} datagrams in its lossy \
                 phase can finish without meeting one"
            )))
        }

        // Whether anything actually arrived out of order decides only whether
        // this ran; putting the stream back together is the liveness result.
        "q-packet-reordering" => {
            if counters.reordered() > 0 {
                return None;
            }
            Some(Observation::NotExercised(
                "no datagram was delivered out of order, so the client's reassembly was \
                 never called on. The impairment begins shortly after a peer's first \
                 datagram and holds one in six after that"
                    .to_string(),
            ))
        }

        // Whether the client was actually shown a second address decides only
        // whether this ran; how it reacted is the liveness result.
        //
        // Left to the generic path on purpose. A client that discards the
        // stray datagrams carries on and completes the probe, and one that
        // follows them starts writing to a socket nothing is reading, which
        // shows up as the connection stalling. Reporting a signal here would
        // override both.
        "q-connection-migration" => {
            let shadowed = counters.shadowed();
            if shadowed > 0 {
                return None;
            }
            Some(Observation::NotExercised(
                "no datagram was copied from the second address, so the client was never \
                 shown one. The copy begins half a second after a peer's first datagram \
                 and needs the server to still be sending by then"
                    .to_string(),
            ))
        }

        // Whether any early data arrived decides only whether this ran.
        //
        // Counted off the wire, like `q-zero-rtt-reject`: an accepted 0-RTT
        // packet is decrypted and disappears into the ordinary stream machinery,
        // so there is nothing above the transport that distinguishes it from a
        // request sent after the handshake. Without the count, a client that
        // never had a ticket would be scored as though it had been told 425 and
        // handled it.
        "q-zero-rtt-replay" => {
            if counters.zero_rtt_in() > 0 {
                return None;
            }
            Some(Observation::NotExercised(
                "the client sent no early data, so it was never answered 425. 0-RTT \
                 needs a session ticket from an earlier connection to this same port, \
                 and a client that connects once has none"
                    .to_string(),
            ))
        }

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
pub(super) async fn answer_probe(
    send: &mut quinn::SendStream,
    test: &'static Test,
    qpack: &QpackLimits,
    encoder: Option<&mut quinn::SendStream>,
    early_data_seen: bool,
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
        //
        // The insertions are written here, immediately before the section that
        // references them, and not in `emit`. They cannot go any earlier: how
        // much of the dynamic table we are allowed is decided by the client's
        // SETTINGS, and those arrive after the connection is up. Inserting into
        // a table the client sized at zero is an encoder-stream error of ours
        // (RFC 9204 §3.2.2), which is why this waits.
        //
        // Writing them first buys tendency, not order: the encoder stream and
        // this one are separate streams, so either can arrive first. That is
        // exactly why `dynamic_table_usable` also requires the client to permit
        // a blocked stream — without one, an insertion that loses the race would
        // make our section unanswerable and the failure would be scored against
        // the client.
        //
        // They were previously written nowhere at all, while the section still
        // claimed a Required Insert Count of two. Every client in reach
        // advertises a capacity of zero and took the literal branch, so the
        // reference was never emitted and the gap stayed invisible — but a
        // client that granted a table would have been sent a section citing two
        // insertions that did not exist, and blamed for the decode failure that
        // followed.
        "h-qpack-dynamic-table" => {
            let section = if qpack.dynamic_table_usable() {
                if let Some(encoder) = encoder {
                    for (name, value) in DYNAMIC_ENTRIES {
                        encoder
                            .write_all(&f::qpack_insert_with_literal_name(name, value))
                            .await?;
                    }
                }
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

        // The same references, deliberately sent before the insertions that
        // satisfy them.
        //
        // The field section arrives with a Required Insert Count the decoder
        // cannot yet meet, so the stream blocks (RFC 9204 §2.2.1). The
        // insertions follow a moment later on the encoder stream, and a correct
        // decoder resumes and completes the request. One that treats a blocked
        // stream as a decoding failure, or simply never comes back to it, does
        // not.
        //
        // The delay is what makes the block certain rather than incidental: the
        // two streams have no ordering between them, so insertions written
        // immediately before the section would usually — but not always —
        // arrive first, and a test that only sometimes tests something is worse
        // than one that says it did not run.
        "h-qpack-blocked-stream" => {
            if qpack.dynamic_table_usable() {
                let section = f::qpack_dynamic_headers(
                    DYNAMIC_INSERTS,
                    &[(":status", "200"), ("content-type", "text/plain")],
                );
                send.write_all(&f::headers_raw(&section)).await?;
                tokio::time::sleep(BLOCKED_FOR).await;
                if let Some(encoder) = encoder {
                    for (name, value) in DYNAMIC_ENTRIES {
                        encoder
                            .write_all(&f::qpack_insert_with_literal_name(name, value))
                            .await?;
                    }
                }
            } else {
                send.write_all(&f::headers(&[
                    (":status", "200"),
                    ("content-type", "text/plain"),
                    ("x-conformance", "client-permitted-no-blocked-streams"),
                ]))
                .await?;
            }
            send.write_all(&f::data(BODY)).await?;
        }

        // SETTINGS belongs to the control stream and nowhere else.
        //
        // A correct response follows it, so a client that ignores the violation
        // completes the request and is recorded as having accepted it — rather
        // than stalling on a stream that went quiet, which would be judged the
        // same as a timeout and say nothing about the frame.
        "h-settings-on-request-stream" => {
            send.write_all(&f::settings(&[(
                f::setting::MAX_FIELD_SECTION_SIZE,
                16_384,
            )]))
            .await?;
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "settings-frame-preceded-this"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // A body before the headers that describe it: an invalid sequence.
        //
        // Distinct from `h-grease-frame`, which also puts a frame ahead of the
        // response. That one is a reserved type carrying a length, which §7.2.8
        // requires a client to skip; DATA is a known type in a position §4.1
        // forbids, and skipping it is the failure.
        "h-data-before-headers" => {
            send.write_all(&f::data(b"a body before any headers\n"))
                .await?;
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "data-frame-preceded-the-headers"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // A field line pointing at a static entry that does not exist.
        //
        // The static table has 99 entries and this asks for 200, which §3.1
        // makes a decoding failure rather than an unknown-but-ignorable value.
        // No SETTINGS grant it — the static table is always there and always the
        // same size — so unlike the dynamic-table tests this reaches every
        // client.
        "h-qpack-static-index-invalid" => {
            send.write_all(&f::headers_raw(&f::qpack_invalid_static_index(
                INVALID_STATIC_INDEX,
            )))
            .await?;
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

        // A response large enough, and slow enough, to still be in flight when
        // the black hole opens.
        //
        // An idle connection loses nothing, so an idle wait produced no
        // detection however long it was: the detector needs packets at the
        // established MTU actually disappearing. Streaming a body across the
        // opening puts them there. The client should see the transfer stall,
        // the path drop back to a working size, and the response complete.
        "q-pmtu-blackhole" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "pmtu-blackhole"),
            ]))
            .await?;

            // 96 KiB paced over roughly fourteen seconds. The first four
            // seconds run on a clean path, which is what lifts the MTU to 1452;
            // the rest meet the hole.
            //
            // The pacing matters as much as the volume. A loss burst is a run of
            // consecutive packet numbers, and the detector wants more than three
            // separate bursts, so the gaps between chunks are what turn one long
            // outage into the several distinct bursts it counts.
            let chunk = vec![b'.'; 4096];
            for _ in 0..24 {
                send.write_all(&f::data(&chunk)).await?;
                tokio::time::sleep(Duration::from_millis(600)).await;
            }
            send.write_all(&f::data(BODY)).await?;
        }

        // Headers and a first chunk, then nothing — the rest of the body never
        // comes, because the server is about to forget this connection exists.
        // A client left waiting keeps acknowledging and eventually probes, which
        // is what puts a packet in front of the endpoint that no longer knows
        // the connection ID.
        "q-stateless-reset" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "stateless-reset"),
            ]))
            .await?;
            send.write_all(&f::data(b"the rest of this body will never arrive\n"))
                .await?;
        }

        // Enough datagrams for the reordering to bite, sent briskly.
        //
        // Reassembly is about a stream that arrives in the wrong order, so what
        // matters is that the body spans many packets — not that it takes a long
        // time. A short pause every few chunks keeps the impairment's window
        // open across the whole transfer without dragging the run out.
        "q-packet-reordering" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "reordered"),
            ]))
            .await?;
            let chunk = vec![b'#'; 8192];
            for _ in 0..48 {
                send.write_all(&f::data(&chunk)).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            send.write_all(&f::data(BODY)).await?;
        }

        // A body paced so that it is still arriving when the loss begins.
        //
        // Sent flat out, this test measured nothing: a client on the same host
        // took the whole body inside the clean window and the impairment never
        // touched a single datagram, so every run came back inconclusive. The
        // transfer has to outlast the window, and no body is large enough to do
        // that on a loopback path — 256 KiB crosses one in about ten
        // milliseconds — so the answer is time, not volume.
        //
        // Paced, the body spans several seconds on any path, and the fraction
        // of it that meets the impairment is the same whether the client is on
        // this host or across an ocean.
        "q-loss-recovery" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "loss-recovery"),
            ]))
            .await?;
            let chunk = vec![b'.'; LOSSY_CHUNK_BYTES];
            for _ in 0..LOSSY_BODY_CHUNKS {
                send.write_all(&f::data(&chunk)).await?;
                tokio::time::sleep(LOSSY_CHUNK_GAP).await;
            }
            send.write_all(&f::data(BODY)).await?;
        }

        // 425 (Too Early), the answer RFC 8470 defines for a request that
        // arrived in early data.
        //
        // Sent whatever the request was: this port accepts 0-RTT, so anything
        // reaching it on the first flight is by definition early data. §5.2
        // leaves the client a choice — retry on the 1-RTT keys, or hand the
        // status back to whoever made the request — and both are recorded as
        // passes, so the response has to be complete and readable rather than
        // merely a status.
        "q-zero-rtt-replay" if early_data_seen => {
            send.write_all(&f::headers(&[
                (":status", "425"),
                ("content-type", "text/plain"),
                ("x-conformance", "too-early"),
            ]))
            .await?;
            send.write_all(&f::data(
                b"this request arrived in early data; retry it on the 1-RTT keys\n",
            ))
            .await?;
        }

        // No early data was accepted on this connection, so there is nothing
        // that arrived too early and a 425 would be a lie. The client is
        // answered normally and the verdict records that the test did not run.
        //
        // Sending it regardless was the first version, and it told a client
        // which had never resumed anything to retry a request that was never
        // early — inventing the very situation the test is supposed to observe.
        "q-zero-rtt-replay" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "no-early-data-on-this-connection"),
            ]))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

        // Headers, part of a body, then the stream is cancelled underneath it.
        //
        // The pause is what makes this a cancellation of something rather than
        // of nothing: RESET_STREAM abandons whatever has not left yet, so
        // resetting immediately after the write would usually deliver no
        // response at all, and §4.1's "cancelled after receiving a partial
        // response" would never be the situation under test. Long enough for the
        // headers to be on the wire, short enough to stay well inside the
        // client's patience.
        //
        // Returns early: falling through to `finish()` below would complete the
        // very stream this test exists to cut off.
        "h-response-stream-reset" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "about-to-be-cancelled"),
            ]))
            .await?;
            send.write_all(&f::data(b"the first part of a body that stops here\n"))
                .await?;
            tokio::time::sleep(BEFORE_RESET).await;
            let code = quinn::VarInt::from_u64(f::error_code::H3_REQUEST_CANCELLED)
                .expect("0x10c is inside the varint range");
            // Fails only if the stream is already gone, which is a client that
            // has closed — nothing left to cancel, and nothing to report.
            if let Err(e) = send.reset(code) {
                debug!("conformance: {} could not reset the response: {e}", test.id);
            }
            return Ok(());
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

    // Deliberately unfinished for the stateless-reset test.
    //
    // A finished response is one the client reads to the end and closes on, and
    // a client that has closed is not a client that can be reset — the silence
    // that follows is just a finished transfer, and reading it as obedience
    // would pass every client alive. Leaving the response open keeps the client
    // waiting for a body, so it is still acknowledging and still probing when
    // the endpoint forgets it, and its next packet is what draws the reset.
    if test.id != "q-stateless-reset" {
        send.finish()?;
    }
    Ok(())
}

/// The entries the two dynamic-table tests insert before referencing them.
///
/// Named field lines rather than filler: they arrive in the client's response
/// headers, so anyone reading the exchange in a packet capture can see which
/// entries the section was pointing at.
const DYNAMIC_ENTRIES: &[(&str, &str)] = &[
    ("x-conformance-dynamic", "first-dynamic-table-entry"),
    ("x-conformance-dynamic-2", "second-dynamic-table-entry"),
];

/// How many entries `h-qpack-dynamic-table` inserts before referencing them.
const DYNAMIC_INSERTS: u64 = 2;

// The Required Insert Count written into the field section has to be the number
// of entries actually inserted; a mismatch is a decode failure the client would
// be blamed for.
const _: () = assert!(DYNAMIC_ENTRIES.len() == 2);

/// How long to hold the response before releasing the client, if at all.
///
/// Two quite different reasons to wait, and both need the connection to still be
/// alive a moment longer than a bare request/response would keep it.
fn probe_hold(test: &'static Test) -> Option<Duration> {
    if catalog::anomaly_stream(test) == catalog::Anomaly::ControlStream {
        // Give a unidirectional stream a chance to be read before the client is
        // free to close.
        return Some(CONTROL_STREAM_GRACE);
    }
    if test.id == "q-connection-migration" {
        // The second address is only shown to the client on datagrams this
        // endpoint sends *after* the copy window opens, and a bare exchange is
        // over in milliseconds — locally the window never opened at all and the
        // test reported, correctly, that nothing had been exercised. Holding
        // here leaves the connection running through it, and the keep-alive
        // ensures there is traffic to copy even while nothing else is being
        // said.
        return Some(SHADOW_HOLD);
    }
    None
}

/// How long a control-stream anomaly is left in front of a client before the
/// response is released.
///
/// The bytes reached the client before its request did; this is about giving it
/// a moment to look at them while it still has a reason to keep the connection
/// open. A second is far longer than reading a queued stream takes and is only
/// spent on the tests that need it.
const CONTROL_STREAM_GRACE: Duration = Duration::from_secs(1);

/// How long `h-qpack-blocked-stream` leaves the field section blocked.
const BLOCKED_FOR: Duration = Duration::from_millis(300);

/// How long `h-response-stream-reset` lets the partial response run before
/// cancelling it.
const BEFORE_RESET: Duration = Duration::from_millis(300);

/// The shape of `q-loss-recovery`'s body: 96 chunks of 8 KiB, 30ms apart.
///
/// 768 KiB over roughly three seconds. The size is not the point — the duration
/// is. The impairment opens half a second after a peer's first datagram, so what
/// decides whether anything is lost is how long the transfer is still running
/// after that, and an unpaced body finishes far too soon on a fast path to meet
/// it at all.
///
/// Two and a half seconds of lossy transfer is around 450 datagrams at this
/// path's MTU, of which one in twelve — roughly forty — vanishes. Comfortably
/// inside the ten-second grace the connection is given to close.
const LOSSY_BODY_CHUNKS: usize = 96;
const LOSSY_CHUNK_BYTES: usize = 8192;
const LOSSY_CHUNK_GAP: Duration = Duration::from_millis(30);

/// Turn a closed connection into an observation, preserving the error code the
/// client chose — which for the correctness tests is the entire point.
fn classify_close(connection: &quinn::Connection) -> Observation {
    match connection.close_reason() {
        Some(e) => classify_error(&e),
        // Still open, or closed in a way the transport did not record: either
        // way nothing was observed about how the client took the anomaly.
        None => Observation::NoCloseObserved,
    }
}

/// The same classification, from an error rather than from a live connection.
///
/// Split out so a client that closes during the handshake is read exactly as one
/// that closes after it. The two used to disagree, because only the second had
/// any code at all.
fn classify_error(err: &quinn::ConnectionError) -> Observation {
    use quinn::ConnectionError as Ce;
    match err {
        // The client rejected the anomaly and named a code. For the correctness
        // tests this is the whole point of the exercise.
        // An application close naming H3_NO_ERROR is a *graceful shutdown*, not a
        // rejection. RFC 9114 §8.1 defines it as "no error. This is used when
        // the connection or stream needs to be closed, but there is no error to
        // signal" — it is what a well-behaved client sends when it has finished.
        //
        // Reading it as a rejection failed every client that closes its HTTP/3
        // connection properly, which is arguably the more correct behaviour than
        // closing at the transport layer. It went unnoticed because the two
        // clients tested first (curl and Chromium) both close at the QUIC layer
        // instead, and that path already checks for NO_ERROR.
        // Only a defined HTTP/3 error code other than H3_NO_ERROR is an
        // objection. RFC 9114 §8.1 requires unknown codes to be "treated as
        // equivalent to H3_NO_ERROR", so code 0 — which aioquic and quic-go both
        // use for a clean close — is a graceful shutdown, not a rejection.
        Ce::ApplicationClosed(app) if !f::error_code::is_rejection(app.error_code.into_inner()) => {
            Observation::ClosedSilently
        }
        Ce::ApplicationClosed(app) => Observation::ClosedWith {
            code: app.error_code.into_inner(),
        },
        // A QUIC-layer close. The client objected but at the transport layer,
        // so there is no HTTP/3 error code to compare against — say what it was
        // rather than flattening it to "silently", which reads as though the
        // client said nothing at all.
        Ce::TransportError(e) => {
            Observation::ObjectedAtTransport(format!("closed at the QUIC layer: {}", e.code))
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
        Ce::ConnectionClosed(close) => {
            if close.error_code == quinn_proto::TransportErrorCode::NO_ERROR {
                Observation::ClosedSilently
            } else {
                Observation::ObjectedAtTransport(format!(
                    "rejected at the QUIC layer with {:?}",
                    close.error_code
                ))
            }
        }
        Ce::Reset => Observation::Signalled("connection reset".to_string()),
        Ce::TimedOut => Observation::TimedOut,
        other => {
            debug!("conformance: unclassified close reason: {other}");
            Observation::ClosedSilently
        }
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
                // Where the anomaly is written, which decides what silence from
                // a client is allowed to prove. Published because it is the
                // difference between a test whose failure is conclusive and one
                // whose quiet outcome can only ever be inconclusive.
                // Published so the matrix can be filtered by how hard the
                // clause insists, and by document, without re-deriving either
                // from the prose.
                "requirement": t.requirement.as_str(),
                "requirement_label": t.requirement.label(),
                "documents": catalog::documents(t),
                "anomaly": match catalog::anomaly_stream(t) {
                    catalog::Anomaly::ControlStream => "control_stream",
                    catalog::Anomaly::ResponseStream => "response_stream",
                    catalog::Anomaly::Transport => "transport",
                },
            })
        })
        .collect();

    serde_json::json!({
        "host": conformance.config.host,
        "tests": entries,
        "how": "Connect to each port in turn. To collect results under one session, \
                use SNI <session>.<host>; obtain a session from /session.",
        "verdicts": "A failure requires positive evidence the client read the anomaly. \
                     Where `anomaly` is response_stream or transport the client had to \
                     process it to be served, so completing the exchange without \
                     objecting is a failure. Where it is control_stream, a one-shot \
                     request can close before ever reading the stream, so silence is \
                     inconclusive rather than a failure.",
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

    /// Every `expected_code`, pinned to the RFC sentence it comes from.
    ///
    /// Checked against the published text on 2026-08-27, not from memory. Two
    /// errors had already reached the catalogue by guessing — `h-duplicate-setting`
    /// scored a MAY as a MUST, and this table's own `h-max-push-id` named
    /// H3_ID_ERROR — and both would have failed conformant clients. If a code
    /// changes here, re-read the clause first.
    #[test]
    fn every_expected_code_matches_its_rfc_clause() {
        use f::error_code as e;
        // (test id, required code, clause, the sentence that requires it)
        let verified: &[(&str, u64, &str, &str)] = &[
            (
                "h-missing-settings",
                e::H3_MISSING_SETTINGS,
                "RFC 9114 §6.2.1",
                "If the first frame of the control stream is any other frame type,                  this MUST be treated as a connection error of type H3_MISSING_SETTINGS.",
            ),
            (
                "h-second-control-stream",
                e::H3_STREAM_CREATION_ERROR,
                "RFC 9114 §6.2.1",
                "Only one control stream per peer is permitted; receipt of a second                  stream claiming to be a control stream MUST be treated as a connection                  error of type H3_STREAM_CREATION_ERROR.",
            ),
            (
                "h-control-frame-unexpected",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.1",
                "If a DATA frame is received on a control stream, the recipient MUST                  respond with a connection error of type H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-max-push-id",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.7",
                "A server MUST NOT send a MAX_PUSH_ID frame. A client MUST treat the                  receipt of a MAX_PUSH_ID frame as a connection error of type                  H3_FRAME_UNEXPECTED.",
            ),
            // Read as published on 2026-08-31, along with the other four added
            // that day.
            (
                "h-settings-on-request-stream",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.4",
                "If an endpoint receives a SETTINGS frame on a different stream, the                  endpoint MUST respond with a connection error of type                  H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-data-before-headers",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §4.1",
                "Receipt of an invalid sequence of frames MUST be treated as a                  connection error of type H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-cancel-push-unsolicited",
                e::H3_ID_ERROR,
                "RFC 9114 §7.2.3",
                "If a CANCEL_PUSH frame is received that references a push ID greater                  than currently allowed on the connection, this MUST be treated as a                  connection error of type H3_ID_ERROR.",
            ),
            // Read as published on 2026-09-01.
            (
                "h-push-promise-unsolicited",
                e::H3_ID_ERROR,
                "RFC 9114 §7.2.5, §4.6",
                "A client MUST treat receipt of a PUSH_PROMISE frame that contains a                  larger push ID than the client has advertised as a connection error of                  H3_ID_ERROR.",
            ),
            (
                "h-goaway-increasing",
                e::H3_ID_ERROR,
                "RFC 9114 §5.2",
                "Receiving a GOAWAY containing a larger identifier than previously                  received MUST be treated as a connection error of type H3_ID_ERROR.",
            ),
            (
                "h-datagram-setting-invalid",
                e::H3_SETTINGS_ERROR,
                "RFC 9297 §2.1.1",
                "If the SETTINGS_H3_DATAGRAM setting is received with a value that is                  neither 0 nor 1, the receiver MUST terminate the connection with error                  H3_SETTINGS_ERROR.",
            ),
            (
                "h-qpack-encoder-overflow",
                e::QPACK_ENCODER_STREAM_ERROR,
                "RFC 9204 §4.3.1, §6",
                "The decoder MUST treat a new dynamic table capacity value that exceeds                  this limit as a connection error of type QPACK_ENCODER_STREAM_ERROR.",
            ),
            (
                "h-push-stream-unpromised",
                e::H3_ID_ERROR,
                "RFC 9114 §6.2.2",
                "A client MUST treat receipt of a push stream as a connection error of                  type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or when the                  stream references a push ID that is greater than the maximum push ID.",
            ),
            (
                "h-qpack-static-index-invalid",
                e::QPACK_DECOMPRESSION_FAILED,
                "RFC 9204 §3.1, §4.5.2",
                "When the decoder encounters an invalid static table index in a field                  line representation, it MUST treat this as a connection error of type                  QPACK_DECOMPRESSION_FAILED.",
            ),
            (
                "h-qpack-encoder-bad-name-index",
                e::QPACK_ENCODER_STREAM_ERROR,
                "RFC 9204 §3.1, §4.3.2",
                "If this index is received on the encoder stream, this MUST be treated                  as a connection error of type QPACK_ENCODER_STREAM_ERROR.",
            ),
        ];

        for (id, code, clause, sentence) in verified {
            let t = catalog::find(id).expect(id);
            assert_eq!(
                expected_code(t),
                Some(*code),
                "{id}: {clause} says \"{sentence}\""
            );
            assert_eq!(
                t.spec, *clause,
                "{id} must cite the clause it was verified against"
            );
            assert_eq!(
                t.class,
                catalog::Class::Correctness,
                "{id} requires a specific rejection, so it is a correctness test"
            );
        }

        // Nothing else may demand a code. A test that is not Correctness has no
        // single required rejection, and asking for one would fail a client
        // that made a legal choice.
        for t in catalog::CATALOG {
            if !verified.iter().any(|(id, ..)| *id == t.id) {
                assert!(
                    expected_code(t).is_none(),
                    "{} names an expected code but is not in the verified table",
                    t.id
                );
            }
        }
    }

    #[test]
    fn error_code_constants_match_rfc_9114_section_8_1() {
        use f::error_code as e;
        // The registry, transcribed from the published table.
        assert_eq!(e::H3_NO_ERROR, 0x0100);
        assert_eq!(e::H3_GENERAL_PROTOCOL_ERROR, 0x0101);
        assert_eq!(e::H3_INTERNAL_ERROR, 0x0102);
        assert_eq!(e::H3_STREAM_CREATION_ERROR, 0x0103);
        assert_eq!(e::H3_CLOSED_CRITICAL_STREAM, 0x0104);
        assert_eq!(e::H3_FRAME_UNEXPECTED, 0x0105);
        assert_eq!(e::H3_FRAME_ERROR, 0x0106);
        assert_eq!(e::H3_ID_ERROR, 0x0108);
        assert_eq!(e::H3_SETTINGS_ERROR, 0x0109);
        assert_eq!(e::H3_MISSING_SETTINGS, 0x010a);
        // QPACK's codes share the same application error space (RFC 9204 §6).
        assert_eq!(e::QPACK_DECOMPRESSION_FAILED, 0x0200);
        assert_eq!(e::QPACK_ENCODER_STREAM_ERROR, 0x0201);
        assert_eq!(e::QPACK_DECODER_STREAM_ERROR, 0x0202);
        // Sent by `h-response-stream-reset`, so it has to be the code the
        // registry actually assigns: a stream reset carrying the wrong value
        // would be asking the client about a different situation entirely.
        assert_eq!(e::H3_REQUEST_CANCELLED, 0x010c);
    }

    /// A CANCEL_PUSH violation is an identifier error, not an unexpected frame.
    ///
    /// The distinction is the whole content of the test. CANCEL_PUSH is legal
    /// from a server, so a client that answers H3_FRAME_UNEXPECTED has objected
    /// to the wrong thing — and `h-max-push-id`, one entry away in this same
    /// catalogue, is exactly the case where H3_FRAME_UNEXPECTED *is* right.
    /// Getting these two the wrong way round is the easiest mistake here.
    #[test]
    fn the_two_push_tests_require_different_codes() {
        let cancel = catalog::find("h-cancel-push-unsolicited").expect("catalogue entry");
        let max = catalog::find("h-max-push-id").expect("catalogue entry");
        assert_eq!(expected_code(cancel), Some(f::error_code::H3_ID_ERROR));
        assert_eq!(expected_code(max), Some(f::error_code::H3_FRAME_UNEXPECTED));
        assert_ne!(
            expected_code(cancel),
            expected_code(max),
            "a frame in a forbidden direction and a frame naming a forbidden id are \
             different objections"
        );
    }

    #[test]
    fn discretionary_tests_never_demand_a_code() {
        // A MAY-level clause has no single right answer, so requiring one would
        // fail a conformant client. This is how h-duplicate-setting went wrong.
        for t in catalog::CATALOG {
            if t.class == catalog::Class::Discretionary {
                assert!(
                    expected_code(t).is_none(),
                    "{} is discretionary and must not require a code",
                    t.id
                );
            }
        }
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
                    | "h-settings-on-request-stream"
                    | "h-data-before-headers"
                    | "h-cancel-push-unsolicited"
                    | "h-push-promise-unsolicited"
                    | "h-goaway-increasing"
                    | "h-datagram-setting-invalid"
                    | "h-qpack-encoder-overflow"
                    | "h-push-stream-unpromised"
                    | "h-qpack-static-index-invalid"
                    | "h-qpack-encoder-bad-name-index"
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
