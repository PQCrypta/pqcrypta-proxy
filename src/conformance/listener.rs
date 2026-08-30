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
use super::impairment::{Counters, ImpairedSocket};
use super::session::Observation;
use super::Conformance;
use crate::tls::TlsProvider;

/// The unknown QUIC frame type `q-reserved-frame` emits.
///
/// Unassigned in the IANA QUIC Frame Types registry and nowhere near an assigned
/// range, so nothing can plausibly parse it.
const RESERVED_FRAME_TYPE: u64 = 0x2a2a;

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
        // Open for the first four seconds, so discovery can raise the MTU to
        // 1452 on a path that genuinely carries it. Then the hole opens and
        // packets at that established size start disappearing — which is what a
        // black hole is, and what the detector looks for.
        let opens_after = blackhole_above.map(|_| Duration::from_secs(4));
        let impaired = Box::new(ImpairedSocket::new(
            inner,
            blackhole_above,
            opens_after,
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

    let connection = match connecting.await {
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
            let observation = frame_encoding_verdict(test, &e).unwrap_or_else(|| {
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
                Observation::NotExercised(format!(
                    "the connection failed during the handshake ({e}), so the client never \
                     reached the anomaly"
                ))
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
    let critical_streams = match emit(&connection, test).await {
        Ok(streams) => streams,
        Err(e) => {
            debug!("conformance: {} could not emit anomaly: {}", test.id, e);
            Vec::new()
        }
    };

    // Streams that must stay open past the verdict. `Drop for SendStream`
    // finishes the stream it owns, so anything answered but not finished has to
    // be parked somewhere that outlives the wait.
    let mut held: Vec<quinn::SendStream> = Vec::new();
    let observation = if critical_streams.is_empty() {
        classify_close(&connection)
    } else {
        watch_for_liveness(
            &connection,
            &conformance,
            test,
            &conformance_counters,
            &mut held,
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
        quic_observation(&connection, test, &conformance_counters).unwrap_or(observation);

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
    Ok(())
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
    counters: &Arc<Counters>,
    hold: &mut Vec<quinn::SendStream>,
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
        let shared = counters.clone();
        async move {
            while let Ok(mut uni) = connection.accept_uni().await {
                let capacity = capacity.clone();
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Ok(bytes) = uni.read_to_end(64 * 1024).await {
                        if let Some(c) = f::parse_qpack_capacity(&bytes) {
                            capacity.store(c, std::sync::atomic::Ordering::Relaxed);
                            shared
                                .qpack_capacity
                                .store(c, std::sync::atomic::Ordering::Relaxed);
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

                let capacity = qpack_capacity.load(std::sync::atomic::Ordering::Relaxed);
                if let Err(e) = answer_probe(&mut send, test, capacity).await {
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
fn quic_observation(
    connection: &quinn::Connection,
    test: &'static Test,
    counters: &Counters,
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
        // all (RFC 9204 §3.2.3), so a client advertising zero capacity cannot
        // be tested on it — and must not be recorded as having passed a test
        // that never ran. That its QPACK dynamic table is off is itself the
        // useful finding.
        "h-qpack-dynamic-table" if counters.qpack_capacity() == 0 => {
            Some(Observation::NotExercised(
                "the client advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY of 0, which \
                 forbids the server's encoder from using the dynamic table at all"
                    .to_string(),
            ))
        }

        // Already sent on every connection: noq includes a reserved transport
        // parameter (31*N+27, RFC 9000 §18.1) in every handshake. Reaching this
        // point at all means the client completed a handshake carrying one, so
        // it ignored it as the specification requires.
        "q-reserved-transport-param" => Some(Observation::Signalled(
            "completed a handshake carrying a reserved transport parameter".to_string(),
        )),

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

/// How many entries `h-qpack-dynamic-table` inserts before referencing them.
const DYNAMIC_INSERTS: u64 = 2;

/// Turn a closed connection into an observation, preserving the error code the
/// client chose — which for the correctness tests is the entire point.
fn classify_close(connection: &quinn::Connection) -> Observation {
    match connection.close_reason() {
        Some(e) => classify_error(&e),
        None => Observation::SurvivedAndContinued,
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
        Ce::ConnectionClosed(close) => {
            if close.error_code == quinn_proto::TransportErrorCode::NO_ERROR {
                Observation::ClosedSilently
            } else {
                Observation::Signalled(format!(
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
