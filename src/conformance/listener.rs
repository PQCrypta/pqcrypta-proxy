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
use super::impairment::{Counters, ImpairedSocket, Impairments, PeerView};
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

/// How long `q-key-update-repeated` waits before updating a second time.
///
/// Long enough for the first phase to be acknowledged, which is what makes the
/// second update legal rather than ignored.
const SECOND_KEY_UPDATE_AFTER: Duration = Duration::from_millis(600);

/// How long `q-max-streams-credit` withholds the credit for a request.
///
/// Comfortably inside the liveness window, so a client that waits still has time
/// to open its request and be answered.
const STREAM_CREDIT_AFTER: Duration = Duration::from_millis(700);

/// How many ECT markings in every this-many become CE on `q-ecn-congestion`.
///
/// Every one of them. A cadence of four marked nothing at all: ECN validation
/// fails on many paths (§13.4.2) and this stack then stops marking ECT, so only
/// two or three datagrams ever carry a codepoint to rewrite and a count of four
/// is never reached. A congested router marks everything that passes, which is
/// both realistic and the only way to be sure the client is shown one before the
/// marking stops.
const CE_CADENCE: u64 = 1;

/// One datagram in this many is held back and released late on
/// `q-packet-reordering`'s port.
const REORDER_CADENCE: u64 = 6;

/// How long a connection ID lives on `q-cid-rotation`'s port before the server
/// asks for it back.
///
/// Short enough that a single request outlives it, long enough to be past the
/// handshake on any path this service can be reached over.
const CID_LIFETIME: Duration = Duration::from_millis(300);

/// How long that test holds the response open, so the expiry lands inside the
/// connection rather than after the client has gone.
const CID_ROTATION_HOLD: Duration = Duration::from_millis(900);

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
        } else if test.id == "t-cert-compression-pq" {
            // The one TLS-tier port whose subject is the certificate rather
            // than the key exchange: an ML-DSA-87 chain, sent compressed when
            // the client offers a codec we share.
            tls_provider
                .build_pq_chain_config()
                .with_context(|| format!("building the TLS config for {}", test.id))?
        } else if matches!(test.tier, Tier::Tls) {
            // The TLS tier's whole anomaly is which group the server will
            // negotiate. Nothing malformed is emitted; the port simply refuses
            // to speak anything else, and what the client does about that is
            // the measurement.
            //
            // `t-hybrid-large-hello` shares the hybrid-only configuration with
            // `t-hybrid-only` deliberately. The two differ in what is judged,
            // not in what is served: one asks whether the handshake completed,
            // the other asks how the client packetised a ClientHello too large
            // for a single Initial. Serving them on one port would force a
            // client to be graded twice on one connection, and the suite's own
            // rule is one anomaly per port.
            let group = match test.id {
                "t-classical-only" => rustls::NamedGroup::X25519,
                _ => rustls::NamedGroup::X25519MLKEM768,
            };
            // Three ports go further than choosing a group: they emit a
            // ServerHello key_share a correct implementation has no code path
            // to produce. That lives in `vendor/rustls-fixed` because it cannot
            // be reached by configuration, which is the whole reason these
            // three were catalogued as unbuilt until the fork gained a hook.
            let impairment = match test.id {
                // secp384r1 is in the provider and is emphatically not what the
                // client offered to a port that will negotiate only the hybrid.
                "t-group-not-offered" => Some(rustls::server::KeyShareImpairment::GroupNotOffered(
                    rustls::NamedGroup::secp384r1,
                )),
                "t-corrupt-hybrid-share" => {
                    Some(rustls::server::KeyShareImpairment::CorruptHybridPqHalf)
                }
                // 1,088 bytes where the group fixes the server share at 1,120:
                // the ML-KEM ciphertext whole and the X25519 tail removed.
                "t-hybrid-share-length" => {
                    Some(rustls::server::KeyShareImpairment::ShareLengthMismatch)
                }
                // 0x2A2A, one of the RFC 8701 reserved values, chosen from the
                // middle of the range rather than the ends so a client that
                // special-cases a boundary is not accidentally let through.
                // Rebuilt where the value is legal: the server's
                // supported_groups in EncryptedExtensions, not the ServerHello
                // key_share. The first version put it in the key_share, which
                // §4.1.3 makes illegal whatever the value is, and so accused
                // every conformant client of a failure. See the catalogue entry.
                "t-grease-group" => Some(rustls::server::KeyShareImpairment::GreaseGroup(
                    GREASE_NAMED_GROUP,
                )),
                _ => None,
            };
            tls_provider
                .build_single_group_config(group, impairment)
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
            // No request may be opened at first. The credit arrives once the
            // connection is up, and the whole test is whether the client waits
            // for it rather than opening anyway.
            "q-max-streams-credit" => {
                transport.max_concurrent_bidi_streams(0u32.into());
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

        // Make the rotation happen instead of waiting to see whether it does.
        //
        // §5.1.2 obliges a client to retire a connection ID when the server
        // issues NEW_CONNECTION_ID with a higher `retire_prior_to`, and quinn
        // issues one when a CID reaches the end of its lifetime. The default
        // lifetime is unbounded, so nothing ever expired and the port was
        // measuring whether a one-request connection happened to outlive a
        // rotation it was never going to be asked for -- eleven of twelve
        // clients reported "the connection was too short-lived", which was our
        // description of a rotation we never asked for.
        //
        // A short lifetime plus the hold in `probe_hold` puts the request
        // squarely after the expiry, so the client is asked and the answer is
        // its own.
        if test.id == "q-cid-rotation" {
            endpoint_config.cid_generator(Arc::new(|| {
                let mut gen = quinn_proto::RandomConnectionIdGenerator::new(8);
                gen.set_lifetime(CID_LIFETIME);
                Box::new(gen)
            }));
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

        // Load this port's remembered ECN path evidence, and give it somewhere
        // to write its own. Only the two ECN ports mark ECT, so only they can
        // ever prove or need it.
        if matches!(test.id, "q-ecn" | "q-ecn-congestion") {
            counters.ecn_evidence.remember_at(
                std::path::Path::new(super::impairment::ECN_EVIDENCE_DIR).join(test.id),
            );
        }

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

        // Every ECT marking becomes CE, for as long as there are any.
        let mark_ce_one_in = (test.id == "q-ecn-congestion").then_some(CE_CADENCE);

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
                mark_ce_one_in,
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
    let peer_addr = incoming.remote_address();
    let peer_ip = crate::security::canonical_addr(peer_addr).ip();

    // This connection's counters, and the only ones any verdict can reach.
    //
    // `Counters` belongs to the listener — one per port, created at start-up
    // and never reset — so read directly, every field is the running total
    // for every client that has ever connected there. Seven verdicts once did
    // read them that way, and the symptom was one client's behaviour reported
    // as nine other clients'.
    //
    // Taken before `accept()`, because 0-RTT and Initial packets are counted
    // on the way in and are already recorded by the time a `Connection`
    // exists. The view carries a baseline as well as the per-peer split: the
    // split is what stops another client's traffic being read at all, and the
    // baseline is what bounds the damage if two connections ever do share an
    // address — unusual for this runner, where each client is a fresh process
    // with a fresh ephemeral port, but the suite is public and a CI harness
    // behind NAT would do it.
    let since = conformance_counters.view_for(peer_addr);

    // A refusal here used to leave no trace, and the report said the opposite of
    // what happened.
    //
    // `?` propagated the error out of `run_one` before anything was recorded, so
    // the session held no result for this test and the report fell back to
    // `not_run` -- rendered as "Not attempted". The client had been attempted.
    // It connected, the endpoint refused it, and the one page whose whole claim
    // is measurement reported that as never having tried.
    //
    // It is not a rare path: every TLS-tier port negotiates exactly one key
    // exchange group, so the three clients in the matrix that offer no
    // post-quantum key share -- curl, aioquic and .NET/msquic -- are refused by
    // all six of them. Nineteen of the twenty cells reading "Not attempted" in
    // the 2026-09-18 run were this, and the reason behind them is the most
    // interesting thing the TLS tier measures.
    let mut connecting = match incoming.accept() {
        Ok(connecting) => connecting,
        Err(e) => {
            // No SNI to resolve with: the ClientHello never got far enough to
            // hand one over, so the source address is all there is.
            let session_id = resolve_session(None, peer_ip, &conformance);
            // Only the TLS tier can explain a pre-handshake refusal, because
            // only there does the endpoint constrain the handshake. Every
            // TLS-tier port negotiates exactly one key exchange group, so a
            // client offering none of it is refused here and that refusal *is*
            // the measurement.
            //
            // On the QUIC and HTTP/3 tiers the same code path fires for an
            // unrelated reason and nothing about key exchange is known. Saying
            // otherwise is not a harmless extra sentence: in the 2026-09-18 run
            // it reached 28 HTTP/3 cells and one QUIC cell, where the tier does
            // not constrain the handshake at all. Twenty-nine of those thirty
            // were xquic, whose four TLS-tier passes show it negotiates the
            // group perfectly well -- so the sentence told a reader the exact
            // opposite of what the TLS tier had measured about the same client
            // in the same run. An instrument that invents a cause is worse than
            // one that reports none, because the invented one is actionable.
            let observation = match test.tier {
                // A definite answer, and the one this tier exists to get. Every
                // TLS port negotiates exactly one group, so a refusal here is
                // the client saying it does not have that group.
                Tier::Tls => Observation::Unsupported(format!(
                    "The client offers no key exchange group this port will negotiate, so it \
                     was refused before a handshake existed ({e}). That is a capability this \
                     client does not have, rather than something the run failed to measure"
                )),
                // Nothing is known here, and that is our problem rather than
                // the client's.
                Tier::Quic | Tier::Http3 => Observation::NotExercised(format!(
                    "the endpoint refused the connection before a handshake existed ({e}), so \
                     the client never reached the anomaly. What the refusal was about is not \
                     recorded here: this tier does not constrain the handshake, and the error \
                     is the transport's own"
                )),
            };
            conformance.sessions.with(&session_id, |sess| {
                sess.record(
                    test,
                    &observation,
                    expected_code(test),
                    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                );
            });
            info!(
                "conformance: {} session={} refused before the handshake: {}",
                test.id, session_id, e
            );
            return Ok(());
        }
    };

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
                    if matches!(test.tier, Tier::Tls) {
                        // On this tier the handshake IS the anomaly, so a
                        // handshake that failed is a result rather than a
                        // non-event. Saying "the client never reached the
                        // anomaly" here would be false: it reached it, and this
                        // is what it did about it.
                        tls_handshake_observation(test, &e)
                    } else if test.id == "q-invalid-transport-param" {
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
    let (critical_streams, mut encoder, mut control, mut probe_target, control_is_late) =
        match emit(&connection, test).await {
            Ok(emitted) => (
                emitted.keep_open,
                Some(emitted.encoder),
                Some(emitted.control),
                emitted.probe_target,
                emitted.control_is_late,
            ),
            Err(e) => {
                debug!("conformance: {} could not emit anomaly: {}", test.id, e);
                (Vec::new(), None, None, None, false)
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

    // Two updates, spaced so the second is legal.
    //
    // §6.1 forbids initiating another update before the previous phase has been
    // acknowledged, and the stack enforces that by ignoring a redundant call —
    // so the second one has to wait for a round trip rather than follow
    // immediately, or it would silently never happen and the test would be the
    // single-update one under another name.
    if test.id == "q-key-update-repeated" && test.implemented {
        connection.force_key_update();
        let again = connection.clone();
        tokio::spawn(async move {
            tokio::time::sleep(SECOND_KEY_UPDATE_AFTER).await;
            again.force_key_update();
        });
    }

    // The stream credit this port withheld at the handshake.
    //
    // Issued from a task rather than inline: the client cannot open its request
    // until this lands, so the code that waits for the request has to already be
    // running when it does.
    if test.id == "q-max-streams-credit" && test.implemented {
        let granting = connection.clone();
        tokio::spawn(async move {
            tokio::time::sleep(STREAM_CREDIT_AFTER).await;
            granting.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(1));
        });
    }

    // Streams that must stay open past the verdict. `Drop for SendStream`
    // finishes the stream it owns, so anything answered but not finished has to
    // be parked somewhere that outlives the wait.
    let mut held: Vec<quinn::SendStream> = Vec::new();
    let qpack = Arc::new(QpackLimits::default());

    // The read-proof has to run *while the client is still there*.
    //
    // The first version of it ran after the exchange had settled, which is
    // exactly too late: for every observation it was meant to resolve the
    // client had already completed its request and closed, so the first write
    // hit a dead connection and the probe reported "could not be put" every
    // single time. It was a correct idea wired into the wrong moment, and the
    // only way to see that was to run it -- the code compiled, the tests
    // passed, and the verdicts were unchanged.
    //
    // Filling the window concurrently with the client's own request is the
    // right moment: the padding is a reserved frame type the client must skip
    // (RFC 9114 §7.2.8), it travels on the control stream rather than the
    // request, and it is only started for the tests whose verdict actually
    // turns on whether that stream was read.
    //
    // Whichever stream carries the anomaly, and only that one. The control
    // stream for the tests written to it; the anomaly's own stream for a push
    // stream or the QPACK encoder stream. Credit on one says nothing about
    // the other, which is the mistake this replaces.
    let mut probe_control = if test.class != catalog::Class::Correctness {
        None
    } else {
        match catalog::anomaly_stream(test) {
            catalog::Anomaly::ControlStream if !control_is_late => control.take(),
            // The push test hands its stream over; the two QPACK tests write
            // to the encoder stream, which `emit` returns by name. Each is
            // padded with something legal on it -- see `fill` in the probe.
            catalog::Anomaly::OtherUniStream => probe_target.take().or_else(|| encoder.take()),
            _ => None,
        }
    };

    let (observation, read_proof) = if critical_streams.is_empty() {
        (
            classify_close(&connection, &conformance.close_elicitation).await,
            None,
        )
    } else {
        tokio::join!(
            watch_for_liveness(
                &connection,
                &conformance,
                test,
                &mut held,
                ServerStreams {
                    encoder: encoder.as_mut(),
                    late_control: if control_is_late {
                        control.as_mut()
                    } else {
                        None
                    },
                },
                &qpack,
                // Not just "0-RTT was possible" — `into_0rtt` succeeds whenever the
                // configuration offers early data, whether or not the client sent
                // any. The wire count is the same evidence the verdict is built on,
                // so the response and the verdict cannot disagree.
                early_data_accepted && since.zero_rtt_in() > 0,
            ),
            async {
                match probe_control.as_mut() {
                    Some(stream) => control_stream_was_read(test.id, &connection, stream).await,
                    None => None,
                }
            }
        )
    };

    // The stateless-reset test only begins once the client is established and
    // talking, so it runs here rather than in `emit`: the anomaly is the server
    // vanishing mid-conversation, which needs a conversation first.
    let observation = if test.id == "q-stateless-reset" && test.implemented {
        abandon_and_watch(&connection, &endpoint, &since, &mut held).await
    } else {
        observation
    };

    // Ask whether the control stream was ever read, rather than reporting that
    // we cannot know.
    //
    // This is the single largest source of inconclusive verdicts in the suite:
    // the client completed its request and closed without objecting, the
    // anomaly was on a unidirectional stream nothing obliges it to read on any
    // schedule, and those two facts together were treated as unanswerable. The
    // flow-control probe answers them. Both outcomes are results:
    //
    //   read it and said nothing -> it saw the violation and accepted it, which
    //                               is the failure the test is looking for
    //   never read it            -> the anomaly did not reach this client, which
    //                               is a fact about how it handles control
    //                               streams and not a hole in the run
    //
    // Only when the probe itself cannot be put -- the stream is gone, or the
    // client's window is too large to fill for the price -- does the verdict
    // stay inconclusive, and then it says which.
    // The control-stream read-proof does not decide anything, and the call
    // site is gone rather than neutered.
    //
    // It was left in place behind `match None::<bool>` with an
    // `#[allow(unreachable_code)]`, which is dead code wearing the shape of
    // live code — in the one subsystem this suite spent a day proving
    // unreliable. Someone reading it in six months sees a probe that appears
    // wired.
    //
    // The probe decides again, and this time the reach was measured first.
    //
    // It was withdrawn because the version of it that wrote the client's whole
    // advertised window answered only for clients with small buffers -- 100%
    // at 64 KB, 9% around 1 MB, skipped entirely above 4 MB -- so the cells it
    // resolved sorted by buffer size rather than by behaviour. The rewrite
    // watches this stream's own credit and stops at the first grant, which
    // costs the same whatever the window, and the reach was measured across
    // six clients before rewiring it: msquic 10/10, picoquic 10/10, quic-go
    // 4/10, aioquic 4/10, chromium 3/35, curl 0/10. curl's are all "connection
    // lost" -- it closes before the probe can be put, which is a different
    // limit from the one that was withdrawn and is not buffer size.
    //
    // Only `Some(true)` is acted on. A grant is positive evidence that the
    // bytes were consumed; its absence is still the old ambiguity and is left
    // as inconclusive, so nothing is failed for a probe that merely did not
    // land.
    let observation = match (&observation, read_proof) {
        (
            Observation::SurvivedAndContinued
            | Observation::ClosedSilently
            | Observation::NoCloseObserved
            | Observation::PeerUnreachable
            | Observation::TimedOut,
            Some(true),
        ) if catalog::anomaly_stream(test) == catalog::Anomaly::ControlStream => {
            Observation::ReadThenSilent("extended flow-control credit on it".to_string())
        }
        _ => observation,
    };

    // Some QUIC-layer tests are judged on what the connection did rather than
    // on whether a request arrived, so the transport's own account of it
    // supersedes the liveness result.
    let observation = quic_observation(&connection, test, &since, &qpack).unwrap_or(observation);

    // A completed handshake on the post-quantum chain port deserves its own
    // sentence rather than the generic discretionary one.
    //
    // "Tolerated it and continued" is true of a client that ignored a GREASE
    // codepoint; it is a poor description of one that decompressed 40 KB of
    // ML-DSA-87 certificates and verified a signature scheme standardised this
    // decade. The distinction matters because this row is the certificate-side
    // answer to the question the TLS tier exists to ask, and today almost
    // nothing reaches it.
    let observation = if test.id == "t-cert-compression-pq"
        && matches!(
            observation,
            Observation::SurvivedAndContinued
                | Observation::NoCloseObserved
                | Observation::PeerUnreachable
        ) {
        Observation::Signalled(
            "completed the handshake against an ML-DSA-87 chain: the compressed certificate \
             message was decompressed, the chain parsed, and a post-quantum signature verified. \
             Note that a client run with certificate verification disabled reaches this point \
             without trusting anything, so what this shows is that the chain was processed, not \
             that it was trusted"
                .to_string(),
        )
    } else {
        observation
    };

    // A client that declined to wait for stream credit has not failed anything.
    //
    // This port withholds the credit a request needs and issues it a moment
    // later. Waiting is what §4.6 expects, but nothing obliges a one-shot client
    // to sit on a connection it cannot use yet — and the catalogue entry says so.
    // Left to the generic path, giving up reads as a discretionary test that
    // stalled, which is scored as a failure.
    let observation = if test.id == "q-max-streams-credit"
        && matches!(
            observation,
            Observation::TimedOut | Observation::ClosedSilently
        ) {
        Observation::NotExercised(format!(
            "the client did not wait for the credit. This port grants no bidirectional \
             stream until {}ms in, and declining to wait that long is not a violation of \
             anything — it simply leaves the limit untested",
            STREAM_CREDIT_AFTER.as_millis()
        ))
    } else {
        observation
    };

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

/// Why a TLS-tier handshake ended, read from the connection error rather than
/// from its wording.
///
/// The first version matched on the error's `Display` string, looking for
/// "error 47", and two things were wrong with that.
///
/// The string does not say who spoke: our own rustls refusing a client that
/// offered no group we will negotiate renders as "the cryptographic handshake
/// failed: error 40", the same shape as a peer's alert and the opposite
/// meaning — the client never even saw the anomaly.
///
/// And 47 is not the only right answer. RFC 9001 §4.8 lets a QUIC endpoint
/// replace any alert with a generic one, so reading anything else as a refusal
/// to obey RFC 8446 §4.1.3 would fail a client for taking a permission it was
/// given in writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsAbort {
    /// The peer converted a TLS alert into a CRYPTO_ERROR close, per RFC 9001
    /// §4.8. Carries the AlertDescription.
    Alert(u8),
    /// This server refused: the client offered no key exchange group the port
    /// will negotiate, so the ServerHello carrying the anomaly was never sent.
    NoGroupsInCommon,
    /// This server refused for the other reason: the client's
    /// `signature_algorithms` named nothing our certificate can be verified
    /// with, so the chain was never sent either.
    ///
    /// Only reachable on the post-quantum chain port. Every other port serves
    /// an ECDSA certificate that every client in existence can verify.
    NoSignatureSchemesInCommon,
    /// The handshake stopped and nothing arrived to say why.
    Silent,
    /// Something else ended it.
    Other,
}

/// Classify a failed TLS-tier handshake.
fn classify_tls_abort(e: &quinn::ConnectionError) -> TlsAbort {
    match e {
        // A close the peer sent. RFC 9001 §4.8 maps a TLS alert to
        // 0x0100 | AlertDescription, so anything in that range is the client
        // telling us which alert its TLS stack raised.
        quinn::ConnectionError::ConnectionClosed(close) => {
            let code = u64::from(close.error_code);
            match code {
                0x0100..=0x01ff => TlsAbort::Alert((code & 0xff) as u8),
                _ => TlsAbort::Other,
            }
        }
        // Raised on this side, not received. `NoKxGroupsInCommon` is rustls
        // saying the ClientHello offered nothing this port will negotiate,
        // which happens before any anomaly is emitted.
        quinn::ConnectionError::TransportError(err) => {
            if err.reason.contains("NoSignatureSchemesInCommon") {
                TlsAbort::NoSignatureSchemesInCommon
            } else if err.reason.contains("NoKxGroupsInCommon") {
                TlsAbort::NoGroupsInCommon
            } else {
                TlsAbort::Other
            }
        }
        quinn::ConnectionError::TimedOut => TlsAbort::Silent,
        _ => TlsAbort::Other,
    }
}

/// What a failed handshake on the TLS tier says about the client.
///
/// # Why a generic alert passes
///
/// RFC 9001 §4.8 is explicit that QUIC "permits the use of a generic code in
/// place of a specific error code ... this includes replacing any alert with a
/// generic alert, such as handshake_failure", and that an endpoint MAY do so to
/// avoid exposing confidential information. Demanding `illegal_parameter`
/// specifically would therefore fail a client for taking a permission the
/// document hands it in writing — the exact false accusation this suite exists
/// to avoid. What §4.1.3 of RFC 8446 requires is the *abort*; the alert value
/// is reported rather than judged.
fn tls_handshake_observation(test: &'static Test, e: &quinn::ConnectionError) -> Observation {
    let abort = classify_tls_abort(e);

    // Common to every port here: a client that offered no group this port will
    // negotiate never received the ServerHello the test is about.
    //
    // `t-classical-only` is the exception, because there that refusal is the
    // measurement rather than a miss.
    if abort == TlsAbort::NoGroupsInCommon && test.id != "t-classical-only" {
        return Observation::Unsupported(
            "The client offered no key exchange group this port will negotiate, so the \
             ServerHello this test is about was never sent. Against a hybrid-only port that \
             means it offered no post-quantum key share at all"
                .to_string(),
        );
    }

    match test.id {
        // ── §4.1.3: a key_share naming a group the client never offered ──
        //
        // The abort is the requirement. Any CRYPTO_ERROR close is evidence of
        // one, whichever alert it names.
        "t-group-not-offered" => match abort {
            TlsAbort::Alert(47) => Observation::Signalled(
                "aborted with illegal_parameter (alert 47) over a key_share naming a group it \
                 never offered, which is exactly what RFC 8446 §4.1.3 requires"
                    .to_string(),
            ),
            TlsAbort::Alert(code) => Observation::Signalled(format!(
                "aborted the handshake with TLS alert {code} (CRYPTO_ERROR 0x{:x}) rather than \
                 illegal_parameter. §4.1.3 requires the abort, and RFC 9001 §4.8 expressly \
                 permits replacing any alert with a generic one over QUIC, so the code is \
                 reported and not judged",
                0x0100 | u64::from(code)
            )),
            // No CONNECTION_CLOSE arrived. The handshake certainly did not
            // complete, so the client did not accept the group -- but a close
            // that was never sent cannot be told from one that was lost, and
            // "stopped talking" cannot be told from "stalled". The requirement
            // is met either way; the manner of it is not observable.
            TlsAbort::Silent => Observation::Ambiguous(
                "The handshake did not complete, so the group was not accepted, but nothing \
                 arrived to say the client rejected it deliberately. RFC 9001 §4.8 carries a \
                 TLS alert in a CONNECTION_CLOSE and none was seen; a close that was never \
                 sent and one that was lost look the same from here"
                    .to_string(),
            ),
            _ => Observation::Ambiguous(format!(
                "The handshake ended ({e}) without a CONNECTION_CLOSE carrying a TLS alert, so \
                 the client did not accept the group but nothing shows how it refused"
            )),
        },

        // ── The hybrid share whose ML-KEM half is corrupt ──
        //
        // Any failure passes here, and only completion fails. The dangerous
        // outcome is the one that *succeeds*: a client that finishes against a
        // corrupt ML-KEM half has used the intact classical half alone and
        // downgraded itself to exactly the security level the hybrid exists to
        // avoid. That case is caught where a completed connection reaches the
        // ordinary response path.
        //
        // Silence is a pass rather than nothing observed, and deliberately: the
        // client's key schedule has diverged from ours, so it cannot encrypt
        // anything we can read at the handshake level. Not answering is the
        // only answer available to it.
        "t-corrupt-hybrid-share" => match abort {
            TlsAbort::Alert(code) => Observation::Signalled(format!(
                "rejected the handshake with TLS alert {code}. The shared secret is both \
                 halves through the key schedule, so a corrupt ML-KEM half must break it -- \
                 and this client did not fall back to the intact X25519 half"
            )),
            _ => Observation::Signalled(format!(
                "did not complete the handshake ({e}). The shared secret is both halves \
                 through the key schedule, so a corrupt ML-KEM half must break it -- and this \
                 client did not fall back to the intact X25519 half"
            )),
        },

        // ── §3.1.2: a share whose length does not match its group ──
        //
        // Judged exactly as `t-group-not-offered` is, and for the same reason:
        // the draft names illegal_parameter, RFC 9001 §4.8 lets a QUIC endpoint
        // replace it, so the abort is the requirement and the code is reported.
        //
        // The distinction worth drawing here is that failing is not by itself
        // evidence of the check. No client can complete this handshake -- the
        // shared secret needs the half we removed -- so a client that never
        // looks at the length still fails, just later and over something else.
        // An alert naming illegal_parameter is the one outcome that shows the
        // length was checked where the draft asks for it; anything else is an
        // abort we can confirm but cannot attribute, and it is reported that
        // way rather than being counted as proof.
        "t-hybrid-share-length" => match abort {
            TlsAbort::Alert(47) => Observation::Signalled(
                "aborted with illegal_parameter (alert 47) over a server share of the wrong \
                 length for X25519MLKEM768, which is the check §3.1.2 asks the client to make \
                 and the code it names"
                    .to_string(),
            ),
            TlsAbort::Alert(code) => Observation::Signalled(format!(
                "aborted the handshake with TLS alert {code} rather than illegal_parameter. \
                 §3.1.2 requires the abort and RFC 9001 §4.8 permits replacing the alert over \
                 QUIC, so the code is reported and not judged -- though note that a truncated \
                 share also breaks the key schedule, so this abort does not on its own show \
                 the length was what the client objected to"
            )),
            TlsAbort::Silent => Observation::Ambiguous(
                "The handshake did not complete, which it could not have done with half the \
                 shared secret missing, but nothing arrived to say the client rejected the \
                 length deliberately. A close that was never sent and one that was lost look \
                 the same from here"
                    .to_string(),
            ),
            _ => Observation::Ambiguous(format!(
                "The handshake ended ({e}) without a CONNECTION_CLOSE carrying a TLS alert. \
                 The share was certainly not used, but nothing shows whether its length was \
                 what the client objected to"
            )),
        },

        // ── The post-quantum chain ──
        //
        // Graded not at all, and the alert is the entire measurement. A client
        // that rejects our private CA has already decompressed 40 KB of
        // ML-DSA-87 certificates to find out who signed them, which is the
        // capability under test; one that cannot parse the chain says so with a
        // different code entirely.
        //
        // Alert numbers from RFC 8446 §6.2: 42 bad_certificate, 43
        // unsupported_certificate, 45 certificate_expired, 46
        // certificate_unknown, 48 unknown_ca, 50 decode_error.
        "t-cert-compression-pq" => match abort {
            // The chain never left this endpoint, so nothing about the client's
            // handling of it was observed. This is a fact about the client and
            // not a gap in the run -- and the most common answer today, which is
            // itself the finding: a certificate signed with ML-DSA-87 cannot be
            // offered to a client whose signature_algorithms does not name it.
            TlsAbort::NoSignatureSchemesInCommon => Observation::Unsupported(
                "The client's signature_algorithms named nothing that can verify an ML-DSA-87 \
                 chain, so this endpoint refused before sending one. Post-quantum certificates \
                 are not reachable for this client at all"
                    .to_string(),
            ),
            TlsAbort::Alert(code @ (42 | 46 | 48)) => Observation::Signalled(format!(
                "decompressed and parsed the 40 KB ML-DSA-87 chain, then rejected it on trust \
                 (alert {code}). That is the right answer to a private CA, and reaching it \
                 means the certificate message itself was handled"
            )),
            TlsAbort::Alert(code @ 43) => Observation::Signalled(format!(
                "parsed the chain and rejected it as unsupported (alert {code}), which reads \
                 as ML-DSA-87 being a signature algorithm this client does not implement -- a \
                 fact about its algorithm support rather than about the compressed chain"
            )),
            TlsAbort::Alert(code @ 50) => Observation::Signalled(format!(
                "could not decode the certificate message (alert {code}). The chain is the \
                 only thing unusual about this port, so this is the compressed 40 KB of it \
                 rather than anything about trust -- the outcome a post-quantum deployment \
                 needs to know about"
            )),
            TlsAbort::Alert(code) => Observation::Signalled(format!(
                "aborted over the certificate with TLS alert {code}. Reported rather than \
                 graded: RFC 8879 §4 lets a receiver cap the decompressed size and abort, and \
                 no document requires ML-DSA support of anyone"
            )),
            TlsAbort::Silent => Observation::Ambiguous(
                "The handshake did not complete and nothing arrived to say why. The chain was \
                 certainly not accepted, but a client that could not parse it and one whose \
                 close was lost look the same from here"
                    .to_string(),
            ),
            _ => Observation::Ambiguous(format!(
                "The handshake ended ({e}) without a CONNECTION_CLOSE carrying a TLS alert, so \
                 nothing shows how far into the chain the client got"
            )),
        },

        // A client that will not negotiate with a classical-only server has
        // taken a post-quantum floor, which is exactly the choice this
        // discretionary test exists to observe. Scoring it "did not exercise"
        // would discard the answer at the moment it was given.
        "t-classical-only" if abort == TlsAbort::NoGroupsInCommon => Observation::Signalled(
            "declined to negotiate when only the classical X25519 was offered, which is a \
             deliberate post-quantum floor. No RFC requires this and none forbids it"
                .to_string(),
        ),

        _ => Observation::NotExercised(format!(
            "the handshake failed ({e}) for a reason other than the key exchange this port \
             constrains"
        )),
    }
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

    // The TLS tier is given its own, much shorter deadline.
    //
    // On every other tier the handshake is scenery and the anomaly comes after
    // it, so a handshake that never finishes is simply a connection that failed.
    // Here the handshake *is* the test, and the client's answer to two of these
    // ports is to stop talking: it cannot encrypt anything the server can read
    // once its key schedule has diverged, so silence is the only answer
    // available to it.
    //
    // Left to the transport's idle timeout, that silence takes 30 seconds to
    // become a verdict — and the runner has fetched the report and moved on by
    // then. Both new TLS tests came back `not_run` for quinn on the first
    // seven-client run for exactly this reason: the verdicts were recorded
    // correctly, just after anybody was still reading.
    //
    // Five seconds is two orders of magnitude more than a handshake on this path
    // takes and still well inside the runner's window.
    if matches!(test.tier, Tier::Tls) {
        const TLS_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);
        return match tokio::time::timeout(TLS_HANDSHAKE_DEADLINE, connecting).await {
            Ok(result) => result,
            Err(_elapsed) => Err(quinn::ConnectionError::TimedOut),
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
    // Per-connection like every other verdict. The connection is abandoned
    // partway through, but the peer does not change, so its own datagram
    // count is the right thing to watch — and the wrong thing is the port
    // aggregate, where another client arriving during the eight-second wait
    // would look like this one still talking.
    counters: &PeerView,
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

    // Let whatever was already in flight land before the clock starts.
    //
    // A Stateless Reset cannot stop packets the peer has already put on the
    // wire, and §10.3.1 asks a client to go quiet once it *recognises* the
    // token -- not retroactively. Counting from the instant the reset was
    // sent charged every one of those crossing packets to the client, which
    // made the verdict turn on how much it happened to have in flight at that
    // moment. Across three runs of the same binaries it flipped
    // picoquic/q-stateless-reset pass -> fail -> pass and
    // xquic/q-stateless-reset the same way, and a cell that changes its claim
    // between identical runs is not a result.
    //
    // The grace is generous next to the round-trip times here, and it does
    // not weaken the test: a client that has not recognised the token keeps
    // retransmitting for the whole silence window that follows, which is
    // longer than any reasonable PTO on this path.
    const CROSSING: Duration = Duration::from_millis(500);
    tokio::time::sleep(CROSSING).await;
    let settled = counters.datagrams_in();

    tokio::time::sleep(SILENCE).await;
    let after = counters.datagrams_in() - settled;
    let crossing = settled - at_reset;

    if after == 0 {
        Observation::Signalled(format!(
            "was sent a Stateless Reset and went quiet — nothing further arrived in the {} \
             seconds that followed, which is the draining period §10.3.1 requires \
             ({crossing} datagram(s) were already in flight when the reset went out and are \
             not counted against it)",
            SILENCE.as_secs()
        ))
    } else {
        Observation::Violated(format!(
            "kept sending after the Stateless Reset: {after} more datagram(s) arrived in \
             the following {} seconds, after a {}ms grace for packets already in flight \
             ({crossing} of those). RFC 9000 §10.3.1 requires a client that recognises the \
             token to enter the draining period and send nothing further, so this \
             connection is wedged against an endpoint that has forgotten it",
            SILENCE.as_secs(),
            CROSSING.as_millis()
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
    // The anomaly's own stream, where that is a unidirectional stream other
    // than the control stream. See `Emitted::probe_target`.
    let mut probe_target: Option<quinn::SendStream> = None;

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
        //
        // Only the SETTINGS go out here. The GOAWAY itself is written later,
        // from `watch_for_liveness`, once the client's request is actually in
        // flight -- see `late_control` below for why sending it now measured
        // the wrong thing.
        "h-goaway" => {
            control.write_all(&f::settings_with_grease()).await?;
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
            // Handed to the read proof rather than parked: this is the stream
            // whose consumption the verdict turns on.
            probe_target = Some(push);
        }

        // A push nobody permitted.
        //
        // The maximum push ID is unset until the client sends MAX_PUSH_ID
        // (§7.2.7), and no client under test sends one, so push ID 0 is already
        // larger than what has been advertised. The promised request is an
        // ordinary GET so the field section decodes cleanly and the only thing
        // left to object to is the push itself.
        // The frame goes on the response stream, not here.
        //
        // It was written to the control stream, where §7.2.5 has a different
        // and more specific answer: "If a PUSH_PROMISE frame is received on
        // the control stream, the client MUST respond with a connection error
        // of type H3_FRAME_UNEXPECTED." So the port asked one question and the
        // catalogue graded the other, and seven independent implementations --
        // quinn, aioquic, chromium, quiche, neqo, ngtcp2, lsquic, xquic -- were
        // failed for answering 0x105 correctly. When every implementation
        // disagrees with the suite, the suite is what needs reading again.
        //
        // Placement is the whole test, exactly as it was for t-grease-group.
        // On a response stream PUSH_PROMISE is a legal frame in a legal place,
        // so the only thing left to object to is the push ID -- which is what
        // the title says this measures.
        "h-push-promise-unsolicited" => {
            control.write_all(&f::settings_with_grease()).await?;
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

    // `h-goaway` is the one test whose frame must arrive *after* the client's
    // request, so its control stream is handed back named rather than parked
    // with the rest. Everything else has already written what it came to write.
    Ok(Emitted {
        keep_open,
        encoder,
        control,
        probe_target,
        control_is_late: test.id == GOAWAY_AFTER_REQUEST,
    })
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
    /// The control stream.
    ///
    /// Named rather than parked in `keep_open` for two reasons now. The first
    /// is `h-goaway`, which writes to it after the client's request rather
    /// than before. The second is the read-proof: where a test's anomaly went
    /// out on this stream and the client then said nothing, the only way to
    /// tell "read it and accepted the violation" from "never read it" is to
    /// write past the client's flow-control limit on this exact stream and see
    /// whether credit is extended. Both need a handle that outlives `emit`.
    pub(super) control: quinn::SendStream,
    /// The stream this test's anomaly was written to, when that is a
    /// server-opened unidirectional stream other than the control stream.
    ///
    /// The read proof has to watch the stream whose bytes are in question. It
    /// watched the control stream for these too, because they were all filed
    /// under one `Anomaly` variant, and concluded that a client which had
    /// drained our control stream must also have consumed a push stream it may
    /// never have looked at. Three of our own client's cells were failed on
    /// that.
    pub(super) probe_target: Option<quinn::SendStream>,
    /// Whether `control` still has its frame to write, which is `h-goaway`
    /// and nothing else.
    pub(super) control_is_late: bool,
}

/// The server-side streams `watch_for_liveness` may still write to.
///
/// One parameter rather than two because they travel together and mean the same
/// thing: streams this endpoint opened, kept past `emit`, because the moment
/// they are allowed to be written is after the client's request rather than
/// before it.
pub(super) struct ServerStreams<'a> {
    /// The QPACK encoder stream, writable only once the client's SETTINGS say
    /// how much of the dynamic table, if any, we may use.
    pub(super) encoder: Option<&'a mut quinn::SendStream>,
    /// The control stream `h-goaway` writes its frame on, once there is a
    /// request in flight for that frame to be about.
    pub(super) late_control: Option<&'a mut quinn::SendStream>,
}

/// The test whose GOAWAY is deliberately held back until a request is in
/// flight.
///
/// Sent at connection setup, as it was until 2026-09-17, the frame races the
/// client's first request -- and RFC 9114 §5.2 makes losing that race a
/// *correct* client's problem, not ours: a client that reads GOAWAY before it
/// has sent anything MUST NOT open a request on that connection, so the right
/// answer is to close and go elsewhere. The suite recorded that as "dropped the
/// connection instead of recovering" and published a failure.
///
/// It fired once, against Chromium, in the 2026-09-17T20:03Z run and did not
/// reproduce in three consecutive re-runs afterwards. An upstream report had
/// already been drafted on it. A verdict decided by which of two packets won a
/// race is the exact thing `MEASUREMENT_METHODOLOGY.md` forbids.
///
/// So the frame now goes out once the request stream has been accepted, naming
/// an identifier above it: the in-flight request is inside the promise, and
/// what the test measures is whether the client finishes it -- which is what
/// the catalogue entry has claimed all along.
const GOAWAY_AFTER_REQUEST: &str = "h-goaway";

/// How far above the in-flight request `h-goaway`'s identifier sits.
///
/// §5.2's identifier names the first request that will *not* be processed, so
/// pointing it at the next client-initiated bidirectional stream (+4, the step
/// between them in RFC 9000 §2.1) says precisely "this one is being handled and
/// nothing after it is".
const GOAWAY_NEXT_REQUEST_STEP: u64 = 4;

/// The RFC 8701 reserved group `t-grease-group` advertises.
///
/// 0x2A2A, taken from the middle of the reserved range rather than either end,
/// so a client that special-cases a boundary value is not let through by
/// accident.
const GREASE_NAMED_GROUP: u16 = 0x2A2A;

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
    ours: ServerStreams<'_>,
    qpack: &Arc<QpackLimits>,
    early_data_seen: bool,
) -> Observation {
    let ServerStreams {
        encoder,
        late_control,
    } = ours;
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
                    // Read as it arrives, and parse as soon as the SETTINGS
                    // frame is whole.
                    //
                    // This was `read_to_end`, which on a *control* stream does
                    // not return until the connection is over -- a control
                    // stream stays open for its whole life (§6.2.1 makes
                    // closing one an error). So the client's QPACK limits were
                    // observed, if at all, long after the response that
                    // depended on them had been written.
                    //
                    // All twelve clients reported "advertised 0 and 0",
                    // Chromium and Firefox among them, and both
                    // h-qpack-dynamic-table and h-qpack-blocked-stream were
                    // `unsupported` across the board on the strength of a
                    // measurement that never happened. 24 cells.
                    let mut buf = Vec::with_capacity(4096);
                    while buf.len() < 64 * 1024 {
                        match uni.read_chunk(4096).await {
                            Ok(Some(chunk)) => buf.extend_from_slice(&chunk),
                            // End of stream, or the stream failed: whatever is
                            // here is all there will be.
                            Ok(None) | Err(_) => break,
                        }
                        if let Some(limits) = f::parse_client_qpack_limits(&buf) {
                            qpack.observe(limits);
                            return;
                        }
                    }
                    // A last attempt on whatever arrived before the stream
                    // ended, so a client that closes promptly is still read.
                    if let Some(limits) = f::parse_client_qpack_limits(&buf) {
                        qpack.observe(limits);
                    }
                });
            }
        }
    });

    let probe = tokio::time::timeout(timeout, connection.accept_bi()).await;
    drainer.abort();

    // Whether the frame `late_control` exists for actually went out.
    //
    // It is written under the client's request, so a client that never opened
    // one was never shown the anomaly at all -- and the branches below would
    // otherwise read its silence as a failure to recover from something it was
    // never sent.
    let mut deferred_written = false;
    let deferred = late_control.is_some();

    let observation = match probe {
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

                // The one frame that is written here rather than in `emit`.
                //
                // `h-goaway` is about a server draining under a request that is
                // already running, and that is only true once the request has
                // arrived. Written at connection setup it raced the request
                // instead, and a client that read it first was right to close
                // -- §5.2 forbids opening a request after GOAWAY -- but the
                // suite scored the close as a failure to recover.
                //
                // The identifier names the *next* request stream, so the one
                // being answered below is inside the promise: finish this,
                // start nothing further. That is the sentence the catalogue
                // entry has always claimed to be testing.
                if let Some(control) = late_control {
                    let in_flight: u64 = send.id().into();
                    let result = control
                        .write_all(&f::goaway(in_flight + GOAWAY_NEXT_REQUEST_STEP))
                        .await;
                    match result {
                        Ok(()) => {
                            deferred_written = true;
                            debug!(
                                "conformance: {} sent GOAWAY({}) under request stream {}",
                                test.id,
                                in_flight + GOAWAY_NEXT_REQUEST_STEP,
                                in_flight
                            );
                        }
                        // Not a client failure: the connection went away before
                        // the anomaly could be written, so the test was never
                        // put to it. The liveness result that follows says so.
                        Err(e) => debug!("conformance: {} could not send GOAWAY: {}", test.id, e),
                    }
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
            // Both arms go through `classify_close`, including the one where
            // the settle window expired with nothing seen.
            //
            // That arm used to return `NoCloseObserved` outright, which is the
            // one conclusion in this function that must not be drawn without
            // asking: a client that rejected the anomaly and whose single
            // CONNECTION_CLOSE was lost looks exactly like a client that
            // carried on, and RFC 9000 §10.2.1 says the only way to tell is to
            // send it a packet. The elicitation probe existed for precisely
            // that case and was wired into every arm except it -- the three it
            // did reach all arrive with `close_reason()` already `Some`, where
            // it can never fire. Counting the probe is what exposed this: a
            // full matrix run attempted it zero times.
            //
            // `close_reason()` is `None` here, so `classify_close` sends the
            // PING and waits. A client that really did close answers with the
            // close it already sent; a live one stays connected and the
            // observation is `NoCloseObserved` exactly as before, 400ms later.
            let _ = tokio::time::timeout(settle, connection.closed()).await;
            match classify_close(connection, &conformance.close_elicitation).await {
                // A clean close after a completed request is exactly what a
                // client that handled the anomaly does -- and that is as true
                // of a close we had to ask for as of one that arrived on its
                // own. Whether the settle window saw it decides nothing here;
                // only whether the client closed, and how.
                Observation::ClosedSilently => Observation::SurvivedAndContinued,
                other => other,
            }
        }
        Ok(Err(_)) => classify_close(connection, &conformance.close_elicitation).await,
        Err(_) => {
            // Nothing arrived in time. If the peer had closed we would have
            // seen an error above, so distinguish a real stall from a close
            // that raced the timeout.
            match connection.close_reason() {
                Some(_) => classify_close(connection, &conformance.close_elicitation).await,
                None => Observation::TimedOut,
            }
        }
    };

    // Nothing was shown, so nothing is concluded.
    //
    // `h-goaway` writes its frame under a request in flight. A client that
    // opened no request never saw it, and the observation above would report
    // that as a client which dropped the connection instead of recovering --
    // the same false accusation the deferral was introduced to remove, moved
    // one step along.
    if deferred && !deferred_written {
        return Observation::NotExercised(
            "the client opened no request, and this test's frame is written under a \
             request in flight rather than at connection setup, so the anomaly was \
             never sent"
                .to_string(),
        );
    }

    observation
}

/// What the transport itself can say about a QUIC-layer test.
///
/// `None` means this test is judged the ordinary way, on the liveness probe.
/// These read the connection's own frame counters, because the behaviour under
/// test happens below HTTP entirely and the client cannot be asked about it.
fn quic_observation(
    connection: &quinn::Connection,
    test: &'static Test,
    // This peer's counters and nothing else. A `&Counters` here is what let
    // one client's traffic decide another client's verdict, seven times over,
    // and there is no route from this type to the port aggregate.
    counters: &PeerView,
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
                "this endpoint asked for a rotation and none came back. The connection \
                 ID issued at the handshake expires part-way through the exchange and \
                 NEW_CONNECTION_ID carries a higher retire_prior_to, so §5.1.2 obliges \
                 a RETIRE_CONNECTION_ID -- but a client that closed before the expiry \
                 was never asked"
                    .to_string(),
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
            no_early_data(counters, "nothing was rejected")
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
                Some(p) if p.ecn_feedback.any() => {
                    // Proof for every peer after this one: the codepoint
                    // survives from here to there.
                    counters.note_ecn_echoed();
                    Observation::Signalled(format!(
                        "echoed ECN counts back in its ACKs: {} ECT(0), {} ECT(1), {} ECN-CE",
                        p.ecn_feedback.ect0, p.ecn_feedback.ect1, p.ecn_feedback.ce
                    ))
                }
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
                // The client's own datagrams settle which of the two it was.
                //
                // Both directions cross the same path. A client whose packets
                // reach us still carrying ECT has shown that the path
                // preserves the field and that its stack sets it, so its
                // silence about our markings is a property of the client and
                // not an unknown -- `unsupported`, the verdict for a client
                // that does not do the thing, rather than a run that failed to
                // ask. §13.4.1 permits exactly this, so it is not a failure.
                Some(p) if !p.sending_ecn && counters.ect_in() > 0 => {
                    Observation::Unsupported(format!(
                        "does not report ECN counts. {} of its own datagrams reached this \
                         endpoint carrying ECT, so the path preserves the codepoint in both \
                         directions and this client's stack sets it -- but nothing came back \
                         about the markings we sent, and §13.4.1 requires reporting only \
                         where the ECN field is accessible to the endpoint",
                        counters.ect_in()
                    ))
                }
                // Or the port itself has been shown to carry ECT by someone
                // else. That is a fact about the path, not about whoever
                // demonstrated it, and it does not expire between clients.
                Some(p) if !p.sending_ecn && counters.path_carries_ect() => {
                    Observation::Unsupported(
                        "does not report ECN counts. Another peer has echoed the markings \
                         this same port sent, so the codepoint demonstrably survives the \
                         path from here -- this client simply reported nothing, which \
                         §13.4.1 permits where the ECN field is not accessible to it"
                            .to_string(),
                    )
                }
                Some(p) if !p.sending_ecn => Observation::NotExercised(
                    "ECN validation failed: packets sent marked ECT(0) came back \
                     acknowledged without ECN counts, so the marking was disabled. \
                     This client's own datagrams arrived unmarked too, so whether it \
                     declined to report or the path rewrote the codepoint cannot be \
                     told apart from this end"
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

        // Whether the client can see a congestion signal at all.
        //
        // Read from the same ECN feedback as the ECT(0) test, and scored the same
        // conditional way: counts coming back is the only conclusion available,
        // and silence cannot be told apart from a peer with no access to the
        // field or a path that rewrote the codepoint.
        "q-ecn-congestion" => {
            let marked = counters.marked_ce();
            let path = connection.path_stats(quinn_proto::PathId::ZERO);
            Some(match path {
                _ if marked == 0 => Observation::NotExercised(
                    "no datagram was marked CE, so the client was never shown a congestion \
                     signal. The marking begins shortly after a peer's first datagram and \
                     rewrites one ECT codepoint in four after that"
                        .to_string(),
                ),
                Some(p) if p.ecn_feedback.ce > 0 => {
                    counters.note_ecn_echoed();
                    Observation::Signalled(format!(
                        "reported the congestion back: {} ECN-CE among {} ECT(0) and {} \
                         ECT(1), after {marked} datagram(s) were marked",
                        p.ecn_feedback.ce, p.ecn_feedback.ect0, p.ecn_feedback.ect1
                    ))
                }
                Some(p) if p.ecn_feedback.any() => Observation::NotExercised(format!(
                    "ECN counts came back but none of them were CE ({} ECT(0), {} ECT(1)), \
                     though {marked} datagram(s) were marked. A path that rewrote the \
                     codepoint in transit cannot be told apart from a client that does not \
                     distinguish CE",
                    p.ecn_feedback.ect0, p.ecn_feedback.ect1
                )),
                // Nothing came back, and the path has already been shown to
                // carry the codepoint -- by this client's own datagrams
                // arriving marked, or by another peer echoing the markings
                // this same port sent. Either way the silence is the client's.
                Some(_) if counters.ect_in() > 0 || counters.path_carries_ect() => {
                    Observation::Unsupported(format!(
                        "does not report ECN counts, so the congestion signal had nowhere \
                         to be seen. {marked} datagram(s) were marked CE and the codepoint \
                         demonstrably survives this path, so nothing here was lost in \
                         transit -- §13.4.1 requires reporting only where the ECN field is \
                         accessible to the endpoint, and for this client it is not"
                    ))
                }
                Some(_) => Observation::NotExercised(
                    "no ECN counts came back at all. §13.4.1 requires reporting only where \
                     the ECN field is accessible, and nothing else on this port has shown \
                     the codepoint surviving, so a path that stripped it cannot be told \
                     apart from a client that does not report"
                        .to_string(),
                ),
                None => Observation::NotExercised(
                    "the path had already been discarded before its ECN counts could be read"
                        .to_string(),
                ),
            })
        }

        // Waiting for credit is the pass; announcing the wait is a bonus.
        //
        // Left to the liveness result when the client did open its request:
        // the probe arriving after the credit is the evidence, and it is the
        // generic path that records it. Only the case where nothing arrived
        // needs saying in this test's own words.
        // Announcing the block is affirmative evidence the client waited
        // properly, and §4.6 recommends exactly that.
        //
        // The first version also checked `frame_rx.stream` for a request having
        // arrived, which is wrong: that counts STREAM frames of every kind, and
        // a client's own control and QPACK streams are made of them. It was
        // therefore true on every connection, the arm never fired, and a client
        // that announced the block and then declined to wait was handed to the
        // generic path and failed for closing quietly — the exact outcome this
        // entry's expectation says is not a failure.
        "q-max-streams-credit" => (rx.streams_blocked_bidi > 0).then(|| {
            Observation::Signalled(format!(
                "announced the block with {} STREAMS_BLOCKED rather than opening a \
                 stream it had no credit for, which is what §4.6 recommends",
                rx.streams_blocked_bidi
            ))
        }),

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
                // The client never raised its path MTU above the floor, so
                // there was never a packet large enough for the hole to take.
                //
                // That is a property of the client, not a gap in the run: the
                // server streams 96 KiB at it and a client doing DPLPMTUD has
                // every opportunity to probe upward. One that stays at the
                // 1200-byte minimum has no black hole to detect, which is
                // what `unsupported` is for.
                Some(p) if p.current_mtu <= 1200 => Observation::Unsupported(format!(
                    "does not raise its path MTU above the {}-byte minimum, so there is no \
                     black hole for it to detect. The server streamed 96 KiB at it and the \
                     path swallows anything over 1300, but nothing it sent was ever that \
                     large",
                    p.current_mtu
                )),
                // It did raise the MTU, and still sent nothing over the limit.
                Some(p) => Observation::NotExercised(format!(
                    "nothing over the limit was sent, so the path never swallowed anything; \
                     the MTU reached {}. This test needs a client that sends enough data \
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
            Some(Observation::Unsupported(qpack.why_unusable()))
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

        // Whether the ClientHello actually needed more than one Initial packet
        // decides only whether this ran; completing the handshake is the
        // liveness result.
        //
        // A client that negotiated the hybrid in a single Initial was never put
        // in the situation this test is about, and crediting it would be
        // claiming it handles a split first flight on the evidence of a flight
        // that was not split. Two is the threshold rather than one because
        // every handshake sends at least one Initial.
        "t-hybrid-large-hello" => {
            if counters.initials_in() > 1 {
                return None;
            }
            Some(Observation::NotExercised(format!(
                "the client's first flight fitted in {} Initial packet(s), so a ClientHello \
                     too large for one was never sent. That usually means it did not \
                     offer a post-quantum key share: an ML-KEM-768 share is 1,216 \
                     bytes and cannot fit beside the rest of a ClientHello inside the \
                     1,200-byte Initial minimum",
                counters.initials_in()
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
            // Our failure and the client's are different sentences.
            //
            // They were the same one until 2026-09-19, and it was the wrong
            // one: the shadow socket bound `::` and every client connects over
            // IPv4, so every copy failed with EAFNOSUPPORT and the error was
            // discarded. The report told twelve clients they had not been
            // shown a second address, which was true, and ours.
            let failed = counters.shadow_failed();
            if failed > 0 {
                return Some(Observation::NotExercised(format!(
                    "this endpoint could not send from its second address at all: \
                     {failed} copy attempt(s) failed. That is a fault in the harness, \
                     not a property of the client, and nothing about this client's \
                     handling of §9.6 should be read from it"
                )));
            }
            Some(Observation::NotExercised(
                "no datagram was copied from the second address, so the client was never \
                 shown one. The copy opens shortly after a peer's first datagram and \
                 needs the server to still be sending by then"
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
            // The delta, not the total: see `zero_rtt_before` in `run_one`.
            if counters.zero_rtt_in() > 0 {
                return None;
            }
            Some(no_early_data(counters, "it was never answered 425"))
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
        // PUSH_PROMISE where the frame itself is allowed, so the push ID is
        // the only thing wrong with it. §7.2.7 leaves the maximum push ID
        // unset until the client sends MAX_PUSH_ID and none of them do, so
        // push ID 0 is already larger than anything advertised.
        "h-push-promise-unsolicited" => {
            send.write_all(&f::headers(&[
                (":status", "200"),
                ("content-type", "text/plain"),
                ("x-conformance", "push-promise-unsolicited"),
            ]))
            .await?;
            send.write_all(&f::push_promise(
                UNPROMISED_PUSH_ID_ZERO,
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "conformance.pqcrypta.com"),
                    (":path", "/pushed"),
                ],
            ))
            .await?;
            send.write_all(&f::data(BODY)).await?;
        }

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
    if catalog::anomaly_may_be_unread(test) {
        // Give a unidirectional stream a chance to be read before the client is
        // free to close.
        return Some(CONTROL_STREAM_GRACE);
    }
    if test.id == "q-cid-rotation" {
        // The CID expires 300ms in; a bare request is over long before that.
        return Some(CID_ROTATION_HOLD);
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
/// For every test but one the bytes reached the client before its request did;
/// this is about giving it a moment to look at them while it still has a reason
/// to keep the connection open. A second is far longer than reading a queued
/// stream takes and is only spent on the tests that need it. `h-goaway` writes
/// its frame at the start of this window rather than before it, and the window
/// is what gives the client room to act on it.
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

/// Why no early data arrived, said accurately.
///
/// Three different things reached the same sentence before this existed, and
/// only one of them was about the client:
///
///   * the client was never given a ticket to resume from -- the driver made
///     one connection per test until 2026-09-19, and 22 cells said "a client
///     that connects once has none" because that was literally true;
///   * the client GREASEs its QUIC version, is answered with Version
///     Negotiation as RFC 8999 §6 requires, and does not re-offer early data
///     on the retry. Measured on the wire, this is exactly what Cloudflare
///     quiche does: its 0-RTT rides in a 0xbabababa first flight and never
///     comes back. It tried, and its own probe cost it the attempt;
///   * the client had every opportunity and did not take it, which is the one
///     case that is a fact about the client.
///
/// Reported as `Unsupported` only in the third: there the client has answered.
fn no_early_data(counters: &PeerView, what_was_missed: &str) -> Observation {
    if counters.version_negotiations_out() > 0 {
        // Fully observed, so not a gap in the run.
        //
        // This read inconclusive, which was too weak: nothing here is
        // inferred. The GREASE version was seen, the Version Negotiation was
        // sent, and the v1 retry arrived carrying no early data -- three
        // facts on the wire, all of them about the client. It describes a
        // client that cannot deliver 0-RTT to any endpoint that answers a
        // GREASEd version, which is what §6 requires of every endpoint, and
        // that is a property worth reporting as one.
        //
        // Conformant on both sides, so not a failure either.
        return Observation::Unsupported(format!(
            "does not deliver early data to an endpoint that negotiates versions, so \
             {what_was_missed}. It offered a GREASE QUIC version first, which this endpoint \
             answered with Version Negotiation (RFC 8999 §6), and it did not re-offer early \
             data on the v1 retry -- so the 0-RTT it intended never reached the wire. Both \
             sides are conformant; the early data is lost between them"
        ));
    }
    // Also inference from an absence, and held to the same bar as the
    // control-stream case above.
    //
    // A client that was primed and sends no early data has probably declined
    // 0-RTT -- but "probably" is the word doing the work. The driver primes,
    // so a ticket was issued; whether *this* client resumed with it is not
    // visible from here, and a client that silently failed to store the ticket
    // is indistinguishable from one that stored it and chose not to use it.
    // Calling that `Unsupported` would put a declaration in the client's mouth.
    //
    // Promoting it needs one more fact: whether the handshake resumed. rustls
    // knows, and the fork could surface it the way `peer_initial_max_stream_data_uni`
    // was surfaced. Until it does, this is inconclusive and the reason says so.
    Observation::NotExercised(format!(
        "the client sent no early data, so {what_was_missed}. A session was issued for it to \
         resume from, so the opportunity existed -- but whether this client resumed the \
         session at all is not observable from this end, and a client that failed to store \
         the ticket looks exactly like one that stored it and chose not to offer early data"
    ))
}

/// How much padding the read proof writes at a time.
///
/// Chosen for the number of writes, not the bytes: the fill has to finish
/// inside the client's own connection, and each write can cost a poll tick.
const PROBE_CHUNK: usize = 64 * 1024;

/// How long the client has to extend credit once the window is full.
const READ_PROOF_WAIT: Duration = Duration::from_millis(1_500);

/// Did the client actually read our control stream?
///
/// Returns `Some(true)` if it demonstrably did, `Some(false)` if it
/// demonstrably did not, and `None` if the question could not be put.
///
/// The one signal in QUIC that distinguishes *delivered* from *read* is flow
/// control. A receiver extends a stream's window with MAX_STREAM_DATA when its
/// application consumes data (RFC 9000 §4.1); it has no reason to do so
/// otherwise. So filling the window and writing one byte more asks the
/// question directly: the write completes only if credit arrived, and credit
/// arrives only if the client read.
///
/// The padding is a reserved frame type, which RFC 9114 §7.2.8 requires
/// clients to skip using its length, so the probe adds nothing the client is
/// entitled to object to. It runs only after the test's own exchange has
/// settled and only when the verdict would otherwise be inconclusive, so it
/// cannot colour what it is measuring.
///
/// Why this exists: "the client completed its request and closed without
/// objecting, but the anomaly was on the control stream" was 41 of the 199
/// inconclusive cells in the 2026-09-18 matrix — the single largest reason in
/// the grid, and stated as though it were a fact of nature. It was not. It was
/// the consequence of never asking.
pub(super) async fn control_stream_was_read(
    test_id: &str,
    connection: &quinn::Connection,
    control: &mut quinn::SendStream,
) -> Option<bool> {
    let limit = connection.peer_initial_max_stream_data_uni();

    // Logged for every connection, reached or skipped, because the first
    // question anyone should ask of this probe is whether it ran at all.
    //
    // If the window a client advertises decides whether it gets probed, then
    // a client with a small window collects real verdicts while one with a
    // large window keeps its inconclusives -- and the difference between them
    // would be a property of this harness wearing the costume of a finding.
    // The per-client windows have to be comparable and the skips have to be
    // countable, so both go in the log.
    // The ceiling is gone, and deliberately.
    //
    // It existed because the old probe had to write the whole window, so a
    // client advertising 1 GB -- curl does -- would have cost a gigabyte to
    // measure. Skipping those clients made the probe's reach a property of a
    // constant in this file: curl and Chromium were never probed at all, on
    // any cell, in the 2026-09-19 02:20Z run.
    //
    // Watching this stream's own credit removes the reason for it. The probe
    // now ends at the first grant, so a large window costs no more than a
    // small one, and every client is measured on the same terms.
    if limit == 0 {
        info!("conformance: {test_id} read-proof skipped (peer window not yet known)");
        return None;
    }
    info!(
        "conformance: {} read-proof starting (peer window {} bytes)",
        test_id, limit
    );

    // Watch this stream's own credit, and stop the moment it moves.
    //
    // The first version proved a read by overrunning the window: write
    // `limit + 2` frames and see whether `write_all` completed. That is
    // unambiguous and it made the probe's cost the client's choice, because
    // the amount to write *is* the window the client advertised. Measured
    // across twelve clients in the 2026-09-19 02:20Z run, the success rate was
    // a monotonic function of that window and nothing else -- 100% at 64 KB,
    // 45% at 512 KB, 9-36% around 1 MB, skipped above 4 MB. Small-buffer
    // clients finished before they could close; large-buffer clients lost a
    // race to their own close timer. Every verdict in that column was a buffer
    // size wearing a behaviour's clothes.
    //
    // A MAX_STREAM_DATA naming *this* stream is the same evidence for a
    // fraction of the work: a peer sends one only when its application has
    // consumed data here. Not `FrameStats::max_stream_data`, which counts them
    // for the whole connection and therefore also rises when the client reads
    // the response on another stream -- fast, and wrong.
    let baseline = match control.peer_max_data() {
        Ok(v) => v,
        Err(_) => {
            info!("conformance: {test_id} read-proof skipped (stream already closed)");
            return None;
        }
    };

    // Padding the stream is allowed to carry.
    //
    // A reserved HTTP/3 frame type is the right filler on a stream made of
    // HTTP/3 frames -- §7.2.8 requires a client to skip it -- and it is
    // meaningless on the QPACK encoder stream, whose bytes are encoder
    // instructions. That looked like the end of it, and the two
    // encoder-stream tests were left inconclusive on the grounds that no
    // legal filler exists there.
    //
    // One does. RFC 9204 §4.3.1's Set Dynamic Table Capacity is a complete,
    // legal encoder instruction, a decoder must process it, and repeating it
    // with the same value changes nothing: capacity 0 is valid and is what
    // this endpoint already advertises. So the encoder stream can be filled
    // as legally as the control stream, and its tests can be answered rather
    // than written off.
    let frame = if matches!(
        test_id,
        "h-qpack-encoder-overflow" | "h-qpack-encoder-bad-name-index"
    ) {
        // 64 KiB of one-byte instructions. The size is about how many
        // writes the fill takes, not about the bytes: at 4 KiB a 1.25 MB
        // window needs ~300 writes and the polling loop can spend a 10ms
        // tick on each, so the probe was still filling when the client
        // finished and went away -- measured at 1,249,280 of 1,250,000
        // bytes written before "connection lost". Twenty writes instead of
        // three hundred.
        let mut buf = bytes::BytesMut::with_capacity(PROBE_CHUNK);
        for _ in 0..PROBE_CHUNK {
            buf.extend_from_slice(&f::qpack_set_capacity(0));
        }
        buf
    } else {
        f::reserved_frame(0x1f, &vec![0u8; PROBE_CHUNK])
    };
    let mut written = 0u64;

    let probe = async {
        loop {
            if control.peer_max_data().unwrap_or(baseline) > baseline {
                return Ok::<bool, quinn::WriteError>(true);
            }
            // Keep filling, because a receiver only grants more once it has
            // consumed enough to be worth granting. Bounded by the window:
            // past that, `write_all` blocks and the polling below is what
            // makes progress.
            tokio::select! {
                res = control.write_all(&frame) => {
                    res?;
                    written += frame.len() as u64;
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
            if control.peer_max_data().unwrap_or(baseline) > baseline {
                return Ok(true);
            }
        }
    };

    let outcome = tokio::time::timeout(READ_PROOF_WAIT, probe).await;
    let (verdict, why) = match &outcome {
        Ok(Ok(true)) => (
            Some(true),
            "peer extended credit on this stream".to_string(),
        ),
        Ok(Ok(false)) => (None, "probe ended without a decision".to_string()),
        // The stream died under us: the client is gone and nothing is proven.
        Ok(Err(e)) => (None, format!("stream ended under the probe: {e}")),
        // Still connected, still not granting credit on this stream.
        Err(_) => (
            Some(false),
            "no credit granted on this stream for the whole wait".to_string(),
        ),
    };
    info!(
        "conformance: {test_id} read-proof result={verdict:?} window={limit} wrote={written} \
         why={why}"
    );
    verdict
}

/// How long to wait for a close that a PING should have shaken loose.
///
/// One round trip plus slack. These clients are on the same host or a few
/// milliseconds away; a peer in closing state answers immediately or not at
/// all, and waiting longer only delays the run.
const CLOSE_ELICIT_WAIT: Duration = Duration::from_millis(400);

/// Turn a closed connection into an observation, preserving the error code the
/// client chose — which for the correctness tests is the entire point.
async fn classify_close(
    connection: &quinn::Connection,
    elicitation: &crate::conformance::CloseElicitation,
) -> Observation {
    if let Some(e) = connection.close_reason() {
        return classify_error(&e);
    }

    // Nothing recorded — so ask, rather than reporting that we could not tell.
    //
    // RFC 9000 §10.2.1: an endpoint in the closing state re-sends its
    // CONNECTION_CLOSE in answer to an incoming packet, and only then. A
    // client that rejected the anomaly correctly and whose one close was lost
    // therefore looks exactly like a client that never objected. The suite
    // documented that indistinguishability in `Observation::NoCloseObserved`
    // for months and treated it as a fact of nature; it is not. It is the
    // consequence of never having sent anything after the anomaly.
    //
    // One PING settles it. A peer in closing state answers with the close it
    // already sent; a peer that never closed stays quiet and the observation
    // is unchanged.
    //
    // This comment used to claim the probe was worth 14 cells of the
    // 2026-09-18 matrix. It was not, and could not have been: until
    // 2026-09-19 the probe was reachable only from call sites that already
    // had a `close_reason()`, so it never ran. The counters below were added
    // to check that claim and measured zero attempts across a full matrix.
    // The figure had been read off a log from the targeted experiments, which
    // are a different population, and written up as a property of the suite.
    //
    // What it is actually worth, now that it runs where the conclusion is
    // drawn: the answer rate is zero and the acknowledgement rate is total.
    // Every peer that reaches this point ACKs the PING and sends no close, so
    // it is alive and `NoCloseObserved` below is correct -- which is the
    // point. The probe's value here is not that it changes the answer but
    // that it earns it, and the counters are published so the day it stops
    // earning it is visible rather than silent.
    //
    // Counted, both halves. This probe is what decides a correctness test when
    // the first close went missing, so how often it works is a published
    // property of the instrument rather than something the suite asserts about
    // itself -- see `/conformance/` for the rate the last run measured.
    elicitation.attempt();
    let acks_before = connection.stats().frame_rx.acks;
    connection.ping();
    let deadline = tokio::time::Instant::now() + CLOSE_ELICIT_WAIT;
    loop {
        if let Some(e) = connection.close_reason() {
            elicitation.answer();
            return classify_error(&e);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Asked, and still nothing. Now the silence is evidence rather than an
    // absence of it: this peer is not in closing state.
    //
    // Provided the question arrived. A PING that drew neither a close nor an
    // acknowledgement reached nobody, and reading that as "the client did not
    // object" would be the very inference this probe exists to replace. So the
    // ACK is counted separately: a peer that acknowledges and sends no close
    // is demonstrably alive, and the observation below is a measurement. A
    // peer that acknowledges nothing leaves it a guess, and the published
    // counters say which of the two the run was.
    if connection.stats().frame_rx.acks > acks_before {
        elicitation.acknowledge();
        return Observation::NoCloseObserved;
    }

    // Nothing came back at all, so the silence is not the peer's -- it may not
    // be there. Reporting this as `NoCloseObserved` would have the correctness
    // tier say a PING ruled out a lost rejection, which a PING that reached
    // nobody does not.
    Observation::PeerUnreachable
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
                "layer": match t.tier { Tier::Http3 => "http3", Tier::Quic => "quic", Tier::Tls => "tls" },
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
                    catalog::Anomaly::OtherUniStream => "other_uni_stream",
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
                "If the first frame of the control stream is any other frame type, this MUST \
                 be treated as a connection error of type H3_MISSING_SETTINGS.",
            ),
            (
                "h-second-control-stream",
                e::H3_STREAM_CREATION_ERROR,
                "RFC 9114 §6.2.1",
                "Only one control stream per peer is permitted; receipt of a second stream \
                 claiming to be a control stream MUST be treated as a connection error of type \
                 H3_STREAM_CREATION_ERROR.",
            ),
            (
                "h-control-frame-unexpected",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.1",
                "If a DATA frame is received on a control stream, the recipient MUST respond \
                 with a connection error of type H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-max-push-id",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.7",
                "A server MUST NOT send a MAX_PUSH_ID frame. A client MUST treat the receipt \
                 of a MAX_PUSH_ID frame as a connection error of type H3_FRAME_UNEXPECTED.",
            ),
            // Read as published on 2026-08-31, along with the other four added
            // that day.
            (
                "h-settings-on-request-stream",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §7.2.4",
                "If an endpoint receives a SETTINGS frame on a different stream, the endpoint \
                 MUST respond with a connection error of type H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-data-before-headers",
                e::H3_FRAME_UNEXPECTED,
                "RFC 9114 §4.1",
                "Receipt of an invalid sequence of frames MUST be treated as a connection \
                 error of type H3_FRAME_UNEXPECTED.",
            ),
            (
                "h-cancel-push-unsolicited",
                e::H3_ID_ERROR,
                "RFC 9114 §7.2.3",
                "If a CANCEL_PUSH frame is received that references a push ID greater than \
                 currently allowed on the connection, this MUST be treated as a connection \
                 error of type H3_ID_ERROR.",
            ),
            // Read as published on 2026-09-01.
            (
                "h-push-promise-unsolicited",
                e::H3_ID_ERROR,
                "RFC 9114 §7.2.5, §4.6",
                "A client MUST treat receipt of a PUSH_PROMISE frame that contains a larger \
                 push ID than the client has advertised as a connection error of H3_ID_ERROR.",
            ),
            (
                "h-goaway-increasing",
                e::H3_ID_ERROR,
                "RFC 9114 §5.2",
                "Receiving a GOAWAY containing a larger identifier than previously received \
                 MUST be treated as a connection error of type H3_ID_ERROR.",
            ),
            (
                "h-datagram-setting-invalid",
                e::H3_SETTINGS_ERROR,
                "RFC 9297 §2.1.1",
                "If the SETTINGS_H3_DATAGRAM setting is received with a value that is neither \
                 0 nor 1, the receiver MUST terminate the connection with error \
                 H3_SETTINGS_ERROR.",
            ),
            (
                "h-qpack-encoder-overflow",
                e::QPACK_ENCODER_STREAM_ERROR,
                "RFC 9204 §4.3.1, §6",
                "The decoder MUST treat a new dynamic table capacity value that exceeds this \
                 limit as a connection error of type QPACK_ENCODER_STREAM_ERROR.",
            ),
            (
                "h-push-stream-unpromised",
                e::H3_ID_ERROR,
                "RFC 9114 §6.2.2",
                "A client MUST treat receipt of a push stream as a connection error of type \
                 H3_ID_ERROR when no MAX_PUSH_ID frame has been sent or when the stream \
                 references a push ID that is greater than the maximum push ID.",
            ),
            (
                "h-qpack-static-index-invalid",
                e::QPACK_DECOMPRESSION_FAILED,
                "RFC 9204 §3.1, §4.5.2",
                "When the decoder encounters an invalid static table index in a field line \
                 representation, it MUST treat this as a connection error of type \
                 QPACK_DECOMPRESSION_FAILED.",
            ),
            (
                "h-qpack-encoder-bad-name-index",
                e::QPACK_ENCODER_STREAM_ERROR,
                "RFC 9204 §3.1, §4.3.2",
                "If this index is received on the encoder stream, this MUST be treated as a \
                 connection error of type QPACK_ENCODER_STREAM_ERROR.",
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

    /// The same rule for the two codes `expected_code` cannot express.
    ///
    /// `expected_code` compares HTTP/3 application codes. Two tests are decided
    /// on a *transport* code instead, in their own verdict functions, and so sat
    /// outside the table above -- which meant the sibling of the mistake that
    /// table exists to prevent could still be made in `frame_encoding_verdict`
    /// or `transport_param_verdict` and nothing would catch it.
    ///
    /// This drives the functions rather than reading a map, so it pins the
    /// behaviour and not just the constant: the required code has to be accepted
    /// as an objection, and a plausible wrong one has to be reported as a
    /// violation naming the right code. Sentences re-read from the published
    /// text on 2026-09-17.
    #[test]
    fn every_transport_code_matches_its_rfc_clause() {
        use quinn_proto::TransportErrorCode as Tec;

        fn closed_with(code: Tec) -> quinn::ConnectionError {
            quinn::ConnectionError::ConnectionClosed(quinn_proto::ConnectionClose {
                error_code: code,
                frame_type: quinn_proto::MaybeFrame::None,
                reason: bytes::Bytes::new(),
            })
        }

        // (test id, clause, the sentence requiring it, the code it names, a
        //  wrong-but-plausible code a client might send instead)
        let verified: &[(
            &str,
            &str,
            &str,
            Tec,
            Tec,
            fn(&Test, &quinn::ConnectionError) -> Option<Observation>,
        )] = &[
            (
                "q-reserved-frame",
                "RFC 9000 §12.4",
                "An endpoint MUST treat the receipt of a frame of unknown type as a \
                 connection error of type FRAME_ENCODING_ERROR.",
                Tec::FRAME_ENCODING_ERROR,
                Tec::PROTOCOL_VIOLATION,
                frame_encoding_verdict,
            ),
            (
                "q-invalid-transport-param",
                "RFC 9000 §7.4",
                // Two sentences, because the violation and the code live in
                // different sections: §18.2 "ack_delay_exponent ... Values above
                // 20 are invalid." is what makes the parameter we send illegal,
                // and §7.4 is what says how a client must answer it.
                "An endpoint MUST treat receipt of a transport parameter with an invalid \
                 value as a connection error of type TRANSPORT_PARAMETER_ERROR.",
                Tec::TRANSPORT_PARAMETER_ERROR,
                Tec::INTERNAL_ERROR,
                transport_param_verdict,
            ),
        ];

        for (id, clause, sentence, required, wrong, verdict) in verified {
            let t = catalog::find(id).expect(id);
            // `contains`, not equality: a test may cite more than one clause,
            // and `q-invalid-transport-param` rightly cites two -- §18.2 is
            // what makes ack_delay_exponent = 32 invalid, §7.4 is what names
            // the code to reject it with. What must hold is that the clause
            // naming the code is among them.
            assert!(
                t.spec.contains(clause),
                "{id} cites \"{}\" but was verified against {clause}",
                t.spec
            );
            assert_eq!(
                t.class,
                catalog::Class::Correctness,
                "{id} requires a specific rejection, so it is a correctness test"
            );
            assert!(
                matches!(
                    verdict(t, &closed_with(*required)),
                    Some(Observation::Signalled(_))
                ),
                "{id}: {clause} says \"{sentence}\", so that code must read as an objection"
            );
            assert!(
                matches!(
                    verdict(t, &closed_with(*wrong)),
                    Some(Observation::Violated(_))
                ),
                "{id}: a rejection carrying the wrong code is still a violation of {clause}"
            );
            // And the functions must keep to their own test: one catalogue-wide
            // matcher answering for everything would judge tests nobody verified.
            for other in catalog::CATALOG {
                if other.id != *id {
                    assert!(
                        verdict(other, &closed_with(*required)).is_none(),
                        "{} answered for {}, which it was not verified against",
                        id,
                        other.id
                    );
                }
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
