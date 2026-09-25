//! The conformance test catalogue.
//!
//! Every entry names the RFC clause it exercises and states what a correct
//! client must do. That pairing is the point: a report saying "FAIL" is useless
//! unless it also says which sentence of which specification was violated, so
//! the library author can go and read it.

use serde::{Deserialize, Serialize};

/// What kind of correctness a test measures.
///
/// These are rolled up separately in the report rather than averaged into one
/// number. A client that ignores unknown extensions correctly but never emits
/// the right error codes has a specific, nameable problem, and a single
/// percentage would hide exactly that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// The client must ignore something it does not understand and carry on.
    /// This is what keeps a protocol extensible; a client that dies here is the
    /// reason ossification happens.
    Extensibility,
    /// The client must reject something invalid, with the specific error code
    /// the specification names. Rejecting with the wrong code is a smaller but
    /// still real bug.
    ///
    /// Failing to reject is the bug being hunted, but it has to be *shown*: see
    /// [`anomaly_stream`], which decides whether a quiet client can be said to
    /// have accepted anything at all.
    Correctness,
    /// The client must recover — retry, re-probe, migrate — rather than fail.
    Resilience,
    /// The client must correctly process something valid but demanding —
    /// Huffman-coded field lines, a dynamic-table reference, trailers.
    ///
    /// Distinct from [`Correctness`](Self::Correctness), which is about
    /// rejecting the invalid. Conflating the two is what made this suite report
    /// "accepted a protocol violation" for four tests that send perfectly legal
    /// HTTP/3 — accusing a client of a fault for doing exactly what the
    /// specification asks.
    Interoperability,
    /// The specification permits more than one response, so both pass and the
    /// report says which was chosen.
    ///
    /// Exists because several requirements are MAY, not MUST — RFC 9114 §7.2.4.1
    /// says a receiver *may* treat duplicate setting identifiers as an error.
    /// Scoring those as Correctness would fail conformant clients for making a
    /// legal choice, and a suite that wrongly accuses the thing it is testing is
    /// worse than no suite: nobody trusts the failures that are real.
    Discretionary,
}

impl Class {
    /// Stable lowercase name, used in JSON and in report URLs.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Extensibility => "extensibility",
            Class::Correctness => "correctness",
            Class::Resilience => "resilience",
            Class::Interoperability => "interoperability",
            Class::Discretionary => "discretionary",
        }
    }
}

/// Which protocol layer a test's anomaly lives at.
///
/// Not a selection mechanism — every test is selected by connecting to its own
/// UDP port. This says where the awkwardness is, which is what a library author
/// needs to know to find the code responsible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The anomaly is in the HTTP/3 framing: SETTINGS, the control stream,
    /// QPACK, the response stream.
    Http3,
    /// The anomaly is in QUIC itself: version negotiation, transport
    /// parameters, frames, path validation.
    Quic,
    /// The anomaly is in the TLS 1.3 handshake carried inside QUIC: which key
    /// exchange group the server will negotiate, and what the client does when
    /// that is not the one it hoped for.
    ///
    /// Added last and it is the layer this company is named after. The first
    /// fifty-one tests covered QUIC and HTTP/3 and said nothing about the
    /// handshake underneath them, during the migration that makes client
    /// behaviour there matter more than it ever has.
    ///
    /// These ports do not emit malformed bytes. They are configured to
    /// negotiate exactly one group, which is a legal server configuration and
    /// not a violation of anything — but it forces a path production never
    /// does, and what a client does on that path is the measurement.
    Tls,
}

/// The requirement level of the clause a test exercises, as it binds the client.
///
/// A separate axis from [`Class`], and deliberately so. The class says what kind
/// of correctness is being measured; this says how hard the specification
/// insists. They do not move together: `h-duplicate-setting` is discretionary
/// *because* its clause is a MAY, but `q-stream-limit` is discretionary while
/// resting on a MUST NOT, because what the test can observe is the SHOULD-level
/// announcement rather than the prohibition itself.
///
/// Published in the catalogue so a reader can ask for every MUST across both
/// protocols, or see at a glance that a failure they are looking at rests on a
/// SHOULD and is a matter of judgement rather than a violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// The clause requires the behaviour.
    Must,
    /// The clause forbids the behaviour.
    MustNot,
    /// The clause recommends it; a client may reasonably do otherwise.
    Should,
    /// The clause permits it; more than one answer is conformant.
    May,
}

impl Requirement {
    /// Stable name, used in JSON and in the matrix filters.
    pub fn as_str(self) -> &'static str {
        match self {
            Requirement::Must => "must",
            Requirement::MustNot => "must_not",
            Requirement::Should => "should",
            Requirement::May => "may",
        }
    }

    /// How it is written in a specification.
    pub fn label(self) -> &'static str {
        match self {
            Requirement::Must => "MUST",
            Requirement::MustNot => "MUST NOT",
            Requirement::Should => "SHOULD",
            Requirement::May => "MAY",
        }
    }
}

/// Which stream a test's anomaly is written to.
///
/// This decides what a *silent* client proves, which is the difference between a
/// sound verdict and a false accusation.
///
/// A client has to read the response stream to obtain its response. So when the
/// anomaly is there and the client delivered the response and closed cleanly, it
/// demonstrably consumed the anomaly and carried on: that is positive evidence
/// of acceptance, and a correctness failure.
///
/// The control stream is unidirectional and nothing compels a client to read it
/// on any particular schedule. A one-shot request can complete and close before
/// the stream is ever picked up, so "no rejection arrived" is consistent with
/// two quite different states — the client accepted the violation, or it never
/// saw it. Inferring failure from that is unsound, and it is exactly what made
/// `h-max-push-id` fail one run in three against a client that rejected the
/// frame correctly, deterministically, every time it got that far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anomaly {
    /// Written to the server's control stream. A client that never reads it
    /// looks identical to one that accepted it.
    ControlStream,
    /// A server-opened unidirectional stream that is not the control stream:
    /// the QPACK encoder stream, a push stream, a reserved type.
    ///
    /// Judged exactly as `ControlStream` is -- nothing obliges a client to
    /// read either on any schedule -- and the read proof is put the same way,
    /// on this stream's own credit. Kept apart because the probe has to write
    /// something legal *for this stream*: QPACK instructions on the encoder
    /// stream, a reserved frame elsewhere.
    OtherUniStream,
    /// Written to the response stream, which the client must read to be served.
    ResponseStream,
    /// Below HTTP/3 entirely: transport parameters, frames, the path itself.
    Transport,
}

/// Whether `test`'s anomaly rides a server-opened unidirectional stream.
///
/// The control stream and the others are judged alike: nothing obliges a
/// client to read either on any schedule, so silence proves nothing. They are
/// separate variants only because the read proof measures credit on the
/// control stream, and that is evidence about the control stream and nothing
/// else. Use this wherever the question is "could the client have missed it",
/// and match `Anomaly::ControlStream` exactly wherever the answer comes from
/// that stream's own credit.
pub fn anomaly_may_be_unread(test: &Test) -> bool {
    matches!(
        anomaly_stream(test),
        Anomaly::ControlStream | Anomaly::OtherUniStream
    )
}

/// What to call the stream `test` wrote its anomaly to, in a sentence.
///
/// The verdict text used to say "the control stream" for every test that
/// `anomaly_may_be_unread` covers, which was true when that was the only
/// unidirectional variant and became false the moment `OtherUniStream`
/// existed. Four tests were then published with a report naming a stream they
/// do not touch -- a small wrong fact in a document whose whole claim is that
/// it does not state any.
pub fn anomaly_stream_name(test: &Test) -> &'static str {
    match test.id {
        "h-qpack-encoder-overflow" | "h-qpack-encoder-bad-name-index" => "the QPACK encoder stream",
        "h-push-stream-unpromised" => "a server-initiated push stream",
        "h-reserved-uni-stream" => "a unidirectional stream of a reserved type",
        _ => match anomaly_stream(test) {
            Anomaly::ControlStream => "the control stream",
            Anomaly::OtherUniStream => "a server-opened unidirectional stream",
            Anomaly::ResponseStream => "the response stream",
            Anomaly::Transport => "the transport",
        },
    }
}

/// Where `test` writes its anomaly.
///
/// Keyed by id, like the error codes are, rather than adding a field to all
/// thirty-five entries for something only the correctness tests consult.
pub fn anomaly_stream(test: &Test) -> Anomaly {
    match test.id {
        "h-missing-settings"
        | "h-control-frame-unexpected"
        | "h-second-control-stream"
        | "h-max-push-id"
        | "h-cancel-push-unsolicited"
        | "h-priority-update"
        | "h-extended-connect"
        | "h-datagram-setting-invalid"
        | "h-goaway-increasing"
        | "h-goaway"
        | "h-grease-settings"
        | "h-duplicate-setting" => Anomaly::ControlStream,

        // Server-opened unidirectional streams that are *not* the control
        // stream: the QPACK encoder stream, a push stream, a reserved type.
        //
        // These share the control stream's problem -- nothing obliges a client
        // to read a unidirectional stream on any schedule -- and for a year
        // that was the only thing about them that mattered, so they were filed
        // under `ControlStream` and the distinction cost nothing.
        //
        // It costs something now. The read proof watches credit on the control
        // stream specifically, and credit there says nothing about whether the
        // client read a *different* stream. Reading them as one made the proof
        // conclude that a client which had drained our control stream must
        // also have consumed a push stream it may never have looked at, and
        // three of our own client's cells were failed on exactly that. Same
        // error the proof's own comment warns about one level down, where
        // connection-wide MAX_STREAM_DATA is rejected in favour of per-stream:
        // the signal has to belong to the thing being claimed.
        "h-qpack-encoder-overflow"
        | "h-push-stream-unpromised"
        | "h-qpack-encoder-bad-name-index"
        | "h-reserved-uni-stream" => Anomaly::OtherUniStream,

        "h-grease-frame"
        | "h-settings-on-request-stream"
        | "h-data-before-headers"
        | "h-qpack-huffman"
        | "h-qpack-dynamic-table"
        | "h-qpack-blocked-stream"
        | "h-oversized-field-section"
        | "h-trailers"
        | "h-early-hints"
        | "h-response-stream-reset"
        | "q-zero-rtt-replay"
        | "h-qpack-static-index-invalid"
        // Moved here from the control stream on 2026-09-20: on the control
        // stream §7.2.5 answers H3_FRAME_UNEXPECTED whatever the push ID, so
        // the port was asking a different question from the one graded.
        | "h-push-promise-unsolicited" => Anomaly::ResponseStream,

        _ => Anomaly::Transport,
    }
}

/// One test in the catalogue.
#[derive(Debug, Clone, Serialize)]
pub struct Test {
    /// Stable identifier. Appears in URLs, JSON and the badge, so it must not
    /// change once published.
    pub id: &'static str,
    /// One line naming what the server does.
    pub title: &'static str,
    /// The specification clause, cited precisely enough to look up.
    pub spec: &'static str,
    pub class: Class,
    pub tier: Tier,
    /// How hard the cited clause insists, as it binds the client.
    pub requirement: Requirement,
    /// What a correct client is required to do. Written as the report renders
    /// it, so a FAIL reads as a complete sentence next to the citation.
    pub expectation: &'static str,
    /// Whether the anomaly is actually emitted yet.
    ///
    /// An unbuilt test serves a correct control stream, so a client sails
    /// through it. For an extensibility test that reads as a pass, which is
    /// merely premature — but for a correctness test it reads as "accepted a
    /// violation", which is a false accusation about something we never sent.
    /// The listener records these as inconclusive instead of judging them.
    pub implemented: bool,
    /// Offset from the start of the configured port range.
    ///
    /// Every test owns a port. Selecting by URL path was the original design,
    /// but reading a path means QPACK-decoding the client's request, and the
    /// `h3` crate exposes no way to inject arbitrary frames into a response it
    /// is managing. Owning the whole connection from the first packet is both
    /// simpler and gives total control over SETTINGS, the control stream and
    /// the response stream.
    pub port_offset: Option<u16>,
}

/// How each entry's requirement was checked.
///
/// Recorded because the two are not equally strong, and a reader deciding
/// whether to trust a verdict deserves to know which they are looking at.
///
/// - **RFC text** — the clause was read as published.
/// - **Reference implementation** — RFC 9000 is too large for the fetcher used
///   here to return whole (it truncated around §7 every time, and on one
///   targeted retry returned two contradictory quotes for §12.4). Those clauses
///   were instead verified against the vendored `noq` QUIC implementation,
///   which encodes the requirement in code and comments. Strong, but secondary.
///
/// | Test | Clause | Checked against |
/// |------|--------|-----------------|
/// | `h-*` (the nineteen from RFC 9114/9204) | RFC 9114, RFC 9204 | RFC text |
/// | `q-version-negotiation` | RFC 9000 §6.2 | RFC text |
/// | `q-zero-rtt-reject` | RFC 9001 §4.6.2 | RFC text |
/// | `q-reserved-frame` | RFC 9000 §12.4 | RFC text |
/// | `q-reserved-transport-param` | RFC 9000 §18.1 | RFC text |
/// | `q-stateless-reset` | RFC 9000 §10.3.1 | RFC text |
/// | `q-pmtu-blackhole` | RFC 9000 §14, RFC 8899 | reference implementation |
/// | `q-flow-control` | RFC 9000 §4.1 | RFC text |
/// | `q-ecn` | RFC 9000 §13.4.1 | RFC text |
/// | `q-key-update` | RFC 9001 §6.2 | RFC text |
/// | `q-stream-limit` | RFC 9000 §4.6 | RFC text |
/// | `q-loss-recovery` | RFC 9000 §2.2, §13.3 | RFC text |
/// | `q-connection-migration` | RFC 9000 §9.6 | RFC text |
/// | `q-invalid-transport-param` | RFC 9000 §7.4, §18.2 | RFC text |
/// | `q-zero-rtt-replay` | RFC 8470 §5.2 | RFC text |
/// | `h-priority-update` | RFC 9218 §7.2 | RFC text |
/// | `h-extended-connect` | RFC 9220 §3, RFC 8441 §3 | RFC text |
/// | `h-push-promise-unsolicited` | RFC 9114 §7.2.5 | RFC text |
/// | `h-datagram-setting-invalid` | RFC 9297 §2.1.1 | RFC text |
/// | `h-qpack-encoder-overflow` | RFC 9204 §4.3.1, §6 | RFC text |
/// | `h-goaway-increasing` | RFC 9114 §5.2 | RFC text |
/// | `h-push-stream-unpromised` | RFC 9114 §6.2.2 | RFC text |
/// | `h-qpack-static-index-invalid` | RFC 9204 §3.1 | RFC text |
/// | `q-packet-reordering` | RFC 9000 §2.2 | RFC text |
/// | `h-qpack-encoder-bad-name-index` | RFC 9204 §3.1 | RFC text |
/// | `q-ecn-congestion` | RFC 9000 §13.4.1 | RFC text |
/// | `q-key-update-repeated` | RFC 9001 §6.1 | RFC text |
/// | `q-max-streams-credit` | RFC 9000 §4.6 | RFC text |
///
/// The five entries added on 2026-09-01 close the areas the site had been listing
/// as untouched, and three of them changed shape while being read.
/// `q-invalid-transport-param` was drafted around a *duplicate* parameter until
/// §7.4 turned out to make duplicates only a SHOULD while an invalid *value* is a
/// MUST — so the port sends one parameter, once, out of range.
/// `q-connection-migration` is a SHOULD for the same reason and is scored as
/// discretionary. `h-extended-connect` asks for a value RFC 8441 forbids, and
/// neither it nor RFC 9220 names a receiver behaviour, so both answers pass.
///
/// The eight entries added on 2026-08-31 were each read as published before the
/// entry was written, and two of them changed shape as a result.
/// `h-response-stream-reset` was drafted as a resilience test — keep the
/// connection through a stream reset — until §8 turned out to say an endpoint
/// "MAY choose to treat a stream error as a connection error under certain
/// circumstances", which makes closing conformant and would have failed clients
/// for a legal choice. `q-stream-limit` separates a MUST from a SHOULD in the
/// same clause the way `q-flow-control` does.
///
/// `q-ecn`'s requirement level turned out to be *conditional*, which changed how
/// it is scored. §13.4.1 says an endpoint "MUST provide feedback about ECN
/// markings it receives, if these are accessible", and the paragraph above it
/// explicitly permits an endpoint with no access to the ECN field to report
/// nothing. Access is a property of the peer's platform and of the path, and
/// neither is observable from here — a network that strips the codepoint in
/// transit is indistinguishable, at this end, from a client that declines to
/// report. So counts coming back score a pass and silence is inconclusive.
/// Scoring silence as a failure would have blamed clients for their networks.
///
/// Every test, in report order.
///
/// Three of these — `q-retry`, `q-ack-frequency` and `h-early-hints` — already
/// happen on the production edge for every visitor. They are included because a
/// conformance report that silently omits the things we already do would
/// understate what a client is actually being asked to handle here.
pub const CATALOG: &[Test] = &[
    // ── Tier B: QUIC layer ────────────────────────────────────────────────
    Test {
        id: "q-version-negotiation",
        title: "Version Negotiation offering a reserved version alongside v1",
        spec: "RFC 9000 §6",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Abandon the connection attempt, or retry with a version both ends \
                      support. §6.2 requires a client that supports only one version to \
                      abandon it rather than persist.",
        implemented: true,
        port_offset: Some(0),
    },
    Test {
        id: "q-retry",
        title: "Retry packet for source-address validation",
        spec: "RFC 9000 §8.1.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Echo the Retry token in a second Initial packet and complete the handshake.",
        implemented: true,
        port_offset: Some(1),
    },
    Test {
        id: "q-reserved-transport-param",
        title: "Reserved transport parameter (31·N+27)",
        spec: "RFC 9000 §18.1",
        class: Class::Extensibility,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Ignore the unknown parameter and complete the handshake normally.",
        implemented: true,
        port_offset: Some(2),
    },
    Test {
        id: "q-reserved-frame",
        title: "Unknown frame type in a 1-RTT packet",
        spec: "RFC 9000 §12.4",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Close the connection with FRAME_ENCODING_ERROR. Unlike HTTP/3, QUIC \
                      reserves no ignorable frame types — §12.4 makes an unknown frame a \
                      connection error, so ignoring it is the failure here.",
        implemented: true,
        port_offset: Some(3),
    },
    Test {
        id: "q-cid-rotation",
        title: "NEW_CONNECTION_ID followed by RETIRE_CONNECTION_ID",
        spec: "RFC 9000 §5.1",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Adopt the new connection ID, retire the old one, and stay connected.",
        implemented: true,
        port_offset: Some(4),
    },
    Test {
        id: "q-stateless-reset",
        title: "Stateless reset",
        spec: "RFC 9000 §10.3",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Recognise the token in the last 16 bytes of the datagram, enter the \
                      draining period, and send no further packets on the connection. The \
                      packet cannot be authenticated, so there is nothing to reply with \
                      and nothing to report to the peer — continuing to send is the \
                      failure §10.3.1 names.",
        implemented: true,
        port_offset: Some(5),
    },
    Test {
        id: "q-flow-control",
        title: "Deliberately tight MAX_DATA and MAX_STREAM_DATA",
        spec: "RFC 9000 §4",
        class: Class::Discretionary,
        requirement: Requirement::Should,
        tier: Tier::Quic,
        expectation: "Respect the limit. Announcing the stall with DATA_BLOCKED or \
                      STREAM_DATA_BLOCKED is a SHOULD in §4.1, not a MUST, so a client that \
                      stays silent is still conformant.",
        implemented: true,
        port_offset: Some(6),
    },
    Test {
        id: "q-ack-frequency",
        title: "ACK Frequency extension offered",
        spec: "draft-ietf-quic-ack-frequency",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Quic,
        expectation: "Negotiate the extension, or ignore it. Either is correct; failing is not.",
        implemented: true,
        port_offset: Some(7),
    },
    Test {
        id: "q-ecn",
        title: "Packets marked ECT(0)",
        spec: "RFC 9000 §13.4",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Echo the ECN counts back in ACK frames carrying an ECN section \
                      (type 0x03). §13.4.1 makes this a conditional requirement — an \
                      endpoint MUST report the markings it receives \"if these are \
                      accessible\", and explicitly permits an endpoint with no access to \
                      the ECN field to report nothing. So counts coming back is a pass, \
                      and silence is never a failure.\n\nSilence is read against the \
                      path rather than left unresolved. Both directions cross the same \
                      path: a client whose own datagrams reach this endpoint still \
                      carrying ECT has shown the codepoint survives and that its stack \
                      sets it, and so has a port where any peer has ever echoed the \
                      markings sent from it. Either makes the silence the client's own \
                      and the result `unsupported` -- a property of the client, which \
                      §13.4.1 expressly allows. Only where nothing has shown the \
                      codepoint surviving is the run inconclusive, because only there \
                      is a stripped path still a live possibility.",
        implemented: true,
        port_offset: Some(8),
    },
    Test {
        id: "q-pmtu-blackhole",
        title: "Path MTU black hole above a threshold",
        spec: "RFC 9000 §14, RFC 8899",
        class: Class::Resilience,
        requirement: Requirement::Should,
        tier: Tier::Quic,
        expectation: "Detect the black hole, probe down to a working size, and keep the \
                      connection. Path-MTU discovery is driven past the limit on this port, \
                      so it engages on every connection.",
        implemented: true,
        port_offset: Some(9),
    },
    Test {
        id: "q-path-challenge",
        title: "Server-initiated PATH_CHALLENGE",
        spec: "RFC 9000 §8.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Reply with PATH_RESPONSE carrying the identical 8-byte payload.",
        implemented: true,
        port_offset: Some(10),
    },
    Test {
        id: "q-zero-rtt-reject",
        title: "0-RTT rejected after the client sends early data",
        spec: "RFC 9001 §4.6.2",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Reset the state of every stream, including application state \
                      bound to them. Section 4.6.2 requires the reset because a rejected \
                      0-RTT means every assumed connection characteristic may have been \
                      wrong. It does not require retransmission, which is the \
                      application concern, not QUIC's.\n\nThis port issues tickets \
                      that advertise early data and then declines every offer, so a \
                      resuming client sends 0-RTT and always has it refused. The handshake \
                      itself completes normally.",
        implemented: true,
        port_offset: Some(11),
    },
    Test {
        id: "q-multipath",
        title: "A second path offered mid-connection",
        spec: "draft-ietf-quic-multipath",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Quic,
        expectation: "Use the additional path, or decline it cleanly. Do not abort the connection.",
        implemented: true,
        port_offset: Some(12),
    },
    Test {
        id: "q-key-update",
        title: "Spontaneous 1-RTT key update",
        spec: "RFC 9001 §6.2",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Update to the next key phase and carry on. Once a packet protected \
                      with the next phase is processed, §6.2 is a MUST — \"The endpoint \
                      MUST update its send keys to the corresponding key phase in \
                      response\" — so the response written after the update has to be \
                      read with the new keys and the request completed.",
        implemented: true,
        port_offset: Some(27),
    },
    Test {
        id: "q-stream-limit",
        title: "Stream limits set to the minimum a request needs",
        spec: "RFC 9000 §4.6",
        class: Class::Discretionary,
        requirement: Requirement::MustNot,
        tier: Tier::Quic,
        expectation: "Stay inside the advertised limits. Respecting them is a MUST — \
                      §4.6 says \"Endpoints MUST NOT exceed the limit set by their \
                      peer\" — but announcing the stall with STREAMS_BLOCKED is only a \
                      SHOULD, so a client that stays silent is still conformant.",
        implemented: true,
        port_offset: Some(28),
    },
    Test {
        id: "q-loss-recovery",
        title: "One datagram in twelve dropped once the path is established",
        spec: "RFC 9000 §2.2, §13.3",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Reassemble the stream and deliver the whole body. §2.2 requires an \
                      endpoint to buffer data received out of order and deliver it as an \
                      ordered byte stream, and §13.3 has the lost data sent again in new \
                      STREAM frames — so a response full of gaps must still arrive \
                      complete and in order.",
        implemented: true,
        port_offset: Some(29),
    },
    Test {
        id: "q-connection-migration",
        title: "Datagrams arriving from a second server address",
        spec: "RFC 9000 §9.6",
        class: Class::Discretionary,
        requirement: Requirement::Should,
        tier: Tier::Quic,
        expectation: "Keep using the address you are already talking to. §9.6 says a \
                      client \"SHOULD ignore packets received from a server address other \
                      than the one it is currently using for sending packets\" — a SHOULD, \
                      so quietly discarding them and objecting are both conformant. \
                      Following the new address is not: nothing is listening there, and a \
                      server may only move a client to an address it advertised as its \
                      preferred one.",
        implemented: true,
        port_offset: Some(35),
    },
    Test {
        id: "q-invalid-transport-param",
        title: "Transport parameter carrying a value the specification forbids",
        spec: "RFC 9000 §7.4, §18.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Close the connection with TRANSPORT_PARAMETER_ERROR. §18.2 makes an \
                      ack_delay_exponent above 20 invalid, and §7.4 is a MUST: \"An \
                      endpoint MUST treat receipt of a transport parameter with an invalid \
                      value as a connection error of type TRANSPORT_PARAMETER_ERROR.\"\n\n\
                      Distinct from a *duplicate* parameter, which the same clause makes \
                      only a SHOULD — this port sends one parameter, once, with a value \
                      outside its permitted range.\n\nThe parameter travels in the \
                      handshake, so every client that connects here reads it. Only a \
                      client that answers with a CONNECTION_CLOSE this endpoint can read \
                      is scored: one that simply abandons the handshake is recorded as \
                      inconclusive, because a close that was sent and lost looks exactly \
                      like one that was never sent.",
        implemented: true,
        port_offset: Some(36),
    },
    Test {
        id: "q-zero-rtt-replay",
        title: "425 (Too Early) in answer to a request sent as early data",
        spec: "RFC 8470 §5.2",
        class: Class::Discretionary,
        requirement: Requirement::Should,
        tier: Tier::Quic,
        expectation: "Handle being told the request arrived too early. §5.2 says a user \
                      agent \"SHOULD retry automatically, but any retries MUST NOT be sent \
                      in early data\" — so retrying on the 1-RTT keys and handing the 425 \
                      back to the caller are both conformant, and the report says which \
                      happened. Falling over is not one of the options.\n\nThis is the \
                      only port that *accepts* early data instead of refusing it, which is \
                      what makes the 425 exchange possible at all. What it does not check \
                      is §4's rule that unsafe methods must never be sent in early data: \
                      reading the method would mean QPACK-decoding the request, which this \
                      suite deliberately never does.\n\nReaching it needs a session \
                      ticket from an earlier connection to this same port, so a client that \
                      connects once has none.",
        implemented: true,
        port_offset: Some(37),
    },
    Test {
        id: "q-ecn-congestion",
        title: "Path marking packets CE, not just ECT(0)",
        spec: "RFC 9000 §13.4",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Report the CE count back in the ECN section of an ACK. §13.4.1 makes \
                      this the same conditional requirement as reporting ECT(0) — an \
                      endpoint MUST provide feedback about the markings it receives \"if \
                      these are accessible\" — and CE is the marking that matters, since \
                      it is how a path says it is congested.\n\nDistinct from the ECT(0) \
                      test on the neighbouring port: that one asks whether a client reports \
                      markings at all, and this asks whether it distinguishes the one that \
                      means something. A client that echoes ECT(0) counts faithfully and \
                      never reports a CE has a congestion signal it cannot see.\n\n\
                      Silence is never a failure, for the same reason, and it is read \
                      against the path in the same way: where this client's own datagrams \
                      arrived carrying ECT, or where any peer has echoed the markings this \
                      port sent, the codepoint demonstrably survives and the silence is \
                      the client's own -- `unsupported`, which §13.4.1 expressly allows. \
                      Only where nothing has shown the codepoint surviving is a stripped \
                      path still possible, and only there is the run inconclusive.",
        implemented: true,
        port_offset: Some(48),
    },
    Test {
        id: "q-key-update-repeated",
        title: "A second key update after the first is acknowledged",
        spec: "RFC 9001 §6.1, §6.5",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Follow both updates and carry on. §6.1 lets an endpoint update again \
                      once the previous phase has been acknowledged, so a long-lived \
                      connection changes keys repeatedly and a client has to track the \
                      phase rather than assume one change.\n\nDistinct from the single \
                      update on the neighbouring port. An implementation that hardcodes the \
                      first transition — treating key phase as a one-way flag rather than a \
                      bit that alternates — passes that test and fails here, which is \
                      precisely the bug worth finding.",
        implemented: true,
        port_offset: Some(49),
    },
    Test {
        id: "q-max-streams-credit",
        title: "No stream credit at first, then MAX_STREAMS mid-connection",
        spec: "RFC 9000 §4.6",
        class: Class::Discretionary,
        requirement: Requirement::MustNot,
        tier: Tier::Quic,
        expectation: "Wait for the credit, then open the request. This port grants no \
                      bidirectional streams in its transport parameters and issues \
                      MAX_STREAMS a moment later. §4.6 is unambiguous that a client may not \
                      jump the gun — \"Endpoints MUST NOT exceed the limit set by their \
                      peer\" — and announcing the wait with STREAMS_BLOCKED is a SHOULD, so \
                      a client that waits quietly is equally conformant.\n\nGiving up \
                      rather than waiting is not scored as a failure: nothing obliges a \
                      one-shot client to sit on a connection it cannot use yet, and the \
                      report says which it did.",
        implemented: true,
        port_offset: Some(50),
    },
    // ── Tier A: HTTP/3 layer ──────────────────────────────────────────────
    Test {
        id: "h-grease-settings",
        title: "Reserved SETTINGS identifier (0x1f·N+0x21)",
        spec: "RFC 9114 §7.2.4.1",
        class: Class::Extensibility,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Ignore the unknown setting and complete the request.",
        implemented: true,
        port_offset: Some(13),
    },
    Test {
        id: "h-grease-frame",
        title: "Reserved frame type on the response stream",
        spec: "RFC 9114 §7.2.8",
        class: Class::Extensibility,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Skip the frame using its length and read the response that follows.",
        implemented: true,
        port_offset: Some(14),
    },
    Test {
        id: "h-reserved-uni-stream",
        title: "Unidirectional stream with a reserved stream type",
        spec: "RFC 9114 §6.2.3",
        class: Class::Extensibility,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Abort reading the stream or discard it — §6.2.3 permits either. \
                      What it forbids is treating it as meaningful, or as fatal to the \
                      connection.",
        implemented: true,
        port_offset: Some(15),
    },
    Test {
        id: "h-duplicate-setting",
        title: "SETTINGS containing the same identifier twice",
        spec: "RFC 9114 §7.2.4",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Http3,
        expectation: "Either reject with H3_SETTINGS_ERROR or ignore the repeat — the \
                      specification says a receiver MAY treat this as an error, so both \
                      are conformant.",
        implemented: true,
        port_offset: Some(16),
    },
    Test {
        id: "h-control-frame-unexpected",
        title: "A DATA frame on the control stream",
        spec: "RFC 9114 §7.2.1",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_FRAME_UNEXPECTED.",
        implemented: true,
        port_offset: Some(17),
    },
    Test {
        id: "h-missing-settings",
        title: "Control stream whose first frame is not SETTINGS",
        spec: "RFC 9114 §6.2.1",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_MISSING_SETTINGS.",
        implemented: true,
        port_offset: Some(18),
    },
    Test {
        id: "h-second-control-stream",
        title: "A second control stream opened by the server",
        spec: "RFC 9114 §6.2.1",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_STREAM_CREATION_ERROR.",
        implemented: true,
        port_offset: Some(19),
    },
    Test {
        id: "h-qpack-dynamic-table",
        title: "Field lines referencing dynamic table insertions",
        spec: "RFC 9204 §4.3.3, §4.5.2",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Apply the encoder-stream insertions and decode the headers correctly.",
        implemented: true,
        port_offset: Some(20),
    },
    Test {
        id: "h-qpack-huffman",
        title: "Huffman-coded field lines with maximal padding",
        spec: "RFC 9204 §4.1.2, RFC 7541 §5.2",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Decode without error. Padding of up to 7 bits is legal, not corruption.",
        implemented: true,
        port_offset: Some(21),
    },
    Test {
        id: "h-oversized-field-section",
        title: "Field section larger than the client's advertised maximum",
        spec: "RFC 9114 §4.2.2",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Handle it as an error against that one request, not the whole connection.",
        implemented: true,
        port_offset: Some(22),
    },
    Test {
        id: "h-trailers",
        title: "Trailing field section after the body",
        spec: "RFC 9114 §4.1",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Deliver the trailers to the application after the body completes.",
        implemented: true,
        port_offset: Some(23),
    },
    Test {
        id: "h-early-hints",
        title: "103 Early Hints before the final response",
        spec: "RFC 9110 §15.2, RFC 8297",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Treat 103 as informational and keep reading for the final response. \
                      RFC 9110 §15.2 makes this a MUST: a client \"MUST be able to parse one \
                      or more 1xx responses received prior to a final response, even if the \
                      client does not expect one\". Ignoring the hints is fine — a user agent \
                      MAY do that — but closing the connection is not.",
        implemented: true,
        port_offset: Some(24),
    },
    Test {
        id: "h-goaway",
        title: "GOAWAY sent mid-connection",
        spec: "RFC 9114 §5.2",
        class: Class::Resilience,
        requirement: Requirement::Should,
        tier: Tier::Http3,
        expectation:
            "Stop opening requests, finish those in flight, and retry idempotent ones elsewhere. \
             The GOAWAY is written once the client's request is running and names the stream \
             after it, so §5.2 puts that request inside the range the server promises to \
             process: finishing it is the behaviour under test. Sent before the request \
             instead, the correct answer would be to close and reconnect, and the test would \
             be measuring a race rather than recovery.",
        implemented: true,
        port_offset: Some(25),
    },
    Test {
        id: "h-max-push-id",
        title: "MAX_PUSH_ID sent by the server",
        spec: "RFC 9114 §7.2.7",
        class: Class::Correctness,
        requirement: Requirement::MustNot,
        tier: Tier::Http3,
        expectation: "Reject with H3_FRAME_UNEXPECTED. MAX_PUSH_ID travels client to \
                      server only, so a server sending one is using a frame in a \
                      direction the specification does not allow.",
        implemented: true,
        port_offset: Some(26),
    },
    Test {
        id: "h-settings-on-request-stream",
        title: "SETTINGS frame on a request stream",
        spec: "RFC 9114 §7.2.4",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_FRAME_UNEXPECTED. SETTINGS belongs to \
                      the control stream alone: §7.2.4 says that if an endpoint receives \
                      one on a different stream it \"MUST respond with a connection error \
                      of type H3_FRAME_UNEXPECTED\".",
        implemented: true,
        port_offset: Some(30),
    },
    Test {
        id: "h-data-before-headers",
        title: "DATA frame before any HEADERS on the response stream",
        spec: "RFC 9114 §4.1",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_FRAME_UNEXPECTED. A response begins \
                      with a field section, and §4.1 makes \"receipt of an invalid \
                      sequence of frames\" a connection error of that type — a body \
                      arriving before the headers that describe it is exactly that.",
        implemented: true,
        port_offset: Some(31),
    },
    Test {
        id: "h-cancel-push-unsolicited",
        title: "CANCEL_PUSH for a push ID that was never promised",
        spec: "RFC 9114 §7.2.3",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_ID_ERROR. No MAX_PUSH_ID was granted, \
                      so every push ID is greater than currently allowed, and §7.2.3 \
                      requires a CANCEL_PUSH referencing one to be treated as a \
                      connection error of that type.",
        implemented: true,
        port_offset: Some(32),
    },
    Test {
        id: "h-qpack-blocked-stream",
        title: "Field section that blocks until the encoder stream catches up",
        spec: "RFC 9204 §2.1.2, §2.2.1",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Hold the field section, apply the insertions when they arrive on \
                      the encoder stream, and complete the request. §2.2.1 makes a \
                      section whose Required Insert Count exceeds the decoder's Insert \
                      Count a blocked stream — something to be waited on, not an error.\n\n\
                      Only run when the client advertised both a table capacity and at \
                      least one blocked stream; §2.1.2 forbids the encoder from blocking \
                      more streams than the decoder promised to support, so a client that \
                      permits none cannot be tested on this.",
        implemented: true,
        port_offset: Some(33),
    },
    Test {
        id: "h-response-stream-reset",
        title: "Response stream reset mid-body with H3_REQUEST_CANCELLED",
        spec: "RFC 9114 §8, §4.1",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Http3,
        expectation: "Abandon the partial response — §4.1 says a response cancelled after \
                      a partial delivery \"SHOULD NOT be used\". Whether the connection \
                      survives is the client's to choose: §8 lets an endpoint \"treat a \
                      stream error as a connection error under certain circumstances\", \
                      so keeping the connection and closing it are both conformant. \
                      Stalling is the one wrong answer.",
        implemented: true,
        port_offset: Some(34),
    },
    Test {
        id: "h-priority-update",
        title: "PRIORITY_UPDATE sent by the server",
        spec: "RFC 9218 §7.2",
        class: Class::Discretionary,
        requirement: Requirement::MustNot,
        tier: Tier::Http3,
        expectation: "Reject it with H3_FRAME_UNEXPECTED, or ignore it — which is \
                      conformant depends on whether you implement extensible priorities \
                      at all, and that is not observable from here.\n\nA client that \
                      does implement RFC 9218 is bound by §7.2: servers \"MUST NOT send \
                      PRIORITY_UPDATE frames of either type\", and a client receiving one \
                      MUST treat it as a connection error of that type. A client that does \
                      not implement it sees frame type 0xf0700 as simply unknown, and RFC \
                      9114 §9 requires unknown frame types to be ignored — so ignoring it \
                      is equally correct, for a different reason.\n\nScoring this as a \
                      failure either way would accuse one of those two clients of a \
                      violation it did not commit, so the report says which answer was \
                      given rather than grading it.",
        implemented: true,
        port_offset: Some(38),
    },
    Test {
        id: "h-extended-connect",
        title: "SETTINGS_ENABLE_CONNECT_PROTOCOL with a value outside 0 and 1",
        spec: "RFC 9220 §3, RFC 8441 §3",
        class: Class::Discretionary,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Reject it or ignore it, but keep working. RFC 8441 §3 says the \
                      value \"MUST be 0 or 1\" and RFC 9220 carries that into HTTP/3 \
                      unchanged — yet neither names a behaviour for a receiver that sees \
                      anything else, so both answers are conformant and stalling is not. \
                      The setting is how a client learns Extended CONNECT is available, so \
                      a WebTransport-capable client has real parsing behind it.",
        implemented: true,
        port_offset: Some(39),
    },
    Test {
        id: "h-push-promise-unsolicited",
        title: "PUSH_PROMISE for a push the client never allowed",
        spec: "RFC 9114 §7.2.5, §4.6",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_ID_ERROR. §7.2.7 leaves the maximum \
                      push ID unset until the client sends MAX_PUSH_ID, so a server \
                      \"cannot push until it receives a MAX_PUSH_ID frame\" and every push \
                      ID is larger than the client has advertised.\n\nWHERE the frame goes \
                      is the whole test. It was written to the control stream, where \
                      §7.2.5 gives a different and more specific answer -- a PUSH_PROMISE \
                      there is H3_FRAME_UNEXPECTED whatever its push ID -- so the port \
                      asked one question and this entry graded the other. Seven \
                      independent implementations answered 0x105 correctly and were \
                      failed for it, until 2026-09-20. It now arrives on the response \
                      stream, where the frame is legal and its push ID is the only thing \
                      left to object to. §7.2.5 is explicit \
                      about the answer: a client \"MUST treat receipt of a PUSH_PROMISE \
                      frame that contains a larger push ID than the client has advertised \
                      as a connection error of H3_ID_ERROR\".",
        implemented: true,
        port_offset: Some(40),
    },
    Test {
        id: "h-datagram-setting-invalid",
        title: "SETTINGS_H3_DATAGRAM with a value that is neither 0 nor 1",
        spec: "RFC 9297 §2.1.1",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_SETTINGS_ERROR. Unusually for a \
                      setting, RFC 9297 pins down the invalid-value case rather than \
                      leaving it open: the value \"MUST be either 0 or 1\", and if one \
                      \"is received with a value that is neither 0 nor 1, the receiver \
                      MUST terminate the connection with error H3_SETTINGS_ERROR\".\n\n\
                      This is the setting that gates HTTP Datagrams and so WebTransport, \
                      which means a client that implements either has real parsing behind \
                      it rather than an ignored identifier.",
        implemented: true,
        port_offset: Some(41),
    },
    Test {
        id: "h-qpack-encoder-overflow",
        title: "Encoder stream setting a dynamic table capacity above the client's limit",
        spec: "RFC 9204 §4.3.1, §6",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with QPACK_ENCODER_STREAM_ERROR (0x201). §4.3.1 \
                      says the new capacity \"MUST be lower than or equal to the limit\" \
                      the decoder advertised, and that a decoder \"MUST treat a new \
                      dynamic table capacity value that exceeds this limit as a connection \
                      error of type QPACK_ENCODER_STREAM_ERROR\".\n\nUnlike the other \
                      two dynamic-table tests, this one runs against every client, because \
                      the capacity asked for is computed from the one that client \
                      advertised: one byte more, whatever it said. It was a fixed 4096 \
                      until 2026-09-20, which exceeded the zero every client then \
                      advertised and would have exceeded nothing at all for a client that \
                      granted a 4096-byte table.",
        implemented: true,
        port_offset: Some(42),
    },
    Test {
        id: "h-goaway-increasing",
        title: "A second GOAWAY naming a larger identifier than the first",
        spec: "RFC 9114 §5.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_ID_ERROR. §5.2 permits multiple GOAWAY \
                      frames but requires the identifier in each to be no greater than any \
                      previously sent, because the identifier is a promise about what will \
                      still be processed and raising it takes that promise back. \
                      \"Receiving a GOAWAY containing a larger identifier than previously \
                      received MUST be treated as a connection error of type \
                      H3_ID_ERROR.\"",
        implemented: true,
        port_offset: Some(43),
    },
    Test {
        id: "h-push-stream-unpromised",
        title: "Push stream opened for a push nobody allowed",
        spec: "RFC 9114 §6.2.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_ID_ERROR. §6.2.2 does not require the \
                      push to have been promised first — the stream alone is enough: a \
                      client \"MUST treat receipt of a push stream as a connection error \
                      of type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent\", and \
                      no client under test sends one.\n\nDistinct from the PUSH_PROMISE \
                      test, which puts the same violation in a frame on the control \
                      stream. This one opens the push stream itself, which a client has to \
                      recognise by its stream type before any frame inside it is read.",
        implemented: true,
        port_offset: Some(44),
    },
    Test {
        id: "h-qpack-static-index-invalid",
        title: "Field line indexing a static table entry that does not exist",
        spec: "RFC 9204 §3.1, §4.5.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with QPACK_DECOMPRESSION_FAILED (0x200). The \
                      static table has 99 entries, so index 200 refers to nothing, and \
                      §3.1 is explicit: \"When the decoder encounters an invalid static \
                      table index in a field line representation, it MUST treat this as a \
                      connection error of type QPACK_DECOMPRESSION_FAILED.\"\n\nThe \
                      static table needs no permission and never changes size, so unlike \
                      the dynamic-table tests this one applies to every client.",
        implemented: true,
        port_offset: Some(45),
    },
    Test {
        id: "q-packet-reordering",
        title: "Datagrams delivered out of order",
        spec: "RFC 9000 §2.2",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Quic,
        expectation: "Put the stream back in order and deliver the whole body. §2.2 \
                      requires an endpoint to be \"able to deliver stream data to an \
                      application as an ordered byte stream\", and says plainly that doing \
                      so \"requires that an endpoint buffer any data that is received out \
                      of order\".\n\nDistinct from the loss test, which needs \
                      retransmission before the gap can be filled. Nothing is lost here: \
                      every byte arrives, some of it early, and a client that assumes \
                      arrival order is delivery order will produce a corrupt body or stall \
                      waiting for data it already has.",
        implemented: true,
        port_offset: Some(46),
    },
    Test {
        id: "h-qpack-encoder-bad-name-index",
        title: "Encoder instruction naming a static index that does not exist",
        spec: "RFC 9204 §3.1, §4.3.2",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Http3,
        expectation: "Close the connection with QPACK_ENCODER_STREAM_ERROR (0x201). The \
                      same bad index means different things depending on where it arrives, \
                      and §3.1 says both: on a field line it is \
                      QPACK_DECOMPRESSION_FAILED, and \"if this index is received on the \
                      encoder stream, this MUST be treated as a connection error of type \
                      QPACK_ENCODER_STREAM_ERROR\".\n\nPaired deliberately with the \
                      field-line version on the neighbouring port: a client that answers \
                      both with the same code has collapsed a distinction the \
                      specification draws twice in one paragraph.",
        implemented: true,
        port_offset: Some(47),
    },
    // ---------------------------------------------------------------- TLS tier
    //
    // The first fifty-one tests cover QUIC and HTTP/3 and say nothing about the
    // TLS 1.3 handshake underneath them. That is the layer the post-quantum
    // migration is actually happening in, and the layer where client bugs are
    // currently being found in the wild.
    //
    // These ports emit no malformed bytes. Each negotiates exactly one key
    // exchange group, which is a legal configuration and not a violation of
    // anything, and the measurement is what the client does when the group it
    // hoped for is not on offer. That distinction matters for how a failure
    // here should be read: a client that cannot complete one of these has a
    // real interoperability problem, not a tolerance problem.
    Test {
        id: "t-hybrid-only",
        title: "Server negotiates only the post-quantum hybrid X25519MLKEM768",
        spec: "RFC 8446 §4.1.4, draft-ietf-tls-hybrid-design",
        class: Class::Interoperability,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Complete the handshake. A client whose first key share was \
                      classical must recover through HelloRetryRequest, which §4.1.4 \
                      requires it to answer with a second ClientHello carrying a share \
                      for the named group. A client that does not offer the group at all \
                      must abandon the attempt cleanly rather than stall — that is a \
                      correct outcome for a client without post-quantum support.\n\nA \
                      client that cannot negotiate the group at all never establishes a \
                      connection, so the server records no verdict and the result is \
                      `not run` rather than a pass or a failure. On this tier that reads \
                      as \"no post-quantum key exchange\", which is itself the finding: \
                      every other tier reaches `not run` only when the runner skipped \
                      something. curl/ngtcp2 1.11.0 lands here.\n\nThis is the round \
                      trip that breaks first in a real migration, because it is the one \
                      that never happens until a server somewhere stops offering the \
                      classical group.",
        implemented: true,
        port_offset: Some(51),
    },
    Test {
        id: "t-classical-only",
        title: "Server negotiates only classical X25519 against a hybrid offer",
        spec: "RFC 8446 §4.1.1, draft-ietf-tls-hybrid-design §5",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Tls,
        expectation: "Either outcome is conformant and the report says which was taken. \
                      A client that proceeds has chosen availability: the connection is \
                      classically secure and it accepted that. A client that refuses has \
                      chosen a post-quantum floor, which is a policy some deployments \
                      now require and no RFC yet mandates.\n\nNo grade is attached, \
                      because attaching one would invent a requirement. What is worth \
                      knowing is that the answer is a deliberate choice rather than an \
                      accident, and today most clients cannot express it either way.",
        implemented: true,
        port_offset: Some(52),
    },
    Test {
        id: "t-hybrid-large-hello",
        title: "Hybrid key share large enough to split the Initial across packets",
        spec: "RFC 9000 §8.1, §14.1, RFC 9001 §4.4",
        class: Class::Resilience,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Complete the handshake with a ClientHello that does not fit one \
                      QUIC Initial packet. An ML-KEM-768 key share is 1,216 bytes, which \
                      pushes a ClientHello past the 1,200-byte floor RFC 9000 §14.1 sets \
                      for an Initial, so the flight must be spread over more than one \
                      packet and every one of them padded to the full size.\n\nThis is \
                      the concrete reason post-quantum TLS deployments fail in the field, \
                      and it interacts with the §8.1 anti-amplification limit: the server \
                      may not send more than three times what it has received, so a \
                      client that under-pads its Initials can stall the handshake without \
                      either side doing anything invalid.",
        implemented: true,
        port_offset: Some(53),
    },
    Test {
        id: "t-group-not-offered",
        title: "Server selects a key exchange group the client never offered",
        spec: "RFC 8446 §4.1.3, §4.2.8, RFC 9001 §4.8",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Abort with illegal_parameter. §4.1.3 is explicit that if the \
                      selected group was not offered, the client MUST abort — accepting \
                      it would let a server steer a client onto a group it deliberately \
                      excluded.\n\nThe port names secp384r1 in its ServerHello against a \
                      client that offered only the hybrid, and leaves the payload exactly \
                      as generated: the only thing wrong is the name, so a client that \
                      aborts can only be aborting over §4.1.3 and not over a share it \
                      could not parse.\n\nWhat is judged is the abort, not the alert \
                      value. RFC 9001 §4.8 lets a QUIC endpoint replace any alert with a \
                      generic one — handshake_failure in place of illegal_parameter — \
                      expressly so that a client need not say what it objected to, so the \
                      code a client chooses is reported here and not scored. A handshake \
                      that ends without any CONNECTION_CLOSE is inconclusive rather than a \
                      failure: the group was certainly not accepted, but a close that was \
                      never sent cannot be told from one that was lost.",
        implemented: true,
        port_offset: Some(54),
    },
    Test {
        id: "t-corrupt-hybrid-share",
        title: "Hybrid key share with an intact X25519 half and a corrupt ML-KEM half",
        spec: "draft-ietf-tls-hybrid-design §3.2, RFC 8446 §4.1.3",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Fail the handshake. The hybrid secret is the concatenation of both \
                      shares fed through the key schedule, so corrupting either half must \
                      produce a transcript mismatch and a failed Finished \
                      verification.\n\nWhat is being looked for is the failure mode, not \
                      the failure: a client that falls back to the classical half alone \
                      has silently downgraded itself to exactly the security level the \
                      hybrid exists to avoid, and would do so against an attacker who can \
                      corrupt one half at will.\n\nThe server share for X25519MLKEM768 is \
                      the 1,088-byte ML-KEM ciphertext followed by the 32-byte X25519 key. \
                      One bit is flipped early in the ciphertext and the classical tail is \
                      left untouched, so a client that still completes has used the \
                      classical half alone. A single bit rather than a scribble on \
                      purpose: ML-KEM decapsulation never fails, it returns an \
                      implicit-rejection secret, so the handshake has to die at Finished \
                      verification rather than at a decode error — damaging the length or \
                      the structure would test the parser instead.",
        implemented: true,
        port_offset: Some(55),
    },
    Test {
        id: "t-hybrid-share-length",
        title: "Hybrid key share whose length does not match the group named with it",
        spec: "draft-kwiatkowski-tls-ecdhe-mlkem §3.1.2, RFC 8446 §6.2, RFC 9001 §4.8",
        class: Class::Correctness,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Abort rather than proceed. §3.1.2 is explicit: \"For all groups, the \
                      client MUST check if the ciphertext length matches the selected group, \
                      and abort with an illegal_parameter alert if it fails.\"\n\nThe port \
                      sends 1,088 bytes where X25519MLKEM768 fixes the server share at 1,120 \
                      — the ML-KEM ciphertext whole and the 32-byte X25519 tail removed. It \
                      parses cleanly as an opaque vector, so the only thing wrong with it is \
                      its length for the group it is named with.\n\nNeither outcome lets a \
                      client derive our keys, because the shared secret needs both halves. \
                      What separates them is where it notices: a client that checks the \
                      length rejects this at the ServerHello, while one that does not carries \
                      a truncated share into decapsulation and fails later and less \
                      clearly.\n\nWhat is judged is the abort, not the alert value. RFC 9001 \
                      §4.8 lets a QUIC endpoint replace any alert with a generic one, so the \
                      code a client chooses is reported and not scored — and a handshake that \
                      ends with no CONNECTION_CLOSE at all is inconclusive rather than a \
                      failure, because a close that was never sent cannot be told from one \
                      that was lost.",
        implemented: true,
        port_offset: Some(57),
    },
    Test {
        id: "t-cert-compression-pq",
        title: "Post-quantum certificate chain, compressed per RFC 8879",
        spec: "RFC 8879 §4, RFC 8446 §4.4.2",
        class: Class::Discretionary,
        requirement: Requirement::May,
        tier: Tier::Tls,
        expectation: "Decompress and parse an ML-DSA-87 chain, then judge it on its \
                      merits. Nothing here is graded: RFC 8879 is optional, no RFC requires \
                      support for ML-DSA certificates, and §4 expressly lets a receiver cap \
                      the decompressed size and abort. What the port reports is which of \
                      those a client does.\n\nThe chain is deliberately issued by a private \
                      CA nobody trusts, and that is what makes the measurement work rather \
                      than spoiling it. A client that rejects it for its *trust anchor* — \
                      unknown_ca, or bad_certificate — has already decompressed a \
                      certificate message several times the size of a classical one, \
                      parsed ML-DSA-87 structures it may never have seen and got as far \
                      as chain building. That is the whole capability under \
                      test, and the rejection that follows is correct behaviour, not a \
                      failure.\n\nA client that cannot get that far answers differently: \
                      decode_error or a record-size abort says the compressed chain itself \
                      defeated it, which is the outcome the post-quantum migration needs to \
                      know about. Certificate sizes are the half of that migration nobody can \
                      configure their way out of — ML-DSA-87 signatures are 4,627 bytes each \
                      and every chain carries several.",
        implemented: true,
        port_offset: Some(58),
    },
    Test {
        id: "t-grease-group",
        title: "GREASE named group a client must tolerate",
        spec: "RFC 8701 §4, RFC 8446 §4.2.7",
        class: Class::Extensibility,
        requirement: Requirement::Must,
        tier: Tier::Tls,
        expectation: "Ignore the unrecognised group and complete the handshake. RFC 8701 \
                      reserves these values precisely so that an endpoint meeting one \
                      learns to tolerate a future real group sharing the same shape.\n\n\
                      The value goes in the server's supported_groups in \
                      EncryptedExtensions, second in a list of real groups. RFC 8446 §4.2.7 \
                      permits a server to send that list — \"regardless of whether they are \
                      currently supported by the client\" — and requires that a client \
                      \"MUST NOT act upon any information found in supported_groups prior \
                      to successful completion of the handshake\". So the handshake must \
                      complete, and a client that aborts over a codepoint it was told not \
                      to act on has ossified against groups that do not exist yet.\n\n\
                      WHERE the value goes is the whole test, and getting it wrong the \
                      first time is on the record deliberately. It was built by naming a \
                      GREASE value in the ServerHello key_share, which is not an \
                      extensibility test at all: §4.1.3 makes a key_share naming any group \
                      the client did not offer illegal whatever the value is, so every \
                      conformant client correctly answered illegal_parameter — and an \
                      Extensibility test demanding tolerance scored all of them as \
                      failures. neqo caught it on first contact. It also duplicated \
                      t-group-not-offered, which measures that rejection properly.\n\n\
                      The honest version needed an extension rustls had no reason to send, \
                      so the fork's ServerExtensions gained a named_groups field. The port \
                      and the id never moved while it was unimplemented.",
        implemented: true,
        port_offset: Some(56),
    },
];

/// The documents a test cites, in the order they appear.
///
/// Parsed from `spec` rather than stored separately: the citation is written
/// once, and two fields that could disagree about which document a test comes
/// from would eventually do exactly that. A test may cite more than one — the
/// path-MTU test rests on RFC 9000 and RFC 8899 together.
///
/// Not every entry cites an RFC. Two rest on IETF drafts, because the extensions
/// they exercise have not been published as RFCs, and a filter that offered only
/// RFCs would quietly hide them.
pub fn documents(test: &Test) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let bytes = test.spec.as_bytes();
    let mut i = 0usize;
    while let Some(at) = test.spec[i..].find("RFC ") {
        let start = i + at + "RFC ".len();
        let digits: String = bytes[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .map(|b| *b as char)
            .collect();
        i = start + digits.len().max(1);
        if digits.is_empty() {
            continue;
        }
        let name = format!("RFC {digits}");
        if !found.contains(&name) {
            found.push(name);
        }
    }

    if found.is_empty() {
        // A draft, or anything else cited by name. Take it up to the first
        // separator so "draft-ietf-quic-multipath §5" still groups with its
        // siblings.
        let name = test
            .spec
            .split([',', ' '])
            .next()
            .unwrap_or(test.spec)
            .trim();
        if !name.is_empty() {
            found.push(name.to_string());
        }
    }
    found
}

/// Look a test up by its stable id.
/// What establishes that the client had its chance to react.
///
/// Not a timer, and not one event for every assertion. A silence-based
/// failure asks whether a required reaction was absent, and that question is
/// only answerable once the client has had the causal opportunity to produce
/// it. What counts as that opportunity is a property of the clause.
///
/// Measured evidence for why this is per-clause rather than universal: on
/// `h-goaway-increasing`, msquic extends flow-control credit on the control
/// stream carrying the second GOAWAY -- it demonstrably consumed the thing
/// RFC 9114 §5.2 requires it to react to -- and then never completes an HTTP
/// exchange, which is reasonable for a client that has just been told to stop
/// starting requests. Waiting for exchange completion there declared the
/// opportunity unobserved while the read proof in the same cell said the
/// opposite. picoquic, with the same positive read proof, was scored `fail`.
/// The verdicts differed on the definition, not on the evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReactionOpportunity {
    /// The client completed the exchange the anomaly was delivered in.
    ///
    /// For assertions whose required reaction is in-band: a connection error,
    /// a stream reset, a refusal to proceed with the request itself.
    ExchangeCompleted,
    /// The client consumed the stream carrying the anomaly.
    ///
    /// For assertions triggered by *receipt*. RFC 9000 §4.1 has a receiver
    /// extend MAX_STREAM_DATA as its application consumes, so credit on that
    /// stream is the client stating it took delivery. It does not establish
    /// that the HTTP/3 state machine interpreted the frame correctly or
    /// emitted the required error -- that is precisely what the assertion
    /// then evaluates.
    AnomalyStreamRead,
    /// The client learned its early data was rejected.
    ///
    /// RFC 9001 §4.6.2 ties the duty to the rejection, which is delivered in
    /// the handshake and long before any application exchange need exist.
    HandshakeEarlyDataRejected,
    /// The client had to still be present later, because the behaviour under
    /// test happens after the exchange.
    StillPresentAfter(u64),
}

/// What establishes the reaction opportunity for one test.
pub fn reaction_opportunity(test: &Test) -> ReactionOpportunity {
    match test.id {
        // Answered by whatever the peer sends next, which may be nothing
        // until its own idle timer fires.
        "q-stateless-reset" => ReactionOpportunity::StillPresentAfter(11_000),

        // Answered on the protocol's own timer: RFC 9000 §8.2.4 ties
        // PATH_CHALLENGE retransmission to the PTO.
        "q-path-challenge" | "q-connection-migration" | "q-pmtu-blackhole" => {
            ReactionOpportunity::StillPresentAfter(3_000)
        }

        // The duty begins when the client learns of the rejection.
        "q-zero-rtt-reject" => ReactionOpportunity::HandshakeEarlyDataRejected,

        // Triggered by receipt of something written to a server-opened
        // stream, so consumption of that stream is the opportunity.
        _ if matches!(
            anomaly_stream(test),
            Anomaly::ControlStream | Anomaly::OtherUniStream
        ) =>
        {
            ReactionOpportunity::AnomalyStreamRead
        }

        // Everything else is answered in the exchange that carried it.
        _ => ReactionOpportunity::ExchangeCompleted,
    }
}

pub fn find(id: &str) -> Option<&'static Test> {
    CATALOG.iter().find(|t| t.id == id)
}

/// The test served on `port`, given the configured range start.
pub fn by_port(range_start: u16, port: u16) -> Option<&'static Test> {
    let offset = port.checked_sub(range_start)?;
    CATALOG.iter().find(|t| t.port_offset == Some(offset))
}

/// How many ports the catalogue needs. Startup uses this to check the
/// configured range is wide enough rather than silently serving a truncated
/// catalogue.
pub fn required_ports() -> u16 {
    CATALOG
        .iter()
        .filter_map(|t| t.port_offset)
        .max()
        .map_or(0, |m| m + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique() {
        let mut seen = HashSet::new();
        for t in CATALOG {
            assert!(seen.insert(t.id), "duplicate test id: {}", t.id);
        }
    }

    #[test]
    fn every_test_owns_a_distinct_port() {
        let mut seen = HashSet::new();
        for t in CATALOG {
            let off = t.port_offset.expect("every test must own a port");
            assert!(seen.insert(off), "duplicate port offset on {}", t.id);
        }
    }

    #[test]
    fn ports_are_contiguous_from_zero() {
        // A gap would leave a bound port serving nothing, which reads as a
        // network fault to whoever connects to it.
        let mut offsets: Vec<u16> = CATALOG.iter().filter_map(|t| t.port_offset).collect();
        offsets.sort_unstable();
        for (i, off) in offsets.iter().enumerate() {
            assert_eq!(
                *off,
                u16::try_from(i).expect("catalogue is far smaller than u16::MAX"),
                "port offsets must run 0..n with no gaps"
            );
        }
    }

    /// Every port that has ever been published, pinned to its offset.
    ///
    /// A test's port is how a client reaches it, and the catalogue, the CI
    /// driver and every shell example on the site derive it from this offset.
    /// Inserting a new test in the middle of the array would renumber every
    /// port after it, silently pointing existing scripts at a different test —
    /// so new entries take the next free offset and the array order, which is
    /// only report order, stays grouped by layer.
    ///
    /// Add a line here when a test is published. Never edit one.
    #[test]
    fn published_port_offsets_never_change() {
        let pinned: &[(&str, u16)] = &[
            ("q-version-negotiation", 0),
            ("q-retry", 1),
            ("q-reserved-transport-param", 2),
            ("q-reserved-frame", 3),
            ("q-cid-rotation", 4),
            ("q-stateless-reset", 5),
            ("q-flow-control", 6),
            ("q-ack-frequency", 7),
            ("q-ecn", 8),
            ("q-pmtu-blackhole", 9),
            ("q-path-challenge", 10),
            ("q-zero-rtt-reject", 11),
            ("q-multipath", 12),
            ("h-grease-settings", 13),
            ("h-grease-frame", 14),
            ("h-reserved-uni-stream", 15),
            ("h-duplicate-setting", 16),
            ("h-control-frame-unexpected", 17),
            ("h-missing-settings", 18),
            ("h-second-control-stream", 19),
            ("h-qpack-dynamic-table", 20),
            ("h-qpack-huffman", 21),
            ("h-oversized-field-section", 22),
            ("h-trailers", 23),
            ("h-early-hints", 24),
            ("h-goaway", 25),
            ("h-max-push-id", 26),
            ("q-key-update", 27),
            ("q-stream-limit", 28),
            ("q-loss-recovery", 29),
            ("h-settings-on-request-stream", 30),
            ("h-data-before-headers", 31),
            ("h-cancel-push-unsolicited", 32),
            ("h-qpack-blocked-stream", 33),
            ("h-response-stream-reset", 34),
            ("q-connection-migration", 35),
            ("q-invalid-transport-param", 36),
            ("q-zero-rtt-replay", 37),
            ("h-priority-update", 38),
            ("h-extended-connect", 39),
            ("h-push-promise-unsolicited", 40),
            ("h-datagram-setting-invalid", 41),
            ("h-qpack-encoder-overflow", 42),
            ("h-goaway-increasing", 43),
            ("h-push-stream-unpromised", 44),
            ("h-qpack-static-index-invalid", 45),
            ("q-packet-reordering", 46),
            ("h-qpack-encoder-bad-name-index", 47),
            ("q-ecn-congestion", 48),
            ("q-key-update-repeated", 49),
            ("q-max-streams-credit", 50),
            // TLS tier, published 2026-09-17.
            ("t-hybrid-only", 51),
            ("t-classical-only", 52),
            ("t-hybrid-large-hello", 53),
            ("t-group-not-offered", 54),
            ("t-corrupt-hybrid-share", 55),
            ("t-grease-group", 56),
            ("t-hybrid-share-length", 57),
            ("t-cert-compression-pq", 58),
        ];

        for (id, offset) in pinned {
            let t =
                find(id).unwrap_or_else(|| panic!("{id} was published and must not be removed"));
            assert_eq!(
                t.port_offset,
                Some(*offset),
                "{id} was published on offset {offset}; moving it points existing \
                 scripts at a different test"
            );
        }
        assert_eq!(
            CATALOG.len(),
            pinned.len(),
            "a new test must be pinned here once it is published"
        );
    }

    /// Every HTTP/3 test says which stream its anomaly went to.
    ///
    /// The fallback arm is `Transport`, which the verdict model treats as an
    /// anomaly the client had to process to be served — so a missing entry does
    /// not fail loudly, it quietly turns "the client stayed silent" into "the
    /// client accepted a violation". `h-push-stream-unpromised` was added
    /// without one and was published as a failure against a client that had
    /// simply not read the stream.
    #[test]
    fn every_http3_test_declares_where_its_anomaly_is_written() {
        for t in CATALOG {
            if t.tier != Tier::Http3 {
                continue;
            }
            assert_ne!(
                anomaly_stream(t),
                Anomaly::Transport,
                "{} is an HTTP/3 test and must say whether its anomaly is on the control \
                 stream or the response stream; falling through to Transport makes silence \
                 look like acceptance",
                t.id
            );
        }
    }

    #[test]
    fn every_test_names_the_document_it_comes_from() {
        for t in CATALOG {
            let cited = documents(t);
            assert!(
                !cited.is_empty(),
                "{} cites nothing that can be parsed out of {:?}",
                t.id,
                t.spec
            );
        }
        // A test citing two documents keeps both, in order.
        let mtu = find("q-pmtu-blackhole").expect("catalogue entry");
        assert_eq!(documents(mtu), vec!["RFC 9000", "RFC 8899"]);
        // And a repeated citation is not listed twice.
        let reorder = find("q-packet-reordering").expect("catalogue entry");
        assert_eq!(documents(reorder), vec!["RFC 9000"]);
        // Drafts are named too, or the filter would hide the extensions.
        let multipath = find("q-multipath").expect("catalogue entry");
        assert_eq!(documents(multipath), vec!["draft-ietf-quic-multipath"]);
    }

    /// Requirement level and class are independent axes.
    ///
    /// Worth pinning, because it is tempting to assume discretionary means MAY.
    /// It does not: `q-stream-limit` is discretionary and rests on a MUST NOT,
    /// since the prohibition is not what the test can observe — the SHOULD-level
    /// announcement is.
    #[test]
    fn requirement_level_is_not_the_class() {
        let stream_limit = find("q-stream-limit").expect("catalogue entry");
        assert_eq!(stream_limit.class, Class::Discretionary);
        assert_eq!(stream_limit.requirement, Requirement::MustNot);

        let duplicate = find("h-duplicate-setting").expect("catalogue entry");
        assert_eq!(duplicate.class, Class::Discretionary);
        assert_eq!(duplicate.requirement, Requirement::May);

        // Every level is represented, or the filters would have empty buckets.
        for level in [
            Requirement::Must,
            Requirement::MustNot,
            Requirement::Should,
            Requirement::May,
        ] {
            assert!(
                CATALOG.iter().any(|t| t.requirement == level),
                "no test carries {}",
                level.label()
            );
        }
    }

    #[test]
    fn both_layers_are_represented() {
        assert!(CATALOG.iter().any(|t| t.tier == Tier::Quic));
        assert!(CATALOG.iter().any(|t| t.tier == Tier::Http3));
    }

    #[test]
    fn every_test_cites_a_spec() {
        for t in CATALOG {
            assert!(!t.spec.is_empty(), "{} cites no specification", t.id);
            assert!(!t.expectation.is_empty(), "{} states no expectation", t.id);
        }
    }

    #[test]
    fn port_lookup_round_trips() {
        for t in CATALOG {
            let port = 4460 + t.port_offset.unwrap();
            assert_eq!(by_port(4460, port).map(|x| x.id), Some(t.id));
        }
        assert!(by_port(4460, 4459).is_none(), "below the range");
        assert!(
            by_port(4460, 4460 + required_ports()).is_none(),
            "past the catalogue"
        );
    }
}
