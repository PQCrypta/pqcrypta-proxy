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
    /// Written to the response stream, which the client must read to be served.
    ResponseStream,
    /// Below HTTP/3 entirely: transport parameters, frames, the path itself.
    Transport,
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
        | "h-goaway"
        | "h-grease-settings"
        | "h-duplicate-setting"
        | "h-reserved-uni-stream" => Anomaly::ControlStream,

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
        | "q-zero-rtt-replay" => Anomaly::ResponseStream,

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
        tier: Tier::Quic,
        expectation: "Echo the ECN counts back in ACK frames carrying an ECN section \
                      (type 0x03). §13.4.1 makes this a conditional requirement — an \
                      endpoint MUST report the markings it receives \"if these are \
                      accessible\", and explicitly permits an endpoint with no access to \
                      the ECN field to report nothing. So counts coming back is a pass, \
                      and silence is inconclusive rather than a failure: it cannot be \
                      told apart from a path that stripped the codepoint in transit.",
        implemented: true,
        port_offset: Some(8),
    },
    Test {
        id: "q-pmtu-blackhole",
        title: "Path MTU black hole above a threshold",
        spec: "RFC 9000 §14, RFC 8899",
        class: Class::Resilience,
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
    // ── Tier A: HTTP/3 layer ──────────────────────────────────────────────
    Test {
        id: "h-grease-settings",
        title: "Reserved SETTINGS identifier (0x1f·N+0x21)",
        spec: "RFC 9114 §7.2.4.1",
        class: Class::Extensibility,
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
        tier: Tier::Http3,
        expectation:
            "Stop opening requests, finish those in flight, and retry idempotent ones elsewhere.",
        implemented: true,
        port_offset: Some(25),
    },
    Test {
        id: "h-max-push-id",
        title: "MAX_PUSH_ID sent by the server",
        spec: "RFC 9114 §7.2.7",
        class: Class::Correctness,
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
];

/// Look a test up by its stable id.
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
