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
    /// the specification names. Failing to reject is a bug; rejecting with the
    /// wrong code is a smaller but still real one.
    Correctness,
    /// The client must recover — retry, re-probe, migrate — rather than fail.
    Resilience,
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
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Ignore the unrecognised version, then retry the handshake using QUIC v1.",
        // Not built: Needs the endpoint to reject the client's version, which EndpointConfig::supported_versions cannot express per-connection.
        implemented: false,
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
        // Not built: Needs a reserved parameter injected into noq's transport-parameter encoder.
        implemented: false,
        port_offset: Some(2),
    },
    Test {
        id: "q-reserved-frame",
        title: "Reserved frame type in a 1-RTT packet",
        spec: "RFC 9000 §12.4",
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Ignore the frame. Closing the connection here is a failure, not caution.",
        // Not built: Needs a reserved frame type injected into noq's 1-RTT frame writer.
        implemented: false,
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
        expectation: "Recognise the reset token and close the connection without erroring loudly.",
        // Not built: Needs a reset token emitted for an unknown connection ID, which the public endpoint API does not expose.
        implemented: false,
        port_offset: Some(5),
    },
    Test {
        id: "q-flow-control",
        title: "Deliberately tight MAX_DATA and MAX_STREAM_DATA",
        spec: "RFC 9000 §4",
        class: Class::Correctness,
        tier: Tier::Quic,
        expectation:
            "Respect the limit and announce the stall with DATA_BLOCKED / STREAM_DATA_BLOCKED.",
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
        expectation: "Report the ECN counts back in ACK_ECN frames.",
        // Not built: Needs per-packet ECT(0) marking and the peer's echoed counts, neither surfaced by ConnectionStats in this fork.
        implemented: false,
        port_offset: Some(8),
    },
    Test {
        id: "q-pmtu-blackhole",
        title: "Path MTU black hole above a threshold",
        spec: "RFC 9000 §14",
        class: Class::Resilience,
        tier: Tier::Quic,
        expectation:
            "Detect the black hole, probe down to a working size, and keep the connection.",
        // Not built: Needs the path to silently drop above a threshold, which is a datagram-layer concern rather than a config one.
        implemented: false,
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
        spec: "RFC 9001 §4.6",
        class: Class::Resilience,
        tier: Tier::Quic,
        expectation: "Retransmit the early data in 1-RTT. No application data may be lost.",
        // Not built: Needs a resumed connection whose early data is deliberately refused.
        implemented: false,
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
        expectation: "Ignore the stream. It must not be treated as fatal.",
        implemented: true,
        port_offset: Some(15),
    },
    Test {
        id: "h-duplicate-setting",
        title: "SETTINGS containing the same identifier twice",
        spec: "RFC 9114 §7.2.4.1",
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
        spec: "RFC 9114 §7.2",
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
        spec: "RFC 9204 §4.3",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Apply the encoder-stream insertions and decode the headers correctly.",
        implemented: true,
        port_offset: Some(20),
    },
    Test {
        id: "h-qpack-huffman",
        title: "Huffman-coded field lines with maximal padding",
        spec: "RFC 9204 §4.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Decode without error. Padding of up to 7 bits is legal, not corruption.",
        implemented: true,
        port_offset: Some(21),
    },
    Test {
        id: "h-oversized-field-section",
        title: "Field section larger than the client's advertised maximum",
        spec: "RFC 9114 §4.2.2",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Handle it as an error against that one request, not the whole connection.",
        implemented: true,
        port_offset: Some(22),
    },
    Test {
        id: "h-trailers",
        title: "Trailing field section after the body",
        spec: "RFC 9114 §4.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Deliver the trailers to the application after the body completes.",
        implemented: true,
        port_offset: Some(23),
    },
    Test {
        id: "h-early-hints",
        title: "103 Early Hints before the final response",
        spec: "RFC 8297",
        class: Class::Resilience,
        tier: Tier::Http3,
        expectation: "Treat 103 as informational and keep reading for the final response.",
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
            assert_eq!(*off, i as u16, "port offsets must run 0..n with no gaps");
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
