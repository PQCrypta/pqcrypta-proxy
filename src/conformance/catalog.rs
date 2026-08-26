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
}

impl Class {
    /// Stable lowercase name, used in JSON and in report URLs.
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Extensibility => "extensibility",
            Class::Correctness => "correctness",
            Class::Resilience => "resilience",
        }
    }
}

/// Which tier a test belongs to, which determines how a client selects it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The anomaly rides on a working HTTP/3 exchange, so the client selects it
    /// with a URL path.
    Http3,
    /// The anomaly precedes any request, so it cannot be named in-band. The
    /// client selects it by connecting to a dedicated UDP port.
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
    /// Offset from the start of the configured port range. Tier A tests carry
    /// `None`; Tier B tests each own one port.
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
        port_offset: Some(0),
    },
    Test {
        id: "q-retry",
        title: "Retry packet for source-address validation",
        spec: "RFC 9000 §8.1.2",
        class: Class::Correctness,
        tier: Tier::Quic,
        expectation: "Echo the Retry token in a second Initial packet and complete the handshake.",
        port_offset: Some(1),
    },
    Test {
        id: "q-reserved-transport-param",
        title: "Reserved transport parameter (31·N+27)",
        spec: "RFC 9000 §18.1",
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Ignore the unknown parameter and complete the handshake normally.",
        port_offset: Some(2),
    },
    Test {
        id: "q-reserved-frame",
        title: "Reserved frame type in a 1-RTT packet",
        spec: "RFC 9000 §12.4",
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Ignore the frame. Closing the connection here is a failure, not caution.",
        port_offset: Some(3),
    },
    Test {
        id: "q-cid-rotation",
        title: "NEW_CONNECTION_ID followed by RETIRE_CONNECTION_ID",
        spec: "RFC 9000 §5.1",
        class: Class::Resilience,
        tier: Tier::Quic,
        expectation: "Adopt the new connection ID, retire the old one, and stay connected.",
        port_offset: Some(4),
    },
    Test {
        id: "q-stateless-reset",
        title: "Stateless reset",
        spec: "RFC 9000 §10.3",
        class: Class::Correctness,
        tier: Tier::Quic,
        expectation: "Recognise the reset token and close the connection without erroring loudly.",
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
        port_offset: Some(6),
    },
    Test {
        id: "q-ack-frequency",
        title: "ACK Frequency extension offered",
        spec: "draft-ietf-quic-ack-frequency",
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Negotiate the extension, or ignore it. Either is correct; failing is not.",
        port_offset: Some(7),
    },
    Test {
        id: "q-ecn",
        title: "Packets marked ECT(0)",
        spec: "RFC 9000 §13.4",
        class: Class::Correctness,
        tier: Tier::Quic,
        expectation: "Report the ECN counts back in ACK_ECN frames.",
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
        port_offset: Some(9),
    },
    Test {
        id: "q-path-challenge",
        title: "Server-initiated PATH_CHALLENGE",
        spec: "RFC 9000 §8.2",
        class: Class::Correctness,
        tier: Tier::Quic,
        expectation: "Reply with PATH_RESPONSE carrying the identical 8-byte payload.",
        port_offset: Some(10),
    },
    Test {
        id: "q-zero-rtt-reject",
        title: "0-RTT rejected after the client sends early data",
        spec: "RFC 9001 §4.6",
        class: Class::Resilience,
        tier: Tier::Quic,
        expectation: "Retransmit the early data in 1-RTT. No application data may be lost.",
        port_offset: Some(11),
    },
    Test {
        id: "q-multipath",
        title: "A second path offered mid-connection",
        spec: "draft-ietf-quic-multipath",
        class: Class::Extensibility,
        tier: Tier::Quic,
        expectation: "Use the additional path, or decline it cleanly. Do not abort the connection.",
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
        port_offset: None,
    },
    Test {
        id: "h-grease-frame",
        title: "Reserved frame type on the response stream",
        spec: "RFC 9114 §7.2.8",
        class: Class::Extensibility,
        tier: Tier::Http3,
        expectation: "Skip the frame using its length and read the response that follows.",
        port_offset: None,
    },
    Test {
        id: "h-reserved-uni-stream",
        title: "Unidirectional stream with a reserved stream type",
        spec: "RFC 9114 §6.2.3",
        class: Class::Extensibility,
        tier: Tier::Http3,
        expectation: "Ignore the stream. It must not be treated as fatal.",
        port_offset: None,
    },
    Test {
        id: "h-duplicate-setting",
        title: "SETTINGS containing the same identifier twice",
        spec: "RFC 9114 §7.2.4",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_SETTINGS_ERROR.",
        port_offset: None,
    },
    Test {
        id: "h-control-frame-unexpected",
        title: "A DATA frame on the control stream",
        spec: "RFC 9114 §7.2",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_FRAME_UNEXPECTED.",
        port_offset: None,
    },
    Test {
        id: "h-missing-settings",
        title: "Control stream whose first frame is not SETTINGS",
        spec: "RFC 9114 §6.2.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_MISSING_SETTINGS.",
        port_offset: None,
    },
    Test {
        id: "h-second-control-stream",
        title: "A second control stream opened by the server",
        spec: "RFC 9114 §6.2.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Close the connection with H3_STREAM_CREATION_ERROR.",
        port_offset: None,
    },
    Test {
        id: "h-qpack-dynamic-table",
        title: "Field lines referencing dynamic table insertions",
        spec: "RFC 9204 §4.3",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Apply the encoder-stream insertions and decode the headers correctly.",
        port_offset: None,
    },
    Test {
        id: "h-qpack-huffman",
        title: "Huffman-coded field lines with maximal padding",
        spec: "RFC 9204 §4.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Decode without error. Padding of up to 7 bits is legal, not corruption.",
        port_offset: None,
    },
    Test {
        id: "h-oversized-field-section",
        title: "Field section larger than the client's advertised maximum",
        spec: "RFC 9114 §4.2.2",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Handle it as an error against that one request, not the whole connection.",
        port_offset: None,
    },
    Test {
        id: "h-trailers",
        title: "Trailing field section after the body",
        spec: "RFC 9114 §4.1",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Deliver the trailers to the application after the body completes.",
        port_offset: None,
    },
    Test {
        id: "h-early-hints",
        title: "103 Early Hints before the final response",
        spec: "RFC 8297",
        class: Class::Resilience,
        tier: Tier::Http3,
        expectation: "Treat 103 as informational and keep reading for the final response.",
        port_offset: None,
    },
    Test {
        id: "h-goaway",
        title: "GOAWAY sent mid-connection",
        spec: "RFC 9114 §5.2",
        class: Class::Resilience,
        tier: Tier::Http3,
        expectation:
            "Stop opening requests, finish those in flight, and retry idempotent ones elsewhere.",
        port_offset: None,
    },
    Test {
        id: "h-max-push-id",
        title: "Push attempted with no MAX_PUSH_ID granted",
        spec: "RFC 9114 §7.2.7",
        class: Class::Correctness,
        tier: Tier::Http3,
        expectation: "Reject with H3_ID_ERROR rather than accepting an unsolicited push.",
        port_offset: None,
    },
];

/// Look a test up by its stable id.
pub fn find(id: &str) -> Option<&'static Test> {
    CATALOG.iter().find(|t| t.id == id)
}

/// The Tier B test served on `port`, given the configured range start.
pub fn by_port(range_start: u16, port: u16) -> Option<&'static Test> {
    let offset = port.checked_sub(range_start)?;
    CATALOG
        .iter()
        .find(|t| t.tier == Tier::Quic && t.port_offset == Some(offset))
}

/// How many ports Tier B needs. Startup uses this to check the configured
/// range is wide enough rather than silently serving a truncated catalogue.
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
    fn quic_tests_own_distinct_ports() {
        let mut seen = HashSet::new();
        for t in CATALOG.iter().filter(|t| t.tier == Tier::Quic) {
            let off = t.port_offset.expect("a Tier B test must own a port");
            assert!(seen.insert(off), "duplicate port offset on {}", t.id);
        }
    }

    #[test]
    fn http3_tests_claim_no_port() {
        for t in CATALOG.iter().filter(|t| t.tier == Tier::Http3) {
            assert!(
                t.port_offset.is_none(),
                "{} is Tier A and must not reserve a port",
                t.id
            );
        }
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
        for t in CATALOG.iter().filter(|t| t.tier == Tier::Quic) {
            let port = 4460 + t.port_offset.unwrap();
            assert_eq!(by_port(4460, port).map(|x| x.id), Some(t.id));
        }
        assert!(by_port(4460, 4459).is_none());
    }
}
