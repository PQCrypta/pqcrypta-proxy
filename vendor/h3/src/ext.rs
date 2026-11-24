//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// Its value is a token from the Hypertext Transfer Protocol Upgrade Token
/// Registry (RFC 8441 section 4, RFC 9220 section 3). Every token parses:
/// which ones a server serves is its own decision, answered with a status,
/// where an unknown token used to make the whole request malformed -- so
/// RFC 9220's `websocket` and WebTransport draft 17's `webtransport-h3`
/// never reached the application.
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(PartialEq, Eq, Hash, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport through draft-ietf-webtrans-http3-16
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// WebTransport from draft-ietf-webtrans-http3-17 (section 3.2)
    pub const WEB_TRANSPORT_H3: Protocol = Protocol(ProtocolInner::WebTransportH3);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9220 (RFC 8441's WebSocket bootstrapping, over HTTP/3)
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::WebTransportH3 => "webtransport-h3",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::WebSocket => "websocket",
            ProtocolInner::Other(token) => token,
        }
    }

    /// Whether it asks for a WebTransport session, in any draft's token
    #[inline]
    pub fn is_webtransport(&self) -> bool {
        matches!(
            self.0,
            ProtocolInner::WebTransport | ProtocolInner::WebTransportH3
        )
    }
}

#[derive(PartialEq, Eq, Hash, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    WebTransportH3,
    ConnectUdp,
    WebSocket,
    /// Any other registered or private token
    Other(Box<str>),
}

/// Error when parsing the protocol: a value that is not a token
#[derive(Debug)]
pub struct InvalidProtocol;

/// A token character (RFC 9110 section 5.6.2)
const fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(match s {
            "webtransport" => ProtocolInner::WebTransport,
            "webtransport-h3" => ProtocolInner::WebTransportH3,
            "connect-udp" => ProtocolInner::ConnectUdp,
            "websocket" => ProtocolInner::WebSocket,
            _ if !s.is_empty() && s.bytes().all(is_tchar) => ProtocolInner::Other(s.into()),
            _ => return Err(InvalidProtocol),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every token parses, each known one to itself; a value that is not a
    /// token does not
    #[test]
    fn protocol_tokens() {
        for (s, p) in [
            ("webtransport", Protocol::WEB_TRANSPORT),
            ("webtransport-h3", Protocol::WEB_TRANSPORT_H3),
            ("connect-udp", Protocol::CONNECT_UDP),
            ("websocket", Protocol::WEBSOCKET),
        ] {
            let parsed: Protocol = s.parse().ok().unwrap();
            assert_eq!(parsed, p);
            assert_eq!(parsed.as_str(), s);
        }
        assert!(Protocol::WEB_TRANSPORT.is_webtransport());
        assert!(Protocol::WEB_TRANSPORT_H3.is_webtransport());
        assert!(!Protocol::WEBSOCKET.is_webtransport());
        let other: Protocol = "masque-ip".parse().ok().unwrap();
        assert_eq!(other.as_str(), "masque-ip");
        for bad in ["", "web transport", "ws/1", "caf\u{e9}"] {
            assert!(bad.parse::<Protocol>().is_err(), "{bad:?}");
        }
    }
}
