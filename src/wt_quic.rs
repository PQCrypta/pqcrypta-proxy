//! WebTransport over QUIC: a session that is a whole QUIC connection
//! (draft-vvv-webtransport-quic-02, ALPN `wq-vvv-01`).
//!
//! The QUIC listener serves it beside HTTP/3, DNS over QUIC and MOQT on every
//! port, chosen by ALPN (`server.webtransport_over_quic`). There is no HTTP
//! request: once the handshake completes the client sends a *client
//! indication* on stream 2, its first unidirectional stream, and ends it with
//! a FIN (section 3.2). The indication is a list of fields, each a 16-bit key,
//! a 16-bit length and that many bytes of value, 65,535 bytes at most in all;
//! `Origin` (0x0000) and `Path` (0x0001) are the two the draft defines, the
//! server ignores any other key, and a key that appears twice closes the
//! connection. The server reads nothing else until the indication is in, and
//! the host is the TLS server name (section 3.2: no authority is sent).
//!
//! From there the session's streams are the connection's QUIC streams and
//! its datagrams the connection's DATAGRAM frames (RFC 9221), carried as they
//! are, with no stream header or session prefix (sections 4 and 5): a
//! [`QuicSession`] is a [`WtSession`] whose every operation is the QUIC one,
//! so the speed test, the telemetry wall and a route's backend serve it as
//! they serve a session over HTTP/3 (webtransport_server.rs). A stream reset
//! or STOP_SENDING carries the application's code as the QUIC error code
//! itself, and the session ends with the connection (section 8).
//!
//! The draft defines no error codes. A session this server will not serve is
//! closed with a CONNECTION_CLOSE whose application error code is the HTTP
//! status the HTTP/3 entrance answers the same refusal with (400 for a
//! malformed indication, 403, 404, 421, 429 and the route gate's own), its
//! reason the refusal's short text, so either entrance reads the same.

use bytes::Bytes;
use std::future::Future;
use std::time::Duration;

use crate::wt_session::{WtClosed, WtSession};

/// The ALPN token (draft-vvv-webtransport-quic-02 section 9.1)
pub const ALPN: &[u8] = b"wq-vvv-01";

/// The largest client indication (section 3.2)
pub const INDICATION_MAX: usize = 65_535;

/// The `Origin` field's key (section 3.2.1)
pub const KEY_ORIGIN: u16 = 0x0000;

/// The `Path` field's key (section 3.2.2)
pub const KEY_PATH: u16 = 0x0001;

/// The application error code of a session's ordinary end: the server's
/// handler finished with it
pub const CLOSE_DONE: u32 = 0;

/// A client indication, as section 3.2 has it
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIndication {
    /// The serialized origin of the page that opened the session; none from
    /// a client that is not a browser
    pub origin: Option<String>,
    /// The path and query the session is for, `/` at least
    pub path: String,
}

/// Why a client indication cannot be served
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndicationError {
    /// A field's header or value runs past the end
    Truncated,
    /// A key used more than once (section 3.2: fields are unique)
    Duplicate(u16),
    /// No `Path` field (section 3.2.2: the user agent sends one)
    NoPath,
    /// A `Path` that is not an absolute path (and query), or `Origin` or
    /// `Path` that is not visible ASCII
    Malformed(u16),
    /// More than 65,535 bytes
    TooLong,
}

impl std::fmt::Display for IndicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("a client indication field runs past its end"),
            Self::Duplicate(key) => write!(f, "client indication field {key:#06x} sent twice"),
            Self::NoPath => f.write_str("the client indication has no Path"),
            Self::Malformed(KEY_ORIGIN) => {
                f.write_str("the client indication's Origin is malformed")
            }
            Self::Malformed(KEY_PATH) => {
                f.write_str("the client indication's Path is not an absolute path")
            }
            Self::Malformed(key) => write!(f, "client indication field {key:#06x} is malformed"),
            Self::TooLong => f.write_str("the client indication is longer than 65,535 bytes"),
        }
    }
}

impl std::error::Error for IndicationError {}

/// Whether every byte is visible ASCII, which both defined fields are: a
/// serialized origin and a URI path and query
fn visible_ascii(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|b| (0x21..=0x7e).contains(b))
}

impl ClientIndication {
    /// Read an indication's fields (section 3.2). Unknown keys are skipped
    /// whatever their value; a repeated key, known or not, is refused.
    pub fn parse(bytes: &[u8]) -> Result<Self, IndicationError> {
        if bytes.len() > INDICATION_MAX {
            return Err(IndicationError::TooLong);
        }
        let mut seen = std::collections::HashSet::new();
        let mut origin = None;
        let mut path = None;
        let mut rest = bytes;
        while !rest.is_empty() {
            let [k0, k1, l0, l1, tail @ ..] = rest else {
                return Err(IndicationError::Truncated);
            };
            let key = u16::from_be_bytes([*k0, *k1]);
            let len = usize::from(u16::from_be_bytes([*l0, *l1]));
            if tail.len() < len {
                return Err(IndicationError::Truncated);
            }
            let (value, next) = tail.split_at(len);
            if !seen.insert(key) {
                return Err(IndicationError::Duplicate(key));
            }
            match key {
                KEY_ORIGIN => {
                    if !visible_ascii(value) {
                        return Err(IndicationError::Malformed(KEY_ORIGIN));
                    }
                    origin = Some(String::from_utf8_lossy(value).into_owned());
                }
                KEY_PATH => {
                    if !visible_ascii(value) || value.first() != Some(&b'/') {
                        return Err(IndicationError::Malformed(KEY_PATH));
                    }
                    path = Some(String::from_utf8_lossy(value).into_owned());
                }
                _ => {}
            }
            rest = next;
        }
        Ok(Self {
            origin,
            path: path.ok_or(IndicationError::NoPath)?,
        })
    }

    /// The path without its query, which routes are matched by
    pub fn path_only(&self) -> &str {
        self.path.split_once('?').map_or(&self.path, |(p, _)| p)
    }

    /// The query after `?`, if there is one
    pub fn query(&self) -> Option<&str> {
        self.path.split_once('?').map(|(_, q)| q)
    }

    /// The indication as a client sends it: `Origin` (where there is one),
    /// then `Path`. `None` when a value is longer than a field can carry.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut out =
            Vec::with_capacity(8 + self.path.len() + self.origin.as_ref().map_or(0, String::len));
        let mut field = |key: u16, value: &str| -> Option<()> {
            let len = u16::try_from(value.len()).ok()?;
            out.extend_from_slice(&key.to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(value.as_bytes());
            Some(())
        };
        if let Some(origin) = &self.origin {
            field(KEY_ORIGIN, origin)?;
        }
        field(KEY_PATH, &self.path)?;
        (out.len() <= INDICATION_MAX).then_some(out)
    }
}

/// Read the client indication off `connection`.
///
/// It is the client's first unidirectional stream, stream 2, read to its
/// FIN within `wait` (section 3.2: the client sends it in full at once). An
/// `Err` is the text the connection is closed with; the caller closes it.
pub async fn read_indication(
    connection: &quinn::Connection,
    wait: Duration,
) -> Result<ClientIndication, IndicationError> {
    let read = async {
        let mut recv = connection
            .accept_uni()
            .await
            .map_err(|_| IndicationError::Truncated)?;
        // noq hands streams over in the order of their IDs, so the first
        // the client opened is the first accepted, and that is stream 2
        if recv.id() != quinn::StreamId::new(quinn::Side::Client, quinn::Dir::Uni, 0) {
            return Err(IndicationError::Truncated);
        }
        match recv.read_to_end(INDICATION_MAX).await {
            Ok(bytes) => ClientIndication::parse(&bytes),
            Err(quinn::ReadToEndError::TooLong) => Err(IndicationError::TooLong),
            Err(quinn::ReadToEndError::Read(_)) => Err(IndicationError::Truncated),
        }
    };
    tokio::time::timeout(wait, read)
        .await
        .unwrap_or(Err(IndicationError::Truncated))
}

/// The longest reason phrase a CONNECTION_CLOSE carries here
const CLOSE_REASON_MAX: usize = 512;

/// A reason phrase cut to [`CLOSE_REASON_MAX`] at a character
fn reason_bytes(reason: &str) -> &[u8] {
    let mut end = reason.len().min(CLOSE_REASON_MAX);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason.as_bytes()[..end]
}

/// End a session with an application error code and a reason: the
/// connection's CONNECTION_CLOSE (section 8)
pub fn close(connection: &quinn::Connection, code: u32, reason: &str) {
    connection.close(quinn::VarInt::from_u32(code), reason_bytes(reason));
}

/// One WebTransport session over QUIC: the connection itself
#[derive(Debug, Clone)]
pub struct QuicSession {
    connection: quinn::Connection,
}

impl QuicSession {
    /// The session on `connection`, whose client indication has been read
    pub const fn new(connection: quinn::Connection) -> Self {
        Self { connection }
    }
}

impl WtSession for QuicSession {
    type Send = quinn::SendStream;
    type Recv = quinn::RecvStream;

    async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        self.connection
            .accept_bi()
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    async fn accept_uni(&self) -> Result<Self::Recv, WtClosed> {
        self.connection
            .accept_uni()
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    async fn open_uni(&self) -> Result<Self::Send, WtClosed> {
        self.connection
            .open_uni()
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    async fn open_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
        self.connection
            .open_bi()
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    /// RESET_STREAM with the application's code as the QUIC error code
    /// (section 4: stream operations are QUIC's own)
    fn reset(&self, send: &mut Self::Send, code: u32) {
        let _ = send.reset(quinn::VarInt::from_u32(code));
    }

    fn stop(recv: &mut Self::Recv, code: u32) {
        let _ = recv.stop(quinn::VarInt::from_u32(code));
    }

    fn set_priority(send: &Self::Send, priority: i32) {
        let _ = send.set_priority(priority);
    }

    fn close(&self, code: u32, reason: &str) {
        close(&self.connection, code, reason);
    }

    async fn receive_datagram(&self) -> Result<Bytes, WtClosed> {
        self.connection
            .read_datagram()
            .await
            .map_err(|e| WtClosed(e.to_string()))
    }

    /// The application's bytes as the DATAGRAM frame's payload, with no
    /// prefix (section 5)
    fn send_datagram(&self, payload: &[u8]) -> Result<(), WtClosed> {
        self.connection
            .send_datagram(Bytes::copy_from_slice(payload))
            .map_err(|e| WtClosed(e.to_string()))
    }

    fn quic_connection(&self) -> &quinn::Connection {
        &self.connection
    }

    fn ended(&self) -> impl Future<Output = ()> + Send {
        let connection = self.connection.clone();
        async move {
            connection.closed().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(key: u16, value: &[u8]) -> Vec<u8> {
        let mut out = key.to_be_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn an_indication_reads_back_as_it_was_encoded() {
        let sent = ClientIndication {
            origin: Some("https://pqcrypta.com".into()),
            path: "/speedtest?x=1".into(),
        };
        let wire = sent.encode().unwrap();
        // Origin first, its key 0x0000 and length 20
        assert_eq!(&wire[..4], &[0, 0, 0, 20]);
        let read = ClientIndication::parse(&wire).unwrap();
        assert_eq!(read, sent);
        assert_eq!(read.path_only(), "/speedtest");
        assert_eq!(read.query(), Some("x=1"));
    }

    #[test]
    fn a_client_that_sends_no_origin_is_not_a_browser() {
        let read = ClientIndication::parse(&field(KEY_PATH, b"/")).unwrap();
        assert_eq!(read.origin, None);
        assert_eq!(read.path, "/");
        assert_eq!(read.query(), None);
    }

    #[test]
    fn unknown_fields_are_ignored_and_a_repeated_one_is_refused() {
        let mut wire = field(0x0400, b"\x00\xffanything");
        wire.extend(field(KEY_PATH, b"/telemetry"));
        wire.extend(field(0xf001, b""));
        assert_eq!(ClientIndication::parse(&wire).unwrap().path, "/telemetry");

        let mut twice = field(KEY_PATH, b"/a");
        twice.extend(field(KEY_PATH, b"/b"));
        assert_eq!(
            ClientIndication::parse(&twice),
            Err(IndicationError::Duplicate(KEY_PATH))
        );
        let mut unknown_twice = field(0x0400, b"1");
        unknown_twice.extend(field(KEY_PATH, b"/"));
        unknown_twice.extend(field(0x0400, b"2"));
        assert_eq!(
            ClientIndication::parse(&unknown_twice),
            Err(IndicationError::Duplicate(0x0400))
        );
    }

    #[test]
    fn a_malformed_indication_is_refused() {
        assert_eq!(ClientIndication::parse(&[]), Err(IndicationError::NoPath));
        assert_eq!(
            ClientIndication::parse(&field(KEY_ORIGIN, b"https://a.example")),
            Err(IndicationError::NoPath)
        );
        // A header cut short, and a value longer than what follows
        assert_eq!(
            ClientIndication::parse(&[0, 1, 0]),
            Err(IndicationError::Truncated)
        );
        assert_eq!(
            ClientIndication::parse(&[0, 1, 0, 5, b'/']),
            Err(IndicationError::Truncated)
        );
        for bad in [&b""[..], b"speedtest", b"/a b", b"/\x7f", "/é".as_bytes()] {
            assert_eq!(
                ClientIndication::parse(&field(KEY_PATH, bad)),
                Err(IndicationError::Malformed(KEY_PATH)),
                "{bad:?}"
            );
        }
        let mut origin = field(KEY_ORIGIN, b"https://a example");
        origin.extend(field(KEY_PATH, b"/"));
        assert_eq!(
            ClientIndication::parse(&origin),
            Err(IndicationError::Malformed(KEY_ORIGIN))
        );
        assert_eq!(
            ClientIndication::parse(&vec![0u8; INDICATION_MAX + 1]),
            Err(IndicationError::TooLong)
        );
    }

    #[test]
    fn a_value_too_long_for_its_field_is_not_encoded() {
        let long = ClientIndication {
            origin: None,
            path: format!("/{}", "a".repeat(usize::from(u16::MAX))),
        };
        assert_eq!(long.encode(), None);
    }

    #[test]
    fn a_close_reason_is_cut_at_a_character() {
        let reason = "é".repeat(400);
        let cut = reason_bytes(&reason);
        assert!(cut.len() <= CLOSE_REASON_MAX);
        assert!(std::str::from_utf8(cut).is_ok());
    }
}
