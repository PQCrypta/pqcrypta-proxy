//! DNS over QUIC (RFC 9250) on the QUIC listener, beside HTTP/3: a client
//! that names `doq` in ALPN gets a connection that carries DNS instead.
//!
//! The name servers answer DoQ on 853 themselves (Knot). This serves the
//! same name server on the port HTTP/3 answers, for a client whose path
//! carries UDP 443 and not 853, through the DNS over HTTPS gateway's checks
//! and its TCP connection to the name server ([`crate::doh`]): standard
//! queries only, anything else answered here with REFUSED and an Extended
//! DNS Error. What RFC 9250 adds:
//! - one query on each client-initiated bidirectional stream, its Message ID
//!   0, followed by the stream's FIN; the answer on the same stream, then FIN
//!   (section 4.2);
//! - a message that is not one length-prefixed DNS query, a Message ID other
//!   than 0, or a unidirectional stream from the client ends the connection
//!   with DOQ_PROTOCOL_ERROR (sections 4.2, 4.2.1, 4.3.3);
//! - in 0-RTT data, a query that is not a standard query is answered with
//!   Extended DNS Error 26, Too Early, so nothing non-replayable is processed
//!   before the handshake completes (section 4.5).
//!
//! Each query is held to the per-address rate limits the HTTP routes use; one
//! over the limit has its stream reset with DOQ_EXCESSIVE_LOAD.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, warn};

use crate::config::DoqConfig;
use crate::doh::{answered_here, inspect, padded, Upstream};
use crate::rate_limiter::{AdvancedRateLimiter, RateLimitContext, RateLimitResult};

/// The ALPN token for DNS over QUIC (RFC 9250 section 4.1.1).
pub const ALPN: &[u8] = b"doq";

/// RFC 9250 section 4.3: DoQ error codes.
pub const DOQ_NO_ERROR: u32 = 0x0;
pub const DOQ_INTERNAL_ERROR: u32 = 0x1;
pub const DOQ_PROTOCOL_ERROR: u32 = 0x2;
pub const DOQ_REQUEST_CANCELLED: u32 = 0x3;
pub const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

/// Largest framed query: the two-octet length and a 65,535-octet message.
const MAX_FRAMED: usize = 2 + 65_535;
/// Time allowed for a client to send its whole query once it opens a stream.
const QUERY_READ_TIMEOUT: Duration = Duration::from_secs(10);

const RCODE_SERVFAIL: u16 = 2;
const RCODE_REFUSED: u16 = 5;
/// RFC 9250 section 8.3: Extended DNS Error 26, Too Early.
const EDE_TOO_EARLY: u16 = 26;
/// RFC 8914 section 4.22: Not Supported.
const EDE_NOT_SUPPORTED: u16 = 21;
const NOT_SUPPORTED_TEXT: &[u8] = b"this DNS over QUIC service answers standard queries only";
/// RFC 8914 section 4.23: No Reachable Authority.
const EDE_NO_REACHABLE_AUTHORITY: u16 = 22;
const TOO_EARLY_TEXT: &[u8] =
    b"only standard queries are answered in 0-RTT data; send it again once the handshake is complete";
const UNREACHABLE_TEXT: &[u8] = b"the name server did not answer";

/// The name server DoQ on the QUIC listener asks, and how long it waits.
pub struct Service {
    upstream: Upstream,
    timeout: Duration,
}

impl Service {
    pub fn new(config: &DoqConfig) -> anyhow::Result<Self> {
        let addr: SocketAddr = config
            .upstream
            .parse()
            .map_err(|e| anyhow::anyhow!("doq.upstream {:?}: {}", config.upstream, e))?;
        Ok(Self {
            upstream: Upstream::new(addr),
            timeout: Duration::from_millis(config.timeout_ms),
        })
    }
}

/// What a client's message on a stream is.
#[derive(Debug, PartialEq, Eq)]
enum Framed<'a> {
    /// One length-prefixed DNS message whose Message ID is 0
    Query(&'a [u8]),
    /// Anything else: a connection error of type DOQ_PROTOCOL_ERROR
    ProtocolError(&'static str),
}

/// A stream's bytes, as section 4.2 has a client send them: the two-octet
/// length, exactly that many octets of DNS message, and its ID 0.
fn framed(bytes: &[u8]) -> Framed<'_> {
    let Some((prefix, message)) = bytes.split_first_chunk::<2>() else {
        return Framed::ProtocolError("the stream ended before the length prefix");
    };
    if usize::from(u16::from_be_bytes(*prefix)) != message.len() {
        return Framed::ProtocolError("the length prefix does not match the message");
    }
    if message.len() < 12 {
        return Framed::ProtocolError("a DNS message shorter than its header");
    }
    if message[..2] != [0, 0] {
        return Framed::ProtocolError("a Message ID other than 0");
    }
    Framed::Query(message)
}

/// What the service sends back for one well-framed query.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    /// Ask the name server
    Forward,
    /// Answer this, made here
    Here(Vec<u8>),
    /// Not a DNS query at all (a response, or sections that run past the end)
    ProtocolError,
}

/// The gateway's rule, with section 4.5's for 0-RTT data first.
fn decide(query: &[u8], in_early_data: bool) -> Reply {
    let Some(info) = inspect(query) else {
        return Reply::ProtocolError;
    };
    if info.forwardable() {
        return Reply::Forward;
    }
    if in_early_data {
        return Reply::Here(answered_here(
            query,
            &info,
            RCODE_REFUSED,
            EDE_TOO_EARLY,
            TOO_EARLY_TEXT,
        ));
    }
    Reply::Here(answered_here(
        query,
        &info,
        RCODE_REFUSED,
        EDE_NOT_SUPPORTED,
        NOT_SUPPORTED_TEXT,
    ))
}

/// Serve one QUIC connection that negotiated `doq`. `early_data` is whether
/// the server accepted the client's 0-RTT data; `established` resolves when
/// the handshake completes.
pub async fn serve(
    connection: quinn::Connection,
    established: impl std::future::Future<Output = bool> + Send + 'static,
    early_data: bool,
    peer: IpAddr,
    service: Arc<Service>,
    limiter: Arc<AdvancedRateLimiter>,
) {
    // A stream opened before the handshake completed came in 0-RTT data
    let handshake_done = Arc::new(AtomicBool::new(!early_data));
    {
        let done = Arc::clone(&handshake_done);
        tokio::spawn(async move {
            established.await;
            done.store(true, Ordering::Release);
        });
    }
    loop {
        tokio::select! {
            bi = connection.accept_bi() => match bi {
                Ok((send, recv)) => {
                    let in_early_data = !handshake_done.load(Ordering::Acquire);
                    let connection = connection.clone();
                    let service = Arc::clone(&service);
                    let limiter = Arc::clone(&limiter);
                    tokio::spawn(async move {
                        stream(connection, send, recv, in_early_data, peer, service, limiter).await;
                    });
                }
                Err(e) => {
                    debug!("DoQ connection from {} ended: {}", peer, e);
                    return;
                }
            },
            uni = connection.accept_uni() => {
                if uni.is_ok() {
                    connection.close(
                        quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR),
                        b"a unidirectional stream",
                    );
                }
                return;
            }
        }
    }
}

async fn stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    in_early_data: bool,
    peer: IpAddr,
    service: Arc<Service>,
    limiter: Arc<AdvancedRateLimiter>,
) {
    let bytes = match tokio::time::timeout(QUERY_READ_TIMEOUT, recv.read_to_end(MAX_FRAMED)).await {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(quinn::ReadToEndError::TooLong)) => {
            connection.close(
                quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR),
                b"more than one DNS message on a stream",
            );
            return;
        }
        Ok(Err(e)) => {
            debug!("DoQ stream from {} ended before its query: {}", peer, e);
            return;
        }
        Err(_) => {
            let _ = recv.stop(quinn::VarInt::from_u32(DOQ_REQUEST_CANCELLED));
            let _ = send.reset(quinn::VarInt::from_u32(DOQ_REQUEST_CANCELLED));
            return;
        }
    };
    let query = match framed(&bytes) {
        Framed::Query(query) => query,
        Framed::ProtocolError(why) => {
            connection.close(quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR), why.as_bytes());
            return;
        }
    };
    if !allowed(&limiter, peer).await {
        let _ = send.reset(quinn::VarInt::from_u32(DOQ_EXCESSIVE_LOAD));
        return;
    }
    let answer = match decide(query, in_early_data) {
        Reply::ProtocolError => {
            connection.close(
                quinn::VarInt::from_u32(DOQ_PROTOCOL_ERROR),
                b"a stream that does not carry a DNS query",
            );
            return;
        }
        Reply::Here(answer) => answer,
        Reply::Forward => {
            let asked = tokio::time::timeout(service.timeout, service.upstream.exchange(query));
            match asked.await {
                Ok(Ok(answer)) => {
                    let wants_padding = inspect(query).is_some_and(|i| i.padding);
                    if wants_padding {
                        padded(&answer).unwrap_or(answer)
                    } else {
                        answer
                    }
                }
                outcome => {
                    if let Ok(Err(e)) = outcome {
                        warn!("DNS over QUIC: name server failed: {}", e);
                    }
                    match inspect(query) {
                        Some(info) => answered_here(
                            query,
                            &info,
                            RCODE_SERVFAIL,
                            EDE_NO_REACHABLE_AUTHORITY,
                            UNREACHABLE_TEXT,
                        ),
                        None => {
                            let _ = send.reset(quinn::VarInt::from_u32(DOQ_INTERNAL_ERROR));
                            return;
                        }
                    }
                }
            }
        }
    };
    let Ok(length) = u16::try_from(answer.len()) else {
        let _ = send.reset(quinn::VarInt::from_u32(DOQ_INTERNAL_ERROR));
        return;
    };
    let mut out = Vec::with_capacity(answer.len() + 2);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&answer);
    if send.write_all(&out).await.is_ok() {
        let _ = send.finish();
    }
}

/// The per-address limits the HTTP routes are held to, for one query.
async fn allowed(limiter: &AdvancedRateLimiter, peer: IpAddr) -> bool {
    let context = RateLimitContext {
        source_ip: peer,
        headers: HashMap::new(),
        path: "/dns-query".to_string(),
        method: "DOQ".to_string(),
        query_params: HashMap::new(),
        cookies: HashMap::new(),
        ja3_hash: None,
        ja4_hash: None,
        route_name: Some("doq".to_string()),
    };
    matches!(
        limiter.check(&context).await,
        RateLimitResult::Allowed { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A query for `example.com` A, ID 0, with an OPT record when `edns`.
    fn query(opcode: u8, edns: bool) -> Vec<u8> {
        let mut q = vec![
            0,
            0,
            (opcode << 3) | 0x01,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            u8::from(edns),
        ];
        q.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        if edns {
            q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        }
        q
    }

    fn framed_bytes(message: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(message.len())
            .expect("a test message")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(message);
        out
    }

    #[test]
    fn a_stream_carries_one_length_prefixed_query_with_id_0() {
        let q = query(0, false);
        assert_eq!(framed(&framed_bytes(&q)), Framed::Query(&q[..]));
        // The length prefix says more, or less, than the stream carried
        let mut long = framed_bytes(&q);
        long.push(0);
        assert!(matches!(framed(&long), Framed::ProtocolError(_)));
        assert!(matches!(
            framed(&long[..long.len() - 3]),
            Framed::ProtocolError(_)
        ));
        assert!(matches!(framed(&[0]), Framed::ProtocolError(_)));
        // Section 4.2.1: the Message ID is 0
        let mut id = q;
        id[1] = 7;
        assert_eq!(
            framed(&framed_bytes(&id)),
            Framed::ProtocolError("a Message ID other than 0")
        );
    }

    /// The Extended DNS Error an answer made here carries.
    fn ede(answer: &[u8]) -> Option<u16> {
        let at = answer.windows(2).rposition(|w| w == 15u16.to_be_bytes())?;
        Some(u16::from_be_bytes([answer[at + 4], answer[at + 5]]))
    }

    #[test]
    fn a_standard_query_goes_to_the_name_server_in_0rtt_or_after() {
        for early in [false, true] {
            assert_eq!(decide(&query(0, true), early), Reply::Forward);
        }
    }

    #[test]
    fn anything_else_in_0rtt_is_too_early_and_after_it_refused() {
        // Opcode 5, UPDATE: not replayable
        let Reply::Here(early) = decide(&query(5, true), true) else {
            panic!("answered here");
        };
        assert_eq!(early[3] & 0x0F, 5, "REFUSED");
        assert_eq!(ede(&early), Some(EDE_TOO_EARLY));
        assert_eq!(&early[..2], &[0, 0], "Message ID 0");
        let Reply::Here(late) = decide(&query(5, true), false) else {
            panic!("answered here");
        };
        assert_eq!(late[3] & 0x0F, 5);
        assert_ne!(ede(&late), Some(EDE_TOO_EARLY));
    }

    #[test]
    fn a_response_on_a_stream_is_a_protocol_error() {
        let mut response = query(0, false);
        response[2] |= 0x80;
        assert_eq!(decide(&response, false), Reply::ProtocolError);
    }
}
