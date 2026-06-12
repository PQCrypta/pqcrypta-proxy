//! MASQUE CONNECT-UDP proxying (RFC 9298).
//!
//! Accepts HTTP/3 Extended CONNECT requests with `:protocol = connect-udp` and
//! relays UDP datagrams between the client and a target `host:port`. UDP
//! payloads travel as HTTP Datagrams (RFC 9297) bound to the CONNECT request
//! stream:
//!
//! ```text
//! QUIC DATAGRAM = varint(Quarter Stream ID) | varint(Context ID) | UDP payload
//! ```
//!
//! For UDP proxying the only defined context is Context ID 0 (RFC 9298 §5),
//! which carries a full UDP payload. Datagrams with any other context are
//! dropped, as required by the spec for unknown contexts.
//!
//! Datagrams are connection-global in QUIC, so a single [`DatagramRouter`] per
//! QUIC connection reads every inbound datagram, parses the Quarter Stream ID,
//! and dispatches the remainder to the matching session. Sessions send by
//! prepending their own Quarter Stream ID and Context ID 0.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use percent_encoding::percent_decode_str;
use quinn::{Connection, VarInt};
use quinn_proto::coding::Codec;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Parse a CONNECT-UDP target from the request path.
///
/// RFC 9298 §3 defines the default template
/// `/.well-known/masque/udp/{target_host}/{target_port}/`. Host and port are
/// percent-encoded path segments; the host may be a reg-name, an IPv4 literal,
/// or an IPv6 literal (without surrounding brackets). Returns the decoded host
/// and port, or `None` if the path does not match.
pub fn parse_target(path: &str) -> Option<(String, u16)> {
    // Split into non-empty segments so a trailing slash is tolerated.
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    // Expect: ".well-known", "masque", "udp", <host>, <port>
    let pos = segments
        .windows(3)
        .position(|w| w == [".well-known", "masque", "udp"])?;
    let host_seg = segments.get(pos + 3)?;
    let port_seg = segments.get(pos + 4)?;

    let host = percent_decode_str(host_seg).decode_utf8().ok()?.to_string();
    if host.is_empty() {
        return None;
    }
    let port: u16 = percent_decode_str(port_seg)
        .decode_utf8()
        .ok()?
        .parse()
        .ok()?;
    if port == 0 {
        return None;
    }
    Some((host, port))
}

/// Routes inbound QUIC datagrams to per-stream CONNECT-UDP sessions.
///
/// One router exists per QUIC connection. The first registered session starts
/// the background reader task; it runs until the connection closes.
pub struct DatagramRouter {
    sessions: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Bytes>>>>,
}

impl DatagramRouter {
    /// Create a router for a connection and start its datagram reader task.
    pub fn new(connection: Connection) -> Arc<Self> {
        let sessions: Arc<Mutex<HashMap<u64, mpsc::UnboundedSender<Bytes>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let router = Arc::new(Self {
            sessions: sessions.clone(),
        });

        tokio::spawn(async move {
            loop {
                match connection.read_datagram().await {
                    Ok(mut datagram) => {
                        // Strip the Quarter Stream ID prefix (RFC 9297).
                        let qsid = match VarInt::decode(&mut datagram) {
                            Ok(v) => v.into_inner(),
                            Err(_) => continue, // malformed prefix
                        };
                        let payload = datagram; // remaining bytes after the prefix
                        let sender = {
                            let map = sessions.lock().await;
                            map.get(&qsid).cloned()
                        };
                        if let Some(tx) = sender {
                            // Unbounded: a slow session cannot stall the reader.
                            let _ = tx.send(payload);
                        }
                        // No registered session => unrelated/closed stream; drop.
                    }
                    Err(e) => {
                        debug!("Datagram reader stopped: {}", e);
                        break;
                    }
                }
            }
        });

        router
    }

    /// Register a session by Quarter Stream ID, returning the receiver that
    /// inbound datagrams for that stream will be dispatched to.
    pub async fn register_session(&self, qsid: u64) -> mpsc::UnboundedReceiver<Bytes> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sessions.lock().await.insert(qsid, tx);
        rx
    }

    /// Remove a session's routing entry once it ends.
    pub async fn unregister_session(&self, qsid: u64) {
        self.sessions.lock().await.remove(&qsid);
    }

    /// Current number of active CONNECT-UDP sessions on this connection.
    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }
}

/// Bind a local UDP socket in the address family of `target` and connect it.
async fn bind_and_connect(target: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind_addr: SocketAddr = match target.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(target).await?;
    Ok(socket)
}

/// Run a CONNECT-UDP relay session until idle timeout, client close, or error.
///
/// `quarter_id` is the request stream id divided by 4. The session must already
/// be registered with `router` (so inbound datagrams arrive on `from_client`).
/// `stream_closed` resolves when the client closes the CONNECT request stream.
pub async fn run_session(
    router: Arc<DatagramRouter>,
    connection: Connection,
    quarter_id: u64,
    target: SocketAddr,
    idle_timeout: Duration,
    mut from_client: mpsc::UnboundedReceiver<Bytes>,
    stream_closed: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let socket = match bind_and_connect(target).await {
        Ok(s) => s,
        Err(e) => {
            warn!("CONNECT-UDP: failed to open socket to {}: {}", target, e);
            router.unregister_session(quarter_id).await;
            return;
        }
    };
    let socket = Arc::new(socket);
    info!(
        "CONNECT-UDP session active: qsid={} target={}",
        quarter_id, target
    );

    // Shared last-activity timestamp drives a true idle timeout: a session is
    // closed only when *neither* direction has carried a datagram within the
    // window. Both relay tasks bump it on every packet.
    let last_active = Arc::new(Mutex::new(Instant::now()));

    // The Quarter Stream ID prefix is identical for every datagram this session
    // sends to the client, so encode it once.
    let prefix = {
        let mut p = BytesMut::new();
        VarInt::from_u64(quarter_id)
            .expect("quarter id fits in 62 bits")
            .encode(&mut p);
        // Context ID 0 (RFC 9298 §5): full UDP payload follows.
        VarInt::from_u32(0).encode(&mut p);
        p.freeze()
    };

    // target -> client: read UDP, wrap as an HTTP datagram, send to the client.
    let recv_socket = socket.clone();
    let recv_conn = connection.clone();
    let recv_prefix = prefix.clone();
    let recv_active = last_active.clone();
    let target_to_client = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match recv_socket.recv(&mut buf).await {
                Ok(n) => {
                    *recv_active.lock().await = Instant::now();
                    // Drop payloads that exceed the connection's datagram budget
                    // rather than tearing down the session (RFC 9298 §5).
                    if let Some(max) = recv_conn.max_datagram_size() {
                        if recv_prefix.len() + n > max {
                            debug!(
                                "CONNECT-UDP: dropping {}-byte payload (exceeds datagram max {})",
                                n, max
                            );
                            continue;
                        }
                    }
                    let mut out = BytesMut::with_capacity(recv_prefix.len() + n);
                    out.put_slice(&recv_prefix);
                    out.put_slice(&buf[..n]);
                    if recv_conn.send_datagram(out.freeze()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    debug!("CONNECT-UDP: socket recv error: {}", e);
                    break;
                }
            }
        }
    };

    // client -> target: strip the Context ID, forward Context 0 payloads.
    let send_socket = socket.clone();
    let send_active = last_active.clone();
    let client_to_target = async move {
        while let Some(mut payload) = from_client.recv().await {
            let ctx = match VarInt::decode(&mut payload) {
                Ok(v) => v.into_inner(),
                Err(_) => continue, // malformed datagram
            };
            if ctx != 0 {
                continue; // unknown context => drop (RFC 9298 §5)
            }
            *send_active.lock().await = Instant::now();
            // `payload` now holds the raw UDP datagram.
            if send_socket.send(&payload).await.is_err() {
                break;
            }
        }
    };

    // Idle watchdog: sleeps until the idle deadline measured from the last
    // packet in either direction, re-checking until the window truly elapses.
    let watchdog = async move {
        loop {
            let elapsed = last_active.lock().await.elapsed();
            if elapsed >= idle_timeout {
                return;
            }
            tokio::time::sleep(idle_timeout.saturating_sub(elapsed)).await;
        }
    };

    // Whichever future finishes first ends the session.
    tokio::select! {
        _ = target_to_client => {},
        _ = client_to_target => {},
        _ = watchdog => {
            debug!("CONNECT-UDP: idle timeout qsid={}", quarter_id);
        }
        _ = stream_closed => {
            debug!("CONNECT-UDP: client closed stream qsid={}", quarter_id);
        }
    }

    router.unregister_session(quarter_id).await;
    info!("CONNECT-UDP session closed: qsid={}", quarter_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_template() {
        assert_eq!(
            parse_target("/.well-known/masque/udp/dns.example.com/853/"),
            Some(("dns.example.com".to_string(), 853))
        );
    }

    #[test]
    fn parses_without_trailing_slash() {
        assert_eq!(
            parse_target("/.well-known/masque/udp/192.0.2.1/443"),
            Some(("192.0.2.1".to_string(), 443))
        );
    }

    #[test]
    fn decodes_percent_encoded_ipv6() {
        // 2001:db8::1 with colons percent-encoded
        assert_eq!(
            parse_target("/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/"),
            Some(("2001:db8::1".to_string(), 443))
        );
    }

    #[test]
    fn rejects_non_masque_path() {
        assert_eq!(parse_target("/index.html"), None);
        assert_eq!(parse_target("/.well-known/masque/udp/host"), None);
    }

    #[test]
    fn rejects_zero_and_bad_port() {
        assert_eq!(parse_target("/.well-known/masque/udp/host/0/"), None);
        assert_eq!(parse_target("/.well-known/masque/udp/host/notaport/"), None);
    }
}
