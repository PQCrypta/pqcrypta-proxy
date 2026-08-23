//! A minimal, complete MASQUE (RFC 9298 CONNECT-UDP) client.
//!
//! Exists because there is almost nowhere to point one. CONNECT-UDP is well
//! specified and increasingly deployed, but a person writing a client has had
//! no public relay to test against and no small reference to read — the working
//! implementations are inside browsers and CDNs. This is both: it talks to the
//! public relay at <https://pqcrypta.com/masque/>, and it is short enough to
//! read in one sitting.
//!
//! What it does: opens an HTTP/3 connection, sends an Extended CONNECT with
//! `:protocol = connect-udp`, and on success relays one DNS query to the target
//! resolver as an HTTP Datagram, then prints the resolved address.
//!
//! ```text
//! cargo run --example masque-client -- pqcrypta.com:443 127.0.0.53:53 example.com
//!                                      \____________/  \____________/ \_________/
//!                                          relay           target       name to
//!                                                        (allowlisted)   resolve
//! ```
//!
//! The wire format it implements, for anyone porting this elsewhere:
//!
//! ```text
//! request:  :method = CONNECT
//!           :protocol = connect-udp
//!           :scheme = https
//!           :authority = <relay>
//!           :path = /.well-known/masque/udp/<target_host>/<target_port>/
//!
//! datagram: varint(quarter_stream_id) | varint(context_id = 0) | UDP payload
//! ```
//!
//! `quarter_stream_id` is the CONNECT request's stream ID divided by four. That
//! division is the whole trick: QUIC datagrams are connection-global and carry
//! no stream association, so RFC 9297 puts the stream back in the payload, and
//! client-initiated bidirectional stream IDs are always multiples of four, so
//! dividing keeps the varint short.

use std::env;
use std::fmt::Write as _;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use h3::ext::Protocol;
use quinn::VarInt;
use quinn_proto::coding::{Decodable, Encodable};

const DEFAULT_RELAY: &str = "pqcrypta.com:443";
const DEFAULT_TARGET: &str = "127.0.0.53:53";
const DEFAULT_NAME: &str = "example.com";

// Deliberately one linear function. This is a reference implementation whose
// value is being readable top to bottom in the order the protocol happens;
// splitting it into helpers to satisfy a length lint would hide the sequence
// that a reader came here for.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let relay = args.next().unwrap_or_else(|| DEFAULT_RELAY.to_string());
    let target = args.next().unwrap_or_else(|| DEFAULT_TARGET.to_string());
    let name = args.next().unwrap_or_else(|| DEFAULT_NAME.to_string());

    let (relay_host, relay_port) = split_host_port(&relay)?;
    let (target_host, target_port) = split_host_port(&target)?;

    println!("relay   : {relay_host}:{relay_port}");
    println!("target  : {target_host}:{target_port}");
    println!("query   : {name} IN A");
    println!();

    // ── 1. QUIC connection to the relay ────────────────────────────────
    //
    // rustls will not pick a provider for you when more than one could apply, and
    // the resulting panic happens deep inside the first handshake rather than
    // here, so install it explicitly before anything touches TLS.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("a rustls CryptoProvider was already installed"))?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .context("rustls config is not usable for QUIC (needs TLS 1.3)")?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

    // Prefer a dual-stack socket, falling back to IPv4 where the host has no
    // IPv6 at all — a bare `[::]:0` bind fails outright on those.
    let v6: SocketAddr = "[::]:0".parse()?;
    let v4: SocketAddr = "0.0.0.0:0".parse()?;
    let endpoint = match quinn::Endpoint::client(v6) {
        Ok(ep) => ep,
        Err(_) => quinn::Endpoint::client(v4).context("failed to bind a local UDP socket")?,
    };
    endpoint.set_default_client_config(client_config);

    let remote: SocketAddr = (relay_host.as_str(), relay_port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("{relay_host} did not resolve"))?;

    let conn = endpoint
        .connect(remote, &relay_host)?
        .await
        .context("QUIC handshake with the relay failed")?;

    println!("[+] QUIC connected to {remote}");

    // ── 2. HTTP/3, with datagrams and extended CONNECT negotiated ──────
    //
    // Both settings are mandatory here and both are easy to forget: without
    // `enable_datagram` the relay has nowhere to put the UDP payloads, and
    // without `enable_extended_connect` the `:protocol` pseudo-header is not
    // permitted on the request at all.
    let (mut driver, mut send_request) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn::Connection::new(conn.clone()))
        .await
        .context("HTTP/3 setup failed")?;

    // The driver must be polled for the connection to make progress.
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    // ── 3. Extended CONNECT ────────────────────────────────────────────
    let path = format!(
        "/.well-known/masque/udp/{}/{}/",
        urlencode(&target_host),
        target_port
    );

    let mut req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{relay_host}{path}"))
        .body(())?;
    req.extensions_mut().insert(Protocol::CONNECT_UDP);

    let mut stream = send_request
        .send_request(req)
        .await
        .context("sending CONNECT-UDP failed")?;

    // Deliberately NOT finished. The CONNECT stream *is* the session: closing
    // the send side tells the relay the client is done, and it tears the UDP
    // socket down — which from here looks like datagrams silently going
    // nowhere. Keep the stream alive for as long as you want the session.
    let stream_id = stream.id();
    let response = stream
        .recv_response()
        .await
        .context("no response to CONNECT-UDP")?;

    if !response.status().is_success() {
        bail!(
            "relay refused the session: {} — the target is probably not on its allowlist",
            response.status()
        );
    }
    println!("[+] CONNECT-UDP accepted ({})", response.status());

    // ── 4. The datagram prefix ─────────────────────────────────────────
    let quarter_id = stream_id.into_inner() / 4;
    let prefix = {
        let mut p = BytesMut::new();
        VarInt::from_u64(quarter_id)
            .expect("quarter id fits in 62 bits")
            .encode(&mut p);
        // Context ID 0: "the payload that follows is a full UDP datagram".
        VarInt::from_u32(0).encode(&mut p);
        p.freeze()
    };
    println!("[+] stream {stream_id} -> quarter stream id {quarter_id}");

    // ── 5. Send a DNS query, read the answer ───────────────────────────
    let query = dns_query(&name);
    let mut out = BytesMut::with_capacity(prefix.len() + query.len());
    out.put_slice(&prefix);
    out.put_slice(&query);
    conn.send_datagram(out.freeze())
        .context("sending the HTTP datagram failed")?;
    println!("[+] sent {} byte DNS query", query.len());

    let reply = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let dg = conn.read_datagram().await?;
            let mut cur = std::io::Cursor::new(&dg[..]);

            // Every inbound datagram on this connection arrives here, including
            // ones for other sessions, so check the quarter stream id before
            // treating the remainder as ours.
            let Ok(qs) = VarInt::decode(&mut cur) else {
                continue;
            };
            let Ok(ctx) = VarInt::decode(&mut cur) else {
                continue;
            };
            if qs.into_inner() != quarter_id || ctx.into_inner() != 0 {
                continue;
            }

            // The cursor is at most two varints into a datagram, so this
            // always fits; be explicit rather than casting.
            let start = usize::try_from(cur.position()).unwrap_or(0);
            return anyhow::Ok(dg.slice(start..));
        }
    })
    .await
    .context("timed out waiting for the DNS reply")??;

    println!("[+] received {} byte reply", reply.len());

    match dns_first_a(&reply) {
        Some(addr) => println!("\n{name} resolved to {addr} — through the relay, over HTTP/3."),
        None => println!("\nReply carried no A record (the round trip still worked)."),
    }

    drop(stream);
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    driver_task.abort();

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("expected host:port, got {s:?}"))?;
    Ok((host.to_string(), port.parse().context("bad port")?))
}

/// Percent-encode a path segment. Only the characters that can appear in a
/// hostname or IPv6 literal and are not path-safe need handling — `:` in
/// particular, which is why IPv6 targets are encoded rather than bracketed.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(b));
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Build a minimal DNS query for an A record (RFC 1035 §4.1).
///
/// Hand-rolled to keep the example dependency-free: pulling in a DNS crate
/// would bury the twelve lines that actually matter under a resolver API.
fn dns_query(name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());

    q.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    q.extend_from_slice(&1u16.to_be_bytes()); // one question
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answer/authority/additional

    for label in name.split('.').filter(|l| !l.is_empty()) {
        // RFC 1035 §2.3.4 caps a label at 63 octets. A longer one cannot be
        // encoded at all, and casting it would silently emit a corrupt query,
        // so skip it rather than produce something the resolver will reject
        // for reasons that point nowhere near the cause.
        let Ok(len) = u8::try_from(label.len()) else {
            continue;
        };
        if len > 63 {
            continue;
        }
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0); // root label

    q.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    q
}

/// Pull the first A record out of a DNS reply, skipping the question section
/// and any non-A answers. Compression pointers are handled only as far as
/// skipping them, which is all a reply to this query needs.
fn dns_first_a(msg: &[u8]) -> Option<String> {
    if msg.len() < 12 {
        return None;
    }

    let questions = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let answers = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12;

    for _ in 0..questions {
        i = skip_name(msg, i)?;
        i = i.checked_add(4)?; // QTYPE + QCLASS
    }

    for _ in 0..answers {
        i = skip_name(msg, i)?;
        if i + 10 > msg.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;

        if rtype == 1 && rdlen == 4 && i + 4 <= msg.len() {
            return Some(format!(
                "{}.{}.{}.{}",
                msg[i],
                msg[i + 1],
                msg[i + 2],
                msg[i + 3]
            ));
        }
        i = i.checked_add(rdlen)?;
    }

    None
}

/// Advance past a DNS name, whether it is a label sequence or a compression
/// pointer (which is always the last two bytes of a name).
fn skip_name(msg: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            return Some(i + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i = i.checked_add(1 + len)?;
    }
}
