//! Open a WebTransport over QUIC session (draft-vvv-webtransport-quic-02,
//! ALPN `wq-vvv-01`) on a node and check that it is served: the handshake
//! negotiates `wq-vvv-01`, the client indication names the path, datagrams
//! are echoed with nothing added, and the speed test answers its `info` and
//! `transport` commands on bidirectional streams. Run it from another host:
//! loopback skips the security layers a real client meets.
//!
//! ```text
//! cargo run --release --example wq-probe -- \
//!     https://api.pqcrypta.com:4433/speedtest --origin https://pqcrypta.com
//! ```
//!
//! Prints one JSON line. Exits non-zero if `wq-vvv-01` is not negotiated, the
//! node closes the session (its code and reason are printed), no datagram
//! comes back, or a command goes unanswered.

use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{json, Value};

use pqcrypta_proxy::wt_quic::{ClientIndication, ALPN};

#[derive(Parser)]
struct Args {
    /// The session's URL: the host, port and path (with any query) to open
    /// it for.
    url: String,
    /// Origin to send in the client indication; the node must list it.
    #[arg(long)]
    origin: Option<String>,
    /// Datagram round trips to time.
    #[arg(long, default_value_t = 20)]
    pings: u32,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

/// A command on a new bidirectional stream, framed as the speed test reads
/// it (a 4-byte big-endian length, then JSON), and its one framed answer
async fn call(conn: &quinn::Connection, command: &Value) -> Result<Value, Error> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let body = serde_json::to_vec(command)?;
    send.write_all(&u32::try_from(body.len())?.to_be_bytes())
        .await?;
    send.write_all(&body).await?;
    send.finish()?;
    let read = async {
        let mut len = [0u8; 4];
        recv.read_exact(&mut len).await?;
        let mut frame = vec![0u8; u32::from_be_bytes(len) as usize];
        recv.read_exact(&mut frame).await?;
        Ok::<_, Error>(serde_json::from_slice(&frame)?)
    };
    tokio::time::timeout(ANSWER_TIMEOUT, read)
        .await
        .map_err(|_| format!("{command} went unanswered for {ANSWER_TIMEOUT:?}"))?
}

/// Datagram round trips, one every 10 ms, matched by sequence number
async fn pings(conn: &quinn::Connection, count: u32) -> Vec<f64> {
    let started = Instant::now();
    let reader = {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut rtts = Vec::new();
            while let Ok(Ok(d)) =
                tokio::time::timeout(Duration::from_secs(2), conn.read_datagram()).await
            {
                if d.len() >= 12 {
                    let sent_us = u64::from_be_bytes(d[4..12].try_into().unwrap_or_default());
                    let now_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                    #[allow(clippy::cast_precision_loss)]
                    rtts.push(now_us.saturating_sub(sent_us) as f64 / 1000.0);
                }
                if rtts.len() >= count as usize {
                    break;
                }
            }
            rtts
        })
    };
    for seq in 0..count {
        let mut d = [0u8; 64];
        d[..4].copy_from_slice(&seq.to_be_bytes());
        let now_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        d[4..12].copy_from_slice(&now_us.to_be_bytes());
        let _ = conn.send_datagram(bytes::Bytes::copy_from_slice(&d));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    reader.await.unwrap_or_default()
}

/// Why the node closed the session, if it has
fn closed(conn: &quinn::Connection) -> Option<String> {
    conn.close_reason().map(|e| match e {
        quinn::ConnectionError::ApplicationClosed(c) => format!(
            "closed by the node, code {}: {}",
            c.error_code,
            String::from_utf8_lossy(&c.reason)
        ),
        other => other.to_string(),
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let uri: http::Uri = args.url.parse()?;
    let host = uri.host().ok_or("the URL names no host")?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_string();
    let indication = ClientIndication {
        origin: args.origin.clone(),
        path,
    }
    .encode()
    .ok_or("the origin or path is too long for a client indication")?;

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .collect();
    let addr = *addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or("the host resolved to nothing")?;
    let bind: std::net::SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        pqcrypta_proxy::tls::build_pqc_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let endpoint = quinn::Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        pqcrypta_proxy::tls::quic_client_config(crypto)?,
    )));

    let started = Instant::now();
    let conn = tokio::time::timeout(ANSWER_TIMEOUT, endpoint.connect(addr, &host)?)
        .await
        .map_err(|_| "the handshake did not complete")??;
    let handshake_ms = started.elapsed().as_secs_f64() * 1000.0;
    let data = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
    let negotiated = data.as_ref().and_then(|d| d.protocol.clone());
    if negotiated.as_deref() != Some(ALPN) {
        return Err(format!(
            "negotiated {:?}, not wq-vvv-01",
            negotiated.map(|p| String::from_utf8_lossy(&p).into_owned())
        )
        .into());
    }
    let group = data.and_then(|d| d.negotiated_key_exchange_group.map(|g| format!("{g:?}")));

    // The client indication, whole, on the first unidirectional stream
    let mut stream = conn.open_uni().await?;
    stream.write_all(&indication).await?;
    stream.finish()?;

    let run = async {
        let rtts = pings(&conn, args.pings).await;
        let info = call(&conn, &json!({"op": "info"})).await?;
        let transport = call(&conn, &json!({"op": "transport"})).await?;
        Ok::<_, Error>((rtts, info, transport))
    };
    let (rtts, info, transport) = match run.await {
        Ok(done) => done,
        Err(e) => return Err(closed(&conn).unwrap_or_else(|| e.to_string()).into()),
    };
    if let Some(why) = closed(&conn) {
        return Err(why.into());
    }
    if rtts.is_empty() {
        return Err("no datagram was echoed".into());
    }
    if info.get("op").and_then(Value::as_str) != Some("info_result") {
        return Err(format!("info was answered {info}").into());
    }
    let mut sorted = rtts.clone();
    sorted.sort_by(f64::total_cmp);
    let median = sorted[sorted.len() / 2];
    println!(
        "{}",
        json!({
            "url": args.url,
            "alpn": "wq-vvv-01",
            "key_exchange": group,
            "handshake_ms": (handshake_ms * 10.0).round() / 10.0,
            "pings_sent": args.pings,
            "pings_echoed": rtts.len(),
            "rtt_ms_median": (median * 100.0).round() / 100.0,
            "server": info.get("server"),
            "version": info.get("version"),
            "congestion_control": transport.get("congestion_control"),
        })
    );
    conn.close(0u32.into(), b"");
    endpoint.wait_idle().await;
    Ok(())
}
