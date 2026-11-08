//! Run the `/speedtest` WebTransport protocol against one node from the
//! command line: datagram round trips, a time-bounded download over parallel
//! streams, and an upload over parallel streams read back from the node's
//! upload meter. It measures what the node and the path can carry without a
//! browser's own limits in the way, so a page's figures can be checked against
//! it. Run it from another host: loopback skips the security layers and the
//! network a real client meets.
//!
//! ```text
//! cargo run --release --example speedtest-probe -- \
//!     https://api.pqcrypta.com:4433/speedtest --origin https://pqcrypta.com \
//!     --secs 6 --down-streams 12 --up-streams 16
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{json, Value};
use wtransport::endpoint::ConnectOptions;
use wtransport::{ClientConfig, Connection, Endpoint};

#[derive(Parser)]
struct Args {
    /// The node's speed-test URL.
    url: String,
    /// Origin header to send; the node must list it as allowed.
    #[arg(long)]
    origin: Option<String>,
    /// Seconds each transfer runs.
    #[arg(long, default_value_t = 6)]
    secs: u64,
    /// Parallel download streams.
    #[arg(long, default_value_t = 12)]
    down_streams: usize,
    /// Parallel upload streams.
    #[arg(long, default_value_t = 16)]
    up_streams: usize,
    /// Datagram round trips to time.
    #[arg(long, default_value_t = 100)]
    pings: u32,
}

type Error = Box<dyn std::error::Error + Send + Sync>;

async fn request(
    conn: &Connection,
    command: &Value,
) -> Result<(wtransport::SendStream, wtransport::RecvStream), Error> {
    let (mut send, recv) = conn.open_bi().await?.await?;
    let body = serde_json::to_vec(command)?;
    send.write_all(&u32::try_from(body.len())?.to_be_bytes())
        .await?;
    send.write_all(&body).await?;
    Ok((send, recv))
}

async fn read_exact(recv: &mut wtransport::RecvStream, buf: &mut [u8]) -> Result<(), Error> {
    let mut at = 0;
    while at < buf.len() {
        match recv.read(&mut buf[at..]).await? {
            Some(n) => at += n,
            None => return Err("stream ended inside a frame".into()),
        }
    }
    Ok(())
}

async fn read_frame(recv: &mut wtransport::RecvStream) -> Result<Value, Error> {
    let mut len = [0u8; 4];
    read_exact(recv, &mut len).await?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    read_exact(recv, &mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn call(conn: &Connection, command: Value) -> Result<Value, Error> {
    let (mut send, mut recv) = request(conn, &command).await?;
    send.finish().await?;
    read_frame(&mut recv).await
}

/// Datagram round trips, sent one every 10 ms and matched by sequence number.
async fn pings(conn: &Connection, count: u32) -> Vec<f64> {
    let started = Instant::now();
    let reader = {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut rtts = Vec::new();
            while let Ok(Ok(d)) =
                tokio::time::timeout(Duration::from_secs(2), conn.receive_datagram()).await
            {
                if d.len() >= 12 {
                    let sent_us = u64::from_be_bytes(d[4..12].try_into().unwrap_or_default());
                    let now_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
                    #[allow(clippy::cast_precision_loss)]
                    rtts.push(now_us.saturating_sub(sent_us) as f64 / 1000.0);
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
        let _ = conn.send_datagram(d);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    reader.await.unwrap_or_default()
}

#[allow(clippy::cast_precision_loss)]
fn mbps(bytes: u64, secs: f64) -> f64 {
    if secs > 0.0 {
        bytes as f64 * 8.0 / secs / 1e6
    } else {
        0.0
    }
}

async fn download(conn: &Connection, streams: usize, secs: u64) -> (u64, f64) {
    let total = Arc::new(AtomicU64::new(0));
    let started = Instant::now();
    let deadline = started + Duration::from_secs(secs);
    let tasks: Vec<_> = (0..streams)
        .map(|_| {
            let conn = conn.clone();
            let total = total.clone();
            tokio::spawn(async move {
                let command = json!({"op": "download", "bytes": 1u64 << 30, "max_secs": secs});
                let Ok((mut send, mut recv)) = request(&conn, &command).await else {
                    return;
                };
                let _ = send.finish().await;
                let mut buf = vec![0u8; 256 * 1024];
                let mut first = true;
                while Instant::now() < deadline {
                    match tokio::time::timeout_at(deadline.into(), recv.read(&mut buf)).await {
                        Ok(Ok(Some(n))) => {
                            let data = if first {
                                first = false;
                                n.saturating_sub(1)
                            } else {
                                n
                            };
                            total.fetch_add(data as u64, Ordering::Relaxed);
                        }
                        _ => break,
                    }
                }
            })
        })
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    (
        total.load(Ordering::Relaxed),
        started
            .elapsed()
            .as_secs_f64()
            .min(Duration::from_secs(secs).as_secs_f64()),
    )
}

/// Upload for `secs`; returns the node's meter and what this side wrote (which
/// runs ahead of the network by at most the send buffers, and is all a node
/// without the meter can be judged by).
async fn upload(conn: &Connection, streams: usize, secs: u64) -> Result<(Value, u64), Error> {
    let test = format!("{:032x}", rand::random::<u128>());
    let written = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(secs);
    // Random bytes: nothing on the path can compress them.
    let chunk: Arc<Vec<u8>> = Arc::new((0..64 * 1024).map(|_| rand::random::<u8>()).collect());
    let tasks: Vec<_> = (0..streams)
        .map(|_| {
            let conn = conn.clone();
            let chunk = chunk.clone();
            let test = test.clone();
            let written = written.clone();
            tokio::spawn(async move {
                let command = json!({"op": "upload", "bytes": 500u64 << 20, "test": test});
                let Ok((mut send, _recv)) = request(&conn, &command).await else {
                    return;
                };
                while Instant::now() < deadline {
                    if tokio::time::timeout_at(deadline.into(), send.write_all(&chunk))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                }
                let _ = send.finish().await;
            })
        })
        .collect();
    for t in tasks {
        let _ = t.await;
    }
    // Every stream finished: read the meter once nothing is still arriving.
    for _ in 0..40 {
        let meter = call(conn, json!({"op": "meter", "test": test})).await?;
        if meter.get("open").and_then(Value::as_u64) == Some(0) || meter.get("error").is_some() {
            return Ok((meter, written.load(Ordering::Relaxed)));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let meter = call(conn, json!({"op": "meter", "test": test})).await?;
    Ok((meter, written.load(Ordering::Relaxed)))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();
    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_native_certs()
            .build(),
    )?;
    let options = match &args.origin {
        Some(o) => ConnectOptions::builder(&args.url)
            .add_header("origin", o)
            .build(),
        None => ConnectOptions::builder(&args.url).build(),
    };
    let t0 = Instant::now();
    let conn = endpoint.connect(options).await?;
    println!("connected in {:.1} ms", t0.elapsed().as_secs_f64() * 1000.0);
    let info = call(&conn, json!({"op": "info"})).await?;
    println!(
        "node: {} ({}), congestion control {}",
        info["location_id"], info["server"], info["capabilities"]["congestion_control"]
    );

    let mut rtts = pings(&conn, args.pings).await;
    rtts.sort_by(f64::total_cmp);
    if let (Some(min), Some(max)) = (rtts.first(), rtts.last()) {
        println!(
            "datagram RTT: {} of {} answered, min {min:.2} ms, median {:.2} ms, max {max:.2} ms",
            rtts.len(),
            args.pings,
            rtts[rtts.len() / 2]
        );
    }

    let before = call(&conn, json!({"op": "transport"})).await?;
    let (bytes, secs) = download(&conn, args.down_streams, args.secs).await;
    let after = call(&conn, json!({"op": "transport"})).await?;
    println!(
        "download: {:.1} Mbps ({} bytes in {secs:.2} s, {} streams)",
        mbps(bytes, secs),
        bytes,
        args.down_streams
    );
    // What the node put on the wire for that download, and how much of it the
    // path dropped (so the node sent it again).
    let grew = |key: &str| {
        after[key]
            .as_u64()
            .unwrap_or(0)
            .saturating_sub(before[key].as_u64().unwrap_or(0))
    };
    let (sent, lost) = (grew("sent_bytes"), grew("lost_bytes"));
    if sent > 0 {
        #[allow(clippy::cast_precision_loss)]
        let share = lost as f64 / sent as f64 * 100.0;
        println!(
            "download on the wire (node's count): {:.1} Mbps sent, {share:.2}% lost and sent again, {} congestion events, {} congestion control",
            mbps(sent, secs),
            grew("congestion_events"),
            after["congestion_control"].as_str().unwrap_or("unnamed")
        );
    }

    let (meter, written) = upload(&conn, args.up_streams, args.secs).await?;
    #[allow(clippy::cast_precision_loss)]
    let secs = args.secs as f64;
    println!(
        "upload (written here): {:.1} Mbps ({written} bytes in {secs:.0} s, {} streams)",
        mbps(written, secs),
        args.up_streams
    );
    if meter.get("error").is_none() {
        let bytes = meter["bytes"].as_u64().unwrap_or(0);
        let span = meter["span_ms"].as_f64().unwrap_or(0.0) / 1000.0;
        println!(
            "upload (node's meter): {:.1} Mbps ({} bytes over {span:.2} s, {} streams)",
            mbps(bytes, span),
            bytes,
            meter["streams"]
        );
    } else {
        println!("upload (node's meter): this node has no meter");
    }
    conn.close(0u32.into(), b"done");
    Ok(())
}
