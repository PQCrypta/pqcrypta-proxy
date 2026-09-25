//! Hold concurrent WebTransport sessions from one origin, and check the node
//! stays responsive while they are open.
//!
//! A session used to hold a lock on the per-origin counter for as long as it
//! lived, and each further session from the same origin parked a runtime
//! worker waiting for it: `worker_threads` + 1 sessions stopped the whole proxy
//! (`webtransport_server.rs`, `OriginSlot`). This opens that many and more, then
//! for as long as they are held opens one more session and makes one HTTPS
//! request every second, timing both. Run it from another host: loopback skips
//! the security layers a real client meets.
//!
//! ```text
//! cargo run --release --example wt-sessions -- \
//!     https://api.pqcrypta.com:4433/webtransport https://pqcrypta.com/ \
//!     --sessions 8 --hold 20 --origin https://pqcrypta.com
//! ```
//!
//! Exits non-zero if any held session was refused, or if any probe went
//! unanswered for five seconds.

use std::time::{Duration, Instant};

use clap::Parser;
use wtransport::endpoint::ConnectOptions;
use wtransport::{ClientConfig, Endpoint};

#[derive(Parser)]
struct Args {
    /// WebTransport URL to hold sessions on.
    wt_url: String,
    /// HTTPS URL on the same node, requested once a second while they are held.
    https_url: String,
    /// Concurrent sessions to hold.
    #[arg(long, default_value_t = 8)]
    sessions: usize,
    /// Seconds to hold them.
    #[arg(long, default_value_t = 20)]
    hold: u64,
    /// Origin header to send; the node must list it as allowed.
    #[arg(long)]
    origin: Option<String>,
}

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn options(args: &Args) -> ConnectOptions {
    let builder = ConnectOptions::builder(&args.wt_url);
    match &args.origin {
        Some(o) => builder.add_header("origin", o).build(),
        None => builder.build(),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_native_certs()
            .build(),
    )
    .expect("client endpoint");
    let http = reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .build()
        .expect("HTTP client");
    let mut bad = 0;

    // Opened together, as a page's reconnects arrive: one after another would
    // let each finish its handshake before the next asked for a slot.
    let opened = futures::future::join_all(
        (0..args.sessions)
            .map(|_| tokio::time::timeout(PROBE_TIMEOUT * 2, endpoint.connect(options(&args)))),
    )
    .await;
    let mut held = Vec::new();
    for (n, r) in opened.into_iter().enumerate() {
        match r {
            Ok(Ok(c)) => held.push(c),
            Ok(Err(e)) => {
                bad += 1;
                println!("session {n}: refused: {e}");
            }
            Err(_) => {
                bad += 1;
                println!("session {n}: never answered");
            }
        }
    }
    println!(
        "holding {} of {} session(s) for {}s",
        held.len(),
        args.sessions,
        args.hold
    );

    let end = Instant::now() + Duration::from_secs(args.hold);
    while Instant::now() < end {
        let t = Instant::now();
        let wt = match tokio::time::timeout(PROBE_TIMEOUT, endpoint.connect(options(&args))).await {
            Ok(Ok(c)) => {
                c.close(0u32.into(), b"probe");
                format!("{:>5} ms", t.elapsed().as_millis())
            }
            Ok(Err(e)) => {
                bad += 1;
                format!("refused ({e})")
            }
            Err(_) => {
                bad += 1;
                "UNANSWERED".to_string()
            }
        };
        let t = Instant::now();
        let https = match http.get(&args.https_url).send().await {
            Ok(r) => format!(
                "{} in {:>5} ms",
                r.status().as_u16(),
                t.elapsed().as_millis()
            ),
            Err(e) => {
                bad += 1;
                format!("FAILED ({e})")
            }
        };
        println!("  one more session: {wt:<12}  https: {https}");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    for c in &held {
        c.close(0u32.into(), b"done");
    }
    if bad > 0 {
        println!("{bad} failure(s)");
        std::process::exit(1);
    }
    println!("ok: the node answered throughout");
}
