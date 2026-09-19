//! Does lsquic complete a handshake against the suite's smallest windows?
//!
//! `q-flow-control` (port 4466) advertises `receive_window` 1024 and
//! `stream_receive_window` 512 — the smallest in the catalogue — and lsquic
//! times out during the handshake there in roughly two runs of three, while
//! ngtcp2 completes on the identical port (139 packets to lsquic's 8). Two
//! hypotheses fit every fact:
//!
//!   1. lsquic cannot complete a handshake under a 1024-byte connection
//!      receive window. A client finding.
//!   2. Something else about this endpoint's first flight defeats it, and the
//!      window is a coincidence of which port it was noticed on.
//!
//! The experiment is the smallest thing that separates them: a plain quinn
//! server, nothing from the conformance listener, run twice — once with those
//! windows and once with quinn's defaults — driven by the same lsquic binary.
//! Both arms are built and run before either is read, because this is exactly
//! the shape where knowing the first result colours the second.
//!
//! Ignored by default: it shells out to `/opt/h3-clients/lsquic-get`, which
//! exists on the fleet host and nowhere else.
//!
//! ## Result, 2026-09-19
//!
//! Hypothesis 1. Measured on a plain quinn endpoint:
//!
//! ```text
//!   receive_window 1024 / stream 512     0 of 6 handshakes completed
//!   quinn defaults                       6 of 6
//!   receive_window 1024 only             0 of 5
//!   stream_receive_window 512 only       0 of 5
//!   receive_window 65536 only            5 of 5
//!   stream_receive_window 65536 only     5 of 5
//! ```
//!
//! Either knob alone stops it at small values; either alone is fine at 64 KB.
//! And it does not decline — quinn reports `timed out`, so lsquic stops
//! responding mid-handshake rather than closing with an error code.
//!
//! What that measures is settled. What it *means* is a reading, and worth
//! keeping separate: RFC 9000 governs CRYPTO frames by their own buffering
//! (§7.5) rather than by MAX_DATA or MAX_STREAM_DATA, so a small
//! `initial_max_data` should not be able to prevent a handshake from
//! completing. On that reading this is a defect. If instead lsquic is
//! deliberately abandoning a configuration it judges unusable, that is a
//! choice it is entitled to make — but §10.2 wants an immediate close to
//! carry CONNECTION_CLOSE, and going quiet is not one.
//!
//! Consequence for the matrix: lsquic's `q-flow-control` cell is inconclusive
//! because the client never reached the anomaly, and that is now known to be
//! the client's limit rather than the suite's blindness. The cell text was
//! already accurate; only the cause was missing.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::zero_rtt::{throwaway_cert, OneCert};

/// One arm: bind a plain quinn endpoint with `tune` applied, run the client at
/// it `attempts` times, and report how many handshakes completed.
async fn arm(
    label: &str,
    attempts: usize,
    tune: impl Fn(&mut quinn::TransportConfig),
) -> (usize, usize) {
    let throwaway = throwaway_cert();
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(crate::tls::build_pqc_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
    config.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .expect("building the QUIC config"),
    );
    let mut server_config = quinn::ServerConfig::with_crypto(crypto);
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .expect("10s is a valid idle timeout"),
    ));
    tune(&mut transport);
    server_config.transport = Arc::new(transport);

    let endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding a loopback port");
    let addr = endpoint.local_addr().expect("the server is bound");

    let completed = Arc::new(AtomicUsize::new(0));
    let accepting = {
        let completed = Arc::clone(&completed);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let completed = Arc::clone(&completed);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(_) => {
                            // The handshake is the whole question. Hold it
                            // briefly so the client is not racing a close.
                            completed.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        // How it fails is the difference between a client
                        // declining a configuration it cannot use and one that
                        // simply stops talking.
                        Err(e) => println!("      handshake failed: {e}"),
                    }
                });
            }
        })
    };

    for _ in 0..attempts {
        let url = format!("https://127.0.0.1:{}/", addr.port());
        let _ = tokio::process::Command::new("/opt/h3-clients/lsquic-get")
            .arg(&url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .status()
            .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Long enough for a stalled handshake to reach quinn's idle timeout and
    // report itself. Short grace hid the reason entirely on the first run.
    tokio::time::sleep(Duration::from_secs(12)).await;
    accepting.abort();

    let got = completed.load(Ordering::Relaxed);
    println!("  {label:<38} {got} of {attempts} handshakes completed");
    (got, attempts)
}

/// Which of the two knobs does it?
///
/// It matters for what the finding is. RFC 9000 §4.1 excludes CRYPTO frames
/// from both connection and stream flow control, so neither limit should be
/// able to prevent a handshake — but the two fail differently if one of them
/// can. Run as four arms, all before any is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "drives the real lsquic binary at /opt/h3-clients: fleet host only, and not fixable in CI — it records a finding rather than guarding one"]
async fn which_window_stops_lsquic() {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    const N: usize = 5;
    println!("\nisolating the knob:");
    let conn_only = arm("receive_window 1024 only", N, |t| {
        t.receive_window(quinn::VarInt::from_u32(1024));
    })
    .await;
    let stream_only = arm("stream_receive_window 512 only", N, |t| {
        t.stream_receive_window(quinn::VarInt::from_u32(512));
    })
    .await;
    let conn_64k = arm("receive_window 65536 only", N, |t| {
        t.receive_window(quinn::VarInt::from_u32(65536));
    })
    .await;
    let stream_64k = arm("stream_receive_window 65536 only", N, |t| {
        t.stream_receive_window(quinn::VarInt::from_u32(65536));
    })
    .await;
    println!(
        "\n  connection 1024: {}/{}   stream 512: {}/{}\n  connection 64K: {}/{}   stream 64K: {}/{}",
        conn_only.0, conn_only.1, stream_only.0, stream_only.1,
        conn_64k.0, conn_64k.1, stream_64k.0, stream_64k.1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "drives the real lsquic binary at /opt/h3-clients: fleet host only, and not fixable in CI — it records a finding rather than guarding one"]
async fn lsquic_against_tight_and_default_windows() {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    const ATTEMPTS: usize = 4;

    println!("\nlsquic, plain quinn endpoint, nothing from the conformance listener:");
    // Both arms run before either is judged.
    let tight = arm("receive_window 1024 / stream 512", ATTEMPTS, |t| {
        t.receive_window(quinn::VarInt::from_u32(1024));
        t.stream_receive_window(quinn::VarInt::from_u32(512));
    })
    .await;
    let default = arm("quinn defaults", ATTEMPTS, |_| {}).await;

    println!(
        "\n  tight  {}/{}\n  default {}/{}",
        tight.0, tight.1, default.0, default.1
    );
    println!(
        "  => {}",
        match (tight.0 == 0, default.0 > 0) {
            (true, true) => "the window is the cause: lsquic cannot handshake under it",
            (false, true) => "the window is not the cause: lsquic handshakes under both",
            (_, false) => "inconclusive: lsquic did not complete against defaults either",
        }
    );
}
