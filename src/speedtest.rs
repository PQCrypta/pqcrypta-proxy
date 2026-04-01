//! Native speed test session handler for WebTransport connections on /speedtest
//!
//! Handles WebTransport sessions at the /speedtest path directly, without
//! forwarding to any backend. Provides:
//!
//! - Datagram echo for RTT and packet loss measurement
//! - Download speed testing (server → client bulk data stream)
//! - Upload speed testing (client → server, server measures throughput)
//! - Server capability info query
//! - Route analysis (traceroute from server → client with GeoIP per hop)
//! - Client GeoIP lookup
//!
//! ## Wire Protocol
//!
//! All stream commands use a length-prefixed JSON frame:
//!   `[4-byte big-endian u32 length][JSON bytes]`
//!
//! ### Download
//! Client sends: framed `{"op":"download","bytes":N}`
//! Server sends: 1-byte status (`0x00` = ok, `0x01` = error) then raw bytes
//!               (or framed error JSON if status byte is `0x01`)
//!
//! ### Upload
//! Client sends: framed `{"op":"upload","bytes":N}` + N raw bytes + closes write side
//! Server sends: framed JSON result `{"bytes_received":M,"duration_ms":D,"throughput_mbps":T}`
//!
//! ### Info
//! Client sends: framed `{"op":"info"}`
//! Server sends: framed JSON capabilities
//!
//! ### GeoIP
//! Client sends: framed `{"op":"geoip"}`
//! Server sends: framed JSON with client IP location + ASN
//!
//! ### Traceroute
//! Client sends: framed `{"op":"traceroute"}`
//! Server sends: stream of framed JSON frames — one per hop — then a done frame.
//!   - `{"type":"client", "ip":"...", "city":"...", ...}` — client's geoip
//!   - `{"type":"hop", "hop":N, "ip":"...", "avg_rtt_ms":F, "org":"...", ...}` — one per hop
//!   - `{"type":"done", "total_hops":N}` — final frame
//!   - `{"type":"error", "error":"...", "message":"..."}` — on failure
//!
//! ### Datagrams
//! Any datagram >= 8 bytes is echoed back immediately. The client uses send
//! timestamps (embedded in the payload) to compute RTT and loss statistics.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use tokio::sync::mpsc;

use serde_json::{json, Value};
use tracing::{debug, error, info, warn};
use wtransport::Connection;

/// Maximum size for a single download: 1 GB (client enforces a time limit of 5–10 s;
/// this cap exists only to prevent runaway sessions on very slow paths).
const MAX_DOWNLOAD_BYTES: usize = 1024 * 1024 * 1024;

/// Maximum size for a single upload: 500 MB (client time-limits to 5–10 s).
const MAX_UPLOAD_BYTES: usize = 500 * 1024 * 1024;

/// Maximum framed command size: 64 KB
const MAX_FRAME_BYTES: usize = 65536;

/// Chunk size for streaming download data: 256 KB — reduces write syscalls, keeps QUIC buffer full
const DOWNLOAD_CHUNK: usize = 256 * 1024;

/// Minimum datagram size to prevent trivial amplification
const MIN_DATAGRAM_BYTES: usize = 8;

/// Traceroute: max hops
const TRACEROUTE_MAX_HOPS: u32 = 30;

/// GeoLite2 database paths (alongside the binary in data/geoip/)
const GEOIP_CITY_PATH: &str = "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb";
const GEOIP_ASN_PATH: &str = "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-ASN.mmdb";

// ─── GeoIP readers (lazy, loaded once) ────────────────────────────────────

#[cfg(feature = "geoip")]
static CITY_READER: OnceLock<Option<maxminddb::Reader<Vec<u8>>>> = OnceLock::new();

#[cfg(feature = "geoip")]
static ASN_READER: OnceLock<Option<maxminddb::Reader<Vec<u8>>>> = OnceLock::new();

// ─── GeoInfo ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct GeoInfo {
    city: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    lat: Option<f64>,
    lon: Option<f64>,
    asn: Option<u32>,
    org: Option<String>,
}

fn lookup_geoip(ip: IpAddr) -> GeoInfo {
    let mut info = GeoInfo::default();

    #[cfg(feature = "geoip")]
    {
        // ── City ─────────────────────────────────────────────────────────
        let city_slot =
            CITY_READER.get_or_init(|| match maxminddb::Reader::open_readfile(GEOIP_CITY_PATH) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("GeoLite2-City unavailable ({}): {}", GEOIP_CITY_PATH, e);
                    None
                }
            });
        if let Some(reader) = city_slot {
            if let Ok(result) = reader.lookup(ip) {
                if let Ok(Some(city)) = result.decode::<maxminddb::geoip2::City>() {
                    info.city = city.city.names.english.map(str::to_string);
                    info.country = city.country.names.english.map(str::to_string);
                    info.country_code = city.country.iso_code.map(str::to_string);
                    info.lat = city.location.latitude;
                    info.lon = city.location.longitude;
                }
            }
        }

        // ── ASN ──────────────────────────────────────────────────────────
        let asn_slot =
            ASN_READER.get_or_init(|| match maxminddb::Reader::open_readfile(GEOIP_ASN_PATH) {
                Ok(r) => Some(r),
                Err(e) => {
                    warn!("GeoLite2-ASN unavailable ({}): {}", GEOIP_ASN_PATH, e);
                    None
                }
            });
        if let Some(reader) = asn_slot {
            if let Ok(result) = reader.lookup(ip) {
                if let Ok(Some(asn)) = result.decode::<maxminddb::geoip2::Asn>() {
                    info.asn = asn.autonomous_system_number;
                    info.org = asn.autonomous_system_organization.map(str::to_string);
                }
            }
        }
    }

    info
}

fn geo_to_json(ip: &str, geo: &GeoInfo) -> Value {
    json!({
        "ip":           ip,
        "city":         geo.city,
        "country":      geo.country,
        "country_code": geo.country_code,
        "lat":          geo.lat,
        "lon":          geo.lon,
        "asn":          geo.asn,
        "org":          geo.org,
    })
}

// ─── IP safety check ──────────────────────────────────────────────────────

/// Returns `true` for IPs that should not be tracerouted to (loopback, private, etc.)
fn is_unsafe_for_traceroute(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast() || v6.is_unspecified(),
    }
}

/// Unwrap IPv6-mapped IPv4 addresses (::ffff:a.b.c.d → a.b.c.d)
fn normalise_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

// ─── Session entry point ──────────────────────────────────────────────────

/// Handle an established WebTransport session on the /speedtest path.
///
/// Called from `webtransport_server::handle_connection` when `path == "/speedtest"`.
pub async fn handle_speedtest_session(
    connection: Arc<Connection>,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("🏎️  Speed test session started: {}", remote_addr);

    loop {
        tokio::select! {
            bidi_result = connection.accept_bi() => {
                match bidi_result {
                    Ok((send_stream, recv_stream)) => {
                        debug!("📊 Speed test stream accepted from {}", remote_addr);
                        tokio::spawn(handle_speedtest_stream(
                            send_stream,
                            recv_stream,
                            remote_addr,
                        ));
                    }
                    Err(e) => {
                        debug!("Speed test bidi accept ended for {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            datagram_result = connection.receive_datagram() => {
                match datagram_result {
                    Ok(datagram) => {
                        if datagram.len() < MIN_DATAGRAM_BYTES {
                            warn!(
                                "Datagram too small from {} ({} bytes) — ignoring",
                                remote_addr,
                                datagram.len()
                            );
                            continue;
                        }
                        if let Err(e) = connection.send_datagram(&*datagram) {
                            debug!("Datagram echo failed for {}: {}", remote_addr, e);
                        }
                    }
                    Err(e) => {
                        debug!("Speed test datagram ended for {}: {}", remote_addr, e);
                        break;
                    }
                }
            }
        }
    }

    info!("🔚 Speed test session closed: {}", remote_addr);
    Ok(())
}

// ─── Per-stream handler ────────────────────────────────────────────────────

async fn handle_speedtest_stream(
    mut send: wtransport::stream::SendStream,
    mut recv: wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
) {
    if let Err(e) = run_speedtest_stream(&mut send, &mut recv, remote_addr).await {
        debug!("Speed test stream error for {}: {}", remote_addr, e);
        let err_payload = json!({"error": "internal_error"});
        let _ = write_framed_json(&mut send, &err_payload).await;
        let _ = send.finish().await;
    }
}

async fn run_speedtest_stream(
    send: &mut wtransport::stream::SendStream,
    recv: &mut wtransport::stream::RecvStream,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let command = read_framed_json(recv).await?;

    match command.get("op").and_then(|v| v.as_str()) {
        Some("info") => handle_op_info(send).await?,
        Some("download") => handle_op_download(send, &command, remote_addr).await?,
        Some("upload") => handle_op_upload(send, recv, &command, remote_addr).await?,
        Some("geoip") => handle_op_geoip(send, remote_addr).await?,
        Some("traceroute") => handle_op_traceroute(send, remote_addr).await?,
        Some(op) => {
            warn!("Unknown speedtest op '{}' from {}", op, remote_addr);
            write_framed_json(send, &json!({"error": "unknown_op", "op": op})).await?;
            send.finish().await?;
        }
        None => {
            warn!("Speedtest command missing 'op' from {}", remote_addr);
            write_framed_json(send, &json!({"error": "missing_op"})).await?;
            send.finish().await?;
        }
    }

    Ok(())
}

// ─── Operations ───────────────────────────────────────────────────────────

async fn handle_op_info(
    send: &mut wtransport::stream::SendStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server_name =
        std::env::var("SPEEDTEST_SERVER_NAME").unwrap_or_else(|_| "PQ Crypta".to_string());
    let location_id =
        std::env::var("SPEEDTEST_LOCATION_ID").unwrap_or_else(|_| "primary".to_string());
    let info = json!({
        "op": "info_result",
        "protocol": "speedtest/1",
        "server": server_name,
        "location_id": location_id,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": {
            "download":        true,
            "upload":          true,
            "datagrams":       true,
            "traceroute":      true,
            "geoip":           true,
            "post_quantum_tls": true,
            "max_download_bytes": MAX_DOWNLOAD_BYTES,
            "max_upload_bytes":   MAX_UPLOAD_BYTES,
            "max_traceroute_hops": TRACEROUTE_MAX_HOPS,
        },
        "server_ts_ms": chrono::Utc::now().timestamp_millis()
    });
    write_framed_json(send, &info).await?;
    send.finish().await?;
    Ok(())
}

async fn handle_op_download(
    send: &mut wtransport::stream::SendStream,
    command: &serde_json::Value,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let requested = usize::try_from(
        command
            .get("bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_000_000)
            .min(MAX_DOWNLOAD_BYTES as u64),
    )
    .unwrap_or(MAX_DOWNLOAD_BYTES);

    // Client passes max_secs so the server timeout matches the client-side test duration.
    // This prevents server download tasks from running past the client's cancel point, which
    // would cause download and upload to compete on the same QUIC connection.
    // Default 10 s is used only for clients that don't send max_secs (backward compat).
    let max_secs = command
        .get("max_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 30);

    if requested == 0 || requested > MAX_DOWNLOAD_BYTES {
        send.write_all(&[0x01_u8]).await?;
        write_framed_json(
            send,
            &json!({"error": "invalid_bytes", "max": MAX_DOWNLOAD_BYTES}),
        )
        .await?;
        send.finish().await?;
        return Ok(());
    }

    info!("📥 Download: {} bytes → {}", requested, remote_addr);

    send.write_all(&[0x00_u8]).await?;

    let chunk = generate_chunk(DOWNLOAD_CHUNK);
    let mut remaining = requested;
    let started = Instant::now();
    // Hard timeout = client's test duration (max_secs) + 1 s grace period.
    // STOP_SENDING from the client often does not unblock a write() that is stalled on
    // QUIC flow-control backpressure, so without this the download task keeps running for
    // the full 10 s default even though the client moved on to upload at 5 s.
    // The extra second allows the connection's QUIC CWND / window to drain normally.
    let download_timeout = std::time::Duration::from_secs(max_secs + 1);

    let result = tokio::time::timeout(download_timeout, async {
        while remaining > 0 {
            let to_send = remaining.min(DOWNLOAD_CHUNK);
            send.write_all(&chunk[..to_send]).await?;
            remaining -= to_send;
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            send.finish().await?;
        }
        Ok(Err(e)) => {
            // Client cancelled via STOP_SENDING — normal time-bounded termination
            debug!("Download stream ended early for {}: {}", remote_addr, e);
        }
        Err(_) => {
            info!(
                "Download timeout for {} after {}s",
                remote_addr,
                max_secs + 1
            );
        }
    }

    info!(
        "✅ Download done: {} bytes in {:.1}ms → {}",
        requested - remaining,
        started.elapsed().as_secs_f64() * 1000.0,
        remote_addr
    );
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
async fn handle_op_upload(
    send: &mut wtransport::stream::SendStream,
    recv: &mut wtransport::stream::RecvStream,
    command: &serde_json::Value,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let declared = usize::try_from(
        command
            .get("bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(1_000_000)
            .min(MAX_UPLOAD_BYTES as u64),
    )
    .unwrap_or(MAX_UPLOAD_BYTES);

    if declared == 0 || declared > MAX_UPLOAD_BYTES {
        write_framed_json(
            send,
            &json!({"error": "invalid_bytes", "max": MAX_UPLOAD_BYTES}),
        )
        .await?;
        send.finish().await?;
        return Ok(());
    }

    info!(
        "📤 Upload: expecting ~{} bytes from {}",
        declared, remote_addr
    );

    // Warmup: discard bytes received in the first 2 s (QUIC slow-start / CWND ramp-up).
    // steady_mbps is computed over the remaining window and is what the client displays.
    // throughput_mbps (overall average) is also reported for diagnostics.
    let warmup_dur = std::time::Duration::from_millis(2000);
    let mut start: Option<Instant> = None; // set on first data byte — excludes command-frame RTT
    let mut total_bytes: usize = 0;
    let mut post_warmup_bytes: usize = 0;
    let mut buf = vec![0u8; DOWNLOAD_CHUNK];
    let upload_timeout = std::time::Duration::from_secs(120);

    let read_result = tokio::time::timeout(upload_timeout, async {
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if start.is_none() {
                        start = Some(Instant::now()); // clock starts on first byte received
                    }
                    total_bytes += n;
                    // Count bytes that arrive after the warmup window has passed
                    if start.is_some_and(|s| s.elapsed() >= warmup_dur) {
                        post_warmup_bytes += n;
                    }
                    if total_bytes >= MAX_UPLOAD_BYTES {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
    .await;

    match read_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Upload read error from {}: {}", remote_addr, e),
        Err(_) => info!(
            "Upload timeout from {} (measured {} bytes)",
            remote_addr, total_bytes
        ),
    }

    let elapsed = start.map(|s| s.elapsed()).unwrap_or_default();
    let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let throughput_mbps = if elapsed.as_secs_f64() > 0.0 {
        (total_bytes as f64 * 8.0) / (elapsed.as_secs_f64() * 1_000_000.0)
    } else {
        0.0
    };

    // Steady-state throughput: bytes received after the warmup period / (elapsed - warmup).
    // Falls back to throughput_mbps if the test was too short to produce a steady window.
    let steady_mbps = if elapsed > warmup_dur {
        let steady_secs = (elapsed - warmup_dur).as_secs_f64();
        if steady_secs >= 0.5 && post_warmup_bytes > 0 {
            (post_warmup_bytes as f64 * 8.0) / (steady_secs * 1_000_000.0)
        } else {
            throughput_mbps
        }
    } else {
        throughput_mbps
    };

    info!(
        "✅ Upload done: {} bytes in {}ms (avg {:.1} Mbps, steady {:.1} Mbps) from {}",
        total_bytes, duration_ms, throughput_mbps, steady_mbps, remote_addr
    );

    write_framed_json(
        send,
        &json!({
            "op": "upload_result",
            "bytes_received":  total_bytes,
            "duration_ms":     duration_ms,
            "throughput_mbps": throughput_mbps,
            "steady_mbps":     steady_mbps,
            "server_ts_ms":    chrono::Utc::now().timestamp_millis()
        }),
    )
    .await?;
    send.finish().await?;
    Ok(())
}

/// Return the client's GeoIP information (city, country, ASN) based on their
/// connecting IP address.
async fn handle_op_geoip(
    send: &mut wtransport::stream::SendStream,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ip = normalise_ip(remote_addr.ip());
    let geo = lookup_geoip(ip);
    let mut resp = geo_to_json(&ip.to_string(), &geo);
    resp["op"] = json!("geoip_result");
    write_framed_json(send, &resp).await?;
    send.finish().await?;
    Ok(())
}

/// Determine the server's own public-facing IP by reading the primary outbound
/// interface address. Returns `None` if the address cannot be determined.
async fn get_server_public_ip() -> Option<String> {
    // Try reading from /etc/pqcrypta/server-ip if available (fast path)
    if let Ok(s) = tokio::fs::read_to_string("/etc/pqcrypta/server-ip").await {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    // Fall back: parse the source address from `ip route get 1.1.1.1`
    if let Ok(out) = tokio::process::Command::new("/usr/sbin/ip")
        .args(["route", "get", "1.1.1.1"])
        .output()
        .await
    {
        if let Ok(text) = std::str::from_utf8(&out.stdout) {
            // Output contains "src <IP>" somewhere in the first line
            if let Some(pos) = text.find("src ") {
                let rest = &text[pos + 4..];
                if let Some(end) = rest.find(|c: char| c.is_whitespace()) {
                    return Some(rest[..end].to_string());
                }
            }
        }
    }
    None
}

// ─── Multi-method traceroute helpers ─────────────────────────────────────

/// One hop result from a single mtr probe method.
struct MtrHopRaw {
    ttl: u32,
    ip: Option<String>,
    avg_rtt_ms: Option<f64>,
    best_rtt_ms: Option<f64>,
    worst_rtt_ms: Option<f64>,
    loss_pct: Option<f64>,
}

/// Merged hop from all probe methods at a given TTL.
#[derive(Default)]
struct MergedHop {
    ttl: u32,
    ip: Option<String>,
    avg_rtt_ms: Option<f64>,
    best_rtt_ms: Option<f64>,
    worst_rtt_ms: Option<f64>,
    loss_pct: Option<f64>,
    probe_methods: Vec<&'static str>,
    rtt_delta_ms: Option<f64>,
    congestion_suspect: bool,
}

/// Run one mtr probe toward `ip_str`.
/// `mode`: "icmp" | "udp" | "tcp"
async fn run_mtr_probe(ip_str: String, mode: &'static str, port: u16) -> Vec<MtrHopRaw> {
    let mut args: Vec<String> = vec![
        "--json".into(),
        "--no-dns".into(),
        "--report-cycles".into(),
        "1".into(), // 1 cycle is enough for path discovery; was 3 (3× slower)
        "--max-ttl".into(),
        "15".into(), // virtually all internet paths are ≤ 15 hops; was 20
        "--timeout".into(),
        "1".into(),
    ];
    match mode {
        "udp" => {
            args.push("--udp".into());
            args.push("--port".into());
            args.push(port.to_string());
        }
        "tcp" => {
            args.push("--tcp".into());
            args.push("--port".into());
            args.push(port.to_string());
        }
        _ => {} // icmp: default, no extra flags
    }
    args.push(ip_str);

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(12), // 15 hops × 1s timeout + 3s buffer; was 18
        tokio::process::Command::new("/usr/bin/mtr")
            .args(&args)
            .output(),
    )
    .await;

    let mut hops: Vec<MtrHopRaw> = Vec::new();
    if let Ok(Ok(output)) = result {
        if let Ok(text) = std::str::from_utf8(&output.stdout) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
                if let Some(hubs) = val["report"]["hubs"].as_array() {
                    for hub in hubs {
                        let ttl = hub["count"]
                            .as_u64()
                            .and_then(|v| u32::try_from(v).ok())
                            .unwrap_or(0);
                        let host = hub["host"].as_str().unwrap_or("???");
                        let ip = if host == "???" {
                            None
                        } else {
                            Some(host.to_string())
                        };
                        let avg = hub["Avg"].as_f64();
                        let best = hub["Best"].as_f64();
                        let worst = hub["Wrst"].as_f64();
                        // mtr JSON field is literally "Loss%"
                        let loss = hub["Loss%"]
                            .as_f64()
                            .or_else(|| hub["Loss%"].as_str().and_then(|s| s.parse().ok()));
                        hops.push(MtrHopRaw {
                            ttl,
                            ip,
                            avg_rtt_ms: avg,
                            best_rtt_ms: best,
                            worst_rtt_ms: worst,
                            loss_pct: loss,
                        });
                    }
                }
            }
        }
    }
    hops
}

/// Re-compute RTT deltas and congestion suspects on a BTreeMap of hops.
/// Called after each probe method's results are merged in.
fn annotate_rtt_deltas(hops: &mut BTreeMap<u32, MergedHop>) {
    let mut prev_rtt: Option<f64> = None;
    for hop in hops.values_mut() {
        if let (Some(curr), Some(prev)) = (hop.avg_rtt_ms, prev_rtt) {
            let delta = curr - prev;
            hop.rtt_delta_ms = Some(delta);
            hop.congestion_suspect = delta > 20.0;
        }
        if hop.avg_rtt_ms.is_some() {
            prev_rtt = hop.avg_rtt_ms;
        }
    }
}

/// Binary-search the path MTU toward `ip_str` using ping with the DF bit set.
/// Returns the discovered path MTU in bytes (IP payload + headers), or None.
async fn probe_path_mtu(ip_str: String) -> Option<u32> {
    // Probe sizes (ping -s is ICMP payload; add 28 = 20 IP + 8 ICMP for total MTU)
    // We test descending from near-Ethernet to minimum Internet MTU.
    let probes: &[u32] = &[1452, 1400, 1300, 1200, 1000, 800, 576];

    for &size in probes {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::process::Command::new("ping")
                .args([
                    "-c",
                    "1",
                    "-W",
                    "2",
                    "-M",
                    "do",
                    "-s",
                    &size.to_string(),
                    &ip_str,
                ])
                .output(),
        )
        .await;

        if let Ok(Ok(output)) = result {
            if output.status.success() {
                return Some(size + 28);
            }
            // Some kernels report "Frag needed" with the actual MTU in stderr/stdout
            let combined = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            if let Some(pos) = combined.find("mtu = ") {
                let rest = &combined[pos + 6..];
                if let Some(end) = rest.find(|c: char| !c.is_ascii_digit()) {
                    if let Ok(v) = rest[..end].parse::<u32>() {
                        return Some(v);
                    }
                }
            }
        }
    }
    None
}

/// Run a server-side multi-method route analysis toward the client IP and stream frames back.
/// Sends: client GeoIP → merged hops (ICMP+UDP+TCP parallel) → server frame → done.
async fn handle_op_traceroute(
    send: &mut wtransport::stream::SendStream,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_ip = normalise_ip(remote_addr.ip());

    // Always send the client GeoIP frame first so the UI can show origin even when
    // traceroute probing isn't possible (e.g. when the client is on the same LAN and
    // the QUIC endpoint sees a private/RFC-1918 source address).
    let client_geo = lookup_geoip(client_ip);
    let mut origin = geo_to_json(&client_ip.to_string(), &client_geo);
    origin["type"] = json!("client");
    write_framed_json(send, &origin).await?;

    if is_unsafe_for_traceroute(&client_ip) {
        write_framed_json(
            send,
            &json!({
                "type": "error",
                "error": "private_ip",
                "message": "Route analysis not available: server sees a private address for this connection"
            }),
        )
        .await?;
        send.finish().await?;
        return Ok(());
    }

    info!("🗺️  Multi-method traceroute → {} starting", client_ip);

    let ip_str = client_ip.to_string();

    // ── Spawn four concurrent probe methods ───────────────────────────────
    // UDP/4433 targets the live QUIC port: routers that silently drop ICMP or
    // UDP/53 probes often still generate TTL-exceeded ICMP for traffic toward
    // a port they've already seen in use, giving hop visibility others miss.
    let (tx, mut rx) = mpsc::channel::<(&'static str, Vec<MtrHopRaw>)>(5);
    for &(label, mode, port) in &[
        ("icmp", "icmp", 0u16),
        ("udp/53", "udp", 53),
        ("tcp/80", "tcp", 80),
        ("udp/4433", "udp", 4433),
    ] {
        let ip = ip_str.clone();
        let tx2 = tx.clone();
        tokio::spawn(async move {
            let hops = run_mtr_probe(ip, mode, port).await;
            let _ = tx2.send((label, hops)).await;
        });
    }
    drop(tx); // channel closes when all four tasks have sent

    // Path MTU runs in the background; we await it just before the done frame.
    let mtu_handle = tokio::spawn(probe_path_mtu(ip_str.clone()));

    // ── Receive method results and stream hops as each method completes ───
    let mut merged: BTreeMap<u32, MergedHop> = BTreeMap::new();
    let mut sent_ttls: HashSet<u32> = HashSet::new();
    let mut probe_methods_tried: Vec<&'static str> = Vec::new();

    while let Some((label, raw_hops)) = rx.recv().await {
        probe_methods_tried.push(label);

        // Merge this method's data into the shared hop map
        for raw in raw_hops {
            let entry = merged.entry(raw.ttl).or_insert_with(|| MergedHop {
                ttl: raw.ttl,
                ..Default::default()
            });
            let raw_had_ip = raw.ip.is_some();
            if entry.ip.is_none() {
                entry.ip = raw.ip;
            }
            match (entry.avg_rtt_ms, raw.avg_rtt_ms) {
                (None, Some(v)) => entry.avg_rtt_ms = Some(v),
                (Some(a), Some(b)) if b < a => entry.avg_rtt_ms = Some(b),
                _ => {}
            }
            match (entry.best_rtt_ms, raw.best_rtt_ms) {
                (None, Some(v)) => entry.best_rtt_ms = Some(v),
                (Some(a), Some(b)) if b < a => entry.best_rtt_ms = Some(b),
                _ => {}
            }
            match (entry.worst_rtt_ms, raw.worst_rtt_ms) {
                (None, Some(v)) => entry.worst_rtt_ms = Some(v),
                (Some(a), Some(b)) if b > a => entry.worst_rtt_ms = Some(b),
                _ => {}
            }
            if raw_had_ip && entry.loss_pct.is_none() {
                entry.loss_pct = raw.loss_pct;
            }
            if !entry.probe_methods.contains(&label) {
                entry.probe_methods.push(label);
            }
        }

        // Re-annotate RTT deltas with the updated merged set
        annotate_rtt_deltas(&mut merged);

        // Stream any newly-visible hops (not yet sent to client)
        for (&ttl, hop) in &merged {
            if hop.ip.is_none() || sent_ttls.contains(&ttl) {
                continue;
            }
            sent_ttls.insert(ttl);

            let ip_ref = hop.ip.as_deref().unwrap_or("");
            let mut frame = json!({
                "type":               "hop",
                "hop":                hop.ttl,
                "ip":                 ip_ref,
                "avg_rtt_ms":         hop.avg_rtt_ms,
                "best_rtt_ms":        hop.best_rtt_ms,
                "worst_rtt_ms":       hop.worst_rtt_ms,
                "loss_pct":           hop.loss_pct,
                "probe_methods":      hop.probe_methods,
                "rtt_delta_ms":       hop.rtt_delta_ms,
                "congestion_suspect": hop.congestion_suspect,
            });

            if let Ok(hop_ip) = ip_ref.parse::<IpAddr>() {
                if !is_unsafe_for_traceroute(&hop_ip) {
                    let geo = lookup_geoip(hop_ip);
                    frame["city"] = json!(geo.city);
                    frame["country"] = json!(geo.country);
                    frame["country_code"] = json!(geo.country_code);
                    frame["lat"] = json!(geo.lat);
                    frame["lon"] = json!(geo.lon);
                    frame["asn"] = json!(geo.asn);
                    frame["org"] = json!(geo.org);
                }
            }

            write_framed_json(send, &frame).await?;
        }
    }

    // Final counts
    let hop_count =
        u32::try_from(merged.values().filter(|h| h.ip.is_some()).count()).unwrap_or(u32::MAX);
    let hidden_count =
        u32::try_from(merged.values().filter(|h| h.ip.is_none()).count()).unwrap_or(u32::MAX);
    let congestion_count =
        u32::try_from(merged.values().filter(|h| h.congestion_suspect).count()).unwrap_or(u32::MAX);

    // ── Server terminal frame ─────────────────────────────────────────────
    let server_ip_str = get_server_public_ip().await;
    let server_geo = if let Some(ref s) = server_ip_str {
        s.parse::<IpAddr>().ok().map(lookup_geoip)
    } else {
        None
    };
    write_framed_json(
        send,
        &json!({
            "type":         "server",
            "ip":           server_ip_str,
            "city":         server_geo.as_ref().and_then(|g| g.city.as_deref()),
            "country":      server_geo.as_ref().and_then(|g| g.country.as_deref()),
            "country_code": server_geo.as_ref().and_then(|g| g.country_code.as_deref()),
            "org":          server_geo.as_ref().and_then(|g| g.org.as_deref()),
        }),
    )
    .await?;

    // ── Done frame ────────────────────────────────────────────────────────
    let path_mtu = mtu_handle.await.unwrap_or(None);
    write_framed_json(
        send,
        &json!({
            "type":                "done",
            "total_hops":          hop_count,
            "hidden_hops":         hidden_count,
            "path_mtu_bytes":      path_mtu,
            "congestion_hops":     congestion_count,
            "probe_methods_tried": probe_methods_tried,
        }),
    )
    .await?;

    info!(
        "🗺️  Traceroute done: {} visible, {} filtered, {} congestion suspects, MTU {:?}, methods {:?} → {}",
        hop_count, hidden_count, congestion_count, path_mtu, probe_methods_tried, client_ip
    );
    send.finish().await?;
    Ok(())
}

// ─── Frame I/O helpers ────────────────────────────────────────────────────

/// Read a length-prefixed JSON frame: `[4-byte BE u32][JSON bytes]`
async fn read_framed_json(
    recv: &mut wtransport::stream::RecvStream,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    read_exact(recv, &mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;

    if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
        return Err(format!(
            "frame length {} out of range [1, {}]",
            frame_len, MAX_FRAME_BYTES
        )
        .into());
    }

    let mut body = vec![0u8; frame_len];
    read_exact(recv, &mut body).await?;

    Ok(serde_json::from_slice(&body)?)
}

/// Write a length-prefixed JSON frame: `[4-byte BE u32][JSON bytes]`
async fn write_framed_json(
    send: &mut wtransport::stream::SendStream,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(value)?;
    let len = u32::try_from(bytes.len())
        .expect("frame too large")
        .to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Read exactly `buf.len()` bytes from a wtransport RecvStream.
async fn read_exact(
    recv: &mut wtransport::stream::RecvStream,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut pos = 0;
    while pos < buf.len() {
        match recv.read(&mut buf[pos..]).await {
            Ok(Some(n)) => pos += n,
            Ok(None) => {
                return Err(format!("unexpected EOF after {} of {} bytes", pos, buf.len()).into())
            }
            Err(e) => return Err(format!("stream read error: {}", e).into()),
        }
    }
    Ok(())
}

// ─── Data generation ──────────────────────────────────────────────────────

/// Generate a pseudo-random chunk for download testing via xorshift64.
///
/// Avoids all-zeros to prevent ISP compression from inflating apparent speeds.
fn generate_chunk(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for chunk in data.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        let len = chunk.len();
        chunk.copy_from_slice(&bytes[..len]);
    }
    data
}
