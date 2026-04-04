#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops
)]
//! WebTransport Telemetry Wall — native handler for the `/telemetry` path
//!
//! Provides independent QUIC stream channels for real-time transport-layer
//! visualisation.  Each throughput channel runs in its own tokio task; an
//! impairment applied to one channel does **not** affect any other channel,
//! demonstrating true QUIC stream isolation vs TCP / HTTP/2 / WebSockets.
//!
//! ## Session lifecycle
//! 1. Client connects to `wss://api.pqcrypta.com:4433/telemetry`
//! 2. Server spawns 6 throughput channels (server-opened uni-streams, pushing
//!    bulk data continuously + per-frame metrics)
//! 3. Server spawns 1 stats channel (RTT, CWND, CPU, mem — 10 Hz)
//! 4. Client opens a control bidi-stream; sends impairment / heal commands
//! 5. Datagrams are echoed for RTT / loss measurement (same as /speedtest)
//!
//! ## Wire protocol
//! All stream frames use 4-byte big-endian length prefix followed by JSON:
//!   `[u32 BE length][JSON bytes]`
//!
//! ### Server → client channel header (first frame on every uni-stream)
//! ```json
//! {"stream_type":"channel_header","channel":"ch1","rate_hz":20}
//! ```
//!
//! ### Throughput channel data frame
//! ```json
//! {"t":1234567.890,"seq":42,"channel":"ch1","bytes_total":1048576,
//!  "impaired":false,"impairment":null}
//! ```
//!
//! ### Stats channel data frame
//! ```json
//! {"t":1234567.890,"rtt_ms":23.5,"cwnd_bytes":1250000,
//!  "cpu_pct":8.3,"mem_pct":42.1,"uptime_s":86400}
//! ```
//!
//! ### Control channel — client → server commands
//! ```json
//! {"cmd":"impair","channel":"ch3","type":"delay_ms","intensity":200.0,
//!  "pattern":"burst","burst_freq_s":5.0,"burst_dur_ms":500.0,"duration_s":30.0}
//!
//! {"cmd":"heal","channel":"ch3"}
//! {"cmd":"heal_all"}
//! ```
//!
//! ### Control channel — server → client ack
//! ```json
//! {"type":"ack","cmd":"impair","channel":"ch3","ok":true}
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use wtransport::Connection;

// ─── Constants ────────────────────────────────────────────────────────────────

const CHANNEL_NAMES: &[&str] = &["ch1", "ch2", "ch3", "ch4", "ch5", "ch6"];
/// Virtual bytes credited per metrics frame — used by impairment pacing and throughput display.
/// 32 KB × 20 Hz = ~5 Mbps per channel (all framed JSON, no raw binary).
const VIRTUAL_CHUNK_BYTES: u64 = 32 * 1024;
/// Base frame interval without impairment — 20 Hz.
const FRAME_INTERVAL_MS: u64 = 50;
const MAX_FRAME_BYTES: usize = 65_536;
const MIN_DATAGRAM_BYTES: usize = 8;
const STATS_INTERVAL_MS: u64 = 100; // 10 Hz stats push

// ─── Impairment types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum ImpairmentType {
    None,
    DelayMs,       // sleep N ms before each write
    LossPct,       // skip write with probability p (0.0–1.0)
    BandwidthKbps, // token-bucket rate limiter
    JitterMs,      // random delay ±σ ms
    Disconnect,    // close stream; outer loop reopens it
}

impl ImpairmentType {
    fn from_str(s: &str) -> Self {
        match s {
            "delay_ms" => ImpairmentType::DelayMs,
            "loss_pct" => ImpairmentType::LossPct,
            "bandwidth_kbps" => ImpairmentType::BandwidthKbps,
            "jitter_ms" => ImpairmentType::JitterMs,
            "disconnect" => ImpairmentType::Disconnect,
            _ => ImpairmentType::None,
        }
    }

    fn to_str(&self) -> &'static str {
        match self {
            ImpairmentType::None => "none",
            ImpairmentType::DelayMs => "delay_ms",
            ImpairmentType::LossPct => "loss_pct",
            ImpairmentType::BandwidthKbps => "bandwidth_kbps",
            ImpairmentType::JitterMs => "jitter_ms",
            ImpairmentType::Disconnect => "disconnect",
        }
    }
}

// ─── Impairment patterns ──────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum ImpairmentPattern {
    Fixed,   // constant intensity
    Random,  // uniform random in [rand_min, rand_max] each evaluation
    Sine,    // sinusoidal oscillation 0 → intensity → 0 over period_s
    Square,  // alternates between intensity and 0 with period_s
    Burst,   // full intensity for burst_dur_ms every burst_freq_s seconds
    Ramp,    // linearly increases 0 → intensity over ramp_s then resets
    Cascade, // staircase: increases in cascade_steps steps then decreases
}

impl ImpairmentPattern {
    fn from_str(s: &str) -> Self {
        match s {
            "random" => ImpairmentPattern::Random,
            "sine" => ImpairmentPattern::Sine,
            "square" => ImpairmentPattern::Square,
            "burst" => ImpairmentPattern::Burst,
            "ramp" => ImpairmentPattern::Ramp,
            "cascade" => ImpairmentPattern::Cascade,
            _ => ImpairmentPattern::Fixed,
        }
    }
}

// ─── Impairment configuration ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ImpairmentConfig {
    active: bool,
    imp_type: ImpairmentType,
    pattern: ImpairmentPattern,
    intensity: f64, // primary intensity (ms, probability 0–1, or kbps)
    rand_min: f64,
    rand_max: f64,
    period_s: f64,
    burst_freq_s: f64,
    burst_dur_ms: f64,
    ramp_s: f64,
    cascade_step_s: f64,
    cascade_steps: u32,
    duration_s: Option<f64>,
    started_at: Option<Instant>,
}

impl Default for ImpairmentConfig {
    fn default() -> Self {
        ImpairmentConfig {
            active: false,
            imp_type: ImpairmentType::None,
            pattern: ImpairmentPattern::Fixed,
            intensity: 0.0,
            rand_min: 0.0,
            rand_max: 1.0,
            period_s: 3.0,
            burst_freq_s: 5.0,
            burst_dur_ms: 500.0,
            ramp_s: 10.0,
            cascade_step_s: 2.0,
            cascade_steps: 5,
            duration_s: None,
            started_at: None,
        }
    }
}

/// Compute the effective impairment intensity for the given elapsed seconds.
fn compute_intensity(cfg: &ImpairmentConfig, elapsed_s: f64) -> f64 {
    use std::f64::consts::PI;
    match cfg.pattern {
        ImpairmentPattern::Fixed => cfg.intensity,

        ImpairmentPattern::Random => {
            let mut rng = rand::thread_rng();
            cfg.rand_min + rng.gen::<f64>() * (cfg.rand_max - cfg.rand_min)
        }

        ImpairmentPattern::Sine => {
            let phase = (elapsed_s / cfg.period_s * 2.0 * PI).sin();
            cfg.intensity * (phase + 1.0) / 2.0
        }

        ImpairmentPattern::Square => {
            let t = elapsed_s % cfg.period_s;
            if t < cfg.period_s / 2.0 {
                cfg.intensity
            } else {
                0.0
            }
        }

        ImpairmentPattern::Burst => {
            let t = elapsed_s % cfg.burst_freq_s;
            if t < cfg.burst_dur_ms / 1000.0 {
                cfg.intensity
            } else {
                0.0
            }
        }

        ImpairmentPattern::Ramp => {
            let t = elapsed_s % cfg.ramp_s;
            cfg.intensity * (t / cfg.ramp_s)
        }

        ImpairmentPattern::Cascade => {
            let steps = cfg.cascade_steps as f64;
            let cycle = cfg.cascade_steps * 2;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let step = ((elapsed_s / cfg.cascade_step_s) as u32) % cycle;
            let normalized = if step < cfg.cascade_steps {
                step as f64 / steps
            } else {
                (cycle - step) as f64 / steps
            };
            cfg.intensity * normalized
        }
    }
}

/// Parse an impairment command JSON into an `ImpairmentConfig`.
fn parse_impairment_cmd(cmd: &Value) -> ImpairmentConfig {
    let imp_type = cmd["type"]
        .as_str()
        .map(ImpairmentType::from_str)
        .unwrap_or(ImpairmentType::None);
    let pattern = cmd["pattern"]
        .as_str()
        .map(ImpairmentPattern::from_str)
        .unwrap_or(ImpairmentPattern::Fixed);
    let intensity = cmd["intensity"].as_f64().unwrap_or(0.0);
    let duration_s = cmd["duration_s"].as_f64();

    ImpairmentConfig {
        active: true,
        imp_type,
        pattern,
        intensity,
        rand_min: cmd["rand_min"].as_f64().unwrap_or(0.0),
        rand_max: cmd["rand_max"].as_f64().unwrap_or(intensity),
        period_s: cmd["period_s"].as_f64().unwrap_or(3.0),
        burst_freq_s: cmd["burst_freq_s"].as_f64().unwrap_or(5.0),
        burst_dur_ms: cmd["burst_dur_ms"].as_f64().unwrap_or(500.0),
        ramp_s: cmd["ramp_s"].as_f64().unwrap_or(10.0),
        cascade_step_s: cmd["cascade_step_s"].as_f64().unwrap_or(2.0),
        cascade_steps: cmd["cascade_steps"].as_u64().unwrap_or(5) as u32,
        duration_s,
        started_at: Some(Instant::now()),
    }
}

// ─── Token bucket for bandwidth limiting ──────────────────────────────────────

struct TokenBucket {
    tokens: f64,   // bytes available
    capacity: f64, // max bytes (burst ceiling)
    rate: f64,     // bytes per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(kbps: f64) -> Self {
        let rate = kbps * 1000.0 / 8.0; // bytes/s
        let capacity = (rate * 0.2).max(4096.0); // 200 ms burst
        TokenBucket {
            tokens: capacity,
            capacity,
            rate,
            last_refill: Instant::now(),
        }
    }

    /// Consume `bytes` from the bucket; returns how long to sleep if insufficient.
    fn consume(&mut self, bytes: usize) -> Duration {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.last_refill = now;

        let needed = bytes as f64;
        if self.tokens >= needed {
            self.tokens -= needed;
            Duration::ZERO
        } else {
            let deficit = needed - self.tokens;
            self.tokens = 0.0;
            Duration::from_secs_f64(deficit / self.rate)
        }
    }
}

// ─── Shared session state ─────────────────────────────────────────────────────

type ChannelMap = HashMap<String, Arc<RwLock<ImpairmentConfig>>>;

// ─── Session entry point ──────────────────────────────────────────────────────

/// Handle an established WebTransport session on the `/telemetry` path.
/// Called from `webtransport_server::handle_connection` when `path == "/telemetry"`.
pub async fn handle_telemetry_session(
    connection: Arc<Connection>,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("📡 Telemetry Wall session started: {}", remote_addr);

    // Shared impairment state — one RwLock per channel
    let channels: Arc<ChannelMap> = Arc::new(
        CHANNEL_NAMES
            .iter()
            .map(|&name| {
                (
                    name.to_string(),
                    Arc::new(RwLock::new(ImpairmentConfig::default())),
                )
            })
            .collect(),
    );

    // Spawn the stats push channel (server-initiated uni-stream, 10 Hz)
    {
        let conn = Arc::clone(&connection);
        tokio::spawn(async move {
            if let Err(e) = run_stats_channel(conn).await {
                debug!("Telemetry stats channel ended: {}", e);
            }
        });
    }

    // Spawn one throughput channel per CHANNEL_NAME (independent uni-streams)
    for &name in CHANNEL_NAMES {
        let conn = Arc::clone(&connection);
        let imp = Arc::clone(channels.get(name).expect("channel exists"));
        let cid = name.to_string();
        tokio::spawn(async move {
            if let Err(e) = run_throughput_channel(conn, cid, imp).await {
                debug!("Telemetry throughput channel ended: {}", e);
            }
        });
    }

    // Main loop: datagram echo + accept control streams
    loop {
        tokio::select! {
            bidi_result = connection.accept_bi() => {
                match bidi_result {
                    Ok((send_s, recv_s)) => {
                        let ch = Arc::clone(&channels);
                        tokio::spawn(async move {
                            if let Err(e) = handle_control_stream(send_s, recv_s, ch).await {
                                debug!("Control stream error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        debug!("Telemetry bidi accept closed for {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            dg_result = connection.receive_datagram() => {
                match dg_result {
                    Ok(dg) => {
                        if dg.len() >= MIN_DATAGRAM_BYTES {
                            if let Err(e) = connection.send_datagram(&*dg) {
                                debug!("Datagram echo failed for {}: {}", remote_addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Telemetry datagram ended for {}: {}", remote_addr, e);
                        break;
                    }
                }
            }
        }
    }

    info!("🔚 Telemetry Wall session closed: {}", remote_addr);
    Ok(())
}

// ─── Throughput channel ───────────────────────────────────────────────────────

async fn run_throughput_channel(
    connection: Arc<Connection>,
    channel_id: String,
    impairment: Arc<RwLock<ImpairmentConfig>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Open a server-initiated unidirectional stream (double-await per wtransport API)
        let mut send = match connection.open_uni().await {
            Ok(opening) => match opening.await {
                Ok(s) => s,
                Err(e) => {
                    debug!("Channel {} stream open failed: {}", channel_id, e);
                    sleep(Duration::from_millis(500)).await;
                    continue;
                }
            },
            Err(e) => {
                debug!("Channel {} open_uni failed: {}", channel_id, e);
                break;
            }
        };

        // Write channel header — all frames on this stream are length-prefixed JSON.
        // No raw binary is ever written; the framing parser on the client always sees
        // valid JSON.  Throughput is measured via the virtual bytes_total counter.
        if let Err(e) = write_frame(
            &mut send,
            &json!({
                "stream_type":   "channel_header",
                "channel":       &channel_id,
                "virtual_chunk": VIRTUAL_CHUNK_BYTES,
                "rate_hz":       1000 / FRAME_INTERVAL_MS,
            }),
        )
        .await
        {
            debug!("Channel {} header write failed: {}", channel_id, e);
            continue;
        }

        let session_start = Instant::now();
        let mut bytes_total: u64 = 0;
        let mut seq: u32 = 0;
        let mut bw_bucket: Option<TokenBucket> = None;
        let mut last_kbps: f64 = 0.0;
        let mut disconnected = false;

        loop {
            // Snapshot and potentially auto-heal impairment config
            {
                let imp = impairment.read().await;
                if imp.active {
                    if let (Some(started), Some(dur_s)) = (imp.started_at, imp.duration_s) {
                        if started.elapsed().as_secs_f64() >= dur_s {
                            drop(imp);
                            impairment.write().await.active = false;
                        }
                    }
                }
            }

            let imp = impairment.read().await.clone();
            let elapsed_s = session_start.elapsed().as_secs_f64();

            if imp.active {
                let intensity = compute_intensity(&imp, elapsed_s);

                match imp.imp_type {
                    ImpairmentType::DelayMs => {
                        let ms = intensity.max(0.0) as u64;
                        if ms > 0 {
                            sleep(Duration::from_millis(ms)).await;
                        }
                    }

                    ImpairmentType::LossPct => {
                        let prob = intensity.clamp(0.0, 1.0);
                        if rand::thread_rng().gen::<f64>() < prob {
                            // Frame dropped — do NOT credit bytes_total.
                            // Client sees a gap in bytes_total → lower measured Mbps.
                            sleep(Duration::from_millis(FRAME_INTERVAL_MS)).await;
                            seq += 1;
                            // Send a "lost frame" marker so the client knows we're alive
                            let frame = json!({
                                "stream_type": "channel_data",
                                "channel":     &channel_id,
                                "t":           now_ms(),
                                "seq":         seq,
                                "bytes_total": bytes_total,
                                "impaired":    true,
                                "dropped":     true,
                                "impairment":  build_imp_desc(&imp),
                            });
                            if write_frame(&mut send, &frame).await.is_err() {
                                break;
                            }
                            continue;
                        }
                    }

                    ImpairmentType::BandwidthKbps => {
                        let kbps = intensity.max(1.0);
                        if bw_bucket.is_none() || (kbps - last_kbps).abs() > 1.0 {
                            bw_bucket = Some(TokenBucket::new(kbps));
                            last_kbps = kbps;
                        }
                        if let Some(ref mut bucket) = bw_bucket {
                            let wait = bucket.consume(VIRTUAL_CHUNK_BYTES as usize);
                            if wait > Duration::ZERO {
                                sleep(wait).await;
                            }
                        }
                    }

                    ImpairmentType::JitterMs => {
                        let sigma = intensity.max(0.0);
                        let offset = rand::thread_rng().gen::<f64>() * sigma * 2.0 - sigma;
                        let ms = (offset.abs() as u64).min(2000);
                        if ms > 0 {
                            sleep(Duration::from_millis(ms)).await;
                        }
                    }

                    ImpairmentType::Disconnect => {
                        info!("Channel {} disconnect triggered", channel_id);
                        disconnected = true;
                        break;
                    }

                    ImpairmentType::None => {}
                }
            } else {
                // Healthy pacing: 20 Hz
                sleep(Duration::from_millis(FRAME_INTERVAL_MS)).await;
            }

            // Credit virtual bytes and emit framed JSON metrics frame
            bytes_total += VIRTUAL_CHUNK_BYTES;
            seq += 1;

            let frame = json!({
                "stream_type": "channel_data",
                "channel":     &channel_id,
                "t":           now_ms(),
                "seq":         seq,
                "bytes_total": bytes_total,
                "impaired":    imp.active,
                "dropped":     false,
                "impairment":  if imp.active { build_imp_desc(&imp) } else { Value::Null },
            });

            if let Err(e) = write_frame(&mut send, &frame).await {
                debug!("Channel {} frame write error: {}", channel_id, e);
                break;
            }
        } // inner frame loop

        let _ = send.finish().await;

        if disconnected {
            sleep(Duration::from_millis(600)).await;
            // Heal the disconnect impairment so the channel comes back clean
            impairment.write().await.active = false;
        } else {
            break;
        }
    } // outer stream-open loop

    Ok(())
}

fn build_imp_desc(imp: &ImpairmentConfig) -> Value {
    json!({
        "type":      imp.imp_type.to_str(),
        "pattern":   format!("{:?}", imp.pattern).to_lowercase(),
        "intensity": imp.intensity,
    })
}

// ─── Stats channel (RTT, CWND, CPU, memory) ───────────────────────────────────

async fn run_stats_channel(
    connection: Arc<Connection>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut send = match connection.open_uni().await {
        Ok(opening) => opening.await?,
        Err(e) => return Err(e.into()),
    };

    // Channel header
    write_frame(
        &mut send,
        &json!({
            "stream_type": "channel_header",
            "channel":     "stats",
            "rate_hz":     10,
        }),
    )
    .await?;

    let session_start = Instant::now();
    let mut prev_cpu = read_cpu_snapshot().await;

    loop {
        sleep(Duration::from_millis(STATS_INTERVAL_MS)).await;

        let rtt_ms = connection.rtt().as_secs_f64() * 1000.0;
        let qs = connection.quic_connection().stats();
        let cwnd = qs.path.cwnd;
        let sent_b = qs.udp_tx.bytes;
        let recv_b = qs.udp_rx.bytes;

        let curr_cpu = read_cpu_snapshot().await;
        let cpu_pct = cpu_delta_pct(&prev_cpu, &curr_cpu);
        prev_cpu = curr_cpu;
        let mem_pct = read_mem_pct().await;

        let frame = json!({
            "stream_type":   "stats",
            "t":             now_ms(),
            "uptime_s":      session_start.elapsed().as_secs(),
            "rtt_ms":        rtt_ms,
            "cwnd_bytes":    cwnd,
            "udp_sent_b":    sent_b,
            "udp_recv_b":    recv_b,
            "cpu_pct":       cpu_pct,
            "mem_pct":       mem_pct,
        });

        if let Err(e) = write_frame(&mut send, &frame).await {
            debug!("Stats channel write error: {}", e);
            break;
        }
    }

    Ok(())
}

// ─── Control stream ───────────────────────────────────────────────────────────

async fn handle_control_stream(
    mut send: wtransport::stream::SendStream,
    mut recv: wtransport::stream::RecvStream,
    channels: Arc<ChannelMap>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Send session handshake listing available channels
    write_frame(
        &mut send,
        &json!({
            "stream_type": "session_info",
            "channels":    CHANNEL_NAMES,
            "protocol":    "telemetry/1",
            "version":     env!("CARGO_PKG_VERSION"),
        }),
    )
    .await?;

    loop {
        let cmd = match read_frame(&mut recv).await {
            Ok(v) => v,
            Err(_) => break,
        };

        let op = cmd.get("cmd").and_then(|v| v.as_str()).unwrap_or("");

        match op {
            "impair" => {
                let channel = cmd["channel"].as_str().unwrap_or("").to_string();
                let new_imp = parse_impairment_cmd(&cmd);

                if channel == "all" {
                    for imp_lock in channels.values() {
                        *imp_lock.write().await = new_imp.clone();
                    }
                    info!(
                        "Telemetry: impairment applied to ALL channels ({:?}, {:?})",
                        new_imp.imp_type, new_imp.pattern
                    );
                } else if let Some(imp_lock) = channels.get(&channel) {
                    info!(
                        "Telemetry: impairment applied to channel '{}' ({:?}, {:?})",
                        channel, new_imp.imp_type, new_imp.pattern
                    );
                    *imp_lock.write().await = new_imp.clone();
                } else {
                    warn!("Telemetry: unknown channel '{}' in impair command", channel);
                    write_frame(
                        &mut send,
                        &json!({"type":"ack","cmd":"impair","ok":false,"error":"unknown_channel"}),
                    )
                    .await?;
                    continue;
                }

                write_frame(
                    &mut send,
                    &json!({
                        "type":    "ack",
                        "cmd":     "impair",
                        "channel": channel,
                        "ok":      true,
                    }),
                )
                .await?;
            }

            "heal" => {
                let channel = cmd["channel"].as_str().unwrap_or("").to_string();
                if let Some(imp_lock) = channels.get(&channel) {
                    imp_lock.write().await.active = false;
                    info!("Telemetry: healed channel '{}'", channel);
                    write_frame(
                        &mut send,
                        &json!({"type":"ack","cmd":"heal","channel":channel,"ok":true}),
                    )
                    .await?;
                } else {
                    write_frame(
                        &mut send,
                        &json!({"type":"ack","cmd":"heal","ok":false,"error":"unknown_channel"}),
                    )
                    .await?;
                }
            }

            "heal_all" => {
                for imp_lock in channels.values() {
                    imp_lock.write().await.active = false;
                }
                info!("Telemetry: all channels healed");
                write_frame(&mut send, &json!({"type":"ack","cmd":"heal_all","ok":true})).await?;
            }

            other => {
                warn!("Telemetry: unknown control command '{}'", other);
                write_frame(
                    &mut send,
                    &json!({"type":"ack","cmd":other,"ok":false,"error":"unknown_cmd"}),
                )
                .await?;
            }
        }
    }

    Ok(())
}

// ─── System stats helpers ─────────────────────────────────────────────────────

struct CpuSnapshot {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

async fn read_cpu_snapshot() -> CpuSnapshot {
    let content = tokio::fs::read_to_string("/proc/stat")
        .await
        .unwrap_or_default();
    let line = content.lines().next().unwrap_or("");
    // "cpu  user nice system idle iowait irq softirq steal ..."
    let nums: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    CpuSnapshot {
        user: nums.first().copied().unwrap_or(0),
        nice: nums.get(1).copied().unwrap_or(0),
        system: nums.get(2).copied().unwrap_or(0),
        idle: nums.get(3).copied().unwrap_or(0),
        iowait: nums.get(4).copied().unwrap_or(0),
        irq: nums.get(5).copied().unwrap_or(0),
        softirq: nums.get(6).copied().unwrap_or(0),
        steal: nums.get(7).copied().unwrap_or(0),
    }
}

fn cpu_delta_pct(prev: &CpuSnapshot, curr: &CpuSnapshot) -> f64 {
    let prev_total = prev.user
        + prev.nice
        + prev.system
        + prev.idle
        + prev.iowait
        + prev.irq
        + prev.softirq
        + prev.steal;
    let curr_total = curr.user
        + curr.nice
        + curr.system
        + curr.idle
        + curr.iowait
        + curr.irq
        + curr.softirq
        + curr.steal;
    let total_delta = curr_total.saturating_sub(prev_total);
    if total_delta == 0 {
        return 0.0;
    }
    let prev_idle = prev.idle + prev.iowait;
    let curr_idle = curr.idle + curr.iowait;
    let idle_delta = curr_idle.saturating_sub(prev_idle);
    let busy_delta = total_delta.saturating_sub(idle_delta);
    (busy_delta as f64 / total_delta as f64) * 100.0
}

async fn read_mem_pct() -> f64 {
    let content = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .unwrap_or_default();
    let mut total: u64 = 0;
    let mut available: u64 = 0;
    for line in content.lines() {
        if line.starts_with("MemTotal:") {
            total = parse_meminfo_kb(line);
        } else if line.starts_with("MemAvailable:") {
            available = parse_meminfo_kb(line);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let used = total.saturating_sub(available);
    (used as f64 / total as f64) * 100.0
}

fn parse_meminfo_kb(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

// ─── Frame I/O helpers ────────────────────────────────────────────────────────

/// Write a length-prefixed JSON frame.
async fn write_frame(
    send: &mut wtransport::stream::SendStream,
    value: &Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(value)?;
    let len = u32::try_from(bytes.len())
        .map_err(|_| "frame too large")?
        .to_be_bytes();
    send.write_all(&len).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

/// Read a length-prefixed JSON frame.
async fn read_frame(
    recv: &mut wtransport::stream::RecvStream,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let mut len_buf = [0u8; 4];
    read_exact(recv, &mut len_buf).await?;
    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
        return Err(format!("telemetry frame length {frame_len} out of range").into());
    }
    let mut body = vec![0u8; frame_len];
    read_exact(recv, &mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

async fn read_exact(
    recv: &mut wtransport::stream::RecvStream,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut pos = 0;
    while pos < buf.len() {
        match recv.read(&mut buf[pos..]).await {
            Ok(Some(n)) => pos += n,
            Ok(None) => {
                return Err(format!("unexpected EOF after {pos} of {} bytes", buf.len()).into())
            }
            Err(e) => return Err(format!("stream read error: {e}").into()),
        }
    }
    Ok(())
}

// ─── Timestamp helper ─────────────────────────────────────────────────────────

fn now_ms() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
        * 1000.0
}
