#![expect(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops
)]
//! WebTransport Telemetry Wall — native handler for the `/telemetry` path
//!
//! Six QUIC streams of one connection, each carrying real data, and what
//! happens to each when something goes wrong with one of them, or with the
//! path under all of them.
//!
//! ## Session lifecycle
//! 1. Client connects to `https://<node>:4433/telemetry`
//! 2. Server opens 6 throughput channels (server-opened uni-streams), each
//!    sending real payload at [`CHANNEL_RATE_BPS`] in [`CHUNK_BYTES`] chunks,
//!    every chunk stamped with the moment it entered the stream
//! 3. Server opens 1 stats channel (RTT, congestion window, the packets QUIC
//!    lost and the congestion events they caused, CPU, memory — 10 Hz)
//! 4. Client opens a control bidi-stream; sends impairment / heal commands
//! 5. Datagrams are echoed for RTT / loss measurement (same as /speedtest)
//!
//! ## What an impairment does
//! Every one acts on real bytes, and what the page shows is what the client
//! measured of them: the bytes it received, and when each chunk arrived
//! against when it was sent.
//! - `delay_ms` and `jitter_ms` hold a channel's chunks back by a fixed or a
//!   random time before they are written: that stream's data arrives that
//!   much later, the others' not at all.
//! - `bandwidth_kbps` writes a channel's chunks no faster than the rate.
//! - `disconnect` ends the channel's stream; a new one opens after 600 ms.
//! - `loss_pct` is not a channel's: loss happens to packets on a path, and
//!   the share asked for is dropped on this session's path at the socket
//!   ([`crate::path_loss`]). QUIC finds the packets lost and sends their data
//!   again, and each stream stalls only for the data that was in them.
//!
//! The patterns (fixed, random, sine, square, burst, ramp, cascade) vary an
//! impairment's intensity over time. A session's payload is counted against
//! the speed test's download allowance for the client's network
//! ([`crate::speedtest_budget`]); past it, channels send frames without
//! payload until the window turns.
//!
//! ## Wire protocol (`telemetry/2`)
//! Frames are a 4-byte big-endian length followed by JSON. A `channel_data`
//! frame is followed by `payload` raw bytes, outside the frame.
//!
//! ### Server → client channel header (first frame on every uni-stream)
//! ```json
//! {"stream_type":"channel_header","channel":"ch1","rate_bps":2000000,"chunk_bytes":16384}
//! ```
//!
//! ### Throughput channel data frame (then `payload` bytes)
//! ```json
//! {"stream_type":"channel_data","channel":"ch1","seq":42,"t":1731450000123.4,
//!  "payload":16384,"sent_total":688128,"impaired":false,"impairment":null}
//! ```
//!
//! ### Stats channel data frame
//! ```json
//! {"stream_type":"stats","t":1234567.890,"rtt_ms":23.5,"cwnd_bytes":1250000,
//!  "lost_packets":12,"lost_bytes":15000,"congestion_events":3,
//!  "path_loss_pct":5.0,"path_dropped":40,"cpu_pct":8.3,"mem_pct":42.1,"uptime_s":86400}
//! ```
//!
//! ### Control channel — client → server commands
//! ```json
//! {"cmd":"impair","channel":"ch3","type":"delay_ms","intensity":200.0,
//!  "pattern":"burst","burst_freq_s":5.0,"burst_dur_ms":500.0,"duration_s":30.0}
//! {"cmd":"impair","channel":"path","type":"loss_pct","intensity":5.0}
//! {"cmd":"heal","channel":"ch3"}
//! {"cmd":"heal","channel":"path"}
//! {"cmd":"heal_all"}
//! {"cmd":"pause"}   (the page's tab is hidden: the channels send nothing)
//! {"cmd":"resume"}
//! ```
//!
//! ### Control channel — server → client ack
//! ```json
//! {"type":"ack","cmd":"impair","channel":"ch3","ok":true}
//! ```

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use rand::Rng;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::wt_session::WtSession;

// ─── Constants ────────────────────────────────────────────────────────────────

const CHANNEL_NAMES: &[&str] = &["ch1", "ch2", "ch3", "ch4", "ch5", "ch6"];
/// What each channel sends when nothing holds it back: 2 Mbit/s, so a session
/// is 12 Mbit/s across its six streams.
const CHANNEL_RATE_BPS: u64 = 2_000_000;
/// The bytes of payload in one chunk.
const CHUNK_BYTES: usize = 16 * 1024;
/// The most a channel holds back (delayed, or waiting on its bandwidth
/// limit): two seconds of its rate. Past it the channel produces nothing
/// until there is room, as an application whose writes block.
const QUEUE_LIMIT: usize = (2 * CHANNEL_RATE_BPS as usize / 8) / CHUNK_BYTES;
/// What is taken from the client network's download allowance at a time.
const ALLOWANCE_BLOCK: u64 = 8 * 1024 * 1024;
/// How often a channel with no allowance left says so.
const BUDGET_NOTICE: Duration = Duration::from_secs(1);
/// The longest a channel sleeps between looking at its queue and its
/// impairment.
const TICK: Duration = Duration::from_millis(50);
const MAX_FRAME_BYTES: usize = 65_536;
const MIN_DATAGRAM_BYTES: usize = 8;
const STATS_INTERVAL_MS: u64 = 100; // 10 Hz stats push
/// How often the path loss follows its impairment's pattern.
const PATH_LOSS_TICK: Duration = Duration::from_millis(100);

/// Session idle timeout: close if no stream or datagram activity for this long.
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_mins(5); // 5 minutes
/// Hard cap on total session lifetime regardless of activity.
const SESSION_MAX_DURATION: Duration = Duration::from_hours(1); // 60 minutes

/// The bytes every chunk carries: random, once, so nothing on the path can
/// make them smaller than they are.
static PAYLOAD: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let mut bytes = vec![0u8; CHUNK_BYTES];
    rand::thread_rng().fill(bytes.as_mut_slice());
    bytes
});

// ─── Impairment types ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
enum ImpairmentType {
    None,
    DelayMs,       // a channel's chunks held back N ms
    LossPct,       // the session's path drops N % of its datagrams
    BandwidthKbps, // a channel's chunks written no faster than N kbit/s
    JitterMs,      // a channel's chunks held back a random 0 to 2σ ms
    Disconnect,    // the channel's stream ends; a new one opens
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
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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

/// The client network's download allowance, as the session's channels
/// draw on it: a block reserved at a time, its unused part given back when
/// the session ends.
struct Allowance {
    client: std::net::IpAddr,
    held: Option<crate::speedtest_budget::Reservation>,
    left: u64,
}

impl Allowance {
    fn new(client: std::net::IpAddr) -> Self {
        Self {
            client,
            held: None,
            left: 0,
        }
    }

    /// Take `bytes` for one chunk; false when the allowance is spent.
    fn take(&mut self, bytes: u64) -> bool {
        if self.left < bytes {
            match crate::speedtest_budget::reserve(
                self.client,
                crate::speedtest_budget::Direction::Download,
                ALLOWANCE_BLOCK,
            ) {
                Ok(block) => {
                    self.held = Some(block);
                    self.left = ALLOWANCE_BLOCK;
                }
                Err(_) => return false,
            }
        }
        self.left -= bytes;
        if let Some(block) = &mut self.held {
            block.use_bytes(bytes);
        }
        true
    }
}

/// What a session's tasks share: the channels' impairments, the path's,
/// the allowance, and the token that ends them all with the session.
struct Session {
    channels: ChannelMap,
    path: Arc<RwLock<ImpairmentConfig>>,
    allowance: parking_lot::Mutex<Allowance>,
    /// Set while the page is not being looked at (its tab hidden): the
    /// channels send nothing then, rather than data no one sees
    paused: std::sync::atomic::AtomicBool,
    ended: CancellationToken,
}

// ─── Session entry point ──────────────────────────────────────────────────────

/// Handle an established WebTransport session on the `/telemetry` path.
/// Called from `webtransport_server::handle_connection` when `path == "/telemetry"`.
pub async fn handle_telemetry_session<S: WtSession>(
    connection: Arc<S>,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("📡 Telemetry Wall session started: {}", remote_addr);

    let session = Arc::new(Session {
        channels: CHANNEL_NAMES
            .iter()
            .map(|&name| {
                (
                    name.to_string(),
                    Arc::new(RwLock::new(ImpairmentConfig::default())),
                )
            })
            .collect(),
        path: Arc::new(RwLock::new(ImpairmentConfig::default())),
        allowance: parking_lot::Mutex::new(Allowance::new(remote_addr.ip())),
        paused: std::sync::atomic::AtomicBool::new(false),
        ended: CancellationToken::new(),
    });
    // The loss on this session's path, held for as long as the session is
    let path_loss = Arc::new(crate::path_loss::PeerLoss::new(remote_addr));

    // Every task the session starts ends with it: the token is cancelled
    // however the loop below is left, and the tasks drop their handles on
    // the connection, so nothing goes on sending to a client that is gone
    let _end_tasks = session.ended.clone().drop_guard();

    // The stats push channel (server-initiated uni-stream, 10 Hz)
    {
        let conn = Arc::clone(&connection);
        let loss = Arc::clone(&path_loss);
        let ended = session.ended.clone();
        tokio::spawn(async move {
            tokio::select! {
                result = run_stats_channel(conn, loss) => {
                    if let Err(e) = result {
                        debug!("Telemetry stats channel ended: {}", e);
                    }
                }
                () = ended.cancelled() => {}
            }
        });
    }

    // The path loss, following its impairment's pattern
    {
        let session = Arc::clone(&session);
        let loss = Arc::clone(&path_loss);
        tokio::spawn(async move {
            tokio::select! {
                () = run_path_loss(&session.path, &loss) => {}
                () = session.ended.cancelled() => {}
            }
        });
    }

    // One throughput channel per CHANNEL_NAME (independent uni-streams)
    for &name in CHANNEL_NAMES {
        let conn = Arc::clone(&connection);
        let session = Arc::clone(&session);
        tokio::spawn(async move {
            let ended = session.ended.clone();
            tokio::select! {
                result = run_throughput_channel(conn, name, &session) => {
                    if let Err(e) = result {
                        debug!("Telemetry throughput channel ended: {}", e);
                    }
                }
                () = ended.cancelled() => {}
            }
        });
    }

    // Hard cap: close after SESSION_MAX_DURATION regardless of activity.
    let session_deadline = sleep(SESSION_MAX_DURATION);
    tokio::pin!(session_deadline);

    // Idle timer: reset on any stream or datagram; fires if nothing arrives for
    // SESSION_IDLE_TIMEOUT. Catches clients that disconnect without a clean QUIC
    // close while keep-alive PINGs hold the transport open.
    let idle_deadline = sleep(SESSION_IDLE_TIMEOUT);
    tokio::pin!(idle_deadline);

    // Main loop: datagram echo + accept control streams
    loop {
        tokio::select! {
            bidi_result = connection.accept_bi() => {
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + SESSION_IDLE_TIMEOUT);
                match bidi_result {
                    Ok((send_s, recv_s)) => {
                        let session = Arc::clone(&session);
                        tokio::spawn(async move {
                            let ended = session.ended.clone();
                            tokio::select! {
                                result = handle_control_stream(send_s, recv_s, &session) => {
                                    if let Err(e) = result {
                                        debug!("Control stream error: {}", e);
                                    }
                                }
                                () = ended.cancelled() => {}
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
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + SESSION_IDLE_TIMEOUT);
                match dg_result {
                    Ok(dg) => {
                        if dg.len() >= MIN_DATAGRAM_BYTES {
                            if let Err(e) = connection.send_datagram(&dg) {
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

            _ = &mut idle_deadline => {
                warn!(
                    "⏰ Telemetry session idle timeout ({}s no activity): {}",
                    SESSION_IDLE_TIMEOUT.as_secs(),
                    remote_addr
                );
                break;
            }

            _ = &mut session_deadline => {
                warn!(
                    "⏰ Telemetry session max duration ({}s) reached: {}",
                    SESSION_MAX_DURATION.as_secs(),
                    remote_addr
                );
                break;
            }
        }
    }

    // Ended here rather than when the client goes: the channels would
    // otherwise go on sending on a connection kept open by keep-alives
    session.ended.cancel();
    connection
        .quic_connection()
        .close(0u32.into(), b"telemetry session ended");
    info!("🔚 Telemetry Wall session closed: {}", remote_addr);
    Ok(())
}

// ─── Path loss ────────────────────────────────────────────────────────────────

/// Keep the session's path loss at what its impairment says, as its pattern
/// moves it, and at none once the impairment ends.
async fn run_path_loss(path: &RwLock<ImpairmentConfig>, loss: &crate::path_loss::PeerLoss) {
    let started = Instant::now();
    loop {
        let imp = {
            let mut imp = path.write().await;
            if imp.active && expired(&imp) {
                imp.active = false;
            }
            imp.clone()
        };
        let permille = if imp.active && imp.imp_type == ImpairmentType::LossPct {
            let pct = compute_intensity(&imp, started.elapsed().as_secs_f64()).clamp(0.0, 100.0);
            (pct * 10.0).round() as u16
        } else {
            0
        };
        loss.set_permille(permille);
        sleep(PATH_LOSS_TICK).await;
    }
}

/// Whether an impairment given a duration has run it.
fn expired(imp: &ImpairmentConfig) -> bool {
    matches!(
        (imp.started_at, imp.duration_s),
        (Some(started), Some(duration)) if started.elapsed().as_secs_f64() >= duration
    )
}

// ─── Throughput channel ───────────────────────────────────────────────────────

/// A chunk produced and not yet written: when it entered the stream, and
/// when it may be written.
struct Pending {
    seq: u64,
    /// Wall-clock milliseconds when it was produced: the client measures its
    /// arrival against this
    produced_ms: f64,
    due: Instant,
}

/// How long the next chunk is held back, for an active delay or jitter.
fn hold_back(imp: &ImpairmentConfig, elapsed_s: f64) -> Duration {
    if !imp.active {
        return Duration::ZERO;
    }
    let intensity = compute_intensity(imp, elapsed_s).max(0.0);
    let ms = match imp.imp_type {
        ImpairmentType::DelayMs => intensity,
        ImpairmentType::JitterMs => rand::thread_rng().gen::<f64>() * intensity * 2.0,
        _ => 0.0,
    };
    Duration::from_secs_f64(ms.min(10_000.0) / 1000.0)
}

async fn run_throughput_channel<S: WtSession>(
    connection: Arc<S>,
    channel_id: &'static str,
    session: &Session,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let impairment = session
        .channels
        .get(channel_id)
        .map(Arc::clone)
        .ok_or("no such channel")?;
    let chunk_interval =
        Duration::from_secs_f64((CHUNK_BYTES as f64 * 8.0) / CHANNEL_RATE_BPS as f64);

    loop {
        let mut send = match connection.open_uni().await {
            Ok(s) => s,
            Err(e) => {
                debug!("Channel {} open_uni failed: {}", channel_id, e);
                break;
            }
        };

        write_frame(
            &mut send,
            &json!({
                "stream_type": "channel_header",
                "channel":     channel_id,
                "rate_bps":    CHANNEL_RATE_BPS,
                "chunk_bytes": CHUNK_BYTES,
            }),
        )
        .await?;

        let started = Instant::now();
        let mut next_production = started;
        let mut queue: VecDeque<Pending> = VecDeque::with_capacity(QUEUE_LIMIT);
        let mut seq: u64 = 0;
        let mut sent_total: u64 = 0;
        let mut bw_bucket: Option<TokenBucket> = None;
        let mut last_kbps: f64 = 0.0;
        let mut budget_notice: Option<Instant> = None;

        loop {
            let imp = {
                let mut imp = impairment.write().await;
                if imp.active && expired(&imp) {
                    imp.active = false;
                }
                imp.clone()
            };
            if imp.active && imp.imp_type == ImpairmentType::Disconnect {
                info!("Channel {} disconnect triggered", channel_id);
                break;
            }
            let elapsed_s = started.elapsed().as_secs_f64();
            let now = Instant::now();

            // Not being looked at: nothing is produced or held, and the rate
            // starts afresh when the page is back, rather than catching up
            if session.paused.load(std::sync::atomic::Ordering::Relaxed) {
                queue.clear();
                next_production = now + chunk_interval;
                tokio::time::sleep(TICK).await;
                continue;
            }

            // Produce at the channel's rate, as far as there is room
            while next_production <= now && queue.len() < QUEUE_LIMIT {
                let lag = now.duration_since(next_production);
                queue.push_back(Pending {
                    seq,
                    produced_ms: now_ms() - lag.as_secs_f64() * 1000.0,
                    due: next_production + hold_back(&imp, elapsed_s),
                });
                seq += 1;
                next_production += chunk_interval;
            }
            // A full queue is a writer that blocks: no burst to catch up
            if queue.len() >= QUEUE_LIMIT && next_production <= now {
                next_production = now + chunk_interval;
            }

            // Write what is due, as its bandwidth allows
            if let Some(head) = queue.front().filter(|head| head.due <= now) {
                if imp.active && imp.imp_type == ImpairmentType::BandwidthKbps {
                    let kbps = compute_intensity(&imp, elapsed_s).max(1.0);
                    if bw_bucket.is_none() || (kbps - last_kbps).abs() > 1.0 {
                        bw_bucket = Some(TokenBucket::new(kbps));
                        last_kbps = kbps;
                    }
                    if let Some(bucket) = bw_bucket.as_mut() {
                        let wait = bucket.consume(CHUNK_BYTES);
                        if wait > Duration::ZERO {
                            sleep(wait.min(Duration::from_secs(2))).await;
                        }
                    }
                } else {
                    bw_bucket = None;
                }

                let impaired = imp.active || session.path.read().await.active;
                let description = if imp.active {
                    build_imp_desc(&imp)
                } else {
                    Value::Null
                };

                if session.allowance.lock().take(CHUNK_BYTES as u64) {
                    write_frame(
                        &mut send,
                        &json!({
                            "stream_type": "channel_data",
                            "channel":     channel_id,
                            "seq":         head.seq,
                            "t":           head.produced_ms,
                            "payload":     CHUNK_BYTES,
                            "sent_total":  sent_total + CHUNK_BYTES as u64,
                            "impaired":    impaired,
                            "impairment":  description,
                        }),
                    )
                    .await?;
                    // The payload follows the frame, outside it
                    send.write_all(&PAYLOAD).await?;
                    sent_total += CHUNK_BYTES as u64;
                    queue.pop_front();
                    budget_notice = None;
                    continue;
                }

                // The client network's allowance is spent: nothing is held
                // for it, and the client is told once a second
                queue.clear();
                if budget_notice.is_none_or(|at| at.elapsed() >= BUDGET_NOTICE) {
                    budget_notice = Some(Instant::now());
                    write_frame(
                        &mut send,
                        &json!({
                            "stream_type": "channel_data",
                            "channel":     channel_id,
                            "seq":         seq,
                            "t":           now_ms(),
                            "payload":     0,
                            "sent_total":  sent_total,
                            "impaired":    impaired,
                            "impairment":  description,
                            "budget":      "exhausted",
                        }),
                    )
                    .await?;
                }
            }

            // Until the next chunk is produced or due, or the impairment may
            // have changed
            let next_due = queue.front().map(|head| head.due);
            let wake = [Some(next_production), next_due]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(now + TICK)
                .min(now + TICK);
            tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
        }

        // Disconnected: the stream ends, and after 600 ms a new one opens,
        // the disconnect healed so it comes back clean. Anything else that
        // ends a channel is an error, or the session ending
        let _ = send.shutdown().await;
        sleep(Duration::from_millis(600)).await;
        impairment.write().await.active = false;
    }

    Ok(())
}

fn build_imp_desc(imp: &ImpairmentConfig) -> Value {
    json!({
        "type":      imp.imp_type.to_str(),
        "pattern":   format!("{:?}", imp.pattern).to_lowercase(),
        "intensity": imp.intensity,
    })
}

// ─── Stats channel (RTT, CWND, loss, CPU, memory) ─────────────────────────────

async fn run_stats_channel<S: WtSession>(
    connection: Arc<S>,
    path_loss: Arc<crate::path_loss::PeerLoss>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut send = connection.open_uni().await?;

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
        // noq is multipath: congestion window is per-path, not a single
        // connection-level value. Report the initial path's cwnd (the
        // single-path equivalent), 0 if that path isn't currently present.
        let path = connection.quic_connection().path_stats(quinn::PathId::ZERO);
        let cwnd = path.as_ref().map_or(0, |p| p.cwnd);
        // What QUIC itself found lost, and the congestion it answered
        let (lost_packets, lost_bytes, congestion_events) = path.as_ref().map_or((0, 0, 0), |p| {
            (p.lost_packets, p.lost_bytes, p.congestion_events)
        });
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
            "lost_packets":  lost_packets,
            "lost_bytes":    lost_bytes,
            "congestion_events": congestion_events,
            "path_loss_pct": f64::from(path_loss.permille()) / 10.0,
            "path_dropped":  path_loss.dropped(),
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

async fn handle_control_stream<W: AsyncWrite + Unpin + Send, R: AsyncRead + Unpin + Send>(
    mut send: W,
    mut recv: R,
    session: &Session,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let channels = &session.channels;
    // Send session handshake listing available channels
    write_frame(
        &mut send,
        &json!({
            "stream_type": "session_info",
            "channels":    CHANNEL_NAMES,
            "protocol":    "telemetry/2",
            "rate_bps":    CHANNEL_RATE_BPS,
            "chunk_bytes": CHUNK_BYTES,
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

                // Loss is the path's, whichever channel was named: packets
                // are lost, not streams
                if new_imp.imp_type == ImpairmentType::LossPct {
                    info!(
                        "Telemetry: path loss applied ({:?}, {} %)",
                        new_imp.pattern, new_imp.intensity
                    );
                    *session.path.write().await = new_imp;
                    write_frame(
                        &mut send,
                        &json!({"type":"ack","cmd":"impair","channel":"path","ok":true}),
                    )
                    .await?;
                    continue;
                }

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
                    debug!(
                        "Telemetry: unknown channel '{}' in impair command",
                        channel.chars().take(64).collect::<String>()
                    );
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
                if channel == "path" {
                    session.path.write().await.active = false;
                    info!("Telemetry: healed the path");
                    write_frame(
                        &mut send,
                        &json!({"type":"ack","cmd":"heal","channel":"path","ok":true}),
                    )
                    .await?;
                } else if let Some(imp_lock) = channels.get(&channel) {
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

            // The page's tab hidden or shown again
            "pause" | "resume" => {
                let paused = op == "pause";
                session
                    .paused
                    .store(paused, std::sync::atomic::Ordering::Relaxed);
                write_frame(&mut send, &json!({"type":"ack","cmd":op,"ok":true})).await?;
            }

            "heal_all" => {
                for imp_lock in channels.values() {
                    imp_lock.write().await.active = false;
                }
                session.path.write().await.active = false;
                info!("Telemetry: all channels healed");
                write_frame(&mut send, &json!({"type":"ack","cmd":"heal_all","ok":true})).await?;
            }

            other => {
                debug!(
                    "Telemetry: unknown control command '{}'",
                    other.chars().take(64).collect::<String>()
                );
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
async fn write_frame<W: AsyncWrite + Unpin + Send>(
    send: &mut W,
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
async fn read_frame<R: AsyncRead + Unpin + Send>(
    recv: &mut R,
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

async fn read_exact<R: AsyncRead + Unpin + Send>(
    recv: &mut R,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut pos = 0;
    while pos < buf.len() {
        match recv.read(&mut buf[pos..]).await {
            Ok(0) => {
                return Err(format!("unexpected EOF after {pos} of {} bytes", buf.len()).into())
            }
            Ok(n) => pos += n,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wt_session::WtClosed;

    /// A session whose one uni-stream is the write half of a pipe the test
    /// reads; nothing else of a connection is used by a throughput channel.
    struct Pipe(parking_lot::Mutex<Option<tokio::io::DuplexStream>>);

    impl WtSession for Pipe {
        type Send = tokio::io::DuplexStream;
        type Recv = tokio::io::DuplexStream;
        async fn accept_bi(&self) -> Result<(Self::Send, Self::Recv), WtClosed> {
            std::future::pending().await
        }
        async fn accept_uni(&self) -> Result<Self::Recv, WtClosed> {
            std::future::pending().await
        }
        async fn open_uni(&self) -> Result<Self::Send, WtClosed> {
            let stream = self.0.lock().take();
            match stream {
                Some(stream) => Ok(stream),
                None => std::future::pending().await,
            }
        }
        async fn receive_datagram(&self) -> Result<bytes::Bytes, WtClosed> {
            std::future::pending().await
        }
        fn send_datagram(&self, _payload: &[u8]) -> Result<(), WtClosed> {
            Ok(())
        }
        fn rtt(&self) -> Duration {
            Duration::ZERO
        }
        fn quic_connection(&self) -> &quinn::Connection {
            unreachable!("a throughput channel asks nothing of the connection")
        }
    }

    fn session() -> Session {
        Session {
            channels: CHANNEL_NAMES
                .iter()
                .map(|&name| {
                    (
                        name.to_string(),
                        Arc::new(RwLock::new(ImpairmentConfig::default())),
                    )
                })
                .collect(),
            path: Arc::new(RwLock::new(ImpairmentConfig::default())),
            allowance: parking_lot::Mutex::new(Allowance::new("198.51.100.200".parse().unwrap())),
            paused: std::sync::atomic::AtomicBool::new(false),
            ended: CancellationToken::new(),
        }
    }

    /// Read one data frame and the payload after it: the frame, and the
    /// moment its payload had all arrived, in wall-clock milliseconds.
    async fn next_chunk(read: &mut tokio::io::DuplexStream) -> (Value, f64) {
        let frame = read_frame(read).await.expect("a frame");
        let payload = usize::try_from(frame["payload"].as_u64().unwrap_or(0)).unwrap();
        let mut bytes = vec![0u8; payload];
        read_exact(read, &mut bytes).await.expect("its payload");
        assert_eq!(bytes, PAYLOAD[..payload], "the payload is the real bytes");
        (frame, now_ms())
    }

    #[tokio::test]
    async fn a_channel_sends_real_payload_at_its_rate() {
        let (write, mut read) = tokio::io::duplex(1 << 20);
        let pipe = Arc::new(Pipe(parking_lot::Mutex::new(Some(write))));
        let session = Arc::new(session());
        let running = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { run_throughput_channel(pipe, "ch1", &session).await })
        };
        let header = read_frame(&mut read).await.unwrap();
        assert_eq!(header["stream_type"], "channel_header");
        assert_eq!(header["chunk_bytes"], CHUNK_BYTES);

        let started = Instant::now();
        let mut received = 0u64;
        let mut last_seq = None;
        for _ in 0..8 {
            let (frame, _) = next_chunk(&mut read).await;
            assert_eq!(frame["stream_type"], "channel_data");
            let seq = frame["seq"].as_u64().unwrap();
            assert!(last_seq.is_none_or(|last| seq == last + 1), "in order");
            last_seq = Some(seq);
            received += frame["payload"].as_u64().unwrap();
        }
        assert_eq!(received, 8 * CHUNK_BYTES as u64);
        // Eight chunks at 2 Mbit/s take seven intervals of 65.5 ms: paced,
        // not sent at once
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(400), "{took:?}");
        running.abort();
    }

    #[tokio::test]
    async fn a_delay_holds_a_channels_chunks_back() {
        let (write, mut read) = tokio::io::duplex(1 << 20);
        let pipe = Arc::new(Pipe(parking_lot::Mutex::new(Some(write))));
        let session = Arc::new(session());
        *session.channels["ch3"].write().await = ImpairmentConfig {
            active: true,
            imp_type: ImpairmentType::DelayMs,
            intensity: 300.0,
            started_at: Some(Instant::now()),
            ..ImpairmentConfig::default()
        };
        let running = {
            let session = Arc::clone(&session);
            tokio::spawn(async move { run_throughput_channel(pipe, "ch3", &session).await })
        };
        read_frame(&mut read).await.unwrap();
        for _ in 0..3 {
            let (frame, arrived) = next_chunk(&mut read).await;
            let held = arrived - frame["t"].as_f64().unwrap();
            assert!(held >= 290.0, "held {held} ms");
            assert_eq!(frame["impaired"], true);
        }
        running.abort();
    }

    #[test]
    fn what_an_impairment_holds_back() {
        let at = |imp_type, intensity| ImpairmentConfig {
            active: true,
            imp_type,
            intensity,
            ..ImpairmentConfig::default()
        };
        assert_eq!(hold_back(&ImpairmentConfig::default(), 0.0), Duration::ZERO);
        assert_eq!(
            hold_back(&at(ImpairmentType::DelayMs, 120.0), 0.0),
            Duration::from_millis(120)
        );
        for _ in 0..100 {
            let jitter = hold_back(&at(ImpairmentType::JitterMs, 50.0), 0.0);
            assert!(jitter <= Duration::from_millis(100));
        }
        assert_eq!(
            hold_back(&at(ImpairmentType::BandwidthKbps, 500.0), 0.0),
            Duration::ZERO
        );
        assert_eq!(
            hold_back(&at(ImpairmentType::DelayMs, 1e9), 0.0),
            Duration::from_secs(10),
            "never held past ten seconds"
        );

        let mut timed = at(ImpairmentType::DelayMs, 1.0);
        timed.duration_s = Some(0.0);
        timed.started_at = Some(Instant::now());
        assert!(expired(&timed));
        timed.duration_s = Some(60.0);
        assert!(!expired(&timed));
    }

    #[test]
    fn the_allowance_is_drawn_a_block_at_a_time() {
        let mut allowance = Allowance::new("198.51.100.201".parse().unwrap());
        assert!(allowance.take(CHUNK_BYTES as u64));
        assert_eq!(allowance.left, ALLOWANCE_BLOCK - CHUNK_BYTES as u64);
        allowance.left = 10;
        assert!(
            allowance.take(CHUNK_BYTES as u64),
            "a new block when one runs out"
        );
        assert_eq!(allowance.left, ALLOWANCE_BLOCK - CHUNK_BYTES as u64);
    }
}
