//! The proxy's own memory, as its cgroup accounts it, and what the proxy
//! gives up when that runs short.
//!
//! The service manager caps the process (`MemoryHigh`, `MemoryMax`): above
//! the first the kernel reclaims from it and slows every allocation it makes,
//! at the second it kills it, and with it every connection it holds. This
//! acts first, on what the proxy itself keeps. Every 250 ms it reads the
//! cgroup's working set against those limits, and how much of the last ten
//! seconds the process spent stalled on memory (the kernel's pressure stall
//! information), and sets a level:
//!
//! - [`Level::Elevated`]: at 80 % of `MemoryHigh` (70 % of `MemoryMax` where
//!   there is no `MemoryHigh`), or stalled 20 % of the time. No response is
//!   cached and the cache is cut to half its budget; the request bodies held
//!   at once may take half theirs; connections with nothing in flight are
//!   closed (HTTP/1.1 closed, HTTP/2 and HTTP/3 sent GOAWAY), and the others
//!   once they have been idle 5 s instead of the configured idle time; the
//!   allocator returns what has been freed to the system.
//! - [`Level::Critical`]: at 95 % of `MemoryHigh` or 90 % of `MemoryMax`. As
//!   above, with the cache emptied, request bodies held to an eighth of
//!   their budget, and new connections refused but from exempt addresses
//!   (the operator's own), on every listener.
//!
//! A level is left only well below where it is entered, so the proxy does not
//! flap at a threshold, and while it lasts the relief is applied again every
//! 5 s, for connections that were busy the last time.
//!
//! The working set is what reclaim cannot simply drop: anonymous memory (the
//! heap), socket buffers, and kernel memory other than reclaimable slab. The
//! cgroup's `memory.current` also counts the page cache its log writes leave
//! behind, which the kernel takes back at `MemoryHigh` on its own; measured
//! against that, a proxy with plenty of memory would look short of it.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;
use tracing::{info, warn};

/// How often the cgroup is read.
const SAMPLE: Duration = Duration::from_millis(250);
/// How often its limits are read again (a `daemon-reload` changes them).
const LIMITS_EVERY: Duration = Duration::from_secs(10);
/// How often the relief is applied again while a level lasts.
const RELIEVE_EVERY: Duration = Duration::from_secs(5);
/// The idle time of a connection while memory is short.
const PRESSURE_IDLE: Duration = Duration::from_secs(5);

/// How short memory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Normal = 0,
    Elevated = 1,
    Critical = 2,
}

impl Level {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::Elevated,
            _ => Self::Critical,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Normal as u8);
static WORKING: AtomicU64 = AtomicU64::new(0);
/// `memory.high` and `memory.max`; 0 where there is none.
static HIGH: AtomicU64 = AtomicU64::new(0);
static MAX: AtomicU64 = AtomicU64::new(0);
/// Share of the last 10 s stalled on memory, in hundredths of a percent.
static STALL: AtomicU64 = AtomicU64::new(0);
static WATCHED: AtomicU8 = AtomicU8::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static SHED: AtomicU64 = AtomicU64::new(0);
/// Bumped each time relief is applied: connections watch it.
static RELIEF: LazyLock<watch::Sender<u64>> = LazyLock::new(|| watch::channel(0).0);

/// The level now.
pub fn level() -> Level {
    Level::from_u8(LEVEL.load(Ordering::Relaxed))
}

/// Whether a new connection is refused for memory: at
/// [`Level::Critical`], from an address that is not exempt. Counted.
pub fn refuses_connection(exempt: bool) -> bool {
    let refused = !exempt && level() == Level::Critical;
    if refused {
        REFUSED.fetch_add(1, Ordering::Relaxed);
    }
    refused
}

/// Whether responses are cached now.
pub fn caches() -> bool {
    level() == Level::Normal
}

/// The idle time after which a connection with nothing in flight is closed,
/// for one configured as `configured`.
pub fn idle_limit(configured: Duration) -> Duration {
    idle_limit_at(level(), configured)
}

const fn idle_limit_at(level: Level, configured: Duration) -> Duration {
    match level {
        Level::Normal => configured,
        Level::Elevated | Level::Critical => {
            if configured.as_nanos() < PRESSURE_IDLE.as_nanos() {
                configured
            } else {
                PRESSURE_IDLE
            }
        }
    }
}

/// The request-body budget in effect, for one configured as `limit`.
pub fn body_budget(limit: usize) -> usize {
    body_budget_at(level(), limit)
}

const fn body_budget_at(level: Level, limit: usize) -> usize {
    match level {
        Level::Normal => limit,
        Level::Elevated => limit / 2,
        Level::Critical => limit / 8,
    }
}

/// What a connection watches for relief.
pub fn relief() -> watch::Receiver<u64> {
    RELIEF.subscribe()
}

/// Completes when relief is applied while `activity` has nothing in flight:
/// the connection is then to be closed. Pending for ever once the monitor
/// is gone.
pub async fn idle_at_relief(
    relief: &mut watch::Receiver<u64>,
    activity: &crate::conn_limits::Activity,
) {
    loop {
        if relief.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
        if activity.idle_for().is_some() {
            return;
        }
    }
}

/// A connection closed for memory.
pub fn connection_shed() {
    SHED.fetch_add(1, Ordering::Relaxed);
}

/// The figures, for the metrics and the admin API.
#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    /// Whether the process's cgroup is read at all
    pub watched: bool,
    pub level: Level,
    pub working_set_bytes: u64,
    pub high_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    /// Share of the last 10 s stalled on memory, in percent
    pub stalled_percent: f64,
    pub refused_connections: u64,
    pub shed_connections: u64,
}

pub fn snapshot() -> MemorySnapshot {
    let limit = |value: u64| (value > 0).then_some(value);
    let stall = STALL.load(Ordering::Relaxed);
    MemorySnapshot {
        watched: WATCHED.load(Ordering::Relaxed) != 0,
        level: level(),
        working_set_bytes: WORKING.load(Ordering::Relaxed),
        high_bytes: limit(HIGH.load(Ordering::Relaxed)),
        max_bytes: limit(MAX.load(Ordering::Relaxed)),
        stalled_percent: f64::from(u32::try_from(stall).unwrap_or(u32::MAX)) / 100.0,
        refused_connections: REFUSED.load(Ordering::Relaxed),
        shed_connections: SHED.load(Ordering::Relaxed),
    }
}

/// One reading of the cgroup.
#[derive(Debug, Clone, Copy)]
struct Reading {
    working: u64,
    high: Option<u64>,
    max: Option<u64>,
    /// Hundredths of a percent
    stall: u64,
}

/// `working` as thousandths of `limit`.
fn per_mille(working: u64, limit: Option<u64>) -> u64 {
    limit
        .filter(|l| *l > 0)
        .map_or(0, |l| working.saturating_mul(1000) / l)
}

/// The level for `reading`, from `previous`: entered at one threshold, left
/// only below a lower one.
fn classify(previous: Level, reading: Reading) -> Level {
    let high = per_mille(reading.working, reading.high);
    let max = per_mille(reading.working, reading.max);
    // Against MemoryMax only where there is no MemoryHigh for Elevated
    let soft = if reading.high.is_some() {
        high
    } else {
        max * 80 / 70
    };
    let critical = high >= 950 || max >= 900;
    let stays_critical = high >= 850 || max >= 800;
    let elevated = soft >= 800 || reading.stall >= 2000;
    let stays_elevated = soft >= 650 || reading.stall >= 500;
    if critical || (previous == Level::Critical && stays_critical) {
        Level::Critical
    } else if elevated || (previous >= Level::Elevated && stays_elevated) {
        Level::Elevated
    } else {
        Level::Normal
    }
}

/// The cgroup v2 path in `/proc/self/cgroup`.
fn own_cgroup(text: &str) -> Option<&str> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|path| !path.is_empty() && *path != "/")
}

/// A limit file: a byte count, or `max` for none.
fn parse_limit(text: &str) -> Option<u64> {
    text.trim().parse().ok().filter(|v| *v > 0)
}

/// The working set from `memory.stat`.
fn parse_working(stat: &str) -> Option<u64> {
    let mut fields = std::collections::HashMap::new();
    for line in stat.lines() {
        if let Some((name, value)) = line.split_once(' ') {
            if let Ok(value) = value.trim().parse::<u64>() {
                fields.insert(name, value);
            }
        }
    }
    let field = |name: &str| fields.get(name).copied().unwrap_or(0);
    let anon = *fields.get("anon")?;
    // `kernel` (Linux 5.18 on) is every kind of kernel memory; before it,
    // the kinds that matter here, without reclaimable slab
    let kernel = fields.get("kernel").map_or_else(
        || {
            field("kernel_stack")
                + field("pagetables")
                + field("percpu")
                + field("slab_unreclaimable")
                + field("vmalloc")
        },
        |kernel| kernel.saturating_sub(field("slab_reclaimable")),
    );
    Some(anon + kernel + field("sock"))
}

/// The `some avg10` share of `memory.pressure`, in hundredths of a percent.
fn parse_stall(pressure: &str) -> Option<u64> {
    let some = pressure.lines().find(|l| l.starts_with("some "))?;
    let value = some
        .split_whitespace()
        .find_map(|field| field.strip_prefix("avg10="))?;
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    let whole: u64 = whole.parse().ok()?;
    let mut digits = fraction
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|d| u64::from(d - b'0'));
    let hundredths = digits.next().unwrap_or(0) * 10 + digits.next().unwrap_or(0);
    Some(whole * 100 + hundredths)
}

/// The process's own cgroup directory, where its memory is accounted.
#[derive(Debug)]
struct Cgroup {
    dir: std::path::PathBuf,
}

impl Cgroup {
    fn own() -> Option<Self> {
        let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let path = own_cgroup(&text)?;
        let dir = std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
        dir.join("memory.stat").exists().then_some(Self { dir })
    }

    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(name)).ok()
    }

    fn limit(&self, name: &str) -> Option<u64> {
        self.read(name).as_deref().and_then(parse_limit)
    }
}

/// Watch the process's memory, for as long as the runtime runs. Nothing is
/// watched where the process has no cgroup v2 memory accounting of its own.
pub fn spawn() {
    let Some(cgroup) = Cgroup::own() else {
        info!("Memory pressure: no cgroup memory accounting for this process; not watched");
        return;
    };
    WATCHED.store(1, Ordering::Relaxed);
    info!("Memory pressure: watching {}", cgroup.dir.display());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SAMPLE);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut limits: Option<(tokio::time::Instant, Option<u64>, Option<u64>)> = None;
        let mut relieved: Option<tokio::time::Instant> = None;
        loop {
            tick.tick().await;
            let now = tokio::time::Instant::now();
            let (high, max) = match limits {
                Some((at, high, max)) if now.duration_since(at) < LIMITS_EVERY => (high, max),
                _ => {
                    let high = cgroup.limit("memory.high");
                    let max = cgroup.limit("memory.max");
                    HIGH.store(high.unwrap_or(0), Ordering::Relaxed);
                    MAX.store(max.unwrap_or(0), Ordering::Relaxed);
                    limits = Some((now, high, max));
                    (high, max)
                }
            };
            let Some(working) = cgroup
                .read("memory.stat")
                .as_deref()
                .and_then(parse_working)
            else {
                continue;
            };
            let stall = cgroup
                .read("memory.pressure")
                .as_deref()
                .and_then(parse_stall)
                .unwrap_or(0);
            WORKING.store(working, Ordering::Relaxed);
            STALL.store(stall, Ordering::Relaxed);

            let previous = level();
            let next = classify(
                previous,
                Reading {
                    working,
                    high,
                    max,
                    stall,
                },
            );
            if next != previous {
                LEVEL.store(next as u8, Ordering::Relaxed);
                let mib = |bytes: Option<u64>| {
                    bytes.map_or_else(|| "none".to_string(), |b| format!("{} MiB", b >> 20))
                };
                let message = format!(
                    "Memory pressure {} -> {}: working set {} MiB, MemoryHigh {}, MemoryMax {}, stalled {}.{:02} %",
                    previous.as_str(),
                    next.as_str(),
                    working >> 20,
                    mib(high),
                    mib(max),
                    stall / 100,
                    stall % 100
                );
                if next > previous {
                    warn!("{message}");
                } else {
                    info!("{message}");
                }
            }
            if next == Level::Normal {
                relieved = None;
            } else if next > previous
                || relieved.is_none_or(|at| now.duration_since(at) >= RELIEVE_EVERY)
            {
                relieve(next);
                relieved = Some(now);
            }
        }
    });
}

/// Give up what the proxy keeps that it can do without, at `level`.
fn relieve(level: Level) {
    if let Some(cache) = crate::cache::built() {
        match level {
            Level::Normal => {}
            Level::Elevated => cache.shrink_to_half(),
            Level::Critical => {
                cache.purge_all();
            }
        }
    }
    RELIEF.send_modify(|generation| *generation = generation.wrapping_add(1));
    return_freed_memory(level == Level::Critical);
}

/// Have the allocator give what has been freed back to the system now,
/// rather than after its own delay; `force` takes everything it can.
#[allow(unsafe_code)] // libmimalloc-sys's C entry point
fn return_freed_memory(force: bool) {
    // SAFETY: mi_collect takes no pointers and may be called from any thread
    // at any time; it only releases memory no allocation refers to.
    unsafe { libmimalloc_sys::mi_collect(force) };
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn reading(working: u64, high: Option<u64>, max: Option<u64>, stall: u64) -> Reading {
        Reading {
            working: working * MIB,
            high: high.map(|h| h * MIB),
            max: max.map(|m| m * MIB),
            stall,
        }
    }

    #[test]
    fn levels_are_entered_at_their_thresholds() {
        let at = |working, stall| {
            classify(
                Level::Normal,
                reading(working, Some(1000), Some(1500), stall),
            )
        };
        assert_eq!(at(790, 0), Level::Normal);
        assert_eq!(at(800, 0), Level::Elevated);
        assert_eq!(at(949, 0), Level::Elevated);
        assert_eq!(at(950, 0), Level::Critical);
        // Stalled a fifth of the time: Elevated, never Critical
        assert_eq!(at(100, 2000), Level::Elevated);
        assert_eq!(at(100, 9999), Level::Elevated);
        // MemoryMax alone
        let max_only = |working| classify(Level::Normal, reading(working, None, Some(1000), 0));
        assert_eq!(max_only(690), Level::Normal);
        assert_eq!(max_only(700), Level::Elevated);
        assert_eq!(max_only(900), Level::Critical);
        // No limits: the stall alone
        assert_eq!(
            classify(Level::Normal, reading(10_000, None, None, 0)),
            Level::Normal
        );
        assert_eq!(
            classify(Level::Normal, reading(10_000, None, None, 2500)),
            Level::Elevated
        );
    }

    #[test]
    fn a_level_is_left_only_well_below_its_threshold() {
        let from = |previous, working| classify(previous, reading(working, Some(1000), None, 0));
        assert_eq!(from(Level::Critical, 900), Level::Critical);
        assert_eq!(from(Level::Critical, 849), Level::Elevated);
        assert_eq!(from(Level::Elevated, 700), Level::Elevated);
        assert_eq!(from(Level::Elevated, 649), Level::Normal);
        assert_eq!(from(Level::Normal, 700), Level::Normal);
    }

    #[test]
    fn what_each_level_gives_up() {
        let idle = Duration::from_secs(60);
        assert_eq!(idle_limit_at(Level::Normal, idle), idle);
        assert_eq!(idle_limit_at(Level::Elevated, idle), PRESSURE_IDLE);
        assert_eq!(
            idle_limit_at(Level::Critical, Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        assert_eq!(body_budget_at(Level::Normal, 800), 800);
        assert_eq!(body_budget_at(Level::Elevated, 800), 400);
        assert_eq!(body_budget_at(Level::Critical, 800), 100);
    }

    #[test]
    fn the_cgroup_files_are_read() {
        assert_eq!(
            own_cgroup("0::/system.slice/pqcrypta-proxy.service\n"),
            Some("/system.slice/pqcrypta-proxy.service")
        );
        assert_eq!(own_cgroup("12:memory:/x\n0::/\n"), None);
        assert_eq!(own_cgroup("12:memory:/x\n"), None);
        assert_eq!(parse_limit("max\n"), None);
        assert_eq!(parse_limit("1654784000\n"), Some(1_654_784_000));
        let stat = "anon 100\nfile 5000\nkernel 40\nkernel_stack 8\nslab_reclaimable 10\nsock 7\nshmem 0\n";
        assert_eq!(parse_working(stat), Some(100 + 30 + 7));
        let old = "anon 100\nfile 5000\nkernel_stack 8\npagetables 4\npercpu 2\nslab_unreclaimable 6\nslab_reclaimable 99\nsock 7\n";
        assert_eq!(parse_working(old), Some(100 + 8 + 4 + 2 + 6 + 7));
        assert_eq!(parse_working("file 5000\n"), None);
        let pressure = "some avg10=12.34 avg60=1.00 avg300=0.10 total=123\nfull avg10=3.00 avg60=0.00 avg300=0.00 total=9\n";
        assert_eq!(parse_stall(pressure), Some(1234));
        assert_eq!(
            parse_stall("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"),
            Some(0)
        );
        assert_eq!(parse_stall("some avg10=7.5 avg60=0 total=0\n"), Some(750));
        assert_eq!(parse_stall("full avg10=3.00\n"), None);
    }
}
