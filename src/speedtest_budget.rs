//! What one client may take of the speed test.
//!
//! A speed test moves as much data as a link carries and runs a route
//! analysis that starts processes, so each client network (an IPv4 address,
//! an IPv6 /64) is held to:
//!
//! - [`STREAMS_PER_NETWORK`] test streams at once, across its connections;
//! - an hourly allowance of bytes each way ([`HOURLY_DOWNLOAD`],
//!   [`HOURLY_UPLOAD`]), which a transfer draws on as its bytes move, a block
//!   at a time ([`Reservation::draw`]), so transfers side by side cannot
//!   overdraw it and none holds more than it is about to move;
//! - one route analysis at a time, [`ANALYSIS_COOLDOWN`] apart, and no more
//!   than [`ANALYSES_AT_ONCE`] analyses on the server at once.
//!
//! A refusal says when to try again.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Test streams one network may have open at once.
///
/// That is the page's largest QUIC upload pool and its control streams beside
/// it (the node's info and meter). A browser keeps about 128 KB in flight per
/// WebTransport session,
/// so the page uploads on a pool of sessions, up to [`UPLOAD_POOL_SESSIONS`]
/// of [`UPLOAD_POOL_STREAMS_PER_SESSION`] streams, and a long path needs most
/// of them. The node's info answer carries this limit, and the page fits its
/// pool under it.
pub const STREAMS_PER_NETWORK: usize =
    UPLOAD_POOL_SESSIONS * UPLOAD_POOL_STREAMS_PER_SESSION + CONTROL_STREAMS;
/// The most sessions the page's QUIC upload pool opens.
pub const UPLOAD_POOL_SESSIONS: usize = 32;
/// The streams the page's QUIC upload pool runs on each session.
pub const UPLOAD_POOL_STREAMS_PER_SESSION: usize = 4;
/// Streams beside the pool: the node's info, meter and route analysis.
const CONTROL_STREAMS: usize = 8;
/// What a transfer takes of its allowance at a time ([`Reservation::draw`]).
pub const DRAW_BLOCK: u64 = 16 * 1024 * 1024;
/// Bytes one network may download in an hour.
pub const HOURLY_DOWNLOAD: u64 = 16 * 1024 * 1024 * 1024;
/// Bytes one network may upload in an hour.
pub const HOURLY_UPLOAD: u64 = 8 * 1024 * 1024 * 1024;
/// The window the allowances are counted in.
const WINDOW: Duration = Duration::from_hours(1);
/// Route analyses running on the server at once (four probe processes each).
pub const ANALYSES_AT_ONCE: usize = 4;
/// The least time between two route analyses for one network.
pub const ANALYSIS_COOLDOWN: Duration = Duration::from_secs(30);
/// Networks whose usage is remembered before the oldest is let go.
const NETWORKS: usize = 8192;

/// Which way a transfer goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

/// A refusal: what the client asked for is past its allowance, or the
/// server is busy, until `retry_after` has passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refused {
    pub retry_after: Duration,
}

/// The network a client is counted as ([`crate::conn_limits::client_network`]).
pub fn network(ip: IpAddr) -> IpAddr {
    crate::conn_limits::client_network(ip)
}

#[derive(Debug)]
struct Usage {
    window_start: Instant,
    downloaded: u64,
    uploaded: u64,
}

#[derive(Debug, Default)]
struct Budget {
    streams: DashMap<IpAddr, usize>,
    usage: DashMap<IpAddr, Usage>,
    last_analysis: DashMap<IpAddr, Instant>,
    analyses: AtomicU64,
}

static BUDGET: LazyLock<Budget> = LazyLock::new(Budget::default);

/// One open test stream, given back when dropped.
#[derive(Debug)]
pub struct StreamSlot {
    network: IpAddr,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        BUDGET.streams.remove_if_mut(&self.network, |_, open| {
            *open = open.saturating_sub(1);
            *open == 0
        });
    }
}

/// A place for one more test stream from `ip`, or `None` at the limit.
pub fn enter_stream(ip: IpAddr) -> Option<StreamSlot> {
    let network = network(ip);
    let mut open = BUDGET.streams.entry(network).or_insert(0);
    if *open >= STREAMS_PER_NETWORK {
        return None;
    }
    *open += 1;
    Some(StreamSlot { network })
}

/// Bytes reserved from an allowance; what is not used is given back.
#[derive(Debug)]
pub struct Reservation {
    /// The budget it was taken from
    budget: &'static Budget,
    network: IpAddr,
    direction: Direction,
    reserved: u64,
    used: u64,
    /// The window it was taken in: what it does not use goes back to that
    /// window only, not to one that has started since
    window: Instant,
}

impl Reservation {
    /// Use `bytes` more, taking more of the allowance first when what is
    /// reserved is spent: a block at a time ([`DRAW_BLOCK`]), or just what
    /// `bytes` needs when a block no longer fits. A transfer draws as its
    /// bytes move, so transfers side by side hold only what they are about
    /// to move rather than all they might, and together cannot overdraw the
    /// allowance. Refused, using nothing more, when the allowance cannot
    /// cover `bytes`.
    pub fn draw(&mut self, bytes: u64) -> Result<(), Refused> {
        self.draw_at(bytes, Instant::now())
    }

    fn draw_at(&mut self, bytes: u64, now: Instant) -> Result<(), Refused> {
        let needed = self.used.saturating_add(bytes);
        if needed > self.reserved {
            let short = needed - self.reserved;
            let block = short.max(DRAW_BLOCK);
            let (window, taken) = match take(self.budget, self.network, self.direction, block, now)
            {
                Ok(window) => (window, block),
                Err(_) => (
                    take(self.budget, self.network, self.direction, short, now)?,
                    short,
                ),
            };
            if window != self.window {
                // The window this was taken in has ended, and what it left
                // unused went with it: count from the new one
                self.reserved = self.used;
                self.window = window;
            }
            self.reserved += taken;
        }
        self.used = needed;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let unused = self.reserved - self.used;
        if unused > 0 {
            if let Some(mut usage) = self
                .budget
                .usage
                .get_mut(&self.network)
                .filter(|usage| usage.window_start == self.window)
            {
                let taken = match self.direction {
                    Direction::Download => &mut usage.downloaded,
                    Direction::Upload => &mut usage.uploaded,
                };
                *taken = taken.saturating_sub(unused);
            }
        }
    }
}

/// Reserve `bytes` of `ip`'s allowance for one transfer.
///
/// The transfer then draws on it, and on more, as its bytes move
/// ([`Reservation::draw`]). It reserves what it moves first (a block, or
/// less), so one the allowance cannot start is refused before any byte moves.
pub fn reserve(ip: IpAddr, direction: Direction, bytes: u64) -> Result<Reservation, Refused> {
    reserve_in(&BUDGET, ip, direction, bytes, Instant::now())
}

fn reserve_in(
    budget: &'static Budget,
    ip: IpAddr,
    direction: Direction,
    bytes: u64,
    now: Instant,
) -> Result<Reservation, Refused> {
    let network = network(ip);
    let window = take(budget, network, direction, bytes, now)?;
    Ok(Reservation {
        budget,
        network,
        direction,
        reserved: bytes,
        used: 0,
        window,
    })
}

/// Take `bytes` of `network`'s allowance in the window running at `now`,
/// which it returns, or refuse, taking nothing.
fn take(
    budget: &'static Budget,
    network: IpAddr,
    direction: Direction,
    bytes: u64,
    now: Instant,
) -> Result<Instant, Refused> {
    if budget.usage.len() >= NETWORKS {
        budget
            .usage
            .retain(|_, usage| now.duration_since(usage.window_start) < WINDOW);
    }
    let mut usage = budget.usage.entry(network).or_insert_with(|| Usage {
        window_start: now,
        downloaded: 0,
        uploaded: 0,
    });
    if now.duration_since(usage.window_start) >= WINDOW {
        *usage = Usage {
            window_start: now,
            downloaded: 0,
            uploaded: 0,
        };
    }
    let (taken, allowance) = match direction {
        Direction::Download => (&mut usage.downloaded, HOURLY_DOWNLOAD),
        Direction::Upload => (&mut usage.uploaded, HOURLY_UPLOAD),
    };
    if taken.saturating_add(bytes) > allowance {
        let elapsed = now.duration_since(usage.window_start);
        return Err(Refused {
            retry_after: WINDOW.saturating_sub(elapsed),
        });
    }
    *taken += bytes;
    Ok(usage.window_start)
}

/// One route analysis under way, given back when dropped.
#[derive(Debug)]
pub struct AnalysisSlot(());

impl Drop for AnalysisSlot {
    fn drop(&mut self) {
        BUDGET.analyses.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Start a route analysis for `ip`: refused while the server runs
/// [`ANALYSES_AT_ONCE`], or within [`ANALYSIS_COOLDOWN`] of this network's
/// last one (which covers one running now).
pub fn start_analysis(ip: IpAddr) -> Result<AnalysisSlot, Refused> {
    let network = network(ip);
    let now = Instant::now();
    if BUDGET.last_analysis.len() >= NETWORKS {
        BUDGET
            .last_analysis
            .retain(|_, started| now.duration_since(*started) < ANALYSIS_COOLDOWN);
    }
    let last = BUDGET.last_analysis.entry(network);
    if let dashmap::mapref::entry::Entry::Occupied(started) = &last {
        let since = now.duration_since(*started.get());
        if since < ANALYSIS_COOLDOWN {
            return Err(Refused {
                retry_after: ANALYSIS_COOLDOWN.saturating_sub(since),
            });
        }
    }
    let running = BUDGET.analyses.fetch_add(1, Ordering::AcqRel);
    if running >= ANALYSES_AT_ONCE as u64 {
        BUDGET.analyses.fetch_sub(1, Ordering::AcqRel);
        return Err(Refused {
            retry_after: Duration::from_secs(5),
        });
    }
    last.insert(now);
    Ok(AnalysisSlot(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ipv6_client_is_counted_by_its_slash_64() {
        assert_eq!(
            network("2001:db8:1:2:aa::9".parse().unwrap()),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            network("::ffff:192.0.2.7".parse().unwrap()),
            "192.0.2.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_network_has_so_many_streams_at_once() {
        let ip: IpAddr = "198.51.100.40".parse().unwrap();
        let slots: Vec<_> = (0..STREAMS_PER_NETWORK)
            .map(|_| enter_stream(ip).expect("within the limit"))
            .collect();
        assert!(enter_stream(ip).is_none());
        drop(slots);
        assert!(enter_stream(ip).is_some());
    }

    /// Reserved up front, so transfers side by side cannot overdraw the
    /// allowance; what a transfer does not use is given back.
    #[test]
    fn an_allowance_is_reserved_and_the_unused_part_given_back() {
        let budget: &'static Budget = Box::leak(Box::default());
        let ip: IpAddr = "198.51.100.41".parse().unwrap();
        let now = Instant::now();
        let half = HOURLY_UPLOAD / 2;
        let first = reserve_in(budget, ip, Direction::Upload, half, now).unwrap();
        let mut second = reserve_in(budget, ip, Direction::Upload, half, now).unwrap();
        let refused = reserve_in(budget, ip, Direction::Upload, 1, now).unwrap_err();
        assert!(refused.retry_after <= WINDOW && refused.retry_after > Duration::ZERO);
        // Downloads are their own allowance
        assert!(reserve_in(budget, ip, Direction::Download, half, now).is_ok());
        second.draw(1024).unwrap();
        drop(second);
        drop(first);
        assert!(reserve_in(budget, ip, Direction::Upload, half, now).is_ok());
        // An hour on, the window starts again
        let later = now + WINDOW;
        assert!(reserve_in(budget, ip, Direction::Upload, HOURLY_UPLOAD, later).is_ok());
    }

    /// A transfer draws a block at a time, then just what it needs when a
    /// block no longer fits, is refused past the allowance, and gives back
    /// what it took and did not use.
    #[test]
    fn a_transfer_draws_its_allowance_as_its_bytes_move() {
        let budget: &'static Budget = Box::leak(Box::default());
        let ip: IpAddr = "198.51.100.43".parse().unwrap();
        let now = Instant::now();
        let taken = |budget: &Budget| budget.usage.get(&network(ip)).unwrap().uploaded;
        let mut transfer = reserve_in(budget, ip, Direction::Upload, 0, now).unwrap();
        transfer.draw_at(1000, now).unwrap();
        assert_eq!(
            taken(budget),
            DRAW_BLOCK,
            "a block taken for the first bytes"
        );
        transfer.draw_at(DRAW_BLOCK - 1000, now).unwrap();
        assert_eq!(taken(budget), DRAW_BLOCK, "the block covers them");
        // Another transfer takes all but what is left of half a block
        let rest = HOURLY_UPLOAD - DRAW_BLOCK - DRAW_BLOCK / 2;
        let other = reserve_in(budget, ip, Direction::Upload, rest, now).unwrap();
        transfer.draw_at(DRAW_BLOCK / 4, now).unwrap();
        assert_eq!(
            taken(budget),
            HOURLY_UPLOAD - DRAW_BLOCK / 2 + DRAW_BLOCK / 4,
            "just what is needed once a block does not fit"
        );
        let refused = transfer.draw_at(DRAW_BLOCK, now).unwrap_err();
        assert!(refused.retry_after > Duration::ZERO);
        assert_eq!(
            transfer.used,
            DRAW_BLOCK + DRAW_BLOCK / 4,
            "a refusal uses nothing"
        );
        drop(other);
        drop(transfer);
        assert_eq!(
            taken(budget),
            DRAW_BLOCK + DRAW_BLOCK / 4,
            "only what moved stays taken"
        );
    }

    /// A transfer running across the hour draws on the new window and gives
    /// back to it only what it took there.
    #[test]
    fn a_transfer_across_the_hour_draws_on_the_new_window() {
        let budget: &'static Budget = Box::leak(Box::default());
        let ip: IpAddr = "198.51.100.44".parse().unwrap();
        let now = Instant::now();
        let mut transfer = reserve_in(budget, ip, Direction::Download, 0, now).unwrap();
        transfer.draw_at(DRAW_BLOCK, now).unwrap();
        let later = now + WINDOW;
        transfer.draw_at(10, later).unwrap();
        drop(transfer);
        let usage = budget.usage.get(&network(ip)).unwrap();
        assert_eq!(usage.window_start, later);
        assert_eq!(usage.downloaded, 10, "the new window keeps what it moved");
    }

    #[test]
    fn route_analyses_are_spaced_and_few() {
        let ip: IpAddr = "198.51.100.42".parse().unwrap();
        let slot = start_analysis(ip).expect("the first one runs");
        let again = start_analysis(ip).unwrap_err();
        assert!(again.retry_after <= ANALYSIS_COOLDOWN);
        drop(slot);
    }
}
