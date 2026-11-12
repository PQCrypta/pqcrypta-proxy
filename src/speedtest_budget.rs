//! What one client may take of the speed test.
//!
//! A speed test moves as much data as a link carries and runs a route
//! analysis that starts processes, so each client network (an IPv4 address,
//! an IPv6 /64) is held to:
//!
//! - [`STREAMS_PER_NETWORK`] test streams at once, across its connections;
//! - an hourly allowance of bytes each way ([`HOURLY_DOWNLOAD`],
//!   [`HOURLY_UPLOAD`]), reserved before a transfer starts and the unused
//!   part given back when it ends, so concurrent transfers cannot overdraw it;
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
pub const STREAMS_PER_NETWORK: usize = 32;
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
    /// Note `bytes` more of the reservation used.
    pub fn use_bytes(&mut self, bytes: u64) {
        self.used = self.used.saturating_add(bytes).min(self.reserved);
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
    let window = usage.window_start;
    Ok(Reservation {
        budget,
        network,
        direction,
        reserved: bytes,
        used: 0,
        window,
    })
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
        second.use_bytes(1024);
        drop(second);
        drop(first);
        assert!(reserve_in(budget, ip, Direction::Upload, half, now).is_ok());
        // An hour on, the window starts again
        let later = now + WINDOW;
        assert!(reserve_in(budget, ip, Direction::Upload, HOURLY_UPLOAD, later).is_ok());
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
