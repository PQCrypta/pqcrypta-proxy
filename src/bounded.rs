//! Ceilings for the tables a request can add to.
//!
//! A table keyed by something a client chooses (an address, a fingerprint, a
//! cookie, a path) grows by one entry for each new value it sends, and a
//! ceiling enforced only by a periodic sweep lets it grow by the arrival rate
//! times the sweep's period first. A ceiling enforced by sweeping whenever a
//! new key finds the table full costs every new key a pass over the whole
//! table once the table is full of live entries, which is exactly when new
//! keys arrive fastest.
//!
//! [`Ceiling`] is enforced where entries are made: a new key is admitted while
//! the table is below its ceiling; at the ceiling the caller's sweep (which
//! drops what has expired) runs at most once per `gap`, by whichever caller
//! gets there first, and a key that still finds the table full is not
//! admitted. What not being admitted means is the table's own decision: a
//! request counted against a shared overflow entry, a value not cached, early
//! data not accepted.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The process's clock origin, so a sweep time fits in an atomic.
static START: LazyLock<Instant> = LazyLock::new(Instant::now);

fn now_ms() -> u64 {
    u64::try_from(START.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The most entries a table holds, and how often a full table may be swept.
#[derive(Debug)]
pub struct Ceiling {
    cap: usize,
    gap_ms: u64,
    /// When the table was last swept for room, in ms since [`START`]; 0 when
    /// never
    swept: AtomicU64,
}

impl Ceiling {
    /// A ceiling of `cap` entries, swept for room at most once per `gap`.
    pub fn new(cap: usize, gap: Duration) -> Self {
        Self {
            cap: cap.max(1),
            gap_ms: u64::try_from(gap.as_millis()).unwrap_or(u64::MAX),
            swept: AtomicU64::new(0),
        }
    }

    /// The most entries the table holds.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Whether a new key may be added to a table holding `len` entries.
    /// `sweep` drops what has expired and returns how many entries are left;
    /// it runs only when the table is full and the last sweep is at least a
    /// gap old, and then only in one caller.
    pub fn admits(&self, len: usize, sweep: impl FnOnce() -> usize) -> bool {
        if len < self.cap {
            return true;
        }
        let now = now_ms().max(1);
        let last = self.swept.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < self.gap_ms {
            return false;
        }
        if self
            .swept
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            // Another caller is sweeping
            return false;
        }
        sweep() < self.cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn below_the_ceiling_nothing_is_swept() {
        let c = Ceiling::new(4, Duration::from_secs(60));
        let swept = Cell::new(0);
        assert!(c.admits(3, || {
            swept.set(swept.get() + 1);
            0
        }));
        assert_eq!(swept.get(), 0);
    }

    /// A full table is swept once a gap: the next new keys are refused
    /// without a pass over the table.
    #[test]
    fn a_full_table_is_swept_once_a_gap() {
        let c = Ceiling::new(4, Duration::from_secs(60));
        let swept = Cell::new(0);
        let sweep = || {
            swept.set(swept.get() + 1);
            4
        };
        assert!(!c.admits(4, sweep));
        assert!(!c.admits(4, sweep));
        assert!(!c.admits(5, sweep));
        assert_eq!(swept.get(), 1);
    }

    #[test]
    fn a_sweep_that_makes_room_admits() {
        let c = Ceiling::new(4, Duration::from_secs(60));
        assert!(c.admits(4, || 2));
    }

    #[test]
    fn after_the_gap_a_full_table_is_swept_again() {
        let c = Ceiling::new(4, Duration::from_millis(1));
        assert!(!c.admits(4, || 4));
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.admits(4, || 1));
    }
}
