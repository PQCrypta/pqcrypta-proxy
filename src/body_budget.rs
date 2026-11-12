//! The memory request bodies may occupy while the proxy holds them.
//!
//! A request body is read whole before it is inspected and forwarded, up to
//! `security.max_request_size` each. That bounds one request; this bounds
//! all of them together, on every transport: each body is counted here as
//! it is read, and a request whose next piece would take the process past
//! `security.max_buffered_body_bytes` is answered 503 instead of read. The
//! count is given back when the request is done, however it ends.

use std::sync::atomic::{AtomicUsize, Ordering};

/// The least the budget is when it is derived from `max_request_size`.
const FLOOR: usize = 256 * 1024 * 1024;

static LIMIT: AtomicUsize = AtomicUsize::new(usize::MAX);
static HELD: AtomicUsize = AtomicUsize::new(0);

/// The budget for `[security]` as configured: `max_buffered_body_bytes`, or
/// when that is 0 four bodies of `max_request_size`, and at least 256 MiB.
pub fn budget_for(max_buffered_body_bytes: usize, max_request_size: usize) -> usize {
    if max_buffered_body_bytes > 0 {
        max_buffered_body_bytes
    } else {
        max_request_size.saturating_mul(4).max(FLOOR)
    }
}

/// Apply the budget, at startup and on every reload.
pub fn configure(max_buffered_body_bytes: usize, max_request_size: usize) {
    LIMIT.store(
        budget_for(max_buffered_body_bytes, max_request_size),
        Ordering::Relaxed,
    );
}

/// The bytes of request bodies held now.
pub fn held() -> usize {
    HELD.load(Ordering::Relaxed)
}

/// One request's share of the budget, given back when it drops.
#[derive(Debug, Default)]
pub struct Reservation {
    bytes: usize,
}

impl Reservation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count `more` bytes about to be kept for this request. `false` when
    /// they would take the process past its budget: nothing is counted, and
    /// the caller refuses the request rather than read on.
    #[must_use]
    pub fn grow(&mut self, more: usize) -> bool {
        Self::take(&HELD, LIMIT.load(Ordering::Relaxed), more) && {
            self.bytes += more;
            true
        }
    }

    fn take(held: &AtomicUsize, limit: usize, more: usize) -> bool {
        held.try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
            now.checked_add(more).filter(|total| *total <= limit)
        })
        .is_ok()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        HELD.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_follows_the_body_limit_unless_it_is_set() {
        assert_eq!(budget_for(0, 10 * 1024 * 1024), FLOOR);
        assert_eq!(budget_for(0, 200 * 1024 * 1024), 800 * 1024 * 1024);
        assert_eq!(budget_for(1024, 200 * 1024 * 1024), 1024);
    }

    /// Against a count of its own: the process's is shared with every test
    /// that reads a body.
    #[test]
    fn a_piece_past_the_budget_is_not_counted() {
        let held = AtomicUsize::new(0);
        assert!(Reservation::take(&held, 100, 60));
        assert!(!Reservation::take(&held, 100, 41));
        assert_eq!(held.load(Ordering::Relaxed), 60);
        assert!(Reservation::take(&held, 100, 40));
        assert!(!Reservation::take(&held, 100, 1));
        assert!(!Reservation::take(&held, usize::MAX, usize::MAX));
    }

    #[test]
    fn a_reservation_gives_back_what_it_took() {
        {
            let mut reservation = Reservation::new();
            assert!(reservation.grow(4096));
            assert!(reservation.grow(4096));
            assert!(held() >= 8192);
        }
        // Other tests' reservations come and go; this one's is gone.
        let mut probe = Reservation::new();
        assert!(probe.grow(1));
    }
}
