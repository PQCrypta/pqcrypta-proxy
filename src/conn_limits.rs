//! What every listener holds a client connection to.
//!
//! How many may be open at once, in all and from one address; the socket
//! options that notice a peer that has gone; and the idle time after which a
//! connection with nothing in flight is closed.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// `server.max_connections`; 0 for no limit.
static MAX_TOTAL: AtomicU32 = AtomicU32::new(0);
/// `security.max_connections_per_ip`; 0 for no limit.
static MAX_PER_ADDRESS: AtomicU32 = AtomicU32::new(0);
static OPEN: AtomicU64 = AtomicU64::new(0);
static PER_ADDRESS: LazyLock<DashMap<IpAddr, u32>> = LazyLock::new(DashMap::new);

/// Set the limits [`admit`] applies. Called at startup and after a reload.
pub fn configure(max_total: u32, max_per_address: u32) {
    MAX_TOTAL.store(max_total, Ordering::Relaxed);
    MAX_PER_ADDRESS.store(max_per_address, Ordering::Relaxed);
}

/// The network a client is counted as: an IPv4 address (an IPv4-mapped one
/// unwrapped), or the /64 an IPv6 address is in, which one client holds.
pub fn client_network(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Client connections open now, on every listener.
pub fn open_connections() -> u64 {
    OPEN.load(Ordering::Relaxed)
}

/// One client connection's place under the limits, given back on drop.
#[derive(Debug)]
pub struct ConnectionSlot {
    /// The address it is counted against; None when it is exempt.
    address: Option<IpAddr>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Ordering::Relaxed);
        if let Some(address) = self.address {
            if let Some(mut count) = PER_ADDRESS.get_mut(&address) {
                *count = count.saturating_sub(1);
            }
            PER_ADDRESS.remove_if(&address, |_, count| *count == 0);
        }
    }
}

/// Take a place for one more connection from `address`.
///
/// `None` when the proxy holds `server.max_connections` already, or this
/// address `security.max_connections_per_ip`. `exempt` addresses (the
/// operator's own, and a load balancer that connects for many clients) are
/// counted in the total alone.
pub fn admit(address: IpAddr, exempt: bool) -> Option<ConnectionSlot> {
    let max_total = u64::from(MAX_TOTAL.load(Ordering::Relaxed));
    let taken = OPEN.fetch_add(1, Ordering::Relaxed);
    if max_total > 0 && taken >= max_total {
        OPEN.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    let max_per_address = MAX_PER_ADDRESS.load(Ordering::Relaxed);
    if exempt || max_per_address == 0 {
        return Some(ConnectionSlot { address: None });
    }
    let address = address.to_canonical();
    let within = {
        let mut count = PER_ADDRESS.entry(address).or_insert(0);
        if *count < max_per_address {
            *count += 1;
            true
        } else {
            false
        }
    };
    if within {
        Some(ConnectionSlot {
            address: Some(address),
        })
    } else {
        OPEN.fetch_sub(1, Ordering::Relaxed);
        None
    }
}

/// How long a silent TCP peer is given before it is probed, between probes,
/// and how many unanswered probes end the connection: a peer that went away
/// without closing is found in about a minute and a half.
const KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_PROBES: u32 = 3;

/// The options every accepted client socket gets: Nagle off where configured,
/// keep-alive probes, and a bound on how long sent data may go unacknowledged.
pub fn tune_client_socket(stream: &tokio::net::TcpStream, nodelay: bool, unacked: Duration) {
    if nodelay {
        if let Err(e) = stream.set_nodelay(true) {
            tracing::debug!("TCP_NODELAY not set on a client socket: {}", e);
        }
    }
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_TIME)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_PROBES);
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        tracing::debug!("keep-alive not set on a client socket: {}", e);
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = socket.set_tcp_user_timeout(Some(unacked)) {
        tracing::debug!("TCP_USER_TIMEOUT not set on a client socket: {}", e);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = unacked;
}

/// Wait out an `accept()` failure that will fail again at once: with no
/// descriptors or memory left the call returns immediately, and a loop that
/// retried it at once would spin.
pub async fn after_accept_error(error: &std::io::Error) {
    #[cfg(unix)]
    let exhausted = matches!(
        error.raw_os_error(),
        Some(libc_codes::EMFILE | libc_codes::ENFILE | libc_codes::ENOBUFS | libc_codes::ENOMEM)
    );
    #[cfg(not(unix))]
    let exhausted = error.kind() == std::io::ErrorKind::OutOfMemory;
    if exhausted {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The errno values [`after_accept_error`] waits on (Linux and the BSDs agree
/// on these four).
#[cfg(unix)]
mod libc_codes {
    pub const ENOMEM: i32 = 12;
    pub const ENFILE: i32 = 23;
    pub const EMFILE: i32 = 24;
    #[cfg(target_os = "linux")]
    pub const ENOBUFS: i32 = 105;
    #[cfg(not(target_os = "linux"))]
    pub const ENOBUFS: i32 = 55;
}

/// What one connection is doing: the exchanges in flight on it, and since
/// when it has had none. An exchange is in flight from its request's arrival
/// until its response body has been sent or dropped.
#[derive(Debug)]
pub struct Activity {
    in_flight: AtomicUsize,
    idle_since: Mutex<Instant>,
}

impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            in_flight: AtomicUsize::new(0),
            idle_since: Mutex::new(Instant::now()),
        })
    }

    /// One exchange begins; it ends when the returned guard drops.
    pub fn begin(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        InFlight(Arc::clone(self))
    }

    /// How long the connection has had nothing in flight; `None` while
    /// something is.
    pub fn idle_for(&self) -> Option<Duration> {
        (self.in_flight.load(Ordering::Acquire) == 0).then(|| self.idle_since.lock().elapsed())
    }
}

/// One exchange in flight on a connection ([`Activity::begin`]).
#[derive(Debug)]
pub struct InFlight(Arc<Activity>);

impl Drop for InFlight {
    fn drop(&mut self) {
        // The time first: a reader that sees the count reach zero then finds
        // the moment it did.
        *self.0.idle_since.lock() = Instant::now();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_is_idle_only_with_nothing_in_flight() {
        let activity = Activity::new();
        assert!(activity.idle_for().is_some());
        let first = activity.begin();
        let second = activity.begin();
        assert!(activity.idle_for().is_none());
        drop(first);
        assert!(activity.idle_for().is_none());
        drop(second);
        let idle = activity.idle_for().expect("nothing in flight");
        assert!(idle < Duration::from_secs(1));
    }

    /// The limits are process-wide, so this is the one test that sets them.
    #[test]
    fn an_address_is_held_to_its_share_and_the_proxy_to_its_total() {
        let address: IpAddr = "203.0.113.50".parse().unwrap();
        let other: IpAddr = "203.0.113.51".parse().unwrap();
        configure(0, 2);
        let first = admit(address, false).expect("first");
        let second = admit(address, false).expect("second");
        assert!(admit(address, false).is_none(), "past its share");
        // An IPv4-mapped spelling is the same address
        assert!(admit("::ffff:203.0.113.50".parse().unwrap(), false).is_none());
        let elsewhere = admit(other, false).expect("another address has its own");
        let uncounted = admit(address, true).expect("an exempt connection is not counted");
        drop(first);
        let again = admit(address, false).expect("a place came back");
        drop((second, elsewhere, uncounted, again));
        assert!(PER_ADDRESS.get(&address).is_none(), "nothing left counted");

        let before = open_connections();
        configure(u32::try_from(before + 1).unwrap(), 0);
        let only = admit(address, false).expect("one place left");
        assert!(admit(other, false).is_none(), "the proxy is full");
        drop(only);
        assert!(admit(other, false).is_some());
        configure(0, 0);
    }
}
