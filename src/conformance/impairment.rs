//! A UDP socket that misbehaves on purpose.
//!
//! Two of the QUIC-layer tests are about what the *path* does, not what the
//! server says, so they cannot be produced by any amount of protocol writing:
//!
//! - `q-pmtu-blackhole` needs datagrams above a threshold to vanish silently,
//!   exactly as a real black hole behaves — no ICMP, no error, just nothing.
//! - `q-version-negotiation` needs the endpoint to reject the client's version,
//!   after which no connection is ever established. The verdict has to come
//!   from somewhere, and the only evidence is at the socket: packets arrived
//!   and no connection followed, which is the client abandoning the attempt as
//!   RFC 9000 §6.2 requires.
//!
//! Both are handled here by decorating the socket rather than patching the QUIC
//! stack, which keeps the fork's divergence from upstream to what genuinely
//! needs it.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};

use super::h3_frames::read_varint;
use quinn::{AsyncUdpSocket, UdpSender};
use tracing::{debug, warn};

/// One peer's share of what the socket counted.
///
/// The fields mirror the numeric ones on [`Counters`], and they exist because
/// `Counters` belongs to the *listener* — one per port, never reset — so every
/// field there is the running total for every client that has ever connected.
/// A verdict about one client must not be able to read a number another
/// client moved.
///
/// That was not theoretical. It shipped seven times, and the symptom was a run
/// reporting that ten of twelve implementations lose their 0-RTT to a version
/// GREASE when exactly one of them does. A baseline handle over the shared
/// counters closed that by
/// subtracting a baseline — correct arithmetic over the wrong state. It still
/// read a number every connection on the port was writing to, so the next
/// defect from that root would have been an interleaving rather than a stale
/// read, and no subtraction fixes that.
///
/// So the state is split at the source: every datagram is attributed to the
/// peer it came from or went to, and a verdict reads only that peer's counts.
#[derive(Debug, Default)]
pub struct PeerCounters {
    pub datagrams_in: AtomicU64,
    pub dropped_oversize: AtomicU64,
    pub marked_ce: AtomicU64,
    pub reordered: AtomicU64,
    pub shadowed: AtomicU64,
    pub shadow_failed: AtomicU64,
    pub ect_in: AtomicU64,
    pub initials_in: AtomicU64,
    pub dropped_loss: AtomicU64,
    pub zero_rtt_in: AtomicU64,
    pub version_negotiations_out: AtomicU64,
    /// Whether a connection has already taken a view of this entry.
    ///
    /// Decides whether a view baselines at zero or at the current values, and
    /// the distinction is not cosmetic. A connection's first datagram is what
    /// *creates* this entry, and for the 0-RTT tests that datagram is the
    /// whole measurement: early data is coalesced behind the Initial that
    /// produces the `Incoming`, so it is counted before `run_one` exists to
    /// take a baseline. Baselining at the current values there discards the
    /// only 0-RTT packet the client sends, and the suite reports that a
    /// client which did offer early data did not — measured, on the wire,
    /// with ngtcp2.
    ///
    /// So the first view of an entry starts from zero, which is exactly the
    /// count that entry was created with. A second view means a second
    /// connection from the same address, and that one baselines normally.
    viewed: std::sync::atomic::AtomicBool,
}

/// Where a port's ECN path evidence is kept between restarts.
///
/// "This port's path carries ECT" is a fact about the network between this
/// host and the clients that reach it, and it does not stop being true because
/// the proxy restarted. Keeping it only in memory meant the first matrix run
/// after every deploy measured its first three clients before any peer had
/// proven the path, and six cells read inconclusive that read `unsupported` on
/// every later run -- a verdict decided by run order, which is not a verdict.
///
/// Expires, because a path that genuinely stops carrying ECT must be able to
/// say so rather than being contradicted by a note from last month.
pub const ECN_EVIDENCE_DIR: &str = "/var/lib/pqcrypta/conformance/ecn-evidence";

/// How long remembered evidence stands before the path has to prove itself
/// again.
const ECN_EVIDENCE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

fn chrono_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A port's ECN path evidence: the flag, and where it is remembered.
///
/// One object because the two were separate and drifted immediately -- the
/// flag lived on `Counters` and also behind an `Arc` on every `PeerView`, and
/// the file path only on `Counters`, so the copy that observations actually
/// call set the flag and wrote nothing. Sharing one thing removes the chance.
#[derive(Debug, Default)]
pub struct EcnEvidence {
    proven: std::sync::atomic::AtomicBool,
    path: parking_lot::Mutex<Option<std::path::PathBuf>>,
}

impl EcnEvidence {
    pub fn proven(&self) -> bool {
        self.proven.load(Ordering::Relaxed)
    }

    /// Say where to remember it, and load what is already remembered.
    pub fn remember_at(&self, path: std::path::PathBuf) {
        if ecn_evidence_remembered(&path) {
            self.proven.store(true, Ordering::Relaxed);
        }
        *self.path.lock() = Some(path);
    }

    /// A peer echoed the markings this port sent.
    pub fn note(&self) {
        if self.proven.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Some(path) = self.path.lock().as_ref() {
            // Best effort: losing the file costs one cold run, not a wrong
            // answer.
            let _ = std::fs::create_dir_all(ECN_EVIDENCE_DIR);
            let _ = std::fs::write(path, chrono_secs().to_string());
        }
    }
}

/// Read this port's remembered evidence, if it is still within its TTL.
pub fn ecn_evidence_remembered(path: &std::path::Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let Ok(written) = text.trim().parse::<u64>() else {
        return false;
    };
    chrono_secs().saturating_sub(written) < ECN_EVIDENCE_TTL_SECS
}

/// What the socket counted while a test ran.
#[derive(Debug, Default)]
pub struct Counters {
    /// Datagrams received from any peer.
    pub datagrams_in: AtomicU64,
    /// Datagrams the black hole swallowed.
    pub dropped_oversize: AtomicU64,
    /// Datagrams whose ECT marking was rewritten to CE.
    pub marked_ce: AtomicU64,
    /// Datagrams held back and released after a later one, for
    /// `q-packet-reordering`.
    ///
    /// Counted because the verdict has to know whether anything was actually
    /// delivered out of order: a connection that carried on proves nothing if
    /// its datagrams all arrived in the order they were sent.
    pub reordered: AtomicU64,
    /// Datagrams copied out of the second socket for `q-connection-migration`.
    ///
    /// The verdict needs to know whether the client was ever actually shown an
    /// unannounced server address: if the copy never went out, a connection that
    /// carried on proves nothing.
    pub shadowed: AtomicU64,
    /// Copies that could not be sent at all, which is our failure and not the
    /// client's. Separated because for a year the two were the same zero.
    pub shadow_failed: AtomicU64,
    /// Client datagrams that reached us carrying ECT(0) or ECT(1).
    pub ect_in: AtomicU64,
    /// Whether any peer on this port has ever echoed ECN counts back, and
    /// where that is remembered between restarts.
    ///
    /// Per-port and sticky on purpose, and deliberately not the bug this suite
    /// has closed three times: what it records is a property of the *path*,
    /// not a per-connection fact read from shared state. A client that then
    /// reports nothing is choosing not to, which §13.4.1 permits.
    pub ecn_evidence: Arc<EcnEvidence>,
    /// Client datagrams that carried a QUIC Initial packet.
    ///
    /// The evidence for `t-hybrid-large-hello`. An ML-KEM-768 key share is 1,216
    /// bytes, which takes a ClientHello past the 1,200-byte minimum RFC 9000
    /// §14.1 sets for an Initial datagram, so the first flight has to be split
    /// across more than one of them. Counting them is the only way to know the
    /// client was actually put in that situation: if its ClientHello fit in one
    /// packet after all, the connection completing proves nothing about how it
    /// handles one that does not, and the test must say so rather than take
    /// credit for it.
    pub initials_in: AtomicU64,
    /// Datagrams the loss impairment dropped.
    ///
    /// Kept apart from `dropped_oversize` because the two answer different
    /// questions: one is a size threshold the client can dodge by sending less,
    /// the other is unconditional. A single counter would make
    /// `q-loss-recovery` unable to say whether anything was actually lost, and a
    /// resilience test that cannot tell has no verdict to give.
    pub dropped_loss: AtomicU64,
    /// Datagrams carrying at least one 0-RTT packet.
    ///
    /// Read from the wire rather than from the TLS stack, because a rejected
    /// 0-RTT attempt leaves no trace in the connection: the packets cannot be
    /// decrypted with the keys the handshake settles on, so they are discarded
    /// before anything above the transport sees them. Without this there is no
    /// way to tell a client whose early data was refused from one that never
    /// tried, and scoring the second as though it were the first would pass
    /// every client that has no session ticket.
    pub zero_rtt_in: AtomicU64,
    /// Version Negotiation packets this endpoint sent.
    ///
    /// Counted because it is the missing half of the 0-RTT verdict. A client
    /// that GREASEs its QUIC version -- quiche puts 0xbabababa in a
    /// speculative first flight -- is answered with Version Negotiation, as
    /// RFC 8999 §6 requires, and then starts again on v1. Measured on the
    /// wire, quiche coalesces its early data into that GREASE flight and does
    /// not re-offer it on the retry, so not one 0-RTT packet reaches us.
    ///
    /// Without this counter the suite reported that as "the client sent no
    /// early data", which is true of the wire and quite wrong about the
    /// client: it tried, and its own version probe cost it the attempt.
    pub version_negotiations_out: AtomicU64,
    /// The address the most recent datagram came from.
    ///
    /// `q-version-negotiation` is judged from the socket alone — no connection
    /// is ever established there, so there is no peer address anywhere else to
    /// read. Without it that test's verdict has no session to be filed under and
    /// never reaches the client that earned it.
    pub last_peer: parking_lot::Mutex<Option<SocketAddr>>,
    /// The same counts, split by peer. See [`PeerCounters`].
    ///
    /// Entries carry their last touch rather than their first, and are dropped
    /// only once untouched for [`PEER_MEMORY`]. Every datagram to or from a
    /// peer touches its entry, so a connection that is still being measured
    /// cannot be evicted — which matters more here than for the impairment
    /// clock next door. Losing a clock entry restarts a timing window and is
    /// mildly wrong; losing a counter entry restarts a delta at zero and a
    /// verdict reads a partial count as a whole one.
    peers: DashMap<SocketAddr, (Arc<PeerCounters>, Instant)>,
}

impl Counters {
    pub fn datagrams_in(&self) -> u64 {
        self.datagrams_in.load(Ordering::Relaxed)
    }

    pub fn initials_in(&self) -> u64 {
        self.initials_in.load(Ordering::Relaxed)
    }

    pub fn dropped_oversize(&self) -> u64 {
        self.dropped_oversize.load(Ordering::Relaxed)
    }

    pub fn dropped_loss(&self) -> u64 {
        self.dropped_loss.load(Ordering::Relaxed)
    }

    pub fn shadowed(&self) -> u64 {
        self.shadowed.load(Ordering::Relaxed)
    }

    pub fn shadow_failed(&self) -> u64 {
        self.shadow_failed.load(Ordering::Relaxed)
    }

    /// Whether this port has ever been shown that the path carries ECT.
    pub fn path_carries_ect(&self) -> bool {
        self.ecn_evidence.proven()
    }

    /// Record that a peer echoed ECN counts, which proves the path.
    pub fn note_ecn_echoed(&self) {
        self.ecn_evidence.note();
    }

    pub fn reordered(&self) -> u64 {
        self.reordered.load(Ordering::Relaxed)
    }

    pub fn marked_ce(&self) -> u64 {
        self.marked_ce.load(Ordering::Relaxed)
    }

    pub fn zero_rtt_in(&self) -> u64 {
        self.zero_rtt_in.load(Ordering::Relaxed)
    }

    pub fn version_negotiations_out(&self) -> u64 {
        self.version_negotiations_out.load(Ordering::Relaxed)
    }

    pub fn last_peer(&self) -> Option<SocketAddr> {
        *self.last_peer.lock()
    }

    /// This peer's counters, creating the entry if it is new.
    ///
    /// Touches the entry, which is what keeps a live connection from being
    /// evicted: every datagram either way comes through here.
    pub fn peer(&self, addr: SocketAddr) -> Arc<PeerCounters> {
        let now = Instant::now();
        if self.peers.len() >= MAX_TRACKED_PEERS {
            self.prune(now);
        }
        let mut entry = self
            .peers
            .entry(addr)
            .or_insert_with(|| (Arc::new(PeerCounters::default()), now));
        entry.1 = now;
        Arc::clone(&entry.0)
    }

    /// Drop what can be dropped, oldest first, protecting anything live.
    ///
    /// Age alone is not enough. Retaining only entries younger than
    /// [`PEER_MEMORY`] frees nothing when every entry is younger than that,
    /// which is exactly the case under a burst — a scan opening a thousand
    /// source ports inside a minute leaves the map unbounded, and a
    /// constructed test caught it doing precisely that at 2,049 entries.
    ///
    /// So age first, then oldest-first down to the bound, and never an entry
    /// touched within [`ACTIVE_GRACE`]. Every datagram to or from a peer
    /// touches its entry and these tests settle in seconds, so a connection
    /// still being measured is inside that grace by construction. Losing its
    /// entry would restart a delta at zero and let a verdict read a partial
    /// count as a whole one, which is the one outcome worth growing the map
    /// to avoid: if the bound cannot be met without evicting live peers, it
    /// is not met, and the log says so.
    fn prune(&self, now: Instant) {
        self.peers
            .retain(|_, (_, touched)| now.duration_since(*touched) < PEER_MEMORY);
        if self.peers.len() < MAX_TRACKED_PEERS {
            return;
        }
        // Past the ceiling, age stops protecting anything. Below it, an
        // active peer is untouchable.
        let over_ceiling = self.peers.len() >= HARD_PEER_CEILING;
        let mut ages: Vec<(SocketAddr, Instant)> = self
            .peers
            .iter()
            .map(|e| (*e.key(), e.value().1))
            .filter(|(_, t)| over_ceiling || now.duration_since(*t) >= ACTIVE_GRACE)
            .collect();
        ages.sort_by_key(|(_, t)| *t);
        let excess = self.peers.len().saturating_sub(MAX_TRACKED_PEERS / 2);
        for (addr, _) in ages.into_iter().take(excess) {
            self.peers.remove(&addr);
        }
        if over_ceiling {
            warn!(
                "conformance: {} peers on one port inside a minute — evicting active \
                 entries to stay bounded, so a verdict in flight may be short its counts",
                self.peers.len()
            );
        }
    }

    /// A verdict's view of one connection: this peer's counts, from where they
    /// stood when the connection began.
    ///
    /// The baseline is not redundant with the per-peer split. Two connections
    /// sharing an address is unusual for this runner — each client is a fresh
    /// process with a fresh ephemeral port — but the suite is public, and a CI
    /// harness behind NAT or a client binding a fixed source port would do it.
    /// With the baseline, overlap degrades to a bounded stale count; without
    /// it, it is cross-client contamination, which is the bug this split
    /// exists to remove.
    pub fn view_for(&self, addr: SocketAddr) -> PeerView {
        let peer = self.peer(addr);
        // First connection on this entry: the entry is this connection's, so
        // its counts start at zero and nothing that arrived before `run_one`
        // is lost. A later one baselines, which bounds what a reused address
        // can inherit.
        let first = !peer.viewed.swap(true, std::sync::atomic::Ordering::Relaxed);
        PeerView::new(peer, first, Arc::clone(&self.ecn_evidence))
    }
}

/// One connection's counts, and the only counter type a verdict can reach.
///
/// The handle this replaces subtracted a baseline from a number the whole
/// port was writing to — correct arithmetic over shared state. This reads a
/// number only one peer writes to, and subtracts a baseline as well. The
/// difference that matters is not the arithmetic: it is that there is no way
/// from here to the port aggregate, so a verdict cannot read another
/// connection's traffic even by mistake.
///
/// `watch_version_negotiation` still takes `&Counters`, and that is the one
/// legitimate exception: no connection is ever established on that port —
/// the stack answers the Initial and discards it without surfacing an
/// `Incoming` — so there is no per-connection state for it to read.
pub struct PeerView {
    counters: Arc<PeerCounters>,
    zero_rtt_in: u64,
    version_negotiations_out: u64,
    initials_in: u64,
    marked_ce: u64,
    dropped_loss: u64,
    dropped_oversize: u64,
    reordered: u64,
    shadowed: u64,
    shadow_failed: u64,
    ect_in: u64,
    datagrams_in: u64,
    /// The port's path evidence, shared rather than snapshotted: it is a fact
    /// about the path and stays true once shown.
    path_ect: Arc<EcnEvidence>,
}

impl PeerView {
    fn new(counters: Arc<PeerCounters>, from_zero: bool, path_ect: Arc<EcnEvidence>) -> Self {
        if from_zero {
            return Self {
                zero_rtt_in: 0,
                version_negotiations_out: 0,
                initials_in: 0,
                marked_ce: 0,
                dropped_loss: 0,
                dropped_oversize: 0,
                reordered: 0,
                shadowed: 0,
                shadow_failed: 0,
                ect_in: 0,
                datagrams_in: 0,
                path_ect,
                counters,
            };
        }
        Self {
            zero_rtt_in: counters.zero_rtt_in.load(Ordering::Relaxed),
            version_negotiations_out: counters.version_negotiations_out.load(Ordering::Relaxed),
            initials_in: counters.initials_in.load(Ordering::Relaxed),
            marked_ce: counters.marked_ce.load(Ordering::Relaxed),
            dropped_loss: counters.dropped_loss.load(Ordering::Relaxed),
            dropped_oversize: counters.dropped_oversize.load(Ordering::Relaxed),
            reordered: counters.reordered.load(Ordering::Relaxed),
            shadowed: counters.shadowed.load(Ordering::Relaxed),
            shadow_failed: counters.shadow_failed.load(Ordering::Relaxed),
            ect_in: counters.ect_in.load(Ordering::Relaxed),
            datagrams_in: counters.datagrams_in.load(Ordering::Relaxed),
            path_ect,
            counters,
        }
    }
}

macro_rules! peer_delta {
    ($($name:ident),+ $(,)?) => {
        impl PeerView {
            $(
                /// How far this peer's counter moved during this connection.
                pub fn $name(&self) -> u64 {
                    self.counters.$name.load(Ordering::Relaxed).saturating_sub(self.$name)
                }
            )+
        }
    };
}

impl PeerView {
    /// Whether this port has ever been shown that the path carries ECT.
    pub fn path_carries_ect(&self) -> bool {
        self.path_ect.proven()
    }

    /// Record that this peer echoed ECN counts, which proves the path for
    /// every peer after it.
    pub fn note_ecn_echoed(&self) {
        self.path_ect.note();
    }
}

peer_delta!(
    zero_rtt_in,
    version_negotiations_out,
    initials_in,
    marked_ce,
    dropped_loss,
    dropped_oversize,
    reordered,
    shadowed,
    shadow_failed,
    ect_in,
    datagrams_in,
);

/// How long a peer's traffic flows cleanly before the black hole opens under it.
///
/// The delay is measured **per peer**, from that peer's first datagram — not
/// from when the socket was bound. The socket is bound once at start-up and then
/// serves every client for the lifetime of the process, so a delay measured from
/// binding has always long since elapsed by the time anyone connects, and every
/// connection meets the hole from its very first packet.
///
/// That distinction decides whether the test works at all. A path impaired from
/// packet one is not a black hole, it is a small path: MTU discovery simply
/// searches under the limit, settles just below it, and the connection runs
/// perfectly on a smaller MTU with nothing lost and nothing to detect.
struct PeerClock {
    first_seen: DashMap<SocketAddr, Instant>,
    delay: Duration,
}

impl std::fmt::Debug for PeerClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerClock")
            .field("peers", &self.first_seen.len())
            .field("delay", &self.delay)
            .finish()
    }
}

/// Peers tracked before stale entries are cleared. A conformance port sees one
/// client at a time; this is headroom, not a working set.
const MAX_TRACKED_PEERS: usize = 1024;

/// How recently a peer must have been seen to count as still being measured.
///
/// Longer than any test takes to settle and longer than the liveness window,
/// so an entry inside this is one a verdict may still be reading. Nothing in
/// it is ever evicted.
const ACTIVE_GRACE: Duration = Duration::from_secs(60);

/// The point at which bounded memory beats a precise verdict.
///
/// Below this, a peer touched inside [`ACTIVE_GRACE`] is never evicted, so a
/// connection being measured cannot lose its count. That protection has no
/// bound of its own: under a scan opening thousands of source ports a second,
/// every entry is recent and nothing is evictable. A constructed test found
/// the map at 2,049 entries and climbing.
///
/// So there is a ceiling, and past it the oldest go regardless. A port that
/// has seen four thousand peers inside a minute is being scanned, not
/// measured, and the verdict that might be spoiled belongs to a connection
/// competing with a flood. Losing it is the better failure.
const HARD_PEER_CEILING: usize = MAX_TRACKED_PEERS * 4;

/// How long a peer is remembered. Comfortably longer than the 30-second idle
/// timeout these connections run with, so no live peer is ever forgotten and
/// silently handed a fresh clean window.
const PEER_MEMORY: Duration = Duration::from_mins(5);

impl PeerClock {
    fn new(delay: Duration) -> Self {
        Self {
            first_seen: DashMap::new(),
            delay,
        }
    }

    /// Record a peer's first datagram. Later datagrams do not move the clock.
    fn note(&self, peer: SocketAddr, now: Instant) {
        if self.first_seen.contains_key(&peer) {
            return;
        }
        if self.first_seen.len() >= MAX_TRACKED_PEERS {
            self.first_seen
                .retain(|_, seen| now.duration_since(*seen) < PEER_MEMORY);
        }
        self.first_seen.insert(peer, now);
    }

    /// Whether the hole has opened for this peer.
    ///
    /// A peer that has never been heard from is unimpaired: nothing has been
    /// carried for it yet, so there is nothing for a black hole to take away.
    fn is_open(&self, peer: SocketAddr, now: Instant) -> bool {
        self.first_seen
            .get(&peer)
            .is_some_and(|seen| now.duration_since(*seen) >= self.delay)
    }
}

/// What the path does to a peer's datagrams.
///
/// Grouped rather than passed as loose arguments because the two impairments
/// share a clock and are easy to transpose at a call site: a socket built with
/// the black hole's threshold in the loss field would drop 1300 datagrams in
/// every 1300 and look, from the far end, like a dead port.
#[derive(Debug, Clone, Copy, Default)]
pub struct Impairments {
    /// Datagrams larger than this vanish. `None` carries every size.
    pub blackhole_above: Option<usize>,
    /// One datagram in every `n` vanishes, whatever its size. `None` loses
    /// nothing.
    pub loss_one_in: Option<u64>,
    /// How long each peer's traffic flows cleanly before either impairment
    /// begins. `None` impairs from the first datagram.
    pub opens_after: Option<Duration>,
    /// Rewrite one ECT marking in every `n` to CE, as a congested router would.
    ///
    /// Only an already-ECT-marked datagram is touched. A router does not invent
    /// ECN capability on a packet that never claimed it, and neither does this:
    /// marking CE on an unmarked datagram would be a path doing something no
    /// path does, and the client would be right to ignore it.
    pub mark_ce_one_in: Option<u64>,
    /// Hold one datagram in every `n` and release it after the next, so it
    /// arrives out of order.
    ///
    /// Nothing is lost: every byte is delivered, some of it late. That is the
    /// distinction from the loss impairment, and it is the point — reassembly
    /// and retransmission are different requirements, and a client can satisfy
    /// one without the other.
    pub reorder_one_in: Option<u64>,
    /// Copy this many datagrams out of a *second* socket, so they reach the
    /// client from a server address it never sent to.
    ///
    /// A server cannot migrate a connection — only a client can move, and only
    /// to a preferred address the server advertised (RFC 9000 §9.6). So packets
    /// from an unannounced address are something a client is expected to
    /// discard, and this is the only way to put one in front of it: the datagram
    /// has to leave from a different port, which means a different socket.
    pub shadow_datagrams: Option<u64>,
}

/// A socket that silently discards datagrams larger than `blackhole_above`.
///
/// Reported to the caller as sent. That is the point: a real black hole gives
/// the sender no signal at all, and a socket error would tell the QUIC stack
/// something a black hole never would, turning a path-discovery test into an
/// error-handling one.
#[derive(Debug)]
pub struct ImpairedSocket {
    inner: Box<dyn AsyncUdpSocket>,
    blackhole_above: Option<usize>,
    /// When the black hole opens, per peer. `None` opens it immediately.
    ///
    /// A path that was never able to carry large datagrams is not a black hole
    /// — it is just a small path, and losing PLPMTUD probes to it is discovery
    /// working exactly as designed. quinn counts those separately and, quite
    /// rightly, does not call them a black hole.
    ///
    /// A real black hole is a path that *worked* at some size and then stopped.
    /// So the impairment stays shut while the connection raises its MTU, and
    /// only then begins swallowing — which is the condition the detector is
    /// actually looking for.
    clock: Option<Arc<PeerClock>>,
    /// One datagram in every `n` is dropped once the clock has opened.
    ///
    /// Deterministic rather than random: a resilience test whose severity
    /// changes run to run cannot be told apart from a client that is
    /// intermittently broken, and the first thing anyone does with a surprising
    /// verdict is run it again.
    loss_one_in: Option<u64>,
    /// A second socket, and how many datagrams to duplicate out of it.
    shadow: Option<Arc<ShadowSocket>>,
    /// Rewrite one ECT marking in every `n` to CE.
    mark_ce_one_in: Option<u64>,
    /// Datagrams offered while CE marking is open.
    ce_seen: Arc<AtomicU64>,
    /// Hold one datagram in every `n` and send it after the following one.
    reorder_one_in: Option<u64>,
    /// The datagram currently being held back, if any.
    ///
    /// Shared across senders so a held datagram is released by whichever sender
    /// carries the next one, rather than stranded in the one that took it.
    reorder_held: Arc<parking_lot::Mutex<Option<(Vec<u8>, SocketAddr)>>>,
    /// Datagrams offered while reordering is open.
    reorder_seen: Arc<AtomicU64>,
    /// Datagrams offered to the sender since the loss impairment opened.
    ///
    /// Shared with every sender this socket hands out, so the cadence is a
    /// property of the path rather than of whichever sender happened to carry a
    /// packet.
    sent_while_lossy: Arc<AtomicU64>,
    counters: Arc<Counters>,
}

impl ImpairedSocket {
    /// Wrap `inner`. A default [`Impairments`] passes everything through.
    ///
    /// `opens_after` delays both impairments for each peer separately, measured
    /// from that peer's first datagram: path-MTU discovery needs time to settle
    /// on a size larger than the threshold before anything starts vanishing, and
    /// the loss impairment needs the handshake to finish before it begins, or it
    /// would be testing handshake recovery instead of stream reassembly.
    pub fn new(
        inner: Box<dyn AsyncUdpSocket>,
        impairments: Impairments,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            inner,
            blackhole_above: impairments.blackhole_above,
            clock: impairments.opens_after.map(|d| Arc::new(PeerClock::new(d))),
            loss_one_in: impairments.loss_one_in,
            shadow: impairments
                .shadow_datagrams
                .and_then(|budget| ShadowSocket::bind(budget).map(Arc::new)),
            mark_ce_one_in: impairments.mark_ce_one_in,
            ce_seen: Arc::new(AtomicU64::new(0)),
            reorder_one_in: impairments.reorder_one_in,
            reorder_held: Arc::new(parking_lot::Mutex::new(None)),
            reorder_seen: Arc::new(AtomicU64::new(0)),
            sent_while_lossy: Arc::new(AtomicU64::new(0)),
            counters,
        }
    }

    /// The threshold in force for `peer`, or `None` while it is still shut.
    fn limit_for(&self, peer: SocketAddr, now: Instant) -> Option<usize> {
        let limit = self.blackhole_above?;
        match &self.clock {
            Some(clock) if !clock.is_open(peer, now) => None,
            _ => Some(limit),
        }
    }
}

impl AsyncUdpSocket for ImpairedSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(ImpairedSender {
            inner: self.inner.create_sender(),
            blackhole_above: self.blackhole_above,
            clock: self.clock.clone(),
            loss_one_in: self.loss_one_in,
            shadow: self.shadow.clone(),
            mark_ce_one_in: self.mark_ce_one_in,
            ce_seen: self.ce_seen.clone(),
            reorder_one_in: self.reorder_one_in,
            reorder_held: self.reorder_held.clone(),
            reorder_seen: self.reorder_seen.clone(),
            sent_while_lossy: self.sent_while_lossy.clone(),
            counters: self.counters.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let ready = self.inner.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(n)) = ready {
            // Counted even when the datagram never becomes a connection, which
            // is the whole evidence base for the version-negotiation test.
            self.counters
                .datagrams_in
                .fetch_add(n as u64, Ordering::Relaxed);
            // Per datagram rather than per batch: a `recvmmsg` batch can carry
            // datagrams from more than one peer, and crediting the whole batch
            // to the first sender would reintroduce exactly the cross-client
            // contamination this split removes.
            for m in meta.iter().take(n) {
                let peer = self.counters.peer(m.addr);
                peer.datagrams_in.fetch_add(1, Ordering::Relaxed);
                // Whether the client marks its own packets, and whether those
                // marks survive the path to us.
                //
                // This is what separates "the network stripped the codepoint"
                // from "this client does not report ECN" when no counts come
                // back. Both directions cross the same path, so a client whose
                // own datagrams arrive carrying ECT has shown that the path
                // preserves the field and that its stack can set it -- and its
                // silence about ours is then a property of the client, not an
                // unknown. Without this the two were indistinguishable and
                // seven clients were recorded as an inconclusive run.
                if matches!(m.ecn, Some(EcnCodepoint::Ect0 | EcnCodepoint::Ect1)) {
                    self.counters.ect_in.fetch_add(1, Ordering::Relaxed);
                    peer.ect_in.fetch_add(1, Ordering::Relaxed);
                }
            }

            if let Some(m) = meta.first().filter(|_| n > 0) {
                *self.counters.last_peer.lock() = Some(m.addr);
            }

            // Early data, counted on the way in.
            //
            // Checked here rather than after decryption because a refused 0-RTT
            // packet is never decrypted at all — it is discarded with the keys
            // that would have read it, leaving nothing above the transport to
            // observe. On the wire it is plainly labelled.
            for (buf, m) in bufs.iter().zip(meta.iter()).take(n) {
                if let Some(dgram) = buf.get(..m.len) {
                    // Both totals move together: the port aggregate for the
                    // one reader that has no connection to speak of, and this
                    // peer's own for every verdict.
                    let peer = self.counters.peer(m.addr);
                    if carries_zero_rtt(dgram) {
                        self.counters.zero_rtt_in.fetch_add(1, Ordering::Relaxed);
                        peer.zero_rtt_in.fetch_add(1, Ordering::Relaxed);
                    }
                    if carries_initial(dgram) {
                        self.counters.initials_in.fetch_add(1, Ordering::Relaxed);
                        peer.initials_in.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            let now = Instant::now();
            if let Some(clock) = &self.clock {
                // Start each peer's clean window at its first datagram. This is
                // the only place a peer becomes known, so it has to happen
                // before any drop decision is taken for it — including a
                // decision taken on the sending half, which never sees an
                // inbound datagram and so can never start a clock of its own.
                //
                // This sits ahead of the black-hole guard below rather than
                // inside it. While the clock existed only for the black hole the
                // two were the same thing; a loss-impaired port has a clock and
                // no size threshold, and returning early would leave its peers
                // permanently unknown — `is_open` reports false for a peer it
                // has never heard of, so nothing would ever be dropped and the
                // test would pass every client without impairing anything.
                for m in meta.iter().take(n) {
                    clock.note(m.addr, now);
                }
            }

            if self.blackhole_above.is_none() {
                return ready;
            }

            // Swallow oversized datagrams on the way in as well.
            //
            // A black hole that only ate our own sending would test this
            // stack's path discovery, not the client's — the client would never
            // meet the limit at all. Dropping inbound is what puts the client
            // on an impaired path, which is what the test is about.
            let kept = compact_oversize(bufs, meta, n, |m| {
                self.limit_for(m.addr, now)
                    .is_none_or(|limit| m.len <= limit)
            });
            let dropped = n - kept;
            if dropped > 0 {
                self.counters
                    .dropped_oversize
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                // `compact_oversize` has already removed the dropped entries,
                // so the addresses are gone by here; the peer is the one this
                // socket is talking to.
                if let Some(m) = meta.first() {
                    self.counters
                        .peer(m.addr)
                        .dropped_oversize
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                }
                debug!("conformance: black hole swallowed {dropped} inbound datagram(s)");
            }
            if kept == 0 && n > 0 {
                // Every datagram in this batch vanished. Report "nothing
                // readable yet" rather than zero datagrams, which the stack
                // would read as a closed socket.
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            return Poll::Ready(Ok(kept));
        }
        ready
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Whether a datagram carries a 0-RTT packet.
///
/// QUIC coalesces packets into one datagram, so a client's early data usually
/// travels behind the Initial that starts the handshake — checking only the
/// first packet would miss almost every real attempt. This walks the chain.
///
/// Everything read here is unprotected. Header protection covers the four least
/// significant bits of a long header's first byte (RFC 9001 §5.4.2); the packet
/// type sits in bits 4 and 5, above the mask, and the version, connection IDs
/// and length are all in the clear. No keys are needed and none are used.
///
/// Conservative by construction: anything it cannot parse ends the walk, so the
/// answer is only ever "a 0-RTT packet was definitely here".
fn carries_zero_rtt(dgram: &[u8]) -> bool {
    walk_for_packet_type(dgram, 0x1).unwrap_or(false)
}

/// Whether this datagram carries a QUIC Initial packet.
///
/// Same walk as the 0-RTT check and for the same reason: the answer is only
/// ever "one was definitely here". A datagram this cannot parse is not counted,
/// which can undercount but cannot invent an Initial that was not sent — and an
/// undercount makes `t-hybrid-large-hello` report itself unexercised rather than
/// claim a client handled something it was never shown.
fn carries_initial(dgram: &[u8]) -> bool {
    walk_for_packet_type(dgram, 0x0).unwrap_or(false)
}

/// The walk itself. `None` means "could not parse any further", which the caller
/// reads as "not found" — the answer is only ever "a 0-RTT packet was definitely
/// here".
fn walk_for_packet_type(mut dgram: &[u8], wanted: u8) -> Option<bool> {
    /// QUIC v1. A different version is a different packet layout, and guessing
    /// at one is how a parser starts inventing results.
    const V1: u32 = 1;
    const INITIAL: u8 = 0x0;
    const RETRY: u8 = 0x3;

    loop {
        // A short-header packet is 1-RTT and runs to the end of the datagram, so
        // nothing can be coalesced behind it.
        let (&first, rest) = dgram.split_first()?;
        if first & 0x80 == 0 {
            return Some(false);
        }
        if rest.len() < 4 {
            return None;
        }
        let (version, rest) = rest.split_at(4);
        let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
        if version != V1 {
            // Version Negotiation (version 0) and anything newer than v1 use
            // layouts this does not know.
            return Some(false);
        }

        let packet_type = (first & 0x30) >> 4;
        if packet_type == wanted {
            return Some(true);
        }

        // Skip this packet to reach whatever is coalesced behind it.
        let rest = skip_cid(rest).and_then(skip_cid)?;
        if packet_type == RETRY {
            // A Retry carries no Length field and nothing may follow it.
            return Some(false);
        }
        let rest = if packet_type == INITIAL {
            // Token Length, then the token itself.
            let (token_len, n) = read_varint(rest)?;
            let rest = rest.get(n..)?;
            let token_len = usize::try_from(token_len).ok()?;
            rest.get(token_len..)?
        } else {
            rest
        };
        let (length, n) = read_varint(rest)?;
        let rest = rest.get(n..)?;
        let length = usize::try_from(length).ok()?;
        dgram = rest.get(length..)?;
    }
}

/// Skip a length-prefixed connection ID.
fn skip_cid(buf: &[u8]) -> Option<&[u8]> {
    let (&len, rest) = buf.split_first()?;
    rest.get(usize::from(len)..)
}

/// Remove datagrams `keep` rejects from a received batch, keeping the rest.
///
/// `poll_recv` fills `bufs` and `meta` in parallel and reports how many are
/// valid, so dropping one means moving the survivors down to close the gap —
/// leaving a hole would hand the stack a datagram it was told to ignore.
fn compact_oversize(
    bufs: &mut [io::IoSliceMut<'_>],
    meta: &mut [RecvMeta],
    received: usize,
    keep: impl Fn(&RecvMeta) -> bool,
) -> usize {
    let mut kept = 0usize;
    for i in 0..received {
        if keep(&meta[i]) {
            if kept != i {
                meta.swap(kept, i);
                bufs.swap(kept, i);
            }
            kept += 1;
        }
    }
    kept
}

/// A second socket on the same host, used only to reach a client from an address
/// it never sent to.
///
/// Deliberately tiny in effect: it copies a fixed number of datagrams the real
/// socket has already sent, then stops. The client should discard every one of
/// them, and if it does, nothing about the connection changes — which is exactly
/// the outcome that makes the test pass, and why the budget exists rather than
/// shadowing the whole conversation.
#[derive(Debug)]
struct ShadowSocket {
    /// One socket per address family, because a datagram cannot cross them.
    ///
    /// This bound a single socket on `::` and sent to whatever address the
    /// connection was using. Every client in the fleet connects over IPv4, so
    /// every copy failed with EAFNOSUPPORT -- and `send_to(..).is_err()`
    /// returned `false`, which is also what "budget exhausted" returns, so the
    /// failure was indistinguishable from the feature working. The test then
    /// reported that the client had never been shown a second address, which
    /// was true and entirely our doing: `q-connection-migration` was
    /// unexercisable for all twelve clients and said so as though it were
    /// their run.
    ///
    /// Two sockets rather than one dual-stack socket with v4-mapped addresses:
    /// `IPV6_V6ONLY` defaults to 0 here but is a system setting, and a test
    /// that silently stops working when a sysctl changes is how this happened.
    v4: Option<std::net::UdpSocket>,
    v6: Option<std::net::UdpSocket>,
    /// How many copies each peer is shown. Enforced per peer by the caller
    /// against `Counters`, never by a counter inside this struct.
    ///
    /// It was `sent: AtomicU64` here, one tally for the whole listener, which
    /// is bound once at start-up and serves every client for the life of the
    /// process. The first connection to arrive consumed the entire budget and
    /// every connection after it was shown nothing -- the same bug class as
    /// the per-port counters this suite already had to close once: shared
    /// mutable state whose scope does not match what it describes. It was
    /// invisible while the address-family fault meant no copy ever left the
    /// socket, and surfaced the moment that was fixed.
    budget: u64,
    /// Copies that could not be sent. Surfaced, never swallowed.
    failed: AtomicU64,
}

impl ShadowSocket {
    /// Bind an ephemeral port per family. `None` only if neither can be bound,
    /// which leaves the test reporting that nothing was exercised rather than
    /// failing a client for our own missing socket.
    fn bind(budget: u64) -> Option<Self> {
        fn ephemeral(addr: std::net::IpAddr) -> Option<std::net::UdpSocket> {
            let socket = std::net::UdpSocket::bind((addr, 0)).ok()?;
            // Never block the sending path: a datagram that cannot go out
            // immediately is simply not shadowed.
            socket.set_nonblocking(true).ok()?;
            Some(socket)
        }
        let v4 = ephemeral(std::net::Ipv4Addr::UNSPECIFIED.into());
        let v6 = ephemeral(std::net::Ipv6Addr::UNSPECIFIED.into());
        if v4.is_none() && v6.is_none() {
            return None;
        }
        Some(Self {
            v4,
            v6,
            budget,
            failed: AtomicU64::new(0),
        })
    }

    /// Copy `datagram` to `peer` from the socket of `peer`'s family.
    ///
    /// The budget is the caller's to enforce, per peer. See `budget`.
    fn shadow(&self, datagram: &[u8], peer: SocketAddr) -> bool {
        let socket = match peer {
            SocketAddr::V4(_) => self.v4.as_ref(),
            SocketAddr::V6(_) => self.v6.as_ref(),
        };
        let Some(socket) = socket else {
            self.failed.fetch_add(1, Ordering::Relaxed);
            return false;
        };
        if let Err(e) = socket.send_to(datagram, peer) {
            // Counted and named. The version that swallowed this made the
            // test report a client behaviour it had never had the chance to
            // exhibit.
            self.failed.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "conformance: could not copy a datagram from the shadow address to {}: {}",
                peer,
                e
            );
            return false;
        }
        true
    }

    fn failures(&self) -> u64 {
        self.failed.load(Ordering::Relaxed)
    }
}

/// Whether the `nth` datagram since the impairment opened is the one to lose.
///
/// Counting from one, so the first datagram after the clean window is never the
/// casualty: the response headers usually ride in it, and losing those on some
/// runs and not others would make the same client pass and fail by turns.
fn is_lost(nth: u64, one_in: u64) -> bool {
    is_multiple_of(nth, one_in)
}

/// Whether the `nth` datagram falls on a cadence of one in `one_in`.
///
/// Zero means no impairment rather than "every datagram": a cadence of zero can
/// only come from a miswritten configuration, and `%` by zero would panic.
fn is_multiple_of(nth: u64, one_in: u64) -> bool {
    one_in > 0 && nth.is_multiple_of(one_in)
}

/// The sending half. Everything not dropped is passed straight through.
#[derive(Debug)]
struct ImpairedSender {
    inner: Pin<Box<dyn UdpSender>>,
    blackhole_above: Option<usize>,
    clock: Option<Arc<PeerClock>>,
    loss_one_in: Option<u64>,
    shadow: Option<Arc<ShadowSocket>>,
    mark_ce_one_in: Option<u64>,
    ce_seen: Arc<AtomicU64>,
    reorder_one_in: Option<u64>,
    reorder_held: Arc<parking_lot::Mutex<Option<(Vec<u8>, SocketAddr)>>>,
    reorder_seen: Arc<AtomicU64>,
    sent_while_lossy: Arc<AtomicU64>,
    counters: Arc<Counters>,
}

impl ImpairedSender {
    fn limit_for(&self, peer: SocketAddr, now: Instant) -> Option<usize> {
        let limit = self.blackhole_above?;
        match &self.clock {
            Some(clock) if !clock.is_open(peer, now) => None,
            _ => Some(limit),
        }
    }

    /// The loss cadence in force for `peer`, or `None` while it is still shut.
    ///
    /// A cadence of zero is treated as no impairment rather than as "drop
    /// everything": it can only arrive from a miswritten configuration, and a
    /// port that silently swallows every datagram is indistinguishable from one
    /// that is not running.
    fn loss_cadence(&self, peer: SocketAddr, now: Instant) -> Option<u64> {
        let one_in = self.loss_one_in.filter(|n| *n > 0)?;
        match &self.clock {
            Some(clock) if !clock.is_open(peer, now) => None,
            _ => Some(one_in),
        }
    }

    /// The CE-marking cadence in force for `peer`, or `None` while it is shut.
    fn ce_cadence(&self, peer: SocketAddr, now: Instant) -> Option<u64> {
        let one_in = self.mark_ce_one_in.filter(|n| *n > 0)?;
        match &self.clock {
            Some(clock) if !clock.is_open(peer, now) => None,
            _ => Some(one_in),
        }
    }

    /// The reordering cadence in force for `peer`, or `None` while it is shut.
    fn reorder_cadence(&self, peer: SocketAddr, now: Instant) -> Option<u64> {
        let one_in = self.reorder_one_in.filter(|n| *n > 0)?;
        match &self.clock {
            Some(clock) if !clock.is_open(peer, now) => None,
            _ => Some(one_in),
        }
    }
}

impl UdpSender for ImpairedSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let now = Instant::now();

        // A Version Negotiation packet carries version 0 (RFC 8999 §6), and it
        // is the one long-header packet whose type bits mean nothing. Counting
        // it here rather than inferring it later, because by the time a
        // verdict is being written the packet is long gone.
        if let Some(contents) = transmit.contents.get(..5) {
            if contents[0] & 0x80 != 0
                && u32::from_be_bytes([contents[1], contents[2], contents[3], contents[4]]) == 0
            {
                self.counters
                    .version_negotiations_out
                    .fetch_add(1, Ordering::Relaxed);
                self.counters
                    .peer(transmit.destination)
                    .version_negotiations_out
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        // Loss first, and counted only while the impairment is open.
        //
        // Advancing the counter during the clean window would spend the cadence
        // on handshake packets, so the first datagram after the window opened
        // could be the twelfth and vanish immediately — losing the response
        // headers on some runs and not others, which is the kind of flakiness a
        // resilience verdict must never rest on.
        if let Some(one_in) = self.loss_cadence(transmit.destination, now) {
            let nth = self.sent_while_lossy.fetch_add(1, Ordering::Relaxed) + 1;
            if is_lost(nth, one_in) {
                self.counters.dropped_loss.fetch_add(1, Ordering::Relaxed);
                self.counters
                    .peer(transmit.destination)
                    .dropped_loss
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    "conformance: dropped datagram {nth} of every {one_in} to the peer \
                     ({} bytes)",
                    transmit.contents.len()
                );
                // Reported as sent, like the black hole: a lost datagram gives
                // its sender no signal.
                return Poll::Ready(Ok(()));
            }
        }

        // Congestion marking: turn an ECT codepoint into CE.
        //
        // What a congested router does, and the only way to ask a client whether
        // it can see the signal at all. The datagram is otherwise untouched and
        // still goes out — this rewrites one header field, it does not drop or
        // delay anything — so it is decided first and the result carried into
        // whatever follows.
        let mut marked = None;
        if let Some(one_in) = self.ce_cadence(transmit.destination, now) {
            if matches!(transmit.ecn, Some(EcnCodepoint::Ect0 | EcnCodepoint::Ect1)) {
                let nth = self.ce_seen.fetch_add(1, Ordering::Relaxed) + 1;
                if is_multiple_of(nth, one_in) {
                    self.counters.marked_ce.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .peer(transmit.destination)
                        .marked_ce
                        .fetch_add(1, Ordering::Relaxed);
                    marked = Some(Transmit {
                        destination: transmit.destination,
                        ecn: Some(EcnCodepoint::Ce),
                        contents: transmit.contents,
                        segment_size: transmit.segment_size,
                        src_ip: transmit.src_ip,
                    });
                }
            }
        }
        let transmit = marked.as_ref().unwrap_or(transmit);

        // Reordering: hold one datagram back, then send it after the next.
        //
        // Nothing is dropped. The held datagram goes out immediately behind the
        // one that overtook it, so the peer receives every byte with exactly one
        // pair out of order — which is what a reassembly buffer is for, and what
        // a client that assumes arrival order is delivery order gets wrong.
        //
        // The release happens before this datagram is sent, in the opposite
        // order: current first, then the one being held.
        if let Some(one_in) = self.reorder_cadence(transmit.destination, now) {
            let held = self.reorder_held.lock().take();
            if let Some((bytes, dest)) = held {
                // Send the newer datagram first — that is the overtaking.
                match self.inner.as_mut().poll_send(transmit, cx) {
                    Poll::Ready(Ok(())) => {}
                    other => {
                        // Could not send; put the held one back so it is not
                        // lost, and let the caller retry.
                        *self.reorder_held.lock() = Some((bytes, dest));
                        return other;
                    }
                }
                let late = Transmit {
                    destination: dest,
                    ecn: None,
                    contents: &bytes,
                    segment_size: None,
                    src_ip: None,
                };
                if self.inner.as_mut().poll_send(&late, cx).is_ready() {
                    self.counters.reordered.fetch_add(1, Ordering::Relaxed);
                    self.counters
                        .peer(transmit.destination)
                        .reordered
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    // The socket is full. Keep it rather than drop it: this
                    // impairment reorders, it does not lose.
                    *self.reorder_held.lock() = Some((bytes, dest));
                }
                return Poll::Ready(Ok(()));
            }

            let nth = self.reorder_seen.fetch_add(1, Ordering::Relaxed) + 1;
            if is_multiple_of(nth, one_in) {
                // Reported as sent. It has not been lost — the next datagram
                // out will carry it along behind itself.
                *self.reorder_held.lock() =
                    Some((transmit.contents.to_vec(), transmit.destination));
                return Poll::Ready(Ok(()));
            }
        }

        // A copy from the second socket, once the connection is up.
        //
        // Sent alongside the real datagram rather than instead of it, so the
        // conversation is unaffected and the only new thing the client sees is
        // the same bytes arriving from an address it never wrote to. A client
        // that discards them — which §9.6 asks for — carries on exactly as it
        // would have.
        if let Some(shadow) = self.shadow.as_ref() {
            if self
                .clock
                .as_ref()
                .is_none_or(|clock| clock.is_open(transmit.destination, now))
            {
                let peer = self.counters.peer(transmit.destination);
                let shown = peer.shadowed.load(Ordering::Relaxed);
                let before = shadow.failures();
                if shown < shadow.budget && shadow.shadow(transmit.contents, transmit.destination) {
                    self.counters.shadowed.fetch_add(1, Ordering::Relaxed);
                    peer.shadowed.fetch_add(1, Ordering::Relaxed);
                } else if shadow.failures() > before {
                    self.counters.shadow_failed.fetch_add(1, Ordering::Relaxed);
                    peer.shadow_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        if let Some(limit) = self.limit_for(transmit.destination, now) {
            if transmit.contents.len() > limit {
                self.counters
                    .dropped_oversize
                    .fetch_add(1, Ordering::Relaxed);
                debug!(
                    "conformance: black hole swallowed a {}-byte datagram (limit {})",
                    transmit.contents.len(),
                    limit
                );
                // Reported as sent. A real black hole is indistinguishable from
                // success at the sender.
                return Poll::Ready(Ok(()));
            }
        }
        self.inner.as_mut().poll_send(transmit, cx)
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        // One datagram per transmit while impaired: GSO would batch several
        // into one syscall, and the batch's length is not the length of the
        // datagrams inside it, so a size threshold could not be applied
        // honestly — and a batch dropped for loss would take every datagram in
        // it, turning one loss in twelve into a burst of several.
        if self.blackhole_above.is_some() || self.loss_one_in.is_some() || self.shadow.is_some() {
            NonZeroUsize::MIN
        } else {
            self.inner.max_transmit_segments()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 7], port))
    }

    #[test]
    fn counters_start_at_zero_and_accumulate() {
        let c = Counters::default();
        assert_eq!(c.datagrams_in(), 0);
        assert_eq!(c.dropped_oversize(), 0);
        c.datagrams_in.fetch_add(3, Ordering::Relaxed);
        c.dropped_oversize.fetch_add(2, Ordering::Relaxed);
        assert_eq!(c.datagrams_in(), 3);
        assert_eq!(c.dropped_oversize(), 2);
    }

    #[test]
    fn the_black_hole_stays_shut_until_it_opens() {
        // The distinction the detector depends on: a path that never carried
        // large datagrams is a small path, not a black hole. Swallowing from
        // the first packet would only ever produce lost PLPMTUD probes, which
        // quinn counts separately and does not call a black hole.
        let clock = PeerClock::new(Duration::from_secs(4));
        let t0 = Instant::now();
        clock.note(peer(1), t0);

        assert!(!clock.is_open(peer(1), t0), "shut on the first datagram");
        assert!(
            !clock.is_open(peer(1), t0 + Duration::from_secs(3)),
            "still shut inside the clean window"
        );
        assert!(
            clock.is_open(peer(1), t0 + Duration::from_secs(5)),
            "open once the window has passed"
        );
    }

    #[test]
    fn one_datagram_in_every_n_is_lost_and_the_rest_are_not() {
        let one_in = 12;
        let lost: Vec<u64> = (1..=36).filter(|n| is_lost(*n, one_in)).collect();
        assert_eq!(lost, vec![12, 24, 36], "an even cadence, counted from one");
        assert!(!is_lost(1, one_in), "the first datagram must survive");
        assert_eq!(
            (1..=120).filter(|n| is_lost(*n, one_in)).count(),
            10,
            "1 in 12 over 120 datagrams"
        );
    }

    #[test]
    fn a_cadence_of_zero_loses_nothing() {
        // Only reachable from a miswritten configuration. Dropping everything
        // would leave a port that looks dead rather than impaired, and `%` by
        // zero would panic on the first datagram.
        for n in 1..=10 {
            assert!(!is_lost(n, 0));
        }
    }

    #[test]
    fn an_unimpaired_path_is_described_by_the_default() {
        let i = Impairments::default();
        assert!(i.blackhole_above.is_none());
        assert!(i.loss_one_in.is_none());
        assert!(i.opens_after.is_none(), "nothing to wait for");
    }

    #[test]
    fn the_clean_window_is_measured_per_peer() {
        // The socket is bound once and serves every client for the life of the
        // process. A window measured from binding has always elapsed by the time
        // anyone connects, so every connection would meet the hole from its
        // first packet and MTU discovery would simply settle underneath it.
        let clock = PeerClock::new(Duration::from_secs(4));
        let t0 = Instant::now();
        clock.note(peer(1), t0);

        let later = t0 + Duration::from_mins(10);
        assert!(
            clock.is_open(peer(1), later),
            "the first peer's window is up"
        );

        // A client arriving now gets its own clean window, not the leftovers of
        // one that opened ten minutes ago.
        clock.note(peer(2), later);
        assert!(!clock.is_open(peer(2), later));
        assert!(clock.is_open(peer(2), later + Duration::from_secs(5)));
    }

    #[test]
    fn a_peer_never_heard_from_is_unimpaired() {
        // Nothing has been carried for it, so there is nothing to take away.
        let clock = PeerClock::new(Duration::from_secs(4));
        assert!(!clock.is_open(peer(9), Instant::now()));
    }

    #[test]
    fn later_datagrams_do_not_restart_the_window() {
        // Otherwise a steady flow of traffic would hold the hole shut forever.
        let clock = PeerClock::new(Duration::from_secs(4));
        let t0 = Instant::now();
        clock.note(peer(1), t0);
        clock.note(peer(1), t0 + Duration::from_secs(3));
        assert!(clock.is_open(peer(1), t0 + Duration::from_secs(5)));
    }

    #[test]
    fn a_threshold_of_none_impairs_nothing() {
        // The same wrapper carries every conformance port, so the unimpaired
        // path has to be exactly transparent.
        let counters = Arc::new(Counters::default());
        let sender = ImpairedSenderShape {
            blackhole_above: None,
            clock: None,
            counters: counters.clone(),
        };
        assert!(!sender.would_drop(9000, peer(1)));
        assert_eq!(counters.dropped_oversize(), 0);
    }

    #[test]
    fn only_datagrams_over_the_threshold_are_swallowed() {
        let counters = Arc::new(Counters::default());
        let sender = ImpairedSenderShape {
            blackhole_above: Some(1300),
            clock: None,
            counters,
        };
        assert!(!sender.would_drop(1300, peer(1)), "at the limit passes");
        assert!(!sender.would_drop(1299, peer(1)));
        assert!(
            sender.would_drop(1301, peer(1)),
            "one byte over is swallowed"
        );
    }

    #[test]
    fn compaction_keeps_the_survivors_contiguous() {
        // A hole left behind would hand the stack a datagram it was told to
        // ignore, which is worse than not dropping at all.
        let mut storage: Vec<Vec<u8>> = vec![vec![0; 16]; 4];
        let mut bufs: Vec<io::IoSliceMut<'_>> = storage
            .iter_mut()
            .map(|b| io::IoSliceMut::new(b.as_mut_slice()))
            .collect();
        let mut meta = vec![RecvMeta::default(); 4];
        meta[0].len = 100; // keep
        meta[1].len = 5000; // drop
        meta[2].len = 200; // keep
        meta[3].len = 9000; // drop

        let kept = compact_oversize(&mut bufs, &mut meta, 4, |m| m.len <= 1200);
        assert_eq!(kept, 2);
        assert_eq!(meta[0].len, 100);
        assert_eq!(meta[1].len, 200, "the survivor moved down into the gap");
    }

    #[test]
    fn compaction_can_keep_nothing() {
        let mut storage: Vec<Vec<u8>> = vec![vec![0; 16]; 2];
        let mut bufs: Vec<io::IoSliceMut<'_>> = storage
            .iter_mut()
            .map(|b| io::IoSliceMut::new(b.as_mut_slice()))
            .collect();
        let mut meta = vec![RecvMeta::default(); 2];
        meta[0].len = 5000;
        meta[1].len = 5000;
        assert_eq!(
            compact_oversize(&mut bufs, &mut meta, 2, |m| m.len <= 1200),
            0
        );
    }

    #[test]
    fn tracking_is_bounded() {
        // A public port should not accumulate an entry per source address for
        // the lifetime of the process.
        let clock = PeerClock::new(Duration::from_secs(4));
        let t0 = Instant::now();
        for i in 0..MAX_TRACKED_PEERS {
            clock.note(
                peer(u16::try_from(i).expect("fewer peers than u16::MAX")),
                t0,
            );
        }
        assert_eq!(clock.first_seen.len(), MAX_TRACKED_PEERS);

        // Everything so far is stale by the time the next peer arrives, so the
        // sweep clears it rather than growing without bound.
        clock.note(peer(60000), t0 + PEER_MEMORY + Duration::from_secs(1));
        assert_eq!(clock.first_seen.len(), 1);
    }

    /// A QUIC v1 long header: first byte, version, empty DCID and SCID.
    fn long_header(packet_type: u8) -> Vec<u8> {
        let mut p = vec![0xc0 | (packet_type << 4)];
        p.extend_from_slice(&1u32.to_be_bytes()); // version 1
        p.push(0); // DCID length
        p.push(0); // SCID length
        p
    }

    /// An Initial with `payload_len` bytes of (opaque) payload behind it.
    fn initial(payload_len: usize) -> Vec<u8> {
        let mut p = long_header(0x0);
        p.push(0); // Token Length: 0
        p.push(u8::try_from(payload_len).expect("test payloads are small")); // Length varint
        p.extend(std::iter::repeat_n(0u8, payload_len));
        p
    }

    #[test]
    fn zero_rtt_is_found_behind_the_initial_it_is_coalesced_with() {
        // The case that matters. A client's early data rides in the same
        // datagram as the Initial that opens the handshake, so a check that
        // looked only at the first packet would miss nearly every real attempt
        // and report that no client ever tries 0-RTT.
        let mut dgram = initial(16);
        dgram.extend(long_header(0x1));
        assert!(carries_zero_rtt(&dgram));
    }

    #[test]
    fn a_plain_initial_is_not_zero_rtt() {
        assert!(!carries_zero_rtt(&initial(24)));
    }

    #[test]
    fn a_handshake_packet_is_not_zero_rtt() {
        let mut dgram = long_header(0x2);
        dgram.push(8); // Length
        dgram.extend(std::iter::repeat_n(0u8, 8));
        assert!(!carries_zero_rtt(&dgram));
    }

    #[test]
    fn a_short_header_ends_the_walk() {
        // 1-RTT runs to the end of the datagram; nothing is coalesced behind it,
        // and its bytes must never be read as another header.
        assert!(!carries_zero_rtt(&[0x40, 0x01, 0x02, 0x03, 0x04, 0x05]));
    }

    #[test]
    fn a_truncated_or_unknown_datagram_is_never_a_positive() {
        // The counter drives a verdict, so a parser that guesses is worse than
        // one that gives up.
        assert!(!carries_zero_rtt(&[]));
        assert!(!carries_zero_rtt(&[0xc0]));
        assert!(!carries_zero_rtt(&[0xc0, 0x00, 0x00, 0x00]));
        // A version this does not know: the layout behind it is not ours to
        // guess at.
        let mut other_version = vec![0xd0];
        other_version.extend_from_slice(&0x709a_50c4u32.to_be_bytes());
        assert!(!carries_zero_rtt(&other_version));
        // A length that runs past the end of the datagram.
        let mut overrun = long_header(0x2);
        overrun.push(60);
        overrun.extend(std::iter::repeat_n(0u8, 4));
        assert!(!carries_zero_rtt(&overrun));
    }

    #[test]
    fn a_retry_ends_the_walk() {
        // A Retry has no Length field, so its remaining bytes are the token —
        // reading them as a coalesced header would be a fabrication.
        let mut dgram = long_header(0x3);
        dgram.extend_from_slice(&[0x1; 32]);
        assert!(!carries_zero_rtt(&dgram));
    }

    /// The size decision, isolated from the socket so it can be tested without
    /// one. `poll_send` applies exactly this rule.
    struct ImpairedSenderShape {
        blackhole_above: Option<usize>,
        clock: Option<Arc<PeerClock>>,
        counters: Arc<Counters>,
    }

    impl ImpairedSenderShape {
        fn limit_for(&self, peer: SocketAddr, now: Instant) -> Option<usize> {
            let limit = self.blackhole_above?;
            match &self.clock {
                Some(clock) if !clock.is_open(peer, now) => None,
                _ => Some(limit),
            }
        }

        fn would_drop(&self, len: usize, peer: SocketAddr) -> bool {
            match self.limit_for(peer, Instant::now()) {
                Some(limit) if len > limit => {
                    self.counters
                        .dropped_oversize
                        .fetch_add(1, Ordering::Relaxed);
                    true
                }
                _ => false,
            }
        }
    }
}

#[cfg(test)]
mod peer_counter_tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// One client's traffic must not be visible to another's verdict.
    ///
    /// The regression is not hypothetical: it shipped seven times. Reading a
    /// cumulative per-port counter as though it described one connection made
    /// the first client to do something decide the verdict for every client
    /// after it, and the symptom was a run reporting that ten of twelve
    /// implementations lose their 0-RTT to a version GREASE when one does.
    #[test]
    fn a_peer_sees_only_its_own_traffic() {
        let counters = Counters::default();

        // Nine earlier clients, each on its own ephemeral port.
        for p in 40000..40009 {
            let peer = counters.peer(addr(p));
            peer.version_negotiations_out
                .fetch_add(1, Ordering::Relaxed);
            peer.zero_rtt_in.fetch_add(3, Ordering::Relaxed);
            peer.initials_in.fetch_add(2, Ordering::Relaxed);
            counters
                .version_negotiations_out
                .fetch_add(1, Ordering::Relaxed);
            counters.zero_rtt_in.fetch_add(3, Ordering::Relaxed);
            counters.initials_in.fetch_add(2, Ordering::Relaxed);
        }

        let ours = addr(50000);
        let view = counters.view_for(ours);
        assert_eq!(
            view.version_negotiations_out(),
            0,
            "nine earlier GREASEs are not ours"
        );
        assert_eq!(view.zero_rtt_in(), 0);
        assert_eq!(view.initials_in(), 0);

        counters
            .peer(ours)
            .initials_in
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(view.initials_in(), 1, "only this connection's Initials");
        assert_eq!(
            view.zero_rtt_in(),
            0,
            "it sent none, whatever the port total says"
        );
        assert_eq!(
            counters.initials_in(),
            18,
            "the port aggregate is still there for the one reader with no connection"
        );
    }

    /// `t-hybrid-large-hello` asks whether *this* ClientHello needed more than
    /// one Initial, and it feeds the post-quantum results. Two earlier clients
    /// on the port used to be enough to answer yes for everybody.
    #[test]
    fn a_split_client_hello_is_this_clients_or_nobodys() {
        let counters = Counters::default();
        counters
            .peer(addr(40001))
            .initials_in
            .fetch_add(2, Ordering::Relaxed);

        let ours = addr(50001);
        let view = counters.view_for(ours);
        counters
            .peer(ours)
            .initials_in
            .fetch_add(1, Ordering::Relaxed);
        assert!(
            view.initials_in() <= 1,
            "a client whose hello fits in one Initial must not inherit an earlier client's split"
        );
    }

    /// A connection keeps what arrived before `run_one` could baseline.
    ///
    /// The regression this guards is measured, not imagined: 0-RTT is
    /// coalesced behind the Initial that produces the `Incoming`, so the only
    /// early-data packet ngtcp2 sends is counted before there is a connection
    /// to attribute it to. Baselining at the current values discarded it, and
    /// the suite reported that a client which did offer early data did not.
    #[test]
    fn the_first_view_keeps_what_created_the_entry() {
        let counters = Counters::default();
        let peer = addr(50004);

        // The connection's first datagram: an Initial with 0-RTT coalesced
        // behind it, counted by the socket before `run_one` runs.
        counters
            .peer(peer)
            .initials_in
            .fetch_add(1, Ordering::Relaxed);
        counters
            .peer(peer)
            .zero_rtt_in
            .fetch_add(1, Ordering::Relaxed);

        let view = counters.view_for(peer);
        assert_eq!(
            view.zero_rtt_in(),
            1,
            "early data that arrived with the Initial belongs to this connection"
        );
        assert_eq!(view.initials_in(), 1);
    }

    /// Two connections from the same address do not share a count.
    ///
    /// Each client here is a fresh process with a fresh ephemeral port, so
    /// this should not arise — but the suite is public, and a CI harness
    /// behind NAT or a client binding a fixed source port would do it. The
    /// baseline inside the view is what makes that degrade to a bounded stale
    /// count rather than to the contamination the split exists to remove.
    #[test]
    fn a_reused_address_does_not_inherit_the_previous_connections_count() {
        let counters = Counters::default();
        let same = addr(50002);

        let first = counters.view_for(same);
        counters
            .peer(same)
            .zero_rtt_in
            .fetch_add(5, Ordering::Relaxed);
        assert_eq!(first.zero_rtt_in(), 5);

        // A second connection from the same address takes a fresh view.
        let second = counters.view_for(same);
        assert_eq!(
            second.zero_rtt_in(),
            0,
            "the previous connection's early data is not ours"
        );
        counters
            .peer(same)
            .zero_rtt_in
            .fetch_add(1, Ordering::Relaxed);
        assert_eq!(second.zero_rtt_in(), 1);
    }

    /// Eviction must not be able to drop a peer that is still being measured.
    ///
    /// Constructed rather than reasoned about, because "the map is big enough"
    /// is the assumption that bites when something opens a thousand
    /// connections. The impairment clock next door tolerates losing an entry —
    /// its timing window restarts, mildly wrong. Losing a *counter* entry
    /// restarts a delta at zero and a verdict reads a partial count as a whole
    /// one, which is a quiet wrong answer.
    ///
    /// Entries are keyed on last touch and every datagram touches, so a live
    /// peer is safe by construction. This drives the map well past its bound
    /// with a live peer in it and checks the count survives.
    #[test]
    fn eviction_cannot_drop_a_peer_still_being_measured() {
        let counters = Counters::default();
        let live = addr(50003);

        let view = counters.view_for(live);
        counters
            .peer(live)
            .datagrams_in
            .fetch_add(7, Ordering::Relaxed);

        // Far more peers than the bound, interleaved with traffic on the live
        // one exactly as a real connection would be.
        for p in 0..(MAX_TRACKED_PEERS as u32 * 2) {
            let port = 10000u32.wrapping_add(p) as u16;
            counters
                .peer(addr(port))
                .datagrams_in
                .fetch_add(1, Ordering::Relaxed);
            if p % 8 == 0 {
                counters
                    .peer(live)
                    .datagrams_in
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        assert!(
            view.datagrams_in() >= 7,
            "a peer touched throughout must keep its count across pruning, got {}",
            view.datagrams_in()
        );
        assert!(
            counters.peers.len() <= HARD_PEER_CEILING,
            "the map must stay bounded even when every entry is active, got {}",
            counters.peers.len()
        );
    }
}

#[cfg(test)]
mod shadow_socket_tests {
    use super::*;

    /// A copy must go out from a socket of the peer's own address family.
    ///
    /// This bound one socket on `::` and sent to whatever address the
    /// connection used. Every client in the fleet connects over IPv4, so every
    /// copy failed with EAFNOSUPPORT, and `send_to(..).is_err()` returned the
    /// same `false` as "nothing to do" -- so `q-connection-migration` reported
    /// that twelve clients had never been shown a second address, which was
    /// true and entirely ours. The failure counter exists so that can never
    /// again be silent, and this asserts the send itself.
    #[test]
    fn a_copy_reaches_a_peer_of_either_family() {
        let shadow = ShadowSocket::bind(6).expect("bind an ephemeral port");

        // Real receivers, so a send that the kernel refuses is a real failure
        // rather than an unroutable address being tolerated.
        let v4 = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(
            shadow.shadow(b"copy", v4.local_addr().unwrap()),
            "a v4 peer must be served from the v4 socket"
        );

        if let Ok(v6) = std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)) {
            assert!(
                shadow.shadow(b"copy", v6.local_addr().unwrap()),
                "a v6 peer must be served from the v6 socket"
            );
        }

        assert_eq!(shadow.failures(), 0, "no send should have failed");
    }

    /// A send that cannot go out is counted, not discarded.
    #[test]
    fn a_failed_copy_is_counted() {
        let shadow = ShadowSocket {
            v4: None,
            v6: None,
            budget: 6,
            failed: AtomicU64::new(0),
        };
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(!shadow.shadow(b"copy", dest));
        assert_eq!(
            shadow.failures(),
            1,
            "a copy with nowhere to go is our failure and must be visible"
        );
    }

    /// The budget belongs to a peer, not to the listener.
    ///
    /// `ShadowSocket` is built once per test port and serves every client for
    /// the life of the process. While the tally lived here, the first
    /// connection consumed all six copies and every later one was shown
    /// nothing -- so the test worked once per restart and reported the other
    /// runs as clients that had never been offered a second address.
    #[test]
    fn the_budget_is_counted_per_peer() {
        let counters = Counters::default();
        let a: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:1001".parse().unwrap();
        let budget = 6;

        for _ in 0..budget {
            counters.peer(a).shadowed.fetch_add(1, Ordering::Relaxed);
        }

        assert_eq!(
            counters.peer(a).shadowed.load(Ordering::Relaxed),
            budget,
            "the first peer has had its allowance"
        );
        assert_eq!(
            counters.peer(b).shadowed.load(Ordering::Relaxed),
            0,
            "and the next peer starts from zero rather than inheriting it"
        );
    }
}
