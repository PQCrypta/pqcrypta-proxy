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
use quinn::udp::{RecvMeta, Transmit};

use super::h3_frames::read_varint;
use quinn::{AsyncUdpSocket, UdpSender};
use tracing::debug;

/// What the socket counted while a test ran.
#[derive(Debug, Default)]
pub struct Counters {
    /// Datagrams received from any peer.
    pub datagrams_in: AtomicU64,
    /// Datagrams the black hole swallowed.
    pub dropped_oversize: AtomicU64,
    /// Datagrams copied out of the second socket for `q-connection-migration`.
    ///
    /// The verdict needs to know whether the client was ever actually shown an
    /// unannounced server address: if the copy never went out, a connection that
    /// carried on proves nothing.
    pub shadowed: AtomicU64,
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
    /// The address the most recent datagram came from.
    ///
    /// `q-version-negotiation` is judged from the socket alone — no connection
    /// is ever established there, so there is no peer address anywhere else to
    /// read. Without it that test's verdict has no session to be filed under and
    /// never reaches the client that earned it.
    pub last_peer: parking_lot::Mutex<Option<SocketAddr>>,
}

impl Counters {
    pub fn datagrams_in(&self) -> u64 {
        self.datagrams_in.load(Ordering::Relaxed)
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

    pub fn zero_rtt_in(&self) -> u64 {
        self.zero_rtt_in.load(Ordering::Relaxed)
    }

    pub fn last_peer(&self) -> Option<SocketAddr> {
        *self.last_peer.lock()
    }
}

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
                    if carries_zero_rtt(dgram) {
                        self.counters.zero_rtt_in.fetch_add(1, Ordering::Relaxed);
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
    walk_for_zero_rtt(dgram).unwrap_or(false)
}

/// The walk itself. `None` means "could not parse any further", which the caller
/// reads as "not found" — the answer is only ever "a 0-RTT packet was definitely
/// here".
fn walk_for_zero_rtt(mut dgram: &[u8]) -> Option<bool> {
    /// QUIC v1. A different version is a different packet layout, and guessing
    /// at one is how a parser starts inventing results.
    const V1: u32 = 1;
    const INITIAL: u8 = 0x0;
    const ZERO_RTT: u8 = 0x1;
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
        if packet_type == ZERO_RTT {
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
    socket: std::net::UdpSocket,
    budget: u64,
    sent: AtomicU64,
}

impl ShadowSocket {
    /// Bind an ephemeral port on the same host. `None` if that is not possible,
    /// which leaves the test reporting that nothing was exercised rather than
    /// failing a client for our own missing socket.
    fn bind(budget: u64) -> Option<Self> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, 0))
            .or_else(|_| std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)))
            .ok()?;
        // Never block the sending path: a datagram that cannot go out
        // immediately is simply not shadowed.
        socket.set_nonblocking(true).ok()?;
        Some(Self {
            socket,
            budget,
            sent: AtomicU64::new(0),
        })
    }

    /// Copy `datagram` to `peer` from this socket, while budget remains.
    fn shadow(&self, datagram: &[u8], peer: SocketAddr) -> bool {
        if self.sent.load(Ordering::Relaxed) >= self.budget {
            return false;
        }
        if self.socket.send_to(datagram, peer).is_err() {
            return false;
        }
        self.sent.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// Whether the `nth` datagram since the impairment opened is the one to lose.
///
/// Counting from one, so the first datagram after the clean window is never the
/// casualty: the response headers usually ride in it, and losing those on some
/// runs and not others would make the same client pass and fail by turns.
fn is_lost(nth: u64, one_in: u64) -> bool {
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
}

impl UdpSender for ImpairedSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let now = Instant::now();

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
                && shadow.shadow(transmit.contents, transmit.destination)
            {
                self.counters.shadowed.fetch_add(1, Ordering::Relaxed);
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
