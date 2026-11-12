//! Real packet loss on one peer's path, at the socket.
//!
//! The WebTransport telemetry wall lets a visitor put loss on their own
//! connection and watch what QUIC does with it. Loss is a property of the
//! path, so this is where it is made: the QUIC endpoints send through
//! [`LossySocket`], which drops the given share of the datagrams bound for a
//! peer that asked for it, and reports them sent, as a lossy path does. What
//! follows is QUIC's own: the packets are declared lost, their frames are
//! sent again, the congestion controller responds, and each stream stalls
//! only for the data that was in a lost packet, which is the isolation from
//! head-of-line blocking the wall exists to show.
//!
//! A peer's loss is held by a [`PeerLoss`], which takes it away when dropped,
//! so a session that ends for any reason leaves its path clean. With no loss
//! set anywhere a datagram costs one atomic load.

use std::hash::BuildHasher;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use dashmap::DashMap;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpSender};

/// The loss set for one peer: thousandths of its datagrams dropped, and how
/// many have been.
#[derive(Debug, Default)]
struct Loss {
    permille: AtomicU16,
    dropped: AtomicU64,
}

/// Peers with loss set, by address as the socket sees it.
static PEERS: LazyLock<DashMap<SocketAddr, Arc<Loss>>> = LazyLock::new(DashMap::new);
/// How many entries [`PEERS`] has: the fast path when it has none.
static SET: AtomicUsize = AtomicUsize::new(0);
/// The key of the drop decision, chosen per process.
static KEY: LazyLock<std::collections::hash_map::RandomState> =
    LazyLock::new(std::collections::hash_map::RandomState::new);

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The path loss of one peer, set while this is held.
#[derive(Debug)]
pub struct PeerLoss {
    peer: SocketAddr,
    loss: Arc<Loss>,
}

impl PeerLoss {
    /// Take hold of `peer`'s path loss, at none to begin with.
    pub fn new(peer: SocketAddr) -> Self {
        let peer = canonical(peer);
        let loss = Arc::new(Loss::default());
        if PEERS.insert(peer, Arc::clone(&loss)).is_none() {
            SET.fetch_add(1, Ordering::Relaxed);
        }
        Self { peer, loss }
    }

    /// Drop this share of the datagrams to the peer, in thousandths (at
    /// most 1000).
    pub fn set_permille(&self, permille: u16) {
        self.loss
            .permille
            .store(permille.min(1000), Ordering::Relaxed);
    }

    /// The share being dropped, in thousandths.
    pub fn permille(&self) -> u16 {
        self.loss.permille.load(Ordering::Relaxed)
    }

    /// Datagrams dropped on the way to the peer so far.
    pub fn dropped(&self) -> u64 {
        self.loss.dropped.load(Ordering::Relaxed)
    }
}

impl Drop for PeerLoss {
    fn drop(&mut self) {
        // Only this holder's entry: a later one for the same address stays
        let mine = &self.loss;
        if PEERS
            .remove_if(&self.peer, |_, held| Arc::ptr_eq(held, mine))
            .is_some()
        {
            SET.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// The loss to apply to a datagram bound for `destination`, if any.
fn loss_to(destination: SocketAddr) -> Option<Arc<Loss>> {
    if SET.load(Ordering::Relaxed) == 0 {
        return None;
    }
    PEERS
        .get(&canonical(destination))
        .map(|entry| Arc::clone(entry.value()))
        .filter(|loss| loss.permille.load(Ordering::Relaxed) > 0)
}

/// Whether the datagram `segment` is one of those lost at `permille`.
///
/// Decided from the datagram itself, its last 16 bytes (a packet's AEAD tag,
/// random to anyone without its keys) under a key of this process's own, so
/// the same transmit polled again after `Pending` loses the same datagrams.
fn is_lost(segment: &[u8], permille: u16) -> bool {
    let tail = &segment[segment.len().saturating_sub(16)..];
    KEY.hash_one(tail) % 1000 < u64::from(permille)
}

/// A socket whose sends lose what [`PeerLoss`] asks for; everything else
/// passes through unchanged.
#[derive(Debug)]
pub struct LossySocket {
    inner: Box<dyn AsyncUdpSocket>,
}

impl LossySocket {
    pub fn new(inner: Box<dyn AsyncUdpSocket>) -> Self {
        Self { inner }
    }
}

impl AsyncUdpSocket for LossySocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(LossySender {
            inner: self.inner.create_sender(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
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

#[derive(Debug)]
struct LossySender {
    inner: Pin<Box<dyn UdpSender>>,
}

impl UdpSender for LossySender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(loss) = loss_to(transmit.destination) else {
            return self.inner.as_mut().poll_send(transmit, cx);
        };
        let permille = loss.permille.load(Ordering::Relaxed);
        // A batch of equal-sized datagrams (the last may be shorter): each is
        // lost or not on its own, and what is left still makes a batch
        let size = transmit
            .segment_size
            .filter(|s| *s > 0)
            .unwrap_or_else(|| transmit.contents.len().max(1));
        let segments = transmit.contents.chunks(size);
        let total = segments.len();
        let kept: Vec<&[u8]> = segments.filter(|s| !is_lost(s, permille)).collect();
        let lost = total - kept.len();
        if lost == 0 {
            return self.inner.as_mut().poll_send(transmit, cx);
        }
        if kept.is_empty() {
            loss.dropped.fetch_add(lost as u64, Ordering::Relaxed);
            // Gone without a trace, as on a lossy path
            return Poll::Ready(Ok(()));
        }
        let contents: Vec<u8> = kept.concat();
        let thinned = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size: (kept.len() > 1).then_some(size),
            src_ip: transmit.src_ip,
        };
        let sent = self.inner.as_mut().poll_send(&thinned, cx);
        if sent.is_ready() {
            loss.dropped.fetch_add(lost as u64, Ordering::Relaxed);
        }
        sent
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        self.inner.max_transmit_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peers_loss_is_set_while_held_and_gone_after() {
        let peer: SocketAddr = "[::ffff:203.0.113.9]:4433".parse().unwrap();
        assert!(loss_to(peer).is_none());
        let held = PeerLoss::new(peer);
        assert!(loss_to(peer).is_none(), "none until a share is set");
        held.set_permille(250);
        // The same peer however its address is spelled
        assert!(loss_to("203.0.113.9:4433".parse().unwrap()).is_some());
        assert!(loss_to("203.0.113.9:4434".parse().unwrap()).is_none());
        held.set_permille(5000);
        assert_eq!(held.permille(), 1000);
        drop(held);
        assert!(loss_to(peer).is_none());
    }

    #[test]
    fn the_share_lost_is_the_share_asked_for_and_the_same_each_time() {
        let mut lost = 0;
        for n in 0u32..20_000 {
            let mut datagram = vec![0u8; 64];
            datagram[48..52].copy_from_slice(&n.to_be_bytes());
            if is_lost(&datagram, 200) {
                lost += 1;
            }
            assert_eq!(is_lost(&datagram, 200), is_lost(&datagram, 200));
        }
        // 20 % of 20,000, within a generous margin
        assert!((3_500..4_500).contains(&lost), "{lost}");
        assert!(!is_lost(&[1, 2, 3], 0));
        assert!(is_lost(&[1, 2, 3], 1000));
    }
}
