//! WebTransport over HTTP/3: a session's flow control, and the capsules its
//! CONNECT stream carries (draft-ietf-webtrans-http3-17 sections 5 and 6).
//!
//! Flow control is on for a session when both ends' SETTINGS declare initial
//! limits (section 5.1). It then limits, in each direction, how many
//! unidirectional and bidirectional streams the peer may open (cumulative
//! counts, raised by WT_MAX_STREAMS) and how many bytes of Stream Body it may
//! send across all of them (WT_MAX_DATA). This side grants more as the
//! peer's streams close and as their data is read, without waiting for the
//! peer to say it is blocked (section 5.6), and never opens more streams or
//! sends more data than the peer granted, saying so with WT_STREAMS_BLOCKED
//! and WT_DATA_BLOCKED.
//!
//! The capsules travel on the session's CONNECT stream; the task that holds
//! it reads them with [`CapsuleReader`] and hands them to [`Flow::capsule`],
//! and writes what [`Flow`] queues.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use tokio::sync::{mpsc, watch, Notify};

/// WT_FLOW_CONTROL_ERROR, the HTTP/3 error code a session is closed with
/// when its peer breaks a limit (section 9.5)
pub const WT_FLOW_CONTROL_ERROR: u64 = 0x045d_4487;
/// WT_CLOSE_SESSION (section 6)
pub const WT_CLOSE_SESSION: u64 = 0x2843;
/// WT_DRAIN_SESSION (section 4.7)
pub const WT_DRAIN_SESSION: u64 = 0x78ae;
/// WT_MAX_DATA (section 5.6.4)
pub const WT_MAX_DATA: u64 = 0x190b_4d3d;
/// WT_MAX_STREAMS for bidirectional streams (section 5.6.2)
pub const WT_MAX_STREAMS_BIDI: u64 = 0x190b_4d3f;
/// WT_MAX_STREAMS for unidirectional streams
pub const WT_MAX_STREAMS_UNI: u64 = 0x190b_4d40;
/// WT_DATA_BLOCKED (section 5.6.5)
pub const WT_DATA_BLOCKED: u64 = 0x190b_4d41;
/// WT_STREAMS_BLOCKED for bidirectional streams (section 5.6.3)
pub const WT_STREAMS_BLOCKED_BIDI: u64 = 0x190b_4d43;
/// WT_STREAMS_BLOCKED for unidirectional streams
pub const WT_STREAMS_BLOCKED_UNI: u64 = 0x190b_4d44;
/// WebTransport over HTTP/2's per-stream capsules (draft-ietf-webtrans-http2
/// sections 6.5 and 6.6), prohibited over HTTP/3 (section 5.4 here)
pub const WT_MAX_STREAM_DATA: u64 = 0x190b_4d3e;
/// See [`WT_MAX_STREAM_DATA`]
pub const WT_STREAM_DATA_BLOCKED: u64 = 0x190b_4d42;

/// The largest Maximum Streams a capsule may carry: no stream ID above
/// 2^62 - 1 can be encoded (section 5.6.2)
const MAX_STREAMS_CEILING: u64 = 1 << 60;
/// The longest capsule value this side keeps; a longer one of a type it
/// reads is a session error, and a longer one of any other type is skipped
const CAPSULE_MAX: u64 = 1 << 16;

/// A session error: the HTTP/3 error code the session is closed with, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowError {
    pub code: u64,
    pub reason: &'static str,
}

impl FlowError {
    const fn flow(reason: &'static str) -> Self {
        Self {
            code: WT_FLOW_CONTROL_ERROR,
            reason,
        }
    }
}

impl std::fmt::Display for FlowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:#x})", self.reason, self.code)
    }
}

/// Initial limits: streams of each direction and Stream Body bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    pub streams_uni: u64,
    pub streams_bidi: u64,
    pub data: u64,
}

/// What a capsule asks of the session, beyond flow control.
#[derive(Debug, PartialEq, Eq)]
pub enum Capsule {
    /// Flow control, or a capsule with nothing to act on
    Handled,
    /// WT_CLOSE_SESSION: the peer ended the session
    Close { code: u32, reason: String },
    /// WT_DRAIN_SESSION: the peer asks for a graceful end
    Drain,
}

/// One direction's stream count: those opened, and the cumulative limit.
#[derive(Debug, Default)]
struct Streams {
    opened: AtomicU64,
    closed: AtomicU64,
    max: AtomicU64,
}

/// A session's flow control.
#[derive(Debug)]
pub struct Flow {
    enabled: bool,
    /// The windows this side grants: streams open at once, bytes unread
    window: Limits,
    in_uni: Streams,
    in_bidi: Streams,
    in_data: AtomicU64,
    in_data_max: AtomicU64,
    out_uni: Streams,
    out_bidi: Streams,
    out_data: AtomicU64,
    out_data_max: AtomicU64,
    /// Raised whenever the peer grants more streams
    stream_credit: Notify,
    /// Writers waiting for the peer to grant more data
    data_waiters: Mutex<Vec<Waker>>,
    /// The peer limit each BLOCKED capsule was last sent for (uni, bidi,
    /// data): one per limit, not one per attempt
    blocked_at: Mutex<[Option<u64>; 3]>,
    /// Capsules for the CONNECT stream
    out: mpsc::UnboundedSender<Bytes>,
    /// The first session error raised, for the task that holds the CONNECT
    /// stream to close the session with
    violated: watch::Sender<Option<FlowError>>,
}

impl Flow {
    /// A session's flow control: on when `enabled` (both ends declared
    /// limits), granting `ours` and held to `peer`'s, its capsules sent to
    /// `out`.
    pub fn new(
        enabled: bool,
        ours: Limits,
        peer: Limits,
        out: mpsc::UnboundedSender<Bytes>,
    ) -> Arc<Self> {
        let streams = |max: u64| Streams {
            max: AtomicU64::new(max),
            ..Streams::default()
        };
        Arc::new(Self {
            enabled,
            window: ours,
            in_uni: streams(ours.streams_uni),
            in_bidi: streams(ours.streams_bidi),
            in_data: AtomicU64::new(0),
            in_data_max: AtomicU64::new(ours.data),
            out_uni: streams(peer.streams_uni),
            out_bidi: streams(peer.streams_bidi),
            out_data: AtomicU64::new(0),
            out_data_max: AtomicU64::new(peer.data),
            stream_credit: Notify::new(),
            data_waiters: Mutex::new(Vec::new()),
            blocked_at: Mutex::new([None; 3]),
            out,
            violated: watch::channel(None).0,
        })
    }

    /// Close the session for `e`: the task holding its CONNECT stream resets
    /// it with `e`'s code. The first error raised is the one used.
    pub fn violate(&self, e: FlowError) {
        self.violated.send_if_modified(|v| {
            if v.is_some() {
                return false;
            }
            *v = Some(e);
            true
        });
    }

    /// Resolves with the first session error raised.
    pub async fn violation(&self) -> FlowError {
        let mut raised = self.violated.subscribe();
        let first = raised
            .wait_for(Option::is_some)
            .await
            .map(|e| e.clone().unwrap_or(FlowError::flow("a session error")));
        match first {
            Ok(e) => e,
            // The sender lives in `self`, which outlives this borrow
            Err(_) => std::future::pending().await,
        }
    }

    /// Whether flow control is on for this session.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    fn send(&self, kind: u64, value: u64) {
        let _ = self.out.send(capsule_u64(kind, value));
    }

    // ── Streams and data the peer sends ─────────────────────────────────────

    /// A stream the peer opened: its slot, released when the stream is done,
    /// or the session error when it is one more than the peer may open
    /// (section 5.6.2).
    pub fn peer_opened(self: &Arc<Self>, bidi: bool) -> Result<StreamSlot, FlowError> {
        if self.enabled {
            let s = if bidi { &self.in_bidi } else { &self.in_uni };
            let n = s.opened.fetch_add(1, Ordering::AcqRel) + 1;
            if n > s.max.load(Ordering::Acquire) {
                return Err(FlowError::flow("a stream beyond WT_MAX_STREAMS"));
            }
        }
        Ok(StreamSlot(Arc::new(SlotInner {
            flow: Arc::clone(self),
            bidi,
        })))
    }

    /// One of the peer's streams is done: its credit goes back, a
    /// WT_MAX_STREAMS sent once half a window is to be granted.
    fn peer_closed(&self, bidi: bool) {
        if !self.enabled {
            return;
        }
        let (s, window, kind) = if bidi {
            (&self.in_bidi, self.window.streams_bidi, WT_MAX_STREAMS_BIDI)
        } else {
            (&self.in_uni, self.window.streams_uni, WT_MAX_STREAMS_UNI)
        };
        let closed = s.closed.fetch_add(1, Ordering::AcqRel) + 1;
        let new_max = closed.saturating_add(window).min(MAX_STREAMS_CEILING);
        let current = s.max.load(Ordering::Acquire);
        if new_max >= current.saturating_add(window.div_ceil(2))
            && s.max
                .compare_exchange(current, new_max, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.send(kind, new_max);
        }
    }

    /// `n` bytes of Stream Body read from the peer, or the session error when
    /// they take it past the data it may send (section 5.6.4). WT_MAX_DATA
    /// goes out once half a window is to be granted.
    pub fn peer_data(&self, n: u64) -> Result<(), FlowError> {
        if !self.enabled || n == 0 {
            return Ok(());
        }
        let received = self.in_data.fetch_add(n, Ordering::AcqRel) + n;
        let current = self.in_data_max.load(Ordering::Acquire);
        if received > current {
            return Err(FlowError::flow("Stream Body beyond WT_MAX_DATA"));
        }
        let window = self.window.data;
        let new_max = received.saturating_add(window);
        if new_max >= current.saturating_add(window.div_ceil(2))
            && self
                .in_data_max
                .compare_exchange(current, new_max, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.send(WT_MAX_DATA, new_max);
        }
        Ok(())
    }

    // ── Streams and data this side sends ────────────────────────────────────

    /// Wait until the peer allows one more stream of this direction, saying
    /// WT_STREAMS_BLOCKED once per limit while waiting (section 5.6.3).
    pub async fn open(&self, bidi: bool) {
        if !self.enabled {
            return;
        }
        let (s, index, kind) = if bidi {
            (&self.out_bidi, 1, WT_STREAMS_BLOCKED_BIDI)
        } else {
            (&self.out_uni, 0, WT_STREAMS_BLOCKED_UNI)
        };
        loop {
            let credit = self.stream_credit.notified();
            let max = s.max.load(Ordering::Acquire);
            let opened = s.opened.load(Ordering::Acquire);
            if opened < max
                && s.opened
                    .compare_exchange(opened, opened + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return;
            }
            if opened >= max {
                self.blocked(index, kind, max);
                credit.await;
            }
        }
    }

    /// How many of `want` bytes may be written now; none registers `cx` to
    /// be woken when the peer grants more, after one WT_DATA_BLOCKED for the
    /// limit (section 5.6.5).
    pub fn reserve(&self, want: usize, cx: &mut Context<'_>) -> Poll<usize> {
        if !self.enabled || want == 0 {
            return Poll::Ready(want);
        }
        loop {
            let max = self.out_data_max.load(Ordering::Acquire);
            let sent = self.out_data.load(Ordering::Acquire);
            let room = usize::try_from(max.saturating_sub(sent)).unwrap_or(usize::MAX);
            if room == 0 {
                self.data_waiters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(cx.waker().clone());
                // A grant between the load and the registration is seen here
                if self.out_data_max.load(Ordering::Acquire) > sent {
                    continue;
                }
                self.blocked(2, WT_DATA_BLOCKED, max);
                return Poll::Pending;
            }
            let n = want.min(room);
            if self
                .out_data
                .compare_exchange(sent, sent + n as u64, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Poll::Ready(n);
            }
        }
    }

    /// Bytes reserved and not written (a write that sent fewer), returned.
    pub fn unreserve(&self, n: usize) {
        if self.enabled && n > 0 {
            self.out_data.fetch_sub(n as u64, Ordering::AcqRel);
        }
    }

    fn blocked(&self, index: usize, kind: u64, max: u64) {
        let mut at = self
            .blocked_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if at[index] != Some(max) {
            at[index] = Some(max);
            drop(at);
            self.send(kind, max);
        }
    }

    // ── Capsules from the peer ───────────────────────────────────────────────

    /// A capsule the peer sent on the CONNECT stream: flow control applied,
    /// a session end returned, or the session error it is.
    pub fn capsule(&self, kind: u64, value: &[u8]) -> Result<Capsule, FlowError> {
        match kind {
            WT_CLOSE_SESSION => {
                if value.len() < 4 {
                    return Err(FlowError {
                        code: H3_MESSAGE_ERROR,
                        reason: "a WT_CLOSE_SESSION shorter than its code",
                    });
                }
                let code = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                // Section 6: a message past 1024 bytes, or not UTF-8, resets
                // the stream with H3_MESSAGE_ERROR
                if value.len() - 4 > CLOSE_MESSAGE_MAX {
                    return Err(FlowError {
                        code: H3_MESSAGE_ERROR,
                        reason: "a WT_CLOSE_SESSION message over 1024 bytes",
                    });
                }
                let Ok(reason) = std::str::from_utf8(&value[4..]) else {
                    return Err(FlowError {
                        code: H3_MESSAGE_ERROR,
                        reason: "a WT_CLOSE_SESSION message that is not UTF-8",
                    });
                };
                return Ok(Capsule::Close {
                    code,
                    reason: reason.to_string(),
                });
            }
            WT_DRAIN_SESSION => return Ok(Capsule::Drain),
            WT_MAX_STREAM_DATA | WT_STREAM_DATA_BLOCKED => {
                return Err(FlowError::flow(
                    "WT_MAX_STREAM_DATA or WT_STREAM_DATA_BLOCKED, which HTTP/3 prohibits",
                ));
            }
            WT_MAX_STREAMS_BIDI
            | WT_MAX_STREAMS_UNI
            | WT_MAX_DATA
            | WT_DATA_BLOCKED
            | WT_STREAMS_BLOCKED_BIDI
            | WT_STREAMS_BLOCKED_UNI => {}
            // An unknown capsule is ignored (RFC 9297 section 3.2)
            _ => return Ok(Capsule::Handled),
        }
        // Flow control capsules mean nothing while it is off (section 5.1)
        if !self.enabled {
            return Ok(Capsule::Handled);
        }
        let Some(n) = single_varint(value) else {
            return Err(FlowError {
                code: H3_MESSAGE_ERROR,
                reason: "a flow control capsule that is not one integer",
            });
        };
        match kind {
            WT_MAX_STREAMS_BIDI | WT_MAX_STREAMS_UNI => {
                if n > MAX_STREAMS_CEILING {
                    return Err(FlowError::flow("a Maximum Streams above 2^60"));
                }
                let s = if kind == WT_MAX_STREAMS_BIDI {
                    &self.out_bidi
                } else {
                    &self.out_uni
                };
                if n <= s.max.load(Ordering::Acquire) {
                    return Err(FlowError::flow("a WT_MAX_STREAMS that does not increase"));
                }
                s.max.store(n, Ordering::Release);
                self.stream_credit.notify_waiters();
            }
            WT_MAX_DATA => {
                if n <= self.out_data_max.load(Ordering::Acquire) {
                    return Err(FlowError::flow("a WT_MAX_DATA that does not increase"));
                }
                self.out_data_max.store(n, Ordering::Release);
                for waker in self
                    .data_waiters
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .drain(..)
                {
                    waker.wake();
                }
            }
            WT_STREAMS_BLOCKED_BIDI | WT_STREAMS_BLOCKED_UNI if n > MAX_STREAMS_CEILING => {
                return Err(FlowError::flow("a Maximum Streams above 2^60"));
            }
            // The peer is blocked at our limit: what it may open is granted
            // as its streams close, and said again here so a lost update
            // does not hold it (section 5.6: never wait for BLOCKED)
            WT_STREAMS_BLOCKED_BIDI => {
                self.send(
                    WT_MAX_STREAMS_BIDI,
                    self.in_bidi.max.load(Ordering::Acquire),
                );
            }
            WT_STREAMS_BLOCKED_UNI => {
                self.send(WT_MAX_STREAMS_UNI, self.in_uni.max.load(Ordering::Acquire));
            }
            WT_DATA_BLOCKED => {
                self.send(WT_MAX_DATA, self.in_data_max.load(Ordering::Acquire));
            }
            _ => {}
        }
        Ok(Capsule::Handled)
    }
}

/// H3_MESSAGE_ERROR (RFC 9114 section 8.1): a malformed capsule
pub const H3_MESSAGE_ERROR: u64 = 0x10e;

/// The longest Application Error Message WT_CLOSE_SESSION carries (section 6)
const CLOSE_MESSAGE_MAX: usize = 1024;

/// A stream the peer opened, counted until both its halves are dropped.
#[derive(Clone, Debug)]
pub struct StreamSlot(Arc<SlotInner>);

#[derive(Debug)]
struct SlotInner {
    flow: Arc<Flow>,
    bidi: bool,
}

impl Drop for SlotInner {
    fn drop(&mut self) {
        self.flow.peer_closed(self.bidi);
    }
}

impl StreamSlot {
    /// The session's flow control.
    pub fn flow(&self) -> &Flow {
        &self.0.flow
    }
}

// ── Capsules on the wire ─────────────────────────────────────────────────────

/// A capsule whose value is one variable-length integer.
pub fn capsule_u64(kind: u64, value: u64) -> Bytes {
    let mut v = Vec::with_capacity(8);
    put_varint(&mut v, value);
    capsule(kind, &v)
}

/// A capsule: its type, length and value (RFC 9297 section 3.2).
pub fn capsule(kind: u64, value: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(value.len() + 16);
    put_varint(&mut out, kind);
    put_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    Bytes::from(out)
}

fn put_varint(out: &mut Vec<u8>, value: u64) {
    let (len, tag) = match value {
        0..=0x3f => (1, 0x00),
        0x40..=0x3fff => (2, 0x40),
        0x4000..=0x3fff_ffff => (4, 0x80),
        _ => (8, 0xc0),
    };
    let start = out.len();
    out.extend_from_slice(&value.to_be_bytes()[8 - len..]);
    out[start] |= tag;
}

/// A QUIC variable-length integer at the front of `b`, and its length.
fn varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len)?;
    let mut v = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        v = (v << 8) | u64::from(*byte);
    }
    Some((v, len))
}

/// A value that is exactly one variable-length integer.
fn single_varint(b: &[u8]) -> Option<u64> {
    varint(b).and_then(|(v, len)| (len == b.len()).then_some(v))
}

/// The capsules in a CONNECT stream's data, as it arrives in pieces: each
/// whole capsule of a type this side reads, others skipped as they pass.
#[derive(Debug, Default)]
pub struct CapsuleReader {
    buf: BytesMut,
    /// Bytes of a capsule being skipped still to come
    skipping: u64,
}

impl CapsuleReader {
    /// Whether bytes of a capsule not yet whole are held, or being skipped.
    pub fn has_pending(&self) -> bool {
        !self.buf.is_empty() || self.skipping > 0
    }

    /// The capsules `data` completes, or the session error a malformed or
    /// oversized one is.
    pub fn push(&mut self, mut data: Bytes) -> Result<Vec<(u64, Bytes)>, FlowError> {
        let skip = usize::try_from(self.skipping)
            .unwrap_or(usize::MAX)
            .min(data.len());
        data.advance(skip);
        self.skipping -= skip as u64;
        self.buf.extend_from_slice(&data);
        let mut out = Vec::new();
        while self.skipping == 0 {
            let Some((kind, a)) = varint(&self.buf) else {
                break;
            };
            let Some((len, b)) = varint(&self.buf[a..]) else {
                break;
            };
            let here = self.buf.len() - a - b;
            if !reads(kind) {
                // Not kept: skipped, however long
                match usize::try_from(len) {
                    Ok(len) if len <= here => {
                        self.buf.advance(a + b + len);
                        continue;
                    }
                    _ => {
                        self.skipping = len - here as u64;
                        self.buf.clear();
                        break;
                    }
                }
            }
            let Some(len) = usize::try_from(len)
                .ok()
                .filter(|l| *l as u64 <= CAPSULE_MAX)
            else {
                return Err(FlowError {
                    code: H3_MESSAGE_ERROR,
                    reason: "a WebTransport capsule too long to be one",
                });
            };
            let whole = a + b + len;
            if self.buf.len() < whole {
                break;
            }
            let mut capsule = self.buf.split_to(whole).freeze();
            capsule.advance(a + b);
            out.push((kind, capsule));
        }
        Ok(out)
    }
}

/// The capsule types a WebTransport session reads.
const fn reads(kind: u64) -> bool {
    matches!(
        kind,
        WT_CLOSE_SESSION
            | WT_DRAIN_SESSION
            | WT_MAX_DATA
            | WT_MAX_STREAMS_BIDI
            | WT_MAX_STREAMS_UNI
            | WT_DATA_BLOCKED
            | WT_STREAMS_BLOCKED_BIDI
            | WT_STREAMS_BLOCKED_UNI
            | WT_MAX_STREAM_DATA
            | WT_STREAM_DATA_BLOCKED
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const OURS: Limits = Limits {
        streams_uni: 4,
        streams_bidi: 4,
        data: 1000,
    };

    fn flow(peer: Limits) -> (Arc<Flow>, mpsc::UnboundedReceiver<Bytes>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Flow::new(true, OURS, peer, tx), rx)
    }

    fn sent(rx: &mut mpsc::UnboundedReceiver<Bytes>) -> Vec<(u64, u64)> {
        let mut r = CapsuleReader::default();
        let mut out = Vec::new();
        while let Ok(b) = rx.try_recv() {
            for (kind, value) in r.push(b).unwrap() {
                out.push((kind, single_varint(&value).unwrap()));
            }
        }
        out
    }

    /// The peer may open as many streams as granted, one more is
    /// WT_FLOW_CONTROL_ERROR, and closed streams' credit goes back by half
    /// windows (section 5.6.2)
    #[test]
    fn the_peer_s_streams_are_counted_and_their_credit_returned() {
        let (f, mut rx) = flow(OURS);
        let slots: Vec<_> = (0..4).map(|_| f.peer_opened(false).unwrap()).collect();
        assert_eq!(
            f.peer_opened(false).unwrap_err().code,
            WT_FLOW_CONTROL_ERROR
        );
        drop(slots);
        // Four closed: the limit goes from 4 to 6 at the second close (half
        // a window granted), then to 8 at the fourth
        assert_eq!(
            sent(&mut rx),
            [(WT_MAX_STREAMS_UNI, 6), (WT_MAX_STREAMS_UNI, 8)]
        );
        assert!(f.peer_opened(true).is_ok(), "bidi has its own count");
    }

    /// A bidirectional stream is done when both halves are
    #[test]
    fn a_bidirectional_stream_closes_with_its_last_half() {
        let (f, mut rx) = flow(OURS);
        let a = f.peer_opened(true).unwrap();
        let b = f.peer_opened(true).unwrap();
        let a2 = a.clone();
        drop(a);
        drop(b);
        assert_eq!(sent(&mut rx), [], "one stream still open");
        drop(a2);
        assert_eq!(sent(&mut rx), [(WT_MAX_STREAMS_BIDI, 6)]);
    }

    /// Data past WT_MAX_DATA is a session error; reading earns more
    #[test]
    fn the_peer_s_data_is_held_to_the_limit() {
        let (f, mut rx) = flow(OURS);
        f.peer_data(400).unwrap();
        assert_eq!(sent(&mut rx), []);
        f.peer_data(200).unwrap();
        assert_eq!(sent(&mut rx), [(WT_MAX_DATA, 1600)]);
        assert_eq!(f.peer_data(1001).unwrap_err().code, WT_FLOW_CONTROL_ERROR);
    }

    /// This side opens no more than the peer allows, waits for its
    /// WT_MAX_STREAMS, and says WT_STREAMS_BLOCKED once
    #[tokio::test]
    async fn opening_waits_for_the_peer_s_credit() {
        let (f, mut rx) = flow(Limits {
            streams_uni: 1,
            streams_bidi: 0,
            data: 10,
        });
        f.open(false).await;
        let waiting = tokio::spawn({
            let f = Arc::clone(&f);
            async move { f.open(false).await }
        });
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());
        assert_eq!(sent(&mut rx), [(WT_STREAMS_BLOCKED_UNI, 1)]);
        assert_eq!(
            f.capsule(WT_MAX_STREAMS_UNI, &[2]).unwrap(),
            Capsule::Handled
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .expect("credit opens the stream")
            .unwrap();
    }

    /// Writes stop at the peer's WT_MAX_DATA and go on when it grows
    #[test]
    fn writing_stops_at_the_peer_s_data_limit() {
        let (f, mut rx) = flow(Limits {
            streams_uni: 1,
            streams_bidi: 1,
            data: 10,
        });
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(f.reserve(8, &mut cx), Poll::Ready(8));
        assert_eq!(f.reserve(8, &mut cx), Poll::Ready(2));
        assert_eq!(f.reserve(8, &mut cx), Poll::Pending);
        assert_eq!(sent(&mut rx), [(WT_DATA_BLOCKED, 10)]);
        f.capsule(WT_MAX_DATA, &[0x40, 20]).unwrap();
        assert_eq!(f.reserve(8, &mut cx), Poll::Ready(8));
    }

    /// The peer's limits only grow, never past 2^60; HTTP/2's per-stream
    /// capsules are refused; with flow control off they mean nothing
    #[test]
    fn the_peer_s_capsules_are_checked() {
        let (f, _rx) = flow(OURS);
        assert_eq!(
            f.capsule(WT_MAX_DATA, &[0x40, 0x10]).unwrap_err().reason,
            "a WT_MAX_DATA that does not increase"
        );
        let mut big = Vec::new();
        put_varint(&mut big, (1 << 60) + 1);
        assert!(f.capsule(WT_MAX_STREAMS_BIDI, &big).is_err());
        assert!(f.capsule(WT_STREAMS_BLOCKED_UNI, &big).is_err());
        assert!(f.capsule(WT_MAX_STREAM_DATA, &[]).is_err());
        assert!(f.capsule(WT_STREAM_DATA_BLOCKED, &[]).is_err());
        assert_eq!(f.capsule(0x1234, &[1, 2, 3]).unwrap(), Capsule::Handled);
        let (tx, _rx) = mpsc::unbounded_channel();
        let off = Flow::new(false, OURS, OURS, tx);
        assert_eq!(off.capsule(WT_MAX_DATA, &[0]).unwrap(), Capsule::Handled);
        assert!(off.peer_opened(false).is_ok());
        assert!(off.peer_data(u64::MAX / 2).is_ok());
    }

    /// WT_CLOSE_SESSION's message: up to 1024 bytes of UTF-8, or the stream
    /// is reset with H3_MESSAGE_ERROR (section 6)
    #[test]
    fn a_close_message_is_utf8_and_at_most_1024_bytes() {
        let (f, _rx) = flow(OURS);
        let close = |message: &[u8]| {
            let mut v = 9u32.to_be_bytes().to_vec();
            v.extend_from_slice(message);
            f.capsule(WT_CLOSE_SESSION, &v)
        };
        assert_eq!(
            close(&[b'a'; 1024]).unwrap(),
            Capsule::Close {
                code: 9,
                reason: "a".repeat(1024)
            }
        );
        assert_eq!(close(&[b'a'; 1025]).unwrap_err().code, H3_MESSAGE_ERROR);
        assert_eq!(close(&[0xff, 0xfe]).unwrap_err().code, H3_MESSAGE_ERROR);
    }

    /// Capsules come whole however the data is split, unknown ones skipped
    /// however long, and WT_CLOSE_SESSION gives its code and message
    #[test]
    fn capsules_are_read_from_pieces() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&capsule(0x00ff, &[7u8; 300]));
        wire.extend_from_slice(&capsule_u64(WT_MAX_DATA, 5000));
        let mut close = 7u32.to_be_bytes().to_vec();
        close.extend_from_slice(b"done");
        wire.extend_from_slice(&capsule(WT_CLOSE_SESSION, &close));
        let mut r = CapsuleReader::default();
        let mut got = Vec::new();
        for piece in wire.chunks(7) {
            got.extend(r.push(Bytes::copy_from_slice(piece)).unwrap());
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, WT_MAX_DATA);
        assert_eq!(single_varint(&got[0].1), Some(5000));
        let (f, _rx) = flow(OURS);
        assert_eq!(
            f.capsule(got[1].0, &got[1].1).unwrap(),
            Capsule::Close {
                code: 7,
                reason: "done".into()
            }
        );
        let mut oversized = Vec::new();
        put_varint(&mut oversized, WT_MAX_DATA);
        put_varint(&mut oversized, CAPSULE_MAX + 1);
        assert!(CapsuleReader::default()
            .push(Bytes::from(oversized))
            .is_err());
    }
}
