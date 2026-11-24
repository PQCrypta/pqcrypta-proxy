//! One MOQT session at the relay (draft-ietf-moq-transport sections 6, 9,
//! 11).
//!
//! The SETUP exchange on a pair of control streams, one request per
//! bidirectional stream, objects on unidirectional streams and datagrams.
//!
//! The same code runs both roles: the server side for a client that
//! connected to the relay, and the client side for the relay's own sessions
//! to an upstream relay. Requests from the peer are served from the shared
//! [`Relay`]; the relay's requests to the peer (an upstream SUBSCRIBE or
//! FETCH to a publisher) go out on streams this session opens.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::StreamExt as _;
use tokio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::auth::{PublishAuth, TokenCache};
use super::codec::{read_vi64, Location, Namespace, TrackName};
use super::data::{
    self, decode_datagram, encode_datagram, encode_subgroup_object, DataError, DatagramKind,
    Delivery, FetchEntry, FetchState, Object, ObjectStatus, RangeKind, SubgroupHeader,
    SubgroupIdMode,
};
use super::error::{DoneCode, RequestCode, ResetCode, SessionCode as C, SessionError};
use super::message::{
    self, allowed, read_frame, Context, FrameError, GroupOrder, LocationFilter, Message, Params,
    PrefixRequest, Publish, RangeFilter, RequestError, Setup, TrackRequest,
};
use super::relay::{
    Advertisement, Event, Lookup, NamespaceEvent, NamespacePublisher, Relay, Track, Upstream,
};
use super::transport::{RecvHalf, SendHalf, Transport};
use super::version::Version;

/// How long the peer has to send SETUP (CONTROL_MESSAGE_TIMEOUT)
const SETUP_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a response to the relay's own request may take
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a data stream with an unknown Track Alias is held (3.1.3.1)
const UNKNOWN_ALIAS_WAIT: Duration = Duration::from_secs(2);
/// Objects queued for one subgroup stream before the subscriber is too far
/// behind (PUBLISH_DONE TOO_FAR_BEHIND, section 12.4)
const STREAM_QUEUE: usize = 1024;
/// An upstream subscription nobody downstream has used for this long ends
const UPSTREAM_LINGER: Duration = Duration::from_secs(30);
/// PUBLISH requests one SUBSCRIBE_TRACKS may produce
const TRACKS_PER_SUBSCRIBE_TRACKS: usize = 1024;

/// Which end of the session this relay is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Server,
    Client,
}

/// What the relay's sessions are configured with (`[moq]`).
pub struct Settings {
    pub implementation: String,
    pub max_request_updates: u64,
    pub max_filter_ranges: u64,
    pub max_auth_token_cache: u64,
    pub max_control_message: u64,
    /// PATH values a native QUIC client may name (section 9.1.2)
    pub paths: Vec<String>,
    /// AUTHORITY values a native QUIC client may name (section 9.1.1)
    pub authorities: Vec<String>,
    pub publish_auth: Option<PublishAuth>,
    pub goaway_timeout: Duration,
    /// The per-address rate limits the HTTP routes use, set when the first
    /// listener starts; every request is held to them
    pub limiter: std::sync::OnceLock<Arc<crate::rate_limiter::AdvancedRateLimiter>>,
}

/// The peer's SETUP, and the session's identity, for the admin view.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionInfo {
    pub id: u64,
    pub peer: String,
    pub transport: &'static str,
    pub version: String,
    pub role: &'static str,
    pub implementation: Option<String>,
    pub path: Option<String>,
    #[serde(skip)]
    pub started: Option<Instant>,
    pub age_secs: u64,
}

/// Request IDs the peer has used: all those below `below` (of the peer's
/// parity), and the ones seen above it (section 6.4.2.1).
struct SeenIds {
    below: u64,
    above: BTreeSet<u64>,
}

impl SeenIds {
    fn new(first: u64) -> Self {
        Self {
            below: first,
            above: BTreeSet::new(),
        }
    }

    /// False for a duplicate.
    fn insert(&mut self, id: u64) -> bool {
        if id < self.below || !self.above.insert(id) {
            return false;
        }
        while self.above.remove(&self.below) {
            self.below += 2;
        }
        true
    }
}

/// A FETCH the relay sent upstream: where its data stream's entries go.
struct FetchSink {
    tx: mpsc::Sender<FetchEntry>,
    order: GroupOrder,
}

pub struct Session<T: Transport> {
    pub id: u64,
    t: Arc<T>,
    version: Version,
    role: Role,
    relay: Arc<Relay>,
    settings: Arc<Settings>,
    /// The path the session arrived on (WebTransport's request path, or
    /// native QUIC's PATH option)
    path: Mutex<Option<String>>,
    /// The AUTHORITY this (client) session names in SETUP
    authority: Option<String>,
    peer_setup: Mutex<Option<Setup>>,
    setup_done: watch::Sender<bool>,
    next_request_id: AtomicU64,
    peer_ids: Mutex<SeenIds>,
    aliases_in: Mutex<HashMap<u64, Arc<Track>>>,
    alias_added: Notify,
    next_alias: AtomicU64,
    fetches_out: Mutex<HashMap<u64, FetchSink>>,
    goaway_received: AtomicBool,
    goaway_sent: AtomicBool,
    control: tokio::sync::Mutex<Option<T::Send>>,
    tokens: Mutex<TokenCache>,
    setup_tokens: Mutex<Vec<Bytes>>,
    upstream_streams: AtomicU64,
    closing: CancellationToken,
    started: Instant,
    /// Whether this end's SETUP went out
    setup_sent: AtomicBool,
    /// The requests the peer opened, by type ([`message::REQUEST_TYPES`])
    requests: [AtomicU32; message::REQUEST_TYPES.len()],
    /// How the session ended, first cause first: a session error this end
    /// closed it with, or the peer's or the transport's end
    ended_by: Mutex<Option<String>>,
}

/// A session's end, however it comes. Its cleanup (the session's
/// advertisements withdrawn, its tracks left, its registration and count
/// removed) and its summary line run when this drops: the WebTransport
/// CONNECT task drops a session's future when the CONNECT stream ends or the
/// close the session asked for goes out first, and a session whose cleanup
/// ran only at the end of [`Session::run`] stayed registered, counted open
/// and subscribed for good (2026-11-23).
struct Ended<T: Transport>(Arc<Session<T>>);

impl<T: Transport> Drop for Ended<T> {
    fn drop(&mut self) {
        let s = &self.0;
        s.closing.cancel();
        s.relay.withdraw_session(s.id);
        let tracks: Vec<Arc<Track>> = s
            .aliases_in
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .map(|(_, t)| t)
            .collect();
        for t in tracks {
            t.detach_publisher(s.id);
        }
        s.relay.unregister_session(s.id);
        s.relay.stats.sessions_open.fetch_sub(1, Ordering::Relaxed);
        info!("{}", s.summary());
    }
}

/// Why a request stream's exchange ended without a response.
enum Abort {
    /// The session is closed with this error
    Session(SessionError),
    /// The stream ended or was reset; nothing more to do
    Gone,
}

impl From<SessionError> for Abort {
    fn from(e: SessionError) -> Self {
        Self::Session(e)
    }
}

impl From<FrameError> for Abort {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Session(s) => Self::Session(s),
            FrameError::Io(_) => Self::Gone,
        }
    }
}

impl From<std::io::Error> for Abort {
    fn from(_: std::io::Error) -> Self {
        Self::Gone
    }
}

type Shared<S> = Arc<tokio::sync::Mutex<S>>;

impl<T: Transport> Session<T> {
    pub fn new(
        t: T,
        version: Version,
        role: Role,
        relay: Arc<Relay>,
        settings: Arc<Settings>,
        path: Option<String>,
    ) -> Arc<Self> {
        let id = relay.next_id();
        let (ours, theirs) = match role {
            Role::Server => (1, 0),
            Role::Client => (0, 1),
        };
        let tokens = TokenCache::new(settings.max_auth_token_cache);
        Arc::new(Self {
            id,
            t: Arc::new(t),
            version,
            role,
            relay,
            settings,
            path: Mutex::new(path),
            authority: None,
            peer_setup: Mutex::new(None),
            setup_done: watch::channel(false).0,
            next_request_id: AtomicU64::new(ours),
            peer_ids: Mutex::new(SeenIds::new(theirs)),
            aliases_in: Mutex::new(HashMap::new()),
            alias_added: Notify::new(),
            next_alias: AtomicU64::new(1),
            fetches_out: Mutex::new(HashMap::new()),
            goaway_received: AtomicBool::new(false),
            goaway_sent: AtomicBool::new(false),
            control: tokio::sync::Mutex::new(None),
            tokens: Mutex::new(tokens),
            setup_tokens: Mutex::new(Vec::new()),
            upstream_streams: AtomicU64::new(0),
            closing: CancellationToken::new(),
            started: Instant::now(),
            setup_sent: AtomicBool::new(false),
            requests: Default::default(),
            ended_by: Mutex::new(None),
        })
    }

    /// The relay's own session to an upstream relay: the client side, its
    /// SETUP naming `authority` and `path` (sections 9.1.1, 9.1.2).
    pub fn new_client(
        t: T,
        version: Version,
        relay: Arc<Relay>,
        settings: Arc<Settings>,
        authority: String,
        path: String,
    ) -> Arc<Self> {
        let session = Self::new(t, version, Role::Client, relay, settings, Some(path));
        // Only this function holds the Arc yet
        let mut session =
            Arc::try_unwrap(session).unwrap_or_else(|_| unreachable!("not shared yet"));
        session.authority = Some(authority);
        Arc::new(session)
    }

    /// Whether the session has ended.
    pub fn is_closed(&self) -> bool {
        self.closing.is_cancelled()
    }

    /// Wait for the peer's SETUP; false when the session ends first.
    pub async fn wait_for_setup(&self) -> bool {
        self.setup_complete().await
    }

    pub fn info(&self) -> SessionInfo {
        let setup = self
            .peer_setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        SessionInfo {
            id: self.id,
            peer: self.t.peer().to_string(),
            transport: self.t.kind(),
            version: self.version.to_string(),
            role: match self.role {
                Role::Server => "server",
                Role::Client => "client",
            },
            implementation: setup.as_ref().and_then(|s| s.implementation.clone()),
            path: self
                .path
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            started: Some(self.started),
            age_secs: self.started.elapsed().as_secs(),
        }
    }

    // ── Running ─────────────────────────────────────────────────────────────

    /// Serve the session until it ends. `shutdown` asks it to send GOAWAY
    /// and drain (section 6.6.1).
    pub async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        self.relay
            .stats
            .sessions_total
            .fetch_add(1, Ordering::Relaxed);
        self.relay
            .stats
            .sessions_open
            .fetch_add(1, Ordering::Relaxed);
        self.relay.register_session(self.info());
        let _ended = Ended(Arc::clone(&self));
        let result = async {
            // Opening the control stream waits on the peer's stream credit;
            // the session can end first
            tokio::select! {
                r = self.send_setup() => r?,
                () = self.t.closed() => {
                    self.note_end("the peer ended the session before the relay's SETUP went out");
                    return Ok(());
                }
                () = self.closing.cancelled() => return Ok(()),
            }
            self.setup_sent.store(true, Ordering::Release);
            let uni = Arc::clone(&self).accept_uni_loop();
            let bi = Arc::clone(&self).accept_bi_loop();
            let dg = Arc::clone(&self).datagram_loop();
            let setup_wait = async {
                let mut done = self.setup_done.subscribe();
                if tokio::time::timeout(SETUP_TIMEOUT, done.wait_for(|d| *d))
                    .await
                    .is_err()
                {
                    return Err(SessionError::new(
                        C::ControlMessageTimeout,
                        "no SETUP in time",
                    ));
                }
                std::future::pending::<Result<(), SessionError>>().await
            };
            let drain = async {
                let _ = shutdown.wait_for(|s| *s).await;
                self.goaway().await;
                tokio::time::sleep(self.settings.goaway_timeout).await;
                Err::<(), _>(SessionError::new(
                    C::GoawayTimeout,
                    "the relay is restarting",
                ))
            };
            tokio::select! {
                r = uni => r,
                r = bi => r,
                r = dg => r,
                r = setup_wait => r,
                r = drain => r,
                () = self.t.closed() => {
                    self.note_end("the peer ended the session");
                    Ok(())
                }
                () = self.closing.cancelled() => Ok(()),
            }
        }
        .await;
        if let Err(e) = result {
            self.fail(&e);
        }
        // `_ended` cleans up, here or wherever this future is dropped
    }

    /// Whether the session's transport ends within two round trips (at least
    /// 50 ms, at most a second). A control stream that ends with its session
    /// (WT_CLOSE_SESSION, CONNECTION_CLOSE, a lost connection) is the
    /// session's end, not the CLOSED_CONTROL_STREAM error, which is for a
    /// peer that closes its control stream and goes on; the two arrive
    /// together, in either order.
    async fn ends_within_a_round_trip(&self) -> bool {
        let rtt = self.t.quic().rtt(quinn::PathId::ZERO).unwrap_or_default();
        let grace = (rtt * 2).clamp(Duration::from_millis(50), Duration::from_secs(1));
        tokio::time::timeout(grace, self.t.closed()).await.is_ok()
    }

    /// The first cause of the session's end, kept for its summary.
    fn note_end(&self, how: impl Into<String>) {
        self.ended_by
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(|| how.into());
    }

    /// One line for the session's whole life: who it was, how far setup
    /// got, what it asked for, and how it ended.
    fn summary(&self) -> String {
        let implementation = self
            .peer_setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|s| {
                s.implementation.as_deref().map_or_else(
                    || "SETUP received".to_string(),
                    |i| format!("SETUP from {i}"),
                )
            });
        let setup = match (self.setup_sent.load(Ordering::Acquire), implementation) {
            (true, Some(peer)) => format!("SETUP sent, {peer}"),
            (true, None) => "SETUP sent, none received".to_string(),
            (false, Some(peer)) => format!("no SETUP sent, {peer}"),
            (false, None) => "no SETUP either way".to_string(),
        };
        let requests: Vec<String> = message::REQUEST_TYPES
            .iter()
            .zip(&self.requests)
            .filter_map(|(kind, n)| {
                let n = n.load(Ordering::Relaxed);
                (n > 0).then(|| format!("{} {n}", message::request_name(*kind)))
            })
            .collect();
        let ended_by = self
            .ended_by
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_else(|| "its transport closed".to_string());
        format!(
            "MoQ session {} from {} ({} {}) ended after {:.1} s: {}; {}; {}",
            self.id,
            self.t.peer(),
            self.t.kind(),
            self.version,
            self.started.elapsed().as_secs_f64(),
            setup,
            if requests.is_empty() {
                "no requests".to_string()
            } else {
                requests.join(", ")
            },
            ended_by
        )
    }

    /// Close the session with a session error (section 6.6).
    fn fail(&self, e: &SessionError) {
        info!(
            "MoQ session {} from {}: closing with {}",
            self.id,
            self.t.peer(),
            e
        );
        self.note_end(format!("the relay closed it with {e}"));
        self.relay
            .stats
            .session_errors
            .fetch_add(1, Ordering::Relaxed);
        self.t.close(e.code.code(self.version), e.reason);
        self.closing.cancel();
    }

    async fn send_setup(&self) -> Result<(), SessionError> {
        // A client names the URI's authority and path (sections 9.1.1, 9.1.2)
        let (authority, path) = if self.role == Role::Client {
            (
                self.authority.clone().map(Bytes::from),
                self.path
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .map(Bytes::from),
            )
        } else {
            (None, None)
        };
        let setup = Setup {
            path,
            authority,
            implementation: Some(self.settings.implementation.clone()),
            max_request_updates: self.settings.max_request_updates,
            max_filter_ranges: self.settings.max_filter_ranges,
            max_auth_token_cache_size: self.settings.max_auth_token_cache,
            max_control_message_size: self.settings.max_control_message,
            ..Setup::default()
        };
        let mut send = self.t.open_uni().await.map_err(|_| {
            SessionError::new(C::InternalError, "could not open the control stream")
        })?;
        send.set_priority(i32::MAX);
        send.write_all(&Message::Setup(setup).encode(self.version))
            .await
            .map_err(|_| SessionError::new(C::InternalError, "could not write SETUP"))?;
        *self.control.lock().await = Some(send);
        Ok(())
    }

    /// Send GOAWAY on the control stream; new requests are then refused
    /// with GOING_AWAY.
    pub async fn goaway(&self) {
        if self.goaway_sent.swap(true, Ordering::AcqRel) {
            return;
        }
        let timeout_ms =
            u64::try_from(self.settings.goaway_timeout.as_millis()).unwrap_or(u64::MAX);
        let m = Message::Goaway {
            uri: Bytes::new(),
            timeout_ms,
        };
        if let Some(send) = self.control.lock().await.as_mut() {
            let _ = send.write_all(&m.encode(self.version)).await;
        }
    }

    async fn setup_complete(&self) -> bool {
        let mut done = self.setup_done.subscribe();
        tokio::select! {
            r = done.wait_for(|d| *d) => r.is_ok(),
            () = self.closing.cancelled() => false,
        }
    }

    fn peer_is_client(&self) -> bool {
        self.role == Role::Server
    }

    // ── Unidirectional streams ──────────────────────────────────────────────

    async fn accept_uni_loop(self: Arc<Self>) -> Result<(), SessionError> {
        let control_seen = Arc::new(AtomicBool::new(false));
        loop {
            let Ok(recv) = self.t.accept_uni().await else {
                return Ok(());
            };
            let me = Arc::clone(&self);
            let control_seen = Arc::clone(&control_seen);
            tokio::spawn(async move {
                if let Err(e) = Arc::clone(&me).uni_stream(recv, &control_seen).await {
                    me.fail(&e);
                }
            });
        }
    }

    async fn uni_stream(
        self: Arc<Self>,
        recv: T::Recv,
        control_seen: &AtomicBool,
    ) -> Result<(), SessionError> {
        let mut r = BufReader::new(recv);
        let kind = match tokio::time::timeout(SETUP_TIMEOUT, read_vi64(&mut r)).await {
            Ok(Ok(Some(k))) => k,
            Ok(_) => return Ok(()),
            Err(_) => {
                r.get_mut().stop(ResetCode::Cancelled as u32);
                return Ok(());
            }
        };
        if kind == message::SETUP {
            if control_seen.swap(true, Ordering::AcqRel) {
                return Err(SessionError::new(
                    C::UnexpectedMessage,
                    "a second control stream",
                ));
            }
            return self.control_stream(r).await;
        }
        if !self.setup_complete().await {
            return Ok(());
        }
        if kind == data::STREAM_PADDING {
            let mut sink = tokio::io::sink();
            let _ = tokio::io::copy(&mut r, &mut sink).await;
            return Ok(());
        }
        if kind == data::STREAM_FETCH_HEADER {
            return self.fetch_stream_in(r).await;
        }
        if data::is_subgroup_type(kind) {
            return self.subgroup_stream_in(kind, r).await;
        }
        Err(SessionError::new(
            C::InvalidStreamHeader,
            "an unknown unidirectional stream type",
        ))
    }

    /// The peer's control stream: SETUP (its type already read), then GOAWAY.
    async fn control_stream(&self, mut r: BufReader<T::Recv>) -> Result<(), SessionError> {
        // The rest of SETUP: its length and options, under the default limit
        // until the peer's own is known (section 9.1.8)
        let len = if self.version.varint_message_length() {
            read_vi64(&mut r)
                .await
                .ok()
                .flatten()
                .ok_or(SessionError::new(
                    C::ClosedControlStream,
                    "the control stream ended in SETUP",
                ))?
        } else {
            let mut b = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut r, &mut b)
                .await
                .map_err(|_| {
                    SessionError::new(C::ClosedControlStream, "the control stream ended in SETUP")
                })?;
            u64::from(u16::from_be_bytes(b))
        };
        if len > message::DEFAULT_MAX_CONTROL_MESSAGE {
            return Err(SessionError::new(
                C::FieldLengthExceeded,
                "SETUP longer than 65535 bytes",
            ));
        }
        let mut body = vec![0u8; usize::try_from(len).unwrap_or(0)];
        tokio::io::AsyncReadExt::read_exact(&mut r, &mut body)
            .await
            .map_err(|_| {
                SessionError::new(C::ClosedControlStream, "the control stream ended in SETUP")
            })?;
        let setup = Setup::decode(&body, self.version)?;
        self.check_setup(&setup)?;
        *self
            .peer_setup
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(setup);
        self.relay.update_session(self.info());
        let _ = self.setup_done.send(true);

        let limit = self.settings.max_control_message;
        let mut goaways = 0u32;
        loop {
            let frame = read_frame(&mut r, self.version, limit).await;
            match frame {
                Ok(Some((message::GOAWAY, body))) => {
                    let Message::Goaway { uri, .. } =
                        Message::decode(message::GOAWAY, &body, self.version, &Context::default())?
                    else {
                        unreachable!()
                    };
                    goaways += 1;
                    if goaways > 1 {
                        return Err(SessionError::new(C::UnexpectedMessage, "a second GOAWAY"));
                    }
                    if self.peer_is_client() && !uri.is_empty() {
                        return Err(SessionError::new(
                            C::RoleViolation,
                            "a client's GOAWAY with a New Session URI",
                        ));
                    }
                    self.goaway_received.store(true, Ordering::Release);
                }
                Ok(Some(_)) => {
                    return Err(SessionError::new(
                        C::UnexpectedMessage,
                        "a message other than GOAWAY on the control stream",
                    ));
                }
                Ok(None) | Err(FrameError::Io(_)) => {
                    if self.closing.is_cancelled() || self.ends_within_a_round_trip().await {
                        return Ok(());
                    }
                    return Err(SessionError::new(
                        C::ClosedControlStream,
                        "the peer closed its control stream",
                    ));
                }
                Err(FrameError::Session(e)) => return Err(e),
            }
        }
    }

    /// The checks on the peer's SETUP (sections 9.1.1, 9.1.2, 9.1.4).
    fn check_setup(&self, s: &Setup) -> Result<(), SessionError> {
        let webtransport = self.t.kind() == "webtransport";
        if let Some(p) = &s.path {
            if !self.peer_is_client() || webtransport {
                return Err(SessionError::new(
                    C::InvalidPath,
                    "PATH from a server, or on WebTransport",
                ));
            }
            let text = std::str::from_utf8(p)
                .map_err(|_| SessionError::new(C::MalformedPath, "PATH is not UTF-8"))?;
            if !(text.is_empty() || text.starts_with('/'))
                || text.chars().any(|c| c.is_control() || c == ' ' || c == '#')
            {
                return Err(SessionError::new(
                    C::MalformedPath,
                    "PATH is not path-abempty [? query]",
                ));
            }
            let path_only = text.split('?').next().unwrap_or("");
            if !self.settings.paths.iter().any(|ok| ok == path_only) {
                return Err(SessionError::new(
                    C::InvalidPath,
                    "this relay does not serve that PATH",
                ));
            }
            *self
                .path
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(text.to_string());
        }
        if let Some(a) = &s.authority {
            if !self.peer_is_client() || webtransport {
                return Err(SessionError::new(
                    C::InvalidAuthority,
                    "AUTHORITY from a server, or on WebTransport",
                ));
            }
            let text = std::str::from_utf8(a)
                .map_err(|_| SessionError::new(C::MalformedAuthority, "AUTHORITY is not UTF-8"))?;
            if text.is_empty() || text.contains(['/', '?', '#', '@', ' ']) {
                return Err(SessionError::new(
                    C::MalformedAuthority,
                    "AUTHORITY is not host[:port]",
                ));
            }
            let host = authority_host(text).ok_or(SessionError::new(
                C::MalformedAuthority,
                "AUTHORITY is not host[:port]",
            ))?;
            if !self.settings.authorities.is_empty()
                && !self
                    .settings
                    .authorities
                    .iter()
                    .any(|ok| ok.eq_ignore_ascii_case(&host))
            {
                return Err(SessionError::new(
                    C::InvalidAuthority,
                    "this relay does not serve that AUTHORITY",
                ));
            }
        }
        let values = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .apply(&s.auth_tokens, true, self.peer_is_client())
            .map_err(|code| SessionError::new(code, "an AUTHORIZATION_TOKEN in SETUP"))?;
        *self
            .setup_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = values;
        Ok(())
    }

    /// Wait briefly for a Track Alias the control messages have not yet
    /// established (section 3.1.3.1).
    async fn alias_track(&self, alias: u64) -> Option<Arc<Track>> {
        let deadline = tokio::time::Instant::now() + UNKNOWN_ALIAS_WAIT;
        loop {
            let notified = self.alias_added.notified();
            if let Some(t) = self
                .aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&alias)
            {
                return Some(Arc::clone(t));
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return None;
            }
        }
    }

    /// Objects a publisher sends on a subgroup stream.
    async fn subgroup_stream_in(
        &self,
        flags: u64,
        mut r: BufReader<T::Recv>,
    ) -> Result<(), SessionError> {
        let header = match SubgroupHeader::read(flags, &mut r).await {
            Ok(h) => h,
            Err(DataError::Session(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        let Some(track) = self.alias_track(header.track_alias).await else {
            r.get_mut().stop(ResetCode::Cancelled as u32);
            return Ok(());
        };
        let stream_id = (self.id << 32) | self.upstream_streams.fetch_add(1, Ordering::Relaxed);
        let priority = header.priority.unwrap_or_else(|| track.default_priority());
        let mut prior: Option<u64> = None;
        let mut subgroup = match header.subgroup {
            SubgroupIdMode::Zero => Some(0),
            SubgroupIdMode::Explicit(id) => Some(id),
            SubgroupIdMode::FirstObjectId => None,
        };
        let max = self.relay.limits.max_object;
        loop {
            match data::read_subgroup_object(&mut r, &header, prior, max).await {
                Ok(Some((id, status, properties, payload))) => {
                    let sub = *subgroup.get_or_insert(id);
                    let first = prior.is_none() && header.first_object;
                    prior = Some(id);
                    self.relay.ingest(
                        &track,
                        Object {
                            location: Location::new(header.group, id),
                            delivery: Delivery::Subgroup(sub),
                            priority,
                            status,
                            properties,
                            payload,
                        },
                        Some(stream_id),
                        first,
                        header.end_of_group,
                    );
                }
                Ok(None) => {
                    if let (true, Some(last)) = (header.end_of_group, prior) {
                        track.note_group_end(header.group, last);
                    }
                    self.relay.subgroup_ended(
                        &track,
                        stream_id,
                        header.group,
                        subgroup.unwrap_or(0),
                        true,
                    );
                    return Ok(());
                }
                Err(DataError::Session(e)) => {
                    // The object is not forwarded to anyone (section 7.7)
                    self.relay.subgroup_ended(
                        &track,
                        stream_id,
                        header.group,
                        subgroup.unwrap_or(0),
                        false,
                    );
                    return Err(e);
                }
                Err(DataError::TooLarge) => {
                    r.get_mut().stop(ResetCode::ExcessiveLoad as u32);
                    self.relay.subgroup_ended(
                        &track,
                        stream_id,
                        header.group,
                        subgroup.unwrap_or(0),
                        false,
                    );
                    return Ok(());
                }
                Err(DataError::Io(_)) => {
                    self.relay.subgroup_ended(
                        &track,
                        stream_id,
                        header.group,
                        subgroup.unwrap_or(0),
                        false,
                    );
                    return Ok(());
                }
            }
        }
    }

    /// A FETCH response the relay asked a publisher for.
    async fn fetch_stream_in(&self, mut r: BufReader<T::Recv>) -> Result<(), SessionError> {
        let Ok(Some(request_id)) = read_vi64(&mut r).await else {
            return Ok(());
        };
        let sink = self
            .fetches_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        let Some(sink) = sink else {
            r.get_mut().stop(ResetCode::Cancelled as u32);
            return Ok(());
        };
        let mut state = FetchState::default();
        loop {
            match state
                .read(
                    &mut r,
                    sink.order,
                    self.version,
                    self.relay.limits.max_object,
                )
                .await
            {
                Ok(Some(entry)) => {
                    if sink.tx.send(entry).await.is_err() {
                        r.get_mut().stop(ResetCode::Cancelled as u32);
                        return Ok(());
                    }
                }
                Ok(None) => return Ok(()),
                Err(DataError::Session(e)) => return Err(e),
                Err(_) => return Ok(()),
            }
        }
    }

    async fn datagram_loop(self: Arc<Self>) -> Result<(), SessionError> {
        loop {
            let Ok(d) = self.t.recv_datagram().await else {
                return Ok(());
            };
            if !*self.setup_done.borrow() {
                continue; // before SETUP: dropped (section 6.3)
            }
            let d = match decode_datagram(&d)? {
                DatagramKind::Padding => continue,
                DatagramKind::Object(d) => d,
            };
            let track = self
                .aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&d.track_alias)
                .cloned();
            let Some(track) = track else { continue };
            if d.payload.len() > self.relay.limits.max_object {
                continue;
            }
            if d.end_of_group {
                track.note_group_end(d.group, d.object);
            }
            let priority = d.priority.unwrap_or_else(|| track.default_priority());
            self.relay.ingest(
                &track,
                Object {
                    location: Location::new(d.group, d.object),
                    delivery: Delivery::Datagram,
                    priority,
                    status: d.status,
                    properties: d.properties,
                    payload: d.payload,
                },
                None,
                false,
                d.end_of_group,
            );
        }
    }

    // ── Requests from the peer ──────────────────────────────────────────────

    async fn accept_bi_loop(self: Arc<Self>) -> Result<(), SessionError> {
        loop {
            let Ok((send, recv)) = self.t.accept_bi().await else {
                return Ok(());
            };
            let me = Arc::clone(&self);
            tokio::spawn(async move {
                if !me.setup_complete().await {
                    return;
                }
                match me.clone().request(send, recv).await {
                    Ok(()) | Err(Abort::Gone) => {}
                    Err(Abort::Session(e)) => me.fail(&e),
                }
            });
        }
    }

    /// One request stream: its first message, its Request ID, then the
    /// request's own exchange.
    async fn request(self: Arc<Self>, send: T::Send, recv: T::Recv) -> Result<(), Abort> {
        let mut recv = BufReader::new(recv);
        let limit = self.settings.max_control_message;
        let Some((kind, body)) = read_frame(&mut recv, self.version, limit).await? else {
            return Ok(());
        };
        let Some(slot) = message::REQUEST_TYPES.iter().position(|k| *k == kind) else {
            return Err(SessionError::new(
                C::UnexpectedMessage,
                "a request stream that begins with no request",
            )
            .into());
        };
        self.requests[slot].fetch_add(1, Ordering::Relaxed);
        let msg = Message::decode(kind, &body, self.version, &Context::default())?;
        let request_id = match &msg {
            Message::Subscribe(r) | Message::Fetch(r) | Message::TrackStatus(r) => r.request_id,
            Message::PublishNamespace(r)
            | Message::SubscribeNamespace(r)
            | Message::SubscribeTracks(r) => r.request_id,
            Message::Publish(p) => p.request_id,
            _ => unreachable!("checked above"),
        };
        let parity = u64::from(!self.peer_is_client());
        if request_id % 2 != parity {
            return Err(
                SessionError::new(C::InvalidRequestId, "a Request ID of the wrong parity").into(),
            );
        }
        if !self
            .peer_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(request_id)
        {
            return Err(SessionError::new(C::InvalidRequestId, "a Request ID used before").into());
        }
        let send: Shared<T::Send> = Arc::new(tokio::sync::Mutex::new(send));
        if !self.within_rate_limits(kind).await {
            return self
                .refuse(
                    &send,
                    RequestCode::ExcessiveLoad,
                    "over this address's rate limit",
                    1000,
                )
                .await;
        }
        if self.goaway_sent.load(Ordering::Acquire) {
            return self
                .refuse(
                    &send,
                    RequestCode::GoingAway,
                    "the relay is going away",
                    1000,
                )
                .await;
        }
        match msg {
            Message::Subscribe(r) => self.serve_subscribe(send, recv, r).await,
            Message::Fetch(r) => self.serve_fetch(send, recv, r).await,
            Message::TrackStatus(r) => self.serve_track_status(send, r).await,
            Message::PublishNamespace(r) => self.serve_publish_namespace(send, recv, r).await,
            Message::SubscribeNamespace(r) => self.serve_subscribe_namespace(send, recv, r).await,
            Message::SubscribeTracks(r) => self.serve_subscribe_tracks(send, recv, r).await,
            Message::Publish(p) => self.serve_publish(send, recv, p).await,
            _ => unreachable!("checked above"),
        }
    }

    /// Whether the peer's address is within the rate limits for one more
    /// request of type `kind`.
    async fn within_rate_limits(&self, kind: u64) -> bool {
        let Some(limiter) = self.settings.limiter.get() else {
            return true;
        };
        let context = crate::rate_limiter::RateLimitContext {
            source_ip: crate::security::canonical_addr(self.t.peer()).ip(),
            headers: HashMap::new(),
            path: self
                .path
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .unwrap_or_default(),
            method: format!("MOQT-{kind:#x}"),
            query_params: HashMap::new(),
            cookies: HashMap::new(),
            ja3_hash: None,
            ja4_hash: None,
            route_name: Some("moq".to_string()),
        };
        matches!(
            limiter.check(&context).await,
            crate::rate_limiter::RateLimitResult::Allowed { .. }
        )
    }

    async fn write(&self, send: &Shared<T::Send>, m: &Message) -> Result<(), Abort> {
        send.lock()
            .await
            .write_all(&m.encode(self.version))
            .await
            .map_err(|_| Abort::Gone)
    }

    /// REQUEST_ERROR and FIN (section 6.4.2.3).
    async fn refuse(
        &self,
        send: &Shared<T::Send>,
        code: RequestCode,
        reason: &str,
        retry_ms: u64,
    ) -> Result<(), Abort> {
        self.relay
            .stats
            .requests_refused
            .fetch_add(1, Ordering::Relaxed);
        let m = Message::RequestError(RequestError {
            code: code.code(self.version),
            retry_interval: retry_ms,
            reason: reason.into(),
            details: Vec::new(),
        });
        self.write(send, &m).await?;
        let _ = send.lock().await.shutdown().await;
        Ok(())
    }

    /// The token values a request's parameters and the session's SETUP give.
    fn tokens_for(&self, params: &Params) -> Result<Vec<Bytes>, Abort> {
        let mut values = self
            .tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .apply(&params.auth_tokens, false, self.peer_is_client())
            .map_err(|code| SessionError::new(code, "an AUTHORIZATION_TOKEN"))?;
        values.extend(
            self.setup_tokens
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .cloned(),
        );
        Ok(values)
    }

    /// The common refusals for a request naming `namespace` (sections 2.4.3,
    /// 6.5): the reserved `.` namespace, and session-level namespaces this
    /// relay defines none of.
    fn reserved(namespace: &Namespace) -> bool {
        matches!(namespace.first(), Some(b"." | b".session"))
    }

    /// Range Filter checks shared by SUBSCRIBE, FETCH and SUBSCRIBE_TRACKS
    /// (sections 3.3.2, 9.1.6).
    fn filter_refusal(&self, params: &Params) -> Option<&'static str> {
        if let Some(why) = params.filter_error {
            return Some(why);
        }
        if params.range_count() as u64 > self.settings.max_filter_ranges {
            return Some("more Ranges than MAX_FILTER_RANGES");
        }
        None
    }

    // ── SUBSCRIBE ───────────────────────────────────────────────────────────

    async fn serve_subscribe(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        r: TrackRequest,
    ) -> Result<(), Abort> {
        self.relay.stats.subscribes.fetch_add(1, Ordering::Relaxed);
        let _ = self.tokens_for(&r.params)?;
        if Self::reserved(&r.track.namespace) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        if let Some(why) = self.filter_refusal(&r.params) {
            return self.refuse(&send, RequestCode::InvalidFilter, why, 0).await;
        }
        let Some(track) = self.relay.track(&r.track) else {
            return self
                .refuse(&send, RequestCode::ExcessiveLoad, "too many tracks", 5000)
                .await;
        };
        // Counted as a subscriber from here, so a publisher that arrives
        // while this waits is subscribed upstream for it
        let events = track.subscribe();
        let guard = Unsubscribe(Arc::clone(&track));
        if let Err((code, reason)) = self
            .ensure_publisher(
                &track,
                r.params.rendezvous_timeout,
                r.params.new_group_request,
            )
            .await
        {
            return self.refuse(&send, code, &reason, 0).await;
        }
        if let Some(v) = r.params.new_group_request {
            track.request_new_group(v);
        }
        if self.unsupported_extension(&send, &track).await? {
            return Ok(());
        }
        let alias = self.next_alias.fetch_add(1, Ordering::Relaxed);
        let largest = track.largest();
        let ok = Message::SubscribeOk {
            track_alias: alias,
            params: Params {
                largest_object: largest,
                ..Params::default()
            },
            properties: if r.params.include_properties == Some(false) {
                Bytes::new()
            } else {
                track.properties()
            },
        };
        self.write(&send, &ok).await?;
        let state = SubState::from_params(&r.params, &track, largest);
        let (state_tx, state_rx) = watch::channel(state);
        let fill = r.params.fill.clone();
        let delivery = Delivery_ {
            session: Arc::clone(&self),
            track: Arc::clone(&track),
            alias,
            request_id: r.request_id,
            state: state_rx,
            streams_opened: Arc::new(AtomicU64::new(0)),
        };
        if let Some(fill) = fill {
            if !state_tx.borrow().paused {
                delivery.spawn_fill(&r.params, &fill);
            }
        }
        let update_ctx = Context {
            update_allows: allowed::update_subscription(),
            ..Context::default()
        };
        let updates = self.clone().subscription_updates(
            Arc::clone(&send),
            &mut recv,
            update_ctx,
            state_tx,
            delivery.clone_for_fill(&r.params),
        );
        let outcome = tokio::select! {
            outcome = delivery.run(events) => outcome,
            r = updates => match r {
                Err(Abort::Session(e)) => return Err(Abort::Session(e)),
                // The subscriber cancelled: STOP_SENDING or a reset
                _ => Outcome::Cancelled,
            },
            () = self.closing.cancelled() => Outcome::Cancelled,
        };
        drop(guard);
        match outcome {
            Outcome::Cancelled => {
                let mut s = send.lock().await;
                s.reset(ResetCode::Cancelled as u32);
                recv.get_mut().stop(ResetCode::Cancelled as u32);
                Ok(())
            }
            Outcome::Done {
                code,
                reason,
                streams,
            } => {
                let m = Message::PublishDone {
                    status: code.code(self.version),
                    stream_count: streams,
                    reason,
                };
                self.write(&send, &m).await?;
                let _ = send.lock().await.shutdown().await;
                Ok(())
            }
        }
    }

    /// REQUEST_UPDATEs on a subscription, each answered in order (section
    /// 9.5); returns when the subscriber's direction ends.
    async fn subscription_updates(
        self: Arc<Self>,
        send: Shared<T::Send>,
        recv: &mut BufReader<T::Recv>,
        ctx: Context,
        state: watch::Sender<SubState>,
        fills: FillSpawner<T>,
    ) -> Result<(), Abort> {
        let limit = self.settings.max_control_message;
        loop {
            let frame = match read_frame(recv, self.version, limit).await {
                Ok(Some(f)) => f,
                // A FIN only ends the subscriber's direction (6.4.2.2):
                // delivery goes on until the stream is stopped
                Ok(None) => {
                    let mut s = send.lock().await;
                    let _ = futures_util::future::poll_fn(|cx| {
                        std::pin::Pin::new(&mut *s).poll_flush(cx)
                    })
                    .await;
                    drop(s);
                    std::future::pending::<()>().await;
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            };
            match frame.0 {
                message::REQUEST_UPDATE => {
                    let Message::RequestUpdate { request_id, params } =
                        Message::decode(frame.0, &frame.1, self.version, &ctx)?
                    else {
                        unreachable!()
                    };
                    self.check_update_id(request_id)?;
                    let _ = self.tokens_for(&params)?;
                    if let Some(why) = self.filter_refusal(&params) {
                        self.write(
                            &send,
                            &update_error(self.version, RequestCode::InvalidFilter, why),
                        )
                        .await?;
                        // A failed update ends the subscription (9.5.1)
                        state.send_modify(|s| s.failed = true);
                        return Ok(());
                    }
                    if let Some(v) = params.new_group_request {
                        if fills.track.has_publisher()
                            && !fills.track.dynamic_groups()
                            && fills.track.largest().is_some()
                        {
                            // A subscriber MUST NOT send it for a track
                            // without DYNAMIC_GROUPS; the publisher ignores it
                        } else {
                            fills.track.request_new_group(v);
                        }
                    }
                    let was_paused = state.borrow().paused;
                    state.send_modify(|s| s.update(&params, &fills.track));
                    let now_paused = state.borrow().paused;
                    if let Some(fill) = &params.fill {
                        if !now_paused {
                            fills.spawn_update_fill(request_id, fill, &state.borrow());
                        }
                    }
                    let _ = was_paused;
                    let ok = Message::RequestOk {
                        params: Params {
                            largest_object: fills.track.largest(),
                            ..Params::default()
                        },
                        properties: Bytes::new(),
                    };
                    self.write(&send, &ok).await?;
                }
                message::GOAWAY => {
                    return Err(SessionError::new(
                        C::ProtocolViolation,
                        "GOAWAY from the sender of a request",
                    )
                    .into());
                }
                _ => {
                    return Err(SessionError::new(
                        C::UnexpectedMessage,
                        "an unexpected message on a subscription",
                    )
                    .into())
                }
            }
        }
    }

    /// A REQUEST_UPDATE consumes a Request ID of the requester's parity.
    fn check_update_id(&self, request_id: u64) -> Result<(), Abort> {
        let parity = u64::from(!self.peer_is_client());
        if request_id % 2 != parity
            || !self
                .peer_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(request_id)
        {
            return Err(
                SessionError::new(C::InvalidRequestId, "a REQUEST_UPDATE's Request ID").into(),
            );
        }
        Ok(())
    }

    /// REQUEST_ERROR UNSUPPORTED_EXTENSION for a track with a Mandatory
    /// Track Property this relay does not understand (sections 3.7, 9.4.2.2).
    async fn unsupported_extension(
        &self,
        send: &Shared<T::Send>,
        track: &Track,
    ) -> Result<bool, Abort> {
        let unsupported = match track.set_properties(track.properties()) {
            Ok(u) => u,
            Err(_) => return Ok(false),
        };
        if unsupported.is_empty() {
            return Ok(false);
        }
        let details = unsupported
            .iter()
            .map(|t| super::codec::Kvp {
                kind: 0x02,
                value: super::codec::KvpValue::Int(*t),
            })
            .collect();
        let m = Message::RequestError(RequestError {
            code: RequestCode::UnsupportedExtension.code(self.version),
            retry_interval: 0,
            reason: "a Mandatory Track Property this relay does not understand".into(),
            details,
        });
        self.write(send, &m).await?;
        let _ = send.lock().await.shutdown().await;
        Ok(true)
    }

    /// Make sure the track has an established upstream: a publisher that
    /// sent PUBLISH, a subscription upstream through each publisher that
    /// advertised its namespace (section 7.7), or a publisher that arrives
    /// within the rendezvous time (section 9.19.6).
    async fn ensure_publisher(
        &self,
        track: &Arc<Track>,
        rendezvous_ms: Option<u64>,
        new_group: Option<u64>,
    ) -> Result<(), (RequestCode, String)> {
        if track.has_publisher() {
            return Ok(());
        }
        let ads = self.relay.publishers_for(&track.name.namespace);
        if !ads.is_empty() {
            // Through every publisher of the namespace at once, going on at
            // the first that answers: a publisher that went without closing
            // (a restarted one, still advertised until its idle timeout) held
            // every request for the track until it was given up on
            let mut attempts: futures_util::stream::FuturesUnordered<_> = ads
                .iter()
                .map(|ad| {
                    ad.publisher
                        .subscribe_upstream(Arc::clone(track), new_group)
                })
                .collect();
            let mut refused = None;
            while let Some(r) = attempts.next().await {
                match r {
                    Ok(()) => {
                        // The others finish on their own: one dropped part
                        // way would leave its SUBSCRIBE unanswered upstream
                        if !attempts.is_empty() {
                            tokio::spawn(async move { while attempts.next().await.is_some() {} });
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        refused.get_or_insert(e);
                    }
                }
            }
            if track.has_publisher() {
                return Ok(());
            }
            let (code, reason) = refused.unwrap_or((0x10, String::new()));
            let code = match code {
                0x1 => RequestCode::Unauthorized,
                0x2 => RequestCode::Timeout,
                _ => RequestCode::DoesNotExist,
            };
            return Err((code, format!("the publisher refused: {reason}")));
        }
        let wait =
            Duration::from_millis(rendezvous_ms.unwrap_or(0)).min(self.relay.limits.rendezvous_max);
        if wait.is_zero() {
            return Err((
                RequestCode::DoesNotExist,
                "no publisher for this track".into(),
            ));
        }
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let arrived = track.publisher_arrived.notified();
            if track.has_publisher() {
                return Ok(());
            }
            if tokio::time::timeout_at(deadline, arrived).await.is_err() {
                return Err((RequestCode::Timeout, "no publisher arrived in time".into()));
            }
        }
    }

    // ── FETCH ───────────────────────────────────────────────────────────────

    async fn serve_fetch(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        r: TrackRequest,
    ) -> Result<(), Abort> {
        self.relay.stats.fetches.fetch_add(1, Ordering::Relaxed);
        let _ = self.tokens_for(&r.params)?;
        if Self::reserved(&r.track.namespace) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        if let Some(why) = self.filter_refusal(&r.params) {
            return self.refuse(&send, RequestCode::InvalidFilter, why, 0).await;
        }
        let filter = r.params.location_filter.unwrap_or(LocationFilter::None);
        if filter.is_relative() {
            return self
                .refuse(
                    &send,
                    RequestCode::InvalidRange,
                    "a relative Location Filter in FETCH",
                    0,
                )
                .await;
        }
        let track = match self.relay.existing(&r.track) {
            Some(t) => t,
            None => {
                if self.relay.publishers_for(&r.track.namespace).is_empty() {
                    return self
                        .refuse(&send, RequestCode::DoesNotExist, "no such track", 0)
                        .await;
                }
                let Some(t) = self.relay.track(&r.track) else {
                    return self
                        .refuse(&send, RequestCode::ExcessiveLoad, "too many tracks", 5000)
                        .await;
                };
                t
            }
        };
        if track.is_malformed() {
            return self
                .refuse(
                    &send,
                    RequestCode::MalformedTrack,
                    "the track is malformed",
                    0,
                )
                .await;
        }
        if track.largest().is_none() && !track.has_publisher() {
            // Learn the track's state through a publisher that advertised it
            let _guard = Unsubscribe(Arc::clone(&track));
            let _events = track.subscribe();
            let _ = self.ensure_publisher(&track, Some(0), None).await;
        }
        let Some(largest) = track.largest() else {
            return self
                .refuse(
                    &send,
                    RequestCode::InvalidRange,
                    "no objects published in this track",
                    0,
                )
                .await;
        };
        let (start, end) = filter.bounds(Some(largest));
        let end = end.unwrap_or(largest);
        if start > largest || start > end {
            return self
                .refuse(
                    &send,
                    RequestCode::InvalidRange,
                    "the range starts after Largest Object",
                    0,
                )
                .await;
        }
        let largest_in_range = end >= largest;
        let end = end.min(largest);
        let order = r.params.group_order.unwrap_or(GroupOrder::Ascending);
        let include = r.params.include_properties != Some(false);
        let ok = if self.version.fetch_ok_is_request_ok() {
            Message::RequestOk {
                params: Params {
                    largest_object: largest_in_range.then_some(largest),
                    ..Params::default()
                },
                properties: if include {
                    track.properties()
                } else {
                    Bytes::new()
                },
            }
        } else {
            Message::FetchOk22 {
                end_of_track: track.end_of_track().is_some_and(|e| e <= end),
                end,
                params: Params::default(),
                properties: if include {
                    track.properties()
                } else {
                    Bytes::new()
                },
            }
        };
        self.write(&send, &ok).await?;
        let _ = send.lock().await.shutdown().await;
        let fill_timeout = r.params.fill_timeout.map(Duration::from_millis);
        let priority = r.params.subscriber_priority.unwrap_or(128);
        let me = Arc::clone(&self);
        let filters = r.params.range_filters.clone();
        let serve = me.fetch_response(
            r.request_id,
            track,
            start,
            end,
            order,
            fill_timeout,
            priority,
            filters,
        );
        // The requester cancels with STOP_SENDING on the request stream
        // (section 3.2.4); its FIN only ends its direction
        let cancelled = async {
            let mut buf = [0u8; 64];
            loop {
                match tokio::io::AsyncReadExt::read(&mut recv, &mut buf).await {
                    Ok(0) => std::future::pending::<()>().await,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
        };
        tokio::select! {
            () = serve => {}
            () = cancelled => {}
        }
        Ok(())
    }

    /// The FETCH data stream (section 11.4): cached objects in the requested
    /// group order, gaps marked, missing objects fetched upstream within the
    /// fill timeout first (section 3.2.3).
    #[allow(clippy::too_many_arguments)]
    async fn fetch_response(
        self: Arc<Self>,
        request_id: u64,
        track: Arc<Track>,
        start: Location,
        end: Location,
        order: GroupOrder,
        fill_timeout: Option<Duration>,
        priority: u8,
        filters: Vec<RangeFilter>,
    ) {
        let Ok(mut out) = self.t.open_uni().await else {
            return;
        };
        out.set_priority(stream_priority(priority, 128, 0, order));
        let mut header = Vec::new();
        super::codec::put_vi64(&mut header, data::STREAM_FETCH_HEADER);
        super::codec::put_vi64(&mut header, request_id);
        if out.write_all(&header).await.is_err() {
            return;
        }
        let budget = fill_timeout
            .unwrap_or(self.relay.limits.fill_timeout)
            .min(self.relay.limits.fill_timeout);
        let covered = fill_from_upstream(&self.relay, &track, start, end, budget).await;
        let entries = plan_fetch(&track, start, end, order, &covered, &filters, self.version);
        let mut state = FetchState::default();
        let mut buf = Vec::new();
        for e in &entries {
            state.encode(&mut buf, e, order, self.version);
            if let FetchEntry::Object(o) = e {
                self.relay.stats.objects_out.fetch_add(1, Ordering::Relaxed);
                self.relay
                    .stats
                    .bytes_out
                    .fetch_add(o.payload.len() as u64, Ordering::Relaxed);
                self.relay.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            if buf.len() >= 64 * 1024 {
                if out.write_all(&buf).await.is_err() {
                    return;
                }
                buf.clear();
            }
        }
        if out.write_all(&buf).await.is_ok() {
            let _ = out.shutdown().await;
        }
    }

    // ── TRACK_STATUS ────────────────────────────────────────────────────────

    async fn serve_track_status(
        self: Arc<Self>,
        send: Shared<T::Send>,
        r: TrackRequest,
    ) -> Result<(), Abort> {
        let _ = self.tokens_for(&r.params)?;
        if Self::reserved(&r.track.namespace) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        let track = match self.relay.existing(&r.track) {
            Some(t) if t.has_publisher() || t.largest().is_some() => t,
            _ => {
                if self.relay.publishers_for(&r.track.namespace).is_empty() {
                    return self
                        .refuse(&send, RequestCode::DoesNotExist, "no such track", 0)
                        .await;
                }
                let Some(t) = self.relay.track(&r.track) else {
                    return self
                        .refuse(&send, RequestCode::ExcessiveLoad, "too many tracks", 5000)
                        .await;
                };
                let events = t.subscribe();
                let guard = Unsubscribe(Arc::clone(&t));
                let found = self.ensure_publisher(&t, Some(0), None).await;
                drop(events);
                drop(guard);
                if let Err((code, reason)) = found {
                    return self.refuse(&send, code, &reason, 0).await;
                }
                t
            }
        };
        if self.unsupported_extension(&send, &track).await? {
            return Ok(());
        }
        let ok = Message::RequestOk {
            params: Params {
                largest_object: track.largest(),
                ..Params::default()
            },
            properties: if r.params.include_properties == Some(false) {
                Bytes::new()
            } else {
                track.properties()
            },
        };
        self.write(&send, &ok).await?;
        let _ = send.lock().await.shutdown().await;
        Ok(())
    }

    // ── Publishing into the relay ───────────────────────────────────────────

    fn publish_allowed(&self, tokens: &[Bytes], namespace: &Namespace) -> Result<(), RequestCode> {
        match &self.settings.publish_auth {
            None => Err(RequestCode::Unauthorized),
            Some(auth) => auth.authorize(tokens, namespace).map_err(|r| r.code()),
        }
    }

    async fn serve_publish(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        p: Publish,
    ) -> Result<(), Abort> {
        let tokens = self.tokens_for(&p.params)?;
        if Self::reserved(&p.track.namespace) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        if let Err(code) = self.publish_allowed(&tokens, &p.track.namespace) {
            return self
                .refuse(&send, code, "not authorized to publish this track", 0)
                .await;
        }
        {
            let aliases = self
                .aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if aliases
                .get(&p.track_alias)
                .is_some_and(|t| t.name != p.track)
            {
                return Err(SessionError::new(
                    C::DuplicateTrackAlias,
                    "a Track Alias already in use",
                )
                .into());
            }
        }
        let Some(track) = self.relay.track(&p.track) else {
            return self
                .refuse(&send, RequestCode::ExcessiveLoad, "too many tracks", 5000)
                .await;
        };
        match track.set_properties(p.properties.clone()) {
            Ok(unsupported) if !unsupported.is_empty() => {
                let details = unsupported
                    .iter()
                    .map(|t| super::codec::Kvp {
                        kind: 0x02,
                        value: super::codec::KvpValue::Int(*t),
                    })
                    .collect();
                let m = Message::RequestError(RequestError {
                    code: RequestCode::UnsupportedExtension.code(self.version),
                    retry_interval: 0,
                    reason: "a Mandatory Track Property this relay does not understand".into(),
                    details,
                });
                self.write(&send, &m).await?;
                let _ = send.lock().await.shutdown().await;
                return Ok(());
            }
            Ok(_) => {}
            Err(code) => return Err(SessionError::new(code, "PUBLISH's Track Properties").into()),
        }
        if let Some(l) = p.params.largest_object {
            track.note_largest(l);
        }
        self.aliases_in
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(p.track_alias, Arc::clone(&track));
        self.alias_added.notify_waiters();
        let upstream: Arc<dyn Upstream> = Arc::new(SessionUpstream {
            session: Arc::downgrade(&self),
            id: self.id,
        });
        track.attach_publisher(Arc::clone(&upstream));
        self.relay.track_published(&track);
        // PUBLISH_OK: the relay keeps the subscription unpaused, so its cache
        // is warm for the first subscriber (section 7.2)
        self.write(
            &send,
            &Message::RequestOk {
                params: Params::default(),
                properties: Bytes::new(),
            },
        )
        .await?;
        let limit = self.settings.max_control_message;
        let ctx = Context::default();
        let end = loop {
            match read_frame(&mut recv, self.version, limit).await {
                Ok(Some((message::PUBLISH_DONE, body))) => {
                    let _ = Message::decode(message::PUBLISH_DONE, &body, self.version, &ctx)?;
                    break Ok(());
                }
                Ok(Some((message::PUBLISH_STATE_NOTIFY, body))) => {
                    if let Message::PublishStateNotify(params) =
                        Message::decode(message::PUBLISH_STATE_NOTIFY, &body, self.version, &ctx)?
                    {
                        if let Some(l) = params.largest_object {
                            track.note_largest(l);
                        }
                    }
                }
                Ok(Some((message::GOAWAY, _))) => {
                    break Err(Abort::Session(SessionError::new(
                        C::ProtocolViolation,
                        "GOAWAY from the sender of a request",
                    )));
                }
                Ok(Some(_)) => {
                    break Err(Abort::Session(SessionError::new(
                        C::UnexpectedMessage,
                        "an unexpected message on a PUBLISH",
                    )))
                }
                Ok(None) | Err(FrameError::Io(_)) => break Ok(()),
                Err(FrameError::Session(e)) => break Err(Abort::Session(e)),
            }
        };
        // Objects in flight may still arrive briefly after PUBLISH_DONE
        let me = Arc::clone(&self);
        let alias = p.track_alias;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            me.aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&alias);
            track.detach_publisher(me.id);
        });
        let _ = send.lock().await.shutdown().await;
        end
    }

    async fn serve_publish_namespace(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        r: PrefixRequest,
    ) -> Result<(), Abort> {
        let tokens = self.tokens_for(&r.params)?;
        if Self::reserved(&r.prefix) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        if let Err(code) = self.publish_allowed(&tokens, &r.prefix) {
            return self
                .refuse(&send, code, "not authorized to publish this namespace", 0)
                .await;
        }
        let id = self.relay.next_id();
        let publisher: Arc<dyn NamespacePublisher> = Arc::new(SessionUpstream {
            session: Arc::downgrade(&self),
            id: self.id,
        });
        self.write(
            &send,
            &Message::RequestOk {
                params: Params::default(),
                properties: Bytes::new(),
            },
        )
        .await?;
        self.relay.advertise(Advertisement {
            prefix: r.prefix.clone(),
            publisher,
            id,
        });
        let ctx = Context {
            update_allows: allowed::update_publish_namespace(),
            ..Context::default()
        };
        let limit = self.settings.max_control_message;
        let result = loop {
            match read_frame(&mut recv, self.version, limit).await {
                Ok(Some((message::REQUEST_UPDATE, body))) => {
                    let Message::RequestUpdate { request_id, params } =
                        Message::decode(message::REQUEST_UPDATE, &body, self.version, &ctx)?
                    else {
                        unreachable!()
                    };
                    self.check_update_id(request_id)?;
                    let tokens = self.tokens_for(&params)?;
                    match self.publish_allowed(&tokens, &r.prefix) {
                        Ok(()) => {
                            self.write(
                                &send,
                                &Message::RequestOk {
                                    params: Params::default(),
                                    properties: Bytes::new(),
                                },
                            )
                            .await?;
                        }
                        Err(code) => {
                            // A failed update closes the request (9.5.1)
                            self.write(&send, &update_error(self.version, code, "not authorized"))
                                .await?;
                            break Ok(());
                        }
                    }
                }
                Ok(Some((message::GOAWAY, _))) => {
                    break Err(Abort::Session(SessionError::new(
                        C::ProtocolViolation,
                        "GOAWAY from the sender of a request",
                    )));
                }
                Ok(Some(_)) => {
                    break Err(Abort::Session(SessionError::new(
                        C::UnexpectedMessage,
                        "an unexpected message on a PUBLISH_NAMESPACE",
                    )))
                }
                // The publisher's FIN does not withdraw; a reset does
                Ok(None) => {
                    tokio::select! {
                        () = stream_stopped(&send) => break Ok(()),
                        () = self.closing.cancelled() => break Ok(()),
                    }
                }
                Err(FrameError::Io(_)) => break Ok(()),
                Err(FrameError::Session(e)) => break Err(Abort::Session(e)),
            }
        };
        self.relay.withdraw(id);
        let _ = send.lock().await.shutdown().await;
        result
    }

    // ── SUBSCRIBE_NAMESPACE ─────────────────────────────────────────────────

    async fn serve_subscribe_namespace(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        r: PrefixRequest,
    ) -> Result<(), Abort> {
        let _ = self.tokens_for(&r.params)?;
        if Self::reserved(&r.prefix) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        let Some((watch_id, now, mut events)) = self.relay.watch_namespaces(r.prefix.clone())
        else {
            return self
                .refuse(
                    &send,
                    RequestCode::NamespaceTooLarge,
                    "more namespaces than this relay enumerates",
                    0,
                )
                .await;
        };
        let _unwatch = OnDrop(Some({
            let relay = Arc::clone(&self.relay);
            move || relay.unwatch_namespaces(watch_id)
        }));
        self.write(
            &send,
            &Message::RequestOk {
                params: Params::default(),
                properties: Bytes::new(),
            },
        )
        .await?;
        let mut prefix = r.prefix.clone();
        let mut told: BTreeSet<Namespace> = BTreeSet::new();
        for ns in now {
            if prefix.is_prefix_of(&ns) && told.insert(ns.clone()) {
                self.write(
                    &send,
                    &Message::Namespace {
                        suffix: prefix.suffix_of(&ns),
                        params: Params::default(),
                    },
                )
                .await?;
            }
        }
        let ctx = Context {
            update_allows: allowed::update_subscribe_namespace(),
            ..Context::default()
        };
        let limit = self.settings.max_control_message;
        let mut recv_open = true;
        loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(NamespaceEvent::Added(ns)) => {
                        if prefix.is_prefix_of(&ns) && told.insert(ns.clone()) {
                            self.write(&send, &Message::Namespace { suffix: prefix.suffix_of(&ns), params: Params::default() }).await?;
                        }
                    }
                    Some(NamespaceEvent::Removed(ns)) => {
                        if told.remove(&ns) {
                            self.write(&send, &Message::NamespaceDone { suffix: prefix.suffix_of(&ns) }).await?;
                        }
                    }
                    None => return Ok(()),
                },
                frame = read_frame(&mut recv, self.version, limit), if recv_open => match frame {
                    Ok(Some((message::REQUEST_UPDATE, body))) => {
                        let Message::RequestUpdate { request_id, params } = Message::decode(message::REQUEST_UPDATE, &body, self.version, &ctx)? else { unreachable!() };
                        self.check_update_id(request_id)?;
                        let _ = self.tokens_for(&params)?;
                        if let Some(p) = params.track_namespace_prefix {
                            if Self::reserved(&p) {
                                self.write(&send, &update_error(self.version, RequestCode::DoesNotExist, "a reserved namespace")).await?;
                                let _ = send.lock().await.shutdown().await;
                                return Ok(());
                            }
                            prefix = p;
                            self.relay.update_namespace_watch(watch_id, prefix.clone());
                            // The OK implies NAMESPACE_DONE for every namespace
                            // that no longer matches (section 9.5.2)
                            told.retain(|ns| prefix.is_prefix_of(ns));
                            self.write(&send, &Message::RequestOk { params: Params::default(), properties: Bytes::new() }).await?;
                            for ns in self.relay.advertised_prefixes() {
                                if prefix.is_prefix_of(&ns) && told.insert(ns.clone()) {
                                    self.write(&send, &Message::Namespace { suffix: prefix.suffix_of(&ns), params: Params::default() }).await?;
                                }
                            }
                        } else {
                            self.write(&send, &Message::RequestOk { params: Params::default(), properties: Bytes::new() }).await?;
                        }
                    }
                    Ok(Some((message::GOAWAY, _))) => return Err(SessionError::new(C::ProtocolViolation, "GOAWAY from the sender of a request").into()),
                    Ok(Some(_)) => return Err(SessionError::new(C::UnexpectedMessage, "an unexpected message on a SUBSCRIBE_NAMESPACE").into()),
                    Ok(None) => recv_open = false,
                    Err(FrameError::Io(_)) => return Ok(()),
                    Err(FrameError::Session(e)) => return Err(e.into()),
                },
                () = stream_stopped(&send) => return Ok(()),
                () = self.closing.cancelled() => return Ok(()),
            }
        }
    }

    // ── SUBSCRIBE_TRACKS ────────────────────────────────────────────────────

    async fn serve_subscribe_tracks(
        self: Arc<Self>,
        send: Shared<T::Send>,
        mut recv: BufReader<T::Recv>,
        r: PrefixRequest,
    ) -> Result<(), Abort> {
        let _ = self.tokens_for(&r.params)?;
        if Self::reserved(&r.prefix) {
            return self
                .refuse(&send, RequestCode::DoesNotExist, "a reserved namespace", 0)
                .await;
        }
        if let Some(why) = self.filter_refusal(&r.params) {
            return self.refuse(&send, RequestCode::InvalidFilter, why, 0).await;
        }
        let (watch_id, now, mut arrivals) = self.relay.watch_tracks(r.prefix.clone());
        let _unwatch = OnDrop(Some({
            let relay = Arc::clone(&self.relay);
            move || relay.unwatch_tracks(watch_id)
        }));
        self.write(
            &send,
            &Message::RequestOk {
                params: Params::default(),
                properties: Bytes::new(),
            },
        )
        .await?;
        let mut template = r.params.clone();
        template.auth_tokens.clear(); // not copied into PUBLISH (9.19.2)
        let mut prefix = r.prefix.clone();
        let mut published: BTreeSet<TrackName> = BTreeSet::new();
        let ctx = Context {
            update_allows: allowed::update_subscribe_tracks(),
            ..Context::default()
        };
        let limit = self.settings.max_control_message;
        let mut recv_open = true;
        for t in now {
            self.offer_track(&send, &prefix, &template, r.request_id, t, &mut published)
                .await?;
        }
        loop {
            tokio::select! {
                t = arrivals.recv() => match t {
                    Some(arrived) => {
                        if prefix.is_prefix_of(&arrived.0.name.namespace) {
                            self.offer_track(&send, &prefix, &template, r.request_id, arrived.0, &mut published).await?;
                        }
                    }
                    None => return Ok(()),
                },
                frame = read_frame(&mut recv, self.version, limit), if recv_open => match frame {
                    Ok(Some((message::REQUEST_UPDATE, body))) => {
                        let Message::RequestUpdate { request_id, params } = Message::decode(message::REQUEST_UPDATE, &body, self.version, &ctx)? else { unreachable!() };
                        self.check_update_id(request_id)?;
                        let _ = self.tokens_for(&params)?;
                        if let Some(p) = params.track_namespace_prefix {
                            prefix = p;
                            self.relay.update_track_watch(watch_id, prefix.clone());
                        }
                        if let Some(paused) = params.paused {
                            template.paused = Some(paused);
                        }
                        if !params.range_filters.is_empty() {
                            template.range_filters.retain(|f| f.kind != message::P_TRACK_PROPERTY_FILTER);
                            template.range_filters.extend(params.range_filters.iter().filter(|f| f.kind == message::P_TRACK_PROPERTY_FILTER).cloned());
                        }
                        self.write(&send, &Message::RequestOk { params: Params::default(), properties: Bytes::new() }).await?;
                    }
                    Ok(Some((message::GOAWAY, _))) => return Err(SessionError::new(C::ProtocolViolation, "GOAWAY from the sender of a request").into()),
                    Ok(Some(_)) => return Err(SessionError::new(C::UnexpectedMessage, "an unexpected message on a SUBSCRIBE_TRACKS").into()),
                    Ok(None) => recv_open = false,
                    Err(FrameError::Io(_)) => return Ok(()),
                    Err(FrameError::Session(e)) => return Err(e.into()),
                },
                () = stream_stopped(&send) => return Ok(()),
                () = self.closing.cancelled() => return Ok(()),
            }
        }
    }

    /// Send the subscriber PUBLISH for one track of a SUBSCRIBE_TRACKS
    /// (section 7.7), or PUBLISH_SKIPPED past the per-request limit.
    async fn offer_track(
        self: &Arc<Self>,
        send: &Shared<T::Send>,
        prefix: &Namespace,
        template: &Params,
        subscribe_tracks_id: u64,
        track: Arc<Track>,
        published: &mut BTreeSet<TrackName>,
    ) -> Result<(), Abort> {
        if published.contains(&track.name) {
            return Ok(()); // never a second PUBLISH for a track (9.5.2)
        }
        if !track_property_filters_pass(&track, &template.range_filters) {
            return Ok(());
        }
        if published.len() >= TRACKS_PER_SUBSCRIBE_TRACKS {
            let m = Message::PublishSkipped {
                suffix: prefix.suffix_of(&track.name.namespace),
                name: track.name.name.clone(),
            };
            return self.write(send, &m).await;
        }
        published.insert(track.name.clone());
        let me = Arc::clone(self);
        let template = template.clone();
        tokio::spawn(async move {
            let _ = me
                .publish_downstream(track, template, subscribe_tracks_id)
                .await;
        });
        Ok(())
    }

    /// PUBLISH to the peer on a stream the relay opens, then deliver like a
    /// SUBSCRIBE once the peer accepts.
    async fn publish_downstream(
        self: Arc<Self>,
        track: Arc<Track>,
        template: Params,
        subscribe_tracks_id: u64,
    ) -> Result<(), Abort> {
        let (send, recv) = self.t.open_bi().await.map_err(|_| Abort::Gone)?;
        let send: Shared<T::Send> = Arc::new(tokio::sync::Mutex::new(send));
        let mut recv = BufReader::new(recv);
        let request_id = self.next_request_id.fetch_add(2, Ordering::Relaxed);
        let alias = self.next_alias.fetch_add(1, Ordering::Relaxed);
        let events = track.subscribe();
        let _guard = Unsubscribe(Arc::clone(&track));
        let largest = track.largest();
        let params = Params {
            subscribe_tracks_id: Some(subscribe_tracks_id),
            largest_object: largest,
            paused: template.paused,
            subscriber_priority: template.subscriber_priority,
            group_order: template.group_order,
            location_filter: template.location_filter,
            object_delivery_timeout: template.object_delivery_timeout,
            subgroup_delivery_timeout: template.subgroup_delivery_timeout,
            ..Params::default()
        };
        let m = Message::Publish(Publish {
            request_id,
            track: track.name.clone(),
            track_alias: alias,
            params,
            properties: if template.include_properties == Some(false) {
                Bytes::new()
            } else {
                track.properties()
            },
        });
        self.write(&send, &m).await?;
        let ctx = Context {
            ok_allows: allowed::ok_expires(),
            ..Context::default()
        };
        let first = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            read_frame(&mut recv, self.version, self.settings.max_control_message),
        )
        .await;
        match first {
            Ok(Ok(Some((message::REQUEST_OK, body)))) => {
                let _ = Message::decode(message::REQUEST_OK, &body, self.version, &ctx)?;
            }
            Ok(Ok(Some((message::REQUEST_ERROR, _)))) => return Ok(()),
            Ok(Ok(Some(_))) => {
                return Err(SessionError::new(
                    C::UnexpectedMessage,
                    "PUBLISH answered with neither OK nor ERROR",
                )
                .into())
            }
            _ => return Ok(()),
        }
        let state = SubState::from_params(&template, &track, largest);
        let (state_tx, state_rx) = watch::channel(state);
        let delivery = Delivery_ {
            session: Arc::clone(&self),
            track: Arc::clone(&track),
            alias,
            request_id,
            state: state_rx,
            streams_opened: Arc::new(AtomicU64::new(0)),
        };
        let update_ctx = Context {
            update_allows: allowed::update_subscription(),
            ..Context::default()
        };
        let updates = self.clone().subscription_updates(
            Arc::clone(&send),
            &mut recv,
            update_ctx,
            state_tx,
            delivery.clone_for_fill(&template),
        );
        let outcome = tokio::select! {
            o = delivery.run(events) => o,
            _ = updates => Outcome::Cancelled,
            () = self.closing.cancelled() => Outcome::Cancelled,
        };
        if let Outcome::Done {
            code,
            reason,
            streams,
        } = outcome
        {
            let m = Message::PublishDone {
                status: code.code(self.version),
                stream_count: streams,
                reason,
            };
            self.write(&send, &m).await?;
            let _ = send.lock().await.shutdown().await;
        } else {
            send.lock().await.reset(ResetCode::Cancelled as u32);
        }
        Ok(())
    }

    // ── The relay's own requests to the peer ────────────────────────────────

    /// SUBSCRIBE upstream to `track` through this (publisher's) session.
    pub(crate) async fn subscribe_upstream(
        self: Arc<Self>,
        track: Arc<Track>,
        new_group: Option<u64>,
    ) -> Result<(), (u64, String)> {
        if self.goaway_received.load(Ordering::Acquire) {
            return Err((
                RequestCode::GoingAway as u64,
                "the publisher is going away".into(),
            ));
        }
        let (send, recv) = self
            .t
            .open_bi()
            .await
            .map_err(|e| (RequestCode::InternalError as u64, e.0))?;
        let mut send = send;
        let mut recv = BufReader::new(recv);
        let request_id = self.next_request_id.fetch_add(2, Ordering::Relaxed);
        let m = Message::Subscribe(TrackRequest {
            request_id,
            track: track.name.clone(),
            params: Params {
                new_group_request: new_group,
                ..Params::default()
            },
        });
        send.write_all(&m.encode(self.version))
            .await
            .map_err(|e| (0, e.to_string()))?;
        let ctx = Context::default();
        let first = tokio::time::timeout(
            RESPONSE_TIMEOUT,
            read_frame(&mut recv, self.version, self.settings.max_control_message),
        )
        .await
        .map_err(|_| (RequestCode::Timeout as u64, "no answer in time".to_string()))?;
        let (track_alias, params, properties) = match first {
            Ok(Some((message::SUBSCRIBE_OK, body))) => {
                match Message::decode(message::SUBSCRIBE_OK, &body, self.version, &ctx) {
                    Ok(Message::SubscribeOk {
                        track_alias,
                        params,
                        properties,
                    }) => (track_alias, params, properties),
                    Ok(_) => unreachable!(),
                    Err(e) => {
                        self.fail(&e);
                        return Err((0, e.to_string()));
                    }
                }
            }
            Ok(Some((message::REQUEST_ERROR, body))) => {
                return match Message::decode(message::REQUEST_ERROR, &body, self.version, &ctx) {
                    Ok(Message::RequestError(e)) => Err((e.code, e.reason)),
                    _ => Err((0, "a malformed REQUEST_ERROR".into())),
                };
            }
            Ok(Some(_)) => {
                self.fail(&SessionError::new(
                    C::UnexpectedMessage,
                    "SUBSCRIBE answered with neither SUBSCRIBE_OK nor ERROR",
                ));
                return Err((0, "unexpected answer".into()));
            }
            _ => return Err((0, "the publisher ended the request".into())),
        };
        {
            let mut aliases = self
                .aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if aliases
                .get(&track_alias)
                .is_some_and(|t| t.name != track.name)
            {
                drop(aliases);
                self.fail(&SessionError::new(
                    C::DuplicateTrackAlias,
                    "a Track Alias already in use",
                ));
                return Err((0, "duplicate track alias".into()));
            }
            aliases.insert(track_alias, Arc::clone(&track));
        }
        self.alias_added.notify_waiters();
        if let Err(code) = track.set_properties(properties) {
            self.fail(&SessionError::new(code, "SUBSCRIBE_OK's Track Properties"));
            return Err((0, "malformed properties".into()));
        }
        if let Some(l) = params.largest_object {
            track.note_largest(l);
        }
        let upstream: Arc<dyn Upstream> = Arc::new(SessionUpstream {
            session: Arc::downgrade(&self),
            id: self.id,
        });
        track.attach_publisher(upstream);
        // Hold the upstream subscription while anyone downstream uses it
        let me = Arc::clone(&self);
        tokio::spawn(async move {
            let limit = me.settings.max_control_message;
            let mut idle_since: Option<Instant> = None;
            loop {
                tokio::select! {
                    frame = read_frame(&mut recv, me.version, limit) => match frame {
                        Ok(Some((message::PUBLISH_DONE, _)) | None) | Err(_) => break,
                        Ok(Some((message::PUBLISH_STATE_NOTIFY, body))) => {
                            if let Ok(Message::PublishStateNotify(p)) = Message::decode(message::PUBLISH_STATE_NOTIFY, &body, me.version, &Context::default()) {
                                if let Some(l) = p.largest_object { track.note_largest(l); }
                            }
                        }
                        Ok(Some(_)) => {
                            me.fail(&SessionError::new(C::UnexpectedMessage, "an unexpected message on a subscription"));
                            break;
                        }
                    },
                    () = tokio::time::sleep(Duration::from_secs(5)) => {
                        if track.subscriber_count() == 0 {
                            let since = *idle_since.get_or_insert_with(Instant::now);
                            if since.elapsed() >= UPSTREAM_LINGER {
                                send.reset(ResetCode::Cancelled as u32);
                                recv.get_mut().stop(ResetCode::Cancelled as u32);
                                break;
                            }
                        } else {
                            idle_since = None;
                        }
                    }
                    () = me.closing.cancelled() => break,
                }
            }
            me.aliases_in
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&track_alias);
            track.detach_publisher(me.id);
        });
        Ok(())
    }

    /// FETCH upstream through this session; entries arrive on the returned
    /// channel, which closes at the end of the response.
    pub(super) fn fetch_upstream(
        self: Arc<Self>,
        track: TrackName,
        start: Location,
        end: Location,
        timeout: Duration,
    ) -> Option<mpsc::Receiver<FetchEntry>> {
        if self.goaway_received.load(Ordering::Acquire) || self.closing.is_cancelled() {
            return None;
        }
        let (tx, rx) = mpsc::channel(256);
        let request_id = self.next_request_id.fetch_add(2, Ordering::Relaxed);
        self.fetches_out
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                request_id,
                FetchSink {
                    tx,
                    order: GroupOrder::Ascending,
                },
            );
        let me = Arc::clone(&self);
        tokio::spawn(async move {
            let Ok((mut send, recv)) = me.t.open_bi().await else {
                me.fetches_out
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&request_id);
                return;
            };
            let mut recv = BufReader::new(recv);
            let m = Message::Fetch(TrackRequest {
                request_id,
                track,
                params: Params {
                    location_filter: Some(LocationFilter::AbsoluteRange { start, end }),
                    fill_timeout: Some(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
                    ..Params::default()
                },
            });
            if send.write_all(&m.encode(me.version)).await.is_err() {
                return;
            }
            let ctx = Context {
                ok_allows: allowed::ok_with_largest(),
                ok_properties: true,
                ..Context::default()
            };
            let answer = tokio::time::timeout(
                timeout,
                read_frame(&mut recv, me.version, me.settings.max_control_message),
            )
            .await;
            match answer {
                Ok(Ok(Some((kind, body))))
                    if kind == message::REQUEST_OK || kind == message::FETCH_OK_22 =>
                {
                    if let Err(e) = Message::decode(kind, &body, me.version, &ctx) {
                        me.fail(&e);
                    }
                }
                _ => {
                    me.fetches_out
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&request_id);
                }
            }
        });
        Some(rx)
    }
}

/// The host of an authority, `host[:port]` or `[v6]:port` (RFC 3986
/// section 3.2), lowercased; `None` when it is malformed.
fn authority_host(text: &str) -> Option<String> {
    let digits = |p: &str| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit());
    let host = if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(digits)) || host.is_empty() {
            return None;
        }
        host
    } else {
        match text.split_once(':') {
            Some((host, port)) if digits(port) => host,
            Some(_) => return None,
            None => text,
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// A REQUEST_ERROR answering a REQUEST_UPDATE.
fn update_error(version: Version, code: RequestCode, reason: &str) -> Message {
    Message::RequestError(RequestError {
        code: code.code(version),
        retry_interval: 0,
        reason: reason.into(),
        details: Vec::new(),
    })
}

/// Resolves when the peer has stopped reading a request stream.
async fn stream_stopped<S: SendHalf>(send: &Shared<S>) {
    // A zero-length write fails once the peer has sent STOP_SENDING
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let mut s = send.lock().await;
        if futures_util::future::poll_fn(|cx| std::pin::Pin::new(&mut *s).poll_flush(cx))
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Runs a closure when dropped.
struct OnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Counts a subscriber off its track when the subscription ends.
struct Unsubscribe(Arc<Track>);

impl Drop for Unsubscribe {
    fn drop(&mut self) {
        self.0.unsubscribe();
    }
}

/// A publisher's session, as the relay asks it for objects.
struct SessionUpstream<T: Transport> {
    session: Weak<Session<T>>,
    id: u64,
}

impl<T: Transport> Upstream for SessionUpstream<T> {
    fn fetch(
        &self,
        track: TrackName,
        start: Location,
        end: Location,
        timeout: Duration,
    ) -> Option<mpsc::Receiver<FetchEntry>> {
        self.session
            .upgrade()?
            .fetch_upstream(track, start, end, timeout)
    }

    fn new_group(&self, track: &TrackName, value: u64) {
        // A REQUEST_UPDATE on the upstream subscription would carry it; the
        // relay asks with a new SUBSCRIBE carrying NEW_GROUP_REQUEST instead,
        // which an original publisher honours the same way (9.19.19)
        let Some(s) = self.session.upgrade() else {
            return;
        };
        let Some(t) = s.relay.existing(track) else {
            return;
        };
        tokio::spawn(async move {
            let _ = s.subscribe_upstream(t, Some(value)).await;
        });
    }

    fn id(&self) -> u64 {
        self.id
    }
}

impl<T: Transport> NamespacePublisher for SessionUpstream<T> {
    fn subscribe_upstream(
        &self,
        track: Arc<Track>,
        new_group: Option<u64>,
    ) -> BoxFuture<'static, Result<(), (u64, String)>> {
        let session = self.session.upgrade();
        Box::pin(async move {
            match session {
                Some(s) => s.subscribe_upstream(track, new_group).await,
                None => Err((
                    RequestCode::DoesNotExist as u64,
                    "the publisher left".into(),
                )),
            }
        })
    }

    fn fetch_through(
        &self,
        track: TrackName,
        start: Location,
        end: Location,
        timeout: Duration,
    ) -> BoxFuture<'static, Option<mpsc::Receiver<FetchEntry>>> {
        let session = self.session.upgrade();
        Box::pin(async move { session?.fetch_upstream(track, start, end, timeout) })
    }

    fn session_id(&self) -> u64 {
        self.id
    }
}

// ── Subscription delivery ──────────────────────────────────────────────────

/// What a subscription currently asks for.
#[derive(Debug, Clone)]
struct SubState {
    paused: bool,
    start: Location,
    end: Option<Location>,
    priority: u8,
    order: GroupOrder,
    filters: Vec<RangeFilter>,
    failed: bool,
}

impl SubState {
    fn from_params(p: &Params, track: &Track, largest: Option<Location>) -> Self {
        let (start, end) = p
            .location_filter
            .unwrap_or(LocationFilter::None)
            .bounds(largest);
        Self {
            paused: p.paused.unwrap_or(false),
            start,
            end,
            priority: p.subscriber_priority.unwrap_or(128),
            order: p.group_order.unwrap_or_else(|| track.group_order()),
            filters: p
                .range_filters
                .iter()
                .filter(|f| f.kind != message::P_TRACK_PROPERTY_FILTER)
                .cloned()
                .collect(),
            failed: false,
        }
    }

    /// Apply a REQUEST_UPDATE: what it carries replaces, what it omits stays.
    fn update(&mut self, p: &Params, track: &Track) {
        if let Some(paused) = p.paused {
            self.paused = paused;
        }
        if let Some(f) = p.location_filter {
            let (start, end) = f.bounds(track.largest());
            self.start = start;
            self.end = end;
        }
        if let Some(pr) = p.subscriber_priority {
            self.priority = pr;
        }
        for (kind, set, prop) in &p.removed_filters {
            self.filters.retain(|f| {
                !(f.kind == *kind
                    && (f.set_id == *set || *set == 0)
                    && (f.property == *prop || prop.is_none()))
            });
        }
        for f in &p.range_filters {
            self.filters.retain(|x| {
                !(x.kind == f.kind && x.set_id == f.set_id && x.property == f.property)
            });
            self.filters.push(f.clone());
        }
    }

    /// Whether an object passes every filter (section 3.3.3).
    fn passes(&self, o: &Object) -> bool {
        if self.paused || o.location < self.start || self.end.is_some_and(|e| o.location > e) {
            return false;
        }
        object_range_filters_pass(&self.filters, o)
    }
}

/// Range Filters on an object: filters with the same SetID are AND'd,
/// different SetIDs OR'd (section 3.3.2).
fn object_range_filters_pass(filters: &[RangeFilter], o: &Object) -> bool {
    if filters.is_empty() {
        return true;
    }
    let mut sets: Vec<u8> = filters.iter().map(|f| f.set_id).collect();
    sets.sort_unstable();
    sets.dedup();
    let props = super::codec::Reader::new(&o.properties, C::MalformedObject)
        .kvps_to_end()
        .unwrap_or_default();
    sets.into_iter().any(|set| {
        filters
            .iter()
            .filter(|f| f.set_id == set)
            .all(|f| match f.kind {
                message::P_SUBGROUP_FILTER => match o.delivery {
                    Delivery::Subgroup(s) => f.admits(s),
                    Delivery::Datagram => false,
                },
                message::P_OBJECTID_FILTER => f.admits(o.location.object),
                message::P_PRIORITY_FILTER => f.admits(u64::from(o.priority)),
                message::P_OBJECT_PROPERTY_FILTER => {
                    let t = f.property.unwrap_or(1);
                    props
                        .iter()
                        .any(|k| k.kind == t && k.int().is_some_and(|v| f.admits(v)))
                }
                _ => true,
            })
    })
}

/// TRACK_PROPERTY_FILTER on a track (section 9.19.14).
fn track_property_filters_pass(track: &Track, filters: &[RangeFilter]) -> bool {
    let tf: Vec<&RangeFilter> = filters
        .iter()
        .filter(|f| f.kind == message::P_TRACK_PROPERTY_FILTER)
        .collect();
    if tf.is_empty() {
        return true;
    }
    let raw = track.properties();
    let props = super::codec::Reader::new(&raw, C::MalformedKeyValue)
        .kvps_to_end()
        .unwrap_or_default();
    let mut sets: Vec<u8> = tf.iter().map(|f| f.set_id).collect();
    sets.sort_unstable();
    sets.dedup();
    sets.into_iter().any(|set| {
        tf.iter().filter(|f| f.set_id == set).all(|f| {
            let t = f.property.unwrap_or(1);
            props
                .iter()
                .any(|k| k.kind == t && k.int().is_some_and(|v| f.admits(v)))
        })
    })
}

/// How a subscription's delivery ended.
enum Outcome {
    Cancelled,
    Done {
        code: DoneCode,
        reason: String,
        streams: u64,
    },
}

/// The QUIC stream priority for a subgroup: subscriber priority first, then
/// publisher priority, then group order (section 5.1.2), lower MOQT values
/// meaning sooner. Within one priority pair the group's low bits order it.
fn stream_priority(subscriber: u8, publisher: u8, group: u64, order: GroupOrder) -> i32 {
    let g = (group & 0xFF) as i32;
    let group_rank = match order {
        GroupOrder::Ascending => 0xFF - g,
        GroupOrder::Descending => g,
    };
    ((0xFF - i32::from(subscriber)) << 16) | ((0xFF - i32::from(publisher)) << 8) | group_rank
}

/// One subgroup stream being written to the subscriber.
struct OpenStream {
    tx: mpsc::Sender<Arc<Object>>,
    upstream: Option<u64>,
    last: u64,
    task: tokio::task::JoinHandle<()>,
    stop: CancellationToken,
}

/// A subscription's delivery: objects from the track's broadcast to
/// subgroup streams and datagrams, as its filters allow.
struct Delivery_<T: Transport> {
    session: Arc<Session<T>>,
    track: Arc<Track>,
    alias: u64,
    request_id: u64,
    state: watch::Receiver<SubState>,
    streams_opened: Arc<AtomicU64>,
}

/// What a subscription needs to open fill fetch streams later.
struct FillSpawner<T: Transport> {
    session: Arc<Session<T>>,
    track: Arc<Track>,
    base: Params,
    streams_opened: Arc<AtomicU64>,
}

impl<T: Transport> FillSpawner<T> {
    /// A REQUEST_UPDATE's FILL_PARAMETERS: a fill fetch stream with the
    /// update's Request ID (section 3.4).
    fn spawn_update_fill(&self, request_id: u64, fill: &Params, state: &SubState) {
        let mut base = self.base.clone();
        base.subscriber_priority = Some(state.priority);
        spawn_fill(
            &self.session,
            &self.track,
            request_id,
            &base,
            fill,
            &self.streams_opened,
        );
    }
}

/// Open a fill fetch stream for a subscription (sections 3.4, 3.4.1): the
/// fill range is FILL_PARAMETERS' Location Filter evaluated as for a FETCH,
/// or the subscription's own; nothing past Largest Object.
fn spawn_fill<T: Transport>(
    session: &Arc<Session<T>>,
    track: &Arc<Track>,
    request_id: u64,
    sub: &Params,
    fill: &Params,
    opened: &Arc<AtomicU64>,
) {
    let Some(largest) = track.largest() else {
        return;
    };
    let filter = fill
        .location_filter
        .or(sub.location_filter)
        .unwrap_or(LocationFilter::None);
    let (start, end) = filter.bounds(Some(largest));
    let end = end.unwrap_or(largest).min(largest);
    if start > end {
        return; // an empty fill range opens no stream
    }
    let order = fill
        .group_order
        .or(sub.group_order)
        .unwrap_or(GroupOrder::Ascending);
    let timeout = fill
        .fill_timeout
        .or(sub.fill_timeout)
        .map(Duration::from_millis);
    let priority = fill
        .subscriber_priority
        .or(sub.subscriber_priority)
        .unwrap_or(128);
    let filters = if fill.range_filters.is_empty() {
        sub.range_filters.clone()
    } else {
        fill.range_filters.clone()
    };
    opened.fetch_add(1, Ordering::Relaxed);
    let s = Arc::clone(session);
    let t = Arc::clone(track);
    tokio::spawn(async move {
        s.fetch_response(request_id, t, start, end, order, timeout, priority, filters)
            .await;
    });
}

impl<T: Transport> Delivery_<T> {
    fn spawn_fill(&self, sub: &Params, fill: &Params) {
        spawn_fill(
            &self.session,
            &self.track,
            self.request_id,
            sub,
            fill,
            &self.streams_opened,
        );
    }

    fn clone_for_fill(&self, base: &Params) -> FillSpawner<T> {
        FillSpawner {
            session: Arc::clone(&self.session),
            track: Arc::clone(&self.track),
            base: base.clone(),
            streams_opened: Arc::clone(&self.streams_opened),
        }
    }

    async fn run(mut self, mut events: broadcast::Receiver<Event>) -> Outcome {
        let mut open: HashMap<(u64, u64), OpenStream> = HashMap::new();
        let mut stopped: BTreeSet<(u64, u64)> = BTreeSet::new();
        let publisher_priority = self.track.default_priority();
        let outcome = loop {
            tokio::select! {
                ev = events.recv() => match ev {
                    Ok(Event::Object { object, upstream_stream, first_in_subgroup, end_of_group_stream }) => {
                        let st = self.state.borrow().clone();
                        if st.failed {
                            break Outcome::Done { code: DoneCode::UpdateFailed, reason: "REQUEST_UPDATE failed".into(), streams: 0 };
                        }
                        if !st.passes(&object) {
                            continue;
                        }
                        match object.delivery {
                            Delivery::Datagram => {
                                let d = encode_datagram(self.alias, &object, false, end_of_group_stream);
                                if self.session.t.max_datagram_size().is_some_and(|m| d.len() <= m) {
                                    if self.session.t.send_datagram(Bytes::from(d)).is_ok() {
                                        self.count_out(&object);
                                    }
                                }
                            }
                            Delivery::Subgroup(sub) => {
                                let key = (object.location.group, sub);
                                if stopped.contains(&key) {
                                    continue;
                                }
                                // The next object of an open stream: from the
                                // same upstream stream in order, or the next ID
                                // (section 11.3.2)
                                let reuse = open.get(&key).is_some_and(|s| {
                                    (s.upstream.is_some() && s.upstream == upstream_stream) || object.location.object == s.last + 1
                                });
                                if !reuse {
                                    if let Some(old) = open.remove(&key) {
                                        old.stop.cancel();
                                    }
                                    let stream = self.open_stream(&object, upstream_stream, first_in_subgroup, end_of_group_stream, publisher_priority, &st);
                                    open.insert(key, stream);
                                }
                                let s = open.get_mut(&key).expect("just inserted");
                                s.last = object.location.object;
                                match s.tx.try_send(Arc::clone(&object)) {
                                    Ok(()) => self.count_out(&object),
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        self.session.relay.stats.too_far_behind.fetch_add(1, Ordering::Relaxed);
                                        break Outcome::Done { code: DoneCode::TooFarBehind, reason: "the subscriber is too far behind".into(), streams: 0 };
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        // The subscriber stopped this subgroup
                                        open.remove(&key);
                                        stopped.insert(key);
                                    }
                                }
                            }
                        }
                    }
                    Ok(Event::SubgroupEnd { upstream_stream, group, subgroup, complete }) => {
                        let key = (group, subgroup);
                        if open.get(&key).is_some_and(|s| s.upstream == Some(upstream_stream)) {
                            let s = open.remove(&key).expect("checked");
                            if complete {
                                drop(s.tx); // the writer FINs once its queue is sent
                            } else {
                                s.stop.cancel();
                            }
                        }
                    }
                    Ok(Event::Done { code, reason }) => break Outcome::Done { code, reason, streams: 0 },
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        self.session.relay.stats.too_far_behind.fetch_add(1, Ordering::Relaxed);
                        break Outcome::Done { code: DoneCode::TooFarBehind, reason: "the subscriber is too far behind".into(), streams: 0 };
                    }
                    Err(broadcast::error::RecvError::Closed) => break Outcome::Done { code: DoneCode::TrackEnded, reason: "the track ended".into(), streams: 0 },
                },
                changed = self.state.changed() => {
                    if changed.is_err() {
                        break Outcome::Cancelled;
                    }
                    let st = self.state.borrow().clone();
                    if st.failed {
                        break Outcome::Done { code: DoneCode::UpdateFailed, reason: "REQUEST_UPDATE failed".into(), streams: 0 };
                    }
                    // Paused, or narrowed past an open stream's group: reset
                    // it (section 11.3.2)
                    open.retain(|(g, _), s| {
                        let keep = !st.paused && *g >= st.start.group && st.end.is_none_or(|e| *g <= e.group);
                        if !keep {
                            s.stop.cancel();
                        }
                        keep
                    });
                    if !st.paused {
                        stopped.clear(); // a resume renews interest (11.3.2)
                    }
                }
            }
        };
        // Every stream closed before PUBLISH_DONE (section 9.9)
        let cancelled = matches!(outcome, Outcome::Cancelled);
        let handles: Vec<_> = open
            .drain()
            .map(|(_, s)| {
                if cancelled
                    || !matches!(
                        outcome,
                        Outcome::Done {
                            code: DoneCode::TrackEnded,
                            ..
                        }
                    )
                {
                    s.stop.cancel();
                }
                drop(s.tx);
                s.task
            })
            .collect();
        for h in handles {
            let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
        }
        match outcome {
            Outcome::Done { code, reason, .. } => Outcome::Done {
                code,
                reason,
                streams: self.streams_opened.load(Ordering::Relaxed),
            },
            Outcome::Cancelled => Outcome::Cancelled,
        }
    }

    fn count_out(&self, o: &Object) {
        self.session
            .relay
            .stats
            .objects_out
            .fetch_add(1, Ordering::Relaxed);
        self.session
            .relay
            .stats
            .bytes_out
            .fetch_add(o.payload.len() as u64, Ordering::Relaxed);
    }

    /// A subgroup stream and its writer task.
    fn open_stream(
        &self,
        first: &Object,
        upstream: Option<u64>,
        first_in_subgroup: bool,
        end_of_group: bool,
        publisher_priority: u8,
        st: &SubState,
    ) -> OpenStream {
        let (tx, mut rx) = mpsc::channel::<Arc<Object>>(STREAM_QUEUE);
        let stop = CancellationToken::new();
        let Delivery::Subgroup(sub) = first.delivery else {
            unreachable!("subgroup objects only")
        };
        let header = SubgroupHeader {
            track_alias: self.alias,
            group: first.location.group,
            subgroup: if sub == 0 {
                SubgroupIdMode::Zero
            } else {
                SubgroupIdMode::Explicit(sub)
            },
            priority: Some(first.priority),
            // A relay might forward properties on any later object (11.3.1)
            properties: true,
            end_of_group,
            first_object: first_in_subgroup,
        };
        let priority = stream_priority(
            st.priority,
            publisher_priority.min(first.priority),
            first.location.group,
            st.order,
        );
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
        let session = Arc::clone(&self.session);
        let stop2 = stop.clone();
        let task = tokio::spawn(async move {
            let Ok(mut out) = session.t.open_uni().await else {
                return;
            };
            out.set_priority(priority);
            let mut hb = Vec::new();
            header.encode(&mut hb);
            let mut prior: Option<u64> = None;
            if out.write_all(&hb).await.is_err() {
                return;
            }
            loop {
                tokio::select! {
                    o = rx.recv() => match o {
                        Some(o) => {
                            let mut b = Vec::with_capacity(o.payload.len() + 16);
                            encode_subgroup_object(&mut b, prior, &o, true);
                            prior = Some(o.location.object);
                            if out.write_all(&b).await.is_err() {
                                return; // STOP_SENDING from the subscriber
                            }
                        }
                        None => {
                            let _ = out.shutdown().await; // FIN
                            return;
                        }
                    },
                    () = stop2.cancelled() => {
                        out.reset(ResetCode::Cancelled as u32);
                        return;
                    }
                }
            }
        });
        OpenStream {
            tx,
            upstream,
            last: first.location.object,
            task,
            stop,
        }
    }
}

// ── FETCH planning ─────────────────────────────────────────────────────────

/// Ranges the upstream answered for: an unmarked gap inside one is an
/// object that does not exist (section 3.2.2); and whether the upstream ran
/// out of time.
struct Covered {
    spans: Vec<(Location, Location)>,
    timed_out: bool,
}

/// Fetch what the cache lacks in `start..=end` from the track's publishers,
/// within `budget` (section 3.2.3); what arrives is cached.
async fn fill_from_upstream(
    relay: &Arc<Relay>,
    track: &Arc<Track>,
    start: Location,
    end: Location,
    budget: Duration,
) -> Covered {
    let mut covered = Covered {
        spans: Vec::new(),
        timed_out: false,
    };
    let missing = track.cached_range(start, end);
    let gaps = gaps_in(start, end, &missing, track);
    if gaps.is_empty() || budget.is_zero() {
        covered.timed_out = budget.is_zero() && !gaps.is_empty();
        return covered;
    }
    let deadline = tokio::time::Instant::now() + budget;
    let (a, b) = (gaps[0].0, gaps[gaps.len() - 1].1);
    // The track's publishers first, then those of its namespace: a track the
    // relay is no longer subscribed to (a finished one's subscription ends
    // with it) is fetched through the session that advertised it
    let mut answer = track
        .publishers()
        .into_iter()
        .find_map(|p| p.fetch(track.name.clone(), a, b, budget));
    if answer.is_none() {
        // The newest advertisement first: a publisher that restarted
        // advertises again from a new session while its old one, gone
        // without a close, is listed until its idle timeout
        let mut ads = relay.publishers_for(&track.name.namespace);
        ads.sort_by_key(|ad| std::cmp::Reverse(ad.id));
        for ad in ads {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let asked = ad.publisher.fetch_through(track.name.clone(), a, b, left);
            if let Ok(Some(rx)) = tokio::time::timeout_at(deadline, asked).await {
                answer = Some(rx);
                break;
            }
        }
    }
    let Some(mut rx) = answer else {
        covered.timed_out = tokio::time::Instant::now() >= deadline;
        return covered;
    };
    let mut prior: Option<Location> = None;
    let mut complete = false;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(FetchEntry::Object(o))) => {
                prior = Some(o.location);
                relay.ingest(track, o, None, false, false);
            }
            Ok(Some(FetchEntry::EndOfRange { kind, end: e })) => {
                if kind == RangeKind::Gone {
                    track.note_gone(prior.map_or(a, Location::next_object), e);
                }
                prior = Some(e);
            }
            Ok(Some(FetchEntry::EndOfGroup)) => {
                if let Some(p) = prior {
                    track.note_group_end(p.group, p.object);
                }
            }
            Ok(Some(FetchEntry::EndOfTrack)) => {
                if let Some(p) = prior {
                    track.note_group_end(p.group, p.object);
                }
            }
            Ok(None) => {
                complete = true;
                break;
            }
            Err(_) => {
                covered.timed_out = true;
                break;
            }
        }
    }
    if complete {
        covered.spans.push((a, b));
    } else if let Some(p) = prior {
        covered.spans.push((a, p));
    }
    covered
}

/// The spans of `start..=end` the cache holds nothing for.
fn gaps_in(
    start: Location,
    end: Location,
    objects: &[Arc<Object>],
    track: &Track,
) -> Vec<(Location, Location)> {
    let mut gaps = Vec::new();
    let mut cursor = start;
    for o in objects {
        if o.location > cursor {
            gaps.push((cursor, before(o.location)));
        }
        cursor = after_object(o.location, track);
    }
    if cursor <= end && !(cursor.object == 0 && cursor.group > end.group) {
        gaps.push((cursor, end));
    }
    gaps
}

/// The Location before `l`.
fn before(l: Location) -> Location {
    if l.object == 0 {
        Location::new(l.group.saturating_sub(1), u64::MAX)
    } else {
        Location::new(l.group, l.object - 1)
    }
}

/// The last Location before `l` as a FETCH stream names it: the previous
/// group's last object where the relay knows it, so an End of Range carries
/// an Object ID a receiver holds as a number; 2^64 - 1, the whole group,
/// only where it does not.
fn last_before(l: Location, track: &Track) -> Location {
    if l.object == 0 {
        let g = l.group.saturating_sub(1);
        Location::new(g, track.group_end(g).unwrap_or(u64::MAX))
    } else {
        Location::new(l.group, l.object - 1)
    }
}

/// Where unknown territory starts after `l`: the next object, or the next
/// group when `l` ends its group.
fn after_object(l: Location, track: &Track) -> Location {
    if track.group_end(l.group) == Some(l.object) {
        Location::new(l.group.saturating_add(1), 0)
    } else {
        l.next_object()
    }
}

/// The entries of a FETCH response for `start..=end` (sections 3.2.1, 3.2.2,
/// 11.4): cached Normal objects in the group order, End of Group and End of
/// Track where known (draft 23), and every span the relay cannot vouch for
/// marked Unknown (or Timed-Out, or Gone).
fn plan_fetch(
    track: &Track,
    start: Location,
    end: Location,
    order: GroupOrder,
    covered: &Covered,
    filters: &[RangeFilter],
    version: Version,
) -> Vec<FetchEntry> {
    let objects = track.cached_range(start, end);
    let mut groups: Vec<(u64, Vec<Arc<Object>>)> = Vec::new();
    for o in objects {
        match groups.last_mut() {
            Some((g, v)) if *g == o.location.group => v.push(o),
            _ => groups.push((o.location.group, vec![o])),
        }
    }
    let unknown_kind = |a: Location, b: Location| -> Option<RangeKind> {
        if covered.spans.iter().any(|&(x, y)| x <= a && b <= y) {
            return None; // the upstream vouched: they do not exist
        }
        if matches!(track.lookup(a), Lookup::Gone) {
            return Some(RangeKind::Gone);
        }
        Some(if covered.timed_out && version.fetch_stream_v23() {
            RangeKind::TimedOut
        } else {
            RangeKind::Unknown
        })
    };
    let mut out = Vec::new();
    let emit_group =
        |out: &mut Vec<FetchEntry>, g: u64, objs: &[Arc<Object>], lo: Location, hi: Location| {
            let mut cursor = lo;
            let mut last_normal: Option<Location> = None;
            for o in objs {
                if o.location < lo || o.location > hi {
                    continue;
                }
                if o.location > cursor {
                    let end = last_before(o.location, track);
                    if let Some(kind) = unknown_kind(cursor, end) {
                        out.push(FetchEntry::EndOfRange { kind, end });
                    }
                }
                match o.status {
                    ObjectStatus::Normal => {
                        if object_range_filters_pass(filters, o) {
                            out.push(FetchEntry::Object((**o).clone()));
                            last_normal = Some(o.location);
                        }
                        cursor = o.location.next_object();
                    }
                    ObjectStatus::EndOfGroup | ObjectStatus::EndOfTrack => {
                        if version.fetch_stream_v23() && last_normal.is_some() {
                            out.push(if o.status == ObjectStatus::EndOfTrack {
                                FetchEntry::EndOfTrack
                            } else {
                                FetchEntry::EndOfGroup
                            });
                        }
                        return Location::new(g.saturating_add(1), 0);
                    }
                }
                if track.group_end(g) == Some(o.location.object) {
                    if version.fetch_stream_v23() && last_normal == Some(o.location) {
                        out.push(FetchEntry::EndOfGroup);
                    }
                    return Location::new(g.saturating_add(1), 0);
                }
            }
            cursor
        };
    match order {
        GroupOrder::Ascending => {
            let mut cursor = start;
            for (g, objs) in &groups {
                // From where the last group left off: a group the cache lacks
                // entirely is part of the next group's leading gap
                cursor = emit_group(&mut out, *g, objs, cursor.max(start), end);
                // Groups skipped between this and the next are covered by the
                // next group's leading gap
                let _ = cursor;
            }
            // Tail: from after the last object to the end
            let tail = groups.last().map_or(start, |(g, objs)| {
                let last = objs.last().expect("non-empty").location;
                if track.group_end(*g) == Some(last.object) || last.object == u64::MAX {
                    Location::new(g.saturating_add(1), 0)
                } else {
                    last.next_object()
                }
            });
            if tail <= end {
                if let Some(kind) = unknown_kind(tail, end) {
                    out.push(FetchEntry::EndOfRange { kind, end });
                }
            }
        }
        GroupOrder::Descending => {
            // Groups from End's down to Start's; each group in Object ID order
            for (g, objs) in groups.iter().rev() {
                let lo = if *g == start.group {
                    start
                } else {
                    Location::new(*g, 0)
                };
                let hi = if *g == end.group {
                    end
                } else {
                    Location::new(*g, u64::MAX)
                };
                emit_group(&mut out, *g, objs, lo, hi);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moq::relay::Limits;

    fn track(relay: &Relay) -> Arc<Track> {
        relay
            .track(&TrackName {
                namespace: Namespace(vec![Bytes::from_static(b"m")]),
                name: Bytes::from_static(b"a"),
            })
            .unwrap()
    }

    fn obj(g: u64, o: u64) -> Object {
        Object {
            location: Location::new(g, o),
            delivery: Delivery::Subgroup(0),
            priority: 1,
            status: ObjectStatus::Normal,
            properties: Bytes::new(),
            payload: Bytes::from_static(b"p"),
        }
    }

    #[test]
    fn authorities_parse_with_and_without_ports() {
        assert_eq!(
            authority_host("Example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            authority_host("example.com:443").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            authority_host("[2001:db8::1]:8443").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(authority_host("[::1]").as_deref(), Some("::1"));
        for bad in [
            "",
            ":443",
            "example.com:",
            "example.com:x",
            "[::1",
            "[::1]x",
            "a:b:c",
        ] {
            assert_eq!(authority_host(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn request_ids_are_unique_out_of_order() {
        let mut seen = SeenIds::new(0);
        assert!(seen.insert(4));
        assert!(seen.insert(0));
        assert!(seen.insert(2));
        assert_eq!(seen.below, 6);
        assert!(!seen.insert(2));
        assert!(!seen.insert(4));
        assert!(seen.insert(6));
    }

    #[test]
    fn a_fetch_of_cached_objects_marks_what_is_missing() {
        let relay = Relay::new(Limits::default());
        let t = track(&relay);
        for (g, o) in [(1, 0), (1, 1), (1, 3), (3, 0)] {
            relay.ingest(&t, obj(g, o), None, false, false);
        }
        let covered = Covered {
            spans: vec![],
            timed_out: false,
        };
        let plan = plan_fetch(
            &t,
            Location::new(1, 0),
            Location::new(3, 0),
            GroupOrder::Ascending,
            &covered,
            &[],
            Version::Draft23,
        );
        let kinds: Vec<String> = plan
            .iter()
            .map(|e| match e {
                FetchEntry::Object(o) => format!("{}.{}", o.location.group, o.location.object),
                FetchEntry::EndOfRange { kind, end } => {
                    format!("{kind:?}->{}.{}", end.group, end.object)
                }
                FetchEntry::EndOfGroup => "EoG".into(),
                FetchEntry::EndOfTrack => "EoT".into(),
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "1.0",
                "1.1",
                "Unknown->1.2",
                "1.3",
                &format!("Unknown->2.{}", u64::MAX),
                "3.0"
            ]
        );
    }

    #[test]
    fn a_vouched_span_is_left_unmarked() {
        let relay = Relay::new(Limits::default());
        let t = track(&relay);
        relay.ingest(&t, obj(1, 0), None, false, false);
        relay.ingest(&t, obj(1, 5), None, false, false);
        let covered = Covered {
            spans: vec![(Location::new(1, 1), Location::new(1, 4))],
            timed_out: false,
        };
        let plan = plan_fetch(
            &t,
            Location::new(1, 0),
            Location::new(1, 5),
            GroupOrder::Ascending,
            &covered,
            &[],
            Version::Draft23,
        );
        assert_eq!(plan.len(), 2);
    }

    #[test]
    fn the_end_of_a_group_is_marked_in_draft_23() {
        let relay = Relay::new(Limits::default());
        let t = track(&relay);
        relay.ingest(&t, obj(1, 0), None, false, false);
        relay.ingest(
            &t,
            Object {
                status: ObjectStatus::EndOfGroup,
                payload: Bytes::new(),
                ..obj(1, 1)
            },
            None,
            false,
            false,
        );
        relay.ingest(&t, obj(2, 0), None, false, false);
        let covered = Covered {
            spans: vec![],
            timed_out: false,
        };
        let plan = plan_fetch(
            &t,
            Location::new(1, 0),
            Location::new(2, 0),
            GroupOrder::Ascending,
            &covered,
            &[],
            Version::Draft23,
        );
        assert!(matches!(plan[1], FetchEntry::EndOfGroup), "{plan:?}");
        assert_eq!(plan.len(), 3);
    }

    #[test]
    fn stream_priorities_order_subscriber_then_publisher_then_group() {
        let hi = stream_priority(0, 255, 0, GroupOrder::Ascending);
        let lo = stream_priority(1, 0, 0, GroupOrder::Ascending);
        assert!(hi > lo, "subscriber priority first");
        assert!(
            stream_priority(5, 1, 0, GroupOrder::Ascending)
                > stream_priority(5, 2, 0, GroupOrder::Ascending)
        );
        assert!(
            stream_priority(5, 1, 3, GroupOrder::Ascending)
                > stream_priority(5, 1, 4, GroupOrder::Ascending)
        );
        assert!(
            stream_priority(5, 1, 4, GroupOrder::Descending)
                > stream_priority(5, 1, 3, GroupOrder::Descending)
        );
    }

    #[test]
    fn range_filters_and_within_a_set_and_or_across() {
        let f = |kind, set, lo, hi| RangeFilter {
            kind,
            set_id: set,
            property: None,
            ranges: vec![(lo, Some(hi))],
        };
        let filters = vec![
            f(message::P_OBJECTID_FILTER, 0, 0, 4),
            f(message::P_PRIORITY_FILTER, 0, 0, 0),
            f(message::P_OBJECTID_FILTER, 1, 10, 20),
        ];
        assert!(
            !object_range_filters_pass(&filters, &obj(1, 2)),
            "set 0 needs priority 0"
        );
        assert!(
            object_range_filters_pass(&filters, &obj(1, 12)),
            "set 1 admits object 12"
        );
        assert!(object_range_filters_pass(
            &filters,
            &Object {
                priority: 0,
                ..obj(1, 2)
            }
        ));
    }
}
