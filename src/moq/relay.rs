//! The relay's shared state (draft-ietf-moq-transport section 7): tracks and
//! their cached objects, the namespaces publishers advertise, and the
//! namespace and track watchers subscribers register.
//!
//! One [`Relay`] serves every session on the node. A track has at most one
//! cache whatever number of sessions publish or subscribe to it: objects from
//! every publisher of a track go into it once (deduplicated by Location,
//! section 7.3) and out to every subscriber through the track's broadcast
//! channel. The cache is bounded in bytes across all tracks, oldest first,
//! and honours MAX_CACHE_DURATION (section 10.3).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{broadcast, mpsc, Notify};

use super::codec::{Kvp, KvpValue, Location, Namespace, Reader, TrackName};
use super::data::{Object, ObjectStatus};
use super::error::{DoneCode, SessionCode};
use super::message::GroupOrder;

/// Track Properties this relay reads (section 10, 16.8)
pub const PROP_MAX_CACHE_DURATION: u64 = 0x04;
pub const PROP_DEFAULT_PUBLISHER_PRIORITY: u64 = 0x0E;
pub const PROP_DEFAULT_PUBLISHER_GROUP_ORDER: u64 = 0x22;
pub const PROP_DYNAMIC_GROUPS: u64 = 0x30;
pub const PROP_IMMUTABLE: u64 = 0x0B;
/// Mandatory Track Properties (section 3.7, 16.8): a relay that does not
/// understand one refuses the track
pub const MANDATORY_PROPERTIES: std::ops::RangeInclusive<u64> = 0x4000..=0x7FFF;

/// What a track's broadcast carries to its subscribers.
#[derive(Debug, Clone)]
pub enum Event {
    /// An object, and where it came from: the upstream stream it arrived on
    /// (`None` for a datagram) and whether that stream began the subgroup
    Object {
        object: Arc<Object>,
        upstream_stream: Option<u64>,
        first_in_subgroup: bool,
        end_of_group_stream: bool,
    },
    /// An upstream subgroup stream ended: with its FIN (`complete`) or reset
    SubgroupEnd {
        upstream_stream: u64,
        group: u64,
        subgroup: u64,
        complete: bool,
    },
    /// The track is done (its last publisher left, or it is malformed)
    Done { code: DoneCode, reason: String },
}

/// The relay's limits (from `[moq]`).
#[derive(Debug, Clone)]
pub struct Limits {
    pub cache_bytes: usize,
    pub max_object: usize,
    pub broadcast_depth: usize,
    pub rendezvous_max: Duration,
    pub fill_timeout: Duration,
    pub max_tracks: usize,
    pub namespace_enumeration_max: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            cache_bytes: 256 << 20,
            max_object: 4 << 20,
            broadcast_depth: 4096,
            rendezvous_max: Duration::from_secs(30),
            fill_timeout: Duration::from_secs(5),
            max_tracks: 100_000,
            namespace_enumeration_max: 10_000,
        }
    }
}

/// A source of a track's objects other than the cache: the session of a
/// publisher (or upstream relay) that can be asked for what the cache lacks.
pub trait Upstream: Send + Sync + 'static {
    /// Fetch `start..=end` of `track` (section 3.2.3); entries arrive on the
    /// channel, which closes at the end of the response.
    fn fetch(
        &self,
        track: TrackName,
        start: Location,
        end: Location,
        timeout: Duration,
    ) -> Option<mpsc::Receiver<super::data::FetchEntry>>;
    /// Ask the original publisher for a new group (section 9.19.19).
    fn new_group(&self, track: &TrackName, value: u64);
    /// A stable identity, to tell publishers apart.
    fn id(&self) -> u64;
}

/// One track at the relay.
pub struct Track {
    pub name: TrackName,
    state: Mutex<TrackState>,
    events: broadcast::Sender<Event>,
    /// Woken when a publisher attaches (rendezvous, section 9.19.6)
    pub publisher_arrived: Notify,
}

struct Cached {
    object: Arc<Object>,
    received: Instant,
}

struct TrackState {
    properties: Bytes,
    largest: Option<Location>,
    end_of_track: Option<Location>,
    /// Groups whose last object is known (End of Group)
    group_ends: BTreeMap<u64, u64>,
    default_priority: u8,
    group_order: GroupOrder,
    dynamic_groups: bool,
    max_cache: Option<Duration>,
    objects: BTreeMap<Location, Cached>,
    /// Locations known not to exist, and Gone (from FETCH responses)
    gone: Vec<(Location, Location)>,
    publishers: Vec<Arc<dyn Upstream>>,
    subscribers: usize,
    malformed: bool,
    last_used: Instant,
    outstanding_new_group: Option<u64>,
}

impl Track {
    fn new(name: TrackName, depth: usize) -> Self {
        Self {
            name,
            state: Mutex::new(TrackState {
                properties: Bytes::new(),
                largest: None,
                end_of_track: None,
                group_ends: BTreeMap::new(),
                default_priority: 128,
                group_order: GroupOrder::Ascending,
                dynamic_groups: false,
                max_cache: None,
                objects: BTreeMap::new(),
                gone: Vec::new(),
                publishers: Vec::new(),
                subscribers: 0,
                malformed: false,
                last_used: Instant::now(),
                outstanding_new_group: None,
            }),
            events: broadcast::channel(depth).0,
            publisher_arrived: Notify::new(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TrackState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        let mut s = self.lock();
        s.subscribers += 1;
        s.last_used = Instant::now();
        self.events.subscribe()
    }

    pub fn unsubscribe(&self) {
        let mut s = self.lock();
        s.subscribers = s.subscribers.saturating_sub(1);
        s.last_used = Instant::now();
    }

    pub fn largest(&self) -> Option<Location> {
        self.lock().largest
    }

    pub fn properties(&self) -> Bytes {
        self.lock().properties.clone()
    }

    pub fn default_priority(&self) -> u8 {
        self.lock().default_priority
    }

    pub fn group_order(&self) -> GroupOrder {
        self.lock().group_order
    }

    pub fn dynamic_groups(&self) -> bool {
        self.lock().dynamic_groups
    }

    pub fn has_publisher(&self) -> bool {
        !self.lock().publishers.is_empty()
    }

    pub fn is_malformed(&self) -> bool {
        self.lock().malformed
    }

    pub fn publishers(&self) -> Vec<Arc<dyn Upstream>> {
        self.lock().publishers.clone()
    }

    /// Set the track's properties from a publisher (PUBLISH or SUBSCRIBE_OK):
    /// the most recent set replaces the cached one (section 8.4). The ones
    /// the relay acts on are read; an out-of-range value is
    /// MALFORMED_KEY_VALUE, a Mandatory Track Property this relay does not
    /// understand is returned for UNSUPPORTED_EXTENSION.
    pub fn set_properties(&self, raw: Bytes) -> Result<Vec<u64>, SessionCode> {
        let kvps = Reader::new(&raw, SessionCode::MalformedKeyValue)
            .kvps_to_end()
            .map_err(|e| e.code)?;
        let mut s = self.lock();
        let mut unsupported = Vec::new();
        let flat = flatten(&kvps).map_err(|()| SessionCode::MalformedKeyValue)?;
        for kvp in &flat {
            match (kvp.kind, &kvp.value) {
                (PROP_DEFAULT_PUBLISHER_PRIORITY, KvpValue::Int(v)) => {
                    s.default_priority =
                        u8::try_from(*v).map_err(|_| SessionCode::MalformedKeyValue)?;
                }
                (PROP_DEFAULT_PUBLISHER_GROUP_ORDER, KvpValue::Int(v)) => {
                    s.group_order = match v {
                        1 => GroupOrder::Ascending,
                        2 => GroupOrder::Descending,
                        _ => return Err(SessionCode::MalformedKeyValue),
                    };
                }
                (PROP_DYNAMIC_GROUPS, KvpValue::Int(v)) => {
                    s.dynamic_groups = match v {
                        0 => false,
                        1 => true,
                        _ => return Err(SessionCode::MalformedKeyValue),
                    };
                }
                (PROP_MAX_CACHE_DURATION, KvpValue::Int(v)) => {
                    s.max_cache = Some(Duration::from_millis(*v));
                }
                (k, _) if MANDATORY_PROPERTIES.contains(&k) && !super::error::is_grease(k) => {
                    unsupported.push(k);
                }
                _ => {}
            }
        }
        s.properties = raw;
        Ok(unsupported)
    }

    /// Raise Largest Object to `loc` if it is larger (section 7.5).
    pub fn note_largest(&self, loc: Location) {
        let mut s = self.lock();
        if s.largest.is_none_or(|l| loc > l) {
            s.largest = Some(loc);
            if s.outstanding_new_group.is_some_and(|g| loc.group >= g) {
                s.outstanding_new_group = None;
            }
        }
    }

    pub fn attach_publisher(&self, upstream: Arc<dyn Upstream>) {
        let mut s = self.lock();
        if !s.publishers.iter().any(|p| p.id() == upstream.id()) {
            s.publishers.push(upstream);
        }
        s.malformed = false;
        drop(s);
        self.publisher_arrived.notify_waiters();
    }

    /// A publisher left: when it was the last, the track's subscribers are
    /// told the track ended.
    pub fn detach_publisher(&self, id: u64) {
        let last = {
            let mut s = self.lock();
            s.publishers.retain(|p| p.id() != id);
            s.publishers.is_empty()
        };
        if last {
            let _ = self.events.send(Event::Done {
                code: DoneCode::TrackEnded,
                reason: "the track's publisher left".into(),
            });
        }
    }

    /// Ask a publisher for a new group, once per Largest Group (section
    /// 9.19.19's relay rules).
    pub fn request_new_group(&self, value: u64) {
        let (publishers, send) = {
            let mut s = self.lock();
            let largest_group = s.largest.map(|l| l.group);
            let wanted = value == 0 || largest_group.is_none_or(|g| value > g);
            let already = s
                .outstanding_new_group
                .is_some_and(|o| o >= value && value != 0);
            if !s.dynamic_groups || !wanted || already {
                (Vec::new(), false)
            } else {
                s.outstanding_new_group = Some(value.max(largest_group.map_or(0, |g| g + 1)));
                (s.publishers.clone(), true)
            }
        };
        if send {
            for p in publishers {
                p.new_group(&self.name, value);
            }
        }
    }

    /// Mark the track malformed (section 12.1): its subscribers are ended
    /// with MALFORMED_TRACK and nothing more of it is cached until a
    /// publisher attaches again.
    pub fn mark_malformed(&self, why: &str) {
        let mut s = self.lock();
        if s.malformed {
            return;
        }
        s.malformed = true;
        s.objects.clear();
        drop(s);
        let _ = self.events.send(Event::Done {
            code: DoneCode::MalformedTrack,
            reason: why.into(),
        });
    }

    /// The state of one Location in the cache.
    pub fn lookup(&self, loc: Location) -> Lookup {
        let s = self.lock();
        if let Some(c) = s.objects.get(&loc) {
            if s.max_cache.is_none_or(|m| c.received.elapsed() < m) {
                return Lookup::Exists(Arc::clone(&c.object));
            }
        }
        if s.gone.iter().any(|&(a, b)| a <= loc && loc <= b) {
            return Lookup::Gone;
        }
        if s.end_of_track.is_some_and(|e| loc > e)
            || s.group_ends
                .get(&loc.group)
                .is_some_and(|&last| loc.object > last)
        {
            return Lookup::DoesNotExist;
        }
        Lookup::Unknown
    }

    /// Cached objects in `start..=end`, in Location order.
    pub fn cached_range(&self, start: Location, end: Location) -> Vec<Arc<Object>> {
        let s = self.lock();
        s.objects
            .range(start..=end)
            .filter(|(_, c)| s.max_cache.is_none_or(|m| c.received.elapsed() < m))
            .map(|(_, c)| Arc::clone(&c.object))
            .collect()
    }

    /// Whether `group`'s last object is known, and which it is.
    pub fn group_end(&self, group: u64) -> Option<u64> {
        self.lock().group_ends.get(&group).copied()
    }

    pub fn end_of_track(&self) -> Option<Location> {
        self.lock().end_of_track
    }

    pub fn note_gone(&self, start: Location, end: Location) {
        let mut s = self.lock();
        if s.gone.len() < 1024 {
            s.gone.push((start, end));
        }
    }

    pub fn note_group_end(&self, group: u64, last: u64) {
        self.lock().group_ends.insert(group, last);
    }

    pub fn subscriber_count(&self) -> usize {
        self.lock().subscribers
    }

    pub fn cached_bytes(&self) -> usize {
        self.lock().objects.values().map(|c| c.object.size()).sum()
    }

    pub fn idle_for(&self) -> Duration {
        self.lock().last_used.elapsed()
    }
}

/// A Location's state in the cache (section 2.1.2).
#[derive(Debug, Clone)]
pub enum Lookup {
    Exists(Arc<Object>),
    DoesNotExist,
    Gone,
    Unknown,
}

/// Properties with the contents of Immutable Properties alongside, since a
/// processor looks in both (section 10.7). An Immutable Properties inside
/// another is malformed.
fn flatten(kvps: &[Kvp]) -> Result<Vec<Kvp>, ()> {
    let mut out = Vec::with_capacity(kvps.len());
    for kvp in kvps {
        if kvp.kind == PROP_IMMUTABLE {
            let KvpValue::Bytes(inner) = &kvp.value else {
                return Err(());
            };
            let inner = Reader::new(inner, SessionCode::MalformedKeyValue)
                .kvps_to_end()
                .map_err(|_| ())?;
            if inner.iter().any(|k| k.kind == PROP_IMMUTABLE) {
                return Err(());
            }
            out.extend(inner);
        } else {
            out.push(kvp.clone());
        }
    }
    Ok(out)
}

/// A namespace a publisher advertised with PUBLISH_NAMESPACE.
#[derive(Clone)]
pub struct Advertisement {
    pub prefix: Namespace,
    pub publisher: Arc<dyn NamespacePublisher>,
    pub id: u64,
}

/// The session of a publisher that advertised a namespace: the relay
/// subscribes through it to tracks in the namespace (section 7.7).
pub trait NamespacePublisher: Send + Sync + 'static {
    /// Subscribe upstream to `track`; resolves to the track once the
    /// upstream SUBSCRIBE_OK has arrived, or the request's error.
    fn subscribe_upstream(
        &self,
        track: Arc<Track>,
        new_group_request: Option<u64>,
    ) -> futures_util::future::BoxFuture<'static, Result<(), (u64, String)>>;
    /// FETCH `start..=end` of `track` through this publisher (section
    /// 3.2.3): what the cache lacks of a track in the namespace, whether or
    /// not the relay is subscribed to it now. A finished track's upstream
    /// subscription ends with its last object, and every FETCH past the
    /// cache came back Unknown.
    fn fetch_through(
        &self,
        track: TrackName,
        start: Location,
        end: Location,
        timeout: Duration,
    ) -> futures_util::future::BoxFuture<'static, Option<mpsc::Receiver<super::data::FetchEntry>>>;
    fn session_id(&self) -> u64;
}

/// What SUBSCRIBE_NAMESPACE watchers hear (section 9.15, 9.16).
#[derive(Debug, Clone)]
pub enum NamespaceEvent {
    Added(Namespace),
    Removed(Namespace),
}

/// What SUBSCRIBE_TRACKS watchers hear: a track that has a publisher now.
#[derive(Clone)]
pub struct TrackArrived(pub Arc<Track>);

/// The relay: every session on the node shares it.
pub struct Relay {
    pub limits: Limits,
    tracks: Mutex<HashMap<TrackName, Arc<Track>>>,
    /// Every cached object, oldest first, for eviction across tracks
    lru: Mutex<VecDeque<(Weak<Track>, Location, usize)>>,
    cached: AtomicUsize,
    advertisements: Mutex<Vec<Advertisement>>,
    namespace_watchers: Mutex<Vec<(u64, Namespace, mpsc::UnboundedSender<NamespaceEvent>)>>,
    track_watchers: Mutex<Vec<(u64, Namespace, mpsc::UnboundedSender<TrackArrived>)>>,
    next_id: AtomicU64,
    sessions: Mutex<HashMap<u64, super::session::SessionInfo>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    /// The upstream relay asked for every namespace no local publisher
    /// advertises (`[moq] upstream`)
    upstream: std::sync::OnceLock<Arc<dyn NamespacePublisher>>,
    pub stats: Stats,
}

/// Counters for `/metrics` and the admin API.
#[derive(Default)]
pub struct Stats {
    pub sessions_total: AtomicU64,
    pub sessions_open: AtomicU64,
    pub objects_in: AtomicU64,
    pub objects_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_evictions: AtomicU64,
    pub subscribes: AtomicU64,
    pub fetches: AtomicU64,
    pub requests_refused: AtomicU64,
    pub session_errors: AtomicU64,
    pub too_far_behind: AtomicU64,
}

impl Relay {
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            tracks: Mutex::new(HashMap::new()),
            lru: Mutex::new(VecDeque::new()),
            cached: AtomicUsize::new(0),
            advertisements: Mutex::new(Vec::new()),
            namespace_watchers: Mutex::new(Vec::new()),
            track_watchers: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            sessions: Mutex::new(HashMap::new()),
            shutdown: tokio::sync::watch::channel(false).0,
            upstream: std::sync::OnceLock::new(),
            stats: Stats::default(),
        })
    }

    // ── Sessions ────────────────────────────────────────────────────────────

    pub fn register_session(&self, info: super::session::SessionInfo) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(info.id, info);
    }

    /// A registered session's new details; a session that has ended is not
    /// brought back by a late update
    pub fn update_session(&self, info: super::session::SessionInfo) {
        if let Some(entry) = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_mut(&info.id)
        {
            *entry = info;
        }
    }

    pub fn unregister_session(&self, id: u64) {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
    }

    /// The open sessions, for the admin API.
    pub fn sessions(&self) -> Vec<super::session::SessionInfo> {
        let mut v: Vec<_> = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .map(|mut s| {
                s.age_secs = s.started.map_or(0, |t| t.elapsed().as_secs());
                s
            })
            .collect();
        v.sort_by_key(|s| s.id);
        v
    }

    /// What every session watches for the relay's drain: GOAWAY, then the
    /// session's close after its timeout (section 6.6.1).
    pub fn shutdown_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn begin_shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// A process-unique identifier for sessions, advertisements, watchers.
    pub fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The track, created when it is new; `None` past the track limit.
    pub fn track(&self, name: &TrackName) -> Option<Arc<Track>> {
        let mut tracks = self
            .tracks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = tracks.get(name) {
            return Some(Arc::clone(t));
        }
        if tracks.len() >= self.limits.max_tracks {
            // Make room from tracks nobody uses
            tracks.retain(|_, t| {
                t.subscriber_count() > 0
                    || t.has_publisher()
                    || t.idle_for() < Duration::from_secs(60)
            });
            if tracks.len() >= self.limits.max_tracks {
                return None;
            }
        }
        let t = Arc::new(Track::new(name.clone(), self.limits.broadcast_depth));
        tracks.insert(name.clone(), Arc::clone(&t));
        Some(t)
    }

    /// The track if it exists.
    pub fn existing(&self, name: &TrackName) -> Option<Arc<Track>> {
        self.tracks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    pub fn tracks(&self) -> Vec<Arc<Track>> {
        self.tracks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    /// Take in an object from a publisher: cached once, sent to the track's
    /// subscribers. A second copy of a cached object is checked against it
    /// (section 7.1): a different delivery, priority or payload makes the
    /// track malformed; an identical one is not sent again.
    pub fn ingest(
        &self,
        track: &Arc<Track>,
        object: Object,
        upstream_stream: Option<u64>,
        first_in_subgroup: bool,
        end_of_group_stream: bool,
    ) {
        let loc = object.location;
        let size = object.size();
        self.stats.objects_in.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_in
            .fetch_add(object.payload.len() as u64, Ordering::Relaxed);
        let object = Arc::new(object);
        {
            let mut s = track.lock();
            if s.malformed {
                return;
            }
            if let Some(c) = s.objects.get(&loc) {
                let o = &c.object;
                if o.delivery != object.delivery
                    || o.priority != object.priority
                    || o.payload != object.payload
                {
                    drop(s);
                    track.mark_malformed("an object received twice with different contents");
                    return;
                }
                return;
            }
            // Past the track's end, or the group's (section 12.1)
            if s.end_of_track.is_some_and(|e| loc > e)
                || s.group_ends
                    .get(&loc.group)
                    .is_some_and(|&last| loc.object > last)
            {
                drop(s);
                track.mark_malformed("an object after the end of its group or track");
                return;
            }
            match object.status {
                ObjectStatus::EndOfGroup => {
                    s.group_ends.insert(loc.group, loc.object);
                }
                ObjectStatus::EndOfTrack => {
                    s.end_of_track = Some(loc);
                    s.group_ends.insert(loc.group, loc.object);
                }
                ObjectStatus::Normal => {}
            }
            if s.largest.is_none_or(|l| loc > l) {
                s.largest = Some(loc);
                if s.outstanding_new_group.is_some_and(|g| loc.group >= g) {
                    s.outstanding_new_group = None;
                }
            }
            s.objects.insert(
                loc,
                Cached {
                    object: Arc::clone(&object),
                    received: Instant::now(),
                },
            );
        }
        self.lru
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back((Arc::downgrade(track), loc, size));
        self.cached.fetch_add(size, Ordering::Relaxed);
        self.evict();
        let _ = track.events.send(Event::Object {
            object,
            upstream_stream,
            first_in_subgroup,
            end_of_group_stream,
        });
    }

    /// An upstream subgroup stream ended.
    pub fn subgroup_ended(
        &self,
        track: &Track,
        upstream_stream: u64,
        group: u64,
        subgroup: u64,
        complete: bool,
    ) {
        let _ = track.events.send(Event::SubgroupEnd {
            upstream_stream,
            group,
            subgroup,
            complete,
        });
    }

    /// Drop the oldest objects until the cache fits its budget.
    fn evict(&self) {
        let budget = self.limits.cache_bytes;
        if self.cached.load(Ordering::Relaxed) <= budget {
            return;
        }
        let mut lru = self
            .lru
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while self.cached.load(Ordering::Relaxed) > budget {
            let Some((track, loc, size)) = lru.pop_front() else {
                break;
            };
            self.cached.fetch_sub(size, Ordering::Relaxed);
            if let Some(t) = track.upgrade() {
                t.lock().objects.remove(&loc);
                self.stats.cache_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn cached_bytes(&self) -> usize {
        self.cached.load(Ordering::Relaxed)
    }

    // ── Namespaces ──────────────────────────────────────────────────────────

    /// A publisher advertised `prefix` (PUBLISH_NAMESPACE): watchers whose
    /// prefix matches hear of it, and tracks in it that have subscribers but
    /// no publisher are subscribed upstream through it (section 7.7).
    pub fn advertise(&self, ad: Advertisement) -> u64 {
        let id = ad.id;
        {
            let watchers = self
                .namespace_watchers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (_, prefix, tx) in watchers.iter() {
                if prefix.is_prefix_of(&ad.prefix) || ad.prefix.is_prefix_of(prefix) {
                    let _ = tx.send(NamespaceEvent::Added(ad.prefix.clone()));
                }
            }
        }
        for t in self.tracks() {
            if ad.prefix.is_prefix_of(&t.name.namespace)
                && t.subscriber_count() > 0
                && !t.has_publisher()
            {
                let fut = ad.publisher.subscribe_upstream(Arc::clone(&t), None);
                tokio::spawn(async move {
                    let _ = fut.await;
                });
            }
        }
        self.advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(ad);
        id
    }

    pub fn withdraw(&self, id: u64) {
        let removed: Vec<Namespace> = {
            let mut ads = self
                .advertisements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let gone = ads
                .iter()
                .filter(|a| a.id == id)
                .map(|a| a.prefix.clone())
                .collect();
            ads.retain(|a| a.id != id);
            gone
        };
        let still: Vec<Namespace> = self.advertised_prefixes();
        let watchers = self
            .namespace_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for prefix in removed {
            // Another publisher may still advertise the same namespace
            if still.contains(&prefix) {
                continue;
            }
            for (_, w, tx) in watchers.iter() {
                if w.is_prefix_of(&prefix) || prefix.is_prefix_of(w) {
                    let _ = tx.send(NamespaceEvent::Removed(prefix.clone()));
                }
            }
        }
    }

    /// Every session's advertisements end when it does.
    pub fn withdraw_session(&self, session: u64) {
        let ids: Vec<u64> = self
            .advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|a| a.publisher.session_id() == session)
            .map(|a| a.id)
            .collect();
        for id in ids {
            self.withdraw(id);
        }
    }

    pub fn advertised_prefixes(&self) -> Vec<Namespace> {
        let mut v: Vec<Namespace> = self
            .advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|a| a.prefix.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Publishers whose advertised prefix matches `namespace`; with none,
    /// the upstream relay, where there is one.
    pub fn publishers_for(&self, namespace: &Namespace) -> Vec<Advertisement> {
        let local: Vec<Advertisement> = self
            .advertisements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|a| a.prefix.is_prefix_of(namespace))
            .cloned()
            .collect();
        if !local.is_empty() {
            return local;
        }
        self.upstream
            .get()
            .map(|up| Advertisement {
                prefix: Namespace::default(),
                publisher: Arc::clone(up),
                id: 0,
            })
            .into_iter()
            .collect()
    }

    /// Ask `upstream` for every namespace no local publisher advertises.
    pub fn set_upstream(&self, upstream: Arc<dyn NamespacePublisher>) {
        let _ = self.upstream.set(upstream);
    }

    /// Register a SUBSCRIBE_NAMESPACE: the namespaces advertised now under
    /// `prefix`, and a channel of changes; `None` when there are more than
    /// the relay enumerates (NAMESPACE_TOO_LARGE, section 7.6).
    pub fn watch_namespaces(
        &self,
        prefix: Namespace,
    ) -> Option<(u64, Vec<Namespace>, mpsc::UnboundedReceiver<NamespaceEvent>)> {
        let now: Vec<Namespace> = self
            .advertised_prefixes()
            .into_iter()
            .filter(|ns| prefix.is_prefix_of(ns))
            .collect();
        if now.len() > self.limits.namespace_enumeration_max {
            return None;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.next_id();
        self.namespace_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((id, prefix, tx));
        Some((id, now, rx))
    }

    pub fn update_namespace_watch(&self, id: u64, prefix: Namespace) {
        let mut w = self
            .namespace_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = w.iter_mut().find(|e| e.0 == id) {
            entry.1 = prefix;
        }
    }

    pub fn unwatch_namespaces(&self, id: u64) {
        self.namespace_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|e| e.0 != id);
    }

    /// Register a SUBSCRIBE_TRACKS: the tracks under `prefix` that have a
    /// publisher now, and a channel of tracks that gain one.
    pub fn watch_tracks(
        &self,
        prefix: Namespace,
    ) -> (u64, Vec<Arc<Track>>, mpsc::UnboundedReceiver<TrackArrived>) {
        let now = self
            .tracks()
            .into_iter()
            .filter(|t| prefix.is_prefix_of(&t.name.namespace) && t.has_publisher())
            .collect();
        let (tx, rx) = mpsc::unbounded_channel();
        let id = self.next_id();
        self.track_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((id, prefix, tx));
        (id, now, rx)
    }

    pub fn update_track_watch(&self, id: u64, prefix: Namespace) {
        let mut w = self
            .track_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = w.iter_mut().find(|e| e.0 == id) {
            entry.1 = prefix;
        }
    }

    pub fn unwatch_tracks(&self, id: u64) {
        self.track_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|e| e.0 != id);
    }

    /// A track gained a publisher through PUBLISH: SUBSCRIBE_TRACKS watchers
    /// whose prefix matches are offered it (section 7.7).
    pub fn track_published(&self, track: &Arc<Track>) {
        let watchers = self
            .track_watchers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (_, prefix, tx) in watchers.iter() {
            if prefix.is_prefix_of(&track.name.namespace) {
                let _ = tx.send(TrackArrived(Arc::clone(track)));
            }
        }
    }

    /// Drop tracks nobody publishes, subscribes to or has used for a while,
    /// with their cached objects.
    pub fn sweep(&self, idle: Duration) {
        let mut tracks = self
            .tracks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tracks.retain(|_, t| t.subscriber_count() > 0 || t.has_publisher() || t.idle_for() < idle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::moq::data::Delivery;

    /// A session's late update (its SETUP read after it ended) does not
    /// register it again
    #[test]
    fn an_ended_session_is_not_registered_again_by_an_update() {
        let relay = Relay::new(Limits::default());
        let info = || crate::moq::session::SessionInfo {
            id: 7,
            peer: "192.0.2.1:443".into(),
            transport: "webtransport",
            version: "moqt-23".into(),
            role: "server",
            implementation: None,
            path: Some("/moq".into()),
            started: None,
            age_secs: 0,
        };
        relay.register_session(info());
        relay.update_session(crate::moq::session::SessionInfo {
            implementation: Some("a client".into()),
            ..info()
        });
        assert_eq!(
            relay.sessions()[0].implementation.as_deref(),
            Some("a client")
        );
        relay.unregister_session(7);
        relay.update_session(info());
        assert!(relay.sessions().is_empty());
    }

    fn name() -> TrackName {
        TrackName {
            namespace: Namespace(vec![Bytes::from_static(b"t")]),
            name: Bytes::from_static(b"a"),
        }
    }

    fn obj(g: u64, o: u64, payload: &'static [u8]) -> Object {
        Object {
            location: Location::new(g, o),
            delivery: Delivery::Subgroup(0),
            priority: 1,
            status: ObjectStatus::Normal,
            properties: Bytes::new(),
            payload: Bytes::from_static(payload),
        }
    }

    #[tokio::test]
    async fn objects_are_cached_once_and_broadcast() {
        let relay = Relay::new(Limits::default());
        let t = relay.track(&name()).unwrap();
        let mut rx = t.subscribe();
        relay.ingest(&t, obj(1, 0, b"a"), Some(4), true, false);
        relay.ingest(&t, obj(1, 0, b"a"), Some(8), true, false); // a duplicate
        assert!(matches!(rx.recv().await.unwrap(), Event::Object { .. }));
        assert!(rx.try_recv().is_err(), "the duplicate was sent again");
        assert_eq!(t.largest(), Some(Location::new(1, 0)));
        assert!(matches!(t.lookup(Location::new(1, 0)), Lookup::Exists(_)));
        assert!(matches!(t.lookup(Location::new(1, 1)), Lookup::Unknown));
    }

    #[tokio::test]
    async fn a_conflicting_copy_makes_the_track_malformed() {
        let relay = Relay::new(Limits::default());
        let t = relay.track(&name()).unwrap();
        let mut rx = t.subscribe();
        relay.ingest(&t, obj(1, 0, b"a"), None, false, false);
        relay.ingest(&t, obj(1, 0, b"b"), None, false, false);
        let _ = rx.recv().await;
        match rx.recv().await.unwrap() {
            Event::Done { code, .. } => assert_eq!(code, DoneCode::MalformedTrack),
            other => panic!("{other:?}"),
        }
        assert!(t.is_malformed());
    }

    #[test]
    fn objects_past_the_end_of_group_are_malformed() {
        let relay = Relay::new(Limits::default());
        let t = relay.track(&name()).unwrap();
        relay.ingest(
            &t,
            Object {
                status: ObjectStatus::EndOfGroup,
                payload: Bytes::new(),
                ..obj(2, 3, b"")
            },
            None,
            false,
            false,
        );
        assert!(matches!(
            t.lookup(Location::new(2, 4)),
            Lookup::DoesNotExist
        ));
        relay.ingest(&t, obj(2, 5, b"late"), None, false, false);
        assert!(t.is_malformed());
    }

    #[test]
    fn the_cache_keeps_to_its_budget() {
        let relay = Relay::new(Limits {
            cache_bytes: 1000,
            ..Limits::default()
        });
        let t = relay.track(&name()).unwrap();
        for i in 0..100 {
            relay.ingest(&t, obj(i, 0, b"0123456789"), None, false, false);
        }
        assert!(relay.cached_bytes() <= 1000);
        assert!(matches!(t.lookup(Location::new(99, 0)), Lookup::Exists(_)));
        assert!(matches!(t.lookup(Location::new(0, 0)), Lookup::Unknown));
    }

    #[test]
    fn properties_are_read_and_validated() {
        let relay = Relay::new(Limits::default());
        let t = relay.track(&name()).unwrap();
        let mut raw = Vec::new();
        crate::moq::codec::put_kvps(
            &mut raw,
            &[
                Kvp {
                    kind: PROP_DEFAULT_PUBLISHER_PRIORITY,
                    value: KvpValue::Int(9),
                },
                Kvp {
                    kind: PROP_DEFAULT_PUBLISHER_GROUP_ORDER,
                    value: KvpValue::Int(2),
                },
                Kvp {
                    kind: 0x4002,
                    value: KvpValue::Int(1),
                },
            ],
        );
        let unsupported = t.set_properties(Bytes::from(raw)).unwrap();
        assert_eq!(unsupported, vec![0x4002]);
        assert_eq!(t.default_priority(), 9);
        assert_eq!(t.group_order(), GroupOrder::Descending);
        let mut bad = Vec::new();
        crate::moq::codec::put_kvps(
            &mut bad,
            &[Kvp {
                kind: PROP_DEFAULT_PUBLISHER_PRIORITY,
                value: KvpValue::Int(300),
            }],
        );
        assert_eq!(
            t.set_properties(Bytes::from(bad)).unwrap_err(),
            SessionCode::MalformedKeyValue
        );
    }
}
