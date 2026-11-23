//! Media over QUIC Transport (draft-ietf-moq-transport): a relay on the QUIC
//! listener, beside HTTP/3 and DNS over QUIC.
//!
//! A client reaches it two ways (section 6.2), both selected by protocol
//! negotiation and never by port:
//! - native QUIC: the client offers a MOQT ALPN (`moqt-23`, `moqt-22`) on
//!   the QUIC listener's port; the connection is a MOQT session;
//! - WebTransport: an extended CONNECT to `[moq] path` on the HTTP/3 port or
//!   the WebTransport server's own, with `WT-Available-Protocols` naming the
//!   versions; the server answers `WT-Protocol` with the one it chose.
//!
//! [`version`] lists the versions; [`codec`], [`message`] and [`data`] are
//! the wire; [`session`] is one session, either role; [`relay`] is what the
//! sessions share: tracks, the object cache, the namespaces publishers
//! advertise. Publishing needs a token ([`auth`]); subscribing does not.

pub mod auth;
pub mod codec;
pub mod data;
pub mod error;
pub mod message;
pub mod relay;
pub mod session;
pub mod transport;
pub mod upstream;
pub mod version;

#[cfg(test)]
mod e2e;

/// The MoQ decoders on arbitrary bytes, for the fuzz targets and the
/// mutation tests: nothing may panic, and whatever decodes re-encodes to the
/// same message.
pub mod check {
    use super::data::{
        decode_datagram, read_subgroup_object, DatagramKind, FetchState, SubgroupHeader,
    };
    use super::message::{allowed, Context, GroupOrder, Message, Setup};
    use super::version::Version;

    /// Every message type this relay knows, by the version in the first byte.
    const TYPES: [u64; 20] = [
        super::message::SETUP,
        super::message::GOAWAY,
        super::message::SUBSCRIBE,
        super::message::SUBSCRIBE_OK,
        super::message::PUBLISH_STATE_NOTIFY,
        super::message::PUBLISH,
        super::message::PUBLISH_DONE,
        super::message::FETCH,
        super::message::FETCH_OK_22,
        super::message::TRACK_STATUS,
        super::message::PUBLISH_NAMESPACE,
        super::message::SUBSCRIBE_NAMESPACE,
        super::message::SUBSCRIBE_TRACKS,
        super::message::NAMESPACE,
        super::message::NAMESPACE_DONE,
        super::message::PUBLISH_SKIPPED,
        super::message::REQUEST_UPDATE,
        super::message::REQUEST_OK,
        super::message::REQUEST_ERROR,
        0x7777,
    ];

    fn version(data: &[u8]) -> (Version, usize, &[u8]) {
        let v = Version::ALL[usize::from(data.first().copied().unwrap_or(0)) % Version::ALL.len()];
        let kind = usize::from(data.get(1).copied().unwrap_or(0)) % TYPES.len();
        (v, kind, data.get(2..).unwrap_or_default())
    }

    /// A control message body: decoded as the type the second byte picks,
    /// then encoded and decoded again to the same message.
    pub fn control(data: &[u8]) {
        let (v, kind, body) = version(data);
        let ctx = Context {
            update_allows: allowed::update_subscription(),
            ok_allows: allowed::ok_with_largest(),
            ok_properties: true,
        };
        let kind = TYPES[kind];
        if let Ok(m) = Message::decode(kind, body, v, &ctx) {
            // Parameters that cannot be honoured are kept for the request's
            // own error, not re-encoded
            let unencodable = |p: &super::message::Params| {
                p.filter_error.is_some() || !p.removed_filters.is_empty()
            };
            let skip = match &m {
                Message::Subscribe(r) | Message::Fetch(r) | Message::TrackStatus(r) => {
                    unencodable(&r.params)
                }
                Message::SubscribeTracks(r) => unencodable(&r.params),
                Message::RequestUpdate { params, .. } => unencodable(params),
                // A Reason Phrase that was not UTF-8 is kept as text with
                // replacement characters, which can outgrow its 1024 bytes
                Message::PublishDone { reason, .. } => reason.contains('\u{FFFD}'),
                Message::RequestError(e) => e.reason.contains('\u{FFFD}'),
                _ => false,
            };
            if skip {
                return;
            }
            let again = m.encode_body(v);
            let back = Message::decode(kind, &again, v, &ctx)
                .expect("a message the relay encodes decodes");
            match (&m, &back) {
                (Message::Setup(a), Message::Setup(b)) => {
                    assert_eq!(
                        Setup {
                            options: Vec::new(),
                            ..a.clone()
                        },
                        Setup {
                            options: Vec::new(),
                            ..b.clone()
                        }
                    );
                }
                _ => assert_eq!(m, back, "a decoded message re-encodes to itself"),
            }
        }
    }

    /// A datagram, a subgroup stream and a FETCH stream, each read to its
    /// end or first error.
    pub fn data(data: &[u8]) {
        let (v, _, body) = version(data);
        if let Ok(DatagramKind::Object(d)) = decode_datagram(body) {
            assert!(d.status == super::data::ObjectStatus::Normal || d.payload.is_empty());
        }
        let block = |f: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>>| {
            futures::executor::block_on(f);
        };
        block(Box::pin(async {
            let mut r = body;
            if let Ok(Some(flags)) = super::codec::read_vi64(&mut r).await {
                if let Ok(h) = SubgroupHeader::read(flags, &mut r).await {
                    let mut prior = None;
                    while let Ok(Some((id, ..))) =
                        read_subgroup_object(&mut r, &h, prior, 1 << 16).await
                    {
                        assert!(
                            prior.is_none_or(|p| id > p),
                            "object IDs rise on a subgroup stream"
                        );
                        prior = Some(id);
                    }
                }
            }
        }));
        block(Box::pin(async {
            for order in [GroupOrder::Ascending, GroupOrder::Descending] {
                let mut r = body;
                let mut state = FetchState::default();
                while let Ok(Some(_)) = state.read(&mut r, order, v, 1 << 16).await {}
            }
        }));
    }
}

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::MoqConfig;
use crate::wt_session::WtSession;
use relay::{Limits, Relay};
use session::{Role, Session, Settings};
use transport::{QuicTransport, WtTransport};
use version::Version;

/// The node's one relay: the QUIC listeners and the WebTransport server
/// share it, so a track published through one entrance is served through
/// every other. Its settings are read at start; a change to `[moq]` takes
/// effect at the next restart (which, socket-activated, refuses nothing).
static SHARED: std::sync::OnceLock<Arc<Moq>> = std::sync::OnceLock::new();

/// Start the relay where `[moq]` is on (once; later calls return it).
pub fn start(config: &MoqConfig) -> anyhow::Result<Option<Arc<Moq>>> {
    if !config.enabled {
        return Ok(None);
    }
    if let Some(m) = SHARED.get() {
        return Ok(Some(Arc::clone(m)));
    }
    let m = Moq::new(config)?;
    Ok(Some(Arc::clone(SHARED.get_or_init(|| m))))
}

/// The running relay, if `[moq]` is on.
pub fn running() -> Option<Arc<Moq>> {
    SHARED.get().cloned()
}

/// The relay and what its sessions are configured with.
pub struct Moq {
    pub relay: Arc<Relay>,
    pub settings: Arc<Settings>,
    /// The WebTransport path MoQ answers on
    pub path: String,
}

impl Moq {
    pub fn new(config: &MoqConfig) -> anyhow::Result<Arc<Self>> {
        let publish_auth = config
            .publish_key
            .as_deref()
            .filter(|k| !k.is_empty())
            .map(|k| auth::PublishAuth::new(k.as_bytes()));
        let settings = Settings {
            implementation: format!("pqcrypta-proxy/{}", env!("CARGO_PKG_VERSION")),
            max_request_updates: config.max_request_updates,
            max_filter_ranges: config.max_filter_ranges,
            max_auth_token_cache: config.max_auth_token_cache,
            max_control_message: config
                .max_control_message
                .max(message::DEFAULT_MAX_CONTROL_MESSAGE),
            paths: std::iter::once(config.path.clone())
                .chain(config.extra_paths.iter().cloned())
                .collect(),
            authorities: config.authorities.clone(),
            publish_auth,
            goaway_timeout: Duration::from_millis(config.goaway_timeout_ms),
            limiter: std::sync::OnceLock::new(),
        };
        let limits = Limits {
            cache_bytes: config.cache_mb.saturating_mul(1 << 20),
            max_object: config.max_object_kb.saturating_mul(1 << 10),
            rendezvous_max: Duration::from_millis(config.rendezvous_max_ms),
            fill_timeout: Duration::from_millis(config.fill_timeout_ms),
            max_tracks: config.max_tracks,
            ..Limits::default()
        };
        let relay = Relay::new(limits);
        let settings = Arc::new(settings);
        if !config.upstream.is_empty() {
            let uri = upstream::UpstreamUri::parse(&config.upstream)?;
            let link = upstream::UpstreamLink::new(uri, &relay, Arc::clone(&settings))?;
            relay.set_upstream(Arc::new(upstream::UpstreamPublisher(link)));
        }
        // Tracks nobody uses are swept with their cached objects
        let sweeper = Arc::downgrade(&relay);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let Some(relay) = sweeper.upgrade() else {
                    return;
                };
                relay.sweep(Duration::from_secs(600));
            }
        });
        Ok(Arc::new(Self {
            relay,
            settings,
            path: config.path.clone(),
        }))
    }

    /// Serve a QUIC connection from `peer` whose ALPN is `alpn`, a MOQT
    /// version.
    pub async fn serve_quic(
        self: Arc<Self>,
        connection: quinn::Connection,
        alpn: &[u8],
        peer: SocketAddr,
    ) {
        let Some(version) = Version::from_alpn(alpn) else {
            connection.close(
                quinn::VarInt::from_u32(0x3),
                b"not a MOQT version this relay speaks",
            );
            return;
        };
        let session = Session::new(
            QuicTransport(connection, peer),
            version,
            Role::Server,
            Arc::clone(&self.relay),
            Arc::clone(&self.settings),
            None,
        );
        session.run(self.relay.shutdown_signal()).await;
    }

    /// Serve a WebTransport session that negotiated `version`.
    pub async fn serve_webtransport<S: WtSession>(
        self: Arc<Self>,
        session: Arc<S>,
        peer: SocketAddr,
        version: Version,
        path: String,
    ) {
        let session = Session::new(
            WtTransport::new(session, peer),
            version,
            Role::Server,
            Arc::clone(&self.relay),
            Arc::clone(&self.settings),
            Some(path),
        );
        session.run(self.relay.shutdown_signal()).await;
    }

    /// Ask every session to drain (GOAWAY), as the proxy shuts down.
    pub fn begin_shutdown(&self) {
        self.relay.begin_shutdown();
    }

    /// The figures `/metrics` and the admin API show.
    pub fn snapshot(&self) -> MoqSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let s = &self.relay.stats;
        MoqSnapshot {
            versions: Version::ALL.iter().map(|v| v.alpn()).collect(),
            path: self.path.clone(),
            sessions_open: s.sessions_open.load(Relaxed),
            sessions_total: s.sessions_total.load(Relaxed),
            tracks: self.relay.tracks().len(),
            namespaces: self.relay.advertised_prefixes().len(),
            cache_bytes: self.relay.cached_bytes(),
            objects_in: s.objects_in.load(Relaxed),
            objects_out: s.objects_out.load(Relaxed),
            bytes_in: s.bytes_in.load(Relaxed),
            bytes_out: s.bytes_out.load(Relaxed),
            subscribes: s.subscribes.load(Relaxed),
            fetches: s.fetches.load(Relaxed),
            requests_refused: s.requests_refused.load(Relaxed),
            session_errors: s.session_errors.load(Relaxed),
            cache_evictions: s.cache_evictions.load(Relaxed),
            too_far_behind: s.too_far_behind.load(Relaxed),
            publishing_enabled: self.settings.publish_auth.is_some(),
        }
    }
}

impl Moq {
    /// The relay's counters and gauges in Prometheus' text format.
    pub fn export_prometheus(&self, out: &mut String) {
        use std::fmt::Write;
        let s = self.snapshot();
        let mut put = |name: &str, kind: &str, help: &str, value: u64| {
            let _ = writeln!(out, "# HELP pqcrypta_moq_{name} {help}");
            let _ = writeln!(out, "# TYPE pqcrypta_moq_{name} {kind}");
            let _ = writeln!(out, "pqcrypta_moq_{name} {value}");
        };
        put(
            "sessions_open",
            "gauge",
            "MoQ sessions open now",
            s.sessions_open,
        );
        put(
            "sessions_total",
            "counter",
            "MoQ sessions accepted",
            s.sessions_total,
        );
        put("tracks", "gauge", "Tracks the relay holds", s.tracks as u64);
        put(
            "namespaces",
            "gauge",
            "Namespaces publishers advertise",
            s.namespaces as u64,
        );
        put(
            "cache_bytes",
            "gauge",
            "Bytes of objects cached",
            s.cache_bytes as u64,
        );
        put(
            "objects_in_total",
            "counter",
            "Objects received from publishers",
            s.objects_in,
        );
        put(
            "objects_out_total",
            "counter",
            "Objects sent to subscribers and fetches",
            s.objects_out,
        );
        put(
            "payload_bytes_in_total",
            "counter",
            "Object payload bytes received",
            s.bytes_in,
        );
        put(
            "payload_bytes_out_total",
            "counter",
            "Object payload bytes sent",
            s.bytes_out,
        );
        put(
            "subscribes_total",
            "counter",
            "SUBSCRIBE requests",
            s.subscribes,
        );
        put("fetches_total", "counter", "FETCH requests", s.fetches);
        put(
            "requests_refused_total",
            "counter",
            "Requests answered with REQUEST_ERROR",
            s.requests_refused,
        );
        put(
            "session_errors_total",
            "counter",
            "Sessions closed with an error",
            s.session_errors,
        );
        put(
            "cache_evictions_total",
            "counter",
            "Objects evicted from the cache",
            s.cache_evictions,
        );
        put(
            "too_far_behind_total",
            "counter",
            "Subscriptions ended as too far behind",
            s.too_far_behind,
        );
        for v in Version::ALL {
            let _ = writeln!(
                out,
                "pqcrypta_moq_version_info{{version=\"{}\"}} 1",
                v.alpn()
            );
        }
    }

    /// The tracks the relay holds, for the admin API.
    pub fn tracks_view(&self) -> Vec<TrackView> {
        let mut v: Vec<TrackView> = self
            .relay
            .tracks()
            .into_iter()
            .map(|t| TrackView {
                track: t.name.to_string(),
                largest: t.largest(),
                publishers: t.publishers().len(),
                subscribers: t.subscriber_count(),
                cached_bytes: t.cached_bytes(),
                malformed: t.is_malformed(),
            })
            .collect();
        v.sort_by(|a, b| a.track.cmp(&b.track));
        v
    }

    /// The namespaces publishers advertise, in section 8.8's serialized form.
    pub fn namespaces_view(&self) -> Vec<String> {
        self.relay
            .advertised_prefixes()
            .iter()
            .map(ToString::to_string)
            .collect()
    }
}

/// One track, as the admin API shows it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TrackView {
    pub track: String,
    pub largest: Option<codec::Location>,
    pub publishers: usize,
    pub subscribers: usize,
    pub cached_bytes: usize,
    pub malformed: bool,
}

/// The relay's figures.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MoqSnapshot {
    pub versions: Vec<&'static str>,
    pub path: String,
    pub sessions_open: u64,
    pub sessions_total: u64,
    pub tracks: usize,
    pub namespaces: usize,
    pub cache_bytes: usize,
    pub objects_in: u64,
    pub objects_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub subscribes: u64,
    pub fetches: u64,
    pub requests_refused: u64,
    pub session_errors: u64,
    pub cache_evictions: u64,
    pub too_far_behind: u64,
    pub publishing_enabled: bool,
}

/// The protocols a `WT-Available-Protocols` field lists.
///
/// The field is a Structured Field List whose members must all be Strings,
/// or the whole field is ignored (draft-ietf-webtrans-http3 section 3.3,
/// RFC 9651 section 3.1); member parameters are ignored.
pub fn available_protocols(field: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut chars = field.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| *c == ' ' || *c == '\t') {
            chars.next();
        }
        if chars.peek().is_none() {
            return if out.is_empty() { None } else { Some(out) };
        }
        if chars.next() != Some('"') {
            return None; // a member that is not a String
        }
        let mut s = String::new();
        loop {
            match chars.next()? {
                '"' => break,
                '\\' => match chars.next()? {
                    c @ ('"' | '\\') => s.push(c),
                    _ => return None,
                },
                c if (' '..='~').contains(&c) => s.push(c),
                _ => return None,
            }
        }
        out.push(s);
        // Parameters, then a comma or the end
        let mut in_quote = false;
        loop {
            match chars.peek().copied() {
                None => break,
                Some('"') => {
                    in_quote = !in_quote;
                    chars.next();
                }
                Some(',') if !in_quote => {
                    chars.next();
                    break;
                }
                Some(_) => {
                    chars.next();
                }
            }
        }
    }
}

/// The version to serve for a `WT-Available-Protocols` field, and the
/// `WT-Protocol` value that says so.
pub fn negotiate_webtransport(field: Option<&str>) -> Option<(Version, String)> {
    let offered = available_protocols(field?)?;
    let version = Version::negotiate(offered.iter().map(|s| s.as_bytes()))?;
    Some((version, format!("\"{}\"", version.alpn())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wt_available_protocols_parse_as_a_list_of_strings() {
        assert_eq!(
            available_protocols(r#""moqt-23", "moqt-22""#).unwrap(),
            ["moqt-23", "moqt-22"]
        );
        assert_eq!(
            available_protocols(r#""moqt-23";q=1,"x""#).unwrap(),
            ["moqt-23", "x"]
        );
        assert_eq!(
            available_protocols(r"moqt-23"),
            None,
            "a token, not a String"
        );
        assert_eq!(available_protocols(r#""moqt-23", 5"#), None);
        assert_eq!(available_protocols(""), None);
        assert_eq!(available_protocols(r#""a\"b""#).unwrap(), ["a\"b"]);
    }

    #[test]
    fn webtransport_negotiation_answers_with_a_string_item() {
        let (v, field) = negotiate_webtransport(Some(r#""moqt-22", "moqt-23""#)).unwrap();
        assert_eq!(v, Version::Draft23);
        assert_eq!(field, "\"moqt-23\"");
        assert!(negotiate_webtransport(Some(r#""moqt-16""#)).is_none());
        assert!(negotiate_webtransport(None).is_none());
    }
}
