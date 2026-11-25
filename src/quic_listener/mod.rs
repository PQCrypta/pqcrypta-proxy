//! QUIC/HTTP3/WebTransport listener
//!
//! Accepts QUIC connections, negotiates HTTP/3, and handles WebTransport sessions.
//! Routes streams and datagrams to configured backends.
//!
//! One listener a port: `udp_port`, each of `additional_ports`, and
//! `webtransport_port`, whose connections get windows for bulk transfers
//! (the speed test's). WebTransport (draft-ietf-webtrans-http3-17 and the
//! drafts before it) is served on every one.

use http::header::{self, HeaderName, HeaderValue};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;
use h3::ext::Protocol;
use h3_quinn::Connection as H3Connection;
use quinn::{
    AckFrequencyConfig, Connection as QuinnConnection, Endpoint, ServerConfig as QuinnServerConfig,
    TransportConfig, VarInt,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn, Instrument};

use crate::cache::ResponseCache;
use crate::config::{ConfigReloadEvent, ProxyConfig};
use crate::connect_udp::{self, DatagramRouter};
use crate::http3_features::EarlyHintsState;
use crate::load_balancer::LoadBalancer;
use crate::metrics::{ConnectionProtocol, MetricsRegistry};

use crate::fingerprint::FingerprintExtractor;
use crate::proxy::BackendPool;
use crate::rate_limiter::AdvancedRateLimiter;
use crate::security::SecurityState;
use crate::tls::TlsProvider;

mod cors;
mod request;
mod websocket;

use websocket::ws_h3_tunnel;

/// HTTP/3's code for a connection closed with nothing wrong (RFC 9114
/// section 8.1).
const H3_NO_ERROR: u32 = 0x100;

/// How long a peer sent GOAWAY for memory has to close the connection itself
/// before it is closed (crate::memory_pressure).
const SHED_GRACE: Duration = Duration::from_secs(2);

/// `server.server_header` (SEC-08: product name, no version) on a response the
/// proxy builds; an empty setting sends none.
pub(super) trait ServerHeader {
    fn server_header(self, config: &ProxyConfig) -> Self;
}

impl ServerHeader for http::response::Builder {
    fn server_header(self, config: &ProxyConfig) -> Self {
        let server = config.server.server_header.as_str();
        if server.is_empty() {
            self
        } else {
            self.header("server", server)
        }
    }
}

/// True when an h3 error is just the peer hanging up rather than a fault here.
///
/// Every one of these shapes is produced by ordinary client behaviour: a clean
/// graceful shutdown (H3_NO_ERROR / application code 0), a browser navigating
/// away mid-request, or an idle connection ageing out. They carry no operator
/// signal, so they belong at debug — logged at error they drowned out real
/// failures and kept the collector's log-analysis in a permanent error spike.
fn is_benign_h3_close<E: std::fmt::Display>(err: &E) -> bool {
    let msg = err.to_string();
    msg.contains("H3_NO_ERROR")
        || msg.contains("ApplicationClose: 0x0")
        || msg.contains("aborted by peer")
        || msg.contains("closed abruptly")
        || msg.contains("Timeout")
        // quinn's idle and handshake timeouts: the peer stopped answering.
        || msg.contains("timed out")
        // A browser cancelling a request it no longer wants (navigation,
        // a superseded fetch). RFC 9114 §4.1.1 defines it for exactly that.
        || msg.contains("H3_REQUEST_CANCELLED")
        // The peer closed with an application code h3 does not define —
        // browsers do this dropping a connection, and every connection open
        // across a restart does it at once. "Remote" is the discriminator: a
        // failure on this side is reported as a "Local error".
        || (msg.contains("Remote error") && msg.contains("closed"))
        // The peer closed cleanly, as quinn prints it: application code 0
        // (": 0" with no reason, "scan complete (code 0)" with one) or
        // H3_NO_ERROR, 0x100. A peer closing with any other code stays loud: it
        // may be answering something this side sent. The reasonless code 0 was
        // missing: the health check's h3 probe ends that way every 15 minutes,
        // and each one was logged as an error.
        || (msg.contains("closed by peer")
            && (msg.ends_with(": 0")
                || msg.ends_with("(code 0)")
                || msg.ends_with(": 256")
                || msg.ends_with("(code 256)")))
}

/// True when the error is the peer's own doing beyond hanging up: it broke
/// HTTP/3 or QPACK and this side closed the connection for it (the codes RFC
/// 9114 section 8.1 and RFC 9204 section 6 define for a peer's violation,
/// and QUIC's PROTOCOL_VIOLATION), or it reset a stream of its own. Worth a
/// line, since a client that keeps doing it is worth knowing about, but not
/// an error of this server's: the conformance suite's own clients do it every
/// hour by design.
fn is_peer_violation<E: std::fmt::Display>(err: &E) -> bool {
    const PEER_CODES: [&str; 13] = [
        "H3_GENERAL_PROTOCOL_ERROR",
        "H3_STREAM_CREATION_ERROR",
        "H3_CLOSED_CRITICAL_STREAM",
        "H3_FRAME_UNEXPECTED",
        "H3_FRAME_ERROR",
        "H3_EXCESSIVE_LOAD",
        "H3_ID_ERROR",
        "H3_SETTINGS_ERROR",
        "H3_MISSING_SETTINGS",
        "H3_MESSAGE_ERROR",
        "QPACK_DECOMPRESSION_FAILED",
        "QPACK_ENCODER_STREAM_ERROR",
        "QPACK_DECODER_STREAM_ERROR",
    ];
    let msg = err.to_string();
    // Raised here ("Local error"): the same code from the peer ("Remote
    // error", "closed by peer") is the peer saying this side broke HTTP/3.
    (msg.contains("Local error") && PEER_CODES.iter().any(|code| msg.contains(code)))
        || msg.contains("Remote reset")
        // quinn's description of PROTOCOL_VIOLATION, detected here
        || (msg.contains("error with protocol compliance") && !msg.contains("closed by peer"))
}

/// Resolves once `activity` has had nothing in flight for `idle` (as
/// `crate::memory_pressure::idle_limit` shortens it), or at the next moment it
/// might have: while something is in flight there is nothing to count from,
/// so the caller looks again after a whole `idle`.
async fn idle_past(activity: &crate::conn_limits::Activity, idle: Duration) {
    let idle = crate::memory_pressure::idle_limit(idle);
    match activity.idle_for() {
        Some(quiet) if quiet >= idle => {}
        Some(quiet) => tokio::time::sleep(idle.saturating_sub(quiet)).await,
        None => tokio::time::sleep(idle).await,
    }
}

/// What the HTTP/3 accept loop woke for: a stream accepted, or a request
/// stream's header block resolved (or not, by its deadline).
enum Step<A, R> {
    Accepted(A),
    Resolved(Result<R, tokio::time::error::Elapsed>),
}

/// Whether a request that could not be resolved (`resolve_any`) failed on the
/// peer's account, by the error's type rather than its text: a stream error h3
/// raised on what the peer sent (a malformed or incomplete header block, a
/// frame out of place: every code but H3_INTERNAL_ERROR, which is h3's own
/// failure), a stream the peer reset or a connection it closed, or a header
/// block over the limit. The hourly conformance battery sends malformed
/// requests on purpose, and each was an error line.
fn request_error_is_peers(err: &h3::error::StreamError) -> bool {
    use h3::error::{Code, ConnectionError, LocalError, StreamError};
    match err {
        StreamError::StreamError { code, .. } => *code != Code::H3_INTERNAL_ERROR,
        StreamError::RemoteTerminate { .. }
        | StreamError::RemoteClosing { .. }
        | StreamError::HeaderTooBig { .. } => true,
        StreamError::ConnectionError { 0: connection, .. } => match connection {
            ConnectionError::Local {
                error: LocalError::Application { code, .. },
                ..
            } => *code != Code::H3_INTERNAL_ERROR,
            ConnectionError::Local {
                error: LocalError::Closing { .. },
                ..
            }
            | ConnectionError::Remote { .. }
            | ConnectionError::Timeout { .. } => true,
            _ => false,
        },
        _ => false,
    }
}

/// Whether this side closed the connection itself (`LocallyClosed`): a
/// handshake past its deadline, a refused fingerprint, HTTP/3 that could not
/// be set up, an idle connection let go. Each is decided, and said, where it
/// is made; the connection ending for it is no error.
fn closed_here(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        matches!(
            e.downcast_ref::<quinn::ConnectionError>(),
            Some(quinn::ConnectionError::LocallyClosed)
        )
    })
}

/// How loudly to report a QUIC connection that ended in an error.
///
/// Most of what ends a connection is the client's doing and says nothing about
/// this server: a scanner that offers no h3 ALPN, a peer that aborts or goes
/// quiet. Those were logged at error, several a day on an idle node, which the
/// log collector counts as error spikes. What stays loud is anything this side
/// could have caused; a handshake with no certificate for the requested name is
/// a warning, because it is usually a client asking for a name we never served
/// but is also what a missing certificate looks like.
fn log_connection_end(remote_addr: SocketAddr, err: &anyhow::Error) {
    if closed_here(err) {
        debug!("QUIC connection from {} closed by this side", remote_addr);
        return;
    }
    log_quic_end(remote_addr, &format!("{err:#}"));
}

/// `log_connection_end` for a QUIC connection that ended with `msg`, shared by
/// the HTTP/3 listener and the WebTransport server so the two cannot rank the
/// same ending differently. They did: a handshake asking for a name with no
/// certificate was a warning here and an error on the WebTransport port.
pub(crate) fn log_quic_end(remote_addr: SocketAddr, msg: &str) {
    if is_benign_h3_close(&msg)
        || msg.contains("peer doesn't support any known protocol")
        || msg.contains("received fatal alert")
        // A client offering no key exchange group, cipher suite or signature
        // scheme this server accepts (the TLS group checks offer refused ones
        // on purpose)
        || msg.contains("peer is incompatible")
    {
        debug!("QUIC connection from {} ended: {}", remote_addr, msg);
    } else if is_peer_violation(&msg) {
        info!(
            "QUIC connection from {} ended: the peer broke the protocol ({})",
            remote_addr, msg
        );
    } else if msg.contains("no server certificate chain resolved") {
        warn!(
            "QUIC handshake from {}: no certificate for the requested server name ({})",
            remote_addr, msg
        );
    } else {
        error!("Connection error from {}: {}", remote_addr, msg);
    }
}

/// The Alt-Svc value for a response being sent **over QUIC**: the same value a
/// response over TCP carries, every UDP port that serves HTTP/3, this
/// connection's among them.
///
/// RFC 7838 section 3: an Alt-Svc header "invalidates and replaces all cached
/// alternative services for that origin". A response over QUIC that leaves out the
/// connection it arrives on therefore has the client forget it. This path left out
/// h3 on its own port and named `h2` there instead, which a browser does not store
/// (Chrome keeps QUIC alternatives only): after a page over HTTP/3 on 443 the
/// client held only h3 on 4434, after the next one, over TCP, h3 on 443 again, so
/// a visitor reloading philibertsecurity.com alternated HTTP/3 and HTTP/2 on every
/// load (the access log, 2026-11-02: fourteen reloads, strictly alternating). One
/// value on every transport keeps a client's set the same whichever connection
/// carried the response.
///
/// `config.server.udp_port` is the port *this* listener is bound to (`main.rs`
/// clones the config per port and overwrites the field), the first one listed, as
/// the TCP listener lists its own port first. An empty value (`alt_svc_ports = []`,
/// a node that advertises no HTTP/3) is answered `clear` by
/// [`H3ConnHeaders::alt_svc`]: a client that reached it over QUIC anyway drops
/// what it cached.
///
/// Built once per connection into [`H3ConnHeaders`], whose `alt_svc` answers
/// `clear` instead for hosts listed in `server.tcp_only_hosts`.
fn build_alt_svc_header_over_quic(config: &ProxyConfig) -> String {
    crate::http_listener::layers::build_alt_svc_header_with_override(
        config.server.udp_port,
        &config.server.additional_ports,
        config.server.alt_svc_ports.as_deref(),
        config.server.alt_svc_max_age_secs,
    )
}

/// The starting point for a QUIC connection's handshake facts.
///
/// Only the TLS version is knowable without reading `HandshakeData`: QUIC
/// permits nothing older than TLS 1.3 (RFC 9001 §4.2). The caller fills the rest
/// from a single `handshake_data()` read.
///
/// ECH starts `unknown` and is overwritten from `HandshakeData` as soon as the
/// handshake is read. It only stays `unknown` if that read fails, which would be
/// a real fault rather than a property of the protocol.
fn quic_handshake_facts_empty() -> crate::tls_acceptor::HandshakeFacts {
    crate::tls_acceptor::HandshakeFacts {
        tls_version: Some("TLSv1_3".to_string()),
        cipher_suite: None,
        kex_group: None,
        alpn: None,
        ech: "unknown",
        library: crate::tls_acceptor::TlsLibrary::Rustls,
        prepared: std::sync::OnceLock::default(),
    }
}

/// Response and forwarding header values that are fixed for a connection,
/// built once when it is accepted instead of on every request.
///
/// Each of these used to be formatted or validated per request: the Alt-Svc
/// value was assembled with a `format!` per advertised port and a join, the
/// client address was rendered with `to_string` and re-validated, and each
/// fingerprint hash was copied into a fresh `HeaderValue`. None of them can
/// change while the connection lives — the config is the connection's own
/// snapshot, the address and the handshake are the connection's — so the
/// per-request cost bought nothing.
pub(super) struct H3ConnHeaders {
    /// Client-Hints, reporting and security headers and the fallback CSP,
    /// applied by the same rules as on the TCP listeners
    /// (`apply_response_policy_headers`).
    pub(super) response_headers: std::sync::Arc<crate::http_listener::layers::ResponseHeaderSet>,
    /// `server.server_header`; `None` lets the origin's own pass through.
    pub(super) server: Option<HeaderValue>,
    /// This listener's Alt-Svc value for hosts not in `tcp_only_hosts`.
    alt_svc: Option<HeaderValue>,
    /// The client address as forwarded in `x-forwarded-for` / `x-real-ip`.
    pub(super) client_ip: Option<HeaderValue>,
    /// `x-forwarded-port`: the port this listener serves, as the TCP
    /// listeners send it. HTTP/3 set none, so a client's own passed through.
    pub(super) forwarded_port: HeaderValue,
    pub(super) ja3: Option<HeaderValue>,
    pub(super) ja4: Option<HeaderValue>,
    pub(super) client_name: Option<HeaderValue>,
    /// Whether the client presented a certificate the handshake verified --
    /// `x-client-cert`, which per-route mTLS enforcement reads. Never set on
    /// this transport before, so an mTLS route refused every HTTP/3 client,
    /// including one that had authenticated.
    ///
    /// Settled by the first request accepted after the handshake completed
    /// (see `resolve_client_cert`). A connection serving 0-RTT is set up
    /// before the client's certificate has been verified, and its early
    /// requests never report one.
    pub(super) client_cert: std::sync::OnceLock<bool>,
    /// `x-pqc-enabled`: whether this handshake was post-quantum, as the TCP
    /// listeners report it.
    pub(super) pqc_enabled: HeaderValue,
    /// The Host value forwarded to the backend, for the first host this
    /// connection asked for. A connection nearly always asks for one host;
    /// another one is simply built per request.
    host: std::sync::OnceLock<(Box<str>, HeaderValue)>,
}

impl H3ConnHeaders {
    fn new(
        config: &ProxyConfig,
        remote_addr: SocketAddr,
        local_port: u16,
        fingerprint: &crate::fingerprint::FingerprintResult,
        handshake: &crate::tls_acceptor::HandshakeFacts,
    ) -> Self {
        let value = |s: Option<&str>| s.and_then(|s| HeaderValue::from_str(s).ok());
        let pqc = handshake.is_post_quantum();
        Self {
            response_headers: std::sync::Arc::new(
                crate::http_listener::layers::ResponseHeaderSet::from_config(&config.headers),
            ),
            server: Some(config.server.server_header.as_str())
                .filter(|s| !s.is_empty())
                .and_then(|s| HeaderValue::from_str(s).ok()),
            alt_svc: Some(build_alt_svc_header_over_quic(config))
                .filter(|v| !v.is_empty())
                .and_then(|v| HeaderValue::from_str(&v).ok()),
            client_ip: HeaderValue::from_str(&remote_addr.ip().to_string()).ok(),
            forwarded_port: HeaderValue::from(local_port),
            ja3: value(fingerprint.ja3_hash.as_deref()),
            ja4: value(fingerprint.ja4_hash.as_deref()),
            client_name: value(fingerprint.client_name.as_deref()),
            client_cert: std::sync::OnceLock::new(),
            pqc_enabled: HeaderValue::from_static(if pqc { "true" } else { "false" }),
            host: std::sync::OnceLock::new(),
        }
    }

    /// Read the client certificate off a connection whose handshake has
    /// completed, once. Called for every stream that was not 0-RTT, which
    /// noq decides against the connection's own state when it hands the
    /// stream over, so the first such call already sees the final answer.
    pub(super) fn resolve_client_cert(&self, connection: &QuinnConnection) {
        self.client_cert.get_or_init(|| {
            connection
                .peer_identity()
                .and_then(|id| {
                    id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        .ok()
                })
                .is_some_and(|certs| !certs.is_empty())
        });
    }

    /// `host` as a header value, built once for the connection's usual host.
    pub(super) fn host_value(&self, host: &str) -> Option<HeaderValue> {
        if let Some((h, v)) = self.host.get() {
            if **h == *host {
                return Some(v.clone());
            }
        }
        let v = HeaderValue::from_str(host).ok()?;
        let _ = self.host.set((host.into(), v.clone()));
        Some(v)
    }

    /// The Alt-Svc value for a response: `clear` for a host listed in
    /// `server.tcp_only_hosts`, so browsers evict any cached QUIC upgrade and
    /// fall back to TCP, otherwise the value built for this connection.
    pub(super) fn alt_svc(&self, config: &ProxyConfig, host: Option<&str>) -> HeaderValue {
        if let Some(h) = host {
            if config.server.is_tcp_only_host(h) {
                return HeaderValue::from_static("clear");
            }
        }
        self.alt_svc
            .clone()
            .unwrap_or_else(|| HeaderValue::from_static("clear"))
    }
}

/// QUIC/HTTP3/WebTransport listener
pub struct QuicListener {
    /// QUIC endpoint
    endpoint: Endpoint,
    /// TLS provider
    tls_provider: Arc<TlsProvider>,
    /// The endpoint's server configuration as built at startup. A TLS reload
    /// (rotated ECH keys, renewed certificates, the admin API) rebuilds the
    /// provider's rustls config; [`Self::install_tls_config`] puts it into a
    /// copy of this and installs that on the endpoint. The endpoint keeps the
    /// config it was given until then: before it did this, a rotated ECH key
    /// reached every TCP listener and no QUIC one, and HTTP/3 refused the
    /// configs DNS published until a restart.
    server_config: QuinnServerConfig,
    /// Moves once per TLS reload (`ech_config::reloads`)
    tls_reloads: tokio::sync::watch::Receiver<u64>,
    /// Backend connection pool
    backend_pool: Arc<BackendPool>,
    /// Configuration
    config: Arc<ProxyConfig>,
    /// Shutdown signal receiver
    shutdown_rx: mpsc::Receiver<()>,
    /// Config reload receiver
    reload_rx: mpsc::Receiver<ConfigReloadEvent>,
    /// Early Hints state for 103 responses
    early_hints_state: Arc<EarlyHintsState>,
    /// Metrics registry for recording request/connection stats
    metrics: Arc<MetricsRegistry>,
    /// Security state for IP blocking, GeoIP country blocking, and rate limiting.
    ///
    /// `Arc`, not an owned clone: this is handed to every connection task and
    /// every request within it, and `SecurityState` holds 17 `Arc`s of its own —
    /// so an owned copy is ~19 atomic increments on the way in and as many
    /// decrements on the way out, per request. The TCP path was fixed for this;
    /// the QUIC path kept the copy.
    security: Arc<SecurityState>,
    /// Advanced multi-dimensional rate limiter (shared with TCP listeners)
    advanced_rate_limiter: Arc<AdvancedRateLimiter>,
    /// Shared load balancer for canary routing and pool-based selection
    load_balancer: Arc<LoadBalancer>,
    /// Shared response cache (HTTP/3 path)
    cache: Arc<ResponseCache>,
    /// TLS client fingerprint extractor, shared with the TCP listeners.
    ///
    /// The QUIC path computed no JA3/JA4 at all: it read `x-ja3-hash` and
    /// `x-ja4-hash` from request headers that nothing on this path ever set, so
    /// fingerprint rate limiting, `block_malicious`/`block_scanners` and
    /// per-route `allowed_ja3` were all inert over HTTP/3 while appearing
    /// configured.
    fingerprint_extractor: Arc<FingerprintExtractor>,
    /// Fingerprint policy (blocking toggles, cache TTL) — same config the TCP
    /// listeners read, so one setting governs both transports.
    fingerprint_config: crate::config::FingerprintConfig,
    /// DNS over QUIC for a client that names `doq` in ALPN, where `[doq]` is on
    doq: Option<Arc<crate::doq::Service>>,
}

/// `template` with `crypto` as its TLS configuration, installed on `endpoint`
/// for the connections that arrive from now on.
pub(crate) fn install_crypto(
    endpoint: &Endpoint,
    template: &QuinnServerConfig,
    crypto: Arc<quinn::crypto::rustls::QuicServerConfig>,
) {
    let mut next = template.clone();
    next.crypto = crypto;
    endpoint.set_server_config(Some(next));
}

/// Response headers that are identical on every response until the config is
/// reloaded.
///
/// These were rebuilt per response from config `String`s: fifteen header-name
/// parses and, because `HeaderValue::from_str` copies into `Bytes`, fifteen heap
/// allocations for values that never change. Built once per connection instead,
/// after which applying them is a `HeaderName` clone (cheap) and a `HeaderValue`
/// clone (a refcount bump).
///
/// Deliberately excludes `alt-svc`, which varies by host, and `server-timing`,
/// which carries the elapsed time of the request.
/// Resolve the per-route security policy for a request.
///
/// This was inlined twice in `handle_h3_request` -- once for the header-pass WAF
/// evaluation and again for the body-pass inspection, because the first lived in
/// a block that had since closed. Each copy re-derived the host, called
/// `is_conformance_host`, ran `find_route` (an O(routes) scan -- one route in a
/// test config, sixty on the live edge, nine of them carrying regexes) and
/// cloned every policy field. Extracted so the caller can resolve it once.
/// The Stream Body bytes a WebTransport session may send before this server
/// grants more (SETTINGS_WT_INITIAL_MAX_DATA): twice the connection's own
/// receive window, so QUIC's flow control binds first
const WT_INITIAL_MAX_DATA: u64 = 16 << 20;

/// The initial WebTransport limits this server declares in SETTINGS
/// (draft-ietf-webtrans-http3-17 section 5.6): as many streams per session as
/// the connection allows, and [`WT_INITIAL_MAX_DATA`].
fn wt_initial_limits(config: &ProxyConfig) -> crate::wt_flow::Limits {
    // A session's streams by server.webtransport_max_streams_per_session, in
    // each direction, within what QUIC allows the connection (which holds the
    // CONNECT stream too): set to the connection's own limits, the session's
    // could never be passed and meant nothing
    let per_session = u64::from(config.server.webtransport_max_streams_per_session);
    crate::wt_flow::Limits {
        streams_uni: per_session.min(u64::from(config.server.max_uni_streams_per_connection)),
        streams_bidi: per_session
            .min(u64::from(config.server.max_streams_per_connection).saturating_sub(1)),
        data: WT_INITIAL_MAX_DATA,
    }
}

/// A WebTransport session's flow control, on when the client's SETTINGS
/// declare limits as this server's do (section 5.1), and where its capsules
/// go out.
fn session_flow(
    ours: crate::wt_flow::Limits,
    peer: Option<h3::Settings>,
) -> (
    Arc<crate::wt_flow::Flow>,
    tokio::sync::mpsc::UnboundedReceiver<Bytes>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let enabled = peer.is_some_and(|s| s.wt_flow_control());
    let peer = peer.map_or_else(Default::default, |s| crate::wt_flow::Limits {
        streams_uni: s.wt_initial_max_streams_uni(),
        streams_bidi: s.wt_initial_max_streams_bidi(),
        data: s.wt_initial_max_data(),
    });
    (crate::wt_flow::Flow::new(enabled, ours, peer, tx), rx)
}

/// How long a WebTransport session's handler (MoQ, or a route's) has to
/// finish once the session has ended: it sees the end at once, and this
/// bounds a stuck one
const WT_SESSION_WIND_DOWN: Duration = Duration::from_secs(5);

/// Hand a WebTransport unidirectional stream to its session, or refuse it
/// (WT_BUFFERED_STREAM_REJECTED) when there is no such session now.
fn deliver_wt_uni(
    sessions: &mut std::collections::HashMap<u64, crate::wt_session::H3SessionFeed>,
    session: u64,
    prefix: Bytes,
    mut stream: h3_quinn::RecvStream,
) {
    use h3::quic::RecvStream as _;
    let feed = sessions.get(&session).filter(|feed| !feed.has_ended());
    match feed {
        Some(feed) => match stream.into_inner_or_pending() {
            Ok(recv) => feed.deliver_uni(crate::wt_session::Prefixed::new(prefix, recv)),
            // h3 read past the header and the rest has not come: the stream
            // goes to its session with that read's data once it does
            Err(pending) => {
                let feed = feed.clone();
                tokio::spawn(async move {
                    if let Some((prefix, recv)) = after_pending_read(prefix, pending).await {
                        feed.deliver_uni(crate::wt_session::Prefixed::new(prefix, recv));
                    }
                });
            }
        },
        None => {
            // No such session: refused, whether or not a read is pending
            stream.stop_sending(u64::from(crate::wt_session::WT_BUFFERED_STREAM_REJECTED));
            sessions.remove(&session);
        }
    }
}

/// A WebTransport stream whose read h3 left pending: the stream, and what
/// arrived before and with that read, once it completes; `None` where the
/// peer reset it first.
async fn after_pending_read(
    prefix: Bytes,
    pending: h3_quinn::PendingRead,
) -> Option<(Bytes, quinn::RecvStream)> {
    let (recv, read) = pending.await;
    match read {
        Ok(Some(more)) if prefix.is_empty() => Some((more, recv)),
        Ok(Some(more)) => {
            let mut joined = Vec::with_capacity(prefix.len() + more.len());
            joined.extend_from_slice(&prefix);
            joined.extend_from_slice(&more);
            Some((Bytes::from(joined), recv))
        }
        // Finished: what arrived is all of it
        Ok(None) => Some((prefix, recv)),
        Err(e) => {
            debug!("WebTransport stream ended before its first data: {}", e);
            None
        }
    }
}

/// Hand a WebTransport bidirectional stream to its session, or refuse it as
/// [`deliver_wt_uni`] does.
fn deliver_wt_bi(
    sessions: &mut std::collections::HashMap<u64, crate::wt_session::H3SessionFeed>,
    session: u64,
    prefix: Bytes,
    stream: h3_quinn::BidiStream<Bytes>,
) {
    use h3::quic::{BidiStream as _, RecvStream as _, SendStream as _};
    let (mut send, mut recv) = stream.split();
    let feed = sessions.get(&session).filter(|feed| !feed.has_ended());
    let Some(feed) = feed else {
        let code = u64::from(crate::wt_session::WT_BUFFERED_STREAM_REJECTED);
        send.reset(code);
        recv.stop_sending(code);
        sessions.remove(&session);
        return;
    };
    let Some(send) = send.into_inner() else {
        // Nothing has been written to a stream the peer just opened
        debug!("WebTransport stream with a write in flight: dropped");
        return;
    };
    match recv.into_inner_or_pending() {
        Ok(recv) => feed.deliver_bi(send, crate::wt_session::Prefixed::new(prefix, recv)),
        // As deliver_wt_uni: the stream goes once its pending read completes
        Err(pending) => {
            let feed = feed.clone();
            tokio::spawn(async move {
                if let Some((prefix, recv)) = after_pending_read(prefix, pending).await {
                    feed.deliver_bi(send, crate::wt_session::Prefixed::new(prefix, recv));
                }
            });
        }
    }
}

/// Whether an extended CONNECT this listener answers itself (WebTransport,
/// WebSocket, CONNECT-UDP) is refused, with the status and any headers the
/// refusal carries. It meets what every other request does, in the same
/// order: the advanced rate limiter and `SecurityState::evaluate`, then the
/// per-route rate limit and the route gate (`route_gate::evaluate`) of
/// `route`, the route it is served by. The request's headers are the
/// connection-derived ones by now (`request::derive_connection_headers`). A
/// client opening a session is a program, so the user-agent rules for unnamed
/// clients are not applied to it.
#[expect(clippy::too_many_arguments)]
async fn connect_refusal(
    security: &SecurityState,
    advanced_rate_limiter: &AdvancedRateLimiter,
    config: &ProxyConfig,
    request: &http::Request<()>,
    host: Option<&str>,
    path: &str,
    route: Option<&crate::config::RouteConfig>,
    remote_addr: SocketAddr,
    fingerprint: &crate::fingerprint::FingerprintResult,
) -> Option<(http::StatusCode, Vec<(&'static str, String)>)> {
    let ip = remote_addr.ip();
    let refuse = |status: http::StatusCode| Some((status, Vec::new()));
    if !security.is_trusted(&ip) {
        let context = crate::rate_limiter::build_context_from_request(
            ip,
            request.headers(),
            path,
            request.method().as_str(),
            fingerprint.ja3_hash.clone(),
            fingerprint.ja4_hash.clone(),
            None,
        );
        match advanced_rate_limiter.check(&context).await {
            crate::rate_limiter::RateLimitResult::Allowed { .. } => {}
            crate::rate_limiter::RateLimitResult::Limited { .. } => {
                return refuse(http::StatusCode::TOO_MANY_REQUESTS);
            }
            crate::rate_limiter::RateLimitResult::Blocked { .. } => {
                return refuse(http::StatusCode::FORBIDDEN);
            }
        }
        // The policy of the route it is served by: an extended CONNECT is not
        // matched among ordinary routes, and a WebTransport route is matched
        // only for one
        let mut policy =
            crate::security::route_request_policy(config, host, path, request.method(), route);
        policy.skip_bot_blocking = true;
        let raw_path = request.uri().path().to_ascii_lowercase();
        let view = crate::security::SecurityRequestView {
            ip,
            peer_port: Some(remote_addr.port()),
            method: request.method().as_str(),
            path: &raw_path,
            query: request.uri().query().unwrap_or(""),
            headers: request.headers(),
            body: None,
            version: Some(http::Version::HTTP_3),
            authority: host,
        };
        let decision = security.evaluate(&view, &policy);
        let rendered = {
            let security_config = security.config.read();
            crate::security::decision_rendering(&decision, None, &security_config).map(|r| r.status)
        };
        if let Some(status) = rendered {
            return refuse(status);
        }
    }

    let route = route?;
    // The route's own rate limit, as an ordinary request on it is held to
    if let Some(name) = &route.name {
        if config
            .advanced_rate_limiting
            .route_limits
            .contains_key(name.as_str())
        {
            let context = crate::rate_limiter::build_context_from_request(
                ip,
                request.headers(),
                path,
                request.method().as_str(),
                fingerprint.ja3_hash.clone(),
                fingerprint.ja4_hash.clone(),
                Some(name.clone()),
            );
            if let crate::rate_limiter::RateLimitResult::Limited { .. } =
                advanced_rate_limiter.check(&context).await
            {
                return refuse(http::StatusCode::TOO_MANY_REQUESTS);
            }
        }
    }
    // The route's gates: mTLS, HMAC proof-of-possession and the rest, over
    // the request target as the client sent it
    let received = request.uri();
    let path_and_query = received
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| received.path());
    let gate = crate::route_gate::GateContext {
        route,
        method: request.method().as_str(),
        path_and_query,
        path,
        headers: request.headers(),
        verified_content_digest: None,
        client_ip: ip,
        is_http11: false,
        is_websocket_upgrade: false,
        is_http3: true,
        zero_rtt_safe_methods: &config.tls.zero_rtt_safe_methods,
        hmac_nonce_store: crate::route_gate::shared_nonce_store(),
    };
    match crate::route_gate::evaluate(&gate) {
        crate::route_gate::GateOutcome::Continue => None,
        crate::route_gate::GateOutcome::Refuse { status, headers } => Some((status, headers)),
    }
}

/// The access-log line of an extended CONNECT answered here.
fn log_connect(
    request: &http::Request<()>,
    host: Option<&str>,
    path: &str,
    remote_addr: SocketAddr,
    fingerprint: &crate::fingerprint::FingerprintResult,
    status: u16,
) {
    let field = |name: HeaderName| request.headers().get(name).and_then(|v| v.to_str().ok());
    crate::access_logger::log_access(&crate::access_logger::AccessLogEntry {
        ja3: fingerprint.ja3_hash.as_deref(),
        ja4: fingerprint.ja4_hash.as_deref(),
        backend: None,
        remote_addr,
        method: request.method().as_str(),
        path,
        protocol: "HTTP/3",
        status,
        body_size: 0,
        referer: field(header::REFERER),
        user_agent: field(header::USER_AGENT),
        host,
        response_time_ms: 0,
    });
}

/// The policy an ordinary HTTP/3 request is judged by: its route's, where one
/// matches (`security::request_policy`).
fn resolve_route_policy(
    security: &SecurityState,
    request: &http::Request<()>,
    host: Option<&str>,
    path: &str,
) -> crate::security::RequestPolicy {
    let routes = security.route_index.load_full();
    crate::security::request_policy(&routes, host, path, request.method())
}

/// A route's header decisions and then the security headers onto an HTTP/3
/// response, in the TCP listeners' order: the route's overrides replace what
/// the origin sent, a Stripe-compatible route drops the cross-origin
/// policies, and the `[headers]` set goes on by its rules
/// (`ResponseHeaderSet::apply`) -- a cross-origin policy the origin set is
/// kept, the fallback CSP only where the origin sent none, and nothing the
/// route decided is touched; then the configured `Server`.
///
/// Until 2026-10-11 the overrides were appended after the security headers,
/// so Grafana answered over HTTP/3 with two of each cross-origin policy, and
/// a cache hit got none of its route's overrides at all (a cached font
/// without its `access-control-allow-origin: *`).
pub(super) fn apply_response_policy_headers(
    mut builder: http::response::Builder,
    route: Option<&crate::config::RouteConfig>,
    set: &crate::http_listener::layers::ResponseHeaderSet,
    server: Option<&HeaderValue>,
    host: Option<&str>,
    path: &str,
) -> http::response::Builder {
    if let Some(h) = builder.headers_mut() {
        let owned = route.map(crate::http_listener::layers::RouteOwnedHeaders::of);
        if let Some(route) = route {
            for (key, value) in &route.headers_override {
                if let (Ok(name), Ok(val)) = (
                    HeaderName::from_bytes(key.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    h.insert(name, val);
                }
            }
            if route.stripe_compatibility {
                h.remove("cross-origin-embedder-policy");
                h.remove("cross-origin-opener-policy");
            }
        }
        set.apply(h, set.is_addin(host, path), owned.as_ref());
        if let Some(server) = server {
            h.insert(header::SERVER, server.clone());
        }
    }
    builder
}

impl QuicListener {
    /// Create a new QUIC listener
    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::unused_async_trait_impl)] // public async API; callers .await it
    pub async fn new(
        config: Arc<ProxyConfig>,
        tls_provider: Arc<TlsProvider>,
        shutdown_rx: mpsc::Receiver<()>,
        reload_rx: mpsc::Receiver<ConfigReloadEvent>,
        metrics: Arc<MetricsRegistry>,
        security: Arc<SecurityState>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        early_hints_state: Arc<EarlyHintsState>,
    ) -> anyhow::Result<Self> {
        let addr = config.server.socket_addr()?;

        info!("Creating QUIC listener on {}", addr);

        // Create transport configuration
        let mut transport_config = TransportConfig::default();
        // server.quic_congestion_control: BBRv3 by default (see its docs); the
        // speed test reports it as the sender its results were measured with
        transport_config
            .congestion_controller_factory(config.server.quic_congestion_control.factory());
        crate::speedtest::set_congestion_control(config.server.quic_congestion_control.name());
        // Path MTU discovery to the byte, up to a 1500-byte link (see its docs).
        transport_config.mtu_discovery_config(Some(crate::config::quic_mtu_discovery()));
        transport_config
            .max_concurrent_bidi_streams(config.server.max_streams_per_connection.into());
        transport_config
            .max_concurrent_uni_streams(config.server.max_uni_streams_per_connection.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(
            config.server.keepalive_interval_secs,
        )));
        // Flow-control windows. These are the INITIAL credit a peer gets; the
        // receiver extends it with MAX_STREAM_DATA as it consumes, so these figures
        // cap neither transfer size nor eventual throughput — they set how much a
        // peer may send before waiting for us once.
        //
        // The previous 8 MB per stream / 16 MB per connection was set to match the
        // WebTransport server and beat quinn's ~256 KB default. 2 MB still clears
        // any realistic path: a stream window sustains window/RTT, so 2 MB is
        // ~533 Mbps at 30 ms and ~160 Mbps at 100 ms, far above what an HTTP upload
        // to this proxy needs. What the old figure bought instead was a much larger
        // advertised memory commitment per connection, multiplied by every stream a
        // peer chose to open.
        transport_config.receive_window(VarInt::from_u32(8 * 1024 * 1024)); // 8 MB connection
        transport_config.stream_receive_window(VarInt::from_u32(2 * 1024 * 1024)); // 2 MB per stream

        // The WebTransport port's connections carry the speed test's bulk
        // transfers with its latency datagrams beside them: windows for
        // 200 Mbps and more at 50 ms (64 MB a connection, 32 MB a stream, a
        // 64 MB send window) and 4 MB datagram buffers, without which 64 KB of
        // datagrams filled under a download and the connection was aborted
        // with EXCESSIVE_LOAD. The dedicated WebTransport server had them;
        // this listener serves the port now.
        if config.server.udp_port == config.server.webtransport_port {
            transport_config.receive_window(VarInt::from_u32(64 * 1024 * 1024));
            transport_config.stream_receive_window(VarInt::from_u32(32 * 1024 * 1024));
            transport_config.send_window(64 * 1024 * 1024);
            transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
            transport_config.datagram_send_buffer_size(4 * 1024 * 1024);
            info!(
                "QUIC on the WebTransport port {}: windows 64 MB a connection and 32 MB a stream, datagram buffers 4 MB",
                config.server.udp_port
            );
        }
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(config.server.max_idle_timeout_secs)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid idle timeout: {}", e))?,
        ));

        // When we acknowledge, and when we transmit. Owed ACKs ride on any
        // packet that is leaving anyway (piggyback), so a request is
        // acknowledged by its own response; the threshold then only decides
        // when an ACK is worth a packet of its own. Without piggybacking a lone
        // request waited out max_ack_delay — 25 ms — for its ACK, and the
        // client would not start its next request until it arrived. Send
        // coalescing lets responses that finish together leave together. See
        // `ServerConfig` for each setting's measurement.
        //
        // Distinct from the ACK Frequency extension below, which asks the PEER
        // to change ITS behaviour and cannot affect ours.
        transport_config.local_ack_eliciting_threshold(config.server.ack_eliciting_threshold);
        transport_config.ack_piggyback(config.server.ack_piggyback);
        transport_config.send_coalescing(config.server.quic_send_coalescing);
        info!(
            "QUIC: ACK-only packet every {} ack-eliciting packets, piggyback {}, send coalescing {}",
            config.server.ack_eliciting_threshold + 1,
            if config.server.ack_piggyback { "on" } else { "off" },
            if config.server.quic_send_coalescing { "on" } else { "off" },
        );

        // ACK Frequency extension (draft-ietf-quic-ack-frequency): allow the peer
        // to request fewer, batched ACKs, reducing ACK traffic and CPU on
        // high-throughput connections. Negotiated — inert if the peer lacks it.
        if config.server.enable_ack_frequency {
            transport_config.ack_frequency_config(Some(AckFrequencyConfig::default()));
            info!("QUIC ACK Frequency extension enabled");
        }

        // Full draft-ietf-quic-multipath support (via the noq QUIC stack):
        // allow this many concurrent, data-carrying paths per connection when
        // the peer negotiates multipath. Unlike the earlier narrow single-
        // path validation probe, noq implements the complete extension -
        // per-path packet-number spaces, PATH_ACK/ABANDON/STATUS lifecycle
        // frames, per-path loss recovery, and a scheduler - and manages path
        // creation/validation/teardown automatically once negotiated. Inert
        // for peers that don't advertise multipath.
        let multipath_paths = config.server.max_concurrent_multipath_paths;
        transport_config.max_concurrent_multipath_paths(multipath_paths);
        if multipath_paths > 0 {
            info!(
                "QUIC multipath enabled: up to {} concurrent path(s) per connection",
                multipath_paths
            );
        } else {
            info!("QUIC multipath disabled by configuration (max_concurrent_multipath_paths = 0)");
        }

        // Create QUIC server configuration. Subscribed first, so a reload
        // between taking the provider's config and running is installed too.
        let tls_reloads = crate::ech_config::reloads();
        let mut server_config =
            QuinnServerConfig::with_crypto(tls_provider.get_quic_server_config());
        server_config.transport = Arc::new(transport_config);

        // STEP 12: Gate connection migration on server config.
        // `migration()` is a method on ServerConfig, not TransportConfig.
        if !config.server.enable_quic_migration {
            server_config.migration(false);
            info!("QUIC connection migration disabled by configuration");
        }

        // Create endpoint. Built manually (rather than Endpoint::server) so we can
        // override the advertised QUIC version list. noq's DEFAULT_SUPPORTED_VERSIONS
        // is v1 + draft-29..34, but this proxy only handshakes stable versions —
        // advertising the obsolete drafts in Version Negotiation is misleading (and a
        // client that selected one would fail). We handshake QUIC v1 (RFC 9000) and
        // QUIC v2 (RFC 9369): v1 is listed first as the default, v2 support is
        // additive (the version is chosen per-connection from the client's Initial,
        // so v1 clients are unaffected). The vendored noq fork implements v2's
        // version-specific Initial keys (via rustls), retry integrity key, and
        // long-header packet-type renumbering. noq still adds its reserved/GREASE
        // version automatically.
        let socket = crate::inherited::udp_socket(addr)?;

        // Explicitly size the kernel UDP socket buffers. quinn-udp enables GSO/GRO
        // automatically but does NOT set SO_RCVBUF/SO_SNDBUF — it inherits the host's
        // net.core.{r,w}mem_default. On a stock host that default is ~212 KB, which
        // drops datagrams under bulk QUIC load *before* quinn sees them (distinct from
        // the QUIC-level flow-control windows below). Setting it here makes throughput
        // portable across hosts instead of depending on a hand-tuned sysctl. The kernel
        // clamps the request to net.core.{r,w}mem_max and reports back ~2x the granted
        // size. 16 MB matches the 16 MB connection receive_window configured below.
        {
            const UDP_BUFFER_BYTES: usize = 16 * 1024 * 1024;
            let sock_ref = socket2::SockRef::from(&socket);
            if let Err(e) = sock_ref.set_recv_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set UDP SO_RCVBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            if let Err(e) = sock_ref.set_send_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set UDP SO_SNDBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            // getsockopt returns roughly double the granted size on Linux (bookkeeping
            // overhead); halve for an honest figure. If these come back far below the
            // request, net.core.{r,w}mem_max is clamping and should be raised.
            let rcv = sock_ref.recv_buffer_size().map(|v| v / 2).unwrap_or(0);
            let snd = sock_ref.send_buffer_size().map(|v| v / 2).unwrap_or(0);
            info!(
                "QUIC UDP socket buffers: SO_RCVBUF≈{} KB, SO_SNDBUF≈{} KB (requested {} KB each)",
                rcv / 1024,
                snd / 1024,
                UDP_BUFFER_BYTES / 1024
            );
        }

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime found for QUIC endpoint"))?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.supported_versions(vec![0x0000_0001, 0x6b33_43cf]); // QUIC v1 (RFC 9000) + v2 (RFC 9369)
                                                                            // Through the path-loss decorator: a telemetry session served here
                                                                            // (WebTransport over this port) can put loss on its own path, and with
                                                                            // none set a datagram costs one atomic load (path_loss.rs)
        let socket = Box::new(crate::path_loss::LossySocket::new(
            runtime.wrap_udp_socket(socket)?,
        ));
        let endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config.clone()),
            socket,
            runtime,
        )?;

        info!("QUIC endpoint created on {}", addr);
        info!(
            "QUIC application protocols: {:?}",
            config
                .quic_applications()
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
        );
        info!("PQC enabled: {}", tls_provider.is_pqc_enabled());

        // Create backend pool
        let backend_pool = Arc::new(BackendPool::new(&config));

        // Early Hints state is created once in main() and shared across all QUIC
        // listeners so the config reload handler can update it live.
        if early_hints_state.is_enabled() {
            info!("HTTP/3 Early Hints (103) enabled");
        }

        // Cloned before `config` moves into `Self`.
        let config_for_fingerprints = config.fingerprint.clone();
        let doq = if config.doq.enabled {
            Some(Arc::new(crate::doq::Service::new(&config.doq)?))
        } else {
            None
        };
        // The node's MoQ relay, shared with every listener and the
        // WebTransport server, its requests held to the same rate limits
        if let Some(moq) = crate::moq::start(&config.moq)? {
            let _ = moq.settings.limiter.set(Arc::clone(&advanced_rate_limiter));
        }

        Ok(Self {
            endpoint,
            tls_provider,
            server_config,
            tls_reloads,
            backend_pool,
            config,
            shutdown_rx,
            reload_rx,
            early_hints_state,
            metrics,
            security,
            advanced_rate_limiter,
            load_balancer,
            cache,
            fingerprint_extractor: Arc::new(FingerprintExtractor::new()),
            fingerprint_config: config_for_fingerprints,
            doq,
        })
    }

    /// Install the TLS provider's current rustls config on the endpoint, for
    /// the connections that arrive from now on (those open keep theirs). The
    /// rest of the server config is the startup one, so the transport settings
    /// and the key validating Retry tokens already handed out stay as they were.
    fn install_tls_config(&self) {
        install_crypto(
            &self.endpoint,
            &self.server_config,
            self.tls_provider.get_quic_server_config(),
        );
        info!(
            "🔏 QUIC {}: TLS configuration installed with the current ECH configs and certificates",
            self.endpoint
                .local_addr()
                .map_or_else(|_| "listener".to_string(), |a| a.to_string())
        );
    }

    /// Run the QUIC listener
    pub async fn run(mut self) -> anyhow::Result<()> {
        info!(
            "QUIC/HTTP3/WebTransport listener running on {}",
            self.endpoint.local_addr()?
        );

        let mut accept_count = 0u64;
        // The port this endpoint listens on, for `X-Forwarded-Port`: one
        // listener runs per port, so the configuration cannot say which.
        let local_port = self.endpoint.local_addr()?.port();

        loop {
            tokio::select! {
                // Handle incoming connections
                Some(incoming) = self.endpoint.accept() => {
                    accept_count += 1;
                    let remote_addr = crate::security::canonical_addr(incoming.remote_address());
                    let ip = remote_addr.ip();

                    // Connection-level security checks: IP blocklist and GeoIP country blocking.
                    // Evaluated before completing the QUIC/TLS handshake so blocked IPs never
                    // consume cryptographic handshake resources.
                    // The block was said once, when it was made: a refusal is
                    // at debug, since every Initial from (or spoofed as) a
                    // blocked address would otherwise be a warning.
                    let should_refuse = if !self.security.is_trusted(&ip) {
                        if let Some(block_info) = self.security.is_blocked(&ip) {
                            debug!(
                                "[QUIC] Refusing connection from blocked IP {} (reason: {:?})",
                                ip, block_info.reason
                            );
                            true
                        } else if let Some(reason) = self.security.geo_block_reason(&ip) {
                            self.security.geo_block(ip, &reason);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // A place under the connection limits, taken once the
                    // address is validated (a Retry costs nothing to answer).
                    let validated = !self.config.server.enable_quic_retry
                        || incoming.remote_address_validated();
                    let slot = if should_refuse || !validated {
                        None
                    } else {
                        let slot =
                            crate::conn_limits::admit(ip, self.security.is_limit_exempt(&ip));
                        if slot.is_none() {
                            debug!("[QUIC] Refusing {}: connection limit reached", remote_addr);
                        }
                        slot
                    };

                    if should_refuse || (validated && slot.is_none()) {
                        incoming.refuse();
                    } else if self.config.server.enable_quic_retry
                        && !incoming.remote_address_validated()
                    {
                        // QUIC Retry (RFC 9000 §8.1.2): the client's source
                        // address hasn't been validated yet, so answer with a
                        // Retry token instead of accepting. The client re-sends
                        // its Initial echoing the token; that second Incoming
                        // arrives with remote_address_validated() == true and
                        // is accepted normally on the next loop iteration.
                        // Configurable via [server].enable_quic_retry.
                        match incoming.retry() {
                            Ok(()) => {
                                debug!("[QUIC] Sent Retry for address validation to {}", remote_addr);
                            }
                            Err(e) => {
                                warn!("[QUIC] Retry failed for {}: {} — accepting without Retry", remote_addr, e);
                                // retry() consumes `incoming` even on error, so
                                // there is nothing left to accept here; the
                                // client will simply time out and retry itself.
                            }
                        }
                    } else {
                        debug!("[{}] Incoming QUIC connection from {}", accept_count, remote_addr);

                        // Spawn connection handler
                        let config = self.config.clone();
                        let backend_pool = self.backend_pool.clone();
                        let early_hints_state = self.early_hints_state.clone();
                        let metrics = self.metrics.clone();
                        let security = self.security.clone();
                        let advanced_rate_limiter = self.advanced_rate_limiter.clone();
                        let load_balancer = self.load_balancer.clone();
                        let cache = self.cache.clone();
                        let fingerprint_extractor = self.fingerprint_extractor.clone();
                        let fingerprint_config = self.fingerprint_config.clone();
                        let doq = self.doq.clone();

                        tokio::spawn(async move {
                            // Held until the connection ends
                            let _slot = slot;
                            if let Err(e) = Self::handle_connection(
                                incoming,
                                remote_addr,
                                local_port,
                                config,
                                backend_pool,
                                early_hints_state,
                                security,
                                metrics.clone(),
                                advanced_rate_limiter,
                                load_balancer,
                                cache,
                                fingerprint_extractor,
                                fingerprint_config,
                                doq,
                            ).await {
                                log_connection_end(remote_addr, &e);
                            }
                        });
                    }
                }

                // Handle config reload
                Some(event) = self.reload_rx.recv() => {
                    match event {
                        ConfigReloadEvent::ConfigReloaded(new_config) => {
                            info!("Applying configuration reload");
                            // New connections take everything from these; the
                            // fingerprint settings and the backend pool (its
                            // connect and pool timeouts are fixed when it is
                            // built) were kept from startup.
                            self.fingerprint_config = new_config.fingerprint.clone();
                            self.backend_pool = Arc::new(BackendPool::new(&new_config));
                            self.config = new_config;
                        }
                        // main reloads the shared TLS provider, once, and
                        // the reload is installed below (`tls_reloads`).
                        // Reloading it here too rebuilt it once more per
                        // QUIC listener, and none of them reached an endpoint.
                        ConfigReloadEvent::TlsCertsReloaded => {}
                        ConfigReloadEvent::ReloadFailed(msg) => {
                            error!("Configuration reload failed: {}", msg);
                        }
                    }
                }

                // A TLS reload: new connections get the rebuilt config
                Ok(()) = self.tls_reloads.changed() => {
                    self.install_tls_config();
                }

                // Handle shutdown
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping QUIC listener");
                    break;
                }
            }
        }

        // Graceful shutdown: tell peers we are going away, then wait for the
        // connections to finish.
        //
        // `wait_idle()` on its own waits for connections to close *by
        // themselves*, and an idle HTTP/3 connection from a browser does not:
        // it sits there until its own idle timeout, which outlives any
        // shutdown budget.  So every restart drained for the full
        // `graceful_shutdown_timeout_secs` and then gave up with connections
        // still counted active.  `close()` sends CONNECTION_CLOSE to each open
        // connection first (QUIC's equivalent of HTTP/2 GOAWAY), so peers
        // reconnect to the new process immediately instead of waiting to be
        // cut off.
        info!("Closing QUIC connections and waiting for them to drain...");
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"server shutting down");
        self.endpoint.wait_idle().await;

        info!("QUIC listener stopped");
        Ok(())
    }

    /// Handle a single QUIC connection
    #[expect(clippy::too_many_arguments)]
    async fn handle_connection(
        incoming: quinn::Incoming,
        remote_addr: SocketAddr,
        local_port: u16,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: Arc<SecurityState>,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        fingerprint_extractor: Arc<FingerprintExtractor>,
        fingerprint_config: crate::config::FingerprintConfig,
        doq: Option<Arc<crate::doq::Service>>,
    ) -> anyhow::Result<()> {
        // Accept connection
        let mut connecting = incoming.accept()?;

        // The handshake has the time a TCP one has (tls.handshake_timeout_secs);
        // the idle timeout is for a connection that completed it.
        let handshake_deadline = tokio::time::Instant::now()
            + Duration::from_secs(config.tls.handshake_timeout_secs.max(1));

        // Readable once the server has processed the ClientHello. Whether it
        // accepted 0-RTT is settled in that same step, and when it did, nothing
        // else here can still change: early data is impossible after a
        // HelloRetryRequest, which is the one thing that leaves the group and
        // ALPN undecided at this point.
        let hello_data = tokio::time::timeout_at(handshake_deadline, connecting.handshake_data())
            .await
            .map_err(|_| anyhow::anyhow!("QUIC handshake timed out before the ClientHello"))??
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok();
        let early_data = hello_data.as_ref().is_some_and(|d| d.early_data_accepted);

        // 0.5-RTT: take the connection before the handshake completes, so the
        // HTTP/3 SETTINGS below leave with the server's first flight instead of
        // after the client's Finished.
        //
        // The order matters to a resuming client. RFC 9114 §7.2.4.2 has it keep
        // the server's SETTINGS alongside a session ticket, and the tickets go
        // out the moment the handshake completes; SETTINGS sent after that
        // arrive behind them. neqo -- Firefox's stack -- drops a ticket that
        // arrives before SETTINGS, so it kept none of ours and never resumed or
        // sent 0-RTT here, while it did both against Cloudflare, Google and
        // nginx. Measured 2026-09-24 against pqcrypta.com and the conformance
        // 0-RTT ports alike.
        //
        // Nothing sent here depends on who the client is: SETTINGS carry no
        // secret and no client authentication has happened yet, which is
        // exactly the caution noq documents for 0.5-RTT data.
        let (connection, established) = connecting
            .into_0rtt()
            .map_err(|_| anyhow::anyhow!("QUIC stack refused 0.5-RTT on an incoming connection"))?;
        // The handshake's completion, held to its deadline: a connection that
        // has not finished by then is closed, which resolves it.
        let established: Established = {
            let connection = connection.clone();
            Box::pin(async move {
                tokio::pin!(established);
                tokio::select! {
                    accepted = &mut established => accepted,
                    () = tokio::time::sleep_until(handshake_deadline) => {
                        debug!(
                            "QUIC handshake from {} not finished by its deadline: closed",
                            remote_addr
                        );
                        connection.close(0u32.into(), b"handshake timeout");
                        established.await
                    }
                }
            })
        };

        // DNS over QUIC, where the client named it: `doq` is in the ALPN list
        // only when `[doq]` is on, so a negotiated `doq` has its service
        let (negotiated, established) =
            application_protocol(hello_data.as_deref(), &connection, established).await;
        // Counted by the application the client negotiated, once it is known:
        // every QUIC connection was counted as HTTP/3 when it was accepted, so
        // DNS over QUIC and handshakes that never finished read as HTTP/3
        // traffic in every figure built on these counters. Held until the
        // connection ends.
        if negotiated.as_deref() == Some(crate::doq::ALPN) {
            let _open = metrics
                .connections
                .connection_opened(ConnectionProtocol::Doq);
            if let Some(service) = doq {
                crate::doq::serve(
                    connection,
                    established,
                    early_data,
                    remote_addr.ip(),
                    service,
                    advanced_rate_limiter,
                )
                .await;
            }
            return Ok(());
        }
        // Media over QUIC on native QUIC: a MOQT version is in the ALPN list
        // only when `[moq]` is on. Served once the handshake completes, so
        // nothing replayable in 0-RTT starts a subscription upstream
        // (draft-ietf-moq-transport section 6.3.1).
        if let (Some(alpn), Some(moq)) = (negotiated.as_deref(), crate::moq::running()) {
            if crate::moq::version::Version::from_alpn(alpn).is_some() {
                let _open = metrics
                    .connections
                    .connection_opened(ConnectionProtocol::Moqt);
                if handshake_completed(established, &connection).await {
                    moq.serve_quic(connection, alpn, remote_addr).await;
                }
                return Ok(());
            }
        }
        let _open = metrics
            .connections
            .connection_opened(ConnectionProtocol::Http3);

        // Advertises SETTINGS_ENABLE_WEBTRANSPORT=1 and
        // SETTINGS_WEBTRANSPORT_MAX_SESSIONS (draft-ietf-webtrans-http3-09 §8.2).
        //
        // The advertised limit is the limit actually enforced. It was hardcoded
        // to 1000 while `webtransport_max_sessions_per_origin` — the value
        // `handle_webtransport_session` refuses connections against — defaults
        // to 100. A client was told it could open ten times what it would be
        // given, which is worse than saying nothing: the setting exists so a
        // peer can size its own behaviour, and a wrong number is acted upon.
        // The field section limit is the one the TCP listeners hold requests
        // to (security.max_header_size), advertised in SETTINGS and enforced
        // while decoding: h3's default was no limit, so a request of tens of
        // thousands of one-octet field lines was decoded in full (QPACK
        // "header accordions", FoxIO, October 2026).
        let wt_limits = wt_initial_limits(&config);
        let h3_built = h3::server::builder()
            .max_field_section_size(config.security.max_header_size as u64)
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(config.server.webtransport_max_sessions_per_origin as u64)
            // draft-ietf-webtrans-http3-17 section 3.1, beside the earlier
            // drafts' two settings, which clients of those drafts read
            .wt_enabled(true)
            .wt_initial_limits(
                wt_limits.streams_uni,
                wt_limits.streams_bidi,
                wt_limits.data,
            )
            .build(H3Connection::new(connection.clone()))
            .await;

        // Serving waits for the handshake unless the connection carries 0-RTT.
        // A request that arrives after it is safe from replay, since a replayed
        // flight can never produce the client's Finished; the ones that arrive
        // before it are marked per stream (`x-tls-early-data`) and held to
        // RFC 8470 by the route gate.
        let (handshake_data, completing) = if early_data {
            info!("QUIC connection accepted with 0-RTT: {}", remote_addr);
            (hello_data, Some(established))
        } else {
            // Resolves when the handshake ends either way. Its value is whether
            // 0-RTT was accepted -- false on every ordinary connection, so it
            // says nothing about success; a close reason does.
            established.await;
            if let Some(reason) = connection.close_reason() {
                metrics.handshake_failed();
                return Err(reason.into());
            }
            debug!("QUIC connection established: {}", remote_addr);
            // Read again: this is where a HelloRetryRequest's group and ALPN
            // become final.
            let data = connection
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
            (data.or(hello_data), None)
        };

        // Read everything the handshake exposes in one pass: ALPN, the
        // negotiated group and cipher suite for the Handshake Mirror, and the
        // ClientHello bytes for fingerprinting.
        //
        // The hello is only reachable here. Over TCP a listener peeks the socket
        // and parses the hello itself; over QUIC it arrives inside encrypted
        // Initial CRYPTO frames, so the TLS stack holds the only plaintext copy
        // and the vendored rustls/noq forks hand it out through HandshakeData.
        let mut handshake_facts = quic_handshake_facts_empty();
        let mut client_hello: Option<Vec<u8>> = None;

        if let Some(crypto_data) = handshake_data.as_deref() {
            if let Some(protocol) = &crypto_data.protocol {
                let alpn = String::from_utf8_lossy(protocol);
                debug!("ALPN negotiated: {} for {}", alpn, remote_addr);
                handshake_facts.alpn = Some(alpn.into_owned());
            }
            handshake_facts.kex_group = crypto_data
                .negotiated_key_exchange_group
                .map(|g| format!("{g:?}"));
            handshake_facts.cipher_suite = crypto_data
                .negotiated_cipher_suite
                .map(|c| format!("{c:?}"));
            client_hello = crypto_data.client_hello_wire.clone();
            // ECH applies over QUIC exactly as over TCP; the page reported
            // it as "not observable over HTTP/3" only because nothing
            // carried the result up here.
            if let Some(ech) = crypto_data.ech_accepted {
                handshake_facts.ech = match ech {
                    rustls::server::EchAcceptance::NotOffered => "not-offered",
                    rustls::server::EchAcceptance::Rejected => "rejected",
                    rustls::server::EchAcceptance::UnknownConfig => "unknown-config",
                    rustls::server::EchAcceptance::Accepted => "accepted",
                };
            }
        }

        // Counted once the facts are final: now, or -- for a connection that
        // is already serving 0-RTT -- when its handshake completes, which a
        // replayed flight never does.
        let pqc = handshake_facts.is_post_quantum();
        let completed = {
            let metrics = metrics.clone();
            let group = handshake_facts.kex_group.clone();
            let client = remote_addr.ip();
            move || {
                metrics.tls.handshake_completed(true, pqc);
                crate::pqc_policy::handshake_completed(client, group.as_deref(), pqc);
            }
        };
        match completing {
            None => completed(),
            Some(established) => {
                let connection = connection.clone();
                tokio::spawn(async move {
                    established.await;
                    if connection.close_reason().is_none() {
                        completed();
                    }
                });
            }
        }

        // Fingerprint the client, applying exactly the policy the TCP path
        // applies — same classification order, same cache, same pentest bypass,
        // same ban decision.
        //
        // Unlike TCP this happens *after* the handshake rather than before it. A
        // QUIC server cannot decline earlier: the hello is encrypted under keys
        // derived during the handshake it would be trying to avoid. The block
        // still lands before any HTTP/3 request is served.
        let fingerprint = match client_hello.as_deref() {
            // `fingerprint.enabled = false` has to mean the same thing on both
            // transports. The TCP listeners gate their whole fingerprint stage on
            // it; this path did not, so an operator who turned fingerprinting off
            // still had QUIC connections classified and banned — a security policy
            // that applied over HTTP/3 and not over HTTP/1.1 or HTTP/2, with
            // nothing in the configuration saying so. Found when a load generator
            // was blocked as Suspicious on a run with the feature explicitly
            // disabled.
            Some(hello) if fingerprint_config.enabled => fingerprint_extractor
                .process_client_hello_quic(hello, remote_addr.ip(), &security, &fingerprint_config),
            Some(_) => crate::fingerprint::FingerprintResult {
                allowed: true,
                ja3_hash: None,
                ja4_hash: None,
                classification: None,
                client_name: None,
            },
            None => {
                debug!(
                    "[QUIC] No ClientHello available for {} — not fingerprinted",
                    remote_addr
                );
                crate::fingerprint::FingerprintResult {
                    allowed: true,
                    ja3_hash: None,
                    ja4_hash: None,
                    classification: None,
                    client_name: None,
                }
            }
        };

        if !fingerprint.allowed {
            warn!(
                "[QUIC] Blocking {} on TLS fingerprint (class={:?}, ja4={:?})",
                remote_addr, fingerprint.classification, fingerprint.ja4_hash
            );
            connection.close(0u32.into(), b"blocked");
            return Ok(());
        }

        // Multipath path management is fully automatic in noq once
        // negotiated (see max_concurrent_multipath_paths in the transport
        // config) - the peer opens/validates additional paths and the stack
        // schedules across them. Subscribe to noq's PathEvent stream so real
        // multipath activity (a second path opening, its per-path stats, and
        // teardown) is observable in the server logs, not silent inside the
        // transport. Costs nothing when no extra paths are opened.
        {
            let conn_for_paths = connection.clone();
            let peer = remote_addr;
            tokio::spawn(async move {
                let mut events = conn_for_paths.path_events();
                while let Some(ev) = events.next().await {
                    match ev {
                        Ok(quinn::PathEvent::Established { id, .. }) => {
                            let (rtt_ms, cwnd, mtu) = conn_for_paths
                                .path_stats(id)
                                .map(|s| {
                                    (
                                        u64::try_from(s.rtt.as_millis()).unwrap_or(u64::MAX),
                                        s.cwnd,
                                        u64::from(s.current_mtu),
                                    )
                                })
                                .unwrap_or((0, 0, 0));
                            info!(
                                "Multipath: path {} ESTABLISHED for {} (rtt={}ms cwnd={}B mtu={}B)",
                                id.get(),
                                peer,
                                rtt_ms,
                                cwnd,
                                mtu
                            );
                        }
                        Ok(quinn::PathEvent::Abandoned { id, reason, .. }) => {
                            info!(
                                "Multipath: path {} ABANDONED for {} (reason: {:?})",
                                id.get(),
                                peer,
                                reason
                            );
                        }
                        Ok(quinn::PathEvent::Discarded { id, path_stats, .. }) => {
                            info!(
                                "Multipath: path {} DISCARDED for {} (final: rtt={}ms cwnd={}B lost_pkts={})",
                                id.get(),
                                peer,
                                u64::try_from(path_stats.rtt.as_millis()).unwrap_or(u64::MAX),
                                path_stats.cwnd,
                                path_stats.lost_packets
                            );
                        }
                        Ok(_) => {}
                        Err(_lagged) => {
                            // Broadcast receiver fell behind; benign for logging.
                        }
                    }
                }
            });
        }

        match h3_built {
            Ok(mut h3) => {
                // HTTP/3 connection established
                Self::handle_h3_connection(
                    &mut h3,
                    connection,
                    remote_addr,
                    local_port,
                    config,
                    backend_pool,
                    early_hints_state,
                    security,
                    metrics,
                    advanced_rate_limiter,
                    load_balancer,
                    cache,
                    Arc::new(handshake_facts),
                    Arc::new(fingerprint),
                )
                .await?;
            }
            Err(e) => {
                // A connection that cannot set up HTTP/3 has nothing this
                // listener serves: it is closed, as H3_SETTINGS_ERROR asks
                // (RFC 9114 section 7.2.4). Its streams used to be passed to
                // the root route's backend as raw POSTs, past every rule.
                debug!("HTTP/3 setup with {} failed: {}", remote_addr, e);
                connection.close(quinn::VarInt::from_u32(0x109), b"HTTP/3 setup failed");
            }
        }

        debug!("Connection closed: {}", remote_addr);
        Ok(())
    }

    /// Handle HTTP/3 connection with WebTransport support
    #[expect(clippy::too_many_arguments)]
    async fn handle_h3_connection(
        h3: &mut h3::server::Connection<H3Connection, Bytes>,
        quic_connection: QuinnConnection,
        remote_addr: SocketAddr,
        local_port: u16,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: Arc<SecurityState>,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        handshake: Arc<crate::tls_acceptor::HandshakeFacts>,
        fingerprint: Arc<crate::fingerprint::FingerprintResult>,
    ) -> anyhow::Result<()> {
        // Lazily created on the first CONNECT-UDP session so connections that
        // never use MASQUE pay nothing for the datagram reader task.
        let mut datagram_router: Option<Arc<DatagramRouter>> = None;

        // Built once for the connection rather than once per request; see
        // `H3ConnHeaders`.
        let conn_headers = Arc::new(H3ConnHeaders::new(
            &config,
            remote_addr,
            local_port,
            &fingerprint,
            &handshake,
        ));

        // Decided once per connection, as the TCP listeners decide it once per
        // router: with tracing off, a request pays nothing for it.
        let request_spans = config.otel.enabled || request_span_enabled();

        // What is in flight on the connection (every request, tunnel and
        // session holds a place until it ends), so that while memory is short
        // a connection with nothing in flight is sent GOAWAY and closed
        // (crate::memory_pressure); the time it closes at once sent it.
        let activity = crate::conn_limits::Activity::new();
        let mut relief = crate::memory_pressure::relief();
        let mut closing: Option<tokio::time::Instant> = None;

        // Every ordinary request becomes its own task. One definition for both
        // places that dispatch one: the plain-request fast path below and an
        // extended CONNECT this listener does not terminate itself.
        let spawn_request = |stream, request: http::Request<()>| {
            let span = if request_spans {
                request_span(&request, remote_addr.ip())
            } else {
                tracing::Span::none()
            };
            let config_clone = config.clone();
            let backend_pool_clone = backend_pool.clone();
            let early_hints_clone = early_hints_state.clone();
            let metrics_clone = metrics.clone();
            let security_clone = security.clone();
            let rl_clone = advanced_rate_limiter.clone();
            let lb_clone = load_balancer.clone();
            let cache_clone = cache.clone();
            let handshake_clone = handshake.clone();
            let fingerprint_clone = fingerprint.clone();
            let conn_headers_clone = conn_headers.clone();

            let flight = activity.begin();
            tokio::spawn(
                async move {
                    let _flight = flight;
                    if let Err(e) = Self::handle_h3_request(
                        stream,
                        request,
                        remote_addr,
                        config_clone,
                        backend_pool_clone,
                        early_hints_clone,
                        security_clone,
                        metrics_clone,
                        rl_clone,
                        lb_clone,
                        cache_clone,
                        handshake_clone,
                        fingerprint_clone,
                        conn_headers_clone,
                    )
                    .await
                    {
                        // A violation that ends the connection is reported
                        // once, where the connection's accept loop ends.
                        if is_benign_h3_close(&e) || is_peer_violation(&e) {
                            debug!("HTTP/3 request ended by peer: {}", e);
                        } else {
                            error!("HTTP/3 request error: {}", e);
                        }
                    }
                }
                .instrument(span),
            );
        };

        // The WebTransport sessions open on this connection, by session ID
        // (the CONNECT's stream ID): their streams and datagrams are handed
        // to them here (crate::wt_session).
        let mut wt_sessions: std::collections::HashMap<u64, crate::wt_session::H3SessionFeed> =
            std::collections::HashMap::new();

        // Request streams whose header block is still arriving, resolved beside
        // the accept loop rather than in it: one stream's slow or stalled
        // header block held up every other stream of the connection, and the
        // loop's own GOAWAY and close with them. Each has as long as the TCP
        // listeners give a request's header (`server.max_idle_timeout_secs`).
        let mut resolving = futures_util::stream::FuturesUnordered::new();
        let header_wait = Duration::from_secs(config.server.max_idle_timeout_secs.max(1));
        // WebTransport requests that came before the client's SETTINGS,
        // waiting for them (draft-ietf-webtrans-http3-17 section 3.1: a
        // server processes none before), the connection served meanwhile
        let mut awaiting_settings = futures_util::stream::FuturesUnordered::new();
        // What this connection's SETTINGS declared (the builder's own)
        let wt_limits = wt_initial_limits(&config);

        loop {
            let step = tokio::select! {
                Some(resolved) = resolving.next(), if !resolving.is_empty() => {
                    Step::Resolved(resolved)
                }
                Some(held) = awaiting_settings.next(), if !awaiting_settings.is_empty() => {
                    match held {
                        Some((request, stream)) => {
                            Step::Resolved(Ok(Ok(h3::server::Resolved::Request(request, stream))))
                        }
                        None => {
                            // Dropping the stream resets it
                            debug!(
                                "WebTransport request from {} with no SETTINGS within {:?}",
                                remote_addr, header_wait
                            );
                            continue;
                        }
                    }
                }
                accepted = h3.accept_any() => Step::Accepted(accepted),
                () = crate::memory_pressure::idle_at_relief(&mut relief, &activity),
                    if closing.is_none() =>
                {
                    // GOAWAY (RFC 9114 section 5.2): the peer opens no more
                    // requests here and takes the next one elsewhere
                    crate::memory_pressure::connection_shed();
                    if let Err(e) = h3.shutdown(0).await {
                        debug!("HTTP/3 GOAWAY to {} failed: {}", remote_addr, e);
                        break;
                    }
                    closing = Some(tokio::time::Instant::now() + SHED_GRACE);
                    continue;
                }
                // Nothing in flight for `server.max_idle_timeout_secs`
                // (shorter while memory is short): GOAWAY, then closed as
                // above, as the TCP listeners close an idle connection. The
                // server's keep-alive PINGs kept an idle client's connection
                // open for as long as the client acknowledged them.
                () = idle_past(&activity, header_wait),
                    if closing.is_none() && resolving.is_empty() =>
                {
                    if activity
                        .idle_for()
                        .is_some_and(|quiet| quiet >= crate::memory_pressure::idle_limit(header_wait))
                    {
                        debug!("HTTP/3 connection from {} idle: GOAWAY", remote_addr);
                        if let Err(e) = h3.shutdown(0).await {
                            debug!("HTTP/3 GOAWAY to {} failed: {}", remote_addr, e);
                            break;
                        }
                        closing = Some(tokio::time::Instant::now() + SHED_GRACE);
                    }
                    continue;
                }
                () = async {
                    match closing {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    if activity.idle_for().is_some() {
                        quic_connection.close(quinn::VarInt::from_u32(H3_NO_ERROR), b"");
                        break;
                    }
                    // What was opened before the GOAWAY is still running
                    closing = Some(tokio::time::Instant::now() + SHED_GRACE);
                    continue;
                }
            };
            match step {
                Step::Accepted(Ok(Some(h3::server::Accepted::WebTransportUni {
                    session,
                    prefix,
                    stream,
                }))) => {
                    deliver_wt_uni(&mut wt_sessions, session, prefix, stream);
                }
                Step::Accepted(Ok(Some(h3::server::Accepted::Request(resolver)))) => {
                    resolving.push(tokio::time::timeout(header_wait, resolver.resolve_any()));
                }
                Step::Resolved(resolved) => {
                    // The request, or the WebTransport stream
                    let (mut request, stream) = match resolved {
                        Ok(Ok(h3::server::Resolved::Request(request, stream))) => (request, stream),
                        Ok(Ok(h3::server::Resolved::WebTransportBi {
                            session,
                            prefix,
                            stream,
                        })) => {
                            deliver_wt_bi(&mut wt_sessions, session, prefix, stream);
                            continue;
                        }
                        Err(_) => {
                            // Dropping the stream resets it
                            debug!(
                                "HTTP/3 request from {} sent no whole header block within {:?}",
                                remote_addr, header_wait
                            );
                            continue;
                        }
                        Ok(Err(e)) => {
                            if request_error_is_peers(&e)
                                || is_benign_h3_close(&e)
                                || is_peer_violation(&e)
                            {
                                debug!("HTTP/3 request from {} not taken: {}", remote_addr, e);
                            } else {
                                error!("Failed to resolve request from {}: {}", remote_addr, e);
                            }
                            continue;
                        }
                    };

                    if !stream.is_0rtt() {
                        conn_headers.resolve_client_cert(&quic_connection);
                    }

                    // Everything below is for extended CONNECT — WebTransport,
                    // WebSocket and CONNECT-UDP. An ordinary request needs none
                    // of it, and computing it first cost every request a URI
                    // clone and two owned strings it never read.
                    if request.method() != http::Method::CONNECT {
                        debug!(
                            "HTTP/3 request: {} {} from {}",
                            request.method(),
                            request.uri().path(),
                            remote_addr
                        );
                        spawn_request(stream, request);
                        continue;
                    }

                    if h3.peer_settings().is_none()
                        && request
                            .extensions()
                            .get::<Protocol>()
                            .is_some_and(Protocol::is_webtransport)
                    {
                        let arrived = h3.peer_settings_arrived();
                        awaiting_settings.push(async move {
                            tokio::time::timeout(header_wait, arrived)
                                .await
                                .ok()
                                .map(|()| (request, stream))
                        });
                        continue;
                    }

                    // A session or tunnel opened from 0-RTT is one a replayed
                    // flight could open as well, and none of them is a request
                    // the route gate's safe-method list can vouch for. RFC 8470
                    // §5.2: 425 asks the client to repeat it once the handshake
                    // has completed, where it is served as usual.
                    if stream.is_0rtt() {
                        debug!(
                            "Extended CONNECT in 0-RTT from {} answered 425 Too Early",
                            remote_addr
                        );
                        let mut stream = stream;
                        let too_early = http::Response::builder()
                            .status(http::StatusCode::TOO_EARLY)
                            .body(())?;
                        if stream.send_response(too_early).await.is_ok() {
                            let _ = stream.finish().await;
                        }
                        continue;
                    }

                    // The connection's own fingerprint, certificate and
                    // protocol fields, set as on every other request before
                    // anything reads its headers (no early data reaches here)
                    request::derive_connection_headers(
                        request.headers_mut(),
                        &handshake,
                        &conn_headers,
                        &fingerprint,
                        false,
                    );

                    let method = request.method().clone();
                    let uri = request.uri().clone();
                    let path = crate::path_canon::canonical_path(
                        uri.path(),
                        crate::path_canon::PathCanon::from(&config.server),
                    )
                    .into_owned();
                    // The host this request names (crate::request_target); one
                    // that names two is left to the request handler, which
                    // answers it 400.
                    let Ok(host) =
                        crate::request_target::effective_host_name(&uri, request.headers())
                    else {
                        spawn_request(stream, request);
                        continue;
                    };

                    // Check for protocol extension (RFC 9220 Extended CONNECT)
                    // In h3 crate, the :protocol pseudo-header is accessed via extensions
                    let protocol_ext = request.extensions().get::<Protocol>();
                    debug!(
                        "HTTP/3 request: {} {} from {} (host: {:?}, :protocol: {:?})",
                        method, path, remote_addr, host, protocol_ext
                    );

                    // WebTransport: extended CONNECT whose :protocol is
                    // `webtransport-h3` (draft-ietf-webtrans-http3-17
                    // section 3.2) or the earlier drafts' `webtransport`
                    let is_webtransport = method == http::Method::CONNECT
                        && protocol_ext.is_some_and(Protocol::is_webtransport);

                    // RFC 9220: WebSocket over HTTP/3 uses Extended CONNECT with :protocol = websocket
                    let is_ws_h3 = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "websocket")
                            .unwrap_or(false);

                    // RFC 9298: CONNECT-UDP uses Extended CONNECT with :protocol = connect-udp
                    let is_connect_udp = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "connect-udp")
                            .unwrap_or(false);

                    // What this listener answers itself is held to the rules
                    // every other request meets before anything is opened, and
                    // written to the access log either way.
                    if is_webtransport || is_ws_h3 || is_connect_udp {
                        // The route each is served by, whose gates it meets:
                        // a WebTransport or WebSocket route, and for
                        // CONNECT-UDP (governed by `[masque]`) any route that
                        // covers its path.
                        let gate_route = if is_webtransport {
                            config
                                .find_route(host.as_deref(), &path, true)
                                .filter(|r| r.webtransport)
                        } else if is_ws_h3 {
                            config
                                .find_route(host.as_deref(), &path, false)
                                .filter(|r| r.supports_websocket)
                        } else {
                            config.find_route(host.as_deref(), &path, false)
                        };
                        // A classical key exchange where the server refuses
                        // those is answered as any other request on the
                        // connection is (pqc_policy.rs).
                        let refusal =
                            if crate::pqc_policy::refuses(conn_headers.pqc_enabled == "true") {
                                Some((http::StatusCode::MISDIRECTED_REQUEST, Vec::new()))
                            } else {
                                connect_refusal(
                                    &security,
                                    &advanced_rate_limiter,
                                    &config,
                                    &request,
                                    host.as_deref(),
                                    &path,
                                    gate_route,
                                    remote_addr,
                                    &fingerprint,
                                )
                                .await
                            };
                        if let Some((status, extra)) = refusal {
                            log_connect(
                                &request,
                                host.as_deref(),
                                &path,
                                remote_addr,
                                &fingerprint,
                                status.as_u16(),
                            );
                            warn!(
                                "[QUIC/H3] extended CONNECT ({:?}) for {} from {} refused: {}",
                                protocol_ext, path, remote_addr, status
                            );
                            let mut stream = stream;
                            let mut refused = http::Response::builder().status(status);
                            for (name, value) in extra {
                                refused = refused.header(name, value);
                            }
                            let refused = refused.body(())?;
                            if stream.send_response(refused).await.is_ok() {
                                let _ = stream.finish().await;
                            }
                            continue;
                        }
                    }

                    // The access-log line of whichever answer follows.
                    let log_outcome = |status: http::StatusCode| {
                        log_connect(
                            &request,
                            host.as_deref(),
                            &path,
                            remote_addr,
                            &fingerprint,
                            status.as_u16(),
                        );
                    };

                    if is_webtransport {
                        info!(
                            "WebTransport CONNECT request for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        // A draft-17 client (its `webtransport-h3` token, or
                        // its SETTINGS_WT_ENABLED) may have one session per
                        // connection without flow control, which needs both
                        // ends to declare initial limits (draft-ietf-webtrans-
                        // http3-17 section 5.1): a further CONNECT is reset
                        // with H3_REQUEST_REJECTED
                        let peer_settings = h3.peer_settings();
                        let draft17 = protocol_ext == Some(&Protocol::WEB_TRANSPORT_H3)
                            || peer_settings.is_some_and(|s| s.wt_enabled());
                        let flow_control = peer_settings.is_some_and(|s| s.wt_flow_control());
                        if draft17
                            && !flow_control
                            && wt_sessions.values().any(|feed| !feed.has_ended())
                        {
                            debug!(
                                "WebTransport CONNECT from {}: a second session without flow control, reset H3_REQUEST_REJECTED",
                                remote_addr
                            );
                            let mut stream = stream;
                            stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                            stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                            continue;
                        }

                        // The same admission as every entrance's
                        // (webtransport_server::admit): a browser's Origin
                        // against server.webtransport_allowed_origins where
                        // the route is not the MoQ relay's (which verifies it
                        // by [moq]'s rules, below), and the per-client and
                        // per-origin session caps, held while the session lasts
                        let moq_route = crate::moq::running().is_some_and(|m| path == m.path);
                        let admission = match crate::webtransport_server::admit(
                            &config,
                            request
                                .headers()
                                .get(http::header::ORIGIN)
                                .map(|o| o.to_str().unwrap_or("null")),
                            remote_addr.ip(),
                            !moq_route,
                        ) {
                            Ok(a) => a,
                            Err(why) => {
                                warn!(
                                    "WebTransport session from {} for {} refused: {}",
                                    remote_addr, path, why
                                );
                                log_outcome(http::StatusCode::FORBIDDEN);
                                let mut stream = stream;
                                let refused = http::Response::builder()
                                    .status(http::StatusCode::FORBIDDEN)
                                    .body(())?;
                                if stream.send_response(refused).await.is_ok() {
                                    let _ = stream.finish().await;
                                }
                                continue;
                            }
                        };

                        // Media over QUIC over WebTransport: the version is
                        // the one WT-Available-Protocols and WT-Protocol
                        // agree (draft-ietf-moq-transport section 6.2.1,
                        // draft-ietf-webtrans-http3 section 3.3)
                        if let Some(moq) = crate::moq::running().filter(|m| path == m.path) {
                            // A browser's Origin is verified (draft-ietf-
                            // webtrans-http3-17 section 3.2); a client that
                            // sends none is not a browser
                            let origin = request
                                .headers()
                                .get(http::header::ORIGIN)
                                .map(|o| o.to_str().unwrap_or("null").to_string());
                            if let Some(origin) = origin.filter(|o| {
                                !moq.origin_allowed(o, uri.authority().map(|a| a.as_str()))
                            }) {
                                debug!(
                                    "MoQ WebTransport session from {} refused: Origin {} not allowed",
                                    remote_addr, origin
                                );
                                log_outcome(http::StatusCode::FORBIDDEN);
                                let mut stream = stream;
                                let refused = http::Response::builder()
                                    .status(http::StatusCode::FORBIDDEN)
                                    .body(())?;
                                if stream.send_response(refused).await.is_ok() {
                                    let _ = stream.finish().await;
                                }
                                continue;
                            }
                            let offered = request
                                .headers()
                                .get("wt-available-protocols")
                                .and_then(|v| v.to_str().ok());
                            let mut stream = stream;
                            let Some((version, wt_protocol)) =
                                crate::moq::negotiate_webtransport(offered)
                            else {
                                log_outcome(http::StatusCode::BAD_REQUEST);
                                let refused = http::Response::builder()
                                    .status(http::StatusCode::BAD_REQUEST)
                                    .header("content-type", "text/plain")
                                    .body(())?;
                                if stream.send_response(refused).await.is_ok() {
                                    let _ = stream
                                        .send_data(Bytes::from_static(
                                            b"WT-Available-Protocols names no MOQT version this relay speaks\n",
                                        ))
                                        .await;
                                    let _ = stream.finish().await;
                                }
                                continue;
                            };
                            let response = http::Response::builder()
                                .status(http::StatusCode::OK)
                                .header("wt-protocol", wt_protocol)
                                .body(())?;
                            if stream.send_response(response).await.is_err() {
                                continue;
                            }
                            log_outcome(http::StatusCode::OK);
                            let wt_open = metrics
                                .connections
                                .connection_opened(ConnectionProtocol::WebTransport);
                            let session_id = stream.send_id().into_inner();
                            let (flow, capsules) = session_flow(wt_limits, peer_settings);
                            let (session, feed) = crate::wt_session::H3Session::new(
                                session_id,
                                quic_connection.clone(),
                                flow,
                            );
                            let router = datagram_router
                                .get_or_insert_with(|| DatagramRouter::new(quic_connection.clone()))
                                .clone();
                            router.route_webtransport(
                                session.quarter_stream_id(),
                                feed.datagram_sender(),
                            );
                            wt_sessions.retain(|_, feed| !feed.has_ended());
                            wt_sessions.insert(session_id, feed);
                            let close_requests = session.close_requests();
                            let serve = moq.serve_webtransport(
                                Arc::clone(&session),
                                remote_addr,
                                version,
                                path.clone(),
                            );
                            let flight = activity.begin();
                            tokio::spawn(async move {
                                let _flight = flight;
                                let _admission = admission;
                                // The MoQ session sees its end and finishes,
                                // noting how; were it dropped instead, its
                                // cleanup would still run (moq::session's
                                // `Ended`)
                                let (_, end) = crate::wt_session::hold_connect_stream(
                                    stream,
                                    &session,
                                    capsules,
                                    close_requests,
                                    serve,
                                    WT_SESSION_WIND_DOWN,
                                )
                                .await;
                                debug!(
                                    "MoQ WebTransport session from {} ended: {:?}",
                                    remote_addr, end
                                );
                                router.unregister_session(session.quarter_stream_id());
                                drop(wt_open);
                            });
                            continue;
                        }

                        // Reject WebTransport sessions for hosts/paths with no matching WT route.
                        // Without this check the proxy accepts every CONNECT unconditionally,
                        // leaving the session open until a 5-second idle timeout fires — which
                        // stalls scanners and health checks on non-WebTransport hosts.
                        // Note: find_route(is_webtransport=true) still returns non-WT routes
                        // (route_matches only prevents WT-only routes matching non-WT requests,
                        // not the reverse), so we must additionally check route.webtransport.
                        let wt_route = config
                            .find_route(host.as_deref(), &path, true)
                            .filter(|r| r.webtransport);
                        if wt_route.is_none() {
                            debug!(
                                "WebTransport CONNECT rejected (no WT route) for {} from {}",
                                path, remote_addr
                            );
                            log_outcome(http::StatusCode::NOT_FOUND);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Send 200 OK to accept the WebTransport session.
                        // IMPORTANT: Do NOT finish the stream - WebTransport sessions keep it open.
                        //
                        // No `sec-webtransport-http3-draft` header. That pair was
                        // draft-02's version handshake: the client sent
                        // `Sec-Webtransport-Http3-Draft02: 1` and the server
                        // echoed `draft02`. Every draft since removed it, and
                        // Chrome has not sent the request half for years — so
                        // answering with the echo announces a version the peer
                        // never asked for.
                        //
                        // It was the entire difference. Replaying Chrome's exact
                        // CONNECT with an independent stack, :443 answered
                        // `200` + this header and :4433 answered a bare `200`;
                        // Chrome accepts :4433 and rejects :443. The SETTINGS
                        // were already correct on both — ENABLE_CONNECT_PROTOCOL,
                        // H3_DATAGRAM and WEBTRANSPORT_MAX_SESSIONS=100 all
                        // present and read back by an outside client.
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())?;

                        // Respond on the stream first
                        let mut stream = stream;
                        if let Err(e) = stream.send_response(response).await {
                            error!(
                                "Failed to send WebTransport response to {}: {}",
                                remote_addr, e
                            );
                            continue;
                        }

                        info!(
                            "WebTransport session accepted for {} on path {}",
                            remote_addr, path
                        );
                        log_outcome(http::StatusCode::OK);

                        // Counted open until the session's task ends
                        let wt_open = metrics
                            .connections
                            .connection_opened(ConnectionProtocol::WebTransport);

                        // Handle WebTransport session - pass the stream to the handler
                        // The session handler will manage bidirectional streams and datagrams
                        // The session: its streams and datagrams come from
                        // this loop and the connection's datagram router, and
                        // it is served as the WebTransport server serves its
                        // own (webtransport_server::serve_session).
                        let session_id = stream.send_id().into_inner();
                        let (flow, capsules) = session_flow(wt_limits, peer_settings);
                        let (session, feed) = crate::wt_session::H3Session::new(
                            session_id,
                            quic_connection.clone(),
                            flow,
                        );
                        let router = datagram_router
                            .get_or_insert_with(|| DatagramRouter::new(quic_connection.clone()))
                            .clone();
                        router.route_webtransport(
                            session.quarter_stream_id(),
                            feed.datagram_sender(),
                        );
                        wt_sessions.retain(|_, feed| !feed.has_ended());
                        wt_sessions.insert(session_id, feed);

                        let serve = crate::webtransport_server::serve_session(
                            Arc::clone(&session),
                            remote_addr,
                            host.clone(),
                            path.clone(),
                            wt_route.map(crate::webtransport_server::WtTarget::of),
                            config.clone(),
                            backend_pool.clone(),
                            Some((*security).clone()),
                        );
                        let close_requests = session.close_requests();
                        let flight = activity.begin();
                        tokio::spawn(async move {
                            let _flight = flight;
                            let _admission = admission;
                            // The CONNECT stream IS the session (Chrome tears
                            // the session down when it is finished or reset):
                            // held for the session's life, its capsules read
                            // and written (crate::wt_session::hold_connect_stream)
                            debug!(
                                "WebTransport session active for {} on path {}",
                                remote_addr, path
                            );
                            let (served, end) = crate::wt_session::hold_connect_stream(
                                stream,
                                &session,
                                capsules,
                                close_requests,
                                serve,
                                WT_SESSION_WIND_DOWN,
                            )
                            .await;
                            if let Some(Err(e)) = served {
                                debug!("WebTransport session for {} ended: {}", remote_addr, e);
                            }
                            router.unregister_session(session.quarter_stream_id());
                            debug!("WebTransport session ended for {}: {:?}", remote_addr, end);
                            drop(wt_open);
                        });
                    } else if is_connect_udp {
                        // RFC 9298: CONNECT-UDP. Relay UDP datagrams between the
                        // client and an allowlisted target host:port.
                        let mut stream = stream;

                        if !config.masque.enabled {
                            debug!("CONNECT-UDP rejected (disabled) from {}", remote_addr);
                            log_outcome(http::StatusCode::NOT_FOUND);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        let Some((target_host, target_port)) = connect_udp::parse_target(&path)
                        else {
                            debug!(
                                "CONNECT-UDP bad target path '{}' from {}",
                                path, remote_addr
                            );
                            log_outcome(http::StatusCode::BAD_REQUEST);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        if !config.masque.is_target_allowed(&target_host, target_port) {
                            warn!(
                                "CONNECT-UDP target {}:{} not allowed (from {})",
                                target_host, target_port, remote_addr
                            );
                            log_outcome(http::StatusCode::FORBIDDEN);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::FORBIDDEN)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Resolve target to a socket address.
                        let resolved = tokio::net::lookup_host((target_host.as_str(), target_port))
                            .await
                            .ok()
                            .and_then(|mut addrs| addrs.next());
                        let Some(target_addr) = resolved else {
                            warn!(
                                "CONNECT-UDP: cannot resolve {}:{} (from {})",
                                target_host, target_port, remote_addr
                            );
                            log_outcome(http::StatusCode::BAD_GATEWAY);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        // For the clients masque.allowed_clients admits, and to
                        // a target on this host or a private network only for
                        // those masque.private_target_clients names.
                        if !config
                            .masque
                            .is_client_allowed(remote_addr.ip(), target_addr.ip())
                        {
                            warn!(
                                "CONNECT-UDP to {} is not open to {}",
                                target_addr, remote_addr
                            );
                            log_outcome(http::StatusCode::FORBIDDEN);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::FORBIDDEN)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Start (or reuse) the per-connection datagram router.
                        let router = datagram_router
                            .get_or_insert_with(|| DatagramRouter::new(quic_connection.clone()))
                            .clone();

                        if router.session_count() >= config.masque.max_sessions_per_connection {
                            warn!("CONNECT-UDP: session limit reached for {}", remote_addr);
                            log_outcome(http::StatusCode::SERVICE_UNAVAILABLE);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Quarter Stream ID = request stream id / 4 (RFC 9297).
                        let quarter_id = stream.id().into_inner() / 4;
                        let from_client = router.register_session(quarter_id);

                        // Accept the session (RFC 9298 §3: 2xx).
                        let accept = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())?;
                        if let Err(e) = stream.send_response(accept).await {
                            error!("CONNECT-UDP: failed to accept for {}: {}", remote_addr, e);
                            router.unregister_session(quarter_id);
                            continue;
                        }

                        info!(
                            "CONNECT-UDP session opened: {} -> {} (qsid={})",
                            remote_addr, target_addr, quarter_id
                        );
                        log_outcome(http::StatusCode::OK);
                        let udp_open = metrics
                            .connections
                            .connection_opened(ConnectionProtocol::ConnectUdp);

                        let idle =
                            Duration::from_secs(config.masque.session_idle_timeout_secs.max(1));
                        let conn_clone = quic_connection.clone();
                        let flight = activity.begin();
                        tokio::spawn(async move {
                            let _flight = flight;
                            // The request stream stays open for the session; reading it
                            // to end (FIN/RESET) signals the client closed the tunnel.
                            let (_send, mut recv) = stream.split();
                            let stream_closed = async move {
                                // Drain any capsule data; FIN/RESET ends the loop.
                                while let Ok(Some(_)) = recv.recv_data().await {}
                            };
                            connect_udp::run_session(
                                router,
                                conn_clone,
                                quarter_id,
                                target_addr,
                                idle,
                                from_client,
                                stream_closed,
                            )
                            .await;
                            drop(udp_open);
                        });
                    } else if is_ws_h3 {
                        // RFC 9220: WebSocket-over-HTTP/3 extended CONNECT tunnel.
                        // Respond with 200 OK (not 101), then bridge the HTTP/3 bidi stream
                        // to a plain HTTP/1.1 WebSocket upgrade on the backend.
                        info!(
                            "WS/H3 extended CONNECT for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        let ws_route = config
                            .find_route(host.as_deref(), &path, false)
                            .filter(|r| r.supports_websocket);

                        let Some(route) = ws_route else {
                            debug!(
                                "WS/H3 CONNECT rejected (no ws route) for {} from {}",
                                path, remote_addr
                            );
                            log_outcome(http::StatusCode::NOT_FOUND);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        let Some(backend) = config.get_backend(&route.backend).cloned() else {
                            error!("WS/H3: backend not found: {}", route.backend);
                            log_outcome(http::StatusCode::BAD_GATEWAY);
                            let err_resp = http::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(err_resp).await;
                            continue;
                        };

                        // The request's fields as an ordinary proxied request
                        // carries them
                        let host_ws = host.clone().unwrap_or_default();
                        let request_id = crate::request_id::header_name(
                            &config.server.request_id_header,
                        )
                        .map(|name| {
                            let id = crate::request_id::resolve(request.headers(), &name);
                            (name, id)
                        });
                        let forwarded = crate::http_listener::backend_request_headers(
                            request.headers(),
                            &host_ws,
                            remote_addr.ip(),
                            local_port,
                            route,
                            request_id.as_ref(),
                        );
                        let path_and_query = match uri.query() {
                            Some(q) => format!("{path}?{q}"),
                            None => path.clone(),
                        };
                        let idle_secs = route.ws_idle_timeout_secs;

                        let flight = activity.begin();
                        tokio::spawn(async move {
                            let _flight = flight;
                            if let Err(e) = ws_h3_tunnel(
                                stream,
                                backend,
                                forwarded,
                                path_and_query,
                                host_ws,
                                idle_secs,
                            )
                            .await
                            {
                                debug!("WS/H3 tunnel ended: {}", e);
                            }
                        });
                    } else {
                        // An extended CONNECT with a protocol this listener does
                        // not terminate itself: an ordinary request.
                        spawn_request(stream, request);
                    }
                }
                Step::Accepted(Ok(None)) => {
                    debug!("HTTP/3 connection closed by peer: {}", remote_addr);
                    break;
                }
                Step::Accepted(Err(e)) => {
                    // A browser navigating away closes the connection mid-accept.
                    // That is the overwhelming majority of what lands here, and
                    // logging it at error level made the collector's log-analysis
                    // report continuous "error spikes" for ordinary traffic.
                    if is_benign_h3_close(&e) {
                        debug!("HTTP/3 connection closed by peer: {}", e);
                    } else if is_peer_violation(&e) {
                        info!(
                            "HTTP/3 connection from {} ended: the peer broke the protocol ({})",
                            remote_addr, e
                        );
                    } else {
                        error!("HTTP/3 accept error: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

/// The handshake's completion, once [`application_protocol`] may have waited
/// for it.
type Established = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>;

/// Whether a connection's handshake completed. `established` resolves when
/// the handshake ends either way, and its value is whether the client's 0-RTT
/// was accepted, false on every ordinary connection: the close reason is what
/// says it failed. Read as success, it kept the MoQ entrance from serving
/// any client that sent no 0-RTT.
async fn handshake_completed(established: Established, connection: &quinn::Connection) -> bool {
    established.await;
    connection.close_reason().is_none()
}

/// The application protocol a connection negotiated, by ALPN, and the
/// handshake's completion to wait on from here.
///
/// noq makes a server's handshake data readable as soon as the first
/// ClientHello's server name is known. After a HelloRetryRequest the protocol
/// is chosen from the second ClientHello, so that first read has none, and it
/// is read again once the handshake is done, where it is final. Taken from the
/// first read alone, a DNS over QUIC client that named the server and was asked
/// to retry was served HTTP/3: the server opened its control stream where the
/// client allows no unidirectional stream, and the query went unanswered (kdig
/// sending ML-KEM key shares, 2026-11-02). A client that names no server is
/// readable only once the protocol is chosen. There is no 0-RTT after a
/// HelloRetryRequest, so waiting holds back nothing the client sent early;
/// HTTP/3's SETTINGS then leave after the handshake rather than with the
/// server's first flight.
async fn application_protocol(
    hello: Option<&quinn::crypto::rustls::HandshakeData>,
    connection: &quinn::Connection,
    established: impl std::future::Future<Output = bool> + Send + 'static,
) -> (Option<Vec<u8>>, Established) {
    if let Some(protocol) = hello.and_then(|d| d.protocol.clone()) {
        return (Some(protocol), Box::pin(established));
    }
    let accepted = established.await;
    let protocol = connection
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol.clone());
    (protocol, Box::pin(std::future::ready(accepted)))
}

#[cfg(test)]
mod pending_read_tests {
    use crate::conformance::zero_rtt::{throwaway_cert, OneCert, PinnedTo};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    /// A client and a server connection over loopback QUIC (ALPN h3), with
    /// their endpoints, which must outlive them.
    async fn connected() -> (
        quinn::Connection,
        quinn::Connection,
        quinn::Endpoint,
        quinn::Endpoint,
    ) {
        let throwaway = throwaway_cert();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).expect("QUIC server"),
            )),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("a server port");
        let addr = server.local_addr().expect("its address");
        let mut client_tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let (client_conn, server_conn) = tokio::join!(
            async { client.connect(addr, "localhost").unwrap().await.unwrap() },
            async { server.accept().await.unwrap().await.unwrap() }
        );
        (client_conn, server_conn, client, server)
    }

    /// A stream whose first data comes after its header: a read of it is
    /// left pending, and into_inner_or_pending gives that read back, which
    /// yields the stream and the data when it comes. into_inner gave None
    /// there, and the listener dropped the stream (2026-11-24).
    #[tokio::test]
    async fn a_pending_read_gives_back_the_stream_and_its_data() {
        use h3::quic::RecvStream as _;

        let (client_conn, server_conn, _client, _server) = connected().await;
        // The header's worth first, the rest later
        let mut send = client_conn.open_uni().await.unwrap();
        send.write_all(b"h").await.unwrap();
        let mut h3conn = h3_quinn::Connection::new(server_conn);
        let mut recv = std::future::poll_fn(|cx| {
            h3::quic::Connection::<bytes::Bytes>::poll_accept_recv(&mut h3conn, cx)
        })
        .await
        .unwrap();
        let first = std::future::poll_fn(|cx| recv.poll_data(cx))
            .await
            .unwrap()
            .expect("the first byte");
        assert_eq!(&first[..], b"h");
        // Read on past it: nothing yet, so the read is left pending
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(recv.poll_data(&mut cx), Poll::Pending));
        let Err(pending) = recv.into_inner_or_pending() else {
            panic!("the stream is inside its pending read");
        };
        send.write_all(b"ello").await.unwrap();
        let (_stream, read) = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("the read completes");
        assert_eq!(&read.unwrap().expect("data")[..], b"ello");
    }

    /// A WebTransport stream that arrives alone, no request after it, is
    /// accepted: h3 reads incoming unidirectional streams while polling for
    /// requests, queued this one, and left nothing to wake the accept for
    /// it, so it waited for some other stream (2026-11-24: a browser's MoQ
    /// SETUP, sent with nothing after it, never reached the relay)
    #[tokio::test]
    async fn a_webtransport_stream_alone_is_accepted() {
        let (client_conn, server_conn, _client, _server) = connected().await;
        let mut h3: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
            h3::server::builder()
                .enable_extended_connect(true)
                .enable_webtransport(true)
                .build(h3_quinn::Connection::new(server_conn))
                .await
                .unwrap();
        // WT_STREAM's unidirectional type (0x54, a two-byte varint),
        // session 0, and one byte of data
        let mut send = client_conn.open_uni().await.unwrap();
        send.write_all(&[0x40, 0x54, 0x00, b'x']).await.unwrap();
        // Taken on the poll that reads it. The deadline is checked first: a
        // timeout that polls the accept when it fires would wake it itself
        // and hide the missing wakeup (without the fix the accept returned
        // only when such a timer fired; for a browser's session, nothing did)
        let accepted = tokio::select! {
            biased;
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("not accepted: nothing woke the accept for the stream")
            }
            accepted = h3.accept_any() => accepted.unwrap(),
        };
        let Some(h3::server::Accepted::WebTransportUni { session, .. }) = accepted else {
            panic!("a WebTransport stream");
        };
        assert_eq!(session, 0);
    }
}

#[cfg(test)]
mod application_protocol_tests {
    use super::*;
    use crate::conformance::zero_rtt::{throwaway_cert, OneCert, PinnedTo};
    use std::net::{Ipv4Addr, SocketAddr};

    /// A provider with these groups alone, in this order
    fn groups(
        kx: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    ) -> rustls::crypto::CryptoProvider {
        rustls::crypto::CryptoProvider {
            kx_groups: kx,
            ..rustls::crypto::aws_lc_rs::default_provider()
        }
    }

    /// An ordinary connection, no 0-RTT sent: the server's 0.5-RTT future
    /// resolves to false (whether 0-RTT was accepted), and the handshake has
    /// completed. Taken as the handshake's outcome, that false kept the MoQ
    /// entrance from serving the music origin, a relay's upstream and the
    /// analyzer's sessions (2026-11-23); `handshake_completed` reads the
    /// close reason instead.
    #[tokio::test]
    async fn an_ordinary_handshake_completes_though_no_0rtt_was_accepted() {
        let throwaway = throwaway_cert();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
        server_crypto.alpn_protocols = vec![b"moqt-23".to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                    .expect("building the QUIC server configuration"),
            )),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("binding a server port");
        let server_addr = server.local_addr().expect("the server's address");
        let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"moqt-23".to_vec()];
        let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding a client port");
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .expect("building the QUIC client configuration"),
        )));

        for judged in [false, true] {
            let accept = async {
                let (connection, established) = server
                    .accept()
                    .await
                    .expect("a connection arrives")
                    .accept()
                    .expect("accepting it")
                    .into_0rtt()
                    .expect("a server takes 0.5-RTT");
                if judged {
                    handshake_completed(Box::pin(established), &connection).await
                } else {
                    // The premise: no 0-RTT, so the future's value is false
                    !established.await && connection.close_reason().is_none()
                }
            };
            let connect = async {
                client
                    .connect(server_addr, "localhost")
                    .expect("starting the connection")
                    .await
                    .expect("the handshake completes")
            };
            let (outcome, _client) = tokio::join!(accept, connect);
            assert!(
                outcome,
                "{}",
                if judged {
                    "an ordinary handshake is judged complete"
                } else {
                    "the 0.5-RTT future resolves to false with no 0-RTT"
                }
            );
        }
    }

    /// The protocol the first read of the handshake data had, and the one
    /// [`application_protocol`] settles on, for a DNS over QUIC client that
    /// connects as `server_name` with its key share for X25519 to a server
    /// that takes only P-384, so the server asks it to retry
    async fn after_a_retry(server_name: &str) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let throwaway = throwaway_cert();
        let mut server_crypto =
            rustls::ServerConfig::builder_with_provider(Arc::new(groups(vec![
                rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
            ])))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
        server_crypto.alpn_protocols = vec![b"h3".to_vec(), crate::doq::ALPN.to_vec()];
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(
                quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                    .expect("building the QUIC server configuration"),
            )),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )
        .expect("binding a server port");
        let server_addr = server.local_addr().expect("the server's address");

        let client_provider = Arc::new(groups(vec![
            rustls::crypto::aws_lc_rs::kx_group::X25519,
            rustls::crypto::aws_lc_rs::kx_group::SECP384R1,
        ]));
        let mut client_crypto =
            rustls::ClientConfig::builder_with_provider(client_provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is available")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedTo(
                    throwaway.der.clone(),
                    client_provider,
                )))
                .with_no_client_auth();
        client_crypto.alpn_protocols = vec![crate::doq::ALPN.to_vec()];
        let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("binding a client port");
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .expect("building the QUIC client configuration"),
        )));

        let accept = async {
            let mut connecting = server
                .accept()
                .await
                .expect("a connection arrives")
                .accept()
                .expect("accepting it");
            let hello = connecting
                .handshake_data()
                .await
                .expect("the ClientHello is read")
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .ok();
            let first_read = hello.as_ref().and_then(|d| d.protocol.clone());
            let (connection, established) = connecting.into_0rtt().expect("a server takes 0.5-RTT");
            let (protocol, established) =
                application_protocol(hello.as_deref(), &connection, established).await;
            established.await;
            let group = connection
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.negotiated_key_exchange_group);
            assert_eq!(
                group,
                Some(rustls::NamedGroup::secp384r1),
                "the retried group"
            );
            (first_read, protocol)
        };
        let connect = async {
            client
                .connect(server_addr, server_name)
                .expect("starting the connection")
                .await
                .expect("the handshake completes")
        };
        let (_client_connection, read) = tokio::join!(connect, accept);
        read
    }

    #[tokio::test]
    async fn dns_over_quic_that_names_the_server_and_is_asked_to_retry_is_dns_over_quic() {
        let (first_read, protocol) = after_a_retry("conformance.test").await;
        assert_eq!(
            first_read, None,
            "readable on the server name, before the protocol"
        );
        assert_eq!(protocol.as_deref(), Some(crate::doq::ALPN));
    }

    #[tokio::test]
    async fn dns_over_quic_that_names_no_server_is_dns_over_quic_from_the_first_read() {
        // An address as the name: rustls sends no server name for one
        let (first_read, protocol) = after_a_retry("127.0.0.1").await;
        assert_eq!(first_read.as_deref(), Some(crate::doq::ALPN));
        assert_eq!(protocol.as_deref(), Some(crate::doq::ALPN));
    }
}

#[cfg(test)]
mod response_header_tests {
    use super::*;
    use crate::config::{HeadersConfig, RouteConfig};
    use http::HeaderMap;

    /// A route with nothing set but its backend (as config.rs's tests make one)
    fn route() -> RouteConfig {
        serde_json::from_str(r#"{"backend":"b"}"#).expect("minimal route")
    }
    use crate::http_listener::layers::ResponseHeaderSet;

    fn headers_of(builder: http::response::Builder) -> HeaderMap {
        builder.body(()).unwrap().headers().clone()
    }

    /// An HTTP/3 response gets the security headers by the TCP listeners'
    /// rules: an origin's cross-origin policies stand (and are not doubled),
    /// the always-set headers replace the origin's, the origin's CSP is kept,
    /// and the configured Server replaces the origin's.
    #[test]
    fn http3_applies_the_tcp_listeners_rules() {
        let config = HeadersConfig {
            cross_origin_embedder_policy: "unsafe-none".into(),
            ..HeadersConfig::default()
        };
        let set = ResponseHeaderSet::from_config(&config);
        let server = HeaderValue::from_static("pqcrypta-proxy");
        let builder = http::Response::builder()
            .header("cross-origin-embedder-policy", "require-corp")
            .header("cross-origin-opener-policy", "same-origin")
            .header(header::X_FRAME_OPTIONS, "SAMEORIGIN")
            .header(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'self' 'nonce-abc'",
            )
            .header(header::SERVER, "Apache");
        let h = headers_of(apply_response_policy_headers(
            builder,
            None,
            &set,
            Some(&server),
            Some("pqcrypta.com"),
            "/encryption/",
        ));
        let all = |name: &str| -> Vec<&str> {
            h.get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect()
        };
        assert_eq!(all("cross-origin-embedder-policy"), ["require-corp"]);
        assert_eq!(all("cross-origin-opener-policy"), ["same-origin"]);
        assert_eq!(all("x-frame-options"), [config.x_frame_options.as_str()]);
        assert_eq!(
            all("content-security-policy"),
            ["default-src 'self' 'nonce-abc'"]
        );
        assert_eq!(all("server"), ["pqcrypta-proxy"]);
        // Where the origin set none, the configured defaults
        let bare = headers_of(apply_response_policy_headers(
            http::Response::builder(),
            None,
            &set,
            None,
            Some("pqcrypta.com"),
            "/",
        ));
        assert_eq!(
            bare.get("cross-origin-embedder-policy").unwrap(),
            "unsafe-none"
        );
        assert_eq!(
            bare.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            config.content_security_policy.as_str()
        );
    }

    /// What a route decided stands: its overrides replace the origin's value
    /// and the global one, even for an always-set header, and a
    /// Stripe-compatible route goes out with no COOP or COEP at all.
    #[test]
    fn a_routes_headers_stand() {
        let config = HeadersConfig::default();
        let set = ResponseHeaderSet::from_config(&config);
        let mut grafana = route();
        for (k, v) in [
            ("cross-origin-opener-policy", "unsafe-none"),
            ("cross-origin-resource-policy", "cross-origin"),
            ("x-frame-options", "SAMEORIGIN"),
        ] {
            grafana.headers_override.insert(k.into(), v.into());
        }
        let h = headers_of(apply_response_policy_headers(
            http::Response::builder().header("cross-origin-opener-policy", "same-origin"),
            Some(&grafana),
            &set,
            None,
            None,
            "/grafana/login",
        ));
        let all = |h: &HeaderMap, name: &str| -> Vec<String> {
            h.get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(all(&h, "cross-origin-opener-policy"), ["unsafe-none"]);
        assert_eq!(all(&h, "cross-origin-resource-policy"), ["cross-origin"]);
        assert_eq!(all(&h, "x-frame-options"), ["SAMEORIGIN"]);

        let mut billing = route();
        billing.stripe_compatibility = true;
        let h = headers_of(apply_response_policy_headers(
            http::Response::builder().header("cross-origin-opener-policy", "same-origin"),
            Some(&billing),
            &set,
            None,
            None,
            "/dashboard/billing/",
        ));
        assert!(h.get("cross-origin-opener-policy").is_none());
        assert!(h.get("cross-origin-embedder-policy").is_none());
        assert_eq!(
            all(&h, "x-frame-options"),
            [config.x_frame_options.as_str()]
        );
    }
}

#[cfg(test)]
mod alt_svc_tests {
    use super::*;

    fn config_with(udp_port: u16, additional: Vec<u16>, tcp_only: Vec<String>) -> ProxyConfig {
        let mut c = ProxyConfig::default();
        c.server.udp_port = udp_port;
        c.server.additional_ports = additional;
        c.server.tcp_only_hosts = tcp_only;
        c
    }

    /// What a response over TCP from the same listener says: every serving h3 port.
    fn over_tcp(c: &ProxyConfig) -> String {
        crate::http_listener::layers::build_alt_svc_header_with_override(
            c.server.udp_port,
            &c.server.additional_ports,
            c.server.alt_svc_ports.as_deref(),
            c.server.alt_svc_max_age_secs,
        )
    }

    /// The connection in use stays in the set: Alt-Svc replaces a client's cached
    /// alternatives (RFC 7838 section 3), so leaving it out had the client forget it
    #[test]
    fn advertises_the_connection_it_is_on_as_tcp_does() {
        let c = config_with(443, vec![4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert_eq!(v, "h3=\":443\"; ma=86400, h3=\":4434\"; ma=86400");
        assert_eq!(v, over_tcp(&c));
        assert!(
            !v.contains("h2="),
            "a browser stores QUIC alternatives only: {v}"
        );
    }

    /// Every listener, primary or not, says the same of the origin
    #[test]
    fn every_listener_names_every_h3_port() {
        for (port, more) in [(443, vec![4433, 4434]), (4434, vec![4433, 4434])] {
            let c = config_with(port, more, vec![]);
            let v = build_alt_svc_header_over_quic(&c);
            assert_eq!(v, over_tcp(&c));
            for p in [port, 4433, 4434] {
                assert_eq!(v.matches(&format!("h3=\":{p}\"")).count(), 1, "{p}: {v}");
            }
        }
    }

    /// A port listed in both `udp_port` and `additional_ports` must not produce two
    /// entries, or a client sees the same alternative twice.
    #[test]
    fn does_not_duplicate_a_port() {
        let c = config_with(443, vec![443, 443, 4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert_eq!(v.matches("h3=\":443\"").count(), 1, "{v}");
        assert_eq!(v.matches("h3=\":4434\"").count(), 1, "{v}");
    }

    /// The Midwest speedtest node: UDP 4433 is the WebTransport endpoint, so a plain
    /// HTTP/3 request there is answered by the WebTransport server and never gets
    /// response headers. With a real h3 port on 4434, only that one is advertised,
    /// from the WebTransport listener as from the h3 one.
    #[test]
    fn override_names_only_the_ports_that_serve_http3() {
        for port in [4433, 4434] {
            let mut c = config_with(port, vec![4433, 4434], vec![]);
            c.server.alt_svc_ports = Some(vec![4434]);
            assert_eq!(build_alt_svc_header_over_quic(&c), "h3=\":4434\"; ma=86400");
        }
    }

    /// A node that advertises no HTTP/3 has nothing to name, and a client that
    /// reached it over QUIC anyway is told to drop what it cached
    #[test]
    fn empty_override_advertises_nothing_and_clears() {
        let mut c = config_with(4433, vec![], vec![]);
        c.server.alt_svc_ports = Some(vec![]);
        assert_eq!(build_alt_svc_header_over_quic(&c), "");
        let fp = crate::fingerprint::FingerprintResult {
            allowed: true,
            ja3_hash: None,
            ja4_hash: None,
            classification: None,
            client_name: None,
        };
        let h = H3ConnHeaders::new(
            &c,
            "192.0.2.1:50000".parse().unwrap(),
            4433,
            &fp,
            &crate::tls_acceptor::HandshakeFacts::default(),
        );
        assert_eq!(h.alt_svc(&c, None), "clear");
    }

    /// Unchanged behaviour: a TCP-only host still gets the eviction token, which is
    /// what stops a browser using a cached upgrade.
    #[test]
    fn tcp_only_hosts_still_clear() {
        let c = config_with(443, vec![4434], vec!["ssllabs.pqcrypta.com".to_string()]);
        let fp = crate::fingerprint::FingerprintResult {
            allowed: true,
            ja3_hash: None,
            ja4_hash: None,
            classification: None,
            client_name: None,
        };
        let h = H3ConnHeaders::new(
            &c,
            "192.0.2.1:50000".parse().unwrap(),
            443,
            &fp,
            &crate::tls_acceptor::HandshakeFacts::default(),
        );
        assert_eq!(h.alt_svc(&c, Some("ssllabs.pqcrypta.com")), "clear");
        // A host on another port arrives with its port, in any case.
        assert_eq!(h.alt_svc(&c, Some("SSLLabs.pqcrypta.com:4433")), "clear");
        assert_ne!(h.alt_svc(&c, Some("pqcrypta.com")), "clear");
        assert_ne!(h.alt_svc(&c, Some("pqcrypta.com:4433")), "clear");
        assert_ne!(h.alt_svc(&c, None), "clear");
        // Built once, and the same value the builder produces.
        assert_eq!(
            h.alt_svc(&c, None),
            build_alt_svc_header_over_quic(&c).as_str()
        );
        assert_eq!(h.client_ip.as_ref().unwrap(), "192.0.2.1");
        // No request has settled it yet: a connection serving 0-RTT is set up
        // before any certificate could have been verified.
        assert_eq!(h.client_cert.get(), None);
    }
}

#[cfg(test)]
mod close_classification_tests {
    use super::{is_benign_h3_close, is_peer_violation};

    /// What this side closes for the peer's breach is the peer's doing, and
    /// the same code from the peer is not: it may be answering this side.
    #[test]
    fn a_peer_violation_is_told_from_an_accusation() {
        for raised_here in [
            "Connection error: Local error: Application { code: H3_FRAME_UNEXPECTED, reason: \"x\" }",
            "Local error: Application { code: QPACK_DECOMPRESSION_FAILED, reason: \"x\" }",
            "Local error: Application { code: H3_SETTINGS_ERROR, reason: \"x\" }",
            "Remote reset: 0x0",
            "detected an error with protocol compliance that was not covered by more specific error codes",
        ] {
            assert!(is_peer_violation(&raised_here), "{raised_here}");
        }
        for not_the_peers in [
            "Remote error: H3_FRAME_ERROR",
            "closed by peer: H3_SETTINGS_ERROR (code 265)",
            "closed by peer: detected an error with protocol compliance (code 10)",
            "Local error: Application { code: H3_INTERNAL_ERROR, reason: \"x\" }",
        ] {
            assert!(!is_peer_violation(&not_the_peers), "{not_the_peers}");
        }
    }

    /// Every connection open across a restart closes at once with a code h3
    /// does not define; logged as ERROR that was a burst of false alarms per
    /// deploy. A failure on this side must still be an error.
    #[test]
    fn a_peer_close_is_benign_and_a_local_failure_is_not() {
        assert!(is_benign_h3_close(
            &"Remote error: Error undefined by h3: closed"
        ));
        assert!(!is_benign_h3_close(&"Local error: H3_FRAME_UNEXPECTED"));
        assert!(!is_benign_h3_close(&"Remote error: H3_FRAME_ERROR"));
    }

    /// The shapes seen in a day of production logs at error level, every one
    /// of them caused by the client.
    #[test]
    fn client_caused_endings_are_benign() {
        assert!(is_benign_h3_close(&"timed out"));
        assert!(is_benign_h3_close(&"Remote reset: H3_REQUEST_CANCELLED"));
        assert!(is_benign_h3_close(
            &"aborted by peer: the connection is being closed abruptly in the absence of any error"
        ));
        // A local protocol failure still is not.
        assert!(!is_benign_h3_close(&"Local error: H3_INTERNAL_ERROR"));
        // Clean closes by the peer, as quinn prints them (seen 2026-09-28).
        assert!(is_benign_h3_close(
            &"closed by peer: scan complete (code 0)"
        ));
        assert!(is_benign_h3_close(&"closed by peer: 256"));
        assert!(is_benign_h3_close(&"closed by peer: 0"));
        assert!(!is_benign_h3_close(&"closed by peer: 10"));
        // A peer closing with an error code may be answering us: stays loud.
        assert!(!is_benign_h3_close(&"closed by peer: 263"));
        assert!(!is_benign_h3_close(&"closed by peer: frame error (code 7)"));
    }
}

/// Whether an HTTP/3 request span would be recorded by the installed
/// subscriber. Evaluated in this module, whose target the span carries.
fn request_span_enabled() -> bool {
    tracing::span_enabled!(tracing::Level::INFO)
}

/// The server span for one HTTP/3 request: the same span the TCP listeners
/// open in `trace_context_middleware`, stitched into the caller's trace.
///
/// The parent is attached before the span is ever entered -- once entered it
/// has begun a trace of its own and a remote parent is refused. This listener
/// used to call `set_parent` on `Span::current()` partway through the request,
/// and there was no current span on this path at all, so an HTTP/3 request
/// never joined its caller's trace and the backend was handed an empty
/// context, whatever the documentation said about all transports.
fn request_span(request: &http::Request<()>, peer: std::net::IpAddr) -> tracing::Span {
    let span = tracing::info_span!(
        "http.request",
        http.method = %request.method(),
        http.uri = %request.uri().path(),
        http.flavor = "3",
        otel.kind = "server",
        trace_id = tracing::field::Empty,
    );
    crate::otel::set_parent_from_headers(&span, request.headers(), peer);
    let trace_id = crate::otel::trace_id_of(&span);
    if !trace_id.is_empty() {
        span.record("trace_id", trace_id);
    }
    span
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An HTTP/3 request continues its trusted caller's trace. It did not: the
    /// parent was set on `Span::current()`, and on this path there was none.
    #[test]
    fn an_http3_request_span_joins_the_callers_trace() {
        crate::otel::with_test_tracing(|| {
            let request = http::Request::builder()
                .uri("https://pqcrypta.com/x")
                .header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                .body(())
                .unwrap();
            let (trusted, _) = crate::otel::tests::trust_test_parents();
            let span = request_span(&request, trusted);
            assert_eq!(
                crate::otel::trace_id_of(&span),
                "4bf92f3577b34da6a3ce929d0e0e4736"
            );
        });
    }
}

/// An extended CONNECT meets what an ordinary request on its route meets: the
/// connection's own headers, the route's policy and the route gate.
#[cfg(test)]
mod connect_parity_tests {
    use super::*;

    fn route(toml_src: &str) -> crate::config::RouteConfig {
        toml::from_str(toml_src).expect("valid route TOML")
    }

    fn proxy_config(routes: Vec<crate::config::RouteConfig>) -> ProxyConfig {
        let mut config = ProxyConfig::default();
        config.security.geoip_db_path = None;
        config.security.geoip_asn_db_path = None;
        config.fingerprint.fingerprint_db_path = None;
        config.routes = routes;
        config
    }

    fn connect(path: &str, headers: &[(&str, &str)]) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://example.test{path}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).expect("request")
    }

    fn fingerprint(ja3: Option<&str>) -> crate::fingerprint::FingerprintResult {
        crate::fingerprint::FingerprintResult {
            allowed: true,
            ja3_hash: ja3.map(str::to_string),
            ja4_hash: None,
            classification: None,
            client_name: None,
        }
    }

    const PEER: &str = "198.51.100.7:50000";

    /// The request as the dispatch has it: the connection's own headers set,
    /// then judged against `route`.
    async fn refusal(
        config: &ProxyConfig,
        mut request: http::Request<()>,
        route: Option<&crate::config::RouteConfig>,
        connection_ja3: Option<&str>,
    ) -> Option<http::StatusCode> {
        let security = SecurityState::new(config);
        let limiter = AdvancedRateLimiter::new(config.advanced_rate_limiting.clone());
        let peer: SocketAddr = PEER.parse().unwrap();
        let fp = fingerprint(connection_ja3);
        let handshake = quic_handshake_facts_empty();
        let conn_headers = H3ConnHeaders::new(config, peer, 443, &fp, &handshake);
        request::derive_connection_headers(
            request.headers_mut(),
            &handshake,
            &conn_headers,
            &fp,
            false,
        );
        let path = request.uri().path().to_string();
        connect_refusal(
            &security,
            &limiter,
            config,
            &request,
            Some("example.test"),
            &path,
            route,
            peer,
            &fp,
        )
        .await
        .map(|(status, _)| status)
    }

    #[tokio::test]
    async fn an_mtls_route_refuses_a_session_without_a_client_certificate() {
        let wt = route(
            "name = \"wt\"\nbackend = \"b\"\nwebtransport = true\npath_prefix = \"/wt\"\n\
             [security]\nmtls_required = true\n",
        );
        let config = proxy_config(vec![wt.clone()]);
        // A client's own claim to a certificate is not one; over HTTP/3 the
        // refusal is 421 (route_gate::mtls_gate)
        let request = connect("/wt", &[("x-client-cert", "1")]);
        assert_eq!(
            refusal(&config, request, Some(&wt), None).await,
            Some(http::StatusCode::MISDIRECTED_REQUEST)
        );
    }

    #[tokio::test]
    async fn an_hmac_route_refuses_an_unsigned_session() {
        let ws = route(&format!(
            "name = \"ws\"\nbackend = \"b\"\nsupports_websocket = true\npath_prefix = \"/ws\"\n\
             [security]\nhmac_secret = \"{}\"\n",
            hex::encode(rand::random::<[u8; 32]>())
        ));
        let config = proxy_config(vec![ws.clone()]);
        assert_eq!(
            refusal(&config, connect("/ws", &[]), Some(&ws), None).await,
            Some(http::StatusCode::UNAUTHORIZED)
        );
    }

    /// A JA3 allowlist reads the connection's fingerprint: a client naming an
    /// allowed one itself is refused, the connection that has it is admitted,
    /// on a WebTransport-only route as on any other.
    #[tokio::test]
    async fn a_ja3_allowlist_reads_the_connections_fingerprint() {
        let allowed = "0123456789abcdef0123456789abcdef";
        let wt = route(&format!(
            "name = \"wt\"\nbackend = \"b\"\nwebtransport = true\npath_prefix = \"/wt\"\n\
             [security]\nallowed_ja3 = [\"{allowed}\"]\n"
        ));
        let config = proxy_config(vec![wt.clone()]);
        let forged = connect("/wt", &[("x-ja3-hash", allowed)]);
        assert!(refusal(&config, forged, Some(&wt), None).await.is_some());
        let other = connect("/wt", &[("x-ja3-hash", allowed)]);
        assert!(refusal(
            &config,
            other,
            Some(&wt),
            Some("ffffffffffffffffffffffffffffffff")
        )
        .await
        .is_some());
        let genuine = connect("/wt", &[]);
        assert_eq!(
            refusal(&config, genuine, Some(&wt), Some(allowed)).await,
            None
        );
    }

    #[tokio::test]
    async fn a_route_with_no_gates_admits_the_session() {
        let wt =
            route("name = \"wt\"\nbackend = \"b\"\nwebtransport = true\npath_prefix = \"/wt\"\n");
        let config = proxy_config(vec![wt.clone()]);
        assert_eq!(
            refusal(&config, connect("/wt", &[]), Some(&wt), None).await,
            None
        );
    }
}

/// The whole QUIC listener on a loopback port, as a node runs it (its
/// connection loop included), and clients against it: the draft-17
/// WebTransport rules the loop applies to a connection.
#[cfg(test)]
mod listener_tests {
    use super::*;
    use crate::conformance::zero_rtt::PinnedTo;
    use std::net::Ipv4Addr;

    /// A listener on 127.0.0.1 with a throwaway certificate and `[moq]` on;
    /// the certificate's DER, for the client to pin, and the sender that
    /// stops it
    async fn listener() -> (SocketAddr, Vec<u8>, mpsc::Sender<()>) {
        listener_with(|_| {}).await
    }

    /// [`listener`], its config changed by `tune` first
    async fn listener_with(
        tune: impl FnOnce(&mut ProxyConfig),
    ) -> (SocketAddr, Vec<u8>, mpsc::Sender<()>) {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "pqcrypta-listener-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // The resolver reads <domain>.crt and <domain>.key pairs
        std::fs::write(dir.join("localhost.crt"), cert.cert.pem()).unwrap();
        std::fs::write(dir.join("localhost.key"), cert.signing_key.serialize_pem()).unwrap();
        let mut config = ProxyConfig::default();
        config.server.bind_address = "127.0.0.1".into();
        config.server.udp_port = 0;
        config.tls.cert_path = dir.join("localhost.crt");
        config.tls.key_path = dir.join("localhost.key");
        config.moq.enabled = true;
        tune(&mut config);
        let tls = Arc::new(
            TlsProvider::new(
                &config.tls,
                &config.pqc,
                config.client_auth(),
                config.quic_applications(),
            )
            .unwrap(),
        );
        let (stop, stop_rx) = mpsc::channel(1);
        let (_reload, reload_rx) = mpsc::channel(8);
        let listener = QuicListener::new(
            Arc::new(config.clone()),
            tls,
            stop_rx,
            reload_rx,
            Arc::new(MetricsRegistry::new()),
            Arc::new(SecurityState::new(&config)),
            Arc::new(AdvancedRateLimiter::new(
                config.advanced_rate_limiting.clone(),
            )),
            Arc::new(LoadBalancer::new(Arc::new(config.load_balancer.clone()))),
            crate::cache::shared(&config.cache),
            Arc::new(EarlyHintsState::from_http3_config(&config.http3)),
        )
        .await
        .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(listener.run());
        (addr, cert.cert.der().to_vec(), stop)
    }

    /// A QUIC connection to the listener, ALPN h3
    async fn connect(addr: SocketAddr, der: &[u8]) -> (quinn::Connection, quinn::Endpoint) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTo(der.to_vec().into(), provider)))
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        (conn, endpoint)
    }

    /// An HTTP/3 client on `conn`, its connection driven
    async fn h3_client(
        conn: quinn::Connection,
    ) -> h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
        let (mut driver, send) = h3::client::builder()
            .enable_extended_connect(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        send
    }

    /// Every entrance admits a WebTransport session by the same rules
    /// (webtransport_server::admit): on this one, a session over the
    /// per-origin cap is refused 403, and one is admitted again once a
    /// session has ended. The origin is the relay's own, which [moq]
    /// admits and no other test sends: the caps are node-wide, tests run in
    /// one process, and the relay is the process's one, set up by the first
    #[tokio::test]
    async fn a_session_over_the_origin_cap_is_refused() {
        const ORIGIN: &str = "https://localhost";
        let (addr, der, _stop) =
            listener_with(|c| c.server.webtransport_max_sessions_per_origin = 1).await;
        let from = || {
            let mut r = wt_connect();
            r.headers_mut()
                .insert(http::header::ORIGIN, http::HeaderValue::from_static(ORIGIN));
            r
        };
        let wait = Duration::from_secs(5);
        let (first_conn, _first_endpoint) = connect(addr, &der).await;
        let mut first_send = h3_client(first_conn.clone()).await;
        let mut first = first_send.send_request(from()).await.unwrap();
        let answer = tokio::time::timeout(wait, first.recv_response())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer.status(), http::StatusCode::OK);

        // Another connection, the same origin: over the cap
        let (second_conn, _second_endpoint) = connect(addr, &der).await;
        let mut second_send = h3_client(second_conn).await;
        let mut second = second_send.send_request(from()).await.unwrap();
        let answer = tokio::time::timeout(wait, second.recv_response())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer.status(), http::StatusCode::FORBIDDEN);

        // The first ends: its slot is given back
        drop(first);
        first_conn.close(0u32.into(), b"");
        let mut admitted = None;
        for _ in 0..60 {
            let mut s = second_send.send_request(from()).await.unwrap();
            let status = tokio::time::timeout(wait, s.recv_response())
                .await
                .unwrap()
                .unwrap()
                .status();
            if status == http::StatusCode::OK {
                admitted = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(admitted.is_some(), "a session once the first has ended");
    }

    /// Sessions held open do not stop the listener: a session once held a
    /// lock on its origin's counter for as long as it lived, and each further
    /// session from the same origin parked a runtime worker waiting for it, so
    /// `worker_threads` + 1 sessions stopped the whole proxy (OriginSlot,
    /// 2026-09-25). The listener runs alone on a runtime of two workers, its
    /// clients on another, so a stall shows as a failure, not a hang.
    #[test]
    fn sessions_held_open_do_not_stop_the_listener() {
        let server_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (addr, der, stop) = server_rt.block_on(listener());
        let server = server_rt.handle().clone();
        let client_rt = tokio::runtime::Runtime::new().unwrap();
        client_rt.block_on(async move {
            let wait = Duration::from_secs(10);
            let mut held = Vec::new();
            for n in 0..3 {
                let (conn, endpoint) = connect(addr, &der).await;
                let mut send = h3_client(conn).await;
                let mut session = send.send_request(wt_connect()).await.unwrap();
                let answer = tokio::time::timeout(wait, session.recv_response())
                    .await
                    .unwrap_or_else(|_| panic!("session {n} was never answered"))
                    .unwrap();
                assert_eq!(answer.status(), http::StatusCode::OK, "session {n}");
                held.push((session, send, endpoint));
            }
            tokio::time::timeout(Duration::from_secs(5), server.spawn(async {}))
                .await
                .expect("the listener's runtime stopped running tasks")
                .unwrap();
            drop(held);
        });
        drop(stop);
        server_rt.shutdown_background();
    }

    /// A WebTransport CONNECT to the relay's entrance, draft 17's token
    fn wt_connect() -> http::Request<()> {
        let mut r = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://localhost/moq")
            .header("wt-available-protocols", "\"moqt-23\"")
            .body(())
            .unwrap();
        r.extensions_mut().insert(Protocol::WEB_TRANSPORT_H3);
        r
    }

    /// Draft-ietf-webtrans-http3-17 section 5.1: a draft-17 client that
    /// declares no flow control has one session per connection; a second
    /// CONNECT while it lasts is reset with H3_REQUEST_REJECTED, and once it
    /// has ended, another is served.
    #[tokio::test]
    async fn a_second_session_without_flow_control_is_rejected() {
        let (addr, der, _stop) = listener().await;
        let (conn, _endpoint) = connect(addr, &der).await;
        let (mut driver, mut send) = h3::client::builder()
            .enable_extended_connect(true)
            .build::<_, _, Bytes>(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let wait = Duration::from_secs(5);
        let mut first = send.send_request(wt_connect()).await.unwrap();
        let response = tokio::time::timeout(wait, first.recv_response())
            .await
            .expect("the first session's answer")
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let mut second = send.send_request(wt_connect()).await.unwrap();
        let refused = tokio::time::timeout(wait, second.recv_response())
            .await
            .expect("the second session's answer");
        let error = refused.expect_err("a second session is not served");
        assert!(
            format!("{error:?}").contains("H3_REQUEST_REJECTED"),
            "reset with H3_REQUEST_REJECTED: {error:?}"
        );

        // The first ended (its CONNECT stream finished): another is served
        first.finish().await.unwrap();
        drop(first);
        let mut third = None;
        for _ in 0..20 {
            let mut s = send.send_request(wt_connect()).await.unwrap();
            if let Ok(Ok(r)) = tokio::time::timeout(wait, s.recv_response()).await {
                third = Some((r.status(), s));
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            third.map(|(status, _)| status),
            Some(http::StatusCode::OK),
            "a session once the first has ended"
        );
    }

    /// A QPACK string literal of `s` (RFC 9204 section 4.1.2), its length on
    /// `prefix` bits (at most 7) with `flags` above them, no Huffman coding
    fn qpack_string(out: &mut Vec<u8>, flags: u8, prefix: u32, s: &[u8]) {
        let max = (1u8 << prefix) - 1;
        match u8::try_from(s.len()) {
            Ok(n) if n < max => out.push(flags | n),
            _ => {
                out.push(flags | max);
                let mut rest = s.len() - usize::from(max);
                while rest >= 128 {
                    out.push(u8::try_from(rest % 128).expect("below 128") | 0x80);
                    rest /= 128;
                }
                out.push(u8::try_from(rest).expect("below 128"));
            }
        }
        out.extend_from_slice(s);
    }

    /// A QUIC varint (RFC 9000 section 16), in its fewest bytes
    fn varint(out: &mut Vec<u8>, v: u64) {
        if let Ok(b) = u8::try_from(v)
            .map_err(drop)
            .and_then(|b| if b < 64 { Ok(b) } else { Err(()) })
        {
            out.push(b);
        } else if let Ok(w) =
            u16::try_from(v)
                .map_err(drop)
                .and_then(|w| if w < 0x4000 { Ok(w) } else { Err(()) })
        {
            out.extend_from_slice(&(w | 0x4000).to_be_bytes());
        } else if let Ok(w) =
            u32::try_from(v)
                .map_err(drop)
                .and_then(|w| if w < 0x4000_0000 { Ok(w) } else { Err(()) })
        {
            out.extend_from_slice(&(w | 0x8000_0000).to_be_bytes());
        } else {
            out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes());
        }
    }

    /// The payload of the first HEADERS frame in `bytes`, once it is whole;
    /// frames of other types before it are passed over
    fn first_headers(bytes: &[u8]) -> Option<Vec<u8>> {
        let mut at = 0;
        loop {
            let (kind, n) = read_varint(bytes.get(at..)?)?;
            at += n;
            let (len, n) = read_varint(bytes.get(at..)?)?;
            at += n;
            let payload = bytes.get(at..at + usize::try_from(len).ok()?)?;
            at += payload.len();
            if kind == 0x01 {
                return Some(payload.to_vec());
            }
        }
    }

    /// A QUIC varint at the start of `b`, and its length
    fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
        let first = *b.first()?;
        let len = 1usize << (first >> 6);
        let bytes = b.get(..len)?;
        let mut v = u64::from(first & 0x3f);
        for byte in &bytes[1..] {
            v = (v << 8) | u64::from(*byte);
        }
        Some((v, len))
    }

    /// Draft-ietf-webtrans-http3-17 section 3.1: a server processes no
    /// WebTransport request before the client's SETTINGS. A CONNECT sent
    /// before them is held (no answer while they have not come), and served
    /// once they arrive.
    #[tokio::test]
    async fn a_webtransport_request_waits_for_the_client_s_settings() {
        let (addr, der, _stop) = listener().await;
        let (conn, _endpoint) = connect(addr, &der).await;
        // The CONNECT's field section (RFC 9204): no dynamic table; :method
        // CONNECT and :scheme https from the static table (15, 23),
        // :authority and :path by static name (0, 1), the rest literal
        // (an indexed static field line is 0xc0 | its index: 0xcf, 0xd7)
        let mut fields = vec![0x00, 0x00, 0xcf, 0xd7];
        fields.push(0x50);
        qpack_string(&mut fields, 0, 7, b"localhost");
        fields.push(0x51);
        qpack_string(&mut fields, 0, 7, b"/moq");
        for (name, value) in [
            (&b":protocol"[..], &b"webtransport-h3"[..]),
            (b"wt-available-protocols", b"\"moqt-23\""),
        ] {
            qpack_string(&mut fields, 0x20, 3, name);
            qpack_string(&mut fields, 0, 7, value);
        }
        let mut headers = Vec::new();
        varint(&mut headers, 0x01);
        varint(&mut headers, fields.len() as u64);
        headers.extend_from_slice(&fields);
        let (mut req_send, mut req_recv) = conn.open_bi().await.unwrap();
        req_send.write_all(&headers).await.unwrap();

        // No SETTINGS yet: no answer
        let mut first = [0u8; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), req_recv.read(&mut first))
                .await
                .is_err(),
            "a WebTransport request answered before the client's SETTINGS"
        );

        // The control stream and its SETTINGS: SETTINGS_H3_DATAGRAM 1,
        // SETTINGS_WT_ENABLED 1
        let mut settings = Vec::new();
        for (id, value) in [(0x33u64, 1u64), (0x20b8_933b, 1)] {
            varint(&mut settings, id);
            varint(&mut settings, value);
        }
        let mut control = Vec::new();
        varint(&mut control, 0x00);
        varint(&mut control, 0x04);
        varint(&mut control, settings.len() as u64);
        control.extend_from_slice(&settings);
        let mut control_stream = conn.open_uni().await.unwrap();
        control_stream.write_all(&control).await.unwrap();

        // Now the answer: its HEADERS frame (frames of unknown types, such
        // as GREASE, skipped: RFC 9114 section 9), whose field section's
        // first line is :status 200 from the static table (index 25)
        let mut answer = Vec::new();
        let headers = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 512];
            loop {
                if let Some(fields) = first_headers(&answer) {
                    return fields;
                }
                let n = req_recv.read(&mut buf).await.unwrap().unwrap_or(0);
                assert!(n > 0, "the stream ended with no HEADERS: {answer:02x?}");
                answer.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .expect("no answer once the SETTINGS came");
        // The two-byte field section prefix, then :status 200
        assert_eq!(
            headers.get(2),
            // 0xc0 | 25
            Some(&0xd9),
            ":status 200: {headers:02x?}"
        );
        drop(control_stream);
    }
}
