//! Custom TLS Acceptor with ClientHello Capture
//!
//! Wraps the standard TLS acceptor to capture ClientHello bytes for JA3/JA4 fingerprinting
//! before the TLS handshake completes.
//!
//! # Integration
//! This module is fully integrated into the HTTP listener via `run_http_listener_with_fingerprint`.
//! The custom TLS accept loop uses `FingerprintingTlsAcceptor` to:
//! - Capture ClientHello bytes before TLS handshake
//! - Extract JA3/JA4 fingerprints
//! - Block malicious clients early (before wasting handshake resources)
//! - Inject fingerprint data into request headers
//!
//! # Usage
//! ```ignore
//! let acceptor = FingerprintingTlsAcceptor::new(config, extractor, security, fp_config);
//! let stream = acceptor.accept(tcp_stream, remote_addr).await?;
//! // stream.conn_info contains JA3/JA4 fingerprints
//! ```

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use axum::extract::connect_info::Connected;
use dashmap::DashMap;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, trace, warn};

use crate::config::FingerprintConfig;
use crate::fingerprint::{FingerprintExtractor, FingerprintResult};
use crate::security::SecurityState;

/// Maximum size to peek for ClientHello (typically < 1KB but can be up to 16KB with extensions)
const MAX_CLIENT_HELLO_SIZE: usize = 4096;

/// 0-RTT replay protection nonce store.
///
/// Stores SHA-256 digests of the first 64 bytes of observed ClientHello messages
/// to detect replayed early-data attempts.  Entries older than `window_secs` are
/// evicted lazily on each `check_and_insert` call.
pub struct ZeroRttNonceStore {
    /// nonce → insertion time
    nonces: DashMap<[u8; 32], Instant>,
    /// Retention window in seconds
    window_secs: u64,
}

impl ZeroRttNonceStore {
    /// Create a new nonce store with the given replay window.
    pub fn new(window_secs: u64) -> Self {
        Self {
            nonces: DashMap::new(),
            window_secs,
        }
    }

    /// Compute a 32-byte nonce from the raw ClientHello bytes (first 64 bytes).
    fn nonce_from_client_hello(data: &[u8]) -> [u8; 32] {
        let slice = &data[..data.len().min(64)];
        let digest = Sha256::digest(slice);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Returns `true` if this ClientHello is a replay (nonce seen before);
    /// `false` if it is new (nonce recorded for future comparison).
    ///
    /// Expired entries are evicted before the lookup.
    pub fn check_and_insert(&self, client_hello: &[u8]) -> bool {
        self.check_and_insert_digest(Self::nonce_from_client_hello(client_hello))
    }

    /// As [`check_and_insert`](Self::check_and_insert), for a key already
    /// reduced to a digest.
    pub fn check_and_insert_digest(&self, nonce: [u8; 32]) -> bool {
        let now = Instant::now();
        let window = self.window_secs;
        self.nonces
            .retain(|_, inserted_at| now.duration_since(*inserted_at).as_secs() < window);
        // One atomic step: two connections carrying the same ClientHello must
        // not both find it absent.
        match self.nonces.entry(nonce) {
            dashmap::mapref::entry::Entry::Occupied(_) => true, // replay
            dashmap::mapref::entry::Entry::Vacant(v) => {
                v.insert(now);
                false
            }
        }
    }
}

/// The body of extension `ext_type` in a raw ClientHello record (record and
/// handshake headers included), or `None` if it is absent or the extensions
/// block is not all in `data`.
pub fn client_hello_extension(data: &[u8], ext_type: u16) -> Option<&[u8]> {
    // TLS record header (5 bytes) and handshake header (4 bytes).
    let ch = data.get(9..)?;
    // legacy_version (2) + random (32)
    let mut off = 34usize;
    let session_id_len = *ch.get(off)? as usize;
    off += 1 + session_id_len;
    let cipher_len = u16::from_be_bytes([*ch.get(off)?, *ch.get(off + 1)?]) as usize;
    off += 2 + cipher_len;
    let compression_len = *ch.get(off)? as usize;
    off += 1 + compression_len;
    let ext_total = u16::from_be_bytes([*ch.get(off)?, *ch.get(off + 1)?]) as usize;
    off += 2;
    let ext_end = off.checked_add(ext_total)?;
    if ext_end > ch.len() {
        return None;
    }
    while off + 4 <= ext_end {
        let ty = u16::from_be_bytes([ch[off], ch[off + 1]]);
        let len = u16::from_be_bytes([ch[off + 2], ch[off + 3]]) as usize;
        off += 4;
        let body = ch.get(off..off.checked_add(len)?.min(ext_end))?;
        if ty == ext_type {
            return Some(body);
        }
        off += len;
    }
    None
}

/// The first PSK identity -- the session ticket being resumed -- in a
/// ClientHello's `pre_shared_key` extension (RFC 8446 §4.2.11).
pub fn client_hello_psk_identity(data: &[u8]) -> Option<&[u8]> {
    let ext = client_hello_extension(data, 0x0029)?;
    // identities<7..2^16-1>, each identity<1..2^16-1> + obfuscated_ticket_age.
    let len = u16::from_be_bytes([*ext.get(2)?, *ext.get(3)?]) as usize;
    ext.get(4..4 + len).filter(|id| !id.is_empty())
}

/// SEC-002: `tls.zero_rtt_replay_protection`, applied to a ClientHello that
/// offers early data before its handshake starts. One guard for both TCP
/// stacks; the OpenSSL listener applied none.
#[derive(Clone)]
pub struct ZeroRttReplayGuard {
    mode: ZeroRttReplayMode,
    store: Option<Arc<ZeroRttNonceStore>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ZeroRttReplayMode {
    Strict,
    Session,
    Off,
}

impl ZeroRttReplayGuard {
    pub fn from_config(mode: &str, window_secs: u64) -> Self {
        let mode = match mode {
            "none" => ZeroRttReplayMode::Off,
            "session" => ZeroRttReplayMode::Session,
            // "strict", and anything unrecognised: the safe reading.
            _ => ZeroRttReplayMode::Strict,
        };
        Self {
            mode,
            store: (mode != ZeroRttReplayMode::Off)
                .then(|| Arc::new(ZeroRttNonceStore::new(window_secs))),
        }
    }

    /// True when `client_hello` offers early data and repeats one seen within
    /// the window: under "strict" the ClientHello itself, under "session" the
    /// ticket it resumes, so each ticket carries early data once.
    pub fn is_replay(&self, client_hello: &[u8]) -> bool {
        let Some(store) = &self.store else {
            return false;
        };
        if !FingerprintingTlsAcceptor::client_hello_has_early_data_extension(client_hello) {
            return false;
        }
        match (self.mode, client_hello_psk_identity(client_hello)) {
            (ZeroRttReplayMode::Session, Some(ticket)) => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&Sha256::digest(ticket));
                store.check_and_insert_digest(key)
            }
            _ => store.check_and_insert(client_hello),
        }
    }
}

/// Per-request nonce store for HMAC proof-of-possession replay protection.
///
/// Clients include a unique `X-Request-Nonce` (or `X-Admin-Nonce`) whose value
/// is incorporated into the HMAC signature. The server records SHA-256 digests
/// of seen nonces and rejects duplicates within the retention window.
///
/// Nonces are stored as SHA-256 digests to bound memory regardless of input length.
/// Entries are lazily evicted on each `check_and_insert` call.
pub struct HmacNonceStore {
    /// nonce-digest → insertion time
    nonces: DashMap<[u8; 32], Instant>,
    /// Retention window in seconds (should equal the HMAC timestamp window)
    window_secs: u64,
}

impl HmacNonceStore {
    pub fn new(window_secs: u64) -> Self {
        Self {
            nonces: DashMap::new(),
            window_secs,
        }
    }

    /// Returns `true` if this nonce has been seen before within the window
    /// (replay detected); `false` if it is new (nonce recorded).
    ///
    /// Expired entries are lazily evicted on each call.
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        let now = Instant::now();
        let window = self.window_secs;
        self.nonces
            .retain(|_, inserted_at| now.duration_since(*inserted_at).as_secs() < window);
        let digest = Self::digest(nonce);
        if self.nonces.contains_key(&digest) {
            return true; // replay
        }
        self.nonces.insert(digest, now);
        false
    }

    fn digest(nonce: &str) -> [u8; 32] {
        let d = Sha256::digest(nonce.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}

/// Connection info with fingerprint data
#[derive(Clone, Debug)]
pub struct FingerprintedConnection {
    pub remote_addr: SocketAddr,
    pub ja3_hash: Option<String>,
    pub ja4_hash: Option<String>,
    pub client_name: Option<String>,
    pub is_browser: bool,
    /// SEC-002: whether this connection's handshake has completed. A request
    /// dispatched before it has is early data (see [`crate::early_data`]), and
    /// the route gate answers 425 unless the route and method allow 0-RTT.
    /// [`HandshakeDone::completed`](crate::early_data::HandshakeDone::completed)
    /// on every connection that cannot carry early data.
    ///
    /// This was a flag set when the ClientHello *offered* early data, which
    /// marked every request on the connection, including those sent after the
    /// handshake, and said nothing about whether any early data was accepted.
    pub handshake_done: crate::early_data::HandshakeDone,
    /// True when the client presented a valid certificate during the TLS handshake.
    /// Used by per-route internal mTLS enforcement: routes with `internal = true`
    /// default to requiring a client certificate.
    pub client_cert_present: bool,
    /// What the handshake actually negotiated, captured once when it completes.
    ///
    /// Read back out by the Handshake Mirror (`/handshake/`), which reports a
    /// visitor their own connection. Every field here is already known to the
    /// TLS layer and thrown away today; none of it is derived from anything the
    /// client can assert in a request.
    pub handshake: HandshakeFacts,
}

impl FingerprintedConnection {
    /// Every header a TCP listener derives from the connection rather than
    /// takes from the client, besides the handshake set in
    /// [`HandshakeFacts::HEADER_NAMES`]. The HTTP/3 path strips the same eight.
    pub const DERIVED_HEADERS: [&'static str; 8] = [
        "x-ja3-hash",
        "x-ja4-hash",
        "x-client-name",
        "x-client-type",
        "x-client-cert",
        "x-tls-early-data",
        "x-connection-protocol",
        "x-pqc-enabled",
    ];

    /// Replace every connection-derived header the client sent with what this
    /// connection established: strip all of them, then set the ones that apply.
    ///
    /// One implementation for every TCP listener. It was written out per
    /// listener and the copies disagreed -- only one set `x-pqc-enabled`, and
    /// neither stripped `x-ja3-hash` or `x-ja4-hash` when the fingerprinter had
    /// no hash, so a client could supply its own to a route's JA3 allowlist --
    /// while the two listeners served through `axum_server` had none at all,
    /// so a client there could send `x-client-cert: 1` to an internal route.
    pub fn apply_headers(&self, headers: &mut http::HeaderMap, is_http1: bool) {
        use http::HeaderValue;

        // Most requests carry no `x-` header at all; look before hashing eight
        // names for removal.
        if headers.keys().any(|k| k.as_str().starts_with("x-")) {
            for name in Self::DERIVED_HEADERS {
                headers.remove(name);
            }
        }
        self.handshake.inject_headers(headers);

        let mut set = |name: &'static str, value: Option<&str>| {
            if let Some(v) = value.and_then(|v| HeaderValue::from_str(v).ok()) {
                headers.insert(name, v);
            }
        };
        set("x-ja3-hash", self.ja3_hash.as_deref());
        set("x-ja4-hash", self.ja4_hash.as_deref());
        set("x-client-name", self.client_name.as_deref());
        set("x-client-type", self.is_browser.then_some("browser"));
        // SEC-002: the route gate answers 425 on routes that do not allow
        // 0-RTT. Read as each request is dispatched: early until the
        // handshake completes, and never after.
        set(
            "x-tls-early-data",
            (!self.handshake_done.is_done()).then_some("1"),
        );
        // Per-route mTLS enforcement reads this.
        set("x-client-cert", self.client_cert_present.then_some("1"));
        // Per-route allow_http11 enforcement reads this.
        set("x-connection-protocol", is_http1.then_some("h1"));
        // Whether *this handshake* was post-quantum, not whether the listener
        // supports it.
        let pqc = self.handshake.is_post_quantum();
        set("x-pqc-enabled", Some(if pqc { "true" } else { "false" }));
    }
}

/// The negotiated properties of one completed TLS handshake.
///
/// Deliberately `String`/`&'static str` rather than the rustls types: this is
/// cloned per connection and handed to header injection, and the rustls enums
/// would only be `format!`-ed there instead.
#[derive(Clone, Debug, Default)]
pub struct HandshakeFacts {
    /// e.g. `TLSv1_3`.
    pub tls_version: Option<String>,
    /// e.g. `TLS13_AES_256_GCM_SHA384`.
    pub cipher_suite: Option<String>,
    /// The negotiated key exchange group, e.g. `X25519MLKEM768` for a hybrid
    /// post-quantum handshake or `X25519` for a classical one. This is the
    /// field that says whether a visitor is actually PQC-protected.
    pub kex_group: Option<String>,
    /// The ALPN protocol the connection settled on, e.g. `h2`.
    pub alpn: Option<String>,
    /// Encrypted Client Hello outcome: `not-offered`, `rejected`, or `accepted`.
    pub ech: &'static str,
    /// The five header values, built on first use. A connection's handshake
    /// does not change, so validating and copying these strings on every
    /// request — five `HeaderValue::from_str` allocations and five
    /// name parses each time — was work done once per request for an answer
    /// fixed per connection. Filled after the fields above are final: every
    /// constructor finishes them before the facts are shared.
    pub(crate) prepared: std::sync::OnceLock<[Option<http::HeaderValue>; 5]>,
}

impl HandshakeFacts {
    /// Whether the negotiated group carries ML-KEM.
    ///
    /// One definition for everything that reports it: `x-pqc-enabled` on
    /// every transport and the handshake counters the monitor shows.
    pub fn is_post_quantum(&self) -> bool {
        self.kex_group
            .as_deref()
            .and_then(crate::pqc_tls::PqcKemAlgorithm::from_str)
            .is_some()
    }

    /// The headers [`inject_headers`](Self::inject_headers) owns.
    ///
    /// Named in one place because they have to be stripped and set as a set:
    /// removing four of five would leave the fifth forgeable.
    pub const HEADER_NAMES: [&'static str; 5] = [
        "x-tls-version",
        "x-tls-cipher",
        "x-tls-group",
        "x-tls-alpn",
        "x-tls-ech",
    ];

    /// Replace any client-supplied handshake headers with what this connection
    /// actually negotiated.
    ///
    /// Strip-then-set, matching the SEC-002 handling of `x-tls-early-data`: the
    /// Handshake Mirror reports these back to the visitor as fact, so a client
    /// that sends its own `x-tls-group: X25519MLKEM768` must not be able to
    /// make the page claim a post-quantum handshake that never happened.
    ///
    /// A field the listener could not determine is left absent rather than
    /// filled with a placeholder — "unknown" and "we didn't look" are different
    /// answers and the mirror renders them differently.
    pub fn inject_headers(&self, headers: &mut http::HeaderMap) {
        const NAMES: [http::HeaderName; 5] = [
            http::HeaderName::from_static(HandshakeFacts::HEADER_NAMES[0]),
            http::HeaderName::from_static(HandshakeFacts::HEADER_NAMES[1]),
            http::HeaderName::from_static(HandshakeFacts::HEADER_NAMES[2]),
            http::HeaderName::from_static(HandshakeFacts::HEADER_NAMES[3]),
            http::HeaderName::from_static(HandshakeFacts::HEADER_NAMES[4]),
        ];
        let values = self.prepared.get_or_init(|| {
            let v = |s: Option<&str>| s.and_then(|s| http::HeaderValue::from_str(s).ok());
            [
                v(self.tls_version.as_deref()),
                v(self.cipher_suite.as_deref()),
                v(self.kex_group.as_deref()),
                v(self.alpn.as_deref()),
                v(Some(self.ech)),
            ]
        });
        // `insert` replaces every value the client sent under the name, so
        // strip-then-set is one operation; a field we could not determine is
        // removed instead.
        for (name, value) in NAMES.iter().zip(values) {
            match value {
                Some(v) => {
                    headers.insert(name.clone(), v.clone());
                }
                None => {
                    headers.remove(name);
                }
            }
        }
    }

    /// Capture from a completed server-side handshake.
    pub(crate) fn from_connection(conn: &rustls::ServerConnection) -> Self {
        Self {
            tls_version: conn.protocol_version().map(|v| format!("{v:?}")),
            cipher_suite: conn
                .negotiated_cipher_suite()
                .map(|s| format!("{:?}", s.suite())),
            kex_group: conn
                .negotiated_key_exchange_group()
                .map(|g| format!("{:?}", g.name())),
            alpn: conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
            ech: match conn.ech_acceptance() {
                rustls::server::EchAcceptance::NotOffered => "not-offered",
                rustls::server::EchAcceptance::Rejected => "rejected",
                rustls::server::EchAcceptance::Accepted => "accepted",
            },
            prepared: std::sync::OnceLock::default(),
        }
    }
}

impl Connected<&FingerprintedTlsStream<ServerTlsStream>> for FingerprintedConnection {
    fn connect_info(target: &FingerprintedTlsStream<ServerTlsStream>) -> Self {
        target.conn_info.clone()
    }
}

/// The server side of a rustls connection on the fingerprinting listener:
/// tokio-rustls's stream, or [`EarlyRustls`](crate::early_data::EarlyRustls)
/// when 0-RTT is enabled.
pub enum ServerTlsStream {
    Rustls(TlsStream<TcpStream>),
    Early(crate::early_data::EarlyRustls<TcpStream>),
}

impl ServerTlsStream {
    pub fn connection(&self) -> &rustls::ServerConnection {
        match self {
            Self::Rustls(s) => s.get_ref().1,
            Self::Early(s) => s.connection(),
        }
    }

    pub fn handshake_done(&self) -> crate::early_data::HandshakeDone {
        match self {
            Self::Rustls(_) => crate::early_data::HandshakeDone::completed(),
            Self::Early(s) => s.handshake_done(),
        }
    }
}

impl AsyncRead for ServerTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => Pin::new(s).poll_read(cx, buf),
            Self::Early(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(s) => Pin::new(s).poll_write(cx, buf),
            Self::Early(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    // Forwarded for the reason given on `FingerprintedTlsStream`'s.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Rustls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            Self::Early(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Rustls(s) => s.is_write_vectored(),
            Self::Early(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => Pin::new(s).poll_flush(cx),
            Self::Early(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Rustls(s) => Pin::new(s).poll_shutdown(cx),
            Self::Early(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

pin_project! {
    /// TLS stream wrapper that includes fingerprint information
    pub struct FingerprintedTlsStream<S> {
        #[pin]
        inner: S,
        pub conn_info: FingerprintedConnection,
    }
}

impl<S> FingerprintedTlsStream<S> {
    pub fn new(inner: S, conn_info: FingerprintedConnection) -> Self {
        Self { inner, conn_info }
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead> AsyncRead for FingerprintedTlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for FingerprintedTlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    // Both of these must be forwarded, not left to the trait defaults.
    // `AsyncWrite::poll_write_vectored` defaults to writing only the first
    // buffer and `is_write_vectored` defaults to `false`, so a wrapper that
    // omits them tells hyper the transport cannot do vectored I/O. hyper then
    // writes an HTTP/2 HEADERS frame and its DATA frame as two separate
    // segments instead of one, and with Nagle enabled on the accepted socket
    // the small second write is held until the peer's delayed-ACK timer fires:
    // a flat 40 ms added to every response on the fingerprinting path.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

/// TLS acceptor that captures ClientHello for fingerprinting
pub struct FingerprintingTlsAcceptor {
    tls_acceptor: tokio_rustls::TlsAcceptor,
    fingerprint_extractor: Arc<FingerprintExtractor>,
    security_state: SecurityState,
    fingerprint_config: FingerprintConfig,
    /// SEC-002: whether 0-RTT is enabled. Handshakes then run on
    /// [`EarlyRustls`](crate::early_data::EarlyRustls), which serves early data
    /// before the handshake completes; otherwise on tokio-rustls, unchanged.
    zero_rtt_enabled: bool,
    /// `tls.zero_rtt_replay_protection`.
    zero_rtt_replay: ZeroRttReplayGuard,
    /// `tls.handshake_timeout_secs`: with 0-RTT on, also how long closing a
    /// connection waits for its handshake to finish.
    handshake_timeout: std::time::Duration,
    /// HTTP/1.1-only TLS acceptor used when the SNI matches http11_only_hosts.
    /// Advertises only "http/1.1" in ALPN so browsers open independent TCP
    /// connections per fetch() stream instead of coalescing into one HTTP/2 pipe.
    http11_only_tls_acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    /// Hostnames for which only HTTP/1.1 ALPN is advertised (no h2).
    http11_only_hosts: Vec<String>,
}

impl FingerprintingTlsAcceptor {
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        fingerprint_extractor: Arc<FingerprintExtractor>,
        security_state: SecurityState,
        fingerprint_config: FingerprintConfig,
        zero_rtt_enabled: bool,
    ) -> Self {
        Self {
            tls_acceptor: tokio_rustls::TlsAcceptor::from(config),
            fingerprint_extractor,
            security_state,
            fingerprint_config,
            zero_rtt_enabled,
            zero_rtt_replay: ZeroRttReplayGuard::from_config("strict", 60),
            handshake_timeout: std::time::Duration::from_secs(10),
            http11_only_tls_acceptor: None,
            http11_only_hosts: Vec::new(),
        }
    }

    /// Configure HTTP/1.1-only ALPN for the given hostnames.
    ///
    /// When a ClientHello SNI matches one of `hosts`, the acceptor uses
    /// `config` (which must advertise only "http/1.1") instead of the default
    /// TLS config.  This prevents HTTP/2 connection coalescing so parallel
    /// `fetch()` streams open independent TCP connections.
    #[must_use]
    pub fn with_http11_only_acceptor(
        mut self,
        config: Arc<rustls::ServerConfig>,
        hosts: Vec<String>,
    ) -> Self {
        self.http11_only_tls_acceptor = Some(Arc::new(tokio_rustls::TlsAcceptor::from(config)));
        self.http11_only_hosts = hosts;
        self
    }

    /// Configure 0-RTT replay protection mode and nonce window.
    ///
    /// Call this after `new()` when the TLS config has non-default 0-RTT settings.
    #[must_use]
    pub fn with_zero_rtt_protection(mut self, mode: &str, window_secs: u64) -> Self {
        self.zero_rtt_replay = ZeroRttReplayGuard::from_config(mode, window_secs);
        self
    }

    /// `tls.handshake_timeout_secs`.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Extract the SNI hostname from a raw TLS ClientHello record.
    ///
    /// Parses the SNI extension (type 0x0000) and returns the first `host_name`
    /// entry as a UTF-8 string.  Returns `None` if SNI is absent, malformed, or
    /// the data is too short to parse.
    fn extract_sni(data: &[u8]) -> Option<String> {
        // TLS record header: 5 bytes.  Handshake header: 4 bytes.
        if data.len() < 9 {
            return None;
        }
        let ch = &data[9..]; // ClientHello body starts here
        if ch.len() < 34 {
            return None;
        }
        // Skip legacy_version (2) + random (32)
        let mut off = 34usize;
        // Session ID
        if off >= ch.len() {
            return None;
        }
        let sid_len = ch[off] as usize;
        off = off.saturating_add(1 + sid_len);
        // Cipher suites
        if off + 2 > ch.len() {
            return None;
        }
        let cs_len = u16::from_be_bytes([ch[off], ch[off + 1]]) as usize;
        off = off.saturating_add(2 + cs_len);
        // Compression methods
        if off >= ch.len() {
            return None;
        }
        let cm_len = ch[off] as usize;
        off = off.saturating_add(1 + cm_len);
        // Extensions block
        if off + 2 > ch.len() {
            return None;
        }
        let ext_total = u16::from_be_bytes([ch[off], ch[off + 1]]) as usize;
        off += 2;
        let ext_end = off.saturating_add(ext_total);
        if ext_end > ch.len() {
            return None;
        }
        // Walk extensions looking for SNI (type 0x0000)
        while off + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([ch[off], ch[off + 1]]);
            let ext_len = u16::from_be_bytes([ch[off + 2], ch[off + 3]]) as usize;
            off += 4;
            if ext_type == 0x0000 {
                // SNI extension: 2 bytes list_length, 1 byte name_type, 2 bytes name_length, N bytes name
                if off + 5 > ext_end {
                    return None;
                }
                let name_type = ch[off + 2];
                if name_type != 0x00 {
                    return None; // only host_name (0x00) is supported
                }
                let name_len = u16::from_be_bytes([ch[off + 3], ch[off + 4]]) as usize;
                let name_off = off + 5;
                if name_off + name_len > ch.len() {
                    return None;
                }
                return String::from_utf8(ch[name_off..name_off + name_len].to_vec()).ok();
            }
            off = off.saturating_add(ext_len);
        }
        None
    }

    /// SEC-002: Scan a raw ClientHello record for the TLS 1.3 `early_data`
    /// extension (type 0x002a, RFC 8446 §4.2.10).  Returns true if the client
    /// offered early data, regardless of whether the server will accept it.
    pub fn client_hello_has_early_data_extension(data: &[u8]) -> bool {
        client_hello_extension(data, 0x002a).is_some()
    }

    /// Accept a TLS connection with fingerprint capture
    pub async fn accept(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) -> io::Result<Option<FingerprintedTlsStream<ServerTlsStream>>> {
        // Peek at the ClientHello before TLS handshake
        let mut peek_buf = vec![0u8; MAX_CLIENT_HELLO_SIZE];
        let peek_result = stream.peek(&mut peek_buf).await;
        // Save peeked length for use after the match (peek_result is consumed there)
        let peek_len = peek_result.as_ref().map(|n| *n).unwrap_or(0);

        let (fingerprint_result, offered_early_data) = match peek_result {
            Ok(n) if n > 0 => {
                trace!("Peeked {} bytes of ClientHello from {}", n, remote_addr);
                let fp = self.fingerprint_extractor.process_client_hello(
                    &peek_buf[..n],
                    remote_addr.ip(),
                    &self.security_state,
                    &self.fingerprint_config,
                );
                // SEC-002: Detect early_data extension only when 0-RTT is enabled.
                let early = self.zero_rtt_enabled
                    && Self::client_hello_has_early_data_extension(&peek_buf[..n]);
                (fp, early)
            }
            Ok(_) => {
                debug!("Empty peek from {}", remote_addr);
                (
                    FingerprintResult {
                        allowed: true,
                        ja3_hash: None,
                        ja4_hash: None,
                        classification: None,
                        client_name: None,
                    },
                    false,
                )
            }
            Err(e) => {
                debug!("Failed to peek ClientHello from {}: {}", remote_addr, e);
                (
                    FingerprintResult {
                        allowed: true,
                        ja3_hash: None,
                        ja4_hash: None,
                        classification: None,
                        client_name: None,
                    },
                    false,
                )
            }
        };

        // Check if connection should be blocked
        if !fingerprint_result.allowed {
            warn!(
                "Blocking connection from {} due to fingerprint {:?}",
                remote_addr, fingerprint_result.ja3_hash
            );
            return Ok(None);
        }

        // SEC-002 / STEP 10: 0-RTT replay protection, before any handshake
        // work: a repeated ClientHello (or, under "session", ticket) that
        // offers early data is refused outright.
        if offered_early_data
            && peek_len > 0
            && self.zero_rtt_replay.is_replay(&peek_buf[..peek_len])
        {
            warn!(
                "0-RTT replay detected from {} — rejecting early data",
                remote_addr
            );
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "0-RTT replay protection: duplicate early data rejected",
            ));
        }

        // Log fingerprint info
        if let Some(ref ja3) = fingerprint_result.ja3_hash {
            let client = fingerprint_result
                .client_name
                .as_deref()
                .unwrap_or("unknown");
            debug!(
                "TLS fingerprint from {}: JA3={}, JA4={:?}, client={}",
                remote_addr, ja3, fingerprint_result.ja4_hash, client
            );
        }

        // Select TLS acceptor based on SNI: use the HTTP/1.1-only acceptor when
        // the client is connecting to a host that must not use HTTP/2.  This
        // prevents the browser from coalescing all parallel fetch() streams onto
        // a single HTTP/2 TCP connection (which would stall all streams together).
        let sni = Self::extract_sni(&peek_buf[..peek_len]);
        let use_http11_only = sni
            .as_deref()
            .map(|name| {
                self.http11_only_hosts
                    .iter()
                    .any(|h| h.eq_ignore_ascii_case(name))
            })
            .unwrap_or(false);

        // Perform TLS handshake
        let acceptor = match (use_http11_only, &self.http11_only_tls_acceptor) {
            (true, Some(h11_acceptor)) => {
                trace!(
                    "Using HTTP/1.1-only TLS config for SNI {:?} from {}",
                    sni,
                    remote_addr
                );
                h11_acceptor.as_ref()
            }
            _ => &self.tls_acceptor,
        };
        let tls_stream = if self.zero_rtt_enabled {
            crate::early_data::EarlyRustls::accept(
                Arc::clone(acceptor.config()),
                stream,
                self.handshake_timeout,
            )
            .await
            .map(ServerTlsStream::Early)
        } else {
            acceptor.accept(stream).await.map(ServerTlsStream::Rustls)
        }
        .map_err(|e| {
            debug!("TLS handshake failed for {}: {}", remote_addr, e);
            io::Error::new(io::ErrorKind::ConnectionAborted, e)
        })?;

        // Detect whether client presented a certificate (for per-route mTLS enforcement).
        let client_cert_present = tls_stream
            .connection()
            .peer_certificates()
            .map(|certs| !certs.is_empty())
            .unwrap_or(false);

        // Create connection info
        let is_browser = fingerprint_result
            .classification
            .as_ref()
            .map(|c| matches!(c, crate::security::FingerprintClass::Browser))
            .unwrap_or(false);

        let handshake = HandshakeFacts::from_connection(tls_stream.connection());

        let conn_info = FingerprintedConnection {
            remote_addr,
            ja3_hash: fingerprint_result.ja3_hash,
            ja4_hash: fingerprint_result.ja4_hash,
            client_name: fingerprint_result.client_name,
            is_browser,
            handshake_done: tls_stream.handshake_done(),
            client_cert_present,
            handshake,
        };

        Ok(Some(FingerprintedTlsStream::new(tls_stream, conn_info)))
    }
}

/// Extension trait for extracting fingerprint info from requests
pub trait FingerprintExt {
    fn ja3_hash(&self) -> Option<&str>;
    fn ja4_hash(&self) -> Option<&str>;
    fn client_name(&self) -> Option<&str>;
    fn is_browser(&self) -> bool;
}

impl FingerprintExt for FingerprintedConnection {
    fn ja3_hash(&self) -> Option<&str> {
        self.ja3_hash.as_deref()
    }

    fn ja4_hash(&self) -> Option<&str> {
        self.ja4_hash.as_deref()
    }

    fn client_name(&self) -> Option<&str> {
        self.client_name.as_deref()
    }

    fn is_browser(&self) -> bool {
        self.is_browser
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS 1.3 ClientHello with optional extensions.
    /// Used by SEC-002 tests.
    fn build_client_hello(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut ext_bytes: Vec<u8> = Vec::new();
        for (ext_type, ext_data) in extensions {
            ext_bytes.extend_from_slice(&ext_type.to_be_bytes());
            ext_bytes.extend_from_slice(
                &u16::try_from(ext_data.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            ext_bytes.extend_from_slice(ext_data);
        }
        let ext_len = u16::try_from(ext_bytes.len()).unwrap_or(u16::MAX);

        // ClientHello body
        let mut ch: Vec<u8> = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0x00); // session ID length = 0
        ch.extend_from_slice(&[0x00, 0x02]); // cipher suites length = 2
        ch.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch.push(0x01); // compression methods length = 1
        ch.push(0x00); // null compression
        ch.extend_from_slice(&ext_len.to_be_bytes());
        ch.extend_from_slice(&ext_bytes);

        // Handshake header: type=0x01 (ClientHello) + 3-byte length
        let ch_len = u32::try_from(ch.len()).unwrap_or(u32::MAX);
        let mut hs: Vec<u8> = vec![
            0x01,
            ((ch_len >> 16) & 0xff) as u8,
            ((ch_len >> 8) & 0xff) as u8,
            (ch_len & 0xff) as u8,
        ];
        hs.extend_from_slice(&ch);

        // TLS record header: content type 0x16, version 0x0301, 2-byte length
        let hs_len = u16::try_from(hs.len()).unwrap_or(u16::MAX);
        let mut record: Vec<u8> = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&hs_len.to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    #[test]
    fn test_early_data_extension_detected() {
        // ClientHello with early_data extension (0x002a, empty payload)
        let ch = build_client_hello(&[(0x002a, &[])]);
        assert!(
            FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&ch),
            "early_data extension 0x002a must be detected"
        );
    }

    #[test]
    fn test_early_data_extension_absent() {
        // ClientHello with SNI extension only
        let sni_ext = {
            let name = b"example.com";
            let mut v = Vec::new();
            let list_len = u16::try_from(name.len() + 3).unwrap_or(u16::MAX);
            v.extend_from_slice(&list_len.to_be_bytes()); // list length
            v.push(0x00); // host_name type
            v.extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
            v.extend_from_slice(name);
            v
        };
        let ch = build_client_hello(&[(0x0000, &sni_ext)]);
        assert!(
            !FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&ch),
            "early_data extension must not be detected when absent"
        );
    }

    #[test]
    fn test_early_data_extension_empty_input() {
        assert!(
            !FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&[]),
            "empty input must not panic and must return false"
        );
        assert!(
            !FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&[0u8; 4]),
            "truncated input must return false"
        );
    }

    /// The full set of connection-derived headers the listeners must strip
    /// before asserting their own values.
    ///
    /// `x-client-type` and `x-client-name` are the two that were missed: unlike
    /// the rest they are inserted only when the fingerprinter has something to
    /// say, so a conditional insert with no strip let a caller assert them.
    /// curl sending `x-client-type: browser` reached the backend as a browser.
    #[test]
    fn connection_derived_headers_are_all_strippable() {
        for name in [
            "x-ja3-hash",
            "x-ja4-hash",
            "x-client-name",
            "x-client-type",
            "x-client-cert",
            "x-tls-early-data",
            "x-connection-protocol",
            "x-pqc-enabled",
        ] {
            assert!(
                http::HeaderName::from_bytes(name.as_bytes()).is_ok(),
                "{name} must be a valid header name for the strip lists to work"
            );
        }

        // The handshake set is stripped wholesale by inject_headers; the rest
        // are stripped explicitly at each listener's injection site.
        assert_eq!(HandshakeFacts::HEADER_NAMES.len(), 5);
    }

    #[test]
    fn inject_headers_overwrites_client_supplied_values() {
        // The whole point of strip-then-set: a caller that asserts its own
        // handshake must not be believed. The Handshake Mirror renders these as
        // fact, and a forged x-tls-group would make it claim a post-quantum
        // connection that never happened.
        let facts = HandshakeFacts {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: Some("TLS13_AES_256_GCM_SHA384".to_string()),
            kex_group: Some("secp384r1".to_string()),
            alpn: Some("h2".to_string()),
            ech: "not-offered",
            prepared: std::sync::OnceLock::default(),
        };

        let mut headers = http::HeaderMap::new();
        headers.insert("x-tls-group", "X25519MLKEM768".parse().unwrap());
        headers.insert("x-tls-ech", "accepted".parse().unwrap());
        headers.insert("x-tls-version", "TLSv9_9".parse().unwrap());

        facts.inject_headers(&mut headers);

        assert_eq!(headers.get("x-tls-group").unwrap(), "secp384r1");
        assert_eq!(headers.get("x-tls-ech").unwrap(), "not-offered");
        assert_eq!(headers.get("x-tls-version").unwrap(), "TLSv1_3");
        // Exactly one value each, not the client's appended to ours.
        assert_eq!(headers.get_all("x-tls-group").iter().count(), 1);
    }

    #[test]
    fn inject_headers_removes_forged_values_it_cannot_replace() {
        // The QUIC path cannot observe cipher suite or group. A field we have no
        // value for must come out absent, never left holding whatever the client
        // sent — that is the difference between "not observable" and a lie.
        let facts = HandshakeFacts {
            tls_version: Some("TLSv1_3".to_string()),
            cipher_suite: None,
            kex_group: None,
            alpn: Some("h3".to_string()),
            ech: "unknown",
            prepared: std::sync::OnceLock::default(),
        };

        let mut headers = http::HeaderMap::new();
        headers.insert("x-tls-group", "X25519MLKEM768".parse().unwrap());
        headers.insert("x-tls-cipher", "TLS13_AES_256_GCM_SHA384".parse().unwrap());

        facts.inject_headers(&mut headers);

        assert!(headers.get("x-tls-group").is_none());
        assert!(headers.get("x-tls-cipher").is_none());
        assert_eq!(headers.get("x-tls-alpn").unwrap(), "h3");
    }

    /// A ClientHello record with the given extensions (type, body).
    fn client_hello(random: u8, exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[random; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        let mut ext = Vec::new();
        for (ty, b) in exts {
            ext.extend_from_slice(&ty.to_be_bytes());
            ext.extend_from_slice(&u16::try_from(b.len()).unwrap().to_be_bytes());
            ext.extend_from_slice(b);
        }
        body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, 0x00];
        hs.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// A pre_shared_key extension body naming one ticket.
    fn psk(ticket: &[u8]) -> Vec<u8> {
        let mut ids = u16::try_from(ticket.len()).unwrap().to_be_bytes().to_vec();
        ids.extend_from_slice(ticket);
        ids.extend_from_slice(&[0, 0, 0, 1]); // obfuscated_ticket_age
        let mut b = u16::try_from(ids.len()).unwrap().to_be_bytes().to_vec();
        b.extend_from_slice(&ids);
        b.extend_from_slice(&[0x00, 0x21, 0x20]); // binders, contents irrelevant here
        b.extend_from_slice(&[0u8; 32]);
        b
    }

    fn early_hello(random: u8, ticket: &[u8]) -> Vec<u8> {
        client_hello(random, &[(0x002a, vec![]), (0x0029, psk(ticket))])
    }

    #[test]
    fn extensions_and_the_resumed_ticket_are_read_from_a_client_hello() {
        let ch = early_hello(7, b"ticket-one");
        assert!(FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&ch));
        assert_eq!(client_hello_psk_identity(&ch), Some(&b"ticket-one"[..]));
        let plain = client_hello(7, &[(0x0000, vec![0, 0])]);
        assert!(!FingerprintingTlsAcceptor::client_hello_has_early_data_extension(&plain));
        assert_eq!(client_hello_psk_identity(&plain), None);
        // Cut short, the extensions block is not all there: nothing is claimed.
        assert_eq!(client_hello_psk_identity(&ch[..ch.len() - 10]), None);
    }

    #[test]
    fn strict_refuses_a_repeated_client_hello() {
        let guard = ZeroRttReplayGuard::from_config("strict", 60);
        assert!(!guard.is_replay(&early_hello(1, b"t")));
        assert!(
            guard.is_replay(&early_hello(1, b"t")),
            "the same ClientHello again"
        );
        assert!(
            !guard.is_replay(&early_hello(2, b"t")),
            "a new random is a new ClientHello"
        );
    }

    #[test]
    fn session_refuses_a_ticket_used_twice_for_early_data() {
        let guard = ZeroRttReplayGuard::from_config("session", 60);
        assert!(!guard.is_replay(&early_hello(1, b"ticket-a")));
        assert!(
            guard.is_replay(&early_hello(2, b"ticket-a")),
            "a different ClientHello resuming the same ticket"
        );
        assert!(!guard.is_replay(&early_hello(3, b"ticket-b")));
    }

    #[test]
    fn only_client_hellos_offering_early_data_are_tracked() {
        let guard = ZeroRttReplayGuard::from_config("strict", 60);
        let plain = client_hello(9, &[(0x0029, psk(b"t"))]);
        assert!(!guard.is_replay(&plain));
        assert!(
            !guard.is_replay(&plain),
            "a resumption without early data can repeat"
        );
        let off = ZeroRttReplayGuard::from_config("none", 60);
        assert!(!off.is_replay(&early_hello(1, b"t")));
        assert!(!off.is_replay(&early_hello(1, b"t")));
    }

    #[test]
    fn test_fingerprinted_connection() {
        let conn = FingerprintedConnection {
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            ja3_hash: Some("abc123".to_string()),
            ja4_hash: Some("t13d0102h2_def456_ghi789".to_string()),
            client_name: Some("Chrome".to_string()),
            is_browser: true,
            handshake_done: crate::early_data::HandshakeDone::completed(),
            client_cert_present: false,
            handshake: HandshakeFacts::default(),
        };

        assert_eq!(conn.ja3_hash(), Some("abc123"));
        assert!(conn.is_browser());
    }
}
