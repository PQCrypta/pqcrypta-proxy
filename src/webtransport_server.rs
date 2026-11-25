//! WebTransport sessions as every QUIC listener serves them.
//!
//! Their admission (`admit`: a browser's Origin, the per-client and
//! per-origin caps), and an
//! established session's streams and datagrams (`serve_session`: the speed
//! test and the telemetry wall at their paths, otherwise forwarded to the
//! route's backend). The QUIC listener (quic_listener) negotiates the
//! sessions, WebTransport over HTTP/3 draft 17 and the drafts before it, on
//! `udp_port`, `additional_ports` and `webtransport_port` alike.

use dashmap::DashMap;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wt_session::WtSession;
use tracing::{debug, error, info, warn, Instrument};

use crate::config::ProxyConfig;
use crate::proxy::BackendPool;

/// One origin's claim on a concurrent-session slot, given back on drop.
///
/// The counter is cloned out of the map in one expression, so the map's guard
/// is gone before anything awaits. It used to be read through the `RefMut`
/// that `entry` returns, bound to a name that was then shadowed -- and
/// shadowing drops nothing. That guard is a write lock on the map's shard, it
/// lived for the whole session, and it is not an async lock: the next session
/// from the same origin parked a worker thread waiting for it. Once every
/// worker was parked, nothing could poll the session holding the lock, and the
/// proxy stopped outright -- every listener, the admin port, SIGTERM -- until
/// the hang watchdog restarted it, twice on 2026-09-25.
#[derive(Debug)]
struct OriginSlot(Arc<AtomicU32>);

impl OriginSlot {
    /// Take a slot for `origin`, or `None` when it already has `max` sessions.
    ///
    /// A compare-and-swap, not a load followed by an add: with the separate
    /// read, two sessions arriving together could both see room for one and
    /// both take it.
    fn reserve(counts: &DashMap<String, Arc<AtomicU32>>, origin: &str, max: u32) -> Option<Self> {
        let counter = Arc::clone(
            counts
                .entry(origin.to_string())
                .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                .value(),
        );
        counter
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then_some(n + 1)
            })
            .ok()
            .map(|_| Self(counter))
    }
}

impl Drop for OriginSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Sessions open per client address (`server.webtransport_max_sessions_per_client`).
static CLIENT_SESSIONS: LazyLock<DashMap<IpAddr, u32>> = LazyLock::new(DashMap::new);

/// Sessions open per origin (`server.webtransport_max_sessions_per_origin`),
/// node-wide: a session counts here whichever entrance it came to
static ORIGIN_SESSIONS: LazyLock<DashMap<String, Arc<AtomicU32>>> = LazyLock::new(DashMap::new);

/// A WebTransport session's admission, held while it lasts: its claims on
/// the per-client and per-origin session caps
#[derive(Debug)]
pub(crate) struct Admission {
    _client: ClientSlot,
    _origin: OriginSlot,
}

/// Why a WebTransport session was not admitted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// A browser's Origin not in `server.webtransport_allowed_origins`
    Origin,
    /// Its address already holds `webtransport_max_sessions_per_client`
    ClientCap(u32),
    /// Its origin already holds `webtransport_max_sessions_per_origin`
    OriginCap(u32),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin => f.write_str("its Origin is not in server.webtransport_allowed_origins"),
            Self::ClientCap(n) => write!(f, "its address holds {n} sessions already"),
            Self::OriginCap(n) => write!(f, "its origin holds {n} sessions already"),
        }
    }
}

/// Admit a WebTransport session from `remote` whose browser sent `origin`,
/// by the same rules at every entrance: where the route's Origin is
/// verified by `server.webtransport_allowed_origins` (`check_origin`; the
/// MoQ relay verifies a browser's by `[moq]`'s own rules), a browser's must
/// be listed there (none listed admits none; a client that sends no Origin
/// is not a browser, draft-ietf-webtrans-http3-17 section 3.2); then a slot
/// under the per-client and the per-origin caps, given back when the
/// admission is dropped.
pub(crate) fn admit(
    config: &ProxyConfig,
    origin: Option<&str>,
    remote: IpAddr,
    check_origin: bool,
) -> Result<Admission, Refusal> {
    if check_origin {
        if let Some(o) = origin {
            if !config
                .server
                .webtransport_allowed_origins
                .iter()
                .any(|a| a == o)
            {
                return Err(Refusal::Origin);
            }
        }
    }
    let max_client = config.server.webtransport_max_sessions_per_client;
    let client = ClientSlot::reserve(
        &CLIENT_SESSIONS,
        crate::speedtest::canonical_ip(remote),
        max_client,
    )
    .ok_or(Refusal::ClientCap(max_client))?;
    let max_origin = config.server.webtransport_max_sessions_per_origin;
    let origin = OriginSlot::reserve(&ORIGIN_SESSIONS, origin.unwrap_or("no-origin"), max_origin)
        .ok_or(Refusal::OriginCap(max_origin))?;
    Ok(Admission {
        _client: client,
        _origin: origin,
    })
}

/// One client address's claim on a concurrent-session slot, given back on drop.
///
/// The count is read and raised under the map shard's lock and nothing awaits
/// while it is held (see [`OriginSlot`] for what holding it across an await
/// did). An address's entry goes when its last session ends, so the map holds
/// only addresses with sessions open.
#[derive(Debug)]
struct ClientSlot {
    counts: &'static DashMap<IpAddr, u32>,
    ip: IpAddr,
}

impl ClientSlot {
    /// Take a slot for `ip`, or `None` when it already has `max` sessions
    /// (0: no limit).
    fn reserve(counts: &'static DashMap<IpAddr, u32>, ip: IpAddr, max: u32) -> Option<Self> {
        let mut n = counts.entry(ip).or_insert(0);
        if max != 0 && *n >= max {
            return None;
        }
        *n += 1;
        drop(n);
        Some(Self { counts, ip })
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        if let Some(mut n) = self.counts.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
        }
        self.counts.remove_if(&self.ip, |_, n| *n == 0);
    }
}

/// The path a session was opened for and the backend its route names.
struct SessionRoute {
    /// The host the session was opened for (lowercase, no port)
    host: Option<String>,
    path: String,
    /// The route's backend and method; none for a session no route covers
    target: Option<WtTarget>,
    /// The bytes this session's streams hold while their requests are read
    /// (see [`SESSION_BUFFERED_REQUESTS`])
    buffered: Arc<AtomicUsize>,
}

impl SessionRoute {
    /// The method each payload is forwarded with: the route's
    /// `stream_to_method`, POST by default and for a session with no route.
    fn method(&self) -> &http::Method {
        self.target
            .as_ref()
            .map_or(&http::Method::POST, |t| &t.method)
    }
}

/// Where a WebTransport session's streams and datagrams go: its route's
/// backend, and the HTTP method their payloads are forwarded with.
#[derive(Clone, Debug)]
pub struct WtTarget {
    /// The route's backend or pool
    pub backend: String,
    /// `stream_to_method`, or POST
    pub method: http::Method,
}

impl WtTarget {
    /// The target a WebTransport route names.
    #[must_use]
    pub fn of(route: &crate::config::RouteConfig) -> Self {
        Self {
            backend: route.backend.clone(),
            method: route.stream_method(),
        }
    }
}

/// How long a stream's request may take to arrive.
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// What one session's streams may hold together while their requests are
/// read, in requests of `security.max_request_size`: however many streams a
/// session opens, and however long each withholds its end. The process as a
/// whole holds no more than its body budget (body_budget.rs), which every
/// transport's request bodies count against.
const SESSION_BUFFERED_REQUESTS: usize = 4;

/// How much of a stream is read at a time: each piece is counted before it
/// is kept.
const STREAM_READ_CHUNK: usize = 16 * 1024;

/// Why a stream's request was not read.
enum StreamRead {
    TooLarge,
    /// The session's share or the process's body budget would be exceeded
    NoMemory,
    Failed(std::io::Error),
    TimedOut,
}

/// The bytes one stream's request holds of its session's share, given back
/// when it drops.
struct SessionHold {
    held: Arc<AtomicUsize>,
    bytes: usize,
}

impl SessionHold {
    /// Count `more` bytes against the session's share of `limit`; `false`
    /// (nothing counted) when they would take it past.
    fn grow(&mut self, more: usize, limit: usize) -> bool {
        self.held
            .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                now.checked_add(more).filter(|total| *total <= limit)
            })
            .is_ok()
            && {
                self.bytes += more;
                true
            }
    }
}

impl Drop for SessionHold {
    fn drop(&mut self) {
        self.held.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// A stream's request as read, with the memory it holds counted against the
/// process's body budget and its session's share until it drops.
struct StreamRequest {
    bytes: Vec<u8>,
    _process: crate::body_budget::Reservation,
    _session: SessionHold,
}

impl std::ops::Deref for StreamRequest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

/// A stream's whole request, no more than `max` bytes. Every piece is counted
/// against the session's share (`session_limit` bytes in all) and the
/// process's body budget before it is kept, so a stream that would take
/// either past is refused as it arrives, not once it ends: a stream that
/// withholds its end holds no more than was counted.
async fn read_request<R: tokio::io::AsyncRead + Unpin>(
    recv_stream: &mut R,
    max: usize,
    session_held: &Arc<AtomicUsize>,
    session_limit: usize,
) -> Result<StreamRequest, StreamRead> {
    let deadline = tokio::time::Instant::now() + STREAM_READ_TIMEOUT;
    let mut bytes = Vec::new();
    let mut process = crate::body_budget::Reservation::new();
    let mut session = SessionHold {
        held: Arc::clone(session_held),
        bytes: 0,
    };
    let mut chunk = vec![0u8; STREAM_READ_CHUNK];
    loop {
        let n = match tokio::time::timeout_at(deadline, recv_stream.read(&mut chunk)).await {
            Err(_) => return Err(StreamRead::TimedOut),
            Ok(Err(e)) => return Err(StreamRead::Failed(e)),
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
        };
        if bytes.len() + n > max {
            return Err(StreamRead::TooLarge);
        }
        if !session.grow(n, session_limit) || !process.grow(n) {
            return Err(StreamRead::NoMemory);
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    Ok(StreamRequest {
        bytes,
        _process: process,
        _session: session,
    })
}

/// Serve an established WebTransport session, on either listener: the speed
/// test and the telemetry wall at their paths, and otherwise each stream and
/// datagram forwarded to the session route's backend.
#[expect(clippy::too_many_arguments)]
pub async fn serve_session<S: WtSession>(
    connection: Arc<S>,
    remote_addr: SocketAddr,
    host: Option<String>,
    path: String,
    session_target: Option<WtTarget>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(
        "🔄 Handling WebTransport connection from {} (path: {})",
        remote_addr, path
    );

    // Native speed test handler — serves /speedtest without backend proxying
    if path == "/speedtest" {
        return crate::speedtest::handle_speedtest_session(connection, remote_addr).await;
    }

    // Native telemetry wall handler — serves /telemetry without backend proxying
    if path == "/telemetry" {
        return crate::telemetry::handle_telemetry_session(connection, remote_addr).await;
    }

    // What every stream and datagram of this session is routed by.
    let session = Arc::new(SessionRoute {
        host,
        path,
        target: session_target,
        buffered: Arc::new(AtomicUsize::new(0)),
    });

    // Per-session datagram budget window (see webtransport_max_datagrams_per_sec).
    let mut dg_window_start = std::time::Instant::now();
    let mut dg_count: u32 = 0;

    loop {
        tokio::select! {
            // Handle unidirectional streams (client -> server)
            stream_result = connection.accept_uni() => {
                match stream_result {
                    Ok(recv_stream) => {
                        debug!("📥 New unidirectional stream from {}", remote_addr);
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_uni_stream(
                            recv_stream, remote_addr, conn, session_clone, config_clone, backend_clone,
                            security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Unidirectional stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            // Handle bidirectional streams
            stream_result = connection.accept_bi() => {
                match stream_result {
                    Ok((send_stream, recv_stream)) => {
                        debug!("📥📤 New bidirectional stream from {}", remote_addr);
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_bi_stream(
                            send_stream, recv_stream, remote_addr, conn, session_clone, config_clone,
                            backend_clone, security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Bidirectional stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }

            // Handle datagrams
            datagram_result = connection.receive_datagram() => {
                match datagram_result {
                    Ok(datagram) => {
                        // server.webtransport_max_datagrams_per_sec was configured
                        // and never enforced, so a session could flood datagrams
                        // unbounded — each one spawning a task. Drop anything past
                        // the per-second budget: datagrams are unreliable by
                        // definition, so shedding is the correct response.
                        let dg_limit = config.server.webtransport_max_datagrams_per_sec;
                        if dg_limit > 0 {
                            let now = std::time::Instant::now();
                            if now.duration_since(dg_window_start) >= std::time::Duration::from_secs(1) {
                                dg_window_start = now;
                                dg_count = 0;
                            }
                            dg_count += 1;
                            if dg_count > dg_limit {
                                debug!("Datagram budget exceeded for {} ({}/s) — dropping", remote_addr, dg_limit);
                                continue;
                            }
                        }
                        debug!("📦 Datagram received from {} ({} bytes)", remote_addr, datagram.len());
                        let conn = Arc::clone(&connection);
                        let config_clone = config.clone();
                        let backend_clone = backend_pool.clone();
                        let security_clone = security.clone();
                        let session_clone = Arc::clone(&session);
                        tokio::spawn(handle_datagram(
                            datagram.to_vec(), remote_addr, conn, session_clone, config_clone,
                            backend_clone, security_clone,
                        ).in_current_span());
                    }
                    Err(e) => {
                        debug!("Datagram stream closed from {}: {}", remote_addr, e);
                        break;
                    }
                }
            }
        }
    }

    debug!("🔚 WebTransport connection closed: {}", remote_addr);
    Ok(())
}

/// Handle unidirectional stream (client -> server)
async fn handle_uni_stream<S: WtSession>(
    mut recv_stream: S::Recv,
    remote_addr: SocketAddr,
    _connection: Arc<S>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let max_size = config.security.max_request_size;
    let session_limit = max_size.saturating_mul(SESSION_BUFFERED_REQUESTS);
    let buffer = match read_request(&mut recv_stream, max_size, &session.buffered, session_limit)
        .await
    {
        Ok(buffer) => buffer,
        Err(StreamRead::NoMemory) => {
            debug!(
                "Stream from {} refused: its session or the process holds as much request data as it may",
                remote_addr
            );
            return Err("Request memory exhausted".into());
        }
        Err(StreamRead::TooLarge) => {
            debug!(
                "Request from {} exceeds max size ({} bytes)",
                remote_addr, max_size
            );
            return Err("Request too large".into());
        }
        Err(StreamRead::Failed(e)) => {
            debug!("Read error from {}: {}", remote_addr, e);
            return Err(format!("Stream read error: {}", e).into());
        }
        Err(StreamRead::TimedOut) => {
            debug!("Request timeout from {}", remote_addr);
            return Err("Request timeout".into());
        }
    };

    debug!(
        "📥 Unidirectional data from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(
        &buffer,
        &session,
        remote_addr,
        &config,
        &backend_pool,
        &security,
    )
    .await
    {
        Ok(response) => {
            debug!("✅ Processed unidirectional request from {}", remote_addr);
            debug!("   Response: {} bytes", response.len());
        }
        Err(e) => {
            error!("❌ Failed to process request from {}: {}", remote_addr, e);
        }
    }

    Ok(())
}

/// Handle bidirectional stream
#[expect(clippy::too_many_arguments)] // WT handler: transport + routing + security
async fn handle_bi_stream<S: WtSession>(
    mut send_stream: S::Send,
    mut recv_stream: S::Recv,
    remote_addr: SocketAddr,
    _connection: Arc<S>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // A raw TCP backend: the stream's bytes are relayed both ways as they
    // come, to a connection of its own
    if let Some(backend) = session
        .target
        .as_ref()
        .and_then(|t| config.backends.get(&t.backend))
        .filter(|b| b.backend_type == crate::config::BackendType::Tcp)
    {
        return relay_to_tcp(send_stream, recv_stream, backend, remote_addr).await;
    }
    let max_size = config.security.max_request_size;
    let session_limit = max_size.saturating_mul(SESSION_BUFFERED_REQUESTS);
    let buffer = match read_request(&mut recv_stream, max_size, &session.buffered, session_limit)
        .await
    {
        Ok(buffer) => buffer,
        Err(why) => {
            // SEC-02: the detail is logged here; the client gets a generic
            // message, with no file path, OS error or library internals in it.
            let (message, error): (String, Box<dyn std::error::Error + Send + Sync>) = match why {
                StreamRead::TooLarge => (
                    format!("Request exceeds max size of {} bytes", max_size),
                    "Request too large".into(),
                ),
                StreamRead::NoMemory => (
                    "Server busy, try again".to_string(),
                    "Request memory exhausted".into(),
                ),
                StreamRead::Failed(e) => {
                    debug!("Stream read error for {}: {}", remote_addr, e);
                    (
                        "Stream error".to_string(),
                        format!("Stream read error: {}", e).into(),
                    )
                }
                StreamRead::TimedOut => ("Request timeout".to_string(), "Request timeout".into()),
            };
            let error_response = json!({
                "success": false,
                "error": message,
                "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            let _ = send_stream.shutdown().await;
            return Err(error);
        }
    };

    debug!(
        "📥 Bidirectional request from {} ({} bytes)",
        remote_addr,
        buffer.len()
    );

    // Process and proxy the request
    match proxy_request(
        &buffer,
        &session,
        remote_addr,
        &config,
        &backend_pool,
        &security,
    )
    .await
    {
        Ok(response) => {
            debug!(
                "📤 Sending response to {} ({} bytes)",
                remote_addr,
                response.len()
            );
            send_stream.write_all(&response).await?;
            send_stream.shutdown().await?;
            info!("✅ Bidirectional stream completed: {}", remote_addr);
        }
        Err(e) => {
            // SEC-02: Log full error server-side; send only a generic message to the client.
            error!("❌ Request processing failed for {}: {}", remote_addr, e);

            // Send error response
            let error_response = json!({
                "success": false,
                "error": "Request processing failed",
                "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
            });

            let error_bytes = serde_json::to_vec(&error_response)?;
            send_stream.write_all(&error_bytes).await?;
            send_stream.shutdown().await?;
        }
    }

    Ok(())
}

/// Handle datagram
/// How long a relayed stream may carry nothing either way
const RELAY_IDLE: Duration = Duration::from_mins(5);

/// Relay a WebTransport stream to a raw TCP `backend` and back until either
/// side finishes, or nothing moves for [`RELAY_IDLE`].
async fn relay_to_tcp<W, R>(
    send_stream: W,
    recv_stream: R,
    backend: &crate::config::BackendConfig,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    let _place = crate::backend_limits::acquire(backend).await?;
    let connect = tokio::net::TcpStream::connect(&backend.address);
    let tcp = tokio::time::timeout(Duration::from_millis(backend.timeout_ms.max(1)), connect)
        .await
        .map_err(|_| format!("connecting to {} timed out", backend.address))??;
    tcp.set_nodelay(true)?;
    let mut client = tokio::io::join(recv_stream, send_stream);
    let (up, down) = crate::ws_tunnel::relay(&mut client, tcp, Some(RELAY_IDLE)).await;
    debug!(
        "WebTransport relay for {} to {} ended: {} bytes up, {} down",
        remote_addr, backend.address, up, down
    );
    Ok(())
}

async fn handle_datagram<S: WtSession>(
    datagram: Vec<u8>,
    remote_addr: SocketAddr,
    connection: Arc<S>,
    session: Arc<SessionRoute>,
    config: Arc<ProxyConfig>,
    backend_pool: Arc<BackendPool>,
    security: Option<crate::security::SecurityState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Check datagram size limit (datagrams should be small, typically < 64KB)
    let max_datagram_size = 65535; // Max UDP datagram size
    if datagram.len() > max_datagram_size {
        error!(
            "Datagram from {} exceeds max size ({} > {})",
            remote_addr,
            datagram.len(),
            max_datagram_size
        );
        let error_response = json!({
            "success": false,
            "error": "Datagram too large",
            "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
        });
        let error_bytes = serde_json::to_vec(&error_response)?;
        connection.send_datagram(&error_bytes)?;
        return Ok(());
    }

    debug!(
        "📦 Processing datagram from {} ({} bytes)",
        remote_addr,
        datagram.len()
    );

    // Apply timeout for backend proxy call
    let timeout_duration = Duration::from_secs(30);
    let proxy_result = tokio::time::timeout(
        timeout_duration,
        proxy_request(
            &datagram,
            &session,
            remote_addr,
            &config,
            &backend_pool,
            &security,
        ),
    )
    .await;

    match proxy_result {
        Ok(Ok(response)) => {
            debug!(
                "📤 Sending datagram response to {} ({} bytes)",
                remote_addr,
                response.len()
            );
            connection.send_datagram(&response)?;
            debug!("✅ Datagram response sent to {}", remote_addr);
        }
        Ok(Err(e)) => {
            // SEC-02: Log full error server-side; send only a generic message to the client.
            error!("❌ Datagram processing failed for {}: {}", remote_addr, e);
            let error_response = json!({
                "success": false,
                "error": "Datagram processing failed",
                "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            connection.send_datagram(&error_bytes)?;
        }
        Err(_) => {
            error!("❌ Datagram proxy timeout for {}", remote_addr);
            let error_response = json!({
                "success": false,
                "error": "Backend timeout",
                "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
            });
            let error_bytes = serde_json::to_vec(&error_response)?;
            connection.send_datagram(&error_bytes)?;
        }
    }

    Ok(())
}

/// Proxy request to backend server via HTTP
async fn proxy_request(
    data: &[u8],
    session: &SessionRoute,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
    security: &Option<crate::security::SecurityState>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Where the payload goes: a JSON request names an operation, each the
    // backend path it is forwarded to; anything else goes to the session's
    // own path. A ping is answered here.
    let request: Option<serde_json::Value> = std::str::from_utf8(data)
        .ok()
        .and_then(|text| serde_json::from_str(text).ok());
    let operation = request
        .as_ref()
        .and_then(|r| r.get("operation"))
        .and_then(|v| v.as_str());
    if operation == Some("ping") {
        let response = json!({
            "success": true,
            "operation": "pong",
            "server": "pqcrypta-proxy",
            "webtransport": true,
            "timestamp": jiff::Timestamp::now().display_with_offset(jiff::tz::Offset::UTC).to_string()
        });
        return Ok(serde_json::to_vec(&response)?);
    }
    let forward_path = match operation {
        Some("encrypt") => "/encrypt",
        Some("decrypt") => "/decrypt",
        Some("generate_keys" | "keygen") => "/keys/generate",
        Some("health") => "/health",
        _ => session.path.as_str(),
    };

    // WAF inspection. A WebTransport stream/datagram payload is proxied to the
    // same backends (/encrypt, /decrypt, …) as an HTTP request, so it is an
    // attack surface on those backends and must clear the same WAF the HTTP and
    // HTTP/3 paths run, under the policy of the route its path is on (that
    // route's WAF switch and mode). The payload is treated as the request
    // body; there are no HTTP headers on a WT frame, so the header map is
    // empty. When no security state is attached (WAF disabled) this is a no-op.
    if let Some(sec) = security {
        if sec.waf().is_some() {
            let ip = crate::security::canonical_addr(remote_addr).ip();
            let is_pentest =
                crate::config::ip_list_contains(&sec.config.read().pentest_bypass_ips, &ip);
            let headers = axum::http::HeaderMap::new();
            let view = crate::security::SecurityRequestView {
                ip,
                peer_port: Some(remote_addr.port()),
                method: session.method().as_str(),
                path: forward_path,
                query: "",
                headers: &headers,
                body: Some(data),
                version: Some(http::Version::HTTP_3),
                authority: session.host.as_deref(),
            };
            let policy = crate::security::request_policy(
                config,
                session.host.as_deref(),
                forward_path,
                session.method(),
            );
            if let crate::security::SecurityDecision::WafBlock { rule } =
                sec.inspect_body(&view, &policy, is_pentest)
            {
                warn!(
                    "[WebTransport] WAF block: rule={} ip={} path={}",
                    rule, ip, forward_path
                );
                let body = json!({
                    "success": false,
                    "error": "Request blocked by security policy",
                    "webtransport": true,
                });
                return Ok(serde_json::to_vec(&body)?);
            }
        }
    }

    // Forward to backend, with a JSON request's own credential
    let credential = request
        .as_ref()
        .filter(|_| operation.is_some())
        .and_then(request_credential);
    forward_to_backend(
        data,
        forward_path,
        session.target.as_ref(),
        credential.as_deref(),
        remote_addr,
        config,
        backend_pool,
    )
    .await
}

/// The API key a WebTransport request carries in its body ("api_key"),
/// to send on as `X-API-Key`. A WebTransport frame has no headers, and the
/// backend authenticates every request: `X-WebTransport-Proxy` only says the
/// proxy forwarded it (and its WAF already inspected it), it is not a
/// credential. Anything a header cannot carry is not a key.
fn request_credential(request: &serde_json::Value) -> Option<String> {
    request
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|k| !k.is_empty() && k.len() <= 512 && k.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_string)
}

/// Forward a request to the backend of the session's route.
///
/// A session no WebTransport route covers has no backend, and what it sends
/// is answered here: nothing is forwarded on a guess.
async fn forward_to_backend(
    data: &[u8],
    path: &str,
    target: Option<&WtTarget>,
    api_key: Option<&str>,
    remote_addr: SocketAddr,
    config: &Arc<ProxyConfig>,
    backend_pool: &Arc<BackendPool>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(WtTarget {
        backend: backend_name,
        method,
    }) = target
    else {
        debug!(
            "WebTransport request from {} for {}: the session has no route",
            remote_addr, path
        );
        let body = json!({
            "success": false,
            "error": "No WebTransport route for this session",
            "webtransport": true,
        });
        return Ok(serde_json::to_vec(&body)?);
    };

    let backend = config.backends.get(backend_name).ok_or_else(|| {
        format!(
            "Backend '{}' of the session's route is not configured",
            backend_name
        )
    })?;

    debug!(
        "🔄 Forwarding WebTransport request to backend '{}': {}",
        backend_name, path
    );

    // Create headers for the request
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("X-Forwarded-For".to_string(), remote_addr.ip().to_string());
    headers.insert(
        "X-WebTransport-Proxy".to_string(),
        "pqcrypta-proxy".to_string(),
    );
    headers.insert("X-Real-IP".to_string(), remote_addr.ip().to_string());
    if let Some(key) = api_key {
        headers.insert("X-API-Key".to_string(), key.to_string());
    }

    // Use the BackendPool's proxy_http method
    let response = backend_pool
        .proxy_http(backend, method.as_str(), path, headers, data)
        .await
        .map_err(|e| format!("Backend proxy error: {}", e))?;

    debug!("✅ Backend response received ({} bytes)", response.len());

    Ok(response)
}

#[cfg(test)]
mod tests {
    /// A stream that sends `left` bytes and then neither ends nor sends more:
    /// a peer withholding its FIN.
    struct Withholding {
        left: usize,
    }

    impl tokio::io::AsyncRead for Withholding {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.left == 0 {
                return std::task::Poll::Pending;
            }
            let n = self.left.min(buf.remaining()).min(4096);
            buf.put_slice(&vec![b'a'; n]);
            self.left -= n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn outcome(r: &Result<super::StreamRequest, super::StreamRead>) -> &'static str {
        match r {
            Ok(_) => "read",
            Err(super::StreamRead::TooLarge) => "too large",
            Err(super::StreamRead::NoMemory) => "no memory",
            Err(super::StreamRead::Failed(_)) => "failed",
            Err(super::StreamRead::TimedOut) => "timed out",
        }
    }

    /// A stream past its session's share is refused as the bytes arrive,
    /// though it never ends, and gives back what it held.
    #[tokio::test]
    async fn a_stream_is_refused_at_its_session_s_share_without_waiting_for_its_end() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let held = Arc::new(AtomicUsize::new(0));
        let mut stream = Withholding { left: 100 * 1024 };
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::read_request(&mut stream, 1024 * 1024, &held, 64 * 1024),
        )
        .await
        .expect("refused as it arrives, not after the 30 s read timeout");
        assert_eq!(outcome(&r), "no memory");
        drop(r);
        assert_eq!(
            held.load(Ordering::Acquire),
            0,
            "the refused stream holds nothing"
        );
    }

    /// A stream past the request limit is refused as the bytes arrive, too.
    #[tokio::test]
    async fn a_stream_is_refused_at_the_request_limit_without_waiting_for_its_end() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;
        let held = Arc::new(AtomicUsize::new(0));
        let mut stream = Withholding { left: 100 * 1024 };
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::read_request(&mut stream, 32 * 1024, &held, 1024 * 1024),
        )
        .await
        .expect("refused as it arrives");
        assert_eq!(outcome(&r), "too large");
    }

    /// The streams of one session share it: what one holds the next cannot
    /// take, and it is given back when the first is done.
    #[tokio::test]
    async fn the_streams_of_a_session_share_its_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let held = Arc::new(AtomicUsize::new(0));
        let body = vec![b'b'; 40 * 1024];
        let limit = 64 * 1024;
        let first = super::read_request(&mut body.as_slice(), 1024 * 1024, &held, limit).await;
        assert_eq!(outcome(&first), "read");
        assert_eq!(held.load(Ordering::Acquire), 40 * 1024);
        let second = super::read_request(&mut body.as_slice(), 1024 * 1024, &held, limit).await;
        assert_eq!(outcome(&second), "no memory");
        drop(second);
        assert_eq!(held.load(Ordering::Acquire), 40 * 1024);
        drop(first);
        assert_eq!(held.load(Ordering::Acquire), 0);
        let third = super::read_request(&mut body.as_slice(), 1024 * 1024, &held, limit).await;
        assert_eq!(outcome(&third), "read");
        assert_eq!(third.map(|r| r.len()).ok(), Some(40 * 1024));
    }

    #[test]
    fn the_request_s_api_key_is_its_credential() {
        use super::request_credential;
        use serde_json::json;
        assert_eq!(
            request_credential(&json!({"operation": "encrypt", "api_key": " WebUI_key_123 "}))
                .as_deref(),
            Some("WebUI_key_123")
        );
        assert_eq!(request_credential(&json!({"operation": "encrypt"})), None);
        assert_eq!(request_credential(&json!({"api_key": ""})), None);
        // Nothing that could break out of a header
        assert_eq!(
            request_credential(&json!({"api_key": "key\r\nX-Admin: 1"})),
            None
        );
        assert_eq!(request_credential(&json!({"api_key": 42})), None);
    }

    use super::*;

    /// The per-origin cap still holds, and a slot comes back when its
    /// session ends.
    #[test]
    fn a_client_address_holds_at_most_its_cap_and_leaves_no_entry() {
        static COUNTS: LazyLock<DashMap<IpAddr, u32>> = LazyLock::new(DashMap::new);
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let a = ClientSlot::reserve(&COUNTS, ip, 2).expect("first session");
        let b = ClientSlot::reserve(&COUNTS, ip, 2).expect("second session");
        assert!(
            ClientSlot::reserve(&COUNTS, ip, 2).is_none(),
            "a third exceeded a cap of two"
        );
        drop(a);
        let c = ClientSlot::reserve(&COUNTS, ip, 2).expect("a slot given back");
        drop(b);
        drop(c);
        assert!(
            COUNTS.get(&ip).is_none(),
            "an address with no sessions keeps no entry"
        );
        assert!(
            ClientSlot::reserve(&COUNTS, ip, 0).is_some(),
            "0 is no limit"
        );
    }

    /// One admission for every entrance: a browser's Origin is checked
    /// against server.webtransport_allowed_origins where the route asks it
    /// (none listed admits none), a client with no Origin is not a browser,
    /// and the MoQ relay's route leaves the Origin to [moq]'s own rules
    #[test]
    fn a_session_is_admitted_by_its_origin_and_the_caps() {
        let mut config = ProxyConfig::default();
        let ip: IpAddr = "192.0.2.71".parse().unwrap();
        // None listed: no browser is admitted where the list is asked
        assert_eq!(
            super::admit(&config, Some("https://a.test"), ip, true).unwrap_err(),
            super::Refusal::Origin
        );
        config.server.webtransport_allowed_origins = vec!["https://a.test".into()];
        assert!(super::admit(&config, Some("https://a.test"), ip, true).is_ok());
        assert_eq!(
            super::admit(&config, Some("https://b.test"), ip, true).unwrap_err(),
            super::Refusal::Origin
        );
        // Not asked (the MoQ relay's route), and no Origin at all
        assert!(super::admit(&config, Some("https://b.test"), ip, false).is_ok());
        assert!(super::admit(&config, None, ip, true).is_ok());
        // The per-origin cap, held while the admission lives
        config.server.webtransport_max_sessions_per_origin = 1;
        let held = super::admit(&config, Some("https://a.test"), ip, true).unwrap();
        assert_eq!(
            super::admit(
                &config,
                Some("https://a.test"),
                "192.0.2.72".parse().unwrap(),
                true
            )
            .unwrap_err(),
            super::Refusal::OriginCap(1)
        );
        drop(held);
        assert!(super::admit(&config, Some("https://a.test"), ip, true).is_ok());
    }
}
