//! Connections to backends.
//!
//! HTTP/1.1 pooled per backend (over TCP, TLS or a Unix socket), HTTP/2 (TLS
//! with ALPN `h2`, or cleartext with prior knowledge) and HTTP/3 (QUIC)
//! multiplexed on one connection per backend. A response's body is a
//! [`BackendBody`] whatever carried it.
//!
//! The HTTP/1.1 pool:
//!
//! This replaced `hyper_util`'s legacy `Client` on the proxied-request path.
//! That client is general-purpose, and a reverse proxy paid for the
//! generality on every request: the pool key was rebuilt and hashed from the
//! URI, the absolute URI was rewritten to origin form, a `connect_to` future
//! was built whether or not a connection was needed, and returning a
//! connection to the pool spawned a task per request to wait for it to become
//! ready. Profiled on the HTTP/3 path that was 8.4% of the proxy's user time,
//! outside the HTTP/1.1 codec itself.
//!
//! Here a backend's idle connections sit in a stack. A request takes the most
//! recently used one (its socket is warm), waits for it to be ready, and hands
//! the request over; when the caller has read the response body to its end it
//! returns the connection with [`Lease::release`]. A connection the peer closed
//! while idle is noticed at checkout and dropped, and a request that could not
//! be written to a reused connection is retried on a new one — hyper hands the
//! unsent request back, so nothing is sent twice.
//!
//! One closure checkout cannot see: the backend's keep-alive timeout firing
//! just as a request is written (Apache's `KeepAliveTimeout` is 5 s; idle
//! connections live here up to `idle_timeout_secs`). The request went out and
//! the connection closed before any answer: "connection closed before message
//! completed", a 502 to the client. A request that may be repeated (RFC 9110
//! §9.2.2: GET, HEAD, OPTIONS, TRACE, PUT, DELETE) and whose body can be
//! replayed ([`Replay`]) is sent again on another connection; anything else
//! fails as before, since its first copy may have been acted on.
//!
//! It also gives backend TLS a real implementation: a backend with
//! `tls = true` connects through [`create_backend_tls_connector`], so its CA,
//! client certificate, SNI and verification settings apply.
//!
//! [`create_backend_tls_connector`]: crate::http_listener::create_backend_tls_connector

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use hyper::body::{Body, Frame, Incoming};
use hyper::client::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::BackendConfig;

/// A request body that can be sent again when a reused connection closes
/// before answering. Only a body certain to be the same the second time is.
pub trait Replay: Sized {
    fn replay(&self) -> Option<Self>;
}

impl<D: bytes::Buf + Clone> Replay for http_body_util::Full<D> {
    fn replay(&self) -> Option<Self> {
        Some(self.clone())
    }
}

/// A streamed body cannot be read twice; an empty one (a GET's) is empty
/// again.
impl Replay for axum::body::Body {
    fn replay(&self) -> Option<Self> {
        (Body::size_hint(self).exact() == Some(0)).then(axum::body::Body::empty)
    }
}

/// A copy of `req` to send again, when its method may be repeated (RFC 9110
/// §9.2.2) and its body replayed.
fn replayable<B: Replay>(req: &http::Request<B>) -> Option<http::Request<B>> {
    use http::Method;
    let idempotent = matches!(
        *req.method(),
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    );
    if !idempotent {
        return None;
    }
    let body = req.body().replay()?;
    let mut copy = http::Request::new(body);
    *copy.method_mut() = req.method().clone();
    *copy.uri_mut() = req.uri().clone();
    *copy.version_mut() = req.version();
    *copy.headers_mut() = req.headers().clone();
    *copy.extensions_mut() = req.extensions().clone();
    Some(copy)
}

/// A boxed error, as every transport's body reports one.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A backend response's body, from whichever transport carried it.
pub enum BackendBody {
    /// HTTP/1.1 or HTTP/2 (hyper)
    Hyper(Incoming),
    /// HTTP/3
    H3(H3Body),
}

impl Body for BackendBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            Self::Hyper(body) => std::pin::Pin::new(body)
                .poll_frame(cx)
                .map(|f| f.map(|r| r.map_err(Into::into))),
            Self::H3(body) => std::pin::Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Hyper(body) => body.is_end_stream(),
            Self::H3(body) => body.done,
        }
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self {
            Self::Hyper(body) => body.size_hint(),
            Self::H3(_) => hyper::body::SizeHint::default(),
        }
    }
}

impl std::fmt::Debug for BackendBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Hyper(_) => "BackendBody::Hyper",
            Self::H3(_) => "BackendBody::H3",
        })
    }
}

/// An HTTP/3 response body: the response stream's DATA, then its trailers.
/// The request body is still being sent while it is read; dropping this
/// stops that.
pub struct H3Body {
    recv: h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    data_done: bool,
    done: bool,
    upload: tokio::task::JoinHandle<()>,
}

impl Drop for H3Body {
    fn drop(&mut self) {
        self.upload.abort();
    }
}

impl Body for H3Body {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        use std::task::Poll;
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if !this.data_done {
            match std::task::ready!(this.recv.poll_recv_data(cx)) {
                Ok(Some(mut data)) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }
                Ok(None) => this.data_done = true,
                Err(e) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(Box::new(e))));
                }
            }
        }
        let trailers = std::task::ready!(this.recv.poll_recv_trailers(cx));
        this.done = true;
        Poll::Ready(match trailers {
            Ok(Some(trailers)) => Some(Ok(Frame::trailers(trailers))),
            Ok(None) => None,
            Err(e) => Some(Err(Box::new(e))),
        })
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

/// How an origin is spoken to
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wire {
    Http1,
    Http2,
    Http3,
}

impl Wire {
    fn of(backend: &BackendConfig) -> anyhow::Result<Self> {
        use crate::config::BackendType;
        Ok(match backend.backend_type {
            BackendType::Http1 | BackendType::Unix => Self::Http1,
            BackendType::Http2 => Self::Http2,
            BackendType::Http3 => Self::Http3,
            BackendType::Tcp => {
                return Err(anyhow::anyhow!(
                    "backend {} is a raw TCP backend: it carries WebTransport streams, not HTTP requests",
                    backend.name
                ))
            }
        })
    }
}

/// The one connection an HTTP/2 or HTTP/3 origin's requests share
enum Multiplexed<B> {
    H2(http2::SendRequest<B>),
    H3 {
        send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        connection: quinn::Connection,
        _endpoint: quinn::Endpoint,
    },
}

/// Pooled HTTP/1.1 client for one proxy's backends.
pub struct BackendClient<B> {
    origins: RwLock<HashMap<String, Arc<Origin<B>>>>,
    idle_timeout: Duration,
    max_idle: usize,
    connect_timeout: Duration,
}

/// Where each exchange's outcome is recorded: its latency when the backend
/// answered, an error when it did not (see [`set_metrics`]).
static METRICS: std::sync::OnceLock<Arc<crate::metrics::MetricsRegistry>> =
    std::sync::OnceLock::new();

/// Record every backend exchange in `metrics` (once, at startup).
pub fn set_metrics(metrics: Arc<crate::metrics::MetricsRegistry>) {
    let _ = METRICS.set(metrics);
}

/// Idle connections every client holds, by backend name (for the metrics).
static IDLE: std::sync::LazyLock<dashmap::DashMap<String, std::sync::atomic::AtomicU64>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

/// Idle connections held for each backend now, by every client.
pub fn idle_by_backend() -> Vec<(String, u64)> {
    IDLE.iter()
        .map(|e| {
            (
                e.key().clone(),
                e.value().load(std::sync::atomic::Ordering::Relaxed),
            )
        })
        .collect()
}

/// One backend: where it is, how to reach it, and its connections.
struct Origin<B> {
    /// The backend's name, which its idle connections are counted under
    name: String,
    address: String,
    wire: Wire,
    /// The socket of a Unix backend (`unix:/path` or `/path`)
    unix: Option<std::path::PathBuf>,
    /// QUIC client configuration and server name of an HTTP/3 backend
    quic: Option<(quinn::ClientConfig, String)>,
    /// The connection an HTTP/2 or HTTP/3 backend's requests share
    multiplexed: tokio::sync::Mutex<Option<Multiplexed<B>>>,
    /// Connector and server name when the backend is reached over TLS.
    tls: Option<(
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )>,
    /// Oldest at the front, most recently returned at the back.
    idle: Mutex<VecDeque<Idle<B>>>,
    idle_timeout: Duration,
    max_idle: usize,
    /// `BackendConfig::disable_pooling` inverted: when false every exchange
    /// gets a new connection and none is kept.
    pooling: bool,
}

struct Idle<B> {
    tx: http1::SendRequest<B>,
    since: Instant,
}

/// An attempt that failed, with the request when it was never written.
struct Failed<B> {
    error: anyhow::Error,
    /// Boxed: a request is large, and most attempts succeed
    unsent: Option<Box<http::Request<B>>>,
}

/// Why [`BackendClient::send_with_retry`] has no response.
#[derive(Debug)]
pub enum SendError {
    /// The last attempt had no answer within its time
    TimedOut(Duration),
    /// The backend could not be reached or failed the exchange
    Failed(anyhow::Error),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimedOut(after) => write!(f, "no answer within {}ms", after.as_millis()),
            Self::Failed(error) => write!(f, "{error}"),
        }
    }
}

/// When a request goes to its backend again (`retries`, `retry_backoff_ms`,
/// `retry_on` on the backend).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts after the first
    pub retries: u8,
    /// Before the first retry; doubled before each after it
    pub backoff: Duration,
    /// A connection that could not be made (nothing was sent)
    pub on_connect_failure: bool,
    /// No answer within the backend's timeout
    pub on_timeout: bool,
    /// A 5xx answer
    pub on_5xx: bool,
}

impl RetryPolicy {
    /// The backend's policy: by default two more attempts, 50 ms apart and
    /// doubling, when a connection could not be made, which cannot repeat
    /// anything the backend did. `retry_on` names the conditions in place of
    /// that default: `connect-failure`, `timeout`, `5xx`.
    pub fn of(backend: &BackendConfig) -> Self {
        let on = |name: &str| match &backend.retry_on {
            Some(list) => list.iter().any(|c| c.eq_ignore_ascii_case(name)),
            None => name == "connect-failure",
        };
        Self {
            retries: backend.retries.unwrap_or(2),
            backoff: Duration::from_millis(backend.retry_backoff_ms.unwrap_or(50)),
            on_connect_failure: on("connect-failure"),
            on_timeout: on("timeout"),
            on_5xx: on("5xx"),
        }
    }
}

/// A connection carrying one exchange.
///
/// [`release`](Self::release) it once the response body has been read to its
/// end; dropping it instead closes the connection, which is right when the
/// exchange was abandoned part-way.
pub struct Lease<B> {
    tx: Option<http1::SendRequest<B>>,
    origin: Arc<Origin<B>>,
    /// The request's place under its backend's limit (`backend_limits`),
    /// given back with the connection
    _place: crate::backend_limits::Place,
}

impl<B> std::fmt::Debug for Lease<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("backend", &self.origin.name)
            .field("pooled", &self.tx.is_some())
            .finish_non_exhaustive()
    }
}

impl<B> Lease<B> {
    /// The exchange is complete: the connection can carry another request.
    pub fn release(mut self) {
        if let Some(tx) = self.tx.take() {
            self.origin.put(tx);
        }
    }
}

/// A response body that returns its connection to the pool when it ends.
///
/// For callers that hand the body on rather than reading it themselves — the
/// TCP listener passes it to hyper's server, which decides when to poll it.
/// The connection is released when the body reports its end, including when
/// the last data frame is also the end (`is_end_stream`), because a server that
/// knows the length stops polling there and would never see the final `None`.
/// A body that fails, or is dropped part-way, closes its connection instead.
pub struct ReleaseOnEnd<Bd: Body, B> {
    body: Bd,
    lease: Option<Lease<B>>,
}

impl<Bd: Body, B> ReleaseOnEnd<Bd, B> {
    pub fn new(body: Bd, lease: Lease<B>) -> Self {
        Self {
            body,
            lease: Some(lease),
        }
    }
}

/// A body dropped at its end still returns its connection.
///
/// hyper's server does not poll a body that reports `is_end_stream()` before
/// the first poll — an empty `Content-Length: 0` response, a 204, a 304, the
/// answer to a HEAD — so for those `poll_frame` never runs. Without this the
/// lease was dropped with the body and the connection closed: every such
/// response opened a new backend connection, measured as HTTP/1.1 empty-body
/// throughput falling from 48,000 to 13,800 req/s.
impl<Bd: Body, B> Drop for ReleaseOnEnd<Bd, B> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            if self.body.is_end_stream() {
                lease.release();
            }
        }
    }
}

impl<Bd, B> Body for ReleaseOnEnd<Bd, B>
where
    Bd: Body + Unpin,
    B: Unpin,
{
    type Data = Bd::Data;
    type Error = Bd::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        let polled = std::pin::Pin::new(&mut this.body).poll_frame(cx);
        match &polled {
            std::task::Poll::Ready(None) => {
                if let Some(lease) = this.lease.take() {
                    lease.release();
                }
            }
            std::task::Poll::Ready(Some(Err(_))) => {
                this.lease = None;
            }
            std::task::Poll::Ready(Some(Ok(_))) if this.body.is_end_stream() => {
                if let Some(lease) = this.lease.take() {
                    lease.release();
                }
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl<B> Drop for Origin<B> {
    fn drop(&mut self) {
        let held = self.idle.get_mut().len();
        Self::count(&self.name, held, 0);
    }
}

impl<B> Origin<B> {
    /// Move this backend's idle count from `before` to `after`.
    fn count(name: &str, before: usize, after: usize) {
        use std::sync::atomic::Ordering;
        if before == after {
            return;
        }
        let gone = before.saturating_sub(after) as u64;
        let came = after.saturating_sub(before) as u64;
        if came > 0 {
            IDLE.entry(name.to_string())
                .or_default()
                .fetch_add(came, Ordering::Relaxed);
        } else if let Some(n) = IDLE.get(name) {
            let _ = n.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_sub(gone))
            });
        }
    }

    /// Return a connection, pruning any that have sat idle too long.
    fn put(&self, tx: http1::SendRequest<B>) {
        if !self.pooling || tx.is_closed() {
            return;
        }
        let now = Instant::now();
        let mut idle = self.idle.lock();
        let before = idle.len();
        while idle
            .front()
            .is_some_and(|c| now.duration_since(c.since) > self.idle_timeout)
        {
            idle.pop_front();
        }
        if idle.len() < self.max_idle {
            idle.push_back(Idle { tx, since: now });
        }
        Self::count(&self.name, before, idle.len());
    }

    /// The most recently returned connection that is still usable.
    fn take(&self) -> Option<http1::SendRequest<B>> {
        let now = Instant::now();
        let mut idle = self.idle.lock();
        let before = idle.len();
        let mut usable = None;
        while let Some(c) = idle.pop_back() {
            if !c.tx.is_closed() && now.duration_since(c.since) <= self.idle_timeout {
                usable = Some(c.tx);
                break;
            }
        }
        Self::count(&self.name, before, idle.len());
        usable
    }

    fn matches(&self, backend: &BackendConfig) -> bool {
        self.address == backend.address
            && Wire::of(backend).ok() == Some(self.wire)
            && self.unix.is_some() == (backend.backend_type == crate::config::BackendType::Unix)
            && self.tls.is_some() == (backend.wants_tls() && self.wire != Wire::Http3)
            && self.pooling != backend.disable_pooling
    }
}

impl<B> BackendClient<B>
where
    B: Body + Replay + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    pub fn new(idle_timeout: Duration, max_idle: usize, connect_timeout: Duration) -> Self {
        Self {
            origins: RwLock::new(HashMap::new()),
            idle_timeout,
            max_idle,
            connect_timeout,
        }
    }

    /// Send `req` to `backend` and return the response head with the lease on
    /// the connection it arrived on.
    ///
    /// `req`'s URI must be in origin form (`/path?query`): it is written to the
    /// request line as-is. A missing `Host` is filled in from the backend
    /// address.
    pub async fn send(
        &self,
        backend: &BackendConfig,
        req: http::Request<B>,
    ) -> anyhow::Result<(http::Response<BackendBody>, Lease<B>)> {
        self.attempt(backend, req)
            .await
            .map_err(|failed| failed.error)
    }

    /// [`Self::send`], again where the backend's retry policy
    /// (`retries`, `retry_backoff_ms`, `retry_on`; see [`RetryPolicy`]) and
    /// the request allow, each attempt held to `attempt_timeout`.
    ///
    /// A request that was never written (its connection could not be made)
    /// may go again whatever its method. One that was written goes again only
    /// when its method may be repeated (RFC 9110 section 9.2.2) and its body
    /// replayed: after a timeout, or a 5xx answer, where `retry_on` names them.
    pub async fn send_with_retry(
        &self,
        backend: &BackendConfig,
        req: http::Request<B>,
        attempt_timeout: Duration,
    ) -> Result<(http::Response<BackendBody>, Lease<B>), SendError> {
        let policy = RetryPolicy::of(backend);
        let mut req = req;
        let mut attempt: u8 = 0;
        loop {
            let copy = replayable(&req);
            let again = attempt < policy.retries;
            let next = match tokio::time::timeout(attempt_timeout, self.attempt(backend, req)).await
            {
                Ok(Ok((resp, lease))) => {
                    match copy.filter(|_| again && policy.on_5xx && resp.status().is_server_error())
                    {
                        Some(copy) => {
                            debug!(
                                "backend {} answered {}; sending again ({} of {})",
                                backend.name,
                                resp.status(),
                                attempt + 1,
                                policy.retries
                            );
                            // The exchange is abandoned: its connection closes.
                            drop((resp, lease));
                            copy
                        }
                        None => return Ok((resp, lease)),
                    }
                }
                Ok(Err(failed)) => {
                    match failed.unsent.filter(|_| again && policy.on_connect_failure) {
                        Some(unsent) => {
                            debug!(
                                "backend {}: {}; sending again ({} of {})",
                                backend.name,
                                failed.error,
                                attempt + 1,
                                policy.retries
                            );
                            *unsent
                        }
                        None => return Err(SendError::Failed(failed.error)),
                    }
                }
                Err(_) => {
                    self.timed_out(backend);
                    match copy.filter(|_| again && policy.on_timeout) {
                        Some(copy) => {
                            debug!(
                                "backend {} did not answer in {}ms; sending again ({} of {})",
                                backend.name,
                                attempt_timeout.as_millis(),
                                attempt + 1,
                                policy.retries
                            );
                            copy
                        }
                        None => return Err(SendError::TimedOut(attempt_timeout)),
                    }
                }
            };
            tokio::time::sleep(policy.backoff * (1u32 << attempt.min(9))).await;
            attempt += 1;
            req = next;
        }
    }

    /// One attempt at [`Self::send`]. A request that was not written comes
    /// back with the failure, to be sent again.
    async fn attempt(
        &self,
        backend: &BackendConfig,
        req: http::Request<B>,
    ) -> Result<(http::Response<BackendBody>, Lease<B>), Failed<B>> {
        let started = Instant::now();
        let outcome = self.exchange(backend, req).await;
        if let Some(metrics) = METRICS.get() {
            match &outcome {
                Ok(_) => metrics
                    .pools
                    .record_latency(&backend.name, started.elapsed()),
                Err(_) => metrics.pools.connection_error(&backend.name),
            }
        }
        outcome
    }

    /// An exchange with `backend` that did not finish in its time (the caller
    /// held it to that time and dropped it).
    pub fn timed_out(&self, backend: &BackendConfig) {
        if let Some(metrics) = METRICS.get() {
            metrics.pools.connection_error(&backend.name);
        }
    }

    /// The exchange [`Self::attempt`] times.
    async fn exchange(
        &self,
        backend: &BackendConfig,
        mut req: http::Request<B>,
    ) -> Result<(http::Response<BackendBody>, Lease<B>), Failed<B>> {
        // A place under the backend's limit, for every transport, held by the
        // lease until the exchange is complete (crate::backend_limits). A
        // request without one waited its time already: it is not sent again.
        let place = match crate::backend_limits::acquire(backend).await {
            Ok(place) => place,
            Err(error) => {
                return Err(Failed {
                    error,
                    unsent: None,
                })
            }
        };
        let origin = match self.origin(backend) {
            Ok(origin) => origin,
            Err(error) => {
                return Err(Failed {
                    error,
                    unsent: None,
                })
            }
        };
        if !req.headers().contains_key(http::header::HOST) {
            // A Unix backend's address is a path, not an authority
            let host = if origin.unix.is_some() {
                "localhost"
            } else {
                backend.address.as_str()
            };
            if let Ok(v) = http::HeaderValue::from_str(host) {
                req.headers_mut().insert(http::header::HOST, v);
            }
        }
        match origin.wire {
            Wire::Http1 => {}
            Wire::Http2 => return self.exchange_h2(origin, req, place).await,
            Wire::Http3 => return self.exchange_h3(origin, req, place).await,
        }

        // Reused connections first. A request hyper could not put on one comes
        // back unsent and goes to the next.
        while let Some(mut tx) = origin.take() {
            match tokio::time::timeout(self.connect_timeout, tx.ready()).await {
                Ok(Ok(())) => {}
                _ => continue,
            }
            let again = replayable(&req);
            match tx.try_send_request(req).await {
                Ok(resp) => {
                    return Ok((
                        resp.map(BackendBody::Hyper),
                        Lease {
                            tx: Some(tx),
                            origin,
                            _place: place,
                        },
                    ))
                }
                Err(mut e) => match e.take_message() {
                    Some(unsent) => {
                        debug!(
                            "backend {}: reused connection closed, retrying",
                            backend.name
                        );
                        req = unsent;
                    }
                    None => {
                        let error = e.into_error();
                        match again {
                            // Written, then the connection closed with no
                            // answer: the backend's keep-alive timeout won
                            // the race. Safe to repeat on another.
                            Some(copy) if error.is_incomplete_message() => {
                                debug!(
                                    "backend {}: reused connection closed before answering, sending again",
                                    backend.name
                                );
                                req = copy;
                            }
                            _ => {
                                return Err(Failed {
                                    error: error.into(),
                                    unsent: None,
                                })
                            }
                        }
                    }
                },
            }
        }

        // Boxed: a new connection is the rare case, and its future — TCP
        // connect, TLS handshake, HTTP/1.1 handshake — is most of this
        // function's size. Inline, every request's state machine carried room
        // for it and was copied with it on every spawn.
        let mut tx = match Box::pin(self.connect(&origin)).await {
            Ok(tx) => tx,
            Err(error) => {
                return Err(Failed {
                    error,
                    unsent: Some(Box::new(req)),
                })
            }
        };
        match tx.try_send_request(req).await {
            Ok(resp) => Ok((
                resp.map(BackendBody::Hyper),
                Lease {
                    tx: Some(tx),
                    origin,
                    _place: place,
                },
            )),
            Err(mut e) => {
                let unsent = e.take_message().map(Box::new);
                Err(Failed {
                    error: e.into_error().into(),
                    unsent,
                })
            }
        }
    }

    /// The pool for `backend`, created on first use and rebuilt if the
    /// backend's address or transport has changed under the same name.
    fn origin(&self, backend: &BackendConfig) -> anyhow::Result<Arc<Origin<B>>> {
        if let Some(o) = self.origins.read().get(&backend.name) {
            if o.matches(backend) {
                return Ok(o.clone());
            }
        }
        let wire = Wire::of(backend)?;
        let unix = (backend.backend_type == crate::config::BackendType::Unix).then(|| {
            std::path::PathBuf::from(
                backend
                    .address
                    .strip_prefix("unix:")
                    .unwrap_or(&backend.address),
            )
        });
        let quic = if wire == Wire::Http3 {
            let tls = crate::http_listener::backend_client_config(backend, vec![b"h3".to_vec()])
                .map_err(|e| anyhow::anyhow!("backend {} TLS setup: {e}", backend.name))?;
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| anyhow::anyhow!("backend {} QUIC setup: {e}", backend.name))?;
            let name = backend
                .tls_sni
                .clone()
                .unwrap_or_else(|| host_of(&backend.address).to_string());
            Some((quinn::ClientConfig::new(Arc::new(crypto)), name))
        } else {
            None
        };
        let tls = if backend.wants_tls() && wire != Wire::Http3 && unix.is_none() {
            let connector = crate::http_listener::create_backend_tls_connector(backend)
                .map_err(|e| anyhow::anyhow!("backend {} TLS setup: {e}", backend.name))?;
            let host = match &backend.tls_sni {
                Some(sni) => sni.clone(),
                None => host_of(&backend.address).to_string(),
            };
            let name = rustls::pki_types::ServerName::try_from(host)
                .map_err(|e| anyhow::anyhow!("backend {} server name: {e}", backend.name))?;
            Some((connector, name))
        } else {
            None
        };
        let origin = Arc::new(Origin {
            name: backend.name.clone(),
            address: backend.address.clone(),
            wire,
            unix,
            quic,
            multiplexed: tokio::sync::Mutex::new(None),
            tls,
            idle: Mutex::new(VecDeque::new()),
            idle_timeout: self.idle_timeout,
            max_idle: self.max_idle,
            pooling: !backend.disable_pooling,
        });
        self.origins
            .write()
            .insert(backend.name.clone(), origin.clone());
        Ok(origin)
    }

    async fn connect(&self, origin: &Origin<B>) -> anyhow::Result<http1::SendRequest<B>> {
        #[cfg(unix)]
        if let Some(path) = &origin.unix {
            let socket =
                tokio::time::timeout(self.connect_timeout, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| anyhow::anyhow!("connect to {} timed out", path.display()))??;
            let (tx, conn) = http1::handshake(TokioIo::new(socket)).await?;
            tokio::spawn(async move {
                if let Err(e) = conn.await {
                    debug!("backend connection ended: {e}");
                }
            });
            return Ok(tx);
        }
        #[cfg(not(unix))]
        if origin.unix.is_some() {
            return Err(anyhow::anyhow!("Unix socket backends need a Unix host"));
        }
        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(&origin.address))
            .await
            .map_err(|_| anyhow::anyhow!("connect to {} timed out", origin.address))??;
        // Nagle off: a proxied request is one small write followed by a wait
        // for the reply, the case Nagle serves worst.
        tcp.set_nodelay(true)?;
        match &origin.tls {
            Some((connector, name)) => {
                let tls = tokio::time::timeout(
                    self.connect_timeout,
                    connector.connect(name.clone(), tcp),
                )
                .await
                .map_err(|_| anyhow::anyhow!("TLS to {} timed out", origin.address))??;
                let (tx, conn) = http1::handshake(TokioIo::new(tls)).await?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("backend connection ended: {e}");
                    }
                });
                Ok(tx)
            }
            None => {
                let (tx, conn) = http1::handshake(TokioIo::new(tcp)).await?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("backend connection ended: {e}");
                    }
                });
                Ok(tx)
            }
        }
    }
}

impl<B> BackendClient<B>
where
    B: Body + Replay + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    /// An exchange on the origin's HTTP/2 connection (made, or made again
    /// when it has closed).
    async fn exchange_h2(
        &self,
        origin: Arc<Origin<B>>,
        req: http::Request<B>,
        place: crate::backend_limits::Place,
    ) -> Result<(http::Response<BackendBody>, Lease<B>), Failed<B>> {
        let req = multiplexed_form(req, origin.tls.is_some(), http::Version::HTTP_2);
        let mut tx = match self.h2_sender(&origin).await {
            Ok(tx) => tx,
            Err(error) => {
                return Err(Failed {
                    error,
                    unsent: Some(Box::new(req)),
                })
            }
        };
        if let Err(error) = tx.ready().await {
            return Err(Failed {
                error: error.into(),
                unsent: Some(Box::new(req)),
            });
        }
        match tx.try_send_request(req).await {
            Ok(resp) => Ok((
                resp.map(BackendBody::Hyper),
                Lease {
                    tx: None,
                    origin,
                    _place: place,
                },
            )),
            Err(mut e) => {
                let unsent = e.take_message().map(Box::new);
                Err(Failed {
                    error: e.into_error().into(),
                    unsent,
                })
            }
        }
    }

    async fn h2_sender(&self, origin: &Origin<B>) -> anyhow::Result<http2::SendRequest<B>> {
        let mut shared = origin.multiplexed.lock().await;
        if let Some(Multiplexed::H2(tx)) = shared.as_ref() {
            if !tx.is_closed() {
                return Ok(tx.clone());
            }
        }
        let tx = Box::pin(self.connect_h2(origin)).await?;
        *shared = Some(Multiplexed::H2(tx.clone()));
        Ok(tx)
    }

    async fn connect_h2(&self, origin: &Origin<B>) -> anyhow::Result<http2::SendRequest<B>> {
        let tcp = tokio::time::timeout(self.connect_timeout, TcpStream::connect(&origin.address))
            .await
            .map_err(|_| anyhow::anyhow!("connect to {} timed out", origin.address))??;
        tcp.set_nodelay(true)?;
        let exec = TokioExecutor::new();
        match &origin.tls {
            Some((connector, name)) => {
                let tls = tokio::time::timeout(
                    self.connect_timeout,
                    connector.connect(name.clone(), tcp),
                )
                .await
                .map_err(|_| anyhow::anyhow!("TLS to {} timed out", origin.address))??;
                if tls.get_ref().1.alpn_protocol() != Some(&b"h2"[..]) {
                    return Err(anyhow::anyhow!(
                        "{} did not agree to HTTP/2 (ALPN h2)",
                        origin.address
                    ));
                }
                let (tx, conn) = http2::handshake(exec, TokioIo::new(tls)).await?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("backend HTTP/2 connection ended: {e}");
                    }
                });
                Ok(tx)
            }
            // Cleartext: HTTP/2 with prior knowledge (RFC 9113 section 3.3)
            None => {
                let (tx, conn) = http2::handshake(exec, TokioIo::new(tcp)).await?;
                tokio::spawn(async move {
                    if let Err(e) = conn.await {
                        debug!("backend HTTP/2 connection ended: {e}");
                    }
                });
                Ok(tx)
            }
        }
    }

    /// An exchange on the origin's HTTP/3 connection: the request body is
    /// sent from its own task while the response is read, so neither waits
    /// for the other.
    async fn exchange_h3(
        &self,
        origin: Arc<Origin<B>>,
        req: http::Request<B>,
        place: crate::backend_limits::Place,
    ) -> Result<(http::Response<BackendBody>, Lease<B>), Failed<B>> {
        let req = multiplexed_form(req, true, http::Version::HTTP_3);
        let mut send = match self.h3_sender(&origin).await {
            Ok(send) => send,
            Err(error) => {
                return Err(Failed {
                    error,
                    unsent: Some(Box::new(req)),
                })
            }
        };
        let (parts, body) = req.into_parts();
        let stream = match send
            .send_request(http::Request::from_parts(parts, ()))
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                return Err(Failed {
                    error: anyhow::anyhow!("HTTP/3 request to {}: {e}", origin.address),
                    unsent: None,
                })
            }
        };
        let (mut request_side, mut response_side) = stream.split();
        let upload = tokio::spawn(async move {
            let mut body = Box::pin(body);
            loop {
                let frame = match http_body_util::BodyExt::frame(&mut body).await {
                    Some(Ok(frame)) => frame,
                    Some(Err(e)) => {
                        debug!("request body for an HTTP/3 backend failed: {}", e.into());
                        request_side.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                        return;
                    }
                    None => break,
                };
                let sent = match frame.into_data() {
                    Ok(mut data) => {
                        let bytes = data.copy_to_bytes(data.remaining());
                        if bytes.is_empty() {
                            Ok(())
                        } else {
                            request_side.send_data(bytes).await
                        }
                    }
                    Err(frame) => match frame.into_trailers() {
                        Ok(trailers) => request_side.send_trailers(trailers).await,
                        Err(_) => Ok(()),
                    },
                };
                if sent.is_err() {
                    return;
                }
            }
            let _ = request_side.finish().await;
        });
        match response_side.recv_response().await {
            Ok(resp) => Ok((
                resp.map(|()| {
                    BackendBody::H3(H3Body {
                        recv: response_side,
                        data_done: false,
                        done: false,
                        upload,
                    })
                }),
                Lease {
                    tx: None,
                    origin,
                    _place: place,
                },
            )),
            Err(e) => {
                upload.abort();
                Err(Failed {
                    error: anyhow::anyhow!("HTTP/3 response from {}: {e}", origin.address),
                    unsent: None,
                })
            }
        }
    }

    async fn h3_sender(
        &self,
        origin: &Origin<B>,
    ) -> anyhow::Result<h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>> {
        let mut shared = origin.multiplexed.lock().await;
        if let Some(Multiplexed::H3 {
            send, connection, ..
        }) = shared.as_ref()
        {
            if connection.close_reason().is_none() {
                return Ok(send.clone());
            }
        }
        let (send, connection, endpoint) = Box::pin(self.connect_h3(origin)).await?;
        *shared = Some(Multiplexed::H3 {
            send: send.clone(),
            connection,
            _endpoint: endpoint,
        });
        Ok(send)
    }

    async fn connect_h3(
        &self,
        origin: &Origin<B>,
    ) -> anyhow::Result<(
        h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        quinn::Connection,
        quinn::Endpoint,
    )> {
        let (config, server_name) = origin
            .quic
            .clone()
            .ok_or_else(|| anyhow::anyhow!("{} has no QUIC configuration", origin.address))?;
        let target = tokio::net::lookup_host(&origin.address)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("{} resolves to no address", origin.address))?;
        let bind: std::net::SocketAddr = if target.is_ipv6() {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(bind)?;
        let connection = tokio::time::timeout(
            self.connect_timeout,
            endpoint.connect_with(config, target, &server_name)?,
        )
        .await
        .map_err(|_| anyhow::anyhow!("QUIC to {} timed out", origin.address))??;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|e| anyhow::anyhow!("HTTP/3 to {}: {e}", origin.address))?;
        tokio::spawn(async move {
            let e = driver.wait_idle().await;
            debug!("backend HTTP/3 connection ended: {e}");
        });
        Ok((send, connection, endpoint))
    }
}

/// `req` as HTTP/2 and HTTP/3 carry it: an absolute URI (scheme, the `Host`
/// as authority, the path and query), and none of the fields those versions
/// forbid (RFC 9113 section 8.2.2, RFC 9114 section 4.2).
fn multiplexed_form<B>(
    mut req: http::Request<B>,
    https: bool,
    version: http::Version,
) -> http::Request<B> {
    use http::header;
    let authority = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
    if let Some(authority) = authority {
        if let Ok(uri) = http::Uri::builder()
            .scheme(if https { "https" } else { "http" })
            .authority(authority)
            .path_and_query(path)
            .build()
        {
            *req.uri_mut() = uri;
        }
    }
    let headers = req.headers_mut();
    for name in [
        header::HOST,
        header::CONNECTION,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        header::HeaderName::from_static("keep-alive"),
        header::HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
    if headers
        .get(header::TE)
        .is_some_and(|te| te.as_bytes() != b"trailers")
    {
        headers.remove(header::TE);
    }
    *req.version_mut() = version;
    req
}

/// `host` of `host:port`, `[v6]:port` or a bare host.
fn host_of(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match address.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => address,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn host_of_handles_ports_and_brackets() {
        assert_eq!(host_of("127.0.0.1:8080"), "127.0.0.1");
        assert_eq!(host_of("[::1]:443"), "::1");
        assert_eq!(host_of("backend.internal"), "backend.internal");
        assert_eq!(host_of("backend.internal:9000"), "backend.internal");
    }

    fn backend(address: &str) -> BackendConfig {
        toml::from_str(&format!(
            "name = \"t\"\ntype = \"http1\"\naddress = \"{address}\"\n"
        ))
        .unwrap()
    }

    /// A keep-alive HTTP/1.1 server that counts the connections it accepts
    /// and answers every request with `ok`; `close_after` closes a connection
    /// after that many requests without saying so.
    async fn server(close_after: usize) -> (String, Arc<AtomicUsize>) {
        server_with(
            close_after,
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok",
        )
        .await
    }

    async fn server_with(
        close_after: usize,
        response: &'static [u8],
    ) -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let mut served = 0;
                    loop {
                        let mut got = Vec::new();
                        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => got.extend_from_slice(&buf[..n]),
                            }
                        }
                        let _ = s.write_all(response).await;
                        served += 1;
                        if served == close_after {
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepted)
    }

    fn get() -> http::Request<Full<Bytes>> {
        http::Request::builder()
            .uri("/x")
            .body(Full::new(Bytes::new()))
            .unwrap()
    }

    /// A 5xx is answered again only where `retry_on` asks and the method may
    /// be repeated; a connection that cannot be made is tried again for any
    /// method, since nothing was sent.
    #[tokio::test]
    async fn requests_go_again_as_the_backend_policy_and_the_method_allow() {
        let unavailable: &'static [u8] =
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n";
        let (addr, accepted) = server_with(usize::MAX, unavailable).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let mut b = backend(&addr);
        b.retries = Some(2);
        b.retry_backoff_ms = Some(1);
        b.retry_on = Some(vec!["5xx".into()]);
        let (resp, _lease) = client
            .send_with_retry(&b, get(), Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(resp.status(), 503, "the last answer, after every attempt");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            3,
            "a new connection per attempt"
        );

        let post = http::Request::builder()
            .method("POST")
            .uri("/x")
            .body(Full::new(Bytes::from_static(b"once")))
            .unwrap();
        let before = accepted.load(Ordering::SeqCst);
        let (resp, _lease) = client
            .send_with_retry(&b, post, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            before + 1,
            "a POST is sent once"
        );

        // Nothing listens: each attempt fails to connect, so each is retried
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gone = closed.local_addr().unwrap().to_string();
        drop(closed);
        let mut b = backend(&gone);
        b.retries = Some(1);
        b.retry_backoff_ms = Some(1);
        let started = std::time::Instant::now();
        let failed = client
            .send_with_retry(&b, get(), Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(failed, SendError::Failed(_)), "{failed}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_released_connection_is_reused() {
        let (addr, accepted) = server(usize::MAX).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..5 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");
            lease.release();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unreleased_connection_is_not_reused() {
        let (addr, accepted) = server(usize::MAX).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..3 {
            let (resp, _lease) = client.send(&b, get()).await.unwrap();
            let _ = resp.into_body().collect().await.unwrap();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_body_read_to_its_length_releases_through_the_wrapper() {
        // Read exactly as a length-aware server does: stop at is_end_stream
        // without polling for the final None.
        let (addr, accepted) = server(usize::MAX).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..3 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            let mut body = ReleaseOnEnd::new(resp.into_body(), lease);
            let mut got = Vec::new();
            while !body.is_end_stream() {
                match std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)).await
                {
                    Some(Ok(f)) => got.extend_from_slice(f.data_ref().unwrap()),
                    _ => break,
                }
            }
            assert_eq!(got, b"ok");
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    /// The case hyper's server produces for an empty response: the body is
    /// never polled at all, only dropped.
    #[tokio::test]
    async fn an_empty_body_dropped_unpolled_releases() {
        let (addr, accepted) = server_with(usize::MAX, b"HTTP/1.1 204 No Content\r\n\r\n").await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..4 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            let body = ReleaseOnEnd::new(resp.into_body(), lease);
            assert!(body.is_end_stream());
            drop(body);
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    /// A body abandoned part-way closes its connection rather than returning
    /// one with unread bytes on it.
    #[tokio::test]
    async fn a_body_dropped_part_way_is_not_released() {
        let (addr, accepted) = server(usize::MAX).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..3 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            drop(ReleaseOnEnd::new(resp.into_body(), lease));
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn disable_pooling_opens_a_connection_per_request() {
        let (addr, accepted) = server(usize::MAX).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let mut b = backend(&addr);
        b.disable_pooling = true;
        for _ in 0..3 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            let _ = resp.into_body().collect().await.unwrap();
            lease.release();
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 3);
    }

    /// A server that answers a connection's first request and, on the second,
    /// reads it and closes without answering: a keep-alive timeout firing
    /// just as the request arrives.
    async fn closes_on_second_request() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    for n in 0.. {
                        let mut got = Vec::new();
                        while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                            match s.read(&mut buf).await {
                                Ok(0) | Err(_) => return,
                                Ok(k) => got.extend_from_slice(&buf[..k]),
                            }
                        }
                        if n == 1 {
                            return; // read, then closed: no answer
                        }
                        if s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });
        (addr, accepted)
    }

    #[tokio::test]
    async fn an_idempotent_request_on_a_connection_closed_unanswered_goes_again() {
        let (addr, accepted) = closes_on_second_request().await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        let (resp, lease) = client.send(&b, get()).await.unwrap();
        resp.into_body().collect().await.unwrap();
        lease.release();
        // Reuses the connection, which closes unanswered; sent again on a new one.
        let (resp, lease) = client.send(&b, get()).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
        lease.release();
        assert_eq!(accepted.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_post_on_a_connection_closed_unanswered_is_not_repeated() {
        let (addr, accepted) = closes_on_second_request().await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        let (resp, lease) = client.send(&b, get()).await.unwrap();
        resp.into_body().collect().await.unwrap();
        lease.release();
        let post = http::Request::post("/")
            .body(Full::new(Bytes::from_static(b"once")))
            .unwrap();
        let Err(error) = client.send(&b, post).await else {
            panic!("a POST on a connection closed unanswered was sent again");
        };
        assert!(error.to_string().contains("connection closed"), "{error}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn only_repeatable_requests_with_replayable_bodies_are_copied() {
        let get = http::Request::get("/a")
            .header("x", "1")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let copy = replayable(&get).unwrap();
        assert_eq!(copy.uri(), "/a");
        assert_eq!(copy.headers()["x"], "1");
        let post = http::Request::post("/a")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert!(replayable(&post).is_none());
        let empty = http::Request::get("/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(replayable(&empty).is_some());
        let streamed = http::Request::put("/")
            .body(axum::body::Body::from_stream(futures::stream::iter(vec![
                Ok::<_, std::io::Error>(Bytes::from_static(b"x")),
            ])))
            .unwrap();
        assert!(replayable(&streamed).is_none());
    }

    #[tokio::test]
    async fn a_connection_closed_while_idle_is_replaced() {
        // The server closes each connection after one response, without a
        // `Connection: close`, so every pooled connection is dead by the time
        // it is reused. Each request must still succeed, on a new connection.
        let (addr, accepted) = server(1).await;
        let client = BackendClient::new(Duration::from_secs(60), 8, Duration::from_secs(5));
        let b = backend(&addr);
        for _ in 0..4 {
            let (resp, lease) = client.send(&b, get()).await.unwrap();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], b"ok");
            lease.release();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 4);
    }
}
