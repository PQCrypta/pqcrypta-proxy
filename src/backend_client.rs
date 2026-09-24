//! HTTP/1.1 connections to backends, pooled per backend.
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
//! It also gives backend TLS a real implementation: a backend with
//! `tls = true` connects through [`create_backend_tls_connector`], so its CA,
//! client certificate, SNI and verification settings apply.
//!
//! [`create_backend_tls_connector`]: crate::http_listener::create_backend_tls_connector

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use parking_lot::{Mutex, RwLock};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::BackendConfig;

/// Pooled HTTP/1.1 client for one proxy's backends.
pub struct BackendClient<B> {
    origins: RwLock<HashMap<String, Arc<Origin<B>>>>,
    idle_timeout: Duration,
    max_idle: usize,
    connect_timeout: Duration,
}

/// One backend: where it is, how to reach it, and its idle connections.
struct Origin<B> {
    address: String,
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

/// A connection carrying one exchange.
///
/// [`release`](Self::release) it once the response body has been read to its
/// end; dropping it instead closes the connection, which is right when the
/// exchange was abandoned part-way.
pub struct Lease<B> {
    tx: Option<http1::SendRequest<B>>,
    origin: Arc<Origin<B>>,
}

impl<B> Lease<B> {
    /// The exchange is complete: the connection can carry another request.
    pub fn release(mut self) {
        if let Some(tx) = self.tx.take() {
            self.origin.put(tx);
        }
    }
}

impl<B> Origin<B> {
    /// Return a connection, pruning any that have sat idle too long.
    fn put(&self, tx: http1::SendRequest<B>) {
        if !self.pooling || tx.is_closed() {
            return;
        }
        let now = Instant::now();
        let mut idle = self.idle.lock();
        while idle
            .front()
            .is_some_and(|c| now.duration_since(c.since) > self.idle_timeout)
        {
            idle.pop_front();
        }
        if idle.len() < self.max_idle {
            idle.push_back(Idle { tx, since: now });
        }
    }

    /// The most recently returned connection that is still usable.
    fn take(&self) -> Option<http1::SendRequest<B>> {
        let now = Instant::now();
        let mut idle = self.idle.lock();
        while let Some(c) = idle.pop_back() {
            if !c.tx.is_closed() && now.duration_since(c.since) <= self.idle_timeout {
                return Some(c.tx);
            }
        }
        None
    }

    fn matches(&self, backend: &BackendConfig) -> bool {
        self.address == backend.address
            && self.tls.is_some() == backend.tls
            && self.pooling != backend.disable_pooling
    }
}

impl<B> BackendClient<B>
where
    B: Body + Send + 'static,
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
        mut req: http::Request<B>,
    ) -> anyhow::Result<(http::Response<Incoming>, Lease<B>)> {
        let origin = self.origin(backend)?;
        if !req.headers().contains_key(http::header::HOST) {
            if let Ok(v) = http::HeaderValue::from_str(&backend.address) {
                req.headers_mut().insert(http::header::HOST, v);
            }
        }

        // Reused connections first. A request hyper could not put on one comes
        // back unsent and goes to the next.
        while let Some(mut tx) = origin.take() {
            match tokio::time::timeout(self.connect_timeout, tx.ready()).await {
                Ok(Ok(())) => {}
                _ => continue,
            }
            match tx.try_send_request(req).await {
                Ok(resp) => {
                    return Ok((
                        resp,
                        Lease {
                            tx: Some(tx),
                            origin,
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
                    None => return Err(e.into_error().into()),
                },
            }
        }

        // Boxed: a new connection is the rare case, and its future — TCP
        // connect, TLS handshake, HTTP/1.1 handshake — is most of this
        // function's size. Inline, every request's state machine carried room
        // for it and was copied with it on every spawn.
        let mut tx = Box::pin(self.connect(&origin)).await?;
        let resp = tx.send_request(req).await?;
        Ok((
            resp,
            Lease {
                tx: Some(tx),
                origin,
            },
        ))
    }

    /// The pool for `backend`, created on first use and rebuilt if the
    /// backend's address or transport has changed under the same name.
    fn origin(&self, backend: &BackendConfig) -> anyhow::Result<Arc<Origin<B>>> {
        if let Some(o) = self.origins.read().get(&backend.name) {
            if o.matches(backend) {
                return Ok(o.clone());
            }
        }
        let tls = if backend.tls {
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
            address: backend.address.clone(),
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
                        let _ = s
                            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                            .await;
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
