//! rustls `ServerConfig` builders and PEM private-key loading for the TCP listeners.

/// Load a private key from a PEM file trying PKCS#8 then PKCS#1 formats.
// L-1: Uses rustls-pki-types PEM API (replaces unmaintained rustls-pemfile)
pub(super) fn load_private_key_from_pem(
    key_path: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
    use rustls_pki_types::pem::PemObject;
    use std::fs::File;
    use std::io::BufReader;

    // Try PKCS#8 first (modern format)
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Some(key) = PrivatePkcs8KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok()) {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
        }
    }
    // Try PKCS#1 (legacy RSA)
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Some(key) = PrivatePkcs1KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok()) {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
        }
    }
    Err(format!(
        "No private key found in {} (tried PKCS#8 and PKCS#1)",
        key_path
    )
    .into())
}

/// ALPN for a TCP listener: HTTP/2 and HTTP/1.1, or HTTP/1.1 alone for the
/// hosts in `http11_only_hosts`, so a browser opens independent connections per
/// `fetch()` rather than coalescing them onto one HTTP/2 pipe.
pub(super) const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
pub(super) const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// A per-domain SNI resolver over the directory `cert_path` sits in, loading
/// every `{domain}.crt` / `{domain}.key` pair, for a listener that is not given
/// the shared one.
pub(super) fn private_resolver(
    cert_path: &str,
) -> Result<
    std::sync::Arc<crate::tls::MultiDomainCertResolver>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    use std::path::Path;

    let certs_dir = Path::new(cert_path)
        .parent()
        .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));
    let resolver = crate::tls::MultiDomainCertResolver::new(certs_dir).map_err(|e| {
        format!(
            "Failed to build SNI cert resolver from {:?}: {}",
            certs_dir, e
        )
    })?;
    Ok(std::sync::Arc::new(resolver))
}

/// A rustls `ServerConfig` for a TCP listener.
///
/// Groups, protocol versions, client authentication and session tickets come
/// from `policy`, which the QUIC listener builds from too. These listeners used
/// `ServerConfig::builder()` -- rustls's crate defaults -- so `pqc.enabled`,
/// `tls.min_version`, `tls.require_client_cert` and `tls.pqc_session_tickets`
/// each had no effect here while taking effect on HTTP/3.
pub(super) fn build_rustls_server_config(
    policy: &crate::tls::ServerTlsPolicy,
    resolver: std::sync::Arc<crate::tls::MultiDomainCertResolver>,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = policy.builder()?.with_cert_resolver(resolver);
    policy.apply_tickets(&mut config)?;
    policy.apply_tcp_early_data(&mut config);
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.ech = crate::ech_config::load();
    crate::cert_compression::apply(&mut config);
    Ok(config)
}

/// The acceptor `axum_server` hands a rustls listener's connections to when
/// 0-RTT is on: the handshake runs on [`EarlyRustls`](crate::early_data::EarlyRustls),
/// which serves early data before it completes. With 0-RTT off the listener
/// keeps `axum_server`'s own acceptor.
#[derive(Clone)]
pub(super) struct EarlyRustlsAcceptor<A> {
    config: std::sync::Arc<rustls::ServerConfig>,
    inner: A,
    handshake_timeout: std::time::Duration,
    replay: crate::tls_acceptor::ZeroRttReplayGuard,
}

impl<A> EarlyRustlsAcceptor<A> {
    pub(super) fn new(
        config: std::sync::Arc<rustls::ServerConfig>,
        inner: A,
        handshake_timeout: std::time::Duration,
        replay: crate::tls_acceptor::ZeroRttReplayGuard,
    ) -> Self {
        Self {
            config,
            inner,
            handshake_timeout,
            replay,
        }
    }
}

fn handshake_timed_out() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, "TLS handshake timed out")
}

/// SEC-002: refuse a repeated ClientHello (or ticket) that offers early data,
/// as the fingerprinting listeners do, before any handshake work.
async fn refuse_replay(
    stream: &tokio::net::TcpStream,
    replay: &crate::tls_acceptor::ZeroRttReplayGuard,
) -> std::io::Result<()> {
    let mut hello = vec![0u8; 4096];
    let n = stream.peek(&mut hello).await?;
    if replay.is_replay(&hello[..n]) {
        tracing::warn!("0-RTT replay detected — rejecting early data");
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "0-RTT replay protection: duplicate early data rejected",
        ));
    }
    Ok(())
}

impl<A, S> axum_server::accept::Accept<tokio::net::TcpStream, S> for EarlyRustlsAcceptor<A>
where
    A: axum_server::accept::Accept<tokio::net::TcpStream, S, Stream = tokio::net::TcpStream>,
    A::Future: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = crate::early_data::EarlyRustls<tokio::net::TcpStream>;
    type Service = A::Service;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let inner = self.inner.accept(stream, service);
        let config = std::sync::Arc::clone(&self.config);
        let timeout = self.handshake_timeout;
        let replay = self.replay.clone();
        Box::pin(async move {
            let (stream, service) = inner.await?;
            let tls = tokio::time::timeout(timeout, async {
                refuse_replay(&stream, &replay).await?;
                crate::early_data::EarlyRustls::accept(config, stream, timeout).await
            })
            .await
            .map_err(|_| handshake_timed_out())??;
            Ok((tls, service))
        })
    }
}

/// The OpenSSL counterpart of [`EarlyRustlsAcceptor`]: accepts through
/// `SSL_read_early_data`, which OpenSSL requires of every connection once a
/// context allows early data.
#[cfg(feature = "pqc")]
#[derive(Clone)]
pub(super) struct EarlyOpensslAcceptor<A> {
    acceptor: std::sync::Arc<openssl::ssl::SslAcceptor>,
    inner: A,
    handshake_timeout: std::time::Duration,
    replay: crate::tls_acceptor::ZeroRttReplayGuard,
}

#[cfg(feature = "pqc")]
impl<A> EarlyOpensslAcceptor<A> {
    pub(super) fn new(
        acceptor: std::sync::Arc<openssl::ssl::SslAcceptor>,
        inner: A,
        handshake_timeout: std::time::Duration,
        replay: crate::tls_acceptor::ZeroRttReplayGuard,
    ) -> Self {
        Self {
            acceptor,
            inner,
            handshake_timeout,
            replay,
        }
    }
}

#[cfg(feature = "pqc")]
impl<A, S> axum_server::accept::Accept<tokio::net::TcpStream, S> for EarlyOpensslAcceptor<A>
where
    A: axum_server::accept::Accept<tokio::net::TcpStream, S, Stream = tokio::net::TcpStream>,
    A::Future: Send + 'static,
    A::Service: Send + 'static,
{
    type Stream = crate::early_data::EarlyOpenssl<tokio::net::TcpStream>;
    type Service = A::Service;
    type Future = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send,
        >,
    >;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let inner = self.inner.accept(stream, service);
        let acceptor = std::sync::Arc::clone(&self.acceptor);
        let timeout = self.handshake_timeout;
        let replay = self.replay.clone();
        Box::pin(async move {
            let (stream, service) = inner.await?;
            let ssl = openssl::ssl::Ssl::new(acceptor.context()).map_err(std::io::Error::other)?;
            let tls = tokio::time::timeout(timeout, async {
                refuse_replay(&stream, &replay).await?;
                crate::early_data::EarlyOpenssl::accept(ssl, stream, timeout).await
            })
            .await
            .map_err(|_| handshake_timed_out())??;
            Ok((tls, service))
        })
    }
}
