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

use axum::extract::connect_info::Connected;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, trace, warn};

use crate::config::FingerprintConfig;
use crate::fingerprint::{FingerprintExtractor, FingerprintResult};
use crate::security::SecurityState;

/// Maximum size to peek for ClientHello (typically < 1KB but can be up to 16KB with extensions)
const MAX_CLIENT_HELLO_SIZE: usize = 4096;

/// Connection info with fingerprint data
#[derive(Clone, Debug)]
pub struct FingerprintedConnection {
    pub remote_addr: SocketAddr,
    pub ja3_hash: Option<String>,
    pub ja4_hash: Option<String>,
    pub client_name: Option<String>,
    pub is_browser: bool,
}

impl Connected<&FingerprintedTlsStream<TlsStream<TcpStream>>> for FingerprintedConnection {
    fn connect_info(target: &FingerprintedTlsStream<TlsStream<TcpStream>>) -> Self {
        target.conn_info.clone()
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
}

impl FingerprintingTlsAcceptor {
    pub fn new(
        config: Arc<rustls::ServerConfig>,
        fingerprint_extractor: Arc<FingerprintExtractor>,
        security_state: SecurityState,
        fingerprint_config: FingerprintConfig,
    ) -> Self {
        Self {
            tls_acceptor: tokio_rustls::TlsAcceptor::from(config),
            fingerprint_extractor,
            security_state,
            fingerprint_config,
        }
    }

    /// Accept a TLS connection with fingerprint capture
    pub async fn accept(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) -> io::Result<Option<FingerprintedTlsStream<TlsStream<TcpStream>>>> {
        // Peek at the ClientHello before TLS handshake
        let mut peek_buf = vec![0u8; MAX_CLIENT_HELLO_SIZE];
        let peek_result = stream.peek(&mut peek_buf).await;

        let fingerprint_result = match peek_result {
            Ok(n) if n > 0 => {
                trace!("Peeked {} bytes of ClientHello from {}", n, remote_addr);
                self.fingerprint_extractor.process_client_hello(
                    &peek_buf[..n],
                    remote_addr.ip(),
                    &self.security_state,
                    &self.fingerprint_config,
                )
            }
            Ok(_) => {
                debug!("Empty peek from {}", remote_addr);
                FingerprintResult {
                    allowed: true,
                    ja3_hash: None,
                    ja4_hash: None,
                    classification: None,
                    client_name: None,
                }
            }
            Err(e) => {
                debug!("Failed to peek ClientHello from {}: {}", remote_addr, e);
                FingerprintResult {
                    allowed: true,
                    ja3_hash: None,
                    ja4_hash: None,
                    classification: None,
                    client_name: None,
                }
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

        // Perform TLS handshake
        let tls_stream = self.tls_acceptor.accept(stream).await.map_err(|e| {
            debug!("TLS handshake failed for {}: {}", remote_addr, e);
            io::Error::new(io::ErrorKind::ConnectionAborted, e)
        })?;

        // Create connection info
        let is_browser = fingerprint_result
            .classification
            .as_ref()
            .map(|c| matches!(c, crate::security::FingerprintClass::Browser))
            .unwrap_or(false);

        let conn_info = FingerprintedConnection {
            remote_addr,
            ja3_hash: fingerprint_result.ja3_hash,
            ja4_hash: fingerprint_result.ja4_hash,
            client_name: fingerprint_result.client_name,
            is_browser,
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

    #[test]
    fn test_fingerprinted_connection() {
        let conn = FingerprintedConnection {
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            ja3_hash: Some("abc123".to_string()),
            ja4_hash: Some("t13d0102h2_def456_ghi789".to_string()),
            client_name: Some("Chrome".to_string()),
            is_browser: true,
        };

        assert_eq!(conn.ja3_hash(), Some("abc123"));
        assert!(conn.is_browser());
    }
}
