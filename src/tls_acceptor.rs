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
    /// SEC-002: True when the client offered TLS 1.3 early data (0-RTT) in its
    /// ClientHello AND the server has 0-RTT enabled.  Handlers must check the
    /// matched route's `allow_0rtt` flag and return 425 Too Early for
    /// non-idempotent routes to prevent replay attacks.
    pub is_early_data: bool,
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
    /// SEC-002: Whether the server has 0-RTT (early data) enabled.
    /// Used to set `FingerprintedConnection::is_early_data` only when the server
    /// would actually accept early data from a resumed session.
    zero_rtt_enabled: bool,
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
        }
    }

    /// SEC-002: Scan a raw ClientHello record for the TLS 1.3 `early_data`
    /// extension (type 0x002a, RFC 8446 §4.2.10).  Returns true if the client
    /// offered early data, regardless of whether the server will accept it.
    pub fn client_hello_has_early_data_extension(data: &[u8]) -> bool {
        // Minimum TLS record + ClientHello header: 5 (record) + 4 (handshake) = 9 bytes
        if data.len() < 9 {
            return false;
        }
        // Skip TLS record header (5 bytes) and handshake header (4 bytes)
        let client_hello = &data[9..];
        if client_hello.len() < 34 {
            return false;
        }
        // Skip legacy version (2) + random (32) = 34 bytes
        let mut offset = 34usize;

        // Session ID length
        if offset >= client_hello.len() {
            return false;
        }
        let session_id_len = client_hello[offset] as usize;
        offset = offset.saturating_add(1 + session_id_len);

        // Cipher suites length (2 bytes)
        if offset + 2 > client_hello.len() {
            return false;
        }
        let cipher_len =
            u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
        offset = offset.saturating_add(2 + cipher_len);

        // Compression methods length (1 byte)
        if offset >= client_hello.len() {
            return false;
        }
        let compression_len = client_hello[offset] as usize;
        offset = offset.saturating_add(1 + compression_len);

        // Extensions length (2 bytes)
        if offset + 2 > client_hello.len() {
            return false;
        }
        let ext_total =
            u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]) as usize;
        offset += 2;

        let ext_end = offset.saturating_add(ext_total);
        if ext_end > client_hello.len() {
            return false;
        }

        // Walk extensions looking for type 0x002a (early_data).
        while offset + 4 <= ext_end {
            let ext_type =
                u16::from_be_bytes([client_hello[offset], client_hello[offset + 1]]);
            let ext_len =
                u16::from_be_bytes([client_hello[offset + 2], client_hello[offset + 3]]) as usize;
            offset += 4;

            if ext_type == 0x002a {
                return true;
            }

            offset = offset.saturating_add(ext_len);
        }

        false
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
            is_early_data: offered_early_data,
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
            ext_bytes.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(ext_data);
        }
        let ext_len = ext_bytes.len() as u16;

        // ClientHello body
        let mut ch: Vec<u8> = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy version
        ch.extend_from_slice(&[0u8; 32]);    // random
        ch.push(0x00);                        // session ID length = 0
        ch.extend_from_slice(&[0x00, 0x02]); // cipher suites length = 2
        ch.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        ch.push(0x01);                        // compression methods length = 1
        ch.push(0x00);                        // null compression
        ch.extend_from_slice(&ext_len.to_be_bytes());
        ch.extend_from_slice(&ext_bytes);

        // Handshake header: type=0x01 (ClientHello) + 3-byte length
        let ch_len = ch.len() as u32;
        let mut hs: Vec<u8> = Vec::new();
        hs.push(0x01);
        hs.push(((ch_len >> 16) & 0xff) as u8);
        hs.push(((ch_len >> 8) & 0xff) as u8);
        hs.push((ch_len & 0xff) as u8);
        hs.extend_from_slice(&ch);

        // TLS record header: content type 0x16, version 0x0301, 2-byte length
        let hs_len = hs.len() as u16;
        let mut record: Vec<u8> = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
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
            let list_len = (name.len() + 3) as u16;
            v.extend_from_slice(&list_len.to_be_bytes()); // list length
            v.push(0x00);                                  // host_name type
            v.extend_from_slice(&(name.len() as u16).to_be_bytes());
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

    #[test]
    fn test_fingerprinted_connection() {
        let conn = FingerprintedConnection {
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            ja3_hash: Some("abc123".to_string()),
            ja4_hash: Some("t13d0102h2_def456_ghi789".to_string()),
            client_name: Some("Chrome".to_string()),
            is_browser: true,
            is_early_data: false,
        };

        assert_eq!(conn.ja3_hash(), Some("abc123"));
        assert!(conn.is_browser());
    }
}
