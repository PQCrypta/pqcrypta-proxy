//! TLS passthrough.
//!
//! A connection whose ClientHello names a passthrough route
//! (`passthrough_routes`, by SNI; `*.example.com` covers its subdomains and
//! itself) is relayed to that route's backend still encrypted.
//!
//! It is a switch inside every TCP listener's own accept path, after the
//! connection has been admitted (connection limits, block list) and its whole
//! ClientHello peeked within the handshake time: a separate listener on the
//! same port could not bind it. The peeked bytes are still in the socket, so
//! the backend receives the ClientHello as the client sent it. A relay ends
//! when either side does, after `idle` with nothing moving either way, or at
//! shutdown.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::{PassthroughRoute, ProxyConfig};
use crate::metrics::{ConnectionProtocol, MetricsRegistry};

use super::proxy_protocol::send_proxy_v2_header;

/// The passthrough routes, as last loaded or reloaded
static ROUTES: LazyLock<ArcSwap<Vec<PassthroughRoute>>> =
    LazyLock::new(|| ArcSwap::from_pointee(Vec::new()));

/// Where relays are counted, and the signal that the process is shutting down
static RUNTIME: std::sync::OnceLock<(Arc<MetricsRegistry>, watch::Receiver<()>)> =
    std::sync::OnceLock::new();

/// Count relays in `metrics` and end them when `shutdown` fires (once, at
/// startup).
pub fn init(metrics: Arc<MetricsRegistry>, shutdown: watch::Receiver<()>) {
    let _ = RUNTIME.set((metrics, shutdown));
}

/// Take `passthrough_routes`, at startup and on every reload.
pub fn configure(config: &ProxyConfig) {
    for route in &config.passthrough_routes {
        info!("🔀 TLS passthrough: {} → {}", route.sni, route.backend);
    }
    ROUTES.store(Arc::new(config.passthrough_routes.clone()));
}

/// Whether any passthrough route is configured (a listener that does not
/// peek the ClientHello otherwise need not, then).
pub fn active() -> bool {
    !ROUTES.load().is_empty()
}

/// The route for a ClientHello naming `sni`.
fn route_for(sni: &str) -> Option<PassthroughRoute> {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    ROUTES
        .load()
        .iter()
        .find(|route| {
            let pattern = route.sni.to_ascii_lowercase();
            match pattern.strip_prefix("*.") {
                Some(base) => sni == base || sni.ends_with(&format!(".{base}")),
                None => pattern == sni,
            }
        })
        .cloned()
}

/// When the ClientHello in `peeked` names a passthrough route, relay the
/// connection there and return None once the relay ends; otherwise give the
/// stream back to be served.
pub(crate) async fn divert(
    stream: TcpStream,
    peeked: &[u8],
    client: SocketAddr,
    idle: Duration,
) -> Option<TcpStream> {
    if !active() {
        return Some(stream);
    }
    let Some(route) =
        crate::tls_acceptor::client_hello_server_name(peeked).and_then(|sni| route_for(&sni))
    else {
        return Some(stream);
    };
    let Some((metrics, shutdown)) = RUNTIME.get() else {
        return Some(stream);
    };
    relay(stream, &route, client, metrics, idle, shutdown.clone()).await;
    None
}

/// [`divert`] for a listener that has not peeked the ClientHello: peek it
/// whole (within `deadline`), then divert.
pub(crate) async fn peek_and_divert(
    stream: TcpStream,
    client: SocketAddr,
    idle: Duration,
    deadline: tokio::time::Instant,
) -> Option<TcpStream> {
    if !active() {
        return Some(stream);
    }
    let mut peeked = vec![0u8; 5 + 16 * 1024];
    let n = match super::peek_client_hello(&stream, &mut peeked, deadline).await {
        Some(Ok(n)) => n,
        _ => 0,
    };
    divert(stream, &peeked[..n], client, idle).await
}

async fn relay(
    mut client_stream: TcpStream,
    route: &PassthroughRoute,
    client: SocketAddr,
    metrics: &MetricsRegistry,
    idle: Duration,
    mut shutdown: watch::Receiver<()>,
) {
    let _open = metrics
        .connections
        .connection_opened(ConnectionProtocol::Passthrough);
    let backend = match tokio::time::timeout(
        Duration::from_millis(route.timeout_ms.max(1)),
        TcpStream::connect(&route.backend),
    )
    .await
    {
        Ok(Ok(backend)) => backend,
        Ok(Err(e)) => {
            warn!("Passthrough {} → {}: {}", client, route.backend, e);
            return;
        }
        Err(_) => {
            warn!(
                "Passthrough {} → {}: connect timed out",
                client, route.backend
            );
            return;
        }
    };
    let _ = backend.set_nodelay(true);
    if route.proxy_protocol {
        let local = client_stream
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        if let Err(e) = send_proxy_v2_header(&backend, client, local).await {
            warn!(
                "Passthrough {} → {}: PROXY header not sent: {}",
                client, route.backend, e
            );
            return;
        }
    }
    debug!(
        "Passthrough {} → {} ({})",
        client,
        route.backend,
        route.name.as_deref().unwrap_or(&route.sni)
    );
    tokio::select! {
        (up, down) = crate::ws_tunnel::relay(&mut client_stream, backend, Some(idle)) => {
            debug!("Passthrough {} ended: {} bytes up, {} down", client, up, down);
        }
        _ = shutdown.changed() => {
            debug!("Passthrough {} closed at shutdown", client);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tls_acceptor::client_hello_server_name;

    /// The passthrough listener reads the SNI of a ClientHello it never
    /// terminates; with panic = "abort" a panic here ends the process.
    #[test]
    fn sni_extraction_never_panics() {
        crate::fuzz_support::fuzz_bytes(
            &build_client_hello_with_sni("example.com"),
            200_000,
            |m| {
                let _ = client_hello_server_name(m);
            },
        );
    }

    // =========================================================================
    // ClientHello SNI Parser Tests
    // =========================================================================

    /// Build a minimal valid TLS 1.2 ClientHello with SNI extension
    fn build_client_hello_with_sni(hostname: &str) -> Vec<u8> {
        let hostname_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + hostname_bytes.len(); // type(1) + len(2) + name
        let sni_list_len = sni_entry_len;
        let sni_ext_len = 2 + sni_list_len; // list_len(2) + list

        // Extensions: SNI only
        let extensions_len = 4 + sni_ext_len; // type(2) + len(2) + data

        // ClientHello body (minimal)
        let mut client_hello = Vec::new();

        // Version (TLS 1.2 = 0x0303)
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID length (0)
        client_hello.push(0);

        // Cipher suites (2 bytes length + 2 cipher suites)
        client_hello.extend_from_slice(&[0x00, 0x04]); // 4 bytes
        client_hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        client_hello.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // Compression methods (1 byte length + null)
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions length
        client_hello.extend_from_slice(
            &u16::try_from(extensions_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );

        // SNI extension (type 0x0000)
        client_hello.extend_from_slice(&[0x00, 0x00]); // Extension type
        client_hello
            .extend_from_slice(&u16::try_from(sni_ext_len).unwrap_or(u16::MAX).to_be_bytes()); // Extension length
        client_hello.extend_from_slice(
            &u16::try_from(sni_list_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        ); // SNI list length
        client_hello.push(0x00); // Name type (host_name)
        client_hello.extend_from_slice(
            &u16::try_from(hostname_bytes.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        client_hello.extend_from_slice(hostname_bytes);

        // Handshake header
        let handshake_len = client_hello.len();
        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.push(0x00); // Length high byte (always 0 for reasonable sizes)
        handshake.extend_from_slice(
            &u16::try_from(handshake_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        handshake.extend(client_hello);

        // TLS record header
        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16); // Handshake
        record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (legacy version in record)
        record.extend_from_slice(&u16::try_from(record_len).unwrap_or(u16::MAX).to_be_bytes());
        record.extend(handshake);

        record
    }

    #[test]
    fn test_sni_extraction_simple() {
        let data = build_client_hello_with_sni("example.com");
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn test_sni_extraction_subdomain() {
        let data = build_client_hello_with_sni("api.pqcrypta.com");
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, Some("api.pqcrypta.com".to_string()));
    }

    #[test]
    fn test_sni_extraction_long_hostname() {
        let hostname = "very-long-subdomain.another-subdomain.example.domain.com";
        let data = build_client_hello_with_sni(hostname);
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_with_port_like_name() {
        // Some hostnames might look unusual
        let data = build_client_hello_with_sni("server-443.internal.local");
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, Some("server-443.internal.local".to_string()));
    }

    #[test]
    fn test_sni_extraction_empty_data() {
        let sni = client_hello_server_name(&[]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_too_short() {
        // Less than 5 bytes (TLS record header)
        let sni = client_hello_server_name(&[0x16, 0x03, 0x01]);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_not_handshake() {
        // Application data record (0x17) instead of handshake (0x16)
        let data = [0x17, 0x03, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00];
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_not_client_hello() {
        // ServerHello (0x02) instead of ClientHello (0x01)
        let data = [
            0x16, 0x03, 0x03, 0x00, 0x05, // TLS record header
            0x02, 0x00, 0x00, 0x01, 0x00, // ServerHello header
        ];
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_truncated_handshake() {
        // Valid record header but truncated handshake
        let data = [
            0x16, 0x03, 0x03, 0x00, 0x02, // TLS record header (claims 2 bytes)
            0x01, 0x00, // Truncated ClientHello
        ];
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_no_extensions() {
        // ClientHello without extensions
        let mut data = Vec::new();

        // TLS record header
        data.push(0x16); // Handshake
        data.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

        // We'll set length later
        let record_len_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00]); // the record length, set below

        // Handshake header
        data.push(0x01); // ClientHello
        let handshake_len_pos = data.len();
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // the handshake length, set below

        let client_hello_start = data.len();

        // Version
        data.extend_from_slice(&[0x03, 0x03]);

        // Random (32 bytes)
        data.extend_from_slice(&[0u8; 32]);

        // Session ID (0)
        data.push(0);

        // Cipher suites
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // 2 bytes, TLS_EMPTY_RENEGOTIATION_INFO_SCSV

        // Compression methods
        data.extend_from_slice(&[0x01, 0x00]);

        // NO extensions (0 length)
        data.extend_from_slice(&[0x00, 0x00]);

        // Fix lengths
        let client_hello_len = data.len() - client_hello_start;
        let handshake_len = client_hello_len + 4;
        let record_len = handshake_len;

        data[record_len_pos] = u8::try_from((record_len >> 8) & 0xFF).unwrap_or(u8::MAX);
        data[record_len_pos + 1] = u8::try_from(record_len & 0xFF).unwrap_or(u8::MAX);

        data[handshake_len_pos + 1] =
            u8::try_from((client_hello_len >> 8) & 0xFF).unwrap_or(u8::MAX);
        data[handshake_len_pos + 2] = u8::try_from(client_hello_len & 0xFF).unwrap_or(u8::MAX);

        let sni = client_hello_server_name(&data);
        assert_eq!(sni, None);
    }

    #[test]
    fn test_sni_extraction_with_grease_extensions() {
        // Build ClientHello with GREASE extension before SNI
        let hostname = "grease-test.example.com";
        let hostname_bytes = hostname.as_bytes();

        let mut client_hello = Vec::new();

        // Version
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID
        client_hello.push(0);

        // Cipher suites
        client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions
        let mut extensions = Vec::new();

        // GREASE extension (0x0A0A)
        extensions.extend_from_slice(&[0x0A, 0x0A]); // GREASE type
        extensions.extend_from_slice(&[0x00, 0x01]); // Length 1
        extensions.push(0x00); // Data

        // SNI extension
        let sni_list_len = 3 + hostname_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        extensions.extend_from_slice(&[0x00, 0x00]); // SNI type
        extensions.extend_from_slice(&u16::try_from(sni_ext_len).unwrap_or(u16::MAX).to_be_bytes());
        extensions.extend_from_slice(
            &u16::try_from(sni_list_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.push(0x00); // host_name type
        extensions.extend_from_slice(
            &u16::try_from(hostname_bytes.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        extensions.extend_from_slice(hostname_bytes);

        // Another GREASE extension (0xFAFA)
        extensions.extend_from_slice(&[0xFA, 0xFA]); // GREASE type
        extensions.extend_from_slice(&[0x00, 0x00]); // Length 0

        client_hello.extend_from_slice(
            &u16::try_from(extensions.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        client_hello.extend(extensions);

        // Build full record
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(0x00);
        handshake.extend_from_slice(
            &u16::try_from(client_hello.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        handshake.extend(client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(
            &u16::try_from(handshake.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        record.extend(handshake);

        let sni = client_hello_server_name(&record);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_long_session_id() {
        // ClientHello with maximum session ID (32 bytes)
        let hostname = "session-test.example.com";
        let hostname_bytes = hostname.as_bytes();

        let mut client_hello = Vec::new();

        // Version
        client_hello.extend_from_slice(&[0x03, 0x03]);

        // Random
        client_hello.extend_from_slice(&[0u8; 32]);

        // Session ID (32 bytes - maximum)
        client_hello.push(32);
        client_hello.extend_from_slice(&[0xAB; 32]);

        // Cipher suites
        client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);

        // Compression
        client_hello.extend_from_slice(&[0x01, 0x00]);

        // Extensions (SNI only)
        let sni_list_len = 3 + hostname_bytes.len();
        let sni_ext_len = 2 + sni_list_len;
        let extensions_len = 4 + sni_ext_len;

        client_hello.extend_from_slice(
            &u16::try_from(extensions_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        client_hello.extend_from_slice(&[0x00, 0x00]); // SNI type
        client_hello
            .extend_from_slice(&u16::try_from(sni_ext_len).unwrap_or(u16::MAX).to_be_bytes());
        client_hello.extend_from_slice(
            &u16::try_from(sni_list_len)
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        client_hello.push(0x00);
        client_hello.extend_from_slice(
            &u16::try_from(hostname_bytes.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        client_hello.extend_from_slice(hostname_bytes);

        // Build full record
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(0x00);
        handshake.extend_from_slice(
            &u16::try_from(client_hello.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        handshake.extend(client_hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(
            &u16::try_from(handshake.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        record.extend(handshake);

        let sni = client_hello_server_name(&record);
        assert_eq!(sni, Some(hostname.to_string()));
    }

    #[test]
    fn test_sni_extraction_punycode_hostname() {
        // International domain name in ASCII-compatible encoding
        let hostname = "xn--n3h.example.com"; // Contains emoji in punycode
        let data = build_client_hello_with_sni(hostname);
        let sni = client_hello_server_name(&data);
        assert_eq!(sni, Some(hostname.to_string()));
    }
}
