//! PROXY protocol v2 header construction and emission.
//!
//! Reference: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>
//!
//! PROXY protocol v2 allows the proxy to pass the original client connection
//! information to the backend server. This is essential for TLS passthrough
//! where the proxy cannot modify the TLS stream but the backend needs to know
//! the real client IP address.

use std::net::SocketAddr;

use tokio::net::TcpStream;
use tracing::debug;

pub(super) const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// PROXY protocol v2 version and command byte
pub(super) mod proxy_v2 {
    /// Version 2, PROXY command (connection was proxied)
    pub(super) const VERSION_PROXY: u8 = 0x21;

    /// Version 2, LOCAL command (connection was not proxied, health check etc.)
    #[cfg(test)]
    pub(super) const VERSION_LOCAL: u8 = 0x20;

    /// Address family and protocol
    #[cfg(test)]
    pub(super) const AF_UNSPEC: u8 = 0x00; // Unspecified (used with LOCAL command)
    pub(super) const AF_INET_STREAM: u8 = 0x11; // IPv4 + TCP
    pub(super) const AF_INET6_STREAM: u8 = 0x21; // IPv6 + TCP
}

/// Build a PROXY protocol v2 header for the given connection
///
/// # Arguments
/// * `src_addr` - The original client address
/// * `dst_addr` - The proxy's local address (where client connected to)
///
/// # Returns
/// A byte vector containing the complete PROXY protocol v2 header
pub(super) fn build_proxy_v2_header(src_addr: SocketAddr, dst_addr: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(16 + 36); // Max size for IPv6

    // 12-byte signature
    header.extend_from_slice(&PROXY_V2_SIGNATURE);

    match (src_addr, dst_addr) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            // Version 2 + PROXY command
            header.push(proxy_v2::VERSION_PROXY);
            // IPv4 + TCP
            header.push(proxy_v2::AF_INET_STREAM);
            // Address length: 4 + 4 + 2 + 2 = 12 bytes
            header.extend_from_slice(&12u16.to_be_bytes());
            // Source IP (4 bytes)
            header.extend_from_slice(&src.ip().octets());
            // Destination IP (4 bytes)
            header.extend_from_slice(&dst.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&src.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
            // Version 2 + PROXY command
            header.push(proxy_v2::VERSION_PROXY);
            // IPv6 + TCP
            header.push(proxy_v2::AF_INET6_STREAM);
            // Address length: 16 + 16 + 2 + 2 = 36 bytes
            header.extend_from_slice(&36u16.to_be_bytes());
            // Source IP (16 bytes)
            header.extend_from_slice(&src.ip().octets());
            // Destination IP (16 bytes)
            header.extend_from_slice(&dst.ip().octets());
            // Source port (2 bytes)
            header.extend_from_slice(&src.port().to_be_bytes());
            // Destination port (2 bytes)
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        // Mixed IPv4/IPv6 - convert IPv4 to IPv4-mapped IPv6
        (SocketAddr::V4(src), SocketAddr::V6(dst)) => {
            let src_v6 = src.ip().to_ipv6_mapped();
            header.push(proxy_v2::VERSION_PROXY);
            header.push(proxy_v2::AF_INET6_STREAM);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src_v6.octets());
            header.extend_from_slice(&dst.ip().octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
        (SocketAddr::V6(src), SocketAddr::V4(dst)) => {
            let dst_v6 = dst.ip().to_ipv6_mapped();
            header.push(proxy_v2::VERSION_PROXY);
            header.push(proxy_v2::AF_INET6_STREAM);
            header.extend_from_slice(&36u16.to_be_bytes());
            header.extend_from_slice(&src.ip().octets());
            header.extend_from_slice(&dst_v6.octets());
            header.extend_from_slice(&src.port().to_be_bytes());
            header.extend_from_slice(&dst.port().to_be_bytes());
        }
    }

    header
}

/// Send PROXY protocol v2 header to the backend
pub(super) async fn send_proxy_v2_header(
    stream: &TcpStream,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
) -> std::io::Result<()> {
    let header = build_proxy_v2_header(client_addr, local_addr);

    // We need to write to the stream before it's split
    // This is a bit tricky - we'll use try_write which doesn't require &mut
    let mut written = 0;
    while written < header.len() {
        stream.writable().await?;
        match stream.try_write(&header[written..]) {
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }

    debug!(
        "Sent PROXY protocol v2 header ({} bytes) for {} -> {}",
        header.len(),
        client_addr,
        local_addr
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    // =========================================================================
    // PROXY Protocol v2 Header Builder Tests
    // =========================================================================

    #[test]
    fn test_proxy_v2_header_ipv4() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 54321));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 443));

        let header = build_proxy_v2_header(src, dst);

        // Total size: 12 (signature) + 4 (header) + 12 (addresses) = 28 bytes
        assert_eq!(header.len(), 28);

        // Verify signature (first 12 bytes)
        assert_eq!(&header[0..12], &PROXY_V2_SIGNATURE);

        // Version 2 + PROXY command
        assert_eq!(header[12], proxy_v2::VERSION_PROXY);

        // IPv4 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET_STREAM);

        // Address length (12 bytes for IPv4)
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 12);

        // Source IP: 192.168.1.100
        assert_eq!(&header[16..20], &[192, 168, 1, 100]);

        // Destination IP: 10.0.0.1
        assert_eq!(&header[20..24], &[10, 0, 0, 1]);

        // Source port: 54321 (0xD431)
        assert_eq!(u16::from_be_bytes([header[24], header[25]]), 54321);

        // Destination port: 443 (0x01BB)
        assert_eq!(u16::from_be_bytes([header[26], header[27]]), 443);
    }

    #[test]
    fn test_proxy_v2_header_ipv6() {
        let src = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            12345,
            0,
            0,
        ));
        let dst = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            8443,
            0,
            0,
        ));

        let header = build_proxy_v2_header(src, dst);

        // Total size: 12 (signature) + 4 (header) + 36 (addresses) = 52 bytes
        assert_eq!(header.len(), 52);

        // Verify signature
        assert_eq!(&header[0..12], &PROXY_V2_SIGNATURE);

        // Version 2 + PROXY command
        assert_eq!(header[12], proxy_v2::VERSION_PROXY);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Address length (36 bytes for IPv6)
        assert_eq!(u16::from_be_bytes([header[14], header[15]]), 36);

        // Source IP: 2001:db8::1
        let expected_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(&header[16..32], &expected_src);

        // Destination IP: fe80::1
        let expected_dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(&header[32..48], &expected_dst);

        // Source port: 12345
        assert_eq!(u16::from_be_bytes([header[48], header[49]]), 12345);

        // Destination port: 8443
        assert_eq!(u16::from_be_bytes([header[50], header[51]]), 8443);
    }

    #[test]
    fn test_proxy_v2_header_mixed_ipv4_to_ipv6() {
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000));
        let dst = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));

        let header = build_proxy_v2_header(src, dst);

        // Should use IPv6 format (52 bytes)
        assert_eq!(header.len(), 52);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Source should be IPv4-mapped IPv6 (::ffff:127.0.0.1)
        let expected_src = Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets();
        assert_eq!(&header[16..32], &expected_src);
    }

    #[test]
    fn test_proxy_v2_header_mixed_ipv6_to_ipv4() {
        let src = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5000, 0, 0));
        let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80));

        let header = build_proxy_v2_header(src, dst);

        // Should use IPv6 format (52 bytes)
        assert_eq!(header.len(), 52);

        // IPv6 + TCP
        assert_eq!(header[13], proxy_v2::AF_INET6_STREAM);

        // Destination should be IPv4-mapped IPv6 (::ffff:10.0.0.1)
        let expected_dst = Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped().octets();
        assert_eq!(&header[32..48], &expected_dst);
    }

    #[test]
    fn test_proxy_v2_signature_constant() {
        // Verify the signature matches the PROXY protocol v2 spec
        let expected = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        ];
        assert_eq!(PROXY_V2_SIGNATURE, expected);
    }

    #[test]
    fn test_proxy_v2_constants() {
        // Version 2, PROXY command = 0x21
        assert_eq!(proxy_v2::VERSION_PROXY, 0x21);

        // Version 2, LOCAL command = 0x20
        assert_eq!(proxy_v2::VERSION_LOCAL, 0x20);

        // IPv4 + TCP = 0x11
        assert_eq!(proxy_v2::AF_INET_STREAM, 0x11);

        // IPv6 + TCP = 0x21
        assert_eq!(proxy_v2::AF_INET6_STREAM, 0x21);

        // Unspecified = 0x00
        assert_eq!(proxy_v2::AF_UNSPEC, 0x00);
    }
}
