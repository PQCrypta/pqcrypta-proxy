//! PROXY protocol: emitting v2 to backends, and reading v1 or v2 from a load
//! balancer in front of the proxy.
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

/// What a PROXY header said about the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyHeader {
    /// The client's address; `None` for v1 `UNKNOWN` or a v2 `LOCAL` command
    /// (a health check from the load balancer itself).
    pub source: Option<SocketAddr>,
    /// v2 type-length-value extensions, in order: authority (0x02), unique
    /// ID (0x05), and the cloud vendors' own (AWS 0xEA, Azure 0xEE, GCP 0xE0).
    pub tlvs: Vec<(u8, Vec<u8>)>,
}

impl ProxyHeader {
    /// The value of TLV `kind`, if the header carried one.
    #[cfg(test)]
    pub(crate) fn tlv(&self, kind: u8) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|(k, _)| *k == kind)
            .map(|(_, v)| v.as_slice())
    }
}

/// Longest legal v1 line, CRLF included (the spec's own bound).
const V1_MAX: usize = 107;
/// PP2_TYPE_CRC32C.
const PP2_TYPE_CRC32C: u8 = 0x04;

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("PROXY protocol: {msg}"),
    )
}

/// Read one PROXY header, v1 or v2, from the start of `stream`, consuming
/// exactly its bytes so whatever follows — the TLS ClientHello — is untouched.
pub(crate) async fn read_proxy_header<R>(stream: &mut R) -> std::io::Result<ProxyHeader>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    match first[0] {
        b'P' => {
            // v1: ASCII up to CRLF, read a byte at a time so nothing past the
            // line is consumed. At most 107 bytes.
            let mut line = vec![b'P'];
            while !line.ends_with(b"\r\n") {
                if line.len() >= V1_MAX {
                    return Err(invalid("v1 line exceeds 107 bytes"));
                }
                let mut b = [0u8; 1];
                stream.read_exact(&mut b).await?;
                line.push(b[0]);
            }
            parse_v1(&line[..line.len() - 2])
        }
        0x0D => {
            let mut head = [0u8; 16];
            head[0] = 0x0D;
            stream.read_exact(&mut head[1..]).await?;
            if head[..12] != PROXY_V2_SIGNATURE {
                return Err(invalid("bad v2 signature"));
            }
            let len = usize::from(u16::from_be_bytes([head[14], head[15]]));
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await?;
            parse_v2(&head, &body)
        }
        _ => Err(invalid("no PROXY header from a trusted proxy")),
    }
}

fn parse_v1(line: &[u8]) -> std::io::Result<ProxyHeader> {
    let line = std::str::from_utf8(line).map_err(|_| invalid("v1 line is not ASCII"))?;
    let parts: Vec<&str> = line.split(' ').collect();
    if parts.first() != Some(&"PROXY") {
        return Err(invalid("v1 line does not start with PROXY"));
    }
    match parts.get(1).copied() {
        Some("UNKNOWN") => Ok(ProxyHeader {
            source: None,
            tlvs: Vec::new(),
        }),
        Some(fam @ ("TCP4" | "TCP6")) => {
            let [_, _, src, _dst, sport, _dport] = parts.as_slice() else {
                return Err(invalid("v1 line has the wrong number of fields"));
            };
            let ip: std::net::IpAddr = src.parse().map_err(|_| invalid("v1 source address"))?;
            if (fam == "TCP4") != ip.is_ipv4() {
                return Err(invalid("v1 address does not match its family"));
            }
            let port: u16 = sport.parse().map_err(|_| invalid("v1 source port"))?;
            Ok(ProxyHeader {
                source: Some(SocketAddr::new(ip, port)),
                tlvs: Vec::new(),
            })
        }
        _ => Err(invalid("v1 protocol must be TCP4, TCP6 or UNKNOWN")),
    }
}

fn parse_v2(head: &[u8; 16], body: &[u8]) -> std::io::Result<ProxyHeader> {
    if head[12] >> 4 != 2 {
        return Err(invalid("unsupported v2 version"));
    }
    let local = match head[12] & 0x0F {
        0 => true,
        1 => false,
        _ => return Err(invalid("unknown v2 command")),
    };
    let (source, addr_len) = match head[13] {
        0x11 | 0x12 => {
            if body.len() < 12 {
                return Err(invalid("v2 IPv4 address block truncated"));
            }
            let ip = std::net::Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let port = u16::from_be_bytes([body[8], body[9]]);
            (Some(SocketAddr::new(ip.into(), port)), 12)
        }
        0x21 | 0x22 => {
            if body.len() < 36 {
                return Err(invalid("v2 IPv6 address block truncated"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&body[..16]);
            let port = u16::from_be_bytes([body[32], body[33]]);
            (
                Some(SocketAddr::new(std::net::Ipv6Addr::from(o).into(), port)),
                36,
            )
        }
        // AF_UNSPEC, or AF_UNIX which carries no routable address.
        0x00 | 0x31 | 0x32 => (None, if head[13] == 0x00 { 0 } else { 216 }),
        _ => return Err(invalid("unknown v2 address family")),
    };
    if body.len() < addr_len {
        return Err(invalid("v2 address block truncated"));
    }
    // TLVs: type (1), length (2, big-endian), value.
    let mut tlvs = Vec::new();
    let mut rest = &body[addr_len..];
    while !rest.is_empty() {
        if rest.len() < 3 {
            return Err(invalid("v2 TLV truncated"));
        }
        let kind = rest[0];
        let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
        if rest.len() < 3 + len {
            return Err(invalid("v2 TLV value truncated"));
        }
        tlvs.push((kind, rest[3..3 + len].to_vec()));
        rest = &rest[3 + len..];
    }
    // A CRC32C TLV covers the whole header with its own value zeroed.
    if let Some((_, crc)) = tlvs.iter().find(|(k, _)| *k == PP2_TYPE_CRC32C) {
        let expected: [u8; 4] = crc
            .as_slice()
            .try_into()
            .map_err(|_| invalid("v2 CRC32C length"))?;
        let mut whole = head.to_vec();
        whole.extend_from_slice(body);
        // Zero the checksum's value where it sits in the header.
        if let Some(pos) = find_tlv_value(&whole[16 + addr_len..], PP2_TYPE_CRC32C) {
            let at = 16 + addr_len + pos;
            whole[at..at + 4].fill(0);
        }
        if crc32c(&whole) != u32::from_be_bytes(expected) {
            return Err(invalid("v2 CRC32C mismatch"));
        }
    }
    Ok(ProxyHeader {
        source: if local { None } else { source },
        tlvs,
    })
}

/// Offset of TLV `kind`'s value within a TLV block.
fn find_tlv_value(mut block: &[u8], kind: u8) -> Option<usize> {
    let mut off = 0;
    while block.len() >= 3 {
        let len = usize::from(u16::from_be_bytes([block[1], block[2]]));
        if block[0] == kind {
            return Some(off + 3);
        }
        off += 3 + len;
        block = block.get(3 + len..)?;
    }
    None
}

/// CRC-32C (Castagnoli), the checksum PP2_TYPE_CRC32C carries.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(bytes: &[u8]) -> (std::io::Result<ProxyHeader>, Vec<u8>) {
        use tokio::io::AsyncReadExt;
        let mut r = bytes;
        let h = read_proxy_header(&mut r).await;
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        (h, rest)
    }

    #[tokio::test]
    async fn v1_is_read_exactly_and_leaves_the_tls_bytes() {
        let (h, rest) =
            parse(b"PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n\x16\x03\x01").await;
        assert_eq!(
            h.unwrap().source,
            Some("203.0.113.7:51234".parse().unwrap())
        );
        assert_eq!(rest, b"\x16\x03\x01");
        let (h, _) = parse(b"PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n").await;
        assert_eq!(
            h.unwrap().source,
            Some("[2001:db8::1]:4000".parse().unwrap())
        );
        let (h, _) = parse(b"PROXY UNKNOWN\r\n").await;
        assert_eq!(h.unwrap().source, None);
        assert!(parse(b"PROXY TCP4 2001:db8::1 1.2.3.4 1 2\r\n")
            .await
            .0
            .is_err());
        assert!(parse(b"\x16\x03\x01 not a proxy header").await.0.is_err());
    }

    #[tokio::test]
    async fn v2_round_trips_our_own_encoder() {
        let src: SocketAddr = "203.0.113.9:40000".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let mut bytes = build_proxy_v2_header(src, dst);
        bytes.extend_from_slice(b"\x16\x03");
        let (h, rest) = parse(&bytes).await;
        assert_eq!(h.unwrap().source, Some(src));
        assert_eq!(rest, b"\x16\x03");

        let src6: SocketAddr = "[2001:db8::7]:5000".parse().unwrap();
        let dst6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let (h, _) = parse(&build_proxy_v2_header(src6, dst6)).await;
        assert_eq!(h.unwrap().source, Some(src6));
    }

    #[tokio::test]
    async fn v2_tlvs_local_and_crc32c() {
        // PROXY, TCP4, then an AWS VPC endpoint TLV and a CRC32C TLV.
        let mut body = vec![203, 0, 113, 9, 198, 51, 100, 1, 0x9C, 0x40, 0x01, 0xBB];
        body.extend_from_slice(&[0xEA, 0x00, 0x04, b'v', b'p', b'c', b'e']);
        body.extend_from_slice(&[PP2_TYPE_CRC32C, 0x00, 0x04, 0, 0, 0, 0]);
        let mut head = PROXY_V2_SIGNATURE.to_vec();
        head.extend_from_slice(&[0x21, 0x11]);
        head.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        let mut whole = head.clone();
        whole.extend_from_slice(&body);
        let crc = crc32c(&whole).to_be_bytes();
        let n = whole.len();
        whole[n - 4..].copy_from_slice(&crc);
        let h = parse(&whole).await.0.unwrap();
        assert_eq!(h.source, Some("203.0.113.9:40000".parse().unwrap()));
        assert_eq!(h.tlv(0xEA), Some(&b"vpce"[..]));

        whole[n - 1] ^= 0xFF;
        assert!(parse(&whole).await.0.is_err(), "a bad checksum is refused");

        // LOCAL: a health check from the load balancer; no client address.
        let mut local = PROXY_V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        assert_eq!(parse(&local).await.0.unwrap().source, None);
    }

    #[tokio::test]
    async fn only_trusted_peers_are_read() {
        use tokio::io::AsyncReadExt;
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let timeout = std::time::Duration::from_secs(1);
        let spoof = b"PROXY TCP4 198.51.100.66 1.2.3.4 1 2\r\n\x16";

        // Untrusted: not a byte is consumed, so a client cannot claim an address.
        let mut r = &spoof[..];
        let got = crate::http_listener::proxied_peer(
            &mut r,
            "203.0.113.1:5000".parse().unwrap(),
            &trusted,
            timeout,
        )
        .await;
        assert_eq!(got.unwrap(), None);
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, spoof);

        // Trusted: the header is required and its address is used.
        let mut r = &spoof[..];
        let got = crate::http_listener::proxied_peer(
            &mut r,
            "10.1.2.3:5000".parse().unwrap(),
            &trusted,
            timeout,
        )
        .await;
        assert_eq!(got.unwrap(), Some("198.51.100.66:1".parse().unwrap()));
        let mut r = &b"\x16\x03\x01"[..];
        assert!(crate::http_listener::proxied_peer(
            &mut r,
            "10.1.2.3:5000".parse().unwrap(),
            &trusted,
            timeout
        )
        .await
        .is_err());
    }

    #[test]
    fn crc32c_known_answer() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }
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
