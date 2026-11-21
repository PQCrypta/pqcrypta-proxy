//! Entry points for the coverage-guided fuzz targets in `fuzz/` (cargo-fuzz,
//! run by ClusterFuzzLite): each hands the fuzzer's bytes to one family of
//! parsers a client's or a peer's bytes reach, and asserts what must hold of
//! any input. Compiled only under `cfg(fuzzing)`, which cargo-fuzz sets.
//!
//! Release builds abort on a panic, so a panic anywhere these parsers run ends
//! the process on every node. The deterministic mutation tests
//! (`fuzz_support`) run several of the same surfaces in `cargo test`; these
//! are guided by coverage, so they reach the branches a blind mutation rarely
//! does.

use std::sync::OnceLock;

use rustls::server::ProducesTickets;

use crate::fingerprint::FingerprintExtractor;
use crate::pqc_tickets::PqcTicketer;

/// A TLS record carrying a ClientHello, as the TCP acceptors, the passthrough
/// router and the fingerprinter read it.
pub fn client_hello(data: &[u8]) {
    for ext in [0, 16, 41, 42, 43, 45, 51, 0xfe0d] {
        let _ = crate::tls_acceptor::client_hello_extension(data, ext);
    }
    let _ = crate::tls_acceptor::client_hello_psk_identity(data);
    let _ =
        crate::tls_acceptor::FingerprintingTlsAcceptor::client_hello_has_early_data_extension(data);
    let _ = crate::http_listener::client_hello_needs(data, data.len());

    // The name everything before the handshake reads (passthrough routing,
    // the HTTP/1.1-only acceptor) is the name the handshake reads: rustls's own
    // parse of the same record, where it takes the record as a ClientHello.
    // Only a record holding one whole ClientHello is compared; rustls would
    // join one split over records, which nothing before it reads.
    let ours = crate::tls_acceptor::client_hello_server_name(data);
    if let crate::tls_acceptor::HandshakeReads::ServerName(theirs) =
        crate::tls_acceptor::handshake_server_name(data)
    {
        assert_eq!(
            ours.as_deref(),
            theirs.as_deref(),
            "the proxy reads SNI {ours:?} where the handshake reads {theirs:?}"
        );
    }

    let extractor = extractor();
    let _ = extractor.extract_ja3(data);
    if data.len() > 5 {
        let _ = extractor.extract_ja3_quic(&data[5..]);
    }
}

/// A DNS message, as the DoH and DoQ front ends read one: every name at every
/// offset (compression pointers included), the message's layout, and the
/// refusal and cache lifetime made from it.
pub fn dns_message(data: &[u8]) {
    for at in 0..data.len().min(256) {
        let _ = crate::dns_wire::read_name(data, at);
        let _ = crate::dns_wire::name_end(data, at);
        let _ = crate::dns_wire::record_at(data, at);
    }
    let _ = crate::dns_wire::layout(data);
    if let Some(info) = crate::doh::inspect(data) {
        let refusal = crate::doh::refusal(data, &info);
        assert!(
            crate::dns_wire::layout(&refusal).is_some(),
            "the refusal made from a query is a well-formed message"
        );
    }
    let _ = crate::doh::freshness(data);
    let _ = crate::doq::framed(data);
}

/// A request body and its `Content-Encoding`: the first byte picks one or two
/// codings and the limit, the rest is the body. Whatever decodes is never
/// more than the limit, however far the body would expand.
pub fn request_body(data: &[u8]) {
    const CODINGS: [&str; 4] = ["gzip", "deflate", "br", "zstd"];
    let Some((&select, body)) = data.split_first() else {
        return;
    };
    let first = CODINGS[usize::from(select & 3)];
    let encoding = if select & 0x80 == 0 {
        first.to_string()
    } else {
        format!("{first}, {}", CODINGS[usize::from((select >> 2) & 3)])
    };
    let limit = 256usize << ((select >> 4) & 7);
    let mut budget = crate::body_budget::Reservation::new();
    if let Ok(Some(decoded)) =
        crate::request_encoding::decode(Some(&encoding), body, limit, &mut budget)
    {
        assert!(
            decoded.len() <= limit,
            "{encoding} decoded to {} bytes past the limit of {limit}",
            decoded.len()
        );
    }
}

/// A PROXY protocol header as a load balancer in front of the listener sends
/// it: version 1 (a text line) and version 2 (16 bytes, then the addresses
/// and TLVs).
pub fn proxy_header(data: &[u8]) {
    let _ = crate::http_listener::proxy_protocol::parse_v1(data);
    if let Some((head, body)) = data.split_first_chunk::<16>() {
        let _ = crate::http_listener::proxy_protocol::parse_v2(head, body);
    }
}

/// The documents fetched from elsewhere: a crawler's published address ranges
/// and the fingerprint corpus as stored on disk.
pub fn fetched_documents(data: &[u8]) {
    let _ = crate::crawler_verify::parse_feed(data);
    let _ = crate::fingerprint_corpus::parse(data);
}

/// A CONNECT-UDP request target (RFC 9298), as a path.
pub fn connect_udp_target(data: &[u8]) {
    let _ = crate::connect_udp::parse_target(&String::from_utf8_lossy(data));
}

/// A session ticket as a client presents it: anything not sealed by this
/// ticketer is refused, never a panic; and whatever is sealed opens again to
/// itself.
pub fn session_ticket(data: &[u8]) {
    let ticketer = ticketer();
    let _ = ticketer.decrypt(data);
    let sealed = ticketer.encrypt(data).expect("any resumption state seals");
    assert_eq!(
        ticketer.decrypt(&sealed).as_deref(),
        Some(data),
        "a sealed ticket opens to what was sealed"
    );
}

fn extractor() -> &'static FingerprintExtractor {
    static EXTRACTOR: OnceLock<FingerprintExtractor> = OnceLock::new();
    EXTRACTOR.get_or_init(FingerprintExtractor::new)
}

fn ticketer() -> &'static PqcTicketer {
    static TICKETER: OnceLock<PqcTicketer> = OnceLock::new();
    TICKETER.get_or_init(|| PqcTicketer::new(3600).expect("a ticketer"))
}
