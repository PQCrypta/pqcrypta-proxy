//! The server's one HTTP/3 GREASE frame (RFC 9114 7.2.8) goes ahead of its
//! first response's HEADERS frame, never last on the stream.
//!
//! RFC 9114 4.1 lets an unknown frame go anywhere on a request stream, but
//! aioquic before 1.6 loses the end of a stream whose last frame is one it
//! ignores: dnspython's DNS over HTTPS (HTTP/3 when httpx is absent) then
//! waits out its timeout for a response it has already received, which
//! dnsscanner.net reported as "DoH not supported".
//!
//! A real QUIC server runs the vendored h3 with its defaults (GREASE on), and a
//! raw QUIC client reads the response stream's frames as they are on the wire.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig};

/// Accept any server certificate: a loopback test.
#[derive(Debug)]
struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A QUIC variable-length integer at `buf[*at..]` (RFC 9000 16)
fn varint(buf: &[u8], at: &mut usize) -> u64 {
    let first = buf[*at];
    let len = 1usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for byte in &buf[*at + 1..*at + len] {
        value = (value << 8) | u64::from(*byte);
    }
    *at += len;
    value
}

/// A reserved frame type, 0x1f * N + 0x21 (RFC 9114 7.2.8)
fn reserved(frame_type: u64) -> bool {
    frame_type >= 0x21 && (frame_type - 0x21) % 0x1f == 0
}

#[tokio::test]
async fn the_grease_frame_is_not_the_last_on_a_response_stream() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server = Endpoint::server(
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let port = server.local_addr().unwrap().port();

    let serving = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        // The proxy's builder, GREASE left at h3's default (on)
        let mut h3_conn = h3::server::builder()
            .build(h3_quinn::Connection::new(conn.clone()))
            .await
            .unwrap();
        let resolver = h3_conn.accept().await.unwrap().expect("a request");
        let (_request, mut stream) = resolver.resolve_request().await.unwrap();
        stream
            .send_response(http::Response::builder().status(200).body(()).unwrap())
            .await
            .unwrap();
        stream
            .send_data(Bytes::from_static(b"answer"))
            .await
            .unwrap();
        stream.finish().await.unwrap();
        // Until the client has read the stream
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).unwrap(),
    )));
    let conn = client
        .connect((std::net::Ipv4Addr::LOCALHOST, port).into(), "localhost")
        .unwrap()
        .await
        .unwrap();

    // The client's control stream (type 0x00) with an empty SETTINGS frame
    let mut control = conn.open_uni().await.unwrap();
    control.write_all(&[0x00, 0x04, 0x00]).await.unwrap();

    // GET https://localhost/ with static QPACK references only (RFC 9204
    // Appendix A): :method GET (17), :scheme https (23), :path / (1), and
    // :authority (0) with a literal value
    let mut block = vec![0x00, 0x00, 0xc0 | 17, 0xc0 | 23, 0xc0 | 1, 0x50, 9];
    block.extend_from_slice(b"localhost");
    let mut request = vec![0x01, u8::try_from(block.len()).unwrap()];
    request.extend_from_slice(&block);
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(&request).await.unwrap();
    send.finish().unwrap();

    let wire = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
        .await
        .expect("the response stream ends")
        .unwrap();
    let mut types = Vec::new();
    let mut at = 0;
    while at < wire.len() {
        let frame_type = varint(&wire, &mut at);
        let length = usize::try_from(varint(&wire, &mut at)).unwrap();
        at += length;
        types.push(frame_type);
    }
    serving.await.unwrap();

    assert!(
        types.iter().any(|t| reserved(*t)),
        "h3's default sends a GREASE frame on the first response: {types:x?}"
    );
    assert!(
        reserved(types[0]),
        "the GREASE frame leads, ahead of HEADERS: {types:x?}"
    );
    assert_eq!(
        types[1..],
        [0x01, 0x00],
        "then HEADERS and DATA, DATA last: {types:x?}"
    );
}
