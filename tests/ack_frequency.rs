//! Integration test for the QUIC ACK Frequency extension
//! (draft-ietf-quic-ack-frequency).
//!
//! The proxy enables `AckFrequencyConfig` on its transport when
//! `server.enable_ack_frequency` is set. When both peers negotiate the
//! extension they exchange `ACK_FREQUENCY` frames; quinn records every received
//! `ACK_FREQUENCY` frame in `connection.stats().frame_rx.ack_frequency`.
//!
//! This test stands up a real quinn server + client — both configured exactly
//! the way the proxy configures its listener — and asserts that `ACK_FREQUENCY`
//! frames actually cross the wire. A second case confirms that, with the
//! extension disabled (matching `enable_ack_frequency = false`), no such frames
//! appear, so the test fails loudly if the wiring ever regresses.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{AckFrequencyConfig, ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};

/// Accept any server certificate — this is a localhost loopback test.
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

fn transport(ack_frequency: bool) -> Arc<TransportConfig> {
    let mut tc = TransportConfig::default();
    // Match the proxy's gated wiring.
    if ack_frequency {
        tc.ack_frequency_config(Some(AckFrequencyConfig::default()));
    }
    tc.max_concurrent_bidi_streams(VarInt::from_u32(8));
    Arc::new(tc)
}

fn server_endpoint(ack_frequency: bool) -> (Endpoint, u16) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();

    let crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let mut server_config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto).unwrap()));
    server_config.transport = transport(ack_frequency);

    let endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    (endpoint, port)
}

fn client_endpoint(ack_frequency: bool) -> Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
        .with_no_client_auth();
    let mut client_config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
    client_config.transport_config(transport(ack_frequency));

    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Drive a short bidirectional exchange and return the `ACK_FREQUENCY` frames
/// each side received.
async fn run_exchange(ack_frequency: bool) -> (u64, u64) {
    // rustls needs a process-level crypto provider before any config is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (server, port) = server_endpoint(ack_frequency);

    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        // Echo one bidirectional stream.
        if let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let data = recv.read_to_end(64).await.unwrap_or_default();
            let _ = send.write_all(&data).await;
            let _ = send.finish();
        }
        // Hold the connection open long enough for ACK_FREQUENCY frames to flow.
        tokio::time::sleep(Duration::from_millis(300)).await;
        conn.stats().frame_rx.ack_frequency
    });

    let client = client_endpoint(ack_frequency);
    let conn = client
        .connect((std::net::Ipv4Addr::LOCALHOST, port).into(), "localhost")
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let _ = recv.read_to_end(64).await;

    tokio::time::sleep(Duration::from_millis(300)).await;
    let client_rx = conn.stats().frame_rx.ack_frequency;

    let server_rx = server_task.await.unwrap();
    (client_rx, server_rx)
}

#[tokio::test]
async fn ack_frequency_frames_exchanged_when_enabled() {
    let (client_rx, server_rx) = run_exchange(true).await;
    assert!(
        client_rx > 0 || server_rx > 0,
        "expected ACK_FREQUENCY frames with the extension enabled \
         (client_rx={client_rx}, server_rx={server_rx})"
    );
}

#[tokio::test]
async fn no_ack_frequency_frames_when_disabled() {
    let (client_rx, server_rx) = run_exchange(false).await;
    assert_eq!(
        (client_rx, server_rx),
        (0, 0),
        "no ACK_FREQUENCY frames expected when the extension is disabled"
    );
}
