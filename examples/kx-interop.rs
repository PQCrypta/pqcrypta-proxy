//! Interoperability check for a key-exchange group against another TLS stack.
//!
//! `kx-interop server <port>` accepts one TLS 1.3 connection on 127.0.0.1,
//! offering only curveSM2MLKEM768, and prints the group it negotiated.
//! `kx-interop client <host:port>` connects offering only curveSM2MLKEM768.
//!
//! Run against OpenSSL 4.0, the first release with the group:
//!
//! ```text
//! openssl s_client -groups curveSM2MLKEM768 -connect 127.0.0.1:<port>
//! openssl s_server -groups curveSM2MLKEM768 -accept <port> -cert c.pem -key k.pem
//! ```
//!
//! A completed handshake is the evidence: both Finished messages are keyed from
//! the shared secret, so they verify only if both sides computed the same one.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::kx_group::CURVESM2MLKEM768;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut p = rustls::crypto::aws_lc_rs::default_provider();
    p.kx_groups = vec![CURVESM2MLKEM768];
    Arc::new(p)
}

#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("server") => {
            let port: u16 = args.get(2).and_then(|p| p.parse().ok()).expect("port");
            let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![key.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into()),
                )
                .unwrap();
            let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
            println!("listening on 127.0.0.1:{port}");
            let (mut tcp, _) = listener.accept().unwrap();
            let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut tcp).unwrap();
            }
            println!(
                "server negotiated {:?}",
                conn.negotiated_key_exchange_group()
                    .map(rustls::crypto::SupportedKxGroup::name)
            );
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
            stream.write_all(b"curveSM2MLKEM768 ok\n").unwrap();
            stream.flush().unwrap();
            conn.send_close_notify();
            let _ = conn.complete_io(&mut tcp);
        }
        Some("client") => {
            let target = args.get(2).expect("host:port");
            let p = provider();
            let config = rustls::ClientConfig::builder_with_provider(p.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AnyCertificate(p)))
                .with_no_client_auth();
            let mut tcp = TcpStream::connect(target).unwrap();
            let mut conn = rustls::ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("localhost").unwrap(),
            )
            .unwrap();
            while conn.is_handshaking() {
                conn.complete_io(&mut tcp).unwrap();
            }
            println!(
                "client negotiated {:?}",
                conn.negotiated_key_exchange_group()
                    .map(rustls::crypto::SupportedKxGroup::name)
            );
            let mut stream = rustls::Stream::new(&mut conn, &mut tcp);
            stream.write_all(b"hello\n").unwrap();
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf).unwrap_or(0);
            println!("read {n} bytes");
        }
        _ => eprintln!("usage: kx-interop server <port> | client <host:port>"),
    }
}
