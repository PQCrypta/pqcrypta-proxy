//! Proof that `q-zero-rtt-reject` rejects 0-RTT.
//!
//! The test exists because the claim is otherwise unfalsifiable from outside.
//! `curl` does not attempt early data over HTTP/3, so every live run of that
//! port reports — correctly — that nothing was exercised, and an unexercised
//! test proves nothing about the server either. The mechanism has to be driven
//! by a client that genuinely resumes and genuinely sends early data, and there
//! is no such client to hand.
//!
//! So one is built here, and the whole chain is checked in a single run:
//!
//! 1. a client connects, completes a handshake and is issued a session ticket
//! 2. it reconnects, resumes, and writes early data
//! 3. the server answers with a HelloRetryRequest, which rejects that early data
//!    (RFC 8446 §4.2.10)
//! 4. the socket counts the 0-RTT packets that arrived, which is the evidence
//!    the live verdict is built on
//! 5. the client's request completes on the 1-RTT keys — the recovery RFC 9001
//!    §4.6.2 requires
//!
//! Every piece is the real one: the server configuration is the same function
//! the listener calls, and the counting is the same socket wrapper the listener
//! binds. Only the certificate is a throwaway.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};

use super::impairment::{Counters, ImpairedSocket, Impairments};

/// A certificate nobody trusts, for a server nobody else talks to.
pub(super) struct Throwaway {
    pub(super) key: Arc<rustls::sign::CertifiedKey>,
    pub(super) der: CertificateDer<'static>,
}

pub(super) fn throwaway_cert() -> Throwaway {
    let cert = rcgen::generate_simple_self_signed(vec!["conformance.test".to_string()])
        .expect("generating a self-signed certificate");
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .expect("the generated key is a valid PKCS#8 document");
    let provider = crate::tls::build_pqc_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .expect("loading the generated key");
    Throwaway {
        key: Arc::new(rustls::sign::CertifiedKey::new(
            vec![der.clone()],
            signing_key,
        )),
        der,
    }
}

/// Serves the throwaway certificate for every name.
#[derive(Debug)]
pub(super) struct OneCert(pub(super) Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for OneCert {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Trusts exactly the one certificate this test generated.
///
/// Not a "verify nothing" stand-in: an accept-all verifier would also accept a
/// server that presented the wrong certificate, and the point of pinning here is
/// that the test fails if it is ever pointed at something other than the server
/// it started.
#[derive(Debug)]
pub(super) struct PinnedTo(
    pub(super) CertificateDer<'static>,
    pub(super) Arc<rustls::crypto::CryptoProvider>,
);

impl rustls::client::danger::ServerCertVerifier for PinnedTo {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.0.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "not the certificate this test pinned".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.1.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

/// A session store that reports what it was given.
///
/// When a client offers no early data there are two very different causes — the
/// server never issued a ticket, or it issued one the client would not resume
/// with — and from outside they look identical. This tells them apart, so a
/// failure here names the cause instead of leaving it to be guessed at.
#[derive(Debug)]
struct CountingStore {
    inner: rustls::client::ClientSessionMemoryCache,
    tickets: std::sync::atomic::AtomicUsize,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: rustls::client::ClientSessionMemoryCache::new(32),
            tickets: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn tickets(&self) -> usize {
        self.tickets.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl rustls::client::ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, server: ServerName<'static>, group: rustls::NamedGroup) {
        self.inner.set_kx_hint(server, group);
    }

    fn kx_hint(&self, server: &ServerName<'_>) -> Option<rustls::NamedGroup> {
        self.inner.kx_hint(server)
    }

    fn set_tls12_session(
        &self,
        server: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.inner.set_tls12_session(server, value);
    }

    fn tls12_session(
        &self,
        server: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.inner.tls12_session(server)
    }

    fn remove_tls12_session(&self, server: &ServerName<'static>) {
        self.inner.remove_tls12_session(server);
    }

    fn insert_tls13_ticket(
        &self,
        server: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.tickets
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner.insert_tls13_ticket(server, value);
    }

    fn take_tls13_ticket(
        &self,
        server: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server)
    }
}

/// Bind a server on loopback with `crypto`, counting through the same socket
/// wrapper the listener binds, and answer every stream on every connection.
fn spawn_server(
    crypto: Arc<quinn::crypto::rustls::QuicServerConfig>,
    counters: Arc<Counters>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let mut server_config = quinn::ServerConfig::with_crypto(crypto);
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .expect("10s is a valid idle timeout"),
    ));
    server_config.transport = Arc::new(transport);

    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a loopback port");
    let runtime = quinn::default_runtime().expect("a tokio runtime is running");
    // Unimpaired: this test is about early data being refused, and a path that
    // dropped anything would confuse a rejection with a loss.
    let impaired = Box::new(ImpairedSocket::new(
        runtime
            .wrap_udp_socket(socket)
            .expect("wrapping the socket"),
        Impairments::default(),
        counters,
    ));
    let server = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        impaired,
        runtime,
    )
    .expect("building the server endpoint");
    let addr = server.local_addr().expect("the server is bound");

    let accepting = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let _ = recv.read_to_end(4096).await;
                    let _ = send.write_all(b"answered\n").await;
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, accepting)
}

/// A client that resumes and is willing to send early data.
fn client_endpoint(throwaway: &Throwaway) -> (quinn::Endpoint, Arc<CountingStore>) {
    let provider = Arc::new(crate::tls::build_pqc_provider());
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is available")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    // Without this the client stores the ticket but never offers early data, and
    // both tests would pass for the wrong reason.
    client_crypto.enable_early_data = true;
    let store = Arc::new(CountingStore::new());
    client_crypto.resumption = rustls::client::Resumption::store(store.clone());

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .expect("building the QUIC client configuration"),
    ));
    let client = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a client port");
    client.set_default_client_config(client_config);
    (client, store)
}

/// One full connection, so the client has a session ticket to resume from.
async fn prime_session(client: &quinn::Endpoint, server_addr: SocketAddr) {
    let connection = client
        .connect(server_addr, "conformance.test")
        .expect("starting the first connection")
        .await
        .expect("the first handshake completes");
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .expect("opening a stream on the first connection");
    send.write_all(b"first\n").await.expect("writing");
    send.finish().expect("finishing");
    let _ = recv.read_to_end(4096).await;
    // The ticket arrives after the handshake, in its own frame, and is stored
    // when it is processed rather than when the handshake completes. Closing
    // before then leaves nothing to resume from.
    tokio::time::sleep(Duration::from_millis(500)).await;
    connection.close(0u32.into(), b"done");
    client.wait_idle().await;
}

/// A permissive server that accepts the client's first key share and offers
/// early data — the control for the rejecting one.
///
/// Its job is to fail loudly if the *harness* stops producing 0-RTT. Without it,
/// a client that quietly stopped offering early data would make the rejection
/// test pass for the wrong reason: no early data sent, none accepted, assertion
/// satisfied, nothing tested.
fn permissive_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(crate::tls::build_pqc_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h3".to_vec()];
    // No ticketer, for the same reason the real configuration has none: rustls
    // only permits 0-RTT with stateful resumption (RFC 8446 §8.1), and a
    // ticketer switches resumption to the stateless kind that cannot carry it.
    config.max_early_data_size = u32::MAX;
    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .expect("building the QUIC config"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn early_data_is_sent_counted_rejected_and_recovered_from() {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());

    let throwaway = throwaway_cert();
    let counters = Arc::new(Counters::default());

    // The same function the listener calls, so this exercises the shipped
    // configuration rather than a copy of it.
    let crypto =
        crate::tls::zero_rtt_reject_server_config(Arc::new(OneCert(throwaway.key.clone())))
            .expect("building the 0-RTT reject configuration");
    let (server_addr, accepting) = spawn_server(crypto, counters.clone());
    let (client, store) = client_endpoint(&throwaway);

    prime_session(&client, server_addr).await;

    let before = counters.zero_rtt_in();

    // ── Second connection: resume and send early data ──────────────────────
    let connecting = client
        .connect(server_addr, "conformance.test")
        .expect("starting the resumed connection");

    // `into_0rtt` hands the `Connecting` back on failure rather than an error,
    // so there is nothing to report from the `Err` — the diagnosis comes from
    // the session store instead.
    let Ok((connection, accepted)) = connecting.into_0rtt() else {
        panic!(
            "the client had no 0-RTT keys to offer, so nothing was tested. The client stored \
             {} session ticket(s): none means the server issued none, and one or more means \
             it issued a ticket the client would not resume with early data.",
            store.tickets()
        )
    };

    // Written before the handshake resolves — this is the early data.
    let early = connection.open_bi().await;
    if let Ok((mut send, _recv)) = early {
        let _ = send.write_all(b"early\n").await;
        let _ = send.finish();
    }

    // ── The rejection ──────────────────────────────────────────────────────
    let accepted = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .expect("the handshake resolves");
    assert!(
        !accepted,
        "early data was ACCEPTED. This port answers with a HelloRetryRequest precisely so \
         that it cannot be — RFC 8446 §4.2.10 rejects 0-RTT whenever one is sent — so an \
         acceptance means the key-exchange groups no longer force the retry and the test \
         port is quietly not testing anything."
    );

    // ── The evidence the live verdict is built on ──────────────────────────
    let counted = counters.zero_rtt_in() - before;
    assert!(
        counted > 0,
        "no 0-RTT packet was counted, though the client demonstrably sent early data. The \
         live verdict reads this counter to tell a client whose early data was refused from \
         one that never tried, so a zero here would score every client as not exercised."
    );

    // ── The recovery §4.6.2 requires ───────────────────────────────────────
    let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
        .await
        .expect("opening a stream after the rejection does not hang")
        .expect("the connection survives its early data being refused");
    send.write_all(b"retried\n").await.expect("writing");
    send.finish().expect("finishing");
    let answer = tokio::time::timeout(Duration::from_secs(10), recv.read_to_end(4096))
        .await
        .expect("the answer arrives")
        .expect("the request completes on the 1-RTT keys");
    assert_eq!(answer, b"answered\n");

    connection.close(0u32.into(), b"done");
    client.wait_idle().await;
    accepting.abort();
}

/// The control: the same client, against a server that has no reason to refuse.
///
/// If this fails, the harness is not producing early data and the rejection test
/// above is proving nothing — so it is the first thing to read when that one
/// starts passing suspiciously easily.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_harness_really_does_send_early_data() {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    let throwaway = throwaway_cert();
    let counters = Arc::new(Counters::default());
    let crypto = permissive_server_config(Arc::new(OneCert(throwaway.key.clone())));

    let (server_addr, accepting) = spawn_server(crypto, counters.clone());
    let (client, store) = client_endpoint(&throwaway);

    prime_session(&client, server_addr).await;
    let before = counters.zero_rtt_in();

    let (connection, accepted) = client
        .connect(server_addr, "conformance.test")
        .expect("starting the resumed connection")
        .into_0rtt()
        .unwrap_or_else(|_| {
            panic!(
                "the client offered no early data even to a server that welcomes it, so the \
                 rejection test cannot be proving anything either. The client stored {} \
                 session ticket(s).",
                store.tickets()
            )
        });

    if let Ok((mut send, _recv)) = connection.open_bi().await {
        let _ = send.write_all(b"early\n").await;
        let _ = send.finish();
    }

    let accepted = tokio::time::timeout(Duration::from_secs(10), accepted)
        .await
        .expect("the handshake resolves");
    assert!(
        accepted,
        "a server that offers early data and accepts the client's key share still refused \
         it, so the rejection test's result cannot be attributed to the HelloRetryRequest"
    );
    assert!(
        counters.zero_rtt_in() > before,
        "early data was accepted but no 0-RTT packet was counted, so the counter the live \
         verdict reads is not seeing what actually arrives"
    );

    connection.close(0u32.into(), b"done");
    client.wait_idle().await;
    accepting.abort();
}
