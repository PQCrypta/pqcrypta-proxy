//! Proof that the control-stream read-proof answers in both directions.
//!
//! The probe decides, for every correctness test whose anomaly rides the
//! control stream, whether the client actually read it -- which turns 41 cells
//! of "we cannot tell" into verdicts. It does that by filling the client's
//! flow-control window and writing one frame more: the write completes only if
//! MAX_STREAM_DATA arrived, and a receiver sends that only once its
//! application has consumed what it has.
//!
//! Test-only, and for a reason worth stating plainly. Across 708 live verdicts
//! the probe returned "read" every time and "not read" never once. A branch
//! that has never executed is not a working branch -- it is a branch that
//! compiles -- and the claim "this distinguishes read from not-read" cannot
//! rest on evidence from one direction. No client in the fleet declines to
//! read its control stream, so the negative case has to be built rather than
//! waited for.
//!
//! So both are built here: one client that drains its unidirectional streams
//! and one that pointedly does not, against the same server, the same window
//! and the same probe.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::impairment::{Counters, ImpairedSocket, Impairments};
use super::listener::control_stream_was_read;
use super::zero_rtt::{throwaway_cert, OneCert, PinnedTo, Throwaway};

/// Small enough that filling it is quick, large enough to need several frames.
const CLIENT_UNI_WINDOW: u32 = 64 * 1024;

fn server_crypto(throwaway: &Throwaway) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
    let mut config =
        rustls::ServerConfig::builder_with_provider(Arc::new(crate::tls::build_pqc_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
    config.alpn_protocols = vec![b"h3".to_vec()];
    Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .expect("building the QUIC config"),
    )
}

fn client_endpoint(throwaway: &Throwaway) -> quinn::Endpoint {
    let provider = Arc::new(crate::tls::build_pqc_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is available")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTo(throwaway.der.clone(), provider)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("building the QUIC client config"),
    ));
    let mut transport = quinn::TransportConfig::default();
    // The window the probe has to overrun. Pinned rather than left to the
    // default so the test measures the probe and not quinn's tuning.
    transport.stream_receive_window(CLIENT_UNI_WINDOW.into());
    transport.max_idle_timeout(Some(
        Duration::from_secs(10)
            .try_into()
            .expect("10s is a valid idle timeout"),
    ));
    config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .expect("binding a client socket");
    endpoint.set_default_client_config(config);
    endpoint
}

/// Run the probe against a client that either drains its uni streams or does
/// not, and report what the probe concluded.
async fn probe_against(drains_uni_streams: bool) -> Option<bool> {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    let throwaway = throwaway_cert();
    let counters = Arc::new(Counters::default());

    let mut server_config = quinn::ServerConfig::with_crypto(server_crypto(&throwaway));
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

    let server_side = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection arrives");
        let connection = incoming.await.expect("the handshake completes");
        // Stand in for the control stream: a unidirectional stream the server
        // opens and writes to, exactly as `emit` does.
        let mut control = connection
            .open_uni()
            .await
            .expect("opening the control stream");
        control
            .write_all(b"\x00\x04\x00")
            .await
            .expect("writing a SETTINGS-shaped prelude");
        control_stream_was_read("read-proof-self-test", &connection, &mut control).await
    });

    let client = client_endpoint(&throwaway);
    let connection = client
        .connect(addr, "conformance.test")
        .expect("starting the connection")
        .await
        .expect("the handshake completes");

    if drains_uni_streams {
        // What a real HTTP/3 client does: read the control stream as it
        // arrives, which is what extends the flow-control window.
        let draining = connection.clone();
        tokio::spawn(async move {
            while let Ok(mut recv) = draining.accept_uni().await {
                let mut buf = vec![0u8; 16 * 1024];
                while matches!(recv.read(&mut buf).await, Ok(Some(_))) {}
            }
        });
    }
    // Otherwise: accept nothing. The stream arrives, the window fills, and
    // nothing is ever consumed.

    let outcome = server_side.await.expect("the probe task finishes");
    // Hold the connection until the probe has finished, so a `None` can only
    // mean the probe failed rather than the client having gone away.
    drop(connection);
    client.wait_idle().await;
    outcome
}

/// Can the signal move without a read?
///
/// The probe now concludes "read" from this stream's credit rising. That is
/// only sound if nothing else raises it, and the obvious candidate is the
/// client reading something *else*: a client pulling down the response is
/// consuming data and extending credit the whole time. If the probe watched a
/// connection-wide count of MAX_STREAM_DATA frames it would see that and call
/// it a read of the control stream, which is the exact contamination the
/// window-overrun probe did not have and its fast replacement could have
/// introduced.
///
/// So the case is built rather than argued: a client that reads a bidirectional
/// stream enthusiastically and never accepts a unidirectional one. Its credit
/// for the response stream climbs; the control stream's must not.
/// Like `probe_against(false)`, except the client is busy reading a *different*
/// stream throughout -- the case that would fool a connection-wide counter.
async fn probe_with_busy_request_stream() -> Option<bool> {
    let _ = rustls::crypto::CryptoProvider::install_default(crate::tls::build_pqc_provider());
    let throwaway = throwaway_cert();
    let counters = Arc::new(Counters::default());

    let mut server_config = quinn::ServerConfig::with_crypto(server_crypto(&throwaway));
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

    let server_side = tokio::spawn(async move {
        let incoming = server.accept().await.expect("a connection arrives");
        let connection = incoming.await.expect("the handshake completes");

        // Pour data down a bidirectional stream for the whole probe, so the
        // client is continuously consuming and continuously granting credit
        // -- on that stream.
        let busy = connection.clone();
        tokio::spawn(async move {
            if let Ok((mut send, _recv)) = busy.accept_bi().await {
                let chunk = vec![0u8; 8192];
                loop {
                    if send.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            }
        });

        let mut control = connection
            .open_uni()
            .await
            .expect("opening the control stream");
        control
            .write_all(b"\x00\x04\x00")
            .await
            .expect("writing a SETTINGS-shaped prelude");
        control_stream_was_read("credit-elsewhere-self-test", &connection, &mut control).await
    });

    let client = client_endpoint(&throwaway);
    let connection = client
        .connect(addr, "conformance.test")
        .expect("starting the connection")
        .await
        .expect("the handshake completes");

    // Open the bidirectional stream the server will flood, and read it hard.
    // Never accept a unidirectional stream.
    let reader = connection.clone();
    tokio::spawn(async move {
        if let Ok((_send, mut recv)) = reader.open_bi().await {
            let mut buf = vec![0u8; 16 * 1024];
            while matches!(recv.read(&mut buf).await, Ok(Some(_))) {}
        }
    });

    let outcome = server_side.await.expect("the probe task finishes");
    drop(connection);
    client.wait_idle().await;
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credit_granted_on_another_stream_is_not_read_as_a_control_stream_read() {
    assert_eq!(
        probe_with_busy_request_stream().await,
        Some(false),
        "a client reading hard on its request stream extends credit there, and that must \
         not be mistaken for having read the control stream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_reads_the_control_stream_is_seen_to_read_it() {
    assert_eq!(
        probe_against(true).await,
        Some(true),
        "a client draining its unidirectional streams extends flow-control credit, \
         and the probe must report that as read"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_never_reads_the_control_stream_is_seen_not_to() {
    assert_eq!(
        probe_against(false).await,
        Some(false),
        "a client that never accepts a unidirectional stream cannot extend credit, \
         so the window stays full and the probe must report that as not read -- this is \
         the branch that had never once fired in 708 live verdicts"
    );
}
