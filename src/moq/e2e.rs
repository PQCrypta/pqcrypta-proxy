//! The relay end to end over real QUIC connections, in both drafts: a
//! publisher and subscribers that speak the wire directly (the codec only
//! frames bytes; every exchange is the client's own), and the relay as the
//! listener serves it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::BufReader;

use super::codec::{put_vi64, read_vi64, Location, Namespace, TrackName};
use super::data::{
    encode_subgroup_object, read_subgroup_object, Delivery, FetchEntry, FetchState, Object,
    ObjectStatus, SubgroupHeader, SubgroupIdMode, STREAM_FETCH_HEADER,
};
use super::message::{
    self, read_frame, Context, GroupOrder, LocationFilter, Message, Params, PrefixRequest, Publish,
    Setup, Token, TrackRequest,
};
use super::version::Version;
use super::Moq;
use crate::config::MoqConfig;
use crate::conformance::zero_rtt::{throwaway_cert, OneCert, PinnedTo};

const KEY: &str = "e2e-publish-key";
const WAIT: Duration = Duration::from_secs(5);

type Served = (
    quinn::Endpoint,
    Arc<Moq>,
    tokio::task::JoinHandle<()>,
    Vec<u8>,
);

/// A relay on a loopback port, serving every MOQT version.
async fn relay() -> Served {
    let moq = Moq::new(&MoqConfig {
        enabled: true,
        publish_key: Some(KEY.into()),
        ..MoqConfig::default()
    })
    .expect("the relay");
    serve(moq)
}

/// `moq` served on a loopback port, with a throwaway certificate.
fn serve(moq: Arc<Moq>) -> Served {
    let (server, cert) = server_endpoint();
    let accept = {
        let server = server.clone();
        let moq = Arc::clone(&moq);
        tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(serve_one(Arc::clone(&moq), incoming));
            }
        })
    };
    (server, moq, accept, cert)
}

/// One connection served as the listener serves it.
async fn serve_one(moq: Arc<Moq>, incoming: quinn::Incoming) {
    let peer = incoming.remote_address();
    let Ok(conn) = incoming.await else { return };
    let alpn = conn
        .handshake_data()
        .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol)
        .unwrap_or_default();
    moq.serve_quic(conn, &alpn, peer).await;
}

/// A loopback QUIC server offering every MOQT version, and its certificate.
fn server_endpoint() -> (quinn::Endpoint, Vec<u8>) {
    let throwaway = throwaway_cert();
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3")
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
    crypto.alpn_protocols = Version::alpns();
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).expect("QUIC server config"),
        )),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("a server port");
    (server, throwaway.der.to_vec())
}

/// A client endpoint that trusts the relay's certificate and offers `alpns`.
fn client_endpoint(cert: &[u8], alpns: Vec<Vec<u8>>) -> quinn::Endpoint {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTo(cert.to_vec().into(), provider)))
        .with_no_client_auth();
    crypto.alpn_protocols = alpns;
    let client =
        quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a client port");
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).expect("QUIC client config"),
    )));
    client
}

/// One MOQT client session, speaking the wire itself.
struct Client {
    conn: quinn::Connection,
    v: Version,
    _control: quinn::SendStream,
    server_setup: Setup,
    next_id: u64,
}

impl Client {
    async fn connect(server: &quinn::Endpoint, cert: &[u8], v: Version, setup: Setup) -> Self {
        let ep = client_endpoint(cert, vec![v.alpn().as_bytes().to_vec()]);
        Self::connect_over(&ep, server.local_addr().unwrap(), "localhost", v, setup).await
    }

    /// A session to `addr` (as `name`) through `ep`, whose client
    /// configuration offers `v`.
    async fn connect_over(
        ep: &quinn::Endpoint,
        addr: SocketAddr,
        name: &str,
        v: Version,
        setup: Setup,
    ) -> Self {
        let conn = ep
            .connect(addr, name)
            .unwrap()
            .await
            .expect("the handshake");
        let mut control = conn.open_uni().await.unwrap();
        control
            .write_all(&Message::Setup(setup).encode(v))
            .await
            .unwrap();
        let recv = tokio::time::timeout(WAIT, conn.accept_uni())
            .await
            .expect("the server's control stream")
            .unwrap();
        let mut recv = BufReader::new(recv);
        let (kind, body) = read_frame(&mut recv, v, 1 << 20)
            .await
            .ok()
            .flatten()
            .expect("SETUP");
        assert_eq!(kind, message::SETUP);
        let server_setup = Setup::decode(&body, v).expect("the server's SETUP");
        // The server's control stream stays open for GOAWAY
        tokio::spawn(async move {
            let mut r = recv;
            while let Ok(Some(_)) = read_frame(&mut r, v, 1 << 20).await {}
        });
        Self {
            conn,
            v,
            _control: control,
            server_setup,
            next_id: 0,
        }
    }

    /// A session the relay is expected to refuse: SETUP is sent, and the
    /// relay's own SETUP may or may not arrive before its close.
    async fn connect_refused(
        server: &quinn::Endpoint,
        cert: &[u8],
        v: Version,
        setup: Setup,
    ) -> quinn::Connection {
        let ep = client_endpoint(cert, vec![v.alpn().as_bytes().to_vec()]);
        let conn = ep
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .expect("the handshake");
        let mut control = conn.open_uni().await.unwrap();
        control
            .write_all(&Message::Setup(setup).encode(v))
            .await
            .unwrap();
        // The stream stays open until the relay closes the session
        std::mem::forget(control);
        conn
    }

    fn id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 2;
        id
    }

    /// Open a request stream with `m`; the response's first message.
    async fn request(
        &self,
        m: Message,
    ) -> (
        quinn::SendStream,
        BufReader<quinn::RecvStream>,
        u64,
        Message,
    ) {
        let (mut send, recv) = self.conn.open_bi().await.unwrap();
        send.write_all(&m.encode(self.v)).await.unwrap();
        let mut recv = BufReader::new(recv);
        let (kind, body) = tokio::time::timeout(WAIT, read_frame(&mut recv, self.v, 1 << 20))
            .await
            .expect("an answer in time")
            .ok()
            .flatten()
            .expect("an answer");
        let ctx = Context {
            ok_allows: message::allowed::ok_with_largest(),
            ok_properties: true,
            ..Context::default()
        };
        let decoded = Message::decode(kind, &body, self.v, &ctx).expect("a well-formed answer");
        (send, recv, kind, decoded)
    }

    /// The session's close code, once the relay closes it.
    async fn closed_with(&self) -> u64 {
        match tokio::time::timeout(WAIT, self.conn.closed())
            .await
            .expect("the relay closes the session")
        {
            quinn::ConnectionError::ApplicationClosed(c) => c.error_code.into_inner(),
            other => panic!("closed otherwise: {other}"),
        }
    }
}

/// The code a refused session was closed with.
async fn closed_code(conn: &quinn::Connection) -> u64 {
    match tokio::time::timeout(WAIT, conn.closed())
        .await
        .expect("the relay closes the session")
    {
        quinn::ConnectionError::ApplicationClosed(c) => c.error_code.into_inner(),
        other => panic!("closed otherwise: {other}"),
    }
}

fn ns(fields: &[&'static [u8]]) -> Namespace {
    Namespace(fields.iter().map(|f| Bytes::from_static(f)).collect())
}

fn track() -> TrackName {
    TrackName {
        namespace: ns(&[b"music", b"e2e"]),
        name: Bytes::from_static(b"audio"),
    }
}

fn token_for(prefix: &Namespace) -> Token {
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600;
    let value = super::auth::PublishAuth::new(KEY.as_bytes()).issue(prefix, expiry);
    Token::UseValue {
        kind: 0,
        value: Bytes::from(value),
    }
}

fn object(g: u64, o: u64, payload: &'static [u8]) -> Object {
    Object {
        location: Location::new(g, o),
        delivery: Delivery::Subgroup(0),
        priority: 64,
        status: ObjectStatus::Normal,
        properties: Bytes::new(),
        payload: Bytes::from_static(payload),
    }
}

/// Send `objects` (one group, subgroup 0) on a new stream, then FIN.
async fn send_subgroup(conn: &quinn::Connection, alias: u64, group: u64, objects: &[Object]) {
    let mut s = conn.open_uni().await.unwrap();
    let header = SubgroupHeader {
        track_alias: alias,
        group,
        subgroup: SubgroupIdMode::Zero,
        priority: Some(64),
        properties: false,
        end_of_group: false,
        first_object: true,
    };
    let mut wire = Vec::new();
    header.encode(&mut wire);
    let mut prior = None;
    for o in objects {
        encode_subgroup_object(&mut wire, prior, o, false);
        prior = Some(o.location.object);
    }
    s.write_all(&wire).await.unwrap();
    s.finish().unwrap();
}

/// Read one subgroup stream the relay opened: its alias, group and objects.
async fn receive_subgroup(conn: &quinn::Connection) -> (u64, u64, Vec<(u64, Bytes)>) {
    let recv = tokio::time::timeout(WAIT, conn.accept_uni())
        .await
        .expect("a subgroup stream")
        .unwrap();
    let mut r = BufReader::new(recv);
    let flags = read_vi64(&mut r).await.unwrap().unwrap();
    let header = SubgroupHeader::read(flags, &mut r)
        .await
        .expect("a SUBGROUP_HEADER");
    let mut out = Vec::new();
    let mut prior = None;
    while let Some((id, _status, _props, payload)) =
        read_subgroup_object(&mut r, &header, prior, 1 << 20)
            .await
            .unwrap()
    {
        prior = Some(id);
        out.push((id, payload));
    }
    (header.track_alias, header.group, out)
}

#[tokio::test]
async fn published_objects_reach_a_subscriber_and_a_fetch_in_both_drafts() {
    let (server, _moq, _accept, cert) = relay().await;
    for v in Version::ALL {
        let t = TrackName {
            namespace: Namespace(vec![Bytes::from_static(b"music"), Bytes::from(v.alpn())]),
            name: Bytes::from_static(b"audio"),
        };
        let mut publisher = Client::connect(&server, &cert, v, Setup::default()).await;
        let id = publisher.id();
        let (_pub_send, _pub_recv, kind, _) = publisher
            .request(Message::Publish(Publish {
                request_id: id,
                track: t.clone(),
                track_alias: 9,
                params: Params {
                    auth_tokens: vec![token_for(&t.namespace)],
                    ..Params::default()
                },
                properties: Bytes::new(),
            }))
            .await;
        assert_eq!(kind, message::REQUEST_OK, "{v}: PUBLISH_OK");

        let mut subscriber = Client::connect(&server, &cert, v, Setup::default()).await;
        assert!(subscriber
            .server_setup
            .implementation
            .as_deref()
            .unwrap_or("")
            .starts_with("pqcrypta-proxy/"));
        let id = subscriber.id();
        let (_s, _r, kind, ok) = subscriber
            .request(Message::Subscribe(TrackRequest {
                request_id: id,
                track: t.clone(),
                params: Params::default(),
            }))
            .await;
        assert_eq!(kind, message::SUBSCRIBE_OK, "{v}");
        let Message::SubscribeOk { track_alias, .. } = ok else {
            unreachable!()
        };

        let objects = [
            object(0, 0, b"zero"),
            object(0, 1, b"one"),
            object(0, 2, b"two"),
        ];
        send_subgroup(&publisher.conn, 9, 0, &objects).await;
        let (alias, group, got) = receive_subgroup(&subscriber.conn).await;
        assert_eq!((alias, group), (track_alias, 0), "{v}");
        assert_eq!(
            got.iter().map(|(i, p)| (*i, p.clone())).collect::<Vec<_>>(),
            objects
                .iter()
                .map(|o| (o.location.object, o.payload.clone()))
                .collect::<Vec<_>>(),
            "{v}"
        );

        // A FETCH of the same range is served from the relay's cache
        let mut fetcher = Client::connect(&server, &cert, v, Setup::default()).await;
        let id = fetcher.id();
        let (_s, _r, kind, ok) = fetcher
            .request(Message::Fetch(TrackRequest {
                request_id: id,
                track: t.clone(),
                params: Params {
                    location_filter: Some(LocationFilter::AbsoluteRange {
                        start: Location::new(0, 0),
                        end: Location::new(0, 2),
                    }),
                    ..Params::default()
                },
            }))
            .await;
        if v.fetch_ok_is_request_ok() {
            assert_eq!(kind, message::REQUEST_OK, "{v}");
            let Message::RequestOk { params, .. } = ok else {
                unreachable!()
            };
            assert_eq!(
                params.largest_object,
                Some(Location::new(0, 2)),
                "LARGEST_OBJECT is within the range"
            );
        } else {
            assert_eq!(kind, message::FETCH_OK_22, "{v}");
        }
        let recv = tokio::time::timeout(WAIT, fetcher.conn.accept_uni())
            .await
            .unwrap()
            .unwrap();
        let mut r = BufReader::new(recv);
        assert_eq!(read_vi64(&mut r).await.unwrap(), Some(STREAM_FETCH_HEADER));
        assert_eq!(read_vi64(&mut r).await.unwrap(), Some(id));
        let mut state = FetchState::default();
        let mut fetched = Vec::new();
        while let Some(e) = state
            .read(&mut r, GroupOrder::Ascending, v, 1 << 20)
            .await
            .unwrap()
        {
            if let FetchEntry::Object(o) = e {
                fetched.push(o.payload);
            }
        }
        assert_eq!(
            fetched,
            objects
                .iter()
                .map(|o| o.payload.clone())
                .collect::<Vec<_>>(),
            "{v}"
        );
    }
}

#[tokio::test]
async fn a_request_id_of_the_wrong_parity_or_used_twice_closes_the_session() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let c = Client::connect(&server, &cert, v, Setup::default()).await;
    let (mut s, _r) = c.conn.open_bi().await.unwrap();
    s.write_all(
        &Message::TrackStatus(TrackRequest {
            request_id: 1,
            track: track(),
            params: Params::default(),
        })
        .encode(v),
    )
    .await
    .unwrap();
    assert_eq!(c.closed_with().await, 0x4, "INVALID_REQUEST_ID");

    let mut c = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = c.id();
    let _ = c
        .request(Message::TrackStatus(TrackRequest {
            request_id: id,
            track: track(),
            params: Params::default(),
        }))
        .await;
    let (mut s, _r) = c.conn.open_bi().await.unwrap();
    s.write_all(
        &Message::TrackStatus(TrackRequest {
            request_id: id,
            track: track(),
            params: Params::default(),
        })
        .encode(v),
    )
    .await
    .unwrap();
    assert_eq!(
        c.closed_with().await,
        0x4,
        "a duplicate is INVALID_REQUEST_ID"
    );
}

#[tokio::test]
async fn a_request_stream_that_opens_with_no_request_is_unexpected() {
    let (server, _moq, _accept, cert) = relay().await;
    for (v, code) in [(Version::Draft23, 0x303), (Version::Draft22, 0x3)] {
        let c = Client::connect(&server, &cert, v, Setup::default()).await;
        let (mut s, _r) = c.conn.open_bi().await.unwrap();
        s.write_all(
            &Message::Goaway {
                uri: Bytes::new(),
                timeout_ms: 0,
            }
            .encode(v),
        )
        .await
        .unwrap();
        assert_eq!(c.closed_with().await, code, "{v}");
    }
}

#[tokio::test]
async fn publishing_needs_a_token_for_the_namespace() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let mut c = Client::connect(&server, &cert, v, Setup::default()).await;
    for params in [
        Params::default(),
        Params {
            auth_tokens: vec![token_for(&ns(&[b"other"]))],
            ..Params::default()
        },
    ] {
        let id = c.id();
        let (_s, _r, kind, m) = c
            .request(Message::Publish(Publish {
                request_id: id,
                track: track(),
                track_alias: id + 1,
                params,
                properties: Bytes::new(),
            }))
            .await;
        assert_eq!(kind, message::REQUEST_ERROR);
        let Message::RequestError(e) = m else {
            unreachable!()
        };
        assert_eq!(e.code, 0x1, "UNAUTHORIZED");
    }
    // A token in SETUP authorizes the session's requests
    let setup = Setup {
        auth_tokens: vec![token_for(&ns(&[b"music"]))],
        ..Setup::default()
    };
    let mut c = Client::connect(&server, &cert, v, setup).await;
    let id = c.id();
    let (_s, _r, kind, _) = c
        .request(Message::PublishNamespace(PrefixRequest {
            request_id: id,
            prefix: ns(&[b"music", b"e2e"]),
            params: Params::default(),
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);
}

#[tokio::test]
async fn namespace_subscribers_hear_advertisements_and_subscriptions_reach_the_publisher() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let mut watcher = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = watcher.id();
    let (_ws, mut wr, kind, _) = watcher
        .request(Message::SubscribeNamespace(PrefixRequest {
            request_id: id,
            prefix: ns(&[b"music"]),
            params: Params::default(),
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);

    let mut publisher = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = publisher.id();
    let prefix = ns(&[b"music", b"e2e"]);
    let (_ps, _pr, kind, _) = publisher
        .request(Message::PublishNamespace(PrefixRequest {
            request_id: id,
            prefix: prefix.clone(),
            params: Params {
                auth_tokens: vec![token_for(&prefix)],
                ..Params::default()
            },
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);
    let (kind, body) = tokio::time::timeout(WAIT, read_frame(&mut wr, v, 1 << 20))
        .await
        .unwrap()
        .ok()
        .flatten()
        .unwrap();
    assert_eq!(kind, message::NAMESPACE);
    let Message::Namespace { suffix, .. } =
        Message::decode(kind, &body, v, &Context::default()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(suffix, ns(&[b"e2e"]));

    // A SUBSCRIBE for a track in the namespace goes to the publisher
    let pub_conn = publisher.conn.clone();
    let serve_publisher = tokio::spawn(async move {
        let (mut send, recv) = tokio::time::timeout(WAIT, pub_conn.accept_bi())
            .await
            .unwrap()
            .unwrap();
        let mut recv = BufReader::new(recv);
        let (kind, body) = read_frame(&mut recv, v, 1 << 20)
            .await
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(kind, message::SUBSCRIBE);
        let Message::Subscribe(req) = Message::decode(kind, &body, v, &Context::default()).unwrap()
        else {
            unreachable!()
        };
        assert_eq!(req.request_id % 2, 1, "the relay's requests are odd");
        let ok = Message::SubscribeOk {
            track_alias: 4,
            params: Params::default(),
            properties: Bytes::new(),
        };
        send.write_all(&ok.encode(v)).await.unwrap();
        send_subgroup(&pub_conn, 4, 7, &[object(7, 0, b"live")]).await;
        // Hold the subscription open
        tokio::time::sleep(WAIT).await;
        drop(send);
    });
    let mut subscriber = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = subscriber.id();
    let (_s, _r, kind, _) = subscriber
        .request(Message::Subscribe(TrackRequest {
            request_id: id,
            track: track(),
            params: Params::default(),
        }))
        .await;
    assert_eq!(kind, message::SUBSCRIBE_OK);
    let (_alias, group, got) = receive_subgroup(&subscriber.conn).await;
    assert_eq!(group, 7);
    assert_eq!(got, vec![(0, Bytes::from_static(b"live"))]);
    serve_publisher.abort();
}

#[tokio::test]
async fn a_subscribe_with_no_publisher_is_refused_at_once_or_after_the_rendezvous() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let mut c = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = c.id();
    let (_s, _r, kind, m) = c
        .request(Message::Subscribe(TrackRequest {
            request_id: id,
            track: track(),
            params: Params::default(),
        }))
        .await;
    assert_eq!(kind, message::REQUEST_ERROR);
    let Message::RequestError(e) = m else {
        unreachable!()
    };
    assert_eq!(e.code, 0x10, "DOES_NOT_EXIST with no RENDEZVOUS_TIMEOUT");

    let id = c.id();
    let started = std::time::Instant::now();
    let (_s, _r, _, m) = c
        .request(Message::Subscribe(TrackRequest {
            request_id: id,
            track: track(),
            params: Params {
                rendezvous_timeout: Some(300),
                ..Params::default()
            },
        }))
        .await;
    let Message::RequestError(e) = m else {
        panic!("{m:?}")
    };
    assert_eq!(e.code, 0x2, "TIMEOUT after the rendezvous");
    assert!(started.elapsed() >= Duration::from_millis(250));
}

#[tokio::test]
async fn the_reserved_namespace_does_not_exist() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let mut client = Client::connect(&server, &cert, v, Setup::default()).await;
    for first in [&b"."[..], b".session"] {
        let id = client.id();
        let name = TrackName {
            namespace: Namespace(vec![Bytes::copy_from_slice(first)]),
            name: Bytes::from_static(b"x"),
        };
        let (_s, _r, kind, answer) = client
            .request(Message::TrackStatus(TrackRequest {
                request_id: id,
                track: name,
                params: Params::default(),
            }))
            .await;
        assert_eq!(kind, message::REQUEST_ERROR);
        let Message::RequestError(error) = answer else {
            unreachable!()
        };
        assert_eq!(error.code, 0x10);
    }
}

/// A client that offers no version the relay speaks is refused in the
/// handshake with no_application_protocol (RFC 9001 section 8.1), promptly:
/// whether its ClientHello fits one Initial packet (X25519 alone) or spans
/// two (the hybrid post-quantum key share).
#[tokio::test]
async fn an_unknown_alpn_is_refused_in_the_handshake() {
    let (server, _moq, _accept, cert) = relay().await;
    // The server's own groups less the hybrid ones: a classical key share
    // keeps the ClientHello within one Initial packet
    let default = rustls::crypto::aws_lc_rs::default_provider();
    let classical = rustls::crypto::CryptoProvider {
        kx_groups: default
            .kx_groups
            .iter()
            .copied()
            .filter(|g| !format!("{:?}", g.name()).contains("MLKEM"))
            .collect(),
        ..default
    };
    for (name, provider) in [
        ("one Initial packet", Arc::new(classical)),
        (
            "two Initial packets",
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        ),
    ] {
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedTo(cert.clone().into(), provider)))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"moqt-99".to_vec()];
        let ep = quinn::Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        )));
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            WAIT,
            ep.connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
        )
        .await;
        let Ok(outcome) = outcome else {
            panic!("{name}: no answer within {WAIT:?}: the refusal was never sent");
        };
        let Err(err) = outcome else {
            panic!("{name}: a MOQT-less ALPN was accepted");
        };
        // no_application_protocol (alert 120) as a CRYPTO_ERROR (0x100 + 120)
        let refused = matches!(
            &err,
            quinn::ConnectionError::ConnectionClosed(c)
                if c.error_code == quinn::TransportErrorCode::crypto(120)
        );
        assert!(
            refused,
            "{name}: refused otherwise, after {:?}: {err:?}",
            started.elapsed()
        );
    }
}

/// A session whose future is dropped part way (the WebTransport CONNECT task
/// drops it when the CONNECT stream ends, or the close the session asked for
/// goes out, first) is still unregistered and counted out: before, it stayed
/// in /moq/sessions and sessions_open for good (2026-11-23)
#[tokio::test]
async fn a_session_dropped_part_way_is_still_ended() {
    let moq = Moq::new(&MoqConfig {
        enabled: true,
        publish_key: Some(KEY.into()),
        ..MoqConfig::default()
    })
    .expect("the relay");
    let (server, cert) = server_endpoint();
    let incoming = {
        let server = server.clone();
        tokio::spawn(async move { server.accept().await.expect("a connection") })
    };
    let client = tokio::spawn({
        let server = server.clone();
        let cert = cert.clone();
        async move { Client::connect(&server, &cert, Version::Draft23, Setup::default()).await }
    });
    let session = tokio::spawn(serve_one(Arc::clone(&moq), incoming.await.unwrap()));
    let _client = client.await.unwrap();
    assert_eq!(moq.relay.sessions().len(), 1, "the session is registered");
    assert_eq!(moq.snapshot().sessions_open, 1);

    session.abort();
    let _ = session.await;
    assert!(
        moq.relay.sessions().is_empty(),
        "a dropped session is unregistered"
    );
    assert_eq!(moq.snapshot().sessions_open, 0, "and counted out");
}

/// A peer that ends its session (here its whole connection) takes its
/// control stream with it: that is the session's end, not the
/// CLOSED_CONTROL_STREAM error, and no session error is counted
#[tokio::test]
async fn a_session_that_ends_is_no_closed_control_stream_error() {
    let (server, moq, _accept, cert) = relay().await;
    let c = Client::connect(&server, &cert, Version::Draft23, Setup::default()).await;
    assert_eq!(moq.snapshot().sessions_open, 1);
    c.conn.close(0u32.into(), b"done");
    for _ in 0..100 {
        if moq.snapshot().sessions_open == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let s = moq.snapshot();
    assert_eq!(s.sessions_open, 0, "the session ended");
    assert_eq!(s.session_errors, 0, "and not as a session error");
}

#[tokio::test]
async fn a_second_control_stream_and_an_unknown_stream_type_close_the_session() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let c = Client::connect(&server, &cert, v, Setup::default()).await;
    let mut s = c.conn.open_uni().await.unwrap();
    s.write_all(&Message::Setup(Setup::default()).encode(v))
        .await
        .unwrap();
    assert_eq!(
        c.closed_with().await,
        0x303,
        "a second control stream is UNEXPECTED_MESSAGE"
    );

    let c = Client::connect(&server, &cert, v, Setup::default()).await;
    let mut s = c.conn.open_uni().await.unwrap();
    let mut w = Vec::new();
    put_vi64(&mut w, 0x7777);
    s.write_all(&w).await.unwrap();
    assert_eq!(c.closed_with().await, 0x200, "INVALID_STREAM_HEADER");
}

#[tokio::test]
async fn path_and_authority_from_a_native_client_are_checked() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let ok = Setup {
        path: Some(Bytes::from_static(b"/moq")),
        authority: Some(Bytes::from_static(b"localhost:443")),
        ..Setup::default()
    };
    let c = Client::connect(&server, &cert, v, ok).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), c.conn.closed())
            .await
            .is_err(),
        "a served PATH is accepted"
    );

    let bad = Setup {
        path: Some(Bytes::from_static(b"/elsewhere")),
        ..Setup::default()
    };
    let conn = Client::connect_refused(&server, &cert, v, bad).await;
    assert_eq!(closed_code(&conn).await, 0x8, "INVALID_PATH");

    let malformed = Setup {
        path: Some(Bytes::from_static(b"no-slash")),
        ..Setup::default()
    };
    let conn = Client::connect_refused(&server, &cert, v, malformed).await;
    assert_eq!(closed_code(&conn).await, 0x9, "MALFORMED_PATH");

    let malformed = Setup {
        authority: Some(Bytes::from_static(b"a/b")),
        ..Setup::default()
    };
    let conn = Client::connect_refused(&server, &cert, v, malformed).await;
    assert_eq!(closed_code(&conn).await, 0x1A, "MALFORMED_AUTHORITY");
}

/// Two relays as one (section 7): a subscriber at the edge gets a track
/// published at the origin through the edge's upstream session, and a FETCH
/// at the edge for objects only the origin holds is filled from upstream.
/// A publisher of a finished track, as the music origin is: the relay's
/// SUBSCRIBE is answered with the track's Largest Object and ended at once
/// (PUBLISH_DONE, the track complete), and each FETCH from its objects.
async fn serve_finished_track(conn: quinn::Connection, v: Version, objects: Vec<Object>) {
    while let Ok(Ok((mut send, recv))) = tokio::time::timeout(WAIT, conn.accept_bi()).await {
        let conn = conn.clone();
        let objects = objects.clone();
        tokio::spawn(async move {
            let mut recv = BufReader::new(recv);
            let Some((kind, body)) = read_frame(&mut recv, v, 1 << 20).await.ok().flatten() else {
                return;
            };
            match Message::decode(kind, &body, v, &Context::default()).unwrap() {
                Message::Subscribe(_) => {
                    let ok = Message::SubscribeOk {
                        track_alias: 5,
                        params: Params {
                            largest_object: objects.last().map(|o| o.location),
                            ..Params::default()
                        },
                        properties: Bytes::new(),
                    };
                    send.write_all(&ok.encode(v)).await.unwrap();
                    let done = Message::PublishDone {
                        status: super::error::DoneCode::TrackEnded as u64,
                        stream_count: 0,
                        reason: "the track is complete".into(),
                    };
                    send.write_all(&done.encode(v)).await.unwrap();
                    let _ = send.finish();
                }
                Message::Fetch(req) => {
                    let (start, end) = req
                        .params
                        .location_filter
                        .expect("a range")
                        .bounds(objects.last().map(|o| o.location));
                    let end = end.expect("an end");
                    let ok = Message::RequestOk {
                        params: Params::default(),
                        properties: Bytes::new(),
                    };
                    send.write_all(&ok.encode(v)).await.unwrap();
                    let mut out = conn.open_uni().await.unwrap();
                    let mut buf = Vec::new();
                    put_vi64(&mut buf, STREAM_FETCH_HEADER);
                    put_vi64(&mut buf, req.request_id);
                    let mut state = FetchState::default();
                    for o in objects
                        .iter()
                        .filter(|o| start <= o.location && o.location <= end)
                    {
                        state.encode(
                            &mut buf,
                            &FetchEntry::Object(o.clone()),
                            GroupOrder::Ascending,
                            v,
                        );
                    }
                    out.write_all(&buf).await.unwrap();
                    let _ = out.finish();
                    let _ = send.finish();
                }
                _ => {}
            }
        });
    }
}

/// FETCH `start..=end` of `t` at the relay: the payloads, in order, of every
/// entry, an End of Range as its kind.
async fn fetch_all(
    server: &quinn::Endpoint,
    cert: &[u8],
    v: Version,
    t: &TrackName,
    start: Location,
    end: Location,
) -> Vec<Result<Bytes, String>> {
    let mut fetcher = Client::connect(server, cert, v, Setup::default()).await;
    let id = fetcher.id();
    let (_fs, _fr, kind, _) = fetcher
        .request(Message::Fetch(TrackRequest {
            request_id: id,
            track: t.clone(),
            params: Params {
                location_filter: Some(LocationFilter::AbsoluteRange { start, end }),
                ..Params::default()
            },
        }))
        .await;
    // Draft 22 answers a FETCH with FETCH_OK; 23 with REQUEST_OK
    let answered = if v.fetch_ok_is_request_ok() {
        message::REQUEST_OK
    } else {
        message::FETCH_OK_22
    };
    assert_eq!(kind, answered, "{v}");
    let recv = tokio::time::timeout(WAIT, fetcher.conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let mut r = BufReader::new(recv);
    assert_eq!(read_vi64(&mut r).await.unwrap(), Some(STREAM_FETCH_HEADER));
    assert_eq!(read_vi64(&mut r).await.unwrap(), Some(id));
    let mut state = FetchState::default();
    let mut entries = Vec::new();
    while let Some(e) =
        tokio::time::timeout(WAIT, state.read(&mut r, GroupOrder::Ascending, v, 1 << 20))
            .await
            .unwrap()
            .unwrap()
    {
        entries.push(match e {
            FetchEntry::Object(o) => Ok(o.payload),
            other => Err(format!("{other:?}")),
        });
    }
    entries
}

/// A FETCH past what the relay has cached of a finished track is filled
/// from the publisher that advertised its namespace, though the relay's
/// subscription to the track has ended: /music/'s songs came back with
/// every group the cache lacked marked Unknown, once each song's first
/// group was cached and its upstream subscription had ended (0.22.1).
#[tokio::test]
async fn a_fetch_past_the_cache_is_filled_by_the_namespace_s_publisher() {
    let (server, moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let t = track();
    let mut publisher = Client::connect(&server, &cert, v, Setup::default()).await;
    let id = publisher.id();
    let (_ps, _pr, kind, _) = publisher
        .request(Message::PublishNamespace(PrefixRequest {
            request_id: id,
            prefix: t.namespace.clone(),
            params: Params {
                auth_tokens: vec![token_for(&t.namespace)],
                ..Params::default()
            },
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);
    const PAYLOADS: [&[u8]; 9] = [
        b"a0", b"a1", b"a2", b"b0", b"b1", b"b2", b"c0", b"c1", b"c2",
    ];
    let objects: Vec<Object> = PAYLOADS
        .iter()
        .enumerate()
        .map(|(i, p)| object(i as u64 / 3, i as u64 % 3, p))
        .collect();
    let serving = tokio::spawn(serve_finished_track(
        publisher.conn.clone(),
        v,
        objects.clone(),
    ));

    // The first group: the relay learns the track and caches it
    let first = fetch_all(
        &server,
        &cert,
        v,
        &t,
        Location::new(0, 0),
        Location::new(0, 2),
    )
    .await;
    assert_eq!(
        first,
        PAYLOADS[..3]
            .iter()
            .map(|p| Ok(Bytes::from_static(p)))
            .collect::<Vec<_>>()
    );
    // The upstream subscription has ended with the track
    let tracked = moq.relay.existing(&t).expect("the relay knows the track");
    let deadline = tokio::time::Instant::now() + WAIT;
    while tracked.has_publisher() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the subscription ended"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The whole track: the cached group, and the rest from the publisher
    let all = fetch_all(
        &server,
        &cert,
        v,
        &t,
        Location::new(0, 0),
        Location::new(2, 2),
    )
    .await;
    assert_eq!(
        all,
        PAYLOADS
            .iter()
            .map(|p| Ok(Bytes::from_static(p)))
            .collect::<Vec<_>>(),
        "every object, none marked Unknown"
    );
    serving.abort();
}

/// PUBLISH_NAMESPACE `prefix`, with its token: the answer's message type,
/// and the request's streams, which the advertisement lasts as long as
async fn advertise(
    publisher: &mut Client,
    prefix: &Namespace,
) -> (u64, (quinn::SendStream, BufReader<quinn::RecvStream>)) {
    let id = publisher.id();
    let (send, recv, kind, _) = publisher
        .request(Message::PublishNamespace(PrefixRequest {
            request_id: id,
            prefix: prefix.clone(),
            params: Params {
                auth_tokens: vec![token_for(prefix)],
                ..Params::default()
            },
        }))
        .await;
    (kind, (send, recv))
}

/// A publisher that restarted advertises again from a new session while its
/// old one, gone without a close, is listed until its idle timeout: a FETCH
/// goes on at the publisher that answers, the newest first, rather than
/// waiting on the silent one (the music origin's restart, 2026-11-24: every
/// first FETCH of a song waited 15 s, then came back empty).
#[tokio::test]
async fn a_silent_publisher_of_the_namespace_does_not_hold_a_fetch() {
    let (server, _moq, _accept, cert) = relay().await;
    let v = Version::Draft23;
    let t = track();
    // The old session: advertised, then answers nothing and never closes
    let mut silent = Client::connect(&server, &cert, v, Setup::default()).await;
    let (kind, _silent_request) = advertise(&mut silent, &t.namespace).await;
    assert_eq!(kind, message::REQUEST_OK);
    // The new one, which answers
    let mut publisher = Client::connect(&server, &cert, v, Setup::default()).await;
    let (kind, _request) = advertise(&mut publisher, &t.namespace).await;
    assert_eq!(kind, message::REQUEST_OK);
    const PAYLOADS: [&[u8]; 4] = [b"a0", b"a1", b"b0", b"b1"];
    let objects: Vec<Object> = PAYLOADS
        .iter()
        .enumerate()
        .map(|(i, p)| object(i as u64 / 2, i as u64 % 2, p))
        .collect();
    let serving = tokio::spawn(serve_finished_track(publisher.conn.clone(), v, objects));

    let started = tokio::time::Instant::now();
    let all = fetch_all(
        &server,
        &cert,
        v,
        &t,
        Location::new(0, 0),
        Location::new(1, 1),
    )
    .await;
    assert_eq!(
        all,
        PAYLOADS
            .iter()
            .map(|p| Ok(Bytes::from_static(p)))
            .collect::<Vec<_>>(),
        "every object, from the publisher that answers"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the FETCH waited {:?} on the silent publisher",
        started.elapsed()
    );
    serving.abort();
    drop(silent);
}

/// A publisher that serves a SUBSCRIBE from group 2 and refuses every FETCH
/// (REQUEST_ERROR), as moq-dev's relay refuses one over more than a group at
/// draft 23.
async fn refuse_fetches(conn: quinn::Connection, v: Version) {
    while let Ok(Ok((mut send, recv))) = tokio::time::timeout(WAIT, conn.accept_bi()).await {
        let conn = conn.clone();
        tokio::spawn(async move {
            let mut recv = BufReader::new(recv);
            let Some((kind, body)) = read_frame(&mut recv, v, 1 << 20).await.ok().flatten() else {
                return;
            };
            match Message::decode(kind, &body, v, &Context::default()).unwrap() {
                Message::Subscribe(_) => {
                    let ok = Message::SubscribeOk {
                        track_alias: 5,
                        params: Params {
                            largest_object: Some(Location::new(1, 0)),
                            ..Params::default()
                        },
                        properties: Bytes::new(),
                    };
                    send.write_all(&ok.encode(v)).await.unwrap();
                    send_subgroup(&conn, 5, 2, &[object(2, 0, b"c")]).await;
                    // The subscription lasts while its request stream does
                    tokio::time::sleep(WAIT * 2).await;
                    drop(send);
                }
                Message::Fetch(_) => {
                    let refused = Message::RequestError(message::RequestError {
                        code: super::error::RequestCode::NotSupported as u64,
                        retry_interval: 0,
                        reason: "one group at a time".into(),
                        details: Vec::new(),
                    });
                    send.write_all(&refused.encode(v)).await.unwrap();
                    let _ = send.finish();
                }
                _ => {}
            }
        });
    }
}

/// A FETCH the upstream refuses leaves its range unknown, never vouched for:
/// a refused fill once closed its channel as a complete answer would, and
/// the relay told a subscriber the objects did not exist (found against
/// moq-dev's relay at draft 23, 2026-11-26).
#[tokio::test]
async fn a_refused_upstream_fetch_leaves_the_range_unknown() {
    let (server, _moq, _accept, cert) = relay().await;
    for v in Version::ALL {
        let t = TrackName {
            namespace: ns(&[b"music", b"refused"]),
            name: Bytes::from(v.alpn()),
        };
        let mut publisher = Client::connect(&server, &cert, v, Setup::default()).await;
        let (kind, _request) = advertise(&mut publisher, &t.namespace).await;
        assert_eq!(kind, message::REQUEST_OK, "{v}");
        let serving = tokio::spawn(refuse_fetches(publisher.conn.clone(), v));
        // Group 2 reaches the relay through a subscription
        let mut subscriber = Client::connect(&server, &cert, v, Setup::default()).await;
        let id = subscriber.id();
        let (_ss, _sr, kind, _) = subscriber
            .request(Message::Subscribe(TrackRequest {
                request_id: id,
                track: t.clone(),
                params: Params::default(),
            }))
            .await;
        assert_eq!(kind, message::SUBSCRIBE_OK, "{v}");
        let (_alias, group, got) = receive_subgroup(&subscriber.conn).await;
        assert_eq!((group, got.len()), (2, 1), "{v}: group 2, live");
        // Groups 0 and 1 the relay never had, and the publisher refuses them
        let all = fetch_all(
            &server,
            &cert,
            v,
            &t,
            Location::new(0, 0),
            Location::new(2, 0),
        )
        .await;
        assert!(
            matches!(all.first(), Some(Err(e)) if e.contains("Unknown")),
            "{v}: groups 0 and 1 unknown, not objects that do not exist: {all:?}"
        );
        assert_eq!(
            all.last(),
            Some(&Ok(Bytes::from_static(b"c"))),
            "{v}: then group 2: {all:?}"
        );
        serving.abort();
    }
}

#[tokio::test]
async fn an_edge_relay_serves_the_origin_s_tracks() {
    let (origin, _o, _oa, origin_cert) = relay().await;
    let edge_moq = Moq::new(&MoqConfig {
        enabled: true,
        ..MoqConfig::default()
    })
    .expect("the edge");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedTo(origin_cert.clone().into(), provider)))
        .with_no_client_auth();
    crypto.alpn_protocols = Version::alpns();
    let client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));
    let uri = super::upstream::UpstreamUri::parse(&format!(
        "moqt://127.0.0.1:{}/moq",
        origin.local_addr().unwrap().port()
    ))
    .unwrap();
    let link = super::upstream::UpstreamLink::with_client(
        uri,
        &edge_moq.relay,
        Arc::clone(&edge_moq.settings),
        client,
    )
    .unwrap();
    edge_moq
        .relay
        .set_upstream(Arc::new(super::upstream::UpstreamPublisher(link)));
    let (edge, _e, _ea, edge_cert) = serve(edge_moq);

    let v = Version::Draft23;
    let t = track();
    let mut publisher = Client::connect(&origin, &origin_cert, v, Setup::default()).await;
    let id = publisher.id();
    let (_ps, _pr, kind, _) = publisher
        .request(Message::Publish(Publish {
            request_id: id,
            track: t.clone(),
            track_alias: 3,
            params: Params {
                auth_tokens: vec![token_for(&t.namespace)],
                ..Params::default()
            },
            properties: Bytes::new(),
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);
    // Group 0 reaches the origin before anyone at the edge subscribes
    let early = [object(0, 0, b"a"), object(0, 1, b"b"), object(0, 2, b"c")];
    send_subgroup(&publisher.conn, 3, 0, &early).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut subscriber = Client::connect(&edge, &edge_cert, v, Setup::default()).await;
    let id = subscriber.id();
    let (_ss, _sr, kind, ok) = subscriber
        .request(Message::Subscribe(TrackRequest {
            request_id: id,
            track: t.clone(),
            params: Params::default(),
        }))
        .await;
    assert_eq!(
        kind,
        message::SUBSCRIBE_OK,
        "the edge subscribed upstream first"
    );
    let Message::SubscribeOk { params, .. } = ok else {
        unreachable!()
    };
    assert_eq!(
        params.largest_object,
        Some(Location::new(0, 2)),
        "Largest Object from upstream"
    );

    send_subgroup(&publisher.conn, 3, 1, &[object(1, 0, b"live")]).await;
    let (_alias, group, got) = receive_subgroup(&subscriber.conn).await;
    assert_eq!((group, got), (1, vec![(0, Bytes::from_static(b"live"))]));

    // Group 0 was never at the edge: its FETCH is filled from the origin
    let mut fetcher = Client::connect(&edge, &edge_cert, v, Setup::default()).await;
    let id = fetcher.id();
    let (_fs, _fr, kind, _) = fetcher
        .request(Message::Fetch(TrackRequest {
            request_id: id,
            track: t.clone(),
            params: Params {
                location_filter: Some(LocationFilter::AbsoluteRange {
                    start: Location::new(0, 0),
                    end: Location::new(0, 2),
                }),
                ..Params::default()
            },
        }))
        .await;
    assert_eq!(kind, message::REQUEST_OK);
    let recv = tokio::time::timeout(WAIT, fetcher.conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let mut r = BufReader::new(recv);
    assert_eq!(read_vi64(&mut r).await.unwrap(), Some(STREAM_FETCH_HEADER));
    assert_eq!(read_vi64(&mut r).await.unwrap(), Some(id));
    let mut state = FetchState::default();
    let mut fetched = Vec::new();
    while let Some(e) = state
        .read(&mut r, GroupOrder::Ascending, v, 1 << 20)
        .await
        .unwrap()
    {
        match e {
            FetchEntry::Object(o) => fetched.push(o.payload),
            other => panic!("the origin holds every object: {other:?}"),
        }
    }
    assert_eq!(
        fetched,
        early.iter().map(|o| o.payload.clone()).collect::<Vec<_>>()
    );
}

/// RESET_STREAM_AT between two endpoints of this QUIC stack: the bytes
/// before the reliable size arrive whatever follows them, then the reset
/// (draft-ietf-quic-reliable-stream-reset; a WebTransport data stream is
/// reset this way to keep its header, draft-ietf-webtrans-http3 4.4).
#[tokio::test]
async fn a_stream_reset_at_its_header_still_delivers_the_header() {
    let throwaway = throwaway_cert();
    let mut crypto = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(OneCert(throwaway.key.clone())));
    crypto.alpn_protocols = vec![b"test".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto).unwrap(),
        )),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let sender = tokio::spawn(async move {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut s = conn.open_uni().await.unwrap();
        s.write_all(b"HDR").await.unwrap();
        s.write_all(&vec![7u8; 64 * 1024]).await.unwrap();
        s.reset_at(quinn::VarInt::from_u32(9), 3)
            .expect("the peer supports RESET_STREAM_AT");
        conn.closed().await;
    });
    let ep = client_endpoint(&throwaway.der, vec![b"test".to_vec()]);
    let conn = ep.connect(addr, "localhost").unwrap().await.unwrap();
    let mut r = tokio::time::timeout(WAIT, conn.accept_uni())
        .await
        .unwrap()
        .unwrap();
    let mut header = [0u8; 3];
    r.read_exact(&mut header)
        .await
        .expect("the reliable bytes arrive");
    assert_eq!(&header, b"HDR");
    let end = tokio::time::timeout(WAIT, r.read_to_end(usize::MAX))
        .await
        .unwrap();
    match end {
        Err(quinn::ReadToEndError::Read(quinn::ReadError::Reset(code))) => {
            assert_eq!(code, quinn::VarInt::from_u32(9));
        }
        other => panic!("the stream ended otherwise: {other:?}"),
    }
    conn.close(0u32.into(), b"");
    sender.abort();
}

/// FETCH `from..=to` of `t` on a session: the Locations of the objects that
/// come and the other entries, or None where the FETCH is refused.
async fn fetch_locations(
    session: &mut Client,
    track: &TrackName,
    from: Location,
    to: Location,
) -> Option<(Vec<Location>, Vec<String>)> {
    let v = session.v;
    let id = session.id();
    let (_fs, _fr, kind, _) = session
        .request(Message::Fetch(TrackRequest {
            request_id: id,
            track: track.clone(),
            params: Params {
                // To the end of a group as the draft says it
                location_filter: Some(if to.object == u64::MAX {
                    LocationFilter::AbsoluteGroupEnd {
                        start: from,
                        end_group: to.group,
                    }
                } else {
                    LocationFilter::AbsoluteRange {
                        start: from,
                        end: to,
                    }
                }),
                ..Params::default()
            },
        }))
        .await;
    if kind == message::REQUEST_ERROR {
        return None;
    }
    // Draft 22 answers a FETCH with FETCH_OK; 23 with REQUEST_OK
    let answered = if v.fetch_ok_is_request_ok() {
        message::REQUEST_OK
    } else {
        message::FETCH_OK_22
    };
    assert_eq!(kind, answered, "{v:?}: FETCH of {from:?} to {to:?}");
    let recv = tokio::time::timeout(WAIT, session.conn.accept_uni())
        .await
        .expect("a fetch stream")
        .unwrap();
    let mut stream = BufReader::new(recv);
    assert_eq!(
        read_vi64(&mut stream).await.unwrap(),
        Some(STREAM_FETCH_HEADER)
    );
    assert_eq!(read_vi64(&mut stream).await.unwrap(), Some(id));
    let mut state = FetchState::default();
    let (mut objects, mut others) = (Vec::new(), Vec::new());
    while let Some(e) = state
        .read(&mut stream, GroupOrder::Ascending, v, 1 << 20)
        .await
        .unwrap()
    {
        match e {
            FetchEntry::Object(o) => objects.push(o.location),
            other => others.push(format!("{other:?}")),
        }
    }
    Some((objects, others))
}

/// An outside implementation's relay as this relay's upstream, live: a
/// subscriber here, in each draft this relay speaks, subscribes to a track
/// another implementation publishes into that relay, and fetches a group it
/// holds only there. Against moqtail 0.19.0 (draft 22) with its client
/// publishing (`client -c publish -n moqtail -T demo`):
///
/// ```text
/// MOQ_INTEROP_UPSTREAM=moqt://127.0.0.1:14433 MOQ_INTEROP_CA=ca.pem \
/// MOQ_INTEROP_TRACK=moqtail/demo cargo test --lib live_an_outside_relay_as_upstream -- --ignored --nocapture
/// ```
///
/// A track that is published whole and ended (`MOQ_INTEROP_FINITE=1`, as
/// moq-dev's `interop-tail publish … cached` writes) brings no live group to a
/// subscriber: each is fetched instead, from group 0 to the Largest Object.
#[tokio::test]
#[ignore = "needs an outside relay with a track published into it"]
async fn live_an_outside_relay_as_upstream() {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let upstream = std::env::var("MOQ_INTEROP_UPSTREAM").expect("MOQ_INTEROP_UPSTREAM");
    let ca = std::env::var("MOQ_INTEROP_CA").expect("MOQ_INTEROP_CA");
    let wanted = std::env::var("MOQ_INTEROP_TRACK").unwrap_or_else(|_| "moqtail/demo".into());
    let (namespace, name) = wanted.rsplit_once('/').expect("namespace/track");
    let finite = std::env::var("MOQ_INTEROP_FINITE").is_ok_and(|v| v == "1");
    let t = TrackName {
        namespace: Namespace(
            namespace
                .split('/')
                .map(|f| Bytes::copy_from_slice(f.as_bytes()))
                .collect(),
        ),
        name: Bytes::copy_from_slice(name.as_bytes()),
    };

    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&ca).expect("the CA file") {
        roots.add(cert.expect("a certificate")).expect("a root");
    }
    let roots = Arc::new(roots);
    let client_for = |alpns: Vec<Vec<u8>>| {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(Arc::clone(&roots))
            .with_no_client_auth();
        crypto.alpn_protocols = alpns;
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
        ))
    };
    let client = client_for(Version::alpns());
    let up = super::upstream::UpstreamUri::parse(&upstream).expect("an upstream URI");
    let up_addr = tokio::net::lookup_host((up.host.as_str(), up.port))
        .await
        .expect("the upstream's address")
        .next()
        .expect("an address");
    let edge_moq = Moq::new(&MoqConfig {
        enabled: true,
        ..MoqConfig::default()
    })
    .expect("the edge");
    let link = super::upstream::UpstreamLink::with_client(
        super::upstream::UpstreamUri::parse(&upstream).expect("an upstream URI"),
        &edge_moq.relay,
        Arc::clone(&edge_moq.settings),
        client,
    )
    .unwrap();
    edge_moq
        .relay
        .set_upstream(Arc::new(super::upstream::UpstreamPublisher(link)));
    let (edge, _e, _ea, edge_cert) = serve(edge_moq);

    for v in Version::ALL {
        let mut subscriber = Client::connect(&edge, &edge_cert, v, Setup::default()).await;
        let id = subscriber.id();
        let (_ss, _sr, kind, ok) = subscriber
            .request(Message::Subscribe(TrackRequest {
                request_id: id,
                track: t.clone(),
                params: Params::default(),
            }))
            .await;
        assert_eq!(
            kind,
            message::SUBSCRIBE_OK,
            "{v:?}: subscribed through the upstream"
        );
        let Message::SubscribeOk { params, .. } = ok else {
            unreachable!()
        };
        let largest = params
            .largest_object
            .expect("the upstream's Largest Object");
        println!("{v:?}: SUBSCRIBE_OK, Largest Object {largest:?}");

        // Live objects, group by group, each in order (a finished track has none)
        let mut groups = Vec::new();
        while !finite && groups.len() < 2 {
            let (_alias, group, got) = receive_subgroup(&subscriber.conn).await;
            assert!(!got.is_empty(), "{v:?}: group {group} carried objects");
            assert!(
                got.windows(2).all(|w| w[0].0 < w[1].0),
                "{v:?}: group {group} in order"
            );
            println!("{v:?}: group {group}, {} objects", got.len());
            groups.push(group);
        }

        // A group from before the subscription: the edge never had it, so the
        // FETCH is filled from the upstream. A finished track: every group of it
        let past = largest.group.saturating_sub(1);
        let (from, to) = if finite {
            (Location::new(0, 0), largest)
        } else {
            (Location::new(past, 0), Location::new(past, 2))
        };
        let mut fetcher = Client::connect(&edge, &edge_cert, v, Setup::default()).await;
        let (fetched, marks) = fetch_locations(&mut fetcher, &t, from, to)
            .await
            .expect("this relay answers the FETCH");
        println!("{v:?}: FETCH of {from:?} to {to:?} through this relay: {fetched:?} {marks:?}");
        assert!(!fetched.is_empty(), "{v:?}: objects from the upstream");
        if finite {
            // The same asked of the upstream itself: this relay passes on all
            // it gives, and marks Unknown what it will not give
            let ep =
                quinn::Endpoint::client(SocketAddr::from(([0u8; 4], 0))).expect("a client port");
            ep.set_default_client_config(client_for(vec![v.alpn().as_bytes().to_vec()]));
            let mut direct =
                Client::connect_over(&ep, up_addr, &up.host, v, Setup::default()).await;
            match fetch_locations(&mut direct, &t, from, to).await {
                Some((theirs, _)) => {
                    assert_eq!(
                        fetched, theirs,
                        "{v:?}: this relay returns what the upstream holds"
                    );
                }
                None => {
                    println!("{v:?}: the upstream refuses a FETCH of {from:?} to {to:?}");
                    assert!(
                        marks.iter().any(|m| m.contains("Unknown")),
                        "{v:?}: what the upstream refused is marked Unknown: {marks:?}"
                    );
                }
            }
            // One group at a time: what the upstream serves comes through
            // whole, what it refuses is refused or marked Unknown
            for g in 0..=largest.group {
                let (a, b) = (Location::new(g, 0), Location::new(g, u64::MAX));
                let ours = fetch_locations(&mut fetcher, &t, a, b).await;
                let theirs = fetch_locations(&mut direct, &t, a, b).await;
                println!(
                    "{v:?}: group {g}: through this relay {ours:?}, from the upstream {theirs:?}"
                );
                match (&ours, &theirs) {
                    (Some((o, _)), Some((th, _))) => {
                        assert_eq!(o, th, "{v:?}: group {g} as the upstream has it");
                    }
                    (None, None) => {}
                    (Some((o, marks)), None) => assert!(
                        o.iter().all(|l| l.group != g)
                            || marks.iter().any(|m| m.contains("Unknown")),
                        "{v:?}: group {g}, refused upstream, marked Unknown: {ours:?}"
                    ),
                    (None, Some(_)) => panic!("{v:?}: group {g} refused here, served upstream"),
                }
            }
        }
    }
}
