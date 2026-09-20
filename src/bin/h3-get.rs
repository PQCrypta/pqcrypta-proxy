//! One HTTP/3 GET, over the vendored quinn/h3 stack.
//!
//! Exists to be a *client under test*. `h3-conformance` drives whatever command
//! it is given once per test, so a client only has to do one thing: make a
//! single HTTP/3 request and exit. This is that, for the quinn + h3 stack.
//!
//! It is deliberately thin. Every behaviour the conformance suite is judging —
//! how an unknown frame is handled, whether a Stateless Reset is honoured,
//! whether a rejected 0-RTT resets stream state — belongs to the libraries
//! underneath, not here. Anything clever added to this file would be measuring
//! this file instead of them.
//!
//! Exit status is not a verdict. The suite reads its results from the server
//! side; a client failing a test frequently *should* exit non-zero, and that is
//! a result rather than an error. The status is here for humans running it by
//! hand.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context as _};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(url) = args.next() else {
        eprintln!("usage: h3-get <url> [timeout-seconds]");
        return std::process::ExitCode::from(2);
    };
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(15);

    match tokio::time::timeout(Duration::from_secs(secs), get(&url)).await {
        Ok(Ok(status)) => {
            println!("{status}");
            std::process::ExitCode::SUCCESS
        }
        Ok(Err(e)) => {
            eprintln!("h3-get: {e:#}");
            std::process::ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("h3-get: timed out after {secs}s");
            std::process::ExitCode::from(3)
        }
    }
}

async fn get(url: &str) -> anyhow::Result<u16> {
    let uri: http::Uri = url.parse().context("parsing the url")?;
    let host = uri.host().ok_or_else(|| anyhow!("url has no host"))?;
    let port = uri.port_u16().unwrap_or(443);

    // Resolve here rather than letting the endpoint do it, so a DNS failure is
    // reported as a DNS failure instead of a connection one.
    //
    // Every address, not just the first: a UDP socket is bound to one family, and
    // quinn rejects a remote from the other one outright ("invalid remote
    // address"). Taking `next()` alone meant any dual-stack host whose AAAA came
    // back first (haproxy.com does) failed before a packet was ever sent, which
    // reads as a broken origin rather than a client that never tried.
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?
        .collect();
    let addr = *addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| anyhow!("{host}:{port} resolved to nothing"))?;
    // Bind the family the chosen address actually needs.
    let bind: std::net::SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0"
            .parse()
            .expect("INADDR_ANY:0 is a valid address")
    } else {
        "[::]:0".parse().expect("in6addr_any:0 is a valid address")
    };

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Our own post-quantum root, so `t-cert-compression-pq` can be verified
    // rather than waved through.
    //
    // That port serves an ML-DSA-87 chain issued by a CA of ours, which no
    // public root store carries. The clients that pass this test today do so
    // with certificate verification disabled -- the suite says as much in the
    // verdict -- and matching them by turning verification off here would
    // make our own client the least rigorous in the fleet at the one test
    // about certificates. Trusting the issuer keeps the chain, the signature
    // and the compression all genuinely checked.
    //
    // Missing file is not fatal: away from this host the test is unreachable
    // anyway, and every other port uses the public roots above.
    const PQ_ROOT: &str = "/etc/pqcrypta/pqc-certs/root_ca.crt";
    match std::fs::read(PQ_ROOT) {
        Ok(pem) => {
            let mut rd = std::io::BufReader::new(std::io::Cursor::new(pem));
            for cert in rustls_pemfile::certs(&mut rd).flatten() {
                if let Err(e) = roots.add(cert) {
                    eprintln!("h3-get: ignoring {PQ_ROOT}: {e}");
                }
            }
        }
        Err(e) => eprintln!("h3-get: {PQ_ROOT} not readable ({e}); public roots only"),
    }

    let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
        pqcrypta_proxy::tls::build_pqc_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .context("selecting TLS 1.3")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    // The suite's two 0-RTT ports need a resumed connection carrying early
    // data, and the driver runs this binary once per test -- so the pair is
    // made here, in one process, with an in-memory ticket store. On disk it
    // would need a serialisation format nobody else reads; in memory it is a
    // field.
    //
    // Without this the self-test client offered no early data at all and both
    // 0-RTT cells reported that the run had not exercised them. Ours to fix,
    // and it is the client we ship.
    let resuming = std::env::var("H3_CONFORMANCE_RESUME").as_deref() == Ok("1");
    if resuming {
        // Storing a ticket is not the same as offering early data with it.
        crypto.enable_early_data = true;
    }

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow!("building the QUIC client config: {e}"))?,
    ));

    let endpoint = quinn::Endpoint::client(bind).context("binding a client socket")?;
    endpoint.set_default_client_config(client_config);

    if resuming {
        // One connection purely to be issued a ticket, and it makes an
        // ordinary request like any other.
        //
        // It used to handshake, sleep, and close. The server judges every
        // connection it is given, so that one was judged too -- and a peer
        // that connects and then goes away without asking for anything reads
        // as a client that dropped out. q-zero-rtt-reject scored our own
        // stack "Dropped the connection instead of recovering" on the
        // strength of the priming connection, while the connection the test
        // was actually about completed and returned 200.
        //
        // The clients that already worked here prime by running themselves
        // twice, so their first connection is a complete exchange. This does
        // the same. Its failure is still not this run's failure: without a
        // ticket the connection below is an ordinary one and the suite
        // reports honestly that no early data was offered.
        let _ = plain_exchange(&endpoint, addr, host, &uri).await;
        // The ticket arrives after the response, not with it. Without this
        // wait the resumed connection sometimes finds an empty store and
        // offers no early data, which made q-zero-rtt-replay alternate
        // between pass and inconclusive between runs -- an unstable cell is
        // not a result.
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    let connecting = endpoint
        .connect(addr, host)
        .context("starting the connection")?;

    // `into_0rtt` is what actually puts the request in the first flight. A
    // resumed handshake that waits for completion sends its request in 1-RTT
    // like any other, which is indistinguishable from never having resumed.
    let (connection, zero_rtt) = match connecting.into_0rtt() {
        Ok((connection, accepted)) => (connection, Some(accepted)),
        Err(connecting) => match connecting.await {
            Ok(connection) => (connection, None),
            // A failed handshake still has something to say, and ours does
            // not manage to say it.
            //
            // RFC 9001 §4.8 carries a TLS alert in a CONNECTION_CLOSE. On
            // t-group-not-offered this client detects the fault and names the
            // alert -- "error 47: peer misbehaved: WrongGroupForKeyShare" --
            // and on q-invalid-transport-param it names the parameter. The
            // server sees neither, and reports both as a handshake that
            // stopped with nothing said, which is indistinguishable from a
            // client that objected to nothing. Nine of the twelve clients do
            // produce a readable close on those same ports, so the server is
            // reading them; we are not sending one.
            //
            // The drain below is here because it is the same shape as the
            // fault on the request path, where exiting before the datagram
            // left was exactly the problem. It did not fix this one: the
            // cells are unchanged with it. So the close is not merely
            // unflushed, it is not being produced, and that is in the noq
            // fork rather than in this file. Left in place because it costs
            // nothing and the next person should not have to rule it out
            // again; the open question is recorded rather than guessed at.
            Err(e) => {
                let _ = tokio::time::timeout(DRAIN, endpoint.wait_idle()).await;
                return Err(anyhow::Error::new(e).context("completing the handshake"));
            }
        },
    };

    // Offer the server a QPACK dynamic table, and no blocked streams.
    //
    // The table is honest now: the encoder stream is read and applied, and
    // field sections decode against the same decoder that applied them.
    //
    // Blocked streams are not, and saying 16 was an overclaim that the suite
    // caught within one run. A blocked stream is one whose field section
    // references an insert the decoder has not received yet, and handling it
    // means parking the section until the encoder stream catches up. This
    // decoder does not park: `decode_header` returns MissingRefs and the
    // connection fails with QPACK_DECOMPRESSION_FAILED. Advertising zero is
    // what a decoder without that machinery is required to say -- the encoder
    // then may not reference an insert we have not acknowledged, so the
    // situation never arises.
    //
    // h-qpack-blocked-stream therefore reads `unsupported`, which is true.
    let (mut driver, mut send_request) = h3::client::builder()
        .qpack_max_table_capacity(4096)
        .qpack_blocked_streams(0)
        .build(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| anyhow!("opening the HTTP/3 connection: {e}"))?;

    // Everything from here can fail by deciding the *server* is at fault, and
    // that decision has to reach the wire.
    //
    // It did not. On any error this returned straight out of `get`, `main`
    // printed it and the process exited -- dropping the endpoint, which does
    // not flush a CONNECTION_CLOSE. So the client detected the violation,
    // chose the right HTTP/3 error code, and threw it away before sending it.
    // From the server the connection simply went quiet, which is
    // indistinguishable from a client that never objected: h-data-before-
    // headers and h-settings-on-request-stream both reported our own client
    // as inconclusive for a rejection it had already made.
    //
    // `exchange` holds the fallible part; the drain below runs whichever way
    // it ends.

    // The driver owns the control stream and the connection-level frames, which
    // is exactly where most of this suite's anomalies arrive. It has to keep
    // running for the whole request.
    let driving =
        tokio::spawn(
            async move { futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await },
        );

    let mut outcome = exchange(&mut send_request, &uri).await;

    // A refused 0-RTT is not a failed request.
    //
    // RFC 9001 §4.6.2: when a server rejects early data the handshake carries
    // on, the streams opened in the first flight are reset, and the client is
    // expected to send the data again once the handshake completes. This
    // client did not -- it surfaced the reset as an error and gave up, so
    // q-zero-rtt-reject read "Dropped the connection instead of recovering"
    // against our own stack, which was accurate.
    //
    // Retried once, on a fresh connection that does not offer early data, so
    // the retry cannot be refused for the same reason and cannot loop.
    if outcome.is_err() {
        let rejected = match zero_rtt {
            Some(accepted) => !accepted.await,
            None => false,
        };
        if rejected {
            drop(send_request);
            let _ = tokio::time::timeout(DRAIN, driving).await;
            return plain_exchange(&endpoint, addr, host, &uri).await;
        }
        // Put the error back where the caller expects it.
        outcome = outcome.map_err(|e| e);
    }

    // Always, not only on the error path.
    //
    // It does two jobs and both matter. A rejection this client decided on
    // has to reach the wire before the process exits, and the connection has
    // to stay up long enough to answer the server's close-elicitation PING --
    // a client that vanishes the instant its request completes is recorded as
    // PeerUnreachable, which establishes less than a live peer that says
    // nothing.
    //
    // It was briefly made conditional, because draining on success turned the
    // exit into a graceful close and q-zero-rtt-reject read that as "Dropped
    // the connection instead of recovering". That was the suite's reading to
    // fix, not this client's behaviour: a close carrying no error code is a
    // shutdown, not a surrender. Making it conditional here cost five cells
    // that the unconditional version had already resolved.
    drop(send_request);
    let _ = tokio::time::timeout(DRAIN, driving).await;
    let _ = tokio::time::timeout(DRAIN, endpoint.wait_idle()).await;

    outcome
}

/// How long to let a decided close reach the wire before giving up on it.
const DRAIN: Duration = Duration::from_secs(2);

/// A complete exchange on a fresh connection that offers no early data.
///
/// Used twice: to be issued a session ticket before the resumed connection,
/// and to retry after a server refuses the early data that ticket allowed.
async fn plain_exchange(
    endpoint: &quinn::Endpoint,
    addr: std::net::SocketAddr,
    host: &str,
    uri: &http::Uri,
) -> anyhow::Result<u16> {
    let connection = endpoint
        .connect(addr, host)
        .context("starting the retry connection")?
        .await
        .context("completing the retry handshake")?;

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| anyhow!("opening the HTTP/3 connection for the retry: {e}"))?;
    let driving =
        tokio::spawn(
            async move { futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await },
        );

    let outcome = exchange(&mut send_request, uri).await;

    drop(send_request);
    let _ = tokio::time::timeout(DRAIN, driving).await;
    let _ = tokio::time::timeout(DRAIN, endpoint.wait_idle()).await;
    outcome
}

async fn exchange(
    send_request: &mut h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    uri: &http::Uri,
) -> anyhow::Result<u16> {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri.clone())
        .header(http::header::USER_AGENT, "h3-get/1.0 (quinn+h3)")
        .body(())
        .context("building the request")?;

    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| anyhow!("sending the request: {e}"))?;
    stream
        .finish()
        .await
        .map_err(|e| anyhow!("finishing the request stream: {e}"))?;

    let response = stream
        .recv_response()
        .await
        .map_err(|e| anyhow!("reading the response head: {e}"))?;

    // Drain the body. Several tests put their anomaly *after* the headers — a
    // trailing field section, a reserved frame between DATA frames — so a client
    // that stopped at the response head would sail past the thing being tested.
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|e| anyhow!("reading the body: {e}"))?
    {
        let _ = chunk;
    }
    // Trailers too, for the same reason.
    let _ = stream.recv_trailers().await;

    Ok(response.status().as_u16())
}
