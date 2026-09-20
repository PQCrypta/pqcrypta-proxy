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
        // One connection purely to be issued a ticket. Its failure is not this
        // run's failure: without a ticket the connection below is an ordinary
        // one and the suite reports honestly that no early data was offered.
        if let Ok(connecting) = endpoint.connect(addr, host) {
            if let Ok(priming) = connecting.await {
                // The ticket arrives after the handshake, not with it, so the
                // connection has to outlive the handshake to receive one.
                tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                priming.close(0u32.into(), b"primed");
            }
        }
    }

    let connecting = endpoint
        .connect(addr, host)
        .context("starting the connection")?;

    // `into_0rtt` is what actually puts the request in the first flight. A
    // resumed handshake that waits for completion sends its request in 1-RTT
    // like any other, which is indistinguishable from never having resumed.
    let connection = match connecting.into_0rtt() {
        Ok((connection, _accepted)) => connection,
        Err(connecting) => connecting.await.context("completing the handshake")?,
    };

    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .map_err(|e| anyhow!("opening the HTTP/3 connection: {e}"))?;

    // The driver owns the control stream and the connection-level frames, which
    // is exactly where most of this suite's anomalies arrive. It has to keep
    // running for the whole request.
    let driving =
        tokio::spawn(
            async move { futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await },
        );

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

    drop(send_request);
    let _ = driving.await;

    Ok(response.status().as_u16())
}
