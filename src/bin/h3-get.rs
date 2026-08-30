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
    let addr = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("{host}:{port} resolved to nothing"))?;

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

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow!("building the QUIC client config: {e}"))?,
    ));

    let endpoint = quinn::Endpoint::client(
        "0.0.0.0:0"
            .parse()
            .expect("INADDR_ANY:0 is always a valid socket address"),
    )
    .context("binding a client socket")?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr, host)
        .context("starting the connection")?
        .await
        .context("completing the handshake")?;

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
