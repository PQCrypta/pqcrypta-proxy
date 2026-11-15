//! 103 Early Hints over HTTP/2.
//!
//! Upstream hyper gives an HTTP/2 service no way to send an interim response;
//! the vendored hyper (`vendor/hyper/src/ext/h2_informational.rs`) puts a
//! `hyper::ext::InformationalSender` in each HTTP/2 request's extensions. These
//! tests run a real HTTP/2 connection, an `h2` client reading the interim
//! responses before the final one: the sender itself, and the TCP listener's
//! middleware sending a configured page's preloads on it while the backend is
//! still answering.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

/// An HTTP/2 client on one end of an in-memory pipe, `serve` on the other.
async fn client<F>(serve: F) -> h2::client::SendRequest<Bytes>
where
    F: FnOnce(tokio::io::DuplexStream) -> tokio::task::JoinHandle<()>,
{
    let (client_io, server_io) = tokio::io::duplex(1 << 16);
    serve(server_io);
    let (client, connection) = h2::client::handshake(client_io)
        .await
        .expect("HTTP/2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

/// The interim responses before the final one, and the final one's status.
async fn exchange(
    client: &mut h2::client::SendRequest<Bytes>,
    request: http::Request<()>,
) -> (Vec<http::Response<()>>, http::StatusCode) {
    let (mut response, _) = client.send_request(request, true).expect("request sent");
    let mut interim = Vec::new();
    while let Some(info) = std::future::poll_fn(|cx| response.poll_informational(cx)).await {
        interim.push(info.expect("an interim response"));
    }
    let status = response.await.expect("the final response").status();
    (interim, status)
}

#[tokio::test]
async fn a_service_sends_103_before_its_response() {
    let mut client = client(|io| {
        tokio::spawn(async move {
            let service = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                let sender = req
                    .extensions()
                    .get::<hyper::ext::InformationalSender>()
                    .cloned()
                    .expect("an HTTP/2 request carries the sender");
                sender
                    .send(
                        hyper::Response::builder()
                            .status(103)
                            .header("link", "</a.css>; rel=preload; as=style")
                            .body(())
                            .unwrap(),
                    )
                    .expect("a 103 is accepted before the response");
                // A final status is refused: only interim ones go this way
                assert!(sender.send(hyper::Response::new(())).is_err());
                // The backend is still working when the hint goes out
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"page"))))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(io), service)
                .await;
        })
    })
    .await;
    let request = http::Request::builder()
        .uri("https://example.test/")
        .body(())
        .unwrap();
    let (interim, status) = exchange(&mut client, request).await;
    assert_eq!(interim.len(), 1);
    assert_eq!(interim[0].status(), 103);
    assert_eq!(
        interim[0].headers()["link"],
        "</a.css>; rel=preload; as=style"
    );
    assert_eq!(status, 200);
}

/// Not in a `bench-null-middleware` build, whose middleware does none of its
/// work by design.
#[cfg(not(feature = "bench-null-middleware"))]
#[tokio::test]
async fn the_middleware_sends_a_pages_preloads_as_103() {
    use axum::routing::get;
    use axum::Router;
    use pqcrypta_proxy::config::PreloadResourceConfig;
    use pqcrypta_proxy::{http3_features_middleware, Http3Config, Http3FeaturesState};

    let config = Http3Config {
        early_hints_enabled: true,
        preload_resources: vec![PreloadResourceConfig {
            host: Some("example.test".into()),
            path: "/".into(),
            href: "/css/home.css".into(),
            rel: "preload".into(),
            as_type: "style".into(),
            crossorigin: None,
            exact: true,
            version_file: None,
        }],
        ..Default::default()
    };
    let state = Http3FeaturesState::from_proxy_config(&config);
    let app = Router::new()
        .route(
            "/",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                "page"
            }),
        )
        .route("/other", get(|| async { "other" }))
        .layer(axum::middleware::from_fn_with_state(
            state,
            http3_features_middleware,
        ));
    let mut client = client(move |io| {
        tokio::spawn(async move {
            let service =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let app = app.clone();
                    async move {
                        use tower::ServiceExt;
                        app.oneshot(req.map(axum::body::Body::new)).await
                    }
                });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(io), service)
                .await;
        })
    })
    .await;

    let page = |path: &str| {
        http::Request::builder()
            .uri(format!("https://example.test{path}"))
            .header("accept", "text/html,application/xhtml+xml")
            .header("sec-fetch-dest", "document")
            .body(())
            .unwrap()
    };
    let (interim, status) = exchange(&mut client, page("/")).await;
    assert_eq!(status, 200);
    assert_eq!(interim.len(), 1, "one 103 for the page with preloads");
    assert_eq!(interim[0].status(), 103);
    assert_eq!(
        interim[0].headers()["link"],
        "</css/home.css>; rel=preload; as=style"
    );

    // No preloads for this path, and none for a subresource of the page
    let (interim, _) = exchange(&mut client, page("/other")).await;
    assert!(interim.is_empty());
    let subresource = http::Request::builder()
        .uri("https://example.test/")
        .header("sec-fetch-dest", "style")
        .body(())
        .unwrap();
    let (interim, _) = exchange(&mut client, subresource).await;
    assert!(interim.is_empty());
}
