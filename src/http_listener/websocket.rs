//! WebSocket tunnels on the TCP listeners: HTTP/1.1 upgrades (RFC 6455) and
//! HTTP/2 extended CONNECT (RFC 8441), to the backend through
//! [`crate::ws_tunnel`].

use std::time::Duration;

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tracing::{debug, warn};

use crate::config::BackendConfig;

/// Open the backend's side of a WebSocket, then answer the client (`101` to
/// an HTTP/1.1 upgrade, `200` to an HTTP/2 extended CONNECT) with what the
/// backend agreed to, and relay the two until either ends or nothing moves
/// for the route's `ws_idle_timeout_secs` (0: no limit).
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_websocket_tunnel(
    backend: &BackendConfig,
    forwarded: HeaderMap,
    client_key: Option<HeaderValue>,
    on_upgrade: OnUpgrade,
    path_and_query: &str,
    host: &str,
    idle_timeout_secs: u64,
    extended_connect: bool,
) -> Response {
    if !extended_connect && client_key.is_none() {
        return (StatusCode::BAD_REQUEST, "Sec-WebSocket-Key is required").into_response();
    }
    let (backend_io, agreed) =
        match crate::ws_tunnel::open_backend(backend, path_and_query, host, forwarded, client_key)
            .await
        {
            Ok(opened) => opened,
            Err(refused) => {
                warn!(
                    "WebSocket to {} not opened: {}",
                    backend.name, refused.reason
                );
                return refused.status.into_response();
            }
        };

    let mut answer = if extended_connect {
        Response::builder().status(StatusCode::OK)
    } else {
        let mut answer = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket");
        if let Some(accept) = agreed.accept {
            answer = answer.header(header::SEC_WEBSOCKET_ACCEPT, accept);
        }
        answer
    };
    if let Some(protocol) = agreed.protocol {
        answer = answer.header(header::SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    if let Some(extensions) = agreed.extensions {
        answer = answer.header(header::SEC_WEBSOCKET_EXTENSIONS, extensions);
    }
    let Ok(answer) = answer.body(Body::empty()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    let idle = (idle_timeout_secs > 0).then(|| Duration::from_secs(idle_timeout_secs));
    tokio::spawn(async move {
        // The client's stream, once hyper has sent the answer
        let client = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(e) => {
                debug!("WebSocket client upgrade failed: {}", e);
                return;
            }
        };
        let mut client = TokioIo::new(client);
        let (up, down) = crate::ws_tunnel::relay(&mut client, backend_io, idle).await;
        debug!("WebSocket tunnel ended: {} bytes up, {} down", up, down);
    });

    answer
}
