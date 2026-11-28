//! WebTransport over QUIC on the QUIC listener: a connection that negotiated
//! `wq-vvv-01` is one session (draft-vvv-webtransport-quic-02, crate::wt_quic).
//!
//! It is held to what a WebTransport session over HTTP/3 is held to, in the
//! same order, so the two entrances admit and refuse alike: the client
//! indication, read whole before anything else (section 3.2), names the
//! session's origin and path, and with the TLS server name as its host it
//! is judged as the extended CONNECT that opens a session over HTTP/3 would
//! be -- the key-exchange policy, the rate limiters and the security layer,
//! the route's own rate limit and gates (`connect_refusal`), the Origin
//! allowlist and the per-client and per-origin session caps
//! (`webtransport_server::admit`), and a WebTransport route or a path the
//! proxy serves itself -- and written to the access log either way. Then it
//! is served as every session is (`webtransport_server::serve_session`):
//! the speed test at `/speedtest`, the telemetry wall at `/telemetry`, a
//! route's backend otherwise.
//!
//! The draft defines no way to answer a session, only to end it (section 8),
//! so a refusal is the connection's CONNECTION_CLOSE, its application error
//! code the HTTP status the HTTP/3 entrance would have answered.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use quinn::{Connection as QuinnConnection, VarInt};
use tracing::{debug, info, warn};

use super::{connect_refusal, log_connect, request, H3ConnHeaders};
use crate::config::ProxyConfig;
use crate::proxy::BackendPool;
use crate::rate_limiter::AdvancedRateLimiter;
use crate::security::SecurityState;
use crate::wt_quic::{self, ClientIndication, QuicSession};

/// The request line's protocol in the access log: the ALPN token, which is
/// the protocol's name and version both
pub(super) const LOG_PROTOCOL: &str = "wq-vvv-01";

/// What a session over QUIC needs from the connection it arrived on
pub(super) struct Arrival {
    pub connection: QuinnConnection,
    pub remote_addr: SocketAddr,
    pub local_port: u16,
    /// The TLS server name, which is the session's host (section 3.2)
    pub server_name: Option<String>,
    pub handshake: Arc<crate::tls_acceptor::HandshakeFacts>,
    pub fingerprint: Arc<crate::fingerprint::FingerprintResult>,
}

/// What the listener serves a session with
pub(super) struct Services {
    pub config: Arc<ProxyConfig>,
    pub backend_pool: Arc<BackendPool>,
    pub security: Arc<SecurityState>,
    pub advanced_rate_limiter: Arc<AdvancedRateLimiter>,
}

/// The extended CONNECT a session over HTTP/3 would have opened with: its
/// method, its target (the server name and the indication's path), its
/// Origin, and the headers the connection itself sets on every request
fn session_request(
    indication: &ClientIndication,
    arrival: &Arrival,
    conn_headers: &H3ConnHeaders,
) -> Option<http::Request<()>> {
    let target = match arrival.server_name.as_deref() {
        Some(name) => format!("https://{name}{}", indication.path),
        None => indication.path.clone(),
    };
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(target.parse::<http::Uri>().ok()?)
        .version(http::Version::HTTP_3)
        .body(())
        .ok()?;
    if let Some(origin) = &indication.origin {
        request
            .headers_mut()
            .insert(http::header::ORIGIN, HeaderValue::from_str(origin).ok()?);
    }
    request::derive_connection_headers(
        request.headers_mut(),
        &arrival.handshake,
        conn_headers,
        &arrival.fingerprint,
        false,
    );
    // Not HTTP/3: the protocol the connection negotiated
    request.headers_mut().insert(
        HeaderName::from_static("x-connection-protocol"),
        HeaderValue::from_static(LOG_PROTOCOL),
    );
    Some(request)
}

/// Refuse the session: its access-log line, then the connection closed
/// with `status` as the application error code
fn refuse(
    arrival: &Arrival,
    request: &http::Request<()>,
    host: Option<&str>,
    path: &str,
    status: http::StatusCode,
    why: &str,
) {
    log_connect(
        request,
        host,
        path,
        arrival.remote_addr,
        &arrival.fingerprint,
        status.as_u16(),
        LOG_PROTOCOL,
    );
    warn!(
        "WebTransport over QUIC session from {} for {} refused {}: {}",
        arrival.remote_addr,
        path,
        status.as_u16(),
        why
    );
    let reason = format!(
        "{} {}: {why}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    );
    wt_quic::close(&arrival.connection, u32::from(status.as_u16()), &reason);
}

/// Serve the session a `wq-vvv-01` connection is, once its handshake has
/// completed and its client passed the fingerprint check: read the client
/// indication, admit it as an HTTP/3 entrance would, serve it, and close
/// the connection when its handler is done with it.
pub(super) async fn serve(arrival: Arrival, services: Services) {
    let Services {
        config,
        backend_pool,
        security,
        advanced_rate_limiter,
    } = services;
    let connection = arrival.connection.clone();

    // A session's streams by server.webtransport_max_streams_per_session, in
    // each direction, as over HTTP/3 (wt_initial_limits): here the
    // connection is the session, so the limit is QUIC's own
    let per_session = config.server.webtransport_max_streams_per_session;
    connection.set_max_concurrent_bi_streams(VarInt::from_u32(
        per_session.min(config.server.max_streams_per_connection),
    ));
    connection.set_max_concurrent_uni_streams(VarInt::from_u32(
        per_session.min(config.server.max_uni_streams_per_connection),
    ));

    // The indication has the time an HTTP/3 request's header block has
    let wait = Duration::from_secs(config.server.max_idle_timeout_secs.max(1));
    let indication = match wt_quic::read_indication(&connection, wait).await {
        Ok(indication) => indication,
        Err(why) => {
            // Logged with no target: there is none to name
            let placeholder = http::Request::builder()
                .method(http::Method::CONNECT)
                .body(())
                .unwrap_or_default();
            refuse(
                &arrival,
                &placeholder,
                arrival.server_name.as_deref(),
                "-",
                http::StatusCode::BAD_REQUEST,
                &why.to_string(),
            );
            return;
        }
    };

    let conn_headers = H3ConnHeaders::new(
        &config,
        arrival.remote_addr,
        arrival.local_port,
        &arrival.fingerprint,
        &arrival.handshake,
    );
    // The handshake has completed: a client certificate is settled
    conn_headers.resolve_client_cert(&connection);
    let Some(request) = session_request(&indication, &arrival, &conn_headers) else {
        let placeholder = http::Request::builder()
            .method(http::Method::CONNECT)
            .body(())
            .unwrap_or_default();
        refuse(
            &arrival,
            &placeholder,
            arrival.server_name.as_deref(),
            "-",
            http::StatusCode::BAD_REQUEST,
            "the client indication names no request target",
        );
        return;
    };
    let uri = request.uri().clone();
    let path = crate::path_canon::canonical_path(
        uri.path(),
        crate::path_canon::PathCanon::from(&config.server),
    )
    .into_owned();
    let Ok(host) = crate::request_target::effective_host_name(&uri, request.headers()) else {
        refuse(
            &arrival,
            &request,
            arrival.server_name.as_deref(),
            &path,
            http::StatusCode::BAD_REQUEST,
            "the session names two hosts",
        );
        return;
    };

    // The rules an extended CONNECT for a session meets (connect_refusal),
    // under the WebTransport route that serves its path
    let route = config
        .find_route(host.as_deref(), &path, true)
        .filter(|r| r.webtransport);
    let refusal = if crate::pqc_policy::refuses(conn_headers.pqc_enabled == "true") {
        Some((http::StatusCode::MISDIRECTED_REQUEST, Vec::new()))
    } else {
        connect_refusal(
            &security,
            &advanced_rate_limiter,
            &config,
            &request,
            host.as_deref(),
            &path,
            route,
            arrival.remote_addr,
            &arrival.fingerprint,
        )
        .await
    };
    if let Some((status, _)) = refusal {
        refuse(
            &arrival,
            &request,
            host.as_deref(),
            &path,
            status,
            "refused by policy",
        );
        return;
    }

    // The Origin allowlist and the session caps, held while it lasts. There
    // is no Media over QUIC on this protocol (MOQT negotiates its version
    // with WT-Available-Protocols, which it has no way to carry), so the
    // relay's own Origin rules never apply here.
    let origin = request
        .headers()
        .get(http::header::ORIGIN)
        .map(|o| o.to_str().unwrap_or("null"));
    let admission =
        match crate::webtransport_server::admit(&config, origin, arrival.remote_addr.ip(), true) {
            Ok(admission) => admission,
            Err(why) => {
                refuse(
                    &arrival,
                    &request,
                    host.as_deref(),
                    &path,
                    http::StatusCode::FORBIDDEN,
                    &why.to_string(),
                );
                return;
            }
        };

    // A path with no WebTransport route that the proxy does not serve itself
    // is refused at once, as over HTTP/3 (404), rather than held open
    if route.is_none() && !crate::webtransport_server::served_by_the_proxy(&path) {
        refuse(
            &arrival,
            &request,
            host.as_deref(),
            &path,
            http::StatusCode::NOT_FOUND,
            "no WebTransport service at this path",
        );
        return;
    }

    log_connect(
        &request,
        host.as_deref(),
        &path,
        arrival.remote_addr,
        &arrival.fingerprint,
        http::StatusCode::OK.as_u16(),
        LOG_PROTOCOL,
    );
    info!(
        "WebTransport over QUIC session accepted for {} on path {}",
        arrival.remote_addr, path
    );
    let session = Arc::new(QuicSession::new(connection.clone()));
    let served = crate::webtransport_server::serve_session(
        session,
        arrival.remote_addr,
        host,
        path,
        route.map(crate::webtransport_server::WtTarget::of),
        Arc::clone(&config),
        backend_pool,
        Some((*security).clone()),
    )
    .await;
    if let Err(e) = served {
        debug!(
            "WebTransport over QUIC session from {} ended: {}",
            arrival.remote_addr, e
        );
    }
    drop(admission);
    // The handler is done with the session, so the connection is too
    // (section 8: the session ends with it)
    if connection.close_reason().is_none() {
        wt_quic::close(&connection, wt_quic::CLOSE_DONE, "");
    }
}
