//! Per-route request gates, applied identically on every transport.
//!
//! These run after a route has been resolved and before the request is
//! forwarded: the 0-RTT policy, the HTTP/1.1 restriction, internal-route mTLS,
//! and per-route HMAC proof-of-possession. Redirect routes are handled by
//! [`redirect_target`], which callers apply before their CORS preflight so that
//! a preflight to an authenticated route is still answered.
//!
//! # Why this is not in the listeners
//!
//! It was, in one listener. Every gate below was enforced on the TCP path and
//! **none of them existed on the HTTP/3 path**, because the two transports each
//! carried their own copy of everything that happens after route resolution. A
//! route with `mtls_required` or an `hmac_secret` was protected over HTTP/1.1
//! and HTTP/2 and open over HTTP/3, and a `redirect` route answered 308 on TCP
//! and 502 over HTTP/3 — the browsers most likely to be on h3 are exactly the
//! ones that follow the `Alt-Svc` this proxy advertises.
//!
//! Nothing here needs to know which transport it is on. The connection-derived
//! headers (`x-tls-early-data`, `x-client-cert`) are established by the accept
//! loop, which strips any client-supplied copy first, so they cannot be forged.
//!
//! The protocol is **not** one of them. It arrives as [`GateContext::is_http11`],
//! read from the request's own version, because relying on an injected header
//! meant relying on all three TCP accept loops to inject it — and the plain
//! Rustls one, used whenever `fingerprint.tls_layer_capture` is off, never did.
//! That made the HTTP/1.1 gate fail open on that listener: a route with
//! `allow_http11 = false` served HTTP/1.1 whenever fingerprinting was disabled.
//! A gate that depends on cooperation from every code path that can reach it is
//! a gate that is off wherever someone forgot.

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::{HeaderMap, StatusCode};
use tracing::{debug, warn};

use crate::config::RouteConfig;
use crate::tls_acceptor::HmacNonceStore;

/// How far, in seconds, an HMAC timestamp may be from this server's clock,
/// either way. The nonce store is built from the same figure
/// ([`HmacNonceStore::for_timestamp_skew`]): it holds a nonce for as long as a
/// signature bearing it can still be accepted.
const HMAC_WINDOW_SECS: u64 = 300;

static NONCE_STORE: OnceLock<HmacNonceStore> = OnceLock::new();

/// The process-wide HMAC nonce store.
///
/// One store for the whole process, not one per listener. A nonce is a
/// single-use replay token, and each TCP listener used to build its own store —
/// so a nonce spent against a route on :443 could be spent again on another
/// listener, and the replay protection only held within whichever socket the
/// caller happened to use first. HTTP/3 had no store at all. Every transport
/// now consults this one.
///
/// Its retention follows [`HMAC_WINDOW_SECS`], the window the gate accepts
/// timestamps in, and nothing else: replay protection for these signatures is
/// a property of how long they are valid.
pub fn shared_nonce_store() -> &'static HmacNonceStore {
    NONCE_STORE.get_or_init(|| HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS))
}

/// What the gates decided.
pub enum GateOutcome {
    /// Every gate passed; forward the request.
    Continue,
    /// Refuse, with a status and any headers that must accompany it. Each
    /// transport renders this in its own response type; the decision is shared.
    Refuse {
        status: StatusCode,
        headers: Vec<(&'static str, String)>,
    },
}

/// Everything the gates read about a request.
pub struct GateContext<'a> {
    pub route: &'a RouteConfig,
    pub method: &'a str,
    /// Path plus query exactly as received — this is what the HMAC signs, so it
    /// must not be normalised or the signature will not verify.
    pub path_and_query: &'a str,
    /// Path only, for logging.
    pub path: &'a str,
    pub headers: &'a HeaderMap,
    /// The `Content-Digest` a body decoded before the gates was verified
    /// against and stripped of ([`VerifiedContentDigest`])
    pub verified_content_digest: Option<&'a str>,
    pub client_ip: IpAddr,
    /// Whether this request arrived over HTTP/1.1.
    ///
    /// Taken from the request's own version, not from a header. It used to be
    /// read from `x-connection-protocol`, which each accept loop was expected to
    /// inject — and the plain Rustls listener, the one used whenever
    /// `fingerprint.tls_layer_capture` is off, never did. The HTTP/1.1 gate
    /// therefore failed **open** on that listener: a route with
    /// `allow_http11 = false` accepted HTTP/1.1 whenever fingerprinting happened
    /// to be disabled, which is a security decision silently contingent on an
    /// unrelated performance switch.
    pub is_http11: bool,
    /// A WebSocket upgrade is always HTTP/1.1, so it bypasses the HTTP/1.1 gate
    /// when the route opts into WebSocket passthrough.
    pub is_websocket_upgrade: bool,
    /// Whether this request arrived over HTTP/3. A client that sends no
    /// certificate over QUIC is answered 421 rather than 401 on an mTLS route
    /// (see `mtls_gate`), so it repeats the request on a new connection.
    pub is_http3: bool,
    /// `tls.zero_rtt_safe_methods` — which methods may ride on early data.
    pub zero_rtt_safe_methods: &'a [String],
    pub hmac_nonce_store: &'a HmacNonceStore,
}

/// Where a redirect route should send this request, and whether permanently.
///
/// Separate from [`evaluate`] because callers apply it *before* answering a
/// CORS preflight, matching the order the TCP path has always used.
pub fn redirect_target(route: &RouteConfig, path: &str, query: &str) -> Option<(String, bool)> {
    let redirect_to = route.redirect.as_ref()?;
    // Replace the prefix with the redirect target, keeping the rest. The route
    // matched case-insensitively, so the prefix is compared the same way. A
    // lowercase-only comparison assumed `normalize_paths` had already
    // lowercased the path; with it off, `/THREAT_BOT/x` went to `/threat-bot`.
    let rest = route.path_prefix.as_deref().and_then(|prefix| {
        crate::config::starts_with_ignore_ascii_case(path, prefix)
            .then(|| rest_after_prefix(prefix, &path[prefix.len()..]))
            .flatten()
    });
    Some((
        join_redirect(redirect_to, rest, query),
        route.redirect_permanent,
    ))
}

/// What of a path follows its route's prefix at a segment boundary: `None`
/// for an exact match or one that ends inside a segment (`/oldx` under
/// `/old`), `Some(rest)` after a `/` (`/old/deep` → `deep`, `/old/` → ``).
///
/// The rest is carried over only from a boundary, and [`join_redirect`] puts
/// it under exactly one `/`: what follows the prefix is always a path below
/// the target, whatever form the target and the request's path take.
fn rest_after_prefix<'a>(prefix: &str, suffix: &'a str) -> Option<&'a str> {
    if prefix.ends_with('/') {
        Some(suffix)
    } else {
        suffix.strip_prefix('/')
    }
}

/// `target` with the rest of the path joined on under exactly one `/`, then
/// the request's query. A target that carries a query of its own keeps it and
/// takes the request's after it; the rest of the path then has no place in it
/// and is left off.
fn join_redirect(target: &str, rest: Option<&str>, query: &str) -> String {
    let (base, own_query) = match target.split_once('?') {
        Some((base, q)) => (base, Some(q)),
        None => (target, None),
    };
    let mut out = String::with_capacity(target.len() + query.len() + 16);
    match rest {
        Some(rest) if own_query.is_none() => {
            out.push_str(base.trim_end_matches('/'));
            out.push('/');
            out.push_str(rest.trim_start_matches('/'));
        }
        _ => out.push_str(base),
    }
    let incoming = query.strip_prefix('?').unwrap_or(query);
    match (own_query, incoming.is_empty()) {
        (Some(q), true) => {
            out.push('?');
            out.push_str(q);
        }
        (Some(q), false) => {
            out.push('?');
            out.push_str(q);
            out.push('&');
            out.push_str(incoming);
        }
        (None, false) => {
            out.push('?');
            out.push_str(incoming);
        }
        (None, true) => {}
    }
    out
}

/// Run every per-route gate, in the order the TCP path established.
pub fn evaluate(cx: &GateContext<'_>) -> GateOutcome {
    if let Some(outcome) = zero_rtt_gate(cx) {
        return outcome;
    }
    if let Some(outcome) = http11_gate(cx) {
        return outcome;
    }
    if let Some(outcome) = mtls_gate(cx) {
        return outcome;
    }
    if let Some(outcome) = hmac_gate(cx) {
        return outcome;
    }
    GateOutcome::Continue
}

fn refuse(status: StatusCode) -> Option<GateOutcome> {
    Some(GateOutcome::Refuse {
        status,
        headers: Vec::new(),
    })
}

/// SEC-002: per-route 0-RTT (early data) policy, RFC 8470.
///
/// `x-tls-early-data` is set exclusively by the accept loop after stripping any
/// client-supplied copy, so it cannot be forged. Routes with `allow_0rtt = false`
/// (the default) must not receive early data, which a network attacker can replay.
fn zero_rtt_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    let is_early_data = cx
        .headers
        .get("x-tls-early-data")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);

    if !is_early_data {
        return None;
    }

    if !cx.route.allow_0rtt {
        // RFC 8470: 425 Too Early — unwilling to risk processing a request that
        // might be a replay.
        debug!(
            "Rejecting 0-RTT early-data request on route {:?} (allow_0rtt = false): {} {}",
            cx.route.name, cx.method, cx.path
        );
        return refuse(StatusCode::TOO_EARLY);
    }

    // L-5: the per-route flag says *whether* early data is allowed at all; this
    // says *what* may travel on it, and both have to hold. Without this a route
    // with `allow_0rtt = true` forwarded a replayable POST as happily as a GET.
    let safe = cx
        .zero_rtt_safe_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(cx.method));
    if !safe {
        debug!(
            "Rejecting 0-RTT early-data request on route {:?}: method {} is not in tls.zero_rtt_safe_methods",
            cx.route.name, cx.method
        );
        return refuse(StatusCode::TOO_EARLY);
    }
    None
}

/// Per-route HTTP/1.1 restriction, RFC 7231 §6.5.15.
///
/// `x-connection-protocol` is set exclusively by the accept loop after stripping
/// any client-supplied copy. Routes with `allow_http11 = false` (the default)
/// require HTTP/2 or HTTP/3.
fn http11_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    // From the request's own version. Reading `x-connection-protocol` here meant
    // trusting every accept loop to inject it, and one of the three did not.
    let is_http1 = cx.is_http11;

    // A WebSocket upgrade is always HTTP/1.1 — bypass the gate when the route
    // explicitly enables WebSocket passthrough.
    let ws_passthrough = cx.is_websocket_upgrade && cx.route.supports_websocket;
    if is_http1 && !cx.route.allow_http11 && !ws_passthrough {
        debug!(
            "Rejecting HTTP/1.1 request on route {:?} (allow_http11 = false): {} {}",
            cx.route.name, cx.method, cx.path
        );
        return Some(GateOutcome::Refuse {
            status: StatusCode::UPGRADE_REQUIRED,
            headers: vec![("upgrade", "h2, h3".to_string())],
        });
    }
    None
}

/// Per-route mTLS enforcement: `[routes.security] mtls_required`, which
/// defaults to true on an `internal = true` route and false elsewhere.
///
/// It used to run for internal routes only, so `mtls_required = true` on any
/// other route -- documented as "Require mTLS for this route" -- did nothing.
///
/// `x-client-cert` is set exclusively by the TLS accept loop, stripped from any
/// client-supplied copy, so it cannot be forged. A transport that cannot present
/// a client certificate therefore fails this closed, which is the intent: an
/// mTLS route is not reachable from a transport that cannot authenticate.
///
/// Every listener asks for a certificate wherever a route needs one, QUIC
/// included, but not every client answers over QUIC: a browser may present its
/// certificate over TLS on TCP alone. An HTTP/3 request without one is
/// therefore answered 421 Misdirected Request (RFC 9110 section 15.5.20),
/// which a client may repeat on a new connection -- Chromium repeats it
/// without the HTTP/3 alternative, over TCP, where its certificate is sent.
/// Over TCP the answer is 401.
fn mtls_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    if !cx.route.requires_client_cert() {
        return None;
    }

    let client_cert_present = cx
        .headers
        .get("x-client-cert")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "1")
        .unwrap_or(false);
    if !client_cert_present {
        warn!(
            "mTLS route {:?} rejected request from {}: no client certificate",
            cx.route.name, cx.client_ip
        );
        return refuse(if cx.is_http3 {
            StatusCode::MISDIRECTED_REQUEST
        } else {
            StatusCode::UNAUTHORIZED
        });
    }
    None
}

/// The admin API's request signature, which covers the body too.
///
/// Hex HMAC-SHA256 of `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nNONCE\nBODY_SHA256`
/// (the body's SHA-256 in hex, of no bytes for a request without one), so
/// neither the request nor its body can be changed on the way.
pub fn admin_request_signature(
    secret: &str,
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Digest;
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(
        format!(
            "{method}\n{path_and_query}\n{timestamp}\n{nonce}\n{}",
            hex::encode(sha2::Sha256::digest(body))
        )
        .as_bytes(),
    );
    hex::encode(mac.finalize().into_bytes())
}

/// A route request's signature, which covers its body through `Content-Digest`.
///
/// Hex HMAC-SHA256 of `METHOD\nPATH_AND_QUERY\nTIMESTAMP\nNONCE\nCONTENT_DIGEST`,
/// the last the request's `Content-Digest` field as sent (RFC 9530), empty
/// when it has none.
pub fn route_request_signature(
    secret: &str,
    method: &str,
    path_and_query: &str,
    timestamp: &str,
    nonce: &str,
    content_digest: &str,
) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(
        format!("{method}\n{path_and_query}\n{timestamp}\n{nonce}\n{content_digest}").as_bytes(),
    );
    hex::encode(mac.finalize().into_bytes())
}

/// A `Content-Digest` verified before its body was decoded and it was removed.
///
/// Checked against the body as received; the body sent on is no longer the
/// one it describes. A request extension, so a signature that covers the
/// field still verifies.
#[derive(Debug, Clone)]
pub struct VerifiedContentDigest(pub String);

/// The SHA-256 a signed route request's body must have as it is forwarded.
///
/// The `sha-256` of its `Content-Digest` (RFC 9530), or that of no bytes when
/// it sends none. `None` for a route that signs nothing, for a field with no
/// usable sha-256 (the gate refuses it), and for a body already verified
/// before it was decoded (`verified`).
pub fn expected_body_digest(
    route: &crate::config::RouteConfig,
    headers: &HeaderMap,
    verified: bool,
) -> Option<[u8; 32]> {
    use sha2::Digest;
    route.security.as_ref()?.hmac_secret.as_ref()?;
    match headers.get("content-digest") {
        Some(field) => content_digest_sha256(field.to_str().ok()?),
        None if verified => None,
        None => Some(sha2::Sha256::digest(b"").into()),
    }
}

/// Whether `body` is what its `Content-Digest` says: `Ok(None)` without the
/// field (or with none of the algorithms this checks), `Ok(Some(field))`
/// when its sha-256 matches, `Err` when it does not.
pub fn check_content_digest(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<String>, DigestMismatch> {
    use sha2::Digest;
    let Some(field) = headers.get("content-digest").and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    match content_digest_sha256(field) {
        None => Ok(None),
        Some(expected) if <[u8; 32]>::from(sha2::Sha256::digest(body)) == expected => {
            Ok(Some(field.to_string()))
        }
        Some(_) => Err(DigestMismatch),
    }
}

/// A body that is not what its `Content-Digest` says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestMismatch;

impl std::fmt::Display for DigestMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the body does not match its Content-Digest")
    }
}

impl std::error::Error for DigestMismatch {}

/// The `sha-256` member of a `Content-Digest` field: `sha-256=:<base64>:`
/// among its comma-separated members (RFC 9530 section 2, a structured
/// dictionary of byte sequences).
fn content_digest_sha256(field: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    field.split(',').find_map(|member| {
        let (key, value) = member.trim().split_once('=')?;
        if !key.trim().eq_ignore_ascii_case("sha-256") {
            return None;
        }
        let bytes = value.trim().strip_prefix(':')?.strip_suffix(':')?;
        base64::engine::general_purpose::STANDARD
            .decode(bytes)
            .ok()?
            .try_into()
            .ok()
    })
}

pin_project_lite::pin_project! {
    /// A request body checked against the digest its signature covered: at
    /// its end, one whose SHA-256 differs ends in an error instead, so the
    /// backend never has it whole.
    pub struct DigestChecked<B> {
        #[pin]
        inner: B,
        hasher: sha2::Sha256,
        expected: [u8; 32],
        finished: bool,
    }
}

impl<B> DigestChecked<B> {
    pub fn new(inner: B, expected: [u8; 32]) -> Self {
        use sha2::Digest;
        Self {
            inner,
            hasher: sha2::Sha256::new(),
            expected,
            finished: false,
        }
    }
}

impl<B> hyper::body::Body for DigestChecked<B>
where
    B: hyper::body::Body<Data = bytes::Bytes>,
    B::Error: Into<axum::BoxError>,
{
    type Data = bytes::Bytes;
    type Error = axum::BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, axum::BoxError>>> {
        use sha2::Digest;
        use std::task::Poll;
        let this = self.project();
        if *this.finished {
            return Poll::Ready(None);
        }
        match std::task::ready!(this.inner.poll_frame(cx)) {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    this.hasher.update(data);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            None => {
                *this.finished = true;
                let got: [u8; 32] = this.hasher.finalize_reset().into();
                if got == *this.expected {
                    Poll::Ready(None)
                } else {
                    warn!("A signed request's body does not match its Content-Digest");
                    Poll::Ready(Some(Err(
                        "the request body does not match its signed Content-Digest".into(),
                    )))
                }
            }
        }
    }
}

/// Per-route HMAC proof-of-possession.
///
/// Signature: [`route_request_signature`], over the method, path and query,
/// timestamp, nonce and `Content-Digest`, whose sha-256 the body is held to
/// as it is forwarded ([`DigestChecked`]; a request with no field must have
/// no body). `X-Request-Nonce` (8 to 128 characters) is required, bound into
/// the signature and accepted once within the window: a signed request cannot
/// be sent again, which freshness alone (the timestamp) would allow for the
/// whole window.
fn hmac_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    use subtle::ConstantTimeEq;

    let secret = cx
        .route
        .security
        .as_ref()
        .and_then(|s| s.hmac_secret.as_ref())?;

    let sig = cx
        .headers
        .get("x-request-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ts = cx
        .headers
        .get("x-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(nonce_val) = cx
        .headers
        .get("x-request-nonce")
        .and_then(|v| v.to_str().ok())
        .filter(|n| (8..=128).contains(&n.len()))
    else {
        warn!(
            "Route {:?} HMAC request from {} carries no usable nonce",
            cx.route.name, cx.client_ip
        );
        return refuse(StatusCode::UNAUTHORIZED);
    };

    let ts_u: u64 = ts.parse().unwrap_or(0);
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_ts.abs_diff(ts_u) > HMAC_WINDOW_SECS {
        warn!(
            "Route {:?} HMAC timestamp out of {}s window from {}",
            cx.route.name, HMAC_WINDOW_SECS, cx.client_ip
        );
        return refuse(StatusCode::UNAUTHORIZED);
    }

    // The full path and query are signed, so no parameter can be changed, and
    // the body's digest, so neither can it.
    let content_digest = match cx.headers.get("content-digest") {
        None => cx.verified_content_digest.unwrap_or_default(),
        Some(field) => match field.to_str() {
            Ok(text) if content_digest_sha256(text).is_some() => text,
            _ => {
                warn!(
                    "Route {:?} HMAC request from {} has a Content-Digest with no sha-256",
                    cx.route.name, cx.client_ip
                );
                return refuse(StatusCode::BAD_REQUEST);
            }
        },
    };
    let expected = route_request_signature(
        secret,
        cx.method,
        cx.path_and_query,
        ts,
        nonce_val,
        content_digest,
    );

    let valid: bool = sig.as_bytes().ct_eq(expected.as_bytes()).into();
    if !valid {
        warn!(
            "Route {:?} HMAC signature invalid from {}",
            cx.route.name, cx.client_ip
        );
        return refuse(StatusCode::UNAUTHORIZED);
    }

    // Nonce deduplication: reject replays within the window. Runs after
    // signature validation so a bad signature cannot pollute the store.
    if cx.hmac_nonce_store.check_and_insert(nonce_val) {
        warn!(
            "Route {:?} HMAC nonce replay detected from {}",
            cx.route.name, cx.client_ip
        );
        return refuse(StatusCode::UNAUTHORIZED);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// Build a route from TOML rather than a struct literal: `RouteConfig` has
    /// many fields and no `Default`, so a literal here would need editing every
    /// time an unrelated field is added.
    fn route_from(toml_src: &str) -> RouteConfig {
        toml::from_str(toml_src).expect("valid route TOML")
    }

    /// A secret of this run's own: the gate verifies against the route's
    /// configured secret, whatever it is, not one written into its tests.
    fn test_secret() -> String {
        hex::encode(rand::random::<[u8; 32]>())
    }

    /// A nonce of this run's own, as a client makes one: never a value
    /// written into the tests.
    fn test_nonce() -> String {
        hex::encode(rand::random::<[u8; 16]>())
    }

    fn route() -> RouteConfig {
        route_from("name = \"t\"\nbackend = \"b\"\n")
    }

    /// The admin signature covers the body: the same request with another
    /// body, or none, signs differently, and no body signs as an empty one.
    #[test]
    fn the_admin_signature_covers_the_body() {
        let secret = test_secret();
        let nonce = test_nonce();
        let sign = |body: &[u8]| {
            admin_request_signature(
                &secret,
                "POST",
                "/pools/p/servers/s/canary",
                "1",
                &nonce,
                body,
            )
        };
        assert_ne!(sign(b"{\"weight\":5}"), sign(b"{\"weight\":50}"));
        assert_ne!(sign(b"{\"weight\":5}"), sign(b""));
        assert_eq!(sign(b""), sign(&[]));
        assert_ne!(
            sign(b""),
            route_request_signature(
                &secret,
                "POST",
                "/pools/p/servers/s/canary",
                "1",
                &nonce,
                ""
            ),
            "not the route signature"
        );
    }

    #[test]
    fn content_digest_reads_its_sha256_member() {
        use base64::Engine;
        use sha2::Digest;
        let digest: [u8; 32] = sha2::Sha256::digest(b"{\"a\":1}").into();
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        assert_eq!(
            content_digest_sha256(&format!("sha-256=:{b64}:")),
            Some(digest)
        );
        assert_eq!(
            content_digest_sha256(&format!("sha-512=:AAAA:, sha-256=:{b64}:")),
            Some(digest)
        );
        assert_eq!(content_digest_sha256("sha-512=:AAAA:"), None);
        assert_eq!(content_digest_sha256("sha-256=:not base64:"), None);

        let mut h = HeaderMap::new();
        assert_eq!(check_content_digest(&h, b"x"), Ok(None));
        h.insert(
            "content-digest",
            HeaderValue::from_str(&format!("sha-256=:{b64}:")).unwrap(),
        );
        assert!(check_content_digest(&h, b"{\"a\":1}").unwrap().is_some());
        assert_eq!(check_content_digest(&h, b"{\"a\":2}"), Err(DigestMismatch));
    }

    /// A signed body is forwarded as it comes, and ends in an error where it
    /// is not the one signed, so the backend never has it whole.
    #[tokio::test]
    async fn a_signed_body_that_differs_ends_in_an_error() {
        use http_body_util::BodyExt;
        use sha2::Digest;
        let signed: [u8; 32] = sha2::Sha256::digest(b"hello world").into();
        let whole = DigestChecked::new(axum::body::Body::from("hello world"), signed)
            .collect()
            .await;
        assert_eq!(whole.unwrap().to_bytes().as_ref(), b"hello world");
        let other = DigestChecked::new(axum::body::Body::from("hello there"), signed)
            .collect()
            .await;
        assert!(other.is_err());
    }

    fn ctx<'a>(
        r: &'a RouteConfig,
        h: &'a HeaderMap,
        store: &'a HmacNonceStore,
        method: &'a str,
        safe: &'a [String],
    ) -> GateContext<'a> {
        ctx_proto(r, h, store, method, safe, false)
    }

    fn ctx_proto<'a>(
        r: &'a RouteConfig,
        h: &'a HeaderMap,
        store: &'a HmacNonceStore,
        method: &'a str,
        safe: &'a [String],
        is_http11: bool,
    ) -> GateContext<'a> {
        GateContext {
            route: r,
            method,
            path_and_query: "/x",
            path: "/x",
            headers: h,
            verified_content_digest: None,
            client_ip: "203.0.113.9".parse().unwrap(),
            is_http11,
            is_websocket_upgrade: false,
            is_http3: false,
            zero_rtt_safe_methods: safe,
            hmac_nonce_store: store,
        }
    }

    fn status_of(o: &GateOutcome) -> Option<StatusCode> {
        match o {
            GateOutcome::Continue => None,
            GateOutcome::Refuse { status, .. } => Some(*status),
        }
    }

    /// A redirect route yields a target regardless of transport — the HTTP/3
    /// path had no redirect handling at all and answered 502 for these.
    #[test]
    fn redirect_route_rewrites_the_prefix() {
        let mut r = route();
        r.path_prefix = Some("/http3_quic".to_string());
        r.redirect = Some("/http3-quic".to_string());
        r.redirect_permanent = true;
        let (target, permanent) = redirect_target(&r, "/http3_quic", "").expect("a redirect");
        assert_eq!(target, "/http3-quic");
        assert!(permanent);
    }

    #[test]
    fn redirect_keeps_the_suffix_and_query() {
        let mut r = route();
        r.path_prefix = Some("/old".to_string());
        r.redirect = Some("/new".to_string());
        let (target, permanent) = redirect_target(&r, "/old/deep", "?a=1").expect("a redirect");
        assert_eq!(target, "/new/deep?a=1");
        assert!(!permanent);
    }

    #[test]
    fn redirect_keeps_the_suffix_of_a_mixed_case_path() {
        let mut r = route();
        r.path_prefix = Some("/threat_bot".to_string());
        r.redirect = Some("/threat-bot".to_string());
        let (target, _) = redirect_target(&r, "/THREAT_BOT/x", "").expect("a redirect");
        assert_eq!(target, "/threat-bot/x");
        r.path_prefix = Some("/Encryption/Fun/FractalTree".to_string());
        r.redirect = Some("/fun/fractaltree".to_string());
        let (target, _) =
            redirect_target(&r, "/encryption/fun/fractaltree/", "").expect("a redirect");
        assert_eq!(target, "/fun/fractaltree/");
    }

    /// The rest of the path is carried over only from a segment boundary and
    /// under exactly one `/`: it is always a path below the target.
    #[test]
    fn a_redirect_never_leaves_its_target() {
        let mut r = route();
        r.path_prefix = Some("/old".to_string());
        r.redirect = Some("https://example.com".to_string());
        let to =
            |r: &RouteConfig, path: &str, query: &str| redirect_target(r, path, query).unwrap().0;
        assert_eq!(to(&r, "/old.other.example/x", ""), "https://example.com");
        assert_eq!(to(&r, "/oldx", "?q=1"), "https://example.com?q=1");
        assert_eq!(to(&r, "/old/x", ""), "https://example.com/x");
        assert_eq!(to(&r, "/old", ""), "https://example.com");

        r.redirect = Some("/".to_string());
        assert_eq!(to(&r, "/old//other.example/x", ""), "/other.example/x");
        assert_eq!(to(&r, "/old///", ""), "/");

        // A prefix ending in `/` is itself the boundary
        r.path_prefix = Some("/old/".to_string());
        r.redirect = Some("/new".to_string());
        assert_eq!(to(&r, "/old/deep", ""), "/new/deep");
        assert_eq!(to(&r, "/old/", ""), "/new/");

        // A target with a query keeps it, and the request's follows it
        r.redirect = Some("/new?from=old".to_string());
        assert_eq!(to(&r, "/old/deep", "?a=1"), "/new?from=old&a=1");
        assert_eq!(to(&r, "/old/deep", ""), "/new?from=old");
    }

    #[test]
    fn a_plain_route_is_not_a_redirect() {
        assert!(redirect_target(&route(), "/x", "").is_none());
    }

    /// An internal route with no client certificate is refused. On HTTP/3 no
    /// certificate is ever presented, so this is what keeps an internal route
    /// off that transport rather than silently open on it.
    #[test]
    fn internal_route_without_a_client_cert_is_unauthorized() {
        let mut r = route();
        r.internal = true;
        let h = HeaderMap::new();
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    /// Over HTTP/3 the same refusal is 421, which a client repeats on a new
    /// connection, where TLS on TCP carries its certificate.
    #[test]
    fn an_mtls_route_answers_421_over_http3_without_a_certificate() {
        let mut r = route();
        r.internal = true;
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        let none = HeaderMap::new();
        let mut cx = ctx(&r, &none, &store, "GET", &safe);
        cx.is_http3 = true;
        assert_eq!(
            status_of(&evaluate(&cx)),
            Some(StatusCode::MISDIRECTED_REQUEST)
        );
        let mut with = HeaderMap::new();
        with.insert("x-client-cert", HeaderValue::from_static("1"));
        let mut cx = ctx(&r, &with, &store, "GET", &safe);
        cx.is_http3 = true;
        assert!(status_of(&evaluate(&cx)).is_none());
    }

    #[test]
    fn internal_route_with_a_client_cert_passes() {
        let mut r = route();
        r.internal = true;
        let mut h = HeaderMap::new();
        h.insert("x-client-cert", HeaderValue::from_static("1"));
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert!(status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none());
    }

    /// `mtls_required` on a route that is not internal. The gate used to run
    /// for internal routes only, so this setting did nothing.
    #[test]
    fn mtls_required_applies_to_any_route() {
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            mtls_required: Some(true),
            ..Default::default()
        });
        assert!(r.requires_client_cert());
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        let none = HeaderMap::new();
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &none, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
        let mut with = HeaderMap::new();
        with.insert("x-client-cert", HeaderValue::from_static("1"));
        assert!(status_of(&evaluate(&ctx(&r, &with, &store, "GET", &safe))).is_none());
    }

    /// An internal route may opt out explicitly.
    #[test]
    fn internal_route_can_opt_out_of_mtls() {
        let mut r = route();
        r.internal = true;
        r.security = Some(crate::config::RouteSecurityPolicy {
            mtls_required: Some(false),
            ..Default::default()
        });
        assert!(!r.requires_client_cert());
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert!(status_of(&evaluate(&ctx(&r, &HeaderMap::new(), &store, "GET", &safe))).is_none());
    }

    /// Early data on a route that did not opt in is 425, per RFC 8470.
    #[test]
    fn early_data_on_a_non_0rtt_route_is_too_early() {
        let r = route(); // allow_0rtt defaults false
        let mut h = HeaderMap::new();
        h.insert("x-tls-early-data", HeaderValue::from_static("1"));
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec!["GET".to_string()];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::TOO_EARLY)
        );
    }

    /// Opting a route into 0-RTT still does not let a non-idempotent method ride
    /// on replayable early data.
    #[test]
    fn early_data_with_an_unsafe_method_is_too_early() {
        let mut r = route();
        r.allow_0rtt = true;
        let mut h = HeaderMap::new();
        h.insert("x-tls-early-data", HeaderValue::from_static("1"));
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec!["GET".to_string(), "HEAD".to_string()];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "POST", &safe))),
            Some(StatusCode::TOO_EARLY)
        );
        assert!(status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none());
    }

    /// The HTTP/1.1 gate fires on HTTP/1.1 and not on anything else, and it reads
    /// the connection's real protocol rather than a header.
    #[test]
    fn the_http11_gate_fires_only_on_http11() {
        let r = route(); // allow_http11 defaults false
        let h = HeaderMap::new();
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];

        assert!(
            status_of(&evaluate(&ctx_proto(&r, &h, &store, "GET", &safe, false))).is_none(),
            "HTTP/2 and HTTP/3 must pass a route that forbids HTTP/1.1"
        );
        assert_eq!(
            status_of(&evaluate(&ctx_proto(&r, &h, &store, "GET", &safe, true))),
            Some(StatusCode::UPGRADE_REQUIRED)
        );
    }

    /// Regression: the gate must not be satisfiable, or defeatable, by a header.
    ///
    /// It used to read `x-connection-protocol`, which each accept loop was
    /// expected to inject. The plain Rustls listener — the one used whenever
    /// `fingerprint.tls_layer_capture` is off — never injected it, so the gate
    /// failed **open** there and a route with `allow_http11 = false` served
    /// HTTP/1.1 whenever fingerprinting happened to be disabled. Found on
    /// 2026-09-07: the same config answered 200 to an HTTP/1.1 request with
    /// fingerprinting off and 426 with it on.
    #[test]
    fn the_http11_gate_ignores_the_connection_protocol_header() {
        let r = route(); // allow_http11 defaults false
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];

        // A real HTTP/1.1 request is refused even with no header to say so —
        // this is the case the plain listener used to let through.
        let empty = HeaderMap::new();
        assert_eq!(
            status_of(&evaluate(&ctx_proto(
                &r, &empty, &store, "GET", &safe, true
            ))),
            Some(StatusCode::UPGRADE_REQUIRED),
            "the gate must not depend on an accept loop injecting a header"
        );

        // And a client asserting h3 cannot talk its way out of it.
        let mut spoofed = HeaderMap::new();
        spoofed.insert("x-connection-protocol", HeaderValue::from_static("h3"));
        assert_eq!(
            status_of(&evaluate(&ctx_proto(
                &r, &spoofed, &store, "GET", &safe, true
            ))),
            Some(StatusCode::UPGRADE_REQUIRED)
        );
    }

    /// A route carrying an `hmac_secret` refuses an unsigned request, on every
    /// transport. This gate did not exist on the HTTP/3 path.
    #[test]
    fn hmac_route_refuses_an_unsigned_request() {
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some(test_secret()),
            ..Default::default()
        });
        let h = HeaderMap::new();
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    /// A correctly signed request passes, and replaying its nonce does not.
    #[test]
    fn hmac_signature_verifies_and_the_nonce_cannot_be_replayed() {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        let secret = test_secret();
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some(secret.clone()),
            ..Default::default()
        });

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "n-once-1";
        // No Content-Digest: the signature ends with an empty one
        let message = format!("GET\n/x\n{}\n{}\n", ts, nonce);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut h = HeaderMap::new();
        h.insert("x-request-signature", HeaderValue::from_str(&sig).unwrap());
        h.insert("x-request-timestamp", HeaderValue::from_str(&ts).unwrap());
        h.insert("x-request-nonce", HeaderValue::from_static("n-once-1"));

        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none(),
            "a correctly signed request must pass"
        );
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED),
            "the same nonce must not be accepted twice"
        );
    }

    /// A request signed without a nonce could be sent again for the whole
    /// window, so it is refused however good its signature.
    #[test]
    fn hmac_without_a_nonce_is_refused() {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::Sha256;

        // A key of this run's own: the signature is as good as one can be
        let key = hex::encode(rand::random::<[u8; 32]>());
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some(key.clone()),
            ..Default::default()
        });
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(format!("GET\n/x\n{ts}").as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());
        let mut h = HeaderMap::new();
        h.insert("x-request-signature", HeaderValue::from_str(&sig).unwrap());
        h.insert("x-request-timestamp", HeaderValue::from_str(&ts).unwrap());
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    /// A stale timestamp is refused even when the signature over it is valid.
    #[test]
    fn hmac_stale_timestamp_is_refused() {
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some(test_secret()),
            ..Default::default()
        });
        let mut h = HeaderMap::new();
        h.insert("x-request-timestamp", HeaderValue::from_static("1"));
        h.insert("x-request-signature", HeaderValue::from_static("deadbeef"));
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    /// A signature's timestamp passes for `HMAC_WINDOW_SECS` either side of
    /// this clock, so a signature can be presented over twice that span. Its
    /// nonce is held for all of it, across a generation rotation too: a
    /// replay at any point a signature could still be accepted is refused.
    #[test]
    fn a_nonce_is_held_for_as_long_as_its_signature_is_accepted() {
        let secs = std::time::Duration::from_secs;
        let span = 2 * HMAC_WINDOW_SECS;
        let store = HmacNonceStore::for_timestamp_skew(HMAC_WINDOW_SECS);
        let t0 = std::time::Instant::now();
        let first = test_nonce();
        assert!(!store.check_and_insert_at(&first, t0));
        for later in [1, span / 2, span - 1] {
            assert!(store.check_and_insert_at(&first, t0 + secs(later)));
        }
        // Spent just before the store rotates, and replayed as late as a
        // signature carrying it could still be accepted
        let late = t0 + secs(span - 1);
        let late_nonce = test_nonce();
        assert!(!store.check_and_insert_at(&late_nonce, late));
        assert!(store.check_and_insert_at(&late_nonce, late + secs(span - 1)));
    }

    /// The store every listener shares is built from the gate's own window,
    /// not from an unrelated setting.
    #[test]
    fn the_shared_store_follows_the_hmac_window() {
        let store = shared_nonce_store();
        let t0 = std::time::Instant::now();
        let nonce = test_nonce();
        assert!(!store.check_and_insert_at(&nonce, t0));
        let still_valid = t0 + std::time::Duration::from_secs(2 * HMAC_WINDOW_SECS - 1);
        assert!(store.check_and_insert_at(&nonce, still_valid));
    }
}
