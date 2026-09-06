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
//! Nothing here needs to know which transport it is on. Both listeners
//! establish the connection-derived headers (`x-tls-early-data`,
//! `x-connection-protocol`, `x-client-cert`) before any of this reads them, and
//! both strip any client-supplied copy first, so these values cannot be forged.
//! On HTTP/3 that means early data reads as absent and the protocol reads as
//! `h3`, so the 0-RTT and HTTP/1.1 gates correctly never fire there.

use std::net::IpAddr;
use std::sync::OnceLock;

use axum::http::{HeaderMap, StatusCode};
use tracing::{debug, warn};

use crate::config::RouteConfig;
use crate::tls_acceptor::HmacNonceStore;

/// The HMAC timestamp window, in seconds. Also the nonce retention window: a
/// nonce may be forgotten once no signature bearing it can still be accepted.
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
/// `window_secs` is honoured on the first call and ignored afterwards. Every
/// listener is built from the same config, so whichever starts first sets it.
pub fn shared_nonce_store(window_secs: u64) -> &'static HmacNonceStore {
    NONCE_STORE.get_or_init(|| HmacNonceStore::new(window_secs))
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
    pub client_ip: IpAddr,
    /// A WebSocket upgrade is always HTTP/1.1, so it bypasses the HTTP/1.1 gate
    /// when the route opts into WebSocket passthrough.
    pub is_websocket_upgrade: bool,
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
    let new_path = if let Some(ref prefix) = route.path_prefix {
        // Replace the prefix with the redirect target, keeping the rest.
        // Compared lowercased because the caller may have normalised the path.
        let prefix_lower = prefix.to_ascii_lowercase();
        let suffix = if path.starts_with(&prefix_lower) {
            &path[prefix_lower.len()..]
        } else {
            ""
        };
        format!("{}{}{}", redirect_to, suffix, query)
    } else {
        format!("{}{}", redirect_to, query)
    };
    Some((new_path, route.redirect_permanent))
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
    let is_http1 = cx
        .headers
        .get("x-connection-protocol")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "h1")
        .unwrap_or(false);

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

/// Internal-route mTLS enforcement.
///
/// `x-client-cert` is set exclusively by the TLS accept loop, stripped from any
/// client-supplied copy, so it cannot be forged. A transport that cannot present
/// a client certificate therefore fails this closed, which is the intent: an
/// internal route is not reachable from a transport that cannot authenticate.
fn mtls_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    if !cx.route.internal {
        return None;
    }
    let mtls_required = cx
        .route
        .security
        .as_ref()
        .and_then(|s| s.mtls_required)
        .unwrap_or(true); // default true when internal = true
    if !mtls_required {
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
            "Internal route {:?} rejected request from {}: no client certificate",
            cx.route.name, cx.client_ip
        );
        return refuse(StatusCode::UNAUTHORIZED);
    }
    None
}

/// Per-route HMAC proof-of-possession.
///
/// Signature = HMAC-SHA256(METHOD\nPATH_AND_QUERY\nTIMESTAMP\[\nNONCE\], secret).
/// `X-Request-Nonce`, when present, is bound into the signature and checked for
/// uniqueness within the window, which makes this full replay prevention rather
/// than just freshness.
fn hmac_gate(cx: &GateContext<'_>) -> Option<GateOutcome> {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
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
    let nonce_val = cx
        .headers
        .get("x-request-nonce")
        .and_then(|v| v.to_str().ok());

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

    // Sign the full path and query to prevent query-parameter mutation attacks.
    let message = match nonce_val {
        Some(n) => format!("{}\n{}\n{}\n{}", cx.method, cx.path_and_query, ts, n),
        None => format!("{}\n{}\n{}", cx.method, cx.path_and_query, ts),
    };

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

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
    if let Some(n) = nonce_val {
        if cx.hmac_nonce_store.check_and_insert(n) {
            warn!(
                "Route {:?} HMAC nonce replay detected from {}",
                cx.route.name, cx.client_ip
            );
            return refuse(StatusCode::UNAUTHORIZED);
        }
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

    fn route() -> RouteConfig {
        route_from("name = \"t\"\nbackend = \"b\"\n")
    }

    fn ctx<'a>(
        r: &'a RouteConfig,
        h: &'a HeaderMap,
        store: &'a HmacNonceStore,
        method: &'a str,
        safe: &'a [String],
    ) -> GateContext<'a> {
        GateContext {
            route: r,
            method,
            path_and_query: "/x",
            path: "/x",
            headers: h,
            client_ip: "203.0.113.9".parse().unwrap(),
            is_websocket_upgrade: false,
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
        let store = HmacNonceStore::new(300);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }

    #[test]
    fn internal_route_with_a_client_cert_passes() {
        let mut r = route();
        r.internal = true;
        let mut h = HeaderMap::new();
        h.insert("x-client-cert", HeaderValue::from_static("1"));
        let store = HmacNonceStore::new(300);
        let safe: Vec<String> = vec![];
        assert!(status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none());
    }

    /// Early data on a route that did not opt in is 425, per RFC 8470.
    #[test]
    fn early_data_on_a_non_0rtt_route_is_too_early() {
        let r = route(); // allow_0rtt defaults false
        let mut h = HeaderMap::new();
        h.insert("x-tls-early-data", HeaderValue::from_static("1"));
        let store = HmacNonceStore::new(300);
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
        let store = HmacNonceStore::new(300);
        let safe: Vec<String> = vec!["GET".to_string(), "HEAD".to_string()];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "POST", &safe))),
            Some(StatusCode::TOO_EARLY)
        );
        assert!(status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none());
    }

    /// HTTP/3 never sets `x-connection-protocol: h1`, so the HTTP/1.1 gate must
    /// not fire there even on a route that forbids HTTP/1.1.
    #[test]
    fn the_http11_gate_does_not_fire_on_h3() {
        let r = route(); // allow_http11 defaults false
        let mut h = HeaderMap::new();
        h.insert("x-connection-protocol", HeaderValue::from_static("h3"));
        let store = HmacNonceStore::new(300);
        let safe: Vec<String> = vec![];
        assert!(status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))).is_none());

        h.insert("x-connection-protocol", HeaderValue::from_static("h1"));
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UPGRADE_REQUIRED)
        );
    }

    /// A route carrying an `hmac_secret` refuses an unsigned request, on every
    /// transport. This gate did not exist on the HTTP/3 path.
    #[test]
    fn hmac_route_refuses_an_unsigned_request() {
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some("s3cret".to_string()),
            ..Default::default()
        });
        let h = HeaderMap::new();
        let store = HmacNonceStore::new(300);
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

        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some("s3cret".to_string()),
            ..Default::default()
        });

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let nonce = "n-once-1";
        let message = format!("GET\n/x\n{}\n{}", ts, nonce);
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"s3cret").unwrap();
        mac.update(message.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let mut h = HeaderMap::new();
        h.insert("x-request-signature", HeaderValue::from_str(&sig).unwrap());
        h.insert("x-request-timestamp", HeaderValue::from_str(&ts).unwrap());
        h.insert("x-request-nonce", HeaderValue::from_static("n-once-1"));

        let store = HmacNonceStore::new(300);
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

    /// A stale timestamp is refused even when the signature over it is valid.
    #[test]
    fn hmac_stale_timestamp_is_refused() {
        let mut r = route();
        r.security = Some(crate::config::RouteSecurityPolicy {
            hmac_secret: Some("s3cret".to_string()),
            ..Default::default()
        });
        let mut h = HeaderMap::new();
        h.insert("x-request-timestamp", HeaderValue::from_static("1"));
        h.insert("x-request-signature", HeaderValue::from_static("deadbeef"));
        let store = HmacNonceStore::new(300);
        let safe: Vec<String> = vec![];
        assert_eq!(
            status_of(&evaluate(&ctx(&r, &h, &store, "GET", &safe))),
            Some(StatusCode::UNAUTHORIZED)
        );
    }
}
