//! Request IDs: `server.request_id_header`.
//!
//! When the setting names a header, every proxied request carries it to the
//! backend and back to the client. A client's own ID is kept when it is sane
//! (non-empty, at most 128 visible ASCII characters) so a trace can start
//! upstream of the proxy; otherwise the proxy mints 128 random bits as hex.
//! Off by default: an empty setting costs nothing per request.

use http::{HeaderMap, HeaderName, HeaderValue};
use rand::RngCore;

/// Longest client-supplied ID the proxy will pass on.
const MAX_LEN: usize = 128;

/// The configured header name, or `None` when request IDs are off.
pub fn header_name(configured: &str) -> Option<HeaderName> {
    if configured.is_empty() {
        None
    } else {
        HeaderName::from_bytes(configured.as_bytes()).ok()
    }
}

/// The ID for a request: the client's own when sane, else a fresh one.
pub fn resolve(request_headers: &HeaderMap, name: &HeaderName) -> HeaderValue {
    if let Some(v) = request_headers.get(name) {
        let b = v.as_bytes();
        if !b.is_empty() && b.len() <= MAX_LEN && b.iter().all(|c| c.is_ascii_graphic()) {
            return v.clone();
        }
    }
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    // Hex is always a valid header value.
    HeaderValue::from_str(&hex::encode(id)).unwrap_or_else(|_| HeaderValue::from_static("0"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_a_sane_client_id_and_replaces_anything_else() {
        let name = header_name("x-request-id").unwrap();
        let mut h = HeaderMap::new();
        h.insert(&name, HeaderValue::from_static("abc-123"));
        assert_eq!(resolve(&h, &name), "abc-123");

        h.insert(&name, HeaderValue::from_static("has space"));
        let minted = resolve(&h, &name);
        assert_eq!(minted.len(), 32);
        assert!(minted.as_bytes().iter().all(u8::is_ascii_hexdigit));

        h.insert(&name, HeaderValue::from_str(&"a".repeat(129)).unwrap());
        assert_eq!(resolve(&h, &name).len(), 32);

        assert_ne!(
            resolve(&HeaderMap::new(), &name),
            resolve(&HeaderMap::new(), &name)
        );
    }

    #[test]
    fn empty_setting_is_off_and_bad_names_are_refused() {
        assert!(header_name("").is_none());
        assert!(header_name("bad name").is_none());
    }
}
