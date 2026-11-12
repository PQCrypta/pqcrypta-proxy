//! The host a request names, which routing and the HTTP-to-HTTPS redirect read.

use std::future::Future;

use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};

/// The host a request names, with its port where it gave one.
///
/// The request target's authority when it has one (HTTP/2 and HTTP/3
/// `:authority`, an absolute-form HTTP/1.1 target), else the `Host` header:
/// RFC 9110 section 7.2, and RFC 9113 section 8.3.1, which has `:authority`
/// take the place of `Host`.
///
/// `Forwarded` and `X-Forwarded-Host` are not read: they describe the hops a
/// request took behind another proxy, and this proxy is the first hop. (axum
/// 0.8 has no `Host` extractor of its own; this takes its place.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestHost(pub(crate) String);

impl<S: Send + Sync> FromRequestParts<S> for RequestHost {
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Read from the parts at once: nothing here waits.
        std::future::ready(
            request_host(parts)
                .map(Self)
                .ok_or((StatusCode::BAD_REQUEST, "No host in the request")),
        )
    }
}

/// The request's host by the one rule every layer uses
/// ([`crate::request_target::effective_host`]). A request that names two
/// hosts has none here; the security layer has already answered it 400.
fn request_host(parts: &Parts) -> Option<String> {
    crate::request_target::effective_host(&parts.uri, &parts.headers)
        .ok()
        .flatten()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn parts(uri: &str, headers: &[(&str, &str)]) -> Parts {
        let mut builder = Request::builder().uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(()).unwrap().into_parts().0
    }

    #[test]
    fn the_authority_names_the_host_and_its_port() {
        let p = parts("https://tcp2.pqcrypta.com:4433/x", &[]);
        assert_eq!(request_host(&p).as_deref(), Some("tcp2.pqcrypta.com:4433"));
        let p = parts("https://[2600:1900:4090:724:0:1::]/dns-query", &[]);
        assert_eq!(
            request_host(&p).as_deref(),
            Some("[2600:1900:4090:724:0:1::]")
        );
    }

    #[test]
    fn an_origin_form_request_is_named_by_its_host_header() {
        let p = parts("/index.html", &[("host", "pqcrypta.com")]);
        assert_eq!(request_host(&p).as_deref(), Some("pqcrypta.com"));
    }

    #[test]
    fn the_authority_and_a_host_header_name_one_host() {
        let p = parts("https://pqcrypta.com/", &[("host", "PQCrypta.com:443")]);
        assert_eq!(request_host(&p).as_deref(), Some("pqcrypta.com"));
        // Two different hosts name none: the request is malformed
        let p = parts("https://pqcrypta.com/", &[("host", "other.example")]);
        assert_eq!(request_host(&p), None);
    }

    #[test]
    fn forwarding_headers_name_no_host() {
        let p = parts(
            "/",
            &[
                ("host", "pqcrypta.com"),
                ("x-forwarded-host", "other.example"),
                ("forwarded", "host=other.example"),
            ],
        );
        assert_eq!(request_host(&p).as_deref(), Some("pqcrypta.com"));
        let p = parts("/", &[("x-forwarded-host", "other.example")]);
        assert_eq!(request_host(&p), None);
    }

    #[test]
    fn userinfo_is_not_part_of_the_host() {
        let p = parts("https://user@pqcrypta.com:8443/", &[]);
        assert_eq!(request_host(&p).as_deref(), Some("pqcrypta.com:8443"));
    }
}
