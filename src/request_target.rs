//! The host a request names, resolved one way for every layer and transport.
//!
//! Routing, the per-route security policy, the response cache's key, the
//! Alt-Svc and header layers and the access log all need the request's host.
//! Each reads it here, so they cannot disagree about which site a request is
//! for.

use http::{header, HeaderMap, Uri};

/// The request target and the `Host` field name different hosts, or the
/// request carries `Host` fields that differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostMismatch;

/// The host a request names, with its port where it gave one.
///
/// The request target's authority when it has one (HTTP/2 and HTTP/3
/// `:authority`, an absolute-form HTTP/1.1 target), else the `Host` field:
/// RFC 9110 section 7.2. `Forwarded` and `X-Forwarded-Host` are not read: they
/// describe hops behind another proxy, and this proxy is the first hop.
///
/// A request that gives both must name one host in both (RFC 9113 section
/// 8.3.1, RFC 9114 section 4.3.1), and one `Host` field (RFC 9112 section
/// 3.2); anything else is [`HostMismatch`], which every listener answers 400.
pub fn effective_host<'a>(
    uri: &'a Uri,
    headers: &'a HeaderMap,
) -> Result<Option<&'a str>, HostMismatch> {
    let authority = uri
        .authority()
        .map(|a| {
            // A userinfo part (`user@`) is not part of the host; RFC 9113
            // forbids it in `:authority` and RFC 9110 deprecates it.
            a.as_str()
                .rsplit_once('@')
                .map_or(a.as_str(), |(_, host)| host)
        })
        .filter(|h| !h.is_empty());

    let mut field: Option<&'a str> = None;
    for value in headers.get_all(header::HOST) {
        // A value that is not visible ASCII names no host this proxy serves.
        let value = value.to_str().map_err(|_| HostMismatch)?;
        if value.is_empty() {
            continue;
        }
        match field {
            None => field = Some(value),
            Some(first) if same_host(first, value) => {}
            Some(_) => return Err(HostMismatch),
        }
    }

    match (authority, field) {
        (Some(a), Some(f)) if !same_host(a, f) => Err(HostMismatch),
        (Some(a), _) => Ok(Some(a)),
        (None, f) => Ok(f),
    }
}

/// [`effective_host`] without its port, lowercase: the form route hosts are
/// written in.
pub fn effective_host_name(uri: &Uri, headers: &HeaderMap) -> Result<Option<String>, HostMismatch> {
    Ok(effective_host(uri, headers)?
        .map(|h| crate::config::host_without_port(h).to_ascii_lowercase()))
}

/// Whether two `host[:port]` values name the same host: the names compare
/// without regard to ASCII case, and the ports only where both give one.
fn same_host(a: &str, b: &str) -> bool {
    let (host_a, host_b) = (
        crate::config::host_without_port(a),
        crate::config::host_without_port(b),
    );
    if !host_a.eq_ignore_ascii_case(host_b) {
        return false;
    }
    let port = |full: &'_ str, host: &str| -> Option<String> {
        full.get(host.len()..)
            .and_then(|rest| rest.strip_prefix(':'))
            .map(str::to_string)
    };
    match (port(a, host_a), port(b, host_b)) {
        (Some(pa), Some(pb)) => pa == pb,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn parts(uri: &str, hosts: &[&str]) -> (Uri, HeaderMap) {
        let mut builder = Request::builder().uri(uri);
        for h in hosts {
            builder = builder.header(header::HOST, *h);
        }
        let (parts, ()) = builder.body(()).unwrap().into_parts();
        (parts.uri, parts.headers)
    }

    fn host(uri: &str, hosts: &[&str]) -> Result<Option<String>, HostMismatch> {
        let (uri, headers) = parts(uri, hosts);
        effective_host(&uri, &headers).map(|h| h.map(str::to_string))
    }

    #[test]
    fn the_authority_names_the_host_and_its_port() {
        assert_eq!(
            host("https://tcp2.pqcrypta.com:4433/x", &[])
                .unwrap()
                .as_deref(),
            Some("tcp2.pqcrypta.com:4433")
        );
        assert_eq!(
            host("https://[2600:1900:4090:724:0:1::]/dns-query", &[])
                .unwrap()
                .as_deref(),
            Some("[2600:1900:4090:724:0:1::]")
        );
    }

    #[test]
    fn an_origin_form_target_takes_the_host_field() {
        assert_eq!(
            host("/x", &["Example.com:8443"]).unwrap().as_deref(),
            Some("Example.com:8443")
        );
        assert_eq!(host("/x", &[]).unwrap(), None);
        assert_eq!(host("/x", &[""]).unwrap(), None);
    }

    #[test]
    fn userinfo_is_not_part_of_the_host() {
        assert_eq!(
            host("https://user:pw@example.com/x", &[])
                .unwrap()
                .as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn the_target_and_the_host_field_must_name_one_host() {
        assert_eq!(
            host("https://example.com/x", &["EXAMPLE.com"])
                .unwrap()
                .as_deref(),
            Some("example.com")
        );
        // A port given in one and not the other is the same host
        assert_eq!(
            host("https://example.com/x", &["example.com:443"])
                .unwrap()
                .as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host("https://example.com/x", &["other.example"]),
            Err(HostMismatch)
        );
        assert_eq!(
            host("https://example.com:443/x", &["example.com:8443"]),
            Err(HostMismatch)
        );
    }

    #[test]
    fn one_host_field() {
        assert_eq!(
            host("/x", &["example.com", "example.com"])
                .unwrap()
                .as_deref(),
            Some("example.com")
        );
        assert_eq!(
            host("/x", &["example.com", "other.example"]),
            Err(HostMismatch)
        );
    }

    #[test]
    fn the_name_form_is_lowercase_without_the_port() {
        let (uri, headers) = parts("/x", &["Example.COM:8443"]);
        assert_eq!(
            effective_host_name(&uri, &headers).unwrap().as_deref(),
            Some("example.com")
        );
        let (uri, headers) = parts("https://[2001:DB8::1]:4433/x", &[]);
        assert_eq!(
            effective_host_name(&uri, &headers).unwrap().as_deref(),
            Some("[2001:db8::1]")
        );
    }
}
