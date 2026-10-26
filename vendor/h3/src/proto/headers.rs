use std::{
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
    Extensions, HeaderMap, Method, StatusCode,
};

use crate::{ext::Protocol, qpack::HeaderField};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        ext: Extensions,
    ) -> Result<Self, HeaderError> {
        match (uri.authority(), fields.get("host")) {
            (None, None) => Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => Err(HeaderError::ContradictedAuthority),
            _ => Ok(Self {
                pseudo: Pseudo::request(method, uri, ext),
                fields,
            }),
        }
    }

    /// Every field line in the order it is sent — pseudo-header fields first
    /// (RFC 9114 §4.3), then the regular fields, each value of a repeated name
    /// on its own line — borrowed from `self`.
    pub fn field_slices(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        let p = &self.pseudo;
        let pseudo: [Option<(&[u8], &[u8])>; 6] = [
            p.method
                .as_ref()
                .map(|m| (&b":method"[..], m.as_str().as_bytes())),
            p.scheme
                .as_ref()
                .map(|s| (&b":scheme"[..], s.as_str().as_bytes())),
            p.authority
                .as_ref()
                .map(|a| (&b":authority"[..], a.as_str().as_bytes())),
            p.path
                .as_ref()
                .map(|x| (&b":path"[..], x.as_str().as_bytes())),
            p.status
                .as_ref()
                .map(|s| (&b":status"[..], s.as_str().as_bytes())),
            p.protocol
                .as_ref()
                .map(|x| (&b":protocol"[..], x.as_str().as_bytes())),
        ];
        pseudo.into_iter().flatten().chain(
            self.fields
                .iter()
                .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes())),
        )
    }

    pub fn response(status: StatusCode, fields: HeaderMap) -> Self {
        Self {
            pseudo: Pseudo::response(status),
            fields,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            fields,
        }
    }

    pub fn into_request_parts(
        self,
    ) -> Result<(Method, Uri, Option<Protocol>, HeaderMap), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# Endpoints MUST treat a request or response that contains undefined or
        //# invalid pseudo-header fields as malformed.
        if self.pseudo.status.is_some() {
            return Err(HeaderError::MisplacedPseudoHeader(":status"));
        }
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority)
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        Ok((
            self.pseudo.method.ok_or(HeaderError::MissingMethod)?,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.fields,
        ))
    }

    pub fn into_response_parts(self) -> Result<(StatusCode, HeaderMap), HeaderError> {
        // The request pseudo-header fields, in a response (section 4.3)
        for (present, name) in [
            (self.pseudo.method.is_some(), ":method"),
            (self.pseudo.scheme.is_some(), ":scheme"),
            (self.pseudo.authority.is_some(), ":authority"),
            (self.pseudo.path.is_some(), ":path"),
            (self.pseudo.protocol.is_some(), ":protocol"),
        ] {
            if present {
                return Err(HeaderError::MisplacedPseudoHeader(name));
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            last_header_name: None,
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
}

impl Iterator for HeaderIter {
    type Item = HeaderField;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(ref mut pseudo) = self.pseudo {
            if let Some(method) = pseudo.method.take() {
                return Some((":method", method.as_str()).into());
            }

            if let Some(scheme) = pseudo.scheme.take() {
                return Some((":scheme", scheme.as_str().as_bytes()).into());
            }

            if let Some(authority) = pseudo.authority.take() {
                return Some((":authority", authority.as_str().as_bytes()).into());
            }

            if let Some(path) = pseudo.path.take() {
                return Some((":path", path.as_str().as_bytes()).into());
            }

            if let Some(status) = pseudo.status.take() {
                return Some((":status", status.as_str()).into());
            }

            if let Some(protocol) = pseudo.protocol.take() {
                return Some((":protocol", protocol.as_str().as_bytes()).into());
            }
        }

        self.pseudo = None;

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(ref n), v) = (&self.last_header_name, header_value) {
                return Some((n.as_str(), v.as_bytes()).into());
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.  Any request or response that contains a
        //# pseudo-header field that appears in a header section after a regular
        //# header field MUST be treated as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        //
        // A pseudo-header given twice, or after a regular field, was taken:
        // the later value replaced the earlier one and the request went on.
        fn once<T>(slot: &mut Option<T>, value: T, name: &'static str) -> Result<(), HeaderError> {
            if slot.replace(value).is_some() {
                return Err(HeaderError::RepeatedPseudoHeader(name));
            }
            Ok(())
        }
        for field in headers.into_iter() {
            let (name, value) = field.into_inner();
            let field = Field::parse(name, value)?;
            if !matches!(field, Field::Header(_)) && !fields.is_empty() {
                return Err(HeaderError::PseudoHeaderAfterField);
            }
            match field {
                Field::Method(m) => once(&mut pseudo.method, m, ":method")?,
                Field::Scheme(s) => once(&mut pseudo.scheme, s, ":scheme")?,
                Field::Authority(a) => once(&mut pseudo.authority, a, ":authority")?,
                Field::Path(p) => once(&mut pseudo.path, p, ":path")?,
                Field::Status(s) => once(&mut pseudo.status, s, ":status")?,
                Field::Protocol(p) => once(&mut pseudo.protocol, p, ":protocol")?,
                Field::Header((n, v)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
                    //# An endpoint MUST NOT generate an HTTP/3 field section containing
                    //# connection-specific fields; any message containing connection-
                    //# specific fields MUST be treated as malformed.
                    //
                    //# The only exception to this is the TE header field, which MAY be
                    //# present in an HTTP/3 request header; when it is, it MUST NOT
                    //# contain any value other than "trailers".
                    let connection_specific = [
                        http::header::CONNECTION,
                        HeaderName::from_static("keep-alive"),
                        HeaderName::from_static("proxy-connection"),
                        http::header::TRANSFER_ENCODING,
                        http::header::UPGRADE,
                    ]
                    .contains(&n)
                        || (n == http::header::TE
                            && !v.as_bytes().eq_ignore_ascii_case(b"trailers"));
                    if connection_specific {
                        return Err(HeaderError::ConnectionSpecificField(n.to_string()));
                    }
                    fields.append(n, v);
                    continue;
                }
            }
            pseudo.len += 1;
        }

        Ok(Header { pseudo, fields })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Protocol(Protocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse<N, V>(name: N, value: V) -> Result<Self, HeaderError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => Field::Path(try_value(name, value)?),
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":protocol" => Field::Protocol(try_value(name, value)?),
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
/// A message's Content-Length: None when it has none, Err when its values do
/// not name one length (RFC 9110 section 8.6 allows a list only of one value
/// repeated).
pub fn content_length(fields: &HeaderMap) -> Result<Option<u64>, HeaderError> {
    let mut length = None;
    for value in fields.get_all(header::CONTENT_LENGTH) {
        let text = value
            .to_str()
            .map_err(|_| HeaderError::InvalidContentLength)?;
        for part in text.split(',') {
            let n: u64 = part
                .trim()
                .parse()
                .map_err(|_| HeaderError::InvalidContentLength)?;
            if length.replace(n).is_some_and(|m| m != n) {
                return Err(HeaderError::InvalidContentLength);
            }
        }
    }
    Ok(length)
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().copied()
        } else {
            None
        };

        let len = 3 + authority.is_some() as usize + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        Self {
            method: Some(method),
            scheme: scheme.or(Some(Scheme::HTTPS)),
            authority,
            path: Some(path),
            status: None,
            protocol,
            len,
        }
    }

    fn response(status: StatusCode) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            len: 1,
            protocol: None,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
    /// A pseudo-header field more than once (RFC 9114 section 4.3.1)
    RepeatedPseudoHeader(&'static str),
    /// A pseudo-header field after a regular field (section 4.3)
    PseudoHeaderAfterField,
    /// A request's pseudo-header field in a response, or a response's in a
    /// request (section 4.3)
    MisplacedPseudoHeader(&'static str),
    /// A connection-specific field, or TE other than "trailers" (section 4.2)
    ConnectionSpecificField(String),
    /// Content-Length that is not one non-negative integer
    InvalidContentLength,
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::RepeatedPseudoHeader(n) => write!(f, "pseudo-header {n} given twice"),
            HeaderError::PseudoHeaderAfterField => {
                write!(f, "pseudo-header field after a regular field")
            }
            HeaderError::MisplacedPseudoHeader(n) => {
                write!(f, "pseudo-header {n} where the message cannot carry it")
            }
            HeaderError::ConnectionSpecificField(n) => {
                write!(f, "connection-specific field {n}")
            }
            HeaderError::InvalidContentLength => write!(f, "content-length is not one length"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;

    fn fields(list: &[(&str, &str)]) -> Vec<HeaderField> {
        list.iter()
            .map(|(n, v)| HeaderField::new(n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    fn request(list: &[(&str, &str)]) -> Result<(), HeaderError> {
        Header::try_from(fields(list))?
            .into_request_parts()
            .map(|_| ())
    }

    const GET: [(&str, &str); 4] = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "example.com"),
        (":path", "/"),
    ];

    /// RFC 9114 sections 4.2 and 4.3: what makes a request malformed.
    #[test]
    fn malformed_requests_are_refused() {
        assert_matches!(request(&GET), Ok(()));
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut list = GET.to_vec();
            list.extend_from_slice(extra);
            request(&list)
        };
        assert_matches!(
            with(&[(":path", "/again")]),
            Err(HeaderError::RepeatedPseudoHeader(":path"))
        );
        assert_matches!(
            request(&[
                (":method", "GET"),
                (":scheme", "https"),
                ("user-agent", "x"),
                (":authority", "example.com"),
                (":path", "/"),
            ]),
            Err(HeaderError::PseudoHeaderAfterField)
        );
        assert_matches!(
            with(&[(":status", "200")]),
            Err(HeaderError::MisplacedPseudoHeader(":status"))
        );
        for name in [
            "connection",
            "keep-alive",
            "proxy-connection",
            "transfer-encoding",
            "upgrade",
        ] {
            assert_matches!(
                with(&[(name, "x")]),
                Err(HeaderError::ConnectionSpecificField(n)) if n == name,
                "{name}"
            );
        }
        assert_matches!(
            with(&[("te", "trailers")]),
            Ok(()),
            "TE: trailers is the exception"
        );
        assert_matches!(
            with(&[("te", "gzip")]),
            Err(HeaderError::ConnectionSpecificField(n)) if n == "te"
        );
    }

    #[test]
    fn a_response_carries_no_request_pseudo_header() {
        let response = |list: &[(&str, &str)]| {
            Header::try_from(fields(list)).and_then(|h| h.into_response_parts().map(|_| ()))
        };
        assert_matches!(response(&[(":status", "200")]), Ok(()));
        assert_matches!(
            response(&[(":status", "200"), (":path", "/")]),
            Err(HeaderError::MisplacedPseudoHeader(":path"))
        );
    }

    #[test]
    fn content_length_is_one_length() {
        let length = |values: &[&str]| {
            let mut map = HeaderMap::new();
            for v in values {
                map.append(header::CONTENT_LENGTH, HeaderValue::from_str(v).unwrap());
            }
            content_length(&map)
        };
        assert_matches!(length(&[]), Ok(None));
        assert_matches!(length(&["10"]), Ok(Some(10)));
        assert_matches!(length(&["10, 10"]), Ok(Some(10)), "one value repeated");
        assert_matches!(length(&["10", "10"]), Ok(Some(10)));
        assert_matches!(length(&["10, 11"]), Err(HeaderError::InvalidContentLength));
        assert_matches!(length(&["-1"]), Err(HeaderError::InvalidContentLength));
        assert_matches!(length(&["ten"]), Err(HeaderError::InvalidContentLength));
    }

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo")
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar")
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value")
            },]
        );
    }
}
