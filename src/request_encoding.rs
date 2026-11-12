//! A request body's content coding (RFC 9110 section 8.4), decoded here.
//!
//! The WAF reads a compressed body by decoding it. A backend that does not
//! decode request bodies itself reads the bytes as they came, and bytes after
//! the end of a gzip member, say, were never part of what was inspected. So
//! a body with a content coding is decoded at the proxy and forwarded decoded,
//! without its `Content-Encoding`: what is inspected is what is delivered.
//!
//! - `gzip`, `x-gzip`, `deflate` (zlib), `br` and `zstd`, and several of them
//!   applied in turn (`Content-Encoding: gzip, br`), are decoded.
//! - Anything else cannot be inspected and is refused 415, with the codings
//!   this server reads in `Accept-Encoding` (RFC 9110 section 12.5.3).
//! - A stream that does not decode is refused 400.
//! - A body that decodes past `limit` is refused 413.

use std::io::Read;

/// The codings decoded here, as an `Accept-Encoding` answer lists them.
pub const ACCEPTED: &str = "gzip, deflate, br, zstd";

/// The codings decoded here, as `Content-Encoding` names them.
const DECODED: [&str; 6] = ["gzip", "x-gzip", "deflate", "x-deflate", "br", "zstd"];

/// The most codings one body may carry.
const MAX_LAYERS: usize = 4;

/// Why a body with a content coding is not forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// A coding this server does not decode (415)
    Unsupported(String),
    /// The body is not a stream of its coding (400)
    Malformed,
    /// It decodes past the limit (413)
    TooLarge,
}

impl Refusal {
    pub fn status(&self) -> http::StatusCode {
        match self {
            Self::Unsupported(_) => http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Malformed => http::StatusCode::BAD_REQUEST,
            Self::TooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::Unsupported(coding) => {
                format!("Content-Encoding {coding} is not one this server reads ({ACCEPTED})")
            }
            Self::Malformed => {
                "The request body does not decode as its Content-Encoding says".into()
            }
            Self::TooLarge => "The request body decodes past the size this server accepts".into(),
        }
    }
}

/// The codings a `Content-Encoding` value lists, in the order they were
/// applied; none for an absent, empty or `identity` value.
fn codings(content_encoding: &str) -> Vec<String> {
    content_encoding
        .split(',')
        .map(|c| c.trim().to_ascii_lowercase())
        .filter(|c| !c.is_empty() && c != "identity")
        .collect()
}

/// `body` decoded from every coding `content_encoding` lists, last applied
/// first; `Ok(None)` when it lists none. At most `limit` bytes.
pub fn decode(
    content_encoding: Option<&str>,
    body: &[u8],
    limit: usize,
) -> Result<Option<Vec<u8>>, Refusal> {
    let applied = content_encoding.map(codings).unwrap_or_default();
    if applied.is_empty() {
        return Ok(None);
    }
    if applied.len() > MAX_LAYERS {
        return Err(Refusal::Unsupported(applied.join(", ")));
    }
    if let Some(unknown) = applied.iter().find(|c| !DECODED.contains(&c.as_str())) {
        return Err(Refusal::Unsupported(unknown.clone()));
    }
    let mut current = body.to_vec();
    for coding in applied.iter().rev() {
        current = decode_one(coding, &current, limit)?;
    }
    Ok(Some(current))
}

/// The reader that decodes `coding` from `input`, if this server has one.
fn decoder<'a>(coding: &str, input: &'a [u8]) -> Option<Box<dyn Read + 'a>> {
    Some(match coding {
        // Every member of the stream, as `gzip -d` reads it; bytes that are
        // not a member are an error, not a tail left unread.
        "gzip" | "x-gzip" => Box::new(flate2::bufread::MultiGzDecoder::new(input)),
        "deflate" | "x-deflate" => Box::new(flate2::bufread::ZlibDecoder::new(input)),
        "br" => Box::new(brotli::Decompressor::new(input, 4096)),
        "zstd" => Box::new(zstd::stream::read::Decoder::with_buffer(input).ok()?),
        _ => return None,
    })
}

fn decode_one(coding: &str, input: &[u8], limit: usize) -> Result<Vec<u8>, Refusal> {
    let reader = decoder(coding, input).ok_or_else(|| Refusal::Unsupported(coding.to_string()))?;
    let mut out = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| Refusal::Malformed)?;
    if out.len() > limit {
        return Err(Refusal::TooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    #[test]
    fn a_body_without_a_coding_is_left_as_it_is() {
        assert_eq!(decode(None, b"x", 10), Ok(None));
        assert_eq!(decode(Some("identity"), b"x", 10), Ok(None));
        assert_eq!(decode(Some(" "), b"x", 10), Ok(None));
    }

    #[test]
    fn every_coding_is_decoded_last_applied_first() {
        let body = b"name=value&q=1";
        assert_eq!(
            decode(Some("gzip"), &gzip(body), 1024),
            Ok(Some(body.to_vec()))
        );
        assert_eq!(
            decode(Some("br"), &brotli(body), 1024),
            Ok(Some(body.to_vec()))
        );
        let zstd = zstd::encode_all(&body[..], 3).unwrap();
        assert_eq!(decode(Some("ZSTD"), &zstd, 1024), Ok(Some(body.to_vec())));
        // gzip applied first, then br
        let stacked = brotli(&gzip(body));
        assert_eq!(
            decode(Some("gzip, br"), &stacked, 1024),
            Ok(Some(body.to_vec()))
        );
    }

    /// Bytes after a gzip member are not a tail the backend reads unseen:
    /// they are not gzip, and the body is refused.
    #[test]
    fn bytes_after_the_stream_are_not_passed_on() {
        let mut body = gzip(b"benign=1");
        body.extend_from_slice(b"&q=' UNION SELECT password FROM users--");
        assert_eq!(decode(Some("gzip"), &body, 1024), Err(Refusal::Malformed));
        // Two members are one body, as gzip -d reads it
        let mut two = gzip(b"a=1&");
        two.extend_from_slice(&gzip(b"b=2"));
        assert_eq!(
            decode(Some("gzip"), &two, 1024),
            Ok(Some(b"a=1&b=2".to_vec()))
        );
    }

    #[test]
    fn what_cannot_be_read_is_refused() {
        assert_eq!(
            decode(Some("aes128gcm"), b"x", 1024),
            Err(Refusal::Unsupported("aes128gcm".into()))
        );
        assert_eq!(
            decode(Some("gzip"), b"not gzip", 1024),
            Err(Refusal::Malformed)
        );
        let big = gzip(&vec![b'a'; 4096]);
        assert_eq!(decode(Some("gzip"), &big, 4095), Err(Refusal::TooLarge));
        assert_eq!(
            decode(Some("gzip, gzip, gzip, gzip, gzip"), b"x", 10),
            Err(Refusal::Unsupported("gzip, gzip, gzip, gzip, gzip".into()))
        );
        assert_eq!(
            Refusal::TooLarge.status(),
            http::StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
