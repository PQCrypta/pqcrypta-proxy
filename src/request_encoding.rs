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
//! - Decoded output is counted against the process's body budget
//!   ([`crate::body_budget`]) piece by piece, before it is kept; a body the
//!   budget has no room for is refused 503.

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
    /// The body budget has no room for what it decodes to (503)
    NoMemory,
}

impl Refusal {
    pub fn status(&self) -> http::StatusCode {
        match self {
            Self::Unsupported(_) => http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::Malformed => http::StatusCode::BAD_REQUEST,
            Self::TooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
            Self::NoMemory => http::StatusCode::SERVICE_UNAVAILABLE,
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
            Self::NoMemory => "The server has no room to decode the request body now".into(),
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
///
/// Each piece of output is counted in `budget` before it is kept, so the
/// decoded body is within the process's budget while it is built, not only
/// once it is whole; a layer's output is given back once the next layer has
/// been decoded from it, and a refused decode gives back all it took. The
/// returned body stays counted: the caller gives back `body` when it replaces
/// it.
pub fn decode(
    content_encoding: Option<&str>,
    body: &[u8],
    limit: usize,
    budget: &mut crate::body_budget::Reservation,
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
    let mut layers = applied.iter().rev();
    let Some(first) = layers.next() else {
        return Ok(None);
    };
    let mut current = decode_one(first, body, limit, budget)?;
    for coding in layers {
        let next = decode_one(coding, &current, limit, budget);
        budget.shrink(current.len());
        current = next?;
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

/// The size of each piece of output read and counted at a time.
const PIECE: usize = 16 * 1024;

/// `input` decoded from `coding`, at most `limit` bytes, each piece counted
/// in `budget` before it is kept. On a refusal, what was counted is given back.
fn decode_one(
    coding: &str,
    input: &[u8],
    limit: usize,
    budget: &mut crate::body_budget::Reservation,
) -> Result<Vec<u8>, Refusal> {
    let mut reader =
        decoder(coding, input).ok_or_else(|| Refusal::Unsupported(coding.to_string()))?;
    let mut out = Vec::new();
    let mut piece = [0u8; PIECE];
    let outcome = loop {
        let n = match reader.read(&mut piece) {
            Ok(0) => break Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break Err(Refusal::Malformed),
        };
        if out.len() + n > limit {
            break Err(Refusal::TooLarge);
        }
        if !budget.grow(n) {
            break Err(Refusal::NoMemory);
        }
        out.extend_from_slice(&piece[..n]);
    };
    match outcome {
        Ok(()) => Ok(out),
        Err(refusal) => {
            budget.shrink(out.len());
            Err(refusal)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use crate::body_budget::Reservation;

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
        assert_eq!(decode(None, b"x", 10, &mut Reservation::new()), Ok(None));
        assert_eq!(
            decode(Some("identity"), b"x", 10, &mut Reservation::new()),
            Ok(None)
        );
        assert_eq!(
            decode(Some(" "), b"x", 10, &mut Reservation::new()),
            Ok(None)
        );
    }

    #[test]
    fn every_coding_is_decoded_last_applied_first() {
        let body = b"name=value&q=1";
        assert_eq!(
            decode(Some("gzip"), &gzip(body), 1024, &mut Reservation::new()),
            Ok(Some(body.to_vec()))
        );
        assert_eq!(
            decode(Some("br"), &brotli(body), 1024, &mut Reservation::new()),
            Ok(Some(body.to_vec()))
        );
        let zstd = zstd::encode_all(&body[..], 3).unwrap();
        assert_eq!(
            decode(Some("ZSTD"), &zstd, 1024, &mut Reservation::new()),
            Ok(Some(body.to_vec()))
        );
        // gzip applied first, then br
        let stacked = brotli(&gzip(body));
        assert_eq!(
            decode(Some("gzip, br"), &stacked, 1024, &mut Reservation::new()),
            Ok(Some(body.to_vec()))
        );
    }

    /// Bytes after a gzip member are not a tail the backend reads unseen:
    /// they are not gzip, and the body is refused.
    #[test]
    fn bytes_after_the_stream_are_not_passed_on() {
        let mut body = gzip(b"benign=1");
        body.extend_from_slice(b"&q=' UNION SELECT password FROM users--");
        assert_eq!(
            decode(Some("gzip"), &body, 1024, &mut Reservation::new()),
            Err(Refusal::Malformed)
        );
        // Two members are one body, as gzip -d reads it
        let mut two = gzip(b"a=1&");
        two.extend_from_slice(&gzip(b"b=2"));
        assert_eq!(
            decode(Some("gzip"), &two, 1024, &mut Reservation::new()),
            Ok(Some(b"a=1&b=2".to_vec()))
        );
    }

    #[test]
    fn what_cannot_be_read_is_refused() {
        assert_eq!(
            decode(Some("aes128gcm"), b"x", 1024, &mut Reservation::new()),
            Err(Refusal::Unsupported("aes128gcm".into()))
        );
        assert_eq!(
            decode(Some("gzip"), b"not gzip", 1024, &mut Reservation::new()),
            Err(Refusal::Malformed)
        );
        let big = gzip(&vec![b'a'; 4096]);
        assert_eq!(
            decode(Some("gzip"), &big, 4095, &mut Reservation::new()),
            Err(Refusal::TooLarge)
        );
        assert_eq!(
            decode(
                Some("gzip, gzip, gzip, gzip, gzip"),
                b"x",
                10,
                &mut Reservation::new()
            ),
            Err(Refusal::Unsupported("gzip, gzip, gzip, gzip, gzip".into()))
        );
        assert_eq!(
            Refusal::TooLarge.status(),
            http::StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    /// What a body decodes to is counted as it is decoded, and stays counted
    /// for the caller; the input it came from is the caller's to give back.
    #[test]
    fn decoded_output_is_counted_in_the_budget() {
        let body = vec![b'a'; 100 * 1024];
        let mut budget = Reservation::new();
        let decoded = decode(Some("gzip"), &gzip(&body), body.len(), &mut budget)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, body);
        assert_eq!(budget.bytes(), body.len());
        // Two layers: the intermediate one is given back once decoded from
        let stacked = brotli(&gzip(&body));
        let mut budget = Reservation::new();
        let decoded = decode(Some("gzip, br"), &stacked, body.len(), &mut budget)
            .unwrap()
            .unwrap();
        assert_eq!(budget.bytes(), decoded.len());
    }

    /// A refused decode holds nothing afterwards, however far it got.
    #[test]
    fn a_refused_decode_gives_back_what_it_counted() {
        let body = vec![b'a'; 200 * 1024];
        let mut budget = Reservation::new();
        assert_eq!(
            decode(Some("gzip"), &gzip(&body), 100 * 1024, &mut budget),
            Err(Refusal::TooLarge)
        );
        assert_eq!(budget.bytes(), 0);
        let mut truncated = gzip(&body);
        truncated.truncate(truncated.len() / 2);
        assert_eq!(
            decode(Some("gzip"), &truncated, body.len(), &mut budget),
            Err(Refusal::Malformed)
        );
        assert_eq!(budget.bytes(), 0);
    }
}
