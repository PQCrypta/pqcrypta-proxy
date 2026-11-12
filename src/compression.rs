//! Response compression middleware
//!
//! Provides:
//! - Brotli compression (best ratio, 95%+ browser support)
//! - Zstandard compression (fastest, gaining adoption)
//! - Gzip compression (fallback for older clients)
//! - Deflate compression (legacy support)
//! - Content negotiation via Accept-Encoding
//! - Streaming compression for large responses
//! - Smart skipping of pre-compressed content

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use futures_util::TryStreamExt;
use tracing::{debug, trace};

/// Compression configuration, read from `[compression]`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CompressionConfig {
    /// Enable compression
    pub enabled: bool,
    /// Minimum size to compress (bytes)
    pub min_size: usize,
    /// Brotli quality level (0-11, default 4)
    pub brotli_quality: u32,
    /// Zstd compression level (1-22, default 3)
    pub zstd_level: i32,
    /// Gzip compression level (1-9, default 6)
    pub gzip_level: u32,
    /// Content types to compress
    pub compress_types: Vec<String>,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_size: 1024, // Don't compress small responses
            brotli_quality: 4,
            zstd_level: 3,
            gzip_level: 6,
            compress_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "text/javascript".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "application/xml".to_string(),
                "application/xhtml+xml".to_string(),
                "application/rss+xml".to_string(),
                "application/atom+xml".to_string(),
                "image/svg+xml".to_string(),
                "font/ttf".to_string(),
                "font/otf".to_string(),
                "application/wasm".to_string(),
            ],
        }
    }
}

/// Compression encoding types in preference order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    /// Brotli - best compression ratio
    Brotli,
    /// Zstandard - fastest with good ratio
    Zstd,
    /// Gzip - wide compatibility
    Gzip,
    /// Deflate - legacy support
    Deflate,
    /// No compression
    Identity,
}

impl CompressionEncoding {
    /// Get the Content-Encoding header value
    pub fn as_str(&self) -> &'static str {
        match self {
            CompressionEncoding::Brotli => "br",
            CompressionEncoding::Zstd => "zstd",
            CompressionEncoding::Gzip => "gzip",
            CompressionEncoding::Deflate => "deflate",
            CompressionEncoding::Identity => "identity",
        }
    }
}

/// The codings the proxy produces, in the order it prefers them when a
/// client weighs several the same.
const PRODUCED: [(CompressionEncoding, &[&str]); 4] = [
    (CompressionEncoding::Brotli, &["br"]),
    (CompressionEncoding::Zstd, &["zstd"]),
    (CompressionEncoding::Gzip, &["gzip", "x-gzip"]),
    (CompressionEncoding::Deflate, &["deflate"]),
];

/// A qvalue (RFC 9110 section 12.4.2) in thousandths: `0` to `1`, with at
/// most three decimals. `None` for anything else.
fn qvalue(text: &str) -> Option<u16> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths = fraction
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// The coding to send, from a request's `Accept-Encoding` (RFC 9110 section
/// 12.5.3).
///
/// The one the client weighs highest of those the proxy produces, the
/// proxy's preference among equals; a coding weighed `q=0`, or not named
/// where `*` is not either, is not acceptable. Identity where none is.
///
/// Browsers name every coding with the same weight (Chrome sends `gzip,
/// deflate, br, zstd`), so the order they are listed in says nothing; it
/// once picked gzip for them.
pub fn parse_accept_encoding(accept_encoding: Option<&HeaderValue>) -> CompressionEncoding {
    let Some(value) = accept_encoding.and_then(|v| v.to_str().ok()) else {
        return CompressionEncoding::Identity;
    };
    let mut named: [Option<u16>; PRODUCED.len()] = [None; PRODUCED.len()];
    let mut any: Option<u16> = None;
    for member in value.split(',') {
        let mut fields = member.split(';');
        let coding = fields.next().unwrap_or_default().trim();
        if coding.is_empty() {
            continue;
        }
        // The weight, `q=` among the parameters with optional whitespace
        // around the `;`; one that is not a qvalue makes the member refused
        let mut weight = 1000;
        for parameter in fields {
            if let Some((name, value)) = parameter.split_once('=') {
                if name.trim().eq_ignore_ascii_case("q") {
                    weight = qvalue(value.trim()).unwrap_or(0);
                }
            }
        }
        if coding == "*" {
            any = Some(weight);
        } else if let Some(slot) = PRODUCED
            .iter()
            .position(|(_, names)| names.iter().any(|n| n.eq_ignore_ascii_case(coding)))
        {
            named[slot] = Some(weight);
        }
    }
    let mut best: Option<(u16, CompressionEncoding)> = None;
    for (slot, (encoding, _)) in PRODUCED.iter().enumerate() {
        let weight = named[slot].or(any).unwrap_or(0);
        // Strictly greater: an equal weight keeps the proxy's earlier choice
        if weight > 0 && best.is_none_or(|(held, _)| weight > held) {
            best = Some((weight, *encoding));
        }
    }
    best.map_or(CompressionEncoding::Identity, |(_, encoding)| encoding)
}

/// Whether compressing the response to this request would let a page on
/// another site learn a secret from it (BREACH).
///
/// The request carries the visitor's credentials (a cookie, an `Authorization`), and the browser
/// says another site made it (`Sec-Fetch-Site: cross-site`). Such a page
/// chooses part of what the response reflects and sees only how long it
/// is; compressed, that length tells it how much of its guess matched a
/// secret beside it. Same-origin and same-site requests, and navigations
/// the visitor made (`none`), are compressed as before.
pub fn exposes_secrets_to_compression(request: &HeaderMap) -> bool {
    let credentialed =
        request.contains_key(header::COOKIE) || request.contains_key(header::AUTHORIZATION);
    credentialed
        && request
            .get("sec-fetch-site")
            .is_some_and(|site| site.as_bytes().eq_ignore_ascii_case(b"cross-site"))
}

/// Whether the origin forbids a proxy changing the content's coding
/// (`Cache-Control: no-transform`, RFC 9111 section 5.2.2.6).
pub fn forbids_transformation(response: &HeaderMap) -> bool {
    response
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
}

/// Check if content type should be compressed
pub fn should_compress_content_type(
    content_type: Option<&HeaderValue>,
    config: &CompressionConfig,
) -> bool {
    let Some(value) = content_type else {
        return false;
    };

    let Ok(value_str) = value.to_str() else {
        return false;
    };

    // Extract MIME type (ignore charset and other parameters)
    let mime_type = value_str
        .split(';')
        .next()
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();

    // Check against allowed types
    config.compress_types.iter().any(|t| t == &mime_type)
}

/// Check if response is already compressed
pub fn is_already_compressed(headers: &HeaderMap) -> bool {
    if let Some(encoding) = headers.get(header::CONTENT_ENCODING) {
        if let Ok(enc_str) = encoding.to_str() {
            let enc_lower = enc_str.to_lowercase();
            return enc_lower != "identity" && !enc_lower.is_empty();
        }
    }
    false
}

/// Compression middleware state
#[derive(Clone)]
pub struct CompressionState {
    pub config: CompressionConfig,
}

impl Default for CompressionState {
    fn default() -> Self {
        Self {
            config: CompressionConfig::default(),
        }
    }
}

/// Compression middleware for axum
///
/// This middleware:
/// 1. Parses Accept-Encoding from the request
/// 2. Passes request to next handler
/// 3. Compresses response body if appropriate
/// 4. Sets Content-Encoding header
pub async fn compression_middleware(
    State(state): State<CompressionState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    let config = &state.config;

    if !config.enabled {
        return next.run(request).await;
    }

    // Parse Accept-Encoding from request
    let encoding = parse_accept_encoding(request.headers().get(header::ACCEPT_ENCODING));

    // Don't compress if client doesn't support it, or where the length of a
    // compressed response would tell another site about its secrets
    if encoding == CompressionEncoding::Identity
        || exposes_secrets_to_compression(request.headers())
    {
        return next.run(request).await;
    }

    trace!("Client accepts compression: {:?}", encoding);

    // HEAD carries no body to encode; its headers must describe the GET's.
    let is_head = request.method() == axum::http::Method::HEAD;

    // Run the next handler
    let response = next.run(request).await;

    // Check if we should compress the response
    let should_compress = {
        let headers = response.headers();

        // Don't compress already compressed responses
        if is_already_compressed(headers) {
            trace!("Response already compressed, skipping");
            false
        }
        // Nor what the origin said no proxy may transform
        else if forbids_transformation(headers) {
            trace!("Cache-Control: no-transform, not compressed");
            false
        }
        // A byte range is a range of the representation the origin sent:
        // encoded here, its Content-Range would describe bytes that are no
        // longer the ones in the body.
        else if response.status() == StatusCode::PARTIAL_CONTENT
            || headers.contains_key(header::CONTENT_RANGE)
        {
            trace!("Partial content, not compressed");
            false
        }
        // Don't compress non-compressible content types
        else if !should_compress_content_type(headers.get(header::CONTENT_TYPE), config) {
            trace!("Content type not compressible");
            false
        }
        // Don't compress if Content-Length is below minimum
        else if let Some(len) = headers.get(header::CONTENT_LENGTH) {
            if let Ok(len_str) = len.to_str() {
                if let Ok(len_num) = len_str.parse::<usize>() {
                    if len_num < config.min_size {
                        trace!("Response too small to compress: {} bytes", len_num);
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            // No Content-Length, compress anyway (streaming)
            true
        }
    };

    if !should_compress {
        return response;
    }

    // Responses with no body to encode.
    let status = response.status();
    if is_head || status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
        return response;
    }

    // Streaming compression. The body is encoded as it arrives, in the
    // encoder's own small chunks, so memory stays constant whatever the size,
    // the first bytes leave before the backend has finished, and no single
    // poll runs long enough to stall the other connections on this worker.
    // This replaced collecting the whole body with a 100 MB cap, where a body
    // over the cap or a backend stream error became a 200 with an empty body.
    let (mut parts, body) = response.into_parts();
    let reader =
        tokio_util::io::StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    let encoded = encode_stream(reader, encoding, config);

    debug!("Streaming compression: {}", encoding.as_str());

    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(encoding.as_str()),
    );
    // The encoded length is not known until the stream ends.
    parts.headers.remove(header::CONTENT_LENGTH);
    // Byte ranges index the identity representation; a compressed body cannot
    // honour them.
    parts.headers.remove(header::ACCEPT_RANGES);
    // RFC 9110 §8.8.3: a strong validator names exact bytes, and these are no
    // longer the backend's. Weaken it, as nginx does, so revalidation still
    // works without claiming byte identity.
    if let Some(etag) = parts.headers.get(header::ETAG).cloned() {
        if let Ok(tag) = etag.to_str() {
            if !tag.starts_with("W/") {
                if let Ok(weak) = HeaderValue::from_str(&format!("W/{tag}")) {
                    parts.headers.insert(header::ETAG, weak);
                }
            }
        }
    }

    // Add Vary header to indicate response varies by Accept-Encoding
    if let Some(vary) = parts.headers.get(header::VARY) {
        if let Ok(vary_str) = vary.to_str() {
            if !vary_str.to_lowercase().contains("accept-encoding") {
                let new_vary = format!("{}, Accept-Encoding", vary_str);
                if let Ok(v) = HeaderValue::from_str(&new_vary) {
                    parts.headers.insert(header::VARY, v);
                }
            }
        }
    } else {
        parts
            .headers
            .insert(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }

    Response::from_parts(parts, encoded)
}

/// Wrap `reader` in the streaming encoder for `encoding`, at the configured
/// level, and hand it back as a response body.
fn encode_stream<R>(reader: R, encoding: CompressionEncoding, config: &CompressionConfig) -> Body
where
    R: tokio::io::AsyncBufRead + Send + 'static,
{
    use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder, ZlibEncoder, ZstdEncoder};
    use async_compression::Level;
    use tokio_util::io::ReaderStream;
    #[expect(clippy::cast_possible_wrap)]
    match encoding {
        CompressionEncoding::Brotli => Body::from_stream(ReaderStream::new(
            BrotliEncoder::with_quality(reader, Level::Precise(config.brotli_quality as i32)),
        )),
        CompressionEncoding::Zstd => Body::from_stream(ReaderStream::new(
            ZstdEncoder::with_quality(reader, Level::Precise(config.zstd_level)),
        )),
        CompressionEncoding::Gzip => Body::from_stream(ReaderStream::new(
            GzipEncoder::with_quality(reader, Level::Precise(config.gzip_level as i32)),
        )),
        // HTTP's "deflate" coding is the zlib format (RFC 9110 §8.4.1.2), not
        // raw DEFLATE; a raw stream is undecodable by a conforming client.
        CompressionEncoding::Deflate => Body::from_stream(ReaderStream::new(
            ZlibEncoder::with_quality(reader, Level::Precise(config.gzip_level as i32)),
        )),
        // Never reaches here: identity requests return before encoding.
        CompressionEncoding::Identity => Body::from_stream(ReaderStream::new(reader)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_accept_encoding() {
        // Test with quality values
        let header = HeaderValue::from_static("gzip;q=0.8, br;q=1.0, deflate;q=0.6");
        assert_eq!(
            parse_accept_encoding(Some(&header)),
            CompressionEncoding::Brotli
        );

        // Test simple list
        let header = HeaderValue::from_static("gzip, deflate");
        assert_eq!(
            parse_accept_encoding(Some(&header)),
            CompressionEncoding::Gzip
        );

        // Equal weights: the proxy's preference, not the listing order
        let header = HeaderValue::from_static("zstd, gzip, br");
        assert_eq!(
            parse_accept_encoding(Some(&header)),
            CompressionEncoding::Brotli
        );
        let chrome = HeaderValue::from_static("gzip, deflate, br, zstd");
        assert_eq!(
            parse_accept_encoding(Some(&chrome)),
            CompressionEncoding::Brotli
        );

        // Test no compression
        assert_eq!(parse_accept_encoding(None), CompressionEncoding::Identity);
    }

    #[test]
    fn a_refused_coding_is_not_sent_however_the_weight_is_spelled() {
        let pick = |v: &'static str| parse_accept_encoding(Some(&HeaderValue::from_static(v)));
        assert_eq!(pick("br; q=0, gzip"), CompressionEncoding::Gzip);
        assert_eq!(pick("br ;Q=0 , zstd;q=0.5"), CompressionEncoding::Zstd);
        assert_eq!(pick("br;q=0.000, gzip;q=0.001"), CompressionEncoding::Gzip);
        // `*` stands for every coding not named
        assert_eq!(pick("*;q=0.5, br;q=0"), CompressionEncoding::Zstd);
        assert_eq!(pick("*"), CompressionEncoding::Brotli);
        assert_eq!(pick("gzip;q=0, *;q=0"), CompressionEncoding::Identity);
        // A weight that is not a qvalue refuses the coding
        assert_eq!(pick("br;q=2, gzip;q=0.9"), CompressionEncoding::Gzip);
        assert_eq!(pick("br;q=0.5000, gzip;q=0.1"), CompressionEncoding::Gzip);
        assert_eq!(pick("x-gzip"), CompressionEncoding::Gzip);
        assert_eq!(pick("identity, compress"), CompressionEncoding::Identity);
        assert_eq!(qvalue("1.000"), Some(1000));
        assert_eq!(qvalue("0.25"), Some(250));
        assert_eq!(qvalue("1.5"), None);
    }

    #[test]
    fn a_cross_site_request_with_credentials_is_not_compressed() {
        let headers = |pairs: &[(&'static str, &'static str)]| {
            let mut h = HeaderMap::new();
            for (name, value) in pairs {
                h.insert(*name, HeaderValue::from_static(value));
            }
            h
        };
        assert!(exposes_secrets_to_compression(&headers(&[
            ("cookie", "session=1"),
            ("sec-fetch-site", "cross-site"),
        ])));
        assert!(exposes_secrets_to_compression(&headers(&[
            ("authorization", "Bearer x"),
            ("sec-fetch-site", "Cross-Site"),
        ])));
        assert!(!exposes_secrets_to_compression(&headers(&[
            ("cookie", "session=1"),
            ("sec-fetch-site", "same-origin"),
        ])));
        assert!(!exposes_secrets_to_compression(&headers(&[(
            "sec-fetch-site",
            "cross-site"
        )])));
        assert!(!exposes_secrets_to_compression(&headers(&[(
            "cookie",
            "session=1"
        )])));
        assert!(forbids_transformation(&headers(&[(
            "cache-control",
            "public, No-Transform"
        )])));
        assert!(!forbids_transformation(&headers(&[(
            "cache-control",
            "no-store"
        )])));
    }

    #[test]
    fn test_should_compress_content_type() {
        let config = CompressionConfig::default();

        // Should compress
        let html = HeaderValue::from_static("text/html; charset=utf-8");
        assert!(should_compress_content_type(Some(&html), &config));

        let json = HeaderValue::from_static("application/json");
        assert!(should_compress_content_type(Some(&json), &config));

        // Should not compress
        let png = HeaderValue::from_static("image/png");
        assert!(!should_compress_content_type(Some(&png), &config));

        let mp4 = HeaderValue::from_static("video/mp4");
        assert!(!should_compress_content_type(Some(&mp4), &config));
    }

    /// What the response encoder writes, the request decoder reads back
    /// whole, for every coding the proxy offers.
    #[tokio::test]
    async fn every_coding_encodes_what_decodes_back() {
        let config = CompressionConfig::default();
        let data = b"Hello, World! This is a test string that should compress well when repeated. "
            .repeat(100);
        for encoding in [
            CompressionEncoding::Brotli,
            CompressionEncoding::Zstd,
            CompressionEncoding::Gzip,
            CompressionEncoding::Deflate,
        ] {
            let body = encode_stream(std::io::Cursor::new(data.clone()), encoding, &config);
            let encoded = axum::body::to_bytes(body, usize::MAX).await.unwrap();
            assert!(encoded.len() < data.len(), "{encoding:?} compresses");
            let decoded =
                crate::request_encoding::decode(Some(encoding.as_str()), &encoded, data.len() * 2)
                    .unwrap()
                    .unwrap();
            assert_eq!(decoded, data, "{encoding:?} round trip");
        }
    }
}
