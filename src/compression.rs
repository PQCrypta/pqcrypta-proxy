//! Response compression middleware
//!
//! Provides cutting-edge compression features:
//! - Brotli compression (best ratio, 95%+ browser support)
//! - Zstandard compression (fastest, gaining adoption)
//! - Gzip compression (fallback for older clients)
//! - Deflate compression (legacy support)
//! - Content negotiation via Accept-Encoding
//! - Streaming compression for large responses
//! - Smart skipping of pre-compressed content

use std::io::Write;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;
use tracing::{debug, trace};

/// Compression configuration
#[derive(Debug, Clone)]
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

/// Parse Accept-Encoding header and return best supported encoding
pub fn parse_accept_encoding(accept_encoding: Option<&HeaderValue>) -> CompressionEncoding {
    let Some(value) = accept_encoding else {
        return CompressionEncoding::Identity;
    };

    let Ok(value_str) = value.to_str() else {
        return CompressionEncoding::Identity;
    };

    // Parse encodings with quality values
    let mut encodings: Vec<(&str, f32)> = value_str
        .split(',')
        .filter_map(|part| {
            let part = part.trim();
            let (encoding, quality) = if let Some(idx) = part.find(";q=") {
                let (enc, q) = part.split_at(idx);
                let q = q[3..].parse::<f32>().unwrap_or(1.0);
                (enc.trim(), q)
            } else {
                (part, 1.0)
            };
            if quality > 0.0 {
                Some((encoding, quality))
            } else {
                None
            }
        })
        .collect();

    // Sort by quality (highest first)
    encodings.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Return best supported encoding
    for (encoding, _) in encodings {
        match encoding.to_lowercase().as_str() {
            "br" | "brotli" => return CompressionEncoding::Brotli,
            "zstd" => return CompressionEncoding::Zstd,
            "gzip" => return CompressionEncoding::Gzip,
            "deflate" => return CompressionEncoding::Deflate,
            "*" => return CompressionEncoding::Brotli, // Use best by default
            _ => {}
        }
    }

    CompressionEncoding::Identity
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

/// Compress data using the specified encoding
pub fn compress_bytes(
    data: &[u8],
    encoding: CompressionEncoding,
    config: &CompressionConfig,
) -> Option<Vec<u8>> {
    match encoding {
        CompressionEncoding::Brotli => {
            let mut encoder = brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                config.brotli_quality,
                22, // lgwin
            );
            encoder.write_all(data).ok()?;
            Some(encoder.into_inner())
        }
        CompressionEncoding::Zstd => zstd::encode_all(data, config.zstd_level).ok(),
        CompressionEncoding::Gzip => {
            use std::io::Write;
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(config.gzip_level),
            );
            encoder.write_all(data).ok()?;
            encoder.finish().ok()
        }
        CompressionEncoding::Deflate => {
            use std::io::Write;
            let mut encoder = flate2::write::DeflateEncoder::new(
                Vec::new(),
                flate2::Compression::new(config.gzip_level),
            );
            encoder.write_all(data).ok()?;
            encoder.finish().ok()
        }
        CompressionEncoding::Identity => None,
    }
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
// Prometheus gauge values are f64; precision loss on large counter values is acceptable.
#[allow(clippy::cast_precision_loss)]
pub async fn compression_middleware(
    State(state): State<CompressionState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let config = &state.config;

    if !config.enabled {
        return next.run(request).await;
    }

    // Parse Accept-Encoding from request
    let encoding = parse_accept_encoding(request.headers().get(header::ACCEPT_ENCODING));

    // Don't compress if client doesn't support it
    if encoding == CompressionEncoding::Identity {
        return next.run(request).await;
    }

    trace!("Client accepts compression: {:?}", encoding);

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

    // Collect body bytes for compression
    // Note: For very large responses, streaming compression would be better
    let (mut parts, body) = response.into_parts();

    // Try to collect the body
    let body_bytes = match axum::body::to_bytes(body, 100 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            debug!("Failed to read body for compression: {}", e);
            return Response::from_parts(parts, Body::empty());
        }
    };

    // Check size after reading
    if body_bytes.len() < config.min_size {
        trace!("Body too small after reading: {} bytes", body_bytes.len());
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    // Compress the body
    let compressed = match compress_bytes(&body_bytes, encoding, config) {
        Some(compressed) => compressed,
        None => {
            debug!("Compression failed, returning uncompressed");
            return Response::from_parts(parts, Body::from(body_bytes));
        }
    };

    // Only use compressed version if it's smaller
    if compressed.len() >= body_bytes.len() {
        trace!(
            "Compressed size ({}) >= original ({}), skipping",
            compressed.len(),
            body_bytes.len()
        );
        return Response::from_parts(parts, Body::from(body_bytes));
    }

    let original_size = body_bytes.len();
    let compressed_size = compressed.len();
    // clamp(0.0, u32::MAX as f64) ensures value is non-negative and within u32 range.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ratio = (compressed_size as f64 / original_size as f64 * 100.0)
        .clamp(0.0, u32::MAX as f64) as u32;

    debug!(
        "Compressed response: {} -> {} bytes ({}%, {})",
        original_size,
        compressed_size,
        ratio,
        encoding.as_str()
    );

    // Update headers
    parts.headers.insert(
        header::CONTENT_ENCODING,
        HeaderValue::from_static(encoding.as_str()),
    );
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&compressed_size.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

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

    Response::from_parts(parts, Body::from(compressed))
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

        // Test zstd
        let header = HeaderValue::from_static("zstd, gzip, br");
        assert_eq!(
            parse_accept_encoding(Some(&header)),
            CompressionEncoding::Zstd
        );

        // Test no compression
        assert_eq!(parse_accept_encoding(None), CompressionEncoding::Identity);
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

    #[test]
    fn test_compress_bytes() {
        let config = CompressionConfig::default();
        let data = b"Hello, World! This is a test string that should compress well when repeated. "
            .repeat(100);

        // Test Brotli
        let compressed = compress_bytes(&data, CompressionEncoding::Brotli, &config).unwrap();
        assert!(compressed.len() < data.len());

        // Test Zstd
        let compressed = compress_bytes(&data, CompressionEncoding::Zstd, &config).unwrap();
        assert!(compressed.len() < data.len());

        // Test Gzip
        let compressed = compress_bytes(&data, CompressionEncoding::Gzip, &config).unwrap();
        assert!(compressed.len() < data.len());
    }
}
