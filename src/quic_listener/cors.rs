//! CORS header injection for HTTP/3 responses built via `http::response::Builder`.

use crate::config::CorsConfig;

/// Add CORS headers to an http::Response::builder from CorsConfig
pub(super) fn add_cors_headers_to_builder(
    mut builder: http::response::Builder,
    cors: &CorsConfig,
    request_origin: Option<&str>,
) -> http::response::Builder {
    // Access-Control-Allow-Origin — reflect when allow_origins list is set
    let resolved_origin = if !cors.allow_origins.is_empty() {
        request_origin
            .filter(|o| cors.allow_origins.iter().any(|a| a == *o))
            .map(String::from)
    } else {
        cors.allow_origin.clone()
    };
    // `Vary: Origin` whenever the answer depends on the request's origin.
    //
    // Required by the Fetch standard, and load-bearing for anything in front of
    // this: without it a cache may hand one origin the header that names
    // another. Set only when reflecting from an allowlist — a fixed
    // `allow_origin` is the same for every caller and needs no Vary.
    if !cors.allow_origins.is_empty() {
        builder = builder.header("vary", "Origin");
    }
    if let Some(ref origin) = resolved_origin {
        builder = builder.header("access-control-allow-origin", origin);
    }

    // Access-Control-Allow-Methods
    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        builder = builder.header("access-control-allow-methods", methods);
    }

    // Access-Control-Allow-Headers
    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        builder = builder.header("access-control-allow-headers", hdrs);
    }

    // Access-Control-Allow-Credentials
    if cors.allow_credentials {
        builder = builder.header("access-control-allow-credentials", "true");
    }

    // Access-Control-Max-Age
    if cors.max_age > 0 {
        builder = builder.header("access-control-max-age", cors.max_age.to_string());
    }

    builder
}
