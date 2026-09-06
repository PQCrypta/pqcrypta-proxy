//! CORS preflight handling and response-header injection for the TCP listener.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};

use crate::config::CorsConfig;

/// Handle CORS preflight OPTIONS request
pub(super) fn handle_cors_preflight(cors: &CorsConfig, request_origin: Option<&str>) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;

    let headers = response.headers_mut();

    // Multi-origin reflection: prefer allow_origins list; fall back to allow_origin
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
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    if let Some(ref origin) = resolved_origin {
        if let Ok(v) = HeaderValue::from_str(origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }

    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        if let Ok(v) = HeaderValue::from_str(&methods) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, v);
        }
    }

    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        if let Ok(v) = HeaderValue::from_str(&hdrs) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
        }
    }

    if cors.allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if cors.max_age > 0 {
        if let Ok(v) = HeaderValue::from_str(&cors.max_age.to_string()) {
            headers.insert(header::ACCESS_CONTROL_MAX_AGE, v);
        }
    }

    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));

    response
}

/// Add CORS headers to response
pub(super) fn add_cors_headers(
    headers: &mut HeaderMap,
    cors: &CorsConfig,
    request_origin: Option<&str>,
) {
    // Multi-origin reflection: prefer allow_origins list; fall back to allow_origin
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
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    }
    if let Some(ref origin) = resolved_origin {
        if let Ok(v) = HeaderValue::from_str(origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }

    if !cors.allow_methods.is_empty() {
        let methods = cors.allow_methods.join(", ");
        if let Ok(v) = HeaderValue::from_str(&methods) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, v);
        }
    }

    if !cors.allow_headers.is_empty() {
        let hdrs = cors.allow_headers.join(", ");
        if let Ok(v) = HeaderValue::from_str(&hdrs) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v);
        }
    }

    if cors.allow_credentials {
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
    }

    if cors.max_age > 0 {
        if let Ok(v) = HeaderValue::from_str(&cors.max_age.to_string()) {
            headers.insert(header::ACCESS_CONTROL_MAX_AGE, v);
        }
    }
}

/// Check if user agent is a mobile device
pub(super) fn is_mobile_user_agent(ua: &str) -> bool {
    let ua_lower = ua.to_lowercase();
    ua_lower.contains("mobile")
        || ua_lower.contains("android")
        || ua_lower.contains("webos")
        || ua_lower.contains("iphone")
        || ua_lower.contains("ipad")
        || ua_lower.contains("ipod")
        || ua_lower.contains("blackberry")
        || ua_lower.contains("iemobile")
        || ua_lower.contains("opera mini")
}
