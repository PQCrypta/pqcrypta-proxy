//! OpenTelemetry distributed tracing integration
//!
//! Provides end-to-end trace propagation across all HTTP transports:
//! - HTTP/1.1 and HTTP/2 (axum middleware in http_listener.rs)
//! - HTTP/3 / QUIC (quic_listener.rs)
//! - WebTransport (webtransport_server.rs)
//!
//! Propagation formats supported:
//! - **W3C TraceContext** (`traceparent` / `tracestate`) — RFC 9543
//! - **B3 multi-header** (`x-b3-traceid`, `x-b3-spanid`, `x-b3-sampled`)
//! - **B3 single-header** (`b3`)
//!
//! The composite propagator extracts from whichever format is present in the
//! incoming request (W3C takes priority) and injects both formats into every
//! upstream/backend request so downstream services can correlate traces.
//!
//! OTLP export uses HTTP/JSON transport via the existing `reqwest` client.
//! The global tracer provider is a NOOP until `init_otel()` is called, so
//! spans created during startup are silently dropped — request-handling spans
//! created after startup are fully exported.

use std::collections::HashMap;
use std::sync::OnceLock;

use http::{HeaderMap, HeaderName, HeaderValue};
use opentelemetry::propagation::text_map_propagator::FieldIter;
use opentelemetry::{
    global,
    propagation::{Extractor, Injector, TextMapCompositePropagator, TextMapPropagator},
    trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState},
    Context, KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    propagation::TraceContextPropagator,
    trace::{self as sdktrace, Sampler, TracerProvider},
    Resource,
};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::config::OtelConfig;

// ── Internal carrier implementations ─────────────────────────────────────────

/// Extractor over an HTTP `HeaderMap` (immutable).
struct HeaderMapCarrier<'a>(&'a HeaderMap);

impl Extractor for HeaderMapCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Injector over a mutable HTTP `HeaderMap`.
struct HeaderMapInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, val);
        }
    }
}

/// Injector into a mutable `HashMap<String, String>` (lower-cased keys).
/// Used by the QUIC/HTTP3 and backend proxy paths.
struct HashMapInjector<'a>(&'a mut HashMap<String, String>);

impl Injector for HashMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_lowercase(), value);
    }
}

/// Extractor over a `HashMap<String, String>` with case-insensitive key lookup.
struct HashMapCarrier<'a>(&'a HashMap<String, String>);

impl Extractor for HashMapCarrier<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(&key.to_lowercase()).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

// ── B3 propagator ─────────────────────────────────────────────────────────────

/// B3 propagator implementing both multi-header and single-header formats.
///
/// **Extraction priority**: single-header `b3` → multi-header `x-b3-*`.
/// **Injection**: always writes both forms for maximum downstream compatibility.
#[derive(Debug, Default)]
pub struct B3Propagator;

/// Header name constants (str slices — converted to Strings on demand)
const B3_SINGLE: &str = "b3";
const B3_TRACE_ID: &str = "x-b3-traceid";
const B3_SPAN_ID: &str = "x-b3-spanid";
const B3_SAMPLED: &str = "x-b3-sampled";

/// Static field list as `Vec<String>` — required by `FieldIter::new(&[String])`.
static B3_FIELD_NAMES: OnceLock<Vec<String>> = OnceLock::new();

fn b3_field_names() -> &'static Vec<String> {
    B3_FIELD_NAMES.get_or_init(|| {
        vec![
            B3_SINGLE.to_string(),
            B3_TRACE_ID.to_string(),
            B3_SPAN_ID.to_string(),
            B3_SAMPLED.to_string(),
        ]
    })
}

impl TextMapPropagator for B3Propagator {
    fn inject_context(&self, cx: &Context, carrier: &mut dyn Injector) {
        let span_ref = cx.span();
        let span_ctx = span_ref.span_context();
        if !span_ctx.is_valid() {
            return;
        }

        let trace_id = format!("{}", span_ctx.trace_id());
        let span_id = format!("{}", span_ctx.span_id());
        let sampled = if span_ctx.is_sampled() { "1" } else { "0" };

        // Multi-header B3
        carrier.set(B3_TRACE_ID, trace_id.clone());
        carrier.set(B3_SPAN_ID, span_id.clone());
        carrier.set(B3_SAMPLED, sampled.to_string());
        // Single-header b3: {traceId}-{spanId}-{flag}
        carrier.set(B3_SINGLE, format!("{}-{}-{}", trace_id, span_id, sampled));
    }

    fn extract_with_context(&self, cx: &Context, carrier: &dyn Extractor) -> Context {
        // Try single-header first: {traceId}-{spanId}[-{flag}[-{parentSpanId}]]
        let (trace_str, span_str, sampled) = if let Some(b3) = carrier.get(B3_SINGLE) {
            let parts: Vec<&str> = b3.splitn(4, '-').collect();
            if parts.len() < 2 {
                return cx.clone();
            }
            let s = parts.get(2).is_none_or(|&f| f != "0");
            (parts[0].to_owned(), parts[1].to_owned(), s)
        } else {
            let tid = carrier.get(B3_TRACE_ID).unwrap_or("").to_owned();
            let sid = carrier.get(B3_SPAN_ID).unwrap_or("").to_owned();
            if tid.is_empty() || sid.is_empty() {
                return cx.clone();
            }
            let s = carrier.get(B3_SAMPLED) != Some("0");
            (tid, sid, s)
        };

        let trace_id = match TraceId::from_hex(&trace_str) {
            Ok(id) if id != TraceId::INVALID => id,
            _ => return cx.clone(),
        };
        let span_id = match SpanId::from_hex(&span_str) {
            Ok(id) if id != SpanId::INVALID => id,
            _ => return cx.clone(),
        };

        let flags = if sampled {
            TraceFlags::SAMPLED
        } else {
            TraceFlags::default()
        };

        let span_ctx = SpanContext::new(trace_id, span_id, flags, true, TraceState::NONE);
        cx.with_remote_span_context(span_ctx)
    }

    fn fields(&self) -> FieldIter<'_> {
        FieldIter::new(b3_field_names().as_slice())
    }
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Initialise OpenTelemetry with OTLP HTTP/JSON export and a composite
/// W3C TraceContext + B3 propagator.
///
/// This function is synchronous — it only builds the OTLP HTTP client and
/// registers the global provider/propagator.  Actual span export happens
/// asynchronously via the tokio-based batch processor.
///
/// # Errors
/// Returns an error if the OTLP exporter cannot be constructed (e.g. invalid endpoint).
pub fn init_otel(config: &OtelConfig) -> anyhow::Result<TracerProvider> {
    // 1. Install composite propagator: W3C TraceContext first, then B3
    let propagators: Vec<Box<dyn TextMapPropagator + Send + Sync>> = vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(B3Propagator),
    ];
    global::set_text_map_propagator(TextMapCompositePropagator::new(propagators));

    // 2. Build OTLP span exporter (HTTP/JSON, no protobuf required)
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(&config.otlp_endpoint)
        .build()
        .map_err(|e| anyhow::anyhow!("OTLP exporter init failed: {}", e))?;

    // 3. Build service resource with user-supplied attributes
    let mut kv = vec![KeyValue::new("service.name", config.service_name.clone())];
    for (k, v) in &config.resource_attributes {
        kv.push(KeyValue::new(k.clone(), v.clone()));
    }
    let resource = Resource::new(kv);

    // 4. Sampler — parentBased wraps the configured root sampler
    let root_sampler = if config.sample_ratio >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_ratio)
    };

    // 5. Build tracer provider with batch exporter (tokio runtime)
    let provider = sdktrace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .with_sampler(Sampler::ParentBased(Box::new(root_sampler)))
        .build();

    // 6. Register as global provider — the tracing_opentelemetry layer picks this up
    global::set_tracer_provider(provider.clone());

    tracing::info!(
        endpoint = %config.otlp_endpoint,
        service = %config.service_name,
        sample_ratio = config.sample_ratio,
        "OpenTelemetry tracing initialised (OTLP HTTP/JSON)"
    );

    Ok(provider)
}

/// Flush and shut down the OTLP exporter, blocking until the queue is drained.
pub fn shutdown_otel(provider: &TracerProvider) {
    if let Err(e) = provider.shutdown() {
        tracing::warn!("OpenTelemetry shutdown error: {}", e);
    }
}

// ── Propagation helpers ───────────────────────────────────────────────────────

/// Extract the remote parent context from an HTTP `HeaderMap` using the
/// globally configured propagator (W3C TraceContext + B3).
pub fn extract_context_from_headers(headers: &HeaderMap) -> Context {
    global::get_text_map_propagator(|p| p.extract(&HeaderMapCarrier(headers)))
}

/// Extract the remote parent context from a `HashMap<String, String>`.
/// Used by the QUIC/HTTP3 and WebTransport paths.
#[allow(clippy::implicit_hasher)]
pub fn extract_context_from_map(map: &HashMap<String, String>) -> Context {
    global::get_text_map_propagator(|p| p.extract(&HashMapCarrier(map)))
}

/// Inject the given context into an HTTP `HeaderMap` (writes both W3C and B3).
pub fn inject_context_into_headers(ctx: &Context, headers: &mut HeaderMap) {
    global::get_text_map_propagator(|p| p.inject_context(ctx, &mut HeaderMapInjector(headers)));
}

/// Inject the given context into a `HashMap<String, String>`.
#[allow(clippy::implicit_hasher)]
pub fn inject_context_into_map(ctx: &Context, map: &mut HashMap<String, String>) {
    global::get_text_map_propagator(|p| p.inject_context(ctx, &mut HashMapInjector(map)));
}

/// Set the parent of the given tracing `Span` from the remote context in HTTP headers.
///
/// Call this at the top of every server-side request handler to stitch the incoming
/// trace into the local span tree.
pub fn set_parent_from_headers(span: &Span, headers: &HeaderMap) {
    let ctx = extract_context_from_headers(headers);
    span.set_parent(ctx);
}

/// Set the parent from a `HashMap<String, String>` (QUIC / WebTransport path).
#[allow(clippy::implicit_hasher)]
pub fn set_parent_from_map(span: &Span, map: &HashMap<String, String>) {
    let ctx = extract_context_from_map(map);
    span.set_parent(ctx);
}

/// Inject the **current** active tracing span's context into an HTTP `HeaderMap`.
/// Use this immediately before forwarding a request to an upstream backend so
/// that the backend can continue the trace.
pub fn inject_current_context_into_headers(headers: &mut HeaderMap) {
    let ctx = Span::current().context();
    inject_context_into_headers(&ctx, headers);
}

/// Inject the current span context into a `HashMap<String, String>`.
#[allow(clippy::implicit_hasher)]
pub fn inject_current_context_into_map(map: &mut HashMap<String, String>) {
    let ctx = Span::current().context();
    inject_context_into_map(&ctx, map);
}

/// Return the trace-ID hex string of the currently active tracing span.
///
/// Returns an empty string when there is no active span. Used to stamp trace IDs
/// into access-log entries for log → trace correlation.
pub fn current_trace_id() -> String {
    let trace_id = Span::current().context().span().span_context().trace_id();
    if trace_id == TraceId::INVALID {
        String::new()
    } else {
        format!("{}", trace_id)
    }
}
