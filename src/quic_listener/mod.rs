//! QUIC/HTTP3/WebTransport listener
//!
//! Accepts QUIC connections, negotiates HTTP/3, and handles WebTransport sessions.
//! Routes streams and datagrams to configured backends.
//!
//! This listener handles QUIC/HTTP3 connections (h3/quinn stack) and runs alongside
//! `WebTransportServer` (wtransport stack), which handles the dedicated WebTransport port.

use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;
use h3::ext::Protocol;
use h3_quinn::Connection as H3Connection;
use quinn::{
    AckFrequencyConfig, Connection as QuinnConnection, Endpoint, ServerConfig as QuinnServerConfig,
    TransportConfig, VarInt,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::cache::ResponseCache;
use crate::config::{ConfigReloadEvent, ProxyConfig};
use crate::connect_udp::{self, DatagramRouter};
use crate::handlers::WebTransportHandler;
use crate::http3_features::EarlyHintsState;
use crate::load_balancer::LoadBalancer;
use crate::metrics::{ConnectionProtocol, MetricsRegistry};

use crate::fingerprint::FingerprintExtractor;
use crate::proxy::BackendPool;
use crate::rate_limiter::AdvancedRateLimiter;
use crate::security::{BlockReason, SecurityState};
use crate::tls::TlsProvider;

mod cors;
mod request;
mod websocket;

use websocket::ws_h3_tunnel;

const SERVER_HEADER: &str = "pqcrypta"; // SEC-08: no version disclosure

/// True when an h3 error is just the peer hanging up rather than a fault here.
///
/// Every one of these shapes is produced by ordinary client behaviour: a clean
/// graceful shutdown (H3_NO_ERROR / application code 0), a browser navigating
/// away mid-request, or an idle connection ageing out. They carry no operator
/// signal, so they belong at debug — logged at error they drowned out real
/// failures and kept the collector's log-analysis in a permanent error spike.
fn is_benign_h3_close<E: std::fmt::Display>(err: &E) -> bool {
    let msg = err.to_string();
    msg.contains("H3_NO_ERROR")
        || msg.contains("ApplicationClose: 0x0")
        || msg.contains("aborted by peer")
        || msg.contains("closed abruptly")
        || msg.contains("Timeout")
}

/// The Alt-Svc value for a response being sent **over QUIC**.
///
/// RFC 7838 §3: Alt-Svc lists services that are alternatives *to the connection the
/// response arrived on*. A client already speaking h3 on this port learns nothing
/// from being told h3 is available on this port — that is the connection it is
/// using. This path used to send exactly that, an h3 advertisement over h3, which is
/// redundant rather than wrong, but it also means the header carries no information
/// at all for the one audience that receives it.
///
/// What is genuinely alternative from here:
///   * `h2` on the same port — the same origin over TCP, a real fallback
///   * `h3` on any *other* configured UDP port
///
/// haproxy.org is the reference for this behaviour: `h3=":443"` over TCP and
/// `h2=":443"` over QUIC. This goes one step further by keeping the other h3 ports,
/// which are alternatives to this connection even though they share its protocol.
///
/// `config.server.udp_port` is the port *this* listener is bound to — `main.rs`
/// clones the config per port and overwrites the field — so it identifies the
/// current connection without threading a parameter through every call site.
///
/// Returns "clear" for hosts listed in `server.tcp_only_hosts` so browsers evict any
/// cached QUIC upgrade and fall back to TCP/TLS.
fn build_alt_svc_header_over_quic(config: &ProxyConfig) -> String {
    let current = config.server.udp_port;

    // The same port over TCP. Both listeners bind the same port set, so a client on
    // h3:P can always reach h2:P.
    let mut parts = vec![format!("h2=\":{current}\"; ma=86400")];

    let mut seen = vec![current];
    for p in &config.server.additional_ports {
        if seen.contains(p) {
            continue;
        }
        seen.push(*p);
        parts.push(format!("h3=\":{p}\"; ma=86400"));
    }

    parts.join(", ")
}

/// The starting point for a QUIC connection's handshake facts.
///
/// Only the TLS version is knowable without reading `HandshakeData`: QUIC
/// permits nothing older than TLS 1.3 (RFC 9001 §4.2). The caller fills the rest
/// from a single `handshake_data()` read.
///
/// ECH starts `unknown` and is overwritten from `HandshakeData` as soon as the
/// handshake is read. It only stays `unknown` if that read fails, which would be
/// a real fault rather than a property of the protocol.
fn quic_handshake_facts_empty() -> crate::tls_acceptor::HandshakeFacts {
    crate::tls_acceptor::HandshakeFacts {
        tls_version: Some("TLSv1_3".to_string()),
        cipher_suite: None,
        kex_group: None,
        alpn: None,
        ech: "unknown",
    }
}

fn alt_svc_for_host(config: &ProxyConfig, host: Option<&str>) -> String {
    if let Some(h) = host {
        if config.server.tcp_only_hosts.iter().any(|t| t == h) {
            return "clear".to_string();
        }
    }
    build_alt_svc_header_over_quic(config)
}

/// QUIC/HTTP3/WebTransport listener
pub struct QuicListener {
    /// QUIC endpoint
    endpoint: Endpoint,
    /// TLS provider
    tls_provider: Arc<TlsProvider>,
    /// Backend connection pool
    backend_pool: Arc<BackendPool>,
    /// Configuration
    config: Arc<ProxyConfig>,
    /// Shutdown signal receiver
    shutdown_rx: mpsc::Receiver<()>,
    /// Config reload receiver
    reload_rx: mpsc::Receiver<ConfigReloadEvent>,
    /// Early Hints state for 103 responses
    early_hints_state: Arc<EarlyHintsState>,
    /// Metrics registry for recording request/connection stats
    metrics: Arc<MetricsRegistry>,
    /// Security state for IP blocking, GeoIP country blocking, and rate limiting.
    ///
    /// `Arc`, not an owned clone: this is handed to every connection task and
    /// every request within it, and `SecurityState` holds 17 `Arc`s of its own —
    /// so an owned copy is ~19 atomic increments on the way in and as many
    /// decrements on the way out, per request. The TCP path was fixed for this;
    /// the QUIC path kept the copy.
    security: Arc<SecurityState>,
    /// Advanced multi-dimensional rate limiter (shared with TCP listeners)
    advanced_rate_limiter: Arc<AdvancedRateLimiter>,
    /// Shared load balancer for canary routing and pool-based selection
    load_balancer: Arc<LoadBalancer>,
    /// Shared response cache (HTTP/3 path)
    cache: Arc<ResponseCache>,
    /// TLS client fingerprint extractor, shared with the TCP listeners.
    ///
    /// The QUIC path computed no JA3/JA4 at all: it read `x-ja3-hash` and
    /// `x-ja4-hash` from request headers that nothing on this path ever set, so
    /// fingerprint rate limiting, `block_malicious`/`block_scanners` and
    /// per-route `allowed_ja3` were all inert over HTTP/3 while appearing
    /// configured.
    fingerprint_extractor: Arc<FingerprintExtractor>,
    /// Fingerprint policy (blocking toggles, cache TTL) — same config the TCP
    /// listeners read, so one setting governs both transports.
    fingerprint_config: crate::config::FingerprintConfig,
}

/// Response headers that are identical on every response until the config is
/// reloaded.
///
/// These were rebuilt per response from config `String`s: fifteen header-name
/// parses and, because `HeaderValue::from_str` copies into `Bytes`, fifteen heap
/// allocations for values that never change. Built once per connection instead,
/// after which applying them is a `HeaderName` clone (cheap) and a `HeaderValue`
/// clone (a refcount bump).
///
/// Deliberately excludes `alt-svc`, which varies by host, and `server-timing`,
/// which carries the elapsed time of the request.
/// Resolve the per-route security policy for a request.
///
/// This was inlined twice in `handle_h3_request` -- once for the header-pass WAF
/// evaluation and again for the body-pass inspection, because the first lived in
/// a block that had since closed. Each copy re-derived the host, called
/// `is_conformance_host`, ran `find_route` (an O(routes) scan -- one route in a
/// test config, sixty on the live edge, nine of them carrying regexes) and
/// cloned every policy field. Extracted so the caller can resolve it once.
fn resolve_route_policy(
    security: &SecurityState,
    request: &http::Request<()>,
    path: &str,
) -> crate::security::RequestPolicy {
    let host = request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
        .or_else(|| request.uri().host().map(str::to_ascii_lowercase));
    let on_conformance_host =
        crate::security::is_conformance_host(&security.route_index, host.as_deref());
    security
        .route_index
        .find_route(host.as_deref(), path, false)
        .map(|r| crate::security::RequestPolicy {
            // The conformance vhost has no route entry, so the flag has to be
            // OR'd in rather than read from one.
            skip_bot_blocking: r.skip_bot_blocking || on_conformance_host,
            allowed_ja3: r.security.as_ref().and_then(|s| s.allowed_ja3.clone()),
            waf_enabled: r.security.as_ref().and_then(|s| s.waf_enabled),
            waf_mode: r.security.as_ref().and_then(|s| s.waf_mode.clone()),
            rate_limit_override: r
                .security
                .as_ref()
                .and_then(|s| s.rate_limit_override.clone()),
        })
        // No route matched — which is the conformance vhost's normal state,
        // since it is answered in-process and has no route entry.
        // `unwrap_or_default()` alone would drop the flag on exactly the host
        // that needs it.
        .unwrap_or_else(|| crate::security::RequestPolicy {
            skip_bot_blocking: on_conformance_host,
            ..crate::security::RequestPolicy::default()
        })
}

fn build_static_response_headers(config: &ProxyConfig) -> HeaderMap {
    let mut h = HeaderMap::with_capacity(16);
    let mut put = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            h.append(HeaderName::from_static(name), v);
        }
    };
    put("server", SERVER_HEADER);
    if !config.headers.accept_ch.is_empty() {
        put("accept-ch", &config.headers.accept_ch);
    }
    if !config.headers.nel.is_empty() {
        put("nel", &config.headers.nel);
    }
    if !config.headers.report_to.is_empty() {
        put("report-to", &config.headers.report_to);
    }
    if !config.headers.priority.is_empty() {
        put("priority", &config.headers.priority);
    }
    put("strict-transport-security", &config.headers.hsts);
    put("x-frame-options", &config.headers.x_frame_options);
    put(
        "x-content-type-options",
        &config.headers.x_content_type_options,
    );
    put("referrer-policy", &config.headers.referrer_policy);
    put("permissions-policy", &config.headers.permissions_policy);
    put(
        "cross-origin-opener-policy",
        &config.headers.cross_origin_opener_policy,
    );
    put(
        "cross-origin-embedder-policy",
        &config.headers.cross_origin_embedder_policy,
    );
    put(
        "cross-origin-resource-policy",
        &config.headers.cross_origin_resource_policy,
    );
    put("x-quantum-resistant", &config.headers.x_quantum_resistant);
    put("x-security-level", &config.headers.x_security_level);
    put(
        "x-permitted-cross-domain-policies",
        &config.headers.x_permitted_cross_domain_policies,
    );
    put("x-download-options", &config.headers.x_download_options);
    put(
        "x-dns-prefetch-control",
        &config.headers.x_dns_prefetch_control,
    );
    h
}

/// Apply the per-connection static header set and the policy headers that
/// depend on the request itself.
///
/// The TCP listener's `security_headers_middleware` is an axum layer, so it
/// never ran for HTTP/3 — and this path's own static set omitted the one header
/// that matters most. Every HTTP/3 response left here **without a
/// Content-Security-Policy**: the backend's nonce-bearing CSP is not on the
/// forwarding allowlist, and nothing injected the configured one. Since the DNS
/// HTTPS record advertises `alpn="h3"`, a browser's *first* connection is QUIC,
/// so the strict CSP the site is built around was absent for exactly the
/// visitors most likely to arrive on it.
///
/// Order matters: a CSP already on the builder came from the origin (it carries
/// the per-request nonces) and always wins over the configured fallback.
pub(super) fn apply_response_policy_headers(
    mut builder: http::response::Builder,
    config: &ProxyConfig,
    static_headers: &HeaderMap,
    host: Option<&str>,
    path: &str,
) -> http::response::Builder {
    // The Outlook add-in surface is framed cross-origin by Office: it must not
    // get X-Frame-Options: DENY, and it needs its own CSP. Same three config
    // knobs the TCP path reads, so the two transports agree.
    let hc = &config.headers;
    let is_outlook_addin = !hc.addin_csp.is_empty()
        && !hc.addin_path_prefix.is_empty()
        && path.starts_with(&hc.addin_path_prefix)
        && host.is_some_and(|h| {
            let h = h.split(':').next().unwrap_or(h);
            hc.addin_hosts.iter().any(|a| a.eq_ignore_ascii_case(h))
        });

    if let Some(h) = builder.headers_mut() {
        h.reserve(static_headers.len());
        for (name, value) in static_headers.iter() {
            if is_outlook_addin && name == header::X_FRAME_OPTIONS {
                continue;
            }
            h.append(name.clone(), value.clone());
        }
    }

    let has_csp = builder
        .headers_ref()
        .is_some_and(|h| h.contains_key(header::CONTENT_SECURITY_POLICY));
    if !has_csp {
        let csp = if is_outlook_addin {
            hc.addin_csp.as_str()
        } else {
            hc.content_security_policy.as_str()
        };
        if !csp.is_empty() {
            if let Ok(v) = HeaderValue::from_str(csp) {
                builder = builder.header(header::CONTENT_SECURITY_POLICY, v);
            }
        }
    }

    builder
}

impl QuicListener {
    /// Create a new QUIC listener
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::unused_async_trait_impl)] // public async API; callers .await it
    pub async fn new(
        config: Arc<ProxyConfig>,
        tls_provider: Arc<TlsProvider>,
        shutdown_rx: mpsc::Receiver<()>,
        reload_rx: mpsc::Receiver<ConfigReloadEvent>,
        metrics: Arc<MetricsRegistry>,
        security: Arc<SecurityState>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        early_hints_state: Arc<EarlyHintsState>,
    ) -> anyhow::Result<Self> {
        let addr = config.server.socket_addr()?;

        info!("Creating QUIC listener on {}", addr);

        // Create transport configuration
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(config.server.max_streams_per_connection.into());
        transport_config
            .max_concurrent_uni_streams(config.server.max_uni_streams_per_connection.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(
            config.server.keepalive_interval_secs,
        )));
        // Flow-control windows. These are the INITIAL credit a peer gets; the
        // receiver extends it with MAX_STREAM_DATA as it consumes, so these figures
        // cap neither transfer size nor eventual throughput — they set how much a
        // peer may send before waiting for us once.
        //
        // The previous 8 MB per stream / 16 MB per connection was set to match the
        // WebTransport server and beat quinn's ~256 KB default. 2 MB still clears
        // any realistic path: a stream window sustains window/RTT, so 2 MB is
        // ~533 Mbps at 30 ms and ~160 Mbps at 100 ms, far above what an HTTP upload
        // to this proxy needs. What the old figure bought instead was a much larger
        // advertised memory commitment per connection, multiplied by every stream a
        // peer chose to open.
        transport_config.receive_window(VarInt::from_u32(8 * 1024 * 1024)); // 8 MB connection
        transport_config.stream_receive_window(VarInt::from_u32(2 * 1024 * 1024)); // 2 MB per stream
        transport_config.max_idle_timeout(Some(
            Duration::from_secs(config.server.max_idle_timeout_secs)
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid idle timeout: {}", e))?,
        ));

        // When we acknowledge. The stack's default of 1 means "acknowledge every
        // other ack-eliciting packet", so a request the client does not overlap
        // with another waits out max_ack_delay — 25 ms — before its ACK leaves,
        // and the client will not start the next request on that connection
        // until it arrives. Measured here at 384 req/s and 26.04 ms for one
        // in-flight HTTP/3 stream, against 22,272 req/s and 448 µs at 0.
        //
        // Distinct from the ACK Frequency extension below, which asks the PEER
        // to change ITS behaviour and cannot affect ours.
        transport_config.local_ack_eliciting_threshold(config.server.ack_eliciting_threshold);
        if config.server.ack_eliciting_threshold > 0 {
            info!(
                "QUIC: acknowledging every {} ack-eliciting packets (threshold {})",
                config.server.ack_eliciting_threshold + 1,
                config.server.ack_eliciting_threshold
            );
        }

        // ACK Frequency extension (draft-ietf-quic-ack-frequency): allow the peer
        // to request fewer, batched ACKs, reducing ACK traffic and CPU on
        // high-throughput connections. Negotiated — inert if the peer lacks it.
        if config.server.enable_ack_frequency {
            transport_config.ack_frequency_config(Some(AckFrequencyConfig::default()));
            info!("QUIC ACK Frequency extension enabled");
        }

        // Full draft-ietf-quic-multipath support (via the noq QUIC stack):
        // allow this many concurrent, data-carrying paths per connection when
        // the peer negotiates multipath. Unlike the earlier narrow single-
        // path validation probe, noq implements the complete extension -
        // per-path packet-number spaces, PATH_ACK/ABANDON/STATUS lifecycle
        // frames, per-path loss recovery, and a scheduler - and manages path
        // creation/validation/teardown automatically once negotiated. Inert
        // for peers that don't advertise multipath.
        let multipath_paths = config.server.max_concurrent_multipath_paths;
        transport_config.max_concurrent_multipath_paths(multipath_paths);
        if multipath_paths > 0 {
            info!(
                "QUIC multipath enabled: up to {} concurrent path(s) per connection",
                multipath_paths
            );
        } else {
            info!("QUIC multipath disabled by configuration (max_concurrent_multipath_paths = 0)");
        }

        // Create QUIC server configuration
        let mut server_config =
            QuinnServerConfig::with_crypto(tls_provider.get_quic_server_config());
        server_config.transport = Arc::new(transport_config);

        // STEP 12: Gate connection migration on server config.
        // `migration()` is a method on ServerConfig, not TransportConfig.
        if !config.server.enable_quic_migration {
            server_config.migration(false);
            info!("QUIC connection migration disabled by configuration");
        }

        // Create endpoint. Built manually (rather than Endpoint::server) so we can
        // override the advertised QUIC version list. noq's DEFAULT_SUPPORTED_VERSIONS
        // is v1 + draft-29..34, but this proxy only handshakes stable versions —
        // advertising the obsolete drafts in Version Negotiation is misleading (and a
        // client that selected one would fail). We handshake QUIC v1 (RFC 9000) and
        // QUIC v2 (RFC 9369): v1 is listed first as the default, v2 support is
        // additive (the version is chosen per-connection from the client's Initial,
        // so v1 clients are unaffected). The vendored noq fork implements v2's
        // version-specific Initial keys (via rustls), retry integrity key, and
        // long-header packet-type renumbering. noq still adds its reserved/GREASE
        // version automatically.
        let socket = std::net::UdpSocket::bind(addr)?;

        // Explicitly size the kernel UDP socket buffers. quinn-udp enables GSO/GRO
        // automatically but does NOT set SO_RCVBUF/SO_SNDBUF — it inherits the host's
        // net.core.{r,w}mem_default. On a stock host that default is ~212 KB, which
        // drops datagrams under bulk QUIC load *before* quinn sees them (distinct from
        // the QUIC-level flow-control windows below). Setting it here makes throughput
        // portable across hosts instead of depending on a hand-tuned sysctl. The kernel
        // clamps the request to net.core.{r,w}mem_max and reports back ~2x the granted
        // size. 16 MB matches the 16 MB connection receive_window configured below.
        {
            const UDP_BUFFER_BYTES: usize = 16 * 1024 * 1024;
            let sock_ref = socket2::SockRef::from(&socket);
            if let Err(e) = sock_ref.set_recv_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set UDP SO_RCVBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            if let Err(e) = sock_ref.set_send_buffer_size(UDP_BUFFER_BYTES) {
                warn!("Failed to set UDP SO_SNDBUF to {UDP_BUFFER_BYTES} bytes: {e}");
            }
            // getsockopt returns roughly double the granted size on Linux (bookkeeping
            // overhead); halve for an honest figure. If these come back far below the
            // request, net.core.{r,w}mem_max is clamping and should be raised.
            let rcv = sock_ref.recv_buffer_size().map(|v| v / 2).unwrap_or(0);
            let snd = sock_ref.send_buffer_size().map(|v| v / 2).unwrap_or(0);
            info!(
                "QUIC UDP socket buffers: SO_RCVBUF≈{} KB, SO_SNDBUF≈{} KB (requested {} KB each)",
                rcv / 1024,
                snd / 1024,
                UDP_BUFFER_BYTES / 1024
            );
        }

        let runtime = quinn::default_runtime()
            .ok_or_else(|| anyhow::anyhow!("no async runtime found for QUIC endpoint"))?;
        let mut endpoint_config = quinn::EndpointConfig::default();
        endpoint_config.supported_versions(vec![0x0000_0001, 0x6b33_43cf]); // QUIC v1 (RFC 9000) + v2 (RFC 9369)
        let endpoint = Endpoint::new(endpoint_config, Some(server_config), socket, runtime)?;

        info!("QUIC endpoint created on {}", addr);
        info!("ALPN protocols: {:?}", config.tls.alpn_protocols);
        info!("PQC enabled: {}", tls_provider.is_pqc_enabled());

        // Create backend pool
        let backend_pool = Arc::new(BackendPool::new(config.clone()));

        // Early Hints state is created once in main() and shared across all QUIC
        // listeners so the config reload handler can update it live.
        if early_hints_state.is_enabled() {
            info!("HTTP/3 Early Hints (103) enabled");
        }

        // Cloned before `config` moves into `Self`.
        let config_for_fingerprints = config.fingerprint.clone();

        Ok(Self {
            endpoint,
            tls_provider,
            backend_pool,
            config,
            shutdown_rx,
            reload_rx,
            early_hints_state,
            metrics,
            security,
            advanced_rate_limiter,
            load_balancer,
            cache,
            fingerprint_extractor: Arc::new(FingerprintExtractor::new()),
            fingerprint_config: config_for_fingerprints,
        })
    }

    /// Run the QUIC listener
    pub async fn run(mut self) -> anyhow::Result<()> {
        info!(
            "QUIC/HTTP3/WebTransport listener running on {}",
            self.endpoint.local_addr()?
        );

        let mut accept_count = 0u64;

        loop {
            tokio::select! {
                // Handle incoming connections
                Some(incoming) = self.endpoint.accept() => {
                    accept_count += 1;
                    let remote_addr = crate::security::canonical_addr(incoming.remote_address());
                    let ip = remote_addr.ip();

                    // Connection-level security checks: IP blocklist and GeoIP country blocking.
                    // Evaluated before completing the QUIC/TLS handshake so blocked IPs never
                    // consume cryptographic handshake resources.
                    let should_refuse = if !self.security.is_trusted(&ip) {
                        if let Some(block_info) = self.security.is_blocked(&ip) {
                            warn!(
                                "[QUIC] Refusing connection from blocked IP {} (reason: {:?})",
                                ip, block_info.reason
                            );
                            true
                        } else if self.security.is_country_blocked(&ip) {
                            warn!("[QUIC] Refusing connection from GeoIP-blocked IP {}", ip);
                            self.security.block_ip(ip, BlockReason::GeoBlocked, None);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if should_refuse {
                        incoming.refuse();
                    } else if self.config.server.enable_quic_retry
                        && !incoming.remote_address_validated()
                    {
                        // QUIC Retry (RFC 9000 §8.1.2): the client's source
                        // address hasn't been validated yet, so answer with a
                        // Retry token instead of accepting. The client re-sends
                        // its Initial echoing the token; that second Incoming
                        // arrives with remote_address_validated() == true and
                        // is accepted normally on the next loop iteration.
                        // Configurable via [server].enable_quic_retry.
                        match incoming.retry() {
                            Ok(()) => {
                                debug!("[QUIC] Sent Retry for address validation to {}", remote_addr);
                            }
                            Err(e) => {
                                warn!("[QUIC] Retry failed for {}: {} — accepting without Retry", remote_addr, e);
                                // retry() consumes `incoming` even on error, so
                                // there is nothing left to accept here; the
                                // client will simply time out and retry itself.
                            }
                        }
                    } else {
                        info!("[{}] Incoming QUIC connection from {}", accept_count, remote_addr);

                        // Spawn connection handler
                        let config = self.config.clone();
                        let backend_pool = self.backend_pool.clone();
                        let early_hints_state = self.early_hints_state.clone();
                        let metrics = self.metrics.clone();
                        let security = self.security.clone();
                        let advanced_rate_limiter = self.advanced_rate_limiter.clone();
                        let load_balancer = self.load_balancer.clone();
                        let cache = self.cache.clone();
                        let fingerprint_extractor = self.fingerprint_extractor.clone();
                        let fingerprint_config = self.fingerprint_config.clone();

                        tokio::spawn(async move {
                            metrics.connections.connection_opened(ConnectionProtocol::Http3);
                            if let Err(e) = Self::handle_connection(
                                incoming,
                                remote_addr,
                                config,
                                backend_pool,
                                early_hints_state,
                                security,
                                metrics.clone(),
                                advanced_rate_limiter,
                                load_balancer,
                                cache,
                                fingerprint_extractor,
                                fingerprint_config,
                            ).await {
                                error!("Connection error from {}: {}", remote_addr, e);
                            }
                            metrics.connections.connection_closed();
                        });
                    }
                }

                // Handle config reload
                Some(event) = self.reload_rx.recv() => {
                    match event {
                        ConfigReloadEvent::ConfigReloaded(new_config) => {
                            info!("Applying configuration reload");
                            self.config = new_config;
                            // Note: Backend pool is thread-safe and will pick up new config
                        }
                        ConfigReloadEvent::TlsCertsReloaded => {
                            info!("TLS certificates reloaded");
                            // TLS provider handles cert reload internally
                            if let Err(e) = self.tls_provider.reload_certificates() {
                                error!("Failed to reload TLS certificates: {}", e);
                            }
                        }
                        ConfigReloadEvent::ReloadFailed(msg) => {
                            error!("Configuration reload failed: {}", msg);
                        }
                    }
                }

                // Handle shutdown
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping QUIC listener");
                    break;
                }
            }
        }

        // Graceful shutdown: tell peers we are going away, then wait for the
        // connections to finish.
        //
        // `wait_idle()` on its own waits for connections to close *by
        // themselves*, and an idle HTTP/3 connection from a browser does not:
        // it sits there until its own idle timeout, which outlives any
        // shutdown budget.  So every restart drained for the full
        // `graceful_shutdown_timeout_secs` and then gave up with connections
        // still counted active.  `close()` sends CONNECTION_CLOSE to each open
        // connection first (QUIC's equivalent of HTTP/2 GOAWAY), so peers
        // reconnect to the new process immediately instead of waiting to be
        // cut off.
        info!("Closing QUIC connections and waiting for them to drain...");
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"server shutting down");
        self.endpoint.wait_idle().await;

        info!("QUIC listener stopped");
        Ok(())
    }

    /// Handle a single QUIC connection
    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        incoming: quinn::Incoming,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: Arc<SecurityState>,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        fingerprint_extractor: Arc<FingerprintExtractor>,
        fingerprint_config: crate::config::FingerprintConfig,
    ) -> anyhow::Result<()> {
        // Accept connection
        let connecting = incoming.accept()?;
        let connection = connecting.await?;

        info!("QUIC connection established: {}", remote_addr);

        // Log ALPN negotiation and record TLS handshake
        metrics.tls.handshake_completed(true, false);

        // Read everything the handshake exposes in one pass: ALPN, the
        // negotiated group and cipher suite for the Handshake Mirror, and the
        // ClientHello bytes for fingerprinting.
        //
        // The hello is only reachable here. Over TCP a listener peeks the socket
        // and parses the hello itself; over QUIC it arrives inside encrypted
        // Initial CRYPTO frames, so the TLS stack holds the only plaintext copy
        // and the vendored rustls/noq forks hand it out through HandshakeData.
        let mut handshake_facts = quic_handshake_facts_empty();
        let mut client_hello: Option<Vec<u8>> = None;

        if let Some(handshake_data) = connection.handshake_data() {
            if let Some(crypto_data) =
                handshake_data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            {
                if let Some(protocol) = &crypto_data.protocol {
                    let alpn = String::from_utf8_lossy(protocol);
                    info!("ALPN negotiated: {} for {}", alpn, remote_addr);
                    handshake_facts.alpn = Some(alpn.into_owned());
                }
                handshake_facts.kex_group = crypto_data
                    .negotiated_key_exchange_group
                    .map(|g| format!("{g:?}"));
                handshake_facts.cipher_suite = crypto_data
                    .negotiated_cipher_suite
                    .map(|c| format!("{c:?}"));
                client_hello = crypto_data.client_hello_wire.clone();
                // ECH applies over QUIC exactly as over TCP; the page reported
                // it as "not observable over HTTP/3" only because nothing
                // carried the result up here.
                if let Some(ech) = crypto_data.ech_accepted {
                    handshake_facts.ech = match ech {
                        rustls::server::EchAcceptance::NotOffered => "not-offered",
                        rustls::server::EchAcceptance::Rejected => "rejected",
                        rustls::server::EchAcceptance::Accepted => "accepted",
                    };
                }
            }
        }

        // Fingerprint the client, applying exactly the policy the TCP path
        // applies — same classification order, same cache, same pentest bypass,
        // same ban decision.
        //
        // Unlike TCP this happens *after* the handshake rather than before it. A
        // QUIC server cannot decline earlier: the hello is encrypted under keys
        // derived during the handshake it would be trying to avoid. The block
        // still lands before any HTTP/3 request is served.
        let fingerprint = match client_hello.as_deref() {
            // `fingerprint.enabled = false` has to mean the same thing on both
            // transports. The TCP listeners gate their whole fingerprint stage on
            // it; this path did not, so an operator who turned fingerprinting off
            // still had QUIC connections classified and banned — a security policy
            // that applied over HTTP/3 and not over HTTP/1.1 or HTTP/2, with
            // nothing in the configuration saying so. Found when a load generator
            // was blocked as Suspicious on a run with the feature explicitly
            // disabled.
            Some(hello) if fingerprint_config.enabled => fingerprint_extractor
                .process_client_hello_quic(hello, remote_addr.ip(), &security, &fingerprint_config),
            Some(_) => crate::fingerprint::FingerprintResult {
                allowed: true,
                ja3_hash: None,
                ja4_hash: None,
                classification: None,
                client_name: None,
            },
            None => {
                debug!(
                    "[QUIC] No ClientHello available for {} — not fingerprinted",
                    remote_addr
                );
                crate::fingerprint::FingerprintResult {
                    allowed: true,
                    ja3_hash: None,
                    ja4_hash: None,
                    classification: None,
                    client_name: None,
                }
            }
        };

        if !fingerprint.allowed {
            warn!(
                "[QUIC] Blocking {} on TLS fingerprint (class={:?}, ja4={:?})",
                remote_addr, fingerprint.classification, fingerprint.ja4_hash
            );
            connection.close(0u32.into(), b"blocked");
            return Ok(());
        }

        // Multipath path management is fully automatic in noq once
        // negotiated (see max_concurrent_multipath_paths in the transport
        // config) - the peer opens/validates additional paths and the stack
        // schedules across them. Subscribe to noq's PathEvent stream so real
        // multipath activity (a second path opening, its per-path stats, and
        // teardown) is observable in the server logs, not silent inside the
        // transport. Costs nothing when no extra paths are opened.
        {
            let conn_for_paths = connection.clone();
            let peer = remote_addr;
            tokio::spawn(async move {
                let mut events = conn_for_paths.path_events();
                while let Some(ev) = events.next().await {
                    match ev {
                        Ok(quinn::PathEvent::Established { id, .. }) => {
                            let (rtt_ms, cwnd, mtu) = conn_for_paths
                                .path_stats(id)
                                .map(|s| {
                                    (
                                        u64::try_from(s.rtt.as_millis()).unwrap_or(u64::MAX),
                                        s.cwnd,
                                        u64::from(s.current_mtu),
                                    )
                                })
                                .unwrap_or((0, 0, 0));
                            info!(
                                "Multipath: path {} ESTABLISHED for {} (rtt={}ms cwnd={}B mtu={}B)",
                                id.get(),
                                peer,
                                rtt_ms,
                                cwnd,
                                mtu
                            );
                        }
                        Ok(quinn::PathEvent::Abandoned { id, reason, .. }) => {
                            info!(
                                "Multipath: path {} ABANDONED for {} (reason: {:?})",
                                id.get(),
                                peer,
                                reason
                            );
                        }
                        Ok(quinn::PathEvent::Discarded { id, path_stats, .. }) => {
                            info!(
                                "Multipath: path {} DISCARDED for {} (final: rtt={}ms cwnd={}B lost_pkts={})",
                                id.get(),
                                peer,
                                u64::try_from(path_stats.rtt.as_millis()).unwrap_or(u64::MAX),
                                path_stats.cwnd,
                                path_stats.lost_packets
                            );
                        }
                        Ok(_) => {}
                        Err(_lagged) => {
                            // Broadcast receiver fell behind; benign for logging.
                        }
                    }
                }
            });
        }

        // Create H3 connection
        let h3_conn = H3Connection::new(connection.clone());

        // Try to establish HTTP/3 connection with WebTransport support enabled
        // This advertises SETTINGS_ENABLE_WEBTRANSPORT=1 to clients
        match h3::server::builder()
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(1000)
            .build(h3_conn)
            .await
        {
            Ok(mut h3) => {
                // HTTP/3 connection established
                Self::handle_h3_connection(
                    &mut h3,
                    connection,
                    remote_addr,
                    config,
                    backend_pool,
                    early_hints_state,
                    security,
                    metrics,
                    advanced_rate_limiter,
                    load_balancer,
                    cache,
                    Arc::new(handshake_facts),
                    Arc::new(fingerprint),
                )
                .await?;
            }
            Err(e) => {
                // Fall back to raw QUIC streams (WebTransport without HTTP/3)
                warn!("HTTP/3 handshake failed, handling raw QUIC streams: {}", e);
                Self::handle_raw_quic(connection, remote_addr, config, backend_pool).await?;
            }
        }

        info!("Connection closed: {}", remote_addr);
        Ok(())
    }

    /// Handle HTTP/3 connection with WebTransport support
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    async fn handle_h3_connection(
        h3: &mut h3::server::Connection<H3Connection, Bytes>,
        quic_connection: QuinnConnection,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
        early_hints_state: Arc<EarlyHintsState>,
        security: Arc<SecurityState>,
        metrics: Arc<MetricsRegistry>,
        advanced_rate_limiter: Arc<AdvancedRateLimiter>,
        load_balancer: Arc<LoadBalancer>,
        cache: Arc<ResponseCache>,
        handshake: Arc<crate::tls_acceptor::HandshakeFacts>,
        fingerprint: Arc<crate::fingerprint::FingerprintResult>,
    ) -> anyhow::Result<()> {
        // Lazily created on the first CONNECT-UDP session so connections that
        // never use MASQUE pay nothing for the datagram reader task.
        let mut datagram_router: Option<Arc<DatagramRouter>> = None;

        // Built once for the connection rather than once per response; see
        // `build_static_response_headers`.
        let static_headers = Arc::new(build_static_response_headers(&config));

        loop {
            match h3.accept().await {
                Ok(Some(resolver)) => {
                    // Resolve the request
                    let (request, stream) = match resolver.resolve_request().await {
                        Ok(result) => result,
                        Err(e) => {
                            error!("Failed to resolve request: {}", e);
                            continue;
                        }
                    };

                    let method = request.method().clone();
                    let uri = request.uri().clone();
                    let path = if config.server.normalize_paths {
                        uri.path().to_ascii_lowercase()
                    } else {
                        uri.path().to_string()
                    };
                    // In HTTP/3, host comes from :authority pseudo-header (in URI) or fallback to host header
                    let host = uri
                        .authority()
                        .map(|a| a.host().to_ascii_lowercase())
                        .or_else(|| {
                            request
                                .headers()
                                .get("host")
                                .and_then(|v| v.to_str().ok())
                                .map(String::from)
                        });

                    // Check for protocol extension (RFC 9220 Extended CONNECT)
                    // In h3 crate, the :protocol pseudo-header is accessed via extensions
                    let protocol_ext = request.extensions().get::<Protocol>();
                    debug!(
                        "HTTP/3 request: {} {} from {} (host: {:?}, :protocol: {:?})",
                        method, path, remote_addr, host, protocol_ext
                    );

                    // Check for WebTransport CONNECT (RFC 9220)
                    // WebTransport uses Extended CONNECT with :protocol = webtransport
                    let is_webtransport = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p == &Protocol::WEB_TRANSPORT)
                            .unwrap_or(false);

                    // RFC 9220: WebSocket over HTTP/3 uses Extended CONNECT with :protocol = websocket
                    let is_ws_h3 = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "websocket")
                            .unwrap_or(false);

                    // RFC 9298: CONNECT-UDP uses Extended CONNECT with :protocol = connect-udp
                    let is_connect_udp = method == http::Method::CONNECT
                        && protocol_ext
                            .map(|p| p.as_str() == "connect-udp")
                            .unwrap_or(false);

                    if is_webtransport {
                        info!(
                            "WebTransport CONNECT request for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        // Reject WebTransport sessions for hosts/paths with no matching WT route.
                        // Without this check the proxy accepts every CONNECT unconditionally,
                        // leaving the session open until a 5-second idle timeout fires — which
                        // stalls scanners and health checks on non-WebTransport hosts.
                        // Note: find_route(is_webtransport=true) still returns non-WT routes
                        // (route_matches only prevents WT-only routes matching non-WT requests,
                        // not the reverse), so we must additionally check route.webtransport.
                        let has_wt_route = config
                            .find_route(host.as_deref(), &path, true)
                            .as_ref()
                            .is_some_and(|r| r.webtransport);
                        if !has_wt_route {
                            debug!(
                                "WebTransport CONNECT rejected (no WT route) for {} from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Send 200 OK to accept the WebTransport session
                        // IMPORTANT: Do NOT finish the stream - WebTransport sessions keep it open
                        let response = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .header("sec-webtransport-http3-draft", "draft02")
                            .body(())?;

                        // Respond on the stream first
                        let mut stream = stream;
                        if let Err(e) = stream.send_response(response).await {
                            error!(
                                "Failed to send WebTransport response to {}: {}",
                                remote_addr, e
                            );
                            continue;
                        }

                        info!(
                            "WebTransport session accepted for {} on path {}",
                            remote_addr, path
                        );

                        // Track WebTransport session in metrics
                        metrics
                            .connections
                            .connection_opened(ConnectionProtocol::WebTransport);

                        // Handle WebTransport session - pass the stream to the handler
                        // The session handler will manage bidirectional streams and datagrams
                        let handler = WebTransportHandler::new(
                            config.clone(),
                            backend_pool.clone(),
                            remote_addr,
                        );

                        let wt_metrics = metrics.clone();
                        tokio::spawn(async move {
                            debug!(
                                "WebTransport session active for {} on path {}",
                                remote_addr, path
                            );
                            if let Err(e) = handler.handle_session().await {
                                error!("WebTransport session error for {}: {}", remote_addr, e);
                            }
                            wt_metrics.connections.connection_closed();
                        });

                        // NOTE: Stream is intentionally NOT finished here
                        // The WebTransport session keeps it open for bidirectional communication
                        // The session will be closed when the client disconnects or on error
                    } else if is_connect_udp {
                        // RFC 9298: CONNECT-UDP. Relay UDP datagrams between the
                        // client and an allowlisted target host:port.
                        let mut stream = stream;

                        if !config.masque.enabled {
                            debug!("CONNECT-UDP rejected (disabled) from {}", remote_addr);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        let Some((target_host, target_port)) = connect_udp::parse_target(&path)
                        else {
                            debug!(
                                "CONNECT-UDP bad target path '{}' from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        if !config.masque.is_target_allowed(&target_host, target_port) {
                            warn!(
                                "CONNECT-UDP target {}:{} not allowed (from {})",
                                target_host, target_port, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::FORBIDDEN)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Resolve target to a socket address.
                        let resolved = tokio::net::lookup_host((target_host.as_str(), target_port))
                            .await
                            .ok()
                            .and_then(|mut addrs| addrs.next());
                        let Some(target_addr) = resolved else {
                            warn!(
                                "CONNECT-UDP: cannot resolve {}:{} (from {})",
                                target_host, target_port, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        // Start (or reuse) the per-connection datagram router.
                        let router = datagram_router
                            .get_or_insert_with(|| DatagramRouter::new(quic_connection.clone()))
                            .clone();

                        if router.session_count().await >= config.masque.max_sessions_per_connection
                        {
                            warn!("CONNECT-UDP: session limit reached for {}", remote_addr);
                            let reject = http::Response::builder()
                                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                                .body(())?;
                            let _ = stream.send_response(reject).await;
                            continue;
                        }

                        // Quarter Stream ID = request stream id / 4 (RFC 9297).
                        let quarter_id = stream.id().into_inner() / 4;
                        let from_client = router.register_session(quarter_id).await;

                        // Accept the session (RFC 9298 §3: 2xx).
                        let accept = http::Response::builder()
                            .status(http::StatusCode::OK)
                            .body(())?;
                        if let Err(e) = stream.send_response(accept).await {
                            error!("CONNECT-UDP: failed to accept for {}: {}", remote_addr, e);
                            router.unregister_session(quarter_id).await;
                            continue;
                        }

                        info!(
                            "CONNECT-UDP session opened: {} -> {} (qsid={})",
                            remote_addr, target_addr, quarter_id
                        );
                        metrics
                            .connections
                            .connection_opened(ConnectionProtocol::WebTransport);

                        let idle =
                            Duration::from_secs(config.masque.session_idle_timeout_secs.max(1));
                        let conn_clone = quic_connection.clone();
                        let metrics_clone = metrics.clone();
                        tokio::spawn(async move {
                            // The request stream stays open for the session; reading it
                            // to end (FIN/RESET) signals the client closed the tunnel.
                            let (_send, mut recv) = stream.split();
                            let stream_closed = async move {
                                // Drain any capsule data; FIN/RESET ends the loop.
                                while let Ok(Some(_)) = recv.recv_data().await {}
                            };
                            connect_udp::run_session(
                                router,
                                conn_clone,
                                quarter_id,
                                target_addr,
                                idle,
                                from_client,
                                stream_closed,
                            )
                            .await;
                            metrics_clone.connections.connection_closed();
                        });
                    } else if is_ws_h3 {
                        // RFC 9220: WebSocket-over-HTTP/3 extended CONNECT tunnel.
                        // Respond with 200 OK (not 101), then bridge the HTTP/3 bidi stream
                        // to a plain HTTP/1.1 WebSocket upgrade on the backend.
                        info!(
                            "WS/H3 extended CONNECT for {} from {} (host: {:?})",
                            path, remote_addr, host
                        );

                        let ws_route = config
                            .find_route(host.as_deref(), &path, false)
                            .filter(|r| r.supports_websocket);

                        let Some(route) = ws_route else {
                            debug!(
                                "WS/H3 CONNECT rejected (no ws route) for {} from {}",
                                path, remote_addr
                            );
                            let reject = http::Response::builder()
                                .status(http::StatusCode::NOT_FOUND)
                                .body(())?;
                            let mut stream = stream;
                            let _ = stream.send_response(reject).await;
                            continue;
                        };

                        let backend_address = match config.get_backend(&route.backend) {
                            Some(b) => b.address.clone(),
                            None => {
                                error!("WS/H3: backend not found: {}", route.backend);
                                let err_resp = http::Response::builder()
                                    .status(http::StatusCode::BAD_GATEWAY)
                                    .body(())?;
                                let mut stream = stream;
                                let _ = stream.send_response(err_resp).await;
                                continue;
                            }
                        };

                        let req_headers = request.headers().clone();
                        let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();
                        let idle_secs = route.ws_idle_timeout_secs;
                        let path_ws = path.clone();
                        let host_ws = host.clone().unwrap_or_default();

                        tokio::spawn(async move {
                            if let Err(e) = ws_h3_tunnel(
                                stream,
                                backend_address,
                                req_headers,
                                path_ws,
                                query,
                                host_ws,
                                idle_secs,
                            )
                            .await
                            {
                                debug!("WS/H3 tunnel ended: {}", e);
                            }
                        });
                    } else {
                        // Regular HTTP/3 request
                        let config_clone = config.clone();
                        let backend_pool_clone = backend_pool.clone();
                        let early_hints_clone = early_hints_state.clone();
                        let metrics_clone = metrics.clone();
                        let security_clone = security.clone();
                        let rl_clone = advanced_rate_limiter.clone();
                        let lb_clone = load_balancer.clone();
                        let cache_clone = cache.clone();
                        let handshake_clone = handshake.clone();
                        let fingerprint_clone = fingerprint.clone();
                        let static_headers_clone = static_headers.clone();

                        tokio::spawn(async move {
                            // Note: health check detection happens inside handle_h3_request
                            if let Err(e) = Self::handle_h3_request(
                                stream,
                                request,
                                remote_addr,
                                config_clone,
                                backend_pool_clone,
                                early_hints_clone,
                                security_clone,
                                metrics_clone,
                                rl_clone,
                                lb_clone,
                                cache_clone,
                                handshake_clone,
                                fingerprint_clone,
                                static_headers_clone,
                            )
                            .await
                            {
                                if is_benign_h3_close(&e) {
                                    debug!("HTTP/3 request ended by peer: {}", e);
                                } else {
                                    error!("HTTP/3 request error: {}", e);
                                }
                            }
                        });
                    }
                }
                Ok(None) => {
                    debug!("HTTP/3 connection closed by peer: {}", remote_addr);
                    break;
                }
                Err(e) => {
                    // A browser navigating away closes the connection mid-accept.
                    // That is the overwhelming majority of what lands here, and
                    // logging it at error level made the collector's log-analysis
                    // report continuous "error spikes" for ordinary traffic.
                    if is_benign_h3_close(&e) {
                        debug!("HTTP/3 connection closed by peer: {}", e);
                    } else {
                        error!("HTTP/3 accept error: {}", e);
                    }
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle raw QUIC streams (fallback when HTTP/3 handshake fails)
    async fn handle_raw_quic(
        connection: quinn::Connection,
        remote_addr: SocketAddr,
        config: Arc<ProxyConfig>,
        backend_pool: Arc<BackendPool>,
    ) -> anyhow::Result<()> {
        let handler = WebTransportHandler::new(config.clone(), backend_pool, remote_addr);

        loop {
            tokio::select! {
                // Bidirectional streams
                bi_result = connection.accept_bi() => {
                    match bi_result {
                        Ok((send, recv)) => {
                            debug!("Bidirectional stream from {}", remote_addr);
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_bi_stream(send, recv, "/", None)
                                    .await
                                {
                                    error!("Bi-stream error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Bi-stream accept ended: {}", e);
                            break;
                        }
                    }
                }

                // Unidirectional streams
                uni_result = connection.accept_uni() => {
                    match uni_result {
                        Ok(recv) => {
                            debug!("Unidirectional stream from {}", remote_addr);
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_uni_stream(recv, "/", None)
                                    .await
                                {
                                    error!("Uni-stream error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Uni-stream accept ended: {}", e);
                            break;
                        }
                    }
                }

                // Datagrams
                datagram_result = connection.read_datagram() => {
                    match datagram_result {
                        Ok(datagram) => {
                            debug!("Datagram from {} ({} bytes)", remote_addr, datagram.len());
                            let handler_clone = WebTransportHandler::new(
                                config.clone(),
                                handler.backend_pool.clone(),
                                remote_addr,
                            );
                            let conn = connection.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handler_clone
                                    .handle_datagram(&conn, datagram, "/", None)
                                    .await
                                {
                                    error!("Datagram error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            debug!("Datagram read ended: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get local address
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

#[cfg(test)]
mod alt_svc_tests {
    use super::*;

    fn config_with(udp_port: u16, additional: Vec<u16>, tcp_only: Vec<String>) -> ProxyConfig {
        let mut c = ProxyConfig::default();
        c.server.udp_port = udp_port;
        c.server.additional_ports = additional;
        c.server.tcp_only_hosts = tcp_only;
        c
    }

    /// The point of the change: a client already on h3:443 is not told about h3:443.
    #[test]
    fn does_not_advertise_the_connection_it_is_on() {
        let c = config_with(443, vec![4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert!(
            !v.contains("h3=\":443\""),
            "h3 on the current port is this connection, not an alternative: {v}"
        );
        assert!(v.contains("h2=\":443\""), "TCP on the same port is: {v}");
        assert!(v.contains("h3=\":4434\""), "another h3 port is: {v}");
    }

    /// A second h3 port shares the protocol but is still a different service, so
    /// unlike haproxy.org's simpler form it is kept.
    #[test]
    fn keeps_other_h3_ports() {
        let c = config_with(443, vec![4433, 4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert_eq!(
            v,
            "h2=\":443\"; ma=86400, h3=\":4433\"; ma=86400, h3=\":4434\"; ma=86400"
        );
    }

    /// Each listener is handed a config clone with its own port in `udp_port`, so
    /// the listener on an additional port must exclude *that* port, not 443.
    #[test]
    fn excludes_the_current_port_on_a_secondary_listener() {
        let c = config_with(4434, vec![4433, 4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert!(v.contains("h2=\":4434\""), "{v}");
        assert!(v.contains("h3=\":4433\""), "{v}");
        assert!(
            !v.contains("h3=\":4434\""),
            "4434 is the current connection here: {v}"
        );
    }

    /// A port listed in both `udp_port` and `additional_ports` must not produce two
    /// entries, or a client sees the same alternative twice.
    #[test]
    fn does_not_duplicate_a_port() {
        let c = config_with(443, vec![443, 443, 4434], vec![]);
        let v = build_alt_svc_header_over_quic(&c);
        assert_eq!(v.matches("h3=\":4434\"").count(), 1, "{v}");
        assert!(!v.contains("h3=\":443\""), "{v}");
    }

    /// Unchanged behaviour: a TCP-only host still gets the eviction token, which is
    /// what stops a browser using a cached upgrade.
    #[test]
    fn tcp_only_hosts_still_clear() {
        let c = config_with(443, vec![4434], vec!["ssllabs.pqcrypta.com".to_string()]);
        assert_eq!(alt_svc_for_host(&c, Some("ssllabs.pqcrypta.com")), "clear");
        assert_ne!(alt_svc_for_host(&c, Some("pqcrypta.com")), "clear");
        assert_ne!(alt_svc_for_host(&c, None), "clear");
    }
}
