//! Configuration module with TOML parsing and hot-reload support
//!
//! All configuration values are externalized - no hardcoded ports, paths, or addresses.
//! Supports hot-reload of config and TLS certificates without process restart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipnet::IpNet;

use arc_swap::ArcSwap;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::acme::AcmeConfig;
use crate::cache::ResponseCacheConfig;
use crate::rate_limiter::AdvancedRateLimitConfig;

/// OpenTelemetry distributed tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OtelConfig {
    /// Enable OpenTelemetry tracing and OTLP export (default: false)
    pub enabled: bool,
    /// Service name reported to the tracing backend
    pub service_name: String,
    /// OTLP HTTP/JSON endpoint for span export (default: http://localhost:4318)
    pub otlp_endpoint: String,
    /// Sampling ratio: 1.0 = always sample, 0.0 = never, 0.1 = 10% (default: 1.0)
    pub sample_ratio: f64,
    /// Additional OpenTelemetry resource attributes (key = "value" pairs)
    pub resource_attributes: HashMap<String, String>,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            service_name: "pqcrypta-proxy".to_string(),
            // Standard OTLP HTTP port — compatible with Jaeger, Tempo, Honeycomb, etc.
            otlp_endpoint: "http://localhost:4318".to_string(),
            sample_ratio: 1.0,
            resource_attributes: HashMap::new(),
        }
    }
}

/// OCSP stapling configuration (TOML-compatible version)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OcspConfig {
    /// Enable OCSP stapling
    pub enabled: bool,
    /// Cache duration for OCSP responses (seconds)
    pub cache_duration_secs: u64,
    /// Refresh OCSP response before expiry (seconds)
    pub refresh_before_expiry_secs: u64,
    /// OCSP request timeout (seconds)
    pub timeout_secs: u64,
    /// Maximum retries for OCSP requests
    pub max_retries: u32,
    /// Retry delay between attempts (milliseconds)
    pub retry_delay_ms: u64,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cache_duration_secs: 3600,
            refresh_before_expiry_secs: 300,
            timeout_secs: 10,
            max_retries: 3,
            retry_delay_ms: 1000,
        }
    }
}

/// Global configuration container with hot-reload support
pub struct ConfigManager {
    /// Current active configuration (atomic swap for hot-reload)
    config: ArcSwap<ProxyConfig>,
    /// File watcher for hot-reload
    watcher: RwLock<Option<RecommendedWatcher>>,
    /// Channel to notify config changes
    reload_tx: mpsc::Sender<ConfigReloadEvent>,
    /// Configuration file path
    config_path: PathBuf,
}

/// Events emitted on configuration changes
#[derive(Debug, Clone)]
pub enum ConfigReloadEvent {
    /// Full configuration reload
    ConfigReloaded(Arc<ProxyConfig>),
    /// TLS certificates reloaded (triggered via admin API)
    TlsCertsReloaded,
    /// Reload failed with error
    ReloadFailed(String),
}

/// Main proxy configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    /// Config schema version (default 1; warn if absent, error if > CURRENT_CONFIG_VERSION)
    pub version: Option<u32>,
    /// Server bind configuration
    pub server: ServerConfig,
    /// TLS configuration
    pub tls: TlsConfig,
    /// Post-quantum cryptography settings
    pub pqc: PqcConfig,
    /// Web Application Firewall configuration
    #[serde(default)]
    pub waf: WafConfig,
    /// Backend definitions (single backend per name)
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
    /// Backend pools (multiple servers with load balancing)
    #[serde(default)]
    pub backend_pools: HashMap<String, BackendPoolConfig>,
    /// Route mappings
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// TLS passthrough routes (SNI-based routing without termination)
    #[serde(default)]
    pub passthrough_routes: Vec<PassthroughRoute>,
    /// Admin API configuration
    pub admin: AdminConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Rate limiting configuration (basic)
    pub rate_limiting: RateLimitConfig,
    /// Advanced multi-dimensional rate limiting
    #[serde(default)]
    pub advanced_rate_limiting: AdvancedRateLimitConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Security headers configuration
    #[serde(default)]
    pub headers: HeadersConfig,
    /// Response compression (TCP listeners). Defaults to on, as it always was;
    /// before this section existed the setting could not be changed at all.
    #[serde(default)]
    pub compression: crate::compression::CompressionConfig,
    /// HTTP redirect configuration
    #[serde(default)]
    pub http_redirect: HttpRedirectConfig,
    /// Load balancer configuration
    #[serde(default)]
    pub load_balancer: LoadBalancerConfig,
    /// TLS fingerprint detection configuration
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    /// HTTP connection pool configuration
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,
    /// OCSP stapling configuration
    #[serde(default)]
    pub ocsp: OcspConfig,
    /// ACME certificate automation configuration
    #[serde(default)]
    pub acme: AcmeConfig,
    /// HTTP/3 advanced features configuration
    #[serde(default)]
    pub http3: Http3Config,
    /// Response cache configuration
    #[serde(default)]
    pub cache: ResponseCacheConfig,
    /// OpenTelemetry distributed tracing configuration
    #[serde(default)]
    pub otel: OtelConfig,
    /// MASQUE / CONNECT-UDP proxying configuration (RFC 9298)
    #[serde(default)]
    pub masque: MasqueConfig,
    /// HTTP/3 + QUIC client conformance suite
    #[serde(default)]
    pub conformance: ConformanceConfig,
}

/// Current config schema version supported by this binary
pub const CURRENT_CONFIG_VERSION: u32 = 1;

/// Web Application Firewall configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WafConfig {
    /// Enable WAF (default false — opt-in)
    pub enabled: bool,
    /// Mode: "detect" (log only) | "block" (reject request) — default "block"
    pub mode: String,
    /// Enable SQLi pattern matching
    pub sqli: bool,
    /// Enable XSS pattern matching
    pub xss: bool,
    /// Enable path traversal detection
    pub path_traversal: bool,
    /// Enable NoSQL injection detection
    pub nosqli: bool,
    /// Enable SSRF pattern detection (higher false-positive rate)
    pub ssrf: bool,
    /// Scan JSON request bodies
    pub scan_json_body: bool,
    /// Maximum body bytes to scan (default 65536)
    pub max_body_scan_bytes: usize,
    /// User-supplied extra regex patterns (applied in block mode)
    pub custom_patterns: Vec<String>,
    /// Block known scanner/reconnaissance probe paths (default true)
    pub scanner_probe: bool,
    /// Block known malicious scanner/bot user-agents (sqlmap, nikto, masscan, etc.)
    #[serde(default = "default_true")]
    pub block_scanner_uas: bool,
    /// Paths exempt from the scanner/bot User-Agent check, as regular
    /// expressions over the lowercased request path. For artefacts whose whole
    /// purpose is programmatic access — the ones a site tells people to `curl`.
    /// Injection and traversal scanning still run on them. The default covers
    /// files that exist for tools by convention; a site adds its own. These
    /// used to be compiled in, and named one site's pages.
    #[serde(default = "default_scanner_ua_exempt_paths")]
    pub scanner_ua_exempt_paths: Vec<String>,
    /// OWASP A03: OS command injection detection
    #[serde(default = "default_true")]
    pub cmd_injection: bool,
    /// OWASP A08: XML external entity detection
    #[serde(default = "default_true")]
    pub xxe: bool,
    /// OWASP A08: insecure deserialization detection (Java/PHP/Python)
    #[serde(default = "default_true")]
    pub deserialization: bool,
    /// OWASP A06: JNDI/Log4Shell and expression-language injection
    #[serde(default = "default_true")]
    pub jndi: bool,
    /// OWASP A03: server-side template injection
    #[serde(default = "default_true")]
    pub ssti: bool,
    /// Local/remote file inclusion via URL stream wrappers (php://, expect://)
    #[serde(default = "default_true")]
    pub file_inclusion: bool,
    /// CRLF injection / HTTP response splitting
    #[serde(default = "default_true")]
    pub crlf_injection: bool,
    /// JavaScript prototype pollution
    #[serde(default = "default_true")]
    pub proto_pollution: bool,
    /// GraphQL schema introspection (default false — legitimate for public schemas)
    #[serde(default)]
    pub graphql: bool,
    /// Structural request anomalies: request smuggling, header injection,
    /// diagnostic methods, malformed Host
    #[serde(default = "default_true")]
    pub request_anomaly: bool,
    /// Anomaly score at which a request is blocked (default 5).
    ///
    /// Severities contribute Low 2, Medium 5, High 8, Critical 10. At the
    /// default, any single Medium-or-higher rule blocks on its own while two
    /// Low-severity signals must agree. Raise it to require more corroboration
    /// on a route that produces false positives; lower it to act on single weak
    /// signals.
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,
    /// How many times to percent-decode an input before matching (default 3).
    ///
    /// One pass is a bypass: `%253Cscript%253E` decodes once to
    /// `%3Cscript%3E`, matches nothing, and is decoded again by the origin.
    #[serde(default = "default_max_decode_passes")]
    pub max_decode_passes: usize,
    /// Scan all request headers rather than a fixed short list (default true).
    /// Content negotiation, cache validators, client hints and credentials are
    /// always skipped.
    #[serde(default = "default_true")]
    pub scan_all_headers: bool,
    /// Maximum bytes of any single header value to scan (default 8192)
    #[serde(default = "default_max_header_scan_bytes")]
    pub max_header_scan_bytes: usize,
    /// Header count above which a request is flagged as anomalous (default 80)
    #[serde(default = "default_max_header_count")]
    pub max_header_count: usize,
    /// Per-path rule exclusions for false-positive tuning
    #[serde(default)]
    pub exclusions: Vec<WafExclusion>,
    /// Decompress Content-Encoding'd request bodies before scanning them.
    ///
    /// Without this a gzip/br/zstd/deflate request body is inspected compressed
    /// — pure entropy to the pattern engine — so a compressed `<script>` or
    /// `' OR 1=1` reaches the origin unmatched.
    #[serde(default = "default_true")]
    pub decode_compressed_body: bool,
    /// Cap on decompressed body bytes inspected (default 1 MiB), so a
    /// compression bomb cannot exhaust memory during inspection.
    #[serde(default = "default_max_decompressed_body_bytes")]
    pub max_decompressed_body_bytes: usize,
}

/// Suppress specific WAF rules or categories on paths matching a regex.
///
/// Tuning used to mean switching a whole category off globally: a single
/// false positive on one endpoint cost the protection everywhere.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafExclusion {
    /// Regex matched against the request path
    pub path: String,
    /// Rule identifiers to suppress, e.g. "PQW-NOSQL-001"
    #[serde(default)]
    pub rules: Vec<String>,
    /// Whole categories to suppress, e.g. "nosqli"
    #[serde(default)]
    pub categories: Vec<String>,
}

const fn default_anomaly_threshold() -> u32 {
    5
}

const fn default_max_decode_passes() -> usize {
    3
}

const fn default_max_header_scan_bytes() -> usize {
    8192
}

const fn default_max_header_count() -> usize {
    80
}

const fn default_max_decompressed_body_bytes() -> usize {
    1024 * 1024
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "block".to_string(),
            sqli: true,
            xss: true,
            path_traversal: true,
            nosqli: true,
            ssrf: false,
            scan_json_body: true,
            max_body_scan_bytes: 65_536,
            custom_patterns: Vec::new(),
            scanner_probe: true,
            block_scanner_uas: true,
            scanner_ua_exempt_paths: default_scanner_ua_exempt_paths(),
            cmd_injection: true,
            xxe: true,
            deserialization: true,
            jndi: true,
            ssti: true,
            file_inclusion: true,
            crlf_injection: true,
            proto_pollution: true,
            graphql: false,
            request_anomaly: true,
            anomaly_threshold: default_anomaly_threshold(),
            max_decode_passes: default_max_decode_passes(),
            scan_all_headers: true,
            max_header_scan_bytes: default_max_header_scan_bytes(),
            max_header_count: default_max_header_count(),
            exclusions: Vec::new(),
            decode_compressed_body: true,
            max_decompressed_body_bytes: default_max_decompressed_body_bytes(),
        }
    }
}

/// Whether the TLS listeners ask the client for a certificate; see
/// [`ProxyConfig::client_auth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// Not requested.
    None,
    /// Requested; a client without one still completes the handshake, and the
    /// route gate refuses it on the routes that need one.
    Requested,
    /// Required of every client at the handshake.
    Required,
}

/// Per-route security policy override
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RouteSecurityPolicy {
    /// Require mTLS for this route
    pub mtls_required: Option<bool>,
    /// Allowlisted JA3 fingerprint hashes for this route
    pub allowed_ja3: Option<Vec<String>>,
    /// Rate limit override for this route
    pub rate_limit_override: Option<RateLimitConfig>,
    /// Allow 0-RTT for this route (overrides global tls.enable_0rtt)
    pub enable_0rtt: Option<bool>,
    /// Enable WAF for this route (overrides global waf.enabled)
    pub waf_enabled: Option<bool>,
    /// WAF mode for this route: "detect" | "block"
    pub waf_mode: Option<String>,
    /// HMAC-SHA256 secret for per-request signing on this route.
    /// When set, requests must carry X-Request-Signature and X-Request-Timestamp headers.
    /// Signature = HMAC-SHA256(METHOD + "\n" + PATH + "\n" + TIMESTAMP, secret).
    /// Timestamp must be within 300 seconds of server time (replay protection).
    pub hmac_secret: Option<String>,
}

/// A single resource to preload via 103 Early Hints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreloadResourceConfig {
    /// Hostname to restrict this rule to (e.g. "stlweb.dev"). None = all hosts.
    #[serde(default)]
    pub host: Option<String>,
    /// Path that triggers this preload. By default a prefix (e.g. "/" matches
    /// all pages); with `exact = true` it must equal the request path exactly.
    pub path: String,
    /// Resource href (e.g. "/css/style.css")
    pub href: String,
    /// Link relation: "preload" (default), "modulepreload", "preconnect",
    /// "dns-prefetch" or "prerender".
    #[serde(default = "default_preload_rel")]
    pub rel: String,
    /// Resource type for the `as=` attribute (style, script, font, image, etc.).
    /// Required for `rel = "preload"`, ignored by the others.
    #[serde(default)]
    pub as_type: String,
    /// Optional crossorigin attribute value
    #[serde(default)]
    pub crossorigin: Option<String>,
    /// Match `path` exactly instead of as a prefix. Use for page-specific
    /// assets (e.g. the homepage's CSS should only preload on "/", not on
    /// every page whose path starts with "/").
    #[serde(default)]
    pub exact: bool,
}

/// HTTP/3 advanced features configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Http3Config {
    /// Enable Early Hints (103 status code)
    pub early_hints_enabled: bool,
    /// Enable Priority Hints (RFC 9218)
    pub priority_hints_enabled: bool,
    /// Enable Request Coalescing (deduplicate identical requests)
    pub coalescing_enabled: bool,
    /// Default preconnect origins for Early Hints
    pub preconnect_origins: Vec<String>,
    /// Resources to preload via 103 Early Hints.
    /// Each entry maps a path prefix to a resource. Empty = no preloads.
    pub preload_resources: Vec<PreloadResourceConfig>,
    /// Maximum wait time for coalesced requests (ms)
    pub coalescing_max_wait_ms: u64,
    /// Maximum subscribers per coalesced request
    pub coalescing_max_subscribers: usize,
    /// HTTP methods to coalesce
    pub coalescing_methods: Vec<String>,
    /// Paths to exclude from coalescing
    pub coalescing_exclude_paths: Vec<String>,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            early_hints_enabled: true,
            priority_hints_enabled: true,
            coalescing_enabled: true,
            preconnect_origins: vec![
                "https://fonts.googleapis.com".to_string(),
                "https://fonts.gstatic.com".to_string(),
            ],
            preload_resources: vec![],
            coalescing_max_wait_ms: 100,
            coalescing_max_subscribers: 100,
            coalescing_methods: vec!["GET".to_string(), "HEAD".to_string()],
            coalescing_exclude_paths: vec![
                "/api/".to_string(),
                "/ws".to_string(),
                "/stream".to_string(),
            ],
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            version: Some(CURRENT_CONFIG_VERSION),
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            pqc: PqcConfig::default(),
            waf: WafConfig::default(),
            backends: HashMap::new(),
            backend_pools: HashMap::new(),
            routes: Vec::new(),
            passthrough_routes: Vec::new(),
            admin: AdminConfig::default(),
            logging: LoggingConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            advanced_rate_limiting: AdvancedRateLimitConfig::default(),
            security: SecurityConfig::default(),
            headers: HeadersConfig::default(),
            compression: crate::compression::CompressionConfig::default(),
            http_redirect: HttpRedirectConfig::default(),
            load_balancer: LoadBalancerConfig::default(),
            fingerprint: FingerprintConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            ocsp: OcspConfig::default(),
            acme: AcmeConfig::default(),
            http3: Http3Config::default(),
            cache: ResponseCacheConfig::default(),
            otel: OtelConfig::default(),
            masque: MasqueConfig::default(),
            conformance: ConformanceConfig::default(),
        }
    }
}

/// MASQUE / CONNECT-UDP proxying configuration (RFC 9298).
///
/// When enabled, the proxy accepts HTTP/3 Extended CONNECT requests with
/// `:protocol = connect-udp` and relays UDP datagrams between the client and a
/// target `host:port`. UDP payloads travel as HTTP Datagrams (RFC 9297) bound
/// to the CONNECT request stream.
///
/// **Security:** disabled by default. An open UDP relay can be abused for
/// amplification, scanning, and exfiltration, so a target MUST match
/// `allowed_targets` before a session is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MasqueConfig {
    /// Master switch for CONNECT-UDP. Default: false.
    pub enabled: bool,

    /// Allowlist of permitted relay targets. Each entry is `host:port`, where
    /// `host` may be an exact name/IP or `*` (any host), and `port` may be an
    /// exact port or `*` (any port). A request is permitted only if it matches
    /// at least one entry. An empty list permits nothing.
    ///
    /// Examples:
    /// ```toml
    /// allowed_targets = ["dns.example.com:853", "*:443"]
    /// ```
    pub allowed_targets: Vec<String>,

    /// Per-session idle timeout in seconds. A session with no datagrams in
    /// either direction for this long is closed. Default: 60.
    pub session_idle_timeout_secs: u64,

    /// Maximum concurrent CONNECT-UDP sessions per QUIC connection. Default: 8.
    pub max_sessions_per_connection: usize,
}

impl Default for MasqueConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_targets: Vec::new(),
            session_idle_timeout_secs: 60,
            max_sessions_per_connection: 8,
        }
    }
}

/// HTTP/3 and QUIC **client** conformance suite.
///
/// Exists because we fork the QUIC stack. A conformance service has to make the
/// server misbehave on demand — GREASE frames, reserved stream types, deliberate
/// protocol violations — which is not something a CDN customer or cloud tenant
/// can arrange. The client under test connects, the server emits the anomaly,
/// and the server records whether the client tolerated it.
///
/// **Every test owns a UDP port** from [`port_range`](Self::port_range), and the
/// listener knows which test it is serving from its own `local_addr()`.
///
/// Selecting by URL path was the original design, kept for the HTTP/3-layer
/// tests while the QUIC-layer ones took ports of their own. It did not survive:
/// reading a path means QPACK-decoding the client's request, and the `h3` crate
/// exposes no way to inject an arbitrary frame into a response it is managing.
/// Owning the connection from its first packet avoids the decoder entirely, so
/// the split went away and every test now selects the same way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConformanceConfig {
    /// Master switch. Default: false — this deliberately serves malformed
    /// protocol output and must never come up by accident on a normal vhost.
    pub enabled: bool,

    /// Hostname serving the catalogue, the reports and the badge. Requests for
    /// any other host are handled normally, so a misrouted request cannot land
    /// on a test — and this vhost does not select tests either, which is what
    /// the per-test ports are for.
    pub host: String,

    /// Inclusive UDP port range, one port per test. Must not overlap
    /// `server.udp_port` or `server.additional_ports`; startup refuses to bind
    /// if it does, and refuses just as firmly if the range is too narrow for the
    /// catalogue rather than quietly serving the tests that fit.
    ///
    /// Sized with headroom on purpose. Widening it later means a firewall change
    /// on every node before the new ports are reachable, and a test nobody
    /// outside can connect to reports nothing at all.
    pub port_range: (u16, u16),

    /// How long a session's verdicts are retained before expiry, in seconds.
    /// A session is a single client's walk through the catalogue. Default: 3600.
    pub session_ttl_secs: u64,

    /// Maximum concurrent sessions. Each holds a small verdict map; the cap
    /// exists so an unauthenticated public endpoint cannot be used to grow
    /// memory without bound. Default: 512.
    pub max_sessions: usize,

    /// How long to wait for the liveness probe that follows every test, in
    /// milliseconds.
    ///
    /// The probe is what makes a verdict meaningful: after the anomaly the
    /// server expects one ordinary request on the same connection. Without it,
    /// "ignored correctly" and "crashed" look identical from here.
    ///
    /// Arrival is evidence the client got through the anomaly. Silence is not
    /// the opposite of that: a client can reject an anomaly correctly and have
    /// the close go missing, so a probe that never comes is judged against what
    /// the test was measuring rather than read as acceptance. Default: 5000.
    pub liveness_timeout_ms: u64,

    /// The certificate chain `t-cert-compression-pq` serves, PEM, leaf first.
    ///
    /// ML-DSA-87 throughout, and deliberately not the showcase chain /pqc/
    /// publishes. That one is an SLH-DSA-SHA2-256s root over ML-DSA-87
    /// intermediates, and verifying it needs two post-quantum signature
    /// families, which nothing in the client fleet has: the clients that passed
    /// against it reached the end with certificate verification disabled. The
    /// test asks whether a client can process a compressed ML-DSA-87
    /// certificate message, and the CA's family is incidental to that, so the
    /// fixture is one family and a client with ML-DSA-87 can verify it rather
    /// than skip it.
    ///
    /// Issued by a private CA on purpose -- see the catalogue entry for why
    /// being untrusted is what makes the measurement work. The verdicts quote
    /// the chain's size as loaded from here, so replacing the file changes
    /// what they say. Default: `/etc/pqcrypta/pqc-certs/conformance/fullchain.pem`.
    pub pq_chain_cert: PathBuf,

    /// The private key for [`pq_chain_cert`](Self::pq_chain_cert).
    /// Default: `/etc/pqcrypta/pqc-certs/conformance/server.key`.
    pub pq_chain_key: PathBuf,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: "conformance.pqcrypta.com".to_string(),
            port_range: (4460, 4600),
            session_ttl_secs: 3600,
            max_sessions: 512,
            liveness_timeout_ms: 5000,
            pq_chain_cert: PathBuf::from("/etc/pqcrypta/pqc-certs/conformance/fullchain.pem"),
            pq_chain_key: PathBuf::from("/etc/pqcrypta/pqc-certs/conformance/server.key"),
        }
    }
}

impl MasqueConfig {
    /// Returns true if the given target host/port is permitted by the allowlist.
    pub fn is_target_allowed(&self, host: &str, port: u16) -> bool {
        self.allowed_targets.iter().any(|entry| {
            let Some((h, p)) = entry.rsplit_once(':') else {
                return false;
            };
            let host_ok = h == "*" || h.eq_ignore_ascii_case(host);
            let port_ok = p == "*" || p.parse::<u16>().map(|v| v == port).unwrap_or(false);
            host_ok && port_ok
        })
    }
}

/// Server bind configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address for QUIC listener (default: 0.0.0.0)
    pub bind_address: String,
    /// Primary UDP port for QUIC/HTTP3/WebTransport (default: 443)
    pub udp_port: u16,
    /// Additional ports for WebTransport (e.g., [4433, 4434])
    #[serde(default)]
    pub additional_ports: Vec<u16>,
    /// The UDP ports to advertise in Alt-Svc, when that is not simply every port
    /// the proxy binds.
    ///
    /// Binding a UDP port is not the same as serving HTTP/3 on it, and only the
    /// operator knows the difference:
    ///
    ///   * on the mail host, inbound UDP/443 is filtered by the provider and never
    ///     reaches the machine — the proxy binds it, logs a clean QUIC start, and no
    ///     datagram ever arrives
    ///   * on the Midwest speedtest node, UDP/4433 is deliberately the WebTransport
    ///     endpoint, so a plain HTTP/3 request there is answered by the WebTransport
    ///     server and gets no response headers
    ///
    /// In both cases the derived value advertised HTTP/3 on a port a browser cannot
    /// use, which costs every visitor a QUIC attempt that can only time out before
    /// it falls back to TCP. Set this to the ports that actually answer.
    ///
    /// `None` keeps the derived behaviour (this listener's port plus
    /// `additional_ports`); an empty list advertises no HTTP/3 at all, which is the
    /// truthful value for a node that serves none.
    #[serde(default)]
    pub alt_svc_ports: Option<Vec<u16>>,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Maximum concurrent BIDIRECTIONAL streams per connection (HTTP/3 requests).
    pub max_streams_per_connection: u32,
    /// Maximum concurrent UNIDIRECTIONAL streams per connection.
    ///
    /// Split out from `max_streams_per_connection`, which drove both directions.
    /// HTTP/3 needs exactly three unidirectional streams — the control stream and
    /// the two QPACK streams — and a WebTransport session opens a handful more.
    /// Advertising the bidirectional figure here told every peer it could open a
    /// thousand, each with its own per-stream receive window and stream state, for
    /// a capability nothing uses. HAProxy advertises 3 here; 100 leaves generous
    /// WebTransport headroom while dropping the advertised ceiling tenfold.
    #[serde(default = "default_max_uni_streams")]
    pub max_uni_streams_per_connection: u32,
    /// Keep-alive interval in seconds
    pub keepalive_interval_secs: u64,
    /// Maximum idle timeout in seconds
    pub max_idle_timeout_secs: u64,
    /// Enable IPv6 dual-stack binding
    pub enable_ipv6: bool,
    /// Worker threads (0 = auto-detect)
    pub worker_threads: usize,
    /// Graceful shutdown drain timeout in seconds (AUD-11).
    /// After receiving a shutdown signal the proxy waits up to this many seconds
    /// for in-flight requests to complete before exiting.
    /// Should not exceed systemd TimeoutStopSec (default 30 s).
    pub graceful_shutdown_timeout_secs: u64,
    /// SR-02: Allowed Origin values for incoming WebTransport sessions.
    ///
    /// WebTransport sessions carry an HTTP `Origin` header from the browser.
    /// Any session whose `Origin` is not in this list is rejected with 403 to
    /// prevent cross-origin abuse from arbitrary web pages.
    ///
    /// Set to your frontend origin(s), e.g.:
    /// ```toml
    /// webtransport_allowed_origins = ["https://pqcrypta.com"]
    /// ```
    ///
    /// An empty list (the default) rejects ALL cross-origin sessions.
    /// Sessions without an `Origin` header (non-browser clients) are always
    /// accepted when the list is empty; if the list is non-empty they must
    /// match one of the listed origins.
    #[serde(default)]
    pub webtransport_allowed_origins: Vec<String>,

    /// Optional override for the maximum request body size, in bytes.
    ///
    /// The enforced limit lives in `security.max_request_size`; this is the
    /// server-side name for the same thing and was previously read by nothing,
    /// so setting it did not change what was accepted. It is now an Option so
    /// "not configured" is distinguishable from a default that would otherwise
    /// silently lower an explicitly configured security limit — when set, it
    /// replaces `security.max_request_size` at load time.
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,

    /// Enable QUIC connection migration (RFC 9000 §9).
    /// Allows clients to migrate to a new network path without losing the session.
    /// Default: true (enabled — Quinn default behaviour).
    #[serde(default = "default_true")]
    pub enable_quic_migration: bool,

    /// Enable the QUIC ACK Frequency extension (draft-ietf-quic-ack-frequency).
    ///
    /// Lets the peer request fewer, batched acknowledgements, cutting ACK
    /// traffic and CPU on high-throughput connections (bulk download/upload,
    /// speedtest). Only takes effect when the peer also negotiates the
    /// extension, so enabling it is safe for clients that do not support it.
    /// Default: true.
    #[serde(default = "default_true")]
    pub enable_ack_frequency: bool,

    /// How many ack-eliciting QUIC packets to accept before sending an
    /// ACK-only packet.
    ///
    /// An ACK-only packet goes out once the count *exceeds* this; 1 — RFC 9000's
    /// "acknowledge every other packet" — is the default. Below it, an owed ACK
    /// rides on the next packet sent for any other reason (`ack_piggyback`), so
    /// a lone request is acknowledged by its own response rather than waiting.
    ///
    /// This was 0 before piggybacking existed, because without it a lone request
    /// was not acknowledged until `max_ack_delay` (25 ms) expired and the client
    /// would not start its next request until it was — 384 req/s at one stream.
    /// 0 fixed that by sending a separate ACK for every request, which at a
    /// hundred connections was 0.64 extra datagrams per request. With
    /// piggybacking, measured on one machine, HTTP/3, interleaved:
    ///
    /// | cell | threshold 0 | threshold 1 |
    /// |---|---|---|
    /// | 1 KB, 10 connections × 1 stream | 11,392 req/s | 13,171 req/s |
    /// | empty, 10 × 10 | 21,063 | 21,286 |
    /// | empty, 100 × 10 | 12,289 | 13,404 |
    ///
    /// Set 0 to acknowledge every packet immediately regardless.
    #[serde(default = "default_ack_eliciting_threshold")]
    pub ack_eliciting_threshold: u64,

    /// Carry owed QUIC ACKs on packets that are being sent anyway (default: true).
    ///
    /// Without it an acknowledgement below `ack_eliciting_threshold` is not
    /// sent until the threshold is crossed or `max_ack_delay` expires, even
    /// when a response packet is leaving with room for it — so the response
    /// arrives without acknowledging the request it answers. With it the ACK
    /// rides on that packet, and `ack_eliciting_threshold` only decides when a
    /// separate ACK-only packet is worth sending.
    #[serde(default = "default_true")]
    pub ack_piggyback: bool,

    /// Let other ready work run before a QUIC connection transmits (default: true).
    ///
    /// Each response written to a connection wakes its driver, which otherwise
    /// sends at once — one packet per response, and the client answers each
    /// with one of its own. With this the driver yields once first, so every
    /// response already finishing on that connection leaves in the same
    /// transmit: the flush-once-per-turn an event-loop server does by
    /// construction.
    ///
    /// Measured on one machine, HTTP/3, empty body, a hundred connections of
    /// ten streams: 13,540 req/s without it, 19,528 with it, and datagrams per
    /// request from 2.08 to about 1.3 — on the same machine HAProxy's event
    /// loop sends 0.31. At ten connections and at one stream per connection it
    /// measured level: there is less finishing together to coalesce.
    #[serde(default = "default_true")]
    pub quic_send_coalescing: bool,

    /// Set `TCP_NODELAY` on accepted client-facing sockets (default: true).
    ///
    /// With Nagle left on, the kernel refuses to put a short segment on the
    /// wire while earlier data is unacknowledged. A proxy writes a response and
    /// then waits, so the peer has nothing to piggyback an acknowledgement on
    /// and its delayed-ACK timer — 40 ms on Linux — has to expire first. That
    /// was measured here as a flat 41.7 ms on every HTTP/2 request at a 1 KB
    /// body, and 41.9 ms at 64 KB with a single stream in flight.
    ///
    /// Disabling this restores Nagle's coalescing. Whether that buys measurable
    /// throughput on large bodies is being measured and is NOT yet established
    /// — a pooled matrix suggested it at 64 KB, inside the run-to-run spread,
    /// which is a hypothesis rather than a result. The default stays `true`
    /// regardless: a 40 ms per-request stall is not a trade worth making for
    /// anything interactive.
    #[serde(default = "default_tcp_nodelay")]
    pub tcp_nodelay: bool,

    /// Coalesce received UDP datagrams with the kernel's UDP_GRO.
    ///
    /// Off by default, and that is a correctness choice with a throughput
    /// cost attached. Measured 2026-09-21, four trials each way against our
    /// own conformance suite: with GRO the receiver saw 1 ECN-marked datagram
    /// per connection, without it 12 to 19. The kernel does not deliver the
    /// IP_TOS control message for most coalesced batches, so the markings are
    /// absent rather than undercounted.
    ///
    /// That matters more as a server than as a client. An endpoint reporting
    /// fewer ECT(0) than its peer sent fails that peer's ECN validation
    /// (RFC 9000 §13.4.2), and the peer then disables ECN for the path -- so
    /// every client marking toward this proxy was being told the path was
    /// broken. Silently degrading every peer's congestion control is a worse
    /// trade than spending some receive-side CPU.
    ///
    /// Turn it back on if inbound volume ever makes it pay: GRO helps where
    /// many datagrams from one flow arrive together, which is bulk upload,
    /// not the small requests and acknowledgements a content site receives.
    /// There was no h3 inbound traffic at all in a 45-second capture when
    /// this was decided, so the cost could not be measured -- and the
    /// benchmark rig drives HTTP/2 over TCP, which never touches this path.
    #[serde(default)]
    pub udp_gro: bool,

    /// Enable QUIC Retry for explicit address validation (RFC 9000 §8.1.2).
    ///
    /// When enabled, a new connection whose source address has not yet been
    /// validated is answered with a Retry packet carrying a token; the client
    /// must re-send its Initial echoing that token before the handshake
    /// proceeds. This proves the client controls the address it claims,
    /// hardening the server against spoofed-source amplification/DDoS - at the
    /// cost of ONE extra round trip on every new connection. When disabled
    /// (the default), the server relies on RFC 9000's implicit validation via
    /// the 3x anti-amplification limit, which most production QUIC servers use
    /// and which adds no per-connection latency.
    /// Default: false.
    #[serde(default)]
    pub enable_quic_retry: bool,

    /// Maximum concurrent data-carrying paths per connection
    /// (draft-ietf-quic-multipath), served by the noq QUIC stack.
    ///
    /// The full extension is implemented — per-path packet-number spaces,
    /// PATH_ACK/ABANDON/STATUS lifecycle frames, per-path loss recovery and a
    /// scheduler — and paths are created, validated and torn down
    /// automatically once the peer negotiates multipath. Peers that do not
    /// advertise it are unaffected whatever this is set to.
    ///
    /// 1 leaves every connection single-path; 0 disables the extension so it
    /// is never negotiated. Default: 4.
    #[serde(default = "default_multipath_paths")]
    pub max_concurrent_multipath_paths: u32,

    /// Maximum concurrent WebTransport sessions per origin (default 100).
    #[serde(default = "default_wt_max_sessions")]
    pub webtransport_max_sessions_per_origin: u32,

    /// Maximum concurrent streams per WebTransport session (default 1000).
    #[serde(default = "default_wt_max_streams")]
    pub webtransport_max_streams_per_session: u32,

    /// Maximum datagrams per second per WebTransport session (default 500).
    #[serde(default = "default_wt_max_datagrams")]
    pub webtransport_max_datagrams_per_sec: u32,

    /// UDP port reserved for the dedicated WebTransport server (default 4433).
    ///
    /// P3-fix: previously hardcoded as the literal `4433` in main.rs.  This
    /// port is skipped in the generic QUIC listener loop and handed to the
    /// wtransport-based WebTransportServer instead.  Must be listed in
    /// `additional_ports` (or be the primary `udp_port`) for the Alt-Svc
    /// advertisement to include it.
    #[serde(default = "default_webtransport_port")]
    pub webtransport_port: u16,

    /// Hosts that must never advertise HTTP/3 upgrade.
    ///
    /// When a request arrives from one of these hostnames, the proxy sends
    /// `Alt-Svc: clear` instead of an h3 advertisement, actively evicting any
    /// cached Alt-Svc in the browser so it always connects via TCP/TLS.
    ///
    /// Example — a dedicated TCP-only speedtest subdomain:
    /// ```toml
    /// tcp_only_hosts = ["tcp.pqcrypta.com"]
    /// ```
    #[serde(default)]
    pub tcp_only_hosts: Vec<String>,

    /// Value of the `Server` header on every response (SEC-08: product name,
    /// no version). An empty string leaves the backend's own `Server` header in
    /// place on proxied responses and sends none on the proxy's own — the
    /// pass-through HAProxy and NGINX do by default, which discloses whatever
    /// the backend advertises.
    #[serde(default = "default_server_header")]
    pub server_header: String,

    /// Header carrying a per-request ID to the backend and back to the client
    /// (e.g. "x-request-id"). A sane client-supplied ID is kept; otherwise
    /// 128 random bits are minted as hex. Empty (the default) turns it off.
    #[serde(default)]
    pub request_id_header: String,

    /// Load balancers allowed to send a PROXY protocol header (v1 or v2). A
    /// connection from one of these must open with it, and the address it
    /// names becomes the client address; from anyone else no header is read.
    /// Empty (the default) accepts no PROXY headers.
    #[serde(default)]
    pub proxy_protocol_trusted: Vec<ipnet::IpNet>,

    /// How long a trusted peer has to send its PROXY header.
    #[serde(default = "default_proxy_protocol_timeout_ms")]
    pub proxy_protocol_timeout_ms: u64,

    /// `ma` (max-age, seconds) on every Alt-Svc alternative the proxy advertises.
    #[serde(default = "default_alt_svc_max_age_secs")]
    pub alt_svc_max_age_secs: u64,

    /// Clients that get `Alt-Svc: clear` instead of an HTTP/3 advertisement on
    /// TCP, by source network. Defaults to Cloudflare's published ranges:
    /// Cloudflare Radar / URLScan fetch with a generic Chrome UA, so they can
    /// only be recognised by address, and they fail on a QUIC upgrade.
    #[serde(default = "default_alt_svc_clear_cidrs")]
    pub alt_svc_clear_cidrs: Vec<ipnet::IpNet>,

    /// Clients that get `Alt-Svc: clear`, by case-insensitive User-Agent
    /// substring. Defaults to the search-engine crawlers and TLS scanners that
    /// either fail on QUIC or record empty MIME types after upgrading.
    #[serde(default = "default_alt_svc_clear_user_agents")]
    pub alt_svc_clear_user_agents: Vec<String>,

    /// Hosts that must negotiate HTTP/1.1 only — `h2` is NOT included in the
    /// ALPN list for these SNI names.
    ///
    /// When a browser connects to one of these hosts it cannot coalesce all
    /// `fetch()` streams into a single HTTP/2 connection.  Instead, each stream
    /// opens an independent TCP connection (up to the browser's 6-per-origin
    /// HTTP/1.1 limit), which eliminates head-of-line blocking across parallel
    /// speed test streams.
    ///
    /// Example:
    /// ```toml
    /// http11_only_hosts = ["tcp.pqcrypta.com"]
    /// ```
    #[serde(default)]
    pub http11_only_hosts: Vec<String>,

    /// Explicit TLS certificate for the WebTransport server (port 4433).
    ///
    /// When set, overrides the auto-detection logic that looks for
    /// `api.{primary_domain}.crt` in the certs directory.  Use this when
    /// the WebTransport hostname doesn't follow the `api.` prefix convention
    /// (e.g. `api2.pqcrypta.com` served from a `tcp2.pqcrypta.com` config).
    ///
    /// Example:
    /// ```toml
    /// webtransport_cert_path = "/etc/pqcrypta/certs/api2.pqcrypta.com.crt"
    /// webtransport_key_path  = "/etc/pqcrypta/certs/api2.pqcrypta.com.key"
    /// ```
    #[serde(default)]
    pub webtransport_cert_path: Option<std::path::PathBuf>,

    #[serde(default)]
    pub webtransport_key_path: Option<std::path::PathBuf>,

    /// Lowercase request paths before route matching and before forwarding to backends.
    ///
    /// When `true` (default) all incoming paths are lowercased, mirroring the
    /// historical behaviour of the proxy and the Apache `RewriteMap tolower`
    /// pattern used on most hosted sites.
    ///
    /// Set to `false` for backends that have case-sensitive URL paths (e.g.
    /// REST APIs, AI chat endpoints, PHP apps that use mixed-case slugs).
    ///
    /// Route matching remains case-insensitive regardless of this setting —
    /// only the path forwarded to the backend is affected.
    ///
    /// ```toml
    /// normalize_paths = false
    /// ```
    #[serde(default = "default_true")]
    pub normalize_paths: bool,
}

impl ServerConfig {
    /// Bind address to actually listen on.
    ///
    /// `enable_ipv6 = false` downgrades a dual-stack `[::]` bind to IPv4-only,
    /// which is what the setting has always claimed to do — until now nothing
    /// read it, so the only thing that decided address family was the literal
    /// in `bind_address`. An explicitly non-wildcard IPv6 address is left alone
    /// and warned about, since silently rewriting an operator's chosen address
    /// would be worse than honouring it.
    pub fn effective_bind_address(&self) -> String {
        if self.enable_ipv6 {
            return self.bind_address.clone();
        }
        match self.bind_address.as_str() {
            "[::]" | "::" => {
                tracing::info!(
                    "enable_ipv6 = false: binding 0.0.0.0 instead of {}",
                    self.bind_address
                );
                "0.0.0.0".to_string()
            }
            addr if addr.starts_with('[') => {
                tracing::warn!(
                    "enable_ipv6 = false but bind_address is {} — honouring the explicit address",
                    addr
                );
                addr.to_string()
            }
            addr => addr.to_string(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            udp_port: 443,
            additional_ports: vec![4433, 4434],
            alt_svc_ports: None,
            max_connections: 10000,
            max_streams_per_connection: 1000,
            max_uni_streams_per_connection: default_max_uni_streams(),
            keepalive_interval_secs: 15,
            max_idle_timeout_secs: 120,
            enable_ipv6: true,
            worker_threads: 0,
            graceful_shutdown_timeout_secs: 30,
            // SR-02: Empty by default — all cross-origin sessions are rejected
            // until the operator explicitly lists allowed origins.
            webtransport_allowed_origins: Vec::new(),
            max_request_body_bytes: None,
            enable_quic_migration: true,
            enable_ack_frequency: true,
            ack_eliciting_threshold: default_ack_eliciting_threshold(),
            ack_piggyback: true,
            quic_send_coalescing: true,
            tcp_nodelay: default_tcp_nodelay(),
            udp_gro: false,
            enable_quic_retry: false,
            max_concurrent_multipath_paths: 4,
            webtransport_max_sessions_per_origin: 100,
            webtransport_max_streams_per_session: 1000,
            webtransport_max_datagrams_per_sec: 500,
            webtransport_port: 4433,
            tcp_only_hosts: Vec::new(),
            server_header: default_server_header(),
            request_id_header: String::new(),
            proxy_protocol_trusted: Vec::new(),
            proxy_protocol_timeout_ms: default_proxy_protocol_timeout_ms(),
            alt_svc_max_age_secs: default_alt_svc_max_age_secs(),
            alt_svc_clear_cidrs: default_alt_svc_clear_cidrs(),
            alt_svc_clear_user_agents: default_alt_svc_clear_user_agents(),
            http11_only_hosts: Vec::new(),
            webtransport_cert_path: None,
            webtransport_key_path: None,
            normalize_paths: true,
        }
    }
}

/// Parse a configuration, returning it with every key serde discarded.
///
/// `ProxyConfig` does not deny unknown fields — a node may carry a key a newer
/// or older binary does not know — so a misspelt or invented key used to be
/// dropped without a word, and the setting the operator thought they had made
/// silently did not exist. The paths are reported instead.
pub fn parse_config_str(content: &str) -> Result<(ProxyConfig, Vec<String>), toml::de::Error> {
    let mut ignored = Vec::new();
    let config = serde_ignored::deserialize(toml::Deserializer::new(content), |path| {
        ignored.push(path.to_string());
    })?;
    Ok((config, ignored))
}

fn warn_ignored_keys(path: &Path, ignored: &[String]) {
    for key in ignored {
        warn!(
            "{}: `{}` is not a configuration setting and was ignored",
            path.display(),
            key
        );
    }
}

fn default_scanner_ua_exempt_paths() -> Vec<String> {
    [
        r"^/robots\.txt$",
        r"^/sitemap\.xml$",
        r"^/llms\.txt$",
        r"^/\.well-known/",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn default_preload_rel() -> String {
    "preload".to_string()
}

fn default_observed_fingerprints_path() -> Option<PathBuf> {
    Some(PathBuf::from(
        "/var/lib/pqcrypta-proxy/fingerprints/observed.json",
    ))
}

fn default_access_log_format() -> String {
    "combined".to_string()
}

fn default_proxy_protocol_timeout_ms() -> u64 {
    3000
}

fn default_server_header() -> String {
    "pqcrypta".to_string()
}

fn default_alt_svc_max_age_secs() -> u64 {
    86400
}

fn default_alt_svc_clear_cidrs() -> Vec<ipnet::IpNet> {
    // https://www.cloudflare.com/ips/
    [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]
    .iter()
    .filter_map(|c| c.parse().ok())
    .collect()
}

fn default_alt_svc_clear_user_agents() -> Vec<String> {
    [
        "googlebot",
        "adsbot-google",
        "google-inspectiontool",
        "googleother",
        "bingbot",
        "msnbot",
        "yandexbot",
        "baiduspider",
        "duckduckbot",
        "slurp",
        "applebot",
        "semrushbot",
        "ahrefsbot",
        "dotbot",
        "sogou",
        "exabot",
        "facebot",
        "ia_archiver",
        "ssllabs",
        "qualys",
        "ssl-pulse",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn default_max_uni_streams() -> u32 {
    100
}

/// ACK-only packets for every other ack-eliciting packet; owed ACKs otherwise
/// ride on outgoing data. See [`ServerConfig::ack_eliciting_threshold`] for the
/// measurement behind this.
fn default_ack_eliciting_threshold() -> u64 {
    1
}

/// Nagle off on accepted sockets. See [`ServerConfig::tcp_nodelay`].
fn default_tcp_nodelay() -> bool {
    true
}

fn default_multipath_paths() -> u32 {
    4
}

fn default_wt_max_sessions() -> u32 {
    100
}

fn default_wt_max_streams() -> u32 {
    1000
}

fn default_webtransport_port() -> u16 {
    4433
}

fn default_wt_max_datagrams() -> u32 {
    500
}

impl ServerConfig {
    /// Get the full socket address
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.bind_address, self.udp_port).parse()
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Path to TLS certificate (PEM format)
    pub cert_path: PathBuf,
    /// Path to TLS private key (PEM format)
    pub key_path: PathBuf,
    /// Optional CA certificate for client verification (mTLS)
    pub ca_cert_path: Option<PathBuf>,
    /// Require client certificates (mTLS)
    pub require_client_cert: bool,
    /// ALPN protocols to advertise
    pub alpn_protocols: Vec<String>,
    /// Minimum TLS version (1.2 or 1.3)
    pub min_version: String,
    /// Enable OCSP stapling
    pub ocsp_stapling: bool,
    /// Certificate reload interval in seconds (0 = disabled)
    pub cert_reload_interval_secs: u64,
    /// Enable 0-RTT (early data) - SECURITY WARNING: vulnerable to replay attacks.
    /// Default: false (disabled for security).
    ///
    /// When enabled, TLS 0-RTT early data is forwarded to backends WITHOUT replay
    /// detection. Only enable on routes where ALL of the following are true:
    ///
    /// 1. The HTTP method is idempotent (GET or HEAD)
    /// 2. The backend handles duplicate requests safely
    /// 3. The route has `allow_0rtt = true` set explicitly
    ///
    /// Use `zero_rtt_safe_methods` to declare which HTTP methods may use early data.
    pub enable_0rtt: bool,

    /// L-5: HTTP methods that are safe to forward via 0-RTT early data.
    /// Defaults to `["GET", "HEAD"]` (the only idempotent, side-effect-free methods).
    /// POST, PUT, DELETE, PATCH and others must NOT appear here unless the backend
    /// implements idempotency-key-based deduplication.
    #[serde(default = "default_zero_rtt_safe_methods")]
    pub zero_rtt_safe_methods: Vec<String>,

    /// 0-RTT replay protection mode: "strict" | "session" | "none" — default "strict".
    /// - "strict": nonce tracked globally; duplicate nonces rejected with 425.
    /// - "session": nonce tracked per TLS session only.
    /// - "none": no replay protection (not recommended).
    #[serde(default = "default_zero_rtt_replay_protection")]
    pub zero_rtt_replay_protection: String,

    /// Time window (seconds) for 0-RTT nonce tracking (default 60).
    #[serde(default = "default_zero_rtt_nonce_window")]
    pub zero_rtt_nonce_window_secs: u64,

    /// Issue TLS 1.3 session tickets sealed with ML-KEM-1024 (FIPS 203).
    ///
    /// rustls installs no ticketer by default, so with this off the proxy
    /// issues no tickets and resumption relies on rustls session storage. When
    /// on, each ticket carries its own ML-KEM encapsulation and the resumption
    /// state is sealed with an AES-256-GCM key derived from that encapsulation;
    /// the keypair rolls every `session_ticket_lifetime_secs` with one
    /// generation of overlap. Default: false.
    #[serde(default)]
    pub pqc_session_tickets: bool,

    /// Ticket key lifetime in seconds; also the lifetime hint sent to clients.
    /// Rotation is what bounds the damage a stolen ticket can do, so this is a
    /// forward-secrecy control rather than a tuning knob. Default 43200 (12 h).
    #[serde(default = "default_session_ticket_lifetime")]
    pub session_ticket_lifetime_secs: u32,

    /// RFC 8879 certificate compression: `"auto"` (default) or `"off"`.
    ///
    /// `auto` offers whatever the compiled TLS stack can actually produce —
    /// zlib on the OpenSSL side, brotli or zlib on rustls for QUIC and HTTP/3 —
    /// and `off` sends an uncompressed chain on both. The semantics match
    /// HAProxy's `tune.ssl.certificate-compression`, which is the closest thing
    /// to a convention here; nginx spells the same idea
    /// `ssl_certificate_compression on|off` but defaults it to off.
    ///
    /// Default `auto` rather than `off` because the saving is real and costs
    /// only CPU: 1,051 bytes off every full handshake on this chain, which is
    /// most of what the X25519MLKEM768 key share adds.
    ///
    /// Takes effect at restart, not on config reload: both stacks bake the
    /// answer into the TLS context when it is built rather than consulting it
    /// per handshake, so a reloaded value would not reach the live listeners.
    #[serde(default = "default_certificate_compression")]
    pub certificate_compression: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("/etc/pqcrypta/cert.pem"),
            key_path: PathBuf::from("/etc/pqcrypta/key.pem"),
            ca_cert_path: None,
            require_client_cert: false,
            alpn_protocols: vec![
                "h3".to_string(),
                "h2".to_string(),
                "http/1.1".to_string(),
                "webtransport".to_string(),
            ],
            min_version: "1.3".to_string(),
            ocsp_stapling: true,
            cert_reload_interval_secs: 3600,
            enable_0rtt: false, // Disabled by default for security (replay attack risk)
            zero_rtt_safe_methods: default_zero_rtt_safe_methods(),
            zero_rtt_replay_protection: default_zero_rtt_replay_protection(),
            zero_rtt_nonce_window_secs: default_zero_rtt_nonce_window(),
            pqc_session_tickets: false,
            session_ticket_lifetime_secs: default_session_ticket_lifetime(),
            certificate_compression: default_certificate_compression(),
        }
    }
}

fn default_zero_rtt_replay_protection() -> String {
    "strict".to_string()
}

fn default_session_ticket_lifetime() -> u32 {
    43_200 // 12 hours
}

/// Follow the TLS library, as HAProxy's `auto` does.
fn default_certificate_compression() -> String {
    "auto".to_string()
}

fn default_zero_rtt_nonce_window() -> u64 {
    60
}

fn default_zero_rtt_safe_methods() -> Vec<String> {
    // L-5: Only GET and HEAD are safe for 0-RTT early data by default.
    // These are the only idempotent, side-effect-free HTTP methods.
    vec!["GET".to_string(), "HEAD".to_string()]
}

/// Post-quantum cryptography configuration
///
/// Supports both TLS backends:
/// - **rustls** (default): Pure Rust, memory-safe, QUIC support, uses aws-lc-rs
/// - **OpenSSL 3.5+**: Broader algorithm support, hardware acceleration
///
/// ## Algorithm Support
///
/// | Algorithm | rustls | OpenSSL 3.5+ |
/// |-----------|--------|--------------|
/// | X25519MLKEM768 | ✅ | ✅ |
/// | SecP256r1MLKEM768 | ⏳ | ✅ |
/// | SecP384r1MLKEM1024 | ⏳ | ✅ |
/// | ML-KEM-512/768/1024 | ✅ | ✅ |
/// | ML-DSA-44/65/87 | 🔧 | ✅ |
///
/// ✅ = Available, ⏳ = Planned, 🔧 = Requires `pqc-signatures` feature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PqcConfig {
    /// Enable PQC hybrid key exchange
    pub enabled: bool,
    /// Refuse to start unless a post-quantum key exchange is *verified* at startup.
    ///
    /// `enabled` asks for PQC; this insists on it. When true, the proxy performs an
    /// in-memory TLS 1.3 handshake against its own provider during startup and exits
    /// non-zero unless the negotiated group is a post-quantum hybrid — including when
    /// the handshake could not be completed at all, because "we could not check" is not
    /// grounds to claim a post-quantum boundary.
    ///
    /// Defaults to false so an existing deployment keeps its current behaviour on
    /// upgrade. An operator who is selling PQC as the security property wants it true.
    #[serde(default)]
    pub required: bool,
    /// PQC provider: "auto", "rustls", or "openssl3.5"
    /// - "auto" (default): Use rustls for QUIC, OpenSSL when broader algorithms needed
    /// - "rustls": Pure Rust via aws-lc-rs (memory-safe, QUIC support)
    /// - "openssl3.5": OpenSSL 3.5+ with native ML-KEM (broader algorithms)
    pub provider: String,
    /// OpenSSL binary path (for OpenSSL 3.5+ with native ML-KEM)
    pub openssl_path: Option<PathBuf>,
    /// OpenSSL library path
    pub openssl_lib_path: Option<PathBuf>,
    /// Preferred KEM algorithm for key exchange
    pub preferred_kem: String,
    /// Offer a classical key-exchange group (P-384) alongside the hybrid PQC
    /// groups, so a client with no ML-KEM support can still complete a
    /// handshake. This is a CLIENT COMPATIBILITY switch, not a statement about
    /// our own posture: with it off, such clients cannot connect at all.
    ///
    /// Measured on this deployment before the split: system curl built against
    /// quictls 3.1.4 has no ML-KEM and reaches the site over P-384, as do
    /// third-party monitoring and several crawlers. Turning this off is a live
    /// lockout, which is why it no longer also governs startup strictness —
    /// see `require_pqc_provider`.
    pub fallback_to_classical: bool,
    /// Refuse to start when PQC is enabled but its provider cannot be used,
    /// instead of degrading to a classical-only listener with a warning.
    ///
    /// Split out of `fallback_to_classical`, which conflated two unrelated
    /// decisions: what we offer CLIENTS, and what we do when our OWN crypto is
    /// broken. An operator wanting to fail closed on the second had to accept a
    /// client lockout as the price, so in practice nobody did.
    #[serde(default = "default_require_pqc_provider")]
    pub require_pqc_provider: bool,
    /// Minimum security level (1-5, corresponding to NIST levels)
    /// - 1: 128-bit (ML-KEM-512)
    /// - 3: 192-bit (X25519MLKEM768, ML-KEM-768) - recommended
    /// - 5: 256-bit (ML-KEM-1024, SecP384r1MLKEM1024)
    #[serde(default = "default_min_security_level")]
    pub min_security_level: u8,
    /// Additional KEM algorithms to offer (in preference order)
    #[serde(default)]
    pub additional_kems: Vec<String>,
    /// PQC downgrade action: "allow" | "log" | "block" — default "log".
    /// "block" rejects connections that negotiate classical-only KEM when PQC is enabled.
    #[serde(default = "default_downgrade_action")]
    pub downgrade_action: String,

    /// Log PQC downgrade events (default true).
    #[serde(default = "default_true_pqc")]
    pub log_downgrades: bool,

    /// Serve ML-DSA-87 (FIPS 204) certificate keys.
    ///
    /// When a loaded key is an ML-DSA-87 PKCS#8 key, it is signed with the
    /// dedicated PQDSA signer (TLS signature scheme 0x0906) rather than the
    /// provider's key loader, which cannot handle it. Setting this false makes
    /// the proxy refuse such keys instead, so a host configured with an ML-DSA
    /// certificate stops serving rather than silently falling back.
    /// Requires the `pqc-signatures` build feature. Default: true.
    #[serde(default = "default_true_pqc")]
    pub enable_signatures: bool,

    /// Require every offered key-exchange group to be hybrid (classical + PQC).
    ///
    /// Suppresses the pure-PQC preferred KEM and the classical P-384 fallback in
    /// the offered group list, so a peer that supports neither a hybrid group
    /// nor nothing at all fails the handshake outright. Default false: on a
    /// public listener this turns away every client without PQC support.
    #[serde(default)]
    pub require_hybrid: bool,
    /// Verify OpenSSL provider integrity at startup
    #[serde(default = "default_true_pqc")]
    pub verify_provider: bool,
    /// Check TLS key file permissions for security
    #[serde(default = "default_true_pqc")]
    pub check_key_permissions: bool,
    /// Fail startup if key permissions are insecure (vs just warning)
    #[serde(default)]
    pub strict_key_permissions: bool,
}

fn default_min_security_level() -> u8 {
    3 // NIST Level 3 (192-bit equivalent)
}

fn default_true_pqc() -> bool {
    true
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            required: false,
            provider: "auto".to_string(), // Auto-select best available
            openssl_path: Some(PathBuf::from("/usr/local/openssl-3.5/bin/openssl")),
            openssl_lib_path: Some(PathBuf::from("/usr/local/openssl-3.5/lib64")),
            // X25519MLKEM768 is the IETF standard hybrid (classical + PQC)
            // Provides NIST Level 3 security with classical fallback
            preferred_kem: "X25519MLKEM768".to_string(),
            fallback_to_classical: true,
            require_pqc_provider: default_require_pqc_provider(),
            min_security_level: 3,
            additional_kems: vec![
                "SecP256r1MLKEM768".to_string(),
                "SecP384r1MLKEM1024".to_string(),
            ],
            downgrade_action: default_downgrade_action(),
            log_downgrades: true,
            enable_signatures: true,
            require_hybrid: false,
            verify_provider: true,
            check_key_permissions: true,
            strict_key_permissions: false,
        }
    }
}

/// Fail closed by default. `pqc.enabled` already gates this, so it only fires
/// where an operator asked for PQC and the provider is broken — a state that
/// should stop a deployment rather than quietly serve classical crypto under a
/// configuration that claims otherwise.
fn default_require_pqc_provider() -> bool {
    true
}

fn default_downgrade_action() -> String {
    "log".to_string()
}

/// Backend server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Backend name (used in routing)
    pub name: String,
    /// Backend type: http1, http2, http3, unix, tcp
    #[serde(rename = "type")]
    pub backend_type: BackendType,
    /// Backend address (e.g., "127.0.0.1:8080" or "unix:/run/php-fpm.sock")
    pub address: String,
    /// TLS mode for backend connection
    #[serde(default)]
    pub tls_mode: TlsMode,
    /// Enable TLS to backend (re-encrypt) - legacy option, use tls_mode instead
    #[serde(default)]
    pub tls: bool,
    /// TLS certificate for backend verification (CA cert)
    pub tls_cert: Option<PathBuf>,
    /// TLS client certificate for mTLS
    pub tls_client_cert: Option<PathBuf>,
    /// TLS client key for mTLS
    pub tls_client_key: Option<PathBuf>,
    /// Skip TLS verification (dangerous, for testing only)
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// SNI hostname for backend TLS (defaults to backend address hostname)
    pub tls_sni: Option<String>,
    /// Connection timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum connections to this backend
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Health check endpoint
    pub health_check: Option<String>,
    /// Health check interval in seconds
    #[serde(default = "default_health_interval")]
    pub health_check_interval_secs: u64,

    /// Retry count for failed requests (default 3)
    pub retries: Option<u8>,
    /// Initial retry backoff in milliseconds (doubles each attempt, default 50)
    pub retry_backoff_ms: Option<u64>,
    /// Conditions that trigger a retry: "connect-failure", "timeout", "5xx"
    pub retry_on: Option<Vec<String>>,
    /// Per-backend circuit breaker parameter overrides
    pub circuit_breaker: Option<CircuitBreakerOverride>,
    /// Disable connection pooling/reuse for this backend — every request opens a
    /// brand-new connection instead of reusing one from the pool. Costs a fresh
    /// TCP handshake per request (negligible for loopback backends), but
    /// sidesteps pooled-connection-reuse hangs/resets seen under sustained
    /// concurrent load on some backends.
    #[serde(default)]
    pub disable_pooling: bool,
}

impl BackendConfig {
    /// Whether requests to this backend go over TLS: `tls = true`, or
    /// `tls_mode = "reencrypt"`.
    ///
    /// The two settings say the same thing and both are documented, but the
    /// transports each read one: the TCP listener re-encrypted on `tls_mode`
    /// while HTTP/3 looked only at `tls`, so a backend configured with
    /// `tls_mode = "reencrypt"` alone was reached over TLS from HTTP/1.1 and
    /// HTTP/2 and in plain text from HTTP/3.
    pub fn wants_tls(&self) -> bool {
        self.tls || matches!(self.tls_mode, TlsMode::Reencrypt)
    }
}

/// Per-backend circuit breaker parameter overrides
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerOverride {
    /// Failure count before opening circuit (overrides global)
    pub failure_threshold: Option<u32>,
    /// Seconds to wait before moving from Open to Half-Open (overrides global)
    pub half_open_delay_secs: Option<u64>,
    /// Success count in Half-Open before closing circuit (overrides global)
    pub success_threshold: Option<u32>,
}

/// TLS mode for backend connections
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Terminate TLS at proxy, connect to backend via plain HTTP (default)
    #[default]
    Terminate,
    /// Terminate TLS at proxy, re-encrypt connection to backend via HTTPS
    Reencrypt,
    /// Pass through TLS without termination (SNI-based routing)
    Passthrough,
}

/// TLS passthrough route configuration (SNI-based routing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassthroughRoute {
    /// Route name for logging
    pub name: Option<String>,
    /// SNI hostname pattern to match (supports wildcards: *.example.com)
    pub sni: String,
    /// Backend address to forward to (host:port)
    pub backend: String,
    /// Enable PROXY protocol v2 when connecting to backend
    #[serde(default)]
    pub proxy_protocol: bool,
    /// Connection timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    30000
}

fn default_max_connections() -> u32 {
    100
}

fn default_health_interval() -> u64 {
    30
}

/// Backend type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendType {
    /// HTTP/1.1 backend
    Http1,
    /// HTTP/2 backend
    Http2,
    /// HTTP/3 (QUIC) backend
    Http3,
    /// Unix socket backend
    Unix,
    /// Raw TCP backend
    Tcp,
}

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// Route name for logging/metrics
    pub name: Option<String>,
    /// Host pattern to match (supports wildcards: *.example.com)
    pub host: Option<String>,
    /// Path prefix to match
    pub path_prefix: Option<String>,
    /// Exact path match
    pub path_exact: Option<String>,
    /// Path regex pattern
    pub path_regex: Option<String>,
    /// `path_regex` compiled, built once on first use and reused thereafter.
    ///
    /// It used to be compiled from source inside `route_matches`, which runs on
    /// every request against every route — so a request hitting a config with
    /// nine regex routes paid nine regex *compilations*, an operation orders of
    /// magnitude dearer than the match it exists to perform. Not serialised and
    /// not part of the config surface: it is derived state, and `#[serde(skip)]`
    /// gives it its `Default` on load and on reload.
    #[serde(skip)]
    compiled_path_regex: std::sync::OnceLock<Option<regex::Regex>>,
    /// Enable WebTransport for this route
    #[serde(default)]
    pub webtransport: bool,
    /// Backend name to route to (not required if redirect is set)
    #[serde(default)]
    pub backend: String,
    /// Transform WebTransport stream to HTTP method
    pub stream_to_method: Option<String>,
    /// Headers to add to backend request
    #[serde(default)]
    pub add_headers: HashMap<String, String>,
    /// Backend response headers not to forward to the client, on every
    /// transport. (Applied to the response, not the backend request.)
    #[serde(default)]
    pub remove_headers: Vec<String>,
    /// Forward client identity header
    #[serde(default)]
    pub forward_client_identity: bool,
    /// Client identity header name
    pub client_identity_header: Option<String>,
    /// Priority (lower = higher priority)
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// CORS configuration for this route
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Redirect URL (for SEO redirects)
    pub redirect: Option<String>,
    /// Permanent redirect (301) vs temporary (302)
    #[serde(default)]
    pub redirect_permanent: bool,
    /// Override headers for this route
    #[serde(default)]
    pub headers_override: HashMap<String, String>,
    /// Allow HTTP/1.1 for this route (for search bots)
    #[serde(default)]
    pub allow_http11: bool,
    /// Skip bot blocking for this route
    #[serde(default)]
    pub skip_bot_blocking: bool,
    /// Stripe.js compatibility (removes COEP/COOP headers)
    #[serde(default)]
    pub stripe_compatibility: bool,
    /// Timeout override in milliseconds
    pub timeout_override_ms: Option<u64>,

    /// L-5: Allow 0-RTT (early data) for this route.
    ///
    /// When `tls.enable_0rtt = true`, this per-route flag controls whether
    /// early data is accepted.  Only set to `true` for routes that serve
    /// **idempotent** requests (GET, HEAD) and whose backends are safe to
    /// receive duplicate deliveries.  The proxy enforces `tls.zero_rtt_safe_methods`
    /// when this flag is set.
    #[serde(default)]
    pub allow_0rtt: bool,

    /// Mark this route as internal-only (service-to-service).
    /// When true: mTLS is required by default, HMAC signing is enforced if hmac_secret set.
    #[serde(default)]
    pub internal: bool,
    /// Per-route security policy override (mTLS, JA3 allowlist, rate limit, WAF mode)
    pub security: Option<RouteSecurityPolicy>,
    /// Shadow / traffic-mirroring — async fire-and-forget copy of requests sent to a
    /// secondary backend without affecting the client response.
    #[serde(default)]
    pub shadow: Option<ShadowConfig>,

    /// Enable WebSocket upgrade proxying for this route.
    /// When true the proxy passes HTTP/1.1 upgrade handshakes and pipes the raw upgraded TCP
    /// stream bidirectionally, bypassing the normal body-buffering path.
    /// Implies HTTP/1.1 is permitted for the upgrade request regardless of `allow_http11`.
    #[serde(default)]
    pub supports_websocket: bool,

    /// Idle timeout for proxied WebSocket connections, in seconds.
    /// A connection with no data in either direction for this long is dropped.
    /// Set to 0 to disable (not recommended for production).
    #[serde(default = "default_ws_idle_timeout_secs")]
    pub ws_idle_timeout_secs: u64,

    /// JSON fields to strip from backend response bodies (application/json only).
    /// Use to remove internal stack traces (e.g. Frappe `exc` field) before
    /// forwarding responses to clients.
    #[serde(default)]
    pub strip_response_json_fields: Vec<String>,

    /// Enforce HttpOnly and Secure attributes on all Set-Cookie headers from
    /// the backend. Use for backends (e.g. Frappe/ERPNext) that intentionally
    /// omit HttpOnly on non-session cookies but where the proxy should add it.
    /// Applied on HTTP/1.1, HTTP/2 and HTTP/3, streamed or buffered.
    #[serde(default)]
    pub enforce_cookie_security: bool,

    /// `Domain` added to every backend Set-Cookie that has none. Applied on
    /// every transport: a cookie scoped one way over HTTP/2 and another over
    /// HTTP/3 leaves the browser holding two cookies of the same name.
    #[serde(default)]
    pub set_cookie_domain: Option<String>,
}

impl RouteConfig {
    /// Whether requests to this route must come with a client certificate:
    /// `security.mtls_required`, defaulting to `internal`.
    pub fn requires_client_cert(&self) -> bool {
        self.security
            .as_ref()
            .and_then(|s| s.mtls_required)
            .unwrap_or(self.internal)
    }

    /// Whether this route rewrites backend Set-Cookie headers at all.
    pub fn rewrites_set_cookie(&self) -> bool {
        self.enforce_cookie_security
            || self
                .set_cookie_domain
                .as_deref()
                .is_some_and(|d| !d.is_empty())
    }

    /// Apply this route's Set-Cookie policy to one backend cookie, or `None`
    /// when it needs no change.
    ///
    /// Attributes are matched by name. The substring test this replaced read
    /// a cookie *named* `securetoken` as already carrying `Secure`.
    pub fn rewrite_set_cookie(&self, cookie: &str) -> Option<String> {
        let has = |attr: &str| {
            cookie.split(';').skip(1).any(|a| {
                a.split('=')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case(attr)
            })
        };
        let mut out = String::new();
        if self.enforce_cookie_security {
            if !has("HttpOnly") {
                out.push_str("; HttpOnly");
            }
            if !has("Secure") {
                out.push_str("; Secure");
            }
        }
        if let Some(domain) = self.set_cookie_domain.as_deref().filter(|d| !d.is_empty()) {
            if !has("Domain") {
                out.push_str("; Domain=");
                out.push_str(domain);
            }
        }
        (!out.is_empty()).then(|| format!("{cookie}{out}"))
    }

    /// Apply [`Self::rewrite_set_cookie`] to every Set-Cookie in `headers`.
    pub fn apply_set_cookie_policy(&self, headers: &mut http::HeaderMap) {
        if !self.rewrites_set_cookie() || !headers.contains_key(http::header::SET_COOKIE) {
            return;
        }
        let cookies: Vec<http::HeaderValue> = headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| {
                v.to_str()
                    .ok()
                    .and_then(|c| self.rewrite_set_cookie(c))
                    .and_then(|c| http::HeaderValue::from_str(&c).ok())
                    .unwrap_or_else(|| v.clone())
            })
            .collect();
        headers.remove(http::header::SET_COOKIE);
        for c in cookies {
            headers.append(http::header::SET_COOKIE, c);
        }
    }
}

fn default_priority() -> i32 {
    100
}

fn default_ws_idle_timeout_secs() -> u64 {
    300
}

fn default_shadow_percent() -> u8 {
    100
}

fn default_shadow_timeout_ms() -> u64 {
    5000
}

fn default_shadow_header() -> String {
    "X-Shadow-Request".to_string()
}

fn default_shadow_header_value() -> String {
    "1".to_string()
}

/// Shadow / traffic-mirroring configuration.
///
/// When present on a route, a fire-and-forget copy of each selected request is
/// sent asynchronously to `backend`.  The client only ever sees the primary
/// backend response; the shadow response is logged and discarded.  The shadow
/// backend receives an identical request body with the configurable marker header
/// appended so it can distinguish mirror traffic from real traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShadowConfig {
    /// Backend name that receives the mirrored copy (must be a key in `[backends.*]`)
    pub backend: String,
    /// Percentage of requests to mirror (0–100, default 100)
    #[serde(default = "default_shadow_percent")]
    pub percent: u8,
    /// Timeout for the shadow request in milliseconds — independent of the primary
    /// backend timeout (default 5000 ms).  Shadow tasks are abandoned after this.
    #[serde(default = "default_shadow_timeout_ms")]
    pub timeout_ms: u64,
    /// Name of the request header injected on shadow requests so the shadow
    /// backend can identify mirror traffic (default "X-Shadow-Request")
    #[serde(default = "default_shadow_header")]
    pub shadow_header: String,
    /// Value written into `shadow_header` (default "1")
    #[serde(default = "default_shadow_header_value")]
    pub shadow_header_value: String,
    /// Log shadow response status and latency at INFO level (default true)
    #[serde(default = "default_true")]
    pub log_responses: bool,
}

impl Default for ShadowConfig {
    fn default() -> Self {
        Self {
            backend: String::new(),
            percent: default_shadow_percent(),
            timeout_ms: default_shadow_timeout_ms(),
            shadow_header: default_shadow_header(),
            shadow_header_value: default_shadow_header_value(),
            log_responses: true,
        }
    }
}

/// Admin API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdminConfig {
    /// Enable admin API
    pub enabled: bool,
    /// Admin API bind address
    pub bind_address: String,
    /// Admin API port
    pub port: u16,
    /// Serve the admin API over TLS 1.3 and require a client certificate
    /// issued by [`client_ca_path`](Self::client_ca_path). The certificate is
    /// then the credential: `auth_token` becomes optional, and is still
    /// checked when set.
    pub require_mtls: bool,
    /// Certificate the admin listener presents under `require_mtls`.
    /// Default: `tls.cert_path`.
    pub tls_cert_path: Option<PathBuf>,
    /// Its private key. Default: `tls.key_path`.
    pub tls_key_path: Option<PathBuf>,
    /// CA that issues admin client certificates. Default: `tls.ca_cert_path`;
    /// `require_mtls` refuses to start with neither.
    pub client_ca_path: Option<PathBuf>,
    /// Admin API token for authentication (if not using mTLS)
    pub auth_token: Option<String>,
    /// Allowed IP addresses for admin API
    pub allowed_ips: Vec<String>,
    /// Proof-of-possession HMAC secret for admin API.
    /// When set, all admin requests must include X-Admin-Signature and X-Admin-Timestamp.
    /// Signature = HMAC-SHA256(METHOD + "\n" + PATH + "\n" + TIMESTAMP, secret).
    /// Provides per-request proof without replacing the bearer token.
    pub hmac_secret: Option<String>,
    /// Refuse to start if the admin bind address is not loopback (default: true).
    /// Applies to the plain-HTTP listener, where a non-loopback bind transmits
    /// Bearer tokens in cleartext; set it to `false` only behind a TLS tunnel
    /// (SSH port-forward, WireGuard). Under `require_mtls` the listener is TLS
    /// with client authentication, and a non-loopback bind is what it is for.
    #[serde(default = "default_require_loopback")]
    pub require_loopback: bool,
}

fn default_require_loopback() -> bool {
    true
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            // SEC-13: Admin API disabled by default — operators must explicitly set
            // [admin] enabled = true in config. This prevents accidental exposure
            // in container environments where 127.0.0.1 may be shared across containers.
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            port: 8081,
            require_mtls: false,
            tls_cert_path: None,
            tls_key_path: None,
            client_ca_path: None,
            auth_token: None,
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            hmac_secret: None,
            require_loopback: default_require_loopback(),
        }
    }
}

impl AdminConfig {
    /// Get the full socket address
    pub fn socket_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.bind_address, self.port).parse()
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,
    /// Log format: json or text
    pub format: String,
    /// Log file path (empty = stdout)
    pub file: Option<PathBuf>,
    /// Enable access logs
    pub access_log: bool,
    /// Access log file path
    pub access_log_file: Option<PathBuf>,
    /// Access log line format: "combined" (default), "json", or a template of
    /// `$variables` such as `$remote_addr [$time_local] "$request" $status $ja4`.
    #[serde(default = "default_access_log_format")]
    pub access_log_format: String,
    /// Audit log file path (None = write to stderr)
    pub audit_log_path: Option<PathBuf>,
    /// Enable structured audit logging (default true)
    #[serde(default = "default_true")]
    pub audit_log_enabled: bool,
    /// Rotate `file` once it reaches this size, in MB (0 = never rotate on size)
    #[serde(default = "default_log_max_size_mb")]
    pub max_size_mb: u64,
    /// How many rotated files to keep alongside `file`
    #[serde(default = "default_log_max_backups")]
    pub max_backups: usize,
    /// Delete rotated files older than this many days (0 = never delete on age)
    #[serde(default = "default_log_max_age_days")]
    pub max_age_days: u64,
}

fn default_log_max_size_mb() -> u64 {
    50
}

fn default_log_max_backups() -> usize {
    3
}

fn default_log_max_age_days() -> u64 {
    7
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file: None,
            access_log: true,
            access_log_file: None,
            access_log_format: default_access_log_format(),
            audit_log_path: None,
            audit_log_enabled: true,
            max_size_mb: default_log_max_size_mb(),
            max_backups: default_log_max_backups(),
            max_age_days: default_log_max_age_days(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    ///
    /// The master switch for this whole section: `false` turns off the request
    /// limiter *and* the connection limiter below. It did not always — the
    /// connection limiter was gated only on its own flag, which defaults to
    /// true, so disabling the section left it banning clients for 300s.
    pub enabled: bool,
    /// Requests per second per IP
    pub requests_per_second: u32,
    /// Burst size
    pub burst_size: u32,
    /// Enable connection rate limiting. Only consulted when `enabled` is true.
    pub connection_rate_limit: bool,
    /// New connections per second per IP
    pub connections_per_second: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 50,
            connection_rate_limit: true,
            connections_per_second: 10,
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Maximum request size in bytes
    pub max_request_size: usize,
    /// Maximum header size in bytes
    pub max_header_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Enable DoS protection
    pub dos_protection: bool,
    /// Blocked IP addresses
    pub blocked_ips: Vec<String>,
    /// Allowed IP addresses (whitelist mode)
    pub allowed_ips: Vec<String>,
    /// GeoIP database path (for country blocking)
    pub geoip_db_path: Option<PathBuf>,
    /// Blocked country codes (ISO 3166-1 alpha-2, e.g., "CN", "RU")
    pub blocked_countries: Vec<String>,
    /// Maximum connections per IP
    pub max_connections_per_ip: u32,
    /// Auto-block threshold (suspicious patterns before auto-block)
    pub auto_block_threshold: u32,
    /// Auto-block duration in seconds
    pub auto_block_duration_secs: u64,
    /// 4xx error count threshold before checking error rate
    pub error_4xx_threshold: u32,
    /// Minimum requests before error rate check applies
    pub min_requests_for_error_check: u64,
    /// Error rate threshold (0.0-1.0) to trigger suspicious pattern
    pub error_rate_threshold: f64,
    /// Request window duration in seconds for error tracking
    pub error_window_secs: u64,
    /// Additional trusted CIDR ranges beyond loopback and RFC1918.
    /// Operators must explicitly add any non-private ranges here.
    /// Default: empty (loopback 127.0.0.0/8 and RFC1918 are always trusted).
    #[serde(default)]
    pub trusted_internal_cidrs: Vec<IpNet>,
    /// Directory for database-synced blocklist JSON files.
    /// Must be outside the web root and mode 0700, owned by the service user.
    pub blocklist_dir: PathBuf,
    /// F-01: Allow backends that resolve to RFC1918 private addresses.
    ///
    /// By default PQCrypta Proxy warns when a backend address falls in an RFC1918
    /// range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and **rejects** any
    /// backend that resolves to the link-local range (169.254.0.0/16) which is
    /// used by cloud metadata services (AWS IMDSv1/v2, GCP, Azure) and must
    /// **never** be reachable via the proxy.
    ///
    /// Set `allow_internal_backends = true` only in controlled environments where
    /// RFC1918 backends are intentional (e.g. a fully private internal network)
    /// and the SSRF risk has been explicitly accepted.
    ///
    /// Link-local (169.254.0.0/16) rejection cannot be disabled.
    #[serde(default)]
    pub allow_internal_backends: bool,
    /// Duration in seconds for GeoIP-based IP blocks.
    ///
    /// `0` means the block never expires. TOML has no null and this field carries
    /// a serde default, so omitting it cannot express "permanent" — zero is the
    /// only spelling available. Any other `n` expires the block after n seconds.
    /// Default: 86400 — 24 h, giving operators recourse for mis-classified IPs.
    ///
    /// Note this is global, not per-country: it applies to every entry in
    /// `blocked_countries`.
    #[serde(default = "default_geoip_block_duration_secs")]
    pub geoip_block_duration_secs: Option<u64>,
    /// Enable zero-trust mode. At startup, enforces:
    /// - All backends must use tls_mode = "reencrypt" or "passthrough" (no plaintext)
    /// - trusted_internal_cidrs must be empty
    /// - TLS require_client_cert must be true
    /// - admin.hmac_secret or admin.require_mtls must be set (bearer-only admin auth is insufficient)
    ///
    /// Startup aborts if any constraint is violated.
    #[serde(default)]
    pub zero_trust_mode: bool,
    /// Authorized pentest IPs — skip rate-limiting and auto-block but still run WAF.
    /// Each blocked attack still returns 403; the IP is never auto-banned mid-run.
    /// Remove these entries after the pentest engagement ends.
    #[serde(default)]
    pub pentest_bypass_ips: Vec<String>,
    /// Origins allowed to read the proxy's own refusals (403/429) cross-origin.
    /// Without CORS headers a refusal reaches the page as an opaque CORS error,
    /// so it cannot see the status and retries instead of backing off. One list
    /// for every transport and both rate limiters.
    #[serde(default = "default_refusal_cors_origins")]
    pub refusal_cors_origins: Vec<String>,
    /// Where a geo-blocked request is redirected (302). Empty refuses it with a
    /// plain 403 instead. Must be served under `error_pages_path_prefix`, which
    /// is exempt from blocking, or the redirect loops.
    #[serde(default = "default_geo_block_redirect_url")]
    pub geo_block_redirect_url: String,
    /// Path prefix exempt from IP, country and rate blocking, so a blocked
    /// visitor can still load the error page that explains the block. Empty
    /// exempts nothing.
    #[serde(default = "default_error_pages_path_prefix")]
    pub error_pages_path_prefix: String,
    /// Request hygiene limits, checked before the WAF on every transport.
    #[serde(default)]
    pub validation: RequestValidationConfig,
    /// When non-empty, only these countries (ISO 3166-1 alpha-2) are served;
    /// an address with no country in the database is not refused by it.
    #[serde(default)]
    pub allowed_countries: Vec<String>,
    /// Refused regions, ISO 3166-2 (e.g. "US-CA"), from the City database.
    #[serde(default)]
    pub blocked_regions: Vec<String>,
    /// Refused autonomous systems, by number, from the ASN database.
    #[serde(default)]
    pub blocked_asns: Vec<u32>,
    /// MaxMind GeoLite2-ASN database: `blocked_asns` and the speed test's
    /// ISP lookup.
    #[serde(default = "default_geoip_asn_db_path")]
    pub geoip_asn_db_path: Option<PathBuf>,
    /// Refuse Tor exit nodes, from the list at `tor_exit_list_url`.
    #[serde(default)]
    pub block_tor_exit_nodes: bool,
    /// One address per line; the Tor Project publishes the current exits.
    #[serde(default = "default_tor_exit_list_url")]
    pub tor_exit_list_url: String,
    /// How often the exit list is re-fetched.
    #[serde(default = "default_tor_exit_refresh_secs")]
    pub tor_exit_refresh_secs: u64,
    /// How many distinct TLS fingerprints the observed corpus retains.
    ///
    /// This began as a memory-exhaustion guard at a hardcoded 50,000 and is now
    /// the size limit on a published dataset: `observed.json` is what
    /// `/ja4/` serves, and that is the most-crawled path on the site by a
    /// factor of eight. The corpus reached exactly 50,000 entries, which means
    /// it had been evicting its long tail — least-recently-seen first, so the
    /// rare fingerprints a directory exists to record are precisely the ones
    /// that go.
    ///
    /// Still bounded, because it is still fed by anyone who can open a
    /// connection. At roughly 500 bytes an entry the default costs ~125 MB
    /// resident and ~125 MB on disk.
    #[serde(default = "default_max_tracked_fingerprints")]
    pub max_tracked_fingerprints: usize,
}

fn default_max_tracked_fingerprints() -> usize {
    250_000
}

fn default_geoip_asn_db_path() -> Option<PathBuf> {
    Some(PathBuf::from(
        "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-ASN.mmdb",
    ))
}

fn default_tor_exit_list_url() -> String {
    "https://check.torproject.org/torbulkexitlist".to_string()
}

fn default_tor_exit_refresh_secs() -> u64 {
    3600
}

fn default_geoip_block_duration_secs() -> Option<u64> {
    Some(86400) // 24 hours — prevents permanent blocks from stale GeoIP data
}

// Site-specific refusal settings default to nothing: no origin trusted, a
// plain 403 for a geo block, no exempt path. Each deployment names its own in
// `[security]`; these used to be literals naming pqcrypta.com.
fn default_refusal_cors_origins() -> Vec<String> {
    Vec::new()
}

fn default_geo_block_redirect_url() -> String {
    String::new()
}

fn default_error_pages_path_prefix() -> String {
    String::new()
}

/// `[security.validation]`: structural limits on a request.
///
/// Each is refused with the status that names the problem (414, 431, 405,
/// 400). A missing Host is
/// already refused by routing, which matches on it — over HTTP/2 and HTTP/3 the
/// host is the `:authority` pseudo-header rather than a `Host` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestValidationConfig {
    pub enabled: bool,
    /// Path plus query string, in bytes (414 above it).
    pub max_uri_length: usize,
    /// Number of header fields (431 above it).
    pub max_headers_count: usize,
    /// Longest header name, in bytes (431 above it).
    pub max_header_name_length: usize,
    /// Longest single header value, in bytes (431 above it).
    pub max_header_value_length: usize,
    /// Methods accepted; empty accepts any (405 otherwise).
    pub allowed_methods: Vec<String>,
    /// Refuse a NUL byte, raw or percent-encoded, in the path or query (400).
    pub reject_null_bytes: bool,
}

impl Default for RequestValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_uri_length: 16384,
            max_headers_count: 200,
            max_header_name_length: 256,
            max_header_value_length: 16384,
            allowed_methods: Vec::new(),
            reject_null_bytes: true,
        }
    }
}

impl RequestValidationConfig {
    /// The status and reason for a request these limits refuse, if any.
    pub fn check(
        &self,
        method: &str,
        path: &str,
        query: &str,
        headers: &http::HeaderMap,
    ) -> Option<(u16, String)> {
        if !self.enabled {
            return None;
        }
        let uri_len = path.len() + if query.is_empty() { 0 } else { query.len() + 1 };
        if uri_len > self.max_uri_length {
            return Some((
                414,
                format!("URI of {uri_len} bytes exceeds {}", self.max_uri_length),
            ));
        }
        if self.reject_null_bytes {
            let has_nul = |s: &str| {
                s.contains('\0')
                    || s.as_bytes()
                        .windows(3)
                        .any(|w| w[0] == b'%' && w[1] == b'0' && w[2] == b'0')
            };
            if has_nul(path) || has_nul(query) {
                return Some((400, "NUL byte in request target".to_string()));
            }
        }
        if !self.allowed_methods.is_empty() && !self.allowed_methods.iter().any(|m| m == method) {
            return Some((405, format!("method {method} not allowed")));
        }
        if headers.len() > self.max_headers_count {
            return Some((
                431,
                format!(
                    "{} header fields exceed {}",
                    headers.len(),
                    self.max_headers_count
                ),
            ));
        }
        for (name, value) in headers {
            if name.as_str().len() > self.max_header_name_length {
                return Some((
                    431,
                    format!("header name exceeds {} bytes", self.max_header_name_length),
                ));
            }
            if value.len() > self.max_header_value_length {
                return Some((
                    431,
                    format!(
                        "header {} exceeds {} bytes",
                        name, self.max_header_value_length
                    ),
                ));
            }
        }
        None
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 64 * 1024,         // 64KB
            connection_timeout_secs: 30,
            dos_protection: true,
            blocked_ips: Vec::new(),
            allowed_ips: Vec::new(),
            geoip_db_path: Some(PathBuf::from(
                "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb",
            )),
            blocked_countries: Vec::new(), // e.g., vec!["CN", "RU", "KP", "IR"]
            max_connections_per_ip: 100,
            auto_block_threshold: 10, // 10 suspicious patterns before auto-block
            auto_block_duration_secs: 300, // 5 minute auto-block
            error_4xx_threshold: 100, // 100 4xx errors before checking rate
            min_requests_for_error_check: 200, // Need 200+ requests before error check
            error_rate_threshold: 0.7, // 70% error rate triggers suspicious
            error_window_secs: 60,    // 1 minute sliding window
            max_tracked_fingerprints: default_max_tracked_fingerprints(),
            trusted_internal_cidrs: Vec::new(),
            blocklist_dir: PathBuf::from("/var/lib/pqcrypta-proxy/blocklists"),
            allow_internal_backends: false,
            geoip_block_duration_secs: default_geoip_block_duration_secs(),
            zero_trust_mode: false,
            pentest_bypass_ips: Vec::new(),
            refusal_cors_origins: default_refusal_cors_origins(),
            geo_block_redirect_url: default_geo_block_redirect_url(),
            error_pages_path_prefix: default_error_pages_path_prefix(),
            validation: RequestValidationConfig::default(),
            allowed_countries: Vec::new(),
            blocked_regions: Vec::new(),
            blocked_asns: Vec::new(),
            geoip_asn_db_path: default_geoip_asn_db_path(),
            block_tor_exit_nodes: false,
            tor_exit_list_url: default_tor_exit_list_url(),
            tor_exit_refresh_secs: default_tor_exit_refresh_secs(),
        }
    }
}

/// Fingerprint detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /// Enable TLS fingerprint detection
    pub enabled: bool,
    /// Use TLS-layer capture with custom accept loop (captures raw ClientHello)
    /// When enabled, uses FingerprintingTlsAcceptor for full JA3/JA4 capture
    /// before TLS handshake, allowing early blocking of malicious clients.
    /// When disabled, fingerprinting relies on headers from middleware layer.
    pub tls_layer_capture: bool,
    /// Block duration for malicious fingerprints (seconds)
    pub malicious_block_duration_secs: u64,
    /// Block duration for suspicious fingerprints with high rate (seconds)
    pub suspicious_block_duration_secs: u64,
    /// Request count threshold to trigger suspicious fingerprint rate check
    pub suspicious_rate_threshold: u64,
    /// Time window for suspicious rate detection (seconds)
    pub suspicious_rate_window_secs: u64,
    /// Fingerprint cache max age before cleanup (seconds)
    pub cache_max_age_secs: u64,
    /// Block scanner fingerprints (Nmap, Nikto, Burp Suite, etc.)
    pub block_scanners: bool,
    /// Add fingerprint info headers to responses (for debugging/monitoring)
    pub add_response_headers: bool,
    /// Path to the JA3/JA4 fingerprint database JSON file.
    /// Format: [{hash, classification, description}] where classification is one of:
    /// "browser", "bot", "legitimate_bot", "malicious", "scanner", "api_client"
    /// If None or the file is missing, an empty database is used (advisory only).
    pub fingerprint_db_path: Option<PathBuf>,
    /// Where the observed-fingerprint corpus persists between restarts.
    /// `None` keeps it in memory only. Loaded and flushed only while
    /// fingerprinting is enabled.
    #[serde(default = "default_observed_fingerprints_path")]
    pub observed_path: Option<PathBuf>,
    /// AUD-12: Automatically block connections whose JA3/JA4 fingerprint is classified
    /// as Malicious in the fingerprint database.
    /// Default: true — Malicious fingerprints are blocked, which is the point of
    /// AUD-12. (This comment previously claimed the default was false, advisory-only;
    /// the Default impl below has always set true, so the comment was wrong.)
    /// Set to false to make classification advisory if your fingerprint database
    /// produces false positives against legitimate clients.
    pub block_malicious: bool,

    /// Enable JA3 replay detection (same fingerprint from many IPs in short window)
    #[serde(default = "default_true")]
    pub replay_detection: bool,
    /// Time window in seconds for replay detection (default 60)
    #[serde(default = "default_fp_replay_window")]
    pub replay_window_secs: u64,
    /// Enable JA3 drift detection (same hash but different cipher/extension composition)
    #[serde(default = "default_true")]
    pub drift_detection: bool,
    /// Time window in seconds for drift detection (default 300)
    #[serde(default = "default_fp_drift_window")]
    pub drift_window_secs: u64,
    /// Fraction of requests with drift to flag (0.0–1.0, default 0.7)
    #[serde(default = "default_fp_drift_threshold")]
    pub drift_threshold: f64,
}

fn default_fp_replay_window() -> u64 {
    60
}

fn default_fp_drift_window() -> u64 {
    300
}

fn default_fp_drift_threshold() -> f64 {
    0.7
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tls_layer_capture: false, // Use middleware-based capture by default
            malicious_block_duration_secs: 3600, // 1 hour
            suspicious_block_duration_secs: 300, // 5 minutes
            suspicious_rate_threshold: 100, // 100 requests
            suspicious_rate_window_secs: 60, // 1 minute
            cache_max_age_secs: 3600, // 1 hour
            block_scanners: false,    // Log but don't block by default
            add_response_headers: false, // Disabled by default for security
            fingerprint_db_path: Some(PathBuf::from(
                "/var/lib/pqcrypta-proxy/fingerprints/ja3.json",
            )),
            observed_path: default_observed_fingerprints_path(),
            block_malicious: true, // Block malicious fingerprints by default (AUD-12)
            replay_detection: true,
            replay_window_secs: 60,
            drift_detection: true,
            drift_window_secs: 300,
            drift_threshold: 0.7,
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Enable circuit breaker
    pub enabled: bool,
    /// Time before circuit breaker transitions from Open to Half-Open (seconds)
    pub half_open_delay_secs: u64,
    /// Maximum test requests allowed in Half-Open state
    pub half_open_max_requests: u32,
    /// Failure threshold to open the circuit
    pub failure_threshold: u32,
    /// Success threshold to close the circuit from Half-Open
    pub success_threshold: u32,
    /// Stale request counter cleanup interval (seconds)
    pub stale_counter_cleanup_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            half_open_delay_secs: 30,        // 30 seconds
            half_open_max_requests: 3,       // 3 test requests
            failure_threshold: 5,            // 5 failures to open
            success_threshold: 2,            // 2 successes to close
            stale_counter_cleanup_secs: 300, // 5 minutes
        }
    }
}

/// HTTP connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionPoolConfig {
    /// Pool idle timeout (seconds) - how long idle connections stay in pool
    pub idle_timeout_secs: u64,
    /// Maximum idle connections per host
    pub max_idle_per_host: usize,
    /// Maximum total connections per host
    pub max_connections_per_host: usize,
    /// Connection acquire timeout (milliseconds)
    pub acquire_timeout_ms: u64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 90,         // 90 seconds
            max_idle_per_host: 10,         // 10 idle connections
            max_connections_per_host: 100, // 100 total connections
            acquire_timeout_ms: 5000,      // 5 second timeout
        }
    }
}

/// Security headers configuration (similar to nginx/Apache security headers)
///
/// Every value is optional: an empty string omits that header. With all of
/// them empty and `server_timing_enabled = false` the TCP listener leaves the
/// response-header layer out of its middleware chain altogether.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HeadersConfig {
    /// HSTS header
    pub hsts: String,
    /// X-Frame-Options header
    pub x_frame_options: String,
    /// X-Content-Type-Options header
    pub x_content_type_options: String,
    /// Referrer-Policy header
    pub referrer_policy: String,
    /// Permissions-Policy header
    pub permissions_policy: String,
    /// Cross-Origin-Opener-Policy header
    pub cross_origin_opener_policy: String,
    /// Cross-Origin-Embedder-Policy header
    pub cross_origin_embedder_policy: String,
    /// Cross-Origin-Resource-Policy header
    pub cross_origin_resource_policy: String,
    /// X-Permitted-Cross-Domain-Policies header
    pub x_permitted_cross_domain_policies: String,
    /// X-Download-Options header
    pub x_download_options: String,
    /// X-DNS-Prefetch-Control header
    pub x_dns_prefetch_control: String,
    /// X-Quantum-Resistant branding header
    pub x_quantum_resistant: String,
    /// X-Security-Level branding header
    pub x_security_level: String,
    /// SEC-07: Content-Security-Policy header.
    /// Default restricts sources to same-origin. Set to empty string to omit the header.
    pub content_security_policy: String,

    // ═══════════════════════════════════════════════════════════════
    // HTTP/3 Performance & Monitoring Headers
    // ═══════════════════════════════════════════════════════════════
    /// Enable Server-Timing header (performance metrics)
    #[serde(default = "default_true")]
    pub server_timing_enabled: bool,

    /// `desc` of the Server-Timing metric.
    #[serde(default = "default_server_timing_desc")]
    pub server_timing_desc: String,

    /// Accept-CH header for Client Hints (responsive content delivery)
    /// Example: "DPR, Viewport-Width, Width, ECT, RTT, Downlink, Sec-CH-UA-Platform"
    #[serde(default)]
    pub accept_ch: String,

    /// NEL (Network Error Logging) header for client-side error reporting
    /// JSON configuration for NEL policy
    #[serde(default)]
    pub nel: String,

    /// Report-To header endpoint configuration for NEL and other reports
    /// JSON array of reporting endpoints
    #[serde(default)]
    pub report_to: String,

    /// Priority header for HTTP/3 response prioritization (RFC 9218)
    /// Format: `u=<urgency>, i` where urgency is 0-7 and i indicates incremental
    #[serde(default)]
    pub priority: String,

    // ═══════════════════════════════════════════════════════════════
    // Outlook add-in surface exception
    // ═══════════════════════════════════════════════════════════════
    // Office hosts the add-in task pane in a cross-origin iframe, so this URL
    // prefix must NOT receive X-Frame-Options and instead gets an add-in CSP
    // (frame-ancestors for the Office hosts). Leave addin_csp empty to disable.
    /// Hosts on which the add-in exception applies (matched against the Host header).
    #[serde(default = "default_addin_hosts")]
    pub addin_hosts: Vec<String>,
    /// URL path prefix that identifies the add-in surface.
    #[serde(default = "default_addin_path_prefix")]
    pub addin_path_prefix: String,
    /// CSP applied to the add-in surface. Empty disables the exception entirely.
    #[serde(default = "default_addin_csp")]
    pub addin_csp: String,
}

fn default_server_timing_desc() -> String {
    "PQ Crypta Processing".to_string()
}

// The Outlook add-in exception is off unless configured. These defaults used
// to name pqpdf.com's hosts and CSP, so every deployment inherited one site's
// framing exception.
fn default_addin_hosts() -> Vec<String> {
    Vec::new()
}
fn default_addin_path_prefix() -> String {
    String::new()
}
fn default_addin_csp() -> String {
    String::new()
}

impl Default for HeadersConfig {
    fn default() -> Self {
        Self {
            hsts: "max-age=63072000; includeSubDomains; preload".to_string(),
            x_frame_options: "DENY".to_string(),
            x_content_type_options: "nosniff".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=(), interest-cohort=(), fullscreen=(self), payment=()".to_string(),
            cross_origin_opener_policy: "same-origin".to_string(),
            cross_origin_embedder_policy: "require-corp".to_string(),
            cross_origin_resource_policy: "same-origin".to_string(),
            x_permitted_cross_domain_policies: "none".to_string(),
            x_download_options: "noopen".to_string(),
            x_dns_prefetch_control: "off".to_string(),
            x_quantum_resistant: "ML-KEM-1024, ML-DSA-87, X25519MLKEM768".to_string(),
            x_security_level: "Post-Quantum Ready".to_string(),
            // SEC-07: Provide a safe default CSP. Operators should tighten this per-deployment.
            content_security_policy: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'".to_string(),

            // HTTP/3 Performance & Monitoring Headers
            server_timing_enabled: true,
            server_timing_desc: default_server_timing_desc(),

            // Accept-CH, NEL, Report-To and Priority are empty by default, the same
            // value `#[serde(default)]` gives each field when a `[headers]` section
            // omits it. The two used to disagree: a config with no `[headers]`
            // section at all took these from here, and this default pointed every
            // other operator's browsers at pqcrypta.com's report collector.
            accept_ch: String::new(),
            nel: String::new(),
            report_to: String::new(),
            priority: String::new(),

            // Outlook add-in surface exception
            addin_hosts: default_addin_hosts(),
            addin_path_prefix: default_addin_path_prefix(),
            addin_csp: default_addin_csp(),
        }
    }
}

/// HTTP redirect configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpRedirectConfig {
    /// Enable HTTP redirect server
    pub enabled: bool,
    /// HTTP port to listen on
    pub port: u16,
    /// Redirect all HTTP to HTTPS
    pub redirect_to_https: bool,
    /// AUD-02: Allowed hostnames for the HTTP→HTTPS redirect.
    /// Requests whose Host header is not in this list receive 400 Bad Request,
    /// preventing open-redirect abuse.  An empty list disables host validation.
    pub allowed_domains: Vec<String>,
    /// Status of the HTTP→HTTPS redirect: 301, 302, 307 or 308 (default).
    /// 307/308 keep the method and body; 301/302 let a client turn a POST into
    /// a GET, which breaks anything that posts over plain HTTP first.
    pub redirect_status: u16,
}

impl Default for HttpRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 80,
            redirect_to_https: true,
            allowed_domains: vec![],
            redirect_status: 308,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Load Balancer Configuration
// ═══════════════════════════════════════════════════════════════

/// Load balancer global configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoadBalancerConfig {
    /// Enable load balancing
    pub enabled: bool,
    /// Default algorithm: least_connections, round_robin, weighted_round_robin, random, ip_hash, least_response_time
    pub default_algorithm: String,
    /// Session affinity configuration
    pub session_affinity: SessionAffinityConfig,
    /// Request queue configuration
    pub queue: QueueConfig,
    /// Slow start configuration for recovering backends
    pub slow_start: SlowStartLbConfig,
    /// Connection draining configuration
    pub connection_draining: ConnectionDrainingConfig,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_algorithm: "least_connections".to_string(),
            session_affinity: SessionAffinityConfig::default(),
            queue: QueueConfig::default(),
            slow_start: SlowStartLbConfig::default(),
            connection_draining: ConnectionDrainingConfig::default(),
        }
    }
}

/// Session affinity (sticky sessions) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionAffinityConfig {
    /// Enable session affinity globally
    pub enabled: bool,
    /// Cookie name for session tracking
    pub cookie_name: String,
    /// Cookie TTL in seconds (0 = session cookie)
    pub cookie_ttl_secs: u64,
    /// Use secure cookies (HTTPS only)
    pub cookie_secure: bool,
    /// Use HttpOnly cookies
    pub cookie_httponly: bool,
    /// SameSite attribute: strict, lax, none
    pub cookie_samesite: String,
}

impl Default for SessionAffinityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cookie_name: "PQCPROXY_BACKEND".to_string(),
            cookie_ttl_secs: 3600,
            cookie_secure: true,
            cookie_httponly: true,
            cookie_samesite: "lax".to_string(),
        }
    }
}

/// Request queue configuration for saturated backends
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueConfig {
    /// Enable request queuing
    pub enabled: bool,
    /// Maximum queue size per pool
    pub max_size: usize,
    /// Queue timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 1000,
            timeout_ms: 5000,
        }
    }
}

/// Slow start configuration for recovering backends
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SlowStartLbConfig {
    /// Enable slow start
    pub enabled: bool,
    /// Duration in seconds for gradual traffic increase
    pub duration_secs: u64,
    /// Initial weight percentage (1-100)
    pub initial_weight_percent: u32,
}

impl Default for SlowStartLbConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            duration_secs: 30,
            initial_weight_percent: 10,
        }
    }
}

/// Connection draining configuration for graceful backend removal
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionDrainingConfig {
    /// Enable connection draining
    pub enabled: bool,
    /// Maximum time to wait for connections to drain (seconds)
    pub timeout_secs: u64,
}

impl Default for ConnectionDrainingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            timeout_secs: 30,
        }
    }
}

/// Backend pool configuration (multiple servers with load balancing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendPoolConfig {
    /// Pool name (used in routes as backend = "name")
    pub name: String,
    /// Load balancing algorithm (overrides global default)
    #[serde(default = "default_lb_algorithm")]
    pub algorithm: String,
    /// Enable health-aware routing (skip unhealthy backends)
    #[serde(default = "default_true")]
    pub health_aware: bool,
    /// Session affinity mode
    #[serde(default)]
    pub affinity: AffinityMode,
    /// Header name for header-based affinity
    pub affinity_header: Option<String>,
    /// Pool-specific queue max size (overrides global)
    pub queue_max_size: Option<usize>,
    /// Pool-specific queue timeout (overrides global)
    pub queue_timeout_ms: Option<u64>,
    /// Health check endpoint path
    pub health_check_path: Option<String>,
    /// Health check interval in seconds
    #[serde(default = "default_pool_health_interval")]
    pub health_check_interval_secs: u64,
    /// Servers in this pool
    #[serde(default)]
    pub servers: Vec<PoolServerConfig>,
    /// Canary deployment configuration for this pool
    #[serde(default)]
    pub canary: Option<CanaryPoolConfig>,
}

fn default_lb_algorithm() -> String {
    "least_connections".to_string()
}

fn default_true() -> bool {
    true
}

fn default_pool_health_interval() -> u64 {
    10
}

/// Pool-level canary deployment configuration.
///
/// When enabled, a fraction of new traffic is probabilistically routed to
/// servers marked `canary = true`, with optional sticky-cookie assignment and
/// automatic rollback on error-rate threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CanaryPoolConfig {
    /// Enable canary routing for this pool (default: false)
    pub enabled: bool,
    /// Stick an assigned client to the same canary via a response cookie (default: true)
    pub sticky: bool,
    /// Name of the sticky-canary Set-Cookie (default: "PQCPROXY_CANARY")
    pub sticky_cookie_name: String,
    /// Max-Age of the sticky cookie in seconds (default: 3600)
    pub sticky_cookie_ttl_secs: u64,
    /// Optional request header that pre-assigns a client to canary (e.g. "X-Canary-Group").
    /// Any request carrying this header (regardless of value) is routed to the canary.
    pub sticky_header: Option<String>,
    /// Automatically suspend the canary when its error rate exceeds `rollback_error_rate` (default: false)
    pub auto_rollback: bool,
    /// Error-rate threshold that triggers auto-rollback (0.0–1.0, default: 0.05 = 5%)
    pub rollback_error_rate: f64,
    /// Sliding window length for error-rate measurement in seconds (default: 60)
    pub rollback_window_secs: u64,
    /// Minimum requests in the window before rollback can trigger (default: 10)
    pub rollback_min_requests: u64,
}

impl Default for CanaryPoolConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sticky: true,
            sticky_cookie_name: "PQCPROXY_CANARY".to_string(),
            sticky_cookie_ttl_secs: 3600,
            sticky_header: None,
            auto_rollback: false,
            rollback_error_rate: 0.05,
            rollback_window_secs: 60,
            rollback_min_requests: 10,
        }
    }
}

/// Individual server within a backend pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolServerConfig {
    /// Server address (host:port)
    pub address: String,
    /// Weight for weighted algorithms (1-1000)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Priority for failover (lower = higher priority)
    #[serde(default = "default_server_priority")]
    pub priority: u32,
    /// Maximum connections to this server
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Request timeout in milliseconds
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// TLS mode for this server
    #[serde(default)]
    pub tls_mode: TlsMode,
    /// TLS certificate for backend verification
    pub tls_cert: Option<PathBuf>,
    /// Skip TLS verification (dangerous)
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Custom SNI hostname
    pub tls_sni: Option<String>,
    /// Circuit breaker: number of consecutive failures before tripping (overrides global default of 5)
    #[serde(default)]
    pub cb_failure_threshold: Option<u32>,
    /// Circuit breaker: number of consecutive successes to close the circuit (overrides global default of 3)
    #[serde(default)]
    pub cb_success_threshold: Option<u32>,
    /// Circuit breaker: half-open delay in seconds (overrides global default of 0)
    #[serde(default)]
    pub cb_half_open_delay_secs: Option<u64>,
    /// Mark this server as a canary deployment target
    #[serde(default)]
    pub canary: bool,
    /// Percentage of new traffic to route to this canary server (0–100).
    /// Only used when canary = true and pool.canary.enabled = true.
    #[serde(default)]
    pub canary_weight_percent: u8,
}

fn default_weight() -> u32 {
    100
}

fn default_server_priority() -> u32 {
    1
}

/// Session affinity mode for sticky sessions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AffinityMode {
    /// No session affinity
    #[default]
    None,
    /// Cookie-based sticky sessions
    Cookie,
    /// IP hash sticky sessions
    IpHash,
    /// Header-based sticky sessions
    Header,
}

impl AffinityMode {
    /// Get header name for the affinity mode
    pub fn header_name(&self) -> &'static str {
        match self {
            Self::Header => "X-Session-ID",
            Self::Cookie => "Cookie",
            Self::IpHash => "X-Forwarded-For",
            Self::None => "",
        }
    }
}

/// CORS configuration for routes
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorsConfig {
    /// Allowed origin (e.g. `https://pqcrypta.com`) — single origin, legacy
    pub allow_origin: Option<String>,
    /// Allowed origins list — when set, the matching request origin is reflected
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// Allowed methods
    #[serde(default)]
    pub allow_methods: Vec<String>,
    /// Allowed headers
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// Allow credentials
    #[serde(default)]
    pub allow_credentials: bool,
    /// Max age for preflight cache
    #[serde(default)]
    pub max_age: u64,
}

impl ConfigManager {
    /// Create a new configuration manager and load initial config
    #[allow(clippy::unused_async_trait_impl)] // public async API; callers .await it
    pub async fn new(
        config_path: impl AsRef<Path>,
    ) -> anyhow::Result<(Self, mpsc::Receiver<ConfigReloadEvent>)> {
        let config_path = config_path.as_ref().to_path_buf();
        let (reload_tx, reload_rx) = mpsc::channel(16);

        // Load initial configuration
        let config = Self::load_config(&config_path)?;
        info!("Configuration loaded from {:?}", config_path);

        let manager = Self {
            config: ArcSwap::new(Arc::new(config)),
            watcher: RwLock::new(None),
            reload_tx,
            config_path,
        };

        Ok((manager, reload_rx))
    }

    /// Load configuration from TOML file
    fn load_config(path: &Path) -> anyhow::Result<ProxyConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read config file {:?}: {}", path, e))?;

        let (mut config, ignored) = parse_config_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file {:?}: {}", path, e))?;
        warn_ignored_keys(path, &ignored);

        config.apply_body_size_override();

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Get current configuration
    pub fn get(&self) -> Arc<ProxyConfig> {
        self.config.load_full()
    }

    /// Atomically swap in a freshly-loaded configuration so subsequent `get()`
    /// calls observe it. The file-watcher path (`start_watching`) emits a reload
    /// event but does not update this `ArcSwap` itself; the reload handler calls
    /// this to keep the central snapshot consistent with what listeners apply.
    pub fn store_config(&self, config: Arc<ProxyConfig>) {
        self.config.store(config);
    }
} // impl ConfigManager

/// Recursively merge two TOML values.
///
/// For `Table` values the overlay keys are merged on top of the base; all
/// other value types are replaced by the overlay value (overlay wins).
fn merge_toml_values(base: toml::Value, overlay: toml::Value) -> toml::Value {
    match (base, overlay) {
        (toml::Value::Table(mut base_table), toml::Value::Table(overlay_table)) => {
            for (key, overlay_val) in overlay_table {
                let merged = match base_table.remove(&key) {
                    Some(base_val) => merge_toml_values(base_val, overlay_val),
                    None => overlay_val,
                };
                base_table.insert(key, merged);
            }
            toml::Value::Table(base_table)
        }
        // For all other combinations the overlay wins unconditionally.
        (_, overlay) => overlay,
    }
}

impl ConfigManager {
    // re-open for remaining methods

    /// Notify listeners that TLS certificates were reloaded
    pub async fn notify_tls_reload(&self) {
        let _ = self
            .reload_tx
            .send(ConfigReloadEvent::TlsCertsReloaded)
            .await;
    }

    /// Manually reload configuration
    pub async fn reload(&self) -> anyhow::Result<()> {
        match Self::load_config(&self.config_path) {
            Ok(new_config) => {
                let new_config = Arc::new(new_config);
                self.config.store(new_config.clone());
                info!("Configuration reloaded successfully");

                // Notify listeners
                let _ = self
                    .reload_tx
                    .send(ConfigReloadEvent::ConfigReloaded(new_config))
                    .await;
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
                let _ = self
                    .reload_tx
                    .send(ConfigReloadEvent::ReloadFailed(e.to_string()))
                    .await;
                Err(e)
            }
        }
    }

    /// Apply an environment-specific TOML overlay on top of the currently loaded config.
    ///
    /// The overlay is a partial TOML file whose keys win over the base config.
    /// Tables are merged recursively; all other value types are replaced.
    /// After merging, `ProxyConfig::validate()` is called so any conflicts introduced
    /// by the overlay are caught at startup.
    pub fn apply_env_overlay(&self, overlay_path: &Path) -> anyhow::Result<()> {
        let overlay_str = std::fs::read_to_string(overlay_path)
            .map_err(|e| anyhow::anyhow!("Failed to read env overlay {:?}: {}", overlay_path, e))?;

        // Serialise the live config back to a TOML value so we can merge.
        let current = self.config.load_full();
        let base_str = toml::to_string(current.as_ref())
            .map_err(|e| anyhow::anyhow!("Failed to serialise base config: {}", e))?;

        let base_val: toml::Value = toml::from_str(&base_str)
            .map_err(|e| anyhow::anyhow!("Failed to re-parse base config: {}", e))?;
        let overlay_val: toml::Value = toml::from_str(&overlay_str).map_err(|e| {
            anyhow::anyhow!("Failed to parse env overlay {:?}: {}", overlay_path, e)
        })?;

        let merged_val = merge_toml_values(base_val, overlay_val);
        let merged_str = toml::to_string(&merged_val)
            .map_err(|e| anyhow::anyhow!("Failed to serialise merged config: {}", e))?;

        let overlay_ignored = parse_config_str(&overlay_str)
            .map(|(_, ignored)| ignored)
            .unwrap_or_default();
        warn_ignored_keys(overlay_path, &overlay_ignored);
        let new_config: ProxyConfig = toml::from_str(&merged_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse merged config: {}", e))?;
        new_config.validate()?;

        self.config.store(Arc::new(new_config));
        info!("Environment overlay applied from {:?}", overlay_path);
        Ok(())
    }

    /// Start watching the configuration file and the TLS cert/key for changes
    ///
    /// Watches PARENT DIRECTORIES, never the files themselves. inotify follows
    /// the inode, and almost every way of replacing a file — `sed -i`, vim, most
    /// editors, certbot's renew-then-rename, any write-temp-then-rename — swaps
    /// it. Watching a file directly therefore fires exactly once and then goes
    /// permanently deaf, with no error and no log line. Measured over three
    /// consecutive `sed -i` edits: file watch [1, 0, 0], directory watch
    /// [3, 3, 3]. Watching the directory and filtering by path survives it.
    pub fn start_watching(&self) -> anyhow::Result<()> {
        let config_path = self.config_path.clone();
        let reload_tx = self.reload_tx.clone();
        let config = Arc::clone(&self.config.load_full());

        // Canonicalise so events (which carry absolute paths) compare equal even
        // when the process was given a relative --config. A path that does not
        // exist yet cannot be canonicalised; fall back to it as given, so a cert
        // that appears later is still recognised.
        let canon = |p: &Path| -> PathBuf { p.canonicalize().unwrap_or_else(|_| p.to_path_buf()) };

        let config_file = canon(&config_path);
        let cert_file = canon(&config.tls.cert_path);
        let key_file = canon(&config.tls.key_path);

        // Directories to watch, deduplicated — cert and key usually share one,
        // and may well be the config directory too. Watching the same path twice
        // would just deliver every event twice.
        let mut dirs: Vec<PathBuf> = Vec::new();
        let add_dir = |p: &Path, dirs: &mut Vec<PathBuf>| {
            if let Some(d) = p.parent() {
                if d.as_os_str().is_empty() || !d.is_dir() {
                    return;
                }
                let d = canon(d);
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        };
        add_dir(&config_file, &mut dirs);
        add_dir(&cert_file, &mut dirs);
        add_dir(&key_file, &mut dirs);
        if dirs.is_empty() {
            anyhow::bail!("no watchable directory for config {:?}", config_file);
        }

        let ev_config = config_file.clone();
        let ev_cert = cert_file.clone();
        let ev_key = key_file.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if !(event.kind.is_modify() || event.kind.is_create()) {
                        return;
                    }
                    // A directory watch also reports siblings — editor swap files,
                    // .bak copies, certbot's staging files — so dispatch strictly
                    // on which watched path the event names.
                    let hit_config = event.paths.iter().any(|p| p == &ev_config);
                    let hit_tls = event.paths.iter().any(|p| p == &ev_cert || p == &ev_key);

                    if hit_config {
                        debug!("Config file change detected: {:?}", event);
                        match Self::load_config(&config_path) {
                            Ok(new_config) => {
                                let new_config = Arc::new(new_config);
                                info!("Configuration hot-reloaded");
                                // blocking send: this closure is not async
                                let _ = reload_tx
                                    .blocking_send(ConfigReloadEvent::ConfigReloaded(new_config));
                            }
                            Err(e) => {
                                error!("Failed to hot-reload configuration: {}", e);
                                let _ = reload_tx
                                    .blocking_send(ConfigReloadEvent::ReloadFailed(e.to_string()));
                            }
                        }
                    }

                    if hit_tls {
                        // Previously a cert change fell through to the config
                        // branch, which re-read the TOML and never re-read the
                        // certificate off disk — so the watcher could not
                        // actually reload a renewed cert. Emit the event that
                        // main.rs and quic_listener.rs already handle.
                        info!("TLS certificate or key changed on disk");
                        let _ = reload_tx.blocking_send(ConfigReloadEvent::TlsCertsReloaded);
                    }
                }
                Err(e) => {
                    warn!("Config file watch error: {}", e);
                }
            }
        })?;

        for d in &dirs {
            watcher.watch(d, RecursiveMode::NonRecursive)?;
            info!("Watching directory {:?}", d);
        }
        info!(
            "Config watch target {:?}; TLS watch targets {:?} and {:?}",
            config_file, cert_file, key_file
        );

        *self.watcher.write() = Some(watcher);
        info!("Configuration file watching enabled");

        Ok(())
    }

    /// Stop watching configuration file
    pub fn stop_watching(&self) {
        *self.watcher.write() = None;
        info!("Configuration file watching disabled");
    }
}

/// M-3: Validate an ACME domain name against RFC 1035 rules and path-safety requirements.
///
/// Rejects domains containing '/', '\\', '..', null bytes, or characters that are
/// not permitted in domain names, preventing path traversal in certificate file paths.
pub fn validate_acme_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("domain name is empty".to_string());
    }
    if domain.len() > 253 {
        return Err(format!(
            "domain name exceeds 253 characters (len={})",
            domain.len()
        ));
    }
    // Reject path-traversal characters and null bytes
    if domain.contains('/') {
        return Err("domain name contains '/'".to_string());
    }
    if domain.contains('\\') {
        return Err("domain name contains '\\'".to_string());
    }
    if domain.contains("..") {
        return Err("domain name contains '..'".to_string());
    }
    if domain.contains('\0') {
        return Err("domain name contains a null byte".to_string());
    }
    // Only allow RFC 1035 characters: letters, digits, hyphens, dots, and leading '*' for wildcards
    let valid = domain
        .chars()
        .enumerate()
        .all(|(i, c)| c.is_ascii_alphanumeric() || c == '-' || c == '.' || (c == '*' && i == 0));
    if !valid {
        return Err(format!(
            "domain name '{}' contains characters not permitted by RFC 1035",
            domain
        ));
    }
    Ok(())
}

/// SEC-009 / F-01: Validate a backend address against dangerous IP ranges to
/// prevent Server-Side Request Forgery (SSRF) attacks.
///
/// Rules:
///   • Link-local (169.254.0.0/16, fe80::/10): **always rejected** — these ranges
///     host cloud metadata services (AWS IMDSv1/v2, GCP, Azure) whose exposure
///     via a proxy is an unconditional SSRF vulnerability.
///   • Loopback + RFC1918: warn unless `allow_internal` is `true`.
///   • Known dangerous hostnames (e.g. `169.254.169.254`) are caught before IP
///     parsing so that operator typos are flagged early.
///   • Hostnames that do not resolve to an IP at config-load time are skipped
///     (DNS is not resolved here; operators should ensure backends are IPs).
fn validate_backend_address_ssrf(address: &str, allow_internal: bool) -> anyhow::Result<()> {
    use std::net::IpAddr;

    // Strip scheme prefix (e.g. unix: paths are not IP-based — skip them)
    if address.starts_with("unix:") || address.starts_with('/') {
        return Ok(());
    }

    // Extract host from host:port — handle IPv6 brackets: [::1]:8080
    let host = if address.starts_with('[') {
        // IPv6 bracket notation: [addr]:port
        address.find(']').map(|i| &address[1..i]).unwrap_or(address)
    } else {
        // IPv4 or hostname: strip trailing :port
        address.rfind(':').map_or(address, |i| &address[..i])
    };

    // Block well-known dangerous hostnames before IP parsing
    const METADATA_HOSTS: &[&str] = &[
        "169.254.169.254", // AWS/Azure IMDSv1, GCP
        "169.254.170.2",   // AWS ECS metadata
        "metadata.google.internal",
        "metadata",
        "instance-data", // common internal alias
    ];
    if METADATA_HOSTS.contains(&host) {
        return Err(anyhow::anyhow!(
            "SEC-009 / F-01: Backend '{}' resolves to a well-known cloud metadata service. \
             Routing requests here would create an SSRF vulnerability allowing attackers \
             to extract IAM credentials.  Use a non-link-local backend address.",
            address
        ));
    }

    // Check if the host is a parseable IP address for range validation
    let Ok(ip) = host.parse::<IpAddr>() else {
        // SEC-04: Hostname backends cannot have their IP range validated at config load
        // because DNS resolution is deferred. A hostname that resolves to a link-local or
        // cloud-metadata address (e.g. 169.254.169.254) would bypass SSRF protection.
        // Operators must ensure backend hostnames only resolve to trusted addresses.
        warn!(
            "SEC-04: Backend '{}' is a hostname — SSRF range check skipped (DNS not resolved at \
             config load). Ensure this hostname cannot resolve to a private/link-local address.",
            address
        );
        return Ok(());
    };

    // Link-local (169.254.0.0/16 or fe80::/10) — hard reject, no override
    let is_link_local = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            o[0] == 0xfe && (o[1] & 0xc0) == 0x80
        }
    };
    if is_link_local {
        return Err(anyhow::anyhow!(
            "SEC-009 / F-01: Backend '{}' is in the link-local range \
             (169.254.0.0/16 or fe80::/10).  This range hosts cloud metadata services \
             (AWS IMDSv1/v2, GCP, Azure) — proxying requests here is an SSRF \
             vulnerability.  This restriction cannot be disabled.",
            address
        ));
    }

    // RFC1918 / loopback — warn unless explicitly permitted
    if !allow_internal {
        let is_private = match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 127                                              // loopback
                    || o[0] == 10                                        // 10.0.0.0/8
                    || (o[0] == 172 && (16..=31).contains(&o[1]))       // 172.16.0.0/12
                    || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16
            }
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        if is_private {
            warn!(
                "SEC-009 / F-01: Backend '{}' is in a private/loopback range.  In cloud \
                 environments this could expose internal services.  If intentional, set \
                 `allow_internal_backends = true` in [security] to suppress this warning.",
                address
            );
        }
    }

    Ok(())
}

/// `haystack.starts_with(prefix)`, ASCII-case-insensitively, without allocating.
fn starts_with_ignore_ascii_case(haystack: &str, prefix: &str) -> bool {
    haystack.len() >= prefix.len()
        && haystack.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

/// `haystack.ends_with(suffix)`, ASCII-case-insensitively, without allocating.
fn ends_with_ignore_ascii_case(haystack: &str, suffix: &str) -> bool {
    haystack.len() >= suffix.len()
        && haystack.as_bytes()[haystack.len() - suffix.len()..]
            .eq_ignore_ascii_case(suffix.as_bytes())
}

impl ProxyConfig {
    /// `[admin]` with its TLS paths filled from `[tls]` where it names none.
    pub fn admin_resolved(&self) -> AdminConfig {
        let mut admin = self.admin.clone();
        admin
            .tls_cert_path
            .get_or_insert_with(|| self.tls.cert_path.clone());
        admin
            .tls_key_path
            .get_or_insert_with(|| self.tls.key_path.clone());
        if admin.client_ca_path.is_none() {
            admin.client_ca_path = self.tls.ca_cert_path.clone();
        }
        admin
    }

    /// How the listeners ask for client certificates: required of every
    /// client when `tls.require_client_cert` is set; requested but optional
    /// when only some routes need one, so the TLS layer still carries the
    /// certificate to the route gate that decides; not requested otherwise.
    ///
    /// Without the middle case a route with `mtls_required` could never be
    /// satisfied unless every route required a certificate: no listener asked
    /// for one, so no client ever sent one.
    pub fn client_auth(&self) -> ClientAuth {
        if self.tls.require_client_cert {
            ClientAuth::Required
        } else if self.routes.iter().any(RouteConfig::requires_client_cert) {
            ClientAuth::Requested
        } else {
            ClientAuth::None
        }
    }

    /// Validate the configuration
    /// Fold `server.max_request_body_bytes` into the limit that is actually
    /// enforced (`security.max_request_size`).
    ///
    /// Two settings named for the same thing is the real defect here; only the
    /// security one was ever read. Rather than have one silently lose, an
    /// explicit server-side value now wins and says so, and leaving it unset
    /// changes nothing.
    pub fn apply_body_size_override(&mut self) {
        if let Some(limit) = self.server.max_request_body_bytes {
            let Ok(limit) = usize::try_from(limit) else {
                warn!(
                    "server.max_request_body_bytes = {} does not fit in usize on this platform — ignoring",
                    limit
                );
                return;
            };
            if limit != self.security.max_request_size {
                info!(
                    "server.max_request_body_bytes = {} overrides security.max_request_size = {}",
                    limit, self.security.max_request_size
                );
            }
            self.security.max_request_size = limit;
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        // Config schema version check
        match self.version {
            None => {
                warn!("Config missing 'version' field — assuming v{}. Add `version = 1` to suppress this warning.", CURRENT_CONFIG_VERSION);
            }
            Some(v) if v > CURRENT_CONFIG_VERSION => {
                return Err(anyhow::anyhow!(
                    "Config version {} is newer than this binary supports (max {}). \
                     Please upgrade pqcrypta-proxy.",
                    v,
                    CURRENT_CONFIG_VERSION
                ));
            }
            Some(_) => {}
        }

        for (i, r) in self.http3.preload_resources.iter().enumerate() {
            match r.rel.as_str() {
                "preload" if r.as_type.is_empty() => {
                    return Err(anyhow::anyhow!(
                        "http3.preload_resources[{i}] ({}): rel = \"preload\" needs as_type",
                        r.href
                    ));
                }
                "preload" | "modulepreload" | "preconnect" | "dns-prefetch" | "prerender" => {}
                other => {
                    return Err(anyhow::anyhow!(
                        "http3.preload_resources[{i}] ({}): rel {other:?} is not one of \
                         preload, modulepreload, preconnect, dns-prefetch, prerender",
                        r.href
                    ));
                }
            }
        }

        if !matches!(self.http_redirect.redirect_status, 301 | 302 | 307 | 308) {
            return Err(anyhow::anyhow!(
                "http_redirect.redirect_status must be 301, 302, 307 or 308, not {}",
                self.http_redirect.redirect_status
            ));
        }

        if let Err(e) = crate::access_logger::LogFormat::parse(&self.logging.access_log_format) {
            return Err(anyhow::anyhow!("logging.access_log_format: {e}"));
        }

        if !self.server.request_id_header.is_empty()
            && crate::request_id::header_name(&self.server.request_id_header).is_none()
        {
            return Err(anyhow::anyhow!(
                "server.request_id_header {:?} is not a valid header name",
                self.server.request_id_header
            ));
        }

        if let Err(e) = regex::RegexSet::new(&self.waf.scanner_ua_exempt_paths) {
            return Err(anyhow::anyhow!("waf.scanner_ua_exempt_paths: {e}"));
        }

        // `headers_override` takes literal header names, while `[headers]` spells
        // the same headers as snake_case TOML keys. Copying one into the other
        // produced `cross_origin_embedder_policy: unsafe-none` on the wire — a
        // header no browser reads — while the real policy stayed in force.
        // Refuse a snake_case spelling of a header the proxy itself manages.
        {
            const MANAGED: &[&str] = &[
                "strict-transport-security",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
                "cross-origin-opener-policy",
                "cross-origin-embedder-policy",
                "cross-origin-resource-policy",
                "x-permitted-cross-domain-policies",
                "x-download-options",
                "x-dns-prefetch-control",
                "content-security-policy",
                "access-control-allow-origin",
                "cache-control",
            ];
            let bad: Vec<String> = self
                .routes
                .iter()
                .flat_map(|r| {
                    r.headers_override.keys().filter_map(move |k| {
                        let dashed = k.to_ascii_lowercase().replace('_', "-");
                        (k.contains('_') && MANAGED.contains(&dashed.as_str())).then(|| {
                            format!(
                                "route {:?}: headers_override key {k:?} (did you mean {dashed:?}?)",
                                r.name.as_deref().unwrap_or("<unnamed>")
                            )
                        })
                    })
                })
                .collect();
            if !bad.is_empty() {
                return Err(anyhow::anyhow!(
                    "headers_override takes header names, not [headers] keys: {}",
                    bad.join("; ")
                ));
            }
        }

        // An unknown load balancing algorithm used to fall through to
        // `least_connections` in silence. An operator who wrote `ip_hash ` with a
        // stray space, or `leastconn` from HAProxy muscle memory, would get
        // round-robin-ish behaviour and no way to discover it — sticky sessions
        // simply would not stick. Refuse it at load instead.
        {
            let mut bad: Vec<String> = Vec::new();
            if !crate::load_balancer::BackendPool::is_known_algorithm(
                &self.load_balancer.default_algorithm,
            ) {
                bad.push(format!(
                    "load_balancer.default_algorithm = {:?}",
                    self.load_balancer.default_algorithm
                ));
            }
            for (pool_name, pool) in &self.backend_pools {
                if !crate::load_balancer::BackendPool::is_known_algorithm(&pool.algorithm) {
                    bad.push(format!(
                        "backend_pools[{pool_name:?}].algorithm = {:?}",
                        pool.algorithm
                    ));
                }
            }
            if !bad.is_empty() {
                return Err(anyhow::anyhow!(
                    "Unknown load balancing algorithm: {}. Supported: {}.",
                    bad.join(", "),
                    crate::load_balancer::BackendPool::ALGORITHMS.join(", ")
                ));
            }
        }

        // Config conflict: mTLS required but no CA cert
        if self.tls.require_client_cert && self.tls.ca_cert_path.is_none() {
            return Err(anyhow::anyhow!(
                "tls.require_client_cert = true but tls.ca_cert_path is not set. \
                 Provide a CA certificate path to verify client certificates."
            ));
        }
        // The same for a route that needs one: without a CA the listeners would
        // verify against the system roots, and any publicly issued certificate
        // would satisfy the route.
        if self.client_auth() == ClientAuth::Requested && self.tls.ca_cert_path.is_none() {
            let routes: Vec<&str> = self
                .routes
                .iter()
                .filter(|r| r.requires_client_cert())
                .map(|r| r.name.as_deref().unwrap_or("(unnamed)"))
                .collect();
            return Err(anyhow::anyhow!(
                "route(s) {} require a client certificate (mtls_required, or internal = true) \
                 but tls.ca_cert_path is not set. Provide the CA that issues them.",
                routes.join(", ")
            ));
        }

        // Admin mTLS needs a CA to verify client certificates against.
        if self.admin.require_mtls
            && self.admin.client_ca_path.is_none()
            && self.tls.ca_cert_path.is_none()
        {
            return Err(anyhow::anyhow!(
                "admin.require_mtls = true but neither admin.client_ca_path nor \
                 tls.ca_cert_path is set. Provide the CA that issues admin client certificates."
            ));
        }

        // Config conflict: 0-RTT enabled with non-safe methods and no replay protection
        if self.tls.enable_0rtt && self.tls.zero_rtt_replay_protection == "none" {
            for route in &self.routes {
                if route.allow_0rtt {
                    // Check if any non-safe method route could accept 0-RTT
                    warn!(
                        "SEC-11: Route {:?} has allow_0rtt = true with zero_rtt_replay_protection = \"none\". \
                         This allows replay attacks. Use \"strict\" or \"session\" replay protection.",
                        route.name
                    );
                }
            }
        }

        // Config conflict: WebTransport routes but no allowed origins
        let has_wt_routes = self.routes.iter().any(|r| r.webtransport);
        if has_wt_routes && self.server.webtransport_allowed_origins.is_empty() {
            warn!(
                "SR-02: WebTransport routes are configured but server.webtransport_allowed_origins is empty. \
                 All cross-origin WebTransport sessions will be rejected. \
                 Set webtransport_allowed_origins to your frontend origins."
            );
        }

        // MASQUE / CONNECT-UDP: enabled with no allowlist accepts no targets.
        if self.masque.enabled && self.masque.allowed_targets.is_empty() {
            warn!(
                "masque.enabled = true but masque.allowed_targets is empty. \
                 Every CONNECT-UDP request will be rejected with 403. \
                 Add entries like \"host:port\" (host/port may be \"*\")."
            );
        }

        // PQC passthrough conflict
        for route in &self.routes {
            if let Some(backend_name) = route.backend.split(',').next() {
                if let Some(backend) = self.backends.get(backend_name.trim()) {
                    if backend.tls_mode == TlsMode::Passthrough && self.pqc.enabled {
                        warn!(
                            "Route {:?} backend '{}' uses TLS passthrough — PQC headers cannot \
                             be added to passthrough connections.",
                            route.name, backend_name
                        );
                    }
                }
            }
        }

        // Validate server config
        self.server
            .socket_addr()
            .map_err(|e| anyhow::anyhow!("Invalid server bind address: {}", e))?;

        // Validate TLS config
        if !self.tls.cert_path.exists() {
            warn!("TLS certificate not found: {:?}", self.tls.cert_path);
        }
        if !self.tls.key_path.exists() {
            warn!("TLS private key not found: {:?}", self.tls.key_path);
        }

        // Validate routes reference existing backends or backend_pools (unless they're redirect routes)
        for route in &self.routes {
            // SEC-09: Validate redirect target to prevent open redirect.
            // Only relative paths (starting with '/') are allowed by default.
            // Absolute URLs pointing to unknown origins are rejected.
            if let Some(ref redirect_target) = route.redirect {
                if !redirect_target.starts_with('/') {
                    return Err(anyhow::anyhow!(
                        "Route {:?}: redirect target '{}' must be a relative path starting with \
                         '/' to prevent open redirect. Absolute URLs pointing to external \
                         origins are not permitted.",
                        route.name,
                        redirect_target
                    ));
                }
                // Reject any attempt to embed absolute URL components in a relative path
                if redirect_target.contains("://") || redirect_target.contains("//") {
                    return Err(anyhow::anyhow!(
                        "Route {:?}: redirect target '{}' contains a protocol separator — \
                         use a plain relative path to prevent open redirect.",
                        route.name,
                        redirect_target
                    ));
                }
                continue;
            }

            // Check if backend exists in either backends or backend_pools
            let backend_exists = self.backends.contains_key(&route.backend)
                || self.backend_pools.contains_key(&route.backend);

            if route.backend.is_empty() || !backend_exists {
                return Err(anyhow::anyhow!(
                    "Route {:?} references unknown backend or pool: {}",
                    route.name,
                    route.backend
                ));
            }

            // Validate path_regex to prevent ReDoS attacks
            if let Some(ref regex_str) = route.path_regex {
                // Check regex length limit (prevent extremely long patterns)
                if regex_str.len() > 1024 {
                    return Err(anyhow::anyhow!(
                        "Route {:?} has path_regex exceeding 1024 characters (ReDoS prevention)",
                        route.name
                    ));
                }

                // Validate regex compiles and use regex with size limits
                match regex::RegexBuilder::new(regex_str)
                    .size_limit(1024 * 1024) // 1MB compiled size limit
                    .build()
                {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Route {:?} has invalid path_regex '{}': {}",
                            route.name,
                            regex_str,
                            e
                        ));
                    }
                }
            }

            // Validate host pattern format
            if let Some(ref pattern) = route.host {
                if pattern.starts_with("*.") && pattern.len() <= 2 {
                    return Err(anyhow::anyhow!(
                        "Route {:?} has invalid wildcard host pattern '{}' (missing domain)",
                        route.name,
                        pattern
                    ));
                }
            }

            // SEC-11: Warn whenever allow_0rtt is explicitly enabled on a route.
            // 0-RTT early data may be replayed by the TLS layer, delivering POST/PUT/
            // DELETE/PATCH requests twice with no indication to the backend. Operators
            // must ensure this route only handles GET/HEAD (idempotent) traffic, or
            // that the backend implements idempotency-key deduplication.
            if route.allow_0rtt {
                warn!(
                    "SEC-11: Route {:?} has allow_0rtt = true. TLS 0-RTT early data is \
                     susceptible to replay attacks. Ensure this route only accepts idempotent \
                     methods (GET, HEAD) and that backends handle duplicate requests safely. \
                     Set allow_0rtt = false if in doubt.",
                    route.name
                );
            }

            // SEC-004: Reject wildcard CORS origin combined with allow_credentials.
            // The CORS spec (and all modern browsers) forbid Access-Control-Allow-Origin: *
            // with Access-Control-Allow-Credentials: true.  Silently emitting this combination
            // causes confusing client failures and may expose credentials to unintended origins
            // in non-compliant clients.  Fail at config load time rather than at request time.
            if let Some(ref cors) = route.cors {
                if cors.allow_credentials && cors.allow_origin.as_deref() == Some("*") {
                    return Err(anyhow::anyhow!(
                        "Route {:?} has a CORS misconfiguration: allow_credentials = true cannot \
                         be combined with allow_origin = \"*\" (RFC 6454, CORS specification). \
                         All modern browsers will refuse this combination. Set allow_origin to a \
                         specific origin (e.g. \"https://pqcrypta.com\") instead of the wildcard.",
                        route.name
                    ));
                }
            }
        }

        // Validate backend pool server addresses
        for (name, pool) in &self.backend_pools {
            if pool.servers.is_empty() {
                return Err(anyhow::anyhow!(
                    "Backend pool '{}' has no servers configured",
                    name
                ));
            }
            for server in &pool.servers {
                if server.address.parse::<std::net::SocketAddr>().is_err() {
                    return Err(anyhow::anyhow!(
                        "Invalid server address '{}' in pool '{}'",
                        server.address,
                        name
                    ));
                }
                // SEC-009 / F-01: SSRF check on pool server addresses
                validate_backend_address_ssrf(
                    &server.address,
                    self.security.allow_internal_backends,
                )?;
            }
        }

        // SEC-009 / F-01: SSRF check on all named backend addresses
        for (backend_name, backend) in &self.backends {
            if let Err(e) = validate_backend_address_ssrf(
                &backend.address,
                self.security.allow_internal_backends,
            ) {
                return Err(anyhow::anyhow!(
                    "Backend '{}' failed SSRF validation: {}",
                    backend_name,
                    e
                ));
            }
        }

        // Validate admin config
        if self.admin.enabled {
            self.admin
                .socket_addr()
                .map_err(|e| anyhow::anyhow!("Invalid admin bind address: {}", e))?;

            // SEC-005: Enforce a minimum token length to reject trivially weak tokens.
            // A token shorter than 32 characters offers insufficient entropy against
            // offline dictionary or brute-force attacks.
            if let Some(ref token) = self.admin.auth_token {
                if token.len() < 32 {
                    return Err(anyhow::anyhow!(
                        "Admin API auth_token is too short ({} characters). \
                         The token must be at least 32 characters to ensure sufficient entropy. \
                         Generate a strong token with: openssl rand -base64 48",
                        token.len()
                    ));
                }
            }

            // H-1: Require auth_token OR loopback-only allowed_ips for admin API.
            // An admin API with no token and no IP restriction is unauthenticated.
            if self.admin.auth_token.is_none() {
                let loopback_prefixes = ["127.", "::1", "localhost"];
                let is_loopback_only = !self.admin.allowed_ips.is_empty()
                    && self.admin.allowed_ips.iter().all(|ip| {
                        loopback_prefixes
                            .iter()
                            .any(|prefix| ip.starts_with(prefix) || ip.as_str() == *prefix)
                    });

                if !is_loopback_only {
                    return Err(anyhow::anyhow!(
                        "Admin API security error: `auth_token` must be configured in [admin] \
                         when `allowed_ips` is not restricted to loopback addresses (127.x.x.x, ::1). \
                         Current allowed_ips: {:?}. \
                         Either set `auth_token = \"<secret>\"` or ensure `allowed_ips` contains \
                         only loopback addresses.",
                        self.admin.allowed_ips
                    ));
                }
            }
        }

        // SEC-001: Reject tls_skip_verify in production environments.
        // Production is indicated by ACME being enabled (real domain) or PQCRYPTA_ENV=production.
        {
            let is_production =
                self.acme.enabled || std::env::var("PQCRYPTA_ENV").as_deref() == Ok("production");

            if is_production {
                let signal = if self.acme.enabled {
                    "ACME is enabled (production domain detected)"
                } else {
                    "PQCRYPTA_ENV=production environment variable"
                };

                for (name, backend) in &self.backends {
                    if backend.tls_skip_verify {
                        return Err(anyhow::anyhow!(
                            "Backend '{}' has tls_skip_verify = true, which is forbidden in \
                             production environments (detected via {}). Use a valid CA-signed \
                             certificate. To allow this only in non-production deployments, \
                             set PQCRYPTA_ENV=development.",
                            name,
                            signal
                        ));
                    }
                }

                for (pool_name, pool) in &self.backend_pools {
                    for server in &pool.servers {
                        if server.tls_skip_verify {
                            return Err(anyhow::anyhow!(
                                "A server in backend pool '{}' has tls_skip_verify = true, which \
                                 is forbidden in production environments (detected via {}). Use a \
                                 valid CA-signed certificate. To allow this only in \
                                 non-production deployments, set PQCRYPTA_ENV=development.",
                                pool_name,
                                signal
                            ));
                        }
                    }
                }
            }
        }

        // M-3: Validate ACME domain names against RFC 1035 before they are used in file paths.
        // Domain names are used directly in PathBuf::join(); a domain like "../etc/cron.d/evil"
        // would result in arbitrary file writes.
        if self.acme.enabled {
            for domain in &self.acme.domains {
                validate_acme_domain(domain)
                    .map_err(|e| anyhow::anyhow!("Invalid ACME domain '{}': {}", domain, e))?;
            }
        }

        Ok(())
    }

    /// Find matching route for a request
    pub fn find_route(
        &self,
        host: Option<&str>,
        path: &str,
        is_webtransport: bool,
    ) -> Option<&RouteConfig> {
        // Lowest priority wins. This used to collect every match into a Vec and
        // sort it, allocating on a path that runs for every request on every
        // transport; a single min pass gives the same answer with no allocation.
        // `min_by_key` keeps the *first* of equal keys, which is the same route
        // a stable sort would have put first.
        self.routes
            .iter()
            .filter(|r| self.route_matches(r, host, path, is_webtransport))
            .min_by_key(|r| r.priority)
    }

    /// Check if a route matches the request
    /// All path and host comparisons are case-insensitive (lowercased)
    fn route_matches(
        &self,
        route: &RouteConfig,
        host: Option<&str>,
        path: &str,
        is_webtransport: bool,
    ) -> bool {
        // Check WebTransport requirement
        if route.webtransport && !is_webtransport {
            return false;
        }

        // Check host pattern (case-insensitive)
        if let Some(ref pattern) = route.host {
            if let Some(h) = host {
                if !self.host_matches(pattern, h) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check path - exact match takes priority (case-insensitive)
        if let Some(ref exact) = route.path_exact {
            return path.eq_ignore_ascii_case(exact);
        }

        // Check path regex. Compiled once into the route's OnceLock and reused;
        // it was previously rebuilt from source here, on every request, for
        // every route carrying one. The regex is built case-insensitive, so it
        // matches the raw path and needs no lowercased copy of it.
        if let Some(ref regex_str) = route.path_regex {
            let compiled = route.compiled_path_regex.get_or_init(|| {
                regex::RegexBuilder::new(regex_str)
                    .case_insensitive(true)
                    .size_limit(1024 * 1024)
                    .build()
                    .ok()
            });
            // A pattern that will not compile matches nothing, rather than being
            // silently skipped so the route matches everything after it.
            return compiled.as_ref().is_some_and(|re| re.is_match(path));
        }

        // Check path prefix (case-insensitive)
        if let Some(ref prefix) = route.path_prefix {
            if !starts_with_ignore_ascii_case(path, prefix) {
                return false;
            }
        }

        true
    }

    /// Check if host matches pattern (supports wildcards)
    /// Case-insensitive comparison
    fn host_matches(&self, pattern: &str, host: &str) -> bool {
        if let Some(rest) = pattern.strip_prefix("*.") {
            // Wildcard subdomain: `*.example.com` matches `api.example.com` and
            // the apex `example.com` itself.
            ends_with_ignore_ascii_case(host, &pattern[1..]) || host.eq_ignore_ascii_case(rest)
        } else {
            pattern.eq_ignore_ascii_case(host)
        }
    }

    /// Get backend by name
    pub fn get_backend(&self, name: &str) -> Option<&BackendConfig> {
        self.backends.get(name)
    }
}

/// Does `ip` appear in a `pentest_bypass_ips`-style list?
///
/// Compares PARSED addresses, not strings. `IpAddr::to_string()` emits the
/// canonical compressed form, so a string comparison silently fails for every
/// other valid spelling of the same IPv6 address — `2607:f1c0:f064:5800:0:0:0:1`
/// and `2607:F1C0:F064:5800::1` are the same host but neither matches
/// `2607:f1c0:f064:5800::1`. An operator editing this list by hand should not
/// have to guess Rust's formatting to make a bypass take effect.
pub fn ip_list_contains(list: &[String], ip: &std::net::IpAddr) -> bool {
    list.iter().any(|entry| {
        entry
            .trim()
            .parse::<std::net::IpAddr>()
            .map(|parsed| &parsed == ip)
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        // Verify defaults exist and are sensible - actual values come from config
        assert!(config.server.udp_port > 0);
        assert!(config.admin.port > 0);
        assert!(config.pqc.enabled);
    }

    #[test]
    fn headers_override_refuses_a_snake_case_managed_header() {
        let mut config = ProxyConfig::default();
        let mut r = route(None, Some("/grafana"), None, None, 3);
        r.headers_override
            .insert("cross_origin_embedder_policy".into(), "unsafe-none".into());
        config.routes.push(r);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("cross-origin-embedder-policy"), "{err}");

        // The header name itself is accepted, and so is an unmanaged underscore.
        let mut r = route(None, Some("/grafana"), None, None, 3);
        r.headers_override
            .insert("cross-origin-embedder-policy".into(), "unsafe-none".into());
        r.headers_override.insert("x_custom".into(), "1".into());
        config.routes = vec![r];
        if let Err(e) = config.validate() {
            assert!(!e.to_string().contains("headers_override"), "{e}");
        }
    }

    #[test]
    fn set_cookie_policy_matches_attributes_by_name() {
        let mut r = route(None, Some("/"), None, None, 1);
        assert_eq!(r.rewrite_set_cookie("a=1"), None, "no policy, no change");

        r.enforce_cookie_security = true;
        // A cookie NAMED securetoken does not carry the Secure attribute.
        assert_eq!(
            r.rewrite_set_cookie("securetoken=1; Path=/").as_deref(),
            Some("securetoken=1; Path=/; HttpOnly; Secure")
        );
        assert_eq!(r.rewrite_set_cookie("a=1; Secure; HttpOnly"), None);

        r.enforce_cookie_security = false;
        r.set_cookie_domain = Some("example.test".into());
        assert_eq!(
            r.rewrite_set_cookie("sid=x; Path=/").as_deref(),
            Some("sid=x; Path=/; Domain=example.test")
        );
        // Idempotent, so a cached, already-rewritten header is left alone.
        assert_eq!(
            r.rewrite_set_cookie("sid=x; Path=/; Domain=example.test"),
            None
        );
    }

    #[test]
    fn ignored_keys_are_reported_with_their_path() {
        // The production defect: keys after an array-of-tables header belong
        // to its last entry, where nothing reads them.
        let (_, ignored) = parse_config_str(
            "[http3]\ncoalescing_enabled = true\n[[http3.preload_resources]]\nhost = \"a\"\npath = \"/\"\nhref = \"/x.css\"\nas_type = \"style\"\ncoalescing_max_wait_ms = 5\n[headers]\nstrict_transport_security = \"x\"\n",
        )
        .unwrap();
        assert!(
            ignored
                .iter()
                .any(|k| k == "http3.preload_resources.0.coalescing_max_wait_ms"),
            "{ignored:?}"
        );
        assert!(
            ignored
                .iter()
                .any(|k| k == "headers.strict_transport_security"),
            "{ignored:?}"
        );
        let (_, clean) = parse_config_str("[headers]\nhsts = \"x\"\n").unwrap();
        assert!(clean.is_empty(), "{clean:?}");
    }

    #[test]
    fn redirect_status_is_validated() {
        let mut c = ProxyConfig::default();
        c.http_redirect.redirect_status = 200;
        assert!(c
            .validate()
            .unwrap_err()
            .to_string()
            .contains("redirect_status"));
        c.http_redirect.redirect_status = 301;
        if let Err(e) = c.validate() {
            assert!(!e.to_string().contains("redirect_status"), "{e}");
        }
    }

    /// Build a route carrying just the matching fields under test.
    fn route(
        host: Option<&str>,
        prefix: Option<&str>,
        exact: Option<&str>,
        rx: Option<&str>,
        priority: i32,
    ) -> RouteConfig {
        let mut r: RouteConfig = serde_json::from_str(r#"{"backend":"b"}"#).expect("minimal route");
        r.host = host.map(String::from);
        r.path_prefix = prefix.map(String::from);
        r.path_exact = exact.map(String::from);
        r.path_regex = rx.map(String::from);
        r.priority = priority;
        r
    }

    fn config_with(routes: Vec<RouteConfig>) -> ProxyConfig {
        ProxyConfig {
            routes,
            ..Default::default()
        }
    }

    #[test]
    fn path_prefix_matches_case_insensitively_without_allocating() {
        let c = config_with(vec![route(None, Some("/API"), None, None, 1)]);
        assert!(c.find_route(None, "/api/v1/thing", false).is_some());
        assert!(c.find_route(None, "/ApI/v1", false).is_some());
        assert!(c.find_route(None, "/other", false).is_none());
    }

    #[test]
    fn path_exact_matches_only_the_exact_path() {
        let c = config_with(vec![route(None, None, Some("/Health"), None, 1)]);
        assert!(c.find_route(None, "/health", false).is_some());
        assert!(c.find_route(None, "/HEALTH", false).is_some());
        assert!(
            c.find_route(None, "/health/sub", false).is_none(),
            "exact must not match a longer path"
        );
    }

    #[test]
    fn path_regex_matches_and_is_compiled_once() {
        let c = config_with(vec![route(None, None, None, Some(r"\.(woff2?|ttf)$"), 1)]);
        assert!(c.find_route(None, "/fonts/a.woff2", false).is_some());
        assert!(
            c.find_route(None, "/fonts/A.TTF", false).is_some(),
            "case-insensitive"
        );
        assert!(c.find_route(None, "/fonts/a.png", false).is_none());

        // The compiled regex is cached on the route rather than rebuilt: after a
        // match the slot is populated, which is what makes repeat requests cheap.
        assert!(
            c.routes[0].compiled_path_regex.get().is_some(),
            "regex should be compiled and cached after first use"
        );
    }

    #[test]
    fn an_uncompilable_regex_matches_nothing_rather_than_everything() {
        // Unbalanced bracket: it cannot compile. The route must then match no
        // path at all, never fall through to matching every path.
        let c = config_with(vec![route(None, None, None, Some("[unclosed"), 1)]);
        assert!(c.find_route(None, "/anything", false).is_none());
    }

    #[test]
    fn lowest_priority_wins_and_ties_keep_declaration_order() {
        let c = config_with(vec![
            route(None, Some("/"), None, None, 10),
            route(None, Some("/api"), None, None, 2),
            route(None, Some("/api"), None, None, 2),
        ]);
        let hit = c
            .find_route(None, "/api/x", false)
            .expect("a route matches");
        assert_eq!(hit.priority, 2);
        // Ties resolve to the first declared, as a stable sort would have.
        assert!(std::ptr::eq(hit, std::ptr::from_ref(&c.routes[1])));
    }

    #[test]
    fn wildcard_host_matches_subdomain_and_apex() {
        let c = config_with(vec![route(Some("*.example.com"), Some("/"), None, None, 1)]);
        assert!(c.find_route(Some("api.example.com"), "/x", false).is_some());
        assert!(
            c.find_route(Some("EXAMPLE.COM"), "/x", false).is_some(),
            "apex, any case"
        );
        assert!(c.find_route(Some("example.org"), "/x", false).is_none());
    }

    #[test]
    fn test_host_matching() {
        let config = ProxyConfig::default();

        assert!(config.host_matches("example.com", "example.com"));
        assert!(config.host_matches("*.example.com", "api.example.com"));
        assert!(config.host_matches("*.example.com", "example.com"));
        assert!(!config.host_matches("*.example.com", "other.com"));
    }

    #[test]
    fn test_config_parsing() {
        let toml_content = r#"
[server]
bind_address = "0.0.0.0"
udp_port = 4433

[tls]
cert_path = "/etc/pqcrypta/cert.pem"
key_path = "/etc/pqcrypta/key.pem"

[pqc]
enabled = true
provider = "openssl3.5"

[admin]
enabled = true
port = 8081

[backends.php]
name = "php"
type = "unix"
address = "unix:/run/php-fpm.sock"

[[routes]]
name = "webtransport-to-php"
webtransport = true
backend = "php"
stream_to_method = "POST"
"#;

        let config: ProxyConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.server.udp_port, 4433);
        assert!(config.pqc.enabled);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.routes.len(), 1);
    }
}
