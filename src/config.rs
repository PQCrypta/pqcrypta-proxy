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
use crate::rate_limiter::AdvancedRateLimitConfig;

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
        }
    }
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
            http_redirect: HttpRedirectConfig::default(),
            load_balancer: LoadBalancerConfig::default(),
            fingerprint: FingerprintConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            connection_pool: ConnectionPoolConfig::default(),
            ocsp: OcspConfig::default(),
            acme: AcmeConfig::default(),
            http3: Http3Config::default(),
        }
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
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Maximum concurrent streams per connection
    pub max_streams_per_connection: u32,
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

    /// Maximum request body size in bytes (default 50 MiB).
    /// Requests with Content-Length exceeding this are rejected with 413.
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: u64,

    /// Enable QUIC connection migration (RFC 9000 §9).
    /// Allows clients to migrate to a new network path without losing the session.
    /// Default: true (enabled — Quinn default behaviour).
    #[serde(default = "default_true")]
    pub enable_quic_migration: bool,

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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            udp_port: 443,
            additional_ports: vec![4433, 4434],
            max_connections: 10000,
            max_streams_per_connection: 1000,
            keepalive_interval_secs: 15,
            max_idle_timeout_secs: 120,
            enable_ipv6: true,
            worker_threads: 0,
            graceful_shutdown_timeout_secs: 30,
            // SR-02: Empty by default — all cross-origin sessions are rejected
            // until the operator explicitly lists allowed origins.
            webtransport_allowed_origins: Vec::new(),
            max_request_body_bytes: 52_428_800, // 50 MiB
            enable_quic_migration: true,
            webtransport_max_sessions_per_origin: 100,
            webtransport_max_streams_per_session: 1000,
            webtransport_max_datagrams_per_sec: 500,
            webtransport_port: 4433,
        }
    }
}

fn default_max_request_body_bytes() -> u64 {
    52_428_800 // 50 MiB
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

    /// Enable PQC-wrapped session tickets (experimental).
    /// When true, session ticket HKDF keys are encapsulated with ML-KEM-1024.
    /// Default: false.
    #[serde(default)]
    pub pqc_session_tickets: bool,
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
        }
    }
}

fn default_zero_rtt_replay_protection() -> String {
    "strict".to_string()
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
    /// Fallback to classical if PQC fails
    pub fallback_to_classical: bool,
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

    /// Enable PQC signatures (ML-DSA) - requires `pqc-signatures` feature
    #[serde(default)]
    pub enable_signatures: bool,
    /// Require hybrid mode (reject pure PQC or pure classical)
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
            provider: "auto".to_string(), // Auto-select best available
            openssl_path: Some(PathBuf::from("/usr/local/openssl-3.5/bin/openssl")),
            openssl_lib_path: Some(PathBuf::from("/usr/local/openssl-3.5/lib64")),
            // X25519MLKEM768 is the IETF standard hybrid (classical + PQC)
            // Provides NIST Level 3 security with classical fallback
            preferred_kem: "X25519MLKEM768".to_string(),
            fallback_to_classical: true,
            min_security_level: 3,
            additional_kems: vec![
                "SecP256r1MLKEM768".to_string(),
                "SecP384r1MLKEM1024".to_string(),
            ],
            downgrade_action: default_downgrade_action(),
            log_downgrades: true,
            enable_signatures: false,
            require_hybrid: false,
            verify_provider: true,
            check_key_permissions: true,
            strict_key_permissions: false,
        }
    }
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
    /// Headers to remove from backend request
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

    /// Per-route security policy override (mTLS, JA3 allowlist, rate limit, WAF mode)
    pub security: Option<RouteSecurityPolicy>,
}

fn default_priority() -> i32 {
    100
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
    /// Require mTLS for admin API
    pub require_mtls: bool,
    /// Admin API token for authentication (if not using mTLS)
    pub auth_token: Option<String>,
    /// Allowed IP addresses for admin API
    pub allowed_ips: Vec<String>,
    /// Refuse to start if the admin bind address is not loopback (default: true).
    /// Admin traffic is plain HTTP; a non-loopback bind transmits Bearer tokens in
    /// cleartext.  Set to `false` only when the bind interface is protected by a
    /// TLS tunnel (e.g. SSH port-forward or WireGuard).
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
            auth_token: None,
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
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
    /// Audit log file path (None = write to stderr)
    pub audit_log_path: Option<PathBuf>,
    /// Enable structured audit logging (default true)
    #[serde(default = "default_true")]
    pub audit_log_enabled: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file: None,
            access_log: true,
            access_log_file: None,
            audit_log_path: None,
            audit_log_enabled: true,
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Requests per second per IP
    pub requests_per_second: u32,
    /// Burst size
    pub burst_size: u32,
    /// Enable connection rate limiting
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
    /// `None` means permanent (old behaviour); `Some(n)` expires the block after n seconds.
    /// Default: Some(86400) — 24 h, giving operators recourse for mis-classified IPs.
    #[serde(default = "default_geoip_block_duration_secs")]
    pub geoip_block_duration_secs: Option<u64>,
}

fn default_geoip_block_duration_secs() -> Option<u64> {
    Some(86400) // 24 hours — prevents permanent blocks from stale GeoIP data
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
            trusted_internal_cidrs: Vec::new(),
            blocklist_dir: PathBuf::from("/var/lib/pqcrypta-proxy/blocklists"),
            allow_internal_backends: false,
            geoip_block_duration_secs: default_geoip_block_duration_secs(),
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
    /// AUD-12: Automatically block connections whose JA3/JA4 fingerprint is classified
    /// as Malicious in the fingerprint database.
    /// Default: false (advisory-only — Malicious fingerprints are logged, not blocked).
    /// Set to true only after validating that your fingerprint database does not
    /// produce false positives against legitimate clients.
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
    /// Format: "u=<urgency>, i" where urgency is 0-7 and i indicates incremental
    #[serde(default)]
    pub priority: String,
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

            // Client Hints for responsive content delivery
            accept_ch: "DPR, Viewport-Width, Width, ECT, RTT, Downlink, Sec-CH-UA-Platform, Sec-CH-UA-Mobile".to_string(),

            // Network Error Logging configuration
            // Reports connection errors to the configured endpoint
            nel: r#"{"report_to":"default","max_age":86400,"include_subdomains":true}"#.to_string(),

            // Reporting API endpoint configuration
            // Groups for NEL, CSP violations, and other reports
            report_to: r#"{"group":"default","max_age":86400,"endpoints":[{"url":"https://pqcrypta.com/api/reports"}]}"#.to_string(),

            // HTTP/3 Priority (RFC 9218) - u=3 is default urgency, i=?0 means non-incremental
            priority: "u=3,i=?0".to_string(),
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
}

impl Default for HttpRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 80,
            redirect_to_https: true,
            allowed_domains: vec![],
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
    /// Allowed origin (e.g., "https://pqcrypta.com")
    pub allow_origin: Option<String>,
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

        let config: ProxyConfig = toml::from_str(&content)
            .map_err(|e| anyhow::anyhow!("Failed to parse config file {:?}: {}", path, e))?;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    /// Get current configuration
    pub fn get(&self) -> Arc<ProxyConfig> {
        self.config.load_full()
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

        let new_config: ProxyConfig = toml::from_str(&merged_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse merged config: {}", e))?;
        new_config.validate()?;

        self.config.store(Arc::new(new_config));
        info!("Environment overlay applied from {:?}", overlay_path);
        Ok(())
    }

    /// Start watching configuration file for changes
    pub fn start_watching(&self) -> anyhow::Result<()> {
        let config_path = self.config_path.clone();
        let reload_tx = self.reload_tx.clone();
        let config = Arc::clone(&self.config.load_full());

        // Create file watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if event.kind.is_modify() || event.kind.is_create() {
                        debug!("Config file change detected: {:?}", event);

                        // Reload configuration
                        match Self::load_config(&config_path) {
                            Ok(new_config) => {
                                let new_config = Arc::new(new_config);
                                info!("Configuration hot-reloaded");

                                // Send reload event (blocking send for non-async context)
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
                }
                Err(e) => {
                    warn!("Config file watch error: {}", e);
                }
            }
        })?;

        // Watch the configuration file
        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;

        // Also watch TLS certificate files for changes
        let tls_config = &config.tls;
        if tls_config.cert_path.exists() {
            watcher.watch(&tls_config.cert_path, RecursiveMode::NonRecursive)?;
            info!("Watching TLS cert: {:?}", tls_config.cert_path);
        }
        if tls_config.key_path.exists() {
            watcher.watch(&tls_config.key_path, RecursiveMode::NonRecursive)?;
            info!("Watching TLS key: {:?}", tls_config.key_path);
        }

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

impl ProxyConfig {
    /// Validate the configuration
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

        // Config conflict: mTLS required but no CA cert
        if self.tls.require_client_cert && self.tls.ca_cert_path.is_none() {
            return Err(anyhow::anyhow!(
                "tls.require_client_cert = true but tls.ca_cert_path is not set. \
                 Provide a CA certificate path to verify client certificates."
            ));
        }

        // Config conflict: admin require_mtls (not yet implemented)
        if self.admin.require_mtls {
            return Err(anyhow::anyhow!(
                "admin.require_mtls = true is not yet implemented. \
                 Remove this setting to start the proxy."
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
        // Sort routes by priority and find first match
        let mut matching_routes: Vec<_> = self
            .routes
            .iter()
            .filter(|r| self.route_matches(r, host, path, is_webtransport))
            .collect();

        matching_routes.sort_by_key(|r| r.priority);
        matching_routes.first().copied()
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

        let path_lower = path.to_ascii_lowercase();

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
            if path_lower != exact.to_ascii_lowercase() {
                return false;
            }
            return true;
        }

        // Check path regex (already validated during config load)
        // Use case-insensitive matching
        if let Some(ref regex_str) = route.path_regex {
            if let Ok(re) = regex::RegexBuilder::new(regex_str)
                .case_insensitive(true)
                .size_limit(1024 * 1024)
                .build()
            {
                if !re.is_match(&path_lower) {
                    return false;
                }
                return true;
            }
        }

        // Check path prefix (case-insensitive)
        if let Some(ref prefix) = route.path_prefix {
            if !path_lower.starts_with(&prefix.to_ascii_lowercase()) {
                return false;
            }
        }

        true
    }

    /// Check if host matches pattern (supports wildcards)
    /// Case-insensitive comparison
    fn host_matches(&self, pattern: &str, host: &str) -> bool {
        let pattern_lower = pattern.to_ascii_lowercase();
        let host_lower = host.to_ascii_lowercase();
        if pattern_lower.starts_with("*.") {
            // Wildcard subdomain match
            let suffix = &pattern_lower[1..];
            host_lower.ends_with(suffix) || host_lower == pattern_lower[2..]
        } else {
            // Exact match
            pattern_lower == host_lower
        }
    }

    /// Get backend by name
    pub fn get_backend(&self, name: &str) -> Option<&BackendConfig> {
        self.backends.get(name)
    }
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
