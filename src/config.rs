//! Configuration module with TOML parsing and hot-reload support
//!
//! All configuration values are externalized - no hardcoded ports, paths, or addresses.
//! Supports hot-reload of config and TLS certificates without process restart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::rate_limiter::AdvancedRateLimitConfig;

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
    /// Server bind configuration
    pub server: ServerConfig,
    /// TLS configuration
    pub tls: TlsConfig,
    /// Post-quantum cryptography settings
    pub pqc: PqcConfig,
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
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            pqc: PqcConfig::default(),
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
        }
    }
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
    /// Enable 0-RTT (early data) - SECURITY WARNING: vulnerable to replay attacks
    /// Default: false (disabled for security)
    pub enable_0rtt: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_path: PathBuf::from("/etc/pqcrypta/cert.pem"),
            key_path: PathBuf::from("/etc/pqcrypta/key.pem"),
            ca_cert_path: None,
            require_client_cert: false,
            alpn_protocols: vec!["h3".to_string(), "webtransport".to_string()],
            min_version: "1.3".to_string(),
            ocsp_stapling: true,
            cert_reload_interval_secs: 3600,
            enable_0rtt: false, // Disabled by default for security (replay attack risk)
        }
    }
}

/// Post-quantum cryptography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PqcConfig {
    /// Enable PQC hybrid key exchange
    pub enabled: bool,
    /// PQC provider: "openssl3.5" or "rustls-pqc"
    pub provider: String,
    /// OpenSSL binary path (for OpenSSL 3.5+ with OQS provider)
    pub openssl_path: Option<PathBuf>,
    /// OpenSSL library path
    pub openssl_lib_path: Option<PathBuf>,
    /// Preferred KEM algorithm for key exchange
    pub preferred_kem: String,
    /// Fallback to classical if PQC fails
    pub fallback_to_classical: bool,
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            provider: "openssl3.5".to_string(),
            openssl_path: Some(PathBuf::from("/usr/local/openssl-3.5/bin/openssl")),
            openssl_lib_path: Some(PathBuf::from("/usr/local/openssl-3.5/lib64")),
            // X25519MLKEM768 is the IETF standard hybrid (classical + PQC)
            // Provides NIST Level 3 security with classical fallback
            preferred_kem: "X25519MLKEM768".to_string(),
            fallback_to_classical: true,
        }
    }
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
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1".to_string(),
            port: 8081,
            require_mtls: false,
            auth_token: None,
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
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
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            file: None,
            access_log: true,
            access_log_file: None,
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
            auto_block_threshold: 10,           // 10 suspicious patterns before auto-block
            auto_block_duration_secs: 300,      // 5 minute auto-block
            error_4xx_threshold: 100,           // 100 4xx errors before checking rate
            min_requests_for_error_check: 200,  // Need 200+ requests before error check
            error_rate_threshold: 0.7,          // 70% error rate triggers suspicious
            error_window_secs: 60,              // 1 minute sliding window
        }
    }
}

/// Fingerprint detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FingerprintConfig {
    /// Enable TLS fingerprint detection
    pub enabled: bool,
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
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            malicious_block_duration_secs: 3600,      // 1 hour
            suspicious_block_duration_secs: 300,       // 5 minutes
            suspicious_rate_threshold: 100,            // 100 requests
            suspicious_rate_window_secs: 60,           // 1 minute
            cache_max_age_secs: 3600,                  // 1 hour
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
            half_open_delay_secs: 30,                  // 30 seconds
            half_open_max_requests: 3,                 // 3 test requests
            failure_threshold: 5,                      // 5 failures to open
            success_threshold: 2,                      // 2 successes to close
            stale_counter_cleanup_secs: 300,           // 5 minutes
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
            idle_timeout_secs: 90,                     // 90 seconds
            max_idle_per_host: 10,                     // 10 idle connections
            max_connections_per_host: 100,             // 100 total connections
            acquire_timeout_ms: 5000,                  // 5 second timeout
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
}

impl Default for HttpRedirectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 80,
            redirect_to_https: true,
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
    /// Get header name for header-based affinity
    #[allow(dead_code)]
    pub fn header_name(&self) -> Option<&'static str> {
        match self {
            Self::Header => Some("X-Session-ID"),
            _ => None,
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

impl ProxyConfig {
    /// Validate the configuration
    pub fn validate(&self) -> anyhow::Result<()> {
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
            // Skip backend validation for redirect routes
            if route.redirect.is_some() {
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
            }
        }

        // Validate admin config
        if self.admin.enabled {
            self.admin
                .socket_addr()
                .map_err(|e| anyhow::anyhow!("Invalid admin bind address: {}", e))?;
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

        // Check host pattern
        if let Some(ref pattern) = route.host {
            if let Some(h) = host {
                if !self.host_matches(pattern, h) {
                    return false;
                }
            } else {
                return false;
            }
        }

        // Check path - exact match takes priority
        if let Some(ref exact) = route.path_exact {
            if path != exact {
                return false;
            }
            return true;
        }

        // Check path regex
        if let Some(ref regex_str) = route.path_regex {
            if let Ok(re) = regex::Regex::new(regex_str) {
                if !re.is_match(path) {
                    return false;
                }
                return true;
            }
        }

        // Check path prefix
        if let Some(ref prefix) = route.path_prefix {
            if !path.starts_with(prefix) {
                return false;
            }
        }

        true
    }

    /// Check if host matches pattern (supports wildcards)
    fn host_matches(&self, pattern: &str, host: &str) -> bool {
        if pattern.starts_with("*.") {
            // Wildcard subdomain match
            let suffix = &pattern[1..];
            host.ends_with(suffix) || host == &pattern[2..]
        } else {
            // Exact match
            pattern == host
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
