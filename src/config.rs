//! Configuration module with TOML parsing and hot-reload support
//!
//! All configuration values are externalized - no hardcoded ports, paths, or addresses.
//! Supports hot-reload of config and TLS certificates without process restart.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
    /// TLS certificates reloaded
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
    /// Backend definitions
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
    /// Route mappings
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
    /// Admin API configuration
    pub admin: AdminConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
    /// Rate limiting configuration
    pub rate_limiting: RateLimitConfig,
    /// Security settings
    pub security: SecurityConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
            pqc: PqcConfig::default(),
            backends: HashMap::new(),
            routes: Vec::new(),
            admin: AdminConfig::default(),
            logging: LoggingConfig::default(),
            rate_limiting: RateLimitConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

/// Server bind configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Bind address for QUIC listener (default: 0.0.0.0)
    pub bind_address: String,
    /// UDP port for QUIC/HTTP3/WebTransport (default: 4433)
    pub udp_port: u16,
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
            udp_port: 4433,
            max_connections: 10000,
            max_streams_per_connection: 1000,
            keepalive_interval_secs: 15,
            max_idle_timeout_secs: 120,
            enable_ipv6: false,
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
            preferred_kem: "kyber768".to_string(),
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
    /// Enable TLS to backend (re-encrypt)
    #[serde(default)]
    pub tls: bool,
    /// TLS certificate for backend verification
    pub tls_cert: Option<PathBuf>,
    /// Skip TLS verification (dangerous, for testing only)
    #[serde(default)]
    pub tls_skip_verify: bool,
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
    /// Enable WebTransport for this route
    #[serde(default)]
    pub webtransport: bool,
    /// Backend name to route to
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
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_request_size: 10 * 1024 * 1024, // 10MB
            max_header_size: 64 * 1024,          // 64KB
            connection_timeout_secs: 30,
            dos_protection: true,
            blocked_ips: Vec::new(),
            allowed_ips: Vec::new(),
        }
    }
}

impl ConfigManager {
    /// Create a new configuration manager and load initial config
    pub async fn new(config_path: impl AsRef<Path>) -> anyhow::Result<(Self, mpsc::Receiver<ConfigReloadEvent>)> {
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

    /// Manually reload configuration
    pub async fn reload(&self) -> anyhow::Result<()> {
        match Self::load_config(&self.config_path) {
            Ok(new_config) => {
                let new_config = Arc::new(new_config);
                self.config.store(new_config.clone());
                info!("Configuration reloaded successfully");

                // Notify listeners
                let _ = self.reload_tx.send(ConfigReloadEvent::ConfigReloaded(new_config)).await;
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload configuration: {}", e);
                let _ = self.reload_tx.send(ConfigReloadEvent::ReloadFailed(e.to_string())).await;
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
                                let _ = reload_tx.blocking_send(ConfigReloadEvent::ConfigReloaded(new_config));
                            }
                            Err(e) => {
                                error!("Failed to hot-reload configuration: {}", e);
                                let _ = reload_tx.blocking_send(ConfigReloadEvent::ReloadFailed(e.to_string()));
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
        self.server.socket_addr()
            .map_err(|e| anyhow::anyhow!("Invalid server bind address: {}", e))?;

        // Validate TLS config
        if !self.tls.cert_path.exists() {
            warn!("TLS certificate not found: {:?}", self.tls.cert_path);
        }
        if !self.tls.key_path.exists() {
            warn!("TLS private key not found: {:?}", self.tls.key_path);
        }

        // Validate routes reference existing backends
        for route in &self.routes {
            if !self.backends.contains_key(&route.backend) {
                return Err(anyhow::anyhow!(
                    "Route {:?} references unknown backend: {}",
                    route.name,
                    route.backend
                ));
            }
        }

        // Validate admin config
        if self.admin.enabled {
            self.admin.socket_addr()
                .map_err(|e| anyhow::anyhow!("Invalid admin bind address: {}", e))?;
        }

        Ok(())
    }

    /// Find matching route for a request
    pub fn find_route(&self, host: Option<&str>, path: &str, is_webtransport: bool) -> Option<&RouteConfig> {
        // Sort routes by priority and find first match
        let mut matching_routes: Vec<_> = self.routes.iter()
            .filter(|r| self.route_matches(r, host, path, is_webtransport))
            .collect();

        matching_routes.sort_by_key(|r| r.priority);
        matching_routes.first().copied()
    }

    /// Check if a route matches the request
    fn route_matches(&self, route: &RouteConfig, host: Option<&str>, path: &str, is_webtransport: bool) -> bool {
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

        // Check path
        if let Some(ref exact) = route.path_exact {
            if path != exact {
                return false;
            }
        }

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
        assert_eq!(config.server.udp_port, 4433);
        assert_eq!(config.admin.port, 8081);
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
