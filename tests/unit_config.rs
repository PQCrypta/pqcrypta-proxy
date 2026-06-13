//! Unit tests for configuration parsing and validation
//!
//! Tests for config struct field parsing, defaults, and validation.

use pqcrypta_proxy::config::*;

#[test]
fn test_default_config() {
    let config = ProxyConfig::default();

    // Just verify defaults exist and are sensible - actual values come from config
    assert!(!config.server.bind_address.is_empty());
    assert!(config.server.udp_port > 0);
    assert!(config.admin.port > 0);
    assert!(config.pqc.enabled);
    assert!(!config.pqc.provider.is_empty());
}

#[test]
fn test_server_socket_addr() {
    let config = ServerConfig::default();
    let addr = config.socket_addr().unwrap();

    // Verify socket address can be parsed - don't hardcode port values
    assert!(addr.port() > 0);
    assert!(!addr.ip().to_string().is_empty());
}

#[test]
fn test_admin_socket_addr() {
    let config = AdminConfig::default();
    let addr = config.socket_addr().unwrap();

    // Verify socket address can be parsed
    assert!(addr.port() > 0);
    assert!(!addr.ip().to_string().is_empty());
}

#[test]
fn test_config_parsing_minimal() {
    let toml_content = r#"
[server]
udp_port = 8443

[tls]
cert_path = "/etc/test/cert.pem"
key_path = "/etc/test/key.pem"
"#;

    let config: ProxyConfig = toml::from_str(toml_content).unwrap();

    // Test that TOML values override defaults
    assert_eq!(config.server.udp_port, 8443);
    assert_eq!(config.tls.cert_path.to_str().unwrap(), "/etc/test/cert.pem");
}

#[test]
fn test_backend_types() {
    // Test parsing via TOML which uses serde defaults
    let toml_http1 = r#"
name = "http1-backend"
type = "http1"
address = "127.0.0.1:8080"
"#;
    let backend: BackendConfig = toml::from_str(toml_http1).unwrap();
    assert_eq!(backend.backend_type, BackendType::Http1);

    let toml_http2 = r#"
name = "http2-backend"
type = "http2"
address = "127.0.0.1:8080"
"#;
    let backend: BackendConfig = toml::from_str(toml_http2).unwrap();
    assert_eq!(backend.backend_type, BackendType::Http2);

    let toml_http3 = r#"
name = "http3-backend"
type = "http3"
address = "127.0.0.1:8080"
"#;
    let backend: BackendConfig = toml::from_str(toml_http3).unwrap();
    assert_eq!(backend.backend_type, BackendType::Http3);

    let toml_unix = r#"
name = "unix-backend"
type = "unix"
address = "/var/run/test.sock"
"#;
    let backend: BackendConfig = toml::from_str(toml_unix).unwrap();
    assert_eq!(backend.backend_type, BackendType::Unix);

    let toml_tcp = r#"
name = "tcp-backend"
type = "tcp"
address = "127.0.0.1:9000"
"#;
    let backend: BackendConfig = toml::from_str(toml_tcp).unwrap();
    assert_eq!(backend.backend_type, BackendType::Tcp);
}

#[test]
fn test_tls_mode_defaults() {
    let config = TlsConfig::default();
    assert_eq!(config.min_version, "1.3");
}

#[test]
fn test_pqc_config_defaults() {
    let config = PqcConfig::default();
    assert!(config.enabled);
    assert_eq!(config.provider, "auto");
    assert!(!config.preferred_kem.is_empty());
    assert!(config.fallback_to_classical);
    assert!(config.min_security_level >= 1 && config.min_security_level <= 5);
}

#[test]
fn test_pqc_provider_options() {
    // Test parsing different provider values
    let toml_auto = r#"
[server]
udp_port = 8443

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[pqc]
enabled = true
provider = "auto"
"#;
    let config: ProxyConfig = toml::from_str(toml_auto).unwrap();
    assert_eq!(config.pqc.provider, "auto");

    let toml_rustls = r#"
[server]
udp_port = 8443

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[pqc]
enabled = true
provider = "rustls"
"#;
    let config: ProxyConfig = toml::from_str(toml_rustls).unwrap();
    assert_eq!(config.pqc.provider, "rustls");

    let toml_openssl = r#"
[server]
udp_port = 8443

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[pqc]
enabled = true
provider = "openssl3.5"
"#;
    let config: ProxyConfig = toml::from_str(toml_openssl).unwrap();
    assert_eq!(config.pqc.provider, "openssl3.5");
}

#[test]
fn test_tls_mode_parsing() {
    // Test parsing TLS modes via TOML
    let toml_terminate = r#"
name = "test"
type = "http2"
address = "127.0.0.1:8080"
tls_mode = "terminate"
"#;
    let backend: BackendConfig = toml::from_str(toml_terminate).unwrap();
    assert_eq!(backend.tls_mode, TlsMode::Terminate);

    let toml_reencrypt = r#"
name = "test"
type = "http2"
address = "127.0.0.1:8080"
tls_mode = "reencrypt"
"#;
    let backend: BackendConfig = toml::from_str(toml_reencrypt).unwrap();
    assert_eq!(backend.tls_mode, TlsMode::Reencrypt);

    let toml_passthrough = r#"
name = "test"
type = "http2"
address = "127.0.0.1:8080"
tls_mode = "passthrough"
"#;
    let backend: BackendConfig = toml::from_str(toml_passthrough).unwrap();
    assert_eq!(backend.tls_mode, TlsMode::Passthrough);
}

#[test]
fn test_passthrough_route_parsing() {
    let toml_content = r#"
sni = "*.example.com"
backend = "10.0.0.1:443"
proxy_protocol = true
timeout_ms = 30000
"#;
    let route: PassthroughRoute = toml::from_str(toml_content).unwrap();
    assert!(!route.sni.is_empty());
    assert!(!route.backend.is_empty());
    assert!(route.proxy_protocol);
    assert!(route.timeout_ms > 0);
}

#[test]
fn test_rate_limit_parsing() {
    let toml_content = r"
enabled = true
requests_per_second = 100
burst_size = 200
";
    let rate_limit: RateLimitConfig = toml::from_str(toml_content).unwrap();
    assert!(rate_limit.enabled);
    assert!(rate_limit.requests_per_second > 0);
    assert!(rate_limit.burst_size > 0);
}

#[test]
fn test_ack_frequency_default_enabled() {
    // ACK Frequency is on by default; absent from config it must stay enabled.
    assert!(ServerConfig::default().enable_ack_frequency);
}

#[test]
fn test_masque_defaults_disabled() {
    // MASQUE must be off by default — it is a UDP relay.
    let config = ProxyConfig::default();
    assert!(!config.masque.enabled);
    assert!(config.masque.allowed_targets.is_empty());
}

#[test]
fn test_masque_parsing() {
    let toml_content = r#"
enabled = true
allowed_targets = ["127.0.0.53:53", "*:443", "dns.example.com:*"]
session_idle_timeout_secs = 30
max_sessions_per_connection = 4
"#;
    let masque: MasqueConfig = toml::from_str(toml_content).unwrap();
    assert!(masque.enabled);
    assert_eq!(masque.session_idle_timeout_secs, 30);
    assert_eq!(masque.max_sessions_per_connection, 4);
}

#[test]
fn test_masque_allowlist_matching() {
    let toml_content = r#"
enabled = true
allowed_targets = ["127.0.0.53:53", "*:443", "dns.example.com:*"]
"#;
    let masque: MasqueConfig = toml::from_str(toml_content).unwrap();

    // Exact host:port
    assert!(masque.is_target_allowed("127.0.0.53", 53));
    // Wildcard host, exact port
    assert!(masque.is_target_allowed("anything.example", 443));
    // Exact host (case-insensitive), wildcard port
    assert!(masque.is_target_allowed("DNS.example.com", 8853));

    // Not allowed
    assert!(!masque.is_target_allowed("127.0.0.53", 54));
    assert!(!masque.is_target_allowed("evil.example", 53));
}

#[test]
fn test_masque_empty_allowlist_denies_all() {
    let masque = MasqueConfig::default();
    assert!(!masque.is_target_allowed("127.0.0.53", 53));
    assert!(!masque.is_target_allowed("anything", 443));
}
