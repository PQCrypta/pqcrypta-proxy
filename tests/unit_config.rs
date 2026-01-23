//! Unit tests for configuration parsing and validation
//!
//! TODO: Update tests to match new config struct fields (`BackendConfig`, `RouteConfig`)
//! Tests that construct these structs directly need to include all required fields.

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
    assert_eq!(config.provider, "openssl3.5");
}
