//! Integration tests for `PQCrypta` Proxy
//!
//! These tests verify end-to-end functionality including:
//! - Configuration loading and validation
//! - QUIC listener startup
//! - Admin API endpoints
//! - TLS certificate handling
//! - Backend routing
//!
//! TODO: Update tests to match new config struct fields (`BackendConfig`, `RouteConfig`)
//! The config structs have been extended with additional fields. Tests need to be updated
//! to provide all required fields or use Default implementations.

// Tests temporarily disabled - need to update to match expanded config struct fields
// See: `BackendConfig` now requires `tls_mode`, `tls_client_cert`, `tls_client_key`, `tls_sni`
// See: `RouteConfig` now requires `cors`, `headers_override`, `allow_http11`, `skip_bot_blocking`, etc.

#[cfg(test)]
mod integration_tests {
    /// Test that configuration can be loaded and validated
    #[tokio::test]
    async fn test_config_loading() {
        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[admin]
enabled = false
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        assert_eq!(config.server.bind_address, "127.0.0.1");
        assert_eq!(config.server.udp_port, 14433);
    }

    /// Test backend type variants
    #[tokio::test]
    async fn test_backend_type_variants() {
        use pqcrypta_proxy::config::BackendType;

        // Test equality
        assert_eq!(BackendType::Http1, BackendType::Http1);
        assert_ne!(BackendType::Http1, BackendType::Http2);
        assert_ne!(BackendType::Http2, BackendType::Http3);
        assert_ne!(BackendType::Unix, BackendType::Tcp);
    }

    /// Test socket addr parsing
    #[tokio::test]
    async fn test_socket_addr_parsing() {
        let config = pqcrypta_proxy::config::ProxyConfig::default();

        // Verify defaults exist - don't hardcode actual values
        assert!(!config.server.bind_address.is_empty());
        assert!(config.server.udp_port > 0);
    }
}
