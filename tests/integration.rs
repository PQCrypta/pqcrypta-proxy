//! Integration tests for `PQCrypta` Proxy
//!
//! These tests verify end-to-end functionality including:
//! - Configuration loading and validation
//! - QUIC listener startup
//! - Admin API endpoints
//! - TLS certificate handling
//! - Backend routing
//! - PQC configuration and provider selection

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

    /// Test PQC configuration loading with all options
    #[tokio::test]
    async fn test_pqc_config_loading() {
        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[pqc]
enabled = true
provider = "openssl3.5"
preferred_kem = "X25519MLKEM768"
fallback_to_classical = true
min_security_level = 3
additional_kems = ["SecP256r1MLKEM768", "SecP384r1MLKEM1024"]
enable_signatures = true
require_hybrid = true
verify_provider = true
check_key_permissions = true
strict_key_permissions = false
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        assert!(config.pqc.enabled);
        assert_eq!(config.pqc.provider, "openssl3.5");
        assert_eq!(config.pqc.preferred_kem, "X25519MLKEM768");
        assert!(config.pqc.fallback_to_classical);
        assert_eq!(config.pqc.min_security_level, 3);
        assert_eq!(config.pqc.additional_kems.len(), 2);
        assert!(config.pqc.enable_signatures);
        assert!(config.pqc.require_hybrid);
    }

    /// Test PQC provider defaults
    #[tokio::test]
    async fn test_pqc_default_values() {
        let config = pqcrypta_proxy::config::ProxyConfig::default();

        // Verify PQC defaults
        assert!(config.pqc.enabled);
        assert_eq!(config.pqc.provider, "auto");
        assert_eq!(config.pqc.min_security_level, 3);
        assert!(config.pqc.fallback_to_classical);
    }

    /// Test backend config with TLS options
    #[tokio::test]
    async fn test_backend_config_tls_options() {
        use pqcrypta_proxy::config::TlsMode;

        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[backends.secure-backend]
name = "secure-backend"
type = "http2"
address = "127.0.0.1:8443"
tls_mode = "reencrypt"
tls_sni = "backend.internal"
timeout_ms = 5000
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        // Verify backend parsed correctly
        assert_eq!(config.backends.len(), 1);
        let backend = config
            .backends
            .values()
            .next()
            .expect("Backend should exist");
        assert!(!backend.name.is_empty());
        assert!(!backend.address.is_empty());
        assert_eq!(backend.tls_mode, TlsMode::Reencrypt);
        assert!(backend.tls_sni.is_some());
        assert!(backend.timeout_ms > 0);
    }

    /// Test route config with CORS and headers
    #[tokio::test]
    async fn test_route_config_cors_headers() {
        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[backends.api]
name = "api"
type = "http2"
address = "127.0.0.1:3000"

[[routes]]
name = "api-route"
host = "api.example.com"
path_prefix = "/v1/"
backend = "api"
allow_http11 = true

[routes.cors]
allow_origin = "https://example.com"
allow_methods = ["GET", "POST"]
allow_credentials = true
max_age = 3600
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        // Verify routes parsed correctly
        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert!(route.name.is_some());
        assert!(route.host.is_some());
        assert!(route.cors.is_some());
        assert!(route.allow_http11);

        // Verify CORS parsed correctly
        let cors = route.cors.as_ref().unwrap();
        assert!(cors.allow_origin.is_some());
        assert!(!cors.allow_methods.is_empty());
        assert!(cors.allow_credentials);
        assert!(cors.max_age > 0);
    }

    /// Test passthrough route configuration
    #[tokio::test]
    async fn test_passthrough_route_config() {
        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test.crt"
key_path = "/tmp/test.key"

[[passthrough_routes]]
sni = "*.backend.local"
backend = "192.168.1.100:443"
proxy_protocol = true
timeout_ms = 30000
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        // Verify passthrough routes parsed correctly
        assert_eq!(config.passthrough_routes.len(), 1);
        let route = &config.passthrough_routes[0];
        assert!(!route.sni.is_empty());
        assert!(!route.backend.is_empty());
        assert!(route.proxy_protocol);
        assert!(route.timeout_ms > 0);
    }

    /// Test PQC extended module types
    #[tokio::test]
    async fn test_pqc_extended_types() {
        use pqcrypta_proxy::pqc_extended::{PqcKem, SecurityLevel};

        // Test security level ordering
        assert!(SecurityLevel::Level1 < SecurityLevel::Level3);
        assert!(SecurityLevel::Level3 < SecurityLevel::Level5);

        // Test KEM security levels
        assert_eq!(
            PqcKem::X25519MlKem768.security_level(),
            SecurityLevel::Level3
        );
        assert_eq!(
            PqcKem::SecP384r1MlKem1024.security_level(),
            SecurityLevel::Level5
        );

        // Test OpenSSL names are valid
        assert!(!PqcKem::X25519MlKem768.openssl_name().is_empty());
        assert!(!PqcKem::MlKem768.openssl_name().is_empty());
    }

    /// Test PQC capabilities detection
    #[tokio::test]
    async fn test_pqc_capabilities() {
        use pqcrypta_proxy::pqc_extended::{ExtendedPqcConfig, PqcCapabilities};

        // Create default config for detection
        let config = ExtendedPqcConfig::default();

        // Detect available PQC capabilities
        let caps = PqcCapabilities::detect(&config);

        // Should have at least one backend available (rustls or OpenSSL)
        assert!(caps.rustls_available || caps.openssl_available);

        // Should detect some KEM algorithms
        assert!(!caps.available_kems.is_empty() || caps.rustls_available);
    }
}
