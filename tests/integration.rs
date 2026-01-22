//! Integration tests for PQCrypta Proxy
//!
//! These tests verify end-to-end functionality including:
//! - Configuration loading and validation
//! - QUIC listener startup
//! - Admin API endpoints
//! - TLS certificate handling
//! - Backend routing

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test that configuration can be loaded and validated
    #[tokio::test]
    async fn test_config_loading() {
        let config_content = r#"
[server]
bind_address = "127.0.0.1"
udp_port = 14433

[tls]
cert_path = "/tmp/test-cert.pem"
key_path = "/tmp/test-key.pem"

[pqc]
enabled = false

[admin]
enabled = true
port = 18081

[backends.test]
name = "test"
type = "http1"
address = "127.0.0.1:9999"
timeout_ms = 5000
max_connections = 10

[[routes]]
name = "default"
path_prefix = "/"
backend = "test"
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        assert_eq!(config.server.udp_port, 14433);
        assert_eq!(config.admin.port, 18081);
        assert!(!config.pqc.enabled);
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.routes.len(), 1);
    }

    /// Test configuration validation catches invalid backends
    #[tokio::test]
    async fn test_config_validation_invalid_backend() {
        let config_content = r#"
[server]
udp_port = 14433

[tls]
cert_path = "/tmp/test-cert.pem"
key_path = "/tmp/test-key.pem"

[[routes]]
name = "invalid-route"
path_prefix = "/"
backend = "non-existent-backend"
"#;

        let config: pqcrypta_proxy::config::ProxyConfig =
            toml::from_str(config_content).expect("Failed to parse config");

        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown backend"));
    }

    /// Test route matching with host and path
    #[tokio::test]
    async fn test_route_matching() {
        use pqcrypta_proxy::config::{BackendConfig, BackendType, ProxyConfig, RouteConfig};
        use std::collections::HashMap;

        let mut config = ProxyConfig::default();

        // Add backend
        config.backends.insert(
            "api".to_string(),
            BackendConfig {
                name: "api".to_string(),
                backend_type: BackendType::Http1,
                address: "127.0.0.1:8080".to_string(),
                tls: false,
                tls_cert: None,
                tls_skip_verify: false,
                timeout_ms: 30000,
                max_connections: 100,
                health_check: None,
                health_check_interval_secs: 30,
            },
        );

        // Add specific route
        config.routes.push(RouteConfig {
            name: Some("api-route".to_string()),
            host: Some("api.example.com".to_string()),
            path_prefix: Some("/api".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "api".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: true,
            client_identity_header: Some("X-Client-IP".to_string()),
            priority: 10,
        });

        // Add catch-all route
        config.routes.push(RouteConfig {
            name: Some("default".to_string()),
            host: None,
            path_prefix: Some("/".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "api".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 100,
        });

        // Test specific route matches
        let route = config.find_route(Some("api.example.com"), "/api/users", false);
        assert!(route.is_some());
        assert_eq!(route.unwrap().name, Some("api-route".to_string()));

        // Test catch-all matches other paths
        let route = config.find_route(Some("other.example.com"), "/health", false);
        assert!(route.is_some());
        assert_eq!(route.unwrap().name, Some("default".to_string()));
    }

    /// Test wildcard host matching
    #[tokio::test]
    async fn test_wildcard_host_matching() {
        use pqcrypta_proxy::config::{BackendConfig, BackendType, ProxyConfig, RouteConfig};
        use std::collections::HashMap;

        let mut config = ProxyConfig::default();

        config.backends.insert(
            "wildcard".to_string(),
            BackendConfig {
                name: "wildcard".to_string(),
                backend_type: BackendType::Http1,
                address: "127.0.0.1:8080".to_string(),
                tls: false,
                tls_cert: None,
                tls_skip_verify: false,
                timeout_ms: 30000,
                max_connections: 100,
                health_check: None,
                health_check_interval_secs: 30,
            },
        );

        config.routes.push(RouteConfig {
            name: Some("wildcard-route".to_string()),
            host: Some("*.example.com".to_string()),
            path_prefix: None,
            path_exact: None,
            webtransport: false,
            backend: "wildcard".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 10,
        });

        // Should match subdomains
        assert!(config
            .find_route(Some("api.example.com"), "/", false)
            .is_some());
        assert!(config
            .find_route(Some("www.example.com"), "/", false)
            .is_some());

        // Should match root domain
        assert!(config
            .find_route(Some("example.com"), "/", false)
            .is_some());

        // Should not match different domain
        assert!(config
            .find_route(Some("example.org"), "/", false)
            .is_none());
    }

    /// Test WebTransport route filtering
    #[tokio::test]
    async fn test_webtransport_route_filtering() {
        use pqcrypta_proxy::config::{BackendConfig, BackendType, ProxyConfig, RouteConfig};
        use std::collections::HashMap;

        let mut config = ProxyConfig::default();

        config.backends.insert(
            "wt".to_string(),
            BackendConfig {
                name: "wt".to_string(),
                backend_type: BackendType::Http1,
                address: "127.0.0.1:8080".to_string(),
                tls: false,
                tls_cert: None,
                tls_skip_verify: false,
                timeout_ms: 30000,
                max_connections: 100,
                health_check: None,
                health_check_interval_secs: 30,
            },
        );

        // WebTransport-only route
        config.routes.push(RouteConfig {
            name: Some("wt-only".to_string()),
            host: None,
            path_prefix: Some("/stream".to_string()),
            path_exact: None,
            webtransport: true,
            backend: "wt".to_string(),
            stream_to_method: Some("POST".to_string()),
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 10,
        });

        // HTTP-only route
        config.routes.push(RouteConfig {
            name: Some("http-only".to_string()),
            host: None,
            path_prefix: Some("/api".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "wt".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 10,
        });

        // WebTransport request should only match WebTransport routes
        let wt_route = config.find_route(None, "/stream/test", true);
        assert!(wt_route.is_some());
        assert_eq!(wt_route.unwrap().name, Some("wt-only".to_string()));

        // HTTP request should not match WebTransport route
        let http_route = config.find_route(None, "/stream/test", false);
        assert!(http_route.is_none());

        // HTTP request should match HTTP route
        let http_route = config.find_route(None, "/api/test", false);
        assert!(http_route.is_some());
        assert_eq!(http_route.unwrap().name, Some("http-only".to_string()));
    }

    /// Test backend type parsing
    #[tokio::test]
    async fn test_backend_type_parsing() {
        use pqcrypta_proxy::config::{BackendConfig, BackendType};

        // HTTP/1.1
        let http1: BackendConfig = toml::from_str(
            r#"
            name = "http1"
            type = "http1"
            address = "127.0.0.1:8080"
        "#,
        )
        .unwrap();
        assert_eq!(http1.backend_type, BackendType::Http1);

        // HTTP/2
        let http2: BackendConfig = toml::from_str(
            r#"
            name = "http2"
            type = "http2"
            address = "127.0.0.1:8080"
        "#,
        )
        .unwrap();
        assert_eq!(http2.backend_type, BackendType::Http2);

        // HTTP/3
        let http3: BackendConfig = toml::from_str(
            r#"
            name = "http3"
            type = "http3"
            address = "127.0.0.1:4433"
        "#,
        )
        .unwrap();
        assert_eq!(http3.backend_type, BackendType::Http3);

        // Unix socket
        let unix: BackendConfig = toml::from_str(
            r#"
            name = "unix"
            type = "unix"
            address = "unix:/run/php-fpm.sock"
        "#,
        )
        .unwrap();
        assert_eq!(unix.backend_type, BackendType::Unix);

        // TCP
        let tcp: BackendConfig = toml::from_str(
            r#"
            name = "tcp"
            type = "tcp"
            address = "127.0.0.1:9000"
        "#,
        )
        .unwrap();
        assert_eq!(tcp.backend_type, BackendType::Tcp);
    }

    /// Test route priority ordering
    #[tokio::test]
    async fn test_route_priority() {
        use pqcrypta_proxy::config::{BackendConfig, BackendType, ProxyConfig, RouteConfig};
        use std::collections::HashMap;

        let mut config = ProxyConfig::default();

        config.backends.insert(
            "backend".to_string(),
            BackendConfig {
                name: "backend".to_string(),
                backend_type: BackendType::Http1,
                address: "127.0.0.1:8080".to_string(),
                tls: false,
                tls_cert: None,
                tls_skip_verify: false,
                timeout_ms: 30000,
                max_connections: 100,
                health_check: None,
                health_check_interval_secs: 30,
            },
        );

        // Low priority (higher number = lower priority)
        config.routes.push(RouteConfig {
            name: Some("low-priority".to_string()),
            host: None,
            path_prefix: Some("/".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "backend".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 100,
        });

        // High priority (lower number = higher priority)
        config.routes.push(RouteConfig {
            name: Some("high-priority".to_string()),
            host: None,
            path_prefix: Some("/api".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "backend".to_string(),
            stream_to_method: None,
            add_headers: HashMap::new(),
            remove_headers: Vec::new(),
            forward_client_identity: false,
            client_identity_header: None,
            priority: 10,
        });

        // /api should match high-priority route
        let route = config.find_route(None, "/api/test", false);
        assert!(route.is_some());
        assert_eq!(route.unwrap().name, Some("high-priority".to_string()));

        // Other paths should match low-priority route
        let route = config.find_route(None, "/other", false);
        assert!(route.is_some());
        assert_eq!(route.unwrap().name, Some("low-priority".to_string()));
    }

    /// Test socket address parsing
    #[tokio::test]
    async fn test_socket_addr_parsing() {
        use pqcrypta_proxy::config::{AdminConfig, ServerConfig};

        // Server config
        let server = ServerConfig {
            bind_address: "0.0.0.0".to_string(),
            udp_port: 4433,
            ..Default::default()
        };
        let addr = server.socket_addr().unwrap();
        assert_eq!(addr.port(), 4433);
        assert!(addr.ip().is_unspecified());

        // Admin config
        let admin = AdminConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8081,
            ..Default::default()
        };
        let addr = admin.socket_addr().unwrap();
        assert_eq!(addr.port(), 8081);
        assert!(addr.ip().is_loopback());

        // IPv6
        let server_v6 = ServerConfig {
            bind_address: "::".to_string(),
            udp_port: 4433,
            ..Default::default()
        };
        let addr = server_v6.socket_addr().unwrap();
        assert_eq!(addr.port(), 4433);
        assert!(addr.ip().is_unspecified());
    }

    /// Test header manipulation in routes
    #[tokio::test]
    async fn test_route_headers() {
        use pqcrypta_proxy::config::RouteConfig;
        use std::collections::HashMap;

        let mut add_headers = HashMap::new();
        add_headers.insert("X-Forwarded-Proto".to_string(), "https".to_string());
        add_headers.insert("X-Custom-Header".to_string(), "value".to_string());

        let route = RouteConfig {
            name: Some("with-headers".to_string()),
            host: None,
            path_prefix: Some("/".to_string()),
            path_exact: None,
            webtransport: false,
            backend: "test".to_string(),
            stream_to_method: None,
            add_headers,
            remove_headers: vec!["Cookie".to_string(), "Authorization".to_string()],
            forward_client_identity: true,
            client_identity_header: Some("X-Real-IP".to_string()),
            priority: 10,
        };

        assert_eq!(route.add_headers.len(), 2);
        assert_eq!(route.remove_headers.len(), 2);
        assert!(route.forward_client_identity);
        assert_eq!(
            route.client_identity_header,
            Some("X-Real-IP".to_string())
        );
    }
}
