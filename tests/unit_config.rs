//! Unit tests for configuration parsing and validation

use pqcrypta_proxy::config::*;
use std::collections::HashMap;

#[test]
fn test_default_config() {
    let config = ProxyConfig::default();

    assert_eq!(config.server.udp_port, 4433);
    assert_eq!(config.server.bind_address, "0.0.0.0");
    assert_eq!(config.admin.port, 8081);
    assert!(config.pqc.enabled);
    assert_eq!(config.pqc.provider, "openssl3.5");
}

#[test]
fn test_server_socket_addr() {
    let config = ServerConfig::default();
    let addr = config.socket_addr().unwrap();

    assert_eq!(addr.port(), 4433);
    assert_eq!(addr.ip().to_string(), "0.0.0.0");
}

#[test]
fn test_admin_socket_addr() {
    let config = AdminConfig::default();
    let addr = config.socket_addr().unwrap();

    assert_eq!(addr.port(), 8081);
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
}

#[test]
fn test_config_parsing_minimal() {
    let toml_content = r#"
[server]
udp_port = 4433

[tls]
cert_path = "/etc/test/cert.pem"
key_path = "/etc/test/key.pem"
"#;

    let config: ProxyConfig = toml::from_str(toml_content).unwrap();

    assert_eq!(config.server.udp_port, 4433);
    assert_eq!(
        config.tls.cert_path.to_str().unwrap(),
        "/etc/test/cert.pem"
    );
}

#[test]
fn test_config_parsing_full() {
    let toml_content = r#"
[server]
bind_address = "0.0.0.0"
udp_port = 4433
max_connections = 5000
max_streams_per_connection = 500

[tls]
cert_path = "/etc/test/cert.pem"
key_path = "/etc/test/key.pem"
alpn_protocols = ["h3", "webtransport"]

[pqc]
enabled = true
provider = "openssl3.5"
preferred_kem = "kyber768"

[admin]
enabled = true
port = 9090
allowed_ips = ["127.0.0.1"]

[backends.test-backend]
name = "test-backend"
type = "http1"
address = "127.0.0.1:8080"
timeout_ms = 5000
max_connections = 50

[[routes]]
name = "test-route"
path_prefix = "/api"
backend = "test-backend"
webtransport = true
"#;

    let config: ProxyConfig = toml::from_str(toml_content).unwrap();

    assert_eq!(config.server.udp_port, 4433);
    assert_eq!(config.server.max_connections, 5000);
    assert!(config.pqc.enabled);
    assert_eq!(config.admin.port, 9090);
    assert_eq!(config.backends.len(), 1);
    assert_eq!(config.routes.len(), 1);
    assert!(config.routes[0].webtransport);
}

#[test]
fn test_backend_types() {
    let toml_http1 = r#"
name = "http1"
type = "http1"
address = "127.0.0.1:8080"
"#;
    let backend: BackendConfig = toml::from_str(toml_http1).unwrap();
    assert_eq!(backend.backend_type, BackendType::Http1);

    let toml_http2 = r#"
name = "http2"
type = "http2"
address = "127.0.0.1:8080"
"#;
    let backend: BackendConfig = toml::from_str(toml_http2).unwrap();
    assert_eq!(backend.backend_type, BackendType::Http2);

    let toml_unix = r#"
name = "unix"
type = "unix"
address = "unix:/run/test.sock"
"#;
    let backend: BackendConfig = toml::from_str(toml_unix).unwrap();
    assert_eq!(backend.backend_type, BackendType::Unix);

    let toml_tcp = r#"
name = "tcp"
type = "tcp"
address = "127.0.0.1:9000"
"#;
    let backend: BackendConfig = toml::from_str(toml_tcp).unwrap();
    assert_eq!(backend.backend_type, BackendType::Tcp);
}

#[test]
fn test_route_matching_exact_host() {
    let mut config = ProxyConfig::default();

    config.backends.insert(
        "test".to_string(),
        BackendConfig {
            name: "test".to_string(),
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
        name: Some("test-route".to_string()),
        host: Some("api.example.com".to_string()),
        path_prefix: Some("/api".to_string()),
        path_exact: None,
        webtransport: false,
        backend: "test".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 100,
    });

    // Should match
    let route = config.find_route(Some("api.example.com"), "/api/test", false);
    assert!(route.is_some());
    assert_eq!(route.unwrap().name, Some("test-route".to_string()));

    // Should not match (wrong host)
    let route = config.find_route(Some("other.example.com"), "/api/test", false);
    assert!(route.is_none());

    // Should not match (wrong path)
    let route = config.find_route(Some("api.example.com"), "/other", false);
    assert!(route.is_none());
}

#[test]
fn test_route_matching_wildcard_host() {
    let mut config = ProxyConfig::default();

    config.backends.insert(
        "test".to_string(),
        BackendConfig {
            name: "test".to_string(),
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
        backend: "test".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 100,
    });

    // Should match subdomain
    let route = config.find_route(Some("api.example.com"), "/", false);
    assert!(route.is_some());

    // Should match root domain
    let route = config.find_route(Some("example.com"), "/", false);
    assert!(route.is_some());

    // Should not match different domain
    let route = config.find_route(Some("example.org"), "/", false);
    assert!(route.is_none());
}

#[test]
fn test_route_matching_webtransport() {
    let mut config = ProxyConfig::default();

    config.backends.insert(
        "test".to_string(),
        BackendConfig {
            name: "test".to_string(),
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
        name: Some("wt-route".to_string()),
        host: None,
        path_prefix: Some("/wt".to_string()),
        path_exact: None,
        webtransport: true,
        backend: "test".to_string(),
        stream_to_method: Some("POST".to_string()),
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 10,
    });

    // HTTP-only route
    config.routes.push(RouteConfig {
        name: Some("http-route".to_string()),
        host: None,
        path_prefix: Some("/http".to_string()),
        path_exact: None,
        webtransport: false,
        backend: "test".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 10,
    });

    // WebTransport request should match WebTransport route
    let route = config.find_route(None, "/wt/stream", true);
    assert!(route.is_some());
    assert_eq!(route.unwrap().name, Some("wt-route".to_string()));

    // Non-WebTransport request should not match WebTransport route
    let route = config.find_route(None, "/wt/stream", false);
    assert!(route.is_none());

    // HTTP request should match HTTP route
    let route = config.find_route(None, "/http/api", false);
    assert!(route.is_some());
    assert_eq!(route.unwrap().name, Some("http-route".to_string()));
}

#[test]
fn test_route_priority() {
    let mut config = ProxyConfig::default();

    config.backends.insert(
        "test".to_string(),
        BackendConfig {
            name: "test".to_string(),
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

    // Low priority (higher number)
    config.routes.push(RouteConfig {
        name: Some("low-priority".to_string()),
        host: None,
        path_prefix: Some("/".to_string()),
        path_exact: None,
        webtransport: false,
        backend: "test".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 100,
    });

    // High priority (lower number)
    config.routes.push(RouteConfig {
        name: Some("high-priority".to_string()),
        host: None,
        path_prefix: Some("/api".to_string()),
        path_exact: None,
        webtransport: false,
        backend: "test".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 10,
    });

    // Should match high-priority route for /api paths
    let route = config.find_route(None, "/api/test", false);
    assert!(route.is_some());
    assert_eq!(route.unwrap().name, Some("high-priority".to_string()));

    // Should match low-priority route for other paths
    let route = config.find_route(None, "/other", false);
    assert!(route.is_some());
    assert_eq!(route.unwrap().name, Some("low-priority".to_string()));
}

#[test]
fn test_config_validation_missing_backend() {
    let mut config = ProxyConfig::default();

    // Add route that references non-existent backend
    config.routes.push(RouteConfig {
        name: Some("invalid-route".to_string()),
        host: None,
        path_prefix: Some("/".to_string()),
        path_exact: None,
        webtransport: false,
        backend: "non-existent".to_string(),
        stream_to_method: None,
        add_headers: HashMap::new(),
        remove_headers: Vec::new(),
        forward_client_identity: false,
        client_identity_header: None,
        priority: 100,
    });

    let result = config.validate();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unknown backend"));
}
