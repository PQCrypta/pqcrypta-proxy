# PQCrypta Proxy Configuration Reference

Complete reference for all configuration options in PQCrypta Proxy.

**Version**: 0.1.0
**Last Updated**: 2026-01-24

---

## Table of Contents

- [Server Configuration](#server-configuration)
- [TLS Configuration](#tls-configuration)
- [HTTP Redirect](#http-redirect)
- [Security Headers](#security-headers)
- [Post-Quantum Cryptography](#post-quantum-cryptography)
- [Admin API](#admin-api)
- [Logging](#logging)
- [Basic Rate Limiting](#basic-rate-limiting)
- [Advanced Rate Limiting](#advanced-rate-limiting)
- [Security Settings](#security-settings)
- [TLS Fingerprint Detection](#tls-fingerprint-detection)
- [Circuit Breaker](#circuit-breaker)
- [Connection Pool](#connection-pool)
- [Load Balancer](#load-balancer)
- [Backend Pools](#backend-pools)
- [Single Backends](#single-backends)
- [TLS Passthrough Routes](#tls-passthrough-routes)
- [Routes](#routes)

---

## Server Configuration

```toml
[server]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `bind_address` | string | `"0.0.0.0"` | IP address to bind QUIC/UDP listener |
| `udp_port` | u16 | `443` | Primary UDP port for QUIC/HTTP3/WebTransport |
| `additional_ports` | array[u16] | `[4433, 4434]` | Additional ports for WebTransport |
| `max_connections` | u32 | `10000` | Maximum concurrent connections |
| `max_streams_per_connection` | u32 | `1000` | Maximum concurrent streams per connection |
| `keepalive_interval_secs` | u64 | `15` | Keep-alive interval in seconds |
| `max_idle_timeout_secs` | u64 | `120` | Maximum idle timeout in seconds |
| `enable_ipv6` | bool | `true` | Enable IPv6 dual-stack binding |
| `worker_threads` | usize | `0` | Worker threads (0 = auto-detect based on CPU cores) |

---

## TLS Configuration

```toml
[tls]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_path` | path | `"/etc/pqcrypta/cert.pem"` | Path to TLS certificate chain (PEM format) |
| `key_path` | path | `"/etc/pqcrypta/key.pem"` | Path to TLS private key (PEM format) |
| `ca_cert_path` | path? | `null` | Optional CA certificate for client verification (mTLS) |
| `require_client_cert` | bool | `false` | Require client certificates (mTLS mode) |
| `alpn_protocols` | array[string] | `["h3", "webtransport"]` | ALPN protocols to advertise |
| `min_version` | string | `"1.3"` | Minimum TLS version. Options: `"1.2"`, `"1.3"` |
| `ocsp_stapling` | bool | `true` | Enable OCSP stapling for certificate validation |
| `cert_reload_interval_secs` | u64 | `3600` | Certificate reload interval (0 = disabled) |
| `enable_0rtt` | bool | `false` | Enable 0-RTT early data. **WARNING**: Vulnerable to replay attacks |

---

## HTTP Redirect

```toml
[http_redirect]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable HTTP redirect server on port 80 |
| `port` | u16 | `80` | HTTP port to listen on |
| `redirect_to_https` | bool | `true` | Redirect all HTTP requests to HTTPS (301 permanent) |

---

## Security Headers

```toml
[headers]
```

All responses automatically include these security headers. The `Server` header is always replaced with `PQCProxy v0.1.0`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `hsts` | string | `"max-age=63072000; includeSubDomains; preload"` | HTTP Strict Transport Security header |
| `x_frame_options` | string | `"DENY"` | Prevent clickjacking. Options: `"DENY"`, `"SAMEORIGIN"` |
| `x_content_type_options` | string | `"nosniff"` | Prevent MIME-type sniffing |
| `referrer_policy` | string | `"strict-origin-when-cross-origin"` | Control referrer information |
| `permissions_policy` | string | `"camera=(), microphone=(), geolocation=(), interest-cohort=(), fullscreen=(self), payment=()"` | Disable browser features |
| `cross_origin_opener_policy` | string | `"same-origin"` | COOP header. Options: `"same-origin"`, `"same-origin-allow-popups"`, `"unsafe-none"` |
| `cross_origin_embedder_policy` | string | `"require-corp"` | COEP header. Options: `"require-corp"`, `"credentialless"`, `"unsafe-none"` |
| `cross_origin_resource_policy` | string | `"same-origin"` | CORP header. Options: `"same-origin"`, `"same-site"`, `"cross-origin"` |
| `x_permitted_cross_domain_policies` | string | `"none"` | Flash/PDF cross-domain policy |
| `x_download_options` | string | `"noopen"` | IE download options |
| `x_dns_prefetch_control` | string | `"off"` | DNS prefetch control |
| `x_quantum_resistant` | string | `"ML-KEM-1024, ML-DSA-87, X25519MLKEM768"` | Custom PQC branding header |
| `x_security_level` | string | `"Post-Quantum Ready"` | Custom security level header |

---

## Post-Quantum Cryptography

```toml
[pqc]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable PQC hybrid key exchange |
| `provider` | string | `"openssl3.5"` | PQC provider. Options: `"openssl3.5"`, `"rustls-pqc"` |
| `openssl_path` | path? | `"/usr/local/openssl-3.5/bin/openssl"` | Path to OpenSSL 3.5+ binary |
| `openssl_lib_path` | path? | `"/usr/local/openssl-3.5/lib64"` | OpenSSL library path |
| `preferred_kem` | string | `"X25519MLKEM768"` | Preferred KEM algorithm. Options: `"X25519MLKEM768"`, `"kyber768"`, `"kyber1024"`, `"mlkem768"`, `"mlkem1024"` |
| `fallback_to_classical` | bool | `true` | Fallback to classical TLS if PQC unavailable |

---

## Admin API

```toml
[admin]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable admin HTTP API |
| `bind_address` | string | `"127.0.0.1"` | Admin API bind address (use localhost for security) |
| `port` | u16 | `8081` | Admin API port |
| `require_mtls` | bool | `false` | Require mTLS for admin API access |
| `auth_token` | string? | `null` | Bearer token for API authentication |
| `allowed_ips` | array[string] | `["127.0.0.1", "::1"]` | IP addresses allowed to access admin API |

### Admin API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with backend status |
| `/metrics` | GET | Prometheus metrics |
| `/reload` | POST | Reload configuration |
| `/shutdown` | POST | Graceful shutdown |
| `/config` | GET | Read-only config view |
| `/backends` | GET | Backend health status |
| `/tls` | GET | TLS certificate info |

---

## Logging

```toml
[logging]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `level` | string | `"info"` | Log level. Options: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `format` | string | `"json"` | Log format. Options: `"json"`, `"text"` |
| `file` | path? | `null` | Log file path (null = stdout) |
| `access_log` | bool | `true` | Enable access logs |
| `access_log_file` | path? | `null` | Access log file path |

---

## Basic Rate Limiting

```toml
[rate_limiting]
```

Simple per-IP rate limiting. For advanced features, use `[advanced_rate_limiting]`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable basic rate limiting |
| `requests_per_second` | u32 | `100` | Requests per second per IP |
| `burst_size` | u32 | `50` | Burst size for token bucket |
| `connection_rate_limit` | bool | `true` | Enable connection rate limiting |
| `connections_per_second` | u32 | `10` | New connections per second per IP |

---

## Advanced Rate Limiting

```toml
[advanced_rate_limiting]
```

Multi-dimensional rate limiting with composite keys, JA3/JA4 fingerprinting, and adaptive ML.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable advanced rate limiting (overrides basic) |
| `ipv6_subnet_bits` | u8 | `64` | IPv6 subnet grouping (64 = /64 subnets as single client) |
| `trusted_proxies` | array[string] | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.1"]` | Trusted proxies for X-Forwarded-For parsing |

### Key Resolution Strategy

```toml
[advanced_rate_limiting.key_strategy]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `order` | array[string] | `["api_key", "jwt_subject", "ja3_fingerprint", "real_ip", "source_ip"]` | Priority order for key resolution (first found wins) |
| `fallback` | string | `"source_ip"` | Fallback key type if none found |
| `use_composite` | bool | `false` | Enable composite keys (combine multiple keys) |

**Key Types**: `source_ip`, `real_ip`, `api_key`, `jwt_subject`, `ja3_fingerprint`, `ja4_fingerprint`, `header:NAME`, `cookie:NAME`, `query_param:NAME`, `path`, `method`, `asn`

### Headers for Key Extraction

```toml
[advanced_rate_limiting.headers]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `api_key` | string | `"X-API-Key"` | Header name for API key extraction |
| `user_id` | string | `"X-User-ID"` | Header name for user ID |
| `tenant_id` | string | `"X-Tenant-ID"` | Header name for tenant/org ID |
| `real_ip` | string | `"X-Real-IP"` | Header name for real IP |

### Global Limits

```toml
[advanced_rate_limiting.global_limits]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `100000` | Global requests per second (DDoS protection) |
| `burst_size` | u32 | `50000` | Global burst size |

### Per-IP Limits

```toml
[advanced_rate_limiting.global_limits.per_ip]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `1000` | Per-IP requests per second |
| `burst_size` | u32 | `500` | Per-IP burst size |
| `requests_per_minute` | u32? | `30000` | Per-IP requests per minute (sliding window) |
| `requests_per_hour` | u32? | `500000` | Per-IP requests per hour (sliding window) |

### Per-Fingerprint Limits

```toml
[advanced_rate_limiting.global_limits.per_fingerprint]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `100` | Per-fingerprint requests per second |
| `burst_size` | u32 | `50` | Per-fingerprint burst size |
| `requests_per_minute` | u32? | `3000` | Per-fingerprint requests per minute |
| `requests_per_hour` | u32? | `50000` | Per-fingerprint requests per hour |

### Fingerprint-Based Limiting

```toml
[advanced_rate_limiting.fingerprint_limiting]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable JA3/JA4 fingerprint-based limiting |
| `prefer_over_ip` | bool | `false` | Use fingerprint as primary key (NAT scenarios) |
| `blocked_fingerprints` | array[string] | `[]` | Block known malicious fingerprints |
| `trusted_fingerprints` | map[string, PerKeyLimits] | `{}` | Higher limits for known good fingerprints |

#### Unknown Fingerprint Limits

```toml
[advanced_rate_limiting.fingerprint_limiting.unknown_limits]
```

More restrictive limits for unrecognized TLS fingerprints.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `50` | Unknown fingerprint requests per second |
| `burst_size` | u32 | `25` | Unknown fingerprint burst size |
| `requests_per_minute` | u32? | `1500` | Unknown fingerprint per minute limit |
| `requests_per_hour` | u32? | `25000` | Unknown fingerprint per hour limit |

### Adaptive Rate Limiting

```toml
[advanced_rate_limiting.adaptive]
```

ML-inspired anomaly detection that learns normal traffic patterns.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable adaptive rate limiting |
| `baseline_window_secs` | u64 | `3600` | Baseline learning window (1 hour) |
| `sensitivity` | f64 | `0.7` | Anomaly detection sensitivity (0.0-1.0) |
| `auto_adjust` | bool | `false` | Auto-adjust limits based on traffic |
| `min_samples` | u64 | `1000` | Minimum samples before blocking |
| `std_dev_multiplier` | f64 | `3.0` | Standard deviations for anomaly threshold |

### Per-Route Rate Limits

```toml
[advanced_rate_limiting.route_limits.ROUTE_NAME]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pattern` | string | required | Route pattern (path prefix or regex) |
| `key_override` | string? | `null` | Override key resolution for this route |
| `exempt_keys` | array[string] | `[]` | Keys exempt from rate limiting |

```toml
[advanced_rate_limiting.route_limits.ROUTE_NAME.limits]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `100` | Route-specific requests per second |
| `burst_size` | u32 | `50` | Route-specific burst size |
| `requests_per_minute` | u32? | `null` | Route-specific per minute limit |
| `requests_per_hour` | u32? | `null` | Route-specific per hour limit |

### Composite Keys

```toml
[[advanced_rate_limiting.composite_keys]]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Name for logging/metrics |
| `keys` | array[string] | required | Keys to combine (e.g., `["header:X-Tenant-ID", "jwt_subject"]`) |
| `routes` | array[string] | `[]` | Routes this applies to (empty = all) |

```toml
[advanced_rate_limiting.composite_keys.limits]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `requests_per_second` | u32 | `100` | Composite key requests per second |
| `burst_size` | u32 | `50` | Composite key burst size |
| `requests_per_minute` | u32? | `null` | Composite key per minute limit |
| `requests_per_hour` | u32? | `null` | Composite key per hour limit |

---

## Security Settings

```toml
[security]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_request_size` | usize | `10485760` | Maximum request body size in bytes (10MB) |
| `max_header_size` | usize | `65536` | Maximum header size in bytes (64KB) |
| `connection_timeout_secs` | u64 | `30` | Connection timeout in seconds |
| `dos_protection` | bool | `true` | Enable DoS protection |
| `blocked_ips` | array[string] | `[]` | Manually blocked IP addresses |
| `allowed_ips` | array[string] | `[]` | IP whitelist (empty = allow all) |
| `geoip_db_path` | path? | `"/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb"` | MaxMind GeoIP database path |
| `blocked_countries` | array[string] | `[]` | Blocked country codes (ISO 3166-1 alpha-2, e.g., `["CN", "RU", "KP"]`) |
| `max_connections_per_ip` | u32 | `100` | Maximum connections per IP |
| `auto_block_threshold` | u32 | `10` | Suspicious patterns before auto-block |
| `auto_block_duration_secs` | u64 | `300` | Auto-block duration (5 minutes) |
| `error_4xx_threshold` | u32 | `100` | 4xx errors before checking rate |
| `min_requests_for_error_check` | u64 | `200` | Minimum requests before error rate check |
| `error_rate_threshold` | f64 | `0.7` | Error rate threshold (70%) to trigger suspicious |
| `error_window_secs` | u64 | `60` | Error tracking sliding window (1 minute) |

---

## TLS Fingerprint Detection

```toml
[fingerprint]
```

JA3/JA4 TLS fingerprint detection for identifying browsers, bots, and malware.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable TLS fingerprint detection |
| `malicious_block_duration_secs` | u64 | `3600` | Block duration for malicious fingerprints (1 hour) |
| `suspicious_block_duration_secs` | u64 | `300` | Block duration for suspicious fingerprints (5 minutes) |
| `suspicious_rate_threshold` | u64 | `100` | Request count to trigger suspicious rate check |
| `suspicious_rate_window_secs` | u64 | `60` | Time window for suspicious rate detection (1 minute) |
| `cache_max_age_secs` | u64 | `3600` | Fingerprint cache max age (1 hour) |

---

## Circuit Breaker

```toml
[circuit_breaker]
```

Protects backends from cascading failures with automatic recovery.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable circuit breaker |
| `half_open_delay_secs` | u64 | `30` | Time before Open → Half-Open transition |
| `half_open_max_requests` | u32 | `3` | Max test requests in Half-Open state |
| `failure_threshold` | u32 | `5` | Failures to open the circuit |
| `success_threshold` | u32 | `2` | Successes to close from Half-Open |
| `stale_counter_cleanup_secs` | u64 | `300` | Stale counter cleanup interval (5 minutes) |

**Circuit States**:
- **Closed**: Normal operation, requests pass through
- **Open**: All requests fail fast (503), no backend requests
- **Half-Open**: Limited test requests to check backend recovery

---

## Connection Pool

```toml
[connection_pool]
```

HTTP connection pool settings for backend connections.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `idle_timeout_secs` | u64 | `90` | Idle connection timeout (seconds) |
| `max_idle_per_host` | usize | `10` | Maximum idle connections per host |
| `max_connections_per_host` | usize | `100` | Maximum total connections per host |
| `acquire_timeout_ms` | u64 | `5000` | Connection acquire timeout (5 seconds) |

---

## Load Balancer

```toml
[load_balancer]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable load balancing |
| `default_algorithm` | string | `"least_connections"` | Default algorithm for all pools |

**Algorithms**:
- `least_connections` - Routes to server with fewest active connections (default)
- `round_robin` - Simple rotation through servers
- `weighted_round_robin` - nginx-style smooth weighted distribution
- `random` - Random server selection
- `ip_hash` - Consistent hashing by client IP
- `least_response_time` - Routes to fastest responding server (EMA tracking)

### Session Affinity

```toml
[load_balancer.session_affinity]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable session affinity globally |
| `cookie_name` | string | `"PQCPROXY_BACKEND"` | Cookie name for session tracking |
| `cookie_ttl_secs` | u64 | `3600` | Cookie TTL (0 = session cookie) |
| `cookie_secure` | bool | `true` | Use secure cookies (HTTPS only) |
| `cookie_httponly` | bool | `true` | Use HttpOnly cookies |
| `cookie_samesite` | string | `"lax"` | SameSite attribute. Options: `"strict"`, `"lax"`, `"none"` |

### Request Queue

```toml
[load_balancer.queue]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable request queuing when backends saturated |
| `max_size` | usize | `1000` | Maximum queue size per pool |
| `timeout_ms` | u64 | `5000` | Queue timeout (5 seconds) |

### Slow Start

```toml
[load_balancer.slow_start]
```

Gradually increases traffic to recovering backends.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable slow start |
| `duration_secs` | u64 | `30` | Duration for gradual traffic increase |
| `initial_weight_percent` | u32 | `10` | Initial weight percentage (1-100) |

### Connection Draining

```toml
[load_balancer.connection_draining]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable connection draining |
| `timeout_secs` | u64 | `30` | Max time to wait for connections to drain |

---

## Backend Pools

```toml
[backend_pools.POOL_NAME]
```

Backend pools group multiple servers for load balancing.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Pool name (used in routes as `backend = "name"`) |
| `algorithm` | string | `"least_connections"` | Load balancing algorithm (overrides global) |
| `health_aware` | bool | `true` | Skip unhealthy backends |
| `affinity` | string | `"none"` | Session stickiness. Options: `"none"`, `"cookie"`, `"ip_hash"`, `"header"` |
| `affinity_header` | string? | `null` | Header name when `affinity = "header"` |
| `queue_max_size` | usize? | `null` | Pool-specific queue size (overrides global) |
| `queue_timeout_ms` | u64? | `null` | Pool-specific queue timeout (overrides global) |
| `health_check_path` | string? | `null` | Health check endpoint path |
| `health_check_interval_secs` | u64 | `10` | Health check interval |

### Pool Servers

```toml
[[backend_pools.POOL_NAME.servers]]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `address` | string | required | Server address (host:port) |
| `weight` | u32 | `100` | Weight for weighted algorithms (1-1000) |
| `priority` | u32 | `1` | Priority for failover (lower = higher priority) |
| `max_connections` | u32 | `100` | Maximum connections to this server |
| `timeout_ms` | u64 | `30000` | Request timeout (30 seconds) |
| `tls_mode` | string | `"terminate"` | TLS mode. Options: `"terminate"`, `"reencrypt"`, `"passthrough"` |
| `tls_cert` | path? | `null` | CA certificate for backend verification |
| `tls_skip_verify` | bool | `false` | Skip TLS verification (**DANGEROUS** - testing only) |
| `tls_sni` | string? | `null` | Custom SNI hostname for TLS handshake |

---

## Single Backends

```toml
[backends.BACKEND_NAME]
```

Single backend definitions (use backend pools for load balancing).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string | required | Backend name (used in routes) |
| `type` | string | required | Backend type. Options: `"http1"`, `"http2"`, `"http3"`, `"unix"`, `"tcp"` |
| `address` | string | required | Backend address (e.g., `"127.0.0.1:8080"` or `"unix:/run/php-fpm.sock"`) |
| `tls_mode` | string | `"terminate"` | TLS mode. Options: `"terminate"`, `"reencrypt"`, `"passthrough"` |
| `tls` | bool | `false` | Legacy: Enable TLS (use `tls_mode` instead) |
| `tls_cert` | path? | `null` | CA certificate for backend verification |
| `tls_client_cert` | path? | `null` | Client certificate for mTLS |
| `tls_client_key` | path? | `null` | Client key for mTLS |
| `tls_skip_verify` | bool | `false` | Skip TLS verification (**DANGEROUS**) |
| `tls_sni` | string? | `null` | Custom SNI hostname |
| `timeout_ms` | u64 | `30000` | Connection timeout (30 seconds) |
| `max_connections` | u32 | `100` | Maximum connections to this backend |
| `health_check` | string? | `null` | Health check endpoint path |
| `health_check_interval_secs` | u64 | `30` | Health check interval |

### TLS Modes Explained

1. **`terminate`** (default): TLS terminates at proxy, plain HTTP to backend
   ```
   Client ←(HTTPS)→ Proxy ←(HTTP)→ Backend
   ```

2. **`reencrypt`**: TLS terminates at proxy, re-encrypts to backend
   ```
   Client ←(HTTPS)→ Proxy ←(HTTPS)→ Backend
   ```

3. **`passthrough`**: No TLS termination, SNI-based routing (use `[[passthrough_routes]]`)
   ```
   Client ←(HTTPS)→ Proxy ←(HTTPS)→ Backend (same TLS session)
   ```

---

## TLS Passthrough Routes

```toml
[[passthrough_routes]]
```

SNI-based routing without TLS termination.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string? | `null` | Route name for logging |
| `sni` | string | required | SNI hostname pattern (supports wildcards: `*.example.com`) |
| `backend` | string | required | Backend address (host:port) |
| `proxy_protocol` | bool | `false` | Enable PROXY protocol v2 for client IP preservation |
| `timeout_ms` | u64 | `30000` | Connection timeout |

---

## Routes

```toml
[[routes]]
```

Route configuration for request matching and forwarding.

### Basic Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `name` | string? | `null` | Route name for logging/metrics |
| `host` | string? | `null` | Host pattern (supports wildcards: `*.example.com`) |
| `backend` | string | `""` | Backend or pool name to route to |
| `priority` | i32 | `100` | Priority (lower = higher priority) |

### Path Matching (use one)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `path_prefix` | string? | `null` | Match if path starts with value (e.g., `/api` matches `/api/v1`) |
| `path_exact` | string? | `null` | Match only the exact path (e.g., `/health` won't match `/health/db`) |
| `path_regex` | string? | `null` | Regex pattern for complex matching (e.g., `^/v[0-9]+/.*`) |

### Header Manipulation

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `add_headers` | map[string, string] | `{}` | Headers to add to backend request |
| `remove_headers` | array[string] | `[]` | Headers to strip before sending to backend |
| `headers_override` | map[string, string] | `{}` | Override global security headers for this route |
| `forward_client_identity` | bool | `false` | Forward client identity header |
| `client_identity_header` | string? | `null` | Client identity header name |

### WebTransport

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webtransport` | bool | `false` | Enable WebTransport for this route |
| `stream_to_method` | string? | `null` | Transform WebTransport stream to HTTP method |

### Redirects

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `redirect` | string? | `null` | Redirect URL (for SEO redirects) |
| `redirect_permanent` | bool | `false` | Use 301 (permanent) vs 302 (temporary) |

### Special Modes

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allow_http11` | bool | `false` | Allow HTTP/1.1 for this route (for search bots) |
| `skip_bot_blocking` | bool | `false` | Skip bot protection for this route |
| `stripe_compatibility` | bool | `false` | Remove COEP/COOP headers (for Stripe.js) |
| `timeout_override_ms` | u64? | `null` | Custom timeout for this route |

### CORS Configuration

```toml
[routes.cors]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allow_origin` | string? | `null` | Allowed origin (e.g., `"https://example.com"`) |
| `allow_methods` | array[string] | `[]` | Allowed HTTP methods |
| `allow_headers` | array[string] | `[]` | Allowed request headers |
| `allow_credentials` | bool | `false` | Allow credentials (cookies, auth headers) |
| `max_age` | u64 | `0` | Preflight cache max age (seconds) |

---

## Environment Variables

All configuration can be overridden via environment variables:

| Variable | Description |
|----------|-------------|
| `PQCRYPTA_CONFIG` | Configuration file path |
| `PQCRYPTA_UDP_PORT` | Override UDP port |
| `PQCRYPTA_ADMIN_PORT` | Override admin API port |
| `PQCRYPTA_LOG_LEVEL` | Log level |
| `PQCRYPTA_JSON_LOGS` | Enable JSON logging |

---

## CLI Arguments

```
pqcrypta-proxy [OPTIONS]

Options:
  -c, --config <PATH>       Configuration file [default: /etc/pqcrypta/config.toml]
      --udp-port <PORT>     Override UDP port for QUIC
      --admin-port <PORT>   Override admin API port
      --log-level <LEVEL>   Log level [default: info]
      --json-logs           Enable JSON log format
      --no-pqc              Disable PQC hybrid key exchange
      --watch-config        Watch config file for changes [default: true]
      --validate            Validate configuration only
  -h, --help                Print help
  -V, --version             Print version
```

---

## See Also

- [example-config.toml](../config/example-config.toml) - Complete example with all options
- [SECURITY.md](SECURITY.md) - Security hardening guide
- [README.md](../README.md) - Quick start guide
