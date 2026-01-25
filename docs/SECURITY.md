# Security Checklist & Operational Guide

This document provides security hardening guidelines, operational best practices, and a migration plan for deploying PQCrypta Proxy in production environments.

**Last Updated**: 2026-01-25
**Status**: All security features implemented with hardening release

## Security Features Status

| Feature | Status | Module |
|---------|--------|--------|
| TLS 1.3 Only | ✅ Complete | `http_listener.rs` |
| PQC Hybrid Key Exchange | ✅ Complete | `http_listener.rs` (X25519MLKEM768) |
| Rate Limiting | ✅ Complete | `security.rs` |
| DoS Protection | ✅ Complete | `security.rs` |
| GeoIP Blocking | ✅ Complete | `security.rs` |
| JA3/JA4 Fingerprinting | ✅ Complete | `fingerprint.rs` |
| Circuit Breaker | ✅ Complete | `security.rs` + `http_listener.rs` |
| IP Blocking | ✅ Complete | `security.rs` |
| Request Size Limits | ✅ Complete | `security.rs` |
| Security Headers | ✅ Complete | `http_listener.rs` |
| Background Cleanup | ✅ Complete | `security.rs` |
| Memory Exhaustion Prevention | ✅ Complete | `security.rs`, `rate_limiter.rs` |
| ReDoS Prevention | ✅ Complete | `config.rs` |
| Command Injection Prevention | ✅ Complete | `acme.rs` |
| Safe Panic Handling | ✅ Complete | All modules |

## Security Checklist

### TLS Configuration

- [x] **Use TLS 1.3 only** (enforced by QUIC)
- [x] **Enable hybrid PQC key exchange** for quantum resistance (X25519MLKEM768)
- [ ] **Use strong certificates** (ECDSA P-384 or Ed25519 recommended)
- [ ] **Enable OCSP stapling** for certificate validation
- [ ] **Configure automatic certificate renewal** with Let's Encrypt
- [ ] **Disable 0-RTT** if replay attacks are a concern
- [x] **Set appropriate cipher suites** (TLS 1.3 only has secure options)

```toml
[tls]
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"
min_version = "1.3"
ocsp_stapling = true
cert_reload_interval_secs = 3600
# SECURITY: Disable 0-RTT to prevent replay attacks (default: false)
enable_0rtt = false
```

### TLS Modes

PQCrypta Proxy supports three TLS modes for backend connections:

#### 1. TLS Terminate (Default)
- TLS is terminated at the proxy
- Backend connections use plain HTTP
- Most common mode for internal backends

```toml
[backends.apache]
name = "apache"
type = "http1"
address = "127.0.0.1:8080"
tls_mode = "terminate"
```

#### 2. TLS Re-encrypt
- TLS is terminated at the proxy
- New TLS connection established to backend
- Use for backends requiring end-to-end encryption

```toml
[backends.internal-api]
name = "internal-api"
type = "http1"
address = "internal.example.com:443"
tls_mode = "reencrypt"
tls_cert = "/path/to/ca.pem"           # Custom CA for verification
tls_client_cert = "/path/to/client.pem" # mTLS client certificate
tls_client_key = "/path/to/client.key"  # mTLS client key
tls_skip_verify = false                 # NEVER set true in production
tls_sni = "internal.example.com"        # Custom SNI hostname
```

**Security considerations for re-encrypt mode:**
- Always verify backend certificates (`tls_skip_verify = false`)
- Use mTLS for mutual authentication when possible
- Ensure CA certificates are up to date
- Monitor certificate expiration

#### 3. TLS Passthrough (SNI Routing)
- No TLS termination at proxy
- Traffic routed based on SNI hostname
- Backend handles all TLS

```toml
[[passthrough_routes]]
name = "external-service"
sni = "external.example.com"    # Supports wildcards: *.example.com
backend = "10.0.0.5:443"
proxy_protocol = false          # Enable for client IP preservation
timeout_ms = 30000
```

**Security considerations for passthrough mode:**
- Proxy cannot inspect traffic (no WAF, rate limiting)
- Backend must handle all security
- Use for services requiring end-to-end encryption
- Consider PROXY protocol for client IP preservation

### Security Headers

PQCrypta Proxy automatically injects security headers to all responses:

```toml
[headers]
# HSTS - 2 year max-age for preload list eligibility
hsts = "max-age=63072000; includeSubDomains; preload"

# Prevent clickjacking
x_frame_options = "DENY"

# Prevent MIME-type sniffing
x_content_type_options = "nosniff"

# Control referrer information
referrer_policy = "strict-origin-when-cross-origin"

# Disable browser features
permissions_policy = "camera=(), microphone=(), geolocation=(), interest-cohort=()"

# Cross-origin isolation
cross_origin_opener_policy = "same-origin"
cross_origin_embedder_policy = "require-corp"
cross_origin_resource_policy = "same-origin"

# Additional security
x_permitted_cross_domain_policies = "none"
x_download_options = "noopen"
x_dns_prefetch_control = "off"

# Custom branding (hides backend identity)
x_quantum_resistant = "ML-KEM-1024, ML-DSA-87, X25519MLKEM768"
x_security_level = "Post-Quantum Ready"
```

**Note:** The proxy automatically replaces backend `Server` headers with `PQCProxy v0.1.0` to hide backend identity.

### Post-Quantum Cryptography

- [ ] **Install OpenSSL 3.5+** with OQS provider
- [ ] **Enable hybrid PQC** (combines classical + quantum-resistant)
- [ ] **Use x25519_kyber768** as preferred KEM
- [ ] **Enable fallback** to classical TLS for incompatible clients

```toml
[pqc]
enabled = true
provider = "openssl3.5"
preferred_kem = "x25519_kyber768"
fallback_to_classical = true
```

### Admin API Security

- [ ] **Bind admin API to localhost only** by default
- [ ] **Enable mTLS** for remote admin access
- [ ] **Configure IP allowlist** for admin access
- [ ] **Use authentication token** for API calls
- [ ] **Never expose admin API to the internet** without mTLS

```toml
[admin]
enabled = true
bind_address = "127.0.0.1"  # localhost only
port = 8081
require_mtls = true
auth_token = "your-secret-token-here"
allowed_ips = ["127.0.0.1", "10.0.0.0/8"]
```

### Rate Limiting & DoS Protection ✅ FULLY IMPLEMENTED & INTEGRATED

All rate limiting and DoS protection features are now fully implemented and integrated into the request flow:

- [x] **Request rate limiting** - Per-IP token bucket via `governor` crate (integrated via security_middleware)
- [x] **Connection rate limiting** - Configurable `max_connections_per_ip` (integrated via security_middleware)
- [x] **Burst handling** - `burst_size` configuration (integrated via security_middleware)
- [x] **Automatic IP blocking** - After `auto_block_threshold` exceeded (integrated with auto-expiration)
- [x] **Maximum request/header sizes** - 413/431 responses for oversized requests (integrated via security_middleware)
- [x] **Connection timeouts** - Configurable timeouts (integrated via axum-server)
- [x] **DoS protection** - Connection limits, auto-blocking with expiration (integrated via security_middleware)
- [x] **GeoIP blocking** - MaxMind DB integration for country-level blocking (loaded at startup)
- [x] **JA3/JA4 fingerprinting** - Full TLS ClientHello extraction and classification (new `fingerprint.rs` module)
- [x] **Circuit breaker** - Backend protection from cascading failures (integrated in `proxy_handler`)
- [x] **Background cleanup** - Auto-spawned task for expired entry cleanup (60-second interval)

```toml
[security]
dos_protection = true
blocked_ips = []
geoip_db_path = "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb"
blocked_countries = ["CN", "RU", "KP"]

[security.rate_limit]
requests_per_second = 100
burst_size = 200
auto_block_threshold = 1000
block_duration_secs = 3600
max_connections_per_ip = 100
```

### Network Security

- [ ] **Configure firewall** to allow only required ports
- [ ] **Use separate network segments** for backends
- [ ] **Enable mTLS** for backend connections if required
- [ ] **Block suspicious IP addresses**

```bash
# Linux firewall rules
iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP redirect
iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS (TCP)
iptables -A INPUT -p udp --dport 443 -j ACCEPT   # QUIC (UDP)
iptables -A INPUT -p tcp --dport 8081 -s 127.0.0.1 -j ACCEPT  # Admin (localhost only)
```

### Process Security

- [ ] **Run as non-root user**
- [ ] **Use systemd security hardening** (NoNewPrivileges, ProtectSystem, etc.)
- [ ] **Limit file descriptors** appropriately
- [ ] **Enable SELinux/AppArmor** profiles
- [ ] **Mount sensitive directories as read-only**

### Logging & Monitoring

- [ ] **Enable JSON logging** for structured log analysis
- [ ] **Send logs to centralized logging system**
- [ ] **Configure Prometheus metrics** scraping
- [ ] **Set up alerting** for health check failures
- [ ] **Monitor certificate expiration**

```toml
[logging]
level = "info"
format = "json"
access_log = true
access_log_file = "/var/log/pqcrypta-proxy/access.log"
```

### Secrets Management

- [ ] **Never commit secrets** to version control
- [ ] **Use environment variables** for sensitive configuration
- [ ] **Encrypt secrets at rest**
- [ ] **Rotate credentials regularly**
- [ ] **Use secret management tools** (Vault, AWS Secrets Manager)

## Operational Playbook

### Startup Procedure

1. Validate configuration:
   ```bash
   pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --validate
   ```

2. Start service:
   ```bash
   systemctl start pqcrypta-proxy
   ```

3. Verify health:
   ```bash
   curl http://127.0.0.1:8081/health
   ```

4. Verify server header:
   ```bash
   curl -I https://your-domain.com/ | grep -i server
   # Expected: server: PQCProxy v0.1.0
   ```

### Configuration Reload

Hot-reload without restart:
```bash
curl -X POST http://127.0.0.1:8081/reload
```

Reload TLS certificates only:
```bash
curl -X POST http://127.0.0.1:8081/reload -d '{"tls_only":true}'
```

### Graceful Shutdown

```bash
# Via systemd
systemctl stop pqcrypta-proxy

# Via admin API
curl -X POST http://127.0.0.1:8081/shutdown

# Via signal
kill -TERM $(pidof pqcrypta-proxy)
```

### Health Monitoring

```bash
# Health check
curl http://127.0.0.1:8081/health

# Prometheus metrics
curl http://127.0.0.1:8081/metrics

# Backend status
curl http://127.0.0.1:8081/backends

# TLS certificate info
curl http://127.0.0.1:8081/tls
```

### Troubleshooting

1. **Check service status**:
   ```bash
   systemctl status pqcrypta-proxy
   journalctl -u pqcrypta-proxy -f
   ```

2. **Verify configuration**:
   ```bash
   pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --validate
   ```

3. **Check port binding**:
   ```bash
   ss -ulnp | grep 443    # QUIC UDP port
   ss -tlnp | grep 443    # HTTPS TCP port
   ss -tlnp | grep 80     # HTTP redirect port
   ss -tlnp | grep 8081   # Admin TCP port
   ```

4. **Test HTTP/3 connectivity**:
   ```bash
   # Using curl with HTTP/3 support
   curl --http3 https://your-domain:443/
   ```

5. **Verify TLS certificate**:
   ```bash
   openssl s_client -connect your-domain:443 -alpn h3
   ```

6. **Check Alt-Svc header**:
   ```bash
   curl -I https://your-domain.com/ | grep alt-svc
   # Expected: alt-svc: h3=":443"; ma=86400, h3=":4433"; ma=86400
   ```

### Backup & Recovery

**What to backup:**
- Configuration file (`/etc/pqcrypta/proxy-config.toml`)
- TLS certificates (or Let's Encrypt account)
- Prometheus metrics history (if using persistent storage)

**Recovery procedure:**
1. Install PQCrypta Proxy binary
2. Restore configuration file
3. Restore or regenerate TLS certificates
4. Validate configuration
5. Start service

### Certificate Renewal

For Let's Encrypt with automatic renewal:
```bash
# Certbot post-renewal hook
cat > /etc/letsencrypt/renewal-hooks/post/pqcrypta-reload.sh << 'EOF'
#!/bin/bash
curl -X POST http://127.0.0.1:8081/reload -d '{"tls_only":true}'
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/pqcrypta-reload.sh
```

## Migration Plan

### From nginx/HAProxy/Envoy

1. **Audit existing configuration**:
   - List all virtual hosts and routes
   - Document backend configurations
   - Note TLS settings and certificates
   - Document security headers

2. **Create equivalent PQCrypta config**:
   ```toml
   # Map nginx upstream to backends
   [backends.api]
   name = "api"
   type = "http1"
   address = "127.0.0.1:8080"
   tls_mode = "terminate"

   # Map nginx location to routes
   [[routes]]
   name = "api-route"
   host = "api.example.com"
   path_prefix = "/api"
   backend = "api"

   [routes.cors]
   allow_origin = "https://example.com"
   allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
   ```

3. **Test in parallel**:
   - Run PQCrypta Proxy on different port
   - Use curl/wrk to test routes
   - Compare responses with existing proxy
   - Verify security headers

4. **Switch over**:
   ```bash
   # Stop nginx
   sudo systemctl stop nginx
   sudo systemctl disable nginx

   # Start PQCrypta Proxy
   sudo systemctl start pqcrypta-proxy
   sudo systemctl enable pqcrypta-proxy
   ```

5. **Monitor for issues**:
   - Check logs for errors
   - Monitor metrics
   - Verify all routes work
   - Keep nginx ready for rollback

### From Node.js WebTransport

1. **Update client code**:
   ```javascript
   // Old: Direct connection to Node.js
   const transport = new WebTransport('https://api.example.com:3003/stream');

   // New: Connect via PQCrypta Proxy
   const transport = new WebTransport('https://api.example.com:443/stream');
   ```

2. **Configure backend routing**:
   ```toml
   [backends.nodejs]
   name = "nodejs"
   type = "http1"
   address = "127.0.0.1:3003"

   [[routes]]
   name = "webtransport-stream"
   webtransport = true
   backend = "nodejs"
   stream_to_method = "POST"
   ```

3. **Update firewall rules**:
   - Allow TCP/UDP 443 (HTTPS/QUIC)
   - Remove external access to Node.js port

### Rollback Procedure

If issues occur after migration:

1. **Immediate rollback**:
   ```bash
   sudo systemctl stop pqcrypta-proxy
   sudo systemctl start nginx
   ```

2. **Gradual rollback**:
   - Reduce traffic percentage to PQCrypta Proxy
   - Investigate issues
   - Re-attempt migration after fixes

3. **Post-rollback analysis**:
   - Collect logs and metrics
   - Identify root cause
   - Create action items

## Security Hardening (v1.3.0)

The following security hardening measures were implemented in the v1.3.0 release:

### Panic Prevention

All `unwrap()` calls on potentially-None values have been replaced with safe patterns:

```rust
// Before (could panic)
let rps = NonZeroU32::new(config.requests_per_second).unwrap();

// After (safe)
let rps = NonZeroU32::new(config.requests_per_second.max(1)).unwrap_or(NonZeroU32::MIN);
```

### Memory Exhaustion Prevention

DashMap collections are now bounded to prevent DoS attacks:

```rust
// Constants in security.rs
const MAX_TRACKED_IPS: usize = 100_000;
const MAX_JA3_FINGERPRINTS: usize = 50_000;

// Eviction logic in cleanup() function
if blocked_count > MAX_TRACKED_IPS {
    // Evict oldest temporary blocks
}
```

### ReDoS Prevention

Regex patterns in route configuration are validated during config load:

```rust
// Length limit
if regex_str.len() > 1024 {
    return Err("path_regex exceeding 1024 characters");
}

// Compiled size limit
RegexBuilder::new(regex_str)
    .size_limit(1024 * 1024) // 1MB limit
    .build()?;
```

### Command Injection Prevention

Domain names in ACME module are validated per RFC 1035:

```rust
fn validate_domain(domain: &str) -> Result<()> {
    // Length validation (1-253 chars total, 1-63 per label)
    // Character validation (alphanumeric + hyphen only)
    // No leading/trailing hyphens per label
}
```

### Path Handling

All path-to-string conversions use safe error handling:

```rust
// Before (could panic on non-UTF8 paths)
let path_str = path.to_str().unwrap();

// After (safe)
let path_str = path.to_str()
    .ok_or_else(|| "Path contains invalid UTF-8")?;
```

## Compliance Considerations

### PCI-DSS

- TLS 1.3 only (compliant with PCI-DSS 4.0)
- Strong key exchange (PQC hybrid recommended)
- Access logging enabled
- Admin API access restricted

### HIPAA

- Encryption in transit (TLS 1.3 + PQC)
- Audit logging
- Access controls
- Secure configuration management

### SOC 2

- Change management (configuration versioning)
- Monitoring and alerting
- Incident response procedures
- Access controls

## Performance Tuning

### Kernel Parameters (Linux)

```bash
# /etc/sysctl.d/99-pqcrypta.conf
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.udp_mem = 65536 131072 262144
net.core.netdev_max_backlog = 65536
```

### Build Optimizations

```bash
# Native CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Link-time optimization
RUSTFLAGS="-C lto=thin" cargo build --release
```

### Connection Limits

```toml
[server]
max_connections = 10000
max_streams_per_connection = 1000
worker_threads = 0  # Auto-detect based on CPU cores
```
