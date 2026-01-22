# Security Checklist & Operational Guide

This document provides security hardening guidelines, operational best practices, and a migration plan for deploying PQCrypta Proxy in production environments.

## Security Checklist

### TLS Configuration

- [ ] **Use TLS 1.3 only** (enforced by QUIC)
- [ ] **Enable hybrid PQC key exchange** for quantum resistance
- [ ] **Use strong certificates** (ECDSA P-384 or Ed25519 recommended)
- [ ] **Enable OCSP stapling** for certificate validation
- [ ] **Configure automatic certificate renewal** with Let's Encrypt
- [ ] **Disable 0-RTT** if replay attacks are a concern
- [ ] **Set appropriate cipher suites** (TLS 1.3 only has secure options)

```toml
[tls]
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"
min_version = "1.3"
ocsp_stapling = true
cert_reload_interval_secs = 3600
```

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

### Rate Limiting & DoS Protection

- [ ] **Enable request rate limiting**
- [ ] **Enable connection rate limiting**
- [ ] **Set maximum request/header sizes**
- [ ] **Configure connection timeouts**
- [ ] **Enable DoS protection**

```toml
[rate_limiting]
enabled = true
requests_per_second = 100
burst_size = 50
connection_rate_limit = true
connections_per_second = 10

[security]
max_request_size = 10485760      # 10MB
max_header_size = 65536          # 64KB
connection_timeout_secs = 30
dos_protection = true
```

### Network Security

- [ ] **Configure firewall** to allow only required ports
- [ ] **Use separate network segments** for backends
- [ ] **Enable mTLS** for backend connections if required
- [ ] **Block suspicious IP addresses**

```bash
# Linux firewall rules
iptables -A INPUT -p udp --dport 4433 -j ACCEPT   # QUIC
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
   pqcrypta-proxy --config /etc/pqcrypta/config.toml --validate
   ```

2. Start service:
   ```bash
   systemctl start pqcrypta-proxy
   ```

3. Verify health:
   ```bash
   curl http://127.0.0.1:8081/health
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
   pqcrypta-proxy --config /etc/pqcrypta/config.toml --validate
   ```

3. **Check port binding**:
   ```bash
   ss -ulnp | grep 4433   # QUIC UDP port
   ss -tlnp | grep 8081   # Admin TCP port
   ```

4. **Test QUIC connectivity**:
   ```bash
   # Using curl with HTTP/3 support
   curl --http3 https://your-domain:4433/health
   ```

5. **Verify TLS certificate**:
   ```bash
   openssl s_client -connect your-domain:4433 -alpn h3
   ```

### Backup & Recovery

**What to backup:**
- Configuration file (`/etc/pqcrypta/config.toml`)
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

2. **Create equivalent PQCrypta config**:
   ```toml
   # Map nginx upstream to backends
   [backends.api]
   name = "api"
   type = "http1"
   address = "127.0.0.1:8080"

   # Map nginx location to routes
   [[routes]]
   name = "api-route"
   host = "api.example.com"
   path_prefix = "/api"
   backend = "api"
   ```

3. **Test in parallel**:
   - Run PQCrypta Proxy on different port
   - Use curl/wrk to test routes
   - Compare responses with existing proxy

4. **Gradual traffic migration**:
   - Start with internal/staging traffic
   - Monitor metrics and logs
   - Gradually increase traffic percentage

5. **Full cutover**:
   - Update DNS/load balancer
   - Monitor for issues
   - Keep old proxy ready for rollback

### From Node.js WebTransport

1. **Update client code**:
   ```javascript
   // Old: Direct connection to Node.js
   const transport = new WebTransport('https://api.example.com:3003/stream');

   // New: Connect via PQCrypta Proxy
   const transport = new WebTransport('https://api.example.com:4433/stream');
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
   - Allow UDP 4433 (QUIC)
   - Remove external access to Node.js port

### Rollback Procedure

If issues occur after migration:

1. **Immediate rollback**:
   - Update DNS/load balancer to point to old proxy
   - Keep PQCrypta Proxy running for debugging

2. **Gradual rollback**:
   - Reduce traffic percentage to PQCrypta Proxy
   - Investigate issues
   - Re-attempt migration after fixes

3. **Post-rollback analysis**:
   - Collect logs and metrics
   - Identify root cause
   - Create action items

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
