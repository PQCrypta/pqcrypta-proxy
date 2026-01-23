# PQCrypta Proxy

**Production-ready HTTP/3/QUIC/WebTransport reverse proxy with hybrid Post-Quantum Cryptography (PQC) TLS support.**

[![Build Status](https://github.com/PQCrypta/pqcrypta-proxy/workflows/CI/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-33%20passing-brightgreen.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions)

## Highlights

- **Full-Featured Proxy**: Domain-based routing, security headers, CORS, redirects
- **Three TLS Modes**: Terminate, Re-encrypt, and Passthrough (SNI-based)
- **Modern Protocols**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebTransport
- **Post-Quantum Ready**: Hybrid PQC key exchange (X25519MLKEM768) via rustls-post-quantum
- **Zero Downtime**: Hot reload configuration and TLS certificates
- **Advanced Security**: JA3/JA4 fingerprinting, circuit breaker, GeoIP blocking

## All Features Implemented

| Feature | Status | Description |
|---------|--------|-------------|
| Circuit Breaker | ✅ | Backend health monitoring with auto-recovery |
| Rate Limiting | ✅ | Per-IP + global limits with auto-blocking |
| DoS Protection | ✅ | Connection limits, request validation |
| GeoIP Blocking | ✅ | Country-based blocking (MaxMind DB) |
| JA3/JA4 Fingerprinting | ✅ | TLS client fingerprint detection and classification |
| Priority Hints | ✅ | RFC 9218 response prioritization |
| Request Coalescing | ✅ | Deduplicates identical in-flight requests |
| Early Hints (103) | ✅ | Link headers for preload/preconnect |
| Compression | ✅ | Brotli/gzip/deflate/zstd |
| Security Headers | ✅ | HSTS, CSP, CORS, Alt-Svc |
| PQC TLS | ✅ | X25519MLKEM768 hybrid (NIST Level 3) |
| Background Cleanup | ✅ | Auto-cleanup of expired entries |

## Features

### Reverse Proxy
- **Domain-based Routing**: Route `api.example.com` → port 3003, `example.com` → port 8080
- **TLS Termination**: Decrypt at proxy, plain HTTP to backend (default)
- **TLS Re-encryption**: Decrypt at proxy, re-encrypt HTTPS to backend with mTLS support
- **TLS Passthrough**: SNI-based routing without decryption
- **HTTP→HTTPS Redirect**: Automatic port 80 to 443 redirect server

### Security
- **JA3/JA4 TLS Fingerprinting**: Detects browsers, bots, scanners, malware based on TLS ClientHello
- **Circuit Breaker**: Protects backends from cascading failures with automatic recovery
- **Rate Limiting**: Per-IP token bucket with configurable burst and auto-blocking
- **DoS Protection**: Connection limits, request size validation, auto-blocking
- **GeoIP Blocking**: Block by country/region using MaxMind GeoLite2 database
- **Security Headers**: HSTS, X-Frame-Options, CSP, COEP, COOP, CORP, and more
- **CORS Handling**: Full CORS support with preflight OPTIONS handling
- **Server Branding**: Hide backend identity (Apache/nginx → "PQCProxy v0.1.0")

### HTTP/3 Advanced Features
- **Early Hints (103)**: Preload CSS/JS resources via Link headers
- **Priority Hints**: RFC 9218 Extensible Priorities for resource scheduling
- **Request Coalescing**: Deduplicate identical GET/HEAD requests in flight
- **Alt-Svc Advertisement**: Automatic HTTP/3 upgrade headers

### Protocols
- **QUIC/HTTP/3**: Full HTTP/3 support with QUIC transport
- **WebTransport**: Native WebTransport session handling for bidirectional streaming
- **X-Forwarded Headers**: X-Real-IP, X-Forwarded-For, X-Forwarded-Proto

### Operations
- **Hot Reload**: Configuration and TLS certificate reload without restart
- **Admin API**: Health checks, Prometheus metrics, config reload, graceful shutdown
- **Cross-Platform**: Linux, macOS, and Windows support

## Quick Start

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- TLS certificates (Let's Encrypt recommended)

### Build

```bash
# Clone repository
git clone https://github.com/PQCrypta/pqcrypta-proxy.git
cd pqcrypta-proxy

# Build release binary
cargo build --release

# Validate configuration
./target/release/pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --validate

# Run
./target/release/pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml
```

### Docker

```bash
# Build Docker image
docker build -t pqcrypta-proxy .

# Run container
docker run -p 80:80 -p 443:443/tcp -p 443:443/udp \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -v ./config:/etc/pqcrypta:ro \
  pqcrypta-proxy
```

## Configuration

### Minimal Configuration

```toml
# /etc/pqcrypta/proxy-config.toml

[server]
bind_address = "0.0.0.0"
udp_port = 443
additional_ports = [4433, 4434]

[tls]
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"

[http_redirect]
enabled = true
port = 80

# Backend: Apache on port 8080
[backends.apache]
name = "apache"
type = "http1"
address = "127.0.0.1:8080"
tls_mode = "terminate"

# Backend: Rust API on port 3003
[backends.api]
name = "api"
type = "http1"
address = "127.0.0.1:3003"
tls_mode = "terminate"

# Route: api.example.com → API backend
[[routes]]
name = "api-route"
host = "api.example.com"
path_prefix = "/"
backend = "api"
forward_client_identity = true
priority = 100

# Route: example.com → Apache backend
[[routes]]
name = "main-site"
host = "example.com"
path_prefix = "/"
backend = "apache"
forward_client_identity = true
priority = 100
```

### Security Configuration

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

[security.circuit_breaker]
failure_threshold = 5
success_threshold = 2
timeout_secs = 30
```

### TLS Modes

#### 1. TLS Terminate (Default)
Decrypt TLS at proxy, plain HTTP to backend.

```toml
[backends.apache]
name = "apache"
type = "http1"
address = "127.0.0.1:8080"
tls_mode = "terminate"  # Default - can be omitted
```

#### 2. TLS Re-encrypt
Decrypt at proxy, re-encrypt to backend via HTTPS.

```toml
[backends.internal-api]
name = "internal-api"
type = "http1"
address = "internal.example.com:443"
tls_mode = "reencrypt"
tls_cert = "/path/to/ca.pem"           # Optional: custom CA
tls_client_cert = "/path/to/client.pem" # Optional: mTLS client cert
tls_client_key = "/path/to/client.key"  # Optional: mTLS client key
tls_skip_verify = false                 # DANGEROUS if true
tls_sni = "internal.example.com"        # Optional: custom SNI
```

#### 3. TLS Passthrough (SNI Routing)
Route based on SNI without decryption.

```toml
[[passthrough_routes]]
name = "external-service"
sni = "external.example.com"    # Supports wildcards: *.example.com
backend = "10.0.0.5:443"
proxy_protocol = false          # Optional: PROXY protocol v2
timeout_ms = 30000
```

### Security Headers

```toml
[headers]
hsts = "max-age=63072000; includeSubDomains; preload"
x_frame_options = "DENY"
x_content_type_options = "nosniff"
referrer_policy = "strict-origin-when-cross-origin"
permissions_policy = "camera=(), microphone=(), geolocation=()"
cross_origin_opener_policy = "same-origin"
cross_origin_embedder_policy = "require-corp"
cross_origin_resource_policy = "same-origin"

# Custom branding headers
x_quantum_resistant = "ML-KEM-1024, ML-DSA-87, X25519MLKEM768"
x_security_level = "Post-Quantum Ready"
```

### CORS Configuration

```toml
[[routes]]
name = "api-cors"
host = "api.example.com"
path_prefix = "/"
backend = "api"

[routes.cors]
allow_origin = "https://example.com"
allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allow_headers = ["Content-Type", "Authorization", "X-API-Key"]
allow_credentials = true
max_age = 86400
```

See [config/example-config.toml](config/example-config.toml) for full documentation.

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

Environment variables: `PQCRYPTA_CONFIG`, `PQCRYPTA_UDP_PORT`, `PQCRYPTA_ADMIN_PORT`, `PQCRYPTA_LOG_LEVEL`, `PQCRYPTA_JSON_LOGS`

## Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                         PQCProxy v0.1.0                   │
                    │                                                          │
  Client ──────────►│  Port 80  ─► HTTP Redirect Server ─► HTTPS (301/308)    │
  (Browser/App)     │                                                          │
                    │  Port 443 ─► TLS Termination ─► Reverse Proxy            │
                    │     │           │                                        │
                    │     │           ├─► HTTP/1.1, HTTP/2 (TCP)              │
                    │     │           ├─► HTTP/3 (QUIC/UDP)                   │
                    │     │           └─► WebTransport Sessions               │
                    │     │                                                    │
                    │     └─► TLS Passthrough ─► SNI Routing (no decrypt)     │
                    │                                                          │
                    │  ┌─────────────────────────────────────────────────────┐ │
                    │  │              Security Middleware Stack              │ │
                    │  │  JA3/JA4 → Rate Limit → GeoIP → Circuit Breaker   │ │
                    │  └─────────────────────────────────────────────────────┘ │
                    │                                                          │
                    │  ┌─────────────────────────────────────────────────────┐ │
                    │  │              HTTP/3 Features Middleware             │ │
                    │  │  Early Hints → Priority → Coalescing → Compression │ │
                    │  └─────────────────────────────────────────────────────┘ │
                    │                                                          │
                    │  ┌─────────────────────────────────────────────────────┐ │
                    │  │                    Route Engine                      │ │
                    │  │  - Domain matching (api.example.com vs example.com) │ │
                    │  │  - Path matching (prefix, exact, regex)             │ │
                    │  │  - CORS handling                                     │ │
                    │  │  - Redirect rules                                    │ │
                    │  └─────────────────────────────────────────────────────┘ │
                    │                                                          │
                    │  ┌─────────────────────────────────────────────────────┐ │
                    │  │                   Backend Pool                       │ │
                    │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │ │
                    │  │  │ TLS         │  │ TLS         │  │ TLS         │  │ │
                    │  │  │ Terminate   │  │ Re-encrypt  │  │ Passthrough │  │ │
                    │  │  │ (HTTP)      │  │ (HTTPS)     │  │ (SNI)       │  │ │
                    │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │ │
                    │  └─────────┼────────────────┼────────────────┼─────────┘ │
                    │            │                │                │           │
                    │            ▼                ▼                ▼           │
                    │      Backend A        Backend B        Backend C         │
                    │   (Apache :8080)   (API :3003)    (External :443)       │
                    │                                                          │
                    │  Admin API (HTTP 8081)                                   │
                    │    /health, /metrics, /reload, /shutdown                 │
                    └──────────────────────────────────────────────────────────┘
```

## Module Structure

```
src/
├── main.rs              # Entry point
├── lib.rs               # Library exports
├── config.rs            # Configuration parsing
├── proxy.rs             # Backend pool & load balancing
├── http_listener.rs     # HTTP/1.1 + HTTP/2 listener with PQC TLS
├── quic_listener.rs     # QUIC/HTTP/3 listener
├── security.rs          # Rate limiting, DoS, GeoIP, circuit breaker
├── fingerprint.rs       # JA3/JA4 TLS fingerprint extraction
├── tls_acceptor.rs      # Custom TLS acceptor with fingerprint capture
├── compression.rs       # Brotli/Zstd/Gzip compression
├── http3_features.rs    # Early Hints, Priority, Request Coalescing
├── admin.rs             # Admin API endpoints
├── tls.rs               # TLS configuration
└── pqc_tls.rs           # Post-Quantum TLS provider
```

## Post-Quantum Cryptography

PQCrypta Proxy supports hybrid PQC key exchange using rustls-post-quantum (X25519MLKEM768).

### Supported KEMs

| Algorithm | Security Level | Description |
|-----------|---------------|-------------|
| `X25519MLKEM768` | NIST Level 3 | Hybrid X25519 + ML-KEM-768 (default) |
| `kyber768` | NIST Level 3 | Kyber-768 standalone |
| `kyber1024` | NIST Level 5 | Kyber-1024 standalone |
| `mlkem768` | NIST Level 3 | ML-KEM-768 (FIPS 203) |
| `mlkem1024` | NIST Level 5 | ML-KEM-1024 (FIPS 203) |

### Configuration

```toml
[pqc]
enabled = true
provider = "rustls-pqc"
preferred_kem = "x25519_mlkem768"
hybrid_mode = true
fallback_to_classical = true
```

## Admin API

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with backend status |
| `/metrics` | GET | Prometheus metrics |
| `/reload` | POST | Reload configuration |
| `/shutdown` | POST | Graceful shutdown |
| `/config` | GET | Read-only config view |
| `/backends` | GET | Backend health status |
| `/tls` | GET | TLS certificate info |

### Example

```bash
# Health check
curl http://127.0.0.1:8081/health

# Prometheus metrics
curl http://127.0.0.1:8081/metrics

# Reload configuration
curl -X POST http://127.0.0.1:8081/reload

# Reload TLS certificates only
curl -X POST http://127.0.0.1:8081/reload -d '{"tls_only":true}'
```

## Deployment

### Systemd (Linux)

```bash
# Copy service file
sudo cp packaging/systemd/pqcrypta-proxy.service /etc/systemd/system/

# Enable and start
sudo systemctl enable pqcrypta-proxy
sudo systemctl start pqcrypta-proxy

# View logs
journalctl -u pqcrypta-proxy -f
```

### macOS (launchd)

```bash
# Copy plist
cp packaging/macos/com.pqcrypta.proxy.plist ~/Library/LaunchAgents/

# Load service
launchctl load ~/Library/LaunchAgents/com.pqcrypta.proxy.plist
```

### Windows Service

```powershell
# Using NSSM (Non-Sucking Service Manager)
nssm install pqcrypta-proxy "C:\Program Files\pqcrypta-proxy\pqcrypta-proxy.exe"
nssm set pqcrypta-proxy AppParameters "--config C:\ProgramData\pqcrypta\config.toml"
nssm start pqcrypta-proxy
```

## Performance Tuning

### Kernel Parameters (Linux)

```bash
# /etc/sysctl.d/99-pqcrypta.conf
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.udp_mem = 65536 131072 262144
```

### Build Optimizations

```bash
# Build with native CPU optimizations
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

### Benchmarking

```bash
# Run benchmarks
cargo bench

# Test QUIC throughput
cargo run --release --bin quic-bench -- --target localhost:443
```

## Security

### All Security Features Complete

- [x] TLS 1.3 only (enforced by QUIC)
- [x] Full security headers (HSTS, COEP, COOP, CORP, etc.)
- [x] Server identity hidden (custom branding)
- [x] X-Forwarded-For header support
- [x] Rate limiting (per-IP token bucket with burst handling)
- [x] DoS protection (connection limits, auto-blocking)
- [x] Request size limits (413/431 responses)
- [x] GeoIP blocking (MaxMind DB integration)
- [x] JA3/JA4 TLS fingerprinting (browser/bot/malware detection)
- [x] Circuit breaker (backend protection)
- [x] IP blocking (manual + auto with expiration)
- [x] Compression (Brotli, Zstd, Gzip, Deflate)
- [x] Early Hints (103) support
- [x] Priority Hints (RFC 9218)
- [x] Request Coalescing (dedupe identical requests)
- [x] PQC hybrid key exchange (X25519MLKEM768)
- [x] Background cleanup (auto-expire blocked IPs)

### mTLS Configuration

```toml
[tls]
ca_cert_path = "/etc/pqcrypta/client-ca.pem"
require_client_cert = true

[admin]
require_mtls = true
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
