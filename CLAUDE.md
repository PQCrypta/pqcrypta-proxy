# CLAUDE.md - PQCrypta Proxy

This file provides guidance to Claude Code when working with the PQCrypta Proxy codebase.

## Project Overview

PQCrypta Proxy is a high-performance reverse proxy with QUIC/HTTP/3, WebTransport, and Post-Quantum Cryptography TLS support.

**Version**: v1.1.0 (2026-01-23)
**Status**: All features complete and integrated
**Tests**: 38 passing

## All Features Fully Integrated

| Feature | Status | Module | Integration |
|---------|--------|--------|-------------|
| **Load Balancing** | ✅ COMPLETE | `load_balancer.rs` | 6 algorithms, session affinity, health-aware |
| Circuit Breaker | ✅ COMPLETE | `security.rs` | Integrated in `http_listener.rs` proxy_handler |
| Rate Limiting | ✅ COMPLETE | `security.rs` | Integrated via security_middleware |
| DoS Protection | ✅ COMPLETE | `security.rs` | Integrated via security_middleware |
| IP Blocking | ✅ COMPLETE | `security.rs` | Integrated with auto-expiration |
| GeoIP Blocking | ✅ COMPLETE | `security.rs` | MaxMind DB loaded at startup |
| Compression | ✅ COMPLETE | `compression.rs` | Integrated via compression_middleware |
| Request Size Limits | ✅ COMPLETE | `security.rs` | Integrated via security_middleware |
| Early Hints (103) | ✅ COMPLETE | `http3_features.rs` | Link headers added to responses |
| Priority Hints | ✅ COMPLETE | `http3_features.rs` | RFC 9218 headers added |
| Request Coalescing | ✅ COMPLETE | `http3_features.rs` | Deduplicates in-flight requests |
| JA3/JA4 Fingerprinting | ✅ COMPLETE | `fingerprint.rs` | Full extraction and classification |
| TLS Acceptor | ✅ COMPLETE | `tls_acceptor.rs` | ClientHello capture infrastructure |
| Background Cleanup | ✅ COMPLETE | `security.rs` | Auto-spawned cleanup task |
| PQC TLS | ✅ COMPLETE | `http_listener.rs` | X25519MLKEM768 via rustls-post-quantum |

## Development Commands

```bash
# Build release binary
cargo build --release

# Run tests (38 tests)
cargo test

# Run with config
./target/release/pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml

# Validate config only
./target/release/pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --validate
```

## Deployment

```bash
# Stop service first (to avoid "Text file busy" error)
sudo systemctl stop pqcrypta-proxy

# Copy binary
sudo cp target/release/pqcrypta-proxy /usr/local/bin/

# Start service
sudo systemctl start pqcrypta-proxy

# Check status
sudo systemctl status pqcrypta-proxy

# View logs
sudo journalctl -u pqcrypta-proxy -f
```

## Project Structure

```
/var/www/html/pqcrypta-proxy/
├── Cargo.toml              # Workspace configuration
├── CLAUDE.md               # This file
├── README.md               # Project documentation
├── CONTRIBUTING.md         # Contribution guidelines
├── config/
│   └── proxy.toml          # Main configuration
├── data/
│   └── geoip/
│       ├── GeoLite2-City.mmdb
│       └── GeoLite2-Country.mmdb
├── docs/
│   └── SECURITY.md         # Security checklist
├── src/
│   ├── main.rs             # Entry point
│   ├── lib.rs              # Library exports
│   ├── config.rs           # Configuration parsing
│   ├── load_balancer.rs    # Load balancing algorithms, pools, session affinity (NEW)
│   ├── proxy.rs            # Backend pool & request routing
│   ├── http_listener.rs    # HTTP/1.1 + HTTP/2 listener with PQC TLS
│   ├── quic_listener.rs    # QUIC/HTTP/3 listener
│   ├── handlers.rs         # Request handlers
│   ├── security.rs         # Rate limiting, DoS, GeoIP, circuit breaker
│   ├── fingerprint.rs      # JA3/JA4 TLS fingerprint extraction
│   ├── tls_acceptor.rs     # Custom TLS acceptor with fingerprint capture
│   ├── compression.rs      # Brotli/Zstd/Gzip compression
│   ├── http3_features.rs   # Early Hints, Priority, Coalescing
│   ├── admin.rs            # Admin API endpoints
│   ├── tls.rs              # TLS configuration
│   └── pqc_tls.rs          # Post-Quantum TLS provider
├── vendor/
│   └── wtransport/         # Vendored WebTransport library
└── target/
    └── release/
        └── pqcrypta-proxy  # Production binary
```

## Middleware Stack Order

The middleware stack processes requests in this order:

```
Request → Security → HTTP/3 Features → Compression → Alt-Svc → Headers → Handler
                                                                           ↓
Response ← Security ← HTTP/3 Features ← Compression ← Alt-Svc ← Headers ← Handler
```

### Security Middleware (`security.rs`)
1. Check if IP is blocked
2. Apply rate limiting (per-IP token bucket)
3. Check GeoIP restrictions
4. Validate request size
5. Check circuit breaker status

### HTTP/3 Features Middleware (`http3_features.rs`)
1. Add Priority headers (RFC 9218)
2. Check request coalescing
3. Add Early Hints Link headers

### Compression Middleware (`compression.rs`)
1. Check Accept-Encoding
2. Apply Brotli/Zstd/Gzip/Deflate compression
3. Skip pre-compressed content

## Feature Details

### 1. Circuit Breaker (`security.rs` + `http_listener.rs`)

**Integration Points:**
- `security.rs:circuit_allows()` - Check if backend is healthy
- `security.rs:record_backend_result()` - Record success/failure
- `http_listener.rs:proxy_handler()` - Check before forwarding, record after response

**Behavior:**
- Opens after 5 consecutive failures
- Closes after 2 consecutive successes
- Returns 503 when open

### 2. Rate Limiting (`security.rs`)

- Per-IP token bucket algorithm via `governor` crate
- Configurable requests/second and burst size
- Automatic IP blocking after threshold
- Retry-After headers on rate limit responses

### 3. JA3/JA4 Fingerprinting (`fingerprint.rs`)

**New module with:**
- Full JA3 extraction from TLS ClientHello
- JA4 fingerprint calculation (newer format)
- Known fingerprint database:
  - Browsers: Chrome, Firefox, Safari, Edge
  - Legitimate bots: Googlebot, Bingbot, Cloudflare-Bot
  - Malicious: SQLMap, Exploit Kits
  - Scanners: Nmap, Nikto, Burp Suite
  - API clients: curl, wget, Python-requests
- Classification: Browser, LegitimateBot, Suspicious, Malicious, Scanner, ApiClient
- Auto-blocking of malicious fingerprints

### 4. TLS Acceptor (`tls_acceptor.rs`)

**New module with:**
- `FingerprintingTlsAcceptor` - Custom TLS acceptor
- `FingerprintedTlsStream` - Stream wrapper with fingerprint metadata
- `FingerprintedConnection` - Connection info with JA3/JA4 data
- Peeks at ClientHello before TLS handshake

### 5. GeoIP Blocking (`security.rs`)

- MaxMind GeoLite2 database integration
- Country-level access control
- Database path: `/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb`

### 6. Compression (`compression.rs`)

- **Brotli** (quality 4) - Best compression
- **Zstandard** (level 3) - Fast with good ratios
- **Gzip** (level 6) - Wide compatibility
- **Deflate** - Legacy support
- Content negotiation via Accept-Encoding
- Skips pre-compressed content

### 7. Early Hints (`http3_features.rs`)

- `LinkHint::Preload` - Preload CSS, JS, fonts
- `LinkHint::Preconnect` - Preconnect to origins
- `LinkHint::DnsPrefetch` - DNS prefetch
- `LinkHint::ModulePreload` - ES Module preload
- `LinkHint::Prerender` - Speculative page prerender

### 8. Priority Hints (`http3_features.rs`)

RFC 9218 Extensible Priorities:
- HTML: `u=0` (highest)
- CSS: `u=1`
- JS: `u=2`
- Fonts: `u=3`
- JSON API: `u=2`
- Images: `u=5, incremental`

### 9. Request Coalescing (`http3_features.rs`)

- Deduplicates identical GET/HEAD requests
- Broadcast channel for response sharing
- Configurable max wait time (100ms default)
- `x-coalesced: true` header on coalesced responses

### 10. Background Cleanup (`security.rs`)

- Spawned automatically when SecurityState is created
- Runs every 60 seconds
- Cleans up:
  - Expired blocked IPs
  - Old rate limiter entries
  - Stale circuit breaker states
  - Expired fingerprint cache entries

## Configuration

Main config file: `/etc/pqcrypta/proxy-config.toml`

```toml
[server]
bind_address = "0.0.0.0"
udp_port = 443
additional_ports = [4433, 4434]

[tls]
cert_path = "/etc/letsencrypt/live/pqcrypta.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/pqcrypta.com/privkey.pem"
min_version = "1.3"

[pqc]
enabled = true
provider = "rustls-pqc"
preferred_kem = "x25519_mlkem768"
hybrid_mode = true

[security]
dos_protection = true
geoip_db_path = "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb"
blocked_countries = []

[security.rate_limit]
requests_per_second = 100
burst_size = 200
auto_block_threshold = 1000

[security.circuit_breaker]
failure_threshold = 5
success_threshold = 2
timeout_secs = 30

[compression]
enabled = true
algorithms = ["br", "zstd", "gzip", "deflate"]

[http3]
early_hints_enabled = true
priority_hints_enabled = true
coalescing_enabled = true

[backends.api]
name = "api"
type = "http1"
address = "127.0.0.1:3003"
tls_mode = "terminate"

[backends.apache]
name = "apache"
type = "http1"
address = "127.0.0.1:8080"
tls_mode = "terminate"

[[routes]]
name = "api-route"
host = "api.pqcrypta.com"
path_prefix = "/"
backend = "api"

[[routes]]
name = "main-site"
host = "pqcrypta.com"
path_prefix = "/"
backend = "apache"
```

## Code Standards

- **Language**: Rust (stable channel)
- **Async Runtime**: Tokio
- **HTTP Framework**: Axum + Hyper
- **TLS**: Rustls with rustls-post-quantum
- **QUIC**: Quinn (via wtransport)
- **Formatting**: `cargo fmt`
- **Linting**: `cargo clippy`

## CSP Policy

Same as main PQCrypta project:
- No inline styles
- No inline scripts
- No inline event handlers
- External CSS/JS files only
- Use nonces when absolutely necessary

## Security Considerations

- Rate limiting prevents abuse
- GeoIP blocking for geographic restrictions
- JA3/JA4 fingerprinting detects suspicious clients
- Circuit breaker protects backends from cascading failures
- All TLS 1.3 (enforced by QUIC)
- PQC hybrid key exchange (X25519MLKEM768)
- Background cleanup prevents memory leaks

## Systemd Service

Location: `/etc/systemd/system/pqcrypta-proxy.service`

```ini
[Unit]
Description=PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS
After=network.target
Documentation=https://github.com/PQCrypta/pqcrypta-proxy

[Service]
Type=simple
ExecStart=/usr/local/bin/pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml
Restart=always
RestartSec=5
User=root
WorkingDirectory=/var/www/html/pqcrypta-proxy
Environment=RUST_LOG=info

[Install]
WantedBy=multi-target.target
```

## Troubleshooting

### Binary won't update ("Text file busy")
```bash
sudo systemctl stop pqcrypta-proxy
sudo cp target/release/pqcrypta-proxy /usr/local/bin/
sudo systemctl start pqcrypta-proxy
```

### Check logs
```bash
sudo journalctl -u pqcrypta-proxy -f
```

### Verify service is running
```bash
sudo systemctl status pqcrypta-proxy
```

### Test endpoints
```bash
# Health check
curl -s https://api.pqcrypta.com/health | head -c 200

# Check response headers
curl -sI https://api.pqcrypta.com/health | grep -E "^(server|alt-svc|priority):"

# Test circuit breaker (multiple requests)
for i in {1..5}; do curl -s -o /dev/null -w "%{http_code}\n" https://api.pqcrypta.com/health; done
```

### 11. Load Balancing (`load_balancer.rs`)

**New module with:**
- **6 Load Balancing Algorithms:**
  - `least_connections` (default) - Routes to server with fewest active connections
  - `round_robin` - Simple rotation through servers
  - `weighted_round_robin` - nginx-style smooth weighted distribution
  - `random` - Random server selection
  - `ip_hash` - Consistent hashing by client IP for sticky sessions
  - `least_response_time` - Routes to fastest responding server (EMA tracking)
- **Backend Pools** - Group multiple servers per route for high availability
- **Session Affinity** - Cookie-based, IP hash, or custom header sticky sessions
- **Health-Aware Routing** - Automatically bypasses unhealthy backends
- **Slow Start** - Gradually increases traffic to recovering servers
- **Connection Draining** - Graceful server removal without dropping connections
- **Priority Failover** - Primary servers (priority 1) first, then failover

**Integration Points:**
- `load_balancer.rs:LoadBalancer` - Main load balancer manager
- `load_balancer.rs:BackendPool` - Pool of servers with algorithm
- `load_balancer.rs:BackendServer` - Individual server with health tracking
- `http_listener.rs:proxy_handler()` - Selects backend via load balancer, records response times
- `config.rs:LoadBalancerConfig` - TOML configuration structs

**Configuration:**
```toml
[load_balancer]
enabled = true
default_algorithm = "least_connections"

[backend_pools.api]
algorithm = "least_connections"
health_aware = true
affinity = "cookie"

[[backend_pools.api.servers]]
address = "127.0.0.1:3003"
weight = 100
priority = 1
```

## Recent Changes (2026-01-23)

1. **Load Balancing Module** - New `load_balancer.rs` with 6 algorithms, session affinity, health-aware routing
2. **Circuit Breaker Integration** - Now checks backend health before forwarding, records results after
3. **JA3/JA4 Fingerprinting Module** - New `fingerprint.rs` with full extraction and classification
4. **TLS Acceptor Module** - New `tls_acceptor.rs` for ClientHello capture
5. **Background Cleanup** - Auto-spawned task for expired entry cleanup
6. **FingerprintExtractor in HttpListenerState** - Added to state for request processing
7. **Tests Fixed** - Updated to use `#[tokio::test]` for async tests
8. **All 38 tests passing** (5 new load balancer tests)
