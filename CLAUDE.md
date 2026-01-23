# CLAUDE.md - PQCrypta Proxy

This file provides guidance to Claude Code when working with the PQCrypta Proxy codebase.

## Project Overview

PQCrypta Proxy is a high-performance reverse proxy with QUIC/HTTP/3, WebTransport, and Post-Quantum Cryptography TLS support. It serves as a complete nginx replacement.

## ✅ All Features Implemented

| Feature | Status | Module |
|---------|--------|--------|
| Rate Limiting | ✅ COMPLETE | `security.rs` |
| DoS Protection | ✅ COMPLETE | `security.rs` |
| IP Blocking | ✅ COMPLETE | `security.rs` |
| GeoIP Blocking | ✅ COMPLETE | `security.rs` |
| Compression | ✅ COMPLETE | `compression.rs` |
| Request Size Limits | ✅ COMPLETE | `security.rs` |
| Early Hints (103) | ✅ COMPLETE | `http3_features.rs` |
| Priority Hints | ✅ COMPLETE | `http3_features.rs` |
| Request Coalescing | ✅ COMPLETE | `http3_features.rs` |
| JA3/JA4 Fingerprinting | ✅ COMPLETE | `security.rs` |
| Circuit Breaker | ✅ COMPLETE | `security.rs` |

## Development Commands

```bash
# Build release binary
cargo build --release

# Run tests
cargo test

# Run with config
./target/release/pqcrypta-proxy --config /var/www/html/pqcrypta-proxy/config/proxy.toml

# Validate config only
./target/release/pqcrypta-proxy --config /var/www/html/pqcrypta-proxy/config/proxy.toml --validate
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
│   ├── proxy.rs            # Backend pool & load balancing
│   ├── http_listener.rs    # HTTP/1.1 + HTTP/2 listener
│   ├── quic_listener.rs    # QUIC/HTTP/3 listener
│   ├── handlers.rs         # Request handlers
│   ├── security.rs         # Rate limiting, DoS, GeoIP, JA3/JA4
│   ├── compression.rs      # Brotli/Zstd/Gzip compression
│   └── http3_features.rs   # Early Hints, Priority, Coalescing
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

## Feature Details

### 1. Rate Limiting (`security.rs`)

- Per-IP token bucket algorithm via `governor` crate
- Configurable requests/second and burst size
- Automatic IP blocking after threshold
- Retry-After headers on rate limit responses

### 2. DoS Protection (`security.rs`)

- Connection limits per IP
- Auto-blocking with expiration
- Request size validation (413/431 responses)

### 3. GeoIP Blocking (`security.rs`)

- MaxMind GeoLite2 database integration
- Country-level access control
- Database path: `/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb`

### 4. Compression (`compression.rs`)

- **Brotli** (quality 4) - Best compression
- **Zstandard** (level 3) - Fast with good ratios
- **Gzip** (level 6) - Wide compatibility
- **Deflate** - Legacy support
- Content negotiation via Accept-Encoding
- Skips pre-compressed content

### 5. Early Hints (`http3_features.rs`)

- `LinkHint::Preload` - Preload CSS, JS, fonts
- `LinkHint::Preconnect` - Preconnect to origins
- `LinkHint::DnsPrefetch` - DNS prefetch
- `LinkHint::ModulePreload` - ES Module preload
- `LinkHint::Prerender` - Speculative page prerender

### 6. Priority Hints (`http3_features.rs`)

RFC 9218 Extensible Priorities:
- HTML: `u=0` (highest)
- CSS: `u=1`
- JS: `u=2`
- Fonts: `u=3`
- JSON API: `u=2`
- Images: `u=5, incremental`

### 7. Request Coalescing (`http3_features.rs`)

- Deduplicates identical GET/HEAD requests
- Broadcast channel for response sharing
- Configurable max wait time (100ms default)
- `x-coalesced: true` header on coalesced responses

## Configuration

Main config file: `/var/www/html/pqcrypta-proxy/config/proxy.toml`

```toml
[proxy]
bind_addr = "0.0.0.0"
http_port = 80
https_port = 443
quic_port = 443

[backends]
[[backends.routes]]
domain = "api.pqcrypta.com"
upstream = "127.0.0.1:3003"

[[backends.routes]]
domain = "pqcrypta.com"
upstream = "127.0.0.1:8080"

[security]
dos_protection = true
geoip_db_path = "/var/www/html/pqcrypta-proxy/data/geoip/GeoLite2-City.mmdb"

[security.rate_limit]
requests_per_second = 100
burst_size = 200
auto_block_threshold = 1000

[compression]
enabled = true
algorithms = ["br", "zstd", "gzip", "deflate"]

[http3]
early_hints_enabled = true
priority_hints_enabled = true
coalescing_enabled = true
```

## Code Standards

- **Language**: Rust (stable channel)
- **Async Runtime**: Tokio
- **HTTP Framework**: Axum + Hyper
- **TLS**: Rustls
- **QUIC**: Quinn (via wtransport)
- **Formatting**: `cargo fmt`
- **Linting**: `cargo clippy`

## CSP Policy

Same as main PQCrypta project:
- ❌ NO inline styles
- ❌ NO inline scripts
- ❌ NO inline event handlers
- ✅ External CSS/JS files only
- ✅ Use nonces when absolutely necessary

## Security Considerations

- Rate limiting prevents abuse
- GeoIP blocking for geographic restrictions
- JA3/JA4 fingerprinting detects suspicious clients
- Circuit breaker protects backends
- All TLS 1.3 (enforced by QUIC)

## Systemd Service

Location: `/etc/systemd/system/pqcrypta-proxy.service`

```ini
[Unit]
Description=PQCrypta Proxy - QUIC/HTTP3/WebTransport Proxy with PQC TLS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pqcrypta-proxy --config /var/www/html/pqcrypta-proxy/config/proxy.toml
Restart=always
RestartSec=5
User=root
WorkingDirectory=/var/www/html/pqcrypta-proxy
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
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

## Version

**v1.0.0** - All features complete (2026-01-22)
