# PQCrypta Proxy

**Production-ready QUIC/HTTP/3/WebTransport proxy with hybrid Post-Quantum Cryptography (PQC) TLS support.**

[![Build Status](https://github.com/PQCrypta/pqcrypta-proxy/workflows/CI/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Features

- **QUIC/HTTP/3 Protocol**: Full HTTP/3 support with QUIC transport
- **WebTransport**: Native WebTransport session handling for bidirectional streaming
- **Hybrid PQC TLS**: Post-quantum key exchange via OpenSSL 3.5 + OQS provider (Kyber/ML-KEM)
- **Multi-Backend Routing**: Route to HTTP/1.1, HTTP/2, HTTP/3, Unix sockets, or raw TCP
- **Hot Reload**: Configuration and TLS certificate reload without restart
- **Admin API**: Health checks, Prometheus metrics, config reload, graceful shutdown
- **Cross-Platform**: Linux, macOS, and Windows support

## Quick Start

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- OpenSSL 3.5+ with OQS provider (optional, for PQC support)
- TLS certificates (Let's Encrypt recommended)

### Build

```bash
# Clone repository
git clone https://github.com/PQCrypta/pqcrypta-proxy.git
cd pqcrypta-proxy

# Build release binary
cargo build --release

# Run with default config
./target/release/pqcrypta-proxy --config config/example-config.toml
```

### Docker

```bash
# Build Docker image
docker build -t pqcrypta-proxy .

# Run container
docker run -p 4433:4433/udp -p 8081:8081 \
  -v /etc/letsencrypt:/etc/letsencrypt:ro \
  -v ./config:/etc/pqcrypta:ro \
  pqcrypta-proxy
```

## Configuration

All configuration is externalized via TOML file. No hardcoded values.

```toml
# /etc/pqcrypta/config.toml

[server]
bind_address = "0.0.0.0"
udp_port = 4433

[tls]
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"

[pqc]
enabled = true
provider = "openssl3.5"
preferred_kem = "x25519_kyber768"

[backends.php]
name = "php"
type = "unix"
address = "unix:/run/php-fpm.sock"

[[routes]]
name = "webtransport-to-php"
webtransport = true
backend = "php"
stream_to_method = "POST"
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
                    ┌─────────────────────────────────────────┐
                    │           PQCrypta Proxy                │
                    │                                         │
  Client ──────────►│  QUIC Listener (UDP 4433)              │
  (Browser/App)     │    │                                    │
                    │    ├─► HTTP/3 Handler                   │
                    │    │     └─► WebTransport Sessions      │
                    │    │                                    │
                    │    └─► Raw QUIC Streams                 │
                    │                                         │
                    │  ┌────────────────────────────────────┐ │
                    │  │         Route Engine               │ │
                    │  │  - Host matching                   │ │
                    │  │  - Path matching                   │ │
                    │  │  - WebTransport routing            │ │
                    │  └────────────────────────────────────┘ │
                    │                                         │
                    │  ┌────────────────────────────────────┐ │
                    │  │         Backend Pool               │ │
                    │  │  - HTTP/1.1                        │──────►  Backend A
                    │  │  - HTTP/2                          │──────►  Backend B
                    │  │  - HTTP/3 (QUIC)                   │──────►  Backend C
                    │  │  - Unix Socket (PHP-FPM)           │──────►  PHP-FPM
                    │  │  - Raw TCP                         │──────►  TCP Service
                    │  └────────────────────────────────────┘ │
                    │                                         │
                    │  Admin API (HTTP 8081)                  │
                    │    /health, /metrics, /reload           │
                    └─────────────────────────────────────────┘
```

## Post-Quantum Cryptography

PQCrypta Proxy supports hybrid PQC key exchange using OpenSSL 3.5+ with the OQS (Open Quantum Safe) provider.

### Supported KEMs

| Algorithm | Security Level | Description |
|-----------|---------------|-------------|
| `kyber768` | NIST Level 3 | Kyber-768 standalone |
| `kyber1024` | NIST Level 5 | Kyber-1024 standalone |
| `mlkem768` | NIST Level 3 | ML-KEM-768 (FIPS 203) |
| `mlkem1024` | NIST Level 5 | ML-KEM-1024 (FIPS 203) |
| `x25519_kyber768` | Hybrid | X25519 + Kyber-768 hybrid |

### Setup OpenSSL 3.5 with OQS

```bash
# Install OpenSSL 3.5
wget https://www.openssl.org/source/openssl-3.5.0.tar.gz
tar xzf openssl-3.5.0.tar.gz
cd openssl-3.5.0
./Configure --prefix=/usr/local/openssl-3.5
make -j$(nproc)
sudo make install

# Install OQS provider
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -DCMAKE_PREFIX_PATH=/usr/local/openssl-3.5 -B build
cmake --build build
sudo cmake --install build

# Verify PQC support
/usr/local/openssl-3.5/bin/openssl list -kem-algorithms | grep -i kyber
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
cargo run --release --bin quic-bench -- --target localhost:4433
```

## Security

### Checklist

- [ ] Use TLS 1.3 only (configured by default)
- [ ] Enable PQC hybrid key exchange for quantum resistance
- [ ] Restrict admin API to localhost or mTLS
- [ ] Configure rate limiting
- [ ] Enable DoS protection
- [ ] Set appropriate request size limits
- [ ] Use strong TLS certificates (ECDSA P-384 or Ed25519)
- [ ] Disable 0-RTT if replay attacks are a concern
- [ ] Monitor with Prometheus metrics

### mTLS Configuration

```toml
[tls]
ca_cert_path = "/etc/pqcrypta/client-ca.pem"
require_client_cert = true

[admin]
require_mtls = true
```

## Integration with Existing PQ Crypta

To migrate existing PQ Crypta WebTransport code to use this proxy:

1. **Update DNS/Load Balancer**: Point WebTransport traffic to the proxy on port 4433

2. **Configure Backend**: Add your existing API as a backend:
   ```toml
   [backends.pqcrypta-api]
   type = "http1"
   address = "127.0.0.1:3003"
   ```

3. **Add WebTransport Route**:
   ```toml
   [[routes]]
   webtransport = true
   backend = "pqcrypta-api"
   stream_to_method = "POST"
   ```

4. **Forward Client Identity**:
   ```toml
   [[routes]]
   forward_client_identity = true
   client_identity_header = "X-Client-IP"
   ```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
