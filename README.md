# PQCrypta Proxy

**Production-ready HTTP/3/QUIC/WebTransport reverse proxy with hybrid Post-Quantum Cryptography (PQC) TLS support.**

[![Build Status](https://github.com/PQCrypta/pqcrypta-proxy/workflows/CI/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-142%20passing-brightgreen.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions)
[![Security](https://img.shields.io/badge/security-hardened-green.svg)](docs/SECURITY.md)

## Highlights

- **Full-Featured Proxy**: Domain-based routing, custom header injection, per-route timeouts, security headers, CORS, redirects
- **Three TLS Modes**: Terminate, Re-encrypt, and Passthrough (SNI-based)
- **Modern Protocols**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebTransport
- **Post-Quantum Ready**: Hybrid PQC key exchange (X25519MLKEM768) via OpenSSL 3.5+ with native ML-KEM; PQC downgrade detection
- **Zero Downtime**: Hot reload configuration and TLS certificates; environment-specific config overlay (`--env`)
- **ACME Automation**: Automatic Let's Encrypt certificate provisioning, renewal, and Certificate Transparency log submission
- **OCSP Stapling**: Automated OCSP response fetching and stapling
- **Prometheus Metrics**: Comprehensive metrics for TLS, connections, requests, backends, and WAF blocks
- **WAF**: OWASP Top 10 pattern-based request inspection (SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization) in detect or block mode
- **Advanced Security**: JA3/JA4 fingerprinting with replay and drift detection, circuit breaker, GeoIP blocking, DB-synced IP blocklists, WebTransport origin validation, 0-RTT replay protection
- **Structured Audit Logging**: Async JSON audit log for admin actions, auth failures, WAF blocks, IP blocks, rate limit hits, PQC downgrades, config reloads
- **Structured Access Logging**: Per-request JSON or text logs with latency, bytes, upstream, and client IP
- **Enterprise Load Balancing**: 6 algorithms, session affinity, health-aware routing, per-backend retry policies, per-backend circuit breaker overrides
- **Multi-Dimensional Rate Limiting**: Composite keys, JA3/JA4-based, JWT-verified, adaptive ML anomaly detection

## All Features Implemented

| Feature | Status | Description |
|---------|--------|-------------|
| **Load Balancing** | ✅ | 6 algorithms with session affinity and health-aware routing |
| Circuit Breaker | ✅ | Backend health monitoring with auto-recovery |
| **Advanced Rate Limiting** | ✅ | Multi-dimensional: IP, JA3/JA4, JWT, headers, composite keys |
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
| **ACME Automation** | ✅ | Let's Encrypt HTTP-01/DNS-01 certificate provisioning |
| **OCSP Stapling** | ✅ | Automated OCSP response fetching with caching |
| **Prometheus Metrics** | ✅ | TLS, connection, request, backend, and error metrics |
| PROXY Protocol v2 | ✅ | Client IP preservation for downstream proxies |
| Access Logging | ✅ | Per-request logging in JSON or text format with configurable file output |
| WebTransport Origin Validation | ✅ | SR-02 cross-origin blocking with configurable allowlist |
| WebTransport Per-Origin Rate Limiting | ✅ | Max sessions per origin, streams per session, datagrams/sec enforced |
| IP Blocklists (DB-synced) | ✅ | Live-synced IP/fingerprint/country blocklists from application database |
| Per-Route Timeouts | ✅ | Per-route timeout overrides independent of global defaults |
| Custom Header Injection | ✅ | Inject arbitrary headers per route before forwarding to backends |
| Multiple Listener Ports | ✅ | Primary port plus any number of additional ports via `additional_ports` |
| WebTransport Operations | ✅ | JSON operation routing over streams (encrypt/decrypt/keygen/health/ping) |
| **WAF** | ✅ | OWASP Top 10 pattern inspection — SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization |
| **Audit Logger** | ✅ | Async structured JSON audit log — admin actions, auth failures, WAF events, rate limits, PQC downgrades |
| **JA3/JA4 Replay Detection** | ✅ | Flags same fingerprint from multiple IPs within configurable window |
| **JA3/JA4 Drift Detection** | ✅ | Flags cipher/extension composition changes on the same fingerprint hash |
| **PQC Downgrade Detection** | ✅ | Detects classical-only TLS negotiation when PQC is required; block/log/allow action |
| **Per-Backend Retry** | ✅ | Configurable retries with exponential backoff per backend; retry on 5xx/connect-failure/timeout |
| **Per-Backend Circuit Breaker** | ✅ | Per-backend overrides for failure threshold, half-open delay, and success threshold |
| **0-RTT Replay Protection** | ✅ | Nonce store (strict/session/none); rejects replayed early-data nonces |
| **Certificate Transparency** | ✅ | Submits new certs to CT logs via `POST /ct/v1/add-chain` after ACME issuance |
| **QUIC Connection Migration** | ✅ | Configurable enable/disable of QUIC connection migration (`enable_quic_migration`) |
| **Per-Route Security Policy** | ✅ | Per-route mTLS requirement, JA3 allowlist, rate limit override, WAF mode, 0-RTT control |
| **Body Size Limit** | ✅ | Global `max_request_body_bytes` enforced (default 50 MB); 413 on excess |
| **Config Schema Versioning** | ✅ | `version` field in config; warns if absent, errors if version > current |
| **Config Conflict Validation** | ✅ | Startup validation catches conflicting settings (PQC+passthrough, 0-RTT non-safe, mTLS without CA) |
| **Environment Config Overlay** | ✅ | `--env <name>` flag loads `config.<name>.toml` overlay merged on top of base config |
| **CIDR Blocklist Support** | ✅ | Blocklist files now match full subnet ranges (e.g. `192.0.2.0/24`); previously only host addresses were matched |
| **Session Affinity TTL** | ✅ | Sticky session maps evict stale entries after configurable TTL; header affinity uses its own dedicated map |
| **Proactive Backend Health Checks** | ✅ | Background TCP-connect health task marks backends unreachable before traffic hits them; configurable interval |
| **Configurable GeoIP Block Duration** | ✅ | `geoip_block_duration_secs` in `[security]` (default 24 h); previously blocks were permanent with no expiry |
| **Configurable WebTransport Port** | ✅ | `webtransport_port` in `[server]` replaces the hardcoded port 4433 for the dedicated WebTransport server |
| **Dynamic Alt-Svc Header** | ✅ | Alt-Svc value built from `udp_port` + `additional_ports` at startup instead of a hardcoded constant |
| **Admin Loopback Enforcement** | ✅ | `require_loopback = true` (default) aborts startup when admin API is bound to a non-loopback address |
| **Shared Security State (QUIC)** | ✅ | All QUIC listeners now share one `SecurityState`; blocked IPs and rate limiters are visible across all ports |
| **Audit Logger Wired** | ✅ | `AuditLogger` constructed at startup and passed to the admin server; audit events are now actually written |
| **Cryptographically Secure Admin Token** | ✅ | Ephemeral admin tokens use `OsRng` instead of `thread_rng` |
| **OpenSSL Subprocess Env Sanitisation** | ✅ | All `openssl` subprocesses clear the environment before execution (`env_clear()`) to prevent PATH/LD_PRELOAD injection |
| **Hot Reload** | ✅ | Configuration and TLS certificates reloaded at runtime without dropping connections or restarting |
| **Log Rotation (SIGHUP)** | ✅ | `SIGHUP` reopens all log file handles in-place; compatible with logrotate `postrotate` — no restart required |
| **TLS 1.3 Enforcement** | ✅ | TLS 1.3 minimum enforced on all listeners (OpenSSL 3.5+ for TCP/TLS, rustls for QUIC/HTTP3) |
| **Server Identity Concealment** | ✅ | Server header suppressed and replaced with configurable custom branding |
| **JWT Rate Limiting** | ✅ | Per-subject rate limiting with HMAC-SHA256 signature verification; unsigned `sub` claims rejected; non-HMAC algorithms blocked |
| **Log Injection Prevention** | ✅ | Newlines and control characters stripped from all user-controlled fields before writing to access and audit logs |
| **NEL (Network Error Logging)** | ✅ | Network Error Logging headers with configurable policy for client-side error reporting |
| **`tls_skip_verify` Production Block** | ✅ | `tls_skip_verify = true` rejected at config load unless `--allow-insecure-backends` CLI flag is passed |
| **SSRF Protection** | ✅ | Link-local and loopback backend addresses rejected; RFC1918 logged with warning; WAF SSRF pattern set active |
| **Admin Brute-Force Lockout** | ✅ | Per-IP and global lockout with exponential back-off (5 min base, up to 30 min) on repeated auth failures |
| **Connection Draining** | ✅ | Graceful backend removal with configurable drain timeout; in-flight requests complete before backend is taken out of rotation |
| **Request Queuing** | ✅ | Queues requests when all backends are saturated; configurable queue depth and wait timeout |
| **Slow Start** | ✅ | Gradually ramps traffic to recovered backends to avoid thundering herd after a circuit breaker reopens |
| **Connection Pool** | ✅ | Per-backend connection pool with configurable max idle, max total, acquire timeout, and idle timeout |
| **Session Affinity Modes** | ✅ | Sticky sessions via IP hash, custom header, or Set-Cookie with configurable SameSite attribute |
| **Path Regex Routing** | ✅ | Per-route regex pattern matching with ReDoS prevention (pattern size-limited) |
| **PQC Session Tickets** | ✅ | TLS session ticket HKDF keys wrapped with ML-KEM-1024 encapsulation (`pqc_session_tickets`) |
| **TLS Key Permission Checks** | ✅ | Validates private key file permissions at startup; configurable strict mode aborts on insecure permissions |
| **Malicious Fingerprint Blocking** | ✅ | JA3/JA4 database classification blocks known-malicious fingerprints (`block_malicious`) with configurable cache TTL |
| **Server-Timing Header** | ✅ | Per-request `Server-Timing` header with proxy latency breakdown for performance visibility |
| **Accept-CH Header** | ✅ | `Accept-CH` client hints advertisement for adaptive content delivery |
| **Graceful Shutdown Drain** | ✅ | Configurable drain timeout polls active connections at 100 ms intervals; exits as soon as connections reach zero |
| **Weighted Load Balancing** | ✅ | Per-server weight (1–1000) with smooth weighted round-robin for proportional traffic distribution |
| **Least Response Time Routing** | ✅ | Routes requests to the backend with the lowest moving-average response time |
| **IP Hash Load Balancing** | ✅ | Deterministic backend selection by client IP hash for implicit session stickiness |
| **Per-Server Priority** | ✅ | Failover priority levels; lower-priority backends only receive traffic when higher-priority ones are unhealthy |
| **Per-Server Keep-Alive** | ✅ | Configurable QUIC keep-alive interval per server to prevent idle connection timeouts |
| **DNS Prefetch / Preconnect / Prerender Hints** | ✅ | Early Hints Link headers for dns-prefetch, preconnect, modulepreload, and speculative prerender |
| **Report-To Header** | ✅ | Reporting endpoint configuration injected into responses for NEL and CSP violation delivery |
| **Fingerprint Cache TTL** | ✅ | JA3/JA4 fingerprint classification cache with configurable max-age and background cleanup |

## Features

### Reverse Proxy
- **Domain-based Routing**: Route `api.example.com` → port 3003, `example.com` → port 8080
- **TLS Termination**: Decrypt at proxy, plain HTTP to backend (default)
- **TLS Re-encryption**: Decrypt at proxy, re-encrypt HTTPS to backend with mTLS support
- **TLS Passthrough**: SNI-based routing without decryption
- **HTTP→HTTPS Redirect**: Automatic port 80 to 443 redirect server
- **Custom Header Injection**: Inject arbitrary response or request headers per route before forwarding to backends
- **Per-Route Timeout Overrides**: Independent timeout configuration per route, overriding global defaults
- **Multiple Listener Ports**: Primary port plus any number of additional ports (`additional_ports`) all supporting QUIC/HTTP3/WebTransport
- **Path Regex Routing**: Per-route regex pattern matching alongside exact and prefix matching; ReDoS prevention via pattern size limit

### Security
- **WAF**: OWASP Top 10 pattern-based inspection — SQLi, XSS, path traversal, NoSQLi, SSRF, command injection, XXE, insecure deserialization; detect or block mode; custom patterns; body scanning
- **JA3/JA4 TLS Fingerprinting**: Detects browsers, bots, scanners, malware based on TLS ClientHello
- **JA3/JA4 Replay Detection**: Flags same fingerprint arriving from multiple IPs within a configurable window — catches credential-stuffing and fingerprint spoofing
- **JA3/JA4 Drift Detection**: Flags cipher/extension composition changes on the same fingerprint hash — detects TLS library upgrades or evasion attempts
- **Malicious Fingerprint Blocking**: `block_malicious = true` in fingerprint config automatically blocks connections whose JA3/JA4 hash matches a known-malicious entry in the classification database; fingerprint cache with configurable TTL and background cleanup
- **PQC Downgrade Detection**: Detects classical-only TLS negotiation when PQC is required; configurable action: block (421), log, or allow
- **PQC + Fingerprinting Combined**: OpenSSL ML-KEM with ClientHello capture for early blocking
- **PQC Session Tickets**: TLS session ticket HKDF keys wrapped with ML-KEM-1024 encapsulation (`pqc_session_tickets`) to protect resumed sessions against harvest-now-decrypt-later attacks
- **TLS 1.3 Enforcement**: TLS 1.2 and below rejected on all listeners — OpenSSL 3.5+ for TCP/TLS, rustls for QUIC/HTTP3
- **TLS Key Permission Checks**: Private key file permissions validated at startup; `strict_key_permissions = true` aborts if permissions are too permissive
- **0-RTT Replay Protection**: Nonce store (strict/session/none modes) — rejects replayed TLS 1.3 early-data nonces within configurable window
- **Circuit Breaker**: Per-backend protection from cascading failures; per-backend threshold/delay overrides
- **Advanced Rate Limiting**: Multi-dimensional limiting (IP, JA3/JA4, JWT-verified subject, headers, composite keys)
- **JWT Rate Limiting**: Per-subject limiting with HMAC-SHA256 signature verification before trusting the `sub` claim; unsigned tokens and non-HMAC algorithms rejected
- **Admin Brute-Force Lockout**: Per-IP and global lockout with exponential back-off (5 min base, up to 30 min) on repeated admin authentication failures
- **NAT-Friendly**: JA3/JA4 fingerprints identify clients behind shared corporate IPs
- **Adaptive Baseline**: ML-inspired anomaly detection learns normal traffic patterns
- **DoS Protection**: Connection limits, body size enforcement, request validation, auto-blocking
- **GeoIP Blocking**: Block by country/region using MaxMind GeoLite2 database; configurable block duration via `geoip_block_duration_secs` (default 24 h)
- **SSRF Protection**: Link-local (169.254.x.x) and loopback backend addresses rejected at config load; RFC1918 backends log a warning; WAF SSRF pattern set active for request inspection
- **Per-Route Security Policy**: Per-route mTLS requirement, JA3 allowlist, rate limit override, WAF mode override, 0-RTT control
- **Security Headers**: HSTS, X-Frame-Options, CSP, COEP, COOP, CORP, and more
- **CORS Handling**: Full CORS support with preflight OPTIONS handling
- **Server Identity Concealment**: Server header suppressed; configurable custom branding replaces backend identity
- **Log Injection Prevention**: Newlines and all control characters stripped from every user-controlled field before writing to access or audit logs
- **`tls_skip_verify` Production Block**: `tls_skip_verify = true` rejected at config load; requires explicit `--allow-insecure-backends` CLI flag to override
- **IP Blocklists (DB-synced)**: Live-synced IP, fingerprint, and country blocklists pulled from the application database — supports individual IPs and CIDR subnet ranges (e.g. `192.0.2.0/24`); updates without restart
- **ACME Domain Path Sanitization**: Domain names validated against RFC 1035 before use in file-system paths — prevents path traversal via config

### Load Balancing
- **6 Load Balancing Algorithms**:
  - `least_connections` (default): Routes to server with fewest active connections
  - `round_robin`: Simple rotation through servers
  - `weighted_round_robin`: nginx-style smooth weighted distribution
  - `random`: Random server selection
  - `ip_hash`: Consistent hashing by client IP for sticky sessions
  - `least_response_time`: Routes to fastest responding server (EMA tracking)
- **Backend Pools**: Group multiple servers per route for high availability
- **Session Affinity**: Cookie-based, IP hash, or custom header sticky sessions; each mode uses its own dedicated map with TTL eviction
- **Health-Aware Routing**: Automatically bypasses unhealthy backends; proactive TCP-connect health checks on configurable interval detect failures before traffic hits them
- **Slow Start**: Gradually increases traffic to recovering servers to avoid thundering herd after circuit breaker reopens
- **Connection Draining**: Graceful server removal with configurable drain timeout; in-flight requests complete before backend is taken out of rotation
- **Request Queuing**: Queues requests when all backends are saturated; configurable queue depth and wait timeout
- **Connection Pool**: Per-backend connection pool with configurable max idle connections, max total connections, acquire timeout, and idle timeout
- **Per-Server Keep-Alive**: Configurable QUIC keep-alive interval per server to prevent idle connection timeouts
- **Priority Failover**: Primary servers first, then failover to lower priority

### HTTP/3 Advanced Features
- **Full HTTP/3 Support**: Native HTTP/3 via `h3` crate with proper header forwarding
- **Early Hints (103)**: Preload CSS/JS resources via Link headers — dns-prefetch, preconnect, modulepreload, and speculative prerender hint types supported
- **Priority Hints**: RFC 9218 Extensible Priorities for resource scheduling (`u=3,i=?0`)
- **Request Coalescing**: Deduplicate identical GET/HEAD requests in flight
- **Alt-Svc Advertisement**: Dynamic HTTP/3 upgrade headers on all ports — built from `udp_port` and `additional_ports` at startup so every listener advertises its actual address
- **Virtual Host Routing**: Proper `:authority` pseudo-header handling for backend routing
- **Server-Timing**: Performance metrics header for browser DevTools (RFC 6797)
- **NEL (Network Error Logging)**: Client-side error reporting with configurable policy
- **Report-To**: Endpoint configuration for NEL and Reporting API
- **Accept-CH**: Client Hints for responsive content delivery (DPR, Viewport-Width, ECT)

### Protocols
- **QUIC/HTTP/3**: Full HTTP/3 support via QuicListener (h3 + quinn crates)
- **WebTransport**: Native WebTransport session handling with bidirectional streams, unidirectional streams, and datagrams
- **WebTransport Origin Validation**: SR-02 cross-origin enforcement — configurable `webtransport_allowed_origins` allowlist rejects browser sessions from unlisted origins with 403; non-browser clients (no Origin header) always accepted
- **WebTransport JSON Operations**: JSON operation routing over streams — encrypt, decrypt, keygen, health, ping dispatched to backend by operation type
- **Unified UDP Listener**: Single QuicListener handles both HTTP/3 and WebTransport
- **Shared Security State (QUIC)**: All QUIC listeners share one security context — blocked IPs, rate limiters, and fingerprint databases are consistent across every port
- **Configurable WebTransport Port**: `webtransport_port` in `[server]` controls the dedicated WebTransport server bind port (default 4433)
- **X-Forwarded Headers**: X-Real-IP, X-Forwarded-For, X-Forwarded-Proto

### Operations
- **Hot Reload**: Configuration and TLS certificate reload without restart
- **Environment Config Overlay**: `--env <name>` CLI flag (or `PQCRYPTA_ENV`) loads `config.<name>.toml` and merges it on top of the base config — shared base with environment-specific overrides
- **Config Conflict Validation**: Startup-time validation catches conflicting settings (PQC + passthrough, 0-RTT on non-safe routes without replay protection, mTLS required but no CA cert configured)
- **Access Logging**: Per-request structured logging in JSON or plain-text format; configurable output file, includes method, path, status, latency, bytes, client IP, and upstream; user-controlled fields sanitized to prevent log injection
- **Audit Logging**: Async structured JSON audit log for security-relevant events — admin actions, auth failures, WAF blocks/detects, IP blocks, rate limit hits, PQC downgrade events, config and TLS reloads, JA3 replay/drift detections
- **Log Rotation via SIGHUP**: Sending `SIGHUP` to the proxy reopens all log file handles without dropping connections or restarting — compatible with standard logrotate `postrotate` hooks (`systemctl kill -s HUP pqcrypta-proxy`)
- **Admin API**: Health checks, Prometheus metrics, config reload, graceful shutdown, QUIC health, WebTransport health; loopback enforcement prevents plain-HTTP token exposure on non-loopback interfaces; ephemeral session tokens use `OsRng` for cryptographic security; per-IP and global brute-force lockout with exponential back-off
- **Graceful Shutdown Drain**: Configurable drain timeout polls active connections at 100 ms intervals and exits as soon as they reach zero — no unnecessary delay on idle restarts
- **Certificate Transparency**: New ACME-issued certs submitted to configured CT logs via `POST /ct/v1/add-chain` for public auditability
- **Per-Backend Retry**: Configurable retry count and exponential backoff per backend; retry on 5xx responses, connect failures, or timeouts
- **Cross-Platform**: Linux, macOS, and Windows support

## Security

### Runtime Directories

The following directories must exist outside the web root before starting the proxy:

| Directory | Mode | Purpose |
|-----------|------|---------|
| `/var/lib/pqcrypta-proxy/blocklists/` | `0700`, owned by `pqcrypta` | Database-synced IP/fingerprint/country blocklists |
| `/var/lib/pqcrypta-proxy/fingerprints/` | `0700`, owned by `pqcrypta` | JA3/JA4 fingerprint database (`ja3.json`) |

```bash
# Create directories with correct ownership and permissions
install -d -m 0700 -o pqcrypta -g pqcrypta /var/lib/pqcrypta-proxy/blocklists
install -d -m 0700 -o pqcrypta -g pqcrypta /var/lib/pqcrypta-proxy/fingerprints
```

### SSRF Protection (Backend Address Validation)

Backend addresses are validated against dangerous IP ranges at config load time (F-01):

- **Link-local (`169.254.0.0/16`, `fe80::/10`)** — always rejected. These ranges host cloud
  metadata services (AWS IMDSv1/v2, GCP metadata server, Azure IMDS). Routing proxy traffic here
  would expose IAM credentials to attackers. This check cannot be disabled.
- **RFC1918 / loopback** — a warning is logged. To suppress it (e.g., in a private internal
  network where all RFC1918 backends are intentional):

```toml
[security]
# Explicitly acknowledge that RFC1918 backends are intentional and the SSRF
# risk has been assessed.  Link-local (169.254.0.0/16) is still rejected.
allow_internal_backends = true
```

### GeoIP Database Setup

The MaxMind GeoLite2 databases are **not included** in the repository (weekly updates would make
committed copies stale within days). Download them with the provided script:

```bash
# Register free at https://www.maxmind.com/en/geolite2/signup then:
export MAXMIND_ACCOUNT_ID=<your account ID>
export MAXMIND_LICENSE_KEY=<your license key>
scripts/download_geoip.sh
```

This writes `GeoLite2-Country.mmdb`, `GeoLite2-City.mmdb`, and `GeoLite2-ASN.mmdb` to
`data/geoip/`. Add this script to a weekly cron job to keep the databases current.

### Trusted Internal CIDRs

Only loopback (`127.0.0.0/8` / `::1`) is trusted by default (SEC-A05). RFC1918 private ranges
are treated as untrusted external traffic — this prevents XFF/Real-IP spoofing attacks from
RFC1918 sources (e.g., on multi-tenant or shared networks). If you operate a genuinely isolated
private network where RFC1918 sources are legitimate, add them explicitly:

```toml
[security]
# Explicit opt-in for CIDRs that should bypass security checks.
# Default: empty (only loopback 127.x/::1 is trusted; RFC1918 is NOT trusted by default).
trusted_internal_cidrs = ["10.200.0.0/16"]
```

### JA3/JA4 Fingerprint Database

To enable fingerprint-based detection:

1. Download an open-source JA3 database (e.g., from [salesforce/ja3](https://github.com/salesforce/ja3))
   or create your own JSON file with the format:
   ```json
   [
     {"hash": "<md5>", "classification": "browser", "description": "Chrome 120"},
     {"hash": "<md5>", "classification": "malicious", "description": "Mirai scanner"}
   ]
   ```
   Valid classifications: `browser`, `bot`, `legitimate_bot`, `malicious`, `scanner`, `api_client`

2. Place the file at `/var/lib/pqcrypta-proxy/fingerprints/ja3.json`
   (or configure a custom path via `fingerprint.fingerprint_db_path`)

3. If the file is missing or malformed the proxy starts normally with an empty database
   and logs a warning.

4. **Enforcement** is controlled by two flags in `[fingerprint]`:
   - `block_malicious = true` *(default)* — automatically blocks and IP-bans connections whose
     JA3/JA4 hash is classified as `malicious` in the database.  Set to `false` for advisory-only
     logging while you build confidence in the database.
   - `block_scanners = false` *(default)* — set to `true` to also block `scanner` fingerprints.

### HTTP→HTTPS Redirect Host Validation

To prevent open-redirect abuse via a spoofed `Host` header, configure the allowed-domains list:

```toml
[http_redirect]
enabled = true
port = 80
# Only redirect requests whose Host header matches one of these domains.
# Requests with an unknown Host receive 400 Bad Request.
allowed_domains = ["example.com", "api.example.com", "www.example.com"]
```

Leave `allowed_domains = []` (empty, the default) to disable the check and allow any Host.

### Admin API Authentication

The admin API should always have an authentication token set:

```toml
[admin]
bind_address = "127.0.0.1"
port = 8082
allowed_ips = ["127.0.0.1", "::1"]
# Generate with: openssl rand -base64 32
auth_token = "your-random-token-here"
# require_loopback = true  ← default: aborts startup when bind_address is non-loopback
```

Without an `auth_token` any process on the host can call destructive endpoints
(`/shutdown`, `/reload`) without credentials.

**Loopback enforcement (`require_loopback`):** By default the proxy refuses to start when the
admin `bind_address` resolves to a non-loopback interface, because all admin traffic — including
the Bearer token — is plain HTTP. To intentionally expose the admin API on a non-loopback address
(e.g. behind a TLS-terminating SSH tunnel), set:

```toml
[admin]
bind_address = "0.0.0.0"
require_loopback = false  # explicitly acknowledge the risk
```

### Version-Controlled Configuration

**Never commit your production `config/proxy-config.toml` to version control** — it contains
secrets (auth token, ACME email), real infrastructure topology, and backend addresses.

Use `config/example-config.toml` as the template:

```bash
cp config/example-config.toml config/proxy-config.toml
# Fill in real values; proxy-config.toml is in .gitignore
```


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

# Copy example config and fill in real values (proxy-config.toml is gitignored)
cp config/example-config.toml /etc/pqcrypta/proxy-config.toml

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

### Advanced Rate Limiting Configuration

The advanced rate limiter provides multi-dimensional rate limiting inspired by Cloudflare, Envoy, HAProxy, and ML research. It solves the corporate NAT problem where many users share one gateway IP.

```toml
[advanced_rate_limiting]
enabled = true

# Key resolution strategy
# Options: source_ip, xff_trusted, ja3_fingerprint, jwt_subject, composite
key_strategy = "composite"

# X-Forwarded-For trust configuration
xff_trust_depth = 1                 # How many proxies to trust
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# IPv6 subnet grouping (prevents per-host evasion)
ipv6_prefix_length = 64

# Global rate limits (DDoS protection layer)
[advanced_rate_limiting.global_limits]
requests_per_second = 10000
burst_size = 2000

# Per-IP limits (NAT-aware via composite keys)
[advanced_rate_limiting.global_limits.per_ip]
requests_per_second = 100
burst_size = 200
requests_per_minute = 1000
requests_per_hour = 10000

# Per-JA3 fingerprint limits (NAT-friendly client identification)
[advanced_rate_limiting.global_limits.per_ja3]
requests_per_second = 500
burst_size = 100

# Per-JWT subject limits (user-level limiting)
[advanced_rate_limiting.global_limits.per_jwt_subject]
requests_per_second = 50
burst_size = 100

# Composite key limits (IP + JA3 + Path)
[advanced_rate_limiting.global_limits.composite]
requests_per_second = 200
burst_size = 50

# Adaptive baseline learning (ML-inspired anomaly detection)
[advanced_rate_limiting.adaptive]
enabled = true
learning_window_secs = 3600         # 1 hour learning window
anomaly_threshold = 3.0             # Standard deviations from mean
block_anomalies = false             # Only log, don't block during learning
min_samples = 100                   # Minimum samples before blocking

# Route-specific overrides
[[advanced_rate_limiting.route_overrides]]
route_name = "api-route"
per_ip_rps = 200                    # Higher limits for API route
per_ip_burst = 400
per_ja3_rps = 1000

[[advanced_rate_limiting.route_overrides]]
route_name = "login-route"
per_ip_rps = 10                     # Stricter limits for login
per_ip_burst = 20
```

**Key Features:**
- **Composite Keys**: Combine IP + JA3 fingerprint + path for fine-grained limiting
- **JA3/JA4 Fingerprinting**: Identify clients behind NAT by TLS handshake signature
- **JWT Subject Extraction**: Rate limit by authenticated user, not just IP
- **X-Forwarded-For Trust Chain**: Properly handle clients behind trusted proxies
- **IPv6 Subnet Grouping**: Group /64 subnets to prevent per-host evasion
- **Adaptive Baseline**: Learns normal traffic patterns and detects anomalies
- **Layered Limits**: Global → Route → Client hierarchy for defense in depth

### WAF Configuration

```toml
[waf]
enabled = true
mode = "block"          # "detect" logs only; "block" returns 403
sqli = true             # SQL injection patterns
xss = true              # Cross-site scripting patterns
path_traversal = true   # Directory traversal (../, %2e%2e, null bytes)
nosqli = true           # NoSQL injection ($where, $gt, $regex, etc.)
ssrf = false            # SSRF patterns (higher false-positive rate — tune before enabling)
scan_json_body = true   # Scan request bodies
max_body_scan_bytes = 65536   # Max bytes of body to scan (default 64 KB)
custom_patterns = [
    "(?i)\\bmy-banned-keyword\\b",
]
```

Route-level WAF override:
```toml
[[routes]]
name = "public-api"
host = "api.example.com"
path_prefix = "/"
backend = "api"

[routes.security]
waf_enabled = true
waf_mode = "block"   # override global mode for this route
```

### Audit Logging Configuration

```toml
[logging]
audit_log_enabled = true
audit_log_path = "/var/log/pqcrypta-proxy/audit.json"   # omit to write to stderr
```

Each audit event is a JSON object with `timestamp`, `level`, `category`, and event-specific fields. Event categories: `admin_action`, `auth_failure`, `ip_blocked`, `rate_limit`, `pqc_downgrade`, `waf_block`, `waf_detect`, `config_reload`, `tls_reload`, `ja3_replay`, `ja3_drift`.

### Per-Backend Retry Configuration

```toml
[backends.api]
name = "api"
address = "127.0.0.1:3003"
retries = 3                                        # default 3
retry_backoff_ms = 50                              # initial backoff; doubles each attempt
retry_on = ["connect-failure", "5xx", "timeout"]   # default: connect-failure + 5xx
```

### Per-Backend Circuit Breaker Override

```toml
[backends.critical-api]
name = "critical-api"
address = "127.0.0.1:4000"

[backends.critical-api.circuit_breaker]
failure_threshold = 3        # trip after 3 failures (global default: 5)
half_open_delay_secs = 10    # half-open probe delay (global default: 30)
success_threshold = 1        # close after 1 success (global default: 2)
```

### Environment Config Overlay

```bash
# Load base config, then merge /etc/pqcrypta/proxy-config.prod.toml on top
pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml --env prod

# Or via environment variable
PQCRYPTA_ENV=prod pqcrypta-proxy --config /etc/pqcrypta/proxy-config.toml
```

Overlay values win for all matching keys; unmatched keys from the base are kept. The overlay is re-applied on hot-reload.

### Certificate Transparency Configuration

```toml
[acme]
enabled = true
certificate_transparency = true
ct_logs = [
    "https://ct.googleapis.com/logs/xenon2025h1/",
    "https://yeti2025.ct.digicert.com/log/",
]
```

### WebTransport Rate Limiting Configuration

```toml
[server]
webtransport_max_sessions_per_origin = 100    # max concurrent sessions per Origin header
webtransport_max_streams_per_session = 1000   # max concurrent streams per session
webtransport_max_datagrams_per_sec = 500      # datagram rate limit per session
```

### QUIC Connection Migration

```toml
[server]
enable_quic_migration = true   # default true; set false to disable client IP migration
```

### Per-Route Security Policy

```toml
[[routes]]
name = "secure-api"
host = "api.example.com"
path_prefix = "/"
backend = "api"

[routes.security]
mtls_required = true                          # require client certificate on this route
allowed_ja3 = ["abc123...", "def456..."]      # allowlist of known-good JA3 fingerprints
waf_enabled = true
waf_mode = "block"
enable_0rtt = false                           # deny 0-RTT early data on this route
```

### Load Balancer Configuration

```toml
# Global load balancer settings
[load_balancer]
enabled = true
default_algorithm = "least_connections"  # Options: least_connections, round_robin, weighted_round_robin, random, ip_hash, least_response_time

# Session affinity (sticky sessions) settings
[load_balancer.session_affinity]
cookie_name = "PQCPROXY_BACKEND"
cookie_ttl_secs = 3600
cookie_secure = true
cookie_httponly = true
cookie_samesite = "lax"  # Options: strict, lax, none

# Request queue when all backends busy
[load_balancer.queue]
enabled = true
max_size = 1000
timeout_ms = 5000

# Slow start for recovering servers
[load_balancer.slow_start]
enabled = true
duration_secs = 30
initial_weight_percent = 10

# Connection draining for graceful removal
[load_balancer.connection_draining]
enabled = true
timeout_secs = 30

# Backend pool with multiple servers
[backend_pools.api]
name = "api"
algorithm = "least_connections"
health_aware = true
affinity = "cookie"  # Options: none, cookie, ip_hash, header
health_check_path = "/health"
health_check_interval_secs = 10

# Primary server
[[backend_pools.api.servers]]
address = "127.0.0.1:3003"
weight = 100
priority = 1
max_connections = 100
timeout_ms = 30000
tls_mode = "terminate"

# Secondary server
[[backend_pools.api.servers]]
address = "127.0.0.1:3004"
weight = 100
priority = 1
max_connections = 100

# Failover server (only used when primary/secondary unavailable)
[[backend_pools.api.servers]]
address = "10.0.0.5:3003"
weight = 50
priority = 2  # Lower priority = failover only
max_connections = 50
```

**Route to Pool**: Routes can reference either single backends or backend pools:

```toml
# Route using a backend pool
[[routes]]
name = "api-route"
host = "api.example.com"
path_prefix = "/"
backend = "api"  # References backend_pools.api
priority = 100
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
allow_origin = "https://example.com"   # must be a specific origin when allow_credentials = true
allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allow_headers = ["Content-Type", "Authorization", "X-API-Key"]
allow_credentials = true
max_age = 86400
```

> **Configuration validation** rejects `allow_origin = "*"` combined with `allow_credentials = true` at startup (RFC 6454 / CORS spec). All modern browsers refuse this combination; the proxy enforces it at load time rather than producing confusing runtime failures. Use a specific origin string when credentials are required.

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

Environment variables: `PQCRYPTA_CONFIG`, `PQCRYPTA_UDP_PORT`, `PQCRYPTA_ADMIN_PORT`, `PQCRYPTA_LOG_LEVEL`, `PQCRYPTA_JSON_LOGS`, `PQCRYPTA_ENV`

Set `PQCRYPTA_ENV=production` to explicitly declare a production deployment. Set `PQCRYPTA_ENV=development` to permit development-only options (such as `tls_skip_verify`) when ACME is not enabled. When ACME is active the environment is always treated as production regardless of this variable.

## Architecture

```
                    ┌──────────────────────────────────────────────────────────┐
                    │                         PQCProxy v0.2.2                   │
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
                    │  │                   Load Balancer                      │ │
                    │  │  Algorithms: least_conn | round_robin | weighted    │ │
                    │  │              random | ip_hash | least_response_time │ │
                    │  │  Features: Session affinity, Health-aware routing   │ │
                    │  │           Slow start, Connection draining           │ │
                    │  └─────────────────────────────────────────────────────┘ │
                    │                                                          │
                    │  ┌─────────────────────────────────────────────────────┐ │
                    │  │                   Backend Pools                      │ │
                    │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │ │
                    │  │  │ TLS         │  │ TLS         │  │ TLS         │  │ │
                    │  │  │ Terminate   │  │ Re-encrypt  │  │ Passthrough │  │ │
                    │  │  │ (HTTP)      │  │ (HTTPS)     │  │ (SNI)       │  │ │
                    │  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  │ │
                    │  └─────────┼────────────────┼────────────────┼─────────┘ │
                    │            │                │                │           │
                    │            ▼                ▼                ▼           │
                    │      Pool: Apache     Pool: API       Pool: External    │
                    │   ┌────┬────┬────┐ ┌────┬────┬────┐  ┌────┬────┐       │
                    │   │ S1 │ S2 │ S3 │ │ S1 │ S2 │ S3 │  │ S1 │ S2 │       │
                    │   └────┴────┴────┘ └────┴────┴────┘  └────┴────┘       │
                    │                                                          │
                    │  Admin API (HTTP 8082)                                   │
                    │    /health, /metrics, /reload, /shutdown                 │
                    └──────────────────────────────────────────────────────────┘
```

## Module Structure

```
src/
├── main.rs              # Entry point; --env overlay; startup validation
├── lib.rs               # Library exports
├── config.rs            # Configuration parsing, schema versioning, conflict validation, env overlay
├── load_balancer.rs     # Load balancing algorithms, pools, session affinity, per-backend CB overrides
├── proxy.rs             # Backend pool, request routing, per-backend retry with exponential backoff
├── http_listener.rs     # HTTP/1.1 + HTTP/2 listener with PQC TLS
├── quic_listener.rs     # QUIC/HTTP/3 listener; configurable connection migration
├── security.rs          # Rate limiting, DoS, GeoIP, circuit breaker, WAF hook, body size limit
├── fingerprint.rs       # JA3/JA4 TLS fingerprint extraction, replay cache, drift detector
├── tls_acceptor.rs      # Custom TLS acceptor with fingerprint capture; 0-RTT nonce store
├── compression.rs       # Brotli/Zstd/Gzip compression
├── http3_features.rs    # Early Hints, Priority, Request Coalescing
├── admin.rs             # Admin API endpoints; audit logging; /health/quic; /health/webtransport
├── tls.rs               # TLS configuration; PQC session tickets
├── pqc_tls.rs           # Post-Quantum TLS provider; downgrade detection
├── pqc_extended.rs      # Extended PQC configuration and capabilities
├── acme.rs              # ACME certificate automation; Certificate Transparency log submission; domain path validation
├── ocsp.rs              # OCSP stapling automation
├── metrics.rs           # Prometheus metrics registry
├── rate_limiter.rs      # Advanced multi-dimensional rate limiting; JWT HMAC verification
├── proxy_protocol.rs    # PROXY protocol v2 support
├── access_logger.rs     # Structured access log with log-injection sanitization
├── waf.rs               # WAF engine — OWASP Top 10 pattern sets, detect/block modes
├── audit_logger.rs      # Async structured JSON audit logger for security events
└── webtransport_server.rs  # WebTransport session handling; per-origin session rate limiting
```

## Post-Quantum Cryptography

PQCrypta Proxy supports hybrid PQC key exchange using rustls-post-quantum (X25519MLKEM768).

### Supported KEMs

| Algorithm | Security Level | Description |
|-----------|---------------|-------------|
| `X25519MLKEM768` | NIST Level 3 | Hybrid X25519 + ML-KEM-768 — **recommended default** (FIPS 203) |
| `SecP256r1MLKEM768` | NIST Level 3 | Hybrid P-256 + ML-KEM-768 (FIPS 203) |
| `SecP384r1MLKEM1024` | NIST Level 5 | Hybrid P-384 + ML-KEM-1024 (FIPS 203) |
| `X448MLKEM1024` | NIST Level 5 | Hybrid X448 + ML-KEM-1024 (FIPS 203) |
| `mlkem512` | NIST Level 1 | Pure ML-KEM-512 (FIPS 203) |
| `mlkem768` | NIST Level 3 | Pure ML-KEM-768 (FIPS 203) |
| `mlkem1024` | NIST Level 5 | Pure ML-KEM-1024 (FIPS 203) |
| `kyber768` ⚠️ | NIST Level 3 | **Deprecated** — pre-NIST round-3 draft, not FIPS 203. Requires `--features legacy-pqc` at build time. Not interoperable with ML-KEM peers. Do not use for new deployments. |
| `x25519_kyber768` ⚠️ | NIST Level 3 | **Deprecated** — pre-NIST round-3 draft hybrid, not FIPS 203. Requires `--features legacy-pqc` at build time. |

> **Only FIPS 203-compliant algorithms are built by default.** `kyber768` and `x25519_kyber768` (pre-standardisation Kyber drafts) are excluded from all default builds. To enable them only for backward-compatible migration periods, compile with `cargo build --release --features legacy-pqc`. A deprecation warning is logged at startup whenever a legacy algorithm is selected.

### Configuration

```toml
[pqc]
enabled = true
provider = "openssl3.5"
openssl_path = "/usr/local/openssl-pq/bin/openssl"
openssl_lib_path = "/usr/local/openssl-pq/lib64"
preferred_kem = "x25519_kyber768"
fallback_to_classical = true
```

> **Important**: `openssl_path` must point to an OpenSSL 3.5+ binary built with ML-KEM support. The proxy checks this path at startup to determine whether the PQC TCP listener is available. If the path is wrong or the binary is missing, the proxy silently falls back to a standard rustls listener that accepts TLS 1.2 and does not negotiate X25519MLKEM768. Always verify the path exists before deploying.

## ACME Certificate Automation

Automatic Let's Encrypt certificate provisioning and renewal with SAN (Subject Alternative Name) support. Issues a single certificate covering all configured domains. Uses ECDSA P-256 keys for smaller certs and faster TLS handshakes.

### How It Works

1. **Daily check** reads the local cert file to check expiry (zero network cost)
2. **Renewal triggers** when cert is within 30 days of expiry (~day 60 of 90-day cert)
3. **ACME protocol** runs only during actual renewal (~once every 60 days)
4. **HTTP-01 challenges** served on port 80 before HTTPS redirect kicks in
5. **Exponential backoff** on challenge polling (2s → 4s → 8s → 16s cap)
6. **SAN certificate** — single order, single cert, all domains as SANs

### Configuration

```toml
[acme]
enabled = true
domains = ["example.com", "api.example.com"]
email = "admin@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"  # Production
# directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"  # Staging
challenge_type = "http-01"
certs_path = "/etc/pqcrypta/certs"
account_path = "/etc/pqcrypta/acme/account.json"
renewal_days = 30           # Renew 30 days before expiry
check_interval_hours = 24   # Once daily (local check only, no network cost)
use_ecdsa = true            # ECDSA P-256 (smaller keys, faster handshakes)
accept_tos = true

# External Account Binding (required by ZeroSSL, optional for Let's Encrypt)
# eab_kid = "your-kid"
# eab_hmac_key = "your-hmac-key"
```

### Challenge Types

| Type | Description | Requirements |
|------|-------------|--------------|
| `http-01` | HTTP validation on port 80 | Port 80 accessible, served by redirect server |
| `dns-01` | DNS TXT record | DNS API access |

### Supported CAs

| CA | Directory URL |
|----|---------------|
| Let's Encrypt | `https://acme-v02.api.letsencrypt.org/directory` |
| Let's Encrypt Staging | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| ZeroSSL | `https://acme.zerossl.com/v2/DV90` (requires EAB) |
| Buypass | `https://api.buypass.com/acme/directory` |
| Google Trust Services | `https://dv.acme-v02.api.pki.goog/directory` |

## OCSP Stapling

Automated OCSP response fetching with background refresh.

### Configuration

```toml
[ocsp]
enabled = true
cache_duration_secs = 3600  # 1 hour cache
refresh_before_expiry_secs = 300  # Refresh 5 min before expiry
timeout_secs = 10
max_retries = 3
```

### Status Monitoring

```bash
# Check OCSP status
curl http://127.0.0.1:8082/ocsp

# Force refresh
curl -X POST http://127.0.0.1:8082/ocsp/refresh
```

## Admin API

### Endpoints

**Public (no authentication required):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Minimal health check — safe for load-balancer probes (F-03) |

**Protected (Bearer token required):**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus metrics (comprehensive) |
| `/metrics/json` | GET | JSON metrics snapshot |
| `/metrics/errors` | GET | Per-endpoint error counts and recent failure log. Filter with `?type=client` (4xx) or `?type=server` (5xx) |
| `/reload` | POST | Reload configuration — audit logged |
| `/shutdown` | POST | Graceful shutdown — audit logged |
| `/config` | GET | Read-only config view |
| `/backends` | GET | Backend health status |
| `/tls` | GET | TLS certificate info |
| `/ocsp` | GET | OCSP stapling status |
| `/ocsp/refresh` | POST | Force OCSP response refresh *(5-min cooldown)* |
| `/acme` | GET | ACME certificate status |
| `/acme/renew` | POST | Force certificate renewal *(1-hour cooldown)* |
| `/ratelimit` | GET | Rate limiter status and statistics |
| `/health/quic` | GET | QUIC listener health — port, migration status, active connections |
| `/health/webtransport` | GET | WebTransport health — active sessions, allowed origins, limits |

### Example

```bash
# Health check
curl http://127.0.0.1:8082/health

# Prometheus metrics
curl http://127.0.0.1:8082/metrics

# Reload configuration
curl -X POST http://127.0.0.1:8082/reload

# Reload TLS certificates only
curl -X POST http://127.0.0.1:8082/reload -d '{"tls_only":true}'
```

## Metrics

### Latency Percentiles (p50 / p95 / p99)

Latency percentiles are computed from a **double-buffered 5-minute sliding window** rather than a cumulative histogram. The active buffer accumulates request durations; every 2.5 minutes the buffers rotate, so reported percentiles always reflect the last 2.5–5 minutes of live traffic. Historical outliers from startup or past load spikes do not pollute current readings.

Percentiles are interpolated using **Prometheus-style linear interpolation** within each bucket. The histogram uses 18 fine-grained buckets with boundaries chosen to match SLO thresholds: 5, 10, 25, 50, 75, 100, 150, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000 ms, and +Inf. This eliminates the step-function snapping seen with coarse bucket boundaries (e.g., a p99 of 1001 ms being reported as 2500 ms).

### Health Check Traffic Exclusion

Requests that carry the `x-health-check-bypass: 1` request header are excluded from **all** metrics counters and the latency histogram:

- Not counted in `total_requests`, `successful_requests`, `failed_requests`
- Not added to the latency histogram (no impact on p50/p95/p99)
- Not tracked in `in_progress` connections
- Not recorded as endpoint errors

This prevents the health check cron's synthetic cryptographic workflows (which generate intentional 500s during wrong-key rejection tests) from appearing as real errors or skewing production latency percentiles.

The API server's `tower_http::TraceLayer` is also configured with `.on_failure(())` on all three router layers, suppressing the default `ERROR`-level log entries that would otherwise be emitted for every health-check-bypass 500. Genuine non-bypass 5xx responses are still logged as `ERROR` by the metrics middleware, which checks the `x-health-check-bypass` header before deciding whether to emit the log entry.

### WAF Blocked Requests

Requests rejected by the security IP-blocklist or bot-blocklist receive an `x-waf-block: 1` response header. The collector tracks these separately in `waf_blocked_requests` (distinct from `failed_requests`) so that bot attack traffic cannot inflate error-rate SLOs or depress domain health scores.

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

### All Security Features

- [x] TLS 1.3 only (enforced for both TCP/TLS via OpenSSL 3.5+ and QUIC/HTTP3 via rustls)
- [x] Full security headers (HSTS, COEP, COOP, CORP, etc.)
- [x] Server identity hidden (custom branding)
- [x] X-Forwarded-For header support
- [x] Rate limiting (per-IP token bucket with burst handling; multi-dimensional composite keys)
- [x] DoS protection (connection limits, body size limit, request validation, auto-blocking)
- [x] Request size limits (413/431 responses); chunked body size enforced (Transfer-Encoding bypass closed)
- [x] GeoIP blocking (MaxMind DB integration)
- [x] JA3/JA4 TLS fingerprinting (browser/bot/malware detection)
- [x] JA3/JA4 replay detection (same fingerprint from multiple IPs in window)
- [x] JA3/JA4 drift detection (cipher/extension composition change on same hash)
- [x] Circuit breaker (backend protection; per-backend failure threshold and half-open delay overrides)
- [x] Per-backend retry (configurable count, exponential backoff, retry-on conditions)
- [x] IP blocking (manual + auto with expiration; DB-synced blocklists)
- [x] Compression (Brotli, Zstd, Gzip, Deflate)
- [x] Early Hints (103) support
- [x] Priority Hints (RFC 9218)
- [x] Request Coalescing (dedupe identical requests)
- [x] PQC hybrid key exchange (X25519MLKEM768 — NIST FIPS 203)
- [x] PQC downgrade detection (block/log/allow when classical-only TLS negotiated)
- [x] 0-RTT replay protection (nonce store with strict/session/none modes; window configurable)
- [x] Background cleanup (auto-expire blocked IPs)
- [x] SSRF protection (link-local backend rejection, RFC1918 warning, WAF SSRF pattern set)
- [x] WAF (OWASP Top 10: SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization; detect/block modes; custom patterns)
- [x] Structured audit logging (async JSON — admin actions, auth failures, WAF events, rate limits, PQC downgrades, config reloads, JA3 replay/drift)
- [x] Admin router tier split (public /health vs. authenticated /metrics, /reload, etc.)
- [x] Admin token auth (ephemeral if not configured; constant-time comparison; per-IP + global brute-force lockout with exponential back-off)
- [x] JWT rate limiting with HMAC-SHA256 signature verification (no unsigned sub claim trust)
- [x] Configurable JWT algorithms (default HS256; non-HMAC rejected — prevents algorithm-confusion attacks)
- [x] Exponential back-off on global auth cooldown (5 min base, up to 30 min)
- [x] ACME/OCSP endpoint rate limiting (/acme/renew 1-hour cooldown; /ocsp/refresh 5-min cooldown)
- [x] Certificate Transparency — new ACME certs submitted to CT logs after issuance
- [x] ACME domain path sanitization — RFC 1035 validation before any certs_path join
- [x] QUIC connection migration (configurable enable/disable via `enable_quic_migration`)
- [x] WebTransport per-origin session rate limiting (max sessions, streams, datagrams/sec)
- [x] Per-route security policy (mTLS, JA3 allowlist, rate limit override, WAF mode, 0-RTT control)
- [x] Config conflict validation at startup and hot-reload (PQC+passthrough, 0-RTT without replay protection, mTLS without CA cert)
- [x] Environment config overlay (`--env <name>` merges `config.<name>.toml` over base)
- [x] Config schema versioning (warns on absent version; errors on future version)
- [x] Admin API non-loopback warning (WARN when bind_address is not loopback)
- [x] `require_mtls = true` hard startup error (prevents false sense of security — mTLS not yet implemented on admin listener)
- [x] Backend topology not disclosed in logs (resolved host:port pairs removed from startup output)
- [x] Loopback-only trust for `is_trusted_ip()` (RFC1918 not trusted by default — closes XFF bypass)
- [x] Graceful shutdown drain polling (100 ms poll loop exits when connections reach zero — no fixed sleep)
- [x] OpenSSL binary path validation (must be absolute, pointing to a regular file)
- [x] Log injection prevention (newlines and control characters stripped from all user-controlled log fields)
- [x] `tls_skip_verify` blocked in production (rejected at config load; requires `--allow-insecure-backends`)
- [x] `unsafe_code = deny` globally (OpenSSL FFI retains targeted allow)
- [x] Panic prevention (no production-path unwrap(); ok_or/? throughout)
- [x] Memory exhaustion prevention (DashMap collections bounded with eviction)
- [x] ReDoS prevention (regex patterns size-limited)
- [x] SECURITY.md vulnerability disclosure policy

### mTLS Configuration

```toml
[tls]
ca_cert_path = "/etc/pqcrypta/client-ca.pem"
require_client_cert = true

[admin]
require_mtls = true
```

## Admin API Authentication

The admin API requires **at least one** of the following to be configured, or the proxy refuses to start:

- `auth_token` set in `[admin]` — Bearer token required on every admin request, or
- `allowed_ips` restricted to loopback addresses (`127.x.x.x`, `::1`)

```toml
[admin]
enabled = true
bind_address = "127.0.0.1"
port = 8082
auth_token = "your-strong-secret-token-at-least-32-chars"   # required unless allowed_ips is loopback-only
allowed_ips = ["127.0.0.1", "::1"]
```

**Token requirements:**
- Minimum **32 characters** — the proxy rejects shorter tokens at startup. Generate a strong token with `openssl rand -base64 48`.
- Token comparison uses constant-time equality to prevent timing side-channel attacks.

**Brute-force protection:**
- **Per-IP:** 10 failures per 60-second window triggers a `429 Too Many Requests` lockout for that IP.
- **Distributed (F-08):** 50 total failures across all IPs triggers a global cooldown of **5 minutes**
  (base). Each successive trigger doubles the cooldown (5 min → 10 min → 20 min → 30 min max).
  Resets to 0 on a successful authentication. This catches distributed attacks where each source IP
  stays below the per-IP threshold.
- **Endpoint cooldowns (F-14):** `/acme/renew` is limited to once per hour; `/ocsp/refresh` to once
  per 5 minutes to prevent inadvertent CA rate-limit exhaustion.

## JWT Rate Limiting

Per-subject JWT rate limiting verifies the token's HMAC-SHA256 signature before trusting the `sub` claim. Configure a shared signing secret that matches the upstream token issuer:

```toml
[advanced_rate_limiting]
key_strategy = "jwt_subject"
jwt_secret = "your-hmac-sha256-secret-at-least-32-bytes"
```

Without `jwt_secret`, the `jwt_subject` strategy is disabled and falls back to the next configured key strategy.

**Algorithm restriction (F-10):** By default only `HS256` is accepted. To allow additional HMAC variants:

```toml
[advanced_rate_limiting]
jwt_secret = "your-hmac-sha256-secret-at-least-32-bytes"
jwt_algorithms = ["HS256"]   # Only HS256/HS384/HS512 are valid; non-HMAC strings are rejected
```

## Insecure Backend TLS

`tls_skip_verify = true` on a backend completely disables certificate and signature verification for that upstream connection, enabling man-in-the-middle attacks on the proxy↔backend leg. The proxy logs a loud warning for every such backend at startup.

**Production deployments reject `tls_skip_verify` at config load.** Production is detected automatically when:
- ACME is enabled (`[acme] enabled = true`), or
- `PQCRYPTA_ENV=production` is set in the environment.

To use `tls_skip_verify` in a development environment where neither condition applies, set `PQCRYPTA_ENV=development`:

```sh
PQCRYPTA_ENV=development pqcrypta-proxy --config config.toml
```

```toml
# Only valid when PQCRYPTA_ENV=development and acme.enabled = false
[backends.dev-backend]
name = "dev-backend"
tls_mode = "reencrypt"
address = "localhost:8443"
tls_skip_verify = true
```

Replace self-signed backend certificates with CA-signed ones before enabling ACME or moving to production.

## 0-RTT Early Data

0-RTT (TLS 1.3 early data) is **disabled by default**. When enabled, the proxy detects early-data connections at the TLS accept layer by inspecting the ClientHello and enforces per-route replay protection at the HTTP dispatch layer.

```toml
[tls]
enable_0rtt = true
# Methods safe for 0-RTT forwarding (idempotent, no side effects)
zero_rtt_safe_methods = ["GET", "HEAD"]
```

### Per-route enforcement (RFC 8470)

Every route has an `allow_0rtt` flag that defaults to `false`. When a request arrives as TLS 1.3 early data on a route where `allow_0rtt = false`, the proxy responds with **425 Too Early** and does not forward the request to the backend. This prevents replay attacks on non-idempotent operations (POST, PUT, DELETE, PATCH, etc.).

Routes that serve purely idempotent, replay-safe content can opt in explicitly:

```toml
[[routes]]
name = "static-assets"
host = "cdn.example.com"
path_prefix = "/static/"
backend = "cdn"
allow_0rtt = true   # safe: static files, no side effects
```

```toml
[[routes]]
name = "api"
host = "api.example.com"
path_prefix = "/"
backend = "api"
# allow_0rtt = false  ← default; early-data requests receive 425 Too Early
```

The `x-tls-early-data` header used internally to propagate the early-data flag is stripped from all incoming requests before being set by the accept loop, and is removed from every outgoing backend request, so it cannot be forged by clients or leaked to backends.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
