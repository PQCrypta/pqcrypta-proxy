# PQCrypta Proxy

**Production-ready HTTP/3/QUIC/WebTransport reverse proxy with hybrid Post-Quantum Cryptography (PQC) TLS support.**

[![CI](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/ci.yml)
[![Cargo Deny](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/cargo-deny.yml/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/cargo-deny.yml)
[![OSSF Scorecard](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/ossf-scorecard.yml/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/ossf-scorecard.yml)
[![CodeQL](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/codeql.yml/badge.svg)](https://github.com/PQCrypta/pqcrypta-proxy/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

## Highlights

- **Full-Featured Proxy**: Domain-based routing, custom header injection, per-route timeouts, security headers, CORS, redirects
- **Three TLS Modes**: Terminate, Re-encrypt, and Passthrough (SNI-based)
- **Modern Protocols**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebTransport
- **Post-Quantum Ready**: Hybrid PQC key exchange (X25519MLKEM768) via OpenSSL 3.5+ with native ML-KEM; ML-DSA-87 (FIPS 204) server certificates per SNI; PQC downgrade detection reading the negotiated group off the connection
- **Encrypted Client Hello**: Server-side ECH (draft-ietf-tls-esni-25) on TCP and QUIC, with rotating HPKE keys published in the DNS HTTPS record
- **Zero Downtime**: Hot reload configuration and TLS certificates; environment-specific config overlay (`--env`)
- **ACME Automation**: Automatic Let's Encrypt certificate provisioning, renewal, and Certificate Transparency log submission
- **OCSP Stapling**: Automated OCSP response fetching and stapling
- **Prometheus Metrics**: Comprehensive metrics for TLS, connections, requests, backends, and WAF blocks
- **WAF**: Pattern-based request inspection for injection and traversal attacks (SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization) in detect or block mode — covers OWASP A01/A03/A08/A10 attack patterns; categories requiring architectural or supply-chain controls (A02, A04, A05, A06, A09) are handled at other layers. Scanner/reconnaissance probe paths (`.git`, `.env`, `.aws`, `wp-login.php`, terraform state, SSH keys, CI/CD files, etc.) are blocked at path level before pattern scanning, preventing automated scanner traffic from reaching backends and polluting error-rate metrics
- **Advanced Security**: JA3/JA4 fingerprinting on TCP *and* QUIC with replay and drift detection, circuit breaker, GeoIP blocking, DB-synced IP blocklists, WebTransport origin validation, 0-RTT replay protection
- **Structured Audit Logging**: Async JSON audit log for admin actions, auth failures, WAF blocks, IP blocks, rate limit hits, PQC downgrades, config reloads
- **Structured Access Logging**: Per-request JSON or text logs with latency, bytes, upstream, and client IP
- **Enterprise Load Balancing**: 6 algorithms, session affinity, health-aware routing, per-backend retry policies, per-backend circuit breaker overrides, canary / percentage traffic splitting with sticky assignment and auto-rollback, traffic shadowing / mirroring
- **Multi-Dimensional Rate Limiting**: Composite keys, JA3/JA4-based, JWT-verified, adaptive ML anomaly detection; optional Redis backend distributes counters across all proxy instances
- **Zero-Trust Primitives**: Per-route HMAC proof-of-possession (path+query signed, nonce replay prevention), internal route mTLS auto-enforcement, zero-trust mode startup validation (includes admin HMAC requirement), admin proof-of-possession, `trusted_internal_cidrs` deprecation
- **OpenTelemetry Distributed Tracing**: W3C TraceContext + B3 propagation on all transports, OTLP HTTP/JSON export, configurable sampling, access-log trace-ID correlation

## All Features Implemented

| Feature | Status | Description |
|---------|--------|-------------|
| **Load Balancing** | ✅ | 6 algorithms with session affinity and health-aware routing |
| Circuit Breaker | ✅ | Backend health monitoring with auto-recovery |
| **Advanced Rate Limiting** | ✅ | Multi-dimensional: IP, JA3/JA4, JWT, headers, composite keys on all paths (TCP + QUIC/HTTP3); optional Redis backend for distributed cross-instance coordination |
| **Connection Rate Limiting** | ✅ | Per-IP cap on *new connections per second* (`connection_rate_limit`, `connections_per_second`), separate from `max_connections_per_ip` which caps concurrency — a client that opens and closes as fast as it can never trips a concurrency limit |
| **Per-Route Security Policy** | ✅ | `[routes.security]` overrides applied before the global checks: WAF on/off and mode, rate limits, JA3 allowlist, mTLS, HMAC request signing, plus `skip_bot_blocking` for routes that serve automated clients |
| DoS Protection | ✅ | Connection limits, request validation |
| GeoIP Blocking | ✅ | Country-based blocking (MaxMind DB) |
| JA3/JA4 Fingerprinting | ✅ | TLS client fingerprint detection and classification on **every transport** — HTTP/1.1, HTTP/2 and HTTP/3. Over QUIC the ClientHello arrives inside encrypted Initial CRYPTO frames, so the vendored rustls/noq forks surface it through `HandshakeData` and it is parsed by the same extractor the TCP paths use. The JA4 transport marker is `q` over QUIC and `t` over TCP |
| Priority Hints | ✅ | RFC 9218 response prioritization |
| Request Coalescing | ✅ | Deduplicates identical in-flight requests |
| Early Hints (103) | ✅ | Link headers for preload/preconnect |
| Compression | ✅ | Brotli/gzip/deflate/zstd |
| Security Headers | ✅ | HSTS, CSP, CORS, Alt-Svc; CORS headers injected on 429 rate-limit responses so browsers surface the status code instead of a misleading CORS error |
| PQC TLS | ✅ | X25519MLKEM768 hybrid key exchange (NIST Level 3) + ML-DSA-87 server certificates (NIST Level 5, FIPS 204) |
| Background Cleanup | ✅ | Auto-cleanup of expired entries |
| **ACME Automation** | ✅ | Let's Encrypt HTTP-01/DNS-01; one individual cert per domain with atomic writes and immediate hot-reload |
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
| WebTransport Operations | ✅ | JSON operation routing over streams (encrypt/decrypt/keygen/health/ping/speedtest); QUIC-native speed test server with datagram RTT probing, stream throughput download/upload, packet-loss measurement, MTR-based hop traceroute with GeoIP annotation, and per-client info lookup |
| **WAF** | ✅ | Pattern-based injection and traversal inspection — SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization; covers OWASP A01/A03/A08/A10 attack patterns. Scanner probe blocking: path-level block for `.git`, `.env`, `.aws`, `wp-login.php`, terraform state, SSH keys, CI/CD files, and 40+ other reconnaissance targets |
| **Audit Logger** | ✅ | Async structured JSON audit log — admin actions, auth failures, WAF events, rate limits, PQC downgrades |
| **JA3/JA4 Replay Detection** | ✅ | Flags same fingerprint from multiple IPs within configurable window |
| **JA3/JA4 Drift Detection** | ✅ | Flags cipher/extension composition changes on the same fingerprint hash |
| **PQC Downgrade Detection** | ✅ | Detects classical-only TLS negotiation when PQC is required; block/log/allow action. The negotiated group is read from the connection via `SSL_get0_group_name`, not assumed — it was previously hardcoded to `X25519MLKEM768`, which made the check unable to fire |
| **Response Cache (RFC 9111)** | ✅ | Optional RFC 9111-compliant HTTP cache with Cache-Control parsing, ETag/If-None-Match, Last-Modified/If-Modified-Since, Vary header support, size-bounded DashMap store, and configurable path/host exclusions. HEAD responses are never stored — their body is empty by definition, and a stored empty body made the hit path report the resource as zero-length |
| **HTTP/3 Client Conformance Suite** | ✅ | A public service that makes the server misbehave on purpose so a client library can find out how it copes: 51 anomalies, each citing the RFC clause it exercises — reserved frame types, a duplicated SETTINGS identifier, a control stream opening with the wrong frame, an unknown QUIC frame type, a Stateless Reset, a path-MTU black hole, refused 0-RTT. Every test binds its own UDP port, because anomalies like `supported_versions` are endpoint-wide and one port is the whole test; the vhost serves the catalogue, reports and badge. Verdicts are asymmetric by class — ignoring a reserved *HTTP/3* frame is a pass and ignoring a reserved *QUIC* frame is a failure, since QUIC reserves no ignorable frame types (RFC 9000 §12.4). A failure requires positive evidence that the client read the anomaly: silence on a unidirectional control stream, or a window that closes with nothing observed, is **inconclusive** — a rejection whose CONNECTION_CLOSE was lost looks exactly like no rejection at all. A run that never puts the client in the situation under test records inconclusive too, never a pass and never a failure. Machine-readable catalogue, JSON reports and an SVG badge; `h3-conformance` drives any client from CI |
| **Cache Purge (admin API)** | ✅ | `GET /cache` reports entries and bytes held; `POST /cache/purge` drops them — everything, or narrowed by `?host=`, `?prefix=` or `?host=&path=` for one exact URL across every method. Exists because a deploy that changes generated output otherwise leaves the edge serving the old body until max-age expires, and the alternative was restarting the proxy. `path=` without `host=` is refused rather than silently widened. Audit-logged with scope and target |
| **Single Shared Response Cache** | ✅ | One cache instance per process rather than one per listener. There were five — one per HTTP listener variant and one per QUIC port — so the same URL was cached separately for h2 and h3 and for each port, and a purge would have cleared one while the others served the old body. The key is `METHOD\|host\|path`, with no port or protocol in it, so sharing is what the key already assumed |
| **Correct HEAD Semantics (RFC 9110 §9.3.2)** | ✅ | A HEAD response carries the header fields a GET would have. Backends serving chunked send no `Content-Length`, and the proxy no longer synthesizes `content-length: 0` from the empty buffered body — which had been telling every link checker, uptime monitor, CDN probe and security scanner that every dynamic page was empty. Fixed on all three transports (HTTP/1.1, HTTP/2 and the separate HTTP/3 implementation) |
| **Per-Backend Connection Pool** | ✅ | Per-host idle timeout, max idle connections, max total connections, and acquire timeout for the HTTP/1.1 backend pool |
| **Per-Backend Retry** | ✅ | Configurable retries with exponential backoff per backend; retry on 5xx/connect-failure/timeout |
| **Per-Backend Circuit Breaker** | ✅ | Per-backend overrides for failure threshold, half-open delay, and success threshold |
| **0-RTT Replay Protection** | ✅ | Nonce store (strict/session/none); rejects replayed early-data nonces |
| **QUIC Retry** | ✅ | Optional RFC 9000 source-address validation (`enable_quic_retry`); Retry token echoed before handshake, anti-spoofing at +1 RTT |
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
| **Enforced Backend Request Timeout** | ✅ | Per-backend/pool-server `timeout_ms` bounds the forwarded request itself (not just connection setup) — a hung backend returns 504 Gateway Timeout instead of holding the client connection open indefinitely |
| **Configurable GeoIP Block Duration** | ✅ | `geoip_block_duration_secs` in `[security]` (default 24 h); previously blocks were permanent with no expiry |
| **Configurable WebTransport Port** | ✅ | `webtransport_port` in `[server]` replaces the hardcoded port 4433 for the dedicated WebTransport server |
| **Dynamic Alt-Svc Header** | ✅ | Alt-Svc value built from `udp_port` + `additional_ports` at startup instead of a hardcoded constant |
| **TCP-Only Hosts** | ✅ | `tcp_only_hosts` in `[server]` — listed hostnames receive `Alt-Svc: clear`, evicting cached QUIC upgrades so browsers always connect via TCP/TLS |
| **HTTP/1.1-Only Hosts** | ✅ | `http11_only_hosts` in `[server]` — listed hostnames negotiate HTTP/1.1 only (no `h2` ALPN); browsers open an independent TCP connection per `fetch()` stream instead of coalescing onto one HTTP/2 pipe, eliminating head-of-line blocking on parallel speed test streams |
| **Admin Loopback Enforcement** | ✅ | `require_loopback = true` (default) aborts startup when admin API is bound to a non-loopback address |
| **Shared Security State** | ✅ | **Every** listener — QUIC and all three TCP paths — shares one `SecurityState`. Blocked IPs, rate limiter counters, the fingerprint corpus and DB-synced blocklists are visible across all of them. The TCP listeners previously each constructed their own, so an IP blocked on one was not blocked on another and the admin API could not clear it |
| **Audit Logger Wired** | ✅ | `AuditLogger` constructed at startup and passed to the admin server; audit events are now actually written |
| **Cryptographically Secure Admin Token** | ✅ | Ephemeral admin tokens use `OsRng` instead of `thread_rng` |
| **`zero_trust_mode`** | ✅ | Startup validation enforcing mTLS, no plaintext backends, no CIDR trust, and admin HMAC proof-of-possession |
| **Per-Route HMAC Signing** | ✅ | HMAC-SHA256 proof-of-possession signing full path+query string; optional `X-Request-Nonce` binds nonce into signature for full replay prevention within 300 s window |
| **Internal Route Auto-mTLS** | ✅ | `internal = true` routes default to requiring client certificate |
| **Admin HMAC Proof-of-Possession** | ✅ | Optional per-request HMAC signature (path+query signed) alongside bearer token; optional `X-Admin-Nonce` for full replay prevention |
| **`trusted_internal_cidrs` Deprecation** | ✅ | Startup warning directing operators to cert-based trust |
| **OpenSSL Subprocess Env Sanitisation** | ✅ | All `openssl` subprocesses clear the environment before execution (`env_clear()`) to prevent PATH/LD_PRELOAD injection |
| **Hot Reload** | ✅ | Configuration and TLS certificates reloaded at runtime without dropping connections or restarting |
| **Log Rotation (SIGHUP)** | ✅ | `SIGHUP` reopens all log file handles in-place; compatible with logrotate `postrotate` — no restart required |
| **TLS 1.3 Default** | ✅ | TLS 1.3 minimum by default on all listeners (`min_version = "1.3"`); configurable to allow TLS 1.2 via `min_version` in `[tls]` |
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
| **PQC Session Tickets** | ✅ | Each TLS 1.3 ticket carries its own ML-KEM-1024 encapsulation; the resumption state is sealed with an AES-256-GCM key derived from it via HKDF-SHA384 (`pqc_session_tickets`, `session_ticket_lifetime_secs`) |
| **TLS Key Permission Checks** | ✅ | Validates private key file permissions at startup; configurable strict mode aborts on insecure permissions |
| **Malicious Fingerprint Blocking** | ✅ | Classification consults the operator database at `fingerprint_db_path` first, then the built-in table, matching JA3 then JA4 (`block_malicious`, `block_scanners`). Authorised `pentest_bypass_ips` are classified but never banned |
| **Server-Timing Header** | ✅ | Per-request `Server-Timing` header with proxy latency breakdown for performance visibility |
| **Accept-CH Header** | ✅ | `Accept-CH` client hints advertisement for adaptive content delivery |
| **Graceful Shutdown Drain** | ✅ | Configurable drain timeout polls active connections at 100 ms intervals; exits as soon as connections reach zero |
| **Weighted Load Balancing** | ✅ | Per-server weight (1–1000) with smooth weighted round-robin for proportional traffic distribution |
| **Canary / Traffic Splitting** | ✅ | Percentage-based canary routing with sticky cookie assignment, per-pool auto-rollback on error rate threshold, and live admin control — active on HTTP/1.1, HTTP/2, HTTP/3/QUIC |
| **Traffic Shadowing / Mirroring** | ✅ | Per-route fire-and-forget copy of requests to a secondary backend; client only sees primary response; all parameters configurable (backend, percent, timeout, marker header) — active on HTTP/1.1, HTTP/2, HTTP/3/QUIC |
| **RFC 9111 Response Cache** | ✅ | Full Cache-Control parsing (max-age, s-maxage, no-cache, no-store, private, public); ETag/If-None-Match → 304; Last-Modified/If-Modified-Since → 304; Vary header support; TTL-based expiry; size-bounded DashMap store — active on HTTP/1.1, HTTP/2, HTTP/3/QUIC |
| **Hop-by-Hop Header Stripping** | ✅ | HTTP/1.1 connection-specific headers (`Transfer-Encoding`, `Connection`, `Keep-Alive`, `Proxy-Connection`, `Upgrade`, `TE`, `Trailer`, `Proxy-Authenticate`, `Proxy-Authorization`) stripped from backend responses before caching and forwarding — compliant with RFC 9113 §8.2.2 and RFC 9114 §4.2; prevents `ERR_QUIC_PROTOCOL_ERROR` on HTTP/3/QUIC and stream errors on HTTP/2 |
| **OpenTelemetry Distributed Tracing** | ✅ | W3C TraceContext (`traceparent`/`tracestate`, RFC 9543) + B3 multi-header + B3 single-header extraction and injection; composite propagator on all transports (HTTP/1.1, HTTP/2, HTTP/3/QUIC, WebTransport); OTLP HTTP/JSON export; `ParentBased(TraceIdRatioBased)` sampler; trace IDs in access-log lines |
| **Least Response Time Routing** | ✅ | Routes requests to the backend with the lowest moving-average response time |
| **IP Hash Load Balancing** | ✅ | Deterministic backend selection by client IP hash for implicit session stickiness |
| **Per-Server Priority** | ✅ | Failover priority levels; lower-priority backends only receive traffic when higher-priority ones are unhealthy |
| **Per-Server Keep-Alive** | ✅ | Configurable QUIC keep-alive interval per server to prevent idle connection timeouts |
| **DNS Prefetch / Preconnect / Prerender Hints** | ✅ | Early Hints Link headers for dns-prefetch, preconnect, modulepreload, and speculative prerender |
| **Report-To Header** | ✅ | Reporting endpoint configuration injected into responses for NEL and CSP violation delivery |
| **Fingerprint Cache TTL** | ✅ | JA3/JA4 fingerprint classification cache with configurable max-age and background cleanup |
| **QUIC ACK Frequency** | ✅ | draft-ietf-quic-ack-frequency extension (`enable_ack_frequency`, default on) — peers may request fewer, batched ACKs, cutting ACK traffic and CPU on high-throughput connections; negotiated, so inert against clients that lack it |
| **MASQUE / CONNECT-UDP (RFC 9298)** | ✅ | UDP proxying over HTTP/3 Extended CONNECT (`:protocol = connect-udp`); UDP payloads relayed as HTTP Datagrams (RFC 9297) bound to the request stream; disabled by default with `host:port` allowlist, per-session idle timeout, and per-connection session cap (`[masque]`) |
| **Encrypted Client Hello (ECH)** | ✅ | Server-side ECH, draft-ietf-tls-esni-25. HPKE keypairs generated and rotated by `ech-keygen` / `ech-rotate.timer` into `/etc/pqcrypta/ech-configs`, with previous configs retained so clients holding a cached DNS record still complete. Applies on **TCP and QUIC** — ECH is a TLS 1.3 extension and QUIC is TLS 1.3, so the same handshake resolves it. The outcome (`accepted` / `rejected` / `not-offered`) is exposed to backends as `x-tls-ech` |
| **Handshake Facts to Backends** | ✅ | `x-tls-version`, `x-tls-cipher`, `x-tls-group`, `x-tls-alpn`, `x-tls-ech` injected on all three listener paths, alongside the existing `x-ja3-hash` / `x-ja4-hash` / `x-client-name` / `x-client-type` / `x-client-cert` / `x-tls-early-data`. Every one is **stripped from the incoming request before being set**, so a caller cannot assert a handshake it did not have |
| **Observed Fingerprint Corpus** | ✅ | Fingerprints seen in live traffic are persisted to `/var/lib/pqcrypta-proxy/fingerprints/observed.json` every 5 minutes and reloaded at startup, with the pre-hash JA3 string, per-fingerprint connection counts, and the User-Agents seen on requests carrying them. Bounded and evicted least-recently-seen. Evidence only — it never feeds classification or blocking |

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
- **WAF**: Pattern-based injection and traversal inspection — SQLi, XSS, path traversal, NoSQLi, SSRF, command injection, XXE, insecure deserialization; detect or block mode; custom patterns; body scanning; covers OWASP A01/A03/A08/A10 attack patterns; `X-Forwarded-For` headers scanned without SSRF patterns (localhost/RFC1918 IPs in XFF are legitimate proxy hops, not SSRF — prevents false positives for clients behind local reverse proxies)
- **JA3/JA4 TLS Fingerprinting**: Detects browsers, bots, scanners, malware based on TLS ClientHello
- **JA3/JA4 Replay Detection**: Flags same fingerprint arriving from multiple IPs within a configurable window — catches credential-stuffing and fingerprint spoofing
- **JA3/JA4 Drift Detection**: Flags cipher/extension composition changes on the same fingerprint hash — detects TLS library upgrades or evasion attempts
- **Malicious Fingerprint Blocking**: `block_malicious = true` in fingerprint config automatically blocks connections whose JA3/JA4 hash matches a known-malicious entry in the classification database; fingerprint cache with configurable TTL and background cleanup
- **PQC Downgrade Detection**: Detects classical-only TLS negotiation when PQC is required; configurable action: block (421), log, or allow
- **PQC + Fingerprinting Combined**: OpenSSL ML-KEM with ClientHello capture for early blocking
- **PQC Session Tickets**: rustls installs no ticketer by default, so with `pqc_session_tickets = false` the proxy issues no TLS 1.3 tickets at all and resumption relies on session storage. When enabled, each ticket encapsulates to the server's ML-KEM-1024 (FIPS 204) key for a fresh per-ticket secret, derives an AES-256-GCM key from it with HKDF-SHA384, and seals the resumption state with the KEM ciphertext as associated data. The keypair rolls every `session_ticket_lifetime_secs` (default 12 h) retaining one previous generation, since the trait requires lifetime to be enforced by key rolling rather than a timestamp inside the ticket. Note the server holds both halves of the keypair: what this changes is the algorithm protecting ticket key material and that each ticket gets an independent secret — it is not a defence against reading server memory
- **TLS 1.3 Default**: TLS 1.3 minimum on all listeners by default (`min_version = "1.3"` in `[tls]`); TLS 1.2 can be permitted via config — OpenSSL 3.5+ for TCP/TLS, rustls for QUIC/HTTP3
- **TLS Key Permission Checks**: Private key file permissions validated at startup; `strict_key_permissions = true` aborts if permissions are too permissive
- **0-RTT Replay Protection**: Nonce store (strict/session/none modes) — rejects replayed TLS 1.3 early-data nonces within configurable window
- **QUIC Retry (source-address validation)**: Optional RFC 9000 §8.1.2 Retry — a new, unvalidated connection is answered with a Retry token the client must echo before the handshake proceeds, hardening against spoofed-source amplification/DDoS at the cost of one extra round trip per new connection. Configurable via `enable_quic_retry` in `[server]` (default off, in which case RFC 9000's implicit 3× anti-amplification validation is used instead — no per-connection latency).
- **Circuit Breaker**: Per-backend protection from cascading failures; per-backend threshold/delay overrides
- **Advanced Rate Limiting**: Multi-dimensional limiting (IP, JA3/JA4, JWT-verified subject, headers, composite keys) applied on both TCP (HTTP/1.1, HTTP/2) and QUIC/HTTP3 paths; optional Redis backend distributes counters across all proxy instances
- **JWT Rate Limiting**: Per-subject limiting with HMAC-SHA256 signature verification before trusting the `sub` claim; unsigned tokens and non-HMAC algorithms rejected
- **Admin Brute-Force Lockout**: Per-IP and global lockout with exponential back-off (5 min base, up to 30 min) on repeated admin authentication failures
- **NAT-Friendly**: JA3/JA4 fingerprints identify clients behind shared corporate IPs
- **Adaptive Baseline**: ML-inspired anomaly detection learns normal traffic patterns
- **DoS Protection**: Connection limits, body size enforcement, request validation, auto-blocking
- **GeoIP Blocking**: Block by country/region using MaxMind GeoLite2 database; configurable block duration via `geoip_block_duration_secs` (default 24 h)
- **SSRF Protection**: Link-local (169.254.x.x) and loopback backend addresses rejected at config load; RFC1918 backends log a warning; WAF SSRF pattern set active for path, query, and body inspection; `X-Forwarded-For` exempt from SSRF patterns since proxy hops legitimately insert loopback/RFC1918 IPs into the forwarded chain
- **Per-Route Security Policy**: Per-route mTLS requirement, JA3 allowlist, rate limit override, WAF mode override, 0-RTT control
- **Security Headers**: HSTS, X-Frame-Options, CSP, COEP, COOP, CORP, and more
- **CORS Handling**: Full CORS support with preflight OPTIONS handling; all rate-limit 429 responses include `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` headers when the request Origin matches an allowed origin — prevents browsers from reporting rate-limit errors as CORS failures
- **Server Identity Concealment**: Server header suppressed; configurable custom branding replaces backend identity
- **Log Injection Prevention**: Newlines and all control characters stripped from every user-controlled field before writing to access or audit logs
- **`tls_skip_verify` Production Block**: `tls_skip_verify = true` rejected at config load; requires explicit `--allow-insecure-backends` CLI flag to override
- **IP Blocklists (DB-synced)**: Live-synced IP, fingerprint, and country blocklists pulled from the application database — supports individual IPs and CIDR subnet ranges (e.g. `192.0.2.0/24`); updates without restart. The reload **reconciles in both directions**: entries added to the synced file are blocked, and database-sourced entries that disappear from it are released from memory on the next reload (60 s), so deactivating a row or clicking unblock in the threat dashboard actually lifts a live block. Only `DatabaseSync` entries are reconciled — blocks the proxy raised itself (rate limit, WAF, `Manual` config entries) are unaffected. For an immediate release, `POST /blocklist/unblock/:ip` on the admin API drops the IP (and any CIDR entry covering it) without waiting for the next sync; `GET /blocklist` shows what the running proxy is actually enforcing, which is the copy that decides whether a request is refused
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
- **Canary / Percentage Traffic Splitting**: Route a configurable percentage of new traffic to a canary server while stable servers handle the rest; once assigned, clients receive a sticky `PQCPROXY_CANARY` cookie so they stay on the same server for the duration of the experiment; auto-rollback suspends the canary if its sliding-window error rate exceeds a configured threshold; live admin endpoints (`GET /canary`, `POST /canary/suspend/:id`, `POST /canary/resume/:id`, `POST /canary/weight/:id`) allow runtime inspection and control without restarting the proxy
- **Traffic Shadowing / Mirroring**: Per-route `[routes.shadow]` block sends a fire-and-forget async copy of each request to a secondary backend; client only ever sees the primary response and the shadow response is discarded; configurable percentage (0–100), independent timeout, custom marker header name+value, and per-route response logging — zero overhead on routes without shadow configured
- **Health-Aware Routing**: Automatically bypasses unhealthy backends; proactive TCP-connect health checks on configurable interval detect failures before traffic hits them
- **Slow Start**: Gradually increases traffic to recovering servers to avoid thundering herd after circuit breaker reopens
- **Connection Draining**: Graceful server removal with configurable drain timeout; in-flight requests complete before backend is taken out of rotation
- **Request Queuing**: Queues requests when all backends are saturated; configurable queue depth and wait timeout
- **Connection Pool**: Per-backend connection pool with configurable max idle connections, max total connections, acquire timeout, and idle timeout
- **Per-Server Keep-Alive**: Configurable QUIC keep-alive interval per server to prevent idle connection timeouts
- **Priority Failover**: Primary servers first, then failover to lower priority

### HTTP/3 Advanced Features
- **Full HTTP/3 Support**: Native HTTP/3 via `h3` crate with proper header forwarding; hop-by-hop headers (`Transfer-Encoding`, `Connection`, etc.) stripped from all backend responses before forwarding or caching — prevents `ERR_QUIC_PROTOCOL_ERROR` per RFC 9114 §4.2
- **QUIC v1 only**: The endpoint advertises **QUIC v1 (RFC 9000)** in Version Negotiation and nothing else. The QUIC stack's default version list also includes the obsolete `draft-29..34` (which it cannot actually handshake); the listener overrides `EndpointConfig::supported_versions` to v1 so VN advertises only what the server really speaks (plus the reserved/GREASE version per RFC 9287)
- **Early Hints (103)**: Preload CSS/JS resources via Link headers — dns-prefetch, preconnect, modulepreload, and speculative prerender hint types supported. Preload rules are scoped per host/path in `[[http3.preload_resources]]` and hot-reload at runtime (preconnect origins + preload rules apply on the next request, no restart). Note: an `href` is only used by the browser when it byte-matches the page URL, so any `?v=` cache-buster must be included and kept in sync.
- **Priority Hints**: RFC 9218 Extensible Priorities for resource scheduling (`u=3,i=?0`)
- **Request Coalescing**: Deduplicate identical GET/HEAD requests in flight
- **Alt-Svc Advertisement**: Dynamic HTTP/3 upgrade headers on all ports — built from `udp_port` and `additional_ports` at startup so every listener advertises its actual address; `tcp_only_hosts` in `[server]` sends `Alt-Svc: clear` for designated TCP-only origins; `http11_only_hosts` in `[server]` suppresses `h2` ALPN entirely so browsers open an independent TCP connection per stream (required for parallel TCP speed tests)
- **Virtual Host Routing**: Proper `:authority` pseudo-header handling for backend routing
- **Server-Timing**: Performance metrics header for browser DevTools (RFC 6797)
- **NEL (Network Error Logging)**: Client-side error reporting with configurable policy
- **Report-To**: Endpoint configuration for NEL and Reporting API
- **Accept-CH**: Client Hints for responsive content delivery (DPR, Viewport-Width, ECT)

### Protocols
- **QUIC/HTTP/3**: Full HTTP/3 support via QuicListener (h3 + noq crates — noq is n0-computer's multipath-capable quinn fork; see Multipath QUIC above)
- **Multipath QUIC (draft-ietf-quic-multipath)**: Full multipath support. The QUIC stack is [noq](https://github.com/n0-computer/noq) (n0-computer's multipath-capable quinn fork), which implements the complete extension — concurrent, data-carrying paths with per-path packet-number spaces, per-path loss recovery and congestion control, the full lifecycle frame set (ACK_MP/PATH_ABANDON/PATH_STATUS/MAX_PATH_ID/PATHS_BLOCKED), per-path connection-ID spaces, and a scheduler. The concurrent path budget is set by `server.max_concurrent_multipath_paths` (default 4; `1` keeps every connection single-path, `0` stops the extension being negotiated at all) and path creation/validation/teardown is automatic once negotiated. Peers that do not advertise multipath are unaffected whatever the value. HTTP/3 and WebTransport both run over noq (via the in-tree `h3-noq` binding and the noq-ported `wtransport`). Verify: scan pqcrypta.com at https://pqcrypta.com/http3_quic/ — the Multipath field validates a genuine second data-carrying path.
- **WebTransport**: Native WebTransport session handling with bidirectional streams, unidirectional streams, and datagrams
- **WebTransport SNI Certificates**: The dedicated WebTransport listener selects the per-domain certificate by SNI from the certs directory (same multi-cert resolver as the HTTPS listeners), so a single node serves WebTransport for every hosted domain with that domain's own certificate
- **WebTransport Origin Validation**: SR-02 cross-origin enforcement — configurable `webtransport_allowed_origins` allowlist rejects browser sessions from unlisted origins with 403; non-browser clients (no Origin header) always accepted
- **WebTransport JSON Operations**: JSON operation routing over streams — encrypt, decrypt, keygen, health, ping dispatched to backend by operation type; plus a built-in QUIC-native speed test server (`speedtest` operation) providing datagram RTT probing, stream download/upload throughput measurement, packet-loss counting, MTR-based hop traceroute with GeoIP city/ASN/country annotation, and client IP info lookup
- **Telemetry Wall** (`/telemetry`): Native WebTransport handler that pushes 6 independent QUIC uni-streams at 20 Hz each (~5 Mbps virtual throughput per channel), demonstrating true QUIC stream isolation. A stats channel pushes RTT, CWND, CPU, and memory at 10 Hz. A control bidi-stream accepts impairment commands (delay, loss, bandwidth cap, jitter, disconnect) scoped to individual channels, leaving others unaffected — the opposite of TCP head-of-line blocking.
- **QUIC vs TCP Speed Test** (`/speedtest`): Side-by-side throughput comparison over QUIC and TCP. WebTransport path measures download/upload throughput, datagram RTT, and packet loss. The `tcp_only_hosts` + `http11_only_hosts` config options force a parallel HTTP/1.1 connection so the browser opens one TCP stream per fetch rather than coalescing onto HTTP/2 — enabling a true protocol-level comparison. TCP-speedtest responses echo the request `Origin` when it is in `webtransport_allowed_origins`, so the test works from any allowed front-end regardless of allowlist order.
- **Pentest Suite** (`pentests/`): 32 automated black-box attack scripts across 12 phases covering WAF bypass, HTTP smuggling (HTTP/1.1 CL.TE, HTTP/2 Rapid Reset, HTTP/3, WebTransport), SSRF, timing oracles, race conditions, and AI/LLM attack surface. Use `pentest_bypass_ips` in `[security]` to skip rate-limiting and auto-block for test runner IPs while keeping the WAF active.
- **Unified UDP Listener**: Single QuicListener handles both HTTP/3 and WebTransport
- **Shared Security State**: Every listener — QUIC and all three TCP paths — shares one security context, so blocked IPs, rate limiter counters, the fingerprint corpus and DB-synced blocklists are consistent across every port and transport, and the admin API's unblock route reaches all of them
- **Configurable WebTransport Port**: `webtransport_port` in `[server]` controls the dedicated WebTransport server bind port (default 4433)
- **X-Forwarded Headers**: X-Real-IP, X-Forwarded-For, X-Forwarded-Proto
- **Hop-by-Hop Header Stripping**: HTTP/1.1 connection-specific headers stripped from backend responses at the proxy layer before any caching or forwarding — safe across HTTP/1.1, HTTP/2, HTTP/3/QUIC, and WebTransport

### Operations
- **Hot Reload**: Configuration and TLS certificate reload without restart
- **Environment Config Overlay**: `--env <name>` CLI flag (or `PQCRYPTA_ENV`) loads `config.<name>.toml` and merges it on top of the base config — shared base with environment-specific overrides
- **Config Conflict Validation**: Startup-time validation catches conflicting settings (PQC + passthrough, 0-RTT on non-safe routes without replay protection, mTLS required but no CA cert configured)
- **Access Logging**: Per-request structured logging in JSON or plain-text format; configurable output file, includes method, path, status, latency, bytes, client IP, and upstream; user-controlled fields sanitized to prevent log injection
- **Audit Logging**: Async structured JSON audit log for security-relevant events — admin actions, auth failures, WAF blocks/detects, IP blocks, rate limit hits, PQC downgrade events, config and TLS reloads, JA3 replay/drift detections
- **Log Rotation via SIGHUP**: Sending `SIGHUP` to the proxy reopens all log file handles without dropping connections or restarting — compatible with standard logrotate `postrotate` hooks (`systemctl kill -s HUP pqcrypta-proxy`)
- **Admin API**: Health checks, Prometheus metrics, config reload, graceful shutdown, QUIC health, WebTransport health, canary status and live weight/suspend/resume control, live blocklist inspection (`GET /blocklist`) and immediate unblock (`POST /blocklist/unblock/:ip`); loopback enforcement prevents plain-HTTP token exposure on non-loopback interfaces; ephemeral session tokens use `OsRng` for cryptographic security; per-IP and global brute-force lockout with exponential back-off
- **Graceful Shutdown Drain**: Configurable drain timeout polls active connections at 100 ms intervals and exits as soon as they reach zero — no unnecessary delay on idle restarts
- **Certificate Transparency**: New ACME-issued certs submitted to configured CT logs via `POST /ct/v1/add-chain` for public auditability
- **Per-Backend Retry**: Configurable retry count and exponential backoff per backend; retry on 5xx responses, connect failures, or timeouts
- **Cross-Platform**: Linux, macOS, and Windows support

## Security

### One Enforcement Path

The WAF, blocklist, GeoIP check, rate limiters, header-size limit and per-route
policy are implemented once, in `SecurityState::evaluate`, and both transports
call it. It takes a transport-agnostic view of a request and returns a verdict;
only the rendering differs — axum builds a `Response`, the HTTP/3 handler builds
an `http::Response<()>`.

This matters because the HTTP/3 handler previously carried its own copy of the
checks, which omitted the WAF entirely: every rule was bypassable by connecting
over QUIC. Two implementations of one policy drift. When changing a rule, change
`evaluate` — a new decision variant will not compile until both renderers handle
it. Verify parity after any change:

```bash
# both must return 403
curl              "https://<host>/?id=1%20UNION%20SELECT%20pw%20FROM%20users"
curl --http3-only "https://<host>/?id=1%20UNION%20SELECT%20pw%20FROM%20users"
```

### TLS Fingerprint Classification

Fingerprints are computed on **every transport**. On TCP the listener peeks the socket
and parses the ClientHello itself; over QUIC the hello arrives inside encrypted Initial
CRYPTO frames, so the vendored rustls fork captures its wire bytes and the vendored noq
fork surfaces them through `HandshakeData`. Both feed the **same** extractor — two
parsers would mean one client classified differently depending on which port it reached,
and a blocklist entry gathered on one silently not applying on the other.

Because a QUIC client legitimately offers a different extension set (QUIC transport
parameters in, others out), the JA4 transport marker distinguishes them: `q` over QUIC,
`t` over TCP.

Blocking on the QUIC path happens *after* the handshake rather than before it. A QUIC
server cannot decline earlier — the hello is encrypted under keys derived during the
handshake it would be trying to avoid — but the block still lands before any HTTP/3
request is served.


Classification consults the operator database at `fingerprint.fingerprint_db_path`
first, then the built-in table. Entries are matched by **JA3, then JA4**.

Prefer JA4 when adding a scanner. JA3 hashes the raw cipher/extension order, so a
tool that varies its cipher list between probes produces a different JA3 every
run — two runs of `nmap --script ssl-enum-ciphers` against this proxy produced two
disjoint sets of 19 JA3 hashes while their JA4 values were identical. An entry
whose `hash` field holds a JA4 string is matched the same way as a JA3 one.

Collect fingerprints rather than copying them from public lists — a wrong entry
silently blocks real visitors. The proxy logs one line per *new* fingerprint under
the `fingerprint_observed` target, so running a single named tool and reading that
window gives verified ground truth:

```bash
MARK=$(date -Is)
# run exactly one tool against the proxy, then:
journalctl -u pqcrypta-proxy --since "$MARK" | grep "New TLS fingerprint"
```

Addresses in `security.pentest_bypass_ips` are classified and logged but never
banned by fingerprint, so adding a scanner entry cannot ban the host your
authorised scans come from.

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
bind_address = "0.0.0.0"           # "[::]" for dual-stack; enable_ipv6 = false downgrades it to IPv4
udp_port = 443
additional_ports = [4433, 4434]
worker_threads = 0                  # 0 = one per CPU core; read before the Tokio runtime is built
max_concurrent_multipath_paths = 4  # draft-ietf-quic-multipath; 1 = single-path, 0 = never negotiated

[tls]
cert_path = "/etc/letsencrypt/live/example.com/fullchain.pem"
key_path = "/etc/letsencrypt/live/example.com/privkey.pem"
ocsp_stapling = true                # must be true AND [ocsp].enabled for stapling to run
pqc_session_tickets = true          # without this, no TLS 1.3 tickets are issued at all
session_ticket_lifetime_secs = 43200

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

# Rate limits live in [rate_limiting], not under [security]; the auto-block
# thresholds that react to them are [security] keys.
[rate_limiting]
requests_per_second = 100
burst_size = 200

[security]
auto_block_threshold = 10           # suspicious patterns before an IP is blocked
auto_block_duration_secs = 300      # how long that block lasts
max_connections_per_ip = 100

[security.circuit_breaker]
failure_threshold = 5
success_threshold = 2
timeout_secs = 30
```

### Advanced Rate Limiting Configuration

The advanced rate limiter provides multi-dimensional rate limiting inspired by Cloudflare, Envoy, HAProxy, and ML research. It solves the corporate NAT problem where many users share one gateway IP.

```toml
# Basic layer: request rate and, separately, how fast an IP may OPEN connections.
# max_connections_per_ip caps concurrency; a client that opens and closes as fast
# as it can never trips a concurrency cap, which is what connection_rate_limit is for.
[rate_limiting]
enabled = true
requests_per_second = 100
burst_size = 50
connection_rate_limit = true
connections_per_second = 10

[advanced_rate_limiting]
enabled = true
ipv6_subnet_bits = 64               # group /64 subnets so a single host cannot rotate addresses
trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

# Key resolution: a table, not a string. The first entry that can be derived
# from the request wins; `fallback` applies when none can.
[advanced_rate_limiting.key_strategy]
order = ["api_key", "jwt_subject", "ja3_fingerprint", "real_ip", "source_ip"]
fallback = "source_ip"
use_composite = false

[advanced_rate_limiting.global_limits]
requests_per_second = 10000
burst_size = 2000

[advanced_rate_limiting.global_limits.per_ip]
requests_per_second = 100
burst_size = 200
requests_per_minute = 1000
requests_per_hour = 10000

[advanced_rate_limiting.global_limits.per_fingerprint]
requests_per_second = 500
burst_size = 100

[advanced_rate_limiting.global_limits.per_api_key]
requests_per_second = 50
burst_size = 100

[advanced_rate_limiting.global_limits.per_composite]
requests_per_second = 200
burst_size = 50

# Adaptive anomaly detection
[advanced_rate_limiting.adaptive]
enabled = true
baseline_window_secs = 3600         # window used to profile normal traffic
sensitivity = 0.7                   # 0.0 = laxest, 1.0 = strictest; 0.7 == raw multiplier
auto_adjust = true                  # tighten each key's limits toward its own baseline
min_samples = 1000                  # samples required before adaptive limiting acts
std_dev_multiplier = 3.0            # requests > mean + N*stddev counts as an anomaly

# Per-route limits are keyed by route name and carry their own [.limits] table.
[advanced_rate_limiting.route_limits.login]
pattern = "/api/method/login"

[advanced_rate_limiting.route_limits.login.limits]
requests_per_second = 2
burst_size = 5
requests_per_minute = 20
requests_per_hour = 100
```

**Key Features:**
- **Composite Keys**: Combine IP + JA3 fingerprint + path for fine-grained limiting
- **JA3/JA4 Fingerprinting**: Identify clients behind NAT by TLS handshake signature, on TCP and QUIC alike
- **JWT Subject Extraction**: Rate limit by authenticated user, not just IP
- **X-Forwarded-For Trust Chain**: `trusted_proxies` lists the hops whose XFF header is honoured when deriving the client IP
- **IPv6 Subnet Grouping**: `ipv6_subnet_bits` groups /64 subnets to prevent per-host evasion
- **Adaptive Baseline**: profiles normal traffic over `baseline_window_secs` and flags requests beyond `std_dev_multiplier` standard deviations
- **Layered Limits**: Global → Route → Client hierarchy for defense in depth

#### Adaptive: `sensitivity` and `auto_adjust`

A request is anomalous once its rate exceeds `mean + k * stddev` for its key.
`std_dev_multiplier` is the raw `k`; **`sensitivity`** is the same control
expressed the way an operator thinks about it, and the two compose rather than
compete. The scale is **anchored at the default 0.7**, which yields exactly
`std_dev_multiplier` — so a deployment that leaves `sensitivity` alone behaves
identically to one that had never heard of it:

| `sensitivity` | effective `k` at the 3.0 default | effect |
|---|---|---|
| 0.0 | 10.0 | only gross outliers |
| 0.7 | 3.0 | the default, unchanged |
| 1.0 | 0.25 | floored — maximum sensitivity still needs a real deviation |

**`auto_adjust`** tightens each key's `requests_per_minute` and
`requests_per_hour` toward that key's own learned threshold. The configured
limits are necessarily sized for the busiest plausible caller, so without it
every quiet key carries the loudest key's headroom: an account that normally
makes 5 requests a minute may make 3,000 before anything objects, which is all
the room a credential-stuffing run needs.

Adjustment is **one-directional and bounded**. The configured limit is a ceiling
that is never exceeded and `burst_size` is the floor, so a nearly-idle key
cannot be tightened into limiting its own first legitimate burst. Nothing
happens at all until the key's baseline reaches `min_samples` — a new key is not
throttled for being new. The per-second token bucket is deliberately untouched:
its quota is fixed when the bucket is built, and per-second bursts are what
`burst_size` and the anomaly detector already answer.

### Distributed Rate Limiting (Redis)

By default all rate limit state lives in per-process memory (DashMap). Each proxy instance counts independently, so in a multi-instance deployment one client can consume their full quota on every node.

Enabling the Redis backend makes all per-key counters shared across every instance. The global token bucket stays in-process (one per node, for local DDoS protection); per-IP, per-fingerprint, per-API-key, and per-composite sliding windows move to Redis using atomic Lua scripts.

```toml
[advanced_rate_limiting.redis]
url                  = "redis://127.0.0.1:6379"
key_prefix           = "pqcp"          # Namespace prefix for all Redis keys
connect_timeout_ms   = 2000            # Abort connection attempt after 2 s
command_timeout_ms   = 50             # Per-command timeout; on timeout → silent local fallback
distribute_per_second = true           # Include per-second window in Redis (recommended)
```

**Per-key limit tunables** (all keys in `[advanced_rate_limiting.global_limits.*]`):

```toml
[advanced_rate_limiting.global_limits.per_api_key]
requests_per_second = 500
burst_size          = 250
requests_per_minute = 15000
requests_per_hour   = 250000

[advanced_rate_limiting.global_limits.per_composite]
requests_per_second = 200
burst_size          = 100
requests_per_minute = 6000
requests_per_hour   = 100000
```

**How it works (HTTP/1.1, HTTP/2 via TCP and HTTP/3 via QUIC):**

```
Request arrives on any path
  │
  ├─ [QUIC/HTTP3 only] Simple per-IP SecurityState governor + auto-block
  │   (fast in-process check; increments suspicious_patterns counter and
  │   auto-blocks repeat offenders — runs before the advanced limiter)
  │
  ├─ Advanced rate limiter (ALL paths: TCP HTTP/1.1 + HTTP/2 + QUIC HTTP/3)
  │     │
  │     ├─ Global token-bucket (IN-MEMORY — per-node DDoS protection)
  │     │
  │     ├─ Resolve key (IP / API key / JA3 / JWT / composite)
  │     │
  │     ├─ Redis available?
  │     │    YES → Lua token-bucket  (per-second, distributed, atomic EVAL)
  │     │          Lua fixed-window  (per-minute, distributed, INCR+EXPIRE)
  │     │          Lua fixed-window  (per-hour,   distributed, INCR+EXPIRE)
  │     │          ── any command timeout → local DashMap fallback ──
  │     │    NO  → local DashMap bucket (original behaviour)
  │     │
  │     └─ Adaptive anomaly detection (always local, per-node)
```

**Graceful fallback**: if Redis is unreachable or a command exceeds `command_timeout_ms`, that single request silently falls back to the local in-memory bucket. No error is returned to the client and no exception is thrown. The proxy remains fully functional without Redis.

**Admin API** reports `redis_connected: true/false` in the rate limiter stats snapshot so you can verify the connection is live.

**No Redis = zero behaviour change.** The `[advanced_rate_limiting.redis]` section is optional. Omitting it leaves the proxy running exactly as before with in-memory limiting.

### WAF Configuration

```toml
[waf]
enabled = true
mode = "block"          # "detect" logs only; "block" returns 403
anomaly_threshold = 5   # score at which a request is blocked

# Detection categories
sqli = true             # SQL injection patterns
xss = true              # Cross-site scripting patterns
path_traversal = true   # Traversal and path confusion (../, ..;/, %2e%2e, overlong UTF-8)
nosqli = true           # NoSQL injection ($where, $gt, $regex, etc.)
ssrf = true            # SSRF (metadata IPs Critical; loopback spellings Info — no FP on prose)
cmd_injection = true    # OS command injection, ${IFS}, reverse shells
xxe = true              # XML external entity injection
deserialization = true  # Java/PHP/Python object injection, incl. byte signatures
jndi = true             # JNDI/Log4Shell, OGNL, SpEL expression injection
ssti = true             # Server-side template injection (Jinja, Twig, ERB)
file_inclusion = true   # php://, expect://, phar://, data:// stream wrappers
crlf_injection = true   # Response splitting (URL and headers only)
proto_pollution = true  # __proto__, constructor.prototype
graphql = false         # Schema introspection — off, legitimate for public schemas
request_anomaly = true  # Request smuggling, header injection, diagnostic methods
scanner_probe = true    # Reconnaissance probe paths (.git, .env, wp-login, …)
block_scanner_uas = true

# Inspection surface
scan_json_body = true         # Scan bodies, decoding JSON string escapes
max_body_scan_bytes = 65536   # Max bytes of body to scan (default 64 KB)
scan_all_headers = true       # Every header except negotiation/cache/hints/credentials
max_header_scan_bytes = 8192  # Max bytes of any single header value
max_header_count = 80         # Header count above which a request is anomalous
max_decode_passes = 3         # Percent-decode passes before matching

custom_patterns = [
    "(?i)\\bmy-banned-keyword\\b",
]
```

**Anomaly scoring.** A rule match contributes its severity's score — Low 3,
Medium 5, High 8, Critical 10 — and the request is blocked once the total
reaches `anomaly_threshold`. At the default of 5 any single Medium-or-higher
rule blocks on its own, while two Low-severity signals must agree. Low is where
genuinely ambiguous patterns live: `localhost` in a URL parameter, a bare
`exec(`, a backtick pair. Raise the threshold to demand more corroboration,
lower it to act on single weak signals. A match below the threshold is still
counted in the per-rule metrics, so a rule can be evaluated before it is trusted
to block.

**Rule identifiers.** Every rule has a stable identifier of the form
`PQW-<CATEGORY>-<NNN>`, and verdicts are reported as `category:identifier` —
`bad-bot-ua:PQW-BOT-001`, `sqli:PQW-SQLI-011`. Identifiers are stable across
pattern edits and across category toggles: switching a category off keeps its
rules' metric series in place rather than renumbering everything after them.

**Decoding.** Inputs are matched raw and in every decoded form: percent-decoding
is applied repeatedly to a fixpoint (`max_decode_passes`), plus form decoding
(`+` → space), HTML character references (`&#x3c;`), JSON string escapes
(`\u003c`), IIS-style `%uXXXX` escapes, and Unicode fullwidth folding
(`\uff1cscript\uff1e` → `<script>`). A rule that matches several decoded forms of the same input counts
once. Bodies are decoded lossily and are always inspected, whether or not they
are valid UTF-8; binary bodies are additionally matched against byte signatures
(Java serialisation header, Python pickle opcodes) that no textual decoding
could preserve.

**Transport parity.** The WAF runs identically over HTTP/1.1, HTTP/2, HTTP/3
and WebTransport. The TCP and QUIC/h3 handlers both call the one
`SecurityState::evaluate` (and `inspect_body` once the body is buffered), so
path, query, header and **body** inspection are the same on every transport; a
regression corpus is run over both `--transport auto` (h1/h2) and
`--transport h3` to prove that parity, not assume it. WebTransport stream and
datagram payloads are proxied to the same backends as HTTP requests, so they run
through the same `inspect_body` before reaching a backend — a WebTransport
session is not an uninspected path to `/encrypt` and friends.

**Compressed bodies.** A `Content-Encoding: gzip|deflate|br|zstd` request body
is decompressed (bounded by `max_decompressed_body_bytes`, so a decompression
bomb cannot exhaust memory) and the decompressed form is scanned — otherwise a
compressed payload is entropy to the pattern engine and passes. The raw
compressed bytes are never text-scanned (they trip binary-ish rules), only
matched against the binary deserialization signatures.

**Request anomalies.** `request_anomaly` covers what no regex can express:
conflicting `Content-Length` headers and `Content-Length` beside
`Transfer-Encoding` (request smuggling), transfer codings other than `chunked`,
control characters in header values, `TRACE`/`TRACK`/`DEBUG`, excessive header
counts, and a `Host` containing a path, space or userinfo marker.

**Per-path exclusions.** Tune a false positive without switching a category off
site-wide:

```toml
[[waf.exclusions]]
path = "^/regex/"          # regex matched against the request path
categories = ["xss"]       # whole categories to suppress

[[waf.exclusions]]
path = "^/api/graphql"
rules = ["PQW-NOSQL-001"]  # or individual rule identifiers
```

**Metrics.** The Prometheus endpoint exports `pqcrypta_waf_requests_total`,
`pqcrypta_waf_allowed_total`, `pqcrypta_waf_blocked_total`,
`pqcrypta_waf_detected_total`, and `pqcrypta_waf_rule_hits_total` labelled by
`rule`, `category` and `severity`. Only rules that have actually matched are
emitted, so the series count tracks the traffic this node sees rather than the
full rule table.

`block_scanner_uas` matches against a built-in regex set covering common attack tools. It operates independently from path/payload pattern matching — a request can be blocked purely by its User-Agent even if the body is clean. Disable per-route via `waf_mode = "detect"` if you need to allow scanner tools from specific paths (e.g., an internal security tooling endpoint).

The scanner-UA check also matches the default `curl/N` and `Wget/N` User-Agents, which are the expected clients for public binary-download endpoints (e.g. install scripts distributed as `curl -o file https://.../stream/downloads/...`). Paths under `/stream/downloads/` are hard-exempted from this specific check (same mechanism as the `X-Health-Check-Bypass` header) so documented `curl`/`wget` install commands aren't blocked — injection and path-traversal scanning still runs on these paths.

A route can declare the same exemption rather than relying on the built-in path prefix: `skip_bot_blocking = true` on a `[[routes]]` entry turns off the scanner/bot User-Agent check for that route only, on both the TCP and HTTP/3 paths. Prefer it over adding hardcoded prefixes.

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

Per-route policy is resolved before the security checks run, so all of it
applies on both transports. The WAF and rate limiter sit in front of routing, so
the security layer resolves the route itself through the same `find_route` the
proxy uses downstream — which is what makes `[routes.security]` and
`skip_bot_blocking` take effect at all.

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

### Connection Pool Configuration

Controls the HTTP/1.1 connection pool used for requests to backends over TCP. All fields are optional — defaults are production-ready for moderate traffic.

```toml
[connection_pool]
idle_timeout_secs        = 90    # Close idle connections after 90 s
max_idle_per_host        = 10    # Keep up to 10 idle connections per backend
max_connections_per_host = 100   # Limit for backends that do not set their own max_connections.
                                 # NOT a ceiling over an explicit per-backend value — several
                                 # backends are deliberately configured above this figure.
acquire_timeout_ms       = 5000  # Fail the request if a connection can't be acquired in 5 s.
                                 # Unbounded waiting turns a backend stall into a proxy-wide stall.
```

Reducing `max_idle_per_host` lowers file-descriptor usage on backends with many idle periods. Increasing `max_connections_per_host` improves burst throughput at the cost of backend fd pressure.

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
timeout_ms = 30000     # Bounds the forwarded request; on expiry the client gets 504 Gateway Timeout
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

### Canary / Percentage Traffic Splitting

Canary routing lets you ship a new server version to a small percentage of traffic while stable servers handle the rest. The configuration lives in a `[backend_pools.NAME.canary]` subsection placed **before** the first `[[NAME.servers]]` entry. Canary routing is active on **all transport protocols**: HTTP/1.1, HTTP/2, and HTTP/3/QUIC.

```toml
# Pool-level canary settings — place before [[servers]] entries
[backend_pools.api-pool.canary]
enabled                = true               # activate canary routing
sticky                 = true               # keep each client on the same canary
sticky_cookie_name     = "PQCPROXY_CANARY"  # cookie set on first canary assignment
sticky_cookie_ttl_secs = 3600              # sticky assignment lifetime (seconds)
sticky_header          = "X-Canary-Group"  # optional: pre-assign group via request header
auto_rollback          = true              # suspend canary on high error rate
rollback_error_rate    = 0.05             # error rate threshold (5 %)
rollback_window_secs   = 60              # sliding window length (seconds)
rollback_min_requests  = 10             # minimum requests before rollback can trigger

# Canary server — mark with canary = true, set canary_weight_percent
[[backend_pools.api-pool.servers]]
address               = "127.0.0.1:3005"
canary                = true             # designate as canary
canary_weight_percent = 5                # route 5 % of new traffic here
weight                = 100
priority              = 1
max_connections       = 100
timeout_ms            = 30000
tls_mode              = "terminate"

# Stable server — receives remaining 95 % of traffic
[[backend_pools.api-pool.servers]]
address = "127.0.0.1:3003"
weight  = 100
priority = 1
max_connections = 100
timeout_ms = 30000
tls_mode = "terminate"
```

**How it works:**
1. A request arrives. If it carries a `PQCPROXY_CANARY` cookie matching a live canary server, it is routed there (sticky assignment).
2. Otherwise, a random roll (0–99) is compared against `canary_weight_percent`. If the roll is lower, the request goes to the canary and a `Set-Cookie` header is added to the response for future stickiness.
3. If `auto_rollback = true` and the canary's error count within the sliding window exceeds `rollback_error_rate × requests`, the canary is suspended and all traffic falls back to stable servers.

**Live admin control** (all endpoints require Bearer token auth):

```
GET  /canary                     — current status of every canary server across all pools
POST /canary/suspend/:server_id  — suspend a canary immediately
POST /canary/resume/:server_id   — re-enable a suspended canary (resets error window)
POST /canary/weight/:server_id   — adjust weight at runtime
                                   body: {"percent": 10}
```

Example:
```bash
curl -s http://127.0.0.1:8082/canary \
     -H "Authorization: Bearer <token>"
# {"pools":[{"pool":"api-pool","servers":[{"id":"127.0.0.1:3005","is_canary":true,
#   "canary_weight_percent":5,"suspended":false,"error_rate":0.0,...}]}]}
```

### Traffic Shadowing / Mirroring

Add a `[routes.shadow]` subsection to any route to mirror traffic to a secondary backend. The client only receives the primary response; the shadow response is logged and discarded. All values are configurable — nothing is hardcoded. Shadow mirroring is active on **all transport protocols**: HTTP/1.1, HTTP/2, and HTTP/3/QUIC.

```toml
[[routes]]
name    = "api-route"
host    = "api.example.com"
backend = "api-stable"

# Mirror 10 % of traffic to a canary instance for dark testing
[routes.shadow]
backend             = "api-canary"      # Must be a key in [backends.*]
percent             = 10                # 0–100 % of requests to mirror (default 100)
timeout_ms          = 5000              # Abandon shadow after this many ms (default 5000)
shadow_header       = "X-Shadow-Request"   # Header injected on shadow requests (default)
shadow_header_value = "1"              # Value for that header (default "1")
log_responses       = true             # Log shadow status + latency at INFO (default true)
```

**How it works:**

1. Request arrives → body is buffered (only when shadow is configured).
2. A `tokio::task::spawn` fires the shadow copy asynchronously — the primary forward proceeds in parallel.
3. The primary response is returned to the client immediately; the spawned task runs independently.
4. The shadow backend receives an identical request with the configurable marker header appended so it can distinguish mirror traffic.
5. Shadow errors, timeouts, and 5xx responses are logged as warnings but never affect the client.

**Activating on the running config:**

1. Add a `[backends.api-canary]` entry pointing at the canary instance (e.g. `127.0.0.1:3004`).
2. Add the `[routes.shadow]` block to the desired route in `/etc/pqcrypta/proxy-config.toml`.
3. Reload config: `curl -s -X POST http://127.0.0.1:8082/reload -H "Authorization: Bearer $TOKEN"`.

### Response Cache Configuration

The proxy includes an RFC 9111-compliant HTTP response cache. It is **disabled by default** — add a `[cache]` section to opt in. The cache stores raw backend response bodies (pre-compression); all outer middleware layers (security headers, Alt-Svc, Brotli/gzip) run on every served response, including cache hits.

**What is cached**: GET and HEAD responses with a cacheable status code (200, 203, 204, 206, 300, 301, 410) that carry `Cache-Control: public` or no `Cache-Control` directive. Responses with `Cache-Control: no-store`, `private`, `no-cache`, or `Vary: *` are never stored. Responses that set cookies are skipped by default.

**Conditional request support**: ETag / `If-None-Match` (strong and weak) and `Last-Modified` / `If-Modified-Since` — the cache returns `304 Not Modified` and avoids body transfer when content is unchanged.

```toml
[cache]
enabled              = true    # default false — must opt in
max_size_mb          = 128     # total cache size cap in MiB
default_ttl_secs     = 60      # TTL when backend sends no Cache-Control max-age
max_body_size_bytes  = 2097152 # responses larger than ~2 MiB are forwarded but not stored
no_cache_set_cookie  = true    # skip caching responses that set cookies

# Path prefixes that bypass the cache entirely
excluded_paths = ["/api/", "/ws", "/stream", "/auth", "/admin"]

# Exact hostnames (or subdomain suffixes) whose responses are never cached.
# Use this for API subdomains whose backends omit Cache-Control: no-store.
excluded_hosts = ["api.example.com"]
```

The cache layer is placed as the innermost Axum layer so security headers and compression always apply regardless of whether the response came from the cache or the backend.

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
├── waf.rs               # WAF engine — 256-rule RegexSet, PQW-* IDs, anomaly scoring, multi-pass decoding, per-rule metrics; enforced on TCP, HTTP/3 and WebTransport (A01/A03/A06/A08/A10)
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

### ML-DSA-87 Server Certificates (FIPS 204)

With the default `pqc-signatures` feature, the SNI certificate resolver serves **ML-DSA-87-signed X.509 certificates** for domains whose key file contains an ML-DSA-87 PKCS#8 private key (OID `2.16.840.1.101.3.4.3.19`). Drop `{domain}.crt` (full PQ chain) and `{domain}.key` into the certs directory alongside the classical pairs — detection is automatic per domain, on the same TCP :443 and QUIC listeners.

- The TLS 1.3 `CertificateVerify` is signed with ML-DSA-87 (TLS signature scheme `mldsa87`, codepoint `0x0906`) via aws-lc-rs
- All three PKCS#8 CHOICE encodings from draft-ietf-lamps-dilithium-certificates are accepted: `seed [0]`, `expandedKey`, and the seed+expanded `both` form OpenSSL 3.5 writes
- Clients that do not offer `mldsa87` in `signature_algorithms` are refused (no silent classical fallback on that SNI)
- Combined with `-groups X25519MLKEM768` this yields a fully post-quantum handshake: PQ key exchange + PQ certificate signature

```bash
# Connect with OpenSSL 3.5+
openssl s_client -connect pqc.pqcrypta.com:443 -sigalgs mldsa87 \
    -groups X25519MLKEM768 -CAfile root-ca.crt
```

### Configuration

```toml
[pqc]
enabled = true
provider = "openssl3.5"
openssl_path = "/usr/local/openssl-pq/bin/openssl"
openssl_lib_path = "/usr/local/openssl-pq/lib64"
preferred_kem = "X25519MLKEM768"
fallback_to_classical = true
```

> **Important**: `openssl_path` must point to an OpenSSL 3.5+ binary built with ML-KEM support. The proxy checks this path at startup to determine whether the PQC TCP listener is available. If the path is wrong or the binary is missing, the proxy silently falls back to a standard rustls listener that accepts TLS 1.2 and does not negotiate X25519MLKEM768. Always verify the path exists before deploying.

## ACME Certificate Automation

Automatic Let's Encrypt certificate provisioning and renewal. Issues one **individual certificate per domain** — each domain gets its own `{domain}.crt` / `{domain}.key` pair written atomically (write-to-`.tmp`-then-rename) to prevent corruption on concurrent renewal. Uses ECDSA P-256 keys for smaller certs and faster TLS handshakes.

SNI-based cert selection is handled by `MultiDomainCertResolver` (rustls/QUIC) and `create_pqc_acceptor_with_sni` (OpenSSL/TCP), both loading all cert pairs from the certs directory at startup and on every ACME renewal.

### How It Works

1. **Daily check** reads each domain's cert file to check expiry (zero network cost)
2. **Renewal triggers** per-domain when cert is within 30 days of expiry (~day 60 of 90-day cert)
3. **ACME protocol** runs only during actual renewal (~once every 60 days per domain)
4. **HTTP-01 challenges** served on port 80 before HTTPS redirect kicks in
5. **Exponential backoff** on challenge polling (2s → 4s → 8s → 16s cap)
6. **Hot reload** — ACME notifies the TLS provider immediately after each cert is written; no restart required

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

## Telemetry Wall

The Telemetry Wall is a native WebTransport handler at `/telemetry` (default `wss://api.pqcrypta.com:4433/telemetry`) that streams real-time transport-layer data without any backend involvement.

### What it demonstrates

QUIC's key advantage over TCP is that stream-level impairment on one stream does **not** affect other streams. The Telemetry Wall makes this concrete: impair channel `ch3` and watch channels `ch1`, `ch2`, `ch4`, `ch5`, `ch6` continue uninterrupted. The equivalent on HTTP/2 or WebSocket over TCP would stall all streams.

### Session structure

| Stream | Type | Rate | Content |
|--------|------|------|---------|
| `ch1`–`ch6` | Server uni-streams | 20 Hz | Throughput frames (~32 KB virtual per frame ≈ 5 Mbps per channel) |
| Stats | Server uni-stream | 10 Hz | RTT, CWND, CPU %, memory %, uptime |
| Control | Bidi-stream | Client-driven | Impairment and heal commands |
| Datagrams | — | Echo | RTT and packet-loss measurement |

Session idle timeout: 5 minutes. Hard cap: 60 minutes.

### Wire protocol

All stream frames use a 4-byte big-endian length prefix followed by JSON:

```
[u32 BE length][JSON bytes]
```

**Channel header** (first frame on each uni-stream):
```json
{"stream_type":"channel_header","channel":"ch1","rate_hz":20}
```

**Throughput frame**:
```json
{"t":1234567.890,"seq":42,"channel":"ch1","bytes_total":1048576,"impaired":false,"impairment":null}
```

**Stats frame**:
```json
{"t":1234567.890,"rtt_ms":23.5,"cwnd_bytes":1250000,"cpu_pct":8.3,"mem_pct":42.1,"uptime_s":86400}
```

### Impairment commands (client → server on control bidi-stream)

```json
{"cmd":"impair","channel":"ch3","type":"delay_ms","intensity":200.0,
 "pattern":"burst","burst_freq_s":5.0,"burst_dur_ms":500.0,"duration_s":30.0}

{"cmd":"heal","channel":"ch3"}
{"cmd":"heal_all"}
```

**Impairment types**: `delay_ms`, `loss_pct`, `bandwidth_kbps`, `jitter_ms`, `disconnect`

**Patterns**: `constant`, `burst` (periodic spike), `random`

Server acknowledges each command:
```json
{"type":"ack","cmd":"impair","channel":"ch3","ok":true}
```

---

## Speed Test

The speed test handler at `/speedtest` (`wss://api.pqcrypta.com:4433/speedtest`) provides a side-by-side QUIC vs TCP throughput comparison from the same server.

### How the QUIC vs TCP comparison works

The proxy has two config options that together enable independent TCP and QUIC measurements in the browser:

- `tcp_only_hosts` in `[server]`: listed hostnames get `Alt-Svc: clear`, evicting any cached QUIC upgrade so the browser stays on TCP/TLS.
- `http11_only_hosts` in `[server]`: listed hostnames suppress the `h2` ALPN token, forcing HTTP/1.1. The browser then opens one TCP connection per `fetch()` stream instead of coalescing onto an HTTP/2 pipe — giving each parallel speed test stream its own TCP flow.

The QUIC path uses WebTransport streams natively; the TCP path uses HTTP/1.1 connections to the same backend. Both paths hit the same server, measuring the protocol itself rather than network distance.

### Operations (JSON over length-prefixed frames)

| Operation | Client sends | Server sends |
|-----------|-------------|--------------|
| `download` | `{"op":"download","bytes":N}` | 1-byte status + N raw bytes |
| `upload` | `{"op":"upload","bytes":N}` + N raw bytes | `{"bytes_received":M,"duration_ms":D,"throughput_mbps":T}` |
| `info` | `{"op":"info"}` | Server capabilities JSON |
| `geoip` | `{"op":"geoip"}` | Client IP, city, country, ASN |
| `traceroute` | `{"op":"traceroute"}` | Stream of hop frames with per-hop GeoIP, then `{"type":"done"}` |

**Datagram echo**: any datagram ≥ 8 bytes is echoed immediately. Client embeds a send timestamp in the payload to compute RTT and count loss.

### Limits

| Parameter | Value |
|-----------|-------|
| Max download | 1 GB (client time-limits to 5–10 s in practice) |
| Max upload | 500 MB |
| Download chunk | 256 KB (keeps QUIC send buffer full) |
| Session idle timeout | 5 minutes |
| Session hard cap | 30 minutes |

---

## Examples

### `masque-client` — a MASQUE (RFC 9298) reference client

```bash
cargo run --example masque-client -- <relay:port> <target:port> <name>
cargo run --example masque-client -- pqcrypta.com:443 1.1.1.1:53 example.com
```

Opens an HTTP/3 connection, sends an Extended CONNECT with `:protocol = connect-udp`,
and relays one DNS query to the target resolver as an HTTP Datagram. Written to be read:
it is the shortest complete demonstration of the CONNECT-UDP flow, including the
quarter-stream-ID framing that RFC 9297 uses to bind a connection-global datagram back to
its request stream.

Three things it gets right that are easy to get wrong:

1. **The CONNECT stream is not finished.** The stream *is* the session; closing the send
   side tells the relay to tear the UDP socket down, and datagrams then vanish silently
   with a 200 OK already in hand.
2. **Both `SETTINGS_H3_DATAGRAM` and `SETTINGS_ENABLE_CONNECT_PROTOCOL` are negotiated.**
   Separate settings; without the second, `:protocol` is not legal on the request.
3. **Inbound datagrams are filtered by quarter stream ID.** Every datagram on the
   connection reaches every reader.

A standalone copy that builds against upstream `quinn`/`h3` rather than the vendored noq
forks is published at <https://pqcrypta.com/masque/>, for people who want the client
without the proxy.

## Pentest Suite

The `pentests/` directory contains 32 automated black-box attack scripts across 12 phases, used to continuously validate pqcrypta-proxy's security posture. No source access is required — all scripts target the public HTTP surface.

### Quick start

```bash
cd pqcrypta-proxy/pentests
cp config.demo.sh config.sh
vi config.sh   # set TARGET and API_TARGET at minimum

./preflight.sh             # check required tools
./run_all.sh               # all 32 scripts
./run_all.sh --skip-slow   # skip TLS deep-scan and resilience/chaos
./run_all.sh --local        # tighter timing thresholds (LAN / same datacenter)
./run_all.sh --phase 5     # single phase
```

### Phase map

| Phase | Scripts | Attack category |
|-------|---------|-----------------|
| 1 | 14 | Reconnaissance & information disclosure |
| 2 | 01, 12 | WAF bypass & advanced evasion |
| 3 | 02, 03 | Bot detection bypass, header injection |
| 4 | 07, 06, 13 | HTTP smuggling (1.1/2/3/WebTransport), TLS/SSL, WebSocket |
| 5 | 08, 09, 05, 10, 11, 04 | SSRF, cache poisoning, API auth, crypto fuzzing, timing oracles, rate limiting |
| 6 | 15, 19, 20 | Auth hardening, session security, MFA bypass, access control |
| 7 | 16, 17, 23 | Business logic, race conditions, CSP, client-side JS |
| 8 | 21, 22, 18 | Supply chain, cloud/infra, resilience & chaos |
| 9 | 24 | Data privacy & PII exposure |
| 10 | 25, 26, 27 | Container/K8s runtime, CI/CD pipeline, database & storage |
| 11 | 28 | AI / LLM attack surface (prompt injection, context bleed) |
| 12 | 29, 30, 31, 32 | XXE, SSTI, file upload, gRPC/Protobuf |

### Protocol coverage

| Protocol | Coverage |
|----------|----------|
| HTTP/1.1 | CL.TE and TE.CL smuggling via raw `nc`, all WAF / auth / API tests |
| HTTP/2 | TE rejection (RFC 9113 §8.2.2), Rapid Reset (CVE-2023-44487), all API tests |
| HTTP/3 / QUIC | `curl --http3` with Alt-Svc fallback detection; WAF and rate-limit tests |
| WebTransport | TCP probe on `QUIC_PORT`, HTTP/3 QUIC framing |
| WebSocket | RFC 6455 upgrade, auth bypass, token-in-query-string, RFC 8441 H2 WS |

### Pentest bypass IP

Add your test runner IP to `pentest_bypass_ips` in `[security]` to skip rate-limiting and auto-block **without disabling the WAF**:

```toml
[security]
# Remove after the engagement ends.
pentest_bypass_ips = ["YOUR.RUNNER.IP.HERE"]
```

Effect: rate limiting and auto-block are disabled for listed IPs (preventing mid-run lockout), but the WAF still executes — attack payloads still return 403, confirming WAF detection is working. Script 04 (rate limiting) needs a non-bypassed IP to test the limiter itself.

### Output

Each run writes to `results/run_YYYYMMDD_HHMMSS/`:

```
results/run_20260522_153000/
├── MASTER_REPORT.txt     # full concatenated output
├── SUMMARY.tsv           # machine-readable: phase<TAB>script<TAB>name<TAB>status<TAB>findings<TAB>warns<TAB>duration_s
├── 01_waf_bypass.txt
├── 07_advanced_smuggling.txt
└── ...
```

| Exit code | Meaning |
|-----------|---------|
| `0` | All scripts passed — no findings, no warnings |
| `1` | At least one `[WARN]` or `[VULN]` finding |
| `2` | One or more scripts failed with an execution error |
| `3` | Preflight check failed or `scope_guard.sh` refused the target |

### Timing oracle methodology (script 11)

50 samples per test group, `python3 statistics.mean` + `pstdev` per group, alert threshold 3σ above baseline mean. Minimum floor: 15 ms remote, 3 ms with `--local`. Tests: API key oracle, admin login timing, decrypt padding oracle, WAF timing side-channel.

### Required tools

`bash 5.0+`, `curl`, `python3`, `openssl`, `nc`, `dig`, `jq`. Optional: `hey` (race conditions), `websocat` (WebSocket), `grpcurl` (gRPC), `testssl.sh` (TLS deep-scan), `nikto` (web scan).

---

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

## OpenTelemetry Distributed Tracing

PQCrypta Proxy supports end-to-end distributed tracing via the OpenTelemetry SDK. When enabled, every HTTP request creates a span that is stitched into the incoming trace (if one is present) and propagated to upstream backends.

### Propagation Formats

| Format | Headers | Notes |
|--------|---------|-------|
| W3C TraceContext (RFC 9543) | `traceparent`, `tracestate` | Extracted first; highest priority |
| B3 Multi-header | `x-b3-traceid`, `x-b3-spanid`, `x-b3-sampled` | Fallback extract; always injected |
| B3 Single-header | `b3` | `{traceId}-{spanId}-{flag}` compact form; also injected |

Both W3C and B3 formats are injected into every upstream request so Jaeger, Zipkin, Tempo, and W3C-compatible backends can all correlate traces from a single proxy deployment.

### Transport Coverage

Trace context extraction and injection is active on **all four transports**:
- **HTTP/1.1 + HTTP/2** — axum `trace_context_middleware` extracts from `HeaderMap` before the first handler runs
- **HTTP/3 / QUIC** — extracted from the incoming H3 header map before any routing
- **WebTransport** — same QUIC path; context propagated into backend requests
- **Backend requests** — `inject_current_context_into_map()` stamps both formats into every proxied request

### Configuration

```toml
[otel]
# Enable distributed tracing (disabled by default)
enabled = true

# Service name reported in spans and to the collector
service_name = "pqcrypta-proxy"

# OTLP HTTP/JSON endpoint — works with Jaeger, Grafana Tempo,
# OpenTelemetry Collector, Honeycomb, Lightstep, etc.
otlp_endpoint = "http://localhost:4318"

# Sampling ratio: 1.0 = always, 0.0 = never, 0.1 = 10% of root spans
# Uses ParentBased(TraceIdRatioBased) — child spans inherit parent decision
sample_ratio = 1.0

# Optional resource attributes added to every exported span
# [otel.resource_attributes]
# deployment.environment = "production"
# host.name = "proxy-1"
```

### Access Log Correlation

When tracing is active, every access-log line includes a `trace_id=<hex>` field so log entries can be looked up directly in Jaeger or Tempo:

```
203.0.113.42 - - [02/Mar/2026:14:23:01 +0000] "GET /api/v1/users HTTP/3" 200 1542 "-" "curl/8.5.0" host="api.pqcrypta.com" time=18ms trace_id=4bf92f3577b34da6a3ce929d0e0e4736
```

### Span Export

Spans are batched and exported asynchronously via OTLP HTTP/JSON (no protobuf dependency — uses the existing `reqwest` client). The global tracer provider is a NOOP until `init_otel()` is called after config loads, so startup spans are silently dropped; all request-handling spans are fully exported. On graceful shutdown, the batch queue is flushed before the process exits.

## Deployment

### Fleet deploy (build-verified)

`scripts/deploy.sh` builds the release binary, records its sha256, deploys to
every proxy node, and verifies each node is running that exact hash with the
service active. It always builds first: `cargo test` and `cargo clippy` do not
produce the release binary, so copying `target/release/pqcrypta-proxy` after
only those can ship a stale build — this script closes that gap.

```bash
scripts/deploy.sh              # build + deploy all nodes + verify hashes
scripts/deploy.sh --local-only # this node only
scripts/deploy.sh --gate       # also run the post-deploy WAF regression gate
```

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

- [x] TLS 1.3 minimum by default (configurable via `min_version`; applies to both TCP/TLS via OpenSSL 3.5+ and QUIC/HTTP3 via rustls)
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
- [x] WAF (pattern-based injection and traversal detection: SQLi, XSS, path traversal, NoSQLi, SSRF, CMDi, XXE, deserialization; covers OWASP A01/A03/A08/A10; detect/block modes; custom patterns)
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
