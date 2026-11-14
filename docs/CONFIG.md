# PQCrypta Proxy Configuration Reference

Complete reference for all configuration options in PQCrypta Proxy.

**Version**: 0.1.0
**Last Updated**: 2026-01-24

---

## Table of Contents

- [Server Configuration](#server-configuration)
- [MASQUE / CONNECT-UDP](#masque--connect-udp-rfc-9298)
- [HTTP/3 Advanced Features](#http3-advanced-features)
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
| `max_connections` | u32 | `10000` | Maximum concurrent client connections across every listener (TCP, QUIC, WebTransport); a connection past it is refused. `0` = no limit |
| `max_streams_per_connection` | u32 | `1000` | Maximum concurrent streams per connection |
| `keepalive_interval_secs` | u64 | `15` | How often the QUIC listener sends a keep-alive PING, in seconds, so a NAT keeps the path of a connection with a session or tunnel open; an idle connection is still closed after `max_idle_timeout_secs` |
| `max_idle_timeout_secs` | u64 | `120` | How long a connection may be idle, in seconds: the QUIC idle timeout; the time a TCP or HTTP/3 connection may have no exchange, session or tunnel in flight before it is closed (HTTP/3 with GOAWAY first); and how long a request's header block may take to arrive, on both |
| `enable_ipv6` | bool | `true` | Enable IPv6 dual-stack binding |
| `worker_threads` | usize | `0` | Worker threads (0 = auto-detect based on CPU cores) |
| `enable_quic_migration` | bool | `true` | Enable QUIC connection migration (RFC 9000 §9) |
| `enable_ack_frequency` | bool | `true` | Enable the QUIC ACK Frequency extension (draft-ietf-quic-ack-frequency) — fewer, batched ACKs on high-throughput connections |
| `ack_eliciting_threshold` | u64 | `1` | Ack-eliciting QUIC packets accepted before an ACK-only packet is sent (1 = every other packet, RFC 9000). Below it, owed ACKs ride on outgoing packets when `ack_piggyback` is on; 0 acknowledges every packet immediately |
| `ack_piggyback` | bool | `true` | Carry owed QUIC ACKs on any packet already being sent, so a response acknowledges the request it answers rather than the ACK waiting out `max_ack_delay` (25 ms) |
| `quic_send_coalescing` | bool | `true` | The QUIC connection driver yields past the runtime's next I/O poll before transmitting, so responses that finish together leave in one transmit (measured 2.08 → ~1.3 datagrams per request at 100 connections) |

---

## MASQUE / CONNECT-UDP (RFC 9298)

```toml
[masque]
```

UDP proxying over HTTP/3 Extended CONNECT. The proxy accepts requests with
`:protocol = connect-udp` and relays UDP datagrams between the client and a
target `host:port`, with UDP payloads carried as HTTP Datagrams (RFC 9297).

**Disabled by default.** An open UDP relay can be abused for amplification,
scanning, and exfiltration, so a target MUST match `allowed_targets` before a
session is established. A CONNECT-UDP request is also held to the rules every
other request meets (the blocklist, the location rules, the rate limits and
the WAF) and is written to the access log.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for CONNECT-UDP |
| `allowed_targets` | array[string] | `[]` | Permitted targets as `host:port`; `host`/`port` may be `*`. Empty = deny all |
| `session_idle_timeout_secs` | u64 | `60` | Close a session after no datagrams in either direction for this long |
| `max_sessions_per_connection` | usize | `8` | Maximum concurrent CONNECT-UDP sessions per QUIC connection |
| `allowed_clients` | array[string] | `[]` | Clients a session is relayed for: addresses, CIDR networks, or host names (resolved through `security.host_resolver`, as in `pentest_bypass_ips`). Empty = any client |
| `private_target_clients` | array[string] | `[]` | Clients a session is relayed for when its target is on this host or a private network (loopback, RFC 1918, link-local, unique local), written as `allowed_clients` is. Empty = no client: such a target is relayed for nobody, whatever `allowed_targets` lists |

---

## DNS over HTTPS

```toml
[doh]
```

DNS over HTTPS (RFC 8484) for an authoritative name server on the same host.
The proxy runs a gateway on a loopback address. A backend of type `http1`
points at that address, and routes send DoH requests there like any other
request. The gateway then gets HTTP/2, HTTP/3, post-quantum key exchange, ECH,
rate limits and the access log from the proxy, and asks the name server over
TCP (RFC 7766).

The gateway accepts GET and HEAD with the base64url `dns` parameter, and POST
with an `application/dns-message` body. It returns the name server's answer
with `Cache-Control: max-age` set from the answer's TTLs (RFC 8484 §5.1).
When the query carries the EDNS Padding option, the answer is padded to a
multiple of 468 octets (RFC 7830, RFC 8467 §4.1). Only standard queries reach
the name server. Zone transfers and every other opcode are answered with
REFUSED and Extended DNS Error 21, "Not Supported" (RFC 8914).

**Disabled by default.** Changes take effect on restart.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Run the gateway |
| `listen` | string | `"127.0.0.1:8053"` | Gateway address, `ip:port`. Must be loopback: the gateway applies no limits of its own, so a client must reach it only through a route |
| `upstream` | string | `"127.0.0.1:53"` | The name server, `ip:port`, asked over TCP |
| `path` | string | `"/dns-query"` | The URI template path, `{path}{?dns}` |
| `timeout_ms` | u64 | `3000` | Time allowed for the name server's answer; past it the client gets 504 |

A route for it (see the example config):

```toml
[backends.doh]
name = "doh"
type = "http1"
address = "127.0.0.1:8053"

[[routes]]
name = "doh"
host = "ns1.example.com"
path_exact = "/dns-query"
backend = "doh"
allow_http11 = true        # RFC 8484 recommends HTTP/2 but does not require it
skip_bot_blocking = true   # DNS clients, not browsers: user-agent rules do not apply
priority = 1

[routes.security]
waf_enabled = false        # base64url DNS messages are not form input
```

Also add `path` to `[cache] excluded_paths`: an authoritative answer must come
from the zone as it stands, not from a cached copy.

---

## HTTP/3 Advanced Features

```toml
[http3]
```

Optional HTTP/3 optimizations layered on the QUIC listener. All settings
hot-reload at runtime — editing this section applies on the next request with no
restart. The proxy advertises **QUIC v1 (RFC 9000) only** in Version Negotiation;
it does not offer the obsolete `draft-29..34` versions.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `early_hints_enabled` | bool | `true` | Send `103 Early Hints` (for `GET`/`HEAD`) when preconnect/preload rules match |
| `priority_hints_enabled` | bool | `true` | Honour RFC 9218 Extensible Priorities |
| `coalescing_enabled` | bool | `true` | Deduplicate identical in-flight requests |
| `preconnect_origins` | array[string] | `[]` | Origins added to every 103 response as `<origin>; rel=preconnect` (global, all hosts) |
| `coalescing_max_wait_ms` | u64 | `100` | Max time a coalesced request waits for the in-flight leader |
| `coalescing_max_subscribers` | usize | `100` | Max requests coalesced onto one leader |
| `coalescing_methods` | array[string] | `["GET","HEAD"]` | Methods eligible for coalescing |
| `coalescing_exclude_paths` | array[string] | `["/api/","/ws","/stream"]` | Path prefixes never coalesced |

### Preload Resources (103 Early Hints)

Each `[[http3.preload_resources]]` entry adds a `Link: …; rel=preload` header to
the 103 response for matching requests. A 103 goes only with a page load
(`Sec-Fetch-Dest: document` or `iframe`, or, from a client without Fetch
Metadata, an `Accept` that asks for `text/html`), never with the page's own
stylesheet, script or image fetches, so `path = "/"` does not repeat a page's
hints on every request it makes.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host` | string | optional | Hostname this rule applies to. Omit = all hosts |
| `path` | string | required | Path prefix that triggers the preload (`/` matches every page) |
| `href` | string | required | Resource URL to preload |
| `rel` | string | optional | `preload` (default), `modulepreload`, `preconnect`, `dns-prefetch` or `prerender` |
| `as_type` | string | for `preload` | `as=` attribute: `style`, `script`, `font`, `image`, … |
| `crossorigin` | string | optional | `crossorigin` attribute value (e.g. `anonymous`) |
| `exact` | bool | optional | Match `path` exactly instead of as a prefix (default `false`) |
| `version_file` | path | optional | Absolute path of the file whose mtime is the href's `?v=` cache-buster (`preload` and `modulepreload` only) |

> **Note:** a browser only *uses* a preload whose `href` byte-matches the URL in
> the page HTML — including any `?v=` cache-buster. For a page that versions an
> asset by its modification time (PHP `filemtime`), give the file as
> `version_file` and leave `?v=` out of `href`: the proxy adds `v=<mtime>`, and
> looks at the file again at most every 5 seconds, so the hint follows every
> edit. A pinned `?v=` goes stale with the next one, and the browser then fetches
> the file twice. If the file cannot be read, that hint is not sent.

```toml
[[http3.preload_resources]]
host = "example.com"
path = "/"
exact = true
href = "/css/style.css"
version_file = "/var/www/example/css/style.css"
as_type = "style"
```

---

## TLS Configuration

```toml
[tls]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_path` | path | `"/etc/pqcrypta/cert.pem"` | Path to TLS certificate chain (PEM format) |
| `key_path` | path | `"/etc/pqcrypta/key.pem"` | Path to TLS private key (PEM format) |
| `ca_cert_path` | path? | `null` | The CA that issues client certificates (mTLS). Required whenever a listener asks for one (`require_client_cert`, a route with `mtls_required` or `internal`): client certificates are verified against it and nothing else |
| `require_client_cert` | bool | `false` | Require client certificates (mTLS mode) |
| `alpn_protocols` | array[string] | `["h3", "webtransport"]` | ALPN protocols to advertise |
| `min_version` | string | `"1.3"` | Minimum TLS version. Options: `"1.2"`, `"1.3"` |
| `ocsp_stapling` | bool | `true` | Staple verified OCSP responses (with `[ocsp].enabled`); see the README's OCSP section |
| `cert_reload_interval_secs` | u64 | `3600` | How often the certificates and ECH configs on disk are checked for a change (0 = disabled). A change is a file created, replaced, removed or written in place. A pair is served once its key is the certificate's key; a domain whose files do not load keeps the certificate it is serving |
| `enable_0rtt` | bool | `false` | Enable 0-RTT early data on TCP and QUIC; early requests are served before the handshake completes and gated per route (425 Too Early). **WARNING**: early data can be replayed |
| `zero_rtt_max_early_data` | u32 | `16384` | Early data a TCP session ticket allows when `enable_0rtt` is on (QUIC tickets always carry 0xffffffff) |
| `zero_rtt_replay_protection` | string | `"strict"` | `strict`: refuse a repeated ClientHello; `session`: each ticket carries early data once (RFC 8446 §8.1); `none` |
| `zero_rtt_nonce_window_secs` | u64 | `60` | How long a ClientHello or ticket is remembered for replay protection |
| `handshake_timeout_secs` | u64 | `10` | Seconds a TCP client has to complete its TLS handshake, ClientHello included |

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
| `permissions_policy` | string | `"camera=(), microphone=(), geolocation=(), fullscreen=(self), payment=()"` | Disable browser features |
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
| `required` | bool | `false` | Refuse to start unless an in-memory TLS 1.3 handshake against the proxy's own provider negotiates a post-quantum hybrid at startup; a handshake that cannot be completed counts as a failure |
| `provider` | string | `"auto"` | PQC provider. Options: `"auto"`, `"rustls"`, `"openssl3.5"` |
| `preferred_kem` | string | `"X25519MLKEM768"` | Preferred KEM algorithm |
| `fallback_to_classical` | bool | `true` | Offer the classical groups (P-384, P-256, X25519, one tuple, on every listener) alongside the hybrid PQC groups, so a client without ML-KEM can connect; never under `require_hybrid`. What happens when PQC itself is unavailable is `require_pqc_provider` |
| `require_pqc_provider` | bool | `true` | Refuse to start when `enabled` is true but the PQC provider cannot be used, instead of degrading to a classical-only listener |
| `min_security_level` | u8 | `3` | Minimum NIST security level (1-5) |
| `additional_kems` | array[string] | `[]` | Additional KEMs to enable |
| `experimental_groups` | array[string] | `[]` | Provider groups with no IANA codepoint (OQS: `frodo976shake`, `p384_frodo976shake`, ...), offered over TCP and QUIC after standard ML-KEM and before the classical fallback; hybrids only under `require_hybrid`, on both |
| `enable_signatures` | bool | `true` | Serve ML-DSA-87 (FIPS 204) certificate keys with the PQDSA signer (scheme 0x0906); false refuses such keys, so a host configured with one stops serving rather than falling back. Needs the `pqc-signatures` build feature |
| `downgrade_action` | string | `"log"` | What a connection whose key exchange is classical gets while `enabled` is true: `"allow"` (served), `"log"` (served, recorded in the audit log), `"block"` (every request on it answered 421). Any other value is refused at load |
| `log_downgrades` | bool | `true` | Record classical handshakes in the audit log under `"log"` and `"block"`, once per address in 10 minutes |
| `require_hybrid` | bool | `false` | Offer hybrid groups only (classical + PQC): no pure ML-KEM, no non-hybrid experimental group and no classical fallback, on every listener. A client with neither a hybrid nor PQC support fails the handshake |
| `verify_provider` | bool | `true` | Verify PQC provider at startup |
| `check_key_permissions` | bool | `true` | Check TLS key file permissions |
| `strict_key_permissions` | bool | `false` | Fail if key permissions are too permissive |

### PQC KEM Algorithms

| Algorithm | Security Level | Type | Description |
|-----------|---------------|------|-------------|
| `X25519MLKEM768` | 3 | Hybrid | X25519 + ML-KEM-768 (IETF standard, recommended) |
| `SecP256r1MLKEM768` | 3 | Hybrid | P-256 + ML-KEM-768 (NIST curve) |
| `SecP384r1MLKEM1024` | 5 | Hybrid | P-384 + ML-KEM-1024 (high security) |
| `X448MLKEM1024` | 5 | Hybrid | X448 + ML-KEM-1024 (maximum security) |
| `MLKEM512` | 1 | Pure PQC | ML-KEM-512 (smallest, fastest) |
| `MLKEM768` | 3 | Pure PQC | ML-KEM-768 (balanced) |
| `MLKEM1024` | 5 | Pure PQC | ML-KEM-1024 (maximum security) |

### PQC Providers

| Provider | Backend | QUIC Support | Algorithms |
|----------|---------|--------------|------------|
| `auto` | Auto-detect | Yes | Best available |
| `rustls` | aws-lc-rs | Yes | X25519MLKEM768 |
| `openssl3.5` | OpenSSL 3.5+ | No | All ML-KEM variants |

---

## Admin API

```toml
[admin]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Run the admin API |
| `bind_address` | string | `"127.0.0.1"` | Admin API bind address; a non-loopback one is refused unless `require_loopback = false` or `require_mtls` |
| `port` | u16 | `8081` | Admin API port |
| `require_loopback` | bool | `true` | Refuse to start when `bind_address` is not loopback (the API is plain HTTP without `require_mtls`) |
| `require_mtls` | bool | `false` | TLS with client certificates: the certificate is the credential (a configured `auth_token` is still checked) |
| `client_ca_path` | path? | `null` | CA that admin client certificates must chain to (`require_mtls`) |
| `tls_cert_path` / `tls_key_path` | path? | `null` | The admin listener's certificate and key under `require_mtls`; default to `[tls]`'s |
| `auth_token` | string? | `null` | Bearer token, at least 32 characters. Unset (and no mTLS): a 48-character token is generated at each start and printed to standard error |
| `allowed_ips` | array[string] | `["127.0.0.1", "::1"]` | Addresses that may reach the API at all (a filter, not authentication); one that is not loopback-only needs `auth_token` |
| `hmac_secret` | string? | `null` | Per-request proof of possession: `X-Admin-Signature` (HMAC-SHA256 of method, path and query, timestamp, nonce) with `X-Admin-Timestamp` (±300 s) and `X-Admin-Nonce` (each accepted once) |

### Admin API Endpoints

The README's [Admin API](../README.md#admin-api) tables list every route with its method; a test
(`tests/docs.rs`) holds them to the router, so they are the one list kept.

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
| `audit_log_enabled` | bool | `true` | Write the audit log: admin actions and refused admin requests, WAF verdicts, address blocks, rate-limit refusals, classical handshakes, configuration and TLS reloads |
| `audit_log_path` | path? | `null` | Audit log file, one JSON line an event (null = stderr). Created `0640`; reopened after a rotation |

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

Multi-dimensional rate limiting with composite keys, JA3/JA4 fingerprinting, and adaptive baselines (each key's own request rate, as time-decayed statistics).

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

A key the client cannot choose (`source_ip`, `real_ip`, and a `jwt_subject`
whose token verified) is one bucket. Any other key is counted beside the
bucket of the network the request came from, and that bucket is checked
first: a request with a new `api_key` value every time is still one address,
held to `per_ip`. A value the client writes itself (`api_key`, `header:`,
`cookie:`, `query_param:`, `path`) is not verified here, so it never earns a
budget: such a request is also counted in the bucket it would have without
that value (the first other key in `order` that applies, a fingerprint for
instance), and the tightest of them holds it. A TLS fingerprint names a client
build that all of its users share, so a fingerprint bucket is kept per network. With Redis, the
buckets of keys the client cannot choose are shared between instances;
buckets keyed on a value the client wrote are kept on each instance.

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
| `baseline_window_secs` | u64 | `3600` | How long the baseline remembers: a sample this old weighs 1/e of a new one |
| `sensitivity` | f64 | `0.7` | Anomaly detection sensitivity (0.0-1.0) |
| `auto_adjust` | bool | `false` | Auto-adjust limits based on traffic |
| `min_samples` | u64 | `1000` | Samples (at most one a second while the key is active) before the baseline is used |
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
| `max_buffered_body_bytes` | usize | `0` | The memory all request bodies together may occupy while the proxy holds them, on every transport; a request whose body would take the process past it is answered 503 with `Retry-After`. `0` = four bodies of `max_request_size`, and at least 256 MiB |
| `max_header_size` | usize | `65536` | Maximum header size in bytes (64KB) |
| `connection_timeout_secs` | u64 | `30` | Connection timeout in seconds |
| `dos_protection` | bool | `true` | Enable DoS protection |
| `blocked_ips` | array[string] | `[]` | Manually blocked IP addresses |
| `allowed_ips` | array[string] | `[]` | IP whitelist (empty = allow all) |
| `geoip_db_path` | path? | `"/var/lib/pqcrypta-proxy/geoip/GeoLite2-City.mmdb"` | MaxMind GeoIP (City) database path |
| `geoip_asn_db_path` | path? | `"/var/lib/pqcrypta-proxy/geoip/GeoLite2-ASN.mmdb"` | MaxMind GeoIP ASN database path |
| `blocked_countries` | array[string] | `[]` | Blocked country codes (ISO 3166-1 alpha-2, e.g., `["CN", "RU", "KP"]`) |
| `max_connections_per_ip` | u32 | `100` | Maximum concurrent client connections from one client (an IPv4 address, or the /64 an IPv6 address is in), on every listener including the conformance suite's, and maximum requests in flight from one address. Trusted addresses, `pentest_bypass_ips` and `proxy_protocol_trusted` peers are outside the connection count. `0` = no connection limit |
| `auto_block_threshold` | u32 | `10` | Suspicious patterns before auto-block |
| `auto_block_duration_secs` | u64 | `300` | Auto-block duration (5 minutes) |
| `error_4xx_threshold` | u32 | `100` | 4xx errors before checking rate |
| `min_requests_for_error_check` | u64 | `200` | Minimum requests before error rate check |
| `error_rate_threshold` | f64 | `0.7` | Error rate threshold (70%) to trigger suspicious |
| `error_window_secs` | u64 | `60` | Error tracking sliding window (1 minute) |
| `pentest_bypass_ips` | array[string] | `[]` | Authorised test sources: inspected by the WAF but never rate-limited or auto-banned. An entry is an address or a host name standing for the addresses it resolves to |
| `host_resolver` | socket address? | none | A validating resolver, reached over TCP, for the host names in `pentest_bypass_ips`. Only an answer it authenticates (AD bit) counts, refreshed every minute; without one, a name matches nothing |

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
| `replay_detection` | bool | `true` | Flag one fingerprint that is not a browser's or a known crawler's arriving from many client networks (IPv4 /24, IPv6 /48) at once |
| `replay_window_secs` | u64 | `60` | Replay window |
| `replay_min_networks` | usize | `50` | Client networks within the window that flag a fingerprint |
| `replay_action` | string | `"log"` | `"log"` (warn and audit once a window) or `"block"` (also block each address for `suspicious_block_duration_secs`) |
| `drift_detection` | bool | `true` | Flag a client network presenting a different JA4 on most of its connections (a client rotating its fingerprint; a browser keeps one per transport) |
| `drift_window_secs` | u64 | `300` | Drift window |
| `drift_threshold` | f64 | `0.7` | Distinct fingerprints per connection that flag a network (more than 0, at most 1) |
| `drift_min_connections` | u32 | `12` | Connections from the network within the window before it is judged |
| `drift_action` | string | `"log"` | As `replay_action` |

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
| `max_connections_per_host` | usize | `100` | Requests in flight to a backend that sets no `max_connections` of its own; a request holds its place until its response body has been sent on, on every transport |
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
- `uri_hash` - Affinity by request path, query string excluded (HAProxy `uri`)
- `url_param:<name>` - Affinity by one query parameter (HAProxy `url_param`); round-robin for a request without it
- `header:<name>` - Affinity by one request header (HAProxy `hdr(<name>)`); round-robin for a request without it
- `first_available` - Fills servers in declared order up to each one's `max_connections` (HAProxy `first`); a server with no limit is last
- `power_of_two_choices` - Two servers sampled at random, the less loaded per unit of weight taken (Envoy's default)

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
| `tls_skip_verify` | bool | `false` | Refused when true: the certificate is always verified; pin a self-signed backend or private CA with `tls_cert` |
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
| `type` | string | required | How requests reach it: `"http1"` (HTTP/1.1 over TCP, or TLS with `tls`/`tls_mode = "reencrypt"`; connections pooled), `"http2"` (one multiplexed connection: TLS with ALPN `h2`, or cleartext h2c with prior knowledge), `"http3"` (one QUIC connection, ALPN `h3`, always TLS), `"unix"` (HTTP/1.1 over a Unix socket; `address` is its path), `"tcp"` (raw bytes: only for WebTransport routes, whose streams it carries) |
| `address` | string | required | Backend address (e.g., `"127.0.0.1:8080"` or `"unix:/run/php-fpm.sock"`) |
| `tls_mode` | string | `"terminate"` | TLS mode. Options: `"terminate"`, `"reencrypt"`, `"passthrough"` |
| `tls` | bool | `false` | Legacy: Enable TLS (use `tls_mode` instead) |
| `tls_cert` | path? | `null` | CA certificate for backend verification |
| `tls_client_cert` | path? | `null` | Client certificate for mTLS |
| `tls_client_key` | path? | `null` | Client key for mTLS |
| `tls_skip_verify` | bool | `false` | Refused when true, as for backends |
| `tls_sni` | string? | `null` | Custom SNI hostname |
| `timeout_ms` | u64 | `30000` | Connection timeout (30 seconds) |
| `max_connections` | u32 | `100` | Requests in flight to this backend at once, for the whole process and every transport; a request holds its place until its response body has been sent on, and one that cannot have a place within `connection_pool.acquire_timeout_ms` is refused |
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
| `supports_websocket` | bool | `false` | Tunnel WebSockets on this route: an HTTP/1.1 upgrade (RFC 6455), an HTTP/2 extended CONNECT (RFC 8441) or an HTTP/3 one (RFC 9220), each opened to the backend as an HTTP/1.1 upgrade with the backend's TLS settings and the request's fields, within its `timeout_ms`; the backend's `Sec-WebSocket-Accept` is verified and the subprotocol and extensions it agreed to are passed to the client |
| `ws_idle_timeout_secs` | u64 | `300` | Close a WebSocket tunnel when nothing has moved either way for this long (0: never) |
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
| `skip_bot_blocking` | bool | `false` | Skip bot protection for this route: every User-Agent rule, attack tools included |
| `allow_credentialed_clients` | bool | `false` | Let curl, Wget, python-requests, python-urllib, Go, Java and empty User-Agents through when the request carries `X-API-Key` or `Authorization: Bearer`; scanners, scrapers and headless browsers stay blocked |
| `allow_programmatic_clients` | bool | `false` | The same clients with or without a credential, for public endpoints documented for scripts; scanners, scrapers and headless browsers stay blocked |
| `stripe_compatibility` | bool | `false` | Remove COEP/COOP headers (for Stripe.js) |
| `timeout_override_ms` | u64? | `null` | The backend timeout for this route's requests, in place of the backend's `timeout_ms`, over TCP and HTTP/3 alike, pool members included |

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
