# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Active security fixes |
| < 0.2   | ❌ End of life — upgrade required |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through GitHub Issues.**

### Private Disclosure

Email **security@pqcrypta.com** with:

1. **Description** — A clear summary of the vulnerability and its impact.
2. **Steps to reproduce** — A minimal, self-contained reproduction case.
3. **Affected versions** — Which versions or commits are affected.
4. **Suggested severity** — Critical / High / Medium / Low.
5. **CVE request** — Let us know if you need a CVE assigned (we can assist).

PGP-encrypted reports are welcome.  Our public key is available at
`https://pqcrypta.com/.well-known/security.txt`.

### Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within 48 hours |
| Initial assessment | Within 5 business days |
| Patch / mitigation | Within 90 days for High/Critical |
| Public disclosure | Coordinated with reporter |

We follow a **90-day coordinated disclosure** policy.  If a patch cannot be
issued within 90 days we will notify you and agree on an extension or limited
disclosure.

## Scope

**In scope:**
- `pqcrypta-proxy` binary and all Rust source files in this repository
- PQC TLS key exchange implementation (`src/pqc_tls.rs`)
- Admin API authentication (`src/admin.rs`)
- Rate limiting and DoS protection (`src/rate_limiter.rs`, `src/security.rs`)
- Configuration parsing and validation (`src/config.rs`)
- HTTP/QUIC/WebTransport handling

**Out of scope:**
- Third-party dependencies (report to the respective maintainers)
- Vulnerabilities in OpenSSL 3.5+ itself (report to the OpenSSL project)
- Issues requiring physical access to the server
- Social engineering attacks

## Security Hardening

For operational security hardening guidance see [`docs/SECURITY.md`](../docs/SECURITY.md).

## Hall of Fame

We thank responsible security researchers who help keep PQCrypta Proxy secure.
Reporters who follow this policy will be acknowledged (with permission) in
release notes and credited in the fix commit.
