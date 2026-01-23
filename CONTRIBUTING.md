# Contributing to PQCrypta Proxy

Thank you for your interest in contributing to PQCrypta Proxy! This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- Rust 1.75+ (install via [rustup](https://rustup.rs/))
- OpenSSL 3.x development libraries
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/PQCrypta/pqcrypta-proxy.git
cd pqcrypta-proxy

# Build
cargo build

# Run tests
cargo test

# Run with example config
cargo run -- --config config/example-config.toml --validate
```

## Making Changes

### Branching Strategy

- `main` - Stable release branch
- `develop` - Development branch (target for PRs)
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches

### Pull Request Process

1. **Fork the repository** and create your branch from `develop`

2. **Make your changes**:
   - Write clear, concise commit messages
   - Add tests for new functionality
   - Update documentation as needed

3. **Ensure quality**:
   ```bash
   # Format code
   cargo fmt

   # Run linter
   cargo clippy --all-targets --all-features -- -D warnings

   # Run tests
   cargo test
   ```

4. **Submit PR**:
   - Provide a clear description of changes
   - Reference any related issues
   - Request review from maintainers

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Build, CI, or tooling changes

Examples:
```
feat(quic): add connection migration support
fix(tls): handle certificate reload race condition
docs(readme): update PQC setup instructions
```

## Code Style

### Rust Guidelines

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting
- Address all `clippy` warnings
- Document public APIs with doc comments

### Error Handling

- Use `anyhow` for application errors
- Use `thiserror` for library errors
- Provide context in error messages

```rust
// Good
.context("failed to load TLS certificate")?

// Bad
.expect("certificate")
```

### Logging

Use the `tracing` crate with appropriate levels:

```rust
use tracing::{debug, info, warn, error};

info!("Server starting on {}", addr);
debug!(connection_id = %id, "New connection");
warn!("Certificate expires in {} days", days);
error!(error = %e, "Failed to process request");
```

### Testing

- Write unit tests for all new functionality
- Add integration tests for end-to-end scenarios
- Use property-based testing for complex logic

```rust
#[test]
fn test_route_matching() {
    // ...
}

#[tokio::test]
async fn test_admin_health_endpoint() {
    // ...
}
```

## Architecture

### Module Structure

```
src/
├── main.rs              # Entry point and CLI
├── lib.rs               # Library exports
├── config.rs            # Configuration parsing and validation
│                        # - TlsMode enum (terminate, reencrypt, passthrough)
│                        # - PassthroughRoute for SNI routing
│                        # - HeadersConfig for security headers
│                        # - CorsConfig for CORS handling
│                        # - RateLimitConfig, CompressionConfig
├── http_listener.rs     # HTTP/1.1/2 reverse proxy
│                        # - TLS termination and re-encryption
│                        # - TLS passthrough (SNI routing)
│                        # - Security headers middleware
│                        # - CORS handling
│                        # - HTTP→HTTPS redirect server
├── security.rs          # Security middleware (NEW)
│                        # - Rate limiting (governor crate)
│                        # - DoS protection & connection limits
│                        # - IP blocking (manual + auto)
│                        # - GeoIP blocking (MaxMind DB)
│                        # - JA3/JA4 TLS fingerprinting
│                        # - Circuit breaker
├── compression.rs       # Compression middleware (NEW)
│                        # - Brotli, Zstd, Gzip, Deflate
│                        # - Content negotiation
│                        # - Skip pre-compressed content
├── http3_features.rs    # HTTP/3 advanced features (NEW)
│                        # - Early Hints (103)
│                        # - Priority Hints (RFC 9218)
│                        # - Request Coalescing
├── tls.rs               # TLS provider with PQC support
├── quic_listener.rs     # QUIC/HTTP3 listener
├── webtransport_server.rs # WebTransport session handling
├── proxy.rs             # Backend connection pool
├── admin.rs             # Admin API server
└── handlers/
    ├── mod.rs
    └── webtransport.rs  # WebTransport handlers
```

### Key Design Decisions

1. **Hot reload**: Use `arc_swap` for atomic configuration updates
2. **Async runtime**: Use `tokio` for async I/O
3. **TLS**: Use `rustls` with optional OpenSSL for PQC
4. **QUIC**: Use `quinn` crate for QUIC protocol
5. **Admin API**: Use `axum` for HTTP server

## Security Considerations

### Reporting Security Issues

**Do not** report security vulnerabilities via public GitHub issues.

Instead, email security@pqcrypta.com with:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Security Best Practices

When contributing:
- Never commit secrets or credentials
- Validate all user input
- Use constant-time comparisons for secrets
- Avoid panics in production code paths
- Consider timing attacks in crypto code

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (MIT/Apache-2.0 dual license).

## Questions?

- Open a [GitHub Discussion](https://github.com/PQCrypta/pqcrypta-proxy/discussions)
- Join our [Discord](https://discord.gg/pqcrypta)
- Email: dev@pqcrypta.com
