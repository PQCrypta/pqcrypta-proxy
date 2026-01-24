# PQCrypta Proxy Dockerfile
# =========================
# Multi-stage build for minimal production image with PQC support
#
# SECURITY NOTES:
# - Runs as non-root user (pqcrypta)
# - TLS keys should be mounted at runtime via secrets or volumes
# - NEVER embed private keys in the container image
# - Key files should have 0600 permissions and be owned by uid 1000
#
# USAGE:
#   docker run -d \
#     -v /path/to/certs:/etc/pqcrypta/certs:ro \
#     -v /path/to/config.toml:/etc/pqcrypta/config.toml:ro \
#     -p 443:4433/tcp -p 443:4433/udp \
#     pqcrypta-proxy
#
# For Kubernetes, use secrets:
#   volumes:
#     - name: tls-certs
#       secret:
#         secretName: pqcrypta-tls
#         defaultMode: 0400

# Stage 1: Build
FROM rust:1-bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests and vendored dependencies (needed for path dependencies)
COPY Cargo.toml Cargo.lock ./
COPY vendor ./vendor

# Create dummy main.rs to cache dependencies
RUN mkdir -p src && echo "fn main() {}" > src/main.rs

# Build dependencies only (caching layer)
RUN cargo build --release && rm -rf src target/release/deps/pqcrypta*

# Copy actual source
COPY src ./src
COPY tests ./tests

# Build release binary
RUN cargo build --release --locked

# Stage 2: Runtime
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with explicit UID for predictable ownership
RUN useradd -r -u 1000 -s /bin/false pqcrypta

# Create directories for config, certs (mounted at runtime), and logs
# SECURITY: /etc/pqcrypta/certs is a mount point - do NOT copy keys into image
RUN mkdir -p /etc/pqcrypta/certs /var/log/pqcrypta-proxy \
    && chown -R pqcrypta:pqcrypta /etc/pqcrypta /var/log/pqcrypta-proxy \
    && chmod 750 /etc/pqcrypta/certs

# Copy binary
COPY --from=builder /build/target/release/pqcrypta-proxy /usr/local/bin/

# Copy default configuration (users should mount their own config)
COPY config/example-config.toml /etc/pqcrypta/config.toml.example

# SECURITY: Do NOT copy TLS certificates into the image!
# Mount them at runtime:
#   -v /path/to/cert.pem:/etc/pqcrypta/certs/cert.pem:ro
#   -v /path/to/key.pem:/etc/pqcrypta/certs/key.pem:ro
# Or use Docker secrets / Kubernetes secrets

# Set user (run as non-root)
USER pqcrypta

# Define volumes for runtime secrets
VOLUME ["/etc/pqcrypta/certs"]

# Expose ports
EXPOSE 4433/udp
EXPOSE 8081/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run
ENTRYPOINT ["/usr/local/bin/pqcrypta-proxy"]
CMD ["--config", "/etc/pqcrypta/config.toml"]
