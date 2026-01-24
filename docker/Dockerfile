# PQCrypta Proxy Dockerfile
# =========================
# Multi-stage build for minimal production image

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

# Create non-root user
RUN useradd -r -s /bin/false pqcrypta

# Create directories
RUN mkdir -p /etc/pqcrypta /var/log/pqcrypta-proxy \
    && chown -R pqcrypta:pqcrypta /etc/pqcrypta /var/log/pqcrypta-proxy

# Copy binary
COPY --from=builder /build/target/release/pqcrypta-proxy /usr/local/bin/

# Copy default configuration
COPY config/example-config.toml /etc/pqcrypta/config.toml

# Set user
USER pqcrypta

# Expose ports
EXPOSE 4433/udp
EXPOSE 8081/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run
ENTRYPOINT ["/usr/local/bin/pqcrypta-proxy"]
CMD ["--config", "/etc/pqcrypta/config.toml"]
