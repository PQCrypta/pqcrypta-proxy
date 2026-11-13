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
# OpenSSL 4.0.3, the version production links, built here as CI builds it
# (.github/actions/setup-openssl-linux): the archive checked against its
# published SHA-256, zlib, brotli and zstd for RFC 8879 certificate
# compression, and all of it linked statically into the binary. Trixie's own
# OpenSSL 3.5 has zlib and zstd but not brotli, so a client offering only
# brotli, as BoringSSL's do, was sent a plain Certificate. Production also
# loads liboqs through oqs-provider, which this image does not carry.
#
# Both images are pinned by digest as well as by name: a tag is moved by
# whoever publishes it, and the toolchain is the 1.99.0 every other build
# uses. The release workflow builds this file, so a pin that stops working is
# found when a release is cut, not by whoever builds the image next.
FROM rust:1.99.0-trixie@sha256:81015672d6939b0265f09adf96d5de125482bb1330106076956b0518e74edc90 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    cmake \
    zlib1g-dev \
    libbrotli-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

ARG OPENSSL_VERSION=4.0.3
ARG OPENSSL_SHA256=325b5c806167c13b40b1ffeadfe0248197c00eccc4cf123ec1e28d2d2fd216d9
# The configuration directory is Debian's, where ca-certificates puts the CA
# store. libcrypto's archive needs the compression libraries' archives at
# link time: beside it, where openssl-sys looks for what OPENSSL_LIBS names.
RUN curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o /tmp/openssl.tar.gz \
    && echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum -c - \
    && tar -C /tmp -xzf /tmp/openssl.tar.gz \
    && cd "/tmp/openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix=/opt/openssl --openssldir=/usr/lib/ssl --libdir=lib \
       no-docs no-tests shared zlib enable-brotli enable-zstd \
    && make -j"$(nproc)" \
    && make install_sw \
    && multiarch="$(gcc -dumpmachine)" \
    && cp "/usr/lib/${multiarch}"/libz.a "/usr/lib/${multiarch}"/libbrotlienc.a \
       "/usr/lib/${multiarch}"/libbrotlidec.a "/usr/lib/${multiarch}"/libbrotlicommon.a \
       "/usr/lib/${multiarch}"/libzstd.a /opt/openssl/lib/ \
    && cd / && rm -rf /tmp/openssl.tar.gz "/tmp/openssl-${OPENSSL_VERSION}"
ENV OPENSSL_DIR=/opt/openssl \
    OPENSSL_LIB_DIR=/opt/openssl/lib \
    OPENSSL_INCLUDE_DIR=/opt/openssl/include \
    OPENSSL_STATIC=1 \
    OPENSSL_LIBS=ssl:crypto:brotlienc:brotlidec:brotlicommon:zstd:z

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
# build.rs names the commit in `--version`; the context has no .git, so CI
# passes it (docker build --build-arg PQCRYPTA_GIT_COMMIT=<sha>). Without it
# the version reads "unknown" rather than failing the build.
COPY build.rs ./
ARG PQCRYPTA_GIT_COMMIT=
ENV PQCRYPTA_GIT_COMMIT=${PQCRYPTA_GIT_COMMIT}

# Build release binary
RUN cargo build --release --locked

# Stage 2: Runtime
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# Install runtime dependencies
# AUD-08: curl is required by the HEALTHCHECK instruction below.
# Without it the container is immediately marked unhealthy.
# OpenSSL and the compression libraries are linked into the binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
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

# Expose ports: HTTP/3 on UDP, HTTP/1.1 and HTTP/2 on TCP, the admin API
EXPOSE 4433/udp
EXPOSE 4433/tcp
EXPOSE 8081/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run
ENTRYPOINT ["/usr/local/bin/pqcrypta-proxy"]
CMD ["--config", "/etc/pqcrypta/config.toml"]
