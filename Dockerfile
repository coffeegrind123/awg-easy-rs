# Stage 1: Build the Rust binary
FROM rust:alpine AS builder
WORKDIR /build

# Install build dependencies
RUN apk add --no-cache musl-dev pkgconfig

# Copy source
COPY Cargo.toml Cargo.lock* ./
COPY src/ ./src/
COPY static/ ./static/

# Build release binary
RUN cargo build --release && \
    strip target/release/awg-easy-rs

# Stage 2: Build amneziawg-go (needs Go >= 1.24)
FROM golang:alpine AS awg-go-builder
WORKDIR /build
RUN apk add --no-cache git make
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git && \
    cd amneziawg-go && make

# Stage 3: Build amneziawg-tools
FROM alpine:3.21 AS awg-builder
WORKDIR /build

RUN apk add --no-cache git build-base linux-headers

# Build amneziawg-tools (awg and awg-quick)
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git && \
    cd amneziawg-tools/src && make

# Stage 4: Minimal runtime
FROM alpine:3.21
WORKDIR /app

# Install runtime dependencies (nftables-backed iptables)
RUN apk add --no-cache \
    bash \
    iptables \
    nftables \
    kmod \
    wireguard-tools \
    curl \
    && rm -rf /var/cache/apk/*

# Copy amneziawg binaries
COPY --from=awg-go-builder /build/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-builder /build/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=awg-builder /build/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick /usr/bin/amneziawg-go

# Symlink amnezia config dir to wireguard
RUN mkdir -p /etc/amnezia && ln -s /etc/wireguard /etc/amnezia/amneziawg

# Copy the Rust binary
COPY --from=builder /build/target/release/awg-easy-rs /usr/local/bin/awg-easy-rs

# Health check — verifies the web UI binary is responding. We deliberately
# don't probe `awg show` here because a misconfigured WireGuard interface
# should surface in the UI / metrics rather than make the container
# unhealthy and start a restart loop.
HEALTHCHECK --interval=1m --timeout=5s --retries=3 \
    CMD /usr/bin/curl -fsS http://127.0.0.1:${PORT:-51821}/health || exit 1

ENV PORT=51821
ENV HOST=0.0.0.0
ENV INSECURE=false
ENV DISABLE_IPV6=false

EXPOSE 51821/tcp
EXPOSE 51820/udp

CMD ["/usr/local/bin/awg-easy-rs"]
