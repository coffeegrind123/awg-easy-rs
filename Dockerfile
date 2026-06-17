# Stage 1: Build the Rust binary
FROM rust:alpine AS builder
WORKDIR /build

# Install build dependencies
RUN apk add --no-cache musl-dev pkgconfig

# Copy source
COPY Cargo.toml Cargo.lock* ./
COPY build.rs ./build.rs
COPY src/ ./src/
COPY static/ ./static/
# vendor/ holds the pinned Xray-core ELF (amd64 only, gzipped) and,
# when curated, the DNS-stack ELFs (dnscrypt-proxy, tor + PTs).
# build.rs embeds them into the binary via include_bytes!. The
# runtime extractor decompresses on first start. x86_64 only.
COPY vendor/ ./vendor/

# Build release binary as a fully static (interpreter-free) musl ELF.
#
# The three RUSTFLAGS below collaborate:
#   +crt-static          — link the C runtime into the binary so no
#                          .so files are needed at exec time.
#   linker=musl-gcc      — use musl's wrapper around the system gcc.
#                          Available in rust:alpine via `apk add musl-dev`.
#   relocation-model=static
#                        — disable PIE so the kernel doesn't look for
#                          a PT_INTERP entry. Without this the binary
#                          still declares /lib/ld-musl-x86_64.so.1 as
#                          its interpreter and won't run on glibc-only
#                          hosts (Debian / Ubuntu / RHEL).
#
# Result: `file` reports "statically linked" (no interpreter line) and
# the binary runs unchanged on glibc, musl, or any other libc x86_64
# Linux distro — verified by docker cp into debian:stable-slim.
ENV RUSTFLAGS="-C target-feature=+crt-static -C linker=musl-gcc -C relocation-model=static"
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/awg-easy-rs && \
    cp target/x86_64-unknown-linux-musl/release/awg-easy-rs /build/awg-easy-rs

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

# Install runtime dependencies. We use nftables natively now —
# `iptables` is no longer installed since we don't shell out to it.
# nftables comes from the `nftables` package and provides the `nft` CLI.
RUN apk add --no-cache \
    bash \
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

# Copy the Rust binary (truly static, runs on any x86_64 libc).
COPY --from=builder /build/awg-easy-rs /usr/local/bin/awg-easy-rs

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

# Run entirely in RAM by default (the operator asked for the WireGuard-style
# "data plane never depends on a healthy disk" property):
#  - IN_MEMORY=true        → SQLite opens :memory:; bundled subprocess ELFs
#                            (Xray/telemt/MasterDnsVPN/dnscrypt-proxy/tor) are
#                            exec'd from anonymous memfds, never written to a
#                            filesystem.
#  - WG_EASY_PERSIST_DB    → the only durable touch point: the RAM database is
#                            snapshotted here (and restored on boot) so a
#                            planned restart keeps the full client roster. Put
#                            it on a small persistent volume (see compose).
#  - /etc/wireguard is a tmpfs (see compose) so the generated configs, the
#    AmneziaWG .conf, and tor's data dir live in RAM too.
ENV IN_MEMORY=true
ENV WG_EASY_PERSIST_DB=/data/wg-easy.db
ENV WG_EASY_PERSIST_INTERVAL=30

# Durable snapshot target (a volume is mounted here by compose). Created so
# the snapshot rename has a directory to land in even before the volume mount.
RUN mkdir -p /data

EXPOSE 51821/tcp
EXPOSE 51820/udp

CMD ["/usr/local/bin/awg-easy-rs"]
