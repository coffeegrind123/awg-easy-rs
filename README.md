# awg-easy-rs

Standalone AmneziaWG VPN manager with Web UI — pure Rust rewrite of [wg-easy](https://github.com/wg-easy/wg-easy) / [awg-easy](https://github.com/coffeegrind123/awg-easy).

Single binary. No Node.js, no npm, no dependency hell.

## Features

- **AmneziaWG** support with full obfuscation (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5)
- **Web UI** for managing WireGuard clients (built-in static HTML/JS/CSS)
- **SQLite** database — same schema as the Node.js awg-easy for drop-in migration
- **Session auth** with Argon2id password hashing
- **TOTP 2FA** support
- **Setup wizard** for first-run configuration
- **Per-client firewall** via iptables/ip6tables
- **QR code** generation for client configs
- **One-time links** for secure config sharing
- **Prometheus** + JSON metrics endpoints
- **Background cron job** for client expiry

## Quick Start

```bash
docker compose up -d
```

The Web UI will be available at `http://localhost:51821`.

## Configuration

All configuration is done via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | `51821` | Web UI port |
| `HOST` | `0.0.0.0` | Web UI bind address |
| `INSECURE` | `false` | Serve over HTTP (no TLS) |
| `DISABLE_IPV6` | `false` | Disable IPv6 |
| `WG_EASY_DB_PATH` | `/etc/wireguard/wg-easy.db` | SQLite database path |
| `WG_EASY_CONF_DIR` | `/etc/wireguard` | WireGuard config directory |
| `INIT_ENABLED` | `false` | Auto-setup on first run |
| `INIT_USERNAME` | — | Initial admin username |
| `INIT_PASSWORD` | — | Initial admin password |
| `INIT_HOST` | — | Server endpoint hostname |
| `INIT_PORT` | `51820` | WireGuard listen port |
| `INIT_DNS` | — | Comma-separated DNS servers |
| `INIT_IPV4_CIDR` | — | IPv4 CIDR for VPN clients |
| `INIT_IPV6_CIDR` | — | IPv6 CIDR for VPN clients |
| `INIT_ALLOWED_IPS` | — | Comma-separated allowed IPs |

## Building from source

Requires Rust 1.80+.

```bash
cargo build --release
```

The binary will be at `target/release/awg-easy-rs`.

### Running without Docker

```bash
# Ensure awg and awg-quick are installed and in PATH
# Ensure /etc/wireguard exists and is writable
sudo ./target/release/awg-easy-rs
```

## Migrating from awg-easy (Node.js)

The Rust version uses the same SQLite schema (`/etc/wireguard/wg-easy.db`).
Stop the Node.js container, start the Rust container with the same volume mount,
and everything should work.

## License

MIT
