# awg-easy-rs

A standalone, single-binary VPN manager with a built-in web UI. Pure Rust port of [wg-easy](https://github.com/wg-easy/wg-easy) / [awg-easy](https://github.com/coffeegrind123/awg-easy) — no Node.js, no npm, no JS toolchain in the container.

Two protocols on one server, switchable per peer:

- **Gaming mode** — [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) (obfuscated WireGuard over UDP). Low-latency, full-tunnel.
- **Browsing mode** — [Xray](https://github.com/XTLS/Xray-core) VLESS + Reality + Vision over TCP/443. Camouflaged as a real TLS connection to a public CDN host. Browser-friendly. (Reality and Vision are Xray-core extensions and don't exist outside it.)

Both modes share the same admin UI, user accounts, session/auth, and SQLite DB.

- **~18 MB stripped release binary** (was ~3 MB before Xray; bundled Xray-core ELF accounts for ~13 MB of that).
- **252 tests** (DB, auth, security, API, AmneziaWG kernel-parity, Xray Reality e2e).
- **Native nftables firewall** — single `inet awg-easy-rs` table with atomic transactions. Transparent compat shim for hosts still on `iptables-legacy`: detected at startup, three FORWARD/INPUT accept rules mirrored into the legacy backend, removed on graceful shutdown.

---

## Features

| Area | What's included |
|---|---|
| **AmneziaWG 2.0 (Gaming)** | Full obfuscation set: `Jc / Jmin / Jmax`, `S1‑S4`, `H1‑H4` (with non-overlapping ranges), `I1‑I5` (with CPS tag-grammar validation: `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`). Per-peer `AdvancedSecurity` opt-in (on / off / auto-detect from H1 magic header). |
| **Xray VLESS+Reality+Vision (Browsing)** | Bundled Xray-core v26.3.27 ELF (vendored, gzipped, SHA-verified, ~13 MB compressed) for amd64 + aarch64. Vision flow hardcoded. Per-client UUID **and** per-client `shortId` (revocable individually). TLS 1.3 dest probe with SAN-match enforcement (rejects burned-IP / private-CN destinations before save). Tokio-supervised subprocess: SIGHUP reload, SIGTERM+10s grace shutdown, capped exponential backoff on crash. Free-form `additional_config` JSON deep-merged into the inbound. |
| **Web UI** | Single embedded SPA (HTML + `app.js`). Top-nav Gaming / Browsing toggle. Live transfer rates (AmneziaWG side), QR codes, one-time download links, admin panels for interface / hooks / general / user-config / Xray inbound. Inline guidance on which client app eats which share format (Amnezia VPN, v2rayN, v2rayNG, NekoBox, Hiddify, Streisand, Shadowrocket, FoXray). |
| **Share formats** | AmneziaWG: `.conf` file, QR, one-time link. Xray: `vless://` URL (with both `spx` and `spiderX` for max compat), QR, native Amnezia-format JSON. |
| **Auth** | Argon2id password hashing, server-side session cookies (`SameSite=Strict`, `HttpOnly`, `Secure` unless `INSECURE=true`). Per-username (10/min) **and** per-source-IP (50/min) login rate limit. Constant-time username-not-found path (no enumeration via timing). |
| **2FA / TOTP** | Server-generated 20-byte secrets, RFC 6238 verification, separate 5/5min rate limit on TOTP code attempts. `setup` / `create` / `delete` API contract. |
| **Setup wizard** | 4-step first-run flow. `INIT_ENABLED` env-var auto-setup for Kubernetes/CI deployments. |
| **Per-client firewall** | Native nftables `wg-clients` chain inside the `inet awg-easy-rs` table. `IP:port[/tcp\|udp]` rules, default-deny, atomic rebuild via a single `nft -f -` transaction. (AmneziaWG side; Xray multiplexes through one socket so per-peer filtering doesn't apply.) |
| **Metrics** | `/metrics/json` and `/metrics/prometheus`, gated by hashed Bearer token (when `metricsPassword` is set). Exposes per-peer rx/tx, last-handshake, online state. |
| **Operational** | Background cron expires clients/one-time-links every 60 s. `/health` endpoint (always 200). Persistent SQLite (WAL mode, foreign keys on). Idempotent schema migrations. |

---

## Quick start

```bash
docker compose up -d
```

Open `https://YOUR_HOST:51821/` (place a reverse proxy in front — see [TLS](#tls)).

On first run, the setup wizard prompts for an admin user, host endpoint, and AmneziaWG parameters (auto-generated). Or pre-populate via env vars:

```yaml
environment:
  - INIT_ENABLED=true
  - INIT_USERNAME=admin
  - INIT_PASSWORD=use-a-real-password-please
  - INIT_HOST=vpn.example.com
  - INIT_PORT=51820
```

---

## Configuration

All configuration is via environment variables.

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `51821` | Web UI listen port |
| `HOST` | `0.0.0.0` | Web UI bind address |
| `INSECURE` | `false` | If `true`, drops the `Secure` flag from the session cookie. **Only set this when running on a trusted local network without TLS.** Production deployments should leave this `false` and terminate TLS upstream. |
| `DISABLE_IPV6` | `false` | Skip IPv6 in generated configs / firewall rules |
| `WG_EASY_DB_PATH` | `/etc/wireguard/wg-easy.db` | SQLite database path |
| `WG_EASY_CONF_DIR` | `/etc/wireguard` | Where the generated `awg0.conf` is written |
| `WG_EASY_XRAY_DIR` | `<WG_EASY_CONF_DIR>/xray` | Where the bundled Xray ELF is extracted and `server.json` written. Persist this on a docker volume so the binary doesn't re-extract on every restart. |
| `XRAY_BIN_PATH` | — | If set, the supervisor uses this `xray` binary instead of extracting the bundled one. Useful for operators tracking upstream Xray independently of awg-easy-rs releases. |

### First-run auto-setup

These take effect only when no admin user exists. They make `INIT_ENABLED=true` deployments idempotent — restarting the container with the same env doesn't recreate the user.

| Variable | Default | Description |
|---|---|---|
| `INIT_ENABLED` | `false` | Master switch for the auto-setup |
| `INIT_USERNAME` | — | Initial admin username (required when `INIT_ENABLED=true`) |
| `INIT_PASSWORD` | — | Initial admin password (≥6 chars; required when `INIT_ENABLED=true`) |
| `INIT_HOST` | — | WireGuard endpoint hostname (DNS or IP) |
| `INIT_PORT` | `51820` | WireGuard listen port |
| `INIT_DNS` | — | Comma-separated DNS servers pushed to clients |
| `INIT_IPV4_CIDR` | `10.8.0.0/24` | IPv4 pool for clients |
| `INIT_IPV6_CIDR` | `fdcc:ad94:bacf:61a4::cafe:0/112` | IPv6 pool for clients |
| `INIT_ALLOWED_IPS` | — | Comma-separated default `AllowedIPs` for clients |

### Runtime tunables (admin UI)

Stored in SQLite, editable via the admin panel:

- `metricsPrometheus`, `metricsJson`, `metricsPassword` (hashed)
- `sessionTimeout` (seconds)
- AmneziaWG params (Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5)
- Per-client `AdvancedSecurity` (on / off / auto)
- Per-client firewall rules
- Free-form `additional_config` append for AmneziaWG `[Interface]` (server + per-peer)
- Xray Reality inbound (port, dest, server names, fingerprint, additional_config) and per-peer expiry / additional config

---

## Browsing mode (Xray VLESS+Reality+Vision)

Browsing mode is **off by default**. To enable it:

1. Open **Admin → Inbound** in the web UI.
2. Click **Generate** to produce a fresh x25519 keypair.
3. Pick a `dest` from the curated dropdown (default: `www.microsoft.com:443`) and click **Probe** — the backend opens a real TLS 1.3 handshake to verify the dest is reachable, the cert SAN matches the SNI, and ALPN is `h2`. Probes must come back green or save will fail.
4. Toggle **Enabled** and **Save**. The supervisor extracts the bundled Xray ELF on first run, writes `server.json`, and brings up the listener.
5. Switch to **Browsing** in the top nav, click **New peer**, hand the user the `vless://` URL or QR.

Expose the inbound port (default `443/tcp`) on your reverse proxy / cloud firewall for clients to reach. Reality runs on port 443 by design — non-443 ports are the #1 telltale.

### Why bundle the Xray binary?

Reality + Vision is non-trivial and there's no production-quality Rust reimplementation. Embedding the upstream Go binary as a `include_bytes!` blob and supervising it as a tokio child process gives the "single binary" UX without forking the protocol. The trade-off is a 15 MB binary-size increase and a Xray version that's pinned at compile time. Operators who want to track upstream Xray independently can set `XRAY_BIN_PATH` to their own `xray`.

### What it doesn't do

- **No `fallbacks` array** — surveyed every focused Reality reference impl; with Vision + a real `dest`, the camouflage *is* the dest.
- **No GeoIP rules** — explicit RFC1918/loopback/ULA blocklist (avoids needing to ship `geoip.dat`).
- **No per-client traffic stats** — Xray's stats API is enableable but adds gRPC dependencies; deferred. AmneziaWG side has live rates via `wg dump`.

### Compatibility with the Amnezia VPN client

The official Amnezia VPN app (iOS/Android/Win/Mac/Linux) **consumes** the configs we generate via:

1. Paste `vless://` URL → "Add server → Configuration file or text"
2. Scan QR
3. Paste the native JSON we expose at `/api/xray/clients/:id/json`

It cannot **provision** peers on awg-easy-rs (its self-hosting flow expects SSH access to a Docker host). That's by design — peer management lives in the awg-easy-rs admin UI; the Amnezia app is just one of several supported clients.

---

## TLS

The binary ships **without** TLS termination — put a reverse proxy in front of it. Caddy is the easiest:

```caddy
vpn.example.com {
    reverse_proxy awg-easy:51821
}
```

Or nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name vpn.example.com;
    ssl_certificate /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:51821;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP       $remote_addr;
    }
}
```

The login rate limiter honours `X-Forwarded-For` / `X-Real-IP` for per-source-IP buckets — set them on the proxy so individual IPs are throttled correctly.

If you really must run without a proxy on a trusted network: set `INSECURE=true`. **Do not** leave that on for an Internet-facing deployment — the session cookie then travels over plain HTTP and any on-path observer steals the session.

---

## Upgrades

awg-easy-rs is a **standalone project** — not a drop-in for upstream `awg-easy` (Node.js) or `wg-easy`. It runs against its own SQLite database at `/etc/wireguard/wg-easy.db` (path kept for our own historical compat; override via `WG_EASY_DB_PATH`).

For upgrades between awg-easy-rs versions, idempotent `ALTER TABLE` migrations apply on first boot; no manual DDL.

---

## Building from source

Requires **Rust 1.80+** (uses `LazyLock`, `OnceLock`, edition 2021).

```bash
cargo build --release
strip target/release/awg-easy-rs
```

Output: `target/release/awg-easy-rs`, ~18 MB stripped (vendored Xray ELF + tokio-rustls account for the bulk; pure-AmneziaWG build is ~3 MB).

```bash
cargo test                       # 252 tests, ~3 minutes
cargo test -- --include-ignored  # also runs the 3 e2e tests that spawn real Xray + open TLS
cargo build                      # debug build for quick iteration
```

### Updating the bundled Xray version

Bumping is a three-step process documented in `vendor/README.md`. Summary:

1. Download the new `Xray-linux-64.zip` + `Xray-linux-arm64-v8a.zip`, verify SHA-256 against upstream `.dgst` files.
2. Extract the `xray` ELF from each, `gzip -9 -c xray > vendor/xray-linux-<arch>.gz`.
3. Update `vendor/XRAY_VERSION` (version + uncompressed-ELF SHA-256s).

`build.rs` will refuse to build if the SHA in `XRAY_VERSION` doesn't match the actual blob; runtime extraction will refuse to install a binary whose SHA doesn't match the embedded constant.

### Running without Docker

Requires `awg`, `awg-quick`, and the AmneziaWG kernel module on the host (Gaming mode). Browsing mode is self-contained — the bundled `xray` is extracted to `WG_EASY_XRAY_DIR` on first start and doesn't need anything else on the host.

```bash
sudo ./target/release/awg-easy-rs
```

`/etc/wireguard/` must be writable by the user the binary runs as. If `awg-quick up awg0` fails the binary still starts and exposes the web UI — fix the host config and click *Restart Interface* in the admin panel. Browsing mode supervisor failures surface in `Admin → Inbound`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Single binary (~18 MB, musl-static)                          │
│                                                              │
│  Axum 0.7 ──── HTTP server                                   │
│  rusqlite ──── SQLite (WAL, FK on)                           │
│  argon2 ────── password hashing                              │
│  totp-rs ───── 2FA                                           │
│  qrcode ────── SVG QR generation (vless:// + AWG configs)    │
│  tokio-rustls ─ TLS 1.3 dest probe for Reality               │
│                                                              │
│  Static UI: index.html + app.js (embedded via include_str!)  │
│  Bundled Xray ELF: include_bytes!(vendor/xray-linux-*.gz)    │
└────┬───────────────────────────────────────┬─────────────────┘
     │                                       │
     │ Gaming mode                           │ Browsing mode
     │ argv-only Command::new()              │ tokio::process::Child
     ▼                                       ▼
  awg / awg-quick / nft                    xray (extracted to
     │                                     <xray_dir>/xray, SIGHUP
     ▼                                     reload, SIGTERM shutdown)
  AmneziaWG kernel module                    │
  (or amneziawg-go userspace)                ▼
                                          VLESS + Reality + Vision
                                          listener on TCP/443

  Firewall: single `inet awg-easy-rs` nftables table holding
  forward / nat-postrouting / filter-input / wg-clients chains.
  PostUp creates it, PostDown deletes it atomically.
```

### Source layout

```
src/
  main.rs          # entrypoint, env→config, INIT_ENABLED auto-setup,
                   # AWG + Xray supervisor startup
  config.rs        # env-var Config (LazyLock)
  db.rs            # rusqlite + schema + idempotent migrations
                   # (interfaces, clients, xray_inbound, xray_clients, …)
  auth.rs          # Argon2id wrappers, SHA-256, session-token gen
  qr.rs            # SVG QR codes
  firewall.rs      # native nftables; manages inet awg-easy-rs / wg-clients chain
  wg/              # — Gaming mode (AmneziaWG) —
    cli.rs         # argv-only awg/awg-quick wrappers
    params.rs      # AmneziaWG param generation + CPS tag validator
    config_gen.rs  # server/client .conf generation
    mod.rs         # startup, save_config, cron
  xray/            # — Browsing mode (Xray VLESS+Reality+Vision) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    keys.rs        # `xray x25519` wrapper + UUID/short-id generators
    config_gen.rs  # server.json generator (multi-client, per-peer sid)
    share.rs       # vless:// URL builder + Amnezia JSON template
    probe.rs       # TLS 1.3 dest probe (rustls + x509-parser)
    supervisor.rs  # tokio::process::Child + SIGHUP/SIGTERM lifecycle
    mod.rs
  api/
    mod.rs         # router, AppState, require_auth
    session.rs     # /api/session, /api/me, TOTP, rate limiter
    clients.rs     # /api/client/* CRUD (AWG), IDOR enforcement
    admin.rs       # /api/admin/* (admin role required)
    xray.rs        # /api/admin/xray/* + /api/xray/clients/*
    setup.rs       # /api/setup/* wizard + v3 backup migrate
    routes.rs      # /api/information, /metrics/*, /cnf/:token
static/
  index.html       # SPA shell + inline CSS
  app.js           # SPA logic
  *.png *.svg      # branding
vendor/
  xray-linux-amd64.gz   # pinned Xray-core v26.3.27 ELF, gzipped
  xray-linux-arm64.gz
  XRAY_VERSION          # version + decompressed-ELF SHA-256s
  README.md             # update procedure
build.rs                # picks the matching vendor blob per target arch
```

---

## Security model

- **Auth**: session cookies, server-side session table (in-memory), argon2id password hashes, optional TOTP.
- **CSRF**: relies on `SameSite=Strict` cookie + JSON-only request bodies. JSON content-type forces a CORS preflight, which a cross-site form submit cannot satisfy.
- **CSP**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'`. The two `'unsafe-inline'` allowances are required by inline `onclick=` event handlers in the embedded SPA.
- **Privilege model**: role 0 = client (sees only their own peers, cannot edit IPs/AllowedIPs/DNS/MTU/AWG params/server-endpoint of any client), role 1 = admin.
- **Command execution**: every shell-out for `awg`/`awg-quick`/`nft` uses argv-style `Command::new(...).args(...)`. No `bash -c` with user-tainted arguments. nftables transactions are piped to `nft -f -` via stdin (still argv-only) so peer names containing quotes / backticks / shell metas can never escape into command interpretation. Interface names are validated against `[A-Za-z0-9_-]{1,15}` before any command call.
- **Metrics**: SHA-256 of the configured `metricsPassword` is stored, never the cleartext. Endpoints use constant-time comparison.

If you find a security issue, please open an issue marked `security`.

---

## Operational notes

- **Backups**: copy `/etc/wireguard/wg-easy.db` while the container is stopped (or use `sqlite3 .backup`). The `.conf` and live kernel state regenerate from it on next start.
- **Health check**: the Dockerfile health check runs `awg show` to verify the kernel interface is up. Add an HTTP probe on `/health` if you want the proxy / orchestrator to also check the web UI.
- **Sessions**: stored in-memory only, so a restart logs everyone out. Persist to disk if needed by trading off restart time vs. the slim attack surface of in-memory sessions.

---

## Comparison with upstream `awg-easy` (Node.js)

| | Upstream Node.js | awg-easy-rs |
|---|---|---|
| Container size | ~150 MB (Node + deps) | ~30 MB (Alpine + Rust binary + bundled Xray + AmneziaWG tools) |
| Cold start | seconds (Nuxt warm-up) | ~50 ms |
| RAM (idle) | 80-120 MB | 8-15 MB (idle Xray subprocess accounts for ~5 MB on top of the AWG-only baseline) |
| AmneziaWG params | Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 | Same + per-peer AdvancedSecurity (kernel parity) + per-peer & UserConfig `additional_config` escape hatch |
| Xray VLESS+Reality+Vision | **no** | **yes** (bundled v26.3.27, supervised subprocess, per-peer UUIDs + shortIds, TLS dest probe) |
| TOTP secret | server-generated | server-generated |
| CSP | `'unsafe-inline'` | `'unsafe-inline'` (inline event handlers) |
| Schema | Drizzle migrations | hand-rolled `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE` |
| Plain WireGuard fallback | yes (`EXPERIMENTAL_AWG`/`OVERRIDE_AUTO_AWG`) | **no** — pure AmneziaWG (Gaming) + Xray Reality (Browsing) only |
| Tests | vitest unit suite | 252 integration tests across DB, API, security, AmneziaWG params, Xray config & supervisor |

If you need plain-WireGuard support, stay on upstream `awg-easy`. If you only want AmneziaWG and don't care about Browsing mode, you still get a strict superset of upstream's functionality. If you want both AmneziaWG and Xray VLESS+Reality+Vision in one binary, this is the only option.

---

## License

[MIT](LICENSE)
