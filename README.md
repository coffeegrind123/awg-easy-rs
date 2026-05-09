# awg-easy-rs

A standalone, single-binary [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) VPN manager with a built-in web UI. Pure Rust port of [wg-easy](https://github.com/wg-easy/wg-easy) / [awg-easy](https://github.com/coffeegrind123/awg-easy) — no Node.js, no npm, no JS toolchain in the container.

- **Drop-in DB compatible** with upstream awg-easy (`/etc/wireguard/wg-easy.db`); stop the old container, start this one against the same volume.
- **3 MB stripped release binary**, ~12 MB Alpine container before the AmneziaWG kernel module.
- **192 tests** (DB, auth, security, API, AmneziaWG kernel-parity).

---

## Features

| Area | What's included |
|---|---|
| **AmneziaWG 2.0** | Full obfuscation set: `Jc / Jmin / Jmax`, `S1‑S4`, `H1‑H4` (with non-overlapping ranges), `I1‑I5` (with CPS tag-grammar validation: `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`). Per-peer `AdvancedSecurity` opt-in (on / off / auto-detect from H1 magic header). |
| **Web UI** | Single embedded SPA (~1000-line HTML + extracted `app.js`). Client list with live transfer rates, QR codes, one-time download links, admin panels for interface / hooks / general / user-config. |
| **Auth** | Argon2id password hashing, server-side session cookies (`SameSite=Strict`, `HttpOnly`, `Secure` unless `INSECURE=true`). Per-username (10/min) **and** per-source-IP (50/min) login rate limit. Constant-time username-not-found path (no enumeration via timing). |
| **2FA / TOTP** | Server-generated 20-byte secrets, RFC 6238 verification, separate 5/5min rate limit on TOTP code attempts. `setup` / `create` / `delete` API contract. |
| **Setup wizard** | 4-step first-run flow. v3 backup-file migration (`POST /api/setup/migrate`) accepts the original Node.js `wg-easy` JSON export. `INIT_ENABLED` env-var auto-setup for Kubernetes/CI deployments. |
| **Per-client firewall** | iptables/ip6tables `WG_CLIENTS` chain with `IP:port[/tcp\|udp]` rules, default-deny, atomic rebuild. |
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
| `WG_EASY_CONF_DIR` | `/etc/wireguard` | Where the generated `wg0.conf` is written |

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

## Migrating from upstream `awg-easy` (Node.js)

The Rust port uses the same SQLite schema. Two paths:

**Live volume swap (recommended):**

```bash
docker stop awg-easy-node
docker compose up -d   # awg-easy-rs binds to the same /etc/wireguard volume
```

The startup migration adds the new `clients_table.advanced_security` column on first boot — no manual DDL. Existing peers migrate to `advanced_security = NULL` (kernel auto-detect from H1 magic header), which is the safe default.

**Backup-file import:**

If you prefer a clean install: while still in the setup wizard (`setup_step != 0`), POST the legacy `{file: "<json export>"}` body to `/api/setup/migrate`. The handler re-keys the interface, allocates fresh IPv6 addresses for each client, and marks setup complete.

---

## Building from source

Requires **Rust 1.80+** (uses `LazyLock`, `OnceLock`, edition 2021).

```bash
cargo build --release
strip target/release/awg-easy-rs
```

Output: `target/release/awg-easy-rs`, ~3 MB stripped, fully static against the Alpine `musl` toolchain.

```bash
cargo test          # 192 tests across DB, auth, API security, kernel-parity
cargo build         # debug build for quick iteration
```

### Running without Docker

Requires `awg`, `awg-quick`, and the AmneziaWG kernel module on the host:

```bash
sudo ./target/release/awg-easy-rs
```

`/etc/wireguard/` must be writable by the user the binary runs as. If `awg-quick up wg0` fails the binary still starts and exposes the web UI — fix the host config and click *Restart Interface* in the admin panel.

---

## Architecture

```
┌─────────────────────────────────────────────┐
│ Single binary (~3 MB, musl-static)          │
│                                             │
│  Axum 0.7 ──── HTTP server                  │
│  rusqlite ──── SQLite (WAL, FK on)          │
│  argon2 ────── password hashing             │
│  totp-rs ───── 2FA                          │
│  qrcode ────── SVG QR generation            │
│                                             │
│  Static UI: HTML + app.js (embedded via     │
│  include_str!, served from /, /app.js)      │
└────────────┬────────────────────────────────┘
             │ Command::new("awg" / "awg-quick" / "iptables")
             │ argv-only — never `bash -c <user-tainted>`
             ▼
   awg / awg-quick / iptables / ip6tables
             │
             ▼
   AmneziaWG kernel module (or amneziawg-go userspace)
```

### Source layout

```
src/
  main.rs          # entrypoint, env→config, INIT_ENABLED auto-setup
  config.rs        # env-var Config (LazyLock)
  db.rs            # rusqlite + schema + idempotent migrations
  auth.rs          # Argon2id wrappers, SHA-256, session-token gen
  qr.rs            # SVG QR codes
  firewall.rs      # iptables WG_CLIENTS chain
  wg/
    cli.rs         # argv-only awg/awg-quick wrappers
    params.rs      # AmneziaWG param generation + CPS tag validator
    config_gen.rs  # server/client .conf generation
    mod.rs         # startup, save_config, cron
  api/
    mod.rs         # router, AppState, require_auth
    session.rs     # /api/session, /api/me, TOTP, rate limiter
    clients.rs     # /api/client/* CRUD, IDOR enforcement
    admin.rs       # /api/admin/* (admin role required)
    setup.rs       # /api/setup/* wizard + v3 backup migrate
    routes.rs      # /api/information, /metrics/*, /cnf/:token
static/
  index.html       # SPA shell + inline CSS
  app.js           # SPA logic
  *.png *.svg      # branding
```

---

## Security model

- **Auth**: session cookies, server-side session table (in-memory), argon2id password hashes, optional TOTP.
- **CSRF**: relies on `SameSite=Strict` cookie + JSON-only request bodies. JSON content-type forces a CORS preflight, which a cross-site form submit cannot satisfy.
- **CSP**: `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'`. The two `'unsafe-inline'` allowances are required by inline `onclick=` event handlers in the embedded SPA.
- **Privilege model**: role 0 = client (sees only their own peers, cannot edit IPs/AllowedIPs/DNS/MTU/AWG params/server-endpoint of any client), role 1 = admin.
- **Command execution**: every shell-out for `awg`/`awg-quick`/`iptables` uses argv-style `Command::new(...).args(...)`. No `bash -c` with user-tainted arguments. Interface names are validated against `[A-Za-z0-9_-]{1,15}` before any command call.
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
| Container size | ~150 MB (Node + deps) | ~12 MB (Alpine + Rust binary + AmneziaWG tools) |
| Cold start | seconds (Nuxt warm-up) | ~50 ms |
| RAM (idle) | 80-120 MB | 5-10 MB |
| AmneziaWG params | Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 | Same + per-peer AdvancedSecurity (kernel parity) |
| TOTP secret | server-generated | server-generated |
| CSP | `'unsafe-inline'` | `'unsafe-inline'` (inline event handlers) |
| Schema | Drizzle migrations | hand-rolled `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE` |
| Plain WireGuard fallback | yes (`EXPERIMENTAL_AWG`/`OVERRIDE_AUTO_AWG`) | **no** — pure AmneziaWG by design |
| Tests | vitest unit suite | 192 integration tests covering DB, API, security, AmneziaWG params |

If you need plain-WireGuard support, stay on upstream `awg-easy`. Otherwise this port is a strict superset of upstream's AmneziaWG functionality.

---

## License

[MIT](LICENSE)
