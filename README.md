# awg-easy-rs

A standalone, single-binary VPN + censorship-resistant proxy manager with a built-in web UI. Pure Rust port of [wg-easy](https://github.com/wg-easy/wg-easy) / [awg-easy](https://github.com/coffeegrind123/awg-easy) — no Node.js, no npm, no JS toolchain in the container.

Four transports + an optional bundled resolver, all sharing one admin UI, user accounts, session/auth, and SQLite DB:

- **Gaming mode** — [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) (obfuscated WireGuard over UDP). Low-latency, full-tunnel.
- **Browsing mode** — [Xray](https://github.com/XTLS/Xray-core) VLESS + Reality + Vision over TCP/443. Camouflaged as a real TLS connection to a public CDN host. Browser-friendly. (Reality and Vision are Xray-core extensions and don't exist outside it.)
- **Telegram MTProxy** — [telemt](https://github.com/telemt/telemt) Fake-TLS / SNI fronting (the `secret=ee<…>` link variant). Per-user 32-hex secrets, optional traffic masking. Tokio-supervised; users are reconciled into telemt's `127.0.0.1:9091` HTTP control plane on every spawn.
- **DNS-tunnel mode** — [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) DNS-over-DNS tunnel: clients pack encrypted TCP/SOCKS5 traffic into DNS queries through public resolvers, the server listens on UDP/53 for tunnel envelopes (via NS-delegated subdomain) and re-emits the inner TCP through SOCKS5 or a fixed TCP forwarder. Survives total egress blackouts where only DNS is allowed.
- **DNS bundle (optional)** — bundled [dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy) with optional [tor](https://www.torproject.org/) + lyrebird/snowflake/webtunnel pluggable transports for DoH/DNSCrypt egress, plus an nftables `dns-prerouting` DNAT chain that catches peer-side `:53/:853` leaks before they reach the WAN.

- **DPI-imitation proxy (optional)** — an in-process async UDP proxy that *fronts the AmneziaWG port itself* and rewrites each packet's S1–S4 padding so the datagrams look like a real **QUIC / DNS / STUN / SIP** service to Deep Packet Inspection — while answering active protocol probes with valid responses (QUIC Version Negotiation / a full TLS 1.3 handshake, DNS SERVFAIL-or-forwarded-answer, STUN Binding Success, a stateful SIP dialog). Unlike the four transports above (which move you onto a *different* protocol), this hardens the native low-latency AmneziaWG datapath in place. When enabled, AmneziaWG is transparently rebound to a loopback backend port (firewalled to `lo`) and the proxy takes the public port — **client configs are unchanged**. Ported in-process from [wiresock/amneziawg-proxy](https://github.com/wiresock/amneziawg-install); bidirectional imitation is fully unlocked with [WireSock Secure Connect 3.5+](https://www.wiresock.net/) on the client.

  > **Detection trade-off — this is protocol *mimicry*, not a crypto layer, and it is off by default.** It cannot weaken WireGuard's encryption (the proxy holds no keys and rewrites only the random junk-padding prefix; the audit confirms it never touches the authenticated region). What it changes is *detectability*, and the direction depends on the adversary: it **helps** against commodity entropy/whitelist DPI and shallow active probers (where plain AmneziaWG reads as suspicious high-entropy UDP), but against an adversary who fingerprints *this specific tool* it can be **more** detectable than plain AmneziaWG — the imitation adds fixed protocol markers (and leaves AmneziaWG's own handshake-size tells intact underneath). This is the well-known ["Parrot is Dead"](https://people.cs.umass.edu/~amir/papers/parrot.pdf) limitation of all unauthenticated mimicry, not a flaw unique to this tool. Prefer `quic` mode (weakest static signature); `dns`/`sip` carry stronger fixed tells. Enable it only when countering commodity blocking.

- **~20 MB stripped release binary** (musl-static, distro-agnostic — runs unchanged on glibc, musl, or any other libc x86_64 host). Bundled Xray accounts for ~13 MB; telemt adds ~6 MB; MasterDnsVPN adds ~2 MB; the DNS bundle adds another ~20 MB when curated.
- **400+ unit + integration tests** (DB, auth, security, API, AmneziaWG kernel-parity, Xray Reality e2e, telemt + MasterDnsVPN config-gen smoke).
- **Native nftables firewall** — single `inet awg-easy-rs` table with atomic transactions. Transparent compat shim for hosts still on `iptables-legacy`: detected at startup, three FORWARD/INPUT accept rules mirrored into the legacy backend, removed on graceful shutdown.

---

## Features

| Area | What's included |
|---|---|
| **AmneziaWG 2.0 (Gaming)** | Full obfuscation set: `Jc / Jmin / Jmax`, `S1‑S4`, `H1‑H4` (with non-overlapping ranges), `I1‑I5` (with CPS tag-grammar validation: `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`). Per-peer `AdvancedSecurity` opt-in (on / off / auto-detect from H1 magic header). |
| **Xray VLESS+Reality+Vision (Browsing)** | Bundled Xray-core v26.3.27 ELF (vendored, gzipped, SHA-verified, ~13 MB compressed). Vision flow hardcoded. Per-client UUID **and** per-client `shortId` (revocable individually). TLS 1.3 dest probe with SAN-match enforcement (rejects burned-IP / private-CN destinations before save). Tokio-supervised subprocess: SIGHUP reload, SIGTERM+10s grace shutdown, capped exponential backoff on crash. Free-form `additional_config` JSON deep-merged into the inbound. |
| **Telegram MTProxy** | Bundled [telemt](https://github.com/telemt/telemt) v3.4.11 ELF (vendored, gzipped, SHA-verified, ~6 MB compressed). Fake-TLS / SNI fronting (`secret=ee<…>` link variant), per-user 32-hex secrets, optional `dd`-prefix and classic modes, traffic masking. Tokio-supervised subprocess; users live durably in the awg-easy-rs DB and reconcile into telemt's `127.0.0.1:9091` HTTP control plane after every spawn so a telemt state-file wipe doesn't lose the operator's roster. `tg://proxy?…` share links rendered server-side, QR via `qr.rs`. |
| **MasterDnsVPN (DNS-tunnel)** | Bundled [MasterDnsVPN](https://github.com/masterking32/MasterDnsVPN) v2026.05.10 ELF (vendored, gzipped, SHA-verified, ~2 MB compressed). Encryption: XOR / ChaCha20 / AES-128/192/256-GCM (selectable). SOCKS5 or fixed-TCP forwarding. Per-client bookkeeping (display name, custom resolver list, local SOCKS5 port, expiry) — but every client uses the same singleton encryption key (a property of the underlying protocol). Share format: downloadable `client_config.toml` + `client_resolvers.txt`, plus a `mdnsvpn://b64?<base64>` single-string variant for `mdnsvpn -json_base64`. **Requires** the operator to own a domain and create an `NS` delegation to this server. |
| **DNS bundle (optional)** | Bundled `dnscrypt-proxy` 2.1.15 + `tor` 0.4.9.8 + `lyrebird` 0.8.1 (obfs4) + `snowflake` v2.13.1 + `webtunnel` v0.0.4 — ~20 MB additional, curated as static-musl ELFs. Off by default; tor stays off independent of the dnscrypt-proxy master switch. Pairs with an nftables `dns-prerouting` chain that DNATs every peer `:53/:853` UDP+TCP packet to the configured resolver, plus an optional `dns-lockdown` filter chain that drops residual external DNS — gives belt-and-braces leak prevention even when the WireGuard `DNS = …` line is honored only loosely by the client. |
| **Build & release** | Vendored binary blobs (`vendor/*.gz`) are CI artifacts, **not committed**. `vendor/*_VERSION` pin files (versions + SHA-256) are the audited spec. `scripts/build.sh` materialises the blobs from the pin files and produces a fully static `x86_64-unknown-linux-musl` ELF locally; `.github/workflows/build-release.yml` runs the same flow in CI on every push to `main` (or manually) and publishes a release with the binary, SHA-256, and a per-component versions table. |
| **Target** | x86_64 Linux only. arm64 was dropped intentionally — see `vendor/README.md` for the rationale. |
| **Web UI** | Single embedded SPA (HTML + `app.js`). Top-nav Gaming / Browsing toggle, plus admin sub-tabs for Telegram (MTProxy), DNS Tunnel (MasterDnsVPN), and DNS bundle. Live transfer rates (AmneziaWG side), QR codes, one-time download links, admin panels for interface / hooks / general / user-config / Xray inbound / MTProxy inbound + users / DNS Tunnel inbound + clients / DNS bundle. Inline guidance on which client app eats which share format (Amnezia VPN, v2rayN, v2rayNG, NekoBox, Hiddify, Streisand, Shadowrocket, FoXray, Telegram desktop / mobile, MasterDnsVPN client). |
| **Share formats** | AmneziaWG: `.conf` file, QR, one-time link. Xray: `vless://` URL (with both `spx` and `spiderX` for max compat), QR, native Amnezia-format JSON. Telegram: `tg://proxy?…&secret=ee<…>` link (Fake-TLS) + `dd`-prefix and classic variants for the same user, QR. MasterDnsVPN: downloadable `client_config.toml` + `client_resolvers.txt`, JSON, `mdnsvpn://b64?<base64>` single-string blob (for `mdnsvpn -json_base64`), QR. |
| **Auth** | Argon2id password hashing, server-side session cookies (`SameSite=Strict`, `HttpOnly`, `Secure` unless `INSECURE=true`). Per-username (10/min) **and** per-source-IP (50/min) login rate limit. Constant-time username-not-found path (no enumeration via timing). |
| **2FA / TOTP** | Server-generated 20-byte secrets, RFC 6238 verification, separate 5/5min rate limit on TOTP code attempts. `setup` / `create` / `delete` API contract. |
| **Setup wizard** | 4-step first-run flow. `INIT_ENABLED` env-var auto-setup for Kubernetes/CI deployments. |
| **DPI-imitation proxy** | In-process async UDP proxy (ported from [amneziawg-proxy](https://github.com/wiresock/amneziawg-install)) fronting the AmneziaWG port. Protocol modes `quic` / `dns` / `stun` / `sip` / `auto`; per-packet S1–S4 padding transform driven by the interface's live S/H params; active-probe responders including a stateful `quinn-proto` QUIC/TLS-1.3 handshake responder (self-signed per-SNI cert) and a stateful SIP dialog machine; optional real DNS-upstream forwarding. Supervised as a Tokio task (no subprocess, no blob). Enabling it rebinds AmneziaWG onto a loopback backend port + an nftables `proxy-lockdown` input chain confining that port to `lo`; client `Endpoint` lines are untouched. |
| **Per-client firewall** | Native nftables `wg-clients` chain inside the `inet awg-easy-rs` table. `IP:port[/tcp\|udp]` rules, default-deny, atomic rebuild via a single `nft -f -` transaction. (AmneziaWG side only; Xray, telemt, and MasterDnsVPN multiplex through one socket each, so per-peer L3/L4 filtering doesn't compose with VLESS UUIDs / MTProxy secrets / DNS-tunnel envelopes.) |
| **Metrics** | `/metrics/json` and `/metrics/prometheus`, gated by hashed Bearer token (when `metricsPassword` is set). Exposes per-peer rx/tx, last-handshake, online state. |
| **Operational** | Background cron expires clients/one-time-links every 60 s. `/health` endpoint (always 200). Persistent SQLite (WAL mode, foreign keys on). Idempotent schema migrations. |
| **Run-in-RAM mode** | `IN_MEMORY=true` (default in the Docker image): `:memory:` SQLite + every bundled subprocess ELF exec'd from an anonymous, sealed `memfd` — nothing on the request path or `exec` path touches disk. Optional async snapshot/restore (`WG_EASY_PERSIST_DB`) keeps the roster across restarts without ever blocking the data plane on a failing disk. See [Run entirely in memory](#run-entirely-in-memory). |

---

## Quick start

### Docker

```bash
docker compose up -d
```

Open `https://YOUR_HOST:51821/` (place a reverse proxy in front — see [TLS](#tls)).

### Prebuilt binary

Each push to `main` produces a tagged release with a fully-static `awg-easy-rs` ELF on the [Releases page](https://github.com/coffeegrind123/awg-easy-rs/releases). The binary runs on any x86_64 Linux distro — no glibc / musl mismatch:

```bash
curl -fsSL -o /usr/local/bin/awg-easy-rs \
  https://github.com/coffeegrind123/awg-easy-rs/releases/latest/download/awg-easy-rs
chmod +x /usr/local/bin/awg-easy-rs
sudo /usr/local/bin/awg-easy-rs
```

The release page lists SHA-256 hashes and the version of every bundled component (Xray, telemt, dnscrypt-proxy, tor, etc.) sourced from the `vendor/*_VERSION` pin files at build time.

### Bare-metal install (systemd)

For a host install without Docker, `scripts/install.sh` provisions the AmneziaWG kernel module (DKMS via the distro's package repos), installs the `awg-easy-rs` binary, and runs it as a systemd service:

```bash
curl -O https://raw.githubusercontent.com/coffeegrind123/awg-easy-rs/main/scripts/install.sh
chmod +x install.sh
sudo ./install.sh              # guided; or: sudo AUTO_INSTALL=y ./install.sh
```

Supports Debian ≥11 / Ubuntu ≥22.04 / Mint ≥21 (Fedora/RHEL-family code paths are present but gated until verified AmneziaWG 2.0 RPMs ship). Subcommands: `install` / `upgrade` / `uninstall` / `status`. Migrating a pre-2.0 on-disk AmneziaWG server? `scripts/migrate-pre2.sh` backfills S3/S4 and converts H1–H4 to non-overlapping ranges in place, with `.bak` backup and rollback. Full reference: [`docs/INSTALL.md`](docs/INSTALL.md).

### First-run

The setup wizard prompts for an admin user, host endpoint, and AmneziaWG parameters (auto-generated). Or pre-populate via env vars:

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
| `WG_EASY_MTPROXY_DIR` | `<WG_EASY_CONF_DIR>/mtproxy` | Where the bundled `telemt` ELF is extracted, plus the generated `config.toml`, telemt's PID file, and the `tlsfront` cache (real TLS records fetched from the masking domain). Persist on a docker volume to avoid re-extraction + tlsfront rebuilds across restarts. |
| `WG_EASY_DNS_DIR` | `<WG_EASY_CONF_DIR>/dns` | Where the bundled DNS-stack ELFs (dnscrypt-proxy, tor, lyrebird, snowflake, webtunnel) are extracted, plus generated configs (`dnscrypt-proxy.toml`, `torrc`, etc.) and tor's data directory. Persist to keep tor's onion descriptors / consensus across restarts. |
| `WG_EASY_MDNSVPN_DIR` | `<WG_EASY_CONF_DIR>/mdnsvpn` | Where the bundled MasterDnsVPN ELF is extracted, plus the generated `server_config.toml` and the singleton `encrypt_key.txt`. Persist on a docker volume to avoid re-extraction across restarts. |

### Run entirely in memory

| Variable | Default | Description |
|---|---|---|
| `IN_MEMORY` | `true` (set `IN_MEMORY=false` to opt out) | Run with the data plane fully RAM-resident. SQLite is opened `:memory:`, and every bundled subprocess ELF (Xray, telemt, MasterDnsVPN, dnscrypt-proxy, tor) is exec'd from an anonymous `memfd_create(2)` object instead of being written to disk. No query and no `exec` touches a block device. Set `IN_MEMORY=false` for the classic durable on-disk database under `WG_EASY_DB_PATH`. |
| `WG_EASY_PERSIST_DB` | — (`/data/wg-easy.db` in the image) | Durable snapshot file for the RAM database. Restored on boot (the only time it's read) and re-written by a background task + on graceful shutdown via SQLite's online-backup API. Unset ⇒ pure RAM, state lost on restart. Only consulted when `IN_MEMORY=true`. |
| `WG_EASY_PERSIST_INTERVAL` | `30` | Seconds between RAM→disk snapshots. `0` disables periodic snapshots (shutdown still snapshots). |

When `IN_MEMORY=true`:

- **Database** — `:memory:`, so no SQLite query ever blocks on disk. If `WG_EASY_PERSIST_DB` is set, the full roster (clients, Reality keys, MTProxy secrets, the MasterDnsVPN key, accounts, 2FA) is restored from that file at boot and snapshotted back out-of-band. Every snapshot is best-effort and off the request path — a degraded or read-only disk demotes you to "no fresh snapshot", it never stalls or crashes the data plane. This is the WireGuard property the mode is built for: the service comes up and stays up from RAM regardless of disk health.
- **Subprocess binaries** — decompressed, SHA-256-verified, and sealed (`F_SEAL_WRITE`) inside an anonymous memfd, then exec'd via `/proc/self/fd/N`. The binary has no name in any filesystem and is immutable. The memfd is cached for the process lifetime, so a crash-looping child re-`exec`s the same in-RAM image with zero re-extraction. (`XRAY_BIN_PATH` still overrides Xray with a real on-disk binary if you want to track upstream yourself.)
- **Config files / `.conf` / tor data dir / PT plugins** — these still need real paths (tor `exec`s its lyrebird/snowflake/webtunnel plugins by the path written into `torrc`, and `awg-quick` reads `/etc/wireguard/<iface>.conf`). Mount the runtime root (`WG_EASY_CONF_DIR`, default `/etc/wireguard`) as a **tmpfs** so those live in RAM too. The bundled `docker-compose.yml` does exactly that (`tmpfs: /etc/wireguard`, durable volume only at `/data`). The server logs a warning at startup if `IN_MEMORY=true` but the runtime root isn't tmpfs.

No extra Linux capabilities are required — memfd needs none, and the tmpfs is supplied by the container runtime, so the cap set stays `NET_ADMIN` + `SYS_MODULE`.

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
- DNS lockdown (master switch + redirect target IP + drop-residual toggle)
- Xray Reality inbound (port, dest, server names, fingerprint, additional_config) and per-peer expiry / additional config
- MTProxy inbound (port, public host/port, TLS-front domain, mask toggle, mode flags, use_middle_proxy, default ad_tag, additional_config) and per-user secret + ad_tag override + enabled state
- DNS bundle (master switch, listen port, upstream resolvers, DNSSEC/no-log/no-filter requirements, optional Tor SOCKS routing with exit-country selectors and pluggable-transport choice)

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

## Telegram MTProxy (telemt)

Telemt is **off by default**. To enable it:

1. Open **Admin → Telegram (MTProxy) → Inbound** in the web UI.
2. Pick a **TLS-front domain** (a popular HTTPS site reachable from this server — `www.cloudflare.com`, `petrovich.ru`, etc.). The domain shows up hex-encoded in every Fake-TLS link's secret suffix; changing it invalidates all previously generated `tg://` links. Fake-TLS mode is on by default; classic / `dd`-prefix modes are off but available.
3. Set the listen port (default `8080` to avoid the 443 collision with Xray Reality) and optional `publicHost` / `publicPort` for the share links. Toggle **Enabled** and **Save** — telemt extracts on first start, writes `config.toml`, and brings up the listener. Subsequent saves rewrite `config.toml`; telemt's `notify`-based hot-reload picks up changes without a restart.
4. Switch to **Telegram → Users**, click **Add user**, and hand over the auto-generated `tg://proxy?…&secret=ee<…>` link or QR.

Awg-easy-rs is the **durable source of truth** for the user roster. The supervisor reconciles `mtproxy_users_table` into telemt's `127.0.0.1:9091/v1/users` HTTP control plane after every spawn, so a telemt state-file wipe doesn't lose the operator's users — same model as Xray's per-peer UUID/shortId lifecycle.

Expose the listening port on your reverse proxy / cloud firewall for Telegram clients to reach. Unlike Xray Reality, MTProxy on a non-443 port isn't a fingerprint; pick whatever doesn't conflict.

### Why bundle telemt?

Telemt's MTProto + Fake-TLS + middle-end pool integration is non-trivial and there's no Rust-native MTProxy library that's actually production-ready. Embedding a pinned static-musl ELF + supervising via tokio gives the "single binary" UX without forking the protocol — same trade-off Xray made, except telemt has a real loopback HTTP control plane (`/v1/users`, `/v1/stats/*`, `/v1/health`) so the supervisor only needs to drive that rather than rewrite `config.toml` on every roster change.

---

## DNS-tunnel mode (MasterDnsVPN)

MasterDnsVPN is **off by default** — and unlike the other transports it has a hard infrastructure prerequisite: you need to own a real domain and create an `NS` delegation pointing a tunnel subdomain at this server's public IP. There's no way to short-cut that. The upstream README walks through the DNS-record setup; once it's live:

1. Open **Admin → DNS Tunnel (MasterDnsVPN) → Inbound** in the web UI.
2. Click **Regenerate** to mint a fresh 16-byte shared encryption key. The same key is baked into every client's `client_config.toml` (MasterDnsVPN has no per-user secret slot — that's a property of the underlying protocol).
3. Paste the NS-delegated FQDN(s) into **Tunnel domains** (one per line). Pick an encryption method (XOR for low CPU on weak hardware, AES-256-GCM otherwise) and a protocol type — `SOCKS5` lets clients pick the destination per-stream; `TCP` forwards every connection to a fixed `forwardIp:forwardPort` (useful for chaining mdnsvpn into a Shadowsocks / 3X-UI panel).
4. Set the UDP listen port (default 53). On hosts where awg-easy-rs runs unprivileged, the binary needs `CAP_NET_BIND_SERVICE` or a port-forward (since :53 is privileged); on a `docker compose up -d` deployment the default `cap_add: NET_ADMIN` is already broad enough.
5. Toggle **Enabled** and **Save** — mdnsvpn extracts on first start, writes `server_config.toml` + `encrypt_key.txt`, and binds the UDP listener.
6. Switch to **DNS Tunnel → Clients**, click **Add client**, and hand over the auto-generated `client_config.toml` + `client_resolvers.txt` (or the single-string `mdnsvpn://b64?<base64>` blob — paste straight into `mdnsvpn -json_base64 <blob>` on the client side).

Awg-easy-rs is the **bookkeeping source of truth** for the client roster — but MasterDnsVPN itself authenticates every tunnel with the singleton encryption key, so per-client rows are pure UX state (share-link slot, expiry, enabled toggle). Disabling a client in the admin UI revokes its config bundle from the download URLs but doesn't break the underlying tunnel for someone who already has a copy; rolling the encryption key (**Regenerate**) is what revokes every issued config.

### Why bundle MasterDnsVPN?

The custom protocol — packed encrypted fragments stuffed into DNS labels, ARQ-based reliability over a UDP-only transport, MTU discovery across heterogeneous resolvers — isn't trivial to reimplement, and the upstream Go binary is small (~2 MB compressed) and already statically linked. Embedding it + supervising via tokio matches the Xray and telemt pattern: "single binary" UX without forking the protocol. The trade-off is the same as the others — bundled version is pinned in `vendor/MDNSVPN_VERSION` and bumped via `vendor/update.sh mdnsvpn <ver>`.

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

The bundled binary blobs (`vendor/*.gz`) are **not** committed to the repo — they're CI artifacts produced from the audited pin files in `vendor/*_VERSION`. To get a fully-bundled release binary, run:

```bash
scripts/build.sh
```

That:

1. Reads each pinned version from `vendor/{XRAY,DNS_BUNDLE,TELEMT}_VERSION`.
2. Materialises `vendor/<name>-linux-amd64.gz` for each entry by delegating to `vendor/update.sh` (downloads pre-built artifacts where upstream publishes them; builds from source in Alpine Docker for `tor` and the Go pluggable transports). Skips binaries whose `.gz` already round-trips to the pinned SHA.
3. Builds awg-easy-rs as a fully static **x86_64-linux-musl** ELF (`target/x86_64-unknown-linux-musl/release/awg-easy-rs`, ~18 MB stripped, runs unchanged on glibc / musl / any libc).

For the workflow that does the same thing in CI + publishes a release, see [`.github/workflows/build-release.yml`](.github/workflows/build-release.yml).

For a quick iterating-on-Rust loop without re-fetching upstreams, the .gz blobs can stay on disk between runs:

```bash
scripts/build.sh --cargo-only          # use cached vendor blobs
scripts/build.sh --skip tor --skip xray  # skip specific binaries
cargo test                              # 250+ tests, ~3 minutes
cargo build                             # plain debug build
                                        # (build.rs is tolerant of
                                        # missing blobs — code paths
                                        # gate on cfg(*_bundled))
```

### Updating bundled component versions

Versions are pinned in:

- `vendor/XRAY_VERSION` (Xray-core)
- `vendor/TELEMT_VERSION` (telemt MTProxy)
- `vendor/MDNSVPN_VERSION` (MasterDnsVPN DNS-tunnel server)
- `vendor/DNS_BUNDLE_VERSION` (dnscrypt-proxy + tor + lyrebird + snowflake + webtunnel)

To bump, run `vendor/update.sh <binary> <version>`. The script downloads / builds, SHA-verifies, and rewrites the matching pin file. For example:

```bash
vendor/update.sh xray            v26.3.28
vendor/update.sh telemt          3.4.12
vendor/update.sh mdnsvpn         v2026.06.01.000000-abcdef0
vendor/update.sh dnscrypt-proxy  2.1.16
vendor/update.sh tor             0.4.9.9     # Alpine Docker build, ~10 min
vendor/update.sh lyrebird        0.8.2       # Go static, ~2 min
vendor/update.sh snowflake       v2.13.2
vendor/update.sh webtunnel       v0.0.5
```

Then commit the updated pin file (the `.gz` itself stays out of git). `build.rs` refuses to build if a pin's SHA doesn't match the actual blob; runtime extraction refuses to install a binary whose SHA doesn't match the embedded constant.

### Running without Docker

Gaming mode requires `awg`, `awg-quick`, and the AmneziaWG kernel module on the host. The other four subsystems are self-contained — the bundled `xray`, `telemt`, `mdnsvpn`, and DNS-stack ELFs are extracted to `WG_EASY_XRAY_DIR` / `WG_EASY_MTPROXY_DIR` / `WG_EASY_MDNSVPN_DIR` / `WG_EASY_DNS_DIR` on first start and don't need anything else on the host. Only the firewall stage needs `nft` available.

```bash
sudo ./target/x86_64-unknown-linux-musl/release/awg-easy-rs
```

`/etc/wireguard/` must be writable by the user the binary runs as. If `awg-quick up awg0` fails the binary still starts and exposes the web UI — fix the host config and click *Restart Interface* in the admin panel. Per-supervisor failures surface in their respective admin tabs (`Admin → Browsing → Inbound`, `Admin → Telegram → Inbound`, `Admin → DNS Tunnel → Inbound`, `Admin → DNS bundle`). All five are independently disable-able and degrade gracefully — a misconfigured Browsing inbound doesn't block AmneziaWG, etc.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Single binary (~20 MB stripped, musl-static, distro-agnostic)│
│                                                              │
│  Axum 0.7 ──── HTTP server                                   │
│  rusqlite ──── SQLite (WAL, FK on)                           │
│  argon2 ────── password hashing                              │
│  totp-rs ───── 2FA                                           │
│  qrcode ────── SVG QR (vless:// + tg:// + mdnsvpn:// + AWG)  │
│  tokio-rustls ─ TLS 1.3 dest probe for Reality               │
│                                                              │
│  Static UI: index.html + app.js (embedded via include_str!)  │
│  Bundled ELFs (include_bytes!(vendor/<name>-linux-amd64.gz)):│
│    xray-core, telemt, MasterDnsVPN, dnscrypt-proxy, tor,     │
│    lyrebird, snowflake, webtunnel — all extracted on first   │
│    start, SHA-verified against the embedded constant.        │
└─┬─────────┬──────────────┬─────────────┬─────────────────────┘
  │         │              │             │            │
  │ Gaming  │ Browsing     │ Telegram    │ DNS-tunnel │ DNS bundle
  │ argv    │ tokio Child  │ tokio Child │ tokio Child│ tokio Child
  ▼         ▼              ▼             ▼            ▼
awg /     xray (SIGHUP   telemt        MasterDnsVPN  dnscrypt-proxy
awg-quick reload, ...)   (notify       (rewrite +    (+ optional tor
/ nft     │              hot-reload    restart on    with PT plugin)
  │       ▼              of config)    config change)    │
  ▼      VLESS+Reality+    │              │              ▼
AWG      Vision listener   ▼              ▼          DoH / DNSCrypt
kernel   on TCP/443      MTProto      DNS-tunnel     egress, opt. via
module                   listener     listener       tor SOCKS :9053
                         on TCP/8080  on UDP/53
                         (Fake-TLS)   (NS-delegated)

  Firewall: single `inet awg-easy-rs` nftables table.
  PostUp creates: forward / nat-postrouting / filter-input.
  firewall.rs owns: wg-clients chain (per-peer rules) +
  dns-prerouting (DNS-leak DNAT) + dns-lockdown (residual drop).
  PostDown atomically deletes the whole table.
```

### Source layout

```
src/
  main.rs          # entrypoint, env→config, INIT_ENABLED auto-setup,
                   # AWG + Xray + DNS bundle + telemt + MasterDnsVPN
                   # supervisor startup
  config.rs        # env-var Config (LazyLock)
  db.rs            # rusqlite + schema + idempotent migrations
                   # (interfaces, clients, xray_inbound, xray_clients,
                   #  dns_bundle, mtproxy_inbound, mtproxy_users,
                   #  mdnsvpn_inbound, mdnsvpn_clients, …)
  auth.rs          # Argon2id wrappers, SHA-256, session-token gen
  qr.rs            # SVG QR codes
  firewall.rs      # native nftables; manages inet awg-easy-rs table:
                   #   wg-clients chain (per-peer rules)
                   #   dns-prerouting chain (DNS-leak DNAT)
                   #   dns-lockdown chain (residual drop)
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
  mtproxy/         # — Telegram MTProxy (telemt) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    config.rs      # config.toml generator (no [access.users] —
                   # users go via the runtime API)
    client.rs      # minimal HTTP/1.1 client for 127.0.0.1:9091/v1/*
    supervisor.rs  # spawn telemt, reconcile users on every start
    mod.rs
  mdnsvpn/         # — DNS-tunnel mode (MasterDnsVPN) —
    runtime.rs     # include_bytes! the gzipped ELF, decompress to disk
    keys.rs        # 16-byte hex shared-key generator + validator
    config.rs      # server_config.toml generator (singleton inbound)
    share.rs       # per-client client_config.toml + resolvers.txt +
                   # JSON + mdnsvpn://b64?<base64> share blob
    supervisor.rs  # tokio Child; rewrite-and-restart on config change
                   # (no upstream SIGHUP)
    mod.rs
  dns/             # — Bundled DNS stack (dnscrypt-proxy + tor + PTs) —
    runtime.rs     # extract bundled ELFs (5 binaries, all optional)
    dnscrypt.rs    # dnscrypt-proxy.toml generator
    tor.rs         # torrc + BridgeDB scraping for PT support
    supervisor.rs  # tokio Children for dnscrypt-proxy + tor (opt-in)
    mod.rs
  api/
    mod.rs         # router, AppState, require_auth
    session.rs     # /api/session, /api/me, TOTP, rate limiter
    clients.rs     # /api/client/* CRUD (AWG), IDOR enforcement
    admin.rs       # /api/admin/* (admin role required)
    xray.rs        # /api/admin/xray/* + /api/xray/clients/*
    mtproxy.rs     # /api/admin/mtproxy/* (inbound, users, stats, QR)
    mdnsvpn.rs     # /api/admin/mdnsvpn/* + /api/mdnsvpn/clients/*
                   # (inbound, key regen, per-client config downloads)
    dns.rs         # /api/admin/dns/* (bundle config, status, restart)
    setup.rs       # /api/setup/* wizard + v3 backup migrate
    routes.rs      # /api/information, /metrics/*, /cnf/:token
static/
  index.html       # SPA shell + inline CSS
  app.js           # SPA logic
  *.png *.svg      # branding
vendor/
  XRAY_VERSION          # pinned Xray-core version + uncompressed-ELF SHA-256
  TELEMT_VERSION        # pinned telemt version + SHA
  MDNSVPN_VERSION       # pinned MasterDnsVPN version + SHA
  DNS_BUNDLE_VERSION    # pinned dnscrypt-proxy / tor / PTs versions + SHAs
  LICENSES/             # preserved upstream LICENSE files (legal attribution)
  update.sh             # curation tool — bumps a binary to a new version
                        # (download/build, SHA-verify, gzip, rewrite pin)
  README.md             # provenance + curation procedure
  *.gz                  # IMMATERIAL — produced by scripts/build.sh from
                        # the pin files; gitignored, not committed
build.rs                # validates pin SHAs, embeds via include_bytes!,
                        # tolerates missing blobs (warns + disables cfg)
scripts/
  build.sh              # local end-to-end build: scripts/build.sh wraps
                        # vendor/update.sh per pinned binary, then runs
                        # cargo build --release --target …-musl
.github/workflows/
  build-release.yml     # CI version of the above + tag + GitHub release
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
| Container size | ~150 MB (Node + deps) | ~50 MB (Alpine + Rust binary with bundled Xray + telemt + MasterDnsVPN + AmneziaWG tools; +~20 MB if the DNS bundle is curated) |
| Cold start | seconds (Nuxt warm-up) | ~50 ms |
| RAM (idle) | 80-120 MB | 8-15 MB (each idle subprocess adds ~5 MB; budget for AWG only, AWG+Xray, AWG+Xray+telemt+mdnsvpn, etc.) |
| Distribution | docker image only | musl-static binary, runs unchanged on glibc / musl / any other libc x86_64 host |
| AmneziaWG params | Jc/Jmin/Jmax, S1-S4, H1-H4, I1-I5 | Same + per-peer AdvancedSecurity (kernel parity) + per-peer & UserConfig `additional_config` escape hatch |
| Xray VLESS+Reality+Vision | **no** | **yes** (bundled v26.3.27, supervised subprocess, per-peer UUIDs + shortIds, TLS dest probe) |
| Telegram MTProxy | **no** | **yes** (bundled telemt 3.4.11 — Fake-TLS / SNI fronting, per-user secrets, runtime HTTP control plane) |
| MasterDnsVPN DNS-tunnel | **no** | **yes** (bundled v2026.05.10 — encrypted TCP over DNS, NS-delegated subdomain, SOCKS5 / fixed-TCP forwarding) |
| Bundled DNS stack | **no** | **yes** (optional dnscrypt-proxy + tor + lyrebird/snowflake/webtunnel; off by default; tor opt-in independently) |
| DNS-leak prevention | client-side `DNS = …` only | nftables `dns-prerouting` DNAT + optional residual-drop chain — server-enforced regardless of client config |
| TOTP secret | server-generated | server-generated |
| CSP | `'unsafe-inline'` | `'unsafe-inline'` (inline event handlers) |
| Schema | Drizzle migrations | hand-rolled `CREATE TABLE IF NOT EXISTS` + idempotent `ALTER TABLE` |
| Plain WireGuard fallback | yes (`EXPERIMENTAL_AWG`/`OVERRIDE_AUTO_AWG`) | **no** — pure AmneziaWG (Gaming) + Xray Reality (Browsing) + telemt (Telegram) + MasterDnsVPN (DNS-tunnel) only |
| Reproducible build | n/a | vendored binaries are CI artifacts produced from `vendor/*_VERSION` pins; `scripts/build.sh` does the same locally |
| Tests | vitest unit suite | 400+ unit + integration tests across DB, API, security, AmneziaWG params, Xray config & supervisor, MTProxy + MasterDnsVPN config + envelope parsing, plus `--ignored` e2e tests that spawn real subprocesses |

If you need plain-WireGuard support, stay on upstream `awg-easy`. If you want any combination of AmneziaWG + Xray Reality + Telegram MTProxy + MasterDnsVPN DNS-tunnel in one self-supervising binary — with optional bundled DNS-leak prevention — this is the only option.

---

## License

[MIT](LICENSE)
