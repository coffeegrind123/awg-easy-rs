# Vendored third-party binaries

## Supported architectures

**x86_64-linux only.** arm64 / aarch64 was dropped intentionally — the
DNS bundle's pluggable transports have no upstream pre-built static
arm64 ELFs and no viable cross-build path that's worth maintaining.
`build.rs` only emits `xray_bundled`, `dns_bundled`, and `telemt_bundled`
cfgs for `("linux", "x86_64")`; other targets compile cleanly but
without the bundled binaries.

## `xray-linux-amd64.gz`

Pinned [XTLS/Xray-core](https://github.com/XTLS/Xray-core) v26.3.27 ELF,
gzip-compressed (level 9). The Rust binary embeds it via
`include_bytes!` and extracts to disk on first run — this is what makes
the "Xray runs in the same binary" UX possible without writing a Rust
port of VLESS/Reality/Vision.

### Provenance

Downloaded from the upstream release page on 2026-05-09:

- `Xray-linux-64.zip` — SHA256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` (verified against the upstream `Xray-linux-64.zip.dgst`)

The `xray` ELF was extracted from the zip and re-compressed with
`gzip -9`. The decompressed-ELF SHA-256 hash (used by the runtime
extractor to detect cache-staleness) is recorded in `XRAY_VERSION`.

### Licensing

Xray-core is distributed under the
[Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
Redistribution of the binary as part of awg-easy-rs is permitted under
MPL-2.0 §3.3 — the upstream source remains available at
<https://github.com/XTLS/Xray-core/tree/v26.3.27>.

### Updating

Bumping Xray is a three-step process:

1. Pick a new tag and download `Xray-linux-64.zip`.
2. Verify the zip SHA-256 against the upstream `.dgst` file.
3. Extract `xray`, run `gzip -9 -c xray > vendor/xray-linux-amd64.gz`, and update both `XRAY_VERSION` (version + uncompressed-ELF SHA) and the SHA above.

The build will refuse to start if `XRAY_VERSION` and the vendored blob disagree.

---

## DNS bundle (`dns_bundled` cfg)

Five binaries shipped together, each in `vendor/<name>-linux-amd64.gz`,
embedded the same way as Xray. `vendor/DNS_BUNDLE_VERSION` pins versions
and uncompressed-ELF SHA-256 sums. `build.rs` enables `cfg(dns_bundled)`
only when **all five** binaries have non-blank SHAs in the version file —
partial bundles are intentionally rejected so runtime supervisor code
can rely on every component being present.

### Components

| Binary | Upstream | How we sourced it |
|---|---|---|
| `dnscrypt-proxy` | <https://github.com/DNSCrypt/dnscrypt-proxy/releases> | Pre-built static-Go release asset (`dnscrypt-proxy-linux_x86_64-<ver>.tar.gz`). |
| `tor` | <https://www.torproject.org/download/tor/> | Built from source as a fully static-PIE binary in an Alpine Docker container, against musl-static `openssl-libs-static` + `libevent-static` + `zlib-static`. Distro-agnostic — runs on glibc, musl, or any other libc with no shared-library deps. |
| `lyrebird` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird> | Built from source (`./cmd/lyrebird`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |
| `snowflake` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake> | Built from source (`./client`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |
| `webtunnel` | <https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel> | Built from source (`./main/client`) with `CGO_ENABLED=0 -ldflags='-s -w -extldflags=-static'` — truly distro-agnostic static binary. |

Total compressed bundle: ~20 MB. Adds the same again to the shipped
binary (~18 MB → ~35–40 MB stripped).

### Curation procedure

The whole pipeline is automated by `vendor/update.sh`. To bump any of
the six binaries to a new upstream version:

```bash
vendor/update.sh xray            v26.3.28
vendor/update.sh dnscrypt-proxy  2.1.16
vendor/update.sh tor             0.4.9.9
vendor/update.sh lyrebird        0.8.2
vendor/update.sh snowflake       v2.13.2
vendor/update.sh webtunnel       v0.0.5
```

For each binary the script:

1. Downloads or builds (Docker for tor + the Go PTs; HTTPS-pulled
   release tarball for xray + dnscrypt-proxy).
2. Verifies signatures where stable upstream keys exist
   (`Xray-linux-64.zip.dgst` SHA, `tor-<ver>.tar.gz.sha256sum`).
   For dnscrypt-proxy the maintainer's minisign key has rotated
   without updating their public docs in the past, so a sig failure
   is a warning rather than a hard stop — bumps require manual
   out-of-band verification.
3. Confirms the resulting ELF is fully static (`file` reports
   `statically linked` or `static-pie`, no dynamic interpreter).
   Aborts if anything is dynamically linked — `awg-easy-rs` is
   distro-agnostic and a non-static dependency would regress that.
4. SHA-256-hashes the uncompressed ELF, gzips at level 9 into
   `vendor/<name>-linux-amd64.gz`.
5. Atomically rewrites the matching `<NAME>_VERSION` and
   `<NAME>_AMD64_SHA256` lines in the pin file (`XRAY_VERSION` or
   `DNS_BUNDLE_VERSION`).
6. Cross-verifies: re-hashes the on-disk gzipped blob and confirms
   the unpacked content matches the SHA the pin file now holds.
   Catches "wrote the wrong SHA into the wrong field" bugs.

After the script finishes, `cargo build --release` will pick up the
new blob and SHA automatically — `build.rs` re-reads the pin file and
fails the build if the vendored blob and the pinned SHA disagree.

### Manual fallback

If you'd rather curate by hand (or the script's Docker-based build
isn't an option), the underlying steps are:

1. Download the upstream archive.
2. Verify the upstream signature when available.
3. Extract the ELF, sanity-check: `file <path>` must report
   `ELF 64-bit LSB executable`; `<path> --version` should run.
4. `sha256sum <elf>` — record in the appropriate pin file.
5. `gzip -9 -c <elf> > vendor/<name>-linux-amd64.gz`.
6. Bump `<NAME>_VERSION` in the pin file.

The runtime extractor (`src/dns/runtime.rs`) verifies the SHA on every
extract, so a tampered or corrupt blob fails fast at startup rather than
silently launching a wrong binary.

### Provenance (current pinned versions)

Curated 2026-05-10:

- **`dnscrypt-proxy` 2.1.15** — `dnscrypt-proxy-linux_x86_64-2.1.15.tar.gz`
  downloaded over HTTPS from
  <https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/2.1.15/dnscrypt-proxy-linux_x86_64-2.1.15.tar.gz>.
  Signature verification (minisign) was attempted but the public key
  published in the README is stale relative to the 2.1.15 signing key
  (sig key id `79833371EA15D7E4`). Trust model: HTTPS chain-of-trust to
  `objects.githubusercontent.com`. **For future bumps, locate the
  current minisign public key from the dnscrypt-proxy maintainers and
  verify before vendoring.**
  Decompressed-ELF SHA-256: `0dca3463c7f596e36f1819f4c8b669c451c735415f04fb7e2cf4a0958e4f7119`.

- **`tor` 0.4.9.8** — built from source in an Alpine Docker container
  with `apk add openssl-libs-static libevent-static zlib-static`, then
  `./configure --enable-static-tor --enable-static-openssl
  --enable-static-libevent --enable-static-zlib --disable-asciidoc
  --disable-html-manual --disable-manpage --disable-systemd
  --disable-lzma --disable-zstd && make && strip src/app/tor`.
  Result: 8.8 MB static-PIE ELF, no shared-library deps (verified via
  `file` + smoke-test on a Debian glibc host). SHA-256:
  `03aa2c413ed30845cc7b5dd358148ce3ef51878a834b455d775a2d0d720e6ad9`.
- **`lyrebird` 0.8.1** — built from source at git tag `lyrebird-0.8.1`
  via `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static' ./cmd/lyrebird`
  (Go 1.23.4). SHA-256: `0776d1052a8a30e800b68740628ab867d5bf733fa53af968660996eb783f1ba4`.
- **`snowflake` v2.13.1** — built from source at git tag `v2.13.1` via
  `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static' ./client`
  (Go 1.24.4). SHA-256: `b3261406b38f065726b271475401e180738471c0f10a65faf94b83816c01332e`.
- **`webtunnel` v0.0.4** — built from source at git tag `v0.0.4` via
  `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -extldflags=-static' ./main/client`
  (Go 1.19.8). SHA-256: `0d684db99a1ca955d6cd6262686f8832e92180563e115b4f23ad31cc8fb3c954`.

### Default posture

The bundle is opt-in at runtime. Even with `cfg(dns_bundled)` set:

- **dnscrypt-proxy** is started only when the operator enables it via the
  admin UI / env var.
- **tor + the three pluggable transports** are NEVER started by default.
  Tor adds latency, exit-node trust assumptions, and bridge-fetching
  network calls — all unwelcome in the default install. Operators who
  want the censorship-circumvention features flip an explicit toggle.

### Licensing

| Binary | License |
|---|---|
| `dnscrypt-proxy` | ISC |
| `tor` | BSD-3-Clause |
| `lyrebird` | BSD-2-Clause |
| `snowflake` | BSD-3-Clause |
| `webtunnel` | BSD-3-Clause |

All five are permissive licenses that allow redistribution of the
unmodified binary as part of awg-easy-rs.

---

## `telemt-linux-amd64.gz` (`telemt_bundled` cfg)

Pinned [telemt/telemt](https://github.com/telemt/telemt) **v3.4.11** ELF,
gzip-compressed (level 9). telemt is a Rust + Tokio implementation of
Telegram's MTProto proxy with full Fake-TLS / SNI fronting (the
`ee`-prefix link variant), per-user secrets, replay protection, and
optional masking. Embedded the same way as Xray — `include_bytes!` at
build time, runtime extraction with SHA verification.

### Provenance

Downloaded from the [3.4.11 release](https://github.com/telemt/telemt/releases/tag/3.4.11)
on 2026-05-10:

- `telemt-x86_64-linux-musl.tar.gz` — SHA256 `513e1f951bc88320dffe40c1aec8eefe83f6d2c82c152cbf9e35a5a57a757ede` (verified against the upstream `telemt-x86_64-linux-musl.tar.gz.sha256`)

The single `telemt` ELF inside is `static-pie linked` (per `file(1)`), so
it runs unchanged on glibc, musl, or any other libc x86_64 host. It was
extracted from the tarball and re-compressed with `gzip -9`.
Decompressed-ELF SHA-256 (used by the runtime extractor to detect
cache-staleness): `9b003bc0ae0cd92e38635d5542a2fbfc14b6e5015904bcbf495a7462b10bbbbd` — recorded in `TELEMT_VERSION`.

### Licensing

telemt is distributed under the **Telemt Public License 3** (TPL 3), an
Apache-License-2.0–derived permissive license. The full text is mirrored
at [`vendor/LICENSES/TELEMT-LICENSE.md`](LICENSES/TELEMT-LICENSE.md);
upstream copy at <https://github.com/telemt/telemt/blob/main/LICENSE>.

Redistribution of the unmodified binary as part of awg-easy-rs is
permitted under the TPL 3, provided that all copyright notices, license
terms, and conditions in the License are preserved — `vendor/LICENSES/`
is exactly that preservation.

### Updating

Bumping telemt is a three-step process — `vendor/update.sh telemt
<version>` automates it:

1. Download the new `telemt-x86_64-linux-musl.tar.gz` and verify the
   `.sha256` companion against upstream.
2. Extract the `telemt` ELF; re-gzip with `gzip -9`.
3. Update `TELEMT_VERSION` (version + uncompressed-ELF SHA-256) and the
   tarball SHA recorded above.

The build will refuse to start if `TELEMT_VERSION` and the vendored blob
disagree.
