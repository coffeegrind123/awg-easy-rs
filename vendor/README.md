# Vendored third-party binaries

## `xray-linux-amd64.gz` / `xray-linux-arm64.gz`

Pinned [XTLS/Xray-core](https://github.com/XTLS/Xray-core) v26.3.27 ELF
binaries, gzip-compressed (level 9). The Rust binary embeds these via
`include_bytes!` and extracts the matching one to disk on first run —
this is what makes the "Xray runs in the same binary" UX possible
without writing a Rust port of VLESS/Reality/Vision.

### Provenance

Downloaded from the upstream release page on 2026-05-09:

- `Xray-linux-64.zip` — SHA256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` (verified against the upstream `Xray-linux-64.zip.dgst`)
- `Xray-linux-arm64-v8a.zip` — SHA256 `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c` (verified against the upstream `Xray-linux-arm64-v8a.zip.dgst`)

The `xray` ELF was extracted from each zip and re-compressed with
`gzip -9`. Decompressed-ELF SHA-256 hashes (used by the runtime
extractor to detect cache-staleness) are recorded in `XRAY_VERSION`.

### Licensing

Xray-core is distributed under the
[Mozilla Public License 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE).
Redistribution of the binary as part of awg-easy-rs is permitted under
MPL-2.0 §3.3 — the upstream source remains available at
<https://github.com/XTLS/Xray-core/tree/v26.3.27>.

### Updating

Bumping Xray is a three-step process:

1. Pick a new tag and download `Xray-linux-64.zip` + `Xray-linux-arm64-v8a.zip`.
2. Verify both zip SHA-256 against the upstream `.dgst` files.
3. Extract `xray` from each zip, run `gzip -9 -c xray > vendor/xray-linux-<arch>.gz`, and update both `XRAY_VERSION` (version + uncompressed-ELF SHAs) and the SHAs above.

The build will refuse to start if `XRAY_VERSION` and the vendored blobs disagree.
