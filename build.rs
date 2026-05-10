//! Build-time embedding of the vendored ELFs for the target architecture.
//!
//! Two independent bundles, each gated by its own `cfg`:
//!
//! - `xray_bundled`  — Xray-core (single ELF, ~13 MB compressed) for the
//!   Browsing-mode VLESS+Reality+Vision flow. Pinned in
//!   `vendor/XRAY_VERSION`.
//! - `dns_bundled`   — DNS stack: dnscrypt-proxy, tor, lyrebird,
//!   snowflake, webtunnel. Five ELFs per architecture. Pinned in
//!   `vendor/DNS_BUNDLE_VERSION`. The bundle is all-or-nothing per
//!   target arch — partial bundles are intentionally rejected so
//!   runtime supervisor code can rely on every component being present.
//!
//! Both bundles surface their version + per-binary SHA-256 to the rest
//! of the crate via `cargo:rustc-env=AWG_EASY_*` constants so the
//! runtime extractor can verify-on-extract and the `/about` page can
//! display what shipped.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

/// Each name here corresponds to a `<NAME>_VERSION` /
/// `<NAME>_AMD64_SHA256` pair in `vendor/DNS_BUNDLE_VERSION` and a
/// `vendor/<file>-linux-amd64.gz` blob. Adding a binary to the bundle
/// means appending one row here + dropping the blob + updating the
/// version file. (x86_64 only — arm64 was dropped intentionally.)
const DNS_BUNDLE_BINARIES: &[DnsBinary] = &[
    DnsBinary {
        // Logical name used in env-var prefix / sha key
        env_prefix: "DNSCRYPT_PROXY",
        // Filename root (must match `vendor/<file>-linux-<arch>.gz`)
        file_root: "dnscrypt-proxy",
    },
    DnsBinary { env_prefix: "TOR",       file_root: "tor" },
    DnsBinary { env_prefix: "LYREBIRD",  file_root: "lyrebird" },
    DnsBinary { env_prefix: "SNOWFLAKE", file_root: "snowflake" },
    DnsBinary { env_prefix: "WEBTUNNEL", file_root: "webtunnel" },
];

struct DnsBinary {
    env_prefix: &'static str,
    file_root: &'static str,
}

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    process_xray_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
    process_dns_bundle(&target_os, &target_arch, &out_dir, &manifest_dir);
}

// ---------------------------------------------------------------------------
// Xray bundle (existing)
// ---------------------------------------------------------------------------

fn process_xray_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &PathBuf,
    manifest_dir: &PathBuf,
) {
    println!("cargo:rerun-if-changed=vendor/XRAY_VERSION");
    println!("cargo:rerun-if-changed=vendor/xray-linux-amd64.gz");

    let version_path = manifest_dir.join("vendor/XRAY_VERSION");
    let version_text = fs::read_to_string(&version_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", version_path.display()));
    let kv = parse_kv(&version_text);
    let xray_version = kv
        .get("XRAY_VERSION")
        .expect("XRAY_VERSION not set in vendor/XRAY_VERSION");

    // x86_64 is the only supported target. arm64 was removed intentionally
    // (see vendor/README.md).
    let bundle = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("xray-linux-amd64.gz", "XRAY_AMD64_SHA256")),
        _ => None,
    };

    if let Some((blob_name, sha_key)) = bundle {
        let blob_src = manifest_dir.join("vendor").join(blob_name);
        let blob_dst = out_dir.join("xray.gz");
        fs::copy(&blob_src, &blob_dst)
            .unwrap_or_else(|e| panic!("copy {} → {}: {e}", blob_src.display(), blob_dst.display()));

        let expected_sha = kv.get(sha_key).unwrap_or_else(|| {
            panic!("{sha_key} missing from vendor/XRAY_VERSION but {target_arch} build expects it")
        });

        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256={expected_sha}");
        println!("cargo:rustc-cfg=xray_bundled");
        println!("cargo:rustc-check-cfg=cfg(xray_bundled)");
    } else {
        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256=");
        println!("cargo:rustc-check-cfg=cfg(xray_bundled)");
        println!(
            "cargo:warning=Xray bundled mode is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without Browsing-mode support."
        );
    }
}

// ---------------------------------------------------------------------------
// DNS bundle
// ---------------------------------------------------------------------------

fn process_dns_bundle(
    target_os: &str,
    target_arch: &str,
    out_dir: &PathBuf,
    manifest_dir: &PathBuf,
) {
    println!("cargo:rerun-if-changed=vendor/DNS_BUNDLE_VERSION");
    for bin in DNS_BUNDLE_BINARIES {
        println!(
            "cargo:rerun-if-changed=vendor/{}-linux-amd64.gz",
            bin.file_root
        );
    }
    // Always declare the cfg so `#[cfg(dns_bundled)]` doesn't warn on
    // builds where the bundle is absent.
    println!("cargo:rustc-check-cfg=cfg(dns_bundled)");

    let version_path = manifest_dir.join("vendor/DNS_BUNDLE_VERSION");
    let version_text = match fs::read_to_string(&version_path) {
        Ok(s) => s,
        Err(e) => {
            // Non-fatal — DNS bundling is opt-in. Build proceeds without it.
            println!(
                "cargo:warning=DNS bundle version file missing ({}); skipping DNS bundle",
                e
            );
            for bin in DNS_BUNDLE_BINARIES {
                println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION=", bin.env_prefix);
                println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256=", bin.env_prefix);
            }
            return;
        }
    };
    let kv = parse_kv(&version_text);

    // Map target_arch to (suffix used in filenames, suffix used in SHA keys).
    // x86_64 is the only supported target — arm64 was removed.
    let arch = match (target_os, target_arch) {
        ("linux", "x86_64") => Some(("amd64", "AMD64")),
        _ => None,
    };

    let Some((file_arch, sha_arch)) = arch else {
        println!(
            "cargo:warning=DNS bundle is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without bundled DNS support."
        );
        for bin in DNS_BUNDLE_BINARIES {
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION=", bin.env_prefix);
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256=", bin.env_prefix);
        }
        return;
    };

    // First pass: gate on completeness. Every binary in the bundle must
    // have both a non-empty version AND a non-empty SHA for THIS arch.
    // Partial bundles → no `dns_bundled` cfg, supervisor code stays out
    // of the build entirely. We still emit per-binary env vars (blank
    // if missing) so /about can show what would have shipped.
    let mut missing: Vec<String> = Vec::new();
    for bin in DNS_BUNDLE_BINARIES {
        let ver_key = format!("{}_VERSION", bin.env_prefix);
        let sha_key = format!("{}_{}_SHA256", bin.env_prefix, sha_arch);
        let ver = kv.get(&ver_key).map(|s| s.as_str()).unwrap_or("");
        let sha = kv.get(&sha_key).map(|s| s.as_str()).unwrap_or("");
        let blob_path = manifest_dir
            .join("vendor")
            .join(format!("{}-linux-{}.gz", bin.file_root, file_arch));
        if ver.is_empty() {
            missing.push(format!("{} (no version pinned)", bin.env_prefix));
        } else if sha.is_empty() {
            missing.push(format!(
                "{} (no {} SHA pinned)",
                bin.env_prefix, sha_arch
            ));
        } else if !blob_path.exists() {
            missing.push(format!(
                "{} (vendor blob {} missing)",
                bin.env_prefix,
                blob_path.display()
            ));
        }
    }

    if !missing.is_empty() {
        println!(
            "cargo:warning=DNS bundle incomplete for {target_arch}, building without dns_bundled: {}",
            missing.join(", ")
        );
        for bin in DNS_BUNDLE_BINARIES {
            let ver = kv
                .get(&format!("{}_VERSION", bin.env_prefix))
                .cloned()
                .unwrap_or_default();
            let sha = kv
                .get(&format!("{}_{}_SHA256", bin.env_prefix, sha_arch))
                .cloned()
                .unwrap_or_default();
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION={ver}", bin.env_prefix);
            println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256={sha}", bin.env_prefix);
        }
        return;
    }

    // All present — copy each blob to OUT_DIR with a stable name the
    // runtime can `include_bytes!`. Names mirror the vendor file root.
    for bin in DNS_BUNDLE_BINARIES {
        let blob_src = manifest_dir
            .join("vendor")
            .join(format!("{}-linux-{}.gz", bin.file_root, file_arch));
        let blob_dst = out_dir.join(format!("{}.gz", bin.file_root));
        fs::copy(&blob_src, &blob_dst).unwrap_or_else(|e| {
            panic!(
                "copy {} → {}: {e}",
                blob_src.display(),
                blob_dst.display()
            )
        });

        let ver = &kv[&format!("{}_VERSION", bin.env_prefix)];
        let sha = &kv[&format!("{}_{}_SHA256", bin.env_prefix, sha_arch)];
        println!("cargo:rustc-env=AWG_EASY_DNS_{}_VERSION={ver}", bin.env_prefix);
        println!("cargo:rustc-env=AWG_EASY_DNS_{}_SHA256={sha}", bin.env_prefix);
    }
    println!("cargo:rustc-cfg=dns_bundled");
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// Parse `KEY = VALUE` lines into a map. Comments (`#`) and blank lines
/// are skipped. Whitespace around the `=` is tolerated. Identical to the
/// previous inline parser; lifted out so both bundle handlers can share it.
fn parse_kv(text: &str) -> HashMap<String, String> {
    let mut kv = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    kv
}
