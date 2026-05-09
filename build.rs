//! Build-time embedding of the vendored Xray-core ELF for the target
//! architecture. Reads `vendor/XRAY_VERSION` for the pinned version + the
//! expected uncompressed-ELF SHA-256, copies the matching `vendor/xray-linux-*.gz`
//! to `OUT_DIR/xray.gz`, and exposes both as `env!()` constants so
//! `src/xray/runtime.rs` can `include_bytes!` the blob and verify it on
//! extract.
//!
//! Refuses to build (with a clear message) for unsupported architectures —
//! the Xray supervisor isn't compiled in on those targets. Hosts that don't
//! ship Xray simply build awg-easy-rs without the bundled binary; the
//! ServerOnly AmneziaWG flow remains identical.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=vendor/XRAY_VERSION");
    println!("cargo:rerun-if-changed=vendor/xray-linux-amd64.gz");
    println!("cargo:rerun-if-changed=vendor/xray-linux-arm64.gz");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));

    // Parse vendor/XRAY_VERSION into a key/value map.
    let version_path = manifest_dir.join("vendor/XRAY_VERSION");
    let version_text = fs::read_to_string(&version_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", version_path.display()));
    let mut kv: HashMap<String, String> = HashMap::new();
    for line in version_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    let xray_version = kv.get("XRAY_VERSION").expect("XRAY_VERSION not set in vendor/XRAY_VERSION");

    // Map target_arch → (vendor blob filename, expected ELF SHA-256 key).
    // Anything not in this table builds without the Xray supervisor.
    let bundle = match (target_os.as_str(), target_arch.as_str()) {
        ("linux", "x86_64") => Some(("xray-linux-amd64.gz", "XRAY_AMD64_SHA256")),
        ("linux", "aarch64") => Some(("xray-linux-arm64.gz", "XRAY_ARM64_SHA256")),
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

        // Surface the version + expected ELF SHA to the rest of the crate.
        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256={expected_sha}");
        println!("cargo:rustc-cfg=xray_bundled");
        println!("cargo:rustc-check-cfg=cfg(xray_bundled)");
    } else {
        // Still emit the version string so /about can mention it, but no
        // bundled blob and no `xray_bundled` cfg gate.
        println!("cargo:rustc-env=AWG_EASY_XRAY_VERSION={xray_version}");
        println!("cargo:rustc-env=AWG_EASY_XRAY_SHA256=");
        println!("cargo:rustc-check-cfg=cfg(xray_bundled)");
        println!(
            "cargo:warning=Xray bundled mode is not available for target {target_os}-{target_arch}; \
             awg-easy-rs will build without Browsing-mode support."
        );
    }
}
