//! Shell command execution and awg CLI wrappers.
//!
//! All AmneziaWG commands go through this module.
//! Binary is always `awg` / `awg-quick`.
//!
//! We deliberately avoid `bash -c` for any command that takes a
//! caller-provided argument, so that the interface name (which is read from
//! the database and could in principle be set to a malicious value by an
//! admin) cannot be used to inject arbitrary shell commands.

use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, anyhow};

/// Check whether the awg binary is available on this system.
fn awg_available() -> bool {
    Command::new("which")
        .arg("awg")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Execute a shell command via `bash -c` and return trimmed stdout.
/// Reserved for the firewall module which needs shell features (chained
/// rules, output redirection). Argv-only `run` helper below is preferred.
pub fn exec(cmd: &str) -> Result<String> {
    if !cfg!(target_os = "linux") || !awg_available() {
        return Ok(String::new());
    }
    let output = Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Command failed: {}: {}", cmd, stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run `prog arg1 arg2 ...` with no shell involvement. Returns trimmed stdout.
/// This is the preferred entry point for any command that takes
/// caller-controlled arguments.
pub fn run(prog: &str, args: &[&str]) -> Result<String> {
    run_argv(prog, args)
}

fn run_argv(prog: &str, args: &[&str]) -> Result<String> {
    if !cfg!(target_os = "linux") || !awg_available() {
        return Ok(String::new());
    }
    let output = Command::new(prog).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Command failed: {} {:?}: {}",
            prog,
            args,
            stderr
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Validate an interface name — argv-style execution prevents shell
/// injection, but a malformed name can still confuse `awg-quick`. Allow
/// only the AmneziaWG-conventional pattern.
fn validate_iface_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 15 {
        return Err(anyhow!("Invalid interface name length"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')) {
        return Err(anyhow!("Invalid characters in interface name"));
    }
    Ok(())
}

/// Bring up an AmneziaWG interface with awg-quick.
pub fn awg_up(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    run_argv("awg-quick", &["up", name]).map(|_| ())
}

/// Take down an AmneziaWG interface with awg-quick.
pub fn awg_down(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    run_argv("awg-quick", &["down", name]).map(|_| ())
}

/// Sync config without restarting the interface.
/// Uses process substitution: awg syncconf <name> <(awg-quick strip <name>)
pub fn awg_sync(name: &str) -> Result<()> {
    validate_iface_name(name)?;
    if !cfg!(target_os = "linux") || !awg_available() {
        return Ok(());
    }
    // Capture `awg-quick strip <name>` first, then pipe via stdin to
    // `awg syncconf <name> /dev/stdin`. Avoids the bash-only `<(...)`
    // syntax and the associated shell-injection surface.
    let stripped = run_argv("awg-quick", &["strip", name])?;
    let mut child = Command::new("awg")
        .args(["syncconf", name, "/dev/stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(stripped.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "awg syncconf failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// A single peer's runtime status from `awg show <if> dump`.
#[derive(Debug, Clone)]
pub struct PeerDump {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub latest_handshake: Option<chrono::DateTime<chrono::Utc>>,
    pub transfer_rx: i64,
    pub transfer_tx: i64,
}

/// Dump AmneziaWG peer status for an interface.
/// Parses tab-separated output from `awg show <name> dump`.
pub fn awg_dump(name: &str) -> Result<Vec<PeerDump>> {
    validate_iface_name(name)?;
    let output = run_argv("awg", &["show", name, "dump"])?;
    let mut peers = Vec::new();

    for line in output.lines().skip(1) {
        // skip header line
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() >= 8 {
            let handshake = if fields[4] == "0" {
                None
            } else {
                fields[4]
                    .parse::<i64>()
                    .ok()
                    .and_then(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                    })
            };
            peers.push(PeerDump {
                public_key: fields[0].to_string(),
                endpoint: if fields[2] == "(none)" {
                    None
                } else {
                    Some(fields[2].to_string())
                },
                latest_handshake: handshake,
                transfer_rx: fields[5].parse().unwrap_or(0),
                transfer_tx: fields[6].parse().unwrap_or(0),
            });
        }
    }
    Ok(peers)
}
