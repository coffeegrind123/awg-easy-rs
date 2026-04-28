//! Shell command execution and awg CLI wrappers.
//!
//! All WireGuard/AmneziaWG commands go through this module.
//! Binary is always `awg` / `awg-quick`.

use std::process::Command;
use anyhow::{Result, anyhow};

/// Check whether the awg binary is available on this system.
fn awg_available() -> bool {
    Command::new("which")
        .arg("awg")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Execute a shell command and return trimmed stdout.
/// Returns empty string on non-Linux platforms or when awg is unavailable
/// (for dev/testing without WireGuard installed).
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

/// Bring up an AmneziaWG/WireGuard interface with awg-quick.
pub fn awg_up(name: &str) -> Result<()> {
    exec(&format!("awg-quick up {}", name)).map(|_| ())
}

/// Take down an AmneziaWG/WireGuard interface with awg-quick.
pub fn awg_down(name: &str) -> Result<()> {
    exec(&format!("awg-quick down {}", name)).map(|_| ())
}

/// Sync config without restarting the interface.
/// Uses process substitution: awg syncconf <name> <(awg-quick strip <name>)
pub fn awg_sync(name: &str) -> Result<()> {
    exec(&format!(
        "awg syncconf {} <(awg-quick strip {})",
        name, name
    ))
    .map(|_| ())
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

/// Dump WireGuard/AmneziaWG peer status for an interface.
/// Parses tab-separated output from `awg show <name> dump`.
pub fn awg_dump(name: &str) -> Result<Vec<PeerDump>> {
    let output = exec(&format!("awg show {} dump", name))?;
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
