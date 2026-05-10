//! AmneziaWG/AmneziaWG orchestration module.
//!
//! Pure AmneziaWG — binary is always `awg`/`awg-quick`.

pub mod cli;
pub mod config_gen;
pub mod kernel;
pub mod params;

use anyhow::Result;

/// Generate a new AmneziaWG keypair via `awg genkey` / `awg pubkey`.
///
/// Avoids shelling out via `bash -c` — uses Command stdin instead so the
/// (already-validated) base64 private key never touches a shell parser.
pub fn generate_keypair() -> Result<(String, String)> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if !cfg!(target_os = "linux") {
        return Ok((String::new(), String::new()));
    }
    let private = cli::run("awg", &["genkey"])?;
    if private.is_empty() {
        return Ok((private, String::new()));
    }
    let mut child = Command::new("awg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut sin) = child.stdin.take() {
        sin.write_all(private.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "awg pubkey failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let public = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Ok((private, public))
}

/// Generate a new pre-shared key.
pub fn generate_psk() -> Result<String> {
    cli::run("awg", &["genpsk"])
}

/// Full AmneziaWG startup sequence.
pub fn startup() -> Result<()> {
    let mut iface = crate::db::get_interface()?;
    tracing::info!("Starting AmneziaWG interface {}", iface.name);

    // Generate keys if default placeholder
    if iface.private_key == "---default---" {
        tracing::info!("Generating new AmneziaWG keypair...");
        let (priv_key, pub_key) = generate_keypair()?;
        crate::db::update_key_pair(&pub_key, &priv_key)?;
        iface = crate::db::get_interface()?;
    }

    // Generate random AWG obfuscation params on first run
    if iface.h1.is_empty() || iface.h1 == "0" {
        tracing::info!("Generating random AmneziaWG obfuscation parameters...");
        let awg_params = params::generate_awg_params();
        crate::db::update_interface_awg_params(&awg_params)?;
        iface = crate::db::get_interface()?;
    }

    // Write config and bring up interface
    save_config().ok();
    cli::awg_down(&iface.name).ok(); // ignore if not yet up
    cli::awg_up(&iface.name)?;
    cli::awg_sync(&iface.name)?;

    // Apply firewall rules
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().ok();
    }

    tracing::info!("AmneziaWG interface {} started successfully", iface.name);
    Ok(())
}

/// Save AmneziaWG config to disk and sync to running interface.
pub fn save_config() -> Result<()> {
    let iface = crate::db::get_interface()?;
    let clients = crate::db::get_all_clients()?;
    let hooks = crate::db::get_hooks()?;

    let mut config = config_gen::generate_server_interface(&iface, &hooks)?;

    for client in &clients {
        if client.enabled {
            config.push_str("\n\n");
            config.push_str(&config_gen::generate_server_peer(client)?);
        }
    }
    config.push('\n');

    let path = format!("{}/{}.conf", crate::config::CONFIG.wg_conf_dir, iface.name);
    std::fs::write(&path, &config)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    cli::awg_sync(&iface.name)?;
    Ok(())
}

/// Generate a client's `.conf` file contents.
pub fn get_client_config(client_id: i64) -> Result<String> {
    let iface = crate::db::get_interface()?;
    let user_config = crate::db::get_user_config()?;
    let client = crate::db::get_client(client_id)?;
    config_gen::generate_client_config(&iface, &user_config, &client)
}

/// Dump running AmneziaWG status for all peers.
pub fn dump_peers(iface_name: &str) -> Result<Vec<cli::PeerDump>> {
    cli::awg_dump(iface_name)
}

/// Background cron job — expire clients.
pub fn cron_job() -> Result<()> {
    let clients = crate::db::get_all_clients()?;
    let mut needs_save = false;
    let now = chrono::Utc::now();

    for client in &clients {
        if !client.enabled {
            continue;
        }
        if let Some(ref expires) = client.expires_at {
            if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
                if now > exp {
                    tracing::info!("Client {} ({}) expired, disabling", client.id, client.name);
                    crate::db::toggle_client(client.id, false)?;
                    needs_save = true;
                }
            }
        }
    }

    if needs_save {
        save_config()?;
    }
    Ok(())
}

/// Graceful shutdown — take down the AmneziaWG interface.
pub fn shutdown() -> Result<()> {
    let iface = crate::db::get_interface()?;
    cli::awg_down(&iface.name).ok();
    Ok(())
}

/// Restart the AmneziaWG interface.
pub fn restart() -> Result<()> {
    let iface = crate::db::get_interface()?;
    cli::awg_down(&iface.name).ok();
    cli::awg_up(&iface.name)?;
    Ok(())
}
