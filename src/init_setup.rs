//! First-run auto-provisioning shared by the `INIT_ENABLED` env path.
//!
//! The binary's `main` reads the `INIT_*` environment into [`InitSetupParams`]
//! and calls [`provision_initial_setup`]; keeping the provisioning logic here
//! (rather than inline in `main.rs`) makes it unit-testable without a process
//! environment.

use anyhow::{bail, Result};

use crate::{auth, db};

/// Inputs for first-run auto-setup. Borrowed so the caller can hand over slices
/// of its own config without cloning.
pub struct InitSetupParams<'a> {
    pub username: &'a str,
    pub password: &'a str,
    pub host: Option<&'a str>,
    pub port: Option<u16>,
    pub ipv4_cidr: Option<&'a str>,
    pub ipv6_cidr: Option<&'a str>,
    pub dns: Option<&'a [String]>,
    pub allowed_ips: Option<&'a [String]>,
}

/// Provision the first admin user and base interface settings, then mark the
/// setup wizard complete. Idempotent: returns `Ok(false)` without touching the
/// DB when a user already exists. Returns `Ok(true)` when it provisioned.
pub fn provision_initial_setup(p: &InitSetupParams) -> Result<bool> {
    if db::get_user_count().unwrap_or(0) > 0 {
        return Ok(false);
    }
    if p.password.chars().count() < 12 {
        bail!("INIT_PASSWORD must be at least 12 characters");
    }

    let hash = auth::hash_password(p.password)?;
    db::create_user(&db::CreateUserParams {
        username: p.username.into(),
        password: hash,
        email: None,
        name: "Admin".into(),
        role: 1,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })?;

    if let Some(host) = p.host {
        let port = p.port.unwrap_or(51820) as i64;
        db::update_host_port(host, port)?;
        let mut iface_fields = db::UpdateMap::new();
        iface_fields.insert("port".into(), port.to_string());
        if let Some(cidr) = p.ipv4_cidr {
            iface_fields.insert("ipv4_cidr".into(), cidr.into());
        }
        if let Some(cidr) = p.ipv6_cidr {
            iface_fields.insert("ipv6_cidr".into(), cidr.into());
        }
        db::update_interface(&iface_fields)?;
    }

    if let Some(dns) = p.dns {
        // Each entry lands in the generated WireGuard `DNS = …` line — reject
        // anything that isn't a bare IP so a hostile INIT_DNS can't inject
        // config directives.
        for e in dns {
            if e.trim().parse::<std::net::IpAddr>().is_err() {
                bail!("INIT_DNS entry {e:?} is not a valid IP address");
            }
        }
        let mut fields = db::UpdateMap::new();
        fields.insert(
            "default_dns".into(),
            serde_json::to_string(dns).unwrap_or_else(|_| "[]".into()),
        );
        db::update_user_config(&fields)?;
    }
    if let Some(allowed) = p.allowed_ips {
        // Each entry flows into the per-client nftables transaction — reject
        // anything that isn't an IP/CIDR literal.
        for e in allowed {
            crate::api::clients::validate_routing_entry(e)
                .map_err(|m| anyhow::anyhow!("INIT_ALLOWED_IPS entry: {m}"))?;
        }
        let mut fields = db::UpdateMap::new();
        fields.insert(
            "default_allowed_ips".into(),
            serde_json::to_string(allowed).unwrap_or_else(|_| "[]".into()),
        );
        db::update_user_config(&fields)?;
    }

    db::set_setup_step(0)?;
    Ok(true)
}
