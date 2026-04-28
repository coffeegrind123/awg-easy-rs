//! iptables/ip6tables per-client firewall.
//!
//! When firewall_enabled is true, creates a custom chain WG_CLIENTS,
//! inserts a jump from FORWARD, adds per-client ACCEPT rules, and
//! drops everything else.

use anyhow::{Result, anyhow};
use std::process::Command;

const CHAIN: &str = "WG_CLIENTS";

fn bash(cmd: &str) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Ok(String::new());
    }
    let out = Command::new("bash").arg("-c").arg(cmd).output()?;
    if !out.status.success() {
        return Err(anyhow!("{}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn shell_escape(s: &str) -> String {
    // Wrap in single quotes, escaping any embedded single quotes.
    // Single-quote strings in shell don't expand anything.
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn try_bash(cmd: &str) { let _ = bash(cmd); }

pub fn is_available() -> bool {
    Command::new("iptables").arg("--version").output()
        .map(|o| o.status.success()).unwrap_or(false)
}

pub fn init_chain(iface: &str) -> Result<()> {
    try_bash(&format!("iptables -N {} 2>/dev/null", CHAIN));
    try_bash(&format!("ip6tables -N {} 2>/dev/null", CHAIN));
    try_bash(&format!("iptables -C FORWARD -i {} -j {} 2>/dev/null || iptables -I FORWARD 1 -i {} -j {}", iface, CHAIN, iface, CHAIN));
    try_bash(&format!("ip6tables -C FORWARD -i {} -j {} 2>/dev/null || ip6tables -I FORWARD 1 -i {} -j {}", iface, CHAIN, iface, CHAIN));
    Ok(())
}

pub fn flush_chain() -> Result<()> {
    bash(&format!("iptables -F {} 2>/dev/null || true", CHAIN))?;
    bash(&format!("ip6tables -F {} 2>/dev/null || true", CHAIN))?;
    Ok(())
}

pub fn remove_filtering(iface: &str) -> Result<()> {
    try_bash(&format!("iptables -D FORWARD -i {} -j {} 2>/dev/null", iface, CHAIN));
    try_bash(&format!("ip6tables -D FORWARD -i {} -j {} 2>/dev/null", iface, CHAIN));
    try_bash(&format!("iptables -F {} 2>/dev/null", CHAIN));
    try_bash(&format!("ip6tables -F {} 2>/dev/null", CHAIN));
    try_bash(&format!("iptables -X {} 2>/dev/null", CHAIN));
    try_bash(&format!("ip6tables -X {} 2>/dev/null", CHAIN));
    Ok(())
}

/// Full rebuild of firewall rules from database state.
pub fn rebuild_rules() -> Result<()> {
    let iface = crate::db::get_interface()?;
    let enable_ipv6 = !crate::config::CONFIG.disable_ipv6;

    if !iface.firewall_enabled {
        return remove_filtering(&iface.name);
    }

    let clients = crate::db::get_all_clients()?;
    let user_config = crate::db::get_user_config()?;
    let default_ips: Vec<String> =
        serde_json::from_str(&user_config.default_allowed_ips).unwrap_or_default();

    init_chain(&iface.name)?;
    flush_chain()?;

    for client in &clients {
        if !client.enabled { continue; }
        apply_client_rules(client, &default_ips, enable_ipv6)?;
    }

    bash(&format!("iptables -A {} -j DROP", CHAIN))?;
    if enable_ipv6 {
        bash(&format!("ip6tables -A {} -j DROP", CHAIN))?;
    }
    Ok(())
}

fn apply_client_rules(
    client: &crate::db::Client,
    default_ips: &[String],
    enable_ipv6: bool,
) -> Result<()> {
    let targets: Vec<String> = match client.firewall_ips.as_deref() {
        Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
        _ => match client.allowed_ips.as_deref() {
            Some(s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
            _ => default_ips.to_vec(),
        },
    };

    let src4 = client.ipv4_address.as_deref().unwrap_or("0.0.0.0");
    let src6 = client.ipv6_address.as_deref().unwrap_or("::");
    let comment = sanitize(&client.name, client.id);

    for t in &targets {
        let (ip, port, proto) = parse(t)?;
        let is_v6 = ip.contains(':');
        if is_v6 && !enable_ipv6 { continue; }
        let src = if is_v6 { src6 } else { src4 };
        let bin = if is_v6 { "ip6tables" } else { "iptables" };

        for rule in gen_rules(src, ip, port, proto, &comment) {
            bash(&format!("{} {}", bin, rule))?;
        }
    }
    Ok(())
}

fn sanitize(name: &str, id: i64) -> String {
    let s: String = name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        .take(200).collect();
    format!("client {}: {}", id, s)
}

fn parse(entry: &str) -> Result<(&str, Option<u16>, Option<&str>)> {
    let (body, proto) = if entry.ends_with("/tcp") {
        (&entry[..entry.len()-4], Some("tcp"))
    } else if entry.ends_with("/udp") {
        (&entry[..entry.len()-4], Some("udp"))
    } else { (entry, None) };

    if body.starts_with('[') {
        if let Some(end) = body.find(']') {
            let ip = &body[1..end];
            let rest = &body[end+1..];
            if rest.starts_with(':') {
                return Ok((ip, Some(rest[1..].parse()?), proto));
            }
            return Ok((ip, None, proto));
        }
    }

    if body.matches(':').count() <= 1 {
        if let Some(col) = body.rfind(':') {
            let maybe_port = &body[col+1..];
            if maybe_port.chars().all(|c| c.is_ascii_digit()) {
                return Ok((&body[..col], Some(maybe_port.parse()?), proto));
            }
        }
    }

    Ok((body, None, proto))
}

fn gen_rules(src: &str, dst: &str, port: Option<u16>, proto: Option<&str>, comment: &str) -> Vec<String> {
    let mut rules = Vec::new();
    let base = format!("-A {} -s {} -d {}", CHAIN, shell_escape(src), shell_escape(dst));

    if let Some(p) = port {
        let do_tcp = proto.is_none() || proto == Some("tcp");
        let do_udp = proto.is_none() || proto == Some("udp");
        if do_tcp {
            rules.push(format!("{} -p tcp --dport {} -m comment --comment {} -j ACCEPT", base, p, shell_escape(comment)));
        }
        if do_udp {
            rules.push(format!("{} -p udp --dport {} -m comment --comment {} -j ACCEPT", base, p, shell_escape(comment)));
        }
    } else {
        rules.push(format!("{} -m comment --comment {} -j ACCEPT", base, shell_escape(comment)));
    }

    rules
}
