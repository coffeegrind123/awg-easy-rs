//! Per-client firewall, native nftables.
//!
//! All our rules live inside one `inet awg-easy-rs` table — the same
//! table the AmneziaWG PostUp hook creates for masquerade / accept rules.
//! Sharing the table means we can rebuild *just* the per-client chain
//! atomically without disturbing the operator's NAT / forwarding setup.
//!
//! Layout we expect:
//!
//! ```text
//! table inet awg-easy-rs {
//!   chain forward {                          # owned by hooks
//!     type filter hook forward priority filter; policy accept;
//!     iifname "awg0" jump wg-clients
//!     oifname "awg0" jump wg-clients
//!   }
//!   chain wg-clients {                       # owned by this module
//!     # per-client rules, then a final `drop` (when firewall_enabled)
//!     # or empty (when firewall_disabled — all traffic returns and is
//!     # accepted by the forward chain's policy)
//!   }
//!   chain nat-postrouting { ... }            # owned by hooks
//!   chain filter-input    { ... }            # owned by hooks
//! }
//! ```
//!
//! The per-client chain is built via a single `nft -f -` transaction so
//! the rebuild is atomic — peers never see a half-applied ruleset.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Result};

/// Single source of truth for the table name. Hooks reference it from
/// the DB-stored PostUp/PostDown templates; everything in this module
/// references it from here.
pub const TABLE: &str = "awg-easy-rs";

/// Per-client filtering chain. Lives inside `TABLE`.
const CHAIN: &str = "wg-clients";

/// Run a single `nft` invocation with the given argv. argv-only — no
/// shell — so peer names containing quotes / backticks / shell metas
/// can never escape into command interpretation.
fn nft(args: &[&str]) -> Result<String> {
    if !cfg!(target_os = "linux") {
        return Ok(String::new());
    }
    let out = Command::new("nft").args(args).output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Apply a multi-statement nftables transaction atomically by piping it
/// to `nft -f -`. The rule body is freshly assembled every call so a
/// caller can't end up with stale rules from a previous rebuild.
fn nft_apply(transaction: &str) -> Result<()> {
    if !cfg!(target_os = "linux") {
        return Ok(());
    }
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow!("nft child has no stdin"))?;
        stdin.write_all(transaction.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft transaction failed: {}\n--- transaction ---\n{}",
            String::from_utf8_lossy(&out.stderr).trim(),
            transaction
        ));
    }
    Ok(())
}

pub fn is_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Make sure the table + per-client chain exist, and that the forward
/// chain has a jump into us. Idempotent — `add table`/`add chain` /
/// `add rule` are tolerant of pre-existing definitions, and we only
/// add the jump if it isn't already there.
pub fn init_chain(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    let txn = format!(
        "add table inet {table}\n\
         add chain inet {table} {chain}\n\
         add chain inet {table} forward {{ type filter hook forward priority filter; policy accept; }}\n",
        table = TABLE,
        chain = CHAIN,
    );
    nft_apply(&txn)?;

    // The `add rule … jump wg-clients` form is NOT idempotent — it
    // appends a duplicate every time. We list the chain first and only
    // add the jump if the literal rule isn't already there.
    let listing = nft(&["list", "chain", "inet", TABLE, "forward"]).unwrap_or_default();
    let want_in = format!("iifname \"{iface}\" jump {CHAIN}");
    let want_out = format!("oifname \"{iface}\" jump {CHAIN}");
    let mut adds = String::new();
    if !listing.contains(&want_in) {
        adds.push_str(&format!(
            "add rule inet {TABLE} forward iifname \"{iface}\" jump {CHAIN}\n"
        ));
    }
    if !listing.contains(&want_out) {
        adds.push_str(&format!(
            "add rule inet {TABLE} forward oifname \"{iface}\" jump {CHAIN}\n"
        ));
    }
    if !adds.is_empty() {
        nft_apply(&adds)?;
    }
    Ok(())
}

/// Empty the per-client chain. Doesn't touch the forward chain or the
/// table itself — those are owned by the hooks.
pub fn flush_chain() -> Result<()> {
    nft_apply(&format!("flush chain inet {TABLE} {CHAIN}\n"))
}

/// Toggle off: flush the chain and remove the forward-chain jumps. We
/// leave the empty `wg-clients` chain in place so re-enabling is a
/// pure rebuild without having to recreate it.
pub fn remove_filtering(iface: &str) -> Result<()> {
    let iface = sanitize_iface(iface);
    flush_chain()?;

    // Locate and delete the jump rules by handle. `--handle --numeric`
    // gives us `… # handle N` suffix on each rule line.
    let listing = nft(&["--handle", "--numeric", "list", "chain", "inet", TABLE, "forward"])
        .unwrap_or_default();
    let mut deletions = String::new();
    for line in listing.lines() {
        let line = line.trim();
        if line.contains(&format!("iifname \"{iface}\" jump {CHAIN}"))
            || line.contains(&format!("oifname \"{iface}\" jump {CHAIN}"))
        {
            if let Some(handle) = parse_handle(line) {
                deletions.push_str(&format!(
                    "delete rule inet {TABLE} forward handle {handle}\n"
                ));
            }
        }
    }
    if !deletions.is_empty() {
        // Best-effort: a missing handle is not an error worth aborting
        // the whole shutdown for.
        let _ = nft_apply(&deletions);
    }
    Ok(())
}

/// Full rebuild from DB state. Single atomic `nft -f -` apply.
pub fn rebuild_rules() -> Result<()> {
    let iface = crate::db::get_interface()?;
    let enable_ipv6 = !crate::config::CONFIG.disable_ipv6;

    if !iface.firewall_enabled {
        return remove_filtering(&iface.name);
    }

    init_chain(&iface.name)?;

    let clients = crate::db::get_all_clients()?;
    let user_config = crate::db::get_user_config()?;
    let default_ips: Vec<String> =
        serde_json::from_str(&user_config.default_allowed_ips).unwrap_or_default();

    let mut txn = String::new();
    txn.push_str(&format!("flush chain inet {TABLE} {CHAIN}\n"));
    for client in &clients {
        if !client.enabled {
            continue;
        }
        append_client_rules(&mut txn, client, &default_ips, enable_ipv6)?;
    }
    // Final default-deny.
    txn.push_str(&format!("add rule inet {TABLE} {CHAIN} drop\n"));

    nft_apply(&txn)
}

fn append_client_rules(
    txn: &mut String,
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
    let comment = sanitize_comment(&client.name, client.id);

    for t in &targets {
        let (ip, port, proto) = parse_target(t)?;
        let is_v6 = ip.contains(':');
        if is_v6 && !enable_ipv6 {
            continue;
        }
        let src = if is_v6 { src6 } else { src4 };

        for rule in gen_rules(src, ip, port, proto, &comment, is_v6) {
            txn.push_str(&rule);
            txn.push('\n');
        }
    }
    Ok(())
}

/// Allow only chars nft is happy to put inside a `comment "…"` literal.
/// The transaction is fed via stdin so the shell can't interfere, but
/// nft itself rejects unescaped `"` inside the comment string.
fn sanitize_comment(name: &str, id: i64) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
        .take(80) // nft caps comments at 128 — leave headroom for the prefix
        .collect();
    format!("client {id}: {s}")
}

/// Interface names already pass `[A-Za-z0-9_-]{1,15}` validation
/// upstream of every call site, but we redo it here so this module is
/// safe to call directly from tests.
fn sanitize_iface(iface: &str) -> String {
    iface
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        .take(15)
        .collect()
}

fn parse_target(entry: &str) -> Result<(&str, Option<u16>, Option<&str>)> {
    let (body, proto) = if let Some(rest) = entry.strip_suffix("/tcp") {
        (rest, Some("tcp"))
    } else if let Some(rest) = entry.strip_suffix("/udp") {
        (rest, Some("udp"))
    } else {
        (entry, None)
    };

    if body.starts_with('[') {
        if let Some(end) = body.find(']') {
            let ip = &body[1..end];
            let rest = &body[end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                return Ok((ip, Some(port_str.parse()?), proto));
            }
            return Ok((ip, None, proto));
        }
    }

    if body.matches(':').count() <= 1 {
        if let Some(col) = body.rfind(':') {
            let maybe_port = &body[col + 1..];
            if maybe_port.chars().all(|c| c.is_ascii_digit()) {
                return Ok((&body[..col], Some(maybe_port.parse()?), proto));
            }
        }
    }

    Ok((body, None, proto))
}

/// Build the nft `add rule …` lines for one (src, dst, [port], [proto]) triple.
/// `is_v6` switches the address-family qualifier to `ip6`. We use `inet`
/// table family which lets us mix both in the same chain.
fn gen_rules(
    src: &str,
    dst: &str,
    port: Option<u16>,
    proto: Option<&str>,
    comment: &str,
    is_v6: bool,
) -> Vec<String> {
    let fam = if is_v6 { "ip6" } else { "ip" };
    let prefix = format!(
        "add rule inet {TABLE} {CHAIN} {fam} saddr {src} {fam} daddr {dst}"
    );
    let mut out = Vec::new();

    let mk = |proto_clause: &str, port_clause: &str| {
        format!(
            "{prefix}{proto}{port} accept comment \"{comment}\"",
            proto = proto_clause,
            port = port_clause,
        )
    };

    if let Some(p) = port {
        let do_tcp = proto.is_none() || proto == Some("tcp");
        let do_udp = proto.is_none() || proto == Some("udp");
        if do_tcp {
            out.push(mk(" tcp", &format!(" dport {p}")));
        }
        if do_udp {
            out.push(mk(" udp", &format!(" dport {p}")));
        }
    } else {
        out.push(format!(
            "{prefix} accept comment \"{comment}\""
        ));
    }
    out
}

/// Pull `N` out of an nft `… # handle N` line. Returns None when the
/// listing didn't include the handle (e.g. `nft` without `--handle`).
fn parse_handle(line: &str) -> Option<u64> {
    let marker = line.find("# handle ")?;
    line[marker + "# handle ".len()..]
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_bare_ipv4() {
        let (ip, port, proto) = parse_target("8.8.8.8").unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert_eq!(port, None);
        assert_eq!(proto, None);
    }

    #[test]
    fn parse_target_ipv4_with_port_and_proto() {
        let (ip, port, proto) = parse_target("8.8.8.8:53/udp").unwrap();
        assert_eq!(ip, "8.8.8.8");
        assert_eq!(port, Some(53));
        assert_eq!(proto, Some("udp"));
    }

    #[test]
    fn parse_target_ipv6_bracketed() {
        let (ip, port, proto) = parse_target("[2001:db8::1]:443/tcp").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, Some(443));
        assert_eq!(proto, Some("tcp"));
    }

    #[test]
    fn parse_target_bare_ipv6() {
        let (ip, port, _) = parse_target("2001:db8::1").unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[test]
    fn gen_rules_no_port_emits_one_rule() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", None, None, "client 1: alice", false);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("ip saddr 10.8.0.2 ip daddr 8.8.8.8"));
        assert!(rules[0].contains("accept comment \"client 1: alice\""));
        assert!(!rules[0].contains("dport"));
    }

    #[test]
    fn gen_rules_port_no_proto_emits_tcp_and_udp() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", Some(53), None, "alice", false);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().any(|r| r.contains("tcp dport 53")));
        assert!(rules.iter().any(|r| r.contains("udp dport 53")));
    }

    #[test]
    fn gen_rules_explicit_proto_emits_one() {
        let rules = gen_rules("10.8.0.2", "8.8.8.8", Some(53), Some("udp"), "alice", false);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("udp dport 53"));
    }

    #[test]
    fn gen_rules_v6_uses_ip6_qualifier() {
        let rules = gen_rules("fd::2", "2001:db8::1", Some(443), Some("tcp"), "alice", true);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("ip6 saddr fd::2 ip6 daddr 2001:db8::1"));
        assert!(!rules[0].contains("ip saddr"));
    }

    #[test]
    fn sanitize_comment_strips_shell_metas() {
        let c = sanitize_comment("alice'; DROP TABLE users; --", 7);
        assert_eq!(c, "client 7: alice DROP TABLE users --");
    }

    #[test]
    fn sanitize_iface_filters_special_chars() {
        assert_eq!(sanitize_iface("awg0"), "awg0");
        assert_eq!(sanitize_iface("awg0; rm -rf /"), "awg0rm-rf");
        // 16-char input gets clipped to 15.
        assert_eq!(sanitize_iface("0123456789abcdefg").len(), 15);
    }

    #[test]
    fn parse_handle_extracts_numeric_id() {
        assert_eq!(
            parse_handle("\tiifname \"awg0\" jump wg-clients # handle 42"),
            Some(42)
        );
        assert_eq!(parse_handle("no handle here"), None);
    }

    /// End-to-end: feed a representative transaction through `nft -c -f -`
    /// (check-only mode) and assert it parses cleanly. Catches syntax
    /// regressions in `gen_rules` / `init_chain` that pure-string tests
    /// would miss. Marked `#[ignore]` because dev machines often don't
    /// have `nft`; CI runners and the docker container do.
    #[test]
    #[ignore = "requires the nft binary in PATH"]
    fn nft_validates_generated_transaction() {
        if !is_available() {
            // Belt-and-braces in case the runner skips the ignore filter.
            return;
        }

        // Build a transaction that exercises every shape gen_rules can
        // emit (no port, port-with-explicit-proto, port-no-proto, both
        // address families) plus the chain bootstrap from init_chain.
        let mut txn = String::new();
        txn.push_str("add table inet awg-easy-rs-syntaxtest\n");
        txn.push_str(
            "add chain inet awg-easy-rs-syntaxtest forward { type filter hook forward priority filter; policy accept; }\n",
        );
        txn.push_str("add chain inet awg-easy-rs-syntaxtest wg-clients\n");
        // Rewrite TABLE to the test name so the rules land in the test table.
        let rules = vec![
            gen_rules("10.8.0.2", "8.8.8.8", None,           None,         "client 1: alice", false),
            gen_rules("10.8.0.2", "8.8.8.8", Some(53),       Some("udp"),  "client 1: alice", false),
            gen_rules("10.8.0.2", "8.8.8.8", Some(443),      None,         "client 1: alice", false),
            gen_rules("fd::2",    "2001:db8::1", Some(443),  Some("tcp"),  "client 2: bob",   true),
        ];
        for batch in rules {
            for r in batch {
                let r = r.replace("inet awg-easy-rs ", "inet awg-easy-rs-syntaxtest ");
                txn.push_str(&r);
                txn.push('\n');
            }
        }
        txn.push_str("add rule inet awg-easy-rs-syntaxtest wg-clients drop\n");

        // `nft -c` validates without applying. Doesn't need root.
        let mut child = std::process::Command::new("nft")
            .arg("-c")
            .arg("-f")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn nft -c");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(txn.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait nft -c");
        assert!(
            out.status.success(),
            "nft -c rejected our transaction:\nstderr:\n{}\n--- transaction ---\n{}",
            String::from_utf8_lossy(&out.stderr),
            txn,
        );
    }
}
