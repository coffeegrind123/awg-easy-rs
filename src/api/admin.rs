//! Admin endpoint handlers.
//!
//! | Method | Route                           | Description               |
//! |--------|---------------------------------|---------------------------|
//! | GET    | /api/admin/general              | Get general settings      |
//! | POST   | /api/admin/general              | Update general settings   |
//! | GET    | /api/admin/hooks                | Get hooks                 |
//! | POST   | /api/admin/hooks                | Update hooks              |
//! | GET    | /api/admin/ip-info              | Get IP information        |
//! | GET    | /api/admin/userconfig           | Get user config defaults  |
//! | POST   | /api/admin/userconfig           | Update user config        |
//! | GET    | /api/admin/interface            | Get interface (no key)    |
//! | POST   | /api/admin/interface            | Update interface          |
//! | POST   | /api/admin/interface/cidr       | Change CIDR + reassign IPs|
//! | POST   | /api/admin/interface/restart    | Restart AmneziaWG         |

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, value_to_string, AppState};
use crate::{db, wg};

fn get_i64(map: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    map.get(key).and_then(|v| v.as_i64())
}

fn validate_awg_params(map: &serde_json::Map<String, Value>) -> Result<(), (StatusCode, Json<Value>)> {
    let jc = get_i64(map, "jC").or_else(|| get_i64(map, "jc"));
    let jmin = get_i64(map, "jMin").or_else(|| get_i64(map, "jmin"));
    let jmax = get_i64(map, "jMax").or_else(|| get_i64(map, "jmax"));
    let s1 = get_i64(map, "s1");
    let s2 = get_i64(map, "s2");
    let s3 = get_i64(map, "s3");
    let s4 = get_i64(map, "s4");

    if let Some(jc) = jc {
        // Kernel permits jc == 0 ("junk packets disabled"); upstream
        // awg-easy required >= 1. We follow the kernel and accept 0.
        if jc < 0 || jc > 128 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jc must be 0-128"));
        }
    }
    if let (Some(jmin), Some(jmax)) = (jmin, jmax) {
        // Kernel device.c rejects only when jmax > 0 AND jmax < jmin. The
        // jmax == jmin case is handled separately below (kernel auto-bumps,
        // we reject when jc != 0 so the user can fix it explicitly).
        if jmax > 0 && jmax < jmin {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be >= Jmin"));
        }
    }
    if let Some(jmin) = jmin {
        if jmin < 0 || jmin > 1279 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmin must be 0-1279"));
        }
    }
    if let Some(jmax) = jmax {
        // Spec: Jmax < 1280 (strict)
        if jmax < 1 || jmax > 1279 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be 1-1279"));
        }
    }
    // Mirror kernel device.c post-config check: when Jc != 0 the kernel
    // requires Jmax > Jmin (otherwise it auto-increments). We reject the
    // equal case at API time so the user notices.
    if let (Some(jc), Some(jmin), Some(jmax)) = (jc, jmin, jmax) {
        if jc != 0 && jmin == jmax {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "When Jc != 0, Jmax must be strictly greater than Jmin",
            ));
        }
    }
    if let Some(s1) = s1 {
        if s1 < 0 || s1 > 1132 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S1 must be 0-1132"));
        }
    }
    if let Some(s2) = s2 {
        if s2 < 0 || s2 > 1188 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S2 must be 0-1188"));
        }
    }
    if let Some(s3) = s3 {
        // Per gl-inet AmneziaWG-2.0 parameter table.
        if s3 < 0 || s3 > 1216 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S3 must be 0-1216"));
        }
    }
    if let Some(s4) = s4 {
        // Per AmneziaWG-2.0 transport-message padding limit.
        if s4 < 0 || s4 > 32 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S4 must be 0-32"));
        }
    }
    if let (Some(s1), Some(s2)) = (s1, s2) {
        if s1 > 0 && s2 > 0 && s1 + 56 == s2 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S1 + 56 must not equal S2"));
        }
    }

    // Validate I1-I5 CPS tag grammar
    for key in ["i1", "i2", "i3", "i4", "i5"] {
        if let Some(val) = map.get(key).and_then(|v| v.as_str()) {
            if let Err(msg) = crate::wg::params::validate_init_spec(val) {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid {}: {msg}", key.to_uppercase()),
                ));
            }
        }
    }

    // Validate H1-H4 non-overlapping
    let h_keys = ["h1", "h2", "h3", "h4"];
    let ranges: Vec<Option<(i64, i64)>> = h_keys.iter().map(|k| {
        map.get(*k).and_then(|v| v.as_str()).map(|s| {
            let parts: Vec<&str> = s.splitn(2, '-').collect();
            let start: i64 = parts[0].parse().unwrap_or(0);
            let end: i64 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(start);
            (start, end)
        })
    }).collect();

    for i in 0..4 {
        for j in (i+1)..4 {
            if let (Some(a), Some(b)) = (ranges[i], ranges[j]) {
                if !(a.1 < b.0 || b.1 < a.0) {
                    return Err(api_err(StatusCode::BAD_REQUEST,
                        &format!("Magic headers H{} and H{} overlap. They must not overlap.", i+1, j+1)));
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Enforce admin role (role >= 1)
// ---------------------------------------------------------------------------

pub(crate) fn require_admin(
    jar: &CookieJar,
    state: &AppState,
) -> Result<db::User, (StatusCode, Json<Value>)> {
    let user = require_auth(jar, state)?;
    if user.role < 1 {
        return Err(api_err(StatusCode::FORBIDDEN, "Admin access required"));
    }
    Ok(user)
}

// ---------------------------------------------------------------------------
// GET /api/admin/general
// ---------------------------------------------------------------------------

pub async fn get_general(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let general = db::get_general().map_err(map_err)?;

    // Never return the metrics password (it's a hash anyway, but treat the
    // hash as a credential). We surface only a boolean so the UI can display
    // "set / not set" without the value.
    let metrics_password_set = general
        .metrics_password
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    Ok(Json(json!({
        "setupStep": general.setup_step,
        "sessionTimeout": general.session_timeout,
        "metricsPrometheus": general.metrics_prometheus,
        "metricsJson": general.metrics_json,
        "metricsPasswordSet": metrics_password_set,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/general
// ---------------------------------------------------------------------------

pub async fn update_general(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Strict whitelist — never accept arbitrary keys here. The generic
        // pass-through that previously existed could be abused (with admin
        // credentials) to reset `setupStep` and re-trigger the setup wizard.
        let mappings: &[(&str, &str)] = &[
            ("sessionTimeout", "session_timeout"),
            ("metricsPrometheus", "metrics_prometheus"),
            ("metricsJson", "metrics_json"),
        ];
        for (json_key, db_key) in mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert((*db_key).into(), s);
                }
            }
        }
        // Metrics password: never store cleartext. We hash with SHA-256 hex
        // and the metrics endpoints constant-time-compare against the hash.
        // Empty / null clears the value.
        if let Some(val) = map.get("metricsPassword") {
            match val {
                Value::Null => {
                    fields.insert("metrics_password".into(), String::new());
                }
                Value::String(s) if s.is_empty() => {
                    fields.insert("metrics_password".into(), String::new());
                }
                Value::String(s) => {
                    fields.insert("metrics_password".into(), crate::auth::sha256(s));
                }
                _ => {}
            }
        }
    }

    if !fields.is_empty() {
        db::update_general(&fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/hooks
// ---------------------------------------------------------------------------

pub async fn get_hooks(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let hooks = db::get_hooks().map_err(map_err)?;

    Ok(Json(json!({
        "preUp": hooks.pre_up,
        "postUp": hooks.post_up,
        "preDown": hooks.pre_down,
        "postDown": hooks.post_down,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/hooks
// ---------------------------------------------------------------------------

pub async fn update_hooks(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        let mappings = [
            ("preUp", "pre_up"),
            ("postUp", "post_up"),
            ("preDown", "pre_down"),
            ("postDown", "post_down"),
        ];
        for (json_key, db_key) in &mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
    }

    if !fields.is_empty() {
        db::update_hooks(&fields).map_err(map_err)?;
        // Re-save config to apply new hooks
        wg::save_config().map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/ip-info
// ---------------------------------------------------------------------------

pub async fn get_ip_info(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let public_ip = get_public_ip();
    let private_ips = get_private_ips();

    Ok(Json(json!({
        "publicIp": public_ip,
        "privateIps": private_ips,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/admin/userconfig
// ---------------------------------------------------------------------------

pub async fn get_userconfig(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let uc = db::get_user_config().map_err(map_err)?;

    // Parse JSON arrays
    let default_dns: Value =
        serde_json::from_str(&uc.default_dns).unwrap_or(json!([]));
    let default_allowed_ips: Value =
        serde_json::from_str(&uc.default_allowed_ips).unwrap_or(json!([]));

    Ok(Json(json!({
        // Match the frontend / Node.js naming exactly: defaultMtu / defaultDns
        // (lowercase initialism). The previous all-caps form silently failed
        // to round-trip through the Vue UI.
        "defaultMtu": uc.default_mtu,
        "defaultPersistentKeepalive": uc.default_persistent_keepalive,
        "defaultDns": default_dns,
        "defaultAllowedIps": default_allowed_ips,
        "defaultJC": uc.default_j_c,
        "defaultJMin": uc.default_j_min,
        "defaultJMax": uc.default_j_max,
        "defaultI1": uc.default_i1,
        "defaultI2": uc.default_i2,
        "defaultI3": uc.default_i3,
        "defaultI4": uc.default_i4,
        "defaultI5": uc.default_i5,
        "defaultAdditionalConfig": uc.default_additional_config,
        "host": uc.host,
        "port": uc.port,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/userconfig
// ---------------------------------------------------------------------------

pub async fn update_userconfig(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Accept BOTH the all-caps initialism (legacy clients) and the
        // camelCase form used by the modern UI/Nuxt server.
        let mappings: &[(&[&str], &str)] = &[
            (&["defaultMtu", "defaultMTU"], "default_mtu"),
            (&["defaultPersistentKeepalive"], "default_persistent_keepalive"),
            (&["defaultJC"], "default_j_c"),
            (&["defaultJMin"], "default_j_min"),
            (&["defaultJMax"], "default_j_max"),
            (&["defaultI1"], "default_i1"),
            (&["defaultI2"], "default_i2"),
            (&["defaultI3"], "default_i3"),
            (&["defaultI4"], "default_i4"),
            (&["defaultI5"], "default_i5"),
            (&["defaultAdditionalConfig"], "default_additional_config"),
            (&["host"], "host"),
            (&["port"], "port"),
        ];
        for (json_keys, db_key) in mappings {
            for k in *json_keys {
                if let Some(val) = map.get(*k) {
                    if let Some(s) = value_to_string(val) {
                        fields.insert((*db_key).into(), s);
                        break;
                    }
                }
            }
        }
        // DNS array -> JSON string (accept both spellings)
        if let Some(val) = map.get("defaultDns").or_else(|| map.get("defaultDNS")) {
            let s = serde_json::to_string(val).unwrap_or_default();
            fields.insert("default_dns".into(), s);
        }
        // AllowedIPs array -> JSON string
        if let Some(val) = map.get("defaultAllowedIps") {
            let s = serde_json::to_string(val).unwrap_or_default();
            fields.insert("default_allowed_ips".into(), s);
        }
    }

    if !fields.is_empty() {
        db::update_user_config(&fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/admin/interface — get interface (hide private_key)
// ---------------------------------------------------------------------------

pub async fn get_interface(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let iface = db::get_interface().map_err(map_err)?;

    Ok(Json(json!({
        "name": iface.name,
        "device": iface.device,
        "port": iface.port,
        "publicKey": iface.public_key,
        "ipv4Cidr": iface.ipv4_cidr,
        "ipv6Cidr": iface.ipv6_cidr,
        "mtu": iface.mtu,
        "jC": iface.j_c,
        "jMin": iface.j_min,
        "jMax": iface.j_max,
        "s1": iface.s1,
        "s2": iface.s2,
        "s3": iface.s3,
        "s4": iface.s4,
        "h1": iface.h1,
        "h2": iface.h2,
        "h3": iface.h3,
        "h4": iface.h4,
        "i1": iface.i1,
        "i2": iface.i2,
        "i3": iface.i3,
        "i4": iface.i4,
        "i5": iface.i5,
        "additionalConfig": iface.additional_config,
        "firewallEnabled": iface.firewall_enabled,
        // DNS-leak prevention. Three independent fields so the UI can
        // expose the master switch separately from the redirect target
        // (operator might want to set the target ahead of time and flip
        // the switch later) and from the residual-leak drop policy.
        "dnsLockdown": iface.dns_lockdown,
        "dnsLockdownTarget": iface.dns_lockdown_target,
        "dnsBlockExternal": iface.dns_block_external,
        "enabled": iface.enabled,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface — update interface
// ---------------------------------------------------------------------------

pub async fn update_interface(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    // Validate AWG params
    if let Value::Object(ref map) = body {
        validate_awg_params(map)?;
    }

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        let mappings = [
            ("port", "port"),
            ("ipv4Cidr", "ipv4_cidr"),
            ("ipv6Cidr", "ipv6_cidr"),
            ("mtu", "mtu"),
            ("jC", "j_c"),
            ("jMin", "j_min"),
            ("jMax", "j_max"),
            ("s1", "s1"),
            ("s2", "s2"),
            ("s3", "s3"),
            ("s4", "s4"),
            ("h1", "h1"),
            ("h2", "h2"),
            ("h3", "h3"),
            ("h4", "h4"),
            ("i1", "i1"),
            ("i2", "i2"),
            ("i3", "i3"),
            ("i4", "i4"),
            ("i5", "i5"),
            ("additionalConfig", "additional_config"),
            ("device", "device"),
        ];
        for (json_key, db_key) in &mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // Special: firewall_enabled boolean
        if let Some(val) = map.get("firewallEnabled") {
            if let Some(s) = value_to_string(val) {
                fields.insert("firewall_enabled".into(), s);
            }
        }
        // DNS lockdown — three independent fields. Validate the target
        // here (instead of just at firewall-apply time) so a bad value
        // bounces back to the UI as a 4xx instead of getting silently
        // accepted into the DB and then failing on the next nft apply.
        if let Some(val) = map.get("dnsLockdownTarget") {
            if let Some(s) = value_to_string(val) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    if trimmed.parse::<std::net::IpAddr>().is_err() {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            Json(json!({
                                "error":
                                    "dnsLockdownTarget must be a valid IPv4 or IPv6 literal \
                                     (hostnames are not accepted)"
                            })),
                        ));
                    }
                }
                fields.insert("dns_lockdown_target".into(), trimmed.to_string());
            }
        }
        if let Some(val) = map.get("dnsLockdown") {
            if let Some(s) = value_to_string(val) {
                fields.insert("dns_lockdown".into(), s);
            }
        }
        if let Some(val) = map.get("dnsBlockExternal") {
            if let Some(s) = value_to_string(val) {
                fields.insert("dns_block_external".into(), s);
            }
        }
    }

    if !fields.is_empty() {
        db::update_interface(&fields).map_err(map_err)?;
        wg::save_config().map_err(map_err)?;

        // Apply firewall changes if firewall_enabled or any DNS
        // lockdown field was touched. We re-read the interface row
        // rather than acting on `body` directly so the apply uses
        // exactly what the DB now holds — no risk of acting on a
        // partial update if a future caller batches multiple writes.
        if let Value::Object(ref map) = body {
            let firewall_touched = map.contains_key("firewallEnabled");
            let dns_touched = map.contains_key("dnsLockdown")
                || map.contains_key("dnsLockdownTarget")
                || map.contains_key("dnsBlockExternal");

            if firewall_touched || dns_touched {
                let iface = db::get_interface().map_err(map_err)?;
                // rebuild_rules handles both per-peer filtering and DNS
                // lockdown atomically, with the right "off" semantics
                // for each independently. Cheaper than two calls.
                crate::firewall::rebuild_rules().map_err(map_err).ok();

                // If per-peer firewall was specifically turned off and
                // DNS lockdown is also off, rebuild_rules() already
                // called remove_filtering. Nothing more to do.
                let _ = iface;
            }
        }
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface/cidr — change CIDR + reassign client IPs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChangeCidrRequest {
    #[serde(rename = "ipv4Cidr")]
    pub ipv4_cidr: String,
    #[serde(rename = "ipv6Cidr")]
    pub ipv6_cidr: String,
}

pub async fn change_cidr(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangeCidrRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    // Update CIDR in interface
    db::update_cidr(&body.ipv4_cidr, &body.ipv6_cidr).map_err(map_err)?;

    // Reassign all client IPs
    let clients = db::get_all_clients().map_err(map_err)?;
    let mut used_v4: Vec<String> = Vec::new();
    let mut used_v6: Vec<String> = Vec::new();

    for client in &clients {
        let new_v4 = db::next_ipv4(&body.ipv4_cidr, &used_v4).map_err(map_err)?;
        used_v4.push(new_v4.clone());

        let new_v6 = if !body.ipv6_cidr.is_empty() {
            let v6 = db::next_ipv6(&body.ipv6_cidr, &used_v6).map_err(map_err)?;
            used_v6.push(v6.clone());
            Some(v6)
        } else {
            None
        };

        let mut fields = db::UpdateMap::new();
        fields.insert("ipv4_address".into(), new_v4);
        if let Some(ref v6) = new_v6 {
            fields.insert("ipv6_address".into(), v6.clone());
        }
        db::update_client(client.id, &fields).map_err(map_err)?;
    }

    wg::save_config().map_err(map_err)?;

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/admin/interface/restart — restart AmneziaWG
// ---------------------------------------------------------------------------

pub async fn restart_interface(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    wg::restart().map_err(map_err)?;

    // Re-apply firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// IP detection helpers
// ---------------------------------------------------------------------------

/// Run a command with explicit argv; never invokes a shell.
fn run_argv(prog: &str, args: &[&str]) -> String {
    std::process::Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn get_public_ip() -> String {
    // URLs are constants — no user input ever reaches the command line.
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = run_argv("curl", &["-s", "--max-time", "5", url]);
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn get_private_ips() -> Vec<String> {
    // hostname -I prints all assigned IPv4 addresses on stdout.
    let out = run_argv("hostname", &["-I"]);
    if !out.is_empty() {
        return out.split_whitespace().map(|s| s.to_string()).collect();
    }
    // Fallback: parse `ip -4 addr show` output. Still no shell parsing.
    let out = run_argv("ip", &["-4", "addr", "show"]);
    let mut ips = Vec::new();
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet ") {
            if let Some(ip) = rest.split('/').next() {
                if ip != "127.0.0.1" {
                    ips.push(ip.to_string());
                }
            }
        }
    }
    ips
}
