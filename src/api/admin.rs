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
//! | POST   | /api/admin/interface/restart    | Restart WireGuard         |

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, to_snake_case, value_to_string, AppState};
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

    if let Some(jc) = jc {
        if jc < 1 || jc > 128 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jc must be 1-128"));
        }
    }
    if let (Some(jmin), Some(jmax)) = (jmin, jmax) {
        if jmax <= jmin {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be > Jmin"));
        }
    }
    if let Some(jmin) = jmin {
        if jmin < 0 || jmin > 1279 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmin must be 0-1279"));
        }
    }
    if let Some(jmax) = jmax {
        if jmax < 1 || jmax > 1280 {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jmax must be 1-1280"));
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
    if let (Some(s1), Some(s2)) = (s1, s2) {
        if s1 > 0 && s2 > 0 && s1 + 56 == s2 {
            return Err(api_err(StatusCode::BAD_REQUEST, "S1 + 56 must not equal S2"));
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

fn require_admin(
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

    Ok(Json(json!({
        "setupStep": general.setup_step,
        "sessionTimeout": general.session_timeout,
        "metricsPrometheus": general.metrics_prometheus,
        "metricsJson": general.metrics_json,
        "metricsPassword": general.metrics_password,
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
        // Map known fields with snake_case conversion
        if let Some(val) = map.get("sessionTimeout") {
            if let Some(s) = value_to_string(val) {
                fields.insert("session_timeout".into(), s);
            }
        }
        if let Some(val) = map.get("metricsPrometheus") {
            if let Some(s) = value_to_string(val) {
                fields.insert("metrics_prometheus".into(), s);
            }
        }
        if let Some(val) = map.get("metricsJson") {
            if let Some(s) = value_to_string(val) {
                fields.insert("metrics_json".into(), s);
            }
        }
        if let Some(val) = map.get("metricsPassword") {
            if let Some(s) = value_to_string(val) {
                fields.insert("metrics_password".into(), s);
            }
        }
        // Generic fields
        for (key, val) in map {
            if !["sessionTimeout", "metricsPrometheus", "metricsJson", "metricsPassword",
                "sessionPassword"]
                .contains(&key.as_str())
            {
                if let Some(s) = value_to_string(val) {
                    fields.insert(to_snake_case(key), s);
                }
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
        "defaultMTU": uc.default_mtu,
        "defaultPersistentKeepalive": uc.default_persistent_keepalive,
        "defaultDNS": default_dns,
        "defaultAllowedIps": default_allowed_ips,
        "defaultJC": uc.default_j_c,
        "defaultJMin": uc.default_j_min,
        "defaultJMax": uc.default_j_max,
        "defaultI1": uc.default_i1,
        "defaultI2": uc.default_i2,
        "defaultI3": uc.default_i3,
        "defaultI4": uc.default_i4,
        "defaultI5": uc.default_i5,
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
        let mappings = [
            ("defaultMTU", "default_mtu"),
            ("defaultPersistentKeepalive", "default_persistent_keepalive"),
            ("defaultJC", "default_j_c"),
            ("defaultJMin", "default_j_min"),
            ("defaultJMax", "default_j_max"),
            ("defaultI1", "default_i1"),
            ("defaultI2", "default_i2"),
            ("defaultI3", "default_i3"),
            ("defaultI4", "default_i4"),
            ("defaultI5", "default_i5"),
            ("host", "host"),
            ("port", "port"),
        ];
        for (json_key, db_key) in &mappings {
            if let Some(val) = map.get(*json_key) {
                if let Some(s) = value_to_string(val) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // DNS array -> JSON string
        if let Some(val) = map.get("defaultDNS") {
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
        "j1": iface.j1,
        "j2": iface.j2,
        "j3": iface.j3,
        "itime": iface.itime,
        "firewallEnabled": iface.firewall_enabled,
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
            ("j1", "j1"),
            ("j2", "j2"),
            ("j3", "j3"),
            ("itime", "itime"),
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
    }

    if !fields.is_empty() {
        db::update_interface(&fields).map_err(map_err)?;
        wg::save_config().map_err(map_err)?;

        // Apply firewall changes if firewall_enabled was toggled
        if let Value::Object(ref map) = body {
            if map.contains_key("firewallEnabled") {
                let iface = db::get_interface().map_err(map_err)?;
                if iface.firewall_enabled {
                    crate::firewall::rebuild_rules().map_err(map_err).ok();
                } else {
                    crate::firewall::remove_filtering(&iface.name)
                        .map_err(map_err)
                        .ok();
                }
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
// POST /api/admin/interface/restart — restart WireGuard
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

fn exec_cmd(cmd: &str) -> String {
    std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn get_public_ip() -> String {
    // Try multiple services
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = exec_cmd(&format!("curl -s --max-time 5 {}", url));
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn get_private_ips() -> Vec<String> {
    let out = exec_cmd(
        "hostname -I 2>/dev/null || ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | grep -v 127.0.0.1",
    );
    if out.is_empty() {
        return vec![];
    }
    out.split_whitespace().map(|s| s.to_string()).collect()
}
