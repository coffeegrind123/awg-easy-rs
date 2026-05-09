//! Setup wizard handlers (first-run configuration).
//!
//! | Method | Route              | Description                    |
//! |--------|--------------------|--------------------------------|
//! | POST   | /api/setup/2       | Create admin user              |
//! | GET    | /api/setup/4       | Get IP info for host selection |
//! | POST   | /api/setup/4       | Set host and port              |
//! | POST   | /api/setup/migrate | Migrate/re-initialise data     |

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{auth, db};

// ---------------------------------------------------------------------------
// POST /api/setup/2 — create admin user
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupStep2Request {
    pub username: String,
    pub password: String,
    #[serde(rename = "confirmPassword")]
    pub confirm_password: String,
}

pub async fn setup_step2(
    State(_state): State<AppState>,
    _jar: CookieJar,
    Json(body): Json<SetupStep2Request>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check passwords match
    if body.password != body.confirm_password {
        return Err(api_err(StatusCode::BAD_REQUEST, "Passwords do not match"));
    }

    if body.password.len() < 6 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 6 characters",
        ));
    }

    if body.username.len() < 3 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Username must be at least 3 characters",
        ));
    }
    if body.username.len() > 64 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Username must be at most 64 characters",
        ));
    }

    // Check setup step (should be 1 or 2, or 0 if no users exist)
    let step = db::get_setup_step().map_err(map_err)?;
    if step != 1 && step != 2 {
        // Allow step 0 (setup marked complete) only when no users exist
        if step == 0 {
            let user_count = db::get_user_count().unwrap_or(0);
            if user_count > 0 {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "Setup already completed (admin user already exists)",
                ));
            }
            // step == 0 with no users: allow proceeding (recovering from bad state)
        } else {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "Setup already completed or in invalid state",
            ));
        }
    }

    // Hash password and create admin user
    let hash = auth::hash_password(&body.password).map_err(map_err)?;
    let params = db::CreateUserParams {
        username: body.username,
        password: hash,
        email: None,
        name: "Admin".into(),
        role: 1, // admin
        totp_key: None,
        totp_verified: false,
        enabled: true,
    };

    db::create_user(&params).map_err(map_err)?;

    // Advance setup step
    db::set_setup_step(3).map_err(map_err)?;

    Ok(Json(json!({ "success": true, "step": 3 })))
}

// ---------------------------------------------------------------------------
// GET /api/setup/4 — get IP info for host selection
// ---------------------------------------------------------------------------

pub async fn setup_step4_get(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // After initial setup is finished, this endpoint becomes admin-only —
    // it shells out to curl/ip to gather network info and must not be
    // exposed unauthenticated on a running deployment.
    let setup_step = db::get_setup_step().unwrap_or(0);
    if setup_step == 0 {
        let user = require_auth(&jar, &state)?;
        if user.role < 1 {
            return Err(api_err(StatusCode::FORBIDDEN, "Admin access required"));
        }
    }

    let public_ip = detect_public_ip();
    let private_ips = detect_private_ips();

    Ok(Json(json!({
        "publicIp": public_ip,
        "privateIps": private_ips,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/setup/4 — set host and port
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SetupStep4Request {
    pub host: String,
    pub port: Option<u16>,
}

pub async fn setup_step4_post(
    State(_state): State<AppState>,
    _jar: CookieJar,
    Json(body): Json<SetupStep4Request>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Check setup step (should be 3 — ready for host/port config)
    let step = db::get_setup_step().map_err(map_err)?;
    if step != 3 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Setup not ready for this step. Complete step 2 first.",
        ));
    }

    // Update host and port in user_config
    let port = body.port.unwrap_or(51820);
    db::update_host_port(&body.host, port as i64).map_err(map_err)?;

    // Also update the interface port
    let mut iface_fields = db::UpdateMap::new();
    iface_fields.insert("port".into(), port.to_string());
    db::update_interface(&iface_fields).map_err(map_err)?;

    // Mark setup as complete
    db::set_setup_step(0).map_err(map_err)?;

    Ok(Json(json!({ "success": true, "step": 0 })))
}

// ---------------------------------------------------------------------------
// POST /api/setup/migrate — import a v3 wg-easy backup file
// ---------------------------------------------------------------------------
//
// Mirrors the original Node.js handler. The body is `{ file: "<json string>" }`,
// where the JSON string contains:
//
//   {
//     "server": { "privateKey": "...", "publicKey": "...", "address": "10.8.0.1" },
//     "clients": {
//       "<id>": { "name": "...", "address": "10.8.0.2", "privateKey": "...",
//                 "publicKey": "...", "preSharedKey": "...",
//                 "createdAt": "...", "updatedAt": "...", "enabled": true }
//     }
//   }
//
// We reset the interface keypair to the legacy values, derive the IPv4 CIDR
// from the server address (assumed `/24`), assign each client a fresh IPv6
// from the standard fdcc::/112 pool, and persist them via `createFromExisting`
// semantics. Setup is then marked complete.
//
// Auth: the handler is only callable while setup is unfinished (`setup_step
// != 0`). Once setup is done, an authenticated admin must call it.

#[derive(Deserialize)]
pub struct SetupMigrateRequest {
    pub file: String,
}

#[derive(Deserialize)]
struct LegacyServer {
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    address: String,
}

#[derive(Deserialize)]
struct LegacyClient {
    name: String,
    address: String,
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "preSharedKey")]
    pre_shared_key: String,
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize)]
struct LegacyConfig {
    server: LegacyServer,
    clients: std::collections::HashMap<String, LegacyClient>,
}

pub async fn setup_migrate(
    State(state): State<AppState>,
    jar: CookieJar,
    body: Option<Json<SetupMigrateRequest>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let setup_step = db::get_setup_step().unwrap_or(0);
    if setup_step == 0 {
        let user = require_auth(&jar, &state)?;
        if user.role < 1 {
            return Err(api_err(StatusCode::FORBIDDEN, "Admin access required"));
        }
    }

    // No body / no file: legacy behaviour — just resave the config.
    let file = match body.and_then(|Json(b)| if b.file.is_empty() { None } else { Some(b.file) }) {
        Some(f) => f,
        None => {
            crate::wg::save_config().map_err(map_err)?;
            return Ok(ok_success());
        }
    };

    let cfg: LegacyConfig = serde_json::from_str(&file).map_err(|_| {
        api_err(StatusCode::BAD_REQUEST, "Invalid config JSON")
    })?;

    // Re-key the interface with the supplied keypair.
    db::update_key_pair(&cfg.server.public_key, &cfg.server.private_key)
        .map_err(map_err)?;

    // Derive a /24 around the server address.
    let server_ip: std::net::Ipv4Addr = cfg.server.address.parse().map_err(|_| {
        api_err(
            StatusCode::BAD_REQUEST,
            "server.address must be an IPv4 address",
        )
    })?;
    let octets = server_ip.octets();
    let v4_cidr = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
    let v6_cidr = "fdcc:ad94:bacf:61a4::cafe:0/112".to_string();
    db::update_cidr(&v4_cidr, &v6_cidr).map_err(map_err)?;

    // Recreate each client with its original keys/IPv4, allocating IPv6.
    let mut used_v6: Vec<String> = Vec::new();
    for (_, client) in cfg.clients.iter() {
        let v6 = db::next_ipv6(&v6_cidr, &used_v6).map_err(map_err)?;
        used_v6.push(v6.clone());
        let params = db::CreateClientParams {
            user_id: None,
            interface_id: Some("wg0".into()),
            name: client.name.clone(),
            ipv4_address: Some(client.address.clone()),
            ipv6_address: Some(v6),
            private_key: client.private_key.clone(),
            public_key: client.public_key.clone(),
            pre_shared_key: Some(client.pre_shared_key.clone()),
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
            expires_at: None,
            allowed_ips: None,
            server_allowed_ips: None,
            firewall_ips: None,
            persistent_keepalive: 0,
            mtu: 1420,
            j_c: None,
            j_min: None,
            j_max: None,
            i1: None,
            i2: None,
            i3: None,
            i4: None,
            i5: None,
            dns: None,
            server_endpoint: None,
            // Imported v3 backup → keep default opt-in (pure AmneziaWG).
            advanced_security: Some(true),
            enabled: client.enabled,
        };
        db::create_client(&params).map_err(map_err)?;
    }

    db::set_setup_step(0).map_err(map_err)?;
    crate::wg::save_config().map_err(map_err).ok();

    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// IP detection helpers (shared with admin module logic)
// ---------------------------------------------------------------------------

fn run_argv(prog: &str, args: &[&str]) -> String {
    std::process::Command::new(prog)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn detect_public_ip() -> String {
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = run_argv("curl", &["-s", "--max-time", "5", url]);
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn detect_private_ips() -> Vec<String> {
    let out = run_argv("hostname", &["-I"]);
    if !out.is_empty() {
        return out.split_whitespace().map(|s| s.to_string()).collect();
    }
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
