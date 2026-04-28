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
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
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
// POST /api/setup/migrate — re-save config
// ---------------------------------------------------------------------------

pub async fn setup_migrate(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Allow if setup not complete, or if authenticated
    let setup_step = db::get_setup_step().unwrap_or(0);
    if setup_step == 0 {
        // Setup complete — require auth
        let _user = require_auth(&jar, &state)?;
    }
    crate::wg::save_config().map_err(map_err)?;
    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// IP detection helpers (shared with admin module logic)
// ---------------------------------------------------------------------------

fn exec_cmd(cmd: &str) -> String {
    std::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn detect_public_ip() -> String {
    for url in &["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let out = exec_cmd(&format!("curl -s --max-time 5 {}", url));
        if !out.is_empty() && out.len() < 50 {
            return out;
        }
    }
    String::new()
}

fn detect_private_ips() -> Vec<String> {
    let out = exec_cmd(
        "hostname -I 2>/dev/null || ip -4 addr show | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){3}' | grep -v 127.0.0.1",
    );
    if out.is_empty() {
        return vec![];
    }
    out.split_whitespace().map(|s| s.to_string()).collect()
}
