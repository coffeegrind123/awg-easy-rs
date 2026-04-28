//! Session and user-profile handlers.
//!
//! | Method | Route            | Description          |
//! |--------|------------------|----------------------|
//! | POST   | /api/session     | Login                |
//! | GET    | /api/session     | Current user         |
//! | DELETE | /api/session     | Logout               |
//! | POST   | /api/me          | Update profile       |
//! | POST   | /api/me/password | Change password      |
//! | POST   | /api/me/totp     | Enable/disable TOTP  |

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{auth, db};

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static mut LOGIN_ATTEMPTS: Option<Mutex<HashMap<String, Vec<u64>>>> = None;

fn login_attempts() -> &'static Mutex<HashMap<String, Vec<u64>>> {
    unsafe {
        let ptr = std::ptr::addr_of!(LOGIN_ATTEMPTS);
        if (*ptr).is_none() {
            std::ptr::addr_of_mut!(LOGIN_ATTEMPTS).write(Some(Mutex::new(HashMap::new())));
        }
        (*ptr).as_ref().unwrap()
    }
}

/// Reset the rate limiter state (for tests).
pub fn reset_login_attempts() {
    unsafe {
        std::ptr::addr_of_mut!(LOGIN_ATTEMPTS).write(Some(Mutex::new(HashMap::new())));
    }
}

// ---------------------------------------------------------------------------
// Login body
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember: bool,
    #[serde(rename = "totpCode")]
    pub totp_code: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /api/session — login
// ---------------------------------------------------------------------------

pub async fn create_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), (StatusCode, Json<Value>)> {
    // Rate limiting: max 10 attempts per minute per username
    {
        let mut attempts = login_attempts().lock().map_err(|e| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Rate limit error: {e}"),
            )
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = attempts.entry(body.username.clone()).or_default();
        window.retain(|t| now - t < 60);
        if window.len() >= 10 {
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
            ));
        }
        window.push(now);
    }

    // Look up user
    let user = db::get_user_by_username(&body.username).map_err(|_| {
        api_err(StatusCode::UNAUTHORIZED, "Invalid username or password")
    })?;

    if !user.enabled {
        return Err(api_err(StatusCode::UNAUTHORIZED, "User is disabled"));
    }

    // Verify password
    let valid = auth::verify_password(&body.password, &user.password)
        .map_err(map_err)?;
    if !valid {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid username or password"));
    }

    // TOTP check
    if let Some(ref totp_key) = user.totp_key {
        if user.totp_verified {
            match body.totp_code {
                Some(ref code) => {
                    // Verify TOTP code
                    let valid = verify_totp_code(totp_key, code)?;
                    if !valid {
                        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
                    }
                }
                None => {
                    // TOTP is set up and verified but no code provided
                    return Ok((
                        jar,
                        Json(json!({ "status": "TOTP_REQUIRED" })),
                    ));
                }
            }
        }
    }

    // Generate session token and store
    let token = auth::generate_session_token();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let session_data = super::SessionData {
        user_id: user.id,
        username: user.username.clone(),
        role: user.role,
        created_at: now,
    };

    {
        let mut sessions = state.sessions.lock().map_err(|e| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Session lock error: {e}"),
            )
        })?;
        sessions.insert(token.clone(), session_data);
    }

    // Build cookie
    let secure = !crate::config::CONFIG.insecure;
    let cookie = Cookie::build(("awg_session", token))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(axum_extra::extract::cookie::SameSite::Strict);

    let cookie = if body.remember {
        cookie.max_age(time::Duration::days(30))
            .build()
    } else {
        cookie.build()
    };

    let jar = jar.add(cookie);

    let resp = json!({
        "status": "success",
        "user": {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "role": user.role,
            "email": user.email,
            "totpVerified": user.totp_verified,
        }
    });

    Ok((jar, Json(resp)))
}

// ---------------------------------------------------------------------------
// GET /api/session — current user
// ---------------------------------------------------------------------------

pub async fn get_session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    Ok(Json(json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "name": user.name,
            "role": user.role,
            "email": user.email,
            "totpVerified": user.totp_verified,
        }
    })))
}

// ---------------------------------------------------------------------------
// DELETE /api/session — logout
// ---------------------------------------------------------------------------

pub async fn delete_session(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), (StatusCode, Json<Value>)> {
    // Remove session from store if cookie present
    if let Some(cookie) = jar.get("awg_session") {
        let token = cookie.value().to_string();
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.remove(&token);
        }
    }

    // Clear the cookie
    let jar = jar.remove(Cookie::from("awg_session"));

    Ok((jar, Json(json!({ "success": true }))))
}

// ---------------------------------------------------------------------------
// POST /api/me — update current user profile
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateMeRequest {
    #[serde(rename = "currentPassword")]
    pub current_password: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
}

pub async fn update_me(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<UpdateMeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify current password if changing password-sensitive fields
    if let Some(ref pw) = body.current_password {
        let valid = auth::verify_password(pw, &user.password).map_err(map_err)?;
        if !valid {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
        }
    }

    let mut fields = db::UpdateMap::new();
    if let Some(ref email) = body.email {
        fields.insert("email".into(), email.clone());
    }
    if let Some(ref name) = body.name {
        fields.insert("name".into(), name.clone());
    }

    if !fields.is_empty() {
        db::update_user(user.id, &fields).map_err(map_err)?;
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/me/password — change password
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    #[serde(rename = "currentPassword")]
    pub current_password: String,
    #[serde(rename = "newPassword")]
    pub new_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify current password
    let valid = auth::verify_password(&body.current_password, &user.password)
        .map_err(map_err)?;
    if !valid {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
    }

    if body.new_password.len() < 6 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Password must be at least 6 characters",
        ));
    }

    // Hash and store new password
    let hash = auth::hash_password(&body.new_password).map_err(map_err)?;
    db::update_password(user.id, &hash).map_err(map_err)?;

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/me/totp — enable/disable TOTP
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ToggleTotpRequest {
    pub password: String,
    #[serde(rename = "totpKey")]
    pub totp_key: Option<String>,
    pub enable: Option<bool>,
    #[serde(rename = "totpCode")]
    pub totp_code: Option<String>,
}

pub async fn toggle_totp(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<ToggleTotpRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify password
    let valid = auth::verify_password(&body.password, &user.password)
        .map_err(map_err)?;
    if !valid {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid password"));
    }

    let mut fields = db::UpdateMap::new();

    match body.enable {
        Some(true) => {
            // Enable TOTP
            let totp_key = body.totp_key.ok_or_else(|| {
                api_err(StatusCode::BAD_REQUEST, "TOTP key is required to enable")
            })?;

            // Verify the TOTP code (required when enabling)
            let code = body.totp_code.ok_or_else(|| {
                api_err(StatusCode::BAD_REQUEST, "TOTP code is required to enable 2FA")
            })?;
            let valid = verify_totp_code(&totp_key, &code)?;
            if !valid {
                return Err(api_err(StatusCode::BAD_REQUEST, "Invalid TOTP code"));
            }

            fields.insert("totp_key".into(), totp_key);
            fields.insert("totp_verified".into(), "1".into());
        }
        Some(false) => {
            // Disable TOTP
            fields.insert("totp_key".into(), String::new());
            fields.insert("totp_verified".into(), "0".into());
        }
        None => {
            return Err(api_err(StatusCode::BAD_REQUEST, "enable field is required"));
        }
    }

    db::update_user(user.id, &fields).map_err(map_err)?;

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// TOTP helper
// ---------------------------------------------------------------------------

fn verify_totp_code(key: &str, code: &str) -> Result<bool, (StatusCode, Json<Value>)> {
    use totp_rs::{Algorithm, TOTP};

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        key.as_bytes().to_vec(),
        None,
        String::new(),
    )
    .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;

    let valid = totp.check_current(code).map_err(|e| {
        api_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string())
    })?;

    Ok(valid)
}
