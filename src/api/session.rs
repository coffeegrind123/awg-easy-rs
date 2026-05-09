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
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{auth, db};

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Per-key login attempt timestamps (seconds since epoch).
type AttemptStore = HashMap<String, Vec<u64>>;

static LOGIN_ATTEMPTS: OnceLock<Mutex<AttemptStore>> = OnceLock::new();

fn login_attempts() -> &'static Mutex<AttemptStore> {
    LOGIN_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Reset the rate limiter state (for tests).
pub fn reset_login_attempts() {
    if let Some(m) = LOGIN_ATTEMPTS.get() {
        if let Ok(mut g) = m.lock() {
            g.clear();
        }
    }
}

/// Extract a best-effort client identifier from the request headers. Honours
/// `X-Forwarded-For` / `X-Real-IP` when set by a trusted reverse proxy; falls
/// back to None when running directly behind no proxy. Used for rate
/// limiting only — not for authentication decisions.
fn client_ip_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|h| h.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            let s = first.trim();
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|h| h.to_str().ok()) {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

/// Pre-computed Argon2id hash of a constant string. Used to make username
/// enumeration via timing impossible — when a user is missing we still spend
/// ~the same wall-clock time as a real verify before returning 401.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        crate::auth::hash_password("___dummy___never___match___")
            .expect("dummy hash")
    })
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
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<Value>), (StatusCode, Json<Value>)> {
    // Rate limiting: per-username (10/min) AND per-source-IP (50/min). The
    // IP bucket prevents an attacker from spreading attempts across many
    // usernames; the username bucket prevents distributed credential-stuffing
    // against a single account.
    let client_ip = client_ip_from_headers(&headers);
    {
        let mut attempts = login_attempts().lock().map_err(|e| {
            tracing::error!("Rate limit lock poisoned: {e}");
            api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Per-username bucket
        let user_window = attempts
            .entry(format!("user:{}", body.username))
            .or_default();
        user_window.retain(|t| now - t < 60);
        if user_window.len() >= 10 {
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many login attempts. Try again later.",
            ));
        }
        user_window.push(now);

        // Per-source-IP bucket
        if let Some(ip) = client_ip.as_deref() {
            let ip_window = attempts.entry(format!("ip:{ip}")).or_default();
            ip_window.retain(|t| now - t < 60);
            if ip_window.len() >= 50 {
                return Err(api_err(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many login attempts from this address. Try again later.",
                ));
            }
            ip_window.push(now);
        }
    }

    // Look up user — but ALWAYS run argon2 verification against either the
    // real hash or a constant dummy hash so the response time does not leak
    // whether a username exists. The dummy hash is generated once at startup.
    let lookup = db::get_user_by_username(&body.username);
    let (user_opt, hash_to_check) = match lookup {
        Ok(u) => {
            let hash = u.password.clone();
            (Some(u), hash)
        }
        Err(_) => (None, dummy_hash().to_string()),
    };

    let valid = auth::verify_password(&body.password, &hash_to_check)
        .map_err(map_err)?;
    let user = match user_opt {
        Some(u) if valid && u.enabled => u,
        _ => {
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Invalid username or password",
            ));
        }
    };

    // TOTP check — only enforced once the secret is verified.
    if let Some(ref totp_key) = user.totp_key {
        if user.totp_verified && !totp_key.is_empty() {
            match body.totp_code {
                Some(ref code) => {
                    // Burn one TOTP attempt against this user's bucket so a
                    // password+TOTP brute-force is bounded independently of
                    // the password rate limiter.
                    check_totp_rate_limit(user.id)?;
                    if !verify_totp_code(totp_key, code)? {
                        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid TOTP code"));
                    }
                }
                None => {
                    return Ok((jar, Json(json!({ "status": "TOTP_REQUIRED" }))));
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
// POST /api/me/totp — set up / verify / delete TOTP
// ---------------------------------------------------------------------------
//
// Mirrors the original Node.js contract:
//
//   { type: "setup" }
//       → server generates a fresh secret, stores it as unverified, and
//         returns { type: "setup", key: <base32>, uri: <otpauth://...> }.
//   { type: "create", code: "123456" }
//       → verifies the code against the stored secret, marks totp_verified=1.
//   { type: "delete", currentPassword: "..." }
//       → requires the current password and clears the secret.
//
// The secret is generated server-side; it never travels from the browser to
// the server, eliminating an entire class of MITM/CSRF attack surface.

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TotpRequest {
    Setup,
    Create {
        code: String,
    },
    Delete {
        #[serde(rename = "currentPassword")]
        current_password: String,
    },
}

pub async fn toggle_totp(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<TotpRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    match body {
        TotpRequest::Setup => {
            use rand::RngCore;
            // Generate a fresh 20-byte secret per RFC 6238 recommendations.
            let mut secret = [0u8; 20];
            rand::rngs::OsRng.fill_bytes(&mut secret);
            let key_b32 = base32_encode(&secret);

            // Build the otpauth:// URI for QR code consumption.
            let issuer = "wg-easy";
            let label = url_encode(&format!("{}:{}", issuer, user.username));
            let uri = format!(
                "otpauth://totp/{label}?secret={key}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
                label = label,
                key = key_b32,
                issuer = issuer,
            );

            // Persist as unverified.
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_key".into(), key_b32.clone());
            fields.insert("totp_verified".into(), "0".into());
            db::update_user(user.id, &fields).map_err(map_err)?;

            Ok(Json(json!({
                "success": true,
                "type": "setup",
                "key": key_b32,
                "uri": uri,
            })))
        }
        TotpRequest::Create { code } => {
            let key = user.totp_key.ok_or_else(|| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "No TOTP setup in progress — call type=setup first",
                )
            })?;
            // Burn one TOTP attempt against this user's bucket.
            check_totp_rate_limit(user.id)?;
            let secret = base32_decode(&key).ok_or_else(|| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Stored TOTP key is not valid base32",
                )
            })?;
            if !verify_totp_secret(&secret, &code)? {
                return Err(api_err(StatusCode::BAD_REQUEST, "Invalid TOTP code"));
            }
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_verified".into(), "1".into());
            db::update_user(user.id, &fields).map_err(map_err)?;
            Ok(Json(json!({
                "success": true,
                "type": "created",
            })))
        }
        TotpRequest::Delete { current_password } => {
            let valid = auth::verify_password(&current_password, &user.password)
                .map_err(map_err)?;
            if !valid {
                return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid current password"));
            }
            let mut fields = db::UpdateMap::new();
            fields.insert("totp_key".into(), String::new());
            fields.insert("totp_verified".into(), "0".into());
            db::update_user(user.id, &fields).map_err(map_err)?;
            Ok(Json(json!({
                "success": true,
                "type": "deleted",
            })))
        }
    }
}

// ---------------------------------------------------------------------------
// TOTP attempt rate limiter — independent of the password rate limiter so a
// successful login can't be coupled with a brute-force on the 6-digit code.
// ---------------------------------------------------------------------------

static TOTP_ATTEMPTS: OnceLock<Mutex<HashMap<i64, Vec<u64>>>> = OnceLock::new();

fn totp_attempts() -> &'static Mutex<HashMap<i64, Vec<u64>>> {
    TOTP_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn reset_totp_attempts() {
    if let Some(m) = TOTP_ATTEMPTS.get() {
        if let Ok(mut g) = m.lock() {
            g.clear();
        }
    }
}

/// Allow at most 5 TOTP-code attempts per 5-minute window per user.
fn check_totp_rate_limit(user_id: i64) -> Result<(), (StatusCode, Json<Value>)> {
    let mut attempts = totp_attempts().lock().map_err(|e| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("TOTP rate limit error: {e}"),
        )
    })?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let window = attempts.entry(user_id).or_default();
    window.retain(|t| now - t < 300);
    if window.len() >= 5 {
        return Err(api_err(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many TOTP attempts. Try again later.",
        ));
    }
    window.push(now);
    Ok(())
}

// ---------------------------------------------------------------------------
// base32 encode / decode (RFC 4648, no padding) — used for TOTP secrets.
// We avoid pulling in another crate for ~30 lines of code.
// ---------------------------------------------------------------------------

fn base32_encode(bytes: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buf >> bits) & 0x1F) as usize;
            out.push(ALPHA[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buf << (5 - bits)) & 0x1F) as usize;
        out.push(ALPHA[idx] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let v: u32 = match c {
            'A'..='Z' => (c as u8 - b'A') as u32,
            'a'..='z' => (c as u8 - b'a') as u32,
            '2'..='7' => 26 + (c as u8 - b'2') as u32,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// URL-encode a path segment for the otpauth URI (RFC 3986 unreserved + `%`).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// TOTP helper
// ---------------------------------------------------------------------------

/// Verify a TOTP code against the **stored base32 secret**. Used at login
/// after the secret has been stored on the user row. Tries the current
/// 30-second window. Constant-time on the result; the totp-rs library does
/// not expose a const-time comparison so we collapse failures into a single
/// boolean.
fn verify_totp_code(key_b32: &str, code: &str) -> Result<bool, (StatusCode, Json<Value>)> {
    let secret = base32_decode(key_b32).ok_or_else(|| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored TOTP key is not valid base32",
        )
    })?;
    verify_totp_secret(&secret, code)
}

/// Verify a TOTP code against a raw secret byte slice.
fn verify_totp_secret(secret: &[u8], code: &str) -> Result<bool, (StatusCode, Json<Value>)> {
    use totp_rs::{Algorithm, TOTP};

    if !code.chars().all(|c| c.is_ascii_digit()) || code.len() != 6 {
        return Ok(false);
    }

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        None,
        String::new(),
    )
    .map_err(|e| {
        tracing::error!("TOTP construction failed: {e}");
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    let valid = totp.check_current(code).map_err(|e| {
        tracing::error!("TOTP verification error: {e}");
        api_err(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    })?;

    Ok(valid)
}
