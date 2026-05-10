//! API route layer for awg-easy-rs.
//!
//! All HTTP handlers are organised into sub-modules:
//! - `session`  — authentication and session management
//! - `clients`  — AmneziaWG client CRUD
//! - `admin`    — administrative endpoints (general, hooks, interface, etc.)
//! - `setup`    — first-run setup wizard
//! - `routes`   — miscellaneous routes (one-time links, metrics)

pub mod admin;
pub mod clients;
pub mod routes;
pub mod session;
pub mod setup;
pub mod dns;
pub mod xray;

use axum::extract::FromRef;
use axum::Router;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

/// Per-session data stored in-memory.
#[derive(Clone, Debug)]
pub struct SessionData {
    pub user_id: i64,
    pub username: String,
    pub role: i64,
    pub created_at: u64, // unix timestamp seconds
}

impl SessionData {
    pub fn is_expired(&self, timeout_secs: i64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.created_at) > timeout_secs as u64
    }
}

/// Application state shared with every handler.
#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

// Allow extracting parts of AppState individually (not used yet but
// enables future middleware).
impl FromRef<AppState> for Arc<Mutex<HashMap<String, SessionData>>> {
    fn from_ref(state: &AppState) -> Self {
        Arc::clone(&state.sessions)
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

/// Convenience: build a JSON error response.
pub fn api_err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": msg })))
}

/// Convert an `anyhow::Error` into a 500 response. The detailed error
/// (with chain) is logged server-side; clients only see a generic message
/// so we don't leak internal paths, SQL state, or filesystem layout.
pub fn map_err(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    tracing::error!("internal error: {:#}", e);
    api_err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
    )
}

/// Shorthand: 200 OK with `{ "success": true }`.
pub fn ok_success() -> Json<Value> {
    Json(json!({ "success": true }))
}

/// Build the complete application router (API + static files).
pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        // Information & interface
        .route("/information", axum::routing::get(routes::information))
        .route("/interface", axum::routing::get(routes::interface_info))
        // Session
        .route(
            "/session",
            axum::routing::get(session::get_session)
                .post(session::create_session)
                .delete(session::delete_session),
        )
        // Setup
        .route("/setup/2", axum::routing::post(setup::setup_step2))
        .route(
            "/setup/4",
            axum::routing::get(setup::setup_step4_get)
                .post(setup::setup_step4_post),
        )
        // Clients
        .route(
            "/client",
            axum::routing::get(clients::list_clients)
                .post(clients::create_client),
        )
        .route(
            "/client/:id",
            axum::routing::get(clients::get_client)
                .post(clients::update_client)
                .delete(clients::delete_client),
        )
        .route(
            "/client/:id/configuration",
            axum::routing::get(clients::client_configuration),
        )
        .route(
            "/client/:id/qrcode.svg",
            axum::routing::get(clients::client_qrcode),
        )
        .route(
            "/client/:id/enable",
            axum::routing::post(clients::enable_client),
        )
        .route(
            "/client/:id/disable",
            axum::routing::post(clients::disable_client),
        )
        .route(
            "/client/:id/generateOneTimeLink",
            axum::routing::post(clients::generate_one_time_link),
        )
        // Admin
        .route(
            "/admin/general",
            axum::routing::get(admin::get_general)
                .post(admin::update_general),
        )
        .route(
            "/admin/hooks",
            axum::routing::get(admin::get_hooks).post(admin::update_hooks),
        )
        .route("/admin/ip-info", axum::routing::get(admin::get_ip_info))
        .route(
            "/admin/userconfig",
            axum::routing::get(admin::get_userconfig)
                .post(admin::update_userconfig),
        )
        .route(
            "/admin/interface",
            axum::routing::get(admin::get_interface)
                .post(admin::update_interface),
        )
        .route(
            "/admin/interface/cidr",
            axum::routing::post(admin::change_cidr),
        )
        .route(
            "/admin/interface/restart",
            axum::routing::post(admin::restart_interface),
        )
        // Xray (Browsing mode) — admin
        .route(
            "/admin/xray/inbound",
            axum::routing::get(xray::get_inbound).post(xray::update_inbound),
        )
        .route(
            "/admin/xray/inbound/regenerate-keys",
            axum::routing::post(xray::regenerate_keys),
        )
        .route(
            "/admin/xray/inbound/probe-dest",
            axum::routing::post(xray::probe_dest),
        )
        .route(
            "/admin/xray/inbound/dest-candidates",
            axum::routing::get(xray::dest_candidates),
        )
        .route(
            "/admin/xray/status",
            axum::routing::get(xray::supervisor_status),
        )
        .route(
            "/admin/xray/restart",
            axum::routing::post(xray::restart),
        )
        // Bundled DNS stack (dnscrypt-proxy + tor + PTs) — admin
        .route(
            "/admin/dns/bundle",
            axum::routing::get(dns::get_bundle).post(dns::update_bundle),
        )
        .route(
            "/admin/dns/status",
            axum::routing::get(dns::supervisor_status),
        )
        .route(
            "/admin/dns/restart",
            axum::routing::post(dns::restart),
        )
        // Xray clients
        .route(
            "/xray/clients",
            axum::routing::get(xray::list_clients).post(xray::create_client),
        )
        .route(
            "/xray/clients/:id",
            axum::routing::get(xray::get_client)
                .post(xray::update_client)
                .delete(xray::delete_client),
        )
        .route(
            "/xray/clients/:id/share",
            axum::routing::get(xray::client_share_url),
        )
        .route(
            "/xray/clients/:id/qrcode.svg",
            axum::routing::get(xray::client_qrcode),
        )
        .route(
            "/xray/clients/:id/json",
            axum::routing::get(xray::client_amnezia_json),
        )
        // Me (current user)
        .route("/me", axum::routing::post(session::update_me))
        .route("/me/password", axum::routing::post(session::change_password))
        .route("/me/totp", axum::routing::post(session::toggle_totp));

    let api = api.with_state(state.clone());

    let root = Router::new()
        .route("/cnf/:oneTimeLink", axum::routing::get(routes::one_time_link))
        .route("/metrics/json", axum::routing::get(routes::metrics_json))
        .route(
            "/metrics/prometheus",
            axum::routing::get(routes::metrics_prometheus),
        )
        .route("/health", axum::routing::get(|| async { "OK" }))
        .nest("/api", api);
    // Note: no CorsLayer is attached. The single-origin admin UI is served
    // from the same listener as the API, so cross-origin requests must not
    // succeed. Adding `CorsLayer::permissive()` here would expose every
    // unauthenticated endpoint (e.g. /api/information) to any web origin.
    root
}

// ---------------------------------------------------------------------------
// Session helpers used across sub-modules
// ---------------------------------------------------------------------------

/// Extract a session user from the request cookie jar.  Returns 401 when
/// there is no valid session.
pub fn require_auth(
    jar: &axum_extra::extract::cookie::CookieJar,
    state: &AppState,
) -> Result<crate::db::User, (StatusCode, Json<Value>)> {
    let token = jar
        .get("awg_session")
        .map(|c| c.value().to_string())
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Not authenticated"))?;

    let sessions = state.sessions.lock().map_err(|e| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("Session lock: {e}"),
        )
    })?;

    let session = sessions
        .get(&token)
        .ok_or_else(|| api_err(StatusCode::UNAUTHORIZED, "Session expired"))?;

    // Check expiry against config
    let general = crate::db::get_general().map_err(map_err)?;
    if session.is_expired(general.session_timeout) {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Session expired"));
    }

    crate::db::get_user(session.user_id).map_err(map_err)
}

/// Convert a camelCase JSON key to snake_case database column name.
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            for ch in c.to_lowercase() {
                result.push(ch);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Convert a JSON value to its string representation for `db::UpdateMap`.
/// Returns `None` for null values (which means "skip this field").
pub fn value_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "1".into() } else { "0".into() }),
        Value::Array(arr) => {
            // Serialize arrays as JSON – used for allowedIps, dns, etc.
            Some(serde_json::to_string(arr).unwrap_or_default())
        }
        Value::Null => None,
        Value::Object(_) => None,
    }
}
