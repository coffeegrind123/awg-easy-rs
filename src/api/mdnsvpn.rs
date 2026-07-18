//! REST endpoints for "DNS-tunnel mode" — MasterDnsVPN.
//!
//! | Method | Path                                                    | Auth   | Purpose                              |
//! |--------|---------------------------------------------------------|--------|--------------------------------------|
//! | GET    | /api/admin/mdnsvpn/inbound                              | admin  | Read singleton inbound config        |
//! | POST   | /api/admin/mdnsvpn/inbound                              | admin  | Update inbound (domains/port/key/…)  |
//! | POST   | /api/admin/mdnsvpn/inbound/regenerate-key               | admin  | New 16-byte hex shared key           |
//! | GET    | /api/admin/mdnsvpn/status                               | admin  | Supervisor status snapshot           |
//! | POST   | /api/admin/mdnsvpn/restart                              | admin  | Force re-spawn                       |
//! | GET    | /api/mdnsvpn/clients                                    | auth   | List peers (own or all)              |
//! | POST   | /api/mdnsvpn/clients                                    | admin  | Create peer (auto-defaulted port)    |
//! | GET    | /api/mdnsvpn/clients/:id                                | auth   | Read one peer                        |
//! | POST   | /api/mdnsvpn/clients/:id                                | admin  | Update peer                          |
//! | DELETE | /api/mdnsvpn/clients/:id                                | admin  | Delete peer                          |
//! | GET    | /api/mdnsvpn/clients/:id/config.toml                    | auth   | client_config.toml (download)        |
//! | GET    | /api/mdnsvpn/clients/:id/resolvers.txt                  | auth   | client_resolvers.txt (download)      |
//! | GET    | /api/mdnsvpn/clients/:id/config.json                    | auth   | client config as JSON                |
//! | GET    | /api/mdnsvpn/clients/:id/share                          | auth   | mdnsvpn://b64?<base64> share string  |
//! | GET    | /api/mdnsvpn/clients/:id/qrcode.svg                     | auth   | QR of the share string               |

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use serde_json::{json, Value};

use super::admin::require_admin;
use super::{api_err, map_err, ok_success, require_auth, value_to_string, AppState};
use crate::db;
use crate::mdnsvpn;

// ---------------------------------------------------------------------------
// GET /api/admin/mdnsvpn/inbound
// ---------------------------------------------------------------------------

pub async fn get_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let inbound = db::get_mdnsvpn_inbound().map_err(map_err)?;
    let domains: Value =
        serde_json::from_str(&inbound.domains).unwrap_or_else(|_| json!([]));
    let upstreams: Value = serde_json::from_str(&inbound.dns_upstream_servers)
        .unwrap_or_else(|_| json!([]));
    Ok(Json(json!({
        "id": inbound.id,
        "domains": domains,
        "port": inbound.port,
        "bind": inbound.bind,
        "encryptionMethod": inbound.encryption_method,
        // Don't ship the key plaintext — UI just needs to know whether
        // one is set. Operators who need the value can read the DB
        // directly or download a peer config (which embeds the key).
        "hasEncryptionKey": !inbound.encryption_key.is_empty(),
        "encryptionKeyLength": inbound.encryption_key.len(),
        "protocolType": inbound.protocol_type,
        "dnsUpstreamServers": upstreams,
        "forwardIp": inbound.forward_ip,
        "forwardPort": inbound.forward_port,
        "useExternalSocks5": inbound.use_external_socks5,
        "socks5Auth": inbound.socks5_auth,
        "socks5User": inbound.socks5_user,
        "hasSocks5Pass": !inbound.socks5_pass.is_empty(),
        "additionalConfig": inbound.additional_config,
        "enabled": inbound.enabled,
        "isBundled": mdnsvpn::is_bundled(),
        "version": mdnsvpn::MDNSVPN_VERSION,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mdnsvpn/inbound
// ---------------------------------------------------------------------------

pub async fn update_inbound(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let mut fields = db::UpdateMap::new();
    if let Value::Object(map) = &body {
        // Plain scalar fields.
        let scalar = [
            ("port", "port"),
            ("bind", "bind"),
            ("encryptionMethod", "encryption_method"),
            ("protocolType", "protocol_type"),
            ("forwardIp", "forward_ip"),
            ("forwardPort", "forward_port"),
            ("useExternalSocks5", "use_external_socks5"),
            ("socks5Auth", "socks5_auth"),
            ("socks5User", "socks5_user"),
            ("socks5Pass", "socks5_pass"),
            ("additionalConfig", "additional_config"),
            ("enabled", "enabled"),
        ];
        for (json_key, db_key) in &scalar {
            if let Some(v) = map.get(*json_key) {
                if let Some(s) = value_to_string(v) {
                    fields.insert(db_key.to_string(), s);
                }
            }
        }
        // Array fields stored as JSON strings.
        if let Some(v) = map.get("domains") {
            let s = serde_json::to_string(v).unwrap_or_default();
            fields.insert("domains".into(), s);
        }
        if let Some(v) = map.get("dnsUpstreamServers") {
            let s = serde_json::to_string(v).unwrap_or_default();
            fields.insert("dns_upstream_servers".into(), s);
        }
        // The encryption key is NOT settable through this endpoint —
        // operators who want to roll a custom value POST to
        // /inbound/regenerate-key with `key=<value>` instead. Keeps the
        // free-form scalar update path from accidentally accepting an
        // empty / weak key.
    }

    if !fields.is_empty() {
        validate_inbound_update(&fields)?;
        db::update_mdnsvpn_inbound(&fields).map_err(map_err)?;
    }

    reconcile_supervisor().await;
    Ok(ok_success())
}

fn validate_inbound_update(fields: &db::UpdateMap) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(port) = fields.get("port") {
        let n: i64 = port
            .parse()
            .map_err(|_| api_err(StatusCode::BAD_REQUEST, "port must be an integer"))?;
        if !(1..=65535).contains(&n) {
            return Err(api_err(StatusCode::BAD_REQUEST, "port must be 1-65535"));
        }
    }
    if let Some(method) = fields.get("encryption_method") {
        let n: i64 = method.parse().map_err(|_| {
            api_err(StatusCode::BAD_REQUEST, "encryptionMethod must be an integer")
        })?;
        mdnsvpn::keys::validate_encryption_method(n)
            .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }
    if let Some(pt) = fields.get("protocol_type") {
        if pt != "SOCKS5" && pt != "TCP" {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "protocolType must be SOCKS5 or TCP",
            ));
        }
    }
    if let Some(domains) = fields.get("domains") {
        let parsed: Result<Vec<String>, _> = serde_json::from_str(domains);
        match parsed {
            Ok(arr) if arr.is_empty() => {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "domains must contain at least one entry",
                ));
            }
            Err(_) => {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "domains must be a JSON array of strings",
                ));
            }
            _ => {}
        }
    }
    if let Some(upstreams) = fields.get("dns_upstream_servers") {
        let parsed: Result<Vec<String>, _> = serde_json::from_str(upstreams);
        if parsed.is_err() {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "dnsUpstreamServers must be a JSON array of strings",
            ));
        }
    }
    if let Some(fwd_port) = fields.get("forward_port") {
        let n: i64 = fwd_port
            .parse()
            .map_err(|_| api_err(StatusCode::BAD_REQUEST, "forwardPort must be an integer"))?;
        if n != 0 && !(1..=65535).contains(&n) {
            return Err(api_err(
                StatusCode::BAD_REQUEST,
                "forwardPort must be 0 or 1-65535",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/admin/mdnsvpn/inbound/regenerate-key
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct RegenerateKeyRequest {
    /// When set, store this value verbatim instead of generating one.
    /// Lets operators paste in a key from an external system
    /// (`mdnsvpn -genkey`, KMS, etc.). Validated against `validate_key`.
    #[serde(default)]
    pub key: Option<String>,
}

pub async fn regenerate_key(
    State(state): State<AppState>,
    jar: CookieJar,
    body: Option<Json<RegenerateKeyRequest>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;

    let new_key = match body.and_then(|Json(b)| b.key) {
        Some(supplied) => {
            mdnsvpn::keys::validate_key(&supplied)
                .map_err(|e| api_err(StatusCode::BAD_REQUEST, &e.to_string()))?;
            supplied.trim().to_string()
        }
        None => mdnsvpn::keys::generate_key(),
    };

    db::update_mdnsvpn_encryption_key(&new_key).map_err(map_err)?;
    reconcile_supervisor().await;

    Ok(Json(json!({
        // Don't ship the new key back — same reason xray's regen-keys
        // doesn't ship the private half. The browser doesn't need it;
        // every per-peer config download embeds it.
        "encryptionKeySet": true,
        "encryptionKeyLength": new_key.len(),
    })))
}

// ---------------------------------------------------------------------------
// GET /api/admin/mdnsvpn/status
// ---------------------------------------------------------------------------

#[cfg(mdnsvpn_bundled)]
pub async fn supervisor_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let status = mdnsvpn::supervisor::status().await;
    Ok(Json(serde_json::to_value(&status).unwrap_or(Value::Null)))
}

#[cfg(not(mdnsvpn_bundled))]
pub async fn supervisor_status(
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Ok(Json(json!({
        "state": "disabled",
        "reason": "MasterDnsVPN support not bundled in this build",
    })))
}

// ---------------------------------------------------------------------------
// POST /api/admin/mdnsvpn/restart
// ---------------------------------------------------------------------------

#[cfg(mdnsvpn_bundled)]
pub async fn restart(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    mdnsvpn::supervisor::restart().await.map_err(map_err)?;
    Ok(ok_success())
}

#[cfg(not(mdnsvpn_bundled))]
pub async fn restart(
    State(_state): State<AppState>,
    _jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Err(api_err(
        StatusCode::NOT_IMPLEMENTED,
        "MasterDnsVPN support not bundled in this build",
    ))
}

// ---------------------------------------------------------------------------
// Client CRUD
// ---------------------------------------------------------------------------

fn client_to_json(client: &db::MdnsvpnClient) -> Value {
    let resolvers: Value =
        serde_json::from_str(&client.resolvers).unwrap_or(Value::String(client.resolvers.clone()));
    json!({
        "id": client.id,
        "userId": client.user_id,
        "inboundId": client.inbound_id,
        "name": client.name,
        "resolvers": resolvers,
        "listenPort": client.listen_port,
        "socks5User": client.socks5_user,
        "hasSocks5Pass": !client.socks5_pass.is_empty(),
        "expiresAt": client.expires_at,
        "additionalConfigToml": client.additional_config_toml,
        "enabled": client.enabled,
        "createdAt": client.created_at,
        "updatedAt": client.updated_at,
    })
}

pub async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;
    let mut clients = db::list_mdnsvpn_clients().map_err(map_err)?;
    if user.role < 1 {
        clients.retain(|c| c.user_id == Some(user.id));
    }
    let out: Vec<Value> = clients.iter().map(client_to_json).collect();
    Ok(Json(json!(out)))
}

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(default)]
    pub user_id: Option<i64>,
    #[serde(default)]
    pub listen_port: Option<i64>,
    #[serde(default)]
    pub resolvers: Option<Value>,
    #[serde(default)]
    pub socks5_user: Option<String>,
    #[serde(default)]
    pub socks5_pass: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

pub async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "name is required"));
    }

    let listen_port = body.listen_port.unwrap_or(18000);
    if !(1..=65535).contains(&listen_port) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "listenPort must be 1-65535",
        ));
    }

    // Resolvers: accept either a JSON array (from the UI) or a string
    // (free-form paste). Normalise into a JSON array string for storage.
    let resolvers = match body.resolvers {
        Some(Value::Array(_)) => serde_json::to_string(&body.resolvers).unwrap_or_default(),
        Some(Value::String(s)) => s,
        Some(other) => serde_json::to_string(&other).unwrap_or_default(),
        None => String::new(),
    };

    // SOCKS5 auth is per-client. Empty user disables auth in the
    // generated config — handled by share::render_bundle.
    let socks5_user = body.socks5_user.unwrap_or_default().trim().to_string();
    let socks5_pass = body.socks5_pass.unwrap_or_default();
    if !socks5_user.is_empty() && socks5_pass.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "socks5_pass is required when socks5_user is set",
        ));
    }

    let id = db::create_mdnsvpn_client(&db::CreateMdnsvpnClientParams {
        user_id: body.user_id,
        inbound_id: "mdnsvpn0".into(),
        name,
        resolvers,
        listen_port,
        socks5_user,
        socks5_pass,
        expires_at: body.expires_at,
        additional_config_toml: None,
        enabled: true,
    })
    .map_err(|e| api_err(StatusCode::BAD_REQUEST, &format!("create failed: {e}")))?;

    // No supervisor reconcile needed — mdnsvpn doesn't track clients.
    let created = db::get_mdnsvpn_client(id).map_err(map_err)?;
    Ok(Json(client_to_json(&created)))
}

pub async fn get_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;
    let client = db::get_mdnsvpn_client(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "MasterDnsVPN client not found"))?;
    if user.role < 1 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(Json(client_to_json(&client)))
}

#[derive(Deserialize)]
pub struct UpdateClientRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub listen_port: Option<i64>,
    #[serde(default)]
    pub resolvers: Option<Value>,
    #[serde(default)]
    pub socks5_user: Option<String>,
    #[serde(default)]
    pub socks5_pass: Option<String>,
    /// `Some(Some(s))` sets the value, `Some(None)` clears it,
    /// `None` leaves it untouched.
    #[serde(default)]
    pub expires_at: Option<Option<String>>,
    #[serde(default, rename = "additionalConfigToml")]
    pub additional_config_toml: Option<String>,
}

pub async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Json(body): Json<UpdateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    let mut fields = db::UpdateMap::new();
    if let Some(ref v) = body.name {
        if v.trim().is_empty() {
            return Err(api_err(StatusCode::BAD_REQUEST, "name must not be empty"));
        }
        fields.insert("name".into(), v.trim().to_string());
    }
    if let Some(v) = body.enabled {
        fields.insert("enabled".into(), if v { "1".into() } else { "0".into() });
    }
    if let Some(p) = body.listen_port {
        if !(1..=65535).contains(&p) {
            return Err(api_err(StatusCode::BAD_REQUEST, "listenPort must be 1-65535"));
        }
        fields.insert("listen_port".into(), p.to_string());
    }
    if let Some(r) = body.resolvers {
        let stored = match r {
            Value::Array(_) | Value::Object(_) => {
                serde_json::to_string(&r).unwrap_or_default()
            }
            Value::String(s) => s,
            Value::Null => String::new(),
            other => serde_json::to_string(&other).unwrap_or_default(),
        };
        fields.insert("resolvers".into(), stored);
    }
    if let Some(u) = body.socks5_user {
        fields.insert("socks5_user".into(), u);
    }
    if let Some(p) = body.socks5_pass {
        fields.insert("socks5_pass".into(), p);
    }
    if let Some(ref v) = body.expires_at {
        match v {
            Some(s) => fields.insert("expires_at".into(), s.clone()),
            None => fields.insert("expires_at".into(), String::new()),
        };
    }
    if let Some(ref v) = body.additional_config_toml {
        fields.insert("additional_config_toml".into(), v.clone());
    }

    if fields.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }
    db::update_mdnsvpn_client(id, &fields).map_err(map_err)?;
    Ok(ok_success())
}

#[derive(Deserialize, Default)]
pub struct DeleteClientParams {
    /// When `true`, rotate the shared encryption key as part of the delete so
    /// the removed client's saved config actually stops working. This is the
    /// ONLY way to revoke a MasterDnsVPN client — the protocol has a single
    /// singleton key shared by every client, with no per-user secret and no
    /// server-side roster, so deleting the DB row alone does not stop that
    /// client from connecting. Rotating invalidates *all* clients (they must
    /// re-download configs), so it is opt-in rather than automatic.
    #[serde(default, rename = "rotateKey")]
    pub rotate_key: bool,
}

pub async fn delete_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
    Query(params): Query<DeleteClientParams>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let _admin = require_admin(&jar, &state)?;
    db::delete_mdnsvpn_client(id).map_err(map_err)?;

    if params.rotate_key {
        let new_key = mdnsvpn::keys::generate_key();
        db::update_mdnsvpn_encryption_key(&new_key).map_err(map_err)?;
        reconcile_supervisor().await;
        return Ok(Json(json!({
            "success": true,
            "keyRotated": true,
            "revoked": true,
            "warning": "Shared key rotated: the removed client is revoked, but ALL \
                        remaining clients must re-download their config to keep working.",
        })));
    }

    Ok(Json(json!({
        "success": true,
        "keyRotated": false,
        "revoked": false,
        "warning": "Client row deleted, but MasterDnsVPN shares one key across all \
                    clients — the removed client keeps access until you rotate the \
                    encryption key (delete with rotateKey=true, or use regenerate-key).",
    })))
}

// ---------------------------------------------------------------------------
// Share endpoints (config files / QR / share string)
// ---------------------------------------------------------------------------

async fn load_for_share(
    state: &AppState,
    jar: &CookieJar,
    id: i64,
) -> Result<(db::MdnsvpnInbound, db::MdnsvpnClient), (StatusCode, Json<Value>)> {
    let user = require_auth(jar, state)?;
    let client = db::get_mdnsvpn_client(id)
        .map_err(|_| api_err(StatusCode::NOT_FOUND, "MasterDnsVPN client not found"))?;
    if user.role < 1 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    let inbound = db::get_mdnsvpn_inbound().map_err(map_err)?;
    if inbound.encryption_key.trim().is_empty() {
        return Err(api_err(
            StatusCode::PRECONDITION_FAILED,
            "MasterDnsVPN encryption key is not set — generate one in the admin UI first",
        ));
    }
    let domains_trimmed = inbound.domains.trim();
    if domains_trimmed.is_empty() || domains_trimmed == "[]" {
        return Err(api_err(
            StatusCode::PRECONDITION_FAILED,
            "MasterDnsVPN inbound has no domains set — configure them in the admin UI first",
        ));
    }
    Ok((inbound, client))
}

fn sanitize_filename(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() {
        "client".to_string()
    } else {
        s
    }
}

pub async fn client_config_toml(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client) = load_for_share(&state, &jar, id).await?;
    let bundle = mdnsvpn::share::render_bundle(&inbound, &client).map_err(map_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/toml; charset=utf-8".parse().unwrap(),
    );
    let filename = format!("client_config_{}.toml", sanitize_filename(&client.name));
    headers.insert(
        header::CONTENT_DISPOSITION,
        super::attachment_disposition(&filename),
    );
    Ok((StatusCode::OK, headers, bundle.config_toml))
}

pub async fn client_resolvers_txt(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client) = load_for_share(&state, &jar, id).await?;
    let bundle = mdnsvpn::share::render_bundle(&inbound, &client).map_err(map_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/plain; charset=utf-8".parse().unwrap(),
    );
    let filename = format!("client_resolvers_{}.txt", sanitize_filename(&client.name));
    headers.insert(
        header::CONTENT_DISPOSITION,
        super::attachment_disposition(&filename),
    );
    Ok((StatusCode::OK, headers, bundle.resolvers_txt))
}

pub async fn client_config_json(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client) = load_for_share(&state, &jar, id).await?;
    let bundle = mdnsvpn::share::render_bundle(&inbound, &client).map_err(map_err)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "application/json; charset=utf-8".parse().unwrap(),
    );
    Ok((StatusCode::OK, headers, bundle.config_json))
}

pub async fn client_share_url(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client) = load_for_share(&state, &jar, id).await?;
    let bundle = mdnsvpn::share::render_bundle(&inbound, &client).map_err(map_err)?;
    // Custom URI scheme so a single share string carries everything
    // mdnsvpn needs. Mirrors `vless://` and `tg://proxy?…` — the
    // upstream client doesn't natively parse `mdnsvpn://`, but the
    // base64 payload is what feeds into `mdnsvpn -json_base64 <blob>`.
    let url = format!("mdnsvpn://b64?{}", bundle.config_json_base64);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        "text/plain; charset=utf-8".parse().unwrap(),
    );
    Ok((StatusCode::OK, headers, url))
}

pub async fn client_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let (inbound, client) = load_for_share(&state, &jar, id).await?;
    let bundle = mdnsvpn::share::render_bundle(&inbound, &client).map_err(map_err)?;
    let url = format!("mdnsvpn://b64?{}", bundle.config_json_base64);
    let svg = crate::qr::generate_qr_svg(&url)
        .map_err(|e| api_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("qr: {e}")))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "image/svg+xml".parse().unwrap());
    Ok((StatusCode::OK, headers, svg))
}

// ---------------------------------------------------------------------------
// Supervisor reconciliation hook
// ---------------------------------------------------------------------------

#[cfg(mdnsvpn_bundled)]
async fn reconcile_supervisor() {
    if let Err(e) = mdnsvpn::supervisor::ensure_running().await {
        // Non-fatal — the admin UI shows the failure via /status.
        tracing::warn!(error = ?e, "mdnsvpn supervisor reconcile failed");
    }
}

#[cfg(not(mdnsvpn_bundled))]
async fn reconcile_supervisor() {}
