//! WireGuard client CRUD handlers.
//!
//! | Method | Route                                  | Description           |
//! |--------|----------------------------------------|-----------------------|
//! | GET    | /api/client                            | List all clients      |
//! | POST   | /api/client                            | Create client         |
//! | GET    | /api/client/:id                        | Get single client     |
//! | POST   | /api/client/:id                        | Update client         |
//! | DELETE | /api/client/:id                        | Delete client         |
//! | GET    | /api/client/:id/configuration          | Download .conf        |
//! | GET    | /api/client/:id/qrcode.svg             | QR code SVG           |
//! | POST   | /api/client/:id/enable                 | Enable client         |
//! | POST   | /api/client/:id/disable                | Disable client        |
//! | POST   | /api/client/:id/generateOneTimeLink    | One-time config link  |

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{api_err, map_err, ok_success, require_auth, AppState};
use crate::{db, wg};

// ---------------------------------------------------------------------------
// Query params for list
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct ClientFilter {
    pub filter: Option<String>,
}

// ---------------------------------------------------------------------------
// Create request body
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateClientRequest {
    pub name: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateClientRequest {
    name: Option<String>,
    #[serde(rename = "ipv4Address")]
    ipv4_address: Option<String>,
    #[serde(rename = "ipv6Address")]
    ipv6_address: Option<String>,
    enabled: Option<bool>,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    dns: Option<Vec<String>>,
    #[serde(rename = "allowedIps")]
    allowed_ips: Option<Vec<String>>,
    #[serde(rename = "firewallIps")]
    firewall_ips: Option<Vec<String>>,
    mtu: Option<i64>,
    #[serde(rename = "persistentKeepalive")]
    persistent_keepalive: Option<i64>,
    #[serde(rename = "preUp")]
    pre_up: Option<String>,
    #[serde(rename = "postUp")]
    post_up: Option<String>,
    #[serde(rename = "preDown")]
    pre_down: Option<String>,
    #[serde(rename = "postDown")]
    post_down: Option<String>,
    #[serde(rename = "serverEndpoint")]
    server_endpoint: Option<String>,
    #[serde(rename = "jC")]
    j_c: Option<i64>,
    #[serde(rename = "jMin")]
    j_min: Option<i64>,
    #[serde(rename = "jMax")]
    j_max: Option<i64>,
    i1: Option<String>,
    i2: Option<String>,
    i3: Option<String>,
    i4: Option<String>,
    i5: Option<String>,
}

// ---------------------------------------------------------------------------
// Helper: build a JSON representation of a client augmented with wg dump data.
// ---------------------------------------------------------------------------

fn client_to_json(client: &db::Client, peers: &[wg::cli::PeerDump]) -> Value {
    let peer = peers.iter().find(|p| p.public_key == client.public_key);

    json!({
        "id": client.id,
        "userId": client.user_id,
        "interfaceId": client.interface_id,
        "name": client.name,
        "ipv4Address": client.ipv4_address,
        "ipv6Address": client.ipv6_address,
        "privateKey": client.private_key,
        "publicKey": client.public_key,
        "preSharedKey": client.pre_shared_key,
        "preUp": client.pre_up,
        "postUp": client.post_up,
        "preDown": client.pre_down,
        "postDown": client.post_down,
        "expiresAt": client.expires_at,
        "allowedIps": client.allowed_ips,
        "serverAllowedIps": client.server_allowed_ips,
        "firewallIps": client.firewall_ips,
        "persistentKeepalive": client.persistent_keepalive,
        "mtu": client.mtu,
        "jC": client.j_c,
        "jMin": client.j_min,
        "jMax": client.j_max,
        "i1": client.i1,
        "i2": client.i2,
        "i3": client.i3,
        "i4": client.i4,
        "i5": client.i5,
        "dns": client.dns,
        "serverEndpoint": client.server_endpoint,
        "enabled": client.enabled,
        "createdAt": client.created_at,
        "updatedAt": client.updated_at,
        // Runtime data from wg dump
        "transferRx": peer.map(|p| p.transfer_rx).unwrap_or(0),
        "transferTx": peer.map(|p| p.transfer_tx).unwrap_or(0),
        "latestHandshakeAt": peer.and_then(|p| p.latest_handshake.map(|d| d.to_rfc3339())),
        "endpoint": peer.and_then(|p| p.endpoint.clone()),
    })
}

// ---------------------------------------------------------------------------
// GET /api/client — list clients
// ---------------------------------------------------------------------------

pub async fn list_clients(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(filter): Query<ClientFilter>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let clients = db::get_all_clients().map_err(map_err)?;
    let iface = db::get_interface().map_err(map_err)?;
    let peers = wg::dump_peers(&iface.name).unwrap_or_default();

    let list: Vec<Value> = clients
        .into_iter()
        .filter(|c| {
            // Non-admin users can only see their own clients
            if user.role == 0 && c.user_id != Some(user.id) {
                return false;
            }
            if let Some(ref term) = filter.filter {
                let term = term.to_lowercase();
                c.name.to_lowercase().contains(&term)
                    || c.ipv4_address
                        .as_ref()
                        .map(|ip| ip.to_lowercase().contains(&term))
                        .unwrap_or(false)
                    || c.public_key.to_lowercase().contains(&term)
            } else {
                true
            }
        })
        .map(|c| client_to_json(&c, &peers))
        .collect();

    Ok(Json(json!(list)))
}

// ---------------------------------------------------------------------------
// POST /api/client — create client
// ---------------------------------------------------------------------------

pub async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<CreateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let iface = db::get_interface().map_err(map_err)?;
    let user_config = db::get_user_config().map_err(map_err)?;

    // Generate keys
    let (private_key, public_key) = wg::generate_keypair().map_err(map_err)?;
    let psk = wg::generate_psk().map_err(map_err)?;

    // Allocate IPs
    let existing_clients = db::get_all_clients().map_err(map_err)?;
    let used_v4: Vec<String> = existing_clients
        .iter()
        .filter_map(|c| c.ipv4_address.clone())
        .collect();
    let used_v6: Vec<String> = existing_clients
        .iter()
        .filter_map(|c| c.ipv6_address.clone())
        .collect();

    let ipv4 = db::next_ipv4(&iface.ipv4_cidr, &used_v4).map_err(map_err)?;

    let ipv6 = if !iface.ipv6_cidr.is_empty() {
        Some(db::next_ipv6(&iface.ipv6_cidr, &used_v6).map_err(map_err)?)
    } else {
        None
    };

    // Build CreateClientParams with sensible defaults from user_config
    let params = db::CreateClientParams {
        user_id: Some(user.id),
        interface_id: Some(iface.name.clone()),
        name: body.name,
        ipv4_address: Some(ipv4),
        ipv6_address: ipv6,
        private_key,
        public_key,
        pre_shared_key: Some(psk),
        pre_up: None,
        post_up: None,
        pre_down: None,
        post_down: None,
        expires_at: body.expires_at,
        allowed_ips: Some(user_config.default_allowed_ips.clone()),
        server_allowed_ips: None,
        firewall_ips: None,
        persistent_keepalive: user_config.default_persistent_keepalive,
        mtu: user_config.default_mtu,
        j_c: None,
        j_min: None,
        j_max: None,
        i1: None,
        i2: None,
        i3: None,
        i4: None,
        i5: None,
        dns: Some(user_config.default_dns.clone()),
        server_endpoint: None,
        enabled: true,
    };

    let client_id = db::create_client(&params).map_err(map_err)?;

    // Save config to apply changes
    wg::save_config().map_err(map_err)?;

    // Rebuild firewall if enabled
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(Json(json!({
        "success": true,
        "clientId": client_id,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/client/:id — get single client
// ---------------------------------------------------------------------------

pub async fn get_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }
    let iface = db::get_interface().map_err(map_err)?;
    let peers = wg::dump_peers(&iface.name).unwrap_or_default();

    Ok(Json(client_to_json(&client, &peers)))
}

// ---------------------------------------------------------------------------
// POST /api/client/:id — update client
// ---------------------------------------------------------------------------

pub async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
    Json(body): Json<UpdateClientRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Validate numeric fields
    if let Some(mtu) = body.mtu {
        if mtu < 68 || mtu > 65535 {
            return Err(api_err(StatusCode::BAD_REQUEST, "MTU must be 68-65535"));
        }
    }
    if let Some(pk) = body.persistent_keepalive {
        if pk != 0 && (pk < 15 || pk > 65535) {
            return Err(api_err(StatusCode::BAD_REQUEST, "PersistentKeepalive must be 0 or 15-65535"));
        }
    }
    if let Some(jc) = body.j_c {
        if jc < 1 || jc > 128 {
            return Err(api_err(StatusCode::BAD_REQUEST, "JC must be 1-128"));
        }
    }
    if let Some(jmin) = body.j_min {
        if jmin < 0 || jmin > 1279 {
            return Err(api_err(StatusCode::BAD_REQUEST, "JMin must be 0-1279"));
        }
    }
    if let Some(jmax) = body.j_max {
        if jmax < 1 || jmax > 1280 {
            return Err(api_err(StatusCode::BAD_REQUEST, "JMax must be 1-1280"));
        }
        if let Some(jmin) = body.j_min {
            if jmax <= jmin {
                return Err(api_err(StatusCode::BAD_REQUEST, "JMax must be > JMin"));
            }
        }
    }
    // j_c must be >= j_min when both are provided
    if let (Some(jc), Some(jmin)) = (body.j_c, body.j_min) {
        if jc < jmin {
            return Err(api_err(StatusCode::BAD_REQUEST, "Jc must be >= Jmin"));
        }
    }
    if let Some(ref expires) = body.expires_at {
        // Try RFC3339 first, then ISO 8601 without timezone
        let is_valid_date = chrono::DateTime::parse_from_rfc3339(expires).is_ok()
            || chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M").is_ok()
            || chrono::NaiveDateTime::parse_from_str(expires, "%Y-%m-%dT%H:%M:%S").is_ok();
        if !is_valid_date {
            return Err(api_err(StatusCode::BAD_REQUEST, "Invalid date format for expiresAt. Use ISO 8601 format."));
        }
    }

    // Verify client exists and check ownership
    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    let mut fields = db::UpdateMap::new();
    if let Some(ref v) = body.name { fields.insert("name".into(), v.clone()); }
    if let Some(ref v) = body.ipv4_address { fields.insert("ipv4_address".into(), v.clone()); }
    if let Some(ref v) = body.ipv6_address { fields.insert("ipv6_address".into(), v.clone()); }
    if let Some(v) = body.enabled { fields.insert("enabled".into(), if v { "1".into() } else { "0".into() }); }
    if let Some(ref v) = body.expires_at { fields.insert("expires_at".into(), v.clone()); }
    if let Some(ref v) = body.dns { fields.insert("dns".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(ref v) = body.allowed_ips { fields.insert("allowed_ips".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(ref v) = body.firewall_ips { fields.insert("firewall_ips".into(), serde_json::to_string(v).unwrap_or_default()); }
    if let Some(v) = body.mtu { fields.insert("mtu".into(), v.to_string()); }
    if let Some(v) = body.persistent_keepalive { fields.insert("persistent_keepalive".into(), v.to_string()); }
    if let Some(ref v) = body.pre_up { fields.insert("pre_up".into(), v.clone()); }
    if let Some(ref v) = body.post_up { fields.insert("post_up".into(), v.clone()); }
    if let Some(ref v) = body.pre_down { fields.insert("pre_down".into(), v.clone()); }
    if let Some(ref v) = body.post_down { fields.insert("post_down".into(), v.clone()); }
    if let Some(ref v) = body.server_endpoint { fields.insert("server_endpoint".into(), v.clone()); }
    if let Some(v) = body.j_c { fields.insert("j_c".into(), v.to_string()); }
    if let Some(v) = body.j_min { fields.insert("j_min".into(), v.to_string()); }
    if let Some(v) = body.j_max { fields.insert("j_max".into(), v.to_string()); }
    if let Some(ref v) = body.i1 { fields.insert("i1".into(), v.clone()); }
    if let Some(ref v) = body.i2 { fields.insert("i2".into(), v.clone()); }
    if let Some(ref v) = body.i3 { fields.insert("i3".into(), v.clone()); }
    if let Some(ref v) = body.i4 { fields.insert("i4".into(), v.clone()); }
    if let Some(ref v) = body.i5 { fields.insert("i5".into(), v.clone()); }

    if fields.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "No fields to update"));
    }

    db::update_client(client_id, &fields).map_err(map_err)?;
    wg::save_config().map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// DELETE /api/client/:id — delete client
// ---------------------------------------------------------------------------

pub async fn delete_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::delete_client(client_id).map_err(|e| {
        api_err(StatusCode::NOT_FOUND, &e.to_string())
    })?;
    wg::save_config().map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// GET /api/client/:id/configuration — download .conf
// ---------------------------------------------------------------------------

pub async fn client_configuration(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    let config = wg::get_client_config(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found or config generation failed")
    })?;

    let filename = format!("{}.conf", sanitize_filename(&client.name));
    let content_disp = format!("attachment; filename=\"{}\"", filename);

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/x-wireguard-config".parse().unwrap());
    headers.insert(header::CONTENT_DISPOSITION, content_disp.parse().unwrap());

    Ok((StatusCode::OK, headers, config))
}

// ---------------------------------------------------------------------------
// GET /api/client/:id/qrcode.svg — QR code SVG
// ---------------------------------------------------------------------------

pub async fn client_qrcode(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    let config = wg::get_client_config(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found or config generation failed")
    })?;

    let svg = crate::qr::generate_qr_svg(&config).map_err(map_err)?;

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/svg+xml")],
        svg,
    ))
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/enable — enable client
// ---------------------------------------------------------------------------

pub async fn enable_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::toggle_client(client_id, true).map_err(map_err)?;
    wg::save_config().map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/disable — disable client
// ---------------------------------------------------------------------------

pub async fn disable_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    db::toggle_client(client_id, false).map_err(map_err)?;
    wg::save_config().map_err(map_err)?;

    // Rebuild firewall if enabled
    let iface = db::get_interface().map_err(map_err)?;
    if iface.firewall_enabled {
        crate::firewall::rebuild_rules().map_err(map_err).ok();
    }

    Ok(ok_success())
}

// ---------------------------------------------------------------------------
// POST /api/client/:id/generateOneTimeLink — one-time config link
// ---------------------------------------------------------------------------

pub async fn generate_one_time_link(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(client_id): Path<i64>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user = require_auth(&jar, &state)?;

    // Verify client exists and check ownership
    let client = db::get_client(client_id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;
    if user.role == 0 && client.user_id != Some(user.id) {
        return Err(api_err(StatusCode::FORBIDDEN, "Access denied"));
    }

    // Generate CSPRNG-based token (validate config generation)
    let _config = wg::get_client_config(client_id).map_err(map_err)?;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);

    // Expire in 5 minutes
    let expires = chrono::Utc::now() + chrono::Duration::minutes(5);

    db::create_one_time_link(
        client_id,
        &token,
        &expires.to_rfc3339(),
    )
    .map_err(map_err)?;

    Ok(Json(json!({
        "success": true,
        "token": token,
        "expiresAt": expires.to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
