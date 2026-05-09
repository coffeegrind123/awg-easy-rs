//! Miscellaneous routes (one-time links, metrics, info).
//!
//! | Method | Route                | Description               |
//! |--------|----------------------|---------------------------|
//! | GET    | /cnf/:oneTimeLink     | Client config via token   |
//! | GET    | /metrics/json         | JSON traffic metrics      |
//! | GET    | /metrics/prometheus   | Prometheus text metrics   |
//! | GET    | /api/information      | Version/release info      |
//! | GET    | /api/interface        | Interface public info     |

use axum::extract::Path;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};

use super::{api_err, map_err};
use crate::{auth, db, wg};

/// Constant-time string equality for short tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate the incoming Authorization header against the stored metrics
/// password. The password is stored hashed (sha-256 hex) — see `update_general`.
fn check_metrics_password(headers: &HeaderMap, stored_hash: &str) -> bool {
    if stored_hash.is_empty() {
        return true;
    }
    let auth = match headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => return false,
    };
    let token = if let Some(rest) = auth.strip_prefix("Bearer ") {
        rest.trim().to_string()
    } else {
        return false;
    };
    let supplied_hash = auth::sha256(&token);
    constant_time_eq(supplied_hash.as_bytes(), stored_hash.as_bytes())
}

// ---------------------------------------------------------------------------
// GET /api/information
// ---------------------------------------------------------------------------

pub async fn information() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let version = env!("CARGO_PKG_VERSION");
    let iface = db::get_interface().map_err(map_err)?;
    let setup_step = db::get_setup_step().unwrap_or(0);
    let user_count = db::get_user_count().unwrap_or(0);

    Ok(Json(json!({
        "currentRelease": version,
        "defaultConfig": iface.ipv4_cidr,
        "latestRelease": null,
        "setupNeeded": setup_step != 0 || user_count == 0,
        "isAwg": true,
        "firewallEnabled": iface.firewall_enabled,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/interface
// ---------------------------------------------------------------------------

pub async fn interface_info() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let iface = db::get_interface().map_err(map_err)?;

    Ok(Json(json!({
        "isAwg": true,
        "firewallEnabled": iface.firewall_enabled,
    })))
}

// ---------------------------------------------------------------------------
// GET /cnf/:oneTimeLink — one-time client config download
// ---------------------------------------------------------------------------

pub async fn one_time_link(
    Path(token): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    // Look up token
    let link = db::get_one_time_link(&token).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Invalid or expired one-time link")
    })?;

    // Check expiry
    if let Some(ref expires) = link.expires_at {
        if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires) {
            if chrono::Utc::now() > exp {
                // Remove expired link
                let _ = db::delete_one_time_link(link.id);
                return Err(api_err(StatusCode::GONE, "One-time link has expired"));
            }
        }
    }

    // Generate client config
    let config = wg::get_client_config(link.id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;

    let client = db::get_client(link.id).map_err(|_| {
        api_err(StatusCode::NOT_FOUND, "Client not found")
    })?;

    // Delete the one-time link (one-time use)
    let _ = db::delete_one_time_link(link.id);

    let filename = format!("{}.conf", sanitize_filename(&client.name));
    let content_disp = format!("attachment; filename=\"{}\"", filename);

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/x-wireguard-config".parse().unwrap());
    headers.insert(header::CONTENT_DISPOSITION, content_disp.parse().unwrap());

    Ok((StatusCode::OK, headers, config))
}

// ---------------------------------------------------------------------------
// GET /metrics/json
// ---------------------------------------------------------------------------

pub async fn metrics_json(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let general = db::get_general().map_err(map_err)?;

    if !general.metrics_json {
        return Err(api_err(StatusCode::FORBIDDEN, "JSON metrics disabled"));
    }

    if let Some(ref hash) = general.metrics_password {
        if !check_metrics_password(&headers, hash) {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Bearer token required"));
        }
    }

    let iface = db::get_interface().map_err(map_err)?;
    let clients = db::get_all_clients().map_err(map_err)?;
    let peers = wg::dump_peers(&iface.name).unwrap_or_default();

    let metrics: Vec<Value> = clients
        .iter()
        .map(|client| {
            let peer = peers.iter().find(|p| p.public_key == client.public_key);
            json!({
                "id": client.id,
                "name": client.name,
                "enabled": client.enabled,
                "transferRx": peer.map(|p| p.transfer_rx).unwrap_or(0),
                "transferTx": peer.map(|p| p.transfer_tx).unwrap_or(0),
                "latestHandshakeAt": peer.and_then(|p| p.latest_handshake.map(|d| d.to_rfc3339())),
                "endpoint": peer.and_then(|p| p.endpoint.clone()),
                "online": peer.map(|p| p.latest_handshake.is_some()).unwrap_or(false),
            })
        })
        .collect();

    Ok(Json(json!({
        "interface": {
            "name": iface.name,
            "port": iface.port,
        },
        "clients": metrics,
        "totalClients": clients.len(),
        "onlineClients": peers.iter().filter(|p| p.latest_handshake.is_some()).count(),
    })))
}

// ---------------------------------------------------------------------------
// GET /metrics/prometheus
// ---------------------------------------------------------------------------

pub async fn metrics_prometheus(
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    let general = db::get_general().map_err(map_err)?;

    if !general.metrics_prometheus {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Prometheus metrics disabled",
        ));
    }

    if let Some(ref hash) = general.metrics_password {
        if !check_metrics_password(&headers, hash) {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Bearer token required"));
        }
    }

    let iface = db::get_interface().map_err(map_err)?;
    let clients = db::get_all_clients().map_err(map_err)?;
    let peers = wg::dump_peers(&iface.name).unwrap_or_default();

    let mut output = String::new();

    // Interface metrics
    output.push_str("# HELP wireguard_info Interface information\n");
    output.push_str("# TYPE wireguard_info gauge\n");
    output.push_str(&format!(
        "wireguard_info{{interface=\"{}\",port=\"{}\"}} 1\n",
        iface.name, iface.port
    ));

    // Client metrics
    output.push_str("# HELP wireguard_peer_rx_bytes Bytes received per peer\n");
    output.push_str("# TYPE wireguard_peer_rx_bytes counter\n");

    output.push_str("# HELP wireguard_peer_tx_bytes Bytes transmitted per peer\n");
    output.push_str("# TYPE wireguard_peer_tx_bytes counter\n");

    output.push_str("# HELP wireguard_peer_latest_handshake Latest handshake timestamp\n");
    output.push_str("# TYPE wireguard_peer_latest_handshake gauge\n");

    output.push_str("# HELP wireguard_peer_online Whether the peer is online (1 = yes)\n");
    output.push_str("# TYPE wireguard_peer_online gauge\n");

    for client in &clients {
        let peer = peers.iter().find(|p| p.public_key == client.public_key);
        let safe_name = client.name.replace('"', "\\\"");

        let rx = peer.map(|p| p.transfer_rx).unwrap_or(0);
        let tx = peer.map(|p| p.transfer_tx).unwrap_or(0);
        let hs = peer
            .and_then(|p| p.latest_handshake)
            .map(|d| d.timestamp())
            .unwrap_or(0);
        let online = if peer.map(|p| p.latest_handshake.is_some()).unwrap_or(false) { 1 } else { 0 };

        output.push_str(&format!(
            "wireguard_peer_rx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            iface.name, safe_name, client.id, rx
        ));
        output.push_str(&format!(
            "wireguard_peer_tx_bytes{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            iface.name, safe_name, client.id, tx
        ));
        output.push_str(&format!(
            "wireguard_peer_latest_handshake{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            iface.name, safe_name, client.id, hs
        ));
        output.push_str(&format!(
            "wireguard_peer_online{{interface=\"{}\",name=\"{}\",id=\"{}\"}} {}\n",
            iface.name, safe_name, client.id, online
        ));
    }

    // Total counts
    output.push_str("# HELP wireguard_peers_total Total number of peers\n");
    output.push_str("# TYPE wireguard_peers_total gauge\n");
    output.push_str(&format!("wireguard_peers_total {}\n", clients.len()));

    let online_count = peers.iter().filter(|p| p.latest_handshake.is_some()).count();
    output.push_str("# HELP wireguard_peers_online Number of online peers\n");
    output.push_str("# TYPE wireguard_peers_online gauge\n");
    output.push_str(&format!("wireguard_peers_online {}\n", online_count));

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        output,
    ))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
