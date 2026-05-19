//! `vless://` share-link builder + amnezia-client compatible JSON template.
//!
//! Every Xray client we surveyed (v2rayN, v2rayNG, Shadowrocket,
//! Streisand, NekoBox, Hiddify, FoXray, Wings X, ...) consumes the same
//! `vless://uuid@host:port?…` URI shape. Reality-specific query params
//! line up with the field names in `realitySettings`:
//!
//! ```text
//! vless://<uuid>@<host>:<port>
//!     ?encryption=none
//!     &security=reality
//!     &type=tcp|xhttp                ← streamSettings.network
//!     &flow=xtls-rprx-vision         ← tcp only; omitted for xhttp
//!     &path=<xhttp_path>             ← xhttp only; xhttpSettings.path
//!     &sni=<server_name>             ← realitySettings.serverNames[0]
//!     &fp=<fingerprint>              ← uTLS profile (chrome|firefox|...)
//!     &pbk=<public_key>              ← realitySettings.publicKey
//!     &sid=<short_id>                ← realitySettings.shortIds[<peer>]
//!     &spx=<spider_x_path>           ← realitySettings.spiderX (default "/")
//!     #<peer_label>
//! ```
//!
//! For the xhttp transport (amnezia-client/#2339), Vision flow is
//! TCP-only so we drop `flow` entirely and emit `path=<percent-encoded>`
//! — matching `client/core/serialization/vless.cpp` Serialize().
//!
//! The `#fragment` is the human-readable label the client app shows. We
//! percent-encode it because peer names can legitimately contain `#` or
//! whitespace.

use anyhow::{anyhow, Result};

use crate::db;

/// Build the `vless://` share URL for one peer. `host` is the public
/// hostname/IP clients connect to (typically the same as
/// `UserConfig::host` for the AWG side).
pub fn build_vless_url(
    inbound: &db::XrayInbound,
    client: &db::XrayClient,
    host: &str,
) -> Result<String> {
    let server_names: Vec<String> = serde_json::from_str(&inbound.server_names)
        .map_err(|e| anyhow!("xray_inbound.server_names is not a JSON array: {e}"))?;
    let sni = server_names
        .first()
        .ok_or_else(|| anyhow!("xray_inbound.server_names must contain at least one entry"))?
        .clone();

    let public_key = inbound.public_key.trim();
    if public_key.is_empty() {
        return Err(anyhow!(
            "xray_inbound has no public key — generate the Reality keypair first"
        ));
    }

    // Reality params travel through the URL fully verbatim — every
    // reference impl emits them un-encoded because none of them happen
    // to contain reserved characters. We percent-encode anyway so an
    // adventurous operator who picks a fingerprint with `&` in it
    // doesn't end up with a mis-parsed URL.
    let pbk = percent_encode(public_key);
    let sid = percent_encode(&client.short_id);
    let sni_enc = percent_encode(&sni);
    let fp = percent_encode(&inbound.fingerprint_default);
    let label = percent_encode(&client.name);

    let host_clean = host.trim();
    if host_clean.is_empty() {
        return Err(anyhow!("host must be set in user_config before sharing Xray peers"));
    }
    // Bracket bare IPv6 literals so URL parsers don't split on `:`.
    let host_part = format_host_for_url(host_clean);

    // Transport-dependent middle of the query string. For tcp we keep
    // the Vision flow that every classic VLESS+Reality client expects.
    // For xhttp we drop `flow` entirely (Vision is TCP-only) and add
    // the secret `path` — matching amnezia-client's vless.cpp
    // Serialize() which writes `type=xhttp` plus `path=<encoded>`.
    let transport_query = if inbound.transport == "xhttp" {
        if inbound.xhttp_path.trim().is_empty() {
            return Err(anyhow!(
                "xray_inbound.transport is 'xhttp' but xhttp_path is empty \
                 — generate one before sharing this peer"
            ));
        }
        let path = percent_encode(&inbound.xhttp_path);
        format!("&type=xhttp&path={path}")
    } else {
        "&type=tcp&flow=xtls-rprx-vision".to_string()
    };

    // Emit BOTH `spx` (v2rayN / Hiddify / NekoBox / Streisand convention)
    // and `spiderX` (amnezia-client convention — see
    // amnezia-client/client/core/utils/serialization/vless.cpp:235).
    // Same value, different keys — every parser picks up at least one.
    Ok(format!(
        "vless://{uuid}@{host}:{port}\
         ?encryption=none\
         &security=reality\
         {transport_query}\
         &sni={sni}\
         &fp={fp}\
         &pbk={pbk}\
         &sid={sid}\
         &spx=%2F\
         &spiderX=%2F\
         #{label}",
        uuid = client.uuid,
        host = host_part,
        port = inbound.port,
        sni = sni_enc,
        fp = fp,
        pbk = pbk,
        sid = sid,
        label = label,
    ))
}

/// Build the amnezia-client-compatible JSON template (`socks` inbound on
/// 127.0.0.1:10808, vless outbound to the server). Lets users with the
/// official Amnezia VPN client ingest the config natively rather than
/// scanning the URL.
pub fn build_amnezia_json(
    inbound: &db::XrayInbound,
    client: &db::XrayClient,
    host: &str,
) -> Result<String> {
    let server_names: Vec<String> = serde_json::from_str(&inbound.server_names)
        .map_err(|e| anyhow!("xray_inbound.server_names is not a JSON array: {e}"))?;
    let sni = server_names
        .first()
        .ok_or_else(|| anyhow!("xray_inbound.server_names must contain at least one entry"))?
        .clone();

    if inbound.public_key.trim().is_empty() {
        return Err(anyhow!("xray_inbound has no public key"));
    }

    let is_xhttp = inbound.transport == "xhttp";
    // Vision flow is TCP-only — when the server speaks xhttp, the
    // client-side outbound must omit `flow` (empty string round-trips
    // through Xray's JSON loader as "no flow") and add an
    // `xhttpSettings` block mirroring the server template.
    let user_entry = if is_xhttp {
        serde_json::json!({
            "id": client.uuid,
            "encryption": "none",
        })
    } else {
        serde_json::json!({
            "id": client.uuid,
            "flow": "xtls-rprx-vision",
            "encryption": "none",
        })
    };

    let mut stream_settings = serde_json::json!({
        "network": if is_xhttp { "xhttp" } else { "tcp" },
        "security": "reality",
        "realitySettings": {
            "fingerprint": inbound.fingerprint_default,
            "serverName": sni,
            "publicKey": inbound.public_key,
            "shortId": client.short_id,
            "spiderX": "",
        },
    });
    if is_xhttp {
        if inbound.xhttp_path.trim().is_empty() {
            return Err(anyhow!(
                "xray_inbound.transport is 'xhttp' but xhttp_path is empty"
            ));
        }
        stream_settings["xhttpSettings"] = serde_json::json!({
            "path": inbound.xhttp_path,
            "mode": "auto",
        });
    }

    let json = serde_json::json!({
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"udp": true},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": inbound.port,
                    "users": [user_entry],
                }],
            },
            "streamSettings": stream_settings,
        }],
    });
    Ok(serde_json::to_string_pretty(&json)?)
}

/// Bracket IPv6 literals: `2001:db8::1` → `[2001:db8::1]`.
fn format_host_for_url(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

/// Percent-encode the conservative set required for query/fragment
/// values. We re-implement here rather than pulling in `percent-encoding`
/// because the set is small and known. RFC 3986 unreserved + a curated
/// safe-by-context list — `:` is fine in fragments, `/` we encode just
/// in case a client app's parser is strict.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let safe = matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~'
        );
        if safe {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;

    fn inbound_fixture() -> db::XrayInbound {
        db::XrayInbound {
            id: "xray0".into(),
            port: 443,
            dest: "www.microsoft.com:443".into(),
            server_names: r#"["www.microsoft.com"]"#.into(),
            private_key: "PRIV".into(),
            public_key: "7qWmW4TmzGw3YcFUZg6xiI4TDbeS5TTVZO8S1-1SUgg".into(),
            fingerprint_default: "chrome".into(),
            transport: "tcp".into(),
            xhttp_path: String::new(),
            additional_config: String::new(),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    fn client_fixture() -> db::XrayClient {
        db::XrayClient {
            id: 1,
            user_id: None,
            inbound_id: "xray0".into(),
            name: "alice".into(),
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            short_id: "0123456789abcdef".into(),
            expires_at: None,
            additional_config: None,
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn vless_url_has_all_required_params() {
        let url = build_vless_url(&inbound_fixture(), &client_fixture(), "vpn.example.com").unwrap();
        // Scheme + authority
        assert!(url.starts_with("vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443"));
        // Reality must-haves
        assert!(url.contains("encryption=none"));
        assert!(url.contains("security=reality"));
        assert!(url.contains("type=tcp"));
        assert!(url.contains("flow=xtls-rprx-vision"));
        assert!(url.contains("sni=www.microsoft.com"));
        assert!(url.contains("fp=chrome"));
        assert!(url.contains("pbk=7qWmW4TmzGw3YcFUZg6xiI4TDbeS5TTVZO8S1-1SUgg"));
        assert!(url.contains("sid=0123456789abcdef"));
        // Both spx (v2rayN/Hiddify) and spiderX (amnezia-client) must be present.
        assert!(url.contains("spx=%2F"));
        assert!(url.contains("spiderX=%2F"));
        // Label fragment
        assert!(url.ends_with("#alice"));
    }

    #[test]
    fn vless_url_brackets_ipv6_literal() {
        let url = build_vless_url(&inbound_fixture(), &client_fixture(), "2001:db8::1").unwrap();
        assert!(url.contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn vless_url_percent_encodes_label() {
        let mut client = client_fixture();
        client.name = "Alice's Phone #2".into();
        let url = build_vless_url(&inbound_fixture(), &client, "vpn.example.com").unwrap();
        // Apostrophe, space, hash all need encoding to survive a strict
        // parser — Shadowrocket in particular truncates at the first `#`.
        assert!(url.ends_with("#Alice%27s%20Phone%20%232"));
    }

    #[test]
    fn vless_url_rejects_missing_pubkey() {
        let mut inbound = inbound_fixture();
        inbound.public_key = String::new();
        let res = build_vless_url(&inbound, &client_fixture(), "vpn.example.com");
        assert!(res.is_err());
    }

    #[test]
    fn vless_url_rejects_empty_host() {
        let res = build_vless_url(&inbound_fixture(), &client_fixture(), "");
        assert!(res.is_err());
    }

    #[test]
    fn amnezia_json_uses_vision_flow() {
        let cfg = build_amnezia_json(&inbound_fixture(), &client_fixture(), "vpn.example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert_eq!(
            parsed["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
        assert_eq!(
            parsed["outbounds"][0]["streamSettings"]["realitySettings"]["serverName"],
            "www.microsoft.com"
        );
        assert_eq!(parsed["outbounds"][0]["streamSettings"]["network"], "tcp");
        // No xhttpSettings on tcp transport.
        assert!(parsed["outbounds"][0]["streamSettings"]["xhttpSettings"].is_null());
    }

    fn xhttp_inbound_fixture() -> db::XrayInbound {
        let mut i = inbound_fixture();
        i.transport = "xhttp".into();
        i.xhttp_path = "/cafebabecafebabecafebabecafebabe".into();
        i
    }

    #[test]
    fn vless_url_for_xhttp_drops_flow_and_adds_path() {
        let url = build_vless_url(&xhttp_inbound_fixture(), &client_fixture(), "vpn.example.com").unwrap();
        // xhttp must NOT carry the Vision flow — Xray rejects vision
        // over non-tcp transports outright.
        assert!(!url.contains("flow="), "url must not contain flow=, got {url}");
        assert!(url.contains("type=xhttp"));
        // Path must be percent-encoded — leading slash and all hex chars
        // are safe but we encode the slash to mirror amnezia-client's
        // Serialize() (it goes through QUrl::toPercentEncoding which
        // encodes '/' in query values).
        assert!(
            url.contains("path=%2Fcafebabecafebabecafebabecafebabe"),
            "url missing percent-encoded path, got {url}"
        );
    }

    #[test]
    fn amnezia_json_for_xhttp_drops_flow_and_emits_xhttp_settings() {
        let cfg = build_amnezia_json(&xhttp_inbound_fixture(), &client_fixture(), "vpn.example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        // No flow on users[] when transport is xhttp.
        let user = &parsed["outbounds"][0]["settings"]["vnext"][0]["users"][0];
        assert!(user["flow"].is_null(), "users[0].flow must be omitted, got {user}");
        let stream = &parsed["outbounds"][0]["streamSettings"];
        assert_eq!(stream["network"], "xhttp");
        assert_eq!(stream["security"], "reality");
        assert_eq!(stream["xhttpSettings"]["path"], "/cafebabecafebabecafebabecafebabe");
        assert_eq!(stream["xhttpSettings"]["mode"], "auto");
    }

    #[test]
    fn vless_url_xhttp_without_path_errors() {
        let mut inbound = xhttp_inbound_fixture();
        inbound.xhttp_path = String::new();
        let res = build_vless_url(&inbound, &client_fixture(), "vpn.example.com");
        assert!(res.is_err());
    }

    #[test]
    fn amnezia_json_xhttp_without_path_errors() {
        let mut inbound = xhttp_inbound_fixture();
        inbound.xhttp_path = String::new();
        let res = build_amnezia_json(&inbound, &client_fixture(), "vpn.example.com");
        assert!(res.is_err());
    }
}
