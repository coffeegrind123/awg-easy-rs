use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};

use anyhow::{anyhow, Context, Result};
use ipnet::{Ipv4Net, Ipv6Net};
use rand::RngCore;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::config::CONFIG;

// ---------------------------------------------------------------------------
// Global database handle – initialised once by init_db()
// ---------------------------------------------------------------------------
//
// The outer OnceLock is initialised on first use; the inner Mutex<Option<…>>
// allows the test harness to swap the connection between tests without UB.
static DB: OnceLock<Mutex<Option<Connection>>> = OnceLock::new();

fn db_slot() -> &'static Mutex<Option<Connection>> {
    DB.get_or_init(|| Mutex::new(None))
}

/// A guard that exposes the underlying SQLite connection while the global
/// mutex is held. Mirrors the previous `MutexGuard<Connection>` API.
pub struct ConnGuard {
    inner: MutexGuard<'static, Option<Connection>>,
}

impl std::ops::Deref for ConnGuard {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        self.inner
            .as_ref()
            .expect("Database not initialised – call db::init_db() first")
    }
}

impl std::ops::DerefMut for ConnGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
            .as_mut()
            .expect("Database not initialised – call db::init_db() first")
    }
}

fn conn() -> ConnGuard {
    ConnGuard {
        inner: db_slot().lock().expect("Database lock poisoned"),
    }
}

/// Generic field map used by update helpers.
pub type UpdateMap = HashMap<String, String>;

// ---------------------------------------------------------------------------
// Entity structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub device: String,
    pub port: i64,
    pub private_key: String,
    pub public_key: String,
    pub ipv4_cidr: String,
    pub ipv6_cidr: String,
    pub mtu: i64,
    pub j_c: i64,
    pub j_min: i64,
    pub j_max: i64,
    pub s1: i64,
    pub s2: i64,
    pub s3: Option<i64>,
    pub s4: Option<i64>,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    pub i1: String,
    pub i2: String,
    pub i3: String,
    pub i4: String,
    pub i5: String,
    pub firewall_enabled: bool,
    /// Free-form text appended verbatim to the server `[Interface]` block.
    /// Mirrors amnezia-client's `additionalServerConfig` — escape hatch for
    /// keys awg-quick understands but the UI doesn't model. Empty by default.
    pub additional_config: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    pub id: i64,
    pub user_id: Option<i64>,
    pub interface_id: Option<String>,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
    pub expires_at: Option<String>,
    pub allowed_ips: Option<String>,
    pub server_allowed_ips: Option<String>,
    pub firewall_ips: Option<String>,
    pub persistent_keepalive: i64,
    pub mtu: i64,
    pub j_c: Option<i64>,
    pub j_min: Option<i64>,
    pub j_max: Option<i64>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub dns: Option<String>,
    pub server_endpoint: Option<String>,
    /// Tri-state per-peer AmneziaWG opt-in:
    /// - `Some(true)` → emit `AdvancedSecurity = on` in the [Peer] block
    /// - `Some(false)` → emit `AdvancedSecurity = off`
    /// - `None` → omit the key entirely; the kernel auto-detects on first
    ///   handshake by validating the H1 magic header.
    pub advanced_security: Option<bool>,
    /// Free-form text appended to this peer's generated client `[Interface]`
    /// block. When `None`, falls back to `UserConfig::default_additional_config`.
    pub additional_config: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub name: String,
    pub role: i64,
    pub totp_key: Option<String>,
    pub totp_verified: bool,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    pub id: String,
    pub default_mtu: i64,
    pub default_persistent_keepalive: i64,
    pub default_dns: String,
    pub default_allowed_ips: String,
    pub default_j_c: i64,
    pub default_j_min: i64,
    pub default_j_max: i64,
    pub default_i1: String,
    pub default_i2: String,
    pub default_i3: String,
    pub default_i4: String,
    pub default_i5: String,
    /// Default free-form `[Interface]` append used for new clients that don't
    /// override it on their own row. Empty string == no append.
    pub default_additional_config: String,
    pub host: String,
    pub port: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hooks {
    pub id: String,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct General {
    pub id: i64,
    pub setup_step: i64,
    pub session_password: String,
    pub session_timeout: i64,
    pub metrics_prometheus: bool,
    pub metrics_json: bool,
    pub metrics_password: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Singleton "Browsing mode" inbound — one Xray VLESS+Reality+Vision listener
/// per server. Modelled as a single row keyed on `id = 'xray0'` to match
/// the singleton pattern already used by `interfaces_table`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayInbound {
    pub id: String,
    pub port: i64,
    /// Reality `dest` — the upstream `host:port` Xray fronts when DPI
    /// inspects the connection. Must be reachable from the server and
    /// must terminate TLS 1.3 with a SAN matching `server_names[0]`.
    pub dest: String,
    /// JSON array of SNI strings (Reality `serverNames`). The first
    /// entry is what clients put in `?sni=…`.
    pub server_names: String,
    /// Reality x25519 private key (server-side). Empty until first
    /// `regenerate_keys` call.
    pub private_key: String,
    /// Matching x25519 public key (handed to clients in `?pbk=…`).
    pub public_key: String,
    /// Default uTLS fingerprint baked into share links (`chrome`,
    /// `firefox`, `safari`, `randomized`, `random`).
    pub fingerprint_default: String,
    /// Free-form text appended verbatim into the generated `server.json`'s
    /// inbound — escape hatch for sniffing/routing tweaks the UI doesn't
    /// model. Empty by default.
    pub additional_config: String,
    /// When false the supervisor will not start Xray. Safe default —
    /// requires the operator to set `dest`, generate keys, and explicitly
    /// flip the toggle.
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// One Xray (VLESS) peer. The `inbound_id` FK supports multi-inbound
/// later; v1 always points at `'xray0'`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayClient {
    pub id: i64,
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    /// Per-client UUID — goes into `realitySettings.clients[].id` and the
    /// `vless://uuid@…` share URL.
    pub uuid: String,
    /// Per-client Reality short-id (8 hex bytes by default). Pushed into
    /// `realitySettings.shortIds[]` and the `?sid=…` share param.
    pub short_id: String,
    pub expires_at: Option<String>,
    pub additional_config: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimeLink {
    pub id: i64,
    pub one_time_link: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Data required to create a new client.
#[derive(Debug, Clone)]
pub struct CreateClientParams {
    pub user_id: Option<i64>,
    pub interface_id: Option<String>,
    pub name: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub private_key: String,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub pre_up: Option<String>,
    pub post_up: Option<String>,
    pub pre_down: Option<String>,
    pub post_down: Option<String>,
    pub expires_at: Option<String>,
    pub allowed_ips: Option<String>,
    pub server_allowed_ips: Option<String>,
    pub firewall_ips: Option<String>,
    pub persistent_keepalive: i64,
    pub mtu: i64,
    pub j_c: Option<i64>,
    pub j_min: Option<i64>,
    pub j_max: Option<i64>,
    pub i1: Option<String>,
    pub i2: Option<String>,
    pub i3: Option<String>,
    pub i4: Option<String>,
    pub i5: Option<String>,
    pub dns: Option<String>,
    pub server_endpoint: Option<String>,
    pub advanced_security: Option<bool>,
    pub enabled: bool,
}

/// Data required to create a new user.
#[derive(Debug, Clone)]
pub struct CreateUserParams {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub name: String,
    pub role: i64,
    pub totp_key: Option<String>,
    pub totp_verified: bool,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bool_to_int(b: bool) -> i64 {
    if b { 1 } else { 0 }
}

fn int_to_bool(i: i64) -> bool {
    i != 0
}

/// Check if an IPv4/IPv6 address string is contained in the supplied CIDR.
pub fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    if let (Ok(net), Ok(addr)) = (cidr.parse::<Ipv4Net>(), ip.parse::<std::net::Ipv4Addr>()) {
        return net.contains(&addr);
    }
    if let (Ok(net), Ok(addr)) = (cidr.parse::<Ipv6Net>(), ip.parse::<std::net::Ipv6Addr>()) {
        return net.contains(&addr);
    }
    false
}

// ---------------------------------------------------------------------------
// from_row constructors
// ---------------------------------------------------------------------------

impl Interface {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Interface {
            name: row.get("name")?,
            device: row.get("device")?,
            port: row.get("port")?,
            private_key: row.get("private_key")?,
            public_key: row.get("public_key")?,
            ipv4_cidr: row.get("ipv4_cidr")?,
            ipv6_cidr: row.get("ipv6_cidr")?,
            mtu: row.get("mtu")?,
            j_c: row.get("j_c")?,
            j_min: row.get("j_min")?,
            j_max: row.get("j_max")?,
            s1: row.get("s1")?,
            s2: row.get("s2")?,
            s3: row.get("s3")?,
            s4: row.get("s4")?,
            h1: row.get("h1")?,
            h2: row.get("h2")?,
            h3: row.get("h3")?,
            h4: row.get("h4")?,
            i1: row.get("i1")?,
            i2: row.get("i2")?,
            i3: row.get("i3")?,
            i4: row.get("i4")?,
            i5: row.get("i5")?,
            firewall_enabled: int_to_bool(row.get::<_, i64>("firewall_enabled")?),
            // Older DBs may not have this column yet; tolerate it.
            additional_config: row.get("additional_config").unwrap_or_default(),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl Client {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Client {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            interface_id: row.get("interface_id")?,
            name: row.get("name")?,
            ipv4_address: row.get("ipv4_address")?,
            ipv6_address: row.get("ipv6_address")?,
            private_key: row.get("private_key")?,
            public_key: row.get("public_key")?,
            pre_shared_key: row.get("pre_shared_key")?,
            pre_up: row.get("pre_up")?,
            post_up: row.get("post_up")?,
            pre_down: row.get("pre_down")?,
            post_down: row.get("post_down")?,
            expires_at: row.get("expires_at")?,
            allowed_ips: row.get("allowed_ips")?,
            server_allowed_ips: row.get("server_allowed_ips")?,
            firewall_ips: row.get("firewall_ips")?,
            persistent_keepalive: row.get("persistent_keepalive")?,
            mtu: row.get("mtu")?,
            j_c: row.get("j_c")?,
            j_min: row.get("j_min")?,
            j_max: row.get("j_max")?,
            i1: row.get("i1")?,
            i2: row.get("i2")?,
            i3: row.get("i3")?,
            i4: row.get("i4")?,
            i5: row.get("i5")?,
            dns: row.get("dns")?,
            server_endpoint: row.get("server_endpoint")?,
            // Older DBs (created before the column was added) may not have
            // this column; tolerate the missing-column case by defaulting
            // to None so the [Peer] block omits the key and the kernel
            // auto-detects from the H1 magic header.
            advanced_security: row
                .get::<_, Option<i64>>("advanced_security")
                .ok()
                .flatten()
                .map(int_to_bool),
            // Older DBs may not have this column yet; tolerate it.
            additional_config: row.get::<_, Option<String>>("additional_config").ok().flatten(),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl User {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(User {
            id: row.get("id")?,
            username: row.get("username")?,
            password: row.get("password")?,
            email: row.get("email")?,
            name: row.get("name")?,
            role: row.get("role")?,
            totp_key: row.get("totp_key")?,
            totp_verified: int_to_bool(row.get::<_, i64>("totp_verified")?),
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl UserConfig {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(UserConfig {
            id: row.get("id")?,
            default_mtu: row.get("default_mtu")?,
            default_persistent_keepalive: row.get("default_persistent_keepalive")?,
            default_dns: row.get("default_dns")?,
            default_allowed_ips: row.get("default_allowed_ips")?,
            default_j_c: row.get("default_j_c")?,
            default_j_min: row.get("default_j_min")?,
            default_j_max: row.get("default_j_max")?,
            default_i1: row.get("default_i1")?,
            default_i2: row.get("default_i2")?,
            default_i3: row.get("default_i3")?,
            default_i4: row.get("default_i4")?,
            default_i5: row.get("default_i5")?,
            // Older DBs may not have this column yet; tolerate it.
            default_additional_config: row
                .get("default_additional_config")
                .unwrap_or_default(),
            host: row.get("host")?,
            port: row.get("port")?,
        })
    }
}

impl Hooks {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(Hooks {
            id: row.get("id")?,
            pre_up: row.get("pre_up")?,
            post_up: row.get("post_up")?,
            pre_down: row.get("pre_down")?,
            post_down: row.get("post_down")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl General {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(General {
            id: row.get("id")?,
            setup_step: row.get("setup_step")?,
            session_password: row.get("session_password")?,
            session_timeout: row.get("session_timeout")?,
            metrics_prometheus: int_to_bool(row.get::<_, i64>("metrics_prometheus")?),
            metrics_json: int_to_bool(row.get::<_, i64>("metrics_json")?),
            metrics_password: row.get("metrics_password")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl OneTimeLink {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(OneTimeLink {
            id: row.get("id")?,
            one_time_link: row.get("one_time_link")?,
            expires_at: row.get("expires_at")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl XrayInbound {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(XrayInbound {
            id: row.get("id")?,
            port: row.get("port")?,
            dest: row.get("dest")?,
            server_names: row.get("server_names")?,
            private_key: row.get("private_key")?,
            public_key: row.get("public_key")?,
            fingerprint_default: row.get("fingerprint_default")?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

impl XrayClient {
    fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        Ok(XrayClient {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            inbound_id: row.get("inbound_id")?,
            name: row.get("name")?,
            uuid: row.get("uuid")?,
            short_id: row.get("short_id")?,
            expires_at: row.get("expires_at")?,
            additional_config: row.get("additional_config")?,
            enabled: int_to_bool(row.get::<_, i64>("enabled")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SQL DDL – all seven tables with the final schema
// ---------------------------------------------------------------------------

const CREATE_INTERFACES: &str = r#"
CREATE TABLE IF NOT EXISTS interfaces_table (
    name              TEXT PRIMARY KEY,
    device            TEXT NOT NULL,
    port              INTEGER NOT NULL UNIQUE,
    private_key       TEXT NOT NULL,
    public_key        TEXT NOT NULL,
    ipv4_cidr         TEXT NOT NULL,
    ipv6_cidr         TEXT NOT NULL,
    mtu               INTEGER NOT NULL DEFAULT 1420,
    j_c               INTEGER NOT NULL DEFAULT 7,
    j_min             INTEGER NOT NULL DEFAULT 10,
    j_max             INTEGER NOT NULL DEFAULT 1000,
    s1                INTEGER NOT NULL DEFAULT 128,
    s2                INTEGER NOT NULL DEFAULT 56,
    s3                INTEGER,
    s4                INTEGER,
    h1                TEXT NOT NULL DEFAULT '',
    h2                TEXT NOT NULL DEFAULT '',
    h3                TEXT NOT NULL DEFAULT '',
    h4                TEXT NOT NULL DEFAULT '',
    i1                TEXT NOT NULL DEFAULT '',
    i2                TEXT NOT NULL DEFAULT '',
    i3                TEXT NOT NULL DEFAULT '',
    i4                TEXT NOT NULL DEFAULT '',
    i5                TEXT NOT NULL DEFAULT '',
    firewall_enabled  INTEGER NOT NULL DEFAULT 0,
    additional_config TEXT NOT NULL DEFAULT '',
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_CLIENTS: &str = r#"
CREATE TABLE IF NOT EXISTS clients_table (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER,
    interface_id        TEXT,
    name                TEXT NOT NULL,
    ipv4_address        TEXT UNIQUE,
    ipv6_address        TEXT UNIQUE,
    private_key         TEXT NOT NULL,
    public_key          TEXT NOT NULL,
    pre_shared_key      TEXT,
    pre_up              TEXT,
    post_up             TEXT,
    pre_down            TEXT,
    post_down           TEXT,
    expires_at          TEXT,
    allowed_ips         TEXT,
    server_allowed_ips  TEXT,
    firewall_ips        TEXT,
    persistent_keepalive INTEGER NOT NULL DEFAULT 0,
    mtu                 INTEGER NOT NULL DEFAULT 1420,
    j_c                 INTEGER,
    j_min               INTEGER,
    j_max               INTEGER,
    i1                  TEXT,
    i2                  TEXT,
    i3                  TEXT,
    i4                  TEXT,
    i5                  TEXT,
    dns                 TEXT,
    server_endpoint     TEXT,
    advanced_security   INTEGER,
    additional_config   TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)      REFERENCES users_table(id),
    FOREIGN KEY (interface_id) REFERENCES interfaces_table(name)
)"#;

const CREATE_USERS: &str = r#"
CREATE TABLE IF NOT EXISTS users_table (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    password        TEXT NOT NULL,
    email           TEXT,
    name            TEXT NOT NULL DEFAULT '',
    role            INTEGER NOT NULL DEFAULT 0,
    totp_key        TEXT,
    totp_verified   INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_USER_CONFIGS: &str = r#"
CREATE TABLE IF NOT EXISTS user_configs_table (
    id                              TEXT PRIMARY KEY,
    default_mtu                     INTEGER NOT NULL DEFAULT 1420,
    default_persistent_keepalive    INTEGER NOT NULL DEFAULT 0,
    default_dns                     TEXT NOT NULL DEFAULT '[]',
    default_allowed_ips             TEXT NOT NULL DEFAULT '[]',
    default_j_c                     INTEGER NOT NULL DEFAULT 7,
    default_j_min                   INTEGER NOT NULL DEFAULT 10,
    default_j_max                   INTEGER NOT NULL DEFAULT 1000,
    default_i1                      TEXT NOT NULL DEFAULT '',
    default_i2                      TEXT NOT NULL DEFAULT '',
    default_i3                      TEXT NOT NULL DEFAULT '',
    default_i4                      TEXT NOT NULL DEFAULT '',
    default_i5                      TEXT NOT NULL DEFAULT '',
    default_additional_config       TEXT NOT NULL DEFAULT '',
    host                            TEXT NOT NULL DEFAULT '',
    port                            INTEGER NOT NULL DEFAULT 51820,
    created_at                      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at                      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES interfaces_table(name)
)"#;

const CREATE_HOOKS: &str = r#"
CREATE TABLE IF NOT EXISTS hooks_table (
    id              TEXT PRIMARY KEY,
    pre_up          TEXT NOT NULL DEFAULT '',
    post_up         TEXT NOT NULL DEFAULT '',
    pre_down        TEXT NOT NULL DEFAULT '',
    post_down       TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES interfaces_table(name)
)"#;

const CREATE_GENERAL: &str = r#"
CREATE TABLE IF NOT EXISTS general_table (
    id                  INTEGER PRIMARY KEY,
    setup_step          INTEGER NOT NULL DEFAULT 1,
    session_password    TEXT NOT NULL,
    session_timeout     INTEGER NOT NULL DEFAULT 3600,
    metrics_prometheus  INTEGER NOT NULL DEFAULT 0,
    metrics_json        INTEGER NOT NULL DEFAULT 0,
    metrics_password    TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_ONE_TIME_LINKS: &str = r#"
CREATE TABLE IF NOT EXISTS one_time_links_table (
    id              INTEGER PRIMARY KEY,
    one_time_link   TEXT UNIQUE NOT NULL,
    expires_at      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (id) REFERENCES clients_table(id) ON DELETE CASCADE
)"#;

const CREATE_XRAY_INBOUND: &str = r#"
CREATE TABLE IF NOT EXISTS xray_inbound_table (
    id                   TEXT PRIMARY KEY,
    port                 INTEGER NOT NULL DEFAULT 443,
    dest                 TEXT NOT NULL DEFAULT 'www.microsoft.com:443',
    server_names         TEXT NOT NULL DEFAULT '["www.microsoft.com"]',
    private_key          TEXT NOT NULL DEFAULT '',
    public_key           TEXT NOT NULL DEFAULT '',
    fingerprint_default  TEXT NOT NULL DEFAULT 'chrome',
    additional_config    TEXT NOT NULL DEFAULT '',
    enabled              INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at           TEXT NOT NULL DEFAULT (datetime('now'))
)"#;

const CREATE_XRAY_CLIENTS: &str = r#"
CREATE TABLE IF NOT EXISTS xray_clients_table (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER,
    inbound_id          TEXT NOT NULL DEFAULT 'xray0',
    name                TEXT NOT NULL,
    uuid                TEXT NOT NULL UNIQUE,
    short_id            TEXT NOT NULL UNIQUE,
    expires_at          TEXT,
    additional_config   TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id)    REFERENCES users_table(id),
    FOREIGN KEY (inbound_id) REFERENCES xray_inbound_table(id)
)"#;

// ---------------------------------------------------------------------------
// Hook templates
// ---------------------------------------------------------------------------

// Native nftables hooks. All rules live inside one `inet awg-easy-rs`
// table so PostDown can wipe everything atomically with a single
// `nft delete table`. Per-client filtering rules go into the empty
// `wg-clients` chain — those are populated separately by `firewall.rs`
// via `nft -f -` transactions when the firewall toggle is enabled.
//
// Forward-chain policy is `accept`. With no jump rules in place, all
// traffic forwards as before. When firewall.rs adds the jumps, traffic
// from the AWG interface diverts into `wg-clients`, hits per-peer
// accept rules or the final `drop`, and only returns to forward (and
// thus the accept policy) for explicitly-allowed flows.
const POST_UP_TEMPLATE: &str = concat!(
    "nft add table inet awg-easy-rs;",
    " nft 'add chain inet awg-easy-rs forward { type filter hook forward priority filter; policy accept; }';",
    " nft 'add chain inet awg-easy-rs nat-postrouting { type nat hook postrouting priority srcnat; }';",
    " nft 'add chain inet awg-easy-rs filter-input { type filter hook input priority filter; policy accept; }';",
    " nft 'add chain inet awg-easy-rs wg-clients';",
    " nft add rule inet awg-easy-rs nat-postrouting ip saddr {{ipv4Cidr}} oifname \"{{device}}\" masquerade;",
    " nft add rule inet awg-easy-rs nat-postrouting ip6 saddr {{ipv6Cidr}} oifname \"{{device}}\" masquerade;",
    " nft add rule inet awg-easy-rs filter-input udp dport {{port}} accept;",
);

// One-line teardown: deleting the table atomically removes every chain
// and every rule we added in PostUp, plus anything firewall.rs put in
// the `wg-clients` chain. The `2>/dev/null || true` keeps awg-quick
// from aborting interface bring-down if the table is already gone
// (e.g. after a host reboot where state is lost but PostDown still runs).
const POST_DOWN_TEMPLATE: &str =
    "nft delete table inet awg-easy-rs 2>/dev/null || true";

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

fn create_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    conn.execute_batch(CREATE_INTERFACES)?;
    conn.execute_batch(CREATE_CLIENTS)?;
    conn.execute_batch(CREATE_USERS)?;
    conn.execute_batch(CREATE_USER_CONFIGS)?;
    conn.execute_batch(CREATE_HOOKS)?;
    conn.execute_batch(CREATE_GENERAL)?;
    conn.execute_batch(CREATE_ONE_TIME_LINKS)?;
    conn.execute_batch(CREATE_XRAY_INBOUND)?;
    conn.execute_batch(CREATE_XRAY_CLIENTS)?;
    apply_migrations(conn)?;
    Ok(())
}

/// Apply additive schema migrations needed for upgrading from an older
/// awg-easy-rs / awg-easy DB. Each migration is idempotent — checking column
/// existence via `PRAGMA table_info` before issuing ALTER TABLE.
fn apply_migrations(conn: &Connection) -> Result<()> {
    if !column_exists(conn, "clients_table", "advanced_security")? {
        conn.execute_batch(
            "ALTER TABLE clients_table ADD COLUMN advanced_security INTEGER",
        )?;
        tracing::info!(
            "DB migration: added clients_table.advanced_security (per-peer AdvancedSecurity flag)"
        );
    }
    // additional_config: free-form append-to-config text. Mirrors amnezia-client's
    // additionalServerConfig / additionalClientConfig escape hatch — operators
    // need a place to drop in lines awg-quick understands but the UI doesn't
    // model (e.g. `Table = off`, `FwMark = …`).
    if !column_exists(conn, "interfaces_table", "additional_config")? {
        conn.execute_batch(
            "ALTER TABLE interfaces_table ADD COLUMN additional_config TEXT NOT NULL DEFAULT ''",
        )?;
        tracing::info!(
            "DB migration: added interfaces_table.additional_config (free-form Interface append)"
        );
    }
    if !column_exists(conn, "clients_table", "additional_config")? {
        conn.execute_batch(
            "ALTER TABLE clients_table ADD COLUMN additional_config TEXT",
        )?;
        tracing::info!(
            "DB migration: added clients_table.additional_config (per-peer free-form append)"
        );
    }
    if !column_exists(conn, "user_configs_table", "default_additional_config")? {
        conn.execute_batch(
            "ALTER TABLE user_configs_table ADD COLUMN default_additional_config TEXT NOT NULL DEFAULT ''",
        )?;
        tracing::info!(
            "DB migration: added user_configs_table.default_additional_config"
        );
    }
    // One-shot: replace the iptables-flavoured default hooks from earlier
    // versions with the native nftables equivalents. Only fires when the
    // stored post_up still contains "iptables" — operators who already
    // customised their hooks (with `nft`, with no commands, etc.) get
    // left alone. Idempotent because we re-check on every boot.
    let needs_nft_hooks: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM hooks_table \
             WHERE id = 'awg0' AND post_up LIKE '%iptables%')",
            [],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        )
        .unwrap_or(false);
    if needs_nft_hooks {
        conn.execute(
            "UPDATE hooks_table SET post_up = ?1, post_down = ?2 WHERE id = 'awg0'",
            params![POST_UP_TEMPLATE, POST_DOWN_TEMPLATE],
        )?;
        tracing::info!(
            "DB migration: replaced legacy iptables hooks with native nftables defaults"
        );
    }

    // Backfill singleton rows for tables that may have been added in a
    // later release than this DB was first seeded against. INSERT OR
    // IGNORE makes this safe to run on every boot — the row only lands
    // when it's missing. The original `seed_if_empty` path early-exits
    // when general_table is populated, which used to mean an upgraded
    // DB never saw new singleton rows (e.g. xray_inbound).
    ensure_singleton_rows(conn)?;
    Ok(())
}

/// Idempotently ensure every singleton table has its default row.
/// Pulled out of `seed_if_empty` so the migration step can call it
/// even on already-populated DBs.
fn ensure_singleton_rows(conn: &Connection) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO xray_inbound_table \
         (id, port, dest, server_names, fingerprint_default, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "xray0",
            443,
            "www.microsoft.com:443",
            r#"["www.microsoft.com"]"#,
            "chrome",
            0,
        ],
    )?;
    Ok(())
}

fn column_exists(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    // SQLite's `PRAGMA table_info(<name>)` returns one row per column; the
    // `name` field is the second column.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get("name")?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Seed default rows when general_table is empty (first run).
fn seed_if_empty(conn: &Connection) -> Result<()> {
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM general_table", [], |r| r.get(0))?;
    if count > 0 {
        return Ok(());
    }

    // Generate a random 512-character session password (256 bytes hex-encoded).
    let mut rand_bytes = [0u8; 256];
    rand::rngs::OsRng.fill_bytes(&mut rand_bytes);
    let session_pass = hex::encode(rand_bytes);

    // interfaces_table default
    conn.execute(
        "INSERT OR IGNORE INTO interfaces_table \
         (name, device, port, private_key, public_key, ipv4_cidr, ipv6_cidr, mtu, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            "awg0",
            "eth0",
            51820,
            "---default---",
            "---default---",
            "10.8.0.0/24",
            "fdcc:ad94:bacf:61a4::cafe:0/112",
            1420,
            1,
        ],
    )?;

    // general_table default
    conn.execute(
        "INSERT OR IGNORE INTO general_table \
         (id, setup_step, session_password, session_timeout) \
         VALUES (?1, ?2, ?3, ?4)",
        params![1, 1, &session_pass, 3600],
    )?;

    // hooks_table default
    conn.execute(
        "INSERT OR IGNORE INTO hooks_table \
         (id, pre_up, post_up, pre_down, post_down) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params!["awg0", "", POST_UP_TEMPLATE, "", POST_DOWN_TEMPLATE],
    )?;

    // user_configs_table default
    conn.execute(
        "INSERT OR IGNORE INTO user_configs_table \
         (id, default_mtu, default_persistent_keepalive, default_dns, default_allowed_ips, host, port) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            "awg0",
            1420,
            0,
            r#"["1.1.1.1","2606:4700:4700::1111"]"#,
            r#"["0.0.0.0/0","::/0"]"#,
            "",
            51820,
        ],
    )?;

    // xray_inbound default — disabled until the operator generates keys
    // and confirms the dest. Defaults to www.microsoft.com:443 because it's
    // reachable from most jurisdictions including ones that have blocked
    // GitHub-related infra. Operator can change via the admin UI.
    conn.execute(
        "INSERT OR IGNORE INTO xray_inbound_table \
         (id, port, dest, server_names, fingerprint_default, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "xray0",
            443,
            "www.microsoft.com:443",
            r#"["www.microsoft.com"]"#,
            "chrome",
            0,
        ],
    )?;

    tracing::info!("Seeded default database rows");
    Ok(())
}

/// Open the database, create tables, seed defaults, and install the global
/// handle.  Must be called once at startup.
pub fn init_db() -> Result<()> {
    let c = Connection::open(&CONFIG.db_path).context("Failed to open SQLite database")?;
    create_tables(&c)?;
    seed_if_empty(&c)?;
    let mut guard = db_slot().lock().expect("Database lock poisoned");
    *guard = Some(c);
    tracing::info!("Database ready at {}", CONFIG.db_path);
    Ok(())
}

/// Reset the global DB handle to a fresh in-memory database for tests.
/// Always compiled so integration tests can use it.
pub fn init_test_db() {
    let c = Connection::open_in_memory().expect("in-memory DB open");
    create_tables(&c).expect("test db create_tables");
    seed_if_empty(&c).expect("test db seed");
    let mut guard = db_slot().lock().expect("Database lock poisoned");
    *guard = Some(c);
}

// ---------------------------------------------------------------------------
// Generic UPDATE helper – maps HashMap entries -> SET col = ? clauses
// ---------------------------------------------------------------------------

/// Reference to a single bound value used in the WHERE clause of a generic
/// UPDATE.  Strings are matched case-sensitively, integers via SQLite's
/// numeric comparison.
#[derive(Debug, Clone)]
pub enum WhereVal<'a> {
    Str(&'a str),
    I64(i64),
}

fn build_update<'a>(
    table: &str,
    where_col: &str,
    where_val: WhereVal<'a>,
    fields: &'a UpdateMap,
    valid_columns: &[&str],
    valid_where_columns: &[&str],
) -> Result<(String, Vec<Box<dyn rusqlite::types::ToSql + 'a>>)> {
    if !valid_where_columns.contains(&where_col) {
        return Err(anyhow!(
            "Invalid where column '{}' for table {}",
            where_col,
            table
        ));
    }
    for col in fields.keys() {
        if !valid_columns.contains(&col.as_str()) {
            return Err(anyhow!("Invalid column '{}' for table {}", col, table));
        }
    }
    let mut sets: Vec<String> = Vec::with_capacity(fields.len() + 1);
    let mut vals: Vec<Box<dyn rusqlite::types::ToSql + 'a>> = Vec::with_capacity(fields.len() + 1);
    for (col, val) in fields {
        sets.push(format!("{} = ?", col));
        vals.push(Box::new(val.clone()));
    }
    if sets.is_empty() {
        return Err(anyhow!("No fields to update on {}", table));
    }
    sets.push("updated_at = datetime('now')".into());
    let sql = format!(
        "UPDATE {} SET {} WHERE {} = ?",
        table,
        sets.join(", "),
        where_col,
    );
    match where_val {
        WhereVal::Str(s) => vals.push(Box::new(s.to_string())),
        WhereVal::I64(n) => vals.push(Box::new(n)),
    }
    Ok((sql, vals))
}

fn exec_update<'a>(
    table: &str,
    where_col: &str,
    where_val: WhereVal<'a>,
    fields: &'a UpdateMap,
    valid_columns: &[&str],
    valid_where_columns: &[&str],
) -> Result<()> {
    let (sql, vals) = build_update(
        table,
        where_col,
        where_val,
        fields,
        valid_columns,
        valid_where_columns,
    )?;
    let refs: Vec<&dyn rusqlite::types::ToSql> =
        vals.iter().map(|b| b.as_ref() as &dyn rusqlite::types::ToSql).collect();
    conn().execute(&sql, refs.as_slice())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Interface helpers
// ---------------------------------------------------------------------------

pub fn get_interface() -> Result<Interface> {
    let c = conn();
    let iface = c
        .query_row(
            "SELECT * FROM interfaces_table WHERE name = 'awg0'",
            [],
            |row| Interface::from_row(row),
        )
        .context("No interface row found")?;
    Ok(iface)
}

const VALID_INTERFACE_COLUMNS: &[&str] = &[
    "name", "device", "port", "private_key", "public_key", "ipv4_cidr", "ipv6_cidr",
    "mtu", "j_c", "j_min", "j_max", "s1", "s2", "s3", "s4",
    "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
    "firewall_enabled", "additional_config", "enabled",
];

pub fn update_interface(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "interfaces_table",
        "name",
        WhereVal::Str("awg0"),
        fields,
        VALID_INTERFACE_COLUMNS,
        &["name"],
    )
}

pub fn update_key_pair(pub_key: &str, priv_key: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("public_key".into(), pub_key.into());
    fields.insert("private_key".into(), priv_key.into());
    update_interface(&fields)
}

pub fn update_cidr(v4: &str, v6: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("ipv4_cidr".into(), v4.into());
    fields.insert("ipv6_cidr".into(), v6.into());
    update_interface(&fields)
}

pub fn update_interface_awg_params(params: &crate::wg::params::AwgParams) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("j_c".into(), params.jc.to_string());
    fields.insert("j_min".into(), params.jmin.to_string());
    fields.insert("j_max".into(), params.jmax.to_string());
    fields.insert("s1".into(), params.s1.to_string());
    fields.insert("s2".into(), params.s2.to_string());
    if let Some(ref s3) = params.s3 { fields.insert("s3".into(), s3.to_string()); }
    if let Some(ref s4) = params.s4 { fields.insert("s4".into(), s4.to_string()); }
    fields.insert("h1".into(), params.h1.clone());
    fields.insert("h2".into(), params.h2.clone());
    fields.insert("h3".into(), params.h3.clone());
    fields.insert("h4".into(), params.h4.clone());
    if let Some(ref i1) = params.i1 { fields.insert("i1".into(), i1.clone()); }
    if let Some(ref i2) = params.i2 { fields.insert("i2".into(), i2.clone()); }
    if let Some(ref i3) = params.i3 { fields.insert("i3".into(), i3.clone()); }
    if let Some(ref i4) = params.i4 { fields.insert("i4".into(), i4.clone()); }
    if let Some(ref i5) = params.i5 { fields.insert("i5".into(), i5.clone()); }
    update_interface(&fields)
}

pub fn set_firewall_enabled(enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("firewall_enabled".into(), bool_to_int(enabled).to_string());
    update_interface(&fields)
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

pub fn get_all_clients() -> Result<Vec<Client>> {
    let c = conn();
    let mut stmt = c.prepare("SELECT * FROM clients_table ORDER BY id")?;
    let rows = stmt.query_map([], |row| Client::from_row(row))?;
    let mut clients = Vec::new();
    for row in rows {
        clients.push(row?);
    }
    Ok(clients)
}

pub fn get_client(id: i64) -> Result<Client> {
    let c = conn();
    c.query_row("SELECT * FROM clients_table WHERE id = ?1", params![id], |row| {
        Client::from_row(row)
    })
    .context(format!("Client {id} not found"))
}

pub fn create_client(data: &CreateClientParams) -> Result<i64> {
    let mut c = conn();
    let tx = c.transaction()?;
    tx.execute(
        "INSERT INTO clients_table \
         (user_id, interface_id, name, ipv4_address, ipv6_address, private_key, public_key, \
          pre_shared_key, pre_up, post_up, pre_down, post_down, expires_at, \
          allowed_ips, server_allowed_ips, firewall_ips, \
          persistent_keepalive, mtu, j_c, j_min, j_max, i1, i2, i3, i4, i5, \
          dns, server_endpoint, advanced_security, enabled) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,\
                 ?22,?23,?24,?25,?26,?27,?28,?29,?30)",
        params![
            data.user_id,
            data.interface_id,
            data.name,
            data.ipv4_address,
            data.ipv6_address,
            data.private_key,
            data.public_key,
            data.pre_shared_key,
            data.pre_up,
            data.post_up,
            data.pre_down,
            data.post_down,
            data.expires_at,
            data.allowed_ips,
            data.server_allowed_ips,
            data.firewall_ips,
            data.persistent_keepalive,
            data.mtu,
            data.j_c,
            data.j_min,
            data.j_max,
            data.i1,
            data.i2,
            data.i3,
            data.i4,
            data.i5,
            data.dns,
            data.server_endpoint,
            data.advanced_security.map(bool_to_int),
            bool_to_int(data.enabled),
        ],
    )?;
    let id = tx.last_insert_rowid();
    tx.commit()?;
    Ok(id)
}

const VALID_CLIENT_COLUMNS: &[&str] = &[
    "user_id", "interface_id", "name", "ipv4_address", "ipv6_address",
    "private_key", "public_key", "pre_shared_key", "pre_up", "post_up",
    "pre_down", "post_down", "expires_at", "allowed_ips", "server_allowed_ips",
    "firewall_ips", "persistent_keepalive", "mtu", "j_c", "j_min", "j_max",
    "i1", "i2", "i3", "i4", "i5", "dns", "server_endpoint",
    "advanced_security", "additional_config", "enabled",
];

pub fn update_client(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "clients_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_CLIENT_COLUMNS,
        &["id"],
    )
}

pub fn delete_client(id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute("DELETE FROM clients_table WHERE id = ?1", params![id])?;
    if n == 0 {
        return Err(anyhow!("Client {id} not found"));
    }
    Ok(())
}

pub fn toggle_client(id: i64, enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("enabled".into(), bool_to_int(enabled).to_string());
    update_client(id, &fields)
}

/// Set the per-peer AmneziaWG flag. `None` clears the column to SQL NULL —
/// emitted configs will then omit the `AdvancedSecurity` line and the
/// kernel will auto-detect from the H1 magic header.
pub fn set_client_advanced_security(id: i64, value: Option<bool>) -> Result<()> {
    let c = conn();
    let n = match value {
        Some(b) => c.execute(
            "UPDATE clients_table \
             SET advanced_security = ?1, updated_at = datetime('now') \
             WHERE id = ?2",
            params![bool_to_int(b), id],
        )?,
        None => c.execute(
            "UPDATE clients_table \
             SET advanced_security = NULL, updated_at = datetime('now') \
             WHERE id = ?1",
            params![id],
        )?,
    };
    if n == 0 {
        return Err(anyhow!("Client {id} not found"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// User helpers
// ---------------------------------------------------------------------------

pub fn get_user(id: i64) -> Result<User> {
    let c = conn();
    c.query_row(
        "SELECT * FROM users_table WHERE id = ?1",
        params![id],
        |row| User::from_row(row),
    )
    .context(format!("User {id} not found"))
}

pub fn get_user_by_username(username: &str) -> Result<User> {
    let c = conn();
    c.query_row(
        "SELECT * FROM users_table WHERE username = ?1",
        params![username],
        |row| User::from_row(row),
    )
    .context(format!("User '{username}' not found"))
}

pub fn get_user_count() -> Result<i64> {
    let c = conn();
    c.query_row("SELECT COUNT(*) FROM users_table", [], |row| row.get(0))
        .context("Failed to count users")
}

pub fn create_user(data: &CreateUserParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO users_table \
         (username, password, email, name, role, totp_key, totp_verified, enabled) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            data.username,
            data.password,
            data.email,
            data.name,
            data.role,
            data.totp_key,
            bool_to_int(data.totp_verified),
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_USER_COLUMNS: &[&str] = &[
    "username", "password", "email", "name", "role",
    "totp_key", "totp_verified", "enabled",
];

pub fn update_user(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "users_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_USER_COLUMNS,
        &["id"],
    )
}

pub fn update_password(id: i64, hash: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("password".into(), hash.into());
    update_user(id, &fields)
}

// ---------------------------------------------------------------------------
// User config helpers
// ---------------------------------------------------------------------------

pub fn get_user_config() -> Result<UserConfig> {
    let c = conn();
    c.query_row(
        "SELECT * FROM user_configs_table WHERE id = 'awg0'",
        [],
        |row| UserConfig::from_row(row),
    )
    .context("No user config row found")
}

const VALID_USER_CONFIG_COLUMNS: &[&str] = &[
    "default_mtu", "default_persistent_keepalive", "default_dns", "default_allowed_ips",
    "default_j_c", "default_j_min", "default_j_max",
    "default_i1", "default_i2", "default_i3", "default_i4", "default_i5",
    "default_additional_config",
    "host", "port",
];

pub fn update_user_config(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "user_configs_table",
        "id",
        WhereVal::Str("awg0"),
        fields,
        VALID_USER_CONFIG_COLUMNS,
        &["id"],
    )
}

pub fn update_host_port(host: &str, port: i64) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("host".into(), host.into());
    fields.insert("port".into(), port.to_string());
    update_user_config(&fields)
}

// ---------------------------------------------------------------------------
// Hooks helpers
// ---------------------------------------------------------------------------

pub fn get_hooks() -> Result<Hooks> {
    let c = conn();
    c.query_row(
        "SELECT * FROM hooks_table WHERE id = 'awg0'",
        [],
        |row| Hooks::from_row(row),
    )
    .context("No hooks row found")
}

const VALID_HOOKS_COLUMNS: &[&str] = &["pre_up", "post_up", "pre_down", "post_down"];

pub fn update_hooks(data: &UpdateMap) -> Result<()> {
    exec_update(
        "hooks_table",
        "id",
        WhereVal::Str("awg0"),
        data,
        VALID_HOOKS_COLUMNS,
        &["id"],
    )
}

// ---------------------------------------------------------------------------
// General helpers
// ---------------------------------------------------------------------------

pub fn get_general() -> Result<General> {
    let c = conn();
    c.query_row(
        "SELECT * FROM general_table WHERE id = 1",
        [],
        |row| General::from_row(row),
    )
    .context("No general row found")
}

const VALID_GENERAL_COLUMNS: &[&str] = &[
    "setup_step", "session_timeout",
    "metrics_prometheus", "metrics_json", "metrics_password",
];

pub fn update_general(data: &UpdateMap) -> Result<()> {
    exec_update(
        "general_table",
        "id",
        WhereVal::I64(1),
        data,
        VALID_GENERAL_COLUMNS,
        &["id"],
    )
}

pub fn get_setup_step() -> Result<i64> {
    let c = conn();
    c.query_row(
        "SELECT setup_step FROM general_table WHERE id = 1",
        [],
        |row| row.get(0),
    )
    .context("No general row found")
}

pub fn set_setup_step(step: i64) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("setup_step".into(), step.to_string());
    update_general(&fields)
}

// ---------------------------------------------------------------------------
// One-time link helpers
// ---------------------------------------------------------------------------

pub fn create_one_time_link(client_id: i64, token: &str, expires: &str) -> Result<()> {
    let c = conn();
    c.execute(
        "INSERT OR REPLACE INTO one_time_links_table \
         (id, one_time_link, expires_at) VALUES (?1, ?2, ?3)",
        params![client_id, token, expires],
    )?;
    Ok(())
}

pub fn get_one_time_link(token: &str) -> Result<OneTimeLink> {
    let c = conn();
    c.query_row(
        "SELECT * FROM one_time_links_table WHERE one_time_link = ?1",
        params![token],
        |row| OneTimeLink::from_row(row),
    )
    .context("One-time link not found")
}

pub fn delete_one_time_link(client_id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM one_time_links_table WHERE id = ?1",
        params![client_id],
    )?;
    if n == 0 {
        return Err(anyhow!("One-time link for client {client_id} not found"));
    }
    Ok(())
}

/// Active (non-expired) one-time link for *client_id*, if any.
/// The schema enforces at most one row per client (id is both primary key
/// and the foreign-key reference into clients_table), so this is a unique
/// lookup. Returns None when no link exists or the link has expired.
pub fn get_active_one_time_link(client_id: i64) -> Result<Option<OneTimeLink>> {
    let now = chrono::Utc::now().to_rfc3339();
    let c = conn();
    let row = c
        .query_row(
            "SELECT * FROM one_time_links_table \
             WHERE id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
            params![client_id, now],
            |row| OneTimeLink::from_row(row),
        )
        .ok();
    Ok(row)
}

// ---------------------------------------------------------------------------
// IP allocation
// ---------------------------------------------------------------------------

/// Find the first host address inside *cidr* that is not in *used_ips*.
pub fn next_ipv4(cidr: &str, used_ips: &[String]) -> Result<String> {
    let net: Ipv4Net = cidr.parse().context("Invalid IPv4 CIDR")?;
    // The server occupies network_addr + 1 (mirrored in wg::config_gen::server_ip).
    // Allocating that to a peer collides with the server's interface address
    // and `awg syncconf` rejects with "Invalid argument". Treat it as taken.
    let server_ip = std::net::Ipv4Addr::from(u32::from(net.addr()) + 1).to_string();
    for host in net.hosts() {
        let ip = host.to_string();
        if ip != server_ip && !used_ips.contains(&ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("No available IPv4 address in {cidr}"))
}

/// Find the first host address inside *cidr* that is not in *used_ips*.
pub fn next_ipv6(cidr: &str, used_ips: &[String]) -> Result<String> {
    let net: Ipv6Net = cidr.parse().context("Invalid IPv6 CIDR")?;
    // ipnet::Ipv6Net::hosts() includes the network address (IPv6 has no
    // broadcast). Skip both the network address and the server IP
    // (network + 1, mirrored in wg::config_gen::server_ip).
    let network_addr = net.addr().to_string();
    let server_ip = std::net::Ipv6Addr::from(u128::from(net.addr()) + 1).to_string();
    for host in net.hosts() {
        let ip = host.to_string();
        if ip != network_addr && ip != server_ip && !used_ips.contains(&ip) {
            return Ok(ip);
        }
    }
    Err(anyhow!("No available IPv6 address in {cidr}"))
}

// ---------------------------------------------------------------------------
// Xray inbound + clients helpers
// ---------------------------------------------------------------------------

pub fn get_xray_inbound() -> Result<XrayInbound> {
    let c = conn();
    c.query_row(
        "SELECT * FROM xray_inbound_table WHERE id = 'xray0'",
        [],
        |row| XrayInbound::from_row(row),
    )
    .context("No xray_inbound row found")
}

const VALID_XRAY_INBOUND_COLUMNS: &[&str] = &[
    "port", "dest", "server_names", "private_key", "public_key",
    "fingerprint_default", "additional_config", "enabled",
];

pub fn update_xray_inbound(fields: &UpdateMap) -> Result<()> {
    exec_update(
        "xray_inbound_table",
        "id",
        WhereVal::Str("xray0"),
        fields,
        VALID_XRAY_INBOUND_COLUMNS,
        &["id"],
    )
}

/// Replace the inbound's keypair atomically. Used by the
/// "regenerate keys" admin action — both columns move together so the
/// inbound never lands in a state where the public key on disk doesn't
/// pair with the private key in `realitySettings`.
pub fn update_xray_keypair(private_key: &str, public_key: &str) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("private_key".into(), private_key.into());
    fields.insert("public_key".into(), public_key.into());
    update_xray_inbound(&fields)
}

pub fn list_xray_clients() -> Result<Vec<XrayClient>> {
    let c = conn();
    let mut stmt = c.prepare(
        "SELECT * FROM xray_clients_table ORDER BY created_at ASC, id ASC",
    )?;
    let rows = stmt
        .query_map([], |row| XrayClient::from_row(row))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_xray_client(id: i64) -> Result<XrayClient> {
    let c = conn();
    c.query_row(
        "SELECT * FROM xray_clients_table WHERE id = ?1",
        params![id],
        |row| XrayClient::from_row(row),
    )
    .context(format!("Xray client {id} not found"))
}

/// Data required to insert a new xray peer. `uuid` and `short_id` are
/// generated by the caller (see `xray::keys`) so the DB layer never has
/// to fork a process.
#[derive(Debug, Clone)]
pub struct CreateXrayClientParams {
    pub user_id: Option<i64>,
    pub inbound_id: String,
    pub name: String,
    pub uuid: String,
    pub short_id: String,
    pub expires_at: Option<String>,
    pub additional_config: Option<String>,
    pub enabled: bool,
}

pub fn create_xray_client(data: &CreateXrayClientParams) -> Result<i64> {
    let c = conn();
    c.execute(
        "INSERT INTO xray_clients_table \
         (user_id, inbound_id, name, uuid, short_id, expires_at, additional_config, enabled) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            data.user_id,
            data.inbound_id,
            data.name,
            data.uuid,
            data.short_id,
            data.expires_at,
            data.additional_config,
            bool_to_int(data.enabled),
        ],
    )?;
    Ok(c.last_insert_rowid())
}

const VALID_XRAY_CLIENT_COLUMNS: &[&str] = &[
    "user_id", "inbound_id", "name", "uuid", "short_id",
    "expires_at", "additional_config", "enabled",
];

pub fn update_xray_client(id: i64, fields: &UpdateMap) -> Result<()> {
    exec_update(
        "xray_clients_table",
        "id",
        WhereVal::I64(id),
        fields,
        VALID_XRAY_CLIENT_COLUMNS,
        &["id"],
    )
}

pub fn delete_xray_client(id: i64) -> Result<()> {
    let c = conn();
    let n = c.execute(
        "DELETE FROM xray_clients_table WHERE id = ?1",
        params![id],
    )?;
    if n == 0 {
        return Err(anyhow!("Xray client {id} not found"));
    }
    Ok(())
}

pub fn toggle_xray_client(id: i64, enabled: bool) -> Result<()> {
    let mut fields = UpdateMap::new();
    fields.insert("enabled".into(), bool_to_int(enabled).to_string());
    update_xray_client(id, &fields)
}
