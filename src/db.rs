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
    pub j1: String,
    pub j2: String,
    pub j3: String,
    pub itime: i64,
    pub firewall_enabled: bool,
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
            j1: row.get("j1").unwrap_or_default(),
            j2: row.get("j2").unwrap_or_default(),
            j3: row.get("j3").unwrap_or_default(),
            itime: row.get("itime").unwrap_or(0),
            firewall_enabled: int_to_bool(row.get::<_, i64>("firewall_enabled")?),
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
    j1                TEXT NOT NULL DEFAULT '',
    j2                TEXT NOT NULL DEFAULT '',
    j3                TEXT NOT NULL DEFAULT '',
    itime             INTEGER NOT NULL DEFAULT 0,
    firewall_enabled  INTEGER NOT NULL DEFAULT 0,
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

// ---------------------------------------------------------------------------
// Hook templates
// ---------------------------------------------------------------------------

const POST_UP_TEMPLATE: &str = concat!(
    "iptables -t nat -A POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE;",
    " iptables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT;",
    " iptables -A FORWARD -i awg0 -j ACCEPT;",
    " iptables -A FORWARD -o awg0 -j ACCEPT;",
    " ip6tables -t nat -A POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE;",
    " ip6tables -A INPUT -p udp -m udp --dport {{port}} -j ACCEPT;",
    " ip6tables -A FORWARD -i awg0 -j ACCEPT;",
    " ip6tables -A FORWARD -o awg0 -j ACCEPT;",
);

const POST_DOWN_TEMPLATE: &str = concat!(
    "iptables -t nat -D POSTROUTING -s {{ipv4Cidr}} -o {{device}} -j MASQUERADE;",
    " iptables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT;",
    " iptables -D FORWARD -i awg0 -j ACCEPT;",
    " iptables -D FORWARD -o awg0 -j ACCEPT;",
    " ip6tables -t nat -D POSTROUTING -s {{ipv6Cidr}} -o {{device}} -j MASQUERADE;",
    " ip6tables -D INPUT -p udp -m udp --dport {{port}} -j ACCEPT;",
    " ip6tables -D FORWARD -i awg0 -j ACCEPT;",
    " ip6tables -D FORWARD -o awg0 -j ACCEPT;",
);

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
    // Rename the interface row from `wg0` (upstream awg-easy / wg-easy default)
    // to `awg0` to match the AmneziaWG-native naming. Idempotent — only fires
    // when an old `wg0` row is present and no `awg0` row exists yet.
    let needs_rename: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM interfaces_table WHERE name = 'wg0') \
             AND NOT EXISTS(SELECT 1 FROM interfaces_table WHERE name = 'awg0')",
            [],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        )
        .unwrap_or(false);
    if needs_rename {
        conn.execute_batch(
            "UPDATE interfaces_table SET name = 'awg0' WHERE name = 'wg0';\
             UPDATE hooks_table SET id = 'awg0' WHERE id = 'wg0';\
             UPDATE user_configs_table SET id = 'awg0' WHERE id = 'wg0';\
             UPDATE hooks_table SET \
               post_up = REPLACE(post_up, 'wg0', 'awg0'), \
               post_down = REPLACE(post_down, 'wg0', 'awg0'), \
               pre_up = REPLACE(pre_up, 'wg0', 'awg0'), \
               pre_down = REPLACE(pre_down, 'wg0', 'awg0') \
             WHERE id = 'awg0';",
        )?;
        tracing::info!(
            "DB migration: renamed interface wg0 -> awg0 (interfaces_table, hooks_table, user_configs_table)"
        );
    }
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
    "j1", "j2", "j3", "itime", "firewall_enabled", "enabled",
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
    "advanced_security", "enabled",
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
