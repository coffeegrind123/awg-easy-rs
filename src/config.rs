use std::env;
use std::sync::LazyLock;

pub static CONFIG: LazyLock<Config> = LazyLock::new(Config::load);

pub struct Config {
    pub port: u16,
    pub host: String,
    pub insecure: bool,
    pub disable_ipv6: bool,
    pub init_enabled: bool,
    pub init_username: Option<String>,
    pub init_password: Option<String>,
    pub init_host: Option<String>,
    pub init_port: Option<u16>,
    pub init_dns: Option<Vec<String>>,
    pub init_ipv4_cidr: Option<String>,
    pub init_ipv6_cidr: Option<String>,
    pub init_allowed_ips: Option<Vec<String>>,
    pub db_path: String,
    pub wg_conf_dir: String,
    pub wg_binary: String,
    /// Directory where the bundled Xray ELF, generated `server.json`, and
    /// other Xray runtime files live. Defaults to `<wg_conf_dir>/xray`.
    pub xray_dir: String,
    /// Operator escape hatch: when set, the Xray supervisor uses this path
    /// instead of extracting the bundled binary. Lets advanced operators
    /// track upstream Xray independently of awg-easy-rs releases.
    pub xray_binary_override: Option<String>,
    /// Directory where the bundled DNS-stack ELFs (dnscrypt-proxy, tor,
    /// lyrebird, snowflake, webtunnel) are extracted, plus generated
    /// configs (`dnscrypt-proxy.toml`, `torrc`, etc.) and tor's data
    /// directory. Defaults to `<wg_conf_dir>/dns`. Persist this on a
    /// docker volume so binaries don't re-extract on every restart.
    pub dns_dir: String,
}

pub fn get_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

impl Config {
    pub fn load() -> Self {
        let port: u16 = env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(51821);
        let host = get_env("HOST", "0.0.0.0");
        let insecure = get_env("INSECURE", "false").to_lowercase() == "true";
        let disable_ipv6 = get_env("DISABLE_IPV6", "false").to_lowercase() == "true";
        let init_enabled = get_env("INIT_ENABLED", "false").to_lowercase() == "true";

        let init_username = env::var("INIT_USERNAME").ok().filter(|s| !s.is_empty());
        let init_password = env::var("INIT_PASSWORD").ok().filter(|s| !s.is_empty());
        let init_host = env::var("INIT_HOST").ok().filter(|s| !s.is_empty());
        let init_port = env::var("INIT_PORT")
            .ok()
            .and_then(|s| s.parse::<u16>().ok());

        let init_dns = env::var("INIT_DNS").ok().filter(|s| !s.is_empty()).map(|s| {
            s.split(',')
                .map(|part| part.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        });

        let init_ipv4_cidr = env::var("INIT_IPV4_CIDR")
            .ok()
            .filter(|s| !s.is_empty());
        let init_ipv6_cidr = env::var("INIT_IPV6_CIDR")
            .ok()
            .filter(|s| !s.is_empty());

        let init_allowed_ips = env::var("INIT_ALLOWED_IPS")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.split(',')
                    .map(|part| part.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            });

        let db_path = get_env("WG_EASY_DB_PATH", "/etc/wireguard/wg-easy.db");
        let wg_conf_dir = get_env("WG_EASY_CONF_DIR", "/etc/wireguard");
        let xray_dir =
            env::var("WG_EASY_XRAY_DIR").unwrap_or_else(|_| format!("{}/xray", wg_conf_dir));
        let xray_binary_override = env::var("XRAY_BIN_PATH").ok().filter(|s| !s.is_empty());
        let dns_dir =
            env::var("WG_EASY_DNS_DIR").unwrap_or_else(|_| format!("{}/dns", wg_conf_dir));

        Config {
            port,
            host,
            insecure,
            disable_ipv6,
            init_enabled,
            init_username,
            init_password,
            init_host,
            init_port,
            init_dns,
            init_ipv4_cidr,
            init_ipv6_cidr,
            init_allowed_ips,
            db_path,
            wg_conf_dir,
            wg_binary: "awg".to_string(),
            xray_dir,
            xray_binary_override,
            dns_dir,
        }
    }
}
