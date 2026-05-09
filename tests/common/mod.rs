//! Shared test fixtures — temp env, in-memory DB, rate limiter reset.

use std::sync::OnceLock;

static SETUP: OnceLock<()> = OnceLock::new();

pub fn seed() {
    SETUP.get_or_init(|| {
        // Write WireGuard configs to a temp directory instead of /etc/wireguard
        let dir = std::env::temp_dir().join("awg-easy-rs-test");
        std::fs::create_dir_all(&dir).expect("create test conf dir");
        std::env::set_var("WG_EASY_CONF_DIR", dir.to_str().unwrap());
    });

    awg_easy_rs::db::init_test_db();
    awg_easy_rs::api::session::reset_login_attempts();
    awg_easy_rs::api::session::reset_totp_attempts();
}
