use awg_easy_rs::{api, auth, config, db, firewall, wg};

use std::net::SocketAddr;
use std::sync::OnceLock;
use axum::{Router, routing::get, response::Response, http::{header, HeaderMap, StatusCode}};
use tracing_subscriber::EnvFilter;

// Embedded frontend
const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_JS: &str = include_str!("../static/app.js");
const FAVICON_PNG: &[u8] = include_bytes!("../static/favicon.png");
const FAVICON_AWG_ICO: &[u8] = include_bytes!("../static/favicon-amnezia.ico");
const LOGO_PNG: &[u8] = include_bytes!("../static/logo.png");
const LOGO_AWG_SVG: &[u8] = include_bytes!("../static/logo-amnezia.svg");
const APPLE_ICON: &[u8] = include_bytes!("../static/apple-touch-icon.png");
const APPLE_ICON_AWG: &[u8] = include_bytes!("../static/apple-touch-icon-amnezia.png");
const MANIFEST_JSON: &[u8] = include_bytes!("../static/manifest.json");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    db::init_db()?;
    tracing::info!("Database initialized");

    if let Err(e) = run_init_setup() {
        tracing::warn!("INIT_ENABLED auto-setup failed (non-fatal): {e}");
    }

    if let Err(e) = wg::startup() {
        tracing::warn!("AmneziaWG startup failed (non-fatal): {e}");
        tracing::warn!("Web UI will still be available. Fix AmneziaWG and use Restart from admin panel.");
    } else {
        tracing::info!("AmneziaWG started");
    }

    // iptables-legacy compat: on hosts running the xt_tables backend
    // (typically RHEL/CentOS 7 vintage), our nft `accept` is invisible
    // to the legacy FORWARD chain. Mirror the three "let AWG through"
    // rules into iptables-legacy so the verdicts compose. Idempotent;
    // no-op on every modern (iptables-nft) host.
    if let Ok(iface) = db::get_interface() {
        if let Err(e) = firewall::ensure_legacy_compat(
            &iface.name,
            iface.port,
            !config::CONFIG.disable_ipv6,
        ) {
            tracing::warn!("iptables-legacy compat startup failed (non-fatal): {e}");
        }
    }

    // Bring Browsing-mode Xray online if it's been enabled. Non-fatal:
    // operators who haven't set up Reality keys yet will see Status::Disabled
    // in the admin UI rather than a startup crash.
    #[cfg(xray_bundled)]
    if let Err(e) = awg_easy_rs::xray::supervisor::ensure_running().await {
        tracing::warn!("Xray supervisor startup failed (non-fatal): {e}");
    }

    // Bring the bundled DNS stack online if it's been enabled. Same
    // non-fatal contract as Xray — operators who haven't toggled the
    // master switch see Status::Disabled, not a crash. Tor stays off
    // independently of the master switch (see DnsBundle.tor_enabled).
    #[cfg(dns_bundled)]
    if let Err(e) = awg_easy_rs::dns::supervisor::ensure_running().await {
        tracing::warn!("DNS bundle supervisor startup failed (non-fatal): {e}");
    }

    // Start background cron job (every 60 seconds)
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if let Err(e) = wg::cron_job() {
                tracing::error!("Cron job failed: {e}");
            }
        }
    });

    let app_state = api::AppState::new();

    // Static asset routes
    let static_routes = Router::new()
        .route("/app.js", get(|h: HeaderMap| async move { js_response(h, APP_JS) }))
        .route("/favicon.png", get(|h: HeaderMap| async move { png_response(h, FAVICON_PNG, asset_etag("favicon.png", FAVICON_PNG)) }))
        .route("/favicon-amnezia.ico", get(|h: HeaderMap| async move { ico_response(h, FAVICON_AWG_ICO, asset_etag("favicon-amnezia.ico", FAVICON_AWG_ICO)) }))
        .route("/favicon.ico", get(|h: HeaderMap| async move { ico_response(h, FAVICON_AWG_ICO, asset_etag("favicon-amnezia.ico", FAVICON_AWG_ICO)) }))
        .route("/logo.png", get(|h: HeaderMap| async move { png_response(h, LOGO_PNG, asset_etag("logo.png", LOGO_PNG)) }))
        .route("/logo-amnezia.svg", get(|h: HeaderMap| async move { svg_response(h, LOGO_AWG_SVG, asset_etag("logo-amnezia.svg", LOGO_AWG_SVG)) }))
        .route("/apple-touch-icon.png", get(|h: HeaderMap| async move { png_response(h, APPLE_ICON, asset_etag("apple-touch-icon.png", APPLE_ICON)) }))
        .route("/apple-touch-icon-amnezia.png", get(|h: HeaderMap| async move { png_response(h, APPLE_ICON_AWG, asset_etag("apple-touch-icon-amnezia.png", APPLE_ICON_AWG)) }))
        .route("/manifest.json", get(|h: HeaderMap| async move { json_response(h, MANIFEST_JSON, asset_etag("manifest.json", MANIFEST_JSON)) }));

    let app = api::build_router(app_state)
        .merge(static_routes)
        .fallback(|h: HeaderMap| async move {
            html_response(h, INDEX_HTML)
        });

    let addr = SocketAddr::from(([0, 0, 0, 0], config::CONFIG.port));
    tracing::info!("awg-easy-rs starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown future: SIGTERM (docker compose down, systemd stop)
    // or SIGINT (Ctrl-C in foreground) flips the future. axum stops
    // accepting new connections and drains in-flight ones.
    let shutdown = async {
        let mut sigterm = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
                unreachable!();
            }
        };
        let mut sigint = match tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::interrupt(),
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = ?e, "failed to install SIGINT handler");
                std::future::pending::<()>().await;
                unreachable!();
            }
        };
        tokio::select! {
            _ = sigterm.recv() => tracing::info!("SIGTERM received; shutting down"),
            _ = sigint.recv()  => tracing::info!("SIGINT received; shutting down"),
        }
    };
    axum::serve(listener, app).with_graceful_shutdown(shutdown).await?;

    // Post-serve cleanup. Order matters: stop Xray + DNS supervisor
    // children first so they're reaped before we tear down firewall
    // state, then peel back any iptables-legacy compat rules we
    // inserted at startup.
    #[cfg(xray_bundled)]
    awg_easy_rs::xray::supervisor::shutdown_for_exit().await;
    #[cfg(dns_bundled)]
    awg_easy_rs::dns::supervisor::shutdown_for_exit().await;

    if let Ok(iface) = db::get_interface() {
        firewall::remove_legacy_compat(
            &iface.name,
            iface.port,
            !config::CONFIG.disable_ipv6,
        );
    }
    tracing::info!("awg-easy-rs exited cleanly");
    Ok(())
}

// ---------------------------------------------------------------------------
// ETag-backed cache validation. Each asset gets a content-derived ETag
// computed once at startup; browsers cache aggressively but always revalidate
// (Cache-Control: no-cache). When the binary is rebuilt the ETag changes, so
// stale clients automatically pick up the new asset on next page load.
// ---------------------------------------------------------------------------

fn etag_for_bytes(content: &[u8]) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut h);
    format!("\"{:016x}\"", h.finish())
}

/// Per-asset ETag cache. Keyed by asset name so each route owns its slot.
fn asset_etag(name: &'static str, content: &'static [u8]) -> &'static str {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<&'static str, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = cache.lock().expect("etag cache lock");
    if let Some(v) = g.get(name) {
        return v;
    }
    let leaked: &'static str = Box::leak(etag_for_bytes(content).into_boxed_str());
    g.insert(name, leaked);
    leaked
}

fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        .map(|v| v.split(',').map(str::trim).any(|t| t == etag || t == "*"))
        .unwrap_or(false)
}

fn not_modified(etag: &str) -> Response {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, "no-cache")
        .body(axum::body::Body::empty())
        .unwrap()
}

fn binary_response(headers: HeaderMap, content_type: &'static str, data: &'static [u8], etag: &'static str) -> Response {
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn png_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/png", data, etag)
}

fn ico_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/x-icon", data, etag)
}

fn svg_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "image/svg+xml", data, etag)
}

fn json_response(headers: HeaderMap, data: &'static [u8], etag: &'static str) -> Response {
    binary_response(headers, "application/json", data, etag)
}

fn js_response(headers: HeaderMap, data: &'static str) -> Response {
    let etag = asset_etag("app.js", data.as_bytes());
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .header("X-Content-Type-Options", "nosniff")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn html_response(headers: HeaderMap, data: &'static str) -> Response {
    let etag = asset_etag("index.html", data.as_bytes());
    if matches_etag(&headers, etag) {
        return not_modified(etag);
    }
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .header(header::ETAG, etag)
        .body(axum::body::Body::from(data))
        .unwrap()
}

/// Honour the INIT_* environment variables when set: auto-create the admin
/// user, set the host/port, and complete the setup wizard. Idempotent — does
/// nothing once a user already exists or `init_enabled` is false.
fn run_init_setup() -> anyhow::Result<()> {
    let cfg = &*config::CONFIG;
    if !cfg.init_enabled {
        return Ok(());
    }
    let user_count = db::get_user_count().unwrap_or(0);
    if user_count > 0 {
        tracing::debug!("INIT_ENABLED set but admin user already exists — skipping");
        return Ok(());
    }
    let username = cfg
        .init_username
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("INIT_USERNAME is required when INIT_ENABLED=true"))?;
    let password = cfg
        .init_password
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("INIT_PASSWORD is required when INIT_ENABLED=true"))?;
    if password.len() < 6 {
        return Err(anyhow::anyhow!("INIT_PASSWORD must be at least 6 characters"));
    }

    let hash = auth::hash_password(password)?;
    db::create_user(&db::CreateUserParams {
        username: username.into(),
        password: hash,
        email: None,
        name: "Admin".into(),
        role: 1,
        totp_key: None,
        totp_verified: false,
        enabled: true,
    })?;
    tracing::info!("INIT_ENABLED: created admin user '{username}'");

    if let Some(host) = cfg.init_host.as_deref() {
        let port = cfg.init_port.unwrap_or(51820) as i64;
        db::update_host_port(host, port)?;
        let mut iface_fields = db::UpdateMap::new();
        iface_fields.insert("port".into(), port.to_string());
        if let Some(cidr) = cfg.init_ipv4_cidr.as_deref() {
            iface_fields.insert("ipv4_cidr".into(), cidr.into());
        }
        if let Some(cidr) = cfg.init_ipv6_cidr.as_deref() {
            iface_fields.insert("ipv6_cidr".into(), cidr.into());
        }
        db::update_interface(&iface_fields)?;
    }

    if let Some(ref dns) = cfg.init_dns {
        let mut fields = db::UpdateMap::new();
        fields.insert(
            "default_dns".into(),
            serde_json::to_string(dns).unwrap_or_else(|_| "[]".into()),
        );
        db::update_user_config(&fields)?;
    }
    if let Some(ref allowed) = cfg.init_allowed_ips {
        let mut fields = db::UpdateMap::new();
        fields.insert(
            "default_allowed_ips".into(),
            serde_json::to_string(allowed).unwrap_or_else(|_| "[]".into()),
        );
        db::update_user_config(&fields)?;
    }

    db::set_setup_step(0)?;
    tracing::info!("INIT_ENABLED: setup wizard completed");
    Ok(())
}
