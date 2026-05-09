use awg_easy_rs::{api, auth, config, db, wg};

use std::net::SocketAddr;
use axum::{Router, routing::get, response::Response, http::{header, StatusCode}};
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
        tracing::warn!("WireGuard startup failed (non-fatal): {e}");
        tracing::warn!("Web UI will still be available. Fix WireGuard and use Restart from admin panel.");
    } else {
        tracing::info!("WireGuard started");
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
        .route("/app.js", get(|| async { js_response(APP_JS) }))
        .route("/favicon.png", get(|| async { png_response(FAVICON_PNG) }))
        .route("/favicon-amnezia.ico", get(|| async { ico_response(FAVICON_AWG_ICO) }))
        .route("/favicon.ico", get(|| async { ico_response(FAVICON_AWG_ICO) }))
        .route("/logo.png", get(|| async { png_response(LOGO_PNG) }))
        .route("/logo-amnezia.svg", get(|| async { svg_response(LOGO_AWG_SVG) }))
        .route("/apple-touch-icon.png", get(|| async { png_response(APPLE_ICON) }))
        .route("/apple-touch-icon-amnezia.png", get(|| async { png_response(APPLE_ICON_AWG) }))
        .route("/manifest.json", get(|| async { json_response(MANIFEST_JSON) }));

    let app = api::build_router(app_state)
        .merge(static_routes)
        .fallback(|| async {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                .body(axum::body::Body::from(INDEX_HTML))
                .unwrap()
        });

    let addr = SocketAddr::from(([0, 0, 0, 0], config::CONFIG.port));
    tracing::info!("awg-easy-rs starting on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn png_response(data: &'static [u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn ico_response(data: &'static [u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/x-icon")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn svg_response(data: &'static [u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/svg+xml")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn json_response(data: &'static [u8]) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .body(axum::body::Body::from(data))
        .unwrap()
}

fn js_response(data: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .header("X-Content-Type-Options", "nosniff")
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
