use awg_easy_rs::{api, config, db, wg};

use std::net::SocketAddr;
use axum::{Router, routing::get, response::Response, http::{header, StatusCode}};
use tracing_subscriber::EnvFilter;

// Embedded frontend
const INDEX_HTML: &str = include_str!("../static/index.html");
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
