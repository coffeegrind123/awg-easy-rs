//! QR code generation for WireGuard client configuration files.
//!
//! Uses the `qrcode` crate to produce SVG output suitable for embedding
//! in the admin UI.

use anyhow::Result;
use qrcode::QrCode;
use qrcode::render::svg;

/// Generate an SVG QR code for the given configuration string.
///
/// Returns a complete `<svg>` element as a string.
pub fn generate_qr_svg(config: &str) -> Result<String> {
    let code = QrCode::new(config.as_bytes())
        .map_err(|e| anyhow::anyhow!("QR code generation failed: {e}"))?;
    let svg = code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    Ok(svg)
}
