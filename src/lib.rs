//! awg-easy-rs — Standalone AmneziaWG VPN manager with Web UI.
//!
//! This library crate exposes all modules for both the binary and integration
//! tests.

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod dns;
pub mod firewall;
pub mod init_setup;
pub mod memexec;
pub mod mdnsvpn;
pub mod mtproxy;
pub mod proc;
pub mod proxy;
pub mod qr;
pub mod wg;
pub mod xray;
