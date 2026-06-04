//! Probe a candidate Reality `dest` with a real TLS 1.3 handshake.
//!
//! Reality's camouflage is only as good as the dest. The dest must:
//!
//! 1. Accept inbound TLS on the configured port (typically 443).
//! 2. Negotiate TLS 1.3 — Reality's TLS-in-TLS splicing relies on it.
//! 3. Present a valid certificate whose SAN matches the SNI awg-easy-rs
//!    will tell clients to send (`serverNames[0]`).
//! 4. Ideally support HTTP/2 in ALPN — that's what real CDN traffic
//!    looks like to a DPI box, so it's the more convincing fall-through.
//!
//! This module checks all four. The operator's "Probe" button hits
//! `POST /api/admin/xray/probe-dest`, the backend opens a single
//! socket to the dest, and the result is rendered inline.
//!
//! We deliberately use the Mozilla root store (via `webpki-roots`) for
//! verification — if the cert doesn't chain to a public CA, the dest is
//! either a private/self-signed endpoint (terrible camouflage) or a
//! known-bad CA (also terrible). Either way, reject.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer;

const PROBE_TIMEOUT: Duration = Duration::from_secs(7);

/// What the probe reports back to the UI / API caller.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    /// Did all hard checks pass? (TCP up + TLS 1.3 + SAN match + chain valid)
    pub ok: bool,
    /// `host:port` the probe connected to.
    pub dest: String,
    /// SNI the probe sent (== `serverNames[0]`).
    pub sni: String,
    /// Negotiated TLS version: `"1.3"`, `"1.2"`, etc.
    pub tls_version: String,
    /// Negotiated ALPN protocol (e.g. `"h2"`) or empty if none.
    pub alpn: String,
    /// Subject Alternative Names extracted from the leaf certificate.
    pub cert_sans: Vec<String>,
    /// True if any SAN (literal or wildcard) matches `sni`.
    pub sni_matches_san: bool,
    /// TCP+TLS handshake RTT in milliseconds.
    pub rtt_ms: u128,
    /// Soft warnings (e.g. "TLS 1.2 negotiated, expected 1.3"). When
    /// `ok` is true the operator can ignore these; when false, they
    /// explain why the probe rejected the dest.
    pub warnings: Vec<String>,
}

/// Run the probe. `dest` is what goes into `realitySettings.dest` —
/// either `host:port` or just `host` (defaulted to port 443). `sni`
/// is what clients will send (`serverNames[0]`).
pub async fn probe_dest(dest: &str, sni: &str) -> Result<ProbeReport> {
    let (host, port) = split_host_port(dest)?;
    let mut warnings: Vec<String> = Vec::new();

    let started = Instant::now();
    let tcp = timeout(PROBE_TIMEOUT, TcpStream::connect((host.as_str(), port)))
        .await
        .map_err(|_| anyhow!("TCP connect to {host}:{port} timed out after {:?}", PROBE_TIMEOUT))?
        .with_context(|| format!("TCP connect to {host}:{port}"))?;

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Advertise both — h2 is what real CDN-fronted sites negotiate, and
    // a dest that returns h2 makes for the most convincing camouflage.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| anyhow!("invalid SNI {sni:?}: {e}"))?;

    let stream = timeout(PROBE_TIMEOUT, connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow!("TLS handshake with {sni} timed out after {:?}", PROBE_TIMEOUT))?
        .with_context(|| format!("TLS handshake with {sni}"))?;
    let rtt_ms = started.elapsed().as_millis();

    let (_io, tls_conn) = stream.get_ref();
    let proto_version = tls_conn.protocol_version();
    let tls_version = match proto_version {
        Some(rustls::ProtocolVersion::TLSv1_3) => "1.3".to_string(),
        Some(rustls::ProtocolVersion::TLSv1_2) => "1.2".to_string(),
        Some(v) => format!("{v:?}"),
        None => "unknown".to_string(),
    };
    if proto_version != Some(rustls::ProtocolVersion::TLSv1_3) {
        warnings.push(format!(
            "Reality requires TLS 1.3 but {host} negotiated {tls_version}; pick another dest"
        ));
    }

    let alpn = tls_conn
        .alpn_protocol()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    if alpn.is_empty() {
        warnings.push("dest didn't agree to an ALPN protocol — camouflage will be weaker".into());
    } else if alpn != "h2" {
        warnings.push(format!(
            "dest negotiated ALPN {alpn:?}; modern CDN traffic looks like h2"
        ));
    }

    let mut sans: Vec<String> = Vec::new();
    if let Some(certs) = tls_conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            sans = extract_sans(leaf.as_ref()).unwrap_or_default();
        }
    }
    let sni_matches_san = sans.iter().any(|s| san_matches(s, sni));
    if !sni_matches_san {
        warnings.push(format!(
            "leaf cert SAN {sans:?} doesn't cover SNI {sni:?} — clients will fail TLS verification"
        ));
    }

    // Cleanly tear down so we don't leak a socket on the dest. Reality
    // hugs the connection lifecycle so half-closing is fine.
    let mut stream = stream;
    let _ = stream.shutdown().await;

    let ok = proto_version == Some(rustls::ProtocolVersion::TLSv1_3) && sni_matches_san;

    Ok(ProbeReport {
        ok,
        dest: format!("{host}:{port}"),
        sni: sni.to_string(),
        tls_version,
        alpn,
        cert_sans: sans,
        sni_matches_san,
        rtt_ms,
        warnings,
    })
}

/// Pull SANs out of a DER-encoded certificate. Returns dNSName entries
/// (the only kind Reality cares about); we silently drop other GeneralName
/// variants like rfc822Name or iPAddress.
fn extract_sans(der: &[u8]) -> Result<Vec<String>> {
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|e| anyhow!("parse leaf cert: {e}"))?;
    let mut out = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dn) = name {
                    out.push(dn.to_string());
                }
            }
        }
    }
    Ok(out)
}

/// SAN matches SNI by RFC 6125: literal equality OR a leading `*.`
/// wildcard whose suffix matches everything from the first dot onward.
fn san_matches(san: &str, sni: &str) -> bool {
    let san = san.to_ascii_lowercase();
    let sni = sni.to_ascii_lowercase();
    if san == sni {
        return true;
    }
    if let Some(wildcard_suffix) = san.strip_prefix("*.") {
        // *.example.com matches foo.example.com but NOT example.com or foo.bar.example.com.
        if let Some((_, rest)) = sni.split_once('.') {
            return rest == wildcard_suffix;
        }
    }
    false
}

fn split_host_port(dest: &str) -> Result<(String, u16)> {
    if let Some((h, p)) = dest.rsplit_once(':') {
        // Bracketed IPv6 literal like [::1]:443.
        let host = h.trim_start_matches('[').trim_end_matches(']');
        let port: u16 = p.parse().map_err(|_| anyhow!("invalid port {p:?} in dest"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((dest.to_string(), 443))
    }
}

/// Curated list of dest candidates that are reachable from most
/// jurisdictions, terminate TLS 1.3, present long-lived public CA
/// chains, and look like organic CDN traffic. Surfaced in the admin
/// UI as a dropdown.
pub fn curated_candidates() -> &'static [&'static str] {
    &[
        "www.microsoft.com",
        "www.cloudflare.com",
        "www.bing.com",
        "www.cisco.com",
        "www.akamai.com",
        "www.apple.com",
        "learn.microsoft.com",
        "azure.microsoft.com",
        // Deliberately omit GitHub-related infra — intermittently
        // blocked from some jurisdictions per operator reports.
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_default() {
        assert_eq!(split_host_port("foo.com").unwrap(), ("foo.com".into(), 443));
    }

    #[test]
    fn split_host_port_explicit() {
        assert_eq!(
            split_host_port("foo.com:8443").unwrap(),
            ("foo.com".into(), 8443)
        );
    }

    #[test]
    fn split_host_port_ipv6_bracketed() {
        let (h, p) = split_host_port("[::1]:443").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
    }

    #[test]
    fn san_matches_literal() {
        assert!(san_matches("www.microsoft.com", "www.microsoft.com"));
        assert!(san_matches("WWW.MICROSOFT.COM", "www.microsoft.com"));
        assert!(!san_matches("www.microsoft.com", "microsoft.com"));
    }

    #[test]
    fn san_matches_wildcard() {
        assert!(san_matches("*.microsoft.com", "www.microsoft.com"));
        assert!(san_matches("*.microsoft.com", "learn.microsoft.com"));
        // Wildcard must not match the apex.
        assert!(!san_matches("*.microsoft.com", "microsoft.com"));
        // Wildcard is single-level only per RFC 6125.
        assert!(!san_matches("*.microsoft.com", "a.b.microsoft.com"));
    }

    /// Live network test against a known-good public dest. Marked
    /// `#[ignore]` so CI without internet access doesn't fail — run
    /// with `cargo test -- --ignored` for the e2e check.
    #[tokio::test]
    #[ignore = "requires network access to www.microsoft.com:443"]
    async fn probe_microsoft_succeeds() {
        let report = probe_dest("www.microsoft.com:443", "www.microsoft.com").await.unwrap();
        assert!(report.ok, "report not ok: {report:?}");
        assert_eq!(report.tls_version, "1.3");
        assert!(report.sni_matches_san);
        assert!(report.rtt_ms > 0 && report.rtt_ms < 5000);
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn probe_rejects_san_mismatch() {
        // Connect to microsoft.com but send a SNI it doesn't cover —
        // microsoft.com's leaf cert SANs are .microsoft-curated, not
        // example.invalid.
        let res = probe_dest("www.microsoft.com:443", "example.invalid").await;
        // Either the handshake fails (server rejects unknown SNI) or
        // the report comes back ok=false. Both are acceptable rejection
        // signals — the probe must not silently pass.
        // A handshake error is also a valid rejection signal; we only need to
        // ensure that a *successful* probe reports ok=false.
        if let Ok(r) = res {
            assert!(!r.ok);
        }
    }
}
