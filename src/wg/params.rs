//! AmneziaWG obfuscation parameter generation and validation.
//!
//! These parameters control how AmneziaWG hides its traffic:
//! - Jc/Jmin/Jmax: junk packet count and size range
//! - S1/S2: init/response header junk size
//! - H1-H4: magic header values (must be distinct)
//! - I1-I5: init packet junk payload (optional large hex blobs)

use rand::Rng;
use serde::{Serialize, Deserialize};

/// Complete set of AmneziaWG obfuscation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwgParams {
    /// Junk packet count (1-128, typical 4-12)
    pub jc: i32,
    /// Junk packet minimum size in bytes (0-1279)
    pub jmin: i32,
    /// Junk packet maximum size in bytes (1-1280, must be > jmin)
    pub jmax: i32,
    /// Init packet header junk size (0-1132)
    pub s1: i32,
    /// Response packet header junk size (0-1188)
    pub s2: i32,
    /// Optional init junk size 3 (nullable)
    pub s3: Option<i32>,
    /// Optional response junk size 4 (nullable)
    pub s4: Option<i32>,
    /// Magic header 1 (must be distinct from H2-H4)
    pub h1: String,
    /// Magic header 2
    pub h2: String,
    /// Magic header 3
    pub h3: String,
    /// Magic header 4
    pub h4: String,
    /// Init junk payload 1 (large hex, optional)
    pub i1: Option<String>,
    /// Init junk payload 2 (optional)
    pub i2: Option<String>,
    /// Init junk payload 3 (optional)
    pub i3: Option<String>,
    /// Init junk payload 4 (optional)
    pub i4: Option<String>,
    /// Init junk payload 5 (optional)
    pub i5: Option<String>,
}

/// Generate a fresh set of random AmneziaWG obfuscation parameters.
///
/// Ranges match the original awg-easy Node.js implementation:
/// - Jc: 4..=12
/// - Jmin: 8..=80
/// - Jmax: (jmin+1)..=1280
/// - S1: 15..=min(150, 1132)
/// - S2: 15..=min(150, 1188)
/// - H1-H4: distinct values in [5, 2147483647] (awg-go accepts both single values and ranges)
/// - I1: random tagged blob per amnezia-client default format
pub fn generate_awg_params() -> AwgParams {
    let mut rng = rand::thread_rng();

    let jc = rng.gen_range(4..=12);
    let jmin = rng.gen_range(8..=80);
    let jmax = rng.gen_range((jmin + 1).max(1)..=1280);
    let s1 = rng.gen_range(15..=150.min(1132));
    let s2 = rng.gen_range(15..=150.min(1188));

    // Generate 4 distinct magic headers in range [5, 2147483647]
    let mut headers = std::collections::HashSet::new();
    while headers.len() < 4 {
        headers.insert(rng.gen_range(5i64..=2_147_483_647));
    }
    let h: Vec<String> = headers.into_iter().map(|v| v.to_string()).collect();

    // Generate random I1 in amnezia-client tag format:
    // <r 2> = 2 random bytes, <b 0x...> = static hex blob
    let random_hex: String = (0..48).map(|_| format!("{:02x}", rng.gen::<u8>())).collect();
    let i1 = format!("<r 2><b 0x{}>", random_hex);

    AwgParams {
        jc,
        jmin,
        jmax,
        s1,
        s2,
        s3: None,
        s4: None,
        h1: h[0].clone(),
        h2: h[1].clone(),
        h3: h[2].clone(),
        h4: h[3].clone(),
        i1: Some(i1),
        i2: None,
        i3: None,
        i4: None,
        i5: None,
    }
}

/// Validate that AmneziaWG parameters are within allowed ranges.
pub fn validate_awg_params(params: &AwgParams) -> Result<(), String> {
    if !(1..=128).contains(&params.jc) {
        return Err("Jc must be 1-128".into());
    }
    if params.jmin < 0 || params.jmin >= 1280 {
        return Err("Jmin must be 0-1279".into());
    }
    if !(1..=1280).contains(&params.jmax) {
        return Err("Jmax must be 1-1280".into());
    }
    if params.jmax <= params.jmin {
        return Err("Jmax must be > Jmin".into());
    }
    if params.s1 < 0 || params.s1 > 1132 {
        return Err("S1 must be 0-1132".into());
    }
    if params.s2 < 0 || params.s2 > 1188 {
        return Err("S2 must be 0-1188".into());
    }
    if params.s1 + 56 == params.s2 {
        return Err("S1+56 != S2".into());
    }

    // All magic headers must be distinct
    let headers = [&params.h1, &params.h2, &params.h3, &params.h4];
    for i in 0..4 {
        for j in (i + 1)..4 {
            if headers[i] == headers[j] {
                return Err("All H1-H4 must be distinct".into());
            }
        }
    }

    Ok(())
}
