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
    // Spec: Jmax < 1280 (strict). We cap at 1279 to stay inside the spec
    // while still avoiding fragmentation against the default 1420 MTU.
    let jmax = rng.gen_range((jmin + 1).max(1)..=1279);
    let s1 = rng.gen_range(15..=150.min(1132));
    // Retry s2 until the spec rule `s1 + 56 != s2` is satisfied.
    let s2 = loop {
        let candidate = rng.gen_range(15..=150.min(1188));
        if candidate != s1 + 56 {
            break candidate;
        }
    };

    // AmneziaWG 2.0 magic headers — emit 4 non-overlapping windows so the
    // server selects a fresh value per packet (1.5-style single-integer
    // headers are accepted but provide weaker obfuscation). Layout:
    // partition the i32 space [5, 2_147_483_647] into 8 random midpoints,
    // then take 4 disjoint [start, end] sub-ranges around them.
    const H_MIN: i64 = 5;
    const H_MAX: i64 = 2_147_483_647;
    let mut splits: Vec<i64> = (0..8)
        .map(|_| rng.gen_range(H_MIN..H_MAX))
        .collect();
    splits.sort_unstable();
    splits.dedup();
    while splits.len() < 8 {
        let v = rng.gen_range(H_MIN..H_MAX);
        if !splits.contains(&v) {
            splits.push(v);
            splits.sort_unstable();
        }
    }
    let h: Vec<String> = (0..4)
        .map(|i| {
            let lo = splits[i * 2];
            let hi = splits[i * 2 + 1];
            // Each header is encoded as `start-end` per AmneziaWG 2.0.
            // amneziawg-tools accepts both single integers and ranges; we
            // always emit ranges so the kernel selects randomly within them.
            format!("{}-{}", lo, hi)
        })
        .collect();

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

/// Validate an I1-I5 init-spec string against the AmneziaWG CPS tag
/// grammar. An empty string is allowed (means "not configured").
///
/// Recognised tags (per docs.amnezia.org and amneziawg-go):
///   `<b 0xHEX>`  — static byte sequence (hex digits, even length)
///   `<r N>`      — N random bytes; N is decimal, 0 < N <= 1000
///   `<rc N>`     — N random ASCII letters
///   `<rd N>`     — N random decimal digits
///   `<t>`        — current 4-byte timestamp
///   `<c>`        — packet counter
///
/// Anything between consecutive tags must be empty — the spec does not
/// allow free text outside of tag delimiters. Returns Ok(()) on a valid
/// (possibly empty) string, or Err with a human-readable diagnostic.
pub fn validate_init_spec(spec: &str) -> Result<(), String> {
    if spec.is_empty() {
        return Ok(());
    }
    // Kernel jp_spec_setup() rejects when the total init-packet size exceeds
    // MESSAGE_MAX_SIZE (65535). We mirror that bound so bad configs are
    // caught at API time rather than awg-quick time.
    const MESSAGE_MAX_SIZE: u64 = 65_535;
    let bytes = spec.as_bytes();
    let mut i = 0;
    let mut total: u64 = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            return Err(format!(
                "unexpected character {:?} at offset {} (init-spec must contain only <…> tags)",
                bytes[i] as char, i
            ));
        }
        let close = match spec[i..].find('>') {
            Some(off) => i + off,
            None => return Err(format!("unclosed tag starting at offset {}", i)),
        };
        let inner = &spec[i + 1..close];
        let size = validate_init_tag(inner)
            .map_err(|e| format!("invalid tag <{}>: {}", inner, e))?;
        total = total.saturating_add(size);
        if total > MESSAGE_MAX_SIZE {
            return Err(format!(
                "init-spec total packet size {} exceeds kernel MESSAGE_MAX_SIZE ({})",
                total, MESSAGE_MAX_SIZE
            ));
        }
        i = close + 1;
    }
    Ok(())
}

/// Returns the byte size this tag would contribute to the assembled init
/// packet (matching kernel `jp_tag::pkt_size` semantics).
fn validate_init_tag(inner: &str) -> Result<u64, String> {
    let mut parts = inner.splitn(2, ' ');
    let kind = parts.next().unwrap_or("");
    let arg = parts.next().map(str::trim);
    match (kind, arg) {
        // `<t>` and `<c>` both produce a 4-byte u32 in kernel jp_tag.
        ("t", None) | ("c", None) => Ok(4),
        ("b", Some(hex)) => {
            let body = hex.strip_prefix("0x").or_else(|| hex.strip_prefix("0X")).unwrap_or(hex);
            if body.is_empty() || body.len() % 2 != 0 {
                return Err("expected non-empty even-length hex".into());
            }
            if !body.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("contains non-hex characters".into());
            }
            Ok((body.len() / 2) as u64)
        }
        ("r" | "rc" | "rd", Some(num)) => {
            let n: u64 = num
                .parse()
                .map_err(|_| format!("expected integer, got {:?}", num))?;
            if n == 0 {
                return Err("count must be > 0".into());
            }
            // Kernel itself only caps the total packet size, but a single
            // 65535-byte tag is already absurd. We refuse anything beyond
            // 1000 per tag for sanity.
            if n > 1000 {
                return Err("count must be <= 1000".into());
            }
            Ok(n)
        }
        ("b", None) => Err("missing 0xHEX argument".into()),
        ("r" | "rc" | "rd", None) => Err("missing count argument".into()),
        ("t" | "c", Some(_)) => Err(format!("tag <{kind}> takes no argument")),
        _ => Err(format!("unknown tag kind {kind:?}")),
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
    // Spec: Jmax < 1280 (strict)
    if !(1..=1279).contains(&params.jmax) {
        return Err("Jmax must be 1-1279".into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_init_spec_is_valid() {
        assert!(validate_init_spec("").is_ok());
    }

    #[test]
    fn init_spec_static_bytes() {
        assert!(validate_init_spec("<b 0xdeadbeef>").is_ok());
        assert!(validate_init_spec("<b 0xDEAD>").is_ok());
        // Odd hex length must be rejected.
        assert!(validate_init_spec("<b 0xdea>").is_err());
        // Non-hex characters must be rejected.
        assert!(validate_init_spec("<b 0xnothex>").is_err());
        // Missing argument.
        assert!(validate_init_spec("<b>").is_err());
    }

    #[test]
    fn init_spec_random_count_bounds() {
        assert!(validate_init_spec("<r 1>").is_ok());
        assert!(validate_init_spec("<r 1000>").is_ok());
        assert!(validate_init_spec("<r 0>").is_err());
        assert!(validate_init_spec("<r 1001>").is_err());
        assert!(validate_init_spec("<rc 64>").is_ok());
        assert!(validate_init_spec("<rd 32>").is_ok());
    }

    #[test]
    fn init_spec_zero_arg_tags() {
        assert!(validate_init_spec("<t>").is_ok());
        assert!(validate_init_spec("<c>").is_ok());
        assert!(validate_init_spec("<t 5>").is_err());
        assert!(validate_init_spec("<c 5>").is_err());
    }

    #[test]
    fn init_spec_mixed_tags() {
        assert!(validate_init_spec("<r 2><b 0xcafebabe><c><t>").is_ok());
    }

    #[test]
    fn init_spec_rejects_text_outside_tags() {
        assert!(validate_init_spec("hello").is_err());
        assert!(validate_init_spec("<r 2>oops<t>").is_err());
        assert!(validate_init_spec("<unterminated").is_err());
    }

    #[test]
    fn init_spec_rejects_unknown_kind() {
        assert!(validate_init_spec("<bogus 5>").is_err());
    }

    #[test]
    fn generated_params_pass_validation() {
        // Generation must produce valid params on every iteration.
        for _ in 0..100 {
            let p = generate_awg_params();
            validate_awg_params(&p).expect("generated params should validate");
            assert!(p.jmax < 1280, "Jmax must be strictly < 1280");
            assert!(p.jmin < p.jmax);
            // Defaults emit ranges, not single integers.
            for h in [&p.h1, &p.h2, &p.h3, &p.h4] {
                assert!(h.contains('-'), "H must be a `start-end` range, got {h:?}");
            }
            // Generated I1 is a valid CPS tag string.
            validate_init_spec(p.i1.as_deref().unwrap_or(""))
                .expect("generated I1 should validate");
        }
    }

    #[test]
    fn generated_h_ranges_are_non_overlapping() {
        let p = generate_awg_params();
        let parse = |s: &str| -> (i64, i64) {
            let mut it = s.splitn(2, '-').map(|x| x.parse::<i64>().unwrap());
            let lo = it.next().unwrap();
            let hi = it.next().unwrap_or(lo);
            (lo, hi)
        };
        let rs = [parse(&p.h1), parse(&p.h2), parse(&p.h3), parse(&p.h4)];
        for i in 0..4 {
            assert!(rs[i].0 <= rs[i].1, "H{} range out of order", i + 1);
            for j in (i + 1)..4 {
                let (a, b) = (rs[i], rs[j]);
                assert!(
                    a.1 < b.0 || b.1 < a.0,
                    "H{} {:?} overlaps H{} {:?}",
                    i + 1,
                    a,
                    j + 1,
                    b
                );
            }
        }
    }
}
