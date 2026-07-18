//! Small date/time helpers over the `time` crate.
//!
//! `time` is already a mandatory dependency (axum-extra's cookie jar takes a
//! `time::Duration` for `max_age`, and it's pulled transitively regardless), so
//! routing our own date handling through it — instead of `chrono` — drops the
//! entire chrono subtree (`chrono`, `iana-time-zone`, `num-traits`) for zero
//! new cost. These wrappers keep the call sites terse and the `time` API
//! (fallible `format`/`parse`) from leaking everywhere.

use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};

/// Current UTC instant.
pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Format an instant as an RFC 3339 string (the on-disk representation for
/// expiry timestamps and one-time-link deadlines).
///
/// `OffsetDateTime` can always be represented in RFC 3339, so the only way
/// `format` can fail is an out-of-range component that this type cannot hold;
/// `unwrap_or_default` keeps the signature infallible for callers that just
/// want a string to store.
pub fn to_rfc3339(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_default()
}

/// `now_utc()` formatted as RFC 3339 — the common "stamp it now" case.
pub fn now_rfc3339() -> String {
    to_rfc3339(now_utc())
}

/// Parse an RFC 3339 timestamp, returning `None` on any malformed input.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

/// True if `s` is an acceptable client-expiry timestamp: full RFC 3339, or
/// either HTML `datetime-local` shape the UI can emit — `YYYY-MM-DDTHH:MM`
/// (no seconds) and `YYYY-MM-DDTHH:MM:SS`. Mirrors the previous chrono check
/// (`DateTime::parse_from_rfc3339` OR `NaiveDateTime::parse_from_str` with
/// `%Y-%m-%dT%H:%M` / `%Y-%m-%dT%H:%M:%S`).
pub fn is_valid_expiry(s: &str) -> bool {
    if OffsetDateTime::parse(s, &Rfc3339).is_ok() {
        return true;
    }
    let hm = format_description!("[year]-[month]-[day]T[hour]:[minute]");
    let hms = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    PrimitiveDateTime::parse(s, hm).is_ok() || PrimitiveDateTime::parse(s, hms).is_ok()
}

/// Convert a Unix timestamp (seconds) to an instant, `None` if out of range.
/// Used to render `awg show … dump`'s latest-handshake epoch column.
pub fn from_unix(ts: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(ts).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_round_trip() {
        let s = "2024-06-15T12:34:56Z";
        let dt = parse_rfc3339(s).unwrap();
        // time renders UTC with a `Z` designator, same instant.
        assert_eq!(to_rfc3339(dt), s);
    }

    #[test]
    fn accepts_rfc3339_offset_form() {
        // chrono's to_rfc3339 emitted `+00:00`; ensure we still accept it.
        assert!(parse_rfc3339("2024-06-15T12:34:56+00:00").is_some());
    }

    #[test]
    fn valid_expiry_shapes() {
        assert!(is_valid_expiry("2024-06-15T12:34:56Z")); // RFC3339
        assert!(is_valid_expiry("2024-06-15T12:34")); // datetime-local, no secs
        assert!(is_valid_expiry("2024-06-15T12:34:56")); // datetime-local, secs
        assert!(!is_valid_expiry("15/06/2024")); // wrong shape
        assert!(!is_valid_expiry("not a date"));
        assert!(!is_valid_expiry("2024-13-40T99:99")); // out of range
    }

    #[test]
    fn from_unix_matches_expected() {
        let dt = from_unix(1_718_454_896).unwrap();
        assert_eq!(dt.unix_timestamp(), 1_718_454_896);
    }
}
