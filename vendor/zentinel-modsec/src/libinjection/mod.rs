//! SQL injection and XSS detection for `@detectSQLi` and `@detectXSS`:
//! libinjection's own algorithm, through `barbacane-libinjection` (imported
//! as `libinjectionrs`), a memory-safe Rust port measured against the C
//! library.
//!
//! This crate shipped a simplified detector of its own here, "similar to"
//! libinjection: a reduced fingerprint set and a fallback that called input
//! SQL when it found keywords and punctuation. It flagged ordinary crawler
//! User-Agents (`Mozilla/5.0 (compatible; AhrefsBot/7.0;
//! +http://ahrefs.com/robot/)`, Facebook's and Petal's) as SQL injection, so
//! CRS rule 942100 blocked 44% of a day's real requests to pqcrypta.com. The
//! C library flags none of them, and neither does the port: against
//! libinjection v4.0.2 it gave the same verdict on all 34,293 inputs checked
//! (CRS's regression payloads and a week of served requests), with the same
//! fingerprint wherever both flag.

pub mod sqli;
pub mod xss;

pub use sqli::{is_sqli, sqli_fingerprint};
pub use xss::is_xss;

/// A detector's verdict, with the fingerprint when the input is SQL.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// The input is an injection.
    pub is_injection: bool,
    /// libinjection's token fingerprint of an injection (SQLi only).
    pub fingerprint: Option<String>,
}

impl DetectionResult {
    /// An injection, with its fingerprint.
    pub fn detected(fingerprint: String) -> Self {
        Self {
            is_injection: true,
            fingerprint: Some(fingerprint),
        }
    }

    /// No injection.
    pub fn safe() -> Self {
        Self {
            is_injection: false,
            fingerprint: None,
        }
    }
}
