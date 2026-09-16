//! RFC 8879 certificate compression policy.
//!
//! Two TLS stacks terminate traffic here and they enable this in completely
//! different ways: OpenSSL needs two FFI calls (see
//! [`crate::pqc_tls::openssl_pqc`]), while rustls builds its compressor list
//! from compiled crate features and needs none. A single operator-facing
//! setting has to reach both, so the policy is fixed once at startup and read
//! from wherever a TLS context is built — the same shape as
//! [`crate::ech_config`], and for the same reason.

use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

/// Resolve `tls.certificate_compression` into the process-wide policy.
///
/// `auto` (the default) offers whatever the compiled stack can actually
/// produce: zlib on OpenSSL, which reports `-DZLIB` and nothing else here, and
/// brotli or zlib on rustls. `off` sends an uncompressed chain on both.
///
/// An unrecognised value is a configuration mistake, not a reason to refuse
/// service: it warns and falls back to `auto`, because compression is a
/// size optimisation and a typo should not change what the proxy serves.
pub fn init(setting: &str) {
    let enabled = match parse(setting) {
        Some(v) => v,
        None => {
            tracing::warn!(
                "tls.certificate_compression = {:?} is not recognised (expected \"auto\" or \
                 \"off\"); using \"auto\"",
                setting
            );
            true
        }
    };
    if ENABLED.set(enabled).is_err() {
        // Only reachable if startup wiring called this twice; the first value
        // is the one every TLS context was already built against.
        tracing::warn!("certificate compression policy was already fixed; ignoring {setting:?}");
        return;
    }
    if !enabled {
        tracing::info!("TLS certificate compression disabled by configuration (RFC 8879)");
    }
}

/// `Some(true)` for auto/on, `Some(false)` for off, `None` for anything else.
fn parse(setting: &str) -> Option<bool> {
    match setting.trim().to_ascii_lowercase().as_str() {
        "auto" | "on" | "true" | "enabled" => Some(true),
        "off" | "false" | "disabled" | "none" => Some(false),
        _ => None,
    }
}

/// Whether a chain may be sent compressed.
///
/// Defaults to enabled when [`init`] never ran, so a code path that builds a
/// TLS context outside normal startup (tests, the conformance harness) keeps
/// the behaviour the proxy shipped with.
pub fn enabled() -> bool {
    *ENABLED.get().unwrap_or(&true)
}

/// Apply the policy to a rustls server config.
///
/// rustls populates `cert_compressors` from crate features before we see the
/// config, so turning this off means emptying a list rather than filling one.
pub fn apply(config: &mut rustls::ServerConfig) {
    if !enabled() {
        config.cert_compressors = Vec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn auto_and_its_synonyms_enable() {
        for s in ["auto", "AUTO", " auto ", "on", "true", "enabled"] {
            assert_eq!(parse(s), Some(true), "{s:?}");
        }
    }

    #[test]
    fn off_and_its_synonyms_disable() {
        for s in ["off", "OFF", "false", "disabled", "none"] {
            assert_eq!(parse(s), Some(false), "{s:?}");
        }
    }

    /// A typo must be distinguishable from a deliberate "off", so the caller
    /// can warn rather than silently serving uncompressed chains.
    #[test]
    fn an_unknown_value_is_not_silently_treated_as_off() {
        assert_eq!(parse("zlib"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse("no"), None);
    }
}
