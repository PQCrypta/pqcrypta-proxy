//! Loads Encrypted Client Hello (ECH, draft-ietf-tls-esni-25) server
//! configurations from disk.
//!
//! Generated and rotated by the `ech-keygen` binary (see
//! `scripts/ech-rotate.sh` / `ech-rotate.timer`) into [`ECH_CONFIG_DIR`] as
//! `<config_id>.key` (private, mode 600) / `<config_id>.ech` (public wire
//! bytes, mode 644) pairs — one pair per still-accepted generation.
//!
//! [`load`] is called from every place a `rustls::ServerConfig` gets built,
//! the same way certificate loading already is, so a fresh `ech-keygen` run
//! is picked up on the next hot-reload without a proxy restart.

use std::path::Path;
use std::sync::Arc;

use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::server::{ServerEchConfig, ServerEchConfigs};
use tracing::{info, warn};

pub const ECH_CONFIG_DIR: &str = "/etc/pqcrypta/ech-configs";

/// Load every retained `<id>.key`/`<id>.ech` pair from [`ECH_CONFIG_DIR`].
///
/// Returns `None` (not an error) if the directory is absent, empty, or every
/// entry in it fails to load — ECH is an optional, incrementally-rolled-out
/// feature, so its absence or misconfiguration must never block a normal
/// (non-ECH) TLS config from being built. Problems are logged, not
/// propagated.
pub fn load() -> Option<Arc<ServerEchConfigs>> {
    load_from(Path::new(ECH_CONFIG_DIR))
}

fn load_from(dir: &Path) -> Option<Arc<ServerEchConfigs>> {
    let entries = std::fs::read_dir(dir).ok()?;

    let mut configs = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let ech_path = entry.path();
        if ech_path.extension().and_then(|s| s.to_str()) != Some("ech") {
            continue;
        }
        let key_path = ech_path.with_extension("key");

        let ech_bytes = match std::fs::read(&ech_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("ECH: failed to read {}: {}", ech_path.display(), e);
                continue;
            }
        };
        let key_bytes = match std::fs::read(&key_path) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("ECH: failed to read {}: {}", key_path.display(), e);
                continue;
            }
        };

        match ServerEchConfig::new(&ech_bytes, key_bytes.into(), ALL_SUPPORTED_SUITES) {
            Ok(config) => configs.push(config),
            Err(e) => warn!(
                "ECH: failed to parse config at {}: {}",
                ech_path.display(),
                e
            ),
        }
    }

    if configs.is_empty() {
        return None;
    }

    let count = configs.len();
    match ServerEchConfigs::new(configs) {
        Ok(configs) => {
            info!("ECH: loaded {} config(s) from {}", count, dir.display());
            Some(Arc::new(configs))
        }
        Err(e) => {
            warn!("ECH: failed to build ServerEchConfigs: {}", e);
            None
        }
    }
}
