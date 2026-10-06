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

/// The `config_id` of every retained ECHConfig in [`ECH_CONFIG_DIR`].
///
/// What an encrypted_client_hello extension names when a client means it for
/// this server, as opposed to GREASE (draft-ietf-tls-esni-25, section 6.2),
/// which names a random one.
pub fn config_ids() -> Vec<u8> {
    config_ids_from(Path::new(ECH_CONFIG_DIR))
}

fn config_ids_from(dir: &Path) -> Vec<u8> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ids: Vec<u8> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("ech"))
        .filter(|p| p.with_extension("key").exists())
        // ECHConfig: version (2), length (2), then HpkeKeyConfig.config_id
        .filter_map(|p| std::fs::read(p).ok()?.get(4).copied())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The `config_id` an outer encrypted_client_hello extension names.
///
/// `record` is the TLS record holding the ClientHello, as peeked off the
/// socket. None for a ClientHello without ECH, an inner one, or bytes that
/// are not a whole ClientHello record.
pub fn offered_config_id(record: &[u8]) -> Option<u8> {
    fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if b.len() < n {
            return None;
        }
        let (head, rest) = b.split_at(n);
        *b = rest;
        Some(head)
    }
    fn u8_len<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
        let n = *take(b, 1)?.first()? as usize;
        take(b, n)
    }
    fn u16_len<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
        let h = take(b, 2)?;
        take(b, u16::from_be_bytes([h[0], h[1]]) as usize)
    }

    let mut b = record;
    // Record: handshake (22), version, length
    if *take(&mut b, 1)?.first()? != 22 {
        return None;
    }
    take(&mut b, 2)?;
    let mut hs = u16_len(&mut b)?;
    // Handshake: client_hello (1), 24-bit length
    if *take(&mut hs, 1)?.first()? != 1 {
        return None;
    }
    let len = take(&mut hs, 3)?;
    let mut body = take(
        &mut hs,
        u32::from_be_bytes([0, len[0], len[1], len[2]]) as usize,
    )?;
    take(&mut body, 2 + 32)?; // legacy_version, random
    u8_len(&mut body)?; // legacy_session_id
    u16_len(&mut body)?; // cipher_suites
    u8_len(&mut body)?; // legacy_compression_methods
    let mut exts = u16_len(&mut body)?;
    while !exts.is_empty() {
        let kind = take(&mut exts, 2)?;
        let mut data = u16_len(&mut exts)?;
        if u16::from_be_bytes([kind[0], kind[1]]) == 0xfe0d {
            // ECHClientHello: type (0 = outer), cipher suite (kdf, aead), config_id
            if *take(&mut data, 1)?.first()? != 0 {
                return None;
            }
            take(&mut data, 4)?;
            return take(&mut data, 1)?.first().copied();
        }
    }
    None
}

#[cfg(test)]
mod ech_routing_tests {
    use super::{config_ids_from, offered_config_id};

    /// A ClientHello record with the given extensions, `(type, data)`.
    fn client_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut exts = Vec::new();
        for (kind, data) in extensions {
            exts.extend_from_slice(&kind.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(data);
        }
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x02]); // one suite
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1];
        hs.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    /// Outer ECHClientHello naming `config_id`.
    fn ech_outer(config_id: u8) -> Vec<u8> {
        let mut data = vec![0, 0, 1, 0, 1, config_id];
        data.extend_from_slice(&[0, 32]);
        data.extend_from_slice(&[9; 32]); // enc
        data.extend_from_slice(&[0, 16]);
        data.extend_from_slice(&[5; 16]); // payload
        data
    }

    #[test]
    fn the_offered_config_id_is_read_from_the_outer_extension() {
        let sni = (0u16, vec![0, 4, 0, 0, 1, b'x']);
        assert_eq!(
            offered_config_id(&client_hello(&[sni.clone(), (0xfe0d, ech_outer(0x64))])),
            Some(0x64)
        );
        // No ECH, an inner ECHClientHello, and a truncated record: none
        assert_eq!(
            offered_config_id(&client_hello(std::slice::from_ref(&sni))),
            None
        );
        assert_eq!(offered_config_id(&client_hello(&[(0xfe0d, vec![1])])), None);
        let whole = client_hello(&[sni, (0xfe0d, ech_outer(0x64))]);
        assert_eq!(offered_config_id(&whole[..whole.len() - 10]), None);
    }

    #[test]
    fn config_ids_come_from_the_retained_configs() {
        let dir = std::env::temp_dir().join(format!("ech-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // ECHConfig: version fe0d, length, config_id 0x64 ...
        std::fs::write(dir.join("64.ech"), [0xfe, 0x0d, 0, 10, 0x64, 0, 0x20]).unwrap();
        std::fs::write(dir.join("64.key"), [0u8; 32]).unwrap();
        // A config without its key is not one this server can use
        std::fs::write(dir.join("65.ech"), [0xfe, 0x0d, 0, 10, 0x65, 0, 0x20]).unwrap();
        assert_eq!(config_ids_from(&dir), vec![0x64]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
