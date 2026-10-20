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
//! is picked up on the next hot-reload without a proxy restart: the QUIC
//! config is rebuilt in `TlsProvider::reload_certificates`, and when
//! [`reloads`] moves every QUIC listener installs it on its endpoint and every
//! TCP listener rebuilds its own.

use std::path::Path;
use std::sync::{Arc, LazyLock};

use rustls::crypto::hpke::Hpke;
use rustls::server::{ServerEchConfig, ServerEchConfigs};
use tracing::{info, warn};

pub const ECH_CONFIG_DIR: &str = "/etc/pqcrypta/ech-configs";

/// Counts the proxy's TLS reloads (`TlsProvider::reload_certificates`, run
/// when the certificates directory or [`ECH_CONFIG_DIR`] changes, on an ACME
/// renewal, or from the admin API). Every listener's rustls config has the
/// ECH configs built in, and a QUIC endpoint or TCP listener keeps the one it
/// was given: each installs the rebuilt one when this moves. Without that, a
/// rotated ECH key that DNS already published was refused by every listener
/// that had not, until a restart (TCP until 2026-10, QUIC until 2026-10-20).
static TLS_RELOADS: LazyLock<tokio::sync::watch::Sender<u64>> =
    LazyLock::new(|| tokio::sync::watch::channel(0).0);

/// A receiver that changes once per TLS reload.
pub fn reloads() -> tokio::sync::watch::Receiver<u64> {
    TLS_RELOADS.subscribe()
}

/// Tell the TCP listeners the TLS material has reloaded.
pub(crate) fn note_reload() {
    TLS_RELOADS.send_modify(|n| *n = n.wrapping_add(1));
}

/// Every HPKE suite a config can be opened with: the post-quantum ones
/// (X-Wing, ML-KEM-768, ML-KEM-1024) and rustls's RFC 9180 DH ones. A config
/// whose KEM is in neither is refused at load, as before.
pub fn suites() -> &'static [&'static dyn Hpke] {
    static SUITES: LazyLock<Vec<&'static dyn Hpke>> = LazyLock::new(|| {
        pqcrypta_hpke_pq::ALL_SUPPORTED_SUITES
            .iter()
            .chain(rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES)
            .copied()
            .collect()
    });
    &SUITES
}

/// The HPKE KEM an encoded `ECHConfig` (version, length, then its
/// HpkeKeyConfig: config_id, kem_id, ...) is keyed for.
pub fn kem_id(ech_config: &[u8]) -> Option<u16> {
    ech_config
        .get(5..7)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

/// Whether a KEM resists a quantum adversary: everything but the RFC 9180
/// Diffie-Hellman KEMs (P-256, P-384, P-521, X25519, X448).
pub fn is_post_quantum_kem(kem_id: u16) -> bool {
    !matches!(kem_id, 0x0010 | 0x0011 | 0x0012 | 0x0020 | 0x0021)
}

/// The order configs are published and offered in: post-quantum first, then
/// newest first.
///
/// A client uses the first config it implements, so a
/// post-quantum client gets the config a quantum computer cannot open, and a
/// browser (X25519 only today) skips it and uses the newest X25519 one. The
/// list had been oldest first, which handed every client the stalest key.
pub fn publication_order(
    kem_id: u16,
    modified: std::time::SystemTime,
) -> (bool, std::cmp::Reverse<std::time::SystemTime>) {
    (!is_post_quantum_kem(kem_id), std::cmp::Reverse(modified))
}

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
    let mut order = Vec::new();
    let mut loaded = Vec::new();
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

        let modified = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match ServerEchConfig::new(&ech_bytes, key_bytes.into(), suites()) {
            Ok(config) => {
                order.push(publication_order(kem_id(&ech_bytes).unwrap_or(0), modified));
                loaded.push(ech_bytes);
                configs.push(config);
            }
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
    // read_dir has no order: the publication order, so retry_configs lists
    // the post-quantum config first exactly as DNS does
    let mut ordered: Vec<_> = order
        .into_iter()
        .zip(loaded.into_iter().zip(configs))
        .collect();
    ordered.sort_by_key(|(key, _)| *key);
    let (loaded, configs): (Vec<Vec<u8>>, Vec<ServerEchConfig>) =
        ordered.into_iter().map(|(_, pair)| pair).unzip();
    let current = current_configs(dir, &loaded);

    let count = configs.len();
    let offered = current.len();
    match ServerEchConfigs::with_current(configs, current) {
        Ok(configs) => {
            info!(
                "ECH: loaded {} config(s) from {}, {} of them current (offered as retry_configs)",
                count,
                dir.display(),
                offered
            );
            Some(Arc::new(configs))
        }
        Err(e) => {
            warn!("ECH: failed to build ServerEchConfigs: {}", e);
            None
        }
    }
}

/// Which of `loaded` (encoded ECHConfigs, in publication order) are current:
/// the ones `ech-config-list.bin` holds, which is what DNS publishes. A
/// rejection offers only those as retry_configs (RFC 9849 section 7.1: "with
/// up-to-date keys"); the others are retained to open offers sealed to an
/// older config that a resolver still caches. Without a list, or with one
/// naming none of them, the newest of each KEM, which is what `ech-keygen`
/// publishes.
fn current_configs(dir: &Path, loaded: &[Vec<u8>]) -> Vec<usize> {
    let published = std::fs::read(dir.join("ech-config-list.bin"))
        .map(|list| list_entries(&list))
        .unwrap_or_default();
    let listed: Vec<usize> = (0..loaded.len())
        .filter(|i| published.contains(&loaded[*i]))
        .collect();
    if !listed.is_empty() {
        return listed;
    }
    let mut kems = Vec::new();
    (0..loaded.len())
        .filter(|i| {
            let kem = kem_id(&loaded[*i]);
            let first = !kems.contains(&kem);
            kems.push(kem);
            first
        })
        .collect()
}

/// The encoded ECHConfigs of an ECHConfigList: a 2-octet length, then each
/// config's version, 2-octet length and contents.
fn list_entries(list: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Some(body) = list
        .get(..2)
        .map(|n| usize::from(u16::from_be_bytes([n[0], n[1]])))
        .and_then(|n| list.get(2..2 + n))
    else {
        return out;
    };
    let mut at = 0;
    while let Some(len) = body
        .get(at + 2..at + 4)
        .map(|n| usize::from(u16::from_be_bytes([n[0], n[1]])))
    {
        let Some(entry) = body.get(at..at + 4 + len) else {
            break;
        };
        out.push(entry.to_vec());
        at += 4 + len;
    }
    out
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

/// Encrypted Client Hello end to end, in memory: configs written to a
/// directory the way `ech-keygen` writes them, loaded by `load_from`, served
/// by the rustls fork, and offered by a rustls client.
#[cfg(test)]
mod pq_ech_tests {
    use super::{is_post_quantum_kem, kem_id, load_from, suites};
    use rustls::client::{EchConfig, EchMode, EchStatus};
    use rustls::crypto::hpke::Hpke;
    use rustls::internal::msgs::base::PayloadU16;
    use rustls::internal::msgs::codec::Codec;
    use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
    use rustls::internal::msgs::handshake::{
        EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
    };
    use rustls::pki_types::{
        CertificateDer, DnsName, EchConfigListBytes, PrivateKeyDer, ServerName,
    };
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
    use std::path::PathBuf;
    use std::sync::Arc;

    const INNER: &str = "pq.example";
    const OUTER: &str = "public.example";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pq-ech-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write one `<id>.key` / `<id>.ech` pair for `suite`, as ech-keygen does;
    /// returns the encoded ECHConfig.
    fn write_config(dir: &std::path::Path, id: u8, suite: &'static dyn Hpke) -> Vec<u8> {
        let (public_key, private_key) = suite.generate_key_pair().unwrap();
        let s = suite.suite();
        let contents = EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id: id,
                kem_id: s.kem,
                public_key: PayloadU16::new(public_key.0),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                    kdf_id: s.sym.kdf_id,
                    aead_id: s.sym.aead_id,
                }],
            },
            maximum_name_length: 32,
            public_name: DnsName::try_from(OUTER.to_string()).unwrap(),
            extensions: Vec::new(),
        };
        let mut bytes = Vec::new();
        EchConfigPayload::V18(contents).encode(&mut bytes);
        std::fs::write(
            dir.join(format!("{id:02x}.key")),
            private_key.secret_bytes(),
        )
        .unwrap();
        std::fs::write(dir.join(format!("{id:02x}.ech")), &bytes).unwrap();
        bytes
    }

    fn list(configs: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = configs.concat();
        let mut out = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    fn certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = rcgen::generate_simple_self_signed(vec![INNER.into(), OUTER.into()]).unwrap();
        (
            key.cert.der().clone(),
            PrivateKeyDer::Pkcs8(key.signing_key.serialize_der().into()),
        )
    }

    fn handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
        for _ in 0..16 {
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                server.read_tls(&mut rd).unwrap();
                server.process_new_packets().unwrap();
            }
            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            let mut rd = &buf[..];
            while !rd.is_empty() {
                client.read_tls(&mut rd).unwrap();
                client.process_new_packets().unwrap();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("handshake did not complete");
    }

    /// One handshake offering ECH with `published`, using `client_suites`;
    /// returns the client's ECH status and the name the server answered for.
    fn connect(
        dir: &std::path::Path,
        published: &[u8],
        client_suites: &[&'static dyn Hpke],
    ) -> (EchStatus, Option<String>) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let (cert, key) = certificate();
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        server_config.ech = load_from(dir);
        assert!(server_config.ech.is_some());
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let ech =
            EchConfig::new(EchConfigListBytes::from(published.to_vec()), client_suites).unwrap();
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_ech(EchMode::Enable(ech))
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from(INNER).unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        handshake(&mut client, &mut server);
        (
            client.ech_status(),
            server.server_name().map(str::to_string),
        )
    }

    #[test]
    fn an_x_wing_config_is_accepted_and_hides_the_real_name() {
        let dir = scratch("xwing");
        let x_wing = write_config(&dir, 0x11, &pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256);
        let (status, name) = connect(
            &dir,
            &list(&[&x_wing]),
            &pqcrypta_hpke_pq::ALL_SUPPORTED_SUITES,
        );
        assert_eq!(status, EchStatus::Accepted);
        // The server answered for the inner name, which only the sealed hello carried
        assert_eq!(name.as_deref(), Some(INNER));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ml_kem_configs_are_accepted() {
        let ml_kem: [(u8, &'static dyn Hpke); 2] = [
            (0x21, &pqcrypta_hpke_pq::ML_KEM_768_HKDF_SHA256_AES_256),
            (0x22, &pqcrypta_hpke_pq::ML_KEM_1024_HKDF_SHA384_AES_256),
        ];
        for (id, suite) in ml_kem {
            let dir = scratch("mlkem");
            let config = write_config(&dir, id, suite);
            let (status, name) = connect(
                &dir,
                &list(&[&config]),
                &pqcrypta_hpke_pq::ALL_SUPPORTED_SUITES,
            );
            assert_eq!(
                status,
                EchStatus::Accepted,
                "KEM 0x{:04X}",
                u16::from(suite.suite().kem)
            );
            assert_eq!(name.as_deref(), Some(INNER));
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    /// The published list as ech-keygen orders it, X-Wing first: a client with
    /// the post-quantum suites uses the X-Wing config, and one with only
    /// rustls's DH suites (a browser's position today) skips it and still gets
    /// ECH through the X25519 config.
    #[test]
    fn both_kinds_of_client_get_ech_from_one_list() {
        let dir = scratch("both");
        // The classical config a browser uses: X25519, or P-256 in a FIPS build,
        // whose HPKE suites leave X25519 out. Either is a Diffie-Hellman KEM,
        // which is the case under test.
        let classical_suite = |kem: HpkeKem| {
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
                .iter()
                .copied()
                .find(|h| {
                    h.suite().kem == kem
                        && h.suite().sym.kdf_id == HpkeKdf::HKDF_SHA256
                        && h.suite().sym.aead_id == HpkeAead::AES_128_GCM
                })
        };
        let x25519 = classical_suite(HpkeKem::DHKEM_X25519_HKDF_SHA256)
            .or_else(|| classical_suite(HpkeKem::DHKEM_P256_HKDF_SHA256))
            .unwrap();
        let x_wing = write_config(&dir, 0x31, &pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256);
        let classical = write_config(&dir, 0x32, x25519);
        let published = list(&[&x_wing, &classical]);
        assert!(is_post_quantum_kem(kem_id(&x_wing).unwrap()));
        assert!(!is_post_quantum_kem(kem_id(&classical).unwrap()));

        let (status, name) = connect(&dir, &published, suites());
        assert_eq!(
            (status, name.as_deref()),
            (EchStatus::Accepted, Some(INNER))
        );
        let (status, name) = connect(
            &dir,
            &published,
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        );
        assert_eq!(
            (status, name.as_deref()),
            (EchStatus::Accepted, Some(INNER))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A rejection offers what DNS publishes: the configs in
    /// ech-config-list.bin, or without one the newest of each KEM. The older
    /// generations still open offers sealed to them, and are never offered.
    #[test]
    fn retry_configs_are_the_published_configs() {
        // P-256: a FIPS build (--all-features) has no X25519 HPKE suite
        let p256 = *rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
            .iter()
            .find(|h| h.suite().kem == HpkeKem::DHKEM_P256_HKDF_SHA256)
            .unwrap();
        let dir = scratch("current");
        let old = write_config(&dir, 0x10, p256);
        let new = write_config(&dir, 0x11, p256);
        // ech-keygen's order: the older generation's file is older
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(dir.join("10.ech"))
            .unwrap()
            .set_modified(past)
            .unwrap();
        let ids = |dir: &std::path::Path| -> Vec<u8> {
            load_from(dir)
                .unwrap()
                .retry_configs()
                .iter()
                .map(|c| match c {
                    EchConfigPayload::V18(c) => c.key_config.config_id,
                    EchConfigPayload::Unknown { version, .. } => {
                        panic!("expected a V18 config, got version {version:?}")
                    }
                })
                .collect()
        };
        assert_eq!(ids(&dir), vec![0x11], "no list: the newest of the KEM");
        std::fs::write(dir.join("ech-config-list.bin"), list(&[&old])).unwrap();
        assert_eq!(ids(&dir), vec![0x10], "the list decides");
        std::fs::write(dir.join("ech-config-list.bin"), list(&[&new, &old])).unwrap();
        assert_eq!(ids(&dir), vec![0x11, 0x10]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The QUIC side of a rotation: an endpoint holding the configs it
    /// started with refuses one rotated in after, and accepts it once the
    /// rebuilt TLS config is installed (`quic_listener::install_crypto`, what
    /// every QUIC listener runs on a TLS reload). Until 2026-10-20 nothing
    /// installed it: HTTP/3 refused the configs DNS published until a restart.
    #[tokio::test]
    async fn a_rotated_config_reaches_a_running_quic_endpoint() {
        use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};

        let (cert, key) = certificate();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let quic_crypto = |dir: &std::path::Path| {
            let mut config = ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key.clone_key())
                .unwrap();
            config.alpn_protocols = vec![b"h3".to_vec()];
            config.ech = load_from(dir);
            assert!(config.ech.is_some());
            Arc::new(QuicServerConfig::try_from(config).unwrap())
        };
        let before = scratch("quic-before");
        write_config(&before, 0x41, &pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256);
        let after = scratch("quic-after");
        let rotated = write_config(&after, 0x42, &pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256);

        let template = quinn::ServerConfig::with_crypto(quic_crypto(&before));
        let server =
            quinn::Endpoint::server(template.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let accepting = server.clone();
        let names = tokio::spawn(async move {
            let mut names = Vec::new();
            while let Some(incoming) = accepting.accept().await {
                names.push(incoming.await.ok().and_then(|conn| {
                    conn.handshake_data()?
                        .downcast::<HandshakeData>()
                        .ok()?
                        .server_name
                }));
            }
            names
        });

        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let ech = EchConfig::new(
            EchConfigListBytes::from(list(&[&rotated])),
            &pqcrypta_hpke_pq::ALL_SUPPORTED_SUITES,
        )
        .unwrap();
        let mut client_crypto = ClientConfig::builder_with_provider(provider.clone())
            .with_ech(EchMode::Enable(ech))
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_crypto).unwrap(),
        )));
        let connect = || async {
            let conn = client.connect(addr, INNER).unwrap().await.ok()?;
            conn.close(0u32.into(), b"");
            Some(())
        };

        // The startup configs: config 0x42 is unknown here, ECH is refused
        assert!(connect().await.is_none());
        crate::quic_listener::install_crypto(&server, &template, quic_crypto(&after));
        assert!(connect().await.is_some());

        server.close(0u32.into(), b"");
        client.wait_idle().await;
        let names = names.await.unwrap();
        // The refused handshake never completed; the accepted one was for the
        // name ECH carried encrypted
        assert_eq!(names.last(), Some(&Some(INNER.to_string())));
        std::fs::remove_dir_all(&before).unwrap();
        std::fs::remove_dir_all(&after).unwrap();
    }
}
