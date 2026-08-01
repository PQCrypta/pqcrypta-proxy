//! Generates a fresh Encrypted Client Hello (ECH, draft-ietf-tls-esni-25)
//! HPKE keypair and wraps it into a real, publishable `ECHConfig`.
//!
//! Meant to be run periodically (see `scripts/ech-rotate.sh` /
//! `ech-rotate.timer`), not by hand in normal operation - each run adds one
//! new config to `--out-dir` and keeps the most recent `--retain` around
//! (older ones are deleted) so clients that cached a previous DNS record
//! past its TTL can still complete ECH against the config it named. The
//! proxy itself reads every retained config back out of `--out-dir` at
//! startup (see `ech_config::load` in the main crate).
//!
//! Uses `rustls::internal::msgs::*` - explicitly `#[doc(hidden)]` and
//! "DOES NOT form part of the stable interface" per its own doc comment,
//! but it's the only way to construct an `ECHConfig` from outside the
//! rustls crate itself (the parsed wire-format types are otherwise
//! crate-internal); this module already existed upstream for exactly this
//! kind of tooling/test use, it isn't something this fork added.

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use clap::Parser;
use rand::RngCore;
use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use rustls::crypto::hpke::{Hpke, HpkeSuite};
use rustls::internal::msgs::base::PayloadU16;
use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::{
    EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
};
use rustls::pki_types::DnsName;

#[derive(Parser)]
struct Args {
    /// Directory holding one `<config_id>.key` (private, mode 600) and
    /// `<config_id>.ech` (public wire bytes, mode 644) pair per retained
    /// generation, plus the assembled `ech-config-list.{bin,b64}` for DNS
    /// publishing.
    #[arg(long, default_value = "/etc/pqcrypta/ech-configs")]
    out_dir: PathBuf,

    /// The ECH "cover name" sent in the clear (`ClientHelloOuter`'s SNI) -
    /// must be a name this server has a real certificate for, since a
    /// GREASE/non-ECH-aware or ECH-rejecting client's connection is
    /// completed against it.
    #[arg(long, default_value = "pqcrypta.com")]
    public_name: String,

    /// Upper bound `L` used for `ClientHelloInner` padding (section 6.1.3) -
    /// should be at least as long as the longest real hostname this server
    /// answers for via ECH, so padding doesn't leak a length signal.
    #[arg(long, default_value_t = 32)]
    max_name_length: u8,

    /// How many of the most recent generations to keep (including the one
    /// just created). Older ones are deleted. Clients cache DNS records
    /// past their nominal TTL in practice, so this should span at least a
    /// couple of real rotation intervals.
    #[arg(long, default_value_t = 3)]
    retain: usize,
}

fn main() {
    let args = Args::parse();

    let suite: &'static dyn Hpke = *ALL_SUPPORTED_SUITES
        .iter()
        .find(|h| {
            h.suite()
                == HpkeSuite {
                    kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                    sym: HpkeSymmetricCipherSuite {
                        kdf_id: HpkeKdf::HKDF_SHA256,
                        aead_id: HpkeAead::AES_128_GCM,
                    },
                }
        })
        .expect("aws-lc-rs must support the mandatory-to-implement X25519/HKDF-SHA256/AES-128-GCM HPKE suite");

    let (public_key, private_key) = suite
        .generate_key_pair()
        .expect("HPKE key generation must succeed");

    fs::create_dir_all(&args.out_dir).expect("failed to create --out-dir");
    let config_id = pick_unused_config_id(&args.out_dir);

    let contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id,
            kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            public_key: PayloadU16::new(public_key.0),
            symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: HpkeAead::AES_128_GCM,
            }],
        },
        maximum_name_length: args.max_name_length,
        public_name: DnsName::try_from(args.public_name.clone())
            .expect("--public-name must be a valid DNS name"),
        extensions: Vec::new(),
    };

    let mut entry_bytes = Vec::new();
    EchConfigPayload::V18(contents).encode(&mut entry_bytes);

    let key_path = args.out_dir.join(format!("{config_id:02x}.key"));
    fs::write(&key_path, private_key.secret_bytes()).expect("failed to write private key");
    // Unix mode bits have no Windows equivalent; PermissionsExt::from_mode does
    // not exist there, which broke the windows-latest build. On Windows the
    // files inherit the directory ACL instead — the operator is responsible for
    // the ACL on out_dir, exactly as they are for its 0700 on Unix.
    #[cfg(unix)]
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
        .expect("failed to chmod private key");

    let ech_path = args.out_dir.join(format!("{config_id:02x}.ech"));
    fs::write(&ech_path, &entry_bytes).expect("failed to write ECHConfig entry");
    #[cfg(unix)]
    fs::set_permissions(&ech_path, fs::Permissions::from_mode(0o644))
        .expect("failed to chmod ECHConfig entry");

    println!(
        "generated config_id=0x{config_id:02x} -> {}",
        ech_path.display()
    );

    prune_and_rebuild_list(&args.out_dir, args.retain);
}

/// Config IDs only need to be unique among currently-*retained* configs (a
/// client's cached extension names the ID it encrypted under, and the
/// server picks the matching key by ID first - see `server::ech::resolve`)
/// - collisions here would make a stale client pick the wrong (newly
///   rotated-in) key and fail decryption, so this reads whatever `.ech` files
///   are still on disk and avoids their IDs.
fn pick_unused_config_id(out_dir: &std::path::Path) -> u8 {
    let used: std::collections::HashSet<u8> = fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_str()?;
            let hex = name.strip_suffix(".ech")?;
            u8::from_str_radix(hex, 16).ok()
        })
        .collect();

    let mut rng = rand::thread_rng();
    loop {
        let candidate = (rng.next_u32() & 0xff) as u8;
        if !used.contains(&candidate) {
            return candidate;
        }
    }
}

/// Delete all but the `retain` most-recently-generated `.key`/`.ech` pairs
/// (by file mtime), then rebuild `ech-config-list.{bin,b64}` - the real
/// `ECHConfigList` structure (a 2-byte total length, then each retained
/// entry's already-encoded bytes back to back) to publish as a DNS HTTPS
/// record's `ech=` `SvcParam`.
fn prune_and_rebuild_list(out_dir: &std::path::Path, retain: usize) {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = fs::read_dir(out_dir)
        .expect("failed to read --out-dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("ech"))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    entries.sort_by_key(|(mtime, _)| *mtime);

    while entries.len() > retain {
        let (_, ech_path) = entries.remove(0);
        let key_path = ech_path.with_extension("key");
        println!("pruning expired config: {}", ech_path.display());
        let _ = fs::remove_file(&ech_path);
        let _ = fs::remove_file(&key_path);
    }

    let mut list_bytes = Vec::new();
    let entries_bytes: Vec<Vec<u8>> = entries
        .iter()
        .map(|(_, path)| fs::read(path).expect("failed to read retained ECHConfig entry"))
        .collect();
    let total_len: usize = entries_bytes.iter().map(Vec::len).sum();
    let total_len =
        u16::try_from(total_len).expect("ECHConfigList exceeds 65535 bytes - lower --retain");
    total_len.encode(&mut list_bytes);
    for entry in &entries_bytes {
        list_bytes.extend_from_slice(entry);
    }

    // Round-trip-parse what was just assembled as a sanity check before
    // writing it out - a malformed ECHConfigList published to DNS would
    // break ECH for every client until caught and fixed.
    let mut r = Reader::init(&list_bytes[2..]);
    let mut parsed_count = 0;
    while r.any_left() {
        EchConfigPayload::read(&mut r).expect("assembled ECHConfigList failed to round-trip parse");
        parsed_count += 1;
    }
    assert_eq!(parsed_count, entries_bytes.len());

    fs::write(out_dir.join("ech-config-list.bin"), &list_bytes)
        .expect("failed to write ech-config-list.bin");
    let b64 = base64_engine.encode(&list_bytes);
    fs::write(out_dir.join("ech-config-list.b64"), &b64)
        .expect("failed to write ech-config-list.b64");

    println!(
        "retained {} config(s); ECHConfigList ({} bytes) -> {}",
        entries.len(),
        list_bytes.len(),
        out_dir.join("ech-config-list.b64").display()
    );
    println!("DNS HTTPS record ech= value:\n{b64}");
}
