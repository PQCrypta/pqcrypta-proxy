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

use pqcrypta_proxy::ech_config::{kem_id, publication_order};

/// The KEM a new config's key is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Kem {
    /// X-Wing (ML-KEM-768 + X25519, 0x647A): post-quantum, published first.
    XWing,
    /// DHKEM(X25519, HKDF-SHA256) (0x0020): what every ECH client implements
    /// today, browsers included.
    X25519,
}

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

    /// The KEM the new config's key is for. Run once per KEM: the published
    /// list carries the post-quantum config first and the X25519 one after it,
    /// and a client uses the first it implements, so browsers keep ECH while a
    /// post-quantum client seals its inner `ClientHello` to a key a quantum
    /// computer cannot open. `--retain` counts each KEM's generations
    /// separately, so rotating one never prunes the other.
    #[arg(long, value_enum, default_value_t = Kem::XWing)]
    kem: Kem,

    /// Generate nothing: prune to `--retain` and rebuild
    /// `ech-config-list.{bin,b64}` from the configs already in `--out-dir`.
    #[arg(long)]
    list_only: bool,
}

const fn sym(kdf_id: HpkeKdf, aead_id: HpkeAead) -> HpkeSymmetricCipherSuite {
    HpkeSymmetricCipherSuite { kdf_id, aead_id }
}

fn main() {
    let args = Args::parse();
    if args.list_only {
        prune_and_rebuild_list(&args.out_dir, args.retain);
        return;
    }

    // The suite the key is generated with, the KEM the config names, and the
    // symmetric suites it advertises (the server can open every one of them:
    // `ech_config::suites` registers them all). The order is the server's
    // preference hint.
    let (suite, config_kem, symmetric): (&'static dyn Hpke, HpkeKem, Vec<HpkeSymmetricCipherSuite>) =
        match args.kem {
            Kem::XWing => (
                &pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256,
                HpkeKem::from(pqcrypta_hpke_pq::X_WING_HKDF_SHA256_AES_256.kem_id()),
                // AES-256 first: Grover halves a symmetric key, and a
                // post-quantum config should not stop at 64 bits of it
                vec![
                    sym(HpkeKdf::HKDF_SHA256, HpkeAead::AES_256_GCM),
                    sym(HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
                    sym(HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY_1305),
                ],
            ),
            Kem::X25519 => (
                *ALL_SUPPORTED_SUITES
                    .iter()
                    .find(|h| {
                        h.suite()
                            == HpkeSuite {
                                kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                sym: sym(HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
                            }
                    })
                    .expect("aws-lc-rs must support the mandatory-to-implement X25519/HKDF-SHA256/AES-128-GCM HPKE suite"),
                HpkeKem::DHKEM_X25519_HKDF_SHA256,
                // Both AEADs the server can decrypt with. AES-128-GCM first: it
                // is the mandatory-to-implement suite. ChaCha20-Poly1305 for
                // clients on hardware without AES acceleration, where it is the
                // faster and more constant-time choice.
                vec![
                    sym(HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM),
                    sym(HpkeKdf::HKDF_SHA256, HpkeAead::CHACHA20_POLY_1305),
                ],
            ),
        };

    let (public_key, private_key) = suite
        .generate_key_pair()
        .expect("HPKE key generation must succeed");

    fs::create_dir_all(&args.out_dir).expect("failed to create --out-dir");
    let config_id = pick_unused_config_id(&args.out_dir);

    let contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id,
            kem_id: config_kem,
            public_key: PayloadU16::new(public_key.0),
            symmetric_cipher_suites: symmetric,
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

/// Delete all but the `retain` most recently generated `.key`/`.ech` pairs of
/// each KEM (by file mtime), then rebuild `ech-config-list.{bin,b64}`: the
/// real `ECHConfigList` structure (a 2-byte total length, then each entry's
/// already-encoded bytes back to back) to publish as a DNS HTTPS record's
/// `ech=` `SvcParam`, holding the newest config of each KEM in publication
/// order (post-quantum first; see `ech_config::publication_order`).
///
/// Only the newest of each KEM is published. The older retained ones stay on
/// disk, so the server still opens a `ClientHello` from a client holding a
/// cached DNS record, but a client uses the first config it implements, so
/// publishing them would only grow every HTTPS answer: an X-Wing config is
/// about 1.3 KB, and the list already takes the answer past a 1,232-byte UDP
/// response with one.
fn prune_and_rebuild_list(out_dir: &std::path::Path, retain: usize) {
    let mut entries: Vec<(std::time::SystemTime, PathBuf, u16)> = fs::read_dir(out_dir)
        .expect("failed to read --out-dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("ech"))
        .filter_map(|e| {
            let kem = kem_id(&fs::read(e.path()).ok()?)?;
            Some((e.metadata().ok()?.modified().ok()?, e.path(), kem))
        })
        .collect();
    entries.sort_by_key(|(mtime, _, kem)| publication_order(*kem, *mtime));

    let mut kept_per_kem: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    entries.retain(|(_, ech_path, kem)| {
        let kept = kept_per_kem.entry(*kem).or_default();
        if *kept < retain {
            *kept += 1;
            return true;
        }
        let key_path = ech_path.with_extension("key");
        println!("pruning expired config: {}", ech_path.display());
        let _ = fs::remove_file(ech_path);
        let _ = fs::remove_file(&key_path);
        false
    });

    let mut published_kems = std::collections::HashSet::new();
    let published: Vec<&(std::time::SystemTime, PathBuf, u16)> = entries
        .iter()
        .filter(|(_, _, kem)| published_kems.insert(*kem))
        .collect();

    let mut list_bytes = Vec::new();
    let entries_bytes: Vec<Vec<u8>> = published
        .iter()
        .map(|(_, path, _)| fs::read(path).expect("failed to read retained ECHConfig entry"))
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
        "retained {} config(s) on disk; publishing the newest of each KEM, {} config(s): ECHConfigList ({} bytes) -> {}",
        entries.len(),
        published.len(),
        list_bytes.len(),
        out_dir.join("ech-config-list.b64").display()
    );
    println!("DNS HTTPS record ech= value:\n{b64}");
}
