use alloc::vec::Vec;
use core::ops::Range;

use crate::crypto::hpke::{Hpke, HpkePrivateKey};
use crate::enums::EchClientHelloType;
use crate::error::InvalidMessage;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{
    ClientHelloPayload, EchConfigContents, EchConfigPayload, EncryptedClientHello,
    HpkeSymmetricCipherSuite,
};
use crate::{EncryptedClientHelloError, Error};

/// A single server-side Encrypted Client Hello configuration: a real ECHConfig
/// (the same structure published via DNS) paired with the HPKE private key
/// that corresponds to its public key. The server holds one or more of these
/// (typically the currently-published one plus one or more recent
/// predecessors, since clients may cache DNS records past their TTL).
#[derive(Clone, Debug)]
pub struct ServerEchConfig {
    pub(crate) contents: EchConfigContents,
    pub(crate) suite: &'static dyn Hpke,
    pub(crate) private_key: HpkePrivateKey,
}

impl ServerEchConfig {
    /// Construct a `ServerEchConfig` from the wire bytes of a single `ECHConfig`
    /// structure (version + length + contents - the same per-entry format used
    /// inside the `ECHConfigList` published via a DNS HTTPS record's `ech=`
    /// parameter, and what an ECHConfig-generation tool emits for one keypair)
    /// and the HPKE private key corresponding to its `key_config.public_key`.
    ///
    /// `hpke_suites` should be the set of `Hpke` implementations the caller is
    /// willing to use (e.g. `rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`)
    /// - this mirrors the client-side `EchConfig::new` constructor exactly, for
    /// the same reason: the config's `key_config.kem_id` must match a suite the
    /// local HPKE provider actually implements.
    ///
    /// Takes raw bytes (rather than a pre-parsed type) for the same reason the
    /// client-side constructor does: the parsed `ECHConfig` wire-format types
    /// are crate-internal, so this is the only reachable construction path
    /// from outside the crate.
    pub fn new(
        ech_config: &[u8],
        private_key: HpkePrivateKey,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let contents = match EchConfigPayload::read(&mut Reader::init(ech_config)).map_err(
            |_| Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList),
        )? {
            EchConfigPayload::V18(contents) => contents,
            EchConfigPayload::Unknown { .. } => {
                return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
            }
        };

        let kem_id = contents.key_config.kem_id;
        let suite = contents
            .key_config
            .symmetric_cipher_suites
            .iter()
            .find_map(|sym| {
                hpke_suites
                    .iter()
                    .find(|hpke| hpke.suite().kem == kem_id && hpke.suite().sym == *sym)
            })
            .ok_or(EncryptedClientHelloError::NoCompatibleConfig)?;

        Ok(Self {
            contents,
            suite: *suite,
            private_key,
        })
    }

    /// The `config_id` this config's `EncryptedClientHelloOuter` extensions
    /// will carry.
    pub fn config_id(&self) -> u8 {
        self.contents.key_config.config_id
    }

    /// Serialize this config back into the same raw `ECHConfig` wire format
    /// (version + length + contents) it was constructed from - the structure
    /// to base64-encode and publish as a DNS HTTPS record's `ech=` parameter
    /// (wrapped in the 2-byte `ECHConfigList` length prefix alongside any
    /// other currently-accepted configs).
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.to_ech_config_payload().encode(&mut bytes);
        bytes
    }

    fn to_ech_config_payload(&self) -> EchConfigPayload {
        EchConfigPayload::V18(self.contents.clone())
    }

    /// Compute the HPKE `SetupBaseR` `info` parameter for this config -
    /// mirrors the client's `EchConfig::hpke_info` exactly (same "tls ech" ||
    /// 0x00 || ECHConfig construction, required to match for HPKE to agree).
    fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(b"tls ech\0");
        self.to_ech_config_payload().encode(&mut info);
        info
    }
}

/// The full set of ECH configurations a server is willing to accept.
#[derive(Clone, Debug, Default)]
pub struct ServerEchConfigs(pub(crate) Vec<ServerEchConfig>);

impl ServerEchConfigs {
    /// Construct from one or more [`ServerEchConfig`]s. The first is treated
    /// as the "current" config for the purposes of building `retry_configs`.
    pub fn new(configs: Vec<ServerEchConfig>) -> Result<Self, Error> {
        if configs.is_empty() {
            return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
        }
        Ok(Self(configs))
    }

    /// The `EchConfigPayload`s to advertise in `retry_configs` when ECH
    /// wasn't successfully used - i.e. the real, current, up-to-date configs.
    pub(crate) fn retry_configs(&self) -> Vec<EchConfigPayload> {
        self.0
            .iter()
            .map(ServerEchConfig::to_ech_config_payload)
            .collect()
    }
}

/// The outcome of ECH extension processing for the current connection,
/// stashed on `ServerConnectionData` (mirroring how `sni` is already
/// threaded there) so later handshake stages - building ServerHello and
/// EncryptedExtensions, in `server::tls13` - can react to it without
/// re-deriving or re-threading the whole `ClientHelloPayload` through
/// every intervening function signature.
#[derive(Clone, Copy, Debug, Default)]
pub(super) enum EchStatus {
    /// No `encrypted_client_hello` extension was present.
    #[default]
    NotOffered,
    /// An `encrypted_client_hello` extension was present but could not be
    /// decrypted against any configured key. `retry_configs` should be
    /// included in EncryptedExtensions per draft-ietf-tls-esni-25 7.1.1.
    Rejected,
    /// ECH was successfully decrypted and the handshake is proceeding with
    /// the reconstructed ClientHelloInner. Carries that inner hello's
    /// `random`, needed to derive the ServerHello acceptance confirmation
    /// (section 7.2).
    Accepted { client_hello_inner_random: [u8; 32] },
}

/// Outcome of attempting to process an `encrypted_client_hello` extension on
/// an incoming ClientHello.
pub(crate) enum EchResolution {
    /// No `encrypted_client_hello` extension was present at all - proceed
    /// with a normal (non-ECH) handshake.
    NotOffered,
    /// A real "outer" ECH extension was present and successfully decrypted
    /// and reconstructed into a real inner `ClientHelloPayload`, ready to
    /// substitute in place of the received one. The `Vec<u8>` is that same
    /// hello's exact reconstructed wire body bytes (no handshake-message
    /// header) - preserved alongside the parsed form because it is *not*
    /// generally reproducible by re-encoding the parsed struct (extension
    /// order can depend on `ClientExtensions::order_seed`, which is
    /// generation-time-only metadata with no wire representation), and the
    /// transcript this hello feeds into must match the client's own
    /// byte-for-byte.
    Accepted(ClientHelloPayload, Vec<u8>),
    /// A real "outer" ECH extension was present but couldn't be decrypted
    /// against any configured `ServerEchConfig` (wrong/stale config_id,
    /// tampered ciphertext, or a GREASE ECH extension from a client with no
    /// real config). Per draft-ietf-tls-esni-25 section 7.1 this is NOT an
    /// error - the server must fail open and continue with the outer hello,
    /// offering `retry_configs` so a real client can retry correctly.
    Rejected,
}

/// Attempt to locate, decrypt, and reconstruct a real ClientHelloInner from
/// an incoming (already header-stripped, already-parsed) ClientHelloOuter.
///
/// `raw_body` is the *exact* wire bytes of just the ClientHello body (i.e.
/// what `ClientHelloPayload::read` consumes - no handshake-message header),
/// needed because the AAD must be computed from the literal bytes as
/// received, not a re-encoding of the parsed struct (re-encoding can silently
/// drop unrecognized extensions and does not preserve the original
/// extension ordering, which would make every real ECH connection fail the
/// AEAD tag check).
pub(crate) fn resolve(
    configs: &ServerEchConfigs,
    outer_hello: &ClientHelloPayload,
    raw_body: &[u8],
) -> EchResolution {
    let Some(EncryptedClientHello::Outer(ext)) = &outer_hello.encrypted_client_hello else {
        return EchResolution::NotOffered;
    };

    let payload_range = match find_extension_entry(raw_body, ExtensionType::EncryptedClientHello)
        .and_then(|found| match found {
            Some(range) => ech_outer_payload_range(raw_body, range),
            None => Ok(None),
        }) {
        Ok(Some(range)) => range,
        // Structurally malformed ECH extension - can't compute a correct AAD,
        // so there is nothing to trial-decrypt against. Fail open per spec.
        Ok(None) | Err(_) => return EchResolution::Rejected,
    };

    let aad = {
        let mut aad = raw_body.to_vec();
        aad[payload_range].fill(0);
        aad
    };

    // Trial decryption: try the config whose config_id matches first (the
    // spec's recommended method, since it's the only way this scales), but
    // fall through to trying every other configured key too - a stale
    // client-cached DNS record could carry an ID that no longer exists
    // locally, and there is nothing more we can do at that point anyway
    // except correctly reject.
    let mut candidates: Vec<&ServerEchConfig> = configs
        .0
        .iter()
        .filter(|c| c.config_id() == ext.config_id)
        .collect();
    candidates.extend(configs.0.iter().filter(|c| c.config_id() != ext.config_id));

    for config in candidates {
        if !config
            .contents
            .key_config
            .symmetric_cipher_suites
            .contains(&ext.cipher_suite)
        {
            continue;
        }
        let Ok(decrypted) = config.suite.open(
            &crate::crypto::hpke::EncapsulatedSecret(ext.enc.0.clone()),
            &config.hpke_info(),
            &aad,
            &ext.payload.0,
            &config.private_key,
        ) else {
            continue;
        };

        return match reconstruct_inner_hello(raw_body, &decrypted) {
            Ok((inner, wire)) => EchResolution::Accepted(inner, wire),
            // Decrypted successfully but the plaintext wasn't a well-formed
            // EncodedClientHelloInner - per spec this is still just a failed
            // candidate, not a protocol error (an attacker could otherwise
            // use malformed-plaintext responses as a decryption oracle).
            Err(_) => continue,
        };
    }

    EchResolution::Rejected
}

/// Structurally walk a ClientHello body's extensions block (client_version
/// through the end of the extensions list - as found in both a real,
/// on-the-wire ClientHelloOuter, and a decrypted-but-still-padded
/// `EncodedClientHelloInner`) and return the extensions sub-`Reader`
/// together with its absolute byte offset within `raw`.
///
/// Deliberately does not use content/substring search anywhere in this
/// module for locating structure within untrusted bytes - every field
/// walked reuses the crate's own existing `Codec` implementation for that
/// field's type, so offsets can't drift from how the rest of the crate
/// actually parses the same bytes, and can't be confused by attacker-chosen
/// bytes appearing elsewhere in the message.
fn client_hello_extensions_block(raw: &[u8]) -> Result<(usize, Reader<'_>), InvalidMessage> {
    use crate::CipherSuite;
    use crate::ProtocolVersion;
    use crate::msgs::enums::Compression;
    use crate::msgs::handshake::{Random, SessionId};

    let mut r = Reader::init(raw);
    ProtocolVersion::read(&mut r)?;
    Random::read(&mut r)?;
    SessionId::read(&mut r)?;
    Vec::<CipherSuite>::read(&mut r)?;
    Vec::<Compression>::read(&mut r)?;

    let ext_total_len = u16::read(&mut r)? as usize;
    let start = r.used();
    let ext_r = r.sub(ext_total_len)?;
    Ok((start, ext_r))
}

/// Find the absolute byte range (within `raw`) of the *entire* wire entry
/// (2-byte type + 2-byte length + value) for the first extension of type
/// `want`, within a ClientHello body's extensions block.
fn find_extension_entry(
    raw: &[u8],
    want: ExtensionType,
) -> Result<Option<Range<usize>>, InvalidMessage> {
    let (ext_block_start, mut ext_r) = client_hello_extensions_block(raw)?;

    while ext_r.any_left() {
        let entry_start = ext_block_start + ext_r.used();
        let ty = ExtensionType::read(&mut ext_r)?;
        let len = u16::read(&mut ext_r)? as usize;
        ext_r.sub(len)?;
        let entry_end = ext_block_start + ext_r.used();

        if ty == want {
            return Ok(Some(entry_start..entry_end));
        }
    }

    Ok(None)
}

/// Given the absolute range (within `raw_body`) of a whole
/// `encrypted_client_hello` extension entry (as found by
/// `find_extension_entry`), parse just enough of its value to find the
/// absolute byte range of its `payload` field's *data* (after that field's
/// own 2-byte length prefix) - the portion the AAD must have zeroed.
fn ech_outer_payload_range(
    raw_body: &[u8],
    entry_range: Range<usize>,
) -> Result<Option<Range<usize>>, InvalidMessage> {
    let mut r = Reader::init(&raw_body[entry_range.clone()]);
    ExtensionType::read(&mut r)?;
    let len = u16::read(&mut r)? as usize;
    let mut val_r = r.sub(len)?;

    // Only an "outer" ECHClientHello carries a payload to locate; an
    // "inner" one (which should never legitimately arrive directly over the
    // wire) has no payload field at all.
    if EchClientHelloType::read(&mut val_r)? != EchClientHelloType::ClientHelloOuter {
        return Ok(None);
    }
    HpkeSymmetricCipherSuite::read(&mut val_r)?;
    u8::read(&mut val_r)?; // config_id
    // enc: PayloadU16 - consume its own length prefix + data wholesale.
    let enc_len = u16::read(&mut val_r)? as usize;
    val_r.sub(enc_len)?;

    // payload: PayloadU16<NonEmpty> - we want the range of its data, *after*
    // its own 2-byte length prefix.
    let payload_len = u16::read(&mut val_r)? as usize;
    let payload_rel_start = val_r.used();
    let value_start = entry_range.start + r.used() - len; // start of the value region within raw_body
    let absolute_start = value_start + payload_rel_start;
    Ok(Some(absolute_start..absolute_start + payload_len))
}

/// Reconstruct a real `ClientHelloInner` from the HPKE-decrypted
/// `EncodedClientHelloInner` bytes, per draft-ietf-tls-esni-25 section 5.1,
/// returning both the parsed form and its exact reconstructed wire body
/// bytes (see `EchResolution::Accepted`'s doc comment for why both).
///
/// The wire layout of `EncodedClientHelloInner` itself is identical to a
/// normal ClientHello body (confirmed against
/// `ClientHelloPayload::payload_encode`'s `Encoding::EchInnerHello` case),
/// but per section 6.1.3 the HPKE-encrypted plaintext is the encoded inner
/// hello followed by *unmarked* zero padding out to a target length, and its
/// `session_id` is mandatorily empty (the real value is never part of the
/// encrypted bytes at all) - so this cannot be handed directly to
/// `ClientHelloPayload::read`. Instead:
///
/// 1. Any `ech_outer_extensions` compression marker is located and replaced,
///    in place, with the *real* extensions it references, copied verbatim
///    (whole wire entries) from the outer hello's own raw bytes - not
///    re-derived from parsed values, since a compressed extension's value is
///    defined to be byte-identical to the outer's, so copying the literal
///    bytes is both correct and exact. This also proves out byte-for-byte:
///    the client's own encoding of the (uncompressed) inner hello for
///    transcript purposes orders extensions via the same
///    `order_seed`-driven scheme used for the *compressed* encoding (the
///    seed is generation-time-only metadata a receiver can never recover),
///    with the compressed block and the marker occupying the same relative
///    position - so leaving everything else exactly as physically ordered
///    in the decrypted bytes, and only substituting the marker's own byte
///    range, reproduces the client's transcript bytes exactly without ever
///    needing to know that seed.
/// 2. `session_id` is substituted for the outer hello's real one.
/// 3. The (framing-only) padding is simply not included in the rebuilt
///    buffer at all, since it sits past the extensions block's own declared
///    length and this rebuild only ever copies bounded sub-ranges.
fn reconstruct_inner_hello(
    outer_raw_body: &[u8],
    decrypted: &[u8],
) -> Result<(ClientHelloPayload, Vec<u8>), InvalidMessage> {
    use crate::msgs::handshake::SessionId;

    let mut r = Reader::init(decrypted);
    let cv_random_start = r.used();
    crate::ProtocolVersion::read(&mut r)?;
    crate::msgs::handshake::Random::read(&mut r)?;
    let cv_random_end = r.used();

    SessionId::read(&mut r)?; // mandatorily empty in the encrypted form; discarded

    let cs_cm_start = r.used();
    Vec::<crate::CipherSuite>::read(&mut r)?;
    Vec::<crate::msgs::enums::Compression>::read(&mut r)?;
    let cs_cm_end = r.used();

    let ext_total_len = u16::read(&mut r)? as usize;
    let ext_block_start = r.used();
    let mut ext_r = r.sub(ext_total_len)?;

    let mut marker: Option<(Range<usize>, Vec<ExtensionType>)> = None;
    while ext_r.any_left() {
        let entry_start = ext_block_start + ext_r.used();
        let ty = ExtensionType::read(&mut ext_r)?;
        let len = u16::read(&mut ext_r)? as usize;
        let mut val_r = ext_r.sub(len)?;
        let entry_end = ext_block_start + ext_r.used();

        if ty == ExtensionType::EncryptedClientHelloOuterExtensions {
            marker = Some((entry_start..entry_end, Vec::<ExtensionType>::read(&mut val_r)?));
            break;
        }
    }

    let mut spliced_extensions = Vec::with_capacity(ext_total_len);
    match &marker {
        Some((marker_range, refs)) => {
            spliced_extensions.extend_from_slice(&decrypted[ext_block_start..marker_range.start]);
            for ext_type in refs {
                let entry_range = find_extension_entry(outer_raw_body, *ext_type)?.ok_or(
                    InvalidMessage::MissingData("ECHOuterExtensions reference not in outer hello"),
                )?;
                spliced_extensions.extend_from_slice(&outer_raw_body[entry_range]);
            }
            spliced_extensions
                .extend_from_slice(&decrypted[marker_range.end..ext_block_start + ext_total_len]);
        }
        None => {
            spliced_extensions
                .extend_from_slice(&decrypted[ext_block_start..ext_block_start + ext_total_len]);
        }
    }

    let mut body = Vec::with_capacity(decrypted.len() + spliced_extensions.len());
    body.extend_from_slice(&decrypted[cv_random_start..cv_random_end]);
    // Substitute the outer hello's real session_id - read directly from its
    // raw bytes (not `outer_hello.session_id`) so this function only ever
    // depends on wire bytes, consistent with the rest of this module.
    let mut outer_r = Reader::init(outer_raw_body);
    crate::ProtocolVersion::read(&mut outer_r)?;
    crate::msgs::handshake::Random::read(&mut outer_r)?;
    SessionId::read(&mut outer_r)?.encode(&mut body);
    body.extend_from_slice(&decrypted[cs_cm_start..cs_cm_end]);
    (spliced_extensions.len() as u16).encode(&mut body);
    body.extend_from_slice(&spliced_extensions);

    let inner = ClientHelloPayload::read(&mut Reader::init(&body))?;

    Ok((inner, body))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use alloc::vec;
    use std::sync::Mutex;

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, DnsName, EchConfigListBytes, PrivateKeyDer, ServerName};

    use super::{ServerEchConfig, ServerEchConfigs};
    use crate::client::{EchConfig, EchMode, EchStatus as ClientEchStatus};
    use crate::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use crate::crypto::hpke::{Hpke, HpkeSuite};
    use crate::msgs::codec::Codec;
    use crate::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
    use crate::msgs::handshake::{
        EchConfigContents, EchConfigPayload, HpkeKeyConfig, HpkeSymmetricCipherSuite,
    };
    use crate::server::{ClientHello, ResolvesServerCert};
    use crate::sign::CertifiedKey;
    use crate::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};

    /// A real X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM keypair, wrapped in a
    /// real, wire-encoded `ECHConfig` (server-side format) and the matching
    /// `ECHConfigList` (client-side format, i.e. what would be published to
    /// DNS) - both derived from the *same* key material, so a real client
    /// built from the list bytes and a real server built from the config
    /// bytes can actually decrypt each other's messages.
    struct TestEchKeypair {
        server_config: ServerEchConfig,
        client_config_list: EchConfigListBytes<'static>,
    }

    fn make_ech_keypair(config_id: u8, public_name: &str) -> TestEchKeypair {
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
            .expect("aws-lc-rs must support X25519/HKDF-SHA256/AES-128-GCM");
        let (public_key, private_key) = suite
            .generate_key_pair()
            .expect("HPKE key generation must succeed");

        let contents = EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id,
                kem_id: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                public_key: crate::msgs::base::PayloadU16::new(public_key.0),
                symmetric_cipher_suites: vec![HpkeSymmetricCipherSuite {
                    kdf_id: HpkeKdf::HKDF_SHA256,
                    aead_id: HpkeAead::AES_128_GCM,
                }],
            },
            maximum_name_length: 0,
            public_name: DnsName::try_from(public_name)
                .unwrap()
                .to_owned(),
            extensions: vec![],
        };

        let mut single_config_bytes = Vec::new();
        EchConfigPayload::V18(contents.clone()).encode(&mut single_config_bytes);

        let mut list_bytes = Vec::new();
        vec![EchConfigPayload::V18(contents)].encode(&mut list_bytes);

        let server_config = ServerEchConfig::new(&single_config_bytes, private_key, &[suite])
            .expect("constructing ServerEchConfig from our own freshly-generated config must succeed");

        TestEchKeypair {
            server_config,
            client_config_list: EchConfigListBytes::from(list_bytes),
        }
    }

    fn test_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let chain = vec![
            CertificateDer::from(
                &include_bytes!("../../../test-ca/ecdsa-p256/end.der")[..],
            ),
            CertificateDer::from(
                &include_bytes!("../../../test-ca/ecdsa-p256/inter.der")[..],
            ),
        ];
        let key = PrivateKeyDer::from_pem_reader(
            &mut include_bytes!("../../../test-ca/ecdsa-p256/end.key").as_slice(),
        )
        .unwrap();
        (chain, key)
    }

    fn test_roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_slice(include_bytes!(
                "../../../test-ca/ecdsa-p256/ca.der"
            )))
            .unwrap();
        roots
    }

    /// A cert resolver that always resolves to the same real, valid cert
    /// (whose SANs cover every name used in these tests), but records the SNI
    /// it was asked to resolve for - so tests can assert on *which* SNI (the
    /// real, ECH-protected inner one, or the ECH `public_name` outer one)
    /// actually reached certificate resolution.
    #[derive(Debug)]
    struct RecordingResolver {
        key: Arc<CertifiedKey>,
        seen_sni: Arc<Mutex<Option<String>>>,
    }

    impl ResolvesServerCert for RecordingResolver {
        fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            *self.seen_sni.lock().unwrap() = client_hello.server_name().map(String::from);
            Some(self.key.clone())
        }
    }

    fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
        let mut buf = Vec::new();
        for _ in 0..20 {
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }

            buf.clear();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets().unwrap();
            }

            buf.clear();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                client.process_new_packets().unwrap();
            }
        }

        assert!(!client.is_handshaking(), "handshake did not complete");
        assert!(!server.is_handshaking(), "handshake did not complete");
    }

    /// The core correctness claim of this whole module: a real client, using
    /// only rustls's already-shipped client-side ECH support, completes a
    /// real in-memory handshake against our new server-side ECH support, the
    /// server correctly decrypts and reconstructs ClientHelloInner (proven by
    /// the *inner*, ECH-protected SNI - not the outer `public_name` - being
    /// what reaches certificate resolution), and the client's own acceptance
    /// check (an independent, pre-existing implementation this new code never
    /// touches) confirms acceptance via the ServerHello confirmation value
    /// this code computes and splices in.
    #[test]
    fn ech_round_trip_accepted() {
        let keypair = make_ech_keypair(0xA5, "second.testserver.com");

        let (chain, key) = test_cert_and_key();
        let signing_key = crate::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        let seen_sni = Arc::new(Mutex::new(None));
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: seen_sni.clone(),
        });

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ech = Some(Arc::new(
            ServerEchConfigs::new(vec![keypair.server_config]).unwrap(),
        ));

        let ech_config = EchConfig::new(keypair.client_config_list, ALL_SUPPORTED_SUITES).unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            crate::crypto::aws_lc_rs::default_provider(),
        ))
        .with_ech(EchMode::Enable(ech_config))
        .unwrap()
        .with_root_certificates(test_roots())
        .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("testserver.com").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        do_handshake(&mut client, &mut server);

        assert_eq!(client.ech_status(), ClientEchStatus::Accepted);
        assert_eq!(
            seen_sni.lock().unwrap().as_deref(),
            Some("testserver.com"),
            "cert resolution must see the real, ECH-protected inner SNI, not the outer public_name"
        );
    }

    /// When the client's ECH offer can't be decrypted (here: encrypted under
    /// a key the server never configured, standing in for a stale/incorrect
    /// cached config) the *server* must fail open per draft-ietf-tls-esni-25
    /// 7.1.1: it proceeds using ClientHelloOuter (whose SNI is the ECH
    /// `public_name`) and returns `retry_configs` in EncryptedExtensions,
    /// rather than aborting outright. Cert resolution happens early enough
    /// in the server's flow (before ServerHello is even built) that this is
    /// independently observable regardless of what the client does next.
    ///
    /// The *client*, on the other hand, must NOT silently keep using this
    /// connection once it independently confirms the offer was rejected
    /// (rustls's pre-existing, unmodified `confirm_acceptance`) - doing so
    /// would let a network attacker downgrade a real ECH connection to a
    /// plain one without either endpoint's application code ever finding
    /// out. So the expected end-to-end outcome here is that the server
    /// completes its side of the flight, but the client hard-errors with
    /// `PeerIncompatible(ServerRejectedEncryptedClientHello(retry_configs))`
    /// instead of completing the connection - real client applications are
    /// expected to open a fresh connection using those `retry_configs`.
    #[test]
    fn ech_round_trip_rejected_falls_back() {
        let server_keypair = make_ech_keypair(0x01, "second.testserver.com");
        let mismatched_client_keypair = make_ech_keypair(0x01, "second.testserver.com");

        let (chain, key) = test_cert_and_key();
        let signing_key = crate::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        let seen_sni = Arc::new(Mutex::new(None));
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: seen_sni.clone(),
        });

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ech = Some(Arc::new(
            ServerEchConfigs::new(vec![server_keypair.server_config]).unwrap(),
        ));

        // The client is handed the *mismatched* keypair's public config, so
        // it will encrypt ClientHelloInner using a key the server has no
        // matching private key for.
        let ech_config = EchConfig::new(
            mismatched_client_keypair.client_config_list,
            ALL_SUPPORTED_SUITES,
        )
        .unwrap();
        let client_config = ClientConfig::builder_with_provider(Arc::new(
            crate::crypto::aws_lc_rs::default_provider(),
        ))
        .with_ech(EchMode::Enable(ech_config))
        .unwrap()
        .with_root_certificates(test_roots())
        .with_no_client_auth();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("testserver.com").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        // Drive the handshake manually (rather than via `do_handshake`,
        // which asserts success): the server completes its flight, but the
        // client is expected to hard-error partway through processing it.
        let mut buf = Vec::new();
        let mut client_err = None;
        for _ in 0..20 {
            if client_err.is_some() || (!client.is_handshaking() && !server.is_handshaking()) {
                break;
            }

            buf.clear();
            client.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                server.read_tls(&mut &buf[..]).unwrap();
                server.process_new_packets().unwrap();
            }

            buf.clear();
            server.write_tls(&mut buf).unwrap();
            if !buf.is_empty() {
                client.read_tls(&mut &buf[..]).unwrap();
                if let Err(e) = client.process_new_packets() {
                    client_err = Some(e);
                }
            }
        }

        match client_err {
            Some(crate::Error::PeerIncompatible(
                crate::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(retry_configs)),
            )) => {
                assert!(
                    !retry_configs.is_empty(),
                    "server must offer retry_configs so a real client can retry correctly"
                );
            }
            other => panic!(
                "expected the client to hard-error with ServerRejectedEncryptedClientHello, got {other:?}"
            ),
        }

        assert_eq!(
            seen_sni.lock().unwrap().as_deref(),
            Some("second.testserver.com"),
            "on fallback, cert resolution must see the outer public_name, not the (undeliverable) real inner SNI"
        );
    }
}
