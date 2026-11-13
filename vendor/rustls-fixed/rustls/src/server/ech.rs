use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::Range;

use crate::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey};
use crate::enums::AlertDescription;
use crate::enums::EchClientHelloType;
use crate::error::InvalidMessage;
use crate::error::PeerMisbehaved;
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
    /// An HPKE suite for each of the config's symmetric suites the provider
    /// implements, in the config's order: the client picks one of them
    /// (RFC 9849 6.1), and the offer is opened with the one it picked.
    pub(crate) suites: Vec<&'static dyn Hpke>,
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
        let contents =
            match EchConfigPayload::read(&mut Reader::init(ech_config)).map_err(|_| {
                Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList)
            })? {
                EchConfigPayload::V18(contents) => contents,
                EchConfigPayload::Unknown { .. } => {
                    return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
                }
            };

        let kem_id = contents.key_config.kem_id;
        // Every symmetric suite the config offers that can be opened here. A
        // single suite (the first) was kept before, and an offer sealed with
        // any other of the config's suites - ChaCha20-Poly1305 from a client
        // without AES hardware, say - failed to open, was rejected, failed
        // again on the retry and fell back to a cleartext ClientHello.
        let suites: Vec<&'static dyn Hpke> = contents
            .key_config
            .symmetric_cipher_suites
            .iter()
            .filter_map(|sym| {
                hpke_suites
                    .iter()
                    .find(|hpke| hpke.suite().kem == kem_id && hpke.suite().sym == *sym)
                    .copied()
            })
            .collect();
        if suites.is_empty() {
            return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
        }

        Ok(Self {
            contents,
            suites,
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
        self.to_ech_config_payload()
            .encode(&mut bytes);
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
        self.to_ech_config_payload()
            .encode(&mut info);
        info
    }
}

/// The full set of ECH configurations a server is willing to accept, and
/// which of them are current: the ones a rejection offers as
/// `retry_configs`.
#[derive(Clone, Debug, Default)]
pub struct ServerEchConfigs(pub(crate) Vec<ServerEchConfig>, Vec<usize>);

impl ServerEchConfigs {
    /// Construct from one or more [`ServerEchConfig`]s, every one of them
    /// current.
    pub fn new(configs: Vec<ServerEchConfig>) -> Result<Self, Error> {
        let all = (0..configs.len()).collect();
        Self::with_current(configs, all)
    }

    /// Construct from one or more [`ServerEchConfig`]s, of which those at
    /// `current` (in that order) are the up-to-date ones: what DNS publishes,
    /// and what a rejection offers as `retry_configs` (RFC 9849 section 7.1:
    /// "one or more ECHConfig structures with up-to-date keys"). The others
    /// are retained only to open offers sealed to an older config a resolver
    /// still caches; offering them again would hand a client a key on its way
    /// out, and every rejection - a GREASE extension included - would carry
    /// each retained generation's public key.
    pub fn with_current(configs: Vec<ServerEchConfig>, current: Vec<usize>) -> Result<Self, Error> {
        if configs.is_empty()
            || current.is_empty()
            || current
                .iter()
                .any(|i| *i >= configs.len())
        {
            return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
        }
        Ok(Self(configs, current))
    }

    /// The `EchConfigPayload`s to advertise in `retry_configs` when ECH
    /// wasn't successfully used - i.e. the real, current, up-to-date configs.
    pub fn retry_configs(&self) -> Vec<EchConfigPayload> {
        self.1
            .iter()
            .map(|i| self.0[*i].to_ech_config_payload())
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
    /// An `encrypted_client_hello` extension named a configured key but could
    /// not be opened with it (or was malformed). `retry_configs` should be
    /// included in EncryptedExtensions per draft-ietf-tls-esni-25 7.1.1.
    Rejected,
    /// An `encrypted_client_hello` extension named a `config_id` no configured
    /// key has: answered as [`EchStatus::Rejected`] is, with `retry_configs`.
    UnknownConfig,
    /// ECH was successfully decrypted and the handshake is proceeding with
    /// the reconstructed ClientHelloInner. Carries that inner hello's
    /// `random`, needed to derive the ServerHello acceptance confirmation
    /// (section 7.2).
    Accepted { client_hello_inner_random: [u8; 32] },
}

/// The server-side outcome of ECH processing, as observable by the application
/// once the handshake has progressed past the ClientHello.
///
/// This is [`EchStatus`] with the accepted inner hello's `random` dropped. That
/// field is handshake machinery feeding the acceptance-confirmation derivation;
/// it is transcript material and there is no reason to hand it out. The
/// outcome on its own is what an application can act on, as the client side's
/// `ClientConnection::ech_status` is; a rejection is split by whether the offer
/// named one of this server's keys, which only the server can know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EchAcceptance {
    /// No `encrypted_client_hello` extension was present on the ClientHello.
    NotOffered,
    /// The extension named one of the configured keys and did not open with
    /// it: a tampered or corrupted payload, or a GREASE extension whose random
    /// `config_id` happened to be one of this server's (a malformed extension
    /// is reported here too). Per draft-ietf-tls-esni-25 7.1 this is not an
    /// error: the handshake continued on the ClientHelloOuter and
    /// `retry_configs` were returned in EncryptedExtensions.
    Rejected,
    /// The extension named a `config_id` none of the configured keys has. A
    /// GREASE extension (section 6.2: a client that has no ECH configuration
    /// for this server sends one with a random `config_id`), or a config
    /// retired longer ago than the server keeps them; on the wire the two are
    /// alike. Handled as [`EchAcceptance::Rejected`] is: the handshake
    /// continued on the ClientHelloOuter with `retry_configs`.
    UnknownConfig,
    /// The extension decrypted and the handshake ran on the reconstructed
    /// ClientHelloInner, so the client's real SNI never appeared in cleartext
    /// on the wire.
    Accepted,
}

impl From<EchStatus> for EchAcceptance {
    fn from(status: EchStatus) -> Self {
        match status {
            EchStatus::NotOffered => Self::NotOffered,
            EchStatus::Rejected => Self::Rejected,
            EchStatus::UnknownConfig => Self::UnknownConfig,
            EchStatus::Accepted { .. } => Self::Accepted,
        }
    }
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
    Accepted(ClientHelloPayload, Vec<u8>, EchRetryContext),
    /// A real "outer" ECH extension named a configured `ServerEchConfig` but
    /// couldn't be opened with it (tampered ciphertext), or was malformed.
    /// Per draft-ietf-tls-esni-25 section 7.1 this is NOT an error - the
    /// server must fail open and continue with the outer hello, offering
    /// `retry_configs` so a real client can retry correctly.
    Rejected,
    /// An outer ECH extension named a `config_id` no configured
    /// `ServerEchConfig` has: GREASE, or a retired config. Handled as
    /// `Rejected` is.
    UnknownConfig,
    /// An offer that opened, but whose ClientHelloInner cannot be decoded or
    /// breaks RFC 9849's rules for it: the handshake is aborted with the
    /// alert (section 5.1: `decode_error` or `illegal_parameter`, section
    /// 7.1: `illegal_parameter`). Only a client holding the config's public
    /// key gets this far, and it chose the plaintext, so the alert tells it
    /// nothing it did not know.
    Invalid(AlertDescription, PeerMisbehaved),
}

/// The HPKE context an accepted offer opened, kept for a second ClientHello.
///
/// After a HelloRetryRequest the client offers ECH again under the same
/// context (RFC 9849 section 6.1.5): the same config and suite, an empty
/// `enc`, and the payload sealed at the context's next sequence number. Only
/// this opener can read it; a fresh decapsulation cannot.
#[derive(Debug)]
pub(crate) struct EchRetryContext {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
}

/// The ClientHello body with the ECH payload zeroed: the AAD the payload was
/// sealed under (RFC 9849 section 5.2). None for a structurally malformed
/// extension.
fn aad_for(raw_body: &[u8]) -> Option<Vec<u8>> {
    let range = find_extension_entry(raw_body, ExtensionType::EncryptedClientHello)
        .ok()?
        .and_then(|range| {
            ech_outer_payload_range(raw_body, range)
                .ok()
                .flatten()
        })?;
    let mut aad = raw_body.to_vec();
    aad[range].fill(0);
    Some(aad)
}

/// Open the second ClientHello of an accepted ECH handshake with the first's
/// context, as RFC 9849 section 7.1.1 requires: an offer that is missing,
/// that names another config or suite, that carries an `enc`, or that does
/// not open, aborts the handshake with the alert returned.
pub(crate) fn resolve_retry(
    context: &mut EchRetryContext,
    outer_hello: &ClientHelloPayload,
    raw_body: &[u8],
) -> Result<(ClientHelloPayload, Vec<u8>), (AlertDescription, PeerMisbehaved)> {
    let Some(EncryptedClientHello::Outer(ext)) = &outer_hello.encrypted_client_hello else {
        return Err((
            AlertDescription::MissingExtension,
            PeerMisbehaved::EchMissingInSecondClientHello,
        ));
    };
    if ext.config_id != context.config_id
        || ext.cipher_suite != context.cipher_suite
        || !ext.enc.0.is_empty()
    {
        return Err((
            AlertDescription::IllegalParameter,
            PeerMisbehaved::EchVariedInSecondClientHello,
        ));
    }
    let undecryptable = || {
        (
            AlertDescription::DecryptError,
            PeerMisbehaved::EchUndecryptableInSecondClientHello,
        )
    };
    let aad = aad_for(raw_body).ok_or_else(undecryptable)?;
    let decrypted = context
        .opener
        .open(&aad, &ext.payload.0)
        .map_err(|_| undecryptable())?;
    let resolved = reconstruct_inner_hello(raw_body, &decrypted)?;
    check_inner_hello(&resolved.0)?;
    Ok(resolved)
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

    // Structurally malformed ECH extension - can't compute a correct AAD,
    // so there is nothing to trial-decrypt against. Fail open per spec.
    let Some(aad) = aad_for(raw_body) else {
        return EchResolution::Rejected;
    };

    // The candidates are the configs the offer's config_id names (RFC 9849
    // section 7.1: "Unless specified by the application profile or otherwise
    // externally configured, implementations MUST use the first method").
    // Trying every other key too was trial decryption, the method a
    // deployment has to opt into: it opens nothing a stale config sealed (the
    // key behind a retired id is gone), and every GREASE ClientHello - every
    // Chrome's - cost an HPKE decapsulation per held key (section 10.4: it
    // "may exacerbate DoS attacks"). An id this server does not hold is
    // rejected at once, with retry_configs.
    let candidates = configs
        .0
        .iter()
        .filter(|c| c.config_id() == ext.config_id);
    // An id none of the configs has: nothing to try, and worth telling apart
    // from an offer to a held key that did not open.
    if candidates.clone().next().is_none() {
        return EchResolution::UnknownConfig;
    }

    for config in candidates {
        // The suite the client sealed with, if the config offers it
        let Some(suite) = config
            .suites
            .iter()
            .find(|hpke| hpke.suite().sym == ext.cipher_suite)
        else {
            continue;
        };
        // A context rather than a single-shot open: a HelloRetryRequest's
        // second ClientHello is sealed under this same context
        let Ok(mut opener) = suite.setup_opener(
            &EncapsulatedSecret(ext.enc.0.clone()),
            &config.hpke_info(),
            &config.private_key,
        ) else {
            continue;
        };
        let Ok(decrypted) = opener.open(&aad, &ext.payload.0) else {
            continue;
        };

        // Opened: from here the offer is the client's, and a ClientHelloInner
        // that cannot be decoded or breaks the rules for it ends the handshake
        // (RFC 9849 sections 5.1 and 7.1), where an offer that did not open
        // falls back to the outer hello
        let resolved = reconstruct_inner_hello(raw_body, &decrypted)
            .and_then(|resolved| check_inner_hello(&resolved.0).map(|()| resolved));
        return match resolved {
            Ok((inner, wire)) => EchResolution::Accepted(
                inner,
                wire,
                EchRetryContext {
                    opener,
                    config_id: ext.config_id,
                    cipher_suite: ext.cipher_suite,
                },
            ),
            Err((alert, why)) => EchResolution::Invalid(alert, why),
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

/// Why an opened offer's ClientHelloInner is refused: the alert, and what the
/// peer did.
type InnerRefusal = (AlertDescription, PeerMisbehaved);

fn undecodable() -> InnerRefusal {
    (
        AlertDescription::DecodeError,
        PeerMisbehaved::EchInnerHelloUndecodable,
    )
}

fn outer_extensions_refused() -> InnerRefusal {
    (
        AlertDescription::IllegalParameter,
        PeerMisbehaved::EchInnerHelloUndecodable,
    )
}

/// The whole wire entry (type, length, value) of every extension of a
/// ClientHello body, in order, as byte ranges of `raw`.
fn extension_entries(raw: &[u8]) -> Result<Vec<(ExtensionType, Range<usize>)>, InvalidMessage> {
    let (ext_block_start, mut ext_r) = client_hello_extensions_block(raw)?;
    let mut entries = Vec::new();
    while ext_r.any_left() {
        let entry_start = ext_block_start + ext_r.used();
        let ty = ExtensionType::read(&mut ext_r)?;
        let len = u16::read(&mut ext_r)? as usize;
        ext_r.sub(len)?;
        entries.push((ty, entry_start..ext_block_start + ext_r.used()));
    }
    Ok(entries)
}

/// Reconstruct a real `ClientHelloInner` from the HPKE-decrypted
/// `EncodedClientHelloInner` bytes (RFC 9849 section 5.1), returning both the
/// parsed form and its exact reconstructed wire body bytes (see
/// `EchResolution::Accepted`'s doc comment for why both).
///
/// The wire layout of `EncodedClientHelloInner` is a ClientHello body, but
/// its `session_id` is empty (the real one is the outer hello's) and the
/// plaintext ends in zero padding past the extensions block, so it is not
/// handed to `ClientHelloPayload::read` as it is. Instead:
///
/// 1. An `ech_outer_extensions` marker is replaced, in place, by the whole
///    wire entries of the extensions it names, copied from the outer hello's
///    own bytes: a compressed extension is byte-identical to the outer's, and
///    leaving everything else as physically ordered in the decrypted bytes
///    reproduces the client's transcript bytes exactly. The names must
///    appear in the outer hello in the same order, each once, and never
///    `encrypted_client_hello`; they are matched in one pass over the outer
///    extensions, so the work is linear in the two hellos whatever the
///    marker lists, and what is copied is at most the outer hello (section
///    5.1's implementation note). A name the pass cannot match refuses the
///    hello with `illegal_parameter`.
/// 2. `session_id` is substituted for the outer hello's real one.
/// 3. The padding is not copied, since it lies past the extensions block's
///    declared length and only bounded sub-ranges are copied.
///
/// Anything else that does not decode is a `decode_error`.
fn reconstruct_inner_hello(
    outer_raw_body: &[u8],
    decrypted: &[u8],
) -> Result<(ClientHelloPayload, Vec<u8>), InnerRefusal> {
    use crate::msgs::handshake::SessionId;

    let decode = |_: InvalidMessage| undecodable();
    let mut r = Reader::init(decrypted);
    let cv_random_start = r.used();
    crate::ProtocolVersion::read(&mut r).map_err(decode)?;
    crate::msgs::handshake::Random::read(&mut r).map_err(decode)?;
    let cv_random_end = r.used();

    SessionId::read(&mut r).map_err(decode)?; // empty in the encoded form; discarded

    let cs_cm_start = r.used();
    Vec::<crate::CipherSuite>::read(&mut r).map_err(decode)?;
    Vec::<crate::msgs::enums::Compression>::read(&mut r).map_err(decode)?;
    let cs_cm_end = r.used();

    let ext_total_len = u16::read(&mut r).map_err(decode)? as usize;
    let ext_block_start = r.used();
    let mut ext_r = r.sub(ext_total_len).map_err(decode)?;

    let mut marker: Option<(Range<usize>, Vec<ExtensionType>)> = None;
    while ext_r.any_left() {
        let entry_start = ext_block_start + ext_r.used();
        let ty = ExtensionType::read(&mut ext_r).map_err(decode)?;
        let len = u16::read(&mut ext_r).map_err(decode)? as usize;
        let mut val_r = ext_r.sub(len).map_err(decode)?;
        let entry_end = ext_block_start + ext_r.used();

        if ty == ExtensionType::EncryptedClientHelloOuterExtensions {
            marker = Some((
                entry_start..entry_end,
                Vec::<ExtensionType>::read(&mut val_r).map_err(decode)?,
            ));
            break;
        }
    }

    let mut spliced_extensions = Vec::with_capacity(ext_total_len);
    match &marker {
        Some((marker_range, refs)) => {
            spliced_extensions.extend_from_slice(&decrypted[ext_block_start..marker_range.start]);
            // One pass over the outer extensions: each name moves the cursor
            // forward to its match, so a name missing from the outer hello,
            // one already used, or one earlier in the outer's order runs off
            // the end
            let outer_entries = extension_entries(outer_raw_body).map_err(decode)?;
            let mut cursor = outer_entries.iter();
            for ext_type in refs {
                if *ext_type == ExtensionType::EncryptedClientHello {
                    return Err(outer_extensions_refused());
                }
                let (_, entry_range) = cursor
                    .find(|(ty, _)| ty == ext_type)
                    .ok_or_else(outer_extensions_refused)?;
                spliced_extensions.extend_from_slice(&outer_raw_body[entry_range.clone()]);
            }
            spliced_extensions
                .extend_from_slice(&decrypted[marker_range.end..ext_block_start + ext_total_len]);
        }
        None => {
            spliced_extensions
                .extend_from_slice(&decrypted[ext_block_start..ext_block_start + ext_total_len]);
        }
    }
    // The outer extensions copied in can make the block longer than its
    // two-byte length can say
    let spliced_len =
        u16::try_from(spliced_extensions.len()).map_err(|_| outer_extensions_refused())?;

    let mut body = Vec::with_capacity(decrypted.len() + spliced_extensions.len());
    body.extend_from_slice(&decrypted[cv_random_start..cv_random_end]);
    // Substitute the outer hello's real session_id - read directly from its
    // raw bytes (not `outer_hello.session_id`) so this function only ever
    // depends on wire bytes, consistent with the rest of this module.
    let mut outer_r = Reader::init(outer_raw_body);
    crate::ProtocolVersion::read(&mut outer_r).map_err(decode)?;
    crate::msgs::handshake::Random::read(&mut outer_r).map_err(decode)?;
    SessionId::read(&mut outer_r)
        .map_err(decode)?
        .encode(&mut body);
    body.extend_from_slice(&decrypted[cs_cm_start..cs_cm_end]);
    spliced_len.encode(&mut body);
    body.extend_from_slice(&spliced_extensions);

    let inner = ClientHelloPayload::read(&mut Reader::init(&body)).map_err(decode)?;

    Ok((inner, body))
}

/// What RFC 9849 section 7.1 requires of a ClientHelloInner: an
/// `encrypted_client_hello` extension of type inner, and no offer of TLS 1.2
/// or below (only TLS 1.3, named in `supported_versions`).
fn check_inner_hello(inner: &ClientHelloPayload) -> Result<(), InnerRefusal> {
    let refused = || {
        (
            AlertDescription::IllegalParameter,
            PeerMisbehaved::EchInnerHelloInvalid,
        )
    };
    if !matches!(
        inner.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        return Err(refused());
    }
    match &inner.supported_versions {
        Some(versions) if versions.tls13 && !versions.tls12 => Ok(()),
        _ => Err(refused()),
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::sync::Mutex;

    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, DnsName, EchConfigListBytes, PrivateKeyDer, ServerName};

    use super::{
        EchAcceptance, ServerEchConfig, ServerEchConfigs, check_inner_hello, extension_entries,
        reconstruct_inner_hello,
    };
    use crate::enums::AlertDescription;
    use crate::error::PeerMisbehaved;
    use crate::client::{EchConfig, EchMode, EchStatus as ClientEchStatus};
    use crate::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use crate::crypto::hpke::{Hpke, HpkeSuite};
    use crate::msgs::codec::{Codec, Reader};
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
        make_ech_keypair_with(config_id, public_name, &[HpkeAead::AES_128_GCM])
    }

    /// An X25519 config offering `aeads` (with HKDF-SHA256), in that order.
    fn make_ech_keypair_with(
        config_id: u8,
        public_name: &str,
        aeads: &[HpkeAead],
    ) -> TestEchKeypair {
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
                symmetric_cipher_suites: aeads
                    .iter()
                    .map(|aead_id| HpkeSymmetricCipherSuite {
                        kdf_id: HpkeKdf::HKDF_SHA256,
                        aead_id: *aead_id,
                    })
                    .collect(),
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

        let server_config =
            ServerEchConfig::new(&single_config_bytes, private_key, ALL_SUPPORTED_SUITES).expect(
                "constructing ServerEchConfig from our own freshly-generated config must succeed",
            );

        TestEchKeypair {
            server_config,
            client_config_list: EchConfigListBytes::from(list_bytes),
        }
    }

    fn test_cert_and_key() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let chain = vec![
            CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/end.der")[..]),
            CertificateDer::from(&include_bytes!("../../../test-ca/ecdsa-p256/inter.der")[..]),
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
            *self.seen_sni.lock().unwrap() = client_hello
                .server_name()
                .map(String::from);
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
    /// ECH across a HelloRetryRequest (RFC 9849 sections 6.1.5, 7.1.1 and
    /// 7.2.1). The server takes only P-384, which the client offered without a
    /// share, so it asks again: the HelloRetryRequest must confirm the offer
    /// it accepted, and the second ClientHello's offer - an empty `enc`, the
    /// payload sealed at the next sequence number - must open with the
    /// first's HPKE context. Before both, the client read the HelloRetryRequest
    /// as a rejection and the server could not open the second offer: every
    /// ECH client whose first key share this server did not take failed.
    #[test]
    fn ech_round_trip_accepted_after_hello_retry() {
        let keypair = make_ech_keypair(0xA6, "second.testserver.com");
        let (chain, key) = test_cert_and_key();
        let mut server_provider = crate::crypto::aws_lc_rs::default_provider();
        let signing_key = server_provider
            .key_provider
            .load_private_key(key)
            .unwrap();
        server_provider.kx_groups = vec![crate::crypto::aws_lc_rs::kx_group::SECP384R1];
        let seen_sni = Arc::new(Mutex::new(None));
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: seen_sni.clone(),
        });
        let mut server_config = ServerConfig::builder_with_provider(Arc::new(server_provider))
            .with_safe_default_protocol_versions()
            .unwrap()
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

        assert_eq!(
            client.handshake_kind(),
            Some(crate::HandshakeKind::FullWithHelloRetryRequest),
            "the server must have asked again for a P-384 share"
        );
        assert_eq!(client.ech_status(), ClientEchStatus::Accepted);
        assert_eq!(
            seen_sni.lock().unwrap().as_deref(),
            Some("testserver.com"),
            "the second ClientHello's inner SNI, not the public name, reaches certificate resolution"
        );
    }

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

        match client_error(&mut client, &mut server) {
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
        // The offer named the server's own config_id: a held key it did not open with
        assert_eq!(server.ech_acceptance(), EchAcceptance::Rejected);
    }

    /// Drive a handshake by hand (rather than via `do_handshake`, which
    /// asserts success): the server completes its flight, and the client's
    /// error, when it hard-errors processing it, is returned.
    fn client_error(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> Option<crate::Error> {
        let mut buf = Vec::new();
        for _ in 0..20 {
            if !client.is_handshaking() && !server.is_handshaking() {
                return None;
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
                    return Some(e);
                }
            }
        }
        None
    }

    /// A rejection offers the current configs only: a retained older one
    /// still opens offers sealed to it, but is never handed out again.
    #[test]
    fn retry_configs_are_the_current_configs_only() {
        let current = make_ech_keypair(0x01, "second.testserver.com");
        let retained = make_ech_keypair(0x02, "second.testserver.com");
        let stranger = make_ech_keypair(0x03, "second.testserver.com");

        let (chain, key) = test_cert_and_key();
        let signing_key = crate::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: Arc::new(Mutex::new(None)),
        });
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ech = Some(Arc::new(
            ServerEchConfigs::with_current(
                vec![retained.server_config, current.server_config],
                vec![1],
            )
            .unwrap(),
        ));
        let server_config = Arc::new(server_config);

        let client = |list: EchConfigListBytes<'static>| {
            let ech_config = EchConfig::new(list, ALL_SUPPORTED_SUITES).unwrap();
            let config = ClientConfig::builder_with_provider(Arc::new(
                crate::crypto::aws_lc_rs::default_provider(),
            ))
            .with_ech(EchMode::Enable(ech_config))
            .unwrap()
            .with_root_certificates(test_roots())
            .with_no_client_auth();
            ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("testserver.com").unwrap(),
            )
            .unwrap()
        };

        // Sealed to a config the server does not hold: the current one back
        let mut c = client(stranger.client_config_list);
        let mut s = ServerConnection::new(server_config.clone()).unwrap();
        match client_error(&mut c, &mut s) {
            Some(crate::Error::PeerIncompatible(
                crate::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(retry_configs)),
            )) => match retry_configs.as_slice() {
                [EchConfigPayload::V18(config)] => assert_eq!(config.key_config.config_id, 0x01),
                other => panic!("expected the current config alone, got {other:?}"),
            },
            other => panic!("expected a rejection with retry_configs, got {other:?}"),
        }

        // Sealed to the retained one: still opened
        let mut c = client(retained.client_config_list);
        let mut s = ServerConnection::new(server_config).unwrap();
        assert!(client_error(&mut c, &mut s).is_none());
        assert_eq!(c.ech_status(), ClientEchStatus::Accepted);
    }

    /// An offer is opened only with the config its config_id names (RFC 9849
    /// section 7.1). Sealed to the server's own key under an id the server
    /// does not use, it is rejected with retry_configs rather than trial
    /// decrypted - the same answer a GREASE extension or a stale config gets,
    /// at no HPKE cost - and reported as an unknown config, as they are.
    #[test]
    fn ech_offer_is_opened_only_with_the_config_its_id_names() {
        let server_keypair = make_ech_keypair(0x01, "second.testserver.com");
        // The server's own public key, under config_id 0x02
        let mut relabelled =
            Vec::<EchConfigPayload>::read(&mut Reader::init(&*server_keypair.client_config_list))
                .unwrap();
        match &mut relabelled[0] {
            EchConfigPayload::V18(contents) => contents.key_config.config_id = 0x02,
            other => panic!("expected a V18 config, got {other:?}"),
        }
        let mut list_bytes = Vec::new();
        relabelled.encode(&mut list_bytes);

        let (chain, key) = test_cert_and_key();
        let signing_key = crate::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: Arc::new(Mutex::new(None)),
        });
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ech = Some(Arc::new(
            ServerEchConfigs::new(vec![server_keypair.server_config]).unwrap(),
        ));

        let ech_config =
            EchConfig::new(EchConfigListBytes::from(list_bytes), ALL_SUPPORTED_SUITES).unwrap();
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

        match client_error(&mut client, &mut server) {
            Some(crate::Error::PeerIncompatible(
                crate::PeerIncompatible::ServerRejectedEncryptedClientHello(Some(retry_configs)),
            )) => match retry_configs.as_slice() {
                [EchConfigPayload::V18(current)] => {
                    assert_eq!(current.key_config.config_id, 0x01)
                }
                other => panic!("expected the server's one config, got {other:?}"),
            },
            other => panic!("expected a rejection with retry_configs, got {other:?}"),
        }
        assert_eq!(server.ech_acceptance(), EchAcceptance::UnknownConfig);
    }

    /// The client picks one of the config's symmetric suites (RFC 9849 6.1),
    /// not necessarily the first: one that implements only the second must
    /// still have its offer opened.
    #[test]
    fn an_offer_sealed_with_any_of_the_configs_suites_is_opened() {
        let keypair = make_ech_keypair_with(
            0x07,
            "second.testserver.com",
            &[HpkeAead::AES_256_GCM, HpkeAead::CHACHA20_POLY_1305],
        );

        let (chain, key) = test_cert_and_key();
        let signing_key = crate::crypto::aws_lc_rs::default_provider()
            .key_provider
            .load_private_key(key)
            .unwrap();
        let resolver = Arc::new(RecordingResolver {
            key: Arc::new(CertifiedKey::new(chain, signing_key)),
            seen_sni: Arc::new(Mutex::new(None)),
        });
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ech = Some(Arc::new(
            ServerEchConfigs::new(vec![keypair.server_config]).unwrap(),
        ));

        // A client whose only HPKE suite is the config's second
        let chacha: &'static dyn Hpke = *ALL_SUPPORTED_SUITES
            .iter()
            .find(|h| {
                h.suite()
                    == HpkeSuite {
                        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
                        sym: HpkeSymmetricCipherSuite {
                            kdf_id: HpkeKdf::HKDF_SHA256,
                            aead_id: HpkeAead::CHACHA20_POLY_1305,
                        },
                    }
            })
            .unwrap();
        let ech_config = EchConfig::new(keypair.client_config_list, &[chacha]).unwrap();
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

        assert!(client_error(&mut client, &mut server).is_none());
        assert_eq!(client.ech_status(), ClientEchStatus::Accepted);
    }

    // ── ClientHelloInner decoding (RFC 9849 sections 5.1 and 7.1) ──────────

    const SNI: u16 = 0x0000;
    const GROUPS: u16 = 0x000a;
    const ALPN: u16 = 0x0010;
    const VERSIONS: u16 = 0x002b;
    const KEY_SHARE: u16 = 0x0033;
    const ECH: u16 = 0xfe0d;
    const OUTER_EXTENSIONS: u16 = 0xfd00;

    /// A ClientHello body: TLS 1.2 legacy version, a fixed random, the
    /// session id, one suite, null compression, and the extensions in order.
    fn hello_body(session_id: &[u8], extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend([7u8; 32]);
        body.push(u8::try_from(session_id.len()).unwrap());
        body.extend(session_id);
        body.extend([0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        let mut block = Vec::new();
        for (ty, value) in extensions {
            block.extend(ty.to_be_bytes());
            block.extend(u16::try_from(value.len()).unwrap().to_be_bytes());
            block.extend(value);
        }
        body.extend(u16::try_from(block.len()).unwrap().to_be_bytes());
        body.extend(block);
        body
    }

    fn named(types: &[u16]) -> Vec<u8> {
        let mut value = vec![u8::try_from(types.len() * 2).unwrap()];
        for ty in types {
            value.extend(ty.to_be_bytes());
        }
        value
    }

    fn groups() -> Vec<u8> {
        vec![0x00, 0x02, 0x00, 0x1d]
    }

    fn alpn() -> Vec<u8> {
        vec![0x00, 0x03, 0x02, b'h', b'2']
    }

    fn tls13_only() -> Vec<u8> {
        vec![0x02, 0x03, 0x04]
    }

    /// An outer hello with server_name, supported_groups, ALPN and an ECH
    /// offer, in that order.
    fn outer() -> Vec<u8> {
        let mut sni = vec![0x00, 0x0e, 0x00, 0x00, 0x0b];
        sni.extend(b"example.com");
        hello_body(
            &[1, 2, 3, 4],
            &[
                (SNI, sni),
                (GROUPS, groups()),
                (ALPN, alpn()),
                (ECH, vec![0x00, 0x00, 0x01, 0x00, 0x01, 0x05]),
            ],
        )
    }

    /// An EncodedClientHelloInner naming `refs` from the outer hello, with
    /// zero padding after it.
    fn encoded_inner(refs: &[u16]) -> Vec<u8> {
        let mut inner = hello_body(
            &[],
            &[
                (VERSIONS, tls13_only()),
                (OUTER_EXTENSIONS, named(refs)),
                (ECH, vec![0x01]),
            ],
        );
        inner.extend([0u8; 24]);
        inner
    }

    fn types_of(body: &[u8]) -> Vec<u16> {
        extension_entries(body)
            .unwrap()
            .into_iter()
            .map(|(ty, _)| u16::from(ty))
            .collect()
    }

    #[test]
    fn named_outer_extensions_are_spliced_in_where_the_marker_was() {
        let (inner, body) = reconstruct_inner_hello(&outer(), &encoded_inner(&[GROUPS, ALPN]))
            .expect("a well-formed inner hello");
        assert_eq!(types_of(&body), [VERSIONS, GROUPS, ALPN, ECH]);
        assert_eq!(
            inner.session_id.as_ref(),
            &[1, 2, 3, 4],
            "the outer's session id"
        );
        assert!(check_inner_hello(&inner).is_ok());
    }

    #[test]
    fn outer_extensions_named_against_the_rules_are_refused() {
        let refused = |refs: &[u16]| {
            reconstruct_inner_hello(&outer(), &encoded_inner(refs))
                .map(|_| ())
                .unwrap_err()
        };
        let illegal = (
            AlertDescription::IllegalParameter,
            PeerMisbehaved::EchInnerHelloUndecodable,
        );
        assert_eq!(refused(&[ALPN, GROUPS]), illegal, "out of the outer's order");
        assert_eq!(refused(&[GROUPS, GROUPS]), illegal, "named twice");
        assert_eq!(refused(&[GROUPS, ECH]), illegal, "encrypted_client_hello itself");
        assert_eq!(refused(&[KEY_SHARE]), illegal, "not in the outer hello");
        // The most a marker can name: refused at the second, after one copy
        assert_eq!(refused(&[GROUPS; 127]), illegal);
    }

    #[test]
    fn an_inner_hello_that_is_not_one_is_a_decode_error() {
        let mut garbage = vec![0x03, 0x03];
        garbage.extend([0xffu8; 40]);
        assert_eq!(
            reconstruct_inner_hello(&outer(), &garbage)
                .map(|_| ())
                .unwrap_err(),
            (
                AlertDescription::DecodeError,
                PeerMisbehaved::EchInnerHelloUndecodable
            )
        );
    }

    #[test]
    fn an_inner_hello_must_say_it_is_one_and_offer_tls13_alone() {
        let decode = |extensions: &[(u16, Vec<u8>)]| {
            let body = hello_body(&[], extensions);
            reconstruct_inner_hello(&outer(), &body)
                .expect("decodes")
                .0
        };
        let invalid = Err((
            AlertDescription::IllegalParameter,
            PeerMisbehaved::EchInnerHelloInvalid,
        ));
        assert_eq!(
            check_inner_hello(&decode(&[(VERSIONS, tls13_only())])),
            invalid,
            "no encrypted_client_hello of type inner"
        );
        assert_eq!(
            check_inner_hello(&decode(&[
                (VERSIONS, vec![0x04, 0x03, 0x04, 0x03, 0x03]),
                (ECH, vec![0x01])
            ])),
            invalid,
            "TLS 1.2 offered beside 1.3"
        );
        assert_eq!(
            check_inner_hello(&decode(&[(ECH, vec![0x01])])),
            invalid,
            "no supported_versions: TLS 1.2"
        );
        assert!(
            check_inner_hello(&decode(&[(VERSIONS, tls13_only()), (ECH, vec![0x01])])).is_ok()
        );
    }
}
