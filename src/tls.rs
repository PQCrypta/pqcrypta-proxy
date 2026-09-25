//! TLS configuration with Post-Quantum Cryptography (PQC) support
//!
//! Supports:
//! - Standard TLS 1.3 with rustls
//! - Hybrid PQC key exchange via aws-lc-rs (X25519MLKEM768)
//! - Hot-reload of certificates
//! - mTLS for client authentication

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use arc_swap::ArcSwap;
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::server::ServerConfig as RustlsServerConfig;
use rustls::version::{TLS12, TLS13};
// L-1: Migrated from unmaintained rustls-pemfile to rustls-pki-types PEM parsing API
use rustls_pki_types::pem::PemObject;
use tracing::{debug, info, warn};

use crate::config::{ClientAuth, PqcConfig, TlsConfig};

// ── SNI-based per-domain certificate resolver ────────────────────────────────

/// SNI-based per-domain certificate resolver.
///
/// Reads `{domain}.crt` / `{domain}.key` pairs from the certs directory.
/// Thread-safe hot-reload via `reload()` — all listeners sharing the same
/// `Arc` immediately serve the refreshed certificate after a call to `reload()`.
#[derive(Debug)]
pub struct MultiDomainCertResolver {
    /// domain → `CertifiedKey` map, updated atomically on reload
    certs: RwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
    /// Directory containing `{domain}.crt` / `{domain}.key` files
    certs_dir: PathBuf,
}

impl MultiDomainCertResolver {
    /// Build a resolver from all cert/key pairs found in `certs_dir`.
    pub fn new(certs_dir: &Path) -> anyhow::Result<Self> {
        let resolver = Self {
            certs: RwLock::new(HashMap::new()),
            certs_dir: certs_dir.to_path_buf(),
        };
        resolver.reload()?;
        Ok(resolver)
    }

    /// Re-read every `*.crt` + `*.key` pair from the certs directory.
    /// Existing entries are replaced; domains whose files disappeared are removed.
    pub fn reload(&self) -> anyhow::Result<()> {
        let mut new_certs = HashMap::new();

        let read_dir = std::fs::read_dir(&self.certs_dir).map_err(|e| {
            anyhow::anyhow!("Cannot read certs directory {:?}: {}", self.certs_dir, e)
        })?;

        for entry in read_dir.flatten() {
            let cert_path = entry.path();
            if cert_path.extension().and_then(|e| e.to_str()) != Some("crt") {
                continue;
            }
            let key_path = cert_path.with_extension("key");
            if !key_path.exists() {
                continue;
            }
            let domain = match cert_path.file_stem().and_then(|s| s.to_str()) {
                Some(d) => d.to_ascii_lowercase(),
                None => continue,
            };
            match load_certified_key(&cert_path, &key_path) {
                Ok(ck) => {
                    new_certs.insert(domain.clone(), Arc::new(ck));
                    debug!("SNI resolver loaded cert for '{}'", domain);
                }
                Err(e) => {
                    warn!("SNI resolver: skipping '{}' — {}", domain, e);
                }
            }
        }

        info!(
            "SNI cert resolver reloaded: {} domains ({})",
            new_certs.len(),
            new_certs.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        *self.certs.write() = new_certs;
        Ok(())
    }
}

impl rustls::server::ResolvesServerCert for MultiDomainCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.certs.read().get(sni).cloned()
    }
}

/// Load a `CertifiedKey` from PEM cert and key files.
pub fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("Cannot open cert {:?}: {}", cert_path, e))?;
    let mut reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Cannot parse cert {:?}: {}", cert_path, e))?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates in {:?}", cert_path));
    }

    // Load private key (PKCS#8 first, then PKCS#1)
    let private_key = {
        let file = File::open(key_path)
            .map_err(|e| anyhow::anyhow!("Cannot open key {:?}: {}", key_path, e))?;
        let mut r = BufReader::new(file);
        if let Some(k) = PrivatePkcs8KeyDer::pem_reader_iter(&mut r).find_map(|r| r.ok()) {
            PrivateKeyDer::Pkcs8(k)
        } else {
            let file2 = File::open(key_path)
                .map_err(|e| anyhow::anyhow!("Cannot open key {:?}: {}", key_path, e))?;
            let mut r2 = BufReader::new(file2);
            PrivatePkcs1KeyDer::pem_reader_iter(&mut r2)
                .find_map(|r| r.ok())
                .map(PrivateKeyDer::Pkcs1)
                .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?
        }
    };

    // ML-DSA-87 keys (FIPS 204) are not handled by the aws-lc-rs provider's
    // key loader — route them through the dedicated PQC signing key instead.
    // aws-lc-rs gates `unstable` (PQDSA) out of FIPS builds — mirror that here
    #[cfg(all(feature = "pqc-signatures", not(feature = "fips")))]
    if let PrivateKeyDer::Pkcs8(ref k) = private_key {
        if mldsa::is_ml_dsa_87_pkcs8(k.secret_pkcs8_der()) {
            if !ml_dsa_signing_enabled() {
                return Err(anyhow::anyhow!(
                    "{:?} is an ML-DSA-87 key but pqc.enable_signatures is false. \
                     Set it true to serve post-quantum certificate signatures, or \
                     point this host at a classical key.",
                    key_path
                ));
            }
            let signing_key = Arc::new(mldsa::MlDsa87SigningKey::load(k.secret_pkcs8_der())?);
            info!(
                "Loaded ML-DSA-87 (FIPS 204) certificate key from {:?}",
                key_path
            );
            return Ok(rustls::sign::CertifiedKey::new(certs, signing_key));
        }
    }

    // Load the signing key with the provider every listener is built on rather
    // than the process default. Nothing guarantees a default is installed:
    // with pqc.enabled false nothing installs one on purpose, and keys loaded
    // only because some earlier `ServerConfig::builder()` call happened to
    // install rustls's crate default as a side effect.
    let signing_key = build_pqc_provider()
        .key_provider
        .load_private_key(private_key)
        .map_err(|e| anyhow::anyhow!("Cannot load signing key from {:?}: {}", key_path, e))?;

    Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
}

/// Runtime switch for `pqc.enable_signatures`, set once at startup.
///
/// The ML-DSA path sits inside the certificate loader, which the SNI resolver
/// calls per host without any view of the config, so the setting is published
/// here rather than threaded through every call site. Defaults to true so a
/// caller that never sets it (tests, tooling) keeps the compiled behaviour.
static ML_DSA_SIGNING_ENABLED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Apply `pqc.enable_signatures` before any certificate is loaded.
pub fn set_ml_dsa_signing_enabled(enabled: bool) {
    ML_DSA_SIGNING_ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Whether ML-DSA-87 certificate keys may be served.
pub fn ml_dsa_signing_enabled() -> bool {
    ML_DSA_SIGNING_ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

// ── ML-DSA-87 certificate signing (TLS signature scheme 0x0906) ──────────────

/// Server-side ML-DSA-87 (FIPS 204) certificate signing for TLS 1.3.
///
/// rustls knows the `ML_DSA_87` signature scheme codepoint but its aws-lc-rs
/// provider cannot load ML-DSA private keys, so this module supplies a custom
/// [`rustls::sign::SigningKey`] backed by aws-lc-rs's PQDSA implementation.
/// A handshake completes only when the client offers `mldsa87` (0x0906) in its
/// `signature_algorithms` extension (e.g. `openssl s_client -sigalgs mldsa87`).
#[cfg(all(feature = "pqc-signatures", not(feature = "fips")))]
mod mldsa {
    use std::sync::Arc;

    use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_87_SIGNING};
    use rustls::sign::{Signer, SigningKey};
    use rustls::{SignatureAlgorithm, SignatureScheme};

    /// DER encoding of OID 2.16.840.1.101.3.4.3.19 (id-ml-dsa-87)
    const ML_DSA_87_OID: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ];

    /// ML-DSA-87 private-key seed length (FIPS 204)
    const SEED_LEN: usize = 32;

    /// ML-DSA-87 expanded private-key length (FIPS 204)
    const EXPANDED_KEY_LEN: usize = 4896;

    /// Detect an ML-DSA-87 PKCS#8 key by its AlgorithmIdentifier OID.
    /// The OID sits inside the fixed-size PKCS#8 header, so a windowed scan
    /// over the first bytes suffices without pulling in a DER parser.
    pub(super) fn is_ml_dsa_87_pkcs8(der: &[u8]) -> bool {
        der.len() > 32
            && der[..32]
                .windows(ML_DSA_87_OID.len())
                .any(|w| w == ML_DSA_87_OID)
    }

    /// Read one DER TLV at `buf[pos..]`; returns (tag, content_start, content_end).
    fn der_tlv(buf: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
        let tag = *buf.get(pos)?;
        let first_len = *buf.get(pos + 1)? as usize;
        let (len, hdr) = if first_len < 0x80 {
            (first_len, 2)
        } else {
            let n = first_len & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | *buf.get(pos + 2 + i)? as usize;
            }
            (len, 2 + n)
        };
        let start = pos + hdr;
        let end = start.checked_add(len)?;
        (end <= buf.len()).then_some((tag, start, end))
    }

    /// Extract the seed (preferred) or expanded key from the PKCS#8 privateKey
    /// field, handling all three CHOICE forms from
    /// draft-ietf-lamps-dilithium-certificates: seed `[0]`, expandedKey
    /// OCTET STRING, and the `both` SEQUENCE (what OpenSSL 3.5 writes).
    fn extract_key_material(pkcs8: &[u8]) -> Option<(&[u8], bool)> {
        // PKCS#8: SEQUENCE { version INTEGER, algorithm SEQUENCE, privateKey OCTET STRING }
        let (0x30, mut pos, outer_end) = der_tlv(pkcs8, 0)? else {
            return None;
        };
        let mut private_key: Option<&[u8]> = None;
        let mut field = 0;
        while pos < outer_end {
            let (tag, start, end) = der_tlv(pkcs8, pos)?;
            if field == 2 && tag == 0x04 {
                private_key = Some(&pkcs8[start..end]);
                break;
            }
            pos = end;
            field += 1;
        }
        let inner = private_key?;

        // Inner CHOICE
        let (tag, start, end) = der_tlv(inner, 0)?;
        match tag {
            // both SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
            0x30 => {
                let (0x04, s, e) = der_tlv(inner, start)? else {
                    return None;
                };
                (e - s == SEED_LEN).then_some((&inner[s..e], true))
            }
            // seed [0] IMPLICIT OCTET STRING
            0x80 => (end - start == SEED_LEN).then_some((&inner[start..end], true)),
            // expandedKey OCTET STRING (or bare 32-byte seed as OCTET STRING)
            0x04 => match end - start {
                SEED_LEN => Some((&inner[start..end], true)),
                EXPANDED_KEY_LEN => Some((&inner[start..end], false)),
                _ => None,
            },
            _ => None,
        }
    }

    /// A rustls signing key backed by an ML-DSA-87 key pair.
    #[derive(Debug)]
    pub(super) struct MlDsa87SigningKey {
        keypair: Arc<PqdsaKeyPair>,
    }

    impl MlDsa87SigningKey {
        /// Load from PKCS#8 DER. Tries aws-lc-rs's own PKCS#8 parser first,
        /// then falls back to manual extraction of the seed / expanded key for
        /// CHOICE encodings it does not accept.
        pub(super) fn load(pkcs8: &[u8]) -> anyhow::Result<Self> {
            let keypair = PqdsaKeyPair::from_pkcs8(&ML_DSA_87_SIGNING, pkcs8).or_else(|_| {
                let (material, is_seed) = extract_key_material(pkcs8).ok_or_else(|| {
                    anyhow::anyhow!("Unrecognised ML-DSA-87 PKCS#8 private-key encoding")
                })?;
                let result = if is_seed {
                    PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, material)
                } else {
                    PqdsaKeyPair::from_raw_private_key(&ML_DSA_87_SIGNING, material)
                };
                result.map_err(|e| anyhow::anyhow!("ML-DSA-87 key rejected: {:?}", e))
            })?;
            Ok(Self {
                keypair: Arc::new(keypair),
            })
        }
    }

    impl SigningKey for MlDsa87SigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered.contains(&SignatureScheme::ML_DSA_87).then(|| {
                Box::new(MlDsa87Signer {
                    keypair: Arc::clone(&self.keypair),
                }) as Box<dyn Signer>
            })
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            // No legacy TLS 1.2 SignatureAlgorithm codepoint exists for ML-DSA;
            // TLS 1.3 cipher-suite selection ignores this value.
            SignatureAlgorithm::Unknown(0x06)
        }
    }

    #[derive(Debug)]
    struct MlDsa87Signer {
        keypair: Arc<PqdsaKeyPair>,
    }

    impl Signer for MlDsa87Signer {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            let mut sig = vec![0u8; self.keypair.algorithm().signature_len()];
            let n = self
                .keypair
                .sign(message, &mut sig)
                .map_err(|_| rustls::Error::General("ML-DSA-87 signing failed".into()))?;
            sig.truncate(n);
            Ok(sig)
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ML_DSA_87
        }
    }

    #[cfg(test)]
    mod tests {
        use aws_lc_rs::signature::{KeyPair, UnparsedPublicKey};
        use aws_lc_rs::unstable::signature::ML_DSA_87;

        use super::*;

        #[test]
        fn pkcs8_roundtrip_sign_verify() {
            let generated = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
            let pkcs8 = generated.to_pkcs8().unwrap();
            assert!(is_ml_dsa_87_pkcs8(pkcs8.as_ref()));

            let key = MlDsa87SigningKey::load(pkcs8.as_ref()).unwrap();
            let signer = key
                .choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::ML_DSA_87])
                .expect("ML_DSA_87 offered but not chosen");
            assert_eq!(signer.scheme(), SignatureScheme::ML_DSA_87);

            let msg = b"tls certificate verify test message";
            let sig = signer.sign(msg).unwrap();
            UnparsedPublicKey::new(&ML_DSA_87, generated.public_key().as_ref())
                .verify(msg, &sig)
                .expect("signature must verify");
        }

        #[test]
        fn refuses_without_mldsa_offer() {
            let generated = PqdsaKeyPair::generate(&ML_DSA_87_SIGNING).unwrap();
            let pkcs8 = generated.to_pkcs8().unwrap();
            let key = MlDsa87SigningKey::load(pkcs8.as_ref()).unwrap();
            assert!(key
                .choose_scheme(&[
                    SignatureScheme::ED25519,
                    SignatureScheme::ECDSA_NISTP256_SHA256
                ])
                .is_none());
        }

        #[test]
        fn rejects_non_mldsa_pkcs8() {
            // Any small DER without the ML-DSA-87 OID must be rejected
            assert!(!is_ml_dsa_87_pkcs8(&[0x30, 0x03, 0x02, 0x01, 0x00]));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// TLS provider abstraction
pub struct TlsProvider {
    /// Current TLS server configuration (atomic swap for hot-reload)
    server_config: ArcSwap<quinn::crypto::rustls::QuicServerConfig>,
    /// TLS configuration from proxy config
    tls_config: RwLock<TlsConfig>,
    /// PQC configuration
    pqc_config: RwLock<PqcConfig>,
    /// Last certificate modification time (watches certs_dir mtime)
    last_cert_modified: RwLock<Option<SystemTime>>,
    /// PQC availability status
    pqc_available: RwLock<bool>,
    /// Whether clients are asked for a certificate; see `ProxyConfig::client_auth`.
    client_auth: ClientAuth,
    /// SNI cert resolver — shared across all listeners
    pub resolver: Arc<MultiDomainCertResolver>,
}

/// The proxy's key exchange preference, in one place.
///
/// Both the live listener and the startup verification handshake call this, so the
/// attestation cannot describe a provider that differs from the one serving traffic.
/// Constructing them separately would let the two drift, and a banner that reports a
/// stack nothing uses is the failure this whole mechanism exists to prevent.
///
/// X25519 is removed and the hybrids sorted first: clients offering only an X25519
/// key_share get a HelloRetryRequest and fall back to secp384r1.
/// The configuration behind [`TlsProvider::build_zero_rtt_reject_config`].
///
/// Free-standing and taking its own resolver so the behaviour can be exercised
/// against a throwaway certificate. A test that rebuilt this configuration
/// itself would be testing its own copy of the logic, and the two would drift
/// apart exactly when it mattered.
///
/// Offers early data and then declines it, which is the pair the conformance
/// suite's `q-zero-rtt-reject` needs: a client only sends 0-RTT if a ticket said
/// it could, and there is nothing to test unless that offer is then refused.
///
/// Two things had to be got right, and both were wrong first time.
///
/// **A ticketer prevents the offer.** rustls implements RFC 8446 §8.1 — 0-RTT is
/// permitted only with *stateful* resumption, where the server keeps the session
/// and the ticket refers to it. A ticketer means stateless resumption, and a
/// stateless ticket can be replayed by whoever captures it, so rustls will not
/// advertise early data beside one. It does not complain; it logs and omits the
/// extension, and the client then simply never offers 0-RTT. Leaving `ticketer`
/// at its default keeps rustls's server-side session store, which is the
/// stateful half of that choice. Production makes the opposite trade for the
/// opposite reasons: stateless resumption that survives a restart, PQC-protected
/// tickets, and no 0-RTT at all.
///
/// **A HelloRetryRequest does not reject it on the connection that matters.**
/// The first attempt here forced a retry by accepting only key-exchange groups
/// no client key-shares speculatively, since §4.2.10 rejects early data whenever
/// a retry is sent. It rejected nothing: clients cache the group the server
/// chose, so the *resumed* handshake — the only one carrying 0-RTT — key-shares
/// the right group first time and no retry happens. The refusal is now asked for
/// directly.
/// Offers early data and accepts it, for `q-zero-rtt-replay`.
///
/// The mirror of [`zero_rtt_reject_server_config`], and it shares that
/// function's hard-won constraint: rustls only advertises early data beside
/// *stateful* resumption (RFC 8446 §8.1), so the ticketer is left at its default
/// and not replaced with the stateless one production uses. Without that, no
/// ticket ever promises early data and no client ever offers any.
///
/// Accepting it is the point here. `q-zero-rtt-reject` measures what a client
/// does when its early data is refused; this port lets the early data through so
/// the exchange above it — a 425 (Too Early) and whatever the client does next —
/// can happen at all.
pub fn zero_rtt_accept_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(build_pqc_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| anyhow::anyhow!("failed to set protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"h3".to_vec()];
    crate::cert_compression::apply(&mut config);
    // Advertised in the ticket, and honoured rather than declined.
    config.max_early_data_size = u32::MAX;

    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|e| anyhow::anyhow!("failed to build the 0-RTT QUIC config: {e}"))?,
    ))
}

pub fn zero_rtt_reject_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(build_pqc_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| anyhow::anyhow!("failed to set protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"h3".to_vec()];
    crate::cert_compression::apply(&mut config);
    // Advertised in the ticket, so a client offers early data...
    config.max_early_data_size = u32::MAX;
    // ...and declined every time, which is what the test is about.
    config.refuse_early_data = true;

    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config)
            .map_err(|e| anyhow::anyhow!("failed to build the 0-RTT QUIC config: {e}"))?,
    ))
}

/// A provider offering exactly one key-exchange group.
///
/// This is how the TLS tier of the conformance suite emits its anomalies. A
/// server that will negotiate only one group is not misbehaving — it is a
/// perfectly legal configuration — but it forces the client down a path that
/// production never does, and what the client does there is the measurement.
///
/// Two of them matter during the migration:
///
/// * **hybrid only.** A client that offered only classical groups must recover
///   through HelloRetryRequest, which costs it an extra round trip and is the
///   part of post-quantum deployment that breaks first. A client that never
///   listed the group at all cannot recover and must abandon cleanly rather
///   than hang.
/// * **classical only.** The mirror: a client that offered a hybrid is answered
///   with X25519. Whether it proceeds or refuses is a policy decision the RFCs
///   leave open, so the suite reports which was taken rather than grading it.
///
/// The cipher-suite preference is left exactly as `build_pqc_provider` sets it,
/// so the only variable between the production path and a test port is the
/// group. A test that changed two things at once would not measure either.
pub fn build_single_group_provider(
    group: rustls::NamedGroup,
) -> anyhow::Result<rustls::crypto::CryptoProvider> {
    // Built from the unmodified post-quantum provider, not from
    // `build_pqc_provider`, which removes X25519 outright: that is the edge's
    // production policy, and inheriting it here left `t-classical-only` with an
    // empty group list. The port then refused to bind at all -- correctly, by
    // the guard below, but it meant the one test about classical downgrade was
    // the one test that could not run.
    //
    // The cipher-suite preference IS inherited, deliberately, so the only thing
    // that differs between a test port and production is the group.
    let mut provider = rustls_post_quantum::provider();
    prefer_256_bit_aeads(&mut provider);
    provider.kx_groups.retain(|g| g.name() == group);
    if provider.kx_groups.is_empty() {
        // Every caller names a group the post-quantum provider is expected to
        // carry. An empty list would build a server that can complete no
        // handshake at all, and every client would then "fail" a test that was
        // never emitted — the precise false accusation this suite exists to
        // avoid.
        anyhow::bail!(
            "the crypto provider does not carry {:?}; refusing to build a server with no key exchange",
            group
        );
    }
    Ok(provider)
}

/// A QUIC server config that will negotiate only `group`.
///
/// Used by the TLS tier's listeners. Shares the edge's own certificate
/// resolver, so a client meets the same certificate chain it would in
/// production and the only thing under test is the key exchange.
pub fn single_group_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
    group: rustls::NamedGroup,
    impairment: Option<rustls::server::KeyShareImpairment>,
) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
    let provider = build_single_group_provider(group)?;
    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| anyhow::anyhow!("failed to set protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![b"h3".to_vec()];
    crate::cert_compression::apply(&mut config);
    // Only ever `Some` on a conformance port. `vendor/rustls-fixed` treats
    // `None` as ordinary conformant behaviour and never reaches the damaging
    // branch, so nothing here changes what a serving listener emits.
    config.key_share_impairment = impairment;

    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(config).map_err(|e| {
            anyhow::anyhow!("failed to build the single-group QUIC config for {group:?}: {e}")
        })?,
    ))
}

/// The size of the chain the post-quantum port serves, as loaded.
///
/// Verdicts on that port describe the chain, and they once described it from
/// memory: "40 KB" survived the fixture being replaced by one well under half
/// that, and went on appearing in every result. Measured at load time, the
/// sentence cannot outlive the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSize {
    pub certificates: usize,
    pub der_bytes: usize,
}

impl std::fmt::Display for ChainSize {
    /// "2-certificate, 15,430-byte"
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digits = self.der_bytes.to_string();
        let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                grouped.push(',');
            }
            grouped.push(c);
        }
        write!(f, "{}-certificate, {grouped}-byte", self.certificates)
    }
}

#[cfg(test)]
mod chain_size_tests {
    use super::{CertificateDer, ChainSize, PemObject};

    #[test]
    fn groups_bytes_in_thousands() {
        let size = |certificates, der_bytes| {
            ChainSize {
                certificates,
                der_bytes,
            }
            .to_string()
        };
        assert_eq!(size(2, 15_430), "2-certificate, 15,430-byte");
        assert_eq!(size(3, 999), "3-certificate, 999-byte");
        assert_eq!(size(1, 1_000), "1-certificate, 1,000-byte");
        assert_eq!(size(4, 1_234_567), "4-certificate, 1,234,567-byte");
    }

    /// The deployed fixture, when this box has it: the size a verdict quotes
    /// is the one on disk.
    #[test]
    fn measures_the_fixture_it_loads() {
        let cert = std::path::Path::new("/etc/pqcrypta/pqc-certs/conformance/fullchain.pem");
        let key = std::path::Path::new("/etc/pqcrypta/pqc-certs/conformance/server.key");
        if !cert.exists() || !key.exists() {
            return;
        }
        let (_, size) = super::pq_chain_server_config(cert, key).expect("fixture loads");
        let pem = std::fs::read(cert).expect("fixture readable");
        let der: Vec<_> = CertificateDer::pem_reader_iter(&mut &pem[..])
            .collect::<Result<_, _>>()
            .expect("fixture parses");
        assert_eq!(size.certificates, der.len());
        assert_eq!(size.der_bytes, der.iter().map(|c| c.len()).sum::<usize>());
    }
}

#[cfg(test)]
mod server_policy_tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, NamedGroup, ProtocolVersion, RootCertStore};

    use super::{is_post_quantum_group, server_provider, ServerTlsPolicy};
    use crate::config::{ClientAuth, PqcConfig, TlsConfig};
    use crate::startup_verify::{pump_handshake, self_signed_pair, VERIFY_SNI};

    fn tls(min_version: &str) -> TlsConfig {
        TlsConfig {
            min_version: min_version.to_string(),
            ..TlsConfig::default()
        }
    }

    /// Handshake a client against `policy` in memory and report what was
    /// agreed. The client offers the hybrid and every classical group, as
    /// OpenSSL 3.5 and current browsers do, so the server's policy is what
    /// decides.
    fn negotiate(
        policy: &ServerTlsPolicy,
        client_versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> anyhow::Result<(NamedGroup, ProtocolVersion)> {
        let (cert, key) = self_signed_pair()?;
        let server = policy
            .builder()?
            .with_single_cert(vec![cert.clone()], key)?;
        let mut roots = RootCertStore::empty();
        roots.add(cert)?;
        let client = ClientConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
            .with_protocol_versions(client_versions)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(VERIFY_SNI)?.to_owned(),
        )?;
        let mut server = rustls::ServerConnection::new(Arc::new(server))?;
        pump_handshake(&mut client, &mut server)?;
        Ok((
            client
                .negotiated_key_exchange_group()
                .ok_or_else(|| anyhow::anyhow!("no group"))?
                .name(),
            client
                .protocol_version()
                .ok_or_else(|| anyhow::anyhow!("no version"))?,
        ))
    }

    const TLS13: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    const TLS12: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    #[test]
    fn groups_follow_pqc_enabled() {
        let on: Vec<_> = server_provider(true, &PqcConfig::default())
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        let off: Vec<_> = server_provider(false, &PqcConfig::default())
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect();
        assert_eq!(on.first(), Some(&NamedGroup::X25519MLKEM768));
        assert!(off.iter().all(|g| !is_post_quantum_group(*g)), "{off:?}");
        assert_eq!(off.first(), Some(&NamedGroup::secp384r1));
        // Turning PQC off removes the hybrid and nothing else.
        let on_classical: Vec<_> = on
            .iter()
            .copied()
            .filter(|g| !is_post_quantum_group(*g))
            .collect();
        assert_eq!(on_classical, off);
        assert!(!on.contains(&NamedGroup::X25519) && !off.contains(&NamedGroup::X25519));
    }

    fn groups(pqc: &PqcConfig) -> Vec<NamedGroup> {
        server_provider(true, pqc)
            .kx_groups
            .iter()
            .map(|g| g.name())
            .collect()
    }

    /// Every hybrid the build implements is offered, the preferred one first,
    /// and no pure ML-KEM group unless preferred_kem names it.
    #[test]
    fn every_hybrid_is_offered_preferred_first() {
        let g = groups(&PqcConfig::default());
        assert_eq!(g.first(), Some(&NamedGroup::X25519MLKEM768), "{g:?}");
        for hybrid in [
            NamedGroup::X25519MLKEM768,
            NamedGroup::secp256r1MLKEM768,
            NamedGroup::secp384r1MLKEM1024,
        ] {
            assert!(g.contains(&hybrid), "{hybrid:?} missing from {g:?}");
        }
        assert!(!g.contains(&NamedGroup::MLKEM768) && !g.contains(&NamedGroup::MLKEM1024));

        let g = groups(&PqcConfig {
            preferred_kem: "SecP384r1MLKEM1024".into(),
            ..PqcConfig::default()
        });
        assert_eq!(g.first(), Some(&NamedGroup::secp384r1MLKEM1024), "{g:?}");

        let g = groups(&PqcConfig {
            preferred_kem: "ML-KEM-1024".into(),
            ..PqcConfig::default()
        });
        assert_eq!(g.first(), Some(&NamedGroup::MLKEM1024), "{g:?}");
    }

    /// require_hybrid: hybrids only -- no classical group, no pure ML-KEM
    /// even when preferred. fallback_to_classical false: no classical group.
    #[test]
    fn require_hybrid_and_fallback_shape_the_offer() {
        let g = groups(&PqcConfig {
            require_hybrid: true,
            preferred_kem: "MLKEM1024".into(),
            ..PqcConfig::default()
        });
        assert!(g.iter().all(|n| is_post_quantum_group(*n)), "{g:?}");
        assert!(!g.contains(&NamedGroup::MLKEM1024), "{g:?}");

        let g = groups(&PqcConfig {
            fallback_to_classical: false,
            ..PqcConfig::default()
        });
        assert!(g.iter().all(|n| is_post_quantum_group(*n)), "{g:?}");

        let g = groups(&PqcConfig::default());
        assert!(g.contains(&NamedGroup::secp384r1) && g.contains(&NamedGroup::secp256r1));
    }

    /// min_security_level drops post-quantum groups below the NIST level;
    /// additional_kems orders the offer after preferred_kem and may name a
    /// pure ML-KEM group. Both were read by nothing before.
    #[test]
    fn min_security_level_and_additional_kems() {
        let g = groups(&PqcConfig {
            min_security_level: 5,
            preferred_kem: "SecP384r1MLKEM1024".into(),
            ..PqcConfig::default()
        });
        let pq: Vec<_> = g
            .iter()
            .copied()
            .filter(|n| is_post_quantum_group(*n))
            .collect();
        assert_eq!(pq, vec![NamedGroup::secp384r1MLKEM1024], "{g:?}");

        let g = groups(&PqcConfig {
            additional_kems: vec!["SecP384r1MLKEM1024".into(), "MLKEM1024".into()],
            ..PqcConfig::default()
        });
        assert_eq!(
            &g[..3],
            &[
                NamedGroup::X25519MLKEM768,
                NamedGroup::secp384r1MLKEM1024,
                NamedGroup::MLKEM1024
            ],
            "{g:?}"
        );
        assert!(g.contains(&NamedGroup::secp256r1MLKEM768));

        // ML-KEM-512 is level 1: named and allowed only with the minimum at 1.
        let named512 = |min| {
            groups(&PqcConfig {
                additional_kems: vec!["MLKEM512".into()],
                min_security_level: min,
                ..PqcConfig::default()
            })
        };
        assert!(!named512(3).contains(&NamedGroup::MLKEM512));
        assert!(named512(1).contains(&NamedGroup::MLKEM512));
    }

    /// SecP384r1MLKEM1024 -- added to the vendored rustls -- completes a
    /// handshake end to end.
    #[test]
    fn secp384r1_mlkem1024_negotiates() {
        let policy = ServerTlsPolicy::from_config(
            &tls("1.3"),
            &PqcConfig::default(),
            true,
            ClientAuth::None,
        )
        .unwrap();
        let (cert, key) = self_signed_pair().unwrap();
        let server = policy
            .builder()
            .unwrap()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let mut client_provider = rustls_post_quantum::provider();
        client_provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::SECP384R1MLKEM1024];
        let client = ClientConfig::builder_with_provider(Arc::new(client_provider))
            .with_protocol_versions(TLS13)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(VERIFY_SNI).unwrap().to_owned(),
        )
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        pump_handshake(&mut client, &mut server).unwrap();
        assert_eq!(
            client.negotiated_key_exchange_group().unwrap().name(),
            NamedGroup::secp384r1MLKEM1024
        );
    }

    #[test]
    fn pqc_enabled_negotiates_the_hybrid() {
        let policy = ServerTlsPolicy::from_config(
            &tls("1.3"),
            &PqcConfig::default(),
            true,
            ClientAuth::None,
        )
        .unwrap();
        assert!(policy.post_quantum);
        let (group, _) = negotiate(&policy, TLS13).unwrap();
        assert_eq!(group, NamedGroup::X25519MLKEM768);
    }

    /// The defect this policy exists for: with pqc.enabled false the QUIC and
    /// rustls TCP listeners still negotiated X25519MLKEM768 with any client
    /// that offered it.
    #[test]
    fn pqc_disabled_negotiates_classical_even_when_the_client_offers_the_hybrid() {
        let policy = ServerTlsPolicy::from_config(
            &tls("1.3"),
            &PqcConfig::default(),
            false,
            ClientAuth::None,
        )
        .unwrap();
        assert!(!policy.post_quantum);
        let (group, _) = negotiate(&policy, TLS13).unwrap();
        assert!(!is_post_quantum_group(group), "{group:?}");
        // The client's first classical group the server offers: this client
        // lists secp256r1 ahead of secp384r1, and X25519 is never offered.
        assert_eq!(group, NamedGroup::secp256r1);
    }

    #[test]
    fn min_version_1_3_refuses_tls_1_2() {
        let policy = ServerTlsPolicy::from_config(
            &tls("1.3"),
            &PqcConfig::default(),
            true,
            ClientAuth::None,
        )
        .unwrap();
        assert!(policy.tls13_only());
        assert!(negotiate(&policy, TLS12).is_err());
    }

    #[test]
    fn min_version_1_2_accepts_tls_1_2() {
        let policy = ServerTlsPolicy::from_config(
            &tls("1.2"),
            &PqcConfig::default(),
            true,
            ClientAuth::None,
        )
        .unwrap();
        assert!(!policy.tls13_only());
        let (group, version) = negotiate(&policy, TLS12).unwrap();
        assert_eq!(version, ProtocolVersion::TLSv1_2);
        // ML-KEM is TLS 1.3 only, so a 1.2 handshake is classical.
        assert!(!is_post_quantum_group(group));
    }

    /// `tls.enable_0rtt` on the QUIC listener.
    ///
    /// It set 16384, the TCP figure, and RFC 9001 §4.6.1 allows only
    /// 0xffffffff: rustls refuses to start a QUIC session on anything else, and
    /// noq unwraps that refusal, so the first HTTP/3 connection after turning
    /// 0-RTT on panicked the listener. Asserted at the call that failed.
    #[test]
    fn quic_zero_rtt_uses_the_only_value_quic_allows() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![VERIFY_SNI.to_string()]).unwrap();
        std::fs::write(
            dir.path().join(format!("{VERIFY_SNI}.crt")),
            cert.cert.pem(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("{VERIFY_SNI}.key")),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
        let resolver = Arc::new(super::MultiDomainCertResolver::new(dir.path()).unwrap());
        for enable_0rtt in [true, false] {
            let server = super::TlsProvider::create_rustls_config_with_resolver(
                &TlsConfig {
                    enable_0rtt,
                    ..tls("1.3")
                },
                &crate::config::PqcConfig::default(),
                true,
                ClientAuth::None,
                resolver.clone(),
            )
            .unwrap();
            assert_eq!(
                server.max_early_data_size,
                if enable_0rtt { u32::MAX } else { 0 }
            );
            rustls::quic::ServerConnection::new(
                Arc::new(server),
                rustls::quic::Version::V1,
                Vec::new(),
            )
            .expect("rustls accepts the configuration for a QUIC session");
        }
    }

    /// The QUIC listener's config, built the way the listener builds it, over
    /// a TLS handshake: the rustls `ServerConfig` QUIC wraps is where the group
    /// is chosen, so this is the HTTP/3 half of the defect.
    #[test]
    fn quic_config_honours_pqc_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![VERIFY_SNI.to_string()]).unwrap();
        std::fs::write(
            dir.path().join(format!("{VERIFY_SNI}.crt")),
            cert.cert.pem(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join(format!("{VERIFY_SNI}.key")),
            cert.signing_key.serialize_pem(),
        )
        .unwrap();
        let resolver = Arc::new(super::MultiDomainCertResolver::new(dir.path()).unwrap());
        let der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());

        for enabled in [true, false] {
            let pqc = crate::config::PqcConfig {
                enabled,
                ..crate::config::PqcConfig::default()
            };
            let server = super::TlsProvider::create_rustls_config_with_resolver(
                &tls("1.3"),
                &pqc,
                true,
                ClientAuth::None,
                resolver.clone(),
            )
            .unwrap();
            let mut roots = RootCertStore::empty();
            roots.add(der.clone()).unwrap();
            let client =
                ClientConfig::builder_with_provider(Arc::new(rustls_post_quantum::provider()))
                    .with_protocol_versions(TLS13)
                    .unwrap()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let mut client = ClientConnection::new(
                Arc::new(client),
                ServerName::try_from(VERIFY_SNI).unwrap().to_owned(),
            )
            .unwrap();
            let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
            pump_handshake(&mut client, &mut server).unwrap();
            let group = client.negotiated_key_exchange_group().unwrap().name();
            assert_eq!(
                is_post_quantum_group(group),
                enabled,
                "pqc.enabled = {enabled}: {group:?}"
            );
        }
    }

    /// `require_client_cert` refuses a client that presents none. The rustls
    /// TCP listeners used to build with no client authentication at all.
    #[test]
    fn require_client_cert_refuses_a_client_without_one() {
        let ca = rcgen::generate_simple_self_signed(vec!["client-ca.invalid".to_string()]).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, ca.cert.pem().as_bytes()).unwrap();
        let config = TlsConfig {
            require_client_cert: true,
            ca_cert_path: Some(file.path().to_path_buf()),
            ..tls("1.3")
        };
        let policy = ServerTlsPolicy::from_config(
            &config,
            &PqcConfig::default(),
            true,
            ClientAuth::Required,
        )
        .unwrap();
        assert!(policy.client_verifier.is_some());
        assert!(negotiate(&policy, TLS13).is_err());
        // Requested -- some routes need one -- lets the same client finish the
        // handshake, for the route gate to refuse where it must.
        let requested = ServerTlsPolicy::from_config(
            &config,
            &PqcConfig::default(),
            true,
            ClientAuth::Requested,
        )
        .unwrap();
        assert!(requested.client_verifier.is_some());
        assert!(negotiate(&requested, TLS13).is_ok());
        // And without the setting the same client is served.
        let open = ServerTlsPolicy::from_config(
            &tls("1.3"),
            &PqcConfig::default(),
            true,
            ClientAuth::None,
        )
        .unwrap();
        assert!(negotiate(&open, TLS13).is_ok());
    }
}

/// A config that serves the post-quantum certificate chain, for the one
/// conformance port whose subject is the certificate rather than the key
/// exchange.
///
/// Ordinary key exchange, ordinary ALPN, ordinary everything else: what differs
/// is an ML-DSA-87 chain (`conformance.pq_chain_cert`) in place of the edge's
/// own, sent compressed under RFC 8879 when the client offers a codec this
/// build also has.
///
/// Fails loudly when the chain is missing rather than falling back to the
/// ordinary resolver. A port that silently served the classical chain would
/// report every client as handling a post-quantum one.
pub fn pq_chain_server_config(
    cert: &Path,
    key: &Path,
) -> anyhow::Result<(Arc<quinn::crypto::rustls::QuicServerConfig>, ChainSize)> {
    let key = load_certified_key(cert, key)
        .with_context(|| format!("loading the post-quantum chain from {}", cert.display()))?;
    let size = ChainSize {
        certificates: key.cert.len(),
        der_bytes: key.cert.iter().map(|c| c.len()).sum(),
    };

    let mut config = RustlsServerConfig::builder_with_provider(Arc::new(build_pqc_provider()))
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| anyhow::anyhow!("failed to set protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleChain(Arc::new(key))));

    config.alpn_protocols = vec![b"h3".to_vec()];
    crate::cert_compression::apply(&mut config);

    Ok((
        Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(config).map_err(|e| {
                anyhow::anyhow!("failed to build the post-quantum QUIC config: {e}")
            })?,
        ),
        size,
    ))
}

/// The admin API's TLS under `[admin] require_mtls`.
///
/// TLS 1.3, every hybrid group preferred, and a client certificate from
/// `client_ca` required of every connection. One certificate for every name:
/// the admin API is reached by address as often as by name, and without SNI
/// the per-domain resolver would have nothing to answer with.
pub fn admin_server_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> anyhow::Result<RustlsServerConfig> {
    let tls = TlsConfig {
        min_version: "1.3".to_string(),
        ca_cert_path: Some(client_ca.to_path_buf()),
        pqc_session_tickets: false,
        ..TlsConfig::default()
    };
    let policy =
        ServerTlsPolicy::from_config(&tls, &PqcConfig::default(), true, ClientAuth::Required)?;
    let key = load_certified_key(cert, key)
        .with_context(|| format!("loading the admin certificate from {}", cert.display()))?;
    let mut config = policy
        .builder()?
        .with_cert_resolver(Arc::new(SingleChain(Arc::new(key))));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

/// One chain for every name, because this port is about the chain.
///
/// The SNI resolver would answer with whatever certificate matches the name the
/// client sent, which on a conformance port is the ordinary one — the opposite
/// of what this test needs.
#[derive(Debug)]
struct SingleChain(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for SingleChain {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

pub fn build_pqc_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls_post_quantum::provider();
    provider
        .kx_groups
        .retain(|g| g.name() != rustls::NamedGroup::X25519);
    provider.kx_groups.sort_by_key(|g| match g.name() {
        rustls::NamedGroup::X25519MLKEM768 => 0u8,
        rustls::NamedGroup::secp384r1 => 1,
        rustls::NamedGroup::secp521r1 => 2,
        rustls::NamedGroup::secp256r1 => 3,
        _ => 4,
    });

    prefer_256_bit_aeads(&mut provider);

    provider
}

/// Order 256-bit AEADs ahead of AES-128, matching what the OpenSSL listener
/// enforces for HTTP/1.1 and HTTP/2.
///
/// That listener *removes* TLS_AES_128_GCM_SHA256 outright. This cannot: RFC
/// 9001 §5.2 fixes AES-128-GCM as the AEAD for QUIC Initial packet protection,
/// and dropping the suite makes QuicServerConfig construction fail. So it stays
/// available and simply loses the preference contest — rustls picks the
/// server's first suite the client also offers, and every modern client offers
/// all three.
///
/// Without this, HTTP/2 visitors got AES-256 and HTTP/3 visitors silently got
/// AES-128 on the same hostname: the policy was written once, on one of two
/// listeners.
fn prefer_256_bit_aeads(provider: &mut rustls::crypto::CryptoProvider) {
    provider.cipher_suites.sort_by_key(|cs| match cs.suite() {
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => 0u8,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 1,
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => 2,
        _ => 3,
    });
}

/// True for a group whose key exchange includes ML-KEM, alone or in a hybrid.
///
/// Read off the name rather than listed, so a hybrid added to rustls later is
/// classified without anyone remembering to add it here.
pub fn is_post_quantum_group(group: rustls::NamedGroup) -> bool {
    format!("{group:?}").to_ascii_uppercase().contains("MLKEM")
}

/// True for a hybrid: ML-KEM combined with an elliptic-curve exchange, so a
/// break of either alone is not enough.
fn is_hybrid_group(group: rustls::NamedGroup) -> bool {
    let name = format!("{group:?}").to_ascii_uppercase();
    name.contains("MLKEM") && (name.contains("X25519") || name.contains("SECP"))
}

/// The server provider for a listener: every group this build implements,
/// shaped by `[pqc]`, with [`build_pqc_provider`]'s cipher order.
///
/// - `pqc.enabled` false (or the provider unavailable): the classical groups
///   alone.
/// - Otherwise every hybrid -- X25519MLKEM768, SecP256r1MLKEM768 and
///   SecP384r1MLKEM1024 -- led by `preferred_kem` and then `additional_kems`
///   in the order listed. A pure ML-KEM group is offered only when one of
///   those names it, and never under `require_hybrid`. A post-quantum group
///   below `min_security_level` is not offered.
/// - The classical fallback stays unless `require_hybrid` is set or
///   `fallback_to_classical` is false.
///
/// Classical means secp384r1 and secp256r1. X25519 is not offered on any
/// listener. secp256r1 is kept here although the OpenSSL listener refuses it:
/// RFC 8446 makes it the one group every TLS 1.3 implementation must support,
/// and QUIC stacks such as picotls offer nothing else classical.
///
/// Before this read `[pqc]` at all, `preferred_kem`, `require_hybrid` and
/// `fallback_to_classical` shaped a group list the OpenSSL listener logged and
/// never applied, and this provider ignored them.
///
/// Which group a handshake uses is the client's choice: rustls takes the first
/// group in the client's list that the server also offers, so the order here
/// matters to clients built from this provider, not to the server.
pub fn server_provider(post_quantum: bool, pqc: &PqcConfig) -> CryptoProvider {
    let mut provider = build_pqc_provider();
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '_'], "");
    // preferred_kem, then additional_kems as listed: the groups the
    // configuration names, which lead the offer in that order.
    let named: Vec<String> = std::iter::once(&pqc.preferred_kem)
        .chain(pqc.additional_kems.iter())
        .map(|k| norm(k))
        .filter(|k| !k.is_empty())
        .collect();
    let named_at = |g: rustls::NamedGroup| named.iter().position(|n| *n == norm(&format!("{g:?}")));
    let level = |g: rustls::NamedGroup| {
        crate::pqc_tls::PqcKemAlgorithm::from_str(&format!("{g:?}"))
            .map_or(0, |k| k.security_level())
    };
    let keep_classical = !post_quantum || (pqc.fallback_to_classical && !pqc.require_hybrid);

    let mut groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> =
        rustls::crypto::aws_lc_rs::ALL_KX_GROUPS
            .iter()
            .copied()
            .filter(|g| {
                let name = g.name();
                if name == rustls::NamedGroup::X25519 {
                    return false;
                }
                if !is_post_quantum_group(name) {
                    return keep_classical;
                }
                post_quantum
                    && level(name) >= pqc.min_security_level
                    && (is_hybrid_group(name) || (named_at(name).is_some() && !pqc.require_hybrid))
            })
            .collect();
    groups.sort_by_key(|g| {
        let name = g.name();
        match named_at(name) {
            Some(i) => i,
            None if name == rustls::NamedGroup::X25519MLKEM768 => 100,
            None if is_hybrid_group(name) => 101,
            None if is_post_quantum_group(name) => 102,
            None if name == rustls::NamedGroup::secp384r1 => 103,
            None => 104,
        }
    });
    provider.kx_groups = groups;
    provider
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&TLS13];
static TLS12_AND_TLS13: &[&rustls::SupportedProtocolVersion] = &[&TLS12, &TLS13];

/// What every rustls listener's TLS is built from: the key-exchange groups,
/// protocol versions, client authentication and session tickets the
/// configuration asks for.
///
/// Each listener used to decide these for itself, and they decided
/// differently. The QUIC listener offered X25519MLKEM768 whether or not
/// `pqc.enabled` was set. The rustls TCP listeners took rustls's crate
/// defaults, which prefer the hybrid as well, accept TLS 1.2 whatever
/// `tls.min_version` says, never ask for a client certificate and issue no
/// PQC-sealed tickets. The OpenSSL listener fixed TLS 1.3 and never asked for
/// a client certificate either. A setting honoured on one transport and
/// ignored on the next is one nobody can rely on, and for `require_client_cert`
/// that is a hole rather than a surprise: the startup probe could report mTLS
/// as not enforced, but nothing enforced it.
pub struct ServerTlsPolicy {
    /// Groups and cipher suites; see [`server_provider`].
    pub provider: Arc<CryptoProvider>,
    /// From `tls.min_version`: TLS 1.3 alone, or 1.2 and 1.3.
    pub versions: &'static [&'static rustls::SupportedProtocolVersion],
    /// From [`ClientAuth`] and `tls.ca_cert_path`.
    pub client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    /// Whether the provider offers an ML-KEM group.
    pub post_quantum: bool,
    pqc_session_tickets: bool,
    session_ticket_lifetime_secs: u32,
}

impl std::fmt::Debug for ServerTlsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTlsPolicy")
            .field(
                "groups",
                &self
                    .provider
                    .kx_groups
                    .iter()
                    .map(|g| g.name())
                    .collect::<Vec<_>>(),
            )
            .field("tls13_only", &self.tls13_only())
            .field("client_auth", &self.client_verifier.is_some())
            .field("pqc_session_tickets", &self.pqc_session_tickets)
            .finish_non_exhaustive()
    }
}

impl ServerTlsPolicy {
    /// Build the policy. `post_quantum` is `pqc.enabled`, and false as well
    /// when the post-quantum provider is unavailable; `client_auth` is
    /// `ProxyConfig::client_auth`.
    pub fn from_config(
        tls: &TlsConfig,
        pqc: &PqcConfig,
        post_quantum: bool,
        client_auth: ClientAuth,
    ) -> anyhow::Result<Self> {
        let provider = Arc::new(server_provider(post_quantum, pqc));
        if provider.kx_groups.is_empty() {
            return Err(anyhow::anyhow!(
                "[pqc] leaves no key exchange group to offer: pqc.enabled is false but \
                 no classical group is available"
            ));
        }
        let versions = if tls.min_version == "1.3" {
            TLS13_ONLY
        } else {
            TLS12_AND_TLS13
        };
        let client_verifier = if client_auth == ClientAuth::None {
            None
        } else {
            let roots = TlsProvider::load_client_ca(&tls.ca_cert_path)?;
            let builder = rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            );
            // Requested: a client without a certificate still completes the
            // handshake, and the route gate refuses it where one is needed.
            let builder = if client_auth == ClientAuth::Requested {
                builder.allow_unauthenticated()
            } else {
                builder
            };
            Some(
                builder
                    .build()
                    .map_err(|e| anyhow::anyhow!("Failed to create client verifier: {}", e))?,
            )
        };
        Ok(Self {
            post_quantum: provider
                .kx_groups
                .iter()
                .any(|g| is_post_quantum_group(g.name())),
            provider,
            versions,
            client_verifier,
            pqc_session_tickets: tls.pqc_session_tickets,
            session_ticket_lifetime_secs: tls.session_ticket_lifetime_secs,
        })
    }

    /// True when TLS 1.2 is refused.
    pub fn tls13_only(&self) -> bool {
        !self
            .versions
            .iter()
            .any(|v| v.version == rustls::ProtocolVersion::TLSv1_2)
    }

    /// A `ServerConfig` builder carrying the provider, versions and client
    /// authentication, ready for a certificate or resolver.
    pub fn builder(
        &self,
    ) -> anyhow::Result<rustls::ConfigBuilder<RustlsServerConfig, rustls::server::WantsServerCert>>
    {
        let with_versions = RustlsServerConfig::builder_with_provider(self.provider.clone())
            .with_protocol_versions(self.versions)
            .map_err(|e| anyhow::anyhow!("Failed to set protocol versions: {}", e))?;
        Ok(match &self.client_verifier {
            Some(v) => with_versions.with_client_cert_verifier(v.clone()),
            None => with_versions.with_no_client_auth(),
        })
    }

    /// Install the ML-KEM-1024 session ticketer when `tls.pqc_session_tickets`
    /// asks for it. Refuses rather than falls back: an operator who asked for
    /// PQC-protected resumption must not silently get none.
    pub fn apply_tickets(&self, config: &mut RustlsServerConfig) -> anyhow::Result<()> {
        if self.pqc_session_tickets {
            let ticketer = crate::pqc_tickets::PqcTicketer::new(self.session_ticket_lifetime_secs)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "pqc_session_tickets is enabled but the ticketer could not start: {}",
                        e
                    )
                })?;
            config.ticketer = Arc::new(ticketer);
        }
        Ok(())
    }
}

impl TlsProvider {
    /// Create a new TLS provider with initial configuration
    pub fn new(
        tls_config: &TlsConfig,
        pqc_config: &PqcConfig,
        client_auth: ClientAuth,
    ) -> anyhow::Result<Self> {
        // Check PQC availability
        let pqc_available = if pqc_config.enabled {
            Self::check_pqc_availability(pqc_config)
        } else {
            false
        };

        if pqc_config.enabled && !pqc_available {
            warn!("PQC requested but not available - falling back to classical TLS");
        }

        // Build per-domain SNI resolver from the certs directory
        let certs_dir = tls_config
            .cert_path
            .parent()
            .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));
        let resolver = Arc::new(MultiDomainCertResolver::new(certs_dir)?);

        // Create initial QUIC server config using the resolver
        let rustls_config = Self::create_rustls_config_with_resolver(
            tls_config,
            pqc_config,
            pqc_available,
            client_auth,
            Arc::clone(&resolver),
        )?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

        // Watch the certs + ECH configs directory mtimes for change detection
        let cert_modified = Self::combined_watched_mtime(certs_dir);

        Ok(Self {
            server_config: ArcSwap::new(Arc::new(quic_config)),
            tls_config: RwLock::new(tls_config.clone()),
            pqc_config: RwLock::new(pqc_config.clone()),
            last_cert_modified: RwLock::new(cert_modified),
            pqc_available: RwLock::new(pqc_available),
            client_auth,
            resolver,
        })
    }

    /// Get current QUIC server configuration
    pub fn get_quic_server_config(&self) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
        self.server_config.load_full()
    }

    /// A QUIC server configuration that offers 0-RTT and then always refuses it.
    ///
    /// For the conformance suite's `q-zero-rtt-reject`, which needs a client to
    /// genuinely attempt early data and genuinely have it rejected. Both halves
    /// have to be arranged, and they pull in opposite directions.
    ///
    /// **Offering it.** A client only sends early data if a previous session
    /// ticket said it could, and rustls issues no tickets at all without a
    /// ticketer. The production configuration sets `max_early_data_size` to zero
    /// unless 0-RTT is explicitly enabled — a sound default, and one that would
    /// make this test permanently unexercisable. Here it is opened up.
    ///
    /// **Refusing it.** Not by rejecting the early data after the fact, but by
    /// making acceptance impossible: the accepted key-exchange groups are cut
    /// down to ones no client puts in its speculative first key share, so the
    /// server must answer with a HelloRetryRequest. RFC 8446 §4.2.10 has any
    /// 0-RTT rejected whenever a HelloRetryRequest is sent, so the rejection is
    /// structural rather than conditional — it does not depend on getting a
    /// decision right at the moment the early data arrives.
    ///
    /// The groups left in are ones every TLS 1.3 implementation supports and
    /// almost none key-shares first, so the handshake always completes, one
    /// round trip later than it would have.
    ///
    /// Not for production traffic: it costs every visitor an extra round trip
    /// and permits early data on a proxy that does not deduplicate replays.
    pub fn build_zero_rtt_reject_config(
        &self,
    ) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
        zero_rtt_reject_server_config(self.resolver.clone())
    }

    /// The accepting counterpart, for `q-zero-rtt-replay`.
    pub fn build_zero_rtt_accept_config(
        &self,
    ) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
        zero_rtt_accept_server_config(self.resolver.clone())
    }

    /// A config that will negotiate only `group`, for the TLS conformance tier.
    pub fn build_single_group_config(
        &self,
        group: rustls::NamedGroup,
        impairment: Option<rustls::server::KeyShareImpairment>,
    ) -> anyhow::Result<Arc<quinn::crypto::rustls::QuicServerConfig>> {
        single_group_server_config(self.resolver.clone(), group, impairment)
    }

    /// A config serving the post-quantum certificate chain, for
    /// `t-cert-compression-pq`.
    pub fn build_pq_chain_config(
        &self,
        cert: &Path,
        key: &Path,
    ) -> anyhow::Result<(Arc<quinn::crypto::rustls::QuicServerConfig>, ChainSize)> {
        pq_chain_server_config(cert, key)
    }

    /// Check if PQC is available and enabled
    pub fn is_pqc_enabled(&self) -> bool {
        *self.pqc_available.read()
    }

    /// Reload TLS certificates — refreshes the shared SNI resolver then rebuilds QUIC config.
    /// Called when ACME issues a new cert or the certs directory changes.
    pub fn reload_certificates(&self) -> anyhow::Result<()> {
        let tls_config = self.tls_config.read().clone();
        let pqc_config = self.pqc_config.read().clone();
        let pqc_available = *self.pqc_available.read();

        // Reload all per-domain certs from disk into the shared resolver.
        // HTTP listeners that hold Arc::clone(&resolver) see the new certs immediately.
        self.resolver.reload()?;

        // Rebuild the QUIC server config with the refreshed resolver
        let rustls_config = Self::create_rustls_config_with_resolver(
            &tls_config,
            &pqc_config,
            pqc_available,
            self.client_auth,
            Arc::clone(&self.resolver),
        )?;
        let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC server config: {}", e))?;

        self.server_config.store(Arc::new(quic_config));

        // Update the watched directory mtime (certs + ECH configs)
        let certs_dir = tls_config
            .cert_path
            .parent()
            .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));
        *self.last_cert_modified.write() = Self::combined_watched_mtime(certs_dir);

        info!("TLS certificates reloaded (SNI resolver + QUIC config refreshed)");
        Ok(())
    }

    /// Check if certificates (or ECH configs — see `ech_config::ECH_CONFIG_DIR`,
    /// rotated independently by `ech-keygen`) need reloading, by watching
    /// both directories' mtimes.
    pub fn needs_reload(&self) -> bool {
        let tls_config = self.tls_config.read();
        let certs_dir = tls_config
            .cert_path
            .parent()
            .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));
        let current_modified = Self::combined_watched_mtime(certs_dir);

        let last_modified = *self.last_cert_modified.read();

        match (current_modified, last_modified) {
            (Some(current), Some(last)) => current > last,
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// The newer of the certs directory's and the ECH configs directory's
    /// mtime — either one changing is a reason to rebuild the TLS config.
    fn combined_watched_mtime(certs_dir: &Path) -> Option<SystemTime> {
        let certs_mtime = std::fs::metadata(certs_dir)
            .ok()
            .and_then(|m| m.modified().ok());
        let ech_mtime = std::fs::metadata(crate::ech_config::ECH_CONFIG_DIR)
            .ok()
            .and_then(|m| m.modified().ok());
        certs_mtime.max(ech_mtime)
    }

    /// Update configuration (for hot-reload)
    pub fn update_config(
        &self,
        tls_config: &TlsConfig,
        pqc_config: &PqcConfig,
    ) -> anyhow::Result<()> {
        // Update stored configs
        *self.tls_config.write() = tls_config.clone();
        *self.pqc_config.write() = pqc_config.clone();

        // Re-check PQC availability
        let pqc_available = if pqc_config.enabled {
            Self::check_pqc_availability(pqc_config)
        } else {
            false
        };
        *self.pqc_available.write() = pqc_available;

        // Reload certificates with new config
        self.reload_certificates()
    }

    /// Check if PQC is available on this system
    fn check_pqc_availability(pqc_config: &PqcConfig) -> bool {
        // Always try rustls-post-quantum first (preferred, native Rust implementation)
        if Self::check_rustls_pqc() {
            info!("Using rustls-post-quantum provider for PQC (X25519MLKEM768)");
            return true;
        }

        // Fallback to OpenSSL if configured
        match pqc_config.provider.as_str() {
            "openssl3.5" => Self::check_openssl_pqc(pqc_config),
            "rustls-pqc" => false, // Already tried above
            _ => {
                warn!("Unknown PQC provider: {}", pqc_config.provider);
                false
            }
        }
    }

    /// Check if OpenSSL 3.5 with OQS provider is available
    fn check_openssl_pqc(pqc_config: &PqcConfig) -> bool {
        #[cfg(feature = "pqc")]
        {
            use std::process::Command;

            let openssl_path = pqc_config
                .openssl_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "openssl".to_string());

            // Set library path for OpenSSL 3.5
            let lib_path = pqc_config
                .openssl_lib_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            // P1-fix: clear the parent environment before spawning.
            // pqc_tls.rs::check_openssl35 already does this; tls.rs previously did not,
            // leaving LD_PRELOAD, DYLD_INSERT_LIBRARIES, etc. from the parent process
            // open to injection.  Align with the hardened pattern from pqc_tls.rs.
            let version_output = Command::new(&openssl_path)
                .arg("version")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("LD_LIBRARY_PATH", &lib_path)
                .output();

            match version_output {
                Ok(output) => {
                    let version_str = String::from_utf8_lossy(&output.stdout);
                    if version_str.contains("3.5")
                        || version_str.contains("3.4")
                        || version_str.contains("3.3")
                    {
                        info!("OpenSSL version detected: {}", version_str.trim());

                        // Check for OQS provider
                        let provider_output = Command::new(&openssl_path)
                            .args(["list", "-providers"])
                            .env_clear()
                            .env("PATH", "/usr/bin:/bin")
                            .env("LD_LIBRARY_PATH", &lib_path)
                            .output();

                        match provider_output {
                            Ok(output) => {
                                let providers = String::from_utf8_lossy(&output.stdout);
                                if providers.contains("oqs") || providers.contains("OQS") {
                                    info!(
                                        "OQS provider detected - PQC hybrid key exchange available"
                                    );
                                    return true;
                                }

                                // Check for built-in Kyber support (OpenSSL 3.5+)
                                let kem_output = Command::new(&openssl_path)
                                    .args(["list", "-kem-algorithms"])
                                    .env_clear()
                                    .env("PATH", "/usr/bin:/bin")
                                    .env("LD_LIBRARY_PATH", &lib_path)
                                    .output();

                                if let Ok(output) = kem_output {
                                    let kems = String::from_utf8_lossy(&output.stdout);
                                    if kems.contains("kyber")
                                        || kems.contains("Kyber")
                                        || kems.contains("ML-KEM")
                                    {
                                        info!("Kyber/ML-KEM KEM detected - PQC available natively");
                                        return true;
                                    }
                                }

                                warn!("OpenSSL found but no PQC KEM algorithms available");
                                false
                            }
                            Err(e) => {
                                warn!("Failed to check OpenSSL providers: {}", e);
                                false
                            }
                        }
                    } else {
                        warn!(
                            "OpenSSL version {} does not support PQC",
                            version_str.trim()
                        );
                        false
                    }
                }
                Err(e) => {
                    warn!("Failed to check OpenSSL version: {}", e);
                    false
                }
            }
        }

        #[cfg(not(feature = "pqc"))]
        {
            warn!("PQC feature not compiled - OpenSSL PQC unavailable");
            false
        }
    }

    /// Check if rustls PQC support is available via aws-lc-rs
    fn check_rustls_pqc() -> bool {
        // Check if rustls-post-quantum provider is available
        // This uses aws-lc-rs which has X25519MLKEM768 support
        match rustls_post_quantum::provider().install_default() {
            Ok(_) => {
                info!("rustls-post-quantum provider installed - X25519MLKEM768 hybrid key exchange available");
                true
            }
            Err(_) => {
                // Provider might already be installed, check if it's available
                if CryptoProvider::get_default().is_some() {
                    info!("Default crypto provider already set - checking for PQC support");
                    true
                } else {
                    warn!("Failed to install rustls-post-quantum provider");
                    false
                }
            }
        }
    }

    /// Create rustls server configuration using the shared SNI cert resolver.
    pub(crate) fn create_rustls_config_with_resolver(
        tls_config: &TlsConfig,
        pqc_config: &PqcConfig,
        pqc_available: bool,
        client_auth: ClientAuth,
        resolver: Arc<MultiDomainCertResolver>,
    ) -> anyhow::Result<RustlsServerConfig> {
        // Groups, versions, client authentication and tickets come from the one
        // policy every rustls listener builds from -- see ServerTlsPolicy.
        //
        // TLS_AES_128_GCM_SHA256 stays in the suite list: QUIC (RFC 9001) needs
        // it for Initial packet protection. X25519 is not offered; a client whose
        // only key_share is X25519 gets a HelloRetryRequest for the first group
        // in its own list that this server offers.
        let policy = ServerTlsPolicy::from_config(
            tls_config,
            pqc_config,
            pqc_config.enabled && pqc_available,
            client_auth,
        )?;
        info!(
            "TLS (QUIC/HTTP3) cipher suites: {} — named groups: {:?}",
            policy.provider.cipher_suites.len(),
            policy
                .provider
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>()
        );
        if policy.tls13_only() {
            info!("TLS min_version = 1.3 — disabling TLS 1.2");
        } else {
            info!("TLS min_version = 1.2 — allowing TLS 1.2 and 1.3");
        }

        let mut config = policy.builder()?.with_cert_resolver(resolver);
        policy.apply_tickets(&mut config)?;

        // Configure ALPN protocols
        config.alpn_protocols = tls_config
            .alpn_protocols
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();

        info!("ALPN protocols: {:?}", tls_config.alpn_protocols);

        // Encrypted Client Hello (ECH) - optional, loaded from disk (rotated
        // by ech-keygen/ech-rotate.timer). Absent -> normal non-ECH TLS,
        // exactly as before this existed.
        config.ech = crate::ech_config::load();
        crate::cert_compression::apply(&mut config);

        // Configure 0-RTT (early data)
        // L-5: 0-RTT is a replay-attack risk. The proxy forwards early data to
        // backends without deduplication. Only enable on routes whose backends
        // are safe to receive replayed requests, and restrict to idempotent methods
        // via `tls.zero_rtt_safe_methods` (default: GET, HEAD only).
        if tls_config.enable_0rtt {
            // This configuration is the QUIC listener's, and RFC 9001 §4.6.1
            // allows exactly one non-zero value here: 0xffffffff, with QUIC's
            // own flow control bounding what is sent. It was 16384, the TCP
            // figure, and a client MUST treat any other value in a ticket as
            // PROTOCOL_VIOLATION -- so turning 0-RTT on would have failed every
            // resumption rather than enable one.
            //
            // Requests that arrive in 0-RTT are served before the handshake
            // completes and marked `x-tls-early-data`, which is what the route
            // gate's 425 answers are decided on.
            config.max_early_data_size = u32::MAX;
            warn!(
                "⚠️  0-RTT (early data) ENABLED — replay-attack risk. \
                 Safe HTTP methods: {:?}. \
                 Non-idempotent requests (POST/PUT/DELETE/PATCH) forwarded via 0-RTT \
                 may be delivered TWICE to backends with no indication. \
                 Ensure routes serving non-GET/HEAD traffic have `allow_0rtt = false` \
                 (the default). Set `tls.zero_rtt_safe_methods` if your backends \
                 implement idempotency-key deduplication.",
                tls_config.zero_rtt_safe_methods
            );
        } else {
            // Disable 0-RTT for security
            config.max_early_data_size = 0;
            info!("0-RTT disabled (secure default)");
        }

        // Log PQC status
        if pqc_config.enabled && pqc_available {
            info!("🛡️  PQC hybrid key exchange ACTIVE via rustls-post-quantum");
            info!("🔐 Key Exchange: X25519MLKEM768 (hybrid classical + post-quantum)");
            info!("📊 Security Level: NIST Level 3 (192-bit equivalent)");
        } else if pqc_config.enabled {
            warn!("PQC requested but not available - using classical key exchange");
        }

        Ok(config)
    }

    /// Load certificates from PEM file.
    // L-1: Uses rustls-pki-types PEM API (replaces unmaintained rustls-pemfile)
    fn load_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
        let file = File::open(path)
            .map_err(|e| anyhow::anyhow!("Failed to open certificate file {:?}: {}", path, e))?;
        let mut reader = BufReader::new(file);

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse certificates from {:?}: {}", path, e))?;

        if certs.is_empty() {
            return Err(anyhow::anyhow!("No certificates found in {:?}", path));
        }

        Ok(certs)
    }

    /// Load client CA certificates for mTLS
    fn load_client_ca(path: &Option<std::path::PathBuf>) -> anyhow::Result<rustls::RootCertStore> {
        let mut root_store = rustls::RootCertStore::empty();

        if let Some(ca_path) = path {
            let certs = Self::load_certificates(ca_path)?;
            for cert in certs {
                root_store
                    .add(cert)
                    .map_err(|e| anyhow::anyhow!("Failed to add CA certificate: {}", e))?;
            }
            info!("Loaded {} client CA certificates", root_store.len());
        } else {
            // Load system root certificates
            let native_certs = rustls_native_certs::load_native_certs();
            let mut added = 0;
            let mut failed = 0;
            for cert in native_certs.certs {
                match root_store.add(cert) {
                    Ok(()) => added += 1,
                    Err(e) => {
                        debug!("Failed to add system root certificate: {}", e);
                        failed += 1;
                    }
                }
            }
            if failed > 0 {
                info!(
                    "Loaded {} system root certificates ({} failed - likely duplicates)",
                    added, failed
                );
            } else {
                info!("Loaded {} system root certificates", root_store.len());
            }
        }

        Ok(root_store)
    }

    /// Get certificate information for admin API
    pub fn get_cert_info(&self) -> CertificateInfo {
        let tls_config = self.tls_config.read();
        let last_modified = *self.last_cert_modified.read();

        CertificateInfo {
            cert_path: tls_config.cert_path.to_string_lossy().to_string(),
            key_path: tls_config.key_path.to_string_lossy().to_string(),
            pqc_enabled: *self.pqc_available.read(),
            pqc_provider: self.pqc_config.read().provider.clone(),
            alpn_protocols: tls_config.alpn_protocols.clone(),
            last_reloaded: last_modified
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()),
        }
    }
}

/// Certificate information for admin API
#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificateInfo {
    pub cert_path: String,
    pub key_path: String,
    pub pqc_enabled: bool,
    pub pqc_provider: String,
    pub alpn_protocols: Vec<String>,
    pub last_reloaded: Option<String>,
}

// Note: PQC key exchange functionality is provided by pqc_tls::PqcKemAlgorithm
