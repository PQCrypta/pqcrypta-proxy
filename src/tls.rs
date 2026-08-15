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

use arc_swap::ArcSwap;
use parking_lot::RwLock;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use rustls::server::ServerConfig as RustlsServerConfig;
use rustls::version::{TLS12, TLS13};
// L-1: Migrated from unmaintained rustls-pemfile to rustls-pki-types PEM parsing API
use rustls_pki_types::pem::PemObject;
use tracing::{debug, info, warn};

use crate::config::{PqcConfig, TlsConfig};

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

    // Create a signing key using the installed crypto provider
    let provider = CryptoProvider::get_default()
        .ok_or_else(|| anyhow::anyhow!("No rustls CryptoProvider installed"))?;
    let signing_key = provider
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
    provider
}

impl TlsProvider {
    /// Create a new TLS provider with initial configuration
    pub fn new(tls_config: &TlsConfig, pqc_config: &PqcConfig) -> anyhow::Result<Self> {
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
            resolver,
        })
    }

    /// Get current QUIC server configuration
    pub fn get_quic_server_config(&self) -> Arc<quinn::crypto::rustls::QuicServerConfig> {
        self.server_config.load_full()
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
        resolver: Arc<MultiDomainCertResolver>,
    ) -> anyhow::Result<RustlsServerConfig> {
        // Build the base PQC-aware crypto provider. Shared with the startup
        // verification handshake so that what is verified is what serves — a
        // separately-constructed provider could drift from this one and make the
        // attestation describe a stack nothing uses.
        let pq_provider = build_pqc_provider();

        // ── A+ Key Exchange ───────────────────────────────────────────────────
        // NOTE: TLS_AES_128_GCM_SHA256 is intentionally kept in rustls cipher suites.
        // QUIC (RFC 9001) requires it for initial packet protection; removing it
        // causes QuicServerConfig creation to fail. The 256-bit cipher restriction
        // for HTTP/1.1 and HTTP/2 (what SSL Labs tests) is handled by the OpenSSL
        // stack via apply_pqc_groups() in pqc_tls.rs.
        // Remove X25519 (128-bit / ~3072-bit RSA equivalent → 90% SSL Labs score).
        // Clients that offer only an X25519 key_share receive HelloRetryRequest
        // and fall back to secp384r1 (192-bit → 100%). secp256r1 is kept as a
        // last-resort fallback since RFC 8446 mandates all TLS 1.3 implementations
        // support it.  Preferred order: X25519MLKEM768 (PQC) → secp384r1 → secp256r1.
        if pqc_config.enabled && pqc_available {
            info!("Using rustls-post-quantum crypto provider with X25519MLKEM768 (PQC enabled)");
        } else {
            info!("Using rustls-post-quantum crypto provider (PQC fallback to classical)");
        }
        info!(
            "TLS (QUIC/HTTP3) cipher suites: {} — named groups: {:?}",
            pq_provider.cipher_suites.len(),
            pq_provider
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect::<Vec<_>>()
        );

        let crypto_provider = Arc::new(pq_provider);

        // Create base configuration with the appropriate crypto provider
        // SEC-01: Enforce the configured minimum TLS version instead of accepting
        // the rustls safe-default range (which includes TLS 1.2).
        let protocol_versions: &[&rustls::SupportedProtocolVersion] =
            if tls_config.min_version == "1.3" {
                info!("TLS min_version = 1.3 — disabling TLS 1.2");
                &[&TLS13]
            } else {
                info!("TLS min_version = 1.2 — allowing TLS 1.2 and 1.3");
                &[&TLS12, &TLS13]
            };

        let mut config = if tls_config.require_client_cert {
            // mTLS configuration
            let client_ca = Self::load_client_ca(&tls_config.ca_cert_path)?;
            let client_auth = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_ca))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to create client verifier: {}", e))?;

            RustlsServerConfig::builder_with_provider(crypto_provider)
                .with_protocol_versions(protocol_versions)
                .map_err(|e| anyhow::anyhow!("Failed to set protocol versions: {}", e))?
                .with_client_cert_verifier(client_auth)
                .with_cert_resolver(resolver)
        } else {
            // Standard TLS configuration with SNI per-domain cert resolver
            RustlsServerConfig::builder_with_provider(crypto_provider)
                .with_protocol_versions(protocol_versions)
                .map_err(|e| anyhow::anyhow!("Failed to set protocol versions: {}", e))?
                .with_no_client_auth()
                .with_cert_resolver(resolver)
        };

        // Install the ML-KEM-1024 session ticketer when configured. rustls
        // issues no tickets without one, so this is what makes TLS 1.3
        // resumption available at all — pqc_session_tickets used to describe a
        // ticketer that did not exist.
        if tls_config.pqc_session_tickets {
            match crate::pqc_tickets::PqcTicketer::new(tls_config.session_ticket_lifetime_secs) {
                Ok(ticketer) => config.ticketer = Arc::new(ticketer),
                Err(e) => {
                    // Refuse rather than fall back to no tickets: an operator
                    // who asked for PQC-protected resumption must not silently
                    // get none.
                    return Err(anyhow::anyhow!(
                        "pqc_session_tickets is enabled but the ticketer could not start: {}",
                        e
                    ));
                }
            }
        }

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

        // Configure 0-RTT (early data)
        // L-5: 0-RTT is a replay-attack risk. The proxy forwards early data to
        // backends without deduplication. Only enable on routes whose backends
        // are safe to receive replayed requests, and restrict to idempotent methods
        // via `tls.zero_rtt_safe_methods` (default: GET, HEAD only).
        if tls_config.enable_0rtt {
            // Enable 0-RTT with 16KB max early data
            config.max_early_data_size = 16384;
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
