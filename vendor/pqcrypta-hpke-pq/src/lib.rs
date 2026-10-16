//! Post-quantum HPKE (RFC 9180) suites for rustls.
//!
//! Encrypted Client Hello seals the inner ClientHello, the real server name
//! included, to an HPKE key published in DNS. rustls's own HPKE suites are the
//! RFC 9180 Diffie-Hellman KEMs, so every ECH config built on them is exposed
//! to harvest-now-decrypt-later: record the handshake today, read the name
//! once a quantum computer exists. These suites put a post-quantum KEM under
//! the same `rustls::crypto::hpke::Hpke` trait:
//!
//! - X-Wing (0x647A, ML-KEM-768 combined with X25519), the CFRG hybrid;
//! - ML-KEM-768 (0x0041) and ML-KEM-1024 (0x0042), pure.
//!
//! Each with HKDF-SHA256 and AES-128-GCM, AES-256-GCM or ChaCha20Poly1305,
//! and ML-KEM-1024 with HKDF-SHA384 and AES-256-GCM as well. The construction
//! is RustCrypto's `hpke` (draft-ietf-hpke-pq), and the tests open the HPKE
//! working group's published test vectors through this adapter.

use core::marker::PhantomData;

use hpke::aead::{Aead, AeadCtxR, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::{HkdfSha256, HkdfSha384, Kdf};
use hpke::kem::{MlKem1024, MlKem768, XWing};
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use rustls::Error;

/// Names the three algorithms without owning any of them: a `fn` pointer type
/// is `Send + Sync` whatever its parameters are, so a suite is a static.
type Algorithms<A, K, M> = PhantomData<fn() -> (A, K, M)>;

/// One HPKE suite in base mode: an AEAD, a KDF and a KEM.
pub struct PqHpke<A, K, M>(Algorithms<A, K, M>);

impl<A, K, M> PqHpke<A, K, M> {
    const fn new() -> Self {
        PqHpke(PhantomData)
    }
}

impl<A: Aead, K: Kdf, M: Kem> PqHpke<A, K, M> {
    /// The KEM's IANA identifier.
    pub fn kem_id(&self) -> u16 {
        M::KEM_ID
    }
}

impl<A: Aead, K: Kdf, M: Kem> core::fmt::Debug for PqHpke<A, K, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PqHpke(kem=0x{:04X}, kdf=0x{:04X}, aead=0x{:04X})",
            M::KEM_ID,
            K::KDF_ID,
            A::AEAD_ID
        )
    }
}

fn failed(e: hpke::HpkeError) -> Error {
    Error::General(format!("post-quantum HPKE: {e}"))
}

fn public_key<M: Kem>(key: &HpkePublicKey) -> Result<M::PublicKey, Error> {
    M::PublicKey::from_bytes(&key.0).map_err(failed)
}

fn private_key<M: Kem>(key: &HpkePrivateKey) -> Result<M::PrivateKey, Error> {
    M::PrivateKey::from_bytes(key.secret_bytes()).map_err(failed)
}

fn encapsulated<M: Kem>(enc: &EncapsulatedSecret) -> Result<M::EncappedKey, Error> {
    M::EncappedKey::from_bytes(&enc.0).map_err(failed)
}

impl<A, K, M> Hpke for PqHpke<A, K, M>
where
    A: Aead + 'static,
    K: Kdf + 'static,
    M: Kem + 'static,
    AeadCtxS<A, K, M>: Send + Sync,
    AeadCtxR<A, K, M>: Send + Sync,
{
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, ciphertext) = hpke::single_shot_seal::<A, K, M>(
            &OpModeS::Base,
            &public_key::<M>(pub_key)?,
            info,
            plaintext,
            aad,
        )
        .map_err(failed)?;
        Ok((EncapsulatedSecret(enc.to_bytes().to_vec()), ciphertext))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (enc, context) =
            hpke::setup_sender::<A, K, M>(&OpModeS::Base, &public_key::<M>(pub_key)?, info)
                .map_err(failed)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(Sealer(context)),
        ))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        hpke::single_shot_open::<A, K, M>(
            &OpModeR::Base,
            &private_key::<M>(secret_key)?,
            &encapsulated::<M>(enc)?,
            info,
            ciphertext,
            aad,
        )
        .map_err(failed)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let context = hpke::setup_receiver::<A, K, M>(
            &OpModeR::Base,
            &private_key::<M>(secret_key)?,
            &encapsulated::<M>(enc)?,
            info,
        )
        .map_err(failed)?;
        Ok(Box::new(Opener(context)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (private, public) = M::gen_keypair();
        Ok((
            HpkePublicKey(public.to_bytes().to_vec()),
            HpkePrivateKey::from(private.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::from(M::KEM_ID),
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::from(K::KDF_ID),
                aead_id: HpkeAead::from(A::AEAD_ID),
            },
        }
    }
}

/// A sender context. Its keys are not printed.
struct Sealer<A: Aead, K: Kdf, M: Kem>(AeadCtxS<A, K, M>);

impl<A: Aead, K: Kdf, M: Kem> core::fmt::Debug for Sealer<A, K, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sealer")
    }
}

impl<A, K, M> HpkeSealer for Sealer<A, K, M>
where
    A: Aead + 'static,
    K: Kdf + 'static,
    M: Kem + 'static,
    AeadCtxS<A, K, M>: Send + Sync,
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(failed)
    }
}

/// A receiver context. Its keys are not printed.
struct Opener<A: Aead, K: Kdf, M: Kem>(AeadCtxR<A, K, M>);

impl<A: Aead, K: Kdf, M: Kem> core::fmt::Debug for Opener<A, K, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Opener")
    }
}

impl<A, K, M> HpkeOpener for Opener<A, K, M>
where
    A: Aead + 'static,
    K: Kdf + 'static,
    M: Kem + 'static,
    AeadCtxR<A, K, M>: Send + Sync,
{
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.open(ciphertext, aad).map_err(failed)
    }
}

pub static X_WING_HKDF_SHA256_AES_256: PqHpke<AesGcm256, HkdfSha256, XWing> = PqHpke::new();
pub static X_WING_HKDF_SHA256_AES_128: PqHpke<AesGcm128, HkdfSha256, XWing> = PqHpke::new();
pub static X_WING_HKDF_SHA256_CHACHA20_POLY1305: PqHpke<ChaCha20Poly1305, HkdfSha256, XWing> =
    PqHpke::new();
pub static ML_KEM_768_HKDF_SHA256_AES_256: PqHpke<AesGcm256, HkdfSha256, MlKem768> = PqHpke::new();
pub static ML_KEM_768_HKDF_SHA256_AES_128: PqHpke<AesGcm128, HkdfSha256, MlKem768> = PqHpke::new();
pub static ML_KEM_768_HKDF_SHA256_CHACHA20_POLY1305: PqHpke<
    ChaCha20Poly1305,
    HkdfSha256,
    MlKem768,
> = PqHpke::new();
pub static ML_KEM_1024_HKDF_SHA384_AES_256: PqHpke<AesGcm256, HkdfSha384, MlKem1024> =
    PqHpke::new();
pub static ML_KEM_1024_HKDF_SHA256_AES_256: PqHpke<AesGcm256, HkdfSha256, MlKem1024> =
    PqHpke::new();

/// Every suite here, X-Wing first: the hybrid keeps X25519's assurance while
/// ML-KEM is young, which is why it is the CFRG's choice for this job.
pub static ALL_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    &X_WING_HKDF_SHA256_AES_256,
    &X_WING_HKDF_SHA256_AES_128,
    &X_WING_HKDF_SHA256_CHACHA20_POLY1305,
    &ML_KEM_768_HKDF_SHA256_AES_256,
    &ML_KEM_768_HKDF_SHA256_AES_128,
    &ML_KEM_768_HKDF_SHA256_CHACHA20_POLY1305,
    &ML_KEM_1024_HKDF_SHA384_AES_256,
    &ML_KEM_1024_HKDF_SHA256_AES_256,
];

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &[u8] = b"tls ech\0example ECHConfig";
    const AAD: &[u8] = b"outer ClientHello";
    const HELLO: &[u8] = b"inner ClientHello naming the real server";

    #[test]
    fn every_suite_seals_and_opens_through_the_rustls_trait() {
        for suite in ALL_SUPPORTED_SUITES {
            let (public, private) = suite.generate_key_pair().unwrap();
            let (enc, sealed) = suite.seal(INFO, AAD, HELLO, &public).unwrap();
            assert_eq!(
                suite.open(&enc, INFO, AAD, &sealed, &private).unwrap(),
                HELLO
            );
            // The wrong additional data fails, as ECH relies on
            assert!(suite
                .open(&enc, INFO, b"another hello", &sealed, &private)
                .is_err());
            // A context carries a sequence of messages, in order
            let (enc, mut sealer) = suite.setup_sealer(INFO, &public).unwrap();
            let mut opener = suite.setup_opener(&enc, INFO, &private).unwrap();
            for n in 0..3u8 {
                let c = sealer.seal(AAD, &[n; 40]).unwrap();
                assert_eq!(opener.open(AAD, &c).unwrap(), [n; 40]);
            }
        }
    }

    #[test]
    fn suites_carry_their_iana_identifiers_and_key_sizes() {
        let ids: Vec<(u16, u16, u16)> = ALL_SUPPORTED_SUITES
            .iter()
            .map(|s| {
                let s = s.suite();
                (
                    u16::from(s.kem),
                    u16::from(s.sym.kdf_id),
                    u16::from(s.sym.aead_id),
                )
            })
            .collect();
        assert_eq!(ids[0], (0x647A, 0x0001, 0x0002));
        assert!(ids.contains(&(0x0041, 0x0001, 0x0001)));
        assert!(ids.contains(&(0x0042, 0x0002, 0x0002)));
        let (pk, _) = X_WING_HKDF_SHA256_AES_128.generate_key_pair().unwrap();
        assert_eq!(pk.0.len(), 1216);
        let (pk, _) = ML_KEM_768_HKDF_SHA256_AES_128.generate_key_pair().unwrap();
        assert_eq!(pk.0.len(), 1184);
        let (pk, _) = ML_KEM_1024_HKDF_SHA384_AES_256.generate_key_pair().unwrap();
        assert_eq!(pk.0.len(), 1568);
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        kem_id: u16,
        kdf_id: u16,
        aead_id: u16,
        info: String,
        #[serde(rename = "skRm")]
        recipient_private: String,
        enc: String,
        encryptions: Vec<Encryption>,
    }

    #[derive(serde::Deserialize)]
    struct Encryption {
        aad: String,
        ct: String,
        pt: String,
    }

    /// The HPKE working group's published vectors for these KEMs
    /// (draft-ietf-hpke-pq, as RustCrypto's hpke 0.14 carries them in
    /// test-vectors/pq-6433c8f.json), one per KEM this crate ships: each
    /// sequence of ciphertexts opens to its plaintexts through the rustls
    /// trait, one-shot and through a context. The vectors were produced by
    /// the draft's reference code, so agreement here is agreement with
    /// something that is not this crate.
    #[test]
    fn the_published_vectors_open() {
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../tests/vectors/draft-ietf-hpke-pq.json")).unwrap();
        let mut opened = std::collections::BTreeSet::new();
        for v in &vectors {
            let suite = ALL_SUPPORTED_SUITES
                .iter()
                .find(|s| {
                    let s = s.suite();
                    (
                        u16::from(s.kem),
                        u16::from(s.sym.kdf_id),
                        u16::from(s.sym.aead_id),
                    ) == (v.kem_id, v.kdf_id, v.aead_id)
                })
                .unwrap_or_else(|| panic!("no suite for 0x{:04X}", v.kem_id));
            let info = hex::decode(&v.info).unwrap();
            let key = HpkePrivateKey::from(hex::decode(&v.recipient_private).unwrap());
            let enc = EncapsulatedSecret(hex::decode(&v.enc).unwrap());
            let first = &v.encryptions[0];
            assert_eq!(
                suite
                    .open(
                        &enc,
                        &info,
                        &hex::decode(&first.aad).unwrap(),
                        &hex::decode(&first.ct).unwrap(),
                        &key
                    )
                    .unwrap(),
                hex::decode(&first.pt).unwrap()
            );
            let mut opener = suite.setup_opener(&enc, &info, &key).unwrap();
            for e in &v.encryptions {
                let pt = opener
                    .open(&hex::decode(&e.aad).unwrap(), &hex::decode(&e.ct).unwrap())
                    .unwrap();
                assert_eq!(pt, hex::decode(&e.pt).unwrap());
            }
            opened.insert(v.kem_id);
        }
        assert_eq!(
            opened.into_iter().collect::<Vec<_>>(),
            [0x0041, 0x0042, 0x647A]
        );
    }
}
