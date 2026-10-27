use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::time::Duration;

use pki_types::{
    AlgorithmIdentifier, CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime,
};

use super::CryptoProvider;
use crate::client::ResolvesClientCert;
use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::{Error, InconsistentKeys};
use crate::server::{ClientHello, ParsedCertificate, ResolvesServerCert};
use crate::sync::Arc;
use crate::x509;

/// An abstract signing key.
///
/// This interface is used by rustls to use a private signing key
/// for authentication.  This includes server and client authentication.
///
/// Objects of this type are always used within Rustls as
/// `Arc<dyn SigningKey>`. There are no concrete public structs in Rustls
/// that implement this trait.
///
/// There are two main ways to get a signing key:
///
///  - [`KeyProvider::load_private_key()`], or
///  - some other method outside of the `KeyProvider` extension trait,
///    for instance:
///    - [`crypto::ring::sign::any_ecdsa_type()`]
///    - [`crypto::ring::sign::any_eddsa_type()`]
///    - [`crypto::ring::sign::any_supported_type()`]
///    - [`crypto::aws_lc_rs::sign::any_ecdsa_type()`]
///    - [`crypto::aws_lc_rs::sign::any_eddsa_type()`]
///    - [`crypto::aws_lc_rs::sign::any_supported_type()`]
///
/// The `KeyProvider` method `load_private_key()` is called under the hood by
/// [`ConfigBuilder::with_single_cert()`],
/// [`ConfigBuilder::with_client_auth_cert()`], and
/// [`ConfigBuilder::with_single_cert_with_ocsp()`].
///
/// A signing key created outside of the `KeyProvider` extension trait can be used
/// to create a [`CertifiedKey`], which in turn can be used to create a
/// [`ResolvesServerCertUsingSni`]. Alternately, a `CertifiedKey` can be returned from a
/// custom implementation of the [`ResolvesServerCert`] or [`ResolvesClientCert`] traits.
///
/// [`KeyProvider::load_private_key()`]: crate::crypto::KeyProvider::load_private_key
/// [`ConfigBuilder::with_single_cert()`]: crate::ConfigBuilder::with_single_cert
/// [`ConfigBuilder::with_single_cert_with_ocsp()`]: crate::ConfigBuilder::with_single_cert_with_ocsp
/// [`ConfigBuilder::with_client_auth_cert()`]: crate::ConfigBuilder::with_client_auth_cert
/// [`crypto::ring::sign::any_ecdsa_type()`]: crate::crypto::ring::sign::any_ecdsa_type
/// [`crypto::ring::sign::any_eddsa_type()`]: crate::crypto::ring::sign::any_eddsa_type
/// [`crypto::ring::sign::any_supported_type()`]: crate::crypto::ring::sign::any_supported_type
/// [`crypto::aws_lc_rs::sign::any_ecdsa_type()`]: crate::crypto::aws_lc_rs::sign::any_ecdsa_type
/// [`crypto::aws_lc_rs::sign::any_eddsa_type()`]: crate::crypto::aws_lc_rs::sign::any_eddsa_type
/// [`crypto::aws_lc_rs::sign::any_supported_type()`]: crate::crypto::aws_lc_rs::sign::any_supported_type
/// [`ResolvesServerCertUsingSni`]: crate::server::ResolvesServerCertUsingSni
/// [`ResolvesServerCert`]: crate::server::ResolvesServerCert
/// [`ResolvesClientCert`]: crate::client::ResolvesClientCert
pub trait SigningKey: Debug + Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice by returning something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// Get the RFC 5280-compliant SubjectPublicKeyInfo (SPKI) of this [`SigningKey`] if available.
    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        // Opt-out by default
        None
    }

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer: Debug + Send + Sync {
    /// Signs `message` using the selected scheme.
    ///
    /// `message` is not hashed; the implementer must hash it using the hash function
    /// implicit in [`Self::scheme()`].
    ///
    /// The returned signature format is also defined by [`Self::scheme()`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reveals which scheme will be used when you call [`Self::sign()`].
    fn scheme(&self) -> SignatureScheme;
}

/// Server certificate resolver which always resolves to the same certificate and key.
///
/// For use with [`ConfigBuilder::with_cert_resolver()`].
///
/// [`ConfigBuilder::with_cert_resolver()`]: crate::ConfigBuilder::with_cert_resolver
#[derive(Debug)]
pub struct SingleCertAndKey(Arc<CertifiedKey>);

impl From<CertifiedKey> for SingleCertAndKey {
    fn from(certified_key: CertifiedKey) -> Self {
        Self(Arc::new(certified_key))
    }
}

impl From<Arc<CertifiedKey>> for SingleCertAndKey {
    fn from(certified_key: Arc<CertifiedKey>) -> Self {
        Self(certified_key)
    }
}

impl ResolvesClientCert for SingleCertAndKey {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl ResolvesServerCert for SingleCertAndKey {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response.
///
/// Note: this struct is also used to represent an [RFC 7250] raw public key,
/// when the client/server is configured to use raw public keys instead of
/// certificates.
///
/// [RFC 7250]: https://tools.ietf.org/html/rfc7250
#[derive(Clone, Debug)]
pub struct CertifiedKey {
    /// The certificate chain or raw public key.
    pub cert: Vec<CertificateDer<'static>>,

    /// The certified key.
    pub key: Arc<dyn SigningKey>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,

    /// Delegated credentials ([RFC 9345]) for the end-entity certificate, in
    /// the order the server prefers them: a TLS 1.3 handshake uses the first
    /// one the client accepts, and the certificate's own key otherwise.
    ///
    /// [RFC 9345]: https://www.rfc-editor.org/rfc/rfc9345
    pub delegated_credentials: Vec<DelegatedCredential>,
}

impl CertifiedKey {
    /// Create a new `CertifiedKey` from a certificate chain and DER-encoded private key.
    ///
    /// Attempt to parse the private key with the given [`CryptoProvider`]'s [`KeyProvider`] and
    /// verify that it matches the public key in the first certificate of the `cert_chain`
    /// if possible.
    ///
    /// [`KeyProvider`]: crate::crypto::KeyProvider
    pub fn from_der(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        provider: &CryptoProvider,
    ) -> Result<Self, Error> {
        let private_key = provider
            .key_provider
            .load_private_key(key)?;

        let certified_key = Self::new(cert_chain, private_key);
        match certified_key.keys_match() {
            // Don't treat unknown consistency as an error
            Ok(()) | Err(Error::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(certified_key),
            Err(err) => Err(err),
        }
    }

    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            cert,
            key,
            ocsp: None,
            delegated_credentials: Vec::new(),
        }
    }

    /// Verify the consistency of this [`CertifiedKey`]'s public and private keys.
    /// This is done by performing a comparison of SubjectPublicKeyInfo bytes.
    pub fn keys_match(&self) -> Result<(), Error> {
        let Some(key_spki) = self.key.public_key() else {
            return Err(InconsistentKeys::Unknown.into());
        };

        let cert = ParsedCertificate::try_from(self.end_entity_cert()?)?;
        match key_spki == cert.subject_public_key_info() {
            true => Ok(()),
            false => Err(InconsistentKeys::KeyMismatch.into()),
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&CertificateDer<'_>, Error> {
        self.cert
            .first()
            .ok_or(Error::NoCertificatesPresented)
    }
}

/// A delegated credential ([RFC 9345]) for a [`CertifiedKey`]'s end-entity
/// certificate: a short-lived key that the certificate's own key has signed
/// for, which then signs CertificateVerify in its place.
///
/// Clients accept one only under a certificate that carries the
/// DelegationUsage extension (1.3.6.1.4.1.44363.44) and the digitalSignature
/// key usage.
///
/// [RFC 9345]: https://www.rfc-editor.org/rfc/rfc9345
#[derive(Clone, Debug)]
pub struct DelegatedCredential {
    encoded: Vec<u8>,
    key: Arc<dyn SigningKey>,
    scheme: SignatureScheme,
    algorithm: SignatureScheme,
    expires: UnixTime,
}

impl DelegatedCredential {
    /// The longest a credential may be valid for ([RFC 9345 section 4.1.3]).
    ///
    /// [RFC 9345 section 4.1.3]: https://www.rfc-editor.org/rfc/rfc9345#section-4.1.3
    pub const MAX_VALIDITY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

    /// Sign, with `certified`'s key, a credential that delegates its
    /// end-entity certificate to `key` from `now` for `valid_for`.
    ///
    /// `not_before` and `not_after` are that certificate's validity: the
    /// credential's valid_time counts from its notBefore, and the credential
    /// must expire before its notAfter.
    pub fn delegate(
        certified: &CertifiedKey,
        key: Arc<dyn SigningKey>,
        not_before: UnixTime,
        not_after: UnixTime,
        now: UnixTime,
        valid_for: Duration,
    ) -> Result<Self, Error> {
        if valid_for.is_zero() || valid_for > Self::MAX_VALIDITY {
            return Err(Error::General(
                "a delegated credential is valid for at most seven days".into(),
            ));
        }
        let expires = now
            .as_secs()
            .saturating_add(valid_for.as_secs());
        if expires >= not_after.as_secs() {
            return Err(Error::General(
                "a delegated credential must expire before its certificate".into(),
            ));
        }
        // valid_time: seconds from the certificate's notBefore (RFC 9345 section 4)
        let valid_time = expires
            .checked_sub(not_before.as_secs())
            .and_then(|t| u32::try_from(t).ok())
            .ok_or_else(|| {
                Error::General(
                    "a delegated credential's expiry must fall within 2^32 seconds of its certificate's notBefore".into(),
                )
            })?;

        let scheme = key
            .choose_scheme(TLS13_SCHEMES)
            .ok_or_else(|| {
                Error::General("the delegated key signs with no TLS 1.3 signature scheme".into())
            })?
            .scheme();
        let spki = key
            .public_key()
            .ok_or_else(|| Error::General("the delegated key has no public key".into()))?;
        let spki_len = u32::try_from(spki.len())
            .ok()
            .filter(|len| *len < 1 << 24)
            .ok_or_else(|| Error::General("the delegated key's public key is too large".into()))?;

        // Credential: valid_time, dc_cert_verify_algorithm, ASN1_subjectPublicKeyInfo<1..2^24-1>
        let mut encoded = Vec::with_capacity(9 + spki.len());
        encoded.extend_from_slice(&valid_time.to_be_bytes());
        encoded.extend_from_slice(&scheme.to_array());
        encoded.extend_from_slice(&spki_len.to_be_bytes()[1..]);
        encoded.extend_from_slice(spki.as_ref());

        let signer = certified
            .key
            .choose_scheme(TLS13_SCHEMES)
            .ok_or_else(|| {
                Error::General("the certificate's key signs with no TLS 1.3 signature scheme".into())
            })?;
        let algorithm = signer.scheme();
        let leaf = certified.end_entity_cert()?;

        // RFC 9345 section 4: what the certificate's key signs
        let mut content = Vec::with_capacity(100 + leaf.len() + encoded.len());
        content.extend_from_slice(&[0x20; 64]);
        content.extend_from_slice(b"TLS, server delegated credentials\0");
        content.extend_from_slice(leaf.as_ref());
        content.extend_from_slice(&encoded);
        content.extend_from_slice(&algorithm.to_array());
        let signature = signer.sign(&content)?;
        let signature_len = u16::try_from(signature.len())
            .map_err(|_| Error::General("the credential's signature is too large".into()))?;

        // DelegatedCredential: cred, algorithm, signature<1..2^16-1>
        encoded.extend_from_slice(&algorithm.to_array());
        encoded.extend_from_slice(&signature_len.to_be_bytes());
        encoded.extend_from_slice(&signature);

        Ok(Self {
            encoded,
            key,
            scheme,
            algorithm,
            expires: UnixTime::since_unix_epoch(Duration::from_secs(expires)),
        })
    }

    /// The DelegatedCredential structure, as the end-entity certificate's
    /// entry carries it.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `dc_cert_verify_algorithm`: the scheme the delegated key signs
    /// CertificateVerify with.
    pub fn scheme(&self) -> SignatureScheme {
        self.scheme
    }

    /// `algorithm`: the scheme the certificate's key signed the credential with.
    pub fn algorithm(&self) -> SignatureScheme {
        self.algorithm
    }

    /// When the credential expires.
    pub fn expires(&self) -> UnixTime {
        self.expires
    }

    /// The delegated key, which signs CertificateVerify.
    pub(crate) fn key(&self) -> &dyn SigningKey {
        &*self.key
    }

    /// Whether a client that offered `offered` in its delegated_credential
    /// extension and `signature_schemes` in signature_algorithms accepts this
    /// credential at `now` ([RFC 9345 section 4.1.1]).
    ///
    /// [RFC 9345 section 4.1.1]: https://www.rfc-editor.org/rfc/rfc9345#section-4.1.1
    pub(crate) fn acceptable(
        &self,
        offered: &[SignatureScheme],
        signature_schemes: &[SignatureScheme],
        now: UnixTime,
    ) -> bool {
        offered.contains(&self.scheme)
            && signature_schemes.contains(&self.algorithm)
            && now.as_secs() < self.expires.as_secs()
    }
}

/// Every scheme TLS 1.3 signs with, in the order a key that can sign with
/// several takes them.
const TLS13_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ML_DSA_87,
    SignatureScheme::ML_DSA_65,
    SignatureScheme::ML_DSA_44,
    SignatureScheme::ED25519,
    SignatureScheme::ED448,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA512,
];

/// Convert a public key and algorithm identifier into [`SubjectPublicKeyInfoDer`].
pub fn public_key_to_spki(
    alg_id: &AlgorithmIdentifier,
    public_key: impl AsRef<[u8]>,
) -> SubjectPublicKeyInfoDer<'static> {
    // SubjectPublicKeyInfo  ::=  SEQUENCE  {
    //    algorithm            AlgorithmIdentifier,
    //    subjectPublicKey     BIT STRING  }
    //
    // AlgorithmIdentifier  ::=  SEQUENCE  {
    //    algorithm               OBJECT IDENTIFIER,
    //    parameters              ANY DEFINED BY algorithm OPTIONAL  }
    //
    // note that the `pki_types::AlgorithmIdentifier` type is the
    // concatenation of `algorithm` and `parameters`, but misses the
    // outer `Sequence`.

    let mut spki_inner = x509::wrap_in_sequence(alg_id.as_ref());
    spki_inner.extend(&x509::wrap_in_bit_string(public_key.as_ref()));

    let spki = x509::wrap_in_sequence(&spki_inner);

    SubjectPublicKeyInfoDer::from(spki)
}

#[cfg(all(test, feature = "aws_lc_rs"))]
mod tests {
    use alloc::vec;
    use core::time::Duration;

    use pki_types::{PrivateKeyDer, SubjectPublicKeyInfoDer, UnixTime};

    use super::{CertifiedKey, DelegatedCredential, SigningKey};
    use crate::crypto::aws_lc_rs::default_provider;
    use crate::crypto::aws_lc_rs::sign::any_supported_type;
    use crate::enums::SignatureScheme;
    use crate::sync::Arc;
    use crate::verify::DigitallySignedStruct;
    use crate::webpki::{verify_tls13_signature, verify_tls13_signature_with_raw_key};

    const NOT_BEFORE: u64 = 1_767_225_600; // 2026-01-01
    const NOT_AFTER: u64 = 1_798_761_600; // 2027-01-01
    const NOW: u64 = 1_780_272_000; // 2026-06-01

    fn at(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn key(pkcs8: &[u8]) -> Arc<dyn SigningKey> {
        any_supported_type(&PrivateKeyDer::Pkcs8(pkcs8.to_vec().into())).unwrap()
    }

    fn p256() -> Arc<dyn SigningKey> {
        key(&rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap()
            .serialize_der())
    }

    fn ml_dsa_65() -> Arc<dyn SigningKey> {
        use aws_lc_rs::signature::{ML_DSA_65_SIGNING, PqdsaKeyPair};
        key(PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .unwrap()
            .to_pkcs8v1()
            .unwrap()
            .as_ref())
    }

    fn certified() -> CertifiedKey {
        let issuer = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["dc.example".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        let leaf = params
            .self_signed(&issuer)
            .unwrap()
            .der()
            .clone();
        CertifiedKey::new(vec![leaf], key(&issuer.serialize_der()))
    }

    fn delegate(
        certified: &CertifiedKey,
        key: Arc<dyn SigningKey>,
        now: u64,
        valid_for: Duration,
    ) -> Result<DelegatedCredential, crate::Error> {
        DelegatedCredential::delegate(
            certified,
            key,
            at(NOT_BEFORE),
            at(NOT_AFTER),
            at(now),
            valid_for,
        )
    }

    #[test]
    fn the_certificate_signs_a_credential_for_the_delegated_key() {
        let certified = certified();
        let delegated = ml_dsa_65();
        let dc = delegate(&certified, delegated.clone(), NOW, Duration::from_secs(86_400)).unwrap();
        assert_eq!(dc.scheme(), SignatureScheme::ML_DSA_65);
        assert_eq!(dc.algorithm(), SignatureScheme::ECDSA_NISTP256_SHA256);
        assert_eq!(dc.expires().as_secs(), NOW + 86_400);

        // RFC 9345 section 4: Credential, algorithm, signature
        let encoded = dc.encoded();
        let valid_time = u32::from_be_bytes(encoded[..4].try_into().unwrap());
        assert_eq!(u64::from(valid_time), NOW + 86_400 - NOT_BEFORE);
        assert_eq!(encoded[4..6], [0x09, 0x05]);
        let spki_len =
            (usize::from(encoded[6]) << 16) | (usize::from(encoded[7]) << 8) | usize::from(encoded[8]);
        let cred = &encoded[..9 + spki_len];
        let spki = &cred[9..];
        assert_eq!(spki, delegated.public_key().unwrap().as_ref());
        let rest = &encoded[cred.len()..];
        assert_eq!(rest[..2], [0x04, 0x03]);
        let signature = &rest[4..];
        assert_eq!(
            usize::from(u16::from_be_bytes([rest[2], rest[3]])),
            signature.len()
        );

        // the certificate's key signed it
        let mut content = vec![0x20; 64];
        content.extend_from_slice(b"TLS, server delegated credentials\0");
        content.extend_from_slice(certified.cert[0].as_ref());
        content.extend_from_slice(cred);
        content.extend_from_slice(&rest[..2]);
        let algorithms = default_provider().signature_verification_algorithms;
        verify_tls13_signature(
            &content,
            &certified.cert[0],
            &DigitallySignedStruct::new(dc.algorithm(), signature.to_vec()),
            &algorithms,
        )
        .unwrap();

        // and what the delegated key signs checks against the credential
        let signer = dc
            .key()
            .choose_scheme(&[dc.scheme()])
            .unwrap();
        let message = b"handshake transcript";
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(spki),
            &DigitallySignedStruct::new(signer.scheme(), signer.sign(message).unwrap()),
            &algorithms,
        )
        .unwrap();
    }

    #[test]
    fn a_credential_stays_within_seven_days_and_its_certificate() {
        let certified = certified();
        let max = DelegatedCredential::MAX_VALIDITY;
        assert!(delegate(&certified, p256(), NOW, max).is_ok());
        assert!(delegate(&certified, p256(), NOW, max + Duration::from_secs(1)).is_err());
        assert!(delegate(&certified, p256(), NOW, Duration::ZERO).is_err());
        // expiring at the certificate's notAfter
        assert!(delegate(&certified, p256(), NOT_AFTER - 3_600, Duration::from_secs(3_600)).is_err());
        // expiring before the certificate's notBefore
        assert!(delegate(&certified, p256(), NOT_BEFORE - 7_200, Duration::from_secs(3_600)).is_err());
    }

    #[test]
    fn a_client_takes_a_credential_it_offered_and_can_verify_until_it_expires() {
        let dc = delegate(&certified(), p256(), NOW, Duration::from_secs(3_600)).unwrap();
        let offered = [SignatureScheme::ECDSA_NISTP256_SHA256];
        let signature_schemes = [SignatureScheme::ECDSA_NISTP256_SHA256];
        assert!(dc.acceptable(&offered, &signature_schemes, at(NOW)));
        // dc_cert_verify_algorithm not offered
        assert!(!dc.acceptable(&[SignatureScheme::ED25519], &signature_schemes, at(NOW)));
        // the credential's algorithm not in signature_algorithms
        assert!(!dc.acceptable(&offered, &[SignatureScheme::RSA_PSS_SHA256], at(NOW)));
        // expired
        assert!(!dc.acceptable(&offered, &signature_schemes, at(NOW + 3_600)));
    }
}
