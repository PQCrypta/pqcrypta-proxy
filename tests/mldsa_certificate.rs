//! Integration test: load a real ML-DSA-87 certificate chain + key through the
//! SNI resolver's `load_certified_key` and confirm the signing key negotiates
//! the `ML_DSA_87` TLS signature scheme.
//!
//! Skips (passes trivially) when the deployment cert files are not present,
//! so CI machines without `/etc/pqcrypta/pqc-certs` are unaffected.
#![cfg(all(feature = "pqc-signatures", not(feature = "fips")))]

use std::path::Path;

use pqcrypta_proxy::tls::load_certified_key;
use rustls::SignatureScheme;

#[test]
fn loads_deployed_ml_dsa_87_chain() {
    let cert = Path::new("/etc/pqcrypta/pqc-certs/fullchain.pem");
    let key = Path::new("/etc/pqcrypta/pqc-certs/server.key");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: ML-DSA-87 deployment certs not present on this machine");
        return;
    }

    // rustls needs a process-wide default CryptoProvider for the non-PQC path;
    // installing may race with other tests, so ignore an AlreadyInstalled error.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ck = load_certified_key(cert, key).expect("ML-DSA-87 chain must load");
    assert!(
        ck.cert.len() >= 2,
        "expected leaf + intermediate in fullchain, got {}",
        ck.cert.len()
    );

    let signer = ck
        .key
        .choose_scheme(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ML_DSA_87,
        ])
        .expect("signing key must accept ML_DSA_87 offer");
    assert_eq!(signer.scheme(), SignatureScheme::ML_DSA_87);

    // Classical-only clients must be refused rather than mis-signed
    assert!(ck
        .key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .is_none());

    // Produce a real signature to prove the private key is usable
    let sig = signer
        .sign(b"certificate verify smoke test")
        .expect("signing must succeed");
    assert_eq!(sig.len(), 4627, "ML-DSA-87 signature length");
}

/// A domain with an ECDSA certificate and an ML-DSA-87 companion: a client
/// that can use ECDSA gets ECDSA even when it offers ML-DSA too (OpenSSL 3.5
/// does by default); a client that offers only ML-DSA gets the companion.
#[test]
fn the_ml_dsa_companion_goes_only_to_clients_that_need_it() {
    use pqcrypta_proxy::tls::{choose_certified_key, DomainCerts};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    let cert = Path::new("/etc/pqcrypta/pqc-certs/fullchain.pem");
    let key = Path::new("/etc/pqcrypta/pqc-certs/server.key");
    if !cert.exists() || !key.exists() {
        eprintln!("skipping: ML-DSA-87 deployment certs not present on this machine");
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let ecdsa = rcgen::generate_simple_self_signed(vec!["dual.invalid".to_string()]).unwrap();
    let ecdsa_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(ecdsa.signing_key.serialize_der()),
    ))
    .unwrap();
    let primary = Arc::new(rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(ecdsa.cert.der().to_vec())],
        ecdsa_key,
    ));
    let companion = Arc::new(load_certified_key(cert, key).expect("ML-DSA-87 chain must load"));
    let certs = DomainCerts {
        primary: primary.clone(),
        post_quantum: Some(companion.clone()),
    };

    let both = [
        SignatureScheme::ML_DSA_87,
        SignatureScheme::ECDSA_NISTP256_SHA256,
    ];
    assert!(Arc::ptr_eq(&choose_certified_key(&certs, &both), &primary));
    let ml_dsa_only = [SignatureScheme::ML_DSA_87];
    assert!(Arc::ptr_eq(
        &choose_certified_key(&certs, &ml_dsa_only),
        &companion
    ));
    // No companion: the primary, as before
    let single = DomainCerts {
        primary: primary.clone(),
        post_quantum: None,
    };
    assert!(Arc::ptr_eq(
        &choose_certified_key(&single, &ml_dsa_only),
        &primary
    ));
}

/// The server's signature list parses in the linked OpenSSL: if it did not,
/// the listener would keep OpenSSL's default, ML-DSA first, and send the
/// ML-DSA companion to every OpenSSL 3.5 client.
#[cfg(feature = "pqc")]
#[test]
fn the_server_signature_list_is_accepted() {
    let mut ctx = openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_server()).unwrap();
    ctx.set_sigalgs_list(pqcrypta_proxy::pqc_tls::openssl_pqc::SERVER_SIGALGS)
        .expect("SERVER_SIGALGS must parse");
}
