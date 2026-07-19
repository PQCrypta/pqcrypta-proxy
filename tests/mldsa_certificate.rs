//! Integration test: load a real ML-DSA-87 certificate chain + key through the
//! SNI resolver's `load_certified_key` and confirm the signing key negotiates
//! the `ML_DSA_87` TLS signature scheme.
//!
//! Skips (passes trivially) when the deployment cert files are not present,
//! so CI machines without `/etc/pqcrypta/pqc-certs` are unaffected.
#![cfg(feature = "pqc-signatures")]

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
