//! OpenSSL's allocations routed to mimalloc, as `main` does first.
//!
//! A test binary of its own, with one test: OpenSSL accepts other allocation
//! functions only before it has allocated anything, so nothing may touch it
//! before this does.
#![cfg(feature = "pqc")]

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use pqcrypta_proxy::openssl_alloc::{route_to_mimalloc, routed};

#[test]
fn openssl_allocates_through_mimalloc_from_the_start() {
    assert!(route_to_mimalloc(), "OpenSSL had allocated before the test");
    assert!(routed());

    // Work that allocates, grows and frees inside OpenSSL: keys, a
    // certificate's worth of DER, signatures, digests
    for _ in 0..64 {
        let key = PKey::generate_ed25519().expect("key");
        let der = key.private_key_to_der().expect("DER");
        let again = PKey::private_key_from_der(&der).expect("parsed");
        let mut signer = Signer::new_without_digest(&again).expect("signer");
        let signature = signer.sign_oneshot_to_vec(b"routed").expect("signed");
        let mut verifier = Verifier::new_without_digest(&key).expect("verifier");
        assert!(verifier
            .verify_oneshot(&signature, b"routed")
            .expect("verified"));
        let digest = openssl::hash::hash(MessageDigest::sha384(), &der).expect("digest");
        assert_eq!(digest.len(), 48);
    }
    let rsa = PKey::from_rsa(openssl::rsa::Rsa::generate(2048).expect("RSA")).expect("key");
    let pem = rsa.public_key_to_pem().expect("PEM");
    assert!(
        pem.starts_with(b"-----BEGIN PUBLIC KEY-----\n"),
        "a PEM public key"
    );

    // Still routed after all of it
    assert!(routed());
}
