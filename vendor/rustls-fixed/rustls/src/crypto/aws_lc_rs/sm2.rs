//! curveSM2 ECDHE (RFC 8998), the classical half of curveSM2MLKEM768
//! (draft-yang-tls-hybrid-sm2-mlkem).
//!
//! aws-lc has no SM2, so the curve arithmetic is RustCrypto's `sm2`, and the
//! ephemeral scalar is drawn from aws-lc's random generator like every other
//! key share this provider makes. Shares are uncompressed SEC1 points (65
//! bytes, RFC 8446 4.2.8.2); the shared secret is the x-coordinate of the
//! product point (RFC 8446 7.4.2), 32 bytes.

use alloc::boxed::Box;
use alloc::vec::Vec;

use elliptic_curve::sec1::ToSec1Point;
use sm2::{PublicKey, SecretKey};

use crate::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;

/// The length of a curveSM2 key share: 0x04, then x and y, 32 bytes each.
pub(crate) const CURVE_SM2_LEN: usize = 65;

/// curveSM2 ECDHE, NamedGroup 0x0029.
#[derive(Debug)]
pub(crate) struct CurveSm2;

/// curveSM2 ECDHE. On its own it is a classical group like X25519; it is here
/// to be the classical half of [`super::kx_group::CURVESM2MLKEM768`].
pub static CURVE_SM2: &dyn SupportedKxGroup = &CurveSm2;

impl SupportedKxGroup for CurveSm2 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // Rejection sampling: from_slice refuses zero and anything not below
        // the group order, so a uniform 32 bytes is retried until it is a
        // valid scalar (n is within 2^-32 of 2^256: a retry is rare)
        let secret = loop {
            let mut bytes = [0u8; 32];
            aws_lc_rs::rand::fill(&mut bytes).map_err(|_| crate::rand::GetRandomFailed)?;
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                break secret;
            }
        };
        let pub_key = secret
            .public_key()
            .as_affine()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Ok(Box::new(ActiveCurveSm2 { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::curveSM2
    }

    fn usable_for_version(&self, version: crate::ProtocolVersion) -> bool {
        // RFC 8998 defines it for TLS 1.3 only
        version == crate::ProtocolVersion::TLSv1_3
    }
}

struct ActiveCurveSm2 {
    secret: SecretKey,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for ActiveCurveSm2 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // Uncompressed points only, as RFC 8446 4.2.8.2 requires; from_sec1_bytes
        // rejects a point not on the curve and the identity
        if peer_pub_key.len() != CURVE_SM2_LEN || peer_pub_key[0] != 0x04 {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        let peer = PublicKey::from_sec1_bytes(peer_pub_key)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let shared =
            elliptic_curve::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from(shared.raw_secret_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::curveSM2
    }
}
