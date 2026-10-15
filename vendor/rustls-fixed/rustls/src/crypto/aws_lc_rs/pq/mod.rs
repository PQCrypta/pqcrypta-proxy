use aws_lc_rs::kem;

use crate::crypto::SupportedKxGroup;
use crate::crypto::aws_lc_rs::kx_group;
use crate::crypto::aws_lc_rs::pq::mlkem::MlKem;
use crate::{Error, NamedGroup, PeerMisbehaved};

mod hybrid;
mod mlkem;

/// This is the [X25519MLKEM768] key exchange.
///
/// [X25519MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static X25519MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: kx_group::X25519,
    post_quantum: MLKEM768,
    name: NamedGroup::X25519MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: X25519_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: true,
    },
};

/// This is the [SECP256R1MLKEM768] key exchange.
///
/// [SECP256R1MLKEM768]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static SECP256R1MLKEM768: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: kx_group::SECP256R1,
    post_quantum: MLKEM768,
    name: NamedGroup::secp256r1MLKEM768,
    layout: hybrid::Layout {
        classical_share_len: SECP256R1_LEN,
        post_quantum_client_share_len: MLKEM768_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM768_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 3.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM768: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_768,
    group: NamedGroup::MLKEM768,
};

/// This is the [MLKEM] key encapsulation mechanism in NIST with security category 5.
///
/// [MLKEM]: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem
pub static MLKEM1024: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_1024,
    group: NamedGroup::MLKEM1024,
};

/// ML-KEM-512 on its own; see [`MLKEM768`]. NIST level 1.
pub static MLKEM512: &dyn SupportedKxGroup = &MlKem {
    alg: &kem::ML_KEM_512,
    group: NamedGroup::MLKEM512,
};

/// This is the [SECP384R1MLKEM1024] key exchange: P-384 and ML-KEM-1024, the
/// ECDH share first as for SecP256r1MLKEM768.
///
/// [SECP384R1MLKEM1024]: <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/>
pub static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &hybrid::Hybrid {
    classical: kx_group::SECP384R1,
    post_quantum: MLKEM1024,
    name: NamedGroup::secp384r1MLKEM1024,
    layout: hybrid::Layout {
        classical_share_len: SECP384R1_LEN,
        post_quantum_client_share_len: MLKEM1024_ENCAP_LEN,
        post_quantum_server_share_len: MLKEM1024_CIPHERTEXT_LEN,
        post_quantum_first: false,
    },
};

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

const X25519_LEN: usize = 32;
const SECP256R1_LEN: usize = 65;
const SECP384R1_LEN: usize = 97;
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
const MLKEM1024_ENCAP_LEN: usize = 1568;
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
const MLKEM768_ENCAP_LEN: usize = 1184;
