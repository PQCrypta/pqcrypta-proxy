//! ML-KEM-1024 protected TLS session tickets (`tls.pqc_session_tickets`).
//!
//! A TLS 1.3 session ticket is the server handing the client its own resumption
//! state, sealed under a key only the server holds. rustls ships no ticketer by
//! default, so before this module the proxy issued no tickets at all and the
//! `pqc_session_tickets` setting described something that did not exist.
//!
//! # Construction
//!
//! KEM-DEM. At startup the server generates an ML-KEM-1024 (FIPS 203) keypair
//! and keeps both halves. For each ticket:
//!
//! 1. Encapsulate to the server's own public key, yielding a ciphertext and a
//!    fresh 32-byte shared secret — new per ticket, never reused.
//! 2. Derive an AES-256-GCM key from that secret with HKDF-SHA384 under a fixed
//!    context label, so the KEM output is never used directly as a cipher key.
//! 3. Seal the resumption state with a random 96-bit nonce, using the KEM
//!    ciphertext as associated data so a ticket cannot be re-paired with a
//!    different encapsulation.
//!
//! Wire format, all big-endian:
//! `version(1) || ct_len(2) || ct(1568) || nonce(12) || sealed(n+16)`
//!
//! # What this does and does not buy
//!
//! Honestly stated: the server holds both halves of the keypair, so an attacker
//! who reads server memory recovers tickets either way. What changes is the
//! algorithm protecting the ticket key material — ML-KEM rather than a purely
//! symmetric secret — and that each ticket gets an independent secret rather
//! than sharing one long-lived key. Forward secrecy is bounded by rotation
//! (below), not by the KEM.
//!
//! # Rotation
//!
//! The trait documents that lifetime must be enforced "by key rolling and
//! erasure, *not* by storing a lifetime in the ticket". A rotation therefore
//! generates a new keypair and retains exactly one previous decapsulation key
//! so tickets issued moments before the roll still open; anything older fails
//! to decapsulate and the client falls back to a full handshake. Erasing the
//! old key is what actually limits the damage a stolen ticket can do.
//!
//! Each generation is held to that lifetime by the clock as well as by the
//! roll. A key seals tickets only within its lifetime: if a rotation fails, no
//! ticket is issued under the expired key (resumption waits, full handshakes
//! go on) until one succeeds, and the failure is logged as an error once. A
//! key opens tickets only while those it sealed can still be valid: the
//! current one until a lifetime after it stopped sealing, the previous one for
//! a lifetime after it was replaced. The derived AEAD key and every buffer
//! that held resumption state in the clear are erased when dropped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA384};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024};
use aws_lc_rs::rand::SystemRandom;
use parking_lot::RwLock;
use rustls::server::ProducesTickets;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// Wire format version. A ticket that does not start with this is refused
/// rather than parsed, so a future format change cannot be misread as this one.
const TICKET_VERSION: u8 = 0x01;

/// HKDF context label, binding derived keys to this exact use.
const HKDF_INFO: &[u8] = b"pqcrypta-proxy tls session ticket v1 mlkem1024-aes256gcm";

/// ML-KEM-1024 ciphertext length (FIPS 203).
const ML_KEM_1024_CIPHERTEXT_LEN: usize = 1568;

/// One generation of ticket-sealing key material.
struct TicketKey {
    /// Private half — opens tickets sealed against `encaps`.
    decaps: DecapsulationKey<aws_lc_rs::kem::AlgorithmId>,
    /// Public half, used to seal new tickets.
    encaps: EncapsulationKey<aws_lc_rs::kem::AlgorithmId>,
}

impl TicketKey {
    fn generate() -> Result<Self, String> {
        let decaps = DecapsulationKey::generate(&ML_KEM_1024)
            .map_err(|_| "ML-KEM-1024 keypair generation failed".to_string())?;
        let encaps = decaps
            .encapsulation_key()
            .map_err(|_| "could not derive ML-KEM-1024 encapsulation key".to_string())?;
        Ok(Self { decaps, encaps })
    }
}

/// Session ticketer whose key material is protected with ML-KEM-1024.
pub struct PqcTicketer {
    /// Current generation, plus the one before it during the overlap window.
    keys: RwLock<(Arc<TicketKey>, Option<Arc<TicketKey>>)>,
    /// When the current generation was created.
    rotated_at: RwLock<Instant>,
    /// How long a generation is used before rolling.
    lifetime: Duration,
    /// Whether the last rotation failed (logged once per failure, and once
    /// when a rotation succeeds again)
    rotation_failing: AtomicBool,
    rng: SystemRandom,
}

impl std::fmt::Debug for PqcTicketer {
    /// Deliberately opaque: the trait requires Debug and the struct holds key
    /// material, which must never reach a log line. The `..` says so.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcTicketer")
            .field("algorithm", &"ML-KEM-1024 + AES-256-GCM")
            .field("lifetime_secs", &self.lifetime.as_secs())
            .finish_non_exhaustive()
    }
}

impl PqcTicketer {
    /// Build a ticketer, generating the first keypair.
    pub fn new(lifetime_secs: u32) -> Result<Self, String> {
        let key = Arc::new(TicketKey::generate()?);
        info!(
            "PQC session tickets active: ML-KEM-1024 + AES-256-GCM, {}s key lifetime",
            lifetime_secs
        );
        Ok(Self {
            keys: RwLock::new((key, None)),
            rotated_at: RwLock::new(Instant::now()),
            lifetime: Duration::from_secs(u64::from(lifetime_secs)),
            rotation_failing: AtomicBool::new(false),
            rng: SystemRandom::new(),
        })
    }

    /// How long ago, at `now`, the current generation began sealing tickets.
    fn age_at(&self, now: Instant) -> Duration {
        now.saturating_duration_since(*self.rotated_at.read())
    }

    /// Roll the keypair if the current one has reached its lifetime.
    ///
    /// The previous generation is kept for one further period so a ticket
    /// issued just before the roll still resumes; the generation before that is
    /// dropped, which is the erasure the trait asks for.
    ///
    /// At `now`, with `generate` making the new keypair.
    fn maybe_rotate_at(&self, now: Instant, generate: impl FnOnce() -> Result<TicketKey, String>) {
        if self.age_at(now) < self.lifetime {
            return;
        }
        let mut rotated = self.rotated_at.write();
        // Re-check under the write lock: several connections can reach this at
        // once and only one roll should happen.
        if now.saturating_duration_since(*rotated) < self.lifetime {
            return;
        }
        match generate() {
            Ok(fresh) => {
                let mut keys = self.keys.write();
                let previous = std::mem::replace(&mut keys.0, Arc::new(fresh));
                keys.1 = Some(previous);
                *rotated = now;
                if self.rotation_failing.swap(false, Ordering::Relaxed) {
                    info!("PQC session ticket key rotated; tickets are issued again");
                } else {
                    debug!("Rotated PQC session ticket key");
                }
            }
            Err(e) => {
                // The key has reached its lifetime and seals nothing more
                // (`seal_at`); the next ticket tries the rotation again.
                if !self.rotation_failing.swap(true, Ordering::Relaxed) {
                    error!(
                        "PQC session ticket key rotation failed ({}): no tickets are issued \
                         until a new key is generated",
                        e
                    );
                }
            }
        }
    }

    /// Derive the AEAD key for one ticket from a KEM shared secret.
    fn aead_key(shared_secret: &[u8]) -> Option<LessSafeKey> {
        let prk = Salt::new(HKDF_SHA384, &[]).extract(shared_secret);
        let okm = prk.expand(&[HKDF_INFO], &AES_256_GCM).ok()?;
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        okm.fill(&mut key_bytes[..]).ok()?;
        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes[..]).ok()?;
        Some(LessSafeKey::new(unbound))
    }

    /// Try to open a ticket with one specific generation. The buffer it is
    /// opened in becomes the plaintext returned; on a failed open it is erased.
    fn open_with(key: &TicketKey, ct: &[u8], nonce: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        let shared = key.decaps.decapsulate(Ciphertext::from(ct)).ok()?;
        let aead = Self::aead_key(shared.as_ref())?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = Zeroizing::new(sealed.to_vec());
        let plain_len = aead
            .open_in_place(nonce, Aad::from(ct), &mut buf)
            .ok()?
            .len();
        let mut plain = std::mem::take(&mut *buf);
        plain.truncate(plain_len);
        Some(plain)
    }

    /// A ticket for `plain`, sealed at `now`: after any rotation due, and only
    /// under a key within its lifetime.
    fn seal_at(
        &self,
        plain: &[u8],
        now: Instant,
        generate: impl FnOnce() -> Result<TicketKey, String>,
    ) -> Option<Vec<u8>> {
        self.maybe_rotate_at(now, generate);
        if self.age_at(now) >= self.lifetime {
            return None;
        }

        let key = Arc::clone(&self.keys.read().0);
        let (ct, shared) = key.encaps.encapsulate().ok()?;
        let ct = ct.as_ref();
        if ct.len() != ML_KEM_1024_CIPHERTEXT_LEN {
            warn!("Unexpected ML-KEM-1024 ciphertext length {}", ct.len());
            return None;
        }

        let aead = Self::aead_key(shared.as_ref())?;
        // Random, from the system RNG; each ticket also has its own AEAD key
        // (a fresh ML-KEM encapsulation), so the nonce is never reused
        let nonce_bytes: [u8; NONCE_LEN] = aws_lc_rs::rand::generate(&self.rng).ok()?.expose();
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        // Plaintext until it is sealed in place: erased if sealing fails
        let mut sealed = Zeroizing::new(plain.to_vec());
        aead.seal_in_place_append_tag(nonce, Aad::from(ct), &mut *sealed)
            .ok()?;

        let ct_len = u16::try_from(ct.len()).ok()?;
        let mut out = Vec::with_capacity(1 + 2 + ct.len() + NONCE_LEN + sealed.len());
        out.push(TICKET_VERSION);
        out.extend_from_slice(&ct_len.to_be_bytes());
        out.extend_from_slice(ct);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&sealed);
        Some(out)
    }

    /// The resumption state `cipher` seals, opened at `now` by a generation
    /// whose tickets can still be valid.
    fn open_at(&self, cipher: &[u8], now: Instant) -> Option<Vec<u8>> {
        // `cipher` is fully attacker controlled. Every length is checked before
        // it is used to slice, and every failure returns None rather than
        // distinguishing why — a caller learns only "not a valid ticket".
        if cipher.len() < 3 || cipher[0] != TICKET_VERSION {
            return None;
        }
        let ct_len = usize::from(u16::from_be_bytes([cipher[1], cipher[2]]));
        if ct_len != ML_KEM_1024_CIPHERTEXT_LEN {
            return None;
        }
        let header = 3usize;
        let nonce_at = header.checked_add(ct_len)?;
        let sealed_at = nonce_at.checked_add(NONCE_LEN)?;
        // A sealed body must carry at least the 16-byte GCM tag.
        if cipher.len() < sealed_at.checked_add(16)? {
            return None;
        }
        let ct = &cipher[header..nonce_at];
        let nonce = &cipher[nonce_at..sealed_at];
        let sealed = &cipher[sealed_at..];

        let (current, previous) = {
            let keys = self.keys.read();
            (Arc::clone(&keys.0), keys.1.as_ref().map(Arc::clone))
        };
        // The current generation sealed tickets until a lifetime after it
        // began, valid a lifetime each; the previous one stopped sealing when
        // it was replaced, which is `age` ago.
        let age = self.age_at(now);
        if age < self.lifetime.saturating_mul(2) {
            if let Some(plain) = Self::open_with(&current, ct, nonce, sealed) {
                return Some(plain);
            }
        }
        // Issued just before the last rotation.
        if age < self.lifetime {
            return previous.and_then(|prev| Self::open_with(&prev, ct, nonce, sealed));
        }
        None
    }
}

impl ProducesTickets for PqcTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        // Saturating: a lifetime beyond u32 seconds is a misconfiguration, and
        // wrapping it would advertise a nonsensically short hint.
        u32::try_from(self.lifetime.as_secs()).unwrap_or(u32::MAX)
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.seal_at(plain, Instant::now(), TicketKey::generate)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.open_at(cipher, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_the_plaintext() {
        let t = PqcTicketer::new(3600).expect("ticketer");
        let plain = b"resumption state bytes";
        let ticket = t.encrypt(plain).expect("encrypt");
        assert_eq!(t.decrypt(&ticket).as_deref(), Some(&plain[..]));
    }

    #[test]
    fn ticket_carries_a_full_ml_kem_ciphertext() {
        let t = PqcTicketer::new(3600).unwrap();
        let ticket = t.encrypt(b"x").unwrap();
        assert_eq!(ticket[0], TICKET_VERSION);
        assert!(ticket.len() > ML_KEM_1024_CIPHERTEXT_LEN);
    }

    #[test]
    fn each_ticket_uses_a_fresh_encapsulation() {
        let t = PqcTicketer::new(3600).unwrap();
        let a = t.encrypt(b"same input").unwrap();
        let b = t.encrypt(b"same input").unwrap();
        assert_ne!(
            a, b,
            "identical plaintext must not produce identical tickets"
        );
    }

    #[test]
    fn tampering_is_rejected() {
        let t = PqcTicketer::new(3600).unwrap();
        let mut ticket = t.encrypt(b"resumption state").unwrap();
        let last = ticket.len() - 1;
        ticket[last] ^= 0xff;
        assert!(
            t.decrypt(&ticket).is_none(),
            "GCM tag must reject tampering"
        );
    }

    #[test]
    fn a_wrong_encapsulation_does_not_open_a_ticket() {
        let t = PqcTicketer::new(3600).unwrap();
        let mut ticket = t.encrypt(b"resumption state").unwrap();
        // Flip a byte inside the KEM ciphertext; the AAD binding and the
        // decapsulated secret both change.
        ticket[10] ^= 0x01;
        assert!(t.decrypt(&ticket).is_none());
    }

    #[test]
    fn truncated_and_junk_input_is_refused_without_panicking() {
        let t = PqcTicketer::new(3600).unwrap();
        assert!(t.decrypt(&[]).is_none());
        assert!(t.decrypt(&[TICKET_VERSION]).is_none());
        // Random junk: any 64 bytes must be refused, not one fixed pattern
        let junk: [u8; 64] = aws_lc_rs::rand::generate(&SystemRandom::new())
            .unwrap()
            .expose();
        assert!(t.decrypt(&junk).is_none());
        let valid = t.encrypt(b"state").unwrap();
        for cut in [1usize, 3, 100, ML_KEM_1024_CIPHERTEXT_LEN, valid.len() - 1] {
            assert!(t.decrypt(&valid[..cut]).is_none(), "cut at {cut}");
        }
    }

    #[test]
    fn a_ticket_from_a_previous_key_still_opens_after_rotation() {
        let t = PqcTicketer::new(3600).expect("ticketer");
        let hour = Duration::from_secs(3600);
        let t0 = Instant::now();
        let ticket = t.seal_at(b"pre-rotation", t0, TicketKey::generate).unwrap();
        // A lifetime on, the next ticket rolls the key
        let rolled = t0 + hour;
        let _ = t
            .seal_at(b"triggers rotation", rolled, TicketKey::generate)
            .unwrap();
        assert_eq!(
            t.open_at(&ticket, rolled + Duration::from_secs(1))
                .as_deref(),
            Some(&b"pre-rotation"[..]),
            "one generation of overlap must be honoured"
        );
        // And not past the lifetime its tickets were issued for
        assert!(t.open_at(&ticket, rolled + hour).is_none());
    }

    /// A key that could not be rotated seals nothing past its lifetime, and
    /// tickets resume normally once a rotation succeeds.
    #[test]
    fn a_failed_rotation_issues_no_ticket_under_the_expired_key() {
        let t = PqcTicketer::new(3600).expect("ticketer");
        let hour = Duration::from_secs(3600);
        let t0 = Instant::now();
        let earlier = t.seal_at(b"state", t0, TicketKey::generate).unwrap();
        let fail = || Err("no entropy".to_string());
        assert!(t.seal_at(b"state", t0 + hour, fail).is_none());
        assert!(t.seal_at(b"state", t0 + hour + hour / 2, fail).is_none());
        // A ticket sealed within the key's lifetime still opens while it is valid
        assert!(t.open_at(&earlier, t0 + hour + hour / 2).is_some());
        assert!(t.open_at(&earlier, t0 + 2 * hour).is_none());
        // The next successful rotation issues tickets again
        let fresh = t
            .seal_at(b"state", t0 + 2 * hour, TicketKey::generate)
            .unwrap();
        assert!(t.open_at(&fresh, t0 + 2 * hour).is_some());
    }
}
