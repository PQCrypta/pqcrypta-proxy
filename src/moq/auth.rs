//! Who may publish through the relay, and the per-session token cache
//! (draft-ietf-moq-transport sections 7.7 and 8.9).
//!
//! Subscribing is open: the relay forwards what its publishers chose to
//! publish, and holds subscribers to the per-address rate limits. Publishing
//! is not: a PUBLISH or PUBLISH_NAMESPACE must carry an AUTHORIZATION_TOKEN
//! (in the request or in SETUP) whose value names a Track Namespace prefix
//! and an expiry, signed with the relay's publish key (HMAC-SHA-384):
//!
//! ```text
//! v1.<prefix>.<expiry, Unix seconds>.<HMAC-SHA-384 of "v1.<prefix>.<expiry>", hex>
//! ```
//!
//! `<prefix>` is the namespace in section 8.8's serialized form, so it names
//! the same bytes everywhere. The token authorizes that prefix and every
//! namespace under it, and nothing else (section 7.7: a publisher of one
//! namespace is not implicitly a publisher of another). Token Type 0 marks a
//! token whose type is agreed out of band (section 8.9).

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha384;

use super::codec::Namespace;
use super::error::{RequestCode, SessionCode};
use super::message::Token;

const VERSION: &str = "v1";

/// The relay's publish key.
pub struct PublishAuth {
    key: Vec<u8>,
}

/// Why a token does not authorize a request (sections 12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unauthorized,
    Expired,
    Malformed,
}

impl Refusal {
    pub const fn code(self) -> RequestCode {
        match self {
            Self::Unauthorized => RequestCode::Unauthorized,
            Self::Expired => RequestCode::ExpiredAuthToken,
            Self::Malformed => RequestCode::MalformedAuthToken,
        }
    }
}

impl PublishAuth {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    fn mac(&self, signed: &str) -> Hmac<Sha384> {
        let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(&self.key)
            .expect("HMAC takes any key length");
        mac.update(signed.as_bytes());
        mac
    }

    /// A token for `prefix` until `expiry` (Unix seconds): what `pqcrypta-proxy
    /// --moq-token` prints for a publisher.
    pub fn issue(&self, prefix: &Namespace, expiry: u64) -> String {
        let signed = format!("{VERSION}.{prefix}.{expiry}");
        let tag = self.mac(&signed).finalize().into_bytes();
        format!("{signed}.{}", hex::encode(tag))
    }

    /// Whether `value` authorizes publishing under `namespace`.
    pub fn check(&self, value: &[u8], namespace: &Namespace) -> Result<(), Refusal> {
        let text = std::str::from_utf8(value).map_err(|_| Refusal::Malformed)?;
        let (signed, tag) = text.rsplit_once('.').ok_or(Refusal::Malformed)?;
        let mut parts = signed.splitn(2, '.');
        if parts.next() != Some(VERSION) {
            return Err(Refusal::Malformed);
        }
        let rest = parts.next().ok_or(Refusal::Malformed)?;
        let (prefix, expiry) = rest.rsplit_once('.').ok_or(Refusal::Malformed)?;
        let expiry: u64 = expiry.parse().map_err(|_| Refusal::Malformed)?;
        let tag = hex::decode(tag).map_err(|_| Refusal::Malformed)?;
        self.mac(signed)
            .verify_slice(&tag)
            .map_err(|_| Refusal::Unauthorized)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if expiry <= now {
            return Err(Refusal::Expired);
        }
        // Whole fields only ("a-b" does not authorize "a-bc"); in the
        // serialized form a `-` is only ever a field separator. An empty
        // prefix authorizes every namespace.
        if !prefix.is_empty() {
            let rendered = namespace.to_string();
            let under = rendered
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'));
            if !under {
                return Err(Refusal::Unauthorized);
            }
        }
        Ok(())
    }

    /// The first refusal-free answer among `tokens` (a request's, then the
    /// session's from SETUP); the most telling refusal otherwise.
    pub fn authorize<'a>(
        &self,
        tokens: impl IntoIterator<Item = &'a Bytes>,
        namespace: &Namespace,
    ) -> Result<(), Refusal> {
        let mut worst = Refusal::Unauthorized;
        for value in tokens {
            match self.check(value, namespace) {
                Ok(()) => return Ok(()),
                Err(Refusal::Expired) => worst = Refusal::Expired,
                Err(Refusal::Malformed) if worst == Refusal::Unauthorized => {
                    worst = Refusal::Malformed;
                }
                Err(_) => {}
            }
        }
        Err(worst)
    }
}

/// The Token Aliases a peer registered in this session (section 8.9).
pub struct TokenCache {
    limit: u64,
    used: u64,
    entries: HashMap<u64, (u64, Bytes)>,
}

impl TokenCache {
    /// `limit` is the MAX_AUTH_TOKEN_CACHE_SIZE this endpoint sent.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            entries: HashMap::new(),
        }
    }

    /// Resolve the tokens a message carries, applying their registrations
    /// and deletions in order; returns the token values to authorize with.
    /// `in_setup`: a registration over the limit is used as a value instead
    /// of failing (section 9.1.4), and DELETE or USE_ALIAS from a client is a
    /// ROLE_VIOLATION when `from_client`.
    pub fn apply(
        &mut self,
        tokens: &[Token],
        in_setup: bool,
        from_client: bool,
    ) -> Result<Vec<Bytes>, SessionCode> {
        let mut values = Vec::new();
        for t in tokens {
            match t {
                Token::Delete { alias } => {
                    if in_setup && from_client {
                        return Err(SessionCode::RoleViolation);
                    }
                    let Some((_, value)) = self.entries.remove(alias) else {
                        return Err(SessionCode::UnknownAuthTokenAlias);
                    };
                    self.used = self.used.saturating_sub(16 + value.len() as u64);
                }
                Token::Register { alias, kind, value } => {
                    if self.entries.contains_key(alias) {
                        return Err(SessionCode::DuplicateAuthTokenAlias);
                    }
                    let size = 16 + value.len() as u64;
                    if self.used + size > self.limit {
                        if !in_setup {
                            return Err(SessionCode::AuthTokenCacheOverflow);
                        }
                    } else {
                        self.used += size;
                        self.entries.insert(*alias, (*kind, value.clone()));
                    }
                    values.push(value.clone());
                }
                Token::UseAlias { alias } => {
                    if in_setup && from_client {
                        return Err(SessionCode::RoleViolation);
                    }
                    let Some((_, value)) = self.entries.get(alias).cloned() else {
                        return Err(SessionCode::UnknownAuthTokenAlias);
                    };
                    values.push(value);
                }
                Token::UseValue { value, .. } => {
                    values.push(value.clone());
                }
            }
        }
        Ok(values)
    }

    pub fn used(&self) -> u64 {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(fields: &[&'static [u8]]) -> Namespace {
        Namespace(fields.iter().map(|f| Bytes::from_static(f)).collect())
    }

    fn future() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn a_token_authorizes_its_prefix_and_nothing_else() {
        let auth = PublishAuth::new(b"key");
        let token = auth.issue(&ns(&[b"music", b"radio"]), future());
        assert_eq!(
            auth.check(token.as_bytes(), &ns(&[b"music", b"radio"])),
            Ok(())
        );
        assert_eq!(
            auth.check(token.as_bytes(), &ns(&[b"music", b"radio", b"x"])),
            Ok(())
        );
        assert_eq!(
            auth.check(token.as_bytes(), &ns(&[b"music", b"radiox"])),
            Err(Refusal::Unauthorized)
        );
        assert_eq!(
            auth.check(token.as_bytes(), &ns(&[b"music"])),
            Err(Refusal::Unauthorized)
        );
        let other = PublishAuth::new(b"other");
        assert_eq!(
            other.check(token.as_bytes(), &ns(&[b"music", b"radio"])),
            Err(Refusal::Unauthorized)
        );
    }

    #[test]
    fn expired_and_malformed_tokens_say_so() {
        let auth = PublishAuth::new(b"key");
        let old = auth.issue(&ns(&[b"a"]), 1);
        assert_eq!(
            auth.check(old.as_bytes(), &ns(&[b"a"])),
            Err(Refusal::Expired)
        );
        assert_eq!(
            auth.check(b"nonsense", &ns(&[b"a"])),
            Err(Refusal::Malformed)
        );
        let mut bad = auth.issue(&ns(&[b"a"]), future());
        bad.replace_range(bad.len() - 2.., "00");
        assert_eq!(
            auth.check(bad.as_bytes(), &ns(&[b"a"])),
            Err(Refusal::Unauthorized)
        );
    }

    #[test]
    fn the_token_cache_counts_and_refuses() {
        let mut cache = TokenCache::new(40);
        let reg = |alias, v: &'static [u8]| Token::Register {
            alias,
            kind: 0,
            value: Bytes::from_static(v),
        };
        assert!(cache.apply(&[reg(1, b"0123456789")], false, true).is_ok());
        assert_eq!(cache.used(), 26);
        assert_eq!(
            cache.apply(&[reg(1, b"x")], false, true),
            Err(SessionCode::DuplicateAuthTokenAlias)
        );
        assert_eq!(
            cache.apply(&[reg(2, b"0123456789")], false, true),
            Err(SessionCode::AuthTokenCacheOverflow)
        );
        // In SETUP, over the limit is used as a value, not registered
        assert_eq!(
            cache
                .apply(&[reg(2, b"0123456789")], true, true)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(cache.used(), 26);
        assert_eq!(
            cache.apply(&[Token::UseAlias { alias: 9 }], false, true),
            Err(SessionCode::UnknownAuthTokenAlias)
        );
        assert_eq!(
            cache.apply(&[Token::UseAlias { alias: 1 }], true, true),
            Err(SessionCode::RoleViolation)
        );
        assert!(cache
            .apply(&[Token::Delete { alias: 1 }], false, true)
            .is_ok());
        assert_eq!(cache.used(), 0);
    }
}
