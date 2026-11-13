//! Key-exchange groups the linked OpenSSL's providers carry and rustls does not.
//!
//! The experimental KEMs `pqc.experimental_groups` names, which the OpenSSL
//! listener offers over TCP, are offered over QUIC (and every rustls listener)
//! as well, so a client meets the same groups on both transports. They were
//! TCP's alone: a scan read four groups accepted over TCP and refused over
//! QUIC v1 and v2.
//!
//! A group's TLS code point and KEM are read from the provider that implements
//! it (its TLS-GROUP capability), so they are the ones the OpenSSL listener
//! negotiates under the same name, and key generation, encapsulation and
//! decapsulation are the provider's, through EVP_PKEY: one implementation on
//! both transports.
#![allow(unsafe_code)] // OpenSSL's provider and EVP_PKEY entry points

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};
use std::ptr;
use std::sync::{LazyLock, Mutex};

use openssl_sys::{EVP_PKEY, EVP_PKEY_CTX, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PROVIDER};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

unsafe extern "C" {
    fn OSSL_PROVIDER_do_all(
        ctx: *mut OSSL_LIB_CTX,
        cb: unsafe extern "C" fn(*mut OSSL_PROVIDER, *mut c_void) -> c_int,
        cbdata: *mut c_void,
    ) -> c_int;
    fn OSSL_PROVIDER_get_capabilities(
        prov: *const OSSL_PROVIDER,
        capability: *const c_char,
        cb: unsafe extern "C" fn(*const OSSL_PARAM, *mut c_void) -> c_int,
        arg: *mut c_void,
    ) -> c_int;
    fn OSSL_PARAM_get_uint(p: *const OSSL_PARAM, val: *mut c_uint) -> c_int;
    fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut OSSL_LIB_CTX,
        pkey: *mut EVP_PKEY,
        propquery: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
}

/// A TLS group a provider carries, as its TLS-GROUP capability states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGroup {
    /// The name `SSL_CTX_set1_groups_list` takes
    pub name: String,
    /// The IANA code point
    pub id: u16,
    /// The algorithm behind it, by its OpenSSL name
    pub algorithm: String,
    /// A key-encapsulation group (a ciphertext answers the key share)
    pub kem: bool,
}

/// Every TLS group the providers this process has loaded carry: the
/// providers' own statement, read once (each provider is loaded from the
/// configuration when OpenSSL initialises).
pub fn provider_groups() -> &'static [ProviderGroup] {
    static GROUPS: LazyLock<Vec<ProviderGroup>> = LazyLock::new(|| {
        openssl::init();
        let mut groups: Vec<ProviderGroup> = Vec::new();
        // Safety: the callback receives `groups` back as its argument and
        // nothing else holds it during the call.
        unsafe {
            OSSL_PROVIDER_do_all(
                ptr::null_mut(),
                each_provider,
                (&raw mut groups).cast::<c_void>(),
            );
        }
        drop(openssl::error::ErrorStack::get());
        groups
    });
    &GROUPS
}

unsafe extern "C" fn each_provider(provider: *mut OSSL_PROVIDER, data: *mut c_void) -> c_int {
    // Safety: `provider` is live for the call; `data` is passed on unchanged.
    unsafe { OSSL_PROVIDER_get_capabilities(provider, c"TLS-GROUP".as_ptr(), each_group, data) };
    1
}

unsafe extern "C" fn each_group(params: *const OSSL_PARAM, data: *mut c_void) -> c_int {
    // Safety: `data` is the `Vec` `provider_groups` passed, borrowed by no one
    // else for the duration of the walk.
    let groups = unsafe { &mut *data.cast::<Vec<ProviderGroup>>() };
    let text = |key: &CStr| -> Option<String> {
        // Safety: `params` is the provider's array, live for the callback.
        unsafe {
            let p = openssl_sys::OSSL_PARAM_locate_const(params, key.as_ptr());
            let mut value: *const c_char = ptr::null();
            (!p.is_null()
                && openssl_sys::OSSL_PARAM_get_utf8_string_ptr(p, &raw mut value) == 1
                && !value.is_null())
            .then(|| CStr::from_ptr(value).to_string_lossy().into_owned())
        }
    };
    let number = |key: &CStr| -> Option<u32> {
        // Safety: as for `text`.
        unsafe {
            let p = openssl_sys::OSSL_PARAM_locate_const(params, key.as_ptr());
            let mut value: c_uint = 0;
            (!p.is_null() && OSSL_PARAM_get_uint(p, &raw mut value) == 1).then_some(value)
        }
    };
    if let (Some(name), Some(id), Some(algorithm)) = (
        text(c"tls-group-name"),
        number(c"tls-group-id").and_then(|id| u16::try_from(id).ok()),
        text(c"tls-group-alg"),
    ) {
        let kem = number(c"tls-group-is-kem") == Some(1);
        if !groups.iter().any(|g| g.name == name) {
            groups.push(ProviderGroup {
                name,
                id,
                algorithm,
                kem,
            });
        }
    }
    1
}

/// The groups for `names` (`pqc.experimental_groups`), in the order given.
///
/// Each is a key-encapsulation group a loaded provider carries and rustls
/// does not. A name no provider carries is left out, as the OpenSSL listener
/// leaves it out of its offer.
pub fn groups(names: &[String]) -> Vec<&'static dyn SupportedKxGroup> {
    names.iter().filter_map(|name| group(name)).collect()
}

/// The group named `name`, made once per process: rustls holds groups for
/// good, and a reload asks again.
fn group(name: &str) -> Option<&'static dyn SupportedKxGroup> {
    static MADE: LazyLock<Mutex<HashMap<String, &'static ProviderKem>>> =
        LazyLock::new(Mutex::default);
    let mut made = MADE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(kem) = made.get(name) {
        return Some(*kem);
    }
    let found = provider_groups()
        .iter()
        .find(|g| g.kem && g.name.eq_ignore_ascii_case(name))?;
    let group = NamedGroup::from(found.id);
    // A group rustls implements itself is its own
    if !matches!(group, NamedGroup::Unknown(_)) {
        return None;
    }
    let kem: &'static ProviderKem = Box::leak(Box::new(ProviderKem {
        group,
        algorithm: CString::new(found.algorithm.as_str()).ok()?,
    }));
    made.insert(name.to_string(), kem);
    Some(kem)
}

/// Whether `group` is one of these groups.
pub fn is_provider_group(group: NamedGroup) -> bool {
    matches!(group, NamedGroup::Unknown(id) if provider_groups().iter().any(|g| g.kem && g.id == id))
}

/// A provider's key-encapsulation group.
#[derive(Debug)]
struct ProviderKem {
    group: NamedGroup,
    algorithm: CString,
}

impl SupportedKxGroup for ProviderKem {
    /// A client's side: a key pair, the public half the key share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let key = Pkey::generate(&self.algorithm)?;
        let public = key.public()?;
        Ok(Box::new(ActiveProviderKem {
            key,
            public,
            group: self.group,
        }))
    }

    /// A server's side: the client's key share encapsulated to, the
    /// ciphertext answering it.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let key = Pkey::from_public(&self.algorithm, client_share)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let (ciphertext, secret) = key
            .encapsulate()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        Ok(CompletedKeyExchange {
            group: self.group,
            pub_key: ciphertext,
            secret: SharedSecret::from(secret.as_slice()),
        })
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

/// A client's key pair, waiting for the server's ciphertext.
struct ActiveProviderKem {
    key: Pkey,
    public: Vec<u8>,
    group: NamedGroup,
}

impl ActiveKeyExchange for ActiveProviderKem {
    fn complete(self: Box<Self>, ciphertext: &[u8]) -> Result<SharedSecret, Error> {
        let secret = self
            .key
            .decapsulate(ciphertext)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(secret.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

/// An OpenSSL failure, its error queue cleared.
fn failed(what: &str) -> Error {
    drop(openssl::error::ErrorStack::get());
    Error::General(format!("provider KEM: {what} failed"))
}

/// An `EVP_PKEY`, freed on drop.
struct Pkey(*mut EVP_PKEY);

// Safety: an EVP_PKEY is used here by one thread at a time (a key exchange
// is completed once), and OpenSSL's key objects may be moved between threads.
unsafe impl Send for Pkey {}
// Safety: shared references only read the key (its public half).
unsafe impl Sync for Pkey {}

impl Drop for Pkey {
    fn drop(&mut self) {
        // Safety: owned, freed once.
        unsafe { openssl_sys::EVP_PKEY_free(self.0) };
    }
}

/// An `EVP_PKEY_CTX`, freed on drop.
struct Ctx(*mut EVP_PKEY_CTX);

impl Drop for Ctx {
    fn drop(&mut self) {
        // Safety: owned, freed once.
        unsafe { openssl_sys::EVP_PKEY_CTX_free(self.0) };
    }
}

impl Ctx {
    fn by_name(algorithm: &CStr) -> Result<Self, Error> {
        // Safety: default library context and properties; `algorithm` outlives the call.
        let ctx = unsafe {
            openssl_sys::EVP_PKEY_CTX_new_from_name(
                ptr::null_mut(),
                algorithm.as_ptr(),
                ptr::null(),
            )
        };
        if ctx.is_null() {
            return Err(failed("fetching the algorithm"));
        }
        Ok(Self(ctx))
    }

    fn for_key(key: &Pkey) -> Result<Self, Error> {
        // Safety: `key` is live; the context takes its own reference.
        let ctx = unsafe { EVP_PKEY_CTX_new_from_pkey(ptr::null_mut(), key.0, ptr::null()) };
        if ctx.is_null() {
            return Err(failed("a context for the key"));
        }
        Ok(Self(ctx))
    }
}

impl Pkey {
    fn generate(algorithm: &CStr) -> Result<Self, Error> {
        let ctx = Ctx::by_name(algorithm)?;
        let mut key: *mut EVP_PKEY = ptr::null_mut();
        // Safety: `ctx` is live; `key` receives a new key or stays null.
        let ok = unsafe {
            openssl_sys::EVP_PKEY_keygen_init(ctx.0) == 1
                && openssl_sys::EVP_PKEY_generate(ctx.0, &raw mut key) == 1
        };
        if !ok || key.is_null() {
            return Err(failed("key generation"));
        }
        Ok(Self(key))
    }

    fn from_public(algorithm: &CStr, public: &[u8]) -> Result<Self, Error> {
        let ctx = Ctx::by_name(algorithm)?;
        let mut copy = public.to_vec();
        let mut key: *mut EVP_PKEY = ptr::null_mut();
        // Safety: the parameter array points at `copy`, live for the call;
        // `key` receives a new key or stays null.
        let ok = unsafe {
            let mut params = [
                openssl_sys::OSSL_PARAM_construct_octet_string(
                    c"pub".as_ptr(),
                    copy.as_mut_ptr().cast::<c_void>(),
                    copy.len(),
                ),
                openssl_sys::OSSL_PARAM_construct_end(),
            ];
            openssl_sys::EVP_PKEY_fromdata_init(ctx.0) == 1
                && openssl_sys::EVP_PKEY_fromdata(
                    ctx.0,
                    &raw mut key,
                    openssl_sys::EVP_PKEY_PUBLIC_KEY,
                    params.as_mut_ptr(),
                ) == 1
        };
        if !ok || key.is_null() {
            return Err(failed("reading the key share"));
        }
        Ok(Self(key))
    }

    /// The public key's encoding: the key share.
    fn public(&self) -> Result<Vec<u8>, Error> {
        let mut len = 0usize;
        // Safety: a null buffer asks for the length.
        let sized = unsafe {
            openssl_sys::EVP_PKEY_get_octet_string_param(
                self.0,
                c"pub".as_ptr(),
                ptr::null_mut(),
                0,
                &raw mut len,
            )
        };
        if sized != 1 || len == 0 {
            return Err(failed("sizing the public key"));
        }
        let mut out = vec![0u8; len];
        // Safety: `out` holds `len` bytes.
        let ok = unsafe {
            openssl_sys::EVP_PKEY_get_octet_string_param(
                self.0,
                c"pub".as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &raw mut len,
            )
        };
        if ok != 1 {
            return Err(failed("reading the public key"));
        }
        out.truncate(len);
        Ok(out)
    }

    /// A ciphertext to this public key, and the secret it carries.
    fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let ctx = Ctx::for_key(self)?;
        let (mut ct_len, mut ss_len) = (0usize, 0usize);
        // Safety: `ctx` is live; null buffers ask for the lengths.
        let sized = unsafe {
            openssl_sys::EVP_PKEY_encapsulate_init(ctx.0, ptr::null()) == 1
                && openssl_sys::EVP_PKEY_encapsulate(
                    ctx.0,
                    ptr::null_mut(),
                    &raw mut ct_len,
                    ptr::null_mut(),
                    &raw mut ss_len,
                ) == 1
        };
        if !sized {
            return Err(failed("sizing the encapsulation"));
        }
        let (mut ct, mut ss) = (vec![0u8; ct_len], vec![0u8; ss_len]);
        // Safety: the buffers hold the lengths OpenSSL gave.
        let ok = unsafe {
            openssl_sys::EVP_PKEY_encapsulate(
                ctx.0,
                ct.as_mut_ptr(),
                &raw mut ct_len,
                ss.as_mut_ptr(),
                &raw mut ss_len,
            ) == 1
        };
        if !ok {
            return Err(failed("encapsulation"));
        }
        ct.truncate(ct_len);
        ss.truncate(ss_len);
        Ok((ct, ss))
    }

    /// The secret `ciphertext` carries to this private key.
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let ctx = Ctx::for_key(self)?;
        let mut ss_len = 0usize;
        // Safety: `ctx` is live; a null buffer asks for the length.
        let sized = unsafe {
            openssl_sys::EVP_PKEY_decapsulate_init(ctx.0, ptr::null()) == 1
                && openssl_sys::EVP_PKEY_decapsulate(
                    ctx.0,
                    ptr::null_mut(),
                    &raw mut ss_len,
                    ciphertext.as_ptr(),
                    ciphertext.len(),
                ) == 1
        };
        if !sized {
            return Err(failed("sizing the decapsulation"));
        }
        let mut ss = vec![0u8; ss_len];
        // Safety: `ss` holds the length OpenSSL gave; `ciphertext` is live.
        let ok = unsafe {
            openssl_sys::EVP_PKEY_decapsulate(
                ctx.0,
                ss.as_mut_ptr(),
                &raw mut ss_len,
                ciphertext.as_ptr(),
                ciphertext.len(),
            ) == 1
        };
        if !ok {
            return Err(failed("decapsulation"));
        }
        ss.truncate(ss_len);
        Ok(ss)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ML-KEM-768 by the default provider stands in where no experimental
    /// provider is loaded: the same EVP_PKEY path, a KEM every OpenSSL 3.5+
    /// carries.
    fn some_kem() -> CString {
        provider_groups()
            .iter()
            .find(|g| g.kem && NamedGroup::from(g.id) == NamedGroup::Unknown(g.id))
            .map_or_else(
                || CString::new("ML-KEM-768").unwrap(),
                |g| CString::new(g.algorithm.as_str()).unwrap(),
            )
    }

    /// A client's key pair and a server's encapsulation agree on the secret.
    #[test]
    fn both_sides_of_a_provider_kem_agree() {
        let alg = some_kem();
        let kem = ProviderKem {
            group: NamedGroup::Unknown(0xfe00),
            algorithm: alg,
        };
        let client = kem.start().expect("a key pair");
        let server = kem
            .start_and_complete(client.pub_key())
            .expect("an encapsulation");
        let ciphertext = server.pub_key.clone();
        let client_secret = client.complete(&ciphertext).expect("a decapsulation");
        assert_eq!(
            client_secret.secret_bytes(),
            server.secret.secret_bytes(),
            "the two sides' secrets"
        );
        assert_ne!(ciphertext.len(), 0);
    }

    /// A key share that is not a public key is the peer's fault.
    #[test]
    fn a_malformed_key_share_is_refused() {
        let kem = ProviderKem {
            group: NamedGroup::Unknown(0xfe00),
            algorithm: some_kem(),
        };
        assert!(matches!(
            kem.start_and_complete(&[7u8; 9]),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        ));
    }

    /// The provider statement names each group once, with its code point;
    /// the default provider's groups are among them.
    #[test]
    fn the_providers_state_their_groups() {
        let groups = provider_groups();
        assert!(groups.iter().any(|g| g.name.eq_ignore_ascii_case("x25519")));
        let mut names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), groups.len());
        // rustls implements X25519MLKEM768 itself: never offered from here
        assert!(group("X25519MLKEM768").is_none());
    }
}
