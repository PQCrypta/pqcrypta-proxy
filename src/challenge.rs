//! A proof-of-work challenge in front of a browser the proxy would otherwise
//! refuse on a heuristic (`[security.challenge]`).
//!
//! An address blocked by a rule that guesses -- too many requests, too many
//! errors, a fingerprint seen too often -- is refused on every request until
//! the block lapses, a person behind a busy NAT included. With the challenge
//! on, a page load from such an address gets an interstitial instead: the
//! browser solves a proof of work (about a second of hashing) and is handed a
//! pass, a cookie that lets that browser through the heuristic blocks for
//! `pass_ttl_secs`. Other requests from the address are refused as before,
//! and a block an operator or the database made is never lifted by a pass.
//! A route with `[routes.security] challenge = true` asks for a pass on every
//! page load, blocked or not.
//!
//! The work is [ALTCHA](https://altcha.org)'s: the page carries
//! `{algorithm, challenge, maxnumber, salt, signature}` and the browser finds
//! the `n` in `0..=maxnumber` for which `SHA-256(salt || n)` is `challenge`,
//! on average `maxnumber / 2` digests. Nothing is stored when a challenge is
//! issued: the expiry travels in the salt, which the challenge hash covers,
//! and the signature is an HMAC over the challenge and the client's network,
//! so a solution is worth nothing from another network. A solved challenge is
//! spent once. The pass is an HMAC over the network, a digest of the
//! User-Agent and the expiry, so it is not stored either.
//!
//! The page, its script and its worker are served by the proxy under
//! [`PREFIX`], each with a Content-Security-Policy that admits nothing else:
//! no inline script or style, no third party.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use http::HeaderMap;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::ChallengeConfig;

type HmacSha256 = Hmac<Sha256>;

/// Where the challenge's own resources are served, on every host.
pub const PREFIX: &str = "/.well-known/pqcrypta-challenge/";

/// The cookie that carries a pass. `__Host-`: set only over HTTPS, for the
/// whole host and no other.
pub const COOKIE: &str = "__Host-pqcrypta-pass";

/// The most solved challenges remembered as spent at once. Each is kept until
/// it expires; a solution that arrives while the set is full is refused
/// rather than accepted unrecorded.
const MAX_SPENT: usize = 100_000;

/// How long an issued challenge may be solved.
const CHALLENGE_TTL_SECS: u64 = 300;

/// The page's script: reads the challenge, hands it to the worker, and goes
/// to the pass address with the answer.
const SCRIPT: &str = include_str!("challenge/challenge.js");
/// The worker that does the hashing, off the page's thread.
const WORKER: &str = include_str!("challenge/worker.js");
/// The page's stylesheet.
const STYLE: &str = include_str!("challenge/challenge.css");
/// The page's icon: named in the page, so a browser asks for it rather than
/// for the site's `/favicon.ico`, which an address the page stands in front
/// of is refused.
const ICON: &str = include_str!("challenge/icon.svg");

/// The interstitial's Content-Security-Policy.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; worker-src 'self'; \
     style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; \
     frame-ancestors 'none'";

/// What a request under [`PREFIX`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Script,
    Worker,
    Style,
    Icon,
    Pass,
}

impl Endpoint {
    /// The endpoint `path` names, if it is one of the challenge's.
    pub fn of(path: &str) -> Option<Self> {
        match path.strip_prefix(PREFIX)? {
            "challenge.js" => Some(Self::Script),
            "worker.js" => Some(Self::Worker),
            "challenge.css" => Some(Self::Style),
            "icon.svg" => Some(Self::Icon),
            "pass" => Some(Self::Pass),
            _ => None,
        }
    }

    /// A static resource: its media type and body.
    pub const fn asset(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Script => Some(("text/javascript; charset=utf-8", SCRIPT)),
            Self::Worker => Some(("text/javascript; charset=utf-8", WORKER)),
            Self::Style => Some(("text/css; charset=utf-8", STYLE)),
            Self::Icon => Some(("image/svg+xml", ICON)),
            Self::Pass => None,
        }
    }
}

/// Why a solution was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("malformed solution")]
    Malformed,
    #[error("unsupported algorithm")]
    Algorithm,
    #[error("challenge expired")]
    Expired,
    #[error("not a challenge this server issued to this network")]
    Signature,
    #[error("number does not solve the challenge")]
    Unsolved,
    #[error("challenge already used")]
    Replayed,
    #[error("too many recent solutions to record this one; try again")]
    Busy,
}

/// Issues and checks challenges and passes.
pub struct Challenger {
    /// Keys used when `[security.challenge] secret` is unset: a process's
    /// own, so passes lapse when it restarts.
    process_secret: [u8; 32],
    /// Solved challenges, by challenge, with when they expire
    spent: Mutex<HashMap<[u8; 32], u64>>,
    /// Challenges issued, solutions accepted and solutions refused, for
    /// `pqcrypta_challenges_total`
    pub issued: AtomicU64,
    pub passed: AtomicU64,
    pub failed: AtomicU64,
}

impl Default for Challenger {
    fn default() -> Self {
        Self::new()
    }
}

impl Challenger {
    pub fn new() -> Self {
        Self {
            process_secret: rand::random(),
            spent: Mutex::new(HashMap::new()),
            issued: AtomicU64::new(0),
            passed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    /// The key for one purpose, from the configured secret or the process's.
    fn key(&self, config: &ChallengeConfig, purpose: &[u8]) -> [u8; 32] {
        let secret = config
            .secret
            .as_deref()
            .map_or(&self.process_secret[..], str::as_bytes);
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(secret)
            .expect("HMAC-SHA256 takes a key of any length");
        mac.update(b"pqcrypta-proxy challenge v1\0");
        mac.update(purpose);
        mac.finalize().into_bytes().into()
    }

    /// A challenge for a client on `ip`'s network, valid from `now` for
    /// [`CHALLENGE_TTL_SECS`].
    pub fn issue(&self, config: &ChallengeConfig, ip: IpAddr, now: u64) -> Issued {
        let max_number = config.max_number.max(1);
        let salt = format!(
            "{}?expires={}",
            hex::encode(rand::random::<[u8; 12]>()),
            now + CHALLENGE_TTL_SECS
        );
        let number = rand::random_range(0..=max_number);
        let challenge = hex::encode(Sha256::digest(format!("{salt}{number}")));
        let signature = self.signature(config, &challenge, ip);
        self.issued.fetch_add(1, Ordering::Relaxed);
        Issued {
            challenge,
            max_number,
            salt,
            signature,
        }
    }

    fn signature(&self, config: &ChallengeConfig, challenge: &str, ip: IpAddr) -> String {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.key(config, b"issue"))
            .expect("32-byte key");
        mac.update(challenge.as_bytes());
        mac.update(&network_bytes(ip));
        hex::encode(mac.finalize().into_bytes())
    }

    /// Check a solution sent by a client on `ip`'s network, spending it.
    pub fn redeem(
        &self,
        config: &ChallengeConfig,
        solution: &Solution,
        ip: IpAddr,
        now: u64,
    ) -> Result<(), Refusal> {
        let outcome = self.check(config, solution, ip, now);
        match outcome {
            Ok(()) => &self.passed,
            Err(_) => &self.failed,
        }
        .fetch_add(1, Ordering::Relaxed);
        outcome
    }

    fn check(
        &self,
        config: &ChallengeConfig,
        solution: &Solution,
        ip: IpAddr,
        now: u64,
    ) -> Result<(), Refusal> {
        if !solution.algorithm.eq_ignore_ascii_case("SHA-256") {
            return Err(Refusal::Algorithm);
        }
        let expires = salt_expiry(&solution.salt).ok_or(Refusal::Malformed)?;
        if now > expires {
            return Err(Refusal::Expired);
        }
        let expected = self.signature(config, &solution.challenge, ip);
        if !bool::from(
            expected
                .as_bytes()
                .ct_eq(solution.signature.to_ascii_lowercase().as_bytes()),
        ) {
            return Err(Refusal::Signature);
        }
        let digest = Sha256::digest(format!("{}{}", solution.salt, solution.number));
        let claimed: [u8; 32] = hex::decode(&solution.challenge)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Refusal::Malformed)?;
        if !bool::from(digest.as_slice().ct_eq(&claimed[..])) {
            return Err(Refusal::Unsolved);
        }
        let mut spent = self.spent.lock();
        if spent.len() >= MAX_SPENT {
            spent.retain(|_, until| *until >= now);
        }
        if spent.contains_key(&claimed) {
            return Err(Refusal::Replayed);
        }
        if spent.len() >= MAX_SPENT {
            return Err(Refusal::Busy);
        }
        spent.insert(claimed, expires);
        Ok(())
    }

    /// A pass for the browser that sent `headers` from `ip`, from `now`:
    /// the cookie's value.
    pub fn pass(
        &self,
        config: &ChallengeConfig,
        ip: IpAddr,
        headers: &HeaderMap,
        now: u64,
    ) -> String {
        let expires = now + config.pass_ttl_secs;
        format!("{expires}.{}", self.pass_mac(config, ip, headers, expires))
    }

    fn pass_mac(
        &self,
        config: &ChallengeConfig,
        ip: IpAddr,
        headers: &HeaderMap,
        expires: u64,
    ) -> String {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&self.key(config, b"pass"))
            .expect("32-byte key");
        mac.update(&network_bytes(ip));
        mac.update(&Sha256::digest(
            headers
                .get(http::header::USER_AGENT)
                .map_or(&b""[..], |v| v.as_bytes()),
        ));
        mac.update(&expires.to_be_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Whether the request carries a pass, unexpired, for this browser on
    /// this network.
    pub fn has_pass(
        &self,
        config: &ChallengeConfig,
        ip: IpAddr,
        headers: &HeaderMap,
        now: u64,
    ) -> bool {
        cookie_values(headers, COOKIE).any(|value| {
            let Some((expires, mac)) = value.split_once('.') else {
                return false;
            };
            let Ok(expires) = expires.parse::<u64>() else {
                return false;
            };
            if now > expires || expires > now + config.pass_ttl_secs {
                return false;
            }
            let expected = self.pass_mac(config, ip, headers, expires);
            bool::from(expected.as_bytes().ct_eq(mac.as_bytes()))
        })
    }
}

/// A challenge as issued, for the page.
#[derive(Debug, Clone)]
pub struct Issued {
    pub challenge: String,
    pub max_number: u64,
    pub salt: String,
    pub signature: String,
}

/// A solution as the browser returns it: the challenge's fields and the
/// number found.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Solution {
    pub algorithm: String,
    pub challenge: String,
    pub number: u64,
    pub salt: String,
    pub signature: String,
}

impl Solution {
    /// The solution in a pass request's query (`solution=`, base64url JSON),
    /// with the address to return to (`return=`, a path on this host).
    pub fn from_query(query: &str) -> Option<(Self, String)> {
        let mut solution = None;
        let mut back = String::from("/");
        for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match &*name {
                "solution" => {
                    let json = base64::Engine::decode(
                        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                        value.trim_end_matches('=').as_bytes(),
                    )
                    .ok()?;
                    solution = serde_json::from_slice(&json).ok();
                }
                "return" => back = safe_return(&value),
                _ => {}
            }
        }
        Some((solution?, back))
    }
}

/// `target` when it is a path on this host, else `/`: a pass never sends the
/// browser elsewhere.
pub fn safe_return(target: &str) -> String {
    let local = target.starts_with('/')
        && !target.starts_with("//")
        && !target.starts_with("/\\")
        && !target.bytes().any(|b| b.is_ascii_control());
    if local {
        target.to_string()
    } else {
        "/".to_string()
    }
}

/// Whether a request is a page load a person is waiting on: a navigation by
/// its `Sec-Fetch-Mode`, or, from a browser that sends none, a GET or HEAD
/// that accepts HTML.
pub fn is_navigation(method: &str, headers: &HeaderMap) -> bool {
    if !matches!(method, "GET" | "HEAD") {
        return false;
    }
    if let Some(mode) = headers.get("sec-fetch-mode") {
        return mode.as_bytes().eq_ignore_ascii_case(b"navigate");
    }
    headers
        .get_all(http::header::ACCEPT)
        .iter()
        .any(|v| v.to_str().is_ok_and(|v| v.contains("text/html")))
}

/// The interstitial for `issued`. It is served at the address the browser
/// asked for, so once solved the script returns it there.
pub fn page(issued: &Issued) -> String {
    let challenge = serde_json::json!({
        "algorithm": "SHA-256",
        "challenge": issued.challenge,
        "maxnumber": issued.max_number,
        "salt": issued.salt,
        "signature": issued.signature,
    })
    .to_string();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <meta name=\"robots\" content=\"noindex\">\n<title>Checking your browser</title>\n\
         <link rel=\"icon\" href=\"{PREFIX}icon.svg\" type=\"image/svg+xml\">\n\
         <link rel=\"stylesheet\" href=\"{PREFIX}challenge.css\">\n\
         <script src=\"{PREFIX}challenge.js\" defer></script>\n</head>\n<body>\n\
         <main id=\"pqc-challenge\" data-challenge=\"{}\">\n\
         <h1>Checking your browser</h1>\n\
         <p>Traffic from your network looked automated, so this site asks your browser for \
         about a second of work before it continues. Nothing is installed or kept.</p>\n\
         <p id=\"pqc-status\" role=\"status\" aria-live=\"polite\">Working&hellip;</p>\n\
         <noscript><p>This check needs JavaScript. Turn it on and reload the page.</p></noscript>\n\
         </main>\n</body>\n</html>\n",
        escape_attribute(&challenge)
    )
}

/// The interstitial's headers beside its media type.
pub const fn page_csp() -> &'static str {
    PAGE_CSP
}

/// The Set-Cookie value for a pass.
pub fn pass_cookie(value: &str, config: &ChallengeConfig) -> String {
    format!(
        "{COOKIE}={value}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite=Lax",
        config.pass_ttl_secs
    )
}

/// Seconds since the Unix epoch.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The network a challenge and a pass are bound to: the one the fingerprint
/// corpus counts a client as (an IPv4 /24, an IPv6 /48), so a browser whose
/// address moves within its provider's pool keeps its pass.
fn network_bytes(ip: IpAddr) -> [u8; 16] {
    crate::fingerprint_corpus::client_network(ip).to_be_bytes()
}

/// The `expires=` parameter of an ALTCHA salt (`random?expires=unix`).
fn salt_expiry(salt: &str) -> Option<u64> {
    let (_, params) = salt.split_once('?')?;
    url::form_urlencoded::parse(params.as_bytes())
        .find(|(k, _)| k == "expires")
        .and_then(|(_, v)| v.parse().ok())
}

/// Every value `name` has in the request's `Cookie` fields.
fn cookie_values<'a>(headers: &'a HeaderMap, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(move |pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then_some(v)
        })
}

/// Text made safe for a double-quoted HTML attribute.
fn escape_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn config() -> ChallengeConfig {
        ChallengeConfig {
            enabled: true,
            max_number: 2_000,
            ..ChallengeConfig::default()
        }
    }

    fn solve(issued: &Issued) -> Solution {
        let number = (0..=issued.max_number)
            .find(|n| {
                hex::encode(Sha256::digest(format!("{}{n}", issued.salt))) == issued.challenge
            })
            .expect("the number is in range");
        Solution {
            algorithm: "SHA-256".into(),
            challenge: issued.challenge.clone(),
            number,
            salt: issued.salt.clone(),
            signature: issued.signature.clone(),
        }
    }

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

    #[test]
    fn a_solved_challenge_is_redeemed_once_on_its_own_network() {
        let c = Challenger::new();
        let cfg = config();
        let now = 1_000_000;
        let issued = c.issue(&cfg, IP, now);
        let solution = solve(&issued);
        let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(
            c.redeem(&cfg, &solution, elsewhere, now),
            Err(Refusal::Signature)
        );
        assert_eq!(c.redeem(&cfg, &solution, IP, now), Ok(()));
        assert_eq!(c.redeem(&cfg, &solution, IP, now), Err(Refusal::Replayed));
        // Same /24: the same network
        let neighbour = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
        let again = solve(&c.issue(&cfg, IP, now));
        assert_eq!(c.redeem(&cfg, &again, neighbour, now), Ok(()));
    }

    #[test]
    fn a_wrong_number_or_a_late_answer_is_refused() {
        let c = Challenger::new();
        let cfg = config();
        let issued = c.issue(&cfg, IP, 1_000);
        let mut wrong = solve(&issued);
        wrong.number = wrong.number.wrapping_add(1);
        assert_eq!(c.redeem(&cfg, &wrong, IP, 1_000), Err(Refusal::Unsolved));
        let late = solve(&issued);
        assert_eq!(
            c.redeem(&cfg, &late, IP, 1_000 + CHALLENGE_TTL_SECS + 1),
            Err(Refusal::Expired)
        );
        let mut moved = solve(&issued);
        moved.salt = moved.salt.replace("expires=", "expires=9");
        assert!(
            c.redeem(&cfg, &moved, IP, 1_000).is_err(),
            "the expiry is covered by the hash"
        );
    }

    #[test]
    fn a_pass_is_for_its_browser_network_and_lifetime() {
        let c = Challenger::new();
        let cfg = config();
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.0 test".parse().unwrap(),
        );
        let value = c.pass(&cfg, IP, &headers, 5_000);
        headers.insert(
            http::header::COOKIE,
            format!("a=b; {COOKIE}={value}").parse().unwrap(),
        );
        assert!(c.has_pass(&cfg, IP, &headers, 5_000));
        assert!(!c.has_pass(&cfg, IP, &headers, 5_000 + cfg.pass_ttl_secs + 1));
        assert!(!c.has_pass(
            &cfg,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            &headers,
            5_000
        ));
        let mut other_ua = headers.clone();
        other_ua.insert(http::header::USER_AGENT, "curl/8".parse().unwrap());
        assert!(!c.has_pass(&cfg, IP, &other_ua, 5_000));
        // A pass from another process is not one, unless they share a secret
        assert!(!Challenger::new().has_pass(&cfg, IP, &headers, 5_000));
        let shared = ChallengeConfig {
            secret: Some("x".repeat(32)),
            ..cfg
        };
        let (a, b) = (Challenger::new(), Challenger::new());
        let value = a.pass(&shared, IP, &headers, 5_000);
        headers.insert(
            http::header::COOKIE,
            format!("{COOKIE}={value}").parse().unwrap(),
        );
        assert!(b.has_pass(&shared, IP, &headers, 5_000));
    }

    #[test]
    fn the_pass_request_round_trips_and_returns_only_home() {
        let solution = Solution {
            algorithm: "SHA-256".into(),
            challenge: "ab".into(),
            number: 7,
            salt: "s?expires=1".into(),
            signature: "cd".into(),
        };
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&solution).unwrap(),
        );
        let (parsed, back) =
            Solution::from_query(&format!("solution={encoded}&return=%2Fdocs%3Fa%3D1")).unwrap();
        assert_eq!(parsed.number, 7);
        assert_eq!(back, "/docs?a=1");
        for evil in [
            "https://evil.test/",
            "//evil.test",
            "/\\evil.test",
            "/a\r\nSet-Cookie: x",
        ] {
            assert_eq!(safe_return(evil), "/");
        }
    }

    #[test]
    fn only_page_loads_are_navigations() {
        let mut h = HeaderMap::new();
        h.insert("sec-fetch-mode", "navigate".parse().unwrap());
        assert!(is_navigation("GET", &h));
        assert!(!is_navigation("POST", &h));
        h.insert("sec-fetch-mode", "cors".parse().unwrap());
        h.insert(http::header::ACCEPT, "text/html".parse().unwrap());
        assert!(
            !is_navigation("GET", &h),
            "Sec-Fetch-Mode decides when sent"
        );
        let mut old = HeaderMap::new();
        old.insert(
            http::header::ACCEPT,
            "text/html,application/xhtml+xml".parse().unwrap(),
        );
        assert!(is_navigation("GET", &old));
        assert!(!is_navigation("GET", &HeaderMap::new()));
    }

    #[test]
    fn the_page_escapes_what_it_carries() {
        let issued = Issued {
            challenge: "c".into(),
            max_number: 1,
            salt: "\"><script>".into(),
            signature: "x".into(),
        };
        let html = page(&issued);
        assert!(!html.contains("\"><script>"));
        assert!(html.contains("&gt;&lt;script&gt;"));
        assert!(!html.contains(" style="), "no inline style");
        assert_eq!(
            Endpoint::of("/.well-known/pqcrypta-challenge/pass"),
            Some(Endpoint::Pass)
        );
        assert_eq!(Endpoint::of("/.well-known/pqcrypta-challenge/x"), None);
        assert_eq!(
            Endpoint::of("/.well-known/pqcrypta-challenge/icon.svg")
                .and_then(Endpoint::asset)
                .map(|a| a.0),
            Some("image/svg+xml")
        );
        assert!(html.contains("icon.svg"), "the page names its own icon");
        assert!(page_csp().contains("img-src 'self'"));
    }
}
