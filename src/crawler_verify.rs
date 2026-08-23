//! Verified search-engine crawler detection.
//!
//! Search engines render pages by fetching the document plus every subresource
//! in a tight burst from a pool of addresses. To the rate limiter that is
//! indistinguishable from a flood: on 2026-08-19 a single Search Console live
//! test of `/` produced ~25 requests in one second from 66.249.68.1/.2/.8 and
//! tripped `connection_rate_limit`, which banned all three addresses for 300s.
//! Every URL inspected inside that window then reported "Blocked due to access
//! forbidden (403)" in Search Console, and the site's crawl budget collapsed to
//! ~110 requests/day because Google kept walking into the wall.
//!
//! A User-Agent string alone cannot justify a bypass — it is trivially spoofed,
//! and the access logs here already carry plenty of fake `Googlebot` traffic
//! from unrelated networks. This module therefore applies the verification each
//! search engine documents: reverse-resolve the client address to a PTR name,
//! require that name to sit under a domain the operator actually controls, then
//! forward-resolve that name and require it to point back at the same address.
//! Controlling the PTR record is not enough; the attacker would also have to
//! control forward DNS under `googlebot.com`.
//!
//! Lookups are blocking, so they never run on the request path. A first sighting
//! returns [`CrawlerVerdict::Pending`] and schedules the check in the
//! background; the answer is cached and every later request from that address
//! is decided from memory.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// How long a confirmed crawler address stays trusted.
const VERIFIED_TTL: Duration = Duration::from_hours(24);

/// How long a failed verification is remembered. Kept far shorter than
/// [`VERIFIED_TTL`] so that a transient resolver failure cannot lock a genuine
/// crawler out for a day.
const REJECTED_TTL: Duration = Duration::from_mins(15);

/// Upper bound on tracked addresses. Spoofed-UA traffic is the reason this cap
/// exists: without it, a flood of forged `Googlebot` requests from random
/// addresses would grow the map without limit.
const MAX_ENTRIES: usize = 20_000;

/// What is known about a client that claims to be a crawler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrawlerVerdict {
    /// The User-Agent does not claim to be any crawler this module knows.
    NotClaimed,
    /// Claims a crawler; verification has been scheduled but has not finished.
    ///
    /// Callers should treat this as "probably genuine, but unproven": worth
    /// sparing from a punitive multi-minute ban, not worth a full bypass.
    Pending,
    /// Forward-confirmed reverse DNS. Genuine crawler.
    Verified,
    /// Claims a crawler but DNS does not back it up. A spoofer.
    Rejected,
}

/// One crawler family: the User-Agent tokens it identifies itself with, and the
/// DNS suffixes its addresses must reverse-resolve into.
struct CrawlerSpec {
    /// Lowercase substrings; a match on any one selects this spec.
    ua_tokens: &'static [&'static str],
    /// Lowercase PTR suffixes; the PTR name must end with one of them.
    dns_suffixes: &'static [&'static str],
}

/// Documented verification domains for the crawlers worth exempting.
///
/// Only engines that publish a reverse-DNS contract belong here. An engine that
/// cannot be verified must not be listed, because listing it would turn its
/// User-Agent into a free bypass for anyone who types it.
static CRAWLERS: &[CrawlerSpec] = &[
    CrawlerSpec {
        // Googlebot, plus the Search Console live-test fetcher, Google's
        // shopping/other crawlers, and the AdsBot family.
        ua_tokens: &[
            "googlebot",
            "google-inspectiontool",
            "storebot-google",
            "googleother",
            "google-extended",
            "adsbot-google",
            "apis-google",
            "feedfetcher-google",
        ],
        dns_suffixes: &[".googlebot.com", ".google.com", ".googleusercontent.com"],
    },
    CrawlerSpec {
        ua_tokens: &["bingbot", "adidxbot", "msnbot", "bingpreview"],
        dns_suffixes: &[".search.msn.com"],
    },
    CrawlerSpec {
        ua_tokens: &["duckduckbot", "duckduckgo-favicons-bot"],
        dns_suffixes: &[".duckduckgo.com"],
    },
    CrawlerSpec {
        ua_tokens: &["applebot"],
        dns_suffixes: &[".applebot.apple.com"],
    },
    CrawlerSpec {
        ua_tokens: &["yandexbot", "yandeximages", "yandexaccessibilitybot"],
        dns_suffixes: &[".yandex.ru", ".yandex.net", ".yandex.com"],
    },
    CrawlerSpec {
        ua_tokens: &["baiduspider"],
        dns_suffixes: &[".baidu.com", ".baidu.jp"],
    },
];

/// Match a User-Agent against the known crawler families.
fn spec_for_user_agent(user_agent: &str) -> Option<&'static CrawlerSpec> {
    let ua = user_agent.to_ascii_lowercase();
    CRAWLERS
        .iter()
        .find(|spec| spec.ua_tokens.iter().any(|token| ua.contains(token)))
}

#[derive(Clone, Copy)]
struct CacheEntry {
    verdict: CrawlerVerdict,
    /// `None` while a background check is in flight.
    expires: Option<Instant>,
}

/// Cache of crawler verification results, keyed by client address.
pub struct CrawlerVerifier {
    cache: Arc<DashMap<IpAddr, CacheEntry>>,
    /// Set when no async runtime is available (unit tests, startup probes), in
    /// which case verification runs inline instead of being spawned.
    inline: bool,
}

impl Default for CrawlerVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CrawlerVerifier {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            inline: false,
        }
    }

    /// Build a verifier that resolves synchronously. For tests only — a
    /// blocking DNS lookup must never happen on a request path.
    #[cfg(test)]
    pub fn new_inline() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            inline: true,
        }
    }

    /// Classify a request. Never blocks: an unknown address schedules its own
    /// lookup and reports [`CrawlerVerdict::Pending`] until that lands.
    pub fn classify(&self, ip: IpAddr, user_agent: Option<&str>) -> CrawlerVerdict {
        let Some(spec) = user_agent.and_then(spec_for_user_agent) else {
            return CrawlerVerdict::NotClaimed;
        };

        if let Some(entry) = self.cache.get(&ip) {
            match entry.expires {
                // A check is still running.
                None => return CrawlerVerdict::Pending,
                Some(deadline) if deadline > Instant::now() => return entry.verdict,
                // Expired — fall through and re-verify.
                Some(_) => {}
            }
        }

        // Claim the slot before spawning so a burst from one address schedules
        // exactly one lookup rather than one per request.
        use dashmap::mapref::entry::Entry;
        match self.cache.entry(ip) {
            Entry::Occupied(mut occupied) => {
                let current = *occupied.get();
                match current.expires {
                    None => return CrawlerVerdict::Pending,
                    Some(deadline) if deadline > Instant::now() => return current.verdict,
                    Some(_) => occupied.insert(CacheEntry {
                        verdict: CrawlerVerdict::Pending,
                        expires: None,
                    }),
                };
            }
            Entry::Vacant(vacant) => {
                vacant.insert(CacheEntry {
                    verdict: CrawlerVerdict::Pending,
                    expires: None,
                });
            }
        }

        self.prune_if_needed();

        let cache = Arc::clone(&self.cache);
        let suffixes = spec.dns_suffixes;

        if self.inline {
            let verdict = verify_reverse_dns(ip, suffixes);
            cache.insert(ip, finished_entry(verdict));
            return verdict;
        }

        // `spawn_blocking` because getnameinfo/getaddrinfo block the thread.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    let verdict =
                        match tokio::task::spawn_blocking(move || verify_reverse_dns(ip, suffixes))
                            .await
                        {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("Crawler verification task for {} failed: {}", ip, e);
                                CrawlerVerdict::Rejected
                            }
                        };
                    cache.insert(ip, finished_entry(verdict));
                });
            }
            Err(_) => {
                // No runtime (startup verification harness). Resolve inline
                // rather than leaving the entry pinned at Pending forever.
                let verdict = verify_reverse_dns(ip, suffixes);
                cache.insert(ip, finished_entry(verdict));
                return verdict;
            }
        }

        CrawlerVerdict::Pending
    }

    /// Read a previously established verdict without scheduling a lookup.
    ///
    /// For call sites that have an address but no User-Agent — the error-rate
    /// auto-blocker, for instance, which only sees a status code. Returns
    /// `None` when nothing is cached or the entry has expired.
    pub fn cached_verdict(&self, ip: IpAddr) -> Option<CrawlerVerdict> {
        let entry = self.cache.get(&ip)?;
        match entry.expires {
            None => Some(CrawlerVerdict::Pending),
            Some(deadline) if deadline > Instant::now() => Some(entry.verdict),
            Some(_) => None,
        }
    }

    /// Drop expired entries once the map grows past its cap.
    fn prune_if_needed(&self) {
        if self.cache.len() <= MAX_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.cache
            .retain(|_, entry| entry.expires.is_none_or(|deadline| deadline > now));

        // Still oversized means the entries are live, not stale: shed the
        // rejections first, since those are the spoof traffic.
        if self.cache.len() > MAX_ENTRIES {
            self.cache
                .retain(|_, entry| entry.verdict != CrawlerVerdict::Rejected);
        }
    }
}

fn finished_entry(verdict: CrawlerVerdict) -> CacheEntry {
    let ttl = match verdict {
        CrawlerVerdict::Verified => VERIFIED_TTL,
        _ => REJECTED_TTL,
    };
    CacheEntry {
        verdict,
        expires: Some(Instant::now() + ttl),
    }
}

/// The verification itself: PTR lookup, suffix check, then forward confirmation.
///
/// Blocking. Callers must keep it off the request path.
fn verify_reverse_dns(ip: IpAddr, allowed_suffixes: &[&str]) -> CrawlerVerdict {
    let hostname = match dns_lookup::lookup_addr(&ip) {
        Ok(name) => name.to_ascii_lowercase(),
        Err(e) => {
            debug!("Crawler check: no PTR for {} ({})", ip, e);
            return CrawlerVerdict::Rejected;
        }
    };

    // `lookup_addr` yields the address back as a string when no PTR exists.
    if hostname == ip.to_string() {
        debug!("Crawler check: {} has no PTR record", ip);
        return CrawlerVerdict::Rejected;
    }

    // Compare against ".googlebot.com" rather than "googlebot.com" so that a
    // lookalike registration such as "evil-googlebot.com" cannot match.
    let suffix_ok = allowed_suffixes
        .iter()
        .any(|suffix| hostname.ends_with(suffix));
    if !suffix_ok {
        warn!(
            "Crawler check: {} claims a crawler UA but PTR is {} (not an allowed domain)",
            ip, hostname
        );
        return CrawlerVerdict::Rejected;
    }

    // Forward confirmation. Without this step, anyone able to set a PTR record
    // on their own address space could name themselves *.googlebot.com.
    match dns_lookup::lookup_host(&hostname) {
        Ok(addrs) => {
            // lookup_host yields an iterator; collect so the address list can be
            // both tested and reported.
            let addrs: Vec<IpAddr> = addrs.into_iter().collect();
            if addrs.contains(&ip) {
                debug!("Crawler check: {} verified as {}", ip, hostname);
                CrawlerVerdict::Verified
            } else {
                warn!(
                    "Crawler check: {} PTR {} does not resolve back (got {:?})",
                    ip, hostname, addrs
                );
                CrawlerVerdict::Rejected
            }
        }
        Err(e) => {
            debug!(
                "Crawler check: forward lookup of {} failed ({})",
                hostname, e
            );
            CrawlerVerdict::Rejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn matches_googlebot_user_agents() {
        for ua in [
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Google-InspectionTool/1.0)",
            "Mozilla/5.0 (compatible; GoogleOther)",
        ] {
            let spec = spec_for_user_agent(ua).expect("should match google");
            assert!(spec.dns_suffixes.contains(&".googlebot.com"));
        }
    }

    #[test]
    fn matches_other_engines() {
        assert!(spec_for_user_agent("compatible; bingbot/2.0").is_some());
        assert!(spec_for_user_agent("DuckDuckBot/1.1").is_some());
        assert!(spec_for_user_agent("Applebot/0.1").is_some());
    }

    #[test]
    fn ignores_ordinary_browsers() {
        assert!(spec_for_user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36"
        )
        .is_none());
        assert!(spec_for_user_agent("curl/8.5.0").is_none());
    }

    #[test]
    fn no_user_agent_is_not_a_crawler() {
        let verifier = CrawlerVerifier::new_inline();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(verifier.classify(ip, None), CrawlerVerdict::NotClaimed);
        assert_eq!(
            verifier.classify(ip, Some("Mozilla/5.0")),
            CrawlerVerdict::NotClaimed
        );
    }

    #[test]
    fn spoofed_googlebot_from_unrelated_address_is_rejected() {
        let verifier = CrawlerVerifier::new_inline();
        // TEST-NET-1: reserved, guaranteed to have no googlebot.com PTR.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42));
        assert_eq!(
            verifier.classify(ip, Some("Mozilla/5.0 (compatible; Googlebot/2.1)")),
            CrawlerVerdict::Rejected
        );
    }

    #[test]
    fn lookalike_domain_does_not_satisfy_the_suffix_check() {
        // The suffix list is matched with a leading dot precisely so that a
        // registered lookalike cannot pass.
        let suffixes = &[".googlebot.com"];
        let hostname = "crawl-66-249-68-1.evil-googlebot.com";
        assert!(!suffixes.iter().any(|s| hostname.ends_with(s)));
    }

    #[test]
    fn verdict_is_cached_after_first_lookup() {
        let verifier = CrawlerVerifier::new_inline();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 43));
        let ua = Some("Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(verifier.classify(ip, ua), CrawlerVerdict::Rejected);
        assert!(verifier.cache.get(&ip).is_some());
        // Second call is served from cache and must agree.
        assert_eq!(verifier.classify(ip, ua), CrawlerVerdict::Rejected);
    }
}
