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
//!
//! First, though, the address ranges each operator publishes (Google, Bing,
//! DuckDuckGo, Apple, OpenAI, Perplexity, Common Crawl, Ahrefs): the method the
//! operators themselves recommend, decided at once with no lookup. Reverse DNS
//! alone could not verify DuckDuckBot at all (its addresses have no PTR, so
//! every request was "a spoofer"), and Google's documented suffixes include
//! `googleusercontent.com`, which any Google Cloud VM can name itself under.
//! The ranges are refreshed every six hours and cached on disk, where the edge
//! honeypot feed reads them too, so a restart verifies from the first request.

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Where the published ranges are cached between refreshes and restarts. The
/// edge honeypot feed (scripts/detect_bots_from_logs.sh) reads it to spare
/// verified crawlers its bans.
pub const RANGES_CACHE: &str = "/var/lib/pqcrypta-proxy/crawler-ranges.json";

/// How often the published ranges are fetched again.
const RANGES_REFRESH: Duration = Duration::from_hours(6);

/// A feed larger than this is not an address list.
const MAX_FEED_BYTES: usize = 4 << 20;

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

/// One crawler family: the User-Agent tokens it identifies itself with, the
/// address ranges its operator publishes, and the DNS suffixes its addresses
/// reverse-resolve into.
struct CrawlerSpec {
    /// Names the family in the ranges cache.
    family: &'static str,
    /// Lowercase substrings; a match on any one selects this spec.
    ua_tokens: &'static [&'static str],
    /// The operator's published address ranges (`{"prefixes": [{"ipv4Prefix":
    /// ...}, {"ipv6Prefix": ...}]}`). Once loaded they decide on their own: an
    /// address inside is the crawler, outside is not, unless the family also
    /// has a DNS contract, which then gets the final say (a feed can lag a
    /// new range).
    feeds: &'static [&'static str],
    /// Lowercase PTR suffixes; the PTR name must end with one of them. Empty
    /// for operators that publish no reverse-DNS contract.
    dns_suffixes: &'static [&'static str],
}

/// The crawlers worth exempting, with the verification each operator documents.
///
/// Only operators that publish ranges or a reverse-DNS contract belong here.
/// One that cannot be verified must not be listed, because listing it would
/// turn its User-Agent into a free bypass for anyone who types it.
static CRAWLERS: &[CrawlerSpec] = &[
    CrawlerSpec {
        // Googlebot, plus the Search Console live-test fetcher, Google's
        // shopping/other crawlers, the AdsBot family and its fetchers.
        family: "google",
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
        feeds: &[
            "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
            "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
            "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
        ],
        // Not `.googleusercontent.com`: every Google Cloud VM has a PTR there
        // that resolves back, which made it a Googlebot pass for anyone.
        dns_suffixes: &[".googlebot.com", ".google.com"],
    },
    CrawlerSpec {
        family: "bing",
        ua_tokens: &["bingbot", "adidxbot", "msnbot", "bingpreview"],
        feeds: &["https://www.bing.com/toolbox/bingbot.json"],
        dns_suffixes: &[".search.msn.com"],
    },
    CrawlerSpec {
        // No reverse DNS: DuckDuckBot's addresses have no PTR records.
        family: "duckduckgo",
        ua_tokens: &["duckduckbot", "duckduckgo-favicons-bot"],
        feeds: &["https://duckduckgo.com/duckduckbot.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "apple",
        ua_tokens: &["applebot"],
        feeds: &["https://search.developer.apple.com/applebot.json"],
        dns_suffixes: &[".applebot.apple.com"],
    },
    CrawlerSpec {
        family: "openai-gptbot",
        ua_tokens: &["gptbot"],
        feeds: &["https://openai.com/gptbot.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "openai-searchbot",
        ua_tokens: &["oai-searchbot"],
        feeds: &["https://openai.com/searchbot.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "openai-user",
        ua_tokens: &["chatgpt-user"],
        feeds: &["https://openai.com/chatgpt-user.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "perplexity-bot",
        ua_tokens: &["perplexitybot"],
        feeds: &["https://www.perplexity.ai/perplexitybot.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "perplexity-user",
        ua_tokens: &["perplexity-user"],
        feeds: &["https://www.perplexity.ai/perplexity-user.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "commoncrawl",
        ua_tokens: &["ccbot"],
        feeds: &["https://index.commoncrawl.org/ccbot.json"],
        dns_suffixes: &[],
    },
    CrawlerSpec {
        family: "ahrefs",
        ua_tokens: &["ahrefsbot", "ahrefssiteaudit"],
        feeds: &["https://api.ahrefs.com/v3/public/crawler-ip-ranges"],
        dns_suffixes: &[".ahrefs.com", ".ahrefs.net"],
    },
    CrawlerSpec {
        family: "yandex",
        ua_tokens: &["yandexbot", "yandeximages", "yandexaccessibilitybot"],
        feeds: &[],
        dns_suffixes: &[".yandex.ru", ".yandex.net", ".yandex.com"],
    },
    CrawlerSpec {
        family: "baidu",
        ua_tokens: &["baiduspider"],
        feeds: &[],
        dns_suffixes: &[".baidu.com", ".baidu.jp"],
    },
];

/// Each family's published ranges, as last fetched.
type PublishedRanges = HashMap<&'static str, Arc<[IpNet]>>;

/// Match a User-Agent against the known crawler families.
/// Case-insensitive substring search that does not allocate.
///
/// `str::contains` is case-sensitive, so matching a lowercase token meant
/// lowercasing the whole User-Agent first -- a heap allocation on every request,
/// for a scan that almost always finds nothing. The tokens in `CRAWLERS` are all
/// lowercase ASCII, so comparing each window with `eq_ignore_ascii_case` gives
/// the same answer with no allocation.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    if n.is_empty() {
        return true;
    }
    if h.len() < n.len() {
        return false;
    }
    // Compare on the first byte before the full window: most windows differ
    // there, and this keeps the common miss to one comparison per position.
    let first = n[0];
    h.windows(n.len())
        .any(|w| (w[0] | 0x20) == first && w.eq_ignore_ascii_case(n))
}

fn spec_for_user_agent(user_agent: &str) -> Option<&'static CrawlerSpec> {
    CRAWLERS.iter().find(|spec| {
        spec.ua_tokens
            .iter()
            .any(|token| contains_ignore_ascii_case(user_agent, token))
    })
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
    /// The operators' published ranges; empty until loaded or fetched.
    ranges: Arc<ArcSwap<PublishedRanges>>,
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
            ranges: Arc::new(ArcSwap::from_pointee(PublishedRanges::new())),
            inline: false,
        }
    }

    /// A verifier that also checks the operators' published ranges: loaded
    /// from `cache` now, then fetched every six hours and written back to it.
    /// Needs a Tokio runtime to refresh; without one it uses the cache alone.
    pub fn with_published_ranges(cache: &Path) -> Self {
        let verifier = Self::new();
        if let Some(loaded) = read_ranges_cache(cache) {
            info!(
                "Crawler ranges loaded from {}: {} families",
                cache.display(),
                loaded.len()
            );
            verifier.ranges.store(Arc::new(loaded));
        }
        spawn_range_refresh(verifier.ranges.clone(), cache.to_path_buf());
        verifier
    }

    /// Build a verifier that resolves synchronously. For tests only — a
    /// blocking DNS lookup must never happen on a request path.
    #[cfg(test)]
    pub fn new_inline() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ranges: Arc::new(ArcSwap::from_pointee(PublishedRanges::new())),
            inline: true,
        }
    }

    /// Classify a request. Never blocks: an unknown address schedules its own
    /// lookup and reports [`CrawlerVerdict::Pending`] until that lands.
    pub fn classify(&self, ip: IpAddr, user_agent: Option<&str>) -> CrawlerVerdict {
        let Some(spec) = user_agent.and_then(spec_for_user_agent) else {
            return CrawlerVerdict::NotClaimed;
        };

        // The operator's published ranges, when loaded, decide at once.
        if let Some(nets) = self.ranges.load().get(spec.family) {
            if nets.iter().any(|net| net.contains(&ip)) {
                self.remember(ip, CrawlerVerdict::Verified);
                return CrawlerVerdict::Verified;
            }
            if spec.dns_suffixes.is_empty() {
                self.remember(ip, CrawlerVerdict::Rejected);
                return CrawlerVerdict::Rejected;
            }
            // Outside the ranges, but this operator also has a DNS contract:
            // a feed can lag a new range, so DNS has the final say.
        } else if spec.dns_suffixes.is_empty() {
            // Verifiable only by its ranges, and they are not loaded.
            return CrawlerVerdict::Rejected;
        }

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

    /// Record a verdict decided from the published ranges, so that
    /// [`Self::cached_verdict`] (callers with no User-Agent) knows it too.
    /// Writes only when the cache does not already say so.
    fn remember(&self, ip: IpAddr, verdict: CrawlerVerdict) {
        let current = self.cache.get(&ip).map(|e| *e);
        let fresh = current
            .is_some_and(|e| e.verdict == verdict && e.expires.is_some_and(|d| d > Instant::now()));
        if !fresh {
            self.prune_if_needed();
            self.cache.insert(ip, finished_entry(verdict));
        }
    }

    /// Replace the published ranges (tests).
    #[cfg(test)]
    fn set_ranges(&self, family: &'static str, nets: &[&str]) {
        let mut map = (**self.ranges.load()).clone();
        map.insert(family, nets.iter().map(|n| n.parse().unwrap()).collect());
        self.ranges.store(Arc::new(map));
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

/// The prefixes of one published feed: `{"prefixes": [{"ipv4Prefix": "a/n"},
/// {"ipv6Prefix": "b/m"}]}`, the shape every operator here uses. Unparseable
/// entries are skipped; an unparseable document is None.
fn parse_feed(body: &[u8]) -> Option<Vec<IpNet>> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let prefixes = doc.get("prefixes")?.as_array()?;
    Some(
        prefixes
            .iter()
            .filter_map(|p| {
                p.get("ipv4Prefix")
                    .or_else(|| p.get("ipv6Prefix"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|s| s.trim().parse::<IpNet>().ok())
            })
            .map(|net| net.trunc())
            .collect(),
    )
}

/// The cache file: `{"generated_at": ..., "families": {"google": ["a/n", ...]}}`.
/// Families this build does not know are ignored.
fn read_ranges_cache(path: &Path) -> Option<PublishedRanges> {
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let families = doc.get("families")?.as_object()?;
    let mut map = PublishedRanges::new();
    for spec in CRAWLERS.iter().filter(|s| !s.feeds.is_empty()) {
        let Some(list) = families.get(spec.family).and_then(|v| v.as_array()) else {
            continue;
        };
        let nets: Vec<IpNet> = list
            .iter()
            .filter_map(|v| v.as_str()?.parse().ok())
            .collect();
        if !nets.is_empty() {
            map.insert(spec.family, nets.into());
        }
    }
    (!map.is_empty()).then_some(map)
}

fn write_ranges_cache(path: &Path, ranges: &PublishedRanges) -> std::io::Result<()> {
    let families: serde_json::Map<String, serde_json::Value> = ranges
        .iter()
        .map(|(family, nets)| {
            let list = nets
                .iter()
                .map(|n| serde_json::Value::String(n.to_string()));
            (
                (*family).to_string(),
                serde_json::Value::Array(list.collect()),
            )
        })
        .collect();
    let doc = serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "families": families,
    });
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Written whole and renamed, so a reader never sees half a file.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&doc)?)?;
    std::fs::rename(&tmp, path)
}

/// Fetch every family's feeds now and every [`RANGES_REFRESH`] after. A family
/// is replaced only when all of its feeds were fetched and parsed: one failed
/// feed must not drop the ranges the others cover.
fn spawn_range_refresh(ranges: Arc<ArcSwap<PublishedRanges>>, cache: PathBuf) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("pqcrypta-proxy crawler-range refresh (+https://pqcrypta.com/pqcproxy/)")
            .build()
            .unwrap_or_default();
        loop {
            let mut next = (**ranges.load()).clone();
            let mut refreshed = Vec::new();
            for spec in CRAWLERS.iter().filter(|s| !s.feeds.is_empty()) {
                let mut nets = Vec::new();
                let mut complete = true;
                for url in spec.feeds {
                    match fetch_feed(&client, url).await {
                        Ok(feed) if !feed.is_empty() => nets.extend(feed),
                        Ok(_) => {
                            warn!("Crawler ranges: {} listed no prefixes", url);
                            complete = false;
                        }
                        Err(e) => {
                            warn!("Crawler ranges: {} failed: {}", url, e);
                            complete = false;
                        }
                    }
                }
                if complete {
                    nets.sort();
                    nets.dedup();
                    refreshed.push(format!("{} {}", spec.family, nets.len()));
                    next.insert(spec.family, nets.into());
                }
            }
            if !refreshed.is_empty() {
                info!("Crawler ranges refreshed: {}", refreshed.join(", "));
                if let Err(e) = write_ranges_cache(&cache, &next) {
                    warn!("Crawler ranges: could not write {}: {}", cache.display(), e);
                }
                ranges.store(Arc::new(next));
            }
            tokio::time::sleep(RANGES_REFRESH).await;
        }
    });
}

async fn fetch_feed(client: &reqwest::Client, url: &str) -> Result<Vec<IpNet>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| e.to_string())?;
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_FEED_BYTES as u64)
    {
        return Err("larger than an address list".into());
    }
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    if body.len() > MAX_FEED_BYTES {
        return Err("larger than an address list".into());
    }
    parse_feed(&body).ok_or_else(|| "not a prefix list".into())
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
    #[test]
    fn user_agent_matching_is_case_insensitive_without_allocating() {
        // The lowercase path this replaced used `to_ascii_lowercase()` on every
        // request; these assert the hand-rolled search agrees with it.
        assert!(spec_for_user_agent("Mozilla/5.0 (compatible; Googlebot/2.1)").is_some());
        assert!(spec_for_user_agent("mozilla/5.0 (compatible; googlebot/2.1)").is_some());
        assert!(spec_for_user_agent("MOZILLA/5.0 (COMPATIBLE; GOOGLEBOT/2.1)").is_some());
        assert!(spec_for_user_agent("BingBot/2.0").is_some());
        assert!(spec_for_user_agent("bInGbOt/2.0").is_some());

        assert!(spec_for_user_agent("").is_none());
        assert!(spec_for_user_agent("curl/8.5.0").is_none());
        assert!(spec_for_user_agent("h2load nghttp2/1.64.0").is_none());
        // A token that is a prefix of nothing present must not match.
        assert!(spec_for_user_agent("googlebo").is_none());
    }

    #[test]
    fn contains_ignore_ascii_case_matches_the_lowercasing_it_replaced() {
        for (hay, needle) in [
            ("Googlebot", "googlebot"),
            ("xxGOOGLEBOTxx", "googlebot"),
            ("aaa", "aaa"),
            ("aab", "aaa"),
            ("", "x"),
            ("short", "muchlongerneedle"),
            ("AbC", ""),
        ] {
            assert_eq!(
                contains_ignore_ascii_case(hay, needle),
                hay.to_ascii_lowercase().contains(needle),
                "{hay:?} contains {needle:?}"
            );
        }
    }

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
            assert_eq!(spec.family, "google");
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
    fn published_ranges_verify_without_dns() {
        let verifier = CrawlerVerifier::new_inline();
        // DuckDuckBot's real address: no PTR, so DNS alone rejected it
        verifier.set_ranges("duckduckgo", &["20.191.45.212/32", "40.88.21.235/32"]);
        let ua = Some("DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)");
        let ip: IpAddr = "20.191.45.212".parse().unwrap();
        assert_eq!(verifier.classify(ip, ua), CrawlerVerdict::Verified);
        // Known to callers without a User-Agent too
        assert_eq!(verifier.cached_verdict(ip), Some(CrawlerVerdict::Verified));

        // Outside the ranges, and no DNS contract to fall back on
        let other: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(verifier.classify(other, ua), CrawlerVerdict::Rejected);
    }

    #[test]
    fn a_family_without_dns_is_unverifiable_until_its_ranges_load() {
        let verifier = CrawlerVerifier::new_inline();
        let ip: IpAddr = "20.191.45.212".parse().unwrap();
        assert_eq!(
            verifier.classify(ip, Some("DuckDuckBot/1.1")),
            CrawlerVerdict::Rejected
        );
    }

    #[test]
    fn google_cloud_vms_are_not_googlebot() {
        // Every GCP VM resolves under googleusercontent.com, forward-confirmed
        for spec in CRAWLERS {
            assert!(
                !spec
                    .dns_suffixes
                    .iter()
                    .any(|s| s.ends_with("googleusercontent.com")),
                "{} accepts googleusercontent.com",
                spec.family
            );
        }
    }

    #[test]
    fn feeds_parse_both_address_families() {
        let body = br#"{"creationTime":"2026-10-05T14:47:00","prefixes":[
            {"ipv4Prefix":"66.249.64.0/27"},{"ipv6Prefix":"2001:4860:4801:10::/64"},
            {"ipv4Prefix":"not a prefix"},{"other":"x"}]}"#;
        let nets = parse_feed(body).unwrap();
        assert_eq!(nets.len(), 2);
        assert!(nets[0].contains(&"66.249.64.9".parse::<IpAddr>().unwrap()));
        assert!(parse_feed(b"<html>").is_none());
        assert!(parse_feed(br#"{"no":"prefixes"}"#).is_none());
    }

    #[test]
    fn the_cache_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crawler-ranges.json");
        let mut map = PublishedRanges::new();
        map.insert("bing", vec!["157.55.39.0/24".parse().unwrap()].into());
        map.insert("not-a-family", vec!["192.0.2.0/24".parse().unwrap()].into());
        write_ranges_cache(&path, &map).unwrap();
        let back = read_ranges_cache(&path).unwrap();
        assert_eq!(back.len(), 1, "unknown families are dropped");
        assert!(back["bing"][0].contains(&"157.55.39.59".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn every_family_has_a_way_to_verify() {
        for spec in CRAWLERS {
            assert!(
                !spec.feeds.is_empty() || !spec.dns_suffixes.is_empty(),
                "{} cannot be verified",
                spec.family
            );
        }
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
