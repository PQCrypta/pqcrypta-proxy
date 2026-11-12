//! HTTP/3 Advanced Features Module
//!
//! Implements these HTTP/3 features:
//! - **Early Hints (103)**: Preload critical resources before final response
//! - **Priority Hints**: Extensible Priorities (RFC 9218) for resource scheduling
//!
//! # Integration
//! All features are configurable via the `[http3]` section in proxy-config.toml:
//! - `early_hints_enabled` - Enable 103 Early Hints (Link headers as fallback)
//! - `priority_hints_enabled` - Enable RFC 9218 Priority headers
//! - `coalescing_*` - collapse identical cache misses onto one fetch, which the
//!   response cache does (`ResponseCache::lookup`)
//!
//! # Usage
//! ```ignore
//! let state = Http3FeaturesState::from_proxy_config(&config.http3);
//! router.layer(middleware::from_fn_with_state(state, http3_features_middleware));
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, Response};
use axum::middleware::Next;
use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::debug;

// ============================================================================
// Early Hints (103 Status Code)
// ============================================================================

/// Early Hints configuration
#[derive(Debug, Clone)]
pub struct EarlyHintsConfig {
    /// Enable Early Hints
    pub enabled: bool,
    /// Resources to preload (path -> hints)
    pub preload_rules: Vec<PreloadRule>,
    /// Default preconnect origins
    pub preconnect_origins: Vec<String>,
    /// Enable automatic CSS/JS detection from HTML
    pub auto_detect: bool,
}

impl Default for EarlyHintsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            preload_rules: vec![],
            preconnect_origins: vec![
                "https://fonts.googleapis.com".to_string(),
                "https://fonts.gstatic.com".to_string(),
            ],
            auto_detect: true,
        }
    }
}

/// Preload rule for a path pattern
#[derive(Debug, Clone)]
pub struct PreloadRule {
    /// Optional hostname to restrict this rule (exact match, no www). None = all hosts.
    pub host_pattern: Option<String>,
    /// Path pattern (prefix match, or exact when `exact` is set)
    pub path_pattern: String,
    /// Match `path_pattern` exactly instead of as a prefix.
    pub exact: bool,
    /// Link hints to send
    pub hints: Vec<LinkHint>,
}

/// Link hint types for Early Hints
#[derive(Debug, Clone)]
pub enum LinkHint {
    /// Preload a resource
    Preload {
        href: String,
        as_type: String,
        crossorigin: Option<String>,
        /// The href's `?v=` comes from this file's mtime (`version_file`)
        version_file: Option<String>,
    },
    /// Preconnect to an origin
    Preconnect {
        href: String,
        crossorigin: Option<String>,
    },
    /// DNS prefetch
    DnsPrefetch { href: String },
    /// Prerender a page (speculative)
    Prerender { href: String },
    /// Module preload
    ModulePreload {
        href: String,
        crossorigin: Option<String>,
        /// The href's `?v=` comes from this file's mtime (`version_file`)
        version_file: Option<String>,
    },
}

/// `href` with `v=<mtime of file>` added, as PHP's `filemtime` gives it, or
/// None when the file cannot be read: a hint for a URL the page does not
/// link is a wasted download, so none is sent.
fn versioned_href(href: &str, file: Option<&str>) -> Option<String> {
    let Some(file) = file else {
        return Some(href.to_string());
    };
    let mtime = std::fs::metadata(file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let Some(mtime) = mtime else {
        debug!("Early hint for {href}: version_file {file} unreadable, hint left out");
        return None;
    };
    let sep = if href.contains('?') { '&' } else { '?' };
    Some(format!("{href}{sep}v={mtime}"))
}

/// How long compiled hints that carry a `version_file` version are reused
/// before the files are looked at again.
const VERSIONED_HINTS_TTL: Duration = Duration::from_secs(5);

/// Compiled Link headers for one host and path.
#[derive(Debug, Clone)]
pub struct CachedHints {
    pub headers: Vec<String>,
    built: Instant,
    /// Some header carries a `version_file` version, so it can go stale
    versioned: bool,
}

impl LinkHint {
    /// The hint a `[[http3.preload_resources]]` entry describes. `rel` is
    /// checked at config load, so anything unrecognised here is `preload`.
    pub fn from_config(res: &crate::config::PreloadResourceConfig) -> Self {
        let href = res.href.clone();
        let crossorigin = res.crossorigin.clone();
        let version_file = res.version_file.clone();
        match res.rel.as_str() {
            "modulepreload" => LinkHint::ModulePreload {
                href,
                crossorigin,
                version_file,
            },
            "preconnect" => LinkHint::Preconnect { href, crossorigin },
            "dns-prefetch" => LinkHint::DnsPrefetch { href },
            "prerender" => LinkHint::Prerender { href },
            _ => LinkHint::Preload {
                href,
                as_type: res.as_type.clone(),
                crossorigin,
                version_file,
            },
        }
    }

    /// Whether the header depends on a file's mtime (and so can go stale).
    pub const fn is_versioned(&self) -> bool {
        matches!(
            self,
            LinkHint::Preload {
                version_file: Some(_),
                ..
            } | LinkHint::ModulePreload {
                version_file: Some(_),
                ..
            }
        )
    }

    /// Convert to Link header value; None for a versioned hint whose file
    /// cannot be read.
    pub fn to_link_header(&self) -> Option<String> {
        Some(match self {
            LinkHint::Preload {
                href,
                as_type,
                crossorigin,
                version_file,
            } => {
                let href = versioned_href(href, version_file.as_deref())?;
                let mut link = format!("<{}>; rel=preload; as={}", href, as_type);
                if let Some(co) = crossorigin {
                    link.push_str(&format!("; crossorigin={}", co));
                }
                link
            }
            LinkHint::Preconnect { href, crossorigin } => {
                let mut link = format!("<{}>; rel=preconnect", href);
                if let Some(co) = crossorigin {
                    link.push_str(&format!("; crossorigin={}", co));
                }
                link
            }
            LinkHint::DnsPrefetch { href } => {
                format!("<{}>; rel=dns-prefetch", href)
            }
            LinkHint::Prerender { href } => {
                format!("<{}>; rel=prerender", href)
            }
            LinkHint::ModulePreload {
                href,
                crossorigin,
                version_file,
            } => {
                let href = versioned_href(href, version_file.as_deref())?;
                let mut link = format!("<{}>; rel=modulepreload", href);
                if let Some(co) = crossorigin {
                    link.push_str(&format!("; crossorigin={}", co));
                }
                link
            }
        })
    }
}

/// State for Early Hints
#[derive(Clone)]
pub struct EarlyHintsState {
    pub config: Arc<RwLock<EarlyHintsConfig>>,
    /// Compiled hints, by the rules they were compiled from: which reload of
    /// the configuration, and which of its preload rules matched. The hints
    /// are a function of those alone, so there are as many entries as there
    /// are ways the rules combine, whatever paths are asked for.
    pub hints_cache: Arc<DashMap<(u64, Vec<usize>), CachedHints>>,
    /// Counts reloads of `config`; part of the cache key, so hints compiled
    /// from one configuration are never served under the next.
    generation: Arc<std::sync::atomic::AtomicU64>,
}

/// The most rule combinations whose hints are kept compiled; past it they are
/// compiled per request.
const MAX_HINT_SETS: usize = 1024;

impl Default for EarlyHintsState {
    fn default() -> Self {
        Self {
            config: Arc::new(RwLock::new(EarlyHintsConfig::default())),
            hints_cache: Arc::new(DashMap::new()),
            generation: Arc::default(),
        }
    }
}

impl EarlyHintsState {
    /// Build an [`EarlyHintsConfig`] from the [http3] section of proxy-config.toml.
    /// Converts `preload_resources` entries into `PreloadRule`s grouped by (host, path),
    /// so the TOML drives exactly what gets sent in 103 Early Hints.
    fn build_config(config: &crate::config::Http3Config) -> EarlyHintsConfig {
        use std::collections::HashMap;

        // Group preload resources by (host, path, exact) key
        let mut by_key: HashMap<(Option<String>, String, bool), Vec<LinkHint>> = HashMap::new();
        for res in &config.preload_resources {
            by_key
                .entry((res.host.clone(), res.path.clone(), res.exact))
                .or_default()
                .push(LinkHint::from_config(res));
        }
        let preload_rules: Vec<PreloadRule> = by_key
            .into_iter()
            .map(|((host_pattern, path_pattern, exact), hints)| PreloadRule {
                host_pattern,
                path_pattern,
                exact,
                hints,
            })
            .collect();

        EarlyHintsConfig {
            enabled: config.early_hints_enabled,
            preconnect_origins: config.preconnect_origins.clone(),
            preload_rules,
            auto_detect: false,
        }
    }

    /// Create from the `[http3]` section of proxy-config.toml.
    pub fn from_http3_config(config: &crate::config::Http3Config) -> Self {
        Self {
            config: Arc::new(RwLock::new(Self::build_config(config))),
            hints_cache: Arc::new(DashMap::new()),
            generation: Arc::default(),
        }
    }

    /// Live-reload the early-hints rules from a new `[http3]` config section.
    /// Swaps the inner config in place (so every `Arc` clone held by in-flight
    /// connections sees the change) and clears the compiled-hints cache so the
    /// next request rebuilds Link headers from the new rules.
    pub fn update_from_http3_config(&self, config: &crate::config::Http3Config) {
        {
            let mut held = self.config.write();
            *held = Self::build_config(config);
            self.generation
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.hints_cache.clear();
    }

    /// Whether Early Hints (103) are currently enabled (reads live config).
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }

    /// Get Link headers for a request (host + path).
    /// Rules with a `host_pattern` only fire for that exact hostname.
    /// Rules with no `host_pattern` fire for every host.
    pub fn get_hints_for_request(&self, host: &str, path: &str) -> Vec<String> {
        let config = self.config.read();
        // Read under the config lock a reload takes to change it
        let generation = self.generation.load(std::sync::atomic::Ordering::Relaxed);

        // The preload rules that apply, respecting host and path filters
        let matched: Vec<usize> = config
            .preload_rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                let host_matches = match &rule.host_pattern {
                    Some(h) => h == host,
                    None => true,
                };
                let path_matches = if rule.exact {
                    path == rule.path_pattern
                } else {
                    path.starts_with(&rule.path_pattern) || rule.path_pattern == "*"
                };
                host_matches && path_matches
            })
            .map(|(index, _)| index)
            .collect();

        let cache_key = (generation, matched);
        if let Some(cached) = self.hints_cache.get(&cache_key) {
            if !cached.versioned || cached.built.elapsed() < VERSIONED_HINTS_TTL {
                return cached.headers.clone();
            }
        }

        let mut hints = Vec::new();
        let mut versioned = false;

        // Add preconnect hints (global — no per-host filtering needed)
        for origin in &config.preconnect_origins {
            hints.push(format!("<{}>; rel=preconnect", origin));
        }
        for rule in cache_key
            .1
            .iter()
            .filter_map(|i| config.preload_rules.get(*i))
        {
            for hint in &rule.hints {
                versioned |= hint.is_versioned();
                hints.extend(hint.to_link_header());
            }
        }

        // Cache the result (a versioned one is rebuilt after VERSIONED_HINTS_TTL)
        if (!hints.is_empty() || versioned)
            && (self.hints_cache.len() < MAX_HINT_SETS || self.hints_cache.contains_key(&cache_key))
        {
            self.hints_cache.insert(
                cache_key,
                CachedHints {
                    headers: hints.clone(),
                    built: Instant::now(),
                    versioned,
                },
            );
        }

        hints
    }
}

/// Whether a request loads a page, the only kind Early Hints are for.
///
/// The browser's own `Sec-Fetch-Dest` (document, iframe, frame) decides, or,
/// from a client without Fetch Metadata, an `Accept` that asks for HTML. A 103
/// went with every request whose path a rule matched, so with `path = "/"`
/// each stylesheet, script and image fetch carried the page's hints again:
/// fated.org's two were sent nine times per page load (2026-10-22).
pub fn is_page_load(headers: &HeaderMap) -> bool {
    if let Some(dest) = headers.get("sec-fetch-dest").and_then(|v| v.to_str().ok()) {
        return matches!(dest, "document" | "iframe" | "frame");
    }
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("text/html"))
}

// ============================================================================
// Priority Hints (RFC 9218 - Extensible Priorities)
// ============================================================================

/// Priority configuration
#[derive(Debug, Clone)]
pub struct PriorityConfig {
    /// Enable priority hints
    pub enabled: bool,
    /// Default urgency (0-7, lower is more urgent)
    pub default_urgency: u8,
    /// Default incremental flag
    pub default_incremental: bool,
    /// Resource type priorities
    pub type_priorities: HashMap<String, ResourcePriority>,
}

impl Default for PriorityConfig {
    fn default() -> Self {
        let mut type_priorities = HashMap::new();

        // HTML documents - highest priority
        type_priorities.insert(
            "text/html".to_string(),
            ResourcePriority {
                urgency: 0,
                incremental: false,
            },
        );

        // CSS - high priority (render blocking)
        type_priorities.insert(
            "text/css".to_string(),
            ResourcePriority {
                urgency: 1,
                incremental: false,
            },
        );

        // JavaScript - medium-high priority
        type_priorities.insert(
            "application/javascript".to_string(),
            ResourcePriority {
                urgency: 2,
                incremental: false,
            },
        );
        type_priorities.insert(
            "text/javascript".to_string(),
            ResourcePriority {
                urgency: 2,
                incremental: false,
            },
        );

        // Fonts - medium priority
        type_priorities.insert(
            "font/woff2".to_string(),
            ResourcePriority {
                urgency: 3,
                incremental: false,
            },
        );
        type_priorities.insert(
            "font/woff".to_string(),
            ResourcePriority {
                urgency: 3,
                incremental: false,
            },
        );

        // Images - lower priority, incremental
        type_priorities.insert(
            "image/webp".to_string(),
            ResourcePriority {
                urgency: 5,
                incremental: true,
            },
        );
        type_priorities.insert(
            "image/avif".to_string(),
            ResourcePriority {
                urgency: 5,
                incremental: true,
            },
        );
        type_priorities.insert(
            "image/png".to_string(),
            ResourcePriority {
                urgency: 5,
                incremental: true,
            },
        );
        type_priorities.insert(
            "image/jpeg".to_string(),
            ResourcePriority {
                urgency: 5,
                incremental: true,
            },
        );

        // JSON API responses - high priority
        type_priorities.insert(
            "application/json".to_string(),
            ResourcePriority {
                urgency: 2,
                incremental: false,
            },
        );

        Self {
            enabled: true,
            default_urgency: 3,
            default_incremental: false,
            type_priorities,
        }
    }
}

/// Resource priority settings
#[derive(Debug, Clone)]
pub struct ResourcePriority {
    /// Urgency (0-7, lower = more urgent)
    pub urgency: u8,
    /// Incremental delivery allowed
    pub incremental: bool,
}

impl ResourcePriority {
    /// Convert to Priority header value (RFC 9218)
    pub fn to_header_value(&self) -> String {
        let mut value = format!("u={}", self.urgency.min(7));
        if self.incremental {
            value.push_str(", i");
        }
        value
    }
}

/// State for Priority Hints
#[derive(Clone)]
pub struct PriorityState {
    pub config: Arc<RwLock<PriorityConfig>>,
}

impl Default for PriorityState {
    fn default() -> Self {
        Self {
            config: Arc::new(RwLock::new(PriorityConfig::default())),
        }
    }
}

impl PriorityState {
    /// Get priority for a content type
    pub fn get_priority(&self, content_type: Option<&str>) -> ResourcePriority {
        let config = self.config.read();

        if let Some(ct) = content_type {
            // Extract MIME type (ignore charset)
            let mime = ct.split(';').next().unwrap_or(ct).trim();

            if let Some(priority) = config.type_priorities.get(mime) {
                return priority.clone();
            }
        }

        ResourcePriority {
            urgency: config.default_urgency,
            incremental: config.default_incremental,
        }
    }

    /// A Priority field value (RFC 9218 section 4: a Structured Fields
    /// dictionary), as a request header, a response header or a
    /// PRIORITY_UPDATE frame carries it. Members left out keep their
    /// defaults (`u=3`, not incremental); an urgency outside 0-7, an
    /// incremental that is not a boolean, parameters and unknown members are
    /// ignored, and a later member wins over an earlier one. None for a value
    /// that is not ASCII, which no Structured Field is.
    pub fn parse_client_priority(header_value: &str) -> Option<ResourcePriority> {
        if !header_value.is_ascii() {
            return None;
        }
        let mut urgency = 3u8;
        let mut incremental = false;
        for member in header_value.split(',') {
            let item = member.split(';').next().unwrap_or_default().trim();
            match item.split_once('=') {
                Some(("u", value)) => {
                    if let Ok(u @ 0..=7) = value.trim().parse::<u8>() {
                        urgency = u;
                    }
                }
                Some(("i", value)) => match value.trim() {
                    "?1" => incremental = true,
                    "?0" => incremental = false,
                    _ => {}
                },
                None if item == "i" => incremental = true,
                _ => {}
            }
        }
        Some(ResourcePriority {
            urgency,
            incremental,
        })
    }
}

/// Add Priority header to response
pub fn add_priority_header(response: &mut Response<Body>, priority: &ResourcePriority) {
    if let Ok(value) = HeaderValue::from_str(&priority.to_header_value()) {
        response.headers_mut().insert("priority", value);
    }
}

// ============================================================================
// Combined HTTP/3 Features State
// ============================================================================

/// Combined state for all HTTP/3 advanced features
#[derive(Clone, Default)]
pub struct Http3FeaturesState {
    pub early_hints: EarlyHintsState,
    pub priority: PriorityState,
}

impl Http3FeaturesState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from proxy configuration
    pub fn from_proxy_config(config: &crate::config::Http3Config) -> Self {
        let early_hints_state = EarlyHintsState::from_http3_config(config);
        let early_hints = early_hints_state.config.read().clone();

        let priority = PriorityConfig {
            enabled: config.priority_hints_enabled,
            ..Default::default()
        };

        Self::with_config(early_hints, priority)
    }

    /// Create with custom configuration
    pub fn with_config(early_hints: EarlyHintsConfig, priority: PriorityConfig) -> Self {
        Self {
            early_hints: EarlyHintsState {
                config: Arc::new(RwLock::new(early_hints)),
                hints_cache: Arc::new(DashMap::new()),
                generation: Arc::default(),
            },
            priority: PriorityState {
                config: Arc::new(RwLock::new(priority)),
            },
        }
    }
}

/// HTTP/3 features middleware
///
/// This middleware:
/// 1. Sends Early Hints (103) before proxying
/// 2. Adds Priority headers to responses
///
/// Identical requests are collapsed onto one fetch by the response cache
/// (`ResponseCache::lookup`), keyed and answered by the cache's own rules.
pub async fn http3_features_middleware(
    State(state): State<Http3FeaturesState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
    // Process the request
    let mut response = next.run(request).await;

    // Add Priority header based on content type (only if not already set)
    // The security_headers_middleware may have already set a priority from config
    let priority_config = state.priority.config.read();
    if priority_config.enabled && !response.headers().contains_key("priority") {
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let priority = state.priority.get_priority(content_type);
        add_priority_header(&mut response, &priority);
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rel_is_reachable_from_config() {
        let res = |rel: &str, as_type: &str| crate::config::PreloadResourceConfig {
            host: None,
            path: "/".into(),
            href: "/m.js".into(),
            rel: rel.into(),
            as_type: as_type.into(),
            crossorigin: None,
            exact: false,
            version_file: None,
        };
        let h = |rel, as_type| {
            LinkHint::from_config(&res(rel, as_type))
                .to_link_header()
                .unwrap()
        };
        assert_eq!(h("preload", "script"), "</m.js>; rel=preload; as=script");
        assert_eq!(h("modulepreload", ""), "</m.js>; rel=modulepreload");
        assert_eq!(h("preconnect", ""), "</m.js>; rel=preconnect");
        assert_eq!(h("dns-prefetch", ""), "</m.js>; rel=dns-prefetch");
        assert_eq!(h("prerender", ""), "</m.js>; rel=prerender");

        let mut c = crate::config::ProxyConfig::default();
        c.http3.preload_resources = vec![res("prefetch", "")];
        assert!(c.validate().unwrap_err().to_string().contains("rel"));
        c.http3.preload_resources = vec![res("preload", "")];
        assert!(c.validate().unwrap_err().to_string().contains("as_type"));
    }

    /// A file with a known mtime, as PHP's filemtime would report it.
    fn file_with_mtime(name: &str, secs: u64) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("pqcrypta-hint-{}-{name}", std::process::id()));
        let f = std::fs::File::create(&path).unwrap();
        f.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
        path
    }

    fn versioned_preload(href: &str, file: &std::path::Path) -> LinkHint {
        LinkHint::Preload {
            href: href.to_string(),
            as_type: "style".to_string(),
            crossorigin: None,
            version_file: Some(file.to_string_lossy().into_owned()),
        }
    }

    #[test]
    fn a_versioned_hint_names_the_url_the_page_links() {
        let css = file_with_mtime("pdf.css", 1_791_254_711);
        let hint = versioned_preload("/css/pdf.css", &css);
        assert!(hint.is_versioned());
        assert_eq!(
            hint.to_link_header().as_deref(),
            Some("</css/pdf.css?v=1791254711>; rel=preload; as=style")
        );
        // A query of its own keeps it: the version is added with &
        assert_eq!(
            versioned_preload("/css/pdf.css?theme=dark", &css)
                .to_link_header()
                .as_deref(),
            Some("</css/pdf.css?theme=dark&v=1791254711>; rel=preload; as=style")
        );
        // The file changes, the hint follows
        std::fs::File::options()
            .write(true)
            .open(&css)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_792_000_000))
            .unwrap();
        assert_eq!(
            hint.to_link_header().as_deref(),
            Some("</css/pdf.css?v=1792000000>; rel=preload; as=style")
        );
        std::fs::remove_file(&css).unwrap();
        // No file, no hint: a URL no page links is a wasted download
        assert_eq!(hint.to_link_header(), None);
    }

    /// Hints are kept by the rules that produced them: any number of paths
    /// under one rule is one entry.
    #[test]
    fn every_path_under_one_rule_shares_its_compiled_hints() {
        let mut c = crate::config::Http3Config {
            preconnect_origins: vec!["https://api.example.com".into()],
            preload_resources: vec![crate::config::PreloadResourceConfig {
                host: Some("example.com".into()),
                path: "/app".into(),
                href: "/css/site.css".into(),
                rel: "preload".into(),
                as_type: "style".into(),
                crossorigin: None,
                exact: false,
                version_file: None,
            }],
            ..Default::default()
        };
        let state = EarlyHintsState::from_http3_config(&c);
        for n in 0..500 {
            assert_eq!(
                state
                    .get_hints_for_request("example.com", &format!("/app/{n}"))
                    .len(),
                2
            );
            assert_eq!(
                state
                    .get_hints_for_request("example.com", &format!("/other/{n}"))
                    .len(),
                1
            );
        }
        assert_eq!(state.hints_cache.len(), 2);
        // A reload starts again from the new rules
        c.preload_resources.clear();
        state.update_from_http3_config(&c);
        assert_eq!(
            state.get_hints_for_request("example.com", "/app/1").len(),
            1
        );
        assert_eq!(state.hints_cache.len(), 1);
    }

    #[test]
    fn versioned_hints_are_rebuilt_once_stale() {
        let css = file_with_mtime("site.css", 1_700_000_000);
        let mut c = crate::config::Http3Config::default();
        c.preconnect_origins.clear();
        c.preload_resources = vec![crate::config::PreloadResourceConfig {
            host: Some("example.com".into()),
            path: "/".into(),
            href: "/css/site.css".into(),
            rel: "preload".into(),
            as_type: "style".into(),
            crossorigin: None,
            exact: true,
            version_file: Some(css.to_string_lossy().into_owned()),
        }];
        let state = EarlyHintsState::from_http3_config(&c);
        assert_eq!(
            state.get_hints_for_request("example.com", "/"),
            vec!["</css/site.css?v=1700000000>; rel=preload; as=style".to_string()]
        );
        std::fs::File::options()
            .write(true)
            .open(&css)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_999))
            .unwrap();
        // Within the TTL the cached headers are served
        assert!(state.get_hints_for_request("example.com", "/")[0].contains("v=1700000000"));
        // Past it, the file is looked at again
        for mut cached in state.hints_cache.iter_mut() {
            cached.built = Instant::now()
                .checked_sub(VERSIONED_HINTS_TTL + Duration::from_secs(1))
                .expect("the clock reaches back past one TTL");
        }
        assert!(state.get_hints_for_request("example.com", "/")[0].contains("v=1700000999"));
        std::fs::remove_file(&css).unwrap();
    }

    #[test]
    fn version_file_is_checked_at_load() {
        let res = |href: &str, rel: &str, file: &str| crate::config::PreloadResourceConfig {
            host: None,
            path: "/".into(),
            href: href.into(),
            rel: rel.into(),
            as_type: "style".into(),
            crossorigin: None,
            exact: false,
            version_file: Some(file.into()),
        };
        let err = |r| {
            let mut c = crate::config::ProxyConfig::default();
            c.http3.preload_resources = vec![r];
            c.validate().err().map(|e| e.to_string())
        };
        assert!(err(res("/a.css", "preload", "css/a.css"))
            .unwrap()
            .contains("absolute"));
        assert!(err(res("/a.css?v=1", "preload", "/srv/a.css"))
            .unwrap()
            .contains("v="));
        assert!(err(res("https://cdn.example", "preconnect", "/srv/a.css"))
            .unwrap()
            .contains("preload and modulepreload"));
        assert_eq!(err(res("/a.css", "preload", "/srv/a.css")), None);
    }

    #[test]
    fn early_hints_go_to_page_loads_only() {
        let h = |pairs: &[(&'static str, &'static str)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(*k, HeaderValue::from_static(v));
            }
            is_page_load(&m)
        };
        assert!(h(&[
            ("sec-fetch-dest", "document"),
            ("accept", "text/html")
        ]));
        assert!(h(&[("sec-fetch-dest", "iframe")]));
        // The page's own stylesheet, script and image fetches
        assert!(!h(&[
            ("sec-fetch-dest", "style"),
            ("accept", "text/css,*/*;q=0.1")
        ]));
        assert!(!h(&[("sec-fetch-dest", "script"), ("accept", "*/*")]));
        assert!(!h(&[
            ("sec-fetch-dest", "image"),
            ("accept", "image/avif,image/webp,*/*")
        ]));
        // Fetch Metadata says it is not a page even if Accept would
        assert!(!h(&[("sec-fetch-dest", "empty"), ("accept", "text/html")]));
        // No Fetch Metadata: Accept decides
        assert!(h(&[("accept", "text/html,application/xhtml+xml")]));
        assert!(!h(&[("accept", "*/*")]));
        assert!(!h(&[]));
    }

    #[test]
    fn test_link_hint_to_header() {
        let preload = LinkHint::Preload {
            href: "/css/main.css".to_string(),
            as_type: "style".to_string(),
            crossorigin: None,
            version_file: None,
        };
        assert_eq!(
            preload.to_link_header().as_deref(),
            Some("</css/main.css>; rel=preload; as=style")
        );

        let preconnect = LinkHint::Preconnect {
            href: "https://fonts.googleapis.com".to_string(),
            crossorigin: Some("anonymous".to_string()),
        };
        assert_eq!(
            preconnect.to_link_header().as_deref(),
            Some("<https://fonts.googleapis.com>; rel=preconnect; crossorigin=anonymous")
        );
    }

    #[test]
    fn test_priority_header() {
        let priority = ResourcePriority {
            urgency: 2,
            incremental: false,
        };
        assert_eq!(priority.to_header_value(), "u=2");

        let priority_incremental = ResourcePriority {
            urgency: 5,
            incremental: true,
        };
        assert_eq!(priority_incremental.to_header_value(), "u=5, i");
    }

    #[test]
    fn test_parse_client_priority() {
        let priority = PriorityState::parse_client_priority("u=3, i").unwrap();
        assert_eq!(priority.urgency, 3);
        assert!(priority.incremental);

        let priority = PriorityState::parse_client_priority("u=0").unwrap();
        assert_eq!(priority.urgency, 0);
        assert!(!priority.incremental);

        let p = |v| {
            let r = PriorityState::parse_client_priority(v).unwrap();
            (r.urgency, r.incremental)
        };
        assert_eq!(p(""), (3, false), "defaults");
        assert_eq!(p("i=?1"), (3, true));
        assert_eq!(p("u=5, i=?0"), (5, false));
        assert_eq!(p("u=9"), (3, false), "out of range is ignored, not clamped");
        assert_eq!(p("u=1;x=2, i;y"), (1, true), "parameters ignored");
        assert_eq!(p("u=1, u=6"), (6, false), "the last member wins");
        assert_eq!(p("foo, u=2"), (2, false), "unknown members ignored");
        assert!(PriorityState::parse_client_priority("u=1, é").is_none());
    }
}
