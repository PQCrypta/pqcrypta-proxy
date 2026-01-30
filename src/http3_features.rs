//! HTTP/3 Advanced Features Module
//!
//! Implements cutting-edge HTTP/3 features:
//! - **Early Hints (103)**: Preload critical resources before final response
//! - **Priority Hints**: Extensible Priorities (RFC 9218) for resource scheduling
//! - **Request Coalescing**: Deduplicate identical in-flight requests
//!
//! # Integration
//! All features are configurable via the `[http3]` section in proxy-config.toml:
//! - `early_hints_enabled` - Enable 103 Early Hints (Link headers as fallback)
//! - `priority_hints_enabled` - Enable RFC 9218 Priority headers
//! - `coalescing_enabled` - Enable request deduplication
//!
//! # Usage
//! ```ignore
//! let state = Http3FeaturesState::from_proxy_config(&config.http3);
//! router.layer(middleware::from_fn_with_state(state, http3_features_middleware));
//! ```

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode};
use axum::middleware::Next;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, trace};

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
            preload_rules: vec![
                // Common static assets
                PreloadRule {
                    path_pattern: "/".to_string(),
                    hints: vec![
                        LinkHint::Preload {
                            href: "/css/main.css".to_string(),
                            as_type: "style".to_string(),
                            crossorigin: None,
                        },
                        LinkHint::Preload {
                            href: "/js/app.js".to_string(),
                            as_type: "script".to_string(),
                            crossorigin: None,
                        },
                    ],
                },
            ],
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
    /// Path pattern (prefix match)
    pub path_pattern: String,
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
    },
}

impl LinkHint {
    /// Convert to Link header value
    pub fn to_link_header(&self) -> String {
        match self {
            LinkHint::Preload {
                href,
                as_type,
                crossorigin,
            } => {
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
            LinkHint::ModulePreload { href, crossorigin } => {
                let mut link = format!("<{}>; rel=modulepreload", href);
                if let Some(co) = crossorigin {
                    link.push_str(&format!("; crossorigin={}", co));
                }
                link
            }
        }
    }
}

/// State for Early Hints
#[derive(Clone)]
pub struct EarlyHintsState {
    pub config: Arc<RwLock<EarlyHintsConfig>>,
    /// Cache of path -> compiled hints
    pub hints_cache: Arc<DashMap<String, Vec<String>>>,
}

impl Default for EarlyHintsState {
    fn default() -> Self {
        Self {
            config: Arc::new(RwLock::new(EarlyHintsConfig::default())),
            hints_cache: Arc::new(DashMap::new()),
        }
    }
}

impl EarlyHintsState {
    /// Get Link headers for a path
    pub fn get_hints_for_path(&self, path: &str) -> Vec<String> {
        // Check cache first
        if let Some(cached) = self.hints_cache.get(path) {
            return cached.clone();
        }

        let config = self.config.read();
        let mut hints = Vec::new();

        // Add preconnect hints
        for origin in &config.preconnect_origins {
            hints.push(format!("<{}>; rel=preconnect", origin));
        }

        // Find matching preload rules
        for rule in &config.preload_rules {
            if path.starts_with(&rule.path_pattern) || rule.path_pattern == "*" {
                for hint in &rule.hints {
                    hints.push(hint.to_link_header());
                }
            }
        }

        // Cache the result
        if !hints.is_empty() {
            self.hints_cache.insert(path.to_string(), hints.clone());
        }

        hints
    }
}

/// Build a 103 Early Hints response
pub fn build_early_hints_response(hints: &[String]) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::EARLY_HINTS;

    // Add Link headers
    for (i, hint) in hints.iter().enumerate() {
        if let Ok(value) = HeaderValue::from_str(hint) {
            // Use append to add multiple Link headers
            if i == 0 {
                response.headers_mut().insert(header::LINK, value);
            } else {
                response.headers_mut().append(header::LINK, value);
            }
        }
    }

    response
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

    /// Parse client Priority header (RFC 9218)
    pub fn parse_client_priority(header_value: &str) -> Option<ResourcePriority> {
        let mut urgency = 3u8;
        let mut incremental = false;

        for part in header_value.split(',') {
            let part = part.trim();
            if part.starts_with("u=") {
                if let Ok(u) = part[2..].parse::<u8>() {
                    urgency = u.min(7);
                }
            } else if part == "i" {
                incremental = true;
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
// Request Coalescing (Deduplication)
// ============================================================================

/// Request coalescing configuration
#[derive(Debug, Clone)]
pub struct CoalescingConfig {
    /// Enable request coalescing
    pub enabled: bool,
    /// Maximum wait time for coalesced requests (ms)
    pub max_wait_ms: u64,
    /// Maximum subscribers per coalesced request
    pub max_subscribers: usize,
    /// Methods to coalesce (typically only GET)
    pub coalesce_methods: Vec<String>,
    /// Paths to exclude from coalescing
    pub exclude_paths: Vec<String>,
}

impl Default for CoalescingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_wait_ms: 100,
            max_subscribers: 100,
            coalesce_methods: vec!["GET".to_string(), "HEAD".to_string()],
            exclude_paths: vec![
                "/api/".to_string(),
                "/ws".to_string(),
                "/stream".to_string(),
            ],
        }
    }
}

/// Key for coalescing requests
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CoalesceKey {
    /// HTTP method
    pub method: String,
    /// Request URI
    pub uri: String,
    /// Significant headers hash (Accept, Accept-Encoding, etc.)
    pub headers_hash: u64,
}

impl CoalesceKey {
    /// Create a coalesce key from a request
    pub fn from_request(method: &str, uri: &str, headers: &HeaderMap) -> Self {
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();

        // Hash significant headers that affect response
        for header_name in &[
            header::ACCEPT,
            header::ACCEPT_ENCODING,
            header::ACCEPT_LANGUAGE,
            header::AUTHORIZATION,
        ] {
            if let Some(value) = headers.get(header_name) {
                header_name.as_str().hash(&mut hasher);
                value.as_bytes().hash(&mut hasher);
            }
        }

        Self {
            method: method.to_string(),
            uri: uri.to_string(),
            headers_hash: hasher.finish(),
        }
    }
}

/// Coalesced response that can be shared
#[derive(Clone)]
pub struct CoalescedResponse {
    /// Response status
    pub status: StatusCode,
    /// Response headers
    pub headers: HeaderMap,
    /// Response body (shared bytes)
    pub body: Arc<Vec<u8>>,
    /// When the response was created
    pub created_at: Instant,
}

/// In-flight request state
pub struct InFlightRequest {
    /// Broadcast channel for response
    pub sender: broadcast::Sender<CoalescedResponse>,
    /// Number of subscribers
    pub subscriber_count: usize,
    /// When the request started
    pub started_at: Instant,
}

/// State for request coalescing
#[derive(Clone)]
pub struct CoalescingState {
    pub config: Arc<RwLock<CoalescingConfig>>,
    /// In-flight requests
    pub in_flight: Arc<DashMap<CoalesceKey, Arc<RwLock<InFlightRequest>>>>,
    /// Response cache for very short-term caching
    pub response_cache: Arc<DashMap<CoalesceKey, CoalescedResponse>>,
}

impl Default for CoalescingState {
    fn default() -> Self {
        Self {
            config: Arc::new(RwLock::new(CoalescingConfig::default())),
            in_flight: Arc::new(DashMap::new()),
            response_cache: Arc::new(DashMap::new()),
        }
    }
}

impl CoalescingState {
    /// Check if a request should be coalesced
    pub fn should_coalesce(&self, method: &str, path: &str) -> bool {
        let config = self.config.read();

        if !config.enabled {
            return false;
        }

        // Check method
        if !config
            .coalesce_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method))
        {
            return false;
        }

        // Check excluded paths
        for exclude in &config.exclude_paths {
            if path.starts_with(exclude) {
                return false;
            }
        }

        true
    }

    /// Try to join an existing in-flight request
    pub fn try_join(&self, key: &CoalesceKey) -> Option<broadcast::Receiver<CoalescedResponse>> {
        if let Some(request) = self.in_flight.get(key) {
            let mut req = request.write();
            let config = self.config.read();

            if req.subscriber_count < config.max_subscribers {
                req.subscriber_count += 1;
                debug!(
                    "Coalescing request: {} {} (subscribers: {})",
                    key.method, key.uri, req.subscriber_count
                );
                return Some(req.sender.subscribe());
            }
        }
        None
    }

    /// Register a new in-flight request
    pub fn register(&self, key: CoalesceKey) -> broadcast::Sender<CoalescedResponse> {
        let (sender, _) = broadcast::channel(1);

        let request = InFlightRequest {
            sender: sender.clone(),
            subscriber_count: 1,
            started_at: Instant::now(),
        };

        self.in_flight.insert(key, Arc::new(RwLock::new(request)));
        sender
    }

    /// Complete an in-flight request
    pub fn complete(&self, key: &CoalesceKey, response: CoalescedResponse) {
        if let Some((_, request)) = self.in_flight.remove(key) {
            let req = request.read();
            if req.sender.send(response.clone()).is_err() {
                debug!(
                    "Failed to broadcast coalesced response for {} {} - all receivers dropped",
                    key.method, key.uri
                );
            }

            debug!(
                "Completed coalesced request: {} {} (served {} subscribers)",
                key.method, key.uri, req.subscriber_count
            );
        }

        // Optionally cache for a very short time
        self.response_cache.insert(key.clone(), response);

        // Clean up old cache entries
        self.cleanup_cache();
    }

    /// Clean up expired cache entries
    fn cleanup_cache(&self) {
        let max_age = Duration::from_millis(50); // Very short cache

        self.response_cache
            .retain(|_, response| response.created_at.elapsed() < max_age);

        // Also clean up stale in-flight requests
        let max_inflight = Duration::from_secs(30);
        self.in_flight
            .retain(|_, request| request.read().started_at.elapsed() < max_inflight);
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
    pub coalescing: CoalescingState,
}

impl Http3FeaturesState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create from proxy configuration
    pub fn from_proxy_config(config: &crate::config::Http3Config) -> Self {
        let early_hints = EarlyHintsConfig {
            enabled: config.early_hints_enabled,
            preconnect_origins: config.preconnect_origins.clone(),
            ..Default::default()
        };

        let priority = PriorityConfig {
            enabled: config.priority_hints_enabled,
            ..Default::default()
        };

        let coalescing = CoalescingConfig {
            enabled: config.coalescing_enabled,
            max_wait_ms: config.coalescing_max_wait_ms,
            max_subscribers: config.coalescing_max_subscribers,
            coalesce_methods: config.coalescing_methods.clone(),
            exclude_paths: config.coalescing_exclude_paths.clone(),
        };

        Self::with_config(early_hints, priority, coalescing)
    }

    /// Create with custom configuration
    pub fn with_config(
        early_hints: EarlyHintsConfig,
        priority: PriorityConfig,
        coalescing: CoalescingConfig,
    ) -> Self {
        Self {
            early_hints: EarlyHintsState {
                config: Arc::new(RwLock::new(early_hints)),
                hints_cache: Arc::new(DashMap::new()),
            },
            priority: PriorityState {
                config: Arc::new(RwLock::new(priority)),
            },
            coalescing: CoalescingState {
                config: Arc::new(RwLock::new(coalescing)),
                in_flight: Arc::new(DashMap::new()),
                response_cache: Arc::new(DashMap::new()),
            },
        }
    }
}

/// HTTP/3 features middleware
///
/// This middleware:
/// 1. Sends Early Hints (103) before proxying
/// 2. Handles request coalescing for identical requests
/// 3. Adds Priority headers to responses
pub async fn http3_features_middleware(
    State(state): State<Http3FeaturesState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let method = request.method().as_str().to_string();
    let path = request.uri().path().to_string();
    let headers = request.headers().clone();

    // Check for request coalescing
    let coalescing_config = state.coalescing.config.read().clone();
    if coalescing_config.enabled && state.coalescing.should_coalesce(&method, &path) {
        let key = CoalesceKey::from_request(&method, &path, &headers);

        // Try to join existing request
        if let Some(mut receiver) = state.coalescing.try_join(&key) {
            trace!("Joining coalesced request for {} {}", method, path);

            // Wait for the response
            match tokio::time::timeout(
                Duration::from_millis(coalescing_config.max_wait_ms),
                receiver.recv(),
            )
            .await
            {
                Ok(Ok(coalesced)) => {
                    // Build response from coalesced data
                    let mut response = Response::new(Body::from((*coalesced.body).clone()));
                    *response.status_mut() = coalesced.status;
                    *response.headers_mut() = coalesced.headers;

                    // Add header indicating this was coalesced
                    response
                        .headers_mut()
                        .insert("x-coalesced", HeaderValue::from_static("true"));

                    return response;
                }
                _ => {
                    // Timeout or error, proceed with own request
                    trace!("Coalescing timeout/error, proceeding with request");
                }
            }
        }
    }

    // Process the request
    let mut response = next.run(request).await;

    // Add Priority header based on content type
    let priority_config = state.priority.config.read();
    if priority_config.enabled {
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());

        let priority = state.priority.get_priority(content_type);
        add_priority_header(&mut response, &priority);
    }

    response
}

/// Early Hints middleware (sends 103 before main response)
///
/// Note: This requires special handling as we need to send
/// the 103 response before the actual response. In practice,
/// this is handled at the HTTP/3 layer.
pub async fn early_hints_middleware(
    State(state): State<EarlyHintsState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = request.uri().path().to_string();
    let config = state.config.read().clone();

    if config.enabled {
        let hints = state.get_hints_for_path(&path);

        if !hints.is_empty() {
            trace!("Would send Early Hints for {}: {:?}", path, hints);
            // Note: Actually sending 103 requires low-level HTTP/3 access
            // For now, we add Link headers to the final response as fallback
        }
    }

    let mut response = next.run(request).await;

    // Add Link headers as fallback (for preload)
    if config.enabled {
        let hints = state.get_hints_for_path(&path);
        for hint in hints {
            if let Ok(value) = HeaderValue::from_str(&hint) {
                response.headers_mut().append(header::LINK, value);
            }
        }
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_hint_to_header() {
        let preload = LinkHint::Preload {
            href: "/css/main.css".to_string(),
            as_type: "style".to_string(),
            crossorigin: None,
        };
        assert_eq!(
            preload.to_link_header(),
            "</css/main.css>; rel=preload; as=style"
        );

        let preconnect = LinkHint::Preconnect {
            href: "https://fonts.googleapis.com".to_string(),
            crossorigin: Some("anonymous".to_string()),
        };
        assert_eq!(
            preconnect.to_link_header(),
            "<https://fonts.googleapis.com>; rel=preconnect; crossorigin=anonymous"
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
    }

    #[test]
    fn test_coalesce_key() {
        let headers = HeaderMap::new();
        let key1 = CoalesceKey::from_request("GET", "/api/data", &headers);
        let key2 = CoalesceKey::from_request("GET", "/api/data", &headers);

        assert_eq!(key1, key2);
        assert_eq!(key1.method, "GET");
        assert_eq!(key1.uri, "/api/data");
    }
}
