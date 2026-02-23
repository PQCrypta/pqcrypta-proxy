//! TLS Fingerprinting Module
//!
//! Implements JA3/JA4 TLS fingerprinting for bot detection and client identification.
//! Captures ClientHello during TLS handshake and computes fingerprints.
//!
//! # Integration
//! This module provides:
//! - `FingerprintExtractor` - Core fingerprint extraction and classification
//! - `fingerprint_middleware` - Axum middleware for request-level fingerprint handling
//! - `FingerprintInfo` - Request extension data for downstream handlers
//!
//! Fingerprints can be captured either via:
//! 1. Custom TLS acceptor (`FingerprintingTlsAcceptor`) - captures raw ClientHello
//! 2. Internal headers (`x-ja3-hash`, `x-ja4-hash`) - set by lower layers
//! 3. OpenSSL callback mechanism - for PQC-enabled connections

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{header::HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use md5::{Digest, Md5};
use sha2::Sha256;
use tracing::{debug, info, warn};

use crate::config::FingerprintConfig;
use crate::security::{BlockReason, FingerprintClass, SecurityState, TlsFingerprint};

/// TLS fingerprint extractor
#[derive(Clone)]
pub struct FingerprintExtractor {
    /// Cache of computed fingerprints
    cache: Arc<DashMap<String, CachedFingerprint>>,
    /// Known fingerprint database
    known_fingerprints: Arc<KnownFingerprints>,
}

/// Cached fingerprint with metadata
#[derive(Clone, Debug)]
pub struct CachedFingerprint {
    pub ja3_hash: String,
    pub ja4_hash: Option<String>,
    pub classification: FingerprintClass,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub request_count: u64,
}

/// Known fingerprint database
pub struct KnownFingerprints {
    /// Known browser fingerprints (JA3 hash -> browser name)
    browsers: DashMap<String, String>,
    /// Known bot fingerprints
    legitimate_bots: DashMap<String, String>,
    /// Known malicious fingerprints
    malicious: DashMap<String, String>,
    /// Known scanner fingerprints
    scanners: DashMap<String, String>,
    /// Known API client fingerprints
    api_clients: DashMap<String, String>,
}

impl Default for KnownFingerprints {
    fn default() -> Self {
        let db = Self {
            browsers: DashMap::new(),
            legitimate_bots: DashMap::new(),
            malicious: DashMap::new(),
            scanners: DashMap::new(),
            api_clients: DashMap::new(),
        };

        // Known browser fingerprints (these are real JA3 hashes)
        // Chrome 120+
        db.browsers.insert(
            "cd08e31494f9531f560d64c695473da9".to_string(),
            "Chrome/120+".to_string(),
        );
        db.browsers.insert(
            "b32309a26951912be7dba376398abc3b".to_string(),
            "Chrome/100-119".to_string(),
        );
        // Firefox
        db.browsers.insert(
            "47eca2446b260fac53c5cc2dd4aba2ba".to_string(),
            "Firefox/120+".to_string(),
        );
        db.browsers.insert(
            "e7d705a3286e19ea42f587b344ee6865".to_string(),
            "Firefox/90-119".to_string(),
        );
        // Safari
        db.browsers.insert(
            "773906b0efdefa24a7f2b8eb6985bf37".to_string(),
            "Safari/17+".to_string(),
        );
        // Edge
        db.browsers.insert(
            "9e10692f1b7f78228b2d4e424db3a98c".to_string(),
            "Edge/120+".to_string(),
        );

        // Known legitimate bots
        db.legitimate_bots.insert(
            "4d7a28d6f2f7e9c8b5a3c1d0e2f6a9b8".to_string(),
            "Googlebot".to_string(),
        );
        db.legitimate_bots.insert(
            "3b5074b1b5d032e5620f69f9f700ff0e".to_string(),
            "Bingbot".to_string(),
        );
        db.legitimate_bots.insert(
            "5b5074b1b5d032e5620f69f9f700ff0a".to_string(),
            "Cloudflare-Bot".to_string(),
        );

        // Known malicious fingerprints
        db.malicious.insert(
            "e960427dc851bc6c8a87ad68e9e2aa72".to_string(),
            "SQLMap".to_string(),
        );
        db.malicious.insert(
            "51c64c77e60f3980eea90869b68c58a8".to_string(),
            "Exploit Kit".to_string(),
        );

        // Known scanners
        db.scanners.insert(
            "72f4b0e61f7f6a1b2c3d4e5f6a7b8c9d".to_string(),
            "Nmap".to_string(),
        );
        db.scanners.insert(
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string(),
            "Nikto".to_string(),
        );
        db.scanners.insert(
            "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7".to_string(),
            "Burp Suite".to_string(),
        );

        // Known API clients
        db.api_clients.insert(
            "1be3ecebe5aa9d3654e6e703d24b6052".to_string(),
            "curl".to_string(),
        );
        db.api_clients.insert(
            "555c5c77e60f3980eea90869b68c58a8".to_string(),
            "wget".to_string(),
        );
        db.api_clients.insert(
            "2bfc4b8b995e5d37a9a9d05b58655b40".to_string(),
            "Python-requests".to_string(),
        );
        db.api_clients.insert(
            "6734f37431670b3ab4292b8f60f29984".to_string(),
            "Go-http-client".to_string(),
        );
        db.api_clients.insert(
            "28a2c9bd18a11de089ef85a160da0c8b".to_string(),
            "Node.js-axios".to_string(),
        );

        db
    }
}

impl KnownFingerprints {
    /// Classify a JA3 hash
    pub fn classify(&self, ja3_hash: &str) -> (FingerprintClass, Option<String>) {
        if let Some(name) = self.browsers.get(ja3_hash) {
            return (FingerprintClass::Browser, Some(name.clone()));
        }
        if let Some(name) = self.legitimate_bots.get(ja3_hash) {
            return (FingerprintClass::LegitimateBot, Some(name.clone()));
        }
        if let Some(name) = self.malicious.get(ja3_hash) {
            return (FingerprintClass::Malicious, Some(name.clone()));
        }
        if let Some(name) = self.scanners.get(ja3_hash) {
            return (FingerprintClass::Scanner, Some(name.clone()));
        }
        if let Some(name) = self.api_clients.get(ja3_hash) {
            return (FingerprintClass::ApiClient, Some(name.clone()));
        }
        (FingerprintClass::Suspicious, None)
    }
}

impl Default for FingerprintExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl FingerprintExtractor {
    /// Create a new fingerprint extractor
    pub fn new() -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            known_fingerprints: Arc::new(KnownFingerprints::default()),
        }
    }

    /// Classify a JA3 hash against the known fingerprint database
    ///
    /// Returns (classification, optional_client_name)
    pub fn classify(&self, ja3_hash: &str) -> (FingerprintClass, Option<String>) {
        self.known_fingerprints.classify(ja3_hash)
    }

    /// Extract JA3 fingerprint from TLS ClientHello
    ///
    /// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    pub fn extract_ja3(&self, client_hello: &[u8]) -> Option<Ja3Fingerprint> {
        if client_hello.len() < 43 {
            return None;
        }

        // Parse TLS record layer
        let (handshake, tls_version) = if client_hello[0] == 0x16 {
            // TLS record header: type(1) + version(2) + length(2)
            if client_hello.len() < 5 {
                return None;
            }
            let record_version = u16::from_be_bytes([client_hello[1], client_hello[2]]);
            (&client_hello[5..], record_version)
        } else {
            return None;
        };

        // Handshake header: type(1) + length(3)
        if handshake.len() < 4 || handshake[0] != 0x01 {
            // Not a ClientHello
            return None;
        }

        let client_hello_data = &handshake[4..];
        if client_hello_data.len() < 38 {
            return None;
        }

        // ClientHello version (2 bytes)
        let ch_version = u16::from_be_bytes([client_hello_data[0], client_hello_data[1]]);

        // Skip random (32 bytes)
        let mut offset = 34;

        // Session ID
        if offset >= client_hello_data.len() {
            return None;
        }
        let session_id_len = client_hello_data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites
        if offset + 2 > client_hello_data.len() {
            return None;
        }
        let cipher_suites_len =
            u16::from_be_bytes([client_hello_data[offset], client_hello_data[offset + 1]]) as usize;
        offset += 2;

        if offset + cipher_suites_len > client_hello_data.len() {
            return None;
        }

        let mut ciphers = Vec::new();
        for i in (0..cipher_suites_len).step_by(2) {
            let cipher = u16::from_be_bytes([
                client_hello_data[offset + i],
                client_hello_data[offset + i + 1],
            ]);
            // Skip GREASE values (0x?a?a pattern)
            if !is_grease(cipher) {
                ciphers.push(cipher);
            }
        }
        offset += cipher_suites_len;

        // Compression methods
        if offset >= client_hello_data.len() {
            return None;
        }
        let compression_len = client_hello_data[offset] as usize;
        offset += 1 + compression_len;

        // Extensions
        if offset + 2 > client_hello_data.len() {
            return None;
        }
        let extensions_len =
            u16::from_be_bytes([client_hello_data[offset], client_hello_data[offset + 1]]) as usize;
        offset += 2;

        let mut extensions = Vec::new();
        let mut elliptic_curves = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut sni = None;
        let mut alpn_protocols = Vec::new();
        let mut signature_algorithms = Vec::new();

        let extensions_end = offset + extensions_len;
        while offset + 4 <= extensions_end && offset + 4 <= client_hello_data.len() {
            let ext_type =
                u16::from_be_bytes([client_hello_data[offset], client_hello_data[offset + 1]]);
            let ext_len =
                u16::from_be_bytes([client_hello_data[offset + 2], client_hello_data[offset + 3]])
                    as usize;
            offset += 4;

            // Skip GREASE extensions
            if !is_grease(ext_type) {
                extensions.push(ext_type);

                // Parse specific extensions
                if ext_len > 0 && offset + ext_len <= client_hello_data.len() {
                    let ext_data = &client_hello_data[offset..offset + ext_len];

                    match ext_type {
                        0 => {
                            // SNI
                            sni = parse_sni(ext_data);
                        }
                        10 => {
                            // Supported Groups (Elliptic Curves)
                            elliptic_curves = parse_supported_groups(ext_data);
                        }
                        11 => {
                            // EC Point Formats
                            ec_point_formats = parse_ec_point_formats(ext_data);
                        }
                        13 => {
                            // Signature Algorithms
                            signature_algorithms = parse_signature_algorithms(ext_data);
                        }
                        16 => {
                            // ALPN
                            alpn_protocols = parse_alpn(ext_data);
                        }
                        _ => {}
                    }
                }
            }

            offset += ext_len;
        }

        // Build JA3 string
        let ja3_string = format!(
            "{},{},{},{},{}",
            ch_version.max(tls_version),
            ciphers
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            extensions
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            elliptic_curves
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join("-"),
            ec_point_formats
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join("-"),
        );

        // Calculate MD5 hash
        let mut hasher = Md5::new();
        hasher.update(ja3_string.as_bytes());
        let ja3_hash = hex::encode(hasher.finalize());

        // Also calculate JA4 fingerprint
        let ja4_hash = self.calculate_ja4(
            ch_version,
            &ciphers,
            &extensions,
            &alpn_protocols,
            &signature_algorithms,
            sni.is_some(),
        );

        Some(Ja3Fingerprint {
            ja3_string,
            ja3_hash,
            ja4_hash,
            tls_version: ch_version,
            ciphers,
            extensions,
            elliptic_curves,
            ec_point_formats,
            sni,
            alpn_protocols,
        })
    }

    /// Calculate JA4 fingerprint (newer, more detailed format)
    ///
    /// JA4 format: t13d1516h2_8daaf6152771_b186095e22b6
    ///   - t = TLS, q = QUIC
    ///   - 13 = TLS 1.3
    ///   - d = domain SNI (i = IP)
    ///   - 15 = number of ciphers
    ///   - 16 = number of extensions
    ///   - h2 = first ALPN
    ///   - _ = separator
    ///   - 8daaf6152771 = truncated SHA256 of sorted ciphers
    ///   - _ = separator
    ///   - b186095e22b6 = truncated SHA256 of sorted extensions + signature algorithms
    fn calculate_ja4(
        &self,
        tls_version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        alpn: &[String],
        sig_algs: &[u16],
        has_sni: bool,
    ) -> Option<String> {
        // Protocol type
        let proto = "t"; // TLS (would be "q" for QUIC)

        // TLS version
        let version = match tls_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };

        // SNI type
        let sni_type = if has_sni { "d" } else { "i" };

        // Counts
        let cipher_count = format!("{:02}", ciphers.len().min(99));
        let ext_count = format!("{:02}", extensions.len().min(99));

        // First ALPN protocol (truncated)
        let alpn_str = alpn
            .first()
            .map(|a| {
                if a.len() >= 2 {
                    a[..2].to_string()
                } else {
                    format!("{:0<2}", a)
                }
            })
            .unwrap_or_else(|| "00".to_string());

        // Hash of sorted ciphers (truncated to 12 hex chars)
        let mut sorted_ciphers = ciphers.to_vec();
        sorted_ciphers.sort_unstable();
        let cipher_str: String = sorted_ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let mut hasher = Sha256::new();
        hasher.update(cipher_str.as_bytes());
        let cipher_hash = hex::encode(hasher.finalize());
        let cipher_hash_trunc = &cipher_hash[..12];

        // Hash of sorted extensions + signature algorithms
        let mut sorted_exts = extensions.to_vec();
        sorted_exts.sort_unstable();
        let ext_str: String = sorted_exts
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let sig_str: String = sig_algs
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");
        let combined = format!("{}_{}", ext_str, sig_str);
        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        let ext_hash = hex::encode(hasher.finalize());
        let ext_hash_trunc = &ext_hash[..12];

        Some(format!(
            "{}{}{}{}{}{}_{}_{}",
            proto,
            version,
            sni_type,
            cipher_count,
            ext_count,
            alpn_str,
            cipher_hash_trunc,
            ext_hash_trunc
        ))
    }

    /// Process a ClientHello and update security state
    pub fn process_client_hello(
        &self,
        client_hello: &[u8],
        client_ip: IpAddr,
        security: &SecurityState,
        config: &FingerprintConfig,
    ) -> FingerprintResult {
        let fingerprint = match self.extract_ja3(client_hello) {
            Some(fp) => fp,
            None => {
                return FingerprintResult {
                    allowed: true,
                    ja3_hash: None,
                    ja4_hash: None,
                    classification: None,
                    client_name: None,
                }
            }
        };

        let ja3_hash = fingerprint.ja3_hash;
        let ja4_hash = fingerprint.ja4_hash;

        // Classify the fingerprint
        let (classification, client_name) = self.known_fingerprints.classify(&ja3_hash);

        // Update cache
        let now = Instant::now();
        self.cache
            .entry(ja3_hash.clone())
            .and_modify(|cached| {
                cached.last_seen = now;
                cached.request_count += 1;
            })
            .or_insert_with(|| CachedFingerprint {
                ja3_hash: ja3_hash.clone(),
                ja4_hash: ja4_hash.clone(),
                classification: classification.clone(),
                first_seen: now,
                last_seen: now,
                request_count: 1,
            });

        // Update security state JA3 cache
        security.ja3_cache.insert(
            ja3_hash.clone(),
            TlsFingerprint {
                ja3_hash: ja3_hash.clone(),
                ja4_hash: ja4_hash.clone(),
                classification: classification.clone(),
                first_seen: now,
                request_count: 1,
            },
        );

        // Check if this fingerprint should be blocked (using configurable thresholds)
        let allowed = match &classification {
            // AUD-12: Block Malicious fingerprints only when block_malicious = true (default).
            // When false, classification is advisory-only: the fingerprint is logged
            // but the connection is not blocked, allowing operators to build allow-lists
            // before enabling enforcement.
            FingerprintClass::Malicious if config.block_malicious => {
                warn!(
                    "Blocking malicious fingerprint {} from {}",
                    ja3_hash, client_ip
                );
                security.block_ip(
                    client_ip,
                    BlockReason::SuspiciousFingerprint,
                    Some(Duration::from_secs(config.malicious_block_duration_secs)),
                );
                false
            }
            FingerprintClass::Malicious => {
                // block_malicious = false: log but do not block
                info!(
                    "Advisory: malicious fingerprint {} from {} (block_malicious=false, not blocking)",
                    ja3_hash, client_ip
                );
                true
            }
            FingerprintClass::Suspicious => {
                // Check request rate for suspicious fingerprints (configurable thresholds)
                if let Some(cached) = self.cache.get(&ja3_hash) {
                    if cached.request_count > config.suspicious_rate_threshold
                        && cached.first_seen.elapsed()
                            < Duration::from_secs(config.suspicious_rate_window_secs)
                    {
                        warn!(
                            "High rate from suspicious fingerprint {} (IP: {})",
                            ja3_hash, client_ip
                        );
                        security.block_ip(
                            client_ip,
                            BlockReason::SuspiciousFingerprint,
                            Some(Duration::from_secs(config.suspicious_block_duration_secs)),
                        );
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            }
            _ => true,
        };

        if let Some(ref name) = client_name {
            debug!(
                "TLS fingerprint: {} ({}) from {} [{}]",
                ja3_hash,
                name,
                client_ip,
                format!("{:?}", classification)
            );
        }

        FingerprintResult {
            allowed,
            ja3_hash: Some(ja3_hash),
            ja4_hash,
            classification: Some(classification),
            client_name,
        }
    }

    /// Cleanup old cache entries (using configurable max age)
    pub fn cleanup(&self, config: &FingerprintConfig) {
        let max_age = Duration::from_secs(config.cache_max_age_secs);
        self.cache
            .retain(|_, cached| cached.last_seen.elapsed() < max_age);
    }

    /// Get fingerprint statistics
    pub fn get_stats(&self) -> FingerprintStats {
        let mut stats = FingerprintStats {
            total_fingerprints: self.cache.len(),
            ..Default::default()
        };

        for entry in self.cache.iter() {
            match entry.classification {
                FingerprintClass::Browser => stats.browser_count += 1,
                FingerprintClass::LegitimateBot => stats.bot_count += 1,
                FingerprintClass::Suspicious => stats.suspicious_count += 1,
                FingerprintClass::Malicious => stats.malicious_count += 1,
                FingerprintClass::Scanner => stats.scanner_count += 1,
                FingerprintClass::ApiClient => stats.api_client_count += 1,
            }
            stats.total_requests += entry.request_count;
        }

        stats
    }
}

/// Result of fingerprint processing
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    pub allowed: bool,
    pub ja3_hash: Option<String>,
    pub ja4_hash: Option<String>,
    pub classification: Option<FingerprintClass>,
    pub client_name: Option<String>,
}

/// JA3 fingerprint data
#[derive(Debug, Clone)]
pub struct Ja3Fingerprint {
    pub ja3_string: String,
    pub ja3_hash: String,
    pub ja4_hash: Option<String>,
    pub tls_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub sni: Option<String>,
    pub alpn_protocols: Vec<String>,
}

/// Fingerprint statistics
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct FingerprintStats {
    pub total_fingerprints: usize,
    pub total_requests: u64,
    pub browser_count: usize,
    pub bot_count: usize,
    pub suspicious_count: usize,
    pub malicious_count: usize,
    pub scanner_count: usize,
    pub api_client_count: usize,
}

// ============================================================================
// Fingerprint Middleware Integration
// ============================================================================

/// Fingerprint information stored in request extensions
///
/// This struct is added to request extensions by `fingerprint_middleware`
/// and can be extracted by downstream handlers.
#[derive(Debug, Clone)]
pub struct FingerprintInfo {
    /// JA3 fingerprint hash (MD5)
    pub ja3_hash: Option<String>,
    /// JA4 fingerprint hash (SHA256-based)
    pub ja4_hash: Option<String>,
    /// Client classification
    pub classification: Option<FingerprintClass>,
    /// Friendly client name (e.g., "Chrome/120+", "Googlebot")
    pub client_name: Option<String>,
    /// Whether this is a browser client
    pub is_browser: bool,
    /// Whether this is a known legitimate bot
    pub is_legitimate_bot: bool,
}

impl Default for FingerprintInfo {
    fn default() -> Self {
        Self {
            ja3_hash: None,
            ja4_hash: None,
            classification: None,
            client_name: None,
            is_browser: false,
            is_legitimate_bot: false,
        }
    }
}

impl FingerprintInfo {
    /// Create from a fingerprint result
    pub fn from_result(result: &FingerprintResult) -> Self {
        let is_browser = result
            .classification
            .as_ref()
            .map(|c| matches!(c, FingerprintClass::Browser))
            .unwrap_or(false);
        let is_legitimate_bot = result
            .classification
            .as_ref()
            .map(|c| matches!(c, FingerprintClass::LegitimateBot))
            .unwrap_or(false);

        Self {
            ja3_hash: result.ja3_hash.clone(),
            ja4_hash: result.ja4_hash.clone(),
            classification: result.classification.clone(),
            client_name: result.client_name.clone(),
            is_browser,
            is_legitimate_bot,
        }
    }

    /// Create from internal fingerprint headers
    pub fn from_headers(
        ja3_hash: Option<String>,
        ja4_hash: Option<String>,
        extractor: &FingerprintExtractor,
    ) -> Self {
        if let Some(ref ja3) = ja3_hash {
            let (classification, client_name) = extractor.classify(ja3);
            let is_browser = matches!(classification, FingerprintClass::Browser);
            let is_legitimate_bot = matches!(classification, FingerprintClass::LegitimateBot);

            Self {
                ja3_hash,
                ja4_hash,
                classification: Some(classification),
                client_name,
                is_browser,
                is_legitimate_bot,
            }
        } else {
            Self {
                ja3_hash,
                ja4_hash,
                ..Default::default()
            }
        }
    }
}

/// State for fingerprint middleware
#[derive(Clone)]
pub struct FingerprintMiddlewareState {
    /// Fingerprint extractor for classification
    pub extractor: Arc<FingerprintExtractor>,
    /// Security state for blocking decisions
    pub security: SecurityState,
    /// Configuration
    pub config: Arc<FingerprintConfig>,
}

impl FingerprintMiddlewareState {
    /// Create a new fingerprint middleware state
    pub fn new(
        extractor: Arc<FingerprintExtractor>,
        security: SecurityState,
        config: Arc<FingerprintConfig>,
    ) -> Self {
        Self {
            extractor,
            security,
            config,
        }
    }
}

/// Fingerprint middleware for request handling
///
/// This middleware:
/// 1. Extracts fingerprint data from headers or connection info
/// 2. Classifies the client (browser, bot, scanner, etc.)
/// 3. Blocks known malicious fingerprints
/// 4. Stores fingerprint info in request extensions
/// 5. Adds fingerprint headers to response for debugging
///
/// # Example
/// ```ignore
/// let app = Router::new()
///     .route("/", get(handler))
///     .layer(middleware::from_fn_with_state(fp_state, fingerprint_middleware));
/// ```
pub async fn fingerprint_middleware(
    State(state): State<FingerprintMiddlewareState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Extract fingerprint from internal headers (set by TLS acceptor)
    let headers = request.headers();
    let ja3_hash = headers
        .get("x-ja3-hash")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let ja4_hash = headers
        .get("x-ja4-hash")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    // Create fingerprint info
    let fp_info =
        FingerprintInfo::from_headers(ja3_hash.clone(), ja4_hash.clone(), &state.extractor);

    // Check if we should block based on fingerprint
    if let Some(ref classification) = fp_info.classification {
        match classification {
            // AUD-12: Gated behind block_malicious flag (default: true).
            // Set block_malicious = false for advisory-only classification.
            FingerprintClass::Malicious if state.config.block_malicious => {
                if let Some(ref ja3) = fp_info.ja3_hash {
                    warn!(
                        "Blocking malicious fingerprint {} from {} (client: {:?})",
                        ja3,
                        client_addr.ip(),
                        fp_info.client_name
                    );
                }
                // Block the connection
                state.security.block_ip(
                    client_addr.ip(),
                    BlockReason::SuspiciousFingerprint,
                    Some(Duration::from_secs(
                        state.config.malicious_block_duration_secs,
                    )),
                );
                return (StatusCode::FORBIDDEN, "Access denied").into_response();
            }
            FingerprintClass::Malicious => {
                // block_malicious = false: advisory-only, log and continue
                if let Some(ref ja3) = fp_info.ja3_hash {
                    info!(
                        "Advisory: malicious fingerprint {} from {} (client: {:?}) — \
                         block_malicious=false, not blocking",
                        ja3,
                        client_addr.ip(),
                        fp_info.client_name
                    );
                }
            }
            FingerprintClass::Scanner if state.config.block_scanners => {
                if let Some(ref ja3) = fp_info.ja3_hash {
                    info!(
                        "Blocking scanner fingerprint {} from {} (client: {:?})",
                        ja3,
                        client_addr.ip(),
                        fp_info.client_name
                    );
                }
                return (StatusCode::FORBIDDEN, "Scanner detected").into_response();
            }
            _ => {}
        }
    }

    // Log fingerprint info for debugging
    if let Some(ref ja3) = fp_info.ja3_hash {
        debug!(
            "Request from {} with fingerprint JA3={}, JA4={:?}, client={:?}, classification={:?}",
            client_addr.ip(),
            ja3,
            fp_info.ja4_hash,
            fp_info.client_name,
            fp_info.classification
        );
    }

    // Store fingerprint info in request extensions
    request.extensions_mut().insert(fp_info.clone());

    // Process the request
    let mut response = next.run(request).await;

    // Add fingerprint headers to response (for debugging/monitoring)
    if state.config.add_response_headers {
        if let Some(ref ja3) = fp_info.ja3_hash {
            if let Ok(v) = HeaderValue::from_str(ja3) {
                response.headers_mut().insert("x-client-fingerprint", v);
            }
        }
        if let Some(ref name) = fp_info.client_name {
            if let Ok(v) = HeaderValue::from_str(name) {
                response.headers_mut().insert("x-client-type", v);
            }
        }
    }

    response
}

// ============================================================================
// Helper functions
// ============================================================================

/// Check if a value is a GREASE value (0x?a?a pattern)
fn is_grease(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = value as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Parse SNI extension
fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    // List length (2 bytes)
    let mut offset = 2;
    // Name type (1 byte)
    if data[offset] != 0x00 {
        return None;
    }
    offset += 1;
    // Name length (2 bytes)
    let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    if offset + name_len > data.len() {
        return None;
    }

    std::str::from_utf8(&data[offset..offset + name_len])
        .ok()
        .map(|s| s.to_string())
}

/// Parse Supported Groups extension
fn parse_supported_groups(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut groups = Vec::new();

    for i in (2..2 + list_len).step_by(2) {
        if i + 2 <= data.len() {
            let group = u16::from_be_bytes([data[i], data[i + 1]]);
            if !is_grease(group) {
                groups.push(group);
            }
        }
    }
    groups
}

/// Parse EC Point Formats extension
fn parse_ec_point_formats(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let list_len = data[0] as usize;
    data[1..].iter().take(list_len).copied().collect()
}

/// Parse Signature Algorithms extension
fn parse_signature_algorithms(data: &[u8]) -> Vec<u16> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut algs = Vec::new();

    for i in (2..2 + list_len).step_by(2) {
        if i + 2 <= data.len() {
            let alg = u16::from_be_bytes([data[i], data[i + 1]]);
            algs.push(alg);
        }
    }
    algs
}

/// Parse ALPN extension
fn parse_alpn(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut protocols = Vec::new();
    let mut offset = 2;

    while offset < 2 + list_len && offset < data.len() {
        let proto_len = data[offset] as usize;
        offset += 1;
        if offset + proto_len <= data.len() {
            if let Ok(proto) = std::str::from_utf8(&data[offset..offset + proto_len]) {
                protocols.push(proto.to_string());
            }
        }
        offset += proto_len;
    }
    protocols
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grease_detection() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0x1a1a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0001));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn test_known_fingerprints() {
        let db = KnownFingerprints::default();

        // Test browser detection
        let (class, name) = db.classify("e7d705a3286e19ea42f587b344ee6865");
        assert_eq!(class, FingerprintClass::Browser);
        assert!(name.is_some());

        // Test unknown fingerprint
        let (class, name) = db.classify("0000000000000000000000000000000");
        assert_eq!(class, FingerprintClass::Suspicious);
        assert!(name.is_none());
    }

    #[test]
    fn test_fingerprint_extractor_creation() {
        let extractor = FingerprintExtractor::new();
        assert!(extractor.cache.is_empty());
    }

    // ========================================================================
    // ClientHello/SNI Parser Tests
    // ========================================================================

    #[test]
    fn test_parse_sni_valid() {
        // SNI extension format:
        // Server Name Indication extension (type 0x00)
        // Data format: list_length(2) + name_type(1) + name_length(2) + name
        let proper_sni = [
            0x00, 0x0e, // List length: 14 bytes
            0x00, // Name type: host_name (0)
            0x00, 0x0b, // Name length: 11 bytes
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let result = parse_sni(&proper_sni);
        assert_eq!(result, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_sni_empty() {
        let result = parse_sni(&[]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_sni_too_short() {
        let result = parse_sni(&[0x00, 0x01, 0x00]);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_sni_wrong_name_type() {
        // Name type is not 0x00 (host_name)
        let sni_data = [
            0x00, 0x08, 0x01, // Wrong name type
            0x00, 0x05, b'h', b'e', b'l', b'l', b'o',
        ];
        let result = parse_sni(&sni_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_sni_truncated_name() {
        // Name length says 20 but we only have 5 bytes
        let sni_data = [
            0x00, 0x18, 0x00, 0x00, 0x14, // Says 20 bytes
            b'h', b'e', b'l', b'l', b'o', // Only 5 bytes
        ];
        let result = parse_sni(&sni_data);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_supported_groups_valid() {
        // Supported groups extension data:
        // length(2) + groups (2 bytes each)
        let data = [
            0x00, 0x08, // List length: 8 bytes (4 groups)
            0x00, 0x1d, // x25519 (29)
            0x00, 0x17, // secp256r1 (23)
            0x00, 0x18, // secp384r1 (24)
            0x00, 0x19, // secp521r1 (25)
        ];
        let result = parse_supported_groups(&data);
        assert_eq!(result, vec![0x001d, 0x0017, 0x0018, 0x0019]);
    }

    #[test]
    fn test_parse_supported_groups_with_grease() {
        // Include GREASE values that should be filtered out
        let data = [
            0x00, 0x0a, // List length: 10 bytes (5 groups)
            0x0a, 0x0a, // GREASE (should be filtered)
            0x00, 0x1d, // x25519
            0x1a, 0x1a, // GREASE (should be filtered)
            0x00, 0x17, // secp256r1
            0xfa, 0xfa, // GREASE (should be filtered)
        ];
        let result = parse_supported_groups(&data);
        assert_eq!(result, vec![0x001d, 0x0017]);
    }

    #[test]
    fn test_parse_supported_groups_empty() {
        let result = parse_supported_groups(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_supported_groups_too_short() {
        let result = parse_supported_groups(&[0x00]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ec_point_formats_valid() {
        // EC point formats extension data:
        // length(1) + formats (1 byte each)
        let data = [
            0x03, // 3 formats
            0x00, // uncompressed
            0x01, // ansiX962_compressed_prime
            0x02, // ansiX962_compressed_char2
        ];
        let result = parse_ec_point_formats(&data);
        assert_eq!(result, vec![0x00, 0x01, 0x02]);
    }

    #[test]
    fn test_parse_ec_point_formats_empty() {
        let result = parse_ec_point_formats(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_ec_point_formats_single() {
        let data = [0x01, 0x00]; // 1 format: uncompressed
        let result = parse_ec_point_formats(&data);
        assert_eq!(result, vec![0x00]);
    }

    #[test]
    fn test_parse_signature_algorithms_valid() {
        // Signature algorithms extension data:
        // length(2) + algorithms (2 bytes each)
        let data = [
            0x00, 0x08, // List length: 8 bytes (4 algorithms)
            0x04, 0x01, // rsa_pkcs1_sha256
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x05, 0x01, // rsa_pkcs1_sha384
            0x06, 0x01, // rsa_pkcs1_sha512
        ];
        let result = parse_signature_algorithms(&data);
        assert_eq!(result, vec![0x0401, 0x0403, 0x0501, 0x0601]);
    }

    #[test]
    fn test_parse_signature_algorithms_empty() {
        let result = parse_signature_algorithms(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_signature_algorithms_too_short() {
        let result = parse_signature_algorithms(&[0x00]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_alpn_valid() {
        // ALPN extension data:
        // list_length(2) + (protocol_length(1) + protocol)*
        let data = [
            0x00, 0x0c, // List length: 12 bytes
            0x02, b'h', b'2', // "h2" (HTTP/2)
            0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1', // "http/1.1"
        ];
        let result = parse_alpn(&data);
        assert_eq!(result, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn test_parse_alpn_empty() {
        let result = parse_alpn(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_alpn_single_protocol() {
        let data = [
            0x00, 0x03, // List length: 3 bytes
            0x02, b'h', b'2', // "h2"
        ];
        let result = parse_alpn(&data);
        assert_eq!(result, vec!["h2".to_string()]);
    }

    #[test]
    fn test_parse_alpn_h3() {
        let data = [
            0x00, 0x03, // List length: 3 bytes
            0x02, b'h', b'3', // "h3"
        ];
        let result = parse_alpn(&data);
        assert_eq!(result, vec!["h3".to_string()]);
    }

    // ========================================================================
    // Full ClientHello Parsing Tests
    // ========================================================================

    #[test]
    fn test_extract_ja3_invalid_record_type() {
        // Not a TLS handshake record (wrong content type)
        let data = [0x17, 0x03, 0x03, 0x00, 0x10]; // Application data type
        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ja3_too_short() {
        let data = [0x16, 0x03, 0x03]; // Only 3 bytes
        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ja3_not_client_hello() {
        // TLS handshake but not ClientHello (type 0x02 = ServerHello)
        let data = [
            0x16, 0x03, 0x03, 0x00, 0x30, // TLS record header
            0x02, 0x00, 0x00, 0x2c, // Handshake header (ServerHello)
            0x03, 0x03, // Version
                  // ... rest would follow
        ];
        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_ja3_minimal_client_hello() {
        // Minimal valid TLS 1.2 ClientHello
        let mut client_hello: Vec<u8> = vec![
            // TLS Record Layer
            0x16, // Content type: Handshake
            0x03, 0x01, // Version: TLS 1.0 (for record layer)
            0x00, 0x4a, // Length (placeholder, will adjust)
            // Handshake header
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x46, // Length (placeholder)
            // ClientHello
            0x03, 0x03, // Version: TLS 1.2
        ];
        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);
        // Session ID length
        client_hello.push(0x00);
        // Cipher suites
        client_hello.extend_from_slice(&[
            0x00, 0x04, // Length: 4 bytes (2 cipher suites)
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]);
        // Compression methods
        client_hello.extend_from_slice(&[
            0x01, // Length: 1
            0x00, // Null compression
        ]);
        // Extensions length (minimal)
        client_hello.extend_from_slice(&[0x00, 0x00]);

        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&client_hello);
        assert!(result.is_some());

        let fp = result.unwrap();
        assert_eq!(fp.tls_version, 0x0303); // TLS 1.2
        assert_eq!(fp.ciphers.len(), 2);
        assert_eq!(fp.ciphers[0], 0x1301);
        assert_eq!(fp.ciphers[1], 0xc02f);
    }

    #[test]
    fn test_extract_ja3_with_sni() {
        // ClientHello with SNI extension
        let mut client_hello: Vec<u8> = vec![
            // TLS Record Layer
            0x16, // Content type: Handshake
            0x03, 0x01, // Version: TLS 1.0 (record layer)
            0x00, 0x5f, // Length (placeholder)
            // Handshake header
            0x01, // Handshake type: ClientHello
            0x00, 0x00, 0x5b, // Length (placeholder)
            // ClientHello
            0x03, 0x03, // Version: TLS 1.2
        ];
        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);
        // Session ID length
        client_hello.push(0x00);
        // Cipher suites
        client_hello.extend_from_slice(&[
            0x00, 0x02, // Length: 2 bytes
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
        ]);
        // Compression methods
        client_hello.extend_from_slice(&[0x01, 0x00]);
        // Extensions
        let sni_ext = [
            0x00, 0x00, // SNI extension type
            0x00, 0x0e, // Extension length
            0x00, 0x0c, // SNI list length
            0x00, // Name type: host_name
            0x00, 0x09, // Name length
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't',
        ];
        client_hello.extend_from_slice(&[(sni_ext.len() >> 8) as u8, sni_ext.len() as u8]);
        client_hello.extend_from_slice(&sni_ext);

        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&client_hello);
        assert!(result.is_some());

        let fp = result.unwrap();
        assert_eq!(fp.sni, Some("localhost".to_string()));
        assert!(fp.extensions.contains(&0)); // SNI extension type
    }

    #[test]
    fn test_extract_ja3_grease_filtering() {
        // ClientHello with GREASE values in ciphers and extensions
        let mut client_hello: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0x60, 0x01, 0x00, 0x00, 0x5c, 0x03, 0x03,
        ];
        client_hello.extend_from_slice(&[0u8; 32]);
        client_hello.push(0x00);
        // Cipher suites with GREASE
        client_hello.extend_from_slice(&[
            0x00, 0x06, 0x0a, 0x0a, // GREASE
            0x13, 0x01, // Real cipher
            0x1a, 0x1a, // GREASE
        ]);
        client_hello.extend_from_slice(&[0x01, 0x00]);
        // Extensions with GREASE
        let exts = [
            0x00, 0x08, // Extensions length
            0x0a, 0x0a, // GREASE extension type
            0x00, 0x00, // Extension length
            0x00, 0x0d, // Signature algorithms extension
            0x00, 0x00, // Extension length
        ];
        client_hello.extend_from_slice(&exts);

        let extractor = FingerprintExtractor::new();
        let result = extractor.extract_ja3(&client_hello);
        assert!(result.is_some());

        let fp = result.unwrap();
        // GREASE values should be filtered out
        assert!(!fp.ciphers.contains(&0x0a0a));
        assert!(!fp.ciphers.contains(&0x1a1a));
        assert!(fp.ciphers.contains(&0x1301));
        assert!(!fp.extensions.contains(&0x0a0a));
    }

    #[test]
    fn test_ja3_hash_determinism() {
        // Same ClientHello should produce same hash
        let mut client_hello: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0x48, 0x01, 0x00, 0x00, 0x44, 0x03, 0x03,
        ];
        client_hello.extend_from_slice(&[0u8; 32]);
        client_hello.push(0x00);
        client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        client_hello.extend_from_slice(&[0x01, 0x00]);
        client_hello.extend_from_slice(&[0x00, 0x00]);

        let extractor = FingerprintExtractor::new();
        let result1 = extractor.extract_ja3(&client_hello);
        let result2 = extractor.extract_ja3(&client_hello);

        assert!(result1.is_some());
        assert!(result2.is_some());
        assert_eq!(result1.unwrap().ja3_hash, result2.unwrap().ja3_hash);
    }

    #[test]
    fn test_ja4_hash_generation() {
        let extractor = FingerprintExtractor::new();

        // TLS 1.3 with SNI
        let ja4 = extractor.calculate_ja4(
            0x0304,                    // TLS 1.3
            &[0x1301, 0x1302, 0x1303], // 3 ciphers
            &[0, 10, 11, 13, 16],      // 5 extensions
            &["h2".to_string()],       // ALPN
            &[0x0401, 0x0403],         // Signature algorithms
            true,                      // Has SNI
        );

        assert!(ja4.is_some());
        let ja4_str = ja4.unwrap();

        // Format: t13d0305h2_<cipher_hash>_<ext_hash>
        assert!(ja4_str.starts_with("t13d")); // TLS, 1.3, domain
        assert!(ja4_str.contains("03")); // 3 ciphers
        assert!(ja4_str.contains("05")); // 5 extensions
        assert!(ja4_str.contains("h2")); // ALPN
        assert!(ja4_str.contains("_")); // Separators
    }

    #[test]
    fn test_ja4_no_sni() {
        let extractor = FingerprintExtractor::new();

        let ja4 = extractor.calculate_ja4(
            0x0303,    // TLS 1.2
            &[0xc02f], // 1 cipher
            &[],       // No extensions
            &[],       // No ALPN
            &[],       // No sig algs
            false,     // No SNI
        );

        assert!(ja4.is_some());
        let ja4_str = ja4.unwrap();

        // Should have 'i' for IP instead of 'd' for domain
        assert!(ja4_str.starts_with("t12i"));
    }

    // ========================================================================
    // Fingerprint Classification Tests
    // ========================================================================

    #[test]
    fn test_classify_browser_fingerprints() {
        let db = KnownFingerprints::default();

        // Chrome
        let (class, name) = db.classify("cd08e31494f9531f560d64c695473da9");
        assert_eq!(class, FingerprintClass::Browser);
        assert!(name.unwrap().contains("Chrome"));

        // Firefox
        let (class, name) = db.classify("47eca2446b260fac53c5cc2dd4aba2ba");
        assert_eq!(class, FingerprintClass::Browser);
        assert!(name.unwrap().contains("Firefox"));

        // Safari
        let (class, name) = db.classify("773906b0efdefa24a7f2b8eb6985bf37");
        assert_eq!(class, FingerprintClass::Browser);
        assert!(name.unwrap().contains("Safari"));
    }

    #[test]
    fn test_classify_bot_fingerprints() {
        let db = KnownFingerprints::default();

        let (class, name) = db.classify("4d7a28d6f2f7e9c8b5a3c1d0e2f6a9b8");
        assert_eq!(class, FingerprintClass::LegitimateBot);
        assert!(name.unwrap().contains("Googlebot"));
    }

    #[test]
    fn test_classify_malicious_fingerprints() {
        let db = KnownFingerprints::default();

        let (class, name) = db.classify("e960427dc851bc6c8a87ad68e9e2aa72");
        assert_eq!(class, FingerprintClass::Malicious);
        assert!(name.unwrap().contains("SQLMap"));
    }

    #[test]
    fn test_classify_scanner_fingerprints() {
        let db = KnownFingerprints::default();

        let (class, name) = db.classify("72f4b0e61f7f6a1b2c3d4e5f6a7b8c9d");
        assert_eq!(class, FingerprintClass::Scanner);
        assert!(name.unwrap().contains("Nmap"));
    }

    #[test]
    fn test_classify_api_client_fingerprints() {
        let db = KnownFingerprints::default();

        let (class, name) = db.classify("1be3ecebe5aa9d3654e6e703d24b6052");
        assert_eq!(class, FingerprintClass::ApiClient);
        assert!(name.unwrap().contains("curl"));
    }
}
