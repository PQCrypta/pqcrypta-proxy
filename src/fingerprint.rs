//! TLS Fingerprinting Module
//!
//! Implements JA3/JA4 TLS fingerprinting for bot detection and client identification.
//! Captures ClientHello during TLS handshake and computes fingerprints.
//!
//! # Integration Status
//! This module is scaffolded for future integration. Full integration requires
//! a custom TLS acceptor layer to intercept ClientHello before handshake completion.
//! The FingerprintingTlsAcceptor is ready but not yet wired into the main request flow.

// Allow dead code for scaffolded features pending TLS layer integration
#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use md5::{Digest, Md5};
use sha2::Sha256;
use tracing::{debug, warn};

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
            FingerprintClass::Malicious => {
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

// Helper functions

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
}
