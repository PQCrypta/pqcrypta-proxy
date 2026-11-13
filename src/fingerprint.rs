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

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher as StdHasher};
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

/// What a fingerprint, or a client network, did within its window that a
/// person's browser does not
#[derive(Debug, Clone, PartialEq)]
pub enum FingerprintThreat {
    /// One fingerprint that is not a browser's or a known crawler's, from
    /// many client networks at once: one tool run from many addresses
    Replay { networks: usize },
    /// One client network presenting a different fingerprint on most of its
    /// connections: a client rotating its fingerprint
    Drift {
        distinct: usize,
        connections: u32,
        drift_score: f64,
    },
}

/// Fingerprints the classification cache holds: a client that randomises its
/// extension order (as Chrome does) has a new JA3 on nearly every connection,
/// so without a ceiling the cache grew with ordinary traffic for as long as
/// the process ran, and nothing swept it
const MAX_CACHED_FINGERPRINTS: usize = 65_536;
/// How often a full table may be swept for room
const FULL_SWEEP_GAP: Duration = Duration::from_secs(5);
/// Fingerprints followed for replay at once
const MAX_REPLAY_ENTRIES: usize = 50_000;
/// Client networks followed for drift at once
const MAX_DRIFT_ENTRIES: usize = 200_000;
/// Distinct fingerprints kept per network: enough to measure any threshold
const MAX_FINGERPRINTS_PER_NETWORK: usize = 256;

/// One fingerprint's client networks in the current replay window
struct ReplayEntry {
    networks: HashSet<u128>,
    window_start: Instant,
    reported: bool,
}

/// One client network's connections and fingerprints in the current drift
/// window
struct DriftState {
    fingerprints: HashSet<u64>,
    connections: u32,
    window_start: Instant,
    reported: bool,
}

/// TLS fingerprint extractor
#[derive(Clone)]
pub struct FingerprintExtractor {
    /// Cache of computed fingerprints
    cache: Arc<DashMap<String, CachedFingerprint>>,
    /// Known fingerprint database
    known_fingerprints: Arc<KnownFingerprints>,
    /// Replay detection: fingerprint (JA4, else JA3) → its networks
    replay_cache: Arc<DashMap<String, ReplayEntry>>,
    /// Drift detection: client network → its fingerprints
    drift_cache: Arc<DashMap<u128, DriftState>>,
    /// The three tables' ceilings: a full table is swept for expired entries
    /// at most once per [`FULL_SWEEP_GAP`], not once per new key
    cache_ceiling: Arc<crate::bounded::Ceiling>,
    replay_ceiling: Arc<crate::bounded::Ceiling>,
    drift_ceiling: Arc<crate::bounded::Ceiling>,
}

/// A fingerprint as a u64, for counting distinct ones
fn fingerprint_id(fingerprint: &str) -> u64 {
    let mut h = DefaultHasher::new();
    fingerprint.hash(&mut h);
    h.finish()
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
    /// Classify from both fingerprints, trying JA3 then JA4.
    ///
    /// Tools that vary their cipher list between probes — nmap's
    /// ssl-enum-ciphers is the clearest example — produce a fresh JA3 every
    /// run while their JA4 stays constant, because JA4 sorts and summarises
    /// where JA3 hashes raw order. Matching on JA3 alone cannot recognise
    /// such a client twice, so entries for them are stored as JA4.
    pub fn classify_pair(
        &self,
        ja3_hash: &str,
        ja4_hash: Option<&str>,
    ) -> (FingerprintClass, Option<String>) {
        let by_ja3 = self.classify(ja3_hash);
        if !matches!(by_ja3.0, FingerprintClass::Suspicious) {
            return by_ja3;
        }
        match ja4_hash {
            Some(ja4) => self.classify(ja4),
            None => by_ja3,
        }
    }

    /// Classify a single hash (JA3 or JA4 — the tables are keyed by string)
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
            replay_cache: Arc::new(DashMap::new()),
            drift_cache: Arc::new(DashMap::new()),
            cache_ceiling: Arc::new(crate::bounded::Ceiling::new(
                MAX_CACHED_FINGERPRINTS,
                FULL_SWEEP_GAP,
            )),
            replay_ceiling: Arc::new(crate::bounded::Ceiling::new(
                MAX_REPLAY_ENTRIES,
                FULL_SWEEP_GAP,
            )),
            drift_ceiling: Arc::new(crate::bounded::Ceiling::new(
                MAX_DRIFT_ENTRIES,
                FULL_SWEEP_GAP,
            )),
        }
    }

    /// Replay: `fingerprint` (from `network`) counted against its window.
    /// Returns the threat while the fingerprint is over the threshold, and
    /// whether this is the first time it is reported in the window.
    pub fn check_replay(
        &self,
        fingerprint: &str,
        network: u128,
        classification: &FingerprintClass,
        config: &FingerprintConfig,
    ) -> Option<(FingerprintThreat, bool)> {
        if !config.replay_detection
            || matches!(
                classification,
                FingerprintClass::Browser | FingerprintClass::LegitimateBot
            )
        {
            return None;
        }
        let window = Duration::from_secs(config.replay_window_secs);
        let now = Instant::now();
        if !self.replay_cache.contains_key(fingerprint)
            && !self.replay_ceiling.admits(self.replay_cache.len(), || {
                self.replay_cache
                    .retain(|_, e| now.duration_since(e.window_start) <= window);
                self.replay_cache.len()
            })
        {
            return None;
        }
        let mut entry = self
            .replay_cache
            .entry(fingerprint.to_string())
            .or_insert_with(|| ReplayEntry {
                networks: HashSet::new(),
                window_start: now,
                reported: false,
            });
        if now.duration_since(entry.window_start) > window {
            entry.networks.clear();
            entry.window_start = now;
            entry.reported = false;
        }
        let threshold = config.replay_min_networks.max(2);
        if entry.networks.len() < threshold {
            entry.networks.insert(network);
        }
        if entry.networks.len() < threshold {
            return None;
        }
        let first = !entry.reported;
        entry.reported = true;
        Some((
            FingerprintThreat::Replay {
                networks: entry.networks.len(),
            },
            first,
        ))
    }

    /// Drift: a connection from `network` presenting `fingerprint`, counted
    /// against the network's window. Returns the threat while the network is
    /// over the threshold, and whether this is the first time it is reported
    /// in the window.
    pub fn check_drift(
        &self,
        network: u128,
        fingerprint: &str,
        config: &FingerprintConfig,
    ) -> Option<(FingerprintThreat, bool)> {
        if !config.drift_detection {
            return None;
        }
        let window = Duration::from_secs(config.drift_window_secs);
        let now = Instant::now();
        if !self.drift_cache.contains_key(&network)
            && !self.drift_ceiling.admits(self.drift_cache.len(), || {
                self.drift_cache
                    .retain(|_, e| now.duration_since(e.window_start) <= window);
                self.drift_cache.len()
            })
        {
            return None;
        }
        let mut entry = self
            .drift_cache
            .entry(network)
            .or_insert_with(|| DriftState {
                fingerprints: HashSet::new(),
                connections: 0,
                window_start: now,
                reported: false,
            });
        if now.duration_since(entry.window_start) > window {
            entry.fingerprints.clear();
            entry.connections = 0;
            entry.window_start = now;
            entry.reported = false;
        }
        entry.connections = entry.connections.saturating_add(1);
        if entry.fingerprints.len() < MAX_FINGERPRINTS_PER_NETWORK {
            entry.fingerprints.insert(fingerprint_id(fingerprint));
        }
        if entry.connections < config.drift_min_connections.max(2) {
            return None;
        }
        let distinct = entry.fingerprints.len();
        let drift_score =
            f64::from(u32::try_from(distinct).unwrap_or(u32::MAX)) / f64::from(entry.connections);
        if drift_score < config.drift_threshold {
            return None;
        }
        let first = !entry.reported;
        entry.reported = true;
        Some((
            FingerprintThreat::Drift {
                distinct,
                connections: entry.connections,
                drift_score,
            },
            first,
        ))
    }

    /// Classify a JA3 hash against the known fingerprint database
    ///
    /// Returns (classification, optional_client_name)
    pub fn classify(&self, ja3_hash: &str) -> (FingerprintClass, Option<String>) {
        self.known_fingerprints.classify(ja3_hash)
    }
}

/// Which transport carried the ClientHello.
///
/// The JA4 spec's first character. Not cosmetic: the same client build over TCP
/// and over QUIC offers a different extension set (QUIC adds transport
/// parameters, drops others), and the marker is what keeps the two from being
/// read as one fingerprint that keeps drifting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ja4Transport {
    /// TLS over TCP.
    Tcp,
    /// TLS over QUIC.
    Quic,
}

impl Ja4Transport {
    fn marker(self) -> &'static str {
        match self {
            Self::Tcp => "t",
            Self::Quic => "q",
        }
    }
}

impl FingerprintExtractor {
    /// Extract JA3 fingerprint from a TLS record containing a ClientHello.
    ///
    /// JA3 format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    ///
    /// Takes a record because that is what a TCP listener peeks off the socket.
    /// For QUIC, where there is no record layer, use [`extract_ja3_quic`].
    ///
    /// [`extract_ja3_quic`]: Self::extract_ja3_quic
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

        self.extract_from_handshake(handshake, tls_version, Ja4Transport::Tcp)
    }

    /// Extract a fingerprint from a bare ClientHello handshake message.
    ///
    /// QUIC carries the hello in Initial CRYPTO frames with no record layer, so
    /// the bytes start at the handshake header rather than a record header, and
    /// there is no record version to fold into the JA3 version field.
    ///
    /// Deliberately the same parser as the TCP path rather than a second one.
    /// The QUIC and TCP listeners are already separate implementations and have
    /// drifted before; two fingerprint parsers would mean the same client could
    /// be classified differently depending on which port it reached, and a
    /// blocklist entry gathered on one would silently not apply on the other.
    pub fn extract_ja3_quic(&self, handshake: &[u8]) -> Option<Ja3Fingerprint> {
        // 0 as the record version: `ch_version.max(record_version)` below then
        // yields the ClientHello's own version, which is the only one that
        // exists here.
        self.extract_from_handshake(handshake, 0, Ja4Transport::Quic)
    }

    /// Shared body of both entry points, from the handshake header onward.
    fn extract_from_handshake(
        &self,
        handshake: &[u8],
        tls_version: u16,
        transport: Ja4Transport,
    ) -> Option<Ja3Fingerprint> {
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

        // Read through a checked slice in whole pairs. Stepping by two up to an
        // odd length read one byte past the list, and past the buffer when the
        // list ended it: an out-of-bounds index, which with panic = "abort"
        // let any client end the process with a truncated hello.
        let cipher_bytes = client_hello_data.get(offset..offset + cipher_suites_len)?;
        let mut ciphers = Vec::new();
        for pair in cipher_bytes.as_chunks::<2>().0 {
            let cipher = u16::from_be_bytes(*pair);
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
        let mut supported_versions_max: Option<u16> = None;

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
                        43 => {
                            // Supported Versions. A TLS 1.3 client is required
                            // to pin legacy_version at 0x0303 and advertise 1.3
                            // only here, so the ClientHello version alone says
                            // "TLS 1.2" for every modern client.
                            supported_versions_max = parse_supported_versions(ext_data);
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

        // JA4 takes the highest version the client actually offered, which for
        // any TLS 1.3 client lives in supported_versions rather than in the
        // frozen 0x0303 legacy field. Using the legacy field labelled every
        // modern client "12", so our JA4s could not be cross-referenced against
        // public JA4 data and the directory decoded them as TLS 1.2.
        //
        // JA3 deliberately keeps `ch_version`: its spec defines the version as
        // the ClientHello's own field, and changing it would invalidate every
        // JA3 in the curated database.
        let ja4_version = supported_versions_max.unwrap_or(ch_version);

        // Also calculate JA4 fingerprint, and its raw form
        let (ja4, ja4_raw) = ja4_with_raw(
            ja4_version,
            &ciphers,
            &extensions,
            &alpn_protocols,
            &signature_algorithms,
            sni.is_some(),
            transport,
        );
        let ja4_hash = Some(ja4);

        Some(Ja3Fingerprint {
            ja3_string,
            ja3_hash,
            ja4_hash,
            ja4_raw: Some(ja4_raw),
            tls_version: ch_version,
            ciphers,
            extensions,
            elliptic_curves,
            ec_point_formats,
            sni,
            alpn_protocols: alpn_protocols
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect(),
        })
    }

    /// The JA4 alone (see ja4_with_raw for the format), for the tests written
    /// against the extractor; the extractor takes JA4 and JA4_r together.
    #[cfg(test)]
    #[expect(clippy::too_many_arguments)]
    fn calculate_ja4(
        &self,
        tls_version: u16,
        ciphers: &[u16],
        extensions: &[u16],
        alpn: &[Vec<u8>],
        sig_algs: &[u16],
        has_sni: bool,
        transport: Ja4Transport,
    ) -> Option<String> {
        Some(
            ja4_with_raw(
                tls_version,
                ciphers,
                extensions,
                alpn,
                sig_algs,
                has_sni,
                transport,
            )
            .0,
        )
    }

    /// Process a ClientHello from a TLS record and update security state.
    pub fn process_client_hello(
        &self,
        client_hello: &[u8],
        client_ip: IpAddr,
        security: &SecurityState,
        config: &FingerprintConfig,
    ) -> FingerprintResult {
        self.process_fingerprint(self.extract_ja3(client_hello), client_ip, security, config)
    }

    /// Process a ClientHello that arrived over QUIC.
    ///
    /// `handshake` is the bare handshake message the TLS stack recovered from
    /// the Initial CRYPTO frames — there is no record layer to strip.
    ///
    /// Everything after extraction is the same code as the TCP path: the same
    /// classification order, the same cache, the same pentest-bypass rule, the
    /// same ban decision. A QUIC client must not be judged by different rules
    /// than the identical client over TCP, and duplicating the policy here is
    /// how that would happen.
    pub fn process_client_hello_quic(
        &self,
        handshake: &[u8],
        client_ip: IpAddr,
        security: &SecurityState,
        config: &FingerprintConfig,
    ) -> FingerprintResult {
        self.process_fingerprint(
            self.extract_ja3_quic(handshake),
            client_ip,
            security,
            config,
        )
    }

    /// Classification, caching and blocking for an already-extracted
    /// fingerprint. Shared by both transports.
    fn process_fingerprint(
        &self,
        fingerprint: Option<Ja3Fingerprint>,
        client_ip: IpAddr,
        security: &SecurityState,
        config: &FingerprintConfig,
    ) -> FingerprintResult {
        let fingerprint = match fingerprint {
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
        // Classify against the operator-maintained database first, then the
        // built-in table.
        //
        // The JSON database at fingerprint.fingerprint_db_path was loaded at
        // startup into SecurityState::ja3_db, logged as "Loaded N JA3/JA4
        // fingerprints" — and then read by nothing at all. Every classification
        // came from the small hardcoded table below, so entries added to the
        // file changed no decision whatever they said. That is why populating
        // the file could never make block_malicious fire.
        let (classification, client_name) = {
            let from_file = security
                .ja3_db
                .load()
                .classify_pair(&ja3_hash, ja4_hash.as_deref());
            if matches!(from_file, crate::security::FingerprintClass::Suspicious) {
                self.known_fingerprints
                    .classify_pair(&ja3_hash, ja4_hash.as_deref())
            } else {
                (from_file, None)
            }
        };

        // Update cache: a new fingerprint only while there is room, a full
        // cache swept of fingerprints older than `cache_max_age_secs` at most
        // once a gap
        let now = Instant::now();
        if let Some(mut cached) = self.cache.get_mut(&ja3_hash) {
            cached.last_seen = now;
            cached.request_count += 1;
        } else if self.cache_ceiling.admits(self.cache.len(), || {
            let max_age = Duration::from_secs(config.cache_max_age_secs);
            self.cache
                .retain(|_, cached| cached.last_seen.elapsed() < max_age);
            self.cache.len()
        }) {
            self.cache
                .entry(ja3_hash.clone())
                .or_insert_with(|| CachedFingerprint {
                    ja3_hash: ja3_hash.clone(),
                    ja4_hash: ja4_hash.clone(),
                    classification: classification.clone(),
                    first_seen: now,
                    last_seen: now,
                    request_count: 1,
                });
        }

        // Update security state JA3 cache.
        //
        // Accumulates rather than overwrites. The unconditional `insert` this
        // replaced reset `first_seen` to now and `request_count` to 1 on every
        // single connection, so the corpus could answer "have I ever seen this
        // hash" and nothing else — no counts, no age, and eviction sorted on a
        // timestamp that was always the present moment.
        let transport = ja4_hash
            .as_deref()
            .and_then(|j| j.chars().next())
            .unwrap_or('t');

        if let Some(mut existing) = security.ja3_cache.get_mut(&ja3_hash) {
            existing.last_seen = now;
            existing.request_count = existing.request_count.saturating_add(1);
            // Re-classification can change as the operator database grows,
            // so take the current verdict rather than the one from first
            // sighting.
            existing.classification = classification.clone();
            // The JA4 a JA3 maps to is recomputed on every sighting, so a
            // row first stored under an earlier computation (before
            // 2026-10-15 SNI and ALPN were hashed into part c) takes the
            // current one when its client comes back.
            existing.ja4_hash = ja4_hash.clone();
            existing.ja4_raw = fingerprint.ja4_raw.clone();
        } else if security.admit_fingerprint() {
            security
                .ja3_cache
                .entry(ja3_hash.clone())
                .or_insert_with(|| TlsFingerprint {
                    ja3_hash: ja3_hash.clone(),
                    ja4_hash: ja4_hash.clone(),
                    ja4_raw: fingerprint.ja4_raw.clone(),
                    ja3_string: fingerprint.ja3_string.clone(),
                    classification: classification.clone(),
                    transport,
                    first_seen: now,
                    last_seen: now,
                    request_count: 1,
                    // Filled in by the HTTP layer via note_user_agent — no request
                    // exists yet at the TLS layer where this record is created.
                    user_agents: std::collections::HashMap::new(),
                });
        }

        // The record: every distinct fingerprint, under its JA4, for good
        let first_sighting = security
            .corpus
            .observe(&crate::fingerprint_corpus::Sighting {
                ja3_hash: &ja3_hash,
                ja3_string: &fingerprint.ja3_string,
                ja4_hash: ja4_hash.as_deref(),
                ja4_raw: fingerprint.ja4_raw.as_deref(),
                classification: &format!("{classification:?}"),
                transport,
                at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                client: Some(client_ip),
            });

        // Record the first sighting of a fingerprint.
        //
        // One line per fingerprint the corpus has never seen, so running a
        // single named tool and reading that window gives its fingerprints.
        // Keyed on the corpus, by JA4, rather than the JA3 cache: a client that
        // shuffles its extensions (Chrome, per connection) has a new JA3 every
        // time, which logged hundreds of "new" lines an hour for one browser.
        // JA4 sorts what JA3 hashes in order, and the corpus is never evicted.
        // No User-Agent here: this runs at the TLS layer, where no HTTP request
        // exists yet; correlate through the x-ja3-hash header the proxy
        // injects downstream.
        if first_sighting {
            info!(
                target: "fingerprint_observed",
                "New TLS fingerprint: ja3={:?} ja4={:?} class={:?} client={:?} ip={}",
                ja3_hash,
                ja4_hash,
                classification,
                client_name,
                client_ip
            );
        }

        // Authorized pentest sources are never banned by fingerprint.
        //
        // A fingerprint block is an auto-ban, and pentest_bypass_ips exists
        // precisely so an engagement is not cut off mid-run — the same contract
        // the rate limiter and auto-blocker already honour. Without this, adding
        // a scanner fingerprint to the database would ban the very box the scans
        // are meant to come from. Classification still happens and is still
        // logged; only the ban is skipped.
        let is_pentest_source = {
            let sc = security.config.read();
            crate::config::ip_list_contains(&sc.pentest_bypass_ips, &client_ip)
        };
        if is_pentest_source && !matches!(classification, FingerprintClass::Browser) {
            debug!(
                "Pentest source {} presented {:?} fingerprint {} — classified, not banned",
                client_ip, classification, ja3_hash
            );
            return FingerprintResult {
                allowed: true,
                ja3_hash: Some(ja3_hash),
                ja4_hash,
                classification: Some(classification),
                client_name,
            };
        }

        // Replay and drift (see FingerprintThreat): judged on the JA4, which
        // a browser keeps however it orders its extensions
        let threat_blocked = self.judge_behaviour(
            ja4_hash.as_deref().unwrap_or(&ja3_hash),
            client_ip,
            &classification,
            security,
            config,
        );

        // Check if this fingerprint should be blocked (using configurable thresholds)
        let allowed = !threat_blocked
            && match &classification {
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

    /// Count this connection for replay and drift; report what crosses a
    /// threshold (once a window, warn and audit) and block the address when
    /// that threat's action says so. True when it was blocked.
    fn judge_behaviour(
        &self,
        fingerprint: &str,
        client_ip: IpAddr,
        classification: &FingerprintClass,
        security: &SecurityState,
        config: &FingerprintConfig,
    ) -> bool {
        let network = crate::fingerprint_corpus::client_network(client_ip);
        let replay = self.check_replay(fingerprint, network, classification, config);
        let drift = self.check_drift(network, fingerprint, config);
        let mut blocked = false;
        for (threat, first) in replay.into_iter().chain(drift) {
            let block = match threat {
                FingerprintThreat::Replay { .. } => config.replay_action == "block",
                FingerprintThreat::Drift { .. } => config.drift_action == "block",
            };
            if block {
                security.block_ip(
                    client_ip,
                    BlockReason::SuspiciousFingerprint,
                    Some(Duration::from_secs(config.suspicious_block_duration_secs)),
                );
                blocked = true;
            }
            // Reported once a window; a block is audited by `block_ip`
            if !first {
                continue;
            }
            let ip = client_ip.to_string();
            let event = match threat {
                FingerprintThreat::Replay { networks } => {
                    if first {
                        warn!(
                            "Fingerprint {} ({:?}) from {} client networks within {}s (latest {}){}",
                            fingerprint,
                            classification,
                            networks,
                            config.replay_window_secs,
                            ip,
                            if block { ": blocking" } else { "" }
                        );
                    }
                    crate::audit_logger::AuditEvent::FingerprintReplay {
                        fingerprint: fingerprint.to_string(),
                        ip,
                        networks,
                        blocked: block,
                    }
                }
                FingerprintThreat::Drift {
                    distinct,
                    connections,
                    drift_score,
                } => {
                    if first {
                        warn!(
                            "Client network of {} presented {} fingerprints on {} connections within {}s{}",
                            ip,
                            distinct,
                            connections,
                            config.drift_window_secs,
                            if block { ": blocking" } else { "" }
                        );
                    }
                    crate::audit_logger::AuditEvent::FingerprintDrift {
                        fingerprint: fingerprint.to_string(),
                        ip,
                        distinct,
                        connections,
                        drift_score,
                        blocked: block,
                    }
                }
            };
            if let Some(audit) = &security.audit_logger {
                audit.log(event);
            }
        }
        blocked
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
    /// JA4_r: the JA4 inputs before hashing (FoxIO's raw form).
    pub ja4_raw: Option<String>,
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
    // MEASUREMENT ONLY: the layer stays in the chain and pays every bit of the
    // plumbing — the boxed future, the per-request clone, the `Next` indirection —
    // but does none of its own work. Subtracting this from the full build gives
    // the work; subtracting the no-chain build from this gives the plumbing.
    #[cfg(feature = "bench-null-middleware")]
    {
        return next.run(request).await;
    }
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

    // Correlate the connection's fingerprint with what this request calls
    // itself. The TLS layer that computed the fingerprint had no HTTP request to
    // read a User-Agent from; this is the first layer that holds both, and the
    // pairing is what lets the directory name a client rather than list a hash.
    if let Some(ref ja3) = ja3_hash {
        if let Some(ua) = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
        {
            state.security.note_user_agent(ja3, ua);
        }
    }

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
    let lo = (value & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// JA4 and its raw form (FoxIO JA4 spec), as `(ja4, ja4_r)`.
///
/// JA4 is `a_b_c`:
/// - a: transport, TLS version, SNI (d/i), cipher and extension counts
///   (GREASE excluded, SNI and ALPN included), first/last ALPN characters;
/// - b: SHA-256 of the sorted cipher list, first 12 hex characters;
/// - c: SHA-256 of the sorted extension list, then `_` and the signature
///   algorithms in the order sent, first 12 hex characters. SNI (0000) and
///   ALPN (0010) are left out of this list: part a already carries them. With
///   no signature algorithms there is no `_`.
///
/// An empty list hashes to `000000000000`. JA4_r is the same three parts with
/// the lists written out instead of hashed, which is what lets a stored
/// fingerprint be checked or recomputed later.
///
/// Until 2026-10-15 SNI and ALPN went into part c, and an empty signature
/// list still added the `_`: every JA4 from a client sending SNI or ALPN
/// (nearly all) disagreed with every other JA4 implementation.
fn ja4_with_raw(
    tls_version: u16,
    ciphers: &[u16],
    extensions: &[u16],
    alpn: &[Vec<u8>],
    sig_algs: &[u16],
    has_sni: bool,
    transport: Ja4Transport,
) -> (String, String) {
    // Protocol type. This was hardcoded to "t", which meant a QUIC client
    // produced a JA4 claiming it arrived over TCP — colliding with the TCP
    // fingerprint of the same client build and losing the one bit that
    // distinguishes them.
    let proto = transport.marker();

    let version = match tls_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_type = if has_sni { "d" } else { "i" };
    let part_a = format!(
        "{}{}{}{:02}{:02}{}",
        proto,
        version,
        sni_type,
        ciphers.len().min(99),
        extensions.len().min(99),
        ja4_alpn(alpn.first().map(Vec::as_slice))
    );

    let hex_list = |values: &[u16]| {
        values
            .iter()
            .map(|v| format!("{v:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let truncated_sha256 =
        |input: &str| hex::encode(Sha256::digest(input.as_bytes()))[..12].to_string();

    let mut sorted_ciphers = ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let cipher_list = hex_list(&sorted_ciphers);

    let mut sorted_exts: Vec<u16> = extensions
        .iter()
        .copied()
        .filter(|&e| e != 0x0000 && e != 0x0010)
        .collect();
    sorted_exts.sort_unstable();
    let ext_list = hex_list(&sorted_exts);
    let sig_list = hex_list(sig_algs);
    let ext_input = if sig_algs.is_empty() {
        ext_list
    } else {
        format!("{ext_list}_{sig_list}")
    };

    let part_b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        truncated_sha256(&cipher_list)
    };
    let part_c = if sorted_exts.is_empty() {
        "000000000000".to_string()
    } else {
        truncated_sha256(&ext_input)
    };

    (
        format!("{part_a}_{part_b}_{part_c}"),
        format!("{part_a}_{cipher_list}_{ext_input}"),
    )
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
/// Highest non-GREASE version from a `supported_versions` extension.
///
/// ClientHello form: 1-byte list length, then 2-byte versions. GREASE values are
/// skipped for the same reason they are everywhere else here — they are
/// deliberate noise and including them would make the fingerprint unstable.
fn parse_supported_versions(data: &[u8]) -> Option<u16> {
    let list_len = *data.first()? as usize;
    let list = data.get(1..1 + list_len)?;
    list.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|v| !is_grease(*v))
        .max()
}

/// The ALPN protocol names as sent, bytes and all. Names that were not UTF-8
/// used to be dropped, which silently changed which name counted as "first".
fn parse_alpn(data: &[u8]) -> Vec<Vec<u8>> {
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
            protocols.push(data[offset..offset + proto_len].to_vec());
        }
        offset += proto_len;
    }
    protocols
}

/// JA4's ALPN field (FoxIO JA4 spec): the first and last characters of the
/// first ALPN value ("http/1.1" -> "h1", "h2" -> "h2", a one-character value
/// counts as both); "00" when there is none; and when either end is not
/// ASCII alphanumeric, the first and last characters of the value's hex form.
///
/// This used to take the first two characters of a UTF-8 string: "http/1.1"
/// became "ht", raw newlines ended up in fingerprints (and in sitemap URLs),
/// and a value starting with a three-byte character such as "€" was sliced
/// mid-character -- a panic, and with panic = "abort" one ClientHello took the
/// whole proxy down.
fn ja4_alpn(first: Option<&[u8]>) -> String {
    let Some(value) = first.filter(|v| !v.is_empty()) else {
        return "00".to_string();
    };
    let (head, tail) = (value[0], value[value.len() - 1]);
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        format!("{}{}", head as char, tail as char)
    } else {
        let hex = hex::encode(value);
        format!("{}{}", &hex[..1], &hex[hex.len() - 1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A browser's fingerprint from many networks is a browser; a tool's
    /// is flagged once it reaches the threshold, and reported once a window.
    #[test]
    fn one_tool_from_many_networks_is_flagged_and_browsers_are_not() {
        let fx = FingerprintExtractor::new();
        let config = FingerprintConfig {
            replay_min_networks: 5,
            ..FingerprintConfig::default()
        };
        let net = |i: u32| {
            crate::fingerprint_corpus::client_network(IpAddr::from(std::net::Ipv4Addr::from(
                0x0A00_0000 + (i << 8),
            )))
        };
        for i in 0..20 {
            assert!(fx
                .check_replay(
                    "t13d1516h2_chrome",
                    net(i),
                    &FingerprintClass::Browser,
                    &config
                )
                .is_none());
        }
        let tool = |i| {
            fx.check_replay(
                "t13d0812h1_tool",
                net(i),
                &FingerprintClass::Suspicious,
                &config,
            )
        };
        for i in 0..4 {
            assert!(tool(i).is_none(), "{} networks", i + 1);
        }
        // The same network again adds nothing
        assert!(tool(3).is_none());
        assert_eq!(
            tool(4),
            Some((FingerprintThreat::Replay { networks: 5 }, true))
        );
        assert_eq!(
            tool(5),
            Some((FingerprintThreat::Replay { networks: 5 }, false)),
            "still flagged, reported once"
        );
    }

    /// A network whose connections keep one or two fingerprints (a browser,
    /// a NAT of a few) is not drift; one presenting a new one on most
    /// connections is, once it has made enough of them.
    #[test]
    fn a_network_rotating_its_fingerprint_is_flagged() {
        let fx = FingerprintExtractor::new();
        let config = FingerprintConfig {
            drift_min_connections: 10,
            drift_threshold: 0.7,
            ..FingerprintConfig::default()
        };
        let office = 1;
        for i in 0..40 {
            let fp = if i % 2 == 0 {
                "t13d1516h2_a"
            } else {
                "q13d0312h3_a"
            };
            assert!(fx.check_drift(office, fp, &config).is_none());
        }
        let bot = 2;
        for i in 0..9 {
            assert!(fx
                .check_drift(bot, &format!("t13d{i}_rotating"), &config)
                .is_none());
        }
        let Some((
            FingerprintThreat::Drift {
                distinct,
                connections,
                drift_score,
            },
            true,
        )) = fx.check_drift(bot, "t13d9_rotating", &config)
        else {
            panic!("ten connections, ten fingerprints");
        };
        assert_eq!((distinct, connections), (10, 10));
        assert!((drift_score - 1.0).abs() < f64::EPSILON);
        assert!(matches!(
            fx.check_drift(bot, "t13d10_rotating", &config),
            Some((FingerprintThreat::Drift { .. }, false))
        ));
    }

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
        assert_eq!(result, [] as [u16; 0]);
    }

    #[test]
    fn test_parse_supported_groups_too_short() {
        let result = parse_supported_groups(&[0x00]);
        assert_eq!(result, [] as [u16; 0]);
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
        assert_eq!(result, [] as [u8; 0]);
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
        assert_eq!(result, [] as [u16; 0]);
    }

    #[test]
    fn test_parse_signature_algorithms_too_short() {
        let result = parse_signature_algorithms(&[0x00]);
        assert_eq!(result, [] as [u16; 0]);
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
        assert_eq!(result, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_parse_alpn_empty() {
        let result = parse_alpn(&[]);
        assert_eq!(result, [] as [Vec<u8>; 0]);
    }

    #[test]
    fn test_parse_alpn_single_protocol() {
        let data = [
            0x00, 0x03, // List length: 3 bytes
            0x02, b'h', b'2', // "h2"
        ];
        let result = parse_alpn(&data);
        assert_eq!(result, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_parse_alpn_h3() {
        let data = [
            0x00, 0x03, // List length: 3 bytes
            0x02, b'h', b'3', // "h3"
        ];
        let result = parse_alpn(&data);
        assert_eq!(result, vec![b"h3".to_vec()]);
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
        client_hello.extend_from_slice(&[
            u8::try_from((sni_ext.len() >> 8) & 0xff).unwrap_or(u8::MAX),
            u8::try_from(sni_ext.len() & 0xff).unwrap_or(u8::MAX),
        ]);
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

    /// FoxIO's published example (JA4 README): JA4 and JA4_r for the same
    /// hello. The 16 extensions counted in part a include SNI and ALPN; the 14
    /// hashed in part c do not.
    #[test]
    fn ja4_matches_the_foxio_example() {
        let ciphers = [
            0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c,
            0xc02f, 0xc030, 0xcca8, 0xcca9,
        ];
        let extensions = [
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023,
            0x002b, 0x002d, 0x0033, 0x4469, 0xff01,
        ];
        let sig_algs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let (ja4, ja4_r) = ja4_with_raw(
            0x0304,
            &ciphers,
            &extensions,
            &[b"h2".to_vec()],
            &sig_algs,
            true,
            Ja4Transport::Tcp,
        );
        assert_eq!(ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(
            ja4_r,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
             0403,0804,0401,0503,0805,0501,0806,0601"
        );
    }

    /// Chrome 142 as this proxy recorded it (extension order from its JA3
    /// string): the JA4 every other implementation gives for current Chrome.
    /// The old computation produced ..._db113fc12e09 for the same hello.
    #[test]
    fn ja4_matches_chrome_142() {
        let ciphers = [
            4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47,
            53,
        ];
        let extensions = [
            23, 0, 65281, 16, 5, 18, 35, 11, 51, 65037, 27, 13, 17613, 43, 10, 45,
        ];
        let sig_algs = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ];
        let (ja4, _) = ja4_with_raw(
            0x0304,
            &ciphers,
            &extensions,
            &[b"h2".to_vec(), b"http/1.1".to_vec()],
            &sig_algs,
            true,
            Ja4Transport::Tcp,
        );
        assert_eq!(ja4, "t13d1516h2_8daaf6152771_d8a2da3f94cd");
    }

    /// No signature algorithms: part c hashes the extension list alone, with
    /// no trailing underscore. An empty list is 000000000000.
    #[test]
    fn ja4_edge_cases_follow_the_spec() {
        let (ja4, ja4_r) = ja4_with_raw(
            0x0303,
            &[0x002f],
            &[0x0000, 0x000a, 0x0010],
            &[],
            &[],
            false,
            Ja4Transport::Tcp,
        );
        assert_eq!(ja4_r, "t12i010300_002f_000a");
        assert_eq!(
            ja4,
            format!("t12i010300_{}_{}", sha12("002f"), sha12("000a"))
        );

        // Only SNI and ALPN, no ciphers: both hashed lists are empty
        let (ja4, _) = ja4_with_raw(
            0x0304,
            &[],
            &[0x0000, 0x0010],
            &[b"h2".to_vec()],
            &[0x0403],
            true,
            Ja4Transport::Quic,
        );
        assert_eq!(ja4, "q13d0002h2_000000000000_000000000000");
    }

    fn sha12(input: &str) -> String {
        hex::encode(Sha256::digest(input.as_bytes()))[..12].to_string()
    }

    #[test]
    fn test_ja4_hash_generation() {
        let extractor = FingerprintExtractor::new();

        // TLS 1.3 with SNI
        let ja4 = extractor.calculate_ja4(
            0x0304,                    // TLS 1.3
            &[0x1301, 0x1302, 0x1303], // 3 ciphers
            &[0, 10, 11, 13, 16],      // 5 extensions
            &[b"h2".to_vec()],         // ALPN
            &[0x0401, 0x0403],         // Signature algorithms
            true,                      // Has SNI
            Ja4Transport::Tcp,
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

    /// Hostile ClientHellos must never panic: with panic = "abort" in release,
    /// a panic here takes the whole proxy down, and this parser runs on every
    /// handshake, TCP and QUIC, before anything else has looked at the client.
    /// See crate::fuzz_support for the mutations and replay.
    #[test]
    fn mutated_client_hellos_never_panic() {
        fn len16(bytes: &[u8]) -> [u8; 2] {
            u16::try_from(bytes.len()).unwrap().to_be_bytes()
        }
        fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
            let mut v = kind.to_be_bytes().to_vec();
            v.extend_from_slice(&len16(body));
            v.extend_from_slice(body);
            v
        }
        let mut exts = Vec::new();
        exts.extend(ext(0, b"\x00\x0e\x00\x00\x0bexample.com"));
        exts.extend(ext(16, b"\x00\x0c\x02h2\x08http/1.1"));
        exts.extend(ext(43, b"\x04\x03\x04\x03\x03"));
        exts.extend(ext(13, b"\x00\x04\x04\x03\x08\x04"));
        exts.extend(ext(10, b"\x00\x04\x00\x1d\x00\x17"));
        exts.extend(ext(11, b"\x01\x00"));
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(b"\x00\x04\x13\x01\x13\x02\x01\x00");
        body.extend_from_slice(&len16(&exts));
        body.extend_from_slice(&exts);
        let [hi, lo] = len16(&body);
        let mut handshake = vec![0x01, 0, hi, lo];
        handshake.extend_from_slice(&body);
        let [hi, lo] = len16(&handshake);
        let mut record = vec![0x16, 0x03, 0x01, hi, lo];
        record.extend_from_slice(&handshake);

        let extractor = FingerprintExtractor::new();
        assert!(extractor.extract_ja3(&record).is_some(), "the seed parses");
        crate::fuzz_support::fuzz_bytes(&record, 300_000, |m| {
            let _ = extractor.extract_ja3(m);
            if m.len() > 5 {
                let _ = extractor.extract_ja3_quic(&m[5..]);
            }
        });
    }

    /// The JA4 spec's ALPN rules, including the value that used to panic
    /// (and, with panic = "abort", take the whole proxy down): a first ALPN
    /// starting with a three-byte character was sliced at byte 2.
    #[test]
    fn ja4_alpn_follows_the_spec_and_never_panics() {
        assert_eq!(ja4_alpn(None), "00");
        assert_eq!(ja4_alpn(Some(b"")), "00");
        assert_eq!(ja4_alpn(Some(b"h2")), "h2");
        assert_eq!(ja4_alpn(Some(b"h3")), "h3");
        assert_eq!(ja4_alpn(Some(b"http/1.1")), "h1");
        assert_eq!(ja4_alpn(Some(b"h")), "hh");
        // Non-alphanumeric at either end: first and last hex characters.
        assert_eq!(ja4_alpn(Some(&[0xab, 0xcd])), "ad");
        assert_eq!(ja4_alpn(Some(b"\n\n")), "0a");
        assert_eq!(ja4_alpn(Some("€x".as_bytes())), "e8");
        assert_eq!(ja4_alpn(Some("x€".as_bytes())), "7c");
        assert_eq!(ja4_alpn(Some(&[0xff])), "ff");
    }

    /// A ClientHello whose ALPN list starts with "€x" and a non-UTF-8 name:
    /// parsed end to end without panicking, and the non-UTF-8 name is kept.
    #[test]
    fn hostile_alpn_values_do_not_panic() {
        let extractor = FingerprintExtractor::new();
        for first in ["€x".as_bytes(), &[0xc3, 0x28][..], b"\n\n", &[0u8][..]] {
            let ja4 = extractor
                .calculate_ja4(
                    0x0304,
                    &[0x1301],
                    &[16],
                    &[first.to_vec(), b"h2".to_vec()],
                    &[0x0403],
                    true,
                    Ja4Transport::Tcp,
                )
                .expect("ja4");
            let a = ja4.split('_').next().unwrap();
            assert!(a.is_ascii() && !a.contains(char::is_whitespace), "{ja4:?}");
        }
        let alpn = [&[0u8, 6, 2][..], &[0xc3, 0x28], b"\x02h2"].concat();
        assert_eq!(parse_alpn(&alpn), vec![vec![0xc3, 0x28], b"h2".to_vec()]);
    }

    #[test]
    fn supported_versions_beats_the_legacy_field() {
        // TLS 1.3 clients pin legacy_version at 0x0303 and advertise 1.3 only in
        // supported_versions, so reading the legacy field labelled every modern
        // client "12" and made our JA4s uncomparable with public JA4 data.
        // list length 6, then GREASE, 0x0304, 0x0303.
        let ext = [0x06u8, 0x0a, 0x0a, 0x03, 0x04, 0x03, 0x03];
        assert_eq!(parse_supported_versions(&ext), Some(0x0304));

        // GREASE alone yields nothing to fall back on.
        let grease_only = [0x02u8, 0x1a, 0x1a];
        assert_eq!(parse_supported_versions(&grease_only), None);

        // A truncated extension must not panic or invent a version.
        assert_eq!(parse_supported_versions(&[0x08u8, 0x03]), None);
        assert_eq!(parse_supported_versions(&[]), None);
    }

    #[test]
    fn ja4_marks_quic_transport() {
        // The marker was hardcoded to "t", so a QUIC client produced a JA4
        // claiming TCP — colliding with the same client's TCP fingerprint and
        // losing the one character that tells them apart.
        let extractor = FingerprintExtractor::new();

        let over_tcp = extractor
            .calculate_ja4(
                0x0304,
                &[0x1301, 0x1302],
                &[0, 43],
                &[b"h3".to_vec()],
                &[0x0403],
                true,
                Ja4Transport::Tcp,
            )
            .unwrap();
        let over_quic = extractor
            .calculate_ja4(
                0x0304,
                &[0x1301, 0x1302],
                &[0, 43],
                &[b"h3".to_vec()],
                &[0x0403],
                true,
                Ja4Transport::Quic,
            )
            .unwrap();

        assert!(over_tcp.starts_with('t'));
        assert!(over_quic.starts_with('q'));
        // Identical otherwise: only the transport differs.
        assert_eq!(over_tcp[1..], over_quic[1..]);
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
            Ja4Transport::Tcp,
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
