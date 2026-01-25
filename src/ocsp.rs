//! OCSP Stapling Service
//!
//! Provides automated OCSP stapling for TLS certificates:
//! - Fetches OCSP responses from the certificate's OCSP responder
//! - Caches responses and refreshes before expiration
//! - Exposes status via admin API
//! - Integrates with TLS provider for certificate resolver

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustls::pki_types::CertificateDer;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

/// OCSP response status
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum OcspStatus {
    /// OCSP response is valid and certificate is good
    Good,
    /// Certificate has been revoked
    Revoked,
    /// OCSP responder doesn't know about this certificate
    Unknown,
    /// Failed to fetch OCSP response
    FetchError,
    /// No OCSP responder URL found in certificate
    NoResponder,
    /// Not yet fetched
    Pending,
}

/// Cached OCSP response
#[derive(Debug, Clone)]
pub struct CachedOcspResponse {
    /// Raw DER-encoded OCSP response
    pub response: Vec<u8>,
    /// Response status
    pub status: OcspStatus,
    /// When this response was fetched
    pub fetched_at: Instant,
    /// When this response expires (thisUpdate + validity period)
    pub expires_at: Instant,
    /// OCSP responder URL used
    pub responder_url: String,
    /// Next update time from OCSP response
    pub next_update: Option<Instant>,
}

/// OCSP stapling configuration
#[derive(Debug, Clone)]
pub struct OcspConfig {
    /// Enable OCSP stapling
    pub enabled: bool,
    /// Refresh interval before expiration (default: 1 hour before)
    pub refresh_before_expiry: Duration,
    /// Minimum refresh interval (don't fetch more often than this)
    pub min_refresh_interval: Duration,
    /// HTTP timeout for OCSP requests
    pub request_timeout: Duration,
    /// Maximum retries on fetch failure
    pub max_retries: u32,
    /// Retry delay between attempts
    pub retry_delay: Duration,
}

impl Default for OcspConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_before_expiry: Duration::from_secs(3600), // 1 hour before expiry
            min_refresh_interval: Duration::from_secs(300),   // 5 minutes minimum
            request_timeout: Duration::from_secs(10),
            max_retries: 3,
            retry_delay: Duration::from_secs(5),
        }
    }
}

/// OCSP Stapling Service
pub struct OcspService {
    /// Configuration
    config: OcspConfig,
    /// Current cached OCSP response
    cached_response: Arc<RwLock<Option<CachedOcspResponse>>>,
    /// Certificate chain (for extracting OCSP info)
    cert_chain: Arc<RwLock<Vec<CertificateDer<'static>>>>,
    /// Shutdown signal sender
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Service running flag
    running: Arc<RwLock<bool>>,
}

impl OcspService {
    /// Create a new OCSP service
    pub fn new(config: OcspConfig) -> Self {
        Self {
            config,
            cached_response: Arc::new(RwLock::new(None)),
            cert_chain: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: None,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Update certificate chain (called when certs are reloaded)
    pub fn update_certificates(&self, certs: Vec<CertificateDer<'static>>) {
        *self.cert_chain.write() = certs;
        // Clear cached response when certs change
        *self.cached_response.write() = None;
        info!("OCSP: Certificate chain updated, clearing cached response");
    }

    /// Get current OCSP response (for TLS handshake)
    pub fn get_ocsp_response(&self) -> Option<Vec<u8>> {
        let cached = self.cached_response.read();
        cached.as_ref().and_then(|c| {
            if c.status == OcspStatus::Good && c.expires_at > Instant::now() {
                Some(c.response.clone())
            } else {
                None
            }
        })
    }

    /// Get OCSP status for admin API
    pub fn get_status(&self) -> OcspStatusInfo {
        let cached = self.cached_response.read();
        match cached.as_ref() {
            Some(response) => {
                let now = Instant::now();
                let is_valid = response.status == OcspStatus::Good && response.expires_at > now;
                let expires_in = if response.expires_at > now {
                    Some(response.expires_at.duration_since(now))
                } else {
                    None
                };

                OcspStatusInfo {
                    enabled: self.config.enabled,
                    status: response.status,
                    responder_url: Some(response.responder_url.clone()),
                    fetched_at: Some(response.fetched_at.elapsed()),
                    expires_in,
                    is_valid,
                    running: *self.running.read(),
                }
            }
            None => OcspStatusInfo {
                enabled: self.config.enabled,
                status: OcspStatus::Pending,
                responder_url: None,
                fetched_at: None,
                expires_in: None,
                is_valid: false,
                running: *self.running.read(),
            },
        }
    }

    /// Start the OCSP refresh background task
    pub fn start(&mut self) -> anyhow::Result<()> {
        if !self.config.enabled {
            info!("OCSP stapling is disabled");
            return Ok(());
        }

        if *self.running.read() {
            warn!("OCSP service already running");
            return Ok(());
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);
        *self.running.write() = true;

        let config = self.config.clone();
        let cached_response = Arc::clone(&self.cached_response);
        let cert_chain = Arc::clone(&self.cert_chain);
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            info!("OCSP refresh service started");

            // Initial fetch
            if let Err(e) =
                Self::refresh_ocsp_response(&config, &cached_response, &cert_chain).await
            {
                error!("Initial OCSP fetch failed: {}", e);
            }

            loop {
                // Calculate next refresh time
                let refresh_delay = Self::calculate_refresh_delay(&config, &cached_response);

                tokio::select! {
                    _ = tokio::time::sleep(refresh_delay) => {
                        debug!("OCSP refresh triggered");
                        if let Err(e) = Self::refresh_ocsp_response(&config, &cached_response, &cert_chain).await {
                            error!("OCSP refresh failed: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("OCSP service shutting down");
                        break;
                    }
                }
            }

            *running.write() = false;
        });

        Ok(())
    }

    /// Stop the OCSP refresh background task
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Calculate when to next refresh the OCSP response
    fn calculate_refresh_delay(
        config: &OcspConfig,
        cached_response: &Arc<RwLock<Option<CachedOcspResponse>>>,
    ) -> Duration {
        let cached = cached_response.read();
        match cached.as_ref() {
            Some(response) => {
                let now = Instant::now();

                // Use nextUpdate from OCSP response if available
                if let Some(next_update) = response.next_update {
                    // Calculate refresh time (next_update - refresh_before_expiry)
                    if let Some(refresh_at) = next_update.checked_sub(config.refresh_before_expiry)
                    {
                        if refresh_at > now {
                            let delay = refresh_at.duration_since(now);
                            return delay.max(config.min_refresh_interval);
                        }
                    }
                }

                // Otherwise use expires_at
                if let Some(refresh_at) = response
                    .expires_at
                    .checked_sub(config.refresh_before_expiry)
                {
                    if refresh_at > now {
                        let delay = refresh_at.duration_since(now);
                        return delay.max(config.min_refresh_interval);
                    }
                }

                // Response expired or about to expire, refresh soon
                config.min_refresh_interval
            }
            None => {
                // No cached response, fetch immediately
                Duration::from_secs(1)
            }
        }
    }

    /// Refresh OCSP response from the CA
    async fn refresh_ocsp_response(
        config: &OcspConfig,
        cached_response: &Arc<RwLock<Option<CachedOcspResponse>>>,
        cert_chain: &Arc<RwLock<Vec<CertificateDer<'static>>>>,
    ) -> anyhow::Result<()> {
        let certs = cert_chain.read().clone();

        if certs.is_empty() {
            warn!("No certificates loaded, cannot fetch OCSP response");
            return Ok(());
        }

        // Parse the end-entity certificate
        let (_, cert) = X509Certificate::from_der(&certs[0])
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;

        // Find OCSP responder URL from Authority Information Access extension
        let ocsp_url = Self::extract_ocsp_url(&cert)?;
        info!("OCSP responder URL: {}", ocsp_url);

        // Get issuer certificate (second in chain, or self-signed)
        let issuer_der = if certs.len() > 1 {
            &certs[1]
        } else {
            // Self-signed certificate
            &certs[0]
        };

        let (_, issuer) = X509Certificate::from_der(issuer_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse issuer certificate: {:?}", e))?;

        // Build OCSP request
        let ocsp_request = Self::build_ocsp_request(&cert, &issuer)?;

        // Fetch OCSP response with retries
        let mut last_error = None;
        for attempt in 0..config.max_retries {
            if attempt > 0 {
                tokio::time::sleep(config.retry_delay).await;
            }

            match Self::fetch_ocsp_response(&ocsp_url, &ocsp_request, config.request_timeout).await
            {
                Ok((response, status, next_update)) => {
                    let now = Instant::now();

                    // Calculate expiration (default to 7 days if not specified)
                    let expires_at = next_update
                        .map(|d| now + d)
                        .unwrap_or_else(|| now + Duration::from_secs(7 * 24 * 3600));

                    let cached = CachedOcspResponse {
                        response,
                        status,
                        fetched_at: now,
                        expires_at,
                        responder_url: ocsp_url.clone(),
                        next_update: next_update.map(|d| now + d),
                    };

                    *cached_response.write() = Some(cached);

                    info!(
                        "OCSP response fetched successfully (status: {:?}, expires in: {:?})",
                        status,
                        next_update.unwrap_or(Duration::from_secs(7 * 24 * 3600))
                    );

                    return Ok(());
                }
                Err(e) => {
                    warn!("OCSP fetch attempt {} failed: {}", attempt + 1, e);
                    last_error = Some(e);
                }
            }
        }

        // All retries failed, update status
        let mut cached = cached_response.write();
        if let Some(existing) = cached.as_mut() {
            existing.status = OcspStatus::FetchError;
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("OCSP fetch failed")))
    }

    /// Extract OCSP responder URL from certificate AIA extension
    fn extract_ocsp_url(cert: &X509Certificate) -> anyhow::Result<String> {
        // Look for Authority Information Access extension
        for ext in cert.extensions() {
            if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
                for access_desc in aia.accessdescs.iter() {
                    // Check if it's an OCSP access method (OID 1.3.6.1.5.5.7.48.1)
                    if access_desc.access_method.to_id_string() == "1.3.6.1.5.5.7.48.1" {
                        if let GeneralName::URI(uri) = &access_desc.access_location {
                            return Ok((*uri).to_string());
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "No OCSP responder URL found in certificate"
        ))
    }

    /// Build an OCSP request for the certificate
    fn build_ocsp_request(
        cert: &X509Certificate,
        issuer: &X509Certificate,
    ) -> anyhow::Result<Vec<u8>> {
        use sha1::{Digest, Sha1};

        // Hash algorithm OID for SHA-1 (required by OCSP)
        let sha1_oid = &[
            0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00,
        ];

        // Hash the issuer's distinguished name
        let issuer_name_hash = {
            let mut hasher = Sha1::new();
            hasher.update(issuer.subject().as_raw());
            hasher.finalize()
        };

        // Hash the issuer's public key
        let issuer_key_hash = {
            let mut hasher = Sha1::new();
            hasher.update(issuer.public_key().raw);
            hasher.finalize()
        };

        // Get serial number
        let serial = cert.serial.to_bytes_be();

        // Build CertID structure
        let mut cert_id = Vec::new();
        // hashAlgorithm
        cert_id.extend_from_slice(sha1_oid);
        // issuerNameHash (OCTET STRING)
        cert_id.push(0x04);
        cert_id.push(issuer_name_hash.len() as u8);
        cert_id.extend_from_slice(&issuer_name_hash);
        // issuerKeyHash (OCTET STRING)
        cert_id.push(0x04);
        cert_id.push(issuer_key_hash.len() as u8);
        cert_id.extend_from_slice(&issuer_key_hash);
        // serialNumber (INTEGER)
        cert_id.push(0x02);
        cert_id.push(serial.len() as u8);
        cert_id.extend_from_slice(&serial);

        // Wrap CertID in SEQUENCE
        let cert_id_seq = Self::wrap_sequence(&cert_id);

        // Build Request structure
        let request = Self::wrap_sequence(&cert_id_seq);

        // Build requestList (SEQUENCE OF Request)
        let request_list = Self::wrap_sequence(&request);

        // Build TBSRequest
        let tbs_request = Self::wrap_sequence(&request_list);

        // Build OCSPRequest
        let ocsp_request = Self::wrap_sequence(&tbs_request);

        Ok(ocsp_request)
    }

    /// Wrap data in ASN.1 SEQUENCE
    fn wrap_sequence(data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE tag

        // Length encoding
        if data.len() < 128 {
            result.push(data.len() as u8);
        } else if data.len() < 256 {
            result.push(0x81);
            result.push(data.len() as u8);
        } else {
            result.push(0x82);
            result.push((data.len() >> 8) as u8);
            result.push(data.len() as u8);
        }

        result.extend_from_slice(data);
        result
    }

    /// Fetch OCSP response from the responder
    async fn fetch_ocsp_response(
        url: &str,
        request: &[u8],
        timeout: Duration,
    ) -> anyhow::Result<(Vec<u8>, OcspStatus, Option<Duration>)> {
        let client = reqwest::Client::builder().timeout(timeout).build()?;

        let response = client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .body(request.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "OCSP responder returned HTTP {}",
                response.status()
            ));
        }

        let content_type = response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !content_type.contains("application/ocsp-response") {
            warn!("Unexpected OCSP response content type: {}", content_type);
        }

        let response_bytes = response.bytes().await?.to_vec();

        // Parse OCSP response to extract status
        let (status, next_update) = Self::parse_ocsp_response(&response_bytes)?;

        Ok((response_bytes, status, next_update))
    }

    /// Parse OCSP response to extract certificate status
    fn parse_ocsp_response(response: &[u8]) -> anyhow::Result<(OcspStatus, Option<Duration>)> {
        // Minimal OCSP response parsing
        // Full parsing would require a dedicated OCSP library

        if response.len() < 10 {
            return Err(anyhow::anyhow!("OCSP response too short"));
        }

        // Check for OCSPResponseStatus (first byte after SEQUENCE tag)
        // The response status is an ENUMERATED value at offset 4 typically
        // 0 = successful, 1 = malformedRequest, 2 = internalError, etc.

        // Look for responseStatus in the response
        // This is a simplified check - the response structure is:
        // OCSPResponse ::= SEQUENCE {
        //    responseStatus OCSPResponseStatus,  -- ENUMERATED
        //    responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
        // }

        let mut offset = 0;

        // Skip outer SEQUENCE
        if response[offset] != 0x30 {
            return Err(anyhow::anyhow!("Invalid OCSP response: expected SEQUENCE"));
        }
        offset += 1;

        // Skip length
        if response[offset] & 0x80 != 0 {
            let len_bytes = (response[offset] & 0x7F) as usize;
            offset += 1 + len_bytes;
        } else {
            offset += 1;
        }

        // Check responseStatus (ENUMERATED)
        if offset >= response.len() || response[offset] != 0x0A {
            return Err(anyhow::anyhow!(
                "Invalid OCSP response: expected ENUMERATED"
            ));
        }
        offset += 1;

        // Length should be 1
        if offset >= response.len() || response[offset] != 0x01 {
            return Err(anyhow::anyhow!("Invalid OCSP response status length"));
        }
        offset += 1;

        // Response status value
        if offset >= response.len() {
            return Err(anyhow::anyhow!("OCSP response truncated"));
        }
        let response_status = response[offset];

        if response_status != 0 {
            // Non-successful response
            return Ok((OcspStatus::Unknown, None));
        }

        // For successful responses, we need to parse deeper to get cert status
        // This is simplified - we assume "good" if responseStatus is 0
        // A full implementation would parse the SingleResponse to check certStatus

        // Look for certStatus in the response bytes
        // certStatus is either:
        //   good        [0] IMPLICIT NULL,
        //   revoked     [1] IMPLICIT RevokedInfo,
        //   unknown     [2] IMPLICIT UnknownInfo

        // Search for context-specific tags [0], [1], or [2] in the response
        for &byte in &response[offset..response.len().saturating_sub(2)] {
            match byte {
                0x80 => {
                    // [0] IMPLICIT NULL = good
                    // Default validity period: 7 days
                    return Ok((OcspStatus::Good, Some(Duration::from_secs(7 * 24 * 3600))));
                }
                0x81 | 0xA1 => {
                    // [1] IMPLICIT or EXPLICIT RevokedInfo = revoked
                    return Ok((OcspStatus::Revoked, None));
                }
                0x82 | 0xA2 => {
                    // [2] IMPLICIT or EXPLICIT UnknownInfo = unknown
                    return Ok((OcspStatus::Unknown, None));
                }
                _ => continue,
            }
        }

        // If we can't find certStatus but responseStatus was 0, assume good
        // This is lenient but avoids rejecting valid responses we can't fully parse
        warn!("Could not parse certStatus from OCSP response, assuming good");
        Ok((OcspStatus::Good, Some(Duration::from_secs(7 * 24 * 3600))))
    }

    /// Force an immediate OCSP refresh
    pub async fn force_refresh(&self) -> anyhow::Result<()> {
        Self::refresh_ocsp_response(&self.config, &self.cached_response, &self.cert_chain).await
    }
}

/// OCSP status information for admin API
#[derive(Debug, Clone, serde::Serialize)]
pub struct OcspStatusInfo {
    pub enabled: bool,
    pub status: OcspStatus,
    pub responder_url: Option<String>,
    #[serde(serialize_with = "serialize_duration_option")]
    pub fetched_at: Option<Duration>,
    #[serde(serialize_with = "serialize_duration_option")]
    pub expires_in: Option<Duration>,
    pub is_valid: bool,
    pub running: bool,
}

fn serialize_duration_option<S>(
    duration: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match duration {
        Some(d) => serializer.serialize_str(&format!("{}s", d.as_secs())),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_config_defaults() {
        let config = OcspConfig::default();
        assert!(config.enabled);
        assert_eq!(config.refresh_before_expiry, Duration::from_secs(3600));
        assert_eq!(config.min_refresh_interval, Duration::from_secs(300));
        assert_eq!(config.request_timeout, Duration::from_secs(10));
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_wrap_sequence_short() {
        let data = vec![0x01, 0x02, 0x03];
        let wrapped = OcspService::wrap_sequence(&data);
        assert_eq!(wrapped, vec![0x30, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_wrap_sequence_long() {
        let data = vec![0u8; 200];
        let wrapped = OcspService::wrap_sequence(&data);
        assert_eq!(wrapped[0], 0x30);
        assert_eq!(wrapped[1], 0x81); // Long form, 1 byte
        assert_eq!(wrapped[2], 200);
        assert_eq!(wrapped.len(), 203);
    }

    #[test]
    fn test_ocsp_status_info_serialization() {
        let info = OcspStatusInfo {
            enabled: true,
            status: OcspStatus::Good,
            responder_url: Some("http://ocsp.example.com".to_string()),
            fetched_at: Some(Duration::from_secs(60)),
            expires_in: Some(Duration::from_secs(3600)),
            is_valid: true,
            running: true,
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"is_valid\":true"));
    }
}
