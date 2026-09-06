//! TLS connector construction for re-encrypt mode backend connections.

use std::sync::Arc;

use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use super::tls_config::load_private_key_from_pem;

use crate::config::BackendConfig;

/// Create TLS connector for re-encrypt mode with optional client cert
/// Used for TLS backend connections when tls_mode is set to reencrypt
pub fn create_backend_tls_connector(
    backend: &BackendConfig,
) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::CertificateDer;
    use rustls::ClientConfig;
    use std::fs::File;
    use std::io::BufReader;

    let mut root_store = rustls::RootCertStore::empty();

    // Add native root certificates
    let native_certs = rustls_native_certs::load_native_certs();
    let mut added = 0;
    let mut failed = 0;
    for cert in native_certs.certs {
        match root_store.add(cert) {
            Ok(()) => added += 1,
            Err(e) => {
                debug!("Failed to add native root certificate: {}", e);
                failed += 1;
            }
        }
    }
    if failed > 0 {
        debug!(
            "Loaded {} native root certificates ({} failed - likely duplicates)",
            added, failed
        );
    }

    // Add custom CA cert if provided
    if let Some(ref ca_path) = backend.tls_cert {
        let ca_file = File::open(ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let mut ca_certs = Vec::new();
        let mut parse_errors = 0;
        // L-1: Use rustls-pki-types PEM API instead of unmaintained rustls-pemfile
        {
            use rustls_pki_types::pem::PemObject;
            for cert_result in CertificateDer::pem_reader_iter(&mut ca_reader) {
                match cert_result {
                    Ok(cert) => ca_certs.push(cert),
                    Err(e) => {
                        warn!(
                            "Failed to parse CA certificate from {}: {}",
                            ca_path.display(),
                            e
                        );
                        parse_errors += 1;
                    }
                }
            }
        }
        if parse_errors > 0 {
            warn!(
                "Loaded {} CA certificates from {} ({} failed to parse)",
                ca_certs.len(),
                ca_path.display(),
                parse_errors
            );
        }
        for cert in ca_certs {
            root_store.add(cert)?;
        }
    }

    // Build TLS config - use mTLS if client certs provided, otherwise no client auth
    let mut config = if let (Some(cert_path), Some(key_path)) =
        (&backend.tls_client_cert, &backend.tls_client_key)
    {
        let cert_file = File::open(cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let mut certs: Vec<CertificateDer<'static>> = Vec::new();
        let mut parse_errors = 0;
        // L-1: Use rustls-pki-types PEM API instead of unmaintained rustls-pemfile
        {
            use rustls_pki_types::pem::PemObject;
            for cert_result in CertificateDer::pem_reader_iter(&mut cert_reader) {
                match cert_result {
                    Ok(cert) => certs.push(cert),
                    Err(e) => {
                        warn!(
                            "Failed to parse client certificate from {}: {}",
                            cert_path.display(),
                            e
                        );
                        parse_errors += 1;
                    }
                }
            }
        }
        if parse_errors > 0 {
            warn!(
                "Loaded {} client certificates from {} ({} failed to parse)",
                certs.len(),
                cert_path.display(),
                parse_errors
            );
        }

        let key = load_private_key_from_pem(
            key_path
                .to_str()
                .ok_or("mTLS key path is not valid UTF-8")?,
        )?;

        // Note: Using empty root store for mTLS (preserving original behavior)
        ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_client_auth_cert(certs, key)?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // Optionally skip verification (dangerous!)
    if backend.tls_skip_verify {
        warn!(
            "⚠️ TLS verification disabled for backend {} - THIS IS DANGEROUS!",
            backend.name
        );
        config
            .dangerous()
            // Safe: gated by config validation (config.rs SEC-001 guard) which
            // rejects tls_skip_verify=true in production (ACME enabled or
            // PQCRYPTA_ENV=production). Only reachable in explicit dev deployments.
            .set_certificate_verifier(Arc::new(NoVerifier)); // nosemgrep: rust.lang.security.rustls-dangerous.rustls-dangerous
    }

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Dangerous: No-verification TLS verifier for backends with tls_skip_verify
#[derive(Debug)]
pub(super) struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
