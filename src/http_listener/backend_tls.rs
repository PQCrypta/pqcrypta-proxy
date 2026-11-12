//! TLS connector construction for re-encrypt mode backend connections.

use std::sync::Arc;

use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use super::tls_config::load_private_key_from_pem;

use crate::config::BackendConfig;

/// A TLS connector for `backend` over TCP, offering the application protocol
/// its type speaks (`h2` for an HTTP/2 backend, else `http/1.1`).
pub fn create_backend_tls_connector(
    backend: &BackendConfig,
) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    let alpn: &[u8] = if backend.backend_type == crate::config::BackendType::Http2 {
        b"h2"
    } else {
        b"http/1.1"
    };
    Ok(TlsConnector::from(Arc::new(backend_client_config(
        backend,
        vec![alpn.to_vec()],
    )?)))
}

/// The TLS client configuration for `backend`.
///
/// The native roots plus its `tls_cert` (a CA, or the backend's own
/// certificate pinned), its client certificate when it has one, and `alpn`.
/// The server's certificate is always verified.
pub fn backend_client_config(
    backend: &BackendConfig,
    alpn: Vec<Vec<u8>>,
) -> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
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

        // Presenting a client certificate does not stop us verifying the
        // server's: the same roots as the non-mTLS case, native plus the
        // configured CA. This used an empty store, so no server certificate
        // could ever verify and mTLS worked only with verification off.
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    config.alpn_protocols = alpn;
    Ok(config)
}
