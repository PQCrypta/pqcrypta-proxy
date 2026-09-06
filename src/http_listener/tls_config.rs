//! rustls `ServerConfig` builders and PEM private-key loading for the TCP listeners.

/// Load a private key from a PEM file trying PKCS#8 then PKCS#1 formats.
// L-1: Uses rustls-pki-types PEM API (replaces unmaintained rustls-pemfile)
pub(super) fn load_private_key_from_pem(
    key_path: &str,
) -> Result<rustls::pki_types::PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
    use rustls_pki_types::pem::PemObject;
    use std::fs::File;
    use std::io::BufReader;

    // Try PKCS#8 first (modern format)
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Some(key) = PrivatePkcs8KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok()) {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
        }
    }
    // Try PKCS#1 (legacy RSA)
    {
        let mut reader = BufReader::new(File::open(key_path)?);
        if let Some(key) = PrivatePkcs1KeyDer::pem_reader_iter(&mut reader).find_map(|r| r.ok()) {
            return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
        }
    }
    Err(format!(
        "No private key found in {} (tried PKCS#8 and PKCS#1)",
        key_path
    )
    .into())
}

/// Build rustls server configuration using the per-domain SNI cert resolver.
/// Loads all `{domain}.crt` / `{domain}.key` pairs from the certs directory.
pub(super) fn build_rustls_server_config(
    cert_path: &str,
    _key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    use std::path::Path;

    let certs_dir = Path::new(cert_path)
        .parent()
        .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));

    let resolver = crate::tls::MultiDomainCertResolver::new(certs_dir).map_err(|e| {
        format!(
            "Failed to build SNI cert resolver from {:?}: {}",
            certs_dir, e
        )
    })?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(resolver));

    // Set ALPN protocols for HTTP/2 and HTTP/1.1 negotiation
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.ech = crate::ech_config::load();

    Ok(config)
}

/// Build a rustls ServerConfig that advertises only HTTP/1.1 (no h2).
///
/// Used for hostnames in `http11_only_hosts` so browsers open independent
/// TCP connections per fetch() rather than coalescing onto one HTTP/2 pipe.
pub(super) fn build_rustls_server_config_http11_only(
    cert_path: &str,
    _key_path: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    use std::path::Path;

    let certs_dir = Path::new(cert_path)
        .parent()
        .unwrap_or_else(|| Path::new("/etc/pqcrypta/certs"));

    let resolver = crate::tls::MultiDomainCertResolver::new(certs_dir).map_err(|e| {
        format!(
            "Failed to build SNI cert resolver from {:?}: {}",
            certs_dir, e
        )
    })?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(std::sync::Arc::new(resolver));

    // HTTP/1.1 only — browser cannot coalesce streams onto a single TCP pipe
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.ech = crate::ech_config::load();

    Ok(config)
}

/// Build a rustls ServerConfig using an already-constructed shared SNI resolver.
/// The resolver is shared with the ACME subsystem so hot-reloaded certs are
/// served immediately without restarting the TLS listener.
pub(super) fn build_rustls_server_config_with_resolver(
    resolver: std::sync::Arc<crate::tls::MultiDomainCertResolver>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.ech = crate::ech_config::load();
    Ok(config)
}

/// Like `build_rustls_server_config_with_resolver` but advertises only HTTP/1.1.
pub(super) fn build_rustls_server_config_http11_only_with_resolver(
    resolver: std::sync::Arc<crate::tls::MultiDomainCertResolver>,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.ech = crate::ech_config::load();
    Ok(config)
}
