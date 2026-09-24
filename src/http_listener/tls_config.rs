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

/// ALPN for a TCP listener: HTTP/2 and HTTP/1.1, or HTTP/1.1 alone for the
/// hosts in `http11_only_hosts`, so a browser opens independent connections per
/// `fetch()` rather than coalescing them onto one HTTP/2 pipe.
pub(super) const ALPN_H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
pub(super) const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// A per-domain SNI resolver over the directory `cert_path` sits in, loading
/// every `{domain}.crt` / `{domain}.key` pair, for a listener that is not given
/// the shared one.
pub(super) fn private_resolver(
    cert_path: &str,
) -> Result<
    std::sync::Arc<crate::tls::MultiDomainCertResolver>,
    Box<dyn std::error::Error + Send + Sync>,
> {
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
    Ok(std::sync::Arc::new(resolver))
}

/// A rustls `ServerConfig` for a TCP listener.
///
/// Groups, protocol versions, client authentication and session tickets come
/// from `policy`, which the QUIC listener builds from too. These listeners used
/// `ServerConfig::builder()` -- rustls's crate defaults -- so `pqc.enabled`,
/// `tls.min_version`, `tls.require_client_cert` and `tls.pqc_session_tickets`
/// each had no effect here while taking effect on HTTP/3.
pub(super) fn build_rustls_server_config(
    policy: &crate::tls::ServerTlsPolicy,
    resolver: std::sync::Arc<crate::tls::MultiDomainCertResolver>,
    alpn: &[&[u8]],
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut config = policy.builder()?.with_cert_resolver(resolver);
    policy.apply_tickets(&mut config)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.ech = crate::ech_config::load();
    crate::cert_compression::apply(&mut config);
    Ok(config)
}
