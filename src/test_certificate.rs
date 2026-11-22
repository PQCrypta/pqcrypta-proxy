//! Self-signed certificates for trying the proxy out
//! (`--test-certificates DIR`).
//!
//! For every host the configuration's routes name, and `localhost`, it writes
//! the files the certificate directory is read in: `{host}.crt` and
//! `{host}.key`, an ECDSA P-256 certificate any TLS client can use, and
//! `{host}.mldsa.crt` and `{host}.mldsa.key`, an ML-DSA-87 (FIPS 204)
//! companion that a client offering ML-DSA is served instead, so both the
//! classical and the post-quantum signature paths can be tried before a CA
//! issues anything. Each is valid for 30 days and names its host alone; no
//! client trusts them, which is the point: they are for testing, and the
//! files are never written over.

use std::path::{Path, PathBuf};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, SignatureAlgorithm,
};

/// How long a test certificate is valid.
const VALIDITY_DAYS: i64 = 30;

/// The hosts the routes of `config` name, lowercased and de-duplicated,
/// with `localhost`.
pub fn hosts(config: &crate::config::ProxyConfig) -> Vec<String> {
    let mut hosts: Vec<String> = config
        .routes
        .iter()
        .filter_map(|r| r.host.as_deref())
        .map(str::to_ascii_lowercase)
        .chain(std::iter::once("localhost".to_string()))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// One certificate and its key, signed by that key, for `host`.
fn self_signed(
    host: &str,
    algorithm: &'static SignatureAlgorithm,
) -> anyhow::Result<(String, String)> {
    let key = KeyPair::generate_for(algorithm)?;
    let mut params = CertificateParams::new(vec![host.to_string()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, host);
    name.push(DnType::OrganizationName, "pqcrypta-proxy test certificate");
    params.distinguished_name = name;
    let now = jiff::Timestamp::now();
    let not_before = now - jiff::SignedDuration::from_hours(1);
    let not_after = now + jiff::SignedDuration::from_hours(24 * VALIDITY_DAYS);
    params.not_before = rcgen::date_time_ymd(1970, 1, 1)
        + std::time::Duration::from_secs(u64::try_from(not_before.as_second()).unwrap_or(0));
    params.not_after = rcgen::date_time_ymd(1970, 1, 1)
        + std::time::Duration::from_secs(u64::try_from(not_after.as_second()).unwrap_or(0));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Write the certificates for `hosts` into `dir`, which must exist,
/// refusing to replace a file already there. The paths written.
pub fn write(dir: &Path, hosts: &[String]) -> anyhow::Result<Vec<PathBuf>> {
    let mut planned = Vec::new();
    for host in hosts {
        let stem = crate::acme::validate_domain_for_path(host)
            .map_err(|e| anyhow::anyhow!("host {host:?}: {e}"))?;
        for (suffix, algorithm) in [
            ("", &rcgen::PKCS_ECDSA_P256_SHA256),
            (crate::tls::POST_QUANTUM_COMPANION, &rcgen::PKCS_ML_DSA_87),
        ] {
            let cert = dir.join(format!("{stem}{suffix}.crt"));
            let key = dir.join(format!("{stem}{suffix}.key"));
            for path in [&cert, &key] {
                if path.exists() {
                    anyhow::bail!(
                        "{} exists; test certificates never replace a file",
                        path.display()
                    );
                }
            }
            planned.push((host.clone(), algorithm, cert, key));
        }
    }
    let mut written = Vec::new();
    for (host, algorithm, cert, key) in planned {
        let (cert_pem, key_pem) = self_signed(&host, algorithm)?;
        crate::staged_file::write_atomic(&key, &key_pem, true)?;
        crate::staged_file::write_atomic(&cert, &cert_pem, false)?;
        written.push(cert);
        written.push(key);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_certificates_load_as_the_certificate_directory_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let written = write(dir.path(), &["test.example".to_string()]).unwrap();
        assert_eq!(written.len(), 4);
        for (cert, key) in [
            ("test.example.crt", "test.example.key"),
            ("test.example.mldsa.crt", "test.example.mldsa.key"),
        ] {
            let pem = std::fs::read_to_string(dir.path().join(cert)).unwrap();
            let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
            let parsed = der.parse_x509().unwrap();
            let sans = parsed.subject_alternative_name().unwrap().unwrap();
            assert!(format!("{:?}", sans.value).contains("test.example"));
            let left = parsed.validity().time_to_expiration().unwrap();
            assert!(left.whole_days() >= VALIDITY_DAYS - 1 && left.whole_days() <= VALIDITY_DAYS);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(dir.path().join(key))
                    .unwrap()
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o600, "{key} is the owner's alone");
            }
        }
        let pq = std::fs::read_to_string(dir.path().join("test.example.mldsa.crt")).unwrap();
        let (_, der) = x509_parser::pem::parse_x509_pem(pq.as_bytes()).unwrap();
        // id-ml-dsa-87, 2.16.840.1.101.3.4.3.19
        assert_eq!(
            der.parse_x509()
                .unwrap()
                .signature_algorithm
                .algorithm
                .to_id_string(),
            "2.16.840.1.101.3.4.3.19"
        );
        // Never written over
        assert!(write(dir.path(), &["test.example".to_string()]).is_err());
    }

    /// The SNI resolver serves both, and reports when each expires.
    #[test]
    fn the_resolver_serves_them_and_reports_their_expiry() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &["served.example".to_string()]).unwrap();
        let resolver = crate::tls::MultiDomainCertResolver::new(dir.path()).unwrap();
        let expiries = resolver.expiries();
        let kinds: Vec<&str> = expiries.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["ml-dsa", "primary"]);
        let now = jiff::Timestamp::now().as_second();
        for e in &expiries {
            assert_eq!(e.domain, "served.example");
            let days = (e.not_after - now) / 86_400;
            assert!(
                (VALIDITY_DAYS - 1..=VALIDITY_DAYS).contains(&days),
                "{days} days"
            );
        }
    }

    #[test]
    fn a_host_that_could_leave_the_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write(dir.path(), &["../evil".to_string()]).is_err());
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
    }
}
