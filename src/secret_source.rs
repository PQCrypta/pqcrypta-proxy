//! Secrets the configuration names rather than holds.
//!
//! Every secret setting -- `[admin] auth_token`, `hmac_secret` and
//! `metrics_token`, a route's `[routes.security] hmac_secret`,
//! `[advanced_rate_limiting] jwt_secret`, `[security.challenge] secret`,
//! `[acme] eab_hmac_key`, `[moq] publish_key` -- takes its value as a
//! string, or as a table that says where the value is:
//!
//! ```toml
//! [admin]
//! auth_token = { credential = "admin-token" }    # a systemd credential
//! hmac_secret = { file = "/etc/pqcrypta/admin-hmac" }
//! ```
//!
//! A credential is a file of the service's credentials directory,
//! `$CREDENTIALS_DIRECTORY`, which systemd fills from `LoadCredential=` and
//! from `LoadCredentialEncrypted=` -- a credential encrypted at rest with
//! `systemd-creds encrypt`, under the host's TPM2 and/or its host key, and
//! decrypted for the service alone. A command run outside the service
//! (`pqcrypta-proxy --admin`, a script's unit) finds the same names in its own
//! `$CREDENTIALS_DIRECTORY`, in `PQCRYPTA_CREDENTIALS_DIRECTORY`, or -- run as
//! root while the service runs -- in the service's own directory,
//! `/run/credentials/pqcrypta-proxy.service`. A tool that reads one section
//! (`--admin` its `[admin]`, `--moq-token` its `[moq]`) resolves that
//! section's secrets alone (`config::parse_config_section`).
//!
//! The configuration then holds no secret at all, so a copy of it can be
//! tracked as it is, with nothing to redact. A value is read when the
//! configuration is, at start and at every reload; one trailing newline is
//! dropped, and a secret that cannot be read refuses the configuration.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer};

/// Where a secret setting's value is.
#[derive(Deserialize)]
#[serde(untagged)]
enum Source {
    /// The value itself
    Inline(String),
    /// A credential of the service's credentials directory
    Credential(CredentialRef),
    /// A file
    File(FileRef),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRef {
    credential: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRef {
    file: PathBuf,
}

/// The environment variable a command run outside the service names its
/// credentials directory with, where systemd set none.
pub const DIRECTORY_VARIABLE: &str = "PQCRYPTA_CREDENTIALS_DIRECTORY";

/// `deserialize_with` for an optional secret setting.
pub fn optional<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<Source>::deserialize(deserializer)?
        .map(resolve)
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// The running service's credentials directory, which root can read.
pub const SERVICE_DIRECTORY: &str = "/run/credentials/pqcrypta-proxy.service";

/// The credentials directory of this process: systemd's, else the one
/// `PQCRYPTA_CREDENTIALS_DIRECTORY` names, else the running service's.
fn credentials_directory() -> Option<PathBuf> {
    ["CREDENTIALS_DIRECTORY", DIRECTORY_VARIABLE]
        .iter()
        .find_map(|name| std::env::var_os(name).filter(|v| !v.is_empty()))
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(SERVICE_DIRECTORY)).filter(|d| d.is_dir()))
}

/// A credential's name as systemd takes one: no path separator, not `.` or
/// `..`, nothing but letters, digits, `-`, `_` and `.`.
fn valid_credential_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn resolve(source: Source) -> Result<String, String> {
    resolve_in(source, credentials_directory())
}

/// `source`'s value, a credential read from `directory`.
fn resolve_in(source: Source, directory: Option<PathBuf>) -> Result<String, String> {
    match source {
        Source::Inline(value) => Ok(value),
        Source::Credential(CredentialRef { credential }) => {
            if !valid_credential_name(&credential) {
                return Err(format!("{credential:?} is not a credential name"));
            }
            let directory = directory.ok_or_else(|| {
                format!(
                    "credential {credential:?}: no credentials directory (the service's \
                     LoadCredential= or LoadCredentialEncrypted= sets one; outside it, \
                     {DIRECTORY_VARIABLE})"
                )
            })?;
            read(&directory.join(&credential))
                .map_err(|e| format!("credential {credential:?}: {e}"))
        }
        Source::File(FileRef { file }) => read(&file),
    }
}

/// A secret file's value: its content, less one trailing newline.
fn read(path: &Path) -> Result<String, String> {
    let mut value =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Settings {
        #[serde(default, deserialize_with = "optional")]
        secret: Option<String>,
    }

    fn parse(toml_src: &str) -> Result<Option<String>, String> {
        toml::from_str::<Settings>(toml_src)
            .map(|s| s.secret)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_secret_is_written_named_by_file_or_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value");
        std::fs::write(&path, "from-a-file\n").unwrap();
        assert_eq!(
            parse("secret = \"inline\"").unwrap().as_deref(),
            Some("inline")
        );
        assert_eq!(
            parse(&format!(
                "secret = {{ file = {:?} }}",
                path.display().to_string()
            ))
            .unwrap()
            .as_deref(),
            Some("from-a-file")
        );
        assert_eq!(parse("").unwrap(), None);
    }

    #[test]
    fn a_secret_that_cannot_be_read_refuses_the_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        for bad in [
            format!(
                "secret = {{ file = {:?} }}",
                dir.path().join("absent").display().to_string()
            ),
            format!("secret = {{ file = {:?} }}", empty.display().to_string()),
            "secret = { credential = \"../escape\" }".to_string(),
            "secret = { credentail = \"typo\" }".to_string(),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_credential_is_read_from_the_credentials_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("admin-token"), "from-a-credential").unwrap();
        let named = |name: &str| {
            Source::Credential(CredentialRef {
                credential: name.to_string(),
            })
        };
        assert_eq!(
            resolve_in(named("admin-token"), Some(dir.path().to_path_buf())).as_deref(),
            Ok("from-a-credential")
        );
        assert!(resolve_in(named("absent"), Some(dir.path().to_path_buf())).is_err());
        assert!(resolve_in(named("admin-token"), None).is_err());
    }

    #[test]
    fn credential_names_are_systemds() {
        assert!(valid_credential_name("admin-token"));
        assert!(valid_credential_name("proxy.admin_hmac"));
        for bad in ["", ".", "..", "a/b", "a b", "tok\u{e9}n"] {
            assert!(!valid_credential_name(bad), "{bad:?}");
        }
    }
}
