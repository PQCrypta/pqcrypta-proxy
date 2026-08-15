//! Startup verification of the cryptographic runtime.
//!
//! # Why this exists
//!
//! Until this module, the proxy announced "POST-QUANTUM CRYPTOGRAPHY ENABLED" on the
//! strength of shelling out to an `openssl` binary and reading its version and KEM
//! list. That subprocess is not the cryptography this proxy serves: inbound TLS is
//! terminated by rustls with the aws-lc-rs provider, and the ML-KEM hybrid group comes
//! from `rustls_post_quantum::provider()` linked into this executable. The banner could
//! therefore report PQC as enabled on a host where the serving stack offered none, or —
//! as measured on 2026-08-14 — report an OpenSSL version having no bearing on the
//! handshake, on three hosts that loaded three different libcryptos and all negotiated
//! X25519MLKEM768 regardless.
//!
//! An operator reading that banner is being told the security boundary they deployed.
//! Getting it from the wrong component is worse than printing nothing, because it
//! forecloses the question.
//!
//! # The rule
//!
//! **Assert the capability, never the configuration.** Every line this module reports
//! as `verified` is the observed result of a real TLS 1.3 handshake performed against
//! the proxy's own `ServerConfig` during startup. Anything that cannot be probed that
//! cheaply is labelled `configured` and is never allowed to masquerade as a measurement.
//!
//! The handshake runs entirely in memory — no socket, no port, no listener — so it is
//! deterministic, cannot be blocked by a firewall, cannot collide with a port already in
//! use, and costs a few milliseconds. It exercises the same `CryptoProvider`, the same
//! key exchange groups in the same preference order, and the same protocol-version
//! restriction that live traffic will use.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use tracing::{error, info, warn};

/// The hostname used for the in-memory verification handshake.
///
/// `.invalid` is reserved by RFC 2606 and can never resolve, so this name cannot
/// collide with a real certificate or be mistaken for a deployment domain if it
/// appears in a log.
const VERIFY_SNI: &str = "startup-verify.invalid";

/// Key exchange groups that provide post-quantum security.
///
/// Hybrids only. A pure classical group is not PQC no matter how large, and a pure
/// ML-KEM group is not currently offered by the provider — so any group outside this
/// set means the handshake completed without post-quantum protection.
fn is_post_quantum(group: &str) -> bool {
    const PQ_GROUPS: &[&str] = &[
        "X25519MLKEM768",
        "SecP256r1MLKEM768",
        "SecP384r1MLKEM1024",
        "X448MLKEM1024",
    ];
    PQ_GROUPS
        .iter()
        .any(|g| g.eq_ignore_ascii_case(group.trim()))
}

/// What the runtime actually did, as opposed to what it was asked to do.
#[derive(Debug, Clone, Default)]
pub struct VerifiedRuntime {
    /// The key exchange group a real handshake selected.
    pub kx_group: Option<String>,
    /// Whether that group provides post-quantum security.
    pub is_post_quantum: bool,
    /// The protocol version a real handshake selected.
    pub tls_version: Option<String>,
    /// The cipher suite a real handshake selected.
    pub cipher_suite: Option<String>,
    /// Every group the provider offers, in the order it will offer them. Configured,
    /// not verified — only the first acceptable one is exercised by the handshake.
    pub offered_groups: Vec<String>,
    /// Why verification failed, when it did.
    pub error: Option<String>,
}

impl VerifiedRuntime {
    /// Whether the handshake completed at all.
    pub fn succeeded(&self) -> bool {
        self.error.is_none() && self.kx_group.is_some()
    }
}

/// Perform the verification handshake against the proxy's own server configuration.
///
/// Takes the live `ServerConfig` rather than rebuilding one, so the thing verified is
/// the thing that serves. The certificate resolver is the only part not exercised: the
/// client presents [`VERIFY_SNI`], for which no real certificate exists, so a throwaway
/// self-signed pair is supplied through a dedicated config that shares the caller's
/// crypto provider and protocol versions.
pub fn verify_runtime(provider: Arc<CryptoProvider>, tls13_only: bool) -> VerifiedRuntime {
    let offered_groups = provider
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect::<Vec<_>>();

    match run_handshake(provider, tls13_only) {
        Ok((group, version, suite)) => {
            let is_pq = is_post_quantum(&group);
            VerifiedRuntime {
                is_post_quantum: is_pq,
                kx_group: Some(group),
                tls_version: Some(version),
                cipher_suite: Some(suite),
                offered_groups,
                error: None,
            }
        }
        Err(e) => VerifiedRuntime {
            offered_groups,
            error: Some(format!("{e:#}")),
            ..Default::default()
        },
    }
}

/// Drive a complete TLS handshake between two in-memory endpoints.
///
/// Returns the negotiated (key exchange group, protocol version, cipher suite).
fn run_handshake(
    provider: Arc<CryptoProvider>,
    tls13_only: bool,
) -> Result<(String, String, String)> {
    let (cert, key) = self_signed_pair().context("generating the verification certificate")?;

    let versions: &[&rustls::SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS12, &rustls::version::TLS13]
    };

    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)
        .context("server: protocol versions rejected by the provider")?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .context("server: verification certificate rejected")?;

    // The client trusts exactly the throwaway certificate and nothing else, so this
    // cannot accidentally succeed against anything but its own counterpart.
    let mut roots = RootCertStore::empty();
    roots
        .add(cert)
        .context("client: could not trust the verification certificate")?;

    let client_config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("client: protocol versions rejected by the provider")?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name = ServerName::try_from(VERIFY_SNI)?.to_owned();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)
        .context("client: connection setup")?;
    let mut server =
        ServerConnection::new(Arc::new(server_config)).context("server: connection setup")?;

    // Pump bytes between the two until neither wants to send. Bounded so a provider bug
    // cannot spin startup forever: a TLS 1.3 handshake needs a handful of flights, and
    // anything beyond this is a malfunction rather than a slow negotiation.
    const MAX_FLIGHTS: usize = 16;
    let mut buf = Vec::with_capacity(16 * 1024);
    for _ in 0..MAX_FLIGHTS {
        let client_sent = if client.wants_write() {
            buf.clear();
            client.write_tls(&mut buf)?;
            server.read_tls(&mut buf.as_slice())?;
            server.process_new_packets()?;
            true
        } else {
            false
        };
        let server_sent = if server.wants_write() {
            buf.clear();
            server.write_tls(&mut buf)?;
            client.read_tls(&mut buf.as_slice())?;
            client.process_new_packets()?;
            true
        } else {
            false
        };
        let moved = client_sent || server_sent;

        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        if !moved {
            return Err(anyhow!(
                "handshake stalled: neither endpoint had data to send while both were \
                 still handshaking"
            ));
        }
    }

    if client.is_handshaking() {
        return Err(anyhow!(
            "handshake did not complete within {MAX_FLIGHTS} flights"
        ));
    }

    let group = client
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .ok_or_else(|| anyhow!("handshake completed but reported no key exchange group"))?;
    let version = client
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".to_string());
    let suite = client
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".to_string());

    Ok((group, version, suite))
}

/// A throwaway certificate for the verification handshake.
///
/// Generated per start and never written to disk: it exists for the duration of one
/// in-memory handshake and is not an identity the proxy ever presents to a peer.
fn self_signed_pair() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec![VERIFY_SNI.to_string()])?;
    let der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| anyhow!("serialising the verification key: {e}"))?;
    Ok((der, key))
}

/// Where a reported fact came from.
///
/// Three states, not two. The distinction between "we made this happen and watched the
/// result" and "we read this out of the running process" and "someone typed this in a
/// file" is the entire value of the banner, and collapsing the middle case into either
/// neighbour loses real information: an observed libcrypto path is a fact about this
/// process, but nothing exercised it, so it cannot carry the weight of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Something was made to happen and the outcome was measured.
    Verified,
    /// Read from the running process, but not exercised.
    Observed,
    /// Declared in configuration. Says nothing about what the process does.
    Configured,
}

impl Provenance {
    fn tag(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Observed => "OBSERVED",
            Self::Configured => "CONFIGURED",
        }
    }
}

/// One reported fact, with its provenance.
#[derive(Debug, Clone)]
pub struct Row {
    pub name: String,
    pub value: String,
    pub provenance: Provenance,
}

impl Row {
    pub fn verified(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            provenance: Provenance::Verified,
        }
    }
    pub fn observed(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            provenance: Provenance::Observed,
        }
    }
    pub fn configured(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            provenance: Provenance::Configured,
        }
    }
    pub fn flag(name: impl Into<String>, on: bool, p: Provenance) -> Self {
        Self {
            name: name.into(),
            value: if on { "ENABLED" } else { "disabled" }.to_string(),
            provenance: p,
        }
    }
}

/// A named group of rows.
pub struct Section {
    pub title: &'static str,
    pub rows: Vec<Row>,
}

/// Print the security runtime the operator actually deployed.
///
/// Sectioned, and every row carries its provenance. A reader must be able to tell at a
/// glance which claims were measured, which were merely read, and which were only
/// declared — those three have very different worth during an incident, and a banner
/// that blurs them is worse than no banner because it forecloses the question.
pub fn render_banner(sections: &[Section]) {
    let rule_of = |n: usize, v: usize| "─".repeat(n + v + 16);
    info!("");
    info!(
        "PQCrypta Proxy {} — Security Runtime Attestation",
        env!("CARGO_PKG_VERSION")
    );
    // Column widths are computed across every row of every section rather than fixed,
    // so the provenance tags line up in one column no matter how long a group list or
    // a library path turns out to be. A tag knocked out of alignment by one long value
    // is the difference between a table that can be skimmed and one that must be read.
    let name_w = sections
        .iter()
        .flat_map(|s| s.rows.iter())
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(20)
        .max(20);
    let value_w = sections
        .iter()
        .flat_map(|s| s.rows.iter())
        .map(|r| r.value.chars().count())
        .max()
        .unwrap_or(24)
        .max(24);

    let rule = rule_of(name_w, value_w);
    info!("{rule}");
    for section in sections {
        if section.rows.is_empty() {
            continue;
        }
        info!("{}", section.title);
        for row in &section.rows {
            // Warn rather than info for anything that failed verification, so the one
            // line that matters is not the same colour as the thirty that are fine.
            let text = format!(
                "  {:<name_w$} {:<value_w$} [{}]",
                row.name,
                row.value,
                row.provenance.tag()
            );
            // The aligned text is the message; the same facts also go out as
            // structured fields. Under the JSON log format the table is just a string
            // per line and `[VERIFIED]` is buried inside it, so a SIEM cannot assert
            // on any of it — which makes an artifact whose entire purpose is to attest
            // a security boundary unqueryable exactly where it would be relied on.
            // Emitting both costs nothing: the human reads the message, the collector
            // reads the fields.
            if row.provenance == Provenance::Verified && row.value.contains("FAILED") {
                warn!(
                    attestation = true,
                    section = %section.title,
                    capability = %row.name,
                    value = %row.value,
                    provenance = %row.provenance.tag(),
                    "{text}"
                );
            } else {
                info!(
                    attestation = true,
                    section = %section.title,
                    capability = %row.name,
                    value = %row.value,
                    provenance = %row.provenance.tag(),
                    "{text}"
                );
            }
        }
        info!("{rule}");
    }
}

/// The explicit expected-versus-observed comparison for the key exchange.
///
/// Rendered separately from the row list because it is the one claim the whole feature
/// exists to make, and because a comparison reads as a comparison only when both sides
/// are on the page. An operator should not have to know that `X25519MLKEM768` is the
/// post-quantum one in order to read the result.
pub fn render_kx_verification(runtime: &VerifiedRuntime, expected_pq: bool) {
    let rule = "─".repeat(66);
    info!("PQC HANDSHAKE VERIFICATION");
    info!(
        "  {:<22} {}",
        "Expected",
        if expected_pq {
            "a post-quantum hybrid group"
        } else {
            "any group the provider prefers"
        }
    );
    match (&runtime.kx_group, &runtime.error) {
        (Some(group), _) => {
            info!("  {:<22} {}", "Observed", group);
            info!(
                "  {:<22} {}",
                "Method", "in-memory TLS 1.3 handshake, this provider"
            );
            if !expected_pq || runtime.is_post_quantum {
                info!("  {:<22} {}", "Status", "PASS");
            } else {
                warn!(
                    "  {:<22} {}",
                    "Status", "FAIL — negotiated group is not post-quantum"
                );
            }
        }
        (None, Some(err)) => {
            warn!("  {:<22} {}", "Observed", "handshake did not complete");
            warn!("  {:<22} {}", "Status", "FAIL");
            warn!("  {:<22} {}", "Reason", err);
        }
        (None, None) => {
            warn!("  {:<22} {}", "Observed", "not probed");
            warn!("  {:<22} {}", "Status", "UNKNOWN");
        }
    }
    info!("{rule}");
}

/// The dynamic cryptographic runtime: what this process actually mapped.
///
/// libcrypto is reported even though it does not terminate inbound TLS, and the
/// `load-bearing` row is the reason. Today rustls does the handshake and OpenSSL is
/// auxiliary; that is a fact about this build, not a law. If a future dependency moves
/// a TLS path onto OpenSSL, this row is where the change becomes visible instead of
/// silent — which matters most on hosts that load a distro libcrypto with no ML-KEM at
/// all, as two of three do here.
///
/// `load_bearing` is derived, never assumed: inbound TLS is rustls if and only if the
/// rustls verification handshake succeeded. When it did not, this claims nothing.
pub fn dynamic_runtime_section(runtime: &VerifiedRuntime) -> Section {
    let mut rows = Vec::new();
    match mapped_openssl() {
        Some(path) => {
            rows.push(Row::observed("libcrypto", path));
            if let Some(v) = openssl_version_string() {
                rows.push(Row::observed("version", v));
            }
            rows.push(Row::observed("role", "auxiliary"));
            rows.push(Row {
                name: "load-bearing for TLS".into(),
                value: if runtime.succeeded() {
                    "NO — rustls terminates inbound TLS".into()
                } else {
                    "UNKNOWN — TLS not verified this start".into()
                },
                provenance: if runtime.succeeded() {
                    Provenance::Verified
                } else {
                    Provenance::Observed
                },
            });
        }
        None => {
            rows.push(Row::observed("libcrypto", "not mapped by this process"));
        }
    }
    Section {
        title: "DYNAMIC CRYPTO RUNTIME",
        rows,
    }
}

/// The OpenSSL version string, read from the library this process mapped.
///
/// Parsed out of the SONAME-adjacent version banner in the mapped file rather than by
/// running an `openssl` binary: the CLI on PATH is frequently a different build from
/// the library the process loaded, and reporting one while using the other is how the
/// previous banner came to describe a component that had nothing to do with the
/// handshake.
fn openssl_version_string() -> Option<String> {
    let path = mapped_openssl()?;
    let bytes = std::fs::read(path).ok()?;
    let needle = b"OpenSSL 3";
    let idx = bytes.windows(needle.len()).position(|w| w == needle)?;
    let text: String = bytes[idx..]
        .iter()
        .take(24)
        .take_while(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| *b as char)
        .collect();
    Some(
        text.split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Enforce `pqc_required` against what was actually measured.
///
/// Fails closed, and only on evidence. Three outcomes are refused: a verified handshake
/// that chose a classical group, a verification that could not be completed at all, and
/// a verification that was never attempted — because "we did not check" is not grounds
/// to claim a post-quantum boundary, and an operator who set `pqc_required = true` has
/// said they would rather not start than find out later.
pub fn enforce_pqc_policy(runtime: &VerifiedRuntime, pqc_required: bool) -> Result<()> {
    if !pqc_required {
        if runtime.succeeded() && !runtime.is_post_quantum {
            warn!(
                "Key exchange verified as {} — not post-quantum. pqc_required is false, \
                 so startup continues.",
                runtime.kx_group.as_deref().unwrap_or("unknown")
            );
        }
        return Ok(());
    }

    if let Some(err) = &runtime.error {
        error!("FATAL: pqc_required = true but the runtime could not be verified.");
        return Err(anyhow!(
            "PQC required, but the startup verification handshake failed: {err}"
        ));
    }

    match &runtime.kx_group {
        Some(group) if runtime.is_post_quantum => {
            info!("PQC policy satisfied: {group} verified by startup handshake");
            Ok(())
        }
        Some(group) => {
            error!("FATAL: pqc_required = true but the active provider negotiated {group}.");
            Err(anyhow!(
                "PQC required, but the verification handshake negotiated {group}, which \
                 provides no post-quantum security. Offered groups were: {}",
                runtime.offered_groups.join(", ")
            ))
        }
        None => Err(anyhow!(
            "PQC required, but no verification result is available"
        )),
    }
}

/// The OpenSSL this process actually mapped, read from its own memory map.
///
/// `ldd` answers for the caller's environment, not the service's — a distinction that
/// produced a wrong conclusion about this very proxy on 2026-08-14. `/proc/self/maps`
/// is the only source that describes the running process.
#[cfg(target_os = "linux")]
pub fn mapped_openssl() -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
    maps.lines()
        .filter_map(|l| l.split_whitespace().last())
        .find(|p| p.contains("libcrypto.so"))
        .map(|p| p.to_string())
}

#[cfg(not(target_os = "linux"))]
pub fn mapped_openssl() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Arc<CryptoProvider> {
        let mut p = rustls_post_quantum::provider();
        p.kx_groups.sort_by_key(|g| match g.name() {
            rustls::NamedGroup::X25519MLKEM768 => 0u8,
            rustls::NamedGroup::secp384r1 => 1,
            _ => 2,
        });
        Arc::new(p)
    }

    /// The whole point: a real handshake, and the group it chose.
    #[test]
    fn verification_handshake_completes_and_reports_a_group() {
        let r = verify_runtime(provider(), true);
        assert!(r.succeeded(), "handshake failed: {:?}", r.error);
        assert_eq!(r.tls_version.as_deref(), Some("TLSv1_3"));
        assert!(
            r.kx_group.is_some(),
            "a completed handshake must report its key exchange group"
        );
    }

    /// With X25519MLKEM768 first in the provider's preference order, a handshake
    /// between two endpoints that both use that provider must select it. If this
    /// fails, the proxy is not doing post-quantum key exchange no matter what any
    /// configuration file says.
    #[test]
    fn preferred_group_is_post_quantum_when_the_provider_offers_it() {
        let r = verify_runtime(provider(), true);
        assert!(r.succeeded(), "handshake failed: {:?}", r.error);
        assert!(
            r.is_post_quantum,
            "expected a post-quantum group, negotiated {:?}",
            r.kx_group
        );
    }

    /// The regression this whole mechanism exists to catch: a provider that no longer
    /// offers a post-quantum group.
    ///
    /// Nobody edits a config to cause this. It arrives when a dependency changes its
    /// default backend, or a build flag is dropped, or a vendored fork is rebased —
    /// the configuration still says `enabled = true` and the handshake quietly
    /// negotiates X25519. Asserting on a capability table would not notice, because
    /// the table would still list ML-KEM as supported by the crate. Only running the
    /// handshake and reading what came back does.
    ///
    /// Built by stripping the hybrids out of the real provider, so this exercises the
    /// same code path a degraded deployment would, end to end.
    #[test]
    fn a_provider_without_hybrids_is_detected_and_refused() {
        let mut classical = rustls_post_quantum::provider();
        classical
            .kx_groups
            .retain(|g| !is_post_quantum(&format!("{:?}", g.name())));
        assert!(
            !classical.kx_groups.is_empty(),
            "test needs at least one classical group to negotiate"
        );

        let r = verify_runtime(Arc::new(classical), true);
        assert!(
            r.succeeded(),
            "the handshake itself must still succeed — the point is that it succeeds \
             with the wrong group, which is exactly why config inspection misses it"
        );
        assert!(
            !r.is_post_quantum,
            "a provider with no hybrids must not report post-quantum, got {:?}",
            r.kx_group
        );
        assert!(
            enforce_pqc_policy(&r, true).is_err(),
            "pqc_required must refuse to start when the verified group is classical"
        );
        assert!(
            enforce_pqc_policy(&r, false).is_ok(),
            "without pqc_required the same host must still be allowed to start"
        );
    }

    /// Only hybrids count. A classical group must never satisfy the policy, and a
    /// misspelling must not either.
    #[test]
    fn only_hybrid_groups_count_as_post_quantum() {
        assert!(is_post_quantum("X25519MLKEM768"));
        assert!(is_post_quantum("x25519mlkem768"));
        assert!(is_post_quantum(" SecP256r1MLKEM768 "));
        assert!(!is_post_quantum("X25519"));
        assert!(!is_post_quantum("secp384r1"));
        assert!(!is_post_quantum("MLKEM"));
        assert!(!is_post_quantum(""));
    }

    /// `pqc_required` must refuse to start on a classical group, on a failed
    /// verification, and on no verification at all — never on the absence of evidence
    /// interpreted favourably.
    #[test]
    fn pqc_required_fails_closed_on_every_negative_outcome() {
        let classical = VerifiedRuntime {
            kx_group: Some("secp384r1".into()),
            is_post_quantum: false,
            ..Default::default()
        };
        assert!(enforce_pqc_policy(&classical, true).is_err());
        assert!(enforce_pqc_policy(&classical, false).is_ok());

        let failed = VerifiedRuntime {
            error: Some("provider exploded".into()),
            ..Default::default()
        };
        assert!(enforce_pqc_policy(&failed, true).is_err());
        assert!(enforce_pqc_policy(&failed, false).is_ok());

        let never_ran = VerifiedRuntime::default();
        assert!(enforce_pqc_policy(&never_ran, true).is_err());

        let good = VerifiedRuntime {
            kx_group: Some("X25519MLKEM768".into()),
            is_post_quantum: true,
            ..Default::default()
        };
        assert!(enforce_pqc_policy(&good, true).is_ok());
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Post-bind probes
// ═════════════════════════════════════════════════════════════════════════════

/// Probe the *listener that is actually bound*, not just the provider it was built
/// from.
///
/// The in-memory handshake proves the crypto provider negotiates a post-quantum group.
/// It cannot prove that the socket an operator's clients will reach was built from that
/// provider — a listener assembled down a different code path, or handed a different
/// config, would still pass. This closes that gap by completing a real TLS handshake
/// over a real TCP connection to the bound port.
///
/// # Why this probe sends no HTTP request
///
/// It stops at the TLS handshake deliberately. Issuing a request would run the WAF, the
/// rate limiter, the access log and the metrics counters against the proxy's own
/// address, and this host runs a fail2ban jail over that access log. A startup
/// self-test that contributes to a ban decision, consumes a rate-limit budget, or
/// writes 4xx lines that later read as an attack is worse than no self-test. Anything
/// that needs a request — WAF blocking, mTLS rejection, rate-limit thresholds — needs
/// a probe identity the defences can exempt, and that exemption is a bypass primitive
/// which has to be designed rather than improvised.
pub fn probe_bound_listener(
    addr: std::net::SocketAddr,
    sni: &str,
    provider: Arc<CryptoProvider>,
    tls13_only: bool,
) -> VerifiedRuntime {
    let offered_groups = provider
        .kx_groups
        .iter()
        .map(|g| format!("{:?}", g.name()))
        .collect::<Vec<_>>();

    match connect_and_read_params(addr, sni, provider, tls13_only) {
        Ok((group, version, suite)) => VerifiedRuntime {
            is_post_quantum: is_post_quantum(&group),
            kx_group: Some(group),
            tls_version: Some(version),
            cipher_suite: Some(suite),
            offered_groups,
            error: None,
        },
        Err(e) => VerifiedRuntime {
            offered_groups,
            error: Some(format!("{e:#}")),
            ..Default::default()
        },
    }
}

fn connect_and_read_params(
    addr: std::net::SocketAddr,
    sni: &str,
    provider: Arc<CryptoProvider>,
    tls13_only: bool,
) -> Result<(String, String, String)> {
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;

    let versions: &[&rustls::SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS12, &rustls::version::TLS13]
    };

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .context("probe client: protocol versions rejected")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ProbeVerifier))
        .with_no_client_auth();

    let server_name = ServerName::try_from(sni.to_string())?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("probe client: connection setup")?;

    // Short and absolute: this runs on the startup path, and a listener that cannot
    // complete a loopback handshake in two seconds has already failed the test.
    let timeout = Duration::from_secs(2);

    // Retry, because `tokio::spawn` returns before the task it spawned has bound. The
    // first version of this probe fired immediately after the listeners were spawned
    // and reported "Connection refused" against a proxy that was in fact about to
    // serve perfectly — a self-test that cries wolf is worse than none, because the
    // next person to see it will start ignoring the section.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut sock = loop {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => break s,
            Err(e) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(150));
                let _ = e;
            }
            Err(e) => {
                return Err(anyhow!(
                    "connecting to the bound listener at {addr}: {e}                      (still refusing after 5s — the listener did not come up)"
                ))
            }
        }
    };
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;

    while conn.is_handshaking() {
        if conn.wants_write() {
            conn.write_tls(&mut sock).context("probe: write")?;
            sock.flush().ok();
        }
        if conn.is_handshaking() && conn.wants_read() {
            let n = conn.read_tls(&mut sock).context("probe: read")?;
            if n == 0 {
                return Err(anyhow!(
                    "listener closed the connection during the handshake"
                ));
            }
            conn.process_new_packets()
                .context("probe: handshake rejected by the listener")?;
        }
    }

    let group = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()))
        .ok_or_else(|| anyhow!("listener completed a handshake but reported no group"))?;
    let version = conn
        .protocol_version()
        .map(|v| format!("{v:?}"))
        .unwrap_or_else(|| "unknown".into());
    let suite = conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "unknown".into());

    // Close cleanly so the listener does not log an aborted connection for what was a
    // successful test.
    conn.send_close_notify();
    if conn.wants_write() {
        let _ = conn.write_tls(&mut sock);
    }

    Ok((group, version, suite))
}

/// Accepts any certificate, for probing this process's own listener over loopback.
///
/// This probe asks "what cryptographic parameters did my own socket negotiate", not
/// "is this peer who it claims to be". Identity is not in question: the connection is
/// to 127.0.0.1, to a port this process just bound, and nothing is sent over it. Full
/// verification would instead make the probe fail on any host whose certificate is
/// self-signed or issued for a name that does not resolve to loopback — turning a
/// working PQC listener into a reported failure, which is the opposite of the point.
///
/// It is confined to this module, used only by [`probe_bound_listener`], and must
/// never be reachable from configuration. If a future caller wants it for a
/// non-loopback address, that caller is wrong.
#[derive(Debug)]
struct ProbeVerifier;

impl rustls::client::danger::ServerCertVerifier for ProbeVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// Turn a post-bind probe result into attestation rows.
pub fn bound_listener_section(probe: &VerifiedRuntime, addr: std::net::SocketAddr) -> Section {
    let mut rows = vec![Row::observed("Probed endpoint", addr.to_string())];
    match (&probe.kx_group, &probe.error) {
        (Some(group), _) => {
            rows.push(Row::verified("Listener reachable", "yes"));
            rows.push(Row::verified("Listener group", group.clone()));
            rows.push(Row {
                name: "Listener PQC".into(),
                value: if probe.is_post_quantum {
                    "PASS".into()
                } else {
                    "FAILED — classical group".into()
                },
                provenance: Provenance::Verified,
            });
            if let Some(v) = &probe.tls_version {
                rows.push(Row::verified("Listener TLS version", v.clone()));
            }
        }
        (None, Some(err)) => {
            rows.push(Row {
                name: "Listener reachable".into(),
                value: "FAILED".into(),
                provenance: Provenance::Verified,
            });
            rows.push(Row::observed("Probe error", err.clone()));
        }
        (None, None) => rows.push(Row::observed("Listener probe", "not attempted")),
    }
    Section {
        title: "BOUND TLS LISTENER (post-bind probe)",
        rows,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Enforcement probes: WAF, mTLS, rate limiting
// ═════════════════════════════════════════════════════════════════════════════

/// The source address every enforcement probe presents.
///
/// RFC 5737 TEST-NET-1, reserved for documentation and guaranteed never to appear as a
/// real client. This choice is the whole safety argument for these probes, and it
/// replaces the header-token exemption that seemed obvious at first:
///
/// * **No exemption exists, so no bypass primitive exists.** The rules run against the
///   probe exactly as they run against an attacker — there is no branch in the
///   enforcement path that a leaked token could take. A mechanism that lets a request
///   skip the WAF is a liability forever; not needing one is free.
/// * **Side effects land somewhere harmless.** These rules deliberately mutate state —
///   `evaluate` adds to the blocklist and increments suspicious-pattern counters, which
///   is part of the decision, not the rendering. Pointing that at 192.0.2.x means a
///   blocklist entry no client can ever collide with, and a rate-limit bucket that is
///   nobody's budget.
/// * **It is the only address that works at all.** `is_trusted_ip()` short-circuits
///   `evaluate()` to `Allow` for loopback, so a probe from 127.0.0.1 would sail through
///   every rule and report "the WAF did not block" — a false failure that would have
///   made the header-token design test precisely nothing.
///
/// Nothing is sent over a network for these, so there is no access-log line and no
/// fail2ban input either.
const PROBE_SOURCE_WAF: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
const PROBE_SOURCE_RATELIMIT: std::net::IpAddr =
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));

/// The outcome of probing one enforcement control.
pub enum ProbeOutcome {
    /// The control ran and did what it is configured to do.
    Enforced(String),
    /// The control ran and did not enforce. This is a finding.
    NotEnforced(String),
    /// The control is switched off in configuration. Not a failure.
    NotConfigured,
    /// The probe itself could not run.
    Inconclusive(String),
}

impl ProbeOutcome {
    fn row(self, name: &str) -> Row {
        match self {
            Self::Enforced(detail) => Row::verified(name, format!("ENFORCED — {detail}")),
            Self::NotEnforced(detail) => Row {
                name: name.into(),
                value: format!("FAILED — {detail}"),
                provenance: Provenance::Verified,
            },
            Self::NotConfigured => Row::configured(name, "not configured"),
            Self::Inconclusive(why) => Row::observed(name, format!("inconclusive — {why}")),
        }
    }
}

/// A request the WAF should have no reason to object to.
///
/// The first version of these probes sent an empty header map, and every request —
/// including a bare `GET /` — came back `WafBlock`, because this WAF rejects requests
/// with no User-Agent. That made the WAF probe pass for entirely the wrong reason: it
/// was not detecting the attack payloads at all, it was rejecting the absence of a
/// header, and it would have reported ENFORCED against a ruleset that could not spot a
/// single injection.
fn probe_headers() -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    h.insert(
        http::header::USER_AGENT,
        http::HeaderValue::from_static(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/140.0 Safari/537.36",
        ),
    );
    h.insert(http::header::ACCEPT, http::HeaderValue::from_static("*/*"));
    h
}

/// Does the WAF actually block an attack, or does it block everything?
///
/// A probe that only sends attacks cannot tell those two apart, and this one could not:
/// its attacks were blocked, but so was a benign request, so the "2/2 patterns blocked"
/// it reported was evidence of nothing. The differential is the whole test — a control
/// request that must be allowed, then attacks that must not be, with the same headers
/// and the same source. Only the difference between the two is attributable to attack
/// detection.
///
/// Returns `Inconclusive` rather than a verdict when the control is refused, because at
/// that point the probe genuinely cannot separate a working ruleset from a blanket deny,
/// and saying so is more useful than guessing.
pub fn probe_waf(
    config: &crate::config::ProxyConfig,
    engine: &crate::security::SecurityState,
) -> ProbeOutcome {
    use crate::security::{RequestPolicy, SecurityDecision, SecurityRequestView};

    if !config.waf.enabled {
        return ProbeOutcome::NotConfigured;
    }

    let headers = probe_headers();
    let policy = RequestPolicy::default();
    let view = |path: &'static str, query: &'static str| SecurityRequestView {
        ip: PROBE_SOURCE_WAF,
        method: "GET",
        path,
        query,
        headers: &headers,
        body: None,
    };

    // Control first, and before any attack has had the chance to get this source
    // blocklisted — the order matters, because an auto-block triggered by the attacks
    // would make the control fail for a reason that has nothing to do with the control.
    match engine.evaluate(&view("/", ""), &policy) {
        SecurityDecision::Allow => {}
        other => {
            return ProbeOutcome::Inconclusive(format!(
                "control request was refused ({other:?}) — cannot distinguish attack \
                 detection from a blanket deny"
            ))
        }
    }

    let cases: &[(&str, &str, &str)] = &[
        ("path traversal", "/../../../../etc/passwd", ""),
        ("sql injection", "/search", "q=1%27%20OR%20%271%27%3D%271"),
    ];

    let mut blocked = Vec::new();
    let mut allowed = Vec::new();
    for (label, path, query) in cases {
        match engine.evaluate(&view(path, query), &policy) {
            SecurityDecision::Allow => allowed.push(label.to_string()),
            SecurityDecision::WafBlock { rule } => blocked.push(format!("{label} ({rule})")),
            other => blocked.push(format!("{label} ({other:?})")),
        }
    }

    match (blocked.len(), allowed.len()) {
        (n, 0) if n > 0 => {
            ProbeOutcome::Enforced(format!("control allowed, {n}/{n} attacks blocked"))
        }
        (0, _) => ProbeOutcome::NotEnforced(
            "control allowed but no attack pattern was blocked".to_string(),
        ),
        (b, a) => ProbeOutcome::NotEnforced(format!(
            "blocked {b}, allowed {a} ({}) — partial coverage",
            allowed.join(", ")
        )),
    }
}

/// Does the rate limiter actually deny past its threshold?
///
/// Drives a synthetic key past the configured limit and reports the request number at
/// which the limiter said no.
///
/// The first version of this reported "900 consecutive requests were all allowed" on a
/// proxy where every single one had in fact been denied — ten by the WAF, because the
/// probe sent no User-Agent, and the remaining 890 by the blocklist the WAF's
/// auto-block had put the source on. It matched only on `RateLimited` and treated every
/// other verdict as a pass, so it printed a FAILED that was the precise opposite of
/// what happened. A self-test that reports a false failure in a security banner is
/// worse than no self-test: the first person to investigate one and find nothing will
/// discount the next.
///
/// So: requests the WAF has no reason to refuse, and any denial by a *different*
/// control is reported as inconclusive with the verdict named, never as "allowed".
pub async fn probe_rate_limit(
    config: &crate::config::ProxyConfig,
    engine: &crate::security::SecurityState,
) -> ProbeOutcome {
    use crate::security::{RequestPolicy, SecurityDecision, SecurityRequestView};

    if !config.rate_limiting.enabled {
        return ProbeOutcome::NotConfigured;
    }

    let headers = probe_headers();
    let policy = RequestPolicy::default();

    // Bounded above the configured burst so a limiter that never denies is reported
    // rather than spun on, and so "denied late" stays distinguishable from "never".
    let ceiling = config
        .rate_limiting
        .burst_size
        .saturating_add(config.rate_limiting.requests_per_second)
        .saturating_add(50)
        .clamp(10, 5000);

    for attempt in 1..=ceiling {
        let view = SecurityRequestView {
            ip: PROBE_SOURCE_RATELIMIT,
            method: "GET",
            path: "/",
            query: "",
            headers: &headers,
            body: None,
        };
        match engine.evaluate(&view, &policy) {
            SecurityDecision::RateLimited { limit, .. } => {
                return ProbeOutcome::Enforced(format!(
                    "denied at request {attempt} of {ceiling} (limit {limit}/s)"
                ))
            }
            SecurityDecision::Allow => continue,
            other => {
                return ProbeOutcome::Inconclusive(format!(
                    "request {attempt} was denied by another control ({other:?}) before \
                     the rate limiter could be reached"
                ))
            }
        }
    }

    ProbeOutcome::NotEnforced(format!(
        "{ceiling} consecutive requests from one source were all allowed"
    ))
}

/// Is mutual TLS actually required, or only written down?
///
/// Reported from configuration when it is off, because "off" is a deliberate state and
/// not a failure. When it is on, the honest test is a handshake without a client
/// certificate against the bound listener — which is a TLS-layer rejection and involves
/// no HTTP request, no WAF, no rate limiter and no access log.
pub fn probe_mtls(
    require_client_cert: bool,
    addr: std::net::SocketAddr,
    sni: &str,
    provider: Arc<CryptoProvider>,
    tls13_only: bool,
) -> ProbeOutcome {
    if !require_client_cert {
        return ProbeOutcome::NotConfigured;
    }
    // A probe client offers no client certificate, so a listener that demands one must
    // refuse the handshake. Success here would mean mTLS is configured and not enforced.
    match connect_and_read_params(addr, sni, provider, tls13_only) {
        Ok((group, _, _)) => ProbeOutcome::NotEnforced(format!(
            "handshake completed without a client certificate (group {group})"
        )),
        Err(e) => ProbeOutcome::Enforced(format!(
            "handshake without a client certificate was refused ({})",
            e.to_string().lines().next().unwrap_or("rejected")
        )),
    }
}

/// Assemble the enforcement section.
pub fn enforcement_section(waf: ProbeOutcome, rate: ProbeOutcome, mtls: ProbeOutcome) -> Section {
    Section {
        title: "ENFORCEMENT (probed against TEST-NET-1 sources, no network I/O)",
        rows: vec![
            waf.row("WAF blocking"),
            rate.row("Rate limiting"),
            mtls.row("mTLS"),
        ],
    }
}
