//! HTTP/3 and QUIC **client** conformance suite.
//!
//! The QUIC Interop Runner tests implementations against each other in a lab
//! matrix. This is the other thing: a public service a client library can be
//! pointed at to find out whether it handles the protocol's awkward corners.
//!
//! Offering that requires a server that will misbehave on request — emit
//! reserved frame types, duplicate a SETTINGS identifier, reject 0-RTT, black
//! hole the path MTU. A CDN customer cannot arrange any of it, because they do
//! not own the implementation. We fork `noq` (QUIC) and drive HTTP/3 frames
//! directly, so we can.
//!
//! # Layout
//!
//! - [`catalog`] — the tests, each citing the clause it exercises
//! - [`session`] — verdicts, and the liveness probe that makes them meaningful
//! - [`h3_frames`] — a hand-rolled HTTP/3 frame writer
//! - [`report`] — JSON, HTML and badge output
//!
//! # Selection: one UDP port per test
//!
//! Every test owns a port from the configured range, and the listener knows
//! which test it is serving from its own `local_addr()`.
//!
//! Selecting by URL path was the first design, and it does not survive contact
//! with the constraint below. Reading a path means QPACK-decoding the client's
//! request, and `h3` exposes only `send_response`/`send_data`/`send_trailers` —
//! no way to inject an arbitrary frame into a response it is managing. Owning
//! the connection from its first packet avoids the decoder entirely and gives
//! total control over SETTINGS, the control stream and the response stream.
//!
//! The conformance host still matters: it serves the catalogue, the reports and
//! the badge over ordinary HTTPS. It just does not select tests.
//!
//! # Why HTTP/3 frames are written by hand
//!
//! `h3` is an unvendored crates.io dependency while `noq`/`noq-proto` are
//! forked, so the QUIC layer is ours to bend and the HTTP/3 layer is not.
//! Vendoring `h3` would mean tracking upstream forever for less control than
//! writing the frames directly: a correct HTTP/3 implementation will refuse to
//! emit a duplicate SETTINGS identifier, which is precisely what
//! `h-duplicate-setting` needs it to do.
//!
//! Conformance does not need a general-purpose server. It needs specific byte
//! sequences on specific stream types, which is a much smaller thing to build
//! and owes nothing to anyone else's release schedule.

pub mod catalog;
pub mod h3_frames;
pub mod http;
pub mod impairment;
pub mod listener;
pub mod report;
pub mod session;

/// End-to-end proof that `q-zero-rtt-reject` rejects 0-RTT.
///
/// Test-only: no client in reach attempts early data over HTTP/3, so the live
/// port can only ever report that nothing was exercised. This drives it.
#[cfg(test)]
mod zero_rtt;

/// End-to-end proof that the two QPACK dynamic-table tests emit what they claim.
///
/// Test-only, and for the same reason: every HTTP/3 client in reach advertises a
/// QPACK table capacity of zero, so both ports can only report that nothing was
/// exercised. One of them was writing a field section referencing insertions it
/// never made, and no live run could have shown it.
#[cfg(test)]
mod qpack_dynamic;

use std::sync::Arc;

use crate::config::ConformanceConfig;

pub use catalog::{Class, Test, Tier};
pub use session::{Observation, Registry, Verdict};

/// Everything the listeners and handlers need to run the suite.
pub struct Conformance {
    pub config: ConformanceConfig,
    pub sessions: Arc<Registry>,
}

impl std::fmt::Debug for Conformance {
    // Hand-written because the session registry holds a DashMap of live
    // sessions; printing their contents in a config error would be noise.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conformance")
            .field("host", &self.config.host)
            .field("port_range", &self.config.port_range)
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

impl Conformance {
    /// Build the shared state, or `None` when the suite is switched off.
    ///
    /// Returns an error rather than starting with a bad port range: a range too
    /// small for the catalogue would silently serve only the tests that fit,
    /// and a report missing tests without saying so is worse than no report.
    pub fn new(config: &ConformanceConfig) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }

        let (start, end) = config.port_range;
        if end < start {
            return Err(format!("conformance.port_range is inverted: {start}-{end}"));
        }

        let available = end - start + 1;
        let needed = catalog::required_ports();
        if available < needed {
            return Err(format!(
                "conformance.port_range {start}-{end} provides {available} ports but the \
                 catalogue needs {needed}; widen the range or the suite would serve an \
                 incomplete catalogue without saying so"
            ));
        }

        Ok(Some(Self {
            config: config.clone(),
            sessions: Registry::new(config.session_ttl_secs, config.max_sessions),
        }))
    }

    /// Every port the catalogue needs bound, one per test.
    pub fn test_ports(&self) -> Vec<u16> {
        let start = self.config.port_range.0;
        catalog::CATALOG
            .iter()
            .filter_map(|t| t.port_offset)
            .map(|off| start + off)
            .collect()
    }

    /// Whether `host` is the conformance vhost.
    ///
    /// The vhost serves the catalogue, reports and badge. It does not select
    /// tests — that is what the per-test ports are for.
    pub fn owns_host(&self, host: &str) -> bool {
        let host = host.split(':').next().unwrap_or(host);
        host.eq_ignore_ascii_case(&self.config.host)
    }
}

/// The one instance for this process.
///
/// Shared rather than built per listener, and for the same reason `SecurityState`
/// is: a session is created by whichever UDP test listener the client connects
/// to and read back over HTTPS by the report handler, so separate registries
/// would mean every report came back "no such session".
static SHARED: std::sync::OnceLock<Option<Arc<Conformance>>> = std::sync::OnceLock::new();

/// Fetch (building on first call) the process-wide conformance state.
///
/// Errors are logged and become `None`: a misconfigured suite must not stop the
/// proxy serving the site. The first caller's config wins, so a hot reload does
/// not rebuild it — the port bindings could not follow a change anyway without
/// a restart.
pub fn shared(config: &ConformanceConfig) -> Option<Arc<Conformance>> {
    SHARED
        .get_or_init(|| match Conformance::new(config) {
            Ok(c) => c.map(Arc::new),
            Err(e) => {
                tracing::error!("Conformance suite misconfigured, not started: {e}");
                None
            }
        })
        .clone()
}

/// Check the conformance ports do not collide with the ports serving real
/// traffic.
///
/// Called at startup. An overlap would mean ordinary visitors being handed
/// deliberately broken protocol output, so this refuses to start rather than
/// warning.
pub fn check_port_conflicts(
    config: &ConformanceConfig,
    udp_port: u16,
    additional: &[u16],
) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    let (start, end) = config.port_range;
    let mut live = vec![udp_port];
    live.extend_from_slice(additional);
    for p in live {
        if p >= start && p <= end {
            return Err(format!(
                "conformance.port_range {start}-{end} contains port {p}, which serves live \
                 traffic; conformance ports emit deliberately malformed protocol output and \
                 must not overlap"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ConformanceConfig {
        ConformanceConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn disabled_yields_nothing() {
        let c = ConformanceConfig::default();
        assert!(Conformance::new(&c).unwrap().is_none());
    }

    #[test]
    fn a_range_too_small_for_the_catalogue_is_refused() {
        let mut c = cfg();
        c.port_range = (4460, 4461);
        let err = Conformance::new(&c).unwrap_err();
        assert!(err.contains("needs"), "must say how many are needed: {err}");
    }

    #[test]
    fn an_inverted_range_is_refused() {
        let mut c = cfg();
        c.port_range = (4490, 4460);
        assert!(Conformance::new(&c).is_err());
    }

    #[test]
    fn the_default_range_fits_the_catalogue() {
        let c = cfg();
        let conf = Conformance::new(&c).unwrap().expect("enabled");
        assert_eq!(
            u16::try_from(conf.test_ports().len()).expect("one port per test fits in u16"),
            catalog::required_ports()
        );
    }

    #[test]
    fn overlapping_live_ports_is_a_startup_error() {
        let mut c = cfg();
        c.port_range = (440, 4499);
        let err = check_port_conflicts(&c, 443, &[4434]).unwrap_err();
        assert!(err.contains("443"));

        c.port_range = (4460, 4499);
        assert!(check_port_conflicts(&c, 443, &[4434]).is_ok());
        // An additional port inside the range is caught too.
        assert!(check_port_conflicts(&c, 443, &[4434, 4470]).is_err());
    }

    #[test]
    fn the_vhost_is_matched_case_insensitively_and_without_port() {
        let conf = Conformance::new(&cfg()).unwrap().unwrap();
        assert!(conf.owns_host("conformance.pqcrypta.com"));
        assert!(conf.owns_host("Conformance.PQCrypta.com"));
        assert!(conf.owns_host("conformance.pqcrypta.com:443"));
        assert!(!conf.owns_host("pqcrypta.com"));
    }
}
