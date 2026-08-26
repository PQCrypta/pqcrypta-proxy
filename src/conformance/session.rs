//! Sessions, verdicts, and the liveness probe that makes a verdict mean
//! something.
//!
//! # Why the server is the judge
//!
//! The thing under test is the client, so the client cannot be trusted to
//! report on itself — a library that crashes on an unknown frame is in no
//! position to say so. Every verdict here is therefore derived from what the
//! server observed: whether the connection survived, whether the expected error
//! code arrived, whether the follow-up request appeared.
//!
//! # The liveness probe
//!
//! For the extensibility tests, "the client ignored the anomaly" and "the client
//! died on the anomaly" produce almost the same thing on the wire: no complaint.
//! The difference only shows up afterwards. So every test ends by expecting one
//! ordinary request on the same connection:
//!
//! - the probe arrives — the client tolerated the anomaly and kept going
//! - the probe never comes — the client stalled or died
//! - the connection closed with the error the spec names — correct rejection,
//!   which is a pass for a [`Class::Correctness`] test and a fail for an
//!   extensibility one
//!
//! Without the probe the report would call a crashed client compliant, which is
//! worse than having no report at all.
//!
//! [`Class::Correctness`]: super::catalog::Class::Correctness

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::catalog::{self, Class, Test};

/// The outcome of one test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The client did what the specification requires.
    Pass,
    /// The client did something the specification forbids.
    Fail,
    /// The client connected but the test could not be driven to a conclusion —
    /// it hung up early, or the anomaly was never reached. Deliberately distinct
    /// from `Fail`: an inconclusive run is our problem to explain, not the
    /// client's bug to fix, and folding the two together would produce reports
    /// that blame clients for our own flakiness.
    Inconclusive,
    /// The client never attempted this test.
    NotRun,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Inconclusive => "inconclusive",
            Verdict::NotRun => "not_run",
        }
    }
}

/// What the server saw a client do after the anomaly was emitted.
///
/// This is the raw observation; [`judge`] turns it into a [`Verdict`] using the
/// test's class, because the same observation means opposite things depending on
/// what was being tested. A connection closed with `H3_SETTINGS_ERROR` is
/// exactly right for `h-duplicate-setting` and exactly wrong for
/// `h-grease-settings`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The liveness probe arrived: the client carried on.
    SurvivedAndContinued,
    /// The client closed the connection with this application error code.
    ClosedWith { code: u64 },
    /// The client closed without an error code, or the transport dropped.
    ClosedSilently,
    /// Nothing happened before the liveness timeout expired.
    TimedOut,
    /// The client did something specific the test was watching for — a
    /// PATH_RESPONSE, an ACK_ECN, a DATA_BLOCKED. Carries a short label so the
    /// report can say what was seen.
    Signalled(String),
}

/// One recorded result.
#[derive(Debug, Clone, Serialize)]
pub struct Result_ {
    pub test_id: &'static str,
    pub verdict: Verdict,
    /// Human-readable account of what the server saw. Rendered next to the
    /// spec citation, so a failing client gets a sentence it can act on rather
    /// than a bare status.
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Turn an observation into a verdict, in light of what the test was measuring.
///
/// The asymmetry here is the whole reason [`Class`] exists:
///
/// - **Extensibility** — surviving is the pass. Any close is a failure, however
///   politely it was done, because the client was required to ignore something.
/// - **Correctness** — the *specific* error code is the pass. Surviving means
///   the client accepted something invalid, which is the bug being hunted.
/// - **Resilience** — surviving is the pass, and a clean close is a partial
///   failure rather than a crash, but both are failures.
pub fn judge(test: &Test, obs: &Observation, expected_code: Option<u64>) -> (Verdict, String) {
    match (test.class, obs) {
        // ── Extensibility: the client had to ignore it and keep going ──
        (Class::Extensibility, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Ignored the unrecognised element and completed the follow-up request.".to_string(),
        ),
        (Class::Extensibility, Observation::ClosedWith { code }) => (
            Verdict::Fail,
            format!(
                "Closed the connection with error 0x{code:x}. The element was required to be \
                 ignored — rejecting an unknown extension is what causes protocol ossification."
            ),
        ),
        (Class::Extensibility, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Dropped the connection without an error code instead of ignoring the element."
                .to_string(),
        ),
        (Class::Extensibility, Observation::TimedOut) => (
            Verdict::Fail,
            "Stopped responding after the element was sent. The follow-up request never arrived, \
             so the client did not survive it."
                .to_string(),
        ),

        // ── Correctness: a specific rejection was required ──
        (Class::Correctness, Observation::ClosedWith { code }) => match expected_code {
            Some(want) if *code == want => (
                Verdict::Pass,
                format!("Rejected with the required error code 0x{want:x}."),
            ),
            Some(want) => (
                Verdict::Fail,
                format!(
                    "Rejected, but with error 0x{code:x} where the specification requires \
                     0x{want:x}. The violation was detected; the code reported is wrong."
                ),
            ),
            None => (Verdict::Pass, format!("Rejected with error 0x{code:x}.")),
        },
        (Class::Correctness, Observation::SurvivedAndContinued) => (
            Verdict::Fail,
            "Accepted a protocol violation and carried on. This should have been rejected."
                .to_string(),
        ),
        (Class::Correctness, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Responded correctly: {what}."))
        }
        (Class::Correctness, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Closed without an error code. The violation was detected but not reported, so the \
             peer cannot tell what went wrong."
                .to_string(),
        ),
        (Class::Correctness, Observation::TimedOut) => (
            Verdict::Fail,
            "Neither rejected the violation nor continued. The connection simply stalled."
                .to_string(),
        ),

        // ── Resilience: the client had to recover ──
        (Class::Resilience, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Recovered and completed the follow-up request.".to_string(),
        ),
        (Class::Resilience, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Recovered: {what}."))
        }
        (Class::Resilience, Observation::ClosedWith { code }) => (
            Verdict::Fail,
            format!("Gave up with error 0x{code:x} instead of recovering."),
        ),
        (Class::Resilience, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Dropped the connection instead of recovering.".to_string(),
        ),
        (Class::Resilience, Observation::TimedOut) => {
            (Verdict::Fail, "Stalled instead of recovering.".to_string())
        }

        // An extensibility test that got a specific signal is not something the
        // harness knows how to read; say so rather than inventing a verdict.
        (Class::Extensibility, Observation::Signalled(what)) => (
            Verdict::Inconclusive,
            format!("Unexpected signal for an extensibility test: {what}."),
        ),
    }
}

/// One client's walk through the catalogue.
pub struct Session {
    pub id: String,
    created: Instant,
    results: HashMap<&'static str, Result_>,
}

impl Session {
    fn new(id: String) -> Self {
        Self {
            id,
            created: Instant::now(),
            results: HashMap::new(),
        }
    }

    /// Record an outcome. A test re-run within the same session overwrites its
    /// previous result — clients under active development re-run constantly,
    /// and a report that accumulated every historical attempt would be unusable.
    pub fn record(
        &mut self,
        test: &'static Test,
        obs: &Observation,
        expected_code: Option<u64>,
        elapsed_ms: u64,
    ) {
        let (verdict, detail) = judge(test, obs, expected_code);
        self.results.insert(
            test.id,
            Result_ {
                test_id: test.id,
                verdict,
                detail,
                elapsed_ms,
            },
        );
    }

    /// Every catalogue entry, with `NotRun` filled in for those untouched.
    ///
    /// The report always lists the full catalogue: a client that connected once
    /// and gave up should show 26 `NotRun` rows, not a single pass and a
    /// misleading 100%.
    pub fn results(&self) -> Vec<Result_> {
        catalog::CATALOG
            .iter()
            .map(|t| {
                self.results.get(t.id).cloned().unwrap_or_else(|| Result_ {
                    test_id: t.id,
                    verdict: Verdict::NotRun,
                    detail: "Not attempted.".to_string(),
                    elapsed_ms: 0,
                })
            })
            .collect()
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }
}

/// All live sessions.
pub struct Registry {
    sessions: DashMap<String, Session>,
    ttl: Duration,
    max: usize,
}

impl Registry {
    pub fn new(ttl_secs: u64, max: usize) -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max,
        })
    }

    /// Start a session, returning its id.
    ///
    /// Sweeps expired entries first. The endpoint is unauthenticated, so the
    /// cap is what stops it being used to grow memory without bound; when the
    /// registry is full after a sweep, the oldest session is evicted rather
    /// than refusing the new client, since a stale report matters less than a
    /// developer being unable to start a run.
    pub fn create(&self) -> String {
        self.sweep();
        if self.sessions.len() >= self.max {
            if let Some(oldest) = self
                .sessions
                .iter()
                .max_by_key(|e| e.value().age())
                .map(|e| e.key().clone())
            {
                self.sessions.remove(&oldest);
            }
        }
        let id = new_session_id();
        self.sessions.insert(id.clone(), Session::new(id.clone()));
        id
    }

    /// Run `f` against a session, if it still exists.
    pub fn with<F, R>(&self, id: &str, f: F) -> Option<R>
    where
        F: FnOnce(&mut Session) -> R,
    {
        self.sessions.get_mut(id).map(|mut s| f(s.value_mut()))
    }

    pub fn exists(&self, id: &str) -> bool {
        self.sessions.contains_key(id)
    }

    fn sweep(&self) {
        let ttl = self.ttl;
        self.sessions.retain(|_, s| s.age() < ttl);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

/// A random, URL-safe session id.
///
/// Session ids appear in report URLs and are not secrets — a report reveals
/// only what the requester's own client did — but they are unguessable so that
/// one developer's in-progress run is not trivially enumerable by another.
fn new_session_id() -> String {
    use rand::RngCore;
    use std::fmt::Write as _;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
        // Cannot fail: writing to a String is infallible.
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::catalog;

    fn test_of(id: &str) -> &'static catalog::Test {
        catalog::find(id).expect("catalogue entry")
    }

    #[test]
    fn ignoring_an_extension_passes_only_if_the_client_continues() {
        let t = test_of("h-grease-settings");
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, None);
        assert_eq!(v, Verdict::Pass);

        // Closing politely is still a failure: it was required to be ignored.
        let (v, d) = judge(t, &Observation::ClosedWith { code: 0x0106 }, None);
        assert_eq!(v, Verdict::Fail);
        assert!(d.contains("ossification"), "explain why, not just that");
    }

    #[test]
    fn a_violation_must_be_rejected_with_the_named_code() {
        let t = test_of("h-duplicate-setting");
        let (v, _) = judge(t, &Observation::ClosedWith { code: 0x0109 }, Some(0x0109));
        assert_eq!(v, Verdict::Pass);

        // Right instinct, wrong code.
        let (v, d) = judge(t, &Observation::ClosedWith { code: 0x0102 }, Some(0x0109));
        assert_eq!(v, Verdict::Fail);
        assert!(d.contains("0x109"), "name the code that was required");

        // Accepting it is the bug being hunted.
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, Some(0x0109));
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn a_timeout_is_a_failure_not_an_absence() {
        // The liveness probe exists precisely so this is distinguishable from
        // a pass. A client that silently died must not read as compliant.
        let t = test_of("h-grease-frame");
        let (v, _) = judge(t, &Observation::TimedOut, None);
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn resilience_rewards_recovery_however_it_is_signalled() {
        let t = test_of("q-pmtu-blackhole");
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, None);
        assert_eq!(v, Verdict::Pass);
        let (v, _) = judge(
            t,
            &Observation::Signalled("probed down to 1200 bytes".into()),
            None,
        );
        assert_eq!(v, Verdict::Pass);
        let (v, _) = judge(t, &Observation::ClosedWith { code: 0x2 }, None);
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn untouched_tests_report_as_not_run_over_the_whole_catalogue() {
        let reg = Registry::new(60, 8);
        let id = reg.create();
        let results = reg.with(&id, |s| s.results()).unwrap();
        assert_eq!(results.len(), catalog::CATALOG.len());
        assert!(results.iter().all(|r| r.verdict == Verdict::NotRun));
    }

    #[test]
    fn rerunning_a_test_replaces_its_earlier_result() {
        let reg = Registry::new(60, 8);
        let id = reg.create();
        let t = test_of("h-grease-settings");

        reg.with(&id, |s| s.record(t, &Observation::TimedOut, None, 1));
        reg.with(&id, |s| {
            s.record(t, &Observation::SurvivedAndContinued, None, 2)
        });

        let r = reg
            .with(&id, |s| s.results())
            .unwrap()
            .into_iter()
            .find(|r| r.test_id == t.id)
            .unwrap();
        assert_eq!(r.verdict, Verdict::Pass, "the later run wins");
    }

    #[test]
    fn the_registry_stays_bounded() {
        let reg = Registry::new(3600, 3);
        let ids: Vec<_> = (0..5).map(|_| reg.create()).collect();
        assert!(reg.len() <= 3, "cap must hold: {}", reg.len());
        // The most recent creation always survives.
        assert!(reg.exists(ids.last().unwrap()));
    }

    #[test]
    fn session_ids_are_distinct() {
        let reg = Registry::new(60, 64);
        let a = reg.create();
        let b = reg.create();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
    }
}
