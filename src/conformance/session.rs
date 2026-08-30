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
    /// The client did the specific wrong thing the test was watching for, with
    /// a sentence saying what. The counterpart to [`Observation::Signalled`],
    /// for tests whose failure is not "accepted a violation and carried on" —
    /// ignoring a Stateless Reset, say, where the generic wording would
    /// misdescribe what happened.
    Violated(String),
    /// The run completed but never put the client in the situation the test is
    /// about — a flow-control test where the request was too small to approach
    /// the window, say.
    ///
    /// Distinct from every other outcome because the alternative is a lie in
    /// one direction or the other: scoring it as a pass credits a client for
    /// something it was never asked to do, and scoring it as a failure accuses
    /// it of accepting a violation that was never sent. Neither is a result.
    NotExercised(String),
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
    if !test.implemented {
        return (
            Verdict::Inconclusive,
            "This test's anomaly is not implemented yet, so the run proves nothing about \
             it either way."
                .to_string(),
        );
    }

    if let Observation::NotExercised(why) = obs {
        return (
            Verdict::Inconclusive,
            format!("The run did not exercise this test: {why}."),
        );
    }

    // Handled ahead of the class matrix rather than inside it: the point of this
    // observation is that the test supplies wording the generic per-class
    // sentence would get wrong, and that is true for every class.
    if let Observation::Violated(what) = obs {
        return (Verdict::Fail, format!("{what}."));
    }

    // A close that is not a defined HTTP/3 objection is a graceful shutdown,
    // whatever the class.
    //
    // H3_NO_ERROR (0x100) is "no error to signal". So is any *unknown* code:
    // RFC 9114 §8.1 requires unknown error codes to be "treated as equivalent to
    // H3_NO_ERROR", and §9 makes the general rule explicit — implementations
    // MUST ignore unknown values in extensible elements, error codes included.
    //
    // The listener already converts these before they arrive here; this states
    // the same rule where the verdict is actually decided, so the invariant
    // holds however the observation was produced.
    if let Observation::ClosedWith { code } = obs {
        if !crate::conformance::h3_frames::error_code::is_rejection(*code) {
            return (
                Verdict::Pass,
                format!(
                    "Completed the exchange and closed cleanly (0x{code:x} is not an \
                     HTTP/3 error code, which §8.1 makes equivalent to H3_NO_ERROR)."
                ),
            );
        }
    }

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

        // ── Interoperability: valid, demanding, and must be handled ──
        (Class::Interoperability, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Decoded it and completed the request.".to_string(),
        ),
        (Class::Interoperability, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Handled it: {what}."))
        }
        (Class::Interoperability, Observation::ClosedWith { code }) => (
            Verdict::Fail,
            format!(
                "Rejected the response with error 0x{code:x}. Nothing here violates the \
                 specification — this is valid HTTP/3 that a client is required to be able \
                 to process."
            ),
        ),
        (Class::Interoperability, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Dropped the connection on a valid response it was required to be able to \
             process."
                .to_string(),
        ),
        (Class::Interoperability, Observation::TimedOut) => (
            Verdict::Fail,
            "Stalled on a valid response. Something in the decode path did not complete."
                .to_string(),
        ),

        // ── Discretionary: the specification permits either ──
        (Class::Discretionary, Observation::ClosedWith { code }) => (
            Verdict::Pass,
            format!(
                "Rejected with error 0x{code:x}. The specification permits this but does \
                 not require it; a client that ignored it would also be conformant."
            ),
        ),
        (Class::Discretionary, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Tolerated it and continued. The specification permits this but does not \
             require it; a client that rejected it would also be conformant."
                .to_string(),
        ),
        (Class::Discretionary, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Handled it: {what}."))
        }
        (Class::Discretionary, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Closed without an error code. Rejecting this is permitted, but doing so \
             silently leaves the peer unable to tell what happened."
                .to_string(),
        ),
        (Class::Discretionary, Observation::TimedOut) => (
            Verdict::Fail,
            "Neither rejected it nor continued. Both outcomes are allowed; stalling is \
             not one of them."
                .to_string(),
        ),

        // Handled by the early return above. Repeated rather than made
        // unreachable!() so that removing the guard degrades to the right
        // answer instead of panicking in production.
        (_, Observation::NotExercised(why)) => (
            Verdict::Inconclusive,
            format!("The run did not exercise this test: {why}."),
        ),
        (_, Observation::Violated(what)) => (Verdict::Fail, format!("{what}.")),

        // A signal is affirmative evidence the client took the element in its
        // stride, which is exactly what an extensibility test asks for.
        //
        // This was Inconclusive on the grounds that a specific signal was "not
        // something the harness knows how to read" — true when no extensibility
        // test produced one, and wrong as soon as one did.
        // `q-reserved-transport-param` observes the client completing a
        // handshake that carried a reserved transport parameter: that is the
        // requirement of §18.1 met, reported in more detail than a bare
        // survival, and it was being scored as though nothing had been learned.
        (Class::Extensibility, Observation::Signalled(what)) => (
            Verdict::Pass,
            format!("Ignored the unrecognised element and carried on: {what}."),
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
    /// The most recent session started from each source address.
    ///
    /// How a client's test connections find their session. The obvious channel
    /// is SNI — `<session>.conformance.example` — but that needs a wildcard
    /// certificate, and without one every connection fails TLS verification
    /// before a single test can run. Associating by source address needs no
    /// certificate and no cooperation from the client beyond starting the
    /// session itself.
    ///
    /// Two clients behind one NAT can therefore land in the same session. That
    /// is a real limitation and the reason SNI is still preferred when it
    /// carries a usable id: this is the fallback, not the design.
    by_source: DashMap<std::net::IpAddr, (String, Instant)>,
    ttl: Duration,
    max: usize,
}

impl Registry {
    pub fn new(ttl_secs: u64, max: usize) -> Arc<Self> {
        Arc::new(Self {
            sessions: DashMap::new(),
            by_source: DashMap::new(),
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

    /// Remember that `ip` started `id`, so its test connections can find it.
    pub fn associate(&self, ip: std::net::IpAddr, id: &str) {
        self.by_source.insert(ip, (id.to_string(), Instant::now()));
    }

    /// The most recent live session started from `ip`.
    ///
    /// Expired associations are dropped rather than resurrecting a session that
    /// has already aged out of the registry.
    pub fn for_source(&self, ip: std::net::IpAddr) -> Option<String> {
        let entry = self.by_source.get(&ip)?;
        let (id, started) = entry.value();
        if started.elapsed() >= self.ttl || !self.sessions.contains_key(id) {
            let id = id.clone();
            drop(entry);
            self.by_source.remove(&ip);
            let _ = id;
            return None;
        }
        Some(id.clone())
    }

    fn sweep(&self) {
        let ttl = self.ttl;
        self.sessions.retain(|_, s| s.age() < ttl);
        self.by_source
            .retain(|_, (_, started)| started.elapsed() < ttl);
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
    use crate::conformance::catalog::{self, Class, Test, Tier};

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
        // RFC 9114 §6.2.1 is MUST: a control stream whose first frame is not
        // SETTINGS is H3_MISSING_SETTINGS, with no discretion.
        let t = test_of("h-missing-settings");
        let want = 0x010a;
        let (v, _) = judge(t, &Observation::ClosedWith { code: want }, Some(want));
        assert_eq!(v, Verdict::Pass);

        // Right instinct, wrong code.
        let (v, d) = judge(t, &Observation::ClosedWith { code: 0x0102 }, Some(want));
        assert_eq!(v, Verdict::Fail);
        assert!(d.contains("0x10a"), "name the code that was required: {d}");

        // Accepting it is the bug being hunted.
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, Some(want));
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn a_test_that_never_ran_is_inconclusive_whatever_its_class() {
        // A correctness test would otherwise read "accepted a violation" for a
        // violation that was never sent, and an extensibility one would credit
        // the client for tolerating nothing.
        for id in ["q-flow-control", "q-path-challenge", "h-grease-settings"] {
            let t = test_of(id);
            let (v, d) = judge(
                t,
                &Observation::NotExercised("the request never approached the window".into()),
                None,
            );
            assert_eq!(v, Verdict::Inconclusive, "{id}");
            assert!(d.contains("did not exercise"), "{id}: {d}");
        }
    }

    #[test]
    fn a_graceful_shutdown_is_not_a_rejection() {
        // RFC 9114 §8.1: H3_NO_ERROR (0x100) means "no error to signal" — it is
        // what a client sends when it has finished, not a complaint.
        //
        // Scoring it as a rejection failed every client that closes its HTTP/3
        // connection properly. It hid for a while because the first two clients
        // measured, curl and Chromium, both close at the QUIC layer instead,
        // where NO_ERROR was already handled. Three thin clients written later
        // all "failed" the same seven extensibility and interoperability tests,
        // which is what gave it away: three independent libraries do not fail
        // identically.
        let t = test_of("h-grease-frame");
        for code in [
            0x0100, // H3_NO_ERROR itself
            0x0,    // what aioquic and quic-go send for a clean close
            0x21,   // the first reserved GREASE error code, 0x1f*0 + 0x21
            0x1f * 5 + 0x21,
            0x0107, // assigned to nothing in RFC 9114
        ] {
            let (v, d) = judge(t, &Observation::ClosedWith { code }, None);
            assert_ne!(
                v,
                Verdict::Fail,
                "0x{code:x} is not a defined HTTP/3 error code, so §8.1 makes it \
                 equivalent to H3_NO_ERROR — it cannot be a rejection: {d}"
            );
        }

        // A real objection must still register as one.
        let (v, _) = judge(t, &Observation::ClosedWith { code: 0x0105 }, None);
        assert_eq!(
            v,
            Verdict::Fail,
            "H3_FRAME_UNEXPECTED on an extensibility test is a genuine failure"
        );
    }

    #[test]
    fn an_unimplemented_test_is_never_scored() {
        // Falling through to a correct control stream must not read as the
        // client accepting a violation that was never sent.
        //
        // Checked against a purpose-built test rather than by hunting the
        // catalogue for an unbuilt correctness entry: that search used to find
        // one, and stopped finding one the moment the last correctness anomaly
        // was built — turning a guard that still matters into a failing test.
        // The guard has to hold for anything that might be added later, built or
        // not, and this states exactly that.
        let unbuilt = Test {
            id: "test-only-unbuilt",
            title: "An anomaly that is not emitted yet",
            spec: "n/a",
            class: Class::Correctness,
            tier: Tier::Quic,
            expectation: "Never reached: the client meets a correct server.",
            implemented: false,
            port_offset: None,
        };
        let (v, d) = judge(&unbuilt, &Observation::SurvivedAndContinued, None);
        assert_eq!(v, Verdict::Inconclusive);
        assert!(d.contains("not implemented"), "say why: {d}");
    }

    #[test]
    fn valid_but_demanding_output_must_not_read_as_a_violation() {
        // These four send legal HTTP/3 the client has to decode. Scoring them
        // as Correctness reported "accepted a protocol violation" for doing
        // exactly what the specification asks.
        for id in [
            "h-qpack-huffman",
            "h-qpack-dynamic-table",
            "h-trailers",
            "h-oversized-field-section",
        ] {
            let t = test_of(id);
            assert_eq!(t.class, Class::Interoperability, "{id}");
            let (v, _) = judge(t, &Observation::SurvivedAndContinued, None);
            assert_eq!(v, Verdict::Pass, "{id}: decoding it is the pass");

            let (v, d) = judge(t, &Observation::ClosedWith { code: 0x0106 }, None);
            assert_eq!(v, Verdict::Fail, "{id}: rejecting valid output is the fail");
            assert!(d.contains("valid HTTP/3"), "{id}: say it was valid: {d}");
        }
    }

    #[test]
    fn a_may_level_requirement_accepts_either_choice() {
        // RFC 9114 §7.2.4.1 says a receiver MAY reject duplicate setting
        // identifiers. Scoring this as Correctness failed curl for making a
        // legal choice, which is the failure mode that would discredit the
        // whole suite.
        let t = test_of("h-duplicate-setting");
        let (v, d) = judge(t, &Observation::SurvivedAndContinued, None);
        assert_eq!(v, Verdict::Pass, "tolerating it is conformant");
        assert!(d.contains("permits"), "say why it passed: {d}");

        let (v, _) = judge(t, &Observation::ClosedWith { code: 0x0109 }, None);
        assert_eq!(v, Verdict::Pass, "rejecting it is equally conformant");

        // Stalling is not one of the permitted choices.
        let (v, _) = judge(t, &Observation::TimedOut, None);
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn a_timeout_is_a_failure_not_an_absence() {
        // The liveness probe exists precisely so this is distinguishable from
        // a pass. A client that silently died must not read as compliant.
        let t = test_of("h-grease-settings");
        let (v, _) = judge(t, &Observation::TimedOut, None);
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn resilience_rewards_recovery_however_it_is_signalled() {
        let t = test_of("h-goaway");
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, None);
        assert_eq!(v, Verdict::Pass);
        let (v, _) = judge(
            t,
            &Observation::Signalled("stopped opening new requests".into()),
            None,
        );
        assert_eq!(v, Verdict::Pass);
        // A *defined* HTTP/3 error code, because that is what an objection is.
        // This used to assert on 0x2, which is not an HTTP/3 error code at all —
        // RFC 9114 §8.1 makes unknown codes equivalent to H3_NO_ERROR, so it was
        // asserting that a clean close is a failure.
        let (v, _) = judge(
            t,
            &Observation::ClosedWith {
                code: crate::conformance::h3_frames::error_code::H3_INTERNAL_ERROR,
            },
            None,
        );
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
            s.record(t, &Observation::SurvivedAndContinued, None, 2);
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
    fn a_source_address_finds_the_session_it_started() {
        let reg = Registry::new(60, 8);
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        let id = reg.create();
        reg.associate(ip, &id);
        assert_eq!(reg.for_source(ip).as_deref(), Some(id.as_str()));

        // An address that started nothing gets nothing, rather than someone
        // else's session.
        let other: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        assert!(reg.for_source(other).is_none());
    }

    #[test]
    fn an_association_to_a_vanished_session_is_dropped() {
        let reg = Registry::new(60, 2);
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let first = reg.create();
        reg.associate(ip, &first);
        // Evict it by filling the registry past its cap.
        for _ in 0..4 {
            reg.create();
        }
        assert!(!reg.exists(&first));
        assert!(
            reg.for_source(ip).is_none(),
            "must not hand back a session that no longer exists"
        );
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
