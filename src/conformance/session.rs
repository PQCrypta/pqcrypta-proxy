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
    /// The client connected but no conclusion is available — it hung up early,
    /// the anomaly was never reached, or its answer could not be observed from
    /// this end.
    ///
    /// That last case is not a lesser kind of failure. A client can reject an
    /// anomaly exactly as the specification requires and have the close go
    /// missing, or never read the unidirectional stream the anomaly was written
    /// to before its one request completed. Neither is distinguishable here from
    /// a client that accepted the violation, so neither is reported as one.
    ///
    /// Deliberately distinct from `Fail`: an inconclusive run is our problem to
    /// explain, not the client's bug to fix, and folding the two together would
    /// produce reports that blame clients for what we could not see.
    ///
    /// It is also deliberately distinct from [`Unsupported`](Self::Unsupported),
    /// and that split was overdue. Until it existed this variant carried both
    /// "we failed to measure" and "the client told us it does not do this",
    /// which are opposites: one is a defect in the instrument and the other is
    /// the finding. In the 2026-09-18 matrix 63 of 199 inconclusive cells were
    /// the second kind -- a client advertising `SETTINGS_QPACK_MAX_TABLE_CAPACITY:
    /// 0`, or offering no key exchange group a port would negotiate -- and
    /// filing those under "no conclusion available" made a definite capability
    /// gap read as a gap in our own measurement.
    ///
    /// The bar is now: if this verdict appears, the suite has something to fix.
    Inconclusive,
    /// The client is definitively not capable of what the test is about, and
    /// said so itself.
    ///
    /// Not a failure and not a gap: an answer. A client that advertises a QPACK
    /// dynamic table capacity of zero has stated it will not use the dynamic
    /// table, and a client refused for offering no key exchange group this port
    /// negotiates has stated it cannot do that group. Both are facts about the
    /// client, established by the run, and both are the kind of thing someone
    /// reads this matrix to find out.
    ///
    /// Excluded from the pass rate for the same reason `Inconclusive` is --
    /// the client was never judged against the clause -- but reported as a
    /// result rather than as an absence of one.
    Unsupported,
    /// The client never attempted this test.
    NotRun,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Inconclusive => "inconclusive",
            Verdict::Unsupported => "unsupported",
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Observation {
    /// The liveness probe arrived and the client then closed cleanly, with no
    /// objection to the anomaly.
    ///
    /// A close is something the server *saw*. Where the anomaly was in the
    /// response the client read and delivered, that makes this evidence the
    /// violation was accepted.
    SurvivedAndContinued,
    /// The liveness probe arrived, and then nothing — no close, no objection,
    /// within the window the server waits.
    ///
    /// Deliberately distinct from [`SurvivedAndContinued`](Self::SurvivedAndContinued),
    /// which the two were folded into until it caused a false accusation of its
    /// own. A client can reject an anomaly correctly and have its
    /// CONNECTION_CLOSE lost — QUIC only re-sends one in answer to an incoming
    /// packet (RFC 9000 §10.2.1) — and from this end that is indistinguishable
    /// from a client that said nothing because it had nothing to say.
    ///
    /// For a class whose pass *is* carrying on, that distinction does not
    /// matter: the probe completing is the evidence, and it arrived. For a
    /// correctness test it matters entirely, because there the verdict turns on
    /// how the connection ended and this is the case where nobody saw.
    NoCloseObserved,
    /// The probe itself drew nothing: no close, and no acknowledgement either.
    ///
    /// [`NoCloseObserved`](Self::NoCloseObserved) means the server asked and a
    /// live peer declined to say anything. This means the server asked and
    /// cannot show anyone was listening. The two used to be one variant, and
    /// the difference is not cosmetic: 42 of 93 probes in the 2026-09-19
    /// matrix fell here, and for all of them the report claimed a PING had
    /// "ruled out a rejection whose close was lost". A PING that reached
    /// nobody rules out nothing, so that was a false statement about the
    /// evidence in nearly half the cases it was made.
    ///
    /// It is folded back into a pass wherever the pass was earned before the
    /// probe ran -- the follow-up request completing is what those classes
    /// measure, and it had already completed. Only the correctness tier turns
    /// on how the connection ended, and there this is the case where the
    /// instrument cannot show it was heard.
    PeerUnreachable,
    /// The client granted flow-control credit on the control stream after the
    /// anomaly went out, and then did not object to it.
    ///
    /// A receiver sends MAX_STREAM_DATA only once its application has consumed
    /// what was already sent, so a grant on *this* stream is the one signal
    /// that separates reading from receiving. With it, "completed the request
    /// and said nothing" stops being unanswerable: the client read the
    /// violation and accepted it.
    ///
    /// The probe behind this was withdrawn once, for a good reason that no
    /// longer holds. The version that was withdrawn proved a read by writing
    /// the client's whole advertised window, so whether a cell got a verdict
    /// was decided by the client's buffer size -- 100% at 64 KB, 9% around
    /// 1 MB, skipped above 4 MB -- and the column sorted by buffer size
    /// wearing a behaviour's clothes. The current one watches this stream's
    /// own credit and stops at the first grant, so a large window costs no
    /// more than a small one. Measured before rewiring it: msquic 10/10,
    /// picoquic 10/10, quic-go and aioquic 4/10, chromium 3/35, curl 0/10 --
    /// and curl's are all "connection lost", which is curl closing too fast
    /// rather than a window it was too expensive to fill.
    ReadThenSilent(String),
    /// The client closed the connection with this application error code.
    ClosedWith { code: u64 },
    /// The client closed without an error code, or the transport dropped.
    ClosedSilently,
    /// Nothing happened before the liveness timeout expired.
    TimedOut,
    /// The client objected, but at the QUIC layer, so no HTTP/3 error code was
    /// carried.
    ///
    /// Separate from [`Signalled`](Self::Signalled), which a test raises when it
    /// has seen the specific thing it was watching for. This is the opposite: an
    /// objection whose *content* could not be read. curl/ngtcp2 rejects HTTP/3
    /// violations this way — H3_MISSING_SETTINGS arrives as a transport
    /// INTERNAL_ERROR — so for a test whose requirement is a named code, the one
    /// thing being asked about is exactly what did not arrive.
    ///
    /// It used to be folded into `Signalled`, which made it a pass: the report
    /// said "Responded correctly" about a code it had never seen, while a client
    /// that did send an HTTP/3 code and got it slightly wrong was failed. The
    /// stricter client scored worse than the one that said less.
    ObjectedAtTransport(String),
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
    /// The client did something, and what it means cannot be established from
    /// here. Carries the sentence saying why, because the reason is the result.
    ///
    /// The counterpart to [`Observation::Violated`], for the case where the
    /// generic per-class wording would resolve an ambiguity the run did not.
    /// Distinct from [`NotExercised`](Self::NotExercised): the client *was* put
    /// in the situation the test is about — it simply answered in a way that
    /// admits more than one reading, and a suite that guesses between them is
    /// worse than one that says so.
    Ambiguous(String),
    /// The run completed but never put the client in the situation the test is
    /// about — a flow-control test where the request was too small to approach
    /// the window, say.
    ///
    /// Distinct from every other outcome because the alternative is a lie in
    /// one direction or the other: scoring it as a pass credits a client for
    /// something it was never asked to do, and scoring it as a failure accuses
    /// it of accepting a violation that was never sent. Neither is a result.
    ///
    /// Reserved, since 2026-09-19, for cases where *the run* fell short. Where
    /// the client itself closed the door -- it advertised that it will not use
    /// the feature, or offered nothing the port can negotiate -- the outcome is
    /// [`Unsupported`](Self::Unsupported), which is a finding rather than a
    /// hole. Every remaining `NotExercised` is a line on the suite's own bug
    /// list.
    NotExercised(String),
    /// The client stated, by its own configuration or its own refusal, that it
    /// does not do the thing the test is about.
    ///
    /// The distinction from [`NotExercised`](Self::NotExercised) is who fell
    /// short. "The request was too small to approach the window" is the run
    /// failing to set up the situation. "The client advertised a QPACK dynamic
    /// table capacity of zero, which forbids the server's encoder from using
    /// the table at all" is the client answering the question before it was
    /// asked -- and that answer is exactly what a reader wants.
    Unsupported(String),
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
    /// Why the oracle reached this verdict, where a rule changed it from what
    /// the observation alone would have given.
    pub reason: Option<&'static str>,
    pub elapsed_ms: u64,
    /// What the verdict was derived from. `None` only for a test never run.
    pub evidence: Option<Evidence>,
}

/// Turn an observation into a verdict, in light of what the test was measuring.
///
/// The asymmetry here is the whole reason [`Class`] exists:
///
/// - **Extensibility** — surviving is the pass. Any close is a failure, however
///   politely it was done, because the client was required to ignore something.
/// - **Correctness** — the *specific* error code is the pass.
/// - **Resilience** — surviving is the pass, and a clean close is a partial
///   failure rather than a crash, but both are failures.
///
/// # A failure needs positive evidence
///
/// For a correctness test it is tempting to read "no rejection arrived" as "the
/// client accepted it". That inference is unsound, and where the anomaly went
/// decides whether it is available at all.
///
/// A client must read the **response stream** to be served, so one that
/// delivered the response and closed cleanly demonstrably consumed the anomaly
/// and carried on. That is evidence, and it is a failure.
///
/// The **control stream** is unidirectional and nothing obliges a client to read
/// it at any particular moment. A one-shot request can finish and close before
/// the stream is picked up at all, so silence there is consistent with accepting
/// the violation *and* with never having seen it. Those are different states and
/// the server cannot tell them apart, so the honest verdict is inconclusive.
///
/// This is not hypothetical. `h-max-push-id` failed one external run in three
/// against a client that, run directly, rejected the frame with the required
/// code every single time: the request had simply finished before the control
/// stream was read. A published matrix saying a named library "accepted a
/// protocol violation" on that basis is the false accusation this suite exists
/// to avoid.
pub fn judge(test: &Test, obs: &Observation, expected_code: Option<u64>) -> (Verdict, String) {
    if !test.implemented {
        return (
            Verdict::Inconclusive,
            "This test's anomaly is not implemented yet, so the run proves nothing about \
             it either way."
                .to_string(),
        );
    }

    if let Observation::Unsupported(why) = obs {
        return (Verdict::Unsupported, format!("{why}."));
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
    //
    // Correctness is excluded: for those the meaning of a clean close depends on
    // whether the client can be shown to have read the anomaly at all, which is
    // decided below rather than here.
    if let Observation::ClosedWith { code } = obs {
        if test.class != Class::Correctness
            && !crate::conformance::h3_frames::error_code::is_rejection(*code)
        {
            return (
                Verdict::Pass,
                format!(
                    "Completed the exchange and closed cleanly (0x{code:x} is not an \
                     HTTP/3 error code, which §8.1 makes equivalent to H3_NO_ERROR)."
                ),
            );
        }
    }

    // ── The TLS tier reasons from the handshake, not from a response ──
    //
    // Every correctness arm below is written for an anomaly delivered over
    // HTTP/3, where the absence of an objection is genuinely ambiguous: the
    // client may have accepted the violation, or it may never have read it.
    //
    // On this tier it cannot be ambiguous. The anomaly is in the ServerHello,
    // so a client that established a connection at all has read it and carried
    // on regardless — and that is the dangerous outcome rather than a quiet
    // one. A client that completes against a corrupted ML-KEM half has used the
    // intact X25519 half alone and downgraded itself to exactly the security
    // level the hybrid exists to avoid.
    //
    // A client that rejected the handshake never reaches here: the listener
    // turns a failed TLS handshake into a `Signalled` observation, which the
    // correctness arms below already read as a pass.
    if test.tier == catalog::Tier::Tls
        && test.class == Class::Correctness
        && matches!(
            obs,
            Observation::SurvivedAndContinued
                | Observation::NoCloseObserved
                | Observation::PeerUnreachable
                | Observation::ClosedSilently
                | Observation::ClosedWith { .. }
        )
    {
        return (
            Verdict::Fail,
            "Completed the handshake against a ServerHello the specification requires it to \
             reject, then served the request over it. The anomaly is in the key exchange, so \
             a connection that was established at all is evidence the client read it and \
             accepted it."
                .to_string(),
        );
    }

    match (test.class, obs) {
        // ── Extensibility: the client had to ignore it and keep going ──
        (Class::Extensibility, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Ignored the unrecognised element and completed the follow-up request.".to_string(),
        ),
        (Class::Extensibility, Observation::NoCloseObserved) => (
            Verdict::Pass,
            "Ignored the unrecognised element and completed the follow-up request.".to_string(),
        ),
        // The pass was earned by the follow-up request, which completed before
        // the probe ran. Whether the client was still listening afterwards
        // does not bear on it, so the verdict is the same and the sentence
        // claims nothing about the probe.
        (Class::Extensibility, Observation::PeerUnreachable) => (
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
        (Class::Extensibility, Observation::ObjectedAtTransport(what)) => (
            Verdict::Fail,
            format!(
                "Closed the connection ({what}). The element was required to be ignored — \
                 rejecting an unknown extension is what causes protocol ossification."
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
        //
        // A rejection is always evidence, whichever stream the anomaly went to:
        // the client can only object to something it has read.
        (Class::Correctness, Observation::ClosedWith { code })
            if crate::conformance::h3_frames::error_code::is_rejection(*code) =>
        {
            match expected_code {
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
                // No named code means this test's requirement is a specific
                // transport-level behaviour — echoing a PATH_RESPONSE, going
                // quiet after a Stateless Reset — established by
                // `quic_observation`, not by anything an HTTP/3 close can show.
                // Reading a bare rejection as a pass would credit a client for a
                // behaviour nobody observed, which is the same unsound step as
                // reading silence as acceptance, pointed the other way.
                None => (
                    Verdict::Inconclusive,
                    format!(
                        "Closed with error 0x{code:x}. This test names no single required \
                         code: what it asks for is a particular transport-level response, \
                         and a close on its own does not show whether that happened."
                    ),
                ),
            }
        }
        (Class::Correctness, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Responded correctly: {what}."))
        }

        // An objection carrying no HTTP/3 error code.
        //
        // This read inconclusive on the grounds that a QUIC-layer close carries
        // no code, so calling it a failure would accuse a client of accepting a
        // violation it plainly rejected. That was a false choice. A failure here
        // does not say the client accepted anything -- it says the client did
        // not signal the way §8.1 requires, which is the same thing the arm
        // above says to a client that rejects with the wrong HTTP/3 code and
        // scores Fail for it. A close carrying no code at all is further from
        // the requirement than one carrying the wrong code, and it was being
        // scored more gently.
        //
        // What it cost: curl closes every one of these at the transport layer
        // with INTERNAL_ERROR -- "the endpoint encountered an internal error",
        // §20.1 -- and names an HTTP/3 error code nowhere in the catalogue, in
        // any test. Fifteen cells, every one unscored, which is most of why
        // that column read 0 fail and 20 inconclusive. The suite could not
        // score it because it never spoke the language the tests read, and
        // reported its own silence as an open question.
        //
        // Only where a code was named. Where the requirement is a transport-
        // level behaviour instead, a close still shows nothing either way and
        // the result stays inconclusive.
        (Class::Correctness, Observation::ObjectedAtTransport(what)) if expected_code.is_some() => {
            let want = expected_code.expect("guarded above");
            (
                Verdict::Fail,
                format!(
                    "Objected at the QUIC layer ({what}) instead of signalling the HTTP/3 \
                     error. The violation was detected and rejected, which is the right \
                     instinct; §8.1 requires an HTTP/3 connection error to be carried in \
                     an application close, and this test names 0x{want:x}. A transport \
                     close carries no HTTP/3 code at all, so a peer has no way to learn \
                     what was wrong."
                ),
            )
        }
        (Class::Correctness, Observation::ObjectedAtTransport(what)) => (
            Verdict::Inconclusive,
            format!(
                "Objected, but at the QUIC layer ({what}), which does not show whether \
                 the specific behaviour this test asks for occurred."
            ),
        ),

        // Nothing was observed at all, so there is nothing to reason from. This
        // is not the control-stream case below — it applies however the anomaly
        // was delivered, because a rejection that was sent and lost looks
        // exactly like a rejection that was never sent.
        (Class::Correctness, Observation::NoCloseObserved) => (
            Verdict::Inconclusive,
            "The client completed its request, said nothing further, and answered a PING \
             without closing. A peer in closing state re-sends its CONNECTION_CLOSE when a \
             packet arrives (RFC 9000 §10.2.1), and this one acknowledged the packet and \
             sent no close, so it was still there and had not rejected the anomaly. What it \
             did instead is the residue the suite has not yet found a way to read."
                .to_string(),
        ),
        (Class::Correctness, Observation::PeerUnreachable) => (
            Verdict::Inconclusive,
            "The client completed its request and then answered nothing at all — neither a \
             close nor an acknowledgement of the PING sent to elicit one. So this says less \
             than the case above it: the server cannot show the question was even received, \
             and a client that exited without closing looks from here exactly like one that \
             read the anomaly and carried on. Reported separately rather than as silence \
             from a live peer, which is a stronger claim than the run supports."
                .to_string(),
        ),

        // Proven to have read it, and said nothing.
        //
        // The unidirectional-stream case with the evidence that used to be
        // missing, so it is judged as the response-stream case is: the client
        // saw the violation and carried on.
        (Class::Correctness, Observation::ReadThenSilent(how)) => (
            Verdict::Fail,
            format!(
                "Accepted a protocol violation and carried on. The anomaly was on {}, and \
                 this client {how} -- a receiver extends credit on a stream only once its \
                 application has consumed what was already there, so the bytes were read \
                 rather than merely delivered. This should have been rejected.",
                catalog::anomaly_stream_name(test)
            ),
        ),
        // For the classes whose pass is carrying on, proving the read changes
        // nothing: carrying on was already the requirement.
        (
            Class::Extensibility
            | Class::Resilience
            | Class::Interoperability
            | Class::Discretionary,
            Observation::ReadThenSilent(_),
        ) => (
            Verdict::Pass,
            format!(
                "Read the element on {} and carried on, which is what this test asks for.",
                catalog::anomaly_stream_name(test)
            ),
        ),

        // Everything below is the *absence* of a rejection, which only means
        // something where the client had to read the anomaly to be served.
        (
            Class::Correctness,
            Observation::SurvivedAndContinued
            | Observation::ClosedSilently
            | Observation::ClosedWith { .. },
        ) if catalog::anomaly_may_be_unread(test) => (
            Verdict::Inconclusive,
            format!(
                "The client completed its request and closed without objecting, and the \
                 anomaly was on {} — a unidirectional stream nothing obliges it to read on \
                 any schedule. Accepting the violation and never reaching the stream look \
                 the same from here. The one signal that separates reading from receiving \
                 is a flow-control credit grant, and a receiver grants credit only as its \
                 consumption approaches the window it advertised, so a client with a large \
                 window reads everything sent and says nothing. Not a judgement withheld — \
                 a distinction this vantage point cannot draw for this client.",
                catalog::anomaly_stream_name(test)
            ),
        ),
        (Class::Correctness, Observation::SurvivedAndContinued) => (
            Verdict::Fail,
            "Accepted a protocol violation and carried on. The anomaly was in the response \
             the client read and delivered, so it was seen; this should have been rejected."
                .to_string(),
        ),
        (Class::Correctness, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Read the response carrying the violation, then closed without an error code. \
             The peer cannot tell what went wrong."
                .to_string(),
        ),
        (Class::Correctness, Observation::ClosedWith { code }) => (
            Verdict::Fail,
            format!(
                "Read the response carrying the violation and closed with 0x{code:x}, which \
                 §8.1 makes equivalent to no error at all. This should have been rejected."
            ),
        ),
        (Class::Correctness, Observation::TimedOut) if catalog::anomaly_may_be_unread(test) => (
            Verdict::Inconclusive,
            format!(
                "Nothing further arrived, and the anomaly was on {}, so there is no way to \
                 tell whether the client read it.",
                catalog::anomaly_stream_name(test)
            ),
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
        (Class::Resilience, Observation::NoCloseObserved) => (
            Verdict::Pass,
            "Recovered and completed the follow-up request.".to_string(),
        ),
        (Class::Resilience, Observation::PeerUnreachable) => (
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
        (Class::Resilience, Observation::ObjectedAtTransport(what)) => (
            Verdict::Fail,
            format!("Gave up ({what}) instead of recovering."),
        ),
        // A close carrying no error code is a graceful shutdown, not a
        // surrender.
        //
        // This was a flat Fail, which made the test reward the worse
        // behaviour: on a QUIC-tier test there are no critical streams, so the
        // liveness watcher is bypassed and the close alone decides -- and the
        // only way to pass was to walk away without closing at all.
        // `NoCloseObserved` passed; closing politely failed. Our own client
        // recovered from a refused 0-RTT, completed the request, returned 200
        // and closed cleanly, and was scored "Dropped the connection instead
        // of recovering" for the last of those.
        //
        // Giving up has its own arms: `ClosedWith` an error code, and
        // `ObjectedAtTransport`. Both are still failures here.
        (Class::Resilience, Observation::ClosedSilently) if test.tier == catalog::Tier::Quic => (
            Verdict::Pass,
            "Recovered, then closed the connection without an error code, which §8.1 makes \
             a graceful shutdown rather than an objection."
                .to_string(),
        ),
        // On the HTTP/3 tier there *is* a follow-up request, and completing it
        // is what recovery means -- a client that completes it reaches this
        // function as `SurvivedAndContinued`, not here. Reaching here means it
        // closed instead, politely or not.
        (Class::Resilience, Observation::ClosedSilently) => (
            Verdict::Fail,
            "Closed the connection without completing the follow-up request. The close \
             carried no error code, so nothing was objected to -- but recovering is what \
             this test asks for and the request never came."
                .to_string(),
        ),
        (Class::Resilience, Observation::TimedOut) => {
            (Verdict::Fail, "Stalled instead of recovering.".to_string())
        }

        // ── Interoperability: valid, demanding, and must be handled ──
        (Class::Interoperability, Observation::SurvivedAndContinued) => (
            Verdict::Pass,
            "Decoded it and completed the request.".to_string(),
        ),
        (Class::Interoperability, Observation::NoCloseObserved) => (
            Verdict::Pass,
            "Decoded it and completed the request.".to_string(),
        ),
        (Class::Interoperability, Observation::PeerUnreachable) => (
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
        (Class::Interoperability, Observation::ObjectedAtTransport(what)) => (
            Verdict::Fail,
            format!(
                "Rejected the response ({what}). Nothing here violates the specification — \
                 this is valid HTTP/3 that a client is required to be able to process."
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
        (Class::Discretionary, Observation::NoCloseObserved) => (
            Verdict::Pass,
            "Tolerated it and continued. The specification permits this but does not \
             require it; a client that rejected it would also be conformant."
                .to_string(),
        ),
        (Class::Discretionary, Observation::PeerUnreachable) => (
            Verdict::Pass,
            "Tolerated it and continued. The specification permits this but does not \
             require it; a client that rejected it would also be conformant."
                .to_string(),
        ),
        (Class::Discretionary, Observation::Signalled(what)) => {
            (Verdict::Pass, format!("Handled it: {what}."))
        }
        (Class::Discretionary, Observation::ObjectedAtTransport(what)) => (
            Verdict::Pass,
            format!(
                "Rejected it ({what}). The specification permits this but does not require \
                 it; a client that ignored it would also be conformant."
            ),
        ),
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
        (_, Observation::Unsupported(why)) => (Verdict::Unsupported, format!("{why}.")),
        (_, Observation::Violated(what)) => (Verdict::Fail, format!("{what}.")),

        // Same reasoning, pointed at the other outcome: the test has
        // established that nothing can be concluded here, and it says why in
        // its own words rather than through a per-class sentence written for a
        // case where something could.
        (_, Observation::Ambiguous(what)) => (Verdict::Inconclusive, format!("{what}.")),

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

/// The oracle: evidence in, verdict out.
///
/// A free function over `Evidence` and the catalogue entry, reading nothing
/// else. That is what makes a stored run replayable — the same evidence
/// through a later oracle gives the later verdict, with no client involved.
pub fn score(test: &'static Test, ev: &Evidence) -> (Verdict, String, Option<&'static str>) {
    let (verdict, detail) = judge(test, &ev.observation, ev.expected_code);

    // Only a verdict resting on an absence can be affected: the others were
    // reached from something the client did.
    let rests_on_absence = matches!(
        ev.observation,
        Observation::NoCloseObserved
            | Observation::ClosedSilently
            | Observation::TimedOut
            | Observation::PeerUnreachable
            | Observation::SurvivedAndContinued
            | Observation::ReadThenSilent(_)
            | Observation::Ambiguous(_)
    );
    let Some(exited) = ev.t_exit_ms else {
        return (verdict, detail, None);
    };
    if !rests_on_absence {
        return (verdict, detail, None);
    }

    // When the client had its chance, by the clause's own trigger.
    let opportunity: Option<u64> = match catalog::reaction_opportunity(test) {
        catalog::ReactionOpportunity::ExchangeCompleted => ev.t_exchange_completed_ms,
        // Consumption of the stream carrying the anomaly. The proof is a
        // boolean rather than an instant, so the opportunity is taken at the
        // point the anomaly was delivered: credit can only follow it.
        catalog::ReactionOpportunity::AnomalyStreamRead => match ev.read_proof {
            Some(true) => Some(ev.t_anomaly_ms),
            _ => None,
        },
        // The rejection is delivered in the handshake, so a client that
        // offered early data against a rejecting port has learned of it.
        catalog::ReactionOpportunity::HandshakeEarlyDataRejected => {
            if ev.zero_rtt_datagrams_in > 0 || ev.early_data_accepted {
                Some(ev.t_anomaly_ms)
            } else {
                None
            }
        }
        catalog::ReactionOpportunity::StillPresentAfter(ms) => Some(ev.t_anomaly_ms + ms),
    };

    let reached = exited >= ev.t_anomaly_ms && matches!(opportunity, Some(t) if exited >= t);
    if reached {
        return (verdict, detail, None);
    }

    let where_ = opportunity
        .map(|t| format!("{t}ms"))
        .unwrap_or_else(|| "never observed".to_string());
    let reason = Some("client_exit_before_reaction_opportunity");
    if verdict == Verdict::Fail {
        (
            Verdict::Inconclusive,
            format!(
                "The client process exited {}ms in, before it had the opportunity to react — the \
                 anomaly was delivered at {}ms and this test's reaction point is {}. What the \
                 server saw was: {} That is also what a client which had already gone looks \
                 like, so it is recorded as inconclusive rather than as a failure.",
                exited, ev.t_anomaly_ms, where_, detail
            ),
            reason,
        )
    } else {
        (
            verdict,
            format!(
                "{detail} The client process had already exited {exited}ms in, before this \
                 test's reaction point at {where_}, so the silence after that is not evidence \
                 either way."
            ),
            reason,
        )
    }
}

/// Everything a verdict is derived from, stored so it can be derived again.
///
/// The verdict used to be the primary artefact and its inputs were discarded
/// the moment it was computed. That made an oracle correction unreplayable:
/// changing how a silence is judged meant re-executing twelve clients against
/// the wire, because the only record of what they had done was a sentence
/// written by the previous oracle. It also made a correction unauditable --
/// the one honest way to check a re-score was to run it again and hope the
/// clients behaved the same.
///
/// So the pipeline is now
///
/// ```text
/// client run -> observations -> stored evidence -> oracle(v) -> verdict
/// ```
///
/// and the verdict is derived. An oracle-only correction no longer needs a
/// rerun **where the evidence it consults was persisted** -- which is the
/// honest form of that promise, since a future oracle may need an input this
/// struct does not carry, and then a rerun is the correct answer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    /// The catalogue entry, by id, and the version of the definition used.
    pub test_id: String,
    pub test_version: u32,
    /// What the connection did.
    pub observation: Observation,
    /// The error code the clause names, where it names one.
    pub expected_code: Option<u64>,
    /// Whether the read proof established that the client consumed the
    /// stream carrying the anomaly. `None` where the question was not put.
    pub read_proof: Option<bool>,
    /// Whether the handshake accepted early data, and whether any arrived.
    pub early_data_accepted: bool,
    pub zero_rtt_datagrams_in: u64,
    /// The timeline, in milliseconds from the connection's start.
    pub t_anomaly_ms: u64,
    pub t_exchange_completed_ms: Option<u64>,
    pub t_observation_end_ms: u64,
    /// When the driver's client process exited, where it reported one.
    pub t_exit_ms: Option<u64>,
    /// Which connection within the session produced this, and when it was
    /// stored.
    ///
    /// One test can be answered by several connections -- the 0-RTT wrapper
    /// connects twice, browsers reconnect two to four times -- and a report
    /// is a snapshot of whichever had been recorded when it was taken. Without
    /// these a cell cannot say which evidence its verdict consumed, and a
    /// report collected between two connections is indistinguishable from one
    /// that disagrees with the run. That cost half an hour to tell apart once.
    pub connection_seq: u64,
    pub recorded_at_ms: u64,
}

impl Evidence {
    /// Whether this connection learned anything about the client's handling.
    ///
    /// `NotExercised` says outright that the client was never put in the
    /// situation. `Ambiguous` is a connection that ended without anything
    /// readable — the shape a browser's extra reconnect takes when it sits
    /// idle until its own pre-handshake timeout. Neither is a reason to
    /// discard a connection that did observe something.
    ///
    /// Everything else is informative even when it is unwelcome: a silence
    /// that followed a demonstrated read is evidence, and so is a close
    /// carrying the wrong code.
    pub fn informative(&self) -> bool {
        !matches!(
            self.observation,
            Observation::NotExercised(_) | Observation::Ambiguous(_)
        )
    }

    /// Whether early data from this connection reached the endpoint, by the
    /// count taken off the wire for this connection alone.
    ///
    /// Not `early_data_accepted`: on the replay port that is set for every
    /// connection, since a server's `into_0rtt` always succeeds.
    pub fn met_early_data(&self) -> bool {
        self.zero_rtt_datagrams_in > 0
    }
}

/// The oracle that turned this evidence into a verdict.
///
/// Stored beside the verdict so a matrix states which rules produced it, and
/// so two matrices can be compared without guessing whether a difference came
/// from the clients or from us.
pub const ORACLE_VERSION: &str = "reaction-opportunity/2";

/// One client's walk through the catalogue.
pub struct Session {
    pub id: String,
    created: Instant,
    /// The evidence, by test. The verdicts are derived from this.
    evidence: HashMap<&'static str, Evidence>,
    /// When the driver's client process exited, per test, in milliseconds
    /// from the moment it was invoked.
    ///
    /// A verdict that rests on silence is ambiguous in a specific way: the
    /// client may have read the anomaly and carried on, or it may not have
    /// been there any more. Only the driver knows which, because only the
    /// driver holds the process, so it posts the exit and the report reads
    /// the two together.
    client_exit_ms: HashMap<String, u64>,
    /// Connections recorded into this session, in order.
    recorded: u64,
    /// When a connection on each test's port first completed its exchange.
    ///
    /// The server issues its session tickets as the handshake completes, so a
    /// client that has completed an exchange here holds tickets for this port.
    /// A connection it opens *after* that instant and does not resume on has
    /// declined to resume, which is an answer about the client; one opened
    /// before it never had a ticket to use. The 0-RTT tests read the
    /// difference.
    first_exchange_completed: HashMap<&'static str, Instant>,
    /// Readings taken of this session, in order.
    ///
    /// A report is a reading at an instant, and the session keeps moving under
    /// it: the 0-RTT wrapper connects twice, a browser reconnects two to four
    /// times. Two readings taken either side of one of those legitimately
    /// differ, and with nothing naming the instant that is indistinguishable
    /// from two accounts of the *same* instant disagreeing -- which is a
    /// persistence defect and a far more serious thing. Numbering the readings
    /// is what lets an auditor tell those two apart without re-deriving the
    /// timeline by hand.
    snapshots: u64,
    /// Whether this session's machine-readable report has been collected.
    ///
    /// The driver reads `/report/<id>.json` once, at the end, after it has
    /// driven every test it intends to. That read is the only signal this
    /// endpoint gets that a run is over -- there is no goodbye -- and it is what
    /// separates the two ways a session loses its source-address association:
    /// the ordinary one, where the next run starts after this one finished, and
    /// the damaging one in [`Registry::associate`], where a run still being
    /// driven has its connections taken.
    reported: bool,
}

impl Session {
    fn new(id: String) -> Self {
        Self {
            id,
            created: Instant::now(),
            evidence: HashMap::new(),
            client_exit_ms: HashMap::new(),
            recorded: 0,
            first_exchange_completed: HashMap::new(),
            snapshots: 0,
            reported: false,
        }
    }

    /// Note that a connection on `test`'s port completed its exchange at `at`.
    pub fn note_exchange_completed(&mut self, test: &'static Test, at: Instant) {
        self.first_exchange_completed
            .entry(test.id)
            .and_modify(|first| *first = (*first).min(at))
            .or_insert(at);
    }

    /// Whether any connection in this session has completed an exchange.
    pub fn completed_any_exchange(&self) -> bool {
        !self.first_exchange_completed.is_empty()
    }

    /// Whether an earlier connection on `test`'s port had completed its
    /// exchange -- and so held this port's session tickets -- before `started`.
    pub fn held_tickets_before(&self, test: &'static Test, started: Instant) -> bool {
        self.first_exchange_completed
            .get(test.id)
            .is_some_and(|first| *first < started)
    }

    /// Record that the driver's client process for one test has exited.
    ///
    /// Kept whether or not a verdict exists yet: the driver posts this as it
    /// goes and the report is composed at the end, so the two arrive in no
    /// guaranteed order.
    pub fn note_client_exit(&mut self, test_id: &str, elapsed_ms: u64) {
        self.client_exit_ms.insert(test_id.to_string(), elapsed_ms);
        // The driver posts this after the connection has ended, so the
        // evidence usually exists already and is completed in place. Where it
        // does not, the map above carries it until the evidence arrives.
        if let Some(ev) = self.evidence.get_mut(test_id) {
            ev.t_exit_ms = Some(elapsed_ms);
        }
    }

    /// How long after invocation the client process for this test exited.
    pub fn client_exit_ms(&self, test_id: &str) -> Option<u64> {
        self.client_exit_ms.get(test_id).copied()
    }

    /// Note that the results have been collected, so this run is over.
    ///
    /// Only the JSON form counts. A person opening the HTML report in a browser
    /// while a run is going is a reader, not a driver, and must not quietly
    /// disarm the collision warning for the run they are watching.
    pub fn mark_reported(&mut self) {
        self.reported = true;
    }

    /// Record an outcome. A test re-run within the same session overwrites its
    /// previous result — clients under active development re-run constantly,
    /// and a report that accumulated every historical attempt would be unusable.
    /// Store the evidence for one test, and derive its verdict from it.
    ///
    /// The evidence is the record. The verdict is computed here so the live
    /// report has one, and recomputed from the same evidence by anything that
    /// re-scores a stored run — the two cannot disagree, because there is only
    /// one oracle and it reads only what is stored.
    pub fn record_evidence(&mut self, test: &'static Test, ev: Evidence) {
        // A connection that learned nothing must not overwrite one that did.
        //
        // One test can be answered by more than one connection: the 0-RTT
        // ports are driven by a wrapper that connects twice and only the
        // resume is the measurement, and clients open two to four connections
        // per session, so a late reconnect that sat idle must not erase the
        // one that established the finding.
        //
        // Decided on the evidence, deliberately, and not on the verdict it
        // would produce. Keying it on the verdict would mean a future oracle
        // could change *which raw observation survives* — the stored record
        // would then depend on the scoring rules, which is the coupling this
        // whole refactor exists to remove.
        if !ev.informative() {
            if let Some(existing) = self.evidence.get(test.id) {
                if existing.informative() {
                    tracing::info!(
                        "conformance: {} keeping the connection that exercised it, rather than \
                         a later one that did not",
                        test.id
                    );
                    return;
                }
            }
        }
        // On the 0-RTT ports, the connection whose early data arrived is the
        // measurement, and a later one without early data is not an answer
        // to the same question. A client whose 0-RTT is refused may well
        // retry on a fresh connection -- our own h3-get does, as RFC 9001
        // §4.6.2 invites -- and that retry resumes without early data. Once
        // "resumes but offers none" became an informative verdict, the retry
        // overwrote the refusal it was recovering from, and our client read
        // as never sending early data on the one port that had refused it.
        if matches!(test.id, "q-zero-rtt-reject" | "q-zero-rtt-replay") && !ev.met_early_data() {
            if let Some(existing) = self.evidence.get(test.id) {
                if existing.met_early_data() {
                    tracing::info!(
                        "conformance: {} keeping the connection whose early data arrived, \
                         rather than a later one that sent none",
                        test.id
                    );
                    return;
                }
            }
        }
        let mut ev = ev;
        if ev.t_exit_ms.is_none() {
            ev.t_exit_ms = self.client_exit_ms.get(test.id).copied();
        }
        self.recorded += 1;
        ev.connection_seq = self.recorded;
        ev.recorded_at_ms = self
            .created
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        self.evidence.insert(test.id, ev);
    }

    /// Every catalogue entry, with `NotRun` filled in for those untouched.
    ///
    /// Derived, every time, from the stored evidence. The report always lists
    /// the full catalogue: a client that connected once and gave up should
    /// show its untouched rows rather than a single pass and a misleading
    /// 100%.
    pub fn results(&self) -> Vec<Result_> {
        catalog::CATALOG
            .iter()
            .map(|t| match self.evidence.get(t.id) {
                Some(ev) => {
                    let (verdict, detail, reason) = score(t, ev);
                    Result_ {
                        test_id: t.id,
                        verdict,
                        detail,
                        reason,
                        elapsed_ms: ev.t_observation_end_ms,
                        evidence: Some(ev.clone()),
                    }
                }
                None => Result_ {
                    test_id: t.id,
                    verdict: Verdict::NotRun,
                    detail: "Not attempted.".to_string(),
                    reason: None,
                    elapsed_ms: 0,
                    evidence: None,
                },
            })
            .collect()
    }

    /// Take a numbered reading of this session.
    ///
    /// Everything that renders a session -- the JSON report, the HTML one, the
    /// badge -- goes through here, so every reading carries what identifies it:
    /// which reading it was, how long after the session started it was taken,
    /// and how many connections had been recorded by then. Comparing a stored
    /// verdict against the live server is then a comparison between two
    /// identified instants rather than between two unlabelled ones.
    pub fn snapshot(&mut self) -> Snapshot {
        self.snapshots += 1;
        Snapshot {
            seq: self.snapshots,
            collected_at_ms: self
                .created
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            connections_recorded: self.recorded,
            results: self.results(),
        }
    }

    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }
}

/// One reading of a session, with what identifies the reading.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Which reading of this session this was, counting from one.
    pub seq: u64,
    /// When it was taken, in milliseconds from the session's start.
    pub collected_at_ms: u64,
    /// How many connections had been recorded when it was taken. A cell whose
    /// evidence carries a higher `connection_seq` than this cannot have been
    /// in the reading, which is the check that distinguishes a stale report
    /// from a disagreeing one.
    pub connections_recorded: u64,
    pub results: Vec<Result_>,
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
    ///
    /// Last writer wins, and the displaced session keeps running: its client
    /// carries on making connections, and every one of them is now recorded
    /// against whoever associated most recently. Nothing fails, nothing is
    /// logged by the transport, and both reports come back looking plausible.
    ///
    /// That is not hypothetical. Two matrix runs were started from this host
    /// twenty seconds apart on 2026-09-17, and the second one's `POST /session`
    /// silently took the first one's in-flight client mid-run. The only reason
    /// it was caught is that a human happened to be watching both.
    ///
    /// So a collision is now said out loud. It cannot be *prevented* here --
    /// the second caller is entitled to a session, and refusing it would break
    /// the ordinary case of a developer starting a fresh run after an abandoned
    /// one -- but a run whose results are suspect should be visible in the log
    /// at the moment it happens, rather than inferred from a strange row a week
    /// later.
    pub fn associate(&self, ip: std::net::IpAddr, id: &str) {
        if let Some((prev_id, recorded)) = self.displaced_by(ip, id) {
            tracing::warn!(
                "conformance: session {id} claimed {ip}, which session {prev_id} was already \
                 using after {recorded} recorded result(s). Both runs now share one \
                 association and the later one takes every connection: treat both reports as \
                 contaminated"
            );
        }
        self.by_source.insert(ip, (id.to_string(), Instant::now()));
    }

    /// The live session `id` is about to take `ip` from, and how much that
    /// session has already recorded.
    ///
    /// `None` in every ordinary case: no previous association, the same session
    /// re-associating, an expired one, a session that has since been swept, one
    /// that recorded nothing — a client that opened a session and never ran a
    /// test loses nothing by being displaced — and, most importantly, one whose
    /// report has already been collected.
    ///
    /// That last condition is what makes this warning worth reading. Without it
    /// the check fired on every ordinary sequential run: the association lives
    /// for `session_ttl_secs`, an hour in the shipped configuration, so a matrix
    /// run driving seven clients one after another would have logged six
    /// collisions and every one of them would have been a lie. A warning that
    /// appears on every healthy run teaches the reader to skip it, which is
    /// worse than no warning at all -- the first version of this guard had that
    /// defect and it was caught by running the thing it was written to protect.
    fn displaced_by(&self, ip: std::net::IpAddr, id: &str) -> Option<(String, usize)> {
        // Read and drop the guard before the caller inserts: holding one on
        // `by_source` across that insert would deadlock the map against itself.
        let prev_id = {
            let entry = self.by_source.get(&ip)?;
            let (prev_id, since) = entry.value();
            if prev_id == id || since.elapsed() >= self.ttl {
                return None;
            }
            prev_id.clone()
        };
        let (recorded, reported) = self.with(&prev_id, |s| (s.evidence.len(), s.reported))?;
        (recorded > 0 && !reported).then_some((prev_id, recorded))
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

    /// Record an observation with a plausible timeline, for tests about
    /// something other than the timeline itself.
    fn record_obs(
        s: &mut Session,
        t: &'static Test,
        obs: &Observation,
        code: Option<u64>,
        end_ms: u64,
    ) {
        s.record_evidence(
            t,
            Evidence {
                test_id: t.id.to_string(),
                test_version: 1,
                observation: obs.clone(),
                expected_code: code,
                read_proof: Some(true),
                early_data_accepted: true,
                zero_rtt_datagrams_in: 1,
                t_anomaly_ms: 0,
                t_exchange_completed_ms: Some(1),
                t_observation_end_ms: end_ms,
                t_exit_ms: None,
                connection_seq: 0,
                recorded_at_ms: 0,
            },
        );
    }

    fn ev(obs: Observation, t_anomaly: u64, exch: Option<u64>, exit: Option<u64>) -> Evidence {
        Evidence {
            test_id: "q-retry".to_string(),
            test_version: 1,
            observation: obs,
            expected_code: None,
            read_proof: None,
            early_data_accepted: false,
            zero_rtt_datagrams_in: 0,
            t_anomaly_ms: t_anomaly,
            t_exchange_completed_ms: exch,
            t_observation_end_ms: 8_000,
            t_exit_ms: exit,
            connection_seq: 1,
            recorded_at_ms: 0,
        }
    }

    /// The property the whole refactor exists for: a stored run can be scored
    /// again without the client. Evidence through the oracle, then the same
    /// evidence through serialisation and back, must give the same verdict —
    /// otherwise "re-score instead of rerun" is a promise the format cannot
    /// keep.
    #[test]
    fn evidence_survives_a_round_trip_and_scores_identically() {
        let t = test_of("h-goaway-increasing");
        let mut e = ev(
            Observation::ReadThenSilent("extended flow-control credit on it".into()),
            92,
            None,
            Some(250),
        );
        e.read_proof = Some(true);
        e.early_data_accepted = true;
        e.zero_rtt_datagrams_in = 7;
        e.expected_code = Some(0x105);

        let live = score(t, &e);
        let json = serde_json::to_string(&e).expect("evidence serialises");
        let back: Evidence = serde_json::from_str(&json).expect("evidence deserialises");

        // Every field the oracle can consult survives the round trip.
        assert_eq!(back.observation, e.observation);
        assert_eq!(back.read_proof, Some(true));
        assert!(back.early_data_accepted);
        assert_eq!(back.zero_rtt_datagrams_in, 7);
        assert_eq!(back.expected_code, Some(0x105));
        assert_eq!(back.t_anomaly_ms, 92);
        assert_eq!(back.t_exchange_completed_ms, None);
        assert_eq!(back.t_observation_end_ms, 8_000);
        assert_eq!(back.t_exit_ms, Some(250));
        assert_eq!(back.test_version, 1);

        let replayed = score(t, &back);
        assert_eq!(live.0, replayed.0, "verdict differs after a round trip");
        assert_eq!(live.1, replayed.1, "detail differs after a round trip");
        assert_eq!(live.2, replayed.2, "reason differs after a round trip");
    }

    /// The cell that demonstrated the oracle defect. msquic consumed the
    /// control stream carrying the second GOAWAY — RFC 9114 §5.2 ties the
    /// duty to that receipt — and then never completed an HTTP exchange,
    /// which is reasonable for a client told to stop opening requests.
    #[test]
    fn a_read_proof_is_the_opportunity_where_receipt_is_the_trigger() {
        let t = test_of("h-goaway-increasing");
        let mut e = ev(
            Observation::ReadThenSilent("credit".into()),
            92,
            None,
            Some(250),
        );
        e.read_proof = Some(true);
        let (v, _, reason) = score(t, &e);
        assert_eq!(v, Verdict::Fail, "it read the GOAWAY and said nothing");
        assert_eq!(reason, None);
    }

    #[test]
    fn without_a_read_proof_that_opportunity_is_unobserved() {
        let t = test_of("h-goaway-increasing");
        let mut e = ev(Observation::ReadThenSilent("x".into()), 92, None, Some(250));
        e.read_proof = None;
        let (v, _, reason) = score(t, &e);
        assert_eq!(v, Verdict::Inconclusive);
        assert_eq!(reason, Some("client_exit_before_reaction_opportunity"));
    }

    /// The thin-wrapper case: completed its exchange, then exited.
    #[test]
    fn a_wrapper_that_completed_its_exchange_and_exited_keeps_its_failure() {
        let t = test_of("h-push-promise-unsolicited");
        let e = ev(Observation::SurvivedAndContinued, 120, Some(240), Some(260));
        let (v, _, reason) = score(t, &e);
        assert_eq!(v, Verdict::Fail);
        assert_eq!(reason, None);
    }

    #[test]
    fn a_client_gone_before_the_anomaly_was_delivered_is_inconclusive() {
        let t = test_of("h-push-promise-unsolicited");
        let e = ev(Observation::SurvivedAndContinued, 120, Some(240), Some(90));
        assert_eq!(score(t, &e).0, Verdict::Inconclusive);
    }

    #[test]
    fn a_verdict_the_client_answered_is_untouched_whenever_it_left() {
        let t = test_of("h-push-promise-unsolicited");
        let e = ev(
            Observation::Signalled("rejected it".into()),
            120,
            Some(240),
            Some(10),
        );
        let (v, _, reason) = score(t, &e);
        assert_eq!(v, Verdict::Pass);
        assert_eq!(reason, None);
    }

    #[test]
    fn nothing_is_claimed_about_a_client_whose_exit_was_never_reported() {
        let t = test_of("h-push-promise-unsolicited");
        let e = ev(Observation::SurvivedAndContinued, 120, None, None);
        let (v, _, reason) = score(t, &e);
        assert_eq!(
            v,
            Verdict::Fail,
            "a driver that does not post changes nothing"
        );
        assert_eq!(reason, None);
    }

    /// The overwrite guard reads the evidence, not the verdict, so a later
    /// oracle cannot change which raw observation survives.
    #[test]
    fn a_connection_that_learned_nothing_does_not_replace_one_that_did() {
        let t = test_of("h-push-promise-unsolicited");
        let mut s = Session::new("s".to_string());
        s.record_evidence(
            t,
            ev(Observation::SurvivedAndContinued, 120, Some(240), None),
        );
        s.record_evidence(
            t,
            ev(
                Observation::Ambiguous("idle timeout".into()),
                120,
                None,
                None,
            ),
        );
        let kept = s.evidence.get(t.id).expect("evidence kept");
        assert!(matches!(
            kept.observation,
            Observation::SurvivedAndContinued
        ));
    }

    use super::*;
    use crate::conformance::catalog::{self, Class, Test, Tier};

    /// A client's own retry after its early data was refused resumes without
    /// early data; it must not replace the connection that met the refusal.
    #[test]
    fn a_retry_without_early_data_does_not_replace_the_refusal() {
        let t = catalog::find("q-zero-rtt-reject").expect("the test exists");
        let mut s = Session::new("s".into());
        let mut refused = ev(Observation::SurvivedAndContinued, 1, Some(1), Some(900));
        refused.zero_rtt_datagrams_in = 5;
        s.record_evidence(t, refused);
        let retry = ev(
            Observation::Unsupported("resumes a session but does not offer early data".into()),
            1,
            Some(1),
            Some(900),
        );
        s.record_evidence(t, retry);
        assert_eq!(s.evidence[t.id].zero_rtt_datagrams_in, 5);
        assert!(matches!(
            s.evidence[t.id].observation,
            Observation::SurvivedAndContinued
        ));
    }

    /// A ticket counts only if the exchange that delivered it finished before
    /// the later connection began: one opened in parallel never had it.
    #[test]
    fn tickets_are_held_only_after_an_earlier_exchange_completed() {
        let t = catalog::find("q-zero-rtt-reject").expect("the test exists");
        let other = catalog::find("q-zero-rtt-replay").expect("the test exists");
        let mut s = Session::new("s".into());
        let t0 = Instant::now();
        let later = t0 + Duration::from_millis(50);
        assert!(!s.held_tickets_before(t, later), "nothing completed yet");

        s.note_exchange_completed(t, t0 + Duration::from_millis(20));
        assert!(s.held_tickets_before(t, later));
        assert!(
            !s.held_tickets_before(t, t0 + Duration::from_millis(10)),
            "a connection that began before the exchange finished held nothing"
        );
        assert!(!s.held_tickets_before(other, later), "tickets are per port");

        // A later completion does not move the first one.
        s.note_exchange_completed(t, t0 + Duration::from_millis(40));
        assert!(s.held_tickets_before(t, t0 + Duration::from_millis(30)));
    }

    #[test]
    fn a_connection_that_did_not_exercise_the_test_does_not_overwrite_one_that_did() {
        // The 0-RTT wrapper connects twice: once to be issued a ticket, once
        // to resume and offer early data. Only the second measures anything,
        // and the first can finish afterwards — measured at 20 seconds after,
        // because its server-side connection outlived the resume entirely.
        let t = catalog::find("q-zero-rtt-replay").expect("the test exists");
        let mut sess = Session::new("overwrite-test".into());

        // The resume answers, immediately and correctly.
        record_obs(
            &mut sess,
            t,
            &Observation::ObjectedAtTransport("rejected at the QUIC layer".into()),
            None,
            0,
        );
        let after_resume = sess
            .results()
            .iter()
            .find(|r| r.test_id == t.id)
            .expect("recorded")
            .verdict;
        assert_ne!(
            after_resume,
            Verdict::Inconclusive,
            "the resume produced a verdict"
        );

        // The priming connection lands twenty seconds later with nothing.
        record_obs(
            &mut sess,
            t,
            &Observation::NotExercised("the client sent no early data".into()),
            None,
            20_003,
        );
        assert_eq!(
            sess.results()
                .iter()
                .find(|r| r.test_id == t.id)
                .expect("still recorded")
                .verdict,
            after_resume,
            "a connection that exercised nothing must not replace one that did"
        );
    }

    #[test]
    fn a_later_connection_may_still_improve_an_inconclusive_result() {
        // The rule is one-directional: `NotExercised` never overwrites, but
        // anything may replace an inconclusive, or a test that genuinely goes
        // unexercised could never be corrected by a later connection that
        // reached it.
        let t = catalog::find("q-zero-rtt-replay").expect("the test exists");
        let mut sess = Session::new("improve-test".into());
        record_obs(
            &mut sess,
            t,
            &Observation::NotExercised("nothing yet".into()),
            None,
            1,
        );
        assert_eq!(
            sess.results()
                .iter()
                .find(|r| r.test_id == t.id)
                .unwrap()
                .verdict,
            Verdict::Inconclusive
        );
        record_obs(
            &mut sess,
            t,
            &Observation::ObjectedAtTransport("rejected at the QUIC layer".into()),
            None,
            2,
        );
        assert_ne!(
            sess.results()
                .iter()
                .find(|r| r.test_id == t.id)
                .unwrap()
                .verdict,
            Verdict::Inconclusive,
            "a connection that reached the anomaly must be able to replace an inconclusive"
        );
    }

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

        // Silence is NOT the bug being hunted. This anomaly is on the control
        // stream, so a client that finished its request and closed without
        // objecting may equally never have read it.
        let (v, d) = judge(t, &Observation::SurvivedAndContinued, Some(want));
        assert_eq!(v, Verdict::Inconclusive);
        assert!(
            d.contains("control stream"),
            "say why nothing can be concluded: {d}"
        );
    }

    /// A failure has to rest on evidence the client saw the anomaly.
    ///
    /// The two halves of this were one rule until an external run failed
    /// `h-max-push-id` against a client that, driven directly, rejected the
    /// frame with the required code six times out of six. The request had simply
    /// completed before the control stream was read, and "no rejection arrived"
    /// was being read as "accepted a protocol violation" — a published claim
    /// about a named library, drawn from the absence of evidence.
    #[test]
    fn a_correctness_failure_needs_evidence_the_anomaly_was_read() {
        // Response stream: the client had to read it to be served, so finishing
        // and closing cleanly proves it saw the violation and carried on.
        let seen = test_of("h-data-before-headers");
        let (v, d) = judge(&seen, &Observation::SurvivedAndContinued, Some(0x0105));
        assert_eq!(v, Verdict::Fail, "the client demonstrably read this one");
        assert!(d.contains("response"), "say why it counts: {d}");

        // Control stream: nothing obliges a client to read it before closing.
        for id in [
            "h-missing-settings",
            "h-control-frame-unexpected",
            "h-second-control-stream",
            "h-max-push-id",
            "h-cancel-push-unsolicited",
        ] {
            let t = test_of(id);
            let (v, _) = judge(t, &Observation::SurvivedAndContinued, expected_of(t));
            assert_eq!(
                v,
                Verdict::Inconclusive,
                "{id}: silence on a control-stream anomaly proves nothing"
            );
            let (v, _) = judge(t, &Observation::ClosedSilently, expected_of(t));
            assert_eq!(
                v,
                Verdict::Inconclusive,
                "{id}: a clean close proves nothing"
            );

            // A rejection is always evidence, whichever stream it answers.
            let want = expected_of(t).expect("a correctness test names its code");
            let (v, _) = judge(t, &Observation::ClosedWith { code: want }, Some(want));
            assert_eq!(v, Verdict::Pass, "{id}: the required code is still a pass");

            // And so is the wrong one: the client objected, just badly.
            let (v, _) = judge(t, &Observation::ClosedWith { code: 0x0101 }, Some(want));
            assert_eq!(v, Verdict::Fail, "{id}: rejecting with the wrong code");
        }
    }

    /// Seeing nothing is not the same as seeing a clean close.
    ///
    /// Both used to be one observation, and the collapse produced a false
    /// accusation on a *response-stream* test — where the reasoning "the client
    /// had to read this to be served" is otherwise sound. `h-data-before-headers`
    /// was published as a failure against a client that rejects the frame with
    /// the required code six times out of six: its CONNECTION_CLOSE had simply
    /// gone missing, and a lost rejection looks exactly like no rejection.
    #[test]
    fn nothing_observed_is_never_a_correctness_failure() {
        // Response stream, so acceptance *is* observable in principle.
        let t = test_of("h-data-before-headers");
        let want = crate::conformance::h3_frames::error_code::H3_FRAME_UNEXPECTED;

        // Seen to close cleanly: it read the violation and did not object.
        let (v, _) = judge(t, &Observation::SurvivedAndContinued, Some(want));
        assert_eq!(v, Verdict::Fail);

        // A live peer that said nothing: no evidence either way, and the
        // report may say the peer was there, because the probe was answered.
        let (v, d) = judge(t, &Observation::NoCloseObserved, Some(want));
        assert_eq!(v, Verdict::Inconclusive);
        assert!(
            d.contains("acknowledged the packet"),
            "say what the probe established: {d}"
        );

        // A peer that answered nothing at all. Also inconclusive, but for a
        // weaker reason, and the report must not borrow the stronger one: a
        // PING that drew no acknowledgement rules nothing out. This assertion
        // is the guard -- the two texts were one sentence until 2026-09-19,
        // and it claimed a lost rejection had been ruled out in 42 of the 93
        // cases it was printed in.
        let (v, d) = judge(t, &Observation::PeerUnreachable, Some(want));
        assert_eq!(v, Verdict::Inconclusive);
        assert!(
            d.contains("neither a close nor an acknowledgement"),
            "say that nothing came back: {d}"
        );
        assert!(
            !d.contains("rules out"),
            "an unanswered probe rules nothing out: {d}"
        );

        // For the classes whose pass is carrying on, the probe completing is
        // the evidence and what happens afterwards changes nothing -- whether
        // the peer went quiet or went away.
        for (id, class) in [
            ("h-grease-settings", Class::Extensibility),
            ("h-trailers", Class::Interoperability),
            ("h-goaway", Class::Resilience),
            ("h-duplicate-setting", Class::Discretionary),
        ] {
            let t = test_of(id);
            assert_eq!(t.class, class, "{id} changed class");
            for obs in [Observation::NoCloseObserved, Observation::PeerUnreachable] {
                let (v, _) = judge(t, &obs, None);
                assert_eq!(
                    v,
                    Verdict::Pass,
                    "{id}/{obs:?}: the follow-up request completed"
                );
            }
        }
    }

    /// An objection with no readable code does not meet a named-code clause.
    ///
    /// curl/ngtcp2 rejects HTTP/3 violations by closing at the QUIC layer, so
    /// H3_MISSING_SETTINGS arrives as a transport INTERNAL_ERROR and the code the
    /// clause names is never on the wire. Scoring that "Responded correctly" gave
    /// the quietest client the best score in the published matrix, while clients
    /// that did send an HTTP/3 code and got it wrong were failed.
    ///
    /// It was then inconclusive for a year, which was the same mistake in a
    /// softer form: a close carrying no code at all is further from the clause
    /// than one carrying the wrong code, and the wrong code has always been a
    /// failure. The two are asserted together here so they cannot drift apart
    /// again.
    #[test]
    fn objecting_without_a_readable_code_settles_nothing() {
        let t = test_of("h-missing-settings");
        let want = crate::conformance::h3_frames::error_code::H3_MISSING_SETTINGS;
        let at_transport = Observation::ObjectedAtTransport(
            "rejected at the QUIC layer with INTERNAL_ERROR".into(),
        );

        let (v, d) = judge(t, &at_transport, Some(want));
        assert_eq!(
            v,
            Verdict::Fail,
            "the clause names a code and none was sent"
        );
        assert!(d.contains("0x10a"), "name the code it was asked for: {d}");
        assert!(
            d.contains("detected and rejected"),
            "credit the rejection while failing the signalling: {d}"
        );

        // Where the requirement is a transport-level behaviour rather than a
        // code, a close still shows nothing either way.
        let transport_behaviour = test_of("q-stateless-reset");
        assert_eq!(
            judge(transport_behaviour, &at_transport, None).0,
            Verdict::Inconclusive,
            "no code was named, so there is nothing for this close to have missed"
        );

        // The real thing still passes, and a wrong code still fails.
        assert_eq!(
            judge(t, &Observation::ClosedWith { code: want }, Some(want)).0,
            Verdict::Pass
        );
        assert_eq!(
            judge(t, &Observation::ClosedWith { code: 0x0102 }, Some(want)).0,
            Verdict::Fail
        );

        // For the classes whose requirement is to *not* object, closing at the
        // transport layer is as much a failure as closing with a code.
        let ext = test_of("h-grease-settings");
        assert_eq!(judge(ext, &at_transport, None).0, Verdict::Fail);

        // And where either answer is permitted, it remains a pass.
        let disc = test_of("h-duplicate-setting");
        assert_eq!(judge(disc, &at_transport, None).0, Verdict::Pass);
    }

    /// A pass has to be the code the clause names, not merely a rejection.
    ///
    /// The mirror of the rule above: reading any close as a pass credits a
    /// client for a behaviour nobody observed. It matters most for the
    /// transport-level correctness tests, whose real requirement — a
    /// PATH_RESPONSE, silence after a Stateless Reset — an HTTP/3 close says
    /// nothing about either way.
    #[test]
    fn a_correctness_pass_needs_the_code_the_clause_names() {
        let t = test_of("h-max-push-id");
        let want = crate::conformance::h3_frames::error_code::H3_FRAME_UNEXPECTED;

        let (v, _) = judge(t, &Observation::ClosedWith { code: want }, Some(want));
        assert_eq!(v, Verdict::Pass);

        // A different rejection is a failure, not a pass.
        let (v, _) = judge(t, &Observation::ClosedWith { code: 0x0109 }, Some(want));
        assert_eq!(v, Verdict::Fail, "0x109 is not the code §7.2.7 requires");

        // And where no code is named, a bare rejection settles nothing: those
        // tests are judged on a transport behaviour a close cannot show.
        let path = test_of("q-path-challenge");
        assert!(expected_of(path).is_none(), "this test names no code");
        let (v, d) = judge(path, &Observation::ClosedWith { code: 0x0101 }, None);
        assert_eq!(v, Verdict::Inconclusive);
        assert!(d.contains("does not show"), "say what is missing: {d}");
    }

    /// The expected code, read from the same table the listener uses.
    fn expected_of(test: &'static catalog::Test) -> Option<u64> {
        crate::conformance::listener::expected_code_for(test)
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
            requirement: catalog::Requirement::Must,
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
    fn a_completed_tls_handshake_is_acceptance_and_not_ambiguity() {
        // On the HTTP/3 tier, a client that says nothing may simply never have
        // read the anomaly, so several observations are scored inconclusive. On
        // the TLS tier there is no such doubt: the anomaly is the ServerHello,
        // and a connection that was established at all carries it.
        //
        // Silence must therefore be a failure here and an inconclusive there,
        // from the same observation — which is precisely the pair a single
        // shared rule would get wrong.
        for id in ["t-group-not-offered", "t-corrupt-hybrid-share"] {
            let t = test_of(id);
            assert_eq!(t.tier, Tier::Tls, "{id}");
            assert_eq!(t.class, Class::Correctness, "{id}");

            for obs in [
                Observation::SurvivedAndContinued,
                Observation::NoCloseObserved,
                Observation::ClosedSilently,
                Observation::ClosedWith { code: 0x0100 },
            ] {
                let (v, d) = judge(t, &obs, None);
                assert_eq!(v, Verdict::Fail, "{id} on {obs:?}");
                assert!(d.contains("key exchange"), "{id}: say where it was: {d}");
            }

            // The rejection still passes, and is what the listener reports when
            // the handshake dies.
            let (v, _) = judge(t, &Observation::Signalled("aborted".to_string()), None);
            assert_eq!(v, Verdict::Pass, "{id}: rejecting it is the pass");
        }
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

        reg.with(&id, |s| record_obs(s, t, &Observation::TimedOut, None, 1));
        reg.with(&id, |s| {
            record_obs(s, t, &Observation::SurvivedAndContinued, None, 2);
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
    fn a_second_run_from_one_address_is_reported_as_a_collision() {
        // Two matrix runs from this host, twenty seconds apart, and the second
        // one's session silently took the first one's in-flight client. The
        // association cannot refuse the newcomer -- a developer restarting
        // after an abandoned run is the ordinary case and looks identical --
        // so what it owes is a loud record of the moment it happened.
        let reg = Registry::new(60, 64);
        let ip: std::net::IpAddr = "203.0.113.11".parse().unwrap();
        let first = reg.create();
        reg.associate(ip, &first);

        // Nothing recorded yet: displacing this loses nothing, and warning
        // about it would cry wolf at every re-run.
        let second = reg.create();
        assert_eq!(reg.displaced_by(ip, &second), None);

        // Re-associating the same session is not a collision either.
        reg.associate(ip, &first);
        assert_eq!(reg.displaced_by(ip, &first), None);

        // A run in progress, though, is exactly the case worth shouting about.
        let t = test_of("h-grease-settings");
        reg.with(&first, |s| {
            record_obs(s, t, &Observation::SurvivedAndContinued, None, 1);
        });
        assert_eq!(
            reg.displaced_by(ip, &second),
            Some((first, 1)),
            "a live run with results must be named when it is displaced"
        );

        // And the displacement itself still happens: the later session wins,
        // because refusing it would break the ordinary case.
        reg.associate(ip, &second);
        assert_eq!(reg.for_source(ip).as_deref(), Some(second.as_str()));
    }

    /// A run that finished is not a collision, however much it recorded.
    ///
    /// The first version of this guard warned whenever the displaced session had
    /// any results at all, which made it fire on every ordinary sequential run:
    /// the association survives for the session TTL -- an hour as shipped -- so a
    /// matrix driving seven clients in turn produced six warnings, each of them
    /// false. It was caught by reading the log of the thing the guard exists to
    /// protect.
    ///
    /// Collecting the JSON report is the signal that a run is over, so what is
    /// warned about now is a session displaced *before* anyone came for its
    /// results.
    #[test]
    fn a_finished_run_is_not_reported_as_a_collision() {
        let reg = Registry::new(60, 64);
        let ip: std::net::IpAddr = "203.0.113.12".parse().unwrap();
        let first = reg.create();
        reg.associate(ip, &first);

        let t = test_of("h-grease-settings");
        reg.with(&first, |s| {
            record_obs(s, t, &Observation::SurvivedAndContinued, None, 1);
        });

        // Still being driven: displacing it now is the real thing.
        let second = reg.create();
        assert_eq!(reg.displaced_by(ip, &second), Some((first.clone(), 1)));

        // Its driver collects the report, which is how a run ends here.
        reg.with(&first, Session::mark_reported);

        // The next client in the same matrix run now displaces it in silence,
        // which is what an ordinary sequential run looks like.
        let third = reg.create();
        assert_eq!(
            reg.displaced_by(ip, &third),
            None,
            "a run whose results were collected has nothing left to contaminate"
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
