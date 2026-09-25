//! CI driver for the HTTP/3 client conformance suite.
//!
//! Starts a session, walks the catalogue, and renders the report — exiting
//! non-zero if anything failed, so a pipeline stops on a regression.
//!
//! # It drives your client, it does not contain one
//!
//! The obvious design is a binary with a QUIC client inside it. That would only
//! ever test *that* client, which is useless to the person this is for: someone
//! who wants to know how **their** library behaves.
//!
//! So this is a harness. It runs a command you supply, once per test, with the
//! test's URL substituted in. Whatever that command connects with is what gets
//! measured. The default is curl, because most people have it and it is a real
//! HTTP/3 client, but it is only a default.
//!
//! ```text
//! h3-conformance                                        # drive curl
//! h3-conformance --client 'my-client --url {url}'       # drive your own
//! h3-conformance --json                                 # raw report, for tooling
//! ```
//!
//! # Exit status
//!
//! - `0` — nothing failed. Inconclusive results do not fail a build: the run
//!   either never put the client in the situation the test is about, or could
//!   not observe how it answered. Neither is the client's fault and neither
//!   must break someone's pipeline.
//! - `1` — at least one test failed.
//! - `2` — the suite could not be reached, or the run could not be completed.
//!   Deliberately distinct from a test failure, so "the service was down" never
//!   looks like "your client regressed".

use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Parser;
use serde::Deserialize;

#[derive(Parser)]
#[command(
    name = "h3-conformance",
    about = "Drive an HTTP/3 client through the PQ Crypta conformance suite",
    long_about = None
)]
struct Args {
    /// Host running the suite.
    #[arg(
        long,
        default_value = "conformance.pqcrypta.com",
        env = "H3_CONFORMANCE_HOST"
    )]
    host: String,

    /// Command to run once per test. `{url}` and `{port}` are substituted.
    ///
    /// Whatever this command connects with is what gets tested. It is expected
    /// to make one HTTP/3 request to `{url}`; its exit status is ignored,
    /// because a client failing a test frequently *should* exit non-zero and
    /// that is a result, not an error.
    #[arg(
        long,
        default_value = "curl -s --http3-only --max-time 15 -o /dev/null {url}",
        env = "H3_CONFORMANCE_CLIENT"
    )]
    client: String,

    /// Print the report as JSON instead of text.
    #[arg(long)]
    json: bool,

    /// Only print failures and the summary.
    #[arg(long)]
    quiet: bool,

    /// Seconds to allow each client invocation before giving up on it.
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Run only tests whose id contains this substring.
    #[arg(long)]
    filter: Option<String>,
}

/// How long to keep asking for a verdict that has not landed yet.
///
/// This replaced a flat three-second sleep, which was too short for one class of
/// test and guessed for every other. A TLS-tier client whose key exchange fails
/// has no handshake keys and so cannot encrypt a `CONNECTION_CLOSE` at all: the
/// server learns how that connection ended only when its own handshake timeout
/// expires, several seconds after the client process is gone.
///
/// Sitting under the old sleep, that arrived as `not_run` for a test that had
/// just been driven -- a false statement about our own coverage on a page whose
/// claim is measurement, and invisible in a full run because a later test's
/// traffic covered the gap. It showed up only with `--filter`, which is how it
/// was found.
const SETTLE_DEADLINE: Duration = Duration::from_secs(20);

/// How often to re-read the report while a verdict is still outstanding.
const SETTLE_POLL: Duration = Duration::from_millis(500);

#[derive(Deserialize)]
struct Session {
    id: String,
}

#[derive(Deserialize)]
struct Catalog {
    tests: Vec<CatalogEntry>,
}

#[derive(Deserialize)]
struct CatalogEntry {
    id: String,
    title: String,
    port: Option<u16>,
}

#[derive(Deserialize)]
struct Report {
    totals: Totals,
    by_class: std::collections::BTreeMap<String, ClassSummary>,
    results: Vec<ResultRow>,
}

#[derive(Deserialize)]
struct Totals {
    pass: usize,
    fail: usize,
    inconclusive: usize,
    not_run: usize,
}

#[derive(Deserialize)]
struct ClassSummary {
    pass: usize,
    fail: usize,
    inconclusive: usize,
}

#[derive(Deserialize)]
struct ResultRow {
    id: String,
    title: String,
    spec: String,
    class: String,
    verdict: String,
    detail: String,
    expectation: String,
}

/// Read the report, waiting while a test we drove still has no verdict.
///
/// `driven` is what this invocation actually ran, so a `not_run` among those is
/// a verdict in flight rather than a test nobody attempted -- the distinction
/// the old fixed sleep could not make. Everything outside `driven` is left
/// alone: with `--filter`, most of the catalogue is legitimately not run.
///
/// Returns the raw body so the JSON form prints exactly what the server sent.
async fn collect_report(
    http: &reqwest::Client,
    url: &str,
    driven: &std::collections::BTreeSet<&str>,
    deadline: tokio::time::Instant,
    quiet: bool,
) -> Result<String, i32> {
    loop {
        let body = match http.get(url).send().await {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("could not read the report: {e}");
                    return Err(exit::UNREACHABLE);
                }
            },
            Err(e) => {
                eprintln!("could not fetch the report: {e}");
                return Err(exit::UNREACHABLE);
            }
        };

        // Counted from the body each time rather than from a parsed copy kept
        // across iterations, so a malformed report fails in one place: the
        // caller's own parse.
        let outstanding = serde_json::from_str::<Report>(&body).map_or(0, |r| {
            r.results
                .iter()
                .filter(|row| row.verdict == "not_run" && driven.contains(row.id.as_str()))
                .count()
        });

        if outstanding == 0 || tokio::time::Instant::now() >= deadline {
            if outstanding > 0 && !quiet {
                // Said out loud rather than published in silence: a `not_run`
                // that outlives the deadline is a verdict we stopped waiting
                // for, and it must not read as "this client was never driven".
                eprintln!(
                    "warning: {outstanding} test(s) still had no verdict after {}s; \
                     they are reported as not run",
                    SETTLE_DEADLINE.as_secs()
                );
            }
            return Ok(body);
        }

        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// Exit codes, named so the meanings are not scattered as literals.
mod exit {
    pub const OK: i32 = 0;
    pub const FAILURES: i32 = 1;
    pub const UNREACHABLE: i32 = 2;
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    std::process::exit(run(&args).await);
}

async fn run(args: &Args) -> i32 {
    let base = format!("https://{}", args.host);
    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not build an HTTP client: {e}");
            return exit::UNREACHABLE;
        }
    };

    // ── Session ─────────────────────────────────────────────────────────
    let session: Session = match post_json(&http, &format!("{base}/session")).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("could not start a session at {base}: {e}");
            eprintln!("the suite may be down; this is not a result about your client");
            return exit::UNREACHABLE;
        }
    };

    // ── Catalogue ───────────────────────────────────────────────────────
    let catalog: Catalog = match get_json(&http, &format!("{base}/catalog.json")).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("could not fetch the catalogue: {e}");
            return exit::UNREACHABLE;
        }
    };

    let selected: Vec<&CatalogEntry> = catalog
        .tests
        .iter()
        .filter(|t| t.port.is_some())
        .filter(|t| {
            args.filter
                .as_ref()
                .is_none_or(|f| t.id.contains(f.as_str()))
        })
        .collect();

    if selected.is_empty() {
        eprintln!("no tests matched");
        return exit::UNREACHABLE;
    }

    if !args.quiet && !args.json {
        println!("Running {} tests against {}", selected.len(), args.host);
        println!("Client: {}\n", args.client);
    }

    // ── Drive the client, once per test ─────────────────────────────────
    for (i, test) in selected.iter().enumerate() {
        let port = test.port.expect("filtered to Some above");
        let url = format!("https://{}:{}/", args.host, port);
        if !args.quiet && !args.json {
            println!(
                "  [{:>2}/{}] {:<28} {}",
                i + 1,
                selected.len(),
                test.id,
                test.title
            );
        }
        // The 0-RTT ports need a connection that has something to resume.
        //
        // Early data is only possible with a session ticket from an earlier
        // connection to the same port, and the driver makes exactly one
        // connection per test -- so in the 2026-09-18 run these two tests were
        // inconclusive for eleven of twelve clients with "the client sent no
        // early data". True, and not the client's doing: it was never given a
        // ticket to send any with.
        //
        // The wrapper is told to resume rather than the driver making the
        // extra connection itself, because only the wrapper knows the flags
        // its client wants (`--session-file`, `-0`, a resumption token) and
        // whether that client can do this at all. A wrapper that ignores the
        // variable behaves exactly as before. Every client in the matrix now
        // makes the pair -- curl through a session file, Chromium within one
        // launch, .NET with two connections in one process -- so what a cell
        // reports is whether the client resumed and sent early data, never
        // that it was not given the chance.
        let resume = test.id.starts_with("q-zero-rtt");
        // Tell the server when the process stopped, so a verdict that rests on
        // silence can say which kind of silence it was. Advisory: a failure to
        // post leaves every verdict exactly as it would have been, with a less
        // specific sentence explaining it.
        if let ClientEnd::Exited(ms) = invoke_client(&args.client, &url, port, args.timeout, resume)
        {
            // Reported rather than discarded. A diagnostic that quietly fails
            // is indistinguishable from one that was never wired up, which is
            // the shape of defect this suite keeps finding in itself.
            let url = format!("{base}/client-exit/{}/{}/{ms}", session.id, test.id);
            match http.post(&url).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => eprintln!("  client-exit for {} rejected: {}", test.id, r.status()),
                Err(e) => eprintln!("  client-exit for {} failed: {e}", test.id),
            }
        }
    }

    // ── Let the server finish deciding ──────────────────────────────────
    //
    // A verdict is not settled when the client exits. Several tests are judged
    // on what happens *after* the anomaly — whether the connection goes quiet,
    // whether a close carries an error code — and the server waits before
    // recording anything. The client, meanwhile, is often gone the instant it
    // meets the anomaly.
    //
    // This used to be a flat sleep, on the reasoning that the report is always
    // available and only its contents arrive late, so there is nothing to poll
    // for. That was wrong: there is. Every test in `selected` was driven, so any
    // of them still reading `not_run` is a verdict in flight, and that is a
    // condition worth waiting on rather than a duration worth guessing.
    //
    // So: read the report, and while something we drove has no verdict, read it
    // again until the deadline. A run where everything lands promptly now waits
    // for one round trip instead of three seconds.
    let url = format!("{base}/report/{}.json", session.id);
    let driven: std::collections::BTreeSet<&str> = selected.iter().map(|t| t.id.as_str()).collect();
    let deadline = tokio::time::Instant::now() + SETTLE_DEADLINE;

    let body = match collect_report(&http, &url, &driven, deadline, args.json).await {
        Ok(body) => body,
        Err(code) => return code,
    };

    if args.json {
        println!("{body}");
    }

    let report: Report = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("could not parse the report: {e}");
            return exit::UNREACHABLE;
        }
    };

    if !args.json {
        render(&report, args.quiet, &base, &session.id);
    }

    if report.totals.fail > 0 {
        exit::FAILURES
    } else {
        exit::OK
    }
}

/// Run the client command for one test.
///
/// The exit status is deliberately ignored. A client that correctly rejects a
/// protocol violation usually exits non-zero, and treating that as a harness
/// error would turn every correct rejection into a broken run. What the client
/// did is decided by the server, which is the only party in a position to judge
/// it.
#[allow(
    clippy::literal_string_with_formatting_args,
    reason = "{url} and {port} are literal placeholders in a user-supplied template, \
              substituted by replace(); they are not format arguments"
)]
/// How a client invocation ended.
///
/// The exit *status* stays ignored -- a client failing a test frequently
/// should exit non-zero, and reading that would discard the result the run
/// exists to collect. When it exited is a different fact, and one the server
/// cannot obtain: from a socket, a peer that has gone and a peer reading
/// quietly are the same thing.
enum ClientEnd {
    /// The process ended on its own, this many milliseconds after it started.
    Exited(u64),
    /// It was still running when the per-test deadline arrived, so it was
    /// killed. Nothing about the peer's silence is explained by this.
    Killed,
    /// It could not be started or parsed; nothing was driven.
    NotRun,
}

fn invoke_client(
    template: &str,
    url: &str,
    port: u16,
    timeout_secs: u64,
    resume: bool,
) -> ClientEnd {
    // `{url}` and `{port}` are this tool's own placeholder syntax, documented
    // on `--client` and written that way in every wrapper the matrix drives.
    // They are literals on purpose; clippy's nursery lint reads any braced word
    // in a string as a stray format argument.
    #[allow(
        clippy::literal_string_with_formatting_args,
        reason = "the braces are the --client placeholder syntax, not a format string"
    )]
    let rendered = template
        .replace("{url}", url)
        .replace("{port}", &port.to_string());

    let Some(parts) = shell_words(&rendered) else {
        eprintln!("  could not parse the client command: {rendered}");
        return ClientEnd::NotRun;
    };
    let Some((program, rest)) = parts.split_first() else {
        eprintln!("  empty client command");
        return ClientEnd::NotRun;
    };

    let mut command = Command::new(program);
    command
        .args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Always set, never unset, so a wrapper reading it sees "0" rather than a
    // variable that is sometimes absent -- inherited environments have caused
    // enough confusion in this runner already.
    command.env("H3_CONFORMANCE_RESUME", if resume { "1" } else { "0" });
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  could not run {program}: {e}");
            return ClientEnd::NotRun;
        }
    };

    // Bounded: a client that hangs on a test must not hang the whole run. The
    // server's own liveness timeout will have decided the verdict regardless.
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            // Exited, or we cannot tell — either way this invocation is done.
            // The exit status is not consulted, so the two are the same
            // outcome here.
            Ok(Some(_)) | Err(_) => {
                return ClientEnd::Exited(
                    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                )
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return ClientEnd::Killed;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Split a command line on whitespace, honouring single and double quotes.
///
/// Enough for a client invocation, and deliberately not a shell: the command is
/// run directly rather than through `sh`, so nothing here can expand a variable
/// or chain a second command.
fn shell_words(input: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;

    for ch in input.chars() {
        match (quote, ch) {
            // Closing the quote we opened.
            (Some(q), c) if c == q => quote = None,
            // Quoting and word boundaries only apply outside a quote.
            (None, c @ ('\'' | '"')) => {
                quote = Some(c);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() || any {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            // Everything else is a literal character: ordinary text outside a
            // quote, and anything at all inside one — including whitespace and
            // the other quote character.
            (_, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return None; // unbalanced
    }
    if !cur.is_empty() || any {
        out.push(cur);
    }
    Some(out)
}

fn render(report: &Report, quiet: bool, base: &str, session: &str) {
    let t = &report.totals;

    let failures: Vec<&ResultRow> = report
        .results
        .iter()
        .filter(|r| r.verdict == "fail")
        .collect();

    if !failures.is_empty() {
        println!("\nFailures\n");
        for r in &failures {
            println!("  {} — {}", r.id, r.title);
            println!("    class:    {}", r.class);
            println!("    spec:     {}", r.spec);
            println!("    expected: {}", r.expectation);
            println!("    observed: {}\n", r.detail);
        }
    }

    if !quiet {
        println!("\nBy class\n");
        for (class, s) in &report.by_class {
            let decided = s.pass + s.fail;
            #[allow(
                clippy::cast_precision_loss,
                reason = "counts are bounded by the catalogue size, far inside f64's exact range"
            )]
            let rate = if decided == 0 {
                "  —".to_string()
            } else {
                format!("{:>3.0}%", 100.0 * s.pass as f64 / decided as f64)
            };
            println!(
                "  {class:<18} {rate}   {} pass, {} fail, {} inconclusive",
                s.pass, s.fail, s.inconclusive
            );
        }
    }

    println!(
        "\n{} pass, {} fail, {} inconclusive, {} not run",
        t.pass, t.fail, t.inconclusive, t.not_run
    );

    if t.inconclusive > 0 {
        println!(
            "\nInconclusive results do not fail this run. They mean the suite never put\n\
             your client in the situation the test is about — a request too small to\n\
             reach a limit, a connection too short to need a connection ID rotated, or\n\
             a client with no session ticket to resume from. Every anomaly in the\n\
             catalogue is emitted; what varies is whether a given run reaches it."
        );
    }

    println!("\nFull report: {base}/report/{session}");
    println!("Badge:       {base}/badge/{session}.svg");
}

async fn get_json<T: for<'de> Deserialize<'de>>(
    http: &reqwest::Client,
    url: &str,
) -> anyhow::Result<T> {
    let resp = http.get(url).send().await?.error_for_status()?;
    Ok(resp.json::<T>().await?)
}

async fn post_json<T: for<'de> Deserialize<'de>>(
    http: &reqwest::Client,
    url: &str,
) -> anyhow::Result<T> {
    let resp = http.post(url).send().await?.error_for_status()?;
    Ok(resp.json::<T>().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_command_splits_on_whitespace() {
        assert_eq!(
            shell_words("curl -s --http3-only https://x/"),
            Some(vec![
                "curl".into(),
                "-s".into(),
                "--http3-only".into(),
                "https://x/".into()
            ])
        );
    }

    #[test]
    fn quoted_arguments_stay_whole() {
        assert_eq!(
            shell_words("my-client --header 'x-a: b c' --url https://x/"),
            Some(vec![
                "my-client".into(),
                "--header".into(),
                "x-a: b c".into(),
                "--url".into(),
                "https://x/".into()
            ])
        );
    }

    #[test]
    fn an_empty_quoted_argument_survives() {
        // "" is a real argument some clients expect; dropping it silently would
        // shift every argument after it.
        assert_eq!(
            shell_words("client --ua '' --url https://x/"),
            Some(vec![
                "client".into(),
                "--ua".into(),
                String::new(),
                "--url".into(),
                "https://x/".into()
            ])
        );
    }

    #[test]
    fn an_unbalanced_quote_is_refused_rather_than_guessed() {
        assert_eq!(shell_words("client --header 'oops"), None);
    }

    #[test]
    fn nothing_is_interpreted_as_shell() {
        // The command is spawned directly, never via sh, so these are literal
        // arguments and cannot chain or expand.
        let parts = shell_words("client $HOME && rm -rf /").expect("parses");
        assert!(parts.contains(&"$HOME".to_string()));
        assert!(parts.contains(&"&&".to_string()));
    }

    #[test]
    fn placeholders_are_substituted_in_both_forms() {
        let rendered = "c --url {url} --port {port}"
            .replace("{url}", "https://h:4460/")
            .replace("{port}", "4460");
        assert_eq!(rendered, "c --url https://h:4460/ --port 4460");
    }
}
