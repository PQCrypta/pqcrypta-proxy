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
//! - `0` — nothing failed. Inconclusive results do not fail a build: they mean
//!   the run never put the client in the situation the test is about, which is
//!   not the client's fault and must not break someone's pipeline.
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
        invoke_client(&args.client, &url, port, args.timeout);
    }

    // ── Report ──────────────────────────────────────────────────────────
    let url = format!("{base}/report/{}.json", session.id);
    let body = match http.get(&url).send().await {
        Ok(r) => match r.text().await {
            Ok(t) => t,
            Err(e) => {
                eprintln!("could not read the report: {e}");
                return exit::UNREACHABLE;
            }
        },
        Err(e) => {
            eprintln!("could not fetch the report: {e}");
            return exit::UNREACHABLE;
        }
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
fn invoke_client(template: &str, url: &str, port: u16, timeout_secs: u64) {
    let rendered = template
        .replace("{url}", url)
        .replace("{port}", &port.to_string());

    let Some(parts) = shell_words(&rendered) else {
        eprintln!("  could not parse the client command: {rendered}");
        return;
    };
    let Some((program, rest)) = parts.split_first() else {
        eprintln!("  empty client command");
        return;
    };

    let mut child = match Command::new(program)
        .args(rest)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  could not run {program}: {e}");
            return;
        }
    };

    // Bounded: a client that hangs on a test must not hang the whole run. The
    // server's own liveness timeout will have decided the verdict regardless.
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            // Exited, or we cannot tell — either way this invocation is done.
            // The exit status is not consulted, so the two are the same
            // outcome here.
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return;
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
             your client in the situation the test is about — an anomaly not yet\n\
             implemented, or a request too small to reach a limit."
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
