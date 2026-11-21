//! Conformance against the OWASP CRS regression corpus.
//!
//! The corpus is ~5,000 request/expectation pairs maintained upstream, one file
//! per rule, asserting **which rule IDs appear in the log** for a given request.
//! go-ftw drives it against a live server and reads the audit log; this drives
//! the same YAML directly against the engine, which is fast enough to run on
//! every push and precise enough to catch a rule that stops matching.
//!
//! # What this measures, and what it does not
//!
//! The corpus runs in the configuration upstream documents for it
//! (`tests/regression/README.md`, rule 900005): **`DetectionOnly` at paranoia
//! level 4**. That is deliberate on their part and important to understand
//! here: in detection-only mode `block` never blocks, the paranoia gates never
//! fire, and the anomaly score never reaches 949110. So this measures whether
//! individual rules *match*. It says nothing about whether the WAF *decides*
//! correctly.
//!
//! That distinction is not academic. A set of defects that made a stock CRS
//! deployment deny 100% of requests — including `GET /` — moved this number by
//! 23 out of 5,033, because none of the machinery they broke runs in this
//! configuration. A green corpus is not evidence that the WAF works.
//!
//! `stock_crs_blocks_attacks_and_passes_ordinary_traffic` covers the other
//! half: real blocking mode, default paranoia, asserting on the decision.
//! Both are needed. Neither substitutes for the other.
//!
//! # Running
//!
//! ```text
//! mkdir -p test-rules
//! git clone https://github.com/coreruleset/coreruleset.git test-rules/crs
//! git -C test-rules/crs checkout 30cb436   # the commit CI pins
//! cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf
//! cargo test --test crs_conformance -- --nocapture
//! ```
//!
//! The gate expects an exact pass count, so it only holds against the CRS
//! commit CI pins (`.github/workflows/ci.yml`); another checkout will report a
//! different number.
//!
//! `CRS_DIR` overrides the location. `SKIP_CRS_CONFORMANCE=1` skips these tests
//! when the corpus is not present — CI's unit-test job sets it, because the
//! dedicated `conformance` job fetches the corpus and runs this optimised (~14s
//! against ~5,000 cases, versus minutes unoptimised). That job must never set
//! it: a gate that can silently not run is not a gate.
//!
//! Absence of the checkout is otherwise a failure rather than a skip, with
//! instructions — these tests previously existed in a form that returned early
//! when the fixture was missing, and went years without running.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zentinel_modsec::ModSecurity;

/// Cases the corpus passes — exactly. A change in either direction fails the
/// gate, so every gain and every loss is acknowledged in the commit that causes
/// it: raise it when a fix lands; never lower it without saying which rules
/// regressed and why.
///
/// That only works because evaluation is deterministic (#53: collections used
/// to iterate in hash order, and the count varied between runs of one commit)
/// and because CI pins the CRS checkout. Measured on CRS `main` (4.31.0-dev,
/// 30cb436, the commit CI fetches). The corpus upstream keeps moving, so a
/// change after bumping that commit is worth reading as new tests before
/// reading it as a regression.
///
/// 4947 upstream at 8ba8099; 5066 in pqcrypta-proxy's copy (VENDOR.md):
/// libinjection itself and `ctl:ruleRemoveTargetByTag` pass six more cases
/// (941100 two, 941180 one, 942100 two, 942101 one), request bodies read as
/// ModSecurity reads them 31 (944100 four, 944110 four, 944120 sixteen,
/// 944210 six, 920400 one), case-insensitive regex selections 17 (922110),
/// libmodsecurity v3's multipart processor 18 (920120 sixteen, 920121 one,
/// 920410 one), and ModSecurity's URL decoding (`+` to a space) 18 (932200
/// seven, 932205 three, 932206 one, 932207 two, 942101 two, 942210 two,
/// 942240 one), and the path variables URI-decoded as v3 sets them 28 (one
/// each in 932125 to 932380 and 933151 to 933153, three in 933160), and bytes
/// that are not UTF-8 kept as themselves 4 (920250). That
/// decoding fails three cases upstream passed, each a
/// `%2B` the test expects to survive `t:urlDecodeUni` as `+` (934160 test 4,
/// 942500 tests 3 and 4): ModSecurity v2 and v3 turn it into a space too
/// (msc_util.c `urldecode_uni_nonstrict_inplace_ex`, v3 url_decode_uni.cc),
/// so the engine keeps their semantics. No other case upstream passes fails
/// here, compared case file by case file.
const MIN_PASSING: u32 = 5066;

/// Corpus stages that cannot be driven from here: an `encoded_request` payload,
/// or an expectation that is not about rule IDs (`status`, `match_regex`).
/// Reported rather than hidden, so this cap cannot quietly grow.
const EXPECTED_SKIPS_MAX: u32 = 60;

// --- corpus schema (only the fields this harness uses) ---------------------

#[derive(Deserialize)]
struct TestFile {
    tests: Vec<Test>,
}
#[derive(Deserialize)]
struct Test {
    #[serde(default)]
    test_id: Option<u32>,
    #[serde(default)]
    stages: Vec<Stage>,
}
#[derive(Deserialize)]
struct Stage {
    input: Input,
    #[serde(default)]
    output: Output,
}
#[derive(Deserialize, Default)]
struct Input {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    data: Option<serde_yaml::Value>,
    #[serde(default)]
    encoded_request: Option<String>,
    #[serde(default)]
    autocomplete_headers: Option<bool>,
}
#[derive(Deserialize, Default)]
struct Output {
    #[serde(default)]
    log: Option<Log>,
}
#[derive(Deserialize, Default)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<serde_yaml::Value>,
    #[serde(default)]
    no_expect_ids: Vec<serde_yaml::Value>,
}

/// YAML scalars appear as strings or numbers; `data` may be a block sequence.
fn scalar(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Sequence(items) => items.iter().map(scalar).collect::<Vec<_>>().join(""),
        _ => String::new(),
    }
}

// --- fixture ---------------------------------------------------------------

fn crs_dir() -> Option<PathBuf> {
    if std::env::var_os("SKIP_CRS_CONFORMANCE").is_some() {
        return None;
    }
    let dir = std::env::var("CRS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("test-rules/crs"));
    assert!(
        dir.join("crs-setup.conf").is_file(),
        "OWASP CRS checkout not found at {}.\n\
         Fetch it with:\n  \
           mkdir -p test-rules\n  \
           git clone --depth 1 https://github.com/coreruleset/coreruleset.git test-rules/crs\n  \
           cp test-rules/crs/crs-setup.conf.example test-rules/crs/crs-setup.conf\n\
         CRS_DIR overrides the location; SKIP_CRS_CONFORMANCE=1 skips these \
         tests locally. CI must not set it.",
        dir.display()
    );
    Some(dir)
}

/// The configuration the corpus documents for itself: detection-only, paranoia
/// 4, and the size limits its tests assume. Detection-only matters beyond
/// blocking — in blocking mode the first disruptive rule ends the phase, so
/// later rules a test expects would never be recorded.
const FTW_SETUP: &str = r#"SecAction "id:900005,phase:1,nolog,pass,\
    ctl:ruleEngine=DetectionOnly,\
    ctl:ruleRemoveById=910000,\
    setvar:tx.blocking_paranoia_level=4,\
    setvar:tx.crs_validate_utf8_encoding=1,\
    setvar:tx.arg_name_length=100,\
    setvar:tx.arg_length=400,\
    setvar:tx.total_arg_length=64000,\
    setvar:tx.max_num_args=255,\
    setvar:tx.max_file_size=64100,\
    setvar:tx.combined_file_sizes=65535""#;

fn load(dir: &Path, extra: &str) -> ModSecurity {
    let dir = std::fs::canonicalize(dir).expect("CRS dir");
    let d = dir.display();
    // Include directives rather than spliced file contents: CRS `.data` paths
    // are relative to the rule file naming them.
    let cfg = format!(
        "SecRuleEngine On\nSecRequestBodyAccess On\n\
         Include \"{d}/crs-setup.conf\"\n{extra}\nInclude \"{d}/rules/*.conf\"\n"
    );
    ModSecurity::from_string(&cfg).expect("CRS should load")
}

/// A chunked body's data (RFC 9112 section 7.1): each chunk's size line in
/// hex, its data, to the zero-size chunk. Line endings CRLF or LF.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((line, after)) = rest.split_once('\n') {
        let size = line
            .trim_end_matches('\r')
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let Ok(size) = usize::from_str_radix(size, 16) else {
            break;
        };
        if size == 0 || after.len() < size {
            out.push_str(&after[..size.min(after.len())]);
            break;
        }
        out.push_str(&after[..size]);
        rest = after[size..]
            .trim_start_matches('\r')
            .trim_start_matches('\n');
    }
    out
}

/// go-ftw's `methodsWithBodyRegex`, `^POST|PUT|PATCH|DELETE$`, alternation
/// and all.
fn body_method(m: &str) -> bool {
    m.starts_with("POST") || m.contains("PUT") || m.contains("PATCH") || m.contains("DELETE")
}

/// Go's `url.QueryUnescape`: `%XX` and `+`, `None` on a malformed escape.
fn query_unescape(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = |c: u8| (c as char).to_digit(16);
                let (h, l) = (hex(*b.get(i + 1)?)?, hex(*b.get(i + 2)?)?);
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Go's `url.QueryEscape`: unreserved characters kept, a space as `+`, every
/// other byte `%XX`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &c in s.as_bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(c as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{c:02X}")),
        }
    }
    out
}

/// Drive one corpus stage and return the rule IDs that matched.
fn run_stage(m: &ModSecurity, input: &Input) -> Vec<String> {
    drive_stage(m, input).matched_rules().to_vec()
}

/// Drive one corpus stage through a transaction, and return it.
fn drive_stage(m: &ModSecurity, input: &Input) -> zentinel_modsec::engine::Transaction {
    let mut tx = m.new_transaction();
    let uri = input.uri.clone().unwrap_or_else(|| "/".into());
    let method = input.method.clone().unwrap_or_else(|| "GET".into());
    let version = input.version.clone().unwrap_or_else(|| "HTTP/1.1".into());
    if tx.process_uri(&uri, &method, &version).is_err() {
        return tx;
    }

    // The request go-ftw sends for this stage (ftwhttp/request.go:
    // BuildRequest, encodeDataParameters, AddStandardHeaders). It adds no
    // Host, User-Agent or Accept: the tests of a missing header (920280,
    // 920300, 920311, 920320) depend on that.
    let mut headers: Vec<(String, String)> = input
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), scalar(v)))
        .collect();
    let has = |h: &[(String, String)], n: &str| h.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    let header = |h: &[(String, String)], n: &str| {
        h.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(n))
            .map(|(_, v)| v.clone())
    };
    let mut body = input.data.as_ref().map(scalar).unwrap_or_default();
    let autocomplete = input.autocomplete_headers.unwrap_or(true);
    const FORM: &str = "application/x-www-form-urlencoded";
    // A body with no type is a form
    if autocomplete && !body.is_empty() && !has(&headers, "Content-Type") {
        headers.push(("Content-Type".into(), FORM.into()));
    }
    let content_type = header(&headers, "Content-Type").unwrap_or_default();
    // A form body written unescaped is escaped, key and value
    if content_type.contains(FORM) && query_unescape(&body).as_deref() == Some(body.as_str()) {
        body = body
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| match p.split_once('=') {
                Some((k, v)) => format!("{}={}", query_escape(k), query_escape(v)),
                None => query_escape(p),
            })
            .collect::<Vec<_>>()
            .join("&");
    }
    // A multipart body's line endings are CRLF on the wire
    if content_type.contains("multipart/form-data;") {
        body = body.replace('\n', "\r\n");
    }
    if autocomplete {
        if !has(&headers, "Connection") {
            headers.push(("Connection".into(), "close".into()));
        }
        if !has(&headers, "Content-Length") && (!body.is_empty() || body_method(&method)) {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }
    }
    // What the server makes of it before any module sees it (RFC 9112
    // framing, as Apache, the corpus's reference, and pqcrypta-proxy's HTTP
    // stack both apply it): a field holding CR or LF is a request refused;
    // chunked framing drops Content-Length and the body is de-chunked; with
    // neither, an HTTP/1 request has no body.
    if headers
        .iter()
        .any(|(k, v)| k.contains(['\r', '\n']) || v.contains(['\r', '\n']))
    {
        return tx;
    }
    let chunked = header(&headers, "Transfer-Encoding")
        .is_some_and(|te| te.to_ascii_lowercase().contains("chunked"));
    if chunked {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Length"));
        body = dechunk(&body);
    } else if !has(&headers, "Content-Length") && !version.starts_with("HTTP/2") {
        body.clear();
    }
    for (k, v) in &headers {
        let _ = tx.add_request_header(k, v);
    }
    if tx.process_request_headers().is_err() {
        return tx;
    }
    if !body.is_empty() {
        let _ = tx.append_request_body(body.as_bytes());
    }
    let _ = tx.process_request_body();
    tx
}

// --- the gate --------------------------------------------------------------

#[test]
fn crs_regression_corpus() {
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, FTW_SETUP);

    let (mut pass, mut fail, mut skipped) = (0u32, 0u32, 0u32);
    // CRS_CONFORMANCE_FAILURES=1 lists every failing stage, to look at one
    // case rather than a file's count
    let list_failures = std::env::var_os("CRS_CONFORMANCE_FAILURES").is_some();
    let mut by_file: BTreeMap<String, u32> = BTreeMap::new();
    let mut missing: BTreeMap<String, u32> = BTreeMap::new();
    let mut spurious: BTreeMap<String, u32> = BTreeMap::new();

    let root = dir.join("tests/regression/tests");
    assert!(root.is_dir(), "corpus not found at {}", root.display());

    for entry in walkdir::WalkDir::new(&root).into_iter().flatten() {
        if entry
            .path()
            .extension()
            .map(|e| e != "yaml")
            .unwrap_or(true)
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(parsed) = serde_yaml::from_str::<TestFile>(&text) else {
            continue;
        };
        let fname = entry
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        for t in &parsed.tests {
            for stage in &t.stages {
                let Some(log) = &stage.output.log else {
                    skipped += 1;
                    continue;
                };
                if stage.input.encoded_request.is_some()
                    || (log.expect_ids.is_empty() && log.no_expect_ids.is_empty())
                {
                    skipped += 1;
                    continue;
                }

                let got = run_stage(&m, &stage.input);
                let mut ok = true;
                for id in log.expect_ids.iter().map(scalar) {
                    if !got.contains(&id) {
                        ok = false;
                        *missing.entry(id).or_default() += 1;
                    }
                }
                for id in log.no_expect_ids.iter().map(scalar) {
                    if got.contains(&id) {
                        ok = false;
                        *spurious.entry(id).or_default() += 1;
                    }
                }
                if ok {
                    pass += 1;
                } else {
                    if list_failures {
                        let ids =
                            |v: &Vec<serde_yaml::Value>| v.iter().map(scalar).collect::<Vec<_>>();
                        let (want, not) = (ids(&log.expect_ids), ids(&log.no_expect_ids));
                        // The matched rules of the families the stage is about
                        let fam: Vec<&str> = want
                            .iter()
                            .chain(&not)
                            .map(|i| &i[..3.min(i.len())])
                            .collect();
                        let near: Vec<&String> = got
                            .iter()
                            .filter(|g| fam.iter().any(|f| g.starts_with(f)))
                            .collect();
                        let ct = stage
                            .input
                            .headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                            .map(|(_, v)| scalar(v))
                            .unwrap_or_default();
                        let data = stage.input.data.as_ref().map(scalar).unwrap_or_default();
                        let cut = |s: &str, n: usize| {
                            s.chars().take(n).collect::<String>().replace('\n', "\\n")
                        };
                        println!(
                            "FAILING {fname} test {} want {want:?} not {not:?} got {near:?} | {} {} | ct={} | data={}",
                            t.test_id.unwrap_or_default(),
                            stage.input.method.as_deref().unwrap_or("GET"),
                            cut(stage.input.uri.as_deref().unwrap_or("/"), 90),
                            cut(&ct, 40),
                            cut(&data, 90),
                        );
                    }
                    fail += 1;
                    *by_file.entry(fname.clone()).or_default() += 1;
                }
            }
        }
    }

    let total = pass + fail;
    println!(
        "\nCRS regression corpus: {pass}/{total} passing ({:.1}%), {skipped} skipped",
        100.0 * f64::from(pass) / f64::from(total)
    );

    let mut worst: Vec<_> = by_file.into_iter().collect();
    worst.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    if !worst.is_empty() {
        println!("\nfailing files:");
        for (f, n) in worst.iter().take(15) {
            println!("  {n:>4}  {f}");
        }
    }
    let top = |label: &str, m: BTreeMap<String, u32>| {
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        if !v.is_empty() {
            println!("\n{label}:");
            for (id, n) in v.iter().take(15) {
                println!("  {n:>4}  {id}");
            }
        }
    };
    top("rules that should have fired", missing);
    top("rules that fired but must not", spurious);

    assert!(
        skipped <= EXPECTED_SKIPS_MAX,
        "{skipped} corpus stages were skipped, more than the {EXPECTED_SKIPS_MAX} expected. \
         Silently skipping cases reads as coverage that is not there — find out what changed."
    );
    assert!(
        pass >= MIN_PASSING,
        "CRS conformance regressed: {pass} passing, expected at least {MIN_PASSING}. \
         The lists above name the rules. If this is a deliberate trade, say which \
         rules regressed and why, then lower MIN_PASSING in the same commit."
    );
    assert!(
        pass <= MIN_PASSING,
        "CRS conformance improved: {pass} passing, MIN_PASSING is {MIN_PASSING}. \
         Raise MIN_PASSING to {pass} in this commit, so the gain cannot be lost \
         silently."
    );
}

// --- the half the corpus cannot see ----------------------------------------

#[test]
fn stock_crs_blocks_attacks_and_passes_ordinary_traffic() {
    // Real blocking mode, default paranoia — the configuration an operator
    // actually deploys, and the one the corpus above is blind to.
    let Some(dir) = crs_dir() else { return };
    let m = load(&dir, "");

    let ue = "application/x-www-form-urlencoded";
    let xml = "application/xml";
    // name, should_block, method, uri, content-type, body
    type Case = (
        &'static str,
        bool,
        &'static str,
        &'static str,
        &'static str,
        &'static [u8],
    );
    let cases: &[Case] = &[
        ("GET /", false, "GET", "/", "", b""),
        ("static page", false, "GET", "/index.html", "", b""),
        ("health check", false, "GET", "/api/v1/health", "", b""),
        ("pdf download", false, "GET", "/docs/report.pdf", "", b""),
        (
            "ordinary query",
            false,
            "GET",
            "/search?q=blue+widgets&page=2",
            "",
            b"",
        ),
        (
            "form post",
            false,
            "POST",
            "/api/orders",
            ue,
            b"item=widget&qty=3",
        ),
        (
            "xml post",
            false,
            "POST",
            "/api/orders",
            xml,
            br#"<order><item id="7">widget</item></order>"#,
        ),
        (
            "SQLi in query",
            true,
            "GET",
            "/u?id=1'+UNION+SELECT+password+FROM+users--+",
            "",
            b"",
        ),
        (
            "SQLi in form",
            true,
            "POST",
            "/u",
            ue,
            b"q=1' UNION SELECT password FROM users-- ",
        ),
        (
            "SQLi in XML",
            true,
            "POST",
            "/u",
            xml,
            br#"<o><q>1' UNION SELECT password FROM users-- </q></o>"#,
        ),
        (
            "XSS in query",
            true,
            "GET",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "",
            b"",
        ),
        (
            "LFI in query",
            true,
            "GET",
            "/f?p=../../../../etc/passwd",
            "",
            b"",
        ),
        // Detected only by rules whose anomaly score sits on the last link of
        // a chain (920170, 920420): invisible while that `setvar` did not run.
        ("GET with a body", true, "GET", "/", "text/plain", b"hi"),
        (
            "unknown Content-Type",
            true,
            "POST",
            "/",
            "my-new-content-type",
            b"hi=test",
        ),
    ];

    let mut wrong = Vec::new();
    for (name, should_block, method, uri, ct, body) in cases {
        let mut tx = m.new_transaction();
        tx.process_uri(uri, method, "HTTP/1.1").unwrap();
        tx.add_request_header("Host", "example.com").unwrap();
        tx.add_request_header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0",
        )
        .unwrap();
        tx.add_request_header("Accept", "text/html,application/xhtml+xml")
            .unwrap();
        tx.add_request_header("Accept-Language", "en-US,en;q=0.9")
            .unwrap();
        tx.add_request_header("Accept-Encoding", "gzip, deflate")
            .unwrap();
        tx.add_request_header("Connection", "keep-alive").unwrap();
        if !ct.is_empty() {
            tx.add_request_header("Content-Type", ct).unwrap();
            tx.add_request_header("Content-Length", &body.len().to_string())
                .unwrap();
        }
        tx.process_request_headers().unwrap();
        if !body.is_empty() {
            tx.append_request_body(body).unwrap();
        }
        tx.process_request_body().unwrap();

        let blocked = tx.has_intervention();
        let ids = tx
            .intervention()
            .map(|i| i.rule_ids.clone())
            .unwrap_or_default();
        println!("{name:<18} blocked={blocked:<6} {ids:?}");
        if blocked != *should_block {
            wrong.push(format!(
                "{name}: expected {}, got {blocked} {ids:?}",
                if *should_block { "a block" } else { "no block" }
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "stock CRS behaved wrongly:\n  {}",
        wrong.join("\n  ")
    );
}

/// One corpus case, for looking at it: `CRS_CASE=942430.yaml#3` (and
/// `CRS_RULES=942430,942431`, the rules to show) runs that test's stages and
/// prints what the rules matched: variable, value after transformations, and
/// the portion the operator hit.
#[test]
#[ignore]
fn crs_case() {
    let Some(dir) = crs_dir() else { return };
    let case = std::env::var("CRS_CASE").expect("CRS_CASE=<file>#<test id>");
    let (file, id) = case.split_once('#').expect("<file>#<test id>");
    let id: u32 = id.parse().expect("a test id");
    let rules: Vec<String> = std::env::var("CRS_RULES")
        .map(|r| r.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    let m = load(&dir, FTW_SETUP);
    let path = walkdir::WalkDir::new(dir.join("tests/regression/tests"))
        .into_iter()
        .flatten()
        .find(|e| e.file_name().to_string_lossy() == file)
        .expect("the test file")
        .into_path();
    let parsed: TestFile = serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for t in parsed.tests.iter().filter(|t| t.test_id == Some(id)) {
        for stage in &t.stages {
            let tx = drive_stage(&m, &stage.input);
            println!("matched: {:?}", tx.matched_rules());
            for d in tx.matched_data() {
                let rid = d.rule_id.clone().unwrap_or_default();
                if rules.is_empty() || rules.contains(&rid) {
                    println!(
                        "  {rid} {} = {:?} (hit {:?})",
                        d.variable, d.value, d.matched_portion
                    );
                }
            }
        }
    }
}
