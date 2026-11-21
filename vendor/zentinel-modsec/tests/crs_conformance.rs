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
/// 4947 upstream at 8ba8099 (rule IDs only); here every stage, and every
/// expectation in it: rule IDs, log text and status (VENDOR.md lists what it
/// took). The harness drives each stage as go-ftw sends it (or its raw
/// `encoded_request`), through what the reference server, Apache, makes of
/// it (`refused`, RFC 9112 framing, repeated fields merged), and answers it
/// as the corpus's backend, albedo, does, through the response phases and
/// logging.
const MIN_PASSING: u32 = 5225;

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
    /// The response status the client gets (a value or a list of them).
    #[serde(default)]
    status: Option<serde_yaml::Value>,
}
#[derive(Deserialize, Default, Clone)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<serde_yaml::Value>,
    #[serde(default)]
    no_expect_ids: Vec<serde_yaml::Value>,
    #[serde(default)]
    match_regex: Option<String>,
    #[serde(default)]
    no_match_regex: Option<String>,
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
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(nl) = rest.iter().position(|&c| c == b'\n') {
        let (line, after) = (&rest[..nl], &rest[nl + 1..]);
        let line = String::from_utf8_lossy(line);
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
            out.extend_from_slice(&after[..size.min(after.len())]);
            break;
        }
        out.extend_from_slice(&after[..size]);
        rest = &after[size..];
        if rest.starts_with(b"\r") {
            rest = &rest[1..];
        }
        if rest.starts_with(b"\n") {
            rest = &rest[1..];
        }
    }
    out
}

/// The backend's answer, as the corpus's backend, albedo, gives it, through
/// the response phases and logging: `POST /reflect` answers with the JSON
/// body's `status` (200), `headers` and `body` (or base64 `encodedBody`);
/// anything else with an empty 200. A body without a Content-Type is given
/// the one Go's net/http sniffs for it.
fn respond(
    tx: &mut zentinel_modsec::engine::Transaction,
    method: &str,
    uri: &str,
    body: &str,
) -> u16 {
    let mut status = 200u16;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut out: Vec<u8> = Vec::new();
    if method == "POST" && uri.split('?').next() == Some("/reflect") {
        if let Ok(spec) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(s) = spec.get("status").and_then(|s| s.as_u64()) {
                status = u16::try_from(s).unwrap_or(200);
            }
            if let Some(h) = spec.get("headers").and_then(|h| h.as_object()) {
                for (k, v) in h {
                    headers.push((
                        k.clone(),
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string()),
                    ));
                }
            }
            if let Some(b) = spec.get("body").and_then(|b| b.as_str()) {
                out = b.as_bytes().to_vec();
            } else if let Some(e) = spec.get("encodedBody").and_then(|b| b.as_str()) {
                use base64::Engine;
                out = base64::engine::general_purpose::STANDARD
                    .decode(e)
                    .unwrap_or_default();
            }
        }
    }
    if !out.is_empty()
        && !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
    {
        headers.push(("Content-Type".into(), sniff(&out).into()));
    }
    tx.set_response_status(status, "HTTP/1.1");
    for (k, v) in &headers {
        let _ = tx.add_response_header(k, v);
    }
    let _ = tx.process_response_headers();
    if !out.is_empty() {
        let _ = tx.append_response_body(&out);
    }
    let _ = tx.process_response_body();
    let _ = tx.process_logging();
    status
}

/// What Go's `http.DetectContentType` calls a body, in the cases a test
/// body takes: HTML, XML, text, or bytes.
fn sniff(body: &[u8]) -> &'static str {
    let lead: Vec<u8> = body
        .iter()
        .skip_while(|c| c.is_ascii_whitespace())
        .take(14)
        .map(u8::to_ascii_uppercase)
        .collect();
    const HTML: [&[u8]; 17] = [
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    let tag_end = |sig: &[u8]| lead.get(sig.len()).is_none_or(|c| *c == b' ' || *c == b'>');
    if HTML.iter().any(|sig| lead.starts_with(sig) && tag_end(sig)) {
        "text/html; charset=utf-8"
    } else if lead.starts_with(b"<?XML") {
        "text/xml; charset=utf-8"
    } else if body
        .iter()
        .any(|&c| c < 0x20 && !matches!(c, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b))
    {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
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
/// What a stage leaves: the transaction, if the server let the request
/// through to the engine, and the status the client gets.
struct Served {
    tx: Option<zentinel_modsec::engine::Transaction>,
    status: u16,
}

/// What the server's error log holds for the transaction, as ModSecurity 2
/// (the corpus's reference) writes it: what a stage's `match_regex` is
/// matched against. A line a rule message, and a multipart body the
/// processor could not parse as `msc_reqbody.c` logs it.
fn log_text(tx: &zentinel_modsec::engine::Transaction) -> String {
    let mut lines: Vec<String> = tx
        .messages()
        .iter()
        .map(|m| format!("ModSecurity: Warning. {}", m.log_line()))
        .collect();
    if let Some(e) = tx
        .request_body_error()
        .filter(|e| e.starts_with("Multipart:"))
    {
        lines.push(format!("ModSecurity: Multipart parsing error: {e}"));
    }
    lines.join("\n")
}

/// One request as it reaches the server: request line, fields, body.
struct Wire {
    method: String,
    uri: String,
    version: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn has(h: &[(String, String)], n: &str) -> bool {
    h.iter().any(|(k, _)| k.eq_ignore_ascii_case(n))
}

fn header(h: &[(String, String)], n: &str) -> Option<String> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(n))
        .map(|(_, v)| v.clone())
}

/// Drive one corpus stage: the request as it is sent, through the server.
fn drive_stage(m: &ModSecurity, input: &Input) -> Served {
    let wire = match &input.encoded_request {
        Some(encoded) => {
            use base64::Engine;
            // The corpus folds long payloads over lines
            let packed: String = encoded.split_whitespace().collect();
            let raw = base64::engine::general_purpose::STANDARD
                .decode(packed)
                .unwrap_or_default();
            match raw_request(&raw) {
                Some(w) => w,
                None => {
                    return Served {
                        tx: None,
                        status: 400,
                    }
                }
            }
        }
        None => go_ftw_request(input),
    };
    serve(m, wire)
}

/// The request go-ftw sends for a stage (ftwhttp/request.go: BuildRequest,
/// encodeDataParameters, AddStandardHeaders). It adds no Host, User-Agent or
/// Accept: the tests of a missing header (920280, 920300, 920311, 920320)
/// depend on that.
fn go_ftw_request(input: &Input) -> Wire {
    let method = input.method.clone().unwrap_or_else(|| "GET".into());
    let mut headers: Vec<(String, String)> = input
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), scalar(v)))
        .collect();
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
    Wire {
        method,
        uri: input.uri.clone().unwrap_or_else(|| "/".into()),
        version: input.version.clone().unwrap_or_else(|| "HTTP/1.1".into()),
        headers,
        body: body.into_bytes(),
    }
}

/// A raw HTTP/1 request (an `encoded_request` stage, sent as it is): the
/// request line, the fields to the blank line, the rest the body.
fn raw_request(raw: &[u8]) -> Option<Wire> {
    let (head, body) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (&raw[..i], &raw[i + 4..]),
        None => match raw.windows(2).position(|w| w == b"\n\n") {
            Some(i) => (&raw[..i], &raw[i + 2..]),
            None => (raw, &[][..]),
        },
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let mut line = lines.next()?.splitn(3, ' ');
    let (method, uri) = (line.next()?.to_string(), line.next()?.to_string());
    let version = line.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.to_string(), v.trim_start().to_string()))
        .collect();
    Some(Wire {
        method,
        uri,
        version,
        headers,
        body: body.to_vec(),
    })
}

/// Whether the server answers 400 before any module sees the request, as
/// Apache, the corpus's reference, does under `HttpProtocolOptions Strict`
/// (its default; RFC 9112 sections 3, 5 and 6, RFC 9110 section 7.2): a
/// method that is not a token; a request target that is not one word in
/// origin form, absolute form, `*`, or for CONNECT `host:port`, or that holds
/// a fragment; a version not `HTTP/` digit `.` digit from 1.0; a field name
/// that is not a token, or a value holding a control character but HTAB
/// (CR or LF in a field would end it on the wire); a Content-Length that is
/// not digits; a Host that is not a host name or address (`fix_hostname`),
/// or from HTTP/1.1 on, none (`ap_check_request_header`). A request line
/// without a version is an HTTP/0.9 simple request, which Apache serves
/// (`Allow0.9`, its default) for GET alone.
fn refused(w: &Wire) -> bool {
    let tchar = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
    let token = |s: &str| !s.is_empty() && s.bytes().all(tchar);
    let t = w.uri.as_bytes();
    let one_word = !t.is_empty() && t.iter().all(|&c| c > b' ' && c != 0x7f);
    let host_port = |s: &str| {
        let (host, port) = match s.strip_prefix('[') {
            Some(v6) => match v6.split_once(']') {
                Some((addr, rest))
                    if addr
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.') =>
                {
                    (
                        addr,
                        rest.strip_prefix(':')
                            .map(Some)
                            .unwrap_or((!rest.is_empty()).then_some("x")),
                    )
                }
                _ => return None,
            },
            None => match s.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (s, None),
            },
        };
        let host_ok = !host.is_empty()
            && (s.starts_with('[')
                || host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)));
        let port_ok = port.is_none_or(|p| p.bytes().all(|c| c.is_ascii_digit()));
        (host_ok && port_ok).then_some(port.is_some())
    };
    let form = if w.method == "CONNECT" {
        host_port(&w.uri) == Some(true)
    } else {
        t.first() == Some(&b'/') || w.uri == "*" || w.uri.contains("://")
    };
    let v = w.version.as_bytes();
    let version = (v.is_empty() && w.method == "GET")
        || (v.len() == 8
            && v.starts_with(b"HTTP/")
            && (b'1'..=b'9').contains(&v[5])
            && v[6] == b'.'
            && v[7].is_ascii_digit());
    let from_1_1 = v.len() == 8 && (v[5] > b'1' || v[7] >= b'1');
    let fields = w
        .headers
        .iter()
        .all(|(k, val)| token(k) && val.bytes().all(|c| c == b'\t' || (c >= b' ' && c != 0x7f)));
    let length = header(&w.headers, "Content-Length")
        .is_none_or(|l| !l.is_empty() && l.bytes().all(|c| c.is_ascii_digit()));
    let host = match header(&w.headers, "Host") {
        Some(h) if !h.is_empty() => host_port(&h).is_some(),
        _ => !from_1_1,
    };
    !(token(&w.method)
        && one_word
        && !w.uri.contains('#')
        && form
        && version
        && fields
        && length
        && host)
}

/// What the server makes of a request before any module sees it: `refused`,
/// then RFC 9112 framing (as Apache and pqcrypta-proxy's HTTP stack both
/// apply it): chunked framing drops Content-Length and the body is
/// de-chunked; with neither, an HTTP/1 request has no body. Then the engine's
/// phases, and the backend's answer, or the engine's.
fn serve(m: &ModSecurity, mut w: Wire) -> Served {
    if refused(&w) {
        return Served {
            tx: None,
            status: 400,
        };
    }
    // A simple request: the server reads no fields and no body
    if w.version.is_empty() {
        w.version = "HTTP/0.9".into();
        w.headers.clear();
        w.body.clear();
    }
    // Repeated fields are one, their values joined (Apache's
    // apr_table_compress with APR_OVERLAP_TABLES_MERGE)
    let mut merged: Vec<(String, String)> = Vec::with_capacity(w.headers.len());
    for (k, v) in std::mem::take(&mut w.headers) {
        match merged.iter_mut().find(|(n, _)| n.eq_ignore_ascii_case(&k)) {
            Some((_, joined)) => {
                joined.push_str(", ");
                joined.push_str(&v);
            }
            None => merged.push((k, v)),
        }
    }
    w.headers = merged;
    let mut tx = m.new_transaction();
    if tx.process_uri(&w.uri, &w.method, &w.version).is_err() {
        return Served {
            tx: None,
            status: 400,
        };
    }
    let chunked = header(&w.headers, "Transfer-Encoding")
        .is_some_and(|te| te.to_ascii_lowercase().contains("chunked"));
    if chunked {
        w.headers
            .retain(|(k, _)| !k.eq_ignore_ascii_case("Content-Length"));
        w.body = dechunk(&w.body);
    } else if !has(&w.headers, "Content-Length") && !w.version.starts_with("HTTP/2") {
        w.body.clear();
    }
    for (k, v) in &w.headers {
        let _ = tx.add_request_header(k, v);
    }
    let _ = tx.process_request_headers();
    if !w.body.is_empty() {
        let _ = tx.append_request_body(&w.body);
    }
    let _ = tx.process_request_body();
    let answered = respond(
        &mut tx,
        &w.method,
        &w.uri,
        &String::from_utf8_lossy(&w.body),
    );
    let status = tx.intervention().map_or(answered, |i| i.status);
    Served {
        tx: Some(tx),
        status,
    }
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
                let empty = Log::default();
                let log = stage.output.log.as_ref().unwrap_or(&empty);
                if log.expect_ids.is_empty()
                    && log.no_expect_ids.is_empty()
                    && log.match_regex.is_none()
                    && log.no_match_regex.is_none()
                    && stage.output.status.is_none()
                {
                    skipped += 1;
                    continue;
                }

                let served = drive_stage(&m, &stage.input);
                let got: Vec<String> = served
                    .tx
                    .as_ref()
                    .map(|tx| tx.matched_rules().to_vec())
                    .unwrap_or_default();
                let text = served.tx.as_ref().map(log_text).unwrap_or_default();
                let mut ok = true;
                if let Some(want) = &stage.output.status {
                    let statuses: Vec<String> = match want {
                        serde_yaml::Value::Sequence(v) => v.iter().map(scalar).collect(),
                        v => vec![scalar(v)],
                    };
                    if !statuses.contains(&served.status.to_string()) {
                        ok = false;
                        *missing
                            .entry(format!("status {statuses:?}, got {}", served.status))
                            .or_default() += 1;
                    }
                }
                for (pattern, want) in [(&log.match_regex, true), (&log.no_match_regex, false)] {
                    if let Some(p) = pattern {
                        let re = regex::Regex::new(p).expect("the stage's log regex");
                        if re.is_match(&text) != want {
                            ok = false;
                            *missing
                                .entry(format!(
                                    "log {}matching {p:?}",
                                    if want { "" } else { "not " }
                                ))
                                .or_default() += 1;
                        }
                    }
                }
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

    // A stage with nothing this harness checks (no rule IDs, log regex or
    // status): none at 30cb436, so one that appears is reported, never
    // counted as coverage.
    assert_eq!(
        skipped, 0,
        "{skipped} corpus stages assert nothing this harness checks — find out what changed."
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
            let served = drive_stage(&m, &stage.input);
            println!("status {}", served.status);
            let Some(tx) = served.tx else {
                println!("refused by the server");
                continue;
            };
            println!("matched: {:?}", tx.matched_rules());
            println!("{}", log_text(&tx));
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
