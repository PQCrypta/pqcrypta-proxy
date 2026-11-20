//! The WAF measured against the OWASP Core Rule Set's own regression tests.
//!
//! `scripts/crs-cases.py` turns CRS's go-ftw YAML tests into `CRS_CASES`
//! (JSON): each case is one request, what CRS expects of the rule it tests
//! ("attack": the rule must fire; "benign": it must not), and the rule's
//! paranoia level. This runs every case through [`WafEngine::explain`] with
//! the `[waf]` table of `WAF_CONFIG` (a proxy configuration file) and writes
//! one JSON line per case to `CRS_RESULTS`: whether the engine would block,
//! its score, and the rules that matched. Ignored unless asked for:
//!
//! ```text
//! CRS_CASES=cases.json WAF_CONFIG=proxy-config.toml CRS_RESULTS=out.jsonl \
//!   cargo test --release --test crs_regression -- --ignored --nocapture
//! ```

use std::io::Write;

use http::{HeaderMap, HeaderName, HeaderValue};
use pqcrypta_proxy::config::WafConfig;
use pqcrypta_proxy::waf::{WafEngine, WafRequest};
use zentinel_modsec::variables::Collection;

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    rule: String,
    family: String,
    pl: Option<u8>,
    kind: String,
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

fn waf_config(path: &str) -> WafConfig {
    let text = std::fs::read_to_string(path).expect("WAF_CONFIG readable");
    let table: toml::Table = toml::from_str(&text).expect("WAF_CONFIG is TOML");
    table.get("waf").map_or_else(WafConfig::default, |waf| {
        waf.clone().try_into().expect("[waf] is a WafConfig")
    })
}

#[test]
#[ignore = "needs CRS_CASES, WAF_CONFIG and CRS_RESULTS"]
fn crs_regression_cases() {
    let cases_path = std::env::var("CRS_CASES").expect("CRS_CASES");
    let config = waf_config(&std::env::var("WAF_CONFIG").expect("WAF_CONFIG"));
    let out_path = std::env::var("CRS_RESULTS").expect("CRS_RESULTS");
    let cases: Vec<Case> =
        serde_json::from_str(&std::fs::read_to_string(cases_path).expect("cases readable"))
            .expect("cases are JSON");
    let engine = WafEngine::new(&config);
    let mut out = std::io::BufWriter::new(std::fs::File::create(out_path).expect("results file"));
    let (mut run, mut unsendable) = (0usize, 0usize);
    for case in &cases {
        let mut headers = HeaderMap::new();
        let mut sendable = true;
        for (name, value) in &case.headers {
            match (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                (Ok(n), Ok(v)) => {
                    headers.append(n, v);
                }
                // A header no HTTP stack would deliver to the WAF
                _ => sendable = false,
            }
        }
        let (path, query) = case.uri.split_once('?').unwrap_or((case.uri.as_str(), ""));
        let req = WafRequest {
            method: &case.method,
            path,
            query,
            headers: &headers,
            body: case.body.as_deref().map(str::as_bytes),
            skip_bot_ua_check: false,
            generic_client_allowed: false,
            mode_override: None,
            version: None,
            authority: None,
        };
        let x = engine.explain(&req);
        let rules: Vec<&str> = x.matches.iter().map(|m| m.rule.as_str()).collect();
        serde_json::to_writer(
            &mut out,
            &serde_json::json!({
                "id": case.id, "rule": case.rule, "family": case.family, "pl": case.pl,
                "kind": case.kind, "sendable": sendable, "block": x.would_block,
                "score": x.score, "threshold": x.threshold, "matches": rules,
            }),
        )
        .expect("result written");
        out.write_all(b"\n").expect("newline written");
        run += 1;
        if !sendable {
            unsendable += 1;
        }
    }
    eprintln!("{run} cases run ({unsendable} with a header HTTP would not carry)");
}

/// The same cases through the OWASP CRS itself, run by `zentinel-modsec`
/// (a pure-Rust `SecLang` engine) from `CRS_ENTRY`, an entry file that sets
/// the engine on and `Include`s `crs-setup.conf` and CRS's rules. Writes one
/// JSON line per case to `CRS_RESULTS`: whether CRS denies it, its inbound
/// anomaly score, and the rules that matched.
#[test]
#[ignore = "needs CRS_CASES, CRS_ENTRY and CRS_RESULTS"]
fn crs_engine_cases() {
    let cases: Vec<Case> = serde_json::from_str(
        &std::fs::read_to_string(std::env::var("CRS_CASES").expect("CRS_CASES"))
            .expect("cases readable"),
    )
    .expect("cases are JSON");
    let modsec =
        zentinel_modsec::ModSecurity::from_file(&std::env::var("CRS_ENTRY").expect("CRS_ENTRY"))
            .expect("CRS loads");
    eprintln!("{} CRS rules loaded", modsec.rule_count());
    let mut out = std::io::BufWriter::new(
        std::fs::File::create(std::env::var("CRS_RESULTS").expect("CRS_RESULTS"))
            .expect("results file"),
    );
    let mut errors = 0usize;
    for case in &cases {
        let mut tx = modsec.new_transaction();
        tx.set_client_addr("203.0.113.7", 40000);
        let mut error: Option<String> = None;
        let mut step = |r: zentinel_modsec::Result<()>| {
            if let Err(e) = r {
                error.get_or_insert_with(|| e.to_string());
            }
        };
        step(tx.process_uri(&case.uri, &case.method, "HTTP/1.1"));
        for (name, value) in &case.headers {
            step(tx.add_request_header(name, value));
        }
        step(tx.process_request_headers());
        if !tx.has_intervention() {
            if let Some(body) = &case.body {
                step(tx.append_request_body(body.as_bytes()));
            }
            step(tx.process_request_body());
        }
        if error.is_some() {
            errors += 1;
        }
        serde_json::to_writer(
            &mut out,
            &serde_json::json!({
                "id": case.id, "rule": case.rule, "family": case.family, "pl": case.pl,
                "kind": case.kind, "sendable": true, "block": tx.has_intervention(),
                "score": tx.anomaly_score(), "matches": tx.matched_rules(), "error": error,
                "intervention": tx.intervention().map(|i| serde_json::json!({
                    "status": i.status, "rules": i.rule_ids, "log": i.log,
                })),
                "inbound": tx.tx().get("blocking_inbound_anomaly_score").map(|v| v.join(",")),
                "hits": tx.matched_data().iter()
                    .map(|m| format!("{}@{}", m.rule_id.as_deref().unwrap_or("-"), m.variable))
                    .collect::<Vec<_>>(),
            }),
        )
        .expect("result written");
        out.write_all(b"\n").expect("newline written");
    }
    eprintln!("{} cases run, {errors} with an engine error", cases.len());
}
