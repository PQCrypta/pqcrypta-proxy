//! `multiMatch`: the operator runs on the value before any transformation and
//! after each one that changed it, as in ModSecurity. CRS 930110 finds a
//! `..\` traversal that its last transformation, t:cmdLine, removes the
//! backslash from.

use zentinel_modsec::ModSecurity;

fn matched(rules: &str, uri: &str) -> Vec<String> {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

const TRAVERSAL: &str = r#"SecRule ARGS "@rx (?:^|[/;\x5c])\.{2,3}[/;\x5c]" "id:1,phase:2,pass,t:none,t:urlDecodeUni,t:cmdLine,multiMatch""#;

#[test]
fn a_match_at_an_earlier_stage_counts() {
    let rules = format!("SecRuleEngine On\n{TRAVERSAL}");
    assert_eq!(matched(&rules, "/?arg=..%5Cpineapple"), ["1"]);
}

#[test]
fn without_multi_match_only_the_last_stage_is_read() {
    let rules = format!("SecRuleEngine On\n{}", TRAVERSAL.replace(",multiMatch", ""));
    assert!(matched(&rules, "/?arg=..%5Cpineapple").is_empty());
}

#[test]
fn a_value_that_never_matches_does_not() {
    let rules = format!("SecRuleEngine On\n{TRAVERSAL}");
    assert!(matched(&rules, "/?arg=pine.apple").is_empty());
}
