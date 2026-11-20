//! `REQUEST_BODY` as ModSecurity populates it, the body processor known from
//! the request's head, and the `ctl:` directives and variables CRS uses with
//! them: `forceRequestBodyVariable`, `ruleRemoveByTag`, `UNIQUE_ID`.
//!
//! `REQUEST_BODY` held the raw body for every body, so an XML or JSON body was
//! read twice: through what its processor extracted, and raw, markup and names
//! included. CRS's 944 tests put a payload in an XML element's name, which the
//! rules' XML targets exclude, and the raw read matched it anyway.

use zentinel_modsec::ModSecurity;

fn engine(rules: &str) -> ModSecurity {
    ModSecurity::from_string(rules).expect("rules should load")
}

/// One POST through its own transaction: the IDs of the rules that matched.
fn post(msc: &ModSecurity, content_type: Option<&str>, body: &str) -> Vec<String> {
    let mut tx = msc.new_transaction();
    tx.process_uri("/post", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Host", "example.com").unwrap();
    if let Some(ct) = content_type {
        tx.add_request_header("Content-Type", ct).unwrap();
    }
    tx.process_request_headers().unwrap();
    tx.append_request_body(body.as_bytes()).unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

const RAW_BODY_RULE: &str = "SecRuleEngine On\n\
    SecRequestBodyAccess On\n\
    SecRule REQUEST_BODY \"@contains processbuilder\" \"id:10,phase:2,pass,t:lowercase\"\n";

/// CRS's 901340, verbatim but for its tags: a body no processor parses is
/// read raw.
const FORCE_FOR_UNPARSED: &str =
    "SecRule REQBODY_PROCESSOR \"!@rx (?:URLENCODED|MULTIPART|XML|JSON)\" \
    \"id:901340,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On\"\n";

#[test]
fn an_xml_body_is_not_read_raw() {
    let msc = engine(RAW_BODY_RULE);
    let body =
        r#"<?xml version="1.0"?><xml><ProcessBuilder.evil attr="v">x</ProcessBuilder.evil></xml>"#;
    assert!(!post(&msc, Some("application/xml"), body).contains(&"10".to_string()));
}

#[test]
fn a_json_body_is_read_raw() {
    let msc = engine(RAW_BODY_RULE);
    // CRS's 934210 reads a JSON key followed by `":`, which no argument name
    // carries: the corpus expects JSON raw in REQUEST_BODY
    let body = r#"{"ProcessBuilder": "x"}"#;
    assert!(post(&msc, Some("application/json"), body).contains(&"10".to_string()));
}

#[test]
fn a_form_body_is_read_raw() {
    let msc = engine(RAW_BODY_RULE);
    let matched = post(
        &msc,
        Some("application/x-www-form-urlencoded"),
        "a=ProcessBuilder",
    );
    assert!(matched.contains(&"10".to_string()));
}

#[test]
fn a_body_no_processor_parses_is_read_raw_when_901340_forces_it() {
    let msc = engine(&format!("{RAW_BODY_RULE}{FORCE_FOR_UNPARSED}"));
    let matched = post(&msc, Some("text/plain"), "ProcessBuilder");
    assert!(
        matched.contains(&"10".to_string()),
        "text/plain: {matched:?}"
    );
    let matched = post(&msc, None, "ProcessBuilder");
    assert!(
        matched.contains(&"10".to_string()),
        "no Content-Type: {matched:?}"
    );
    // ...and an XML body is not forced, because its processor is known in
    // phase 1, where 901340 decides
    let body = r#"<xml><ProcessBuilder/></xml>"#;
    assert!(!post(&msc, Some("application/xml"), body).contains(&"10".to_string()));
}

#[test]
fn force_request_body_variable_reads_any_body_raw() {
    let msc = engine(&format!(
        "{RAW_BODY_RULE}SecAction \"id:1,phase:1,pass,nolog,ctl:forceRequestBodyVariable=On\"\n"
    ));
    let body = r#"<xml><ProcessBuilder/></xml>"#;
    assert!(post(&msc, Some("application/xml"), body).contains(&"10".to_string()));
}

#[test]
fn the_body_processor_is_known_in_phase_one() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule REQBODY_PROCESSOR \"@streq XML\" \"id:1,phase:1,pass\"\n\
         SecRule REQBODY_PROCESSOR \"@streq JSON\" \"id:2,phase:1,pass\"\n\
         SecRule REQBODY_PROCESSOR \"@streq URLENCODED\" \"id:3,phase:1,pass\"\n\
         SecRule REQBODY_PROCESSOR \"@streq MULTIPART\" \"id:4,phase:1,pass\"\n",
    );
    assert!(post(&msc, Some("text/xml; charset=utf-8"), "<a/>").contains(&"1".to_string()));
    assert!(post(&msc, Some("application/json"), "{}").contains(&"2".to_string()));
    assert!(post(&msc, Some("application/x-www-form-urlencoded"), "a=b").contains(&"3".to_string()));
    let mp = post(&msc, Some("multipart/form-data; boundary=x"), "--x--\r\n");
    assert!(mp.contains(&"4".to_string()));
    assert!(post(&msc, Some("text/plain"), "x").is_empty());
}

#[test]
fn a_forced_processor_is_the_one_phase_one_reads_after_the_ctl() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule REQUEST_HEADERS:Content-Type \"@rx ^text/plain\" \
             \"id:1,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON\"\n\
         SecRule REQBODY_PROCESSOR \"@streq JSON\" \"id:2,phase:1,pass\"\n",
    );
    assert!(post(&msc, Some("text/plain"), "{}").contains(&"2".to_string()));
}

#[test]
fn a_multipart_body_without_a_boundary_is_a_body_error() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule REQBODY_ERROR \"!@eq 0\" \"id:200002,phase:2,deny,status:400\"\n",
    );
    let mut tx = msc.new_transaction();
    tx.process_uri("/upload", "POST", "HTTP/1.1").unwrap();
    tx.add_request_header("Content-Type", "multipart/form-data")
        .unwrap();
    tx.process_request_headers().unwrap();
    tx.append_request_body(b"--x\r\nContent-Disposition: form-data; name=a\r\n\r\nb\r\n--x--\r\n")
        .unwrap();
    tx.process_request_body().unwrap();
    assert!(
        tx.has_intervention(),
        "no boundary: the body cannot be parsed"
    );
}

#[test]
fn rule_remove_by_tag_lifts_every_rule_with_the_tag() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule REQUEST_HEADERS:User-Agent \"@contains internal dummy connection\" \
             \"id:905100,phase:1,pass,nolog,ctl:ruleRemoveByTag=OWASP_CRS\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:2,phase:1,pass,tag:'OWASP_CRS'\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:3,phase:2,pass,tag:'OWASP_CRS',tag:'other'\"\n\
         SecRule REQUEST_URI \"@contains /\" \"id:4,phase:2,pass,tag:'site'\"\n",
    );
    let run = |ua: &str| {
        let mut tx = msc.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.add_request_header("User-Agent", ua).unwrap();
        tx.process_request_headers().unwrap();
        tx.process_request_body().unwrap();
        tx.matched_rules().to_vec()
    };
    let lifted = run("Apache (internal dummy connection)");
    assert!(!lifted.contains(&"2".to_string()) && !lifted.contains(&"3".to_string()));
    assert!(
        lifted.contains(&"4".to_string()),
        "an untagged rule still runs"
    );
    let ordinary = run("Mozilla/5.0");
    assert!(ordinary.contains(&"2".to_string()) && ordinary.contains(&"3".to_string()));
}

#[test]
fn unique_id_names_each_transaction() {
    let msc = engine(
        "SecRuleEngine On\n\
         SecRule UNIQUE_ID \"@rx ^([0-9a-f]{32})$\" \"id:1,phase:1,pass,capture,setvar:tx.uid=%{TX.1}\"\n\
         SecRule UNIQUE_ID \"@streq req-42\" \"id:2,phase:1,pass\"\n",
    );
    use zentinel_modsec::variables::Collection;
    let generated = || {
        let mut tx = msc.new_transaction();
        tx.process_uri("/", "GET", "HTTP/1.1").unwrap();
        tx.process_request_headers().unwrap();
        assert_eq!(tx.matched_rules(), ["1"], "32 hex digits");
        tx.tx()
            .get("uid")
            .and_then(|v| v.first().map(|s| s.to_string()))
            .unwrap()
    };
    let (a, b) = (generated(), generated());
    assert_ne!(a, b, "each transaction has its own");

    let mut c = msc.new_transaction();
    c.set_unique_id("req-42");
    c.process_uri("/", "GET", "HTTP/1.1").unwrap();
    c.process_request_headers().unwrap();
    assert_eq!(
        c.matched_rules(),
        ["2"],
        "the caller's request ID stands in"
    );
}
