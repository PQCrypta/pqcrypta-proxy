//! `@validateUtf8Encoding` and `@validateByteRange` on the request's bytes.
//!
//! Values are `String`s, and the decoders replaced every byte that was not
//! UTF-8 with U+FFFD, so CRS's 920250 could never see an overlong `%c0%af`
//! (`/`) or a truncated sequence, and flagged a NUL, which is valid UTF-8.

use zentinel_modsec::ModSecurity;

fn matched(rules: &str, uri: &str) -> Vec<String> {
    let m = ModSecurity::from_string(rules).expect("rules should load");
    let mut tx = m.new_transaction();
    tx.process_uri(uri, "GET", "HTTP/1.1").unwrap();
    tx.process_request_headers().unwrap();
    tx.process_request_body().unwrap();
    tx.matched_rules().to_vec()
}

const UTF8: &str = "SecRuleEngine On\n\
    SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES \"@validateUtf8Encoding\" \"id:920250,phase:2,pass\"";

#[test]
fn invalid_utf8_in_an_argument_is_found() {
    for bad in [
        "%c0%af",
        "%c0",
        "%F5%80%BF%BF",
        "%E2%A3",
        "%ed%a0%80",
        "%80",
    ] {
        assert_eq!(
            matched(UTF8, &format!("/?param={bad}")),
            ["920250"],
            "{bad}"
        );
    }
}

#[test]
fn valid_utf8_and_a_nul_pass() {
    for good in ["caf%C3%A9", "%E2%82%AC", "%F0%9F%94%91", "a%00b", "plain"] {
        assert!(
            matched(UTF8, &format!("/?param={good}")).is_empty(),
            "{good}"
        );
    }
}

#[test]
fn invalid_utf8_in_the_path_and_after_url_decoding_is_found() {
    assert_eq!(matched(UTF8, "/dir%c0%afx"), ["920250"]);
    let decoded = "SecRuleEngine On\n\
        SecRule ARGS \"@validateUtf8Encoding\" \"id:1,phase:2,pass,t:urlDecodeUni\"";
    // %25c0%25af is %c0%af once the argument is decoded, and invalid after t:urlDecodeUni
    assert_eq!(matched(decoded, "/?p=%25c0%25af"), ["1"]);
}

#[test]
fn byte_range_reads_the_byte_that_was_not_utf8() {
    let ascii = "SecRuleEngine On\n\
        SecRule ARGS \"@validateByteRange 32-126\" \"id:1,phase:2,pass\"";
    assert_eq!(matched(ascii, "/?p=%c0"), ["1"]);
    assert!(matched(ascii, "/?p=abc").is_empty());
    let high = "SecRuleEngine On\n\
        SecRule ARGS \"@validateByteRange 1-191\" \"id:1,phase:2,pass\"";
    // 0xc0 is above 191: the byte itself is judged, not its stand-in's UTF-8
    assert_eq!(matched(high, "/?p=%c0"), ["1"]);
    assert!(matched(high, "/?p=%80").is_empty());
}
