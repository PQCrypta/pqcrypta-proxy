//! `@detectSQLi`: libinjection's SQL injection detector (see `super`).

use super::DetectionResult;

/// libinjection's verdict on `input`, with its fingerprint when it is SQL.
pub fn detect_sqli(input: &str) -> DetectionResult {
    let result = libinjectionrs::detect_sqli(input.as_bytes());
    if result.is_injection() {
        DetectionResult::detected(
            result
                .fingerprint
                .map(|f| f.to_string())
                .unwrap_or_default(),
        )
    } else {
        DetectionResult::safe()
    }
}

/// Whether libinjection calls `input` SQL injection.
pub fn is_sqli(input: &str) -> bool {
    detect_sqli(input).is_injection
}

/// libinjection's fingerprint of `input`, when it is SQL injection.
pub fn sqli_fingerprint(input: &str) -> Option<String> {
    detect_sqli(input).fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_is_sql() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("1 UNION SELECT password FROM users"));
    }

    /// The User-Agents the simplified detector called SQL injection
    #[test]
    fn crawler_user_agents_are_not_sql() {
        for ua in [
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36 (compatible; meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler))",
            "Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (HTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
            "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ShapBot/0.1.0",
        ] {
            assert!(!is_sqli(ua), "{ua}");
        }
    }
}
