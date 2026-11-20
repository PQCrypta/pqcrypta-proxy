//! `@detectXSS`: libinjection's XSS detector (see `super`).

use super::DetectionResult;

/// libinjection's verdict on `input` (XSS has no fingerprint).
pub fn detect_xss(input: &str) -> DetectionResult {
    if libinjectionrs::detect_xss(input.as_bytes()).is_injection() {
        DetectionResult::detected(String::new())
    } else {
        DetectionResult::safe()
    }
}

/// Whether libinjection calls `input` XSS.
pub fn is_xss(input: &str) -> bool {
    detect_xss(input).is_injection
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_is_xss() {
        assert!(is_xss("<script>alert(1)</script>"));
        assert!(is_xss("<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn prose_is_not_xss() {
        assert!(!is_xss("Hello, world"));
        assert!(!is_xss("a < b and c > d"));
    }
}
