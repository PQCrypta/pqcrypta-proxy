//! Validation operators (@validateUrlEncoding, @validateUtf8Encoding).

use super::traits::{Operator, OperatorResult};

/// URL encoding validation operator (@validateUrlEncoding).
pub struct ValidateUrlEncodingOperator;

impl Operator for ValidateUrlEncodingOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if is_valid_url_encoding(value) {
            OperatorResult::no_match() // Valid encoding = no match (not an attack)
        } else {
            OperatorResult::matched("invalid URL encoding".to_string())
        }
    }

    fn name(&self) -> &'static str {
        "validateUrlEncoding"
    }
}

/// UTF-8 encoding validation operator (@validateUtf8Encoding).
pub struct ValidateUtf8EncodingOperator;

impl Operator for ValidateUtf8EncodingOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if is_valid_utf8_sequence(value) {
            OperatorResult::no_match()
        } else {
            OperatorResult::matched("invalid UTF-8 encoding".to_string())
        }
    }

    fn name(&self) -> &'static str {
        "validateUtf8Encoding"
    }
}

/// Check if a string has valid URL encoding.
fn is_valid_url_encoding(s: &str) -> bool {
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            // Must be followed by exactly 2 hex digits
            let hex1 = chars.next();
            let hex2 = chars.next();

            match (hex1, hex2) {
                (Some(h1), Some(h2)) => {
                    if !h1.is_ascii_hexdigit() || !h2.is_ascii_hexdigit() {
                        return false;
                    }
                }
                _ => return false,
            }
        }
    }

    true
}

/// Check for valid UTF-8 sequences (no overlong encodings, etc.).
fn is_valid_utf8_sequence(s: &str) -> bool {
    // A value is a String, so its invalid UTF-8 is what the decoders kept as
    // stand-ins (crate::bytes): truncated sequences, stray continuation
    // bytes, overlong forms (`%c0%af`), surrogates, code points past
    // U+10FFFF. A NUL is valid UTF-8, as in ModSecurity.
    !crate::bytes::has_invalid_utf8(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_url_encoding() {
        assert!(is_valid_url_encoding("hello%20world"));
        assert!(is_valid_url_encoding("test%2Fpath"));
        assert!(!is_valid_url_encoding("hello%2"));
        assert!(!is_valid_url_encoding("hello%GG"));
    }

    #[test]
    fn test_validate_url_encoding_operator() {
        let op = ValidateUrlEncodingOperator;
        assert!(!op.execute("hello%20world").matched); // Valid = no match
        assert!(op.execute("hello%2").matched); // Invalid = match
    }
}
