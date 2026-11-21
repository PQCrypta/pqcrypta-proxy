//! Pattern matching operators (@rx, @pm).
//!
//! Optimized with lazy regex compilation for fast rule parsing.

use super::traits::{Operator, OperatorResult};
use crate::error::{Error, Result};
use aho_corasick::AhoCorasick;
use once_cell::sync::OnceCell;
use regex::bytes::{Regex, RegexBuilder};

/// Regex operator (@rx) with lazy compilation.
///
/// Matched as ModSecurity matches: PCRE without UTF mode, with DOTALL. The
/// pattern runs over the value's bytes, so `\xe2\x80\x99` in a CRS pattern
/// is the three bytes of `’` (not U+00E2 and two controls), `\w`, `\s`,
/// `\d` and `(?i)` are ASCII, and `.` is any byte, a newline included. A
/// pattern that only Unicode mode can express (`\x{2019}`, `\p{L}`) is
/// compiled in it, over the same bytes.
///
/// The pattern's *syntax* is validated when the rule is loaded, but the
/// automaton is only built on first use — CRS defines hundreds of regex rules
/// and most requests exercise few of them.
///
/// The distinction matters: an invalid pattern must be a load error. If it
/// were discovered at match time there would be nothing useful to do about it,
/// and the rule would silently never match — a dead rule that looks alive.
pub struct RxOperator {
    pattern_str: String,
    /// `None` once compilation has been attempted and failed, so a pattern
    /// that passes syntax validation but cannot be built (an oversized
    /// program, say) is reported once rather than retried per request.
    compiled: OnceCell<Option<Regex>>,
}

impl RxOperator {
    /// Create a new regex operator, validating the pattern's syntax.
    ///
    /// Parsing with `regex-syntax` catches every syntax error the full
    /// compiler would, without building the automaton, so loading stays fast
    /// while a malformed pattern fails loudly at load instead of turning into
    /// a rule that can never match.
    #[inline]
    pub fn new(pattern: &str) -> Result<Self> {
        if pattern.is_empty() {
            return Err(Error::RegexCompile {
                pattern: pattern.to_string(),
                source: regex::Error::Syntax("empty pattern".to_string()),
            });
        }

        // Valid as PCRE reads it (bytes), or failing that in Unicode mode
        let as_bytes = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern);
        if as_bytes.is_err() {
            if let Err(e) = regex_syntax::Parser::new().parse(pattern) {
                return Err(Error::RegexCompile {
                    pattern: pattern.to_string(),
                    source: regex::Error::Syntax(e.to_string()),
                });
            }
        }

        Ok(Self {
            pattern_str: pattern.to_string(),
            compiled: OnceCell::new(),
        })
    }

    /// Get or compile the regex pattern.
    ///
    /// Returns `None` if compilation failed. Syntax was already validated in
    /// [`RxOperator::new`], so reaching this is rare — a program too large to
    /// build, for instance. It is reported once, because a rule that cannot
    /// match must not do so silently.
    #[inline]
    fn get_regex(&self) -> Option<&Regex> {
        self.compiled
            .get_or_init(|| match compile(&self.pattern_str) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    tracing::error!(
                        pattern = %self.pattern_str,
                        error = %e,
                        "regex could not be compiled at first use; this rule can never match"
                    );
                    None
                }
            })
            .as_ref()
    }
}

/// A pattern as PCRE compiles it for ModSecurity: bytes, DOTALL; Unicode mode
/// only for a pattern that cannot be written without it.
fn compile(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    let build = |pattern: &str, unicode: bool| {
        RegexBuilder::new(pattern)
            .unicode(unicode)
            .dot_matches_new_line(true)
            .size_limit(64 << 20)
            .build()
    };
    build(&braced_bytes(pattern), false).or_else(|_| build(pattern, true))
}

/// `\x{hh}` as `\xhh`. In PCRE without UTF mode both are the byte; in this
/// crate the braced form is the code point even with Unicode off, so CRS's
/// `\x{e2}\x80[\x98\x99]` (942430's `’`) looked for U+00E2. Escaped
/// backslashes are passed over in pairs, so `\\x{41}` stays a backslash
/// and text. A value above 0xff is left as it is.
fn braced_bytes(pattern: &str) -> std::borrow::Cow<'_, str> {
    if !pattern.contains("\\x{") {
        return std::borrow::Cow::Borrowed(pattern);
    }
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let rest = &pattern[i + 1..];
        if let Some(inner) = rest.strip_prefix("x{") {
            if let Some(end) = inner.find('}') {
                let hex = &inner[..end];
                if (1..=2).contains(&hex.len()) && hex.chars().all(|h| h.is_ascii_hexdigit()) {
                    out.push_str(&format!("\\x{:0>2}", hex));
                    // past `x{`, the digits and `}`
                    for _ in 0..(2 + hex.len() + 1) {
                        chars.next();
                    }
                    continue;
                }
            }
        }
        // Any other escape, an escaped backslash included, as written
        out.push(c);
        if let Some((_, next)) = chars.next() {
            out.push(next);
        }
    }
    std::borrow::Cow::Owned(out)
}

impl Operator for RxOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        let Some(regex) = self.get_regex() else {
            return OperatorResult::no_match();
        };
        let haystack = crate::bytes::request_bytes(value);

        if let Some(captures) = regex.captures(&haystack) {
            let text = |m: regex::bytes::Match<'_>| crate::bytes::text(m.as_bytes());
            let matched_value = captures.get(0).map(text);
            let capture_groups: Vec<String> = captures
                .iter()
                .skip(1) // Skip the full match
                // A group that did not take part stays in its slot (empty), so
                // TX:2 is always the second group.
                .map(|c| c.map(text).unwrap_or_default())
                .collect();

            OperatorResult {
                matched: true,
                captures: capture_groups,
                matched_value,
            }
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "rx"
    }

    fn supports_capture(&self) -> bool {
        true
    }
}

/// Phrase match operator (@pm).
pub struct PmOperator {
    automaton: AhoCorasick,
    patterns: Vec<String>,
}

impl PmOperator {
    /// Create a new phrase match operator from space-separated patterns.
    pub fn new(patterns_str: &str) -> Result<Self> {
        let patterns: Vec<String> = patterns_str
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern list".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self {
            automaton,
            patterns,
        })
    }

    /// Create a phrase match operator from a file.
    pub fn from_file(path: &str) -> Result<Self> {
        // Try the path as-is first, then common CRS locations
        let possible_paths = [
            path.to_string(),
            format!("test-rules/crs/rules/{}", path),
            format!("rules/{}", path),
        ];

        let mut content = None;
        let mut last_error = None;

        for p in &possible_paths {
            match std::fs::read_to_string(p) {
                Ok(c) => {
                    content = Some(c);
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        let content = content.ok_or_else(|| Error::RuleFileLoad {
            path: path.into(),
            source: last_error.unwrap(),
        })?;

        let patterns: Vec<String> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|s| s.to_string())
            .collect();

        if patterns.is_empty() {
            return Err(Error::PatternSet {
                message: "empty pattern file".to_string(),
            });
        }

        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .map_err(|e| Error::PatternSet {
                message: e.to_string(),
            })?;

        Ok(Self {
            automaton,
            patterns,
        })
    }
}

impl Operator for PmOperator {
    fn execute(&self, value: &str) -> OperatorResult {
        if let Some(mat) = self.automaton.find(value) {
            let matched = &self.patterns[mat.pattern().as_usize()];
            OperatorResult::matched(matched.clone())
        } else {
            OperatorResult::no_match()
        }
    }

    fn name(&self) -> &'static str {
        "pm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rx(pattern: &str, value: &str) -> bool {
        RxOperator::new(pattern).unwrap().execute(value).matched
    }

    /// PCRE without UTF mode, as ModSecurity runs CRS: bytes, ASCII classes,
    /// DOTALL
    #[test]
    fn patterns_match_bytes_as_pcre_does() {
        // CRS 942430's class holds the bytes of ’ and ´
        assert!(rx(r"[\xc2\xb4\xe2\x80\x99]{3}", "\u{2019}"));
        assert!(rx(r"^\xe2\x80\x99$", "\u{2019}"));
        assert!(!rx(r"^\xe2$", "\u{e2}"), "\\xe2 is a byte, not U+00E2");
        assert!(rx(r"a.b", "a\nb"), "DOTALL");
        assert!(!rx(r"^\w+$", "caf\u{e9}"), "\\w is ASCII");
        assert!(!rx(r"(?i)^k$", "\u{212a}"), "case folding is ASCII");
        assert!(rx(r"(?i)^select$", "SeLeCt"));
        // A byte that was not UTF-8, kept as its stand-in, is matched as itself
        assert!(rx(r"\xc0\xaf", &crate::bytes::text(b"..\xc0\xaf..")));
        // A pattern only Unicode mode can write still works
        assert!(rx(r"\x{2019}", "it\u{2019}s"));
        assert!(rx(r"\p{Greek}", "\u{3b1}"));
    }

    /// CRS 4.31 writes byte escapes braced: `\x{e2}` is the byte, as in PCRE
    #[test]
    fn braced_byte_escapes_are_bytes() {
        assert!(rx(r"^\x{e2}\x80[\x98\x99]$", "\u{2019}"));
        assert!(rx(r"\x{c2}\x{b4}", "\u{b4}"));
        assert_eq!(braced_bytes(r"\x{e2}[\x{9}-\x{d}]"), r"\xe2[\x09-\x0d]");
        assert_eq!(braced_bytes(r"\\x{41}"), r"\\x{41}", "an escaped backslash");
        assert_eq!(braced_bytes(r"\x{2019}"), r"\x{2019}", "above a byte");
        assert!(
            rx(r"\x{2019}", "\u{2019}"),
            "still matches, in Unicode mode"
        );
    }

    #[test]
    fn captures_come_back_as_text() {
        let r = RxOperator::new(r"(\xe2\x80\x99)(x)?")
            .unwrap()
            .execute("a\u{2019}");
        assert_eq!(r.captures, ["\u{2019}", ""]);
        assert_eq!(r.matched_value.as_deref(), Some("\u{2019}"));
    }

    #[test]
    fn test_rx_simple() {
        let op = RxOperator::new("^admin").unwrap();
        assert!(op.execute("admin").matched);
        assert!(!op.execute("user").matched);
    }

    #[test]
    fn test_rx_captures() {
        let op = RxOperator::new(r"user=(\w+)").unwrap();
        let result = op.execute("user=john");
        assert!(result.matched);
        assert_eq!(result.captures, vec!["john"]);
    }

    #[test]
    fn test_pm_simple() {
        let op = PmOperator::new("admin root user").unwrap();
        assert!(op.execute("the admin user").matched);
        assert!(!op.execute("guest").matched);
    }

    #[test]
    fn test_pm_case_insensitive() {
        let op = PmOperator::new("ADMIN").unwrap();
        assert!(op.execute("admin").matched);
        assert!(op.execute("Admin").matched);
    }
}
