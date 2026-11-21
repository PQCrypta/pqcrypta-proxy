//! Decoding transformations.

use super::Transformation;
use std::borrow::Cow;

/// ModSecurity's non-strict URL decoding, on bytes: `%XX` decoded, an
/// invalid or truncated escape kept as it is, `+` to a space, and with
/// `unicode`, `%uXXXX` as the byte ModSecurity's Unicode map gives it (code
/// page 20127, its recommended map: `%u2019` is `'`), else its low byte.
/// `None` when nothing changed. CRS's rules expect `+` as a space from both (932200
/// reads a command's arguments after `t:urlDecodeUni`).
fn url_decode(input: &str, unicode: bool) -> Option<String> {
    fn hex(c: u8) -> Option<u8> {
        (c as char).to_digit(16).map(|d| d as u8)
    }
    let b = input.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut changed = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if unicode
                && i + 5 < b.len()
                && (b[i + 1] | 0x20) == b'u'
                && b[i + 2..i + 6].iter().all(|&c| hex(c).is_some()) =>
            {
                let code = b[i + 2..i + 6]
                    .iter()
                    .fold(0u32, |acc, &c| acc * 16 + u32::from(hex(c).unwrap_or(0)));
                // ModSecurity's: the byte the Unicode map (code page 20127,
                // super::unicode_map) gives the code point, else its low byte;
                // a full-width ASCII form with no mapping is that ASCII
                let low = (code & 0xff) as u8;
                let byte = super::unicode_map::cp20127(code).unwrap_or(
                    if code >> 8 == 0xff && low > 0 && low < 0x5f {
                        low + 0x20
                    } else {
                        low
                    },
                );
                out.push(byte);
                i += 6;
                changed = true;
            }
            b'%' => match (
                b.get(i + 1).and_then(|&c| hex(c)),
                b.get(i + 2).and_then(|&c| hex(c)),
            ) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                    changed = true;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
                changed = true;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    if !changed {
        return None;
    }
    // Decoded bytes that are not UTF-8 are kept, each as itself
    // (crate::bytes), for @validateUtf8Encoding and @validateByteRange
    Some(crate::bytes::text(&out))
}

/// URL decode transformation (`t:urlDecode`).
pub struct UrlDecode;

impl Transformation for UrlDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        url_decode(input, false).map_or(Cow::Borrowed(input), Cow::Owned)
    }

    fn name(&self) -> &'static str {
        "urlDecode"
    }
}

/// URL decode with `%uXXXX` escapes (`t:urlDecodeUni`).
pub struct UrlDecodeUni;

impl Transformation for UrlDecodeUni {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        url_decode(input, true).map_or(Cow::Borrowed(input), Cow::Owned)
    }

    fn name(&self) -> &'static str {
        "urlDecodeUni"
    }
}

/// Base64 decode transformation.
pub struct Base64Decode;

impl Transformation for Base64Decode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(input) {
            Ok(bytes) => Cow::Owned(crate::bytes::text(&bytes)),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64Decode"
    }
}

/// Extended base64 decode (handles URL-safe base64).
pub struct Base64DecodeExt;

impl Transformation for Base64DecodeExt {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        use base64::Engine;
        // Try URL-safe first, then standard
        let result = base64::engine::general_purpose::URL_SAFE
            .decode(input)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(input));

        match result {
            Ok(bytes) => Cow::Owned(crate::bytes::text(&bytes)),
            Err(_) => Cow::Borrowed(input),
        }
    }

    fn name(&self) -> &'static str {
        "base64DecodeExt"
    }
}

/// Hex decode transformation.
pub struct HexDecode;

impl Transformation for HexDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = Vec::new();
        let mut chars = input.chars().peekable();

        while let Some(c1) = chars.next() {
            if let Some(c2) = chars.next() {
                let hex = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte);
                } else {
                    // Invalid hex, keep original
                    return Cow::Borrowed(input);
                }
            } else {
                // Odd number of chars
                return Cow::Borrowed(input);
            }
        }

        Cow::Owned(crate::bytes::text(&result))
    }

    fn name(&self) -> &'static str {
        "hexDecode"
    }
}

/// HTML entity decode transformation.
pub struct HtmlEntityDecode;

impl Transformation for HtmlEntityDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let decoded = html_escape::decode_html_entities(input);
        if decoded == input {
            Cow::Borrowed(input)
        } else {
            Cow::Owned(decoded.into_owned())
        }
    }

    fn name(&self) -> &'static str {
        "htmlEntityDecode"
    }
}

/// JavaScript decode transformation.
pub struct JsDecode;

impl Transformation for JsDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                match chars.next() {
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some('x') => {
                        // \xHH
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                            result.push(byte as char);
                        } else {
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    }
                    Some('u') => {
                        // \uHHHH
                        let mut hex = String::new();
                        for _ in 0..4 {
                            if let Some(h) = chars.next() {
                                hex.push(h);
                            }
                        }
                        if let Ok(code) = u32::from_str_radix(&hex, 16) {
                            if let Some(decoded) = char::from_u32(code) {
                                result.push(decoded);
                            } else {
                                result.push('\\');
                                result.push('u');
                                result.push_str(&hex);
                            }
                        } else {
                            result.push('\\');
                            result.push('u');
                            result.push_str(&hex);
                        }
                    }
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "jsDecode"
    }
}

/// CSS decode transformation.
pub struct CssDecode;

impl Transformation for CssDecode {
    fn transform<'a>(&self, input: &'a str) -> Cow<'a, str> {
        let mut result = String::new();
        let mut chars = input.chars().peekable();
        let mut modified = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                modified = true;
                // CSS escape: \HH or \HHHHHH
                let mut hex = String::new();
                while hex.len() < 6 {
                    match chars.peek() {
                        Some(h) if h.is_ascii_hexdigit() => {
                            hex.push(chars.next().unwrap());
                        }
                        _ => break,
                    }
                }
                // Skip optional whitespace after hex
                if let Some(' ') | Some('\t') | Some('\n') = chars.peek() {
                    chars.next();
                }

                if !hex.is_empty() {
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(decoded) = char::from_u32(code) {
                            result.push(decoded);
                            continue;
                        }
                    }
                }
                result.push('\\');
                result.push_str(&hex);
            } else {
                result.push(c);
            }
        }

        if modified {
            Cow::Owned(result)
        } else {
            Cow::Borrowed(input)
        }
    }

    fn name(&self) -> &'static str {
        "cssDecode"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_decode() {
        let t = UrlDecode;
        assert_eq!(t.transform("hello%20world"), "hello world");
        assert_eq!(t.transform("test%2Fpath"), "test/path");
    }

    /// ModSecurity's decoding: `+` is a space, an invalid escape stays, and
    /// a byte that is not UTF-8 does not stop the rest from being decoded
    #[test]
    fn url_decoding_is_modsecuritys() {
        for t in [&UrlDecode as &dyn Transformation, &UrlDecodeUni] {
            assert_eq!(t.transform("cat+/etc/passwd"), "cat /etc/passwd");
            assert_eq!(t.transform("100%"), "100%");
            assert_eq!(t.transform("a%zzb%4"), "a%zzb%4");
            // %ff is not UTF-8: kept as itself, its stand-in (crate::bytes)
            assert_eq!(t.transform("%3Cscript%3E%ff"), "<script>\u{f7ff}");
            assert_eq!(t.transform("%E2%82%AC"), "\u{20ac}");
            assert!(matches!(t.transform("plain"), Cow::Borrowed(_)));
        }
        assert_eq!(UrlDecode.transform("%u0041"), "%u0041");
        assert_eq!(UrlDecodeUni.transform("%u0041%u00"), "A%u00");
    }

    #[test]
    fn url_decode_uni_folds_fullwidth_ascii_escapes() {
        let t = UrlDecodeUni;
        for ascii in b'!'..=b'~' {
            let escaped = format!("%u{:04X}", u32::from(ascii) + 0xfee0);
            assert_eq!(t.transform(&escaped), char::from(ascii).to_string());
        }
        assert_eq!(t.transform("%UFF21"), "A");
        // Outside the map, the low byte, as ModSecurity
        assert_eq!(t.transform("%uFF00%uFF5F"), "\0_");
        assert_eq!(t.transform("%u4e2d"), "-");
        assert_eq!(
            t.transform("\u{ff21}"),
            "\u{ff21}",
            "only escapes are mapped"
        );
    }

    /// `%uXXXX` through code page 20127, ModSecurity's recommended map:
    /// typographic quotes and angle quotes are what they look like
    #[test]
    fn url_decode_uni_maps_look_alikes_to_ascii() {
        let t = UrlDecodeUni;
        assert_eq!(
            t.transform("%u2019 or %u2019a%u2019=%u2019a"),
            "' or 'a'='a"
        );
        assert_eq!(t.transform("%u00abscript%u00bb"), "<script>");
        assert_eq!(t.transform("%u2039script%u203a"), "<script>");
    }

    #[test]
    fn test_base64_decode() {
        let t = Base64Decode;
        assert_eq!(t.transform("aGVsbG8="), "hello");
    }

    #[test]
    fn test_html_entity_decode() {
        let t = HtmlEntityDecode;
        assert_eq!(t.transform("&lt;script&gt;"), "<script>");
        assert_eq!(t.transform("&#60;"), "<");
    }

    #[test]
    fn test_js_decode() {
        let t = JsDecode;
        assert_eq!(t.transform(r"\x3cscript\x3e"), "<script>");
        assert_eq!(t.transform(r"\u003c"), "<");
    }
}
