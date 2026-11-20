//! Text from bytes that need not be UTF-8.
//!
//! A request carries bytes; rules match text, and this engine's values are
//! `String`s. Decoding replaced every byte that was not UTF-8 with U+FFFD,
//! so `@validateUtf8Encoding` could never see an invalid sequence (an
//! overlong `%c0%af` for `/` arrived as two replacement characters) and
//! `@validateByteRange` never saw the byte. Here each such byte becomes one
//! private-use character, U+F700 plus the byte (U+F780..U+F7FF, since only
//! bytes from 0x80 can be invalid), which the operators that judge bytes
//! read back as the byte it stands for.
//!
//! Valid UTF-8 that encodes one of those code points itself reads as the
//! byte too: input chosen to look invalid, which is flagged, never input
//! that hides as valid.

/// The first code point standing for a raw byte: U+F700 + byte.
const RAW_BYTE_BASE: u32 = 0xF700;

/// The bytes as text: UTF-8 runs as they are, each byte of an invalid
/// sequence as its stand-in character.
pub fn text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for &b in chunk.invalid() {
            out.push(
                char::from_u32(RAW_BYTE_BASE + u32::from(b)).unwrap_or(char::REPLACEMENT_CHARACTER),
            );
        }
    }
    out
}

/// The byte a stand-in character stands for.
pub fn raw_byte(c: char) -> Option<u8> {
    let n = u32::from(c);
    (RAW_BYTE_BASE + 0x80..=RAW_BYTE_BASE + 0xff)
        .contains(&n)
        .then(|| (n - RAW_BYTE_BASE) as u8)
}

/// The bytes the text stands for: each stand-in as its byte, everything else
/// as its UTF-8.
pub fn bytes(s: &str) -> impl Iterator<Item = u8> + '_ {
    s.chars().flat_map(|c| {
        let mut buf = [0u8; 4];
        let encoded: Vec<u8> = match raw_byte(c) {
            Some(b) => vec![b],
            None => c.encode_utf8(&mut buf).as_bytes().to_vec(),
        };
        encoded.into_iter()
    })
}

/// Whether the text holds a byte that was not UTF-8.
pub fn has_invalid_utf8(s: &str) -> bool {
    s.chars().any(|c| raw_byte(c).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bytes_survive_as_themselves() {
        let input = b"a\xc0\xafb\xe2\x82\xacc\xff";
        let t = text(input);
        assert!(t.starts_with('a') && t.contains('\u{20ac}'));
        assert!(has_invalid_utf8(&t));
        assert_eq!(bytes(&t).collect::<Vec<_>>(), input);
        assert!(!has_invalid_utf8(&text("caf\u{e9}".as_bytes())));
    }
}
