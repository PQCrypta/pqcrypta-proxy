//! MOQT's common structures (draft-ietf-moq-transport section 8).
//!
//! MOQT's variable-length integer is not QUIC's: the count of leading 1 bits
//! of the first byte gives the length, 1 to 9 bytes, so every 64-bit value
//! has an encoding (section 8.1). Any encoding length that can hold a value
//! is valid, so the decoder takes the long forms too; the encoder writes the
//! shortest.

use bytes::{BufMut, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt};

use super::error::{fail, SessionCode as C, SessionResult};

/// Largest number of Track Namespace Fields (section 8.7).
pub const MAX_NAMESPACE_FIELDS: usize = 32;
/// Largest Full Track Name, namespace fields and name together (section 8.7).
pub const MAX_FULL_TRACK_NAME: usize = 4096;
/// Largest Reason Phrase (section 8.5).
pub const MAX_REASON_PHRASE: usize = 1024;
/// Largest Key-Value-Pair value (section 8.3).
pub const MAX_KVP_VALUE: usize = 0xFFFF;

/// The encoded length of `value` in its shortest form.
pub const fn vi64_len(value: u64) -> usize {
    match value {
        0..0x80 => 1,
        0x80..0x4000 => 2,
        0x4000..0x20_0000 => 3,
        0x20_0000..0x1000_0000 => 4,
        0x1000_0000..0x8_0000_0000 => 5,
        0x8_0000_0000..0x400_0000_0000 => 6,
        0x400_0000_0000..0x2_0000_0000_0000 => 7,
        0x2_0000_0000_0000..0x100_0000_0000_0000 => 8,
        _ => 9,
    }
}

/// Append `value` in its shortest form.
pub fn put_vi64(out: &mut Vec<u8>, value: u64) {
    let len = vi64_len(value);
    if len == 9 {
        out.push(0xFF);
        out.extend_from_slice(&value.to_be_bytes());
        return;
    }
    // `len - 1` leading 1 bits, a 0, then the value's bits
    let prefix: u8 = !(0xFFu8 >> (len - 1));
    let be = value.to_be_bytes();
    let start = out.len();
    out.extend_from_slice(&be[8 - len..]);
    out[start] |= prefix;
}

/// The length an encoding whose first byte is `first` has.
pub const fn vi64_len_from_first(first: u8) -> usize {
    let ones = first.leading_ones() as usize;
    if ones >= 8 {
        9
    } else {
        ones + 1
    }
}

fn vi64_value(bytes: &[u8]) -> u64 {
    let len = bytes.len();
    if len == 9 {
        return u64::from_be_bytes(bytes[1..9].try_into().expect("9 bytes"));
    }
    // `len - 1` leading ones and a zero precede the value's bits; at 8
    // bytes the first byte holds none of them
    let mask: u8 = u32::try_from(len)
        .ok()
        .and_then(|l| 0xFFu8.checked_shr(l))
        .unwrap_or(0);
    let mut value = u64::from(bytes[0] & mask);
    for b in &bytes[1..] {
        value = (value << 8) | u64::from(*b);
    }
    value
}

/// Read one variable-length integer from a stream; `None` at a clean end of
/// stream before its first byte.
pub async fn read_vi64<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<u64>> {
    let mut first = [0u8; 1];
    if r.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let len = vi64_len_from_first(first[0]);
    let mut buf = [0u8; 9];
    buf[0] = first[0];
    r.read_exact(&mut buf[1..len]).await?;
    Ok(Some(vi64_value(&buf[..len])))
}

/// One byte from a stream.
pub async fn read_u8<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b).await?;
    Ok(b[0])
}

/// A cursor over a message body.
///
/// Every read that runs past the end is the error the caller names (a control message's length that does not match
/// its contents is MALFORMED_MESSAGE, a datagram's is MALFORMED_OBJECT).
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    short: SessionCode,
}

use super::error::SessionCode;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], short: SessionCode) -> Self {
        Self { buf, pos: 0, short }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn short<T>(&self) -> SessionResult<T> {
        fail(self.short, "a field runs past the end of its message")
    }

    pub fn vi64(&mut self) -> SessionResult<u64> {
        let Some(&first) = self.buf.get(self.pos) else {
            return self.short();
        };
        let len = vi64_len_from_first(first);
        let Some(bytes) = self.buf.get(self.pos..self.pos + len) else {
            return self.short();
        };
        self.pos += len;
        Ok(vi64_value(bytes))
    }

    pub fn u8(&mut self) -> SessionResult<u8> {
        let Some(&b) = self.buf.get(self.pos) else {
            return self.short();
        };
        self.pos += 1;
        Ok(b)
    }

    pub fn u16(&mut self) -> SessionResult<u16> {
        let b = self.bytes(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> SessionResult<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn bytes(&mut self, len: usize) -> SessionResult<&'a [u8]> {
        let Some(end) = self.pos.checked_add(len) else {
            return self.short();
        };
        let Some(bytes) = self.buf.get(self.pos..end) else {
            return self.short();
        };
        self.pos = end;
        Ok(bytes)
    }

    /// A varint length then that many bytes.
    pub fn prefixed(&mut self) -> SessionResult<&'a [u8]> {
        let len = self.vi64()?;
        let len = usize::try_from(len).or_else(|_| self.short())?;
        self.bytes(len)
    }

    /// Everything left.
    pub fn rest(&mut self) -> &'a [u8] {
        let rest = &self.buf[self.pos..];
        self.pos = self.buf.len();
        rest
    }

    /// A Track Namespace (section 8.7); `prefix` allows zero fields (a
    /// namespace prefix, or a suffix after one).
    pub fn namespace(&mut self) -> SessionResult<Namespace> {
        let count = self.vi64()?;
        if count > MAX_NAMESPACE_FIELDS as u64 {
            return fail(
                C::InvalidTrackNamespace,
                "more than 32 Track Namespace Fields",
            );
        }
        let mut fields = Vec::new();
        let mut total = 0usize;
        for _ in 0..count {
            let field = self.prefixed()?;
            if field.is_empty() {
                return fail(
                    C::InvalidTrackNamespace,
                    "a Track Namespace Field of length 0",
                );
            }
            total += field.len();
            if total > MAX_FULL_TRACK_NAME {
                return fail(
                    C::FieldLengthExceeded,
                    "a Track Namespace longer than 4096 bytes",
                );
            }
            fields.push(Bytes::copy_from_slice(field));
        }
        Ok(Namespace(fields))
    }

    /// A Track Name after `namespace`; it must not be empty (section 2.4.1)
    /// and the two together must fit in 4096 bytes (section 8.7).
    pub fn track_name(&mut self, namespace: &Namespace) -> SessionResult<Bytes> {
        let name = self.prefixed()?;
        if name.is_empty() {
            return fail(C::ProtocolViolation, "a Track Name of length 0");
        }
        if namespace.byte_len() + name.len() > MAX_FULL_TRACK_NAME {
            return fail(
                C::FieldLengthExceeded,
                "a Full Track Name longer than 4096 bytes",
            );
        }
        Ok(Bytes::copy_from_slice(name))
    }

    pub fn location(&mut self) -> SessionResult<Location> {
        Ok(Location {
            group: self.vi64()?,
            object: self.vi64()?,
        })
    }

    /// A Reason Phrase (section 8.5).
    pub fn reason(&mut self) -> SessionResult<String> {
        let len = self.vi64()?;
        if len > MAX_REASON_PHRASE as u64 {
            return fail(
                C::FieldLengthExceeded,
                "a Reason Phrase longer than 1024 bytes",
            );
        }
        let bytes = self.bytes(usize::try_from(len).unwrap_or(usize::MAX))?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Key-Value-Pairs to the end of the reader (section 8.3).
    pub fn kvps_to_end(&mut self) -> SessionResult<Vec<Kvp>> {
        let mut out = Vec::new();
        let mut last = 0u64;
        while !self.is_empty() {
            out.push(self.kvp(&mut last)?);
        }
        Ok(out)
    }

    /// One Key-Value-Pair, its type delta encoded from `last`.
    pub fn kvp(&mut self, last: &mut u64) -> SessionResult<Kvp> {
        let delta = self.vi64()?;
        let Some(kind) = last.checked_add(delta) else {
            return fail(
                C::DeltaEncodingOverflow,
                "a Key-Value-Pair type past 2^64 - 1",
            );
        };
        *last = kind;
        let value = if kind % 2 == 0 {
            KvpValue::Int(self.vi64()?)
        } else {
            let len = self.vi64()?;
            if len > MAX_KVP_VALUE as u64 {
                return fail(
                    C::FieldLengthExceeded,
                    "a Key-Value-Pair value longer than 65535 bytes",
                );
            }
            KvpValue::Bytes(Bytes::copy_from_slice(
                self.bytes(usize::try_from(len).unwrap_or(usize::MAX))?,
            ))
        };
        Ok(Kvp { kind, value })
    }
}

/// A Track Namespace: its fields in order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Namespace(pub Vec<Bytes>);

impl Namespace {
    pub fn byte_len(&self) -> usize {
        self.0.iter().map(Bytes::len).sum()
    }

    /// Whether `self`, as a prefix, matches `other` (section 2.4.2).
    pub fn is_prefix_of(&self, other: &Namespace) -> bool {
        self.0.len() <= other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| a == b)
    }

    /// `other`'s fields after this prefix.
    #[must_use]
    pub fn suffix_of(&self, other: &Namespace) -> Namespace {
        Namespace(other.0[self.0.len().min(other.0.len())..].to_vec())
    }

    /// The first field, which says whether the namespace is reserved
    /// (section 2.4.3, 6.5).
    pub fn first(&self) -> Option<&[u8]> {
        self.0.first().map(|f| f.as_ref())
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        put_vi64(out, self.0.len() as u64);
        for field in &self.0 {
            put_prefixed(out, field);
        }
    }

    /// A namespace from section 8.8's serialized form, which has one
    /// rendering per value: a period must be followed by exactly two
    /// lowercase hex digits, and a byte that can be written literally must
    /// be. The empty string is the namespace of no fields.
    pub fn parse_safe(text: &str) -> Option<Self> {
        if text.is_empty() {
            return Some(Self::default());
        }
        let mut fields = Vec::new();
        for part in text.split('-') {
            let field = parse_safe_field(part)?;
            if field.is_empty() {
                return None;
            }
            fields.push(Bytes::from(field));
        }
        (fields.len() <= MAX_NAMESPACE_FIELDS).then_some(Self(fields))
    }
}

/// One field in section 8.8's serialized form.
fn parse_safe_field(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b.is_ascii_alphanumeric() || b == b'_' {
            out.push(b);
        } else if b == b'.' {
            let hex = |c: u8| match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                _ => None,
            };
            let v = hex(bytes.next()?)? << 4 | hex(bytes.next()?)?;
            // A byte that has a literal form must use it
            if v.is_ascii_alphanumeric() || v == b'_' {
                return None;
            }
            out.push(v);
        } else {
            return None;
        }
    }
    Some(out)
}

impl std::fmt::Display for Namespace {
    /// The serialized form section 8.8 recommends: fields joined by `-`,
    /// bytes outside `[A-Za-z0-9_]` as `.` and two lowercase hex digits.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, field) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("-")?;
            }
            write_safe(f, field)?;
        }
        Ok(())
    }
}

/// Section 8.8's safe rendering of one name.
pub fn write_safe(f: &mut impl std::fmt::Write, bytes: &[u8]) -> std::fmt::Result {
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b == b'_' {
            f.write_char(char::from(b))?;
        } else {
            write!(f, ".{b:02x}")?;
        }
    }
    Ok(())
}

/// A Full Track Name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrackName {
    pub namespace: Namespace,
    pub name: Bytes,
}

impl std::fmt::Display for TrackName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}--", self.namespace)?;
        write_safe(f, &self.name)
    }
}

/// A Location (section 8.2): ordered by group, then object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, serde::Serialize)]
pub struct Location {
    pub group: u64,
    pub object: u64,
}

impl Location {
    pub const fn new(group: u64, object: u64) -> Self {
        Self { group, object }
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        put_vi64(out, self.group);
        put_vi64(out, self.object);
    }

    /// The Location after this one in its group (section 3.1.4).
    #[must_use]
    pub const fn next_object(self) -> Self {
        Self::new(self.group, self.object.saturating_add(1))
    }
}

/// A Key-Value-Pair: even types carry an integer, odd types bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kvp {
    pub kind: u64,
    pub value: KvpValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvpValue {
    Int(u64),
    Bytes(Bytes),
}

impl Kvp {
    pub fn int(&self) -> Option<u64> {
        match self.value {
            KvpValue::Int(v) => Some(v),
            KvpValue::Bytes(_) => None,
        }
    }
}

/// Encode Key-Value-Pairs, sorting them by type so the deltas are not
/// negative (the order of equal types is kept).
pub fn put_kvps(out: &mut Vec<u8>, kvps: &[Kvp]) {
    let mut sorted: Vec<&Kvp> = kvps.iter().collect();
    sorted.sort_by_key(|k| k.kind);
    let mut last = 0u64;
    for kvp in sorted {
        put_vi64(out, kvp.kind - last);
        last = kvp.kind;
        match &kvp.value {
            KvpValue::Int(v) => put_vi64(out, *v),
            KvpValue::Bytes(b) => put_prefixed(out, b),
        }
    }
}

pub fn put_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    put_vi64(out, bytes.len() as u64);
    out.put_slice(bytes);
}

/// A Reason Phrase, cut at a character boundary to its 1024-byte limit.
pub fn put_reason(out: &mut Vec<u8>, reason: &str) {
    let mut end = reason.len().min(MAX_REASON_PHRASE);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    put_prefixed(out, &reason.as_bytes()[..end]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_vi64(&mut out, v);
        out
    }

    fn dec(bytes: &[u8]) -> u64 {
        let mut r = Reader::new(bytes, C::MalformedMessage);
        let v = r.vi64().unwrap();
        assert!(r.is_empty(), "{bytes:02x?} left bytes over");
        v
    }

    /// Section 8.1's example encodings, every one decoded, and the shortest
    /// written back.
    #[test]
    fn the_drafts_examples_decode() {
        let examples: [(&[u8], u64); 8] = [
            (&[0x25], 37),
            (&[0x80, 0x25], 37),
            (&[0xbb, 0xbd], 15_293),
            (&[0xed, 0x7f, 0x3e, 0x7d], 226_442_877),
            (&[0xfa, 0xa1, 0xa0, 0xe4, 0x03, 0xd8], 2_893_212_287_960),
            (
                &[0xfc, 0x89, 0x98, 0xab, 0xc6, 0x6b, 0xc0],
                151_288_809_941_952,
            ),
            (
                &[0xfe, 0xfa, 0x31, 0x8f, 0xa8, 0xe3, 0xca, 0x11],
                70_423_237_261_249_041,
            ),
            (&[0xff; 9], u64::MAX),
        ];
        for (bytes, value) in examples {
            assert_eq!(dec(bytes), value, "{bytes:02x?}");
        }
        assert_eq!(enc(37), [0x25]);
        assert_eq!(enc(15_293), [0xbb, 0xbd]);
        assert_eq!(enc(226_442_877), [0xed, 0x7f, 0x3e, 0x7d]);
        assert_eq!(enc(u64::MAX), [0xff; 9]);
    }

    #[test]
    fn every_length_boundary_round_trips() {
        for bits in [7u32, 14, 21, 28, 35, 42, 49, 56, 64] {
            for v in [(1u128 << bits) - 1, 1u128 << (bits - 1)] {
                let v = u64::try_from(v).unwrap();
                let e = enc(v);
                assert_eq!(e.len(), vi64_len(v));
                assert_eq!(vi64_len_from_first(e[0]), e.len());
                assert_eq!(dec(&e), v);
            }
        }
        // 0 in long forms (section 8.1)
        assert_eq!(dec(&[0x80, 0x00]), 0);
        assert_eq!(dec(&[0xc0, 0x00, 0x00]), 0);
    }

    #[test]
    fn key_value_pairs_are_delta_encoded() {
        let kvps = vec![
            Kvp {
                kind: 0x07,
                value: KvpValue::Bytes(Bytes::from_static(b"x")),
            },
            Kvp {
                kind: 0x02,
                value: KvpValue::Int(300),
            },
        ];
        let mut out = Vec::new();
        put_kvps(&mut out, &kvps);
        // 0x02 first (delta 2), then 0x07 (delta 5)
        assert_eq!(out, [0x02, 0x81, 0x2c, 0x05, 0x01, b'x']);
        let back = Reader::new(&out, C::MalformedMessage)
            .kvps_to_end()
            .unwrap();
        assert_eq!(back[0].kind, 2);
        assert_eq!(back[1].kind, 7);
    }

    #[test]
    fn a_type_delta_past_the_top_is_an_overflow() {
        let mut out = Vec::new();
        put_vi64(&mut out, u64::MAX - 1); // even: an integer
        put_vi64(&mut out, 0);
        put_vi64(&mut out, 4); // pushes past 2^64 - 1
        put_vi64(&mut out, 0);
        let err = Reader::new(&out, C::MalformedMessage)
            .kvps_to_end()
            .unwrap_err();
        assert_eq!(err.code, C::DeltaEncodingOverflow);
    }

    #[test]
    fn namespaces_are_bounded() {
        let mut out = Vec::new();
        put_vi64(&mut out, 33);
        let err = Reader::new(&out, C::MalformedMessage)
            .namespace()
            .unwrap_err();
        assert_eq!(err.code, C::InvalidTrackNamespace);

        let mut out = Vec::new();
        put_vi64(&mut out, 1);
        put_vi64(&mut out, 0);
        let err = Reader::new(&out, C::MalformedMessage)
            .namespace()
            .unwrap_err();
        assert_eq!(err.code, C::InvalidTrackNamespace);

        let ns = Namespace(vec![Bytes::from(vec![b'a'; 4000])]);
        let mut out = Vec::new();
        put_prefixed(&mut out, &[b'b'; 97]);
        let err = Reader::new(&out, C::MalformedMessage)
            .track_name(&ns)
            .unwrap_err();
        assert_eq!(err.code, C::FieldLengthExceeded);
    }

    /// The serialized form parses back exactly, and only in its one form.
    #[test]
    fn the_safe_form_parses_one_way_only() {
        let ns = Namespace(vec![
            Bytes::from_static(b"example.net"),
            Bytes::from_static(b"team-2"),
        ]);
        assert_eq!(Namespace::parse_safe(&ns.to_string()), Some(ns));
        assert_eq!(Namespace::parse_safe(""), Some(Namespace::default()));
        for bad in [".61", ".2E", ".2", "a b", "a--b", "-a", "a-"] {
            assert_eq!(Namespace::parse_safe(bad), None, "{bad:?}");
        }
    }

    /// Section 8.8's example renders exactly.
    #[test]
    fn names_render_in_the_safe_form() {
        let t = TrackName {
            namespace: Namespace(vec![
                Bytes::from_static(b"example.net"),
                Bytes::from_static(b"team2"),
                Bytes::from_static(b"project_x"),
            ]),
            name: Bytes::from_static(b"report"),
        };
        assert_eq!(t.to_string(), "example.2enet-team2-project_x--report");
    }

    #[test]
    fn prefixes_match_whole_fields() {
        let ns = |s: &[&'static [u8]]| Namespace(s.iter().map(|f| Bytes::from_static(f)).collect());
        assert!(ns(&[b"foo"]).is_prefix_of(&ns(&[b"foo", b"bar"])));
        assert!(ns(&[]).is_prefix_of(&ns(&[b"foo"])));
        assert!(!ns(&[b"foo"]).is_prefix_of(&ns(&[b"foobar"])));
        assert_eq!(
            ns(&[b"foo"]).suffix_of(&ns(&[b"foo", b"bar"])),
            ns(&[b"bar"])
        );
    }

    #[test]
    fn reason_phrases_are_cut_at_a_character() {
        let long = "é".repeat(600); // 1200 bytes
        let mut out = Vec::new();
        put_reason(&mut out, &long);
        let back = Reader::new(&out, C::MalformedMessage).reason().unwrap();
        assert!(back.len() <= MAX_REASON_PHRASE);
        assert!(back.chars().all(|c| c == 'é'));
    }
}
