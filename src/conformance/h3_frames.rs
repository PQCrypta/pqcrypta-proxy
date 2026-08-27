//! A hand-rolled HTTP/3 frame writer.
//!
//! Deliberately not built on the `h3` crate. A correct HTTP/3 implementation
//! will not emit a duplicate SETTINGS identifier, a DATA frame on the control
//! stream, or a second control stream — and those are exactly the things the
//! catalogue needs emitted. Anything that refuses to produce invalid output is
//! the wrong tool for testing how peers handle invalid output.
//!
//! Everything here writes bytes. Nothing validates, because validation is the
//! client's job and the whole point is to find out whether it does it.
//!
//! References: RFC 9114 (HTTP/3), RFC 9000 §16 (variable-length integers).

use bytes::{BufMut, BytesMut};

/// HTTP/3 frame types (RFC 9114 §7.2).
pub mod frame_type {
    pub const DATA: u64 = 0x00;
    pub const HEADERS: u64 = 0x01;
    pub const CANCEL_PUSH: u64 = 0x03;
    pub const SETTINGS: u64 = 0x04;
    pub const PUSH_PROMISE: u64 = 0x05;
    pub const GOAWAY: u64 = 0x07;
    pub const MAX_PUSH_ID: u64 = 0x0d;
}

/// Unidirectional stream types (RFC 9114 §6.2).
pub mod stream_type {
    pub const CONTROL: u64 = 0x00;
    pub const PUSH: u64 = 0x01;
    pub const QPACK_ENCODER: u64 = 0x02;
    pub const QPACK_DECODER: u64 = 0x03;
}

/// SETTINGS identifiers (RFC 9114 §7.2.4.1).
pub mod setting {
    pub const QPACK_MAX_TABLE_CAPACITY: u64 = 0x01;
    pub const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
    pub const QPACK_BLOCKED_STREAMS: u64 = 0x07;
}

/// HTTP/3 error codes (RFC 9114 §8.1). The catalogue's correctness tests name
/// the one a client is required to send.
pub mod error_code {
    pub const H3_NO_ERROR: u64 = 0x0100;
    pub const H3_GENERAL_PROTOCOL_ERROR: u64 = 0x0101;
    pub const H3_INTERNAL_ERROR: u64 = 0x0102;
    pub const H3_STREAM_CREATION_ERROR: u64 = 0x0103;
    pub const H3_CLOSED_CRITICAL_STREAM: u64 = 0x0104;
    pub const H3_FRAME_UNEXPECTED: u64 = 0x0105;
    pub const H3_FRAME_ERROR: u64 = 0x0106;
    pub const H3_ID_ERROR: u64 = 0x0108;
    pub const H3_SETTINGS_ERROR: u64 = 0x0109;
    pub const H3_MISSING_SETTINGS: u64 = 0x010a;
}

/// Largest value a QUIC variable-length integer can carry (RFC 9000 §16).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Append a variable-length integer (RFC 9000 §16).
///
/// Panics above [`VARINT_MAX`]: every call site here passes a constant or a
/// value already bounded by one, so exceeding it is a bug in this module rather
/// than anything a peer can provoke.
#[allow(
    clippy::cast_possible_truncation,
    reason = "each branch has already bounded the value to the width it casts to; \
              discarding the high bits is what the encoding requires"
)]
pub fn put_varint(buf: &mut BytesMut, value: u64) {
    assert!(value <= VARINT_MAX, "varint out of range: {value}");
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16_384 {
        buf.put_u16(0x4000 | value as u16);
    } else if value < 1_073_741_824 {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | value);
    }
}

/// Encode a varint on its own.
pub fn varint(value: u64) -> BytesMut {
    let mut b = BytesMut::new();
    put_varint(&mut b, value);
    b
}

/// A frame: type, length, payload.
pub fn frame(ty: u64, payload: &[u8]) -> BytesMut {
    let mut b = BytesMut::new();
    put_varint(&mut b, ty);
    put_varint(&mut b, payload.len() as u64);
    b.put_slice(payload);
    b
}

/// The *n*-th reserved value of the form `0x1f * N + 0x21` (RFC 9114 §7.2.8).
///
/// These exist so that peers are routinely exposed to values they do not know,
/// and stay able to ignore them. A client that breaks here is the reason
/// extension points close up over time.
pub fn reserved_value(n: u64) -> u64 {
    // Bound n so the multiply cannot overflow a varint.
    let n = n % ((VARINT_MAX - 0x21) / 0x1f);
    0x1f * n + 0x21
}

/// A SETTINGS frame from `(identifier, value)` pairs.
///
/// Pairs are written exactly as given, including duplicates — which is what
/// `h-duplicate-setting` needs and what a conforming encoder would prevent.
pub fn settings(pairs: &[(u64, u64)]) -> BytesMut {
    let mut payload = BytesMut::new();
    for (id, value) in pairs {
        put_varint(&mut payload, *id);
        put_varint(&mut payload, *value);
    }
    frame(frame_type::SETTINGS, &payload)
}

/// A sensible SETTINGS frame, with one reserved identifier mixed in.
///
/// The reserved entry is present by default rather than only in the GREASE
/// test: every client that talks to this suite should meet an unknown setting
/// immediately, because that is what it will meet on the open internet.
pub fn settings_with_grease() -> BytesMut {
    settings(&[
        (setting::QPACK_MAX_TABLE_CAPACITY, 4096),
        (setting::MAX_FIELD_SECTION_SIZE, 16_384),
        (setting::QPACK_BLOCKED_STREAMS, 16),
        (reserved_value(7), 0x42),
    ])
}

/// A GOAWAY frame carrying the last stream the server will process.
pub fn goaway(last_stream_id: u64) -> BytesMut {
    frame(frame_type::GOAWAY, &varint(last_stream_id))
}

/// A MAX_PUSH_ID frame.
pub fn max_push_id(id: u64) -> BytesMut {
    frame(frame_type::MAX_PUSH_ID, &varint(id))
}

/// A DATA frame.
pub fn data(payload: &[u8]) -> BytesMut {
    frame(frame_type::DATA, payload)
}

/// A frame of a reserved type, which a client must skip using its length.
pub fn reserved_frame(n: u64, payload: &[u8]) -> BytesMut {
    frame(reserved_value(n), payload)
}

/// The prefix that declares a unidirectional stream's type (RFC 9114 §6.2).
pub fn uni_stream_header(ty: u64) -> BytesMut {
    varint(ty)
}

/// A unidirectional stream of a reserved type, which a client must ignore.
pub fn reserved_uni_stream_header(n: u64) -> BytesMut {
    varint(reserved_value(n))
}

/// Minimal QPACK: a field section with no dynamic-table references.
///
/// The prefix is `Required Insert Count = 0`, `Delta Base = 0` (RFC 9204 §4.5),
/// after which every field is a literal with a literal name. Deliberately the
/// simplest legal encoding — the QPACK tests vary from this baseline one axis at
/// a time, so a failure points at the axis rather than at the encoder in
/// general.
pub fn qpack_literal_headers(fields: &[(&str, &str)]) -> BytesMut {
    let mut b = BytesMut::new();
    b.put_u8(0x00); // Required Insert Count
    b.put_u8(0x00); // Delta Base

    for (name, value) in fields {
        // Literal field line with literal name (RFC 9204 §4.5.6): pattern
        // 001NHnnn, N=0 (may be indexed downstream), H=0 (no Huffman), with a
        // 3-bit prefix length.
        put_prefixed_int(&mut b, name.len() as u64, 3, 0b0010_0000);
        b.put_slice(name.as_bytes());
        // Value: 8-bit prefix, H=0.
        put_prefixed_int(&mut b, value.len() as u64, 7, 0x00);
        b.put_slice(value.as_bytes());
    }
    b
}

/// A HEADERS frame wrapping a literal field section.
pub fn headers(fields: &[(&str, &str)]) -> BytesMut {
    let payload = qpack_literal_headers(fields);
    frame(frame_type::HEADERS, &payload)
}

/// The fields of an ordinary successful response.
pub fn ok_response_fields(content_length: usize) -> Vec<(String, String)> {
    vec![
        (":status".to_string(), "200".to_string()),
        ("content-type".to_string(), "text/plain".to_string()),
        ("content-length".to_string(), content_length.to_string()),
    ]
}

/// Huffman-coded literals, precomputed.
///
/// A general encoder needs the whole 256-entry RFC 7541 Appendix B table, which
/// is a lot of data to carry for two strings. These were generated from that
/// table and the generator was checked against every worked example in RFC 7541
/// Appendix C — `www.example.com`, `no-cache`, `custom-key`, `custom-value` —
/// before these bytes were taken.
///
/// The first attempt at this table was written by hand and produced the wrong
/// bytes for `m` among others. It looked plausible and would have made
/// `h-qpack-huffman` fail every client on earth. Hence the vectors.
pub mod huffman {
    /// `200`, 3 bytes down to 2.
    pub const STATUS_200: &[u8] = &[0x10, 0x01];
    /// `text/plain`, 10 bytes down to 7.
    pub const TEXT_PLAIN: &[u8] = &[0x49, 0x7c, 0xa5, 0x8a, 0xe8, 0x19, 0xaa];
    /// `huffman-encoded`, 15 bytes down to 11.
    pub const HUFFMAN_ENCODED: &[u8] = &[
        0x9e, 0xd9, 0x65, 0xa4, 0x75, 0x2c, 0x5a, 0x88, 0x79, 0x0b, 0x27,
    ];
}

/// A field section whose values are Huffman-coded.
///
/// Same literal-with-literal-name shape as [`qpack_literal_headers`], but with
/// the H bit set on each value and the coded bytes in place of the plain ones.
/// Padding of up to 7 bits is legal (RFC 7541 §5.2) and is exactly what a
/// careless decoder trips over.
pub fn qpack_huffman_headers(fields: &[(&str, &[u8], usize)]) -> BytesMut {
    let mut b = BytesMut::new();
    b.put_u8(0x00); // Required Insert Count
    b.put_u8(0x00); // Delta Base

    for (name, coded_value, _plain_len) in fields {
        put_prefixed_int(&mut b, name.len() as u64, 3, 0b0010_0000);
        b.put_slice(name.as_bytes());
        // H = 1: the value that follows is Huffman-coded.
        put_prefixed_int(&mut b, coded_value.len() as u64, 7, 0x80);
        b.put_slice(coded_value);
    }
    b
}

/// An "Insert With Literal Name" instruction for the encoder stream
/// (RFC 9204 §4.3.3).
///
/// Layout `01NH` then a 5-bit name length, so the flag byte is `0b0100_0000`
/// with N and H clear.
pub fn qpack_insert_with_literal_name(name: &str, value: &str) -> BytesMut {
    let mut b = BytesMut::new();
    put_prefixed_int(&mut b, name.len() as u64, 5, 0b0100_0000);
    b.put_slice(name.as_bytes());
    put_prefixed_int(&mut b, value.len() as u64, 7, 0x00);
    b.put_slice(value.as_bytes());
    b
}

/// The largest table capacity we advertise, and the entry count it implies
/// (RFC 9204 §3.2.2: `MaxEntries = floor(capacity / 32)`).
const QPACK_MAX_TABLE_CAPACITY: u64 = 4096;
const QPACK_MAX_ENTRIES: u64 = QPACK_MAX_TABLE_CAPACITY / 32;

/// A field section that references the dynamic table.
///
/// `insert_count` entries must already have been sent on the encoder stream.
/// The Required Insert Count is encoded per RFC 9204 §4.5.1
/// (`(count mod 2*MaxEntries) + 1`), Base equals it so Delta Base is zero, and
/// each field line is an Indexed Field Line with T=0 — a dynamic-table
/// reference, relative to Base.
pub fn qpack_dynamic_headers(insert_count: u64, literal: &[(&str, &str)]) -> BytesMut {
    let mut b = BytesMut::new();

    let encoded = if insert_count == 0 {
        0
    } else {
        (insert_count % (2 * QPACK_MAX_ENTRIES)) + 1
    };
    put_prefixed_int(&mut b, encoded, 8, 0x00);
    // Delta Base 0, S=0: Base == Required Insert Count.
    put_prefixed_int(&mut b, 0, 7, 0x00);

    // Literals first. They carry `:status`, and RFC 9114 §4.3 requires every
    // pseudo-header to precede the regular fields — emitting the dynamic
    // references first put `:status` after them and made the whole section
    // invalid, which is our error and would have been scored against the
    // client.
    for (name, value) in literal {
        put_prefixed_int(&mut b, name.len() as u64, 3, 0b0010_0000);
        b.put_slice(name.as_bytes());
        put_prefixed_int(&mut b, value.len() as u64, 7, 0x00);
        b.put_slice(value.as_bytes());
    }

    // Indexed Field Line, dynamic table: `1` then T=0 then a 6-bit index,
    // relative to Base.
    for i in 0..insert_count {
        put_prefixed_int(&mut b, i, 6, 0b1000_0000);
    }
    b
}

/// Read a variable-length integer, returning the value and its width.
///
/// The counterpart to [`put_varint`], needed to parse the client's SETTINGS —
/// specifically `SETTINGS_QPACK_MAX_TABLE_CAPACITY`, which governs whether the
/// server's encoder may use the dynamic table at all.
pub fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
    let first = *b.first()?;
    let len = 1usize << (first >> 6);
    if b.len() < len {
        return None;
    }
    let mut v = u64::from(first & 0x3f);
    for byte in &b[1..len] {
        v = (v << 8) | u64::from(*byte);
    }
    Some((v, len))
}

/// Pull `SETTINGS_QPACK_MAX_TABLE_CAPACITY` out of a control stream's bytes.
///
/// Returns `None` when no SETTINGS frame has arrived yet or the setting is
/// absent — absent means zero (RFC 9204 §5), which is the default and means the
/// dynamic table is off limits.
pub fn parse_qpack_capacity(control: &[u8]) -> Option<u64> {
    // The stream begins with its type, then frames.
    let (ty, mut off) = read_varint(control)?;
    if ty != stream_type::CONTROL {
        return None;
    }
    while off < control.len() {
        let (frame_ty, n) = read_varint(&control[off..])?;
        off += n;
        let (len, n) = read_varint(&control[off..])?;
        off += n;
        let end = off.checked_add(usize::try_from(len).ok()?)?;
        if end > control.len() {
            return None;
        }
        if frame_ty == frame_type::SETTINGS {
            let mut p = off;
            while p < end {
                let (id, a) = read_varint(&control[p..])?;
                p += a;
                let (value, c) = read_varint(&control[p..])?;
                p += c;
                if id == setting::QPACK_MAX_TABLE_CAPACITY {
                    return Some(value);
                }
            }
            return Some(0);
        }
        off = end;
    }
    None
}

/// A HEADERS frame wrapping an arbitrary, already-encoded field section.
pub fn headers_raw(field_section: &[u8]) -> BytesMut {
    frame(frame_type::HEADERS, field_section)
}

/// An HPACK/QPACK prefixed integer (RFC 7541 §5.1), used for QPACK's string
/// lengths.
///
/// `prefix_bits` is the number of bits available in the first byte;
/// `first_byte_flags` supplies the bits above them.
#[allow(
    clippy::cast_possible_truncation,
    reason = "prefix_bits <= 8, so max_prefix <= 255, and the u8 casts sit behind \
              comparisons against it"
)]
pub fn put_prefixed_int(buf: &mut BytesMut, value: u64, prefix_bits: u8, first_byte_flags: u8) {
    let max_prefix = (1u64 << prefix_bits) - 1;
    if value < max_prefix {
        buf.put_u8(first_byte_flags | value as u8);
        return;
    }
    buf.put_u8(first_byte_flags | max_prefix as u8);
    let mut remainder = value - max_prefix;
    while remainder >= 128 {
        buf.put_u8((remainder % 128) as u8 + 128);
        remainder /= 128;
    }
    buf.put_u8(remainder as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_width() {
        // One value per encoding width, plus the boundaries either side.
        for v in [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            VARINT_MAX,
        ] {
            let encoded = varint(v);
            let (decoded, used) = read_varint(&encoded).expect("valid varint");
            assert_eq!(decoded, v, "value {v} did not survive the round trip");
            assert_eq!(used, encoded.len(), "declared width disagrees for {v}");
        }
    }

    #[test]
    fn varint_widths_are_minimal() {
        assert_eq!(varint(63).len(), 1);
        assert_eq!(varint(64).len(), 2);
        assert_eq!(varint(16_383).len(), 2);
        assert_eq!(varint(16_384).len(), 4);
        assert_eq!(varint(1_073_741_823).len(), 4);
        assert_eq!(varint(1_073_741_824).len(), 8);
    }

    #[test]
    fn a_frame_declares_its_own_length() {
        let f = frame(frame_type::DATA, b"hello");
        let (ty, n) = read_varint(&f).expect("valid varint");
        assert_eq!(ty, frame_type::DATA);
        let (len, m) = read_varint(&f[n..]).expect("valid varint");
        assert_eq!(len, 5);
        assert_eq!(&f[n + m..], b"hello");
    }

    #[test]
    fn reserved_values_follow_the_grease_pattern() {
        for n in [0u64, 1, 7, 1000, u64::MAX] {
            let v = reserved_value(n);
            assert_eq!(
                (v - 0x21) % 0x1f,
                0,
                "0x{v:x} is not of the form 0x1f*N+0x21"
            );
            assert!(v <= VARINT_MAX, "0x{v:x} cannot be encoded as a varint");
        }
    }

    #[test]
    fn settings_writes_duplicates_verbatim() {
        // The whole reason this module exists: a conforming encoder would
        // refuse, and h-duplicate-setting needs it on the wire.
        let f = settings(&[
            (setting::MAX_FIELD_SECTION_SIZE, 100),
            (setting::MAX_FIELD_SECTION_SIZE, 200),
        ]);
        let (ty, n) = read_varint(&f).expect("valid varint");
        assert_eq!(ty, frame_type::SETTINGS);
        let (len, m) = read_varint(&f[n..]).expect("valid varint");
        let payload = &f[n + m..n + m + len as usize];

        let (id1, a) = read_varint(payload).expect("valid varint");
        let (v1, b) = read_varint(&payload[a..]).expect("valid varint");
        let (id2, c) = read_varint(&payload[a + b..]).expect("valid varint");
        let (v2, _) = read_varint(&payload[a + b + c..]).expect("valid varint");

        assert_eq!(
            (id1, id2),
            (
                setting::MAX_FIELD_SECTION_SIZE,
                setting::MAX_FIELD_SECTION_SIZE
            )
        );
        assert_eq!((v1, v2), (100, 200));
    }

    #[test]
    fn the_default_settings_carry_an_unknown_identifier() {
        let f = settings_with_grease();
        let (_, n) = read_varint(&f).expect("valid varint");
        let (len, m) = read_varint(&f[n..]).expect("valid varint");
        let payload = &f[n + m..n + m + len as usize];

        let mut offset = 0;
        let mut saw_reserved = false;
        while offset < payload.len() {
            let (id, a) = read_varint(&payload[offset..]).expect("valid varint");
            let (_, b) = read_varint(&payload[offset + a..]).expect("valid varint");
            if id > 0x21 && (id - 0x21) % 0x1f == 0 {
                saw_reserved = true;
            }
            offset += a + b;
        }
        assert!(
            saw_reserved,
            "every client should meet an unknown setting here"
        );
    }

    #[test]
    fn prefixed_ints_match_rfc_7541_examples() {
        // RFC 7541 §C.1.1: 10 in a 5-bit prefix is one byte.
        let mut b = BytesMut::new();
        put_prefixed_int(&mut b, 10, 5, 0);
        assert_eq!(&b[..], &[10]);

        // §C.1.2: 1337 in a 5-bit prefix is 31, 154, 10.
        let mut b = BytesMut::new();
        put_prefixed_int(&mut b, 1337, 5, 0);
        assert_eq!(&b[..], &[31, 154, 10]);

        // §C.1.3: 42 in an 8-bit prefix is one byte.
        let mut b = BytesMut::new();
        put_prefixed_int(&mut b, 42, 8, 0);
        assert_eq!(&b[..], &[42]);
    }

    #[test]
    fn qpack_field_sections_start_with_a_zero_prefix() {
        let h = qpack_literal_headers(&[(":status", "200")]);
        assert_eq!(&h[..2], &[0x00, 0x00], "insert count and delta base");
        assert!(h.len() > 2);
        // The name and value both appear literally, unencoded.
        let text = String::from_utf8_lossy(&h);
        assert!(text.contains(":status"));
        assert!(text.contains("200"));
    }

    #[test]
    fn a_reserved_stream_header_is_a_bare_varint() {
        let h = reserved_uni_stream_header(3);
        let (ty, used) = read_varint(&h).expect("valid varint");
        assert_eq!(used, h.len());
        assert_eq!((ty - 0x21) % 0x1f, 0);
    }

    #[test]
    fn huffman_literals_are_shorter_than_their_plaintext() {
        // If a "Huffman-coded" value were not actually coded, this test would
        // still pass a naive length check — so assert the real ratio the RFC
        // 7541 table produces for these two strings.
        assert_eq!(huffman::TEXT_PLAIN.len(), 7, "text/plain is 10 bytes plain");
        assert_eq!(
            huffman::HUFFMAN_ENCODED.len(),
            11,
            "huffman-encoded is 15 bytes plain"
        );
    }

    #[test]
    fn huffman_values_set_the_h_bit() {
        // A name short enough to fit the 3-bit length prefix, so the layout is
        // unambiguous — "content-type" is 12 characters and overflows into a
        // continuation byte, which is correct but makes the offsets awkward to
        // assert.
        let name = "ct";
        let section = qpack_huffman_headers(&[(name, huffman::TEXT_PLAIN, 10)]);
        // prefix(2) + name-length byte + name + value-length byte + value
        let value_len_idx = 2 + 1 + name.len();
        assert_eq!(
            section[value_len_idx] & 0x80,
            0x80,
            "the value length byte must set H to mark it Huffman-coded"
        );
        assert_eq!(section[value_len_idx] & 0x7f, 7, "coded length");
    }

    #[test]
    fn a_dynamic_field_section_encodes_the_required_insert_count() {
        // RFC 9204 §4.5.1 with capacity 4096 → MaxEntries 128, so an insert
        // count of 2 encodes as (2 mod 256) + 1 = 3. Encoding it as the raw
        // count would make the client wait for an insertion that never comes.
        let section = qpack_dynamic_headers(2, &[(":status", "200")]);
        assert_eq!(section[0], 3, "encoded required insert count");
        assert_eq!(section[1], 0, "delta base zero, S clear");
        // The literals come first (pseudo-headers must precede regular fields),
        // then one indexed field line per insertion, dynamic table (T=0).
        let indexed: Vec<u8> = section
            .iter()
            .copied()
            .filter(|b| b & 0b1100_0000 == 0b1000_0000)
            .collect();
        assert_eq!(indexed.len(), 2, "one indexed line per insertion");
        assert_eq!(indexed[0] & 0b0011_1111, 0, "relative index 0");
        assert_eq!(indexed[1] & 0b0011_1111, 1, "relative index 1");
    }

    #[test]
    fn an_empty_dynamic_section_encodes_a_zero_insert_count() {
        let section = qpack_dynamic_headers(0, &[(":status", "200")]);
        assert_eq!(section[0], 0, "0 must stay 0, not become 1");
    }

    #[test]
    fn an_encoder_insertion_uses_the_literal_name_pattern() {
        let insert = qpack_insert_with_literal_name("x-a", "b");
        // RFC 9204 §4.3.3: 01NH then a 5-bit name length.
        assert_eq!(insert[0] & 0b1100_0000, 0b0100_0000);
        assert_eq!(insert[0] & 0b0001_1111, 3, "name length in the prefix");
        assert_eq!(&insert[1..4], b"x-a");
    }

    #[test]
    fn varints_survive_a_write_then_read() {
        for v in [
            0u64,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            VARINT_MAX,
        ] {
            let enc = varint(v);
            assert_eq!(read_varint(&enc), Some((v, enc.len())), "value {v}");
        }
        assert_eq!(read_varint(&[]), None);
        // A truncated multi-byte varint must not be read as a short one.
        assert_eq!(read_varint(&[0x40]), None);
    }

    #[test]
    fn qpack_capacity_is_read_from_a_control_stream() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        stream.extend_from_slice(&settings(&[
            (setting::MAX_FIELD_SECTION_SIZE, 16_384),
            (setting::QPACK_MAX_TABLE_CAPACITY, 4096),
        ]));
        assert_eq!(parse_qpack_capacity(&stream), Some(4096));
    }

    #[test]
    fn an_absent_capacity_reads_as_zero_not_unknown() {
        // RFC 9204 §5: the default is zero, which forbids the dynamic table.
        // Reporting "unknown" would tempt a caller into using it anyway.
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        stream.extend_from_slice(&settings(&[(setting::MAX_FIELD_SECTION_SIZE, 16_384)]));
        assert_eq!(parse_qpack_capacity(&stream), Some(0));
    }

    #[test]
    fn a_non_control_stream_yields_no_capacity() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::QPACK_ENCODER));
        assert_eq!(parse_qpack_capacity(&stream), None);
    }

    #[test]
    fn a_truncated_control_stream_is_rejected_not_guessed() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        let full = settings(&[(setting::QPACK_MAX_TABLE_CAPACITY, 4096)]);
        stream.extend_from_slice(&full[..full.len() - 1]);
        assert_eq!(parse_qpack_capacity(&stream), None);
    }

    #[test]
    fn pseudo_headers_precede_regular_fields_in_a_dynamic_section() {
        // RFC 9114 §4.3. Emitting the dynamic references first put `:status`
        // after them and invalidated the section.
        let section = qpack_dynamic_headers(2, &[(":status", "200")]);
        let text = String::from_utf8_lossy(&section);
        let status_at = text.find(":status").expect("status present");
        // The indexed field lines are the 0x80-prefixed bytes; none may precede.
        let first_indexed = section
            .iter()
            .position(|b| b & 0b1100_0000 == 0b1000_0000)
            .expect("an indexed field line");
        assert!(
            status_at < first_indexed,
            "pseudo-header must come before dynamic references"
        );
    }

    #[test]
    fn goaway_carries_the_stream_id() {
        let g = goaway(12);
        let (ty, n) = read_varint(&g).expect("valid varint");
        assert_eq!(ty, frame_type::GOAWAY);
        let (len, m) = read_varint(&g[n..]).expect("valid varint");
        assert_eq!(len, 1);
        let (id, _) = read_varint(&g[n + m..]).expect("valid varint");
        assert_eq!(id, 12);
    }
}
