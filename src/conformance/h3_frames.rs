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

    /// Read a varint back, returning the value and how many bytes it used.
    fn read_varint(b: &[u8]) -> (u64, usize) {
        let first = b[0];
        match first >> 6 {
            0 => ((first & 0x3f) as u64, 1),
            1 => ((((first & 0x3f) as u64) << 8) | b[1] as u64, 2),
            2 => {
                let v = (((first & 0x3f) as u64) << 24)
                    | ((b[1] as u64) << 16)
                    | ((b[2] as u64) << 8)
                    | b[3] as u64;
                (v, 4)
            }
            _ => {
                let mut v = (first & 0x3f) as u64;
                for byte in &b[1..8] {
                    v = (v << 8) | *byte as u64;
                }
                (v, 8)
            }
        }
    }

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
            let (decoded, used) = read_varint(&encoded);
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
        let (ty, n) = read_varint(&f);
        assert_eq!(ty, frame_type::DATA);
        let (len, m) = read_varint(&f[n..]);
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
        let (ty, n) = read_varint(&f);
        assert_eq!(ty, frame_type::SETTINGS);
        let (len, m) = read_varint(&f[n..]);
        let payload = &f[n + m..n + m + len as usize];

        let (id1, a) = read_varint(payload);
        let (v1, b) = read_varint(&payload[a..]);
        let (id2, c) = read_varint(&payload[a + b..]);
        let (v2, _) = read_varint(&payload[a + b + c..]);

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
        let (_, n) = read_varint(&f);
        let (len, m) = read_varint(&f[n..]);
        let payload = &f[n + m..n + m + len as usize];

        let mut offset = 0;
        let mut saw_reserved = false;
        while offset < payload.len() {
            let (id, a) = read_varint(&payload[offset..]);
            let (_, b) = read_varint(&payload[offset + a..]);
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
        let (ty, used) = read_varint(&h);
        assert_eq!(used, h.len());
        assert_eq!((ty - 0x21) % 0x1f, 0);
    }

    #[test]
    fn goaway_carries_the_stream_id() {
        let g = goaway(12);
        let (ty, n) = read_varint(&g);
        assert_eq!(ty, frame_type::GOAWAY);
        let (len, m) = read_varint(&g[n..]);
        assert_eq!(len, 1);
        let (id, _) = read_varint(&g[n + m..]);
        assert_eq!(id, 12);
    }
}
