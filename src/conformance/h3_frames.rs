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
    /// PRIORITY_UPDATE for a request stream (RFC 9218 §7.2). The push-stream
    /// variant is 0xf0701; either is forbidden from a server.
    pub const PRIORITY_UPDATE_REQUEST: u64 = 0xf_0700;
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
    /// SETTINGS_H3_DATAGRAM (RFC 9297 §2.1.1).
    ///
    /// Its value MUST be 0 or 1, and a receiver seeing anything else MUST
    /// terminate the connection with H3_SETTINGS_ERROR — one of the few settings
    /// whose invalid-value handling the specification pins down.
    pub const H3_DATAGRAM: u64 = 0x33;
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220 §3, registered by RFC 8441).
    /// Its value MUST be 0 or 1; this is how a client learns Extended CONNECT —
    /// and so WebTransport — is available.
    pub const ENABLE_CONNECT_PROTOCOL: u64 = 0x08;
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
    pub const H3_REQUEST_REJECTED: u64 = 0x010b;
    pub const H3_REQUEST_CANCELLED: u64 = 0x010c;
    pub const H3_REQUEST_INCOMPLETE: u64 = 0x010d;
    pub const H3_MESSAGE_ERROR: u64 = 0x010e;
    pub const H3_CONNECT_ERROR: u64 = 0x010f;
    pub const H3_VERSION_FALLBACK: u64 = 0x0110;

    // QPACK's error codes (RFC 9204 §6) share the HTTP/3 application error
    // space. They belong here for the same reason the H3_* codes do: a client
    // that closes with one is objecting, and a suite that did not recognise
    // them would read a QPACK rejection as "no error to signal" and score it as
    // though the client had accepted the instruction.
    pub const QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
    pub const QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
    pub const QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;

    /// Whether an application close code means the peer is objecting.
    ///
    /// Only a *defined* HTTP/3 error code other than `H3_NO_ERROR` does.
    /// Everything else — code 0, a GREASE code from the `0x1f * N + 0x21`
    /// space, an unassigned value — is an unknown error code, and RFC 9114 §8.1
    /// requires those to be "treated as equivalent to H3_NO_ERROR". §9 says the
    /// same thing more generally: "Implementations MUST ignore unknown or
    /// unsupported values in all extensible protocol elements", and error codes
    /// are one of the listed extension points.
    ///
    /// This matters because the suite reads a close as the client's verdict on
    /// the anomaly. Treating every non-zero-ish code as a rejection accused
    /// aioquic and quic-go of six protocol violations each — both simply close
    /// with application code 0, which the RFC says means no error at all.
    pub fn is_rejection(code: u64) -> bool {
        matches!(
            code,
            QPACK_DECOMPRESSION_FAILED
                | QPACK_ENCODER_STREAM_ERROR
                | QPACK_DECODER_STREAM_ERROR
                | H3_GENERAL_PROTOCOL_ERROR
                | H3_INTERNAL_ERROR
                | H3_STREAM_CREATION_ERROR
                | H3_CLOSED_CRITICAL_STREAM
                | H3_FRAME_UNEXPECTED
                | H3_FRAME_ERROR
                | H3_ID_ERROR
                | H3_SETTINGS_ERROR
                | H3_MISSING_SETTINGS
                | H3_REQUEST_REJECTED
                | H3_REQUEST_CANCELLED
                | H3_REQUEST_INCOMPLETE
                | H3_MESSAGE_ERROR
                | H3_CONNECT_ERROR
                | H3_VERSION_FALLBACK
        )
    }
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

/// A CANCEL_PUSH frame naming the push this refers to (RFC 9114 §7.2.3).
///
/// Legal in both directions, which is what makes it useful here: the violation
/// under test is not the frame's presence but its identifier. A client that
/// granted no MAX_PUSH_ID has allowed no push IDs at all, so any value names a
/// push that was never permitted.
pub fn cancel_push(push_id: u64) -> BytesMut {
    frame(frame_type::CANCEL_PUSH, &varint(push_id))
}

/// The header of a server push stream (RFC 9114 §6.2.2): stream type then push ID.
///
/// §6.2.2 requires a client to treat a push stream as H3_ID_ERROR "when no
/// MAX_PUSH_ID frame has been sent", which is every client here — so the push ID
/// itself needs to be nothing more exotic than zero.
pub fn push_stream_header(push_id: u64) -> BytesMut {
    let mut buf = uni_stream_header(stream_type::PUSH);
    buf.extend_from_slice(&varint(push_id));
    buf
}

/// A field section whose single field line indexes a static entry that does not
/// exist (RFC 9204 §4.5.2).
///
/// Layout `1T` then a 6-bit prefixed index, with T=1 selecting the static table.
/// The static table has 99 entries, so anything from 99 up is invalid and §3.1
/// requires the decoder to treat it as QPACK_DECOMPRESSION_FAILED.
///
/// Needs no permission from the client, unlike the dynamic-table tests: the
/// static table is always present and always the same size.
pub fn qpack_invalid_static_index(index: u64) -> BytesMut {
    let mut buf = BytesMut::new();
    // Required Insert Count 0, Delta Base 0 — nothing dynamic is referenced.
    buf.put_u8(0);
    buf.put_u8(0);
    put_prefixed_int(&mut buf, index, 6, 0b1100_0000);
    buf
}

/// A PUSH_PROMISE frame (RFC 9114 §7.2.5).
///
/// Push ID as a varint, then an encoded field section describing the request
/// being promised. The field section is an ordinary literal encoding — what a
/// client objects to is the push ID, since the maximum is unset until it sends
/// MAX_PUSH_ID and so every value exceeds what it has advertised.
pub fn push_promise(push_id: u64, fields: &[(&str, &str)]) -> BytesMut {
    let mut payload = varint(push_id);
    payload.extend_from_slice(&qpack_literal_headers(fields));
    frame(frame_type::PUSH_PROMISE, &payload)
}

/// A QPACK "Set Dynamic Table Capacity" instruction (RFC 9204 §4.3.1).
///
/// Pattern `001` followed by the capacity as a 5-bit prefixed integer. §4.3.1
/// requires the new capacity to be no larger than the limit the decoder
/// advertised in SETTINGS_QPACK_MAX_TABLE_CAPACITY, and makes exceeding it a
/// connection error of type QPACK_ENCODER_STREAM_ERROR.
pub fn qpack_set_capacity(capacity: u64) -> BytesMut {
    let mut buf = BytesMut::new();
    put_prefixed_int(&mut buf, capacity, 5, 0b0010_0000);
    buf
}

/// A PRIORITY_UPDATE frame for a request stream (RFC 9218 §7.2).
///
/// Payload is the Prioritized Element ID as a varint, then the Priority Field
/// Value as ASCII structured-field text — `u=3` is a plain, valid urgency, so
/// what a client objects to is the direction the frame travelled and not
/// anything wrong with its contents.
pub fn priority_update(element_id: u64, field_value: &str) -> BytesMut {
    let mut payload = varint(element_id);
    payload.extend_from_slice(field_value.as_bytes());
    frame(frame_type::PRIORITY_UPDATE_REQUEST, &payload)
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

/// What the client's SETTINGS permit our QPACK encoder to do.
///
/// Both values default to zero when the setting is absent (RFC 9204 §5), and
/// zero in either field forbids something: no table capacity means the dynamic
/// table is off limits entirely, and no blocked streams means a field section
/// must never reference an insertion the decoder has not already received.
/// Reading only the capacity was enough while nothing blocked a stream on
/// purpose; `h-qpack-blocked-stream` needs both, because §2.1.2 makes exceeding
/// the blocked-stream limit *our* violation, not the client's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientQpackLimits {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
    pub capacity: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`.
    pub blocked_streams: u64,
}

/// Pull the QPACK limits out of a control stream's bytes.
///
/// Returns `None` when no SETTINGS frame has arrived yet — which is different
/// from a SETTINGS frame that omits them, since an omitted setting is a
/// specified zero and an absent frame is simply not knowing.
pub fn parse_client_qpack_limits(control: &[u8]) -> Option<ClientQpackLimits> {
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
            let mut limits = ClientQpackLimits {
                capacity: 0,
                blocked_streams: 0,
            };
            let mut p = off;
            while p < end {
                let (id, a) = read_varint(&control[p..])?;
                p += a;
                let (value, c) = read_varint(&control[p..])?;
                p += c;
                match id {
                    setting::QPACK_MAX_TABLE_CAPACITY => limits.capacity = value,
                    setting::QPACK_BLOCKED_STREAMS => limits.blocked_streams = value,
                    _ => {}
                }
            }
            return Some(limits);
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
        let frame = settings(&[
            (setting::MAX_FIELD_SECTION_SIZE, 100),
            (setting::MAX_FIELD_SECTION_SIZE, 200),
        ]);
        let (ty, type_len) = read_varint(&frame).expect("valid varint");
        assert_eq!(ty, frame_type::SETTINGS);
        let (len, len_len) = read_varint(&frame[type_len..]).expect("valid varint");
        let header = type_len + len_len;
        let payload = &frame[header..header + usize::try_from(len).expect("frame fits in memory")];

        let (id1, id1_len) = read_varint(payload).expect("valid varint");
        let (v1, v1_len) = read_varint(&payload[id1_len..]).expect("valid varint");
        let after_first = id1_len + v1_len;
        let (id2, id2_len) = read_varint(&payload[after_first..]).expect("valid varint");
        let (v2, _) = read_varint(&payload[after_first + id2_len..]).expect("valid varint");

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
        let frame = settings_with_grease();
        let (_, type_len) = read_varint(&frame).expect("valid varint");
        let (len, len_len) = read_varint(&frame[type_len..]).expect("valid varint");
        let header = type_len + len_len;
        let payload = &frame[header..header + usize::try_from(len).expect("frame fits in memory")];

        let mut offset = 0;
        let mut saw_reserved = false;
        while offset < payload.len() {
            let (id, id_len) = read_varint(&payload[offset..]).expect("valid varint");
            let (_, value_len) = read_varint(&payload[offset + id_len..]).expect("valid varint");
            if id > 0x21 && (id - 0x21) % 0x1f == 0 {
                saw_reserved = true;
            }
            offset += id_len + value_len;
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
    fn both_qpack_limits_are_read_from_one_settings_frame() {
        // `h-qpack-blocked-stream` may only block a stream when the client
        // permits both a table and a blocked stream. Reading one and assuming
        // the other would make our own §2.1.2 violation look like the client's
        // decoding bug.
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        stream.extend_from_slice(&settings(&[
            (setting::QPACK_MAX_TABLE_CAPACITY, 4096),
            (setting::QPACK_BLOCKED_STREAMS, 16),
        ]));
        let limits = parse_client_qpack_limits(&stream).expect("SETTINGS arrived");
        assert_eq!(limits.capacity, 4096);
        assert_eq!(limits.blocked_streams, 16);
    }

    #[test]
    fn a_capacity_without_blocked_streams_permits_no_blocking() {
        // The combination curl and quic-go send when the table is enabled but
        // nothing may block: the dynamic table is usable, blocking is not.
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        stream.extend_from_slice(&settings(&[(setting::QPACK_MAX_TABLE_CAPACITY, 4096)]));
        let limits = parse_client_qpack_limits(&stream).expect("SETTINGS arrived");
        assert_eq!(limits.capacity, 4096);
        assert_eq!(limits.blocked_streams, 0);
    }

    #[test]
    fn cancel_push_carries_its_push_id_as_a_varint() {
        let f = cancel_push(3);
        assert_eq!(f[0], u8::try_from(frame_type::CANCEL_PUSH).unwrap());
        assert_eq!(f[1], 1, "one byte of payload");
        assert_eq!(read_varint(&f[2..]), Some((3, 1)));
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
        let limits = parse_client_qpack_limits(&stream).expect("SETTINGS arrived");
        assert_eq!(limits.capacity, 4096);
        assert_eq!(limits.blocked_streams, 0, "absent means zero, not unknown");
    }

    #[test]
    fn an_absent_capacity_reads_as_zero_not_unknown() {
        // RFC 9204 §5: the default is zero, which forbids the dynamic table.
        // Reporting "unknown" would tempt a caller into using it anyway.
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        stream.extend_from_slice(&settings(&[(setting::MAX_FIELD_SECTION_SIZE, 16_384)]));
        assert_eq!(
            parse_client_qpack_limits(&stream).map(|l| l.capacity),
            Some(0)
        );
    }

    #[test]
    fn a_non_control_stream_yields_no_capacity() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::QPACK_ENCODER));
        assert_eq!(parse_client_qpack_limits(&stream), None);
    }

    #[test]
    fn a_truncated_control_stream_is_rejected_not_guessed() {
        let mut stream = BytesMut::new();
        stream.extend_from_slice(&uni_stream_header(stream_type::CONTROL));
        let full = settings(&[(setting::QPACK_MAX_TABLE_CAPACITY, 4096)]);
        stream.extend_from_slice(&full[..full.len() - 1]);
        assert_eq!(parse_client_qpack_limits(&stream), None);
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
