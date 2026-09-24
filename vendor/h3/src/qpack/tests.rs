use crate::qpack::decoder::Decoder;
use crate::qpack::encoder::Encoder;
use crate::qpack::{dynamic::DynamicTable, Decoded, DecoderError, HeaderField};
use std::io::Cursor;

pub mod helpers {
    use crate::qpack::{dynamic::DynamicTable, HeaderField};

    pub const TABLE_SIZE: usize = 4096;

    pub fn build_table() -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();
        table
    }

    pub fn build_table_with_size(n_field: usize) -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();

        for i in 0..n_field {
            table
                .put(HeaderField::new(format!("foo{}", i + 1), "bar"))
                .unwrap();
        }

        table
    }
}

#[test]
fn codec_basic_get() {
    let mut encoder = Encoder::default();
    let mut decoder = Decoder::from(DynamicTable::new());

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

const TABLE_SIZE: usize = 4096;
#[test]
fn blocked_header() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut encoder = Encoder::from(enc_table);
    let mut dec_table = DynamicTable::new();
    dec_table.set_max_size(TABLE_SIZE).unwrap();
    dec_table.set_max_blocked(100).unwrap();
    let decoder = Decoder::from(dec_table);

    let mut block_buf = vec![];
    let mut enc_buf = vec![];

    encoder
        .encode(
            42,
            &mut block_buf,
            &mut enc_buf,
            &[HeaderField::new("foo", "bar")],
        )
        .unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    assert_eq!(
        decoder.decode_header(&mut block_cur),
        Err(DecoderError::MissingRefs(1))
    );
}

#[test]
fn codec_table_size_0() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    dec_table.set_max_size(0).unwrap();
    enc_table.set_max_size(0).unwrap();

    let mut encoder = Encoder::from(enc_table);
    let mut decoder = Decoder::from(dec_table);

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

#[test]
fn codec_table_full() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new("foo", "bar"),
        HeaderField::new("foo1", "bar1"),
    ];

    dec_table.set_max_size(42).unwrap();
    enc_table.set_max_size(42).unwrap();

    let mut encoder = Encoder::from(enc_table);
    let mut decoder = Decoder::from(dec_table);

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    let mut block_cur = Cursor::new(&mut block_buf);

    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

/// The other half of `blocked_header`: the section decodes once the insert
/// lands.
///
/// `blocked_header` proves the decoder refuses a section that references an
/// insert it has not seen. On its own that reads as a permanent verdict, and
/// it was treated as one -- `MissingRefs` reached the connection as
/// QPACK_DECOMPRESSION_FAILED. It is a temporary one, and this is the test
/// that says so: same decoder, same untouched block, decodable after the
/// encoder stream is applied.
#[test]
fn blocked_header_decodes_once_the_insert_arrives() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut encoder = Encoder::from(enc_table);

    let mut dec_table = DynamicTable::new();
    dec_table.set_max_size(TABLE_SIZE).unwrap();
    dec_table.set_max_blocked(100).unwrap();
    let mut decoder = Decoder::from(dec_table);

    let header = vec![HeaderField::new("foo", "bar")];
    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    // The section arrives first, as QUIC permits.
    assert_eq!(
        decoder.decode_header(&mut Cursor::new(&block_buf)),
        Err(DecoderError::MissingRefs(1))
    );

    // Then the insert it referenced.
    let mut dec_buf = vec![];
    decoder
        .on_encoder_recv(&mut Cursor::new(&mut enc_buf), &mut dec_buf)
        .unwrap();

    // The parked section is decoded from the start, not from wherever the
    // failed attempt left the cursor.
    let Decoded {
        fields, dyn_ref, ..
    } = decoder.decode_header(&mut Cursor::new(&block_buf)).unwrap();
    assert_eq!(fields, header);
    assert!(dyn_ref, "the section referenced the dynamic table");
}

/// A Section Acknowledgment lets the encoder reclaim the entry.
///
/// Insert Count Increment tells the encoder what we received; only the
/// acknowledgement tells it what we used, and until it arrives the entry is
/// still referenced by an outstanding section and cannot be evicted.
#[test]
fn section_acknowledgment_unblocks_eviction() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut encoder = Encoder::from(enc_table);
    let mut decoder = Decoder::from(helpers::build_table());

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    encoder
        .encode(
            42,
            &mut block_buf,
            &mut enc_buf,
            &[HeaderField::new("foo", "bar")],
        )
        .unwrap();

    let mut dec_buf = vec![];
    decoder
        .on_encoder_recv(&mut Cursor::new(&mut enc_buf), &mut dec_buf)
        .unwrap();
    let Decoded { dyn_ref, .. } = decoder.decode_header(&mut Cursor::new(&block_buf)).unwrap();
    assert!(dyn_ref);

    // What the request stream now queues on the decoder stream.
    let mut ack = vec![];
    crate::qpack::ack_header(42, &mut ack);
    assert!(!ack.is_empty());
    encoder.on_decoder_recv(&mut Cursor::new(&mut ack)).unwrap();
}

/// A capacity above what we advertised is an encoder-stream error.
#[test]
fn capacity_above_the_advertised_maximum_is_rejected() {
    use crate::qpack::stream::DynamicTableSizeUpdate;

    let mut decoder = Decoder::default();
    decoder.set_max_capacity(4096);

    let mut instruction = vec![];
    DynamicTableSizeUpdate(4097).encode(&mut instruction);

    assert_eq!(
        decoder.on_encoder_recv(&mut Cursor::new(&mut instruction), &mut vec![]),
        Err(DecoderError::CapacityExceedsAdvertised(4097))
    );
}

/// A capacity at the advertised maximum is not.
#[test]
fn capacity_at_the_advertised_maximum_is_accepted() {
    use crate::qpack::stream::DynamicTableSizeUpdate;

    let mut decoder = Decoder::default();
    decoder.set_max_capacity(4096);

    let mut instruction = vec![];
    DynamicTableSizeUpdate(4096).encode(&mut instruction);

    decoder
        .on_encoder_recv(&mut Cursor::new(&mut instruction), &mut vec![])
        .unwrap();
}

/// The default decoder advertises nothing, so any capacity is too much.
#[test]
fn a_decoder_that_advertised_no_table_refuses_one() {
    use crate::qpack::stream::DynamicTableSizeUpdate;

    let mut decoder = Decoder::default();

    let mut instruction = vec![];
    DynamicTableSizeUpdate(1).encode(&mut instruction);

    assert_eq!(
        decoder.on_encoder_recv(&mut Cursor::new(&mut instruction), &mut vec![]),
        Err(DecoderError::CapacityExceedsAdvertised(1))
    );
}
