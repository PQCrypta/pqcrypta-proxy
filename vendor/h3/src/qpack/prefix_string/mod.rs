mod bitwin;
mod decode;
mod encode;

use std::convert::TryInto;
use std::fmt;
use std::num::TryFromIntError;

use bytes::{Buf, BufMut};

pub use self::bitwin::BitWindow;

pub use self::{
    decode::{Error as HuffmanDecodingError, HpackStringDecode},
    encode::{hpack_encoded_len, Error as HuffmanEncodingError, HpackStringEncode},
};

use crate::qpack::prefix_int::{self, Error as IntegerError};

#[derive(Debug, PartialEq)]
pub enum Error {
    UnexpectedEnd,
    Integer(IntegerError),
    HuffmanDecoding(HuffmanDecodingError),
    HuffmanEncoding(HuffmanEncodingError),
    BufSize(TryFromIntError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEnd => write!(f, "unexpected end"),
            Error::Integer(e) => write!(f, "could not parse integer: {}", e),
            Error::HuffmanDecoding(e) => write!(f, "Huffman decode failed: {:?}", e),
            Error::HuffmanEncoding(e) => write!(f, "Huffman encode failed: {:?}", e),
            Error::BufSize(_) => write!(f, "number in buffer wrong size"),
        }
    }
}

pub fn decode<B: Buf>(size: u8, buf: &mut B) -> Result<Vec<u8>, Error> {
    let (flags, len) = prefix_int::decode(size - 1, buf)?;
    let len: usize = len.try_into()?;
    if buf.remaining() < len {
        return Err(Error::UnexpectedEnd);
    }

    let payload = buf.copy_to_bytes(len);
    let value = if flags & 1 == 0 {
        payload.into_iter().collect()
    } else {
        let mut decoded = Vec::new();
        for byte in payload.into_iter().collect::<Vec<u8>>().hpack_decode() {
            decoded.push(byte?);
        }
        decoded
    };
    Ok(value)
}

pub fn encode<B: BufMut>(size: u8, flags: u8, value: &[u8], buf: &mut B) -> Result<(), Error> {
    // The Huffman bit is a choice, not a constant. This used to hardcode it to
    // 1, which pays for the encoder even on values Huffman makes *longer* --
    // and it is the low bit of the length prefix precisely so a sender can
    // decline. `decode` above already reads both forms, as does every peer.
    let huffman_len = hpack_encoded_len(value);
    if huffman_len >= value.len() {
        prefix_int::encode(size - 1, flags << 1, value.len().try_into()?, buf);
        buf.put_slice(value);
        return Ok(());
    }

    // `Vec::from(value)` copied the input before encoding it; the slice impl
    // does not. `put_slice` replaces a byte-at-a-time write loop.
    let encoded = value.hpack_encode()?;
    prefix_int::encode(size - 1, flags << 1 | 1, encoded.len().try_into()?, buf);
    buf.put_slice(&encoded);
    Ok(())
}

impl From<HuffmanEncodingError> for Error {
    fn from(error: HuffmanEncodingError) -> Self {
        Error::HuffmanEncoding(error)
    }
}

impl From<IntegerError> for Error {
    fn from(error: IntegerError) -> Self {
        match error {
            IntegerError::UnexpectedEnd => Error::UnexpectedEnd,
            e => Error::Integer(e),
        }
    }
}

impl From<HuffmanDecodingError> for Error {
    fn from(error: HuffmanDecodingError) -> Self {
        Error::HuffmanDecoding(error)
    }
}

impl From<TryFromIntError> for Error {
    fn from(error: TryFromIntError) -> Self {
        Error::BufSize(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use std::io::Cursor;

    #[test]
    fn codec_6() {
        let mut buf = Vec::new();
        encode(6, 0b01, b"name without ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[
                0b0110_1100,
                168,
                116,
                149,
                79,
                6,
                76,
                231,
                181,
                42,
                88,
                89,
                127
            ]
        );
        assert_eq!(decode(6, &mut read).unwrap(), b"name without ref");
    }

    #[test]
    fn codec_8() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"name with ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[0b1000_1010, 168, 116, 149, 79, 6, 76, 234, 88, 89, 127]
        );
        assert_eq!(decode(8, &mut read).unwrap(), b"name with ref");
    }

    #[test]
    fn codec_8_empty() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        // Was `0b1000_0000` upstream, which is the same empty string with the
        // Huffman bit set. This fork sets that bit only when Huffman actually
        // shrinks the value, and for an empty string it cannot, so the bit is
        // clear. Both are valid on the wire and both decode to `b""` -- the
        // assertion below held before this change and holds after it.
        assert_eq!(&buf, &[0b0000_0000]);
        assert_eq!(decode(8, &mut read).unwrap(), b"");
    }

    #[test]
    fn huffman_declined_when_it_would_expand() {
        // High bytes have 20-30 bit Huffman codes, so encoding them costs more
        // than sending them literally. Upstream sent them Huffman-coded anyway.
        let value = b"\xff\xfe\xfd\xfc";
        assert!(hpack_encoded_len(value) >= value.len());

        let mut buf = Vec::new();
        encode(8, 0, value, &mut buf).unwrap();
        assert_eq!(buf[0] & 0b1000_0000, 0, "Huffman bit must be clear");
        assert_eq!(&buf[1..], value, "value must follow verbatim");

        let mut read = Cursor::new(&buf);
        assert_eq!(decode(8, &mut read).unwrap(), value);
    }

    #[test]
    fn huffman_used_when_it_shrinks() {
        // Lowercase ASCII is what the Huffman table is tuned for.
        let value = b"text/html; charset=utf-8";
        assert!(hpack_encoded_len(value) < value.len());

        let mut buf = Vec::new();
        encode(8, 0, value, &mut buf).unwrap();
        assert_eq!(buf[0] & 0b1000_0000, 0b1000_0000, "Huffman bit must be set");
        assert!(buf.len() - 1 < value.len(), "must be shorter than literal");

        let mut read = Cursor::new(&buf);
        assert_eq!(decode(8, &mut read).unwrap(), value);
    }

    #[test]
    fn encoded_len_matches_what_the_encoder_produces() {
        // The predicted length is what sizes the output buffer, so a mismatch
        // would either truncate the encoding or leave trailing filler bytes.
        for value in [
            &b""[..],
            b"a",
            b"content-type",
            b"text/html; charset=utf-8",
            b"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            b"\x00\x01\xfe\xff",
            b"0123456789",
        ] {
            let encoded = value.hpack_encode().unwrap();
            assert_eq!(
                encoded.len(),
                hpack_encoded_len(value),
                "length mismatch for {value:?}"
            );
        }
    }

    #[test]
    fn every_byte_value_round_trips() {
        // Each of the 256 codes on its own, and all of them together, through
        // whichever branch `encode` picks for it.
        let all: Vec<u8> = (0..=255u8).collect();
        for byte in 0..=255u8 {
            let value = [byte];
            let mut buf = Vec::new();
            encode(8, 0, &value, &mut buf).unwrap();
            let mut read = Cursor::new(&buf);
            assert_eq!(decode(8, &mut read).unwrap(), &value, "byte {byte}");
        }
        let mut buf = Vec::new();
        encode(8, 0, &all, &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(decode(8, &mut read).unwrap(), all);
    }

    #[test]
    fn decode_non_huffman() {
        let buf = vec![0b0100_0011, b'b', b'a', b'r'];
        let mut read = Cursor::new(&buf);
        assert_eq!(decode(6, &mut read).unwrap(), b"bar");
    }

    #[test]
    fn decode_too_short() {
        let buf = vec![0b0100_0011, b'b', b'a'];
        let mut read = Cursor::new(&buf);
        assert_matches!(decode(6, &mut read), Err(Error::UnexpectedEnd));
    }
}
