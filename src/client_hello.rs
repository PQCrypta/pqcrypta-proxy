//! A ClientHello's extensions, read from the record a TCP listener peeks.
//!
//! The listeners peek the ClientHello off the socket before a TLS stack sees
//! it; what it carries routes the connection to the stack that can serve it
//! (an ECH offer, a signature_algorithms_cert OpenSSL would refuse).

/// The data of extension `kind` in the ClientHello `record` holds, if it has
/// one. None for bytes that are not a whole ClientHello record.
pub fn extension(record: &[u8], kind: u16) -> Option<&[u8]> {
    let mut exts = extensions(record)?;
    while !exts.is_empty() {
        let t = take(&mut exts, 2)?;
        let data = u16_len(&mut exts)?;
        if u16::from_be_bytes([t[0], t[1]]) == kind {
            return Some(data);
        }
    }
    None
}

/// The host name the server_name extension carries (RFC 6066 section 3),
/// lowercased.
pub fn server_name(record: &[u8]) -> Option<String> {
    let mut data = extension(record, 0x0000)?;
    let mut list = u16_len(&mut data)?;
    while !list.is_empty() {
        let kind = *take(&mut list, 1)?.first()?;
        let name = u16_len(&mut list)?;
        if kind == 0 {
            return std::str::from_utf8(name).ok().map(str::to_ascii_lowercase);
        }
    }
    None
}

/// A list of 16-bit code points, as signature_algorithms and
/// signature_algorithms_cert carry them (a 2-byte length, then the points).
pub fn u16_list(mut data: &[u8]) -> Option<Vec<u16>> {
    let list = u16_len(&mut data)?;
    let (points, rest) = list.as_chunks::<2>();
    rest.is_empty()
        .then(|| points.iter().map(|c| u16::from_be_bytes(*c)).collect())
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (head, rest) = b.split_at(n);
    *b = rest;
    Some(head)
}

fn u8_len<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = *take(b, 1)?.first()? as usize;
    take(b, n)
}

fn u16_len<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let h = take(b, 2)?;
    take(b, u16::from_be_bytes([h[0], h[1]]) as usize)
}

/// The extensions block of the ClientHello in `record`.
fn extensions(record: &[u8]) -> Option<&[u8]> {
    let mut b = record;
    // Record: handshake (22), version, length
    if *take(&mut b, 1)?.first()? != 22 {
        return None;
    }
    take(&mut b, 2)?;
    let mut hs = u16_len(&mut b)?;
    // Handshake: client_hello (1), 24-bit length
    if *take(&mut hs, 1)?.first()? != 1 {
        return None;
    }
    let len = take(&mut hs, 3)?;
    let mut body = take(
        &mut hs,
        u32::from_be_bytes([0, len[0], len[1], len[2]]) as usize,
    )?;
    take(&mut body, 2 + 32)?; // legacy_version, random
    u8_len(&mut body)?; // legacy_session_id
    u16_len(&mut body)?; // cipher_suites
    u8_len(&mut body)?; // legacy_compression_methods
    u16_len(&mut body)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello record with the given extensions, `(type, data)`.
    pub(crate) fn client_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut exts = Vec::new();
        for (kind, data) in extensions {
            exts.extend_from_slice(&kind.to_be_bytes());
            exts.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            exts.extend_from_slice(data);
        }
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0); // session id
        body.extend_from_slice(&[0, 2, 0x13, 0x02]); // TLS_AES_256_GCM_SHA384
        body.extend_from_slice(&[1, 0]); // null compression
        body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![1];
        hs.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    pub(crate) fn sni(name: &str) -> Vec<u8> {
        let mut entry = vec![0];
        entry.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut data = u16::try_from(entry.len()).unwrap().to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        data
    }

    pub(crate) fn list(points: &[u16]) -> Vec<u8> {
        let mut data = u16::try_from(points.len() * 2)
            .unwrap()
            .to_be_bytes()
            .to_vec();
        for p in points {
            data.extend_from_slice(&p.to_be_bytes());
        }
        data
    }

    #[test]
    fn extensions_names_and_lists_are_read() {
        let record = client_hello(&[(0, sni("Example.TEST")), (0x0032, list(&[0x0403, 0x0804]))]);
        assert_eq!(server_name(&record).as_deref(), Some("example.test"));
        assert_eq!(
            extension(&record, 0x0032).and_then(u16_list),
            Some(vec![0x0403, 0x0804])
        );
        assert_eq!(extension(&record, 0x000d), None);
        assert_eq!(
            extension(&record[..record.len() - 1], 0x0032),
            None,
            "a cut record"
        );
        assert_eq!(extension(&[23, 3, 3, 0, 0], 0), None, "not a handshake");
    }
}
