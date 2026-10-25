//! The DNS message format (RFC 1035 §4), as far as the proxy reads and writes it.
//!
//! Used by the DoH gateway (doh.rs) and the ACME DNS challenges' updates
//! (acme_dns.rs). Every read is bounds-checked: these bytes come from the
//! network, and a release build aborts the whole process on a panic.

/// A DNS message header's length
pub(crate) const HEADER_LEN: usize = 12;

pub(crate) fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    let b = msg.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

pub(crate) fn u32_at(msg: &[u8], at: usize) -> Option<u32> {
    let b = msg.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// One past the last octet of the name that starts at `at`. A compression
/// pointer ends a name and is not followed, so a pointer loop cannot spin.
pub(crate) fn name_end(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *msg.get(at)?;
        match length & 0xC0 {
            0x00 if length == 0 => return Some(at + 1),
            0x00 => at = at.checked_add(1 + usize::from(length))?,
            0xC0 => {
                msg.get(at + 1)?;
                return Some(at + 2);
            }
            // 0x40 and 0x80: label types RFC 6891 §5 retired.
            _ => return None,
        }
    }
}

/// Where one resource record's parts sit in a message.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Record {
    /// Offset of the owner name
    pub(crate) name: usize,
    pub(crate) rtype: u16,
    pub(crate) ttl: u32,
    /// Offset of the RDATA; its two-octet length sits just before it.
    pub(crate) rdata: usize,
    pub(crate) rdlength: usize,
    pub(crate) end: usize,
}

pub(crate) fn record_at(msg: &[u8], at: usize) -> Option<Record> {
    let fixed = name_end(msg, at)?;
    let rtype = u16_at(msg, fixed)?;
    let ttl = u32_at(msg, fixed + 4)?;
    let rdlength = usize::from(u16_at(msg, fixed + 8)?);
    let rdata = fixed + 10;
    let end = rdata + rdlength;
    (end <= msg.len()).then_some(Record {
        name: at,
        rtype,
        ttl,
        rdata,
        rdlength,
        end,
    })
}

/// A message's sections. `None` when any of them runs past the end.
#[derive(Debug)]
pub(crate) struct Layout {
    pub(crate) questions: usize,
    pub(crate) question_end: usize,
    pub(crate) answer: Vec<Record>,
    pub(crate) authority: Vec<Record>,
    pub(crate) additional: Vec<Record>,
}

pub(crate) fn layout(msg: &[u8]) -> Option<Layout> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let count = |i: usize| u16_at(msg, 4 + 2 * i).map(usize::from);
    let questions = count(0)?;
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = name_end(msg, at)? + 4;
        if at > msg.len() {
            return None;
        }
    }
    let question_end = at;
    let mut section = |n: usize| -> Option<Vec<Record>> {
        let mut records = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let record = record_at(msg, at)?;
            at = record.end;
            records.push(record);
        }
        Some(records)
    };
    let answer = section(count(1)?)?;
    let authority = section(count(2)?)?;
    let additional = section(count(3)?)?;
    Some(Layout {
        questions,
        question_end,
        answer,
        authority,
        additional,
    })
}

/// The name that starts at `at`, lowercase and without the trailing dot
/// (the root is the empty string), following compression pointers. Each
/// pointer must point before itself and before the last one followed, so the
/// walk only goes backwards: a loop cannot spin.
pub(crate) fn read_name(msg: &[u8], mut at: usize) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut limit = usize::MAX;
    loop {
        let length = *msg.get(at)?;
        match length & 0xC0 {
            0x00 if length == 0 => break,
            0x00 => {
                let label = msg.get(at + 1..at + 1 + usize::from(length))?;
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                at += 1 + usize::from(length);
            }
            0xC0 => {
                let target = usize::from(u16_at(msg, at)? & 0x3FFF);
                if target >= at.min(limit) {
                    return None;
                }
                limit = target;
                at = target;
            }
            _ => return None,
        }
        if labels.len() > 127 {
            return None;
        }
    }
    Some(labels.join("."))
}

/// A name in wire form, uncompressed: each label prefixed by its length,
/// ending with the root. `None` for an empty label or one over 63 octets,
/// or a name over 255 octets.
pub(crate) fn encode_name(name: &str) -> Option<Vec<u8>> {
    let name = name.trim_end_matches('.');
    let mut out = Vec::with_capacity(name.len() + 2);
    if !name.is_empty() {
        for label in name.split('.') {
            let length = u8::try_from(label.len())
                .ok()
                .filter(|l| (1..=63).contains(l))?;
            out.push(length);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    (out.len() <= 255).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_encoded_and_read_back() {
        let wire = encode_name("_acme-challenge.NS1.example.com.").unwrap();
        assert_eq!(wire, b"\x0f_acme-challenge\x03NS1\x07example\x03com\x00");
        assert_eq!(
            read_name(&wire, 0).as_deref(),
            Some("_acme-challenge.ns1.example.com")
        );
        assert_eq!(encode_name("").unwrap(), b"\x00");
        assert_eq!(read_name(b"\x00", 0).as_deref(), Some(""));
        assert!(encode_name("a..b").is_none(), "empty label");
        assert!(encode_name(&"x".repeat(64)).is_none(), "label over 63");
    }

    #[test]
    fn a_compressed_name_is_followed_backwards_only() {
        // "example.com" at 0, then "www" + a pointer to 0
        let mut msg = encode_name("example.com").unwrap();
        msg.extend_from_slice(b"\x03www\xC0\x00");
        assert_eq!(read_name(&msg, 13).as_deref(), Some("www.example.com"));
        // A pointer to itself, or forward, is refused
        assert_eq!(read_name(b"\xC0\x00", 0), None);
        assert_eq!(read_name(b"\x03abc\xC0\x06\x00", 0), None);
    }
}
