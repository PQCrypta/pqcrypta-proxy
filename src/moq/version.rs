//! The MOQT versions the relay speaks, in one place.
//!
//! draft-ietf-moq-transport section 6.2: a version is chosen by ALPN on a
//! QUIC connection and by `WT-Available-Protocols` / `WT-Protocol` on a
//! WebTransport session; each draft's identifier is `moqt-` and its number
//! (drafts before -15 shared `moq-00` and negotiated in SETUP, which no
//! version here speaks). The relay keeps the newest two drafts working at
//! once: a new draft is a new [`Version`] variant with its differences in the
//! codec, and the oldest is retired. Nothing else names a draft number: the
//! listener's ALPN list, the WebTransport negotiation, the admin API and the
//! metrics read this table.

/// A MOQT version this relay implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub enum Version {
    /// draft-ietf-moq-transport-22
    Draft22,
    /// draft-ietf-moq-transport-23
    Draft23,
}

impl Version {
    /// Every version, newest first: the order the relay prefers them in.
    pub const ALL: [Self; 2] = [Self::Draft23, Self::Draft22];

    /// The draft number.
    pub const fn draft(self) -> u32 {
        match self {
            Self::Draft22 => 22,
            Self::Draft23 => 23,
        }
    }

    /// The ALPN token on QUIC, which is also the WebTransport protocol
    /// string (section 6.2).
    pub const fn alpn(self) -> &'static str {
        match self {
            Self::Draft22 => "moqt-22",
            Self::Draft23 => "moqt-23",
        }
    }

    /// The version an ALPN token or WebTransport protocol string names.
    pub fn from_alpn(token: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.alpn().as_bytes() == token)
    }

    /// Every ALPN token, newest first.
    pub fn alpns() -> Vec<Vec<u8>> {
        Self::ALL
            .iter()
            .map(|v| v.alpn().as_bytes().to_vec())
            .collect()
    }

    /// The newest version this relay and the peer share. The peer's list is
    /// in its own preference order (draft-ietf-webtrans-http3 section 3.3);
    /// the relay serves its own newest of the shared ones, since a client
    /// offering two drafts speaks both and the newer is the better protocol.
    pub fn negotiate<'a>(offered: impl IntoIterator<Item = &'a [u8]>) -> Option<Self> {
        offered.into_iter().filter_map(Self::from_alpn).max()
    }

    /// From draft 23: control message lengths are variable-length integers
    /// (draft 22: 16 bits).
    pub const fn varint_message_length(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: FETCH is answered with REQUEST_OK (draft 22: FETCH_OK,
    /// 0x18, with End Of Track and End Location).
    pub const fn fetch_ok_is_request_ok(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: PAUSED (0x11, default 0) replaces FORWARD (0x10,
    /// default 1, inverted).
    pub const fn paused_parameter(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: FILL_PARAMETERS is a parameter count (draft 22: a byte
    /// length).
    pub const fn fill_parameters_counted(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: REQUEST_ERROR ends with Error Details (draft 22: an
    /// optional Redirect, present only for REDIRECT).
    pub const fn error_details(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: FETCH End of Range indicators are delta encoded, a
    /// FETCH Object ID Delta within a Group adds 2, and the Gone range, End
    /// of Group and End of Track indicators exist.
    pub const fn fetch_stream_v23(self) -> bool {
        matches!(self, Self::Draft23)
    }

    /// From draft 23: session errors have codes of their own (0x200-0x401
    /// and MALFORMED_KEY_VALUE's siblings); draft 22 closes with
    /// PROTOCOL_VIOLATION for most of them.
    pub const fn specific_session_errors(self) -> bool {
        matches!(self, Self::Draft23)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.alpn())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_name_their_drafts() {
        for v in Version::ALL {
            assert_eq!(v.alpn(), format!("moqt-{}", v.draft()));
            assert_eq!(Version::from_alpn(v.alpn().as_bytes()), Some(v));
        }
        assert_eq!(Version::from_alpn(b"moq-00"), None);
        assert_eq!(Version::from_alpn(b"moqt"), None);
    }

    #[test]
    fn the_newest_shared_version_is_chosen() {
        let offer: [&[u8]; 3] = [b"moqt-22", b"moqt-23", b"moqt-99"];
        assert_eq!(Version::negotiate(offer), Some(Version::Draft23));
        let old: [&[u8]; 2] = [b"moqt-16", b"moqt-22"];
        assert_eq!(Version::negotiate(old), Some(Version::Draft22));
        let none: [&[u8]; 2] = [b"moqt-16", b"h3"];
        assert_eq!(Version::negotiate(none), None);
    }

    #[test]
    fn all_is_newest_first_and_unique() {
        let drafts: Vec<u32> = Version::ALL.iter().map(|v| v.draft()).collect();
        let mut sorted = drafts.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        sorted.dedup();
        assert_eq!(drafts, sorted);
    }
}
