use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

/// The field section this endpoint accepts unless configured otherwise
/// (SETTINGS_MAX_FIELD_SECTION_SIZE, RFC 9114 section 4.2.2), counted as QPACK
/// does: each field's name and value plus 32 octets.
///
/// It was VarInt::MAX, no limit at all: a peer could send a field section of
/// any size and every field of it was decoded and kept (the "header accordion"
/// class FoxIO reported against seven HTTP/3 stacks, h3 among them, in
/// October 2026). 64 KiB is what the proxy's HTTP/1.1 and HTTP/2 listeners
/// allow (security.max_header_size), and what h3's own pending fix proposes.
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// The longest frame read whole, every frame but DATA (whose payload streams):
/// on a control or push stream, SETTINGS, GOAWAY and the rest are a few octets.
pub(crate) const MAX_BUFFERED_FRAME: usize = 1024 * 1024;

/// The longest HEADERS frame a request stream buffers for an endpoint that
/// accepts field sections of `max_field_section_size`.
///
/// A field line encodes in fewer octets than the 32 its decoded size adds for
/// it, so a section within the limit encodes within it too; twice the limit
/// leaves room for an encoder whose Huffman coding made a value longer. A
/// frame past it is refused from its header, before its payload is buffered.
pub(crate) fn headers_frame_ceiling(max_field_section_size: u64) -> usize {
    usize::try_from(
        max_field_section_size
            .saturating_mul(2)
            .saturating_add(1024),
    )
    .unwrap_or(usize::MAX)
    .max(16 * 1024)
}

/// Configures the HTTP/3 connection
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The dynamic table size this endpoint will accept, in bytes.
    ///
    /// Zero means the encoder may not use the dynamic table at all, which is
    /// what this was fixed at: the table was implemented and unreachable, so
    /// advertising anything else would have been a claim we could not honour.
    pub(crate) qpack_max_table_capacity: u64,
    /// How many streams this endpoint will allow to be blocked on a dynamic
    /// table insert it has not yet received.
    pub(crate) qpack_blocked_streams: u64,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();
        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_webtransport),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(defaults.max_webtransport_sessions),
            qpack_max_table_capacity: settings
                .get(frame::SettingId::QPACK_MAX_TABLE_CAPACITY)
                .unwrap_or(defaults.qpack_max_table_capacity),
            qpack_blocked_streams: settings
                .get(frame::SettingId::QPACK_MAX_BLOCKED_STREAMS)
                .unwrap_or(defaults.qpack_blocked_streams),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    max_field_section_size,
                    enable_webtransport,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                },
        } = value;

        if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            match settings.insert(frame::SettingId::grease(), 0) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        settings.insert(
            frame::SettingId::MAX_HEADER_LIST_SIZE,
            max_field_section_size,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_CONNECT_PROTOCOL,
            enable_extended_connect as u64,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_WEBTRANSPORT,
            enable_webtransport as u64,
        )?;
        settings.insert(frame::SettingId::H3_DATAGRAM, enable_datagram as u64)?;
        settings.insert(
            frame::SettingId::QPACK_MAX_TABLE_CAPACITY,
            qpack_max_table_capacity,
        )?;
        settings.insert(
            frame::SettingId::QPACK_MAX_BLOCKED_STREAMS,
            qpack_blocked_streams,
        )?;
        settings.insert(
            frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
            max_webtransport_sessions,
        )?;

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_webtransport_sessions: 0,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            // Settings::default is also what a peer is taken to have before
            // its SETTINGS arrive (RFC 9114 section 7.2.4.2), where the field
            // section limit is unlimited; this endpoint's own is not.
            settings: Settings {
                max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
                ..Default::default()
            },
        }
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;

    /// This endpoint advertises and enforces a field section limit unless
    /// told otherwise; a peer that sends no limit is still taken to have none.
    #[test]
    fn an_endpoint_has_a_field_section_limit_and_a_peer_without_one_has_none() {
        assert_eq!(
            Config::default().settings.max_field_section_size,
            DEFAULT_MAX_FIELD_SECTION_SIZE
        );
        let sent = frame::Settings::try_from(Config::default()).unwrap();
        assert_eq!(
            sent.get(frame::SettingId::MAX_HEADER_LIST_SIZE),
            Some(DEFAULT_MAX_FIELD_SECTION_SIZE)
        );
        let peer = Settings::from(&frame::Settings::default());
        assert_eq!(peer.max_field_section_size, VarInt::MAX.0);
    }

    #[test]
    fn a_headers_frame_ceiling_follows_the_limit() {
        assert_eq!(headers_frame_ceiling(64 * 1024), 128 * 1024 + 1024);
        assert_eq!(headers_frame_ceiling(0), 16 * 1024);
        assert_eq!(headers_frame_ceiling(u64::MAX), usize::MAX);
    }
}
