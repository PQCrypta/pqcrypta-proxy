//! MOQT error codes (draft-ietf-moq-transport section 12, IANA section 16.12).
//!
//! A [`SessionError`] closes the session; its code is the draft's own, and
//! where draft 22 had no code of its own for the condition it is
//! PROTOCOL_VIOLATION ([`SessionError::code`]). Request, PUBLISH_DONE and
//! stream reset codes are shared by both drafts except where noted.

use super::version::Version;

/// Why a session is closed (section 12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCode {
    NoError,
    InternalError,
    Unauthorized,
    ProtocolViolation,
    InvalidRequestId,
    DuplicateTrackAlias,
    MalformedKeyValue,
    InvalidPath,
    MalformedPath,
    GoawayTimeout,
    ControlMessageTimeout,
    DataStreamTimeout,
    AuthTokenCacheOverflow,
    DuplicateAuthTokenAlias,
    MalformedAuthToken,
    UnknownAuthTokenAlias,
    ExpiredAuthToken,
    InvalidAuthority,
    MalformedAuthority,
    TooManyRequestUpdates,
    // From draft 23
    InvalidStreamHeader,
    MalformedObject,
    InvalidObjectStatus,
    TruncatedObject,
    MalformedMessage,
    InvalidField,
    InvalidTrackNamespace,
    UnexpectedMessage,
    RoleViolation,
    InvalidParameter,
    ClosedControlStream,
    DeltaEncodingOverflow,
    FieldLengthExceeded,
}

impl SessionCode {
    /// The code on the wire in `version`.
    pub const fn code(self, version: Version) -> u64 {
        match self {
            Self::NoError => 0x0,
            Self::InternalError => 0x1,
            Self::Unauthorized => 0x2,
            Self::ProtocolViolation => 0x3,
            Self::InvalidRequestId => 0x4,
            Self::DuplicateTrackAlias => 0x5,
            // KEY_VALUE_FORMATTING_ERROR in draft 22, the same code
            Self::MalformedKeyValue => 0x6,
            Self::InvalidPath => 0x8,
            Self::MalformedPath => 0x9,
            Self::GoawayTimeout => 0x10,
            Self::ControlMessageTimeout => 0x11,
            Self::DataStreamTimeout => 0x12,
            Self::AuthTokenCacheOverflow => 0x13,
            Self::DuplicateAuthTokenAlias => 0x14,
            Self::MalformedAuthToken => 0x16,
            Self::UnknownAuthTokenAlias => 0x17,
            Self::ExpiredAuthToken => 0x18,
            Self::InvalidAuthority => 0x19,
            Self::MalformedAuthority => 0x1A,
            Self::TooManyRequestUpdates => 0x1B,
            other => {
                if !version.specific_session_errors() {
                    return 0x3;
                }
                match other {
                    Self::InvalidStreamHeader => 0x200,
                    Self::MalformedObject => 0x201,
                    Self::InvalidObjectStatus => 0x202,
                    Self::TruncatedObject => 0x203,
                    Self::MalformedMessage => 0x300,
                    Self::InvalidField => 0x301,
                    Self::InvalidTrackNamespace => 0x302,
                    Self::UnexpectedMessage => 0x303,
                    Self::RoleViolation => 0x304,
                    Self::InvalidParameter => 0x305,
                    Self::ClosedControlStream => 0x306,
                    Self::DeltaEncodingOverflow => 0x400,
                    Self::FieldLengthExceeded => 0x401,
                    _ => 0x3,
                }
            }
        }
    }

    /// The name of the code sent in `version`: where a draft has no code of
    /// its own for the condition (draft 22, for most of 23's 0x200-0x401),
    /// PROTOCOL_VIOLATION, which is what goes on the wire.
    pub const fn name_in(self, version: Version) -> &'static str {
        if self.code(version) == 0x3 {
            "PROTOCOL_VIOLATION"
        } else {
            self.name()
        }
    }

    /// The draft's name for the code, for logs and the admin API.
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoError => "NO_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::InvalidRequestId => "INVALID_REQUEST_ID",
            Self::DuplicateTrackAlias => "DUPLICATE_TRACK_ALIAS",
            Self::MalformedKeyValue => "MALFORMED_KEY_VALUE",
            Self::InvalidPath => "INVALID_PATH",
            Self::MalformedPath => "MALFORMED_PATH",
            Self::GoawayTimeout => "GOAWAY_TIMEOUT",
            Self::ControlMessageTimeout => "CONTROL_MESSAGE_TIMEOUT",
            Self::DataStreamTimeout => "DATA_STREAM_TIMEOUT",
            Self::AuthTokenCacheOverflow => "AUTH_TOKEN_CACHE_OVERFLOW",
            Self::DuplicateAuthTokenAlias => "DUPLICATE_AUTH_TOKEN_ALIAS",
            Self::MalformedAuthToken => "MALFORMED_AUTH_TOKEN",
            Self::UnknownAuthTokenAlias => "UNKNOWN_AUTH_TOKEN_ALIAS",
            Self::ExpiredAuthToken => "EXPIRED_AUTH_TOKEN",
            Self::InvalidAuthority => "INVALID_AUTHORITY",
            Self::MalformedAuthority => "MALFORMED_AUTHORITY",
            Self::TooManyRequestUpdates => "TOO_MANY_REQUEST_UPDATES",
            Self::InvalidStreamHeader => "INVALID_STREAM_HEADER",
            Self::MalformedObject => "MALFORMED_OBJECT",
            Self::InvalidObjectStatus => "INVALID_OBJECT_STATUS",
            Self::TruncatedObject => "TRUNCATED_OBJECT",
            Self::MalformedMessage => "MALFORMED_MESSAGE",
            Self::InvalidField => "INVALID_FIELD",
            Self::InvalidTrackNamespace => "INVALID_TRACK_NAMESPACE",
            Self::UnexpectedMessage => "UNEXPECTED_MESSAGE",
            Self::RoleViolation => "ROLE_VIOLATION",
            Self::InvalidParameter => "INVALID_PARAMETER",
            Self::ClosedControlStream => "CLOSED_CONTROL_STREAM",
            Self::DeltaEncodingOverflow => "DELTA_ENCODING_OVERFLOW",
            Self::FieldLengthExceeded => "FIELD_LENGTH_EXCEEDED",
        }
    }
}

/// A condition that closes the session: its code and a reason for the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionError {
    pub code: SessionCode,
    pub reason: &'static str,
}

impl SessionError {
    pub const fn new(code: SessionCode, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.name(), self.reason)
    }
}

impl std::error::Error for SessionError {}

/// Shorthand for the codec and session: an error that closes the session.
pub type SessionResult<T> = Result<T, SessionError>;

pub(crate) const fn fail<T>(code: SessionCode, reason: &'static str) -> SessionResult<T> {
    Err(SessionError::new(code, reason))
}

/// REQUEST_ERROR codes (section 12.3, IANA 16.12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RequestCode {
    InternalError = 0x0,
    Unauthorized = 0x1,
    Timeout = 0x2,
    NotSupported = 0x3,
    MalformedAuthToken = 0x4,
    ExpiredAuthToken = 0x5,
    GoingAway = 0x6,
    ExcessiveLoad = 0x9,
    /// From draft 23 (draft 22: EXCESSIVE_LOAD is the nearest)
    Unavailable = 0xA,
    DoesNotExist = 0x10,
    InvalidRange = 0x11,
    MalformedTrack = 0x12,
    Uninterested = 0x20,
    NamespaceTooLarge = 0x31,
    UnsupportedExtension = 0x33,
    Redirect = 0x34,
    ConflictingFilters = 0x35,
    InvalidFilter = 0x36,
}

impl RequestCode {
    pub const fn code(self, version: Version) -> u64 {
        match (self, version) {
            (Self::Unavailable, Version::Draft22) => Self::ExcessiveLoad as u64,
            _ => self as u64,
        }
    }
}

/// PUBLISH_DONE status codes (section 12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum DoneCode {
    InternalError = 0x0,
    Unauthorized = 0x1,
    TrackEnded = 0x2,
    GoingAway = 0x4,
    TooFarBehind = 0x5,
    Expired = 0x6,
    /// From draft 23 (draft 22: UNAUTHORIZED is the nearest)
    ExpiredAuthToken = 0x7,
    UpdateFailed = 0x8,
    ExcessiveLoad = 0x9,
    MalformedTrack = 0x12,
}

impl DoneCode {
    pub const fn code(self, version: Version) -> u64 {
        match (self, version) {
            (Self::ExpiredAuthToken, Version::Draft22) => Self::Unauthorized as u64,
            _ => self as u64,
        }
    }
}

/// Stream reset and STOP_SENDING codes (section 12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ResetCode {
    InternalError = 0x0,
    Cancelled = 0x1,
    DeliveryTimeout = 0x2,
    SessionClosed = 0x3,
    GoingAway = 0x4,
    TooFarBehind = 0x5,
    ExpiredAuthToken = 0x7,
    ExcessiveLoad = 0x9,
    MalformedTrack = 0x12,
}

/// Whether `value` is a grease code point (section 13): 0x7f * N + 0x9D.
pub const fn is_grease(value: u64) -> bool {
    value >= 0x9D && (value - 0x9D).is_multiple_of(0x7F)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_23_codes_fall_back_to_protocol_violation_in_22() {
        assert_eq!(SessionCode::UnexpectedMessage.code(Version::Draft23), 0x303);
        assert_eq!(SessionCode::UnexpectedMessage.code(Version::Draft22), 0x3);
        assert_eq!(
            SessionCode::FieldLengthExceeded.code(Version::Draft23),
            0x401
        );
        assert_eq!(SessionCode::InvalidRequestId.code(Version::Draft22), 0x4);
        assert_eq!(SessionCode::MalformedKeyValue.code(Version::Draft22), 0x6);
    }

    /// A close is named as sent: draft 22 has no INVALID_PARAMETER (an
    /// interop session logged one where 0x3 went on the wire)
    #[test]
    fn a_code_is_named_as_sent() {
        let p = SessionCode::InvalidParameter;
        assert_eq!(p.name_in(Version::Draft23), "INVALID_PARAMETER");
        assert_eq!(p.name_in(Version::Draft22), "PROTOCOL_VIOLATION");
        assert_eq!(
            SessionCode::MalformedPath.name_in(Version::Draft22),
            "MALFORMED_PATH"
        );
        assert_eq!(
            SessionCode::ProtocolViolation.name_in(Version::Draft23),
            "PROTOCOL_VIOLATION"
        );
    }

    #[test]
    fn grease_values_follow_the_pattern() {
        assert!(is_grease(0x9D));
        assert!(is_grease(0x11C));
        assert!(is_grease(0x3fff_ffff_ffff_ffde));
        assert!(!is_grease(0x9C));
        assert!(!is_grease(0x11D));
        assert!(!is_grease(0));
    }
}
