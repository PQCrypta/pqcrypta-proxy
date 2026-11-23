//! MOQT control messages, Setup Options and Message Parameters
//! (draft-ietf-moq-transport sections 9 and 16.4-16.7), for every version
//! in [`Version`].
//!
//! Each message on a control or request stream is its type, its length and
//! its body (section 9): the length is 16 bits in draft 22 and a varint from
//! draft 23. A length that does not match the body is MALFORMED_MESSAGE; an
//! unknown type is UNEXPECTED_MESSAGE; a parameter the message does not allow
//! is INVALID_PARAMETER (section 9.19.1). Range Filter problems are not
//! session errors but the request's own (INVALID_FILTER), so they are kept
//! on the decoded [`Params`] for the session to answer.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::codec::{
    put_kvps, put_prefixed, put_reason, put_vi64, read_vi64, Kvp, Location, Namespace, Reader,
    TrackName,
};
use super::error::{fail, SessionCode as C, SessionError, SessionResult};
use super::version::Version;

// ── Message types (section 9) ───────────────────────────────────────────────

pub const SETUP: u64 = 0x2F00;
pub const GOAWAY: u64 = 0x10;
pub const SUBSCRIBE: u64 = 0x3;
pub const SUBSCRIBE_OK: u64 = 0x4;
pub const PUBLISH_STATE_NOTIFY: u64 = 0x22;
pub const PUBLISH: u64 = 0x1D;
pub const PUBLISH_DONE: u64 = 0xB;
pub const FETCH: u64 = 0x16;
/// Draft 22 only
pub const FETCH_OK_22: u64 = 0x18;
pub const TRACK_STATUS: u64 = 0xD;
pub const PUBLISH_NAMESPACE: u64 = 0x6;
pub const SUBSCRIBE_NAMESPACE: u64 = 0x50;
pub const SUBSCRIBE_TRACKS: u64 = 0x51;
pub const NAMESPACE: u64 = 0x8;
pub const NAMESPACE_DONE: u64 = 0xE;
pub const PUBLISH_SKIPPED: u64 = 0xF;
pub const REQUEST_UPDATE: u64 = 0x2;
pub const REQUEST_OK: u64 = 0x7;
pub const REQUEST_ERROR: u64 = 0x5;

/// The messages that may open a request stream (section 6.3).
/// A request type's name, as the draft writes it (for logs).
pub const fn request_name(kind: u64) -> &'static str {
    match kind {
        TRACK_STATUS => "TRACK_STATUS",
        SUBSCRIBE => "SUBSCRIBE",
        PUBLISH => "PUBLISH",
        FETCH => "FETCH",
        PUBLISH_NAMESPACE => "PUBLISH_NAMESPACE",
        SUBSCRIBE_NAMESPACE => "SUBSCRIBE_NAMESPACE",
        SUBSCRIBE_TRACKS => "SUBSCRIBE_TRACKS",
        _ => "an unknown request",
    }
}

pub const REQUEST_TYPES: [u64; 7] = [
    TRACK_STATUS,
    SUBSCRIBE,
    PUBLISH,
    FETCH,
    PUBLISH_NAMESPACE,
    SUBSCRIBE_NAMESPACE,
    SUBSCRIBE_TRACKS,
];

// ── Setup Options (section 9.1, 16.4) ───────────────────────────────────────

pub const OPT_PATH: u64 = 0x01;
pub const OPT_AUTHORIZATION_TOKEN: u64 = 0x03;
pub const OPT_MAX_AUTH_TOKEN_CACHE_SIZE: u64 = 0x04;
pub const OPT_AUTHORITY: u64 = 0x05;
pub const OPT_MAX_FILTER_RANGES: u64 = 0x06;
pub const OPT_MOQT_IMPLEMENTATION: u64 = 0x07;
pub const OPT_MAX_REQUEST_UPDATES: u64 = 0x08;
/// Draft 23
pub const OPT_MAX_CONTROL_MESSAGE_SIZE: u64 = 0x09;

/// The default and smallest MAX_CONTROL_MESSAGE_SIZE (section 9.1.8); draft
/// 22's 16-bit length makes it the limit there too.
pub const DEFAULT_MAX_CONTROL_MESSAGE: u64 = 65_535;
/// Largest GOAWAY New Session URI (section 9.2)
pub const MAX_GOAWAY_URI: usize = 8_192;

// ── Message Parameters (section 9.19, 16.7) ─────────────────────────────────

pub const P_OBJECT_DELIVERY_TIMEOUT: u64 = 0x02;
pub const P_AUTHORIZATION_TOKEN: u64 = 0x03;
pub const P_RENDEZVOUS_TIMEOUT: u64 = 0x04;
pub const P_SUBGROUP_DELIVERY_TIMEOUT: u64 = 0x06;
pub const P_EXPIRES: u64 = 0x08;
pub const P_LARGEST_OBJECT: u64 = 0x09;
pub const P_FILL_TIMEOUT: u64 = 0x0A;
/// Draft 22: FORWARD (1 = forward); draft 23 replaced it with PAUSED
pub const P_FORWARD_22: u64 = 0x10;
pub const P_PAUSED: u64 = 0x11;
pub const P_SUBSCRIBER_PRIORITY: u64 = 0x20;
pub const P_LOCATION_FILTER: u64 = 0x21;
pub const P_GROUP_ORDER: u64 = 0x22;
pub const P_FILL_PARAMETERS: u64 = 0x23;
pub const P_SUBGROUP_FILTER: u64 = 0x25;
pub const P_OBJECTID_FILTER: u64 = 0x26;
pub const P_PRIORITY_FILTER: u64 = 0x27;
pub const P_OBJECT_PROPERTY_FILTER: u64 = 0x28;
pub const P_TRACK_PROPERTY_FILTER: u64 = 0x29;
pub const P_NEW_GROUP_REQUEST: u64 = 0x32;
pub const P_TRACK_NAMESPACE_PREFIX: u64 = 0x34;
pub const P_INCLUDE_PROPERTIES: u64 = 0x35;
/// Draft 23
pub const P_SUBSCRIBE_TRACKS_ID: u64 = 0x36;

/// The pause parameter's type in `version`.
pub const fn paused_type(version: Version) -> u64 {
    if version.paused_parameter() {
        P_PAUSED
    } else {
        P_FORWARD_22
    }
}

/// Which parameters a message may carry (sections 9.6-9.19); `PAUSED` stands
/// for the version's pause parameter.
pub mod allowed {
    use super::{
        P_AUTHORIZATION_TOKEN, P_EXPIRES, P_FILL_PARAMETERS, P_FILL_TIMEOUT, P_GROUP_ORDER,
        P_INCLUDE_PROPERTIES, P_LARGEST_OBJECT, P_LOCATION_FILTER, P_NEW_GROUP_REQUEST,
        P_OBJECTID_FILTER, P_OBJECT_DELIVERY_TIMEOUT, P_OBJECT_PROPERTY_FILTER, P_PRIORITY_FILTER,
        P_RENDEZVOUS_TIMEOUT, P_SUBGROUP_DELIVERY_TIMEOUT, P_SUBGROUP_FILTER,
        P_SUBSCRIBER_PRIORITY, P_SUBSCRIBE_TRACKS_ID, P_TRACK_NAMESPACE_PREFIX,
        P_TRACK_PROPERTY_FILTER,
    };
    pub const PAUSED: u64 = u64::MAX;
    const RANGE: [u64; 4] = [
        P_SUBGROUP_FILTER,
        P_OBJECTID_FILTER,
        P_PRIORITY_FILTER,
        P_OBJECT_PROPERTY_FILTER,
    ];

    macro_rules! set {
        ($($x:expr),* $(; $($r:expr),*)?) => {{
            #[allow(unused_mut)]
            let mut v: Vec<u64> = vec![$($x),*];
            $($(v.extend_from_slice(&$r);)*)?
            v
        }};
    }

    pub fn subscribe() -> Vec<u64> {
        set![P_OBJECT_DELIVERY_TIMEOUT, P_AUTHORIZATION_TOKEN, P_RENDEZVOUS_TIMEOUT,
            P_SUBGROUP_DELIVERY_TIMEOUT, PAUSED, P_SUBSCRIBER_PRIORITY, P_LOCATION_FILTER,
            P_GROUP_ORDER, P_FILL_PARAMETERS, P_NEW_GROUP_REQUEST, P_INCLUDE_PROPERTIES; RANGE]
    }
    pub fn subscribe_ok() -> Vec<u64> {
        set![P_EXPIRES, P_LARGEST_OBJECT]
    }
    pub fn publish() -> Vec<u64> {
        set![
            P_OBJECT_DELIVERY_TIMEOUT,
            P_AUTHORIZATION_TOKEN,
            P_SUBGROUP_DELIVERY_TIMEOUT,
            P_EXPIRES,
            P_LARGEST_OBJECT,
            PAUSED,
            P_SUBSCRIBER_PRIORITY,
            P_LOCATION_FILTER,
            P_GROUP_ORDER,
            P_FILL_PARAMETERS,
            P_SUBSCRIBE_TRACKS_ID
        ]
    }
    pub fn fetch() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN, P_FILL_TIMEOUT, P_SUBSCRIBER_PRIORITY, P_LOCATION_FILTER,
            P_GROUP_ORDER, P_INCLUDE_PROPERTIES; RANGE]
    }
    pub fn track_status() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN, P_INCLUDE_PROPERTIES]
    }
    pub fn namespace_request() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN]
    }
    pub fn subscribe_tracks() -> Vec<u64> {
        set![P_OBJECT_DELIVERY_TIMEOUT, P_AUTHORIZATION_TOKEN, P_SUBGROUP_DELIVERY_TIMEOUT,
            PAUSED, P_SUBSCRIBER_PRIORITY, P_LOCATION_FILTER, P_GROUP_ORDER, P_FILL_PARAMETERS,
            P_TRACK_PROPERTY_FILTER, P_INCLUDE_PROPERTIES; RANGE]
    }
    pub fn publish_state_notify() -> Vec<u64> {
        set![P_LARGEST_OBJECT, PAUSED, P_LOCATION_FILTER]
    }
    pub fn fill() -> Vec<u64> {
        set![P_FILL_TIMEOUT, P_SUBSCRIBER_PRIORITY, P_LOCATION_FILTER, P_GROUP_ORDER; RANGE]
    }
    /// REQUEST_UPDATE, by the request it updates (section 9.5)
    pub fn update_subscription() -> Vec<u64> {
        set![P_OBJECT_DELIVERY_TIMEOUT, P_AUTHORIZATION_TOKEN, P_SUBGROUP_DELIVERY_TIMEOUT,
            PAUSED, P_SUBSCRIBER_PRIORITY, P_LOCATION_FILTER, P_FILL_PARAMETERS,
            P_NEW_GROUP_REQUEST; RANGE]
    }
    pub fn update_fetch() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN, P_SUBSCRIBER_PRIORITY]
    }
    pub fn update_publish_namespace() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN]
    }
    pub fn update_subscribe_namespace() -> Vec<u64> {
        set![P_AUTHORIZATION_TOKEN, P_TRACK_NAMESPACE_PREFIX]
    }
    pub fn update_subscribe_tracks() -> Vec<u64> {
        set![
            P_AUTHORIZATION_TOKEN,
            PAUSED,
            P_TRACK_PROPERTY_FILTER,
            P_TRACK_NAMESPACE_PREFIX
        ]
    }
    /// REQUEST_OK, by the request it answers (section 9.3); draft 23 allows
    /// EXPIRES in every OK
    pub fn ok_with_largest() -> Vec<u64> {
        set![P_EXPIRES, P_LARGEST_OBJECT]
    }
    pub fn ok_expires() -> Vec<u64> {
        set![P_EXPIRES]
    }
    pub fn none() -> Vec<u64> {
        Vec::new()
    }
}

/// Whether a group's objects go in ascending or descending group order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum GroupOrder {
    Ascending,
    Descending,
}

/// A Location Filter (section 9.19.9), its fields as sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationFilter {
    None,
    RelativeStart {
        start_group: u64,
    },
    AbsoluteStart {
        start: Location,
    },
    /// The end is the last object of group `end_group`
    AbsoluteGroupEnd {
        start: Location,
        end_group: u64,
    },
    AbsoluteRange {
        start: Location,
        end: Location,
    },
    NextObject,
}

impl LocationFilter {
    fn decode(r: &mut Reader<'_>) -> SessionResult<Self> {
        let kind = r.vi64()?;
        let with_end = |r: &mut Reader<'_>, start: Location| -> SessionResult<u64> {
            let delta = r.vi64()?;
            match start.group.checked_add(delta) {
                Some(g) => Ok(g),
                None => fail(
                    C::DeltaEncodingOverflow,
                    "StartGroup + EndGroupDelta past 2^64 - 1",
                ),
            }
        };
        Ok(match kind {
            0x00 => Self::None,
            0x01 => Self::RelativeStart {
                start_group: r.vi64()?,
            },
            0x02 => Self::AbsoluteStart {
                start: r.location()?,
            },
            0x03 => {
                let start = r.location()?;
                let end_group = with_end(r, start)?;
                Self::AbsoluteGroupEnd { start, end_group }
            }
            0x04 => {
                let start = r.location()?;
                let end_group = with_end(r, start)?;
                let end = Location::new(end_group, r.vi64()?);
                Self::AbsoluteRange { start, end }
            }
            0x05 => Self::NextObject,
            _ => return fail(C::InvalidParameter, "an unknown Location Filter Type"),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            Self::None => put_vi64(out, 0),
            Self::RelativeStart { start_group } => {
                put_vi64(out, 1);
                put_vi64(out, start_group);
            }
            Self::AbsoluteStart { start } => {
                put_vi64(out, 2);
                start.encode(out);
            }
            Self::AbsoluteGroupEnd { start, end_group } => {
                put_vi64(out, 3);
                start.encode(out);
                put_vi64(out, end_group - start.group);
            }
            Self::AbsoluteRange { start, end } => {
                put_vi64(out, 4);
                start.encode(out);
                put_vi64(out, end.group - start.group);
                put_vi64(out, end.object);
            }
            Self::NextObject => put_vi64(out, 5),
        }
    }

    pub const fn is_relative(&self) -> bool {
        matches!(self, Self::RelativeStart { .. })
    }

    /// The start and (inclusive) end this filter selects, given the track's
    /// Largest Object; `None` as the end is open-ended (section 9.19.9).
    pub fn bounds(&self, largest: Option<Location>) -> (Location, Option<Location>) {
        let next_object = largest.map_or(Location::new(0, 0), Location::next_object);
        match *self {
            Self::None => (Location::new(0, 0), None),
            Self::RelativeStart { start_group } => {
                let next_group = largest.map_or(0, |l| l.group.saturating_add(1));
                (
                    Location::new(next_group.saturating_sub(start_group), 0),
                    None,
                )
            }
            Self::AbsoluteStart { start } => (start, None),
            Self::AbsoluteGroupEnd { start, end_group } => {
                (start, Some(Location::new(end_group, u64::MAX)))
            }
            Self::AbsoluteRange { start, end } => (start, Some(end)),
            Self::NextObject => (next_object, None),
        }
    }
}

/// One Range Filter parameter (sections 8.6, 9.19.10-14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeFilter {
    pub kind: u64,
    pub set_id: u8,
    /// The Property Type, for the Object and Track Property filters
    pub property: Option<u64>,
    /// Inclusive ranges; `None` as the last end is open-ended
    pub ranges: Vec<(u64, Option<u64>)>,
}

impl RangeFilter {
    /// Whether `value` falls in any of the ranges (they are OR'd).
    pub fn admits(&self, value: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(start, end)| value >= start && end.is_none_or(|e| value <= e))
    }
}

/// An Authorization Token structure (section 8.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Delete { alias: u64 },
    Register { alias: u64, kind: u64, value: Bytes },
    UseAlias { alias: u64 },
    UseValue { kind: u64, value: Bytes },
}

impl Token {
    fn decode(bytes: &[u8]) -> SessionResult<Self> {
        let mut r = Reader::new(bytes, C::MalformedAuthToken);
        let token = match r.vi64()? {
            0x0 => Self::Delete { alias: r.vi64()? },
            0x1 => Self::Register {
                alias: r.vi64()?,
                kind: r.vi64()?,
                value: Bytes::copy_from_slice(r.rest()),
            },
            0x2 => Self::UseAlias { alias: r.vi64()? },
            0x3 => Self::UseValue {
                kind: r.vi64()?,
                value: Bytes::copy_from_slice(r.rest()),
            },
            _ => return fail(C::MalformedAuthToken, "an unknown Alias Type"),
        };
        if !r.is_empty() {
            return fail(C::MalformedAuthToken, "bytes after the Token");
        }
        Ok(token)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Delete { alias } => {
                put_vi64(out, 0);
                put_vi64(out, *alias);
            }
            Self::Register { alias, kind, value } => {
                put_vi64(out, 1);
                put_vi64(out, *alias);
                put_vi64(out, *kind);
                out.extend_from_slice(value);
            }
            Self::UseAlias { alias } => {
                put_vi64(out, 2);
                put_vi64(out, *alias);
            }
            Self::UseValue { kind, value } => {
                put_vi64(out, 3);
                put_vi64(out, *kind);
                out.extend_from_slice(value);
            }
        }
    }
}

/// A message's parameters, decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params {
    pub object_delivery_timeout: Option<u64>,
    pub auth_tokens: Vec<Token>,
    pub rendezvous_timeout: Option<u64>,
    pub subgroup_delivery_timeout: Option<u64>,
    pub expires: Option<u64>,
    pub largest_object: Option<Location>,
    pub fill_timeout: Option<u64>,
    /// PAUSED (draft 23) or the inverse of FORWARD (draft 22)
    pub paused: Option<bool>,
    pub subscriber_priority: Option<u8>,
    pub location_filter: Option<LocationFilter>,
    pub group_order: Option<GroupOrder>,
    pub fill: Option<Box<Params>>,
    pub range_filters: Vec<RangeFilter>,
    pub new_group_request: Option<u64>,
    pub track_namespace_prefix: Option<Namespace>,
    pub include_properties: Option<bool>,
    pub subscribe_tracks_id: Option<u64>,
    /// A Range Filter that cannot be honoured: the request is refused with
    /// INVALID_FILTER (sections 3.3.2, 8.6), not the session
    pub filter_error: Option<&'static str>,
    /// Range Filters whose Length was 0: removed by a REQUEST_UPDATE
    pub removed_filters: Vec<(u64, u8, Option<u64>)>,
}

impl Params {
    /// `count` parameters from `r`, each of a type in `allowed`
    /// ([`allowed::PAUSED`] standing for the version's pause parameter).
    pub fn decode(
        r: &mut Reader<'_>,
        count: u64,
        version: Version,
        allowed: &[u64],
    ) -> SessionResult<Self> {
        let mut p = Params::default();
        let mut last = 0u64;
        let mut seen: Vec<u64> = Vec::new();
        let pause = paused_type(version);
        for _ in 0..count {
            let delta = r.vi64()?;
            let Some(kind) = last.checked_add(delta) else {
                return fail(C::DeltaEncodingOverflow, "a Parameter Type past 2^64 - 1");
            };
            last = kind;
            let permitted = allowed
                .iter()
                .any(|&a| a == kind || (a == allowed::PAUSED && kind == pause));
            // SUBSCRIBE_TRACKS_ID is draft 23's; draft 22 defines no 0x36
            if !permitted || (kind == P_SUBSCRIBE_TRACKS_ID && !version.paused_parameter()) {
                return fail(
                    C::InvalidParameter,
                    "a parameter the message does not allow",
                );
            }
            let repeatable = matches!(
                kind,
                P_AUTHORIZATION_TOKEN
                    | P_SUBGROUP_FILTER
                    | P_OBJECTID_FILTER
                    | P_PRIORITY_FILTER
                    | P_OBJECT_PROPERTY_FILTER
                    | P_TRACK_PROPERTY_FILTER
            );
            if !repeatable && seen.contains(&kind) {
                return fail(C::InvalidParameter, "a parameter repeated");
            }
            seen.push(kind);
            p.decode_one(r, kind, version)?;
        }
        Ok(p)
    }

    fn decode_one(&mut self, r: &mut Reader<'_>, kind: u64, version: Version) -> SessionResult<()> {
        let flag = |v: u8| -> SessionResult<bool> {
            match v {
                0 => Ok(false),
                1 => Ok(true),
                _ => fail(C::InvalidParameter, "a flag parameter other than 0 or 1"),
            }
        };
        match kind {
            P_OBJECT_DELIVERY_TIMEOUT => self.object_delivery_timeout = Some(r.vi64()?),
            P_AUTHORIZATION_TOKEN => self.auth_tokens.push(Token::decode(r.prefixed()?)?),
            P_RENDEZVOUS_TIMEOUT => self.rendezvous_timeout = Some(r.vi64()?),
            P_SUBGROUP_DELIVERY_TIMEOUT => self.subgroup_delivery_timeout = Some(r.vi64()?),
            P_EXPIRES => self.expires = Some(r.vi64()?),
            P_LARGEST_OBJECT => self.largest_object = Some(r.location()?),
            P_FILL_TIMEOUT => self.fill_timeout = Some(r.vi64()?),
            P_FORWARD_22 => self.paused = Some(!flag(r.u8()?)?),
            P_PAUSED => self.paused = Some(flag(r.u8()?)?),
            P_SUBSCRIBER_PRIORITY => self.subscriber_priority = Some(r.u8()?),
            P_LOCATION_FILTER => self.location_filter = Some(LocationFilter::decode(r)?),
            P_GROUP_ORDER => {
                self.group_order = Some(match r.u8()? {
                    1 => GroupOrder::Ascending,
                    2 => GroupOrder::Descending,
                    _ => return fail(C::InvalidParameter, "a GROUP_ORDER other than 1 or 2"),
                });
            }
            P_FILL_PARAMETERS => {
                let fill = if version.fill_parameters_counted() {
                    let count = r.vi64()?;
                    Params::decode(r, count, version, &allowed::fill())?
                } else {
                    let body = r.prefixed()?;
                    let mut inner = Reader::new(body, C::MalformedMessage);
                    let mut fill = Params::default();
                    let mut last = 0u64;
                    while !inner.is_empty() {
                        let delta = inner.vi64()?;
                        let Some(k) = last.checked_add(delta) else {
                            return fail(
                                C::DeltaEncodingOverflow,
                                "a Parameter Type past 2^64 - 1",
                            );
                        };
                        last = k;
                        if !allowed::fill().contains(&k) {
                            return fail(
                                C::InvalidParameter,
                                "a parameter FILL_PARAMETERS does not allow",
                            );
                        }
                        fill.decode_one(&mut inner, k, version)?;
                    }
                    fill
                };
                self.fill = Some(Box::new(fill));
            }
            P_SUBGROUP_FILTER
            | P_OBJECTID_FILTER
            | P_PRIORITY_FILTER
            | P_OBJECT_PROPERTY_FILTER
            | P_TRACK_PROPERTY_FILTER => self.decode_range_filter(r, kind)?,
            P_NEW_GROUP_REQUEST => self.new_group_request = Some(r.vi64()?),
            P_TRACK_NAMESPACE_PREFIX => self.track_namespace_prefix = Some(r.namespace()?),
            P_INCLUDE_PROPERTIES => self.include_properties = Some(flag(r.u8()?)?),
            P_SUBSCRIBE_TRACKS_ID => self.subscribe_tracks_id = Some(r.vi64()?),
            _ => return fail(C::InvalidParameter, "an unknown parameter"),
        }
        Ok(())
    }

    fn decode_range_filter(&mut self, r: &mut Reader<'_>, kind: u64) -> SessionResult<()> {
        let body = r.prefixed()?;
        if body.is_empty() {
            self.removed_filters.push((kind, 0, None));
            return Ok(());
        }
        let mut f = Reader::new(body, C::MalformedMessage);
        let set_id = f.u8()?;
        let property = if matches!(kind, P_OBJECT_PROPERTY_FILTER | P_TRACK_PROPERTY_FILTER) {
            let t = f.vi64()?;
            if t % 2 == 1 {
                self.filter_error
                    .get_or_insert("a property filter on an odd (byte-valued) Property Type");
            }
            Some(t)
        } else {
            None
        };
        let mut ranges = Vec::new();
        let mut prior_end = 0u64;
        while !f.is_empty() {
            let Some(start) = prior_end.checked_add(f.vi64()?) else {
                self.filter_error
                    .get_or_insert("a Range start past 2^64 - 1");
                return Ok(());
            };
            if f.is_empty() {
                ranges.push((start, None));
                break;
            }
            let Some(end) = start.checked_add(f.vi64()?) else {
                self.filter_error.get_or_insert("a Range end past 2^64 - 1");
                return Ok(());
            };
            ranges.push((start, Some(end)));
            prior_end = end;
        }
        if kind == P_PRIORITY_FILTER
            && ranges
                .iter()
                .any(|&(s, e)| s > 255 || e.is_some_and(|e| e > 255))
        {
            self.filter_error
                .get_or_insert("a Publisher Priority range past 255");
        }
        if self
            .range_filters
            .iter()
            .any(|x| x.kind == kind && x.set_id == set_id && x.property == property)
        {
            self.filter_error
                .get_or_insert("a Range Filter repeated with the same type, SetID and property");
        }
        self.range_filters.push(RangeFilter {
            kind,
            set_id,
            property,
            ranges,
        });
        Ok(())
    }

    /// The number of Ranges across every Range Filter (MAX_FILTER_RANGES).
    pub fn range_count(&self) -> usize {
        self.range_filters.iter().map(|f| f.ranges.len()).sum()
    }

    /// Encode as `Number of Parameters` then the parameters, in ascending
    /// type order.
    pub fn encode(&self, out: &mut Vec<u8>, version: Version) {
        let mut items: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut put = |kind: u64, value: Vec<u8>| items.push((kind, value));
        let vi = |v: u64| {
            let mut b = Vec::new();
            put_vi64(&mut b, v);
            b
        };
        if let Some(v) = self.object_delivery_timeout {
            put(P_OBJECT_DELIVERY_TIMEOUT, vi(v));
        }
        for t in &self.auth_tokens {
            let mut tb = Vec::new();
            t.encode(&mut tb);
            let mut b = Vec::new();
            put_prefixed(&mut b, &tb);
            put(P_AUTHORIZATION_TOKEN, b);
        }
        if let Some(v) = self.rendezvous_timeout {
            put(P_RENDEZVOUS_TIMEOUT, vi(v));
        }
        if let Some(v) = self.subgroup_delivery_timeout {
            put(P_SUBGROUP_DELIVERY_TIMEOUT, vi(v));
        }
        if let Some(v) = self.expires {
            put(P_EXPIRES, vi(v));
        }
        if let Some(l) = self.largest_object {
            let mut b = Vec::new();
            l.encode(&mut b);
            put(P_LARGEST_OBJECT, b);
        }
        if let Some(v) = self.fill_timeout {
            put(P_FILL_TIMEOUT, vi(v));
        }
        if let Some(p) = self.paused {
            if version.paused_parameter() {
                put(P_PAUSED, vec![u8::from(p)]);
            } else {
                put(P_FORWARD_22, vec![u8::from(!p)]);
            }
        }
        if let Some(v) = self.subscriber_priority {
            put(P_SUBSCRIBER_PRIORITY, vec![v]);
        }
        if let Some(f) = &self.location_filter {
            let mut b = Vec::new();
            f.encode(&mut b);
            put(P_LOCATION_FILTER, b);
        }
        if let Some(o) = self.group_order {
            put(
                P_GROUP_ORDER,
                vec![if o == GroupOrder::Ascending { 1 } else { 2 }],
            );
        }
        if let Some(fill) = &self.fill {
            let mut inner = Vec::new();
            fill.encode(&mut inner, version);
            if version.fill_parameters_counted() {
                put(P_FILL_PARAMETERS, inner);
            } else {
                // Draft 22: the parameters without their count, length-prefixed
                let mut r = Reader::new(&inner, C::MalformedMessage);
                let _ = r.vi64();
                let mut b = Vec::new();
                put_prefixed(&mut b, r.rest());
                put(P_FILL_PARAMETERS, b);
            }
        }
        for f in &self.range_filters {
            let mut body = vec![f.set_id];
            if let Some(t) = f.property {
                put_vi64(&mut body, t);
            }
            let mut prior_end = 0u64;
            for &(start, end) in &f.ranges {
                put_vi64(&mut body, start - prior_end);
                if let Some(e) = end {
                    put_vi64(&mut body, e - start);
                    prior_end = e;
                }
            }
            let mut b = Vec::new();
            put_prefixed(&mut b, &body);
            put(f.kind, b);
        }
        if let Some(v) = self.new_group_request {
            put(P_NEW_GROUP_REQUEST, vi(v));
        }
        if let Some(ns) = &self.track_namespace_prefix {
            let mut b = Vec::new();
            ns.encode(&mut b);
            put(P_TRACK_NAMESPACE_PREFIX, b);
        }
        if let Some(v) = self.include_properties {
            put(P_INCLUDE_PROPERTIES, vec![u8::from(v)]);
        }
        if let Some(v) = self.subscribe_tracks_id {
            if version.paused_parameter() {
                put(P_SUBSCRIBE_TRACKS_ID, vi(v));
            }
        }
        items.sort_by_key(|(k, _)| *k);
        put_vi64(out, items.len() as u64);
        let mut last = 0u64;
        for (kind, value) in items {
            put_vi64(out, kind - last);
            last = kind;
            out.extend_from_slice(&value);
        }
    }
}

// ── Setup ───────────────────────────────────────────────────────────────────

/// SETUP (section 9.1), the options this relay understands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Setup {
    pub path: Option<Bytes>,
    pub authority: Option<Bytes>,
    pub auth_tokens: Vec<Token>,
    pub max_auth_token_cache_size: u64,
    pub max_filter_ranges: u64,
    pub implementation: Option<String>,
    pub max_request_updates: u64,
    pub max_control_message_size: u64,
    /// Every option as received, for the admin view and the analyzer
    pub options: Vec<Kvp>,
}

impl Setup {
    pub fn decode(body: &[u8], version: Version) -> SessionResult<Self> {
        let options = Reader::new(body, C::MalformedMessage).kvps_to_end()?;
        let mut s = Setup {
            max_control_message_size: DEFAULT_MAX_CONTROL_MESSAGE,
            ..Setup::default()
        };
        let mut seen = Vec::new();
        for kvp in &options {
            // Unknown options are ignored, duplicates of them allowed
            // (section 9.1); a known option is read once
            if seen.contains(&kvp.kind) {
                continue;
            }
            let bytes = |k: &Kvp| match &k.value {
                super::codec::KvpValue::Bytes(b) => Some(b.clone()),
                super::codec::KvpValue::Int(_) => None,
            };
            match kvp.kind {
                OPT_PATH => s.path = bytes(kvp),
                OPT_AUTHORITY => s.authority = bytes(kvp),
                OPT_AUTHORIZATION_TOKEN => {
                    if let Some(b) = bytes(kvp) {
                        s.auth_tokens.push(Token::decode(&b)?);
                    }
                    continue; // may repeat
                }
                OPT_MAX_AUTH_TOKEN_CACHE_SIZE => {
                    s.max_auth_token_cache_size = kvp.int().unwrap_or(0);
                }
                OPT_MAX_FILTER_RANGES => s.max_filter_ranges = kvp.int().unwrap_or(0),
                OPT_MOQT_IMPLEMENTATION => {
                    s.implementation = bytes(kvp).map(|b| String::from_utf8_lossy(&b).into_owned());
                }
                OPT_MAX_REQUEST_UPDATES => s.max_request_updates = kvp.int().unwrap_or(0),
                OPT_MAX_CONTROL_MESSAGE_SIZE if version.varint_message_length() => {
                    // An odd type: its bytes hold one varint (section 9.1.8)
                    let b = bytes(kvp).unwrap_or_default();
                    let mut r = Reader::new(&b, C::MalformedKeyValue);
                    let v = r.vi64()?;
                    if !r.is_empty() {
                        return fail(
                            C::MalformedKeyValue,
                            "MAX_CONTROL_MESSAGE_SIZE is not one varint",
                        );
                    }
                    if v < DEFAULT_MAX_CONTROL_MESSAGE {
                        return fail(C::MalformedKeyValue, "MAX_CONTROL_MESSAGE_SIZE below 65535");
                    }
                    s.max_control_message_size = v;
                }
                _ => {}
            }
            seen.push(kvp.kind);
        }
        s.options = options;
        Ok(s)
    }

    /// The options this endpoint sends (section 9.1).
    pub fn encode(&self, version: Version) -> Vec<u8> {
        let mut kvps = Vec::new();
        let b = |kind, v: &[u8]| Kvp {
            kind,
            value: super::codec::KvpValue::Bytes(Bytes::copy_from_slice(v)),
        };
        let i = |kind, v| Kvp {
            kind,
            value: super::codec::KvpValue::Int(v),
        };
        if let Some(p) = &self.path {
            kvps.push(b(OPT_PATH, p));
        }
        if let Some(a) = &self.authority {
            kvps.push(b(OPT_AUTHORITY, a));
        }
        for t in &self.auth_tokens {
            let mut tb = Vec::new();
            t.encode(&mut tb);
            kvps.push(b(OPT_AUTHORIZATION_TOKEN, &tb));
        }
        if self.max_auth_token_cache_size > 0 {
            kvps.push(i(
                OPT_MAX_AUTH_TOKEN_CACHE_SIZE,
                self.max_auth_token_cache_size,
            ));
        }
        if self.max_filter_ranges > 0 {
            kvps.push(i(OPT_MAX_FILTER_RANGES, self.max_filter_ranges));
        }
        if let Some(name) = &self.implementation {
            kvps.push(b(OPT_MOQT_IMPLEMENTATION, name.as_bytes()));
        }
        if self.max_request_updates > 0 {
            kvps.push(i(OPT_MAX_REQUEST_UPDATES, self.max_request_updates));
        }
        if version.varint_message_length()
            && self.max_control_message_size > DEFAULT_MAX_CONTROL_MESSAGE
        {
            let mut v = Vec::new();
            put_vi64(&mut v, self.max_control_message_size);
            kvps.push(b(OPT_MAX_CONTROL_MESSAGE_SIZE, &v));
        }
        let mut out = Vec::new();
        put_kvps(&mut out, &kvps);
        out
    }
}

// ── Messages ────────────────────────────────────────────────────────────────

/// A request naming one track: SUBSCRIBE, FETCH, TRACK_STATUS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrackRequest {
    pub request_id: u64,
    pub track: TrackName,
    pub params: Params,
}

/// A request naming a namespace prefix: PUBLISH_NAMESPACE,
/// SUBSCRIBE_NAMESPACE, SUBSCRIBE_TRACKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRequest {
    pub request_id: u64,
    pub prefix: Namespace,
    pub params: Params,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    pub request_id: u64,
    pub track: TrackName,
    pub track_alias: u64,
    pub params: Params,
    pub properties: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    pub code: u64,
    pub retry_interval: u64,
    pub reason: String,
    /// Error Details (draft 23) or the Redirect (draft 22, as detail 0x01)
    pub details: Vec<Kvp>,
}

/// A control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Setup(Setup),
    Goaway {
        uri: Bytes,
        timeout_ms: u64,
    },
    Subscribe(TrackRequest),
    SubscribeOk {
        track_alias: u64,
        params: Params,
        properties: Bytes,
    },
    PublishStateNotify(Params),
    Publish(Publish),
    PublishDone {
        status: u64,
        stream_count: u64,
        reason: String,
    },
    Fetch(TrackRequest),
    /// Draft 22's FETCH_OK
    FetchOk22 {
        end_of_track: bool,
        end: Location,
        params: Params,
        properties: Bytes,
    },
    TrackStatus(TrackRequest),
    PublishNamespace(PrefixRequest),
    SubscribeNamespace(PrefixRequest),
    SubscribeTracks(PrefixRequest),
    Namespace {
        suffix: Namespace,
        params: Params,
    },
    NamespaceDone {
        suffix: Namespace,
    },
    PublishSkipped {
        suffix: Namespace,
        name: Bytes,
    },
    RequestUpdate {
        request_id: u64,
        params: Params,
    },
    RequestOk {
        params: Params,
        properties: Bytes,
    },
    RequestError(RequestError),
}

/// What the decoder needs that the message does not say: on a request
/// stream, the parameters REQUEST_UPDATE and REQUEST_OK may carry depend on
/// the request.
#[derive(Debug, Clone, Default)]
pub struct Context {
    pub update_allows: Vec<u64>,
    pub ok_allows: Vec<u64>,
    /// Whether REQUEST_OK may carry Track Properties (TRACK_STATUS_OK and,
    /// from draft 23, FETCH_OK)
    pub ok_properties: bool,
}

impl Message {
    /// The message's type on the wire.
    pub fn kind(&self) -> u64 {
        match self {
            Self::Setup(_) => SETUP,
            Self::Goaway { .. } => GOAWAY,
            Self::Subscribe(_) => SUBSCRIBE,
            Self::SubscribeOk { .. } => SUBSCRIBE_OK,
            Self::PublishStateNotify(_) => PUBLISH_STATE_NOTIFY,
            Self::Publish(_) => PUBLISH,
            Self::PublishDone { .. } => PUBLISH_DONE,
            Self::Fetch(_) => FETCH,
            Self::FetchOk22 { .. } => FETCH_OK_22,
            Self::TrackStatus(_) => TRACK_STATUS,
            Self::PublishNamespace(_) => PUBLISH_NAMESPACE,
            Self::SubscribeNamespace(_) => SUBSCRIBE_NAMESPACE,
            Self::SubscribeTracks(_) => SUBSCRIBE_TRACKS,
            Self::Namespace { .. } => NAMESPACE,
            Self::NamespaceDone { .. } => NAMESPACE_DONE,
            Self::PublishSkipped { .. } => PUBLISH_SKIPPED,
            Self::RequestUpdate { .. } => REQUEST_UPDATE,
            Self::RequestOk { .. } => REQUEST_OK,
            Self::RequestError(_) => REQUEST_ERROR,
        }
    }

    /// Decode one message's body.
    pub fn decode(kind: u64, body: &[u8], version: Version, ctx: &Context) -> SessionResult<Self> {
        let mut r = Reader::new(body, C::MalformedMessage);
        let track_request =
            |r: &mut Reader<'_>, allowed: Vec<u64>| -> SessionResult<TrackRequest> {
                let request_id = r.vi64()?;
                let namespace = r.namespace()?;
                let name = r.track_name(&namespace)?;
                let count = r.vi64()?;
                let params = Params::decode(r, count, version, &allowed)?;
                Ok(TrackRequest {
                    request_id,
                    track: TrackName { namespace, name },
                    params,
                })
            };
        let prefix_request =
            |r: &mut Reader<'_>, allowed: Vec<u64>| -> SessionResult<PrefixRequest> {
                let request_id = r.vi64()?;
                let prefix = r.namespace()?;
                let count = r.vi64()?;
                let params = Params::decode(r, count, version, &allowed)?;
                Ok(PrefixRequest {
                    request_id,
                    prefix,
                    params,
                })
            };
        let msg = match kind {
            SETUP => return Ok(Self::Setup(Setup::decode(body, version)?)),
            GOAWAY => {
                let len = r.vi64()?;
                if len > MAX_GOAWAY_URI as u64 {
                    return fail(
                        C::FieldLengthExceeded,
                        "a GOAWAY New Session URI longer than 8192 bytes",
                    );
                }
                let uri =
                    Bytes::copy_from_slice(r.bytes(usize::try_from(len).unwrap_or(usize::MAX))?);
                Self::Goaway {
                    uri,
                    timeout_ms: r.vi64()?,
                }
            }
            SUBSCRIBE => Self::Subscribe(track_request(&mut r, allowed::subscribe())?),
            SUBSCRIBE_OK => {
                let track_alias = r.vi64()?;
                let count = r.vi64()?;
                let params = Params::decode(&mut r, count, version, &allowed::subscribe_ok())?;
                let properties = properties(&mut r)?;
                Self::SubscribeOk {
                    track_alias,
                    params,
                    properties,
                }
            }
            PUBLISH_STATE_NOTIFY => {
                let count = r.vi64()?;
                Self::PublishStateNotify(Params::decode(
                    &mut r,
                    count,
                    version,
                    &allowed::publish_state_notify(),
                )?)
            }
            PUBLISH => {
                let request_id = r.vi64()?;
                let namespace = r.namespace()?;
                let name = r.track_name(&namespace)?;
                let track_alias = r.vi64()?;
                let count = r.vi64()?;
                let params = Params::decode(&mut r, count, version, &allowed::publish())?;
                let properties = properties(&mut r)?;
                Self::Publish(Publish {
                    request_id,
                    track: TrackName { namespace, name },
                    track_alias,
                    params,
                    properties,
                })
            }
            PUBLISH_DONE => Self::PublishDone {
                status: r.vi64()?,
                stream_count: r.vi64()?,
                reason: r.reason()?,
            },
            FETCH => Self::Fetch(track_request(&mut r, allowed::fetch())?),
            FETCH_OK_22 if !version.fetch_ok_is_request_ok() => {
                let end_of_track = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return fail(C::ProtocolViolation, "End Of Track other than 0 or 1"),
                };
                let end = r.location()?;
                let count = r.vi64()?;
                let params = Params::decode(&mut r, count, version, &allowed::none())?;
                let properties = properties(&mut r)?;
                Self::FetchOk22 {
                    end_of_track,
                    end,
                    params,
                    properties,
                }
            }
            TRACK_STATUS => Self::TrackStatus(track_request(&mut r, allowed::track_status())?),
            PUBLISH_NAMESPACE => {
                Self::PublishNamespace(prefix_request(&mut r, allowed::namespace_request())?)
            }
            SUBSCRIBE_NAMESPACE => {
                Self::SubscribeNamespace(prefix_request(&mut r, allowed::namespace_request())?)
            }
            SUBSCRIBE_TRACKS => {
                Self::SubscribeTracks(prefix_request(&mut r, allowed::subscribe_tracks())?)
            }
            NAMESPACE => {
                let suffix = r.namespace()?;
                let params = if version.paused_parameter() {
                    let count = r.vi64()?;
                    Params::decode(&mut r, count, version, &allowed::none())?
                } else {
                    Params::default()
                };
                Self::Namespace { suffix, params }
            }
            NAMESPACE_DONE => Self::NamespaceDone {
                suffix: r.namespace()?,
            },
            PUBLISH_SKIPPED => {
                let suffix = r.namespace()?;
                let name = Bytes::copy_from_slice(r.prefixed()?);
                if name.is_empty() {
                    return fail(C::ProtocolViolation, "a Track Name of length 0");
                }
                Self::PublishSkipped { suffix, name }
            }
            REQUEST_UPDATE => {
                let request_id = r.vi64()?;
                let count = r.vi64()?;
                let params = Params::decode(&mut r, count, version, &ctx.update_allows)?;
                Self::RequestUpdate { request_id, params }
            }
            REQUEST_OK => {
                let count = r.vi64()?;
                let params = Params::decode(&mut r, count, version, &ctx.ok_allows)?;
                let properties = properties(&mut r)?;
                if !ctx.ok_properties && !properties.is_empty() {
                    return fail(
                        C::InvalidField,
                        "Track Properties in an OK that carries none",
                    );
                }
                Self::RequestOk { params, properties }
            }
            REQUEST_ERROR => {
                let code = r.vi64()?;
                let retry_interval = r.vi64()?;
                let reason = r.reason()?;
                let details = if version.error_details() {
                    r.kvps_to_end()?
                } else if code == super::error::RequestCode::Redirect as u64 {
                    vec![Kvp {
                        kind: 0x01,
                        value: super::codec::KvpValue::Bytes(Bytes::copy_from_slice(r.rest())),
                    }]
                } else {
                    Vec::new()
                };
                if version.error_details()
                    && code == super::error::RequestCode::Redirect as u64
                    && !details.iter().any(|d| d.kind == 0x01)
                {
                    return fail(C::MalformedMessage, "REDIRECT without its Error Detail");
                }
                Self::RequestError(RequestError {
                    code,
                    retry_interval,
                    reason,
                    details,
                })
            }
            _ => return fail(C::UnexpectedMessage, "an unknown control message type"),
        };
        if !r.is_empty() {
            return fail(
                C::MalformedMessage,
                "a control message longer than its contents",
            );
        }
        Ok(msg)
    }

    /// Encode the message's body (not its type or length).
    pub fn encode_body(&self, version: Version) -> Vec<u8> {
        let mut out = Vec::new();
        let o = &mut out;
        match self {
            Self::Setup(s) => return s.encode(version),
            Self::Goaway { uri, timeout_ms } => {
                put_prefixed(o, uri);
                put_vi64(o, *timeout_ms);
            }
            Self::Subscribe(t) | Self::Fetch(t) | Self::TrackStatus(t) => {
                put_vi64(o, t.request_id);
                t.track.namespace.encode(o);
                put_prefixed(o, &t.track.name);
                t.params.encode(o, version);
            }
            Self::SubscribeOk {
                track_alias,
                params,
                properties,
            } => {
                put_vi64(o, *track_alias);
                params.encode(o, version);
                o.extend_from_slice(properties);
            }
            Self::PublishStateNotify(p) => p.encode(o, version),
            Self::Publish(p) => {
                put_vi64(o, p.request_id);
                p.track.namespace.encode(o);
                put_prefixed(o, &p.track.name);
                put_vi64(o, p.track_alias);
                p.params.encode(o, version);
                o.extend_from_slice(&p.properties);
            }
            Self::PublishDone {
                status,
                stream_count,
                reason,
            } => {
                put_vi64(o, *status);
                put_vi64(o, *stream_count);
                put_reason(o, reason);
            }
            Self::FetchOk22 {
                end_of_track,
                end,
                params,
                properties,
            } => {
                o.push(u8::from(*end_of_track));
                end.encode(o);
                params.encode(o, version);
                o.extend_from_slice(properties);
            }
            Self::PublishNamespace(p) | Self::SubscribeNamespace(p) | Self::SubscribeTracks(p) => {
                put_vi64(o, p.request_id);
                p.prefix.encode(o);
                p.params.encode(o, version);
            }
            Self::Namespace { suffix, params } => {
                suffix.encode(o);
                if version.paused_parameter() {
                    params.encode(o, version);
                }
            }
            Self::NamespaceDone { suffix } => suffix.encode(o),
            Self::PublishSkipped { suffix, name } => {
                suffix.encode(o);
                put_prefixed(o, name);
            }
            Self::RequestUpdate { request_id, params } => {
                put_vi64(o, *request_id);
                params.encode(o, version);
            }
            Self::RequestOk { params, properties } => {
                params.encode(o, version);
                o.extend_from_slice(properties);
            }
            Self::RequestError(e) => {
                put_vi64(o, e.code);
                put_vi64(o, e.retry_interval);
                put_reason(o, &e.reason);
                if version.error_details() {
                    put_kvps(o, &e.details);
                } else if let Some(Kvp {
                    value: super::codec::KvpValue::Bytes(b),
                    ..
                }) = e.details.iter().find(|d| d.kind == 0x01)
                {
                    if e.code == super::error::RequestCode::Redirect as u64 {
                        o.extend_from_slice(b);
                    }
                }
            }
        }
        out
    }

    /// The message framed for the wire: type, length, body.
    pub fn encode(&self, version: Version) -> Vec<u8> {
        let body = self.encode_body(version);
        let mut out = Vec::with_capacity(body.len() + 12);
        put_vi64(&mut out, self.kind());
        if version.varint_message_length() {
            put_vi64(&mut out, body.len() as u64);
        } else {
            let len = u16::try_from(body.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_be_bytes());
        }
        out.extend_from_slice(&body);
        out
    }
}

/// Track Properties: the rest of the message, parsed to check they are
/// well-formed Key-Value-Pairs and kept as sent (a relay forwards them
/// unchanged, section 8.4).
fn properties(r: &mut Reader<'_>) -> SessionResult<Bytes> {
    let raw = r.rest();
    Reader::new(raw, C::MalformedKeyValue).kvps_to_end()?;
    Ok(Bytes::copy_from_slice(raw))
}

/// Read one framed message's type and body from a stream; `None` at a clean
/// end of stream before the type. `limit` is this endpoint's
/// MAX_CONTROL_MESSAGE_SIZE.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    version: Version,
    limit: u64,
) -> Result<Option<(u64, Vec<u8>)>, FrameError> {
    let Some(kind) = read_vi64(r).await? else {
        return Ok(None);
    };
    let len = if version.varint_message_length() {
        read_vi64(r).await?.ok_or_else(|| {
            FrameError::Session(SessionError::new(
                C::MalformedMessage,
                "a stream ended inside a message header",
            ))
        })?
    } else {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await?;
        u64::from(u16::from_be_bytes(b))
    };
    if len > limit {
        return Err(FrameError::Session(SessionError::new(
            C::FieldLengthExceeded,
            "a control message longer than MAX_CONTROL_MESSAGE_SIZE",
        )));
    }
    let len = usize::try_from(len).map_err(|_| {
        FrameError::Session(SessionError::new(
            C::FieldLengthExceeded,
            "a control message longer than this host can hold",
        ))
    })?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some((kind, body)))
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    Session(SessionError),
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(m: &Message, version: Version, ctx: &Context) -> Message {
        let wire = m.encode(version);
        let mut r = Reader::new(&wire, C::MalformedMessage);
        let kind = r.vi64().unwrap();
        let len = if version.varint_message_length() {
            r.vi64().unwrap()
        } else {
            u64::from(r.u16().unwrap())
        };
        let body = r.bytes(usize::try_from(len).unwrap()).unwrap();
        assert!(r.is_empty());
        Message::decode(kind, body, version, ctx).unwrap()
    }

    fn track() -> TrackName {
        TrackName {
            namespace: Namespace(vec![
                Bytes::from_static(b"music"),
                Bytes::from_static(b"radio"),
            ]),
            name: Bytes::from_static(b"audio"),
        }
    }

    #[test]
    fn subscribe_round_trips_in_both_drafts() {
        for v in Version::ALL {
            let params = Params {
                subscriber_priority: Some(10),
                paused: Some(false),
                location_filter: Some(LocationFilter::AbsoluteRange {
                    start: Location::new(5, 1),
                    end: Location::new(9, 3),
                }),
                group_order: Some(GroupOrder::Descending),
                fill: Some(Box::new(Params {
                    location_filter: Some(LocationFilter::RelativeStart { start_group: 1 }),
                    ..Params::default()
                })),
                auth_tokens: vec![Token::UseValue {
                    kind: 7,
                    value: Bytes::from_static(b"tok"),
                }],
                ..Params::default()
            };
            let m = Message::Subscribe(TrackRequest {
                request_id: 4,
                track: track(),
                params,
            });
            assert_eq!(round_trip(&m, v, &Context::default()), m, "{v}");
        }
    }

    /// Mutants of real messages, in both drafts: nothing panics, and what
    /// decodes re-encodes to itself (crate::moq::check).
    #[test]
    fn mutated_messages_neither_panic_nor_change_on_re_encoding() {
        for (vi, v) in Version::ALL.iter().enumerate() {
            let params = Params {
                subscriber_priority: Some(3),
                location_filter: Some(LocationFilter::AbsoluteGroupEnd {
                    start: Location::new(2, 1),
                    end_group: 9,
                }),
                fill: Some(Box::new(Params {
                    fill_timeout: Some(40),
                    ..Params::default()
                })),
                range_filters: vec![RangeFilter {
                    kind: P_OBJECTID_FILTER,
                    set_id: 1,
                    property: None,
                    ranges: vec![(1, Some(4)), (9, None)],
                }],
                ..Params::default()
            };
            let seeds = [
                (
                    2u8,
                    Message::Subscribe(TrackRequest {
                        request_id: 2,
                        track: track(),
                        params,
                    }),
                ),
                (
                    18,
                    Message::RequestError(RequestError {
                        code: 0x10,
                        retry_interval: 5,
                        reason: "gone".into(),
                        details: Vec::new(),
                    }),
                ),
                (
                    0,
                    Message::Setup(Setup {
                        implementation: Some("x".into()),
                        max_request_updates: 2,
                        ..Setup::default()
                    }),
                ),
            ];
            for (type_index, m) in seeds {
                let mut seed = vec![u8::try_from(vi).unwrap(), type_index];
                seed.extend(m.encode_body(*v));
                crate::fuzz_support::fuzz_bytes(&seed, 20_000, crate::moq::check::control);
            }
        }
    }

    #[test]
    fn the_pause_parameter_differs_by_draft() {
        let p = Params {
            paused: Some(true),
            ..Params::default()
        };
        let mut d23 = Vec::new();
        p.encode(&mut d23, Version::Draft23);
        assert_eq!(d23, [1, 0x11, 1]);
        let mut d22 = Vec::new();
        p.encode(&mut d22, Version::Draft22);
        assert_eq!(d22, [1, 0x10, 0]);
    }

    #[test]
    fn a_parameter_the_message_does_not_allow_is_invalid() {
        let p = Params {
            expires: Some(5),
            ..Params::default()
        };
        let m = Message::Subscribe(TrackRequest {
            request_id: 0,
            track: track(),
            params: p,
        });
        let wire = m.encode_body(Version::Draft23);
        let err =
            Message::decode(SUBSCRIBE, &wire, Version::Draft23, &Context::default()).unwrap_err();
        assert_eq!(err.code, C::InvalidParameter);
    }

    #[test]
    fn a_length_longer_than_the_contents_is_malformed() {
        let m = Message::PublishDone {
            status: 2,
            stream_count: 3,
            reason: "done".into(),
        };
        let mut body = m.encode_body(Version::Draft23);
        body.push(0);
        let err = Message::decode(PUBLISH_DONE, &body, Version::Draft23, &Context::default())
            .unwrap_err();
        assert_eq!(err.code, C::MalformedMessage);
        assert_eq!(err.code.code(Version::Draft22), 0x3);
    }

    #[test]
    fn unknown_message_types_are_unexpected() {
        let err = Message::decode(0x7777, &[], Version::Draft23, &Context::default()).unwrap_err();
        assert_eq!(err.code, C::UnexpectedMessage);
        // FETCH_OK is draft 22's, reserved in 23
        let err =
            Message::decode(FETCH_OK_22, &[], Version::Draft23, &Context::default()).unwrap_err();
        assert_eq!(err.code, C::UnexpectedMessage);
    }

    #[test]
    fn range_filters_report_their_own_errors() {
        let p = Params {
            range_filters: vec![RangeFilter {
                kind: P_PRIORITY_FILTER,
                set_id: 0,
                property: None,
                ranges: vec![(10, Some(300))],
            }],
            ..Params::default()
        };
        let m = Message::Fetch(TrackRequest {
            request_id: 0,
            track: track(),
            params: p,
        });
        let back = round_trip(&m, Version::Draft23, &Context::default());
        let Message::Fetch(t) = back else { panic!() };
        assert!(t.params.filter_error.is_some());
        assert!(t.params.range_filters[0].admits(10));
        assert!(!t.params.range_filters[0].admits(9));
    }

    #[test]
    fn setup_keeps_unknown_options_and_reads_known_ones() {
        let s = Setup {
            implementation: Some("pqcrypta-proxy test".into()),
            max_request_updates: 4,
            max_control_message_size: 1 << 20,
            path: Some(Bytes::from_static(b"/moq")),
            ..Setup::default()
        };
        let mut body = s.encode(Version::Draft23);
        // A grease option (odd, bytes) after the known ones
        put_vi64(&mut body, 0x9D + 0x7F * 2 - 0x09);
        put_prefixed(&mut body, b"grease");
        let back = Setup::decode(&body, Version::Draft23).unwrap();
        assert_eq!(back.implementation.as_deref(), Some("pqcrypta-proxy test"));
        assert_eq!(back.max_request_updates, 4);
        assert_eq!(back.max_control_message_size, 1 << 20);
        assert_eq!(back.path.as_deref(), Some(&b"/moq"[..]));
        assert_eq!(back.options.len(), 5);
    }

    #[test]
    fn request_error_carries_its_redirect_in_both_drafts() {
        for v in Version::ALL {
            let mut detail = Vec::new();
            put_prefixed(&mut detail, b"");
            Namespace(vec![Bytes::from_static(b"x")]).encode(&mut detail);
            put_prefixed(&mut detail, b"y");
            let e = Message::RequestError(RequestError {
                code: super::super::error::RequestCode::Redirect as u64,
                retry_interval: 0,
                reason: "moved".into(),
                details: vec![Kvp {
                    kind: 1,
                    value: super::super::codec::KvpValue::Bytes(Bytes::from(detail)),
                }],
            });
            assert_eq!(round_trip(&e, v, &Context::default()), e, "{v}");
        }
    }
}
