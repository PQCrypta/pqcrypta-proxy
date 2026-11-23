//! MOQT data streams and datagrams (draft-ietf-moq-transport section 11).
//!
//! Subgroup streams and OBJECT_DATAGRAM are the same in drafts 22 and 23 but
//! for the codes their errors close the session with ([`super::error`]).
//! FETCH streams differ: draft 23 delta encodes End of Range indicators, adds
//! 2 to an Object ID Delta within a group, and adds the Gone range and the
//! End of Group and End of Track indicators.

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::codec::{put_vi64, read_u8, read_vi64, Location, Reader};
use super::error::{fail, SessionCode as C, SessionError, SessionResult};
use super::message::GroupOrder;
use super::version::Version;

/// Unidirectional stream types (section 6.4.1)
pub const STREAM_FETCH_HEADER: u64 = 0x05;
pub const STREAM_PADDING: u64 = 0x132B_3E28;
pub const DATAGRAM_PADDING: u64 = 0x132B_3E29;

/// Object Status (section 11.1.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum ObjectStatus {
    Normal,
    EndOfGroup,
    EndOfTrack,
}

impl ObjectStatus {
    pub fn from_wire(v: u64) -> SessionResult<Self> {
        match v {
            0x0 => Ok(Self::Normal),
            0x3 => Ok(Self::EndOfGroup),
            0x4 => Ok(Self::EndOfTrack),
            _ => fail(C::InvalidObjectStatus, "an unknown Object Status"),
        }
    }

    pub const fn wire(self) -> u64 {
        match self {
            Self::Normal => 0x0,
            Self::EndOfGroup => 0x3,
            Self::EndOfTrack => 0x4,
        }
    }
}

/// How an object was first sent (section 2.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    Subgroup(u64),
    Datagram,
}

/// One object as the relay holds it. Its payload and properties are kept as
/// received: a relay forwards both unchanged (section 7.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub location: Location,
    pub delivery: Delivery,
    pub priority: u8,
    pub status: ObjectStatus,
    /// Object Properties: Key-Value-Pairs, without their length
    pub properties: Bytes,
    pub payload: Bytes,
}

impl Object {
    /// Bytes this object holds in a cache.
    pub fn size(&self) -> usize {
        self.payload.len() + self.properties.len() + 48
    }
}

/// Check Object Properties are well-formed Key-Value-Pairs; a supported
/// Property that cannot be parsed makes the track malformed, which for the
/// session reading them is MALFORMED_OBJECT.
fn check_properties(raw: &[u8]) -> SessionResult<()> {
    Reader::new(raw, C::MalformedObject)
        .kvps_to_end()
        .map(|_| ())
}

// ── Subgroup streams (section 11.3) ─────────────────────────────────────────

/// SUBGROUP_HEADER Type Flags
pub const SG_PROPERTIES: u8 = 0x01;
pub const SG_ID_MODE_MASK: u8 = 0x06;
pub const SG_END_OF_GROUP: u8 = 0x08;
pub const SG_TYPE_BIT: u8 = 0x10;
pub const SG_DEFAULT_PRIORITY: u8 = 0x20;
pub const SG_FIRST_OBJECT: u8 = 0x40;

/// Whether a unidirectional stream type is a SUBGROUP_HEADER (0b0XX1XXXX).
pub const fn is_subgroup_type(t: u64) -> bool {
    t < 0x80 && t & SG_TYPE_BIT as u64 != 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubgroupIdMode {
    Zero,
    FirstObjectId,
    Explicit(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubgroupHeader {
    pub track_alias: u64,
    pub group: u64,
    pub subgroup: SubgroupIdMode,
    /// `None`: the subscription's publisher priority (DEFAULT_PRIORITY)
    pub priority: Option<u8>,
    pub properties: bool,
    pub end_of_group: bool,
    pub first_object: bool,
}

impl SubgroupHeader {
    /// Read the rest of the header after its type `flags`.
    pub async fn read<R: AsyncRead + Unpin>(flags: u64, r: &mut R) -> Result<Self, DataError> {
        let flags = match u8::try_from(flags) {
            Ok(f) if is_subgroup_type(flags) && (f & SG_ID_MODE_MASK) >> 1 != 0b11 => f,
            _ => {
                return Err(DataError::session(
                    C::InvalidStreamHeader,
                    "invalid SUBGROUP_HEADER Type Flags",
                ))
            }
        };
        let track_alias = need(read_vi64(r).await?)?;
        let group = need(read_vi64(r).await?)?;
        let subgroup = match (flags & SG_ID_MODE_MASK) >> 1 {
            0b00 => SubgroupIdMode::Zero,
            0b01 => SubgroupIdMode::FirstObjectId,
            _ => SubgroupIdMode::Explicit(need(read_vi64(r).await?)?),
        };
        let priority = if flags & SG_DEFAULT_PRIORITY != 0 {
            None
        } else {
            Some(read_u8(r).await?)
        };
        Ok(Self {
            track_alias,
            group,
            subgroup,
            priority,
            properties: flags & SG_PROPERTIES != 0,
            end_of_group: flags & SG_END_OF_GROUP != 0,
            first_object: flags & SG_FIRST_OBJECT != 0,
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        let mut flags = SG_TYPE_BIT;
        if self.properties {
            flags |= SG_PROPERTIES;
        }
        flags |= match self.subgroup {
            SubgroupIdMode::Zero => 0,
            SubgroupIdMode::FirstObjectId => 0b01 << 1,
            SubgroupIdMode::Explicit(_) => 0b10 << 1,
        };
        if self.end_of_group {
            flags |= SG_END_OF_GROUP;
        }
        if self.priority.is_none() {
            flags |= SG_DEFAULT_PRIORITY;
        }
        if self.first_object {
            flags |= SG_FIRST_OBJECT;
        }
        put_vi64(out, u64::from(flags));
        put_vi64(out, self.track_alias);
        put_vi64(out, self.group);
        if let SubgroupIdMode::Explicit(id) = self.subgroup {
            put_vi64(out, id);
        }
        if let Some(p) = self.priority {
            out.push(p);
        }
    }
}

/// One object read from a subgroup stream: its ID, status, properties and
/// payload; `None` at the stream's FIN between objects.
pub async fn read_subgroup_object<R: AsyncRead + Unpin>(
    r: &mut R,
    header: &SubgroupHeader,
    prior: Option<u64>,
    max_payload: usize,
) -> Result<Option<(u64, ObjectStatus, Bytes, Bytes)>, DataError> {
    let Some(delta) = read_vi64(r).await.map_err(truncated)? else {
        return Ok(None);
    };
    let id = match prior {
        None => delta,
        Some(p) => p
            .checked_add(delta)
            .and_then(|v| v.checked_add(1))
            .ok_or_else(|| {
                DataError::session(C::DeltaEncodingOverflow, "an Object ID past 2^64 - 1")
            })?,
    };
    let properties = if header.properties {
        let len = need(read_vi64(r).await.map_err(truncated)?)?;
        let raw = read_bytes(r, len, max_payload).await?;
        check_properties(&raw).map_err(DataError::Session)?;
        raw
    } else {
        Bytes::new()
    };
    let len = need(read_vi64(r).await.map_err(truncated)?)?;
    let (status, payload) = if len == 0 {
        let status = ObjectStatus::from_wire(need(read_vi64(r).await.map_err(truncated)?)?)
            .map_err(DataError::Session)?;
        (status, Bytes::new())
    } else {
        (ObjectStatus::Normal, read_bytes(r, len, max_payload).await?)
    };
    if status != ObjectStatus::Normal && !properties.is_empty() {
        return Err(DataError::session(
            C::InvalidObjectStatus,
            "Properties on an Object that is not Normal",
        ));
    }
    Ok(Some((id, status, properties, payload)))
}

/// Encode one object on a subgroup stream.
pub fn encode_subgroup_object(
    out: &mut Vec<u8>,
    prior: Option<u64>,
    object: &Object,
    with_properties: bool,
) {
    let id = object.location.object;
    put_vi64(out, prior.map_or(id, |p| id - p - 1));
    if with_properties {
        put_vi64(out, object.properties.len() as u64);
        out.extend_from_slice(&object.properties);
    }
    if object.status == ObjectStatus::Normal && !object.payload.is_empty() {
        put_vi64(out, object.payload.len() as u64);
        out.extend_from_slice(&object.payload);
    } else {
        put_vi64(out, 0);
        put_vi64(out, object.status.wire());
    }
}

// ── Datagrams (section 11.2) ────────────────────────────────────────────────

pub const DG_PROPERTIES: u64 = 0x01;
pub const DG_END_OF_GROUP: u64 = 0x02;
pub const DG_ZERO_OBJECT_ID: u64 = 0x04;
pub const DG_DEFAULT_PRIORITY: u64 = 0x08;
pub const DG_STATUS: u64 = 0x20;
const DG_DEFINED: u64 =
    DG_PROPERTIES | DG_END_OF_GROUP | DG_ZERO_OBJECT_ID | DG_DEFAULT_PRIORITY | DG_STATUS;

/// An OBJECT_DATAGRAM, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub track_alias: u64,
    pub group: u64,
    pub object: u64,
    pub priority: Option<u8>,
    pub end_of_group: bool,
    pub status: ObjectStatus,
    pub properties: Bytes,
    pub payload: Bytes,
}

/// What one datagram is.
#[derive(Debug, PartialEq, Eq)]
pub enum DatagramKind {
    Object(Datagram),
    Padding,
}

pub fn decode_datagram(bytes: &[u8]) -> SessionResult<DatagramKind> {
    let mut r = Reader::new(bytes, C::MalformedObject);
    let flags = r.vi64()?;
    if flags == DATAGRAM_PADDING {
        return Ok(DatagramKind::Padding);
    }
    if flags & !DG_DEFINED != 0 || (flags & DG_STATUS != 0 && flags & DG_END_OF_GROUP != 0) {
        return fail(C::InvalidStreamHeader, "invalid OBJECT_DATAGRAM Type Flags");
    }
    let track_alias = r.vi64()?;
    let group = r.vi64()?;
    let object = if flags & DG_ZERO_OBJECT_ID != 0 {
        0
    } else {
        r.vi64()?
    };
    let priority = if flags & DG_DEFAULT_PRIORITY != 0 {
        None
    } else {
        Some(r.u8()?)
    };
    let properties = if flags & DG_PROPERTIES != 0 {
        let raw = r.prefixed()?;
        if raw.is_empty() {
            return fail(
                C::MalformedObject,
                "the PROPERTIES bit with a Properties Length of 0",
            );
        }
        check_properties(raw)?;
        Bytes::copy_from_slice(raw)
    } else {
        Bytes::new()
    };
    let (status, payload) = if flags & DG_STATUS != 0 {
        let status = ObjectStatus::from_wire(r.vi64()?)?;
        if !r.is_empty() {
            return fail(C::MalformedObject, "a payload after an Object Status");
        }
        if status != ObjectStatus::Normal && !properties.is_empty() {
            return fail(
                C::InvalidObjectStatus,
                "Properties on an Object that is not Normal",
            );
        }
        (status, Bytes::new())
    } else {
        (ObjectStatus::Normal, Bytes::copy_from_slice(r.rest()))
    };
    Ok(DatagramKind::Object(Datagram {
        track_alias,
        group,
        object,
        priority,
        end_of_group: flags & DG_END_OF_GROUP != 0,
        status,
        properties,
        payload,
    }))
}

pub fn encode_datagram(
    track_alias: u64,
    object: &Object,
    default_priority: bool,
    end_of_group: bool,
) -> Vec<u8> {
    let mut flags = 0u64;
    if !object.properties.is_empty() {
        flags |= DG_PROPERTIES;
    }
    let status = object.status != ObjectStatus::Normal;
    if end_of_group && !status {
        flags |= DG_END_OF_GROUP;
    }
    if object.location.object == 0 {
        flags |= DG_ZERO_OBJECT_ID;
    }
    if default_priority {
        flags |= DG_DEFAULT_PRIORITY;
    }
    if status {
        flags |= DG_STATUS;
    }
    let mut out = Vec::with_capacity(object.payload.len() + 24);
    put_vi64(&mut out, flags);
    put_vi64(&mut out, track_alias);
    put_vi64(&mut out, object.location.group);
    if object.location.object != 0 {
        put_vi64(&mut out, object.location.object);
    }
    if !default_priority {
        out.push(object.priority);
    }
    if !object.properties.is_empty() {
        put_vi64(&mut out, object.properties.len() as u64);
        out.extend_from_slice(&object.properties);
    }
    if status {
        put_vi64(&mut out, object.status.wire());
    } else {
        out.extend_from_slice(&object.payload);
    }
    out
}

// ── FETCH streams (section 11.4) ────────────────────────────────────────────

const F_SUBGROUP_MASK: u64 = 0x03;
const F_OBJECT_DELTA: u64 = 0x04;
const F_GROUP_DELTA: u64 = 0x08;
const F_PRIORITY: u64 = 0x10;
const F_PROPERTIES: u64 = 0x20;
const F_DATAGRAM: u64 = 0x40;

/// The state of a range of objects a FETCH response does not serialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RangeKind {
    NonExistent,
    Unknown,
    TimedOut,
    /// Draft 23
    Gone,
}

impl RangeKind {
    const fn wire(self) -> u64 {
        match self {
            Self::NonExistent => 0x8C,
            Self::Unknown => 0x10C,
            Self::TimedOut => 0x20C,
            Self::Gone => 0x40C,
        }
    }
}

const END_OF_GROUP: u64 = 0x80;
const END_OF_TRACK: u64 = 0x81;

/// One entry on a FETCH stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchEntry {
    Object(Object),
    /// Every object after the prior entry up to and including `end`
    EndOfRange {
        kind: RangeKind,
        end: Location,
    },
    /// Draft 23: the prior object ended its group
    EndOfGroup,
    /// Draft 23: the prior object ended the track
    EndOfTrack,
}

/// The prior-entry state both directions of a FETCH stream keep.
#[derive(Debug, Clone, Default)]
pub struct FetchState {
    prior: Option<Location>,
    prior_subgroup: Option<u64>,
    prior_priority: Option<u8>,
}

impl FetchState {
    /// Encode one entry. Objects come in the response's group order and,
    /// within a group, in Object ID order (section 3.2.1).
    pub fn encode(
        &mut self,
        out: &mut Vec<u8>,
        entry: &FetchEntry,
        order: GroupOrder,
        version: Version,
    ) {
        let v23 = version.fetch_stream_v23();
        match entry {
            FetchEntry::Object(o) => {
                let loc = o.location;
                let mut flags = F_PRIORITY;
                let mut fields = Vec::new();
                let same_group = self
                    .prior
                    .is_some_and(|p| p.group == loc.group && p.object != u64::MAX);
                if !same_group {
                    flags |= F_GROUP_DELTA | F_OBJECT_DELTA;
                    let g = match self.prior {
                        None => loc.group,
                        Some(p) => loc.group.abs_diff(p.group).saturating_sub(1),
                    };
                    put_vi64(&mut fields, g);
                } else {
                    let p = self.prior.expect("same group").object;
                    if loc.object != p + 1 {
                        flags |= F_OBJECT_DELTA;
                    }
                }
                let mut sub = Vec::new();
                match o.delivery {
                    Delivery::Datagram => flags |= F_DATAGRAM,
                    Delivery::Subgroup(id) => {
                        if id == 0 {
                        } else if self.prior_subgroup == Some(id) {
                            flags |= 0x01;
                        } else if self.prior_subgroup.and_then(|s| s.checked_add(1)) == Some(id) {
                            flags |= 0x02;
                        } else {
                            flags |= 0x03;
                            put_vi64(&mut sub, id);
                        }
                    }
                }
                fields.extend_from_slice(&sub);
                if flags & F_OBJECT_DELTA != 0 {
                    let delta = if flags & F_GROUP_DELTA != 0 {
                        loc.object
                    } else {
                        let p = self.prior.expect("same group").object;
                        if v23 {
                            loc.object - p - 2
                        } else {
                            loc.object - p
                        }
                    };
                    put_vi64(&mut fields, delta);
                }
                fields.push(o.priority);
                if !o.properties.is_empty() {
                    flags |= F_PROPERTIES;
                    put_vi64(&mut fields, o.properties.len() as u64);
                    fields.extend_from_slice(&o.properties);
                }
                put_vi64(out, flags);
                out.extend_from_slice(&fields);
                put_vi64(out, o.payload.len() as u64);
                out.extend_from_slice(&o.payload);
                self.prior = Some(loc);
                if let Delivery::Subgroup(id) = o.delivery {
                    self.prior_subgroup = Some(id);
                }
                self.prior_priority = Some(o.priority);
                let _ = order;
            }
            FetchEntry::EndOfRange { kind, end } => {
                let kind = if !v23 && *kind == RangeKind::Gone {
                    RangeKind::Unknown
                } else {
                    *kind
                };
                put_vi64(out, kind.wire());
                match (v23, self.prior) {
                    (true, Some(p)) => {
                        let gd = end.group.abs_diff(p.group);
                        put_vi64(out, gd);
                        if gd == 0 {
                            put_vi64(out, end.object - p.object - 1);
                        } else {
                            put_vi64(out, end.object);
                        }
                    }
                    _ => end.encode(out),
                }
                self.prior = Some(*end);
            }
            FetchEntry::EndOfGroup | FetchEntry::EndOfTrack => {
                if v23 {
                    put_vi64(
                        out,
                        if *entry == FetchEntry::EndOfGroup {
                            END_OF_GROUP
                        } else {
                            END_OF_TRACK
                        },
                    );
                    if let Some(p) = &mut self.prior {
                        p.object = u64::MAX;
                    }
                }
            }
        }
    }

    /// Read one entry; `None` at the stream's FIN between entries.
    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
        order: GroupOrder,
        version: Version,
        max_payload: usize,
    ) -> Result<Option<FetchEntry>, DataError> {
        let v23 = version.fetch_stream_v23();
        let Some(flags) = read_vi64(r).await.map_err(truncated)? else {
            return Ok(None);
        };
        let malformed = |why| DataError::session(C::MalformedObject, why);
        let overflow =
            || DataError::session(C::DeltaEncodingOverflow, "a FETCH Location past its bounds");
        let step = |base: u64, by: u64| -> Result<u64, DataError> {
            match order {
                GroupOrder::Ascending => base.checked_add(by),
                GroupOrder::Descending => base.checked_sub(by),
            }
            .ok_or_else(overflow)
        };
        if flags >= 0x80 {
            let kind = match flags {
                0x8C => Some(RangeKind::NonExistent),
                0x10C => Some(RangeKind::Unknown),
                0x20C => Some(RangeKind::TimedOut),
                0x40C if v23 => Some(RangeKind::Gone),
                END_OF_GROUP | END_OF_TRACK if v23 => None,
                _ => return Err(malformed("an unknown FETCH Serialization Flags indicator")),
            };
            let Some(kind) = kind else {
                let Some(p) = &mut self.prior else {
                    return Err(malformed("End of Group or Track with no prior Object"));
                };
                p.object = u64::MAX;
                return Ok(Some(if flags == END_OF_GROUP {
                    FetchEntry::EndOfGroup
                } else {
                    FetchEntry::EndOfTrack
                }));
            };
            let a = need(read_vi64(r).await.map_err(truncated)?)?;
            let b = need(read_vi64(r).await.map_err(truncated)?)?;
            let end = match (v23, self.prior) {
                (true, Some(p)) => {
                    let group = step(p.group, a)?;
                    let object = if a == 0 {
                        p.object
                            .checked_add(b)
                            .and_then(|v| v.checked_add(1))
                            .ok_or_else(overflow)?
                    } else {
                        b
                    };
                    Location::new(group, object)
                }
                _ => Location::new(a, b),
            };
            self.prior = Some(end);
            return Ok(Some(FetchEntry::EndOfRange { kind, end }));
        }
        let first = self.prior.is_none();
        let datagram = flags & F_DATAGRAM != 0;
        let sub_mode = flags & F_SUBGROUP_MASK;
        if first
            && (flags & F_GROUP_DELTA == 0
                || flags & F_OBJECT_DELTA == 0
                || flags & F_PRIORITY == 0
                || (!datagram && (sub_mode == 1 || sub_mode == 2)))
        {
            return Err(malformed("the first FETCH Object refers to a prior Object"));
        }
        let group_delta = if flags & F_GROUP_DELTA != 0 {
            Some(need(read_vi64(r).await.map_err(truncated)?)?)
        } else {
            None
        };
        let subgroup = if datagram {
            None
        } else {
            Some(match sub_mode {
                0 => 0,
                1 => self
                    .prior_subgroup
                    .ok_or_else(|| malformed("a prior Subgroup ID with no prior Object"))?,
                2 => self
                    .prior_subgroup
                    .ok_or_else(|| malformed("a prior Subgroup ID with no prior Object"))?
                    .checked_add(1)
                    .ok_or_else(overflow)?,
                _ => need(read_vi64(r).await.map_err(truncated)?)?,
            })
        };
        let object_delta = if flags & F_OBJECT_DELTA != 0 {
            Some(need(read_vi64(r).await.map_err(truncated)?)?)
        } else {
            None
        };
        let location = match self.prior {
            None => Location::new(
                group_delta.expect("checked"),
                object_delta.expect("checked"),
            ),
            Some(p) => {
                let group = match group_delta {
                    Some(d) => step(p.group, d.checked_add(1).ok_or_else(overflow)?)?,
                    None => p.group,
                };
                let object = match (group_delta, object_delta) {
                    (Some(_), Some(o)) => o,
                    (None, Some(o)) => {
                        let extra = if v23 { 2 } else { 0 };
                        p.object
                            .checked_add(o)
                            .and_then(|v| v.checked_add(extra))
                            .ok_or_else(overflow)?
                    }
                    (_, None) => p.object.checked_add(1).ok_or_else(overflow)?,
                };
                Location::new(group, object)
            }
        };
        let priority = if flags & F_PRIORITY != 0 {
            read_u8(r).await.map_err(truncated)?
        } else {
            self.prior_priority
                .ok_or_else(|| malformed("a prior Priority with no prior Object"))?
        };
        let properties = if flags & F_PROPERTIES != 0 {
            let len = need(read_vi64(r).await.map_err(truncated)?)?;
            let raw = read_bytes(r, len, max_payload).await?;
            check_properties(&raw).map_err(DataError::Session)?;
            raw
        } else {
            Bytes::new()
        };
        let len = need(read_vi64(r).await.map_err(truncated)?)?;
        let payload = read_bytes(r, len, max_payload).await?;
        self.prior = Some(location);
        if let Some(s) = subgroup {
            self.prior_subgroup = Some(s);
        }
        self.prior_priority = Some(priority);
        Ok(Some(FetchEntry::Object(Object {
            location,
            delivery: subgroup.map_or(Delivery::Datagram, Delivery::Subgroup),
            priority,
            status: ObjectStatus::Normal,
            properties,
            payload,
        })))
    }
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Why a data stream could not be read.
#[derive(Debug)]
pub enum DataError {
    /// The stream ended or was reset
    Io(std::io::Error),
    /// A protocol error: the session closes
    Session(SessionError),
    /// An object larger than this relay holds: the stream is refused
    TooLarge,
}

impl DataError {
    fn session(code: C, why: &'static str) -> Self {
        Self::Session(SessionError::new(code, why))
    }
}

impl From<std::io::Error> for DataError {
    fn from(e: std::io::Error) -> Self {
        // A FIN in the middle of an object (section 11.3)
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Self::session(C::TruncatedObject, "a data stream ended inside an object");
        }
        Self::Io(e)
    }
}

fn truncated(e: std::io::Error) -> DataError {
    DataError::from(e)
}

fn need(v: Option<u64>) -> Result<u64, DataError> {
    v.ok_or_else(|| DataError::session(C::TruncatedObject, "a data stream ended inside an object"))
}

async fn read_bytes<R: AsyncRead + Unpin>(
    r: &mut R,
    len: u64,
    max: usize,
) -> Result<Bytes, DataError> {
    let len = usize::try_from(len).map_err(|_| DataError::TooLarge)?;
    if len > max {
        return Err(DataError::TooLarge);
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(g: u64, o: u64, sub: u64, payload: &'static [u8]) -> Object {
        Object {
            location: Location::new(g, o),
            delivery: Delivery::Subgroup(sub),
            priority: 7,
            status: ObjectStatus::Normal,
            properties: Bytes::new(),
            payload: Bytes::from_static(payload),
        }
    }

    #[tokio::test]
    async fn subgroup_streams_round_trip() {
        let header = SubgroupHeader {
            track_alias: 3,
            group: 9,
            subgroup: SubgroupIdMode::Explicit(2),
            priority: Some(5),
            properties: true,
            end_of_group: true,
            first_object: true,
        };
        let mut wire = Vec::new();
        header.encode(&mut wire);
        let objects = [obj(9, 0, 2, b"a"), obj(9, 1, 2, b"bc"), obj(9, 4, 2, b"")];
        let mut prior = None;
        for o in &objects {
            encode_subgroup_object(&mut wire, prior, o, true);
            prior = Some(o.location.object);
        }
        let mut r = &wire[..];
        let t = read_vi64(&mut r).await.unwrap().unwrap();
        let back = SubgroupHeader::read(t, &mut r).await.unwrap();
        assert_eq!(back, header);
        let mut prior = None;
        for o in &objects {
            let (id, status, _p, payload) = read_subgroup_object(&mut r, &back, prior, 1 << 20)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(id, o.location.object);
            assert_eq!(status, ObjectStatus::Normal);
            assert_eq!(payload, o.payload);
            prior = Some(id);
        }
        assert!(read_subgroup_object(&mut r, &back, prior, 1 << 20)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn invalid_subgroup_flags_are_refused() {
        for flags in [0x00u64, 0x16, 0x80, 0x0F] {
            let mut r = &[0u8; 8][..];
            match SubgroupHeader::read(flags, &mut r).await {
                Err(DataError::Session(e)) => {
                    assert_eq!(e.code, C::InvalidStreamHeader, "{flags:#x}");
                }
                other => panic!("{flags:#x}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_fin_inside_an_object_is_truncation() {
        let header = SubgroupHeader {
            track_alias: 1,
            group: 0,
            subgroup: SubgroupIdMode::Zero,
            priority: None,
            properties: false,
            end_of_group: false,
            first_object: true,
        };
        let mut wire = Vec::new();
        put_vi64(&mut wire, 0);
        put_vi64(&mut wire, 10);
        wire.extend_from_slice(b"short");
        let mut r = &wire[..];
        match read_subgroup_object(&mut r, &header, None, 1 << 20).await {
            Err(DataError::Session(e)) => assert_eq!(e.code, C::TruncatedObject),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn datagrams_round_trip_and_reject_bad_flags() {
        let o = Object {
            delivery: Delivery::Datagram,
            ..obj(4, 0, 0, b"opus")
        };
        let wire = encode_datagram(6, &o, false, true);
        let DatagramKind::Object(d) = decode_datagram(&wire).unwrap() else {
            panic!()
        };
        assert_eq!(
            (d.track_alias, d.group, d.object, d.priority, d.end_of_group),
            (6, 4, 0, Some(7), true)
        );
        assert_eq!(d.payload, o.payload);
        for flags in [0x10u64, 0x22, 0x40] {
            let mut w = Vec::new();
            put_vi64(&mut w, flags);
            w.extend_from_slice(&[0; 8]);
            assert_eq!(
                decode_datagram(&w).unwrap_err().code,
                C::InvalidStreamHeader,
                "{flags:#x}"
            );
        }
        let mut pad = Vec::new();
        put_vi64(&mut pad, DATAGRAM_PADDING);
        pad.extend_from_slice(&[0; 4]);
        assert_eq!(decode_datagram(&pad).unwrap(), DatagramKind::Padding);
    }

    #[tokio::test]
    async fn fetch_streams_round_trip_in_both_drafts_and_orders() {
        for v in Version::ALL {
            for order in [GroupOrder::Ascending, GroupOrder::Descending] {
                let (g1, g2) = if order == GroupOrder::Ascending {
                    (3, 6)
                } else {
                    (6, 3)
                };
                let mut entries = vec![
                    FetchEntry::Object(obj(g1, 0, 0, b"x")),
                    FetchEntry::Object(obj(g1, 1, 0, b"y")),
                    FetchEntry::Object(obj(g1, 5, 1, b"z")),
                    FetchEntry::EndOfRange {
                        kind: RangeKind::Unknown,
                        end: Location::new(g1, 9),
                    },
                    FetchEntry::Object(obj(g2, 2, 4, b"w")),
                ];
                if v.fetch_stream_v23() {
                    entries.push(FetchEntry::EndOfGroup);
                }
                let mut wire = Vec::new();
                let mut enc = FetchState::default();
                for e in &entries {
                    enc.encode(&mut wire, e, order, v);
                }
                let mut r = &wire[..];
                let mut dec = FetchState::default();
                let mut back = Vec::new();
                while let Some(e) = dec.read(&mut r, order, v, 1 << 20).await.unwrap() {
                    back.push(e);
                }
                assert_eq!(back, entries, "{v} {order:?}");
            }
        }
    }

    /// Mutants of a subgroup stream, a datagram and a FETCH stream: none
    /// panics a reader (crate::moq::check).
    #[test]
    fn mutated_data_never_panics_a_reader() {
        let mut subgroup = vec![0u8, 0];
        SubgroupHeader {
            track_alias: 1,
            group: 3,
            subgroup: SubgroupIdMode::Explicit(2),
            priority: Some(9),
            properties: true,
            end_of_group: false,
            first_object: true,
        }
        .encode(&mut subgroup);
        encode_subgroup_object(&mut subgroup, None, &obj(3, 0, 2, b"ab"), true);
        encode_subgroup_object(&mut subgroup, Some(0), &obj(3, 4, 2, b"cd"), true);
        let mut fetch = vec![1u8, 0];
        let mut state = FetchState::default();
        for e in [
            FetchEntry::Object(obj(1, 0, 0, b"x")),
            FetchEntry::EndOfRange {
                kind: RangeKind::Gone,
                end: Location::new(1, 5),
            },
            FetchEntry::Object(obj(2, 1, 1, b"y")),
            FetchEntry::EndOfTrack,
        ] {
            state.encode(&mut fetch, &e, GroupOrder::Ascending, Version::Draft23);
        }
        let mut datagram = vec![0u8, 0];
        datagram.extend(encode_datagram(
            5,
            &Object {
                delivery: Delivery::Datagram,
                ..obj(7, 1, 0, b"opus")
            },
            false,
            true,
        ));
        for seed in [subgroup, fetch, datagram] {
            crate::fuzz_support::fuzz_bytes(&seed, 20_000, crate::moq::check::data);
        }
    }

    #[tokio::test]
    async fn a_first_fetch_object_cannot_refer_back() {
        let mut wire = Vec::new();
        put_vi64(
            &mut wire,
            F_GROUP_DELTA | F_OBJECT_DELTA | 0x01 | F_PRIORITY,
        );
        wire.extend_from_slice(&[0, 0, 0, 0]);
        let mut r = &wire[..];
        match FetchState::default()
            .read(&mut r, GroupOrder::Ascending, Version::Draft23, 1024)
            .await
        {
            Err(DataError::Session(e)) => assert_eq!(e.code, C::MalformedObject),
            other => panic!("{other:?}"),
        }
    }
}
