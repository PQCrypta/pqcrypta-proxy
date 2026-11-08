//! Server-side meter for speed-test uploads, shared by every transport: the
//! WebTransport streams of `/speedtest`, HTTP/1.1 and HTTP/2 over TCP, and
//! HTTP/3.
//!
//! A browser uploads over several parallel streams or connections. Timing each
//! one alone and adding up the rates reads high whenever they do not all run
//! for the same span, and a client counting what it handed to its own send
//! buffer measures what left the page, not what crossed the network. Instead,
//! every stream of one test adds what it receives here to one meter, named by
//! an id the client chose: bytes per fixed time bucket, counted as they arrive
//! at this process. The client reads the meter while the test runs (a live
//! figure) and after it (the result), and computes one rate over the whole
//! test from what this side received.
//!
//! Meters live for [`METER_TTL`] and are capped in number, overall and per
//! client address, so an idle or hostile client cannot grow the registry. An id
//! is 128 random bits chosen by the client; a meter holds byte counts and
//! timings only.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Width of one bucket.
pub const BUCKET_MS: u64 = 50;

/// Buckets kept per meter: 90 s, past the longest test the page runs.
const MAX_BUCKETS: usize = 1800;

/// How long a meter outlives its creation.
const METER_TTL: Duration = Duration::from_mins(3);

/// Meters held at once, across all clients.
const MAX_METERS: usize = 4096;

/// Meters one client address may hold at once.
const MAX_METERS_PER_ADDRESS: usize = 16;

struct MeterState {
    /// When the first byte of the test arrived; bucket 0 starts here.
    first: Option<Instant>,
    /// When the latest byte arrived.
    last: Option<Instant>,
    buckets: Vec<u64>,
    bytes: u64,
    /// Streams or requests that have carried data for this test.
    streams: u32,
    /// Of those, the ones still receiving.
    open: u32,
}

/// One test's upload, as this process received it.
pub struct Meter {
    created: Instant,
    owner: IpAddr,
    state: Mutex<MeterState>,
}

/// A stream's share of a meter; counts the stream as open while it lives.
pub struct MeterStream {
    meter: Arc<Meter>,
}

impl Meter {
    fn new(owner: IpAddr) -> Self {
        Self {
            created: Instant::now(),
            owner,
            state: Mutex::new(MeterState {
                first: None,
                last: None,
                buckets: Vec::new(),
                bytes: 0,
                streams: 0,
                open: 0,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MeterState> {
        // A panic while holding the lock leaves plain counters behind, which
        // are as valid as they were; keep metering.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count `n` bytes received now.
    pub fn record(&self, n: usize) {
        if n == 0 {
            return;
        }
        let now = Instant::now();
        let mut s = self.lock();
        let first = *s.first.get_or_insert(now);
        s.last = Some(now);
        s.bytes = s.bytes.saturating_add(n as u64);
        let index = usize::try_from(
            u64::try_from(now.duration_since(first).as_millis()).unwrap_or(u64::MAX) / BUCKET_MS,
        )
        .unwrap_or(usize::MAX);
        if index < MAX_BUCKETS {
            if s.buckets.len() <= index {
                s.buckets.resize(index + 1, 0);
            }
            s.buckets[index] = s.buckets[index].saturating_add(n as u64);
        }
    }

    /// What the meter holds, for the client.
    pub fn snapshot(&self, test: &str) -> Value {
        let s = self.lock();
        let span_ms = match (s.first, s.last) {
            (Some(f), Some(l)) => l.duration_since(f).as_secs_f64() * 1000.0,
            _ => 0.0,
        };
        // How long ago the first byte arrived: the client lines the buckets up
        // with its own clock from this, without the two clocks agreeing.
        let since_first_ms = s.first.map_or(0.0, |f| f.elapsed().as_secs_f64() * 1000.0);
        json!({
            "op": "meter",
            "test": test,
            "bucket_ms": BUCKET_MS,
            "buckets": s.buckets,
            "bytes": s.bytes,
            "span_ms": span_ms,
            "since_first_ms": since_first_ms,
            "streams": s.streams,
            "open": s.open,
        })
    }
}

impl MeterStream {
    /// Count `n` bytes received now on this stream.
    pub fn record(&self, n: usize) {
        self.meter.record(n);
    }
}

impl Drop for MeterStream {
    fn drop(&mut self) {
        let mut s = self.meter.lock();
        s.open = s.open.saturating_sub(1);
    }
}

static METERS: LazyLock<Mutex<HashMap<String, Arc<Meter>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry() -> std::sync::MutexGuard<'static, HashMap<String, Arc<Meter>>> {
    METERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A test id as the client must send it: 32 lowercase hex digits.
pub fn valid_test_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The `test` parameter of a query string, when it is a valid id.
pub fn test_id_from_query(query: Option<&str>) -> Option<String> {
    query?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == "test" && valid_test_id(v)).then(|| v.to_string())
    })
}

/// Open a stream on the meter for `test`, creating the meter on its first stream.
///
/// `None` when the id is invalid or the client (or the registry) is at its
/// cap: the upload still runs, unmetered, and the client is told so when it
/// asks for the meter.
pub fn open_stream(test: &str, client: IpAddr) -> Option<MeterStream> {
    if !valid_test_id(test) {
        return None;
    }
    let mut meters = registry();
    meters.retain(|_, m| m.created.elapsed() < METER_TTL);
    let meter = if let Some(m) = meters.get(test) {
        m.clone()
    } else {
        let held = meters.values().filter(|m| m.owner == client).count();
        if meters.len() >= MAX_METERS || held >= MAX_METERS_PER_ADDRESS {
            return None;
        }
        let m = Arc::new(Meter::new(client));
        meters.insert(test.to_string(), m.clone());
        m
    };
    drop(meters);
    {
        let mut s = meter.lock();
        s.streams = s.streams.saturating_add(1);
        s.open = s.open.saturating_add(1);
    }
    Some(MeterStream { meter })
}

/// The meter for `test`, if one is live.
pub fn snapshot(test: &str) -> Option<Value> {
    if !valid_test_id(test) {
        return None;
    }
    let meter = registry().get(test).cloned()?;
    (meter.created.elapsed() < METER_TTL).then(|| meter.snapshot(test))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn id(n: u8) -> String {
        format!("{:032x}", u128::from(n) + 0xabcd_0000)
    }

    #[test]
    fn streams_of_one_test_share_a_meter() {
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let test = id(1);
        let a = open_stream(&test, client).expect("first stream");
        let b = open_stream(&test, client).expect("second stream");
        a.record(1000);
        b.record(500);
        let snap = snapshot(&test).expect("meter");
        assert_eq!(snap["bytes"], 1500);
        assert_eq!(snap["streams"], 2);
        assert_eq!(snap["open"], 2);
        drop(a);
        assert_eq!(snapshot(&test).unwrap()["open"], 1);
        drop(b);
        assert_eq!(snapshot(&test).unwrap()["open"], 0);
        let buckets = snap["buckets"].as_array().unwrap();
        assert_eq!(
            buckets.iter().map(|v| v.as_u64().unwrap()).sum::<u64>(),
            1500
        );
    }

    #[test]
    fn ids_must_be_128_bit_hex() {
        assert!(valid_test_id(&id(2)));
        assert!(!valid_test_id("short"));
        assert!(!valid_test_id(&id(2).to_uppercase().replace('0', "G")));
        assert_eq!(
            test_id_from_query(Some(&format!("a=1&test={}", id(3)))),
            Some(id(3))
        );
        assert_eq!(test_id_from_query(Some("test=../../etc")), None);
        assert!(open_stream("not-an-id", IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
    }

    #[test]
    fn one_address_holds_a_bounded_number_of_meters() {
        let client = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let held: Vec<_> = (0..MAX_METERS_PER_ADDRESS)
            .map(|i| open_stream(&id(100 + u8::try_from(i).unwrap()), client).expect("under cap"))
            .collect();
        assert!(open_stream(&id(200), client).is_none());
        // Another stream of a meter it already holds is not a new meter.
        assert!(open_stream(&id(100), client).is_some());
        drop(held);
    }
}
