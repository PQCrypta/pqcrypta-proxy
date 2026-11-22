//! What the requests a node judges look like in aggregate: how many came
//! from each country, and how large the bodies they declared were.
//!
//! Exported at `/metrics` as `pqcrypta_requests_by_country_total{country}`
//! and the `pqcrypta_request_body_bytes` histogram, for whatever keeps a
//! baseline of them: a share of traffic from one country that jumps against
//! its hour of the week, or bodies far larger than this node's usual, is a
//! change no per-request rule sees. Counting costs one country lookup in the
//! GeoIP database (no record decoded beyond the code) and two atomic adds.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// One slot per two-letter code, and one for an address the database has
/// no country for, exported as `ZZ` (ISO 3166's code for an unknown place).
const SLOTS: usize = 26 * 26 + 1;
const UNKNOWN: usize = 26 * 26;

/// Upper bounds of the body-size buckets, in bytes: powers of four from
/// 256 B to 64 MiB.
const BUCKETS: [u64; 10] = [
    256,
    1 << 10,
    1 << 12,
    1 << 14,
    1 << 16,
    1 << 18,
    1 << 20,
    1 << 22,
    1 << 24,
    1 << 26,
];

/// The counters.
pub struct TrafficShape {
    countries: Box<[AtomicU64; SLOTS]>,
    /// Requests whose declared body fell in each bucket, the last above all
    /// of them; cumulative only when exported
    bodies: [AtomicU64; BUCKETS.len() + 1],
    body_bytes: AtomicU64,
}

impl Default for TrafficShape {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficShape {
    pub fn new() -> Self {
        Self {
            countries: Box::new(std::array::from_fn(|_| AtomicU64::new(0))),
            bodies: std::array::from_fn(|_| AtomicU64::new(0)),
            body_bytes: AtomicU64::new(0),
        }
    }

    /// Count a request from the country `code` names, or from nowhere the
    /// database knows.
    pub fn note_country(&self, code: Option<[u8; 2]>) {
        let slot = code
            .filter(|c| c.iter().all(u8::is_ascii_uppercase))
            .map_or(UNKNOWN, |[a, b]| {
                usize::from(a - b'A') * 26 + usize::from(b - b'A')
            });
        self.countries[slot].fetch_add(1, Ordering::Relaxed);
    }

    /// Count a request that declared a body of `bytes`.
    pub fn note_body(&self, bytes: u64) {
        let bucket = BUCKETS
            .iter()
            .position(|&le| bytes <= le)
            .unwrap_or(BUCKETS.len());
        self.bodies[bucket].fetch_add(1, Ordering::Relaxed);
        self.body_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// The counts as they stand: every country with a request, and the
    /// body-size histogram, cumulative as Prometheus has it.
    pub fn snapshot(&self) -> TrafficSnapshot {
        let mut countries = BTreeMap::new();
        for (slot, n) in self.countries.iter().enumerate() {
            let n = n.load(Ordering::Relaxed);
            if n == 0 {
                continue;
            }
            let code = if slot == UNKNOWN {
                "ZZ".to_string()
            } else {
                // A slot is below 26 * 26, so both letters are in A..=Z
                [slot / 26, slot % 26]
                    .map(|i| char::from(b'A' + u8::try_from(i).unwrap_or(0)))
                    .iter()
                    .collect()
            };
            countries.insert(code, n);
        }
        let mut cumulative = 0u64;
        let body_cumulative = self
            .bodies
            .iter()
            .map(|n| {
                cumulative += n.load(Ordering::Relaxed);
                cumulative
            })
            .collect();
        TrafficSnapshot {
            countries,
            body_le: BUCKETS.to_vec(),
            body_cumulative,
            body_bytes: self.body_bytes.load(Ordering::Relaxed),
        }
    }

    /// The Prometheus exposition of both, a country only once it has a
    /// request.
    pub fn export(&self, output: &mut String) {
        use std::fmt::Write;
        let snapshot = self.snapshot();
        if !snapshot.countries.is_empty() {
            output.push_str(
                "\n# HELP pqcrypta_requests_by_country_total Requests judged, by the client's country (GeoIP); ZZ where it has none\n",
            );
            output.push_str("# TYPE pqcrypta_requests_by_country_total counter\n");
            for (code, n) in &snapshot.countries {
                let _ = writeln!(
                    output,
                    "pqcrypta_requests_by_country_total{{country=\"{code}\"}} {n}"
                );
            }
        }
        output.push_str(
            "\n# HELP pqcrypta_request_body_bytes Request bodies by their declared size (Content-Length)\n",
        );
        output.push_str("# TYPE pqcrypta_request_body_bytes histogram\n");
        for (le, n) in snapshot.body_le.iter().zip(&snapshot.body_cumulative) {
            let _ = writeln!(
                output,
                "pqcrypta_request_body_bytes_bucket{{le=\"{le}\"}} {n}"
            );
        }
        let count = snapshot.body_count();
        let _ = writeln!(
            output,
            "pqcrypta_request_body_bytes_bucket{{le=\"+Inf\"}} {count}"
        );
        let _ = writeln!(
            output,
            "pqcrypta_request_body_bytes_sum {}",
            snapshot.body_bytes
        );
        let _ = writeln!(output, "pqcrypta_request_body_bytes_count {count}");
    }
}

/// [`TrafficShape`] as `/metrics/json` carries it.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TrafficSnapshot {
    /// Requests by country (ISO 3166-1 alpha-2; `ZZ` where the database has
    /// none), only the countries with a request
    pub countries: BTreeMap<String, u64>,
    /// Upper bounds of the body-size buckets, in bytes
    pub body_le: Vec<u64>,
    /// Requests whose declared body was at most each bound, cumulative, with
    /// one more entry at the end: every request that declared a body
    pub body_cumulative: Vec<u64>,
    /// The bytes those bodies declared, together
    pub body_bytes: u64,
}

impl TrafficSnapshot {
    /// Requests that declared a body.
    pub fn body_count(&self) -> u64 {
        self.body_cumulative.last().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countries_and_bodies_are_exported_as_counted() {
        let shape = TrafficShape::new();
        shape.note_country(Some(*b"US"));
        shape.note_country(Some(*b"US"));
        shape.note_country(Some(*b"ZA"));
        shape.note_country(None);
        shape.note_country(Some(*b"u1"));
        shape.note_body(100);
        shape.note_body(5_000);
        shape.note_body(1 << 30);
        let mut out = String::new();
        shape.export(&mut out);
        assert!(out.contains("pqcrypta_requests_by_country_total{country=\"US\"} 2\n"));
        assert!(out.contains("pqcrypta_requests_by_country_total{country=\"ZA\"} 1\n"));
        assert!(out.contains("pqcrypta_requests_by_country_total{country=\"ZZ\"} 2\n"));
        assert!(
            !out.contains("country=\"AA\""),
            "a country with none is left out"
        );
        assert!(out.contains("pqcrypta_request_body_bytes_bucket{le=\"256\"} 1\n"));
        assert!(out.contains("pqcrypta_request_body_bytes_bucket{le=\"16384\"} 2\n"));
        assert!(out.contains("pqcrypta_request_body_bytes_bucket{le=\"67108864\"} 2\n"));
        assert!(out.contains("pqcrypta_request_body_bytes_bucket{le=\"+Inf\"} 3\n"));
        assert!(out.contains("pqcrypta_request_body_bytes_count 3\n"));
        assert!(out.contains(&format!(
            "pqcrypta_request_body_bytes_sum {}\n",
            100 + 5_000 + (1u64 << 30)
        )));
    }
}
