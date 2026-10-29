//! The observed TLS fingerprint corpus: every distinct client fingerprint
//! this edge has seen, kept for good, one record per JA4.
//!
//! It used to be the JA3 classification cache itself, written to disk, and
//! so capped like a cache: a client that randomises its extension order (as
//! Chrome does) has a new JA3 on nearly every connection, and its variants
//! filled the cap and evicted, least recently seen first, the rare JA4s the
//! public directory exists to record. /ja4/ fell from 7,071 fingerprints to
//! 4,216 in three days. The cache stays bounded (it is a cache); this is a
//! record, keyed by the stable identity, and is never evicted.
//!
//! A JA4 keeps what the directory shows of it: its counts, first and last
//! sighting, the User-Agents on its requests and a sample of its JA3
//! variants, each sample bounded so that one client cannot grow its record
//! without limit. A ClientHello with no JA4 computed is keyed by its JA3.
//!
//! On disk (`observed.json`), version 2: `{"version": 2, "fingerprints": [..]}`.
//! The version-1 file, one row per JA3, is read and grouped by JA4 on load,
//! and `--merge-fingerprints` merges corpora of either version and the
//! entries of a published directory (`full.json`, from a backup) into one.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use crate::security::ObservedFingerprint;

/// The corpus file's format.
pub const CORPUS_VERSION: u32 = 2;
/// JA3 variants kept per JA4, most seen first; every one is counted.
pub const MAX_JA3_SAMPLES: usize = 16;
/// User-Agents kept per JA4, most seen first.
pub const MAX_USER_AGENTS: usize = 8;
const MAX_UA_LEN: usize = 180;

/// Signature-algorithm lists a JA4_r is rebuilt with, before those the
/// corpus's own JA4_r strings show: the browsers' and OpenSSL's, and none
/// (the directory's sync starts from the same).
const KNOWN_SIGNATURE_LISTS: [&str; 6] = [
    "0403,0804,0401,0503,0805,0501,0806,0601",
    "0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
    "0403,0804,0401,0503,0203,0805,0805,0501,0806,0601,0201",
    "0403,0503,0603,0807,0808,081a,081b,081c,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0301,0302,0402,0502,0602",
    "0403,0503,0603,0807,0808,0809,080a,080b,0804,0805,0806,0401,0501,0601,0303,0203,0301,0201,0302,0202,0402,0502,0602",
    "",
];

/// A published directory generated from here on holds JA4s as the FoxIO
/// spec computes them (2026-10-16T00:00:00Z: the proxy's part c was fixed on
/// 2026-10-15, and the directory's sync recomputed the JA4s stored before).
/// An unproved JA4 from an older directory is taken on no one's word: the
/// sync recomputes it from its JA3, as it does any pre-fix JA4.
const JA4_SPEC_DIRECTORY_EPOCH: i64 = 1_792_108_800;

/// One JA3 a JA4 was seen with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ja3Sample {
    pub ja3_hash: String,
    #[serde(default)]
    pub ja3_string: String,
    pub count: u64,
}

/// One fingerprint: a JA4, or a JA3 where no JA4 was computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// The JA4, or the JA3 hash
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_hash: Option<String>,
    /// JA4_r, the JA4's inputs before hashing, from the latest sighting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_raw: Option<String>,
    /// The JA4 passed the directory's checks when it was published (an entry
    /// restored from a published directory, which carries no JA4_r)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ja4_verified: bool,
    pub classification: String,
    /// 't' (TCP) or 'q' (QUIC)
    pub transport: char,
    /// Unix seconds
    pub first_seen: u64,
    pub last_seen: u64,
    pub request_count: u64,
    #[serde(default)]
    pub user_agents: HashMap<String, u64>,
    /// Distinct JA3s counted as they first appeared
    #[serde(default)]
    pub ja3_variant_count: u64,
    #[serde(default)]
    pub ja3_samples: Vec<Ja3Sample>,
}

/// The file.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorpusFile {
    pub version: u32,
    pub fingerprints: Vec<CorpusEntry>,
}

/// What one sighting adds.
pub struct Sighting<'a> {
    pub ja3_hash: &'a str,
    pub ja3_string: &'a str,
    pub ja4_hash: Option<&'a str>,
    pub ja4_raw: Option<&'a str>,
    pub classification: &'a str,
    pub transport: char,
    pub at: u64,
}

/// The corpus, in memory.
#[derive(Default)]
pub struct Corpus {
    entries: DashMap<String, CorpusEntry>,
}

/// The record's key: the JA4, else the JA3.
pub fn key_of(ja3_hash: &str, ja4_hash: Option<&str>) -> String {
    ja4_hash
        .filter(|j| !j.is_empty())
        .unwrap_or(ja3_hash)
        .to_string()
}

impl Corpus {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record one connection's fingerprint.
    pub fn observe(&self, s: &Sighting<'_>) {
        let key = key_of(s.ja3_hash, s.ja4_hash);
        let mut entry = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| CorpusEntry {
                key,
                ja4_hash: s.ja4_hash.map(str::to_string),
                ja4_raw: None,
                ja4_verified: false,
                classification: s.classification.to_string(),
                transport: s.transport,
                first_seen: s.at,
                last_seen: s.at,
                request_count: 0,
                user_agents: HashMap::new(),
                ja3_variant_count: 0,
                ja3_samples: Vec::new(),
            });
        let e = entry.value_mut();
        e.first_seen = e.first_seen.min(s.at);
        e.last_seen = e.last_seen.max(s.at);
        e.request_count = e.request_count.saturating_add(1);
        e.classification = s.classification.to_string();
        if let Some(raw) = s.ja4_raw.filter(|r| !r.is_empty()) {
            e.ja4_raw = Some(raw.to_string());
        }
        note_ja3(e, s.ja3_hash, s.ja3_string, 1);
    }

    /// Record a User-Agent seen on a request with this fingerprint.
    pub fn note_user_agent(&self, key: &str, user_agent: &str) {
        if key.is_empty() || user_agent.is_empty() {
            return;
        }
        if let Some(mut entry) = self.entries.get_mut(key) {
            let ua: String = user_agent.chars().take(MAX_UA_LEN).collect();
            add_user_agent(entry.value_mut(), ua, 1);
        }
    }

    /// Every record, most recently seen first.
    pub fn entries(&self) -> Vec<CorpusEntry> {
        let mut all: Vec<CorpusEntry> = self.entries.iter().map(|e| e.value().clone()).collect();
        all.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| a.key.cmp(&b.key))
        });
        all
    }

    /// Merge `entry` into the corpus: counts and first sightings from the
    /// lineage that has them (the larger count, the earlier first sighting,
    /// the later last), as two snapshots of one corpus overlap.
    pub fn absorb(&self, entry: CorpusEntry) {
        match self.entries.get_mut(&entry.key) {
            Some(mut have) => merge(have.value_mut(), entry),
            None => {
                self.entries.insert(entry.key.clone(), entry);
            }
        }
    }

    /// Give each JA4 with no JA4_r the one it was hashed from, where that can
    /// be rebuilt and proved (`rebuild_raw`): a record restored from a
    /// published directory carries none. Returns how many were rebuilt.
    pub fn rebuild_missing_raw(&self) -> usize {
        let mut lists: BTreeSet<String> = KNOWN_SIGNATURE_LISTS
            .iter()
            .map(|l| (*l).to_string())
            .collect();
        for e in self.entries.iter() {
            if let Some(sigs) = e.ja4_raw.as_deref().and_then(signature_list) {
                lists.insert(sigs.to_string());
            }
        }
        let lists: Vec<String> = lists.into_iter().collect();
        let mut rebuilt = 0;
        for mut e in self.entries.iter_mut() {
            if e.ja4_raw.is_some() {
                continue;
            }
            let Some(ja4) = e.ja4_hash.clone() else {
                continue;
            };
            let raw = e
                .ja3_samples
                .iter()
                .filter(|s| !s.ja3_string.is_empty())
                .find_map(|s| rebuild_raw(&ja4, &s.ja3_string, &lists));
            if let Some(raw) = raw {
                e.ja4_raw = Some(raw);
                // Proved by its hashes: no longer taken on the directory's word
                e.ja4_verified = false;
                rebuilt += 1;
            }
        }
        rebuilt
    }

    /// Write the corpus, atomically through a temp file: the public directory
    /// reads it on a timer, and a half-written file would be a parse error.
    pub fn flush(&self, path: &Path) -> std::io::Result<usize> {
        let fingerprints = self.entries();
        let n = fingerprints.len();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec(&CorpusFile {
            version: CORPUS_VERSION,
            fingerprints,
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, json)?;
        // 0644: the export job feeding the public directory runs unprivileged
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(n)
    }

    /// Read a corpus file of either version into this one. A missing or
    /// unreadable file is not an error: first boot is the normal case, and a
    /// bad file must not stop the proxy starting.
    pub fn load(&self, path: &Path) -> Result<usize, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let entries = parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        let n = entries.len();
        for e in entries {
            self.absorb(e);
        }
        Ok(n)
    }
}

/// The records a file holds: a version-2 corpus, a version-1 corpus (one row
/// per JA3, grouped by JA4 here), or a published directory's `full.json`
/// (its observed entries).
pub fn parse(bytes: &[u8]) -> Result<Vec<CorpusEntry>, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if value.get("version").is_some() && value.get("fingerprints").is_some() {
        let file: CorpusFile = serde_json::from_value(value).map_err(|e| e.to_string())?;
        if file.version > CORPUS_VERSION {
            return Err(format!(
                "corpus version {} is newer than this proxy's",
                file.version
            ));
        }
        return Ok(file.fingerprints);
    }
    if let Some(list) = value.get("entries").and_then(|e| e.as_array()) {
        let spec = value
            .get("generated_at")
            .and_then(|g| g.as_str())
            .and_then(|g| chrono::DateTime::parse_from_rfc3339(g).ok())
            .is_some_and(|g| g.timestamp() >= JA4_SPEC_DIRECTORY_EPOCH);
        return Ok(list
            .iter()
            .filter_map(|e| from_directory(e, spec))
            .collect());
    }
    let rows: Vec<ObservedFingerprint> =
        serde_json::from_value(value).map_err(|e| e.to_string())?;
    Ok(group_rows(rows))
}

/// Version-1 rows, one per JA3, as JA4 records.
pub fn group_rows(rows: Vec<ObservedFingerprint>) -> Vec<CorpusEntry> {
    let corpus = Corpus::default();
    for r in rows {
        let key = key_of(&r.ja3_hash, r.ja4_hash.as_deref());
        let mut entry = corpus
            .entries
            .entry(key.clone())
            .or_insert_with(|| CorpusEntry {
                key,
                ja4_hash: r.ja4_hash.clone().filter(|j| !j.is_empty()),
                ja4_raw: None,
                ja4_verified: false,
                classification: r.classification.clone(),
                transport: r.transport,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
                request_count: 0,
                user_agents: HashMap::new(),
                ja3_variant_count: 0,
                ja3_samples: Vec::new(),
            });
        let e = entry.value_mut();
        e.first_seen = e.first_seen.min(r.first_seen);
        if r.last_seen >= e.last_seen {
            e.last_seen = r.last_seen;
            e.classification = r.classification.clone();
            if let Some(raw) = r.ja4_raw.clone().filter(|x| !x.is_empty()) {
                e.ja4_raw = Some(raw);
            }
        }
        if e.ja4_raw.is_none() {
            e.ja4_raw = r.ja4_raw.clone().filter(|x| !x.is_empty());
        }
        e.request_count = e.request_count.saturating_add(r.request_count);
        note_ja3(e, &r.ja3_hash, &r.ja3_string, r.request_count.max(1));
        for (ua, n) in r.user_agents {
            add_user_agent(e, ua, n);
        }
    }
    corpus.entries.into_iter().map(|(_, e)| e).collect()
}

/// A published directory's observed entry as a record. From a directory
/// generated after the JA4 spec fix (`spec`), its JA4 passed the directory's
/// checks when it was published, which is what `ja4_verified` says: the entry
/// carries no JA4_r to check it by again (until `rebuild_raw` proves one).
fn from_directory(v: &serde_json::Value, spec: bool) -> Option<CorpusEntry> {
    if v.get("tier")?.as_str()? != "observed" {
        return None;
    }
    let hash = v.get("hash")?.as_str()?.to_string();
    let is_ja4 = v.get("kind").and_then(|k| k.as_str()) == Some("ja4");
    let o = v.get("observed")?;
    let num = |k: &str| o.get(k).and_then(serde_json::Value::as_u64).unwrap_or(0);
    let ja3_string = v
        .get("ja3_string")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string();
    let first_ja3 = o
        .get("ja3_hash")
        .and_then(|s| s.as_str())
        .unwrap_or_default();
    let mut samples: Vec<Ja3Sample> = o
        .get("ja3_variants")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|h| h.as_str())
                .take(MAX_JA3_SAMPLES)
                .map(|h| Ja3Sample {
                    ja3_hash: h.to_string(),
                    ja3_string: if h == first_ja3 {
                        ja3_string.clone()
                    } else {
                        String::new()
                    },
                    count: 0,
                })
                .collect()
        })
        .unwrap_or_default();
    if samples.is_empty() && !first_ja3.is_empty() {
        samples.push(Ja3Sample {
            ja3_hash: first_ja3.to_string(),
            ja3_string,
            count: 0,
        });
    }
    let user_agents: HashMap<String, u64> = o
        .get("user_agents")
        .and_then(|u| u.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, n)| n.as_u64().map(|n| (k.clone(), n)))
                .collect()
        })
        .unwrap_or_default();
    let classification = match v.get("classification").and_then(|c| c.as_str()) {
        Some("browser") => "Browser",
        Some("api_client") => "ApiClient",
        Some("scanner") => "Scanner",
        Some("monitor") => "LegitimateBot",
        _ => "Suspicious",
    };
    let transport = o
        .get("transport")
        .and_then(|t| t.as_str())
        .and_then(|t| t.chars().next())
        .unwrap_or('t');
    Some(CorpusEntry {
        key: hash.clone(),
        ja4_hash: is_ja4.then(|| hash.clone()),
        ja4_raw: None,
        ja4_verified: is_ja4 && spec,
        classification: classification.to_string(),
        transport,
        first_seen: num("first_seen"),
        last_seen: num("last_seen"),
        request_count: num("count"),
        user_agents,
        ja3_variant_count: num("ja3_variant_count").max(samples.len() as u64),
        ja3_samples: samples,
    })
}

/// The signature-algorithm list a JA4_r ends with, if it has one.
fn signature_list(raw: &str) -> Option<&str> {
    let mut parts = raw.splitn(4, '_');
    parts.nth(3).filter(|s| !s.is_empty())
}

/// GREASE values (RFC 8701), which neither JA3 nor JA4 counts.
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a
}

fn sha12(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))[..12].to_string()
}

/// The JA4_r `ja4` was hashed from, rebuilt from a JA3 string of the same
/// ClientHello and one of `signature_lists`.
///
/// A JA4_r is part a, the sorted cipher list, the sorted extension list
/// without SNI and ALPN, and the signature algorithms as sent. The JA3
/// string carries the ciphers and extensions; the signature algorithms it
/// does not, so each candidate list is tried. A rebuilt JA4_r counts only
/// when its cipher list hashes to the JA4's part b and its extension and
/// signature lists to part c: two SHA-256 matches, so a list that fits is the
/// one the client sent, and none that does not can be passed off.
pub fn rebuild_raw(ja4: &str, ja3_string: &str, signature_lists: &[String]) -> Option<String> {
    let mut parts = ja4.split('_');
    let (a, b, c) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let fields: Vec<&str> = ja3_string.split(',').collect();
    if fields.len() != 5 {
        return None;
    }
    let values = |s: &str| -> Option<Vec<u16>> {
        if s.is_empty() {
            return Some(Vec::new());
        }
        s.split('-').map(|x| x.parse::<u16>().ok()).collect()
    };
    let hex_list = |v: &[u16]| {
        v.iter()
            .map(|x| format!("{x:04x}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let mut ciphers: Vec<u16> = values(fields[1])?
        .into_iter()
        .filter(|v| !is_grease(*v))
        .collect();
    ciphers.sort_unstable();
    let cipher_list = hex_list(&ciphers);
    let part_b = if ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        sha12(&cipher_list)
    };
    if part_b != b {
        return None;
    }
    let mut extensions: Vec<u16> = values(fields[2])?
        .into_iter()
        .filter(|v| !is_grease(*v) && *v != 0x0000 && *v != 0x0010)
        .collect();
    extensions.sort_unstable();
    let ext_list = hex_list(&extensions);
    signature_lists.iter().find_map(|sigs| {
        let input = if sigs.is_empty() {
            ext_list.clone()
        } else {
            format!("{ext_list}_{sigs}")
        };
        let part_c = if extensions.is_empty() {
            "000000000000".to_string()
        } else {
            sha12(&input)
        };
        (part_c == c).then(|| format!("{a}_{cipher_list}_{input}"))
    })
}

/// Count a JA3 under its JA4, keeping the most seen.
fn note_ja3(e: &mut CorpusEntry, ja3_hash: &str, ja3_string: &str, n: u64) {
    if ja3_hash.is_empty() {
        return;
    }
    if let Some(s) = e.ja3_samples.iter_mut().find(|s| s.ja3_hash == ja3_hash) {
        s.count = s.count.saturating_add(n);
        if s.ja3_string.is_empty() {
            s.ja3_string = ja3_string.to_string();
        }
    } else {
        e.ja3_variant_count = e.ja3_variant_count.saturating_add(1);
        e.ja3_samples.push(Ja3Sample {
            ja3_hash: ja3_hash.to_string(),
            ja3_string: ja3_string.to_string(),
            count: n,
        });
    }
    if e.ja3_samples.len() > MAX_JA3_SAMPLES {
        e.ja3_samples.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.ja3_hash.cmp(&b.ja3_hash))
        });
        e.ja3_samples.truncate(MAX_JA3_SAMPLES);
    }
}

/// Count a User-Agent, keeping the most seen; a one-off does not displace an
/// agent seen more than once.
fn add_user_agent(e: &mut CorpusEntry, ua: String, n: u64) {
    if let Some(count) = e.user_agents.get_mut(&ua) {
        *count = count.saturating_add(n);
        return;
    }
    if e.user_agents.len() >= MAX_USER_AGENTS {
        let Some((weakest, seen)) = e
            .user_agents
            .iter()
            .min_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(k, c)| (k.clone(), *c))
        else {
            return;
        };
        if seen >= n.max(2) {
            return;
        }
        e.user_agents.remove(&weakest);
    }
    e.user_agents.insert(ua, n);
}

/// Two records of one fingerprint, from one lineage (snapshots overlap).
fn merge(have: &mut CorpusEntry, other: CorpusEntry) {
    have.first_seen = match (have.first_seen, other.first_seen) {
        (0, b) => b,
        (a, 0) => a,
        (a, b) => a.min(b),
    };
    if other.last_seen > have.last_seen {
        have.last_seen = other.last_seen;
        have.classification = other.classification.clone();
        if other.ja4_raw.is_some() {
            have.ja4_raw = other.ja4_raw.clone();
        }
    }
    if have.ja4_raw.is_none() {
        have.ja4_raw = other.ja4_raw.clone();
    }
    have.ja4_verified |= other.ja4_verified;
    if have.ja4_hash.is_none() {
        have.ja4_hash = other.ja4_hash.clone();
    }
    have.request_count = have.request_count.max(other.request_count);
    have.ja3_variant_count = have.ja3_variant_count.max(other.ja3_variant_count);
    for s in other.ja3_samples {
        match have
            .ja3_samples
            .iter_mut()
            .find(|h| h.ja3_hash == s.ja3_hash)
        {
            Some(h) => {
                h.count = h.count.max(s.count);
                if h.ja3_string.is_empty() {
                    h.ja3_string = s.ja3_string;
                }
            }
            None => have.ja3_samples.push(s),
        }
    }
    have.ja3_samples.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.ja3_hash.cmp(&b.ja3_hash))
    });
    have.ja3_samples.truncate(MAX_JA3_SAMPLES);
    have.ja3_variant_count = have.ja3_variant_count.max(have.ja3_samples.len() as u64);
    for (ua, n) in other.user_agents {
        match have.user_agents.get_mut(&ua) {
            Some(c) => *c = (*c).max(n),
            None => add_user_agent(have, ua, n),
        }
    }
}

/// `--merge-fingerprints OUT --from FILE...`: the files' records merged into
/// one corpus, written to OUT.
pub fn merge_files(inputs: &[std::path::PathBuf], out: &Path) -> Result<String, String> {
    let corpus = Corpus::default();
    let mut read = Vec::new();
    for p in inputs {
        let n = corpus.load(p)?;
        read.push(format!("{} ({n})", p.display()));
    }
    let rebuilt = corpus.rebuild_missing_raw();
    let unproved = corpus.entries().iter().filter(|e| e.ja4_verified).count();
    let n = corpus
        .flush(out)
        .map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(format!(
        "{n} fingerprints written to {}, from {}; {rebuilt} JA4_r rebuilt and proved, {unproved} kept on the published directory's word",
        out.display(),
        read.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ja3: &str, ja4: Option<&str>, n: u64, first: u64, last: u64) -> ObservedFingerprint {
        ObservedFingerprint {
            ja3_hash: ja3.into(),
            ja4_hash: ja4.map(str::to_string),
            ja4_raw: None,
            ja3_string: format!("771,{ja3}"),
            classification: "Browser".into(),
            transport: 't',
            first_seen: first,
            last_seen: last,
            request_count: n,
            user_agents: HashMap::from([("Mozilla/5.0".to_string(), n)]),
        }
    }

    #[test]
    fn ja3_variants_of_one_ja4_are_one_fingerprint() {
        // A browser that randomises its extension order: a new JA3 a
        // connection, one JA4
        let rows: Vec<_> = (0..40)
            .map(|i| {
                row(
                    &format!("{i:032x}"),
                    Some("t13d1516h2_8daaf6152771_02713d6af862"),
                    2,
                    100 + i,
                    200 + i,
                )
            })
            .chain([row(
                "f".repeat(32).as_str(),
                Some("t13d0912h1_aaaaaaaaaaaa_bbbbbbbbbbbb"),
                1,
                50,
                60,
            )])
            .collect();
        let grouped = group_rows(rows);
        assert_eq!(grouped.len(), 2);
        let chrome = grouped
            .iter()
            .find(|e| e.key.starts_with("t13d1516"))
            .expect("grouped");
        assert_eq!(chrome.request_count, 80);
        assert_eq!(chrome.ja3_variant_count, 40);
        assert_eq!(chrome.ja3_samples.len(), MAX_JA3_SAMPLES);
        assert_eq!((chrome.first_seen, chrome.last_seen), (100, 239));
        assert_eq!(chrome.user_agents.get("Mozilla/5.0"), Some(&80));
    }

    #[test]
    fn a_fingerprint_is_never_evicted_and_a_record_is_bounded() {
        let corpus = Corpus::default();
        for i in 0..5_000u64 {
            corpus.observe(&Sighting {
                ja3_hash: &format!("{i:032x}"),
                ja3_string: "771,4865",
                ja4_hash: Some(if i % 2 == 0 {
                    "t13d1516h2_8daaf6152771_02713d6af862"
                } else {
                    "q13d0311h3_55b375c5d22e_df5b9e597968"
                }),
                ja4_raw: None,
                classification: "Browser",
                transport: 't',
                at: 1_000 + i,
            });
        }
        // Rare fingerprints alongside: every one kept
        for i in 0..300u64 {
            corpus.observe(&Sighting {
                ja3_hash: "e".repeat(32).as_str(),
                ja3_string: "771,4865",
                ja4_hash: Some(&format!("t13d0{i:03}h2_aaaaaaaaaaaa_bbbbbbbbbbbb")),
                ja4_raw: None,
                classification: "Scanner",
                transport: 't',
                at: 10,
            });
        }
        assert_eq!(corpus.len(), 302);
        let e = corpus.entries();
        let busy = e
            .iter()
            .find(|x| x.key.starts_with("t13d1516"))
            .expect("kept");
        assert_eq!(busy.ja3_variant_count, 2_500);
        assert!(busy.ja3_samples.len() <= MAX_JA3_SAMPLES);
        for i in 0..20 {
            corpus.note_user_agent(&busy.key, &format!("agent {i}"));
        }
        let busy = corpus
            .entries()
            .into_iter()
            .find(|x| x.key.starts_with("t13d1516"))
            .expect("kept");
        assert!(busy.user_agents.len() <= MAX_USER_AGENTS);
    }

    #[test]
    fn a_published_directory_entry_is_restored_verified() {
        let dir = serde_json::json!({ "generated_at": "2026-10-26T11:50:05+00:00", "entries": [
            { "hash": "q13d0311h3_55b375c5d22e_df5b9e597968", "kind": "ja4", "tier": "observed",
              "classification": "api_client", "ja3_string": "771,4865-4866",
              "observed": { "count": 128, "first_seen": 1_787_535_364_u64, "last_seen": 1_793_014_692_u64,
                            "transport": "q", "ja3_hash": "3e9680842aa1ac1f48edc74e779ebc97",
                            "ja3_variant_count": 1, "ja3_variants": ["3e9680842aa1ac1f48edc74e779ebc97"],
                            "user_agents": { "quic-go-HTTP/3": 128 } } },
            { "hash": "t13d1516h2_8daaf6152771_02713d6af862", "kind": "ja4", "tier": "curated" }
        ]});
        let entries = parse(dir.to_string().as_bytes()).expect("parses");
        assert_eq!(entries.len(), 1, "curated entries are not observations");
        let e = &entries[0];
        assert!(e.ja4_verified && e.ja4_raw.is_none());
        assert_eq!(
            (e.transport, e.request_count, e.classification.as_str()),
            ('q', 128, "ApiClient")
        );
        assert_eq!(e.ja3_samples[0].ja3_string, "771,4865-4866");
        // From a directory before the spec fix: not taken as verified
        let mut old = dir.clone();
        old["generated_at"] = serde_json::json!("2026-09-30T06:00:00+00:00");
        assert!(!parse(old.to_string().as_bytes()).expect("parses")[0].ja4_verified);
    }

    #[test]
    fn a_ja4_r_is_rebuilt_only_when_both_hashes_prove_it() {
        // Built the way fingerprint.rs builds one: ciphers 4865-4867,
        // extensions with SNI (0) and ALPN (16) left out, Chromium's
        // signature list
        let sigs = KNOWN_SIGNATURE_LISTS[0];
        let cipher_list = "1301,1302,1303";
        let ext_list = "000a,000b,000d,002b,0033";
        let ja4 = format!(
            "t13d0307h2_{}_{}",
            sha12(cipher_list),
            sha12(&format!("{ext_list}_{sigs}"))
        );
        let ja3 = "771,4865-4866-4867,0-16-10-11-13-43-51,29-23,0";
        let lists: Vec<String> = KNOWN_SIGNATURE_LISTS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            rebuild_raw(&ja4, ja3, &lists).as_deref(),
            Some(format!("t13d0307h2_{cipher_list}_{ext_list}_{sigs}").as_str())
        );
        // GREASE in the JA3 is not counted
        let greased = "771,2570-4865-4866-4867,0-16-10-11-13-43-51-6682,29-23,0";
        assert!(rebuild_raw(&ja4, greased, &lists).is_some());
        // Another cipher set does not hash to part b
        assert!(rebuild_raw(&ja4, "771,4865-4866,0-16-10-11-13-43-51,29-23,0", &lists).is_none());
        // No candidate signature list hashes to part c
        assert!(rebuild_raw(&ja4, ja3, &lists[1..]).is_none());
        // And the corpus rebuilds what a restored record lacks
        let corpus = Corpus::default();
        corpus.absorb(CorpusEntry {
            key: ja4.clone(),
            ja4_hash: Some(ja4),
            ja4_raw: None,
            ja4_verified: true,
            classification: "Browser".into(),
            transport: 't',
            first_seen: 1,
            last_seen: 2,
            request_count: 3,
            user_agents: HashMap::new(),
            ja3_variant_count: 1,
            ja3_samples: vec![Ja3Sample {
                ja3_hash: "a".repeat(32),
                ja3_string: ja3.into(),
                count: 3,
            }],
        });
        assert_eq!(corpus.rebuild_missing_raw(), 1);
        let e = &corpus.entries()[0];
        assert!(e.ja4_raw.is_some() && !e.ja4_verified);
    }

    #[test]
    fn snapshots_of_one_corpus_merge_without_double_counting() {
        let corpus = Corpus::default();
        let mut a = group_rows(vec![row(
            &"a".repeat(32),
            Some("t13d0912h1_aaaaaaaaaaaa_bbbbbbbbbbbb"),
            10,
            100,
            500,
        )]);
        let mut b = a.clone();
        b[0].request_count = 25;
        b[0].last_seen = 900;
        b[0].first_seen = 50;
        corpus.absorb(a.remove(0));
        corpus.absorb(b.remove(0));
        let e = &corpus.entries()[0];
        assert_eq!((e.request_count, e.first_seen, e.last_seen), (25, 50, 900));
    }

    #[test]
    fn the_file_round_trips_and_a_newer_version_is_refused() {
        let corpus = Corpus::default();
        corpus.absorb(
            group_rows(vec![row(
                &"a".repeat(32),
                Some("t13d0912h1_aaaaaaaaaaaa_bbbbbbbbbbbb"),
                3,
                1,
                2,
            )])
            .remove(0),
        );
        let dir = std::env::temp_dir().join(format!("corpus-test-{}", std::process::id()));
        let path = dir.join("observed.json");
        assert_eq!(corpus.flush(&path).expect("written"), 1);
        let back = Corpus::default();
        assert_eq!(back.load(&path).expect("read"), 1);
        assert_eq!(back.entries(), corpus.entries());
        let newer = serde_json::json!({ "version": CORPUS_VERSION + 1, "fingerprints": [] });
        assert!(parse(newer.to_string().as_bytes()).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
