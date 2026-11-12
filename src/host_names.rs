//! Host names in `security.pentest_bypass_ips` and the `[masque]` client
//! lists.
//!
//! Each list takes host names beside addresses. A name stands for the
//! addresses it resolves to: a host whose address its ISP changes (fortress,
//! on a home connection) is listed once by name and DNS carries each change,
//! where a copy of its address went stale at every renumbering and went on
//! exempting an address that was by then someone else's.
//!
//! A name resolves only through `security.host_resolver`, a validating
//! resolver reached over TCP, and only an answer that resolver marks
//! authenticated (AD, RFC 4035 §3.2.3) counts. The list exempts its addresses
//! from rate limits and bans, which cannot rest on an answer someone on the
//! path could forge, or on an unsigned zone's. Without a resolver, a name
//! matches nothing. Names are resolved again every REFRESH; a lookup that
//! fails keeps the last answer, since a resolver that cannot answer says
//! nothing about where the host is now.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use parking_lot::RwLock;
use tracing::{info, warn};

use crate::acme_dns::{addresses_in, exchange, TYPE_A, TYPE_AAAA};
use crate::dns_wire::{encode_name, u16_at, HEADER_LEN};

/// How often the names are resolved again
pub const REFRESH: Duration = Duration::from_secs(60);

const CLASS_IN: u16 = 1;
const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_AD: u16 = 0x0020;
const RCODE_MASK: u16 = 0x000f;

/// Each name's addresses, as the resolver last authenticated them
static ANSWERS: LazyLock<RwLock<HashMap<String, Vec<IpAddr>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// The host names each list outside `security.pentest_bypass_ips` holds, by
/// the list's name: the refresh keeps them resolved with that list's.
static WATCHED: LazyLock<RwLock<HashMap<&'static str, Vec<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Keep `names` resolved for `list`, in place of the names it gave before.
pub fn watch(list: &'static str, names: Vec<String>) {
    WATCHED.write().insert(list, names);
}

/// Every name a list has asked to be kept resolved.
pub fn watched() -> Vec<String> {
    let mut names: Vec<String> = WATCHED.read().values().flatten().cloned().collect();
    names.sort();
    names.dedup();
    names
}

/// Is `entry` a host name rather than an address?
///
/// Letters, digits and hyphens in dot-separated labels of 1 to 63 octets, at
/// most 253 in all, and a last label that is not all digits, so a mistyped
/// address (`192.0.2`) is not taken for a name.
pub fn is_host_name(entry: &str) -> bool {
    let name = entry.trim().trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    !name.is_empty()
        && name.len() <= 253
        && labels.iter().all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}

/// Does `name` resolve to `ip`, as last authenticated?
pub fn resolves_to(name: &str, ip: &IpAddr) -> bool {
    let ip = ip.to_canonical();
    ANSWERS
        .read()
        .get(&key(name))
        .is_some_and(|addresses| addresses.contains(&ip))
}

/// Resolve each of `names` through `resolver` and keep the answers. A name
/// whose lookup fails keeps its last answer.
pub async fn refresh(resolver: SocketAddr, names: &[String]) {
    for name in names {
        let name = key(name);
        match resolve(resolver, &name).await {
            Ok(addresses) => {
                let mut answers = ANSWERS.write();
                if answers.get(&name) != Some(&addresses) {
                    info!("{name} resolves to {addresses:?}");
                }
                answers.insert(name, addresses);
            }
            Err(e) => match ANSWERS.read().get(&name) {
                Some(last) => warn!("{name}: {e}; keeping its last answer, {last:?}"),
                None => warn!("{name}: {e}; it matches nothing"),
            },
        }
    }
}

/// Forget every name but `names`: one taken out of the list must not match
/// again, with an old answer, if it is put back.
pub fn retain(names: &[String]) {
    let names: Vec<String> = names.iter().map(|n| key(n)).collect();
    ANSWERS.write().retain(|name, _| names.contains(name));
}

/// The A and AAAA records of `name`, authenticated by `resolver`
async fn resolve(resolver: SocketAddr, name: &str) -> anyhow::Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    for rtype in [TYPE_A, TYPE_AAAA] {
        let response = exchange(resolver, &query(name, rtype)?).await?;
        let flags = u16_at(&response, 2)
            .ok_or_else(|| anyhow::anyhow!("{resolver} sent a truncated header"))?;
        if flags & FLAG_QR == 0 {
            anyhow::bail!("{resolver} sent a query, not an answer");
        }
        match flags & RCODE_MASK {
            0 => {}
            rcode => anyhow::bail!("{resolver} answered with RCODE {rcode}"),
        }
        if flags & FLAG_AD == 0 {
            anyhow::bail!("{resolver} did not authenticate the answer (no AD bit)");
        }
        addresses.extend(addresses_in(&response, rtype));
    }
    if addresses.is_empty() {
        anyhow::bail!("no A or AAAA records");
    }
    let mut addresses: Vec<IpAddr> = addresses.into_iter().map(|a| a.to_canonical()).collect();
    addresses.sort();
    addresses.dedup();
    Ok(addresses)
}

/// A recursive query that asks for the resolver's validation (AD, RFC 6840 §5.7)
fn query(name: &str, rtype: u16) -> anyhow::Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    msg.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    msg.extend_from_slice(&(FLAG_RD | FLAG_AD).to_be_bytes());
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    msg.extend(encode_name(name).ok_or_else(|| anyhow::anyhow!("{name} is not a domain name"))?);
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

fn key(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
pub(crate) fn set_answer(name: &str, addresses: Vec<IpAddr>) {
    ANSWERS.write().insert(key(name), addresses);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn names_are_told_from_addresses() {
        for name in [
            "fortress.pqcrypta.com",
            "fortress.pqcrypta.com.",
            "a-b.example",
            "localhost",
        ] {
            assert!(is_host_name(name), "{name} is a name");
        }
        for entry in [
            "192.0.2.1",
            "192.0.2",
            "2001:db8::1",
            "",
            "-a.example",
            "a..example",
            "a_b.example",
        ] {
            assert!(!is_host_name(entry), "{entry:?} is not a name");
        }
    }

    /// A resolver on loopback that answers each query with `answer(qtype)`:
    /// the flags and the records, if any, for that type.
    async fn resolver(answer: fn(u16) -> (u16, Vec<[u8; 4]>)) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.unwrap();
                let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
                stream.read_exact(&mut q).await.unwrap();
                let qtype = u16::from_be_bytes([q[q.len() - 4], q[q.len() - 3]]);
                let (flags, records) = answer(qtype);
                let mut r = q[0..2].to_vec();
                r.extend_from_slice(&flags.to_be_bytes());
                r.extend_from_slice(&[0, 1]);
                r.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
                r.extend_from_slice(&[0, 0, 0, 0]);
                r.extend_from_slice(&q[HEADER_LEN..]);
                for a in records {
                    r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
                    r.extend_from_slice(&a);
                }
                let mut framed = u16::try_from(r.len()).unwrap().to_be_bytes().to_vec();
                framed.extend(r);
                stream.write_all(&framed).await.unwrap();
            }
        });
        addr
    }

    #[test]
    fn a_bypass_list_matches_the_addresses_its_names_resolve_to() {
        set_answer("listed.example", vec!["192.0.2.20".parse().unwrap()]);
        let list = vec!["198.51.100.1".to_string(), "listed.example".to_string()];
        let contains = |ip: &str| crate::config::ip_list_contains(&list, &ip.parse().unwrap());
        assert!(contains("192.0.2.20"));
        assert!(contains("198.51.100.1"));
        assert!(!contains("192.0.2.21"));
    }

    #[tokio::test]
    async fn an_authenticated_answer_is_kept() {
        let r = resolver(|qtype| {
            let records = if qtype == TYPE_A {
                vec![[192, 0, 2, 7]]
            } else {
                vec![]
            };
            (FLAG_QR | FLAG_RD | 0x0080 | FLAG_AD, records)
        })
        .await;
        refresh(r, &["Kept.Example.".to_string()]).await;
        assert!(resolves_to("kept.example", &"192.0.2.7".parse().unwrap()));
        assert!(resolves_to(
            "kept.example",
            &"::ffff:192.0.2.7".parse().unwrap()
        ));
        assert!(!resolves_to("kept.example", &"192.0.2.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn an_unauthenticated_answer_counts_for_nothing() {
        let r = resolver(|qtype| {
            let records = if qtype == TYPE_A {
                vec![[192, 0, 2, 9]]
            } else {
                vec![]
            };
            (FLAG_QR | FLAG_RD | 0x0080, records)
        })
        .await;
        refresh(r, &["forged.example".to_string()]).await;
        assert!(!resolves_to(
            "forged.example",
            &"192.0.2.9".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn a_failed_lookup_keeps_the_last_answer() {
        set_answer("held.example", vec!["192.0.2.10".parse().unwrap()]);
        let r = resolver(|_| (FLAG_QR | FLAG_RD | 0x0080 | 2, vec![])).await;
        refresh(r, &["held.example".to_string()]).await;
        assert!(resolves_to("held.example", &"192.0.2.10".parse().unwrap()));
    }
}
