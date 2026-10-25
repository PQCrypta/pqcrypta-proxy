//! DNS-based ACME challenges: dns-01 (RFC 8555 §8.4) and dns-account-01.
//!
//! The TXT record a challenge asks for (draft-ietf-acme-dns-account-label
//! names dns-account-01's) is published and removed by DNS UPDATE (RFC 2136)
//! signed with TSIG (RFC 8945), and waited for at every authoritative server
//! of its zone before the CA is told to look.
//!
//! The update goes to one server, the zone's primary or a secondary that
//! forwards it there (Knot DNS forwards an update to the zone's primary and
//! signs the copy with its own key for it). Its answer is checked against the
//! same TSIG key. The record is then asked for at each of the zone's name
//! servers, as the CA's resolvers will ask, until all of them serve it.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::dns_wire::{encode_name, layout, read_name, u16_at, HEADER_LEN};

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const OPCODE_UPDATE: u16 = 5;
/// RFC 8945 §10: 300 seconds of clock difference allowed
const FUDGE: u16 = 300;
/// One exchange with a server, connection included
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Between two looks at the zone's servers while waiting for the record
const PROPAGATION_POLL: Duration = Duration::from_secs(2);

/// Where and how a node publishes its DNS challenges.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsUpdateConfig {
    /// The server that takes the updates, `address:port`: the zone's primary,
    /// or a secondary that forwards updates to it
    pub server: String,
    /// The TSIG key's name, as the server knows it
    pub key_name: String,
    /// The TSIG algorithm: "hmac-sha256" (RFC 8945's mandatory one) or
    /// "hmac-sha512"
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// A file holding the key's secret, base64 (as `keymgr -t` prints it),
    /// readable by the proxy alone
    pub secret_file: PathBuf,
    /// How long every authoritative server has to serve the record before the
    /// order is given up
    #[serde(default = "default_propagation_timeout_secs")]
    pub propagation_timeout_secs: u64,
    /// The record's TTL: short, as it is removed once the CA has looked
    #[serde(default = "default_ttl")]
    pub ttl: u32,
}

fn default_algorithm() -> String {
    "hmac-sha256".to_string()
}

fn default_propagation_timeout_secs() -> u64 {
    120
}

fn default_ttl() -> u32 {
    60
}

/// The TSIG algorithms this client signs with (RFC 8945 §6)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    HmacSha256,
    HmacSha512,
}

impl Algorithm {
    fn parse(name: &str) -> anyhow::Result<Self> {
        match name.trim_end_matches('.').to_ascii_lowercase().as_str() {
            "hmac-sha256" => Ok(Self::HmacSha256),
            "hmac-sha512" => Ok(Self::HmacSha512),
            other => Err(anyhow::anyhow!(
                "TSIG algorithm '{other}' is not supported (hmac-sha256 or hmac-sha512)"
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha512 => "hmac-sha512",
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::HmacSha256 => {
                let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
                    .expect("HMAC takes a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::HmacSha512 => {
                let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key)
                    .expect("HMAC takes a key of any length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// A TSIG key (RFC 8945)
#[derive(Clone)]
struct TsigKey {
    name: String,
    algorithm: Algorithm,
    secret: Vec<u8>,
}

impl std::fmt::Debug for TsigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TsigKey")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The DNS challenge record a challenge asks for: its owner and TXT value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeRecord {
    /// The zone the owner is in, found from its SOA
    pub zone: String,
    pub owner: String,
    pub value: String,
}

/// The owner of a dns-01 record for `domain` (RFC 8555 §8.4)
pub fn dns01_owner(domain: &str) -> String {
    format!("_acme-challenge.{}", domain.trim_end_matches('.'))
}

/// The owner of a dns-account-01 record for `domain` and an account.
///
/// draft-ietf-acme-dns-account-label §3.1, for the account at `account_url`: "_" and the
/// lowercase base32 of the first 10 octets of SHA-256(account URL), then
/// `_acme-challenge`. Each account has its own record, so several ACME
/// clients (one per node) validate the same name at once without
/// overwriting each other's.
pub fn dns_account01_owner(domain: &str, account_url: &str) -> String {
    let digest = Sha256::digest(account_url.as_bytes());
    format!(
        "_{}._acme-challenge.{}",
        base32_lower(&digest[..10]),
        domain.trim_end_matches('.')
    )
}

/// RFC 4648 base32, lowercase, without padding
fn base32_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize],
        ));
    }
    out
}

/// Publishes and removes challenge records by signed DNS UPDATE.
#[derive(Debug, Clone)]
pub struct DnsUpdater {
    server: SocketAddr,
    key: TsigKey,
    propagation_timeout: Duration,
    ttl: u32,
}

impl DnsUpdater {
    /// The updater `config` describes, its secret read from its file
    pub fn from_config(config: &DnsUpdateConfig) -> anyhow::Result<Self> {
        let server: SocketAddr = config
            .server
            .parse()
            .map_err(|e| anyhow::anyhow!("acme.dns_update.server '{}': {e}", config.server))?;
        let text = std::fs::read_to_string(&config.secret_file).map_err(|e| {
            anyhow::anyhow!("acme.dns_update.secret_file {:?}: {e}", config.secret_file)
        })?;
        let secret = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|e| {
                anyhow::anyhow!(
                    "acme.dns_update.secret_file {:?} is not base64: {e}",
                    config.secret_file
                )
            })?;
        if secret.len() < 16 {
            return Err(anyhow::anyhow!(
                "acme.dns_update.secret_file {:?}: a {}-octet secret is too short for TSIG",
                config.secret_file,
                secret.len()
            ));
        }
        encode_name(&config.key_name).ok_or_else(|| {
            anyhow::anyhow!(
                "acme.dns_update.key_name '{}' is not a domain name",
                config.key_name
            )
        })?;
        Ok(Self {
            server,
            key: TsigKey {
                name: config.key_name.trim_end_matches('.').to_ascii_lowercase(),
                algorithm: Algorithm::parse(&config.algorithm)?,
                secret,
            },
            propagation_timeout: Duration::from_secs(config.propagation_timeout_secs),
            ttl: config.ttl,
        })
    }

    /// The challenge record for `owner` and `value`, with the zone it goes in
    pub async fn record(&self, owner: &str, value: &str) -> anyhow::Result<ChallengeRecord> {
        Ok(ChallengeRecord {
            zone: self.zone_of(owner).await?,
            owner: owner.trim_end_matches('.').to_ascii_lowercase(),
            value: value.to_string(),
        })
    }

    /// The zone `name` is in: the owner of the SOA the server returns for it,
    /// in the answer when `name` is the apex, else in the authority section.
    async fn zone_of(&self, name: &str) -> anyhow::Result<String> {
        let response = exchange(self.server, &query(name, TYPE_SOA)?).await?;
        let parsed = layout(&response)
            .ok_or_else(|| anyhow::anyhow!("the SOA answer for {name} does not parse"))?;
        parsed
            .answer
            .iter()
            .chain(&parsed.authority)
            .find(|r| r.rtype == TYPE_SOA)
            .and_then(|soa| read_name(&response, soa.name))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "{} names no zone for {name} (rcode {})",
                    self.server,
                    rcode(&response)
                )
            })
    }

    /// Adds the record
    pub async fn publish(&self, record: &ChallengeRecord) -> anyhow::Result<()> {
        let rdata = txt_rdata(&record.value)?;
        self.update(&record.zone, &record.owner, CLASS_IN, self.ttl, &rdata)
            .await?;
        info!(
            "ACME DNS: published {} TXT in {} through {}",
            record.owner, record.zone, self.server
        );
        Ok(())
    }

    /// Removes the record, that value alone (RFC 2136 §2.5.4)
    pub async fn withdraw(&self, record: &ChallengeRecord) -> anyhow::Result<()> {
        let rdata = txt_rdata(&record.value)?;
        self.update(&record.zone, &record.owner, CLASS_NONE, 0, &rdata)
            .await?;
        debug!("ACME DNS: removed {} TXT", record.owner);
        Ok(())
    }

    async fn update(
        &self,
        zone: &str,
        owner: &str,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> anyhow::Result<()> {
        let id: u16 = rand::random();
        let message = update_message(id, zone, owner, class, ttl, rdata)?;
        let (signed, mac) = sign(&message, &self.key, unix_now())?;
        let response = exchange(self.server, &signed).await?;
        verify_response(&response, &mac, id, &self.key, unix_now())?;
        match rcode(&response) {
            0 => Ok(()),
            code => Err(anyhow::anyhow!(
                "{} refused the update of {owner} TXT in {zone}: {}",
                self.server,
                rcode_name(code)
            )),
        }
    }

    /// Waits until every name server of the record's zone serves it, asking
    /// each over TCP at each of its addresses.
    pub async fn await_published(&self, record: &ChallengeRecord) -> anyhow::Result<()> {
        let servers = self.name_server_addresses(&record.zone).await?;
        if servers.is_empty() {
            return Err(anyhow::anyhow!(
                "the zone {} lists no name server address",
                record.zone
            ));
        }
        let deadline = Instant::now() + self.propagation_timeout;
        let mut waiting = servers;
        loop {
            let mut still = Vec::new();
            for server in waiting {
                if !self.serves(server, record).await {
                    still.push(server);
                }
            }
            if still.is_empty() {
                info!(
                    "ACME DNS: every name server of {} serves {} TXT",
                    record.zone, record.owner
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(anyhow::anyhow!(
                    "{} TXT not served after {}s by {}",
                    record.owner,
                    self.propagation_timeout.as_secs(),
                    still
                        .iter()
                        .map(SocketAddr::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            waiting = still;
            tokio::time::sleep(PROPAGATION_POLL).await;
        }
    }

    /// Whether `server` answers the record's TXT with its value
    async fn serves(&self, server: SocketAddr, record: &ChallengeRecord) -> bool {
        let Ok(query) = query(&record.owner, TYPE_TXT) else {
            return false;
        };
        match exchange(server, &query).await {
            Ok(response) => txt_values(&response).contains(&record.value),
            Err(e) => {
                debug!("ACME DNS: {server} not asked for {}: {e}", record.owner);
                false
            }
        }
    }

    /// The zone's name servers' addresses, port 53: the NS set from the
    /// update server, each name's A and AAAA from it where it holds them,
    /// else from the system's resolver.
    async fn name_server_addresses(&self, zone: &str) -> anyhow::Result<Vec<SocketAddr>> {
        let response = exchange(self.server, &query(zone, TYPE_NS)?).await?;
        let parsed = layout(&response)
            .ok_or_else(|| anyhow::anyhow!("the NS answer for {zone} does not parse"))?;
        let names: Vec<String> = parsed
            .answer
            .iter()
            .filter(|r| r.rtype == TYPE_NS)
            .filter_map(|r| read_name(&response, r.rdata))
            .collect();
        let mut addresses = Vec::new();
        for name in names {
            let mut found = Vec::new();
            for rtype in [TYPE_A, TYPE_AAAA] {
                if let Ok(answer) = exchange(self.server, &query(&name, rtype)?).await {
                    found.extend(addresses_in(&answer, rtype));
                }
            }
            if found.is_empty() {
                match tokio::net::lookup_host((name.as_str(), 53)).await {
                    Ok(resolved) => found.extend(resolved.map(|a| a.ip())),
                    Err(e) => warn!("ACME DNS: no address for name server {name}: {e}"),
                }
            }
            addresses.extend(found.into_iter().map(|ip| SocketAddr::new(ip, 53)));
        }
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A standard query, recursion not asked for
fn query(name: &str, rtype: u16) -> anyhow::Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    msg.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    msg.extend(encode_name(name).ok_or_else(|| anyhow::anyhow!("{name} is not a domain name"))?);
    msg.extend_from_slice(&rtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(msg)
}

/// The RDATA of a TXT record holding `value` as one string
fn txt_rdata(value: &str) -> anyhow::Result<Vec<u8>> {
    let length = u8::try_from(value.len())
        .map_err(|_| anyhow::anyhow!("a {}-octet TXT string is over 255", value.len()))?;
    let mut rdata = Vec::with_capacity(value.len() + 1);
    rdata.push(length);
    rdata.extend_from_slice(value.as_bytes());
    Ok(rdata)
}

/// An UPDATE (RFC 2136 §2) of `zone` with one RR for `owner`: class IN to
/// add it, NONE to delete that RR alone
fn update_message(
    id: u16,
    zone: &str,
    owner: &str,
    class: u16,
    ttl: u32,
    rdata: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let zone_wire =
        encode_name(zone).ok_or_else(|| anyhow::anyhow!("{zone} is not a zone name"))?;
    let owner_wire =
        encode_name(owner).ok_or_else(|| anyhow::anyhow!("{owner} is not a domain name"))?;
    let rdlength =
        u16::try_from(rdata.len()).map_err(|_| anyhow::anyhow!("RDATA over 65535 octets"))?;
    let mut msg =
        Vec::with_capacity(HEADER_LEN + zone_wire.len() + owner_wire.len() + rdata.len() + 14);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&(OPCODE_UPDATE << 11).to_be_bytes());
    // ZOCOUNT 1, PRCOUNT 0, UPCOUNT 1, ADCOUNT 0
    msg.extend_from_slice(&[0, 1, 0, 0, 0, 1, 0, 0]);
    msg.extend(zone_wire);
    msg.extend_from_slice(&TYPE_SOA.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg.extend(owner_wire);
    msg.extend_from_slice(&TYPE_TXT.to_be_bytes());
    msg.extend_from_slice(&class.to_be_bytes());
    msg.extend_from_slice(&ttl.to_be_bytes());
    msg.extend_from_slice(&rdlength.to_be_bytes());
    msg.extend_from_slice(rdata);
    Ok(msg)
}

/// The TSIG variables (RFC 8945 §4.3.3) after the message in the MAC's input
fn tsig_variables(key: &TsigKey, time: u64, error: u16, other: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut v = encode_name(&key.name).ok_or_else(|| anyhow::anyhow!("bad TSIG key name"))?;
    v.extend_from_slice(&CLASS_ANY.to_be_bytes());
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend(
        encode_name(key.algorithm.name()).ok_or_else(|| anyhow::anyhow!("bad algorithm name"))?,
    );
    v.extend_from_slice(&time.to_be_bytes()[2..]);
    v.extend_from_slice(&FUDGE.to_be_bytes());
    v.extend_from_slice(&error.to_be_bytes());
    v.extend_from_slice(&u16::try_from(other.len()).unwrap_or(0).to_be_bytes());
    v.extend_from_slice(other);
    Ok(v)
}

/// `message` with a TSIG record (RFC 8945 §4.2) signed at `time`, and its MAC
fn sign(message: &[u8], key: &TsigKey, time: u64) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut input = message.to_vec();
    input.extend(tsig_variables(key, time, 0, &[])?);
    let mac = key.algorithm.mac(&key.secret, &input);

    let algorithm =
        encode_name(key.algorithm.name()).ok_or_else(|| anyhow::anyhow!("bad algorithm name"))?;
    let mut rdata = algorithm;
    rdata.extend_from_slice(&time.to_be_bytes()[2..]);
    rdata.extend_from_slice(&FUDGE.to_be_bytes());
    rdata.extend_from_slice(&u16::try_from(mac.len()).unwrap_or(0).to_be_bytes());
    rdata.extend_from_slice(&mac);
    rdata.extend_from_slice(&message[0..2]);
    rdata.extend_from_slice(&[0, 0, 0, 0]);

    let mut signed = message.to_vec();
    signed.extend(encode_name(&key.name).ok_or_else(|| anyhow::anyhow!("bad TSIG key name"))?);
    signed.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    signed.extend_from_slice(&CLASS_ANY.to_be_bytes());
    signed.extend_from_slice(&0u32.to_be_bytes());
    signed.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
    signed.extend(rdata);
    let additional = u16_at(&signed, 10).unwrap_or(0) + 1;
    signed[10..12].copy_from_slice(&additional.to_be_bytes());
    Ok((signed, mac))
}

/// Checks a response's TSIG (RFC 8945 §5.3) against the request's MAC: the
/// last additional record, for our key and algorithm, a MAC over the
/// request MAC, the response without the TSIG (and with the request's ID),
/// and the TSIG variables, signed within the fudge of `now`.
fn verify_response(
    response: &[u8],
    request_mac: &[u8],
    request_id: u16,
    key: &TsigKey,
    now: u64,
) -> anyhow::Result<()> {
    if u16_at(response, 0) != Some(request_id) {
        return Err(anyhow::anyhow!("the response answers another message"));
    }
    let parsed = layout(response).ok_or_else(|| anyhow::anyhow!("the response does not parse"))?;
    let tsig = parsed
        .additional
        .last()
        .filter(|r| r.rtype == TYPE_TSIG)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the response is not signed (rcode {})",
                rcode_name(rcode(response))
            )
        })?;
    if read_name(response, tsig.name).as_deref() != Some(key.name.as_str()) {
        return Err(anyhow::anyhow!("the response is signed with another key"));
    }
    let rd = &response[tsig.rdata..tsig.end];
    let algorithm_end = crate::dns_wire::name_end(rd, 0)
        .ok_or_else(|| anyhow::anyhow!("the response's TSIG does not parse"))?;
    if read_name(rd, 0).as_deref() != Some(key.algorithm.name()) {
        return Err(anyhow::anyhow!(
            "the response's TSIG uses another algorithm"
        ));
    }
    let field = |at: usize, len: usize| rd.get(algorithm_end + at..algorithm_end + at + len);
    let time_bytes = field(0, 6).ok_or_else(|| anyhow::anyhow!("short TSIG"))?;
    let time = time_bytes
        .iter()
        .fold(0u64, |t, b| (t << 8) | u64::from(*b));
    let fudge = u16::from_be_bytes(
        field(6, 2)
            .ok_or_else(|| anyhow::anyhow!("short TSIG"))?
            .try_into()?,
    );
    let mac_len = usize::from(u16::from_be_bytes(
        field(8, 2)
            .ok_or_else(|| anyhow::anyhow!("short TSIG"))?
            .try_into()?,
    ));
    let mac = field(10, mac_len).ok_or_else(|| anyhow::anyhow!("short TSIG"))?;
    let rest = 10 + mac_len;
    let error = u16::from_be_bytes(
        field(rest + 2, 2)
            .ok_or_else(|| anyhow::anyhow!("short TSIG"))?
            .try_into()?,
    );
    let other_len = usize::from(u16::from_be_bytes(
        field(rest + 4, 2)
            .ok_or_else(|| anyhow::anyhow!("short TSIG"))?
            .try_into()?,
    ));
    let other = field(rest + 6, other_len).ok_or_else(|| anyhow::anyhow!("short TSIG"))?;
    if error != 0 {
        return Err(anyhow::anyhow!(
            "the server refused the TSIG: {}",
            tsig_error_name(error)
        ));
    }

    let mut unsigned = response[..tsig.name].to_vec();
    let additional = u16_at(response, 10).unwrap_or(1).saturating_sub(1);
    unsigned[10..12].copy_from_slice(&additional.to_be_bytes());
    let mut input = u16::try_from(request_mac.len())
        .unwrap_or(0)
        .to_be_bytes()
        .to_vec();
    input.extend_from_slice(request_mac);
    input.extend(unsigned);
    let mut variables = tsig_variables(key, time, error, other)?;
    // The response's own fudge, not ours
    let fudge_at = variables.len() - 6 - other.len();
    variables[fudge_at..fudge_at + 2].copy_from_slice(&fudge.to_be_bytes());
    input.extend(variables);
    let expected = key.algorithm.mac(&key.secret, &input);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(expected.as_slice(), mac)) {
        return Err(anyhow::anyhow!("the response's TSIG MAC does not verify"));
    }
    if now.abs_diff(time) > u64::from(fudge) {
        return Err(anyhow::anyhow!(
            "the response was signed {}s from now",
            now.abs_diff(time)
        ));
    }
    Ok(())
}

fn rcode(msg: &[u8]) -> u16 {
    u16_at(msg, 2).map(|flags| flags & 0x000F).unwrap_or(2)
}

fn rcode_name(code: u16) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "an unknown rcode",
    }
}

fn tsig_error_name(code: u16) -> &'static str {
    match code {
        16 => "BADSIG",
        17 => "BADKEY",
        18 => "BADTIME",
        22 => "BADTRUNC",
        _ => "an unknown TSIG error",
    }
}

/// The strings of every TXT record in a response's answer, each record's
/// strings joined (RFC 7208 §3.3 reading)
fn txt_values(msg: &[u8]) -> Vec<String> {
    let Some(parsed) = layout(msg) else {
        return Vec::new();
    };
    parsed
        .answer
        .iter()
        .filter(|r| r.rtype == TYPE_TXT)
        .filter_map(|r| {
            let mut rd = msg.get(r.rdata..r.end)?;
            let mut value = Vec::new();
            while let Some((&len, rest)) = rd.split_first() {
                value.extend_from_slice(rest.get(..usize::from(len))?);
                rd = &rest[usize::from(len)..];
            }
            String::from_utf8(value).ok()
        })
        .collect()
}

/// The addresses of every A or AAAA record in a response's answer
fn addresses_in(msg: &[u8], rtype: u16) -> Vec<IpAddr> {
    let Some(parsed) = layout(msg) else {
        return Vec::new();
    };
    parsed
        .answer
        .iter()
        .filter(|r| r.rtype == rtype)
        .filter_map(|r| match (rtype, msg.get(r.rdata..r.end)?) {
            (TYPE_A, rd) => <[u8; 4]>::try_from(rd).ok().map(IpAddr::from),
            (TYPE_AAAA, rd) => <[u8; 16]>::try_from(rd).ok().map(IpAddr::from),
            _ => None,
        })
        .collect()
}

/// One message and its answer over TCP (RFC 7766), within EXCHANGE_TIMEOUT
async fn exchange(server: SocketAddr, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let length = u16::try_from(message.len())
        .map_err(|_| anyhow::anyhow!("a {}-octet message is over 65535", message.len()))?;
    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let mut stream = TcpStream::connect(server).await?;
        let mut framed = length.to_be_bytes().to_vec();
        framed.extend_from_slice(message);
        stream.write_all(&framed).await?;
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut response).await?;
        if response.get(0..2) != message.get(0..2) {
            return Err(anyhow::anyhow!("{server} answered another message"));
        }
        Ok(response)
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "{server} did not answer within {}s",
            EXCHANGE_TIMEOUT.as_secs()
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> TsigKey {
        TsigKey {
            name: "acme-test".to_string(),
            algorithm: Algorithm::HmacSha256,
            secret: b"0123456789abcdef0123456789abcdef".to_vec(),
        }
    }

    /// The draft's example: SHA-256 of the account URL, first 10 octets,
    /// base32 lowercase, 16 characters.
    #[test]
    fn the_dns_account_01_label_is_base32_of_the_account_hash() {
        let owner = dns_account01_owner(
            "example.org.",
            "https://example.com/acme/acct/ExampleAccount",
        );
        let label = owner.split('.').next().unwrap();
        assert_eq!(label.len(), 17, "{owner}");
        assert!(label.starts_with('_'));
        assert!(label[1..]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b)));
        assert!(owner.ends_with("._acme-challenge.example.org"), "{owner}");
        assert_eq!(dns01_owner("example.org."), "_acme-challenge.example.org");
        // RFC 4648 §10 vectors, lowercase and unpadded
        assert_eq!(base32_lower(b"f"), "my");
        assert_eq!(base32_lower(b"fo"), "mzxq");
        assert_eq!(base32_lower(b"foo"), "mzxw6");
        assert_eq!(base32_lower(b"foob"), "mzxw6yq");
        assert_eq!(base32_lower(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_lower(b"foobar"), "mzxw6ytboi");
    }

    /// The UPDATE's sections, and a TSIG whose MAC covers the message and
    /// the TSIG variables, as an independent implementation computes it.
    #[test]
    fn an_update_is_built_and_signed() {
        let msg = update_message(
            0x1234,
            "example.com",
            "_acme-challenge.www.example.com",
            CLASS_IN,
            60,
            &txt_rdata("token").unwrap(),
        )
        .unwrap();
        assert_eq!(u16_at(&msg, 2), Some(0x2800), "opcode UPDATE");
        let parsed = layout(&msg).unwrap();
        assert_eq!(parsed.questions, 1, "one zone");
        assert_eq!(parsed.authority.len(), 1, "one update RR");
        assert_eq!(
            read_name(&msg, parsed.authority[0].name).as_deref(),
            Some("_acme-challenge.www.example.com")
        );

        let time = 1_792_900_000;
        let (signed, mac) = sign(&msg, &key(), time).unwrap();
        assert_eq!(u16_at(&signed, 10), Some(1), "ADCOUNT counts the TSIG");
        let parsed = layout(&signed).unwrap();
        let tsig = parsed.additional[0];
        assert_eq!(tsig.rtype, TYPE_TSIG);
        // MAC input recomputed by hand: message, then the variables
        let mut input = msg.clone();
        input.extend(b"\x09acme-test\x00\x00\xff\x00\x00\x00\x00\x0bhmac-sha256\x00");
        input.extend(&time.to_be_bytes()[2..]);
        input.extend(b"\x01\x2c\x00\x00\x00\x00");
        let mut expected = <Hmac<Sha256> as KeyInit>::new_from_slice(&key().secret).unwrap();
        expected.update(&input);
        assert_eq!(mac, expected.finalize().into_bytes().to_vec());
    }

    /// A response signed as RFC 8945 §5.3 says verifies; one with a
    /// changed byte, another key, or a stale time does not.
    #[test]
    fn a_signed_response_is_verified() {
        let request = update_message(
            7,
            "example.com",
            "_acme-challenge.example.com",
            CLASS_IN,
            60,
            &txt_rdata("v").unwrap(),
        )
        .unwrap();
        let (_, request_mac) = sign(&request, &key(), 1000).unwrap();
        // The response: the request's header with QR set and rcode 0, its zone section
        let mut response = request[..HEADER_LEN].to_vec();
        response[2] |= 0x80;
        response[8..10].copy_from_slice(&[0, 0]);
        let zone_end = crate::dns_wire::name_end(&request, HEADER_LEN).unwrap() + 4;
        response.extend_from_slice(&request[HEADER_LEN..zone_end]);
        // Signed by "the server": request MAC, response, variables
        let mut input = u16::try_from(request_mac.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        input.extend(&request_mac);
        input.extend(&response);
        input.extend(tsig_variables(&key(), 1001, 0, &[]).unwrap());
        let server_mac = key().algorithm.mac(&key().secret, &input);
        let mut rdata = encode_name("hmac-sha256").unwrap();
        rdata.extend(&1001u64.to_be_bytes()[2..]);
        rdata.extend(&FUDGE.to_be_bytes());
        rdata.extend(&u16::try_from(server_mac.len()).unwrap().to_be_bytes());
        rdata.extend(&server_mac);
        rdata.extend(&7u16.to_be_bytes());
        rdata.extend([0, 0, 0, 0]);
        let mut signed = response.clone();
        signed.extend(encode_name("acme-test").unwrap());
        signed.extend(TYPE_TSIG.to_be_bytes());
        signed.extend(CLASS_ANY.to_be_bytes());
        signed.extend(0u32.to_be_bytes());
        signed.extend(u16::try_from(rdata.len()).unwrap().to_be_bytes());
        signed.extend(&rdata);
        signed[10..12].copy_from_slice(&1u16.to_be_bytes());

        verify_response(&signed, &request_mac, 7, &key(), 1001).unwrap();
        assert!(
            verify_response(&signed, &request_mac, 8, &key(), 1001).is_err(),
            "another ID"
        );
        assert!(
            verify_response(&signed, &request_mac, 7, &key(), 1001 + 301).is_err(),
            "outside the fudge"
        );
        let other = TsigKey {
            secret: b"another secret, also 32 octets!!".to_vec(),
            ..key()
        };
        assert!(
            verify_response(&signed, &request_mac, 7, &other, 1001).is_err(),
            "another secret"
        );
        let mut tampered = signed.clone();
        tampered[3] ^= 0x01;
        assert!(
            verify_response(&tampered, &request_mac, 7, &key(), 1001).is_err(),
            "a changed byte"
        );
        assert!(
            verify_response(&response, &request_mac, 7, &key(), 1001).is_err(),
            "unsigned"
        );
    }

    #[test]
    fn txt_strings_are_joined_per_record() {
        let mut msg = query("_acme-challenge.example.com", TYPE_TXT).unwrap();
        msg[2] = 0x84;
        msg[7] = 1;
        msg.extend(b"\xC0\x0C\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x08\x03abc\x03def");
        assert_eq!(txt_values(&msg), vec!["abcdef".to_string()]);
    }
}
