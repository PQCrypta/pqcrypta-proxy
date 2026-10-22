//! DNS over HTTPS (RFC 8484) for the authoritative name server on this host.
//!
//! Knot DNS answers over UDP, TCP, TLS and QUIC but has no HTTP server, so the
//! name servers had no DoH at all. This is the gateway: a loopback HTTP/1.1
//! server that a route reaches like any other backend. DoH therefore gets every
//! client-facing property the proxy already has (HTTP/2 and HTTP/3,
//! post-quantum key exchange, ECH, the route's rate limits) without a second
//! implementation of any of them. Behind it the gateway asks the name server
//! over TCP (RFC 7766), so an answer of any size arrives whole: over UDP, a
//! signed answer larger than the server's payload limit comes back truncated.
//!
//! What the gateway adds on the way through:
//! - Only standard queries reach the name server. Zone transfers (a stream of
//!   messages that one HTTP response cannot carry) and every other opcode are
//!   answered here with REFUSED and an Extended DNS Error (RFC 8914). That also
//!   keeps the gateway's own address, which the name server sees on every
//!   query, from lending anything a privilege.
//! - `Cache-Control: max-age` from the answer's TTLs (RFC 8484 §5.1).
//! - Padding (RFC 7830) to a multiple of 468 octets, the response block length
//!   RFC 8467 §4.1 recommends, when the query carries the Padding option. The
//!   name server pads only on its own encrypted transports, and the hop to it
//!   is plain TCP.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use bytes::Bytes;
use http::header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use percent_encoding::percent_decode_str;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::config::DohConfig;

/// The media type of a DNS message in wire format (RFC 8484 §6).
pub const MEDIA_TYPE: &str = "application/dns-message";

/// Largest DNS message: its TCP length prefix is two octets.
const MAX_MESSAGE: usize = 65_535;
const HEADER_LEN: usize = 12;
/// RFC 8467 §4.1: pad responses to a multiple of 468 octets.
const RESPONSE_BLOCK: usize = 468;

const TYPE_SIG: u16 = 24;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;
const TYPE_TSIG: u16 = 250;
const TYPE_IXFR: u16 = 251;
const TYPE_AXFR: u16 = 252;

const OPTION_PADDING: u16 = 12;
const OPTION_EDE: u16 = 15;
/// RFC 8914 §4.22, "Not Supported".
const EDE_NOT_SUPPORTED: u16 = 21;
const EDE_TEXT: &[u8] = b"this DNS over HTTPS service answers standard queries only";

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u16 = 5;

/// The payload size a refusal advertises in its OPT record, the one the name
/// servers use (`udp-max-payload`).
const REFUSAL_UDP_PAYLOAD: u16 = 1232;

/// How long an idle connection to the name server is kept for reuse. Knot
/// closes an idle TCP connection after `tcp-idle-timeout`, 10 s by default;
/// stopping at half that means a reused connection is rarely one the server
/// has just closed. When it is, the exchange is retried once on a new one.
const UPSTREAM_IDLE: Duration = Duration::from_secs(5);
const UPSTREAM_MAX_IDLE: usize = 32;

/// The HTTP request head from the proxy must arrive within this.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// base64url as RFC 8484 §6 uses it: no padding, but padding is tolerated.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Bind `config.listen` and serve DNS over HTTPS there until the process ends.
/// Returns the bound address.
pub async fn spawn(config: &DohConfig) -> anyhow::Result<SocketAddr> {
    let upstream: SocketAddr = config
        .upstream
        .parse()
        .map_err(|e| anyhow::anyhow!("doh.upstream {:?}: {}", config.upstream, e))?;
    let listener = TcpListener::bind(&config.listen)
        .await
        .map_err(|e| anyhow::anyhow!("doh.listen {}: {}", config.listen, e))?;
    let local = listener.local_addr()?;
    let gateway = Arc::new(Gateway {
        path: config.path.clone(),
        timeout: Duration::from_millis(config.timeout_ms),
        upstream: Upstream {
            addr: upstream,
            idle: Mutex::new(Vec::new()),
        },
    });
    tokio::spawn(accept_loop(listener, gateway));
    Ok(local)
}

async fn accept_loop(listener: TcpListener, gateway: Arc<Gateway>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                // Out of descriptors, most likely: back off rather than spin.
                warn!("DNS over HTTPS gateway: accept failed: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let gateway = gateway.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let gateway = gateway.clone();
                async move { Ok::<_, Infallible>(gateway.handle(req).await) }
            });
            if let Err(e) = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                debug!("DNS over HTTPS gateway: connection ended: {}", e);
            }
        });
    }
}

struct Gateway {
    path: String,
    timeout: Duration,
    upstream: Upstream,
}

impl Gateway {
    async fn handle(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if req.uri().path() != self.path {
            return plain(StatusCode::NOT_FOUND, "not found");
        }
        if !accepts_dns_message(req.headers()) {
            return plain(
                StatusCode::NOT_ACCEPTABLE,
                "this endpoint answers application/dns-message only",
            );
        }
        let query = match read_query(req).await {
            Ok(query) => query,
            Err(response) => return response,
        };
        let Some(info) = inspect(&query) else {
            return plain(StatusCode::BAD_REQUEST, "malformed DNS query");
        };
        if !info.forwardable() {
            return dns_response(refusal(&query, &info));
        }
        match tokio::time::timeout(self.timeout, self.upstream.exchange(&query)).await {
            Ok(Ok(answer)) => {
                let answer = if info.padding {
                    padded(&answer).unwrap_or(answer)
                } else {
                    answer
                };
                dns_response(answer)
            }
            Ok(Err(e)) => {
                warn!("DNS over HTTPS gateway: name server failed: {}", e);
                plain(StatusCode::BAD_GATEWAY, "the name server did not answer")
            }
            Err(_) => {
                warn!(
                    "DNS over HTTPS gateway: no answer from the name server within {:?}",
                    self.timeout
                );
                plain(
                    StatusCode::GATEWAY_TIMEOUT,
                    "the name server did not answer in time",
                )
            }
        }
    }
}

/// The DNS query a request carries: the `dns` parameter of a GET or HEAD, the
/// body of a POST (RFC 8484 §4.1). Or the response that refuses it.
async fn read_query(req: Request<Incoming>) -> Result<Vec<u8>, Response<Full<Bytes>>> {
    match *req.method() {
        Method::GET | Method::HEAD => {
            let Some(encoded) = req.uri().query().and_then(dns_parameter) else {
                return Err(plain(
                    StatusCode::BAD_REQUEST,
                    "a GET request carries the query in the dns parameter",
                ));
            };
            let query = BASE64URL
                .decode(encoded.as_bytes())
                .map_err(|_| plain(StatusCode::BAD_REQUEST, "dns is not base64url"))?;
            if query.len() > MAX_MESSAGE {
                return Err(plain(StatusCode::PAYLOAD_TOO_LARGE, "query too large"));
            }
            Ok(query)
        }
        Method::POST => {
            let media_type = req
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .map(str::trim);
            if !media_type.is_some_and(|t| t.eq_ignore_ascii_case(MEDIA_TYPE)) {
                return Err(plain(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "a POST request carries an application/dns-message body",
                ));
            }
            match Limited::new(req.into_body(), MAX_MESSAGE).collect().await {
                Ok(body) => Ok(body.to_bytes().to_vec()),
                Err(e) if e.is::<http_body_util::LengthLimitError>() => {
                    Err(plain(StatusCode::PAYLOAD_TOO_LARGE, "query too large"))
                }
                Err(_) => Err(plain(StatusCode::BAD_REQUEST, "unreadable body")),
            }
        }
        _ => {
            let mut response = plain(StatusCode::METHOD_NOT_ALLOWED, "GET, HEAD or POST");
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("GET, HEAD, POST"));
            Err(response)
        }
    }
}

/// The value of the first `dns` parameter in a query string, percent-decoded.
fn dns_parameter(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .map(|v| percent_decode_str(v).decode_utf8_lossy().into_owned())
}

/// Whether the client takes `application/dns-message`. With no Accept header
/// at all it takes anything (RFC 9110 §12.5.1); RFC 8484 §4.1 asks clients to
/// send one.
fn accepts_dns_message(headers: &HeaderMap) -> bool {
    let mut any = false;
    for value in headers.get_all(ACCEPT) {
        let Ok(value) = value.to_str() else { continue };
        for range in value.split(',') {
            any = true;
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or_default().trim();
            let refused = parts.any(|p| {
                let p = p.trim();
                p.get(..2).is_some_and(|k| k.eq_ignore_ascii_case("q="))
                    && p[2..].trim().parse::<f32>().is_ok_and(|q| q <= 0.0)
            });
            if !refused
                && (media.eq_ignore_ascii_case(MEDIA_TYPE)
                    || media.eq_ignore_ascii_case("application/*")
                    || media == "*/*")
            {
                return true;
            }
        }
    }
    !any
}

fn plain(status: StatusCode, text: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(text.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn dns_response(message: Vec<u8>) -> Response<Full<Bytes>> {
    let cache = freshness(&message)
        .and_then(|secs| HeaderValue::from_str(&format!("max-age={secs}")).ok())
        .unwrap_or_else(|| HeaderValue::from_static("no-store"));
    let mut response = Response::new(Full::new(Bytes::from(message)));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    response.headers_mut().insert(CACHE_CONTROL, cache);
    response
}

/// Connections to the name server, kept for reuse. Each carries one query at a
/// time, so an answer always belongs to the query just sent on it.
struct Upstream {
    addr: SocketAddr,
    idle: Mutex<Vec<(TcpStream, Instant)>>,
}

impl Upstream {
    async fn exchange(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        if let Some(stream) = self.take_idle() {
            match self.round_trip(stream, query).await {
                Ok(answer) => return Ok(answer),
                // Closed by the server since it was last used, most likely.
                Err(e) => debug!("DNS over HTTPS gateway: reused connection failed: {}", e),
            }
        }
        let stream = TcpStream::connect(self.addr).await?;
        stream.set_nodelay(true)?;
        self.round_trip(stream, query).await
    }

    async fn round_trip(&self, mut stream: TcpStream, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let length = u16::try_from(query.len())?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;

        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await?;
        let mut answer = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut answer).await?;
        let answers_query = answer.len() >= HEADER_LEN
            && answer.get(..2) == query.get(..2)
            && answer.get(2).is_some_and(|flags| flags & 0x80 != 0);
        if !answers_query {
            anyhow::bail!("the name server sent a message that does not answer the query");
        }
        self.put_idle(stream);
        Ok(answer)
    }

    fn take_idle(&self) -> Option<TcpStream> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        while let Some((stream, since)) = idle.pop() {
            if since.elapsed() < UPSTREAM_IDLE {
                return Some(stream);
            }
        }
        None
    }

    fn put_idle(&self, stream: TcpStream) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < UPSTREAM_MAX_IDLE {
            idle.push((stream, Instant::now()));
        }
    }
}

// ---------------------------------------------------------------------------
// The DNS message format (RFC 1035 §4), as far as the gateway reads it. Every
// read is bounds-checked: these bytes come from the client, and a release
// build aborts the whole process on a panic.
// ---------------------------------------------------------------------------

fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    let b = msg.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(msg: &[u8], at: usize) -> Option<u32> {
    let b = msg.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// One past the last octet of the name that starts at `at`. A compression
/// pointer ends a name and is not followed, so a pointer loop cannot spin.
fn name_end(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *msg.get(at)?;
        match length & 0xC0 {
            0x00 if length == 0 => return Some(at + 1),
            0x00 => at = at.checked_add(1 + usize::from(length))?,
            0xC0 => {
                msg.get(at + 1)?;
                return Some(at + 2);
            }
            // 0x40 and 0x80: label types RFC 6891 §5 retired.
            _ => return None,
        }
    }
}

/// Where one resource record's parts sit in a message.
#[derive(Clone, Copy, Debug)]
struct Record {
    rtype: u16,
    ttl: u32,
    /// Offset of the RDATA; its two-octet length sits just before it.
    rdata: usize,
    rdlength: usize,
    end: usize,
}

fn record_at(msg: &[u8], at: usize) -> Option<Record> {
    let fixed = name_end(msg, at)?;
    let rtype = u16_at(msg, fixed)?;
    let ttl = u32_at(msg, fixed + 4)?;
    let rdlength = usize::from(u16_at(msg, fixed + 8)?);
    let rdata = fixed + 10;
    let end = rdata + rdlength;
    (end <= msg.len()).then_some(Record {
        rtype,
        ttl,
        rdata,
        rdlength,
        end,
    })
}

/// A message's sections. `None` when any of them runs past the end.
#[derive(Debug)]
struct Layout {
    questions: usize,
    question_end: usize,
    answer: Vec<Record>,
    authority: Vec<Record>,
    additional: Vec<Record>,
}

fn layout(msg: &[u8]) -> Option<Layout> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let count = |i: usize| u16_at(msg, 4 + 2 * i).map(usize::from);
    let questions = count(0)?;
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = name_end(msg, at)? + 4;
        if at > msg.len() {
            return None;
        }
    }
    let question_end = at;
    let mut section = |n: usize| -> Option<Vec<Record>> {
        let mut records = Vec::with_capacity(n.min(64));
        for _ in 0..n {
            let record = record_at(msg, at)?;
            at = record.end;
            records.push(record);
        }
        Some(records)
    };
    let answer = section(count(1)?)?;
    let authority = section(count(2)?)?;
    let additional = section(count(3)?)?;
    Some(Layout {
        questions,
        question_end,
        answer,
        authority,
        additional,
    })
}

/// The options in an OPT record's RDATA as (code, offset, end of option).
/// `None` when they do not exactly fill it.
fn options(msg: &[u8], opt: &Record) -> Option<Vec<(u16, usize, usize)>> {
    let mut found = Vec::new();
    let mut at = opt.rdata;
    while at < opt.end {
        let code = u16_at(msg, at)?;
        let end = at + 4 + usize::from(u16_at(msg, at + 2)?);
        if end > opt.end {
            return None;
        }
        found.push((code, at, end));
        at = end;
    }
    Some(found)
}

/// What the gateway reads from a query before anything goes upstream.
#[derive(Debug)]
struct QueryInfo {
    flags: u16,
    questions: usize,
    question_end: usize,
    /// The question's type, for a query with exactly one question.
    qtype: Option<u16>,
    /// The query has an OPT record (EDNS, RFC 6891).
    edns: bool,
    /// Its DNSSEC OK bit.
    dnssec_ok: bool,
    /// It carries the Padding option, asking for a padded response.
    padding: bool,
}

impl QueryInfo {
    fn opcode(&self) -> u16 {
        (self.flags >> 11) & 0x0F
    }

    /// A standard query for anything but a zone transfer.
    fn forwardable(&self) -> bool {
        self.opcode() == 0 && !matches!(self.qtype, Some(TYPE_AXFR | TYPE_IXFR))
    }
}

/// `None` for anything that is not a well-formed query: too short, a response
/// (QR set), or sections that run past the end.
fn inspect(msg: &[u8]) -> Option<QueryInfo> {
    let flags = u16_at(msg, 2)?;
    if flags & 0x8000 != 0 {
        return None;
    }
    let layout = layout(msg)?;
    let qtype = (layout.questions == 1)
        .then(|| u16_at(msg, layout.question_end - 4))
        .flatten();
    let opt = layout.additional.iter().find(|r| r.rtype == TYPE_OPT);
    let padding = opt
        .and_then(|opt| options(msg, opt))
        .is_some_and(|options| options.iter().any(|(code, ..)| *code == OPTION_PADDING));
    Some(QueryInfo {
        flags,
        questions: layout.questions,
        question_end: layout.question_end,
        qtype,
        edns: opt.is_some(),
        dnssec_ok: opt.is_some_and(|opt| opt.ttl & 0x8000 != 0),
        padding,
    })
}

/// REFUSED, answered here, for a query the gateway does not forward: the
/// query's ID, opcode, RD and question, and for an EDNS query an OPT record
/// with an Extended DNS Error saying why (RFC 8914 §4.22), padded on request.
fn refusal(query: &[u8], info: &QueryInfo) -> Vec<u8> {
    let echo_question = info.questions == 1;
    let mut out = Vec::with_capacity(HEADER_LEN + info.question_end + 96);
    out.extend_from_slice(query.get(..2).unwrap_or(&[0, 0]));
    let flags = 0x8000 | (info.flags & 0x7800) | (info.flags & 0x0100) | RCODE_REFUSED;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&u16::from(echo_question).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16::from(info.edns).to_be_bytes());
    if echo_question {
        // Copied verbatim to the same offset, so a compression pointer inside
        // the question still points where it did.
        out.extend_from_slice(query.get(HEADER_LEN..info.question_end).unwrap_or_default());
    }
    if info.edns {
        let ede_length = 2 + EDE_TEXT.len();
        out.push(0); // root owner name
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&REFUSAL_UDP_PAYLOAD.to_be_bytes());
        let dnssec_ok: u32 = if info.dnssec_ok { 0x8000 } else { 0 };
        out.extend_from_slice(&dnssec_ok.to_be_bytes());
        out.extend_from_slice(&u16::try_from(4 + ede_length).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&OPTION_EDE.to_be_bytes());
        out.extend_from_slice(&u16::try_from(ede_length).unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&EDE_NOT_SUPPORTED.to_be_bytes());
        out.extend_from_slice(EDE_TEXT);
    }
    if info.padding {
        if let Some(padded) = padded(&out) {
            return padded;
        }
    }
    out
}

/// `msg` padded to a multiple of [`RESPONSE_BLOCK`] with the EDNS Padding
/// option, replacing any padding it already carries. `None`, to send it as it
/// is, when it has no OPT record to carry the option, when its options are
/// malformed, or when a TSIG or SIG(0) record signs the bytes this changes.
fn padded(msg: &[u8]) -> Option<Vec<u8>> {
    let layout = layout(msg)?;
    if layout
        .additional
        .iter()
        .any(|r| r.rtype == TYPE_TSIG || r.rtype == TYPE_SIG)
    {
        return None;
    }
    let opt = layout.additional.iter().find(|r| r.rtype == TYPE_OPT)?;
    let mut kept = Vec::new();
    for (code, start, end) in options(msg, opt)? {
        if code != OPTION_PADDING {
            kept.extend_from_slice(msg.get(start..end)?);
        }
    }
    let unpadded = msg.len() - opt.rdlength + kept.len() + 4;
    let fill = (RESPONSE_BLOCK - unpadded % RESPONSE_BLOCK) % RESPONSE_BLOCK;
    if unpadded + fill > MAX_MESSAGE {
        return None;
    }
    let rdlength = u16::try_from(kept.len() + 4 + fill).ok()?;
    let fill_length = u16::try_from(fill).ok()?;
    let mut out = Vec::with_capacity(unpadded + fill);
    out.extend_from_slice(msg.get(..opt.rdata - 2)?);
    out.extend_from_slice(&rdlength.to_be_bytes());
    out.extend_from_slice(&kept);
    out.extend_from_slice(&OPTION_PADDING.to_be_bytes());
    out.extend_from_slice(&fill_length.to_be_bytes());
    out.resize(out.len() + fill, 0);
    out.extend_from_slice(msg.get(opt.end..)?);
    Some(out)
}

/// The HTTP freshness lifetime for a response, in seconds (RFC 8484 §5.1): no
/// more than the smallest TTL in the answer section, nor, where the authority
/// section has an SOA (a negative answer), than that record's TTL and its
/// MINIMUM (RFC 2308 §5). A referral, with no answer and no SOA, is bounded by
/// its authority records. `None` for a response nothing should cache: an error
/// RCODE, or one with no records to take a lifetime from.
fn freshness(msg: &[u8]) -> Option<u32> {
    let rcode = msg.get(3)? & 0x0F;
    if rcode != RCODE_NOERROR && rcode != RCODE_NXDOMAIN {
        return None;
    }
    let layout = layout(msg)?;
    // RFC 2181 §8: a TTL with the top bit set is read as zero.
    let ttl = |value: u32| if value > 0x7FFF_FFFF { 0 } else { value };
    let soa = layout
        .authority
        .iter()
        .find(|r| r.rtype == TYPE_SOA && r.rdlength >= 22)
        .and_then(|soa| Some(ttl(soa.ttl).min(ttl(u32_at(msg, soa.end - 4)?))));
    let answer = layout.answer.iter().map(|r| ttl(r.ttl)).min();
    match (answer, soa) {
        (Some(a), Some(s)) => Some(a.min(s)),
        (Some(a), None) => Some(a),
        (None, Some(s)) => Some(s),
        (None, None) => layout.authority.iter().map(|r| ttl(r.ttl)).min(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A query for `pqcrypta.com.` of `qtype`, ID 0 as RFC 8484 §4.1 asks,
    /// with an OPT record when `edns`, carrying the Padding option when `pad`.
    fn query(qtype: u16, opcode: u16, edns: bool, pad: bool) -> Vec<u8> {
        let mut q = vec![0, 0];
        q.extend_from_slice(&((opcode << 11) | 0x0100).to_be_bytes());
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
        q.extend_from_slice(b"\x08pqcrypta\x03com\x00");
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        if edns {
            q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0]);
            if pad {
                q.extend_from_slice(&[0, 8, 0, 12, 0, 4, 0, 0, 0, 0]);
            } else {
                q.extend_from_slice(&[0, 0]);
            }
        }
        q
    }

    /// An authoritative answer to `q`: one A record with `ttl`, then an OPT
    /// record (no options) when the query had one.
    fn answer(q: &[u8], ttl: u32) -> Vec<u8> {
        let info = inspect(q).expect("test query parses");
        let mut a = q[..2].to_vec();
        a.extend_from_slice(&[0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, u8::from(info.edns)]);
        a.extend_from_slice(&q[HEADER_LEN..info.question_end]);
        a.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        a.extend_from_slice(&ttl.to_be_bytes());
        a.extend_from_slice(&[0, 4, 192, 0, 2, 1]);
        if info.edns {
            a.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        }
        a
    }

    /// An NXDOMAIN with an SOA of TTL `soa_ttl` and MINIMUM `minimum`.
    fn negative(q: &[u8], soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let info = inspect(q).expect("test query parses");
        let mut a = q[..2].to_vec();
        a.extend_from_slice(&[0x85, 0x03, 0, 1, 0, 0, 0, 1, 0, 0]);
        a.extend_from_slice(&q[HEADER_LEN..info.question_end]);
        a.extend_from_slice(&[0xC0, 0x0C, 0, 6, 0, 1]);
        a.extend_from_slice(&soa_ttl.to_be_bytes());
        let mut rdata = b"\x03ns1\xC0\x0C\x07contact\xC0\x0C".to_vec();
        for v in [1u32, 7200, 3600, 1_209_600, minimum] {
            rdata.extend_from_slice(&v.to_be_bytes());
        }
        a.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        a.extend_from_slice(&rdata);
        a
    }

    fn rcode(msg: &[u8]) -> u8 {
        msg[3] & 0x0F
    }

    #[test]
    fn names_end_at_the_root_label_or_a_pointer() {
        let msg = b"\x03www\x07example\x03com\x00\xC0\x00";
        assert_eq!(name_end(msg, 0), Some(17));
        assert_eq!(name_end(msg, 17), Some(19));
        assert_eq!(name_end(b"\x03www", 0), None, "runs past the end");
        assert_eq!(name_end(b"\x41abc\x00", 0), None, "retired label type");
        assert_eq!(name_end(b"\xC0", 0), None, "half a pointer");
    }

    #[test]
    fn standard_queries_are_forwarded_and_the_rest_refused() {
        assert!(inspect(&query(1, 0, false, false)).unwrap().forwardable());
        assert!(inspect(&query(65, 0, true, false)).unwrap().forwardable());
        for refused in [query(252, 0, false, false), query(251, 0, true, false)] {
            assert!(!inspect(&refused).unwrap().forwardable(), "zone transfer");
        }
        for opcode in [1, 2, 4, 5, 6, 15] {
            let q = query(6, opcode, false, false);
            assert!(!inspect(&q).unwrap().forwardable(), "opcode {opcode}");
        }
    }

    #[test]
    fn responses_and_truncated_queries_are_malformed() {
        let mut q = query(1, 0, false, false);
        q[2] |= 0x80;
        assert!(inspect(&q).is_none(), "QR set");
        let q = query(1, 0, true, false);
        assert!(inspect(&q[..q.len() - 3]).is_none(), "OPT cut short");
        assert!(inspect(&q[..11]).is_none(), "short header");
        assert!(inspect(&[]).is_none());
    }

    #[test]
    fn the_padding_option_and_dnssec_ok_are_read_from_the_opt_record() {
        let info = inspect(&query(1, 0, true, true)).unwrap();
        assert!(info.edns && info.padding && info.dnssec_ok);
        let info = inspect(&query(1, 0, true, false)).unwrap();
        assert!(info.edns && !info.padding);
        let info = inspect(&query(1, 0, false, false)).unwrap();
        assert!(!info.edns && !info.padding && !info.dnssec_ok);
    }

    #[test]
    fn a_refusal_echoes_the_query_and_says_why() {
        let q = query(252, 0, true, false);
        let info = inspect(&q).unwrap();
        let r = refusal(&q, &info);
        let layout = layout(&r).expect("refusal parses");
        assert_eq!(rcode(&r), 5);
        assert_eq!(r[2] & 0x80, 0x80, "QR");
        assert_eq!(&r[..2], &q[..2], "ID");
        assert_eq!(
            &r[HEADER_LEN..layout.question_end],
            &q[HEADER_LEN..info.question_end]
        );
        let opt = layout
            .additional
            .iter()
            .find(|r| r.rtype == TYPE_OPT)
            .unwrap();
        assert_eq!(opt.ttl & 0x8000, 0x8000, "DO copied");
        let (code, start, _) = options(&r, opt).unwrap()[0];
        assert_eq!(code, OPTION_EDE);
        assert_eq!(u16_at(&r, start + 4), Some(EDE_NOT_SUPPORTED));

        let without_edns = refusal(
            &query(1, 4, false, false),
            &inspect(&query(1, 4, false, false)).unwrap(),
        );
        assert_eq!(rcode(&without_edns), 5);
        assert!(
            layout(&without_edns).unwrap().additional.is_empty(),
            "no OPT for a non-EDNS query"
        );
        assert_eq!((without_edns[2] >> 3) & 0x0F, 4, "opcode copied");

        let q = query(252, 0, true, true);
        assert_eq!(
            refusal(&q, &inspect(&q).unwrap()).len() % RESPONSE_BLOCK,
            0,
            "padded on request"
        );
    }

    #[test]
    fn padding_fills_to_the_block_length_and_replaces_existing_padding() {
        let q = query(1, 0, true, true);
        let a = answer(&q, 300);
        let p = padded(&a).expect("has an OPT record");
        assert_eq!(p.len() % RESPONSE_BLOCK, 0);
        let layout = layout(&p).expect("padded message parses");
        let opt = layout
            .additional
            .iter()
            .find(|r| r.rtype == TYPE_OPT)
            .unwrap();
        let opts = options(&p, opt).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].0, OPTION_PADDING);
        assert_eq!(
            &p[..a.len() - 4],
            &a[..a.len() - 4],
            "everything before the option untouched"
        );
        let again = padded(&p).expect("re-pad");
        assert_eq!(again, p, "existing padding is replaced, not stacked");

        let no_opt = answer(&query(1, 0, false, false), 300);
        assert!(padded(&no_opt).is_none(), "nowhere to put the option");
    }

    #[test]
    fn a_signed_message_is_never_padded() {
        let q = query(1, 0, true, true);
        let mut a = answer(&q, 300);
        a[11] = 2; // ARCOUNT: the OPT record and a TSIG
        a.extend_from_slice(&[0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 0]);
        assert!(layout(&a).is_some());
        assert!(padded(&a).is_none());
    }

    #[test]
    fn freshness_is_the_smallest_ttl_and_negative_answers_follow_the_soa() {
        let q = query(1, 0, false, false);
        assert_eq!(freshness(&answer(&q, 300)), Some(300));
        assert_eq!(freshness(&answer(&q, 0x8000_0000)), Some(0), "RFC 2181 §8");
        assert_eq!(freshness(&negative(&q, 3600, 600)), Some(600), "MINIMUM");
        assert_eq!(
            freshness(&negative(&q, 60, 600)),
            Some(60),
            "the SOA's own TTL"
        );
        let mut servfail = answer(&q, 300);
        servfail[3] = (servfail[3] & 0xF0) | 2;
        assert_eq!(freshness(&servfail), None);
        let r = refusal(&q, &inspect(&q).unwrap());
        assert_eq!(freshness(&r), None, "REFUSED is not cached");
    }

    #[test]
    fn the_dns_parameter_is_base64url_with_or_without_padding() {
        assert_eq!(dns_parameter("ct=x&dns=AAAB&x=1").as_deref(), Some("AAAB"));
        assert_eq!(dns_parameter("dns=AA%3D%3D").as_deref(), Some("AA=="));
        assert_eq!(dns_parameter("name=example.com"), None);
        assert_eq!(BASE64URL.decode("AA").unwrap(), vec![0]);
        assert_eq!(BASE64URL.decode("AA==").unwrap(), vec![0]);
        assert_eq!(BASE64URL.decode("-_8").unwrap(), vec![0xfb, 0xff]);
        assert!(BASE64URL.decode("+/8").is_err(), "standard alphabet");
    }

    #[test]
    fn accept_must_admit_dns_message_when_present() {
        let with = |v: &'static str| {
            let mut h = HeaderMap::new();
            h.insert(ACCEPT, HeaderValue::from_static(v));
            accepts_dns_message(&h)
        };
        assert!(accepts_dns_message(&HeaderMap::new()));
        assert!(with("application/dns-message"));
        assert!(with("text/html, */*;q=0.8"));
        assert!(with("Application/*"));
        assert!(!with("application/dns-json"));
        assert!(!with("application/dns-message;q=0"));
    }

    /// Mutated queries and answers through every parser: none may panic, and a
    /// padded result is always a whole number of blocks that still parses.
    #[test]
    fn fuzz_the_message_parsers() {
        let q = query(1, 0, true, true);
        for seed in [q.clone(), answer(&q, 300), negative(&q, 3600, 600)] {
            crate::fuzz_support::fuzz_bytes(&seed, 20_000, |m| {
                if let Some(info) = inspect(m) {
                    let r = refusal(m, &info);
                    assert!(layout(&r).is_some(), "refusal must parse");
                }
                let _ = freshness(m);
                if let Some(p) = padded(m) {
                    assert_eq!(p.len() % RESPONSE_BLOCK, 0);
                    assert!(layout(&p).is_some(), "padded message must parse");
                }
            });
        }
    }

    #[test]
    fn the_gateway_listens_on_loopback_only() {
        let valid = DohConfig {
            enabled: true,
            ..DohConfig::default()
        };
        assert!(valid.validate().is_ok());
        for listen in [
            "0.0.0.0:8053",
            "66.179.95.51:8053",
            "[::]:8053",
            "localhost:8053",
        ] {
            let config = DohConfig {
                listen: listen.into(),
                ..valid.clone()
            };
            assert!(config.validate().is_err(), "{listen}");
        }
        assert!(DohConfig {
            listen: "[::1]:8053".into(),
            ..valid.clone()
        }
        .validate()
        .is_ok());
        assert!(DohConfig {
            path: "dns-query".into(),
            ..valid.clone()
        }
        .validate()
        .is_err());
        assert!(DohConfig {
            path: "/q?dns".into(),
            ..valid.clone()
        }
        .validate()
        .is_err());
        assert!(DohConfig {
            upstream: "ns1:53".into(),
            ..valid.clone()
        }
        .validate()
        .is_err());
        assert!(DohConfig {
            timeout_ms: 0,
            ..valid
        }
        .validate()
        .is_err());
    }

    // --- end to end: an HTTP client, the gateway, a scripted name server ----

    /// A name server on loopback that answers every query on a connection with
    /// [`answer`] (TTL 300), closing the connection after `per_connection`
    /// answers. Counts the queries it receives.
    async fn name_server(per_connection: usize) -> (SocketAddr, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = counter.clone();
                tokio::spawn(async move {
                    for _ in 0..per_connection {
                        let mut prefix = [0u8; 2];
                        if stream.read_exact(&mut prefix).await.is_err() {
                            return;
                        }
                        let mut q = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
                        if stream.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        counter.fetch_add(1, Ordering::SeqCst);
                        let a = answer(&q, 300);
                        let mut framed = u16::try_from(a.len()).unwrap().to_be_bytes().to_vec();
                        framed.extend_from_slice(&a);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    async fn gateway(upstream: SocketAddr) -> SocketAddr {
        spawn(&DohConfig {
            enabled: true,
            listen: "127.0.0.1:0".into(),
            upstream: upstream.to_string(),
            path: "/dns-query".into(),
            timeout_ms: 2000,
        })
        .await
        .unwrap()
    }

    async fn send<B>(addr: SocketAddr, req: Request<B>) -> (StatusCode, HeaderMap, Vec<u8>)
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let stream = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let response = sender.send_request(req).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, body)
    }

    fn get(path_and_query: &str) -> Request<Empty<Bytes>> {
        Request::get(path_and_query)
            .header("host", "ns1.pqcrypta.com")
            .header(ACCEPT, MEDIA_TYPE)
            .body(Empty::new())
            .unwrap()
    }

    fn post(body: Vec<u8>, content_type: &str) -> Request<Full<Bytes>> {
        Request::post("/dns-query")
            .header("host", "ns1.pqcrypta.com")
            .header(CONTENT_TYPE, content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap()
    }

    #[tokio::test]
    async fn get_and_post_reach_the_name_server_and_carry_its_answer() {
        let (ns, seen) = name_server(usize::MAX).await;
        let gw = gateway(ns).await;
        let q = query(1, 0, false, false);

        let (status, headers, body) =
            send(gw, get(&format!("/dns-query?dns={}", BASE64URL.encode(&q)))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[CONTENT_TYPE], MEDIA_TYPE);
        assert_eq!(headers[CACHE_CONTROL], "max-age=300");
        assert_eq!(body, answer(&q, 300));

        let (status, _, body) = send(gw, post(q.clone(), MEDIA_TYPE)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, answer(&q, 300));
        assert_eq!(seen.load(Ordering::SeqCst), 2);

        let padded_q = query(1, 0, true, true);
        let (_, _, body) = send(gw, post(padded_q, MEDIA_TYPE)).await;
        assert_eq!(body.len() % RESPONSE_BLOCK, 0, "padded on request");
    }

    #[tokio::test]
    async fn requests_that_are_not_doh_are_refused_over_http() {
        let (ns, seen) = name_server(usize::MAX).await;
        let gw = gateway(ns).await;
        let q = query(1, 0, false, false);

        assert_eq!(
            send(gw, post(q.clone(), "text/plain")).await.0,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(send(gw, get("/dns-query")).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            send(gw, get("/dns-query?dns=***")).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            send(gw, get("/dns-query?dns=AAAA")).await.0,
            StatusCode::BAD_REQUEST,
            "3 octets is no query"
        );
        assert_eq!(send(gw, get("/other")).await.0, StatusCode::NOT_FOUND);
        let put = Request::put("/dns-query")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let (status, headers, _) = send(gw, put).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers[ALLOW], "GET, HEAD, POST");
        let json = Request::get(format!("/dns-query?dns={}", BASE64URL.encode(&q)))
            .header(ACCEPT, "application/dns-json")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(send(gw, json).await.0, StatusCode::NOT_ACCEPTABLE);
        assert_eq!(
            seen.load(Ordering::SeqCst),
            0,
            "none of them reached the name server"
        );
    }

    #[tokio::test]
    async fn zone_transfers_and_other_opcodes_never_reach_the_name_server() {
        let (ns, seen) = name_server(usize::MAX).await;
        let gw = gateway(ns).await;
        for q in [
            query(252, 0, true, false),
            query(6, 4, false, false),
            query(6, 5, true, false),
        ] {
            let (status, headers, body) = send(gw, post(q, MEDIA_TYPE)).await;
            assert_eq!(status, StatusCode::OK, "a DNS answer, carried by HTTP");
            assert_eq!(rcode(&body), 5);
            assert_eq!(headers[CACHE_CONTROL], "no-store");
        }
        assert_eq!(seen.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_connection_the_name_server_closed_is_replaced() {
        // One answer per connection: every reuse finds the connection closed.
        let (ns, seen) = name_server(1).await;
        let gw = gateway(ns).await;
        let q = query(1, 0, false, false);
        for _ in 0..3 {
            let (status, _, body) = send(gw, post(q.clone(), MEDIA_TYPE)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, answer(&q, 300));
        }
        assert_eq!(seen.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn no_name_server_is_a_bad_gateway() {
        let unused = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let gw = gateway(unused).await;
        let q = query(1, 0, false, false);
        assert_eq!(
            send(gw, post(q, MEDIA_TYPE)).await.0,
            StatusCode::BAD_GATEWAY
        );
    }
}
