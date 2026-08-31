//! The conformance vhost's own pages.
//!
//! These are ordinary HTTP — deliberately so. Everything awkward happens on the
//! per-test UDP ports; this side has to be completely unremarkable, because it
//! is where a developer starts a run, reads what went wrong, and takes a badge
//! away.
//!
//! ```text
//! GET  /                     what this is, and how to run it
//! POST /session              start a session, returns its id
//! GET  /catalog.json         every test, its port, and the clause it exercises
//! GET  /report/<id>.json     results, for CI
//! GET  /report/<id>          results, for a person
//! GET  /badge/<id>.svg       results, for a README
//! ```

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Response, StatusCode};

use super::report;
use super::Conformance;

/// Answer a request on the conformance vhost, or `None` to let it route
/// normally.
pub fn route(
    conformance: &Arc<Conformance>,
    method: &Method,
    path: &str,
    client_ip: std::net::IpAddr,
) -> Option<Response<Body>> {
    match (method, path) {
        (&Method::GET, "/" | "/index.html") => Some(index(conformance)),
        (&Method::POST, "/session") => Some(new_session(conformance, client_ip)),
        (&Method::GET, "/catalog.json") => Some(catalog_json(conformance)),
        (&Method::GET, "/css/conformance.css") => Some(stylesheet()),
        // Page furniture. This is its own origin under `default-src 'self'`, so
        // every asset the page references has to be served from here — it cannot
        // borrow the site's copies across the hostname boundary.
        (&Method::GET, "/css/bg.css") => Some(asset_css(include_str!("assets/bg.css"))),
        (&Method::GET, "/css/cursor.css") => Some(asset_css(include_str!("assets/cursor.css"))),
        (&Method::GET, "/js/bg.js") => Some(asset_js(include_str!("assets/bg.js"))),
        (&Method::GET, "/js/cursor.js") => Some(asset_js(include_str!("assets/cursor.js"))),
        (&Method::GET, "/favicon.svg") => Some(asset_bytes(
            include_bytes!("assets/favicon.svg"),
            "image/svg+xml",
        )),
        (&Method::GET, "/images/pq-crypta.jpg") => {
            Some(asset_bytes(include_bytes!("assets/logo.jpg"), "image/jpeg"))
        }
        // The site navigation, served from this host at the same paths the
        // markup references, so the shared menu works unchanged across the
        // hostname boundary.
        (&Method::GET, "/fun/css/menu.css") => Some(asset_css(include_str!("assets/menu.css"))),
        (&Method::GET, "/css/quantum-countdown.css") => {
            Some(asset_css(include_str!("assets/quantum-countdown.css")))
        }
        (&Method::GET, "/fun/js/menu.js") => Some(asset_js(include_str!("assets/menu.js"))),
        (&Method::GET, "/fun/js/error-menu.js") => {
            Some(asset_js(include_str!("assets/error-menu.js")))
        }
        (&Method::GET, "/fun/js/mini-countdown.js") => {
            Some(asset_js(include_str!("assets/mini-countdown.js")))
        }
        (&Method::GET, "/robots.txt") => Some(robots(conformance)),
        (&Method::GET, "/sitemap.xml") => Some(sitemap(conformance)),
        (&Method::GET, p) if p.starts_with("/report/") => Some(report_for(conformance, p)),
        (&Method::GET, p) if p.starts_with("/badge/") => Some(badge_for(conformance, p)),
        _ => None,
    }
}

/// A cacheable static asset.
///
/// Unlike the report pages, these never change between deploys, so they carry a
/// long max-age rather than the `no-store` every result-bearing response needs.
fn cacheable(mut resp: Response<Body>) -> Response<Body> {
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=86400"),
    );
    resp
}

fn asset_css(body: &'static str) -> Response<Body> {
    cacheable(text(
        StatusCode::OK,
        "text/css; charset=utf-8",
        body.to_string(),
    ))
}

fn asset_js(body: &'static str) -> Response<Body> {
    cacheable(text(
        StatusCode::OK,
        "application/javascript; charset=utf-8",
        body.to_string(),
    ))
}

fn asset_bytes(body: &'static [u8], content_type: &'static str) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    cacheable(resp)
}

/// Crawl rules for the suite host.
///
/// The landing page is worth indexing; nothing else here is. A report belongs to
/// one session and is gone within the hour, a badge is an image of that report,
/// and `/session` is a POST that mints state — an indexed report URL would be a
/// dead link by the time anyone followed it.
fn robots(conformance: &Arc<Conformance>) -> Response<Body> {
    let host = &conformance.config.host;
    cacheable(text(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        format!(
            "User-agent: *\n\
             Allow: /$\n\
             Disallow: /report/\n\
             Disallow: /badge/\n\
             Disallow: /session\n\
             \n\
             Sitemap: https://{host}/sitemap.xml\n"
        ),
    ))
}

/// One URL, because there is exactly one indexable page here.
fn sitemap(conformance: &Arc<Conformance>) -> Response<Body> {
    let host = &conformance.config.host;
    cacheable(text(
        StatusCode::OK,
        "application/xml; charset=utf-8",
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n\
             <url><loc>https://{host}/</loc><changefreq>weekly</changefreq>\
             <priority>0.8</priority></url>\n\
             </urlset>\n"
        ),
    ))
}

/// The Content-Security-Policy for this host's HTML pages.
///
/// The proxy injects a global CSP only when a response does not already carry
/// one, so setting it here replaces the default for these pages alone.
///
/// It has to be a little wider than the global `default-src 'self'` because the
/// pages carry the shared site navigation: the menu's stylesheet uses `data:`
/// URIs for its chevron icons, and its script asks `api.pqcrypta.com` whether
/// the visitor is signed in. Both were being refused, which the menu survived
/// (the auth call is wrapped in a `catch`) but reported as console errors on
/// every load. Everything else stays same-origin, and inline script and style
/// remain forbidden.
fn html_csp(resp: &mut Response<Body>) {
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             img-src 'self' data:; \
             style-src 'self'; \
             script-src 'self'; \
             connect-src 'self' https://api.pqcrypta.com; \
             font-src 'self' data:; \
             object-src 'none'; \
             base-uri 'self'; \
             frame-ancestors 'none'",
        ),
    );
}

fn text(status: StatusCode, content_type: &'static str, body: String) -> Response<Body> {
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    // Results change as a run proceeds, so nothing here may be cached.
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    // Open, like the JA4 export: a report reveals only what the requester's own
    // client did, and CI has to be able to fetch it.
    resp.headers_mut().insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    resp.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// The session id from `/report/<id>` or `/badge/<id>.svg`.
///
/// Validated to the exact shape the registry issues, so a path segment cannot
/// be echoed back into a page: an id either matches 32 hex characters or the
/// request is a 404.
fn session_id(path: &str, prefix: &str, suffix: &str) -> Option<String> {
    let rest = path.strip_prefix(prefix)?;
    let id = rest.strip_suffix(suffix).unwrap_or(rest);
    if id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(id.to_string())
    } else {
        None
    }
}

fn index(conformance: &Arc<Conformance>) -> Response<Body> {
    let host = &conformance.config.host;
    let start = conformance.config.port_range.0;
    let end = start + super::catalog::required_ports() - 1;
    let total = super::catalog::CATALOG.len();
    let quic = super::catalog::CATALOG
        .iter()
        .filter(|t| matches!(t.tier, super::catalog::Tier::Quic))
        .count();
    let http3 = total - quic;

    // Counts per layer and class, tallied from the catalogue rather than
    // written down, so the breakdown cannot disagree with the table below it.
    let mut breakdown = String::new();
    for (tier, heading) in [
        (super::catalog::Tier::Quic, "QUIC"),
        (super::catalog::Tier::Http3, "HTTP/3"),
    ] {
        let in_tier: Vec<_> = super::catalog::CATALOG
            .iter()
            .filter(|t| t.tier == tier)
            .collect();
        let mut classes: Vec<(&str, usize)> = Vec::new();
        for t in &in_tier {
            let name = t.class.as_str();
            match classes.iter_mut().find(|(c, _)| *c == name) {
                Some((_, n)) => *n += 1,
                None => classes.push((name, 1)),
            }
        }
        classes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));

        breakdown.push_str(&format!(
            "<div class=\"tier\"><h3>{heading}</h3><p class=\"tier-count\">{} tests</p><dl>",
            in_tier.len()
        ));
        for (class, n) in classes {
            breakdown.push_str(&format!(
                "<dt class=\"cls-{class}\">{class}</dt><dd>{n}</dd>"
            ));
        }
        breakdown.push_str("</dl></div>");
    }

    // Every test, grouped by layer, so the page lists what it actually serves
    // rather than a prose summary that can drift from the catalogue.
    let mut rows = String::new();
    for (tier, heading) in [
        (super::catalog::Tier::Http3, "HTTP/3 layer"),
        (super::catalog::Tier::Quic, "QUIC layer"),
    ] {
        rows.push_str(&format!(
            "<h3>{heading}</h3><div class=\"tablewrap\"><table>\
<thead><tr><th>Test</th><th>Port</th><th>Class</th><th>Specification</th></tr></thead><tbody>"
        ));
        for t in super::catalog::CATALOG.iter().filter(|t| t.tier == tier) {
            let port = t
                .port_offset
                .map(|o| (start + o).to_string())
                .unwrap_or_else(|| "&mdash;".to_string());
            rows.push_str(&format!(
                "<tr><td><code>{id}</code><span class=\"title\">{title}</span>\
<span class=\"expect\">{expect}</span></td>\
<td>{port}</td><td><span class=\"chip\">{class}</span></td><td>{spec}</td></tr>",
                id = esc(t.id),
                title = esc(t.title),
                expect = esc(t.expectation),
                class = esc(t.class.as_str()),
                spec = esc(t.spec),
            ));
        }
        rows.push_str("</tbody></table></div>");
    }

    // The shared site navigation, captured from the PHP include it is generated
    // by. Its links are already absolute, so it works from this hostname without
    // rewriting; see assets/README.md for the one that was not.
    let menu = include_str!("assets/menu.html");

    let title = "HTTP/3 &amp; QUIC Client Conformance Suite";
    // Kept inside the site's 160-character limit for a meta description, which
    // the first version overran by two.
    let desc = format!(
        "A free public conformance suite for HTTP/3 and QUIC clients: {total} tests that \
         make the server misbehave on purpose, each citing the RFC clause it exercises."
    );

    // Taken from the clock rather than hard-coded, so the footer does not quietly
    // go stale on 1 January.
    let year = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| 1970 + d.as_secs() / 31_556_952)
        .unwrap_or(1970);

    let body = format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HTTP/3 &amp; QUIC Client Conformance Suite</title>
<meta name="description" content="{desc}">
<meta name="keywords" content="HTTP/3 conformance, QUIC conformance, h3 client testing, QUIC interop, RFC 9114, RFC 9000, RFC 9204, QPACK, GREASE, protocol conformance suite, quic-go, aioquic, ngtcp2, quiche">
<meta name="author" content="Allan Riddel, PQ Crypta">
<meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large">
<link rel="canonical" href="https://{host}/">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta property="og:type" content="website">
<meta property="og:url" content="https://{host}/">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{desc}">
<meta property="og:site_name" content="PQ Crypta">
<meta property="og:image" content="https://pqcrypta.com/images/og-image.jpg">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{desc}">
<meta name="twitter:image" content="https://pqcrypta.com/images/twitter-card.jpg">
<link rel="stylesheet" href="/fun/css/menu.css">
<link rel="stylesheet" href="/css/quantum-countdown.css">
<link rel="stylesheet" href="/css/conformance.css">
<link rel="stylesheet" href="/css/bg.css">
<link rel="stylesheet" href="/css/cursor.css">
<script type="application/ld+json">{{"@context":"https://schema.org","@type":"SoftwareApplication","name":"PQ Crypta HTTP/3 Client Conformance Suite","url":"https://{host}/","applicationCategory":"DeveloperApplication","operatingSystem":"Any","description":"A public conformance service for HTTP/3 and QUIC client libraries. The server emits deliberately awkward but legal protocol output and records how the client under test responds.","offers":{{"@type":"Offer","price":"0","priceCurrency":"USD"}},"creator":{{"@type":"Organization","name":"PQ Crypta","url":"https://pqcrypta.com/"}}}}</script>
</head>
<body class="conformance-report">
{menu}
<div id="cf-bg-container" class="cf-bg-container" aria-hidden="true"><canvas id="cf-bg-canvas" class="cf-bg-canvas"></canvas></div>

<header class="site-header"><div class="inner">
  <div class="brand">
    <a href="https://pqcrypta.com/"><img src="/images/pq-crypta.jpg" alt="PQ Crypta" width="48" height="48"></a>
    <div>
      <h1>HTTP/3 &amp; QUIC Client Conformance</h1>
      <p class="tagline">A server that misbehaves on purpose, so your client library can find out how it copes</p>
      <p class="tagline differentiator">Unlike an interoperability test, this one deliberately sends your
      client protocol edge cases, illegal messages, GREASE, awkward state transitions and hostile network
      conditions &mdash; and judges the result from the wire, not from what the client reports.</p>
    </div>
  </div>
  <nav class="site-nav" aria-label="Site">
    <a href="/">Suite</a>
    <a href="/catalog.json">Catalogue JSON</a>
    <a href="https://pqcrypta.com/conformance/">Documentation</a>
    <a href="https://pqcrypta.com/conformance/matrix.php">Client matrix</a>
    <a href="https://pqcrypta.com/pqcproxy/">The proxy</a>
    <a href="https://pqcrypta.com/">pqcrypta.com</a>
  </nav>
</div></header>

<main class="wrap">
<p>This is a live service, not a description of one. Point an HTTP/3 client at any
port below and the server will emit something awkward but legal &mdash; a reserved
frame type, a duplicated SETTINGS identifier, a control stream that opens with the
wrong frame, an unknown QUIC frame type, a Stateless Reset, a path-MTU black hole
&mdash; then record what your client did about it.</p>

<div class="stats">
  <div><span class="v">{total}</span><span class="k">adversarial tests</span></div>
  <div><span class="v">{http3}</span><span class="k">HTTP/3 layer</span></div>
  <div><span class="v">{quic}</span><span class="k">QUIC layer</span></div>
  <div><span class="v">{start}&ndash;{end}</span><span class="k">UDP ports</span></div>
</div>

<section class="breakdown">{breakdown}</section>

<h2 id="verdict-key">What a result means</h2>
<div class="verdict-key">
  <div class="vk vk-pass"><strong>Pass</strong><span>The client demonstrated the behaviour the specification requires.</span></div>
  <div class="vk vk-fail"><strong>Fail</strong><span>The client did something the specification prohibits.</span></div>
  <div class="vk vk-incon"><strong>Inconclusive</strong><span>The run could not establish the observation &mdash; the client was never put in the situation the test is about. Never counted either way.</span></div>
</div>

<h2 id="running">Running it</h2>
<p>Each test has its own UDP port. Results are filed under a session started from
your address, so the test connections need nothing special &mdash; just run them
from the machine that asked for the session.</p>
<p>A port per test rather than a path per test, because several anomalies are
properties of the <em>endpoint</em> rather than of a connection: the set of QUIC
versions offered is decided before any connection exists, so a test of it has to
own the whole port.</p>
<pre class="ja4-rawpre"><code># start a session
SESSION=$(curl -sX POST https://{host}/session | jq -r .id)

# walk the catalogue
curl -s https://{host}/catalog.json | jq -r '.tests[].port' | while read PORT; do
    curl -s --http3-only --max-time 15 "https://{host}:$PORT/" -o /dev/null
  done

# read the result
curl -s https://{host}/report/$SESSION.json | jq .totals</code></pre>
<p>Without <code>jq</code>: <code>grep -o '"port":[0-9]*' | cut -d: -f2</code> pulls the
ports out of the catalogue. The report is also a page at
<code>/report/&lt;session&gt;</code> and an SVG badge at
<code>/badge/&lt;session&gt;.svg</code>.</p>

<h2 id="ci">In CI</h2>
<p><code>h3-conformance</code> does the above and exits non-zero if anything failed.
It is a harness rather than a client: it runs a command you supply, once per test,
so whatever <em>your</em> library connects with is what gets measured.</p>
<pre class="ja4-rawpre"><code># drive curl
h3-conformance

# drive your own client
h3-conformance --client 'my-client --url {{url}}'

# one area, machine-readable
h3-conformance --filter h-qpack --json</code></pre>
<p>Exit <code>0</code> clean, <code>1</code> a test failed, <code>2</code> the suite
was unreachable &mdash; distinct, so an outage never reads as a regression in your
client. Inconclusive results never fail a run.</p>
<table class="format-table"><thead><tr><th>Option</th><th>Default</th><th>What it does</th></tr></thead><tbody>
<tr><td><code>--host</code></td><td>{host}</td><td>Which suite to run against.</td></tr>
<tr><td><code>--client</code></td><td>curl</td><td>Command run once per test. <code>{{url}}</code> and <code>{{port}}</code> are substituted; its exit status is ignored, because a client failing a test frequently <em>should</em> exit non-zero and that is a result, not an error.</td></tr>
<tr><td><code>--filter</code></td><td>&mdash;</td><td>Run only tests whose id contains this, e.g. <code>h-qpack</code>.</td></tr>
<tr><td><code>--timeout</code></td><td>30s</td><td>Seconds to allow each client invocation before giving up on it.</td></tr>
<tr><td><code>--json</code></td><td>off</td><td>Print the report as JSON instead of text.</td></tr>
<tr><td><code>--quiet</code></td><td>off</td><td>Only print failures and the summary.</td></tr>
</tbody></table>

<h2 id="report">The report</h2>
<p>A session collects results as you walk the ports, and is readable three ways: as
a page at <code>/report/&lt;session&gt;</code>, as JSON at
<code>/report/&lt;session&gt;.json</code>, and as an SVG badge at
<code>/badge/&lt;session&gt;.svg</code>. All three are public and CORS-open, so CI
can fetch them without a key.</p>
<pre class="ja4-rawpre"><code>{{
  "session": "8fbecf53c82f7c6481ecca51727c6742",
  "catalog_size": {total},
  "totals":   {{ "pass": 22, "fail": 0, "inconclusive": 5, "not_run": 0 }},
  "by_class": {{ "correctness": {{ "pass": 6, "fail": 0, "inconclusive": 3 }}, ... }},
  "results": [
    {{ "id": "h-grease-frame", "class": "extensibility", "tier": "http3",
      "spec": "RFC 9114 §7.2.8", "verdict": "pass",
      "detail": "Ignored the unrecognised element and completed the follow-up request." }}
  ]
}}</code></pre>
<p>Test <code>id</code>s are stable and appear in the URL, the JSON and the badge, so
they are safe to pin a CI assertion to. Embed a badge with:</p>
<pre class="ja4-rawpre"><code>![HTTP/3 conformance](https://{host}/badge/$SESSION.svg)</code></pre>
<p>A badge is a picture of one run, not a live status: re-run the suite and use the
new session to refresh it.</p>

<h3>How results find their session</h3>
<p>By default results are filed under the session started from your address, which is
why the walk above needs nothing special. If your tests run from several machines, or
from behind a shared address, connect with the server name
<code>&lt;session&gt;.{host}</code> instead &mdash; the session travels in the SNI,
and results follow it rather than the address.</p>
<p>A session expires an hour after it was <em>created</em>, not an hour after its last
result: activity does not extend it. Start the session at the beginning of the walk
rather than long before, and fetch the report while the run is fresh; nothing is
archived.</p>

<h2 id="verdicts">What a verdict means</h2>
<p><strong>The server is the judge.</strong> A library that crashes on an unknown
frame is in no position to report on itself, so every verdict comes from what the
server observed. Every test ends with a <strong>liveness probe</strong>: after the
anomaly, the server expects one ordinary request on the same connection. For the
extensibility tests that is the whole game &mdash; "ignored it" and "died on it"
look identical on the wire until the probe arrives or does not.</p>
<p>The required answer is not the same everywhere, and sometimes it is the
opposite. Ignoring a reserved <strong>HTTP/3</strong> frame is a pass &mdash;
reserved frame types exist to be ignored. Ignoring a reserved <strong>QUIC</strong>
frame is a failure, because QUIC reserves no ignorable frame types and an unknown
frame carries no length to skip it by. Two tests that look alike on the wire
require opposite behaviour, which is why the classes exist.</p>
<ul>
<li><strong>Extensibility</strong> &mdash; ignore something unrecognised and carry
on. Rejecting it is the failure; that is how protocols ossify.</li>
<li><strong>Correctness</strong> &mdash; reject something invalid, with the error
code the specification names. Accepting it is the bug &mdash; though a failure is
only recorded where the client demonstrably read the anomaly, never merely because
no rejection arrived.</li>
<li><strong>Interoperability</strong> &mdash; the response is valid but demanding
(Huffman-coded fields, a dynamic-table reference, trailers) and has to be decoded.</li>
<li><strong>Resilience</strong> &mdash; recover rather than give up.</li>
<li><strong>Discretionary</strong> &mdash; the specification permits more than one
answer. Both pass; the report says which yours chose.</li>
<li><strong>Inconclusive</strong> &mdash; the run never put your client in the
situation the test is about, so it proves nothing either way and is never counted
as a pass or a failure.</li>
</ul>
<p>An anomaly written to the control stream is a case of its own. That stream is
unidirectional and nothing obliges a client to read it on any schedule, so a
one-shot request can finish and close before it is picked up &mdash; which is
indistinguishable, from this end, from accepting the violation. The response is
held back briefly to give a conformant reader its chance, and where the two still
cannot be told apart the result is inconclusive rather than a failure.</p>
<p>Some tests cannot be reached by every client, and say so rather than guessing:
0-RTT rejection needs a session ticket from an earlier connection to the same port;
ECN reporting is required only where the ECN field is accessible, which a network
can strip in transit; QPACK dynamic-table references need the client to have
granted the encoder some capacity.</p>

<h2 id="catalogue">The catalogue</h2>
<p>Every test, the port it runs on, and the clause it exercises. The same data is
available as <a href="/catalog.json">JSON</a>.</p>
{rows}

<h2 id="scope">Scope, and what this is not</h2>
<p>{total} tests is a beginning, not coverage. QUIC and HTTP/3 together are
enormous, and whole areas are untouched &mdash; connection migration, malformed
transport parameters, extended CONNECT, prioritisation, 0-RTT replay. The
catalogue is chosen rather than exhaustive.</p>
<ul>
<li><strong>This is not a certification.</strong> Passing everything here means a
client handled {total} specific situations correctly. It does not mean the
implementation is conformant, and nothing here should be quoted as though it did.</li>
<li><strong>A failure is a specification violation, not a security
vulnerability.</strong> Some may have security relevance; most are simply behaviour
a specification prohibits. Calling every failure a vulnerability would make the
dataset less credible and would be unfair to the implementations measured.</li>
<li><strong>It tests clients, not servers.</strong> For the other direction, see the
<a href="https://pqcrypta.com/http3-quic/">HTTP/3 scanner</a>.</li>
<li><strong>The suite is itself an implementation</strong>, and subject to the same
doubt as anything it measures. A verdict you believe is wrong is worth reporting: a
suite that accuses the thing it tests is worse than no suite, because the real
failures stop being believed.</li>
</ul>

<h2 id="why">Why this exists</h2>
<p>The <a href="https://interop.seemann.io/" rel="noopener">QUIC Interop Runner</a>
tests implementations against each other in a lab matrix. This is the other thing:
a public endpoint you can point a <strong>client</strong> at. Offering one requires
a server that will misbehave on demand, which is not something a CDN customer can
arrange &mdash; they do not own the implementation. This one runs on a forked QUIC
and HTTP/3 stack, which is what makes the awkward cases possible.</p>
<p>If your client scores a failure you believe is wrong,
<a href="https://pqcrypta.com/contact/">say so</a> &mdash; a suite that accuses the
thing it tests is worth fixing quickly.</p>
</main>

<footer class="site-footer"><div class="inner">
  <ul>
    <li><a href="https://pqcrypta.com/">PQ Crypta</a></li>
    <li><a href="https://pqcrypta.com/conformance/">Documentation</a></li>
    <li><a href="https://pqcrypta.com/conformance/matrix.php">Client matrix</a></li>
    <li><a href="/catalog.json">Catalogue JSON</a></li>
    <li><a href="https://pqcrypta.com/pqcproxy/">The proxy</a></li>
    <li><a href="https://pqcrypta.com/http3-quic/">HTTP/3 scanner</a></li>
    <li><a href="https://pqcrypta.com/ja4/">JA4 directory</a></li>
  </ul>
  <p class="note">Served by pqcrypta-proxy, a forked QUIC and HTTP/3 stack.
  The forking is what makes the suite possible.</p>
  <p class="copy">&copy; {year} Allan Riddel &mdash; PQ Crypta.
  <a href="https://pqcrypta.com/legal/pqcryptalegal.php">Legal</a> &middot;
  <a href="https://pqcrypta.com/legal/pqcryptaprivacy.php">Privacy</a> &middot;
  <a href="https://pqcrypta.com/contact/">Contact</a></p>
</div></footer>

<script src="/fun/js/menu.js" defer></script>
<script src="/fun/js/error-menu.js" defer></script>
<script src="/fun/js/mini-countdown.js" defer></script>
<script src="/js/bg.js" defer></script>
<script src="/js/cursor.js" defer></script>
</body></html>
"#
    );
    let mut resp = text(StatusCode::OK, "text/html; charset=utf-8", body);
    html_csp(&mut resp);
    resp
}

/// Minimal HTML escaping for catalogue text going into the page.
fn esc(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn new_session(conformance: &Arc<Conformance>, client_ip: std::net::IpAddr) -> Response<Body> {
    let id = conformance.sessions.create();
    // Test connections arrive on other ports with no way to name the session,
    // so remember which address started it.
    conformance.sessions.associate(client_ip, &id);
    let host = &conformance.config.host;
    let body = format!(
        "{{\n  \"id\": \"{id}\",\n  \"sni\": \"{id}.{host}\",\n  \
         \"report\": \"https://{host}/report/{id}.json\",\n  \
         \"badge\": \"https://{host}/badge/{id}.svg\"\n}}\n"
    );
    text(StatusCode::OK, "application/json; charset=utf-8", body)
}

/// The report stylesheet.
///
/// Served from here rather than the document root because this vhost has no
/// backend — every path on it is answered in-process — so a file on disk would
/// simply 404. Embedding it also keeps the page and its styling versioned
/// together.
fn stylesheet() -> Response<Body> {
    let mut resp = text(
        StatusCode::OK,
        "text/css; charset=utf-8",
        include_str!("conformance.css").to_string(),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    resp
}

fn catalog_json(conformance: &Arc<Conformance>) -> Response<Body> {
    text(
        StatusCode::OK,
        "application/json; charset=utf-8",
        super::listener::catalog_json(conformance),
    )
}

fn report_for(conformance: &Arc<Conformance>, path: &str) -> Response<Body> {
    // Case-sensitive on purpose: these paths come from links we emit, and a
    // request for `.JSON` is somebody probing, not a caller we need to serve.
    let wants_json = std::path::Path::new(path)
        .extension()
        .is_some_and(|e| e == "json");
    let Some(id) = session_id(path, "/report/", ".json") else {
        return not_found(wants_json);
    };
    let Some(results) = conformance.sessions.with(&id, |s| s.results()) else {
        return not_found(wants_json);
    };

    let generated = chrono_now();
    let built = report::build(&id, &results, generated);

    if wants_json {
        match serde_json::to_string_pretty(&built) {
            Ok(json) => text(StatusCode::OK, "application/json; charset=utf-8", json),
            Err(_) => text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json; charset=utf-8",
                "{\"error\":\"could not render report\"}\n".to_string(),
            ),
        }
    } else {
        let mut resp = text(
            StatusCode::OK,
            "text/html; charset=utf-8",
            report::html(&built),
        );
        html_csp(&mut resp);
        resp
    }
}

fn badge_for(conformance: &Arc<Conformance>, path: &str) -> Response<Body> {
    let Some(id) = session_id(path, "/badge/", ".svg") else {
        return not_found(false);
    };
    let Some(results) = conformance.sessions.with(&id, |s| s.results()) else {
        return not_found(false);
    };
    let built = report::build(&id, &results, chrono_now());
    let mut resp = text(
        StatusCode::OK,
        "image/svg+xml; charset=utf-8",
        report::badge_svg(&built),
    );
    // Badges are fetched by README renderers that cache aggressively; a short
    // max-age keeps a re-run visible without hammering us.
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=60"),
    );
    resp
}

fn not_found(json: bool) -> Response<Body> {
    if json {
        text(
            StatusCode::NOT_FOUND,
            "application/json; charset=utf-8",
            "{\"error\":\"no such session; sessions expire, so start a new one\"}\n".to_string(),
        )
    } else {
        text(
            StatusCode::NOT_FOUND,
            "text/html; charset=utf-8",
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>No such session</title>\
             <meta name=\"robots\" content=\"noindex, nofollow\">\
             <link rel=\"icon\" href=\"/favicon.svg\" type=\"image/svg+xml\">\
             <link rel=\"stylesheet\" href=\"/css/conformance.css\"></head>\
             <body class=\"conformance-report\"><div class=\"wrap\">\
             <h1>No such session</h1>\
             <p>Sessions expire. <a href=\"/\">Start a new one.</a></p>\
             </div></body></html>\n"
                .to_string(),
        )
    }
}

/// An RFC 3339 timestamp for the report header.
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Whole seconds, UTC. A report is stamped so a reader can tell one run from
    // the next, not so it can be used as a clock.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since the Unix epoch to a civil date (Howard Hinnant's algorithm).
#[allow(
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    reason = "inputs are a day count derived from SystemTime, and the intermediate \
              quantities are day- and month-of-year values well inside every width used"
)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConformanceConfig;

    fn conf() -> Arc<Conformance> {
        Arc::new(
            Conformance::new(&ConformanceConfig {
                enabled: true,
                ..Default::default()
            })
            .unwrap()
            .unwrap(),
        )
    }

    #[test]
    fn a_session_id_must_match_the_issued_shape() {
        let good = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            session_id(&format!("/report/{good}.json"), "/report/", ".json").as_deref(),
            Some(good)
        );
        assert_eq!(
            session_id(&format!("/report/{good}"), "/report/", ".json").as_deref(),
            Some(good)
        );
        // Anything else is a 404, so a path segment can never be echoed back
        // into a page.
        assert!(session_id("/report/../../etc/passwd", "/report/", ".json").is_none());
        assert!(session_id("/report/<script>", "/report/", ".json").is_none());
        assert!(session_id("/report/short", "/report/", ".json").is_none());
        assert!(session_id(&format!("/report/{}", "z".repeat(32)), "/report/", ".json").is_none());
    }

    #[test]
    fn an_unknown_session_is_a_404_not_an_empty_report() {
        let c = conf();
        let missing = "f".repeat(32);
        let resp = report_for(&c, &format!("/report/{missing}.json"));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn a_fresh_session_reports_the_whole_catalogue_as_not_run() {
        let c = conf();
        let id = c.sessions.create();
        let resp = report_for(&c, &format!("/report/{id}.json"));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, must-revalidate"),
            "a report changes as the run proceeds and must never be cached"
        );
    }

    #[test]
    fn routing_only_claims_its_own_paths() {
        let c = conf();
        let ip: std::net::IpAddr = "203.0.113.1".parse().unwrap();
        assert!(route(&c, &Method::GET, "/", ip).is_some());
        assert!(route(&c, &Method::POST, "/session", ip).is_some());
        assert!(route(&c, &Method::GET, "/catalog.json", ip).is_some());
        assert!(route(&c, &Method::GET, "/css/conformance.css", ip).is_some());
        // Anything else falls through to normal routing.
        assert!(route(&c, &Method::GET, "/favicon.ico", ip).is_none());
        assert!(route(&c, &Method::GET, "/session", ip).is_none());
    }

    #[test]
    fn the_epoch_converts_to_a_civil_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_000), (2022, 1, 8));
        // A leap day and the day after it, which is where a hand-rolled
        // conversion usually breaks.
        assert_eq!(civil_from_days(18_321), (2020, 2, 29));
        assert_eq!(civil_from_days(18_322), (2020, 3, 1));
    }

    #[test]
    fn the_timestamp_is_rfc_3339_shaped() {
        let t = chrono_now();
        assert_eq!(t.len(), 20, "{t}");
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
    }
}
