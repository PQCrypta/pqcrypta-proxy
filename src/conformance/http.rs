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
        (&Method::GET, p) if p.starts_with("/report/") => Some(report_for(conformance, p)),
        (&Method::GET, p) if p.starts_with("/badge/") => Some(badge_for(conformance, p)),
        _ => None,
    }
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
    let built = super::catalog::CATALOG
        .iter()
        .filter(|t| t.implemented)
        .count();

    let body = format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>HTTP/3 client conformance</title>\
<link rel=\"stylesheet\" href=\"/css/conformance.css\"></head><body class=\"conformance-report\">\
<h1>HTTP/3 &amp; QUIC client conformance</h1>\
<p class=\"meta\">{built} of {total} tests active on udp/{start}&ndash;{end}</p>\
<p>This server misbehaves on purpose so your client library can find out how it \
copes: reserved frame types, a duplicated SETTINGS identifier, a control stream \
that opens with the wrong frame. Each test has its own UDP port. Connect, and \
the server records what your client did.</p>\
<h2>Running it</h2>\
<pre class=\"ja4-rawpre\"><code># start a session\n\
SESSION=$(curl -sX POST https://{host}/session | sed 's/.*\"id\":\"//;s/\".*//')\n\n\
# walk the catalogue; results file under the session from this address\n\
curl -s https://{host}/catalog.json | \\\\\n\
  grep -o '\"port\": [0-9]*' | grep -o '[0-9]*' | while read PORT; do\n\
    curl -s --http3-only --max-time 15 \"https://{host}:$PORT/\" -o /dev/null\n\
  done\n\n\
# read the result\n\
curl -s https://{host}/report/$SESSION.json</code></pre>\
<p>Results are filed under the session started from your address, so the test \
connections need nothing special &mdash; just run them from the same machine \
that asked for the session.</p>\
<h2>What a verdict means</h2>\
<ul>\
<li><strong>Extensibility</strong> &mdash; your client had to ignore something \
it did not recognise and carry on. Rejecting it is the failure; that is how \
protocols ossify.</li>\
<li><strong>Correctness</strong> &mdash; your client had to reject something \
invalid, with the error code the specification names.</li>\
<li><strong>Interoperability</strong> &mdash; the response was valid but \
demanding &mdash; Huffman-coded fields, a dynamic-table reference, trailers \
&mdash; and your client had to decode it.</li>\
<li><strong>Resilience</strong> &mdash; your client had to recover rather than \
give up.</li>\
<li><strong>Discretionary</strong> &mdash; the specification permits more than \
one answer. Both pass; the report says which yours chose.</li>\
<li><strong>Inconclusive</strong> &mdash; the run never put your client in the \
situation the test is about, so it proves nothing either way.</li>\
</ul>\
<p><a href=\"/catalog.json\">The catalogue</a> lists every test with the clause \
it exercises.</p>\
</body></html>\n"
    );
    text(StatusCode::OK, "text/html; charset=utf-8", body)
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
        text(
            StatusCode::OK,
            "text/html; charset=utf-8",
            report::html(&built),
        )
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
             <link rel=\"stylesheet\" href=\"/css/conformance.css\"></head>\
             <body class=\"conformance-report\"><h1>No such session</h1>\
             <p>Sessions expire. <a href=\"/\">Start a new one.</a></p></body></html>\n"
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
