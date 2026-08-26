//! Report rendering: JSON for CI, HTML for people, SVG for READMEs.
//!
//! Results are rolled up **by class**, not into a single percentage. A client
//! that ignores unknown extensions correctly but never emits the error codes the
//! specification names has one specific, fixable problem, and an average would
//! bury exactly the thing worth telling it.
//!
//! Untouched tests are reported as `not_run` rather than omitted. A client that
//! connected once and gave up should show a page full of `not_run`, not a single
//! pass and a misleading 100%.

use std::collections::BTreeMap;

use serde::Serialize;

use super::catalog;
use super::session::{Result_, Verdict};

/// Counts for one class of test.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClassSummary {
    pub pass: usize,
    pub fail: usize,
    pub inconclusive: usize,
    pub not_run: usize,
}

impl ClassSummary {
    /// Tests that reached a verdict.
    pub fn decided(&self) -> usize {
        self.pass + self.fail
    }

    /// Pass rate over decided tests only.
    ///
    /// Tests never run are excluded rather than counted against the client:
    /// a partial run should report what it found, not punish what it skipped.
    #[allow(
        clippy::cast_precision_loss,
        reason = "counts are bounded by the catalogue size, far inside f64's exact range"
    )]
    pub fn rate(&self) -> Option<f64> {
        match self.decided() {
            0 => None,
            n => Some(self.pass as f64 / n as f64),
        }
    }
}

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub session: String,
    pub generated_at: String,
    pub catalog_size: usize,
    pub by_class: BTreeMap<String, ClassSummary>,
    pub totals: ClassSummary,
    pub results: Vec<ResultRow>,
}

/// One row, joined with its catalogue entry so the report is self-contained —
/// a reader should not need the catalogue open alongside it.
#[derive(Debug, Clone, Serialize)]
pub struct ResultRow {
    pub id: &'static str,
    pub title: &'static str,
    pub spec: &'static str,
    pub class: &'static str,
    pub tier: &'static str,
    pub expectation: &'static str,
    pub verdict: &'static str,
    pub detail: String,
    pub elapsed_ms: u64,
}

/// Assemble a report from a session's results.
pub fn build(session_id: &str, results: &[Result_], generated_at: String) -> Report {
    let mut by_class: BTreeMap<String, ClassSummary> = BTreeMap::new();
    let mut totals = ClassSummary::default();
    let mut rows = Vec::with_capacity(results.len());

    for r in results {
        let Some(test) = catalog::find(r.test_id) else {
            continue;
        };
        let entry = by_class.entry(test.class.as_str().to_string()).or_default();

        for bucket in [&mut *entry, &mut totals] {
            match r.verdict {
                Verdict::Pass => bucket.pass += 1,
                Verdict::Fail => bucket.fail += 1,
                Verdict::Inconclusive => bucket.inconclusive += 1,
                Verdict::NotRun => bucket.not_run += 1,
            }
        }

        rows.push(ResultRow {
            id: test.id,
            title: test.title,
            spec: test.spec,
            class: test.class.as_str(),
            tier: match test.tier {
                catalog::Tier::Http3 => "http3",
                catalog::Tier::Quic => "quic",
            },
            expectation: test.expectation,
            verdict: r.verdict.as_str(),
            detail: r.detail.clone(),
            elapsed_ms: r.elapsed_ms,
        });
    }

    Report {
        session: session_id.to_string(),
        generated_at,
        catalog_size: catalog::CATALOG.len(),
        by_class,
        totals,
        results: rows,
    }
}

/// Badge colour, chosen from the failure count rather than the pass rate.
///
/// One protocol violation is worth flagging even at 96%, because the failures
/// here are not cosmetic — they are the cases that make a client fall over
/// against a peer it has not met yet.
fn badge_colour(totals: &ClassSummary) -> &'static str {
    if totals.decided() == 0 {
        "#9f9f9f"
    } else if totals.fail == 0 {
        "#2f7d52"
    } else if totals.fail <= 2 {
        "#9a6a00"
    } else {
        "#b02a2a"
    }
}

/// An SVG badge for a README.
///
/// This is the distribution mechanism for the whole suite. A badge in a widely
/// used client library's README reaches more of the audience than any amount of
/// search ranking, so it is deliberately small, dependency-free and cacheable.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    reason = "badge geometry: label lengths are a handful of characters and the \
              result is rounded to whole pixels, so f32 precision is ample"
)]
pub fn badge_svg(report: &Report) -> String {
    let label = "h3 conformance";
    let value = match report.totals.decided() {
        0 => "not run".to_string(),
        n => format!("{}/{}", report.totals.pass, n),
    };
    let colour = badge_colour(&report.totals);

    // ~6.6px per character at 11px DejaVu Sans, plus padding. Approximate on
    // purpose: exact text metrics would need font loading, and a badge a pixel
    // wide either way is not worth that.
    let label_w = 6.6f32.mul_add(label.len() as f32, 12.0).round() as i32;
    let value_w = 6.6f32.mul_add(value.len() as f32, 12.0).round() as i32;
    let total_w = label_w + value_w;

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{label}: {value}">
<title>{label}: {value}</title>
<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)">
<rect width="{label_w}" height="20" fill="#555"/>
<rect x="{label_w}" width="{value_w}" height="20" fill="{colour}"/>
<rect width="{total_w}" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="{label_x}" y="15" fill="#010101" fill-opacity=".3">{label}</text>
<text x="{label_x}" y="14">{label}</text>
<text x="{value_x}" y="15" fill="#010101" fill-opacity=".3">{value}</text>
<text x="{value_x}" y="14">{value}</text>
</g>
</svg>"##,
        label_x = label_w / 2,
        value_x = label_w + value_w / 2,
    )
}

/// Escape text for HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The human-readable report.
///
/// No inline styles or event handlers: the site runs a strict CSP that forbids
/// both, and a page served from the proxy is bound by it like any other.
pub fn html(report: &Report) -> String {
    let mut body = String::new();

    body.push_str(&format!(
        "<h1>HTTP/3 &amp; QUIC client conformance</h1>\n\
         <p class=\"meta\">Session <code>{}</code> &middot; {} &middot; {} tests</p>\n",
        esc(&report.session),
        esc(&report.generated_at),
        report.catalog_size
    ));

    body.push_str("<section class=\"summary\">\n");
    for (class, s) in &report.by_class {
        let rate = s
            .rate()
            .map(|r| format!("{:.0}%", r * 100.0))
            .unwrap_or_else(|| "—".to_string());
        body.push_str(&format!(
            "<div class=\"card\"><h2>{}</h2><p class=\"rate\">{}</p>\
             <p class=\"counts\">{} pass &middot; {} fail &middot; {} not run</p></div>\n",
            esc(class),
            rate,
            s.pass,
            s.fail,
            s.not_run
        ));
    }
    body.push_str("</section>\n");

    body.push_str(
        "<table><thead><tr><th>Test</th><th>Specification</th><th>Result</th>\
         <th>What happened</th></tr></thead><tbody>\n",
    );
    for r in &report.results {
        body.push_str(&format!(
            "<tr class=\"v-{}\"><td><code>{}</code><br><span class=\"title\">{}</span>\
             <br><span class=\"expect\">Expected: {}</span></td>\
             <td>{}</td><td><span class=\"chip chip-{}\">{}</span></td><td>{}</td></tr>\n",
            r.verdict,
            esc(r.id),
            esc(r.title),
            esc(r.expectation),
            esc(r.spec),
            r.verdict,
            r.verdict.replace('_', " "),
            esc(&r.detail)
        ));
    }
    body.push_str("</tbody></table>\n");

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Conformance report {}</title>\
         <link rel=\"stylesheet\" href=\"/css/conformance.css\"></head>\
         <body class=\"conformance-report\">{}</body></html>\n",
        esc(&report.session),
        body
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conformance::catalog::Class;
    use crate::conformance::session::{Observation, Registry};

    fn report_with(recorded: &[(&str, Observation, Option<u64>)]) -> Report {
        let reg = Registry::new(60, 8);
        let id = reg.create();
        for (test_id, obs, code) in recorded {
            let t = catalog::find(test_id).expect("catalogue entry");
            reg.with(&id, |s| s.record(t, obs, *code, 5));
        }
        let results = reg.with(&id, |s| s.results()).unwrap();
        build(&id, &results, "2026-08-26T00:00:00Z".to_string())
    }

    #[test]
    fn an_empty_run_reports_the_whole_catalogue_as_not_run() {
        let r = report_with(&[]);
        assert_eq!(r.results.len(), catalog::CATALOG.len());
        assert_eq!(r.totals.not_run, catalog::CATALOG.len());
        assert_eq!(r.totals.decided(), 0);
        // No decided tests must not read as a perfect score.
        assert!(r.totals.rate().is_none());
    }

    #[test]
    fn classes_are_counted_separately() {
        let r = report_with(&[
            ("h-grease-settings", Observation::SurvivedAndContinued, None),
            (
                "h-duplicate-setting",
                Observation::SurvivedAndContinued,
                Some(0x0109),
            ),
        ]);
        let ext = &r.by_class[Class::Extensibility.as_str()];
        let corr = &r.by_class[Class::Correctness.as_str()];
        assert_eq!(ext.pass, 1);
        assert_eq!(corr.fail, 1, "accepting a violation is a correctness fail");
        assert_eq!(r.totals.pass, 1);
        assert_eq!(r.totals.fail, 1);
    }

    #[test]
    fn the_rate_ignores_tests_that_never_ran() {
        let r = report_with(&[("h-grease-settings", Observation::SurvivedAndContinued, None)]);
        let ext = &r.by_class[Class::Extensibility.as_str()];
        assert_eq!(ext.rate(), Some(1.0), "one of one decided");
        assert!(ext.not_run > 0, "others in the class were not run");
    }

    #[test]
    fn badge_colour_tracks_failures_not_percentage() {
        let clean = ClassSummary {
            pass: 27,
            ..Default::default()
        };
        assert_eq!(badge_colour(&clean), "#2f7d52");

        // 96% but still a real protocol violation.
        let nearly = ClassSummary {
            pass: 26,
            fail: 1,
            ..Default::default()
        };
        assert_eq!(badge_colour(&nearly), "#9a6a00");

        let bad = ClassSummary {
            pass: 20,
            fail: 7,
            ..Default::default()
        };
        assert_eq!(badge_colour(&bad), "#b02a2a");

        assert_eq!(badge_colour(&ClassSummary::default()), "#9f9f9f");
    }

    #[test]
    fn badge_is_well_formed_and_states_the_score() {
        let r = report_with(&[("h-grease-settings", Observation::SurvivedAndContinued, None)]);
        let svg = badge_svg(&r);
        assert!(svg.starts_with("<svg"));
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("1/1"));
        assert!(svg.contains("role=\"img\""), "needs an accessible role");
        assert!(svg.contains("aria-label"));
    }

    #[test]
    fn badge_says_not_run_rather_than_zero() {
        let svg = badge_svg(&report_with(&[]));
        assert!(
            svg.contains("not run"),
            "an empty run must not render as 0/0"
        );
    }

    #[test]
    fn html_escapes_and_carries_no_inline_style_or_handler() {
        let r = report_with(&[(
            "h-grease-settings",
            Observation::ClosedWith { code: 0x0106 },
            None,
        )]);
        let page = html(&r);
        assert!(page.contains("<!DOCTYPE html>"));
        // The site's CSP forbids both; the report is served under it.
        assert!(!page.contains("style=\""), "no inline styles");
        assert!(!page.contains("onclick"), "no inline handlers");
        assert!(page.contains("conformance.css"), "styling is external");
        // Every row states the spec clause next to the verdict.
        assert!(page.contains("RFC 9114"));
    }

    #[test]
    fn html_escaping_neutralises_markup_in_details() {
        // detail text is server-generated, but escaping is the invariant worth
        // holding regardless of who writes the string.
        assert_eq!(esc("<script>&\"x\""), "&lt;script&gt;&amp;&quot;x&quot;");
    }
}
