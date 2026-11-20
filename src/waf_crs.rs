//! The OWASP Core Rule Set, run beside the native rules of [`crate::waf`].
//!
//! CRS is run by a pure-Rust SecLang engine (`vendor/zentinel-modsec`, with
//! libinjection itself behind `@detectSQLi` and `@detectXSS`) from an entry
//! file, `[waf.crs] entry`: one that turns the engine on and `Include`s
//! `crs-setup.conf`, the rules, and the site's own exclusions. Each request
//! is one transaction. Its head (method, URI, protocol, headers) runs CRS's
//! phase 1 when the head is read; phase 2, where most of CRS's attack rules
//! are, runs with the body, or without one when there is none. CRS decides
//! by anomaly score (rule 949110). A request it would deny is blocked in
//! `mode = "block"` and reported only in `"detect"`, and is named either way
//! by the rules that raised its score, not by 949110.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use http::{HeaderMap, Version};
use zentinel_modsec::engine::SetVarChange;
use zentinel_modsec::{ModSecurity, Transaction};

/// A loaded rule set, and the state of the files it was loaded from.
pub struct CrsLayer {
    modsec: ModSecurity,
    entry: String,
    files: Vec<(PathBuf, Option<SystemTime>, u64)>,
}

/// One request's CRS transaction: phase 1 run, phase 2 to come. Boxed: it
/// rides in every pending head ([`crate::waf::WafHead`]), which is moved.
pub struct CrsTransaction {
    tx: Box<Transaction>,
}

/// The head of a request as CRS reads it.
pub struct CrsHead<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    /// The protocol the request arrived over; HTTP/1.1 when unknown.
    pub version: Option<Version>,
    /// The request's authority (`:authority` over HTTP/2 and HTTP/3, which
    /// carry no Host header), given to CRS as its Host when there is none.
    pub authority: Option<&'a str>,
    pub headers: &'a HeaderMap,
    /// The request is exempt from user-agent rules (the native WAF's
    /// `skip_bot_ua_check`): CRS's scanner detection, 913xxx, is lifted
    /// with them, so one exemption means the same thing to both engines.
    pub skip_scanner_rules: bool,
}

/// CRS's scanner detection: REQUEST-913-SCANNER-DETECTION.
const SCANNER_RULES: &str = "913000-913999";

/// What CRS made of a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrsOutcome {
    /// CRS denies it: its inbound anomaly score reached the threshold
    /// (949110, or 949111 blocking early), or a rule denied outright (an
    /// unparsable body, 200002).
    pub denied: bool,
    /// CRS's inbound anomaly score at the paranoia level it blocks at.
    pub score: u32,
    /// The rules that raised the score, in the order they did, and any rule
    /// that denied outright other than 949110.
    pub rules: Vec<String>,
    /// What those rules matched in: variable names (`ARGS:json.q`,
    /// `REQUEST_HEADERS:Referer`), never values, which may be a user's data.
    /// What an exclusion names. At most [`MAX_VARIABLES`], each printable
    /// and at most [`MAX_VARIABLE_LEN`] bytes: a name can be the client's.
    pub variables: Vec<String>,
}

/// Variable names a verdict carries.
const MAX_VARIABLES: usize = 3;
/// Longest variable name a verdict carries, in bytes.
const MAX_VARIABLE_LEN: usize = 80;

/// A variable name fit for a log line: printable ASCII, the rest `?`, cut to
/// [`MAX_VARIABLE_LEN`].
fn loggable(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .take(MAX_VARIABLE_LEN)
        .collect()
}

impl CrsLayer {
    /// Load the rule set `entry` names, with every file it includes.
    pub fn load(entry: &str) -> Result<Self, String> {
        let modsec = ModSecurity::from_file(entry).map_err(|e| format!("CRS {entry}: {e}"))?;
        Ok(Self {
            modsec,
            entry: entry.to_string(),
            files: file_state(entry),
        })
    }

    /// A rule set from SecLang text, for tests.
    #[cfg(test)]
    pub fn from_rules(rules: &str) -> Self {
        Self {
            modsec: ModSecurity::from_string(rules).expect("rules parse"),
            entry: String::new(),
            files: Vec::new(),
        }
    }

    /// Rules loaded, every chain link counted.
    pub fn rule_count(&self) -> usize {
        self.modsec.rule_count()
    }

    /// The same entry file, and no file beside it changed since this was
    /// loaded: a configuration reload can keep this rule set rather than
    /// compile the same rules again.
    pub fn unchanged(&self, entry: &str) -> bool {
        self.entry == entry && self.files == file_state(entry)
    }

    /// Start a request's transaction: its head through phase 1.
    pub fn head(&self, head: &CrsHead<'_>) -> CrsTransaction {
        let mut tx = self.modsec.new_transaction();
        tx.set_record_setvar_effects(true);
        if head.skip_scanner_rules {
            tx.remove_rules_by_id(SCANNER_RULES);
        }
        let uri = if head.query.is_empty() {
            head.path.to_string()
        } else {
            format!("{}?{}", head.path, head.query)
        };
        let protocol = match head.version {
            Some(Version::HTTP_09) => "HTTP/0.9",
            Some(Version::HTTP_10) => "HTTP/1.0",
            Some(Version::HTTP_2) => "HTTP/2.0",
            Some(Version::HTTP_3) => "HTTP/3.0",
            _ => "HTTP/1.1",
        };
        let mut errors = Vec::new();
        note(&mut errors, tx.process_uri(&uri, head.method, protocol));
        if !head.headers.contains_key(http::header::HOST) {
            if let Some(authority) = head.authority {
                note(&mut errors, tx.add_request_header("Host", authority));
            }
        }
        for (name, value) in head.headers {
            note(
                &mut errors,
                tx.add_request_header(name.as_str(), &String::from_utf8_lossy(value.as_bytes())),
            );
        }
        note(&mut errors, tx.process_request_headers());
        report_errors(&errors);
        CrsTransaction { tx: Box::new(tx) }
    }

    /// Finish a transaction: its body, if any, through phase 2. A request
    /// denied in phase 1 is left as it is.
    pub fn body(&self, t: &mut CrsTransaction, body: Option<&[u8]>) {
        if t.tx.has_intervention() {
            return;
        }
        let mut errors = Vec::new();
        if let Some(body) = body.filter(|b| !b.is_empty()) {
            note(&mut errors, t.tx.append_request_body(body));
        }
        note(&mut errors, t.tx.process_request_body());
        report_errors(&errors);
    }
}

impl CrsTransaction {
    /// What CRS decided so far.
    pub fn outcome(&self) -> CrsOutcome {
        let mut rules: Vec<String> = Vec::new();
        for e in self.tx.setvar_effects() {
            if e.collection == "tx"
                && e.key.starts_with("inbound_anomaly_score_pl")
                && matches!(e.op, SetVarChange::Increment(n) if n > 0)
                && !rules.contains(&e.rule_id)
            {
                rules.push(e.rule_id.clone());
            }
        }
        let intervention = self.tx.intervention();
        if let Some(i) = intervention {
            // The 949 rules (949110, and 949111 when CRS blocks early) say
            // only that the score reached the threshold; the rules that
            // scored are the cause. A rule that denied outright (200002, an
            // unparsable body) is named.
            for id in &i.rule_ids {
                if !id.starts_with("949") && !rules.contains(id) {
                    rules.push(id.clone());
                }
            }
        }
        use zentinel_modsec::variables::Collection;
        let score = self
            .tx
            .tx()
            .get("blocking_inbound_anomaly_score")
            .and_then(|v| v.first().and_then(|s| s.parse::<u32>().ok()))
            .unwrap_or(0);
        let mut variables: Vec<String> = Vec::new();
        for m in self.tx.matched_data() {
            if variables.len() == MAX_VARIABLES {
                break;
            }
            if m.rule_id.as_ref().is_some_and(|id| rules.contains(id)) {
                let name = loggable(&m.variable);
                if !variables.contains(&name) {
                    variables.push(name);
                }
            }
        }
        CrsOutcome {
            denied: intervention.is_some(),
            score,
            rules,
            variables,
        }
    }

    /// Denied already: phase 1 decided, so the body need not be read.
    pub fn denied(&self) -> bool {
        self.tx.has_intervention()
    }
}

fn note(errors: &mut Vec<String>, r: zentinel_modsec::Result<()>) {
    if let Err(e) = r {
        errors.push(e.to_string());
    }
}

/// An engine error leaves the request to the native rules: CRS's verdict on
/// it is incomplete, and is not enforced on a partial reading.
fn report_errors(errors: &[String]) {
    if let Some(first) = errors.first() {
        tracing::debug!(errors = errors.len(), first = %first, "CRS could not read a request in full");
    }
}

/// Every file in the entry file's directory tree, links followed, with its
/// modification time and length: what a reload compares to tell whether the
/// rules changed.
fn file_state(entry: &str) -> Vec<(PathBuf, Option<SystemTime>, u64)> {
    let mut out = Vec::new();
    let root = Path::new(entry).parent().unwrap_or_else(|| Path::new("."));
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Through links: the rules are installed once per version and
            // linked into the entry's directory, so an upgrade changes the
            // files behind the same names
            match std::fs::metadata(&path) {
                Ok(m) if m.is_dir() => stack.push(path),
                Ok(m) => out.push((path, m.modified().ok(), m.len())),
                Err(_) => {}
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecAction "id:1,phase:1,pass,nolog,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule ARGS "@detectSQLi" "id:942100,phase:2,pass,setvar:tx.inbound_anomaly_score_pl1=+5,setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule REQUEST_HEADERS:User-Agent "@contains nikto" "id:913100,phase:1,pass,t:lowercase,setvar:tx.inbound_anomaly_score_pl1=+5,setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule &REQUEST_HEADERS:Host "@eq 0" "id:920280,phase:1,pass,setvar:tx.inbound_anomaly_score_pl1=+3,setvar:tx.blocking_inbound_anomaly_score=+3"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 5" "id:949110,phase:1,deny,status:403"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 5" "id:949111,phase:2,deny,status:403"
"#;

    fn head<'a>(path: &'a str, query: &'a str, headers: &'a HeaderMap) -> CrsHead<'a> {
        CrsHead {
            method: "GET",
            path,
            query,
            version: Some(Version::HTTP_2),
            authority: Some("pqcrypta.com"),
            headers,
            skip_scanner_rules: false,
        }
    }

    #[test]
    fn sql_in_the_query_is_denied_in_phase_two_and_named_by_its_rule() {
        let crs = CrsLayer::from_rules(RULES);
        let headers = HeaderMap::new();
        let mut t = crs.head(&head("/search", "q=1%27%20OR%20%271%27=%271", &headers));
        assert!(!t.denied(), "phase 1 has nothing to deny");
        crs.body(&mut t, None);
        let o = t.outcome();
        assert!(o.denied);
        assert_eq!(o.rules, ["942100"]);
        assert_eq!(o.score, 5);
        assert_eq!(o.variables, ["ARGS:q"], "where it matched, not what");
    }

    /// A variable name is the client's: what a verdict carries of it is
    /// printable and bounded
    #[test]
    fn matched_variable_names_are_bounded_and_printable() {
        assert_eq!(loggable("ARGS:json.a\nb\u{7f}"), "ARGS:json.a?b?");
        assert_eq!(loggable(&"x".repeat(500)).len(), MAX_VARIABLE_LEN);
    }

    #[test]
    fn a_scanner_is_denied_in_phase_one() {
        let crs = CrsLayer::from_rules(RULES);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.00 (Nikto/2.1.6)".parse().unwrap(),
        );
        let t = crs.head(&head("/", "", &headers));
        assert!(t.denied());
        assert_eq!(t.outcome().rules, ["913100"]);
    }

    /// HTTP/2 and HTTP/3 carry the host in `:authority`; CRS must still see one
    #[test]
    fn the_authority_stands_in_for_a_missing_host_header() {
        let crs = CrsLayer::from_rules(RULES);
        let headers = HeaderMap::new();
        let mut t = crs.head(&head("/", "q=hello", &headers));
        crs.body(&mut t, None);
        assert_eq!(t.outcome(), CrsOutcome::default());
    }

    #[test]
    fn crawler_user_agents_and_prose_pass() {
        let crs = CrsLayer::from_rules(RULES);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::USER_AGENT,
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"
                .parse()
                .unwrap(),
        );
        let mut t = crs.head(&head("/blog", "q=select%20a%20cipher%20suite", &headers));
        crs.body(&mut t, None);
        assert!(!t.outcome().denied);
    }

    #[test]
    fn sql_in_a_form_body_is_denied() {
        let crs = CrsLayer::from_rules(RULES);
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let mut t = crs.head(&CrsHead {
            method: "POST",
            ..head("/login", "", &headers)
        });
        crs.body(&mut t, Some(b"user=admin%27--&pass=x"));
        let o = t.outcome();
        assert!(o.denied);
        assert_eq!(o.rules, ["942100"]);
    }

    /// Where the native WAF lifts its user-agent rules (our own monitoring,
    /// crawler paths), CRS's scanner detection is lifted too; its injection
    /// rules are not
    #[test]
    fn the_user_agent_exemption_lifts_scanner_detection_only() {
        let crs = CrsLayer::from_rules(RULES);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::USER_AGENT, "Nikto/2.5.0".parse().unwrap());
        let exempt = |query| CrsHead {
            skip_scanner_rules: true,
            ..head("/", query, &headers)
        };
        let mut t = crs.head(&exempt(""));
        crs.body(&mut t, None);
        assert!(!t.outcome().denied, "the scanner rule is lifted");
        let mut t = crs.head(&exempt("q=1%27%20OR%20%271%27=%271"));
        crs.body(&mut t, None);
        assert_eq!(t.outcome().rules, ["942100"], "SQL injection is not");
    }

    /// CRS's 941010: a path of only characters no XSS needs is dropped from
    /// the XSS rules (`ctl:ruleRemoveTargetByTag`); any other path, and the
    /// arguments, are still inspected
    #[test]
    fn a_safe_path_is_removed_from_the_tagged_rules_by_tag() {
        const XSS: &str = r#"
SecRuleEngine On
SecAction "id:1,phase:1,pass,nolog,setvar:tx.blocking_inbound_anomaly_score=0"
SecRule REQUEST_FILENAME "!@validateByteRange 20,45-47,48-57,65-90,95,97-122" "id:941010,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=xss-perf-disable;REQUEST_FILENAME"
SecRule REQUEST_FILENAME|ARGS "@contains alert" "id:941999,phase:2,pass,tag:'xss-perf-disable',setvar:tx.inbound_anomaly_score_pl1=+5,setvar:tx.blocking_inbound_anomaly_score=+5"
SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE "@ge 5" "id:949110,phase:2,deny,status:403"
"#;
        let crs = CrsLayer::from_rules(XSS);
        let headers = HeaderMap::new();
        let run = |path, query| {
            let mut t = crs.head(&head(path, query, &headers));
            crs.body(&mut t, None);
            t.outcome().denied
        };
        assert!(!run("/alert", ""), "a safe path is not an XSS target");
        assert!(run("/alert(1)", ""), "a path with ( still is");
        assert!(run("/search", "q=alert"), "the arguments still are");
    }

    /// A reload keeps the loaded rules until a file behind the entry changes,
    /// a linked rules directory (one install per version) included
    #[test]
    fn a_changed_rule_file_behind_a_link_is_noticed() {
        let base = std::env::temp_dir().join(format!("crs-reload-{}", std::process::id()));
        let installed = base.join("installed");
        let site = base.join("site");
        std::fs::create_dir_all(&installed).unwrap();
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(
            installed.join("REQUEST-913.conf"),
            "SecRule REQUEST_HEADERS:User-Agent \"@contains nikto\" \"id:913100,phase:1,pass,t:lowercase\"\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&installed, site.join("rules")).unwrap();
        let entry = site.join("main.conf");
        std::fs::write(&entry, "SecRuleEngine On\nInclude rules/*.conf\n").unwrap();
        let entry = entry.to_str().unwrap();

        let crs = CrsLayer::load(entry).expect("loads through the link");
        assert!(crs.rule_count() >= 1);
        assert!(crs.unchanged(entry), "nothing changed");
        std::fs::write(
            installed.join("REQUEST-913.conf"),
            "SecRule REQUEST_HEADERS:User-Agent \"@contains sqlmap\" \"id:913100,phase:1,pass,t:lowercase\"\n# a new version\n",
        )
        .unwrap();
        assert!(!crs.unchanged(entry), "a rule file behind the link changed");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
