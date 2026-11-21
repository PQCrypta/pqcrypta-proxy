//! Intervention tracking for blocked requests.

use super::phase::Phase;
use crate::actions::RuleMetadata;

/// An intervention (blocking decision) from rule processing.
#[derive(Debug, Clone)]
pub struct Intervention {
    /// HTTP status code to return.
    pub status: u16,
    /// Redirect URL (if applicable).
    pub url: Option<String>,
    /// Log message.
    pub log: Option<String>,
    /// Rule IDs that triggered the intervention.
    pub rule_ids: Vec<String>,
    /// Phase in which intervention occurred.
    pub phase: Phase,
    /// Whether to drop the connection.
    pub drop_connection: bool,
    /// Matched rule metadata.
    pub metadata: Vec<RuleMetadata>,
}

impl Intervention {
    /// Create a new intervention.
    pub fn new(status: u16, phase: Phase) -> Self {
        Self {
            status,
            url: None,
            log: None,
            rule_ids: Vec::new(),
            phase,
            drop_connection: false,
            metadata: Vec::new(),
        }
    }

    /// Create a deny intervention.
    pub fn deny(status: u16, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(status, phase);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a redirect intervention.
    pub fn redirect(url: String, phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(302, phase);
        intervention.url = Some(url);
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Create a drop intervention.
    pub fn drop(phase: Phase, rule_id: Option<String>) -> Self {
        let mut intervention = Self::new(444, phase);
        intervention.drop_connection = true;
        if let Some(id) = rule_id {
            intervention.rule_ids.push(id);
        }
        intervention
    }

    /// Add a rule ID, ignoring one already recorded.
    ///
    /// A rule reports its id both directly and through its metadata, so without
    /// this the triggering rule appears twice -- which reaches operators as a
    /// duplicated `X-WAF-Rule` and audit entry.
    pub fn add_rule_id(&mut self, id: String) {
        if !self.rule_ids.contains(&id) {
            self.rule_ids.push(id);
        }
    }

    /// Add metadata from a matched rule.
    pub fn add_metadata(&mut self, metadata: RuleMetadata) {
        if let Some(ref id) = metadata.id {
            if !self.rule_ids.contains(id) {
                self.rule_ids.push(id.clone());
            }
        }
        if let Some(ref msg) = metadata.msg {
            if self.log.is_none() {
                self.log = Some(msg.clone());
            }
        }
        self.metadata.push(metadata);
    }

    /// Set log message.
    pub fn set_log(&mut self, log: String) {
        self.log = Some(log);
    }

    /// Format as a log entry.
    pub fn format_log(&self) -> String {
        let mut parts = vec![format!("[status {}]", self.status)];

        if !self.rule_ids.is_empty() {
            parts.push(format!("[rule_ids: {}]", self.rule_ids.join(", ")));
        }

        if let Some(ref log) = self.log {
            parts.push(format!("[msg: {}]", log));
        }

        if let Some(ref url) = self.url {
            parts.push(format!("[redirect: {}]", url));
        }

        parts.push(format!("[phase: {}]", self.phase.name()));

        parts.join(" ")
    }
}

impl Default for Intervention {
    fn default() -> Self {
        Self::new(403, Phase::RequestHeaders)
    }
}

/// Builder for creating interventions.
#[derive(Debug, Clone)]
pub struct InterventionBuilder {
    intervention: Intervention,
}

impl InterventionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            intervention: Intervention::default(),
        }
    }

    /// Set status code.
    pub fn status(mut self, status: u16) -> Self {
        self.intervention.status = status;
        self
    }

    /// Set phase.
    pub fn phase(mut self, phase: Phase) -> Self {
        self.intervention.phase = phase;
        self
    }

    /// Set redirect URL.
    pub fn redirect(mut self, url: String) -> Self {
        self.intervention.status = 302;
        self.intervention.url = Some(url);
        self
    }

    /// Set drop connection flag.
    pub fn drop_connection(mut self) -> Self {
        self.intervention.drop_connection = true;
        self.intervention.status = 444;
        self
    }

    /// Add rule ID.
    pub fn rule_id(mut self, id: String) -> Self {
        self.intervention.rule_ids.push(id);
        self
    }

    /// Set log message.
    pub fn log(mut self, msg: String) -> Self {
        self.intervention.log = Some(msg);
        self
    }

    /// Build the intervention.
    pub fn build(self) -> Intervention {
        self.intervention
    }
}

impl Default for InterventionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn log_lines_escape_as_modsecurity() {
        let m = super::RuleMessage {
            rule_id: Some("932300".into()),
            msg: Some("say \"hi\"".into()),
            data: Some("\r\nMAIL\u{1}\\\u{e9}".into()),
            severity: Some(2),
            ver: None,
            tags: vec!["a".into()],
        };
        assert_eq!(
            m.log_line(),
            r#"[id "932300"] [msg "say \"hi\""] [data "\r\nMAIL\x01\\\xc3\xa9"] [severity "2"] [tag "a"]"#
        );
    }

    use super::*;

    #[test]
    fn test_deny_intervention() {
        let intervention =
            Intervention::deny(403, Phase::RequestHeaders, Some("12345".to_string()));
        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.rule_ids, vec!["12345".to_string()]);
        assert!(!intervention.drop_connection);
    }

    #[test]
    fn test_redirect_intervention() {
        let intervention = Intervention::redirect(
            "https://example.com/blocked".to_string(),
            Phase::RequestHeaders,
            Some("12345".to_string()),
        );
        assert_eq!(intervention.status, 302);
        assert_eq!(
            intervention.url,
            Some("https://example.com/blocked".to_string())
        );
    }

    #[test]
    fn test_builder() {
        let intervention = InterventionBuilder::new()
            .status(403)
            .phase(Phase::RequestBody)
            .rule_id("100".to_string())
            .log("SQL Injection detected".to_string())
            .build();

        assert_eq!(intervention.status, 403);
        assert_eq!(intervention.phase, Phase::RequestBody);
        assert_eq!(intervention.rule_ids, vec!["100".to_string()]);
    }

    #[test]
    fn test_format_log() {
        let intervention =
            Intervention::deny(403, Phase::RequestHeaders, Some("942100".to_string()));
        let log = intervention.format_log();
        assert!(log.contains("[status 403]"));
        assert!(log.contains("942100"));
    }
}

/// What a rule that matched says about it, as ModSecurity logs it: its id,
/// its `msg` and `logdata` with their macros expanded at the match
/// (`%{MATCHED_VAR}`, `%{TX.0}`), its severity, version and tags. A rule
/// with `nolog` leaves none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMessage {
    /// The rule's id (a chain's starter's).
    pub rule_id: Option<String>,
    /// `msg`, expanded.
    pub msg: Option<String>,
    /// `logdata`, expanded.
    pub data: Option<String>,
    /// `severity`.
    pub severity: Option<u8>,
    /// `ver`.
    pub ver: Option<String>,
    /// `tag`s, in order.
    pub tags: Vec<String>,
}

impl RuleMessage {
    /// The message in ModSecurity's log form:
    /// `[id "942100"] [msg "..."] [data "..."] [severity "2"] [ver "..."] [tag "..."]`,
    /// each value escaped as ModSecurity escapes it (`log_escape`).
    pub fn log_line(&self) -> String {
        let mut out = String::new();
        let mut field = |name: &str, value: &str| {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&format!("[{name} \"{}\"]", log_escape(value)));
        };
        if let Some(id) = &self.rule_id {
            field("id", id);
        }
        if let Some(msg) = &self.msg {
            field("msg", msg);
        }
        if let Some(data) = &self.data {
            field("data", data);
        }
        if let Some(s) = self.severity {
            field("severity", &s.to_string());
        }
        if let Some(v) = &self.ver {
            field("ver", v);
        }
        for t in &self.tags {
            field("tag", t);
        }
        out
    }
}

/// ModSecurity's `log_escape` (`msc_util.c`, with quotes escaped): a log line
/// stays one line of printable ASCII. `"` and `\\` take a backslash, the C
/// control escapes stay as they are written in C, and any other byte below
/// 0x20 or from 0x7f is `\\xHH`.
fn log_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in crate::bytes::bytes(value) {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x0b => out.push_str("\\v"),
            0x00..=0x1f | 0x7f..=0xff => out.push_str(&format!("\\x{b:02x}")),
            _ => out.push(char::from(b)),
        }
    }
    out
}
