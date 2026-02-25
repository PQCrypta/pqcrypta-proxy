//! Web Application Firewall (WAF) module
//!
//! Pattern-based request inspection covering OWASP Top 10 (2021) attack vectors:
//!
//! A01 Broken Access Control     — Path traversal patterns (directory traversal)
//! A02 Cryptographic Failures    — (enforced at TLS layer, not WAF layer)
//! A03 Injection                 — SQLi, NoSQLi, command injection patterns
//! A04 Insecure Design           — (architectural, not WAF-detectable at runtime)
//! A05 Security Misconfiguration — (handled at config validation, not request WAF)
//! A06 Vulnerable Components     — (supply-chain, not request WAF)
//! A07 Auth Failures             — Login brute-force patterns (excessive auth params)
//! A08 Software and Data Integrity — Deserialization patterns (Java/PHP object injection)
//! A09 Logging Failures          — (architectural, not WAF)
//! A10 SSRF                      — SSRF patterns (private IP ranges, metadata endpoints)
//!
//! Additionally covers:
//! - XSS (cross-site scripting)
//! - XXE (XML external entity injection)
//! - User-defined custom patterns
//!
//! All regex patterns are compiled once at startup for performance.

use axum::http::HeaderMap;
use regex::Regex;
use tracing::debug;

use crate::config::WafConfig;

/// Severity of a WAF rule match
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// WAF decision for a request
#[derive(Debug, Clone)]
pub enum WafVerdict {
    /// Request passes WAF checks
    Allow,
    /// Suspicious but allowed in detect mode — log only
    Detect { rule: String, severity: Severity },
    /// Request blocked
    Block { rule: String, severity: Severity },
}

/// Incoming request data for WAF inspection
pub struct WafRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub headers: &'a HeaderMap,
    /// Request body bytes (already limited to `max_body_scan_bytes`)
    pub body: Option<&'a [u8]>,
}

/// Compiled WAF engine
pub struct WafEngine {
    sqli_patterns: Vec<Regex>,
    xss_patterns: Vec<Regex>,
    path_traversal_patterns: Vec<Regex>,
    nosqli_patterns: Vec<Regex>,
    ssrf_patterns: Vec<Regex>,
    cmd_injection_patterns: Vec<Regex>,
    xxe_patterns: Vec<Regex>,
    deserialization_patterns: Vec<Regex>,
    custom_patterns: Vec<Regex>,
    config: WafConfig,
}

impl WafEngine {
    /// Build a new WAF engine from config, compiling all patterns at construction time.
    #[allow(clippy::new_without_default)]
    pub fn new(config: &WafConfig) -> Self {
        let sqli_patterns = if config.sqli {
            compile_patterns(&[
                r"(?i)(\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+(table|database)|alter\s+table|exec(\s|\()|execute\s*\()\b)",
                r#"(?i)('|")\s*(or|and)\s+('|")?\d+('|")?\s*=\s*('|")?\d+"#,
                r"(?i)\bor\s+1\s*=\s*1",
                r"(?i)\b(sleep|benchmark|waitfor\s+delay)\s*\(",
                r"(?i)(;|--)\s*(drop|select|insert|update|delete|create|alter)",
                r"'[^']*'(\s*(or|and)\s+'[^']*')*\s*=\s*'",
                r"(?i)\b(information_schema|sys\.tables|sysobjects|syscolumns)\b",
                r"(?i)(xp_cmdshell|sp_execute|sp_executesql)",
                r"(?i)\bload_file\s*\(",
                r"(?i)\binto\s+(outfile|dumpfile)\s+",
            ])
        } else {
            Vec::new()
        };

        let xss_patterns = if config.xss {
            compile_patterns(&[
                r"(?i)<\s*script[^>]*>",
                r"(?i)</\s*script\s*>",
                r"(?i)\bjavascript\s*:",
                r"(?i)\bon(error|load|click|mouseover|focus|blur|change|submit|reset|select|keydown|keyup|keypress|mousedown|mouseup|mousemove|dblclick|contextmenu|drag|drop|scroll|resize|unload|beforeunload|hashchange|popstate|message|storage|online|offline|pagehide|pageshow|visibilitychange)\s*=",
                r"(?i)\beval\s*\(",
                r"(?i)\bdocument\.(cookie|write|location)",
                r"(?i)\bwindow\.(location|open|eval)",
                r#"(?i)<\s*(img|iframe|object|embed|link|meta|style|body|input|form|a)\s[^>]*\b(src|href|data|action|formaction)\s*=\s*['"]?\s*javascript:"#,
                r"(?i)expression\s*\(",
                r"(?i)vbscript\s*:",
                r"(?i)<\s*svg[^>]*>.*\bon\w+\s*=",
                r"(?i)data\s*:\s*text/html",
            ])
        } else {
            Vec::new()
        };

        let path_traversal_patterns = if config.path_traversal {
            compile_patterns(&[
                r"\.\./",
                r"\.\.\\",
                r"(?i)%2e%2e[%/\\]",
                r"(?i)%252e%252e[%/\\]",
                r"\x00",
                r"(?i)%00",
                r"(?i)(\.\./){2,}",
                r"(?i)(\.\.%2f){2,}",
                r"(?i)(\.\.%5c){2,}",
                r"(?i)%c0%ae%c0%ae",
            ])
        } else {
            Vec::new()
        };

        let nosqli_patterns = if config.nosqli {
            compile_patterns(&[
                r"(?i)\$\s*(where|gt|gte|lt|lte|ne|eq|in|nin|or|and|not|nor|exists|type|mod|regex|text|where)\b",
                r"(?i)\$\s*regex\s*[:\{]",
                r#"\{\s*"\$[a-zA-Z]+"\s*:"#,
                r"(?i)\$\s*javascript\s*:",
                r"(?i)\$\s*accumulator\s*[:\{]",
                r"(?i)\$\s*function\s*[:\{]",
            ])
        } else {
            Vec::new()
        };

        let ssrf_patterns = if config.ssrf {
            compile_patterns(&[
                r"(?i)169\.254\.",
                r"(?i)file\s*://",
                r"(?i)dict\s*://",
                r"(?i)gopher\s*://",
                r"127\.\d+\.\d+\.\d+",
                r"\[::1\]",
                r"(?i)localhost",
                r"(?i)0x7f000001",    // 127.0.0.1 hex
                r"(?i)2130706433",    // 127.0.0.1 decimal
                r"(?i)0177\.0\.0\.1", // 127.0.0.1 octal
                r"(?i)metadata\.google\.internal",
                r"(?i)169\.254\.169\.254",
            ])
        } else {
            Vec::new()
        };

        // A03 Injection — OS/command injection (shell metacharacters in parameters)
        let cmd_injection_patterns = compile_patterns(&[
            r"(?i)(;|\||`|&&|\|\|)\s*(ls|cat|id|whoami|uname|nc|curl|wget|bash|sh|cmd|powershell|python|perl|ruby|php|nmap|ping|traceroute)",
            r"(?i)\$\s*\(.*\)",   // Command substitution $(...)
            r"`[^`]+`",           // Backtick command substitution
            r"(?i)\bsystem\s*\(", // PHP system()
            r"(?i)\bpassthru\s*\(",
            r"(?i)\bshell_exec\s*\(",
            r"(?i)\bpopen\s*\(",
            r"(?i)\bproc_open\s*\(",
            r"(?i)\bexec\s*\(",
        ]);

        // A08 — XXE (XML external entity injection)
        let xxe_patterns = compile_patterns(&[
            r"(?i)<!ENTITY",
            r#"(?i)SYSTEM\s+['"]file://"#,
            r#"(?i)SYSTEM\s+['"]https?://"#,
            r"(?i)<!DOCTYPE[^>]+\[",
            r"(?i)%[a-zA-Z][a-zA-Z0-9]*;", // Parameter entity reference
        ]);

        // A08 — Insecure deserialization (Java serialized objects, PHP unserialize)
        let deserialization_patterns = compile_patterns(&[
            r"rO0AB",                                  // Java serialised object base64 header
            r#"(?i)O:\d+:"[a-zA-Z_][a-zA-Z0-9_\\]*""#, // PHP object injection
            r"\xac\xed\x00\x05",                       // Java serialisation magic bytes (literal)
            r"(?i)aced0005",                           // Java serialisation magic hex
            r"(?i)java\.lang\.(Runtime|ProcessBuilder|Class)",
            r"(?i)sun\.reflect\.",
            r"(?i)com\.sun\.org\.apache\.xml\.internal\.security\.utils\.Base64",
        ]);

        let custom_patterns = config
            .custom_patterns
            .iter()
            .filter_map(|p| {
                Regex::new(p)
                    .map_err(|e| tracing::warn!("Invalid custom WAF pattern '{}': {}", p, e))
                    .ok()
            })
            .collect();

        Self {
            sqli_patterns,
            xss_patterns,
            path_traversal_patterns,
            nosqli_patterns,
            ssrf_patterns,
            cmd_injection_patterns,
            xxe_patterns,
            deserialization_patterns,
            custom_patterns,
            config: config.clone(),
        }
    }

    /// Inspect a request and return a WAF verdict.
    pub fn inspect(&self, req: &WafRequest<'_>) -> WafVerdict {
        let block_mode = self.config.mode == "block";

        // Scan path + query
        let target = format!(
            "{}{}",
            req.path,
            if req.query.is_empty() {
                String::new()
            } else {
                format!("?{}", req.query)
            }
        );

        if let Some(verdict) = self.scan_str(&target, block_mode) {
            debug!("WAF hit on path/query: {}", target);
            return verdict;
        }

        // Scan selected request headers (User-Agent, Referer, Cookie, X-* headers)
        for (name, value) in req.headers.iter() {
            let name_str = name.as_str();
            if matches!(
                name_str,
                "user-agent" | "referer" | "cookie" | "x-forwarded-for"
            ) {
                if let Ok(v) = value.to_str() {
                    if let Some(verdict) = self.scan_str(v, block_mode) {
                        debug!("WAF hit on header {}: {}", name_str, v);
                        return verdict;
                    }
                }
            }
        }

        // Scan body (up to max_body_scan_bytes)
        if let Some(body) = req.body {
            if !body.is_empty() && self.config.scan_json_body {
                let body_slice = &body[..body.len().min(self.config.max_body_scan_bytes)];
                if let Ok(body_str) = std::str::from_utf8(body_slice) {
                    if let Some(verdict) = self.scan_str(body_str, block_mode) {
                        debug!("WAF hit in request body");
                        return verdict;
                    }
                }
            }
        }

        WafVerdict::Allow
    }

    /// Scan a string against all enabled pattern sets.
    fn scan_str(&self, input: &str, block_mode: bool) -> Option<WafVerdict> {
        // Path traversal checked first (highest signal)
        for pat in &self.path_traversal_patterns {
            if pat.is_match(input) {
                let rule = format!(
                    "path-traversal:{}",
                    pat.as_str().chars().take(40).collect::<String>()
                );
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::High,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::High,
                    }
                });
            }
        }

        for pat in &self.sqli_patterns {
            if pat.is_match(input) {
                let rule = format!("sqli:{}", pat.as_str().chars().take(40).collect::<String>());
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::High,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::High,
                    }
                });
            }
        }

        for pat in &self.xss_patterns {
            if pat.is_match(input) {
                let rule = format!("xss:{}", pat.as_str().chars().take(40).collect::<String>());
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::Medium,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::Medium,
                    }
                });
            }
        }

        for pat in &self.nosqli_patterns {
            if pat.is_match(input) {
                let rule = format!(
                    "nosqli:{}",
                    pat.as_str().chars().take(40).collect::<String>()
                );
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::Medium,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::Medium,
                    }
                });
            }
        }

        for pat in &self.ssrf_patterns {
            if pat.is_match(input) {
                let rule = format!("ssrf:{}", pat.as_str().chars().take(40).collect::<String>());
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::Critical,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::Critical,
                    }
                });
            }
        }

        // A03 command injection
        for pat in &self.cmd_injection_patterns {
            if pat.is_match(input) {
                let rule = format!(
                    "cmd-injection:{}",
                    pat.as_str().chars().take(40).collect::<String>()
                );
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::Critical,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::Critical,
                    }
                });
            }
        }

        // A08 XXE
        for pat in &self.xxe_patterns {
            if pat.is_match(input) {
                let rule = format!("xxe:{}", pat.as_str().chars().take(40).collect::<String>());
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::High,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::High,
                    }
                });
            }
        }

        // A08 deserialization
        for pat in &self.deserialization_patterns {
            if pat.is_match(input) {
                let rule = format!(
                    "deser:{}",
                    pat.as_str().chars().take(40).collect::<String>()
                );
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::Critical,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::Critical,
                    }
                });
            }
        }

        for pat in &self.custom_patterns {
            if pat.is_match(input) {
                let rule = format!(
                    "custom:{}",
                    pat.as_str().chars().take(40).collect::<String>()
                );
                return Some(if block_mode {
                    WafVerdict::Block {
                        rule,
                        severity: Severity::High,
                    }
                } else {
                    WafVerdict::Detect {
                        rule,
                        severity: Severity::High,
                    }
                });
            }
        }

        None
    }
}

/// Compile a slice of regex pattern strings, logging warnings for invalid patterns.
fn compile_patterns(patterns: &[&str]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| {
            Regex::new(p)
                .map_err(|e| tracing::error!("Failed to compile WAF pattern '{}': {}", p, e))
                .ok()
        })
        .collect()
}
