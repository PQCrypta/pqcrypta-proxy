//! Structured audit logging for security-relevant events.
//!
//! Events are serialised to JSON and written asynchronously via an unbounded
//! channel to avoid blocking request handlers.  The logger task drains the
//! channel and writes each event to the configured output (file or stderr).

use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::config::LoggingConfig;

/// Security-relevant audit events
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditEvent {
    /// Admin API action (reload, shutdown, etc.)
    AdminAction {
        ip: String,
        action: String,
        success: bool,
        detail: Option<String>,
    },
    /// Authentication failure
    AuthFailure {
        ip: String,
        reason: String,
        attempt: u32,
    },
    /// IP address blocked (manual or automatic)
    IpBlocked {
        ip: String,
        reason: String,
        duration_secs: Option<u64>,
    },
    /// Rate limit exceeded
    RateLimitHit {
        ip: String,
        path: String,
        limit: u32,
    },
    /// PQC downgrade detected (classical KEM negotiated when PQC required)
    PqcDowngrade {
        ip: String,
        reason: String,
        classical_kem: String,
    },
    /// WAF rule triggered — request blocked
    WafBlock {
        ip: String,
        rule: String,
        path: String,
    },
    /// WAF rule triggered — detection mode (logged, not blocked)
    WafDetect {
        ip: String,
        rule: String,
        path: String,
    },
    /// Configuration reloaded
    ConfigReload {
        success: bool,
        changed_sections: Vec<String>,
    },
    /// TLS certificates reloaded
    TlsReload { success: bool },
    /// JA3 fingerprint seen from multiple IPs (possible replay)
    Ja3Replay {
        ja3: String,
        ip: String,
        ip_count: usize,
    },
    /// JA3 fingerprint composition drifted (possible spoofing)
    Ja3Drift {
        ja3: String,
        ip: String,
        drift_score: f64,
    },
}

/// Wrapper with metadata added at emission time
#[derive(Serialize)]
struct AuditRecord {
    timestamp: String,
    level: &'static str,
    category: &'static str,
    #[serde(flatten)]
    event: AuditEvent,
}

impl AuditEvent {
    fn level(&self) -> &'static str {
        match self {
            Self::AdminAction { success: false, .. }
            | Self::AuthFailure { .. }
            | Self::PqcDowngrade { .. }
            | Self::WafBlock { .. }
            | Self::Ja3Replay { .. }
            | Self::Ja3Drift { .. }
            | Self::IpBlocked { .. } => "WARN",
            Self::WafDetect { .. }
            | Self::RateLimitHit { .. }
            | Self::ConfigReload { success: false, .. }
            | Self::TlsReload { success: false } => "INFO",
            _ => "INFO",
        }
    }

    fn category(&self) -> &'static str {
        match self {
            Self::AdminAction { .. } => "admin",
            Self::AuthFailure { .. } => "auth",
            Self::IpBlocked { .. } => "security",
            Self::RateLimitHit { .. } => "rate_limit",
            Self::PqcDowngrade { .. } => "pqc",
            Self::WafBlock { .. } | Self::WafDetect { .. } => "waf",
            Self::ConfigReload { .. } => "config",
            Self::TlsReload { .. } => "tls",
            Self::Ja3Replay { .. } | Self::Ja3Drift { .. } => "fingerprint",
        }
    }
}

/// Async audit logger
pub struct AuditLogger {
    tx: mpsc::UnboundedSender<AuditEvent>,
    /// Background writer task (kept alive as long as the logger is alive)
    _task: Arc<JoinHandle<()>>,
}

impl AuditLogger {
    /// Create an audit logger writing to the path in `logging_config`, or stderr if None.
    pub fn new(logging_config: &LoggingConfig) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEvent>();

        let path = logging_config.audit_log_path.clone();
        let enabled = logging_config.audit_log_enabled;

        let task = tokio::spawn(async move {
            if !enabled {
                // Drain without writing
                while rx.recv().await.is_some() {}
                return;
            }

            while let Some(event) = rx.recv().await {
                let record = AuditRecord {
                    timestamp: Utc::now().to_rfc3339(),
                    level: event.level(),
                    category: event.category(),
                    event,
                };

                match serde_json::to_string(&record) {
                    Ok(mut line) => {
                        line.push('\n');
                        if let Some(ref p) = path {
                            match OpenOptions::new().create(true).append(true).open(p) {
                                Ok(mut f) => {
                                    if let Err(e) = f.write_all(line.as_bytes()) {
                                        error!("audit_logger: write error: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("audit_logger: open {:?} error: {}", p, e);
                                    eprint!("{}", line);
                                }
                            }
                        } else {
                            eprint!("{}", line);
                        }
                    }
                    Err(e) => warn!("audit_logger: serialisation error: {}", e),
                }
            }
        });

        Self {
            tx,
            _task: Arc::new(task),
        }
    }

    /// Submit an audit event (non-blocking).
    pub fn log(&self, event: AuditEvent) {
        // If receiver is gone (shutdown), silently drop
        let _ = self.tx.send(event);
    }

    /// Convenience: log an admin action.
    pub fn log_admin_action(
        &self,
        ip: IpAddr,
        action: impl Into<String>,
        success: bool,
        detail: Option<String>,
    ) {
        self.log(AuditEvent::AdminAction {
            ip: ip.to_string(),
            action: action.into(),
            success,
            detail,
        });
    }

    /// Convenience: log a WAF block.
    pub fn log_waf_block(&self, ip: IpAddr, rule: impl Into<String>, path: impl Into<String>) {
        self.log(AuditEvent::WafBlock {
            ip: ip.to_string(),
            rule: rule.into(),
            path: path.into(),
        });
    }

    /// Convenience: log a WAF detect.
    pub fn log_waf_detect(&self, ip: IpAddr, rule: impl Into<String>, path: impl Into<String>) {
        self.log(AuditEvent::WafDetect {
            ip: ip.to_string(),
            rule: rule.into(),
            path: path.into(),
        });
    }
}
