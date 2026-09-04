//! Access Logger for PQCrypta Proxy
//!
//! Writes access logs in nginx-compatible combined log format:
//! $remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, error, info};

use crate::otel;

/// Sanitize a user-controlled log field by stripping newlines and control characters.
///
/// Prevents log injection attacks where `\n` in a path or header could inject
/// fake log entries into structured log files or SIEM systems.
pub fn sanitize_log_field(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\n' | '\r' | '\x00'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f'))
        .take(2048)
        .collect()
}

/// Access log entry with request and response details
#[derive(Debug, Clone)]
/// One access-log record, borrowing every string it reports.
///
/// It used to own them, which meant each of the eleven call sites allocated a
/// method, a path, a host, a referer, a user-agent and — from a string literal —
/// a protocol, on every request. The logger only ever reads them as `&str`, and
/// `log_access` does nothing at all when access logging is disabled, so on a
/// proxy with the access log off that was six allocations per request thrown
/// away without being looked at.
pub struct AccessLogEntry<'a> {
    pub remote_addr: SocketAddr,
    pub method: &'a str,
    pub path: &'a str,
    pub protocol: &'a str,
    pub status: u16,
    pub body_size: usize,
    pub referer: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub host: Option<&'a str>,
    pub response_time_ms: u64,
}

/// Access logger that writes to a file in nginx-compatible format
pub struct AccessLogger {
    file: Arc<Mutex<Option<File>>>,
    path: Option<PathBuf>,
    enabled: bool,
}

impl AccessLogger {
    /// Create a new access logger
    pub fn new(enabled: bool, path: Option<PathBuf>) -> Self {
        let file = if enabled {
            if let Some(ref p) = path {
                match OpenOptions::new().create(true).append(true).open(p) {
                    Ok(f) => {
                        info!("Access log enabled: {:?}", p);
                        Some(f)
                    }
                    Err(e) => {
                        error!("Failed to open access log file {:?}: {}", p, e);
                        None
                    }
                }
            } else {
                debug!("Access logging enabled but no file path specified");
                None
            }
        } else {
            debug!("Access logging disabled");
            None
        };

        Self {
            file: Arc::new(Mutex::new(file)),
            path,
            enabled,
        }
    }

    /// Log an access entry
    pub fn log(&self, entry: &AccessLogEntry<'_>) {
        if !self.enabled {
            return;
        }

        // Format: nginx combined log format
        // $remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$referer" "$user_agent"
        let timestamp = Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        // M-1: Sanitize all user-controlled fields to prevent log injection
        let safe_path = sanitize_log_field(entry.path);
        let safe_method = sanitize_log_field(entry.method);
        let safe_protocol = sanitize_log_field(entry.protocol);
        let request = format!("{} {} {}", safe_method, safe_path, safe_protocol);
        let referer = entry
            .referer
            .map(sanitize_log_field)
            .unwrap_or_else(|| "-".to_string());
        let user_agent = entry
            .user_agent
            .map(sanitize_log_field)
            .unwrap_or_else(|| "-".to_string());
        let host = entry
            .host
            .map(sanitize_log_field)
            .unwrap_or_else(|| "-".to_string());

        // Capture the trace ID from the active span so log entries can be
        // correlated with distributed traces in Jaeger / Tempo / etc.
        let trace_id = otel::current_trace_id();
        let trace_field = if trace_id.is_empty() {
            String::new()
        } else {
            format!(" trace_id={}", trace_id)
        };

        let log_line = format!(
            "{} - - [{}] \"{}\" {} {} \"{}\" \"{}\" host=\"{}\" time={}ms{}\n",
            entry.remote_addr.ip(),
            timestamp,
            request,
            entry.status,
            entry.body_size,
            referer,
            user_agent,
            host,
            entry.response_time_ms,
            trace_field
        );

        // Write to file if available
        if let Ok(mut guard) = self.file.lock() {
            if let Some(ref mut file) = *guard {
                if let Err(e) = file.write_all(log_line.as_bytes()) {
                    error!("Failed to write access log: {}", e);
                }
            }
        }

        // Also log at debug level for journald capture
        debug!(
            target: "access_log",
            remote_addr = %entry.remote_addr.ip(),
            method = %entry.method,
            path = %entry.path,
            status = entry.status,
            body_size = entry.body_size,
            host = ?entry.host,
            response_time_ms = entry.response_time_ms,
            "access"
        );
    }

    /// Re-open the log file (for log rotation)
    pub fn reopen(&self) {
        if !self.enabled {
            return;
        }

        if let Some(ref p) = self.path {
            if let Ok(mut guard) = self.file.lock() {
                match OpenOptions::new().create(true).append(true).open(p) {
                    Ok(f) => {
                        *guard = Some(f);
                        info!("Access log re-opened: {:?}", p);
                    }
                    Err(e) => {
                        error!("Failed to re-open access log file {:?}: {}", p, e);
                    }
                }
            }
        }
    }
}

impl Clone for AccessLogger {
    fn clone(&self) -> Self {
        Self {
            file: Arc::clone(&self.file),
            path: self.path.clone(),
            enabled: self.enabled,
        }
    }
}

/// Global access logger instance using OnceLock for thread-safe initialization
static ACCESS_LOGGER: OnceLock<AccessLogger> = OnceLock::new();

/// Initialize the global access logger
pub fn init_access_logger(enabled: bool, path: Option<PathBuf>) {
    let _ = ACCESS_LOGGER.set(AccessLogger::new(enabled, path));
}

/// Get the global access logger
pub fn get_access_logger() -> Option<&'static AccessLogger> {
    ACCESS_LOGGER.get()
}

/// Log an access entry using the global logger
pub fn log_access(entry: &AccessLogEntry<'_>) {
    if let Some(logger) = get_access_logger() {
        logger.log(entry);
    }
}
