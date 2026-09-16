//! Access Logger for PQCrypta Proxy
//!
//! Writes access logs in nginx-compatible combined log format:
//! $remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"

use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// The token that belongs in the request line for a given HTTP version.
///
/// Every TCP call site used to hardcode `"HTTP/1.1"`, so an h2 request was
/// logged as h1 and the log could not answer "which protocol did this client
/// use?" — the one question a mixed h1/h2/h3 edge gets asked most.
pub fn protocol_name(version: http::Version) -> &'static str {
    match version {
        http::Version::HTTP_09 => "HTTP/0.9",
        http::Version::HTTP_10 => "HTTP/1.0",
        http::Version::HTTP_11 => "HTTP/1.1",
        http::Version::HTTP_2 => "HTTP/2.0",
        http::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

/// Bytes a fully-built response will send, read from the length it declares.
///
/// For the short refusal bodies the security layers produce, `into_response()`
/// has already set `content-length`, so this is exact. Returns 0 when no length
/// is declared, which for those responses means there is no body.
pub fn declared_body_size(headers: &http::HeaderMap) -> usize {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// An access-log line held open while a streaming body is still being written.
///
/// A passthrough stream (SSE, and anything else the proxy forwards without
/// buffering) has no size at the moment the response head is built. Logging
/// there is why `$body_bytes_sent` read 0 on those requests. This owns its
/// fields so the line can be written when the body actually ends.
pub struct DeferredAccessLog {
    pub remote_addr: SocketAddr,
    pub method: String,
    pub path: String,
    pub protocol: &'static str,
    pub status: u16,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub host: Option<String>,
    pub started: std::time::Instant,
}

impl DeferredAccessLog {
    /// Write the line, now that the body has ended and its size is known.
    pub fn finish(self, body_size: usize) {
        log_access(&AccessLogEntry {
            remote_addr: self.remote_addr,
            method: &self.method,
            path: &self.path,
            protocol: self.protocol,
            status: self.status,
            body_size,
            referer: self.referer.as_deref(),
            user_agent: self.user_agent.as_deref(),
            host: self.host.as_deref(),
            response_time_ms: self
                .started
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        });
    }
}

/// Writes a [`DeferredAccessLog`] when the body it is attached to is dropped.
///
/// Drop rather than end-of-stream on purpose: a client that disconnects halfway
/// through an event stream still gets a log line, carrying the bytes it actually
/// received, which is what nginx records and what makes an aborted stream
/// visible at all.
pub struct StreamedBodyLogger {
    entry: Option<DeferredAccessLog>,
    counter: Arc<AtomicUsize>,
}

impl StreamedBodyLogger {
    pub fn new(entry: DeferredAccessLog) -> (Self, Arc<AtomicUsize>) {
        let counter = Arc::new(AtomicUsize::new(0));
        (
            Self {
                entry: Some(entry),
                counter: Arc::clone(&counter),
            },
            counter,
        )
    }
}

impl Drop for StreamedBodyLogger {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            entry.finish(self.counter.load(Ordering::Relaxed));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every TCP call site once wrote a literal "HTTP/1.1", so an h2 request was
    /// indistinguishable from an h1 one in the log.
    #[test]
    fn protocol_name_reports_the_version_it_was_given() {
        assert_eq!(protocol_name(http::Version::HTTP_11), "HTTP/1.1");
        assert_eq!(protocol_name(http::Version::HTTP_2), "HTTP/2.0");
        assert_eq!(protocol_name(http::Version::HTTP_3), "HTTP/3.0");
        assert_eq!(protocol_name(http::Version::HTTP_10), "HTTP/1.0");
    }

    #[test]
    fn declared_body_size_reads_content_length() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::CONTENT_LENGTH, "2376".parse().unwrap());
        assert_eq!(declared_body_size(&headers), 2376);
    }

    /// No declared length means no body on these refusal responses — not an
    /// unknown length, so 0 is the honest answer rather than a placeholder.
    #[test]
    fn declared_body_size_is_zero_without_a_length() {
        assert_eq!(declared_body_size(&http::HeaderMap::new()), 0);
    }

    /// A malformed content-length must not panic the logger.
    #[test]
    fn declared_body_size_ignores_a_length_it_cannot_parse() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_LENGTH,
            "not-a-number".parse().unwrap(),
        );
        assert_eq!(declared_body_size(&headers), 0);
    }
}
