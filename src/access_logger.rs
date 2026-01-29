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

/// Access log entry with request and response details
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub remote_addr: SocketAddr,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub body_size: usize,
    pub referer: Option<String>,
    pub user_agent: Option<String>,
    pub host: Option<String>,
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
    pub fn log(&self, entry: &AccessLogEntry) {
        if !self.enabled {
            return;
        }

        // Format: nginx combined log format
        // $remote_addr - - [$time_local] "$request" $status $body_bytes_sent "$referer" "$user_agent"
        let timestamp = Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        let request = format!("{} {} {}", entry.method, entry.path, entry.protocol);
        let referer = entry.referer.as_deref().unwrap_or("-");
        let user_agent = entry.user_agent.as_deref().unwrap_or("-");
        let host = entry.host.as_deref().unwrap_or("-");

        let log_line = format!(
            "{} - - [{}] \"{}\" {} {} \"{}\" \"{}\" host=\"{}\" time={}ms\n",
            entry.remote_addr.ip(),
            timestamp,
            request,
            entry.status,
            entry.body_size,
            referer,
            user_agent,
            host,
            entry.response_time_ms
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
pub fn log_access(entry: &AccessLogEntry) {
    if let Some(logger) = get_access_logger() {
        logger.log(entry);
    }
}
