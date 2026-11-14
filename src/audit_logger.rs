//! Structured audit logging for security-relevant events.
//!
//! An event is queued without waiting and written, as one JSON line, by a
//! thread of its own that holds the file open. The queue has a fixed length:
//! when events arrive faster than they are written, the newest are counted
//! instead of kept, and the count is written as an event of its own
//! (`events_dropped`), so the log says what it is missing and the proxy's
//! memory does not follow the rate of the events.
//!
//! The file is created readable by its owner and group only, and is reopened
//! when the path stops naming the file that is open, as after a rotation.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write as IoWrite};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use parking_lot::Mutex;
use serde::Serialize;
use tracing::{error, warn};

use crate::config::LoggingConfig;

/// Events waiting to be written; past this, new ones are counted, not kept.
const QUEUE: usize = 8192;

/// Events written between two flushes of the file.
const BATCH: usize = 256;

/// The longest any one text field of an event is written.
const MAX_FIELD: usize = 1024;

/// How often the writer checks that its path still names the open file.
const REOPEN_CHECK: Duration = Duration::from_secs(1);

/// One rate-limit event per address in this long: a client that is being
/// refused is refused many times a second, and the first refusal is the news.
const RATE_LIMIT_REPEAT: Duration = Duration::from_secs(10);

/// One classical-handshake event per address in this long: a client that
/// has no post-quantum group has none on its next connection either.
const CLASSICAL_REPEAT: Duration = Duration::from_mins(10);

/// Addresses whose last event of a repeated kind is remembered.
const REPEAT_ADDRESSES: usize = 4096;

/// The kinds of event written once per address in an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Repeated {
    RateLimit,
    ClassicalHandshake,
}

impl Repeated {
    fn interval(self) -> Duration {
        match self {
            Self::RateLimit => RATE_LIMIT_REPEAT,
            Self::ClassicalHandshake => CLASSICAL_REPEAT,
        }
    }
}

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
        /// The part of the request the rule matched (`header:<name>`, ...)
        location: String,
    },
    /// WAF rule triggered — detection mode (logged, not blocked)
    WafDetect {
        ip: String,
        rule: String,
        path: String,
        /// The part of the request the rule matched (`header:<name>`, ...)
        location: String,
    },
    /// Configuration reloaded
    ConfigReload {
        success: bool,
        changed_sections: Vec<String>,
    },
    /// TLS certificates reloaded
    TlsReload { success: bool },
    /// One non-browser fingerprint from many client networks at once
    FingerprintReplay {
        fingerprint: String,
        ip: String,
        networks: usize,
        blocked: bool,
    },
    /// One client network presenting a different fingerprint on most of its
    /// connections
    FingerprintDrift {
        fingerprint: String,
        ip: String,
        distinct: usize,
        connections: u32,
        drift_score: f64,
        blocked: bool,
    },
    /// Events that arrived while the queue was full and were not written
    EventsDropped { count: u64 },
}

/// Wrapper with metadata added at emission time
#[derive(Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    level: &'static str,
    category: &'static str,
    /// Set on what the startup self-test caused, acting as a TEST-NET
    /// address to measure that the WAF and the rate limits enforce
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    startup_probe: bool,
    #[serde(flatten)]
    event: &'a AuditEvent,
}

/// `text` cut to [`MAX_FIELD`] bytes, at a character boundary.
fn clip(text: &mut String) {
    if text.len() > MAX_FIELD {
        let mut end = MAX_FIELD;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
}

impl AuditEvent {
    /// The client address the event is about, where it is about one.
    fn ip(&self) -> Option<&str> {
        match self {
            Self::AdminAction { ip, .. }
            | Self::AuthFailure { ip, .. }
            | Self::IpBlocked { ip, .. }
            | Self::RateLimitHit { ip, .. }
            | Self::PqcDowngrade { ip, .. }
            | Self::WafBlock { ip, .. }
            | Self::WafDetect { ip, .. }
            | Self::FingerprintReplay { ip, .. }
            | Self::FingerprintDrift { ip, .. } => Some(ip),
            Self::ConfigReload { .. } | Self::TlsReload { .. } | Self::EventsDropped { .. } => None,
        }
    }

    fn level(&self) -> &'static str {
        match self {
            Self::AdminAction { success: false, .. }
            | Self::AuthFailure { .. }
            | Self::PqcDowngrade { .. }
            | Self::WafBlock { .. }
            | Self::FingerprintReplay { .. }
            | Self::FingerprintDrift { .. }
            | Self::IpBlocked { .. }
            | Self::ConfigReload { success: false, .. }
            | Self::TlsReload { success: false }
            | Self::EventsDropped { .. } => "WARN",
            Self::AdminAction { .. }
            | Self::WafDetect { .. }
            | Self::RateLimitHit { .. }
            | Self::ConfigReload { .. }
            | Self::TlsReload { .. } => "INFO",
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
            Self::FingerprintReplay { .. } | Self::FingerprintDrift { .. } => "fingerprint",
            Self::EventsDropped { .. } => "audit",
        }
    }

    /// The event with every text field no longer than [`MAX_FIELD`]: a
    /// request's path, or a header a rule matched, is as long as its sender
    /// made it.
    fn bounded(mut self) -> Self {
        match &mut self {
            Self::AdminAction {
                ip, action, detail, ..
            } => {
                clip(ip);
                clip(action);
                if let Some(detail) = detail {
                    clip(detail);
                }
            }
            Self::AuthFailure { ip, reason, .. } | Self::IpBlocked { ip, reason, .. } => {
                clip(ip);
                clip(reason);
            }
            Self::RateLimitHit { ip, path, .. } => {
                clip(ip);
                clip(path);
            }
            Self::PqcDowngrade {
                ip,
                reason,
                classical_kem,
            } => {
                clip(ip);
                clip(reason);
                clip(classical_kem);
            }
            Self::WafBlock {
                ip,
                rule,
                path,
                location,
            }
            | Self::WafDetect {
                ip,
                rule,
                path,
                location,
            } => {
                clip(ip);
                clip(rule);
                clip(path);
                clip(location);
            }
            Self::ConfigReload {
                changed_sections, ..
            } => changed_sections.iter_mut().for_each(clip),
            Self::FingerprintReplay {
                fingerprint, ip, ..
            }
            | Self::FingerprintDrift {
                fingerprint, ip, ..
            } => {
                clip(fingerprint);
                clip(ip);
            }
            Self::TlsReload { .. } | Self::EventsDropped { .. } => {}
        }
        self
    }
}

/// The file the events are written to, or stderr without one.
struct Sink {
    path: Option<PathBuf>,
    file: Option<BufWriter<File>>,
    /// Which file is open, as the file system names it
    identity: Option<(u64, u64)>,
    /// When the path was last compared with the open file
    checked: Instant,
    /// Set while the file cannot be opened, so that is reported once
    failing: bool,
}

/// The device and inode of the file `metadata` describes, where the platform
/// has them and the file could be asked.
fn identity(metadata: std::io::Result<std::fs::Metadata>) -> Option<(u64, u64)> {
    let metadata = metadata.ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.dev(), metadata.ino()))
    }
    #[cfg(not(unix))]
    {
        drop(metadata);
        None
    }
}

impl Sink {
    fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            file: None,
            identity: None,
            checked: Instant::now(),
            failing: false,
        }
    }

    /// The open file, reopened when the path has come to name another (a
    /// rotation renamed or removed the one that was open).
    fn file(&mut self) -> Option<&mut BufWriter<File>> {
        let path = self.path.as_deref()?;
        if self.file.is_some() && self.checked.elapsed() >= REOPEN_CHECK {
            self.checked = Instant::now();
            let named = identity(std::fs::metadata(path));
            if named.is_none() || named != self.identity {
                if let Some(mut open) = self.file.take() {
                    let _ = open.flush();
                }
            }
        }
        if self.file.is_none() {
            match crate::log_file::open_append(path) {
                Ok(file) => {
                    self.identity = identity(file.metadata());
                    self.checked = Instant::now();
                    self.failing = false;
                    self.file = Some(BufWriter::new(file));
                }
                Err(e) => {
                    if !self.failing {
                        error!("audit log {path:?} cannot be opened ({e}); events go to stderr");
                    }
                    self.failing = true;
                }
            }
        }
        self.file.as_mut()
    }

    fn write(&mut self, event: &AuditEvent) {
        let record = AuditRecord {
            // As the proxy's own log writes it (`…T23:03:04.302806Z`), so the
            // two streams sort and join on one format; this was `+00:00` with
            // nanoseconds beside it
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            level: event.level(),
            category: event.category(),
            startup_probe: event
                .ip()
                .is_some_and(crate::startup_verify::is_probe_source),
            event,
        };
        let mut line = match serde_json::to_string(&record) {
            Ok(line) => line,
            Err(e) => {
                warn!("audit event not serialised: {e}");
                return;
            }
        };
        line.push('\n');
        match self.file() {
            Some(file) => {
                if let Err(e) = file.write_all(line.as_bytes()) {
                    error!("audit log write failed: {e}");
                    self.file = None;
                    eprint!("{line}");
                }
            }
            None => eprint!("{line}"),
        }
    }

    fn flush(&mut self) {
        if let Some(file) = &mut self.file {
            if let Err(e) = file.flush() {
                error!("audit log flush failed: {e}");
                self.file = None;
            }
        }
    }
}

/// Write every queued event, a batch between flushes, until the last sender
/// is gone; and after each batch, how many events the queue could not hold.
fn write_events(events: &Receiver<AuditEvent>, path: Option<PathBuf>, dropped: &AtomicU64) {
    let mut sink = Sink::new(path);
    while let Ok(first) = events.recv() {
        sink.write(&first);
        for event in events.try_iter().take(BATCH - 1) {
            sink.write(&event);
        }
        let count = dropped.swap(0, Ordering::Relaxed);
        if count > 0 {
            sink.write(&AuditEvent::EventsDropped { count });
        }
        sink.flush();
    }
}

/// The audit log: `log` queues an event, and one thread writes them.
pub struct AuditLogger {
    /// `None` when the audit log is disabled
    events: Option<SyncSender<AuditEvent>>,
    /// Events the queue had no room for, since the writer last reported them
    dropped: Arc<AtomicU64>,
    /// When each address's last event of a repeated kind was queued
    repeated: Mutex<HashMap<(Repeated, IpAddr), Instant>>,
}

impl AuditLogger {
    /// Create an audit logger writing to the path in `logging_config`, or stderr if None.
    pub fn new(logging_config: &LoggingConfig) -> Self {
        let dropped = Arc::new(AtomicU64::new(0));
        let events = logging_config.audit_log_enabled.then(|| {
            let (tx, rx) = sync_channel::<AuditEvent>(QUEUE);
            let path = logging_config.audit_log_path.clone();
            let counted = Arc::clone(&dropped);
            let writer = std::thread::Builder::new()
                .name("audit-log".into())
                .spawn(move || write_events(&rx, path, &counted));
            if let Err(e) = writer {
                error!("audit log writer not started ({e}): no audit events are written");
            }
            tx
        });
        Self {
            events,
            dropped,
            repeated: Mutex::new(HashMap::new()),
        }
    }

    /// Queue an audit event. Never waits: with the queue full the event is
    /// counted, and the count is written when the writer catches up.
    pub fn log(&self, event: AuditEvent) {
        let Some(events) = &self.events else {
            return;
        };
        match events.try_send(event.bounded()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer is gone: the process is shutting down
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Whether an event of `kind` about `ip` is news: none was queued for
    /// that address within the kind's interval.
    fn due(&self, kind: Repeated, ip: IpAddr) -> bool {
        let now = Instant::now();
        let recent = |kind: Repeated, last: Instant| now.duration_since(last) < kind.interval();
        let mut seen = self.repeated.lock();
        if seen
            .get(&(kind, ip))
            .is_some_and(|last| recent(kind, *last))
        {
            return false;
        }
        if seen.len() >= REPEAT_ADDRESSES {
            seen.retain(|(kind, _), last| recent(*kind, *last));
            if seen.len() >= REPEAT_ADDRESSES {
                seen.clear();
            }
        }
        seen.insert((kind, ip), now);
        true
    }

    /// A request refused by a rate limit: written once per address in
    /// [`RATE_LIMIT_REPEAT`].
    pub fn log_rate_limit(&self, ip: IpAddr, path: &str, limit: u32) {
        if self.events.is_some() && self.due(Repeated::RateLimit, ip) {
            self.log(AuditEvent::RateLimitHit {
                ip: ip.to_string(),
                path: path.to_string(),
                limit,
            });
        }
    }

    /// A handshake that ended on a classical group where the server prefers
    /// a post-quantum one (see pqc_policy.rs): written once per address in
    /// [`CLASSICAL_REPEAT`].
    pub fn log_classical_handshake(&self, ip: IpAddr, group: &str, blocked: bool) {
        if self.events.is_some() && self.due(Repeated::ClassicalHandshake, ip) {
            self.log(AuditEvent::PqcDowngrade {
                ip: ip.to_string(),
                reason: if blocked {
                    "the client offered no post-quantum group; its requests are answered 421"
                } else {
                    "the client offered no post-quantum group"
                }
                .to_string(),
                classical_kem: group.to_string(),
            });
        }
    }

    /// Convenience: log a WAF block.
    pub fn log_waf_block(
        &self,
        ip: IpAddr,
        rule: impl Into<String>,
        path: impl Into<String>,
        location: impl Into<String>,
    ) {
        self.log(AuditEvent::WafBlock {
            ip: ip.to_string(),
            rule: rule.into(),
            path: path.into(),
            location: location.into(),
        });
    }

    /// Convenience: log a WAF detect.
    pub fn log_waf_detect(
        &self,
        ip: IpAddr,
        rule: impl Into<String>,
        path: impl Into<String>,
        location: impl Into<String>,
    ) {
        self.log(AuditEvent::WafDetect {
            ip: ip.to_string(),
            rule: rule.into(),
            path: path.into(),
            location: location.into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn waf_block(path: &str) -> AuditEvent {
        AuditEvent::WafBlock {
            ip: "203.0.113.7".into(),
            rule: "sqli".into(),
            path: path.into(),
            location: "query".into(),
        }
    }

    /// A logger whose queue holds `capacity` events and is read by the test.
    fn queued(capacity: usize) -> (AuditLogger, Receiver<AuditEvent>) {
        let (tx, rx) = sync_channel(capacity);
        let logger = AuditLogger {
            events: Some(tx),
            dropped: Arc::new(AtomicU64::new(0)),
            repeated: Mutex::new(HashMap::new()),
        };
        (logger, rx)
    }

    fn lines(path: &Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn events_are_json_lines_in_a_file_others_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let (tx, rx) = sync_channel(8);
        tx.send(waf_block("/a\nb")).unwrap();
        tx.send(AuditEvent::TlsReload { success: false }).unwrap();
        tx.send(AuditEvent::IpBlocked {
            ip: "192.0.2.2".into(),
            reason: "RateLimitExceeded".into(),
            duration_secs: Some(600),
        })
        .unwrap();
        drop(tx);
        write_events(&rx, Some(path.clone()), &AtomicU64::new(0));

        let written = lines(&path);
        assert_eq!(
            written.len(),
            3,
            "one line an event, whatever a field holds"
        );
        // What the startup self-test caused says so; nothing else carries it
        assert_eq!(written[2]["startup_probe"], true);
        assert!(written[0].get("startup_probe").is_none());
        assert_eq!(written[0]["event"], "waf_block");
        assert_eq!(written[0]["category"], "waf");
        assert_eq!(written[0]["path"], "/a\nb");
        assert_eq!(written[1]["event"], "tls_reload");
        assert_eq!(written[1]["level"], "WARN", "a reload that failed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o007, 0, "mode {mode:o}");
        }
    }

    #[test]
    fn a_full_queue_counts_what_it_does_not_keep_and_the_log_says_so() {
        let (logger, rx) = queued(1);
        for _ in 0..3 {
            logger.log(waf_block("/"));
        }
        assert_eq!(logger.dropped.load(Ordering::Relaxed), 2);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let dropped = Arc::clone(&logger.dropped);
        drop(logger);
        write_events(&rx, Some(path.clone()), &dropped);
        let written = lines(&path);
        assert_eq!(written.len(), 2);
        assert_eq!(written[1]["event"], "events_dropped");
        assert_eq!(written[1]["count"], 2);
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_rotated_file_is_left_and_the_path_written_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        let mut sink = Sink::new(Some(path.clone()));
        sink.write(&waf_block("/before"));
        sink.flush();
        let rotated = dir.path().join("audit.json.1");
        std::fs::rename(&path, &rotated).unwrap();

        sink.checked = Instant::now()
            .checked_sub(REOPEN_CHECK)
            .expect("a clock a second old");
        sink.write(&waf_block("/after"));
        sink.flush();
        assert_eq!(lines(&rotated).len(), 1);
        assert_eq!(lines(&path)[0]["path"], "/after");
    }

    #[test]
    fn a_field_is_written_to_its_limit_and_no_further() {
        let long = "é".repeat(MAX_FIELD);
        let AuditEvent::WafBlock { path, .. } = waf_block(&long).bounded() else {
            unreachable!()
        };
        assert!(path.len() <= MAX_FIELD);
        assert!(long.starts_with(&path), "cut between characters");
        assert_eq!(path.len(), MAX_FIELD - MAX_FIELD % 2);
    }

    #[test]
    fn a_refused_address_is_one_rate_limit_event_at_a_time() {
        let (logger, rx) = queued(16);
        let first: IpAddr = "203.0.113.7".parse().unwrap();
        let second: IpAddr = "2001:db8::7".parse().unwrap();
        for _ in 0..5 {
            logger.log_rate_limit(first, "/api", 10);
        }
        logger.log_rate_limit(second, "/api", 10);
        assert_eq!(rx.try_iter().count(), 2);

        // Once the interval has passed, the address is news again
        logger.repeated.lock().insert(
            (Repeated::RateLimit, first),
            Instant::now()
                .checked_sub(RATE_LIMIT_REPEAT)
                .expect("a clock ten seconds old"),
        );
        logger.log_rate_limit(first, "/api", 10);
        assert_eq!(rx.try_iter().count(), 1);

        // A classical handshake from the same address is another kind of news
        logger.log_classical_handshake(first, "X25519", false);
        logger.log_classical_handshake(first, "X25519", true);
        let written: Vec<AuditEvent> = rx.try_iter().collect();
        assert_eq!(written.len(), 1);
        assert!(matches!(
            &written[0],
            AuditEvent::PqcDowngrade { classical_kem, .. } if classical_kem == "X25519"
        ));
    }

    #[test]
    fn a_disabled_log_takes_no_events() {
        let logger = AuditLogger::new(&LoggingConfig {
            audit_log_enabled: false,
            ..LoggingConfig::default()
        });
        assert!(logger.events.is_none());
        logger.log(waf_block("/"));
        logger.log_rate_limit("203.0.113.7".parse().unwrap(), "/", 1);
        assert_eq!(logger.dropped.load(Ordering::Relaxed), 0);
    }
}
