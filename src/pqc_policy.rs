//! What a classical key exchange means to this server (`pqc.downgrade_action`).
//!
//! With `[pqc]` enabled every listener prefers a post-quantum group whatever
//! order the client lists its own in, so a handshake that ends on a classical
//! group is one whose client offered nothing else. What the server does with
//! such a connection is the operator's choice:
//!
//! - `allow`: it is served and nothing is recorded.
//! - `log` (the default): it is served, and recorded in the audit log.
//! - `block`: every request on it is answered 421 (Misdirected Request,
//!   RFC 9110 section 15.5.20), and it is recorded.
//!
//! `pqc.log_downgrades = false` turns the record off and leaves the action.
//! The policy is the process's: every listener asks it here, and a
//! configuration reload moves it for the connections that follow.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use tracing::debug;

use crate::audit_logger::AuditLogger;
use crate::config::PqcConfig;

/// What is done with a connection whose key exchange is classical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassicalAction {
    Allow = 0,
    Log = 1,
    Block = 2,
}

impl ClassicalAction {
    /// `pqc.downgrade_action` as written: `allow`, `log` or `block`.
    pub fn parse(action: &str) -> Option<Self> {
        match action.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "log" => Some(Self::Log),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    /// The action in force for `pqc`: none where post-quantum key exchange
    /// is off, since every handshake is classical there by configuration.
    pub fn of(pqc: &PqcConfig) -> Self {
        if pqc.enabled {
            Self::parse(&pqc.downgrade_action).unwrap_or(Self::Log)
        } else {
            Self::Allow
        }
    }
}

static ACTION: AtomicU8 = AtomicU8::new(ClassicalAction::Allow as u8);
static RECORD: AtomicBool = AtomicBool::new(false);
static AUDIT: OnceLock<Arc<AuditLogger>> = OnceLock::new();

/// Apply `[pqc]`, at startup and on every reload.
pub fn configure(pqc: &PqcConfig) {
    let action = ClassicalAction::of(pqc);
    ACTION.store(action as u8, Ordering::Relaxed);
    RECORD.store(
        action != ClassicalAction::Allow && pqc.log_downgrades,
        Ordering::Relaxed,
    );
}

/// Record classical handshakes in the audit log.
pub fn set_audit_logger(logger: Arc<AuditLogger>) {
    let _ = AUDIT.set(logger);
}

fn action() -> ClassicalAction {
    match ACTION.load(Ordering::Relaxed) {
        1 => ClassicalAction::Log,
        2 => ClassicalAction::Block,
        _ => ClassicalAction::Allow,
    }
}

/// A TLS handshake has completed with `group`, from `client`: recorded when
/// the group is classical and the policy says to.
pub fn handshake_completed(client: IpAddr, group: Option<&str>, post_quantum: bool) {
    if post_quantum || !RECORD.load(Ordering::Relaxed) {
        return;
    }
    let group = group.unwrap_or("unknown");
    let blocked = action() == ClassicalAction::Block;
    debug!(
        "classical key exchange ({group}) from {client}{}",
        if blocked {
            ": its requests are answered 421"
        } else {
            ""
        }
    );
    if let Some(audit) = AUDIT.get() {
        audit.log_classical_handshake(client, group, blocked);
    }
}

/// Whether a request on a connection is answered 421 for its key exchange:
/// `post_quantum` is what the connection's handshake negotiated.
pub fn refuses(post_quantum: bool) -> bool {
    !post_quantum && action() == ClassicalAction::Block
}

/// The body of the 421 a refused request gets.
pub const REFUSAL: &str = "This server requires a post-quantum key exchange";

/// Held by a test that moves the process's policy, so no other reads it
/// mid-change.
#[cfg(test)]
pub(crate) static TEST_POLICY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn pqc(enabled: bool, action: &str) -> PqcConfig {
        PqcConfig {
            enabled,
            downgrade_action: action.to_string(),
            ..PqcConfig::default()
        }
    }

    #[test]
    fn the_action_is_the_one_configured_where_post_quantum_is_on() {
        assert_eq!(
            ClassicalAction::of(&pqc(true, "block")),
            ClassicalAction::Block
        );
        assert_eq!(
            ClassicalAction::of(&pqc(true, " Log ")),
            ClassicalAction::Log
        );
        assert_eq!(
            ClassicalAction::of(&pqc(true, "allow")),
            ClassicalAction::Allow
        );
        // With post-quantum off every handshake is classical by configuration
        assert_eq!(
            ClassicalAction::of(&pqc(false, "block")),
            ClassicalAction::Allow
        );
        assert_eq!(ClassicalAction::parse("blok"), None);
    }

    #[test]
    fn only_block_refuses_and_only_a_classical_connection() {
        let _policy = TEST_POLICY.blocking_lock();
        configure(&pqc(true, "block"));
        assert!(refuses(false));
        assert!(!refuses(true));
        configure(&pqc(true, "log"));
        assert!(!refuses(false));
        configure(&pqc(false, "block"));
        assert!(!refuses(false));
        configure(&PqcConfig::default());
    }
}
