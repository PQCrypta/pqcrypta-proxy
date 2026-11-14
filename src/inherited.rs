//! Listening sockets the service manager opened for this process: systemd
//! socket activation (`sd_listen_fds(3)`, `systemd.socket(5)`).
//!
//! A restart closed every listener for as long as the old process drained and
//! the new one started, and a connection that arrived meanwhile was refused.
//! With the sockets held by a `.socket` unit they outlive the process: the
//! kernel goes on completing TCP handshakes into the listen backlog and
//! queueing datagrams, and the next process takes the same sockets and serves
//! what waited. Each listener asks here for a socket bound to its address
//! before it binds one itself, so the proxy runs the same with or without a
//! socket unit, and `pqcrypta-proxy --socket-unit FILE` writes the unit from the
//! configuration (`ProxyConfig::listen_sockets`), so the two cannot disagree.
//!
//! The protocol: `LISTEN_PID` is this process's ID and `LISTEN_FDS` the number
//! of descriptors passed, from 3 up; `LISTEN_FDNAMES` names them. The
//! environment is only read: setting a variable while other threads may read
//! the environment is undefined behaviour, and the PID check already keeps a
//! child from taking sockets meant for this process.
#![allow(unsafe_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{LazyLock, Mutex};

use socket2::Socket;
use tracing::{info, warn};

/// The kind of socket a listener asks for
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Tcp,
    Udp,
}

/// The sockets passed and not yet taken.
///
/// By kind and bound address, with the name the unit gave each.
static PASSED: LazyLock<Mutex<HashMap<(Kind, SocketAddr), (Socket, String)>>> =
    LazyLock::new(|| {
        Mutex::new(collect(
            std::env::var("LISTEN_PID").ok().as_deref(),
            std::env::var("LISTEN_FDS").ok().as_deref(),
            std::env::var("LISTEN_FDNAMES").ok().as_deref(),
        ))
    });

/// How many descriptors `LISTEN_PID` and `LISTEN_FDS` pass to this process.
///
/// None when they are absent, malformed or meant for another process.
#[cfg(any(unix, test))]
fn passed_count(pid: Option<&str>, fds: Option<&str>, own: u32) -> usize {
    match (
        pid.and_then(|p| p.parse::<u32>().ok()),
        fds.and_then(|n| n.parse::<usize>().ok()),
    ) {
        (Some(pid), Some(n)) if pid == own => n,
        _ => 0,
    }
}

/// Without the descriptor protocol (not Unix) nothing is passed
#[cfg(not(unix))]
fn collect(
    _pid: Option<&str>,
    _fds: Option<&str>,
    _names: Option<&str>,
) -> HashMap<(Kind, SocketAddr), (Socket, String)> {
    HashMap::new()
}

#[cfg(unix)]
fn collect(
    pid: Option<&str>,
    fds: Option<&str>,
    names: Option<&str>,
) -> HashMap<(Kind, SocketAddr), (Socket, String)> {
    use socket2::Type;
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    /// The first descriptor systemd passes (`SD_LISTEN_FDS_START`)
    const FIRST: RawFd = 3;

    let count = passed_count(pid, fds, std::process::id());
    let names: Vec<&str> = names.map(|n| n.split(':').collect()).unwrap_or_default();
    let mut passed = HashMap::new();
    for i in 0..count {
        let Ok(offset) = RawFd::try_from(i) else {
            break;
        };
        let fd = FIRST + offset;
        // SAFETY: systemd hands this process the descriptors FIRST to
        // FIRST + LISTEN_FDS - 1, and nothing else in it claims them: this is
        // the one place they are taken, once (LazyLock), and LISTEN_PID was
        // checked to be this process.
        let socket = Socket::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let name = names.get(i).copied().unwrap_or("").to_string();
        // Not inherited by what this process runs (mtr, for one)
        if let Err(e) = socket.set_cloexec(true) {
            warn!(
                "Passed socket {} ({}): close-on-exec not set: {}",
                fd, name, e
            );
        }
        let kind = match socket.r#type() {
            Ok(t) if t == Type::STREAM => Kind::Tcp,
            Ok(t) if t == Type::DGRAM => Kind::Udp,
            other => {
                warn!(
                    "Passed socket {} ({}) is not a TCP or UDP socket ({:?}): not used",
                    fd, name, other
                );
                continue;
            }
        };
        let Some(addr) = socket.local_addr().ok().and_then(|a| a.as_socket()) else {
            warn!(
                "Passed socket {} ({}) has no IP address: not used",
                fd, name
            );
            continue;
        };
        // SO_ACCEPTCONN, where socket2 can read it
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
        if kind == Kind::Tcp && !socket.is_listener().unwrap_or(false) {
            warn!(
                "Passed TCP socket {} ({}) on {} is not listening: not used",
                fd, name, addr
            );
            continue;
        }
        passed.insert((kind, addr), (socket, name));
    }
    if !passed.is_empty() {
        info!(
            "Socket activation: {} socket(s) passed by the service manager",
            passed.len()
        );
    }
    passed
}

/// Take the passed sockets now, at startup; the number taken.
///
/// Before any listener asks, so they are logged with the rest of startup and
/// what the environment said is read once.
pub fn init() -> usize {
    PASSED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}

/// The passed socket of `kind` bound to `addr`, if there is one.
///
/// Each is handed out once, non-blocking, as the runtime needs.
fn take(kind: Kind, addr: SocketAddr) -> Option<Socket> {
    let (socket, name) = PASSED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&(kind, addr))?;
    if let Err(e) = socket.set_nonblocking(true) {
        warn!(
            "Passed socket {} ({:?}, {}) not made non-blocking: {}",
            addr, kind, name, e
        );
        return None;
    }
    info!(
        "Listening on {} ({:?}) through the socket the service manager holds{}",
        addr,
        kind,
        if name.is_empty() {
            String::new()
        } else {
            format!(" ({name})")
        }
    );
    Some(socket)
}

/// A TCP listener on `addr`: the one the service manager passed, or one bound
/// here.
pub async fn tcp_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    match take(Kind::Tcp, addr) {
        Some(socket) => tokio::net::TcpListener::from_std(socket.into()),
        None => tokio::net::TcpListener::bind(addr).await,
    }
}

/// [`tcp_listener`] as a standard listener (non-blocking), for servers that
/// take one (`axum_server::from_tcp`).
pub fn std_tcp_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    match take(Kind::Tcp, addr) {
        Some(socket) => Ok(socket.into()),
        None => {
            let listener = std::net::TcpListener::bind(addr)?;
            listener.set_nonblocking(true)?;
            Ok(listener)
        }
    }
}

/// A UDP socket on `addr`: the one the service manager passed, or one bound here.
///
/// A passed one is non-blocking; one bound here is blocking, as
/// `std::net::UdpSocket::bind` leaves it. The QUIC endpoints set what they need.
pub fn udp_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    match take(Kind::Udp, addr) {
        Some(socket) => Ok(socket.into()),
        None => std::net::UdpSocket::bind(addr),
    }
}

/// Warn of each passed socket no listener took.
///
/// Each is a port the kernel still accepts connections on for nobody, since
/// the service manager holds it open: said loudly, so a unit and a
/// configuration that disagree are seen at the start.
pub fn report_unclaimed() {
    let passed = PASSED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for ((kind, addr), (_, name)) in passed.iter() {
        warn!(
            "Socket activation: the service manager passed {} ({:?}{}), which no listener in the \
             configuration uses: regenerate the socket unit (pqcrypta-proxy --socket-unit)",
            addr,
            kind,
            if name.is_empty() {
                String::new()
            } else {
                format!(", {name}")
            }
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_descriptors_meant_for_this_process_are_taken() {
        assert_eq!(passed_count(Some("42"), Some("3"), 42), 3);
        assert_eq!(
            passed_count(Some("41"), Some("3"), 42),
            0,
            "another process's"
        );
        assert_eq!(passed_count(None, Some("3"), 42), 0);
        assert_eq!(passed_count(Some("42"), None, 42), 0);
        assert_eq!(passed_count(Some("42"), Some("x"), 42), 0);
    }

    /// Without socket activation every listener binds its own socket
    #[tokio::test]
    async fn without_a_service_manager_listeners_bind_their_own() {
        let tcp = tcp_listener("127.0.0.1:0".parse().unwrap()).await.unwrap();
        assert!(tcp.local_addr().unwrap().port() > 0);
        let udp = udp_socket("127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(udp.local_addr().unwrap().port() > 0);
    }
}
