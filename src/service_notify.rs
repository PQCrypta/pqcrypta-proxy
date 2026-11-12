//! The service manager's notification protocol (`sd_notify(3)`).
//!
//! The proxy says when it is serving (`READY=1`, after its listeners are up and
//! have been probed), when it reloads (`RELOADING=1` with the time, then
//! `READY=1` again, so `systemctl reload` returns when the reload is done and
//! not when the signal was sent), when it is stopping (`STOPPING=1`), and that
//! its runtime is still running tasks (`WATCHDOG=1`, every half of the
//! interval the manager asked for, so a proxy whose runtime has hung is
//! restarted rather than left holding its ports). With a unit of
//! `Type=notify-reload` and `WatchdogSec=`, the manager knows each of those.
//!
//! Without `NOTIFY_SOCKET` in the environment (not started by systemd, or by
//! a unit that does not ask) every call does nothing. The environment is only
//! read here, never changed.

use std::time::Duration;

/// Send one notification. False when there is no manager to tell, or it
/// could not be told.
fn send(message: &str) -> bool {
    std::env::var_os("NOTIFY_SOCKET").is_some_and(|socket| send_to(&socket, message))
}

/// Send `message` to the manager's socket `socket_path`: a file system path,
/// or `@name` in the abstract namespace.
#[cfg(unix)]
fn send_to(socket_path: &std::ffi::OsStr, message: &str) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::UnixDatagram;

    let Ok(socket) = UnixDatagram::unbound() else {
        return false;
    };
    let bytes = socket_path.as_bytes();
    // `@name` is a socket in the abstract namespace (Linux)
    if let Some(name) = bytes.strip_prefix(b"@") {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            #[cfg(target_os = "android")]
            use std::os::android::net::SocketAddrExt as _;
            #[cfg(target_os = "linux")]
            use std::os::linux::net::SocketAddrExt as _;
            return std::os::unix::net::SocketAddr::from_abstract_name(name)
                .and_then(|address| socket.send_to_addr(message.as_bytes(), &address))
                .is_ok();
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            let _ = name;
            return false;
        }
    }
    socket
        .send_to(message.as_bytes(), std::path::Path::new(&socket_path))
        .is_ok()
}

#[cfg(not(unix))]
fn send_to(_socket_path: &std::ffi::OsStr, _message: &str) -> bool {
    false
}

/// The proxy is serving; `status` is what `systemctl status` shows.
pub fn ready(status: &str) {
    send(&format!("READY=1\nSTATUS={}", one_line(status)));
}

/// A reload has begun. The manager compares the time with when it sent the
/// reload signal, so the reload it waits for is this one.
pub fn reloading() {
    match monotonic_usec() {
        Some(usec) => send(&format!(
            "RELOADING=1\nMONOTONIC_USEC={usec}\nSTATUS=Reloading the configuration"
        )),
        None => send("RELOADING=1\nSTATUS=Reloading the configuration"),
    };
}

/// The proxy is shutting down.
pub fn stopping() {
    send("STOPPING=1\nSTATUS=Draining connections");
}

/// `CLOCK_MONOTONIC` in microseconds, the clock the manager reads.
#[cfg(unix)]
fn monotonic_usec() -> Option<u64> {
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC).ok()?;
    let secs = u64::try_from(now.tv_sec()).ok()?;
    let nanos = u64::try_from(now.tv_nsec()).ok()?;
    Some(secs * 1_000_000 + nanos / 1_000)
}

#[cfg(not(unix))]
fn monotonic_usec() -> Option<u64> {
    None
}

/// The watchdog interval the manager asked for (`WATCHDOG_USEC`), if it
/// asked this process (`WATCHDOG_PID`, when set, names the process meant).
fn watchdog_interval(usec: Option<&str>, pid: Option<&str>) -> Option<Duration> {
    let usec: u64 = usec?.parse().ok().filter(|u| *u > 0)?;
    if let Some(pid) = pid {
        if pid.parse::<u32>().ok() != Some(std::process::id()) {
            return None;
        }
    }
    Some(Duration::from_micros(usec))
}

/// Ping the watchdog from the runtime, at half the interval asked for, for as
/// long as the runtime runs tasks. Nothing is spawned without a watchdog.
pub fn spawn_watchdog() {
    let usec = std::env::var("WATCHDOG_USEC").ok();
    let pid = std::env::var("WATCHDOG_PID").ok();
    let Some(interval) = watchdog_interval(usec.as_deref(), pid.as_deref()) else {
        return;
    };
    tracing::info!("Service watchdog: pinging every {:?}", interval / 2);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval / 2);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            send("WATCHDOG=1");
        }
    });
}

/// A status is one line of the protocol: newlines would start fields of
/// their own.
fn one_line(text: &str) -> String {
    text.replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watchdog_interval_is_the_one_asked_of_this_process() {
        let me = std::process::id().to_string();
        assert_eq!(
            watchdog_interval(Some("30000000"), None),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            watchdog_interval(Some("30000000"), Some(&me)),
            Some(Duration::from_secs(30))
        );
        assert_eq!(watchdog_interval(Some("30000000"), Some("1")), None);
        assert_eq!(watchdog_interval(Some("0"), None), None);
        assert_eq!(watchdog_interval(Some("soon"), None), None);
        assert_eq!(watchdog_interval(None, Some(&me)), None);
    }

    #[test]
    fn a_status_stays_one_field() {
        assert_eq!(one_line("a\nb\rc"), "a b c");
    }

    /// What a manager listening on its socket receives, at a path and in
    /// the abstract namespace.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_notification_reaches_the_socket_it_names() {
        use std::os::linux::net::SocketAddrExt as _;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let listener = UnixDatagram::bind(&path).unwrap();
        assert!(send_to(path.as_os_str(), "READY=1\nSTATUS=x"));
        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\nSTATUS=x");

        let name = format!("pqcrypta-notify-test-{}", std::process::id());
        let abstract_listener =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(name.as_bytes()).unwrap())
                .unwrap();
        assert!(send_to(
            std::ffi::OsStr::new(&format!("@{name}")),
            "WATCHDOG=1"
        ));
        let n = abstract_listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"WATCHDOG=1");

        assert!(!send_to(dir.path().join("nobody").as_os_str(), "READY=1"));
        assert!(monotonic_usec().is_some_and(|u| u > 0));
    }
}
