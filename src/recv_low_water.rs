//! A socket's receive low-water mark (`SO_RCVLOWAT`): how many bytes must be
//! queued before the socket is reported readable.
//!
//! The TCP listeners read a client's first TLS record, the ClientHello, by
//! peeking at it, so the bytes stay for the TLS stack that reads them next.
//! A peek returns at once while anything at all is queued, so waiting for the
//! rest of a record that arrives in pieces (a post-quantum ClientHello spans
//! two or three segments) meant peeking again every few milliseconds. With the
//! mark set to what the record still needs, the kernel reports the socket
//! readable once, when the record is whole (or the peer closes): Linux holds
//! the wake-up (`tcp_data_ready`) and the poll (`tcp_poll`) to the mark, and
//! kqueue's `EVFILT_READ` reads it too.
//!
//! No crate the proxy uses sets this option (socket2, nix and rustix have no
//! setter for it), so it is set here, the one `setsockopt` this crate makes.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsRawFd;

/// Report `socket` readable only once `bytes` are queued (at least 1, the
/// default). Linux grows the receive buffer to fit the mark if it must.
pub fn set(socket: &impl AsRawFd, bytes: usize) -> io::Result<()> {
    let value = libc::c_int::try_from(bytes.max(1)).unwrap_or(libc::c_int::MAX);
    let length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: the descriptor belongs to `socket`, which outlives the call; the
    // option value is a live c_int on this stack frame and `length` is its
    // size, as setsockopt(2) requires for SO_RCVLOWAT. Nothing is retained.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVLOWAT,
            (&raw const value).cast::<libc::c_void>(),
            length,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mark set is the mark the kernel reports back
    #[test]
    fn the_mark_is_set_and_reset() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let read = |s: &std::net::TcpStream| {
            let mut value: libc::c_int = 0;
            let mut length = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
            // SAFETY: as in `set`; getsockopt writes at most `length` bytes
            // into `value`.
            let rc = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVLOWAT,
                    (&raw mut value).cast::<libc::c_void>(),
                    &raw mut length,
                )
            };
            assert_eq!(rc, 0);
            value
        };
        set(&client, 1700).unwrap();
        assert_eq!(read(&client), 1700);
        set(&client, 0).unwrap();
        assert_eq!(read(&client), 1, "0 means the default, 1");
    }
}
