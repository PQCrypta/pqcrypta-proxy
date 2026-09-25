//! TLS 1.3 early data (0-RTT) on the TCP listeners.
//!
//! `tls.enable_0rtt` opened early data on QUIC only. TCP session tickets
//! advertised none, and the one TCP path that looked at 0-RTT marked a whole
//! connection early whenever its ClientHello *offered* early data -- which, had
//! any ticket allowed it, would have answered 425 to requests sent after the
//! handshake while serving nothing from the early data itself.
//!
//! Early data only saves anything if the requests in it are served before the
//! handshake completes: a server that waits for the client's Finished answers
//! at the same moment it would have without 0-RTT. So both drivers here hand
//! the stream to HTTP as soon as the server's flight is out, read early data
//! first, and write any response to it as 0.5-RTT data:
//!
//! - [`EarlyOpenssl`] over OpenSSL's `SSL_read_early_data` /
//!   `SSL_write_early_data`, completing the handshake when the client's
//!   EndOfEarlyData arrives.
//! - [`EarlyRustls`] over a `rustls::ServerConnection` it drives itself, since
//!   tokio-rustls runs a server handshake to completion before returning.
//!
//! **What counts as early.** A request is early when it is dispatched before
//! the handshake has completed -- before the client's Finished has been
//! verified. That is the property replay turns on: an attacker can re-send a
//! recorded ClientHello and early data, and even the EndOfEarlyData after it,
//! but never the Finished, so everything a replayed connection dispatches is
//! marked. A request the server gets to after completion came from a client
//! that proved it holds the keys, and RFC 8470 §5.1 names waiting for the
//! handshake as a sound way to handle early data. The flag each connection
//! shares with [`FingerprintedConnection`](crate::tls_acceptor::FingerprintedConnection)
//! is [`HandshakeDone`].

use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Set once a connection's TLS handshake has completed. Shared between the
/// stream that completes it and the requests that ask whether they are early.
#[derive(Clone, Debug, Default)]
pub struct HandshakeDone(Arc<AtomicBool>);

impl HandshakeDone {
    /// A connection whose handshake has already completed: nothing on it can
    /// be early.
    pub fn completed() -> Self {
        Self(Arc::new(AtomicBool::new(true)))
    }

    pub fn is_done(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    fn set(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// How long closing a connection waits for its handshake to complete: until
/// the handshake deadline, measured from when the connection was accepted.
struct ShutdownWait {
    deadline: tokio::time::Instant,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl ShutdownWait {
    fn new(handshake_timeout: std::time::Duration) -> Self {
        Self {
            deadline: tokio::time::Instant::now() + handshake_timeout,
            sleep: None,
        }
    }

    /// Past the deadline; otherwise arranges a wake-up for it.
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        let deadline = self.deadline;
        self.sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)))
            .as_mut()
            .poll(cx)
            .is_ready()
    }
}

fn blocking<T>(r: Poll<io::Result<T>>) -> io::Result<T> {
    match r {
        Poll::Ready(r) => r,
        Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
    }
}

/// `std::io::Read` over an async stream for one poll: `Pending` is `WouldBlock`.
struct SyncIo<'a, 'b, T> {
    io: &'a mut T,
    cx: &'a mut Context<'b>,
}

impl<T: AsyncRead + Unpin> Read for SyncIo<'_, '_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rb = ReadBuf::new(buf);
        blocking(Pin::new(&mut *self.io).poll_read(self.cx, &mut rb))?;
        Ok(rb.filled().len())
    }
}

impl<T: AsyncWrite + Unpin> Write for SyncIo<'_, '_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        blocking(Pin::new(&mut *self.io).poll_write(self.cx, buf))
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        blocking(Pin::new(&mut *self.io).poll_write_vectored(self.cx, bufs))
    }

    fn flush(&mut self) -> io::Result<()> {
        blocking(Pin::new(&mut *self.io).poll_flush(self.cx))
    }
}

// ============================================================================
// rustls
// ============================================================================

/// A server TLS stream over rustls that serves early data before the
/// handshake completes.
pub struct EarlyRustls<IO> {
    io: IO,
    conn: rustls::ServerConnection,
    done: HandshakeDone,
    /// The transport has reported end of stream.
    eof: bool,
    /// How long a close waits for the handshake; see [`ShutdownWait`].
    shutdown: ShutdownWait,
}

impl<IO: AsyncRead + AsyncWrite + Unpin> EarlyRustls<IO> {
    /// Run the handshake until there is something to serve: its completion,
    /// or early data accepted with the server's flight on the wire.
    ///
    /// `handshake_timeout` (`tls.handshake_timeout_secs`) also bounds how long
    /// a close waits for the client's Finished; see [`ShutdownWait`].
    pub async fn accept(
        config: Arc<rustls::ServerConfig>,
        io: IO,
        handshake_timeout: std::time::Duration,
    ) -> io::Result<Self> {
        let conn = rustls::ServerConnection::new(config)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let mut stream = Self {
            io,
            conn,
            done: HandshakeDone::default(),
            eof: false,
            shutdown: ShutdownWait::new(handshake_timeout),
        };
        std::future::poll_fn(|cx| stream.poll_until_serving(cx)).await?;
        Ok(stream)
    }

    pub fn connection(&self) -> &rustls::ServerConnection {
        &self.conn
    }

    pub fn handshake_done(&self) -> HandshakeDone {
        self.done.clone()
    }

    fn note_progress(&self) {
        if !self.conn.is_handshaking() {
            self.done.set();
        }
    }

    fn poll_until_serving(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if !self.conn.is_handshaking() || self.conn.early_data().is_some() {
                // Our flight has to be out before anything is served: a
                // client cannot finish the handshake without it.
                return self.poll_write_tls(cx);
            }
            if self.conn.wants_write() {
                match self.poll_write_tls(cx) {
                    Poll::Ready(Ok(())) => {}
                    other => return other,
                }
            }
            match self.poll_read_tls(cx) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Write every TLS record rustls has queued.
    fn poll_write_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            let mut io = SyncIo {
                io: &mut self.io,
                cx,
            };
            match self.conn.write_tls(&mut io) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Read TLS records from the transport and process them. `Ok(0)` is end
    /// of stream.
    fn poll_read_tls(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut io = SyncIo {
            io: &mut self.io,
            cx,
        };
        let n = match self.conn.read_tls(&mut io) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if n == 0 {
            self.eof = true;
            return Poll::Ready(Ok(0));
        }
        if let Err(e) = self.conn.process_new_packets() {
            // rustls has queued the alert; send it before giving up.
            let _ = self.poll_write_tls(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
        }
        self.note_progress();
        Poll::Ready(Ok(n))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> EarlyRustls<IO> {
    /// Hand plaintext to rustls and push what it encrypts toward the
    /// transport. rustls buffers what the transport will not take yet, up to
    /// its limit; at the limit it accepts nothing, and the buffer is drained
    /// before trying again rather than reporting a zero-length write.
    fn poll_write_with(
        &mut self,
        cx: &mut Context<'_>,
        empty: bool,
        mut write: impl FnMut(&mut rustls::Writer<'_>) -> io::Result<usize>,
    ) -> Poll<io::Result<usize>> {
        loop {
            let n = write(&mut self.conn.writer())?;
            if n > 0 || empty {
                if let Poll::Ready(Err(e)) = self.poll_write_tls(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(n));
            }
            match self.poll_write_tls(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyRustls<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Early data first: the client sent it before anything that
            // follows the handshake, and rustls keeps it in its own buffer.
            if let Some(mut early) = this.conn.early_data() {
                let n = early.read(buf.initialize_unfilled())?;
                if n > 0 {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
            }
            if !this.conn.is_handshaking() {
                match this.conn.reader().read(buf.initialize_unfilled()) {
                    Ok(n) => {
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            } else if this.eof {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            if let Poll::Ready(Err(e)) = this.poll_write_tls(cx) {
                return Poll::Ready(Err(e));
            }
            match this.poll_read_tls(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EarlyRustls<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // After the server's Finished, rustls encrypts this as 0.5-RTT data.
        self.get_mut()
            .poll_write_with(cx, buf.is_empty(), |w| w.write(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let empty = bufs.iter().all(|b| b.is_empty());
        self.get_mut()
            .poll_write_with(cx, empty, |w| w.write_vectored(bufs))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        match this.poll_write_tls(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Finish the handshake before closing: a response to early data can
        // be complete before the client's Finished arrives, and a connection
        // closed then issues no tickets, so the client's next connection
        // cannot resume. Bounded: a replayed connection never finishes.
        while this.conn.is_handshaking() && !this.eof {
            if this.shutdown.expired(cx) {
                return Pin::new(&mut this.io).poll_shutdown(cx);
            }
            if let Poll::Ready(Err(e)) = this.poll_write_tls(cx) {
                return Poll::Ready(Err(e));
            }
            match this.poll_read_tls(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(_)) => return Pin::new(&mut this.io).poll_shutdown(cx),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.conn.send_close_notify();
        match this.poll_write_tls(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_shutdown(cx),
            other => other,
        }
    }
}

// ============================================================================
// OpenSSL
// ============================================================================

#[cfg(feature = "pqc")]
pub use openssl_driver::{EarlyOpenssl, OpensslStream};

#[cfg(feature = "pqc")]
mod openssl_driver {
    use super::{
        io, AsyncRead, AsyncWrite, Context, HandshakeDone, Pin, Poll, ReadBuf, ShutdownWait,
    };
    use openssl::ssl::{ErrorCode, Ssl, SslRef};
    use tokio_openssl::SslStream;

    fn to_io(e: openssl::ssl::Error) -> io::Error {
        if e.code() == ErrorCode::ZERO_RETURN {
            return io::ErrorKind::UnexpectedEof.into();
        }
        e.into_io_error().unwrap_or_else(io::Error::other)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Phase {
        /// Reading early data; writes go out as 0.5-RTT data.
        Early,
        /// EndOfEarlyData has arrived; the handshake is completing.
        Completing,
        Normal,
    }

    /// A server TLS stream over OpenSSL that serves early data before the
    /// handshake completes.
    pub struct EarlyOpenssl<S> {
        inner: SslStream<S>,
        phase: Phase,
        done: HandshakeDone,
        /// Early data read while accepting, served before any more is read.
        first: Vec<u8>,
        pos: usize,
        /// How long a close waits for the handshake; see [`ShutdownWait`].
        shutdown: ShutdownWait,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> EarlyOpenssl<S> {
        /// Accept a connection on a context with early data enabled.
        ///
        /// OpenSSL requires `SSL_read_early_data` until it reports the end of
        /// early data before the handshake may be completed, on every
        /// connection, early data or none. The first call processes the
        /// ClientHello and sends the server's flight; if early data follows,
        /// the stream is returned with it and the handshake still open.
        ///
        /// `handshake_timeout` also bounds how long a close waits for the
        /// client's Finished; see [`ShutdownWait`].
        pub async fn accept(
            ssl: Ssl,
            io: S,
            handshake_timeout: std::time::Duration,
        ) -> io::Result<Self> {
            let mut inner = SslStream::new(ssl, io).map_err(io::Error::other)?;
            let mut buf = vec![0u8; 16 * 1024];
            let n = Pin::new(&mut inner)
                .read_early_data(&mut buf)
                .await
                .map_err(to_io)?;
            let done = HandshakeDone::default();
            let phase = if n == 0 {
                Pin::new(&mut inner).accept().await.map_err(to_io)?;
                done.set();
                Phase::Normal
            } else {
                Phase::Early
            };
            buf.truncate(n);
            Ok(Self {
                inner,
                phase,
                done,
                first: buf,
                pos: 0,
                shutdown: ShutdownWait::new(handshake_timeout),
            })
        }

        pub fn ssl(&self) -> &SslRef {
            self.inner.ssl()
        }

        pub fn handshake_done(&self) -> HandshakeDone {
            self.done.clone()
        }

        fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.phase == Phase::Completing {
                match Pin::new(&mut self.inner).poll_accept(cx) {
                    Poll::Ready(Ok(())) => {
                        self.done.set();
                        self.phase = Phase::Normal;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(to_io(e))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    /// The server side of an OpenSSL connection: tokio-openssl's stream, or
    /// [`EarlyOpenssl`] when 0-RTT is enabled.
    pub enum OpensslStream<S> {
        Plain(SslStream<S>),
        Early(EarlyOpenssl<S>),
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> OpensslStream<S> {
        /// Accept on `ssl`, through `SSL_read_early_data` when its context
        /// allows early data -- which OpenSSL then requires of every
        /// connection -- and with a plain `SSL_accept` otherwise.
        /// `early_data` is `tls.handshake_timeout_secs` when 0-RTT is on.
        pub async fn accept(
            ssl: Ssl,
            io: S,
            early_data: Option<std::time::Duration>,
        ) -> io::Result<Self> {
            if let Some(handshake_timeout) = early_data {
                return EarlyOpenssl::accept(ssl, io, handshake_timeout)
                    .await
                    .map(Self::Early);
            }
            let mut s = SslStream::new(ssl, io).map_err(io::Error::other)?;
            Pin::new(&mut s).accept().await.map_err(to_io)?;
            Ok(Self::Plain(s))
        }

        pub fn ssl(&self) -> &SslRef {
            match self {
                Self::Plain(s) => s.ssl(),
                Self::Early(s) => s.ssl(),
            }
        }

        pub fn handshake_done(&self) -> HandshakeDone {
            match self {
                Self::Plain(_) => HandshakeDone::completed(),
                Self::Early(s) => s.handshake_done(),
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for OpensslStream<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
                Self::Early(s) => Pin::new(s).poll_read(cx, buf),
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for OpensslStream<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
                Self::Early(s) => Pin::new(s).poll_write(cx, buf),
            }
        }

        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
                Self::Early(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            }
        }

        fn is_write_vectored(&self) -> bool {
            match self {
                Self::Plain(s) => s.is_write_vectored(),
                Self::Early(s) => s.is_write_vectored(),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Plain(s) => Pin::new(s).poll_flush(cx),
                Self::Early(s) => Pin::new(s).poll_flush(cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
                Self::Early(s) => Pin::new(s).poll_shutdown(cx),
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for EarlyOpenssl<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            loop {
                match this.phase {
                    Phase::Early => {
                        if this.pos < this.first.len() {
                            let n = buf.remaining().min(this.first.len() - this.pos);
                            buf.put_slice(&this.first[this.pos..this.pos + n]);
                            this.pos += n;
                            return Poll::Ready(Ok(()));
                        }
                        match Pin::new(&mut this.inner)
                            .poll_read_early_data(cx, buf.initialize_unfilled())
                        {
                            Poll::Ready(Ok(0)) => this.phase = Phase::Completing,
                            Poll::Ready(Ok(n)) => {
                                buf.advance(n);
                                return Poll::Ready(Ok(()));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(to_io(e))),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Phase::Completing => match this.poll_complete(cx) {
                        Poll::Ready(Ok(())) => {}
                        other => return other,
                    },
                    Phase::Normal => return Pin::new(&mut this.inner).poll_read(cx, buf),
                }
            }
        }
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for EarlyOpenssl<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            match this.phase {
                Phase::Early => Pin::new(&mut this.inner)
                    .poll_write_early_data(cx, buf)
                    .map_err(to_io),
                Phase::Completing | Phase::Normal => {
                    match this.poll_complete(cx) {
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                    Pin::new(&mut this.inner).poll_write(cx, buf)
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            // Finish the handshake before closing, as EarlyRustls does: a
            // response to early data can be complete before the client's
            // Finished arrives, and closing then issues no ticket -- and
            // OpenSSL's tickets are single-use once early data is on, so the
            // client could not even resume. Early data nobody will read is
            // discarded on the way. Bounded: a replay never finishes.
            let mut scratch = [0u8; 4096];
            while this.phase != Phase::Normal {
                if this.shutdown.expired(cx) {
                    // No close_notify mid-handshake; close the transport.
                    return Pin::new(this.inner.get_mut()).poll_shutdown(cx);
                }
                let step = match this.phase {
                    Phase::Early => Pin::new(&mut this.inner)
                        .poll_read_early_data(cx, &mut scratch)
                        .map(|r| match r {
                            Ok(0) => {
                                this.phase = Phase::Completing;
                                Ok(())
                            }
                            Ok(_) => Ok(()),
                            Err(e) => Err(to_io(e)),
                        }),
                    _ => this.poll_complete(cx),
                };
                match step {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(_)) => return Pin::new(this.inner.get_mut()).poll_shutdown(cx),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut this.inner).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NAME: &str = "early.test";
    const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

    fn cert() -> rcgen::CertifiedKey<rcgen::KeyPair> {
        rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap()
    }

    /// Drive a rustls client by hand over `io`: early data goes in the first
    /// flight, `after` once the handshake is done, and everything the server
    /// sends is returned with whether the early data was accepted.
    async fn rustls_client(
        config: Arc<rustls::ClientConfig>,
        io: tokio::io::DuplexStream,
        early: &[u8],
        after: &[u8],
        want: usize,
    ) -> (bool, Vec<u8>) {
        let mut conn = rustls::ClientConnection::new(config, NAME.try_into().unwrap()).unwrap();
        if !early.is_empty() {
            conn.early_data()
                .expect("the ticket allows early data")
                .write_all(early)
                .unwrap();
        }
        let (mut rd, mut wr) = tokio::io::split(io);
        let mut got = Vec::new();
        let mut sent_after = after.is_empty();
        let mut buf = vec![0u8; 64 * 1024];
        while got.len() < want {
            if !conn.is_handshaking() && !sent_after {
                conn.writer().write_all(after).unwrap();
                sent_after = true;
            }
            while conn.wants_write() {
                let mut out = Vec::new();
                conn.write_tls(&mut out).unwrap();
                wr.write_all(&out).await.unwrap();
            }
            let n = rd.read(&mut buf).await.unwrap();
            assert!(n > 0, "server closed before sending {want} bytes");
            conn.read_tls(&mut &buf[..n]).unwrap();
            conn.process_new_packets().unwrap();
            let mut plain = vec![0u8; 64 * 1024];
            while let Ok(k) = conn.reader().read(&mut plain) {
                if k == 0 {
                    break;
                }
                got.extend_from_slice(&plain[..k]);
            }
        }
        if !sent_after {
            conn.writer().write_all(after).unwrap();
        }
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out).unwrap();
            wr.write_all(&out).await.unwrap();
        }
        (conn.is_early_data_accepted(), got)
    }

    #[tokio::test]
    async fn rustls_serves_early_data_before_the_handshake_completes() {
        tokio::time::timeout(std::time::Duration::from_secs(20), rustls_round_trip())
            .await
            .expect("rejected early data leaves both sides waiting");
    }

    async fn rustls_round_trip() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        let ck = cert();
        let der = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        server.max_early_data_size = 16384;
        let server = Arc::new(server);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.enable_early_data = true;
        let client = Arc::new(client);

        // A full handshake first, to earn a ticket.
        let (c, s) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn({
            let server = Arc::clone(&server);
            async move {
                let mut tls = EarlyRustls::accept(server, s, WAIT).await.unwrap();
                assert!(
                    tls.handshake_done().is_done(),
                    "no early data: complete on return"
                );
                let mut b = [0u8; 5];
                tls.read_exact(&mut b).await.unwrap();
                tls.write_all(b"first").await.unwrap();
                tls.flush().await.unwrap();
            }
        });
        let (accepted, got) = rustls_client(Arc::clone(&client), c, b"", b"hello", 5).await;
        assert!(!accepted);
        assert_eq!(got, b"first");
        srv.await.unwrap();

        // Resumed, with the request in early data.
        let (c, s) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let mut tls = EarlyRustls::accept(server, s, WAIT).await.unwrap();
            let done = tls.handshake_done();
            let mut b = [0u8; 13];
            tls.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"early request");
            assert!(
                !done.is_done(),
                "the early request is served before the Finished"
            );
            // Answered at once: 0.5-RTT data.
            tls.write_all(b"early reply").await.unwrap();
            tls.flush().await.unwrap();
            let mut a = [0u8; 5];
            tls.read_exact(&mut a).await.unwrap();
            assert_eq!(&a, b"later");
            assert!(done.is_done(), "what follows the handshake is not early");
            tls.write_all(b"late").await.unwrap();
            tls.flush().await.unwrap();
        });
        let (accepted, got) = rustls_client(client, c, b"early request", b"later", 15).await;
        assert!(accepted, "the server accepted the early data");
        assert_eq!(got, b"early replylate");
        srv.await.unwrap();
    }

    #[cfg(feature = "pqc")]
    #[tokio::test]
    #[allow(unsafe_code)] // SslRef::set_session: resuming needs it
    async fn openssl_serves_early_data_before_the_handshake_completes() {
        tokio::time::timeout(std::time::Duration::from_secs(20), openssl_round_trip())
            .await
            .expect("rejected early data leaves both sides waiting");
    }

    #[cfg(feature = "pqc")]
    #[allow(unsafe_code)]
    async fn openssl_round_trip() {
        use openssl::pkey::PKey;
        use openssl::ssl::{
            Ssl, SslAcceptor, SslConnector, SslMethod, SslSessionCacheMode, SslVerifyMode,
        };
        use openssl::x509::X509;
        use tokio_openssl::SslStream;

        let ck = cert();
        let mut acceptor = SslAcceptor::mozilla_modern_v5(SslMethod::tls_server()).unwrap();
        acceptor
            .set_certificate(&X509::from_pem(ck.cert.pem().as_bytes()).unwrap())
            .unwrap();
        acceptor
            .set_private_key(
                &PKey::private_key_from_pem(ck.signing_key.serialize_pem().as_bytes()).unwrap(),
            )
            .unwrap();
        acceptor.set_session_cache_mode(SslSessionCacheMode::SERVER);
        acceptor.set_max_early_data(16384).unwrap();
        // OpenSSL accepts early data only if the resumed session's server name
        // matches, and records the name only when SNI is acknowledged -- which
        // takes a servername callback, as the listeners' acceptor has.
        acceptor.set_servername_callback(|_, _| Ok(()));
        let acceptor = Arc::new(acceptor.build());

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();
        connector.set_verify(SslVerifyMode::NONE);
        let connector = connector.build();

        // A full handshake first, to earn a ticket.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn({
            let acceptor = Arc::clone(&acceptor);
            async move {
                let ssl = Ssl::new(acceptor.context()).unwrap();
                let mut tls = EarlyOpenssl::accept(ssl, server_io, WAIT).await.unwrap();
                assert!(
                    tls.handshake_done().is_done(),
                    "no early data: complete on return"
                );
                let mut first = [0u8; 5];
                tls.read_exact(&mut first).await.unwrap();
                tls.write_all(b"first").await.unwrap();
                tls.flush().await.unwrap();
                // A clean close, as the listeners make: OpenSSL drops the
                // session of a connection freed without one from its cache
                // (ssl_clear_bad_session), and the ticket with it.
                tls.shutdown().await.unwrap();
            }
        });
        let ssl = connector.configure().unwrap().into_ssl(NAME).unwrap();
        let mut cli = SslStream::new(ssl, client_io).unwrap();
        Pin::new(&mut cli).connect().await.unwrap();
        cli.write_all(b"hello").await.unwrap();
        let mut first = [0u8; 5];
        cli.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"first");
        let session = cli.ssl().session().unwrap().to_owned();
        assert_eq!(
            session.max_early_data(),
            16384,
            "the ticket allows early data"
        );
        srv.await.unwrap();

        // Resumed, with the request in early data.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            let ssl = Ssl::new(acceptor.context()).unwrap();
            let mut tls = EarlyOpenssl::accept(ssl, server_io, WAIT).await.unwrap();
            let done = tls.handshake_done();
            let mut early = [0u8; 13];
            tls.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early request");
            assert!(
                !done.is_done(),
                "the early request is served before the Finished"
            );
            tls.write_all(b"early reply").await.unwrap();
            tls.flush().await.unwrap();
            let mut later = [0u8; 5];
            tls.read_exact(&mut later).await.unwrap();
            assert_eq!(&later, b"later");
            assert!(done.is_done(), "what follows the handshake is not early");
        });
        let mut ssl = connector.configure().unwrap().into_ssl(NAME).unwrap();
        // Safety: the session came from a connection on the same context.
        unsafe { ssl.set_session(&session).unwrap() };
        let mut cli = SslStream::new(ssl, client_io).unwrap();
        let n = Pin::new(&mut cli)
            .write_early_data(b"early request")
            .await
            .unwrap();
        assert_eq!(n, 13);
        Pin::new(&mut cli).connect().await.unwrap();
        // int SSL_get_early_data_status(const SSL *s): 0 not sent, 1 rejected,
        // 2 accepted. openssl-sys does not bind it.
        unsafe extern "C" {
            fn SSL_get_early_data_status(ssl: *const openssl_sys::SSL) -> std::os::raw::c_int;
        }
        use foreign_types::ForeignTypeRef;
        // Safety: a live SSL owned by `cli`.
        let status = unsafe { SSL_get_early_data_status(cli.ssl().as_ptr()) };
        assert!(cli.ssl().session_reused(), "the ticket was not resumed");
        assert_eq!(status, 2, "early data status {status} (1 = rejected)");
        let mut reply = [0u8; 11];
        cli.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"early reply");
        cli.write_all(b"later").await.unwrap();
        cli.flush().await.unwrap();
        // The server's own assertions above are the proof it was served
        // early; a panic there surfaces here.
        srv.await.unwrap();
    }

    #[test]
    fn a_completed_handshake_is_never_early() {
        assert!(HandshakeDone::completed().is_done());
        let open = HandshakeDone::default();
        let shared = open.clone();
        assert!(!shared.is_done());
        open.set();
        assert!(shared.is_done(), "the flag is shared, not copied");
    }
}
