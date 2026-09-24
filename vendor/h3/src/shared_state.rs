//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
};

use bytes::BytesMut;
use futures_util::task::AtomicWaker;

use crate::{config::Settings, error::internal_error::ErrorOrigin};

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
    /// Whether this endpoint is the client.
    ///
    /// A handful of frames are legal in one direction and not the other, and
    /// the shared request-stream code cannot tell which end it is on without
    /// this. PUSH_PROMISE is the case that needed it: on a client's response
    /// stream it is a legal frame whose push ID may be wrong (§7.2.5,
    /// H3_ID_ERROR), and on a server it should never arrive at all
    /// (H3_FRAME_UNEXPECTED). Both were answered H3_FRAME_UNEXPECTED, and our
    /// own conformance suite failed us for the first.
    is_client: AtomicBool,
    /// The QPACK decoder, and with it the dynamic table.
    ///
    /// Shared because two places need the same one: the connection, which
    /// applies encoder instructions as they arrive, and each request stream,
    /// which decodes field sections that may reference what those
    /// instructions inserted. A copy in each would decode against a table
    /// that had not seen the inserts.
    pub(crate) qpack_decoder: Mutex<crate::qpack::Decoder>,
    /// Bumped whenever the QPACK dynamic table may have grown, and whenever
    /// the connection ends.
    ///
    /// This is what lets a field section wait. A section that references an
    /// insert which has not arrived yet cannot be decoded now and can be
    /// decoded later; the alternative -- failing the connection with
    /// QPACK_DECOMPRESSION_FAILED -- is what a decoder that advertises zero
    /// blocked streams is obliged to do, and it is why we advertised zero.
    /// The counter is a generation, not the insert count: a spurious wakeup
    /// costs one retry of a decode that was going to have to happen anyway,
    /// and a missed one costs a hung request.
    ///
    /// The connection-ended bump matters as much as the insert one. The
    /// sender lives here, inside the `Arc` every stream holds, so it is never
    /// dropped while a stream could be waiting on it, and a closed connection
    /// would otherwise park the waiter forever.
    qpack_progress: tokio::sync::watch::Sender<u64>,
    /// Instructions a request stream has produced for the QPACK decoder
    /// stream, waiting for the connection task to write them.
    ///
    /// Section Acknowledgment and Stream Cancellation are produced where the
    /// field section is decoded, which is the request stream, and can only be
    /// written by the task that owns the decoder stream, which is the
    /// connection. This is the queue between them.
    qpack_decoder_out: Mutex<BytesMut>,
    /// How many field sections are parked waiting for inserts right now.
    qpack_blocked: AtomicU64,
    /// SETTINGS_QPACK_BLOCKED_STREAMS as *this* endpoint advertised it.
    ///
    /// Our own promise, not the peer's: RFC 9204 4.1.1 lets us treat more
    /// blocked streams than we advertised as a connection error, and a
    /// decoder that quietly parks more than it said it would is a decoder
    /// whose SETTINGS mean nothing.
    qpack_blocked_max: AtomicU64,
}

impl SharedState {
    /// Mark this state as belonging to a client endpoint.
    pub(crate) fn set_is_client(&self) {
        self.is_client
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether this endpoint is the client.
    pub(crate) fn is_client(&self) -> bool {
        self.is_client.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Watch the QPACK progress generation.
    ///
    /// Subscribe *before* attempting the decode that might block: the
    /// receiver marks everything up to now as seen, so an insert that lands
    /// between the failed attempt and the wait is still observed.
    pub(crate) fn qpack_progress(&self) -> tokio::sync::watch::Receiver<u64> {
        self.qpack_progress.subscribe()
    }

    /// Wake every parked field section.
    pub(crate) fn qpack_made_progress(&self) {
        self.qpack_progress.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Record this endpoint's advertised blocked-stream limit.
    pub(crate) fn set_qpack_blocked_max(&self, max: u64) {
        self.qpack_blocked_max.store(max, Ordering::Relaxed);
    }

    /// Take a blocked-stream slot, if one is left within what we advertised.
    ///
    /// Takes the `Arc` rather than `&self` so the guard can outlive the
    /// borrow: the caller has to reach `&mut self` for error handling while
    /// still holding the slot.
    pub(crate) fn qpack_block(state: &Arc<Self>) -> Option<QpackBlocked> {
        let max = state.qpack_blocked_max.load(Ordering::Relaxed);
        let mut current = state.qpack_blocked.load(Ordering::Relaxed);
        loop {
            if current >= max {
                return None;
            }
            match state.qpack_blocked.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(QpackBlocked {
                        state: state.clone(),
                    })
                }
                Err(seen) => current = seen,
            }
        }
    }

    /// Queue bytes for the QPACK decoder stream and wake the connection.
    pub(crate) fn queue_decoder_instruction(&self, write: impl FnOnce(&mut BytesMut)) {
        {
            let mut out = self
                .qpack_decoder_out
                .lock()
                .expect("the QPACK decoder stream queue lock is never held across a panic");
            write(&mut out);
        }
        self.waker.wake();
    }

    /// Take everything queued for the QPACK decoder stream.
    pub(crate) fn take_decoder_instructions(&self) -> Option<BytesMut> {
        let mut out = self
            .qpack_decoder_out
            .lock()
            .expect("the QPACK decoder stream queue lock is never held across a panic");
        if out.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut out))
        }
    }
}

/// A blocked-stream slot, released when the section decodes or gives up.
///
/// A guard rather than a pair of calls because every path out of the wait --
/// decoded, connection error, header too big, task dropped mid-await -- has
/// to give the slot back, and one of them will always be forgotten otherwise.
pub(crate) struct QpackBlocked {
    state: Arc<SharedState>,
}

impl Drop for QpackBlocked {
    fn drop(&mut self) {
        self.state.qpack_blocked.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            is_client: AtomicBool::new(false),
            qpack_decoder: Mutex::new(crate::qpack::Decoder::default()),
            qpack_progress: tokio::sync::watch::channel(0).0,
            qpack_decoder_out: Mutex::new(BytesMut::new()),
            qpack_blocked: AtomicU64::new(0),
            qpack_blocked_max: AtomicU64::new(0),
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        // A field section parked on a missing insert is waiting for a table
        // that will now never grow. Waking it here, rather than only in
        // `set_conn_error_and_wake`, covers the paths that set the error
        // without waking the connection -- those still have to unpark the
        // streams, or the request hangs until the caller's own timeout.
        self.shared_state().qpack_made_progress();
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<'_, Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(Cow::Borrowed)
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
