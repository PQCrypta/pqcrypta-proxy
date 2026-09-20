//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    sync::{atomic::AtomicBool, OnceLock},
};

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
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            is_client: AtomicBool::new(false),
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
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(|s| Cow::Borrowed(s))
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
