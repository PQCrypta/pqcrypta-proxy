//! This module contains the error handling logic and types for the h3 crate.

mod codes;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
pub mod connection_error_creators;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
pub(crate) mod connection_error_creators;

#[cfg(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes")]
pub mod internal_error;
#[cfg(not(feature = "i-implement-a-third-party-backend-and-opt-into-breaking-changes"))]
pub(crate) mod internal_error;

// The error types themselves, re-exported below; named for the module they
// live in, as upstream h3 does.
#[allow(clippy::module_inception)]
mod error;

pub use codes::Code;
pub use error::{ConnectionError, LocalError, StreamError};
