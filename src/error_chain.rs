//! An error with every cause under it, for a log line.
//!
//! A `reqwest::Error` displays as "error sending request for url (...)"; why
//! it failed (a connection reset, a timeout, a certificate) is in its
//! `source()` chain, which `Display` leaves out. A fetch that fails now and
//! then says what happened only when the chain is in the line.

use std::error::Error;
use std::fmt;

/// Displays an error and each of its sources in turn, joined by ": ".
pub struct Chain<'a>(pub &'a (dyn Error + 'static));

impl fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<dyn Error + 'static>>);

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.1.as_deref()
        }
    }

    #[test]
    fn every_cause_is_in_the_line() {
        let io = std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset by peer",
        );
        let error = Layer(
            "error sending request for url (https://example.test/feed.json)",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(io)),
            ))),
        );
        assert_eq!(
            Chain(&error).to_string(),
            "error sending request for url (https://example.test/feed.json): client error (Connect): connection reset by peer"
        );
    }

    #[test]
    fn an_error_without_a_source_is_itself() {
        assert_eq!(
            Chain(&Layer("not a prefix list", None)).to_string(),
            "not a prefix list"
        );
    }
}
