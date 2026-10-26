use super::{prefix_int, prefix_string};

#[derive(Debug, PartialEq)]
pub enum ParseError {
    Integer(prefix_int::Error),
    String(prefix_string::Error),
    InvalidPrefix(u8),
    InvalidBase(isize),
    /// An Encoded Insert Count no conformant encoder can produce (RFC 9204
    /// section 4.5.1.1)
    InvalidInsertCount(usize),
}

impl From<prefix_int::Error> for ParseError {
    fn from(e: prefix_int::Error) -> Self {
        ParseError::Integer(e)
    }
}

impl From<prefix_string::Error> for ParseError {
    fn from(e: prefix_string::Error) -> Self {
        ParseError::String(e)
    }
}
