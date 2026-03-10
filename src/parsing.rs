//! Parsing functions to parse data using [Buf].

use std::backtrace::Backtrace;
use std::error::Error as StdError;
use std::fmt;

use bytes::{Buf, Bytes};

/// Parsing errors
#[derive(Debug)]
pub enum Error {
    TooShort {
        typ: Typ,
        context: &'static str,
        source: RemainingError,
    },
    TagMismatch {
        expected: Vec<u8>,
        found: Bytes,
        context: &'static str,
        backtrace: Option<Backtrace>,
    },
    UnexpectedEof {
        source: std::io::Error,
        backtrace: Option<Backtrace>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { context, typ, .. } => write!(f, "{}: reading {:?}", context, typ),
            Self::TagMismatch {
                expected, found, ..
            } => write!(
                f,
                "expected {}, found {}",
                debug_bytes(expected),
                debug_bytes(&found[..]),
            ),
            Self::UnexpectedEof { source, .. } => fmt::Display::fmt(source, f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::TooShort { source, .. } => Some(source),
            Self::TagMismatch { .. } => None,
            Self::UnexpectedEof { source, .. } => source.source(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::UnexpectedEof {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl Error {
    /// Returns true if the error indictates that the input was too short.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TooShort { .. } => true,
            Self::TagMismatch { .. } => false,
            Self::UnexpectedEof { .. } => true,
        }
    }
}

fn debug_bytes(b: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(b) {
        return s.to_string();
    }
    hex::encode(b)
}

#[derive(Debug)]
pub struct RemainingError {
    pub needed: usize,
    pub remaining: usize,
    #[allow(dead_code)]
    backtrace: Option<Backtrace>,
}

impl fmt::Display for RemainingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "needed {}, remaining {}", self.needed, self.remaining)
    }
}

impl StdError for RemainingError {}

#[derive(Debug)]
pub enum Typ {
    U8,
    U16Be,
    U16Le,
    U32Be,
    Array(usize),
    Take(usize),
    Tag(Vec<u8>),
}

pub trait BufParsing: Buf + Sized {
    fn read_u8(&mut self) -> Result<u8, Error> {
        self.ensure_remaining(1).map_err(|e| Error::TooShort {
            typ: Typ::U8,
            source: e,
            context: "todo",
        })?;
        Ok(self.get_u8())
    }

    fn read_le_u16(&mut self) -> Result<u16, Error> {
        self.ensure_remaining(2).map_err(|e| Error::TooShort {
            typ: Typ::U16Le,
            source: e,
            context: "todo",
        })?;
        Ok(self.get_u16_le())
    }

    fn rest(&mut self) -> Bytes {
        let len = self.remaining();
        self.copy_to_bytes(len)
    }

    fn ensure_remaining(&self, size: usize) -> Result<(), RemainingError> {
        if self.remaining() < size {
            return Err(RemainingError {
                needed: size,
                remaining: self.remaining(),
                backtrace: Some(Backtrace::capture()),
            });
        }

        Ok(())
    }
}

impl<B: Buf> BufParsing for B {}
