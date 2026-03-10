//! rPGP errors

use std::backtrace::Backtrace;
use std::error::Error as StdError;
use std::fmt;
use std::num::TryFromIntError;

use ed25519_dalek::SignatureError;

use crate::composed::{SecretKeyParamsBuilderError, SubkeyParamsBuilderError};

pub type Result<T, E = Error> = ::std::result::Result<T, E>;

// custom nom error types
pub const MPI_TOO_LONG: u32 = 1000;

pub use crate::parsing::{Error as ParsingError, RemainingError};

/// Error types
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidInput {
        backtrace: Option<Backtrace>,
    },
    InvalidArmorWrappers,
    InvalidChecksum,
    Base64Decode {
        source: base64::DecodeError,
        backtrace: Option<Backtrace>,
    },
    RequestedSizeTooLarge,
    NoMatchingPacket {
        backtrace: Option<Backtrace>,
    },
    TooManyPackets,
    PacketTooLarge {
        size: u64,
    },
    RSAError {
        source: Box<rsa::errors::Error>,
        backtrace: Option<Backtrace>,
    },
    EllipticCurve {
        source: elliptic_curve::Error,
        backtrace: Option<Backtrace>,
    },
    IO {
        source: std::io::Error,
        backtrace: Option<Backtrace>,
    },
    InvalidKeyLength,
    BlockMode,
    MissingKey,
    CfbInvalidKeyIvLength,
    Unimplemented {
        message: String,
        backtrace: Option<Backtrace>,
    },
    /// Signals packet versions and parameters we don't support, but can safely ignore
    Unsupported {
        message: String,
        backtrace: Option<Backtrace>,
    },
    Message {
        message: String,
        backtrace: Option<Backtrace>,
    },
    PacketError {
        kind: nom::error::ErrorKind,
    },
    UnpadError,
    PadError,
    Utf8Error {
        source: std::str::Utf8Error,
        backtrace: Option<Backtrace>,
    },
    ParseIntError {
        source: std::num::ParseIntError,
        backtrace: Option<Backtrace>,
    },
    InvalidPacketContent {
        source: Box<Error>,
    },
    SignatureError {
        source: SignatureError,
    },
    MdcError,
    TryFromInt {
        source: TryFromIntError,
        backtrace: Option<Backtrace>,
    },
    Aead {
        source: crate::crypto::aead::Error,
    },
    AesKw {
        source: crate::crypto::aes_kw::Error,
    },
    ChecksumMissmatch {
        source: crate::crypto::checksum::ChecksumMismatch,
    },
    Sha1HashCollision {
        source: crate::crypto::checksum::Sha1HashCollision,
    },
    AesKek {
        source: aes_kw::Error,
    },
    PacketParsing {
        source: Box<ParsingError>,
    },
    PacketIncomplete {
        source: Box<ParsingError>,
    },
    Argon2 {
        source: argon2::Error,
        backtrace: Option<Backtrace>,
    },
    SigningError {
        source: cx448::SigningError,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { .. } => f.write_str("invalid input"),
            Self::InvalidArmorWrappers => f.write_str("invalid armor wrappers"),
            Self::InvalidChecksum => f.write_str("invalid crc24 checksum"),
            Self::Base64Decode { source, .. } => fmt::Display::fmt(source, f),
            Self::RequestedSizeTooLarge => {
                f.write_str("requested data size is larger than the packet body")
            }
            Self::NoMatchingPacket { .. } => f.write_str("no matching packet found"),
            Self::TooManyPackets => f.write_str("more than one matching packet was found"),
            Self::PacketTooLarge { size } => write!(
                f,
                "packet contained more data than was parsable (trailing bytes {})",
                size,
            ),
            Self::RSAError { source, .. } => fmt::Display::fmt(source, f),
            Self::EllipticCurve { source, .. } => fmt::Display::fmt(source, f),
            Self::IO { source, .. } => write!(f, "IO error: {}", source),
            Self::InvalidKeyLength => f.write_str("invalid key length"),
            Self::BlockMode => f.write_str("block mode error"),
            Self::MissingKey => f.write_str("missing key"),
            Self::CfbInvalidKeyIvLength => f.write_str("cfb: invalid key iv length"),
            Self::Unimplemented { message, .. } => write!(f, "Not yet implemented: {}", message),
            Self::Unsupported { message, .. } => write!(f, "Unsupported: {}", message),
            Self::Message { message, .. } => fmt::Display::fmt(message, f),
            Self::PacketError { kind } => write!(f, "Invalid Packet {:?}", kind),
            Self::UnpadError => f.write_str("Unpadding failed"),
            Self::PadError => f.write_str("Padding failed"),
            Self::Utf8Error { source, .. } => fmt::Display::fmt(source, f),
            Self::ParseIntError { source, .. } => fmt::Display::fmt(source, f),
            Self::InvalidPacketContent { source } => {
                write!(f, "Invalid Packet Content {:?}", source)
            }
            Self::SignatureError { source, .. } => fmt::Display::fmt(source, f),
            Self::MdcError => f.write_str("Modification Detection Code error"),
            Self::TryFromInt { source, .. } => fmt::Display::fmt(source, f),
            Self::Aead { source } => write!(f, "AEAD {:?}", source),
            Self::AesKw { source } => write!(f, "AES key wrap {:?}", source),
            Self::ChecksumMissmatch { source, .. } => fmt::Display::fmt(source, f),
            Self::Sha1HashCollision { source, .. } => fmt::Display::fmt(source, f),
            Self::AesKek { source, .. } => fmt::Display::fmt(source, f),
            Self::PacketParsing { source, .. } => fmt::Display::fmt(source, f),
            Self::PacketIncomplete { .. } => f.write_str("packet is incomplete"),
            Self::Argon2 { source, .. } => fmt::Display::fmt(source, f),
            Self::SigningError { source, .. } => fmt::Display::fmt(source, f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::InvalidInput { .. } => None,
            Self::InvalidArmorWrappers => None,
            Self::InvalidChecksum => None,
            Self::Base64Decode { source, .. } => source.source(),
            Self::RequestedSizeTooLarge => None,
            Self::NoMatchingPacket { .. } => None,
            Self::TooManyPackets => None,
            Self::PacketTooLarge { .. } => None,
            Self::RSAError { source, .. } => source.source(),
            Self::EllipticCurve { source, .. } => source.source(),
            Self::IO { source, .. } => Some(source),
            Self::InvalidKeyLength => None,
            Self::BlockMode => None,
            Self::MissingKey => None,
            Self::CfbInvalidKeyIvLength => None,
            Self::Unimplemented { .. } => None,
            Self::Unsupported { .. } => None,
            Self::Message { .. } => None,
            Self::PacketError { .. } => None,
            Self::UnpadError => None,
            Self::PadError => None,
            Self::Utf8Error { source, .. } => source.source(),
            Self::ParseIntError { source, .. } => source.source(),
            Self::InvalidPacketContent { source, .. } => Some(&**source),
            Self::SignatureError { source, .. } => source.source(),
            Self::MdcError => None,
            Self::TryFromInt { source, .. } => source.source(),
            Self::Aead { source } => Some(source),
            Self::AesKw { source } => Some(source),
            Self::ChecksumMissmatch { source, .. } => source.source(),
            Self::Sha1HashCollision { source, .. } => source.source(),
            Self::AesKek { source, .. } => source.source(),
            Self::PacketParsing { source, .. } => source.source(),
            Self::PacketIncomplete { source, .. } => Some(&**source),
            Self::Argon2 { source, .. } => source.source(),
            Self::SigningError { source, .. } => source.source(),
        }
    }
}

// --- From impls for transparent variants ---

impl From<base64::DecodeError> for Error {
    fn from(source: base64::DecodeError) -> Self {
        Self::Base64Decode {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(error: rsa::errors::Error) -> Self {
        Self::RSAError {
            backtrace: Some(Backtrace::capture()),
            source: Box::new(error),
        }
    }
}

impl From<elliptic_curve::Error> for Error {
    fn from(source: elliptic_curve::Error) -> Self {
        Self::EllipticCurve {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

// context(false) — auto From
impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::IO {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(source: std::str::Utf8Error) -> Self {
        Self::Utf8Error {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl From<std::num::ParseIntError> for Error {
    fn from(source: std::num::ParseIntError) -> Self {
        Self::ParseIntError {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl From<SignatureError> for Error {
    fn from(source: SignatureError) -> Self {
        Self::SignatureError { source }
    }
}

impl From<TryFromIntError> for Error {
    fn from(source: TryFromIntError) -> Self {
        Self::TryFromInt {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

// context(false) — auto From
impl From<crate::crypto::aead::Error> for Error {
    fn from(source: crate::crypto::aead::Error) -> Self {
        Self::Aead { source }
    }
}

// context(false) — auto From
impl From<crate::crypto::aes_kw::Error> for Error {
    fn from(source: crate::crypto::aes_kw::Error) -> Self {
        Self::AesKw { source }
    }
}

impl From<crate::crypto::checksum::ChecksumMismatch> for Error {
    fn from(source: crate::crypto::checksum::ChecksumMismatch) -> Self {
        Self::ChecksumMissmatch { source }
    }
}

impl From<crate::crypto::checksum::Sha1HashCollision> for Error {
    fn from(source: crate::crypto::checksum::Sha1HashCollision) -> Self {
        Self::Sha1HashCollision { source }
    }
}

impl From<aes_kw::Error> for Error {
    fn from(source: aes_kw::Error) -> Self {
        Self::AesKek { source }
    }
}

impl From<ParsingError> for Error {
    fn from(error: ParsingError) -> Self {
        Self::PacketParsing {
            source: Box::new(error),
        }
    }
}

impl From<argon2::Error> for Error {
    fn from(source: argon2::Error) -> Self {
        Self::Argon2 {
            backtrace: Some(Backtrace::capture()),
            source,
        }
    }
}

impl From<cx448::SigningError> for Error {
    fn from(source: cx448::SigningError) -> Self {
        Self::SigningError { source }
    }
}

// --- Manual From impls (not from snafu) ---

impl From<crate::crypto::hash::Error> for Error {
    fn from(err: crate::crypto::hash::Error) -> Self {
        match err {
            crate::crypto::hash::Error::Unsupported { alg } => UnsupportedSnafu {
                message: format!("hash algorithm: {alg:?}"),
            }
            .build(),
            crate::crypto::hash::Error::Sha1HashCollision { source } => source.into(),
        }
    }
}

impl<T> From<nom::error::Error<T>> for Error {
    fn from(err: nom::error::Error<T>) -> Self {
        Self::PacketError { kind: err.code }
    }
}

impl From<cipher::InvalidLength> for Error {
    fn from(_: cipher::InvalidLength) -> Error {
        Error::CfbInvalidKeyIvLength
    }
}

impl From<block_padding::UnpadError> for Error {
    fn from(_: block_padding::UnpadError) -> Error {
        Error::UnpadError
    }
}

impl From<SecretKeyParamsBuilderError> for Error {
    fn from(err: SecretKeyParamsBuilderError) -> Error {
        Error::Message {
            message: err.to_string(),
            backtrace: Some(Backtrace::capture()),
        }
    }
}

impl From<SubkeyParamsBuilderError> for Error {
    fn from(err: SubkeyParamsBuilderError) -> Error {
        Error::Message {
            message: err.to_string(),
            backtrace: Some(Backtrace::capture()),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Error {
        Error::Message {
            message: err,
            backtrace: Some(Backtrace::capture()),
        }
    }
}

// --- Context selectors ---

pub(crate) struct InvalidInputSnafu;

impl InvalidInputSnafu {
    #[must_use]
    pub(crate) fn build(self) -> Error {
        Error::InvalidInput {
            backtrace: Some(Backtrace::capture()),
        }
    }
}

pub(crate) struct NoMatchingPacketSnafu;

impl NoMatchingPacketSnafu {
    #[must_use]
    pub(crate) fn build(self) -> Error {
        Error::NoMatchingPacket {
            backtrace: Some(Backtrace::capture()),
        }
    }
}

pub(crate) struct UnimplementedSnafu {
    pub(crate) message: String,
}

impl UnimplementedSnafu {
    #[must_use]
    pub(crate) fn build(self) -> Error {
        Error::Unimplemented {
            message: self.message,
            backtrace: Some(Backtrace::capture()),
        }
    }
}

pub(crate) struct UnsupportedSnafu {
    pub(crate) message: String,
}

impl UnsupportedSnafu {
    #[must_use]
    pub(crate) fn build(self) -> Error {
        Error::Unsupported {
            message: self.message,
            backtrace: Some(Backtrace::capture()),
        }
    }
}

macro_rules! unimplemented_err {
    ($e:expr) => {
        return Err($crate::errors::UnimplementedSnafu { message: $e.to_string() }.build())
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::UnimplementedSnafu { message: format!($fmt, $($arg)+)}.build())
    };
}

macro_rules! unsupported_err {
    ($e:expr) => {
        return Err($crate::errors::UnsupportedSnafu {
            message: $e.to_string(),
        }.build())
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::UnsupportedSnafu {
            message: format!($fmt, $($arg)+),
        }.build())
    };
}

macro_rules! bail {
    ($e:expr) => {
        return Err($crate::errors::Error::Message {
            message: $e.to_string(),
            backtrace: Some(::std::backtrace::Backtrace::capture()),
        })
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err($crate::errors::Error::Message {
            message: format!($fmt, $($arg)+),
            backtrace: Some(::std::backtrace::Backtrace::capture()),
        })
    };
}

macro_rules! format_err {
    ($e:expr) => {
        $crate::errors::Error::Message {
            message: $e.to_string(),
            backtrace: Some(::std::backtrace::Backtrace::capture()),
        }
    };
    ($fmt:expr, $($arg:tt)+) => {
        $crate::errors::Error::Message {
            message: format!($fmt, $($arg)+),
            backtrace: Some(::std::backtrace::Backtrace::capture()),
        }
    };
}

macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            $crate::errors::bail!($e);
        }
    };
    ($cond:expr, $fmt:expr, $($arg:tt)+) => {
        if !($cond) {
            $crate::errors::bail!($fmt, $($arg)+);
        }
    };
}

macro_rules! ensure_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    $crate::errors::bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`"#, left_val, right_val)
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::errors::ensure_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&($left), &($right)) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    $crate::errors::bail!(r#"assertion failed: `(left == right)`
  left: `{:?}`,
 right: `{:?}`: {}"#, left_val, right_val,
                           format_args!($($arg)+))
                }
            }
        }
    });
}

macro_rules! err_opt {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(err) => return Some(Err(err)),
        }
    };
}

pub(crate) use bail;
pub(crate) use ensure;
pub(crate) use ensure_eq;
pub(crate) use err_opt;
pub(crate) use format_err;
pub(crate) use unimplemented_err;
pub(crate) use unsupported_err;

#[cfg(test)]
mod tests {
    /// Check the size of the error enum
    ///
    /// Because clippy will start throwing warning if an enum gets above 128, we'd like to keep the
    /// size of the `Error` enum lower than that limit with some headroom to be wrapped by a
    /// downstream crate.
    ///
    /// If this test triggers, you should consider Box'ing the offending member.
    ///
    /// See: <https://rust-lang.github.io/rust-clippy/master/index.html#result_large_err>
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn size_of_error() {
        assert_eq!(core::mem::size_of::<super::Error>(), 80);
    }
}
