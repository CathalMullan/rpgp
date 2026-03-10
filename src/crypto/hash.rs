use std::error::Error as StdError;
use std::fmt;
use std::str::FromStr;

use digest::{Digest, DynDigest};
use md5::Md5;
use num_enum::{FromPrimitive, IntoPrimitive};
use ripemd::Ripemd160;
use sha1_checked::{CollisionResult, Sha1};

use super::checksum::Sha1HashCollision;

/// Available hash algorithms.
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-hash-algorithms>
#[derive(Debug, PartialEq, Eq, Copy, Clone, FromPrimitive, IntoPrimitive, Hash)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum HashAlgorithm {
    #[cfg_attr(test, proptest(skip))]
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Ripemd160 = 3,

    Sha256 = 8,
    Sha384 = 9,
    Sha512 = 10,
    Sha224 = 11,
    Sha3_256 = 12,
    Sha3_512 = 14,

    /// Do not use, just for compatibility with GnuPG.
    Private10 = 110,

    #[num_enum(catch_all)]
    Other(#[cfg_attr(test, proptest(strategy = "111u8.."))] u8),
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("NONE"),
            Self::Md5 => f.write_str("MD5"),
            Self::Sha1 => f.write_str("SHA1"),
            Self::Ripemd160 => f.write_str("RIPEMD160"),
            Self::Sha256 => f.write_str("SHA256"),
            Self::Sha384 => f.write_str("SHA384"),
            Self::Sha512 => f.write_str("SHA512"),
            Self::Sha224 => f.write_str("SHA224"),
            Self::Sha3_256 => f.write_str("SHA3-256"),
            Self::Sha3_512 => f.write_str("SHA3-512"),
            Self::Private10 => f.write_str("Private10"),
            Self::Other(value) => write!(f, "{}", value),
        }
    }
}

/// Marker trait for supported hash algorithms
pub trait KnownDigest: Digest {
    const HASH_ALGORITHM: HashAlgorithm;
}

impl KnownDigest for md5::Md5 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Md5;
}
impl KnownDigest for sha1_checked::Sha1 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha1;
}
impl KnownDigest for Ripemd160 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Ripemd160;
}
impl KnownDigest for sha2::Sha256 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha256;
}
impl KnownDigest for sha2::Sha384 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha384;
}
impl KnownDigest for sha2::Sha512 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha512;
}
impl KnownDigest for sha3::Sha3_256 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha3_256;
}
impl KnownDigest for sha3::Sha3_512 {
    const HASH_ALGORITHM: HashAlgorithm = HashAlgorithm::Sha3_512;
}

impl FromStr for HashAlgorithm {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "md5" => Ok(Self::Md5),
            "sha1" => Ok(Self::Sha1),
            "ripemd160" => Ok(Self::Ripemd160),
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            "sha224" => Ok(Self::Sha224),
            "sha3-256" => Ok(Self::Sha3_256),
            "sha3-512" => Ok(Self::Sha3_512),
            "private10" => Ok(Self::Private10),
            _ => Err(()),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

impl HashAlgorithm {
    /// V6 signature salt size
    /// <https://www.rfc-editor.org/rfc/rfc9580.html#hash-algos>
    pub const fn salt_len(&self) -> Option<usize> {
        match self {
            Self::Sha224 => Some(16),
            Self::Sha256 => Some(16),
            Self::Sha384 => Some(24),
            Self::Sha512 => Some(32),
            Self::Sha3_256 => Some(16),
            Self::Sha3_512 => Some(32),
            _ => None,
        }
    }
}

/// Temporary wrapper around `Box<dyn DynDigest>` to implement `io::Write`.
pub(crate) struct WriteHasher<'a>(pub(crate) &'a mut Box<dyn DynDigest + Send>);

impl std::io::Write for WriteHasher<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let digest = &mut **self.0;
        DynDigest::update(digest, buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Unsupported { alg: HashAlgorithm },
    Sha1HashCollision { source: Sha1HashCollision },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { alg } => write!(f, "unsupported {:?}", alg),
            Self::Sha1HashCollision { source } => fmt::Display::fmt(source, f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Unsupported { .. } => None,
            Self::Sha1HashCollision { source } => source.source(),
        }
    }
}

impl From<Sha1HashCollision> for Error {
    fn from(source: Sha1HashCollision) -> Self {
        Self::Sha1HashCollision { source }
    }
}

struct UnsupportedSnafu {
    alg: HashAlgorithm,
}

impl UnsupportedSnafu {
    #[must_use]
    fn build(self) -> Error {
        Error::Unsupported { alg: self.alg }
    }
}

impl HashAlgorithm {
    /// Create a new hasher.
    pub fn new_hasher(self) -> Result<Box<dyn DynDigest + Send>, Error> {
        match self {
            HashAlgorithm::Md5 => Ok(Box::<Md5>::default()),
            HashAlgorithm::Sha1 => Ok(Box::<Sha1>::default()),
            HashAlgorithm::Ripemd160 => Ok(Box::<Ripemd160>::default()),
            HashAlgorithm::Sha256 => Ok(Box::<sha2::Sha256>::default()),
            HashAlgorithm::Sha384 => Ok(Box::<sha2::Sha384>::default()),
            HashAlgorithm::Sha512 => Ok(Box::<sha2::Sha512>::default()),
            HashAlgorithm::Sha224 => Ok(Box::<sha2::Sha224>::default()),
            HashAlgorithm::Sha3_256 => Ok(Box::<sha3::Sha3_256>::default()),
            HashAlgorithm::Sha3_512 => Ok(Box::<sha3::Sha3_512>::default()),
            _ => Err(UnsupportedSnafu { alg: self }.build()),
        }
    }

    /// Calculate the digest of the given input data.
    pub fn digest(self, data: &[u8]) -> Result<Vec<u8>, Error> {
        use digest::Digest;

        let res = match self {
            HashAlgorithm::Md5 => Md5::digest(data).to_vec(),
            HashAlgorithm::Sha1 => match Sha1::try_digest(data) {
                CollisionResult::Ok(output) => output.to_vec(),
                CollisionResult::Collision(_) | CollisionResult::Mitigated(_) => {
                    return Err(Sha1HashCollision.into());
                }
            },
            HashAlgorithm::Ripemd160 => Ripemd160::digest(data).to_vec(),
            HashAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
            HashAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
            HashAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
            HashAlgorithm::Sha224 => sha2::Sha224::digest(data).to_vec(),
            HashAlgorithm::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            HashAlgorithm::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
            _ => return Err(UnsupportedSnafu { alg: self }.build()),
        };
        Ok(res)
    }

    /// Returns the expected digest size for the given algorithm.
    pub fn digest_size(self) -> Option<usize> {
        use digest::Digest;

        let size = match self {
            HashAlgorithm::Md5 => <Md5 as Digest>::output_size(),
            HashAlgorithm::Sha1 => <Sha1 as Digest>::output_size(),
            HashAlgorithm::Ripemd160 => <Ripemd160 as Digest>::output_size(),
            HashAlgorithm::Sha256 => <sha2::Sha256 as Digest>::output_size(),
            HashAlgorithm::Sha384 => <sha2::Sha384 as Digest>::output_size(),
            HashAlgorithm::Sha512 => <sha2::Sha512 as Digest>::output_size(),
            HashAlgorithm::Sha224 => <sha2::Sha224 as Digest>::output_size(),
            HashAlgorithm::Sha3_256 => <sha3::Sha3_256 as Digest>::output_size(),
            HashAlgorithm::Sha3_512 => <sha3::Sha3_512 as Digest>::output_size(),
            _ => return None,
        };
        Some(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_parse_hash() {
        assert_eq!(HashAlgorithm::None.to_string(), "NONE".to_string());

        assert_eq!(HashAlgorithm::Sha256.to_string(), "SHA256".to_string());

        assert_eq!(HashAlgorithm::Sha3_512, "SHA3-512".parse().unwrap());
    }
}
