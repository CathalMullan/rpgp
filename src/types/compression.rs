/// Available compression algorithms.
///
/// Ref: <https://www.rfc-editor.org/rfc/rfc9580.html#name-compression-algorithms>
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[non_exhaustive]
pub enum CompressionAlgorithm {
    Uncompressed = 0,
    ZIP = 1,
    ZLIB = 2,
    BZip2 = 3,
    /// Do not use, just for compatibility with GnuPG.
    #[cfg_attr(test, proptest(skip))] // not supported
    Private10 = 110,

    #[cfg_attr(test, proptest(skip))] // not supported
    Other(u8),
}

impl From<u8> for CompressionAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0 => CompressionAlgorithm::Uncompressed,
            1 => CompressionAlgorithm::ZIP,
            2 => CompressionAlgorithm::ZLIB,
            3 => CompressionAlgorithm::BZip2,
            110 => CompressionAlgorithm::Private10,
            other => CompressionAlgorithm::Other(other),
        }
    }
}

impl From<CompressionAlgorithm> for u8 {
    fn from(value: CompressionAlgorithm) -> Self {
        match value {
            CompressionAlgorithm::Uncompressed => 0,
            CompressionAlgorithm::ZIP => 1,
            CompressionAlgorithm::ZLIB => 2,
            CompressionAlgorithm::BZip2 => 3,
            CompressionAlgorithm::Private10 => 110,
            CompressionAlgorithm::Other(other) => other,
        }
    }
}
