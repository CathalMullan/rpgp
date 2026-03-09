use std::fmt;

use crate::zeroize::Zeroizing;

/// A type to unlock a secret key packet, or an
/// [SKESK packet](crate::packet::SymKeyEncryptedSessionKey).
///
/// Can contain either a callback or an explicit value.
pub enum Password {
    Dynamic(Box<dyn Fn() -> Zeroizing<Vec<u8>> + 'static + Send + Sync>),
    Static(Zeroizing<Vec<u8>>),
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dynamic(_callback) => f
                .debug_tuple("Dynamic")
                .field(&format_args!("Box<Fn>"))
                .finish(),
            Self::Static(_bytes) => f.debug_tuple("Static").field(&format_args!("***")).finish(),
        }
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self::Static(value.as_bytes().to_vec().into())
    }
}

impl From<&[u8]> for Password {
    fn from(value: &[u8]) -> Self {
        Self::Static(value.to_vec().into())
    }
}

impl Default for Password {
    fn default() -> Self {
        Self::empty()
    }
}

impl Password {
    /// Creates an empty password unlocker.
    pub fn empty() -> Self {
        Self::Static(Vec::new().into())
    }

    /// Executes the callback and returns the result.
    pub fn read(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Self::Dynamic(ref f) => f(),
            Self::Static(ref s) => s.clone(),
        }
    }
}

impl<F: Fn() -> Zeroizing<Vec<u8>> + 'static + Send + Sync> From<F> for Password {
    fn from(value: F) -> Self {
        Self::Dynamic(Box::new(value))
    }
}
