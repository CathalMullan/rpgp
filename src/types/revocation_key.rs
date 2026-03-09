use std::fmt;

use num_enum::TryFromPrimitive;
use smallvec::SmallVec;

use crate::crypto::public_key::PublicKeyAlgorithm;

/// "Revocation key" signature subpacket (deprecated)
///
/// See <https://www.rfc-editor.org/rfc/rfc9580.html#name-revocation-key-deprecated>
///
/// This deprecated mechanism was intended to allow a specified key to issue revocations
/// for a key.
#[derive(PartialEq, Eq, Clone)]
pub struct RevocationKey {
    pub class: RevocationKeyClass,
    pub algorithm: PublicKeyAlgorithm,
    pub fingerprint: SmallVec<[u8; 20]>,
}

impl fmt::Debug for RevocationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationKey")
            .field("class", &self.class)
            .field("algorithm", &self.algorithm)
            .field(
                "fingerprint",
                &format_args!("{}", hex::encode(&self.fingerprint)),
            )
            .finish()
    }
}

/// "Class" setting for a [`RevocationKey`] subpacket (deprecated)
#[derive(Debug, PartialEq, Eq, Copy, Clone, TryFromPrimitive)]
#[repr(u8)]
pub enum RevocationKeyClass {
    Default = 0x80,
    Sensitive = 0x80 | 0x40,
}

impl RevocationKey {
    pub fn new(
        class: RevocationKeyClass,
        algorithm: PublicKeyAlgorithm,
        fingerprint: &[u8],
    ) -> Self {
        RevocationKey {
            class,
            algorithm,
            fingerprint: SmallVec::from_slice(fingerprint),
        }
    }
}
