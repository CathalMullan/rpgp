use std::cmp::PartialEq;
use std::error::Error as StdError;

use rand::{CryptoRng, Rng};
use smallvec::SmallVec;

#[cfg(feature = "draft-pqc")]
use crate::crypto::{
    ml_dsa65_ed25519, ml_dsa87_ed448, ml_kem1024_x448, ml_kem768_x25519, slh_dsa_shake128f,
    slh_dsa_shake128s, slh_dsa_shake256s,
};
use crate::{
    composed::{KeyDetails, SignedSecretKey},
    crypto::{
        aead::AeadAlgorithm, dsa, ecc_curve::ECCCurve, ecdh, ecdsa, ed25519, ed448,
        hash::HashAlgorithm, public_key::PublicKeyAlgorithm, rsa, sym::SymmetricKeyAlgorithm,
        x25519, x448,
    },
    errors::Result,
    packet::{self, KeyFlags, PubKeyInner, UserAttribute, UserId},
    types::{
        self, CompressionAlgorithm, Password, PlainSecretParams, PublicParams, S2kParams, Timestamp,
    },
};

/// A type to set a configuration for the two key flags
/// "encrypt communications" and "encrypt storage".
///
/// <https://www.rfc-editor.org/rfc/rfc9580#name-key-flags>
#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptionCaps {
    #[default]
    None,
    Communication,
    Storage,
    All,
}

impl EncryptionCaps {
    fn is_communication(&self) -> bool {
        matches!(self, Self::Communication | Self::All)
    }

    fn is_storage(&self) -> bool {
        matches!(self, Self::Storage | Self::All)
    }
}

/// Parameters for the creation of a [`SignedSecretKey`]
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKeyParams {
    /// OpenPGP key version of primary
    version: types::KeyVersion,

    /// Asymmetric algorithm for the primary
    key_type: KeyType,

    // -- Keyflags for primary
    can_sign: bool,
    can_certify: bool,
    can_encrypt: EncryptionCaps,
    can_authenticate: bool,

    // -- Metadata for the primary key
    created_at: Timestamp,
    feature_seipd_v1: bool,
    feature_seipd_v2: bool,

    // -- Public-facing preferences on the certificate
    /// List of symmetric algorithms that indicate which algorithms the key holder prefers to use.
    preferred_symmetric_algorithms: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    /// List of hash algorithms that indicate which algorithms the key holder prefers to use.
    preferred_hash_algorithms: SmallVec<[HashAlgorithm; 8]>,
    /// List of compression algorithms that indicate which algorithms the key holder prefers to use.
    preferred_compression_algorithms: SmallVec<[CompressionAlgorithm; 8]>,
    /// List of AEAD algorithms that indicate which algorithms the key holder prefers to use.
    preferred_aead_algorithms: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,

    // -- Password-locking of the primary
    passphrase: Option<String>,
    s2k: Option<S2kParams>,

    // -- Packet framing for the primary key
    packet_version: types::PacketHeaderVersion,

    // -- Associated components
    /// Primary User ID, required for v4 keys, but not required for v6 keys
    primary_user_id: Option<String>,
    user_ids: Vec<String>,
    user_attributes: Vec<UserAttribute>,
    subkeys: Vec<SubkeyParams>,
}

/// Builder for [`SecretKeyParams`].
#[derive(Clone, Default)]
pub struct SecretKeyParamsBuilder {
    version: Option<types::KeyVersion>,
    key_type: Option<KeyType>,
    can_sign: Option<bool>,
    can_certify: Option<bool>,
    can_encrypt: Option<EncryptionCaps>,
    can_authenticate: Option<bool>,
    created_at: Option<Timestamp>,
    feature_seipd_v1: Option<bool>,
    feature_seipd_v2: Option<bool>,
    preferred_symmetric_algorithms: Option<SmallVec<[SymmetricKeyAlgorithm; 8]>>,
    preferred_hash_algorithms: Option<SmallVec<[HashAlgorithm; 8]>>,
    preferred_compression_algorithms: Option<SmallVec<[CompressionAlgorithm; 8]>>,
    preferred_aead_algorithms: Option<SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>>,
    passphrase: Option<Option<String>>,
    s2k: Option<Option<S2kParams>>,
    packet_version: Option<types::PacketHeaderVersion>,
    primary_user_id: Option<Option<String>>,
    user_ids: Option<Vec<String>>,
    user_attributes: Option<Vec<UserAttribute>>,
    subkeys: Option<Vec<SubkeyParams>>,
}

impl SecretKeyParamsBuilder {
    pub fn version(&mut self, value: types::KeyVersion) -> &mut Self {
        self.version = Some(value);
        self
    }

    pub fn key_type(&mut self, value: KeyType) -> &mut Self {
        self.key_type = Some(value);
        self
    }

    pub fn can_sign(&mut self, value: bool) -> &mut Self {
        self.can_sign = Some(value);
        self
    }

    pub fn can_certify(&mut self, value: bool) -> &mut Self {
        self.can_certify = Some(value);
        self
    }

    pub fn can_encrypt(&mut self, value: EncryptionCaps) -> &mut Self {
        self.can_encrypt = Some(value);
        self
    }

    pub fn can_authenticate(&mut self, value: bool) -> &mut Self {
        self.can_authenticate = Some(value);
        self
    }

    pub fn created_at(&mut self, value: Timestamp) -> &mut Self {
        self.created_at = Some(value);
        self
    }

    pub fn feature_seipd_v1(&mut self, value: bool) -> &mut Self {
        self.feature_seipd_v1 = Some(value);
        self
    }

    pub fn feature_seipd_v2(&mut self, value: bool) -> &mut Self {
        self.feature_seipd_v2 = Some(value);
        self
    }

    pub fn preferred_symmetric_algorithms(
        &mut self,
        value: SmallVec<[SymmetricKeyAlgorithm; 8]>,
    ) -> &mut Self {
        self.preferred_symmetric_algorithms = Some(value);
        self
    }

    pub fn preferred_hash_algorithms(&mut self, value: SmallVec<[HashAlgorithm; 8]>) -> &mut Self {
        self.preferred_hash_algorithms = Some(value);
        self
    }

    pub fn preferred_compression_algorithms(
        &mut self,
        value: SmallVec<[CompressionAlgorithm; 8]>,
    ) -> &mut Self {
        self.preferred_compression_algorithms = Some(value);
        self
    }

    pub fn preferred_aead_algorithms(
        &mut self,
        value: SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>,
    ) -> &mut Self {
        self.preferred_aead_algorithms = Some(value);
        self
    }

    pub fn passphrase(&mut self, value: Option<String>) -> &mut Self {
        self.passphrase = Some(value);
        self
    }

    pub fn s2k(&mut self, value: Option<S2kParams>) -> &mut Self {
        self.s2k = Some(value);
        self
    }

    pub fn packet_version(&mut self, value: types::PacketHeaderVersion) -> &mut Self {
        self.packet_version = Some(value);
        self
    }

    pub fn user_ids(&mut self, value: Vec<String>) -> &mut Self {
        self.user_ids = Some(value);
        self
    }

    pub fn user_attributes(&mut self, value: Vec<UserAttribute>) -> &mut Self {
        self.user_attributes = Some(value);
        self
    }

    pub fn subkeys(&mut self, value: Vec<SubkeyParams>) -> &mut Self {
        self.subkeys = Some(value);
        self
    }

    /// Builds a new [`SecretKeyParams`].
    pub fn build(&self) -> std::result::Result<SecretKeyParams, SecretKeyParamsBuilderError> {
        self.validate()?;

        let key_type = self
            .key_type
            .clone()
            .ok_or(SecretKeyParamsBuilderError::UninitializedField("key_type"))?;

        Ok(SecretKeyParams {
            version: self.version.unwrap_or_default(),
            key_type,
            can_sign: self.can_sign.unwrap_or_default(),
            can_certify: self.can_certify.unwrap_or_default(),
            can_encrypt: self.can_encrypt.unwrap_or_default(),
            can_authenticate: self.can_authenticate.unwrap_or_default(),
            created_at: self.created_at.unwrap_or_else(Timestamp::now),
            feature_seipd_v1: self.feature_seipd_v1.unwrap_or(true),
            feature_seipd_v2: self.feature_seipd_v2.unwrap_or_default(),
            preferred_symmetric_algorithms: self
                .preferred_symmetric_algorithms
                .clone()
                .unwrap_or_default(),
            preferred_hash_algorithms: self.preferred_hash_algorithms.clone().unwrap_or_default(),
            preferred_compression_algorithms: self
                .preferred_compression_algorithms
                .clone()
                .unwrap_or_default(),
            preferred_aead_algorithms: self.preferred_aead_algorithms.clone().unwrap_or_default(),
            passphrase: self.passphrase.clone().unwrap_or_default(),
            s2k: self.s2k.clone().unwrap_or_default(),
            packet_version: self.packet_version.unwrap_or_default(),
            primary_user_id: self.primary_user_id.clone().unwrap_or_default(),
            user_ids: self.user_ids.clone().unwrap_or_default(),
            user_attributes: self.user_attributes.clone().unwrap_or_default(),
            subkeys: self.subkeys.clone().unwrap_or_default(),
        })
    }
}

/// Parameters for the creation of a subkey
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubkeyParams {
    // -- OpenPGP key version of this subkey
    version: types::KeyVersion,

    // -- Asymmetric algorithm of this subkey
    key_type: KeyType,

    // -- Keyflags for this subkey
    can_sign: bool,
    can_encrypt: EncryptionCaps,
    can_authenticate: bool,

    // -- Metadata for the primary key
    created_at: Timestamp,

    // -- Password-locking of this subkey
    passphrase: Option<String>,
    s2k: Option<S2kParams>,

    // -- Packet framing for this subkey
    packet_version: types::PacketHeaderVersion,
}

/// Builder for [`SubkeyParams`].
#[derive(Clone, Default)]
pub struct SubkeyParamsBuilder {
    version: Option<types::KeyVersion>,
    key_type: Option<KeyType>,
    can_sign: Option<bool>,
    can_encrypt: Option<EncryptionCaps>,
    can_authenticate: Option<bool>,
    created_at: Option<Timestamp>,
    passphrase: Option<Option<String>>,
    s2k: Option<Option<S2kParams>>,
    packet_version: Option<types::PacketHeaderVersion>,
}

impl SubkeyParamsBuilder {
    pub fn version(&mut self, value: types::KeyVersion) -> &mut Self {
        self.version = Some(value);
        self
    }

    pub fn key_type(&mut self, value: KeyType) -> &mut Self {
        self.key_type = Some(value);
        self
    }

    pub fn can_sign(&mut self, value: bool) -> &mut Self {
        self.can_sign = Some(value);
        self
    }

    pub fn can_encrypt(&mut self, value: EncryptionCaps) -> &mut Self {
        self.can_encrypt = Some(value);
        self
    }

    pub fn can_authenticate(&mut self, value: bool) -> &mut Self {
        self.can_authenticate = Some(value);
        self
    }

    pub fn created_at(&mut self, value: Timestamp) -> &mut Self {
        self.created_at = Some(value);
        self
    }

    pub fn passphrase(&mut self, value: Option<String>) -> &mut Self {
        self.passphrase = Some(value);
        self
    }

    pub fn s2k(&mut self, value: Option<S2kParams>) -> &mut Self {
        self.s2k = Some(value);
        self
    }

    pub fn packet_version(&mut self, value: types::PacketHeaderVersion) -> &mut Self {
        self.packet_version = Some(value);
        self
    }

    /// Builds a new [`SubkeyParams`].
    pub fn build(&self) -> std::result::Result<SubkeyParams, SubkeyParamsBuilderError> {
        let key_type = self
            .key_type
            .clone()
            .ok_or(SubkeyParamsBuilderError::UninitializedField("key_type"))?;

        Ok(SubkeyParams {
            version: self.version.unwrap_or_default(),
            key_type,
            can_sign: self.can_sign.unwrap_or_default(),
            can_encrypt: self.can_encrypt.unwrap_or_default(),
            can_authenticate: self.can_authenticate.unwrap_or_default(),
            created_at: self.created_at.unwrap_or_else(Timestamp::now),
            passphrase: self.passphrase.clone().unwrap_or_default(),
            s2k: self.s2k.clone().unwrap_or_default(),
            packet_version: self.packet_version.unwrap_or_default(),
        })
    }
}

/// Error type for [`SecretKeyParamsBuilder`].
#[non_exhaustive]
#[derive(Debug)]
pub enum SecretKeyParamsBuilderError {
    /// Uninitialized field
    UninitializedField(&'static str),
    /// Custom validation error
    ValidationError(String),
}

impl From<String> for SecretKeyParamsBuilderError {
    fn from(value: String) -> Self {
        Self::ValidationError(value)
    }
}

impl core::fmt::Display for SecretKeyParamsBuilderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UninitializedField(field) => {
                write!(f, "`{field}` must be initialized")
            }
            Self::ValidationError(error) => {
                write!(f, "{error}")
            }
        }
    }
}

impl StdError for SecretKeyParamsBuilderError {}

/// Error type for [`SubkeyParamsBuilder`].
#[non_exhaustive]
#[derive(Debug)]
pub enum SubkeyParamsBuilderError {
    /// Uninitialized field
    UninitializedField(&'static str),
    /// Custom validation error
    ValidationError(String),
}

impl From<String> for SubkeyParamsBuilderError {
    fn from(value: String) -> Self {
        Self::ValidationError(value)
    }
}

impl core::fmt::Display for SubkeyParamsBuilderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UninitializedField(field) => {
                write!(f, "`{field}` must be initialized")
            }
            Self::ValidationError(error) => {
                write!(f, "{error}")
            }
        }
    }
}

impl StdError for SubkeyParamsBuilderError {}

impl SecretKeyParamsBuilder {
    fn validate_keytype(
        key_type: Option<&KeyType>,
        can_sign: Option<bool>,
        can_encrypt: EncryptionCaps,
        can_authenticate: Option<bool>,
    ) -> std::result::Result<(), String> {
        if let Some(key_type) = &key_type {
            if can_sign == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for signing keys"
                ));
            }
            if (can_encrypt == EncryptionCaps::All
                || can_encrypt == EncryptionCaps::Storage
                || can_encrypt == EncryptionCaps::Communication)
                && !key_type.can_encrypt()
            {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for encryption keys"
                ));
            }
            if can_authenticate == Some(true) && !key_type.can_sign() {
                return Err(format!(
                    "KeyType {key_type:?} can not be used for authentication keys"
                ));
            }

            match key_type {
                KeyType::Rsa(size) if *size < 2048 => {
                    return Err("Keys with less than 2048bits are considered insecure".into());
                }
                KeyType::Rsa(_) => {}
                KeyType::ECDSA(curve) => match curve {
                    ECCCurve::P256 | ECCCurve::P384 | ECCCurve::P521 | ECCCurve::Secp256k1 => {}
                    _ => return Err(format!("Curve {} is not supported for ECDSA", curve.name())),
                },
                _ => {}
            }
        }

        Ok(())
    }

    fn validate(&self) -> std::result::Result<(), String> {
        // Don't allow mixing of v4/v6 primary and subkeys
        match self.version {
            // V6 primary
            Some(types::KeyVersion::V6) => {
                // all subkeys must be v6
                for sub in self.subkeys.iter().flatten() {
                    if sub.version != types::KeyVersion::V6 {
                        return Err(format!(
                            "V6 primary key may not be combined with {:?} subkey",
                            sub.version
                        ));
                    }
                }
            }
            // non-V6 primary
            _ => {
                // subkeys may not be v6
                // (but v2/3/4 have been mixed historically, so we will let those slide)
                for sub in self.subkeys.iter().flatten() {
                    if sub.version == types::KeyVersion::V6 {
                        return Err(format!(
                            "{:?} primary key may not be combined with V6 subkey",
                            self.version
                        ));
                    }
                }
            }
        };

        Self::validate_keytype(
            self.key_type.as_ref(),
            self.can_sign,
            self.can_encrypt.unwrap_or_default(),
            self.can_authenticate,
        )?;

        if let Some(subkeys) = &self.subkeys {
            for subkey in subkeys {
                Self::validate_keytype(
                    Some(&subkey.key_type),
                    Some(subkey.can_sign),
                    subkey.can_encrypt,
                    Some(subkey.can_authenticate),
                )?;
            }
        }

        if self.version == Some(types::KeyVersion::V4) && self.primary_user_id.is_none() {
            return Err("V4 keys must have a primary User ID".into());
        }

        Ok(())
    }

    pub fn user_id<VALUE: Into<String>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut user_ids) = self.user_ids {
            user_ids.push(value.into());
        } else {
            self.user_ids = Some(vec![value.into()]);
        }
        self
    }

    pub fn subkey<VALUE: Into<SubkeyParams>>(&mut self, value: VALUE) -> &mut Self {
        if let Some(ref mut subkeys) = self.subkeys {
            subkeys.push(value.into());
        } else {
            self.subkeys = Some(vec![value.into()]);
        }
        self
    }

    pub fn primary_user_id(&mut self, value: String) -> &mut Self {
        self.primary_user_id = Some(Some(value));
        self
    }
}

impl SecretKeyParams {
    pub fn generate<R: Rng + CryptoRng>(self, mut rng: R) -> Result<SignedSecretKey> {
        let passphrase = self.passphrase;
        let s2k = self
            .s2k
            .unwrap_or_else(|| S2kParams::new_default(&mut rng, self.version));
        let (public_params, secret_params) = self.key_type.generate(&mut rng)?;
        let pub_key = PubKeyInner::new(
            self.version,
            self.key_type.to_alg(),
            self.created_at,
            None,
            public_params,
        )?;
        let primary_pub_key = crate::packet::PublicKey::from_inner(pub_key)?;
        let mut primary_key = packet::SecretKey::new(primary_pub_key.clone(), secret_params)?;

        let have_pw = passphrase.is_some();
        let key_pw = passphrase.map(Into::into).unwrap_or_else(Password::empty);

        if have_pw {
            primary_key.set_password_with_s2k(&key_pw, s2k)?;
        }

        let mut keyflags = KeyFlags::default();
        keyflags.set_certify(self.can_certify);
        keyflags.set_encrypt_comms(self.can_encrypt.is_communication());
        keyflags.set_encrypt_storage(self.can_encrypt.is_storage());
        keyflags.set_sign(self.can_sign);
        keyflags.set_authentication(self.can_authenticate);

        let primary_user_id = match self.primary_user_id {
            None => None,
            Some(id) => Some(UserId::from_str(Default::default(), id)?),
        };

        let mut features = packet::Features::default();
        if self.feature_seipd_v1 {
            features.set_seipd_v1(true);
        }
        if self.feature_seipd_v2 {
            features.set_seipd_v2(true);
        };

        let key = super::secret::RawSecretKey::new(
            primary_key,
            KeyDetails::new(
                primary_user_id,
                self.user_ids
                    .iter()
                    .map(|m| UserId::from_str(Default::default(), m))
                    .collect::<Result<Vec<_>, _>>()?,
                self.user_attributes,
                keyflags,
                features,
                self.preferred_symmetric_algorithms,
                self.preferred_hash_algorithms,
                self.preferred_compression_algorithms,
                self.preferred_aead_algorithms,
            ),
            Default::default(),
            self.subkeys
                .into_iter()
                .map(|subkey| {
                    let passphrase = subkey.passphrase;
                    let s2k = subkey
                        .s2k
                        .unwrap_or_else(|| S2kParams::new_default(&mut rng, subkey.version));
                    let (public_params, secret_params) = subkey.key_type.generate(&mut rng)?;
                    let mut keyflags = KeyFlags::default();
                    keyflags.set_encrypt_comms(subkey.can_encrypt.is_communication());
                    keyflags.set_encrypt_storage(subkey.can_encrypt.is_storage());
                    keyflags.set_sign(subkey.can_sign);
                    keyflags.set_authentication(subkey.can_authenticate);

                    let pub_key = PubKeyInner::new(
                        subkey.version,
                        subkey.key_type.to_alg(),
                        subkey.created_at,
                        None,
                        public_params,
                    )?;
                    let pub_key = packet::PublicSubkey::from_inner(pub_key)?;
                    let mut sub = packet::SecretSubkey::new(pub_key, secret_params)?;

                    // Produce embedded back signature for signing-capable subkeys
                    let embedded = if subkey.can_sign {
                        let backsig =
                            sub.sign_primary_key_binding(&mut rng, &primary_pub_key, &"".into())?;

                        Some(backsig)
                    } else {
                        None
                    };

                    if let Some(passphrase) = passphrase {
                        sub.set_password_with_s2k(&passphrase.as_str().into(), s2k)?;
                    }

                    Ok((sub, keyflags, embedded))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let signed = key.sign(rng, &key_pw)?;
        Ok(signed)
    }
}

/// Parameter to set the cipher of a key packet
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// Encryption & Signing with RSA and the given bitsize.
    Rsa(u32),
    /// Encrypting with ECDH
    ECDH(ECCCurve),
    /// Signing with Curve25519, legacy format (deprecated in RFC 9580)
    Ed25519Legacy,
    /// Signing with ECDSA
    ECDSA(ECCCurve),
    /// Signing with DSA for the given bitsize.
    Dsa(DsaKeySize),
    /// Signing with Ed25519
    Ed25519,
    /// Signing with Ed448
    Ed448,
    /// Encrypting with X25519
    X25519,
    /// Encrypting with X448
    X448,
    /// Encrypting using MlKem768-X25519
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519,
    /// Encrypting using MlKem1024-X25519
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448,
    /// Signing using ML DSA 65 ED25519
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519,
    /// Signing using ML DSA 87 ED448
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448,
    /// Signing with SLH DSA Shake 128s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s,
    /// Signing with SLH DSA Shake 128f
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f,
    /// Signing with SLH DSA Shake 256s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s,
}

/// DSA key size
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DsaKeySize {
    /// DSA parameter size constant: L = 1024, N = 160
    B1024 = 1024,
    /// DSA parameter size constant: L = 2048, N = 256
    B2048 = 2048,
    /// DSA parameter size constant: L = 3072, N = 256
    B3072 = 3072,
}

impl From<DsaKeySize> for dsa::KeySize {
    fn from(value: DsaKeySize) -> Self {
        match value {
            #[allow(deprecated)]
            DsaKeySize::B1024 => dsa::KeySize::DSA_1024_160,
            DsaKeySize::B2048 => dsa::KeySize::DSA_2048_256,
            DsaKeySize::B3072 => dsa::KeySize::DSA_3072_256,
        }
    }
}

impl KeyType {
    pub fn to_alg(&self) -> PublicKeyAlgorithm {
        match self {
            KeyType::Rsa(_) => PublicKeyAlgorithm::RSA,
            KeyType::ECDH(_) => PublicKeyAlgorithm::ECDH,
            KeyType::Ed25519Legacy => PublicKeyAlgorithm::EdDSALegacy,
            KeyType::ECDSA(_) => PublicKeyAlgorithm::ECDSA,
            KeyType::Dsa(_) => PublicKeyAlgorithm::DSA,
            KeyType::Ed25519 => PublicKeyAlgorithm::Ed25519,
            KeyType::Ed448 => PublicKeyAlgorithm::Ed448,
            KeyType::X25519 => PublicKeyAlgorithm::X25519,
            KeyType::X448 => PublicKeyAlgorithm::X448,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 => PublicKeyAlgorithm::MlKem768X25519,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem1024X448 => PublicKeyAlgorithm::MlKem1024X448,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519 => PublicKeyAlgorithm::MlDsa65Ed25519,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa87Ed448 => PublicKeyAlgorithm::MlDsa87Ed448,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128s => PublicKeyAlgorithm::SlhDsaShake128s,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128f => PublicKeyAlgorithm::SlhDsaShake128f,
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake256s => PublicKeyAlgorithm::SlhDsaShake256s,
        }
    }

    /// Does this asymmetric algorithm support the cryptographic primitive of encryption?
    /// (Note that this is a subtly different meaning from OpenPGP's key flags.)
    pub fn can_sign(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => true,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => false,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 | KeyType::MlKem1024X448 => false,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519
            | KeyType::MlDsa87Ed448
            | KeyType::SlhDsaShake128s
            | KeyType::SlhDsaShake128f
            | KeyType::SlhDsaShake256s => true,
        }
    }

    /// Does this asymmetric algorithm support the cryptographic primitive of encryption?
    /// (Note that this is a subtly different meaning from OpenPGP's key flags.)
    pub fn can_encrypt(&self) -> bool {
        match self {
            KeyType::Rsa(_) => true,

            KeyType::Dsa(_)
            | KeyType::ECDSA(_)
            | KeyType::Ed25519Legacy
            | KeyType::Ed25519
            | KeyType::Ed448 => false,
            KeyType::ECDH(_) | KeyType::X25519 | KeyType::X448 => true,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 | KeyType::MlKem1024X448 => true,
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519
            | KeyType::MlDsa87Ed448
            | KeyType::SlhDsaShake128s
            | KeyType::SlhDsaShake128f
            | KeyType::SlhDsaShake256s => false,
        }
    }

    pub fn generate<R: Rng + CryptoRng>(
        &self,
        rng: R,
    ) -> Result<(PublicParams, types::SecretParams)> {
        let (pub_params, plain) = match self {
            KeyType::Rsa(bit_size) => {
                let secret = rsa::SecretKey::generate(rng, *bit_size as usize)?;
                let public_params = PublicParams::RSA((&secret).into());
                let secret_params = PlainSecretParams::RSA(secret);
                (public_params, secret_params)
            }
            KeyType::ECDH(curve) => {
                let secret = ecdh::SecretKey::generate(rng, curve)?;
                let public_params = PublicParams::ECDH((&secret).into());
                let secret_params = PlainSecretParams::ECDH(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519Legacy => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::EdDSALegacy);
                let public_params = PublicParams::EdDSALegacy((&secret).into());
                let secret_params = PlainSecretParams::Ed25519Legacy(secret);
                (public_params, secret_params)
            }
            KeyType::ECDSA(curve) => {
                let secret = ecdsa::SecretKey::generate(rng, curve)?;
                let public_params = PublicParams::ECDSA(
                    (&secret).try_into().expect("must not generate unuspported"),
                );
                let secret_params = PlainSecretParams::ECDSA(secret);
                (public_params, secret_params)
            }
            KeyType::Dsa(key_size) => {
                let secret = dsa::SecretKey::generate(rng, (*key_size).into());
                let public_params = PublicParams::DSA((&secret).into());
                let secret_params = PlainSecretParams::DSA(secret);
                (public_params, secret_params)
            }
            KeyType::Ed25519 => {
                let secret = ed25519::SecretKey::generate(rng, ed25519::Mode::Ed25519);
                let public_params = PublicParams::Ed25519((&secret).into());
                let secret_params = PlainSecretParams::Ed25519(secret);
                (public_params, secret_params)
            }
            KeyType::Ed448 => {
                let secret = ed448::SecretKey::generate(rng);
                let public_params = PublicParams::Ed448((&secret).into());
                let secret_params = PlainSecretParams::Ed448(secret);
                (public_params, secret_params)
            }
            KeyType::X25519 => {
                let secret = x25519::SecretKey::generate(rng);
                let public_params = PublicParams::X25519((&secret).into());
                let secret_params = PlainSecretParams::X25519(secret);
                (public_params, secret_params)
            }
            KeyType::X448 => {
                let secret = x448::SecretKey::generate(rng);
                let public_params = PublicParams::X448((&secret).into());
                let secret_params = PlainSecretParams::X448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem768X25519 => {
                let secret = ml_kem768_x25519::SecretKey::generate(rng);
                let public_params = PublicParams::MlKem768X25519((&secret).into());
                let secret_params = PlainSecretParams::MlKem768X25519(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlKem1024X448 => {
                let secret = ml_kem1024_x448::SecretKey::generate(rng);
                let public_params = PublicParams::MlKem1024X448((&secret).into());
                let secret_params = PlainSecretParams::MlKem1024X448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa65Ed25519 => {
                let secret = ml_dsa65_ed25519::SecretKey::generate(rng);
                let public_params = PublicParams::MlDsa65Ed25519((&secret).into());
                let secret_params = PlainSecretParams::MlDsa65Ed25519(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::MlDsa87Ed448 => {
                let secret = ml_dsa87_ed448::SecretKey::generate(rng);
                let public_params = PublicParams::MlDsa87Ed448((&secret).into());
                let secret_params = PlainSecretParams::MlDsa87Ed448(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128s => {
                let secret = slh_dsa_shake128s::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake128s((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake128s(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake128f => {
                let secret = slh_dsa_shake128f::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake128f((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake128f(secret);
                (public_params, secret_params)
            }
            #[cfg(feature = "draft-pqc")]
            KeyType::SlhDsaShake256s => {
                let secret = slh_dsa_shake256s::SecretKey::generate(rng);
                let public_params = PublicParams::SlhDsaShake256s((&secret).into());
                let secret_params = PlainSecretParams::SlhDsaShake256s(secret);
                (public_params, secret_params)
            }
        };

        Ok((pub_params, types::SecretParams::Plain(plain)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use smallvec::smallvec;

    use super::*;
    use crate::{
        composed::{Deserializable, SignedPublicKey, SignedSecretKey},
        packet::Features,
        types::KeyVersion,
    };

    #[test]
    #[ignore] // slow in debug mode
    fn test_key_gen_rsa_2048_v4() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for i in 0..5 {
            println!("round {i}");
            gen_rsa_2048(&mut rng, KeyVersion::V4);
        }
    }

    #[test]
    #[ignore] // slow in debug mode
    fn test_key_gen_rsa_2048_v6() {
        let _ = pretty_env_logger::try_init();
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for i in 0..5 {
            println!("round {i}");
            gen_rsa_2048(&mut rng, KeyVersion::V6);
        }
    }

    fn gen_rsa_2048<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .version(version)
            .key_type(KeyType::Rsa(2048))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me <me@mail.com>".into())
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
                HashAlgorithm::Sha1,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ]);

        let key_params_enc = key_params
            .clone()
            .passphrase(Some("hello".into()))
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::Rsa(2048))
                    .passphrase(Some("hello".into()))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let signed_key_enc = key_params_enc
            .generate(&mut rng)
            .expect("failed to generate secret key, encrypted");

        let key_params_plain = key_params
            .passphrase(None)
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::Rsa(2048))
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let signed_key_plain = key_params_plain
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor_enc = signed_key_enc
            .to_armored_string(None.into())
            .expect("failed to serialize key");
        let armor_plain = signed_key_plain
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-rsa-enc.sec.asc", &armor_enc).unwrap();
        // std::fs::write("sample-rsa.sec.asc", &armor_plain).unwrap();

        let (signed_key2_enc, _headers) =
            SignedSecretKey::from_string(&armor_enc).expect("failed to parse key (enc)");
        signed_key2_enc
            .verify_bindings()
            .expect("invalid key (enc)");

        let (signed_key2_plain, _headers) =
            SignedSecretKey::from_string(&armor_plain).expect("failed to parse key (plain)");
        signed_key2_plain
            .verify_bindings()
            .expect("invalid key (plain)");

        signed_key2_enc
            .unlock(&"hello".into(), |_, _| Ok(()))
            .expect("failed to unlock parsed key (enc)")
            .unwrap();
        signed_key2_plain
            .unlock(&"".into(), |_, _| Ok(()))
            .expect("failed to unlock parsed key (plain)")
            .unwrap();

        assert_eq!(signed_key_plain, signed_key2_plain);

        let public_signed_key = signed_key_plain.to_public_key();
        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-rsa.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[ignore]
    #[test]
    fn key_gen_25519_legacy_long() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for i in 0..10_000 {
            println!("round {i}");
            gen_25519_legacy(&mut rng);
        }
    }

    #[test]
    fn key_gen_25519_legacy_short() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        for _ in 0..10 {
            gen_25519_legacy(&mut rng);
        }
    }

    fn gen_25519_legacy<R: Rng + CryptoRng>(mut rng: R) {
        // The v4-only key format variants based on Curve 25519 (EdDSALegacy/ECDH over 25519)

        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-25519-legacy@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-25519-legacy.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();
        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-25519-legacy.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[ignore]
    #[test]
    fn key_gen_25519_rfc9580_long() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {key_version:?}");

            for i in 0..10_000 {
                println!("round {i}");
                gen_25519_rfc9580(&mut rng, key_version);
            }
        }
    }

    #[test]
    fn key_gen_25519_rfc9580_short() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {key_version:?}");

            for _ in 0..10 {
                gen_25519_rfc9580(&mut rng, key_version);
            }
        }
    }

    fn gen_25519_rfc9580<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        // The RFC 9580 key format variants based on Curve 25519 (X25519/Ed25519)

        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-25519-rfc9580@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-25519-rfc9580.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();
        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-25519-rfc9580.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    fn gen_ecdsa_ecdh<R: Rng + CryptoRng>(
        mut rng: R,
        ecdsa: ECCCurve,
        ecdh: ECCCurve,
        version: KeyVersion,
    ) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::ECDSA(ecdsa.clone()))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-ecdsa@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::ECDH(ecdh.clone()))
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write(
        //     format!("sample-ecdsa-{ecdsa:?}-ecdh-{ecdh:?}.pub.asc"),
        //     &armor,
        // )
        // .unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write(
        //     format!("sample-ecdsa-{ecdsa:?}-ecdh-{ecdh:?}.pub.asc"),
        //     &armor,
        // )
        // .unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[test]
    fn key_gen_ecdsa_p256_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..=175 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P256, ECCCurve::P256, KeyVersion::V4);
        }
    }
    #[test]
    fn key_gen_ecdsa_p256_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..=175 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P256, ECCCurve::P256, KeyVersion::V6);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p384_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);
        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P384, ECCCurve::P384, KeyVersion::V4);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p384_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);
        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P384, ECCCurve::P384, KeyVersion::V6);
        }
    }

    #[test]
    #[ignore]
    fn key_gen_ecdsa_p521_v4() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P521, ECCCurve::P521, KeyVersion::V4);
        }
    }
    #[test]
    #[ignore]
    fn key_gen_ecdsa_p521_v6() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(&mut rng, ECCCurve::P521, ECCCurve::P521, KeyVersion::V6);
        }
    }

    #[test]
    fn key_gen_ecdsa_secp256k1() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..100 {
            gen_ecdsa_ecdh(
                &mut rng,
                ECCCurve::Secp256k1,
                ECCCurve::Curve25519, // we don't currently support ECDH over Secp256k1
                KeyVersion::V4,       // use of secp256k1 isn't specified in RFC 9580
            );
        }
    }

    fn gen_dsa<R: Rng + CryptoRng>(mut rng: R, key_size: DsaKeySize) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Dsa(key_size))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-dsa@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
                HashAlgorithm::Sha224,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-dsa.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write(format!("sample-dsa-{key_size:?}.pub.asc"), &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_1024() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..5 {
            gen_dsa(&mut rng, DsaKeySize::B1024);
        }
    }

    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_2048() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        for _ in 0..5 {
            gen_dsa(&mut rng, DsaKeySize::B2048);
        }
    }
    // Test is slow in debug mode
    #[test]
    #[ignore]
    fn key_gen_dsa_3072() {
        let mut rng = &mut ChaCha8Rng::seed_from_u64(0);

        gen_dsa(&mut rng, DsaKeySize::B3072);
    }

    #[ignore]
    #[test]
    fn key_gen_448_rfc9580_long() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {key_version:?}");

            for i in 0..100 {
                println!("round {i}");
                gen_448_rfc9580(&mut rng, key_version);
            }
        }
    }

    #[test]
    fn key_gen_448_rfc9580_short() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {key_version:?}");

            for _ in 0..10 {
                gen_448_rfc9580(&mut rng, key_version);
            }
        }
    }

    fn gen_448_rfc9580<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        // The RFC 9580 key format variants based on Curve 448 (X448/Ed448)

        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::Ed448)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-448-rfc9580@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![
                SymmetricKeyAlgorithm::AES256,
                SymmetricKeyAlgorithm::AES192,
                SymmetricKeyAlgorithm::AES128,
            ])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha3_512, HashAlgorithm::Sha512,])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::X448)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-448-rfc9580.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-448-rfc9580.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[test]
    fn signing_capable_subkey() {
        let _ = pretty_env_logger::try_init();

        let mut rng = ChaCha8Rng::seed_from_u64(0);

        let key_params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::Ed25519)
                    .can_sign(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_secret_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        // The signing capable subkey should have an embedded signature
        let subkey = signed_secret_key
            .secret_subkeys
            .first()
            .expect("signing subkey");
        let embedded = subkey
            .signatures
            .first()
            .expect("binding signature")
            .embedded_signature();
        assert!(embedded.is_some());

        embedded
            .unwrap()
            .verify_primary_key_binding(
                &subkey.key.public_key(),
                &signed_secret_key.primary_key.public_key(),
            )
            .expect("verify ok");

        let signed_public_key = signed_secret_key.to_public_key();

        // The signing capable subkey should have an embedded signature
        assert!(signed_public_key
            .public_subkeys
            .first()
            .expect("signing subkey")
            .signatures
            .first()
            .expect("binding signature")
            .embedded_signature()
            .is_some());

        signed_public_key
            .verify_bindings()
            .expect("invalid public key");
    }

    #[test]
    fn test_cert_metadata_gen_v4_v4() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        // legal v4 key, with user id
        let key_params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("alice".into())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V4)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        // We should have made no dks
        assert!(signed_key.details.direct_signatures.is_empty());

        // We made one user id
        assert_eq!(signed_key.details.users.len(), 1);
        let user = signed_key.details.users.first().unwrap();
        // .. it has one binding signature
        assert_eq!(user.signatures.len(), 1);
        let sig = user.signatures.first().unwrap();
        // ... key metadata is on that (primary user id binding) signature
        assert_eq!(sig.preferred_hash_algs(), &[HashAlgorithm::Sha512]);
        assert!(sig.key_flags().certify());
        assert!(sig.key_flags().sign());
        assert!(!sig.key_flags().encrypt_comms());
        assert!(!sig.key_flags().encrypt_storage());
        assert_eq!(sig.features(), Some(&Features::from(&[0x01][..])));

        // try making (signed) public key representations
        let _ = signed_key.public_key();
        let _ = signed_key.to_public_key();
    }

    #[test]
    fn test_cert_metadata_gen_v4_v4_no_uid() {
        // v4 key without primary user id - not legal
        let _ = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V4)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .expect_err("should not build because of missing primary user id");
    }

    #[test]
    fn test_cert_metadata_gen_v6_v4_illegal() {
        // illegal v6/v4 mix
        SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("alice".into())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V4)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .expect_err("should not be able to build");
    }

    #[test]
    fn test_cert_metadata_gen_v4_v6_illegal() {
        // illegal v4/v6 mix
        SecretKeyParamsBuilder::default()
            .version(KeyVersion::V4)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("alice".into())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .expect_err("should not be able to build");
    }

    #[test]
    fn test_cert_metadata_gen_v6_v6() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        // v6/v6 with user id
        let key_params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .feature_seipd_v2(true)
            .primary_user_id("alice".into())
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        // --- key metadata should be on dks
        // We made one dks
        assert_eq!(signed_key.details.direct_signatures.len(), 1);
        let sig = signed_key.details.direct_signatures.first().unwrap();
        // ... key metadata is on that dks signature
        assert_eq!(sig.preferred_hash_algs(), &[HashAlgorithm::Sha512]);
        assert!(sig.key_flags().certify());
        assert!(sig.key_flags().sign());
        assert!(!sig.key_flags().encrypt_comms());
        assert!(!sig.key_flags().encrypt_storage());
        assert_eq!(sig.features(), Some(&Features::from(&[0x09][..])));

        // - no key metadata should be on user id binding
        // We made one user id
        assert_eq!(signed_key.details.users.len(), 1);
        let user = signed_key.details.users.first().unwrap();
        // .. it has one binding signature
        assert_eq!(user.signatures.len(), 1);
        let sig = user.signatures.first().unwrap();
        // NO key metadata is on that (primary user id binding) signature
        assert_eq!(sig.preferred_hash_algs(), &[]);
        assert!(!sig.key_flags().certify());
        assert!(!sig.key_flags().sign());
        assert!(!sig.key_flags().encrypt_comms());
        assert!(!sig.key_flags().encrypt_storage());
        assert!(sig.features().is_none());

        // try making (signed) public key representations
        let _ = signed_key.public_key();
        let _ = signed_key.to_public_key();
    }

    #[test]
    fn test_cert_metadata_gen_v6_v6_id_less() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        // v6/v6 without user id
        // variation: this key doesn't want to do seipdv1 (in "features")
        let key_params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .feature_seipd_v1(false) // signal that we don't like seipdv1
            .feature_seipd_v2(true)
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![HashAlgorithm::Sha512])
            .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        // --- key metadata should be on dks
        // We made one dks
        assert_eq!(signed_key.details.direct_signatures.len(), 1);
        let sig = signed_key.details.direct_signatures.first().unwrap();
        // ... key metadata is on that dks signature
        assert_eq!(sig.preferred_hash_algs(), &[HashAlgorithm::Sha512]);
        assert!(sig.key_flags().certify());
        assert!(sig.key_flags().sign());
        assert!(!sig.key_flags().encrypt_comms());
        assert!(!sig.key_flags().encrypt_storage());
        assert_eq!(sig.features(), Some(&Features::from(&[0x08][..])));

        // We made no user id
        assert!(signed_key.details.users.is_empty());

        // try making (signed) public key representations
        let _ = signed_key.public_key();
        let _ = signed_key.to_public_key();
    }

    #[test]
    #[cfg(feature = "draft-pqc")]
    fn key_gen_ed25519_ml_kem_x25519() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V4, KeyVersion::V6] {
            println!("key version {key_version:?}");

            for _ in 0..10 {
                gen_ed25519_ml_kem_x25519(&mut rng, key_version);
            }
        }
    }
    #[cfg(feature = "draft-pqc")]
    fn gen_ed25519_ml_kem_x25519<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-ml-kem-x25519-rfc9580@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha3_512,
                HashAlgorithm::Sha512,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::MlKem768X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-448-rfc9580.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-448-rfc9580.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[test]
    #[cfg(feature = "draft-pqc")]
    fn key_gen_ed448_ml_kem_x448() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for key_version in [KeyVersion::V6] {
            println!("key version {key_version:?}");

            for _ in 0..10 {
                gen_ed448_ml_kem_x448(&mut rng, key_version);
            }
        }
    }
    #[cfg(feature = "draft-pqc")]
    fn gen_ed448_ml_kem_x448<R: Rng + CryptoRng>(mut rng: R, version: KeyVersion) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(KeyType::Ed448)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X <me-ml-kem-x448-rfc9580@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
            .preferred_hash_algorithms(smallvec![
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha3_512,
                HashAlgorithm::Sha512,
            ])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(KeyType::MlKem1024X448)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        // std::fs::write("sample-448-rfc9580.sec.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        // std::fs::write("sample-448-rfc9580.pub.asc", &armor).unwrap();

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }

    #[test]
    #[cfg(feature = "draft-pqc")]
    fn key_gen_ml_dsa_65_ed25519_ml_kem_x25519() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for _ in 0..10 {
            gen_key(
                &mut rng,
                KeyVersion::V6,
                KeyType::MlDsa65Ed25519,
                HashAlgorithm::Sha3_256,
                KeyType::MlKem768X25519,
            );
        }
    }

    #[test]
    #[cfg(feature = "draft-pqc")]
    fn key_ml_dsa_87_ed448_gen_ed448_ml_kem_x448() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        for _ in 0..10 {
            gen_key(
                &mut rng,
                KeyVersion::V6,
                KeyType::MlDsa87Ed448,
                HashAlgorithm::Sha3_512,
                KeyType::MlKem1024X448,
            );
        }
    }

    #[test]
    #[ignore]
    #[cfg(feature = "draft-pqc")]
    fn key_slh_dsa_128s_ml_kem_x25519() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        gen_key(
            &mut rng,
            KeyVersion::V6,
            KeyType::SlhDsaShake128s,
            HashAlgorithm::Sha3_256,
            KeyType::MlKem768X25519,
        );
    }

    #[test]
    #[cfg(feature = "draft-pqc")]
    fn key_slh_dsa_128f_ml_kem_x25519() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        gen_key(
            &mut rng,
            KeyVersion::V6,
            KeyType::SlhDsaShake128f,
            HashAlgorithm::Sha3_256,
            KeyType::MlKem768X25519,
        );
    }
    #[test]
    #[ignore]
    #[cfg(feature = "draft-pqc")]
    fn key_slh_dsa_256s_ml_kem_x448() {
        let mut rng = ChaCha8Rng::seed_from_u64(0);

        gen_key(
            &mut rng,
            KeyVersion::V6,
            KeyType::SlhDsaShake256s,
            HashAlgorithm::Sha3_512,
            KeyType::MlKem1024X448,
        );
    }

    #[cfg(feature = "draft-pqc")]
    fn gen_key<R: Rng + CryptoRng>(
        mut rng: R,
        version: KeyVersion,
        sign: KeyType,
        sign_hash: HashAlgorithm,
        encrypt: KeyType,
    ) {
        let _ = pretty_env_logger::try_init();

        let key_params = SecretKeyParamsBuilder::default()
            .version(version)
            .key_type(sign)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("Me-X me@mail.com>".into())
            .passphrase(None)
            .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
            .preferred_hash_algorithms(smallvec![sign_hash])
            .preferred_compression_algorithms(smallvec![
                CompressionAlgorithm::ZLIB,
                CompressionAlgorithm::ZIP,
            ])
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(version)
                    .key_type(encrypt)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        let signed_key = key_params
            .generate(&mut rng)
            .expect("failed to generate secret key");

        let armor = signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize key");

        let (signed_key2, _headers) =
            SignedSecretKey::from_string(&armor).expect("failed to parse key");
        signed_key2.verify_bindings().expect("invalid key");

        assert_eq!(signed_key, signed_key2);

        let public_signed_key = signed_key.to_public_key();

        public_signed_key
            .verify_bindings()
            .expect("invalid public key");

        let armor = public_signed_key
            .to_armored_string(None.into())
            .expect("failed to serialize public key");

        let (signed_key2, _headers) =
            SignedPublicKey::from_string(&armor).expect("failed to parse public key");
        signed_key2.verify_bindings().expect("invalid public key");
    }
}
