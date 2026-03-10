#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(proptest_derive::Arbitrary))]
#[repr(u8)]
#[non_exhaustive]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt and Sign)
    RSA = 1,
    /// DEPRECATED: RSA (Encrypt-Only)
    RSAEncrypt = 2,
    /// DEPRECATED: RSA (Sign-Only)
    RSASign = 3,
    /// Elgamal (Encrypt-Only)
    #[cfg_attr(test, proptest(skip))]
    ElgamalEncrypt = 16,
    /// DSA (Digital Signature Algorithm)
    DSA = 17,
    /// Elliptic Curve: RFC 9580 [formerly in RFC 6637]
    ECDH = 18,
    /// ECDSA: RFC 9580 [formerly in RFC 6637]
    ECDSA = 19,
    /// DEPRECATED: Elgamal (Encrypt and Sign)
    #[cfg_attr(test, proptest(skip))]
    Elgamal = 20,
    /// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    #[cfg_attr(test, proptest(skip))]
    DiffieHellman = 21,
    /// EdDSA legacy format [deprecated in RFC 9580, superseded by Ed25519 (27)]
    EdDSALegacy = 22,
    /// X25519 [RFC 9580]
    X25519 = 25,
    /// X448 [RFC 9580]
    X448 = 26,
    /// Ed25519 [RFC 9580]
    Ed25519 = 27,
    /// Ed448 [RFC 9580]
    Ed448 = 28,

    /// ML-DSA-65+Ed25519
    #[cfg(feature = "draft-pqc")]
    MlDsa65Ed25519 = 30,
    /// ML-DSA-87+Ed448
    #[cfg(feature = "draft-pqc")]
    MlDsa87Ed448 = 31,

    /// SLH-DSA-SHAKE-128s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128s = 32,
    /// SLH-DSA-SHAKE-128f
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake128f = 33,
    /// SLH-DSA-SHAKE-256s
    #[cfg(feature = "draft-pqc")]
    SlhDsaShake256s = 34,

    /// ML-KEM-768+X25519
    #[cfg(feature = "draft-pqc")]
    MlKem768X25519 = 35,
    /// ML-KEM-1024+X448
    #[cfg(feature = "draft-pqc")]
    MlKem1024X448 = 36,

    /// Private experimental range (from OpenPGP)
    #[cfg_attr(test, proptest(skip))]
    Private100 = 100,
    #[cfg_attr(test, proptest(skip))]
    Private101 = 101,
    #[cfg_attr(test, proptest(skip))]
    Private102 = 102,
    #[cfg_attr(test, proptest(skip))]
    Private103 = 103,
    #[cfg_attr(test, proptest(skip))]
    Private104 = 104,
    #[cfg_attr(test, proptest(skip))]
    Private105 = 105,
    #[cfg_attr(test, proptest(skip))]
    Private106 = 106,
    #[cfg_attr(test, proptest(skip))]
    Private107 = 107,
    #[cfg_attr(test, proptest(skip))]
    Private108 = 108,
    #[cfg_attr(test, proptest(skip))]
    Private109 = 109,
    #[cfg_attr(test, proptest(skip))]
    Private110 = 110,

    #[cfg_attr(test, proptest(skip))]
    Unknown(u8),
}

impl From<u8> for PublicKeyAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::RSA,
            2 => Self::RSAEncrypt,
            3 => Self::RSASign,
            16 => Self::ElgamalEncrypt,
            17 => Self::DSA,
            18 => Self::ECDH,
            19 => Self::ECDSA,
            20 => Self::Elgamal,
            21 => Self::DiffieHellman,
            22 => Self::EdDSALegacy,
            25 => Self::X25519,
            26 => Self::X448,
            27 => Self::Ed25519,
            28 => Self::Ed448,
            #[cfg(feature = "draft-pqc")]
            30 => Self::MlDsa65Ed25519,
            #[cfg(feature = "draft-pqc")]
            31 => Self::MlDsa87Ed448,
            #[cfg(feature = "draft-pqc")]
            32 => Self::SlhDsaShake128s,
            #[cfg(feature = "draft-pqc")]
            33 => Self::SlhDsaShake128f,
            #[cfg(feature = "draft-pqc")]
            34 => Self::SlhDsaShake256s,
            #[cfg(feature = "draft-pqc")]
            35 => Self::MlKem768X25519,
            #[cfg(feature = "draft-pqc")]
            36 => Self::MlKem1024X448,
            100 => Self::Private100,
            101 => Self::Private101,
            102 => Self::Private102,
            103 => Self::Private103,
            104 => Self::Private104,
            105 => Self::Private105,
            106 => Self::Private106,
            107 => Self::Private107,
            108 => Self::Private108,
            109 => Self::Private109,
            110 => Self::Private110,
            other => Self::Unknown(other),
        }
    }
}

impl From<PublicKeyAlgorithm> for u8 {
    fn from(value: PublicKeyAlgorithm) -> Self {
        match value {
            PublicKeyAlgorithm::RSA => 1,
            PublicKeyAlgorithm::RSAEncrypt => 2,
            PublicKeyAlgorithm::RSASign => 3,
            PublicKeyAlgorithm::ElgamalEncrypt => 16,
            PublicKeyAlgorithm::DSA => 17,
            PublicKeyAlgorithm::ECDH => 18,
            PublicKeyAlgorithm::ECDSA => 19,
            PublicKeyAlgorithm::Elgamal => 20,
            PublicKeyAlgorithm::DiffieHellman => 21,
            PublicKeyAlgorithm::EdDSALegacy => 22,
            PublicKeyAlgorithm::X25519 => 25,
            PublicKeyAlgorithm::X448 => 26,
            PublicKeyAlgorithm::Ed25519 => 27,
            PublicKeyAlgorithm::Ed448 => 28,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlDsa65Ed25519 => 30,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlDsa87Ed448 => 31,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake128s => 32,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake128f => 33,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::SlhDsaShake256s => 34,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlKem768X25519 => 35,
            #[cfg(feature = "draft-pqc")]
            PublicKeyAlgorithm::MlKem1024X448 => 36,
            PublicKeyAlgorithm::Private100 => 100,
            PublicKeyAlgorithm::Private101 => 101,
            PublicKeyAlgorithm::Private102 => 102,
            PublicKeyAlgorithm::Private103 => 103,
            PublicKeyAlgorithm::Private104 => 104,
            PublicKeyAlgorithm::Private105 => 105,
            PublicKeyAlgorithm::Private106 => 106,
            PublicKeyAlgorithm::Private107 => 107,
            PublicKeyAlgorithm::Private108 => 108,
            PublicKeyAlgorithm::Private109 => 109,
            PublicKeyAlgorithm::Private110 => 110,
            PublicKeyAlgorithm::Unknown(other) => other,
        }
    }
}

impl PublicKeyAlgorithm {
    /// true if the algorithm uses a post-quantum cryptographic scheme
    /// (and can thus provide post-quantum security)
    pub fn is_pqc(&self) -> bool {
        match self {
            #[cfg(feature = "draft-pqc")]
            Self::MlDsa65Ed25519
            | Self::MlDsa87Ed448
            | Self::SlhDsaShake128s
            | Self::SlhDsaShake128f
            | Self::SlhDsaShake256s
            | Self::MlKem768X25519
            | Self::MlKem1024X448 => true,

            _ => false,
        }
    }

    /// Can this algorithm sign data?
    pub fn can_sign(self) -> bool {
        use PublicKeyAlgorithm::*;

        #[cfg(feature = "draft-pqc")]
        if matches!(
            self,
            MlDsa65Ed25519 | MlDsa87Ed448 | SlhDsaShake128s | SlhDsaShake128f | SlhDsaShake256s
        ) {
            return true;
        }

        matches!(
            self,
            RSA | RSASign | Elgamal | DSA | ECDSA | EdDSALegacy | Ed25519 | Ed448
        )
    }

    /// Can this algorithm encrypt data?
    pub fn can_encrypt(self) -> bool {
        use PublicKeyAlgorithm::*;

        #[cfg(feature = "draft-pqc")]
        if matches!(self, MlKem768X25519 | MlKem1024X448) {
            return true;
        }

        matches!(
            self,
            RSA | RSAEncrypt | ECDH | DiffieHellman | Elgamal | ElgamalEncrypt | X25519 | X448
        )
    }
}
