use std::fmt;
use std::io::{self, BufRead};

use cx448::x448;
use ml_kem::{kem::EncapsulationKey, EncodedSizeUser, MlKem1024Params};

use crate::{
    errors::{format_err, Result},
    parsing_reader::BufReadParsing,
    ser::Serialize,
};

const ML_KEM_PUB_KEY_LENGTH: usize = 1568;
const X448_PUB_KEY_LENGTH: usize = 56;

#[derive(PartialEq, Clone)]
pub struct MlKem1024X448PublicParams {
    pub x448_key: x448::PublicKey,
    pub ml_kem_key: Box<EncapsulationKey<MlKem1024Params>>,
}

impl fmt::Debug for MlKem1024X448PublicParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem1024X448PublicParams")
            .field(
                "x448_key",
                &format_args!("{}", hex::encode(self.x448_key.as_bytes())),
            )
            .field(
                "ml_kem_key",
                &format_args!("{}", hex::encode(self.ml_kem_key.as_bytes())),
            )
            .finish()
    }
}

impl Eq for MlKem1024X448PublicParams {}

impl MlKem1024X448PublicParams {
    pub fn try_from_reader<B: BufRead>(mut i: B) -> Result<Self> {
        let x448_public_raw = i.read_arr::<{ X448_PUB_KEY_LENGTH }>()?;

        let ml_kem_raw = i.read_arr::<ML_KEM_PUB_KEY_LENGTH>()?;
        let ml_kem_key = EncapsulationKey::from_bytes(&ml_kem_raw.into());

        Ok(Self {
            x448_key: x448::PublicKey::from_bytes(&x448_public_raw)
                .ok_or_else(|| format_err!("invalid x448 public key"))?,
            ml_kem_key: Box::new(ml_kem_key),
        })
    }
}

impl Serialize for MlKem1024X448PublicParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.x448_key.as_bytes())?;
        writer.write_all(&self.ml_kem_key.as_bytes())?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        X448_PUB_KEY_LENGTH + ML_KEM_PUB_KEY_LENGTH
    }
}

#[cfg(test)]
mod tests {
    use ml_kem::{KemCore, MlKem1024};
    use proptest::prelude::*;
    use rand::SeedableRng;

    use super::*;

    impl Arbitrary for MlKem1024X448PublicParams {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            fn from_seed(seed: u64) -> MlKem1024X448PublicParams {
                let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed);

                let x = x448::Secret::new(&mut rng);
                let (_, ml) = MlKem1024::generate(&mut rng);

                MlKem1024X448PublicParams {
                    x448_key: (&x).into(),
                    ml_kem_key: Box::new(ml),
                }
            }

            (1..=u64::MAX).prop_map(from_seed).boxed()
        }
    }

    proptest! {
        #[test]
        fn params_write_len(params: MlKem1024X448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            prop_assert_eq!(buf.len(), params.write_len());
        }

        #[test]
        fn params_roundtrip(params: MlKem1024X448PublicParams) {
            let mut buf = Vec::new();
            params.to_writer(&mut buf)?;
            let new_params = MlKem1024X448PublicParams::try_from_reader(&mut &buf[..])?;
            prop_assert_eq!(params, new_params);
        }
    }
}
