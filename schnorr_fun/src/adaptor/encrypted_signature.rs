use secp256kfun::{marker::*, Point, Scalar};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct EncryptedSignature<S = Public> {
    pub R: Point<SquareY, Public, NonZero>,
    pub s_hat: Scalar<S, Zero>,
    pub needs_negation: bool,
}

impl<OldSec> EncryptedSignature<OldSec> {
    #[must_use]
    pub fn mark<NewSec: Secrecy>(self) -> EncryptedSignature<NewSec> {
        EncryptedSignature {
            R: self.R,
            s_hat: self.s_hat.mark::<NewSec>(),
            needs_negation: self.needs_negation,
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "serialization")]
    #[test]
    fn encrypted_signature_serialization_roundtrip() {
        use super::*;
        use crate::{
            adaptor::*,
            secp256kfun::{hash::Derivation, Scalar},
            Schnorr,
        };
        let schnorr = Schnorr::from_tag(b"test");
        let kp = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let encryption_key = Point::random(&mut rand::thread_rng());
        let encrypted_signature =
            schnorr.encrypted_sign(&kp, &encryption_key, b"test", Derivation::Deterministic);
        let serialized = bincode::serialize(&encrypted_signature).unwrap();
        assert_eq!(serialized.len(), 65);
        let deserialized = bincode::deserialize::<EncryptedSignature>(&serialized).unwrap();
        assert_eq!(encrypted_signature, deserialized);
    }
}
