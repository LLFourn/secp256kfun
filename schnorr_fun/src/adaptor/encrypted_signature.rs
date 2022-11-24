use secp256kfun::{marker::*, Point, Scalar};

/// A one-time encrypted Schnorr signature or "adaptor signature".
///
/// Sometimes also called a "pre-signature".

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub struct EncryptedSignature<S = Public> {
    /// The `R` point in the signature
    pub R: Point<EvenY, Public>,
    /// The _one-time encrypted_ `s` value of the signature.
    pub s_hat: Scalar<S, Zero>,
    /// Whether the decryptor should negate their decryption key prior to decryption.
    /// This exists as a side effect of using "x-only" (EvenY) signature nonces.
    pub needs_negation: bool,
}

impl<OldSec> EncryptedSignature<OldSec> {
    /// Marks the encrypted signature with a [`Secrecy`]. If it is marked as `Secret` the operations
    /// (e.g. verification) on the signature encryption should be done in constant time.
    ///
    /// [`Secrecy`]: secp256kfun::marker::Secrecy
    #[must_use]
    pub fn set_secrecy<NewSec: Secrecy>(self) -> EncryptedSignature<NewSec> {
        EncryptedSignature {
            R: self.R,
            s_hat: self.s_hat.set_secrecy::<NewSec>(),
            needs_negation: self.needs_negation,
        }
    }
}

#[cfg(test)]
mod test {
    #[cfg(feature = "serde")]
    #[test]
    fn encrypted_signature_serialization_roundtrip() {
        use super::*;
        use crate::{adaptor::*, fun::Scalar, Message};
        let schnorr = crate::test_instance!();
        let kp = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let encryption_key = Point::random(&mut rand::thread_rng());
        let encrypted_signature = schnorr.encrypted_sign(
            &kp,
            &encryption_key,
            Message::<Public>::plain("test", b"foo"),
        );
        let serialized = bincode::serialize(&encrypted_signature).unwrap();
        assert_eq!(serialized.len(), 65);
        let deserialized = bincode::deserialize::<EncryptedSignature>(&serialized).unwrap();
        assert_eq!(encrypted_signature, deserialized);
    }
}
