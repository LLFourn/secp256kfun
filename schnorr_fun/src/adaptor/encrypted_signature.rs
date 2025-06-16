use secp256kfun::{Point, Scalar, marker::*};

/// A one-time encrypted Schnorr signature or "adaptor signature".
///
/// Sometimes also called a "pre-signature".

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
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
        use crate::{Message, adaptor::*, fun::Scalar};
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let kp = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let encryption_key = Point::random(&mut rand::thread_rng());
        let encrypted_signature = schnorr.encrypted_sign(
            &kp,
            &encryption_key,
            Message::<Public>::plain("test", b"foo"),
        );
        let serialized = bincode::encode_to_vec(
            bincode::serde::Compat(&encrypted_signature),
            bincode::config::standard(),
        )
        .unwrap();
        assert_eq!(serialized.len(), 65);
        let deserialized = bincode::decode_from_slice::<
            bincode::serde::Compat<EncryptedSignature>,
            _,
        >(&serialized, bincode::config::standard())
        .unwrap()
        .0;
        assert_eq!(encrypted_signature, deserialized.0);
    }
}
