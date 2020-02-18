use secp256kfun::{marker::*, Point, Scalar};

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
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
