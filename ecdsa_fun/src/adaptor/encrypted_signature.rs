use super::dleq;
use secp256kfun::{marker::*, Point, Scalar};
#[derive(Debug, Clone)]
/// PointNonce is a NonZero Point that also has an x-coordinate that is NonZero
/// when reduced modulo the curve order.
pub struct PointNonce<S = Public> {
    pub point: Point<Normal, S>,
    pub(crate) x_scalar: Scalar<S, NonZero>,
}

#[derive(Debug, Clone)]
pub struct EncryptedSignature<S = Public> {
    pub R: PointNonce<S>,
    pub R_hat: Point<Normal, S>,
    pub s_hat: Scalar<S, NonZero>,
    pub proof: dleq::Proof,
}
