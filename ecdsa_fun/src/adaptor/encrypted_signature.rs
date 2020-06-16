use super::dleq;
use crate::fun::{marker::*, Point, Scalar};

/// `PointNonce` is a [`NonZero`] Point that also has an x-coordinate that is NonZero
/// when reduced modulo the curve order.
///
/// [`NonZero`]: secp256kfun::marker::NonZero
#[derive(Clone, PartialEq)]
pub struct PointNonce<S = Public> {
    pub point: Point<Normal, S>,
    pub(crate) x_scalar: Scalar<S, NonZero>,
}

secp256kfun::impl_fromstr_deserailize! {
    name => "33-byte compressed secp256k1 point",
    fn from_bytes<S>(bytes: [u8;33]) -> Option<PointNonce<S>> {
        Point::from_bytes(bytes).and_then(|point| {
            let point = point.set_secrecy::<S>();
            Scalar::from_bytes_mod_order(point.to_xonly().into_bytes()).set_secrecy::<S>()
                .mark::<NonZero>().map(move |x_scalar| PointNonce { point, x_scalar } )
        })
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes<S>(point_nonce: &PointNonce<S>) -> [u8;33] {
        point_nonce.point.to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct EncryptedSignature<S = Public> {
    pub R: PointNonce<S>,
    pub R_hat: Point<Normal, S>,
    pub s_hat: Scalar<S, NonZero>,
    pub proof: dleq::Proof,
}

#[cfg(test)]
mod test {

    #[cfg(feature = "serialization")]
    #[test]
    fn encrypted_signature_serde_roundtrip() {
        use super::*;
        use crate::fun::hash::Derivation;
        let adaptor = crate::adaptor::Adaptor::from_tag(b"test");
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let encryption_key = Point::random(&mut rand::thread_rng());
        let encrypted_signature = adaptor.encrypted_sign(
            &secret_key,
            &encryption_key,
            b"hello world you are beautiful!!!",
            Derivation::Deterministic,
        );
        let serialized = bincode::serialize(&encrypted_signature).unwrap();
        assert_eq!(serialized.len(), 33 + 33 + 32 + 64);
        let deseriazed = bincode::deserialize::<EncryptedSignature>(&serialized[..]).unwrap();

        assert_eq!(deseriazed, encrypted_signature);
    }
}
