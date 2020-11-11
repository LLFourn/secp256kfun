use super::DLEQ;
use crate::fun::{marker::*, Point, Scalar};
use sigma_fun::CompactProof;

/// `PointNonce` is a [`NonZero`] Point that also has an x-coordinate that is NonZero
/// when reduced modulo the curve order.
///
/// [`NonZero`]: secp256kfun::marker::NonZero
#[derive(Clone, PartialEq)]
pub struct PointNonce {
    pub point: Point,
    pub(crate) x_scalar: Scalar<Public>,
}

secp256kfun::impl_fromstr_deserailize! {
    name => "33-byte compressed secp256k1 point",
    fn from_bytes(bytes: [u8;33]) -> Option<PointNonce> {
        Point::from_bytes(bytes).and_then(|point| {
            Scalar::from_bytes_mod_order(point.to_xonly().into_bytes()).mark::<Public>()
                .mark::<NonZero>().map(move |x_scalar| PointNonce { point, x_scalar } )
        })
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(point_nonce: &PointNonce) -> [u8;33] {
        point_nonce.point.to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct EncryptedSignature {
    pub R: PointNonce,
    pub R_hat: Point,
    pub s_hat: Scalar<Public>,
    pub proof: CompactProof<DLEQ>,
}

#[cfg(test)]
mod test {

    #[cfg(feature = "serde")]
    #[test]
    fn encrypted_signature_serde_roundtrip() {
        use super::*;
        use crate::{adaptor::Adaptor, fun::nonce};
        use rand::rngs::ThreadRng;
        use sha2::Sha256;
        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let ecdsa_adaptor = Adaptor::<Sha256, _>::new(nonce_gen);
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let encryption_key = Point::random(&mut rand::thread_rng());
        let encrypted_signature = ecdsa_adaptor.encrypted_sign(
            &secret_key,
            &encryption_key,
            b"hello world you are beautiful!!!",
        );
        let serialized = bincode::serialize(&encrypted_signature).unwrap();
        assert_eq!(serialized.len(), 33 + 33 + 32 + 64);
        let deseriazed = bincode::deserialize::<EncryptedSignature>(&serialized[..]).unwrap();

        assert_eq!(deseriazed, encrypted_signature);
    }
}
