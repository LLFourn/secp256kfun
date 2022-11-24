use super::DLEQ;
use crate::fun::{marker::*, Point, Scalar};
use sigma_fun::CompactProof;

/// `PointNonce` is a [`NonZero`] Point that also has an x-coordinate that is NonZero
/// when reduced modulo the curve order.
///
/// [`NonZero`]: secp256kfun::marker::NonZero
#[derive(Clone, PartialEq)]
pub(crate) struct PointNonce {
    pub point: Point,
    pub x_scalar: Scalar<Public>,
}

secp256kfun::impl_fromstr_deserialize! {
    name => "compressed secp256k1 point",
    fn from_bytes(bytes: [u8;33]) -> Option<PointNonce> {
        Point::from_bytes(bytes).and_then(|point| {
            Scalar::from_bytes_mod_order(point.to_xonly_bytes()).public()
                .non_zero().map(move |x_scalar| PointNonce { point, x_scalar } )
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
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub(crate) struct EncryptedSignatureInternal {
    pub R: PointNonce,
    pub R_hat: Point,
    pub s_hat: Scalar<Public>,
    pub proof: CompactProof<DLEQ>,
}

/// An "encrypted" ECDSA signature A.K.A. adaptor signature.
///
/// The implementation interally relies on a [`sigma_fun`] to produce the discrete logarithm
/// equality proof. This can only be created by [`Adaptor::encrypted_sign`].
///
/// [`Adaptor::encrypted_sign`]: crate::adaptor::Adaptor::encrypted_sign
#[derive(Clone, PartialEq)]
pub struct EncryptedSignature(pub(crate) EncryptedSignatureInternal);

#[cfg(feature = "serde")]
secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(es: &EncryptedSignature) -> [u8;162] {
        let mut bytes = [0u8;162];
        bytes.copy_from_slice(bincode::serialize(&es.0).unwrap().as_slice());
        bytes
    }
}

#[cfg(feature = "serde")]
secp256kfun::impl_fromstr_deserialize! {
    name => "ECDSA adaptor signature",
    fn from_bytes(bytes: [u8;162]) -> Option<EncryptedSignature> {
        bincode::deserialize(&bytes[..]).ok().map(EncryptedSignature)
    }
}

impl From<EncryptedSignatureInternal> for EncryptedSignature {
    fn from(es: EncryptedSignatureInternal) -> Self {
        EncryptedSignature(es)
    }
}

impl From<EncryptedSignature> for EncryptedSignatureInternal {
    fn from(es: EncryptedSignature) -> Self {
        es.0
    }
}

#[cfg(test)]
mod test {

    #[cfg(feature = "serde")]
    #[test]
    fn encrypted_signature_serde_roundtrip() {
        use super::*;
        use crate::{adaptor::Adaptor, fun::nonce};
        use rand::rngs::ThreadRng;
        use rand_chacha::ChaCha20Rng;
        use sha2::Sha256;
        use sigma_fun::HashTranscript;

        type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;
        type Transcript = HashTranscript<Sha256, ChaCha20Rng>;
        let ecdsa_adaptor = Adaptor::<Transcript, NonceGen>::default();
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
