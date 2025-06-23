use super::DLEQ;
use crate::fun::{Point, Scalar, marker::*};
use sigma_fun::{CompactProof, Sigma};

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
            let x_scalar = Scalar::<Public, Zero>::from_bytes_mod_order(point.to_xonly_bytes()).public()
                .non_zero()?;
            Some(PointNonce { point, x_scalar })
        })
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(point_nonce: &PointNonce) -> [u8;33] {
        point_nonce.point.to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, bincode::Encode, bincode::Decode)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
pub(crate) struct EncryptedSignatureInternal {
    pub R: PointNonce,
    pub R_hat: Point,
    pub s_hat: Scalar<Public>,
    pub proof: CompactProof<<DLEQ as Sigma>::Response, <DLEQ as Sigma>::ChallengeLength>,
}

/// An "encrypted" ECDSA signature A.K.A. adaptor signature.
///
/// The implementation interally relies on a [`sigma_fun`] to produce the discrete logarithm
/// equality proof. This can only be created by [`Adaptor::encrypted_sign`].
///
/// [`Adaptor::encrypted_sign`]: crate::adaptor::Adaptor::encrypted_sign
#[derive(Clone, PartialEq)]
pub struct EncryptedSignature(pub(crate) EncryptedSignatureInternal);

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(es: &EncryptedSignature) -> [u8;162] {
        let mut bytes = [0u8;162];
        let size = bincode::encode_into_slice(&es.0, &mut bytes[..], bincode::config::legacy()).expect("infallible");
        assert_eq!(size, 162);
        bytes
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "ECDSA adaptor signature",
    fn from_bytes(bytes: [u8;162]) -> Option<EncryptedSignature> {
        bincode::decode_from_slice(&bytes[..], bincode::config::legacy()).ok().map(|(v,_)| EncryptedSignature(v))
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
        let serialized = bincode::encode_to_vec(
            bincode::serde::Compat(&encrypted_signature),
            bincode::config::standard(),
        )
        .unwrap();
        assert_eq!(serialized.len(), 33 + 33 + 32 + 64);
        let (deseriazed, _) = bincode::decode_from_slice::<
            bincode::serde::Compat<EncryptedSignature>,
            _,
        >(&serialized[..], bincode::config::standard())
        .unwrap();

        assert_eq!(deseriazed.0, encrypted_signature);
    }
}
