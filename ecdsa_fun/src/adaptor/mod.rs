//! ECDSA Adaptor signatures.
use crate::{Signature, ECDSA};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::Tagged,
    marker::*,
    nonce::NonceGen,
    s, Point, Scalar, G,
};

mod encrypted_signature;
use encrypted_signature::{EncryptedSignature, PointNonce};
mod dleq;

pub struct Adaptor<ProofChallengeHash, NonceGen> {
    pub ecdsa: ECDSA<NonceGen>,
    pub dleq: dleq::DLEQ<ProofChallengeHash, NonceGen>,
}

impl<H: Tagged, NG: NonceGen + Clone> Adaptor<H, NG> {
    pub fn new(nonce_gen: NG) -> Self {
        Self {
            ecdsa: ECDSA::new(nonce_gen.clone()),
            dleq: dleq::DLEQ::new(nonce_gen.clone()),
        }
    }
}

impl<CH, NG> Adaptor<CH, NG>
where
    CH: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    pub fn encrypted_sign(
        &self,
        signing_key: &Scalar,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: &[u8; 32],
    ) -> EncryptedSignature {
        let x = signing_key;
        let Y = encryption_key;
        let m = Scalar::from_bytes_mod_order(message.clone()).mark::<Public>();
        let r = derive_nonce!(
            nonce_gen => self.ecdsa.nonce_gen,
            secret => x,
            public => [Y, &message[..]]
        );

        let (proof, R_hat, R) = self.dleq.prove_guaranteed(&r, &G, Y);
        let R_x = Scalar::from_bytes_mod_order(R.to_xonly().into_bytes())
            .mark::<(Public, NonZero)>()
            // The point with x-coordinate = 0 mod q exists, but it will never
            // occur since r is pseudorandomly chosen for a given Y, R = r*Y
            // will also be uniform.
            .expect("computationally unreachable");

        let s_hat = s!({ r.invert() } * (m + R_x * x))
            .mark::<(Public, NonZero)>()
            .expect("computationally unreachable");

        EncryptedSignature {
            R: PointNonce {
                point: R,
                x_scalar: R_x,
            },
            R_hat,
            s_hat,
            proof,
        }
    }
}

impl<CH: Digest<OutputSize = U32> + Clone, NG> Adaptor<CH, NG> {
    #[must_use]
    pub fn verify_encrypted_signature(
        &self,
        verification_key: &Point<impl PointType, impl Secrecy>,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: &[u8; 32],
        ciphertext: EncryptedSignature<impl Secrecy>,
    ) -> bool {
        let X = verification_key;
        let Y = encryption_key;
        let m = Scalar::from_bytes_mod_order(message.clone());
        let EncryptedSignature {
            R,
            R_hat,
            proof,
            s_hat,
        } = ciphertext;

        if !self.dleq.verify(&G, &R_hat, Y, &R.point, &proof) {
            return false;
        }
        let s_hat_inv = s_hat.invert();

        g!((s_hat_inv * m) * G + (s_hat_inv * R.x_scalar) * X) == R_hat
    }

    pub fn decrypt_signature(
        &self,
        decryption_key: &Scalar<impl Secrecy, NonZero>,
        EncryptedSignature { R, s_hat, .. }: EncryptedSignature<impl Secrecy>,
    ) -> Signature {
        let y = decryption_key;
        let mut s = s!(s_hat * { y.invert() });
        s.conditional_negate(s.is_high());
        Signature {
            R_x: R.x_scalar.mark::<Public>(),
            s: s.mark::<Public>(),
        }
    }

    pub fn recover_decryption_key(
        &self,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
        ciphertext: &EncryptedSignature<impl Secrecy>,
    ) -> Option<Scalar> {
        if ciphertext.R.x_scalar != signature.R_x
            || (signature.s.is_high() && self.ecdsa.enforce_low_s)
        {
            return None;
        }
        let EncryptedSignature { s_hat, .. } = ciphertext;
        let s = &signature.s;
        let y = s!({ s.invert() } * s_hat);
        let Y = g!(y * G);

        if Y == *encryption_key {
            Some(y)
        } else if -Y == *encryption_key {
            Some(-y)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::fun::{nonce, G};
    use rand::rngs::ThreadRng;
    use sha2::Sha256;

    #[test]
    fn end_to_end() {
        let ecdsa_adaptor =
            Adaptor::<Sha256, _>::new(nonce::from_global_rng::<Sha256, ThreadRng>());
        for _ in 0..20 {
            let msg = b"hello world you are beautiful!!!";
            let signing_key = Scalar::random(&mut rand::thread_rng());
            let verification_key = g!(signing_key * G);
            let decryption_key = Scalar::random(&mut rand::thread_rng());
            let encryption_key = g!(decryption_key * G).mark::<Normal>();
            let ciphertext = ecdsa_adaptor.encrypted_sign(&signing_key, &encryption_key, msg);
            assert!(ecdsa_adaptor.verify_encrypted_signature(
                &verification_key,
                &encryption_key,
                msg,
                ciphertext.clone(),
            ));

            let signature = ecdsa_adaptor.decrypt_signature(&decryption_key, ciphertext.clone());
            assert!(ecdsa_adaptor
                .ecdsa
                .verify(&verification_key, &msg, &signature));

            let recoverd_decryption_sk = ecdsa_adaptor
                .recover_decryption_key(&encryption_key, &signature, &ciphertext)
                .unwrap();

            assert_eq!(recoverd_decryption_sk, decryption_key);
        }
    }
}
