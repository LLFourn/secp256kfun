//! Algorithms for ECDSA "adaptor signature" signature encryption.
//!
//! Adaptor signatures are a kind of signature encryption. Just as you would expect this means you
//! can't get the signature from the encrypted signature unless you know the decryption key. As you
//! might not necessarily expect, this encryption is _one-time_ in that anyone who knows the
//! encrypted signature can recover the decryption key from the decrypted signature.
//!
//! This weird leaking of the decryption key is incredibly useful has numerous
//! applications in Bitcoin and cryptography more generally.
//!
//! # Synopsis
//!
//! ```
//! use ecdsa_fun::{
//!     adaptor::{Adaptor, EncryptedSignature},
//!     fun::{digest::Digest, g, marker::*, nonce, Scalar, G},
//! };
//! use rand::rngs::ThreadRng;
//! use sha2::Sha256;
//! let adaptor = Adaptor::<Sha256, nonce::Deterministic<Sha256>>::default();
//! let adaptor = Adaptor::<Sha256, _>::new(nonce::from_global_rng::<Sha256, ThreadRng>());
//! let secret_signing_key = Scalar::random(&mut rand::thread_rng());
//! let verification_key = g!(secret_signing_key * G).mark::<Normal>();
//! let decryption_key = Scalar::random(&mut rand::thread_rng());
//! let encryption_key = g!(decryption_key * G).mark::<Normal>();
//! let message_hash = {
//!     let message = "send 1 BTC to Bob";
//!     let mut message_hash = [0u8; 32];
//!     let hash = Sha256::default().chain(message);
//!     message_hash.copy_from_slice(hash.finalize().as_ref());
//!     message_hash
//! };
//!
//! // Alice knows: secret_signing_key, encryption_key
//! // Bob knows: decryption_key, verification_key
//!
//! // ALice creates and encrypted signature and sends it to Bob
//! let encrypted_signature =
//!     adaptor.encrypted_sign(&secret_signing_key, &encryption_key, &message_hash);
//!
//! // Bob verifies it and decrypts it
//! assert!(adaptor.verify_encrypted_signature(
//!     &verification_key,
//!     &encryption_key,
//!     &message_hash,
//!     &encrypted_signature
//! ));
//! let signature = adaptor.decrypt_signature(&decryption_key, encrypted_signature.clone());
//!
//! match adaptor.recover_decryption_key(&encryption_key, &signature, &encrypted_signature) {
//!     Some(decryption_key) => println!("Alice got the decryption key {}", decryption_key),
//!     None => panic!("signature is not the decryption of our original encrypted signature"),
//! }
//! ```
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
pub use encrypted_signature::{EncryptedSignature, PointNonce};
pub mod dleq;

#[derive(Clone, Debug)]
pub struct Adaptor<ProofChallengeHash, NonceGen> {
    pub ecdsa: ECDSA<NonceGen>,
    pub dleq: dleq::DLEQ<ProofChallengeHash, NonceGen>,
}

impl<CH, NG> Default for Adaptor<CH, NG>
where
    ECDSA<NG>: Default,
    dleq::DLEQ<CH, NG>: Default,
{
    fn default() -> Self {
        Self {
            ecdsa: ECDSA::<NG>::default(),
            dleq: dleq::DLEQ::<CH, NG>::default(),
        }
    }
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
    /// Create an encryted signature A.K.A. "adaptor signature" A.K.A. "pre-signature".
    ///
    /// See the [synopsis] for usage.
    ///
    /// [synopsis]: crate::adaptor#synopsis
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
    /// Verifies an encrypted signature is valid i.e. if it is decrypted it will yield a signature
    /// on `message_hash` under `verification_key`.
    ///
    /// See [synopsis] for usage.
    ///
    /// [synopsis]: crate::adaptor#synopsis
    #[must_use]
    pub fn verify_encrypted_signature(
        &self,
        verification_key: &Point<impl PointType, impl Secrecy>,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message_hash: &[u8; 32],
        ciphertext: &EncryptedSignature<impl Secrecy>,
    ) -> bool {
        let X = verification_key;
        let Y = encryption_key;
        let m = Scalar::from_bytes_mod_order(message_hash.clone());
        let EncryptedSignature {
            R,
            R_hat,
            proof,
            s_hat,
        } = ciphertext;

        if !self.dleq.verify(&G, R_hat, Y, &R.point, &proof) {
            return false;
        }
        let s_hat_inv = s_hat.invert();

        g!((s_hat_inv * m) * G + (s_hat_inv * R.x_scalar) * X) == *R_hat
    }

    /// Decrypts an encrypted signature yielding the signature.
    ///
    /// There are two crucial things to understand when calling this:
    ///
    /// 1. You should be certain that the encrypted signature is what you think it is by calling
    /// [`verify_encrypted_signature`] on it first.
    /// 2. Once you give the decrypted signature to anyone who has seen `encrypted_signature` they will be
    /// able to learn `decryption_key` by calling [`recover_decryption_key`].
    ///
    /// See [synopsis] for an example
    ///
    /// [`verify_encrypted_signature`]: Adaptor::verify_encrypted_signature
    /// [`recover_decryption_key`]: Adaptor::recover_decryption_key
    /// [synopsis]: crate::adaptor#synopsis
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

    /// Recovers the decryption key given an encrypted signature and the signature that was decrypted from it.
    ///
    /// If the `signature` was **not** the one decrypted from the `encrypted_signature` then this function
    /// returns `None`.  If it returns `Some(decryption_key)`, then `signature` is the unique
    /// signature obtained by decrypting `encrypted_signature` with the `decryption_key` corresponding to
    /// `encryption_key`.  In other words, if you already know that `encrypted_signature` is valid you do not
    /// have to call [`Schnorr::verify`] on `signature` before calling this function because this function returning
    /// `Some` implies it.
    ///
    /// See [synopsis] for an example
    ///
    /// [synopsis]: crate::adaptor#synopsis
    pub fn recover_decryption_key(
        &self,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
        ciphertext: &EncryptedSignature<impl Secrecy>,
    ) -> Option<Scalar> {
        // Check we are not looking at some unrelated signature
        if ciphertext.R.x_scalar != signature.R_x
                // Enforce low_s
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
                &ciphertext,
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
