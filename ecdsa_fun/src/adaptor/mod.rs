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
//!     adaptor::{Adaptor, EncryptedSignature, HashTranscript},
//!     fun::{
//!         digest::{Digest, Update},
//!         g,
//!         marker::*,
//!         nonce, Scalar, G,
//!     },
//! };
//! use rand::rngs::ThreadRng;
//! use rand_chacha::ChaCha20Rng;
//! use sha2::Sha256;
//! // use synthetic nonce generation (preferred)
//! type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;
//! // needed internally to create/verify the DLEQ proof
//! type Transcript = HashTranscript<Sha256, ChaCha20Rng>;
//! let adaptor = Adaptor::<Transcript, NonceGen>::default();
//! let secret_signing_key = Scalar::random(&mut rand::thread_rng());
//! let verification_key = adaptor.ecdsa.verification_key_for(&secret_signing_key);
//! let decryption_key = Scalar::random(&mut rand::thread_rng());
//! let encryption_key = adaptor.encryption_key_for(&decryption_key);
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
//! // Alice recovers the decryption key from the signature
//! // Note there is no need to call .verify before doing this;
//! // successful recovery implies it was a valid signature.
//! match adaptor.recover_decryption_key(&encryption_key, &signature, &encrypted_signature) {
//!     Some(decryption_key) => println!("Alice got the decryption key {}", decryption_key),
//!     None => panic!("signature is not the decryption of our original encrypted signature"),
//! }
//! ```
use crate::{Signature, ECDSA};
use secp256kfun::{
    derive_nonce_rng,
    digest::generic_array::typenum::U32,
    g,
    marker::*,
    nonce::{AddTag, NonceGen},
    s, Point, Scalar, G,
};
pub use sigma_fun::HashTranscript;
use sigma_fun::{secp256k1, Eq, FiatShamir, ProverTranscript, Transcript};

mod encrypted_signature;
pub use encrypted_signature::*;

pub type DLEQ = Eq<secp256k1::DLG<U32>, secp256k1::DL<U32>>;

#[derive(Clone, Debug)]
pub struct Adaptor<T, NonceGen> {
    pub ecdsa: ECDSA<NonceGen>,
    pub dleq_proof_system: FiatShamir<DLEQ, T>,
}

impl<T, NG> Default for Adaptor<T, NG>
where
    NG: Default + AddTag,
    T: Transcript<DLEQ> + Default,
{
    fn default() -> Self {
        Self::new(NG::default())
    }
}

impl<T: Transcript<DLEQ> + Default, NG: AddTag> Adaptor<T, NG> {
    pub fn new(nonce_gen: NG) -> Self {
        let sigma = DLEQ::default();
        Self {
            ecdsa: ECDSA::new(nonce_gen),
            dleq_proof_system: FiatShamir::new(sigma, T::default(), Some("DLEQ")),
        }
    }
}

impl<T: Transcript<DLEQ> + Default> Adaptor<T, ()> {
    /// Create an `Adaptor` instance that can do verification only
    /// # Example
    /// ```
    /// use ecdsa_fun::adaptor::{Adaptor, HashTranscript};
    /// let adaptor = Adaptor::<HashTranscript<sha2::Sha256>, _>::verify_only();
    /// ```
    pub fn verify_only() -> Self {
        Self::new(())
    }
}

impl<T, NG> Adaptor<T, NG>
where
    T: Transcript<DLEQ>,
    NG: NonceGen,
{
}

impl<T: Transcript<DLEQ>, NG> Adaptor<T, NG> {
    /// Create an encryted signature A.K.A. "adaptor signature" A.K.A. "pre-signature".
    ///
    /// See the [synopsis] for usage.
    ///
    /// [synopsis]: crate::adaptor#synopsis
    pub fn encrypted_sign(
        &self,
        signing_key: &Scalar,
        encryption_key: &Point,
        message: &[u8; 32],
    ) -> EncryptedSignature
    where
        T: ProverTranscript<DLEQ>,
        NG: NonceGen,
    {
        let x = signing_key;
        let Y = encryption_key;
        let m = Scalar::from_bytes_mod_order(message.clone()).mark::<Public>();
        let mut rng = derive_nonce_rng!(
            nonce_gen => self.ecdsa.nonce_gen,
            secret => x,
            public => [Y, &message[..]],
            seedable_rng => rand_chacha::ChaCha20Rng
        );

        let r = Scalar::random(&mut rng);
        let R_hat = g!(r * G).mark::<Normal>();
        let R = g!(r * Y).mark::<Normal>();

        let proof = self
            .dleq_proof_system
            .prove(&r, &(R_hat, (*Y, R)), Some(&mut rng));

        let R_x = Scalar::from_bytes_mod_order(R.to_xonly().into_bytes())
            .mark::<(Public, NonZero)>()
            // The point with x-coordinate = 0 mod q exists, but it will never
            // occur since r is pseudorandomly chosen for a given Y, R = r*Y
            // will also be uniform.
            .expect("computationally unreachable");

        let s_hat = s!({ r.invert() } * (m + R_x * x))
            .mark::<(Public, NonZero)>()
            .expect("computationally unreachable");

        EncryptedSignatureInternal {
            R: PointNonce {
                point: R,
                x_scalar: R_x,
            },
            R_hat,
            s_hat,
            proof,
        }
        .into()
    }

    /// Returns the corresponding encryption key for a decryption key
    ///
    /// # Example
    /// ```
    /// # use ecdsa_fun::{ adaptor::{Adaptor, HashTranscript}, fun::Scalar };
    /// # let adaptor = Adaptor::<HashTranscript::<sha2::Sha256>,()>::default();
    /// let secret_decryption_key = Scalar::random(&mut rand::thread_rng());
    /// let public_encryption_key = adaptor.encryption_key_for(&secret_decryption_key);
    pub fn encryption_key_for(&self, decryption_key: &Scalar) -> Point {
        g!(decryption_key * G).mark::<Normal>()
    }
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
        encryption_key: &Point,
        message_hash: &[u8; 32],
        ciphertext: &EncryptedSignature,
    ) -> bool {
        let X = verification_key;
        let Y = encryption_key;
        let m = Scalar::from_bytes_mod_order(message_hash.clone());
        let EncryptedSignature(EncryptedSignatureInternal {
            R,
            R_hat,
            proof,
            s_hat,
        }) = ciphertext;

        if !self
            .dleq_proof_system
            .verify(&(*R_hat, (*Y, R.point)), &proof)
        {
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
        ciphertext: EncryptedSignature,
    ) -> Signature {
        let EncryptedSignature(EncryptedSignatureInternal { R, s_hat, .. }) = ciphertext;
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
    /// have to call [`ECDSA::verify`] on `signature` before calling this function because this function returning
    /// `Some` implies it.
    ///
    /// See [synopsis] for an example
    ///
    /// [`ECDSA::verify`]: crate::ECDSA::verify
    /// [synopsis]: crate::adaptor#synopsis
    pub fn recover_decryption_key(
        &self,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
        ciphertext: &EncryptedSignature,
    ) -> Option<Scalar> {
        let EncryptedSignature(EncryptedSignatureInternal { s_hat, R, .. }) = ciphertext;
        // Check we are not looking at some unrelated signature
        if R.x_scalar != signature.R_x
                // Enforce low_s
            || (signature.s.is_high() && self.ecdsa.enforce_low_s)
        {
            return None;
        }
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
    use crate::fun::nonce;
    use rand::rngs::ThreadRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha256;
    use sigma_fun::HashTranscript;

    #[test]
    fn end_to_end() {
        let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
        let ecdsa_adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);
        for _ in 0..20 {
            let msg = b"hello world you are beautiful!!!";
            let signing_key = Scalar::random(&mut rand::thread_rng());
            let verification_key = ecdsa_adaptor.ecdsa.verification_key_for(&signing_key);
            let decryption_key = Scalar::random(&mut rand::thread_rng());
            let encryption_key = ecdsa_adaptor.encryption_key_for(&decryption_key);
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
