//! Algorithms for Schnorr "adaptor signature" signature encryption.
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
//! ```
//! use rand::rngs::ThreadRng;
//! use schnorr_fun::{
//!     adaptor::{Adaptor, EncryptedSign},
//!     fun::{marker::*, nonce, Scalar},
//!     Message, Schnorr,
//! };
//! use sha2::Sha256;
//! let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
//! let schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
//! let signing_keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! let verification_key = signing_keypair.public_key().to_point();
//! let decryption_key = Scalar::random(&mut rand::thread_rng());
//! let encryption_key = schnorr.encryption_key_for(&decryption_key);
//! let message = Message::<Public>::plain("text-bitcoin", b"send 1 BTC to Bob");
//!
//! // Alice knows: signing_keypair, encryption_key
//! // Bob knows: decryption_key, verification_key
//!
//! // Alice creates an encrypted signature and sends it to Bob
//! let encrypted_signature = schnorr.encrypted_sign(&signing_keypair, &encryption_key, message);
//!
//! // Bob verifies it and decrypts it
//! assert!(schnorr.verify_encrypted_signature(
//!     &verification_key,
//!     &encryption_key,
//!     message,
//!     &encrypted_signature
//! ));
//! let signature = schnorr.decrypt_signature(decryption_key, encrypted_signature.clone());
//!
//! // Bob then broadcasts the signature to the public.
//! // Once Alice sees it she can recover Bob's secret decryption key
//! match schnorr.recover_decryption_key(&encryption_key, &encrypted_signature, &signature) {
//!     Some(decryption_key) => println!("Alice got the decryption key {}", decryption_key),
//!     None => eprintln!("signature is not the decryption of our original encrypted signature"),
//! }
//! ```
use crate::{
    fun::{
        derive_nonce,
        digest::{generic_array::typenum::U32, Digest},
        g,
        marker::*,
        nonce::NonceGen,
        s, Point, Scalar, XOnlyKeyPair, G,
    },
    Message, Schnorr, Signature,
};
mod encrypted_signature;
pub use encrypted_signature::EncryptedSignature;

/// Extension trait for [`Schnorr`] to add the encrypted signing algorithm.
///
/// [`Schnorr`]: crate::Schnorr
pub trait EncryptedSign {
    /// Create a signature on a message encrypted under `encryption_key`.
    ///
    /// See the [synopsis] for usage.
    ///
    /// [synopsis]: crate::adaptor#synopsis
    fn encrypted_sign(
        &self,
        signing_keypair: &XOnlyKeyPair,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: Message<'_, impl Secrecy>,
    ) -> EncryptedSignature;
}

impl<NG, CH> EncryptedSign for Schnorr<CH, NG>
where
    CH: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    fn encrypted_sign(
        &self,
        signing_key: &XOnlyKeyPair,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: Message<'_, impl Secrecy>,
    ) -> EncryptedSignature {
        let (x, X) = signing_key.as_tuple();
        let Y = encryption_key;

        let mut r = derive_nonce!(
            nonce_gen => self.nonce_gen(),
            secret => x,
            public => [X, Y, message]
        );

        let R = g!(r * G + Y)
            // R_hat = r * G is sampled pseudorandomly for every Y which means R_hat + Y is also
            // be pseudoranodm and therefore will not be zero.
            // NOTE: Crucially we add Y to the nonce derivation to ensure this is true.
            .expect_nonzero("computationally unreachable");

        let (R, needs_negation) = R.into_point_with_even_y();
        // We correct r here but we can't correct the decryption key (y) so we
        // store in "needs_negation" whether the decryptor needs to negate their
        // key before decrypting it
        r.conditional_negate(needs_negation);

        let c = self.challenge(R.to_xonly(), X, message);
        let s_hat = s!(r + c * x).mark::<Public>();

        EncryptedSignature {
            R,
            s_hat,
            needs_negation,
        }
    }
}

/// Extension trait adding the algorithms for the adaptor signature scheme to instances of [`Schnorr`].
pub trait Adaptor {
    /// Derives the public encryption key corresponding to a secret decryption key.
    ///
    /// # Example
    /// ```
    /// # use schnorr_fun::{adaptor::Adaptor, fun::Scalar, Schnorr};
    /// # let schnorr = schnorr_fun::test_instance!();
    /// let decryption_key = Scalar::random(&mut rand::thread_rng());
    /// let encryption_key = schnorr.encryption_key_for(&decryption_key);
    fn encryption_key_for(&self, decryption_key: &Scalar) -> Point;

    /// Verifies an encrypted signature is valid i.e. if it is decrypted it will yield a signature
    /// on `message` under `verification_key`.
    ///
    /// See [synopsis] for usage.
    ///
    /// [synopsis]: crate::adaptor#synopsis
    #[must_use]
    fn verify_encrypted_signature(
        &self,
        verification_key: &Point<EvenY, impl Secrecy>,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: Message<'_, impl Secrecy>,
        encrypted_signature: &EncryptedSignature<impl Secrecy>,
    ) -> bool;

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
    fn decrypt_signature(
        &self,
        decryption_key: Scalar<impl Secrecy>,
        encrypted_signature: EncryptedSignature<impl Secrecy>,
    ) -> Signature;

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
    fn recover_decryption_key(
        &self,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        encrypted_signature: &EncryptedSignature<impl Secrecy>,
        signature: &Signature<impl Secrecy>,
    ) -> Option<Scalar>;
}

impl<CH, NG> Adaptor for Schnorr<CH, NG>
where
    CH: Digest<OutputSize = U32> + Clone,
{
    fn encryption_key_for(&self, decryption_key: &Scalar) -> Point {
        g!(decryption_key * G).normalize()
    }

    #[must_use]
    fn verify_encrypted_signature(
        &self,
        verification_key: &Point<EvenY, impl Secrecy>,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        message: Message<'_, impl Secrecy>,
        encrypted_signature: &EncryptedSignature<impl Secrecy>,
    ) -> bool {
        let EncryptedSignature {
            R,
            s_hat,
            needs_negation,
        } = encrypted_signature;
        let X = verification_key;
        let Y = encryption_key;

        //  needs_negation => R_hat = R + Y
        // !needs_negation => R_hat = R - Y
        let R_hat = g!(R + { Y.conditional_negate(!needs_negation) });

        let c = self.challenge(R.to_xonly(), X.to_xonly(), message);

        R_hat == g!(s_hat * G - c * X)
    }

    fn decrypt_signature(
        &self,
        decryption_key: Scalar<impl Secrecy>,
        encrypted_signature: EncryptedSignature<impl Secrecy>,
    ) -> Signature {
        let EncryptedSignature {
            R,
            s_hat,
            needs_negation,
        } = encrypted_signature;
        let mut y = decryption_key;
        y.conditional_negate(needs_negation);
        let s = s!(s_hat + y).mark::<Public>();

        Signature { s, R: R.to_xonly() }
    }

    fn recover_decryption_key(
        &self,
        encryption_key: &Point<impl Normalized, impl Secrecy>,
        encrypted_signature: &EncryptedSignature<impl Secrecy>,
        signature: &Signature<impl Secrecy>,
    ) -> Option<Scalar> {
        if signature.R != encrypted_signature.R {
            return None;
        }

        let EncryptedSignature {
            s_hat,
            needs_negation,
            ..
        } = encrypted_signature;
        let s = &signature.s;

        let mut y = s!(s - s_hat);
        y.conditional_negate(*needs_negation);
        let implied_encryption_key = g!(y * G);

        if implied_encryption_key == *encryption_key {
            Some(y.expect_nonzero("unreachable - encryption_key is NonZero and y*G equals it"))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::nonce::{Deterministic, GlobalRng, Synthetic};
    use rand::rngs::ThreadRng;
    use secp256kfun::proptest::prelude::*;
    use sha2::Sha256;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    proptest! {
        #[test]
        fn signing_tests_deterministic(secret_key in any::<Scalar>(), decryption_key in any::<Scalar>()) {
            let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
            test_it(schnorr, secret_key, decryption_key);
        }

        #[test]
        fn signing_tests_synthetic(secret_key in any::<Scalar>(), decryption_key in any::<Scalar>()) {
            let schnorr = Schnorr::<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>>::default();
            test_it(schnorr, secret_key, decryption_key);
        }

    }

    fn test_it<NG: NonceGen>(
        schnorr: Schnorr<Sha256, NG>,
        secret_key: Scalar,
        decryption_key: Scalar,
    ) {
        let signing_keypair = schnorr.new_keypair(secret_key);
        let verification_key = signing_keypair.public_key().to_point();
        let encryption_key = schnorr.encryption_key_for(&decryption_key);
        let message = Message::<Public>::plain("test", b"give 100 coins to Bob".as_ref());

        let encrypted_signature =
            schnorr.encrypted_sign(&signing_keypair, &encryption_key, message);

        assert!(schnorr.verify_encrypted_signature(
            &verification_key,
            &encryption_key,
            message,
            &encrypted_signature,
        ));

        let decryption_key = decryption_key.mark::<Public>();
        let signature =
            schnorr.decrypt_signature(decryption_key.clone(), encrypted_signature.clone());
        assert!(schnorr.verify(&verification_key, message, &signature));
        let rec_decryption_key = schnorr
            .recover_decryption_key(&encryption_key, &encrypted_signature, &signature)
            .expect("recovery works");
        assert_eq!(rec_decryption_key, decryption_key);
    }
}
