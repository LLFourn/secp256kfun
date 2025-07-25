#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_snake_case)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

mod libsecp_compat;

use fun::Tag;

use fun::{G, Point, Scalar, derive_nonce, g, marker::*, nonce::NonceGen, s};
pub use secp256kfun as fun;
pub use secp256kfun::nonce;
mod signature;
pub use signature::Signature;
#[cfg(feature = "adaptor")]
#[cfg_attr(docsrs, doc(cfg(feature = "adaptor")))]
pub mod adaptor;

/// An instance of the ECDSA signature scheme.
#[derive(Default, Clone, Debug)]
pub struct ECDSA<NG> {
    /// An instance of [`NonceGen`] to produce nonces.
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    pub nonce_gen: NG,
    /// `enforce_low_s`: Whether the verify algorithm should enforce that the `s` component of the signature is low (see [BIP-146]).
    ///
    /// [BIP-146]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
    pub enforce_low_s: bool,
}

impl ECDSA<()> {
    /// Creates an `ECDSA` instance that cannot be used to sign messages but can
    /// verify signatures.
    pub fn verify_only() -> Self {
        ECDSA {
            nonce_gen: (),
            enforce_low_s: false,
        }
    }
}

impl<NG> ECDSA<NG> {
    /// Creates a ECDSA instance.
    ///
    /// The caller chooses how nonces are generated by providing a [`NonceGen`].
    ///
    /// # Example
    /// ```
    /// use ecdsa_fun::{ECDSA, nonce};
    /// use rand::rngs::ThreadRng;
    /// use sha2::Sha256;
    /// let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    /// let ecdsa = ECDSA::new(nonce_gen);
    /// ```
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    pub fn new(nonce_gen: NG) -> Self
    where
        NG: Tag,
    {
        ECDSA {
            nonce_gen: nonce_gen.tag(b"secp256kfun/ecdsa_fun"),
            enforce_low_s: false,
        }
    }

    /// Transforms the ECDSA instance into one which enforces the [BIP-146] low
    /// s constraint **when verifying** (it is always low s when signing).
    ///
    /// *** DO NOT USE THIS IF VERIFYING BITCOIN TRANSACTIONS FROM THE CHAIN***:
    /// [BIP-146] is only enforced for transaction relay so you can still have
    /// valid high s signatures. This is especially true if you are using the
    /// ECDSA adaptor signature scheme.
    ///
    /// [BIP-146]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
    pub fn enforce_low_s(self) -> Self {
        ECDSA {
            nonce_gen: self.nonce_gen,
            enforce_low_s: true,
        }
    }
}

impl<NG> ECDSA<NG> {
    /// Get the corresponding verification key for a secret key
    ///
    /// # Example
    /// ```
    /// use ecdsa_fun::{ECDSA, fun::Scalar};
    /// let ecdsa = ECDSA::verify_only();
    /// let secret_key = Scalar::random(&mut rand::thread_rng());
    /// let verification_key = ecdsa.verification_key_for(&secret_key);
    /// ```
    pub fn verification_key_for(&self, secret_key: &Scalar) -> Point {
        g!(secret_key * G).normalize()
    }
    /// Verify an ECDSA signature.
    #[must_use]
    pub fn verify(
        &self,
        verification_key: &Point<impl PointType, Public, NonZero>,
        message: &[u8; 32],
        signature: &Signature,
    ) -> bool {
        let (R_x, s) = signature.as_tuple();
        // This ensures that there is only one valid s value per R_x for any given message.
        if s.is_high() && self.enforce_low_s {
            return false;
        }

        let m = Scalar::<Public, _>::from_bytes_mod_order(*message).public();
        let s_inv = s.invert();

        g!((s_inv * m) * G + (s_inv * R_x) * verification_key)
            .non_zero()
            .is_some_and(|implied_R| implied_R.x_eq_scalar(R_x))
    }
}

impl<NG: NonceGen> ECDSA<NG> {
    /// Deterministically produce a ECDSA signature on a message hash.
    ///
    /// # Examples
    ///
    /// ```
    /// use ecdsa_fun::{
    ///     ECDSA,
    ///     fun::{digest::Digest, prelude::*},
    ///     nonce,
    /// };
    /// use rand::rngs::ThreadRng;
    /// use sha2::Sha256;
    /// let secret_key = Scalar::random(&mut rand::thread_rng());
    /// let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
    /// let ecdsa = ECDSA::new(nonce_gen);
    /// let verification_key = ecdsa.verification_key_for(&secret_key);
    /// let message_hash = {
    ///     let message = b"Attack at dawn";
    ///     let mut message_hash = [0u8; 32];
    ///     let hash = Sha256::default().chain_update(message);
    ///     message_hash.copy_from_slice(hash.finalize().as_ref());
    ///     message_hash
    /// };
    /// let signature = ecdsa.sign(&secret_key, &message_hash);
    /// assert!(ecdsa.verify(&verification_key, &message_hash, &signature));
    /// ```
    pub fn sign(&self, secret_key: &Scalar, message_hash: &[u8; 32]) -> Signature {
        let x = secret_key;
        let m = Scalar::<Public, _>::from_bytes_mod_order(*message_hash).public();
        let r = derive_nonce!(
            nonce_gen => self.nonce_gen,
            secret => x,
            public => [&message_hash[..]]
        );
        let R = g!(r * G).normalize(); // Must be normal so we can get x-coordinate

        // This coverts R is its x-coordinate mod q. This acts as a kind of poor
        // man's version of the Fiat-Shamir challenge in a Schnorr
        // signature. The lack of any known algebraic relationship between r and
        // R_x is what makes ECDSA signatures difficult to forge.
        let R_x = Scalar::<Public, _>::from_bytes_mod_order(R.to_xonly_bytes())
            // There *is* a single point that will be zero here but since we're
            // choosing R pseudorandomly it won't occur.
            .public()
            .non_zero()
            .expect("computationally unreachable");

        let mut s = s!((m + R_x * x) / r)
            // Given R_x is determined by x and m through a hash, reaching
            // (m + R_x * x) = 0 is intractable.
            .non_zero()
            .expect("computationally unreachable")
            .public();

        // s values must be low (less than half group order), otherwise signatures
        // would be malleable i.e. (R,s) and (R,-s) would both be valid signatures.
        s.conditional_negate(s.is_high());

        Signature { R_x, s }
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! test_instance {
    () => {
        $crate::ECDSA::new($crate::nonce::Deterministic::<sha2::Sha256>::default())
    };
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;

    #[test]
    fn repeated_sign_and_verify() {
        let ecdsa = test_instance!();
        for _ in 0..20 {
            let mut message = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut message);
            let secret_key = Scalar::random(&mut rand::thread_rng());
            let public_key = g!(secret_key * G).normalize();
            let sig = ecdsa.sign(&secret_key, &message);
            assert!(ecdsa.verify(&public_key, &message, &sig))
        }
    }

    #[test]
    fn low_s() {
        let ecdsa_enforce_low_s = test_instance!().enforce_low_s();
        let ecdsa = test_instance!();
        // TODO: use proptest
        for _ in 0..20 {
            let mut message = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut message);
            let secret_key = Scalar::random(&mut rand::thread_rng());
            let public_key = ecdsa.verification_key_for(&secret_key);
            let mut sig = ecdsa.sign(&secret_key, &message);
            assert!(ecdsa.verify(&public_key, &message, &sig));
            assert!(ecdsa_enforce_low_s.verify(&public_key, &message, &sig));
            sig.s = -sig.s;
            assert!(!ecdsa_enforce_low_s.verify(&public_key, &message, &sig));
            assert!(ecdsa.verify(&public_key, &message, &sig));
        }
    }
}
