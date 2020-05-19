//! Bitcoin-compatible ECDSA implementation. Work in progress.

#![no_std]
#![allow(non_snake_case)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

use digest::{generic_array::typenum::U32, Digest};
pub use secp256kfun;
use secp256kfun::{
    derive_nonce, g,
    hash::{Derivation, NonceHash},
    marker::*,
    s, Point, Scalar, G,
};

mod signature;
pub use signature::Signature;
pub mod adaptor;

/// An instance of the ECDSA signature scheme.
pub struct ECDSA<NH = NonceHash<sha2::Sha256>> {
    /// An instance of [`NonceHash`] to produce nonces.
    ///
    /// [`NonceHash`]: secp256kfun::hash::NonceHash
    pub nonce_hash: NH,
    /// `enforce_low_s`: Whether the verify algorithm should enforce that the `s` component of the signature is low (see [BIP-146]).
    ///
    /// [BIP-146]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
    pub enforce_low_s: bool,
}

impl ECDSA<NonceHash<sha2::Sha256>> {
    /// Creates a ECDSA instance capable of signing from a tag. The tag is only
    /// used for nonce derivation.
    pub fn from_tag(tag: &[u8]) -> Self {
        ECDSA {
            nonce_hash: NonceHash::from_tag(tag),
            enforce_low_s: false,
        }
    }
}

impl ECDSA<()> {
    /// Creates an `ECDSA` instance that cannot be used to sign messages but can
    /// verify signatures.
    pub fn verify_only() -> Self {
        ECDSA {
            nonce_hash: (),
            enforce_low_s: false,
        }
    }
}

impl<NH> ECDSA<NH> {
    /// Transforms the ECDSA instance into one which enforces the [BIP-146] low s constraint.
    ///
    /// [BIP-146]: https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki#low_s
    pub fn enforce_low_s(self) -> Self {
        ECDSA {
            nonce_hash: self.nonce_hash,
            enforce_low_s: true,
        }
    }
}

impl<NA> ECDSA<NA> {
    /// Verify an ECDSA signature.
    pub fn verify(
        &self,
        public_key: &Point<impl PointType, Public, NonZero>,
        message: &[u8; 32],
        signature: &Signature<impl Secrecy>,
    ) -> bool {
        let (R_x, s) = signature.as_tuple();
        // This ensures that there is only one valid s value per R_x for any given message.
        if s.is_high() && self.enforce_low_s {
            return false;
        }

        let m = Scalar::from_bytes_mod_order(message.clone()).mark::<Public>();
        let s_inv = s.invert();

        g!((s_inv * m) * G + (s_inv * R_x) * public_key)
            .mark::<NonZero>()
            .map_or(false, |implied_R| implied_R.x_eq_scalar(R_x))
    }
}

impl<NH: Digest<OutputSize = U32> + Clone> ECDSA<NonceHash<NH>> {
    /// Deterministically produce a ECDSA signature on a message hash.
    ///
    /// # Examples
    ///
    /// ```
    /// use digest::Digest;
    /// use ecdsa_fun::ECDSA;
    /// use secp256kfun::{hash::Derivation, Scalar};
    ///
    /// let secret_key = Scalar::random(&mut rand::thread_rng());
    /// let ecdsa = ECDSA::from_tag(b"my-ecdsa");
    /// let message = b"Attack at dawn";
    /// let message_hash = {
    ///     let mut message_hash = [0u8; 32];
    ///     let hash = sha2::Sha256::default().chain(message);
    ///     message_hash.copy_from_slice(hash.result().as_ref());
    ///     message_hash
    /// };
    /// let signature = ecdsa.sign(&secret_key, &message_hash, Derivation::Deterministic);
    /// ```
    pub fn sign(&self, secret_key: &Scalar, message: &[u8; 32], derive: Derivation) -> Signature {
        let x = secret_key;
        let m = Scalar::from_bytes_mod_order(message.clone()).mark::<Public>();
        let r = derive_nonce!(
            nonce_hash => self.nonce_hash,
            derivation => derive,
            secret => x,
            public => [&message[..]]
        );
        let R = g!(r * G).mark::<Normal>(); // Must be normal so we can get x-coordinate

        // This coverts R is its x-coordinate mod q. This acts as a kind of poor
        // man's version of the Fiat-Shamir challenge in a Schnoz
        // signature. The lack of any known algebraic relationship between r and
        // R_x is what makes ECDSA signatures difficult to forge.
        let R_x = Scalar::from_bytes_mod_order(R.to_xonly().into_bytes())
            // There *is* a single point that will be zero here but since we're
            // choosing R pseudorandomly it won't occur.
            .mark::<(Public, NonZero)>()
            .expect("computationally unreachable");

        let mut s = s!({ r.invert() } * (m + R_x * x))
            // Given R_x is determined by x and m through a hash, reaching
            // (m + R_x * x) = 0 is intractable.
            .mark::<NonZero>()
            .expect("computationally unreachable");

        // s values must be low (less than half group order), otherwise signatures
        // would be malleable i.e. (R,s) and (R,-s) would both be valid signatures.
        s.conditional_negate(s.is_high());

        Signature {
            R_x,
            s: s.mark::<Public>(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;
    use secp256kfun::TEST_SOUNDNESS;

    #[test]
    fn repeated_sign_and_verify() {
        let ecdsa = ECDSA::from_tag(b"test");
        for _ in 0..20 {
            let mut message = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut message);
            let secret_key = Scalar::random(&mut rand::thread_rng());
            let public_key = g!(secret_key * G).mark::<Normal>();
            let sig = ecdsa.sign(&secret_key, &message, Derivation::Deterministic);
            assert!(ecdsa.verify(&public_key, &message, &sig))
        }
    }

    #[test]
    fn low_s() {
        for _ in 0..TEST_SOUNDNESS {
            let ecdsa = ECDSA::from_tag(b"test");
            let ecdsa_enforce_low_s = ECDSA::from_tag(b"test").enforce_low_s();
            let mut message = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut message);
            let secret_key = Scalar::random(&mut rand::thread_rng());
            let public_key = g!(secret_key * G);
            let mut sig = ecdsa.sign(&secret_key, &message, Derivation::Deterministic);
            assert!(ecdsa.verify(&public_key, &message, &sig));
            assert!(ecdsa_enforce_low_s.verify(&public_key, &message, &sig));
            sig.s = -sig.s;
            assert!(!ecdsa_enforce_low_s.verify(&public_key, &message, &sig));
            assert!(ecdsa.verify(&public_key, &message, &sig));
        }
    }
}
