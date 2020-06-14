//! Generate and verify Schnorr signatures on secp256k1
//!
//! Schnorr signatures were introduced by their namesake in [1]. This
//! implementation is based on Bitcoin's [BIP-340][2] specification, but is
//! flexible and can be used as a general purpose Schnorr signature scheme.
//!
//! ## Examples
//!
//! ```
//! use schnorr_fun::{
//!     fun::{hash::Derivation, marker::*, Scalar},
//!     Schnorr,
//! };
//!
//! // Create a BIP-340 compatible instance
//! let schnorr = Schnorr::from_tag(b"bip340");
//! // Or create an instance for your own protocol
//! let schnorr = Schnorr::from_tag(b"my-domain-separator");
//! // Generate your public/private key-pair
//! let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! let message = b"Chancellor on brink of second bailout for banks"
//!     .as_ref()
//!     .mark::<Public>();
//! // Sign the message with our keypair
//! let signature = schnorr.sign(&keypair, message, Derivation::rng(&mut rand::thread_rng()));
//! // Get the verifier's key
//! let verification_key = keypair.verification_key();
//! // Check it's valid 🍿
//! assert!(schnorr.verify(&verification_key, message, &signature));
//! ```
//!
//! [1]: https://d-nb.info/1156214580/34
//! [2]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki

#![no_std]
#![allow(non_snake_case)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

use digest::{generic_array::typenum::U32, Digest};
use fun::{
    derive_nonce, g,
    hash::{tagged_hash, Derivation, Hash, NonceHash},
    marker::*,
    s, Point, Scalar, Slice, XOnly,
};
pub use secp256kfun as fun;
mod signature;
pub use signature::Signature;
pub mod adaptor;
mod keypair;
pub use keypair::KeyPair;

/// An instance of the Schnorr signature scheme.
///
/// Each instance is defined by its
/// - `G`: Public base point
/// - `challenge_hash`: The hash function instance that is used to produce the [_Fiat-Shamir_] challenge.
/// - `nonce_hash`: The hash used to hash the signing inputs (and perhaps additional randomness) to produce the secret nonce.
///
/// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
pub struct Schnorr<GT = BasePoint, CH = sha2::Sha256, N = NonceHash<sha2::Sha256>> {
    pub G: Point<GT>,
    pub challenge_hash: CH,
    pub nonce_hash: N,
}

impl Schnorr {
    //! Generates a `Schnorr` instance from a tag.
    //! The instance will have its `challenge_hash` and `nonce_hash` derived from the tag and use the standard value of [`G`].
    //!
    //! [`G`]: fun::G
    pub fn from_tag(tag: &[u8]) -> Self {
        Schnorr {
            G: fun::G.clone(),
            challenge_hash: tagged_hash(&[tag, b"/challenge"].concat()),
            nonce_hash: NonceHash::from_tag(tag),
        }
    }
}

impl<CH, NH> Schnorr<CH, NH> {
    /// Converts a non-zero scalar to a key-pair by interpreting it as a secret key.
    ///
    /// **The secret key in the resulting key is not guaranteed to be the same
    /// as the input**. For half the input values the result will be the
    /// negation of it. This happens because the corresponding [`Point`] may not
    /// have an y-coordinate that is even (see [`EvenY`])
    ///
    /// [`Point`]: fun::Point
    /// [`EvenY`]: fun::marker::EvenY
    pub fn new_keypair(&self, mut sk: Scalar) -> KeyPair {
        let pk = XOnly::from_scalar_mul(&self.G, &mut sk);
        KeyPair { sk, pk }
    }
}

impl<GT, CH, NH> Schnorr<GT, CH, NonceHash<NH>>
where
    CH: Digest<OutputSize = U32> + Clone,
    NH: Digest<OutputSize = U32> + Clone,
{
    /// Sign a message using a secret key and a particular nonce derivation scheme.
    ///
    /// # Examples
    pub fn sign(
        &self,
        keypair: &KeyPair,
        message: Slice<'_, impl Secrecy>,
        derivation: Derivation,
    ) -> Signature {
        let (x, X) = keypair.as_tuple();

        let mut r = derive_nonce!(
            nonce_hash => self.nonce_hash,
            derivation => derivation,
            secret => x,
            public => [X, message]
        );

        let R = XOnly::<SquareY>::from_scalar_mul(&self.G, &mut r);
        let c = self.challenge(&R, X, message);
        let s = s!(r + c * x).mark::<Public>();

        Signature { R, s }
    }
}

impl<GT, CH: Digest<OutputSize = U32> + Clone, NH> Schnorr<GT, CH, NH> {
    /// Produces the Fiat-Shamir challenge for a Schnorr signature in the form
    /// specified by BIP-340.
    ///
    /// Concretely computes the hash `H(R || X || m)`.
    pub fn challenge<S: Secrecy>(
        &self,
        R: &XOnly<SquareY>,
        X: &XOnly<EvenY>,
        m: Slice<'_, S>,
    ) -> Scalar<S, Zero> {
        let hash = self.challenge_hash.clone();
        let challenge = Scalar::from_hash(hash.add(R).add(X).add(&m));
        challenge
            // Since the challenge pre-image is adversarially controlled we
            // conservatively allow for it to be zero
            .mark::<Zero>()
            // The resulting challenge should take the secrecy of the message
            .mark::<S>()
    }

    #[must_use]
    pub fn verify(
        &self,
        public_key: &Point<EvenY, impl Secrecy, NonZero>,
        message: Slice<'_, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
    ) -> bool {
        let X = public_key;
        let (R, s) = signature.as_tuple();
        let c = self.challenge(R, &X.to_xonly(), message);
        g!(s * self.G - c * X) == *R
    }

    /// Anticipates a Schnorr signature given the nonce `R` that will be used ahead
    /// of time.  Deterministically returns the group element that corresponds to
    /// the scalar value of the signature. i.e `R + c * X`
    pub fn anticipate_signature(
        &self,
        X: &Point<EvenY, impl Secrecy>,
        R: &Point<SquareY, impl Secrecy>,
        m: Slice<'_, impl Secrecy>,
    ) -> Point<Jacobian, Public, Zero> {
        let c = self.challenge(&R.to_xonly(), &X.to_xonly(), m);
        g!(R + c * X)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256kfun::{hash::Derivation, TEST_SOUNDNESS};

    fun::test_plus_wasm! {
        fn anticipated_signature_on_should_correspond_to_actual_signature() {
            for _ in 0..TEST_SOUNDNESS {
                let schnorr = Schnorr::from_tag(b"secp256kfun-test/schnorr");
                let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let msg = b"Chancellor on brink of second bailout for banks".as_ref().mark::<Public>();
                let signature = schnorr.sign(&keypair,msg, Derivation::Deterministic);
                let anticipated_signature = schnorr.anticipate_signature(
                    &keypair.verification_key(),
                    &signature.R.to_point(),
                    msg,
                );

                dbg!(g!(signature.s * schnorr.G));
                dbg!(g!(-signature.s * schnorr.G));
                dbg!(&anticipated_signature);
                assert_eq!(
                    anticipated_signature,
                    g!(signature.s * schnorr.G),
                    "should anticipate the same value as actual signature"
                )
            }
        }

        fn sign_deterministic() {
            for _ in 0..TEST_SOUNDNESS {
                let schnorr = Schnorr::from_tag(b"secp256kfun-test/schnorr");
                let keypair_1 = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let keypair_2 = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let msg_atkdwn = b"attack at dawn".as_ref().mark::<Public>();
                let msg_rtrtnoon = b"retreat at noon".as_ref().mark::<Public>();
                let signature_1 = schnorr.sign(&keypair_1, msg_atkdwn, Derivation::Deterministic);
                let signature_2 = schnorr.sign(&keypair_1, msg_atkdwn, Derivation::Deterministic);
                let signature_3 = schnorr.sign(&keypair_1, msg_rtrtnoon, Derivation::Deterministic);
                let signature_4 = schnorr.sign(&keypair_2, msg_atkdwn, Derivation::Deterministic);

                assert!(schnorr.verify(
                    &keypair_1.verification_key(),
                    msg_atkdwn,
                    &signature_1
                ));
                assert_eq!(signature_1, signature_2);
                assert_ne!(signature_3.R, signature_1.R);
                assert_ne!(signature_1.R, signature_4.R);
            }
        }
    }
}
