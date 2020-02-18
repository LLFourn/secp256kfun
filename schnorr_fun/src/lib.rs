//! Generate and verify Schnorr signatures on secp256k1
//!
//! Schnorr signatures were introduced by their namesake in [1]. This implementation
//! implements the scheme according to Bitcoin's [BIP-340][2] specification, but
//! it can be used as a general Schnorr signature scheme.
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
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    derive_nonce, g,
    hash::{tagged_hash, Derivation, Hash, NonceHash},
    marker::*,
    s, Point, Scalar, XOnly,
};
mod signature;
pub use signature::Signature;
pub mod adaptor;

pub struct Schnorr<GT = BasePoint, CH = sha2::Sha256, N = NonceHash<sha2::Sha256>> {
    pub G: Point<GT>,
    pub challenge_hash: CH,
    pub nonce_hash: N,
}

impl Schnorr {
    pub fn from_tag(tag: &[u8]) -> Self {
        Schnorr {
            G: secp256kfun::G.clone(),
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
    /// negation of it. This happens because the corresponding [crate::Point] may not
    /// have an y-coordinate that is even (see [EvenY](secp256kfun::marker::EvenY))
    pub fn keygen(&self, mut sk: Scalar) -> KeyPair {
        let pk = XOnly::from_scalar_mul(&self.G, &mut sk);

        KeyPair { sk, pk }
    }
}

impl<GT, CH, NH> Schnorr<GT, CH, NonceHash<NH>>
where
    CH: Digest<OutputSize = U32> + Clone,
    NH: Digest<OutputSize = U32> + Clone,
{
    /// Sign a message using a secret key. Schnorr signatures require
    /// unpredictable secret values called _nonces_.
    pub fn sign(&self, keypair: &KeyPair, message: &[u8], derivation: Derivation) -> Signature {
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
    pub fn challenge(
        &self,
        R: &XOnly<SquareY>,
        X: &XOnly<EvenY>,
        m: &[u8],
    ) -> Scalar<Public, Zero> {
        let hash = self.challenge_hash.clone();
        let challenge = Scalar::from_hash(hash.add(R).add(X).add(m));
        // Since the challenge pre-image is adversarially controlled we
        // conservatively allow for it to be zero
        challenge.mark::<(Zero, Public)>()
    }

    #[must_use]
    pub fn verify(
        &self,
        public_key: &Point<EvenY, Public, NonZero>,
        message: &[u8],
        signature: &Signature<impl Secrecy>,
    ) -> bool {
        let X = public_key;
        let (R, s) = signature.as_tuple();
        let c = self.challenge(R, &X.to_xonly(), message);
        g!(s * self.G - c * X) == *R
    }

    /// Anticipates a Schnorr signature given the nonce `R` that will be used ahead
    /// of time.  Deterministically returns the group element that corresponds to
    /// the scalar value of the signature. i.e `R + e * X`
    pub fn anticipate_signature(
        &self,
        X: &Point<EvenY, impl Secrecy>,
        R: &Point<SquareY, impl Secrecy>,
        m: &[u8],
    ) -> Point<Jacobian, Public, Zero> {
        let c = self.challenge(&R.to_xonly(), &X.to_xonly(), m);
        g!(R + c * X)
    }
}

/// A secret and public key-pair for generating Schnorr signatures.
///
/// The `KeyPair` struct is exists because it is more efficient to pre-compute
/// the public key and pass it in rather pass it in when signing with the same
/// key multiple times.
pub struct KeyPair {
    sk: Scalar,
    pk: XOnly<EvenY>,
}

impl KeyPair {
    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &XOnly<EvenY> {
        &self.pk
    }

    /// Gets a reference to the key-pair as a tuple
    /// # Example
    /// ```
    /// # use secp256kfun::{G};
    /// # use schnorr_fun::KeyPair;
    /// # let keypair = KeyPair::random(G, &mut rand::thread_rng());
    /// let (sec_key, pub_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, &XOnly<EvenY>) {
        (&self.sk, &self.pk)
    }

    pub fn random<R: CryptoRng + RngCore>(
        G: &Point<BasePoint, Public, NonZero>,
        rng: &mut R,
    ) -> KeyPair {
        let mut sk = Scalar::random(rng);
        let pk = XOnly::from_scalar_mul(G, &mut sk);

        Self { sk, pk }
    }

    pub fn verification_key(&self) -> Point<EvenY> {
        self.pk.to_point()
    }
}

impl From<KeyPair> for (Scalar, XOnly<EvenY>) {
    fn from(kp: KeyPair) -> Self {
        (kp.sk, kp.pk)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use secp256kfun::{hash::Derivation, TEST_SOUNDNESS};

    secp256kfun::test_plus_wasm! {
        fn anticipated_signature_on_should_correspond_to_actual_signature() {
            for _ in 0..TEST_SOUNDNESS {
                let schnorr = Schnorr::from_tag(b"secp256kfun-test/schnorr");
                let keypair = schnorr.keygen(Scalar::random(&mut rand::thread_rng()));
                let signature = schnorr.sign(&keypair, b"message", Derivation::Deterministic);
                let anticipated_signature = schnorr.anticipate_signature(
                    &keypair.verification_key(),
                    &signature.R.to_point(),
                    b"message",
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
                let keypair_1 = schnorr.keygen(Scalar::random(&mut rand::thread_rng()));
                let keypair_2 = schnorr.keygen(Scalar::random(&mut rand::thread_rng()));
                let signature_1 = schnorr.sign(&keypair_1, b"attack at dawn", Derivation::Deterministic);
                let signature_2 = schnorr.sign(&keypair_1, b"attack at dawn", Derivation::Deterministic);
                let signature_3 = schnorr.sign(&keypair_1, b"retreat at noon", Derivation::Deterministic);
                let signature_4 = schnorr.sign(&keypair_2, b"attack at dawn", Derivation::Deterministic);

                assert!(schnorr.verify(
                    &keypair_1.verification_key(),
                    b"attack at dawn",
                    &signature_1
                ));
                assert_eq!(signature_1, signature_2);
                assert_ne!(signature_3.R, signature_1.R);
                assert_ne!(signature_1.R, signature_4.R);
            }
        }
    }
}
