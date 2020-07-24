use crate::{
    fun::{
        derive_nonce, g,
        hash::{tagged_hash, Derivation, HashAdd, NonceHash},
        marker::*,
        s, Point, Scalar, Slice, XOnly,
    },
    KeyPair, Signature,
};
use digest::{generic_array::typenum::U32, Digest};

/// An instance of a [`BIP-340`] style Schnorr signature scheme.
///
/// Each instance is defined by its:
/// - `G`: Public generator (usually [`G`])
/// - `challenge_hash`: The hash function instance that is used to produce the [_Fiat-Shamir_] challenge.
/// - `nonce_hash`: The [`NonceHash<H>`] used to hash the signing inputs (and perhaps additional randomness) to produce the secret nonce.
///
/// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [`G`]: crate::fun::G
/// [`NonceHash<H>`]: crate::fun::hash::NonceHash
/// [`BIP-340`]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
pub struct Schnorr<GT = BasePoint, CH = sha2::Sha256, N = NonceHash<sha2::Sha256>> {
    /// The generator point the Schnorr signature scheme is defined with.
    pub G: Point<GT>,
    /// The hash used to produce the [_Fiat-Shamir_] challenge
    /// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
    pub challenge_hash: CH,
    /// The [`NonceHash<H>`] to produce nonces when signing. If you don't need a signing instance this can just be `()`.
    ///
    /// [`NonceHash<H>`]: crate::fun::hash::NonceHash
    pub nonce_hash: N,
}

impl Default for Schnorr {
    /// The default is just `Schnorr::from_tag("BIP340")`.
    fn default() -> Self {
        Schnorr::from_tag(b"BIP340")
    }
}

impl Schnorr {
    /// Generates a `Schnorr` instance from a tag.
    /// The instance will have its `challenge_hash` and `nonce_hash` derived from the tag and use the standard value of [`G`].
    ///
    /// [`G`]: crate::fun::G
    ///
    /// # Examples
    ///
    /// ```
    /// # use schnorr_fun::Schnorr;
    /// // An instance for your own protocol
    /// let my_schnorr = Schnorr::from_tag(b"my-domain");
    /// // An instance compatible with Bitcoin
    /// let bitcoin_schnorr = Schnorr::from_tag(b"BIP340");
    pub fn from_tag(tag: &[u8]) -> Self {
        Schnorr {
            G: crate::fun::G.clone(),
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
    /// [`Point`]: crate::fun::Point
    /// [`EvenY`]: crate::fun::marker::EvenY
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
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{marker::*, Scalar},
    ///     Derivation, Schnorr,
    /// };
    /// let schnorr = Schnorr::from_tag(b"my-domain");
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let message = b"Chancellor on brink of second bailout for banks"
    ///     .as_ref()
    ///     .mark::<Public>();
    /// // sign a message deterministically
    /// let signature = schnorr.sign(&keypair, message, Derivation::Deterministic);
    /// // sign a message using auxiliary randomness (preferred)
    /// let signature = schnorr.sign(&keypair, message, Derivation::rng(&mut rand::thread_rng()));
    /// ```
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
    /// Produces the Fiat-Shamir challenge for a Schnorr signature in the form specified by BIP-340.
    ///
    /// Concretely computes the hash `H(R || X || m)`.
    ///
    /// # Example
    ///
    /// Here's how you could use this to roll your own signatures.
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{marker::*, s, Scalar, XOnly},
    ///     Schnorr, Signature,
    /// };
    /// let schnorr = Schnorr::from_tag(b"my-domain");
    /// let message = b"we rolled our own sign!".as_ref().mark::<Public>();
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let mut r = Scalar::random(&mut rand::thread_rng());
    /// let R = XOnly::<SquareY>::from_scalar_mul(&schnorr.G, &mut r);
    /// let challenge = schnorr.challenge(&R, keypair.public_key(), message);
    /// let s = s!(r + challenge * { keypair.secret_key() });
    /// let signature = Signature { R, s };
    /// assert!(schnorr.verify(&keypair.verification_key(), message, &signature));
    /// ```
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

    /// Verifies a signature on a message under a given public key.  Note that a full
    /// `Point<EvenY,..>` is passed in rather than a `XOnly<EvenY,..>` because it's more efficient
    /// for repeated verification (where as `XOnly<EvenY,..>` is more efficient for repeated
    /// signing).
    ///
    /// For an example see the [Synopsis](crate#synopsis)
    #[must_use]
    pub fn verify(
        &self,
        public_key: &Point<EvenY, impl Secrecy>,
        message: Slice<'_, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
    ) -> bool {
        let X = public_key;
        let (R, s) = signature.as_tuple();
        let c = self.challenge(R, &X.to_xonly(), message);
        g!(s * self.G - c * X) == *R
    }

    /// _Anticipates_ a Schnorr signature given the nonce `R` that will be used ahead of time.
    /// Deterministically returns the group element that corresponds to the scalar value of the
    /// signature. i.e `R + c * X`
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
    use crate::fun::{hash::Derivation, TEST_SOUNDNESS};

    crate::fun::test_plus_wasm! {
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
