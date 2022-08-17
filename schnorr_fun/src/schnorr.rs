use crate::{
    fun::{
        derive_nonce,
        digest::{generic_array::typenum::U32, Digest},
        g,
        hash::{HashAdd, Tagged},
        marker::*,
        nonce::{AddTag, NonceGen},
        s, Point, Scalar, XOnly, XOnlyKeyPair, G,
    },
    Message, Signature,
};

/// An instance of a [BIP-340] style Schnorr signature scheme.
///
/// Each instance is defined by its:
/// - `challenge_hash`: The hash function instance that is used to produce the [_Fiat-Shamir_] challenge.
/// - `nonce_gen`: The [`NonceGen`] used to hash the signing inputs (and perhaps additional randomness) to produce the secret nonce.
///
/// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [`NonceGen<H>`]: crate::fun::hash::NonceGen
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
#[derive(Clone)]
pub struct Schnorr<CH, NG = ()> {
    /// The [`NonceGen`] used to generate nonces.
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    nonce_gen: NG,
    /// The challenge hash
    challenge_hash: CH,
}

impl<H: Digest<OutputSize = U32> + Tagged> Schnorr<H, ()> {
    /// Create a new instance that can only verify signatures.
    ///
    /// # Example
    ///
    /// ```
    /// use schnorr_fun::Schnorr;
    /// use sha2::Sha256;
    ///
    /// let schnorr = Schnorr::<Sha256>::verify_only();
    /// ```
    pub fn verify_only() -> Self {
        Self::new(())
    }
}

impl<CH, NG> Schnorr<CH, NG>
where
    CH: Digest<OutputSize = U32> + Tagged,
    NG: AddTag,
{
    /// Creates a instance capable of signing and verifying.
    ///
    ///
    /// # Examples
    /// ```
    /// use rand::rngs::ThreadRng;
    /// use schnorr_fun::{
    ///     nonce::{Deterministic, GlobalRng, Synthetic},
    ///     Schnorr,
    /// };
    /// use sha2::Sha256;
    /// // Use synthetic nonces (preferred)
    /// let nonce_gen = Synthetic::<Sha256, GlobalRng<ThreadRng>>::default();
    /// // Use deterministic nonces.
    /// let nonce_gen = Deterministic::<Sha256>::default();
    /// let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
    /// // then go and sign/verify messages!
    /// ```
    pub fn new(nonce_gen: NG) -> Self {
        let nonce_gen = nonce_gen.add_tag("BIP0340");
        Self {
            nonce_gen,
            challenge_hash: CH::default().tagged("BIP0340/challenge".as_bytes()),
        }
    }
}

impl<CH: Default + Tagged + Digest<OutputSize = U32>, NG: Default + AddTag> Default
    for Schnorr<CH, NG>
{
    /// Returns a Schnorr instance tagged in the default way according to BIP340.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{nonce::Deterministic, Schnorr};
    /// use sha2::Sha256;
    ///
    /// let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
    /// ```
    fn default() -> Self {
        Self::new(NG::default())
    }
}

impl<NG, CH> Schnorr<CH, NG>
where
    CH: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    /// Sign a message using a secret key and a particular nonce derivation scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// # use schnorr_fun::{
    /// #     Message,
    /// #     fun::{marker::*, Scalar},
    /// # };
    /// # let schnorr = schnorr_fun::test_instance!();
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let message = Message::<Public>::plain(
    ///     "times-of-london",
    ///     b"Chancellor on brink of second bailout for banks",
    /// );
    /// let signature = schnorr.sign(&keypair, message);
    /// assert!(schnorr.verify(&keypair.public_key().to_point(), message, &signature));
    /// ```
    pub fn sign(&self, keypair: &XOnlyKeyPair, message: Message<'_, impl Secrecy>) -> Signature {
        let (x, X) = keypair.as_tuple();

        let mut r = derive_nonce!(
            nonce_gen => self.nonce_gen(),
            secret => x,
            public => [X, message]
        );

        let R = XOnly::from_scalar_mul(&G, &mut r);
        let c = self.challenge(R, X, message);
        let s = s!(r + c * x).mark::<Public>();

        Signature { R, s }
    }

    /// Returns the [`NonceGen`] instance being used to genreate nonces.
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    pub fn nonce_gen(&self) -> &NG {
        &self.nonce_gen
    }
}

impl<NG, CH: Digest<OutputSize = U32> + Clone> Schnorr<CH, NG> {
    /// Returns the challenge hash being used to sign/verify signatures
    pub fn challenge_hash(&self) -> CH {
        self.challenge_hash.clone()
    }

    /// Create a new signing keypair.
    ///
    /// Short form of [`XOnlyKeyPair::new`].
    pub fn new_keypair(&self, sk: Scalar) -> XOnlyKeyPair {
        XOnlyKeyPair::new(sk)
    }

    /// Produces the Fiat-Shamir challenge for a Schnorr signature in the form specified by [BIP-340].
    ///
    /// Concretely computes the hash `H(R || X || m)`. The [`Secrecy`] of the message is inherited
    /// by the returned scalar.
    ///
    /// # Example
    ///
    /// Here's how you could use this to roll your own signatures.
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{marker::*, s, Scalar, XOnly, G},
    ///     Message, Schnorr, Signature,
    /// };
    /// # let schnorr = schnorr_fun::test_instance!();
    /// let message = Message::<Public>::plain("my-app", b"we rolled our own schnorr!");
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let mut r = Scalar::random(&mut rand::thread_rng());
    /// let R = XOnly::from_scalar_mul(G, &mut r);
    /// let challenge = schnorr.challenge(R, keypair.public_key(), message);
    /// let s = s!(r + challenge * { keypair.secret_key() });
    /// let signature = Signature { R, s };
    /// assert!(schnorr.verify(&keypair.public_key().to_point(), message, &signature));
    /// ```
    ///
    /// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    /// [`Secrecy`]: secp256kfun::marker::Secrecy
    pub fn challenge<S: Secrecy>(&self, R: XOnly, X: XOnly, m: Message<'_, S>) -> Scalar<S, Zero> {
        let hash = self.challenge_hash.clone();
        let challenge = Scalar::from_hash(hash.add(R).add(X).add(&m));

        challenge
            // Since the challenge pre-image is adversarially controlled we
            // conservatively allow for it to be zero
            .mark::<Zero>()
            // The resulting challenge should take the secrecy of the message
            .mark::<S>()
    }

    /// Verifies a signature on a message under a given public key.
    ///
    /// Note that a full `Point<EvenY,..>` is passed in rather than a `XOnly` because it's more
    /// efficient for repeated verification (where as `XOnly` is more efficient for repeated
    /// signing).
    ///
    /// # Example
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{marker::*, nonce, Scalar, hex, Point},
    ///     Message, Schnorr, Signature
    /// };
    /// use sha2::Sha256;
    /// use core::str::FromStr;
    ///
    /// let schnorr = Schnorr::<Sha256>::verify_only();
    /// let public_key = Point::<EvenY, Public>::from_str("d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9").unwrap();
    /// let signature = Signature::<Public>::from_str("00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4").unwrap();
    /// let message = hex::decode("4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703").unwrap();
    /// assert!(schnorr.verify(&public_key, Message::<Secret>::raw(&message), &signature));
    ///
    /// // We could also say the message is secret if we don't want to leak which message we are
    /// // verifying through execution time.
    /// assert!(schnorr.verify(&public_key, Message::<Secret>::raw(&message), &signature));
    /// ```
    #[must_use]
    pub fn verify(
        &self,
        public_key: &Point<EvenY, impl Secrecy>,
        message: Message<'_, impl Secrecy>,
        signature: &Signature<impl Secrecy>,
    ) -> bool {
        let X = public_key;
        let (R, s) = signature.as_tuple();
        let c = self.challenge(R, X.to_xonly(), message);
        let R_implied = g!(s * G - c * X).mark::<Normal>();
        R_implied == R
    }

    /// _Anticipates_ a Schnorr signature given the nonce `R` that will be used ahead of time.
    /// Deterministically returns the group element that corresponds to the scalar value of the
    /// signature. i.e `R + c * X`
    pub fn anticipate_signature(
        &self,
        X: &Point<EvenY, impl Secrecy>,
        R: &Point<EvenY, impl Secrecy>,
        m: Message<'_, impl Secrecy>,
    ) -> Point<Jacobian, Public, Zero> {
        let c = self.challenge(R.to_xonly(), X.to_xonly(), m);
        g!(R + c * X)
    }
}

#[cfg(test)]
pub mod test {
    use crate::fun::nonce::Deterministic;

    use super::*;
    use crate::fun::proptest::prelude::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn deterministic_nonces_for_different_message_kinds() {
        use core::str::FromStr;
        use sha2::Sha256;
        let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
        let x =
            Scalar::from_str("18451f9e08af9530814243e202a4a977130e672079f5c14dcf15bd4dee723072")
                .unwrap();
        let keypair = schnorr.new_keypair(x);
        assert_ne!(
            schnorr.sign(&keypair, Message::<Public>::raw(b"foo")).R,
            schnorr
                .sign(&keypair, Message::<Public>::plain("one", b"foo"))
                .R
        );
        assert_ne!(
            schnorr
                .sign(&keypair, Message::<Public>::plain("one", b"foo"))
                .R,
            schnorr
                .sign(&keypair, Message::<Public>::plain("two", b"foo"))
                .R
        );

        // make sure deterministic signatures don't change
        assert_eq!(schnorr.sign(&keypair, Message::<Public>::raw(b"foo")), Signature::<Public>::from_str("fe9e5d0319d5d221988d6fd7fe1c4bedd2fb4465f592f1002f461503332a266977bb4a0b00c00d07072c796212cbea0957ebaaa5139143761c45d997ebe36cbe").unwrap());
        assert_eq!(schnorr.sign(&keypair, Message::<Public>::plain("one", b"foo")), Signature::<Public>::from_str("2fcf6fd140bbc4048e802c62f028e24f6534e0d15d450963265b67eead774d8b4aa7638bec9d70aa60b97e86bc4a60bf43ad2ff58e981ee1bba4f45ce02ff2c0").unwrap());
    }

    proptest! {

        #[test]
        fn anticipated_signature_on_should_correspond_to_actual_signature(sk in any::<Scalar>()) {
            let schnorr = crate::test_instance!();
            let keypair = schnorr.new_keypair(sk);
            let msg = Message::<Public>::plain(
                "test",
                b"Chancellor on brink of second bailout for banks",
            );
            let signature = schnorr.sign(&keypair, msg);
            let anticipated_signature = schnorr.anticipate_signature(
                &keypair.public_key().to_point(),
                &signature.R.to_point(),
                msg,
            );

            assert_eq!(
                anticipated_signature,
                g!(signature.s * G),
                "should anticipate the same value as actual signature"
            )
        }

        #[test]
        fn sign_deterministic(s1 in any::<Scalar>(), s2 in any::<Scalar>()) {
            let schnorr = crate::test_instance!();
            let keypair_1 = schnorr.new_keypair(s1);
            let keypair_2 = schnorr.new_keypair(s2);
            let msg_atkdwn = Message::<Public>::plain("test", b"attack at dawn");
            let msg_rtrtnoon = Message::<Public>::plain("test", b"retreat at noon");
            let signature_1 = schnorr.sign(&keypair_1, msg_atkdwn);
            let signature_2 = schnorr.sign(&keypair_1, msg_atkdwn);
            let signature_3 = schnorr.sign(&keypair_1, msg_rtrtnoon);
            let signature_4 = schnorr.sign(&keypair_2, msg_atkdwn);

            assert!(schnorr.verify(&keypair_1.public_key().to_point(), msg_atkdwn, &signature_1));
            assert_eq!(signature_1, signature_2);
            if keypair_1 != keypair_2 {
                assert_ne!(signature_3.R, signature_1.R);
                assert_ne!(signature_1.R, signature_4.R);
            }
        }
    }
}
