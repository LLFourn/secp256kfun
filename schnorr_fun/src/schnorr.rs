use crate::{
    fun::{
        self, derive_nonce,
        digest::{generic_array::typenum::U32, Digest},
        g,
        hash::{AddTag, HashAdd, Tagged},
        marker::*,
        nonce::{NonceChallengeBundle, NonceGen},
        s, Point, Scalar, Slice, XOnly,
    },
    KeyPair, Signature,
};

/// An instance of a [BIP-340] style Schnorr signature scheme.
///
/// Each instance is defined by its:
/// - `G`: Public generator (usually [`G`])
/// - `challenge_hash`: The hash function instance that is used to produce the [_Fiat-Shamir_] challenge.
/// - `nonce_gen`: The [`NonceGen`] used to hash the signing inputs (and perhaps additional randomness) to produce the secret nonce.
///
/// [_Fiat-Shamir_]: https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic
/// [`G`]: crate::fun::G
/// [`NonceGen<H>`]: crate::fun::hash::NonceGen
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
#[derive(Clone)]
pub struct Schnorr<CH, NG = (), GT = BasePoint> {
    /// The generator point the Schnorr signature scheme is defined with.
    G: Point<GT>,
    /// The [`NonceGen`] and NonceChalengeBundlesh.
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    nonce_challenge_bundle: NonceChallengeBundle<CH, NG>,
}

/// Describes the kind of messages that will be signed with a [`Schnorr`] instance.
///
/// [`Schnorr`]: crate::Schnorr
#[derive(Debug, Clone, Copy)]
pub enum MessageKind {
    /// Sign a pre-hashed message.
    /// This is used by [BIP-341] to authorize transactions.
    /// If you also want to sign hashed messages in your applicatin you should use a [_tagged hash_] specific to your application.
    ///
    /// [BIP-341]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
    /// [_tagged hash_]: crate::fun::hash::Tagged
    Prehashed,
    /// Sign an ordinary variable length message.
    Plain {
        /// You must provide a tag to separate signatures from your application
        /// from other applications. If two [`Schnorr`] instances are created
        /// with a different `tag` then a signature valid for one will never be valid for the other.
        tag: &'static str,
    },
}

impl<H: Digest<OutputSize = U32> + Tagged> Schnorr<H, (), BasePoint> {
    /// Create a new instance that doesn't
    ///
    /// Creates a `Schnorr` instance to verifying signatures of a particular [`MessageKind`].
    /// The instance will use the standard value of [`G`].
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{MessageKind, Schnorr};
    /// // An instance that can verify Bitcoin Taproot transactions
    /// let taproot_schnorr = Schnorr::<sha2::Sha256>::verify_only(MessageKind::Prehashed);
    /// // An instance for verifying transactions in your application
    /// let myapp_schnorr = Schnorr::<sha2::Sha256>::verify_only(MessageKind::Plain { tag: "myapp" });
    /// ```
    /// [`MessageKind`]: crate::MessageKind
    /// [`G`]: crate::fun::G
    pub fn verify_only(msgkind: MessageKind) -> Self {
        Self::new((), msgkind)
    }
}

impl<CH, NG> Schnorr<CH, NG, BasePoint>
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
    ///     nonce::{self, Deterministic},
    ///     MessageKind, Schnorr,
    /// };
    /// use sha2::Sha256;
    /// // Use synthetic nonces (preferred)
    /// let nonce_gen = nonce::from_global_rng::<Sha256, ThreadRng>();
    /// // Use deterministic nonces.
    /// let nonce_gen = Deterministic::<Sha256>::default();
    /// // Sign pre-hashed messges as in BIP-341.
    /// let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone(), MessageKind::Prehashed);
    /// // Sign ordinary messages in your own application.
    /// let schnorr = Schnorr::<Sha256, _>::new(nonce_gen, MessageKind::Plain { tag: "my-app" });
    /// ```
    pub fn new(nonce_gen: NG, msgkind: MessageKind) -> Self {
        let mut nonce_challenge_bundle = NonceChallengeBundle {
            challenge_hash: CH::default(),
            nonce_gen,
        }
        .add_protocol_tag("BIP340");

        if let MessageKind::Plain { tag } = msgkind {
            nonce_challenge_bundle = nonce_challenge_bundle.add_application_tag(tag);
        }

        Self {
            G: fun::G.clone(),
            nonce_challenge_bundle,
        }
    }
}

impl<NG, CH, GT> Schnorr<CH, NG, GT>
where
    CH: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    /// Sign a message using a secret key and a particular nonce derivation scheme.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{marker::*, Scalar},
    ///     MessageKind,
    /// };
    /// # let schnorr = schnorr_fun::test_instance!();
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let message = b"Chancellor on brink of second bailout for banks"
    ///     .as_ref()
    ///     .mark::<Public>();
    /// let signature = schnorr.sign(&keypair, message);
    /// assert!(schnorr.verify(&keypair.verification_key(), message, &signature));
    /// ```
    pub fn sign(&self, keypair: &KeyPair, message: Slice<'_, impl Secrecy>) -> Signature {
        let (x, X) = keypair.as_tuple();

        let mut r = derive_nonce!(
            nonce_gen => self.nonce_gen(),
            secret => x,
            public => [X, message]
        );

        let R = XOnly::<SquareY>::from_scalar_mul(&self.G, &mut r);
        let c = self.challenge(&R, X, message);
        let s = s!(r + c * x).mark::<Public>();

        Signature { R, s }
    }

    /// Returns the [`NonceGen`] instance being used to genreate nonces.
    ///
    /// [`NonceGen`]: crate::nonce::NonceGen
    pub fn nonce_gen(&self) -> &NG {
        &self.nonce_challenge_bundle.nonce_gen
    }
}

impl<NG, CH: Digest<OutputSize = U32> + Clone, GT> Schnorr<CH, NG, GT> {
    /// Returns the generator point being used for the scheme.
    pub fn G(&self) -> &Point<GT> {
        &self.G
    }

    /// Returns the challenge hash being used to sign/verify signatures
    pub fn challenge_hash(&self) -> CH {
        self.nonce_challenge_bundle.challenge_hash.clone()
    }
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
    /// # let schnorr = schnorr_fun::test_instance!();
    /// let message = b"we rolled our own sign!".as_ref().mark::<Public>();
    /// let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let mut r = Scalar::random(&mut rand::thread_rng());
    /// let R = XOnly::<SquareY>::from_scalar_mul(schnorr.G(), &mut r);
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
        let hash = self.nonce_challenge_bundle.challenge_hash.clone();
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
pub mod test {
    use super::*;
    use crate::fun::TEST_SOUNDNESS;
    crate::fun::test_plus_wasm! {

        fn anticipated_signature_on_should_correspond_to_actual_signature() {
            for _ in 0..TEST_SOUNDNESS {
                let schnorr = crate::test_instance!();
                let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let msg = b"Chancellor on brink of second bailout for banks".as_ref().mark::<Public>();
                let signature = schnorr.sign(&keypair,msg);
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
            let schnorr = crate::test_instance!();
            for _ in 0..TEST_SOUNDNESS {
                let keypair_1 = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let keypair_2 = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
                let msg_atkdwn = b"attack at dawn".as_ref().mark::<Public>();
                let msg_rtrtnoon = b"retreat at noon".as_ref().mark::<Public>();
                let signature_1 = schnorr.sign(&keypair_1, msg_atkdwn);
                let signature_2 = schnorr.sign(&keypair_1, msg_atkdwn);
                let signature_3 = schnorr.sign(&keypair_1, msg_rtrtnoon);
                let signature_4 = schnorr.sign(&keypair_2, msg_atkdwn);

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
