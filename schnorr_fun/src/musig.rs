//! The MuSig2 multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! # use schnorr_fun::binonce::NonceKeyPair;
//! use rand_chacha::ChaCha20Rng;
//! use schnorr_fun::{musig, nonce::Deterministic, Message, Schnorr};
//! use sha2::Sha256;
//! // use sha256 with deterministic nonce generation -- be careful!
//! let musig = musig::new_with_deterministic_nonces::<sha2::Sha256>();
//! // use synthetic nonces with randomness from ThredRng -- harder to make a mistake.
//! let musig = musig::new_with_synthetic_nonces::<sha2::Sha256, rand::rngs::ThreadRng>();
//! // create a keypair
//! use schnorr_fun::fun::Scalar;
//! let my_keypair = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! let public_key1 = my_keypair.public_key();
//! # let kp2 = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let public_key2 = kp2.public_key();
//! # let kp3 = musig.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let public_key3 = kp3.public_key();
//! // recieve the public keys of all other participants to form the aggregate key.
//! let agg_key = musig
//!     .new_agg_key(vec![public_key1, public_key2, public_key3])
//!     .into_xonly_key();
//!
//! // create a unique nonce, and send the public nonce to other parties.
//! // ⚠ session_id must be different for every signing attempt
//! let session_id = b"signing-ominous-message-about-banks-attempt-1".as_slice();
//! let mut nonce_rng: ChaCha20Rng =
//!     musig.seed_nonce_rng(&agg_key, &my_keypair.secret_key(), session_id);
//! let my_nonce = musig.gen_nonce(&mut nonce_rng);
//! let my_public_nonce = my_nonce.public();
//! # let p2_nonce = NonceKeyPair::random(&mut rand::thread_rng());
//! # let p2_public_nonce = p2_nonce.public();
//! # let p3_nonce = NonceKeyPair::random(&mut rand::thread_rng());
//! # let p3_public_nonce = p3_nonce.public();
//! // collect the public nonces from the other two parties
//! let nonces = vec![my_public_nonce, p2_public_nonce, p3_public_nonce];
//! let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! // start the signing session
//! let session = musig.start_sign_session(&agg_key, nonces, message);
//! // sign with our single local keypair
//! let my_sig = musig.sign(&agg_key, &session, 0, &my_keypair, my_nonce);
//! # let p2_sig = musig.sign(&agg_key, &session, 1, &kp2, p2_nonce);
//! # let p3_sig = musig.sign(&agg_key, &session, 2, &kp3, p3_nonce);
//! // receive p2_sig and p3_sig from somewhere and check they're valid
//! assert!(musig.verify_partial_signature(&agg_key, &session, 1, p2_sig));
//! assert!(musig.verify_partial_signature(&agg_key, &session, 2, p3_sig));
//! // combine them with ours into the final signature
//! let sig = musig.combine_partial_signatures(&agg_key, &session, [my_sig, p2_sig, p3_sig]);
//! // check it's a valid normal Schnorr signature
//! musig
//!     .schnorr
//!     .verify(&agg_key.agg_public_key(), message, &sig);
//! ```
//!
//! ## Description
//!
//! The MuSig2 multisignature scheme lets you aggregate multiple public keys into a single public
//! key that requires all of the corresponding secret keys to authorize a signature under the aggregate key.
//!
//! See [the excellent paper] for the abstract details of the protocol and security proofs. **⚠ THIS
//! IS EXPERIMENTAL⚠** it is currently compatible with [this
//! version](https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki) of the
//! specification.
//!
//! **⚠ THIS IS EXPERIMENTAL⚠** it is currently compatible with [this PR](https://github.com/jonasnick/bips/pull/37) to the specification.
//! However, we go "off-spec" in a few places especially with regards to nonce generation where we provide our own APIs (that
//! at the time of writing are subject to change).
//!
//! [the excellent paper]: https://eprint.iacr.org/2020/1261.pdf
//! [secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/131
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{adaptor::EncryptedSignature, Message, Schnorr, Signature};
use alloc::vec::Vec;
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tag},
    marker::*,
    nonce::{self, NoNonces, NonceGen},
    rand_core::{RngCore, SeedableRng},
    s, KeyPair, Point, Scalar, G,
};

/// The MuSig context.
pub struct MuSig<H, NG> {
    /// The hash used to compress the key list to 32 bytes.
    pk_hash: H,
    /// The hash used to generate each key's coefficient.
    coeff_hash: H,
    /// The hash used to generate the nonce coefficients.
    nonce_coeff_hash: H,
    /// The instance of the underlying Schnorr context.
    pub schnorr: Schnorr<H, NG>,
    /// The nonce generator used to
    nonce_gen: NG,
}

impl<H, NG> MuSig<H, NG> {
    /// Create a new keypair.
    ///
    /// A shorthand for [`KeyPair::new`].
    pub fn new_keypair(&self, secret_key: Scalar) -> KeyPair {
        KeyPair::new(secret_key)
    }

    /// Gets the nonce generator from the underlying Schnorr instance.
    pub fn nonce_gen(&self) -> &NG {
        &self.nonce_gen
    }

    /// Generate nonces for creating signatures shares.
    ///
    /// ⚠ You must use a CAREFULLY CHOSEN nonce rng, see [`MuSig::seed_nonce_rng`]
    pub fn gen_nonce<R: RngCore>(&self, nonce_rng: &mut R) -> NonceKeyPair {
        NonceKeyPair::random(nonce_rng)
    }
}

impl<H, NG> MuSig<H, NG>
where
    H: Tag + Default,
    NG: Tag + Clone,
{
    /// Create a new MuSig instance from a [`Schnorr`] instance.
    ///
    /// The MuSig instnace will clone and tag the schnorr instance's `nonce_gen` for its own use.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            pk_hash: H::default().tag(b"KeyAgg list"),
            coeff_hash: H::default().tag(b"KeyAgg coefficient"),
            nonce_coeff_hash: H::default().tag(b"MuSig/noncecoef"),
            nonce_gen: schnorr.nonce_gen().clone().tag(b"MuSig"),
            schnorr,
        }
    }
}

impl<H, NG> Default for MuSig<H, NG>
where
    H: Tag + Default,
    NG: Default + Clone + Tag,
{
    fn default() -> Self {
        MuSig::new(Schnorr::<H, NG>::default())
    }
}

/// A list of keys aggregated into a single key.
///
/// Created using [`MuSig::new_agg_key`].
///
/// The `AggKey` can't be serialized but it's very efficient to re-create it from the initial list of keys.
///
/// [`MuSig::new_agg_key`]
#[derive(Debug, Clone)]
pub struct AggKey<T> {
    /// The keys involved in the key aggregation.
    keys: Vec<Point>,
    /// The coefficients of each key
    coefs: Vec<Scalar<Public>>,
    /// Whether the secret keys needs to be negated when signing
    needs_negation: bool,
    /// The aggregate key
    agg_key: Point<T>,
    /// The tweak on the aggregate key
    tweak: Scalar<Public, Zero>,
}

impl<T: Copy> AggKey<T> {
    /// The aggregate key.
    ///
    /// Note that before using it as a key in a system that accepts "x-only" keys like `[BIP341]`
    /// you must call [`into_xonly_key`] and use that aggregate key.
    ///
    /// [`into_xonly_key`]: Self::into_xonly_key
    pub fn agg_public_key(&self) -> Point<T> {
        self.agg_key
    }

    /// An iterator over the **public keys** of each party in the aggregate key.
    pub fn keys(&self) -> impl Iterator<Item = Point> + '_ {
        self.keys.iter().map(|point| *point)
    }
}

impl AggKey<Normal> {
    /// Convert the key into a BIP340 AggKey.
    ///
    /// This is the [BIP340] x-only version of the key which you can put in a segwitv1 output
    /// and create/verify BIP340 signatures under.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn into_xonly_key(self) -> AggKey<EvenY> {
        let (agg_key, needs_negation) = self.agg_key.into_point_with_even_y();
        let mut tweak = self.tweak;
        tweak.conditional_negate(needs_negation);
        AggKey {
            keys: self.keys,
            coefs: self.coefs,
            needs_negation,
            tweak,
            agg_key,
        }
    }

    /// Add a scalar `tweak` to aggregate MuSig public key.
    ///
    /// The resulting key is equal to the existing key plus `tweak * G`. The tweak mutates the
    /// public key while still allowing the original set of signers to sign under the new key.
    /// This function is appropriate for doing [BIP32] tweaks before calling `into_xonly_key`.
    /// It **is not** appropriate for doing taproot tweaking which must be done on an [`AggKey`]
    /// with [`EvenY`] public key in BIP340 form, see [`into_xonly_key`].
    ///
    /// ## Return value
    ///
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    ///
    /// [BIP32]: https://bips.xyz/32
    /// [`AggKey`]: crate::musig::AggKey
    /// [`into_xonly_key`]: crate::musig::AggKey::into_xonly_key
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let agg_key = g!(self.agg_key + tweak * G).normalize().non_zero()?;
        let tweak = s!(self.tweak + tweak).public();

        Some(AggKey {
            keys: self.keys.clone(),
            coefs: self.coefs.clone(),
            needs_negation: false,
            agg_key,
            tweak,
        })
    }
}

// /// A [`AggKey`] that has been converted into a [BIP340] x-only key.
// ///
// /// [BIP340]: https://bips.xyz/340
impl AggKey<EvenY> {
    /// Applies an "x-only" tweak to the aggregate key.
    ///
    /// This function exists to allow for [BIP341] tweaks to the aggregate public key.
    ///
    /// [BIP341]: https://bips.xyz/341
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let (new_agg_key, needs_negation) = g!(self.agg_key + tweak * G)
            .normalize()
            .non_zero()?
            .into_point_with_even_y();
        let mut new_tweak = s!(self.tweak + tweak).public();
        new_tweak.conditional_negate(needs_negation);
        let needs_negation = self.needs_negation ^ needs_negation;

        Some(Self {
            keys: self.keys,
            coefs: self.coefs,
            needs_negation,
            tweak: new_tweak,
            agg_key: new_agg_key,
        })
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG> MuSig<H, NG> {
    /// Generates a new aggregated key from a list of individual keys.
    ///
    /// Each party can be local (you know the secret key) or remote (you only know the public key).
    ///
    /// ## Example
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{Point, Scalar},
    ///     musig::MuSig,
    ///     nonce::Deterministic,
    ///     Schnorr,
    /// };
    /// # let my_secret_key = Scalar::random(&mut rand::thread_rng());
    /// # let their_public_key = Point::random(&mut rand::thread_rng());
    /// use sha2::Sha256;
    /// let musig = MuSig::<Sha256, Deterministic<Sha256>>::default();
    /// let my_keypair = musig.new_keypair(my_secret_key);
    /// let my_public_key = my_keypair.public_key();
    /// // Note the keys have to come in the same order on the other side!
    /// let agg_key = musig.new_agg_key(vec![their_public_key, my_public_key]);
    /// ```
    pub fn new_agg_key(&self, keys: Vec<Point>) -> AggKey<Normal> {
        let coeff_hash = {
            let L = self.pk_hash.clone().add(&keys[..]).finalize();
            self.coeff_hash.clone().add(L.as_slice())
        };

        let mut second = None;
        let coefs = keys
            .iter()
            .map(|key| {
                // This is the logic for IsSecond from appendix B of the MuSig2 paper
                if second.is_none() && key != &keys[0] {
                    second = Some(key);
                }
                if second != Some(key) {
                    Scalar::from_hash(coeff_hash.clone().add(key))
                } else {
                    Scalar::one()
                }
                .public()
            })
            .collect::<Vec<_>>();

        let agg_key = crate::fun::op::lincomb(coefs.iter(), keys.iter())
            .non_zero().expect("computationally unreachable: linear combination of hash randomised points cannot add to zero");

        AggKey {
            keys,
            coefs,
            agg_key: agg_key.normalize(),
            tweak: Scalar::zero(),
            needs_negation: false,
        }
    }
}

impl<H, NG> MuSig<H, NG>
where
    H: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    /// Seed a random number generator to be used for MuSig nonces.
    ///
    /// ** ⚠ WARNING ⚠**: This method is unstable and easy to use incorrectly. The seed it uses for
    /// the Rng will change without warning between minor versions of this library.
    ///
    /// Parameters:
    ///
    /// - `agg_key`: the joint public key we are signing under. This can be an `XOnly` or `Normal`.
    ///    It will return the same nonce regardless.
    /// - `secret`: you're secret key as part of `agg_key`. This **must be the secret key you are
    /// going to sign with**. It cannot be an "untweaked" version of the signing key. It must be
    /// exactly equal to the secret key you pass to [`sign`] (the MuSig specification requires this).
    /// - `session_id`: a string of bytes that is **unique for each signing attempt**.
    ///
    /// The application should decide upon a unique `session_id` per call to this function. If the
    /// `NonceGen` of this MuSig instance is `Deterministic` then the `session_id` **must** be
    /// unique per signing attempt -- even if the signing attempt fails to produce a signature you
    /// must not reuse the session id, the resulting rng or anything derived from that rng again.
    ///
    /// 💡 Before using this function write a short justification as to why your beleive your session
    /// id will be unique per signing attempt. Perhaps include it as a comment next to the call.
    /// Note **it must be unique even across signing attempts for the same or different messages**.
    ///
    /// The rng returned can be used to create many nonces. For example, when signing a Bitcoin
    /// transaction you may need to sign several inputs each with their own signature. It is
    /// intended here that you call `seed_nonce_rng` once for the transaction and pull several nonces
    /// out of the resulting rng.
    ///
    /// [`sign`]: MuSig::sign
    pub fn seed_nonce_rng<R: SeedableRng<Seed = [u8; 32]>>(
        &self,
        agg_key: &AggKey<impl Normalized>,
        secret: &Scalar,
        session_id: &[u8],
    ) -> R {
        let sid_len = (session_id.len() as u64).to_be_bytes();
        let pk_bytes = agg_key.agg_public_key().to_xonly_bytes();

        let rng: R = secp256kfun::derive_nonce_rng!(
            nonce_gen => self.nonce_gen(),
            secret => &secret,
            public => [pk_bytes, sid_len, session_id],
            seedable_rng => R
        );
        rng
    }
}

/// Marker type for indicating the [`SignSession`] is being used to create an ordinary Schnorr
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct Ordinary;

/// Marks the [`SignSession`] as being used to create an adaptor (a.k.a. one-time encrypted)
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct Adaptor {
    y_needs_negation: bool,
}

/// A signing session.
///
/// Created by [`start_sign_session`] or [`start_encrypted_sign_session`].
/// The type parameter records whether you are trying to jointly generate a signature or an adaptor signature.
///
/// [`start_sign_session`]: MuSig::start_sign_session
/// [`start_encrypted_sign_session`]: MuSig::start_encrypted_sign_session
/// [`sign`]: MuSig::sign
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct SignSession<T = Ordinary> {
    b: Scalar<Public, Zero>,
    c: Scalar<Public, Zero>,
    public_nonces: Vec<Nonce>,
    R: Point<EvenY>,
    nonce_needs_negation: bool,
    signing_type: T,
}

impl<H: Digest<OutputSize = U32> + Clone, NG> MuSig<H, NG> {
    /// Start a signing session.
    ///
    /// You must provide the public nonces for this signing session in the correct order.
    ///
    /// ## Return Value
    ///
    /// Returns `None` in the case that the `remote_nonces` have been (maliciously) selected to
    /// cancel out your local nonces.
    /// This is not a security issue -- we just can't continue the protocol if this happens.
    ///
    /// # Panics
    ///
    /// Panics if number of nonces does not align with the keys in `agg_key`.
    pub fn start_sign_session(
        &self,
        agg_key: &AggKey<EvenY>,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
    ) -> SignSession {
        let (b, c, public_nonces, R, nonce_needs_negation) = self._start_sign_session(
            agg_key,
            nonces,
            message,
            &Point::<Normal, Public, _>::zero(),
        );
        SignSession {
            b,
            c,
            public_nonces,
            R,
            nonce_needs_negation,
            signing_type: Ordinary,
        }
    }

    /// Start an encrypted signing session.
    ///
    /// i.e. a session to produce an adaptor signature under `encryption_key`.
    /// See [`adaptor`] for a more general description of adaptor signatures.
    ///
    /// You must provide the public nonces (where your public portions must be
    /// shared with the other signer(s)).
    ///
    /// ## Return Value
    ///
    /// Returns `None` in the case that the `remote_nonces` have been (maliciously) selected to
    /// cancel out your local nonces.
    /// This is not a security issue -- we just can't continue the protocol if this happens.
    ///
    /// # Panics
    ///
    /// Panics if number of local or remote nonces passed in does not align with the keys in
    /// `agg_key`.
    ///
    /// [`adaptor`]: crate::adaptor
    pub fn start_encrypted_sign_session(
        &self,
        agg_key: &AggKey<EvenY>,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    ) -> Option<SignSession<Adaptor>> {
        let (b, c, public_nonces, R, nonce_needs_negation) =
            self._start_sign_session(agg_key, nonces, message, encryption_key);
        Some(SignSession {
            b,
            c,
            public_nonces,
            R,
            nonce_needs_negation,
            signing_type: Adaptor {
                y_needs_negation: nonce_needs_negation,
            },
        })
    }

    fn _start_sign_session(
        &self,
        agg_key: &AggKey<EvenY>,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    ) -> (
        Scalar<Public, Zero>,
        Scalar<Public, Zero>,
        Vec<Nonce>,
        Point<EvenY>,
        bool,
    ) {
        let mut Rs = nonces;
        let agg_Rs = Rs.iter().fold([Point::zero(); 2], |acc, nonce| {
            [
                g!({ acc[0] } + { nonce.0[0] }),
                g!({ acc[1] } + { nonce.0[1] }),
            ]
        });
        let agg_Rs = Nonce::<Zero>([
            g!({ agg_Rs[0] } + encryption_key).normalize(),
            agg_Rs[1].normalize(),
        ]);

        let b = {
            let H = self.nonce_coeff_hash.clone();
            Scalar::from_hash(
                H.add(agg_Rs.to_bytes())
                    .add(agg_key.agg_public_key())
                    .add(message),
            )
        }
        .public()
        .mark_zero();

        let (R, r_needs_negation) = g!({ agg_Rs.0[0] } + b * { agg_Rs.0[1] })
            .normalize()
            .non_zero()
            .unwrap_or_else(|| {
                // if final nonce is zero we set it to generator as in MuSig spec
                debug_assert!(G.is_y_even());
                G.normalize()
            })
            .into_point_with_even_y();

        for R_i in &mut Rs {
            R_i.conditional_negate(r_needs_negation);
        }

        let c = self
            .schnorr
            .challenge(&R, &agg_key.agg_public_key(), message);

        (b, c, Rs, R, r_needs_negation)
    }

    /// Generates a partial signature (or partial encrypted signature depending on `T`) for the local_secret_nonce.
    pub fn sign<T>(
        &self,
        agg_key: &AggKey<EvenY>,
        session: &SignSession<T>,
        my_index: usize,
        keypair: &KeyPair,
        local_secret_nonce: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        assert_eq!(
            keypair.public_key(),
            agg_key.keys().nth(my_index).unwrap(),
            "key at index {} didn't match",
            my_index
        );
        let c = session.c;
        let b = session.b;
        let x_i = keypair.secret_key();
        let mut a = agg_key.coefs[my_index];

        a.conditional_negate(agg_key.needs_negation);
        let [mut r1, mut r2] = local_secret_nonce.secret.clone();
        r1.conditional_negate(session.nonce_needs_negation);
        r2.conditional_negate(session.nonce_needs_negation);
        s!(c * a * x_i + r1 + b * r2).public()
    }

    #[must_use]
    /// Verifies a partial signature (or partial encrypted signature depending on `T`).
    ///
    /// You must provide the `index` of the party (the index of the key in `agg_key`).
    ///
    /// # Panics
    ///
    /// Panics when `index` is equal to or greater than the number of keys in the agg_key.
    pub fn verify_partial_signature<T>(
        &self,
        agg_key: &AggKey<EvenY>,
        session: &SignSession<T>,
        index: usize,
        partial_sig: Scalar<Public, Zero>,
    ) -> bool {
        let c = session.c;
        let b = session.b;
        let s_i = &partial_sig;
        let a = agg_key.coefs[index].clone();

        let X_i = agg_key
            .keys()
            .nth(index)
            .unwrap()
            .conditional_negate(agg_key.needs_negation);

        let [R1, R2] = &session.public_nonces[index].0;
        g!((c * a) * X_i + R1 + b * R2 - s_i * G).is_zero()
    }

    /// Combines all the partial signatures into a single `Signature`.
    ///
    /// Note this does not check the validity of any of the partial signatures. You should either check
    /// each one using [`verify_partial_signature`] or use [`verify`] on the returned `Signature` to check validity.
    ///
    /// [`verify`]: crate::Schnorr::verify
    /// [`verify_partial_signature`]: Self::verify_partial_signature
    pub fn combine_partial_signatures(
        &self,
        agg_key: &AggKey<EvenY>,
        session: &SignSession<Ordinary>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> Signature {
        let (R, s) = self._combine_partial_signatures(agg_key, &session, partial_sigs);
        Signature { R, s }
    }

    /// Combines all the partial encrypted signatures into one encrypted signature.
    ///
    /// Note this does not check the validity of any of the partial signatures. You should either check
    /// each one using [`verify_partial_signature`] or use [`verify_encrypted_signature`] on the returned `Signature` to check validity.
    ///
    /// [`verify_encrypted_signature`]: crate::adaptor::Adaptor::verify_encrypted_signature
    /// [`verify_partial_signature`]: Self::verify_partial_signature
    pub fn combine_partial_encrypted_signatures(
        &self,
        agg_key: &AggKey<EvenY>,
        session: &SignSession<Adaptor>,
        partial_encrypted_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> EncryptedSignature {
        let (R, s_hat) =
            self._combine_partial_signatures(agg_key, &session, partial_encrypted_sigs);
        EncryptedSignature {
            R,
            s_hat,
            needs_negation: session.signing_type.y_needs_negation,
        }
    }

    fn _combine_partial_signatures<T>(
        &self,
        agg_key: &AggKey<EvenY>,
        session: &SignSession<T>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> (Point<EvenY>, Scalar<Public, Zero>) {
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, s| s!(acc + s).public())
            .unwrap_or(Scalar::zero());

        let s = s!(sum_s + agg_key.tweak * session.c).public();

        (session.R, s)
    }
}

/// Constructor for a MuSig instance using deterministic nonce generation.
///
/// If you use deterministic nonce generation you will have to provide a unique session id to every
/// signing session. The advantage is that you will be able to regenerate the same nonces at a later
/// point from [`MuSig::seed_nonce_rng`].
///
/// ```
/// use schnorr_fun::musig;
/// let musig = musig::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_deterministic_nonces<H>() -> MuSig<H, nonce::Deterministic<H>>
where
    H: Tag + Digest<OutputSize = U32> + Default + Clone,
{
    MuSig::default()
}

/// Constructor for a MuSig instance using synthetic nonce generation.
///
/// Sythetic nonce generation mixes in external randomness into nonce generation which means you
/// don't need a unique session id for each signing session to guarantee security. The disadvantage
/// is that you may have to store and recall somehow the nonces generated from
/// [`MuSig::seed_nonce_rng`].
///
/// ```
/// use schnorr_fun::musig;
/// let musig = musig::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_synthetic_nonces<H, R>() -> MuSig<H, nonce::Synthetic<H, nonce::GlobalRng<R>>>
where
    H: Tag + Digest<OutputSize = U32> + Default + Clone,
    R: RngCore + Default + Clone,
{
    MuSig::default()
}

/// Create a MuSig instance which does not handle nonce generation.
///
/// You can still sign with this instance but you you will have to generate nonces in your own way.
pub fn new_without_nonce_generation<H>() -> MuSig<H, NoNonces>
where
    H: Tag + Digest<OutputSize = U32> + Default,
{
    MuSig::default()
}

#[cfg(test)]
mod test {
    use crate::adaptor::Adaptor;

    use super::*;
    use rand_chacha::ChaCha20Rng;
    use secp256kfun::proptest::{option, prelude::*};
    use sha2::Sha256;

    proptest! {
        #[test]
        fn proptest_sign_verify(sk1 in any::<Scalar>(),
                        sk2 in any::<Scalar>(),
                        sk3 in any::<Scalar>(),
                        pre_tweak1 in option::of(any::<Scalar<Public, Zero>>()),
                        pre_tweak2 in option::of(any::<Scalar<Public, Zero>>()),
                        tweak1 in option::of(any::<Scalar<Public, Zero>>()),
                        tweak2 in option::of(any::<Scalar<Public, Zero>>()),
        ) {
            let schnorr = Schnorr::<Sha256, nonce::Deterministic<Sha256>>::default();
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
                .new_keypair(sk1);
            let keypair2 = musig
                .new_keypair(sk2);
            let keypair3 = musig
                .new_keypair(sk3);

            let mut agg_key1 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]);
            let mut agg_key2 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]);
            let mut agg_key3 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]);

            for tweak in [pre_tweak1, pre_tweak2] {
                if let Some(tweak) = tweak {
                    agg_key1 = agg_key1.tweak(tweak).unwrap();
                    agg_key2 = agg_key2.tweak(tweak).unwrap();
                    agg_key3 = agg_key3.tweak(tweak).unwrap();
                }
            }


            let mut agg_key1 = agg_key1.into_xonly_key();
            let mut agg_key2 = agg_key2.into_xonly_key();
            let mut agg_key3 = agg_key3.into_xonly_key();

            for tweak in [tweak1, tweak2] {
                if let Some(tweak) = tweak {
                    agg_key1 = agg_key1.tweak(tweak).unwrap();
                    agg_key2 = agg_key2.tweak(tweak).unwrap();
                    agg_key3 = agg_key3.tweak(tweak).unwrap();
                }
            }

            assert_eq!(agg_key1.agg_public_key(), agg_key2.agg_public_key());
            assert_eq!(agg_key1.agg_public_key(), agg_key3.agg_public_key());

            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let session_id = message.bytes.into();

            let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key1, keypair1.secret_key(), session_id);
            let p1_nonce = musig.gen_nonce(&mut nonce_rng);
            let p2_nonce = musig.gen_nonce(&mut nonce_rng);
            let p3_nonce = musig.gen_nonce(&mut nonce_rng);
            let nonces = vec![p1_nonce.public, p2_nonce.public, p3_nonce.public];


            let p1_session = musig
                .start_sign_session(
                    &agg_key1,
                    nonces.clone(),
                    message,
                );
            let p2_session = musig
                .start_sign_session(
                    &agg_key2,
                    nonces.clone(),
                    message,
                );
            let p3_session = musig
                .start_sign_session(
                    &agg_key3,
                    nonces.clone(),
                    message,
                );

            let p1_sig = musig.sign(&agg_key1, &p1_session, 0, &keypair1, p1_nonce);

            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 0, p1_sig));
            assert_eq!(p1_session, p2_session);

            assert!(musig.verify_partial_signature(&agg_key1, &p2_session, 0, p1_sig));
            assert!(musig.verify_partial_signature(&agg_key1, &p3_session, 0, p1_sig));

            let p2_sig = musig.sign(&agg_key1, &p2_session, 1, &keypair2, p2_nonce);
            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 1, p2_sig));
            let p3_sig = musig.sign(&agg_key1, &p3_session, 2, &keypair3, p3_nonce);
            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 2, p3_sig));

            let partial_sigs = [p1_sig, p2_sig, p3_sig];
            let sig_p1 = musig.combine_partial_signatures(&agg_key1, &p1_session, partial_sigs);
            let sig_p2 = musig.combine_partial_signatures(&agg_key1, &p2_session, partial_sigs);
            let sig_p3 = musig.combine_partial_signatures(&agg_key1, &p3_session, partial_sigs);
            assert_eq!(sig_p1, sig_p2);
            assert_eq!(sig_p1, sig_p3);

            assert!(musig
                    .schnorr
                    .verify(&agg_key1.agg_public_key(), message, &sig_p1));
            assert!(musig
                    .schnorr
                    .verify(&agg_key1.agg_public_key(), message, &sig_p2));
            assert!(musig
                        .schnorr
                        .verify(&agg_key1.agg_public_key(), message, &sig_p3));
        }

        #[test]
        fn test_musig_adaptor(
            sk1 in any::<Scalar>(),
            sk2 in any::<Scalar>(),
            sk3 in any::<Scalar>(),
            y in any::<Scalar>()
        ) {
            let schnorr = Schnorr::<Sha256, nonce::Deterministic<Sha256>>::default();
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
            .new_keypair(sk1);
            let keypair2 = musig
            .new_keypair(sk2);
            let keypair3 = musig
            .new_keypair(sk3);
            let encryption_key = musig.schnorr.encryption_key_for(&y);

            let agg_key1 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_xonly_key();
            let agg_key2 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_xonly_key();
            let agg_key3 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_xonly_key();

            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let session_id = message.bytes.into();

            let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key1, keypair1.secret_key(), session_id);
            let p1_nonce = musig.gen_nonce(&mut nonce_rng);
            let p2_nonce = musig.gen_nonce(&mut nonce_rng);
            let p3_nonce = musig.gen_nonce(&mut nonce_rng);
            let nonces = vec![p1_nonce.public, p2_nonce.public, p3_nonce.public];

            let mut p1_session = musig
                .start_encrypted_sign_session(
                    &agg_key1,
                    nonces.clone(),
                    message,
                    &encryption_key
                )
                .unwrap();
            let mut p2_session = musig
                .start_encrypted_sign_session(
                    &agg_key2,
                    nonces.clone(),
                    message,
                    &encryption_key
                )
                .unwrap();
            let mut p3_session = musig
                .start_encrypted_sign_session(
                    &agg_key3,
                    nonces,
                    message,
                    &encryption_key
                )
                .unwrap();
                let p1_sig = musig.sign(&agg_key1, &mut p1_session, 0, &keypair1, p1_nonce);
                let p2_sig = musig.sign(&agg_key1, &mut p2_session, 1, &keypair2, p2_nonce);
                let p3_sig = musig.sign(&agg_key1, &mut p3_session, 2, &keypair3, p3_nonce);

            assert!(musig.verify_partial_signature(&agg_key2, &p2_session, 0, p1_sig));
            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 0, p1_sig));

            let partial_sigs = vec![p1_sig, p2_sig, p3_sig];
            let combined_sig_p1 = musig.combine_partial_encrypted_signatures(&agg_key1, &p1_session, partial_sigs.clone());
            let combined_sig_p2 = musig.combine_partial_encrypted_signatures(&agg_key2, &p2_session, partial_sigs.clone());
            let combined_sig_p3 = musig.combine_partial_encrypted_signatures(&agg_key3, &p3_session, partial_sigs);
            assert_eq!(combined_sig_p1, combined_sig_p2);
            assert_eq!(combined_sig_p1, combined_sig_p3);
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&agg_key1.agg_public_key(), &encryption_key, message, &combined_sig_p1));
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&agg_key2.agg_public_key(), &encryption_key, message, &combined_sig_p2));
            assert!(musig
                .schnorr
                .verify_encrypted_signature(&agg_key2.agg_public_key(), &encryption_key, message, &combined_sig_p3));
        }
    }
}
