//! The MuSig2 multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{musig::MuSig, nonce::Deterministic, Message, Schnorr};
//! use sha2::Sha256;
//! // use sha256 with deterministic nonce generation
//! let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
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
//!     .into_bip340_key();
//!
//! // create a unique nonce, and send the public nonce to other parties.
//! let my_nonce = musig.gen_nonces(my_keypair.secret_key(), &agg_key, b"session-id-1337");
//! let my_public_nonce = my_nonce.public();
//! # let p2_nonce = musig.gen_nonces(kp2.secret_key(), &agg_key, b"session-id-1337");
//! # let p2_public_nonce = p2_nonce.public();
//! # let p3_nonce = musig.gen_nonces(kp3.secret_key(), &agg_key, b"session-id-1337");
//! # let p3_public_nonce = p3_nonce.public();
//! // collect the public nonces from the other two parties
//! let nonces = vec![my_public_nonce, p2_public_nonce, p3_public_nonce];
//! let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! // start the signing session
//! let session = musig.start_sign_session(&agg_key, nonces, message).unwrap();
//! // sign with our single local keypair
//! let my_sig = musig.sign(&agg_key, 0, &my_keypair, my_nonce, &session);
//! # let p2_sig = musig.sign(&agg_key, 1, &kp2, p2_nonce, &session);
//! # let p3_sig = musig.sign(&agg_key, 2, &kp3, p3_nonce, &session);
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
//! See [the excellent paper] for the abstract details of the protocol and security proofs.
//! **⚠ THIS IS EXPERIMENTAL AND NOT COMPATIBLE WITH THE [DRAFT SPECIFICATION](https://github.com/jonasnick/bips/blob/musig2/bip-musig2.mediawiki) ⚠**
//!
//!
//! [the excellent paper]: https://eprint.iacr.org/2020/1261.pdf
//! [secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/131
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{adaptor::EncryptedSignature, Message, Schnorr, Signature, Vec};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::NonceGen,
    s, Point, Scalar, G,
};

/// The MuSig context.
pub struct MuSig<H, S = ()> {
    /// The hash used to compress the key list to 32 bytes.
    pub pk_hash: H,
    /// The hash used to generate each key's coefficient.
    pub coeff_hash: H,
    /// The hash used to generate the nonce coefficients.
    pub nonce_coeff_hash: H,
    /// The instance of the underlying Schnorr context.
    pub schnorr: S,
}

impl<H: Tagged, S> MuSig<H, S> {
    /// Create a new [`KeyPair`]
    ///
    /// This is a convenient way of just doing:
    ///
    /// ```
    /// # let secret_key = schnorr_fun::fun::Scalar::random(&mut rand::thread_rng());
    /// use schnorr_fun::musig::KeyPair;
    /// let keypair = KeyPair::new(secret_key);
    /// ```
    pub fn new_keypair(&self, secret_key: Scalar) -> KeyPair {
        KeyPair::new(secret_key)
    }

    fn _new(schnorr: S) -> Self {
        Self {
            pk_hash: H::default().tagged(b"KeyAgg list"),
            coeff_hash: H::default().tagged(b"KeyAgg coefficient"),
            nonce_coeff_hash: H::default().tagged(b"MuSig/noncecoef"),
            schnorr,
        }
    }
}

impl<H: Tagged, S: Default> Default for MuSig<H, S> {
    fn default() -> Self {
        MuSig::_new(S::default())
    }
}

impl<H: Tagged, NG> MuSig<H, Schnorr<H, NG>> {
    /// Generate a new MuSig context from a Schnorr context.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self::_new(schnorr)
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
pub struct AggKey {
    /// The parties involved in the key aggregation.
    parties: Vec<Point>,
    /// The coefficients of each key
    coefs: Vec<Scalar<Public>>,
    /// The aggregate key
    agg_key: Point<Normal>,
    /// The tweak on the aggregate key
    tweak: Scalar<Public, Zero>,
}

impl AggKey {
    /// The aggregate key prior to converting to a BIP340 `XOnly` key.
    pub fn agg_key(&self) -> Point {
        self.agg_key
    }

    /// An iterator over the **public keys** of each party in the aggregate key.
    pub fn keys(&self) -> impl Iterator<Item = Point> + '_ {
        self.parties.iter().map(|point| *point)
    }

    /// Add a scalar `tweak` to aggregate MuSig public key.
    ///
    /// The resulting key is equal to the existing key plus `tweak * G`. The tweak mutates the
    /// public key while still allowing the original set of signers to sign under the new key.
    /// This function is appropriate for doing [BIP32] tweaks before calling `into_bip340_key`.
    /// It **is not** appropriate for doing taproot tweaking which must be done on a [`Bip340AggKey`].
    ///
    /// ## Return value
    ///
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    ///
    /// [BIP32]: https://bips.xyz/32
    /// [`Bip340AggKey`]: crate::musig::Bip340AggKey
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let agg_key = g!(self.agg_key + tweak * G).normalize().mark::<NonZero>()?;
        let tweak = s!(self.tweak + tweak).mark::<Public>();

        Some(AggKey {
            parties: self.parties.clone(),
            coefs: self.coefs.clone(),
            agg_key,
            tweak,
        })
    }

    /// Convert the key into an `Bip340AggKey`.
    ///
    /// This is the BIP340 compatible version of the key which you can put in a segwitv1 output and create BIP340 signatures under.
    pub fn into_bip340_key(self) -> Bip340AggKey {
        let (agg_key, needs_negation) = self.agg_key.into_point_with_even_y();
        let mut tweak = self.tweak;
        tweak.conditional_negate(needs_negation);
        Bip340AggKey {
            parties: self.parties,
            coefs: self.coefs,
            needs_negation,
            tweak,
            agg_key,
        }
    }
}

/// A [`AggKey`] that has been converted into a [BIP340] `XOnly` key.
///
/// [BIP340]: https://bips.xyz/340
#[derive(Debug, Clone)]
pub struct Bip340AggKey {
    /// The parties involved in the key aggregation.
    parties: Vec<Point>,
    /// The coefficients of each key
    coefs: Vec<Scalar<Public>>,
    /// Whether the secret keys needs to be negated when signing
    needs_negation: bool,
    /// The tweaks that have been applied
    tweak: Scalar<Public, Zero>,
    ///
    agg_key: Point<EvenY>,
}

impl Bip340AggKey {
    /// The aggregate key as a `Point`
    pub fn agg_public_key(&self) -> Point<EvenY> {
        self.agg_key
    }

    /// An iterator over the **public keys** of each party in the agg_key.
    pub fn keys(&self) -> impl Iterator<Item = Point> + '_ {
        self.parties.iter().map(|point| *point)
    }

    /// Applies an "XOnly" tweak to the aggregate key
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let (new_agg_key, needs_negation) = g!(self.agg_key + tweak * G)
            .normalize()
            .mark::<NonZero>()?
            .into_point_with_even_y();
        let mut new_tweak = s!(self.tweak + tweak).mark::<Public>();
        new_tweak.conditional_negate(needs_negation);
        let needs_negation = self.needs_negation ^ needs_negation;

        Some(Self {
            parties: self.parties,
            coefs: self.coefs,
            needs_negation,
            tweak: new_tweak,
            agg_key: new_agg_key,
        })
    }
}

impl<H: Digest<OutputSize = U32> + Clone, S> MuSig<H, S> {
    /// Generates a new aggregated key from a list of individual keys.
    ///
    /// Each party can be local (you know the secret key) or remote (you only know the public key).
    ///
    /// ## Example
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{Point, Scalar, XOnly},
    ///     musig::MuSig,
    ///     nonce::Deterministic,
    ///     Schnorr,
    /// };
    /// # let my_secret_key = Scalar::random(&mut rand::thread_rng());
    /// # let their_public_key = Point::random(&mut rand::thread_rng());
    /// use sha2::Sha256;
    /// let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    /// let my_keypair = musig.new_keypair(my_secret_key);
    /// let my_public_key = my_keypair.public_key();
    /// // Note the keys have to come in the same order on the other side!
    /// let agg_key = musig.new_agg_key(vec![their_public_key, my_public_key]);
    /// ```
    pub fn new_agg_key(&self, parties: Vec<Point>) -> AggKey {
        let keys = parties.clone();
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
                .mark::<Public>()
            })
            .collect::<Vec<_>>();

        let agg_key = crate::fun::op::lincomb(coefs.iter(), parties.iter())
            .expect_nonzero("computationally unreachable: linear combination of hash randomised points cannot add to zero");

        AggKey {
            parties,
            coefs,
            agg_key: agg_key.mark::<Normal>(),
            tweak: Scalar::zero().mark::<Public>(),
        }
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> MuSig<H, Schnorr<H, NG>> {
    /// Generate nonces for signing under your aggregate key.
    ///
    /// It is very important to carefully consider the implications of your choice of underlying
    /// [`NonceGen`].
    ///
    /// Using a [`Synthetic`] nonce generator will mean you don't have to worry about passing a
    /// unique `sid` (session id) to this function for each signing session. The downside is that
    /// you must recall the result of `gen_nonces` somewhere and store it for use when you want to
    /// start the signing session with [`start_sign_session`].
    ///
    /// Using a [`Deterministic`] nonce generator means you **must** never start two signing
    /// sessions with nonces generated from the same `sid`. If you do your secret key will be
    /// recoverable from the two partial signatures you created with the same nonce.
    ///
    /// Note that the API allows you to BYO nonces by creating `NonceKeyPair`s manually.
    ///
    /// [`NonceGen`]: secp256kfun::nonce::NonceGen
    /// [`Synthetic`]: secp256kfun::nonce::Synthetic
    /// [`Deterministic`]: secp256kfun::nonce::Deterministic
    /// [`start_sign_session`]: Self::start_sign_session
    /// [`NonceKeyPair`]: schnorr_fun::binonce::NonceKeyPair
    pub fn gen_nonces(&self, secret: &Scalar, agg_key: &Bip340AggKey, sid: &[u8]) -> NonceKeyPair {
        let r1 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r1", agg_key.agg_public_key(), sid]
        );
        let r2 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r2", agg_key.agg_public_key(), sid]
        );
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }
    }
}

/// Marker type for indicating the [`SignSession`] is being used to create an ordinary Schnorr
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct Ordinary;

/// Marks the [`SignSession`] as being used to create an adaptor (a.k.a. one-time encrypted)
/// signature.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct Adaptor {
    y_needs_negation: bool,
}

/// A signing session.
///
/// Created by [`start_sign_session`] or [`start_encrypted_sign_session`].
/// The type parameter records whether you are trying to jointly generate a signature or an adaptor signature.
///
/// ## Security
///
/// This struct has **secret nonces** in it up until you call [`sign`]. If a malicious party
/// gains access to it before and you generate a partial signature with this session they
/// will be able to recover your secret key. If this is a concern simply avoid serializing this
/// struct (until you've cleared it) and recreate it only when you need it.
///
/// [`start_sign_session`]: MuSig::start_sign_session
/// [`start_encrypted_sign_session`]: MuSig::start_encrypted_sign_session
/// [`sign`]: MuSig::sign
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct SignSession<T = Ordinary> {
    b: Scalar<Public, Zero>,
    c: Scalar<Public, Zero>,
    public_nonces: Vec<Nonce>,
    R: Point<EvenY>,
    nonce_needs_negation: bool,
    signing_type: T,
}

impl<H: Digest<OutputSize = U32> + Clone, NG> MuSig<H, Schnorr<H, NG>> {
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
    /// Panics if number of nonces does not align with the parties in `agg_key`.
    pub fn start_sign_session(
        &self,
        agg_key: &Bip340AggKey,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
    ) -> Option<SignSession> {
        let (b, c, public_nonces, R, nonce_needs_negation) =
            self._start_sign_session(agg_key, nonces, message, &Point::zero())?;
        Some(SignSession {
            b,
            c,
            public_nonces,
            R,
            nonce_needs_negation,
            signing_type: Ordinary,
        })
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
    /// Panics if number of local or remote nonces passed in does not align with the parties in
    /// `agg_key`.
    ///
    /// [`adaptor`]: crate::adaptor
    pub fn start_encrypted_sign_session(
        &self,
        agg_key: &Bip340AggKey,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy>,
    ) -> Option<SignSession<Adaptor>> {
        let (b, c, public_nonces, R, nonce_needs_negation) =
            self._start_sign_session(agg_key, nonces, message, encryption_key)?;
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
        agg_key: &Bip340AggKey,
        nonces: Vec<Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    ) -> Option<(
        Scalar<Public, Zero>,
        Scalar<Public, Zero>,
        Vec<Nonce>,
        Point<EvenY>,
        bool,
    )> {
        let mut Rs = nonces;
        let agg_Rs = Rs
            .iter()
            .fold([Point::zero().mark::<Jacobian>(); 2], |acc, nonce| {
                [
                    g!({ acc[0] } + { nonce.0[0] }),
                    g!({ acc[1] } + { nonce.0[1] }),
                ]
            });
        let agg_Rs = [
            g!({ agg_Rs[0] } + encryption_key)
                .normalize()
                .mark::<NonZero>()?,
            agg_Rs[1].normalize().mark::<NonZero>()?,
        ];

        let b = {
            let H = self.nonce_coeff_hash.clone();
            Scalar::from_hash(
                H.add(agg_Rs)
                    .add(agg_key.agg_public_key().to_xonly())
                    .add(message),
            )
        }
        .mark::<(Public, Zero)>();

        let (R, r_needs_negation) = g!({ agg_Rs[0] } + b * { agg_Rs[1] } )
            .normalize()
            .expect_nonzero("computationally unreachable: one of the coefficients is a hash output that commits to both point")
            .into_point_with_even_y();

        for R in &mut Rs {
            R.0[0] = R.0[0].conditional_negate(r_needs_negation);
            R.0[1] = R.0[1].conditional_negate(r_needs_negation);
        }

        let c = self
            .schnorr
            .challenge(R.to_xonly(), agg_key.agg_public_key().to_xonly(), message);

        Some((b, c, Rs, R, r_needs_negation))
    }

    /// Generates a partial signature (or partial encrypted signature depending on `T`) for the local_secret_nonce.
    pub fn sign<T>(
        &self,
        agg_key: &Bip340AggKey,
        my_index: u32,
        keypair: &KeyPair,
        local_secret_nonce: NonceKeyPair,
        session: &SignSession<T>,
    ) -> Scalar<Public, Zero> {
        let c = session.c;
        let b = session.b;
        let x = keypair.secret_key();
        assert_eq!(
            keypair.public_key(),
            agg_key.keys().nth(my_index as usize).unwrap(),
            "key at index {} didn't match",
            my_index
        );
        let mut a = agg_key.coefs[my_index as usize];

        a.conditional_negate(agg_key.needs_negation);
        let [mut r1, mut r2] = local_secret_nonce.secret.clone();
        r1.conditional_negate(session.nonce_needs_negation);
        r2.conditional_negate(session.nonce_needs_negation);
        s!(c * a * x + r1 + b * r2).mark::<(Public, Zero)>()
    }

    #[must_use]
    /// Verifies a partial signature (or partial encrypted signature depending on `T`).
    ///
    /// You must provide the `index` of the party (the index of the key in `agg_key`).
    ///
    /// # Panics
    ///
    /// Panics when `index` is equal to or greater than the number of parties in the agg_key.
    pub fn verify_partial_signature<T>(
        &self,
        agg_key: &Bip340AggKey,
        session: &SignSession<T>,
        index: usize,
        partial_sig: Scalar<Public, Zero>,
    ) -> bool {
        let c = session.c;
        let b = session.b;
        let s = &partial_sig;
        let a = agg_key.coefs[index].clone();

        let X = agg_key
            .keys()
            .nth(index)
            .unwrap()
            .conditional_negate(agg_key.needs_negation);

        let [R1, R2] = &session.public_nonces[index].0;
        g!((c * a) * X + R1 + b * R2 - s * G).is_zero()
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
        agg_key: &Bip340AggKey,
        session: &SignSession<Ordinary>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> Signature {
        let (R, s) = self._combine_partial_signatures(agg_key, &session, partial_sigs);
        Signature { R: R.to_xonly(), s }
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
        agg_key: &Bip340AggKey,
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
        agg_key: &Bip340AggKey,
        session: &SignSession<T>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> (Point<EvenY>, Scalar<Public, Zero>) {
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, s| s!(acc + s).mark::<Public>())
            .unwrap_or(Scalar::zero().mark::<Public>());

        let s = s!(sum_s + agg_key.tweak * session.c).mark::<Public>();

        (session.R, s)
    }
}

#[derive(Clone, Debug, PartialEq)]
/// A MuSig key pair.
///
/// Note that the public key is a ordinary point rather than an `XOnly` key like in Schnorr.
pub struct KeyPair {
    secret_key: Scalar,
    public_key: Point,
}

impl KeyPair {
    /// Create a new MuSig key
    pub fn new(secret_key: Scalar) -> Self {
        Self {
            public_key: g!(secret_key * G).normalize(),
            secret_key,
        }
    }

    /// Get the secret key
    pub fn secret_key(&self) -> &Scalar {
        &self.secret_key
    }

    /// Get the public key
    pub fn public_key(&self) -> Point {
        self.public_key
    }
}

#[cfg(test)]
mod test {
    use crate::adaptor::Adaptor;

    use super::*;
    use secp256kfun::{
        nonce::Deterministic,
        proptest::{option, prelude::*},
    };
    use sha2::Sha256;

    proptest! {
        #[test]
        fn test_end_to_end(sk1 in any::<Scalar>(),
                        sk2 in any::<Scalar>(),
                        sk3 in any::<Scalar>(),
                        pre_tweak1 in option::of(any::<Scalar<Public, Zero>>()),
                        pre_tweak2 in option::of(any::<Scalar<Public, Zero>>()),
                        tweak1 in option::of(any::<Scalar<Public, Zero>>()),
                        tweak2 in option::of(any::<Scalar<Public, Zero>>()),
        ) {
            let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
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


            let mut agg_key1 = agg_key1.into_bip340_key();
            let mut agg_key2 = agg_key2.into_bip340_key();
            let mut agg_key3 = agg_key3.into_bip340_key();

            for tweak in [tweak1, tweak2] {
                if let Some(tweak) = tweak {
                    agg_key1 = agg_key1.tweak(tweak).unwrap();
                    agg_key2 = agg_key2.tweak(tweak).unwrap();
                    agg_key3 = agg_key3.tweak(tweak).unwrap();
                }
            }

            assert_eq!(agg_key1.agg_public_key(), agg_key2.agg_public_key());
            assert_eq!(agg_key1.agg_public_key(), agg_key3.agg_public_key());


            let p1_nonce = musig.gen_nonces(keypair1.secret_key(), &agg_key1, b"test");
            let p2_nonce = musig.gen_nonces(keypair2.secret_key(), &agg_key2, b"test");
            let p3_nonce = musig.gen_nonces(keypair3.secret_key(), &agg_key3, b"test");
            let nonces = vec![p1_nonce.public, p2_nonce.public, p3_nonce.public];

            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let p1_session = musig
                .start_sign_session(
                    &agg_key1,
                    nonces.clone(),
                    message,
                )
                .unwrap();
            let p2_session = musig
                .start_sign_session(
                    &agg_key2,
                    nonces.clone(),
                    message,
                )
                .unwrap();
            let p3_session = musig
                .start_sign_session(
                    &agg_key3,
                    nonces.clone(),
                    message,
                )
                .unwrap();

            let p1_sig = musig.sign(&agg_key1, 0, &keypair1, p1_nonce, &p1_session);

            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 0, p1_sig));
            assert_eq!(p1_session, p2_session);

            assert!(musig.verify_partial_signature(&agg_key1, &p2_session, 0, p1_sig));
            assert!(musig.verify_partial_signature(&agg_key1, &p3_session, 0, p1_sig));

            let p2_sig = musig.sign(&agg_key1, 1, &keypair2, p2_nonce, &p2_session);
            assert!(musig.verify_partial_signature(&agg_key1, &p1_session, 1, p2_sig));
            let p3_sig = musig.sign(&agg_key1, 2, &keypair3, p3_nonce, &p3_session);
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
            let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
            .new_keypair(sk1);
            let keypair2 = musig
            .new_keypair(sk2);
            let keypair3 = musig
            .new_keypair(sk3);
            let encryption_key = musig.schnorr.encryption_key_for(&y);

            let agg_key = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_bip340_key();
            let agg_key2 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_bip340_key();
            let agg_key3 = musig.new_agg_key(vec![
                keypair1.public_key(),
                keypair2.public_key(),
                keypair3.public_key(),
            ]).into_bip340_key();

            let p1_nonce = musig.gen_nonces(keypair1.secret_key(), &agg_key, b"test");
            let p2_nonce = musig.gen_nonces(keypair2.secret_key(), &agg_key2, b"test");
            let p3_nonce = musig.gen_nonces(keypair3.secret_key(), &agg_key3, b"test");
            let nonces = vec![p1_nonce.public, p2_nonce.public, p3_nonce.public];
            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let mut p1_session = musig
                .start_encrypted_sign_session(
                    &agg_key,
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
                let p1_sig = musig.sign(&agg_key, 0, &keypair1, p1_nonce, &mut p1_session);
                let p2_sig = musig.sign(&agg_key, 1, &keypair2, p2_nonce, &mut p2_session);
                let p3_sig = musig.sign(&agg_key, 2, &keypair3, p3_nonce, &mut p3_session);

            assert!(musig.verify_partial_signature(&agg_key2, &p2_session, 0, p1_sig));
            assert!(musig.verify_partial_signature(&agg_key, &p1_session, 0, p1_sig));

            let partial_sigs = vec![p1_sig, p2_sig, p3_sig];
            let combined_sig_p1 = musig.combine_partial_encrypted_signatures(&agg_key, &p1_session, partial_sigs.clone());
            let combined_sig_p2 = musig.combine_partial_encrypted_signatures(&agg_key2, &p2_session, partial_sigs.clone());
            let combined_sig_p3 = musig.combine_partial_encrypted_signatures(&agg_key3, &p3_session, partial_sigs);
            assert_eq!(combined_sig_p1, combined_sig_p2);
            assert_eq!(combined_sig_p1, combined_sig_p3);
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&agg_key.agg_public_key(), &encryption_key, message, &combined_sig_p1));
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&agg_key2.agg_public_key(), &encryption_key, message, &combined_sig_p2));
            assert!(musig
                .schnorr
                .verify_encrypted_signature(&agg_key2.agg_public_key(), &encryption_key, message, &combined_sig_p3));
        }
    }

    //     #[test]
    //     fn test_key_agg() {
    //         let X1 = XOnly::from_bytes([
    //             0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
    //             0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
    //             0xBC, 0xE0, 0x36, 0xF9,
    //         ])
    //         .unwrap();
    //         let X2 = XOnly::from_bytes([
    //             0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
    //             0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
    //             0x50, 0x2B, 0xA6, 0x59,
    //         ])
    //         .unwrap();
    //         let X3 = XOnly::from_bytes([
    //             0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18, 0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80,
    //             0xA8, 0xE3, 0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7, 0xAD, 0x33, 0x83, 0x68,
    //             0xD0, 0x38, 0xCA, 0x66,
    //         ])
    //         .unwrap();
    //         let X = vec![X1, X2, X3];

    //         let expected: Vec<XOnly> = vec![
    //             XOnly::from_bytes([
    //                 0xE5, 0x83, 0x01, 0x40, 0x51, 0x21, 0x95, 0xD7, 0x4C, 0x83, 0x07, 0xE3, 0x96, 0x37,
    //                 0xCB, 0xE5, 0xFB, 0x73, 0x0E, 0xBE, 0xAB, 0x80, 0xEC, 0x51, 0x4C, 0xF8, 0x8A, 0x87,
    //                 0x7C, 0xEE, 0xEE, 0x0B,
    //             ])
    //             .unwrap(),
    //             XOnly::from_bytes([
    //                 0xD7, 0x0C, 0xD6, 0x9A, 0x26, 0x47, 0xF7, 0x39, 0x09, 0x73, 0xDF, 0x48, 0xCB, 0xFA,
    //                 0x2C, 0xCC, 0x40, 0x7B, 0x8B, 0x2D, 0x60, 0xB0, 0x8C, 0x5F, 0x16, 0x41, 0x18, 0x5C,
    //                 0x79, 0x98, 0xA2, 0x90,
    //             ])
    //             .unwrap(),
    //             XOnly::from_bytes([
    //                 0x81, 0xA8, 0xB0, 0x93, 0x91, 0x2C, 0x9E, 0x48, 0x14, 0x08, 0xD0, 0x97, 0x76, 0xCE,
    //                 0xFB, 0x48, 0xAE, 0xB8, 0xB6, 0x54, 0x81, 0xB6, 0xBA, 0xAF, 0xB3, 0xC5, 0x81, 0x01,
    //                 0x06, 0x71, 0x7B, 0xEB,
    //             ])
    //             .unwrap(),
    //             XOnly::from_bytes([
    //                 0x2E, 0xB1, 0x88, 0x51, 0x88, 0x7E, 0x7B, 0xDC, 0x5E, 0x83, 0x0E, 0x89, 0xB1, 0x9D,
    //                 0xDB, 0xC2, 0x80, 0x78, 0xF1, 0xFA, 0x88, 0xAA, 0xD0, 0xAD, 0x01, 0xCA, 0x06, 0xFE,
    //                 0x4F, 0x80, 0x21, 0x0B,
    //             ])
    //             .unwrap(),
    //         ];

    //         let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    //         assert_eq!(
    //             musig
    //                 .new_agg_key(vec![X[0], X[1], X[2]])
    //                 .into_bip340_key()
    //                 .agg_public_key(),
    //             expected[0]
    //         );
    //         assert_eq!(
    //             musig
    //                 .new_agg_key(vec![X[2], X[1], X[0]])
    //                 .into_bip340_key()
    //                 .agg_public_key(),
    //             expected[1]
    //         );
    //         assert_eq!(
    //             musig
    //                 .new_agg_key(vec![X[0], X[0], X[0]])
    //                 .into_bip340_key()
    //                 .agg_public_key(),
    //             expected[2]
    //         );
    //         assert_eq!(
    //             musig
    //                 .new_agg_key(vec![X[0], X[0], X[1], X[1]])
    //                 .into_bip340_key()
    //                 .agg_public_key(),
    //             expected[3]
    //         );
    //     }

    //     #[test]
    //     fn test_sign_vectors() {
    //         let X1 = XOnly::from_bytes([
    //             0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
    //             0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
    //             0xBC, 0xE0, 0x36, 0xF9,
    //         ])
    //         .unwrap();
    //         let X2 = XOnly::from_bytes([
    //             0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
    //             0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
    //             0x50, 0x2B, 0xA6, 0x59,
    //         ])
    //         .unwrap();

    //         let sec_nonce = NonceKeyPair::from_bytes([
    //             0x50, 0x8B, 0x81, 0xA6, 0x11, 0xF1, 0x00, 0xA6, 0xB2, 0xB6, 0xB2, 0x96, 0x56, 0x59,
    //             0x08, 0x98, 0xAF, 0x48, 0x8B, 0xCF, 0x2E, 0x1F, 0x55, 0xCF, 0x22, 0xE5, 0xCF, 0xB8,
    //             0x44, 0x21, 0xFE, 0x61, 0xFA, 0x27, 0xFD, 0x49, 0xB1, 0xD5, 0x00, 0x85, 0xB4, 0x81,
    //             0x28, 0x5E, 0x1C, 0xA2, 0x05, 0xD5, 0x5C, 0x82, 0xCC, 0x1B, 0x31, 0xFF, 0x5C, 0xD5,
    //             0x4A, 0x48, 0x98, 0x29, 0x35, 0x59, 0x01, 0xF7,
    //         ])
    //         .unwrap();

    //         let agg_pubnonce = Nonce::from_bytes([
    //             0x02, 0x84, 0x65, 0xFC, 0xF0, 0xBB, 0xDB, 0xCF, 0x44, 0x3A, 0xAB, 0xCC, 0xE5, 0x33,
    //             0xD4, 0x2B, 0x4B, 0x5A, 0x10, 0x96, 0x6A, 0xC0, 0x9A, 0x49, 0x65, 0x5E, 0x8C, 0x42,
    //             0xDA, 0xAB, 0x8F, 0xCD, 0x61, 0x03, 0x74, 0x96, 0xA3, 0xCC, 0x86, 0x92, 0x6D, 0x45,
    //             0x2C, 0xAF, 0xCF, 0xD5, 0x5D, 0x25, 0x97, 0x2C, 0xA1, 0x67, 0x5D, 0x54, 0x93, 0x10,
    //             0xDE, 0x29, 0x6B, 0xFF, 0x42, 0xF7, 0x2E, 0xEE, 0xA8, 0xC9,
    //         ])
    //         .unwrap();

    //         let sk = Scalar::from_bytes([
    //             0x7F, 0xB9, 0xE0, 0xE6, 0x87, 0xAD, 0xA1, 0xEE, 0xBF, 0x7E, 0xCF, 0xE2, 0xF2, 0x1E,
    //             0x73, 0xEB, 0xDB, 0x51, 0xA7, 0xD4, 0x50, 0x94, 0x8D, 0xFE, 0x8D, 0x76, 0xD7, 0xF2,
    //             0xD1, 0x00, 0x76, 0x71,
    //         ])
    //         .unwrap()
    //         .mark::<NonZero>()
    //         .unwrap();

    //         let msg = [
    //             0xF9, 0x54, 0x66, 0xD0, 0x86, 0x77, 0x0E, 0x68, 0x99, 0x64, 0x66, 0x42, 0x19, 0x26,
    //             0x6F, 0xE5, 0xED, 0x21, 0x5C, 0x92, 0xAE, 0x20, 0xBA, 0xB5, 0xC9, 0xD7, 0x9A, 0xDD,
    //             0xDD, 0xF3, 0xC0, 0xCF,
    //         ];

    //         let expected: Vec<Scalar> = vec![
    //             Scalar::from_bytes([
    //                 0x68, 0x53, 0x7C, 0xC5, 0x23, 0x4E, 0x50, 0x5B, 0xD1, 0x40, 0x61, 0xF8, 0xDA, 0x9E,
    //                 0x90, 0xC2, 0x20, 0xA1, 0x81, 0x85, 0x5F, 0xD8, 0xBD, 0xB7, 0xF1, 0x27, 0xBB, 0x12,
    //                 0x40, 0x3B, 0x4D, 0x3B,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0x2D, 0xF6, 0x7B, 0xFF, 0xF1, 0x8E, 0x3D, 0xE7, 0x97, 0xE1, 0x3C, 0x64, 0x75, 0xC9,
    //                 0x63, 0x04, 0x81, 0x38, 0xDA, 0xEC, 0x5C, 0xB2, 0x0A, 0x35, 0x7C, 0xEC, 0xA7, 0xC8,
    //                 0x42, 0x42, 0x95, 0xEA,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0x0D, 0x5B, 0x65, 0x1E, 0x6D, 0xE3, 0x4A, 0x29, 0xA1, 0x2D, 0xE7, 0xA8, 0xB4, 0x18,
    //                 0x3B, 0x4A, 0xE6, 0xA7, 0xF7, 0xFB, 0xE1, 0x5C, 0xDC, 0xAF, 0xA4, 0xA3, 0xD1, 0xBC,
    //                 0xAA, 0xBC, 0x75, 0x17,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //         ];

    //         let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    //         let keypair = musig.schnorr.new_keypair(sk);

    //         let (remote_nonce1, remote_nonce2) = (
    //             agg_pubnonce,
    //             Nonce([-sec_nonce.public.0[0], -sec_nonce.public.0[1]]),
    //         );
    //         let message = Message::<Public>::raw(&msg);
    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![keypair.pk, X1, X2])
    //                 .into_bip340_key();

    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         sec_nonce.public(),
    //                         remote_nonce1.clone(),
    //                         remote_nonce2.clone(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 0, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[0]);
    //         }

    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![X1, keypair.pk, X2])
    //                 .into_bip340_key();
    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         remote_nonce1.clone(),
    //                         sec_nonce.public(),
    //                         remote_nonce2.clone(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 1, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[1]);
    //         }

    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![X1, X2, keypair.pk])
    //                 .into_bip340_key();
    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         remote_nonce1.clone(),
    //                         remote_nonce2.clone(),
    //                         sec_nonce.public(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 2, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[2]);
    //         }
    //     }

    //     #[test]
    //     fn test_tweak_vectors() {
    //         let X1 = XOnly::from_bytes([
    //             0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
    //             0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
    //             0xBC, 0xE0, 0x36, 0xF9,
    //         ])
    //         .unwrap();
    //         let X2 = XOnly::from_bytes([
    //             0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
    //             0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
    //             0x50, 0x2B, 0xA6, 0x59,
    //         ])
    //         .unwrap();

    //         let sec_nonce = NonceKeyPair::from_bytes([
    //             0x50, 0x8B, 0x81, 0xA6, 0x11, 0xF1, 0x00, 0xA6, 0xB2, 0xB6, 0xB2, 0x96, 0x56, 0x59,
    //             0x08, 0x98, 0xAF, 0x48, 0x8B, 0xCF, 0x2E, 0x1F, 0x55, 0xCF, 0x22, 0xE5, 0xCF, 0xB8,
    //             0x44, 0x21, 0xFE, 0x61, 0xFA, 0x27, 0xFD, 0x49, 0xB1, 0xD5, 0x00, 0x85, 0xB4, 0x81,
    //             0x28, 0x5E, 0x1C, 0xA2, 0x05, 0xD5, 0x5C, 0x82, 0xCC, 0x1B, 0x31, 0xFF, 0x5C, 0xD5,
    //             0x4A, 0x48, 0x98, 0x29, 0x35, 0x59, 0x01, 0xF7,
    //         ])
    //         .unwrap();

    //         let agg_pubnonce = Nonce::from_bytes([
    //             0x02, 0x84, 0x65, 0xFC, 0xF0, 0xBB, 0xDB, 0xCF, 0x44, 0x3A, 0xAB, 0xCC, 0xE5, 0x33,
    //             0xD4, 0x2B, 0x4B, 0x5A, 0x10, 0x96, 0x6A, 0xC0, 0x9A, 0x49, 0x65, 0x5E, 0x8C, 0x42,
    //             0xDA, 0xAB, 0x8F, 0xCD, 0x61, 0x03, 0x74, 0x96, 0xA3, 0xCC, 0x86, 0x92, 0x6D, 0x45,
    //             0x2C, 0xAF, 0xCF, 0xD5, 0x5D, 0x25, 0x97, 0x2C, 0xA1, 0x67, 0x5D, 0x54, 0x93, 0x10,
    //             0xDE, 0x29, 0x6B, 0xFF, 0x42, 0xF7, 0x2E, 0xEE, 0xA8, 0xC9,
    //         ])
    //         .unwrap();

    //         let sk = Scalar::from_bytes([
    //             0x7F, 0xB9, 0xE0, 0xE6, 0x87, 0xAD, 0xA1, 0xEE, 0xBF, 0x7E, 0xCF, 0xE2, 0xF2, 0x1E,
    //             0x73, 0xEB, 0xDB, 0x51, 0xA7, 0xD4, 0x50, 0x94, 0x8D, 0xFE, 0x8D, 0x76, 0xD7, 0xF2,
    //             0xD1, 0x00, 0x76, 0x71,
    //         ])
    //         .unwrap()
    //         .mark::<NonZero>()
    //         .unwrap();

    //         let tweaks: Vec<Scalar> = vec![
    //             Scalar::from_bytes([
    //                 0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF, 0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A,
    //                 0x72, 0x3D, 0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79, 0x80, 0x2B, 0x26, 0x3C,
    //                 0xDF, 0xCD, 0x83, 0xBB,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0xAE, 0x2E, 0xA7, 0x97, 0xCC, 0x0F, 0xE7, 0x2A, 0xC5, 0xB9, 0x7B, 0x97, 0xF3, 0xC6,
    //                 0x95, 0x7D, 0x7E, 0x41, 0x99, 0xA1, 0x67, 0xA5, 0x8E, 0xB0, 0x8B, 0xCA, 0xFF, 0xDA,
    //                 0x70, 0xAC, 0x04, 0x55,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0xF5, 0x2E, 0xCB, 0xC5, 0x65, 0xB3, 0xD8, 0xBE, 0xA2, 0xDF, 0xD5, 0xB7, 0x5A, 0x4F,
    //                 0x45, 0x7E, 0x54, 0x36, 0x98, 0x09, 0x32, 0x2E, 0x41, 0x20, 0x83, 0x16, 0x26, 0xF2,
    //                 0x90, 0xFA, 0x87, 0xE0,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0x19, 0x69, 0xAD, 0x73, 0xCC, 0x17, 0x7F, 0xA0, 0xB4, 0xFC, 0xED, 0x6D, 0xF1, 0xF7,
    //                 0xBF, 0x99, 0x07, 0xE6, 0x65, 0xFD, 0xE9, 0xBA, 0x19, 0x6A, 0x74, 0xFE, 0xD0, 0xA3,
    //                 0xCF, 0x5A, 0xEF, 0x9D,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //         ];
    //         let msg = [
    //             0xF9, 0x54, 0x66, 0xD0, 0x86, 0x77, 0x0E, 0x68, 0x99, 0x64, 0x66, 0x42, 0x19, 0x26,
    //             0x6F, 0xE5, 0xED, 0x21, 0x5C, 0x92, 0xAE, 0x20, 0xBA, 0xB5, 0xC9, 0xD7, 0x9A, 0xDD,
    //             0xDD, 0xF3, 0xC0, 0xCF,
    //         ];

    //         let expected: Vec<Scalar> = vec![
    //             Scalar::from_bytes([
    //                 0x5E, 0x24, 0xC7, 0x49, 0x6B, 0x56, 0x5D, 0xEB, 0xC3, 0xB9, 0x63, 0x9E, 0x6F, 0x13,
    //                 0x04, 0xA2, 0x15, 0x97, 0xF9, 0x60, 0x3D, 0x3A, 0xB0, 0x5B, 0x49, 0x13, 0x64, 0x17,
    //                 0x75, 0xE1, 0x37, 0x5B,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0x78, 0x40, 0x8D, 0xDC, 0xAB, 0x48, 0x13, 0xD1, 0x39, 0x4C, 0x97, 0xD4, 0x93, 0xEF,
    //                 0x10, 0x84, 0x19, 0x5C, 0x1D, 0x4B, 0x52, 0xE6, 0x3E, 0xCD, 0x7B, 0xC5, 0x99, 0x16,
    //                 0x44, 0xE4, 0x4D, 0xDD,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0xC3, 0xA8, 0x29, 0xA8, 0x14, 0x80, 0xE3, 0x6E, 0xC3, 0xAB, 0x05, 0x29, 0x64, 0x50,
    //                 0x9A, 0x94, 0xEB, 0xF3, 0x42, 0x10, 0x40, 0x3D, 0x16, 0xB2, 0x26, 0xA6, 0xF1, 0x6E,
    //                 0xC8, 0x5B, 0x73, 0x57,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //             Scalar::from_bytes([
    //                 0x8C, 0x44, 0x73, 0xC6, 0xA3, 0x82, 0xBD, 0x3C, 0x4A, 0xD7, 0xBE, 0x59, 0x81, 0x8D,
    //                 0xA5, 0xED, 0x7C, 0xF8, 0xCE, 0xC4, 0xBC, 0x21, 0x99, 0x6C, 0xFD, 0xA0, 0x8B, 0xB4,
    //                 0x31, 0x6B, 0x8B, 0xC7,
    //             ])
    //             .unwrap()
    //             .mark::<NonZero>()
    //             .unwrap(),
    //         ];

    //         let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    //         let keypair = musig.schnorr.new_keypair(sk);

    //         let (remote_nonce1, remote_nonce2) = (
    //             agg_pubnonce,
    //             Nonce([-sec_nonce.public.0[0], -sec_nonce.public.0[1]]),
    //         );
    //         let message = Message::<Public>::raw(&msg);

    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![X1, X2, keypair.pk])
    //                 .into_bip340_key()
    //                 .tweak(tweaks[0].clone())
    //                 .unwrap();
    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         remote_nonce1.clone(),
    //                         remote_nonce2.clone(),
    //                         sec_nonce.public(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 2, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[0]);
    //         }

    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![X1, X2, keypair.pk])
    //                 .into_bip340_key()
    //                 .tweak(tweaks[0].clone())
    //                 .unwrap();
    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         remote_nonce1.clone(),
    //                         remote_nonce2.clone(),
    //                         sec_nonce.public(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 2, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[0]);
    //         }

    //         {
    //             let agg_key = musig
    //                 .new_agg_key(vec![X1, X2, keypair.pk])
    //                 .tweak(tweaks[0].clone())
    //                 .unwrap()
    //                 .into_bip340_key()
    //                 .tweak(tweaks[1].clone())
    //                 .unwrap();

    //             let sign_session = musig
    //                 .start_sign_session(
    //                     &agg_key,
    //                     vec![
    //                         remote_nonce1.clone(),
    //                         remote_nonce2.clone(),
    //                         sec_nonce.public(),
    //                     ],
    //                     message,
    //                 )
    //                 .unwrap();
    //             let sig = musig.sign(&agg_key, 2, &keypair, sec_nonce.clone(), &sign_session);
    //             assert_eq!(sig, expected[2]);
    //         }

    //         // {
    //         //     let mut agg_key = musig.new_agg_key(vec![X1, X2, keypair.pk]);
    //         //     agg_key = agg_key.tweak(tweaks[0].clone(), true).unwrap();
    //         //     agg_key = agg_key.tweak(tweaks[1].clone(), false).unwrap();
    //         //     agg_key = agg_key.tweak(tweaks[2].clone(), true).unwrap();
    //         //     agg_key = agg_key.tweak(tweaks[3].clone(), false).unwrap();

    //         //     let sign_session = musig
    //         //         .start_sign_session(
    //         //             &agg_key,
    //         //             vec![
    //         //                 remote_nonce1.clone(),
    //         //                 remote_nonce2.clone(),
    //         //                 sec_nonce.public(),
    //         //             ],
    //         //             message,
    //         //         )
    //         //         .unwrap();
    //         //     let sig = musig.sign(&agg_key, 2, &keypair, sec_nonce.clone(), &sign_session);
    //         //     assert_eq!(sig, expected[3]);
    //         // }
    //     }
}
