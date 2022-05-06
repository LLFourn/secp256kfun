//! The MuSig2 multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{musig::{MuSig, Party}, Schnorr, Message, nonce::Deterministic};
//! use sha2::Sha256;
//! // use sha256 with deterministic nonce generation
//! let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
//! // create a keylist
//! # use schnorr_fun::fun::Scalar;
//! # let kp1 = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let kp3 = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let p1_pubkey = kp1.public_key();
//! # let p3_pubkey = kp3.public_key();
//! # let my_keypair = musig.schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
//! # let _keylist = musig.new_keylist(vec![
//! #     Party::Local(kp1),
//! #     Party::Remote(my_keypair.public_key()),
//! #     Party::Local(kp3),
//! # ]);
//! let keylist = musig.new_keylist(vec![
//!     Party::Remote(p1_pubkey),
//!     Party::Local(my_keypair),
//!     Party::Remote(p3_pubkey),
//! ]);
//! let message = Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! // generate our aggregate key
//! let agg_key = keylist.agg_public_key();
//! // start a MuSig2 session by first exchanging nonces.
//! // Since we're using deterministic nonces it's important we only use the session id once
//! let my_nonces = musig.gen_nonces(&keylist, b"session-id-1337");
//! // send this to the other parties
//! let my_public_nonce = my_nonces[0].public();
//! # let nonces = musig.gen_nonces(&_keylist, b"session-id-1337");
//! # let p1_nonce = nonces[0].public();
//! # let p3_nonce = nonces[1].public();
//! # let mut _session = musig.start_sign_session_deterministic(&_keylist, my_nonces.iter().map(|n| n.public()), b"session-id-1337", message).unwrap();
//! // Once you've got the nonces from the other two (p1_nonce and p3_nonce) you can start the signing session.
//! let mut session = musig.start_sign_session(&keylist, my_nonces, [p1_nonce, p3_nonce], message).unwrap();
//! // but since we're using deterministic nonce generation we can just remember the session id.
//! // You should guarantee that this is not called ever again with the same session id!!!!
//! let mut session = musig.start_sign_session_deterministic(&keylist, [p1_nonce, p3_nonce], b"session-id-1337", message).unwrap();
//! // sign with our (single) local keypair
//! let my_sig = musig.sign_all(&keylist, &mut session)[0];
//! # let _sigs = musig.sign_all(&_keylist, &mut _session);
//! # let p1_sig = _sigs[0];
//! # let p3_sig = _sigs[1];
//! // receive p1_sig and p3_sig from somewhere and check they're valid
//! assert!(musig.verify_partial_signature(&keylist, &session, 0, p1_sig));
//! assert!(musig.verify_partial_signature(&keylist, &session, 2, p3_sig));
//! // combine them with ours into the final signature
//! let sig = musig.combine_partial_signatures(&keylist, &session, [my_sig, p1_sig, p3_sig]);
//! // check it's a valid normal Schnorr signature
//! musig.schnorr.verify(&keylist.agg_verification_key(), message, &sig);
//! ```
//!
//! ## Description
//!
//! The MuSig2 multisignature scheme lets you aggregate multiple public keys into a single public
//! key that requires all of the corresponding secret keys to authorize a signature under the aggregate key.
//!
//! This implementation is protocol compatible with the implementation merged into
//! [secp256k1-zkp].
//!
//! See [the excellent paper] for the abstract details of the protocol.
//!
//! [the excellent paper]: https://eprint.iacr.org/2020/1261.pdf
//! [secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/131
use crate::{adaptor::EncryptedSignature, KeyPair, Message, Schnorr, Signature, Vec};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::{Deterministic, NonceGen},
    s, Point, Scalar, XOnly, G,
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

impl<H: Tagged> MuSig<H, ()> {
    /// Creates a MuSig context that can only do key aggregation.
    ///
    /// # Example
    ///
    /// ```
    /// # use schnorr_fun::fun::{ XOnly };
    /// # let key1 = XOnly::random(&mut rand::thread_rng());
    /// # let key2 = XOnly::random(&mut rand::thread_rng());
    /// use schnorr_fun::musig::{MuSig, Party};
    /// use sha2::Sha256;
    /// let musig = MuSig::<Sha256>::keyagg_only();
    /// let keylist = musig.new_keylist(vec![Party::Remote(key1), Party::Remote(key2)]);
    /// println!("{:?}", keylist.agg_public_key())
    /// ```
    pub fn keyagg_only() -> Self {
        Self::_new(())
    }
}

impl<H: Tagged, NG> MuSig<H, Schnorr<H, NG>> {
    /// Generate a new MuSig context from a Schnorr context.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self::_new(schnorr)
    }
}

/// A party in the protocol.
///
/// A party is either local (we know the secret key) or remote (we only know the public key).
#[derive(Debug, Clone)]
pub enum Party {
    /// A local party (we have the keypair)
    Local(KeyPair),
    /// A remote party (we only know the public key)
    Remote(XOnly),
}

/// A list of keys aggregated into a single key.
///
/// Created using [`MuSig::new_keylist`].
///
/// The `KeyList` can't be serialized but it's very efficient to re-create it from the initial list of keys.
///
/// [`MuSig::new_keylist`]
#[derive(Debug, Clone)]
pub struct KeyList {
    /// The parties involved in the key aggregation.
    parties: Vec<Party>,
    /// The coefficients of each key
    coefs: Vec<Scalar<Public>>,
    /// The aggregate key
    agg_key: Point<EvenY>,
    /// The
    tweak: Scalar<Public, Zero>,
    needs_negation: bool,
}

impl KeyList {
    /// The `XOnly` aggregated key for the keylist.
    pub fn agg_public_key(&self) -> XOnly {
        self.agg_key.to_xonly()
    }
    /// The aggregated key for the keylist as a `Point`.
    pub fn agg_verification_key(&self) -> Point<EvenY> {
        self.agg_key
    }
    /// An iterator over the **public keys** of each party in the keylist.
    pub fn keys(&self) -> impl Iterator<Item = XOnly> + '_ {
        self.parties.iter().map(|party| match party {
            Party::Local(keypair) => keypair.public_key(),
            Party::Remote(xonly) => *xonly,
        })
    }

    /// Returns an iterator over the parties
    pub fn parties(&self) -> impl Iterator<Item = &Party> {
        self.parties.iter()
    }

    /// Clear all secret keys from the parties.
    ///
    /// i.e. convert all [`Party::Local`] into [`Party::Remote`]
    pub fn clear_secrets(self) -> KeyList {
        Self {
            parties: self.keys().map(|key| Party::Remote(key)).collect(),
            ..self
        }
    }

    /// *Tweak* the aggregated key with a scalar so that the resulting key is equal to the existing
    /// key plus `tweak * G`. The tweak mutates the public key while still allowing the original set
    /// of signers to sign under the new key.
    ///
    /// This is how you embed a taproot commitment into a key.
    ///
    /// ## Return value
    ///
    /// Returns a new keylist with the same parties but a different aggregated public key. In the
    /// unusual case that the tweak is exactly equal to the negation of the aggregated secret key
    /// it returns `None`.
    pub fn tweak(&self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let (agg_key, needs_negation) = g!(self.agg_key + tweak * G)
            .mark::<NonZero>()?
            .into_point_with_even_y();

        // Store accumulated tweak
        let mut tweak = s!(self.tweak + tweak).mark::<Public>();
        tweak.conditional_negate(needs_negation);

        let needs_negation = self.needs_negation ^ needs_negation;

        Some(KeyList {
            parties: self.parties.clone(),
            coefs: self.coefs.clone(),
            agg_key,
            tweak,
            needs_negation,
        })
    }
}

impl<H: Digest<OutputSize = U32> + Clone, S> MuSig<H, S> {
    /// Generates a new key list from a list of parties.
    ///
    /// Each party can be local (you know the secret key) or remote (you only know the public key).
    ///
    /// ## Example
    ///
    /// ```
    /// use schnorr_fun::{
    ///     fun::{Point, Scalar, XOnly},
    ///     musig::{MuSig, Party},
    ///     nonce::Deterministic,
    ///     Schnorr,
    /// };
    /// # let my_secret_key = Scalar::random(&mut rand::thread_rng());
    /// # let their_public_key = XOnly::random(&mut rand::thread_rng());
    /// use sha2::Sha256;
    /// let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();
    /// let my_keypair = musig.schnorr.new_keypair(my_secret_key);
    /// // Note the keys have to come in the same order on the other side!
    /// let keylist = musig.new_keylist(vec![
    ///     Party::Local(my_keypair),
    ///     Party::Remote(their_public_key),
    /// ]);
    /// ```
    pub fn new_keylist(&self, parties: Vec<Party>) -> KeyList {
        let keys = parties
            .iter()
            .map(|party| match party {
                Party::Local(keypair) => keypair.public_key(),
                Party::Remote(xonly) => *xonly,
            })
            .collect::<Vec<_>>();

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
        let points = keys.into_iter().map(|x| x.to_point()).collect::<Vec<_>>();

        let (agg_key, needs_negation) = crate::fun::op::lincomb(coefs.iter(), points.iter())
            .expect_nonzero("computationally unreachable: linear combination of hash randomised points cannot add to zero")
            .into_point_with_even_y();

        KeyList {
            parties,
            coefs,
            agg_key,
            tweak: Scalar::zero().mark::<Public>(),
            needs_negation,
        }
    }
}

/// A nonce (pair of points) that each party must share with the others in the first stage of signing.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Nonce(pub [Point; 2]);

impl Nonce {
    /// Reads the pair of nonces from 66 bytes (two 33-byte serialized points).
    pub fn from_bytes(bytes: [u8; 66]) -> Option<Self> {
        let R1 = Point::from_slice(&bytes[..33])?;
        let R2 = Point::from_slice(&bytes[33..])?;
        Some(Nonce([R1, R2]))
    }

    /// Serializes a public nonce as  as 66 bytes (two 33-byte serialized points).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(self.0[0].to_bytes().as_ref());
        bytes[33..].copy_from_slice(self.0[1].to_bytes().as_ref());
        bytes
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "MuSig2 public nonce pair",
    fn from_bytes(bytes: [u8;66]) -> Option<Nonce> {
        Nonce::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nonce: &Nonce) -> [u8;66] {
        nonce.to_bytes()
    }
}

/// A pair of secret nonces along with the public portion.
///
/// A nonce key pair can be created manually with [`from_secrets`] or with [`MuSig::gen_nonces`].
///
/// [`from_secrets`]: Self::from_secrets
/// [`MuSig::gen_nonces`]: MuSig::gen_nonces
#[derive(Debug, Clone, PartialEq)]
pub struct NonceKeyPair {
    /// The public nonce
    public: Nonce,
    /// The secret nonce
    secret: [Scalar; 2],
}

impl NonceKeyPair {
    /// Creates a keypair from two secret scalars.
    ///
    /// ## Security
    ///
    /// You must never use the same `NonceKeyPair` into two signing sessions.
    ///
    /// ## Example
    /// ```
    /// use schnorr_fun::{fun::Scalar, musig::NonceKeyPair};
    /// let nkp = NonceKeyPair::from_secrets([
    ///     Scalar::random(&mut rand::thread_rng()),
    ///     Scalar::random(&mut rand::thread_rng()),
    /// ]);
    /// ```
    pub fn from_secrets(secret: [Scalar; 2]) -> Self {
        let [ref r1, ref r2] = secret;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret,
        }
    }
    /// Deserializes a nonce key pair from 64-bytes (two 32-byte serialized scalars).
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let r1 = Scalar::from_slice(&bytes[..32])?.mark::<NonZero>()?;
        let r2 = Scalar::from_slice(&bytes[32..])?.mark::<NonZero>()?;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        let pub_nonce = Nonce([R1, R2]);
        Some(NonceKeyPair {
            public: pub_nonce,
            secret: [r1, r2],
        })
    }

    /// Serializes a nonce key pair to 64-bytes (two 32-bytes serialized scalars).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.secret[0].to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.secret[1].to_bytes().as_ref());
        bytes
    }

    /// Get the secret portion of the nonce key pair (don't share this!)
    pub fn secret(&self) -> &[Scalar; 2] {
        &self.secret
    }

    /// Get the public portion of the nonce key pair (share this!)
    pub fn public(&self) -> Nonce {
        self.public
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "MuSig secret nonce pair",
    fn from_bytes(bytes: [u8;64]) -> Option<NonceKeyPair> {
        NonceKeyPair::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nkp: &NonceKeyPair) -> [u8;64] {
        nkp.to_bytes()
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> MuSig<H, Schnorr<H, NG>> {
    /// Generate nonces for your local keys in keylist.
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
    /// recoverable from the two partial signatures you created with the same nonce. The upside is
    /// that you can call [`start_sign_session_deterministic`] with the `sid` you originally passed
    /// to `gen_nonces` without having to store the output of `gen_nonces`.
    ///
    /// Note that the API allows you to BYO nonces by creating `NonceKeyPair`s manually.
    ///
    /// [`NonceGen`]: secp256kfun::nonce::NonceGen
    /// [`Synthetic`]: secp256kfun::nonce::Synthetic
    /// [`Deterministic`]: secp256kfun::nonce::Deterministic
    /// [`start_sign_session`]: Self::start_sign_session
    /// [`start_sign_session_deterministic`]: Self::start_sign_session_deterministic
    pub fn gen_nonces(&self, keylist: &KeyList, sid: &[u8]) -> Vec<NonceKeyPair> {
        keylist
            .parties
            .iter()
            .filter_map(|party| match party {
                Party::Local(keypair) => {
                    let r1 = derive_nonce!(
                        nonce_gen => self.schnorr.nonce_gen(),
                        secret => keypair.secret_key(),
                        public => [ b"r1", keypair.public_key(), keylist.agg_public_key(), sid]
                    );
                    let r2 = derive_nonce!(
                        nonce_gen => self.schnorr.nonce_gen(),
                        secret => keypair.secret_key(),
                        public => [ b"r2", keypair.public_key(), keylist.agg_public_key(), sid]
                    );
                    let R1 = g!(r1 * G).normalize();
                    let R2 = g!(r2 * G).normalize();
                    Some(NonceKeyPair {
                        public: Nonce([R1, R2]),
                        secret: [r1, r2],
                    })
                }
                Party::Remote(_) => None,
            })
            .collect()
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
/// This struct has **secret nonces** in it up until you call [`clear_secrets`] or [`sign_all`]. If
/// a malicious party gains access to it before and you generate a partial signature with this session they
/// will be able to recover your secret key. If this is a concern simply avoid serializing this
/// struct (until you've cleared it) and recreate it only when you need it.
///
/// [`start_sign_session`]: MuSig::start_sign_session
/// [`start_encrypted_sign_session`]: MuSig::start_encrypted_sign_session
/// [`clear_secrets`]: SignSession::clear_secrets
/// [`sign_all`]: MuSig::sign_all
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct SignSession<T = Ordinary> {
    b: Scalar<Public, Zero>,
    c: Scalar<Public, Zero>,
    local_secret_nonces: Vec<[Scalar; 2]>,
    public_nonces: Vec<Nonce>,
    R: Point<EvenY>,
    signing_type: T,
}

impl<T> SignSession<T> {
    /// Removes all secret nonce data from the session.
    ///
    /// The session works as normal except that it can no longer be used for signing ([`sign_all`] will return an empty vector).
    ///
    /// [`sign_all`]: MuSig::sign_all
    pub fn clear_secrets(&mut self) {
        self.local_secret_nonces.drain(..);
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG> MuSig<H, Schnorr<H, NG>> {
    /// Start a signing session.
    ///
    /// You must provide you local secret nonces (the public portion must be shared with the other signer(s)).
    /// If you are using deterministic nonce generations it's possible to use [`start_sign_session_deterministic`] instead.
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
    /// `keylist`.
    ///
    /// [`start_sign_session_deterministic`]: Self::start_sign_session_deterministic
    pub fn start_sign_session(
        &self,
        keylist: &KeyList,
        local_nonces: Vec<NonceKeyPair>,
        remote_nonces: impl IntoIterator<Item = Nonce>,
        message: Message<'_, Public>,
    ) -> Option<SignSession> {
        let (b, c, local_secret_nonces, public_nonces, R, _) = self._start_sign_session(
            keylist,
            local_nonces,
            remote_nonces,
            message,
            &Point::zero(),
        )?;
        Some(SignSession {
            b,
            c,
            local_secret_nonces,
            public_nonces,
            R,
            signing_type: Ordinary,
        })
    }

    /// Start an encrypted signing session.
    ///
    /// i.e. a session to produce an adaptor signature under `encryption_key`.
    /// See [`adaptor`] for a more general description of adaptor signatures.
    ///
    /// You must provide you local secret nonces (the public portion must be shared with the other
    /// signer(s)). If you are using deterministic nonce generation it's possible to use
    /// [`start_encrypted_sign_session_deterministic`] instead.
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
    /// `keylist`.
    ///
    /// [`start_encrypted_sign_session_deterministic`]: Self::start_sign_session_deterministic
    /// [`adaptor`]: crate::adaptor
    pub fn start_encrypted_sign_session(
        &self,
        keylist: &KeyList,
        local_nonces: Vec<NonceKeyPair>,
        remote_nonces: impl IntoIterator<Item = Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy>,
    ) -> Option<SignSession<Adaptor>> {
        let (b, c, local_secret_nonces, public_nonces, R, y_needs_negation) = self
            ._start_sign_session(
                keylist,
                local_nonces,
                remote_nonces,
                message,
                encryption_key,
            )?;
        Some(SignSession {
            b,
            c,
            local_secret_nonces,
            public_nonces,
            R,
            signing_type: Adaptor { y_needs_negation },
        })
    }

    fn _start_sign_session(
        &self,
        keylist: &KeyList,
        local_nonces: Vec<NonceKeyPair>,
        remote_nonces: impl IntoIterator<Item = Nonce>,
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy, impl ZeroChoice>,
    ) -> Option<(
        Scalar<Public, Zero>,
        Scalar<Public, Zero>,
        Vec<[Scalar; 2]>,
        Vec<Nonce>,
        Point<EvenY>,
        bool,
    )> {
        let mut remote_nonces = remote_nonces.into_iter();
        let mut local_pubnonces = local_nonces.iter().map(|nonce| nonce.public);

        let mut Rs = keylist
            .parties
            .iter()
            .map(|party| match party {
                Party::Local(_) => local_pubnonces
                    .next()
                    .expect("missing local nonce keypair -- must have one for each local party"),
                Party::Remote(_) => remote_nonces.next().expect("missing remote nonce"),
            })
            .collect::<Vec<_>>();

        assert!(
            remote_nonces.next().is_none(),
            "Too many remote nonces passed in"
        );
        assert!(
            local_pubnonces.next().is_none(),
            "Too many local nonces passed in"
        );

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
            Scalar::from_hash(H.add(agg_Rs).add(keylist.agg_public_key()).add(message))
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

        let local_secret_nonces = local_nonces
            .into_iter()
            .map(|local_nonce| {
                let mut secret = local_nonce.secret;
                secret[0].conditional_negate(r_needs_negation);
                secret[1].conditional_negate(r_needs_negation);
                secret
            })
            .collect();

        let c = self
            .schnorr
            .challenge(R.to_xonly(), keylist.agg_public_key(), message);

        Some((b, c, local_secret_nonces, Rs, R, r_needs_negation))
    }

    /// Generates partial signatures (or partial encrypted signatures depending on `T`) under each of the `Local` entries in `keylist`.
    ///
    /// The order of the partial signatures returned is the order of them in the keylist.
    ///
    /// This can only be called once per session as it clears the session (see also [`clear_secrets`]).
    /// Calling `sign_all` again will return an empty vector.
    ///
    /// [`clear_secrets`]: SignSession::clear_secrets
    pub fn sign_all<T>(
        &self,
        keylist: &KeyList,
        session: &mut SignSession<T>,
    ) -> Vec<Scalar<Public, Zero>> {
        let c = session.c;
        let b = session.b;

        keylist
            .parties
            .iter()
            .enumerate()
            .filter_map(|(i, party)| match party {
                Party::Local(keypair) => Some((i, keypair)),
                Party::Remote(_) => None,
            })
            .zip(session.local_secret_nonces.drain(..))
            .map(|((i, keypair), secret_nonces)| {
                let x = keypair.secret_key();
                let [r1, r2] = secret_nonces;
                let mut a = keylist.coefs[i];
                a.conditional_negate(keylist.needs_negation);
                s!(c * a * x + r1 + b * r2).mark::<(Public, Zero)>()
            })
            .collect()
    }

    #[must_use]
    /// Verifies a partial signature (or partial encrypted signature depending on `T`).
    ///
    /// You must provide the `index` of the party (the index of the key in `keylist`).
    ///
    /// # Panics
    ///
    /// Panics when `index` is equal to or greater than the number of parties in the keylist.
    pub fn verify_partial_signature<T>(
        &self,
        keylist: &KeyList,
        session: &SignSession<T>,
        index: usize,
        partial_sig: Scalar<Public, Zero>,
    ) -> bool {
        let c = session.c;
        let b = session.b;
        let s = &partial_sig;
        let mut a = keylist.coefs[index].clone();
        a.conditional_negate(keylist.needs_negation);
        let X = keylist.keys().nth(index).unwrap().to_point();
        let [ref R1, ref R2] = &session.public_nonces[index].0;
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
        keylist: &KeyList,
        session: &SignSession<Ordinary>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> Signature {
        let (R, s) = self._combine_partial_signatures(keylist, &session, partial_sigs);
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
        keylist: &KeyList,
        session: &SignSession<Adaptor>,
        partial_encrypted_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> EncryptedSignature {
        let (R, s_hat) =
            self._combine_partial_signatures(keylist, &session, partial_encrypted_sigs);
        EncryptedSignature {
            R,
            s_hat,
            needs_negation: session.signing_type.y_needs_negation,
        }
    }

    fn _combine_partial_signatures<T>(
        &self,
        keylist: &KeyList,
        session: &SignSession<T>,
        partial_sigs: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> (Point<EvenY>, Scalar<Public, Zero>) {
        let ck = s!(session.c * keylist.tweak);
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, s| s!(acc + s).mark::<Public>())
            .unwrap_or(Scalar::zero().mark::<Public>());
        let s = s!(sum_s + ck).mark::<Public>();
        (session.R, s)
    }
}

impl<H: Digest<OutputSize = U32> + Clone, HNG> MuSig<H, Schnorr<H, Deterministic<HNG>>>
where
    Deterministic<HNG>: NonceGen,
{
    /// Same as [`start_sign_session`] but re-generate the local nonces deterministically from the
    /// `sid` instead of passing them in.
    ///
    /// ## Security
    ///
    /// Each call to this function must have a unique `sid`. Never call it twice with the same
    /// `sid`, otherwise you risk revealing your secret key with the two signatures generated from
    /// it if `message` or `remote_nonces` changes.
    ///
    /// [`start_sign_session`]: Self::start_sign_session
    pub fn start_sign_session_deterministic(
        &self,
        keylist: &KeyList,
        remote_nonces: impl IntoIterator<Item = Nonce>,
        sid: &[u8],
        message: Message<'_, Public>,
    ) -> Option<SignSession> {
        let local_nonces = self.gen_nonces(keylist, sid);
        self.start_sign_session(keylist, local_nonces, remote_nonces, message)
    }

    /// Same as [`start_encrypted_sign_session`] but re-generate the local nonces deterministically from the
    /// `sid` instead of passing them in.
    ///
    /// ## Security
    ///
    /// Each call to this function must have a unique `sid`. Never call it twice with the same
    /// `sid`, otherwise you risk revealing your secret key with the two signatures generated from
    /// it if `message` or `remote_nonces` changes.
    ///
    /// [`start_encrypted_sign_session`]: Self::start_encrypted_sign_session
    pub fn start_encrypted_sign_session_deterministic(
        &self,
        keylist: &KeyList,
        remote_nonces: impl IntoIterator<Item = Nonce>,
        sid: &[u8],
        message: Message<'_, Public>,
        encryption_key: &Point<impl PointType, impl Secrecy>,
    ) -> Option<SignSession<Adaptor>> {
        let local_nonces = self.gen_nonces(keylist, sid);
        self.start_encrypted_sign_session(
            keylist,
            local_nonces,
            remote_nonces,
            message,
            encryption_key,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::adaptor::Adaptor;

    use super::*;
    use secp256kfun::{nonce::Deterministic, proptest::prelude::*};
    use sha2::Sha256;

    proptest! {
        #[test]
        fn test_end_to_end(sk1 in any::<Scalar>(), sk2 in any::<Scalar>(), sk3 in any::<Scalar>(), tweak in any::<Scalar<Public, Zero>>(), use_tweak in any::<bool>()) {
            let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
                .schnorr
                .new_keypair(sk1);
            let keypair2 = musig
                .schnorr
                .new_keypair(sk2);
            let keypair3 = musig
                .schnorr
                .new_keypair(sk3);
            let mut keylist_p1 = musig.new_keylist(vec![
                Party::Local(keypair1.clone()),
                Party::Remote(keypair2.public_key()),
                Party::Local(keypair3.clone()),
            ]);
            let mut keylist_p2 = musig.new_keylist(vec![
                Party::Remote(keypair1.public_key()),
                Party::Local(keypair2),
                Party::Remote(keypair3.public_key()),
            ]);

            if use_tweak {
                keylist_p1 = keylist_p1.tweak(tweak).unwrap();
                keylist_p2 = keylist_p2.tweak(tweak).unwrap();
            }
            assert_eq!(keylist_p1.agg_public_key(), keylist_p2.agg_public_key());

            let p1_nonces = musig.gen_nonces(&keylist_p1, b"test");
            let p2_nonces = musig.gen_nonces(&keylist_p2, b"test");
            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let mut p1_session = musig
                .start_sign_session(
                    &keylist_p1,
                    p1_nonces.clone(),
                    p2_nonces.iter().map(|nonce| nonce.public),
                    message,
                )
                .unwrap();
            let mut p2_session = musig
                .start_sign_session_deterministic(
                    &keylist_p2,
                    p1_nonces.iter().map(|nonce| nonce.public),
                    b"test",
                    message,
                )
                .unwrap();
            let p1_sigs = musig.sign_all(&keylist_p1, &mut p1_session);
            assert_eq!(musig.sign_all(&keylist_p1, &mut p1_session).len(), 0, "sign_all should hose the session");

            assert_eq!(p1_sigs.len(), 2);
            for (j, i) in [0, 2].iter().enumerate() {
                assert!(musig.verify_partial_signature(&keylist_p2, &p2_session, *i, p1_sigs[j]));
                assert!(musig.verify_partial_signature(&keylist_p1, &p1_session, *i, p1_sigs[j]));
            }

            let p2_sigs = musig.sign_all(&keylist_p2, &mut p2_session);
            assert_eq!(p2_sigs.len(), 1);
            assert!(musig.verify_partial_signature(&keylist_p2, &p2_session, 1, p2_sigs[0]));
            assert!(musig.verify_partial_signature(&keylist_p1, &p1_session, 1, p2_sigs[0]));

            let partial_sigs = [p1_sigs, p2_sigs].concat();
            let sig_p1 = musig.combine_partial_signatures(&keylist_p1, &p1_session, partial_sigs.clone());
            let sig_p2 = musig.combine_partial_signatures(&keylist_p2, &p2_session, partial_sigs);
            assert_eq!(sig_p1, sig_p2);
            assert!(musig
                    .schnorr
                    .verify(&keylist_p1.agg_verification_key(), message, &sig_p1));
            assert!(musig
                    .schnorr
                    .verify(&keylist_p2.agg_verification_key(), message, &sig_p2));
        }

        #[test]
        fn test_musig_adaptor(sk1 in any::<Scalar>(), sk2 in any::<Scalar>(), sk3 in any::<Scalar>(), y in any::<Scalar>()) {
            let schnorr = Schnorr::<Sha256, _>::new(Deterministic::<Sha256>::default());
            let musig = MuSig::new(schnorr);
            let keypair1 = musig
                .schnorr
                .new_keypair(sk1);
            let keypair2 = musig
                .schnorr
                .new_keypair(sk2);
            let keypair3 = musig
                .schnorr
                .new_keypair(sk3);
            let encryption_key = musig.schnorr.encryption_key_for(&y);
            let keylist_p1 = musig.new_keylist(vec![
                Party::Local(keypair1.clone()),
                Party::Remote(keypair2.public_key()),
                Party::Local(keypair3.clone()),
            ]);
            let keylist_p2 = musig.new_keylist(vec![
                Party::Remote(keypair1.public_key()),
                Party::Local(keypair2),
                Party::Remote(keypair3.public_key()),
            ]);
            assert_eq!(keylist_p1.agg_public_key(), keylist_p2.agg_public_key());

            let p1_nonces = musig.gen_nonces(&keylist_p1, b"test");
            let p2_nonces = musig.gen_nonces(&keylist_p2, b"test");
            let message =
                Message::<Public>::plain("test", b"Chancellor on brink of second bailout for banks");

            let mut p1_session = musig
                .start_encrypted_sign_session(
                    &keylist_p1,
                    p1_nonces.clone(),
                    p2_nonces.iter().map(|nonce| nonce.public),
                    message,
                    &encryption_key
                )
                .unwrap();
            let mut p2_session = musig
                .start_encrypted_sign_session_deterministic(
                    &keylist_p2,
                    p1_nonces.iter().map(|nonce| nonce.public),
                    b"test",
                    message,
                    &encryption_key
                )
                .unwrap();
            let p1_sigs = musig.sign_all(&keylist_p1, &mut p1_session);

            assert_eq!(p1_sigs.len(), 2);
            for (j, i) in [0, 2].iter().enumerate() {
                assert!(musig.verify_partial_signature(&keylist_p2, &p2_session, *i, p1_sigs[j]));
                assert!(musig.verify_partial_signature(&keylist_p1, &p1_session, *i, p1_sigs[j]));
            }

            let p2_sigs = musig.sign_all(&keylist_p2, &mut p2_session);
            assert_eq!(p2_sigs.len(), 1);
            assert!(musig.verify_partial_signature(&keylist_p2, &p2_session, 1, p2_sigs[0]));
            assert!(musig.verify_partial_signature(&keylist_p1, &p1_session, 1, p2_sigs[0]));

            let partial_sigs = [p1_sigs, p2_sigs].concat();
            let sig_p1 = musig.combine_partial_encrypted_signatures(&keylist_p1, &p1_session, partial_sigs.clone());
            let sig_p2 = musig.combine_partial_encrypted_signatures(&keylist_p2, &p2_session, partial_sigs);
            assert_eq!(sig_p1, sig_p2);
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&keylist_p1.agg_verification_key(), &encryption_key, message, &sig_p1));
            assert!(musig
                    .schnorr
                    .verify_encrypted_signature(&keylist_p2.agg_verification_key(), &encryption_key, message, &sig_p2));

        }

    }
    #[test]
    fn sign_test_vectors() {
        let musig = MuSig::<Sha256, Schnorr<Sha256, Deterministic<Sha256>>>::default();

        let X1 = XOnly::from_bytes([
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
            0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
            0xBC, 0xE0, 0x36, 0xF9,
        ])
        .unwrap();
        let X2 = XOnly::from_bytes([
            0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
            0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
            0x50, 0x2B, 0xA6, 0x59,
        ])
        .unwrap();
        let keypair = musig.schnorr.new_keypair(
            Scalar::from_bytes([
                0x7F, 0xB9, 0xE0, 0xE6, 0x87, 0xAD, 0xA1, 0xEE, 0xBF, 0x7E, 0xCF, 0xE2, 0xF2, 0x1E,
                0x73, 0xEB, 0xDB, 0x51, 0xA7, 0xD4, 0x50, 0x94, 0x8D, 0xFE, 0x8D, 0x76, 0xD7, 0xF2,
                0xD1, 0x00, 0x76, 0x71,
            ])
            .unwrap()
            .mark::<NonZero>()
            .unwrap(),
        );

        let secnonce = NonceKeyPair::from_bytes([
            0x50, 0x8B, 0x81, 0xA6, 0x11, 0xF1, 0x00, 0xA6, 0xB2, 0xB6, 0xB2, 0x96, 0x56, 0x59,
            0x08, 0x98, 0xAF, 0x48, 0x8B, 0xCF, 0x2E, 0x1F, 0x55, 0xCF, 0x22, 0xE5, 0xCF, 0xB8,
            0x44, 0x21, 0xFE, 0x61, 0xFA, 0x27, 0xFD, 0x49, 0xB1, 0xD5, 0x00, 0x85, 0xB4, 0x81,
            0x28, 0x5E, 0x1C, 0xA2, 0x05, 0xD5, 0x5C, 0x82, 0xCC, 0x1B, 0x31, 0xFF, 0x5C, 0xD5,
            0x4A, 0x48, 0x98, 0x29, 0x35, 0x59, 0x01, 0xF7,
        ])
        .unwrap();

        let agg_pubnonce = Nonce::from_bytes([
            0x02, 0x84, 0x65, 0xFC, 0xF0, 0xBB, 0xDB, 0xCF, 0x44, 0x3A, 0xAB, 0xCC, 0xE5, 0x33,
            0xD4, 0x2B, 0x4B, 0x5A, 0x10, 0x96, 0x6A, 0xC0, 0x9A, 0x49, 0x65, 0x5E, 0x8C, 0x42,
            0xDA, 0xAB, 0x8F, 0xCD, 0x61, 0x03, 0x74, 0x96, 0xA3, 0xCC, 0x86, 0x92, 0x6D, 0x45,
            0x2C, 0xAF, 0xCF, 0xD5, 0x5D, 0x25, 0x97, 0x2C, 0xA1, 0x67, 0x5D, 0x54, 0x93, 0x10,
            0xDE, 0x29, 0x6B, 0xFF, 0x42, 0xF7, 0x2E, 0xEE, 0xA8, 0xC9,
        ])
        .unwrap();
        let remote_nonces = vec![
            agg_pubnonce,
            Nonce([-secnonce.public.0[0], -secnonce.public.0[1]]),
        ];
        let msg = [
            0xF9, 0x54, 0x66, 0xD0, 0x86, 0x77, 0x0E, 0x68, 0x99, 0x64, 0x66, 0x42, 0x19, 0x26,
            0x6F, 0xE5, 0xED, 0x21, 0x5C, 0x92, 0xAE, 0x20, 0xBA, 0xB5, 0xC9, 0xD7, 0x9A, 0xDD,
            0xDD, 0xF3, 0xC0, 0xCF,
        ];
        {
            let keylist = musig.new_keylist(vec![
                Party::Local(keypair.clone()),
                Party::Remote(X1),
                Party::Remote(X2),
            ]);
            let mut session = musig
                .start_sign_session(
                    &keylist,
                    vec![secnonce.clone()],
                    remote_nonces.clone(),
                    Message::<Public>::raw(&msg),
                )
                .unwrap();

            let scalar = musig.sign_all(&keylist, &mut session)[0];
            let expected = Scalar::from_bytes([
                0x68, 0x53, 0x7C, 0xC5, 0x23, 0x4E, 0x50, 0x5B, 0xD1, 0x40, 0x61, 0xF8, 0xDA, 0x9E,
                0x90, 0xC2, 0x20, 0xA1, 0x81, 0x85, 0x5F, 0xD8, 0xBD, 0xB7, 0xF1, 0x27, 0xBB, 0x12,
                0x40, 0x3B, 0x4D, 0x3B,
            ])
            .unwrap();
            assert_eq!(scalar, expected)
        }

        {
            let keylist = musig.new_keylist(vec![
                Party::Remote(X1),
                Party::Local(keypair.clone()),
                Party::Remote(X2),
            ]);
            let mut session = musig
                .start_sign_session(
                    &keylist,
                    vec![secnonce.clone()],
                    remote_nonces.clone(),
                    Message::<Public>::raw(&msg),
                )
                .unwrap();

            let scalar = musig.sign_all(&keylist, &mut session)[0];
            let expected = Scalar::from_bytes([
                0x2D, 0xF6, 0x7B, 0xFF, 0xF1, 0x8E, 0x3D, 0xE7, 0x97, 0xE1, 0x3C, 0x64, 0x75, 0xC9,
                0x63, 0x04, 0x81, 0x38, 0xDA, 0xEC, 0x5C, 0xB2, 0x0A, 0x35, 0x7C, 0xEC, 0xA7, 0xC8,
                0x42, 0x42, 0x95, 0xEA,
            ])
            .unwrap();
            assert_eq!(scalar, expected)
        }

        {
            let keylist = musig.new_keylist(vec![
                Party::Remote(X1),
                Party::Remote(X2),
                Party::Local(keypair.clone()),
            ]);
            let mut session = musig
                .start_sign_session(
                    &keylist,
                    vec![secnonce.clone()],
                    remote_nonces.clone(),
                    Message::<Public>::raw(&msg),
                )
                .unwrap();

            let scalar = musig.sign_all(&keylist, &mut session)[0];
            let expected = Scalar::from_bytes([
                0x0D, 0x5B, 0x65, 0x1E, 0x6D, 0xE3, 0x4A, 0x29, 0xA1, 0x2D, 0xE7, 0xA8, 0xB4, 0x18,
                0x3B, 0x4A, 0xE6, 0xA7, 0xF7, 0xFB, 0xE1, 0x5C, 0xDC, 0xAF, 0xA4, 0xA3, 0xD1, 0xBC,
                0xAA, 0xBC, 0x75, 0x17,
            ])
            .unwrap();
            assert_eq!(scalar, expected)
        }

        {
            let tweak = Scalar::from_bytes([
                0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF, 0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A,
                0x72, 0x3D, 0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79, 0x80, 0x2B, 0x26, 0x3C,
                0xDF, 0xCD, 0x83, 0xBB,
            ])
            .unwrap();
            let keylist = musig
                .new_keylist(vec![
                    Party::Remote(X1),
                    Party::Remote(X2),
                    Party::Local(keypair.clone()),
                ])
                .tweak(tweak)
                .unwrap();
            let mut session = musig
                .start_sign_session(
                    &keylist,
                    vec![secnonce.clone()],
                    remote_nonces.clone(),
                    Message::<Public>::raw(&msg),
                )
                .unwrap();

            let scalar = musig.sign_all(&keylist, &mut session)[0];
            let expected = Scalar::from_bytes([
                0x5E, 0x24, 0xC7, 0x49, 0x6B, 0x56, 0x5D, 0xEB, 0xC3, 0xB9, 0x63, 0x9E, 0x6F, 0x13,
                0x04, 0xA2, 0x15, 0x97, 0xF9, 0x60, 0x3D, 0x3A, 0xB0, 0x5B, 0x49, 0x13, 0x64, 0x17,
                0x75, 0xE1, 0x37, 0x5B,
            ])
            .unwrap();

            assert!(musig.verify_partial_signature(&keylist, &mut session, 2, scalar));
            assert_eq!(scalar, expected)
        }

        {
            let sec_adaptor = Scalar::from_bytes([
                0xD5, 0x6A, 0xD1, 0x85, 0x00, 0xF2, 0xD7, 0x8A, 0xB9, 0x54, 0x80, 0x53, 0x76, 0xF3,
                0x9D, 0x1B, 0x6D, 0x62, 0x04, 0x95, 0x12, 0x39, 0x04, 0x6D, 0x99, 0x3A, 0x9C, 0x31,
                0xE0, 0xF4, 0x78, 0x71,
            ])
            .unwrap()
            .expect_nonzero("");
            let pub_adatpor = g!(sec_adaptor * G);

            let keylist = musig.new_keylist(vec![
                Party::Remote(X1),
                Party::Remote(X2),
                Party::Local(keypair),
            ]);

            let mut session = musig
                .start_encrypted_sign_session(
                    &keylist,
                    vec![secnonce.clone()],
                    remote_nonces.clone(),
                    Message::<Public>::raw(&msg),
                    &pub_adatpor,
                )
                .unwrap();

            let scalar = musig.sign_all(&keylist, &mut session)[0];
            let expected = Scalar::from_bytes([
                0xD7, 0x67, 0xD0, 0x7D, 0x9A, 0xB8, 0x19, 0x8C, 0x9F, 0x64, 0xE3, 0xFD, 0x9F, 0x7B,
                0x8B, 0xAA, 0xC6, 0x05, 0xF1, 0x8D, 0xFF, 0x18, 0x95, 0x24, 0x2D, 0x93, 0x95, 0xD9,
                0xC8, 0xE6, 0xDD, 0x7C,
            ])
            .unwrap();
            assert_eq!(scalar, expected)
        }
    }

    #[test]
    fn test_key_aggregation() {
        let musig = MuSig::<Sha256>::keyagg_only();

        // test taken from
        // https://github.com/ElementsProject/secp256k1-zkp/blob/5d2df0541960554be5c0ba58d86e5fa479935000/src/modules/musig/tests_impl.h
        let x1 = XOnly::from_bytes([
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
            0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
            0xBC, 0xE0, 0x36, 0xF9,
        ])
        .unwrap();
        let x2 = XOnly::from_bytes([
            0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
            0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
            0x50, 0x2B, 0xA6, 0x59,
        ])
        .unwrap();
        let x3 = XOnly::from_bytes([
            0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18, 0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80,
            0xA8, 0xE3, 0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7, 0xAD, 0x33, 0x83, 0x68,
            0xD0, 0x38, 0xCA, 0x66,
        ])
        .unwrap();

        let x1_x2_x3 = vec![x1, x2, x3];
        let expected_x1_x2_x3 = XOnly::from_bytes([
            0xE5, 0x83, 0x01, 0x40, 0x51, 0x21, 0x95, 0xD7, 0x4C, 0x83, 0x07, 0xE3, 0x96, 0x37,
            0xCB, 0xE5, 0xFB, 0x73, 0x0E, 0xBE, 0xAB, 0x80, 0xEC, 0x51, 0x4C, 0xF8, 0x8A, 0x87,
            0x7C, 0xEE, 0xEE, 0x0B,
        ])
        .unwrap();
        assert_eq!(
            musig
                .new_keylist(x1_x2_x3.into_iter().map(Party::Remote).collect())
                .agg_public_key(),
            expected_x1_x2_x3
        );

        let x3_x2_x1 = vec![x3, x2, x1];
        let expected_x3_x2_x1 = XOnly::from_bytes([
            0xD7, 0x0C, 0xD6, 0x9A, 0x26, 0x47, 0xF7, 0x39, 0x09, 0x73, 0xDF, 0x48, 0xCB, 0xFA,
            0x2C, 0xCC, 0x40, 0x7B, 0x8B, 0x2D, 0x60, 0xB0, 0x8C, 0x5F, 0x16, 0x41, 0x18, 0x5C,
            0x79, 0x98, 0xA2, 0x90,
        ])
        .unwrap();
        assert_eq!(
            musig
                .new_keylist(x3_x2_x1.into_iter().map(Party::Remote).collect())
                .agg_public_key(),
            expected_x3_x2_x1
        );

        let x1_x1_x1 = vec![x1, x1, x1];
        let expected_x1_x1_x1 = XOnly::from_bytes([
            0x81, 0xA8, 0xB0, 0x93, 0x91, 0x2C, 0x9E, 0x48, 0x14, 0x08, 0xD0, 0x97, 0x76, 0xCE,
            0xFB, 0x48, 0xAE, 0xB8, 0xB6, 0x54, 0x81, 0xB6, 0xBA, 0xAF, 0xB3, 0xC5, 0x81, 0x01,
            0x06, 0x71, 0x7B, 0xEB,
        ])
        .unwrap();
        assert_eq!(
            musig
                .new_keylist(x1_x1_x1.into_iter().map(Party::Remote).collect())
                .agg_public_key(),
            expected_x1_x1_x1
        );

        let x1_x1_x2_x2 = vec![x1, x1, x2, x2];
        let expected_x1_x1_x2_x2 = XOnly::from_bytes([
            0x2E, 0xB1, 0x88, 0x51, 0x88, 0x7E, 0x7B, 0xDC, 0x5E, 0x83, 0x0E, 0x89, 0xB1, 0x9D,
            0xDB, 0xC2, 0x80, 0x78, 0xF1, 0xFA, 0x88, 0xAA, 0xD0, 0xAD, 0x01, 0xCA, 0x06, 0xFE,
            0x4F, 0x80, 0x21, 0x0B,
        ])
        .unwrap();
        assert_eq!(
            musig
                .new_keylist(x1_x1_x2_x2.into_iter().map(Party::Remote).collect())
                .agg_public_key(),
            expected_x1_x1_x2_x2
        );
    }
}
