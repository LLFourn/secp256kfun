//! The FROST threshold multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{
//!     binonce::NonceKeyPair,
//!     frost,
//!     Message,
//! };
//! use rand_chacha::ChaCha20Rng;
//! use sha2::Sha256;
//! // use sha256 to produce deterministic nonces -- be careful!
//! let proto = frost::new_with_deterministic_nonces::<Sha256>();
//! // Use randomness from ThreadRng to create synthetic nonces -- harder to make a mistake.
//! let proto = frost::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>();
//! // We need an RNG for key generation -- don't use ThreadRng in practice see note below.
//! let mut rng = rand::thread_rng();
//! // we're doing a 2 out of 3
//! let threshold = 2;
//! // Generate our secret scalar polynomial we'll use in the key generation protocol
//! let my_secret_poly = frost::generate_scalar_poly(threshold, &mut rng);
//! let my_public_poly = frost::to_point_poly(&my_secret_poly);
//! # let secret_poly2 = frost::generate_scalar_poly(threshold, &mut rng);
//! # let secret_poly3 = frost::generate_scalar_poly(threshold, &mut rng);
//! # let public_poly2 = frost::to_point_poly(&secret_poly2);
//! # let public_poly3 = frost::to_point_poly(&secret_poly3);
//! // share our public point poly, and receive the point polys from other participants
//! let public_polys = vec![my_public_poly, public_poly2, public_poly3];
//! let keygen = proto.new_keygen(public_polys).expect("something wrong with what was provided by other parties");
//! // Generate secret shares for others and proof-of-possession to protect against rogue key attacks.
//! let (my_shares, my_pop) = proto.create_shares(&keygen, my_secret_poly);
//! # let (shares2, pop2) = proto.create_shares(&keygen, secret_poly2);
//! # let (shares3, pop3) = proto.create_shares(&keygen, secret_poly3);
//! // for i = 0..3, Send the secret share at index i and all proofs-of-possession to the participant with index i,
//! // and receive our shares and pops from each participant as well.
//! let received_shares = vec![my_shares[0].clone(), shares2[0].clone(), shares3[0].clone()];
//! # let received_shares3 = vec![my_shares[2].clone(), shares2[2].clone(), shares3[2].clone()];
//! let proofs_of_possession = vec![my_pop, pop2, pop3];
//! // finish keygen by verifying the shares we received, verifying all proofs-of-possession,
//! // and calculate our long-lived secret share of the joint FROST key.
//! let (my_secret_share, frost_key) = proto
//!     .finish_keygen(
//!         keygen.clone(),
//!         0,
//!         received_shares,
//!         proofs_of_possession.clone(),
//!     )
//!     .unwrap();
//! # let (secret_share3, _frost_key3) = proto
//! #    .finish_keygen(
//! #        keygen.clone(),
//! #        2,
//! #        received_shares3,
//! #        proofs_of_possession.clone(),
//! #    )
//! #    .unwrap();
//! // We're ready to do some signing, so convert to xonly key
//! let frost_key = frost_key.into_xonly_key();
//! let message =  Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! // Generate nonces for this signing session.
//! let session_id = b"signing-cool-message-attempt-1".as_slice(); // ⚠ must be different for every session
//! let mut nonce_rng: ChaCha20Rng = proto.gen_nonce_rng(&frost_key, &my_secret_share, session_id, Some(message));
//! let my_nonce = proto.gen_nonce(&mut nonce_rng);
//! # let nonce3 = NonceKeyPair::random(&mut rand::thread_rng());
//! // share your public nonce with the other signing participant(s)
//! # let received_nonce3 = nonce3.public();
//! // receive public nonces from other signers
//! let nonces = vec![(0, my_nonce.public()), (2, received_nonce3)];
//! # let nonces3 = vec![(0, my_nonce.public()), (2, received_nonce3)];
//! // start a sign session with these nonces for a message
//! let session = proto.start_sign_session(&frost_key, nonces, message);
//! # let session3 = proto.start_sign_session(&frost_key, nonces3, message);
//! // create a partial signature using our secret share and secret nonce
//! let my_sig = proto.sign(&frost_key, &session, 0, &my_secret_share, my_nonce);
//! # let sig3 = proto.sign(&frost_key, &session3, 2, &secret_share3, nonce3);
//! // receive the partial signature(s) from the other participant(s) and verify
//! assert!(proto.verify_signature_share(&frost_key, &session, 2, sig3));
//! // combine signature shares into a single signature that is valid under the FROST key
//! let combined_sig = proto.combine_signature_shares(&frost_key, &session, vec![my_sig, sig3]);
//! assert!(proto.schnorr.verify(
//!     &frost_key.public_key(),
//!     message,
//!     &combined_sig
//! ));
//! ```
//!
//! # FROST
//!
//! In FROST, multiple parties cooperatively generate a single joint public key ([`FrostKey`]) for
//! creating Schnorr signatures. Unlike in [`musig`], only some threshold `t` of the `n` signers are
//! required to generate a signature under the key (rather than all `n`).
//!
//! This implementation is **not** yet compatible with other existing FROST
//! implementations (notably [secp256k1-zkp]).
//!
//! The original scheme was introduced in *[FROST: Flexible Round-Optimized Schnorr Threshold
//! Signatures][FROST]*. A more satisfying security proof was provided in *[Security of Multi- and Threshold
//! Signatures]*.
//!
//! > ⚠ At this stage this implementation is for API exploration purposes only. The way it is
//! currently implemented is not proven secure.
//!
//! [FROST]: <https://eprint.iacr.org/2020/852.pdf>
//! [secp256k1-zkp]: <https://github.com/ElementsProject/secp256k1-zkp/pull/138>
//! [Security of Multi- and Threshold Signatures]: <https://eprint.iacr.org/2021/1375.pdf>
//! [`musig`]: crate::musig

//! ##  Polynomial Generation
//!
//! The FROST key generation protocol takes as input a *secret* polynomial of degree `threshold - 1`.
//! We represent a polynomial as a `Vec<Scalar>` where each `Scalar` represents a coefficient in the polynomal.
//!
//! The security of the protocol is only guaranteed if you sample your secret polynomial uniformly
//! at random from the perspective of the other parties. You might also want to be able to
//! deterministically re-generate the polynomial from some secret data so that you may restore the
//! polynomial later from the secret. We don't have tools to use the restored polynomial in this
//! library yet but plan to in the future.
//!
//! This implementation doesn't provide a default policy with regards to polynomial generation. Here
//! we give an example of how to generate a deterministic RNG for the forst key generation session
//! that should make sense in most applications:
//!
//! ```
//! use schnorr_fun::{frost, fun::{ Scalar, nonce, Tag, derive_nonce_rng }};
//! use sha2::Sha256;
//! use rand_chacha::ChaCha20Rng;
//!
//! let static_secret_key = /* from local storage */
//! # Scalar::random(&mut rand::thread_rng());
//! let mut poly_rng = derive_nonce_rng! {
//!     // use Deterministic nonce gen so we reproduce it later
//!     nonce_gen => nonce::Deterministic::<Sha256>::default().tag(b"my-app-name/frost/keygen"),
//!     secret => static_secret_key,
//!     // session id must be unique for each key generation session
//!     public => ["forst_key_session_1053"],
//!     seedable_rng => ChaCha20Rng
//! };
//!
//! let threshold = 2;
//! // we can always reproduce my_secret_poly knowing `static_secret_key`,
//! // the threshold and the session id
//! let my_secret_poly: Vec<Scalar> = frost::generate_scalar_poly(threshold, &mut poly_rng);
//! ```
//!
//! Note that if a key generation sesssion fails you must always start a fresh session with a different session id.
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{Message, Schnorr, Signature};
use alloc::{collections::BTreeMap, vec::Vec};
use secp256kfun::{
    derive_nonce_rng,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tag},
    marker::*,
    nonce::{self, NonceGen},
    rand_core::{RngCore, SeedableRng},
    s, Point, Scalar, G,
};

/// The FROST context.
///
/// Type parametres:
///
/// - `H`: hash type for challenges, keygen_id, and binding coefficient.
/// - `NG`: nonce generator for proofs-of-possessions and FROST nonces
#[derive(Clone)]
pub struct Frost<H, NG> {
    /// The instance of the Schnorr signature scheme.
    pub schnorr: Schnorr<H, NG>,
    /// The hash used to generate the nonce binding coefficient when signing.
    binding_hash: H,
    /// The hash used to generate the `keygen_id`
    keygen_id_hash: H,
}

impl<H, NG> Default for Frost<H, NG>
where
    H: Default + Tag + Digest<OutputSize = U32>,
    NG: Default + Tag,
{
    fn default() -> Self {
        Frost::new(Schnorr::default())
    }
}

impl<H, NG> Frost<H, NG>
where
    H: Tag + Default,
{
    /// Generate a new Frost context from a Schnorr context.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{frost::Frost, nonce::Deterministic, Schnorr};
    /// use sha2::Sha256;
    /// let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
    /// let frost = Frost::new(schnorr);
    /// ```
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            schnorr,
            binding_hash: H::default().tag(b"frost/binding"),
            keygen_id_hash: H::default().tag(b"frost/keygenid"),
        }
    }
}

/// A KeyGen (distributed key generation) session
///
/// Created using [`Frost::new_keygen`]
///
/// [`Frost::new_keygen`]
#[derive(Clone, Debug)]
pub struct KeyGen {
    frost_key: FrostKey<Normal>,
    point_polys: Vec<Vec<Point>>,
    keygen_id: [u8; 32],
}

impl KeyGen {
    /// Return the number of parties in the KeyGen
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

/// First round keygen errors
#[derive(Debug, Clone)]
pub enum NewKeyGenError {
    /// Received polynomial is of differing length.
    PolyDifferentLength(usize),
    /// Number of parties is less than the length of polynomials specifying the threshold.
    NotEnoughParties,
    /// Frost key is zero. Computationally unreachable *if* all parties are honest.
    ZeroFrostKey,
}

impl core::fmt::Display for NewKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use NewKeyGenError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroFrostKey => write!(f, "The frost public key was zero. Computationally unreachable, one party is acting maliciously."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewKeyGenError {}

/// Second round KeyGen errors
#[derive(Debug, Clone)]
pub enum FinishKeyGenError {
    /// Secret share does not match the expected. Incorrect ordering?
    InvalidShare(usize),
    /// proof-of-possession does not match the expected. Incorrect ordering?
    InvalidProofOfPossession(usize),
}

impl core::fmt::Display for FinishKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use FinishKeyGenError::*;
        match self {
            InvalidShare(i) => write!(
                f,
                "the secret share at index {} does not match the expected evaluation \
                of their point polynomial at our index. Check that the order and our index is correct",
                i
            ),
            &InvalidProofOfPossession(i) => write!(
                f,
                "the proof-of-possession provided by party at index {} was invalid, check ordering.",
                i
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinishKeyGenError {}

/// A joint FROST key
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct FrostKey<T: PointType> {
    /// The joint public key of the frost multisignature.
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            deserialize = "Point<T>: crate::serde::de::Deserialize<'de>",
            serialize = "Point<T>: crate::serde::Serialize"
        ))
    )]
    public_key: Point<T>,
    /// Everyone else's point polynomial evaluated at your index, used in partial signature validation.
    verification_shares: Vec<Point<Normal, Public, Zero>>,
    /// Number of partial signatures required to create a combined signature under this key.
    threshold: usize,
    /// The tweak applied to this frost key, tracks the aggregate tweak.
    tweak: Scalar<Public, Zero>,
    /// Whether the secret keys need to be negated during signing (only used for EvenY keys).
    needs_negation: bool,
}

impl<T: Copy + PointType> FrostKey<T> {
    /// The joint public key
    pub fn public_key(&self) -> Point<T> {
        self.public_key
    }

    /// The verification shares of each party in the key.
    ///
    /// The verification share is the image of their secret share.
    pub fn verification_shares(&self) -> impl Iterator<Item = Point<Normal, Public, Zero>> + '_ {
        self.verification_shares.iter().map(|point| *point)
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The total number of signers in this frost multisignature.
    pub fn n_signers(&self) -> usize {
        self.verification_shares.len()
    }
}

impl FrostKey<Normal> {
    /// Convert the key into a BIP340 FrostKey.
    ///
    /// This is the [BIP340] compatible version of the key which you can put in a segwitv1 output.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn into_xonly_key(self) -> FrostKey<EvenY> {
        let (public_key, needs_negation) = self.public_key.into_point_with_even_y();
        let mut tweak = self.tweak;
        tweak.conditional_negate(needs_negation);
        FrostKey {
            public_key,
            verification_shares: self.verification_shares,
            threshold: self.threshold,
            tweak,
            needs_negation,
        }
    }

    /// Apply a plain tweak to the frost public key.
    ///
    /// This is useful for deriving unhardened child frost keys from a master frost public key using [BIP32].
    ///
    /// Tweak the frost public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G`. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    ///
    /// [BIP32]: https://bips.xyz/32
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let public_key = g!(self.public_key + tweak * G).normalize().non_zero()?;
        let tweak = s!(self.tweak + tweak).public();

        Some(FrostKey {
            public_key,
            verification_shares: self.verification_shares.clone(),
            threshold: self.threshold.clone(),
            tweak,
            needs_negation: self.needs_negation,
        })
    }
}

impl FrostKey<EvenY> {
    /// Applies an "XOnly" tweak to the FROST public key.
    /// This is how you embed a taproot commitment into a frost public key
    ///
    /// Tweak the frost public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G` as an [`EvenY`] point. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn tweak(self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let (new_public_key, needs_negation) = g!(self.public_key + tweak * G)
            .normalize()
            .non_zero()?
            .into_point_with_even_y();
        let mut new_tweak = s!(self.tweak + tweak).public();
        new_tweak.conditional_negate(needs_negation);
        let needs_negation = self.needs_negation ^ needs_negation;

        Some(Self {
            public_key: new_public_key,
            needs_negation,
            tweak: new_tweak,
            verification_shares: self.verification_shares,
            threshold: self.threshold,
        })
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> Frost<H, NG> {
    /// Create our secret shares and proof-of-possession to be shared with other participants.
    ///
    /// Each secret share needs to be securely communicated to the intended participant.
    /// The proof-of-possession should be sent to all participants.
    ///
    /// ## Return value
    ///
    /// Returns a vector of secret shares where the index represents the signer index and a
    /// proof-of-possession as a `Signature`.
    pub fn create_shares(
        &self,
        keygen: &KeyGen,
        scalar_poly: Vec<Scalar>,
    ) -> (Vec<Scalar<Secret, Zero>>, Signature) {
        let key_pair = self.schnorr.new_keypair(scalar_poly[0].clone());
        let pop = self
            .schnorr
            .sign(&key_pair, Message::<Public>::raw(&keygen.keygen_id));

        let shares = (1..=keygen.point_polys.len())
            .map(|i| scalar_poly_eval(&scalar_poly, (i as u32).into()))
            .collect();

        (shares, pop)
    }

    /// Generate nonces for creating signatures shares.
    ///
    /// ⚠ You must use a CAREFULLY CHOSEN nonce rng, see [`Frost::gen_nonce_rng`]
    pub fn gen_nonce<R: RngCore>(&self, nonce_rng: &mut R) -> NonceKeyPair {
        NonceKeyPair::random(nonce_rng)
    }

    /// Generate a reusable nonce rng.
    ///
    /// This method should be used carefully.
    ///
    /// When choosing a `secret` to use, if you are generating nonces prior to [`KeyGen`] completion,
    /// use the static first coefficient of your polynomial.
    /// Otherwise you can use your secret share of the frost key.
    ///
    /// The application should decide upon a unique `session_id`. If the `NonceGen` of this FROST
    /// instance is `Deterministic` then the `session_id` **must** be unique per signing session.
    pub fn gen_nonce_rng<T: PointType, R: SeedableRng<Seed = [u8; 32]>>(
        &self,
        frost_key: &FrostKey<T>,
        secret: &Scalar,
        session_id: &[u8],
        // public_key: Option<Point<impl Normalized>>,
        message: Option<Message<'_>>,
    ) -> R {
        let message = message.unwrap_or(Message::raw(b""));
        let msg_len = (message.len() as u64).to_be_bytes();
        let sid_len = (session_id.len() as u64).to_be_bytes();

        // let mut ver_share_bytes = b"";
        // for ver_share in frost_key.verification_shares {
        //     ver_share_bytes = [ver_share_bytes, ver_share.to_bytes()].concat();
        // }
        let ver_shares_bytes: Vec<_> = frost_key
            .verification_shares
            .iter()
            .map(|ver_share| ver_share.to_bytes())
            .collect();
        let threshold_bytes = [frost_key.threshold() as u8];
        let pk_bytes = &ver_shares_bytes[..];
        let rng: R = derive_nonce_rng!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => &secret,
            public => [pk_bytes, threshold_bytes, msg_len, message, sid_len, session_id],
            seedable_rng => R
        );
        rng
    }

    /// Run the key generation protocol while simulating the parties internally.
    ///
    /// This can be used to do generate a "trusted setup" FROST key. It returns the joint `FrostKey`
    /// along with the secret keys for each party.
    pub fn simulate_keygen(
        &self,
        threshold: usize,
        n_parties: usize,
        rng: &mut impl RngCore,
    ) -> (FrostKey<Normal>, Vec<Scalar>) {
        let scalar_polys = (0..n_parties)
            .map(|_| generate_scalar_poly(threshold, rng))
            .collect::<Vec<_>>();
        let point_polys = scalar_polys
            .iter()
            .map(|sp| to_point_poly(sp))
            .collect::<Vec<_>>();
        let keygen = self.new_keygen(point_polys).unwrap();
        let (shares, proofs_of_possesion): (Vec<_>, Vec<_>) = scalar_polys
            .into_iter()
            .map(|sp| self.create_shares(&keygen, sp))
            .unzip();
        // collect the received shares for each party
        let received_shares = (0..n_parties)
            .map(|party_index| {
                (0..n_parties)
                    .map(|share_index| shares[share_index][party_index].clone())
                    .collect()
            })
            .collect::<Vec<Vec<_>>>();

        // finish keygen for each party
        let (secret_shares, mut frost_keys): (Vec<_>, Vec<_>) = (0..n_parties)
            .map(|party_index| {
                let (secret_share, frost_key) = self
                    .finish_keygen(
                        keygen.clone(),
                        party_index,
                        received_shares[party_index].clone(),
                        proofs_of_possesion.clone(),
                    )
                    .unwrap();

                (secret_share, frost_key)
            })
            .unzip();

        (frost_keys.remove(0), secret_shares)
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG> Frost<H, NG> {
    /// Verify a proof-of-possession of a point
    ///
    /// ## Return value
    ///
    /// Returns `bool` true if the proof-of-possession matches the point
    fn verify_pop(&self, keygen: &KeyGen, point: Point, pop: Signature) -> bool {
        let (even_poly_point, _) = point.into_point_with_even_y();

        self.schnorr.verify(
            &even_poly_point,
            Message::<Public>::raw(&keygen.keygen_id),
            &pop,
        )
    }

    /// Collect all the public polynomials into a [`KeyGen`] session with a [`FrostKey`].
    ///
    /// Takes a vector of point polynomials to use for this [`FrostKey`].
    /// Also prepares a vector of verification shares for later.
    ///
    /// ## Return value
    ///
    /// Returns a [`KeyGen`] containing a [`FrostKey`]
    pub fn new_keygen(&self, point_polys: Vec<Vec<Point>>) -> Result<KeyGen, NewKeyGenError> {
        let len_first_poly = point_polys[0].len();
        {
            if let Some((i, _)) = point_polys
                .iter()
                .enumerate()
                .find(|(_, point_poly)| point_poly.len() != len_first_poly)
            {
                return Err(NewKeyGenError::PolyDifferentLength(i));
            }

            // Number of parties is less than the length of polynomials specifying the threshold
            if point_polys.len() < len_first_poly {
                return Err(NewKeyGenError::NotEnoughParties);
            }
        }

        let mut joint_poly = (0..len_first_poly)
            .map(|_| Point::<NonNormal, Public, _>::zero())
            .collect::<Vec<_>>();

        for poly in &point_polys {
            for i in 0..len_first_poly {
                joint_poly[i] += poly[i];
            }
        }

        let public_key = joint_poly[0]
            .normalize()
            .non_zero()
            .ok_or(NewKeyGenError::ZeroFrostKey)?;

        let mut keygen_hash = self.keygen_id_hash.clone();
        keygen_hash.update((len_first_poly as u32).to_be_bytes());
        keygen_hash.update((point_polys.len() as u32).to_be_bytes());
        for poly in &point_polys {
            for point in poly {
                keygen_hash.update(point.to_bytes());
            }
        }
        let keygen_id = keygen_hash.finalize().into();

        let verification_shares = (1..=point_polys.len())
            .map(|i| point_poly_eval(&joint_poly, (i as u32).into()).normalize())
            .collect();

        Ok(KeyGen {
            point_polys,
            keygen_id,
            frost_key: FrostKey {
                verification_shares,
                public_key,
                threshold: joint_poly.len(),
                tweak: Scalar::zero(),
                needs_negation: false,
            },
        })
    }

    /// Combine all receieved shares into your long-lived secret share.
    ///
    /// The `secret_shares` includes your own share as well as shares from each of the other
    /// parties. The `secret_shares` are validated to match the expected result by evaluating their
    /// polynomial at our participant index. Each participant's proof-of-possession is verified
    /// against what they provided in the first round of key generation.
    ///
    /// # Return value
    ///
    /// Your secret share and the [`FrostKey`]
    pub fn finish_keygen(
        &self,
        keygen: KeyGen,
        my_index: usize,
        secret_shares: Vec<Scalar<Secret, Zero>>,
        proofs_of_possession: Vec<Signature>,
    ) -> Result<(Scalar, FrostKey<Normal>), FinishKeyGenError> {
        assert_eq!(
            secret_shares.len(),
            keygen.frost_key.verification_shares.len()
        );
        assert_eq!(secret_shares.len(), proofs_of_possession.len());

        for (i, (poly, pop)) in keygen
            .point_polys
            .iter()
            .zip(proofs_of_possession)
            .enumerate()
        {
            if !self.verify_pop(&keygen, poly[0], pop) {
                return Err(FinishKeyGenError::InvalidProofOfPossession(i));
            }
        }

        let mut total_secret_share = s!(0);
        for (i, (secret_share, poly)) in secret_shares.iter().zip(&keygen.point_polys).enumerate() {
            let expected_public_share =
                point_poly_eval(poly, Scalar::<Public, Zero>::from((my_index + 1) as u32));
            if g!(secret_share * G) != expected_public_share {
                return Err(FinishKeyGenError::InvalidShare(i));
            }
            total_secret_share += secret_share;
        }

        let total_secret_share = total_secret_share.non_zero().expect(
            "since verification shares are non-zero, the total secret share cannot be zero",
        );

        Ok((total_secret_share, keygen.frost_key))
    }

    /// Start a FROST signing session.
    ///
    /// Each signing party must call this with the same arguments for it to succeeed. This means you
    /// must all agree on each other's nonces before starting the sign session. In `nonces` each
    /// item is the signer's index and their `Nonce`. It's length must be at least `threshold`.
    /// Generating your own nonces can be done with [`Frost::gen_nonce`].
    ///
    /// # Panics
    ///
    /// If the number of nonces is less than the threshold.
    pub fn start_sign_session(
        &self,
        frost_key: &FrostKey<EvenY>,
        nonces: Vec<(usize, Nonce)>,
        message: Message,
    ) -> SignSession {
        let mut nonce_map: BTreeMap<_, _> =
            nonces.into_iter().map(|(i, nonce)| (i, nonce)).collect();

        if nonce_map.len() < frost_key.threshold() {
            panic!("nonces' length was less than the threshold");
        }

        let agg_nonce = nonce_map
            .iter()
            .fold([Point::zero(); 2], |acc, (_, nonce)| {
                [
                    g!({ acc[0] } + { nonce.0[0] }),
                    g!({ acc[1] } + { nonce.0[1] }),
                ]
            });

        let agg_nonce = [agg_nonce[0].normalize(), agg_nonce[1].normalize()];

        let binding_coeff = Scalar::from_hash(
            self.binding_hash
                .clone()
                .add(agg_nonce[0])
                .add(agg_nonce[1])
                .add(frost_key.public_key())
                .add(message),
        );
        let (agg_nonce, nonces_need_negation) =
            g!({ agg_nonce[0] } + binding_coeff * { agg_nonce[1] })
                .normalize()
                .non_zero()
                .unwrap_or_else(|| {
                    // Use the same trick as the MuSig spec
                    G.clone().normalize()
                })
                .into_point_with_even_y();

        for (_, nonce) in &mut nonce_map {
            nonce.conditional_negate(nonces_need_negation);
        }

        let challenge = self
            .schnorr
            .challenge(&agg_nonce, &frost_key.public_key(), message);

        SignSession {
            binding_coeff,
            nonces_need_negation,
            agg_nonce,
            challenge,
            nonces: nonce_map,
        }
    }

    /// Generates a partial signature share under the frost key using a secret share.
    ///
    /// ## Return value
    ///
    /// Returns a signature share
    pub fn sign(
        &self,
        frost_key: &FrostKey<EvenY>,
        session: &SignSession,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonce: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        let mut lambda = lagrange_lambda(
            my_index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != my_index)
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let [mut r1, mut r2] = secret_nonce.secret;
        r1.conditional_negate(session.nonces_need_negation);
        r2.conditional_negate(session.nonces_need_negation);

        let b = &session.binding_coeff;
        let x = secret_share;
        let c = &session.challenge;
        s!(r1 + (r2 * b) + lambda * x * c).public()
    }

    /// Verify a partial signature for a participant at `index` (from zero).
    ///
    /// ## Return Value
    ///
    /// Returns `bool`, true if partial signature is valid.
    ///
    /// ## Panics
    ///
    /// If the `index` is is greater than the number of signers in the threshold.
    pub fn verify_signature_share(
        &self,
        frost_key: &FrostKey<EvenY>,
        session: &SignSession,
        index: usize,
        signature_share: Scalar<Public, Zero>,
    ) -> bool {
        let s = signature_share;
        let mut lambda = lagrange_lambda(
            index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != index)
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let c = &session.challenge;
        let b = &session.binding_coeff;
        let X = frost_key.verification_shares().nth(index).unwrap();
        let [ref R1, ref R2] = session
            .nonces
            .get(&index)
            .expect("verifying party index that is not part of frost signing coalition")
            .0;
        g!(R1 + b * R2 + (c * lambda) * X - s * G).is_zero()
    }

    /// Combine a vector of signatures shares into an aggregate signature.
    ///
    /// This method does not check the validity of the `signature_shares` but if you have verified
    /// each signautre share individually the output will be a valid siganture under the `frost_key`
    /// and message provided when starting the session.
    ///
    /// ## Return value
    ///
    /// Returns a combined schnorr [`Signature`] on the message
    pub fn combine_signature_shares(
        &self,
        frost_key: &FrostKey<EvenY>,
        session: &SignSession,
        signature_shares: Vec<Scalar<Public, Zero>>,
    ) -> Signature {
        let ck = s!(session.challenge * frost_key.tweak);
        let sum_s = signature_shares
            .into_iter()
            .reduce(|acc, partial_sig| s!(acc + partial_sig).public())
            .unwrap_or(Scalar::zero());
        Signature {
            R: session.agg_nonce,
            s: s!(sum_s + ck).public(),
        }
    }
}

/// A FROST signing session
///
/// Created using [`Frost::start_sign_session`].
///
/// [`Frost::start_sign_session`]
#[derive(Clone, Debug, PartialEq)]
pub struct SignSession {
    binding_coeff: Scalar,
    nonces_need_negation: bool,
    agg_nonce: Point<EvenY>,
    challenge: Scalar<Public, Zero>,
    nonces: BTreeMap<usize, Nonce>,
}

impl SignSession {
    /// Fetch the participant indices for this signing session.
    ///
    /// ## Return value
    ///
    /// An iterator of participant indices
    pub fn participants(&self) -> impl DoubleEndedIterator<Item = usize> + '_ {
        self.nonces.iter().map(|(i, _)| *i)
    }
}

/// Calculate the lagrange coefficient for participant with index x_j and other signers indexes x_ms
fn lagrange_lambda(x_j: u32, x_ms: &[u32]) -> Scalar {
    let x_j = Scalar::from(x_j)
        .non_zero()
        .expect("target xcoord can not be zero");
    x_ms.iter()
        .map(|x_m| {
            Scalar::from(*x_m)
                .non_zero()
                .expect("index can not be zero")
        })
        .fold(Scalar::one(), |acc, x_m| {
            let denominator = s!(x_m - x_j)
                .non_zero()
                .expect("removed duplicate indexes")
                .invert();
            s!(acc * x_m * denominator)
        })
}

/// Constructor for a Frost instance using deterministic nonce generation.
///
/// If you use deterministic nonce generation you will have to provide a unique session id to every signing session.
/// The advantage is that you will be able to regenerate the same nonces at a later point from [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_deterministic_nonces<H>() -> Frost<H, nonce::Deterministic<H>>
where
    H: Tag + Digest<OutputSize = U32> + Default,
{
    Frost::default()
}

/// Constructor for a Frost instance using synthetic nonce generation.
///
/// Synthetic nonce generation mixes in external randomness into nonce generation which means you
/// don't need a unique session id for each signing session to guarantee security. The disadvantage
/// is that you may have to store and recall somehow the nonces generated from
/// [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_synthetic_nonces<H, R>() -> Frost<H, nonce::Synthetic<H, nonce::GlobalRng<R>>>
where
    H: Tag + Digest<OutputSize = U32> + Default,
    R: RngCore + Default,
{
    Frost::default()
}

/// Create a Frost instance which does not handle nonce generation.
///
/// You can still sign with this instance but you you will have to generate nonces in your own way.
pub fn new_without_nonce_generation<H>() -> Frost<H, nonce::NoNonces>
where
    H: Tag + Digest<OutputSize = U32> + Default,
{
    Frost::default()
}

/// Create a vector of points by multiplying each scalar by `G`.
///
/// # Example
///
/// ```
/// use schnorr_fun::{
///     frost,
///     fun::{g, s, Scalar, G},
/// };
/// let secret_poly = (0..5)
///     .map(|_| Scalar::random(&mut rand::thread_rng()))
///     .collect::<Vec<_>>();
/// let point_poly = frost::to_point_poly(&secret_poly);
/// ```
pub fn to_point_poly(scalar_poly: &[Scalar]) -> Vec<Point> {
    scalar_poly.iter().map(|a| g!(a * G).normalize()).collect()
}

/// Generate a `Scalar` polynomial for key generation
pub fn generate_scalar_poly(threshold: usize, rng: &mut impl RngCore) -> Vec<Scalar> {
    (0..threshold).map(|_| Scalar::random(rng)).collect()
}

fn scalar_poly_eval(poly: &[Scalar], x: Scalar<Public, impl ZeroChoice>) -> Scalar<Secret, Zero> {
    poly.iter()
        .fold((s!(0), s!(1).mark_zero()), |(eval, xpow), coeff| {
            (s!(eval + xpow * coeff), s!(xpow * x))
        })
        .0
}

fn point_poly_eval(
    poly: &[Point<impl PointType, Public, impl ZeroChoice>],
    x: Scalar<Public, impl ZeroChoice>,
) -> Point<NonNormal, Public, Zero> {
    let xpows = core::iter::successors(Some(s!(1).public().mark_zero()), |xpow| {
        Some(s!(xpow * x).public())
    })
    .take(poly.len())
    .collect::<Vec<_>>();
    secp256kfun::op::lincomb(&xpows, poly.iter())
}

#[cfg(test)]
mod test {

    use super::*;
    use sha2::Sha256;

    #[test]
    fn test_lagrange_lambda() {
        let res = s!((1 * 4 * 5) * {
            s!((1 - 2) * (4 - 2) * (5 - 2))
                .non_zero()
                .expect("")
                .invert()
        });
        assert_eq!(res, lagrange_lambda(2, &[1, 4, 5]));
    }

    #[test]
    fn zero_agg_nonce_results_in_G() {
        let frost = new_with_deterministic_nonces::<Sha256>();
        let (frost_key, _shares) = frost.simulate_keygen(2, 3, &mut rand::thread_rng());
        let nonce = NonceKeyPair::random(&mut rand::thread_rng()).public();
        let mut malicious_nonce = nonce.clone();
        malicious_nonce.conditional_negate(true);

        let session = frost.start_sign_session(
            &frost_key.into_xonly_key(),
            vec![(0, nonce), (1, malicious_nonce)],
            Message::<Public>::plain("test", b"hello"),
        );

        assert_eq!(session.agg_nonce, *G);
    }
}
