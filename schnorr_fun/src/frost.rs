//! ## FROST multisignature scheme
//!
//! The FROST (Flexible Round-Optimized Schnorr Threshold) multisignature scheme allows you aggregate
//! multiple public keys into a single public key. To sign a message under this public key, a threshold t-of-n secret keys
//! must use a common set of nonces to each produce a signature share. These signature shares are then combined
//! to form a signature that is valid under the aggregate key.
//!
//! This implementation has **not yet** been made compatible with other existing FROST implementations
//! (notably [secp256k1-zkp]).
//!
//! For reference see the [FROST paper], the MuSig implementation in this repository, and also [Security of Multi- and Threshold Signatures].
//!
//! [secp256k1-zkp]: <https://github.com/ElementsProject/secp256k1-zkp/pull/138>
//! [FROST paper]: <https://eprint.iacr.org/2020/852.pdf>
//! [Security of Multi- and Threshold Signatures]: <https://eprint.iacr.org/2021/1375.pdf>
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::{frost::{Frost, ScalarPoly}, Schnorr, Message, nonce::Deterministic, fun::marker::Public};
//! use sha2::Sha256;
//! // use SHA256 with deterministic nonce generation
//! let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
//!     Deterministic::<Sha256>::default(),
//! ));
//! // to create a FROST multisig with a threshold of two, each participant creates
//! // a random secret scalar polynomial with two coefficients.
//! let scalar_poly = ScalarPoly::random(2, &mut rand::thread_rng());
//! # let scalar_poly2 = ScalarPoly::random(2, &mut rand::thread_rng());
//! # let scalar_poly3 = ScalarPoly::random(2, &mut rand::thread_rng());
//! // share our public point poly, and recieve the point polys from other participants
//! # let point_poly2 = scalar_poly2.to_point_poly();
//! # let point_poly3 = scalar_poly3.to_point_poly();
//! let point_polys = vec![scalar_poly.to_point_poly(), point_poly2, point_poly3];
//! // create secret shares and proofs-of-possession using our secret scalar polynomial
//! let keygen = frost.new_keygen(point_polys).unwrap();
//! let (shares, pop) = frost.create_shares(&keygen, scalar_poly);
//! # let (shares2, pop2) = frost.create_shares(&keygen, scalar_poly2);
//! # let (shares3, pop3) = frost.create_shares(&keygen, scalar_poly3);
//! // send the shares at index i and all proofs-of-possession to each other participant i,
//! // and recieve our shares from each other participant as well as their proofs-of-possession.
//! let recieved_shares = vec![shares[0].clone(), shares2[0].clone(), shares3[0].clone()];
//! # let recieved_shares3 = vec![shares[2].clone(), shares2[2].clone(), shares3[2].clone()];
//! let proofs_of_possession = vec![pop, pop2, pop3];
//! // finish keygen by verifying the shares we recieved as well as proofs-of-possession
//! // and calulate our secret share of the joint FROST key
//! let (secret_share, frost_key) = frost
//!     .finish_keygen(
//!         keygen.clone(),
//!         0,
//!         recieved_shares,
//!         proofs_of_possession.clone(),
//!     )
//!     .unwrap();
//! # let (secret_share3, _frost_key3) = frost
//! #    .finish_keygen(
//! #        keygen.clone(),
//! #        2,
//! #        recieved_shares3,
//! #        proofs_of_possession.clone(),
//! #    )
//! #    .unwrap();
//! // for signing we must have a unique session ID to derive nonces such that nonces
//! // are never reused. For gen_nonce we use all information that is publicly available.
//! let verification_shares_bytes: Vec<_> = frost_key
//!     .verification_shares
//!     .iter()
//!     .map(|share| share.to_bytes())
//!     .collect();
//! // create a unique session ID for this signing session
//! let sid = [
//!     frost_key.joint_public_key.to_bytes().as_slice(),
//!     verification_shares_bytes.concat().as_slice(),
//!     b"frost-very-unique-id".as_slice(),
//!     b"0".as_slice(),
//! ]
//! .concat();
//! # let sid3 = [
//! #    frost_key.joint_public_key.to_bytes().as_slice(),
//! #    verification_shares_bytes.concat().as_slice(),
//! #    b"frost-very-unique-id".as_slice(),
//! #    b"2".as_slice(),
//! # ]
//! # .concat();
//! // generate nonces for this signing session
//! let nonce = frost.gen_nonce(&secret_share, &sid);
//! # let nonce3 = frost.gen_nonce(&secret_share3, &sid3);
//! // share your public nonce with the other signing participant(s)
//! # let recieved_nonce3 = nonce3.public();
//! // recieve public nonces from other participants with their index
//! let nonces = vec![(0, nonce.public()), (2, recieved_nonce3)];
//! # let nonces3 = vec![(0, nonce.public()), (2, recieved_nonce3)];
//! // start a sign session with these nonces for this message
//! let session = frost.start_sign_session(&frost_key, nonces, Message::plain("test", b"test"));
//! # let session3 = frost.start_sign_session(&frost_key, nonces3, Message::plain("test", b"test"));
//! // create a partial signature using our secret share and secret nonce
//! let sig = frost.sign(&frost_key, &session, 0, &secret_share, nonce);
//! # let sig3 = frost.sign(&frost_key, &session3, 2, &secret_share3, nonce3);
//! // recieve partial signature(s) from other participant(s) and verify
//! assert!(frost.verify_signature_share(&frost_key, &session, 2, sig3));
//! // combine signature shares into a single signature that is valid under the joint key
//! let combined_sig = frost.combine_signature_shares(&frost_key, &session, vec![sig, sig3]);
//! assert!(frost.schnorr.verify(
//!     &frost_key.joint_public_key,
//!     Message::<Public>::plain("test", b"test"),
//!     &combined_sig
//! ));
//! ```
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{Message, Schnorr, Signature, Vec};
use core::iter;
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{HashAdd, Tagged},
    marker::*,
    nonce::{AddTag, NonceGen},
    rand_core, s, Point, Scalar, G,
};
use std::collections::BTreeMap;

/// The FROST context.
/// H: hash for challenges and creating a keygen_id
/// NG: hash for nonce generation
#[derive(Clone)]
pub struct Frost<H, NG: AddTag> {
    /// The instance of the Schnorr signature scheme.
    pub schnorr: Schnorr<H, NG>,
    /// The hash used to generate the keygen_id.
    keygen_id_hash: H,
}

impl<H: Tagged, NG: AddTag + Clone> Frost<H, NG> {
    /// Generate a new Frost context from a Schnorr context.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            schnorr: schnorr.clone(),
            keygen_id_hash: H::default().tagged(b"frost/keygenid"),
        }
    }
}

/// A participant's secret polynomial with `t` random coefficients.
#[derive(Clone, Debug, PartialEq)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
    /// Evaluate the scalar polynomial at position x.
    pub fn eval(&self, x: u32) -> Scalar<Secret, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let mut xpow = s!(1).mark::<Public>();
        self.0
            .iter()
            .skip(1)
            .fold(self.0[0].clone().mark::<Zero>(), move |sum, coeff| {
                xpow = s!(xpow * x).mark::<Public>();
                s!(sum + xpow * coeff)
            })
    }

    /// Create a point polynomial through point multiplication of each coefficient.
    pub fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    /// Create a random scalar polynomial
    pub fn random(n_coefficients: u32, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }

    /// Create a scalar polynomial where the first coefficient is a specified secret and
    /// the remaining coefficients are random.
    ///
    /// This will be used for creating secret polynomials with known & reproducable secrets.
    pub fn random_using_secret(
        n_coefficients: u32,
        secret: Scalar,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let mut coeffs = vec![secret];
        for _ in 1..n_coefficients {
            coeffs.push(Scalar::random(rng))
        }
        ScalarPoly(coeffs)
    }

    /// The number of terms in the polynomial (t).
    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    /// The secret coefficient for the polynomial.
    pub fn first_coef(&self) -> &Scalar {
        &self.0[0]
    }

    /// Create a new scalar polynomial from a vector of scalars.
    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }
}

/// A participant's public commitment polynomial.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct PointPoly<Z = NonZero>(
    #[cfg_attr(
        feature = "serde",
        serde(bound(
            deserialize = "Point<Normal, Public, Z>: serde::Deserialize<'de>",
            serialize = "Point<Normal, Public, Z>: serde::Serialize"
        ))
    )]
    Vec<Point<Normal, Public, Z>>,
);

impl<Z> PointPoly<Z> {
    /// Evaluate the point polynomial at position x.
    pub fn eval(&self, x: u32) -> Point<Jacobian, Public, Zero> {
        let x = Scalar::from(x)
            .expect_nonzero("must be non-zero")
            .mark::<Public>();
        let xpows = iter::successors(Some(s!(1).mark::<Public>()), |xpow| {
            Some(s!(x * xpow).mark::<Public>())
        })
        .take(self.0.len())
        .collect::<Vec<_>>();
        crate::fun::op::lincomb(&xpows, &self.0)
    }

    /// Combine a vector of point polynomials into a joint polynomial.
    fn combine(mut polys: impl Iterator<Item = Self>) -> PointPoly<Zero> {
        // take the first point polynomial and collect its coefficients
        let mut combined_poly = polys
            .next()
            .expect("cannot combine empty list of polys")
            .0
            .into_iter()
            .map(|p| p.mark::<(Jacobian, Zero)>())
            .collect::<Vec<_>>();
        // add the coefficients of the remaining polys
        for poly in polys {
            for (combined_point, point) in combined_poly.iter_mut().zip(poly.0) {
                *combined_point = g!({ *combined_point } + point);
            }
        }
        PointPoly(combined_poly.into_iter().map(|p| p.normalize()).collect())
    }

    /// The number of terms in the polynomial (t)
    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    /// Fetch the point for the polynomial
    pub fn points(&self) -> &[Point<Normal, Public, Z>] {
        &self.0
    }
}

/// A KeyGen (distributed key generation) session
///
/// Created using [`Frost::new_keygen`]
///
/// [`Frost::new_keygen`]
#[derive(Clone, Debug)]
pub struct KeyGen {
    point_polys: Vec<PointPoly>,
    keygen_id: [u8; 32],
    frost_key: FrostKey,
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
    /// Frost key is zero. This should be impossible, likely has been maliciously chosen.
    ZeroFrostKey,
    /// Verification share is zero. This should be impossible, likely has been maliciously chosen.
    ZeroVerificationShare,
}

impl core::fmt::Display for NewKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use NewKeyGenError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroFrostKey => write!(f, "The joint FROST key was zero. This should be impossible, one party is acting maliciously."),
            ZeroVerificationShare => write!(f, "Zero verification share. This should be impossible, one party is acting maliciously."),
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
    /// Proof of possession does not match the expected. Incorrect ordering?
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
                "the proof of possession provided by party at index {} was invalid, check ordering.",
                i
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinishKeyGenError {}

/// A joint FROST key
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct FrostKey {
    /// The joint public key of the FROST multisignature.
    pub joint_public_key: Point<EvenY>,
    /// Everyone else's point polynomial evaluated at your index, used in partial signature validation.
    pub verification_shares: Vec<Point>,
    /// Number of partial signatures required to create a combined signature under this key.
    pub threshold: u32,
    /// Taproot tweak applied to this FROST key, tracks the aggregate tweak.
    tweak: Scalar<Public, Zero>,
    /// Whether the secrets need negation in order to sign for the X-Only key.
    needs_negation: bool,
}

impl FrostKey {
    /// The joint public key of the FROST multisignature
    ///
    /// ## Return value
    ///
    /// A point (normalised to have an even Y coordinate).
    pub fn public_key(&self) -> Point<EvenY> {
        self.joint_public_key
    }

    /// Tweak the joint FROST public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G`. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// This is how you embed a taproot commitment into a key.
    ///
    /// ## Return value
    ///
    /// Returns a new FrostKey with the same parties but a different aggregated public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn tweak(&mut self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        // Also updates whether the FROST key needs negation.
        // XOR of existing FROST key needs_negation and new tweaked key needs_negation.
        // If both need negation, they will cancel out.
        //
        // Public key
        //     X = (b*x) * G
        // where b = 1 or -1
        // For a tweak t: X' = X + t * G.
        // If X' needs negation then we need secret
        //     -(b*x + t) = -b*x - t
        // So new b = -b and t = -t.
        // If X' doesn't need negation, leave b as is.
        // i.e. previous needs_negation XOR new needs_negation.
        let new_tweak = s!(0 + tweak).mark::<Public>();
        let (joint_public_key, tweaked_needs_negation) = g!(self.joint_public_key + new_tweak * G)
            .mark::<NonZero>()?
            .into_point_with_even_y();

        let mut tweak = s!(self.tweak + tweak).mark::<Public>();
        tweak.conditional_negate(tweaked_needs_negation);

        let updated_needs_negation = self.needs_negation ^ tweaked_needs_negation;

        // Return the new FrostKey including the new tweak and updated needs_negation
        Some(FrostKey {
            joint_public_key,
            verification_shares: self.verification_shares.clone(),
            threshold: self.threshold.clone(),
            tweak,
            needs_negation: updated_needs_negation,
        })
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The total number of signers in this FROST multisignature.
    pub fn n_signers(&self) -> u32 {
        self.verification_shares.len() as u32
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag + NonceGen> Frost<H, NG> {
    /// Create secret shares and our proof-of-possession to be shared with other participants.
    ///
    /// Secret shares are created for every other participant by evaluating our secret polynomial
    /// at their participant index. f(i) for 1<=i<=n.
    ///
    /// Each secret share f(i) needs to be securely communicated to participant i. Additionally
    /// we share a proof of possession for the first coefficient in our secret scalar polynomial.
    ///
    /// ## Return value
    ///
    /// Returns a vector of secret shares and a proof of possession Signature
    /// The secret shares at index 0 is destined for participant 1.
    pub fn create_shares(
        &self,
        KeyGen: &KeyGen,
        scalar_poly: ScalarPoly,
    ) -> (Vec<Scalar<Secret, Zero>>, Signature) {
        let key_pair = self.schnorr.new_keypair(scalar_poly.0[0].clone());
        let pop = self.schnorr.sign(
            &key_pair,
            Message::<Public>::plain("frost-pop", &KeyGen.keygen_id),
        );

        let shares = (1..=KeyGen.point_polys.len())
            .map(|i| scalar_poly.eval(i as u32))
            .collect();

        (shares, pop)
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag> Frost<H, NG> {
    /// Verify a proof of possession against a participant's committed point polynomial
    ///
    /// ## Return value
    ///
    /// Returns `bool` true if the proof of possession matches the point polynomial
    fn verify_pop(&self, KeyGen: &KeyGen, point_poly: &PointPoly, pop: Signature) -> bool {
        let (even_poly_point, _) = point_poly.0[0].into_point_with_even_y();

        self.schnorr.verify(
            &even_poly_point,
            Message::<Public>::plain("frost-pop", &KeyGen.keygen_id),
            &pop,
        )
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag> Frost<H, NG> {
    /// Collect all the public polynomials into a KeyGen session with a FrostKey.
    ///
    /// Takes a vector of point polynomials to use for this FrostKey
    ///
    /// Also prepares a vector of verification shares for later.
    ///
    /// ## Return value
    ///
    /// Returns a KeyGen containing a FrostKey
    pub fn new_keygen(&self, point_polys: Vec<PointPoly>) -> Result<KeyGen, NewKeyGenError> {
        let len_first_poly = point_polys[0].poly_len();
        {
            if let Some((i, _)) = point_polys
                .iter()
                .enumerate()
                .find(|(_, point_poly)| point_poly.poly_len() != len_first_poly)
            {
                return Err(NewKeyGenError::PolyDifferentLength(i));
            }

            // Number of parties is less than the length of polynomials specifying the threshold
            if point_polys.len() < len_first_poly {
                return Err(NewKeyGenError::NotEnoughParties);
            }
        }

        let joint_poly = PointPoly::combine(point_polys.clone().into_iter());
        let frost_key = joint_poly.0[0];

        let (joint_public_key, needs_negation) = frost_key
            .mark::<NonZero>()
            .ok_or(NewKeyGenError::ZeroFrostKey)?
            .into_point_with_even_y();

        let mut keygen_hash = self.keygen_id_hash.clone();
        keygen_hash.update((len_first_poly as u32).to_be_bytes());
        keygen_hash.update((point_polys.len() as u32).to_be_bytes());
        for poly in &point_polys {
            for point in poly.0.iter() {
                keygen_hash.update(point.to_bytes());
            }
        }
        let keygen_id = keygen_hash.finalize().into();

        let verification_shares = (1..=point_polys.len())
            .map(|i| joint_poly.eval(i as u32).normalize().mark::<NonZero>())
            .collect::<Option<Vec<Point>>>()
            .ok_or(NewKeyGenError::ZeroVerificationShare)?;

        Ok(KeyGen {
            point_polys,
            keygen_id,
            frost_key: FrostKey {
                verification_shares,
                joint_public_key,
                threshold: joint_poly.poly_len() as u32,
                tweak: Scalar::zero().mark::<Public>(),
                needs_negation,
            },
        })
    }

    /// Collect the vector of all recieved secret shares into your total long-lived secret share.
    /// The secret_shares includes your own as well as share from each of the other participants.
    ///
    /// The secret_shares are validated to match the expected result
    /// by evaluating their polynomial at our participant index.
    ///
    /// Each participant's proof of possession is verified against their polynomial.
    ///
    /// # Return value
    ///
    /// Your total secret share Scalar and the FrostKey
    pub fn finish_keygen(
        &self,
        KeyGen: KeyGen,
        my_index: u32,
        secret_shares: Vec<Scalar<Secret, Zero>>,
        proofs_of_possession: Vec<Signature>,
    ) -> Result<(Scalar, FrostKey), FinishKeyGenError> {
        assert_eq!(
            secret_shares.len(),
            KeyGen.frost_key.verification_shares.len()
        );
        assert_eq!(secret_shares.len(), proofs_of_possession.len());

        for (i, (poly, pop)) in KeyGen
            .point_polys
            .iter()
            .zip(proofs_of_possession)
            .enumerate()
        {
            if !self.verify_pop(&KeyGen, poly, pop) {
                return Err(FinishKeyGenError::InvalidProofOfPossession(i));
            }
        }

        let mut total_secret_share = s!(0);
        for (i, (secret_share, poly)) in secret_shares.iter().zip(&KeyGen.point_polys).enumerate() {
            let expected_public_share = poly.eval((my_index + 1) as u32);
            if g!(secret_share * G) != expected_public_share {
                return Err(FinishKeyGenError::InvalidShare(i));
            }
            total_secret_share = s!(total_secret_share + secret_share);
        }

        let total_secret_share = total_secret_share.expect_nonzero(
            "since verification shares are non-zero, the total secret share cannot be zero",
        );

        Ok((total_secret_share, KeyGen.frost_key))
    }
}

/// Calculate the lagrange coefficient for participant with index x_j and other signers indexes x_ms
fn lagrange_lambda(x_j: u32, x_ms: &[u32]) -> Scalar {
    let x_j = Scalar::from(x_j).expect_nonzero("target xcoord can not be zero");
    x_ms.iter()
        .map(|x_m| Scalar::from(*x_m).expect_nonzero("index can not be zero"))
        .fold(Scalar::one(), |acc, x_m| {
            let denominator = s!(x_m - x_j)
                .expect_nonzero("removed duplicate indexes")
                .invert();
            s!(acc * x_m * denominator)
        })
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
    nonces: BTreeMap<u32, Nonce>,
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen + AddTag> Frost<H, NG> {
    /// Start a FROST signing session
    ///
    /// ## Return value
    ///
    /// A FROST signing session
    pub fn start_sign_session(
        &self,
        frost_key: &FrostKey,
        nonces: Vec<(u32, Nonce)>,
        message: Message,
    ) -> SignSession {
        let mut nonce_map: BTreeMap<_, _> =
            nonces.into_iter().map(|(i, nonce)| (i, nonce)).collect();

        let agg_nonce_points: [Point; 2] = nonce_map
            .iter()
            .fold([Point::zero().mark::<Jacobian>(); 2], |acc, (_, nonce)| {
                [
                    g!({ acc[0] } + { nonce.0[0] }),
                    g!({ acc[1] } + { nonce.0[1] }),
                ]
            })
            .iter()
            .map(|agg_nonce| {
                agg_nonce
                    .normalize()
                    .mark::<NonZero>()
                    .expect("aggregate nonce should be non-zero")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("there are only R1 and R2, collecting cant fail");

        let binding_coeff = Scalar::from_hash(
            self.schnorr
                .challenge_hash()
                .clone()
                .add(agg_nonce_points[0])
                .add(agg_nonce_points[1])
                .add(frost_key.joint_public_key)
                .add(message),
        );
        let (agg_nonce, nonces_need_negation) =
            g!({ agg_nonce_points[0] } + binding_coeff * { agg_nonce_points[1] })
                .normalize()
                .expect_nonzero("impossibly unlikely, input is a hash")
                .into_point_with_even_y();

        for (_, nonce) in &mut nonce_map {
            nonce.conditional_negate(nonces_need_negation);
        }

        let challenge = self.schnorr.challenge(
            agg_nonce.to_xonly(),
            frost_key.joint_public_key.to_xonly(),
            message,
        );

        SignSession {
            binding_coeff,
            nonces_need_negation,
            agg_nonce,
            challenge,
            nonces: nonce_map,
        }
    }

    /// Generates a partial signature share under the FROST key using a secret share.
    ///
    /// ## Return value
    ///
    /// Returns a signature Scalar.
    pub fn sign(
        &self,
        frost_key: &FrostKey,
        session: &SignSession,
        my_index: u32,
        secret_share: &Scalar,
        secret_nonces: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        let mut lambda = lagrange_lambda(
            my_index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != (my_index as u32))
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let [mut r1, mut r2] = secret_nonces.secret;
        r1.conditional_negate(session.nonces_need_negation);
        r2.conditional_negate(session.nonces_need_negation);

        let b = &session.binding_coeff;
        let x = secret_share;
        let c = &session.challenge;
        s!(r1 + (r2 * b) + lambda * x * c).mark::<Public>()
    }

    /// Verify a partial signature at `index`.
    ///
    /// Check partial signature against the verification shares created during keygen.
    ///
    /// ## Return Value
    ///
    /// Returns `bool`, true if partial signature is valid.
    pub fn verify_signature_share(
        &self,
        frost_key: &FrostKey,
        session: &SignSession,
        index: u32,
        signature_share: Scalar<Public, Zero>,
    ) -> bool {
        let s = signature_share;
        let mut lambda = lagrange_lambda(
            index as u32 + 1,
            &session
                .nonces
                .iter()
                .filter(|(j, _)| **j != (index as u32))
                .map(|(j, _)| *j as u32 + 1)
                .collect::<Vec<_>>(),
        );
        lambda.conditional_negate(frost_key.needs_negation);
        let c = &session.challenge;
        let b = &session.binding_coeff;
        let X = frost_key.verification_shares[index as usize];
        let [ref R1, ref R2] = session
            .nonces
            .get(&(index as u32))
            .expect("verifying index that is not part of signing coalition")
            .0;
        g!(R1 + b * R2 + (c * lambda) * X - s * G).is_zero()
    }

    /// Combine a vector of partial signatures into an aggregate signature.
    ///
    /// Includes tweak in combined signature.
    ///
    /// ## Return value
    ///
    /// Returns a combined schnorr [`Signature`] for the message.
    /// Valid against the joint public key.
    pub fn combine_signature_shares(
        &self,
        frost_key: &FrostKey,
        session: &SignSession,
        partial_sigs: Vec<Scalar<Public, Zero>>,
    ) -> Signature {
        let ck = s!(session.challenge * frost_key.tweak);
        let sum_s = partial_sigs
            .into_iter()
            .reduce(|acc, partial_sig| s!(acc + partial_sig).mark::<Public>())
            .unwrap_or(Scalar::zero().mark::<Public>());
        Signature {
            R: session.agg_nonce.to_xonly(),
            s: s!(sum_s + ck).mark::<Public>(),
        }
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen + AddTag> Frost<H, NG> {
    /// Generate nonces for secret shares
    ///
    /// It is very important that you use a unique `sid` for this signing session and to also carefully
    /// consider the implications of your choice of underlying [`NonceGen`].
    ///
    /// When choosing a `secret` to use, if you are generating nonces prior to KeyGen completion,
    /// use the static first coefficient of your polynomial.
    /// Otherwise you can use your secret share of the joint FROST key.
    ///
    /// The application must decide upon a unique `sid` for this FROST multisignature.
    /// For example, the concatenation of: my_signing_index, joint_key, verfication_shares
    ///
    /// ## Return Value
    ///
    /// A NonceKeyPair comprised of secret scalars [r1, r2] and public nonces [R1, R2]
    pub fn gen_nonce(&self, secret: &Scalar, sid: &[u8]) -> NonceKeyPair {
        let r1 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r1-frost", sid]
        );
        let r2 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret,
            public => [ b"r2-frost", sid]
        );
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }
    }
}

#[cfg(test)]
mod test {
    use core::num::NonZeroU32;

    use super::*;
    use rand::seq::SliceRandom;
    use secp256kfun::{
        nonce::Deterministic,
        proptest::{
            arbitrary::any,
            option, proptest,
            strategy::{Just, Strategy},
            test_runner::{RngAlgorithm, TestRng},
        },
    };
    use sha2::Sha256;

    proptest! {
        #[test]
        fn frost_prop_test((n_parties, threshold) in (3u32..8).prop_flat_map(|n| (Just(n), 3u32..=n)), tweak1 in option::of(any::<Scalar<Public, Zero>>()), tweak2 in option::of(any::<Scalar<Public, Zero>>())) {
            let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
                Deterministic::<Sha256>::default(),
            ));
            dbg!(threshold, n_parties);
            assert!(threshold <= n_parties);

            // create some scalar polynomial for each party
            let mut scalar_polys = vec![];
            for i in 1..=n_parties {
                let scalar_poly = (1..=threshold).map(|j| Scalar::from_non_zero_u32(NonZeroU32::new(i*j).expect("starts from 1"))).collect();
                scalar_polys.push(ScalarPoly::new(scalar_poly));
            }
            let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

            let KeyGen = frost.new_keygen(point_polys).unwrap();

            let mut proofs_of_possession= vec![];
            let mut shares_vec = vec![];
            for sp in scalar_polys {
                let (shares, pop) = frost.create_shares(&KeyGen, sp);
                proofs_of_possession.push(pop);
                shares_vec.push(shares);
            }

            // collect the recieved shares for each party
            let mut recieved_shares: Vec<Vec<_>> = vec![];
            for party_index in 0..n_parties {
                recieved_shares.push(vec![]);
                for share_index in 0..n_parties {
                    recieved_shares[party_index as usize].push(shares_vec[share_index as usize][party_index as usize].clone());
                }
            }

            // finish keygen for each party
            let (secret_shares, frost_keys): (Vec<Scalar>, Vec<FrostKey>) = (0..n_parties).map(|i| {
                let (secret_share, mut frost_key) = frost.finish_keygen(
                    KeyGen.clone(),
                    i,
                    recieved_shares[i as usize].clone(),
                    proofs_of_possession.clone(),
                )
                .unwrap();

                for tweak in [tweak1, tweak2] {
                    if let Some(tweak) = tweak {
                        frost_key = frost_key.tweak(tweak).unwrap();
                    }
                }
                (secret_share, frost_key)
            }).unzip();

            // use a boolean mask for which t participants are signers
            let mut signer_mask = vec![true; threshold as usize];
            signer_mask.append(&mut vec![false; (n_parties - threshold) as usize]);
            // shuffle the mask for random signers (roughly shuffled and deterministic based on signers_mask_seed)
            signer_mask.shuffle(&mut TestRng::deterministic_rng(RngAlgorithm::ChaCha));

            let signer_indexes: Vec<_> = signer_mask.iter().enumerate().filter(|(_, is_signer)| **is_signer).map(|(i,_)| i).collect();

            let verification_shares_bytes: Vec<_> = frost_keys[signer_indexes[0]]
                .verification_shares
                .iter()
                .map(|share| share.to_bytes())
                .collect();

            let sid = [
                frost_keys[signer_indexes[0]].joint_public_key.to_bytes().as_slice(),
                verification_shares_bytes.concat().as_slice(),
                b"frost-prop-test".as_slice(),
            ]
            .concat();
            let nonces: Vec<NonceKeyPair> = signer_indexes.iter().map(|i| frost.gen_nonce(&secret_shares[*i as usize], &[sid.as_slice(), [*i as u8].as_slice()].concat())).collect();

            let mut recieved_nonces: Vec<_> = vec![];
            for (i, nonce) in signer_indexes.iter().zip(nonces.clone()) {
                recieved_nonces.push((*i as u32, nonce.public()));
            }

            // Create Frost signing session
            let signing_session = frost.start_sign_session(&frost_keys[signer_indexes[0]], recieved_nonces.clone(), Message::plain("test", b"test"));

            let mut signatures = vec![];
            for i in 0..signer_indexes.len() {
                let signer_index = signer_indexes[i] as usize;
                let session = frost.start_sign_session(&frost_keys[signer_index], recieved_nonces.clone(), Message::plain("test", b"test"));
                let sig = frost.sign(&frost_keys[signer_index], &session, signer_index as u32, &secret_shares[signer_index], nonces[i].clone());
                assert!(frost.verify_signature_share(&frost_keys[signer_index], &session, signer_index as u32, sig));
                signatures.push(sig);
            }
            let combined_sig = frost.combine_signature_shares(&frost_keys[signer_indexes[0] as usize], &signing_session, signatures);

            assert!(frost.schnorr.verify(
                &frost_keys[signer_indexes[0] as usize].joint_public_key,
                Message::<Public>::plain("test", b"test"),
                &combined_sig
            ));
        }
    }

    #[test]
    fn frost_test_end_to_end() {
        // Create a secret polynomial for each participant
        let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
        let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
        let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);

        let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
            Deterministic::<Sha256>::default(),
        ));
        let point_polys = vec![
            sp1.to_point_poly(),
            sp2.to_point_poly(),
            sp3.to_point_poly(),
        ];

        let KeyGen = frost.new_keygen(point_polys).unwrap();
        let (shares1, pop1) = frost.create_shares(&KeyGen, sp1);
        let (shares2, pop2) = frost.create_shares(&KeyGen, sp2);
        let (shares3, pop3) = frost.create_shares(&KeyGen, sp3);
        let proofs_of_possession = vec![pop1, pop2, pop3];

        let (secret_share1, mut frost_key) = frost
            .finish_keygen(
                KeyGen.clone(),
                0,
                vec![shares1[0].clone(), shares2[0].clone(), shares3[0].clone()],
                proofs_of_possession.clone(),
            )
            .unwrap();
        let (_secret_share2, mut jk2) = frost
            .finish_keygen(
                KeyGen.clone(),
                1,
                vec![shares1[1].clone(), shares2[1].clone(), shares3[1].clone()],
                proofs_of_possession.clone(),
            )
            .unwrap();
        let (secret_share3, mut jk3) = frost
            .finish_keygen(
                KeyGen.clone(),
                2,
                vec![shares1[2].clone(), shares2[2].clone(), shares3[2].clone()],
                proofs_of_possession,
            )
            .unwrap();

        assert_eq!(frost_key, jk2);
        assert_eq!(frost_key, jk3);

        let use_tweak = true;
        let tweak = if use_tweak {
            Scalar::from_bytes([
                0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF, 0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A,
                0x72, 0x3D, 0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79, 0x80, 0x2B, 0x26, 0x3C,
                0xDF, 0xCD, 0x83, 0xBB,
            ])
            .unwrap()
        } else {
            Scalar::zero()
        };

        frost_key = frost_key.tweak(tweak.clone()).expect("tweak worked");
        jk2 = jk2.tweak(tweak.clone()).expect("tweak worked");
        jk3 = jk3.tweak(tweak).expect("tweak worked");

        dbg!();

        let tweak = if use_tweak {
            Scalar::from_bytes([
                0xE8, 0xF7, 0x92, 0xFF, 0x92, 0x25, 0xA2, 0xAF, 0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A,
                0x72, 0x3D, 0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79, 0x80, 0x2B, 0x26, 0x3C,
                0xDF, 0xCD, 0x83, 0xBB,
            ])
            .unwrap()
        } else {
            Scalar::zero()
        };

        frost_key = frost_key.tweak(tweak.clone()).expect("tweak worked");
        jk2 = jk2.tweak(tweak.clone()).expect("tweak worked");
        jk3 = jk3.tweak(tweak).expect("tweak worked");

        let verification_shares_bytes: Vec<_> = frost_key
            .verification_shares
            .iter()
            .map(|share| share.to_bytes())
            .collect();

        // Create unique session IDs for these signing sessions
        let sid1 = [
            frost_key.joint_public_key.to_bytes().as_slice(),
            verification_shares_bytes.concat().as_slice(),
            b"frost-end-to-end-test-1".as_slice(),
            b"0".as_slice(),
        ]
        .concat();

        let sid2 = [
            frost_key.joint_public_key.to_bytes().as_slice(),
            verification_shares_bytes.concat().as_slice(),
            b"frost-end-to-end-test-2".as_slice(),
            b"2".as_slice(),
        ]
        .concat();

        let nonce1 = frost.gen_nonce(&secret_share1, &sid1);
        let nonce3 = frost.gen_nonce(&secret_share3, &sid2);
        let nonces = vec![(0, nonce1.public()), (2, nonce3.public())];
        let nonces2 = vec![(0, nonce1.public()), (2, nonce3.public())];

        let session = frost.start_sign_session(&frost_key, nonces, Message::plain("test", b"test"));

        dbg!(&session);
        {
            let session2 = frost.start_sign_session(&jk2, nonces2, Message::plain("test", b"test"));
            assert_eq!(session2, session);
        }

        let sig1 = frost.sign(&frost_key, &session, 0, &secret_share1, nonce1);
        let sig3 = frost.sign(&jk3, &session, 2, &secret_share3, nonce3);

        dbg!(sig1, sig3);

        assert!(frost.verify_signature_share(&frost_key, &session, 0, sig1));
        assert!(frost.verify_signature_share(&frost_key, &session, 2, sig3));
        let combined_sig = frost.combine_signature_shares(&frost_key, &session, vec![sig1, sig3]);

        assert!(frost.schnorr.verify(
            &frost_key.joint_public_key,
            Message::<Public>::plain("test", b"test"),
            &combined_sig
        ));
    }

    #[test]
    fn test_lagrange_lambda() {
        let res = s!((1 * 4 * 5) * { s!((1 - 2) * (4 - 2) * (5 - 2)).expect_nonzero("").invert() });
        assert_eq!(res, lagrange_lambda(2, &[1, 4, 5]));
    }
}
