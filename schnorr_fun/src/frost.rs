//! ## Description
//!
//! The FROST (Flexible Round-Optimize Schnorr Threshold) multisignature scheme lets you aggregate
//! multiple public keys into a single public key that requires some threshold t-of-n secret keys to
//! sign a signature under the aggregate key.
//!
//! This implementation has NOT yet been made compatible with other existing implementations
//! [secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/138
//!
//! See MuSig in this repository, the [FROST paper] and [Security of Multi- and Threshold Signatures].
//!
//! [FROST paper]: https://eprint.iacr.org/2020/852.pdf
//! [Security of Multi- and Threshold Signatures]: https://eprint.iacr.org/2021/1375.pdf
use crate::{
    musig::{Nonce, NonceKeyPair},
    Message, Schnorr, Signature, Vec,
};
use core::iter;
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::HashAdd,
    marker::*,
    nonce::{AddTag, NonceGen},
    rand_core, s, Point, Scalar, G,
};
use std::collections::BTreeMap;

/// The FROST context.
// replacing nonce_coeff_hash with dkg_id_hash H
#[derive(Clone)]
pub struct Frost<H, NG: AddTag> {
    schnorr: Schnorr<H, NG>,
    keygen_id_hash: H,
}

impl<H: Clone, NG: AddTag + Clone> Frost<H, NG> {
    /// Generate a new Frost context from a Schnorr context.
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            schnorr: schnorr.clone(),
            keygen_id_hash: schnorr.challenge_hash,
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
    /// Evaluate the polynomial at position x.
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

    /// Combine a vector of polynomials into a joint polynomial.
    fn combine(mut polys: impl Iterator<Item = Self>) -> PointPoly<Zero> {
        let mut combined_poly = polys
            // TODO
            .next()
            .expect("cannot combine empty list of polys")
            .0
            .into_iter()
            .map(|p| p.mark::<(Jacobian, Zero)>())
            .collect::<Vec<_>>();
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
    keygen_id: Point<EvenY>,
    frost_key: FrostKey,
}

impl KeyGen {
    /// Return the number of parties in the KeyGen
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

/// First round errors
#[derive(Debug, Clone)]
pub enum NewKeyGenError {
    /// Received polynomial is of differing length.
    PolyDifferentLength(usize),
    /// Number of parties is less than the length of polynomials specifying the threshold.
    NotEnoughParties,
    /// Joint key is zero. Should be impossible, or maliciously chosen.
    ZeroFrostKey,
    /// Verification share is zero. Should be impossible, or maliciously chosen.
    ZeroVerificationShare,
}

impl core::fmt::Display for NewKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use NewKeyGenError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroFrostKey => write!(f, "The joint key was zero. This means one of the parties was possibly malicious and you are not protecting against this properly"),
            ZeroVerificationShare => write!(f, "One of the verification shares was malicious so we must abort the protocol"),
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
            InvalidShare(i) => write!(f, "the share provided by party at index {} was invalid", i),
            &InvalidProofOfPossession(i) => write!(
                f,
                "the proof of possession provided by party at index {} was invalid",
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
    joint_public_key: Point<EvenY>,
    verification_shares: Vec<Point>,
    threshold: u32,
    tweak: Scalar<Public, Zero>,
    needs_negation: bool,
}

impl FrostKey {
    /// The joint public key of the multisignature
    ///
    /// ## Return value
    ///
    /// A point (normalised to have an even Y coordinate).
    pub fn public_key(&self) -> Point<EvenY> {
        self.joint_public_key
    }

    /// *Tweak* the aggregated key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G`. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// This is how you embed a taproot commitment into a key.
    ///
    /// Also updates whether the secret first coefficient needs negation.
    /// XOR of existing key needs_negation and new tweaked key needs_negation.
    /// If both need negation, they will cancel out.
    ///
    /// ## Return value
    ///
    /// Returns a new frostkey with the same parties but a different aggregated public key.
    /// In the unusual case that the twak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    /// // TODO ^ CHECK THIS
    pub fn tweak(&mut self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        let mut tweak = s!(self.tweak + tweak).mark::<Public>();
        let (joint_public_key, tweak_needs_negation) = g!(self.joint_public_key + tweak * G)
            .mark::<NonZero>()?
            .into_point_with_even_y();
        tweak.conditional_negate(tweak_needs_negation);

        let joint_needs_negation = self.needs_negation ^ tweak_needs_negation;

        // Store new join_public_key and new tweak, as well as needs_negation.
        Some(FrostKey {
            joint_public_key,
            verification_shares: self.verification_shares.clone(),
            threshold: self.threshold.clone(),
            tweak,
            needs_negation: joint_needs_negation,
        })
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The total number of signers in this multisignature.
    pub fn n_signers(&self) -> u32 {
        self.verification_shares.len() as u32
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag> Frost<H, NG> {
    /// TODO POP
    /// Create a secret share for every other participant by evaluating our secret polynomial.
    /// at their participant index. f(i) for 1<=i<= n.
    ///
    /// Each secret share f(i) needs to be securely communicated to participant i.
    ///
    /// ## Return value
    ///
    /// Returns a vector of secret shares, the share at index 0 is destined for participant 1.
    pub fn create_shares(
        &self,
        KeyGen: &KeyGen,
        scalar_poly: ScalarPoly,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> (Vec<Scalar<Secret, Zero>>, (Point, Scalar<Secret, Zero>)) {
        // Create proof of possession
        let pop_r = Scalar::random(rng);
        let pop_R = g!(pop_r * G).normalize();
        let pop_c = Scalar::from_hash(
            self.keygen_id_hash
                .clone()
                // TODO CHECK SECRET REFERENCE
                .add(g!({ scalar_poly.0[0].clone() } * G).normalize())
                .add(KeyGen.keygen_id)
                .add(pop_R),
        );
        let pop_z = s!(pop_c + pop_r);

        let shares = (1..=KeyGen.point_polys.len())
            .map(|i| scalar_poly.eval(i as u32))
            .collect();

        (shares, (pop_R, pop_z))
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag> Frost<H, NG> {
    /// TODO
    fn verify_pop(
        &self,
        keygen_id: Point<secp256kfun::marker::EvenY>,
        point_poly: &PointPoly,
        pop: (Point, Scalar<Secret, Zero>),
    ) -> bool {
        let first_point = point_poly.0[0];
        let (pop_R, pop_z) = pop;
        let pop_c = Scalar::from_hash(
            self.keygen_id_hash
                .clone()
                .add(first_point)
                .add(keygen_id)
                .add(pop_R),
        );
        !g!(pop_R + pop_c * first_point - pop_z * G).is_zero()
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: AddTag> Frost<H, NG> {
    /// Collect all the public polynomials into a KeyGen session with a joint key.
    ///
    /// Takes a vector of point polynomials with your polynomial at index 0.
    ///
    /// Also prepares a vector of verification shares for later.
    ///
    /// ## Return value
    ///
    /// Returns a KeyGen
    pub fn new_keygen(&self, mut point_polys: Vec<PointPoly>) -> Result<KeyGen, NewKeyGenError> {
        {
            let len_first_poly = point_polys[0].poly_len();
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

        // for poly in &mut point_polys {
        //     poly.0[0] = poly.0[0].conditional_negate(needs_negation);
        // }
        // joint_poly.0[0] = joint_poly.0[0].conditional_negate(needs_negation);

        // TODO set keygen
        let keygen_id = joint_public_key;

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

    /// Collect the vector of all the secret shares into your total long-lived secret share.
    /// The secret_shares include your own and a share from each of the other participants.
    ///
    /// Confirms the secret_share sent to us matches the expected
    /// by evaluating their polynomial at our index and comparing.
    ///
    ///
    ///
    /// # Returns
    ///
    /// Your total secret share Scalar and the joint key
    pub fn finish_keygen(
        &self,
        KeyGen: KeyGen,
        my_index: u32,
        secret_shares: Vec<Scalar<Secret, Zero>>,
        proofs_of_possession: Vec<(Point, Scalar<Secret, Zero>)>,
    ) -> Result<(Scalar, FrostKey), FinishKeyGenError> {
        assert_eq!(
            secret_shares.len(),
            KeyGen.frost_key.verification_shares.len()
        );

        for (i, (poly, pop)) in KeyGen
            .point_polys
            .iter()
            .zip(proofs_of_possession)
            .enumerate()
        {
            if !self.verify_pop(KeyGen.keygen_id, poly, pop) {
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
            "since verification shares are non-zero, corresponding secret shares cannot be zero",
        );

        Ok((total_secret_share, KeyGen.frost_key))
    }
}

/// Calculate the lagrange coefficient for participant with index x_j and other signers indexes x_ms
pub fn lagrange_lambda(x_j: u32, x_ms: &[u32]) -> Scalar {
    // TODO
    // Change to one inverse
    // https://people.maths.ox.ac.uk/trefethen/barycentric.pdf
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
    pub fn start_sign_session(
        &self,
        frost_key: &FrostKey,
        nonces: Vec<(u32, Nonce)>,
        message: Message,
    ) -> SignSession {
        let mut nonce_map: BTreeMap<_, _> =
            nonces.into_iter().map(|(i, nonce)| (i, nonce)).collect();
        // assert_eq!(nonces.len(), nonce_map.len());
        assert!(frost_key.threshold <= nonce_map.len() as u32);

        let agg_nonces_R1_R2: Vec<Point> = nonce_map
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
            .collect();

        let agg_nonce_points: [Point; 2] = [agg_nonces_R1_R2[0], agg_nonces_R1_R2[1]];
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

    /// Generates a partial signature share under the joint key using a secret share.
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
    /// Checked using verification shares that are stored in the joint key.
    ///
    /// ## Return Value
    ///
    /// Returns `bool, true if partial signature is valid.
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
    /// Returns a combined schnorr [`schnorr_fun::signature::Signature`] for the message.
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
    /// It is very important to carefully consider the implications of your choice of underlying
    /// [`NonceGen`].
    ///
    /// If you are generating nonces prior to KeyGen completion, use the static first coefficient
    /// for your `secret`. Otherwise you can use your secret share of the joint key.
    ///
    /// The application must decide upon a unique `sid` (session id) for this frost multisignature.
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

/// Allows getting the joint key
// TODO seal this trait
pub trait GetFrostKey {
    fn get_frost_key(&self) -> &FrostKey;
}

impl GetFrostKey for KeyGen {
    fn get_frost_key(&self) -> &FrostKey {
        &self.frost_key
    }
}

impl GetFrostKey for FrostKey {
    fn get_frost_key(&self) -> &FrostKey {
        &self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{prelude::IteratorRandom, Rng};
    // proptest::prelude::*};
    use secp256kfun::{
        nonce::Deterministic,
        proptest::{arbitrary::any, proptest},
    };
    use sha2::Sha256;

    proptest! {
        #[test]
        fn frost_prop_test(n_parties in 3u32..8,  something in any::<u32>()) {
            let mut rng = rand::thread_rng();
            let threshold = rng.gen_range(2..=n_parties);
            let frost = Frost::new(Schnorr::<Sha256, Deterministic<Sha256>>::new(
                Deterministic::<Sha256>::default(),
            ));
            dbg!(threshold, n_parties);

            let scalar_polys: Vec<ScalarPoly> = (0..n_parties).map(|_| ScalarPoly::random(threshold, &mut rng)).collect();
            let point_polys: Vec<PointPoly> = scalar_polys.iter().map(|sp| sp.to_point_poly()).collect();

            let KeyGen = frost.new_keygen(point_polys).unwrap();

            let mut proofs_of_possession= vec![];
            let mut shares_vec = vec![];
            for sp in scalar_polys {
                let (shares, pop) = frost.create_shares(&KeyGen, sp, &mut rng);
                proofs_of_possession.push(pop);
                shares_vec.push(shares);
            }

            // let recieved_shares = signer_indexes.iter().zip(signer_indexes).map(|(i, j)| (i,j)).collect();
            let mut recieved_shares: Vec<Vec<_>> = vec![];
            for party_index in 0..n_parties {
                recieved_shares.push(vec![]);
                for share_index in 0..n_parties {
                    recieved_shares[party_index as usize].push(shares_vec[share_index as usize][party_index as usize].clone());
                }
            }

            let (secret_shares, frost_keys): (Vec<Scalar>, Vec<FrostKey>) = (0..n_parties).map(|i| {
                let (secret_share, frost) = frost.finish_keygen(
                    KeyGen.clone(),
                    i,
                    recieved_shares[i as usize].clone(),
                    proofs_of_possession.clone(),
                )
                .unwrap();
                (secret_share, frost)
             }).unzip();




            // Signing coalition with a threshold of parties
            // let n_signers = if threshold == n_parties {
            //     threshold
            // } else {
            //     rng.gen_range(threshold..=n_parties)
            // };
            let n_signers = threshold;
            let signer_indexes = (0..n_parties).choose_multiple(&mut rng, n_signers as usize);

            let sid = frost_keys[0].joint_public_key.to_bytes();

            let nonces: Vec<NonceKeyPair> = signer_indexes.iter().map(|i| frost.gen_nonce(&secret_shares[*i as usize], &sid)).collect();

            let mut recieved_nonces: Vec<_> = vec![];
            for (i, nonce) in signer_indexes.iter().zip(nonces.clone()) {
                recieved_nonces.push((*i, nonce.public()));
            }

            dbg!(recieved_nonces.clone());

            // Create Frost signing session
            let mut signatures = vec![];
            for i in 0..signer_indexes.len() {
                let signer_index = signer_indexes[i] as usize;
                let session = frost.start_sign_session(&frost_keys[signer_index], recieved_nonces.clone(), Message::plain("test", b"test"));
                dbg!(nonces[i].clone());
                let sig = frost.sign(&frost_keys[signer_index], &session, signer_index as u32, &secret_shares[signer_index], nonces[i].clone());
                assert!(frost.verify_signature_share(&frost_keys[signer_index], &session, signer_index as u32, sig));
                signatures.push(sig);
            }

            dbg!(signatures.clone());
            // TODO get this session from loop above
            let session = frost.start_sign_session(&frost_keys[signer_indexes[0] as usize], recieved_nonces.clone(), Message::plain("test", b"test"));
            let combined_sig = frost.combine_signature_shares(&frost_keys[signer_indexes[0] as usize], &session, signatures);

            assert!(frost.schnorr.verify(
                &frost_keys[signer_indexes[0] as usize].joint_public_key,
                Message::<Public>::plain("test", b"test"),
                &combined_sig
            ));


        }
    }

    #[test]
    fn frost_test_end_to_end() {
        let mut rng = rand::thread_rng();
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
        let (shares1, pop1) = frost.create_shares(&KeyGen, sp1, &mut rng);
        let (shares2, pop2) = frost.create_shares(&KeyGen, sp2, &mut rng);
        let (shares3, pop3) = frost.create_shares(&KeyGen, sp3, &mut rng);
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
        if use_tweak {
            let tweak = Scalar::from_bytes([
                0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF, 0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A,
                0x72, 0x3D, 0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79, 0x80, 0x2B, 0x26, 0x3C,
                0xDF, 0xCD, 0x83, 0xBB,
            ])
            .unwrap();
            // let tweak = Scalar::zero();
            frost_key = frost_key.tweak(tweak.clone()).expect("tweak worked");
            jk2 = jk2.tweak(tweak.clone()).expect("tweak worked");
            jk3 = jk3.tweak(tweak).expect("tweak worked");
        }

        // TODO USE PROPER SID
        // public => [ b"r2-frost", my_index.to_be_bytes(), frost_key.joint_public_key, &frost_key.verification_shares[..], sid]
        let sid = frost_key.joint_public_key.to_bytes();
        // for share in frost_key.verification_shares {
        //     // [sid, share].concat(share.to_bytes());
        // }

        let nonce1 = frost.gen_nonce(&secret_share1, &sid);
        let nonce3 = frost.gen_nonce(&secret_share3, &sid);
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
