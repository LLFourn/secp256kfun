#![allow(missing_docs, unused)]
use core::{char::from_u32_unchecked, iter};

use crate::{KeyPair, Message, Schnorr, Signature, Vec, musig::{NonceKeyPair, SignSession, Nonce}};
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    nonce::NonceGen,
    rand_core, s, Point, Scalar, XOnly, G,
};

pub struct Frost<PS, SS> {
    pub pop_schnorr: PS,
    pub sign_schnorr: SS,
}

#[derive(Clone, Debug)]
pub struct ScalarPoly(Vec<Scalar>);

impl ScalarPoly {
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

    fn to_point_poly(&self) -> PointPoly {
        PointPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    pub fn random(n_coefficients: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        ScalarPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }

    pub fn first_coef(&self) -> &Scalar {
        &self.0[0]
    }
}

#[derive(Clone, Debug)]
pub struct PointPoly<Z = NonZero>(Vec<Point<Normal, Public, Z>>);

impl<Z> PointPoly<Z> {
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

    fn combine(mut polys: impl Iterator<Item = Self>) -> PointPoly<Zero> {
        let mut combined_poly = polys
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

    pub fn poly_len(&self) -> usize {
        self.0.len()
    }
}

#[derive(Clone, Debug)]
pub struct SecretShares {
    shares: Vec<Scalar<Secret, Zero>>,
    proof_of_possession: Signature,
}

#[derive(Clone, Debug)]
pub struct Dkg {
    point_polys: Vec<PointPoly>,
    needs_negation: bool,
    verification_shares: Vec<Point<Normal, Public, Zero>>,
}

#[derive(Debug, Clone)]
pub enum FirstRoundError {
    PolyDifferentLength(usize),
    NotEnoughParties,
    ZeroJointKey,
}

#[derive(Debug, Clone)]
pub enum SecondRoundError {
    InvalidPoP(usize),
    InvalidShare(usize),
}

#[derive(Clone, Debug)]
pub struct JointKey {
    joint_public_key: Point<EvenY>,
    needs_negation: bool,
    verification_shares: Vec<Point<Normal, Public, Zero>>,
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen, SS> Frost<Schnorr<H, NG>, SS> {
    pub fn create_shares(&self, dkg: &Dkg, mut scalar_poly: ScalarPoly) -> SecretShares {
        let pop_key = scalar_poly.first_coef();
        let keypair = self.pop_schnorr.new_keypair(pop_key.clone());
        let proof_of_possession = self.pop_schnorr.sign(&keypair, Message::<Public>::raw(b""));
        scalar_poly.0[0].conditional_negate(dkg.needs_negation);
        let mut shares = (1..=dkg.point_polys.len())
            .map(|i| scalar_poly.eval(i as u32))
            .collect();
        SecretShares {
            shares,
            proof_of_possession,
        }
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG, SS> Frost<Schnorr<H, NG>, SS> {
    pub fn collect_polys(&self, mut point_polys: Vec<PointPoly>) -> Result<Dkg, FirstRoundError> {
        {
            let len_first_poly = point_polys[0].poly_len();
            if let Some((i, _)) = point_polys
                .iter()
                .enumerate()
                .find(|(i, point_poly)| point_poly.poly_len() != len_first_poly)
            {
                return Err(FirstRoundError::PolyDifferentLength(i));
            }

            if point_polys.len() < len_first_poly {
                return Err(FirstRoundError::NotEnoughParties);
            }
        }

        let mut joint_poly = PointPoly::combine(point_polys.clone().into_iter());
        let joint_key = joint_poly.0[0];

        let (joint_key, needs_negation) = joint_key
            .mark::<NonZero>()
            .ok_or(FirstRoundError::ZeroJointKey)?
            .into_point_with_even_y();

        joint_poly.0[0].conditional_negate(needs_negation);

        for poly in &mut point_polys {
            poly.0[0].conditional_negate(needs_negation);
        }

        let verification_shares = (1..=point_polys.len())
            .map(|i| joint_poly.eval(i as u32).normalize())
            .collect();

        Ok(Dkg {
            point_polys,
            needs_negation,
            verification_shares,
        })
    }

    pub fn collect_shares(
        &self,
        dkg: &Dkg,
        my_index: usize,
        secret_shares: Vec<(Scalar<Secret, Zero>, Signature)>,
    ) -> Result<Scalar<Secret, Zero>, SecondRoundError> {
        assert_eq!(secret_shares.len(), dkg.verification_shares.len());
        let mut total_secret_share = s!(0);
        for (i, ((secret_share, proof_of_possession), poly)) in
            secret_shares.iter().zip(dkg.point_polys).enumerate()
        {
            let expected_public_share = poly.eval((my_index + 1) as u32);
            if g!(secret_share * G) != expected_public_share {
                return Err(SecondRoundError::InvalidShare(i));
            }
            let (verification_key, _) = poly.0[0].into_point_with_even_y();

            if !self.pop_schnorr.verify(
                &verification_key,
                Message::<Public>::raw(b""),
                proof_of_possession,
            ) {
                return Err(SecondRoundError::InvalidPoP(i));
            }

            total_secret_share = s!(total_secret_share + secret_share);
        }

        Ok(total_secret_share)
    }
}


impl<H: Digest<OutputSize=U32>, SP, NG> for Frost<SP, Schnorr<H, NG>> {

    pub fn start_sign_session(&self, dkg: &Dkg, nonces: Vec<Nonce>, message: Message) -> SignSession {
        todo!()
    }

    pub fn sign(&self, dkg: &Dkg, secret_nonces: NonceKeyPair, session: &SignSession) -> Scalar {
        todo!()
    }

    #[must_use]
    pub fn verify_signature_share(&self, dkg: &Dkg, session: &SignSession, index: usize, share: Scalar<Public, Zero>) -> bool {
        todo!()
    }


    pub fn combine_signature_shares(&self, dkg: &Dkg, session: &SignSession, partial_sigs: Vec<Scalar<Public, Zero>>) -> Signature {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dkg() {
        let n_coefficients = 3;
        let p1 = ScalarPoly::random(n_coefficients, &mut rand::thread_rng());
        let p2 = ScalarPoly::random(n_coefficients, &mut rand::thread_rng());
        let p3 = ScalarPoly::random(n_coefficients, &mut rand::thread_rng());

        // Dkg::start_first_round()

        dbg!(p1);
        panic!();
    }
}
