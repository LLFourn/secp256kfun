#![allow(missing_docs, unused)]
use core::{char::from_u32_unchecked, iter};

use crate::{KeyPair, Message, Schnorr, Signature, Vec};
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    nonce::NonceGen,
    rand_core, s, Point, Scalar, XOnly, G,
};

pub struct Dkg<S> {
    pub schnorr: S,
}

#[derive(Clone, Debug)]
pub struct LocalPoly(Vec<Scalar>);

#[derive(Clone, Debug)]
pub struct DkgMessage1 {
    public_poly: PublicPoly,
}

#[derive(Clone, Debug)]
pub struct DkgState1 {
    local_poly: LocalPoly,
}

impl LocalPoly {
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

    fn to_public_poly(&self) -> PublicPoly {
        PublicPoly(self.0.iter().map(|a| g!(a * G).normalize()).collect())
    }

    pub fn random(n_coefficients: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        LocalPoly((0..n_coefficients).map(|_| Scalar::random(rng)).collect())
    }
}

#[derive(Clone, Debug)]
pub struct PublicPoly<Z = NonZero>(Vec<Point<Normal, Public, Z>>);

impl<Z> PublicPoly<Z> {
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

    fn combine(mut polys: impl Iterator<Item = Self>) -> PublicPoly<Zero> {
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
        PublicPoly(combined_poly.into_iter().map(|p| p.normalize()).collect())
    }
}

#[derive(Clone, Debug)]
pub struct DkgMessage2 {
    secret_share: Scalar<Secret, Zero>,
    proof_of_possession: Signature,
}

#[derive(Clone, Debug)]
pub struct DkgState2 {
    public_polys: Vec<PublicPoly>,
    index: usize,
    local_share: Scalar<Secret, Zero>,
    joint_key: Point<EvenY>,
}

#[derive(Debug, Clone)]
pub enum FirstRoundError {
    TooFewParticipants,
    ZeroJointKey,
}

#[derive(Debug, Clone)]
pub enum SecondRoundError {
    InvalidPoP(usize),
    InvalidShare(usize),
    TooFewShares,
}

#[derive(Clone, Debug)]
pub struct JointKey {
    joint_public_key: Point<EvenY>,
    verification_shares: Vec<Point<Normal, Public, Zero>>,
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> Dkg<Schnorr<H, NG>> {
    pub fn start_first_round(&self, local_poly: LocalPoly) -> (DkgMessage1, DkgState1) {
        let public_poly = local_poly.to_public_poly();
        (DkgMessage1 { public_poly }, DkgState1 { local_poly })
    }

    pub fn start_second_round(
        &self,
        mut state: DkgState1,
        recieved: Vec<DkgMessage1>,
        index: usize,
    ) -> Result<(Vec<DkgMessage2>, DkgState2), FirstRoundError> {
        let n_parties = recieved.len() + 1;
        // TODO decide what happens if user uses own DkgMessage1 as recieved
        if n_parties < state.local_poly.0.len() {
            return Err(FirstRoundError::TooFewParticipants);
        }

        let mut joint_key = g!({ &state.local_poly.0[0] } * G).mark::<Zero>();
        for message in recieved.iter() {
            joint_key = g!(joint_key + { message.public_poly.0[0] });
        }
        let (joint_key, needs_negation) = joint_key
            .normalize()
            .mark::<NonZero>()
            .ok_or(FirstRoundError::ZeroJointKey)?
            .into_point_with_even_y();
        state.local_poly.0[0].conditional_negate(needs_negation);

        // TODO sign all commitments
        let keypair = self.schnorr.new_keypair(state.local_poly.0[0].clone());
        let proof_of_possession = self.schnorr.sign(&keypair, Message::<Public>::raw(b""));

        let mut secret_shares = (0..n_parties)
            .map(|i| DkgMessage2 {
                secret_share: state.local_poly.eval(i as u32),
                proof_of_possession: proof_of_possession.clone(),
            })
            .collect::<Vec<_>>();

        let local_share = secret_shares.remove(index).secret_share;

        let public_polys = recieved
            .into_iter()
            .map(|message| message.public_poly)
            .collect();

        Ok((secret_shares, DkgState2 {
            public_polys,
            index,
            local_share,
            joint_key,
        }))
    }

    pub fn finish_second_round(
        &self,
        state: DkgState2,
        messages: Vec<DkgMessage2>,
    ) -> Result<(JointKey, Scalar<Secret, Zero>), SecondRoundError> {
        let n_parties = state.public_polys.len() + 1;
        assert_eq!(state.public_polys.len(), messages.len());

        let mut total_secret_share = state.local_share;
        for (i, message) in messages.iter().enumerate() {
            if g!(message.secret_share * G) != state.public_polys[i].eval(state.index as u32 + 1) {
                return Err(SecondRoundError::InvalidShare(i));
            }
            total_secret_share = s!(total_secret_share + message.secret_share);
        }

        for (i, message) in messages.iter().enumerate() {
            let (verification_key, _) = state.public_polys[i].0[0].into_point_with_even_y();
            if !self.schnorr.verify(
                &verification_key,
                Message::<Public>::raw(b""),
                &message.proof_of_possession,
            ) {
                return Err(SecondRoundError::InvalidPoP(i));
            }
        }

        let joint_poly = PublicPoly::combine(state.public_polys.into_iter());
        let other_party_indexes = (1..n_parties).map(|i| if i >= state.index { i + 1 } else { i });
        let verification_shares = other_party_indexes
            .map(|i| joint_poly.eval(i as u32).normalize())
            .collect();

        let joint_key = JointKey {
            joint_public_key: state.joint_key,
            verification_shares,
        };

        Ok((joint_key, total_secret_share))
    }
}

struct Sign<S, H> {
    schnorr: S,
    nonce_coeff_hash: H,
}

impl<S, H> Sign<S, H> {
    fn sign(joint_key: &JointKey, message: Message, secret_share: Scalar) {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dkg() {
        let n_coefficients = 3;
        let p1 = LocalPoly::random(n_coefficients, &mut rand::thread_rng());
        let p2 = LocalPoly::random(n_coefficients, &mut rand::thread_rng());
        let p3 = LocalPoly::random(n_coefficients, &mut rand::thread_rng());

        // Dkg::start_first_round()

        dbg!(p1);
        panic!();
    }
}
