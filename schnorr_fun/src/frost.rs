#![allow(missing_docs, unused)]
use core::{char::from_u32_unchecked, iter};

use crate::{
    musig::{Nonce, NonceKeyPair},
    KeyPair, Message, Schnorr, Signature, Vec,
};
use rand_core::{CryptoRng, RngCore};
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    nonce::NonceGen,
    rand_core, s, Point, Scalar, XOnly, G,
};

#[derive(Clone, Debug, Default)]
pub struct Frost<SS = ()> {
    pub schnorr: SS,
}

#[derive(Clone, Debug, PartialEq)]
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

    pub fn to_point_poly(&self) -> PointPoly {
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

    pub fn new(x: Vec<Scalar>) -> Self {
        Self(x)
    }
}

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

    pub fn points(&self) -> &[Point<Normal, Public, Z>] {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct Dkg {
    point_polys: Vec<PointPoly>,
    needs_negation: bool,
    joint_key: JointKey,
}

impl Dkg {
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

#[derive(Debug, Clone)]
pub enum FirstRoundError {
    PolyDifferentLength(usize),
    NotEnoughParties,
    ZeroJointKey,
    ZeroVerificationShare,
}

impl core::fmt::Display for FirstRoundError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use FirstRoundError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {} was a different length", i),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroJointKey => write!(f, "The joint key was zero. This means one of the parties was possibly malicious and you are not protecting against this properly"),
            ZeroVerificationShare => write!(f, "One of the verification shares was malicious so we must abort the protocol"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FirstRoundError {}

#[derive(Debug, Clone)]
pub enum SecondRoundError {
    InvalidShare(usize),
}

impl core::fmt::Display for SecondRoundError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use SecondRoundError::*;
        match self {
            InvalidShare(i) => write!(f, "the share provided by party at index {} was invalid", i),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SecondRoundError {}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct JointKey {
    joint_public_key: Point<EvenY>,
    verification_shares: Vec<Point>,
    threshold: usize,
}

impl JointKey {
    pub fn public_key(&self) -> Point<EvenY> {
        self.joint_public_key
    }
}

impl<SS> Frost<SS> {
    pub fn create_shares(
        &self,
        dkg: &Dkg,
        mut scalar_poly: ScalarPoly,
    ) -> Vec<Scalar<Secret, Zero>> {
        scalar_poly.0[0].conditional_negate(dkg.needs_negation);
        (1..=dkg.point_polys.len())
            .map(|i| scalar_poly.eval(i as u32))
            .collect()
    }
}

impl<SS> Frost<SS> {
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

        let (joint_public_key, needs_negation) = joint_key
            .mark::<NonZero>()
            .ok_or(FirstRoundError::ZeroJointKey)?
            .into_point_with_even_y();

        joint_poly.0[0].conditional_negate(needs_negation);

        for poly in &mut point_polys {
            poly.0[0].conditional_negate(needs_negation);
        }

        let verification_shares = (1..=point_polys.len())
            .map(|i| joint_poly.eval(i as u32).normalize().mark::<NonZero>())
            .collect::<Option<Vec<Point>>>()
            .ok_or(FirstRoundError::ZeroVerificationShare)?;

        Ok(Dkg {
            point_polys,
            needs_negation,
            joint_key: JointKey {
                verification_shares,
                joint_public_key,
                threshold: joint_poly.poly_len(),
            },
        })
    }

    pub fn collect_shares(
        &self,
        dkg: Dkg,
        my_index: usize,
        secret_shares: Vec<Scalar<Secret, Zero>>,
    ) -> Result<(Scalar, JointKey), SecondRoundError> {
        assert_eq!(secret_shares.len(), dkg.joint_key.verification_shares.len());
        let mut total_secret_share = s!(0);
        for (i, (secret_share, poly)) in secret_shares.iter().zip(&dkg.point_polys).enumerate() {
            let expected_public_share = poly.eval((my_index + 1) as u32);
            if g!(secret_share * G) != expected_public_share {
                return Err(SecondRoundError::InvalidShare(i));
            }
            let (verification_key, _) = poly.0[0].into_point_with_even_y();

            total_secret_share = s!(total_secret_share + secret_share);
        }

        let total_secret_share = total_secret_share.expect_nonzero(
            "since verification shares are non-zero, corresponding secret shares cannot be zero",
        );

        Ok((total_secret_share, dkg.joint_key))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignSession {}

impl<H: Digest<OutputSize = U32> + Clone, NG> Frost<Schnorr<H, NG>> {
    pub fn start_sign_session(
        &self,
        joint_key: &JointKey,
        nonces: &[(usize, Nonce)],
        message: Message,
    ) -> SignSession {
        // make sure no duplicats in nonces somehow
        assert_eq!(joint_key.threshold, nonces.len());
        todo!()
    }

    pub fn sign(
        &self,
        joint_key: &JointKey,
        session: &SignSession,
        my_index: usize,
        secret_share: &Scalar,
        secret_nonces: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        todo!()
    }

    #[must_use]
    pub fn verify_signature_share(
        &self,
        joint_key: &JointKey,
        session: &SignSession,
        index: usize,
        signature_share: Scalar<Public, Zero>,
    ) -> bool {
        todo!()
    }

    pub fn combine_signature_shares(
        &self,
        joint_key: &JointKey,
        session: &SignSession,
        partial_sigs: &[Scalar<Public, Zero>],
    ) -> Signature {
        todo!()
    }
}

impl<H: Digest<OutputSize = U32> + Clone, NG: NonceGen> Frost<Schnorr<H, NG>> {
    pub fn gen_nonce(
        &self,
        joint_key: &JointKey,
        my_index: usize,
        secret_share: &Scalar,
        sid: &[u8],
    ) -> NonceKeyPair {
        let r1 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret_share,
            public => [ b"r1-frost", my_index.to_be_bytes(), joint_key.joint_public_key, &joint_key.verification_shares[..], sid]
        );
        let r2 = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => secret_share,
            public => [ b"r2-frost", my_index.to_be_bytes(), joint_key.joint_public_key, &joint_key.verification_shares[..], sid]
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
    use super::*;

    use secp256kfun::{nonce::Deterministic, proptest::prelude::*};
    use sha2::Sha256;

    #[test]
    fn frost_test_end_to_end() {
        let sp1 = ScalarPoly::new(vec![s!(3), s!(7)]);
        let sp2 = ScalarPoly::new(vec![s!(11), s!(13)]);
        let sp3 = ScalarPoly::new(vec![s!(17), s!(19)]);
        let frost = Frost::<Schnorr<Sha256, Deterministic<Sha256>>>::default();
        let point_polys = vec![
            sp1.to_point_poly(),
            sp2.to_point_poly(),
            sp3.to_point_poly(),
        ];

        let dkg = frost.collect_polys(point_polys).unwrap();
        let shares1 = frost.create_shares(&dkg, sp1);
        let shares2 = frost.create_shares(&dkg, sp2);
        let shares3 = frost.create_shares(&dkg, sp3);

        let (secret_share1, joint_key) = frost
            .collect_shares(
                dkg.clone(),
                0,
                vec![shares1[0].clone(), shares2[0].clone(), shares3[0].clone()],
            )
            .unwrap();
        let (secret_share2, jk2) = frost
            .collect_shares(
                dkg.clone(),
                1,
                vec![shares1[1].clone(), shares2[1].clone(), shares3[1].clone()],
            )
            .unwrap();
        let (secret_share3, jk3) = frost
            .collect_shares(
                dkg.clone(),
                2,
                vec![shares1[2].clone(), shares2[2].clone(), shares3[2].clone()],
            )
            .unwrap();

        assert_eq!(joint_key, jk2);
        assert_eq!(joint_key, jk3);

        let nonce1 = frost.gen_nonce(&joint_key, 0, &secret_share1, b"test");
        let nonce3 = frost.gen_nonce(&joint_key, 2, &secret_share3, b"test");
        let nonces = [(0, nonce1.public()), (2, nonce3.public())];

        let session =
            frost.start_sign_session(&joint_key, &nonces, Message::plain("test", b"test"));

        {
            let session2 = frost.start_sign_session(&jk2, &nonces, Message::plain("test", b"test"));
            assert_eq!(session2, session);
        }

        let sig1 = frost.sign(&joint_key, &session, 0, &secret_share1, nonce1);
        let sig3 = frost.sign(&joint_key, &session, 2, &secret_share3, nonce3);

        assert!(frost.verify_signature_share(&joint_key, &session, 0, sig1));
        assert!(frost.verify_signature_share(&joint_key, &session, 2, sig3));
        let combined_sig = frost.combine_signature_shares(&joint_key, &session, &[sig1, sig3]);

        assert!(frost.schnorr.verify(
            &joint_key.joint_public_key,
            Message::<Public>::plain("test", b"test"),
            &combined_sig
        ));
    }
}
