use crate::fun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::{AddTag, HashAdd, Tagged},
    marker::*,
    nonce::{NonceChallengeBundle, NonceGen},
    s, Point, Scalar,
};

#[derive(Debug, Clone)]
pub struct DLEQ<H, NG> {
    nonce_challenge_bundle: NonceChallengeBundle<H, NG>,
}

impl<H: Tagged, NG: AddTag + Default> Default for DLEQ<H, NG> {
    fn default() -> Self {
        Self::new(NG::default())
    }
}

impl<H: Tagged, NG: AddTag> DLEQ<H, NG> {
    pub fn new(nonce_gen: NG) -> Self {
        DLEQ {
            nonce_challenge_bundle: NonceChallengeBundle {
                challenge_hash: H::default(),
                nonce_gen,
            }
            .add_protocol_tag("DLEQ"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
pub struct Proof<S = Public> {
    pub challenge: Scalar<S, Zero>,
    pub response: Scalar<S, Zero>,
}

impl Proof {
    pub fn as_tuple(&self) -> (&Scalar<Public, Zero>, &Scalar<Public, Zero>) {
        (&self.challenge, &self.response)
    }
}

impl<CH, NG> DLEQ<CH, NG>
where
    CH: Digest<OutputSize = U32> + Clone,
    NG: NonceGen,
{
    pub fn prove_guaranteed(
        &self,
        x: &Scalar,
        G: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
    ) -> (Proof, Point, Point) {
        let xG = g!(x * G).mark::<Normal>();
        let xH = g!(x * H).mark::<Normal>();
        (self.prove(x, G, &xG, H, &xH), xG, xH)
    }

    pub fn prove(
        &self,
        x: &Scalar,
        G: &Point<impl Normalized, impl Secrecy>,
        xG: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
        xH: &Point<impl Normalized, impl Secrecy>,
    ) -> Proof {
        let r = derive_nonce!(
            nonce_gen => self.nonce_challenge_bundle.nonce_gen,
            secret => x,
            public => [G, xG, H, xH]
        );

        let rG = g!(r * G).mark::<Normal>();
        let rH = g!(r * H).mark::<Normal>();

        let c = self.challenge(&rG, &rH, G, xG, H, xH);
        let s = s!(r + c * x).mark::<Public>();

        Proof {
            response: s,
            challenge: c,
        }
    }
}

impl<CH: Digest<OutputSize = U32> + Clone, NG> DLEQ<CH, NG> {
    #[must_use]
    pub fn verify(
        &self,
        G: &Point<impl Normalized, impl Secrecy>,
        xG: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
        xH: &Point<impl Normalized, impl Secrecy>,
        proof: &Proof,
    ) -> bool {
        let (c, s) = proof.as_tuple();
        let minus_c = -c;

        let rG = g!(s * G + minus_c * xG);
        let rH = g!(s * H + minus_c * xH);

        match (
            rG.mark::<(Normal, NonZero)>(),
            rH.mark::<(Normal, NonZero)>(),
        ) {
            (Some(rG), Some(rH)) => {
                let implied_c = self.challenge(&rG, &rH, G, xG, H, xH);

                &implied_c == c
            }
            _ => false,
        }
    }

    fn challenge(
        &self,
        rG: &Point<impl Normalized, impl Secrecy>,
        rH: &Point<impl Normalized, impl Secrecy>,
        G: &Point<impl Normalized, impl Secrecy>,
        xG: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
        xH: &Point<impl Normalized, impl Secrecy>,
    ) -> Scalar<Public, Zero> {
        let hash = self
            .nonce_challenge_bundle
            .challenge_hash
            .clone()
            .add(rG)
            .add(rH)
            .add(G)
            .add(xG)
            .add(H)
            .add(xH);
        Scalar::from_hash(hash).mark::<(Public, Zero)>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{fun::G, nonce};
    use sha2::Sha256;

    macro_rules! dleq_test_instance {
        () => {
            DLEQ::<Sha256, _>::new(nonce::Deterministic::<Sha256>::default())
        };
    }

    #[test]
    fn prove_verify() {
        let dleq = dleq_test_instance!();
        let x = Scalar::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let (proof, xG, xH) = dleq.prove_guaranteed(&x, &G, &H);
        assert!(dleq.verify(&G, &xG, &H, &xH, &proof));
    }

    #[test]
    fn prove_bogus() {
        let dleq = dleq_test_instance!();
        let x = Scalar::random(&mut rand::thread_rng());
        let xG = Point::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let xH = Point::random(&mut rand::thread_rng());
        let bogus_proof = dleq.prove(&x, &G, &xG, &H, &xH);

        assert!(!dleq.verify(&G, &xG, &H, &xH, &bogus_proof));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn dleq_proof_serialize_roundtrip() {
        let dleq = dleq_test_instance!();
        let x = Scalar::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let (proof, ..) = dleq.prove_guaranteed(&x, &G, &H);
        let serialized = bincode::serialize(&proof).unwrap();
        assert_eq!(serialized.len(), 64);
        let deserialized = bincode::deserialize::<Proof<Public>>(&serialized[..]).unwrap();
        assert_eq!(proof, deserialized);
    }
}
