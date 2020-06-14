use crate::fun::{
    derive_nonce, g,
    hash::{tagged_hash, Derivation, Hash, NonceHash},
    marker::*,
    s, Point, Scalar,
};
use digest::{generic_array::typenum::U32, Digest};

pub struct DLEQ<CH, N> {
    pub challenge_hash: CH,
    pub nonce_hash: N,
}

impl DLEQ<sha2::Sha256, NonceHash<sha2::Sha256>> {
    pub fn from_tag(tag: &[u8]) -> Self {
        DLEQ {
            challenge_hash: tagged_hash(&[tag, b"/challenge"].concat()),
            nonce_hash: NonceHash::from_tag(tag),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
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

impl<CH, NH> DLEQ<CH, NonceHash<NH>>
where
    CH: Digest<OutputSize = U32> + Clone,
    NH: Digest<OutputSize = U32> + Clone,
{
    pub fn prove_guaranteed(
        &self,
        x: &Scalar,
        G: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
        nonce: Derivation,
    ) -> (Proof, Point, Point) {
        let xG = g!(x * G).mark::<Normal>();
        let xH = g!(x * H).mark::<Normal>();
        (self.prove(x, G, &xG, H, &xH, nonce), xG, xH)
    }

    pub fn prove(
        &self,
        x: &Scalar,
        G: &Point<impl Normalized, impl Secrecy>,
        xG: &Point<impl Normalized, impl Secrecy>,
        H: &Point<impl Normalized, impl Secrecy>,
        xH: &Point<impl Normalized, impl Secrecy>,
        derivation: Derivation,
    ) -> Proof {
        let r = derive_nonce!(
            nonce_hash => self.nonce_hash,
            derivation => derivation,
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

impl<CH: Digest<OutputSize = U32> + Clone, NH> DLEQ<CH, NH> {
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
    use secp256kfun::G;

    #[test]
    fn prove_verify() {
        let dleq = DLEQ::from_tag(b"test");
        let x = Scalar::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let (proof, xG, xH) = dleq.prove_guaranteed(&x, &G, &H, Derivation::Deterministic);
        assert!(dleq.verify(&G, &xG, &H, &xH, &proof));
    }

    #[test]
    fn prove_bogus() {
        let dleq = DLEQ::from_tag(b"test");
        let x = Scalar::random(&mut rand::thread_rng());
        let xG = Point::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let xH = Point::random(&mut rand::thread_rng());
        let bogus_proof = dleq.prove(&x, &G, &xG, &H, &xH, Derivation::Deterministic);

        assert!(!dleq.verify(&G, &xG, &H, &xH, &bogus_proof));
    }

    #[cfg(feature = "serialization")]
    #[test]
    fn dleq_proof_serialize_roundtrip() {
        let dleq = DLEQ::from_tag(b"test");
        let x = Scalar::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());
        let (proof, ..) = dleq.prove_guaranteed(&x, &G, &H, Derivation::Deterministic);
        let serialized = bincode::serialize(&proof).unwrap();
        assert_eq!(serialized.len(), 64);
        let deserialized = bincode::deserialize::<Proof<Public>>(&serialized[..]).unwrap();
        assert_eq!(proof, deserialized);
    }
}
