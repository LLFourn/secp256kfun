use crate::{
    ed25519,
    or::Either,
    secp256k1,
    secp256k1::fun::{
        self, g,
        marker::*,
        rand_core::{CryptoRng, RngCore},
        s, Point as PointP, Scalar as ScalarP,
    },
    All, And, Eq, FiatShamir, Or, Sigma, Transcript,
};
use curve25519_dalek::{
    edwards::EdwardsPoint as PointQ, scalar::Scalar as ScalarQ, traits::Identity,
};
use generic_array::{
    functional::FunctionalSequence,
    typenum::{U2, U252, U31},
    GenericArray,
};

type SubProof = And<
    And<Eq<U2, secp256k1::DL<U31>>, Eq<U2, ed25519::DL<U31>>>,
    All<
        U252,
        Or<
            And<secp256k1::DLBP<U31>, ed25519::DLBP<U31>>,
            And<secp256k1::DLBP<U31>, ed25519::DLBP<U31>>,
        >,
    >,
>;

pub struct CrossCurveDLEQProof {
    claim: (PointP, PointQ),
    sum_blindings: (ScalarP<Public, Zero>, ScalarQ),
    commitments: Box<GenericArray<(PointP, PointQ), U252>>,
    proof: crate::CompactProof<SubProof>,
}

pub struct CrossCurveDLEQ<T> {
    HQ: PointQ,
    HP: PointP,
    proof_system: FiatShamir<SubProof, T>,
    powers_of_two: Box<GenericArray<(usize, PointP, PointQ), U252>>,
}

static GQ: &'static curve25519_dalek::edwards::EdwardsBasepointTable =
    &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use fun::G as GP;

impl<T: Transcript<SubProof>> CrossCurveDLEQ<T> {
    pub fn new(HP: PointP, HQ: PointQ) -> Self {
        let indexes = GenericArray::<usize, U252>::from_exact_iter(0..252).unwrap();
        let powers_of_two = indexes.map(|i| {
            let mut bytes = [0u8; 32];
            bytes[i / 8] = 1 << ((i as u8) % 8);
            let powP = ScalarP::from_bytes(bytes)
                .unwrap()
                .mark::<NonZero>()
                .unwrap();
            let powQ = ScalarQ::from_canonical_bytes(bytes).unwrap();
            (i, g!(powP * HP).mark::<Normal>(), powQ * HQ)
        });

        let proof_system = FiatShamir::new(SubProof::default());

        Self {
            HP,
            HQ,
            proof_system,
            powers_of_two: Box::new(powers_of_two),
        }
    }

    pub fn prove(
        &self,
        secret: &ScalarQ,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> CrossCurveDLEQProof {
        // Must be a 252 bit ed25519 key
        assert!(secret.as_bytes()[31] & 0x20 == 0);

        let secp_secret = {
            let mut bytes = secret.to_bytes();
            bytes.reverse();
            ScalarP::from_bytes(bytes)
                .expect("must not overflow")
                .mark::<NonZero>()
                .expect("must not be zero")
        };

        let claim = (g!(secp_secret * GP).mark::<Normal>(), secret * GQ);

        let pedersen_blindings = Box::new((&*self.powers_of_two).map(|_| {
            let rP = ScalarP::random(rng);
            let rQ = ScalarQ::random(rng);
            (rP, rQ)
        }));

        let sum_blindings = pedersen_blindings.as_slice().iter().fold(
            (ScalarP::zero(), ScalarQ::zero()),
            |(accP, accQ), (rP, rQ)| (s!(accP + rP), accQ + rQ),
        );
        let sum_blindings = (sum_blindings.0.mark::<Public>(), sum_blindings.1);

        let bits = to_bits(secret);

        let commitments = Box::new((&*self.powers_of_two).zip(*bits, |(i, H2P, H2Q), bit| {
            let (rP, rQ) = &pedersen_blindings[*i];
            let zero_commit_p = g!(rP * GP).mark::<Secret>();
            let one_commit_p = g!(zero_commit_p + H2P).mark::<NonZero>().unwrap();
            let zero_commit_q = rQ * GQ;
            let one_commit_q = &zero_commit_q + H2Q;

            //TODO: constant time choice
            match bit {
                false => (zero_commit_p.mark::<(Public, Normal)>(), zero_commit_q),
                true => (one_commit_p.mark::<Normal>(), one_commit_q),
            }
        }));


        let statement = Box::new(self
            .generate_statement(&sum_blindings, &claim, &commitments)
            .expect("we generated these ourself so your statement will be valid"));

        let proof_witness = Self::get_witness((secp_secret, secret.clone()), pedersen_blindings, bits);

        let proof = self.proof_system.prove(
            &*proof_witness,
            &*statement,
            rng,
        );

        CrossCurveDLEQProof {
            claim,
            sum_blindings,
            commitments,
            proof,
        }
       
      //  unimplemented!()
    }

    fn get_witness(claim_secret: (ScalarP, ScalarQ), blindings: Box<GenericArray<(ScalarP, ScalarQ), U252>>, bits: Box<GenericArray<bool, U252>>) -> Box<<SubProof as Sigma>::Witness> {
        let blindings_witness = blindings.zip(*bits, |(rP, rQ), bit| match bit {
            false => Either::Left((rP, rQ)),
            true => Either::Right((rP, rQ)),
        });
        Box::new((
            claim_secret,
            blindings_witness,
        ))
    }

    fn generate_statement(
        &self,
        (rP, rQ): &(ScalarP<Public, Zero>, ScalarQ),
        (XP, XQ): &(PointP, PointQ),
        commitments: &GenericArray<(PointP, PointQ), U252>,
    ) -> Option<Box<<SubProof as Sigma>::Statement>> {
        let commitment_statement =
            Box::new((&*self.powers_of_two).map(|(i, H2P, H2Q)| {
                let (CP,CQ) = &commitments[*i];
                (
                    // represents the claim the commitment is equal to 0
                    (CP.clone(), CQ.clone()),
                    // represents the claim the commitment is equal 2^i
                    // TODO: Remove unwrap
                    (g!(CP - H2P).mark::<(Normal, NonZero)>().unwrap(), CQ - H2Q),
                )
            }));

        let (sumP, sumQ) = commitments.as_slice().iter().fold(
            (PointP::zero().mark::<Jacobian>(), PointQ::identity()),
            |(accP, accQ), (CP, CQ)| (g!(accP + CP), accQ + CQ),
        );

        let unblindedP = g!(sumP - rP * GP);
        let unblindedQ = sumQ - rQ * GQ;

        let unblindedP = unblindedP.mark::<(Normal, NonZero)>()?;

        let dleq_G_to_H = (
            GenericArray::from([
                (GP.clone().mark::<Normal>(), XP.clone()),
                (self.HP.clone(), unblindedP),
            ]),
            GenericArray::from([(GQ.basepoint(), XQ.clone()), (self.HQ, unblindedQ)]),
        );

        Some(Box::new((dleq_G_to_H, *commitment_statement)))
    }

    #[must_use]
    pub fn verify(&self, proof: &CrossCurveDLEQProof) -> bool {
        let statement =
            self.generate_statement(&proof.sum_blindings, &proof.claim, &proof.commitments);
        match statement {
            Some(statement) => self.proof_system.verify(&statement, &proof.proof),
            None => false,
        }
    }
}

fn to_bits(secret_key: &ScalarQ) -> Box<GenericArray<bool, U252>> {
    let bytes = secret_key.as_bytes();
    let mut bits = GenericArray::<bool, U252>::default();
    let mut index = 0;
    for i in 0..32 {
        for j in 0..8 {
            bits[index + j] = (bytes[i] & (1 << j)) != 0;
            // early exit
            if i == 31 && j == 3 {
                break;
            }
        }
        index += 8;
    }
    Box::new(bits)
}
#[cfg(test)]
mod test {
        use sha2::Sha256;

use super::*;

    #[test]
    fn testtest() {
        let secret = ScalarQ::from(42u64);
        let HP = PointP::random(&mut rand::thread_rng());
        let HQ = &ScalarQ::random(&mut rand::thread_rng()) * GQ;
        let proof_system = CrossCurveDLEQ::<Sha256>::new(HP, HQ);
        let proof = proof_system.prove(&secret, &mut rand::thread_rng());
        assert!(proof_system.verify(&proof));
    }
}
