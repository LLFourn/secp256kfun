//! Cross curve proof of Discrete Log equality between secp256k1 and ed25519
//!
//! Here "equality" means the two secret scalars have the same 252-bit representaion.
use crate::{
    ed25519,
    or::Either,
    secp256k1,
    secp256k1::fun::{
        g,
        marker::*,
        rand_core::{CryptoRng, RngCore},
        s, Point as PointP, Scalar as ScalarP, G as GP,
    },
    All, And, Eq, FiatShamir, Or, Sigma, Transcript,
};
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint as PointQ, scalar::Scalar as ScalarQ,
    traits::Identity,
};
use generic_array::typenum::{U252, U31};
static GQ: &'static curve25519_dalek::edwards::EdwardsBasepointTable = &ED25519_BASEPOINT_TABLE;

/// The underlying proof algorithm we'll be using to prove the relationship between the commitments and the keys.
type CoreProof = And<
    All<
        U252, // For each of the 252 bits of the secret key
        // We show that both commitments are a commitment to zero OR to 2^i for i = 0..252
        Or<
            And<secp256k1::DLBP<U31>, ed25519::DLBP<U31>>,
            And<secp256k1::DLBP<U31>, ed25519::DLBP<U31>>,
        >,
    >,
    // Finally we prove the result of the addition of the commitments is the same as the ones calimed
    // i.e. if the commitmens add up to xH, we show that X = xG.
    And<Eq<secp256k1::DLBP<U31>, secp256k1::DL<U31>>, Eq<ed25519::DLBP<U31>, ed25519::DL<U31>>>,
>;
const COMMITMENT_BITS: usize = 252;

#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Debug, Clone, PartialEq)]
pub struct CrossCurveDLEQProof {
    claim: (PointP, PointQ),
    sum_blindings: (ScalarP<Public, Zero>, ScalarQ),
    commitments: Vec<(PointP, PointQ)>,
    proof: crate::CompactProof<CoreProof>,
}

pub struct CrossCurveDLEQ<T> {
    HQ: PointQ,
    HP: PointP,
    core_proof_system: FiatShamir<CoreProof, T>,
    powers_of_two: Vec<(PointP, PointQ)>,
}

impl<T: Transcript<CoreProof>> CrossCurveDLEQ<T> {
    pub fn new(HP: PointP, HQ: PointQ) -> Self {
        let powers_of_two = core::iter::successors(Some((HP.clone(), HQ.clone())), |(H2P, H2Q)| {
            // compute 2^i * H for i = 0..252 by successively adding the result of the last addition
            Some((
                g!(H2P + H2P).mark::<(Normal, NonZero)>().unwrap(),
                (H2Q + H2Q),
            ))
        })
        .take(COMMITMENT_BITS)
        .collect();

        Self {
            HP,
            HQ,
            core_proof_system: FiatShamir::new(CoreProof::default()),
            powers_of_two,
        }
    }

    /// Generates the two corresponding points for the same 252-bit ed25519
    /// secret and generates a proof that they have the same discrete logarithm.
    ///
    /// # Panics
    ///
    /// - If the secret is larger than 2^253 -1
    /// - If the secret is 0
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
                .expect("will never overflow since ed25519 order is lower")
                .mark::<NonZero>()
                .expect("must not be zero")
        };

        let claim = (g!(secp_secret * GP).mark::<Normal>(), secret * GQ);

        let pedersen_blindings = (0..COMMITMENT_BITS)
            .map(|_| (ScalarP::random(rng), ScalarQ::random(rng)))
            .collect::<Vec<_>>();

        let sum_blindings = pedersen_blindings.iter().fold(
            (ScalarP::zero(), ScalarQ::zero()),
            |(accP, accQ), (rP, rQ)| (s!(accP + rP), accQ + rQ),
        );
        let sum_blindings = (sum_blindings.0.mark::<Public>(), sum_blindings.1);

        let bits = to_bits(secret);

        let commitments = self
            .powers_of_two
            .iter()
            .zip(bits.iter())
            .zip(pedersen_blindings.iter())
            .map(|(((H2P, H2Q), bit), (rP, rQ))| {
                let zero_commit_p = g!(rP * GP).mark::<Secret>();
                let one_commit_p = g!(zero_commit_p + H2P)
                    .mark::<NonZero>()
                    .expect("computationally unreachable since zero_comit_p is random");
                let zero_commit_q = rQ * GQ;
                let one_commit_q = &zero_commit_q + H2Q;

                //TODO: constant time choice
                match bit {
                    false => (zero_commit_p.mark::<(Public, Normal)>(), zero_commit_q),
                    true => (one_commit_p.mark::<Normal>(), one_commit_q),
                }
            })
            .collect::<Vec<_>>();

        let statement = self
            .generate_statement(&sum_blindings, &claim, &commitments[..])
            .expect("statement will be valid since we genreated it ourself");

        let proof_witness = (
            pedersen_blindings
                .into_iter()
                .zip(bits.iter())
                .map(|((rP, rQ), bit)| match bit {
                    false => Either::Left((rP, rQ)),
                    true => Either::Right((rP, rQ)),
                })
                .collect(),
            (secp_secret, secret.clone()),
        );

        let proof = self
            .core_proof_system
            .prove(&proof_witness, &statement, rng);

        CrossCurveDLEQProof {
            claim,
            sum_blindings,
            commitments,
            proof,
        }
    }

    /// Genrates the statement for the core proof from the commitments
    fn generate_statement(
        &self,
        (rP, rQ): &(ScalarP<Public, Zero>, ScalarQ),
        (XP, XQ): &(PointP, PointQ),
        commitments: &[(PointP, PointQ)],
    ) -> Option<<CoreProof as Sigma>::Statement> {
        let commitment_statement = self
            .powers_of_two
            .iter()
            .zip(commitments)
            .map(|((H2P, H2Q), (CP, CQ))| {
                // This goes first since we bail if it's zero
                g!(CP - H2P).mark::<(Normal, NonZero)>().map(|CP_sub_H2P| {
                    (
                        // represents the claim the commitment is equal to 0
                        (CP.clone(), CQ.clone()),
                        // represents the claim the commitment is equal 2^i
                        (CP_sub_H2P, CQ - H2Q),
                    )
                })
            })
            .collect::<Option<Vec<_>>>()?;

        let (sumP, sumQ) = commitments.iter().fold(
            (PointP::zero().mark::<Jacobian>(), PointQ::identity()),
            |(accP, accQ), (CP, CQ)| (g!(accP + CP), accQ + CQ),
        );

        let unblindedP = g!(sumP - rP * GP).mark::<(Normal, NonZero)>()?;
        let unblindedQ = sumQ - rQ * GQ;

        let dleq_G_to_H = (
            (XP.clone(), (self.HP.clone(), unblindedP)),
            (XQ.clone(), (self.HQ, unblindedQ)),
        );

        Some((commitment_statement, dleq_G_to_H))
    }

    #[must_use]
    pub fn verify(&self, proof: &CrossCurveDLEQProof) -> bool {
        // Make sure the claimed ed25519 key is in the prime-order subgroup
        if proof.commitments.len() != COMMITMENT_BITS || !proof.claim.1.is_torsion_free() {
            return false;
        }
        let statement =
            self.generate_statement(&proof.sum_blindings, &proof.claim, &proof.commitments);
        match statement {
            Some(statement) => self.core_proof_system.verify(&statement, &proof.proof),
            None => false,
        }
    }
}

fn to_bits(secret_key: &ScalarQ) -> [bool; COMMITMENT_BITS] {
    let bytes = secret_key.as_bytes();
    let mut bits = [false; COMMITMENT_BITS];
    let mut index = 0;
    for i in 0..32 {
        for j in 0..8 {
            bits[index + j] = (bytes[i] & (1 << j)) != 0;
            // we skip the bits above 252
            if i == 31 && j == 3 {
                break;
            }
        }
        index += 8;
    }
    bits
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        ed25519::proptest::{ed25519_point, ed25519_scalar},
        secp256k1::fun::proptest::point as secp256k1_point,
    };
    use ::proptest::prelude::*;
    use sha2::Sha256;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn dl_secp256k1_ed25519_eq(
            secret in ed25519_scalar(),
            HP in secp256k1_point(),
            HQ in ed25519_point(),
        ) {
            let proof_system = CrossCurveDLEQ::<Sha256>::new(HP, HQ);
            let proof = proof_system.prove(&secret, &mut rand::thread_rng());
            assert!(proof_system.verify(&proof));
        }
    }

    #[cfg(feature = "serde")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn serialization_roundtrip(
            secret in ed25519_scalar(),
            HP in secp256k1_point(),
            HQ in ed25519_point(),
        ) {
            let proof_system = CrossCurveDLEQ::<Sha256>::new(HP, HQ);
            let proof = proof_system.prove(&secret, &mut rand::thread_rng());

            let proof_serialized = bincode::serialize(&proof).unwrap();
            let proof_deserialized: CrossCurveDLEQProof =
                bincode::deserialize(&proof_serialized).unwrap();

            assert_eq!(proof_deserialized, proof);
        }
    }
}
