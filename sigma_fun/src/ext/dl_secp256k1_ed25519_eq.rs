//! Cross curve proof of Discrete Log equality between secp256k1 and ed25519.
//!
//!
//! Here "equality" means the two secret scalars have the same 252-bit representaion. To prove they
//! have the same representation we make two sets of 252 pedersen commiments and show that:
//!
//! 1. For i=0..252 we show the ith commitment is either to 0 or 2^i
//! 2. That the commiments are the same value for both sets.
//! 3. The sum of the commitments equals to the claimed public keys on each curve.
//!
//! [`CrossCurveDLEQ`] is the main prover/verifier.
//! The underlying Sigma protocol it uses is in [`CoreProof`].
//!
//! This was partially inspired by [MRL-0010] but it re-imagines it as a Sigma protocol.
//!
//! # Example
//!
//! [MRL-0010]: https://web.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf
use crate::{
    ed25519,
    or::Either,
    secp256k1,
    secp256k1::fun::{
        g,
        marker::*,
        rand_core::{CryptoRng, RngCore},
        s,
        subtle::{self, ConditionallySelectable},
        Point as PointP, Scalar as ScalarP, G as GP,
    },
    All, And, Eq, FiatShamir, Or, ProverTranscript, Sigma, Transcript,
};
use alloc::vec::Vec;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint as PointQ, scalar::Scalar as ScalarQ,
    traits::Identity,
};
use generic_array::typenum::{U252, U31};
static GQ: &'static curve25519_dalek::edwards::EdwardsBasepointTable = &ED25519_BASEPOINT_TABLE;

/// The underlying sigma protocol we will use to prove the relationship between the two sets of commitments.
///
/// We are trying to prove that `X_p = x * G_p` and `X_q = x * G_q`. The approach is
/// to split x into two sets of 252 bit pedersen commitments for each curve and prove that the
/// corresponding commitments commit to the same bit.
//
/// Note the commitments are in the form commit(b) = r * G + b* H where G is the standard basepoint
/// for each curve.
pub type CoreProof = And<
    All<
        // For each of the 252 bits of the secret key
        // We show that both commitments are a commitment to zero OR to 2^i for i = 0..252
        Or<
            And<secp256k1::DLG<U31>, ed25519::DLG<U31>>,
            And<secp256k1::DLG<U31>, ed25519::DLG<U31>>,
        >,
        U252,
    >,
    // Finally we do two DLEQ proofs to show that if the commitmens add up to xH_p and xH_q, we show
    // that X_p = xG_p and X_q = xG_q.
    And<Eq<secp256k1::DLG<U31>, secp256k1::DL<U31>>, Eq<ed25519::DLG<U31>, ed25519::DL<U31>>>,
>;
const COMMITMENT_BITS: usize = 252;

/// The proof the a public key on secp256k1 and ed25519 have the same 252-bit secret key.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CrossCurveDLEQProof {
    /// The sum of the Pedersen blindings
    pub sum_blindings: (ScalarP<Public, Zero>, ScalarQ),
    /// The 252 pairs of commitments
    pub commitments: Vec<(PointP, PointQ)>,
    /// The core proof which shows the pairs of commitments commit to the same bit and the resulting
    /// sum is the claimed points.
    pub proof: crate::CompactProof<CoreProof>,
}

/// The proof system which prepares the high level statement to be proved/verified with
/// [`CoreProof`].
#[derive(Debug, Clone)]
pub struct CrossCurveDLEQ<T> {
    HQ: PointQ,
    HP: PointP,
    core_proof_system: FiatShamir<CoreProof, T>,
    powers_of_two: Vec<(PointP, PointQ)>,
}

impl<T: Transcript<CoreProof> + Default> CrossCurveDLEQ<T> {
    /// Creates a new prover given the the additional point to be used inthe Pedersen commitment for each curve.
    pub fn new(HP: PointP, HQ: PointQ) -> Self {
        let powers_of_two = core::iter::successors(Some((HP.clone(), HQ.clone())), |(H2P, H2Q)| {
            // compute 2^i * H for i = 0..252 by successively adding the result of the last addition
            Some((
                g!(H2P + H2P)
                    .normalize()
                    .non_zero()
                    .expect("power of two addition"),
                (H2Q + H2Q),
            ))
        })
        .take(COMMITMENT_BITS)
        .collect();

        Self {
            HP,
            HQ,
            core_proof_system: FiatShamir::<CoreProof, T>::default(),
            powers_of_two,
        }
    }

    /// Generates the two corresponding points for the same 252-bit ed25519
    /// secret and generates a proof that they have the same discrete logarithm.
    ///
    /// Returns the proof and the two points that form the equality claim.
    ///
    /// # Panics
    ///
    /// - If the secret is larger than 2^253 -1
    /// - If the secret is 0
    pub fn prove(
        &self,
        secret: &ScalarQ,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> (CrossCurveDLEQProof, (PointP, PointQ))
    where
        T: ProverTranscript<CoreProof>,
    {
        // Must be a 252 bit ed25519 key i.e. must not have it's 253rd bit set
        assert!(secret.as_bytes()[31] & 0b00010000 == 0);

        let secp_secret = {
            let mut bytes = secret.to_bytes();
            // secp256kfun interprets scalars as big endian
            bytes.reverse();
            ScalarP::from_bytes(bytes)
                .expect("will never overflow since ed25519 order is lower")
                .non_zero()
                .expect("must not be zero")
        };

        let claim = (g!(secp_secret * GP).normalize(), secret * GQ);

        let pedersen_blindings = (0..COMMITMENT_BITS)
            .map(|_| (ScalarP::random(rng), ScalarQ::random(rng)))
            .collect::<Vec<_>>();

        let sum_blindings = pedersen_blindings.iter().fold(
            (ScalarP::zero(), ScalarQ::zero()),
            |(accP, accQ), (rP, rQ)| (s!(accP + rP), accQ + rQ),
        );
        let sum_blindings = (sum_blindings.0.public(), sum_blindings.1);

        let bits = to_bits(secret);

        let commitments = self
            .powers_of_two
            .iter()
            .zip(bits.iter())
            .zip(pedersen_blindings.iter())
            .map(|(((H2P, H2Q), bit), (rP, rQ))| {
                let zero_commit_p = g!(rP * GP);
                let one_commit_p = g!(zero_commit_p + H2P)
                    .non_zero()
                    .expect("computationally unreachable since zero_comit_p is random");

                let zero_commit_q = rQ * GQ;
                let one_commit_q = &zero_commit_q + H2Q;

                // Make sure to do a constant time choice here
                let bit = subtle::Choice::from(*bit as u8);
                (
                    PointP::conditional_select(
                        &zero_commit_p.normalize(),
                        &one_commit_p.normalize(),
                        bit,
                    ),
                    PointQ::conditional_select(&zero_commit_q, &one_commit_q, bit),
                )
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
            .prove(&proof_witness, &statement, Some(rng));

        (
            CrossCurveDLEQProof {
                sum_blindings,
                commitments,
                proof,
            },
            claim,
        )
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
                g!(CP - H2P).normalize().non_zero().map(|CP_sub_H2P| {
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
            (PointP::zero(), PointQ::identity()),
            |(accP, accQ), (CP, CQ)| (g!(accP + CP), accQ + CQ),
        );

        let unblindedP = g!(sumP - rP * GP).normalize().non_zero()?;
        let unblindedQ = sumQ - rQ * GQ;

        let dleq_G_to_H = (
            (XP.clone(), (self.HP.clone(), unblindedP)),
            (XQ.clone(), (self.HQ, unblindedQ)),
        );

        Some((commitment_statement, dleq_G_to_H))
    }

    #[must_use]
    /// Verify the claimed points have the same 252-bit discrete logarithm
    pub fn verify(&self, proof: &CrossCurveDLEQProof, claim: (PointP, PointQ)) -> bool {
        // Make sure the claimed ed25519 key is in the prime-order subgroup
        if proof.commitments.len() != COMMITMENT_BITS || !claim.1.is_torsion_free() {
            return false;
        }
        let statement = self.generate_statement(&proof.sum_blindings, &claim, &proof.commitments);
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
        ed25519::test::{ed25519_point, ed25519_scalar},
        HashTranscript,
    };
    use ::proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use sha2::Sha256;
    type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

    #[test]
    #[should_panic]
    /// We can't handle 253 bit scalars
    fn high_scalar_should_panic() {
        let high_scalar = -ScalarQ::one();
        let HP = PointP::random(&mut rand::thread_rng());
        let HQ = &ScalarQ::random(&mut rand::thread_rng()) * &ED25519_BASEPOINT_TABLE;
        let proof_system = CrossCurveDLEQ::<Transcript>::new(HP, HQ);
        let _ = proof_system.prove(&high_scalar, &mut rand::thread_rng());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]
        #[test]
        fn dl_secp256k1_ed25519_eq(
            secret in ed25519_scalar(),
            HP in any::<PointP>(),
            HQ in ed25519_point(),
        ) {
            let proof_system = CrossCurveDLEQ::<Transcript>::new(HP, HQ);
            let (proof, claim) = proof_system.prove(&secret, &mut rand::thread_rng());
            assert!(proof_system.verify(&proof, claim));
        }
    }

    #[cfg(feature = "serde")]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(3))]
        #[test]
        fn serialization_roundtrip(
            secret in ed25519_scalar(),
            HP in any::<PointP>(),
            HQ in ed25519_point(),
        ) {
            let proof_system = CrossCurveDLEQ::<Transcript>::new(HP, HQ);
            let (proof, _) = proof_system.prove(&secret, &mut rand::thread_rng());

            let proof_serialized = bincode::serialize(&proof).unwrap();
            let proof_deserialized: CrossCurveDLEQProof =
                bincode::deserialize(&proof_serialized).unwrap();

            assert_eq!(proof_deserialized, proof);
        }
    }
}
