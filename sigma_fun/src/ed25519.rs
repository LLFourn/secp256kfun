use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use digest::Digest;
use generic_array::{
    typenum::{self, type_operators::IsLessOrEqual, U31},
    ArrayLength, GenericArray,
};

/// Proof of Knowledge of the discrete logarithm between two ed25519 points
/// **WARNING**: This does not check whether the points are in the prime-order subgroup.
/// For the proof to be sound this needs to be checked beforehand by the verifier.
#[derive(Clone, Debug, Default)]
pub struct DL<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DL<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = (EdwardsPoint, EdwardsPoint);
    type AnnounceSecret = Scalar;
    type Announce = EdwardsPoint;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        let G = &statement.0;
        announce_secret * G
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        _statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        Some(response * G - challenge * X)
    }

    fn write_name<W: std::fmt::Write>(&self, w: &mut W) {
        write!(w, "DL-secp256k1").unwrap()
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.compress().as_bytes());
        hash.update(statement.1.compress().as_bytes());
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        hash.update(announcement.compress().as_bytes())
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }
}

#[derive(Clone, Debug, Default)]
pub struct DLBP<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DLBP<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = EdwardsPoint;
    type AnnounceSecret = Scalar;
    type Announce = EdwardsPoint;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        _statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        let G = &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        announce_secret * G
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        _statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let X = statement;
        let challenge = normalize_challenge(challenge);
        Some(EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &challenge, X, response,
        ))
    }

    fn write_name<W: std::fmt::Write>(&self, w: &mut W) {
        write!(w, "DLBP-secp256k1").unwrap()
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.compress().as_bytes());
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        hash.update(announcement.compress().as_bytes())
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }
}

fn normalize_challenge<L: ArrayLength<u8>>(challenge: &GenericArray<u8, L>) -> Scalar {
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes[..challenge.len()].copy_from_slice(challenge.as_slice());
    Scalar::from_canonical_bytes(challenge_bytes)
        .expect("this function is only passed 31 byte arrays at most")
}
