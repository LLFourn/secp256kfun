//! Proofs of knowledge of discrete logarithm on Edwards twist of curve25519 using  using [`curve25519-dalek`].
//!
//! **WARNING**: This does not check whether the points are in the prime-order subgroup. For the
//! proof to be completely sound this needs to be checked by the verifier with [`is_torsion_free`].
//! This code is mostly here to demonstrate that you can prove a secp256k1 and ed25519 public key
//! have the same secret key for use in cross-chain atomic swaps between Bitcoin and Monero. If you
//! are developing a cryptosystem from scratch you should use [`ristretto`] instead.
//!
//!
//! [`curve25519-dalek`]: crate::ed25519::curve25519_dalek
//! [`is_torsion_free`]: crate::ed25519::curve25519_dalek::edwards::EdwardsPoint::is_torsion_free
//! [`ristretto`]: crate::ed25519::curve25519_dalek::ristretto
use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
pub use curve25519_dalek;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar};
use digest::Update;
use generic_array::{
    typenum::{self, type_operators::IsLessOrEqual, U31},
    ArrayLength, GenericArray,
};

/// Proves knowledge of `x` such that `A = x * B` for some `A` and `B` included in the statement.
#[derive(Clone, Debug, Default, PartialEq)]
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
    type Announcement = EdwardsPoint;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &statement.0;
        announce_secret * G
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
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
    ) -> Option<Self::Announcement> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        Some(response * G - challenge * X)
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.compress().as_bytes());
        hash.update(statement.1.compress().as_bytes());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.compress().as_bytes())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }
}

/// Proves knowledge of `x` such that `A = x * G` for some `A` included in the statement.
/// `G` is the standard basepoint used in the ed25519 signature scheme and is not included in the statement.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DLG<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DLG<L>
where
    L: IsLessOrEqual<U31>,
    <L as IsLessOrEqual<U31>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = EdwardsPoint;
    type AnnounceSecret = Scalar;
    type Announcement = EdwardsPoint;
    type Response = Scalar;
    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = normalize_challenge(challenge);
        announce_secret + challenge * witness
    }

    fn announce(
        &self,
        _statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &ED25519_BASEPOINT_TABLE;
        announce_secret * G
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
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
    ) -> Option<Self::Announcement> {
        let X = statement;
        let challenge = normalize_challenge(challenge);
        Some(EdwardsPoint::vartime_double_scalar_mul_basepoint(
            &-challenge,
            X,
            response,
        ))
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.compress().as_bytes());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.compress().as_bytes())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }
}

fn normalize_challenge<L: ArrayLength<u8>>(challenge: &GenericArray<u8, L>) -> Scalar {
    let mut challenge_bytes = [0u8; 32];
    challenge_bytes[..challenge.len()].copy_from_slice(challenge.as_slice());
    Scalar::from_canonical_bytes(challenge_bytes)
        .expect("this function is only passed 31 byte arrays at most")
}

impl<L> crate::Writable for DL<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DL(ed25519)")
    }
}

impl<L> crate::Writable for DLG<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DLG(ed25519)")
    }
}

crate::impl_display!(DL<L>);
crate::impl_display!(DLG<L>);

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::FiatShamir;
    use ::proptest::prelude::*;
    use generic_array::typenum::U31;
    use sha2::Sha256;

    prop_compose! {
        pub fn ed25519_scalar()(
            bytes in any::<[u8; 32]>(),
        ) -> Scalar {
            Scalar::from_bytes_mod_order(bytes)
        }
    }

    prop_compose! {
        pub fn ed25519_point()(
            x in ed25519_scalar(),
        ) -> EdwardsPoint {
            &x * &ED25519_BASEPOINT_TABLE
        }
    }

    type Transcript = crate::HashTranscript<Sha256, rand_chacha::ChaCha20Rng>;

    proptest! {
        #[test]
        fn ed25519_dlg(
            x in ed25519_scalar(),
        ) {
            let G = &ED25519_BASEPOINT_TABLE;
            let xG = &x * G;
            let proof_system = FiatShamir::<DLG<U31>, Transcript>::default();
            let proof = proof_system.prove(&x, &xG, Some(&mut rand::thread_rng()));
            assert!(proof_system.verify(&xG, &proof));
        }
    }

    proptest! {
        #[test]
        fn ed25519_dl(
            x in ed25519_scalar(),
        ) {
            let G = &Scalar::random(&mut rand::thread_rng()) * &ED25519_BASEPOINT_TABLE;
            let xG = &x * G;
            let proof_system = FiatShamir::<DL<U31>, Transcript>::default();
            let proof = proof_system.prove(&x, &(G, xG), Some(&mut rand::thread_rng()));
            assert!(proof_system.verify(&(G, xG), &proof));
        }
    }
}
