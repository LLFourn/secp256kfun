//! Proofs of knowledge of discrete logarithm for the secp256k1 curve using [`secp256kfun`].
//!
//! [`secp256kfun`]: crate::secp256k1::fun
use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
use digest::Update;
use generic_array::{
    typenum::{self, type_operators::IsLessOrEqual, U32},
    ArrayLength, GenericArray,
};
pub use secp256kfun as fun;
use secp256kfun::{g, marker::*, s, Point, Scalar};

/// Proves knowledge of `x` such that `A = x * B` for some `A` and `B` included in the statement.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DL<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DL<L>
where
    L: IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = (Point, Point);
    type AnnounceSecret = Scalar;
    type Announcement = Point;
    type Response = Scalar<Public, Zero>;
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
        s!(announce_secret + challenge * witness).public()
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = &statement.0;
        let announce = g!(announce_secret * G);
        announce.normalize()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng).public().mark_zero()
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let (G, X) = statement;
        let challenge = normalize_challenge(challenge);
        g!(response * G - challenge * X).normalize().non_zero()
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.to_bytes().as_ref());
        hash.update(statement.1.to_bytes().as_ref());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.to_bytes().as_ref())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }
}

impl<L> crate::Writable for DL<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DL(secp256k1)")
    }
}

/// Proves knowledge of `x` such that `A = x * G` for some `A` included in the statement.
/// [`G`] is the standard basepoint for secp256k1 and is ommited from the statement.
///
/// [`G`]: secp256kfun::G
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DLG<L> {
    challenge_len: PhantomData<L>,
}

impl<L: ArrayLength<u8>> Sigma for DLG<L>
where
    L: IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;
    type Statement = Point;
    type AnnounceSecret = Scalar;
    type Announcement = Point;
    type Response = Scalar<Public, Zero>;
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
        s!(announce_secret + challenge * witness).public()
    }

    fn announce(
        &self,
        _statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        let G = fun::G;
        let announce = g!(announce_secret * G);
        announce.normalize()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng).public().mark_zero()
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        let X = statement;
        let G = fun::G;
        let challenge = normalize_challenge(challenge);
        g!(response * G - challenge * X).normalize().non_zero()
    }

    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.to_bytes().as_ref());
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement) {
        hash.update(announcement.to_bytes().as_ref())
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }
}

fn normalize_challenge<L: ArrayLength<u8>>(
    challenge: &GenericArray<u8, L>,
) -> Scalar<Public, Zero> {
    let mut challenge_bytes = [0u8; 32];
    // secp256k1 scalar byte representation is interpreted as big-endian and to
    // be consistent we always copy the bits into the least signgificant bytes.
    challenge_bytes[(32 - challenge.len())..].copy_from_slice(challenge.as_slice());
    Scalar::from_bytes_mod_order(challenge_bytes)
}

impl<L> crate::Writable for DLG<L> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "DLG(secp256k1)")
    }
}

crate::impl_display!(DL<L>);
crate::impl_display!(DLG<L>);
