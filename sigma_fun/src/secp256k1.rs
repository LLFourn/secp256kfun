use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{
    typenum::{self, type_operators::IsLessOrEqual, U32},
    ArrayLength, GenericArray,
};
pub use secp256kfun as fun;
use secp256kfun::{derive_nonce, g, marker::*, nonce::NonceGen, s, Point, Scalar};

pub struct DL<L> {
    len: PhantomData<L>,
}

impl<L> DL<L> {
    pub fn new() -> Self {
        DL { len: PhantomData }
    }
}

impl<L: ArrayLength<u8>> Sigma for DL<L>
where
    L: IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: typenum::marker_traits::NonZero,
{
    type Witness = Scalar;

    type Statement = (Point, Point);

    type AnnounceSecret = Scalar;

    type Announce = Point;

    type Response = Scalar<Public, Zero>;

    type ChallengeLength = L;

    fn respond(
        &self,
        witness: &Self::Witness,
        _statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        _announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let challenge = Self::normalize_challenge(challenge);
        s!(announce_secret + challenge * witness).mark::<Public>()
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        let G = &statement.0;
        let announce = g!(announce_secret * G);
        announce.mark::<Normal>()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        Scalar::random(rng).mark::<(Public, Zero)>()
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let (G, X) = statement;
        let challenge = Self::normalize_challenge(challenge);
        g!(response * G - challenge * X).mark::<(Normal, NonZero)>()
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) {
        write!(w, "DL-secp256k1").unwrap()
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        hash.update(statement.0.to_bytes().as_ref());
        hash.update(statement.1.to_bytes().as_ref());
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        hash.update(announcement.to_bytes().as_ref())
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        hash.update(witness.to_bytes().as_ref())
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        _witness: &Self::Witness,
        _statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        Scalar::random(rng)
    }
}

impl<L: ArrayLength<u8>> DL<L> {
    fn normalize_challenge(challenge: &GenericArray<u8, L>) -> Scalar<Public, Zero> {
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes[..challenge.len()].copy_from_slice(challenge.as_slice());
        Scalar::from_bytes_mod_order(challenge_bytes).mark::<Public>()
    }
}
