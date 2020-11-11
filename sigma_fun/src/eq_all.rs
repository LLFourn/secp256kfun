use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};

#[derive(Debug, Clone, Default)]
pub struct EqAll<N, S> {
    sigma: S,
    n: PhantomData<N>,
}

impl<S, N> EqAll<N, S> {
    pub fn new(sigma: S) -> Self {
        Self {
            sigma,
            n: PhantomData,
        }
    }
}

impl<N: Unsigned, S: Sigma> Sigma for EqAll<N, S> {
    type Witness = S::Witness;
    type Statement = Vec<S::Statement>;
    type AnnounceSecret = S::AnnounceSecret;
    type Announcement = Vec<S::Announcement>;
    type Response = S::Response;
    type ChallengeLength = S::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        self.sigma.respond(
            witness,
            &statement[0],
            announce_secret,
            &announce[0],
            challenge,
        )
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        self.sigma.gen_announce_secret(witness, &statement[0], rng)
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        statement
            .iter()
            .map(|statement| self.sigma.announce(statement, announce_secret))
            .collect()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        self.sigma.sample_response(rng)
    }

    fn implied_announcement(
        &self,
        statements: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        if statements.len() != N::to_usize() {
            return None;
        }

        statements
            .iter()
            .map(|statement| {
                self.sigma
                    .implied_announcement(statement, challenge, response)
            })
            .collect::<Option<Vec<_>>>()
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "eq-all({},", N::to_u32())?;
        self.sigma.write_name(w)?;
        write!(w, ")")
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statements: &Self::Statement) {
        for statement in statements {
            self.sigma.hash_statement(hash, statement)
        }
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcements: &Self::Announcement) {
        for announcement in announcements {
            self.sigma.hash_announcement(hash, announcement)
        }
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        self.sigma.hash_witness(hash, witness)
    }
}

crate::impl_display!(EqAll<N,S>);
