use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::Update;
use generic_array::{typenum::Unsigned, GenericArray};

/// Combinator for proving any number of statements of the same kind have the same witness.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EqAll<S, N> {
    sigma: S,
    n: PhantomData<N>,
}

impl<S, N> EqAll<S, N> {
    /// Create a `EqAll<N,S>` from a Sigma protocol `S`.
    pub fn new(sigma: S) -> Self {
        Self {
            sigma,
            n: PhantomData,
        }
    }
}

impl<N: Unsigned, S: Sigma> Sigma for EqAll<S, N> {
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
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        self.sigma.gen_announce_secret(witness, rng)
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

    fn hash_statement<H: Update>(&self, hash: &mut H, statements: &Self::Statement) {
        for statement in statements {
            self.sigma.hash_statement(hash, statement)
        }
    }

    fn hash_announcement<H: Update>(&self, hash: &mut H, announcements: &Self::Announcement) {
        for announcement in announcements {
            self.sigma.hash_announcement(hash, announcement)
        }
    }

    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness) {
        self.sigma.hash_witness(hash, witness)
    }
}

impl<S: Sigma, N: Unsigned> crate::Writable for EqAll<S, N> {
    fn write_to<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "eq-all({},", N::to_u32())?;
        self.sigma.write_to(w)?;
        write!(w, ")")
    }
}

crate::impl_display!(EqAll<S,N>);
