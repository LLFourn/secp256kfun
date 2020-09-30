use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{functional::FunctionalSequence, typenum::Unsigned, ArrayLength, GenericArray};

pub struct Eq<S, N> {
    sigma: S,
    n: PhantomData<N>,
}

impl<S, N> Eq<S, N> {
    pub fn new(sigma: S) -> Self {
        Self {
            sigma,
            n: PhantomData,
        }
    }
}

impl<S: Sigma, N> Sigma for Eq<S, N>
where
    N: ArrayLength<S::Statement>
        + ArrayLength<S::Announce>
        + ArrayLength<(S::Announce, S::AnnounceSecret)>
        + ArrayLength<S::AnnounceSecret>
        + ArrayLength<Option<S::Announce>>
        + Unsigned,
{
    type Witness = S::Witness;
    type Statement = GenericArray<S::Statement, N>;
    type AnnounceSecret = S::AnnounceSecret;
    type Announce = GenericArray<S::Announce, N>;
    type Response = S::Response;
    type ChallengeLength = S::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
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
    ) -> Self::Announce {
        statement.map(|statement| self.sigma.announce(statement, announce_secret))
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        self.sigma.sample_response(rng)
    }

    fn implied_announcement(
        &self,
        statements: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let announce_opts = statements.map(|statement| {
            self.sigma
                .implied_announcement(statement, challenge, response)
        });
        for announcement_opt in &announce_opts {
            if announcement_opt.is_none() {
                return None;
            }
        }
        Some(announce_opts.map(|announcement| announcement.unwrap()))
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) {
        write!(w, "eq({},", N::to_u32()).unwrap();
        self.sigma.write_name(w);
        write!(w, ")").unwrap();
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statements: &Self::Statement) {
        for statement in statements {
            self.sigma.hash_statement(hash, statement)
        }
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcements: &Self::Announce) {
        for announcement in announcements {
            self.sigma.hash_announcement(hash, announcement)
        }
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        self.sigma.hash_witness(hash, witness)
    }
}

crate::impl_display!(Eq<S,N>);
