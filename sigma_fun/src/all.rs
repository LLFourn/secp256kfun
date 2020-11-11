use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{typenum::Unsigned, GenericArray};

#[derive(Default, Clone, Debug)]
pub struct All<N, S> {
    sigma: S,
    n: PhantomData<N>,
}

impl<S, N> All<N, S> {
    pub fn new(sigma: S) -> Self {
        Self {
            sigma,
            n: PhantomData,
        }
    }
}

impl<N: Unsigned, S: Sigma> Sigma for All<N, S> {
    type Witness = Vec<S::Witness>;
    type Statement = Vec<S::Statement>;
    type AnnounceSecret = Vec<S::AnnounceSecret>;
    type Announcement = Vec<S::Announcement>;
    type Response = Vec<S::Response>;
    type ChallengeLength = S::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        announce_secret
            .into_iter()
            .enumerate()
            .map(|(i, announce_secret)| {
                let response = self.sigma.respond(
                    &witness[i],
                    &statement[i],
                    announce_secret,
                    &announce[i],
                    challenge,
                );
                response
            })
            .collect()
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        (0..N::to_usize())
            .map(|i| self.sigma.announce(&statement[i], &announce_secret[i]))
            .collect()
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        (0..N::to_usize())
            .map(|i| {
                self.sigma
                    .gen_announce_secret(&witness[i], &statement[i], rng)
            })
            .collect()
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        (0..N::to_usize())
            .map(|_| self.sigma.sample_response(rng))
            .collect()
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        if statement.len() != N::to_usize() || response.len() != N::to_usize() {
            return None;
        }

        (0..N::to_usize())
            .map(|i| {
                self.sigma
                    .implied_announcement(&statement[i], challenge, &response[i])
            })
            .collect()
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "all({},", N::to_u32())?;
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

    fn hash_witness<H: Digest>(&self, hash: &mut H, witnesses: &Self::Witness) {
        for witness in witnesses {
            self.sigma.hash_witness(hash, witness)
        }
    }
}

crate::impl_display!(All<S,N>);
