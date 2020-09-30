use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use core::marker::PhantomData;
use digest::Digest;
use generic_array::{functional::FunctionalSequence, typenum::Unsigned, ArrayLength, GenericArray};

pub struct All<S, N> {
    sigma: S,
    n: PhantomData<N>,
}

impl<S, N> All<S, N> {
    pub fn new(sigma: S) -> Self {
        Self {
            sigma,
            n: PhantomData,
        }
    }
}

impl<S: Sigma, N> Sigma for All<S, N>
where
    N: ArrayLength<S::Witness>
        + ArrayLength<S::Statement>
        + ArrayLength<S::Announce>
        + ArrayLength<(S::Announce, S::AnnounceSecret)>
        + ArrayLength<S::AnnounceSecret>
        + ArrayLength<Option<S::Announce>>
        + ArrayLength<S::Response>
        + Unsigned,
{
    type Witness = GenericArray<S::Witness, N>;
    type Statement = GenericArray<S::Statement, N>;
    type AnnounceSecret = GenericArray<S::AnnounceSecret, N>;
    type Announce = GenericArray<S::Announce, N>;
    type Response = GenericArray<S::Response, N>;
    type ChallengeLength = S::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let mut i = 0;
        announce_secret.map(|announce_secret| {
            let response = self.sigma.respond(
                &witness[i],
                &statement[i],
                announce_secret,
                &announce[i],
                challenge,
            );
            i += 1;
            response
        })
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        statement.zip(announce_secret, |statement, announce_secret| {
            self.sigma.announce(statement, announce_secret)
        })
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        witness.zip(statement, |witness, statement| {
            self.sigma.gen_announce_secret(witness, statement, rng)
        })
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        GenericArray::from_exact_iter((0..N::to_usize()).map(|_| self.sigma.sample_response(rng)))
            .unwrap()
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let mut one_failed = false;
        let all_implied_announcements = statement.zip(response, |statement, response| {
            let implied_announcement = self
                .sigma
                .implied_announcement(&statement, challenge, &response);
            if implied_announcement.is_none() {
                one_failed = true;
            }
            implied_announcement
        });

        match one_failed {
            true => None,
            false => Some(all_implied_announcements.map(|x| x.unwrap())),
        }
    }

    fn write_name<W: std::fmt::Write>(&self, w: &mut W) {
        write!(w, "all({},", N::to_u32()).unwrap();
        self.sigma.write_name(w);
        write!(w, ")").unwrap()
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

    fn hash_witness<H: Digest>(&self, hash: &mut H, witnesses: &Self::Witness) {
        for witness in witnesses {
            self.sigma.hash_witness(hash, witness)
        }
    }
}

crate::impl_display!(All<S,N>);
