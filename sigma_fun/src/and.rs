use crate::rand_core::{CryptoRng, RngCore};
use digest::Digest;
use generic_array::GenericArray;

use crate::Sigma;

pub struct And<A, B> {
    lhs: A,
    rhs: B,
}

impl<A: Sigma, B: Sigma<ChallengeLength = A::ChallengeLength>> Sigma for And<A, B> {
    type Witness = (A::Witness, B::Witness);
    type Statement = (A::Statement, B::Statement);
    type Announce = (A::Announce, B::Announce);
    type AnnounceSecret = (A::AnnounceSecret, B::AnnounceSecret);
    type Response = (A::Response, B::Response);
    type ChallengeLength = A::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        (
            self.lhs.respond(
                &witness.0,
                &statement.0,
                announce_secret.0,
                &announce.0,
                challenge,
            ),
            self.rhs.respond(
                &witness.1,
                &statement.1,
                announce_secret.1,
                &announce.1,
                challenge,
            ),
        )
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        (
            self.lhs.announce(&statement.0, &announce_secret.0),
            self.rhs.announce(&statement.1, &announce_secret.1),
        )
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        (
            self.lhs.gen_announce_secret(&witness.0, &statement.0, rng),
            self.rhs.gen_announce_secret(&witness.1, &statement.1, rng),
        )
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        (self.lhs.sample_response(rng), self.rhs.sample_response(rng))
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let (lhs_response, rhs_response) = response;
        let (lhs_statement, rhs_statement) = statement;
        self.lhs
            .implied_announcement(lhs_statement, challenge, lhs_response)
            .and_then(|lhs_announcement| {
                self.rhs
                    .implied_announcement(&rhs_statement, challenge, rhs_response)
                    .map(|rhs_announcement| (lhs_announcement, rhs_announcement))
            })
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) {
        write!(w, "and(").unwrap();
        self.lhs.write_name(w);
        write!(w, ",").unwrap();
        self.rhs.write_name(w);
        write!(w, ")").unwrap();
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        self.lhs.hash_statement(hash, &statement.0);
        self.rhs.hash_statement(hash, &statement.1);
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        self.lhs.hash_announcement(hash, &announcement.0);
        self.rhs.hash_announcement(hash, &announcement.1)
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        self.lhs.hash_witness(hash, &witness.0);
        self.rhs.hash_witness(hash, &witness.1);
    }
}

crate::impl_display!(And<A,B>);
