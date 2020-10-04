use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};

#[derive(Default, Clone, Debug)]
pub struct Eq<A, B> {
    lhs: A,
    rhs: B,
}

impl<A,B>  Eq<A,B> {
    pub fn new(lhs: A, rhs: B) -> Self {
        Self { lhs, rhs }
    }
}

impl<A, B> Sigma for Eq<A, B>
where
    A: Sigma,
    // For two sigma protocols to be have EQ composition they must share the
    // following. If they share the following it doesn't necessarily mean they
    // are Eq compatible but it's the best we can do for now.
    B: Sigma<
        ChallengeLength = A::ChallengeLength,
        Witness = A::Witness,
        Response = A::Response,
        AnnounceSecret = A::AnnounceSecret,
    >,
{
    type Witness = A::Witness;
    type Statement = (A::Statement, B::Statement);
    type AnnounceSecret = A::AnnounceSecret;
    type Announce = (A::Announce, B::Announce);
    type Response = A::Response;
    type ChallengeLength = A::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        self.lhs.respond(
            witness,
            &statement.0,
            announce_secret,
            &announce.0,
            challenge,
        )
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        (
            self.lhs.announce(&statement.0, announce_secret),
            self.rhs.announce(&statement.1, announce_secret),
        )
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        self.lhs.gen_announce_secret(witness, &statement.0, rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        self.lhs.sample_response(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        self.lhs
            .implied_announcement(&statement.0, challenge, response)
            .and_then(|lhs_implied_announcement| {
                self.rhs
                    .implied_announcement(&statement.1, challenge, response)
                    .map(|rhs_implied_announcement| {
                        (lhs_implied_announcement, rhs_implied_announcement)
                    })
            })
    }

    fn write_name<W: std::fmt::Write>(&self, w: &mut W) {
        write!(w, "eq(").unwrap();
        self.lhs.write_name(w);
        write!(w, ",").unwrap();
        self.rhs.write_name(w);
        write!(w, ")").unwrap();
    }

    fn hash_statement<H: digest::Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        self.lhs.hash_statement(hash, &statement.0);
        self.rhs.hash_statement(hash, &statement.1);
    }

    fn hash_announcement<H: digest::Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        self.lhs.hash_announcement(hash, &announcement.0);
        self.rhs.hash_announcement(hash, &announcement.1);
    }

    fn hash_witness<H: digest::Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        self.lhs.hash_witness(hash, witness);
    }
}

crate::impl_display!(Eq<A,B>);
