#![allow(non_snake_case)]
#![feature(move_ref_pattern)]

use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
pub use rand_chacha::rand_core;
use rand_chacha::rand_core::{CryptoRng, RngCore};

#[cfg(feature = "secp256kfun")]
mod secp256k1;

mod and;
pub use and::And;
mod eq;
pub use eq::Eq;
mod or;
pub use or::Or;
mod transcript;
pub use transcript::*;

pub trait Sigma {
    type Witness;
    type Statement;
    type AnnounceSecret;
    type Announce: core::cmp::Eq;
    type Response;
    type ChallengeLength: ArrayLength<u8>;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response;
    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce;
    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret;
    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response;
    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce>;
    fn write_name<W: core::fmt::Write>(&self, write: &mut W);
    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement);
    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce);
    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness);
}

pub struct FiatShamir<S, T> {
    transcript: T,
    sigma: S,
}

impl<S: Sigma, T: Transcript<S>> FiatShamir<S, T> {
    pub fn new(sigma: S) -> Self {
        let transcript = Transcript::initialize(&sigma);

        Self { transcript, sigma }
    }

    pub fn prove<Rng: CryptoRng + RngCore>(
        &mut self,
        witness: &S::Witness,
        statement: &S::Statement,
        rng: &mut Rng,
    ) -> CompactProof<S> {
        let mut transcript = self.transcript.clone();
        transcript.add_statement(&self.sigma, statement);
        let mut transcript_rng = transcript.gen_rng(&self.sigma, witness, rng);
        let announce_secret =
            self.sigma
                .gen_announce_secret(witness, statement, &mut transcript_rng);
        let announce = self.sigma.announce(statement, &announce_secret);
        let challenge = transcript.add_announcement(&self.sigma, &announce);
        let response =
            self.sigma
                .respond(witness, statement, announce_secret, &announce, &challenge);
        CompactProof {
            challenge,
            response,
        }
    }

    #[must_use]
    pub fn verify(&self, statement: &S::Statement, proof: &CompactProof<S>) -> bool {
        let mut transcript = self.transcript.clone();
        transcript.add_statement(&self.sigma, statement);
        let implied_announcement =
            match self
                .sigma
                .implied_announcement(statement, &proof.challenge, &proof.response)
            {
                Some(announcement) => announcement,
                None => return false,
            };
        let implied_challenge = transcript.add_announcement(&self.sigma, &implied_announcement);
        implied_challenge == proof.challenge
    }
}

pub struct CompactProof<S: Sigma> {
    challenge: GenericArray<u8, S::ChallengeLength>,
    response: S::Response,
}

// }

// impl<A: Sigma, B: Sigma> Sigma for And<A,B> {

//     pub fn get_statement(witness: &Self::Witness) -> Self::Statement {
//         (A::get_statement(&witness.0), B::get_statement(&witness.1))
//     }

//     pub fn respond(witness: &Self::Witness, announce_secret: &S::AnnounceSecret, &challenge: &[u8]) -> Self::Response {
//         (A::respond(witness, announce_secret, challenge), B::respond(witness, announce_secret, challenge))
//     }

//     pub fn announce(wintess: &Self::Witness) -> (Self::Announce, Self::AnnounceSecret) {
//         (A::announce(statement.0), B::announce(statement.1))
//     }

//     pub fn simulate(statement: &Self::Statement, challenge: Challenge) -> (Self::Announce, Self::Response) {
//         let simA = A::simulate(&statement.0, challenge);
//         let simB = B::simulate(&statement.1, challenge);
//         ((simA.0, simB.0), (simB.1,simA.1))
//     }

//     pub fn verify_response(statement: &Self::Statement, challenge: Challenge, response: &Self::Response) -> bool {
//         A::veirfy_response(&statement.0, challenge, &response.0) && B::verify_response(&statement.1, challenge, &response.1)
//     }

//     pub fn implied_announcement(statement: &Self::Statement, challenge: Challenge, response: &Self::Response) -> Self::Announce {
//         A::implied_announcement(&statement.0, challenge, &response.0)
//     }
// }
