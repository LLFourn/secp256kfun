#![no_std]
#![allow(non_snake_case)]

use digest::Digest;
pub use generic_array::{self, typenum};
use generic_array::{ArrayLength, GenericArray};
pub use rand_chacha::rand_core;
use rand_chacha::rand_core::{CryptoRng, RngCore};

#[cfg(feature = "secp256kfun")]
pub mod secp256k1;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "alloc")]
extern crate alloc;

mod and;
pub use and::And;
mod eq;
pub use eq::Eq;

#[cfg(feature = "alloc")]
mod eq_all;
#[cfg(feature = "alloc")]
pub use eq_all::EqAll;
mod or;
pub use or::*;

#[cfg(feature = "alloc")]
mod all;
#[cfg(feature = "alloc")]
pub use all::All;
pub mod ext;
mod transcript;
pub use transcript::*;

pub trait Sigma {
    type Witness;
    type Statement;
    type AnnounceSecret;
    type Announce: core::cmp::Eq + core::fmt::Debug;
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
    fn write_name<W: core::fmt::Write>(&self, write: &mut W) -> core::fmt::Result;
    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement);
    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce);
    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness);
}

pub struct FiatShamir<S, T> {
    transcript: T,
    sigma: S,
}

impl<S: Default + Sigma, T: Transcript<S>> Default for FiatShamir<S, T> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<S: Sigma, T: Transcript<S>> FiatShamir<S, T> {
    pub fn new(sigma: S) -> Self {
        let transcript = Transcript::initialize(&sigma);

        Self { transcript, sigma }
    }

    pub fn prove<Rng: CryptoRng + RngCore>(
        &self,
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
        let challenge = transcript.get_challenge(&self.sigma, &announce);
        let response =
            self.sigma
                .respond(witness, statement, announce_secret, &announce, &challenge);
        CompactProof::<S> {
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
        let implied_challenge = transcript.get_challenge(&self.sigma, &implied_announcement);
        implied_challenge == proof.challenge
    }
}

pub type CompactProof<S> =
    CompactProofInternal<GenericArray<u8, <S as Sigma>::ChallengeLength>, <S as Sigma>::Response>;

#[cfg_attr(
    feature = "serde",
    serde(crate = "serde_crate"),
    derive(serde_crate::Serialize, serde_crate::Deserialize)
)]
#[derive(Debug, Clone, PartialEq)]
pub struct CompactProofInternal<C, R> {
    challenge: C,
    response: R,
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display {
    ($name:ident<$($tp:ident),+>) => {
        impl<$($tp),+> core::fmt::Display for $name<$($tp),+>
            where $name<$($tp),+>: $crate::Sigma
        {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                self.write_name(f)
            }
        }
    }
}
