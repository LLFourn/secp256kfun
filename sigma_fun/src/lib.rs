//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![allow(non_snake_case)]
#![cfg_attr(feature = "secp256k1", doc = include_str!("../README.md"))]
#![deny(missing_docs, warnings)]

use core::fmt::Debug;
use digest::Update;
pub use generic_array::{self, typenum};
use generic_array::{ArrayLength, GenericArray};
pub use rand_core;
use rand_core::{CryptoRng, RngCore};

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "secp256k1")]
#[cfg_attr(docsrs, doc(cfg(feature = "secp256k1")))]
pub mod secp256k1;

#[cfg(feature = "ed25519")]
#[cfg_attr(docsrs, doc(cfg(feature = "ed25519")))]
pub mod ed25519;

mod and;
pub use and::And;
mod eq;
pub use eq::Eq;

#[cfg(feature = "alloc")]
mod eq_all;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use eq_all::EqAll;
mod or;
pub use or::*;

#[cfg(feature = "alloc")]
mod all;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use all::All;
pub mod ext;
mod transcript;
pub use transcript::*;
mod fiat_shamir;
pub use fiat_shamir::*;
mod writable;
pub use writable::*;

/// The `Sigma` trait is used to define a Sigma protocol.
///
/// You will need to implement this yourself if you are unable to build your sigma protocol by
/// composing it from existing sigma protocols.
///
/// The role of the main functions of the trait are depicted below:
///
///```ignore
/// Prover(witness, statement, rng)                                                 Verifier(statement)
/// ======
/// announce_secret = gen_announce_secret(rng)
/// announcement = announce(statement, announce_secret)
///                                                       announcement
///                                                   +------------------->
///                                                        challenge         *uniformly sample ChallengeLength bytes*
///                                                   <-------------------+
/// response = respond(witness, statement,
///                    announce_secret, announcement,
///                    challenge)
///
///                                                        response
///                                                   +------------------->
///                                                                                             check
///                                                                         implied_announcement(statement, challenge, response)
///                                                                                               ==
///                                                                                          announcement
/// ```
///
/// The values taken and returned by the functions are all defined as associated types. In addition
/// there is `ChallengeLength` associated type which defines the length of the challenge. Usually
/// the trait is implemented for a sigma protocol for all lengths less than some maximum like so:
///
/// ```ignore
/// use sigma_fun::generic_array::{
///     typenum::{self, type_operators::IsLessOrEqual, U32},
///     ArrayLength, GenericArray,
/// };
/// use sigma_fun::Sigma;
/// struct MySigma<L> {
///     // store the typenum in our type
///     challenge_len: core::marker::PhantomData<L>,
/// }
/// // implement Sigma for any length less than or eqaul to 32-bytes.
/// impl<L: ArrayLength<u8>> Sigma for MySigma<L>
/// where
///    L: IsLessOrEqual<U32>,
///    <L as IsLessOrEqual<U32>>::Output: typenum::marker_traits::NonZero
///    {
///    // ...
///    }
/// ```
pub trait Sigma: Writable {
    /// The witness for the relation.
    type Witness: Debug;
    /// The elements of the statement the prover is proving.
    type Statement: Debug;
    /// The type for the secret the prover creates when generating the proof.
    type AnnounceSecret: Debug;
    /// The type for the public announcement the prover sends in the first round of the protocol.
    type Announcement: core::cmp::Eq + Debug;
    /// The type for the response the prover sends in the last round of the protocol.
    type Response: Debug;
    /// The length as a [`typenum`]
    ///
    /// [`typenum`]: crate::typenum
    type ChallengeLength: ArrayLength<u8>;

    /// Generates the prover's announcement message.
    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement;
    /// Generates the secret data to create the announcement
    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret;
    /// Uniformly samples a response from the response space of the Sigma protocol.
    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response;

    /// Generates the prover's response for the verifier's challenge.
    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response;
    /// Computes what the announcement must be for the `response` to be valid.
    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement>;

    /// Hashes the statement.
    fn hash_statement<H: Update>(&self, hash: &mut H, statement: &Self::Statement);
    /// Hashes the announcement.
    fn hash_announcement<H: Update>(&self, hash: &mut H, announcement: &Self::Announcement);
    /// Hashes the witness.
    fn hash_witness<H: Update>(&self, hash: &mut H, witness: &Self::Witness);
}

#[macro_export]
#[doc(hidden)]
macro_rules! impl_display {
    ($name:ident<$($tp:ident),+>) => {
        impl<$($tp),+> core::fmt::Display for $name<$($tp),+>
            where $name<$($tp),+>: $crate::Sigma
        {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                use $crate::Writable;
                self.write_to(f)
            }
        }
    }
}
