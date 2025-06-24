//! Verifiable Random Function (VRF) implementations for secp256k1.

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "std")]
extern crate std;

pub mod rfc9381;
pub mod vrf;

pub use vrf::{VerifiedRandomOutput, Vrf, VrfProof};

use rand_chacha::ChaCha20Rng;
use sigma_fun::{
    Eq, HashTranscript,
    generic_array::typenum::U32,
    secp256k1::{DL, DLG},
};

/// Type alias for the DLEQ proof with configurable challenge length
pub type VrfDleq<ChallengeLength> = Eq<DLG<ChallengeLength>, DL<ChallengeLength>>;

/// Simple VRF using HashTranscript with 32-byte challenges
pub type SimpleVrf<H> = Vrf<HashTranscript<H, ChaCha20Rng>, U32>;

/// Re-export the [RFC 9381] type aliases
///
/// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
pub use rfc9381::{Rfc9381SswuVrf, Rfc9381TaiVrf};
