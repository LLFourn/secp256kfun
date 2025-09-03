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
///
/// This provides a straightforward VRF implementation using the standard
/// HashTranscript from sigma_fun. It produces 32-byte proofs.
///
/// # Example
///
/// ```
/// use secp256kfun::{KeyPair, Scalar, prelude::*};
/// use secp256kfun::hash::HashAdd;
/// use secp256kfun::digest::Digest;
/// use vrf_fun::SimpleVrf;
/// use sha2::Sha256;
/// use rand::thread_rng;
///
/// // Generate a keypair
/// let keypair = KeyPair::new(Scalar::random(&mut thread_rng()));
///
/// // Create the VRF instance
/// let vrf = SimpleVrf::<Sha256>::default();
///
/// // Hash input data to a curve point
/// let hasher = Sha256::default().add(b"my-input-data");
/// let h = Point::hash_to_curve(hasher).normalize();
///
/// // Generate proof
/// let proof = vrf.prove(&keypair, h);
///
/// // Verify proof
/// let verified = vrf.verify(keypair.public_key(), h, &proof)
///     .expect("proof should verify");
///
/// // The verified output contains a gamma point that can be hashed
/// // to produce deterministic randomness
/// let output_bytes = Sha256::default()
///     .add(verified)
///     .finalize();
/// ```
///
/// # Domain Separation
///
/// You can set a custom name for domain separation using `with_name`:
///
/// ```
/// # use secp256kfun::{KeyPair, Scalar, hash::{Hash32, HashAdd}, prelude::*};
/// # use vrf_fun::SimpleVrf;
/// # use sha2::Sha256;
/// # use rand::thread_rng;
/// # let keypair = KeyPair::new(Scalar::random(&mut thread_rng()));
/// # let hasher = Sha256::default().add(b"my-input-data");
/// # let h = Point::hash_to_curve(hasher).normalize();
/// let vrf = SimpleVrf::<Sha256>::default().with_name("my-app-vrf");
/// let proof = vrf.prove(&keypair, h);
/// ```
pub type SimpleVrf<H> = Vrf<HashTranscript<H, ChaCha20Rng>, U32>;

/// Re-export the [RFC 9381] type aliases
///
/// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
pub use rfc9381::{Rfc9381SswuVrf, Rfc9381TaiVrf};
