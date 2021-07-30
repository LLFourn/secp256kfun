//!
#![no_std]
#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]
#![deny(warnings, missing_docs)]
#[cfg(all(feature = "alloc", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[cfg(feature = "serde")]
extern crate serde_crate as serde;

pub use secp256kfun as fun;
pub use secp256kfun::nonce;
mod signature;
pub use signature::Signature;
pub mod adaptor;
mod keypair;
pub use keypair::KeyPair;
mod schnorr;
pub use schnorr::*;
mod message;
pub use message::*;

#[macro_export]
#[doc(hidden)]
macro_rules! test_instance {
    () => {
        $crate::Schnorr::<sha2::Sha256, _>::new(
            $crate::nonce::Deterministic::<sha2::Sha256>::default(),
        )
    };
}
