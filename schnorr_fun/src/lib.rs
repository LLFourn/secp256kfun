//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
#![allow(non_snake_case)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub use secp256kfun as fun;
pub use secp256kfun::nonce;

/// binonces for Musig and FROST
pub mod binonce;
// musig needs vecs
#[cfg(feature = "alloc")]
pub mod musig;

#[cfg(feature = "alloc")]
pub mod frost;

/// bech32m secret share backup scheme
#[cfg(feature = "share_backup")]
pub mod share_backup;

mod signature;
pub use signature::Signature;
pub mod adaptor;
mod schnorr;
pub use schnorr::*;
mod message;
pub use message::*;

mod libsecp_compat;

#[macro_export]
#[doc(hidden)]
macro_rules! test_instance {
    () => {
        $crate::Schnorr::<sha2::Sha256, secp256kfun::nonce::Deterministic<sha2::Sha256>>::default()
    };
}
