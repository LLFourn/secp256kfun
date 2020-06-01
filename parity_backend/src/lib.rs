//! Vendored version of paritytech/libsecp256k1 with the things needed for
//! secp256kfun. Code in this module is licensed under the Apache License
//! Version 2.0.
#![no_std]
#[cfg(feature = "alloc")]
extern crate alloc;

pub mod ecmult;
pub mod field;
pub mod group;
pub mod scalar;
