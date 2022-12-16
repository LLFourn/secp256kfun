//!
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod hash;
pub mod hex;
pub mod nonce;

pub use digest;
pub use rand_core;
pub use subtle;

mod keypair;
mod point;
mod scalar;
mod slice;

mod vendor;

#[macro_use]
mod macros;
mod backend;
pub mod marker;
pub mod op;

pub use keypair::*;
pub use point::Point;
pub use scalar::Scalar;
pub use slice::Slice;

#[cfg(feature = "libsecp_compat")]
pub extern crate secp256k1;

/// Re-export `serde`
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
#[cfg(feature = "serde")]
pub use serde;

#[cfg(feature = "libsecp_compat")]
mod libsecp_compat;
#[cfg(any(feature = "proptest", test))]
mod proptest_impls;
#[cfg(feature = "proptest")]
#[cfg_attr(docsrs, doc(cfg(feature = "proptest")))]
pub extern crate proptest;
/// The main basepoint for secp256k1 as specified in [_SEC 2: Recommended Elliptic Curve Domain Parameters_] and used in Bitcoin.
///
/// At the moment, [`G`] is the only [`BasePoint`] in the library.
/// ```
/// use secp256kfun::G;
/// assert_eq!(
///     format!("{:?}", G),
///     "Point<BasePoint,Public,NonZero>(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
/// );
/// ```
///
///[_SEC 2: Recommended Elliptic Curve Domain Parameters_]: https://www.secg.org/sec2-v2.pdf
///[`BasePoint`]: crate::marker::BasePoint
pub static G: &'static Point<marker::BasePoint, marker::Public, marker::NonZero> =
    &Point::from_inner(backend::G_POINT, marker::BasePoint);

// it is applied to nonce generators too so export at root
pub use hash::Tag;
