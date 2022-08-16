//!
#![cfg_attr(feature = "nightly", feature(min_specialization, rustc_attrs))]
#![no_std]
#![allow(non_snake_case)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(all(feature = "alloc", not(feature = "std")))]
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
mod xonly;

#[macro_use]
mod macros;
mod backend;
pub mod marker;
pub mod op;

pub use keypair::*;
pub use point::Point;
pub use scalar::Scalar;
pub use slice::Slice;
pub use xonly::XOnly;

#[cfg(feature = "secp256k1")]
pub extern crate secp256k1;
#[cfg(feature = "serde")]
pub extern crate serde_crate as serde;
#[cfg(feature = "libsecp_compat")]
mod libsecp_compat;
#[cfg(any(feature = "proptest", test))]
mod proptest_impls;
#[cfg(feature = "proptest")]
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
    &Point::from_inner(backend::G_JACOBIAN, marker::BasePoint(backend::G_TABLE));

#[doc(hidden)]
/// How many times to repeat tests
pub const TEST_SOUNDNESS: usize = 20;
