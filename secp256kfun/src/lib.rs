#![feature(rustc_attrs, min_specialization, external_doc)]
#![doc(include = "../README.md")]
#![no_std]
#![allow(non_snake_case)]
#![deny(missing_docs)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
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

mod point;
mod scalar;
mod slice;
mod xonly;

mod backend;
pub mod marker;
pub mod op;

mod macros;
pub use point::Point;
pub use scalar::Scalar;
pub use slice::Slice;
pub use xonly::XOnly;

#[cfg(feature = "secp256k1")]
pub extern crate secp256k1;
#[cfg(feature = "serialization")]
pub extern crate serde;
#[cfg(feature = "libsecp_compat")]
mod libsecp_compat;
/// The main basepoint for secp256k1 as specified in [_SEC 2: Recommended Elliptic Curve Domain Parameters_] and used in Bitcoin.
///
/// At the moment, [`G`] is the only [`BasePoint`] in the library.
/// ```
/// use secp256kfun::G;
/// assert_eq!(
///     format!("{}", G),
///     "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
/// );
/// ```
///
///[_SEC 2: Recommended Elliptic Curve Domain Parameters_]: https://www.secg.org/sec2-v2.pdf
///[`BasePoint`]: crate::marker::BasePoint
pub static G: &'static Point<marker::BasePoint, marker::Public, marker::NonZero> =
    &Point::from_inner(backend::G_JACOBIAN, marker::BasePoint(backend::G_TABLE));

#[doc(hidden)]
pub const TEST_SOUNDNESS: usize = 20;
