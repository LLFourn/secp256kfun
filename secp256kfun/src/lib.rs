#![feature(rustc_attrs, min_specialization, external_doc)]
#![doc(include = "../README.md")]
#![no_std]
#![allow(non_snake_case)]

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod hash;
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

#[cfg(feature = "serialization")]
pub extern crate serde;

pub static G: &'static Point<marker::BasePoint, marker::Public, marker::NonZero> =
    &Point::from_inner(backend::G_JACOBIAN, marker::BasePoint(backend::G_TABLE));

/// Error representing a failed conversion from hex into the bytes for the target type.
#[derive(Debug, Clone, PartialEq)]
pub enum HexError {
    /// The string was not a valid hex string.
    InvalidHex,
    /// The string was not the right length for the target type.
    InvalidLength,
    /// The bytes did not encode a valid value for the target type.
    InvalidEncoding,
}

#[doc(hidden)]
pub fn hex_val(c: u8) -> Result<u8, HexError> {
    match c {
        b'A'..=b'F' => Ok(c - b'A' + 10),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'0'..=b'9' => Ok(c - b'0'),
        _ => Err(HexError::InvalidHex),
    }
}

#[doc(hidden)]
pub const TEST_SOUNDNESS: usize = 20;
