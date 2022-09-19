mod field;
pub use field::FieldElement;
mod affine;
pub use affine::AffinePoint;
mod projective;
pub use projective::ProjectivePoint;
mod scalar;
pub use scalar::Scalar;
pub mod mul;
#[allow(unused)]
pub mod util;
use digest::generic_array::{typenum::U32, GenericArray};

const CURVE_EQUATION_B_SINGLE: u32 = 7u32;

#[rustfmt::skip]
const CURVE_EQUATION_B: FieldElement = FieldElement::from_bytes_unchecked(&[
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, CURVE_EQUATION_B_SINGLE as u8,
]);

/// secp256k1 (K-256) field element serialized as bytes.
///
/// Byte array containing a serialized field element value (base field or scalar).
pub type FieldBytes = GenericArray<u8, U32>;
