//! Affine points

use super::{FieldBytes, FieldElement, ProjectivePoint, Scalar, CURVE_EQUATION_B};
use core::ops::{Mul, Neg};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// x-coordinate
    pub(crate) x: FieldElement,

    /// y-coordinate
    pub(crate) y: FieldElement,

    /// Is this point the point at infinity? 0 = no, 1 = yes
    ///
    /// This is a proxy for [`Choice`], but uses `u8` instead to permit `const`
    /// constructors for `IDENTITY` and `GENERATOR`.
    pub(super) infinity: u8,
}

impl AffinePoint {
    /// Is this point the identity point?
    pub fn is_identity(&self) -> Choice {
        Choice::from(self.infinity)
    }
    /// Additive identity of the group: the point at infinity.
    pub const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ZERO,
        infinity: 1,
    };

    /// Base point of secp256k1.
    ///
    /// ```text
    /// Gₓ = 79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798
    /// Gᵧ = 483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8
    /// ```
    pub const GENERATOR: Self = Self {
        x: FieldElement::from_bytes_unchecked(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ]),
        y: FieldElement::from_bytes_unchecked(&[
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ]),
        infinity: 0,
    };
}

impl AffinePoint {
    /// Create a new [`AffinePoint`] with the given coordinates.
    pub(crate) const fn new(x: FieldElement, y: FieldElement) -> Self {
        Self { x, y, infinity: 0 }
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &AffinePoint, b: &AffinePoint, choice: Choice) -> AffinePoint {
        AffinePoint {
            x: FieldElement::conditional_select(&a.x, &b.x, choice),
            y: FieldElement::conditional_select(&a.y, &b.y, choice),
            infinity: u8::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &AffinePoint) -> Choice {
        (self.x.negate(1) + &other.x).normalizes_to_zero()
            & (self.y.negate(1) + &other.y).normalizes_to_zero()
            & self.infinity.ct_eq(&other.infinity)
    }
}

impl Default for AffinePoint {
    fn default() -> Self {
        Self::IDENTITY
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &AffinePoint) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}

impl Mul<Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Mul<&Scalar> for AffinePoint {
    type Output = ProjectivePoint;

    fn mul(self, scalar: &Scalar) -> ProjectivePoint {
        ProjectivePoint::from(self) * scalar
    }
}

impl Neg for AffinePoint {
    type Output = AffinePoint;

    fn neg(self) -> Self::Output {
        AffinePoint {
            x: self.x,
            y: self.y.negate(1).normalize_weak(),
            infinity: self.infinity,
        }
    }
}

impl AffinePoint {
    pub fn decompress(x_bytes: &FieldBytes, y_is_odd: Choice) -> CtOption<Self> {
        FieldElement::from_bytes(x_bytes).and_then(|x| {
            let alpha = (x * &x * &x) + &CURVE_EQUATION_B;
            let beta = alpha.sqrt();

            beta.map(|beta| {
                let beta = beta.normalize(); // Need to normalize for is_odd() to be consistent
                let y = FieldElement::conditional_select(
                    &beta.negate(1),
                    &beta,
                    beta.is_odd().ct_eq(&y_is_odd),
                );

                Self::new(x, y.normalize())
            })
        })
    }
}
