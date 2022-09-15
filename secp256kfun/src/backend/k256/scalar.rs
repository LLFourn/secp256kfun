//! Scalar field arithmetic.

#[cfg(target_pointer_width = "64")]
mod scalar_4x64;
#[cfg(target_pointer_width = "64")]
use scalar_4x64::Scalar4x64 as ScalarImpl;

#[cfg(target_pointer_width = "32")]
mod scalar_8x32;
#[cfg(target_pointer_width = "32")]
use scalar_8x32::Scalar8x32 as ScalarImpl;

use super::FieldBytes;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shr, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Scalars are elements in the finite field modulo n.
#[derive(Clone, Copy, Debug, Default)]
pub struct Scalar(ScalarImpl);

impl Scalar {
    /// Zero scalar.
    pub const ZERO: Self = Self(ScalarImpl::zero());

    /// Attempts to parse the given byte array as an SEC1-encoded scalar.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    pub fn from_repr(bytes: FieldBytes) -> Option<Self> {
        ScalarImpl::from_bytes(bytes.as_ref()).map(Self).into()
    }
    /// Multiplicative identity.
    pub const ONE: Self = Self(ScalarImpl::one());

    /// Checks if the scalar is zero.
    pub fn is_zero(&self) -> Choice {
        self.0.is_zero()
    }

    /// Attempts to parse the given byte array as a scalar.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        Self(ScalarImpl::from_bytes_unchecked(bytes))
    }

    /// Parses the given byte array as a scalar.
    ///
    /// Subtracts the modulus when the byte array is larger than the modulus.
    pub fn from_bytes_reduced(bytes: &FieldBytes) -> Self {
        Self(ScalarImpl::from_bytes_reduced(bytes.as_ref()))
    }

    /// Returns the SEC1 encoding of this scalar.
    pub fn to_bytes(&self) -> FieldBytes {
        self.0.to_bytes()
    }

    /// Is this scalar greater than or equal to n / 2?
    pub fn is_high(&self) -> Choice {
        self.0.is_high()
    }

    /// Negates the scalar.
    pub fn negate(&self) -> Self {
        Self(self.0.negate())
    }

    /// Modulo adds two scalars
    pub fn add(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.add(&(rhs.0)))
    }

    /// Modulo subtracts one scalar from the other.
    pub fn sub(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.sub(&(rhs.0)))
    }

    /// Modulo multiplies two scalars.
    pub fn mul(&self, rhs: &Scalar) -> Scalar {
        Self(self.0.mul(&(rhs.0)))
    }

    /// Modulo squares the scalar.
    pub fn square(&self) -> Self {
        self.mul(&self)
    }

    /// Right shifts the scalar. Note: not constant-time in `shift`.
    pub fn rshift(&self, shift: usize) -> Scalar {
        Self(self.0.rshift(shift))
    }

    /// Raises the scalar to the power `2^k`
    fn pow2k(&self, k: usize) -> Self {
        let mut x = *self;
        for _j in 0..k {
            x = x.square();
        }
        x
    }

    /// Inverts the scalar.
    pub fn invert(&self) -> CtOption<Self> {
        // Using an addition chain from
        // https://briansmith.org/ecc-inversion-addition-chains-01#secp256k1_scalar_inversion

        let x_1 = *self;
        let x_10 = self.pow2k(1);
        let x_11 = x_10.mul(&x_1);
        let x_101 = x_10.mul(&x_11);
        let x_111 = x_10.mul(&x_101);
        let x_1001 = x_10.mul(&x_111);
        let x_1011 = x_10.mul(&x_1001);
        let x_1101 = x_10.mul(&x_1011);

        let x6 = x_1101.pow2k(2).mul(&x_1011);
        let x8 = x6.pow2k(2).mul(&x_11);
        let x14 = x8.pow2k(6).mul(&x6);
        let x28 = x14.pow2k(14).mul(&x14);
        let x56 = x28.pow2k(28).mul(&x28);

        #[rustfmt::skip]
            let res = x56
            .pow2k(56).mul(&x56)
            .pow2k(14).mul(&x14)
            .pow2k(3).mul(&x_101)
            .pow2k(4).mul(&x_111)
            .pow2k(4).mul(&x_101)
            .pow2k(5).mul(&x_1011)
            .pow2k(4).mul(&x_1011)
            .pow2k(4).mul(&x_111)
            .pow2k(5).mul(&x_111)
            .pow2k(6).mul(&x_1101)
            .pow2k(4).mul(&x_101)
            .pow2k(3).mul(&x_111)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_101)
            .pow2k(10).mul(&x_111)
            .pow2k(4).mul(&x_111)
            .pow2k(9).mul(&x8)
            .pow2k(5).mul(&x_1001)
            .pow2k(6).mul(&x_1011)
            .pow2k(4).mul(&x_1101)
            .pow2k(5).mul(&x_11)
            .pow2k(6).mul(&x_1101)
            .pow2k(10).mul(&x_1101)
            .pow2k(4).mul(&x_1001)
            .pow2k(6).mul(&x_1)
            .pow2k(8).mul(&x6);

        CtOption::new(res, !self.is_zero())
    }
}

impl Scalar {
    /// Multiplies `self` by `b` (without modulo reduction) divide the result by `2^shift`
    /// (rounding to the nearest integer).
    /// Variable time in `shift`.
    pub fn mul_shift_var(&self, b: &Scalar, shift: usize) -> Self {
        Self(self.0.mul_shift_var(&(b.0), shift))
    }

    /// Tonelli-Shank's algorithm for q mod 16 = 1
    /// <https://eprint.iacr.org/2012/685.pdf> (page 12, algorithm 5)
    #[allow(clippy::many_single_char_names)]
    pub fn sqrt(&self) -> CtOption<Self> {
        // Note: `pow_vartime` is constant-time with respect to `self`
        let w = self.pow_vartime(&[
            0x777fa4bd19a06c82,
            0xfd755db9cd5e9140,
            0xffffffffffffffff,
            0x1ffffffffffffff,
        ]);

        let mut v = Self::S;
        let mut x = *self * w;
        let mut b = x * w;
        let mut z = Self::root_of_unity();

        for max_v in (1..=Self::S).rev() {
            let mut k = 1;
            let mut tmp = b.square();
            let mut j_less_than_v = Choice::from(1);

            for j in 2..max_v {
                let tmp_is_one = tmp.ct_eq(&Self::ONE);
                let squared = Self::conditional_select(&tmp, &z, tmp_is_one).square();
                tmp = Self::conditional_select(&squared, &tmp, tmp_is_one);
                let new_z = Self::conditional_select(&z, &squared, tmp_is_one);
                j_less_than_v &= !j.ct_eq(&v);
                k = u32::conditional_select(&j, &k, tmp_is_one);
                z = Self::conditional_select(&z, &new_z, j_less_than_v);
            }

            let result = x * z;
            x = Self::conditional_select(&result, &x, b.ct_eq(&Self::ONE));
            z = z.square();
            b *= z;
            v = k;
        }

        CtOption::new(x, x.square().ct_eq(self))
    }

    /// Exponentiates `self` by `exp`, where `exp` is a little-endian order
    /// integer exponent.
    ///
    /// **This operation is variable time with respect to the exponent.** If the
    /// exponent is fixed, this operation is effectively constant time.
    fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::ONE;
        for e in exp.as_ref().iter().rev() {
            for i in (0..64).rev() {
                res = res.square();

                if ((*e >> i) & 1) == 1 {
                    res.mul_assign(self);
                }
            }
        }

        res
    }
}

impl Scalar {
    const S: u32 = 6;

    pub fn is_odd(&self) -> Choice {
        self.0.is_odd()
    }

    fn root_of_unity() -> Self {
        Scalar::from_bytes_unchecked(&[
            0x0c, 0x1d, 0xc0, 0x60, 0xe7, 0xa9, 0x19, 0x86, 0xdf, 0x98, 0x79, 0xa3, 0xfb, 0xc4,
            0x83, 0xa8, 0x98, 0xbd, 0xea, 0xb6, 0x80, 0x75, 0x60, 0x45, 0x99, 0x2f, 0x4b, 0x54,
            0x02, 0xb0, 0x52, 0xf2,
        ])
    }
}

impl From<u32> for Scalar {
    fn from(k: u32) -> Self {
        Self::from(k as u64)
    }
}

impl From<u64> for Scalar {
    fn from(k: u64) -> Self {
        Self(k.into())
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(self, rhs: usize) -> Self::Output {
        self.rshift(rhs)
    }
}

impl Shr<usize> for &Scalar {
    type Output = Scalar;

    fn shr(self, rhs: usize) -> Self::Output {
        self.rshift(rhs)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(ScalarImpl::conditional_select(&(a.0), &(b.0), choice))
    }
}
impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&(other.0))
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

impl Neg for Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Neg for &Scalar {
    type Output = Scalar;

    fn neg(self) -> Scalar {
        self.negate()
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(&self, &other)
    }
}

impl Add<&Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(self, other)
    }
}

impl Add<Scalar> for &Scalar {
    type Output = Scalar;

    fn add(self, other: Scalar) -> Scalar {
        Scalar::add(self, &other)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Scalar;

    fn add(self, other: &Scalar) -> Scalar {
        Scalar::add(&self, other)
    }
}

impl AddAssign<Scalar> for Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        *self = Scalar::add(self, &rhs);
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::add(self, rhs);
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: Scalar) -> Scalar {
        Scalar::sub(&self, &other)
    }
}

impl Sub<&Scalar> for &Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(self, other)
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Scalar;

    fn sub(self, other: &Scalar) -> Scalar {
        Scalar::sub(&self, other)
    }
}

impl SubAssign<Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: Scalar) {
        *self = Scalar::sub(self, &rhs);
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::sub(self, rhs);
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: Scalar) -> Scalar {
        Scalar::mul(&self, &other)
    }
}

impl Mul<&Scalar> for &Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(self, other)
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Scalar;

    fn mul(self, other: &Scalar) -> Scalar {
        Scalar::mul(&self, other)
    }
}

impl MulAssign<Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = Scalar::mul(self, &rhs);
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Scalar) {
        *self = Scalar::mul(self, rhs);
    }
}

impl From<Scalar> for FieldBytes {
    fn from(scalar: Scalar) -> Self {
        scalar.to_bytes()
    }
}

impl From<&Scalar> for FieldBytes {
    fn from(scalar: &Scalar) -> Self {
        scalar.to_bytes()
    }
}
