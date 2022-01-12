//! Operations in the secp256k1 group.
//!
//! The purpose of this module is to hold all the operations that can be done
//! with secp256k1 [`Points`] and [`Scalars`].  Usually, you shouldn't call
//! these directly but instead use the group [`g!`] and scalar [`s!`] expression
//! macros which compile your expressions into (potentially more efficient)
//! calls to these functions.
//!
//! Most of the functions here are [`specialized`] so the compiler may be able to
//! choose a faster algorithm depending on the arguments. For example scalar
//! multiplications are faster points marked `BasePoint` like [`G`], so in the
//! following snippet computing `X1` will be computed faster than `X2` even
//! though the same function is being called.
//! ```
//! use secp256kfun::{marker::*, op, Scalar, G};
//! let x = Scalar::random(&mut rand::thread_rng());
//! let X1 = op::scalar_mul_point(&x, G); // fast
//! let H = &G.clone().mark::<Normal>(); // scrub `BasePoint` marker
//! let X2 = op::scalar_mul_point(&x, &H); // slow
//! assert_eq!(X1, X2);
//! ```
//! [`Points`]: crate::Point
//! [`Scalars`]: crate::Scalar
//! [`specialized`]: https://github.com/rust-lang/rust/issues/31844
//! [`G`]: crate::G
#[allow(unused_imports)]
use crate::{
    backend::{self, ConstantTime, TimeSensitive, VariableTime},
    marker::*,
    Point, Scalar, XOnly,
};

/// Computes `x * A + y * B` more efficiently than calling [`scalar_mul_point`] twice.
pub fn double_mul<ZA, SA, TA, ZX, SX, ZB, SB, TB, ZY, SY>(
    x: &Scalar<SX, ZX>,
    A: &Point<TA, SA, ZA>,
    y: &Scalar<SY, ZY>,
    B: &Point<TB, SB, ZB>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(DoubleMul::double_mul((x, A, y, B)), Jacobian)
}

/// Computes multiplies the point `P` by the scalar `x`.
pub fn scalar_mul_point<Z1, S1, T2, S2, Z2>(
    x: &Scalar<S1, Z1>,
    P: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Point::from_inner(MulPoint::mul_point(x, P), Jacobian)
}

/// Multiplies two scalars together (modulo the curve order)
pub fn scalar_mul<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Scalar::from_inner(ScalarBinary::mul((x, y)))
}

/// Adds two scalars together (modulo the curve order)
pub fn scalar_add<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ScalarBinary::add((x, y)))
}

/// Subtracts one scalar from another
pub fn scalar_sub<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ScalarBinary::sub((x, y)))
}

/// Subtracts one point from another
pub fn point_sub<Z1, S1, T1, Z2, S2, T2>(
    A: &Point<T1, S1, Z1>,
    B: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(PointBinary::sub(A, B), Jacobian)
}

/// Adds two points together
pub fn point_add<Z1, Z2, S1, S2, T1, T2>(
    A: &Point<T1, S1, Z1>,
    B: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(PointBinary::add(A, B), Jacobian)
}

/// Does a linear combination of points
pub fn lincomb<'a, T1: 'a, S1: 'a, Z1: 'a, S2: 'a, Z2: 'a>(
    scalars: impl IntoIterator<Item = &'a Scalar<S2, Z2>>,
    points: impl IntoIterator<Item = &'a Point<T1, S1, Z1>>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(
        ConstantTime::lincomb_iter(
            points.into_iter().map(|p| &p.0),
            scalars.into_iter().map(|s| &s.0),
        ),
        Jacobian,
    )
}

pub(crate) trait PointBinary<T2, S2, Z2> {
    fn add(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point;
    fn sub(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point;
    fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool;
}

impl<T1, S1, Z1, T2, S2, Z2> PointBinary<T2, S2, Z2> for Point<T1, S1, Z1> {
    maybe_specialized! {
        fn add(&self, rhs: &Point<T2,S2,Z2>) -> backend::Point {
            ConstantTime::point_add_point(&self.0, &rhs.0)
        }
    }

    maybe_specialized! {
        fn sub(&self, rhs: &Point<T2,S2,Z2>) -> backend::Point {
            ConstantTime::point_sub_point(&self.0, &rhs.0)
        }
    }

    maybe_specialized! {
        fn eq(&self,rhs: &Point<T2,S2,Z2>) -> bool {
            ConstantTime::point_eq_point(&self.0, &rhs.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2, T1: Normalized, S1, S2, T2> PointBinary<T2, S2, Z2> for Point<T1, S1, Z1> {
    default fn add(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::point_add_norm_point(&rhs.0, &self.0)
    }

    default fn sub(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::norm_point_sub_point(&self.0, &rhs.0)
    }

    default fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool {
        ConstantTime::point_eq_norm_point(&rhs.0, &self.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2, S1, S2, T2: Normalized> PointBinary<T2, S2, Z2> for Point<Jacobian, S1, Z1> {
    default fn add(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::point_add_norm_point(&self.0, &rhs.0)
    }

    default fn sub(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::point_sub_norm_point(&self.0, &rhs.0)
    }

    default fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool {
        ConstantTime::point_eq_norm_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2> PointBinary<Jacobian, Public, Z2> for Point<Jacobian, Public, Z1> {
    fn add(&self, rhs: &Point<Jacobian, Public, Z2>) -> backend::Point {
        VariableTime::point_add_point(&self.0, &rhs.0)
    }

    fn sub(&self, rhs: &Point<Jacobian, Public, Z2>) -> backend::Point {
        VariableTime::point_sub_point(&self.0, &rhs.0)
    }

    fn eq(&self, rhs: &Point<Jacobian, Public, Z2>) -> bool {
        VariableTime::point_eq_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2, T1: Normalized, T2> PointBinary<T2, Public, Z2> for Point<T1, Public, Z1> {
    fn add(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::point_add_norm_point(&rhs.0, &self.0)
    }

    fn sub(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::norm_point_sub_point(&self.0, &rhs.0)
    }

    fn eq(&self, rhs: &Point<T2, Public, Z2>) -> bool {
        VariableTime::point_eq_norm_point(&rhs.0, &self.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2, T2: Normalized> PointBinary<T2, Public, Z2> for Point<Public, Jacobian, Z1> {
    fn add(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::point_add_norm_point(&self.0, &rhs.0)
    }

    fn sub(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::point_sub_norm_point(&self.0, &rhs.0)
    }

    fn eq(&self, rhs: &Point<T2, Public, Z2>) -> bool {
        VariableTime::point_eq_norm_point(&self.0, &rhs.0)
    }
}

pub(crate) trait PointEqXOnly {
    fn point_eq_xonly(&self, xonly: &XOnly) -> bool;
}

impl<T, S, Z> PointEqXOnly for Point<T, S, Z> {
    maybe_specialized! {
        fn point_eq_xonly(&self, xonly: &XOnly) -> bool {
            ConstantTime::point_eq_xonly(&self.0, &xonly.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<T, Z> PointEqXOnly for Point<T, Public, Z> {
    default fn point_eq_xonly(&self, xonly: &XOnly) -> bool {
        VariableTime::point_eq_xonly(&self.0, &xonly.0)
    }
}

#[cfg(feature = "nightly")]
impl<T: Normalized, Z> PointEqXOnly for Point<T, Secret, Z> {
    default fn point_eq_xonly(&self, xonly: &XOnly) -> bool {
        ConstantTime::norm_point_eq_xonly(&self.0, &xonly.0)
    }
}

#[cfg(feature = "nightly")]
impl<T: Normalized, Z> PointEqXOnly for Point<T, Public, Z> {
    fn point_eq_xonly(&self, xonly: &XOnly) -> bool {
        VariableTime::norm_point_eq_xonly(&self.0, &xonly.0)
    }
}

pub(crate) trait MulPoint<S2, T2> {
    fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point;
}

// we don't use the maybe_specialized! macro here because matching against fn level type parameters is tricky
impl<Z1, S1, S2, T2> MulPoint<S2, T2> for Scalar<S1, Z1> {
    #[cfg(not(feature = "nightly"))]
    fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_point(&self.0, &rhs.0)
    }

    #[cfg(feature = "nightly")]
    default fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, S1, S2, T2: NotBasePoint + Normalized> MulPoint<S2, T2> for Scalar<S1, Z1> {
    default fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_norm_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, S1, S2> MulPoint<S2, BasePoint> for Scalar<S1, Z1> {
    default fn mul_point<Z2>(&self, rhs: &Point<BasePoint, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_basepoint(&self.0, &(rhs.1).0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1> MulPoint<Public, Jacobian> for Scalar<Public, Z1> {
    fn mul_point<Z2>(&self, rhs: &Point<Jacobian, Public, Z2>) -> backend::Point {
        VariableTime::scalar_mul_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1, T2: Normalized + NotBasePoint> MulPoint<Public, T2> for Scalar<Public, Z1> {
    fn mul_point<Z2>(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::scalar_mul_norm_point(&self.0, &rhs.0)
    }
}

#[cfg(feature = "nightly")]
impl<Z1> MulPoint<Public, BasePoint> for Scalar<Public, Z1> {
    fn mul_point<Z2>(&self, rhs: &Point<BasePoint, Public, Z2>) -> backend::Point {
        VariableTime::scalar_mul_basepoint(&self.0, &(rhs.1).0)
    }
}

pub(crate) trait DoubleMul {
    fn double_mul(self) -> backend::Point;
}

impl<XZ, XS, AZ, AS, AT, YZ, YS, BZ, BS, BT> DoubleMul
    for (
        &Scalar<XS, XZ>,
        &Point<AT, AS, AZ>,
        &Scalar<YS, YZ>,
        &Point<BT, BS, BZ>,
    )
{
    maybe_specialized! {
        fn double_mul(self) -> backend::Point {
            let (x, A, y, B) = self;
            ConstantTime::point_double_mul(&x.0, &A.0, &y.0, &B.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<XZ, YZ, AT: NotBasePoint, BZ, BT: NotBasePoint, S1, S2> DoubleMul
    for (
        &Scalar<S1, XZ>,
        &Point<AT, Public, NonZero>,
        &Scalar<S2, YZ>,
        &Point<BT, Public, BZ>,
    )
{
    fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        VariableTime::point_double_mul(&x.0, &A.0, &y.0, &B.0)
    }
}

#[cfg(feature = "nightly")]
impl<XZ, YZ, BZ, BT, S1, S2> DoubleMul
    for (
        &Scalar<S1, XZ>,
        &Point<BasePoint, Public, NonZero>,
        &Scalar<S2, YZ>,
        &Point<BT, Public, BZ>,
    )
{
    default fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        ConstantTime::basepoint_double_mul(&x.0, &(A.1).0, &y.0, &B.0)
    }
}

#[cfg(feature = "nightly")]
impl<XZ, AT: NotBasePoint, AS, AZ, YZ, S1, S2> DoubleMul
    for (
        &Scalar<S1, XZ>,
        &Point<AT, AS, AZ>,
        &Scalar<S2, YZ>,
        &Point<BasePoint, Public, NonZero>,
    )
{
    default fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        ConstantTime::basepoint_double_mul(&y.0, &(B.1).0, &x.0, &A.0)
    }
}

#[cfg(feature = "nightly")]
impl<XZ, YZ, BZ, BT> DoubleMul
    for (
        &Scalar<Public, XZ>,
        &Point<BasePoint, Public, NonZero>,
        &Scalar<Public, YZ>,
        &Point<BT, Public, BZ>,
    )
{
    default fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        VariableTime::basepoint_double_mul(&x.0, &(A.1).0, &y.0, &B.0)
    }
}

#[cfg(feature = "nightly")]
impl<XZ, AZ, YZ, AT: NotBasePoint> DoubleMul
    for (
        &Scalar<Public, XZ>,
        &Point<AT, Public, AZ>,
        &Scalar<Public, YZ>,
        &Point<BasePoint, Public, NonZero>,
    )
{
    fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        VariableTime::basepoint_double_mul(&y.0, &(B.1).0, &x.0, &A.0)
    }
}

pub(crate) trait ScalarBinary {
    fn mul(self) -> backend::Scalar;
    fn add(self) -> backend::Scalar;
    fn sub(self) -> backend::Scalar;
    fn eq(self) -> bool;
}

impl<Z1, S1, Z2, S2> ScalarBinary for (&Scalar<S1, Z1>, &Scalar<S2, Z2>) {
    maybe_specialized! {
        fn mul(self) -> backend::Scalar {
            let (lhs, rhs) = self;
            ConstantTime::scalar_mul(&lhs.0, &rhs.0)
        }
    }

    maybe_specialized! {
        fn add(self) -> backend::Scalar {
            let (lhs, rhs) = self;
            ConstantTime::scalar_add(&lhs.0, &rhs.0)
        }
    }

    maybe_specialized! {
        fn sub(self) -> backend::Scalar {
            let (lhs, rhs) = self;
            ConstantTime::scalar_sub(&lhs.0, &rhs.0)
        }
    }

    maybe_specialized! {
        fn eq(self) -> bool {
            let (lhs, rhs) = self;
            ConstantTime::scalar_eq(&lhs.0, &rhs.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<Z1, Z2> ScalarBinary for (&Scalar<Public, Z1>, &Scalar<Public, Z2>) {
    fn mul(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        VariableTime::scalar_mul(&lhs.0, &rhs.0)
    }

    fn add(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        VariableTime::scalar_add(&lhs.0, &rhs.0)
    }

    fn sub(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        VariableTime::scalar_sub(&lhs.0, &rhs.0)
    }

    fn eq(self) -> bool {
        let (lhs, rhs) = self;
        ConstantTime::scalar_eq(&lhs.0, &rhs.0)
    }
}

pub(crate) trait ScalarUnary {
    fn negate(&self) -> backend::Scalar;
    fn invert(&self) -> backend::Scalar;
    fn conditional_negate(&mut self, cond: bool);
    fn is_high(&self) -> bool;
    fn is_zero(&self) -> bool;
}

impl<Z, S> ScalarUnary for Scalar<S, Z> {
    maybe_specialized! {
        fn negate(&self) -> backend::Scalar {
            let mut negated = self.0.clone();
            ConstantTime::scalar_cond_negate(&mut negated, true);
            negated
        }
    }

    maybe_specialized! {
        fn invert(&self) -> backend::Scalar {
            ConstantTime::scalar_invert(&self.0)
        }
    }

    maybe_specialized! {
        fn conditional_negate(&mut self, cond: bool) {
            ConstantTime::scalar_cond_negate(&mut self.0, cond)
        }
    }

    maybe_specialized! {
        fn is_high(&self) -> bool {
            ConstantTime::scalar_is_high(&self.0)
        }
    }

    maybe_specialized! {
        fn is_zero(&self) -> bool {
            ConstantTime::scalar_is_zero(&self.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<Z> ScalarUnary for Scalar<Public, Z> {
    fn negate(&self) -> backend::Scalar {
        let mut negated = self.0.clone();
        VariableTime::scalar_cond_negate(&mut negated, true);
        negated
    }

    fn invert(&self) -> backend::Scalar {
        VariableTime::scalar_invert(&self.0)
    }

    fn conditional_negate(&mut self, cond: bool) {
        VariableTime::scalar_cond_negate(&mut self.0, cond)
    }

    fn is_high(&self) -> bool {
        VariableTime::scalar_is_high(&self.0)
    }

    fn is_zero(&self) -> bool {
        VariableTime::scalar_is_zero(&self.0)
    }
}

pub(crate) trait PointUnary {
    fn negate(self) -> backend::Point;
    fn conditional_negate(self, cond: bool) -> backend::Point;
    fn normalize(self) -> backend::Point;
}

pub(crate) trait NormPointUnary {
    fn is_y_even(&self) -> bool;
}

impl<T, S, Z> PointUnary for Point<T, Z, S> {
    maybe_specialized! {
        fn negate(mut self) -> backend::Point {
            ConstantTime::any_point_neg(&mut self.0);
            self.0
        }
    }

    maybe_specialized! {
        fn conditional_negate(mut self, cond: bool) -> backend::Point {
            ConstantTime::any_point_conditional_negate(&mut self.0, cond);
            self.0
        }
    }

    maybe_specialized! {
        fn normalize(mut self) -> backend::Point {
            ConstantTime::point_normalize(&mut self.0);
            self.0
        }
    }
}

#[cfg(feature = "nightly")]
impl<Z> PointUnary for Point<Jacobian, Z, Secret> {
    fn negate(mut self) -> backend::Point {
        ConstantTime::point_neg(&mut self.0);
        self.0
    }

    fn conditional_negate(mut self, cond: bool) -> backend::Point {
        ConstantTime::point_conditional_negate(&mut self.0, cond);
        self.0
    }
}

#[cfg(feature = "nightly")]
impl<T: Normalized, S, Z> PointUnary for Point<T, Z, S> {
    default fn negate(mut self) -> backend::Point {
        ConstantTime::norm_point_neg(&mut self.0);
        self.0
    }

    default fn conditional_negate(mut self, cond: bool) -> backend::Point {
        ConstantTime::norm_point_conditional_negate(&mut self.0, cond);
        self.0
    }

    default fn normalize(self) -> backend::Point {
        self.0
    }
}

#[cfg(feature = "nightly")]
impl<Z> PointUnary for Point<Jacobian, Z, Public> {
    default fn negate(mut self) -> backend::Point {
        VariableTime::point_neg(&mut self.0);
        self.0
    }

    default fn conditional_negate(mut self, cond: bool) -> backend::Point {
        VariableTime::point_conditional_negate(&mut self.0, cond);
        self.0
    }

    default fn normalize(mut self) -> backend::Point {
        VariableTime::point_normalize(&mut self.0);
        self.0
    }
}

#[cfg(feature = "nightly")]
impl<T: Normalized, Z> PointUnary for Point<T, Z, Public> {
    fn negate(mut self) -> backend::Point {
        VariableTime::norm_point_neg(&mut self.0);
        self.0
    }

    fn conditional_negate(mut self, cond: bool) -> backend::Point {
        VariableTime::norm_point_conditional_negate(&mut self.0, cond);
        self.0
    }
}

impl<T: Normalized, Z, S> NormPointUnary for Point<T, Z, S> {
    maybe_specialized! {
        fn is_y_even(&self) -> bool {
            ConstantTime::norm_point_is_y_even(&self.0)
        }
    }
}

#[cfg(feature = "nightly")]
impl<T: Normalized, Z> NormPointUnary for Point<T, Z, Public> {
    fn is_y_even(&self) -> bool {
        VariableTime::norm_point_is_y_even(&self.0)
    }
}

#[cfg(test)]
mod test {
    use crate::{g, marker::*, Point, Scalar, G};
    use core::str::FromStr;

    #[test]
    fn double_mul_spec_edgecase() {
        // a random bug that took some time to track down.
        let s = Scalar::<Secret, NonZero>::from_str(
            "45941667583c8cfd65e01f696b1864c5c6a896a2722b6ebaddaf332a31ab42a9",
        )
        .unwrap();
        let minus_c = Scalar::<Public, Zero>::from_str(
            "90a10ba834c19b1e89c3ce7d7d733a8cd9c16e73c2f7b45aa5495f7a20765a8f",
        )
        .unwrap();
        let X = Point::<Normal, Public, NonZero>::from_str(
            "02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af",
        )
        .unwrap()
        .mark::<Zero>();
        let R_implied = g!(s * G + minus_c * X).normalize();
        let R_expected = Point::<Normal, Public, NonZero>::from_str(
            "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
        )
        .unwrap();
        assert_eq!(R_implied, R_expected);
    }

    use proptest::prelude::*;

    proptest! {

        #[test]
        fn lincomb_against_mul(a in any::<Scalar>(),
                               b in any::<Scalar>(),
                               c in any::<Scalar>(),
                               A in any::<Point>(),
                               B in any::<Point>(),
                               C in any::<Point>()
        ) {
            use crate::op::*;
            assert_eq!(lincomb([&a,&b,&c], [&A,&B,&C]),
                       point_add(&scalar_mul_point(&a, &A), &point_add(&scalar_mul_point(&b, &B), &scalar_mul_point(&c, &C))))
        }
    }
}
