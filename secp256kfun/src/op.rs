//! Operations in the secp256k1 group.
//!
//! The purpose of this module is to hold all the operations that can be done
//! with secp256k1 [`Points`] and [`Scalars`].  Usually, you shouldn't call
//! these directly but instead use the group [`g!`] and scalar [`s!`] expression
//! macros which compile your expressions into (potentially more efficient)
//! calls to these functions.
//!
//! Some of the functions here use the type parameters to try and optimize the operation they
//! perform.
//!
//! [`Points`]: crate::Point
//! [`Scalars`]: crate::Scalar
#[allow(unused_imports)]
use crate::{
    backend::{self, ConstantTime, TimeSensitive, VariableTime},
    marker::*,
    Point, Scalar,
};
use core::borrow::Borrow;

/// Computes `x * A + y * B` more efficiently than calling [`scalar_mul_point`] twice.
#[inline(always)]
pub fn double_mul<ZA, SA, TA, ZX, SX, ZB, SB, TB, ZY, SY>(
    x: impl Borrow<Scalar<SX, ZX>>,
    A: impl Borrow<Point<TA, SA, ZA>>,
    y: impl Borrow<Scalar<SY, ZY>>,
    B: impl Borrow<Point<TB, SB, ZB>>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(
        ConstantTime::point_double_mul(&x.borrow().0, &A.borrow().0, &y.borrow().0, &B.borrow().0),
        NonNormal,
    )
}

/// Computes multiplies the point `P` by the scalar `x`.
#[inline(always)]
pub fn scalar_mul_point<Z1, S1, T2, S2, Z2>(
    x: impl Borrow<Scalar<S1, Z1>>,
    P: impl Borrow<Point<T2, S2, Z2>>,
) -> Point<NonNormal, Public, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Point::from_inner(
        ConstantTime::scalar_mul_point(&x.borrow().0, &P.borrow().0),
        NonNormal,
    )
}

/// Multiplies two scalars together (modulo the curve order)
#[inline(always)]
pub fn scalar_mul<Z1, Z2, S1, S2>(
    x: impl Borrow<Scalar<S1, Z1>>,
    y: impl Borrow<Scalar<S2, Z2>>,
) -> Scalar<Secret, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Scalar::from_inner(ConstantTime::scalar_mul(&x.borrow().0, &y.borrow().0))
}

/// Adds two scalars together (modulo the curve order)
#[inline(always)]
pub fn scalar_add<Z1, Z2, S1, S2>(
    x: impl Borrow<Scalar<S1, Z1>>,
    y: impl Borrow<Scalar<S2, Z2>>,
) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ConstantTime::scalar_add(&x.borrow().0, &y.borrow().0))
}

/// Subtracts one scalar from another
#[inline(always)]
pub fn scalar_sub<Z1, Z2, S1, S2>(
    x: impl Borrow<Scalar<S1, Z1>>,
    y: impl Borrow<Scalar<S2, Z2>>,
) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ConstantTime::scalar_sub(&x.borrow().0, &y.borrow().0))
}

/// Checks equality between two scalars
#[inline(always)]
pub fn scalar_eq<Z1, S1, Z2, S2>(
    x: impl Borrow<Scalar<S1, Z1>>,
    y: impl Borrow<Scalar<S2, Z2>>,
) -> bool {
    ConstantTime::scalar_eq(&x.borrow().0, &y.borrow().0)
}

/// Negate a scalar
#[inline(always)]
pub fn scalar_negate<Z, S>(x: impl Borrow<Scalar<S, Z>>) -> Scalar<S, Z> {
    let mut negated = x.borrow().0;
    ConstantTime::scalar_cond_negate(&mut negated, true);
    Scalar::from_inner(negated)
}

/// Invert a scalar
#[inline(always)]
pub fn scalar_invert<S1>(x: impl Borrow<Scalar<S1, NonZero>>) -> Scalar<S1, NonZero> {
    Scalar::from_inner(ConstantTime::scalar_invert(&x.borrow().0))
}

/// Conditionally negate a scalar
#[inline(always)]
pub fn scalar_conditional_negate<S, Z>(x: &mut Scalar<S, Z>, cond: bool) {
    ConstantTime::scalar_cond_negate(&mut x.0, cond)
}

/// Check if the scalar is high
#[inline(always)]
pub fn scalar_is_high<S, Z>(x: &Scalar<S, Z>) -> bool {
    ConstantTime::scalar_is_high(&x.0)
}

/// Check if the scalar is zero
#[inline(always)]
pub fn scalar_is_zero<S, Z>(x: &Scalar<S, Z>) -> bool {
    ConstantTime::scalar_is_zero(&x.0)
}

/// Subtracts one point from another
#[inline(always)]
pub fn point_sub<Z1, S1, T1: PointType, Z2, S2, T2: PointType>(
    A: impl Borrow<Point<T1, S1, Z1>>,
    B: impl Borrow<Point<T2, S2, Z2>>,
) -> Point<NonNormal, Public, Zero> {
    point_add(A, point_negate(B))
}

/// Adds two points together
#[inline(always)]
pub fn point_add<Z1, Z2, S1, S2, T1: PointType, T2: PointType>(
    A: impl Borrow<Point<T1, S1, Z1>>,
    B: impl Borrow<Point<T2, S2, Z2>>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(
        if T1::is_normalized() {
            ConstantTime::point_add_norm_point(&B.borrow().0, &A.borrow().0)
        } else if T2::is_normalized() {
            ConstantTime::point_add_norm_point(&A.borrow().0, &B.borrow().0)
        } else {
            ConstantTime::point_add_point(&A.borrow().0, &B.borrow().0)
        },
        NonNormal,
    )
}

/// Checks if two points are equal
#[inline(always)]
pub fn point_eq<Z1, Z2, S1, S2, T1, T2>(A: &Point<T1, S1, Z1>, B: &Point<T2, S2, Z2>) -> bool
where
    T1: PointType,
    T2: PointType,
{
    match (T1::is_normalized(), T2::is_normalized()) {
        (true, true) => ConstantTime::norm_point_eq_norm_point(&A.0, &B.0),
        (true, false) => ConstantTime::point_eq_norm_point(&B.0, &A.0),
        (false, true) => ConstantTime::point_eq_norm_point(&A.0, &B.0),
        (false, false) => ConstantTime::point_eq_point(&A.0, &B.0),
    }
}

/// Negate a point
#[inline(always)]
pub fn point_negate<T: PointType, S, Z>(
    A: impl Borrow<Point<T, S, Z>>,
) -> Point<T::NegationType, S, Z> {
    let mut A = A.borrow().0;
    if T::is_normalized() {
        ConstantTime::norm_point_neg(&mut A);
    } else {
        ConstantTime::point_neg(&mut A);
    }

    Point::from_inner(A, T::NegationType::default())
}

/// Conditionally negate a point
#[inline(always)]
pub fn point_conditional_negate<T: PointType, S, Z>(
    A: impl Borrow<Point<T, S, Z>>,
    cond: bool,
) -> Point<T::NegationType, S, Z> {
    let mut A = A.borrow().0;

    if T::is_normalized() {
        ConstantTime::norm_point_conditional_negate(&mut A, cond);
    } else {
        ConstantTime::point_conditional_negate(&mut A, cond);
    }

    Point::from_inner(A, T::NegationType::default())
}

/// Normalize a point
#[inline(always)]
pub fn point_normalize<T, S, Z>(mut A: Point<T, S, Z>) -> Point<Normal, S, Z>
where
    T: PointType,
{
    if !T::is_normalized() {
        ConstantTime::point_normalize(&mut A.0);
    }
    Point::from_inner(A.0, Normal)
}

/// Does a [dot product](https://en.wikipedia.org/wiki/Dot_product) of points with scalars
///
/// If one of the iterators is longer than the other then the excess points or scalars will be
/// multiplied by 0.
#[inline(always)]
pub fn point_scalar_dot_product<
    T1,
    S1,
    Z1,
    S2,
    Z2,
    I2: Borrow<Scalar<S2, Z2>> + AsRef<backend::Scalar>,
    I1: Borrow<Point<T1, S1, Z1>> + AsRef<backend::Point>,
>(
    scalars: impl IntoIterator<Item = I2>,
    points: impl IntoIterator<Item = I1>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(
        ConstantTime::lincomb_iter(points.into_iter(), scalars.into_iter()),
        NonNormal,
    )
}

/// Does a linear combination of points
///
/// ⚠ deprecated in favor of [`point_scalar_dot_product`] which has a more convienient API and name.
#[inline(always)]
#[deprecated(since = "0.10.0", note = "use point_scalar_dot_product instead")]
pub fn lincomb<'a, T1: 'a, S1: 'a, Z1: 'a, S2: 'a, Z2: 'a>(
    scalars: impl IntoIterator<Item = &'a Scalar<S2, Z2>>,
    points: impl IntoIterator<Item = &'a Point<T1, S1, Z1>>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(
        ConstantTime::lincomb_iter(
            points.into_iter().map(|p| &p.0),
            scalars.into_iter().map(|s| &s.0),
        ),
        NonNormal,
    )
}

#[inline(always)]
/// Does a [dot product] between two iterators of scalars.
///
/// If one of the iterators is longer than the other then the excess scalars will be multipled by 0.
pub fn scalar_dot_product<
    S1,
    Z1,
    S2,
    Z2,
    I1: Borrow<Scalar<S1, Z1>> + AsRef<backend::Scalar>,
    I2: Borrow<Scalar<S2, Z2>> + AsRef<backend::Scalar>,
>(
    scalars1: impl IntoIterator<Item = I1>,
    scalars2: impl IntoIterator<Item = I2>,
) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ConstantTime::scalar_lincomb_iter(
        scalars1.into_iter(),
        scalars2.into_iter(),
    ))
}

/// Check if a point has an even y-coordinate
#[inline(always)]
pub fn point_is_y_even<T: Normalized, S>(A: &Point<T, S, NonZero>) -> bool {
    ConstantTime::norm_point_is_y_even(&A.0)
}

#[cfg(test)]
mod test {
    use crate::{marker::*, Point, Scalar, G};
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
        .mark_zero();
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
            assert_eq!(point_scalar_dot_product([&a,&b,&c], [&A,&B,&C]),
                       point_add(scalar_mul_point(a, A), point_add(scalar_mul_point(b, B), scalar_mul_point(c, C))))
        }
    }
}
