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
//! let H = &G.normalize(); // scrub `BasePoint` marker
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
    Point, Scalar,
};

/// Computes `x * A + y * B` more efficiently than calling [`scalar_mul_point`] twice.
#[inline(always)]
pub fn double_mul<ZA, SA, TA, ZX, SX, ZB, SB, TB, ZY, SY>(
    x: &Scalar<SX, ZX>,
    A: &Point<TA, SA, ZA>,
    y: &Scalar<SY, ZY>,
    B: &Point<TB, SB, ZB>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(
        ConstantTime::point_double_mul(&x.0, &A.0, &y.0, &B.0),
        NonNormal,
    )
}

/// Computes multiplies the point `P` by the scalar `x`.
#[inline(always)]
pub fn scalar_mul_point<Z1, S1, T2, S2, Z2>(
    x: &Scalar<S1, Z1>,
    P: &Point<T2, S2, Z2>,
) -> Point<NonNormal, Public, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Point::from_inner(ConstantTime::scalar_mul_point(&x.0, &P.0), NonNormal)
}

/// Multiplies two scalars together (modulo the curve order)
#[inline(always)]
pub fn scalar_mul<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Scalar::from_inner(ConstantTime::scalar_mul(&x.0, &y.0))
}

/// Adds two scalars together (modulo the curve order)
#[inline(always)]
pub fn scalar_add<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ConstantTime::scalar_add(&x.0, &y.0))
}

/// Subtracts one scalar from another
#[inline(always)]
pub fn scalar_sub<Z1, Z2, S1, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ConstantTime::scalar_sub(&x.0, &y.0))
}

/// Checks equality between two scalars
#[inline(always)]
pub fn scalar_eq<Z1, S1, Z2, S2>(x: &Scalar<S1, Z1>, y: &Scalar<S2, Z2>) -> bool {
    ConstantTime::scalar_eq(&x.0, &y.0)
}

/// Negate a scalar
#[inline(always)]
pub fn scalar_negate<Z, S>(x: &Scalar<S, Z>) -> Scalar<S, Z> {
    let mut negated = x.0.clone();
    ConstantTime::scalar_cond_negate(&mut negated, true);
    Scalar::from_inner(negated)
}

/// Invert a scalar
#[inline(always)]
pub fn scalar_invert<S1>(x: &Scalar<S1, NonZero>) -> Scalar<S1, NonZero> {
    Scalar::from_inner(ConstantTime::scalar_invert(&x.0))
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
pub fn point_sub<Z1, S1, T1, Z2, S2, T2>(
    A: &Point<T1, S1, Z1>,
    B: &Point<T2, S2, Z2>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(ConstantTime::point_sub_point(&A.0, &B.0), NonNormal)
}

/// Adds two points together
#[inline(always)]
pub fn point_add<Z1, Z2, S1, S2, T1, T2>(
    A: &Point<T1, S1, Z1>,
    B: &Point<T2, S2, Z2>,
) -> Point<NonNormal, Public, Zero> {
    Point::from_inner(ConstantTime::point_add_point(&A.0, &B.0), NonNormal)
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
pub fn point_negate<T: PointType, S, Z>(A: &Point<T, S, Z>) -> Point<T::NegationType, S, Z> {
    let mut A = A.0.clone();
    ConstantTime::any_point_neg(&mut A);
    Point::from_inner(A, T::NegationType::default())
}

/// Conditionally negate a point
#[inline(always)]
pub fn point_conditional_negate<T: PointType, S, Z>(
    A: &Point<T, S, Z>,
    cond: bool,
) -> Point<T::NegationType, S, Z> {
    let mut A = A.0.clone();
    ConstantTime::any_point_conditional_negate(&mut A, cond);
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

/// Does a linear combination of points
#[inline(always)]
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

/// Check if a point has an even y-coordinate
#[inline(always)]
pub fn point_is_y_even<T: Normalized, S>(A: &Point<T, S, NonZero>) -> bool {
    ConstantTime::norm_point_is_y_even(&A.0)
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
            assert_eq!(lincomb([&a,&b,&c], [&A,&B,&C]),
                       point_add(&scalar_mul_point(&a, &A), &point_add(&scalar_mul_point(&b, &B), &scalar_mul_point(&c, &C))))
        }
    }
}
