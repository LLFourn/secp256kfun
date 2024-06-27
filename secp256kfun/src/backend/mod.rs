//! These traits are for accounting for what methods each backend actually needs.
mod k256_impl;

pub use k256_impl::*;

pub trait BackendScalar: Sized {
    fn minus_one() -> Self;
    fn from_u32(int: u32) -> Self;
    fn zero() -> Self;
    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self;
    fn from_bytes(bytes: [u8; 32]) -> Option<Self>;
    fn to_bytes(&self) -> [u8; 32];
}

pub trait BackendPoint {
    fn zero() -> Point;
    fn is_zero(&self) -> bool;
    fn norm_to_coordinates(&self) -> ([u8; 32], [u8; 32]);
    fn norm_from_bytes_y_oddness(x_bytes: [u8; 32], y_odd: bool) -> Option<Point>;
    fn norm_from_coordinates(x: [u8; 32], y: [u8; 32]) -> Option<Point>;
}

pub trait TimeSensitive {
    fn scalar_mul_norm_point(lhs: &Scalar, rhs: &Point) -> Point;
    fn scalar_mul_point(lhs: &Scalar, rhs: &Point) -> Point;
    fn scalar_eq(lhs: &Scalar, rhs: &Scalar) -> bool;
    fn point_eq_point(lhs: &Point, rhs: &Point) -> bool;
    fn point_normalize(point: &mut Point);
    fn point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool;
    fn point_add_point(lhs: &Point, rhs: &Point) -> Point;
    fn point_add_norm_point(lhs: &Point, rhs: &Point) -> Point;
    fn point_neg(point: &mut Point);
    fn point_conditional_negate(point: &mut Point, cond: bool);
    fn norm_point_neg(point: &mut Point);
    fn norm_point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool;
    fn norm_point_is_y_even(point: &Point) -> bool;
    fn norm_point_conditional_negate(point: &mut Point, cond: bool);
    #[allow(dead_code)] // we are not using basepoints acceleration for now
    fn basepoint_double_mul(x: &Scalar, A: &BasePoint, y: &Scalar, B: &Point) -> Point;
    fn point_double_mul(x: &Scalar, A: &Point, y: &Scalar, B: &Point) -> Point {
        let xA = Self::scalar_mul_point(x, A);
        let yB = Self::scalar_mul_point(y, B);
        Self::point_add_point(&xA, &yB)
    }
    fn scalar_add(lhs: &Scalar, rhs: &Scalar) -> Scalar;
    fn scalar_sub(lhs: &Scalar, rhs: &Scalar) -> Scalar;
    fn scalar_cond_negate(scalar: &mut Scalar, neg: bool);
    fn scalar_is_high(scalar: &Scalar) -> bool;
    fn scalar_is_zero(scalar: &Scalar) -> bool;
    fn scalar_mul(lhs: &Scalar, rhs: &Scalar) -> Scalar;
    fn scalar_invert(scalar: &Scalar) -> Scalar;
    fn scalar_mul_basepoint(scalar: &Scalar, base: &BasePoint) -> Point;
    fn lincomb_iter<
        A: Iterator<Item = AT>,
        B: Iterator<Item = BT>,
        AT: AsRef<Point>,
        BT: AsRef<Scalar>,
    >(
        points: A,
        scalars: B,
    ) -> Point {
        points.zip(scalars).fold(Point::zero(), |acc, (X, k)| {
            Self::point_add_point(&acc, &Self::scalar_mul_point(k.as_ref(), X.as_ref()))
        })
    }
    fn scalar_lincomb_iter<
        A: Iterator<Item = AT>,
        B: Iterator<Item = BT>,
        AT: AsRef<Scalar>,
        BT: AsRef<Scalar>,
    >(
        scalars1: A,
        scalars2: B,
    ) -> Scalar {
        scalars1.zip(scalars2).fold(Scalar::zero(), |acc, (a, b)| {
            Self::scalar_add(&acc, &Self::scalar_mul(a.as_ref(), b.as_ref()))
        })
    }
}
