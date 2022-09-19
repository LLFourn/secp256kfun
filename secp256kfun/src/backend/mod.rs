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
    fn point_sub_point(lhs: &Point, rhs: &Point) -> Point {
        let mut rhs = rhs.clone();
        Self::point_neg(&mut rhs);
        Self::point_add_point(lhs, &rhs)
    }
    // "any" variants are because doing a jacobian point neg is not good enough for a normalized
    // point neg so for the general case we have to have a slower one that works for both.
    fn any_point_neg(point: &mut Point);
    fn any_point_conditional_negate(point: &mut Point, cond: bool);
    fn point_neg(point: &mut Point);
    fn point_sub_norm_point(lhs: &Point, rhs: &Point) -> Point;
    fn point_conditional_negate(point: &mut Point, cond: bool);
    fn norm_point_sub_point(lhs: &Point, rhs: &Point) -> Point;
    fn norm_point_neg(point: &mut Point);
    fn norm_point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool;
    fn norm_point_is_y_even(point: &Point) -> bool;
    fn norm_point_conditional_negate(point: &mut Point, cond: bool);
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
    fn lincomb_iter<'a, 'b, A: Iterator<Item = &'a Point>, B: Iterator<Item = &'b Scalar>>(
        points: A,
        scalars: B,
    ) -> Point {
        points.zip(scalars).fold(Point::zero(), |acc, (X, k)| {
            Self::point_add_point(&acc, &Self::scalar_mul_point(k, X))
        })
    }
}
