pub use crate::vendor::k256::Scalar;
use crate::{
    backend::{BackendPoint, BackendScalar, TimeSensitive},
    vendor::k256::{mul, AffinePoint, FieldBytes, FieldElement, ProjectivePoint},
};
use core::ops::Neg;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

pub static G_POINT: ProjectivePoint = ProjectivePoint::GENERATOR;
pub type Point = ProjectivePoint;
// We don't implement multiplication tables yet
pub type BasePoint = ProjectivePoint;

impl BackendScalar for Scalar {
    fn minus_one() -> Self {
        -Scalar::ONE
    }

    fn from_u32(int: u32) -> Self {
        Self::from(int)
    }

    fn zero() -> Self {
        Scalar::ZERO
    }

    fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Scalar::from_bytes_reduced(&FieldBytes::from(bytes))
    }

    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Scalar::from_repr(FieldBytes::from(bytes))
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.to_bytes().into()
    }
}

impl BackendPoint for Point {
    fn zero() -> Point {
        ProjectivePoint::IDENTITY
    }

    fn is_zero(&self) -> bool {
        self.is_identity().into()
    }

    fn norm_to_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        (self.x.to_bytes().into(), self.y.to_bytes().into())
    }

    fn norm_from_bytes_y_oddness(x_bytes: [u8; 32], y_odd: bool) -> Option<Point> {
        let x_bytes = FieldBytes::from(x_bytes);
        let option: Option<AffinePoint> =
            AffinePoint::decompress(&x_bytes, (y_odd as u8).into()).into();
        option.map(|affine| affine.into())
    }

    fn norm_from_coordinates(x: [u8; 32], y: [u8; 32]) -> Option<Point> {
        let x = Option::from(FieldElement::from_bytes(&FieldBytes::from(x)))?;
        let y = Option::from(FieldElement::from_bytes(&FieldBytes::from(y)))?;
        Some(AffinePoint::new(x, y).into())
    }
}

pub struct ConstantTime;

impl TimeSensitive for ConstantTime {
    fn scalar_mul_norm_point(lhs: &Scalar, rhs: &Point) -> Point {
        rhs * lhs
    }

    fn scalar_mul_point(lhs: &Scalar, rhs: &Point) -> Point {
        rhs * lhs
    }

    fn scalar_eq(lhs: &Scalar, rhs: &Scalar) -> bool {
        lhs.ct_eq(rhs).into()
    }

    fn point_normalize(point: &mut Point) {
        let zinv_opt = point.z.invert();
        let was_zero = zinv_opt.is_none();
        let zinv = zinv_opt.unwrap_or(FieldElement::ONE);
        point.x *= zinv;
        point.y *= zinv;
        point.x = point.x.normalize();
        point.y = point.y.normalize();
        point.z.conditional_assign(&FieldElement::ONE, !was_zero);
    }

    fn point_eq_point(lhs: &Point, rhs: &Point) -> bool {
        lhs.ct_eq(rhs).into()
    }

    fn point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool {
        let rhs = norm_point_to_affine(rhs);
        lhs.eq_affine(&rhs).into()
    }

    fn point_add_point(lhs: &Point, rhs: &Point) -> Point {
        lhs + rhs
    }

    fn point_add_norm_point(lhs: &Point, rhs: &Point) -> Point {
        // use more efficient version for affine
        let rhs = norm_point_to_affine(rhs);
        lhs + &rhs
    }

    fn any_point_neg(point: &mut Point) {
        point.y = point.y.negate(1).normalize()
    }

    fn any_point_conditional_negate(point: &mut Point, cond: bool) {
        point.conditional_negate(Choice::from(cond as u8));
        point.y = point.y.normalize()
    }

    fn point_neg(point: &mut Point) {
        point.y = point.y.negate(1).normalize_weak()
    }

    fn point_sub_norm_point(lhs: &Point, rhs: &Point) -> Point {
        let rhs = norm_point_to_affine(rhs);
        lhs + &rhs.neg()
    }

    fn point_conditional_negate(point: &mut Point, cond: bool) {
        Self::any_point_conditional_negate(point, cond)
    }

    fn norm_point_sub_point(lhs: &Point, rhs: &Point) -> Point {
        let lhs = norm_point_to_affine(lhs);
        &rhs.neg() + &lhs
    }

    fn norm_point_neg(point: &mut Point) {
        Self::any_point_neg(point)
    }

    fn norm_point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool {
        let both_infinity = Choice::from((lhs.is_zero() && rhs.is_zero()) as u8);
        (both_infinity | lhs.x.ct_eq(&rhs.x) & lhs.y.ct_eq(&rhs.y)).into()
    }

    fn norm_point_is_y_even(point: &Point) -> bool {
        (!point.y.is_odd()).into()
    }

    fn norm_point_conditional_negate(point: &mut Point, cond: bool) {
        Self::any_point_conditional_negate(point, cond)
    }

    fn basepoint_double_mul(x: &Scalar, A: &BasePoint, y: &Scalar, B: &Point) -> Point {
        Self::point_double_mul(x, A, y, B)
    }

    // Only use the "lincomb" method if we don't have alloc. If we do we might as well use the
    // allocating verison to avoid compiling two methods that do the same thing.
    #[cfg(not(feature = "alloc"))]
    fn point_double_mul(x: &Scalar, A: &Point, y: &Scalar, B: &Point) -> Point {
        mul::lincomb_generic(&[A, B], &[x, y])
    }

    #[cfg(feature = "alloc")]
    fn point_double_mul(x: &Scalar, A: &Point, y: &Scalar, B: &Point) -> Point {
        mul::lincomb_iter([A, B].into_iter(), [x, y].into_iter())
    }

    fn scalar_add(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        lhs + rhs
    }

    fn scalar_sub(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        lhs - rhs
    }

    fn scalar_cond_negate(scalar: &mut Scalar, neg: bool) {
        scalar.conditional_negate(Choice::from(neg as u8))
    }

    fn scalar_is_high(scalar: &Scalar) -> bool {
        scalar.is_high().into()
    }

    fn scalar_is_zero(scalar: &Scalar) -> bool {
        scalar.is_zero().into()
    }

    fn scalar_mul(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        lhs * rhs
    }

    fn scalar_invert(scalar: &Scalar) -> Scalar {
        scalar.invert().unwrap()
    }

    fn scalar_mul_basepoint(scalar: &Scalar, base: &BasePoint) -> Point {
        base * scalar
    }

    #[cfg(feature = "alloc")]
    fn lincomb_iter<'a, 'b, A: Iterator<Item = &'a Point>, B: Iterator<Item = &'b Scalar>>(
        points: A,
        scalars: B,
    ) -> Point {
        mul::lincomb_iter(points, scalars)
    }
}

pub struct VariableTime;

// delegate everything to constant time for now
impl TimeSensitive for VariableTime {
    fn scalar_mul_norm_point(lhs: &Scalar, rhs: &Point) -> Point {
        ConstantTime::scalar_mul_norm_point(lhs, rhs)
    }

    fn scalar_mul_point(lhs: &Scalar, rhs: &Point) -> Point {
        ConstantTime::scalar_mul_point(lhs, rhs)
    }

    fn scalar_eq(lhs: &Scalar, rhs: &Scalar) -> bool {
        ConstantTime::scalar_eq(lhs, rhs)
    }

    fn point_eq_point(lhs: &Point, rhs: &Point) -> bool {
        ConstantTime::point_eq_point(lhs, rhs)
    }

    fn point_normalize(point: &mut Point) {
        ConstantTime::point_normalize(point)
    }

    fn point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool {
        ConstantTime::point_eq_norm_point(lhs, rhs)
    }

    fn point_add_point(lhs: &Point, rhs: &Point) -> Point {
        ConstantTime::point_add_point(lhs, rhs)
    }

    fn point_add_norm_point(lhs: &Point, rhs: &Point) -> Point {
        ConstantTime::point_add_norm_point(lhs, rhs)
    }

    fn any_point_neg(point: &mut Point) {
        ConstantTime::any_point_neg(point)
    }

    fn any_point_conditional_negate(point: &mut Point, cond: bool) {
        ConstantTime::any_point_conditional_negate(point, cond)
    }

    fn point_neg(point: &mut Point) {
        ConstantTime::point_neg(point)
    }

    fn point_sub_norm_point(lhs: &Point, rhs: &Point) -> Point {
        ConstantTime::point_sub_norm_point(lhs, rhs)
    }

    fn point_conditional_negate(point: &mut Point, cond: bool) {
        ConstantTime::point_conditional_negate(point, cond)
    }

    fn norm_point_sub_point(lhs: &Point, rhs: &Point) -> Point {
        ConstantTime::norm_point_sub_point(lhs, rhs)
    }

    fn norm_point_neg(point: &mut Point) {
        ConstantTime::norm_point_neg(point)
    }

    fn norm_point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool {
        ConstantTime::norm_point_eq_norm_point(lhs, rhs)
    }

    fn norm_point_is_y_even(point: &Point) -> bool {
        ConstantTime::norm_point_is_y_even(point)
    }

    fn norm_point_conditional_negate(point: &mut Point, cond: bool) {
        ConstantTime::norm_point_conditional_negate(point, cond)
    }

    fn basepoint_double_mul(x: &Scalar, A: &BasePoint, y: &Scalar, B: &Point) -> Point {
        Self::point_double_mul(x, A, y, B)
    }

    fn scalar_add(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        ConstantTime::scalar_add(lhs, rhs)
    }

    fn scalar_sub(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        ConstantTime::scalar_sub(lhs, rhs)
    }

    fn scalar_cond_negate(scalar: &mut Scalar, neg: bool) {
        ConstantTime::scalar_cond_negate(scalar, neg)
    }

    fn scalar_is_high(scalar: &Scalar) -> bool {
        ConstantTime::scalar_is_high(scalar)
    }

    fn scalar_is_zero(scalar: &Scalar) -> bool {
        ConstantTime::scalar_is_zero(scalar)
    }

    fn scalar_mul(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        ConstantTime::scalar_mul(lhs, rhs)
    }

    fn scalar_invert(scalar: &Scalar) -> Scalar {
        ConstantTime::scalar_invert(scalar)
    }

    fn scalar_mul_basepoint(scalar: &Scalar, base: &BasePoint) -> Point {
        ConstantTime::scalar_mul_basepoint(scalar, base)
    }

    fn point_double_mul(x: &Scalar, A: &Point, y: &Scalar, B: &Point) -> Point {
        ConstantTime::point_double_mul(x, A, y, B)
    }

    #[cfg(feature = "alloc")]
    fn lincomb_iter<'a, 'b, A: Iterator<Item = &'a Point>, B: Iterator<Item = &'b Scalar>>(
        points: A,
        scalars: B,
    ) -> Point {
        ConstantTime::lincomb_iter(points, scalars)
    }
}

impl VariableTime {
    pub fn point_x_eq_scalar(point: &Point, scalar: &Scalar) -> bool {
        if point.is_identity().into() {
            return false;
        }
        let mut point = point.clone();
        Self::point_normalize(&mut point);
        Scalar::from_bytes_reduced(&point.x.to_bytes()).eq(scalar)
    }
}

fn norm_point_to_affine(proj_point: &Point) -> AffinePoint {
    debug_assert!(
        proj_point.is_identity().into() && proj_point.z.normalizes_to_zero().into()
            || proj_point.z == FieldElement::ONE
    );
    AffinePoint::conditional_select(
        &AffinePoint::new(proj_point.x, proj_point.y),
        &AffinePoint::IDENTITY,
        proj_point.is_identity(),
    )
}
