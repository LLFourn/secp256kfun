use core::ops::{Add, Neg};
pub use secp256kfun_k256_backend::Scalar;
use secp256kfun_k256_backend::{lincomb, AffinePoint, FieldBytes, FieldElement, ProjectivePoint};
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq};

use super::{BackendPoint, BackendScalar, BackendXOnly, TimeSensitive};
pub type Point = ProjectivePoint;
pub type BasePoint = ProjectivePoint;

pub const G_JACOBIAN: ProjectivePoint = ProjectivePoint {
    x: FieldElement::from_bytes_unchecked(&[
        0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
        0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
        0x17, 0x98,
    ]),
    y: FieldElement::from_bytes_unchecked(&[
        0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08,
        0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10,
        0xd4, 0xb8,
    ]),
    z: FieldElement::one(),
};

pub static G_TABLE: ProjectivePoint = G_JACOBIAN;

impl BackendScalar for Scalar {
    fn minus_one() -> Self {
        -Scalar::one()
    }

    fn from_u32(int: u32) -> Self {
        Self::from(int)
    }

    fn zero() -> Self {
        Scalar::zero()
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

#[derive(Debug, Clone, PartialEq, Copy, Eq, Hash)]
pub struct XOnly([u8; 32]);

impl BackendXOnly for XOnly {
    fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        let bytes = FieldBytes::from(bytes);
        let option: Option<AffinePoint> = AffinePoint::decompress(&bytes, 0u8.into()).into();
        option.map(|_| XOnly(bytes.into()))
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    fn into_norm_point_even_y(self) -> Point {
        let bytes = FieldBytes::from(self.0);
        let affine = AffinePoint::decompress(&bytes, 0u8.into()).unwrap();
        affine.into()
    }
}

impl XOnly {
    fn to_field_elem(&self) -> FieldElement {
        FieldElement::from_bytes_unchecked(&self.0)
    }
}

impl BackendPoint for Point {
    fn zero() -> Point {
        ProjectivePoint::identity()
    }

    fn is_zero(&self) -> bool {
        self.z.normalizes_to_zero().into()
    }

    fn norm_to_coordinates(&self) -> ([u8; 32], [u8; 32]) {
        (self.x.to_bytes().into(), self.y.to_bytes().into())
    }

    fn norm_to_xonly(&self) -> XOnly {
        XOnly(self.x.to_bytes().into())
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
        Some(
            AffinePoint {
                x,
                y,
                infinity: Choice::from(0u8),
            }
            .into(),
        )
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
        let zinv = zinv_opt.unwrap_or(FieldElement::one());
        point.x *= zinv;
        point.y *= zinv;
        point.x = point.x.normalize();
        point.y = point.y.normalize();
        point.z.conditional_assign(&FieldElement::one(), !was_zero);
    }

    fn point_eq_point(lhs: &Point, rhs: &Point) -> bool {
        // The points are stored internally in projective coordinates:
        // lhs: (x₁z₁, y₁z₁, z₁), rhs: (x₂z₂, y₂z₂, z₂)
        // we want to know if x₁ == x₂ and y₁ == y₂
        // So we transform these both to
        // lhs: (x₁z₁z₂, y₁z₁z₂) rhs: (x₂z₁z₂, y₂z₁z₂)
        let lhs_x = lhs.x * &rhs.z;
        let rhs_x = rhs.x * &lhs.z;
        let x_eq = rhs_x.negate(1).add(&lhs_x).normalizes_to_zero();

        let lhs_y = lhs.y * &rhs.z;
        let rhs_y = rhs.y * &lhs.z;
        let y_eq = rhs_y.negate(1).add(&lhs_y).normalizes_to_zero();

        (x_eq & y_eq).into()
    }

    fn point_eq_norm_point(lhs: &Point, rhs: &Point) -> bool {
        let both_infinity = Choice::from((lhs.is_zero() && rhs.is_zero()) as u8);
        let rhs_infinity = Choice::from(rhs.is_zero() as u8);

        let rhs_x = &rhs.x * &lhs.z;
        let x_eq = rhs_x.negate(1).add(&lhs.x).normalizes_to_zero();

        let rhs_y = &rhs.y * &lhs.z;
        let y_eq = rhs_y.negate(1).add(&lhs.y).normalizes_to_zero();

        (both_infinity | (!rhs_infinity & (x_eq & y_eq))).into()
    }

    fn point_eq_xonly(lhs: &Point, rhs: &XOnly) -> bool {
        let mut lhs = lhs.clone();
        Self::point_normalize(&mut lhs);
        Self::norm_point_eq_xonly(&lhs, rhs)
    }

    fn norm_point_eq_xonly(point: &Point, xonly: &XOnly) -> bool {
        let are_equal = point.x.ct_eq(&xonly.to_field_elem());
        let y_is_even = !point.y.is_odd();
        (are_equal & y_is_even).into()
    }

    fn point_add_point(lhs: &Point, rhs: &Point) -> Point {
        lhs + rhs
    }

    fn point_add_norm_point(lhs: &Point, rhs: &Point) -> Point {
        // use more efficient version for affine
        let rhs = AffinePoint::conditional_select(
            &AffinePoint {
                x: rhs.x,
                y: rhs.y,
                infinity: Choice::from(0),
            },
            &AffinePoint::identity(),
            rhs.is_identity(),
        );
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
        // use more efficient version for affine
        let rhs = AffinePoint::conditional_select(
            &AffinePoint {
                x: rhs.x,
                y: rhs.y,
                infinity: Choice::from(0),
            },
            &AffinePoint::identity(),
            rhs.is_identity(),
        );
        lhs + &rhs.neg()
    }

    fn point_conditional_negate(point: &mut Point, cond: bool) {
        Self::any_point_conditional_negate(point, cond)
    }

    fn norm_point_sub_point(lhs: &Point, rhs: &Point) -> Point {
        let lhs = AffinePoint::conditional_select(
            &AffinePoint {
                x: lhs.x,
                y: lhs.y,
                infinity: Choice::from(0),
            },
            &AffinePoint::identity(),
            lhs.is_identity(),
        );
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

    fn point_double_mul(x: &Scalar, A: &Point, y: &Scalar, B: &Point) -> Point {
        lincomb(A, x, B, y)
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

    fn xonly_eq(lhs: &XOnly, rhs: &XOnly) -> bool {
        lhs.0.ct_eq(&rhs.0).into()
    }

    fn lincomb_iter<'a, 'b, A: Iterator<Item = &'a Point>, B: Iterator<Item = &'b Scalar>>(
        points: A,
        scalars: B,
    ) -> Point {
        secp256kfun_k256_backend::lincomb_iter(points, scalars)
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

    fn point_eq_xonly(lhs: &Point, rhs: &XOnly) -> bool {
        ConstantTime::point_eq_xonly(lhs, rhs)
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

    fn norm_point_eq_xonly(point: &Point, xonly: &XOnly) -> bool {
        ConstantTime::norm_point_eq_xonly(point, xonly)
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

    fn xonly_eq(lhs: &XOnly, rhs: &XOnly) -> bool {
        ConstantTime::xonly_eq(lhs, rhs)
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
