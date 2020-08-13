use super::{BasePoint, XOnly, G_TABLE};
use parity_backend::{
    field::Field,
    group::{Affine, Jacobian, JACOBIAN_INFINITY},
    scalar::Scalar,
};
use subtle::{Choice, ConstantTimeEq};
pub struct ConstantTime;

impl crate::backend::TimeSensitive for ConstantTime {
    fn scalar_mul_point(lhs: &Scalar, rhs: &Jacobian) -> Jacobian {
        if rhs.is_infinity() {
            return JACOBIAN_INFINITY.clone();
        }
        let mut ret = Jacobian::default();
        G_TABLE
            .mult_ctx
            .ecmult_const(&mut ret, &Affine::from_gej(&rhs), &lhs);
        ret
    }

    fn scalar_mul_norm_point(lhs: &Scalar, rhs: &Jacobian) -> Jacobian {
        if rhs.is_infinity() {
            return JACOBIAN_INFINITY.clone();
        }
        let mut ret = Jacobian::default();
        G_TABLE.mult_ctx.ecmult_const(
            &mut ret,
            &Affine {
                x: rhs.x.clone(),
                y: rhs.y.clone(),
                infinity: false,
            },
            &lhs,
        );
        ret
    }

    fn scalar_mul_basepoint(scalar: &Scalar, basepoint: &BasePoint) -> Jacobian {
        let mut ret = Jacobian::default();
        basepoint.mult_gen_ctx.ecmult_gen(&mut ret, scalar);
        ret
    }

    fn scalar_eq(lhs: &Scalar, rhs: &Scalar) -> bool {
        lhs.b32().ct_eq(rhs.b32().as_ref()).into()
    }

    fn point_normalize(point: &mut Jacobian) {
        let zinv = point.z.inv();
        let z2 = zinv.sqr();
        let z3 = &zinv * &z2;
        point.x *= &z2;
        point.y *= &z3;
        point.z = Field::from_int(1);
        point.x.normalize();
        point.y.normalize();
    }

    fn point_eq_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        let only_one_is_infinity = Choice::from((lhs.is_infinity() != rhs.is_infinity()) as u8);
        let both_infinity = Choice::from((lhs.is_infinity() && rhs.is_infinity()) as u8);
        // The points are stored internally in jacobian coordinates:
        // lhs: (x₁z₁², y₁z₁³, z₁), rhs: (x₂z₂², y₂z₂³, z₂)
        // we want to know if x₁ == x₂ and y₁ == y₂
        // So we transform these both to
        // lhs: (x₁z₁²z₂², y₁z₁³z₂²) rhs: (x₂z₁²z₂², y₂z₁³z₂²)
        let lhs_z = &lhs.z;
        let lhs_z2 = lhs_z.sqr();
        let rhs_z = &rhs.z;
        let rhs_z2 = rhs_z.sqr();

        let lhs_x = &lhs.x * &rhs_z2;
        let rhs_x = &rhs.x * &lhs_z2;
        let x_eq = Choice::from((&lhs_x == &rhs_x) as u8);

        let rhs_z3 = rhs_z * &rhs_z2;
        let lhs_z3 = lhs_z * &lhs_z2;
        let lhs_y = &lhs.y * &rhs_z3;
        let rhs_y = &rhs.y * &lhs_z3;

        let y_eq = Choice::from((&lhs_y == &rhs_y) as u8);
        (both_infinity | (!only_one_is_infinity & x_eq & y_eq)).into()
    }

    fn point_eq_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        crate::assert_normal!(rhs);
        let only_one_is_infinity = Choice::from((lhs.is_infinity() != rhs.is_infinity()) as u8);
        let both_infinity = Choice::from((lhs.is_infinity() && rhs.is_infinity()) as u8);

        let lhs_z = &lhs.z;
        let lhs_z2 = lhs_z.sqr();

        let rhs_x = &rhs.x * &lhs_z2;

        let x_eq = Choice::from((&lhs.x == &rhs_x) as u8);

        let lhs_z3 = &lhs_z2 * lhs_z;
        let rhs_y = &rhs.y * &lhs_z3;

        let y_eq = Choice::from((&lhs.y == &rhs_y) as u8);

        (both_infinity | (!only_one_is_infinity & x_eq & y_eq)).into()
    }

    fn norm_point_eq_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        crate::assert_normal!(rhs);
        crate::assert_normal!(lhs);
        let only_one_is_infinity = Choice::from((lhs.is_infinity() != rhs.is_infinity()) as u8);
        let both_infinity = Choice::from((lhs.is_infinity() && rhs.is_infinity()) as u8);
        let x_eq = lhs.x.b32().ct_eq(rhs.x.b32().as_ref());
        let y_eq = Choice::from((rhs.y.is_odd() == lhs.y.is_odd()) as u8);
        (both_infinity | (!only_one_is_infinity & y_eq & x_eq)).into()
    }

    fn point_add_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        // In the odd case where the thing you are trying to add is the identity
        // element this function is non-constant time. The lower
        // level constant time addition requires its rhs argument to not be
        // infinity.
        //
        // TODO: Find a solution for this. I think we work around this by always
        // doing a point addition and then constant time moving the lhs into the
        // result if the rhs is infinity.
        if rhs.is_infinity() {
            return lhs.clone();
        }

        lhs.add_ge(&Affine::from_gej(rhs))
    }

    fn point_sub_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        if rhs.is_infinity() {
            return lhs.clone();
        }

        lhs.add_ge(&Affine::from_gej(rhs).neg())
    }

    fn point_add_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(rhs);
        if rhs.is_infinity() {
            return lhs.clone();
        }

        lhs.add_ge(&Affine {
            x: rhs.x.clone(),
            y: rhs.y.clone(),
            infinity: false,
        })
    }

    fn point_sub_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(rhs);
        if rhs.is_infinity() {
            return lhs.clone();
        }

        lhs.add_ge(&Affine {
            x: rhs.x.clone(),
            y: rhs.y.neg(1),
            infinity: false,
        })
    }

    fn point_conditional_negate(point: &mut Jacobian, cond: bool) {
        point.y.normalize_weak();
        let neg_y = point.y.neg(1);
        point.y.cmov(&neg_y, cond);
    }

    fn norm_point_sub_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(lhs);
        let rhs = rhs.neg();
        if lhs.is_infinity() {
            return rhs;
        }

        rhs.add_ge(&Affine {
            x: lhs.x.clone(),
            y: lhs.y.clone(),
            infinity: false,
        })
    }

    fn point_eq_xonly_square_y(lhs: &Jacobian, rhs: &XOnly) -> bool {
        let lhs_not_infinity = Choice::from(!lhs.is_infinity() as u8);

        let x_eq = {
            let rhs_x = rhs.to_field_elem();
            let z2 = lhs.z.sqr();
            let rhs_xz2 = z2 * rhs_x;
            let mut lhs_xz2 = lhs.x.clone();
            lhs_xz2.normalize_weak();
            Choice::from(lhs_xz2.eq(&rhs_xz2) as u8)
        };

        let lhs_square = {
            let yz4 = &lhs.y * &lhs.z;
            let (_, is_square) = yz4.sqrt();
            Choice::from(is_square as u8)
        };

        (lhs_not_infinity & x_eq & lhs_square).into()
    }

    fn basepoint_double_mul(x: &Scalar, A: &BasePoint, y: &Scalar, B: &Jacobian) -> Jacobian {
        let xA = {
            let mut xA = Jacobian::default();
            A.mult_gen_ctx.ecmult_gen(&mut xA, x);
            xA
        };
        let yB = Self::scalar_mul_point(y, B);
        Self::point_add_point(&xA, &yB)
    }

    fn scalar_add(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        lhs + rhs
    }

    fn scalar_sub(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        lhs + &-rhs
    }

    fn scalar_cond_negate(scalar: &mut Scalar, neg: bool) {
        scalar.cond_neg_assign(Choice::from(neg as u8));
    }

    fn scalar_is_high(scalar: &Scalar) -> bool {
        scalar.is_high()
    }

    fn scalar_is_zero(scalar: &Scalar) -> bool {
        scalar.is_zero()
    }

    fn scalar_mul(lhs: &Scalar, rhs: &Scalar) -> Scalar {
        use core::ops::Mul;
        lhs.mul(rhs)
    }

    fn scalar_invert(scalar: &Scalar) -> Scalar {
        scalar.inv()
    }

    fn point_neg(point: &mut Jacobian) {
        point.y.normalize_weak();
        point.y = point.y.neg(1);
    }

    fn norm_point_neg(point: &mut Jacobian) {
        crate::assert_normal!(&point);
        point.y = point.y.neg(1);
        point.y.normalize();
    }

    fn norm_point_is_y_square(point: &Jacobian) -> bool {
        crate::assert_normal!(&point);
        let (_, ret) = point.y.sqrt();
        let is_infinity = Choice::from(point.is_infinity() as u8);
        let is_y_square = Choice::from(ret as u8);
        (!is_infinity & is_y_square).into()
    }

    fn norm_point_is_y_even(point: &Jacobian) -> bool {
        crate::assert_normal!(&point);
        let is_infinity = Choice::from(point.is_infinity() as u8);
        let is_y_even = Choice::from(!point.y.is_odd() as u8);
        (!is_infinity & is_y_even).into()
    }

    fn norm_point_conditional_negate(point: &mut Jacobian, cond: bool) {
        crate::assert_normal!(&point);
        let mut neg_y = point.y.neg(1);
        neg_y.normalize();
        point.y.cmov(&neg_y, cond)
    }

    fn xonly_eq(lhs: &XOnly, rhs: &XOnly) -> bool {
        lhs.0.ct_eq(rhs.0.as_ref()).into()
    }
}
