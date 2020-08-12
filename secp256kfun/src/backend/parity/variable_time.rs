use core::cmp::Ordering;
use parity_backend::{
    field::Field,
    group::{Affine, Jacobian, JACOBIAN_INFINITY},
    scalar::Scalar,
};
pub struct VariableTime;
use super::{BasePoint, ConstantTime, XOnly};

impl crate::backend::TimeSensitive for VariableTime {
    fn scalar_mul_point(lhs: &Scalar, rhs: &Jacobian) -> Jacobian {
        use crate::backend::BackendScalar;
        if rhs.is_infinity() {
            return JACOBIAN_INFINITY.clone();
        }
        //HACK: use the variable time double_mult but multiply the basepoint by zero
        VariableTime::basepoint_double_mul(&Scalar::zero(), &super::G_TABLE, lhs, rhs)
    }

    fn scalar_mul_norm_point(lhs: &Scalar, rhs: &Jacobian) -> Jacobian {
        Self::scalar_mul_point(lhs, rhs)
    }

    fn scalar_eq(lhs: &Scalar, rhs: &Scalar) -> bool {
        &lhs.0 == &rhs.0
    }

    fn point_normalize(point: &mut Jacobian) {
        let zinv = point.z.inv_var();
        let z2 = zinv.sqr();
        let z3 = &zinv * &z2;
        point.x *= &z2;
        point.y *= &z3;
        point.z = Field::from_int(1);
        point.x.normalize_var();
        point.y.normalize_var();
    }

    fn point_eq_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        match (lhs.is_infinity(), rhs.is_infinity()) {
            (true, true) => return true,
            (a, b) if a ^ b == true => return false,
            _ => (),
        }

        let lhs_z = &lhs.z;
        let lhs_z2 = lhs_z.sqr();
        let rhs_z = &rhs.z;
        let rhs_z2 = rhs_z.sqr();

        let lhs_x = &lhs.x * &rhs_z2;
        let rhs_x = &rhs.x * &lhs_z2;

        if !lhs_x.eq_var(&rhs_x) {
            return false;
        }

        let rhs_z3 = rhs_z * &rhs_z2;
        let lhs_z3 = lhs_z * &lhs_z2;
        let lhs_y = &lhs.y * &rhs_z3;
        let rhs_y = &rhs.y * &lhs_z3;

        lhs_y.eq_var(&rhs_y)
    }

    fn point_eq_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        match (lhs.is_infinity(), rhs.is_infinity()) {
            (true, true) => return true,
            (a, b) if a ^ b == true => return false,
            _ => (),
        }

        let lhs_z = &lhs.z;
        let lhs_z2 = lhs_z.sqr();

        let rhs_x = &rhs.x * &lhs_z2;

        if !rhs_x.eq_var(&lhs.x) {
            return false;
        }

        let lhs_z3 = &lhs_z2 * lhs_z;
        let rhs_y = &rhs.y * &lhs_z3;

        rhs_y.eq_var(&lhs.y)
    }

    fn point_conditional_negate(point: &mut Jacobian, cond: bool) {
        if cond {
            point.y.normalize_weak();
            point.y = point.y.neg(1);
        }
    }

    fn norm_point_eq_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> bool {
        crate::assert_normal!(&lhs);
        crate::assert_normal!(&rhs);
        match (lhs.is_infinity(), rhs.is_infinity()) {
            (true, true) => true,     //both infinity
            (a, b) if a ^ b => false, // only one is infinity
            _ => lhs.x.cmp_var(&rhs.x) == Ordering::Equal && (lhs.y.is_odd() == rhs.y.is_odd()),
        }
    }

    fn norm_point_is_y_square(point: &Jacobian) -> bool {
        crate::assert_normal!(&point);
        !point.is_infinity() && point.y.is_quad_var()
    }

    fn norm_point_is_y_even(point: &Jacobian) -> bool {
        crate::assert_normal!(&point);
        ConstantTime::norm_point_is_y_even(point)
    }
    fn norm_point_conditional_negate(point: &mut Jacobian, cond: bool) {
        crate::assert_normal!(&point);
        if cond {
            Self::norm_point_neg(point)
        }
    }

    fn point_add_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        lhs.add_var(&rhs, None)
    }

    fn point_add_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(rhs);

        lhs.add_ge_var(
            &Affine {
                x: rhs.x.clone(),
                y: rhs.y.clone(),
                infinity: rhs.infinity,
            },
            None,
        )
    }

    fn point_sub_norm_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(rhs);

        lhs.add_ge_var(
            &Affine {
                x: rhs.x.clone(),
                y: rhs.y.neg(1),
                infinity: rhs.infinity,
            },
            None,
        )
    }

    fn norm_point_sub_point(lhs: &Jacobian, rhs: &Jacobian) -> Jacobian {
        crate::assert_normal!(lhs);

        rhs.neg().add_ge_var(
            &Affine {
                x: lhs.x.clone(),
                y: lhs.y.clone(),
                infinity: lhs.infinity,
            },
            None,
        )
    }

    fn point_eq_xonly_square_y(lhs: &Jacobian, rhs: &XOnly) -> bool {
        let rhs_x = rhs.to_field_elem();
        !lhs.is_infinity() && lhs.eq_x_var(&rhs_x) && lhs.has_quad_y_var()
    }

    fn basepoint_double_mul(x: &Scalar, A: &BasePoint, y: &Scalar, B: &Jacobian) -> Jacobian {
        if B.is_infinity() {
            return Self::scalar_mul_basepoint(x, A);
        }
        let mut ret = Jacobian::default();
        A.mult_ctx.ecmult(&mut ret, B, y, x);
        ret
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

    fn point_neg(point: &mut Jacobian) {
        ConstantTime::point_neg(point)
    }

    fn norm_point_neg(point: &mut Jacobian) {
        crate::assert_normal!(&point);
        point.y = point.y.neg(1);
        point.y.normalize_var();
    }

    fn scalar_mul_basepoint(scalar: &Scalar, basepoint: &BasePoint) -> Jacobian {
        ConstantTime::scalar_mul_basepoint(scalar, basepoint)
    }

    fn xonly_eq(lhs: &XOnly, rhs: &XOnly) -> bool {
        lhs.0 == rhs.0
    }
}

const P_MINUS_ORDER: Field = Field::new(0, 0, 0, 1, 0x45512319, 0x50B75FC4, 0x402DA172, 0x2FC9BAEE);
const ORDER_AS_FE: Field = Field::new(
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xBAAEDCE6, 0xAF48A03B, 0xBFD25E8C, 0xD0364141,
);

impl VariableTime {
    pub fn point_x_eq_scalar(point: &Jacobian, scalar: &Scalar) -> bool {
        if point.is_infinity() {
            return false;
        }
        let mut field = Field::default();
        let _ = field.set_b32(&scalar.b32());
        // check first to see if they are the same (if so this is by far the most likely
        // outcome)
        if point.eq_x_var(&field) {
            return true;
        }

        // we know that it hasn't been reduced mod q if it's bigger than p - q.
        if field >= P_MINUS_ORDER {
            return false;
        }

        // If it's smaller than p - q, then we add q to it to get something less than p
        field += ORDER_AS_FE;

        // check if this is equal
        point.eq_x_var(&field)
    }
}
