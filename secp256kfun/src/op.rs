use crate::{
    backend::{self, ConstantTime, TimeSensitive, VariableTime},
    marker::*,
    Point, Scalar, XOnly,
};

pub fn double_mul<ZA, SA, TA, ZX, SX, ZB, SB, TB, ZY, SY>(
    x: &Scalar<SX, ZX>,
    A: &Point<TA, SA, ZA>,
    y: &Scalar<SY, ZY>,
    B: &Point<TB, SB, ZB>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(DoubleMul::double_mul((x, A, y, B)), Jacobian)
}

pub fn scalar_mul_point<Z1, S1, T2, S2, Z2>(
    lhs: &Scalar<S1, Z1>,
    rhs: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Point::from_inner(MulPoint::mul_point(lhs, rhs), Jacobian)
}

pub fn scalar_mul<Z1, Z2, S1, S2>(
    lhs: &Scalar<S1, Z1>,
    rhs: &Scalar<S2, Z2>,
) -> Scalar<Secret, Z1::Out>
where
    Z1: DecideZero<Z2>,
{
    Scalar::from_inner(ScalarBinary::mul((lhs, rhs)))
}

pub fn scalar_add<Z1, Z2, S1, S2>(
    lhs: &Scalar<S1, Z1>,
    rhs: &Scalar<S2, Z2>,
) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ScalarBinary::add((lhs, rhs)))
}

pub fn scalar_sub<Z1, Z2, S1, S2>(
    lhs: &Scalar<S1, Z1>,
    rhs: &Scalar<S2, Z2>,
) -> Scalar<Secret, Zero> {
    Scalar::from_inner(ScalarBinary::sub((lhs, rhs)))
}

pub fn point_sub<Z1, S1, T1, Z2, S2, T2>(
    lhs: &Point<T1, S1, Z1>,
    rhs: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(PointBinary::sub((lhs, rhs)), Jacobian)
}

pub fn point_add<Z1, Z2, S1, S2, T1, T2>(
    lhs: &Point<T1, S1, Z1>,
    rhs: &Point<T2, S2, Z2>,
) -> Point<Jacobian, Public, Zero> {
    Point::from_inner(PointBinary::add((lhs, rhs)), Jacobian)
}

pub(crate) trait PointBinary {
    fn add(self) -> backend::Point;
    fn sub(self) -> backend::Point;
    fn eq(self) -> bool;
}

impl<T1, S1, Z1, T2, S2, Z2> PointBinary for (&Point<S1, T1, Z1>, &Point<S2, T2, Z2>) {
    default fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::point_add_point(&lhs.0, &rhs.0)
    }

    default fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::point_sub_point(&lhs.0, &rhs.0)
    }

    default fn eq(self) -> bool {
        let (lhs, rhs) = self;
        ConstantTime::point_eq_point(&lhs.0, &rhs.0)
    }
}

impl<Z1, Z2, T1: Normalized, S1, S2, T2> PointBinary for (&Point<S1, T1, Z1>, &Point<T2, S2, Z2>) {
    default fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::point_add_norm_point(&rhs.0, &lhs.0)
    }

    default fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::norm_point_sub_point(&lhs.0, &rhs.0)
    }

    default fn eq(self) -> bool {
        let (lhs, rhs) = self;
        ConstantTime::point_eq_norm_point(&rhs.0, &lhs.0)
    }
}

impl<Z1, Z2, S1, S2, T2: Normalized> PointBinary
    for (&Point<S1, Jacobian, Z1>, &Point<T2, S2, Z2>)
{
    default fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::point_add_norm_point(&lhs.0, &rhs.0)
    }

    default fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        ConstantTime::point_sub_norm_point(&lhs.0, &rhs.0)
    }

    default fn eq(self) -> bool {
        let (lhs, rhs) = self;
        ConstantTime::point_eq_norm_point(&lhs.0, &rhs.0)
    }
}

impl<Z1, Z2> PointBinary for (&Point<Public, Jacobian, Z1>, &Point<Jacobian, Public, Z2>) {
    fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::point_add_point(&lhs.0, &rhs.0)
    }

    fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::point_sub_point(&lhs.0, &rhs.0)
    }

    fn eq(self) -> bool {
        let (lhs, rhs) = self;
        VariableTime::point_eq_point(&lhs.0, &rhs.0)
    }
}

impl<Z1, Z2, T1: Normalized, T2> PointBinary for (&Point<Public, T1, Z1>, &Point<T2, Public, Z2>) {
    fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::point_add_norm_point(&rhs.0, &lhs.0)
    }

    fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::norm_point_sub_point(&lhs.0, &rhs.0)
    }

    fn eq(self) -> bool {
        let (lhs, rhs) = self;
        VariableTime::point_eq_norm_point(&rhs.0, &lhs.0)
    }
}

impl<Z1, Z2, T2: Normalized> PointBinary
    for (&Point<Public, Jacobian, Z1>, &Point<T2, Public, Z2>)
{
    fn add(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::point_add_norm_point(&lhs.0, &rhs.0)
    }

    fn sub(self) -> backend::Point {
        let (lhs, rhs) = self;
        VariableTime::point_sub_norm_point(&lhs.0, &rhs.0)
    }

    fn eq(self) -> bool {
        let (lhs, rhs) = self;
        VariableTime::point_eq_norm_point(&lhs.0, &rhs.0)
    }
}

pub(crate) trait EqXOnlySquareY {
    fn eq_xonly_square_y(&self, xonly: &XOnly<SquareY>) -> bool;
}

impl<T, S, Z> EqXOnlySquareY for Point<T, S, Z> {
    default fn eq_xonly_square_y(&self, xonly: &XOnly<SquareY>) -> bool {
        ConstantTime::point_eq_xonly_square_y(&self.0, &xonly.0)
    }
}

impl<T, Z> EqXOnlySquareY for Point<T, Public, Z> {
    fn eq_xonly_square_y(&self, xonly: &XOnly<SquareY>) -> bool {
        VariableTime::point_eq_xonly_square_y(&self.0, &xonly.0)
    }
}

pub(crate) trait MulPoint<S2, T2> {
    fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point;
}

impl<Z1, S1, S2, T2> MulPoint<S2, T2> for Scalar<S1, Z1> {
    default fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_point(&self.0, &rhs.0)
    }
}

impl<Z1, S1, S2, T2: NotBasePoint + Normalized> MulPoint<S2, T2> for Scalar<S1, Z1> {
    default fn mul_point<Z2>(&self, rhs: &Point<T2, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_norm_point(&self.0, &rhs.0)
    }
}

impl<Z1, S1, S2> MulPoint<S2, BasePoint> for Scalar<S1, Z1> {
    default fn mul_point<Z2>(&self, rhs: &Point<BasePoint, S2, Z2>) -> backend::Point {
        ConstantTime::scalar_mul_basepoint(&self.0, &(rhs.1).0)
    }
}

impl<Z1> MulPoint<Public, Jacobian> for Scalar<Public, Z1> {
    fn mul_point<Z2>(&self, rhs: &Point<Jacobian, Public, Z2>) -> backend::Point {
        VariableTime::scalar_mul_point(&self.0, &rhs.0)
    }
}

impl<Z1, T2: Normalized + NotBasePoint> MulPoint<Public, T2> for Scalar<Public, Z1> {
    fn mul_point<Z2>(&self, rhs: &Point<T2, Public, Z2>) -> backend::Point {
        VariableTime::scalar_mul_norm_point(&self.0, &rhs.0)
    }
}

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
    default fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        let xA = x.mul_point(A);
        let yB = y.mul_point(B);
        VariableTime::point_add_point(&xA, &yB)
    }
}

impl<XZ, AZ, YZ, BZ, BT> DoubleMul
    for (
        &Scalar<Public, XZ>,
        &Point<BasePoint, Public, AZ>,
        &Scalar<Public, YZ>,
        &Point<BT, Public, BZ>,
    )
{
    default fn double_mul(self) -> backend::Point {
        let (x, A, y, B) = self;
        VariableTime::basepoint_double_mul(&x.0, &(A.1).0, &y.0, &B.0)
    }
}

impl<XZ, AZ, YZ, BZ, AT: Normalized + NotBasePoint> DoubleMul
    for (
        &Scalar<Public, XZ>,
        &Point<AT, Public, AZ>,
        &Scalar<Public, YZ>,
        &Point<BasePoint, Public, BZ>,
    )
{
    default fn double_mul(self) -> backend::Point {
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
    default fn mul(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        ConstantTime::scalar_mul(&lhs.0, &rhs.0)
    }

    default fn add(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        ConstantTime::scalar_add(&lhs.0, &rhs.0)
    }

    default fn sub(self) -> backend::Scalar {
        let (lhs, rhs) = self;
        ConstantTime::scalar_sub(&lhs.0, &rhs.0)
    }

    default fn eq(self) -> bool {
        let (lhs, rhs) = self;
        ConstantTime::scalar_eq(&lhs.0, &rhs.0)
    }
}

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
    default fn negate(&self) -> backend::Scalar {
        let mut negated = self.0.clone();
        ConstantTime::scalar_cond_negate(&mut negated, true);
        negated
    }

    default fn invert(&self) -> backend::Scalar {
        ConstantTime::scalar_invert(&self.0)
    }

    default fn conditional_negate(&mut self, cond: bool) {
        ConstantTime::scalar_cond_negate(&mut self.0, cond)
    }

    default fn is_high(&self) -> bool {
        ConstantTime::scalar_is_high(&self.0)
    }

    default fn is_zero(&self) -> bool {
        ConstantTime::scalar_is_zero(&self.0)
    }
}

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
    fn is_y_square(&self) -> bool;
}

impl<T, S, Z> PointUnary for Point<T, Z, S> {
    default fn negate(mut self) -> backend::Point {
        ConstantTime::point_neg(&mut self.0);
        self.0
    }

    default fn conditional_negate(mut self, cond: bool) -> backend::Point {
        ConstantTime::point_conditional_negate(&mut self.0, cond);
        self.0
    }

    default fn normalize(mut self) -> backend::Point {
        ConstantTime::point_normalize(&mut self.0);
        self.0
    }
}

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
    default fn is_y_square(&self) -> bool {
        ConstantTime::norm_point_is_y_square(&self.0)
    }

    default fn is_y_even(&self) -> bool {
        ConstantTime::norm_point_is_y_even(&self.0)
    }
}

impl<T: Normalized, Z> NormPointUnary for Point<T, Z, Public> {
    fn is_y_square(&self) -> bool {
        VariableTime::norm_point_is_y_square(&self.0)
    }

    fn is_y_even(&self) -> bool {
        VariableTime::norm_point_is_y_even(&self.0)
    }
}
