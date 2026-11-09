#![no_std]
#![allow(non_snake_case)]

use secp256kfun::{G, Point, Scalar, g, marker::*, op, s};

pub type S = Scalar<Secret, Zero>;
pub type P = Point<NonNormal, Secret, Zero>;
pub type N = Point<Normal, Secret, Zero>;

// Stable exported roots prevent the audit's fixture values from specializing the API calls.
#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_mul_base(k: &Scalar<Secret, NonZero>) -> Point<NonNormal> {
    g!(k * G)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_mul_normal(
    k: &Scalar<Secret, NonZero>,
    p: &Point<Normal, Public, NonZero>,
) -> Point<NonNormal> {
    g!(k * p)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_mul_nonnormal(
    k: &Scalar<Secret, NonZero>,
    p: &Point<NonNormal, Public, NonZero>,
) -> Point<NonNormal> {
    g!(k * p)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_mul_secret_point(k: &S, p: &P) -> Point<NonNormal, Public, Zero> {
    g!(k * p)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_double_mul(x: &S, a: &N, y: &S, b: &P) -> Point<NonNormal, Public, Zero> {
    g!(x * a + y * b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_dot_product(scalars: &[S], points: &[N]) -> Point<NonNormal, Public, Zero> {
    op::point_scalar_dot_product(scalars.iter(), points.iter())
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_add(a: &P, b: &P) -> Point<NonNormal, Public, Zero> {
    g!(a + b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_add_normal(a: &P, b: &N) -> Point<NonNormal, Public, Zero> {
    g!(a + b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_negate(a: &P) -> P {
    -a
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_normal_negate(a: &N) -> N {
    -a
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_cond_negate(a: &P, cond: bool) -> P {
    a.conditional_negate(cond)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_normal_cond_negate(a: &N, cond: bool) -> N {
    a.conditional_negate(cond)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_normalize(a: P) -> N {
    a.normalize()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_mul_normalize(k: &Scalar<Secret, NonZero>) -> Point {
    g!(k * G).normalize()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_eq(a: &P, b: &P) -> bool {
    a == b
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_point_eq_normal(a: &P, b: &N) -> bool {
    a == b
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_normal_eq(a: &N, b: &N) -> bool {
    a == b
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_y_even(a: &Point<Normal, Secret, NonZero>) -> bool {
    a.is_y_even()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_add(a: &S, b: &S) -> S {
    s!(a + b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_sub(a: &S, b: &S) -> S {
    s!(a - b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_mul(a: &S, b: &S) -> S {
    s!(a * b)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_invert(a: &Scalar<Secret, NonZero>) -> Scalar {
    a.invert()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_negate(a: &S) -> S {
    -a
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_cond_negate(mut a: S, cond: bool) -> S {
    a.conditional_negate(cond);
    a
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_eq(a: &S, b: &S) -> bool {
    a == b
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_is_high(a: &S) -> bool {
    a.is_high()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_is_zero(a: &S) -> bool {
    a.is_zero()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn audit_scalar_dot(a: &[S], b: &[S]) -> S {
    op::scalar_dot_product(a, b)
}

#[cfg(feature = "negative-controls")]
pub mod controls;
