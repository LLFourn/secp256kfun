#![allow(non_snake_case)]

use secp256kfun::{g, op, s, Point, Scalar};

#[derive(Clone)]
struct Has<T> {
    has: T,
}

struct HasHas<T> {
    has_has: Has<T>,
}

#[test]
fn s_expressions_give_correct_answers() {
    let a = s!(3);
    let b = s!(5);
    let c = s!(11);

    assert_eq!(s!(a), &a);
    assert_eq!(s!({ a.invert() }), a.invert());
    assert_eq!(s!(-a), -&a);
    assert_eq!(s!(a + b), op::scalar_add(&a, &b));
    assert_eq!(s!(-a + b), op::scalar_sub(&b, &a));
    assert_eq!(s!(a - b), op::scalar_sub(&a, &b));
    assert_eq!(s!({ a.invert() } * a), s!(1));
    assert_eq!(
        s!(a + b - c - a),
        op::scalar_sub(&op::scalar_sub(&op::scalar_add(&a, &b), &c), &a)
    );

    assert_eq!(s!(a - c * b), op::scalar_sub(&a, &op::scalar_mul(&c, &b)));
    assert_eq!(
        s!(a - c * b - a),
        op::scalar_sub(&op::scalar_sub(&a, &op::scalar_mul(&c, &b)), &a)
    );
    assert_eq!(
        s!(a - c * b + a),
        op::scalar_add(&op::scalar_sub(&a, &op::scalar_mul(&c, &b)), &a)
    );
    assert_eq!(s!(a * b), op::scalar_mul(&a, &b));
    assert_eq!(s!(a * -b), op::scalar_mul(&a, &-&b));
    assert_eq!(s!(a * b - c), op::scalar_sub(&op::scalar_mul(&a, &b), &c));
    assert_eq!(s!(a * (b + c)), op::scalar_mul(&a, &op::scalar_add(&b, &c)));
    assert_eq!(
        s!(a * -(b + c)),
        op::scalar_mul(&a, &-op::scalar_add(&b, &c))
    );
    assert_eq!(
        s!(a * -(b + c) + a),
        op::scalar_add(&op::scalar_mul(&a, &-op::scalar_add(&b, &c)), &a)
    );
    assert_eq!(s!(a * b * c), op::scalar_mul(&a, &op::scalar_mul(&b, &c)));
    assert_eq!(s!(-a * b * -c), op::scalar_mul(&a, &op::scalar_mul(&b, &c)));

    let has_scalar = Has { has: s!(17) };

    assert_eq!(s!(has_scalar.has * a), op::scalar_mul(&has_scalar.has, &a));
    let has_has_scalar = HasHas {
        has_has: has_scalar.clone(),
    };
    assert_eq!(
        s!(has_has_scalar.has_has.has * a),
        op::scalar_mul(&has_scalar.has, &a)
    );
    assert_eq!(s!(3 * 11 + 5), s!(a * c + b));
}

#[test]
fn g_expressions_give_correct_answers() {
    let x = Scalar::random(&mut rand::thread_rng());
    let y = Scalar::random(&mut rand::thread_rng());
    let z = Scalar::random(&mut rand::thread_rng());
    let A = Point::random(&mut rand::thread_rng());
    let B = Point::random(&mut rand::thread_rng());
    let C = Point::random(&mut rand::thread_rng());

    assert_eq!(g!(A), &A);
    assert_eq!(g!(-A), -&A);
    assert_eq!(g!(x * A), op::scalar_mul_point(&x, &A));
    assert_eq!(g!(-x * A), op::scalar_mul_point(&-&x, &A));
    assert_eq!(g!(A - B), op::point_sub(&A, &B));
    assert_eq!(g!(A + -B), op::point_sub(&A, &B));
    assert_eq!(g!(A + B), op::point_add(&A, &B));
    assert_eq!(
        g!(x * A + B),
        op::point_add(&op::scalar_mul_point(&x, &A), &B)
    );
    assert_eq!(
        g!(x * A - B),
        op::point_sub(&op::scalar_mul_point(&x, &A), &B)
    );
    assert_eq!(
        g!(-x * A + B),
        op::point_add(&op::scalar_mul_point(&-&x, &A), &B)
    );
    assert_eq!(
        g!(-x * A - B),
        op::point_sub(&op::scalar_mul_point(&-&x, &A), &B)
    );
    assert_eq!(
        g!(A + x * B),
        op::point_add(&A, &op::scalar_mul_point(&x, &B))
    );
    assert_eq!(
        g!(A - x * B),
        op::point_sub(&A, &op::scalar_mul_point(&x, &B))
    );
    assert_eq!(g!(x * A + y * B), op::double_mul(&x, &A, &y, &B));
    assert_eq!(g!(x * A - y * B), op::double_mul(&x, &A, &-&y, &B));

    assert_eq!(
        g!((x - x * y) * A + y * B),
        op::double_mul(&op::scalar_sub(&x, &op::scalar_mul(&x, &y)), &A, &y, &B)
    );

    assert_eq!(
        g!(x * A + y * B + z * C),
        op::point_add(
            &op::double_mul(&x, &A, &y, &B),
            &op::scalar_mul_point(&z, &C)
        )
    );

    assert_eq!(
        g!(x * A - y * B + z * C),
        op::point_add(
            &op::double_mul(&x, &A, &-&y, &B),
            &op::scalar_mul_point(&z, &C)
        )
    );

    assert_eq!(
        g!(x * A - y * B - z * C),
        op::point_add(
            &op::double_mul(&x, &A, &-&y, &B),
            &op::scalar_mul_point(&-&z, &C)
        )
    );

    assert_eq!(
        g!(x * A + y * B + C),
        op::point_add(&op::double_mul(&x, &A, &y, &B), &C)
    );

    assert_eq!(
        g!(x * A + y * B - C),
        op::point_add(&op::double_mul(&x, &A, &y, &B), &-&C)
    );

    assert_eq!(
        g!(x * A - y * B + z * C),
        op::point_add(
            &op::double_mul(&x, &A, &-&y, &B),
            &op::scalar_mul_point(&z, &C)
        )
    );

    let has_scalar = Has { has: s!(17) };
    let has_point = Has { has: C.clone() };
    let has_has_scalar = HasHas {
        has_has: has_scalar.clone(),
    };
    let has_has_point = HasHas {
        has_has: has_point.clone(),
    };

    assert_eq!(
        g!(has_scalar.has * A),
        op::scalar_mul_point(&has_scalar.has, &A)
    );

    assert_eq!(
        g!(has_has_scalar.has_has.has * A),
        op::scalar_mul_point(&has_scalar.has, &A)
    );

    assert_eq!(
        g!(x * has_point.has + y * has_has_point.has_has.has),
        op::double_mul(&x, &has_point.has, &y, &has_has_point.has_has.has)
    );
}
