#![allow(non_snake_case)]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use secp256kfun::{g, marker::*, Point, Scalar, G};

fn scalar_mul_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecmult");

    group.bench_function("scalar_mul_point:basepoint,secret", |b| {
        b.iter_batched(
            || Scalar::random(&mut rand::thread_rng()),
            |scalar| g!(scalar * G),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("scalar_mul_point:basepoint,public", |b| {
        b.iter_batched(
            || Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
            |scalar| g!(scalar * G),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("scalar_mul_point:normal,secret", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(scalar, point)| g!(scalar * point),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("scalar_mul_point:normal,public", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(scalar, point)| g!(scalar * point),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("scalar_mul_point:jacobian,secret", |b| {
        b.iter_batched(
            || {
                (Scalar::random(&mut rand::thread_rng()), {
                    let P = Point::random(&mut rand::thread_rng());
                    g!(P + P)
                })
            },
            |(scalar, point)| g!(scalar * point),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("scalar_mul_point:jacobian,public", |b| {
        b.iter_batched(
            || {
                (Scalar::random(&mut rand::thread_rng()).mark::<Public>(), {
                    let P = Point::random(&mut rand::thread_rng());
                    g!(P + P)
                })
            },
            |(scalar, point)| g!(scalar * point),
            BatchSize::SmallInput,
        )
    });
}

fn double_mul(c: &mut Criterion) {
    let mut group = c.benchmark_group("double_mul");

    group.bench_function("double_mul:normal,public", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
                    Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
                    Point::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(x, y, A, B)| g!(x * A + y * B),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double_mul:normal,secret", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()),
                    Scalar::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(x, y, A, B)| g!(x * A + y * B),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double_mul:basepoint,public", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
                    Scalar::random(&mut rand::thread_rng()).mark::<Public>(),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(x, y, B)| g!(x * G + y * B),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("double_mul:basepoint,secret", |b| {
        b.iter_batched(
            || {
                (
                    Scalar::random(&mut rand::thread_rng()),
                    Scalar::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(x, y, B)| g!(x * G + y * B),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, scalar_mul_point, double_mul);
criterion_main!(benches);
