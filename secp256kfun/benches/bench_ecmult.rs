#![allow(non_snake_case)]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use secp256kfun::{g, marker::*, Point, Scalar, G};

fn scalar_mul_point(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecmult");

    group.sample_size(600);
    group.measurement_time(std::time::Duration::from_secs(60));

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

criterion_group!(benches, scalar_mul_point);
criterion_main!(benches);
