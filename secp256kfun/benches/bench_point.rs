#![allow(non_snake_case)]
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use secp256kfun::{BatchNormalize, G, Point, Scalar, g, marker::*};

fn point_add(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_add");

    group.bench_function("normal,normal", |b| {
        b.iter_batched(
            || {
                (
                    Point::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(lhs, rhs)| g!(lhs + rhs),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("non_normal,normal", |b| {
        b.iter_batched(
            || {
                (
                    Point::random(&mut rand::thread_rng()).non_normal(),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(lhs, rhs)| g!(lhs + rhs),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("non_normal,non_normal", |b| {
        b.iter_batched(
            || {
                (
                    Point::random(&mut rand::thread_rng()).non_normal(),
                    Point::random(&mut rand::thread_rng()).non_normal(),
                )
            },
            |(lhs, rhs)| g!(lhs + rhs),
            BatchSize::SmallInput,
        )
    });
}

fn point_eq(c: &mut Criterion) {
    let mut group = c.benchmark_group("point_eq");

    group.bench_function("normal,normal", |b| {
        b.iter_batched(
            || {
                (
                    Point::random(&mut rand::thread_rng()),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(lhs, rhs)| lhs == rhs,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("non_normal,normal", |b| {
        b.iter_batched(
            || {
                (
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
                    Point::random(&mut rand::thread_rng()),
                )
            },
            |(lhs, rhs)| lhs == rhs,
            BatchSize::SmallInput,
        )
    });

    group.bench_function("non_normal,non_normal", |b| {
        b.iter_batched(
            || {
                (
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
                )
            },
            |(lhs, rhs)| lhs == rhs,
            BatchSize::SmallInput,
        )
    });
}

fn random_non_normal() -> Point<NonNormal> {
    g!({ Scalar::random(&mut rand::thread_rng()) } * G)
}

fn normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("normalize");

    macro_rules! bench_array {
        ($($n:literal),*) => {$(
            group.bench_function(concat!("array_one_by_one/", $n), |b| {
                b.iter_batched(
                    || core::array::from_fn::<_, $n, _>(|_| random_non_normal()),
                    |points| points.map(|point| point.normalize()),
                    BatchSize::SmallInput,
                )
            });
            group.bench_function(concat!("array_batch/", $n), |b| {
                b.iter_batched(
                    || core::array::from_fn::<_, $n, _>(|_| random_non_normal()),
                    |points| points.batch_normalize(),
                    BatchSize::SmallInput,
                )
            });
        )*};
    }
    bench_array!(1, 2, 3, 4, 5, 8, 16, 32, 64, 128);

    for n in [2, 5, 16, 64] {
        group.bench_function(format!("vec_one_by_one/{n}"), |b| {
            b.iter_batched(
                || (0..n).map(|_| random_non_normal()).collect::<Vec<_>>(),
                |points| {
                    points
                        .into_iter()
                        .map(|point| point.normalize())
                        .collect::<Vec<_>>()
                },
                BatchSize::SmallInput,
            )
        });
        group.bench_function(format!("vec_batch/{n}"), |b| {
            b.iter_batched(
                || (0..n).map(|_| random_non_normal()).collect::<Vec<_>>(),
                |points| points.batch_normalize(),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(benches, point_add, point_eq, normalize);
criterion_main!(benches);
