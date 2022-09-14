#![allow(non_snake_case)]
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use secp256kfun::{g, Point, Scalar, G};

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
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
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
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
                    g!({ Scalar::random(&mut rand::thread_rng()) } * G),
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

criterion_group!(benches, point_add, point_eq);
criterion_main!(benches);
