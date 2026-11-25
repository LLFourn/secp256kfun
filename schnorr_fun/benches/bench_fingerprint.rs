use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use schnorr_fun::frost::{Fingerprint, SharedKey};
use secp256kfun::prelude::*;

fn shared_key(threshold: usize) -> SharedKey<Normal, Zero> {
    let mut rng = ChaCha20Rng::seed_from_u64(threshold as u64);
    let coefficients = (0..threshold)
        .map(|_| Point::random(&mut rng).mark_zero())
        .collect::<Vec<_>>();
    SharedKey::from_poly(coefficients)
}

fn grind_fingerprint(c: &mut Criterion) {
    let mut group = c.benchmark_group("grind_fingerprint");
    group.sample_size(10);

    for threshold in [2, 3, 5] {
        let key = shared_key(threshold);
        let mut ground = key.clone();
        let tweaks = ground.grind_fingerprint::<sha2::Sha256>(Fingerprint::FROST_V0);
        let candidates: u64 = tweaks
            .iter()
            .skip(1)
            .map(|tweak| u64::from_be_bytes(tweak.to_bytes()[24..].try_into().unwrap()) + 1)
            .sum();
        eprintln!("frost_v0/t={threshold}: {candidates} candidates hashed");

        group.bench_function(format!("frost_v0/t={threshold}"), |b| {
            b.iter_batched(
                || key.clone(),
                |mut key| key.grind_fingerprint::<sha2::Sha256>(Fingerprint::FROST_V0),
                BatchSize::LargeInput,
            )
        });
    }
}

fn grind_fingerprint_small_work(c: &mut Criterion) {
    let mut group = c.benchmark_group("grind_fingerprint_small_work");
    let key = shared_key(3);

    for bits_per_coeff in [0u8, 1, 2, 4, 8] {
        let fingerprint = Fingerprint {
            bits_per_coeff,
            max_bits_total: 2 * bits_per_coeff.max(1),
            tag: "frost-v0",
        };
        group.bench_function(format!("t=3/bits={bits_per_coeff}"), |b| {
            b.iter_batched(
                || key.clone(),
                |mut key| key.grind_fingerprint::<sha2::Sha256>(fingerprint),
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(benches, grind_fingerprint, grind_fingerprint_small_work);
criterion_main!(benches);
