//! Native timing evidence using the previous arith-backend harness's Welch estimator.
//! Crops are pooled and class independent; absence of a flag is not a CT proof.
use rand_chacha::ChaCha20Rng;
use secp256kfun::{
    G, Point, Scalar, g,
    marker::*,
    rand_core::{RngCore, SeedableRng},
};
use secp256kfun_ct_audit as audit;
use std::hint;

fn welch_t(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return f64::NAN;
    }
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var = |v: &[f64], m: f64| {
        v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)
    };
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

fn percentile(sorted: &[f64], fraction: f64) -> f64 {
    sorted[(((sorted.len() - 1) as f64) * fraction) as usize]
}

struct Row {
    name: String,
    n0: usize,
    n1: usize,
    t: [f64; 4],
    median0: f64,
    median1: f64,
}

fn measure<I: Clone>(
    name: String,
    rng: &mut ChaCha20Rng,
    samples: usize,
    mut make: impl FnMut(bool, &mut ChaCha20Rng) -> I,
    mut op: impl FnMut(&I),
) -> Row {
    let mut classes = Vec::with_capacity(samples);
    let mut inputs = Vec::with_capacity(samples);
    for _ in 0..samples {
        let class = rng.next_u32() & 1 == 1;
        classes.push(class);
        inputs.push(make(class, rng));
    }
    for input in inputs.iter().take(64) {
        op(input);
    }
    let mut all = Vec::with_capacity(samples);
    let mut t0 = Vec::new();
    let mut t1 = Vec::new();
    for (class, input) in classes.iter().zip(&inputs) {
        let start = std::time::Instant::now();
        op(std::hint::black_box(input));
        let ns = start.elapsed().as_nanos() as f64;
        all.push(ns);
        if *class { t1.push(ns) } else { t0.push(ns) }
    }
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let cutoffs = [0.9, 0.75, 0.5].map(|f| percentile(&all, f));
    let below = |v: &[f64], cut: f64| v.iter().copied().filter(|x| *x <= cut).collect::<Vec<_>>();
    let sorted = |v: &[f64]| {
        let mut s = v.to_vec();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        s
    };
    Row {
        name,
        n0: t0.len(),
        n1: t1.len(),
        t: [
            welch_t(&t0, &t1),
            welch_t(&below(&t0, cutoffs[0]), &below(&t1, cutoffs[0])),
            welch_t(&below(&t0, cutoffs[1]), &below(&t1, cutoffs[1])),
            welch_t(&below(&t0, cutoffs[2]), &below(&t1, cutoffs[2])),
        ],
        median0: percentile(&sorted(&t0), 0.5),
        median1: percentile(&sorted(&t1), 0.5),
    }
}

fn hex(s: &Scalar<impl Secrecy, impl ZeroChoice>) -> String {
    s.to_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

fn fmt_t(t: f64) -> String {
    if t.is_nan() {
        format!("{:>9}", "n/a")
    } else {
        format!("{t:>9.2}")
    }
}

fn print(row: Row) {
    println!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}",
        row.name,
        row.n0,
        row.n1,
        fmt_t(row.t[0]),
        fmt_t(row.t[1]),
        fmt_t(row.t[2]),
        fmt_t(row.t[3]),
        row.median0,
        row.median1
    );
}

#[inline(never)]
fn delay<const N: usize>(mut value: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(".rept {n}", "add {v}, {v}, #1", ".endr",
                         n = const N, v = inout(reg) value, options(nomem, nostack));
    }
    #[cfg(not(target_arch = "aarch64"))]
    for _ in 0..N {
        value = hint::black_box(value).wrapping_add(1);
    }
    value
}

fn calibration<const N: usize>(rng: &mut ChaCha20Rng, samples: usize, fixed: Scalar) {
    let batch = |with_delay: bool| {
        let start = std::time::Instant::now();
        for _ in 0..1024 {
            hint::black_box(if with_delay {
                delay::<N>(hint::black_box(7))
            } else {
                delay::<0>(hint::black_box(7))
            });
        }
        start.elapsed().as_nanos() as f64 / 1024.0
    };
    let mut deltas = Vec::new();
    for _ in 0..101 {
        let d = if rng.next_u32() & 1 == 0 {
            let base = batch(false);
            batch(true) - base
        } else {
            let added = batch(true);
            added - batch(false)
        };
        deltas.push(d);
    }
    deltas.sort_by(f64::total_cmp);
    println!(
        "calibration adds={N} incremental_ns median={:.3} p10={:.3} p90={:.3}",
        percentile(&deltas, 0.5),
        percentile(&deltas, 0.1),
        percentile(&deltas, 0.9)
    );
    print(measure(
        format!("CALIBRATION k*G + {N} adds"),
        rng,
        samples,
        |c, _| c,
        |c| {
            hint::black_box(audit::audit_mul_base(hint::black_box(&fixed)));
            hint::black_box(if *c {
                delay::<N>(hint::black_box(7))
            } else {
                delay::<0>(hint::black_box(7))
            });
        },
    ));
}

fn normalize_batch(point: &audit::P) {
    for _ in 0..16 {
        hint::black_box(audit::audit_normalize(*hint::black_box(point)));
    }
}

fn normalization_experiment(rng: &mut ChaCha20Rng, samples: usize, point: Point) {
    let projective = g!(point + G).secret();
    assert!(projective.non_zero().is_some());
    let z_one = projective.normalize().non_normal();
    assert_eq!(projective, z_one);
    let identity = audit::P::zero();
    println!(
        "normalization_batch_calls=16 medians_ns=whole_batch nonidentity_affine={}",
        z_one.normalize()
    );
    for (name, class0, class1) in [
        ("normalize IDENTICAL projective", projective, projective),
        ("normalize IDENTICAL z=1", z_one, z_one),
        ("normalize identity/projective", identity, projective),
        ("normalize identity/z=1", identity, z_one),
        ("normalize nonidentity z=1/projective", z_one, projective),
    ] {
        print(measure(
            name.into(),
            rng,
            samples,
            |class, _| if class { class1 } else { class0 },
            normalize_batch,
        ));
    }
    print(measure(
        "normalize POSITIVE +4096 adds".into(),
        rng,
        samples,
        |class, _| class,
        |class| {
            normalize_batch(&projective);
            hint::black_box(if *class {
                delay::<4096>(hint::black_box(7))
            } else {
                delay::<0>(hint::black_box(7))
            });
        },
    ));
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod timingsafe {
    unsafe extern "C" {
        fn timingsafe_enable_if_supported() -> u64;
        fn timingsafe_restore_if_supported(token: u64);
    }
    pub fn read_dit() -> u64 {
        let value;
        unsafe {
            core::arch::asm!("mrs {v}, S3_3_C4_C2_5", v=out(reg) value, options(nomem,nostack));
        }
        value
    }
    pub struct Guard {
        token: Option<u64>,
        previous: u64,
    }
    impl Guard {
        pub fn new(enable: bool) -> Self {
            let before = read_dit();
            let token = enable.then(|| unsafe { timingsafe_enable_if_supported() });
            let after = read_dit();
            println!("timingsafe_requested={enable} DIT_before={before:#x} DIT_during={after:#x}");
            Self {
                token,
                previous: before,
            }
        }
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(t) = self.token {
                unsafe {
                    timingsafe_restore_if_supported(t);
                }
            }
            let restored = read_dit();
            println!("DIT_restored={restored:#x}");
            assert_eq!(
                restored, self.previous,
                "timing experiment changed prior DIT state"
            );
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let seed = args.next().map(|s| s.parse().expect("seed")).unwrap_or(1);
    let samples = args
        .next()
        .map(|s| s.parse().expect("samples"))
        .unwrap_or(100_000);
    assert!(samples >= 1000, "at least 1000 samples");
    let options: Vec<_> = args.collect();
    let (enable, focused) = match options.as_slice() {
        [] => (false, false),
        [mode] if mode == "timingsafe" => (true, false),
        [mode] if mode == "normalize" => (false, true),
        [mode, focus] if mode == "timingsafe" && focus == "normalize" => (true, true),
        _ => panic!("usage: ct_timing SEED SAMPLES [timingsafe] [normalize]"),
    };
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let _guard = timingsafe::Guard::new(enable);
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    assert!(!enable, "timingsafe experiment is macOS aarch64 only");
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let fixed = Scalar::random(&mut rng);
    let point = Point::random(&mut rng);
    println!(
        "seed={seed} samples={samples} fixed={} point={point}",
        hex(&fixed)
    );
    println!("test\tn0\tn1\tt-all\tt90\tt75\tt50\tmedian0-ns\tmedian1-ns");
    if focused {
        normalization_experiment(&mut rng, samples, point);
        return;
    }
    for (name, operation) in [
        ("k*G", audit::audit_mul_base as fn(&Scalar) -> _),
        ("k*G normalize", |k: &Scalar| {
            audit::audit_mul_normalize(k).non_normal()
        }),
    ] {
        print(measure(
            format!("{name} IDENTICAL"),
            &mut rng,
            samples,
            |_, _| fixed,
            |k| {
                hint::black_box(operation(k));
            },
        ));
        print(measure(
            format!("{name} one/random"),
            &mut rng,
            samples,
            |c, r| if c { Scalar::random(r) } else { Scalar::one() },
            |k| {
                hint::black_box(operation(k));
            },
        ));
    }
    print(measure(
        "k*P IDENTICAL".into(),
        &mut rng,
        samples,
        |_, _| fixed,
        |k| {
            hint::black_box(audit::audit_mul_normal(k, &point));
        },
    ));
    print(measure(
        "k*P fixed/random".into(),
        &mut rng,
        samples,
        |c, r| if c { Scalar::random(r) } else { fixed },
        |k| {
            hint::black_box(audit::audit_mul_normal(k, &point));
        },
    ));
    print(measure(
        "invert IDENTICAL".into(),
        &mut rng,
        samples,
        |_, _| fixed,
        |k| {
            hint::black_box(audit::audit_scalar_invert(k));
        },
    ));
    print(measure(
        "invert one/random".into(),
        &mut rng,
        samples,
        |c, r| if c { Scalar::random(r) } else { Scalar::one() },
        |k| {
            hint::black_box(audit::audit_scalar_invert(k));
        },
    ));
    let normal = point.secret().mark_zero();
    print(measure(
        "normal eq IDENTICAL".into(),
        &mut rng,
        samples,
        |_, _| normal,
        |p| {
            hint::black_box(audit::audit_normal_eq(p, &normal));
        },
    ));
    print(measure(
        "normal eq identity/nonidentity".into(),
        &mut rng,
        samples,
        |c, _| if c { normal } else { audit::N::zero() },
        |p| {
            hint::black_box(audit::audit_normal_eq(p, &normal));
        },
    ));
    let nonnormal = g!(point + G).secret();
    print(measure(
        "normalize IDENTICAL".into(),
        &mut rng,
        samples,
        |_, _| nonnormal,
        |p| {
            hint::black_box(audit::audit_normalize(*p));
        },
    ));
    print(measure(
        "normalize identity/nonidentity".into(),
        &mut rng,
        samples,
        |c, _| if c { nonnormal } else { audit::P::zero() },
        |p| {
            hint::black_box(audit::audit_normalize(*p));
        },
    ));
    calibration::<0>(&mut rng, samples, fixed);
    calibration::<4>(&mut rng, samples, fixed);
    calibration::<16>(&mut rng, samples, fixed);
    calibration::<64>(&mut rng, samples, fixed);
    calibration::<256>(&mut rng, samples, fixed);
    calibration::<1024>(&mut rng, samples, fixed);
}

#[cfg(test)]
mod tests {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn timing_mode_restores_nested_and_unwound_scopes() {
        let before = super::timingsafe::read_dit();
        {
            let _outer = super::timingsafe::Guard::new(true);
            let enabled = super::timingsafe::read_dit();
            assert_eq!(enabled, 0x1000000);
            let result = std::panic::catch_unwind(|| {
                let _inner = super::timingsafe::Guard::new(true);
                assert_eq!(super::timingsafe::read_dit(), enabled);
                panic!("exercise restoration during unwinding");
            });
            assert!(result.is_err());
            assert_eq!(super::timingsafe::read_dit(), enabled);
        }
        assert_eq!(super::timingsafe::read_dit(), before);
    }

    #[test]
    fn welch_degenerate_and_known_distribution() {
        assert!(super::welch_t(&[1.0], &[1.0, 2.0]).is_nan());
        assert!(super::welch_t(&[1.0, 1.0], &[1.0, 1.0]).is_nan());
        assert_eq!(super::welch_t(&[1.0, 1.0], &[2.0, 2.0]), f64::NEG_INFINITY);
        assert!((super::welch_t(&[1.0, 2.0, 3.0], &[2.0, 3.0, 4.0]) + 1.224744871).abs() < 1e-8);
    }
}
