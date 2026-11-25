use core::{hint, mem};
use rand_chacha::ChaCha20Rng;
use secp256kfun::{G, Point, Scalar, g, rand_core::SeedableRng};
use secp256kfun_ct_audit as audit;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn request(code: usize, address: usize, length: usize) -> usize {
    let args = [code, address, length, 0, 0, 0];
    let result;
    // Valgrind's documented amd64 client-request ABI; the sequence is inert natively.
    unsafe {
        core::arch::asm!(
            "rol rdi, 3", "rol rdi, 13", "rol rdi, 61", "rol rdi, 51",
            "xchg rbx, rbx",
            in("rax") args.as_ptr(), inout("rdx") 0usize => result,
            out("rdi") _, options(nostack),
        );
    }
    result
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn request(_: usize, _: usize, _: usize) -> usize {
    0
}

fn mark<T>(value: &mut T, secret: bool) {
    let code = if secret { 0x4d43_0001 } else { 0x4d43_0002 };
    self::request(code, (value as *mut T) as usize, mem::size_of::<T>());
}

pub fn run() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("--defined");
    let taint = mode == "--taint" || mode.starts_with("--secret-control-");
    assert!(
        [
            "--defined",
            "--taint",
            "--secret-control-branch",
            "--secret-control-address",
            "--public-control-branch",
            "--public-control-address"
        ]
        .contains(&mode)
    );
    if taint {
        assert_ne!(
            self::request(0x1001, 0, 0),
            0,
            "taint mode requires Linux amd64 Valgrind"
        );
    }
    if mode.contains("-control-") {
        #[cfg(feature = "negative-controls")]
        {
            for byte in [0u32, 1, 127, 255] {
                let mut value = audit::S::from(byte);
                self::mark(&mut value, taint);
                if mode.ends_with("branch") {
                    hint::black_box(audit::controls::ct_control_branch(&value));
                } else {
                    hint::black_box(audit::controls::ct_control_address(
                        &value,
                        &hint::black_box([7; 256]),
                    ));
                }
                self::mark(&mut value, false);
            }
            println!("{mode}: 4 scalar control cases completed");
            return;
        }
        #[cfg(not(feature = "negative-controls"))]
        panic!("control mode requires the audit-only negative-controls feature");
    }
    let selected = args.get(1).map(String::as_str).unwrap_or("all");
    let mut executed = 0;
    let mut rng = ChaCha20Rng::seed_from_u64(0x4354);
    for case in 0..12 {
        let mut k = match case {
            0 => Scalar::one(),
            1 => Scalar::minus_one(),
            _ => Scalar::random(&mut rng),
        };
        let mut x = if case == 2 {
            audit::S::zero()
        } else {
            k.mark_zero()
        };
        let mut y = Scalar::random(&mut rng).mark_zero();
        let mut public = Point::random(&mut rng);
        if case == 0 {
            public = G.normalize();
        }
        let nonnormal = g!(public + public).non_zero().unwrap();
        let mut n = if case == 2 || case == 6 {
            audit::N::zero()
        } else {
            public.secret().mark_zero()
        };
        let mut p = if case == 2 {
            audit::P::zero()
        } else {
            g!(public + public).secret()
        };
        let mut q = match case {
            3 => p,
            4 => -p,
            5 => audit::P::zero(),
            _ => g!(public + G).secret(),
        };
        let mut m = match case {
            3 => n,
            4 => -n,
            5 | 6 => audit::N::zero(),
            _ => q.normalize(),
        };
        let mut nonzero = public.secret();
        let mut cond = case % 2 != 0;
        let mut scalars = [x, y];
        let mut points = [n, m];
        self::mark(&mut k, taint);
        self::mark(&mut x, taint);
        self::mark(&mut y, taint);
        self::mark(&mut n, taint);
        self::mark(&mut p, taint);
        self::mark(&mut q, taint);
        self::mark(&mut m, taint);
        self::mark(&mut cond, taint);
        self::mark(&mut nonzero, taint);
        self::mark(&mut scalars, taint);
        self::mark(&mut points, taint);
        macro_rules! check {
            ($root:ident($($arg:expr),*)) => {
                if selected == "all" || selected == stringify!($root) {
                    hint::black_box(audit::$root($(hint::black_box($arg)),*));
                    executed += 1;
                    println!("case={case} root={} completed", stringify!($root));
                }
            };
        }
        check!(audit_mul_base(&k));
        check!(audit_mul_normal(&k, &public));
        check!(audit_mul_nonnormal(&k, &nonnormal));
        check!(audit_mul_secret_point(&x, &p));
        check!(audit_double_mul(&x, &n, &y, &p));
        check!(audit_dot_product(&scalars[..1 + case % 2], &points));
        check!(audit_point_add(&p, &q));
        check!(audit_point_add_normal(&p, &n));
        check!(audit_point_negate(&p));
        check!(audit_normal_negate(&n));
        check!(audit_point_cond_negate(&p, cond));
        check!(audit_normal_cond_negate(&n, cond));
        check!(audit_normalize(p));
        check!(audit_mul_normalize(&k));
        check!(audit_point_eq(&p, &q));
        check!(audit_point_eq_normal(&p, &n));
        check!(audit_normal_eq(&n, &m));
        check!(audit_y_even(&nonzero));
        check!(audit_scalar_add(&x, &y));
        check!(audit_scalar_sub(&x, &y));
        check!(audit_scalar_mul(&x, &y));
        check!(audit_scalar_invert(&k));
        check!(audit_scalar_negate(&x));
        check!(audit_scalar_cond_negate(x, cond));
        check!(audit_scalar_eq(&x, &y));
        check!(audit_scalar_is_high(&x));
        check!(audit_scalar_is_zero(&x));
        check!(audit_scalar_dot(&scalars[..case % 3], &scalars));
        self::mark(&mut k, false);
        self::mark(&mut x, false);
        self::mark(&mut y, false);
        self::mark(&mut n, false);
        self::mark(&mut p, false);
        self::mark(&mut q, false);
        self::mark(&mut m, false);
        self::mark(&mut cond, false);
        self::mark(&mut nonzero, false);
        self::mark(&mut scalars, false);
        self::mark(&mut points, false);
    }
    assert_ne!(executed, 0, "unknown audit root");
    println!("{mode} {selected}: {executed} calls, 12 deterministic valid-input cases");
}
