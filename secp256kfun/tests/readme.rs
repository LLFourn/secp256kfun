//! Peripheral tests check I'm not lying about stuff in the README.md
// had to be disabled because these give too many false positives.
// TODO come up with a rigorous approach to empirically verifying that one implementation runs faster than another.
#![allow(non_snake_case)]

// #[test]
// fn example_nonzero() {
//     use secp256kfun::{g, marker::*, Scalar, G};
//     // a randomly selected Scalar will never be zero (statistically unreachable)
//     let x = Scalar::random(&mut rand::thread_rng());
//     dbg!(&x); // x is Scalar<Secret, NonZero>
//     assert!(format!("{:?}", &x).starts_with("Scalar<Secret,NonZero>"));
//     // Multiplying a NonZero scalar by G (which is also NonZero) will result
//     // in another NonZero point
//     let X = g!(x * G);
//     assert!(format!("{:?}", &X).starts_with("Point<Jacobian,Public,NonZero>"));

//     let neg_X = -&X;
//     dbg!(&neg_X);
//     assert!(format!("{:?}", &neg_X).starts_with("Point<Jacobian,Public,NonZero>"));
//     // An addition can lead to zero (and in this case does).
//     let sum = g!(X + neg_X);
//     dbg!(&sum);
//     assert!(format!("{:?}", &sum).starts_with("Point<Jacobian,Public,Zero>"));

//     // Now we want to pass this to a function that expects a NonZero point so we
//     // mark it as NonZero and deal with the case it's Zero.
//     match sum.mark::<NonZero>() {
//         Some(_point) => panic!("it wasn't zero"),
//         None => eprintln!("it was zero"),
//     }
// }

// // const N_SAMPLES: usize = 12;
// // const WARM_UP: usize = 2;

// // #[test]
// fn exmaple_specializes_secrecy() {
//     use secp256kfun::{g, marker::*, Point, Scalar, G, TEST_SOUNDNESS};
//     use std::time::Instant;

//     fn pedersen_commit(
//         A: &Point<impl PointType>,
//         B: &Point<impl PointType>,
//         x: &Scalar<impl Secrecy>,
//         y: &Scalar<impl Secrecy>,
//     ) -> Point<Jacobian> {
//         g!(x * A + y * B)
//             .mark::<NonZero>()
//             .expect("computationally unreachable")
//     }

//     let B = Point::random(&mut rand::thread_rng());

//     for i in 0..(TEST_SOUNDNESS + WARM_UP) {
//         let r = Scalar::random(&mut rand::thread_rng());
//         let x = Scalar::random(&mut rand::thread_rng());

//         let before = Instant::now();
//         let mut commitment = pedersen_commit(&G, &B, &r, &x);
//         for _ in 0..N_SAMPLES {
//             commitment = pedersen_commit(&G, &B, &r, &x);
//         }
//         let elapsed_1 = before.elapsed();

//         let r = r.mark::<Public>();
//         let x = x.mark::<Public>();

//         let before = Instant::now();
//         let mut implied_commitment = pedersen_commit(&G, &B, &r, &x);
//         for _ in 0..N_SAMPLES {
//             implied_commitment = pedersen_commit(&G, &B, &r, &x);
//         }
//         let elapsed_2 = before.elapsed();

//         assert_eq!(commitment, implied_commitment);

//         if i >= WARM_UP {
//             assert!(elapsed_1 > elapsed_2);
//         }
//     }
// }

// //#[test]
// fn exmaple_specializes_basepoint() {
//     use secp256kfun::{marker::*, op::double_mul, Point, Scalar, G, TEST_SOUNDNESS};
//     use std::time::Instant;

//     fn pedersen_commit(
//         A: &Point<impl PointType>,
//         B: &Point<impl PointType>,
//         x: &Scalar<impl Secrecy>,
//         y: &Scalar<impl Secrecy>,
//     ) -> Point<Jacobian> {
//         double_mul(x, A, y, B)
//             .mark::<NonZero>()
//             .expect("computationally unreachable")
//     }

//     let B = Point::random(&mut rand::thread_rng()).mark::<Public>();
//     let A = Point::random(&mut rand::thread_rng()).mark::<Public>();

//     for i in 0..(TEST_SOUNDNESS + WARM_UP) {
//         let r = Scalar::random(&mut rand::thread_rng());
//         let x = Scalar::random(&mut rand::thread_rng());

//         let before = Instant::now();
//         for _ in 0..N_SAMPLES {
//             let _ = pedersen_commit(&G, &B, &r, &x);
//         }
//         let elapsed_1 = before.elapsed();

//         let before = Instant::now();

//         for _ in 0..N_SAMPLES {
//             let _ = pedersen_commit(&A, &B, &r, &x);
//         }
//         let elapsed_2 = before.elapsed();

//         if i >= WARM_UP {
//             assert!(elapsed_2 > elapsed_1);
//         }
//     }
// }
