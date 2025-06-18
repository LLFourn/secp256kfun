#![cfg(feature = "alloc")]
use secp256kfun::{poly, prelude::*};

#[cfg(feature = "proptest")]
use proptest::prelude::*;

#[test]
fn test_lagrange_lambda() {
    let res = s!((1 * 4 * 5) / { s!((1 - 2) * (4 - 2) * (5 - 2)).non_zero().unwrap() });
    assert_eq!(
        res,
        poly::eval_basis_poly_at_0(s!(2), [s!(1), s!(4), s!(5)])
    );
}

#[test]
fn test_lagrange_basis_poly() {
    let indices = vec![
        s!(1).public(),
        s!(2).public(),
        s!(4).public(),
        s!(5).public(),
    ];
    let basis_poly = poly::lagrange_basis_poly(indices[1], indices.clone());
    assert_eq!(
        poly::scalar::eval(&basis_poly[..], s!(0)),
        poly::eval_basis_poly_at_0(indices[1], indices.clone())
    );
}

#[test]
fn test_add_point_poly() {
    let mut poly1 = vec![
        g!(1 * G).mark_zero(),
        g!(2 * G).mark_zero(),
        g!(3 * G).mark_zero(),
    ];
    let poly2 = vec![g!(8 * G), g!(5 * G), g!(11 * G), g!(42 * G)];

    let addition = poly::point::add(poly1.clone(), poly2.clone()).collect::<Vec<_>>();
    assert_eq!(addition, vec![g!(9 * G), g!(7 * G), g!(14 * G), g!(42 * G)]);

    poly::point::add_in_place(&mut poly1, poly2);

    assert_eq!(poly1, addition);
}

#[test]
fn test_add_scalar_poly() {
    let mut poly1 = vec![s!(1).mark_zero(), s!(2).mark_zero(), s!(3).mark_zero()];
    let poly2 = vec![s!(8), s!(5), s!(11), s!(42)];

    let addition = poly::scalar::add(poly1.clone(), poly2.clone()).collect::<Vec<_>>();
    assert_eq!(addition, vec![s!(9), s!(7), s!(14), s!(42)]);

    poly::scalar::add_in_place(&mut poly1, poly2);

    assert_eq!(poly1, addition);
}

#[test]
fn test_recover_public_poly() {
    let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let indices = vec![s!(1).public(), s!(3).public(), s!(2).public()];
    let points = indices
        .clone()
        .into_iter()
        .map(|index| {
            (
                index,
                poly::point::eval(&poly, index)
                    .normalize()
                    .non_zero()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let interpolation = poly::point::interpolate(&points);
    assert_eq!(interpolation, poly)
}

#[test]
fn test_recover_overdetermined_poly() {
    let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let indices = vec![
        s!(1).public(),
        s!(2).public(),
        s!(3).public(),
        s!(4).public(),
        s!(5).public(),
    ];
    let points = indices
        .clone()
        .into_iter()
        .map(|index| (index, poly::point::eval(&poly, index.public()).normalize()))
        .collect::<Vec<_>>();

    let interpolation = poly::point::interpolate(&points);

    assert_eq!(interpolation, poly);
}

#[test]
fn test_recover_zero_poly() {
    let interpolation = poly::point::interpolate(&[
        (s!(1).public(), Point::<Normal, Public, _>::zero()),
        (s!(2).public(), Point::<Normal, Public, _>::zero()),
    ]);

    assert_eq!(
        interpolation,
        vec![Point::<NonNormal, Public, _>::zero()],
        "should not be empty vector"
    );
}

#[test]
fn test_reconstruct_shared_secret() {
    let indices = vec![s!(1).public(), s!(2).public(), s!(3).public()];
    let scalar_poly = vec![s!(42), s!(53), s!(64)];

    let secret_shares: Vec<_> = indices
        .clone()
        .into_iter()
        .map(|index| (index, poly::scalar::eval(&scalar_poly, index)))
        .collect();

    let reconstructed_secret = poly::scalar::interpolate_and_eval_poly_at_0(&secret_shares[..]);
    assert_eq!(scalar_poly[0], reconstructed_secret);
}

#[test]
fn test_trusted_dealer_shamir_sharing() {
    let secret = s!(42);
    let threshold = 3;
    let n_shares = 5;

    let shares: Vec<_> = poly::scalar::trusted_dealer_shamir_sharing(
        secret,
        threshold,
        n_shares,
        &mut rand::thread_rng(),
    )
    .collect();

    // Verify we got the expected number of shares
    assert_eq!(shares.len(), n_shares);

    // Take threshold shares and reconstruct
    let selected_shares = &shares[0..threshold];
    let reconstructed = poly::scalar::interpolate_and_eval_poly_at_0(selected_shares);
    assert_eq!(reconstructed, secret);

    // Test with different subset of shares
    let selected_shares = &shares[2..5];
    let reconstructed = poly::scalar::interpolate_and_eval_poly_at_0(selected_shares);
    assert_eq!(reconstructed, secret);
}

#[test]
fn test_mul_scalar_poly() {
    let poly1 = [s!(1), s!(2), s!(3)];
    let poly2 = [s!(4), s!(5)];

    let res = poly::scalar::mul(&poly1[..], &poly2[..]);

    assert_eq!(res, vec![s!(4), s!(13), s!(22), s!(15)]);
}

#[cfg(feature = "proptest")]
mod proptest_tests {
    use super::*;
    use rand::seq::SliceRandom;

    proptest! {
        #[test]
        fn trusted_dealer_shamir_sharing_reconstruction(
            secret_bytes in any::<[u8; 32]>(),
            threshold in 2usize..10usize,
            extra_shares in 0usize..5usize,
        ) {
            let secret = Scalar::<Secret, Zero>::from_bytes_mod_order(secret_bytes);
            let n_shares = threshold + extra_shares;

            let shares: Vec<_> = poly::scalar::trusted_dealer_shamir_sharing(
                secret,
                threshold,
                n_shares,
                &mut rand::thread_rng()
            ).collect();

            // Verify we got the expected number of shares
            prop_assert_eq!(shares.len(), n_shares);

            // Verify all share indices are unique and sequential
            for (i, (share_index, _)) in shares.iter().enumerate() {
                let expected_index = Scalar::<Public, Zero>::from(i + 1).non_zero().expect("> 0");
                prop_assert_eq!(*share_index, expected_index);
            }

            // Test reconstruction with exactly threshold shares
            let mut rng = rand::thread_rng();
            let selected_shares: Vec<_> = shares
                .choose_multiple(&mut rng, threshold)
                .cloned()
                .collect();

            let reconstructed = poly::scalar::interpolate_and_eval_poly_at_0(&selected_shares);
            prop_assert_eq!(reconstructed, secret);

            // Test reconstruction with more than threshold shares (overdetermined)
            if extra_shares > 0 {
                let overdetermined_shares: Vec<_> = shares
                    .choose_multiple(&mut rng, threshold + 1)
                    .cloned()
                    .collect();

                let reconstructed_overdetermined =
                    poly::scalar::interpolate_and_eval_poly_at_0(&overdetermined_shares);
                prop_assert_eq!(reconstructed_overdetermined, secret);
            }
        }
    }
}
