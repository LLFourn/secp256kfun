#![cfg(feature = "alloc")]
use secp256kfun::{poly, prelude::*};

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
fn test_mul_scalar_poly() {
    let poly1 = [s!(1), s!(2), s!(3)];
    let poly2 = [s!(4), s!(5)];

    let res = poly::scalar::mul(&poly1[..], &poly2[..]);

    assert_eq!(res, vec![s!(4), s!(13), s!(22), s!(15)]);
}
