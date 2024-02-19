#![cfg(feature = "alloc")]
use secp256kfun::{g, marker::*, poly, s, Point, G};

#[test]
fn test_lagrange_lambda() {
    let res = s!((1 * 4 * 5) / { s!((1 - 2) * (4 - 2) * (5 - 2)).non_zero().unwrap() });
    assert_eq!(
        res,
        poly::eval_basis_poly_at_0(s!(2), [s!(1), s!(4), s!(5)].iter())
    );
}

#[test]
fn test_add_poly() {
    let poly1 = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let poly2 = vec![g!(8 * G), g!(5 * G), g!(11 * G)];

    let addition = poly::point::add(&poly1, &poly2);
    assert_eq!(addition, vec![g!(9 * G), g!(7 * G), g!(14 * G)])
}

#[test]
fn test_add_poly_unequal_len() {
    let poly1 = vec![g!(1 * G)];
    let poly2 = vec![g!(8 * G), g!(5 * G)];
    let addition = poly::point::add(&poly1, &poly2);
    assert_eq!(addition, vec![g!(9 * G), g!(5 * G)]);

    let poly1 = vec![g!(3 * G), g!(1 * G)];
    let poly2 = vec![g!(5 * G)];
    let addition = poly::point::add(&poly1, &poly2);
    assert_eq!(addition, vec![g!(8 * G), g!(1 * G)]);
}

#[test]
fn test_recover_public_poly() {
    let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let indicies = vec![s!(1).public(), s!(3).public(), s!(2).public()];
    let points = indicies
        .clone()
        .into_iter()
        .map(|index| {
            (
                index,
                poly::point::eval(&poly, index.public())
                    .normalize()
                    .non_zero()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let interpolation = poly::point::interpolate(points);
    assert_eq!(interpolation, poly)
}

#[test]
fn test_recover_overdetermined_poly() {
    let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let indicies = vec![
        s!(1).public(),
        s!(2).public(),
        s!(3).public(),
        s!(4).public(),
        s!(5).public(),
    ];
    let points = indicies
        .clone()
        .into_iter()
        .map(|index| {
            (
                index,
                poly::point::eval(&poly, index.public())
                    .normalize()
                    .non_zero()
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let interpolation = poly::point::interpolate(points);

    let (interpolated_coeffs, zero_coeffs) = interpolation.split_at(poly.len());
    let n_extra_points = indicies.len() - poly.len();
    assert_eq!(
        (0..n_extra_points)
            .map(|_| Point::<Normal, Public, Zero>::zero().public().normalize())
            .collect::<Vec<_>>(),
        zero_coeffs.to_vec()
    );
    assert_eq!(interpolated_coeffs, poly);
}

#[test]
fn test_reconstruct_shared_secret() {
    let indicies = vec![s!(1).public(), s!(2).public(), s!(3).public()];
    let scalar_poly = vec![s!(42), s!(53), s!(64)];

    let secret_shares: Vec<_> = indicies
        .clone()
        .into_iter()
        .map(|index| (index, poly::scalar::eval(&scalar_poly, index)))
        .collect();

    let reconstructed_secret = poly::scalar::interpolate_and_eval_poly_at_0(secret_shares);
    assert_eq!(scalar_poly[0], reconstructed_secret);
}
