#![cfg(feature = "frost_backup")]
use core::str::FromStr;
use schnorr_fun::{
    frost::{self, scalar_poly_eval},
    frost_backup::{
        decode_backup, encode_backup, interpolate_point_polynomial, polynomial_identifier,
        reconstruct_shared_secret,
    },
};
use secp256kfun::{g, marker::Secret, s, Scalar, G};

#[test]
fn frost_backup_short() {
    let polynomial = vec![g!(1 * G).normalize()];
    let threshold = polynomial.len();
    let secret_share = Scalar::<Secret>::from_str(
        "1234123412341234123412341234123412341234123412341234123412341234",
    )
    .unwrap();
    let share_index = s!(7);

    let frost_backup = encode_backup::<sha2::Sha256>(&polynomial, &secret_share, &share_index);
    dbg!(&frost_backup);

    let (decoded_threshold, decoded_identifier, decoded_secret_share, decoded_share_index) =
        decode_backup(frost_backup).unwrap();

    assert_eq!(threshold, decoded_threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(polynomial),
        decoded_identifier
    );
    assert_eq!(secret_share, decoded_secret_share);
    assert_eq!(share_index, decoded_share_index);
}

#[test]
fn frost_backup_long() {
    let polynomial = vec![
        g!(1 * G).normalize(),
        g!(2 * G).normalize(),
        g!(3 * G).normalize(),
    ]; // some polynomial coefficients
    let threshold = polynomial.len();
    let secret_share = Scalar::<Secret>::from_str(
        "7373737373737373737373737373737373737373737373737373737373737373",
    )
    .unwrap();
    let share_index = Scalar::<Secret>::from_str(
        "34f7ce653cfa8454b3463726a599ef2925736442d2d06455974d6feae9450d90",
    )
    .unwrap();

    let frost_backup = encode_backup::<sha2::Sha256>(&polynomial, &secret_share, &share_index);
    dbg!(&frost_backup);

    let (decoded_threshold, decoded_identifier, decoded_secret_share, decoded_share_index) =
        decode_backup(frost_backup).unwrap();

    assert_eq!(threshold, decoded_threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(polynomial),
        decoded_identifier
    );
    assert_eq!(secret_share, decoded_secret_share);
    assert_eq!(share_index, decoded_share_index);
}

#[test]
fn test_recover_public_poly() {
    let poly = vec![g!(1 * G), g!(2 * G), g!(3 * G)];
    let indexes = vec![s!(5), s!(3), s!(2)];
    let evaluations = indexes
        .clone()
        .into_iter()
        .map(|index| {
            frost::point_poly_eval(&poly, index.public())
                .normalize()
                .non_zero()
                .unwrap()
        })
        .collect::<Vec<_>>();

    let interpolation = interpolate_point_polynomial(indexes, evaluations);
    assert_eq!(interpolation, poly)
}

#[test]
fn test_reconstruct_shared_secret() {
    let scalar_poly = vec![s!(42), s!(53), s!(64)];
    // let point_poly = frost::to_point_poly(&scalar_poly);
    let indexes = vec![s!(1), s!(2), s!(3)];

    let secret_shares: Vec<_> = indexes
        .clone()
        .into_iter()
        .map(|index| scalar_poly_eval(&scalar_poly, index))
        .collect();

    let reconstructed_secret = reconstruct_shared_secret(indexes, secret_shares);
    assert_eq!(scalar_poly[0], reconstructed_secret);
}
