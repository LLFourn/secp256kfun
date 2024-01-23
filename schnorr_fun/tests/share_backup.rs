#![cfg(feature = "share_backup")]
use core::str::FromStr;
use schnorr_fun::share_backup::{decode_backup, encode_backup, polynomial_identifier};
use secp256kfun::{g, marker::Secret, poly, s, Scalar, G};

#[test]
fn share_backup_short() {
    let secret_poly = vec![s!(6), s!(1), s!(9)];
    let polynomial: Vec<_> = secret_poly.iter().map(|c| g!(c * G).normalize()).collect(); // some polynomial coefficients
    let threshold = polynomial.len() as u16;
    let share_index = s!(12).public();
    let secret_share = poly::scalar::eval(&secret_poly, share_index)
        .non_zero()
        .unwrap();

    dbg!(&secret_share);
    let share_backup = encode_backup::<sha2::Sha256>(&polynomial, &secret_share, &share_index);
    dbg!(&share_backup);

    let (decoded_threshold, decoded_identifier, decoded_secret_share, decoded_share_index) =
        decode_backup(share_backup).unwrap();

    assert_eq!(threshold, decoded_threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(polynomial),
        decoded_identifier
    );
    assert_eq!(secret_share, decoded_secret_share);
    assert_eq!(share_index, decoded_share_index);
}

#[test]
fn share_backup_long() {
    let secret_poly = vec![s!(1), s!(2), s!(3)];
    let polynomial: Vec<_> = secret_poly.iter().map(|c| g!(c * G).normalize()).collect(); // some polynomial coefficients
    let threshold = polynomial.len() as u16;
    let share_index = Scalar::<Secret>::from_str(
        "34f7ce653cfa8454b3463726a599ef2925736442d2d06455974d6feae9450d90",
    )
    .unwrap()
    .public();
    let secret_share = poly::scalar::eval(&secret_poly, share_index)
        .non_zero()
        .unwrap();

    let share_backup = encode_backup::<sha2::Sha256>(&polynomial, &secret_share, &share_index);
    dbg!(&share_backup);

    let (decoded_threshold, decoded_identifier, decoded_secret_share, decoded_share_index) =
        decode_backup(share_backup).unwrap();

    assert_eq!(threshold, decoded_threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(polynomial),
        decoded_identifier
    );
    assert_eq!(secret_share, decoded_secret_share);
    assert_eq!(share_index, decoded_share_index);
}
