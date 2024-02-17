#![cfg(feature = "share_backup")]
use core::str::FromStr;
use schnorr_fun::share_backup::{decode_backup, polynomial_identifier, ShareBackup};
use secp256kfun::{marker::*, poly, s, Scalar};

#[test]
fn short_backup() {
    let secret_poly = vec![s!(6), s!(1), s!(9)];
    let polynomial: Vec<_> = poly::scalar::to_point_poly(&secret_poly);
    let threshold = polynomial.len() as u16;
    let share_index = s!(12).public();
    let secret_share = poly::scalar::eval(&secret_poly, share_index);

    let share_backup = ShareBackup::new::<sha2::Sha256>(&polynomial, secret_share, share_index);
    let share_backup_bech32 = format!("{}", share_backup);

    let decoded_share_backup = decode_backup(share_backup_bech32).unwrap();

    assert_eq!(threshold, decoded_share_backup.threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(&polynomial),
        decoded_share_backup.identifier
    );
    assert_eq!(secret_share, decoded_share_backup.secret_share);
    assert_eq!(share_index, decoded_share_backup.share_index);
}

#[test]
fn long_backup() {
    let secret_poly = vec![s!(1), s!(2), s!(3)];
    let polynomial: Vec<_> = poly::scalar::to_point_poly(&secret_poly);
    let threshold = polynomial.len() as u16;
    let share_index = Scalar::<Secret>::from_str(
        "34f7ce653cfa8454b3463726a599ef2925736442d2d06455974d6feae9450d90",
    )
    .unwrap()
    .public();
    let secret_share = poly::scalar::eval(&secret_poly, share_index);

    let share_backup = ShareBackup::new::<sha2::Sha256>(&polynomial, secret_share, share_index);
    let share_backup_bech32 = format!("{}", share_backup);
    dbg!(&share_backup_bech32);

    let decoded_share_backup = decode_backup(share_backup_bech32).unwrap();

    assert_eq!(threshold, decoded_share_backup.threshold);
    assert_eq!(
        polynomial_identifier::<sha2::Sha256>(&polynomial),
        decoded_share_backup.identifier
    );
    assert_eq!(secret_share, decoded_share_backup.secret_share);
    assert_eq!(share_index, decoded_share_backup.share_index);
}

#[test]
#[should_panic(expected = "too high of a threshold")]
fn threshold_too_high() {
    let secret_poly: Vec<Scalar> = (0..1025).map(|_| s!(1)).collect();
    let polynomial: Vec<_> = poly::scalar::to_point_poly(&secret_poly);
    let share_index = Scalar::<Secret>::from_str(
        "91dbab9f62660e95258480d2f2cff6dcfdb513f28a85fa4fb55ee993a5b46809",
    )
    .unwrap()
    .public();
    let secret_share = poly::scalar::eval(&secret_poly, share_index);
    ShareBackup::new::<sha2::Sha256>(&polynomial, secret_share, share_index);
}

#[test]
#[should_panic(expected = "threshold can not be zero")]
fn threshold_zero() {
    let secret_poly: Vec<Scalar> = vec![];
    let polynomial: Vec<_> = poly::scalar::to_point_poly(&secret_poly);
    let share_index = Scalar::<Secret>::from_str(
        "000000000000000000000000000000000000000000000066726F7374736E6170",
    )
    .unwrap()
    .public();
    let secret_share = Scalar::<Secret, Zero>::from_str(
        "00000000000000000000000000656C656374726F6E696320707972616D696473",
    )
    .unwrap();

    ShareBackup::new::<sha2::Sha256>(&polynomial, secret_share, share_index);
}

#[test]
#[should_panic(expected = "Secret share is not valid with respect to the polynomial")]
fn share_not_on_poly() {
    let secret_poly: Vec<Scalar> = vec![s!(1), s!(2), s!(3)];
    let polynomial: Vec<_> = poly::scalar::to_point_poly(&secret_poly);
    let share_index = Scalar::<Secret>::from_str(
        "00000000000000000000000000000000000000000000006672656520726F7373",
    )
    .unwrap()
    .public();
    let secret_share = Scalar::<Secret, Zero>::from_str(
        "0000000000000000626974636F696E2068616C76696E6720746F6F2066617374",
    )
    .unwrap();

    ShareBackup::new::<sha2::Sha256>(&polynomial, secret_share, share_index);
}
