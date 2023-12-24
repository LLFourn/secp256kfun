//! Backup scheme for shamir secret shares
//!
//! # Description
//!
//! Based on https://bips.xyz/93
//!
//! ## Backup format (bech32 chars)
//!
//! human readable: "frost"         // (4)
//! separator:      "1"             // (1)
//! threshold:      u5,             // (1)
//! identifier:     [u5; 4],        // (4)
//! secret_share:   [u5; 52],       // (52)
//! share_index:    u5 or [u5; 52], // (1 or 52)
//! checksum:       [u5; 6],        // (6)
//!
//! ## Justification
//!
//! ### Human Readable - (4 bech 32 characters)
//! frost1 looks cool.
//! Most of the time we will be using this backup scheme for FROST related shamir secret shares.
//!
//! ### Threshold - (1)
//! A threshold integer between 1 and 32.
//! Note: a threshold of zero is considered invalid, and threshold is encoded as minus one.
//!
//! While this threshold will generally be ~small, in theory could be much higher than 32.
//! Just doing up to 32 for now, but might be worth futureproofing also..
//! We could also leave higher thresholds for a later backup version.
//!
//! ### Polynomial Identifier - (4)
//! Hash of the polynomial coefficients and take the first 4 bech32 characters.
//! This identifier will allow determination of secret share compatibility.
//!
//! It is possible to have two different polynomials that interpolate the same joint-secret,
//! but shares on these different polynomials will not be compatible with one another.
//!
//! The probability of two polynomials having the same identifier is 1/32^4, about one in a million.
//!
//! ### Secret Share - (52)
//! A secret share scalar is fixed length scalar of 32 bytes.
//! This is 32 * 8 / 5 = 51.2 -> 52 bech32 characters
//!
//! ### Share Index - (1 or 52)
//! The share index can be be scalar, but will often be small for simplicity and smaller backups.
//! By leaving this data piece at the end, we can use the length of the remaining data to
//! easily decode a single bech32 char into integer, or 32 chars into a scalar.

use alloc::{string::String, vec::Vec};
use bech32::{u5, FromBase32, ToBase32, Variant::Bech32m};
use core::num::NonZeroU32;
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    hash::HashAdd,
    Point, Scalar,
};

/// An error encountered when encoding a Frostsnap backup.
#[derive(Debug, Copy, Clone)]
pub enum FrostBackupDecodeError {
    /// Decode error from bech32 library
    Bech32DecodeError(bech32::Error),
    /// Tried to decode a bech32 variant that was not bech32m
    WrongBech32Variant(bech32::Variant),
    /// Decoded secret share is not a valid secp256k1 scalar
    InvalidSecretShareScalar,
    /// Tried to decode backup with unknown prefix
    InvalidHumanReadablePrefix,
    /// The share index data length doesn't match expected for SmallIndex nor Scalar
    UnknownShareIndexLength,
    /// Decoded share index is not a valid secp256k1 scalar
    InvalidShareIndexScalar,
    /// Decoded share index is zero
    ShareIndexIsZero,
}

/// Create an identifier that's used to determine compatibility of shamir secret shares.
/// The first 4 bech32 chars from a hash of the polynomial coefficients.
/// Collision expected once in (32)^4 = 2^20.
pub fn polynomial_identifier<H: Default + Digest<OutputSize = U32>>(
    polynomial: Vec<Point>,
) -> [u5; 4] {
    let hash = H::default();
    hash.add(&polynomial[..]).finalize().to_base32()[0..4]
        .try_into()
        .expect("4 bech32 chars must fit 4 character arry")
}

/// Create a bech32m secret share backup
///
/// Requires that the threshold be no greater than 32.
/// If using an integer (small) index, the backup will be 67 bech32 characters.
/// If using a scalar index, the backup will be 118 bech32 characters.
pub fn encode_backup<H: Default + Digest<OutputSize = U32>>(
    polynomial: &Vec<Point>,
    secret_share: &Scalar,
    share_index: &Scalar,
) -> String {
    let threshold = polynomial.len();
    let mut data = [u5::default(); 1 + 4 + 52 + 52];

    if threshold > 32 {
        panic!("Polynomial has too high of a threshold, {threshold} > 32");
    }
    let threshold_u5 = u5::try_from_u8((threshold - 1).to_le_bytes()[0])
        .expect("can not fail because threshold < 32");
    data[0] = threshold_u5;

    let polynomial_identifier_u5 = polynomial_identifier::<H>(polynomial.clone());
    for (i, byte) in polynomial_identifier_u5.into_iter().enumerate() {
        data[1 + i] = byte;
    }

    let secret_share_u5 = secret_share.to_bytes().to_vec().to_base32();
    for (i, byte) in secret_share_u5.into_iter().enumerate() {
        data[1 + 4 + i] = byte;
    }

    let is_small =
        share_index.to_bytes()[0..31].iter().all(|b| *b == 0) && share_index.to_bytes()[31] < 32;

    let n_unused_bytes = if is_small {
        let share_index_u5 =
            u5::try_from_u8(share_index.to_bytes()[31]).expect("must be less than 32");
        data[57] = share_index_u5;
        52 - 1
    } else {
        let share_index_u5 = share_index.to_bytes().to_base32();
        for (i, byte) in share_index_u5.iter().enumerate() {
            data[1 + 4 + 52 + i] = *byte;
        }
        0
    };

    bech32::encode("frost", &data[..(data.len() - n_unused_bytes)], Bech32m)
        .expect("hrp must be valid")
}

/// Decode a bech32m secret share backup
pub fn decode_backup(
    encoded: String,
) -> Result<(usize, [u5; 4], Scalar, Scalar), FrostBackupDecodeError> {
    let (hrp, data, variant) =
        bech32::decode(&encoded).map_err(FrostBackupDecodeError::Bech32DecodeError)?;

    if hrp != "frost" {
        return Err(FrostBackupDecodeError::InvalidHumanReadablePrefix);
    }

    if !matches!(variant, bech32::Variant::Bech32m) {
        return Err(FrostBackupDecodeError::WrongBech32Variant(variant));
    }

    let threshold = (data[0].to_u8() as usize) + 1;
    let identifier: [u5; 4] = data[1..(1 + 4)].try_into().expect("4 bytes has to fit");
    let secret_share: Scalar = Scalar::from_bytes(
        Vec::<u8>::from_base32(&data[(1 + 4)..(1 + 4 + 52)])
            .map_err(FrostBackupDecodeError::Bech32DecodeError)?
            .try_into()
            .expect("52 bech32 chars corresponds to 32 bytes"),
    )
    .ok_or(FrostBackupDecodeError::InvalidSecretShareScalar)?
    .non_zero()
    .ok_or(FrostBackupDecodeError::ShareIndexIsZero)?;

    let share_index = if data[(1 + 4 + 52)..].len() == 52 {
        Scalar::from_bytes(
            Vec::<u8>::from_base32(&data[(1 + 4 + 52)..])
                .map_err(FrostBackupDecodeError::Bech32DecodeError)?
                .try_into()
                .expect("remaining 52 bech32 chars corresponds to 32 bytes"),
        )
        .ok_or(FrostBackupDecodeError::InvalidShareIndexScalar)?
        .non_zero()
        .expect("secret share can not be zero")
    } else if data[(1 + 4 + 52)..].len() == 1 {
        Scalar::from_non_zero_u32(
            NonZeroU32::new(data[1 + 4 + 52].to_u8() as u32)
                .ok_or(FrostBackupDecodeError::ShareIndexIsZero)?,
        )
    } else {
        return Err(FrostBackupDecodeError::UnknownShareIndexLength);
    };

    Ok((threshold, identifier, secret_share, share_index))
}
