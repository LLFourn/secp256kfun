//! Backup scheme for FROST secret shares
//!
//! # Description
//!
//! Based on https://bips.xyz/93
//!
//! ## Backup format (bech32 chars)
//!
//! human readable: "fr"            // (2)
//! separator:      "1"             // (1)
//! threshold:      u5,             // (1)
//! identifier:     [u5; 4],        // (4)
//! secret_share:   [u5; 52],       // (52)
//! share_index:    u5 or [u5; 52], // (1 or 52)
//! checksum:       [u5; 6],        // (6)
//!
//! ## Justification
//!
//! ### Threshold - (1 bech32 character)
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
//! 32^4 = 2^20 ~> a collision rate of about one in a million.
//!
//! ### Secret Share - (52)
//! A FROST secret share is fixed length scalar of 32 bytes.
//! This is 32 * 8 / 5 = 51.2 -> 52 bech32 characters
//!
//! ### Share Index - (1 or 52)
//! The share index can be be scalar, but will often be small for simplicity and smaller backups.
//! By leaving this data piece at the end, we can use the length of the remaining data to
//! easily decode a single bech32 char into integer, or 32 chars into a scalar.
use alloc::{string::String, vec::Vec};
use bech32::{self, u5, FromBase32, ToBase32, Variant::Bech32m};
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    marker::Secret,
    Point, Scalar,
};

/// Secret shares can have a small index up to 32, or index at a specific scalar.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BackupShareIndex {
    /// a secret share at a small index up to 32
    SmallIndex(usize),
    /// a secret share at a specific scalar index
    Scalar(Scalar),
}

/// An error encountered when encoding a Frostsnap backup.
#[derive(Debug, Copy, Clone)]
pub enum FrostBackupError {
    /// Generic error from bech32 library
    Bech32Error(bech32::Error),
    /// Threshold was zero
    ThresholdCantBeZero,
    /// Threshold was greater than 32.
    ThresholdTooBig,
    /// Tried to decode a bech32 variant that was not bech32m
    WrongBech32Variant(bech32::Variant),
    /// Decoded secret share is not a valid secp256k1 scalar
    InvalidSecretShareScalar,
    /// Tried to decode backup with unknown prefix
    InvalidHumanReadablePrefix,
    /// The share index data length doesn't match expected for SmallIndex nor Scalar
    UnknownShareIndexType,
    /// Decoded share index is not a valid secp256k1 scalar
    InvalidShareIndexScalar,
}

/// Create an identifier that's used to determine compatibility of FROST secret shares.
/// The first 4 bech32 chars from a hash of the polynomial coefficients.
/// Collision expected once in (32)^4 = 2^20.
pub fn polynomial_identifier<H: Default + Digest<OutputSize = U32>>(
    polynomial: Vec<Point>,
) -> [u5; 4] {
    let mut hash = H::default();
    for coefficient in polynomial.into_iter() {
        hash.update(coefficient.to_bytes());
    }
    hash.finalize().to_vec().to_base32()[0..4]
        .try_into()
        .expect("4 bech32 chars must fit 4 character arry")
}

/// Create a bech32m FROST backup
///
/// Requires that the threshold be no greater than 32.
/// If using an integer (small) index, the backup will be 67 bech32 characters.
/// If using a scalar index, the backup will be 118 bech32 characters.
pub fn encode_backup<H: Default + Digest<OutputSize = U32>>(
    threshold: usize,
    polynomial: Vec<Point>,
    secret_share: Scalar<Secret>,
    share_index: BackupShareIndex,
) -> Result<String, FrostBackupError> {
    let mut data = [u5::default(); 1 + 4 + 52 + 52];

    if threshold > 32 {
        return Err(FrostBackupError::ThresholdTooBig);
    } else if threshold == 0 {
        return Err(FrostBackupError::ThresholdCantBeZero);
    }
    let threshold_u5 =
        u5::try_from_u8((threshold - 1).to_le_bytes()[0]).map_err(FrostBackupError::Bech32Error)?;
    data[0] = threshold_u5;

    let polynomial_identifier_u5 = polynomial_identifier::<H>(polynomial);
    for (i, byte) in polynomial_identifier_u5.into_iter().enumerate() {
        data[1 + i] = byte;
    }

    let secret_share_u5 = secret_share.to_bytes().to_vec().to_base32();
    for (i, byte) in secret_share_u5.into_iter().enumerate() {
        data[1 + 4 + i] = byte;
    }

    let n_unused_bytes = match share_index {
        BackupShareIndex::Scalar(share_index) => {
            let share_index_u5 = share_index.to_bytes().to_base32();
            for (i, byte) in share_index_u5.iter().enumerate() {
                data[1 + 4 + 52 + i] = *byte;
            }
            0
        }
        BackupShareIndex::SmallIndex(share_index) => {
            let share_index_u5 = u5::try_from_u8(share_index.to_le_bytes()[0])
                .map_err(|_| FrostBackupError::ThresholdTooBig)?;
            data[57] = share_index_u5;
            52 - 1
        }
    };

    let shortened_data: Vec<_> = data.into_iter().take(data.len() - n_unused_bytes).collect();

    match bech32::encode("fr", shortened_data, Bech32m) {
        Ok(encoded) => Ok(encoded),
        Err(e) => Err(FrostBackupError::Bech32Error(e)),
    }
}

/// Decode a bech32m FROST backup
pub fn decode_backup(
    encoded: String,
) -> Result<(usize, [u5; 4], Scalar, BackupShareIndex), FrostBackupError> {
    let (hrp, data, variant) = bech32::decode(&encoded).map_err(FrostBackupError::Bech32Error)?;

    if hrp != "fr" {
        return Err(FrostBackupError::InvalidHumanReadablePrefix);
    }

    if !matches!(variant, bech32::Variant::Bech32m) {
        return Err(FrostBackupError::WrongBech32Variant(variant));
    }

    let threshold = (data[0].to_u8() as usize) + 1;
    let identifier: [u5; 4] = data[1..(1 + 4)].try_into().expect("4 bytes has to fit");
    let secret_share: Scalar = Scalar::from_bytes(
        Vec::<u8>::from_base32(&data[(1 + 4)..(1 + 4 + 52)])
            .map_err(FrostBackupError::Bech32Error)?
            .try_into()
            .expect("52 bech32 chars corresponds to 32 bytes"),
    )
    .ok_or(FrostBackupError::InvalidSecretShareScalar)?
    .non_zero()
    .expect("secret share can not be zero");

    let share_index = if data[(1 + 4 + 52)..].len() == 52 {
        BackupShareIndex::Scalar(
            Scalar::from_bytes(
                Vec::<u8>::from_base32(&data[(1 + 4 + 52)..])
                    .map_err(FrostBackupError::Bech32Error)?
                    .try_into()
                    .expect("remaining 52 bech32 chars corresponds to 32 bytes"),
            )
            .ok_or(FrostBackupError::InvalidShareIndexScalar)?
            .non_zero()
            .expect("secret share can not be zero"),
        )
    } else if data[(1 + 4 + 52)..].len() == 1 {
        BackupShareIndex::SmallIndex(data[1 + 4 + 52].to_u8() as usize)
    } else {
        return Err(FrostBackupError::UnknownShareIndexType);
    };

    Ok((threshold, identifier, secret_share, share_index))
}
