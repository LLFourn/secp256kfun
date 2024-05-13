//! Backup scheme for Shamir Secret Shares
//!
//! # Description
//!
//! Based on <https://bips.xyz/93>
//!
//! ## Backup format (bech32 chars)
//!
//! human readable: "frost"         // (5)
//! separator:      "1"             // (1)
//! secret_share:   [u5; 52],       // (52)
//! share_index:    u5 or [u5; 52], // (1 or 52)
//! checksum:       [u5; 6],        // (6)
//!
//! The total length of the backup is 65 characters if using 'small' share indicies (1, 2, ..., 32),
//! or 116 bech32m characters if using general scalars for participant indicies.
//!
//! ## Rationale
//!
//! ### Human Readable - (5 bech32 characters)
//!
//! `frost` looks cool.
//! Most of the time we will be using this backup scheme for FROST related shamir secret shares.
//!
//! ### Secret Share - (52)
//!
//! A secret share scalar is fixed length scalar of 32 bytes.
//! This is 32 * 8 / 5 = 51.2 -> 52 bech32 characters
//!
//! ### Share Index - (1 or 52)
//!
//! Can be any scalar, but will often be a small integer for simplicity and smaller backups.
//! By leaving this data piece at the end, we can use the length of the remaining data to
//! easily decode either a single bech32 char into integer, or 52 chars into a 32 byte scalar.

use alloc::{fmt, string::String, vec::Vec};
use bech32::{u5, FromBase32, ToBase32, Variant::Bech32m};
use core::str::FromStr;
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    hash::HashAdd,
    marker::*,
    poly, Point, Scalar, G,
};

/// Create an identifier that's used to determine compatibility of shamir secret shares.
/// The first 4 bech32 chars from a hash of the polynomial coefficients.
/// Collision expected once in (32)^4 = 2^20.
pub fn polynomial_identifier<H: Default + Digest<OutputSize = U32>>(
    polynomial: &[Point<Normal, Public, impl ZeroChoice>],
) -> [u5; 4] {
    let hash = H::default();
    hash.add(polynomial).finalize().to_base32()[0..4]
        .try_into()
        .expect("4 bech32 chars must fit 4 character arry")
}

/// A Shamir Share Backup
///
/// Can be encoded and displayed as bech32m characters.
///
/// If using 'small' share indices (1, 2, ..., 32) the encoded backup will be 71 bech32 characters.
/// If using general scalar participant indicies, the encoded backup will be 122 bech32 characters.
///
/// Encoding requires that the threshold is no greater than 1024.
#[derive(Debug, Copy, Clone)]
pub struct ShareBackup {
    /// The Shamir Secret Share that is being backed up.
    pub secret_share: Scalar<Secret, Zero>,
    /// The scalar index for this secret share, generally a simple participant index (1, 2, ..., 32).
    pub share_index: Scalar<Public>,
}

impl ShareBackup {
    /// Create a new share backup.
    ///
    /// ## Panics
    ///
    /// The threshold must be greater than 0 and less than 1024.
    /// The secret share is checked to confirm that its image lies on the public point polynomial.
    pub fn new<H: Default + Digest<OutputSize = U32>>(
        polynomial: &[Point<Normal, Public, impl ZeroChoice>],
        secret_share: Scalar<Secret, Zero>,
        share_index: Scalar<Public>,
    ) -> Self {
        let threshold = polynomial.len() as u16;
        assert_ne!(threshold, 0, "Polynomial threshold can not be zero");
        assert!(threshold <= 32, "PPolynomial has too high of a threshold");

        assert_eq!(
            poly::point::eval(polynomial, share_index),
            g!(secret_share * G),
            "Secret share is not valid with respect to the polynomial!"
        );

        Self {
            secret_share,
            share_index,
        }
    }
}

impl fmt::Display for ShareBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut data = [u5::default(); 52 + 52];

        let secret_share_u5 = self.secret_share.to_bytes().to_vec().to_base32();
        for (i, byte) in secret_share_u5.into_iter().enumerate() {
            data[i] = byte;
        }

        let is_small = self.share_index.to_bytes()[0..31].iter().all(|b| *b == 0)
            && self.share_index.to_bytes()[31] < 32;

        let n_unused_bytes = if is_small {
            let share_index_u5 =
                u5::try_from_u8(self.share_index.to_bytes()[31]).expect("must be less than 32");
            data[52] = share_index_u5;
            52 - 1
        } else {
            let share_index_u5 = self.share_index.to_bytes().to_base32();
            for (i, byte) in share_index_u5.iter().enumerate() {
                data[52 + i] = *byte;
            }
            0
        };

        bech32::encode_to_fmt(f, "frost", &data[..(data.len() - n_unused_bytes)], Bech32m)
            .expect("hrp is valid and is standard")
    }
}

impl FromStr for ShareBackup {
    type Err = FrostBackupDecodeError;
    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let (hrp, data, variant) =
            bech32::decode(encoded).map_err(FrostBackupDecodeError::Bech32DecodeError)?;

        if hrp != "frost" {
            return Err(FrostBackupDecodeError::InvalidHumanReadablePrefix);
        }

        if !matches!(variant, bech32::Variant::Bech32m) {
            return Err(FrostBackupDecodeError::WrongBech32Variant(variant));
        }

        let secret_share = Scalar::from_bytes(
            Vec::<u8>::from_base32(&data[..52])
                .map_err(FrostBackupDecodeError::Bech32DecodeError)?
                .try_into()
                .expect("52 bech32 chars corresponds to 32 bytes"),
        )
        .ok_or(FrostBackupDecodeError::InvalidSecretShareScalar)?;

        let share_index = if data[52..].len() == 52 {
            Scalar::from_bytes(
                Vec::<u8>::from_base32(&data[52..])
                    .map_err(FrostBackupDecodeError::Bech32DecodeError)?
                    .try_into()
                    .expect("remaining 52 bech32 chars corresponds to 32 bytes"),
            )
            .ok_or(FrostBackupDecodeError::InvalidShareIndexScalar)?
            .non_zero()
            .ok_or(FrostBackupDecodeError::ShareIndexIsZero)?
        } else if data[52..].len() == 1 {
            Scalar::from_non_zero_u32(
                core::num::NonZeroU32::new(data[52].to_u8() as u32)
                    .ok_or(FrostBackupDecodeError::ShareIndexIsZero)?,
            )
            .public()
        } else {
            return Err(FrostBackupDecodeError::UnknownShareIndexLength);
        };

        Ok(ShareBackup {
            secret_share,
            share_index,
        })
    }
}

/// Decode a bech32m secret share backup
pub fn decode_backup(encoded: String) -> Result<ShareBackup, FrostBackupDecodeError> {
    ShareBackup::from_str(&encoded)
}

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

#[cfg(feature = "std")]
impl std::error::Error for FrostBackupDecodeError {}

impl fmt::Display for FrostBackupDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            FrostBackupDecodeError::Bech32DecodeError(e) => {
                write!(f, "Failed to decode bech32m string: {e}")
            }
            FrostBackupDecodeError::WrongBech32Variant(e) => {
                write!(f, "Expected bech32m but decoded {e:?}")
            }
            FrostBackupDecodeError::InvalidSecretShareScalar => {
                write!(
                    f,
                    "Invalid secret share scalar value, not on secp256k1 curve."
                )
            }
            FrostBackupDecodeError::InvalidHumanReadablePrefix => {
                write!(f, "Expected human readable prefix `frost`",)
            }
            FrostBackupDecodeError::UnknownShareIndexLength => {
                write!(f, "Expected share index of 1 character or 52 characters.",)
            }
            FrostBackupDecodeError::InvalidShareIndexScalar => {
                write!(f, "Share index scalar was not a valid secp256k1 scalar.",)
            }
            FrostBackupDecodeError::ShareIndexIsZero => {
                write!(
                    f,
                    "Can not have a share index of zero since this immediately implies the secret.",
                )
            }
        }
    }
}
