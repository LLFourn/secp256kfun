use secp256kfun::{marker::*, poly, Scalar};
/// A *[Shamir secret share]*.
///
/// Each share is an `(x,y)` pair where `y = p(x)` for some polynomial `p`. With a sufficient
/// number of unique pairs you can recontruct `p` as a vector of `Scalar`s where each `Scalar` is a
/// coefficient `p`. This structure is useful for hiding a secret `y*` by having `p(0) = y*` until a
/// sufficient number of shares come together to resconstruct `y*`.
///
/// Signing keys in FROST are also shamir secert shares which is why this is here.
///
/// ## Backup format (bech32 chars)
///
/// We decided to encode each share as a [`bech32m`] string in order to back them up. There are two
/// forms, one where the share index goes in the human readable part and one where that goes into
/// the payload.
///
/// We optionally have the index in the human readable part since users can more easily identify
/// shares that way. Share identification can help for keeping track of them and distinguishing them
/// there are only a small numbner of shares.
///
/// The backuip format is enabled with the `share_backup` feature and accessed with the `FromStr`
/// and `Display`.
///
/// ### Index in human readable part
///
/// human readable: `"frost[<index>]"`   // (8+)
/// separator:      `"1"`                // (1)
/// payload:        `[u5; 53]`,          // (53)
/// checksum:       `[u5; 6]`,           // (6)
///
/// The payload consists of:
///
/// - `secret_share` (`[u8;32]`): the 32 bytes that reperesents the secret share scalar in big-endian encoding
///
/// ### Index in payload
///
/// human readable: "frost"         // (5)
/// separator:      "1"             // (1)
/// payload:        [u5; 53..103],  // (53..103)
/// checksum:       [u5; 6],        // (6)
///
/// The payload consists of:
///
/// - `secret_share` (`[u8;32]`): the 32 bytes that reperesents the secret share scalar in big-endian encoding
/// - `share_index`: [u8;1..32] which is the index where the polynomial was evalulated to create the share. This is also a big-endian scalar except that the leading zero bytes are dropped so the smaller the index the smaller the encoding.
///
/// [Shamir secret share]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
/// [`bech32m`]: https://bips.xyz/350

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SecretShare {
    /// The scalar index for this secret share, usually this is a small number but it can take any
    /// value (other than 0).
    pub index: Scalar<Public>,
    /// The secret scalar which is the output of the polynomial evaluated at `index`
    pub secret: Scalar<Secret, Zero>,
}

impl SecretShare {
    /// From (at least) a threshold number of backups, restores the shared secret.
    pub fn recover_secret(shares: &[SecretShare]) -> Scalar<Secret, Zero> {
        let index_and_secret = shares
            .iter()
            .map(|share| (share.index, share.secret))
            .collect::<alloc::vec::Vec<_>>();

        poly::scalar::interpolate_and_eval_poly_at_0(&index_and_secret[..])
    }
}

#[cfg(feature = "share_backup")]
mod share_backup {
    use super::*;
    use bech32::{primitives::decode::CheckedHrpstring, Bech32m, ByteIterExt, Fe32IterExt, Hrp};
    use core::{fmt, str::FromStr};

    /// the threshold under which we encode the share index in the human readable section.
    const HUMAN_READABLE_THRESHOLD: u32 = 1000;

    impl fmt::Display for SecretShare {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut share_index_bytes = None;
            let hrp = if self.index < Scalar::<Public, _>::from(HUMAN_READABLE_THRESHOLD) {
                let bytes = self.index.to_bytes();
                let mut u32_index_bytes = [0u8; 4];
                u32_index_bytes.copy_from_slice(&bytes[28..]);
                let u32_index = u32::from_be_bytes(u32_index_bytes);
                Hrp::parse(&format!("frost[{}]", u32_index)).unwrap()
            } else {
                share_index_bytes = Some(
                    self.index
                        .to_bytes()
                        .into_iter()
                        .skip_while(|byte| *byte == 0x00),
                );
                Hrp::parse("frost").unwrap()
            };

            let chars = self
                .secret
                .to_bytes()
                .into_iter()
                .chain(share_index_bytes.into_iter().flatten())
                .bytes_to_fes()
                .with_checksum::<Bech32m>(&hrp)
                .chars();

            for c in chars {
                write!(f, "{}", c)?;
            }
            Ok(())
        }
    }

    impl FromStr for SecretShare {
        type Err = ShareDecodeError;
        fn from_str(encoded: &str) -> Result<Self, Self::Err> {
            let checked_hrpstring = &CheckedHrpstring::new::<Bech32m>(encoded)
                .map_err(ShareDecodeError::Bech32DecodeError)?;
            let hrp = checked_hrpstring.hrp();

            let tail = hrp
                .as_str()
                .strip_prefix("frost")
                .ok_or(ShareDecodeError::InvalidHumanReadablePrefix)?;

            let has_parenthetical = !tail.is_empty();
            dbg!(has_parenthetical);
            let hr_index = if has_parenthetical {
                let tail = tail
                    .strip_prefix('[')
                    .ok_or(ShareDecodeError::InvalidHumanReadablePrefix)?;
                let tail = tail
                    .strip_suffix(']')
                    .ok_or(ShareDecodeError::InvalidHumanReadablePrefix)?;
                let u32_scalar = u32::from_str(tail)
                    .map_err(|_| ShareDecodeError::InvalidHumanReadablePrefix)?;

                Some(Scalar::<Public, Zero>::from(u32_scalar))
            } else {
                None
            };

            let mut byte_iter = checked_hrpstring.byte_iter();
            let mut secret_share = [0u8; 32];
            for byte in &mut secret_share {
                *byte = byte_iter
                    .next()
                    .ok_or(ShareDecodeError::InvalidSecretShareScalar)?;
            }

            let secret_share = Scalar::from_bytes(secret_share)
                .ok_or(ShareDecodeError::InvalidSecretShareScalar)?;

            let share_index = match hr_index {
                Some(share_index) => share_index,
                None => {
                    let mut share_index = [0u8; 32];
                    let mut i = 0;
                    for byte in byte_iter {
                        if i >= 32 {
                            return Err(ShareDecodeError::InvalidShareIndexScalar);
                        }
                        share_index[i] = byte;
                        i += 1;
                    }

                    if i == 0 {
                        return Err(ShareDecodeError::InvalidShareIndexScalar)?;
                    }
                    share_index.rotate_right(32 - i);
                    Scalar::<Public, Zero>::from_bytes(share_index)
                        .ok_or(ShareDecodeError::InvalidShareIndexScalar)?
                }
            };

            let share_index = share_index
                .public()
                .non_zero()
                .ok_or(ShareDecodeError::InvalidShareIndexScalar)?;

            Ok(SecretShare {
                secret: secret_share,
                index: share_index,
            })
        }
    }

    /// An error encountered when encoding a Frostsnap backup.
    #[derive(Debug, Clone, PartialEq)]
    pub enum ShareDecodeError {
        /// Decode error from bech32 library
        Bech32DecodeError(bech32::primitives::decode::CheckedHrpstringError),
        /// Decoded secret share is not a valid secp256k1 scalar
        InvalidSecretShareScalar,
        /// Decoded share index is not a valid secp256k1 scalar
        InvalidShareIndexScalar,
        /// Tried to decode backup with unknown prefix
        InvalidHumanReadablePrefix,
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ShareDecodeError {}

    impl fmt::Display for ShareDecodeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self {
                ShareDecodeError::Bech32DecodeError(e) => {
                    write!(f, "Failed to decode bech32m string: {e}")
                }
                ShareDecodeError::InvalidSecretShareScalar => {
                    write!(
                        f,
                        "Invalid secret share scalar value, not on secp256k1 curve."
                    )
                }
                ShareDecodeError::InvalidHumanReadablePrefix => {
                    write!(f, "Expected human readable prefix `frost`",)
                }
                ShareDecodeError::InvalidShareIndexScalar => {
                    write!(f, "Share index scalar was not a valid secp256k1 scalar.",)
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::frost::SecretShare;
        use alloc::string::ToString;
        use core::str::FromStr;
        use secp256kfun::{proptest::prelude::*, Scalar};

        proptest! {
            #[test]
            fn share_backup_roundtrip(index in any::<Scalar<Public, NonZero>>(), secret in any::<Scalar<Secret, Zero>>()) {
                let orig = SecretShare { secret, index };
                let orig_encoded = orig.to_string();
                let decoded = SecretShare::from_str(&orig_encoded).unwrap();
                assert_eq!(orig, decoded)
            }


            #[test]
            fn short_backup_length(secret in any::<Scalar<Secret, Zero>>(), share_index_u32 in 1u32..200) {
                let index = Scalar::<Public, Zero>::from(share_index_u32).non_zero().unwrap().public();
                let secret_share = SecretShare {
                    index,
                    secret,
                };
                let backup = secret_share
                .to_string();

                if share_index_u32 >= HUMAN_READABLE_THRESHOLD {
                    assert!(backup.starts_with("frost1"));
                } else {
                    assert!(backup.starts_with(&format!("frost[{}]", share_index_u32)));
                }

                assert_eq!(SecretShare::from_str(&backup), Ok(secret_share))
            }
        }
    }
}

#[cfg(feature = "share_backup")]
pub use share_backup::ShareDecodeError;

#[cfg(test)]
mod test {
    use super::*;
    use crate::frost;
    use alloc::vec::Vec;
    use secp256kfun::{
        g,
        proptest::{
            prelude::*,
            test_runner::{RngAlgorithm, TestRng},
        },
        G,
    };
    proptest! {
        #[test]
        fn recover_secret(parties in 1usize..10, threshold in 1usize..5) {
            use rand::seq::SliceRandom;
            let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
            let parties = parties.max(threshold);

            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
            let (frost_key, shares) = frost.simulate_keygen(threshold, parties, &mut rng);
            let chosen = shares.choose_multiple(&mut rng, threshold).cloned().collect::<Vec<_>>();
            let secret = SecretShare::recover_secret(&chosen);
            prop_assert_eq!(g!(secret * G), frost_key.public_key());
        }
    }
}
