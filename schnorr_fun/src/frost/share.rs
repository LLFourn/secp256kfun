use secp256kfun::{poly, prelude::*};
/// A *[Shamir secret share]*.
///
/// Each share is an `(x,y)` pair where `y = p(x)` for some polynomial `p`. With a sufficient
/// number of unique pairs you can reconstruct `p` as a vector of `Scalar`s where each `Scalar` is a
/// coefficient `p`. This structure is useful for hiding a secret `y*` by having `p(0) = y*` until a
/// sufficient number of shares come together to reconstruct `y*`.
///
/// Signing keys in FROST are also shamir secret shares which is why this is here.
///
/// ## Backup format (bech32 chars)
///
/// *ℹ enabled with `share_backup` feature*
///
/// We decided to encode each share as a [`bech32m`] string in order to back them up. There are two
/// forms, one where the share index goes in the human readable part and one where that goes into
/// the payload.
///
/// We optionally have the index in the human readable part since users can more easily identify
/// shares that way. Share identification can help for keeping track of them and distinguishing shares
/// when there are only a small number of them.
///
/// The backup format is enabled with the `share_backup` feature and accessed with the feature enabled methods.
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
/// - `secret_share` (`[u8;32]`): the 32 bytes that represents the secret share scalar in big-endian encoding
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
/// - `share_index`: [u8;1..32] which is the index where the polynomial was evaluated to create the share. This is also a big-endian scalar except that the leading zero bytes are dropped so the smaller the index the smaller the encoding.
///
/// [Shamir secret share]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
/// [`bech32m`]: https://bips.xyz/350

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct SecretShare {
    /// The scalar index for this secret share, usually this is a small number but it can take any
    /// value (other than 0).
    pub index: PartyIndex,
    /// The secret scalar which is the output of the polynomial evaluated at `index`
    pub share: Scalar<Secret, Zero>,
}

impl SecretShare {
    /// From (at least) a threshold number of backups, restores the shared secret.
    pub fn recover_secret(shares: &[SecretShare]) -> Scalar<Secret, Zero> {
        let index_and_secret = shares
            .iter()
            .map(|share| (share.index, share.share))
            .collect::<alloc::vec::Vec<_>>();

        poly::scalar::interpolate_and_eval_poly_at_0(&index_and_secret[..])
    }

    /// Encodes the secret share to 64 bytes. The first 32 is the index and the second 32 is the
    /// secret.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.index.to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.share.to_bytes().as_ref());
        bytes
    }

    /// Encodes the secret share from 64 bytes. The first 32 is the index and the second 32 is the
    /// secret.
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        Some(Self {
            index: Scalar::from_slice(&bytes[..32])?,
            share: Scalar::from_slice(&bytes[32..])?,
        })
    }

    /// Get the image of the secret share.
    pub fn share_image(&self) -> Point<NonNormal, Public, Zero> {
        g!(self.share * G)
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secp256k1 FROST share",
    fn from_bytes(bytes: [u8;64]) -> Option<SecretShare> {
        SecretShare::from_bytes(bytes)
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(share: &SecretShare) -> [u8;64] {
        share.to_bytes()
    }
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(
    feature = "bincode",
    derive(crate::fun::bincode::Encode, crate::fun::bincode::Decode),
    bincode(
        crate = "crate::fun::bincode",
        encode_bounds = "Point<T, Public, Z>: crate::fun::bincode::Encode",
        decode_bounds = "Point<T, Public, Z>: crate::fun::bincode::Decode",
        borrow_decode_bounds = "Point<T, Public, Z>: crate::fun::bincode::BorrowDecode<'__de>"
    )
)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(
        crate = "crate::fun::serde",
        bound(
            deserialize = "Point<T, Public, Z>: crate::fun::serde::de::Deserialize<'de>",
            serialize = "Point<T, Public, Z>: crate::fun::serde::Serialize"
        )
    )
)]
/// A secret share paired with the image of the secret for which it is a share of.
///
/// This is useful so you can keep track of tweaks to the secret value and tweaks to the shared key
/// in tandem.
pub struct PairedSecretShare<T = Normal, Z = NonZero> {
    secret_share: SecretShare,
    public_key: Point<T, Public, Z>,
}

impl<T: PointType, Z> PartialEq for PairedSecretShare<T, Z> {
    fn eq(&self, other: &Self) -> bool {
        self.secret_share == other.secret_share && self.public_key == other.public_key
    }
}

impl<T: Normalized, Z: ZeroChoice> PairedSecretShare<T, Z> {
    /// The index of the secret share
    pub fn index(&self) -> PartyIndex {
        self.secret_share.index
    }

    /// The secret bit of the share
    pub fn share(&self) -> Scalar<Secret, Zero> {
        self.secret_share.share
    }

    /// The public key that this secert share is a part of
    pub fn public_key(&self) -> Point<T, Public, Z> {
        self.public_key
    }

    /// The inner un-paired secret share.
    ///
    /// This exists since when you do a physical paper backup of a secret share you usually don't
    /// record explicitly the entire shared key (maybe just a short identifier).
    pub fn secret_share(&self) -> &SecretShare {
        &self.secret_share
    }
}

impl<Z: ZeroChoice, T: PointType> PairedSecretShare<T, Z> {
    /// Pair a secret share to a shared key without checking its valid.
    ///
    /// You're  meant to use [`pair_secret_share`] to create this which guarantees the pairing is
    /// correct with respect to the `SharedKey`.
    ///
    /// [`pair_secret_share`]: crate::frost::SharedKey::pair_secret_share
    pub fn new_unchecked(secret_share: SecretShare, public_key: Point<T, Public, Z>) -> Self {
        Self {
            secret_share,
            public_key,
        }
    }

    /// Adds a scalar `tweak` to the paired secret share.
    ///
    /// The returned `PairedSecretShare<Normal, Zero>` represents a sharing of the original value + `tweak`.
    ///
    /// This is useful for deriving unhardened child frost keys from a master frost public key using
    /// [BIP32]. In cases like this since you know that the tweak was computed from a hash of the
    /// original key you call [`non_zero`] and unwrap the `Option` since zero is computationally
    /// unreachable.
    ///
    /// If you want to apply an "x-only" tweak you need to call this then [`non_zero`] and finally [`into_xonly`].
    ///
    /// See also: [`SharedKey::homomorphic_add`]
    ///
    /// [BIP32]: https://bips.xyz/32
    /// [`non_zero`]: Self::non_zero
    /// [`into_xonly`]: Self::into_xonly
    /// [`SharedKey::homomorphic_add`]: crate::frost::SharedKey::homomorphic_add
    #[must_use]
    pub fn homomorphic_add(
        self,
        tweak: Scalar<impl Secrecy, impl ZeroChoice>,
    ) -> PairedSecretShare<Normal, Zero> {
        let PairedSecretShare {
            mut secret_share,
            public_key: shared_key,
        } = self;
        let shared_key = g!(shared_key + tweak * G).normalize();
        secret_share.share = s!(secret_share.share + tweak);
        PairedSecretShare {
            public_key: shared_key,
            secret_share,
        }
    }

    /// Multiply the secret share by `scalar`.
    #[must_use]
    pub fn homomorphic_mul(self, tweak: Scalar<impl Secrecy>) -> PairedSecretShare<Normal, Z> {
        let PairedSecretShare {
            public_key: shared_key,
            mut secret_share,
        } = self;

        let shared_key = g!(tweak * shared_key).normalize();
        secret_share.share = s!(tweak * self.secret_share.share);
        PairedSecretShare {
            secret_share,
            public_key: shared_key,
        }
    }

    /// Converts a `PairedSecretShare<T, Zero>` to a `PairedSecretShare<T, NonZero>`.
    ///
    /// If the paired shared key *was* actually zero ([`is_zero`] returns true) it returns `None`.
    ///
    /// [`is_zero`]: Point::is_zero
    #[must_use]
    pub fn non_zero(self) -> Option<PairedSecretShare<T, NonZero>> {
        Some(PairedSecretShare {
            secret_share: self.secret_share,
            public_key: self.public_key.non_zero()?,
        })
    }

    /// Is the key this is a share of zero
    pub fn is_zero(&self) -> bool {
        self.public_key.is_zero()
    }
}

impl PairedSecretShare<Normal> {
    /// Create an XOnly secert share where the paired image is always an `EvenY` point.
    #[must_use]
    pub fn into_xonly(mut self) -> PairedSecretShare<EvenY> {
        let (shared_key, needs_negation) = self.public_key.into_point_with_even_y();
        self.secret_share.share.conditional_negate(needs_negation);

        PairedSecretShare {
            secret_share: self.secret_share,
            public_key: shared_key,
        }
    }
}

impl PairedSecretShare<EvenY> {
    /// Get the verification for the inner secret share.
    pub fn verification_share(&self) -> VerificationShare<NonNormal> {
        VerificationShare {
            index: self.index(),
            share_image: self.secret_share.share_image(),
            public_key: self.public_key,
        }
    }
}

/// This is the public image of a [`SecretShare`]. You can't sign with it but you can verify
/// signature shares created by the secret share.
///
/// A `VerificationShare` is the same as a [`share_image`] except it's generated against an `EvenY`
/// key that can actually have signatures verified against it.
///
/// A `VerificationShare` is not designed to be persisted. The verification share will only be able
/// to verify signatures against the key that it was generated from. Tweaking a key with
/// `homomorphic_add` etc will invalidate the verification share.
///
/// [`share_image`]: SecretShare::share_image
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct VerificationShare<T: PointType> {
    /// The index of the share in the secret sharing
    pub index: PartyIndex,
    /// The image of the secret share
    pub share_image: Point<T, Public, Zero>,
    /// The public key that this is a share of
    pub public_key: Point<EvenY>,
}

#[cfg(feature = "share_backup")]
mod share_backup {
    use super::*;
    use bech32::{primitives::decode::CheckedHrpstring, Bech32m, ByteIterExt, Fe32IterExt, Hrp};
    use core::{fmt, str::FromStr};

    /// the threshold under which we encode the share index in the human readable section.
    const HUMAN_READABLE_THRESHOLD: u32 = 1000;

    impl SecretShare {
        /// Generate a bech32 backup string. See [`SecretShare`] for documentation on the format.
        #[cfg_attr(docsrs, doc(cfg(feature = "share_backup")))]
        pub fn to_bech32_backup(&self) -> alloc::string::String {
            let mut string = alloc::string::String::new();
            self.write_bech32_backup(&mut string).expect("infallible");
            string
        }

        /// Write the bech32 backup. See [`SecretShare`] for documentation on the format.
        #[cfg_attr(docsrs, doc(cfg(feature = "share_backup")))]
        pub fn write_bech32_backup(&self, f: &mut impl fmt::Write) -> fmt::Result {
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
                .share
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

        /// Load a `SecretShare` from a backup string. See [`SecretShare`] for documentation on the
        /// format.
        #[cfg_attr(docsrs, doc(cfg(feature = "share_backup")))]
        pub fn from_bech32_backup(backup: &str) -> Result<Self, BackupDecodeError> {
            let checked_hrpstring = &CheckedHrpstring::new::<Bech32m>(backup)
                .map_err(BackupDecodeError::Bech32DecodeError)?;
            let hrp = checked_hrpstring.hrp();

            let tail = hrp
                .as_str()
                .strip_prefix("frost")
                .ok_or(BackupDecodeError::InvalidHumanReadablePrefix)?;

            let has_parenthetical = !tail.is_empty();
            let hr_index = if has_parenthetical {
                let tail = tail
                    .strip_prefix('[')
                    .ok_or(BackupDecodeError::InvalidHumanReadablePrefix)?;
                let tail = tail
                    .strip_suffix(']')
                    .ok_or(BackupDecodeError::InvalidHumanReadablePrefix)?;
                let u32_scalar = u32::from_str(tail)
                    .map_err(|_| BackupDecodeError::InvalidHumanReadablePrefix)?;

                Some(Scalar::<Public, Zero>::from(u32_scalar))
            } else {
                None
            };

            let mut byte_iter = checked_hrpstring.byte_iter();
            let mut secret_share = [0u8; 32];
            for byte in &mut secret_share {
                *byte = byte_iter
                    .next()
                    .ok_or(BackupDecodeError::InvalidSecretShareScalar)?;
            }

            let secret_share = Scalar::from_bytes(secret_share)
                .ok_or(BackupDecodeError::InvalidSecretShareScalar)?;

            let share_index = match hr_index {
                Some(share_index) => share_index,
                None => {
                    let mut share_index = [0u8; 32];
                    let mut i = 0;
                    for byte in byte_iter {
                        if i >= 32 {
                            return Err(BackupDecodeError::InvalidShareIndexScalar);
                        }
                        share_index[i] = byte;
                        i += 1;
                    }

                    if i == 0 {
                        return Err(BackupDecodeError::InvalidShareIndexScalar)?;
                    }
                    share_index.rotate_right(32 - i);
                    Scalar::<Public, Zero>::from_bytes(share_index)
                        .ok_or(BackupDecodeError::InvalidShareIndexScalar)?
                }
            };

            let share_index = share_index
                .public()
                .non_zero()
                .ok_or(BackupDecodeError::InvalidShareIndexScalar)?;

            Ok(SecretShare {
                share: secret_share,
                index: share_index,
            })
        }
    }

    /// An error encountered when decoding a Frostsnap backup.
    #[derive(Debug, Clone, PartialEq)]
    #[cfg_attr(docsrs, doc(cfg(feature = "share_backup")))]
    pub enum BackupDecodeError {
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
    impl std::error::Error for BackupDecodeError {}

    impl fmt::Display for BackupDecodeError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self {
                BackupDecodeError::Bech32DecodeError(e) => {
                    write!(f, "Failed to decode bech32m string: {e}")
                }
                BackupDecodeError::InvalidSecretShareScalar => {
                    write!(
                        f,
                        "Invalid secret share scalar value, not on secp256k1 curve."
                    )
                }
                BackupDecodeError::InvalidHumanReadablePrefix => {
                    write!(f, "Expected human readable prefix `frost`",)
                }
                BackupDecodeError::InvalidShareIndexScalar => {
                    write!(f, "Share index scalar was not a valid secp256k1 scalar.",)
                }
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::frost::SecretShare;
        use secp256kfun::{proptest::prelude::*, Scalar};

        proptest! {
            #[test]
            fn share_backup_roundtrip(index in any::<Scalar<Public, NonZero>>(), share in any::<Scalar<Secret, Zero>>()) {
                let orig = SecretShare { share, index };
                let orig_encoded = orig.to_bech32_backup();
                let decoded = SecretShare::from_bech32_backup(&orig_encoded).unwrap();
                assert_eq!(orig, decoded)
            }


            #[test]
            fn short_backup_length(share in any::<Scalar<Secret, Zero>>(), share_index_u32 in 1u32..200) {
                let index = Scalar::<Public, Zero>::from(share_index_u32).non_zero().unwrap().public();
                let secret_share = SecretShare {
                    index,
                    share,
                };
                let backup = secret_share.to_bech32_backup();

                if share_index_u32 >= HUMAN_READABLE_THRESHOLD {
                    prop_assert!(backup.starts_with("frost1"));
                } else {
                    assert!(backup.starts_with(&format!("frost[{}]", share_index_u32)));
                }

                prop_assert_eq!(SecretShare::from_bech32_backup(&backup), Ok(secret_share))
            }
        }
    }
}

#[cfg(feature = "share_backup")]
pub use share_backup::BackupDecodeError;

use super::PartyIndex;

#[cfg(test)]
mod test {
    use super::*;
    use crate::frost::{self, chilldkg::simplepedpop};
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
        fn recover_secret(
            (parties, threshold) in (1u32..=10).prop_flat_map(|n| (Just(n), 1u32..=n)),
        ) {
            use rand::seq::SliceRandom;
            let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();

            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
            let (frost_poly, shares) = simplepedpop::simulate_keygen(&frost.schnorr, threshold, parties , parties , &mut rng);
            let chosen = shares.choose_multiple(&mut rng, threshold as usize).cloned()
                .map(|paired_share| paired_share.secret_share).collect::<Vec<_>>();
            let secret = SecretShare::recover_secret(&chosen);
            prop_assert_eq!(g!(secret * G), frost_poly.public_key());
        }
    }
}
