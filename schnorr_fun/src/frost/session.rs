use crate::{binonce, frost::PartyIndex, Signature};
use alloc::collections::{BTreeMap, BTreeSet};
use secp256kfun::{poly, prelude::*};

use super::{NonceKeyPair, PairedSecretShare, SharedKey, VerificationShare};
/// A FROST signing session used to *verify* signatures.
///
/// Created using [`coordinator_sign_session`].
///
/// [`coordinator_sign_session`]: super::Frost::coordinator_sign_session
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "bincode",
    derive(crate::fun::bincode::Encode, crate::fun::bincode::Decode),
    bincode(crate = "crate::fun::bincode")
)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct CoordinatorSignSession {
    pub(crate) public_key: Point<EvenY>,
    pub(crate) binding_coeff: Scalar<Public>,
    pub(crate) final_nonce: Point<EvenY>,
    pub(crate) challenge: Scalar<Public, Zero>,

    pub(crate) agg_binonce: binonce::Nonce<Zero>,
    pub(crate) nonces: BTreeMap<PartyIndex, binonce::Nonce>,
}

impl CoordinatorSignSession {
    /// Fetch the participant indices for this signing session.
    ///
    /// ## Return value
    ///
    /// An iterator of participant indices
    pub fn parties(&self) -> BTreeSet<PartyIndex> {
        self.nonces.keys().cloned().collect()
    }

    /// The aggregated nonce used to sign
    pub fn agg_binonce(&self) -> binonce::Nonce<Zero> {
        self.agg_binonce
    }

    /// The final nonce that will actually appear in the signature
    pub fn final_nonce(&self) -> Point<EvenY> {
        self.final_nonce
    }

    /// The public key this session was started under
    pub fn public_key(&self) -> Point<EvenY> {
        self.public_key
    }

    /// Verify a partial signature for a participant for a particular session.
    ///
    /// The `verification_share` is usually derived from either [`SharedKey::verification_share`] or
    /// [`PairedSecretShare::verification_share`].
    ///
    /// ## Return Value
    ///
    /// Returns `true` if signature share is valid.
    pub fn verify_signature_share(
        &self,
        verification_share: VerificationShare<impl PointType>,
        signature_share: Scalar<Public, Zero>,
    ) -> Result<(), SignatureShareInvalid> {
        let X = verification_share.share_image;
        let index = verification_share.index;

        // We need to know the verification share was generated against the session's key for
        // further validity to have any meaning.
        if verification_share.public_key != self.public_key() {
            return Err(SignatureShareInvalid { index });
        }

        let s = signature_share;
        let lambda =
            poly::eval_basis_poly_at_0(verification_share.index, self.nonces.keys().cloned());
        let c = &self.challenge;
        let b = &self.binding_coeff;
        debug_assert!(
            self.parties().contains(&index),
            "the party is not part of the session"
        );
        let [R1, R2] = self
            .nonces
            .get(&index)
            .ok_or(SignatureShareInvalid { index })?
            .0;
        let valid = g!(R1 + b * R2 + (c * lambda) * X - s * G).is_zero();
        if valid {
            Ok(())
        } else {
            Err(SignatureShareInvalid { index })
        }
    }

    /// Combines signature shares from each party into the final signature.
    ///
    /// You can use this instead of calling [`verify_signature_share`] on each share.
    ///
    /// [`verify_signature_share`]: Self::verify_signature_share
    pub fn verify_and_combine_signature_shares(
        &self,
        shared_key: &SharedKey<EvenY>,
        signature_shares: BTreeMap<PartyIndex, Scalar<Public, Zero>>,
    ) -> Result<Signature, VerifySignatureSharesError> {
        if signature_shares.len() < shared_key.threshold() {
            return Err(VerifySignatureSharesError::NotEnough {
                missing: shared_key.threshold() - signature_shares.len(),
            });
        }
        for (party_index, signature_share) in &signature_shares {
            self.verify_signature_share(
                shared_key.verification_share(*party_index),
                *signature_share,
            )
            .map_err(VerifySignatureSharesError::Invalid)?;
        }

        let signature =
            self.combine_signature_shares(self.final_nonce(), signature_shares.values().cloned());

        Ok(signature)
    }

    /// Combine a vector of signatures shares into an aggregate signature given the final nonce.
    ///
    /// You can get `final_nonce` from either of the [`CoordinatorSignSession`] or the [`PartySignSession`].
    ///
    /// This method does not check the validity of the `signature_shares`
    /// but if you have verified each signature share
    /// individually the output will be a valid siganture under the `frost_key` and message provided
    /// when starting the session.
    ///
    /// Alternatively you can use [`verify_and_combine_signature_shares`] which checks and combines
    /// the signature shares.
    ///
    /// ## Return value
    ///
    /// Returns a schnorr [`Signature`] on the message
    ///
    /// [`CoordinatorSignSession`]: CoordinatorSignSession::final_nonce
    /// [`PartySignSession`]: PartySignSession::final_nonce
    /// [`verify_and_combine_signature_shares`]: Self::verify_and_combine_signature_shares
    pub fn combine_signature_shares(
        &self,
        final_nonce: Point<EvenY>,
        signature_shares: impl IntoIterator<Item = Scalar<Public, Zero>>,
    ) -> Signature {
        let sum_s = signature_shares
            .into_iter()
            .reduce(|acc, partial_sig| s!(acc + partial_sig).public())
            .unwrap_or(Scalar::zero());
        Signature {
            R: final_nonce,
            s: sum_s,
        }
    }
}

/// The session that is used to sign a message.
///
/// Created using [`party_sign_session`]
///
/// [`party_sign_session`]: super::Frost::party_sign_session
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "bincode",
    derive(crate::fun::bincode::Encode, crate::fun::bincode::Decode),
    bincode(crate = "crate::fun::bincode")
)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct PartySignSession {
    pub(crate) public_key: Point<EvenY>,
    pub(crate) binding_coeff: Scalar<Public>,
    pub(crate) final_nonce: Point<EvenY>,
    pub(crate) challenge: Scalar<Public, Zero>,

    pub(crate) parties: BTreeSet<Scalar<Public>>,
    pub(crate) binonce_needs_negation: bool,
}

impl PartySignSession {
    /// The final nonce that will actually appear in the signature
    pub fn final_nonce(&self) -> Point<EvenY> {
        self.final_nonce
    }

    /// The public key the session was started under
    pub fn public_key(&self) -> Point<EvenY> {
        self.public_key
    }

    /// Generates a signature share under the frost key using a secret share.
    ///
    /// The `secret_share` is taken as a `PairedSecretShare<EvenY>` to guarantee that the secret is aligned with an `EvenY` point.
    ///
    /// ## Return value
    ///
    /// Returns a signature share
    ///
    /// ## Panics
    ///
    /// Panics if the `secret_share` was not part of the signing session
    pub fn sign(
        &self,
        secret_share: &PairedSecretShare<EvenY>,
        secret_nonce: NonceKeyPair,
    ) -> Scalar<Public, Zero> {
        if self.public_key != secret_share.public_key() {
            panic!("the share's shared key is not the same as the shared key of the session");
        }
        let secret_share = secret_share.secret_share();
        let lambda = poly::eval_basis_poly_at_0(secret_share.index, self.parties.iter().cloned());
        let [mut r1, mut r2] = secret_nonce.secret;
        r1.conditional_negate(self.binonce_needs_negation);
        r2.conditional_negate(self.binonce_needs_negation);

        let b = &self.binding_coeff;
        let x = secret_share.share;
        let c = &self.challenge;
        s!(r1 + (r2 * b) + lambda * x * c).public()
    }
}

/// Error for a signature share being invalid
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureShareInvalid {
    index: PartyIndex,
}

impl core::fmt::Display for SignatureShareInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "signature share from party {} was invalid", self.index)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SignatureShareInvalid {}

/// Error returned by [`CoordinatorSignSession::verify_and_combine_signature_shares`]
#[derive(Clone, Debug, PartialEq)]
pub enum VerifySignatureSharesError {
    /// Not enough signature shares to compelte the signature
    NotEnough {
        /// How many are missing
        missing: usize,
    },
    /// One of the signature shars was invalid
    Invalid(SignatureShareInvalid),
}

impl core::fmt::Display for VerifySignatureSharesError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            VerifySignatureSharesError::NotEnough { missing } => {
                write!(f, "not enough signature shares have been collected to finish the signature. You need {missing} more.")
            }
            VerifySignatureSharesError::Invalid(invalid) => write!(f, "{invalid}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifySignatureSharesError {}
