use crate::{binonce, frost::PartyIndex};
use alloc::collections::{BTreeMap, BTreeSet};
use secp256kfun::prelude::*;
/// A FROST signing session
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
    pub(crate) binding_coeff: Scalar<Public>,
    pub(crate) agg_binonce: binonce::Nonce<Zero>,
    pub(crate) final_nonce: Point<EvenY>,
    pub(crate) challenge: Scalar<Public, Zero>,
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
    pub(crate) shared_key: Point<EvenY>,
    pub(crate) parties: BTreeSet<Scalar<Public>>,
    pub(crate) challenge: Scalar<Public, Zero>,
    pub(crate) binonce_needs_negation: bool,
    pub(crate) binding_coeff: Scalar<Public>,
    pub(crate) final_nonce: Point<EvenY>,
}

impl PartySignSession {
    /// The final nonce that will actually appear in the signature
    pub fn final_nonce(&self) -> Point<EvenY> {
        self.final_nonce
    }
}
