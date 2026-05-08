//! SimplePedPop is a bare bones secure distributed key generation algorithm that leaves a lot left
//! up to the application.
//!
//! The application must figure out:
//!
//! - How to secretly transport secret share contribution from each contributor to their intended destination
//! - Checking that each party got the correct output by comparing
//!   [`VerifiedAggKeygenInput::cert_bytes`] on each of them.
//!
//! [`VerifiedAggKeygenInput::cert_bytes`]: VerifiedAggKeygenInput::cert_bytes
use super::Role;
pub use super::{AuxContributor, ShareReceiver};
use crate::{Message, Schnorr, Signature, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::marker::PhantomData;
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, poly, prelude::*, rand_core};

pub(crate) mod role_sealed {
    pub trait Sealed {
        /// Translate a role-relative index to the absolute slot index in
        /// `[0..n_contributors)`. Returns `None` if `role_index` is out of
        /// range for this role.
        fn slot_index(role_index: u32, n_receivers: u32, n_aux_contributors: u32) -> Option<u32>;
    }
}

impl role_sealed::Sealed for ShareReceiver {
    fn slot_index(role_index: u32, n_receivers: u32, _n_aux_contributors: u32) -> Option<u32> {
        (role_index < n_receivers).then_some(role_index)
    }
}

impl role_sealed::Sealed for AuxContributor {
    fn slot_index(role_index: u32, n_receivers: u32, n_aux_contributors: u32) -> Option<u32> {
        (role_index < n_aux_contributors)
            .then(|| n_receivers.checked_add(role_index))
            .flatten()
    }
}

const POP_DOMAIN_SEP: &str = "BIP DKG/pop message";

/// One party's protocol state for a `simplepedpop` keygen. Construct with
/// [`gen_keygen_input`] and consume with [`verify_agg_input`] (or the
/// `ShareReceiver` variant).
///
/// `R` selects the role-relative meaning of the `my_role_index` argument to
/// [`gen_keygen_input`] — see the [module-level docs] for `R`'s overall job
/// across the three layers.
///
/// Deliberately not serializable: `Contributor` is in-memory protocol state with
/// invariants that can't be re-checked after decode. A tampered blob with
/// consistent-looking fields could trick later checks.
///
/// [`gen_keygen_input`]: Self::gen_keygen_input
/// [`verify_agg_input`]: Contributor::<AuxContributor>::verify_agg_input
/// [module-level docs]: super
#[derive(Clone, Debug, PartialEq)]
pub struct Contributor<R: Role> {
    my_key_contrib: Point,
    my_index: u32,
    threshold: u32,
    n_aux_contributors: u32,
    n_receivers: u32,
    _role: PhantomData<R>,
}

impl<R: Role> Contributor<R> {
    /// Generate this contributor's keygen input for the protocol round.
    ///
    /// `my_role_index` is role-relative: for [`ShareReceiver`] it's the receiver slot
    /// in `[0..n_receivers)` (the polynomial is evaluated at `ShareIndex = my_role_index + 1`);
    /// for [`AuxContributor`] it's in `[0..n_aux_contributors)`.
    pub fn gen_keygen_input<H, NG>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        n_aux_contributors: u32,
        n_receivers: u32,
        my_role_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Self, KeygenInput, SecretKeygenInput), GenKeygenInputError>
    where
        H: Hash32,
        NG: NonceGen,
    {
        if threshold == 0 || threshold > n_receivers {
            return Err(GenKeygenInputError::InvalidThreshold {
                threshold,
                n_receivers,
            });
        }
        n_aux_contributors
            .checked_add(n_receivers)
            .ok_or(GenKeygenInputError::TooManyContributors)?;
        let my_index = R::slot_index(my_role_index, n_receivers, n_aux_contributors).ok_or(
            GenKeygenInputError::IndexOutOfRange {
                role_index: my_role_index,
            },
        )?;
        let secret_poly = poly::scalar::generate(threshold as usize, rng);
        let com = poly::scalar::to_point_poly(&secret_poly);
        let pop_keypair = KeyPair::new_xonly(secret_poly[0]);
        let pop = schnorr.sign(
            &pop_keypair,
            Message::new(POP_DOMAIN_SEP, &pop_message_bytes(com[0], my_index)),
        );

        let shares = (1..=n_receivers)
            .map(|i| {
                let share_index = ShareIndex::try_from(i).expect("non-zero");
                poly::scalar::eval(&secret_poly, share_index)
            })
            .collect();
        let self_ = Self {
            my_key_contrib: com[0],
            my_index,
            threshold,
            n_aux_contributors,
            n_receivers,
            _role: PhantomData,
        };
        let msg = KeygenInput { com, pop };
        Ok((self_, msg, shares))
    }

    fn verify_agg_input_inner<H, NG>(
        self,
        schnorr: &Schnorr<H, NG>,
        agg_input: AggKeygenInput,
    ) -> Result<VerifiedAggKeygenInput, VerifyAggInputError>
    where
        H: Hash32,
    {
        if agg_input.key_contrib.len() != self.n_contributors() as usize {
            return Err(VerifyAggInputError::ContributionDidntMatch);
        }
        // Reject zero-coefficient padding that would inflate the apparent threshold.
        if agg_input.agg_poly.len() + 1 != self.threshold as usize {
            return Err(VerifyAggInputError::ContributionDidntMatch);
        }
        let my_got_contrib = agg_input
            .key_contrib
            .get(self.my_index as usize)
            .map(|(point, _)| *point);
        let my_expected_contrib = self.my_key_contrib;
        if Some(my_expected_contrib) != my_got_contrib {
            return Err(VerifyAggInputError::ContributionDidntMatch);
        }

        agg_input.verify_proofs_of_possession(schnorr)?;

        let shared_key = agg_input
            .shared_key()
            .non_zero()
            .ok_or(VerifyAggInputError::SharedKeyIsZero)?;

        Ok(VerifiedAggKeygenInput {
            inner: agg_input,
            shared_key,
        })
    }

    /// Absolute slot index in `[0..n_contributors)`.
    pub fn contributor_index(&self) -> u32 {
        self.my_index
    }

    /// The `my_role_index` this contributor was constructed with.
    pub fn role_index(&self) -> u32 {
        if self.my_index < self.n_receivers {
            self.my_index
        } else {
            self.my_index - self.n_receivers
        }
    }

    /// `n_aux_contributors + n_receivers`.
    pub fn n_contributors(&self) -> u32 {
        self.n_aux_contributors + self.n_receivers
    }

    /// Number of receivers configured at construction.
    pub fn n_receivers(&self) -> u32 {
        self.n_receivers
    }

    /// Threshold configured at construction.
    pub fn threshold(&self) -> u32 {
        self.threshold
    }
}

impl Contributor<AuxContributor> {
    /// Verify the coordinator faithfully included this contributor's input.
    /// Parties must still confirm agreement on the result by comparing
    /// [`VerifiedAggKeygenInput::cert_bytes`] out-of-band.
    pub fn verify_agg_input<H, NG>(
        self,
        schnorr: &Schnorr<H, NG>,
        agg_input: AggKeygenInput,
    ) -> Result<VerifiedAggKeygenInput, VerifyAggInputError>
    where
        H: Hash32,
    {
        self.verify_agg_input_inner(schnorr, agg_input)
    }
}

impl Contributor<ShareReceiver> {
    /// Verify the aggregated input and extract this contributor's paired secret share
    /// atomically. `secret_share` is already summed across contributors; if you have
    /// per-contributor inputs use [`verify_agg_input_combining`] instead. Parties must
    /// still confirm agreement out-of-band via [`VerifiedAggKeygenInput::cert_bytes`].
    ///
    /// [`verify_agg_input_combining`]: Self::verify_agg_input_combining
    pub fn verify_agg_input<H, NG>(
        self,
        schnorr: &Schnorr<H, NG>,
        agg_input: AggKeygenInput,
        secret_share: Scalar<Secret, Zero>,
    ) -> Result<(VerifiedAggKeygenInput, PairedSecretShare), ShareReceiverError>
    where
        H: Hash32,
    {
        let my_position = self.my_index;
        let verified = self.verify_agg_input_inner(schnorr, agg_input)?;
        let my_share_index = ShareIndex::try_from(my_position + 1).expect("non-zero");
        let secret_share = SecretShare {
            index: my_share_index,
            share: secret_share,
        };
        let paired = verified
            .shared_key
            .pair_secret_share(secret_share)
            .ok_or(ShareReceiverError::InvalidSecretShare)?;
        Ok((verified, paired))
    }

    /// Like [`verify_agg_input`] but sums per-contributor share contributions first.
    ///
    /// Pass the `i`th entry from every contributor's [`SecretKeygenInput`] in
    /// slot order; `secret_share_inputs.len()` must equal `n_contributors`.
    ///
    /// [`verify_agg_input`]: Self::verify_agg_input
    pub fn verify_agg_input_combining<H, NG>(
        self,
        schnorr: &Schnorr<H, NG>,
        agg_input: AggKeygenInput,
        secret_share_inputs: &[Scalar<Secret, Zero>],
    ) -> Result<(VerifiedAggKeygenInput, PairedSecretShare), ShareReceiverError>
    where
        H: Hash32,
    {
        let n_contributors = self.n_contributors();
        if secret_share_inputs.len() != n_contributors as usize {
            return Err(ShareReceiverError::WrongShareInputCount {
                expected: n_contributors,
                got: secret_share_inputs.len() as u32,
            });
        }
        let mut secret_share = s!(0);
        for share in secret_share_inputs {
            secret_share += share;
        }
        self.verify_agg_input(schnorr, agg_input, secret_share)
    }
}

/// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
/// `Contributor` to the *coordinator*.
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct KeygenInput {
    /// The polynomial commitment of the contributor.
    pub com: Vec<Point>,
    /// Their proof-of-possession signature on the first coefficient.
    pub pop: Signature,
}

/// One [`Contributor`]'s share contributions, indexed by receiver slot
/// (position `i` is the share for `ShareIndex = i + 1`). The application
/// must transport each entry to the corresponding receiver out-of-band —
/// `simplepedpop` does not encrypt them; use [`encpedpop`] for that.
///
/// [`encpedpop`]: super::encpedpop
pub type SecretKeygenInput = Vec<Scalar<Secret, Zero>>;

/// Stores the state of the coordinator as it aggregates inputs from [`Contributor`]s.
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    threshold: u32,
    n_receivers: u32,
    inputs: BTreeMap<super::Party, Option<KeygenInput>>,
}

impl Coordinator {
    /// Total contributor slots = `n_aux_contributors + n_receivers`; receivers
    /// occupy `[0..n_receivers)`, aux contributors fill the rest.
    pub fn new(threshold: u32, n_aux_contributors: u32, n_receivers: u32) -> Self {
        assert!(threshold > 0);
        let inputs = (0..n_receivers)
            .map(super::Party::Receiver)
            .chain((0..n_aux_contributors).map(super::Party::AuxContributor))
            .map(|party| (party, None))
            .collect();
        Self {
            threshold,
            n_receivers,
            inputs,
        }
    }

    /// Adds an `input` from a [`Contributor`]. Authentication of the sender —
    /// confirming `from` is who you think it is — is up to the application.
    pub fn add_input<H: Hash32, NG>(
        &mut self,
        schnorr: &Schnorr<H, NG>,
        from: super::Party,
        input: KeygenInput,
    ) -> Result<(), AddInputError> {
        let entry = match self.inputs.get_mut(&from) {
            Some(maybe_input) => match maybe_input {
                Some(_) => return Err(AddInputError::DuplicateInput { from }),
                none => none,
            },
            None => return Err(AddInputError::UnknownContributor { from }),
        };
        if input.com.len() != self.threshold as usize {
            return Err(AddInputError::WrongThreshold {
                expected: self.threshold,
                got: input.com.len() as u32,
            });
        }

        let slot = from.slot_index(self.n_receivers);
        let (first_coeff_even_y, _) = input.com[0].into_point_with_even_y();
        if !schnorr.verify(
            &first_coeff_even_y,
            Message::new(POP_DOMAIN_SEP, &pop_message_bytes(input.com[0], slot)),
            &input.pop,
        ) {
            return Err(AddInputError::InvalidProofOfPossession);
        }
        *entry = Some(input);

        Ok(())
    }

    /// Which [`Contributor`]s are we missing input from.
    pub fn missing_from(&self) -> BTreeSet<super::Party> {
        self.inputs
            .iter()
            .filter_map(|(party, input)| input.is_none().then_some(*party))
            .collect()
    }

    /// Has the coordinator received input from each [`Contributor`].
    pub fn is_finished(&self) -> bool {
        self.inputs.values().all(|v| v.is_some())
    }

    /// Try and finish input aggregation step.
    ///
    /// Returns `None` if [`is_finished`] returns `false`.
    ///
    /// [`is_finished`]: Self::is_finished
    pub fn finish(self) -> Option<AggKeygenInput> {
        if !self.is_finished() {
            return None;
        }
        let inputs = self.inputs.into_values().flatten().collect::<Vec<_>>();
        // The "key contributions" are separated out and treated specially since they can't be
        // aggregated by the coordinator since each one needs to be validated against a
        // proof-of-possesson.
        let key_contrib = inputs
            .iter()
            .map(|message| (message.com[0], message.pop))
            .collect();

        // The rest of the coefficients can be aggregated
        let mut agg_poly = vec![Point::<NonNormal, Public, _>::zero(); self.threshold as usize - 1];
        for message in inputs {
            for (i, com) in message.com[1..].iter().enumerate() {
                agg_poly[i] += com
            }
        }

        let agg_poly = poly::point::normalize(agg_poly).collect::<Vec<_>>();

        Some(AggKeygenInput {
            key_contrib,
            agg_poly,
        })
    }
}

/// Key generation inputs after being aggregated by the coordinator
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct AggKeygenInput {
    /// The key contribution from each [`Contributor`]
    key_contrib: Vec<(Point, Signature)>,
    /// The aggregated non-constant term polynomial
    agg_poly: Vec<Point<Normal, Public, Zero>>,
}

impl AggKeygenInput {
    pub(in crate::frost::chilldkg) fn n_contributors(&self) -> usize {
        self.key_contrib.len()
    }

    fn shared_key(&self) -> SharedKey<Normal, Zero> {
        let public_key = self
            .key_contrib
            .iter()
            .fold(Point::zero(), |agg, (point, _)| g!(agg + point))
            .normalize();
        let mut poly = self.agg_poly.clone();
        poly.insert(0, public_key);
        SharedKey::from_poly(poly)
    }

    /// Grind `fingerprint` into the aggregated polynomial coefficients. Returns
    /// the tweak polynomial so [`encpedpop`] can apply the same tweak
    /// homomorphically to encrypted shares.
    ///
    /// [`encpedpop`]: super::encpedpop
    pub(in crate::frost::chilldkg) fn grind_fingerprint<H: Hash32>(
        &mut self,
        fingerprint: Fingerprint,
    ) -> Vec<Scalar<Public, Zero>> {
        let mut shared_key = self.shared_key();
        let tweak_poly = shared_key.grind_fingerprint::<H>(fingerprint);
        self.agg_poly = shared_key.point_polynomial()[1..].to_vec();
        debug_assert!(
            self.shared_key()
                .check_fingerprint::<H>(fingerprint)
                .is_some()
        );
        tweak_poly
    }

    fn verify_proofs_of_possession<H, NG>(
        &self,
        schnorr: &Schnorr<H, NG>,
    ) -> Result<(), VerifyAggInputError>
    where
        H: Hash32,
    {
        for (i, (key_contrib, pop)) in self.key_contrib.iter().enumerate() {
            let (first_coeff_even_y, _) = key_contrib.into_point_with_even_y();
            if !schnorr.verify(
                &first_coeff_even_y,
                Message::new(POP_DOMAIN_SEP, &pop_message_bytes(*key_contrib, i as u32)),
                pop,
            ) {
                return Err(VerifyAggInputError::InvalidProofOfPossession { from: i as u32 });
            }
        }

        Ok(())
    }
}

/// An [`AggKeygenInput`] that this contributor has verified against its own protocol state.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAggKeygenInput {
    inner: AggKeygenInput,
    shared_key: SharedKey,
}

impl VerifiedAggKeygenInput {
    /// The raw aggregate that was verified.
    pub fn agg_input(&self) -> &AggKeygenInput {
        &self.inner
    }

    /// The [`SharedKey`] this aggregated input produces.
    pub fn shared_key(&self) -> SharedKey {
        self.shared_key.clone()
    }

    /// Bytes that uniquely identify this verified aggregate. Compare this
    /// out-of-band with every other party — if you all match, you all
    /// produced the same key. Outer layers ([`encpedpop`], [`certpedpop`])
    /// extend these bytes to bind their own state.
    ///
    /// [`encpedpop`]: super::encpedpop
    /// [`certpedpop`]: super::certpedpop
    pub fn cert_bytes(&self) -> Vec<u8> {
        let shared_key = self.shared_key();
        let poly = shared_key.point_polynomial();
        let cert_bytes = (poly.len() as u32)
            .to_be_bytes()
            .into_iter()
            .chain(poly.iter().flat_map(|coeff| coeff.to_bytes()));

        cert_bytes.collect()
    }
}

/// Test/example helper: run every `simplepedpop` party in-process. Not for production.
pub fn simulate_keygen<H, NG>(
    schnorr: &Schnorr<H, NG>,
    threshold: u32,
    n_receivers: u32,
    n_aux_contributors: u32,
    rng: &mut impl rand_core::RngCore,
) -> (SharedKey, Vec<PairedSecretShare>)
where
    H: Hash32,
    NG: NonceGen,
{
    let mut aggregator = Coordinator::new(threshold, n_aux_contributors, n_receivers);
    let mut receivers: Vec<Contributor<ShareReceiver>> = vec![];
    let mut auxes: Vec<Contributor<AuxContributor>> = vec![];
    // Per-receiver list of share contributions (indexed by receiver position).
    let mut secret_inputs: Vec<Vec<Scalar<Secret, Zero>>> = vec![vec![]; n_receivers as usize];

    for receiver_idx in 0..n_receivers {
        let (contributor, to_coordinator, shares) = Contributor::<ShareReceiver>::gen_keygen_input(
            schnorr,
            threshold,
            n_aux_contributors,
            n_receivers,
            receiver_idx,
            rng,
        )
        .unwrap();
        aggregator
            .add_input(
                schnorr,
                super::Party::Receiver(receiver_idx),
                to_coordinator,
            )
            .unwrap();
        for (receiver_position, share) in shares.into_iter().enumerate() {
            secret_inputs[receiver_position].push(share);
        }
        receivers.push(contributor);
    }
    for aux_idx in 0..n_aux_contributors {
        let (contributor, to_coordinator, shares) =
            Contributor::<AuxContributor>::gen_keygen_input(
                schnorr,
                threshold,
                n_aux_contributors,
                n_receivers,
                aux_idx,
                rng,
            )
            .unwrap();
        aggregator
            .add_input(
                schnorr,
                super::Party::AuxContributor(aux_idx),
                to_coordinator,
            )
            .unwrap();
        for (receiver_position, share) in shares.into_iter().enumerate() {
            secret_inputs[receiver_position].push(share);
        }
        auxes.push(contributor);
    }

    let agg_input = aggregator.finish().unwrap();

    let mut verified: Option<VerifiedAggKeygenInput> = None;
    let mut paired_shares = vec![];
    for (receiver_position, contributor) in receivers.into_iter().enumerate() {
        let contributions = core::mem::take(&mut secret_inputs[receiver_position]);
        let (v, paired) = contributor
            .verify_agg_input_combining(schnorr, agg_input.clone(), &contributions)
            .unwrap();
        paired_shares.push(paired);
        verified.get_or_insert(v);
    }
    for contributor in auxes {
        verified.get_or_insert(
            contributor
                .verify_agg_input(schnorr, agg_input.clone())
                .unwrap(),
        );
    }
    let verified = verified.expect("at least one contributor");

    (verified.shared_key(), paired_shares)
}

/// Reasons [`Contributor::gen_keygen_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenKeygenInputError {
    /// `threshold == 0` or `threshold > n_receivers`. A threshold above the
    /// receiver count produces an un-reconstructible key.
    InvalidThreshold {
        /// The supplied threshold.
        threshold: u32,
        /// The supplied number of receivers.
        n_receivers: u32,
    },
    /// `my_role_index` was out of range for the role. For [`ShareReceiver`] the
    /// max is `n_receivers`; for [`AuxContributor`] it is `n_aux_contributors`.
    IndexOutOfRange {
        /// The supplied role-relative index.
        role_index: u32,
    },
    /// `n_aux_contributors + n_receivers` overflowed `u32`.
    TooManyContributors,
}

impl core::fmt::Display for GenKeygenInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenKeygenInputError::InvalidThreshold {
                threshold,
                n_receivers,
            } => write!(
                f,
                "threshold {threshold} is invalid for {n_receivers} receivers"
            ),
            GenKeygenInputError::IndexOutOfRange { role_index } => write!(
                f,
                "role-relative index {role_index} is out of range for this role"
            ),
            GenKeygenInputError::TooManyContributors => {
                write!(f, "n_aux_contributors + n_receivers overflowed u32")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenKeygenInputError {}

/// Reasons [`Contributor::verify_agg_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAggInputError {
    /// This contributor's input was not faithfully included in the aggregated input.
    ContributionDidntMatch,
    /// A key contribution had an invalid proof of possession.
    InvalidProofOfPossession {
        /// The contributor slot whose PoP failed.
        from: u32,
    },
    /// The aggregated key contributions summed to the point at infinity —
    /// negligible with one honest random contributor, so this indicates malice.
    SharedKeyIsZero,
}

impl core::fmt::Display for VerifyAggInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyAggInputError::ContributionDidntMatch => write!(
                f,
                "the contribution assigned to us was not what we contributed"
            ),
            VerifyAggInputError::InvalidProofOfPossession { from } => {
                write!(f, "invalid proof of possession from contributor {from}")
            }
            VerifyAggInputError::SharedKeyIsZero => write!(
                f,
                "aggregated key contributions summed to the point at infinity"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyAggInputError {}

/// Reasons [`Contributor::<ShareReceiver>::verify_agg_input`] (or its
/// summing variant [`verify_agg_input_combining`]) may fail.
///
/// [`verify_agg_input_combining`]: Contributor::<ShareReceiver>::verify_agg_input_combining
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ShareReceiverError {
    /// The aggregated input failed to verify.
    VerifyAggInput(VerifyAggInputError),
    /// The supplied `secret_share` did not pair with the verified aggregate.
    InvalidSecretShare,
    /// `secret_share_inputs.len()` passed to `verify_agg_input_combining`
    /// did not match `n_contributors`.
    WrongShareInputCount {
        /// The configured number of contributors.
        expected: u32,
        /// The number of share inputs actually supplied.
        got: u32,
    },
}

impl From<VerifyAggInputError> for ShareReceiverError {
    fn from(err: VerifyAggInputError) -> Self {
        ShareReceiverError::VerifyAggInput(err)
    }
}

impl core::fmt::Display for ShareReceiverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShareReceiverError::VerifyAggInput(err) => write!(f, "{err}"),
            ShareReceiverError::InvalidSecretShare => {
                write!(
                    f,
                    "the secret share did not pair with the verified aggregate"
                )
            }
            ShareReceiverError::WrongShareInputCount { expected, got } => write!(
                f,
                "expected {expected} secret share inputs (one per contributor), got {got}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShareReceiverError {}

/// Reasons [`Coordinator::add_input`] may reject a contributor's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddInputError {
    /// Input from this contributor has already been recorded.
    DuplicateInput {
        /// The party that already has an input recorded.
        from: super::Party,
    },
    /// No contributor is expected at this party.
    UnknownContributor {
        /// The unexpected party.
        from: super::Party,
    },
    /// Polynomial commitment length doesn't match the configured threshold.
    WrongThreshold {
        /// The threshold the coordinator was configured with.
        expected: u32,
        /// The number of coefficients we actually received.
        got: u32,
    },
    /// Proof-of-possession signature failed to verify.
    InvalidProofOfPossession,
}

impl core::fmt::Display for AddInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddInputError::DuplicateInput { from } => {
                write!(f, "already have input from {from:?}")
            }
            AddInputError::UnknownContributor { from } => {
                write!(f, "no input expected from {from:?}")
            }
            AddInputError::WrongThreshold { expected, got } => write!(
                f,
                "input polynomial has {got} coefficients but threshold is {expected}"
            ),
            AddInputError::InvalidProofOfPossession => {
                write!(f, "proof-of-possession signature did not verify")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddInputError {}

// `parity_byte || contributor_index_be`. The parity byte closes the BIP340
// x-only gap so a replay of `(A, pop)` under `-A` fails PoP verification.
// SPEC DEVIATION: spec only has the contribution_index.
fn pop_message_bytes(first_coeff: Point, contributor_index: u32) -> [u8; 5] {
    let mut bytes = [0u8; 5];
    bytes[0] = u8::from(!first_coeff.is_y_even());
    bytes[1..].copy_from_slice(&contributor_index.to_be_bytes());
    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::frost::chilldkg::{Party, simplepedpop};

    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    use secp256kfun::proptest;

    proptest! {
        #[test]
        fn simplepedpop_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_aux_contributors in 0u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            simplepedpop::simulate_keygen(&schnorr, threshold, n_receivers, n_aux_contributors, &mut rng);
        }
    }

    // The PoP must bind both the slot index and the y-parity of com[0]:
    //   (1) Alice's pop for slot 0 must not verify at another slot.
    //   (2) A replay of Alice's pop with the negated first coefficient (-A) must
    //       not verify at any slot, including slot 0.
    #[test]
    fn pop_bound_to_slot_and_parity_rejects_replay() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let threshold = 2u32;
        let n_aux_contributors = 0u32;
        let n_receivers = 2u32;

        let (_alice_state, alice_msg, _alice_shares) =
            simplepedpop::Contributor::<ShareReceiver>::gen_keygen_input(
                &schnorr,
                threshold,
                n_aux_contributors,
                n_receivers,
                0,
                &mut rng,
            )
            .unwrap();

        let mut coord_replay_slot =
            simplepedpop::Coordinator::new(threshold, n_aux_contributors, n_receivers);
        assert_eq!(
            coord_replay_slot.add_input(&schnorr, Party::Receiver(1), alice_msg.clone()),
            Err(AddInputError::InvalidProofOfPossession),
            "Alice's pop for slot 0 must not verify at slot 1"
        );

        let negated_msg = KeygenInput {
            com: core::iter::once(-alice_msg.com[0])
                .chain(alice_msg.com[1..].iter().copied())
                .collect(),
            pop: alice_msg.pop,
        };
        let mut coord_negate_same_slot =
            simplepedpop::Coordinator::new(threshold, n_aux_contributors, n_receivers);
        assert_eq!(
            coord_negate_same_slot.add_input(&schnorr, Party::Receiver(0), negated_msg.clone()),
            Err(AddInputError::InvalidProofOfPossession),
            "negated-key replay at the original slot must now be rejected by the PoP check"
        );

        let mut coord_negate_other_slot =
            simplepedpop::Coordinator::new(threshold, n_aux_contributors, n_receivers);
        assert_eq!(
            coord_negate_other_slot.add_input(&schnorr, Party::Receiver(1), negated_msg),
            Err(AddInputError::InvalidProofOfPossession),
            "negated-key replay at a different slot must be rejected by the PoP check"
        );
    }

    fn run_input_aggregation_stage(
        threshold: u32,
        n_aux_contributors: u32,
        n_receivers: u32,
    ) -> (
        Vec<simplepedpop::Contributor<AuxContributor>>,
        simplepedpop::AggKeygenInput,
    ) {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let mut coordinator =
            simplepedpop::Coordinator::new(threshold, n_aux_contributors, n_receivers);
        for receiver_idx in 0..n_receivers {
            let (_, msg, _) = simplepedpop::Contributor::<ShareReceiver>::gen_keygen_input(
                &schnorr,
                threshold,
                n_aux_contributors,
                n_receivers,
                receiver_idx,
                &mut rng,
            )
            .unwrap();
            coordinator
                .add_input(&schnorr, Party::Receiver(receiver_idx), msg)
                .unwrap();
        }
        let mut auxes = vec![];
        for aux_idx in 0..n_aux_contributors {
            let (contributor, msg, _) =
                simplepedpop::Contributor::<AuxContributor>::gen_keygen_input(
                    &schnorr,
                    threshold,
                    n_aux_contributors,
                    n_receivers,
                    aux_idx,
                    &mut rng,
                )
                .unwrap();
            coordinator
                .add_input(&schnorr, Party::AuxContributor(aux_idx), msg)
                .unwrap();
            auxes.push(contributor);
        }
        (auxes, coordinator.finish().unwrap())
    }

    #[test]
    fn verify_agg_input_rejects_tampered_pop() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let (auxes, mut agg_input) = run_input_aggregation_stage(2, 1, 2);
        let wrong_pop = agg_input.key_contrib[1].1;
        agg_input.key_contrib[0].1 = wrong_pop;

        assert_eq!(
            auxes
                .into_iter()
                .next()
                .unwrap()
                .verify_agg_input(&schnorr, agg_input),
            Err(simplepedpop::VerifyAggInputError::InvalidProofOfPossession { from: 0 }),
            "verify_agg_input must reject raw aggregates with tampered PoPs"
        );
    }

    // A malicious aggregator could pad agg_poly with a zero high-order
    // coefficient to inflate the apparent threshold without changing the
    // polynomial's value at any ShareIndex. verify_agg_input must reject this
    // — contributors signed up for a specific threshold and that determines
    // the polynomial degree.
    #[test]
    fn verify_agg_input_rejects_padded_threshold() {
        use secp256kfun::Point;
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let (auxes, mut agg_input) = run_input_aggregation_stage(2, 1, 2);
        agg_input
            .agg_poly
            .push(Point::<Normal, Public, Zero>::zero());

        assert_eq!(
            auxes
                .into_iter()
                .next()
                .unwrap()
                .verify_agg_input(&schnorr, agg_input),
            Err(simplepedpop::VerifyAggInputError::ContributionDidntMatch),
            "verify_agg_input must reject agg_poly padding that inflates the threshold"
        );
    }

    // A threshold higher than the number of receivers produces an
    // un-reconstructible key generation. gen_keygen_input must reject this up
    // front rather than silently producing a useless aggregate.
    #[test]
    fn gen_keygen_input_rejects_threshold_above_n_receivers() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

        let result = simplepedpop::Contributor::<ShareReceiver>::gen_keygen_input(
            &schnorr, 3, 0, 2, 0, &mut rng,
        );
        assert_eq!(
            result.err(),
            Some(simplepedpop::GenKeygenInputError::InvalidThreshold {
                threshold: 3,
                n_receivers: 2,
            })
        );
    }
}
