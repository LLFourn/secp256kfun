//! SimplePedPop is a bare bones secure distributed key generation algorithm that leaves a lot left
//! up to the application.
//!
//! The application must figure out:
//!
//! - How to secretly transport secret share contribution from each contributor to their intended destination
//! - Checking that each party got the correct output by comparing [`AggKeygenInput::cert_bytes`] on each of them.
//!
//! [`AggKeygenInput::cert_bytes`]: AggKeygenInput::cert_bytes
use crate::{Message, Schnorr, Signature, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::num::NonZeroU32;
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, poly, prelude::*, rand_core};

const POP_DOMAIN_SEP: &str = "BIP DKG/pop";

/// A party that generates secret input to the key generation. You need at least one of these
/// and if at least one of these parties is honest then the final secret key will not be known by an
/// attacker (unless they obtain `t` shares!).
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct Contributor {
    my_key_contrib: Point,
    my_index: u32,
    n_contributors: u32,
}

impl Contributor {
    /// Generates the keygen input for a party at `my_index`. Note that `my_index`
    /// has nothing to do with the "receiver" index (the `ShareIndex` of share receivers). If
    /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
    ///
    /// This method returns `Self` to retain the state of the protocol which is needed to verify
    /// the aggregated input later on.
    pub fn gen_keygen_input<H, NG>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        n_contributors: u32,
        share_receivers: &BTreeSet<ShareIndex>,
        my_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> (Self, KeygenInput, SecretKeygenInput)
    where
        H: Hash32,
        NG: NonceGen,
    {
        assert!(threshold > 0);
        assert!(my_index < n_contributors);
        let secret_poly = poly::scalar::generate(threshold as usize, rng);
        let com = poly::scalar::to_point_poly(&secret_poly);
        let pop_keypair = KeyPair::new_xonly(secret_poly[0]);
        let pop = schnorr.sign(
            &pop_keypair,
            Message::new(POP_DOMAIN_SEP, &pop_message_bytes(com[0], my_index)),
        );

        let shares = share_receivers
            .iter()
            .map(|index| (*index, poly::scalar::eval(&secret_poly, *index)))
            .collect();
        let self_ = Self {
            my_key_contrib: com[0],
            my_index,
            n_contributors,
        };
        let msg = KeygenInput { com, pop };
        (self_, msg, shares)
    }

    /// Verifies that the coordinator has honestly included this party's input into the
    /// aggregated input.
    ///
    /// This passing by itself doesn't mean that the key generation was successful. All
    /// `Contributor`s must agree on this fact and all parties must have received the same
    /// `AggKeygenInput` and validated it.
    pub fn verify_agg_input(
        self,
        agg_input: &AggKeygenInput,
    ) -> Result<(), ContributionDidntMatch> {
        if agg_input.key_contrib.len() != self.n_contributors as usize {
            return Err(ContributionDidntMatch);
        }
        let my_got_contrib = agg_input
            .key_contrib
            .get(self.my_index as usize)
            .map(|(point, _)| *point);
        let my_expected_contrib = self.my_key_contrib;
        if Some(my_expected_contrib) != my_got_contrib {
            return Err(ContributionDidntMatch);
        }

        Ok(())
    }

    /// Get the index for the contributor
    pub fn contributor_index(&self) -> u32 {
        self.my_index
    }

    /// Get the number of contributors this contributor was configured for.
    pub fn n_contributors(&self) -> u32 {
        self.n_contributors
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

/// Map from share index to secret share contribution from the [`Contributor`].
///
/// Each entry in the map must be sent to the corresponding party.
pub type SecretKeygenInput = BTreeMap<ShareIndex, Scalar<Secret, Zero>>;

/// Stores the state of the coordinator as it aggregates inputs from [`Contributor`]s.
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    threshold: u32,
    inputs: BTreeMap<u32, Option<KeygenInput>>,
}

impl Coordinator {
    /// Creates a new coordinator with:
    ///
    /// - `threshold`: of key we're trying to generate
    /// - `n_contributors`: The number of [`Contributor`]s
    pub fn new(threshold: u32, n_contributors: u32) -> Self {
        assert!(threshold > 0);
        Self {
            threshold,
            inputs: (0..n_contributors).map(|i| (i, None)).collect(),
        }
    }

    /// Adds an `input` from a [`Contributor`].
    ///
    /// Note verifying this is the correct input from the correct party is up to your application!
    pub fn add_input<H: Hash32, NG>(
        &mut self,
        schnorr: &Schnorr<H, NG>,
        from: u32,
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

        let (first_coeff_even_y, _) = input.com[0].into_point_with_even_y();
        if !schnorr.verify(
            &first_coeff_even_y,
            Message::new(POP_DOMAIN_SEP, &pop_message_bytes(input.com[0], from)),
            &input.pop,
        ) {
            return Err(AddInputError::InvalidProofOfPossession);
        }
        *entry = Some(input);

        Ok(())
    }

    /// Which [`Contributor`]s are we missing input from.
    pub fn missing_from(&self) -> BTreeSet<u32> {
        self.inputs
            .iter()
            .filter_map(|(index, input)| match input {
                None => Some(*index),
                Some(_) => None,
            })
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
    pub key_contrib: Vec<(Point, Signature)>,
    /// The aggregated non-constant term polynomial
    pub agg_poly: Vec<Point<Normal, Public, Zero>>,
}

impl AggKeygenInput {
    /// The number of contributors whose key contributions are aggregated into this input.
    pub fn n_contributors(&self) -> usize {
        self.key_contrib.len()
    }

    /// Gets the `SharedKey` that this aggregated input produces.
    ///
    /// ## Security
    ///
    /// ⚠ Just because you can call this doesn't mean you can use the `SharedKey` securely yet!
    ///
    /// You have to have checked that all parties (contributors and receivers) think it's valid
    /// *and* have the same copy first.
    pub fn shared_key(&self) -> SharedKey<Normal, Zero> {
        let public_key = self
            .key_contrib
            .iter()
            .fold(Point::zero(), |agg, (point, _)| g!(agg + point))
            .normalize();
        let mut poly = self.agg_poly.clone();
        poly.insert(0, public_key);
        SharedKey::from_poly(poly)
    }

    /// The *certification* bytes. Checking all parties have the same output of this function is
    /// enough to check they have the same `AggKeygenInput`.
    ///
    /// In `simplepedpop` this is just the coefficients of the polynomial.
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

/// Receive secret share after summing the secret input from each [`Contributor`] with
/// [`collect_secret_inputs`] and getting the `AggKeygenInput` from the coordinator.
///
/// This also validates `agg_input`.
pub fn receive_secret_share<H, NG>(
    schnorr: &Schnorr<H, NG>,
    agg_input: &AggKeygenInput,
    secret_share: SecretShare,
) -> Result<PairedSecretShare<Normal, Zero>, ReceiveShareError>
where
    H: Hash32,
{
    for (i, (key_contrib, pop)) in agg_input.key_contrib.iter().enumerate() {
        let (first_coeff_even_y, _) = key_contrib.into_point_with_even_y();
        if !schnorr.verify(
            &first_coeff_even_y,
            Message::new(POP_DOMAIN_SEP, &pop_message_bytes(*key_contrib, i as u32)),
            pop,
        ) {
            return Err(ReceiveShareError::InvalidPop);
        }
    }

    let shared_key = agg_input.shared_key();

    let paired_secret_share = shared_key
        .pair_secret_share(secret_share)
        .ok_or(ReceiveShareError::InvalidSecretShare)?;

    Ok(paired_secret_share)
}

/// Collect the secret inputs from each [`Contributor`] destined for a particular party at `ShareIndex`.
pub fn collect_secret_inputs(
    my_index: ShareIndex,
    secret_share_inputs: impl IntoIterator<Item = Scalar<Secret, Zero>>,
) -> SecretShare {
    let mut sum = s!(0);
    for share in secret_share_inputs {
        sum += share;
    }

    SecretShare {
        index: my_index,
        share: sum,
    }
}

/// Simulate running a key generation with `simplepedpop`.
///
/// This calls all the other functions defined in this module to get the whole job done on a
/// single computer by simulating all the other parties.
pub fn simulate_keygen<H, NG>(
    schnorr: &Schnorr<H, NG>,
    threshold: u32,
    n_receivers: u32,
    n_contributors: u32,
    rng: &mut impl rand_core::RngCore,
) -> (SharedKey<Normal>, Vec<PairedSecretShare<Normal>>)
where
    H: Hash32,
    NG: NonceGen,
{
    let share_receivers = (1..=n_receivers)
        .map(|i| ShareIndex::from(NonZeroU32::new(i).unwrap()))
        .collect::<BTreeSet<_>>();

    let mut aggregator = Coordinator::new(threshold, n_contributors);
    let mut contributors = vec![];
    let mut secret_inputs = BTreeMap::<ShareIndex, Vec<Scalar<Secret, Zero>>>::default();

    for i in 0..n_contributors {
        let (contributor, to_coordinator, shares) = Contributor::gen_keygen_input(
            schnorr,
            threshold,
            n_contributors,
            &share_receivers,
            i,
            rng,
        );

        contributors.push(contributor);
        aggregator.add_input(schnorr, i, to_coordinator).unwrap();

        for (receiver_index, share) in shares {
            secret_inputs.entry(receiver_index).or_default().push(share);
        }
    }

    let agg_input = aggregator.finish().unwrap();

    for contributor in contributors {
        contributor.verify_agg_input(&agg_input).unwrap();
    }

    let mut paired_shares = vec![];

    for receiver in share_receivers {
        let secret_share =
            collect_secret_inputs(receiver, secret_inputs.remove(&receiver).unwrap());
        let paired_share = receive_secret_share(schnorr, &agg_input, secret_share).unwrap();
        paired_shares.push(paired_share.non_zero().unwrap());
    }

    (agg_input.shared_key().non_zero().unwrap(), paired_shares)
}

/// The input the contributor provided has been manipulated
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContributionDidntMatch;

impl core::fmt::Display for ContributionDidntMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "the contribution assigned to us was not what we contributed"
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContributionDidntMatch {}

/// The [`AggKeygenInput`] was invalid so a valid secret share couldn't be extracted.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ReceiveShareError {
    /// Invalid POP for one of the contributions
    InvalidPop,
    /// The secret share we got was invalid
    InvalidSecretShare,
}

impl core::fmt::Display for ReceiveShareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ReceiveShareError::InvalidPop => "Invalid POP for one of the contributions",
                ReceiveShareError::InvalidSecretShare =>
                    "The share extracted from the key generation was invalid",
            }
        )
    }
}

/// Reasons [`Coordinator::add_input`] may reject a contributor's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddInputError {
    /// Input from this contributor has already been recorded.
    DuplicateInput {
        /// The contributor index that already has an input recorded.
        from: u32,
    },
    /// No contributor is expected at this index.
    UnknownContributor {
        /// The unexpected contributor index.
        from: u32,
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
                write!(f, "already have input from contributor {from}")
            }
            AddInputError::UnknownContributor { from } => {
                write!(f, "no input expected from contributor {from}")
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

/// Build the bytes that the proof-of-possession signs.
///
/// Binding format is `parity_byte || contributor_index_be`, where `parity_byte`
/// is `0` if `com[0]` has even y and `1` otherwise. Including the parity closes
/// the BIP340 x-only gap: a replay of `(A, pop)` under the negated key `-A`
/// reconstructs a different message and so fails PoP verification.
///
/// SPEC DEVIATION: we add the parity byte where as the spec only has the contribution_index.
fn pop_message_bytes(first_coeff: Point, contributor_index: u32) -> [u8; 5] {
    let mut bytes = [0u8; 5];
    bytes[0] = u8::from(!first_coeff.is_y_even());
    bytes[1..].copy_from_slice(&contributor_index.to_be_bytes());
    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::frost::chilldkg::simplepedpop;

    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    use secp256kfun::proptest;

    proptest! {
        #[test]
        fn simplepedpop_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_contributors in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            simplepedpop::simulate_keygen(&schnorr, threshold, n_receivers, n_contributors, &mut rng);
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
        let n_contributors = 2u32;
        let share_receivers: BTreeSet<ShareIndex> = [ShareIndex::from(NonZeroU32::new(1).unwrap())]
            .into_iter()
            .collect();

        let (_alice_state, alice_msg, _alice_shares) = simplepedpop::Contributor::gen_keygen_input(
            &schnorr,
            threshold,
            n_contributors,
            &share_receivers,
            0,
            &mut rng,
        );

        let mut coord_replay_slot = simplepedpop::Coordinator::new(threshold, n_contributors);
        assert_eq!(
            coord_replay_slot.add_input(&schnorr, 1, alice_msg.clone()),
            Err(AddInputError::InvalidProofOfPossession),
            "Alice's pop for slot 0 must not verify at slot 1"
        );

        let negated_msg = KeygenInput {
            com: core::iter::once(-alice_msg.com[0])
                .chain(alice_msg.com[1..].iter().copied())
                .collect(),
            pop: alice_msg.pop,
        };
        let mut coord_negate_same_slot = simplepedpop::Coordinator::new(threshold, n_contributors);
        assert_eq!(
            coord_negate_same_slot.add_input(&schnorr, 0, negated_msg.clone()),
            Err(AddInputError::InvalidProofOfPossession),
            "negated-key replay at the original slot must now be rejected by the PoP check"
        );

        let mut coord_negate_other_slot = simplepedpop::Coordinator::new(threshold, n_contributors);
        assert_eq!(
            coord_negate_other_slot.add_input(&schnorr, 1, negated_msg),
            Err(AddInputError::InvalidProofOfPossession),
            "negated-key replay at a different slot must be rejected by the PoP check"
        );
    }
}
