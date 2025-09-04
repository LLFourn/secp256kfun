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
        share_receivers: &BTreeSet<ShareIndex>,
        my_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> (Self, KeygenInput, SecretKeygenInput)
    where
        H: Hash32,
        NG: NonceGen,
    {
        let secret_poly = poly::scalar::generate(threshold as usize, rng);
        let pop_keypair = KeyPair::new_xonly(secret_poly[0]);
        // XXX The thing that's signed differs from the spec
        let pop = schnorr.sign(&pop_keypair, Message::empty());
        let com = poly::scalar::to_point_poly(&secret_poly);

        let shares = share_receivers
            .iter()
            .map(|index| (*index, poly::scalar::eval(&secret_poly, *index)))
            .collect();
        let self_ = Self {
            my_key_contrib: com[0],
            my_index,
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
    ) -> Result<(), &'static str> {
        let entry = match self.inputs.get_mut(&from) {
            Some(maybe_input) => match maybe_input {
                Some(_) => return Err("we already have input from this party"),
                none => none,
            },
            None => return Err("no input expected from this party"),
        };
        if input.com.len() != self.threshold as usize {
            return Err("input has the wrong threshold");
        }

        let (first_coeff_even_y, _) = input.com[0].into_point_with_even_y();
        if !schnorr.verify(&first_coeff_even_y, Message::empty(), &input.pop) {
            return Err("☠ pop didn't verify");
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
        let mut cert_bytes = vec![];
        cert_bytes.extend((self.agg_poly.len() as u32).to_be_bytes());
        for coeff in self.shared_key().point_polynomial() {
            cert_bytes.extend(coeff.to_bytes());
        }
        cert_bytes
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
    for (key_contrib, pop) in &agg_input.key_contrib {
        let (first_coeff_even_y, _) = key_contrib.into_point_with_even_y();
        if !schnorr.verify(&first_coeff_even_y, Message::empty(), pop) {
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
    n_generators: u32,
    rng: &mut impl rand_core::RngCore,
) -> (SharedKey<Normal>, Vec<PairedSecretShare<Normal>>)
where
    H: Hash32,
    NG: NonceGen,
{
    let share_receivers = (1..=n_receivers)
        .map(|i| ShareIndex::from(NonZeroU32::new(i).unwrap()))
        .collect::<BTreeSet<_>>();

    let mut aggregator = Coordinator::new(threshold, n_generators);
    let mut contributors = vec![];
    let mut secret_inputs = BTreeMap::<ShareIndex, Vec<Scalar<Secret, Zero>>>::default();

    for i in 0..n_generators {
        let (contributor, to_coordinator, shares) =
            Contributor::gen_keygen_input(schnorr, threshold, &share_receivers, i, rng);

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

#[cfg(test)]
mod test {
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
            n_generators in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            simplepedpop::simulate_keygen(&schnorr, threshold, n_receivers, n_generators, &mut rng);
        }
    }
}
