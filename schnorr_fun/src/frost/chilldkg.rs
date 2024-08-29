//! Our take on the WIP *[ChillDKG: Distributed Key Generation for FROST][ChillDKG]* spec
//!
//! ChillDKG is a modular distributed key generation protocol. At the end all the intended parties
//! have a valid `t-of-n` [Shamir secret sharing] of a secret key without requiring a trusted party
//! or even an honest majority.
//!
//! The [WIP spec][ChillDKG] defines two roles:
//!
//! - *Coordinator*: A central party who relays and aggregates messages between the other parties.
//! - *Participants*: The parties who provide secret input and receive secret shares as output from the protocol.
//!
//! In this implementation we split "participants" into two further roles:
//!
//! - *Contributors*: parties that provide secret input into the key generation
//! - *Receivers*: parties that receive a secret share from the protocol.
//!
//! We see a benefit to having parties that provide secret input but do not receive secret output.
//! The main example of this is having the coordinator itself be an *Contributor* too. In the context
//! of a Bitcoin hardware wallet, the coordinator is usually the only party with access to the
//! internet therefore, if the coordinator contributes input honestly, even if all the non-internet
//! connected devices are malicious the *remote* adversary (who set the code of the malicious
//! device) will not know the secret key. In fact, the adversary would have to recover `t` devices
//! and extract their internal state to reconstruct the key. This is nice, because *in theory* and
//! in this limited sense it gives the attacker no advantage from controlling the code of the
//! signing devices (anyone who wants to reconstruct the key already needs `t` shares).
//!
//! ## Variants
//!
//! The spec comes in three variants:
//!
//! - [`simplepedpop`]: bare bones FROST key generation
//! - [`encpedpop`]: Adds encryption to the secret input so the coordinator can aggregate encrypted secret shares.
//! - [`certpedpop`]: `encpedpop` where each party also certifies the output so they can cryptographically convince each other that the key generation was successful.
//!
//! [ChillDKG]: https://github.com/BlockstreamResearch/bip-frost-dkg
use crate::{frost::*, Schnorr};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{
    hash::{Hash32, HashAdd},
    nonce::NonceGen,
    poly,
    prelude::*,
    rand_core, KeyPair,
};

/// SimplePedPop is a bare bones secure distributed key generation algorithm that leaves a lot left
/// up to the application.
///
/// The application must figure out:
///
/// - How to secretly transport secret share contribution from each contributor to their intended destination
/// - Checking that each party got the correct output by comparing [`AggKeygenInput::cert_bytes`] on each of them.
///
/// [`AggKeygenInput::cert_bytes`]: simplepedpop::AggKeygenInput::cert_bytes
pub mod simplepedpop {
    use super::*;
    use crate::{Message, Signature};
    use alloc::{
        collections::{BTreeMap, BTreeSet},
        vec::Vec,
    };
    use secp256kfun::hash::Hash32;

    /// A party that generates secret input to the key generation. You need at least one of these
    /// and if at least one of these parties is honest then the final secret key will not be known by an
    /// attacker (unless they obtain `t` shares!).
    #[derive(Clone, Debug)]
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
    pub struct Contributor {
        my_key_contrib: Point,
        my_index: u32,
    }

    impl Contributor {
        /// Generates the keygen input for a party at `my_index`. Note that `my_index`
        /// has nothing to do with the "receiver" index (the `PartyIndex` of share receivers). If
        /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
        ///
        /// This method return `Self` to retain the state of the protocol which is needded to verify
        /// the aggregated input later on.
        pub fn gen_keygen_input<H, NG>(
            schnorr: &Schnorr<H, NG>,
            threshold: u32,
            share_receivers: &BTreeSet<PartyIndex>,
            my_index: u32,
            rng: &mut impl rand_core::RngCore,
        ) -> (Self, KeygenInput, SecretKeygenInput)
        where
            H: Hash32,
            NG: NonceGen,
        {
            let secret_poly = poly::scalar::generate(threshold as usize, rng);
            let pop_keypair = KeyPair::new_xonly(secret_poly[0]);
            // XXX The thing that's singed differs from the spec
            let pop = schnorr.sign(&pop_keypair, Message::<Public>::empty());
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
    }

    /// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
    /// `Contributor` to the *coordinator*.
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
    #[derive(Clone, Debug, PartialEq)]
    pub struct KeygenInput {
        /// The polynomial commitment of the contributor.
        pub com: Vec<Point>,
        /// Their proof-of-possession signature on the first coefficient.
        pub pop: Signature,
    }

    /// Map from party index to secret share contribution from the [`Contributor`].
    ///
    /// Each entry in the map must be sent to the corresponding party.
    pub type SecretKeygenInput = BTreeMap<PartyIndex, Scalar<Secret, Zero>>;

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
            if !schnorr.verify(&first_coeff_even_y, Message::<Public>::empty(), &input.pop) {
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
            let mut agg_poly =
                vec![Point::<NonNormal, Public, _>::zero(); self.threshold as usize - 1];
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
    pub fn receive_share<H, NG>(
        schnorr: &Schnorr<H, NG>,
        agg_input: &AggKeygenInput,
        secret_share: SecretShare,
    ) -> Result<PairedSecretShare<Normal, Zero>, ReceiveShareError>
    where
        H: Hash32,
    {
        for (key_contrib, pop) in &agg_input.key_contrib {
            let (first_coeff_even_y, _) = key_contrib.into_point_with_even_y();
            if !schnorr.verify(&first_coeff_even_y, Message::<Public>::empty(), pop) {
                return Err(ReceiveShareError::InvalidPop);
            }
        }

        let shared_key = agg_input.shared_key();

        let paired_secret_share = shared_key
            .pair_secret_share(secret_share)
            .ok_or(ReceiveShareError::InvalidSecretShare)?;

        Ok(paired_secret_share)
    }

    /// Collect the secret inputs from each [`Contributor`] destined for a particular a party at `PartyIndex`.
    pub fn collect_secret_inputs(
        my_index: PartyIndex,
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
            .map(|i| PartyIndex::from(NonZeroU32::new(i).unwrap()))
            .collect::<BTreeSet<_>>();

        let mut aggregator = Coordinator::new(threshold, n_generators);
        let mut contributors = vec![];
        let mut secret_inputs = BTreeMap::<PartyIndex, Vec<Scalar<Secret, Zero>>>::default();

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
            let paired_share = receive_share(schnorr, &agg_input, secret_share).unwrap();
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
            write!(f, "{}", match self {
                ReceiveShareError::InvalidPop => "Invalid POP for one of the contributions",
                ReceiveShareError::InvalidSecretShare =>
                    "The share extracted from the key generation was invalid",
            })
        }
    }
}

/// `encpedpop` is built on top of [`simplepedpop`] to add share encryption.
///
/// Each per recipient secret key is explicitly encrypted to each recipient and sent through the
/// coordinator. This simplifies things a bit since all messages are to or from the coordinator. The
/// coordinator also aggregates the ciphertexts so communication is reduced to linear in the number
/// of participants.
///
/// The application still must figure out when all parties agree on the [`AggKeygenInput`] before
/// using it.
///
/// [`AggKeygenInput`]: encpedpop::AggKeygenInput
pub mod encpedpop {
    use super::{simplepedpop, *};
    use crate::frost::{PairedSecretShare, PartyIndex, SecretShare, SharedKey};

    /// A party that generates secret input to the key generation. You need at least one of these
    /// and if at least one of these parties is honest then the final secret key will not be known by an
    /// attacker (unless they obtain `t` shares!).
    #[derive(Clone, Debug)]
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
    pub struct Contributor {
        inner: simplepedpop::Contributor,
    }

    impl Contributor {
        /// Generates the keygen input for a party at `my_index`. Note that `my_index`
        /// has nothing to do with the "receiver" index (the `PartyIndex` of share receivers). If
        /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
        ///
        /// This method return `Self` to retain the state of the protocol which is needded to verify
        /// the aggregated input later on.
        pub fn gen_keygen_input<H, NG>(
            schnorr: &Schnorr<H, NG>,
            threshold: u32,
            receiver_encryption_keys: &BTreeMap<PartyIndex, Point>,
            my_index: u32,
            rng: &mut impl rand_core::RngCore,
        ) -> (Self, KeygenInput)
        where
            H: Hash32,
            NG: NonceGen,
        {
            let multi_nonce_keypair = KeyPair::<Normal>::new(Scalar::random(rng));

            let share_receivers = receiver_encryption_keys.keys().cloned().collect();
            let (inner_state, inner_keygen_input, mut shares) =
                simplepedpop::Contributor::gen_keygen_input(
                    schnorr,
                    threshold,
                    &share_receivers,
                    my_index,
                    rng,
                );
            let encryption_jobs = receiver_encryption_keys
                .iter()
                .map(|(receiver, encryption_key)| {
                    (
                        *receiver,
                        (*encryption_key, shares.remove(receiver).unwrap()),
                    )
                })
                .collect();
            assert!(shares.is_empty());
            let encrypted_shares = encrypt::<H>(encryption_jobs, multi_nonce_keypair);
            let keygen_input = KeygenInput {
                inner: inner_keygen_input,
                encrypted_shares,
                encryption_nonce: multi_nonce_keypair.public_key(),
            };

            (Contributor { inner: inner_state }, keygen_input)
        }

        /// Verifies that the coordinator has honestly included this party's input into the
        /// aggregated input.
        ///
        /// This passing by itself doesn't mean that the key generation was successful. All
        /// `Contributor`s must agree on this fact and all parties must have received the same
        /// `AggKeygenInput` and validated it.
        pub fn verify_agg_input(
            self,
            agg_keygen_input: &AggKeygenInput,
        ) -> Result<(), simplepedpop::ContributionDidntMatch> {
            self.inner.verify_agg_input(&agg_keygen_input.inner)?;
            Ok(())
        }
    }

    /// Key generation inputs after being aggregated by the coordinator
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
    pub struct AggKeygenInput {
        inner: simplepedpop::AggKeygenInput,
        encrypted_shares: BTreeMap<PartyIndex, (Point, Scalar<Public, Zero>)>,
        encryption_nonces: Vec<Point>,
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
            self.inner.shared_key()
        }

        /// The *certification* bytes. Checking all parties have the same output of this function is
        /// enough to check they have the same `AggKeygenInput`.
        pub fn cert_bytes(&self) -> Vec<u8> {
            let mut cert_bytes = self.inner.cert_bytes();
            cert_bytes.extend((self.encryption_nonces.len() as u32).to_be_bytes());
            cert_bytes.extend(
                self.encryption_nonces
                    .iter()
                    .flat_map(|nonce| nonce.to_bytes()),
            );
            cert_bytes.extend((self.encrypted_shares.len() as u32).to_be_bytes());
            for (party_index, (encryption_key, encrypted_share)) in &self.encrypted_shares {
                cert_bytes.extend(party_index.to_bytes());
                cert_bytes.extend(encryption_key.to_bytes());
                cert_bytes.extend(encrypted_share.to_bytes());
            }
            cert_bytes
        }

        /// Get the encryption key for every party
        pub fn encryption_keys(&self) -> impl Iterator<Item = (PartyIndex, Point)> + '_ {
            self.encrypted_shares
                .iter()
                .map(|(party_index, (ek, _))| (*party_index, *ek))
        }

        /// Certify the `AggKeygenInput`. If all parties certify this then the keygen was
        /// successful.
        pub fn certify<H, NG>(
            &self,
            schnorr: &Schnorr<H, NG>,
            keypair: &KeyPair<EvenY>,
        ) -> Signature
        where
            H: Hash32,
            NG: NonceGen,
        {
            schnorr.sign(
                keypair,
                Message::<Public>::plain("BIP DKG/cert", self.cert_bytes().as_ref()),
            )
        }

        /// Verify that another party has certified the keygen. If you collect certifications from
        /// all parties then the keygen was successful
        pub fn verify_cert<H: Hash32, NG>(
            &self,
            schnorr: &Schnorr<H, NG>,
            cert_key: Point<EvenY>,
            signature: Signature,
        ) -> bool {
            schnorr.verify(
                &cert_key,
                Message::<Public>::plain("BIP DKG/cert", self.cert_bytes().as_ref()),
                &signature,
            )
        }

        /// Recover a share with the decryption key from the `AggKeygenInput`.
        pub fn recover_share<H: Hash32>(
            &self,
            party_index: PartyIndex,
            encryption_keypair: &KeyPair,
        ) -> Result<PairedSecretShare, &'static str> {
            let (expected_public_key, agg_ciphertext) = self
                .encrypted_shares
                .get(&party_index)
                .ok_or("No party at party_index existed")?;

            if *expected_public_key != encryption_keypair.public_key() {
                return Err("this isn't the right encryption keypair for this share");
            }
            let secret_share = decrypt::<H>(
                party_index,
                encryption_keypair,
                &self.encryption_nonces,
                *agg_ciphertext,
            );

            let paired_secret_share = self
                .shared_key()
                .pair_secret_share(SecretShare {
                    index: party_index,
                    share: secret_share,
                })
                .ok_or("the secret share recovered didn't match what was expected")?;

            paired_secret_share
                .non_zero()
                .ok_or("the shared secret was zero")
        }
    }

    /// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
    /// `Contributor` to the *coordinator*.
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
    #[derive(Clone, Debug, PartialEq)]
    pub struct KeygenInput {
        /// The input from the inner protocol
        pub inner: simplepedpop::KeygenInput,
        /// The shares encrypted for each receiving party
        pub encrypted_shares: BTreeMap<PartyIndex, Scalar<Public, Zero>>,
        /// The multi-encryption nonce for the encryptions in `encrypted_shares`
        pub encryption_nonce: Point,
    }

    /// Stores the state of the coordinator as it aggregates inputs from [`Contributor`]s.
    #[derive(Clone, Debug, PartialEq)]
    pub struct Coordinator {
        inner: simplepedpop::Coordinator,
        agg_encrypted_shares: BTreeMap<PartyIndex, (Point, Scalar<Public, Zero>)>,
        encryption_nonces: Vec<Point>,
    }

    impl Coordinator {
        /// Creates a new coordinator with:
        ///
        /// - `threshold`: of key we're trying to generate
        /// - `n_contributors`: The number of [`Contributor`]s
        /// - `receiver_encryption_keys`: The encryption keys of each of the share receivers.
        pub fn new(
            threshold: u32,
            n_contribtors: u32,
            receiver_encryption_keys: &BTreeMap<PartyIndex, Point>,
        ) -> Self {
            let agg_encrypted_shares = receiver_encryption_keys
                .iter()
                .map(|(&receiver, encryption_key)| (receiver, (*encryption_key, Scalar::zero())))
                .collect();
            Self {
                inner: simplepedpop::Coordinator::new(threshold, n_contribtors),
                agg_encrypted_shares,
                encryption_nonces: Default::default(),
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
            if self.inner.is_finished() {
                return Err("all inputs have already been collected");
            }
            let mut check_missing = self.agg_encrypted_shares.keys().collect::<BTreeSet<_>>();

            for dest in input.encrypted_shares.keys() {
                if !self.agg_encrypted_shares.contains_key(dest) {
                    return Err("included share for unknown party");
                }
                check_missing.remove(dest);
            }

            if !check_missing.is_empty() {
                return Err("didn't have share for all parties");
            }

            // ⚠ only do mutations after we're sure everything is OK
            self.inner.add_input(schnorr, from, input.inner)?;

            for (dest, encrypted_share_contrib) in input.encrypted_shares {
                let agg_encrypted_share = &mut self.agg_encrypted_shares.get_mut(&dest).unwrap().1;
                *agg_encrypted_share += encrypted_share_contrib;
            }

            self.encryption_nonces.push(input.encryption_nonce);

            Ok(())
        }

        /// Which [`Contributor`]s are we missing input from.
        pub fn missing_from(&self) -> BTreeSet<u32> {
            self.inner.missing_from()
        }

        /// Has the coordinator received input from each [`Contributor`].
        pub fn is_finished(&self) -> bool {
            self.inner.is_finished()
        }

        /// Try and finish input aggregation step.
        ///
        /// Returns `None` if [`is_finished`] returns `false`.
        ///
        /// [`is_finished`]: Self::is_finished
        pub fn finish(self) -> Option<AggKeygenInput> {
            let inner = self.inner.finish()?;
            Some(AggKeygenInput {
                inner,
                encrypted_shares: self.agg_encrypted_shares,
                encryption_nonces: self.encryption_nonces,
            })
        }
    }

    /// Extract our secret share from the `AggKeygenInput`.
    ///
    /// This also validates `agg_input`.
    pub fn receive_share<H, NG>(
        schnorr: &Schnorr<H, NG>,
        my_index: PartyIndex,
        encryption_keypair: &KeyPair,
        agg_input: &AggKeygenInput,
    ) -> Result<PairedSecretShare<Normal, Zero>, simplepedpop::ReceiveShareError>
    where
        H: Hash32,
    {
        let encrypted_share = agg_input
            .encrypted_shares
            .get(&my_index)
            .map(|(_pk, share)| *share)
            .unwrap_or_default();
        let share_scalar = decrypt::<H>(
            my_index,
            encryption_keypair,
            &agg_input.encryption_nonces,
            encrypted_share,
        );
        let secret_share = SecretShare {
            index: my_index,
            share: share_scalar,
        };
        let paired_secret_share =
            simplepedpop::receive_share(schnorr, &agg_input.inner, secret_share)?;

        Ok(paired_secret_share)
    }

    fn encrypt<H: Hash32>(
        encryption_jobs: BTreeMap<PartyIndex, (Point, Scalar<Secret, Zero>)>,
        multi_nonce_keypair: KeyPair<Normal>,
    ) -> BTreeMap<PartyIndex, Scalar<Public, Zero>> {
        encryption_jobs
            .iter()
            .map(|(dest, (encryption_key, share))| {
                let dh_key = g!(multi_nonce_keypair.secret_key() * encryption_key).normalize();
                // SPEC DEVIATION: Hash inputs are as defined in "Multi-recipient Encryption, Revisited" by Pinto et al.
                let pad = Scalar::from_hash(H::default().add(dh_key).add(encryption_key).add(dest));
                let payload = s!(pad + share).public();
                (*dest, payload)
            })
            .collect()
    }

    fn decrypt<H: Hash32>(
        my_index: PartyIndex,
        encryption_keypair: &KeyPair<Normal>,
        multi_nocnes: &[Point],
        mut agg_ciphertext: Scalar<Public, Zero>,
    ) -> Scalar<Secret, Zero> {
        for nonce in multi_nocnes {
            let dh_key = g!(encryption_keypair.secret_key() * nonce).normalize();
            let pad = Scalar::from_hash(
                H::default()
                    .add(dh_key)
                    .add(encryption_keypair.public_key())
                    .add(my_index),
            );
            agg_ciphertext -= pad;
        }
        agg_ciphertext.secret()
    }

    /// Simulate running a key generation with `encpedpop`.
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
            .map(|i| Scalar::from(i).non_zero().unwrap())
            .collect::<BTreeSet<_>>();

        let receiver_enckeys = share_receivers
            .iter()
            .cloned()
            .map(|party_index| (party_index, KeyPair::new(Scalar::random(rng))))
            .collect::<BTreeMap<_, _>>();

        let public_receiver_enckeys = receiver_enckeys
            .iter()
            .map(|(party_index, enckeypair)| (*party_index, enckeypair.public_key()))
            .collect::<BTreeMap<PartyIndex, Point>>();

        let (contributors, to_coordinator_messages): (Vec<Contributor>, Vec<KeygenInput>) = (0
            ..n_generators)
            .map(|i| {
                Contributor::gen_keygen_input(schnorr, threshold, &public_receiver_enckeys, i, rng)
            })
            .unzip();

        let mut aggregator = Coordinator::new(threshold, n_generators, &public_receiver_enckeys);

        for (i, to_coordinator_message) in to_coordinator_messages.into_iter().enumerate() {
            aggregator
                .add_input(schnorr, i as u32, to_coordinator_message)
                .unwrap();
        }

        let agg_input = aggregator.finish().unwrap();
        for contributor in contributors {
            contributor.verify_agg_input(&agg_input).unwrap();
        }

        let mut paired_secret_shares = vec![];
        for (party_index, enckey) in receiver_enckeys {
            let paired_secret_share =
                receive_share(schnorr, party_index, &enckey, &agg_input).unwrap();
            paired_secret_shares.push(paired_secret_share.non_zero().unwrap());
        }

        let shared_key = agg_input.shared_key().non_zero().unwrap();
        (shared_key, paired_secret_shares)
    }
}

/// `certpedpop` is built on top of [`encpedpop`] to add certification of the outcome.
///
/// In [`encpedpop`] and [`simplepedpop`] it's left up to the application to figure out whether all
/// the parties agree on the `AggKeygenInput`. In `certpedpop` the relevant methods return
/// certification signatures on `AggKeygenInput` once they've been validated so they can be
/// collected by the share receivers. Once the share receivers have got all the certificates they
/// can finally output the key.
///
/// Certificates are collected from other share receivers as well as `Contributor`s.
pub mod certpedpop {
    use super::*;

    /// A party that generates secret input to the key generation. You need at least one of these
    /// and if at least one of these parties is honest then the final secret key will not be known by an
    /// attacker (unless they obtain `t` shares!).
    pub struct Contributor {
        inner: encpedpop::Contributor,
    }

    /// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
    /// `Contributor` to the *coordinator*.
    pub type KeygenInput = encpedpop::KeygenInput;
    /// Key generation inputs after being aggregated by the coordinator
    pub type AggKeygenInput = encpedpop::AggKeygenInput;
    /// The certification signatures from each certifying party (both contributors and share receivers).
    pub type Certificate = BTreeMap<Point<EvenY>, Signature>;

    impl Contributor {
        /// Generates the keygen input for a party at `my_index`. Note that `my_index`
        /// has nothing to do with the "receiver" index (the `PartyIndex` of share receivers). If
        /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
        ///
        /// This method return `Self` to retain the state of the protocol which is needded to verify
        /// the aggregated input later on.
        pub fn gen_keygen_input<H: Hash32, NG: NonceGen>(
            schnorr: &Schnorr<H, NG>,
            threshold: u32,
            receiver_encryption_keys: &BTreeMap<PartyIndex, Point>,
            my_index: u32,
            rng: &mut impl rand_core::RngCore,
        ) -> (Self, KeygenInput) {
            let (inner, message) = encpedpop::Contributor::gen_keygen_input(
                schnorr,
                threshold,
                receiver_encryption_keys,
                my_index,
                rng,
            );
            (Self { inner }, message)
        }

        /// Verifies that the coordinator has honestly included this party's input into the
        /// aggregated input and returns a certification signature to that effect.
        ///
        /// This passing by itself doesn't mean that the key generation was successful. You must
        /// first collect the signatures from all the certifying parties (contributors and share
        /// receivers).
        pub fn verify_agg_input<H: Hash32, NG: NonceGen>(
            self,
            schnorr: &Schnorr<H, NG>,
            agg_keygen_input: &AggKeygenInput,
            cert_keypair: &KeyPair<EvenY>,
        ) -> Result<Signature, simplepedpop::ContributionDidntMatch> {
            self.inner.verify_agg_input(agg_keygen_input)?;
            let sig = agg_keygen_input.certify(schnorr, cert_keypair);
            Ok(sig)
        }
    }

    /// A key generation session that has been certified by each certifying party (contributors and share receivers).
    #[derive(Clone, Debug, PartialEq)]
    pub struct CertifiedKeygen {
        input: AggKeygenInput,
        certificate: Certificate,
    }

    impl CertifiedKeygen {
        /// Recover a share from a certified key generation with the decryption key.
        ///
        /// This checks that the `encryption_keypair` has signed the key generation first.
        pub fn recover_share<H: Hash32, NG>(
            &self,
            schnorr: &Schnorr<H, NG>,
            party_index: PartyIndex,
            encryption_keypair: KeyPair,
        ) -> Result<PairedSecretShare, &'static str> {
            let cert_key = encryption_keypair.public_key().into_point_with_even_y().0;
            let my_cert = self
                .certificate
                .get(&cert_key)
                .ok_or("I haven't certified this keygen")?;
            if !self.input.verify_cert(schnorr, cert_key, *my_cert) {
                return Err("my certification was invalid");
            }
            self.input
                .recover_share::<H>(party_index, &encryption_keypair)
        }

        /// Gets the inner `encpedpop::AggKeygenInput`.
        pub fn inner(&self) -> &AggKeygenInput {
            &self.input
        }
    }

    pub use encpedpop::Coordinator;

    /// Stores the state of share recipient who first receives their share and then waits to get
    /// signatures from all the certifying parties on the keygeneration before accepting it.
    pub struct ShareReceiver {
        paired_secret_share: PairedSecretShare<Normal, Zero>,
        agg_input: AggKeygenInput,
    }

    impl ShareReceiver {
        /// Extract your `encryption_keypair` and certify the key generation. Before you actually
        /// can use the share you must call [`finalize`] with a completed certificate.
        ///
        /// [`finalize`]: Self::finalize
        pub fn receive_share<H, NG>(
            schnorr: &Schnorr<H, NG>,
            my_index: PartyIndex,
            encryption_keypair: &KeyPair,
            agg_input: &AggKeygenInput,
        ) -> Result<(Self, Signature), simplepedpop::ReceiveShareError>
        where
            H: Hash32,
            NG: NonceGen,
        {
            let paired_secret_share =
                encpedpop::receive_share(schnorr, my_index, encryption_keypair, agg_input)?;
            let sig = agg_input.certify(schnorr, &(*encryption_keypair).into());
            let self_ = Self {
                paired_secret_share,
                agg_input: agg_input.clone(),
            };
            Ok((self_, sig))
        }

        /// Check the certificate contains a signature from each certifying party.
        ///
        /// By default every share receiver is a certifying party but you must also get
        /// certifications from the [`Contributor`]s for security. Their keys are passed in as
        /// `contributor_keys`.
        pub fn finalize<H: Hash32, NG>(
            self,
            schnorr: &Schnorr<H, NG>,
            certificate: Certificate,
            contributor_keys: &[Point<EvenY>],
        ) -> Result<(CertifiedKeygen, PairedSecretShare<Normal, Zero>), &'static str> {
            let cert_keys = self
                .agg_input
                .encryption_keys()
                .map(|(_, encryption_key)| encryption_key.into_point_with_even_y().0)
                .chain(contributor_keys.iter().cloned());
            for cert_key in cert_keys {
                match certificate.get(&cert_key) {
                    Some(sig) => {
                        if !self.agg_input.verify_cert(schnorr, cert_key, *sig) {
                            return Err("certification signature was invalid");
                        }
                    }
                    None => return Err("missing certification signature"),
                }
            }

            let certified_keygen = CertifiedKeygen {
                input: self.agg_input,
                certificate,
            };

            Ok((certified_keygen, self.paired_secret_share))
        }
    }

    /// Simulate running a key generation with `certpedpop`.
    ///
    /// This calls all the other functions defined in this module to get the whole job done on a
    /// single computer by simulating all the other parties.
    pub fn simulate_keygen<H: Hash32, NG: NonceGen>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        n_receivers: u32,
        n_generators: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> (CertifiedKeygen, Vec<(PairedSecretShare<Normal>, KeyPair)>) {
        let share_receivers = (1..=n_receivers)
            .map(|i| Scalar::from(i).non_zero().unwrap())
            .collect::<BTreeSet<_>>();

        let mut receiver_enckeys = share_receivers
            .iter()
            .cloned()
            .map(|party_index| (party_index, KeyPair::new(Scalar::random(rng))))
            .collect::<BTreeMap<_, _>>();

        let public_receiver_enckeys = receiver_enckeys
            .iter()
            .map(|(party_index, enckeypair)| (*party_index, enckeypair.public_key()))
            .collect::<BTreeMap<PartyIndex, Point>>();

        let (contributors, to_coordinator_messages): (Vec<Contributor>, Vec<KeygenInput>) = (0
            ..n_generators)
            .map(|i| {
                Contributor::gen_keygen_input(schnorr, threshold, &public_receiver_enckeys, i, rng)
            })
            .unzip();

        let contributor_keys = (0..n_generators)
            .map(|_| KeyPair::new_xonly(Scalar::random(rng)))
            .collect::<Vec<_>>();
        let contributor_public_keys = contributor_keys
            .iter()
            .map(KeyPair::public_key)
            .collect::<Vec<_>>();

        let mut aggregator = Coordinator::new(threshold, n_generators, &public_receiver_enckeys);

        for (i, to_coordinator_message) in to_coordinator_messages.into_iter().enumerate() {
            aggregator
                .add_input(schnorr, i as u32, to_coordinator_message)
                .unwrap();
        }

        let agg_input = aggregator.finish().unwrap();
        let mut certificate = BTreeMap::default();

        for (contributor, keypair) in contributors.into_iter().zip(contributor_keys.iter()) {
            let sig = contributor
                .verify_agg_input(schnorr, &agg_input, keypair)
                .unwrap();
            certificate.insert(keypair.public_key(), sig);
        }

        let mut paired_secret_shares = vec![];
        let mut share_receivers = vec![];
        for (party_index, enckey) in &receiver_enckeys {
            let (share_receiver, cert) =
                ShareReceiver::receive_share(schnorr, *party_index, enckey, &agg_input).unwrap();
            certificate.insert(enckey.public_key().into_point_with_even_y().0, cert);
            share_receivers.push(share_receiver);
        }

        let certified_keygen = CertifiedKeygen {
            input: agg_input.clone(),
            certificate: certificate.clone(),
        };

        for share_receiver in share_receivers {
            let (certified, paired_secret_share) = share_receiver
                .finalize(schnorr, certificate.clone(), &contributor_public_keys)
                .unwrap();
            assert_eq!(certified, certified_keygen);
            paired_secret_shares.push((
                paired_secret_share.non_zero().unwrap(),
                receiver_enckeys
                    .remove(&paired_secret_share.index())
                    .unwrap(),
            ));
        }

        (certified_keygen, paired_secret_shares)
    }

    /// There was a problem with the keygen certificate so the key generation can't be trusted.
    #[derive(Clone, Debug, Copy, PartialEq)]
    pub enum CertificateError {
        /// A certificate was invalid
        InvalidCert {
            /// The key that had the invalid cert
            key: Point<EvenY>,
        },
        /// A certificate was missing
        Missing {
            /// They key whose cert was missing
            key: Point<EvenY>,
        },
    }

    impl core::fmt::Display for CertificateError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                CertificateError::InvalidCert { key } => {
                    write!(f, "certificate for key {} was invalid", key)
                }
                CertificateError::Missing { key } => {
                    write!(f, "certificate for key {} was missing", key)
                }
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for CertificateError {}
}

#[cfg(test)]
mod test {
    use super::*;
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

        #[test]
        fn encpedpop_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_generators in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            encpedpop::simulate_keygen(&schnorr, threshold, n_receivers, n_generators, &mut rng);
        }

        #[test]
        fn certified_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_generators in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let (certified_keygen, paired_secret_shares_and_keys) = certpedpop::simulate_keygen(&schnorr, threshold, n_receivers, n_generators, &mut rng);

            for (paired_secret_share, encryption_keypair) in paired_secret_shares_and_keys {
                let recovered = certified_keygen.recover_share(&schnorr, paired_secret_share.index(), encryption_keypair).unwrap();
                assert_eq!(paired_secret_share, recovered);
            }
        }
    }
}
