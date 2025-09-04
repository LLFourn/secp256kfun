//! `encpedpop` is built on top of [`simplepedpop`] to add share encryption.
//!
//! Each per recipient secret key is explicitly encrypted to each recipient and sent through the
//! coordinator. This simplifies things a bit since all messages are to or from the coordinator. The
//! coordinator also aggregates the ciphertexts so communication is reduced to linear in the number
//! of participants.
//!
//! The application still must figure out when all parties agree on the [`AggKeygenInput`] before
//! using it.
//!
//! [`AggKeygenInput`]: AggKeygenInput
use super::simplepedpop;
use crate::{Message, Schnorr, Signature, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{
    KeyPair,
    hash::{Hash32, HashAdd},
    nonce::NonceGen,
    prelude::*,
    rand_core,
};

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
    inner: simplepedpop::Contributor,
}

impl Contributor {
    /// Generates the keygen input for a party at `my_index`. Note that `my_index`
    /// has nothing to do with the "receiver" index (the `ShareIndex` of share receivers). If
    /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
    ///
    /// This method return `Self` to retain the state of the protocol which is needded to verify
    /// the aggregated input later on.
    pub fn gen_keygen_input<H, NG>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        receiver_encryption_keys: &BTreeMap<ShareIndex, Point>,
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
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct AggKeygenInput {
    inner: simplepedpop::AggKeygenInput,
    encrypted_shares: BTreeMap<ShareIndex, (Point, Scalar<Public, Zero>)>,
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
    pub fn encryption_keys(&self) -> impl Iterator<Item = (ShareIndex, Point)> + '_ {
        self.encrypted_shares
            .iter()
            .map(|(party_index, (ek, _))| (*party_index, *ek))
    }

    /// Certify the `AggKeygenInput`. If all parties certify this then the keygen was
    /// successful.
    pub fn certify<H, NG>(&self, schnorr: &Schnorr<H, NG>, keypair: &KeyPair<EvenY>) -> Signature
    where
        H: Hash32,
        NG: NonceGen,
    {
        schnorr.sign(
            keypair,
            Message::new("BIP DKG/cert", self.cert_bytes().as_ref()),
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
            Message::new("BIP DKG/cert", self.cert_bytes().as_ref()),
            &signature,
        )
    }

    /// Recover a share with the decryption key from the `AggKeygenInput`.
    pub fn recover_share<H: Hash32>(
        &self,
        share_index: ShareIndex,
        keypair: &KeyPair,
    ) -> Result<PairedSecretShare, &'static str> {
        let (expected_public_key, agg_ciphertext) = self
            .encrypted_shares
            .get(&share_index)
            .ok_or("No party at party_index existed")?;

        if *expected_public_key != keypair.public_key() {
            return Err("this isn't the right encryption keypair for this share");
        }
        let secret_share = decrypt::<H>(
            share_index,
            keypair,
            &self.encryption_nonces,
            *agg_ciphertext,
        );

        let paired_secret_share = self
            .shared_key()
            .pair_secret_share(SecretShare {
                index: share_index,
                share: secret_share,
            })
            .ok_or("the secret share recovered didn't match what was expected")?;

        paired_secret_share
            .non_zero()
            .ok_or("the shared secret was zero")
    }

    /// Embeds a proof-of-work `fingerprint` into the aggregated polynomial.
    ///
    /// This coordinator-only operation modifies the DKG output to include
    /// a verifiable proof of work by grinding the polynomial coefficients.
    /// The `fingerprint` specifies the required difficulty (number of leading
    /// zero bits) and an optional tag to include in the hash.
    ///
    /// The process:
    /// 1. Grinds the shared key's polynomial to achieve the fingerprint
    /// 2. Updates the aggregated polynomial with the ground coefficients
    /// 3. Homomorphically applies the same tweaks to all encrypted shares
    ///
    /// This modification preserves the security of the DKG because:
    /// - The shared secret (constant term) remains unchanged
    /// - Only non-constant coefficients are modified, which are already
    ///   malleable by the coordinator
    /// - The homomorphic property ensures all shares remain consistent
    /// - Participants can verify the fingerprint matches the claimed difficulty
    pub fn grind_fingerprint<H: Hash32>(&mut self, fingerprint: Fingerprint) {
        if self.inner.agg_poly.is_empty() {
            return;
        }

        let mut shared_key = self.shared_key();
        let tweak_poly = shared_key.grind_fingerprint::<H>(fingerprint);
        // replace our poly with the one that has the fingerprint
        self.inner.agg_poly = shared_key.point_polynomial()[1..].to_vec();
        debug_assert!(self.shared_key().check_fingerprint::<H>(&fingerprint));

        for (share_index, (_encryption_key, encrypted_secret_share)) in &mut self.encrypted_shares {
            // 💡 The share encryption is homomorphic so we can apply the tweak
            // operations the same way as if the coordinator had a local copy of
            // the the unencrypted secret share.
            let mut tmp = SecretShare {
                index: *share_index,
                share: *encrypted_secret_share,
            };
            tmp.homomorphic_poly_add(&tweak_poly);
            *encrypted_secret_share = tmp.share;
        }
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
    /// The input from the inner protocol
    pub inner: simplepedpop::KeygenInput,
    /// The shares encrypted for each receiving party
    pub encrypted_shares: BTreeMap<ShareIndex, Scalar<Public, Zero>>,
    /// The multi-encryption nonce for the encryptions in `encrypted_shares`
    pub encryption_nonce: Point,
}

/// Stores the state of the coordinator as it aggregates inputs from [`Contributor`]s.
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    inner: simplepedpop::Coordinator,
    agg_encrypted_shares: BTreeMap<ShareIndex, (Point, Scalar<Public, Zero>)>,
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
        receiver_encryption_keys: &BTreeMap<ShareIndex, Point>,
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
pub fn receive_secret_share<H, NG>(
    schnorr: &Schnorr<H, NG>,
    my_index: ShareIndex,
    keypair: &KeyPair,
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
        keypair,
        &agg_input.encryption_nonces,
        encrypted_share,
    );
    let secret_share = SecretShare {
        index: my_index,
        share: share_scalar,
    };
    let paired_secret_share =
        simplepedpop::receive_secret_share(schnorr, &agg_input.inner, secret_share)?;

    Ok(paired_secret_share)
}

fn encrypt<H: Hash32>(
    encryption_jobs: BTreeMap<ShareIndex, (Point, Scalar<Secret, Zero>)>,
    multi_nonce_keypair: KeyPair<Normal>,
) -> BTreeMap<ShareIndex, Scalar<Public, Zero>> {
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
    my_index: ShareIndex,
    keypair: &KeyPair<Normal>,
    multi_nocnes: &[Point],
    mut agg_ciphertext: Scalar<Public, Zero>,
) -> Scalar<Secret, Zero> {
    for nonce in multi_nocnes {
        let dh_key = g!(keypair.secret_key() * nonce).normalize();
        let pad = Scalar::from_hash(
            H::default()
                .add(dh_key)
                .add(keypair.public_key())
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
///
/// A fingerprint can be provided to grind into the polynomial coefficients.
pub fn simulate_keygen<H, NG>(
    schnorr: &Schnorr<H, NG>,
    threshold: u32,
    n_receivers: u32,
    n_generators: u32,
    fingerprint: Fingerprint,
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
        .collect::<BTreeMap<ShareIndex, Point>>();

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

    let mut agg_input = aggregator.finish().unwrap();

    // Apply fingerprint grinding
    agg_input.grind_fingerprint::<H>(fingerprint);

    for contributor in contributors {
        contributor.verify_agg_input(&agg_input).unwrap();
    }

    let mut paired_secret_shares = vec![];
    for (party_index, enckey) in receiver_enckeys {
        let paired_secret_share =
            receive_secret_share(schnorr, party_index, &enckey, &agg_input).unwrap();
        paired_secret_shares.push(paired_secret_share.non_zero().unwrap());
    }

    let shared_key = agg_input.shared_key().non_zero().unwrap();
    (shared_key, paired_secret_shares)
}

#[cfg(test)]
mod test {
    use crate::frost::{Fingerprint, chilldkg::encpedpop};

    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    use secp256kfun::proptest;

    proptest! {
        #[test]
        fn encpedpop_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_generators in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            encpedpop::simulate_keygen(
                &schnorr,
                threshold,
                n_receivers,
                n_generators,
                Fingerprint::NONE,
                &mut rng,
            );
        }

        #[test]
        fn encpedpop_simulate_keygen_with_fingerprint(
            (n_receivers, threshold) in (2u32..=4).prop_flat_map(|n| (Just(n), 2u32..=n)),
            n_generators in 1u32..5,
            (bits_per_coeff, max_bits_total) in (0u8..10).prop_flat_map(|per_coeff| {
                // max_bits_total should be at least max_bits_per_coeff but can be larger
                (Just(per_coeff), per_coeff..25)
            }),
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let fingerprint = crate::frost::shared_key::Fingerprint {
                bits_per_coeff,
                tag: "test-fingerprint",
                max_bits_total,
            };

            let (shared_key, paired_shares) = encpedpop::simulate_keygen(
                &schnorr,
                threshold,
                n_receivers,
                n_generators,
                fingerprint,
                &mut rng,
            );

            for share in paired_shares {
                assert_eq!(shared_key.pair_secret_share(*share.secret_share()), Some(share));
            }

            assert!(shared_key.check_fingerprint::<sha2::Sha256>(&fingerprint), "fingerprint was grinded correctly");
        }
    }
}
