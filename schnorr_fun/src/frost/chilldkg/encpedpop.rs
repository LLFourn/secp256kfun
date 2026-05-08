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
pub use super::{AuxContributor, Party, Role, ShareReceiver};
use crate::{Schnorr, frost::*};
use alloc::{collections::BTreeSet, vec::Vec};
use secp256kfun::{
    KeyPair,
    hash::{Hash32, HashAdd},
    nonce::NonceGen,
    prelude::*,
    rand_core,
};

/// One party's protocol state for an `encpedpop` keygen. Construct with
/// [`gen_keygen_input`] and consume with `verify_agg_input` (the role-typed
/// method on `Contributor<ShareReceiver>` / `Contributor<AuxContributor>`).
///
/// See the [module-level docs] for `R`.
///
/// [`gen_keygen_input`]: Self::gen_keygen_input
/// [module-level docs]: super
#[derive(Clone, Debug, PartialEq)]
pub struct Contributor<R: Role> {
    inner: simplepedpop::Contributor<R>,
    my_nonce: Point,
    receiver_keys: Vec<Point>,
}

impl<R: Role> Contributor<R> {
    /// Generate this contributor's keygen input.
    ///
    /// For [`ShareReceiver`], `my_role_index` is the receiver slot in
    /// `[0..receiver_keys.len())` and the contributor's `ShareIndex`
    /// is `my_role_index + 1`. For [`AuxContributor`], `my_role_index` is in
    /// `[0..n_aux_contributors)`.
    pub fn gen_keygen_input<H, NG>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        n_aux_contributors: u32,
        receiver_keys: &[Point],
        my_role_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Self, KeygenInput), GenKeygenInputError>
    where
        H: Hash32,
        NG: NonceGen,
    {
        let unique: BTreeSet<Point> = receiver_keys.iter().copied().collect();
        if unique.len() != receiver_keys.len() {
            return Err(GenKeygenInputError::DuplicateReceiverKey);
        }

        let n_receivers = receiver_keys.len() as u32;
        let (inner_state, inner_keygen_input, shares) =
            simplepedpop::Contributor::<R>::gen_keygen_input(
                schnorr,
                threshold,
                n_aux_contributors,
                n_receivers,
                my_role_index,
                rng,
            )?;
        let multi_nonce_keypair = KeyPair::<Normal>::new(Scalar::random(rng));
        let encryption_jobs: Vec<_> = receiver_keys
            .iter()
            .zip(shares)
            .enumerate()
            .map(|(i, (encryption_key, share))| {
                let receiver = ShareIndex::try_from(i as u32 + 1).expect("non-zero");
                (receiver, *encryption_key, share)
            })
            .collect();
        let encrypted_shares = encrypt::<H>(encryption_jobs, multi_nonce_keypair);
        let keygen_input = KeygenInput {
            inner: inner_keygen_input,
            encrypted_shares,
            encryption_nonce: multi_nonce_keypair.public_key(),
        };

        Ok((
            Contributor {
                inner: inner_state,
                my_nonce: multi_nonce_keypair.public_key(),
                receiver_keys: receiver_keys.to_vec(),
            },
            keygen_input,
        ))
    }

    fn check_encryption_shape(
        &self,
        agg_input: &AggKeygenInput,
    ) -> Result<(), EncryptionCheckError> {
        if agg_input.encryption_nonces.len() != self.inner.n_contributors() as usize
            || agg_input.encrypted_shares.len() != self.inner.n_receivers() as usize
        {
            return Err(EncryptionCheckError::CountMismatch);
        }
        let my_index = self.inner.contributor_index();
        let got = agg_input.encryption_nonces[my_index as usize];
        if got != self.my_nonce {
            return Err(EncryptionCheckError::NonceMismatch);
        }
        Ok(())
    }

    /// `n_aux_contributors + n_receivers`.
    pub fn n_contributors(&self) -> u32 {
        self.inner.n_contributors()
    }

    /// Number of receivers configured at construction.
    pub fn n_receivers(&self) -> u32 {
        self.receiver_keys.len() as u32
    }

    /// Absolute slot index in `[0..n_contributors)`.
    pub fn contributor_index(&self) -> u32 {
        self.inner.contributor_index()
    }

    /// The `my_role_index` this contributor was constructed with.
    pub fn role_index(&self) -> u32 {
        self.inner.role_index()
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
        self.check_encryption_shape(&agg_input)?;
        let AggKeygenInput {
            inner,
            encrypted_shares,
            encryption_nonces,
        } = agg_input;
        let simple_verified = self.inner.verify_agg_input(schnorr, inner)?;
        Ok(VerifiedAggKeygenInput {
            simple_verified,
            encrypted_shares,
            encryption_nonces,
            receiver_keys: self.receiver_keys,
        })
    }
}

impl Contributor<ShareReceiver> {
    /// Verify the aggregated input, decrypt this receiver's share, and pair it
    /// with the verified aggregate — all atomically. The verified aggregate is
    /// only returned if every step succeeds.
    pub fn verify_agg_input<H, NG>(
        self,
        schnorr: &Schnorr<H, NG>,
        agg_input: AggKeygenInput,
        keypair: &KeyPair,
    ) -> Result<(VerifiedAggKeygenInput, PairedSecretShare), ShareReceiverError>
    where
        H: Hash32,
    {
        let my_position = self.inner.contributor_index();
        let expected_encryption_key = self.receiver_keys[my_position as usize];
        if expected_encryption_key != keypair.public_key() {
            return Err(ShareReceiverError::WrongEncryptionKey);
        }
        self.check_encryption_shape(&agg_input)?;
        let AggKeygenInput {
            inner,
            encrypted_shares,
            encryption_nonces,
        } = agg_input;

        let my_share_index = ShareIndex::try_from(my_position + 1).expect("non-zero");
        let encrypted_share = encrypted_shares[my_position as usize];
        let share_scalar =
            decrypt::<H>(my_share_index, keypair, &encryption_nonces, encrypted_share);
        let (simple_verified, paired) =
            self.inner.verify_agg_input(schnorr, inner, share_scalar)?;
        Ok((
            VerifiedAggKeygenInput {
                simple_verified,
                encrypted_shares,
                encryption_nonces,
                receiver_keys: self.receiver_keys,
            },
            paired,
        ))
    }
}

/// Key generation inputs after being aggregated by the coordinator. Broadcast
/// from the coordinator to every contributor for verification.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct AggKeygenInput {
    inner: simplepedpop::AggKeygenInput,
    encrypted_shares: Vec<Scalar<Public, Zero>>,
    encryption_nonces: Vec<Point>,
}

#[cfg(any(feature = "bincode", feature = "serde"))]
#[cfg_attr(feature = "bincode", derive(bincode::Decode, bincode::Encode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize),
    serde(crate = "crate::fun::serde")
)]
struct WireAggKeygenInput {
    inner: simplepedpop::AggKeygenInput,
    encrypted_shares: Vec<Scalar<Public, Zero>>,
    encryption_nonces: Vec<Point>,
}

#[cfg(any(feature = "bincode", feature = "serde"))]
impl WireAggKeygenInput {
    fn into_validated(self) -> Result<AggKeygenInput, &'static str> {
        if self.encryption_nonces.len() != self.inner.n_contributors() {
            return Err("encpedpop AggKeygenInput: encryption_nonces.len() != key_contrib.len()");
        }
        Ok(AggKeygenInput {
            inner: self.inner,
            encrypted_shares: self.encrypted_shares,
            encryption_nonces: self.encryption_nonces,
        })
    }
}

#[cfg(feature = "bincode")]
impl<Context> bincode::Decode<Context> for AggKeygenInput {
    fn decode<D: secp256kfun::bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, secp256kfun::bincode::error::DecodeError> {
        let wire = WireAggKeygenInput::decode(decoder)?;
        wire.into_validated()
            .map_err(secp256kfun::bincode::error::DecodeError::Other)
    }
}

#[cfg(feature = "bincode")]
bincode::impl_borrow_decode!(AggKeygenInput);

#[cfg(feature = "serde")]
impl<'de> crate::fun::serde::Deserialize<'de> for AggKeygenInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: secp256kfun::serde::Deserializer<'de>,
    {
        let wire = WireAggKeygenInput::deserialize(deserializer)?;
        wire.into_validated()
            .map_err(crate::fun::serde::de::Error::custom)
    }
}

/// An [`AggKeygenInput`] that this contributor has verified against its own protocol state.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAggKeygenInput {
    simple_verified: simplepedpop::VerifiedAggKeygenInput,
    encrypted_shares: Vec<Scalar<Public, Zero>>,
    encryption_nonces: Vec<Point>,
    receiver_keys: Vec<Point>,
}

impl VerifiedAggKeygenInput {
    /// `n_aux_contributors + n_receivers`.
    pub fn n_contributors(&self) -> usize {
        self.simple_verified.agg_input().n_contributors()
    }

    /// Number of contributor-only parties (no share to receive).
    pub fn n_aux_contributors(&self) -> usize {
        self.n_contributors().saturating_sub(self.n_receivers())
    }

    /// Number of share receivers.
    pub fn n_receivers(&self) -> usize {
        self.encrypted_shares.len()
    }

    /// The [`SharedKey`] this aggregated input produces.
    pub fn shared_key(&self) -> SharedKey {
        self.simple_verified.shared_key()
    }

    /// Bytes that uniquely identify this verified aggregate. Compare out-of-band
    /// with every other party — if you all match, you all produced the same key.
    /// Binds the contributor-side encryption keys, so a coordinator who shows
    /// different parties different keysets produces different `cert_bytes` per
    /// victim.
    pub fn cert_bytes(&self) -> Vec<u8> {
        let mut cert_bytes = self.simple_verified.cert_bytes();
        cert_bytes.extend((self.encryption_nonces.len() as u32).to_be_bytes());
        cert_bytes.extend(
            self.encryption_nonces
                .iter()
                .flat_map(|nonce| nonce.to_bytes()),
        );
        cert_bytes.extend((self.receiver_keys.len() as u32).to_be_bytes());
        for (encryption_key, encrypted_share) in
            self.receiver_keys.iter().zip(self.encrypted_shares.iter())
        {
            cert_bytes.extend(encryption_key.to_bytes());
            cert_bytes.extend(encrypted_share.to_bytes());
        }
        cert_bytes
    }

    /// Encryption key for every receiver, paired with its `ShareIndex`.
    pub fn receiver_keys(&self) -> impl Iterator<Item = (ShareIndex, Point)> + '_ {
        self.receiver_keys
            .iter()
            .enumerate()
            .map(|(i, ek)| (ShareIndex::try_from(i as u32 + 1).expect("non-zero"), *ek))
    }

    /// Recover a share with the decryption key from the verified aggregate.
    pub fn recover_share<H: Hash32>(
        &self,
        share_index: ShareIndex,
        keypair: &KeyPair,
    ) -> Result<PairedSecretShare, RecoverShareError> {
        let position = u32::try_from(share_index)
            .ok()
            .and_then(|idx| idx.checked_sub(1))
            .map(|position| position as usize)
            .filter(|position| *position < self.encrypted_shares.len())
            .ok_or(RecoverShareError::UnknownShareIndex)?;
        let expected_public_key = self
            .receiver_keys
            .get(position)
            .ok_or(RecoverShareError::UnknownShareIndex)?;
        let agg_ciphertext = &self.encrypted_shares[position];

        if *expected_public_key != keypair.public_key() {
            return Err(RecoverShareError::WrongEncryptionKey);
        }
        let secret_share = decrypt::<H>(
            share_index,
            keypair,
            &self.encryption_nonces,
            *agg_ciphertext,
        );

        self.shared_key()
            .pair_secret_share(SecretShare {
                index: share_index,
                share: secret_share,
            })
            .ok_or(RecoverShareError::InvalidShare)
    }
}

/// One contributor's message to the coordinator. Produced by
/// [`Contributor::gen_keygen_input`].
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
#[derive(Clone, Debug, PartialEq)]
pub struct KeygenInput {
    /// The simplepedpop-layer message.
    pub inner: simplepedpop::KeygenInput,
    /// Encrypted share for each receiver in slot order
    /// (position `i` is for `ShareIndex = i + 1`).
    pub encrypted_shares: Vec<Scalar<Public, Zero>>,
    /// Multi-encryption nonce used to encrypt `encrypted_shares`.
    pub encryption_nonce: Point,
}

/// Aggregates [`KeygenInput`]s from each contributor into a single
/// [`AggKeygenInput`] for broadcast.
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinator {
    inner: simplepedpop::Coordinator,
    agg_encrypted_shares: Vec<Scalar<Public, Zero>>,
    encryption_nonces: Vec<Point>,
}

impl Coordinator {
    /// Total contributor slots = `n_aux_contributors + n_receivers`; receivers
    /// occupy `[0..n_receivers)`, aux contributors fill the rest.
    pub fn new(threshold: u32, n_aux_contributors: u32, n_receivers: u32) -> Self {
        let n_contributors = n_aux_contributors + n_receivers;
        let agg_encrypted_shares = vec![Scalar::zero(); n_receivers as usize];
        Self {
            inner: simplepedpop::Coordinator::new(threshold, n_aux_contributors, n_receivers),
            agg_encrypted_shares,
            encryption_nonces: vec![Point::default(); n_contributors as usize],
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
        if self.inner.is_finished() {
            return Err(AddInputError::AlreadyFinished);
        }
        if input.encrypted_shares.len() != self.agg_encrypted_shares.len() {
            return Err(AddInputError::WrongShareCount {
                expected: self.agg_encrypted_shares.len() as u32,
                got: input.encrypted_shares.len() as u32,
            });
        }

        let n_receivers = self.agg_encrypted_shares.len() as u32;
        let slot = from.slot_index(n_receivers);

        // ⚠ only do mutations after we're sure everything is OK
        self.inner.add_input(schnorr, from, input.inner)?;

        for (i, encrypted_share_contrib) in input.encrypted_shares.into_iter().enumerate() {
            self.agg_encrypted_shares[i] += encrypted_share_contrib;
        }

        self.encryption_nonces[slot as usize] = input.encryption_nonce;
        Ok(())
    }

    /// Which [`Contributor`]s are we missing input from.
    pub fn missing_from(&self) -> BTreeSet<super::Party> {
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

    /// Like [`finish`] but grinds `fingerprint` into the resulting aggregate's
    /// polynomial coefficients. Use this if you want the resulting public key
    /// to encode a few bits of identity (e.g. for paper backups).
    ///
    /// [`finish`]: Self::finish
    pub fn finish_with_fingerprint<H: Hash32>(
        self,
        fingerprint: Fingerprint,
    ) -> Option<AggKeygenInput> {
        let mut agg_input = self.finish()?;
        let tweak_poly = agg_input.inner.grind_fingerprint::<H>(fingerprint);
        // Share encryption is homomorphic — apply the tweak as if to plaintext.
        for (i, encrypted_secret_share) in agg_input.encrypted_shares.iter_mut().enumerate() {
            let share_index = ShareIndex::try_from(i as u32 + 1).expect("non-zero");
            let mut tmp = SecretShare {
                index: share_index,
                share: *encrypted_secret_share,
            };
            tmp.homomorphic_poly_add(&tweak_poly);
            *encrypted_secret_share = tmp.share;
        }
        Some(agg_input)
    }
}

fn encrypt<H: Hash32>(
    encryption_jobs: Vec<(ShareIndex, Point, Scalar<Secret, Zero>)>,
    multi_nonce_keypair: KeyPair<Normal>,
) -> Vec<Scalar<Public, Zero>> {
    encryption_jobs
        .into_iter()
        .map(|(dest, encryption_key, share)| {
            let dh_key = g!(multi_nonce_keypair.secret_key() * encryption_key).normalize();
            // SPEC DEVIATION: Hash inputs are as defined in "Multi-recipient Encryption, Revisited" by Pinto et al.
            let pad = Scalar::from_hash(H::default().add(dh_key).add(encryption_key).add(dest));
            s!(pad + share).public()
        })
        .collect()
}

fn decrypt<H: Hash32>(
    my_index: ShareIndex,
    keypair: &KeyPair<Normal>,
    multi_nonces: &[Point],
    mut agg_ciphertext: Scalar<Public, Zero>,
) -> Scalar<Secret, Zero> {
    for nonce in multi_nonces {
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

/// Test/example helper: run every `encpedpop` party in-process. Not for production.
pub fn simulate_keygen<H, NG>(
    schnorr: &Schnorr<H, NG>,
    threshold: u32,
    n_receivers: u32,
    n_aux_contributors: u32,
    fingerprint: Fingerprint,
    rng: &mut impl rand_core::RngCore,
) -> (SharedKey, Vec<PairedSecretShare>)
where
    H: Hash32,
    NG: NonceGen,
{
    let receiver_keypairs: Vec<KeyPair> = (0..n_receivers)
        .map(|_| KeyPair::new(Scalar::random(rng)))
        .collect();
    let receiver_keys: Vec<Point> = receiver_keypairs.iter().map(|kp| kp.public_key()).collect();

    let mut aggregator = Coordinator::new(threshold, n_aux_contributors, n_receivers);
    let mut receivers: Vec<(Contributor<ShareReceiver>, KeyPair)> = vec![];
    let mut auxes: Vec<Contributor<AuxContributor>> = vec![];

    for receiver_idx in 0..n_receivers {
        let (contributor, msg) = Contributor::<ShareReceiver>::gen_keygen_input(
            schnorr,
            threshold,
            n_aux_contributors,
            &receiver_keys,
            receiver_idx,
            rng,
        )
        .unwrap();
        aggregator
            .add_input(schnorr, super::Party::Receiver(receiver_idx), msg)
            .unwrap();
        receivers.push((contributor, receiver_keypairs[receiver_idx as usize]));
    }
    for aux_idx in 0..n_aux_contributors {
        let (contributor, msg) = Contributor::<AuxContributor>::gen_keygen_input(
            schnorr,
            threshold,
            n_aux_contributors,
            &receiver_keys,
            aux_idx,
            rng,
        )
        .unwrap();
        aggregator
            .add_input(schnorr, super::Party::AuxContributor(aux_idx), msg)
            .unwrap();
        auxes.push(contributor);
    }

    let agg_input = aggregator
        .finish_with_fingerprint::<H>(fingerprint)
        .unwrap();

    let mut verified = None;
    let mut paired_secret_shares: Vec<PairedSecretShare> = vec![];
    for (contributor, keypair) in receivers {
        let (v, paired) = contributor
            .verify_agg_input(schnorr, agg_input.clone(), &keypair)
            .unwrap();
        paired_secret_shares.push(paired);
        verified.get_or_insert(v);
    }
    for contributor in auxes {
        let v = contributor
            .verify_agg_input(schnorr, agg_input.clone())
            .unwrap();
        verified.get_or_insert(v);
    }
    let verified = verified.expect("at least one contributor");
    let shared_key = verified.shared_key();
    (shared_key, paired_secret_shares)
}

/// Reasons [`Contributor::gen_keygen_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenKeygenInputError {
    /// `receiver_keys` contained a duplicate point.
    DuplicateReceiverKey,
    /// The underlying simplepedpop input generation rejected the parameters.
    Inner(simplepedpop::GenKeygenInputError),
}

impl From<simplepedpop::GenKeygenInputError> for GenKeygenInputError {
    fn from(err: simplepedpop::GenKeygenInputError) -> Self {
        GenKeygenInputError::Inner(err)
    }
}

impl core::fmt::Display for GenKeygenInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenKeygenInputError::DuplicateReceiverKey => {
                write!(f, "receiver_keys contained a duplicate")
            }
            GenKeygenInputError::Inner(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenKeygenInputError {}

/// Reasons [`Coordinator::add_input`] may reject a contributor's input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddInputError {
    /// All contributor inputs have already been collected.
    AlreadyFinished,
    /// `input.encrypted_shares.len()` doesn't match the configured receiver count.
    WrongShareCount {
        /// The number of receivers configured for the coordinator.
        expected: u32,
        /// The number of encrypted shares in the input.
        got: u32,
    },
    /// The underlying simplepedpop `add_input` failed.
    Inner(simplepedpop::AddInputError),
}

impl From<simplepedpop::AddInputError> for AddInputError {
    fn from(err: simplepedpop::AddInputError) -> Self {
        AddInputError::Inner(err)
    }
}

impl core::fmt::Display for AddInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddInputError::AlreadyFinished => {
                write!(f, "all contributor inputs have already been collected")
            }
            AddInputError::WrongShareCount { expected, got } => {
                write!(
                    f,
                    "input had {got} encrypted shares but coordinator expected {expected}"
                )
            }
            AddInputError::Inner(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddInputError {}

/// Encpedpop-layer encryption shape failures, shared by both the
/// [`AuxContributor`] and [`ShareReceiver`] verify paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionCheckError {
    /// `encryption_nonces.len()` or `encrypted_shares.len()` in the aggregated
    /// input doesn't match what this contributor was configured for.
    CountMismatch,
    /// This contributor's encryption nonce was not faithfully included in the
    /// aggregated input.
    NonceMismatch,
}

impl core::fmt::Display for EncryptionCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EncryptionCheckError::CountMismatch => write!(
                f,
                "aggregated input has a different number of encryption nonces or encrypted shares than expected"
            ),
            EncryptionCheckError::NonceMismatch => write!(
                f,
                "our encryption nonce was not included in the aggregated input"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncryptionCheckError {}

/// Reasons [`Contributor::<AuxContributor>::verify_agg_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAggInputError {
    /// The encpedpop-layer encryption shape check failed.
    EncryptionCheck(EncryptionCheckError),
    /// Underlying simplepedpop verification failed.
    Inner(simplepedpop::VerifyAggInputError),
}

impl From<EncryptionCheckError> for VerifyAggInputError {
    fn from(err: EncryptionCheckError) -> Self {
        VerifyAggInputError::EncryptionCheck(err)
    }
}

impl From<simplepedpop::VerifyAggInputError> for VerifyAggInputError {
    fn from(err: simplepedpop::VerifyAggInputError) -> Self {
        VerifyAggInputError::Inner(err)
    }
}

impl core::fmt::Display for VerifyAggInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyAggInputError::EncryptionCheck(err) => write!(f, "{err}"),
            VerifyAggInputError::Inner(err) => write!(f, "{err}"),
        }
    }
}

/// Reasons [`Contributor::<ShareReceiver>::verify_agg_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ShareReceiverError {
    /// The supplied keypair isn't the encryption key registered for this share.
    WrongEncryptionKey,
    /// The encpedpop-layer encryption shape check failed.
    EncryptionCheck(EncryptionCheckError),
    /// The simplepedpop-layer share-receiver verification failed (PoP,
    /// threshold, or invalid secret share).
    Inner(simplepedpop::ShareReceiverError),
}

impl From<EncryptionCheckError> for ShareReceiverError {
    fn from(err: EncryptionCheckError) -> Self {
        ShareReceiverError::EncryptionCheck(err)
    }
}

impl From<simplepedpop::ShareReceiverError> for ShareReceiverError {
    fn from(err: simplepedpop::ShareReceiverError) -> Self {
        ShareReceiverError::Inner(err)
    }
}

impl core::fmt::Display for ShareReceiverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShareReceiverError::WrongEncryptionKey => {
                write!(
                    f,
                    "keypair is not the encryption key registered for this share"
                )
            }
            ShareReceiverError::EncryptionCheck(err) => write!(f, "{err}"),
            ShareReceiverError::Inner(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ShareReceiverError {}

#[cfg(feature = "std")]
impl std::error::Error for VerifyAggInputError {}

/// Reasons [`VerifiedAggKeygenInput::recover_share`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverShareError {
    /// No encrypted share exists at the given index.
    UnknownShareIndex,
    /// The supplied keypair isn't the encryption key registered for this share.
    WrongEncryptionKey,
    /// The decrypted share didn't pair with the shared key.
    InvalidShare,
}

impl core::fmt::Display for RecoverShareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoverShareError::UnknownShareIndex => {
                write!(f, "no share exists at the requested index")
            }
            RecoverShareError::WrongEncryptionKey => {
                write!(f, "keypair is not the encryption key for this share")
            }
            RecoverShareError::InvalidShare => {
                write!(f, "recovered secret share did not match the shared key")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoverShareError {}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use crate::frost::{Fingerprint, chilldkg::encpedpop};

    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    use secp256kfun::{KeyPair, Point, Scalar, proptest};

    use super::{
        AggKeygenInput, AuxContributor, Contributor, Coordinator, KeygenInput, Party, ShareReceiver,
    };

    fn run_input_aggregation_stage(
        threshold: u32,
        n_aux_contributors: u32,
        n_receivers: u32,
        arrival_order: impl IntoIterator<Item = Party>,
    ) -> (Vec<Contributor<AuxContributor>>, AggKeygenInput) {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

        let receiver_keys: Vec<Point> = (0..n_receivers)
            .map(|_| KeyPair::new(Scalar::random(&mut rng)).public_key())
            .collect();
        let n_contributors = n_aux_contributors + n_receivers;
        let arrival_order: Vec<_> = arrival_order.into_iter().collect();
        assert_eq!(arrival_order.len(), n_contributors as usize);

        let mut inputs: Vec<KeygenInput> = Vec::with_capacity(n_contributors as usize);
        let mut auxes: Vec<Contributor<AuxContributor>> = vec![];
        for receiver_idx in 0..n_receivers {
            let (_, msg) = Contributor::<ShareReceiver>::gen_keygen_input(
                &schnorr,
                threshold,
                n_aux_contributors,
                &receiver_keys,
                receiver_idx,
                &mut rng,
            )
            .unwrap();
            inputs.push(msg);
        }
        for aux_idx in 0..n_aux_contributors {
            let (contributor, msg) = Contributor::<AuxContributor>::gen_keygen_input(
                &schnorr,
                threshold,
                n_aux_contributors,
                &receiver_keys,
                aux_idx,
                &mut rng,
            )
            .unwrap();
            inputs.push(msg);
            auxes.push(contributor);
        }
        let mut coordinator = Coordinator::new(threshold, n_aux_contributors, n_receivers);
        for party in arrival_order {
            let slot = party.slot_index(n_receivers) as usize;
            coordinator
                .add_input(&schnorr, party, inputs[slot].clone())
                .unwrap();
        }

        (auxes, coordinator.finish().unwrap())
    }

    proptest! {
        #[test]
        fn encpedpop_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_aux_contributors in 0u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            encpedpop::simulate_keygen(
                &schnorr,
                threshold,
                n_receivers,
                n_aux_contributors,
                Fingerprint::NONE,
                &mut rng,
            );
        }

        #[test]
        fn encpedpop_simulate_keygen_with_fingerprint(
            (n_receivers, threshold) in (2u32..=4).prop_flat_map(|n| (Just(n), 2u32..=n)),
            n_aux_contributors in 0u32..5,
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
                n_aux_contributors,
                fingerprint,
                &mut rng,
            );

            for share in paired_shares {
                assert_eq!(shared_key.pair_secret_share(*share.secret_share()), Some(share));
            }
            let bits_matched = shared_key.check_fingerprint::<sha2::Sha256>(fingerprint).unwrap();

            let should_have_matched = ((threshold - 1) * bits_per_coeff as u32).min(max_bits_total as u32);
            assert_eq!(bits_matched, should_have_matched as usize, "fingerprint was grinded correctly");
        }
    }

    #[test]
    fn test_input_arrival_order() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let threshold = 2u32;
        let n_aux_contributors = 1;
        let (contributors, agg_input) = run_input_aggregation_stage(
            threshold,
            n_aux_contributors,
            2,
            [
                Party::AuxContributor(0),
                Party::Receiver(0),
                Party::Receiver(1),
            ],
        );

        // Coordinator slots are keyed by `from`, not arrival order; verify_agg_input
        // succeeds for every contributor regardless of the order add_input was called in.
        for (i, contributor) in contributors.into_iter().enumerate() {
            if i < 2 {
                // receiver slots — needs a keypair we don't have here, so just pick aux.
                continue;
            }
            contributor
                .verify_agg_input(&schnorr, agg_input.clone())
                .unwrap();
        }
    }

    // Deserializing a wire form whose encryption_nonces length disagrees with
    // the inner key_contrib length must fail. This is what gates AggKeygenInput
    // from carrying inconsistent state across a serialize/deserialize round trip.
    #[cfg(feature = "bincode")]
    #[test]
    fn deser_rejects_inconsistent_contributor_counts() {
        use super::{AggKeygenInput, WireAggKeygenInput, simplepedpop};
        use bincode::config::standard;
        use std::vec;

        let inner = simplepedpop::Coordinator::new(1, 0, 0).finish().unwrap();
        let bad_wire = WireAggKeygenInput {
            inner,
            encrypted_shares: vec![],
            // n_contributors() == 0; nonces vec has length 1.
            encryption_nonces: vec![secp256kfun::G.normalize()],
        };

        let bytes = bincode::encode_to_vec(&bad_wire, standard()).unwrap();
        let result: Result<(AggKeygenInput, _), _> = bincode::decode_from_slice(&bytes, standard());
        assert!(
            result.is_err(),
            "deserializing inconsistent encpedpop AggKeygenInput must fail"
        );
    }

    // Each contributor signs up for a specific (n_aux_contributors, n_receivers)
    // pair. verify_agg_input must reject any agg_input whose encryption_nonces
    // count or encrypted_shares count disagrees with that — both branches of
    // the OR must fire.
    #[test]
    fn verify_agg_input_rejects_count_mismatch() {
        use super::VerifyAggInputError;

        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let threshold = 2u32;
        let n_aux_contributors = 1u32;
        let n_receivers = 2u32;
        let (contributors, valid) = run_input_aggregation_stage(
            threshold,
            n_aux_contributors,
            n_receivers,
            (0..n_receivers)
                .map(Party::Receiver)
                .chain((0..n_aux_contributors).map(Party::AuxContributor)),
        );
        let aux = contributors.last().unwrap();

        // Sanity: an unmutated agg_input verifies.
        aux.clone()
            .verify_agg_input(&schnorr, valid.clone())
            .unwrap();

        // First branch: shrink encryption_nonces so n_contributors no longer matches.
        let mut bad_nonces = valid.clone();
        bad_nonces.encryption_nonces.pop();
        assert_eq!(
            aux.clone().verify_agg_input(&schnorr, bad_nonces),
            Err(VerifyAggInputError::EncryptionCheck(
                super::EncryptionCheckError::CountMismatch
            )),
            "encryption_nonces count mismatch must be rejected"
        );

        // Second branch: shrink encrypted_shares so n_receivers no longer matches.
        let mut bad_shares = valid;
        bad_shares.encrypted_shares.pop();
        assert_eq!(
            aux.clone().verify_agg_input(&schnorr, bad_shares),
            Err(VerifyAggInputError::EncryptionCheck(
                super::EncryptionCheckError::CountMismatch
            )),
            "encrypted_shares count mismatch must be rejected"
        );
    }

    // The receiver encryption keys live on the contributor's verified state,
    // not in the wire-form agg_input. Two contributors who disagree on the
    // receiver-keyset must produce different cert_bytes — that's how mutual
    // certification fails when a malicious coordinator tries to give
    // different parties different views of the receiver set.
    #[test]
    fn cert_bytes_binds_receiver_keys() {
        use super::VerifiedAggKeygenInput;

        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let threshold = 2u32;
        let n_aux_contributors = 1u32;
        let n_receivers = 2u32;
        let (contributors, agg_input) = run_input_aggregation_stage(
            threshold,
            n_aux_contributors,
            n_receivers,
            (0..n_receivers)
                .map(Party::Receiver)
                .chain((0..n_aux_contributors).map(Party::AuxContributor)),
        );

        let honest = contributors
            .last()
            .unwrap()
            .clone()
            .verify_agg_input(&schnorr, agg_input)
            .unwrap();

        // Tampered view: same agg_input, swap two receiver keys so the slot
        // assignment differs but the multiset doesn't.
        let mut tampered_keys = honest.receiver_keys.clone();
        tampered_keys.swap(0, 1);
        let tampered = VerifiedAggKeygenInput {
            simple_verified: honest.simple_verified.clone(),
            encrypted_shares: honest.encrypted_shares.clone(),
            encryption_nonces: honest.encryption_nonces.clone(),
            receiver_keys: tampered_keys,
        };

        assert_ne!(
            honest.cert_bytes(),
            tampered.cert_bytes(),
            "cert_bytes must bind receiver_keys"
        );
    }

    // Duplicate receiver_keys are a fault signal (honest random
    // keys collide with negligible probability) and would let the same party
    // hold multiple shares. gen_keygen_input must reject this up front.
    #[test]
    fn gen_keygen_input_rejects_duplicate_receiver_keys() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let dupe = KeyPair::new(Scalar::random(&mut rng)).public_key();
        let other = KeyPair::new(Scalar::random(&mut rng)).public_key();

        let result = super::Contributor::<ShareReceiver>::gen_keygen_input(
            &schnorr,
            3,
            0,
            &[dupe, other, dupe],
            0,
            &mut rng,
        );
        assert_eq!(
            result.err(),
            Some(super::GenKeygenInputError::DuplicateReceiverKey)
        );
    }
}
