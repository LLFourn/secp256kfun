//! `certpedpop` is built on top of [`encpedpop`] to add certification of the outcome.
//!
//! At the simplepedpop and encpedpop layers, confirming every party has the same
//! [`AggKeygenInput`] is the application's problem. `certpedpop` packages it: each
//! party's verify produces a certificate signature (collected via [`Certifier`])
//! and a receiver's secret share is withheld in [`SecretShareReceiver`] until every
//! certificate is in.

pub mod certificate;
#[cfg(feature = "vrf_cert_keygen")]
pub use certificate::vrf_cert;
pub use certificate::{
    CertificateError, CertificationScheme, CertifiedKeygen, Certifier, IncompleteCertificates,
    ReceiveCertError, RecoverShareError,
};

use super::encpedpop;
pub use super::encpedpop::{AggKeygenInput, Coordinator, KeygenInput, ShareReceiverError};
pub use super::{AuxContributor, Party, Role, ShareReceiver};
use crate::{Schnorr, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, prelude::*, rand_core};

/// One party's protocol state for a `certpedpop` keygen. Construct with
/// [`gen_keygen_input`] and consume with `verify_agg_input` (the role-typed
/// method on `Contributor<ShareReceiver>` / `Contributor<AuxContributor>`),
/// which produces a self-certificate alongside the verified state.
///
/// See the [module-level docs] for `R`.
///
/// [`gen_keygen_input`]: Self::gen_keygen_input
/// [module-level docs]: super
#[derive(Clone, Debug, PartialEq)]
pub struct Contributor<R: Role> {
    inner: encpedpop::Contributor<R>,
    aux_contributor_keys: Vec<Point>,
}

impl<R: Role> Contributor<R> {
    /// Generate this contributor's keygen input.
    ///
    /// For [`ShareReceiver`], `my_role_index` is the receiver slot in
    /// `[0..receiver_keys.len())` and the contributor's `ShareIndex`
    /// is `my_role_index + 1`. For [`AuxContributor`], `my_role_index` is in
    /// `[0..aux_contributor_keys.len())`.
    pub fn gen_keygen_input<H: Hash32, NG: NonceGen>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        aux_contributor_keys: &[Point],
        receiver_keys: &[Point],
        my_role_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> Result<(Self, KeygenInput), GenKeygenInputError> {
        let aux_unique: BTreeSet<Point> = aux_contributor_keys.iter().copied().collect();
        if aux_unique.len() != aux_contributor_keys.len() {
            return Err(GenKeygenInputError::DuplicateAuxKey);
        }
        let receiver_unique: BTreeSet<Point> = receiver_keys.iter().copied().collect();
        if !aux_unique.is_disjoint(&receiver_unique) {
            return Err(GenKeygenInputError::AuxReceiverOverlap);
        }
        let n_aux_contributors =
            u32::try_from(aux_contributor_keys.len()).expect("too many aux contributors");
        let (inner, message) = encpedpop::Contributor::<R>::gen_keygen_input(
            schnorr,
            threshold,
            n_aux_contributors,
            receiver_keys,
            my_role_index,
            rng,
        )?;
        Ok((
            Self {
                inner,
                aux_contributor_keys: aux_contributor_keys.to_vec(),
            },
            message,
        ))
    }
}

impl Contributor<AuxContributor> {
    /// Verify the aggregated input and produce this aux contributor's certificate
    /// signature. The keygen is only complete once every party's signature has
    /// been collected via [`Certifier`].
    pub fn verify_agg_input<H: Hash32, NG, S: CertificationScheme>(
        self,
        pop_schnorr: &Schnorr<H, NG>,
        cert_scheme: &S,
        agg_input: AggKeygenInput,
        keypair: &KeyPair,
    ) -> Result<(VerifiedAggKeygenInput, S::Signature), VerifyAggInputError> {
        let my_aux_index = self.inner.role_index() as usize;
        let Self {
            inner,
            aux_contributor_keys,
            ..
        } = self;

        let inner_verified = inner.verify_agg_input(pop_schnorr, agg_input)?;
        let expected_cert_key = aux_contributor_keys[my_aux_index];
        if expected_cert_key != keypair.public_key() {
            return Err(VerifyAggInputError::WrongCertificationKey);
        }

        let verified = VerifiedAggKeygenInput {
            inner: inner_verified,
            aux_contributor_keys,
        };
        let sig = cert_scheme.certify(keypair, &verified);
        Ok((verified, sig))
    }
}

impl Contributor<ShareReceiver> {
    /// Verify the aggregated input, extract the secret share, and produce this
    /// receiver's certificate signature. The returned [`SecretShareReceiver`]
    /// holds the share until [`SecretShareReceiver::finalize`] runs with a
    /// complete certificate map — callers must not use the share before then.
    pub fn verify_agg_input<H: Hash32, NG, S: CertificationScheme>(
        self,
        pop_schnorr: &Schnorr<H, NG>,
        cert_scheme: &S,
        agg_input: AggKeygenInput,
        keypair: &KeyPair,
    ) -> Result<(SecretShareReceiver, S::Signature), ShareReceiverError> {
        let Self {
            inner,
            aux_contributor_keys,
            ..
        } = self;
        let (inner_verified, paired_secret_share) =
            inner.verify_agg_input(pop_schnorr, agg_input, keypair)?;
        let verified = VerifiedAggKeygenInput {
            inner: inner_verified,
            aux_contributor_keys,
        };
        let sig = cert_scheme.certify(keypair, &verified);
        Ok((
            SecretShareReceiver {
                paired_secret_share,
                verified_agg_input: verified,
            },
            sig,
        ))
    }
}

/// An [`AggKeygenInput`] that this contributor has verified and is the bytes
/// covered by certpedpop's certificate.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedAggKeygenInput {
    inner: encpedpop::VerifiedAggKeygenInput,
    aux_contributor_keys: Vec<Point>,
}

impl VerifiedAggKeygenInput {
    /// Certifying keys for contributor-only parties, in slot order.
    pub fn aux_contributor_keys(&self) -> &[Point] {
        &self.aux_contributor_keys
    }

    pub(in crate::frost::chilldkg::certpedpop) fn required_keys(&self) -> BTreeSet<Point> {
        self.aux_contributor_keys
            .iter()
            .copied()
            .chain(self.receiver_keys().map(|(_, key)| key))
            .collect()
    }

    /// `n_aux_contributors + n_receivers`.
    pub fn n_contributors(&self) -> usize {
        self.inner.n_contributors()
    }

    /// Number of contributor-only parties.
    pub fn n_aux_contributors(&self) -> usize {
        self.inner.n_aux_contributors()
    }

    /// Number of share receivers.
    pub fn n_receivers(&self) -> usize {
        self.inner.n_receivers()
    }

    /// The [`SharedKey`] this aggregated input produces.
    pub fn shared_key(&self) -> SharedKey {
        self.inner.shared_key()
    }

    /// Bytes covered by every certpedpop certificate. Extends
    /// [`encpedpop::VerifiedAggKeygenInput::cert_bytes`] with this layer's
    /// `aux_contributor_keys`, so disagreement on either keyset produces
    /// different bytes per victim and certification fails.
    pub fn cert_bytes(&self) -> Vec<u8> {
        let mut cert_bytes = self.inner.cert_bytes();
        // No length prefix needed: encpedpop commits to n_contributors and
        // n_receivers, so aux_contributor_keys.len() is fixed.
        for aux_key in &self.aux_contributor_keys {
            cert_bytes.extend(aux_key.to_bytes());
        }
        cert_bytes
    }

    /// Encryption key for every receiver, paired with its `ShareIndex`.
    pub fn receiver_keys(&self) -> impl Iterator<Item = (ShareIndex, Point)> + '_ {
        self.inner.receiver_keys()
    }

    /// Recover a receiver's share from this verified aggregate using their
    /// decryption keypair.
    pub fn recover_share<H: Hash32>(
        &self,
        share_index: ShareIndex,
        keypair: &KeyPair,
    ) -> Result<PairedSecretShare, encpedpop::RecoverShareError> {
        self.inner.recover_share::<H>(share_index, keypair)
    }
}

/// A receiver's secret share, withheld until every certifying party has signed.
/// Returned by [`Contributor::<ShareReceiver>::verify_agg_input`]; release the
/// share with [`finalize`] once you have a complete cert map.
///
/// [`finalize`]: Self::finalize
#[derive(Debug, Clone, PartialEq)]
pub struct SecretShareReceiver {
    paired_secret_share: PairedSecretShare,
    verified_agg_input: VerifiedAggKeygenInput,
}

impl SecretShareReceiver {
    /// The verified aggregated input this receiver was constructed against.
    pub fn verified_agg_input(&self) -> &VerifiedAggKeygenInput {
        &self.verified_agg_input
    }

    /// Release the secret share once `certificate` covers every certifying
    /// party (every aux contributor key plus every receiver's encryption key).
    /// Extras are rejected with [`CertificateError::Unexpected`].
    pub fn finalize<S: CertificationScheme>(
        self,
        cert_scheme: &S,
        certificate: BTreeMap<Point, S::Signature>,
    ) -> Result<(CertifiedKeygen<S::Signature>, PairedSecretShare), CertificateError> {
        let Self {
            paired_secret_share,
            verified_agg_input,
        } = self;
        let certified_keygen = CertifiedKeygen::new(cert_scheme, verified_agg_input, certificate)?;
        Ok((certified_keygen, paired_secret_share))
    }
}

/// Reasons [`Contributor::gen_keygen_input`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenKeygenInputError {
    /// `aux_contributor_keys` contained a duplicate point.
    DuplicateAuxKey,
    /// A key appeared in both `aux_contributor_keys` and `receiver_keys`.
    AuxReceiverOverlap,
    /// The underlying encrypted DKG input generation rejected the parameters.
    Inner(encpedpop::GenKeygenInputError),
}

impl From<encpedpop::GenKeygenInputError> for GenKeygenInputError {
    fn from(err: encpedpop::GenKeygenInputError) -> Self {
        GenKeygenInputError::Inner(err)
    }
}

impl core::fmt::Display for GenKeygenInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenKeygenInputError::DuplicateAuxKey => {
                write!(f, "aux_contributor_keys contained a duplicate")
            }
            GenKeygenInputError::AuxReceiverOverlap => write!(
                f,
                "a key appeared in both aux_contributor_keys and receiver_keys"
            ),
            GenKeygenInputError::Inner(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GenKeygenInputError {}

/// Errors that can occur while verifying and preparing to certify an aggregated input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyAggInputError {
    /// The underlying encrypted DKG verification failed.
    Inner(encpedpop::VerifyAggInputError),
    /// The supplied certification keypair does not belong to this contributor slot.
    WrongCertificationKey,
}

impl From<encpedpop::VerifyAggInputError> for VerifyAggInputError {
    fn from(err: encpedpop::VerifyAggInputError) -> Self {
        VerifyAggInputError::Inner(err)
    }
}

impl core::fmt::Display for VerifyAggInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyAggInputError::Inner(err) => write!(f, "{err}"),
            VerifyAggInputError::WrongCertificationKey => {
                write!(
                    f,
                    "certification keypair does not match this contributor slot"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyAggInputError {}

/// Test/example helper: run every `certpedpop` party in-process. Not for production.
///
/// Returns the [`CertifiedKeygen`] together with each receiver's paired share
/// and the keypair that decrypted it (so callers can exercise `recover_share`).
pub fn simulate_keygen<H: Hash32, NG: NonceGen, S: CertificationScheme>(
    schnorr: &Schnorr<H, NG>,
    cert_scheme: &S,
    threshold: u32,
    n_receivers: u32,
    n_aux_contributors: u32,
    fingerprint: Fingerprint,
    rng: &mut impl rand_core::RngCore,
) -> SimulatedKeygenOutput<S::Signature> {
    // Slot order: receiver-contributors at [0..n_receivers) in ascending
    // ShareIndex order (ShareIndex = slot + 1), aux contributors at
    // [n_receivers..n_receivers + n_aux).
    let receiver_keypairs: Vec<KeyPair> =
        core::iter::repeat_with(|| KeyPair::new(Scalar::random(rng)))
            .take(n_receivers as usize)
            .collect();
    let receiver_keys: Vec<Point> = receiver_keypairs.iter().map(|kp| kp.public_key()).collect();

    let aux_contributor_keys: Vec<KeyPair> =
        core::iter::repeat_with(|| KeyPair::new(Scalar::random(rng)))
            .take(n_aux_contributors as usize)
            .collect();
    let aux_contributor_public_keys: Vec<Point> = aux_contributor_keys
        .iter()
        .map(|kp| kp.public_key())
        .collect();

    let mut aggregator = Coordinator::new(threshold, n_aux_contributors, n_receivers);
    let mut receiver_contributors: Vec<(Contributor<ShareReceiver>, KeyPair)> = vec![];
    let mut aux_contributors: Vec<(Contributor<AuxContributor>, KeyPair)> = vec![];

    for receiver_idx in 0..n_receivers {
        let (contributor, msg) = Contributor::<ShareReceiver>::gen_keygen_input(
            schnorr,
            threshold,
            &aux_contributor_public_keys,
            &receiver_keys,
            receiver_idx,
            rng,
        )
        .unwrap();
        aggregator
            .add_input(schnorr, Party::Receiver(receiver_idx), msg)
            .unwrap();
        receiver_contributors.push((contributor, receiver_keypairs[receiver_idx as usize]));
    }
    for aux_idx in 0..n_aux_contributors {
        let (contributor, msg) = Contributor::<AuxContributor>::gen_keygen_input(
            schnorr,
            threshold,
            &aux_contributor_public_keys,
            &receiver_keys,
            aux_idx,
            rng,
        )
        .unwrap();
        aggregator
            .add_input(schnorr, Party::AuxContributor(aux_idx), msg)
            .unwrap();
        aux_contributors.push((contributor, aux_contributor_keys[aux_idx as usize]));
    }

    let agg_input = aggregator
        .finish_with_fingerprint::<H>(fingerprint)
        .unwrap();

    let mut share_receivers: Vec<(SecretShareReceiver, KeyPair)> = vec![];
    let mut signatures: Vec<(Point, S::Signature)> = vec![];
    let mut verified_agg_input: Option<VerifiedAggKeygenInput> = None;
    for (contributor, keypair) in receiver_contributors {
        let (receiver, sig) = contributor
            .verify_agg_input(schnorr, cert_scheme, agg_input.clone(), &keypair)
            .unwrap();
        signatures.push((keypair.public_key(), sig));
        verified_agg_input.get_or_insert_with(|| receiver.verified_agg_input().clone());
        share_receivers.push((receiver, keypair));
    }
    for (contributor, aux_keypair) in aux_contributors {
        let (verified, sig) = contributor
            .verify_agg_input(schnorr, cert_scheme, agg_input.clone(), &aux_keypair)
            .unwrap();
        signatures.push((aux_keypair.public_key(), sig));
        verified_agg_input.get_or_insert(verified);
    }
    let mut certifier = Certifier::new(
        cert_scheme.clone(),
        verified_agg_input.expect("at least one contributor"),
    );
    for (key, sig) in signatures {
        certifier.receive_certificate(key, sig).unwrap();
    }

    let certified_keygen = certifier
        .finish()
        .expect("Certifier should have all required certificates");

    let cert_map = certified_keygen.certificate().clone();
    let paired_secret_shares: Vec<(PairedSecretShare, KeyPair)> = share_receivers
        .into_iter()
        .map(|(receiver, keypair)| {
            let (receiver_certified, paired_share) = receiver
                .finalize(cert_scheme, cert_map.clone())
                .expect("simulate_keygen finalize");
            assert_eq!(receiver_certified, certified_keygen);
            (paired_share, keypair)
        })
        .collect();

    SimulatedKeygenOutput {
        certified_keygen,
        paired_shares_with_keys: paired_secret_shares,
        aux_contributor_public_keys,
    }
}

/// Output of [`simulate_keygen`].
pub struct SimulatedKeygenOutput<Sig> {
    /// Certified keygen — shared key plus every party's certificate.
    pub certified_keygen: CertifiedKeygen<Sig>,
    /// Each receiver's paired share with the keypair that decrypted it.
    pub paired_shares_with_keys: Vec<(PairedSecretShare, KeyPair)>,
    /// Public keys of the aux contributors.
    pub aux_contributor_public_keys: Vec<Point>,
}

#[cfg(test)]
mod test {
    use crate::frost::chilldkg::certpedpop;

    use super::*;
    use proptest::{
        prelude::*,
        test_runner::{RngAlgorithm, TestRng},
    };
    use secp256kfun::proptest;

    proptest! {
        #[test]
        fn certified_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_aux_contributors in 0u32..=3,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let output = certpedpop::simulate_keygen(
                &schnorr,
                &schnorr,
                threshold,
                n_receivers,
                n_aux_contributors,
                Fingerprint::NONE,
                &mut rng
            );

            CertifiedKeygen::new(
                &schnorr,
                output.certified_keygen.verified_agg_input().clone(),
                output.certified_keygen.certificate().clone(),
            )
            .expect("CertifiedKeygen should be valid");

            for (paired_secret_share, keypair) in output.paired_shares_with_keys {
                let recovered = output.certified_keygen.recover_share::<sha2::Sha256, _>(&schnorr, paired_secret_share.index(), keypair).unwrap();
                assert_eq!(paired_secret_share, recovered);
            }

            // Verify we have the expected number of VRF certificates
            assert_eq!(
                output.certified_keygen.certificate().len(),
                (n_receivers + n_aux_contributors) as usize
            );

        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "vrf_cert_keygen")]
        fn vrf_certified_keygen_randomness_beacon(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_aux_contributors in 0u32..=3,
        ) {
            use proptest::test_runner::{RngAlgorithm, TestRng};

            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let vrf_certifier = vrf_cert::VrfCertScheme::<sha2::Sha256>::new("chilldkg-vrf");
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let output = certpedpop::simulate_keygen(
                &schnorr,
                &vrf_certifier,
                threshold,
                n_receivers,
                n_aux_contributors,
                Fingerprint::NONE,
                &mut rng,
            );

            CertifiedKeygen::new(
                &vrf_certifier,
                output.certified_keygen.verified_agg_input().clone(),
                output.certified_keygen.certificate().clone(),
            )
            .expect("CertifiedKeygen should be valid");

            // Compute randomness beacon from the VRF outputs
            let randomness = output.certified_keygen.vrf_security_check(sha2::Sha256::default());

            // Verify the randomness is deterministic
            let randomness2 = output.certified_keygen.vrf_security_check(sha2::Sha256::default());
            assert_eq!(randomness, randomness2);

            // Verify we have the expected number of VRF certificates
            assert_eq!(
                output.certified_keygen.certificate().len(),
                (n_receivers + n_aux_contributors) as usize
            );
        }
    }

    fn run_input_aggregation_stage(
        threshold: u32,
        n_aux_contributors: u32,
        n_receivers: u32,
    ) -> (Vec<Contributor<AuxContributor>>, AggKeygenInput) {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let receiver_keys: Vec<Point> = (0..n_receivers)
            .map(|_| KeyPair::new(Scalar::random(&mut rng)).public_key())
            .collect();
        let aux_contributor_keys: Vec<Point> = (0..n_aux_contributors)
            .map(|_| KeyPair::new(Scalar::random(&mut rng)).public_key())
            .collect();

        let mut coordinator = Coordinator::new(threshold, n_aux_contributors, n_receivers);
        for receiver_idx in 0..n_receivers {
            let (_, msg) = Contributor::<ShareReceiver>::gen_keygen_input(
                &schnorr,
                threshold,
                &aux_contributor_keys,
                &receiver_keys,
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
            let (contributor, msg) = Contributor::<AuxContributor>::gen_keygen_input(
                &schnorr,
                threshold,
                &aux_contributor_keys,
                &receiver_keys,
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
    fn verify_agg_input_rejects_wrong_certification_key() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let (auxes, agg_input) = run_input_aggregation_stage(2, 1, 2);
        let wrong_keypair = KeyPair::new(Scalar::random(&mut rng));

        assert_eq!(
            auxes
                .into_iter()
                .next()
                .unwrap()
                .verify_agg_input(&schnorr, &schnorr, agg_input, &wrong_keypair)
                .err(),
            Some(VerifyAggInputError::WrongCertificationKey)
        );
    }

    // CertifiedKeygen::new (and SecretShareReceiver::finalize, which shares the
    // validation) must reject caller-supplied certificate maps that contain
    // entries for keys outside the expected certifying set. Otherwise the
    // extras would pollute downstream consumers (e.g. the VRF beacon).
    #[test]
    fn certified_keygen_new_rejects_unexpected_cert_entries() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let output =
            certpedpop::simulate_keygen(&schnorr, &schnorr, 2, 2, 1, Fingerprint::NONE, &mut rng);
        let verified_input = output.certified_keygen.verified_agg_input().clone();

        let mut bad_certs = output.certified_keygen.certificate().clone();
        let unrelated = KeyPair::new(Scalar::random(&mut rng));
        bad_certs.insert(
            unrelated.public_key(),
            schnorr.certify(&unrelated, &verified_input),
        );

        let result = CertifiedKeygen::new(&schnorr, verified_input, bad_certs);
        assert_eq!(
            result.err(),
            Some(CertificateError::Unexpected {
                key: unrelated.public_key()
            })
        );
    }

    // The aux contributor keys live on the contributor's verified state. Two
    // contributors who disagree on aux_contributor_keys must produce
    // different cert_bytes — that's how mutual certification fails when a
    // malicious party tries to substitute an aux key.
    #[test]
    fn cert_bytes_binds_aux_contributor_keys() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let output =
            certpedpop::simulate_keygen(&schnorr, &schnorr, 2, 2, 1, Fingerprint::NONE, &mut rng);
        let honest = output.certified_keygen.verified_agg_input().clone();

        let fake_aux = KeyPair::new(Scalar::random(&mut rng)).public_key();
        let mut tampered_aux = honest.aux_contributor_keys.clone();
        tampered_aux[0] = fake_aux;
        let tampered = VerifiedAggKeygenInput {
            inner: honest.inner.clone(),
            aux_contributor_keys: tampered_aux,
        };

        assert_ne!(
            honest.cert_bytes(),
            tampered.cert_bytes(),
            "cert_bytes must bind aux_contributor_keys"
        );
    }

    // Duplicate aux keys would let the same party play multiple aux roles;
    // an aux key that's also a receiver-encryption key would silently merge
    // the two roles. gen_keygen_input must reject either up front (honest
    // random keys collide with negligible probability).
    #[test]
    fn gen_keygen_input_rejects_invalid_keysets() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let a = KeyPair::new(Scalar::random(&mut rng)).public_key();
        let b = KeyPair::new(Scalar::random(&mut rng)).public_key();

        for (name, aux, receivers, expected) in [
            (
                "duplicate aux",
                &[a, a][..],
                &[b][..],
                GenKeygenInputError::DuplicateAuxKey,
            ),
            (
                "aux/receiver overlap",
                &[a][..],
                &[a, b][..],
                GenKeygenInputError::AuxReceiverOverlap,
            ),
        ] {
            let result = Contributor::<ShareReceiver>::gen_keygen_input(
                &schnorr, 1, aux, receivers, 0, &mut rng,
            );
            assert_eq!(result.err(), Some(expected), "{name}");
        }
    }
}
