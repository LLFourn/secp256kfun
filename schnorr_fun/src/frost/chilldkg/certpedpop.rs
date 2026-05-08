//! `certpedpop` is built on top of [`encpedpop`] to add certification of the outcome.
//!
//! In [`encpedpop`] and [`simplepedpop`] it's left up to the application to figure out whether all
//! the parties agree on the `AggKeygenInput`. In `certpedpop` the relevant methods return
//! certification signatures on `AggKeygenInput` once they've been validated so they can be
//! collected by the share receivers. Once the share receivers have got all the certificates they
//! can finally output the key.
//!
//! Certificates are collected from other share receivers as well as `Contributor`s.

pub mod certificate;
#[cfg(feature = "vrf_cert_keygen")]
pub use certificate::vrf_cert;
pub use certificate::{
    CertificateError, CertificationScheme, CertifiedKeygen, Certifier, CertifierError,
    RecoverShareError,
};

use super::{encpedpop, simplepedpop};
use crate::{Schnorr, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, prelude::*, rand_core};

/// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
/// `Contributor` to the *coordinator*.
pub type KeygenInput = encpedpop::KeygenInput;
/// Key generation inputs after being aggregated by the coordinator
pub type AggKeygenInput = encpedpop::AggKeygenInput;

pub use encpedpop::Coordinator;

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
    inner: encpedpop::Contributor,
}

impl Contributor {
    /// Generates the keygen input for a party at `my_index`. Note that `my_index`
    /// has nothing to do with the "receiver" index (the `ShareIndex` of share receivers). If
    /// there are `n` `KeyGenInputParty`s then each party must be assigned an index from `0` to `n-1`.
    ///
    /// This method return `Self` to retain the state of the protocol which is needded to verify
    /// the aggregated input later on.
    pub fn gen_keygen_input<H: Hash32, NG: NonceGen>(
        schnorr: &Schnorr<H, NG>,
        threshold: u32,
        n_contributors: u32,
        receiver_encryption_keys: &BTreeMap<ShareIndex, Point>,
        my_index: u32,
        rng: &mut impl rand_core::RngCore,
    ) -> (Self, KeygenInput) {
        let (inner, message) = encpedpop::Contributor::gen_keygen_input(
            schnorr,
            threshold,
            n_contributors,
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
    pub fn verify_agg_input<S: CertificationScheme>(
        self,
        cert_scheme: &S,
        agg_keygen_input: &AggKeygenInput,
        cert_keypair: &KeyPair,
    ) -> Result<S::Signature, simplepedpop::ContributionDidntMatch> {
        self.inner.verify_agg_input(agg_keygen_input)?;
        let sig = cert_scheme.certify(cert_keypair, agg_keygen_input);
        Ok(sig)
    }

    /// For parties that are both contributors and receivers: verify contribution,
    /// receive secret share, and certify with a single keypair.
    ///
    /// This method is used when a party acts as both a contributor (providing entropy)
    /// and a receiver (getting a secret share), using the same keypair for both
    /// encryption/decryption and certification.
    ///
    /// Returns the same shape as the receiver-only entry point
    /// [`SecretShareReceiver::receive_secret_share`]: a [`SecretShareReceiver`]
    /// that *holds* the share until [`SecretShareReceiver::finalize`] is
    /// called with a complete cert map. Callers must not use the share before
    /// finalize succeeds — otherwise they're trusting an uncertified keygen.
    pub fn verify_receive_share_and_certify<H: Hash32, NG: NonceGen, S: CertificationScheme>(
        self,
        pop_schnorr: &Schnorr<H, NG>,
        cert_scheme: &S,
        share_index: ShareIndex,
        keypair: &KeyPair,
        agg_input: &AggKeygenInput,
    ) -> Result<(SecretShareReceiver, S::Signature), CombinedRoleError> {
        // First verify my contribution was included
        self.inner
            .verify_agg_input(agg_input)
            .map_err(|_| CombinedRoleError::ContributionDidntMatch)?;

        // Then receive my secret share
        let paired_secret_share =
            encpedpop::receive_secret_share(pop_schnorr, share_index, keypair, agg_input)
                .map_err(CombinedRoleError::ReceiveShareError)?;

        // Finally certify the result
        let sig = cert_scheme.certify(keypair, agg_input);

        Ok((
            SecretShareReceiver {
                paired_secret_share,
                agg_input: agg_input.clone(),
            },
            sig,
        ))
    }
}

/// Stores the state of share recipient who first receives their share and then waits to get
/// signatures from all the certifying parties on the keygeneration before accepting it.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretShareReceiver {
    paired_secret_share: PairedSecretShare<Normal, Zero>,
    agg_input: AggKeygenInput,
}

impl SecretShareReceiver {
    /// Extract your `keypair` and certify the key generation. Before you actually
    /// can use the share you must call [`finalize`] with a completed certificate.
    ///
    /// [`finalize`]: Self::finalize
    pub fn receive_secret_share<H, NG, S>(
        schnorr: &Schnorr<H, NG>,
        cert_scheme: &S,
        my_index: ShareIndex,
        keypair: &KeyPair,
        agg_input: &AggKeygenInput,
    ) -> Result<(Self, S::Signature), simplepedpop::ReceiveShareError>
    where
        H: Hash32,
        NG: NonceGen,
        S: CertificationScheme,
    {
        let paired_secret_share =
            encpedpop::receive_secret_share(schnorr, my_index, keypair, agg_input)?;
        let sig = cert_scheme.certify(keypair, agg_input);
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
    ///
    /// The supplied `certificate` map must contain exactly one entry per
    /// certifying party — any extras are rejected with
    /// [`CertificateError::Unexpected`]. This avoids unverified entries
    /// landing in the resulting [`CertifiedKeygen`] (where downstream
    /// consumers like the VRF beacon would otherwise pick them up).
    pub fn finalize<S: CertificationScheme>(
        self,
        cert_scheme: &S,
        certificate: BTreeMap<Point, S::Signature>,
        contributor_keys: &[Point],
    ) -> Result<CertifiedSecretShare<S::Signature>, CertificateError> {
        let cert_keys = self
            .agg_input
            .encryption_keys()
            .map(|(_, encryption_key)| encryption_key)
            .chain(contributor_keys.iter().cloned())
            .collect::<BTreeSet<_>>(); // dedupe as some contributors may also be receivers

        let mut remaining = certificate;
        let mut verified = BTreeMap::new();
        for cert_key in cert_keys {
            let sig = remaining
                .remove(&cert_key)
                .ok_or(CertificateError::Missing { key: cert_key })?;
            if !cert_scheme.verify_cert(cert_key, &self.agg_input, &sig) {
                return Err(CertificateError::InvalidCert { key: cert_key });
            }
            verified.insert(cert_key, sig);
        }

        if let Some((extra_key, _)) = remaining.into_iter().next() {
            return Err(CertificateError::Unexpected { key: extra_key });
        }

        let certified_keygen = CertifiedKeygen::new(self.agg_input, verified);

        Ok(CertifiedSecretShare {
            certified_keygen,
            paired_share: self.paired_secret_share,
        })
    }
}

/// Errors that can occur when a party acts as both contributor and receiver
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CombinedRoleError {
    /// The contribution we provided was not included correctly
    ContributionDidntMatch,
    /// Could not receive the secret share
    ReceiveShareError(simplepedpop::ReceiveShareError),
}

impl core::fmt::Display for CombinedRoleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CombinedRoleError::ContributionDidntMatch => {
                write!(f, "contribution was not included correctly")
            }
            CombinedRoleError::ReceiveShareError(e) => write!(f, "failed to receive share: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CombinedRoleError {}

/// Simulate running a key generation with `certpedpop`.
///
/// This calls all the other functions defined in this module to get the whole job done on a
/// single computer by simulating all the other parties.
///
/// A fingerprint can be provided to grind into the polynomial coefficients.
///
/// Returns:
/// - The `CertifiedKeygen` containing the aggregated keygen input and all certificates
/// - A vector of paired secret shares along with their corresponding keypairs. The keypairs
///   are returned so that callers can test the `recover_share` functionality, which allows
///   parties to recover their share from the certified keygen using their keypair (verifying
///   both that they certified the keygen and can decrypt their share).
pub fn simulate_keygen<H: Hash32, NG: NonceGen, S: CertificationScheme + Clone>(
    schnorr: &Schnorr<H, NG>,
    cert_scheme: S,
    threshold: u32,
    n_receivers: u32,
    n_extra_generators: u32,
    fingerprint: Fingerprint,
    rng: &mut impl rand_core::RngCore,
) -> SimulatedKeygenOutput<S::Signature> {
    let receiver_enckeys = (1..=n_receivers)
        .map(|i| {
            let party_index = Scalar::from(i).non_zero().unwrap();
            (party_index, KeyPair::new(Scalar::random(rng)))
        })
        .collect::<BTreeMap<_, _>>();

    let public_receiver_enckeys = receiver_enckeys
        .iter()
        .map(|(party_index, enckeypair)| (*party_index, enckeypair.public_key()))
        .collect::<BTreeMap<ShareIndex, Point>>();

    let n_contributors = n_receivers + n_extra_generators;

    // Generate keypairs for contributors - receivers will use their existing keypairs
    let contributor_keys: Vec<_> = (1..=n_receivers)
        .map(|i| {
            let party_index = Scalar::from(i).non_zero().unwrap();
            receiver_enckeys[&party_index]
        })
        .chain(
            core::iter::repeat_with(|| KeyPair::new(Scalar::random(rng)))
                .take(n_extra_generators as _),
        )
        .collect();

    let (contributors, to_coordinator_messages): (Vec<Contributor>, Vec<KeygenInput>) = (0
        ..n_contributors)
        .map(|i| {
            Contributor::gen_keygen_input(
                schnorr,
                threshold,
                n_contributors,
                &public_receiver_enckeys,
                i,
                rng,
            )
        })
        .unzip();

    let contributor_public_keys = contributor_keys
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<_>>();

    let mut aggregator = Coordinator::new(threshold, n_contributors, &public_receiver_enckeys);

    for (i, to_coordinator_message) in to_coordinator_messages.into_iter().enumerate() {
        aggregator
            .add_input(schnorr, i as u32, to_coordinator_message)
            .unwrap();
    }

    let mut agg_input = aggregator.finish().unwrap();
    agg_input.grind_fingerprint::<H>(fingerprint);

    // Create a Certifier to validate certificates as they're received
    let mut certifier = Certifier::new(
        cert_scheme.clone(),
        agg_input.clone(),
        &contributor_public_keys,
    )
    .expect("simulate_keygen produces matching contributor counts");

    // Hold dual-role receiver state until certification finishes; only then
    // can we release the paired share via finalize.
    let mut dual_role_receivers: Vec<(SecretShareReceiver, KeyPair)> = vec![];

    // Handle parties that are both contributors and receivers using the combined API
    for (i, (party_index, enckey)) in receiver_enckeys
        .iter()
        .enumerate()
        .take(n_receivers as usize)
    {
        // This party is both a contributor and receiver - use combined method
        let (receiver, sig) = contributors[i]
            .clone()
            .verify_receive_share_and_certify(
                schnorr,
                &cert_scheme,
                *party_index,
                enckey,
                &agg_input,
            )
            .unwrap();

        // Only one certificate for this dual-role party
        certifier
            .receive_certificate(enckey.public_key(), sig)
            .unwrap();

        dual_role_receivers.push((receiver, *enckey));
    }

    // Handle extra contributors that are only contributors (not receivers)
    for i in n_receivers as usize..n_contributors as usize {
        let sig = contributors[i]
            .clone()
            .verify_agg_input(&cert_scheme, &agg_input, &contributor_keys[i])
            .unwrap();
        certifier
            .receive_certificate(contributor_keys[i].public_key(), sig)
            .unwrap();
    }

    // Finish certification and get the CertifiedKeygen
    let certified_keygen = certifier
        .finish()
        .expect("Certifier should have all required certificates");

    // Now that certification is done, release each dual-role party's share.
    let cert_map = certified_keygen.certificate().clone();
    let paired_secret_shares: Vec<(PairedSecretShare<Normal>, KeyPair)> = dual_role_receivers
        .into_iter()
        .map(|(receiver, enckey)| {
            let CertifiedSecretShare { paired_share, .. } = receiver
                .finalize(&cert_scheme, cert_map.clone(), &contributor_public_keys)
                .expect("simulate_keygen finalize");
            (paired_share.non_zero().unwrap(), enckey)
        })
        .collect();

    SimulatedKeygenOutput {
        certified_keygen,
        paired_shares_with_keys: paired_secret_shares,
        contributor_public_keys,
    }
}

/// The result of finalizing a share receiver's key generation
pub struct CertifiedSecretShare<Sig> {
    /// The certified keygen containing the shared key and certificates
    pub certified_keygen: CertifiedKeygen<Sig>,
    /// The secret share for this receiver
    pub paired_share: PairedSecretShare<Normal, Zero>,
}

/// The result of simulating a complete key generation ceremony
pub struct SimulatedKeygenOutput<Sig> {
    /// The certified keygen containing the shared key and certificates
    pub certified_keygen: CertifiedKeygen<Sig>,
    /// All paired shares with their corresponding keypairs
    pub paired_shares_with_keys: Vec<(PairedSecretShare<Normal>, KeyPair)>,
    /// The public keys of all contributors
    pub contributor_public_keys: Vec<Point>,
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
            n_extra_generators in 0u32..=3,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let output = certpedpop::simulate_keygen(
                &schnorr,
                schnorr.clone(),
                threshold,
                n_receivers,
                n_extra_generators,
                Fingerprint::NONE,
                &mut rng
            );

            // Verify the certified keygen is valid
            output.certified_keygen.verify(schnorr.clone(), &output.contributor_public_keys).expect("CertifiedKeygen should be valid");

            for (paired_secret_share, keypair) in output.paired_shares_with_keys {
                let recovered = output.certified_keygen.recover_share::<sha2::Sha256, _>(&schnorr, paired_secret_share.index(), keypair).unwrap();
                assert_eq!(paired_secret_share, recovered);
            }

            // Verify we have the expected number of VRF certificates
            assert_eq!(
                output.certified_keygen.certificate().len(),
                (n_receivers + n_extra_generators) as usize
            );

        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "vrf_cert_keygen")]
        fn vrf_certified_keygen_randomness_beacon(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_extra_generators in 0u32..=3,
        ) {
            use proptest::test_runner::{RngAlgorithm, TestRng};

            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let vrf_certifier = vrf_cert::VrfCertScheme::<sha2::Sha256>::new("chilldkg-vrf");
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let output = certpedpop::simulate_keygen(
                &schnorr,
                vrf_certifier.clone(),
                threshold,
                n_receivers,
                n_extra_generators,
                Fingerprint::NONE,
                &mut rng,
            );

            // Verify the certified keygen is valid
            output.certified_keygen
                .verify(vrf_certifier, &output.contributor_public_keys)
                .expect("CertifiedKeygen should be valid");

            // Compute randomness beacon from the VRF outputs
            let randomness = output.certified_keygen.vrf_security_check(sha2::Sha256::default());

            // Verify the randomness is deterministic
            let randomness2 = output.certified_keygen.vrf_security_check(sha2::Sha256::default());
            assert_eq!(randomness, randomness2);

            // Verify we have the expected number of VRF certificates
            assert_eq!(
                output.certified_keygen.certificate().len(),
                (n_receivers + n_extra_generators) as usize
            );
        }
    }

    // SecretShareReceiver::finalize must reject any caller-supplied certificate
    // map that contains entries for keys outside the expected certifying set.
    // Otherwise the extras would land in CertifiedKeygen.certificate and
    // pollute downstream consumers (e.g. the VRF beacon).
    #[test]
    fn finalize_rejects_unexpected_cert_entries() {
        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let threshold = 2u32;
        let n_receivers = 2u32;
        let n_extra_generators = 0u32;

        let output = certpedpop::simulate_keygen(
            &schnorr,
            schnorr.clone(),
            threshold,
            n_receivers,
            n_extra_generators,
            Fingerprint::NONE,
            &mut rng,
        );

        // Pick the first receiver as our honest party for the finalize test.
        let (paired_share, keypair) = output.paired_shares_with_keys[0];
        let agg_input = output.certified_keygen.agg_input().clone();
        let contributor_keys = output.contributor_public_keys.clone();

        // Build the receiver state via the receiver-only entry point so we
        // can drive `finalize` directly.
        let (receiver, _own_sig) = SecretShareReceiver::receive_secret_share(
            &schnorr,
            &schnorr,
            paired_share.index(),
            &keypair,
            &agg_input,
        )
        .expect("receive_secret_share");

        // Honest cert map from the simulated keygen, plus an extra valid cert
        // signed by an unrelated keypair (not in contributor_keys ∪ receivers).
        let mut malicious_cert_map = output.certified_keygen.certificate().clone();
        let unrelated_keypair = KeyPair::new(Scalar::random(&mut rng));
        let unrelated_sig = schnorr.certify(&unrelated_keypair, &agg_input);
        malicious_cert_map.insert(unrelated_keypair.public_key(), unrelated_sig);

        let result = receiver.finalize(&schnorr, malicious_cert_map, &contributor_keys);
        assert_eq!(
            result.err(),
            Some(CertificateError::Unexpected {
                key: unrelated_keypair.public_key()
            }),
            "finalize must reject unknown-key entries in the supplied map"
        );
    }
}
