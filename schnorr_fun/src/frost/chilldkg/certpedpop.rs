//! `certpedpop` is built on top of [`encpedpop`] to add certification of the outcome.
//!
//! In [`encpedpop`] and [`simplepedpop`] it's left up to the application to figure out whether all
//! the parties agree on the `AggKeygenInput`. In `certpedpop` the relevant methods return
//! certification signatures on `AggKeygenInput` once they've been validated so they can be
//! collected by the share receivers. Once the share receivers have got all the certificates they
//! can finally output the key.
//!
//! Certificates are collected from other share receivers as well as `Contributor`s.
use super::{encpedpop, simplepedpop};
use crate::{Schnorr, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, prelude::*, rand_core};

/// A trait for signature schemes that can be used to certify the DKG output.
///
/// This allows applications to choose their preferred signature scheme for
/// certifying the aggregated keygen input in certpedpop.
pub trait CertificationScheme {
    /// The signature type produced by this scheme
    type Signature: Clone + core::fmt::Debug + PartialEq;

    /// The output produced by successful verification
    type Output: Clone + core::fmt::Debug;

    /// Sign the AggKeygenInput with the given keypair
    fn certify(&self, keypair: &KeyPair, agg_input: &encpedpop::AggKeygenInput) -> Self::Signature;

    /// Verify a certification signature and return the output
    fn verify_cert(
        &self,
        cert_key: Point,
        agg_input: &encpedpop::AggKeygenInput,
        signature: &Self::Signature,
    ) -> Option<Self::Output>;
}

/// Standard Schnorr (BIP340) implementation of the CertificationScheme trait
impl<H: Hash32, NG: NonceGen> CertificationScheme for Schnorr<H, NG> {
    type Signature = crate::Signature;
    type Output = ();

    fn certify(&self, keypair: &KeyPair, agg_input: &encpedpop::AggKeygenInput) -> Self::Signature {
        let cert_bytes = agg_input.cert_bytes();
        let message = crate::Message::new("BIP DKG/cert", cert_bytes.as_ref());
        let keypair_even_y = (*keypair).into();
        self.sign(&keypair_even_y, message)
    }

    fn verify_cert(
        &self,
        cert_key: Point,
        agg_input: &encpedpop::AggKeygenInput,
        signature: &Self::Signature,
    ) -> Option<Self::Output> {
        let cert_bytes = agg_input.cert_bytes();
        let message = crate::Message::new("BIP DKG/cert", cert_bytes.as_ref());
        let cert_key_even_y = cert_key.into_point_with_even_y().0;
        if self.verify(&cert_key_even_y, message, signature) {
            Some(())
        } else {
            None
        }
    }
}

/// VRF-based implementation of CertificationScheme
#[cfg(feature = "vrf_cert_keygen")]
pub mod vrf_cert {
    use super::*;
    use secp256kfun::digest::core_api::BlockSizeUser;
    use vrf_fun::VrfProof;

    /// VRF certification scheme using SSWU VRF
    #[derive(Clone, Copy, Debug, PartialEq, Default)]
    pub struct VrfCertifier<H> {
        hash: core::marker::PhantomData<H>,
    }

    /// The output from VRF verification containing the gamma point
    #[derive(Clone, Debug, PartialEq)]
    pub struct VrfOutput {
        /// The VRF output point (gamma)
        pub gamma: Point,
    }

    /// Implement CertificationScheme for VrfCertifier
    impl<H: Hash32 + BlockSizeUser> CertificationScheme for VrfCertifier<H> {
        type Signature = VrfProof;
        type Output = VrfOutput;

        fn certify(
            &self,
            keypair: &KeyPair,
            agg_input: &encpedpop::AggKeygenInput,
        ) -> Self::Signature {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            vrf_fun::rfc9381::sswu::prove::<H>(keypair, &cert_bytes)
        }

        fn verify_cert(
            &self,
            cert_key: Point,
            agg_input: &encpedpop::AggKeygenInput,
            signature: &Self::Signature,
        ) -> Option<Self::Output> {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            vrf_fun::rfc9381::sswu::verify::<H>(cert_key, &cert_bytes, signature).map(|output| {
                VrfOutput {
                    gamma: output.gamma,
                }
            })
        }
    }
}

/// A party that generates secret input to the key generation. You need at least one of these
/// and if at least one of these parties is honest then the final secret key will not be known by an
/// attacker (unless they obtain `t` shares!).
#[derive(Clone, Debug, PartialEq)]
pub struct Contributor {
    inner: encpedpop::Contributor,
}

/// Produced by [`Contributor::gen_keygen_input`]. This is sent from the each
/// `Contributor` to the *coordinator*.
pub type KeygenInput = encpedpop::KeygenInput;
/// Key generation inputs after being aggregated by the coordinator
pub type AggKeygenInput = encpedpop::AggKeygenInput;
/// A certificate containing signatures or proofs from certifying parties
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct Certificate<Sig>(BTreeMap<Point, Sig>);

/// A certificate containing signatures or proofs from certifying parties
impl<Sig> Default for Certificate<Sig> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Sig: PartialEq + core::fmt::Debug> Certificate<Sig> {
    /// Create a new empty certificate
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a signature/proof for a public key
    pub fn insert(&mut self, key: Point, sig: Sig) {
        if let Some(existing) = self.0.get(&key) {
            assert_eq!(existing, &sig, "certification should not change");
        }
        self.0.insert(key, sig);
    }

    /// Get the signature/proof for a public key
    pub fn get(&self, key: &Point) -> Option<&Sig> {
        self.0.get(key)
    }

    /// Iterate over all entries in the certificate
    pub fn iter(&self) -> impl Iterator<Item = (&Point, &Sig)> {
        self.0.iter()
    }

    /// The number of certificates stored
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Have any certificates been collected
    pub fn is_empty(&self) -> bool {
        // clippy::len_without_is_empty wanted this method
        self.0.is_empty()
    }
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
        receiver_encryption_keys: &BTreeMap<ShareIndex, Point>,
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
}

/// A key generation session that has been certified by each certifying party (contributors and share receivers).
#[derive(Clone, Debug, PartialEq)]
pub struct CertifiedKeygen<S: CertificationScheme> {
    /// The aggregated inputs to keygen
    pub input: AggKeygenInput,
    /// The collected certificates from each party
    pub certificate: Certificate<S::Signature>,
    /// The outputs from successful verification, indexed by certifying party's public key
    pub outputs: BTreeMap<Point, S::Output>,
}

impl<S: CertificationScheme> CertifiedKeygen<S> {
    /// Recover a share from a certified key generation with the decryption key.
    ///
    /// This checks that the `keypair` has signed the key generation first.
    pub fn recover_share<H: Hash32>(
        &self,
        cert_scheme: &S,
        share_index: ShareIndex,
        keypair: KeyPair,
    ) -> Result<PairedSecretShare, &'static str> {
        let cert_key = keypair.public_key();
        let my_cert = self
            .certificate
            .get(&cert_key)
            .ok_or("I haven't certified this keygen")?;
        // We may have gotten this certificate from *somewhere* so must verify we certified it
        if cert_scheme
            .verify_cert(cert_key, &self.input, my_cert)
            .is_none()
        {
            return Err("my certification was invalid");
        }
        self.input.recover_share::<H>(share_index, &keypair)
    }

    /// Gets the inner `encpedpop::AggKeygenInput`.
    pub fn inner(&self) -> &AggKeygenInput {
        &self.input
    }

    /// Gets the certificate.
    pub fn certificate(&self) -> &Certificate<S::Signature> {
        &self.certificate
    }

    /// Gets the verification outputs.
    pub fn outputs(&self) -> &BTreeMap<Point, S::Output> {
        &self.outputs
    }
}

#[cfg(feature = "vrf_cert_keygen")]
impl<H: Hash32 + secp256kfun::digest::crypto_common::BlockSizeUser>
    CertifiedKeygen<vrf_cert::VrfCertifier<H>>
{
    /// Compute a randomness beacon from the VRF outputs
    ///
    /// This function hashes all the VRF gamma points together to produce
    /// unpredictable randomness that no single party could have controlled
    /// (as long as at least one party is honest).
    ///
    /// ## Use for Manual Verification
    ///
    /// In settings where participants must manually verify the keygen succeeded
    /// and there's no trusted public key infrastructure, the randomness beacon
    /// serves as a compact fingerprint of the entire protocol execution.
    ///
    /// Participants can verify they all have the same view of the protocol by
    /// comparing just a few bytes of the beacon (e.g., the first 4 bytes shown
    /// on device screens). This works because:
    ///
    /// 1. Each honest participant verifies their VRF contribution is included
    /// 2. VRFs are deterministic - malicious parties cannot adapt their
    ///    contribution after seeing honest contributions
    /// 3. No party can predict the final beacon value before the protocol runs
    ///
    /// This prevents malicious parties from giving different participants
    /// different views of the keygen outcome without detection, achieving similar
    /// security to comparing a full 32-byte hash but with better usability.
    pub fn compute_randomness_beacon(&self) -> [u8; 32] {
        let mut hasher = H::default();

        // BTreeMap already maintains sorted order by key
        for output in self.outputs.values() {
            hasher.update(output.gamma.to_bytes().as_ref());
        }

        hasher.finalize_fixed().into()
    }
}

pub use encpedpop::Coordinator;

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
    pub fn finalize<S: CertificationScheme>(
        self,
        cert_scheme: &S,
        certificate: Certificate<S::Signature>,
        contributor_keys: &[Point],
    ) -> Result<(CertifiedKeygen<S>, PairedSecretShare<Normal, Zero>), CertificateError> {
        let mut outputs = BTreeMap::new();
        let cert_keys = self
            .agg_input
            .encryption_keys()
            .map(|(_, encryption_key)| encryption_key)
            .chain(contributor_keys.iter().cloned())
            .collect::<BTreeSet<_>>(); // dedupe as some contributers may have also be receivers

        for cert_key in cert_keys {
            match certificate.get(&cert_key) {
                Some(sig) => match cert_scheme.verify_cert(cert_key, &self.agg_input, sig) {
                    Some(output) => {
                        outputs.insert(cert_key, output);
                    }
                    None => return Err(CertificateError::InvalidCert { key: cert_key }),
                },
                None => return Err(CertificateError::Missing { key: cert_key }),
            }
        }

        let certified_keygen = CertifiedKeygen {
            input: self.agg_input,
            certificate,
            outputs,
        };

        Ok((certified_keygen, self.paired_secret_share))
    }
}

/// Simulate running a key generation with `certpedpop`.
///
/// This calls all the other functions defined in this module to get the whole job done on a
/// single computer by simulating all the other parties.
///
/// A fingerprint can be provided to grind into the polynomial coefficients.
pub fn simulate_keygen<H: Hash32, NG: NonceGen, S: CertificationScheme>(
    schnorr: &Schnorr<H, NG>,
    cert_scheme: &S,
    threshold: u32,
    n_receivers: u32,
    n_extra_generators: u32,
    fingerprint: Fingerprint,
    rng: &mut impl rand_core::RngCore,
) -> (
    CertifiedKeygen<S>,
    Vec<(PairedSecretShare<Normal>, KeyPair)>,
) {
    let mut receiver_enckeys = (1..=n_receivers)
        .map(|i| {
            let party_index = Scalar::from(i).non_zero().unwrap();
            (party_index, KeyPair::new(Scalar::random(rng)))
        })
        .collect::<BTreeMap<_, _>>();

    let public_receiver_enckeys = receiver_enckeys
        .iter()
        .map(|(party_index, enckeypair)| (*party_index, enckeypair.public_key()))
        .collect::<BTreeMap<ShareIndex, Point>>();

    // Total number of generators is receivers + extra generators
    let n_generators = n_receivers + n_extra_generators;

    // Generate keypairs for contributors - receivers will use their existing keypairs
    let contributor_keys: Vec<_> = (1..=n_receivers)
        .map(|i| {
            let party_index = Scalar::from(i).non_zero().unwrap();
            receiver_enckeys[&party_index]
        })
        .chain(core::iter::repeat_n(
            KeyPair::new(Scalar::random(rng)),
            n_extra_generators as _,
        ))
        .collect();

    let (contributors, to_coordinator_messages): (Vec<Contributor>, Vec<KeygenInput>) = (0
        ..n_generators)
        .map(|i| {
            Contributor::gen_keygen_input(schnorr, threshold, &public_receiver_enckeys, i, rng)
        })
        .unzip();

    let contributor_public_keys = contributor_keys
        .iter()
        .map(|kp| kp.public_key())
        .collect::<Vec<_>>();

    let mut aggregator = Coordinator::new(threshold, n_generators, &public_receiver_enckeys);

    for (i, to_coordinator_message) in to_coordinator_messages.into_iter().enumerate() {
        aggregator
            .add_input(schnorr, i as u32, to_coordinator_message)
            .unwrap();
    }

    let mut agg_input = aggregator.finish().unwrap();

    // Apply fingerprint grinding
    agg_input.grind_fingerprint::<H>(fingerprint);
    let mut certificate = Certificate::new();

    for (contributor, keypair) in contributors.into_iter().zip(contributor_keys.iter()) {
        let sig = contributor
            .verify_agg_input(cert_scheme, &agg_input, keypair)
            .unwrap();
        certificate.insert(keypair.public_key(), sig);
    }

    let mut paired_secret_shares = vec![];
    let mut share_receivers = vec![];
    for (party_index, enckey) in &receiver_enckeys {
        let (share_receiver, cert) = SecretShareReceiver::receive_secret_share(
            schnorr,
            cert_scheme,
            *party_index,
            enckey,
            &agg_input,
        )
        .unwrap();
        certificate.insert(enckey.public_key(), cert);
        share_receivers.push(share_receiver);
    }

    // Collect outputs by verifying all certificates
    let mut outputs = BTreeMap::new();
    for (key, sig) in certificate.iter() {
        if let Some(output) = cert_scheme.verify_cert(*key, &agg_input, sig) {
            outputs.insert(*key, output);
        }
    }

    let certified_keygen = CertifiedKeygen {
        input: agg_input.clone(),
        certificate: certificate.clone(),
        outputs,
    };

    for share_receiver in share_receivers {
        let (_certified, paired_secret_share) = share_receiver
            .finalize(cert_scheme, certificate.clone(), &contributor_public_keys)
            .unwrap();
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
        key: Point,
    },
    /// A certificate was missing
    Missing {
        /// They key whose cert was missing
        key: Point,
    },
}

impl core::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CertificateError::InvalidCert { key } => {
                write!(f, "certificate for key {key} was invalid")
            }
            CertificateError::Missing { key } => {
                write!(f, "certificate for key {key} was missing")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CertificateError {}

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

            let (certified_keygen, paired_secret_shares_and_keys) = certpedpop::simulate_keygen(
                &schnorr,
                &schnorr,
                threshold,
                n_receivers,
                n_extra_generators,
                Fingerprint::NONE,
                &mut rng
            );

            for (paired_secret_share, keypair) in paired_secret_shares_and_keys {
                let recovered = certified_keygen.recover_share::<sha2::Sha256>(&schnorr, paired_secret_share.index(), keypair).unwrap();
                assert_eq!(paired_secret_share, recovered);
            }
        }
    }

    #[test]
    #[cfg(feature = "vrf_cert_keygen")]
    fn vrf_certified_keygen_randomness_beacon() {
        use proptest::test_runner::{RngAlgorithm, TestRng};

        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let vrf_certifier = vrf_cert::VrfCertifier::<sha2::Sha256>::default();
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

        let threshold = 2;
        let n_receivers = 3;
        let n_extra_generators = 0; // All receivers are also generators

        let (certified_keygen, _) = certpedpop::simulate_keygen(
            &schnorr,
            &vrf_certifier,
            threshold,
            n_receivers,
            n_extra_generators,
            Fingerprint::NONE,
            &mut rng,
        );

        // Compute randomness beacon from the VRF outputs
        let randomness = certified_keygen.compute_randomness_beacon();

        // Verify the randomness is deterministic
        let randomness2 = certified_keygen.compute_randomness_beacon();
        assert_eq!(randomness, randomness2);

        // Verify we have the expected number of VRF outputs
        assert_eq!(
            certified_keygen.outputs().len(),
            (n_receivers + n_extra_generators) as usize
        );
    }
}
