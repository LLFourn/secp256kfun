//! `certpedpop` is built on top of [`encpedpop`] to add certification of the outcome.
//!
//! In [`encpedpop`] and [`simplepedpop`] it's left up to the application to figure out whether all
//! the parties agree on the `AggKeygenInput`. In `certpedpop` the relevant methods return
//! certification signatures on `AggKeygenInput` once they've been validated so they can be
//! collected by the share receivers. Once the share receivers have got all the certificates they
//! can finally output the key.
//!
//! Certificates are collected from other share receivers as well as `Contributor`s.
use super::{CertificationScheme, encpedpop, simplepedpop, vrf_cert};
use crate::{Schnorr, frost::*};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, prelude::*, rand_core};

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
/// A certificate containing signatures or proofs from certifying parties
#[derive(Clone, Debug)]
pub struct Certificate<Sig>(BTreeMap<Point, Sig>);

/// A certificate containing signatures or proofs from certifying parties
impl<Sig> Default for Certificate<Sig> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<Sig> Certificate<Sig> {
    /// Create a new empty certificate
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a signature/proof for a public key
    pub fn insert(&mut self, key: Point, sig: Sig) {
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
#[derive(Clone, Debug)]
pub struct CertifiedKeygen<S: CertificationScheme> {
    input: AggKeygenInput,
    certificate: Certificate<S::Signature>,
    /// The outputs from successful verification, indexed by certifying party's public key
    outputs: BTreeMap<Point, S::Output>,
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
impl CertifiedKeygen<vrf_cert::VrfCertifier> {
    /// Compute a randomness beacon from the VRF outputs
    ///
    /// This function hashes all the VRF gamma points together to produce
    /// unpredictable randomness that no single party could have controlled
    /// (as long as at least one party is honest).
    pub fn compute_randomness_beacon(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // BTreeMap already maintains sorted order by key
        for output in self.outputs.values() {
            hasher.update(output.gamma.to_bytes());
        }

        hasher.finalize().into()
    }
}

pub use encpedpop::Coordinator;

/// Stores the state of share recipient who first receives their share and then waits to get
/// signatures from all the certifying parties on the keygeneration before accepting it.
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
    ) -> Result<(CertifiedKeygen<S>, PairedSecretShare<Normal, Zero>), &'static str> {
        let mut outputs = BTreeMap::new();
        let cert_keys = self
            .agg_input
            .encryption_keys()
            .map(|(_, encryption_key)| encryption_key)
            .chain(contributor_keys.iter().cloned());
        for cert_key in cert_keys {
            match certificate.get(&cert_key) {
                Some(sig) => match cert_scheme.verify_cert(cert_key, &self.agg_input, sig) {
                    Some(output) => {
                        outputs.insert(cert_key, output);
                    }
                    None => return Err("certification signature was invalid"),
                },
                None => return Err("missing certification signature"),
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
    n_generators: u32,
    fingerprint: Fingerprint,
    rng: &mut impl rand_core::RngCore,
) -> (
    CertifiedKeygen<S>,
    Vec<(PairedSecretShare<Normal>, KeyPair)>,
) {
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
        .collect::<BTreeMap<ShareIndex, Point>>();

    let (contributors, to_coordinator_messages): (Vec<Contributor>, Vec<KeygenInput>) = (0
        ..n_generators)
        .map(|i| {
            Contributor::gen_keygen_input(schnorr, threshold, &public_receiver_enckeys, i, rng)
        })
        .unzip();

    let contributor_keys = (0..n_generators)
        .map(|_| KeyPair::new(Scalar::random(rng)))
        .collect::<Vec<_>>();
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
