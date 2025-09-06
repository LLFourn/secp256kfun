//! Certificate types and certification schemes for ChillDKG
//!
//! This module contains:
//! - Certificate: A collection of certification signatures
//! - CertifiedKeygen: The result of a successfully certified key generation
//! - CertificationScheme: Trait for certification methods
//! - Certifier: A stateful validator that checks certificates as they are received

use super::{AggKeygenInput, encpedpop};
use crate::{Schnorr, frost::*};
use alloc::collections::{BTreeMap, BTreeSet};
use secp256kfun::{hash::*, prelude::*};

/// A trait for different ways of certifying the aggregated keygen input in certpedpop.
pub trait CertificationScheme {
    /// The signature type produced by this scheme
    type Signature: Clone + core::fmt::Debug + PartialEq;

    /// Sign the AggKeygenInput with the given keypair
    fn certify(&self, keypair: &KeyPair, agg_input: &encpedpop::AggKeygenInput) -> Self::Signature;

    /// Verify a certification signature
    fn verify_cert(
        &self,
        cert_key: Point,
        agg_input: &encpedpop::AggKeygenInput,
        signature: &Self::Signature,
    ) -> bool;
}

/// Standard Schnorr (BIP340) implementation of the CertificationScheme trait
impl<H: Hash32, NG: NonceGen> CertificationScheme for Schnorr<H, NG> {
    type Signature = crate::Signature;

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
    ) -> bool {
        let cert_bytes = agg_input.cert_bytes();
        let message = crate::Message::new("BIP DKG/cert", cert_bytes.as_ref());
        let cert_key_even_y = cert_key.into_point_with_even_y().0;
        self.verify(&cert_key_even_y, message, signature)
    }
}

/// The result of a certified key generation
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Deserialize, crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
pub struct CertifiedKeygen<Sig> {
    /// The aggregated inputs to keygen
    input: AggKeygenInput,
    /// The collected certificates from each party
    certificate: BTreeMap<Point, Sig>,
}

impl<Sig> CertifiedKeygen<Sig> {
    /// Internal constructor for use within the crate.
    pub(crate) fn new(input: AggKeygenInput, certificate: BTreeMap<Point, Sig>) -> Self {
        Self { input, certificate }
    }

    /// Verify that all certificates are valid for the given certification scheme and contributor keys.
    ///
    /// This type should normally be impossible to construct in an invalid state through the API,
    /// but since it supports serialization, this method allows validating instances that have been
    /// deserialized or received from untrusted sources.
    pub fn verify<S>(
        &self,
        cert_scheme: S,
        contributor_keys: &[Point],
    ) -> Result<(), CertifierError>
    where
        S: CertificationScheme<Signature = Sig>,
        Sig: Clone,
    {
        let mut certifier = Certifier::new(cert_scheme, self.input.clone(), contributor_keys);

        // Add all certificates to the certifier
        for (key, sig) in &self.certificate {
            certifier.receive_certificate(*key, sig.clone())?;
        }

        // Check if all required certificates are present
        if !certifier.is_finished() {
            return Err(CertifierError::IncompleteCertificates);
        }

        Ok(())
    }

    /// Recover a share from a certified key generation with the decryption key.
    ///
    /// This checks that the `keypair` has signed the key generation first.
    pub fn recover_share<H: Hash32, S: CertificationScheme<Signature = Sig>>(
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
        if !cert_scheme.verify_cert(cert_key, &self.input, my_cert) {
            return Err("my certification was invalid");
        }
        self.input.recover_share::<H>(share_index, &keypair)
    }

    /// Gets the aggregated keygen input.
    pub fn agg_input(&self) -> &AggKeygenInput {
        &self.input
    }

    /// Gets the certificate.
    pub fn certificate(&self) -> &BTreeMap<Point, Sig> {
        &self.certificate
    }
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

/// VRF-based implementation of CertificationScheme
#[cfg(feature = "vrf_cert_keygen")]
pub mod vrf_cert {
    use super::*;
    use secp256kfun::digest::typenum::U32;
    use secp256kfun::{digest::core_api::BlockSizeUser, hash::HashAdd};
    use vrf_fun::{SimpleVrf, VrfProof};

    /// Type alias for VRF proofs used in certification
    pub type CertVrfProof = VrfProof<U32>;

    /// VRF certification scheme using SimpleVrf
    #[derive(Clone, Debug)]
    pub struct VrfCertScheme<H> {
        name: &'static str,
        _hash: core::marker::PhantomData<H>,
    }

    impl<H> PartialEq for VrfCertScheme<H> {
        fn eq(&self, other: &Self) -> bool {
            self.name == other.name
        }
    }

    impl<H> VrfCertScheme<H> {
        /// Create a new VRF certification scheme with a domain separator name.
        pub fn new(name: &'static str) -> Self {
            Self {
                name,
                _hash: core::marker::PhantomData,
            }
        }
    }

    /// Implement CertificationScheme for VrfCertScheme
    impl<H> CertificationScheme for VrfCertScheme<H>
    where
        H: Hash32, // This constraint ensures the hash has a 512-bit block size (required for HashTranscript)
        H: BlockSizeUser<BlockSize = secp256kfun::digest::typenum::U64>,
    {
        type Signature = CertVrfProof;

        fn certify(
            &self,
            keypair: &KeyPair,
            agg_input: &encpedpop::AggKeygenInput,
        ) -> Self::Signature {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            let h =
                Point::hash_to_curve(H::default().ds(self.name).add(&cert_bytes[..])).normalize();
            let vrf = SimpleVrf::<H>::default().with_name(self.name);
            vrf.prove(keypair, h)
        }

        fn verify_cert(
            &self,
            cert_key: Point,
            agg_input: &encpedpop::AggKeygenInput,
            signature: &Self::Signature,
        ) -> bool {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            let h =
                Point::hash_to_curve(H::default().ds(self.name).add(&cert_bytes[..])).normalize();
            let vrf = SimpleVrf::<H>::default().with_name(self.name);
            vrf.verify(cert_key, h, signature).is_some()
        }
    }

    impl super::CertifiedKeygen<CertVrfProof> {
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
        /// on device screens).
        ///
        /// ## Security
        ///
        /// If no parties controlled by the adversary abort, the output will
        /// be uniformly distributed. The VRF outputs effectively act as a "randomness beacon" -
        /// a source of verifiable randomness that all parties can compute deterministically
        /// from the certificates. Observe that:
        ///
        /// 1. The malicious party must commit to all the VRF public keys up front.
        /// 2. The honest party verifies its contribution to the keygen is included (which are always sampled randomly)
        /// 3. The VRF is over the transcript and every transcript with an honest party will always be unique (because of #2).
        /// 4. The honest party's VRF output will be both hidden and uniformly distributed.
        /// 5. All honest parties with the same `AggKeygenInput::cert_bytes` will output the same check
        /// 6. All honest parties with a different `AggKeygenInput::cert_bytes` are statistically likely to output different bytes.
        ///
        /// This check is *statistically* secure -- per keygen the attacker only
        /// has 1/2ⁿ chance of succeeding to collide the checks where `n` is the
        /// number of bits the honest parties check among each other. **It is up
        /// to the application to limit the number of attempts the adversary can make.**
        pub fn vrf_security_check(&self, mut hasher: impl Hash32) -> [u8; 32] {
            for vrf_proof in self.certificate.values() {
                let gamma = vrf_proof.dangerously_access_gamma_without_verifying();
                hasher.update(gamma.to_bytes().as_ref());
            }
            hasher.finalize_fixed().into()
        }
    }
}

/// A certifier that validates certificates as they are received
#[derive(Clone, Debug, PartialEq)]
pub struct Certifier<S: CertificationScheme> {
    cert_scheme: S,
    agg_input: encpedpop::AggKeygenInput,
    required_keys: BTreeSet<Point>,
    certificates: BTreeMap<Point, S::Signature>,
}

impl<S: CertificationScheme> Certifier<S> {
    /// Create a new certifier that expects certificates from contributors and receivers
    pub fn new(
        cert_scheme: S,
        agg_input: encpedpop::AggKeygenInput,
        contributor_keys: &[Point],
    ) -> Self {
        // Collect all expected keys - deduplicate since some parties may be both contributors and receivers
        let mut required_keys = BTreeSet::new();

        // Add contributor certification keys
        for key in contributor_keys {
            required_keys.insert(*key);
        }

        // Add receiver encryption keys from the agg_input
        for (_, encryption_key) in agg_input.encryption_keys() {
            required_keys.insert(encryption_key);
        }

        Self {
            cert_scheme,
            agg_input,
            required_keys,
            certificates: BTreeMap::new(),
        }
    }

    /// Receive and validate a certificate from a party
    pub fn receive_certificate(
        &mut self,
        from: Point,
        signature: S::Signature,
    ) -> Result<(), CertifierError> {
        // Check if we're expecting this party
        if !self.required_keys.contains(&from) {
            return Err(CertifierError::UnknownParty);
        }

        // Check for duplicate - if we already have a cert from this key, it must be identical
        if let Some(existing_sig) = self.certificates.get(&from) {
            debug_assert_eq!(
                existing_sig, &signature,
                "Conflicting certificates from same party"
            );
            // Same signature, this is fine - party is certifying multiple times with same key
            return Ok(());
        }

        // Verify the certificate
        if !self
            .cert_scheme
            .verify_cert(from, &self.agg_input, &signature)
        {
            return Err(CertifierError::InvalidSignature);
        }

        // Store the validated certificate
        self.certificates.insert(from, signature);

        Ok(())
    }

    /// Get the aggregated keygen input
    pub fn agg_input(&self) -> &encpedpop::AggKeygenInput {
        &self.agg_input
    }

    /// Get the set of required keys for certification
    pub fn required_keys(&self) -> &BTreeSet<Point> {
        &self.required_keys
    }

    /// Check if all required certificates have been received
    pub fn is_finished(&self) -> bool {
        self.certificates.len() == self.required_keys.len()
    }

    /// Get the number of certificates still needed
    pub fn missing_count(&self) -> usize {
        self.required_keys
            .len()
            .saturating_sub(self.certificates.len())
    }

    /// Get the number of required keys
    pub fn required_count(&self) -> usize {
        self.required_keys.len()
    }

    /// Finish certification and return the certified keygen
    pub fn finish(self) -> Result<CertifiedKeygen<S::Signature>, CertifierError> {
        if !self.is_finished() {
            return Err(CertifierError::IncompleteCertificates);
        }

        Ok(CertifiedKeygen::new(self.agg_input, self.certificates))
    }
}

/// Errors that can occur during certificate validation
#[derive(Debug, Clone)]
pub enum CertifierError {
    /// Party is not in the expected keyset
    UnknownParty,
    /// Certificate already received from this party
    DuplicateCertificate,
    /// Certificate signature is invalid
    InvalidSignature,
    /// Not all required certificates have been received
    IncompleteCertificates,
}

#[cfg(feature = "std")]
impl std::error::Error for CertifierError {}

impl core::fmt::Display for CertifierError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CertifierError::UnknownParty => write!(f, "Certificate from unknown party"),
            CertifierError::DuplicateCertificate => write!(f, "Duplicate certificate"),
            CertifierError::InvalidSignature => write!(f, "Invalid certificate signature"),
            CertifierError::IncompleteCertificates => write!(f, "Not all certificates received"),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    #[cfg(feature = "vrf_cert_keygen")]
    fn test_certifier_with_vrf_cert_scheme_is_partial_eq() {
        use super::*;
        use sha2::Sha256;

        // Function that requires T to implement PartialEq
        fn assert_partial_eq<T: PartialEq>() {}

        // This will only compile if Certifier<VrfCertScheme<Sha256>> implements PartialEq
        assert_partial_eq::<Certifier<vrf_cert::VrfCertScheme<Sha256>>>();
    }
}
