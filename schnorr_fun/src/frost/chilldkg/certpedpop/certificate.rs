//! Certificate types and certification schemes for [`certpedpop`].
//!
//! [`certpedpop`]: super

use super::{VerifiedAggKeygenInput, encpedpop};
use crate::{Schnorr, frost::*};
use alloc::collections::{BTreeMap, BTreeSet};
use secp256kfun::{hash::*, prelude::*};

/// How a [`certpedpop`] party signs a [`VerifiedAggKeygenInput`] and how others
/// verify that signature. The default implementation is BIP340 Schnorr; the
/// `vrf_cert_keygen` feature provides a VRF variant whose certificates double
/// as a randomness beacon.
///
/// [`certpedpop`]: super
pub trait CertificationScheme: Clone {
    /// Signature type produced by this scheme.
    type Signature: Clone + core::fmt::Debug + PartialEq;

    /// Sign the verified aggregate's [`cert_bytes`] with `keypair`.
    ///
    /// [`cert_bytes`]: VerifiedAggKeygenInput::cert_bytes
    fn certify(
        &self,
        keypair: &KeyPair,
        verified_input: &VerifiedAggKeygenInput,
    ) -> Self::Signature;

    /// Verify a certification signature against the verified aggregate.
    fn verify_cert(
        &self,
        cert_key: Point,
        verified_input: &VerifiedAggKeygenInput,
        signature: &Self::Signature,
    ) -> bool;
}

/// BIP340 Schnorr certification.
impl<H: Hash32, NG: NonceGen + Clone> CertificationScheme for Schnorr<H, NG> {
    type Signature = crate::Signature;

    fn certify(
        &self,
        keypair: &KeyPair,
        verified_input: &VerifiedAggKeygenInput,
    ) -> Self::Signature {
        let cert_bytes = verified_input.cert_bytes();
        let message = crate::Message::new("BIP DKG/cert", cert_bytes.as_ref());
        let keypair_even_y = (*keypair).into();
        self.sign(&keypair_even_y, message)
    }

    fn verify_cert(
        &self,
        cert_key: Point,
        verified_input: &VerifiedAggKeygenInput,
        signature: &Self::Signature,
    ) -> bool {
        let cert_bytes = verified_input.cert_bytes();
        let message = crate::Message::new("BIP DKG/cert", cert_bytes.as_ref());
        let cert_key_even_y = cert_key.into_point_with_even_y().0;
        self.verify(&cert_key_even_y, message, signature)
    }
}

/// Final output of a `certpedpop` keygen — the verified aggregate paired with
/// every party's certificate. Hold this; it proves the whole group certified
/// the same result. Use [`recover_share`] to re-derive a share later from a
/// stored decryption keypair.
///
/// Not serializable: a `CertifiedKeygen` is only ever produced through paths
/// that re-verify every certificate ([`Certifier::finish`] or [`new`]).
///
/// [`recover_share`]: Self::recover_share
/// [`new`]: Self::new
#[derive(Clone, Debug, PartialEq)]
pub struct CertifiedKeygen<Sig> {
    verified_input: VerifiedAggKeygenInput,
    certificate: BTreeMap<Point, Sig>,
}

impl<Sig> CertifiedKeygen<Sig> {
    fn from_verified(
        verified_input: VerifiedAggKeygenInput,
        certificate: BTreeMap<Point, Sig>,
    ) -> Self {
        Self {
            verified_input,
            certificate,
        }
    }

    /// Build a `CertifiedKeygen` from a verified aggregate and complete
    /// certificate map; every signature is verified on the way in. Use this
    /// when you have all the certificates at once; otherwise build a
    /// [`Certifier`] and feed them in incrementally.
    pub fn new<S>(
        cert_scheme: &S,
        verified_input: VerifiedAggKeygenInput,
        certificates: BTreeMap<Point, Sig>,
    ) -> Result<Self, CertificateError>
    where
        S: CertificationScheme<Signature = Sig>,
    {
        let mut certifier = Certifier::new(cert_scheme.clone(), verified_input);
        for (key, sig) in certificates {
            certifier
                .receive_certificate(key, sig)
                .map_err(|err| match err {
                    ReceiveCertError::UnknownParty => CertificateError::Unexpected { key },
                    ReceiveCertError::InvalidSignature => CertificateError::InvalidCert { key },
                })?;
        }
        if let Some(key) = certifier.first_missing() {
            return Err(CertificateError::Missing { key });
        }
        Ok(certifier.finish().expect("just verified completeness"))
    }

    /// Recover a share with `keypair`'s decryption key. Confirms `keypair`
    /// itself certified this keygen before decrypting.
    pub fn recover_share<H: Hash32, S: CertificationScheme<Signature = Sig>>(
        &self,
        cert_scheme: &S,
        share_index: ShareIndex,
        keypair: KeyPair,
    ) -> Result<PairedSecretShare, RecoverShareError> {
        let cert_key = keypair.public_key();
        let my_cert = self
            .certificate
            .get(&cert_key)
            .ok_or(RecoverShareError::NotCertifiedByKey)?;
        // We may have gotten this certificate from *somewhere* so must verify we certified it
        if !cert_scheme.verify_cert(cert_key, self.verified_agg_input(), my_cert) {
            return Err(RecoverShareError::InvalidCertification);
        }
        Ok(self
            .verified_agg_input()
            .recover_share::<H>(share_index, &keypair)?)
    }

    /// The verified aggregated keygen input this certificate covers.
    pub fn verified_agg_input(&self) -> &VerifiedAggKeygenInput {
        &self.verified_input
    }

    /// The certificate map: one signature per certifying party.
    pub fn certificate(&self) -> &BTreeMap<Point, Sig> {
        &self.certificate
    }
}

/// Reasons a caller-supplied certificate map can be rejected by [`CertifiedKeygen::new`]
/// or [`SecretShareReceiver::finalize`].
///
/// [`SecretShareReceiver::finalize`]: super::SecretShareReceiver::finalize
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum CertificateError {
    /// A certificate was present but did not verify.
    InvalidCert {
        /// The key whose certificate failed verification.
        key: Point,
    },
    /// A certifying party's certificate is missing.
    Missing {
        /// The key whose certificate is missing.
        key: Point,
    },
    /// The certificate map contained an entry for a key outside the expected
    /// certifying set.
    Unexpected {
        /// One of the unexpected keys in the supplied map.
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
            CertificateError::Unexpected { key } => {
                write!(
                    f,
                    "certificate map contained unexpected entry for key {key}"
                )
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
            verified_input: &VerifiedAggKeygenInput,
        ) -> Self::Signature {
            // Use the certification bytes as the VRF input
            let cert_bytes = verified_input.cert_bytes();
            let h =
                Point::hash_to_curve(H::default().ds(self.name).add(&cert_bytes[..])).normalize();
            let vrf = SimpleVrf::<H>::default().with_name(self.name);
            vrf.prove(keypair, h)
        }

        fn verify_cert(
            &self,
            cert_key: Point,
            verified_input: &VerifiedAggKeygenInput,
            signature: &Self::Signature,
        ) -> bool {
            // Use the certification bytes as the VRF input
            let cert_bytes = verified_input.cert_bytes();
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
        /// 5. All honest parties with the same `VerifiedAggKeygenInput::cert_bytes` will output the same check
        /// 6. All honest parties with a different `VerifiedAggKeygenInput::cert_bytes` are statistically likely to output different bytes.
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

/// Collects certificates from each certifying party and yields a
/// [`CertifiedKeygen`] once they're all in. Construct after
/// `Contributor::<R>::verify_agg_input` and feed each incoming certificate
/// through [`receive_certificate`].
///
/// [`receive_certificate`]: Self::receive_certificate
#[derive(Clone, Debug, PartialEq)]
pub struct Certifier<S: CertificationScheme> {
    cert_scheme: S,
    verified_agg_input: VerifiedAggKeygenInput,
    certificates: BTreeMap<Point, S::Signature>,
}

impl<S: CertificationScheme> Certifier<S> {
    /// Build a certifier from a verified aggregated input. Feed each
    /// party's certificate (including your own) via [`receive_certificate`].
    ///
    /// [`receive_certificate`]: Self::receive_certificate
    pub fn new(cert_scheme: S, verified_agg_input: VerifiedAggKeygenInput) -> Self {
        Self {
            cert_scheme,
            verified_agg_input,
            certificates: BTreeMap::new(),
        }
    }

    /// Verify and store a certificate from `from`. Idempotent: re-feeding an
    /// already-stored certificate is a no-op (allows replaying a transport
    /// without losing progress).
    pub fn receive_certificate(
        &mut self,
        from: Point,
        signature: S::Signature,
    ) -> Result<(), ReceiveCertError> {
        if !self.verified_agg_input.required_keys().contains(&from) {
            return Err(ReceiveCertError::UnknownParty);
        }

        if !self
            .cert_scheme
            .verify_cert(from, &self.verified_agg_input, &signature)
        {
            return Err(ReceiveCertError::InvalidSignature);
        }

        self.certificates.entry(from).or_insert(signature);

        Ok(())
    }

    /// The certification scheme this certifier uses.
    pub fn cert_scheme(&self) -> &S {
        &self.cert_scheme
    }

    /// Public keys whose certificates are required.
    pub fn required_keys(&self) -> BTreeSet<Point> {
        self.verified_agg_input.required_keys()
    }

    /// Whether every required certificate has been received.
    pub fn is_finished(&self) -> bool {
        self.certificates.len() == self.verified_agg_input.required_keys().len()
    }

    /// First required key still missing a certificate, if any.
    pub fn first_missing(&self) -> Option<Point> {
        self.verified_agg_input
            .required_keys()
            .iter()
            .find(|k| !self.certificates.contains_key(k))
            .copied()
    }

    /// How many certificates are still missing.
    pub fn missing_count(&self) -> usize {
        self.verified_agg_input
            .required_keys()
            .len()
            .saturating_sub(self.certificates.len())
    }

    /// Number of required keys.
    pub fn required_count(&self) -> usize {
        self.verified_agg_input.required_keys().len()
    }

    /// Yield the [`CertifiedKeygen`] if every certificate has been received.
    pub fn finish(self) -> Result<CertifiedKeygen<S::Signature>, IncompleteCertificates> {
        if !self.is_finished() {
            return Err(IncompleteCertificates);
        }

        Ok(CertifiedKeygen::from_verified(
            self.verified_agg_input,
            self.certificates,
        ))
    }
}

/// Errors from [`Certifier::receive_certificate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveCertError {
    /// Party is not in the expected keyset
    UnknownParty,
    /// Certificate signature is invalid
    InvalidSignature,
}

impl core::fmt::Display for ReceiveCertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ReceiveCertError::UnknownParty => write!(f, "Certificate from unknown party"),
            ReceiveCertError::InvalidSignature => write!(f, "Invalid certificate signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReceiveCertError {}

/// Returned by [`Certifier::finish`] when not all expected certificates have
/// been collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncompleteCertificates;

impl core::fmt::Display for IncompleteCertificates {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Not all certificates received")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IncompleteCertificates {}

/// Reasons [`CertifiedKeygen::recover_share`] may fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverShareError {
    /// The supplied keypair didn't sign a certificate for this keygen.
    NotCertifiedByKey,
    /// The certificate stored for this key doesn't verify under the scheme.
    InvalidCertification,
    /// Underlying share recovery from the encrypted aggregate failed.
    Recovery(encpedpop::RecoverShareError),
}

impl From<encpedpop::RecoverShareError> for RecoverShareError {
    fn from(err: encpedpop::RecoverShareError) -> Self {
        RecoverShareError::Recovery(err)
    }
}

impl core::fmt::Display for RecoverShareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoverShareError::NotCertifiedByKey => {
                write!(f, "this keypair has not certified the keygen")
            }
            RecoverShareError::InvalidCertification => {
                write!(f, "our stored certificate did not verify")
            }
            RecoverShareError::Recovery(err) => write!(f, "{err}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RecoverShareError {}

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
