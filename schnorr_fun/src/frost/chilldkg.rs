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

pub mod certpedpop;
pub mod encpedpop;
pub mod simplepedpop;

use crate::Schnorr;
use secp256kfun::{KeyPair, hash::Hash32, nonce::NonceGen, prelude::*};

/// A trait for signature schemes that can be used to certify the DKG output.
///
/// This allows applications to choose their preferred signature scheme for
/// certifying the aggregated keygen input in certpedpop.
pub trait CertificationScheme {
    /// The signature type produced by this scheme
    type Signature: Clone + core::fmt::Debug;

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
    use vrf_fun::VrfProof;

    /// VRF certification scheme using SSWU VRF
    pub struct VrfCertifier;

    /// The output from VRF verification containing the gamma point
    #[derive(Clone, Debug)]
    pub struct VrfOutput {
        /// The VRF output point (gamma)
        pub gamma: Point,
    }

    /// Implement CertificationScheme for VrfCertifier
    impl CertificationScheme for VrfCertifier {
        type Signature = VrfProof;
        type Output = VrfOutput;

        fn certify(
            &self,
            keypair: &KeyPair,
            agg_input: &encpedpop::AggKeygenInput,
        ) -> Self::Signature {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            vrf_fun::rfc9381::sswu::prove::<sha2::Sha256>(keypair, &cert_bytes)
        }

        fn verify_cert(
            &self,
            cert_key: Point,
            agg_input: &encpedpop::AggKeygenInput,
            signature: &Self::Signature,
        ) -> Option<Self::Output> {
            // Use the certification bytes as the VRF input
            let cert_bytes = agg_input.cert_bytes();
            vrf_fun::rfc9381::sswu::verify::<sha2::Sha256>(cert_key, &cert_bytes, signature).map(
                |output| VrfOutput {
                    gamma: output.gamma,
                },
            )
        }
    }
}

#[cfg(test)]
mod test {
    use crate::frost::Fingerprint;

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

            encpedpop::simulate_keygen(
                &schnorr,
                threshold,
                n_receivers,
                n_generators,
                Fingerprint::none(),
                &mut rng,
            );
        }

        #[test]
        fn certified_run_simulate_keygen(
            (n_receivers, threshold) in (1u32..=4).prop_flat_map(|n| (Just(n), 1u32..=n)),
            n_generators in 1u32..5,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let (certified_keygen, paired_secret_shares_and_keys) = certpedpop::simulate_keygen(
                &schnorr,
                &schnorr,
                threshold,
                n_receivers,
                n_generators,
                Fingerprint::none(),
                &mut rng
            );

            for (paired_secret_share, keypair) in paired_secret_shares_and_keys {
                let recovered = certified_keygen.recover_share::<sha2::Sha256>(&schnorr, paired_secret_share.index(), keypair).unwrap();
                assert_eq!(paired_secret_share, recovered);
            }
        }
    }

    proptest! {
        #[test]
        fn encpedpop_simulate_keygen_with_fingerprint(
            (n_receivers, threshold) in (2u32..=4).prop_flat_map(|n| (Just(n), 2u32..=n)),
            n_generators in 1u32..5,
            difficulty in 0u8..10,
        ) {
            let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
            let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

            let fingerprint = crate::frost::shared_key::Fingerprint {
                bit_length: difficulty,
                tag: "test-fingerprint",
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

    #[test]
    #[cfg(feature = "vrf_cert_keygen")]
    fn vrf_certified_keygen_randomness_beacon() {
        use proptest::test_runner::{RngAlgorithm, TestRng};

        let schnorr = crate::new_with_deterministic_nonces::<sha2::Sha256>();
        let vrf_certifier = vrf_cert::VrfCertifier;
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);

        let threshold = 2;
        let n_receivers = 3;
        let n_generators = 2;

        let (certified_keygen, _) = certpedpop::simulate_keygen(
            &schnorr,
            &vrf_certifier,
            threshold,
            n_receivers,
            n_generators,
            Fingerprint::none(),
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
            (n_receivers + n_generators) as usize
        );
    }
}
