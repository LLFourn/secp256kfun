//! [RFC 9381] VRF transcript implementation for secp256k1
//!
//! This module implements [RFC 9381], which is... quite something. The spec manages to
//! take a relatively simple concept (proving you hashed something with your private key)
//! and wrap it in layers of domain separation that would make an onion jealous.
//!
//! We support two hash-to-curve methods:
//! - TAI (Try-And-Increment): The sensible one
//! - [RFC 9380]: Where the DST (Domain Separation Tag) construction reaches peak absurdity
//!
//! [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
//! [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380

use crate::Vrf;
use rand_chacha::ChaCha20Rng;
use secp256kfun::{
    hash::{Hash32, HashAdd},
    prelude::*,
};
use sigma_fun::{
    ProverTranscript, Sigma, Transcript,
    generic_array::{GenericArray, typenum::U16},
    rand_core::{CryptoRng, RngCore, SeedableRng},
};

/// Suite string for TAI (Try-And-Increment) hash-to-curve
/// This comes from... nowhere official. Just what various secp256k1 VRF implementations
/// seem to have converged on (who are also implementing draft-05 of the spec).
/// Unfortunately, we're stuck with 0xFE for compatibility even though they're using
/// an old version of the spec.
pub const SUITE_STRING_TAI: u8 = 0xFE;

/// Suite string for [RFC 9380] hash-to-curve  
/// We made this up (0xFF) because if 0xFE is taken, obviously the next one is 0xFF.
/// The spec doesn't define secp256k1 suites, so we're all just making it up as we go.
///
/// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
pub const SUITE_STRING_RFC9380: u8 = 0xFF;

/// [RFC 9381] compliant VRF using TAI (Try-And-Increment) hash-to-curve
///
/// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
pub type Rfc9381TaiVrf<H> = Vrf<Rfc9381Transcript<H, { SUITE_STRING_TAI }>, U16>;

/// [RFC 9381] compliant VRF using [RFC 9380] SSWU hash-to-curve
///
/// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
/// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
pub type Rfc9381SswuVrf<H> = Vrf<Rfc9381Transcript<H, { SUITE_STRING_RFC9380 }>, U16>;

/// [RFC 9381] compliant transcript implementation
///
/// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
pub struct Rfc9381Transcript<H, const SUITE_STRING: u8> {
    hasher: H,
}

impl<H: Hash32, const SUITE_STRING: u8> Default for Rfc9381Transcript<H, SUITE_STRING> {
    fn default() -> Self {
        Self {
            hasher: H::default(),
        }
    }
}

impl<H: Hash32, const SUITE_STRING: u8> Rfc9381Transcript<H, SUITE_STRING> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<H: Hash32, const SUITE_STRING: u8> Clone for Rfc9381Transcript<H, SUITE_STRING> {
    fn clone(&self) -> Self {
        Self {
            hasher: self.hasher.clone(),
        }
    }
}

impl<H: Hash32, const SUITE_STRING: u8> Transcript<crate::VrfDleq<U16>>
    for Rfc9381Transcript<H, SUITE_STRING>
{
    fn add_name<N: sigma_fun::Writable + ?Sized>(&mut self, _name: &N) {
        const DOMAIN_SEP_FRONT: u8 = 0x02;

        // The "suite string" is actually just a single byte. Because why use a string
        // when you can use a magic number that no one will remember the meaning of?
        self.hasher = H::default().add(SUITE_STRING).add(DOMAIN_SEP_FRONT);
    }

    fn add_statement(
        &mut self,
        _sigma: &crate::VrfDleq<U16>,
        statement: &<crate::VrfDleq<U16> as Sigma>::Statement,
    ) {
        let (public_key, (h, gamma)) = statement;
        self.hasher = self
            .hasher
            .clone()
            .add(public_key.to_bytes())
            .add(h.to_bytes())
            .add(gamma.to_bytes());
    }

    fn get_challenge(
        mut self,
        _sigma: &crate::VrfDleq<U16>,
        announcement: &<crate::VrfDleq<U16> as Sigma>::Announcement,
    ) -> GenericArray<u8, U16> {
        const DOMAIN_SEP_BACK: u8 = 0x00;

        let (u, v) = announcement;
        self.hasher = self
            .hasher
            .add(u.to_bytes())
            .add(v.to_bytes())
            .add(DOMAIN_SEP_BACK);

        let hash = self.hasher.finalize_fixed();

        // Truncate to 16 bytes as per RFC 9381 for secp256k1
        GenericArray::clone_from_slice(&hash[..16])
    }
}

impl<H: Hash32, const SUITE_STRING: u8> ProverTranscript<crate::VrfDleq<U16>>
    for Rfc9381Transcript<H, SUITE_STRING>
{
    type Rng = ChaCha20Rng;

    fn gen_rng<R: CryptoRng + RngCore>(
        &self,
        _sigma: &crate::VrfDleq<U16>,
        witness: &Scalar,
        _in_rng: Option<&mut R>,
    ) -> Self::Rng {
        let mut hasher = H::default();
        hasher = hasher.add(b"vrf-nonce-gen");
        hasher = hasher.add(witness.to_bytes());
        let seed = hasher.finalize_fixed();
        ChaCha20Rng::from_seed(seed.into())
    }
}

/// High-level TAI (Try-And-Increment) VRF API
pub mod tai {
    use super::SUITE_STRING_TAI;
    use crate::{Rfc9381TaiVrf, VerifiedRandomOutput, VrfProof};
    use secp256kfun::{
        KeyPair,
        hash::{Hash32, HashAdd},
        prelude::*,
    };
    use sigma_fun::generic_array::typenum::U16;

    /// Prove VRF according to [RFC 9381] with TAI hash-to-curve
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    pub fn prove<H: Hash32>(keypair: &KeyPair, alpha: &[u8]) -> VrfProof<U16> {
        let vrf = Rfc9381TaiVrf::<H>::default();
        let h = Point::hash_to_curve_rfc9381_tai::<H>(alpha, b"");
        vrf.prove(keypair, h.normalize())
    }

    /// Verify VRF proof according to [RFC 9381] with TAI hash-to-curve
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    pub fn verify<H: Hash32>(
        public_key: Point,
        alpha: &[u8],
        proof: &VrfProof<U16>,
    ) -> Option<VerifiedRandomOutput> {
        let vrf = Rfc9381TaiVrf::<H>::default();
        let h = Point::hash_to_curve_rfc9381_tai::<H>(alpha, b"");
        vrf.verify(public_key, h.normalize(), proof)
    }

    /// Compute [RFC 9381] compliant output with TAI suite string (0xFE)
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    pub fn output<H: Hash32>(verified: VerifiedRandomOutput) -> [u8; 32] {
        H::default()
            .add([SUITE_STRING_TAI])
            .add(0x03u8) // Hash mode domain separator
            .add(verified)
            .add(0x00u8) // Hash mode trailer
            .finalize_fixed()
            .into()
    }
}

/// High-level [RFC 9380] SSWU hash-to-curve VRF API
///
/// **HAZMAT WARNING**: This inherits the warnings from [`hash_to_curve_sswu`](Point::hash_to_curve_sswu)
///
/// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
pub mod sswu {
    use super::SUITE_STRING_RFC9380;
    use crate::{Rfc9381SswuVrf, VerifiedRandomOutput, VrfProof};
    use secp256kfun::{
        KeyPair,
        digest::crypto_common::BlockSizeUser,
        hash::{Hash32, HashAdd},
        prelude::*,
    };
    use sigma_fun::generic_array::typenum::U16;

    /// Zero-allocation DST wrapper that implements the magnificent DST construction from [RFC 9381].
    ///
    /// **HAZMAT**: This is where the complexity really shines. According to the spec,
    /// when using hash-to-curve, the DST must be:
    /// "ECVRF_" || sswu_suite_ID_string || suite_string
    ///
    /// Yes, that's right - we concatenate:
    /// 1. A prefix ("ECVRF_")
    /// 2. The entire SSWU hash-to-curve suite string (which already has its own domain separation)
    /// 3. Our VRF suite string byte (because why not add more?)
    ///
    /// It's domain separation all the way down, folks. One byte wrong here and your
    /// VRF outputs will be completely incompatible.
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    struct Dst;

    impl AsRef<[u8]> for Dst {
        fn as_ref(&self) -> &[u8] {
            // Create a static array with the full DST
            const DST_LEN: usize = 36 + 1; // prefix length + suite string
            const DST: [u8; DST_LEN] = {
                let mut dst = [0u8; DST_LEN];
                let prefix = b"ECVRF_secp256k1_XMD:SHA-256_SSWU_RO_";
                let mut i = 0;
                while i < prefix.len() {
                    dst[i] = prefix[i];
                    i += 1;
                }
                dst[i] = SUITE_STRING_RFC9380; // Tack on our made-up suite byte
                dst
            };
            &DST
        }
    }

    /// Prove VRF according to [RFC 9381] with [RFC 9380] hash-to-curve
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    /// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
    pub fn prove<H>(keypair: &KeyPair, alpha: &[u8]) -> VrfProof<U16>
    where
        H: Hash32 + BlockSizeUser,
    {
        let vrf = Rfc9381SswuVrf::<H>::default();
        let dst = Dst.as_ref();
        #[cfg(all(test, feature = "std"))]
        {
            use secp256kfun::hex;
            std::eprintln!("Dst in prove (hex): {}", hex::encode(dst));
        }
        let h = Point::hash_to_curve_sswu::<H>(alpha, dst).normalize();
        vrf.prove(keypair, h)
    }

    /// Verify VRF proof according to [RFC 9381] with [RFC 9380] hash-to-curve
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    /// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
    pub fn verify<H>(
        public_key: Point,
        alpha: &[u8],
        proof: &VrfProof<U16>,
    ) -> Option<VerifiedRandomOutput>
    where
        H: Hash32 + BlockSizeUser,
    {
        let vrf = Rfc9381SswuVrf::<H>::default();
        let h = Point::hash_to_curve_sswu::<H>(alpha, Dst.as_ref()).normalize();
        vrf.verify(public_key, h, proof)
    }

    /// Compute [RFC 9381] compliant output with [RFC 9380] SSWU suite string (0xFF)
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    /// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
    pub fn output<H: Hash32>(verified: VerifiedRandomOutput) -> [u8; 32] {
        H::default()
            .add([SUITE_STRING_RFC9380])
            .add(0x03u8) // Hash mode domain separator
            .add(verified)
            .add(0x00u8) // Hash mode trailer
            .finalize_fixed()
            .into()
    }
}
