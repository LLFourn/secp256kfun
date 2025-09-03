//! Generic VRF implementation that can work with different transcript types

use secp256kfun::{KeyPair, Scalar, hash::HashInto, prelude::*};
use sigma_fun::{
    CompactProof, FiatShamir, ProverTranscript, Transcript,
    generic_array::{
        ArrayLength,
        typenum::{IsLessOrEqual, NonZero, U16, U32},
    },
};

/// VRF proof structure
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        deserialize = "L: ArrayLength<u8>, CompactProof<Scalar<Public, Zero>, L>: serde::Deserialize<'de>",
        serialize = "L: ArrayLength<u8>, CompactProof<Scalar<Public, Zero>, L>: serde::Serialize",
    ))
)]
#[cfg_attr(
    feature = "bincode",
    derive(bincode::Encode, bincode::Decode),
    bincode(
        encode_bounds = "L: ArrayLength<u8>, CompactProof<Scalar<Public, Zero>, L>: bincode::Encode",
        decode_bounds = "L: ArrayLength<u8>, CompactProof<Scalar<Public, Zero>, L>: bincode::Decode<__Context>",
        borrow_decode_bounds = "L: ArrayLength<u8>, CompactProof<Scalar<Public, Zero>, L>: bincode::BorrowDecode<'__de, __Context>"
    )
)]
pub struct VrfProof<L = U16>
where
    L: ArrayLength<u8>,
{
    /// The VRF output point (gamma).
    ///
    /// **Security Warning**: According to VRF security proofs (see
    /// ["Making NSEC5 Practical for DNSSEC"](https://eprint.iacr.org/2017/099.pdf)),
    /// this point must be hashed before being used as randomness. Direct use of gamma
    /// may compromise the pseudorandomness properties of the VRF.
    ///
    /// After verification, use the `HashInto` implementation on `VerifiedRandomOutput`
    /// to safely extract randomness.
    pub gamma: Point,
    /// The proof that `gamma` is correct.
    pub proof: CompactProof<Scalar<Public, Zero>, L>,
}

/// Verified random output that ensures gamma has been verified
///
/// The gamma point is kept private to enforce proper usage. VRF security proofs
/// require hashing gamma before use as randomness. Use the `HashInto` implementation
/// to safely extract randomness from this output.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedRandomOutput {
    gamma: Point,
}

impl VerifiedRandomOutput {
    /// Access the raw gamma point directly.
    ///
    /// # Security Warning
    ///
    /// The VRF security proofs require that gamma be hashed before being used as randomness.
    /// Using the gamma point directly without hashing may compromise the pseudorandomness
    /// properties of the VRF.
    ///
    /// According to ["Making NSEC5 Practical for DNSSEC"](https://eprint.iacr.org/2017/099.pdf),
    /// the VRF output must be the hash of gamma, not gamma itself, to maintain security
    /// properties. The paper notes that "the VRF output is the hash of the unique point
    /// on the curve" to ensure proper domain separation and pseudorandomness.
    ///
    /// **You should use the `HashInto` implementation instead**, which properly hashes
    /// gamma to produce secure randomness:
    ///
    /// ```ignore
    /// use sha2::Sha256;
    /// let randomness = Sha256::default().add(&verified_output).finalize_fixed();
    /// ```
    pub fn dangerously_access_gamma(&self) -> Point {
        self.gamma
    }
}

impl HashInto for VerifiedRandomOutput {
    fn hash_into(self, hash: &mut impl secp256kfun::digest::Update) {
        self.gamma.hash_into(hash)
    }
}

/// Generic VRF implementation
pub struct Vrf<T, ChallengeLength = U16> {
    dleq: crate::VrfDleq<ChallengeLength>,
    pub transcript: T,
    name: Option<&'static str>,
}

impl<T: Clone, ChallengeLength> Vrf<T, ChallengeLength>
where
    ChallengeLength: ArrayLength<u8> + IsLessOrEqual<U32>,
    <ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
{
    /// Create a new VRF instance with the given transcript
    pub fn new(transcript: T) -> Self {
        use sigma_fun::Eq;
        use sigma_fun::secp256k1::{DL, DLG};
        Self {
            dleq: Eq::new(DLG::default(), DL::default()),
            transcript,
            name: None,
        }
    }

    /// Set a custom name for domain separation
    ///
    /// The name is used in the Fiat-Shamir transform to provide domain separation.
    ///
    /// Note: For RFC 9381 VRFs, setting a name has no effect as they use their own
    /// transcript mechanism that doesn't support custom names.
    pub fn with_name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }
}

impl<T: Clone + Default, ChallengeLength> Default for Vrf<T, ChallengeLength>
where
    ChallengeLength: ArrayLength<u8> + IsLessOrEqual<U32>,
    <ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T, ChallengeLength> Vrf<T, ChallengeLength>
where
    T: Transcript<crate::VrfDleq<ChallengeLength>> + Clone,
    ChallengeLength: ArrayLength<u8> + IsLessOrEqual<U32>,
    <ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
{
    /// Generate VRF proof (requires ProverTranscript)
    pub fn prove<R>(&self, keypair: &KeyPair, h: Point) -> VrfProof<ChallengeLength>
    where
        T: ProverTranscript<crate::VrfDleq<ChallengeLength>, Rng = R>,
        R: sigma_fun::rand_core::CryptoRng + sigma_fun::rand_core::RngCore,
    {
        let (secret_key, public_key) = keypair.as_tuple();
        let gamma = g!(secret_key * h).normalize();
        let fs = FiatShamir::new(self.dleq.clone(), self.transcript.clone(), self.name);
        let witness = secret_key;
        let statement = (public_key, (h, gamma));
        let proof = fs.prove::<R>(&witness, &statement, None);
        VrfProof { gamma, proof }
    }

    /// Verify VRF proof
    pub fn verify(
        &self,
        public_key: Point,
        h: Point,
        proof: &VrfProof<ChallengeLength>,
    ) -> Option<VerifiedRandomOutput> {
        let fs = FiatShamir::new(self.dleq.clone(), self.transcript.clone(), self.name);
        let statement = (public_key.normalize(), (h, proof.gamma));

        if !fs.verify(&statement, &proof.proof) {
            return None;
        }

        Some(VerifiedRandomOutput { gamma: proof.gamma })
    }
}
