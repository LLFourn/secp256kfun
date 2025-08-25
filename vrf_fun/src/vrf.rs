//! Generic VRF implementation that can work with different transcript types

use secp256kfun::{KeyPair, Scalar, prelude::*};
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
    /// The VRF output point.
    ///
    /// Usually you don't use this directly but hash it.
    pub gamma: Point,
    /// The proof that `gamma` is correct.
    pub proof: CompactProof<Scalar<Public, Zero>, L>,
}

/// Verified random output that ensures gamma has been verified
#[derive(Debug, Clone)]
pub struct VerifiedRandomOutput {
    pub gamma: Point,
}

/// Generic VRF implementation
pub struct Vrf<T, ChallengeLength = U16> {
    dleq: crate::VrfDleq<ChallengeLength>,
    pub transcript: T,
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
        }
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
        let fs = FiatShamir::new(self.dleq.clone(), self.transcript.clone(), None);
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
        let fs = FiatShamir::new(self.dleq.clone(), self.transcript.clone(), None);
        let statement = (public_key.normalize(), (h, proof.gamma));

        if !fs.verify(&statement, &proof.proof) {
            return None;
        }

        Some(VerifiedRandomOutput { gamma: proof.gamma })
    }
}
