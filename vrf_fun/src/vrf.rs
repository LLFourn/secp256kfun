//! Generic VRF implementation that can work with different transcript types

use core::marker::PhantomData;
use secp256kfun::{KeyPair, Scalar, prelude::*};
use sigma_fun::{
    CompactProof, FiatShamir, ProverTranscript, Transcript,
    generic_array::{
        ArrayLength,
        typenum::{IsLessOrEqual, NonZero, U16, U32},
    },
};

/// VRF proof structure
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(serialize = "", deserialize = ""))
)]
pub struct VrfProof<L = U16>
where
    L: ArrayLength<u8> + IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: NonZero,
{
    /// The VRF output point.
    ///
    /// Usually you don't use this directly but hash it.
    pub gamma: Point,
    /// The proof that `gamma` is correct.
    pub proof: CompactProof<Scalar<Public, Zero>, L>,
}

#[cfg(feature = "bincode")]
impl<L> bincode::Encode for VrfProof<L>
where
    L: ArrayLength<u8> + IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: NonZero,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        self.gamma.encode(encoder)?;
        self.proof.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
impl<L, Context> bincode::Decode<Context> for VrfProof<L>
where
    L: ArrayLength<u8> + IsLessOrEqual<U32>,
    <L as IsLessOrEqual<U32>>::Output: NonZero,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let gamma = Point::decode(decoder)?;
        let proof = CompactProof::<Scalar<Public, Zero>, L>::decode(decoder)?;
        Ok(VrfProof { gamma, proof })
    }
}

/// Verified random output that ensures gamma has been verified
pub struct VerifiedRandomOutput {
    pub gamma: Point,
}

/// Generic VRF implementation
pub struct Vrf<T, ChallengeLength = U16>
where
    ChallengeLength: ArrayLength<u8> + IsLessOrEqual<U32>,
    <ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
{
    dleq: crate::VrfDleq<ChallengeLength>,
    pub transcript: T,
    _phantom: PhantomData<ChallengeLength>,
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
            _phantom: PhantomData,
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
