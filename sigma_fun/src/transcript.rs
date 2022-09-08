use core::marker::PhantomData;

use crate::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    typenum::{
        marker_traits::NonZero, type_operators::IsLessOrEqual, PartialDiv, Unsigned, U32, U64,
    },
    Sigma, Writable,
};
use digest::{crypto_common::BlockSizeUser, FixedOutput, Update};
use generic_array::GenericArray;

/// A trait for a Fiat-Shamir proof transcript.
///
/// Really this is just a trait around a cryptographic hash that can produce a Fiat-Shamir challenge
/// from the statement and the announcement. The usual workflow is to call `add_name` and then clone
/// the transcript for each new statement.
pub trait Transcript<S: Sigma>: Clone {
    /// The name unambigiously determines the semantics of the statement and announcement which
    /// are subsequently added to the transcript.
    fn add_name<N: Writable + ?Sized>(&mut self, name: &N);

    /// Adds the prover's statement to the transcript. This must be called before [`get_challenge`].
    ///
    /// [`get_challenge`]: Self::get_challenge
    fn add_statement(&mut self, sigma: &S, statement: &S::Statement);

    /// Gets the verifier's synthetic challenge for the non-interactive proof.
    fn get_challenge(
        self,
        sigma: &S,
        announcement: &S::Announcement,
    ) -> GenericArray<u8, S::ChallengeLength>;
}

/// A `Transcript` that can also generate a rng.
///
/// The prover needs an rng to generate it's [`AnnounceSecret`].
///
/// [`AnnounceSecret`]: crate::Sigma::AnnounceSecret
pub trait ProverTranscript<S: Sigma> {
    /// The type of Rng the transcript generates.
    type Rng: CryptoRng + RngCore;
    /// Generates an RNG from the transcript state and an input rng (`in_rng`) which should provide
    /// system randomness.
    fn gen_rng<R: CryptoRng + RngCore>(
        &self,
        sigma: &S,
        witness: &S::Witness,
        in_rng: Option<&mut R>,
    ) -> Self::Rng;
}

#[derive(Clone, Debug)]
/// A transcript which consists of a hash with fixed length output and a seedable RNG.
///
/// The [`SeedableRng`] specified must have the same seed length as the hash's output length.
/// `R` may be set to `()` but the it won't implement [`ProverTranscript`].
///
/// [`SeedableRng`]: rand_core::SeedableRng
pub struct HashTranscript<H, R = ()> {
    hash: H,
    rng: PhantomData<R>,
}

impl<H: Default, R> Default for HashTranscript<H, R> {
    fn default() -> Self {
        HashTranscript {
            hash: H::default(),
            rng: PhantomData,
        }
    }
}

#[derive(Clone)]
struct WriteHash<H>(H);

impl<H: Update> core::fmt::Write for WriteHash<H> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

/// Implements a transcript for any hash that outputs 32 bytes but with a block size of 64 bytes (e.g. SHA256).
///
/// The implementation first [BIP-340] tags the SHA256 instance with the Sigma protocol's name.
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
impl<H, S: Sigma, R: Clone> Transcript<S> for HashTranscript<H, R>
where
    S::ChallengeLength: IsLessOrEqual<U32>,
    <S::ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
    H: BlockSizeUser<BlockSize = U64> + FixedOutput<OutputSize = U32> + Update + Default + Clone,
{
    fn add_name<N: Writable + ?Sized>(&mut self, name: &N) {
        let hashed_tag = {
            let mut hash = WriteHash(H::default());
            name.write_to(&mut hash)
                .expect("writing to hash won't fail");
            hash.0.finalize_fixed()
        };
        // I started doing this with plans to make this more generic than it is.
        // This loop will always run twice
        let fill_block =
            <<H::BlockSize as PartialDiv<H::OutputSize>>::Output as Unsigned>::to_usize();
        for _ in 0..fill_block {
            self.hash.update(&hashed_tag[..]);
        }
    }

    fn add_statement(&mut self, sigma: &S, statement: &S::Statement) {
        sigma.hash_statement(&mut self.hash, statement);
    }

    fn get_challenge(
        mut self,
        sigma: &S,
        announce: &S::Announcement,
    ) -> GenericArray<u8, S::ChallengeLength> {
        sigma.hash_announcement(&mut self.hash, announce);
        let challenge_bytes = self.hash.finalize_fixed();
        // truncate the hash output
        GenericArray::clone_from_slice(&challenge_bytes[..S::ChallengeLength::to_usize()])
    }
}

/// Implements a prover transcript for a 32-byte hash with a rng that takes a 32-byte seed.
impl<S, H, R> ProverTranscript<S> for HashTranscript<H, R>
where
    S: Sigma,
    H: Update + FixedOutput<OutputSize = U32> + Clone,
    R: SeedableRng + CryptoRng + RngCore + Clone,
    R::Seed: From<GenericArray<u8, U32>>,
{
    type Rng = R;

    fn gen_rng<SysRng: CryptoRng + RngCore>(
        &self,
        sigma: &S,
        witness: &S::Witness,
        in_rng: Option<&mut SysRng>,
    ) -> Self::Rng {
        let mut rng_hash = self.hash.clone();
        sigma.hash_witness(&mut rng_hash, witness);
        if let Some(rng) = in_rng {
            let mut randomness = [0u8; 32];
            rng.fill_bytes(&mut randomness);
            rng_hash.update(&randomness);
        }
        let secret_seed = rng_hash.finalize_fixed();
        R::from_seed(secret_seed.into())
    }
}
