use crate::{
    rand_core::{CryptoRng, RngCore, SeedableRng},
    typenum::{
        marker_traits::NonZero, type_operators::IsLessOrEqual, PartialDiv, Unsigned, U32, U64,
    },
};
use digest::{BlockInput, Digest};
use generic_array::{ArrayLength, GenericArray};
use rand_chacha::ChaCha20Rng;

use crate::Sigma;
pub trait Transcript<S: Sigma>: Clone {
    type Rng: CryptoRng + RngCore;
    fn initialize(sigma: &S) -> Self;
    fn add_statement(&mut self, sigma: &S, statement: &S::Statement);
    fn gen_rng<R: CryptoRng + RngCore>(
        &self,
        sigma: &S,
        witness: &S::Witness,
        in_rng: &mut R,
    ) -> Self::Rng;
    fn get_challenge(
        self,
        sigma: &S,
        announce: &S::Announce,
    ) -> GenericArray<u8, S::ChallengeLength>;
}

#[derive(Clone)]
struct WriteHash<H>(H);

impl<H: Digest> core::fmt::Write for WriteHash<H> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.update(s.as_bytes());
        Ok(())
    }
}

impl<H: BlockInput<BlockSize = U64> + Digest<OutputSize = U32> + Default + Clone, S: Sigma>
    Transcript<S> for H
where
    S::ChallengeLength: IsLessOrEqual<U32>,
    <S::ChallengeLength as IsLessOrEqual<U32>>::Output: NonZero,
{
    type Rng = ChaCha20Rng;

    fn initialize(sigma: &S) -> Self {
        let hashed_tag = {
            let mut hash = WriteHash(H::default());
            sigma
                .write_name(&mut hash)
                .expect("writing to hash won't fail");
            hash.0.finalize()
        };
        let mut tagged_hash = H::default();
        let fill_block =
            <<H::BlockSize as PartialDiv<H::OutputSize>>::Output as Unsigned>::to_usize();
        for _ in 0..fill_block {
            tagged_hash.update(&hashed_tag[..]);
        }

        tagged_hash
    }

    fn add_statement(&mut self, sigma: &S, statement: &S::Statement) {
        sigma.hash_statement(self, statement);
    }

    fn gen_rng<R: CryptoRng + RngCore>(
        &self,
        sigma: &S,
        witness: &S::Witness,
        in_rng: &mut R,
    ) -> Self::Rng {
        let mut rng_hash = self.clone();
        sigma.hash_witness(&mut rng_hash, witness);
        let mut randomness = [0u8; 32];
        in_rng.fill_bytes(&mut randomness);
        rng_hash.update(randomness);
        let secret_seed = rng_hash.finalize();
        ChaCha20Rng::from_seed(secret_seed.into())
    }

    fn get_challenge(
        mut self,
        sigma: &S,
        announce: &S::Announce,
    ) -> GenericArray<u8, S::ChallengeLength> {
        sigma.hash_announcement(&mut self, announce);
        let challenge_bytes = self.finalize();
        truncate_hash_output::<U32, S::ChallengeLength>(challenge_bytes)
    }
}

fn truncate_hash_output<I: ArrayLength<u8>, O: ArrayLength<u8>>(
    input: GenericArray<u8, I>,
) -> GenericArray<u8, O>
where
    O: IsLessOrEqual<I>,
    <O as IsLessOrEqual<I>>::Output: NonZero,
{
    GenericArray::clone_from_slice(&input[..O::to_usize()])
}
