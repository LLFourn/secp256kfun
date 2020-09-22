use crate::rand_core::{CryptoRng, RngCore, SeedableRng};
use digest::Digest;
use generic_array::{typenum::U32, GenericArray};
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
    fn add_announcement(
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

impl<H: Digest<OutputSize = U32> + Default + Clone, S: Sigma<ChallengeLength = U32>> Transcript<S>
    for H
{
    type Rng = ChaCha20Rng;

    fn initialize(sigma: &S) -> Self {
        let mut name_hash = WriteHash(H::default());
        sigma.write_name(&mut name_hash);
        let output = name_hash.0.finalize();
        let mut hash = H::default();
        hash.update(output);
        hash.update(output);
        hash
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

    fn add_announcement(
        mut self,
        sigma: &S,
        announce: &S::Announce,
    ) -> GenericArray<u8, S::ChallengeLength> {
        sigma.hash_announcement(&mut self, announce);
        self.finalize()
    }
}
