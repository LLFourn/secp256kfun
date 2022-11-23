use crate::{generic_array::GenericArray, ProverTranscript, Sigma, Transcript};
use rand_core::{CryptoRng, RngCore};

/// Applies the Fiat-Shamir transform to a given [`Sigma`] protocol given a [`Transcript`].
///
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [`Transcript`]: crate::Transcript
/// [`Sigma`]: crate::Sigma
#[derive(Clone, Debug)]
pub struct FiatShamir<S, T> {
    /// The transcript
    pub transcript: T,
    /// The sigma protocol
    pub sigma: S,
}

impl<S: Default + Sigma, T: Transcript<S> + Default> Default for FiatShamir<S, T> {
    fn default() -> Self {
        Self::new(S::default(), T::default(), None)
    }
}

impl<S: Sigma, T: Transcript<S>> FiatShamir<S, T> {
    /// Create a new non-interactive prover/verifier given a [`Sigma`] and a [`Transcript`] for that
    /// Sigma protocol.
    ///
    /// [`Transcript`]: crate::Transcript
    /// [`Sigma`]: crate::Sigma
    pub fn new(sigma: S, mut transcript: T, override_name: Option<&str>) -> Self {
        match override_name {
            Some(name) => transcript.add_name(name),
            None => transcript.add_name(&sigma),
        };

        Self { transcript, sigma }
    }

    /// Generates a proof given the witness, a statement and some optional additional randomness.
    ///
    /// Optimistically, the proof should be secure without passing in `rng` but **it is always recommended**.
    /// to pass in secure system random number generator as `rng`.
    pub fn prove<Rng: CryptoRng + RngCore>(
        &self,
        witness: &S::Witness,
        statement: &S::Statement,
        rng: Option<&mut Rng>,
    ) -> CompactProof<S>
    where
        T: ProverTranscript<S>,
    {
        let mut transcript = self.transcript.clone();
        transcript.add_statement(&self.sigma, statement);
        let mut transcript_rng = transcript.gen_rng(&self.sigma, witness, rng);
        let announce_secret = self.sigma.gen_announce_secret(witness, &mut transcript_rng);
        let announce = self.sigma.announce(statement, &announce_secret);
        let challenge = transcript.get_challenge(&self.sigma, &announce);
        let response =
            self.sigma
                .respond(witness, statement, announce_secret, &announce, &challenge);
        CompactProof::<S> {
            challenge,
            response,
        }
    }

    /// Verifies the proof given the statement.
    #[must_use]
    pub fn verify(&self, statement: &S::Statement, proof: &CompactProof<S>) -> bool {
        let mut transcript = self.transcript.clone();
        transcript.add_statement(&self.sigma, statement);
        let implied_announcement =
            match self
                .sigma
                .implied_announcement(statement, &proof.challenge, &proof.response)
            {
                Some(announcement) => announcement,
                None => return false,
            };
        let implied_challenge = transcript.get_challenge(&self.sigma, &implied_announcement);
        implied_challenge == proof.challenge
    }
}

/// A proof produced by [`FiatShamir`].
///
/// It is called "compact" becasue it includes the challenge instead of all the announcements. It is
/// advantageous to include the announcements instead if you are implementing batch verification for
/// the underlying group's Sigma protocol but this isn't implemented yet.
///
/// [`FiatShamir`]: crate::FiatShamir
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CompactProof<S: Sigma> {
    /// C
    pub challenge: GenericArray<u8, S::ChallengeLength>,
    /// R
    pub response: S::Response,
}
