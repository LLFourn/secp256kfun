use crate::{
    ProverTranscript, Sigma, Transcript,
    generic_array::{ArrayLength, GenericArray},
};
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
    ) -> CompactProof<S::Response, S::ChallengeLength>
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
        CompactProof {
            challenge,
            response,
        }
    }

    /// Verifies the proof given the statement.
    #[must_use]
    pub fn verify(
        &self,
        statement: &S::Statement,
        proof: &CompactProof<S::Response, S::ChallengeLength>,
    ) -> bool {
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
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "R: serde::Serialize",
        deserialize = "R: serde::Deserialize<'de>"
    ))
)]
#[derive(Debug, Clone, PartialEq)]
pub struct CompactProof<R, L: ArrayLength<u8>> {
    /// C
    pub challenge: GenericArray<u8, L>,
    /// R
    pub response: R,
}

/// Implements bincode encoding for `CompactProof` for any challenge length.
#[cfg(feature = "bincode")]
#[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
impl<R, L> bincode::Encode for CompactProof<R, L>
where
    R: bincode::Encode,
    L: ArrayLength<u8>,
{
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        // Write the challenge bytes directly without length prefix
        <E::W as bincode::enc::write::Writer>::write(encoder.writer(), self.challenge.as_slice())?;
        self.response.encode(encoder)?;
        Ok(())
    }
}

#[cfg(feature = "bincode")]
#[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
impl<R, L, Context> bincode::Decode<Context> for CompactProof<R, L>
where
    R: bincode::Decode<Context>,
    L: ArrayLength<u8>,
{
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        // Create a default GenericArray and read directly into it
        let mut challenge = GenericArray::<u8, L>::default();
        <D::R as bincode::de::read::Reader>::read(decoder.reader(), challenge.as_mut_slice())?;

        let response = R::decode(decoder)?;

        Ok(CompactProof {
            challenge,
            response,
        })
    }
}

#[cfg(feature = "bincode")]
#[cfg_attr(docsrs, doc(cfg(feature = "bincode")))]
impl<'de, R, L, Context> bincode::BorrowDecode<'de, Context> for CompactProof<R, L>
where
    R: bincode::Decode<Context>,
    L: ArrayLength<u8>,
{
    fn borrow_decode<D: bincode::de::BorrowDecoder<'de, Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        bincode::Decode::decode(decoder)
    }
}
