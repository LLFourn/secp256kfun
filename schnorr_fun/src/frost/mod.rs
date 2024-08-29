//! The FROST threshold multisignature scheme.
//!
//! ## Synopsis
//!
//! ```
//! use schnorr_fun::binonce::NonceKeyPair;
//! use schnorr_fun::fun::{s, poly};
//! use schnorr_fun::{
//!     frost::{self, chilldkg::simplepedpop},
//!     Message,
//! };
//! use std::collections::BTreeMap;
//! use rand_chacha::ChaCha20Rng;
//! use sha2::Sha256;
//!
//! let frost = frost::new_with_deterministic_nonces::<Sha256>();
//!
//! // This runs a 2-of-3 key generation on a single computer which means it's a trusted party.
//! // See the documentation/API of the protocols in `chilldkg` to see how to distrubute the key generation properly.
//! let (shared_key, secret_shares) = simplepedpop::simulate_keygen(&frost.schnorr, 2, 3,3, &mut rand::thread_rng());
//! let my_secret_share = secret_shares[0];
//! let my_index = my_secret_share.index();
//! # let secret_share2 = secret_shares[1];
//! # let secret_share3 = secret_shares[2];
//! # let party_index3 = secret_share3.index();
//!
//!
//! // With signing we'll have at least one party be the "coordinator" (steps marked with 🐙)
//! // In this example we'll be the coordinator (but it doesn't have to be one of the signing parties)
//! let xonly_shared_key = shared_key.into_xonly(); // this is the key signatures will be valid under
//! let xonly_my_secret_share = my_secret_share.into_xonly();
//! # let xonly_secret_share3 = secret_share3.into_xonly();
//! let message =  Message::plain("my-app", b"chancellor on brink of second bailout for banks");
//! // Generate nonces for this signing session (and send them to coordinator somehow)
//! // ⚠ session_id MUST be different for every signing attempt to avoid nonce reuse (if using deterministic nonces).
//! let session_id = b"signing-ominous-message-about-banks-attempt-1".as_slice();
//! let mut nonce_rng: ChaCha20Rng = frost.seed_nonce_rng(my_secret_share, session_id);
//! let my_nonce = frost.gen_nonce(&mut nonce_rng);
//! # let nonce3 = NonceKeyPair::random(&mut rand::thread_rng());
//! // share your public nonce with the other signing participant(s) receive public nonces
//! # let received_nonce3 = nonce3.public();
//! // 🐙 the coordinator has received the nonces
//! let nonces = BTreeMap::from_iter([(my_index, my_nonce.public()), (party_index3, received_nonce3)]);
//! let coord_session = frost.coordinator_sign_session(&xonly_shared_key, nonces, message);
//! // Parties receive the agg_nonce from the coordiantor and the list of perties
//! let agg_binonce = coord_session.agg_binonce();
//! let parties = coord_session.parties();
//! // start a sign session with these nonces for a message
//! let sign_session = frost.party_sign_session(xonly_my_secret_share.public_key(),parties, agg_binonce, message);
//! // create a partial signature using our secret share and secret nonce
//! let my_sig_share = sign_session.sign(&xonly_my_secret_share, my_nonce);
//! # let sig_share3 = sign_session.sign(&xonly_secret_share3, nonce3);
//! // 🐙 receive the partial signature(s) from the other participant(s).
//! // 🐙 combine signature shares into a single signature that is valid under the FROST key
//! let combined_sig = coord_session.verify_and_combine_signature_shares(
//!     &xonly_shared_key,
//!     [(my_index, my_sig_share), (party_index3, sig_share3)].into()
//! )?;
//! assert!(frost.schnorr.verify(
//!     &xonly_shared_key.public_key(),
//!     message,
//!     &combined_sig
//! ));
//!
//! # Ok::<(), schnorr_fun::frost::VerifySignatureSharesError>(())
//! ```
//!
//! # Description
//!
//! In FROST, multiple parties cooperatively generate a single joint public key ([`SharedKey`]) for
//! creating Schnorr signatures. Unlike in [`musig`], only some threshold `t` of the `n` signers are
//! required to generate a signature under the key (rather than all `n`).
//!
//! This implementation is **not** yet compatible with other existing FROST
//! implementations (notably [secp256k1-zkp]).
//!
//! The original scheme was introduced in *[FROST: Flexible Round-Optimized Schnorr Threshold
//! Signatures][FROST]*. A more satisfying security proof was provided in *[Security of Multi- and Threshold
//! Signatures]*. This implementation follows most closely *[Practical Schnorr Threshold Signatures Without the Algebraic Group Model]*.
//!
//! > ⚠ CAUTION ⚠: We *think* that this follows the scheme in the "Practical" paper which is proven secure but
//! > we haven't put a lot of effort into verifying this yet.
//!
//! [FROST]: <https://eprint.iacr.org/2020/852.pdf>
//! [secp256k1-zkp]: <https://github.com/ElementsProject/secp256k1-zkp/pull/138>
//! [Security of Multi- and Threshold Signatures]: <https://eprint.iacr.org/2021/1375.pdf>
//! [Practical Schnorr Threshold Signatures Without the Algebraic Group Model]: https://eprint.iacr.org/2023/899
//! [`musig`]: crate::musig
//! [`Scalar`]: crate::fun::Scalar

mod shared_key;
pub use shared_key::*;
mod share;
pub use share::*;
mod session;
pub use session::*;
pub mod chilldkg;
pub use crate::binonce::{Nonce, NonceKeyPair};
use crate::{binonce, Message, Schnorr, Signature};
use alloc::collections::{BTreeMap, BTreeSet};
use core::num::NonZeroU32;
use secp256kfun::{
    derive_nonce_rng,
    hash::{Hash32, HashAdd, Tag},
    nonce::{self, NonceGen},
    poly,
    prelude::*,
    rand_core::{RngCore, SeedableRng},
};

/// The index of a party's secret share.
///
/// This index and its secret share define a point on the joint secret polynomial.
/// It is used in interpolation and computation of the shared secret.
///
/// This index can be any non-zero [`Scalar`], but must be unique between parties.
/// In most cases it will make sense to use simple indices `s!(1), s!(2), ...` for smaller backups.
/// Other applications may desire to use indices corresponding to pre-existing keys or identifiers.
pub type PartyIndex = Scalar<Public, NonZero>;

/// The FROST context.
///
/// Type parameters:
///
/// - `H`: hash type for challenges, and binding coefficient.
/// - `NG`: nonce generator for FROST nonces (only used if you explicitly call nonce generation functions).
#[derive(Clone)]
pub struct Frost<H, NG> {
    /// The instance of the Schnorr signature scheme.
    pub schnorr: Schnorr<H, NG>,
    /// The hash used to generate the nonce binding coefficient when signing.
    binding_hash: H,
    /// Usually a tagged clone of the schnorr nonce generator.
    nonce_gen: NG,
}

impl<H, NG> Default for Frost<H, NG>
where
    H: Hash32,
    NG: Default + Tag + Clone,
{
    fn default() -> Self {
        Frost::new(Schnorr::default())
    }
}

impl<H, NG> Frost<H, NG> {
    /// Generate nonces for creating signatures shares.
    ///
    /// ⚠ You must use a CAREFULLY CHOSEN nonce rng, see [`Frost::seed_nonce_rng`]
    pub fn gen_nonce<R: RngCore>(&self, nonce_rng: &mut R) -> NonceKeyPair {
        NonceKeyPair::random(nonce_rng)
    }

    /// Get the [`NonceGen`] that this frost instance is using in [`Frost::seed_nonce_rng`].
    ///
    /// [`NonceGen`]: secp256kfun::nonce::NonceGen
    pub fn nonce_gen(&self) -> &NG {
        &self.nonce_gen
    }

    /// Create our secret shares to be shared with other participants using pre-existing indices
    ///
    /// Each secret share needs to be securely communicated to the intended participant.
    ///
    /// ## Return value
    ///
    /// Returns a vector of secret shares where the index represents the signer index
    pub fn create_share(
        &self,
        scalar_poly: &[Scalar],
        party_index: Scalar<impl Secrecy>,
    ) -> Scalar<Secret, Zero> {
        poly::scalar::eval(scalar_poly, party_index)
    }
}

impl<H, NG> Frost<H, NG>
where
    H: Tag + Default,
    NG: Tag + Clone,
{
    /// Generate a new Frost context from a Schnorr context.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::{frost::Frost, nonce::Deterministic, Schnorr};
    /// use sha2::Sha256;
    /// let schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::default();
    /// let frost = Frost::new(schnorr);
    /// ```
    pub fn new(schnorr: Schnorr<H, NG>) -> Self {
        Self {
            binding_hash: H::default().tag(b"frost/binding"),
            nonce_gen: schnorr.nonce_gen().clone().tag(b"frost"),
            schnorr,
        }
    }
}

impl<H: Hash32, NG: NonceGen> Frost<H, NG> {
    /// Seed a random number generator to be used for FROST nonces.
    ///
    /// ** ⚠ WARNING ⚠**: This method is unstable and easy to use incorrectly. The seed it uses for
    /// the Rng will change without warning between minor versions of this library.
    ///
    /// Parameters:
    ///
    /// - `frost_key`: the joint public key we are signing under. This can be an `EvenY` or `Normal`
    ///    It will return the same nonce regardless.
    /// - `secret`: you're secret key share for the `frost_key`
    /// - `session_id`: a string of bytes that is **unique for each signing attempt**.
    ///
    /// The application should decide upon a unique `session_id` per call to this function. If the
    /// `NonceGen` of this FROST instance is `Deterministic` then the `session_id` **must** be
    /// unique per signing attempt -- even if the signing attempt fails to produce a signature you
    /// must not reuse the session id, the resulting rng or anything derived from that rng again.
    ///
    /// 💡 Before using this function with a deterministic rng write a short justification as to why
    /// you believe your session id will be unique per signing attempt. Perhaps include it as a
    /// comment next to the call. Note **it must be unique even across signing attempts for the same
    /// or different messages**.
    ///
    /// The rng returned can be used to create many nonces. For example, when signing a
    /// Bitcoin transaction you may need to sign several inputs each with their own signature. It is
    /// intended here that you call this once for the transaction and pull several nonces out of the
    /// resulting rng for each input.
    pub fn seed_nonce_rng<R: SeedableRng<Seed = [u8; 32]>>(
        &self,
        paired_secret_share: PairedSecretShare<impl Normalized>,
        session_id: &[u8],
    ) -> R {
        let sid_len = (session_id.len() as u64).to_be_bytes();
        let pk_bytes = paired_secret_share.public_key().to_xonly_bytes();

        let rng: R = derive_nonce_rng!(
            nonce_gen => self.nonce_gen(),
            secret => paired_secret_share.share(),
            public => [pk_bytes, sid_len, session_id],
            seedable_rng => R
        );
        rng
    }
}

impl<H: Hash32, NG> Frost<H, NG> {
    /// Aggregate the nonces of the signers so you can start a [`party_sign_session`] without a
    /// coordinator.
    ///
    /// [`party_sign_session`]: Self::party_sign_session
    pub fn aggregate_binonces(
        &self,
        nonces: impl IntoIterator<Item = Nonce>,
    ) -> binonce::Nonce<Zero> {
        binonce::Nonce::aggregate(nonces)
    }

    /// Start party signing session
    pub fn party_sign_session(
        &self,
        public_key: Point<EvenY>,
        parties: BTreeSet<PartyIndex>,
        agg_binonce: binonce::Nonce<Zero>,
        message: Message,
    ) -> PartySignSession {
        let binding_coeff = self.binding_coefficient(public_key, agg_binonce, message, &parties);
        let (final_nonce, binonce_needs_negation) = agg_binonce.bind(binding_coeff);
        let challenge = self.schnorr.challenge(&final_nonce, &public_key, message);

        PartySignSession {
            public_key,
            parties,
            binding_coeff,
            challenge,
            binonce_needs_negation,
            final_nonce,
        }
    }

    /// Start a FROST signing session as a *coordinator*.
    ///
    /// The corodinator must have collected nonces from each of the signers and pass them in as `nonces`.
    /// From there
    ///
    /// # Panics
    ///
    /// If the number of nonces is less than the threshold.
    pub fn coordinator_sign_session(
        &self,
        shared_key: &SharedKey<EvenY>,
        mut nonces: BTreeMap<PartyIndex, Nonce>,
        message: Message,
    ) -> CoordinatorSignSession {
        if nonces.len() < shared_key.threshold() {
            panic!("nonces' length was less than the threshold");
        }

        let agg_binonce = binonce::Nonce::aggregate(nonces.values().cloned());

        let binding_coeff = self.binding_coefficient(
            shared_key.public_key(),
            agg_binonce,
            message,
            &nonces.keys().cloned().collect(),
        );
        let (final_nonce, binonce_needs_negation) = agg_binonce.bind(binding_coeff);

        let challenge = self
            .schnorr
            .challenge(&final_nonce, &shared_key.public_key(), message);

        for nonce in nonces.values_mut() {
            nonce.conditional_negate(binonce_needs_negation);
        }

        CoordinatorSignSession {
            binding_coeff,
            agg_binonce,
            final_nonce,
            challenge,
            nonces,
            public_key: shared_key.public_key(),
        }
    }

    fn binding_coefficient(
        &self,
        public_key: Point<EvenY>,
        agg_binonce: Nonce<Zero>,
        message: Message,
        parties: &BTreeSet<PartyIndex>,
    ) -> Scalar<Public> {
        Scalar::from_hash(
            self.binding_hash
                .clone()
                .add(public_key)
                .add((parties.len() as u32).to_be_bytes())
                .add(parties)
                .add(agg_binonce)
                .add(message),
        )
        .public()
    }
}

/// Constructor for a Frost instance using deterministic nonce generation.
///
/// If you use deterministic nonce generation you will have to provide a unique session id to every signing session.
/// The advantage is that you will be able to regenerate the same nonces at a later point from [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_deterministic_nonces::<sha2::Sha256>();
/// ```
pub fn new_with_deterministic_nonces<H>() -> Frost<H, nonce::Deterministic<H>>
where
    H: Hash32,
{
    Frost::default()
}

/// Constructor for a Frost instance using synthetic nonce generation.
///
/// Synthetic nonce generation mixes in external randomness into nonce generation which means you
/// don't need a unique session id for each signing session to guarantee security. The disadvantage
/// is that you may have to store and recall somehow the nonces generated from
/// [`Frost::gen_nonce`].
///
/// ```
/// use schnorr_fun::frost;
/// let frost = frost::new_with_synthetic_nonces::<sha2::Sha256, rand::rngs::ThreadRng>();
/// ```
pub fn new_with_synthetic_nonces<H, R>() -> Frost<H, nonce::Synthetic<H, nonce::GlobalRng<R>>>
where
    H: Hash32,
    R: RngCore + Default + Clone,
{
    Frost::default()
}

/// Create a Frost instance which does not handle nonce generation.
///
/// You can still sign with this instance but you you will have to generate nonces in your own way.
pub fn new_without_nonce_generation<H>() -> Frost<H, nonce::NoNonces>
where
    H: Hash32,
{
    Frost::default()
}

#[cfg(test)]
mod test {

    use super::*;
    use chilldkg::simplepedpop;
    use sha2::Sha256;

    #[test]
    fn zero_agg_nonce_results_in_G() {
        let frost = new_with_deterministic_nonces::<Sha256>();
        let (frost_poly, _shares) =
            simplepedpop::simulate_keygen(&frost.schnorr, 2, 3, 3, &mut rand::thread_rng());
        let nonce = NonceKeyPair::random(&mut rand::thread_rng()).public();
        let mut malicious_nonce = nonce;
        malicious_nonce.conditional_negate(true);

        let session = frost.coordinator_sign_session(
            &frost_poly.into_xonly(),
            BTreeMap::from_iter([(s!(1).public(), nonce), (s!(2).public(), malicious_nonce)]),
            Message::<Public>::plain("test", b"hello"),
        );

        assert_eq!(session.final_nonce(), *G);
    }
}
