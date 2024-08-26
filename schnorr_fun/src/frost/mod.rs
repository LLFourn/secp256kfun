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
//! let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();
//!
//! // This runs a 2-of-3 key generation on a single computer which means it's a trusted party.
//! // See the documentation/API of the protocols in `chilldkg` to see how to distrubute the key generation properly.
//! let (shared_key, secret_shares) = simplepedpop::simulate_keygen(&schnorr, 2, 3,3, &mut rand::thread_rng());
//! let my_secret_share = secret_shares[0];
//! let my_index = my_secret_share.index();
//! # let secret_share2 = secret_shares[1];
//! # let secret_share3 = secret_shares[2];
//! # let party_index3 = secret_share3.index();
//!
//! let frost = frost::new_with_deterministic_nonces::<Sha256>();
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
//! Signatures]*.
//!
//! > ⚠ At this stage this implementation is for API exploration purposes only. The way it is
//! > currently implemented is not proven secure.
//!
//! [FROST]: <https://eprint.iacr.org/2020/852.pdf>
//! [secp256k1-zkp]: <https://github.com/ElementsProject/secp256k1-zkp/pull/138>
//! [Security of Multi- and Threshold Signatures]: <https://eprint.iacr.org/2021/1375.pdf>
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
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::num::NonZeroU32;
use secp256kfun::{
    derive_nonce_rng, g,
    hash::{Hash32, HashAdd, Tag},
    marker::*,
    nonce::{self, NonceGen},
    poly,
    rand_core::{RngCore, SeedableRng},
    s, Point, Scalar, G,
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
/// - `H`: hash type for challenges, keygen_id, and binding coefficient.
/// - `NG`: nonce generator for proofs-of-possessions and FROST nonces
#[derive(Clone)]
pub struct Frost<H, NG> {
    /// The instance of the Schnorr signature scheme.
    pub schnorr: Schnorr<H, NG>,
    /// The hash used to generate the nonce binding coefficient when signing.
    binding_hash: H,
    /// The hash used to generate the `keygen_id`
    keygen_id_hash: H,
    /// Nonce generator.
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
            keygen_id_hash: H::default().tag(b"frost/keygenid"),
            nonce_gen: schnorr.nonce_gen().clone().tag(b"frost"),
            schnorr,
        }
    }
}

/// A KeyGen (distributed key generation) session
///
/// Created using [`Frost::new_keygen`]
///
/// [`Frost::new_keygen`]
#[derive(Clone, Debug)]
pub struct KeyGen {
    frost_poly: SharedKey<Normal>,
    point_polys: BTreeMap<PartyIndex, Vec<Point>>,
}

impl KeyGen {
    /// Return the number of parties in the KeyGen
    pub fn n_parties(&self) -> usize {
        self.point_polys.len()
    }
}

/// First round keygen errors
#[derive(Debug, Clone)]
pub enum NewKeyGenError {
    /// Received polynomial is of differing length.
    PolyDifferentLength(PartyIndex),
    /// Number of parties is less than the length of polynomials specifying the threshold.
    NotEnoughParties,
    /// Frost key is zero. Computationally unreachable *if* all parties are honest.
    ZeroFrostKey,
}

impl core::fmt::Display for NewKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use NewKeyGenError::*;
        match self {
            PolyDifferentLength(i) => write!(f, "polynomial commitment from party at index {i} was a different length"),
            NotEnoughParties => write!(f, "the number of parties was less than the threshold"),
            ZeroFrostKey => write!(f, "The frost public key was zero. Computationally unreachable, one party is acting maliciously."),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewKeyGenError {}

/// Second round KeyGen errors
#[derive(Debug, Clone)]
pub enum FinishKeyGenError {
    /// Secret share and proof of possession was not provided for this party
    MissingShare(PartyIndex),
    /// Secret share does not match what we expected
    InvalidShare(PartyIndex),
    /// proof-of-possession does not match the expected. Incorrect ordering?
    InvalidProofOfPossession(PartyIndex),
}

impl core::fmt::Display for FinishKeyGenError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use FinishKeyGenError::*;
        match self {
            MissingShare(i) => write!(f, "secret share was not provided for party {i}"),
            InvalidShare(i) => write!(
                f,
                "the secret share at index {i} does not match the expected evaluation \
                of their point polynomial at our index. Check that the order and our index is correct"
            ),
            &InvalidProofOfPossession(i) => write!(
                f,
                "the proof-of-possession provided by party at index {i} was invalid, check ordering."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FinishKeyGenError {}

impl<H: Hash32, NG: NonceGen> Frost<H, NG> {
    /// Convienence method to generate secret shares and proof-of-possession to be shared with other
    /// participants. Each secret share needs to be securely communicated to the intended
    /// participant but the proof of possession (schnorr signature) can be publically shared with
    /// everyone.
    pub fn create_shares_and_pop(
        &self,
        keygen: &KeyGen,
        scalar_poly: &[Scalar],
        pop_message: Message<Public>,
    ) -> (BTreeMap<PartyIndex, Scalar<Secret, Zero>>, Signature) {
        (
            keygen
                .point_polys
                .keys()
                .map(|party_index| (*party_index, self.create_share(scalar_poly, *party_index)))
                .collect(),
            self.create_proof_of_possession(scalar_poly, pop_message),
        )
    }

    /// Create proof-of-possession to prove ownership of the first term in our scalar polynomial.
    /// This does a Schnorr signature over the given message under the first term of the polynomial
    /// using the internal [`Schnorr`] instance.
    ///
    /// [`Schnorr`]: crate::Schnorr
    pub fn create_proof_of_possession(
        &self,
        scalar_poly: &[Scalar],
        message: Message,
    ) -> Signature {
        let key_pair = self.schnorr.new_keypair(scalar_poly[0]);
        self.schnorr.sign(&key_pair, message)
    }

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

    /// Run the key generation protocol while simulating the parties internally.
    ///
    /// This can be used to do generate a "trusted setup" FROST key (but it is extremely inefficient
    /// for this purpose). It returns the joint `SharedKey` along with the secret keys for each
    /// party.
    pub fn simulate_keygen(
        &self,
        threshold: usize,
        n_parties: usize,
        rng: &mut impl RngCore,
    ) -> (SharedKey<Normal>, Vec<PairedSecretShare<Normal>>) {
        let scalar_polys = (0..n_parties)
            .map(|i| {
                (
                    PartyIndex::from_non_zero_u32(
                        NonZeroU32::new((i + 1) as u32).expect("we added 1"),
                    )
                    .public(),
                    poly::scalar::generate(threshold, rng),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let keygen = self.new_keygen(Default::default(), &scalar_polys).unwrap();
        let mut shares = scalar_polys
            .into_iter()
            .map(|(party_index, sp)| {
                (
                    party_index,
                    self.create_shares_and_pop(&keygen, &sp, Message::<Public>::empty()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        // collect the received shares for each party
        let received_shares = keygen
            .point_polys
            .keys()
            .map(|receiver_party_index| {
                let received = shares
                    .iter_mut()
                    .map(|(gen_party_index, (party_shares, pop))| {
                        (
                            *gen_party_index,
                            (party_shares.remove(receiver_party_index).unwrap(), *pop),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();

                (*receiver_party_index, received)
            })
            .collect::<BTreeMap<_, _>>();

        let mut frost_key = None;
        // finish keygen for each party
        let secret_shares = received_shares
            .into_iter()
            .map(|(party_index, received_shares)| {
                let (secret_share, _frost_key) = self
                    .finish_keygen(
                        keygen.clone(),
                        party_index,
                        received_shares,
                        Message::<Public>::empty(),
                    )
                    .unwrap();

                frost_key = Some(_frost_key);
                secret_share
            })
            .collect();

        (frost_key.unwrap(), secret_shares)
    }
}

impl<H: Hash32, NG> Frost<H, NG> {
    /// Generate an id for the key generation by hashing the party indicies and their point
    /// polynomials
    pub fn keygen_id(&self, keygen: &KeyGen) -> [u8; 32] {
        let mut keygen_hash = self.keygen_id_hash.clone();
        keygen_hash.update((keygen.point_polys.len() as u32).to_be_bytes().as_ref());
        for (index, poly) in &keygen.point_polys {
            keygen_hash.update(index.to_bytes().as_ref());
            for point in poly {
                keygen_hash.update(point.to_bytes().as_ref());
            }
        }
        keygen_hash.finalize_fixed().into()
    }

    /// Collect all the public polynomials commitments into a [`KeyGen`] to produce a [`SharedKey`].
    ///
    /// It is crucial that at least one of these polynomials was not adversarially produced
    /// otherwise the adversary will know the eventual secret key.
    ///
    /// As a safety mechanism `local_secret_polys` allows you to pass in the secret scalar
    /// polynomials you control which will be converted into the public form internally. This way
    /// you don't trust what's in `point_polys` for the entries that you control. This protects
    /// against a malicious adversary who publishes a `point_polys` which replaces your entries with
    /// polynomial commitments it creates. If you don't use `local_secret_polys` you have to do
    /// protect against this in your application.
    ///
    /// Note that in any sensibly designed key generation `local_secret_polys` will only have one
    /// entry as there is no security benefit of one party controlling multiple key generation
    /// polynomials. If an entry is in both `point_polys` and `local_secret_polys` it will be
    /// silently overwritten with the one from `local_secret_polys`.
    pub fn new_keygen<S>(
        &self,
        mut point_polys: BTreeMap<PartyIndex, Vec<Point>>,
        local_secret_polys: &BTreeMap<PartyIndex, S>,
    ) -> Result<KeyGen, NewKeyGenError>
    where
        S: AsRef<[Scalar]>,
    {
        for (party_id, scalar_poly) in local_secret_polys {
            let image = poly::scalar::to_point_poly(scalar_poly.as_ref());
            let _existing = point_polys.insert(*party_id, image);
            if let Some(_existing) = _existing {
                debug_assert_eq!(_existing, poly::scalar::to_point_poly(scalar_poly.as_ref()));
            }
        }
        let len_first_poly = point_polys
            .iter()
            .next()
            .map(|(_, poly)| poly.len())
            .ok_or(NewKeyGenError::NotEnoughParties)?;
        {
            if let Some((i, _)) = point_polys
                .iter()
                .find(|(_, point_poly)| point_poly.len() != len_first_poly)
            {
                return Err(NewKeyGenError::PolyDifferentLength(*i));
            }

            // Number of parties is less than the length of polynomials specifying the threshold
            if point_polys.len() < len_first_poly {
                return Err(NewKeyGenError::NotEnoughParties);
            }
        }

        let mut joint_poly = (0..len_first_poly)
            .map(|_| Point::<NonNormal, Public, _>::zero())
            .collect::<Vec<_>>();

        for poly in point_polys.values() {
            for i in 0..len_first_poly {
                joint_poly[i] += poly[i];
            }
        }

        let frost_poly = SharedKey::from_poly(
            joint_poly
                .into_iter()
                .map(|coef| coef.normalize())
                .collect(),
        )
        .non_zero()
        .ok_or(NewKeyGenError::ZeroFrostKey)?;

        Ok(KeyGen {
            point_polys,
            frost_poly,
        })
    }

    /// Verify a key generation without being a key-owning party
    pub fn finish_keygen_coordinator(
        &self,
        keygen: KeyGen,
        proofs_of_possession: BTreeMap<PartyIndex, Signature>,
        proof_of_possession_msg: Message,
    ) -> Result<SharedKey<Normal>, FinishKeyGenError> {
        for (party_index, poly) in &keygen.point_polys {
            let pop = proofs_of_possession
                .get(party_index)
                .ok_or(FinishKeyGenError::MissingShare(*party_index))?;
            let (even_poly_point, _) = poly[0].into_point_with_even_y();

            if !self
                .schnorr
                .verify(&even_poly_point, proof_of_possession_msg, pop)
            {
                return Err(FinishKeyGenError::InvalidProofOfPossession(*party_index));
            }
        }

        Ok(keygen.frost_poly)
    }

    /// Combine all received shares into your long-lived secret share.
    ///
    /// The `secret_shares` includes your own share as well as shares from each of the other
    /// parties. The `secret_shares` are validated to match the expected result by evaluating their
    /// polynomial at our participant index. Each participant's proof-of-possession is verified
    /// against what they provided in the first round of key generation.
    ///
    /// The proof-of-possession message should be the unique keygen_id unless chosen otherwise.
    ///
    /// # Return value
    ///
    /// Your secret share and the [`SharedKey`]
    pub fn finish_keygen(
        &self,
        keygen: KeyGen,
        my_index: PartyIndex,
        secret_shares: BTreeMap<PartyIndex, (Scalar<Secret, Zero>, Signature)>,
        proof_of_possession_msg: Message,
    ) -> Result<(PairedSecretShare<Normal>, SharedKey<Normal>), FinishKeyGenError> {
        let mut total_secret_share = s!(0);

        for (party_index, poly) in &keygen.point_polys {
            let (secret_share, pop) = secret_shares
                .get(party_index)
                .ok_or(FinishKeyGenError::MissingShare(*party_index))?;
            let (even_poly_point, _) = poly[0].into_point_with_even_y();

            if !self
                .schnorr
                .verify(&even_poly_point, proof_of_possession_msg, pop)
            {
                return Err(FinishKeyGenError::InvalidProofOfPossession(*party_index));
            }

            let expected_public_share = poly::point::eval(poly, my_index);
            if g!(secret_share * G) != expected_public_share {
                return Err(FinishKeyGenError::InvalidShare(*party_index));
            }
            total_secret_share += secret_share;
        }

        let secret_share = SecretShare {
            index: my_index,
            share: total_secret_share,
        };

        let secret_share_with_image =
            PairedSecretShare::new(secret_share, keygen.frost_poly.public_key());

        Ok((secret_share_with_image, keygen.frost_poly))
    }

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
        let binding_coeff = self.binding_coefficient(public_key, agg_binonce, message);
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

        let binding_coeff = self.binding_coefficient(shared_key.public_key(), agg_binonce, message);
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
    ) -> Scalar<Public> {
        Scalar::from_hash(
            self.binding_hash
                .clone()
                .add(agg_binonce)
                .add(public_key)
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
    use sha2::Sha256;

    #[test]
    fn zero_agg_nonce_results_in_G() {
        let frost = new_with_deterministic_nonces::<Sha256>();
        let (frost_poly, _shares) = frost.simulate_keygen(2, 3, &mut rand::thread_rng());
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
