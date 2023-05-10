//! Blind Schnorr Signatures
//!
//! Produce a Schnorr signature where the signer does not know what they have signed.
//!
//! ⚠ When running multiple sessions in parallel a signing server must use `sign`
//! which will randomly fail on 1 out of `max_sessions` signing requests.
//! This is to prevent [Wagner attack]s, where concurrent signing sessions can allow for a forgery.
//!
//! # Summary
//!
//! A blind signing server (with public key `X = x*G`) sends a public nonce (`R = k*G`) to a user
//! who wants to have a message signed. This user generates two random scalars (alpha, beta) and
//! uses them to blinds the signing server's nonce (`R' = R + alpha*G + beta*X`).
//!
//! The user then creates challenge for some message (`M`) they want signed, using these blinding
//! values (`c = H[R'|X|M]`), and then this challenge is then blinded itself also (`c' = c + beta`).
//! The blinded challenge is sent to the signing server who then signs it (`s = k + c'*x`).
//!
//! Once the user recieves the blinded signature, they can unblind it (`s' = s + alpha).
//! The unblinded signature (`s', R'`) is a valid schnorr signature under the public key (`X`).
//! The signer can not correlate this signature-nonce pair even if they know the public key,
//! signature, message, and nonce.
//!
//! This implementation was helped a lot by this [SuredBits article] and follows security fixes from
//! [Blind Schnorr Signatures in the Algebraic Group Model].
//!
//! [Wagner attack]: <https://www.iacr.org/archive/crypto2002/24420288/24420288.pdf>
//! [SuredBits article]: <https://suredbits.com/schnorr-applications-blind-signatures/>
//! [Blind Schnorr Signatures in the Algebraic Group Model]: <https://eprint.iacr.org/2019/877.pdf>
//!
//! # Synopsis
//! ```
//! use schnorr_fun::{blind, Message, Schnorr, nonce};
//! use secp256kfun::{g, marker::Public, Scalar, G, derive_nonce, nonce::Deterministic};
//! use rand::rngs::ThreadRng;
//! use sha2::Sha256;
//!
//! let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
//! let user_schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
//! let server_schnorr = Schnorr::<Sha256, _>::new(nonce_gen);
//! // Generate a secret key for the blind signing server
//! let mut secret = Scalar::random(&mut rand::thread_rng());
//! // The user wants a single blind signature but must initiate two signing sessions, one will fail.
//! // This is to prevent Wagner attacks where many parallel signing sessions can allow forgery.
//! let n_sessions = 2;
//! let mut blind_signer = blind::BlindSigner::new(n_sessions, secret, server_schnorr);
//!
//! // The blind signing server sends out two public nonces, one received for each session
//! let mut pub_nonces = vec![];
//! for i in 0..n_sessions {
//!     pub_nonces.push(blind_signer.gen_nonce(format!("extremely-unique-session-id-{}", i).as_bytes()));
//! }
//!
//! // The user is wants the server to sign a message without knowing what it is
//! let message = Message::<Public>::plain("test", b"sign me up");
//!
//! // The user then blinds the received nonces and creates blind challenges for the message
//! let blind_sessions: Vec<_> = pub_nonces
//!     .iter()
//!     .map(|pub_nonce| {
//!         blind::Blinder::blind(
//!             message,
//!             *pub_nonce,
//!             blind_signer.public_key(),
//!             user_schnorr.clone(),
//!             &mut rand::thread_rng(),
//!         )
//!     })
//!     .collect();
//!
//! // The user creates signature requests for signatures on the blinded challenges
//! let mut signature_requests: Vec<_> = blind_sessions
//!     .iter()
//!     .map(|session| session.signature_request())
//!     .collect();
//!
//! // Sign each signature request with the blind signer
//! let session_signatures = blind_signer.sign(
//!         signature_requests[0].clone(),
//!         &mut rand::thread_rng(),
//!     );
//! // Nothing is signed after the first request
//! assert_eq!(session_signatures.len(), 0);
//!
//! let session_signatures = blind_signer.sign(
//!         signature_requests[1].clone(),
//!         &mut rand::thread_rng(),
//!     );
//! // A response is given for both requests
//! assert_eq!(session_signatures.len(), 2);
//!
//! // One of the sessions will drop out, and will not receive a signature.
//! // We can take the signature we receive in the other session, and unblind it, revealing a
//! // completely uncorrelated signature for the message that is also valid under the public key.
//! for (blind_session, blind_signature) in blind_sessions.iter().zip(session_signatures) {
//!     match blind_signature {
//!         Some(blind_signature) => {
//!             let unblinded_signature = blind_session.unblind(blind_signature);
//!             // Validate the unblinded signature against the public key
//!             assert!(user_schnorr.verify(&blind_signer.public_key(), message, &unblinded_signature));
//!         }
//!         None => {}
//!     }
//! }
//! ```

use alloc::collections::BTreeMap;

use crate::{
    fun::rand_core::{CryptoRng, RngCore},
    Message, Schnorr, Signature,
};
use alloc::vec::Vec;
use rand::Rng;
use secp256kfun::{
    derive_nonce,
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    nonce::NonceGen,
    s, Point, Scalar, Tag, G,
};

/// Apply [`BlindingTweaks`] to create the blinded challenge and nonce
///
/// # Returns
///
/// A blinded_nonce and a blinded_challenge;
/// Also returns a needs_negation for the blinded nonce
pub fn create_blinded_challenge<H: Digest<OutputSize = U32> + Clone, NG>(
    nonce: Point<EvenY>,
    public_key: Point<EvenY>,
    message: Message,
    schnorr: Schnorr<H, NG>,
    blinding_tweaks: &mut BlindingTweaks,
) -> (Point, Scalar, bool) {
    let blinded_nonce = g!(nonce + blinding_tweaks.alpha * G + blinding_tweaks.beta * public_key)
        .normalize()
        .non_zero()
        .expect("added tweak is random");

    // we're actually going to discard these tweaks if the blinded nonce does need negation,
    // if we assert that we sample an even blinded nonce, then we have less to communicate
    let (xonly_blinded_nonce, blinded_nonce_needs_negation) =
        blinded_nonce.into_point_with_even_y();

    let blinded_challenge = s!(
        { schnorr.challenge(&xonly_blinded_nonce, &public_key, message,) } + blinding_tweaks.beta
    )
    .non_zero()
    .expect("added tweak is random");

    (
        blinded_nonce,
        blinded_challenge,
        blinded_nonce_needs_negation,
    )
}

/// Unblind a blind signature
///
/// # Returns
///
/// Returns a scalar signature
pub fn unblind_signature(
    blinded_signature: Scalar<Public, Zero>,
    alpha: &Scalar<Secret, NonZero>,
) -> Scalar<Public, Zero> {
    s!(blinded_signature + alpha).public()
}

/// The tweaks used for blinding the nonce and challenge, later used to unblind the signature
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct BlindingTweaks {
    /// tweak value alpha
    pub alpha: Scalar,
    /// tweak value beta
    pub beta: Scalar,
}

impl BlindingTweaks {
    /// Create new set of [`BlindingTweaks`] from an rng source
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            alpha: Scalar::random(rng),
            beta: Scalar::random(rng),
        }
    }
}

/// Blinder holds a blinded signature context which is later used to unblind the signature
#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
pub struct Blinder {
    /// tweaked public nonce R' = R + alpha*G + beta * X
    pub blinded_nonce: Point,
    /// tweaked challenge c' = c + beta
    pub challenge: Scalar,
    /// blinding values
    pub blinding_tweaks: BlindingTweaks,
    /// original public nonce received from signing server
    public_nonce: Point<EvenY>,
}

impl Blinder {
    /// Prepare a blinded challenge for the server to sign, and blind the nonce which we
    /// recieved from the server.
    ///
    /// Grinds new random [`BlindingTweaks`] until the blinded nonce does not need negation.
    ///
    /// # Returns
    ///
    /// Returns a Blinder session, which is later used to unblind the signature once signed
    pub fn blind<
        H: Digest<OutputSize = U32> + Clone,
        NG: Tag + NonceGen + Clone,
        R: RngCore + CryptoRng,
    >(
        message: Message,
        public_nonce: Point<EvenY>,
        public_key: Point<EvenY>,
        schnorr: Schnorr<H, NG>,
        rng: &mut R,
    ) -> Self {
        loop {
            // we continually grind blinding tweaks until we find some that result in us not needing
            // any negation
            let blinding_tweaks = BlindingTweaks::new(rng);
            let (nonce_needs_negation, blinder) = Blinder::from_tweaks(
                message,
                public_nonce,
                public_key,
                blinding_tweaks,
                schnorr.clone(),
            );
            if !nonce_needs_negation {
                break blinder;
            }
        }
    }

    /// Load blinding tweaks from previously randomly generated scalars, for reloading state
    pub fn from_tweaks<H: Digest<OutputSize = U32> + Clone, NG: Tag + NonceGen + Clone>(
        message: Message,
        public_nonce: Point<EvenY>,
        public_key: Point<EvenY>,
        mut blinding_tweaks: BlindingTweaks,
        schnorr: Schnorr<H, NG>,
    ) -> (bool, Self) {
        let (blinded_nonce, blinded_challenge, nonce_needs_negation) = create_blinded_challenge(
            public_nonce,
            public_key,
            message,
            schnorr,
            &mut blinding_tweaks,
        );

        (nonce_needs_negation, Blinder {
            blinded_nonce,
            challenge: blinded_challenge,
            blinding_tweaks,
            public_nonce,
        })
    }

    /// Unblind a blinded signature
    ///
    /// # Returns
    ///
    /// A schnorr signature that should be valid under the public key and blinded nonce
    pub fn unblind(&self, blinded_signature: Scalar<Public, Zero>) -> Signature {
        let sig = unblind_signature(blinded_signature, &self.blinding_tweaks.alpha);
        Signature {
            s: sig,
            R: self.blinded_nonce.into_point_with_even_y().0,
        }
    }

    /// Create the signature request containing the blinded challenge and nonce
    ///
    /// # Returns
    ///
    /// A [`SignatureRequest`] with a blind_challenge (and needs negations)
    pub fn signature_request(&self) -> SignatureRequest {
        SignatureRequest {
            blind_challenge: self.challenge.clone(),
            public_nonce: self.public_nonce,
        }
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(crate::serde::Deserialize, crate::serde::Serialize),
    serde(crate = "crate::serde")
)]
/// A signature request which will be sent to the signing server
pub struct SignatureRequest {
    /// Blinded challenge request to the signing server
    pub blind_challenge: Scalar,
    /// Public nonce to sign under
    pub public_nonce: Point<EvenY>,
}

/// A blind signing server
///
/// Generates nonces with internal schnorr, extreme care must be taken when choosing a [`NonceGen`].
/// Keeps track of `nonces` generated and only signs under these nonces, discarding them after use.
///
/// Signature requests come in one at a time with [`BlindSigner::sign`], and none of the requests
/// are signed until there are `max_sessions` of them. Then all but one of the requests are signed
/// to prevent parrallel signing attacks (unless max_sessions is one, then signing is immediate).
pub struct BlindSigner<CH, NG> {
    /// schnorr instance for this signing server
    pub schnorr: Schnorr<CH, NG>,
    max_sessions: usize,
    signature_requests: Vec<SignatureRequest>,
    nonces: Vec<(Point<EvenY>, Scalar)>,
    already_signed: BTreeMap<Point<EvenY>, Option<Scalar<Public, Zero>>>,
    secret: Scalar,
}

impl<CH, NG> BlindSigner<CH, NG>
where
    NG: Tag + NonceGen + Clone,
{
    /// Create a new blind signer to track a number of concurrent sessions
    pub fn new(max_sessions: usize, mut secret: Scalar, schnorr: Schnorr<CH, NG>) -> Self {
        // We always want to sign under the secret which corresponse to our EvenY public key.
        // This avoids keeping track of needs negations.
        let (_, secret_needs_negation) = g!(secret * G).normalize().into_point_with_even_y();
        secret.conditional_negate(secret_needs_negation);

        Self {
            max_sessions,
            signature_requests: vec![],
            nonces: vec![],
            already_signed: BTreeMap::new(),
            secret,
            schnorr,
        }
    }

    /// Get the public key for the blind signing server
    pub fn public_key(&self) -> Point<EvenY> {
        let (pk, needs_negation) = g!(self.secret * G).normalize().into_point_with_even_y();
        assert!(!needs_negation);
        pk
    }

    /// Fetch a list of current session nonces
    ///
    /// # Returns
    ///
    /// A list of public nonces we are currently willing to sign under.
    /// Sessions are ordered from first received to last.
    pub fn current_session_nonces(&self) -> impl Iterator<Item = Point<EvenY>> {
        self.nonces
            .clone()
            .into_iter()
            .map(|(public_nonce, _)| public_nonce)
    }

    /// Lookup past signatures using their public nonce. Useful for async polling with many sessions
    pub fn lookup_signed(
        &self,
        public_nonce: Point<EvenY>,
    ) -> Option<Option<Scalar<Public, Zero>>> {
        self.already_signed.get(&public_nonce).cloned()
    }

    /// Generate a nonce to share with users who are requesting blind signatures
    ///
    /// ⚠ Extreme care must be talen with the choice of [`NonceGen`] on the servers' Schnorr,
    /// in order to ensure each generated nonce is unique and never reused.
    ///
    /// # Returns a nonce
    pub fn gen_nonce(&mut self, sid: &[u8]) -> Point<EvenY> {
        let mut nonce = derive_nonce!(
            nonce_gen => self.schnorr.nonce_gen(),
            secret => self.secret,
            public => [ sid ]
        );
        let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
        nonce.conditional_negate(nonce_negated);
        // If there are too many nonces we need to kick one of them out
        if self.nonces.len() >= self.max_sessions {
            self.already_signed.insert(pub_nonce, None);
            self.nonces.remove(0);
        }
        self.nonces.push((pub_nonce, nonce));
        assert!(self.nonces.len() <= self.max_sessions);
        pub_nonce
    }

    /// Fetch the secret nonce for some public nonce and forget it
    fn use_secret_nonce(&mut self, public_nonce: Point<EvenY>) -> Option<Scalar> {
        for (i, (public, _)) in self.nonces.iter().enumerate() {
            if *public == public_nonce {
                let (_, secret) = self.nonces.remove(i);
                return Some(secret);
            }
        }
        None
    }

    /// Sign a blinded challenge and delete the associated secret_nonce
    ///
    /// ⚠ This should never be called concurrently! Use `sign` to safely sign multiple requests.
    ///
    /// Forgets the corresponding secret nonce to the request's public nonce after use.
    /// Returns [`None`] if we are unwilling to use the public nonce in the signature request.
    ///
    /// # Returns
    ///
    /// Returns a scalar of the unblinded signature
    pub fn sign_single(&mut self, sig_request: SignatureRequest) -> Option<Scalar<Public, Zero>> {
        let secret_nonce = self.use_secret_nonce(sig_request.public_nonce);
        let signature_response = match secret_nonce {
            Some(secret_nonce) => {
                let sig = s!(secret_nonce + sig_request.blind_challenge * self.secret).public();
                Some(sig)
            }
            // Did not expect this nonce
            None => None,
        };
        // Store this signature
        self.already_signed
            .insert(sig_request.public_nonce, signature_response);
        signature_response
    }

    /// Sign all the signature requests immediately, except for one
    ///
    /// # Returns
    ///
    /// A vector of scalar signature options
    pub fn sign_all_now<R: RngCore>(&mut self, rng: &mut R) -> Vec<Option<Scalar<Public, Zero>>> {
        // Choose an index to skip signing request
        let skip_i = rng.gen_range(0..self.signature_requests.len() as u32);

        // Sign all the signature requests but don't store one (given there is more than one)
        let signatures = self
            .signature_requests
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, sig_request)| {
                // We we are collecting more than one signature in parallel, then we need to randomly
                // disconnect one of the signatures (overwrite) and forget the secret nonce session
                let sig_response = if self.max_sessions > 1 && i as u32 == skip_i {
                    // For one out of the N sessions, drop the signature.
                    // ⚠ IMPORTANT: Overwrite the stored signature for this nonce
                    self.already_signed.insert(sig_request.public_nonce, None);
                    let _ = self.use_secret_nonce(sig_request.public_nonce);

                    assert!(self
                        .already_signed
                        .get(&sig_request.public_nonce)
                        .expect("history has to have None written for this nonce")
                        .is_none());
                    None
                } else {
                    // Otherwise, sign and store the signature
                    self.sign_single(sig_request)
                };
                sig_response
            })
            .collect();

        // Clear our signature requests
        self.signature_requests = vec![];
        signatures
    }

    /// Queue a signature request for parallel blind signing
    ///
    /// ⚠ You must use this function when running multiple blind signing sessions in parallel.
    ///
    /// Pools until max_sessions requests have been made. You can use it in conjunction with
    /// [`BlindSigner::sign_all_now`] if less than max_sessions are required after some timeout.
    ///
    /// No sessions are signed until max_session [`SignatureRequest`]s have been requested.
    /// Then signs them all but randomly disconnects (returns None) one of the N sessions.
    /// Disconnect only occurs provided N > 1.
    ///
    /// # Returns
    ///
    /// A vector of scalar signature options
    pub fn sign<R: RngCore>(
        &mut self,
        signature_request: SignatureRequest,
        rng: &mut R,
    ) -> Vec<Option<Scalar<Public, Zero>>> {
        // Return nothing if this public nonce is not expected for signing
        if !self
            .current_session_nonces()
            .any(|public_nonce| public_nonce == signature_request.public_nonce)
        {
            return vec![];
        }
        // Store this signature request
        self.signature_requests.push(signature_request);

        // Have we gathered all our concurrent sessions? Return empty vector if not.
        if self.max_sessions > 1 && self.signature_requests.len() < self.max_sessions {
            vec![]
        } else {
            self.sign_all_now(rng)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Message, Schnorr};
    use rand::rngs::ThreadRng;
    use secp256kfun::{
        nonce::{Deterministic, GlobalRng, Synthetic},
        proptest::{arbitrary::any, proptest},
        Scalar,
    };
    use sha2::Sha256;

    #[test]
    fn test_blind_unblind() {
        let mut rng = rand::thread_rng();
        let user_schnorr =
            Schnorr::<Sha256, _>::new(Synthetic::<Sha256, GlobalRng<ThreadRng>>::default());
        let server_schnorr =
            Schnorr::<Sha256, _>::new(Synthetic::<Sha256, GlobalRng<ThreadRng>>::default());

        // Generate a secret & public key for the server that will blindly sign a single message
        let secret = Scalar::random(&mut rand::thread_rng());
        let n_sessions = 1;

        // The blinding server
        let mut blind_signer = BlindSigner::new(n_sessions, secret, server_schnorr);

        // The blind signing server replies with a public nonce to the user
        let pub_nonce = blind_signer.gen_nonce(b"turbo-unique-sid");
        let message = Message::<Public>::plain("test", b"sign me up");

        // The user creates a blinded session which blinds the recieved nonce,
        // and then creating a blind challenge which the server will sign.
        let blind_session = Blinder::blind(
            message,
            pub_nonce,
            blind_signer.public_key(),
            user_schnorr.clone(),
            &mut rng,
        );

        // The user creates a signature request. Comprised of the challenge and public nonce
        let signature_request = blind_session.signature_request();

        // The blind signer server signs under their secret key and with the corresponding nonce for each
        // respective signature request
        let session_signature = blind_signer.sign(signature_request, &mut rng);

        // We recieve an option of the blinded signature from the signer, and unblind it revealing
        // an uncorrelated signature for the message that is valid under the pubkey.
        // The server has also not seen the nonce for this signature.
        assert_eq!(session_signature.len(), 1);
        let blind_signature =
            session_signature[0].expect("max sessions of 1 should sign immediately");

        let unblinded_signature = blind_session.unblind(blind_signature);
        assert!(user_schnorr.verify(&blind_signer.public_key(), message, &unblinded_signature));
    }

    proptest! {
        #[test]
        fn blind_sig_prop_test(secret in any::<Scalar>(), max_sessions in 1usize..10, excess_sessions in 0usize..3) {
            let mut rng = rand::thread_rng();
            let server_schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::new(Deterministic::<Sha256>::default());

            let mut blind_signer = BlindSigner::new(max_sessions, secret, server_schnorr);

            let message = Message::<Public>::plain("test", b"sign me up");
            let user_schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::new(Deterministic::<Sha256>::default());
            let blind_sessions: Vec<_> = (0..(excess_sessions + max_sessions)).map(|i|
                {
                    Blinder::blind(
                        message,
                        blind_signer.gen_nonce(format!("turbo-unique-sid {}",i as u16).as_bytes()),
                        blind_signer.public_key(),
                        user_schnorr.clone(),
                        &mut rng,
                    )
            }
            ).collect();

            let mut blind_sigs = vec![];
            // excess sessions should return none
            for (i, blind_session) in blind_sessions.iter().enumerate() {
                let signature_request = blind_session.signature_request();
                blind_sigs = blind_signer.sign(
                    signature_request,
                    &mut rng,
                );

                // The first excess_sessions number of sessions expired and get responses None,
                // then we need max_sessions to actually sign in order to receive signatures.
                let actually_signed = blind_sigs.iter().filter_map(|v| *v).collect::<Vec<_>>();

                if i + 1 < max_sessions + excess_sessions {
                    assert_eq!(actually_signed.len(), 0);
                } else {
                    // If we have finished all the non expired max_sessions,
                    // we expect signatures now
                    if i + 1 == max_sessions + excess_sessions {
                        if max_sessions == 1 {
                            // We signed a single session when the max sessions is one
                            assert_eq!(actually_signed.len(), max_sessions);
                        } else {
                            // We signed all but one session
                            assert_eq!(actually_signed.len(), max_sessions - 1);
                            assert_eq!(blind_signer.nonces.len(), (1 + i - excess_sessions) % max_sessions);
                        }
                    } else {
                        // We returned nothing otherwise
                        assert_eq!(actually_signed.len(), 0)
                    }
                }
            }

            // Unblind and verify all the signatures
            let verify_schnorr = Schnorr::<Sha256, Deterministic<Sha256>>::new(Deterministic::<Sha256>::default());
            for (blind_session, blind_signature) in blind_sessions.iter().skip(excess_sessions).zip(blind_sigs) {
                if let Some(blind_signature) = blind_signature {
                    let unblinded_signature = blind_session.unblind(blind_signature);
                    assert!(verify_schnorr.verify(&blind_signer.public_key(), message, &unblinded_signature));
                }
            }

        }
    }
}
