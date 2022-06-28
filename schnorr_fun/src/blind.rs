//! Blind Schnorr Signatures
//!
//! Produce a schnorr signature where the signer does not know what they have signed.
//!
//! A blind signing server (with public key `X = x*G`) sends a public nonce (`R = k*G`) to the user who wants a message signed.
//! The user blinds this nonce (`R' = R + alpha*G + beta*X`) as well as the server's public key by adding a random tweak (`X' = X + t*G`).
//!
//! A challenge for the message (`M`) is created using these blinded values (`c = H[R'|X'|M]`), and this challenge is then blinded
//! also (`c' = c + beta`). The blinded challenge is sent to the signing server and is signed (`s = k + c'*x`).
//!
//! Note that when running multiple sessions in parallel a signing server should use `safe_blind_sign_multiple` which will randomly
//! fail on 1 out of N signing requests. This is to prevent Wagner attacks where parallel signing sessions allow for a forgery.
//!
//! Once the user recieves the blinded signature, they can unblind it (`s' = s + alpha + c*t`).
//! The unblinded signature (`s', R'`) is a valid schnorr signature under the tweaked public key (`X'`).
//! The signer can not correlate this signature-nonce pair even if they know the tweaked public key, signature, message, and nonce.
//!
//! This implementation mostly follows this [SuredBits article] and [Blind Schnorr Signatures in the Algebraic Group Model].
//!
//! [SuredBits article]: <https://suredbits.com/schnorr-applications-blind-signatures/>
//! [Blind Schnorr Signatures in the Algebraic Group Model]: <https://eprint.iacr.org/2019/877.pdf>
//!
//! # Synopsis
//! ```
//! use schnorr_fun::{blind, Blinder, Message, Schnorr};
//! use secp256kfun::{g, marker::Public, Scalar, G};
//! use sha2::Sha256;
//! let schnorr = Schnorr::<Sha256, _>::new(());
//! // Generate a secret & public key for the party that will blindly sign a message
//! let secret = Scalar::random(&mut rand::thread_rng());
//! let public_key = g!(secret * G).normalize();
//!
//! // The user wants a single blind signature but must initiate two signing sessions where one will fail.
//! // This is to prevent Wagner attacks where many parallel signing sessions can allow forgery.
//! // Here we request two nonces corresponding to two sessions, such that we will retrieve one signature.
//! let n_sessions = 2;
//!
//! // The blind signing server replies with N public nonces to the user and remembers this number of sessions.
//! let mut nonces = vec![];
//! let mut pub_nonces = vec![];
//! for _ in 0..n_sessions {
//!     let mut nonce = Scalar::random(&mut rand::thread_rng());
//!     // TODO: Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
//!     let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
//!     nonce.conditional_negate(nonce_negated);
//!     nonces.push(nonce);
//!     pub_nonces.push(pub_nonce);
//! }
//!
//! // The message the user wants signed
//! let message = Message::<Public>::plain("test", b"sign me up");
//!
//! // The user creates blinded sessions by blinding the public keys, and recieved nonces.
//! // They also create a challenge which the server will sign.
//! let blind_sessions: Vec<_> = pub_nonces
//!     .iter()
//!     .map(|pub_nonce| {
//!         Blinder::blind(
//!             *pub_nonce,
//!             public_key,
//!             message,
//!             schnorr.clone(),
//!             &mut rand::thread_rng(),
//!         )
//!     })
//!     .collect();
//!
//! // The user creates a signature request for each session. Comprised of the challenge,
//! // (& currently two needs negations ...)
//! let mut signature_requests: Vec<_> = blind_sessions
//!     .iter()
//!     .map(|session| session.signature_request())
//!     .collect();
//!
//! // The blind signer server signs under their secret key and with the corresponding nonce for each
//! // respective signature request
//! let session_signatures = blind::safe_blind_sign_multiple(
//!     &secret,
//!     nonces,
//!     &mut signature_requests,
//!     &mut rand::thread_rng(),
//! );
//!
//! // We iterate over our signing sessions, unblinding the session which completed.
//! // This reveals an uncorrelated signature for the message that is valid under the tweaked pubkey.
//! // The server has also not seen the nonce for this signature.
//! for (blind_session, blind_signature) in blind_sessions.iter().zip(session_signatures) {
//!     match blind_signature {
//!         Some(blind_signature) => {
//!             let unblinded_signature = blind_session.unblind(blind_signature);
//!             // Validate the unblinded signature against the tweaked public key
//!             let (verification_pubkey, _) = blind_session.tweaked_pubkey.into_point_with_even_y();
//!             assert!(schnorr.verify(&verification_pubkey, message, &unblinded_signature));
//!         }
//!         None => {}
//!     }
//! }
//! ```

use crate::fun::rand_core::{CryptoRng, RngCore};
use crate::{Message, Schnorr, Signature};
use rand::Rng;
use secp256kfun::{
    digest::{generic_array::typenum::U32, Digest},
    g,
    marker::*,
    s, Point, Scalar, G,
};
use std::vec::Vec;

/// Use [`BlindingTweaks`] to create the blinded public key, challenge, and nonce needed for a blinded signature
///
/// # Returns
///
/// A tweaked_pubkey, blinded_nonce, and a blinded_challenge;
/// Also returns a needs_negation for the blinded public key and nonce
/// The [`BlindingTweaks`] values (alpha, beta, t) may be negated to ensure even y values.
pub fn create_blinded_values<'a, H: Digest<OutputSize = U32> + Clone, NG>(
    nonce: Point<EvenY>,
    public_key: Point,
    message: Message,
    schnorr: Schnorr<H, NG>,
    blinding_tweaks: &mut BlindingTweaks,
) -> (Point, Point, Scalar, bool, bool) {
    let tweaked_pubkey = g!(public_key + blinding_tweaks.t * G)
        .normalize()
        .mark::<NonZero>()
        .expect("added tweak is random");

    let tweaked_pubkey_needs_negation = !tweaked_pubkey.is_y_even();
    let tweaked_pubkey = tweaked_pubkey.conditional_negate(tweaked_pubkey_needs_negation);

    let blinded_nonce =
        g!(nonce + blinding_tweaks.alpha * G + blinding_tweaks.beta * tweaked_pubkey)
            .normalize()
            .mark::<NonZero>()
            .expect("added tweak is random");

    let blinded_nonce_needs_negation = !blinded_nonce.is_y_even();
    let blinded_nonce = blinded_nonce.conditional_negate(blinded_nonce_needs_negation);

    // negate the respective tweak values if the public key or nonce needed negation
    blinding_tweaks
        .alpha
        .conditional_negate(blinded_nonce_needs_negation);
    blinding_tweaks
        .beta
        .conditional_negate(blinded_nonce_needs_negation);
    blinding_tweaks
        .t
        .conditional_negate(tweaked_pubkey_needs_negation);

    let blinded_challenge =
        s!(
            { schnorr.challenge(blinded_nonce.to_xonly(), tweaked_pubkey.to_xonly(), message,) }
                + blinding_tweaks.beta
        )
        .mark::<NonZero>()
        .expect("added tweak is random");

    (
        tweaked_pubkey,
        blinded_nonce,
        blinded_challenge,
        tweaked_pubkey_needs_negation,
        blinded_nonce_needs_negation,
    )
}

/// Unblind a blinded signature
///
/// # Returns
///
/// Returns a scalar signature
pub fn unblind_signature(
    blinded_signature: Scalar<Public, Zero>,
    alpha: &Scalar<Secret, NonZero>,
    challenge: &Scalar<Secret, NonZero>,
    tweak: &Scalar<Secret, NonZero>,
) -> Scalar<Public, Zero> {
    s!(blinded_signature + alpha + challenge * tweak).mark::<Public>()
}

/// The tweaks used for blinding the nonce, public key, and challenge
/// which are later used to unblind the signature
#[derive(Debug)]
pub struct BlindingTweaks {
    /// tweak value alpha
    pub alpha: Scalar,
    /// tweak value beta
    pub beta: Scalar,
    /// tweak value t
    pub t: Scalar,
}

impl BlindingTweaks {
    /// Create new [`BlindingTweaks`] from an rng source
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> BlindingTweaks {
        BlindingTweaks {
            alpha: Scalar::random(rng),
            beta: Scalar::random(rng),
            t: Scalar::random(rng),
        }
    }
}

/// Blinder holds a blinded signature context which is later used to unblind the signature
#[derive(Debug)]
pub struct Blinder {
    /// blinded public key X' = X + t*G
    pub tweaked_pubkey: Point,
    /// tweaked public nonce R' = R + alpha*G + beta * X
    pub blinded_nonce: Point,
    /// tweaked challenge c' = c + beta
    pub challenge: Scalar,
    /// blinding values
    pub blinding_tweaks: BlindingTweaks,
    /// the tweaked public key needs negation
    pub pubkey_needs_negation: bool,
    /// the pubnonce needs negation
    pub nonce_needs_negation: bool,
}

impl Blinder {
    /// Prepare a blinded challenge for the server to sign, and blind the nonce which we
    /// recieved from the server.
    ///
    /// # Returns
    ///
    /// Returns a Blinder session, which is later used to unblind the signature once signed
    pub fn blind<H: Digest<OutputSize = U32> + Clone, R: RngCore + CryptoRng>(
        pubnonce: Point<EvenY>,
        public_key: Point,
        message: Message,
        schnorr: Schnorr<H>,
        rng: &mut R,
    ) -> Self {
        let mut blinding_tweaks = BlindingTweaks::new(rng);
        let (
            tweaked_pubkey,
            blinded_nonce,
            blinded_challenge,
            pubkey_needs_negation,
            nonce_needs_negation,
        ) = create_blinded_values(pubnonce, public_key, message, schnorr, &mut blinding_tweaks);

        Blinder {
            tweaked_pubkey,
            blinded_nonce,
            challenge: blinded_challenge,
            pubkey_needs_negation,
            nonce_needs_negation,
            blinding_tweaks,
        }
    }

    /// Unblind a blinded signature
    ///
    /// # Returns
    ///
    /// A schnorr signature that should be valid under the tweaked public key and blinded nonce
    pub fn unblind(&self, blinded_signature: Scalar<Public, Zero>) -> Signature {
        let sig = unblind_signature(
            blinded_signature,
            &self.blinding_tweaks.alpha,
            &self.challenge,
            &self.blinding_tweaks.t,
        );
        Signature {
            s: sig,
            R: self.blinded_nonce.to_xonly(),
        }
    }

    /// Create a signature request using this blinding session
    ///
    /// # Returns
    ///
    /// A [`SignatureRequest`] with a blind_challenge (and needs negations)
    pub fn signature_request(&self) -> SignatureRequest {
        SignatureRequest {
            blind_challenge: self.challenge.clone(),
            pubkey_needs_negation: self.pubkey_needs_negation,
            nonce_needs_negation: self.nonce_needs_negation,
        }
    }
}

#[derive(Clone)]
/// A signature request which will be sent to the signing server
pub struct SignatureRequest {
    blind_challenge: Scalar,
    pubkey_needs_negation: bool,
    nonce_needs_negation: bool,
}

/// Blindly sign a challenge using a secret and a nonce
///
/// The user should send their blind challenge for signing,
/// along with whether pubkey_needs_negation and nonce_needs_negation
///
/// # Returns
///
/// Returns a scalar of the unblinded signature
pub fn blind_sign(
    secret: &Scalar,
    mut nonce: Scalar,
    sig_request: SignatureRequest,
) -> Scalar<Public, Zero> {
    let mut negated_blind_challenge = sig_request.blind_challenge.clone();
    negated_blind_challenge.conditional_negate(sig_request.pubkey_needs_negation);
    nonce.conditional_negate(sig_request.nonce_needs_negation);

    let sig = s!({ nonce } + negated_blind_challenge * secret).mark::<Public>();
    sig
}

/// Safely sign multiple blind schnorr signatures concurrently
///
/// Disconnects 1 out of N times if there is N > 1 SignatureRequests supplied.
/// Does not disconnect if only supplied one SignatureRequest
pub fn safe_blind_sign_multiple<R: RngCore + CryptoRng>(
    secret: &Scalar,
    nonces: Vec<Scalar>,
    sig_requests: &mut Vec<SignatureRequest>,
    rng: &mut R,
) -> Vec<Option<Scalar<Public, Zero>>> {
    let skip_i = rng.gen_range(0..sig_requests.len());

    sig_requests
        .iter()
        .zip(nonces)
        .enumerate()
        .map(|(i, (sig_req, nonce))| {
            if i == skip_i {
                None
            } else {
                Some(blind_sign(secret, nonce.clone(), sig_req.clone()))
            }
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Message, Schnorr};
    use secp256kfun::{
        g,
        proptest::{arbitrary::any, proptest},
        Scalar, G,
    };
    use sha2::Sha256;

    #[test]
    fn test_blind_unblind() {
        let schnorr = Schnorr::<Sha256, _>::new(());
        // Generate a secret & public key for the server that will blindly sign a message
        let secret = Scalar::random(&mut rand::thread_rng());
        let public_key = g!(secret * G).normalize();

        // The user wants a single blind signature but must initiate two signing sessions where one will fail.
        // This is to prevent Wagner attacks where many parallel signing sessions can allow forgery.
        // Here we request two nonces corresponding to two sessions, such that we will retrieve one signature.
        let n_sessions = 2;

        // The blind signing server replies with N public nonces to the user and remembers this number of sessions.
        let mut nonces = vec![];
        let mut pub_nonces = vec![];
        for _ in 0..n_sessions {
            let mut nonce = Scalar::random(&mut rand::thread_rng());
            // TODO: Probably want to reintroduce a singular nonce struct? And move musig/frost to "binonce"
            let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
            nonce.conditional_negate(nonce_negated);
            nonces.push(nonce);
            pub_nonces.push(pub_nonce);
        }

        let message = Message::<Public>::plain("test", b"sign me up");

        // The user creates blinded sessions by blinding the public key, and recieved nonces.
        // They also create a challenge which the server will sign.
        let blind_sessions: Vec<_> = pub_nonces
            .iter()
            .map(|pub_nonce| {
                let blind_session = Blinder::blind(
                    *pub_nonce,
                    public_key,
                    message,
                    schnorr.clone(),
                    &mut rand::thread_rng(),
                );
                dbg!(
                    blind_session.pubkey_needs_negation,
                    blind_session.nonce_needs_negation,
                );
                blind_session
            })
            .collect();

        // The user creates a signature request for each session. Comprised of the challenge,
        // (& currently two needs negations ...)
        let mut signature_requests: Vec<_> = blind_sessions
            .iter()
            .map(|session| session.signature_request())
            .collect();

        // The blind signer server signs under their secret key and with the corresponding nonce for each
        // respective signature request
        assert_eq!(signature_requests.len(), n_sessions);
        let session_signatures = safe_blind_sign_multiple(
            &secret,
            nonces,
            &mut signature_requests,
            &mut rand::thread_rng(),
        );
        dbg!(&session_signatures);

        // We recieve an option of the blinded signature from the signer, and unblind it revealing
        // an uncorrelated signature for the message that is valid under the tweaked pubkey.
        // The server has also not seen the nonce for this signature.
        for (blind_session, blind_signature) in blind_sessions.iter().zip(session_signatures) {
            match blind_signature {
                Some(blind_signature) => {
                    let unblinded_signature = blind_session.unblind(blind_signature);

                    // Validate the unblinded signature against the tweaked public key
                    let (verification_pubkey, _) =
                        blind_session.tweaked_pubkey.into_point_with_even_y();
                    assert!(schnorr.verify(&verification_pubkey, message, &unblinded_signature));
                }
                None => {}
            }
        }
    }

    proptest! {
        #[test]
        fn blind_sig_prop_test(secret in any::<Scalar>(), mut nonce in any::<Scalar>()) {
            let schnorr = Schnorr::<Sha256, _>::new(());
            let public_key = g!(secret * G).normalize();

            let (pub_nonce, nonce_negated) = g!(nonce * G).normalize().into_point_with_even_y();
            nonce.conditional_negate(nonce_negated);

            let message = Message::<Public>::plain("test", b"sign me up");

            let blind_session = Blinder::blind(
                pub_nonce,
                public_key,
                message,
                schnorr.clone(),
                &mut rand::thread_rng(),
            );

            dbg!(&secret, &public_key, &nonce, &pub_nonce);
            dbg!(&blind_session);

            let signature_request = SignatureRequest {
                blind_challenge: blind_session.challenge.clone(),
                pubkey_needs_negation: blind_session.pubkey_needs_negation,
                nonce_needs_negation: blind_session.nonce_needs_negation,
            };

            let blind_signature = blind_sign(
                &secret,
                nonce.clone(),
                signature_request,
            );

            let unblinded_signature = blind_session.unblind(blind_signature);

            let (verification_pubkey, _) = blind_session.tweaked_pubkey.into_point_with_even_y();
            assert!(schnorr.verify(&verification_pubkey, message, &unblinded_signature));
        }
    }
}
