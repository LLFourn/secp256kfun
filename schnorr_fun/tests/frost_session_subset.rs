#![cfg(feature = "alloc")]
//! Once a signing session is fixed, the coordinator must require a signature share from every
//! party in it, not merely `threshold` of them.
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use schnorr_fun::{
    Message,
    binonce::NonceKeyPair,
    frost::{self, chilldkg::simplepedpop},
};
use sha2::Sha256;
use std::collections::BTreeMap;

#[test]
fn coordinator_rejects_threshold_subset_of_larger_session() {
    let frost = frost::new_with_deterministic_nonces::<Sha256>();
    let mut rng = ChaCha20Rng::from_seed([12; 32]);
    let (shared_key, secret_shares) =
        simplepedpop::simulate_keygen(&frost.schnorr, 2, 3, 0, &mut rng);
    let shared_key = shared_key.into_xonly();
    let nonces: Vec<_> = (0..3).map(|_| NonceKeyPair::random(&mut rng)).collect();
    let message = Message::raw(b"missing signer");

    // All three parties contribute nonces, so the aggregate nonce and Lagrange coefficients are
    // computed over {1, 2, 3}.
    let coordinator = frost.coordinator_sign_session(
        &shared_key,
        secret_shares
            .iter()
            .zip(&nonces)
            .map(|(share, nonce)| (share.index(), nonce.public()))
            .collect(),
        message,
    );
    let party_session = frost.party_sign_session(
        shared_key.public_key(),
        coordinator.parties(),
        coordinator.agg_binonce(),
        message,
    );

    // Only two parties respond. That meets the threshold, but party 3's nonce is still baked into
    // the session so their missing share can't be compensated for.
    let sig_shares: BTreeMap<_, _> = secret_shares
        .iter()
        .zip(&nonces)
        .take(2)
        .map(|(share, nonce)| {
            (
                share.index(),
                party_session.sign(&share.into_xonly(), nonce),
            )
        })
        .collect();

    for (index, sig_share) in &sig_shares {
        assert!(
            coordinator
                .verify_signature_share(shared_key.verification_share(*index), *sig_share)
                .is_ok(),
            "each submitted share is individually valid, so the failure must be the missing party"
        );
    }

    match coordinator.verify_and_combine_signature_shares(&shared_key, sig_shares) {
        Err(_) => {}
        Ok(signature) => {
            assert!(
                frost
                    .schnorr
                    .verify(&shared_key.public_key(), message, &signature),
                "verify_and_combine_signature_shares returned Ok with a signature that does not \
                 verify: 2 shares from a 3-party session were accepted"
            );
        }
    }
}
