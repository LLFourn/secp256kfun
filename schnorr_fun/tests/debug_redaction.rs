#![cfg(feature = "alloc")]
//! Secret material must never show up in `{:?}` output, since applications routinely log values
//! with it. `Display` remains the explicit way to export a secret.
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use schnorr_fun::{
    binonce::NonceKeyPair,
    frost::{self, chilldkg::simplepedpop},
    fun::{KeyPair, Scalar},
};
use sha2::Sha256;

fn assert_redacted(debug: String, secret: Scalar<impl Sized, impl Sized>) {
    let secret_hex = secret
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(
        !debug.contains(&secret_hex),
        "secret {secret_hex} appears in debug output: {debug}"
    );
}

#[test]
fn keypair_debug_hides_secret_key() {
    let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
    assert_redacted(format!("{keypair:?}"), *keypair.secret_key());
}

#[test]
fn nonce_keypair_debug_hides_secret_nonces() {
    let nonce = NonceKeyPair::random(&mut rand::thread_rng());
    let debug = format!("{nonce:?}");
    assert_redacted(debug.clone(), nonce.secret.0[0]);
    assert_redacted(debug, nonce.secret.0[1]);
}

#[test]
fn secret_share_debug_hides_share() {
    let frost = frost::new_with_deterministic_nonces::<Sha256>();
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let (_, paired_shares) = simplepedpop::simulate_keygen(&frost.schnorr, 2, 3, 0, &mut rng);
    let paired_share = paired_shares[0];
    let secret_share = *paired_share.secret_share();

    assert_redacted(format!("{secret_share:?}"), secret_share.share);
    assert_redacted(format!("{paired_share:?}"), secret_share.share);
    assert_redacted(
        format!("{:?}", paired_share.into_xonly()),
        paired_share.into_xonly().secret_share().share,
    );
}
