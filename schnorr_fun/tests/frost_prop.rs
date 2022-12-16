#![cfg(feature = "alloc")]
#![cfg(feature = "serde")]
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;
use schnorr_fun::{
    frost::*,
    fun::{marker::*, Scalar},
    Message,
};
use secp256kfun::proptest::{
    arbitrary::any,
    option, proptest,
    strategy::{Just, Strategy},
    test_runner::{RngAlgorithm, TestRng},
};
use sha2::Sha256;

proptest! {

    #[test]
    fn frost_prop_test(
        (n_parties, threshold) in (2usize..=4).prop_flat_map(|n| (Just(n), 2usize..=n)),
        plain_tweak in option::of(any::<Scalar<Public, Zero>>()),
        xonly_tweak in option::of(any::<Scalar<Public, Zero>>())
    ) {
        let proto = new_with_deterministic_nonces::<Sha256>();
        assert!(threshold <= n_parties);

        // // create some scalar polynomial for each party
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let (mut frost_key, secret_shares) = proto.simulate_keygen(threshold, n_parties, &mut rng);

        if let Some(tweak) = plain_tweak {
            frost_key = frost_key.tweak(tweak).unwrap();
        }

        let mut frost_key = frost_key.into_xonly_key();

        if let Some(tweak) = xonly_tweak {
            frost_key = frost_key.tweak(tweak).unwrap();
        }

        // use a boolean mask for which t participants are signers
        let mut signer_mask = vec![true; threshold];
        signer_mask.append(&mut vec![false; n_parties - threshold]);
        // shuffle the mask for random signers
        signer_mask.shuffle(&mut rng);

        let signer_indexes: Vec<_> = signer_mask
            .iter()
            .enumerate()
            .filter(|(_, is_signer)| **is_signer)
            .map(|(i,_)| i)
            .collect();

        let sid = b"frost-prop-test".as_slice();
        let message = Message::plain("test", b"test");

        let mut nonce_rngs: Vec<ChaCha20Rng> = secret_shares.iter().map(|secret_share| {
            proto.seed_nonce_rng(
                &frost_key,
                secret_share,
                sid,
            )
        }).collect();

        let nonces: Vec<_> = signer_indexes.iter().map(|i|
            proto.gen_nonce(
                &mut nonce_rngs[*i])).collect();

        let mut received_nonces: Vec<_> = vec![];
        for (i, nonce) in signer_indexes.iter().zip(nonces.clone()) {
            received_nonces.push((*i, nonce.public()));
        }

        let signing_session = proto.start_sign_session(
            &frost_key,
            received_nonces.clone(),
            message
        );

        let mut signatures = vec![];
        for i in 0..signer_indexes.len() {
            let signer_index = signer_indexes[i];
            let session = proto.start_sign_session(
                &frost_key,
                received_nonces.clone(),
                message
            );
            let sig = proto.sign(
                &frost_key,
                &session, signer_index,
                &secret_shares[signer_index],
                nonces[i].clone()
            );
            assert!(proto.verify_signature_share(
                &frost_key,
                &session,
                signer_index,
                sig)
            );
            signatures.push(sig);
        }
        let combined_sig = proto.combine_signature_shares(
            &frost_key,
            &signing_session,
            signatures);

        assert!(proto.schnorr.verify(
            &frost_key.public_key(),
            message,
            &combined_sig
        ));
    }
}
