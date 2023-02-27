#![cfg(feature = "alloc")]
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
use std::collections::BTreeMap;

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

        let secret_shares = signer_mask.into_iter().zip(secret_shares.into_iter()).filter(|(is_signer, _)| *is_signer)
            .map(|(_, secret_share)| secret_share).collect::<BTreeMap<_,_>>();


        let sid = b"frost-prop-test".as_slice();
        let message = Message::plain("test", b"test");

        let mut secret_nonces: BTreeMap<_, _> = secret_shares.iter().map(|(signer_index, secret_share)| {
            (*signer_index, proto.gen_nonce::<ChaCha20Rng>(
                &mut proto.seed_nonce_rng(
                    &frost_key,
                    secret_share,
                    sid,
                )))
        }).collect();


        let public_nonces = secret_nonces.iter().map(|(signer_index, sn)| (*signer_index, sn.public())).collect::<BTreeMap<_, _>>();
        dbg!(&public_nonces);

        let signing_session = proto.start_sign_session(
            &frost_key,
            public_nonces.clone(),
            message
        );

        let mut signatures = vec![];
        for (signer_index, secret_share) in secret_shares  {
            let sig = proto.sign(
                &frost_key,
                &signing_session,
                signer_index,
                &secret_share,
                secret_nonces.remove(&signer_index).unwrap()
            );
            assert!(proto.verify_signature_share(
                &frost_key,
                &signing_session,
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
