#![cfg(feature = "alloc")]
use chilldkg::encpedpop;
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
        (n_parties, threshold) in (2u32..=4).prop_flat_map(|n| (Just(n), 2u32..=n)),
        add_tweak in option::of(any::<Scalar<Public, Zero>>()),
        xonly_add_tweak in option::of(any::<Scalar<Public, Zero>>()),
        mul_tweak in option::of(any::<Scalar<Public>>()),
        xonly_mul_tweak in option::of(any::<Scalar<Public>>())
    ) {
        let frost = new_with_deterministic_nonces::<Sha256>();
        assert!(threshold <= n_parties);

        // // create some scalar polynomial for each party
        let mut rng = TestRng::deterministic_rng(RngAlgorithm::ChaCha);
        let (mut shared_key, mut secret_shares) = encpedpop::simulate_keygen(&frost.schnorr, threshold, n_parties, n_parties, &mut rng);

        if let Some(tweak) = add_tweak {
            for secret_share in &mut secret_shares {
                *secret_share = secret_share.homomorphic_add(tweak).non_zero().unwrap();
            }
            shared_key = shared_key.homomorphic_add(tweak).non_zero().unwrap();
        }

        if let Some(mul_tweak) = mul_tweak {
            shared_key = shared_key.homomorphic_mul(mul_tweak);
            for secret_share in &mut secret_shares {
                *secret_share = secret_share.homomorphic_mul(mul_tweak);
            }
        }

        let mut xonly_shared_key = shared_key.into_xonly();
        let mut xonly_secret_shares = secret_shares.into_iter().map(|secret_share| secret_share.into_xonly()).collect::<Vec<_>>();

        if let Some(tweak) = xonly_add_tweak {
            xonly_shared_key = xonly_shared_key.homomorphic_add(tweak).non_zero().unwrap().into_xonly();
            for secret_share in &mut xonly_secret_shares {
                *secret_share = secret_share.homomorphic_add(tweak).non_zero().unwrap().into_xonly();
            }
        }

        if let Some(xonly_mul_tweak) = xonly_mul_tweak {
            xonly_shared_key = xonly_shared_key.homomorphic_mul(xonly_mul_tweak).into_xonly();
            for secret_share in &mut xonly_secret_shares {
                *secret_share = secret_share.homomorphic_mul(xonly_mul_tweak).into_xonly();
            }
        }

        for secret_share in &xonly_secret_shares {
            assert_eq!(secret_share.public_key(), xonly_shared_key.public_key(), "shared key doesn't match");
        }

        // use a boolean mask for which t participants are signers
        let mut signer_mask = vec![true; threshold as usize];
        signer_mask.append(&mut vec![false; (n_parties - threshold) as usize]);
        // shuffle the mask for random signers
        signer_mask.shuffle(&mut rng);

        let secret_shares_of_signers = signer_mask.into_iter().zip(xonly_secret_shares.into_iter()).filter(|(is_signer, _)| *is_signer)
            .map(|(_, secret_share)| secret_share).collect::<Vec<_>>();


        let sid = b"frost-prop-test".as_slice();
        let message = Message::plain("test", b"test");

        let mut secret_nonces: BTreeMap<_, _> = secret_shares_of_signers.iter().map(|paired_secret_share| {
            (paired_secret_share.secret_share().index, frost.gen_nonce::<ChaCha20Rng>(
                &mut frost.seed_nonce_rng(
                    *paired_secret_share,
                    sid,
                )))
        }).collect();


        let public_nonces = secret_nonces.iter().map(|(signer_index, sn)| (*signer_index, sn.public())).collect::<BTreeMap<_, _>>();

        let coord_signing_session = frost.coordinator_sign_session(
            &xonly_shared_key,
            public_nonces,
            message
        );

        let party_signing_session = frost.party_sign_session(
            xonly_shared_key.public_key(),
            coord_signing_session.parties(),
            coord_signing_session.agg_binonce(),
            message,
        );

        let mut signatures = BTreeMap::default();
        for secret_share in secret_shares_of_signers  {
            let sig = party_signing_session.sign(
                &secret_share,
                secret_nonces.remove(&secret_share.index()).unwrap()
            );
            assert_eq!(coord_signing_session.verify_signature_share(
                secret_share.verification_share(),
                sig), Ok(())
            );
            signatures.insert(secret_share.index(), sig);
        }
        let combined_sig = coord_signing_session.combine_signature_shares(
            coord_signing_session.final_nonce(),
            signatures.values().cloned()
        );

        assert_eq!(coord_signing_session.verify_and_combine_signature_shares(&xonly_shared_key, signatures), Ok(combined_sig));
        assert!(frost.schnorr.verify(
            &xonly_shared_key.public_key(),
            message,
            &combined_sig
        ));

    }
}
