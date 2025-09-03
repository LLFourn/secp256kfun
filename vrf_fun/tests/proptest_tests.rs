use proptest::prelude::*;
use secp256kfun::{KeyPair, hash::HashAdd, prelude::*};
use vrf_fun::{SimpleVrf, rfc9381};

proptest! {
    #[test]
    fn test_tai_vrf_proptest(
        secret_key_bytes in prop::array::uniform32(any::<u8>()),
        alpha1 in prop::collection::vec(any::<u8>(), 0..100),
        alpha2 in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let secret_scalar = Scalar::from_bytes_mod_order(secret_key_bytes);
        let Some(secret_key) = secret_scalar.non_zero() else {
            return Ok(());
        };

        let keypair = KeyPair::new(secret_key);

        // Test basic prove/verify
        let proof1 = rfc9381::tai::prove::<sha2::Sha256>(&keypair, &alpha1);
        let verified1 = rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof1)
            .expect("Proof should verify with correct public key");

        // Test deterministic output
        let proof1_again = rfc9381::tai::prove::<sha2::Sha256>(&keypair, &alpha1);
        assert_eq!(proof1.gamma, proof1_again.gamma, "Gamma should be deterministic");
        let verified1_again = rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof1_again)
            .expect("Proof should verify again");
        assert_eq!(
            rfc9381::tai::output::<sha2::Sha256>(verified1),
            rfc9381::tai::output::<sha2::Sha256>(verified1_again),
            "VRF output should be deterministic"
        );

        // Test wrong public key
        let wrong_keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
        assert!(
            rfc9381::tai::verify::<sha2::Sha256>(wrong_keypair.public_key(), &alpha1, &proof1).is_none(),
            "Proof should not verify with wrong public key"
        );

        // Test different inputs produce different outputs
        if alpha1 != alpha2 {
            let proof2 = rfc9381::tai::prove::<sha2::Sha256>(&keypair, &alpha2);
            let verified2 = rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), &alpha2, &proof2)
                .expect("Second proof should verify");

            assert_ne!(
                rfc9381::tai::output::<sha2::Sha256>(verified1),
                rfc9381::tai::output::<sha2::Sha256>(verified2),
                "Different inputs should produce different outputs"
            );

            // Cross-verification should fail
            assert!(
                rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof2).is_none(),
                "Proof for alpha2 should not verify with alpha1"
            );
            assert!(
                rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), &alpha2, &proof1).is_none(),
                "Proof for alpha1 should not verify with alpha2"
            );
        }
    }

    #[test]
    fn test_sswu_vrf_proptest(
        secret_key_bytes in prop::array::uniform32(any::<u8>()),
        alpha1 in prop::collection::vec(any::<u8>(), 0..100),
        alpha2 in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let secret_scalar = Scalar::from_bytes_mod_order(secret_key_bytes);
        let Some(secret_key) = secret_scalar.non_zero() else {
            return Ok(());
        };

        let keypair = KeyPair::new(secret_key);

        // Test basic prove/verify
        let proof1 = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, &alpha1);
        let verified1 = rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof1)
            .expect("Proof should verify with correct public key");

        // Test deterministic output
        let proof1_again = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, &alpha1);
        assert_eq!(proof1.gamma, proof1_again.gamma, "Gamma should be deterministic");
        let verified1_again = rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof1_again)
            .expect("Proof should verify again");
        assert_eq!(
            rfc9381::sswu::output::<sha2::Sha256>(verified1),
            rfc9381::sswu::output::<sha2::Sha256>(verified1_again),
            "VRF output should be deterministic"
        );

        // Test wrong public key
        let wrong_keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
        assert!(
            rfc9381::sswu::verify::<sha2::Sha256>(wrong_keypair.public_key(), &alpha1, &proof1).is_none(),
            "Proof should not verify with wrong public key"
        );

        // Test different inputs produce different outputs
        if alpha1 != alpha2 {
            let proof2 = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, &alpha2);
            let verified2 = rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), &alpha2, &proof2)
                .expect("Second proof should verify");

            assert_ne!(
                rfc9381::sswu::output::<sha2::Sha256>(verified1),
                rfc9381::sswu::output::<sha2::Sha256>(verified2),
                "Different inputs should produce different outputs"
            );

            // Cross-verification should fail
            assert!(
                rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), &alpha1, &proof2).is_none(),
                "Proof for alpha2 should not verify with alpha1"
            );
            assert!(
                rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), &alpha2, &proof1).is_none(),
                "Proof for alpha1 should not verify with alpha2"
            );
        }
    }

    #[test]
    fn test_simple_vrf_proptest(
        secret_key_bytes in prop::array::uniform32(any::<u8>()),
        alpha1 in prop::collection::vec(any::<u8>(), 0..100),
        alpha2 in prop::collection::vec(any::<u8>(), 0..100)
    ) {
        let secret_scalar = Scalar::from_bytes_mod_order(secret_key_bytes);
        let Some(secret_key) = secret_scalar.non_zero() else {
            return Ok(());
        };

        let keypair = KeyPair::new(secret_key);
        let vrf = SimpleVrf::<sha2::Sha256>::default();

        let h1 = Point::hash_to_curve(sha2::Sha256::default().add(&alpha1[..]));
        let proof1 = vrf.prove(&keypair, h1);

        // Test basic verify
        let verified1 = vrf.verify(keypair.public_key(), h1, &proof1)
            .expect("Proof should verify with correct public key");
        assert_eq!(proof1.gamma, verified1.dangerously_access_gamma());

        // Test deterministic output
        let proof1_again = vrf.prove(&keypair, h1);
        assert_eq!(proof1.gamma, proof1_again.gamma, "Gamma should be deterministic");

        // Test wrong public key
        let wrong_keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
        assert!(
            vrf.verify(wrong_keypair.public_key(), h1, &proof1).is_none(),
            "Proof should not verify with wrong public key"
        );

        // Test wrong H
        let wrong_h = Point::hash_to_curve(sha2::Sha256::default().add(b"different"));
        assert!(
            vrf.verify(keypair.public_key(), wrong_h, &proof1).is_none(),
            "Proof should not verify with wrong H"
        );

        // Test different inputs produce different outputs
        if alpha1 != alpha2 {
            let h2 = Point::hash_to_curve(sha2::Sha256::default().add(&alpha2[..]));
            let proof2 = vrf.prove(&keypair, h2);
            let verified2 = vrf.verify(keypair.public_key(), h2, &proof2)
                .expect("Second proof should verify");

            assert_ne!(verified1.dangerously_access_gamma(), verified2.dangerously_access_gamma(), "Different inputs should produce different gamma");

            // Cross-verification should fail
            assert!(
                vrf.verify(keypair.public_key(), h1, &proof2).is_none(),
                "Proof for h2 should not verify with h1"
            );
            assert!(
                vrf.verify(keypair.public_key(), h2, &proof1).is_none(),
                "Proof for h1 should not verify with h2"
            );
        }
    }
}
