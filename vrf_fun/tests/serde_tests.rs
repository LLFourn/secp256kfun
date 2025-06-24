#![cfg(all(feature = "serde", feature = "bincode"))]
use secp256kfun::{KeyPair, prelude::*};
use vrf_fun::rfc9381;

#[test]
fn test_vrf_proof_serde_through_bincode() {
    use serde::{Deserialize, Serialize};

    let secret_key = Scalar::random(&mut rand::thread_rng());
    let keypair = KeyPair::new(secret_key);
    let alpha = b"test message";

    let proof = rfc9381::tai::prove::<sha2::Sha256>(&keypair, alpha);

    // This function won't compile unless VrfProof implements Serialize/Deserialize
    fn assert_serde<T: Serialize + for<'de> Deserialize<'de>>(_: &T) {}
    assert_serde(&proof);

    let encoded = bincode::serde::encode_to_vec(proof.clone(), bincode::config::standard())
        .expect("Should encode through serde");

    let deserialized: vrf_fun::VrfProof =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
            .expect("Should decode through serde")
            .0;

    let verified = rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), alpha, &deserialized);
    assert!(verified.is_some(), "Deserialized proof should verify");

    assert_eq!(proof.gamma, deserialized.gamma);
    assert_eq!(
        encoded.len(),
        81,
        "VRF proof serde+bincode size should be 81 bytes"
    );
}

#[test]
fn test_vrf_proof_bincode() {
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let keypair = KeyPair::new(secret_key);
    let alpha = b"test message";

    let proof = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, alpha);

    let encoded = bincode::encode_to_vec(&proof, bincode::config::standard())
        .expect("Should encode with bincode");

    let (deserialized, _) = bincode::decode_from_slice(&encoded, bincode::config::standard())
        .expect("Should decode with bincode");

    let verified =
        rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), alpha, &deserialized);
    assert!(verified.is_some(), "Deserialized proof should verify");

    assert_eq!(proof.gamma, deserialized.gamma);
    assert_eq!(
        encoded.len(),
        81,
        "VRF proof bincode size should be 81 bytes"
    );
}
