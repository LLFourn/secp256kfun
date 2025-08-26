use secp256kfun::{KeyPair, prelude::*};
use vrf_fun::VrfProof;

#[cfg(feature = "bincode")]
#[test]
fn test_vrf_proof_bincode_roundtrip() {
    let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
    let proof = vrf_fun::rfc9381::sswu::prove::<sha2::Sha256>(&keypair, b"test message");

    let encoded = bincode::encode_to_vec(&proof, bincode::config::standard()).unwrap();
    let (decoded, _): (VrfProof, _) =
        bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(proof, decoded);
}

#[cfg(all(feature = "bincode", feature = "serde"))]
#[test]
fn test_vrf_proof_serde_roundtrip() {
    use bincode::serde::Compat;

    let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
    let proof = vrf_fun::rfc9381::sswu::prove::<sha2::Sha256>(&keypair, b"test message");

    let compat_proof = Compat(&proof);
    let encoded = bincode::encode_to_vec(compat_proof, bincode::config::standard()).unwrap();
    let (decoded, _): (Compat<VrfProof>, _) =
        bincode::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(proof, decoded.0);
}
