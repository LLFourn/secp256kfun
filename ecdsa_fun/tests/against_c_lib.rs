#![cfg(feature = "libsecp_compat")]
use ecdsa_fun::{
    self,
    fun::{
        hex,
        secp256k1::{self, ecdsa, Message, PublicKey, SecretKey},
        Point, Scalar, TEST_SOUNDNESS,
    },
};

fn rand_32_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Verify that signatures produced by us are valid according to the c-lib
#[test]
fn ecdsa_sign() {
    let secp = secp256k1::Secp256k1::new();
    let ecdsa = ecdsa_fun::test_instance!();
    for _ in 0..TEST_SOUNDNESS {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let public_key = ecdsa.verification_key_for(&secret_key);
        let c_public_key = PublicKey::from(public_key);
        let message = rand_32_bytes();
        let signature = ecdsa.sign(&secret_key, &message);
        let c_message = Message::from_slice(&message[..]).unwrap();
        let c_siganture = ecdsa::Signature::from_compact(&signature.to_bytes()).unwrap();
        assert!(secp
            .verify_ecdsa(&c_message, &c_siganture, &c_public_key)
            .is_ok());
    }
}

/// Verify that signatures produced by the c-lib are valid under our verification algorithm
#[test]
fn ecdsa_verify() {
    let secp = secp256k1::Secp256k1::new();
    let ecdsa = ecdsa_fun::test_instance!();

    for _ in 0..TEST_SOUNDNESS {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let c_secret_key = SecretKey::from(secret_key);
        let c_public_key = PublicKey::from_secret_key(&secp, &c_secret_key);
        let public_key = Point::from(c_public_key);
        let message = rand_32_bytes();
        let c_message = Message::from_slice(&message[..]).unwrap();
        let c_signature = secp.sign_ecdsa(&c_message, &c_secret_key);
        let signature = ecdsa_fun::Signature::from(c_signature);
        assert!(ecdsa.verify(&public_key, &message, &signature));
    }
}

/// Signatures on message above the curve order verify
#[test]
fn ecdsa_verify_high_message() {
    let ecdsa = ecdsa_fun::ECDSA::verify_only();
    let secp = secp256k1::Secp256k1::new();
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let verification_key = ecdsa.verification_key_for(&secret_key);
    let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
    let message =
        hex::decode_array("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            .unwrap();
    let c_message = Message::from_slice(&message[..]).unwrap();
    let c_signature = secp.sign_ecdsa(&c_message, &c_secret_key);
    let signature = ecdsa_fun::Signature::from_bytes(c_signature.serialize_compact()).unwrap();

    assert!(ecdsa.verify(&verification_key, &message, &signature));
}

/// Signature on message above the curve order signed by us can be verified by the c-lib
#[test]
fn ecdsa_sign_high_message() {
    let ecdsa = ecdsa_fun::test_instance!();
    let secp = secp256k1::Secp256k1::new();
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
    let c_public_key = PublicKey::from_secret_key(&secp, &c_secret_key);

    let message =
        hex::decode_array("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            .unwrap();
    let signature = ecdsa.sign(&secret_key, &message);
    let c_message = Message::from_slice(&message[..]).unwrap();
    let c_siganture = ecdsa::Signature::from_compact(&signature.to_bytes()).unwrap();
    assert!(secp
        .verify_ecdsa(&c_message, &c_siganture, &c_public_key)
        .is_ok());
}
