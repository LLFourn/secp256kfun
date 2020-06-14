use ecdsa_fun::{
    self,
    fun::{g, hash::Derivation, Scalar, G, TEST_SOUNDNESS},
};
use secp256k1::{Message, PublicKey, SecretKey};

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

    for _ in 0..TEST_SOUNDNESS {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
        let c_public_key = PublicKey::from_secret_key(&secp, &c_secret_key);

        let ecdsa = ecdsa_fun::ECDSA::from_tag(b"test");
        let message = rand_32_bytes();
        let signature = ecdsa.sign(&secret_key, &message, Derivation::Deterministic);
        let c_message = Message::from_slice(&message[..]).unwrap();
        let c_siganture = secp256k1::Signature::from_compact(&signature.to_bytes()).unwrap();
        assert!(secp.verify(&c_message, &c_siganture, &c_public_key).is_ok());
    }
}

/// Verify that signatures produced by the c-lib are valid under our verification algorithm
#[test]
fn ecdsa_verify() {
    let secp = secp256k1::Secp256k1::new();
    let ecdsa = ecdsa_fun::ECDSA::from_tag(b"test").enforce_low_s();

    for _ in 0..TEST_SOUNDNESS {
        let secret_key = Scalar::random(&mut rand::thread_rng());
        let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
        let message = rand_32_bytes();
        let c_message = Message::from_slice(&message[..]).unwrap();
        let c_signature = secp.sign(&c_message, &c_secret_key);
        let signature = ecdsa_fun::Signature::from_bytes(c_signature.serialize_compact()).unwrap();

        assert!(ecdsa.verify(&g!(secret_key * G), &message, &signature));
    }
}

/// Signatures on message above the curve order verify
#[test]
fn ecdsa_verify_high_message() {
    let ecdsa = ecdsa_fun::ECDSA::from_tag(b"test");
    let secp = secp256k1::Secp256k1::new();
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
    let message =
        hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let c_message = Message::from_slice(&message[..]).unwrap();
    let c_signature = secp.sign(&c_message, &c_secret_key);
    let signature = ecdsa_fun::Signature::from_bytes(c_signature.serialize_compact()).unwrap();

    assert!(ecdsa.verify(&g!(secret_key * G), &message, &signature));
}

/// Signature on message above the curve order signed by us can be verified by the c-lib
#[test]
fn ecdsa_sign_high_message() {
    let ecdsa = ecdsa_fun::ECDSA::from_tag(b"test");
    let secp = secp256k1::Secp256k1::new();
    let secret_key = Scalar::random(&mut rand::thread_rng());
    let c_secret_key = SecretKey::from_slice(&secret_key.to_bytes()).unwrap();
    let c_public_key = PublicKey::from_secret_key(&secp, &c_secret_key);

    let message =
        hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
    let signature = ecdsa.sign(&secret_key, &message, Derivation::Deterministic);
    let c_message = Message::from_slice(&message[..]).unwrap();
    let c_siganture = secp256k1::Signature::from_compact(&signature.to_bytes()).unwrap();
    assert!(secp.verify(&c_message, &c_siganture, &c_public_key).is_ok());
}
