#![cfg(feature = "serde")]
extern crate serde_crate as serde;

static DLC_SPEC_JSON: &'static str = include_str!("./test_vectors.json");
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature, HashTranscript},
    fun::{Point, Scalar},
    Signature,
};
use sha2::Sha256;

#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(crate = "serde_crate")
)]
struct TestVector {
    adaptor_sig: EncryptedSignature,
    public_signing_key: Point,
    encryption_key: Point,
    signature: Signature,
    decryption_key: Scalar,
    message_hash: Scalar,
    error: Option<String>,
}

#[test]
fn run_test_vectors() {
    let ecdsa_adaptor = Adaptor::<HashTranscript<Sha256>, _>::verify_only();
    let test_vectors = serde_json::from_str::<Vec<TestVector>>(DLC_SPEC_JSON).unwrap();
    for t in test_vectors {
        if run_test_vector(&ecdsa_adaptor, &t) {
            assert_eq!(t.error, None)
        } else {
            assert!(t.error.is_some())
        }
    }
}

fn run_test_vector(ecdsa_adaptor: &Adaptor<HashTranscript<Sha256>, ()>, t: &TestVector) -> bool {
    if !ecdsa_adaptor.verify_encrypted_signature(
        &t.public_signing_key,
        &t.encryption_key,
        &t.message_hash.to_bytes(),
        &t.adaptor_sig,
    ) {
        return false;
    }

    let signature = ecdsa_adaptor.decrypt_signature(&t.decryption_key, t.adaptor_sig.clone());

    if t.signature != signature {
        return false;
    }

    let decryption_key =
        ecdsa_adaptor.recover_decryption_key(&t.encryption_key, &t.signature, &t.adaptor_sig);

    decryption_key == Some(t.decryption_key.clone())
}
