#![cfg(all(feature = "serde", feature = "alloc", feature = "adaptor"))]

static DLC_SPEC_JSON: &'static str = include_str!("./test_vectors.json");
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature, HashTranscript},
    fun::{Point, Scalar},
    nonce::NoNonces,
    serde, Signature,
};
use sha2::Sha256;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", crate = "self::serde")]
enum TestVector {
    Verification(Verification),
    Recovery(Recovery),
    Serialization(Serialization),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(crate = "self::serde")]
struct Recovery {
    encryption_key: Point,
    signature: Signature,
    adaptor_sig: EncryptedSignature,
    decryption_key: Option<Scalar>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(crate = "self::serde")]
struct Verification {
    adaptor_sig: EncryptedSignature,
    public_signing_key: Point,
    encryption_key: Point,
    signature: Signature,
    decryption_key: Scalar,
    message_hash: Scalar,
    error: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(crate = "self::serde")]
struct Serialization {
    adaptor_sig: String,
    error: Option<String>,
}

#[test]
fn run_test_vectors() {
    let ecdsa_adaptor = Adaptor::<HashTranscript<Sha256>, _>::verify_only();
    let test_vectors = serde_json::from_str::<Vec<TestVector>>(DLC_SPEC_JSON).unwrap();
    for t in test_vectors {
        match t {
            TestVector::Verification(t) => {
                if run_test_vector(&ecdsa_adaptor, &t) {
                    assert_eq!(t.error, None)
                } else {
                    assert!(t.error.is_some())
                }
            }
            TestVector::Recovery(t) => {
                let decryption_key = ecdsa_adaptor.recover_decryption_key(
                    &t.encryption_key,
                    &t.signature,
                    &t.adaptor_sig,
                );
                assert_eq!(decryption_key, t.decryption_key);
            }
            TestVector::Serialization(t) => {
                use core::str::FromStr;
                match EncryptedSignature::from_str(&t.adaptor_sig) {
                    Ok(encrypted_sig) => {
                        assert!(t.error.is_none());
                        assert_eq!(encrypted_sig.to_string(), t.adaptor_sig);
                    }
                    Err(_) => assert!(t.error.is_some()),
                }
            }
        }
    }
}

fn run_test_vector(
    ecdsa_adaptor: &Adaptor<HashTranscript<Sha256>, NoNonces>,
    t: &Verification,
) -> bool {
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
