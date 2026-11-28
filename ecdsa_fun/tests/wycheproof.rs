#![cfg(feature = "alloc")]

use ecdsa_fun::{
    ECDSA, Signature,
    fun::{Point, hex, marker::*},
};
use sha2::Sha256;

static WYCHEPROOF_JSON: &str = include_str!("wycheproof_ecdsa_p1363.json");

#[derive(serde::Deserialize)]
struct WycheproofFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<TestGroup>,
}

#[derive(serde::Deserialize)]
struct TestGroup {
    #[serde(rename = "publicKey")]
    public_key: PublicKeyData,
    tests: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
struct PublicKeyData {
    uncompressed: String,
}

#[derive(serde::Deserialize)]
struct TestCase {
    #[serde(rename = "tcId")]
    tc_id: u32,
    comment: String,
    msg: String,
    sig: String,
    result: String,
}

#[test]
fn wycheproof_ecdsa_p1363() {
    use ecdsa_fun::fun::digest::Digest;

    let ecdsa = ECDSA::verify_only();
    let test_file: WycheproofFile = serde_json::from_str(WYCHEPROOF_JSON).unwrap();
    let mut tests_run = 0;

    for group in &test_file.test_groups {
        let pk_bytes: [u8; 65] = match hex::decode_array(&group.public_key.uncompressed) {
            Ok(b) => b,
            Err(_) => {
                for test in &group.tests {
                    assert_ne!(
                        test.result, "valid",
                        "tcId {}: valid test but public key failed to decode ({})",
                        test.tc_id, test.comment
                    );
                    tests_run += 1;
                }
                continue;
            }
        };
        let verification_key =
            match Point::<Normal, Public, NonZero>::from_bytes_uncompressed(pk_bytes) {
                Some(pk) => pk,
                None => {
                    for test in &group.tests {
                        assert_ne!(
                            test.result, "valid",
                            "tcId {}: valid test but public key not on curve ({})",
                            test.tc_id, test.comment
                        );
                        tests_run += 1;
                    }
                    continue;
                }
            };

        for test in &group.tests {
            let expected_valid = test.result == "valid";

            let msg_bytes = hex::decode(&test.msg).unwrap();
            let message_hash: [u8; 32] = Sha256::digest(&msg_bytes).into();

            let sig_bytes: [u8; 64] = match hex::decode_array(&test.sig) {
                Ok(b) => b,
                Err(_) => {
                    assert!(
                        !expected_valid,
                        "tcId {}: valid test but signature hex failed to decode ({})",
                        test.tc_id, test.comment
                    );
                    tests_run += 1;
                    continue;
                }
            };
            let signature = match Signature::from_bytes(sig_bytes) {
                Some(sig) => sig,
                None => {
                    assert!(
                        !expected_valid,
                        "tcId {}: valid test but signature failed to parse ({})",
                        test.tc_id, test.comment
                    );
                    tests_run += 1;
                    continue;
                }
            };

            let actual_valid = ecdsa.verify(&verification_key, &message_hash, &signature);
            assert_eq!(
                actual_valid,
                expected_valid,
                "tcId {}: expected {}, got {} ({})",
                test.tc_id,
                test.result,
                if actual_valid { "valid" } else { "invalid" },
                test.comment,
            );
            tests_run += 1;
        }
    }

    assert_eq!(
        tests_run, test_file.number_of_tests,
        "expected to run all test vectors"
    );
}
