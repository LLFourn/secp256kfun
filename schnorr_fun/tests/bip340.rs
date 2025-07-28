use core::str::FromStr;
use schnorr_fun::{
    Message, Schnorr, Signature,
    fun::{hex, marker::*},
};
use secp256kfun::Point;
use sha2::Sha256;

static BIP340_CSV: &str = include_str!("bip340-test-vectors.csv");

#[test]
fn bip340_test_vectors() {
    let bip340 = Schnorr::<Sha256>::verify_only();
    let mut tests_run = 0;

    for (line_num, line) in BIP340_CSV.lines().enumerate() {
        if line_num == 0 || line.trim().is_empty() {
            continue; // Skip header and empty lines
        }

        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 7 {
            continue;
        }

        // CSV format: index,secret_key,public_key,aux_rand,message,signature,verification_result,comment
        let pubkey_hex = parts[2];
        let message_hex = parts[4];
        let sig_hex = parts[5];
        let should_verify = parts[6] == "TRUE";
        let comment = if parts.len() > 7 { parts[7] } else { "" };

        let pubkey = Point::<EvenY, Public>::from_str(pubkey_hex).ok();
        let message = hex::decode(message_hex).unwrap_or_default();
        let signature = Signature::from_str(sig_hex).ok();

        if let (Some(pubkey), Some(signature)) = (pubkey, signature) {
            let result = bip340.verify(&pubkey, Message::raw(&message), &signature);
            assert_eq!(
                result, should_verify,
                "Line {line_num}: Expected {should_verify}, got {result} ({comment})"
            );
            tests_run += 1;
        } else {
            assert!(
                !should_verify,
                "Line {line_num}: Invalid input should fail ({comment})"
            );
            tests_run += 1;
        }
    }

    assert!(tests_run > 0, "No test vectors were executed!");
}
