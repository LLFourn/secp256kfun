#![cfg(feature = "serde")]
use schnorr_fun::{
    binonce,
    fun::{marker::*, Point, Scalar},
    musig::{self, NonceKeyPair},
    Message,
};
static TEST_JSON: &'static str = include_str!("musig/sign_verify_vectors.json");
use secp256kfun::hex;
use serde_crate as serde;

#[derive(serde::Deserialize, Clone, Copy, Debug)]
#[serde(crate = "serde_crate", untagged)]
pub enum Maybe<T> {
    Valid(T),
    Invalid(&'static str),
}

impl<T> Maybe<T> {
    fn unwrap(self) -> T {
        match self {
            Maybe::Valid(t) => t,
            Maybe::Invalid(string) => panic!("unwrapped an invalid Maybe: {}", string),
        }
    }
}
#[derive(serde::Deserialize)]
#[serde(crate = "serde_crate")]
pub struct TestCases {
    sk: Scalar,
    secnonce: NonceKeyPair,
    #[serde(bound(deserialize = "Maybe<Point>: serde::de::Deserialize<'de>"))]
    pubkeys: Vec<Maybe<Point>>,
    #[serde(bound(deserialize = "Maybe<binonce::Nonce>: serde::de::Deserialize<'de>"))]
    pnonces: Vec<Maybe<binonce::Nonce>>,
    #[serde(bound(deserialize = "Maybe<binonce::Nonce<Zero>>: serde::de::Deserialize<'de>"))]
    aggnonces: Vec<Maybe<binonce::Nonce<Zero>>>,
    msgs: Vec<String>,
    #[serde(bound(deserialize = "TestCase: serde::de::Deserialize<'de>"))]
    valid_test_cases: Vec<TestCase>,
    verify_error_test_cases: Vec<TestCase>,
    verify_fail_test_cases: Vec<TestCase>,
    sign_error_test_cases: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
#[serde(crate = "serde_crate")]
pub struct TestCase {
    #[serde(bound(deserialize = "Maybe<Scalar<Public, Zero>>: serde::de::Deserialize<'de>"))]
    sig: Option<Maybe<Scalar<Public, Zero>>>,
    key_indices: Vec<usize>,
    nonce_indices: Option<Vec<usize>>,
    aggnonce_index: Option<usize>,
    msg_index: usize,
    signer_index: Option<usize>,
    expected: Option<Scalar>,
    #[allow(dead_code)]
    error: Option<serde_json::Value>,
}

#[test]
fn musig_sign_verify() {
    let test_cases = serde_json::from_str::<TestCases>(TEST_JSON).unwrap();
    let musig = musig::new_without_nonce_generation::<sha2::Sha256>();
    let keypair = musig.new_keypair(test_cases.sk.clone());

    for test_case in &test_cases.valid_test_cases {
        let pubkeys = test_case
            .key_indices
            .iter()
            .map(|i| test_cases.pubkeys[*i].unwrap())
            .collect();
        let pubnonces = test_case
            .nonce_indices
            .clone()
            .unwrap()
            .iter()
            .map(|i| test_cases.pnonces[*i].unwrap())
            .collect();
        let _aggnonce = test_cases.aggnonces[test_case.aggnonce_index.unwrap()].unwrap();
        let msg = hex::decode(&test_cases.msgs[test_case.msg_index]).unwrap();
        let agg_key = musig.new_agg_key(pubkeys).into_xonly_key();
        let session = musig.start_sign_session(&agg_key, pubnonces, Message::raw(&msg[..]));
        let partial_sig = musig.sign(
            &agg_key,
            &session,
            test_case.signer_index.unwrap(),
            &keypair,
            test_cases.secnonce.clone(),
        );
        assert_eq!(partial_sig, test_case.expected.clone().unwrap());
        assert!(musig.verify_partial_signature(
            &agg_key,
            &session,
            test_case.signer_index.unwrap(),
            partial_sig
        ));
    }

    for test_case in &test_cases.sign_error_test_cases {
        let result = std::panic::catch_unwind(|| {
            let pubkeys = test_case
                .key_indices
                .iter()
                .map(|i| test_cases.pubkeys[*i].unwrap())
                .collect();
            let _agg_key = musig.new_agg_key(pubkeys).into_xonly_key();
            let _msg = hex::decode(&test_cases.msgs[test_case.msg_index]).unwrap();
            let _aggnonce = test_cases.aggnonces[test_case.aggnonce_index.unwrap()].unwrap();
        });

        assert!(result.is_err());
    }

    for test_case in &test_cases.verify_fail_test_cases {
        let sig = test_case.sig.unwrap();
        let result = std::panic::catch_unwind(|| {
            let partial_sig = sig.unwrap();
            let pubkeys = test_case
                .key_indices
                .iter()
                .map(|i| test_cases.pubkeys[*i].unwrap())
                .collect();

            let agg_key = musig.new_agg_key(pubkeys).into_xonly_key();

            let pubnonces = test_case
                .nonce_indices
                .clone()
                .unwrap()
                .iter()
                .map(|i| test_cases.pnonces[*i].unwrap())
                .collect();

            let msg = hex::decode(&test_cases.msgs[test_case.msg_index]).unwrap();
            let session = musig.start_sign_session(&agg_key, pubnonces, Message::raw(&msg[..]));

            assert!(musig.verify_partial_signature(
                &agg_key,
                &session,
                test_case.signer_index.unwrap(),
                partial_sig
            ));
        });

        assert!(result.is_err());
    }

    for test_case in &test_cases.verify_error_test_cases {
        let sig = test_case.sig.unwrap();

        let result = std::panic::catch_unwind(|| {
            let _partial_sig = sig.unwrap();
            let _pubkeys = test_case
                .key_indices
                .iter()
                .map(|i| test_cases.pubkeys[*i].unwrap())
                .collect::<Vec<_>>();

            let _pubnonces = test_case
                .nonce_indices
                .clone()
                .unwrap()
                .iter()
                .map(|i| test_cases.pnonces[*i].unwrap())
                .collect::<Vec<_>>();

            let _msg = hex::decode(&test_cases.msgs[test_case.msg_index]).unwrap();
        });

        assert!(result.is_err());
    }
}
