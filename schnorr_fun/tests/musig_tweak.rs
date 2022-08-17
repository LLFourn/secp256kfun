#![allow(warnings)]
#![cfg(feature = "serde")]
use std::{rc::Rc, sync::Arc};

use schnorr_fun::{
    binonce,
    fun::{marker::*, Point, Scalar},
    musig::{self, NonceKeyPair},
    Message,
};
static TEST_JSON: &'static str = include_str!("musig/tweak_vectors.json");
use secp256kfun::hex;
use serde_crate as serde;

#[derive(serde::Deserialize, Clone, Debug)]
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
impl<T: Copy> Copy for Maybe<T> {}

#[derive(serde::Deserialize)]
#[serde(crate = "serde_crate")]
pub struct TestCases {
    sk: Scalar,
    secnonce: NonceKeyPair,
    #[serde(bound(deserialize = "Maybe<Point>: serde::de::Deserialize<'de>"))]
    pubkeys: Vec<Maybe<Point>>,
    #[serde(bound(deserialize = "Maybe<binonce::Nonce>: serde::de::Deserialize<'de>"))]
    pnonces: Vec<Maybe<binonce::Nonce>>,
    aggnonce: binonce::Nonce<Zero>,
    #[serde(bound(deserialize = "Maybe<Scalar<Public,Zero>>: serde::de::Deserialize<'de>"))]
    tweaks: Vec<Maybe<Scalar<Public, Zero>>>,
    msg: String,
    valid_test_cases: Vec<TestCase>,
    error_test_cases: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
#[serde(crate = "serde_crate")]
pub struct TestCase {
    #[serde(bound(deserialize = "Maybe<Scalar<Public,Zero>>: serde::de::Deserialize<'de>"))]
    sig: Option<Maybe<Scalar<Public, Zero>>>,
    key_indices: Vec<usize>,
    nonce_indices: Option<Vec<usize>>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    signer_index: Option<usize>,
    expected: Option<Scalar>,
    #[allow(dead_code)]
    error: Option<serde_json::Value>,
}

#[test]
fn musig_tweak_tests() {
    let test_cases = serde_json::from_str::<TestCases>(TEST_JSON).unwrap();

    for test_case in &test_cases.valid_test_cases {
        run_test(&test_cases, test_case);
    }

    for test_case in &test_cases.error_test_cases {
        let result = std::panic::catch_unwind(|| {
            run_test(&test_cases, test_case);
        });
        assert!(result.is_err());
    }
}

fn run_test(test_cases: &TestCases, test_case: &TestCase) {
    let musig = musig::new_without_nonce_generation::<sha2::Sha256>();
    let msg = hex::decode(&test_cases.msg).unwrap();
    let keypair = musig.new_keypair(test_cases.sk.clone());

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

    let mut tweaks = test_case
        .tweak_indices
        .iter()
        .map(|i| test_cases.tweaks[*i].unwrap());

    let mut tweak_is_xonly = test_case.is_xonly.clone();
    let mut agg_key = musig.new_agg_key(pubkeys);

    while tweak_is_xonly.get(0) == Some(&false) {
        tweak_is_xonly.remove(0);
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    let mut agg_key = agg_key.into_xonly_key();

    while tweak_is_xonly.get(0) == Some(&true) {
        tweak_is_xonly.remove(0);
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    if !tweak_is_xonly.is_empty() {
        // XXX: we can't run this test because it does an plain tweak after an xonly tweak
        return;
    }

    let session = musig.start_sign_session(&agg_key, pubnonces, Message::raw(&msg[..]));
    let partial_sig = musig.sign(
        &agg_key,
        &session,
        test_case.signer_index.unwrap(),
        &keypair,
        test_cases.secnonce.clone(),
    );

    if let Some(expected) = test_case.expected.clone() {
        assert_eq!(partial_sig, expected);
    }
    assert!(musig.verify_partial_signature(
        &agg_key,
        &session,
        test_case.signer_index.unwrap(),
        partial_sig
    ));
}
