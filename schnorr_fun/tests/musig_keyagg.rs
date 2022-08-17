#![cfg(feature = "serde")]
use schnorr_fun::{
    fun::{marker::*, Point, Scalar},
    musig,
};
static TEST_JSON: &'static str = include_str!("musig/key_agg_vectors.json");
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
    #[serde(bound(deserialize = "Maybe<Point>: serde::de::Deserialize<'de>"))]
    pubkeys: Vec<Maybe<Point>>,
    #[serde(default)]
    #[serde(bound(deserialize = "Maybe<Scalar<Public,Zero>>: serde::de::Deserialize<'de>"))]
    tweaks: Vec<Maybe<Scalar<Public, Zero>>>,
    valid_test_cases: Vec<TestCase>,
    error_test_cases: Vec<TestCase>,
}

#[derive(serde::Deserialize)]
#[serde(crate = "serde_crate")]
pub struct TestCase {
    key_indices: Vec<usize>,
    #[serde(default)]
    tweak_indices: Vec<usize>,
    #[serde(default)]
    is_xonly: Vec<bool>,
    #[allow(dead_code)]
    error: Option<serde_json::Value>,
    expected: Option<Point<EvenY>>,
}

#[test]
fn musig_key_agg() {
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

    let pubkeys = test_case
        .key_indices
        .iter()
        .map(|i| test_cases.pubkeys[*i].unwrap())
        .collect();

    let mut agg_key = musig.new_agg_key(pubkeys);

    let mut tweaks = test_case
        .tweak_indices
        .iter()
        .map(|i| test_cases.tweaks[*i].unwrap());

    let mut tweak_is_xonly = test_case.is_xonly.clone();

    while tweak_is_xonly.get(0) == Some(&false) {
        tweak_is_xonly.remove(0);
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    let mut agg_key = agg_key.into_xonly_key();

    while tweak_is_xonly.get(0) == Some(&true) {
        tweak_is_xonly.remove(0);
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    if let Some(expected) = &test_case.expected {
        assert_eq!(agg_key.agg_public_key(), *expected);
    }
}
