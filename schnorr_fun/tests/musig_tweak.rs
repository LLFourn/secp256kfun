#![allow(warnings)]
#![cfg(feature = "serde")]
use std::{rc::Rc, sync::Arc};

use schnorr_fun::{
    Message,
    binonce::{self, NonceKeyPair},
    fun::{Point, Scalar, marker::*, serde},
    musig,
};
static TEST_JSON: &'static str = include_str!("musig/tweak_vectors.json");
use secp256kfun::hex;

#[derive(serde::Deserialize, Clone, Debug)]
#[serde(crate = "self::serde", untagged)]
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

struct SecNonce {
    nonce: binonce::SecretNonce,
    _pk: Point,
}

impl SecNonce {
    pub fn from_bytes(bytes: [u8; 97]) -> Option<Self> {
        let mut nonce = [0u8; 64];
        nonce.copy_from_slice(&bytes[..64]);
        let nonce = binonce::SecretNonce::from_bytes(nonce)?;
        Some(SecNonce {
            nonce,
            _pk: Point::from_slice(&bytes[64..])?,
        })
    }
}

schnorr_fun::fun::impl_fromstr_deserialize! {
    name => "secret nonce with 33 byte public key at the end",
    fn from_bytes(bytes: [u8; 97]) -> Option<SecNonce> {
        SecNonce::from_bytes(bytes)
    }
}

impl<T: Copy> Copy for Maybe<T> {}

#[derive(serde::Deserialize)]
#[serde(crate = "self::serde")]
pub struct TestCases {
    sk: Scalar,
    secnonce: SecNonce,
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
#[serde(crate = "self::serde")]
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

/// Returns `None` if a plain tweak follows an x-only tweak because `AggKey` can't express that.
fn apply_tweaks(
    mut agg_key: musig::AggKey<Normal>,
    mut tweaks: impl Iterator<Item = Scalar<Public, Zero>>,
    is_xonly: &[bool],
) -> Option<musig::AggKey<EvenY>> {
    let n_plain = is_xonly.iter().take_while(|is_xonly| !**is_xonly).count();
    let (plain, xonly) = is_xonly.split_at(n_plain);

    for _ in plain {
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    let mut agg_key = agg_key.into_xonly_key();

    for is_xonly in xonly {
        if !is_xonly {
            return None;
        }
        agg_key = agg_key.tweak(tweaks.next().unwrap()).unwrap();
    }

    Some(agg_key)
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

    let tweaks = test_case
        .tweak_indices
        .iter()
        .map(|i| test_cases.tweaks[*i].unwrap());

    let Some(agg_key) = apply_tweaks(musig.new_agg_key(pubkeys), tweaks, &test_case.is_xonly)
    else {
        return;
    };

    let session = musig.start_sign_session(&agg_key, pubnonces, Message::raw(&msg[..]));
    let partial_sig = musig.sign(
        &agg_key,
        &session,
        test_case.signer_index.unwrap(),
        &keypair,
        test_cases.secnonce.nonce.clone(),
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

static SIG_AGG_JSON: &str = include_str!("musig/sig_agg_vectors.json");

#[derive(serde::Deserialize)]
#[serde(crate = "self::serde")]
struct SigAggCases {
    pubkeys: Vec<Point>,
    pnonces: Vec<binonce::Nonce>,
    tweaks: Vec<Scalar<Public, Zero>>,
    psigs: Vec<String>,
    msg: String,
    valid_test_cases: Vec<SigAggCase>,
    error_test_cases: Vec<SigAggCase>,
}

#[derive(serde::Deserialize)]
#[serde(crate = "self::serde")]
struct SigAggCase {
    aggnonce: binonce::Nonce<Zero>,
    nonce_indices: Vec<usize>,
    key_indices: Vec<usize>,
    tweak_indices: Vec<usize>,
    is_xonly: Vec<bool>,
    psig_indices: Vec<usize>,
    expected: Option<schnorr_fun::Signature>,
    error: Option<serde_json::Value>,
}

#[test]
fn musig_sig_agg() {
    let test_cases = serde_json::from_str::<SigAggCases>(SIG_AGG_JSON).unwrap();
    let musig = musig::new_without_nonce_generation::<sha2::Sha256>();
    let msg = hex::decode(&test_cases.msg).unwrap();
    let message = Message::raw(&msg[..]);

    for test_case in &test_cases.valid_test_cases {
        let pubkeys = test_case
            .key_indices
            .iter()
            .map(|i| test_cases.pubkeys[*i])
            .collect();
        let pubnonces = test_case
            .nonce_indices
            .iter()
            .map(|i| test_cases.pnonces[*i])
            .collect::<Vec<_>>();
        let tweaks = test_case
            .tweak_indices
            .iter()
            .map(|i| test_cases.tweaks[*i]);
        let psigs = test_case
            .psig_indices
            .iter()
            .map(|i| test_cases.psigs[*i].parse().unwrap());

        assert_eq!(
            binonce::Nonce::aggregate(pubnonces.iter().copied()),
            test_case.aggnonce
        );

        let Some(agg_key) = apply_tweaks(musig.new_agg_key(pubkeys), tweaks, &test_case.is_xonly)
        else {
            continue;
        };

        let session = musig.start_sign_session(&agg_key, pubnonces, message);
        let sig = musig.combine_partial_signatures(&agg_key, &session, psigs);

        assert_eq!(sig, test_case.expected.unwrap());
        assert!(
            musig
                .schnorr
                .verify(&agg_key.agg_public_key(), message, &sig)
        );
    }

    for test_case in &test_cases.error_test_cases {
        let error = test_case.error.as_ref().unwrap();
        let signer = error["signer"].as_u64().unwrap() as usize;
        let bad_psig = &test_cases.psigs[test_case.psig_indices[signer]];
        assert!(bad_psig.parse::<Scalar<Public, Zero>>().is_err());
    }
}
