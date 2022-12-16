#![cfg(feature = "serde")]
use schnorr_fun::{
    binonce,
    fun::{marker::*, Point, Scalar},
    musig::{self, NonceKeyPair},
    serde, Message,
};
static TEST_JSON: &'static str = include_str!("musig/sign_verify_vectors.json");
use secp256kfun::hex;

#[derive(schnorr_fun::serde::Deserialize, Clone, Copy, Debug)]
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

#[derive(Clone, Debug)]
struct SecNonce {
    nonce: NonceKeyPair,
    pk: Point,
}

impl SecNonce {
    pub fn from_bytes(bytes: [u8; 97]) -> Option<Self> {
        let mut nonce = [0u8; 64];
        nonce.copy_from_slice(&bytes[..64]);
        let nonce = binonce::NonceKeyPair::from_bytes(nonce)?;
        Some(SecNonce {
            nonce,
            pk: Point::from_slice(&bytes[64..])?,
        })
    }
}

schnorr_fun::fun::impl_fromstr_deserialize! {
    name => "secret nonce with 33 byte public key at the end",
    fn from_bytes(bytes: [u8; 97]) -> Option<SecNonce> {
        SecNonce::from_bytes(bytes)
    }
}

#[derive(serde::Deserialize)]
#[serde(crate = "self::serde")]
pub struct TestCases {
    sk: Scalar,
    #[serde(bound(deserialize = "Maybe<SecNonce>: serde::de::Deserialize<'de>"))]
    secnonces: Vec<Maybe<SecNonce>>,
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

#[derive(serde::Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct TestCase {
    #[serde(bound(deserialize = "Maybe<Scalar<Public, Zero>>: serde::de::Deserialize<'de>"))]
    sig: Option<Maybe<Scalar<Public, Zero>>>,
    key_indices: Vec<usize>,
    #[serde(default)]
    secnonce_index: usize,
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
            test_cases.secnonces[test_case.secnonce_index]
                .clone()
                .unwrap()
                .nonce,
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
                .collect::<Vec<_>>();
            let agg_key = musig.new_agg_key(pubkeys.clone()).into_xonly_key();
            let msg = hex::decode(&test_cases.msgs[test_case.msg_index]).unwrap();
            let _aggnonce = test_cases.aggnonces[test_case.aggnonce_index.unwrap()].unwrap();
            let secnonce = test_cases.secnonces[test_case.secnonce_index]
                .clone()
                .unwrap();

            let pubnonces = test_case
                .nonce_indices
                .clone()
                .unwrap()
                .iter()
                .map(|i| test_cases.pnonces[*i].unwrap())
                .collect();

            let session = musig.start_sign_session(&agg_key, pubnonces, Message::raw(&msg[..]));

            let signer_index = test_case.signer_index.unwrap_or(0);

            assert_eq!(
                secnonce.pk, pubkeys[signer_index],
                "we don't implement this check in our implementation but maybe it's tested?"
            );

            musig.sign(&agg_key, &session, signer_index, &keypair, secnonce.nonce);
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
