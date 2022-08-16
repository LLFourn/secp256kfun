//! This broken and just as a reference until we get proper bip340 benchmarks from proper rust lib
#![allow(non_upper_case_globals)]
use criterion::{criterion_group, criterion_main, Criterion};
use schnorr_fun::{Message, Schnorr};
use secp256kfun::{marker::*, nonce::Deterministic, Scalar};
use sha2::Sha256;

const MESSAGE: &'static [u8; 32] = b"hello world you are beautiful!!!";

lazy_static::lazy_static! {
    static ref SK: Scalar<Secret,NonZero> = Scalar::from_bytes_mod_order(*b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").mark::<NonZero>().unwrap();
    static ref schnorr: Schnorr<Sha256, Deterministic<Sha256>> = Schnorr::new(Deterministic::default());
}

// note schnorr runs against grin's secp256k1 library
fn sign_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_sign");
    {
        let keypair = schnorr.new_keypair(SK.clone());
        group.bench_function("fun::schnorr_sign", |b| {
            b.iter(|| schnorr.sign(&keypair, Message::<Public>::raw(MESSAGE)))
        });
    }

    {
        use secp256k1::{KeyPair, Message, Secp256k1};
        let secp = Secp256k1::new();
        let kp = KeyPair::from_secret_key(&secp, SK.clone().into());
        let msg = Message::from_slice(&MESSAGE[..]).unwrap();
        group.bench_function("secp::schnorrsig_sign_no_aux_rand", |b| {
            b.iter(|| {
                secp.sign_schnorr_no_aux_rand(&msg, &kp);
            });
        });
    }
}

fn verify_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_verify");
    let keypair = schnorr.new_keypair(SK.clone());
    {
        let message = Message::<Public>::raw(MESSAGE);
        let sig = schnorr.sign(&keypair, message);
        let verification_key = &keypair.public_key().to_point();
        group.bench_function("fun::schnorr_verify", |b| {
            b.iter(|| schnorr.verify(&verification_key, message, &sig))
        });

        {
            let sig = sig.clone().mark::<Secret>();
            group.bench_function("fun::schnorr_verify_ct", |b| {
                b.iter(|| schnorr.verify(&verification_key, message, &sig))
            });
        }
    }

    {
        use secp256k1::{KeyPair, Message, Secp256k1, XOnlyPublicKey};
        let secp = Secp256k1::new();
        let kp = KeyPair::from_secret_key(&secp, SK.clone().into());
        let pk = XOnlyPublicKey::from_keypair(&kp);
        let msg = Message::from_slice(&MESSAGE[..]).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        group.bench_function("secp::schnorrsig_verify", |b| {
            b.iter(|| secp.verify_schnorr(&sig, &msg, &pk));
        });
    }
}

criterion_group!(benches, verify_schnorr, sign_schnorr);
criterion_main!(benches);
