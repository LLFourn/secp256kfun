//! This broken and just as a reference until we get proper bip340 benchmarks from proper rust lib
#![allow(non_upper_case_globals)]
use criterion::{Criterion, criterion_group, criterion_main};
use schnorr_fun::{
    Message, Schnorr,
    fun::{Scalar, marker::*, nonce, secp256k1},
};
use sha2::Sha256;

const MESSAGE: &[u8; 32] = b"hello world you are beautiful!!!";

lazy_static::lazy_static! {
    static ref SK: Scalar<Secret, NonZero> = Scalar::from_bytes_mod_order(*b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").non_zero().unwrap();
    static ref schnorr: Schnorr<Sha256, nonce::Deterministic<Sha256>> = Schnorr::default();
}

// note schnorr runs against grin's secp256k1 library
fn sign_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_sign");
    {
        let keypair = schnorr.new_keypair(*SK);
        group.bench_function("fun::schnorr_sign", |b| {
            b.iter(|| schnorr.sign(&keypair, Message::<Public>::raw(MESSAGE)))
        });
    }

    {
        use secp256k1::{Keypair, Secp256k1};
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &(*SK).into());
        group.bench_function("secp::schnorrsig_sign_no_aux_rand", |b| {
            b.iter(|| {
                secp.sign_schnorr_no_aux_rand(&MESSAGE[..], &kp);
            });
        });
    }
}

fn verify_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr_verify");
    let keypair = schnorr.new_keypair(*SK);
    {
        let message = Message::<Public>::raw(MESSAGE);
        let sig = schnorr.sign(&keypair, message);
        let verification_key = &keypair.public_key();
        group.bench_function("fun::schnorr_verify", |b| {
            b.iter(|| schnorr.verify(verification_key, message, &sig))
        });

        {
            let sig = sig.set_secrecy::<Secret>();
            group.bench_function("fun::schnorr_verify_ct", |b| {
                b.iter(|| schnorr.verify(verification_key, message, &sig))
            });
        }
    }

    {
        use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &(*SK).into());
        let pk = XOnlyPublicKey::from_keypair(&kp).0;
        let sig = secp.sign_schnorr_no_aux_rand(&MESSAGE[..], &kp);
        group.bench_function("secp::schnorrsig_verify", |b| {
            b.iter(|| secp.verify_schnorr(&sig, &MESSAGE[..], &pk));
        });
    }
}

criterion_group!(benches, verify_schnorr, sign_schnorr);
criterion_main!(benches);
