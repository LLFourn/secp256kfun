use criterion::{criterion_group, criterion_main, Criterion};
use secp256kfun::{marker::*, nonce::Deterministic, secp256k1, Scalar};
use sha2::Sha256;

const MESSAGE: &'static [u8; 32] = b"hello world you are beautiful!!!";

lazy_static::lazy_static! {
    static ref SK: Scalar = Scalar::from_bytes_mod_order(*b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").mark::<NonZero>().unwrap();
    static ref ECDSA: ecdsa_fun::ECDSA<Deterministic::<Sha256>> = ecdsa_fun::ECDSA::default();
}

fn sign_ecdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_sign");

    group.bench_function("fun::ecdsa_sign", |b| b.iter(|| ECDSA.sign(&SK, MESSAGE)));

    {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&SK.to_bytes()[..]).unwrap();
        {
            group.bench_function("secp256k1::ecdsa_sign", |b| {
                b.iter(|| secp.sign_ecdsa(&Message::from_slice(&MESSAGE[..]).unwrap(), &secret_key))
            });
        }
    }
}

fn verify_ecdsa(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa_verify");

    let signature = ECDSA.sign(&SK, MESSAGE);
    let pk = ECDSA.verification_key_for(&SK);

    group.bench_function("fun::ecdsa_verify", |b| {
        b.iter(|| ECDSA.verify(&pk, MESSAGE, &signature))
    });

    {
        let signature = signature.clone().mark::<Secret>();
        group.bench_function("fun::ecdsa_verify_ct", |b| {
            b.iter(|| ECDSA.verify(&pk, MESSAGE, &signature))
        });
    }

    {
        use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let sig = Signature::from_compact(signature.to_bytes().as_ref()).unwrap();
        let secret_key = SecretKey::from_slice(&SK.to_bytes()[..]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        {
            group.bench_function("secp256k1::ecdsa_verify", |b| {
                b.iter(|| {
                    secp.verify_ecdsa(
                        &Message::from_slice(&MESSAGE[..]).unwrap(),
                        &sig,
                        &public_key,
                    )
                })
            });
        }
    }
}

criterion_group!(benches, sign_ecdsa, verify_ecdsa);
criterion_main!(benches);
