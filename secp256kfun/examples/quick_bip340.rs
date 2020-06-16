#![allow(non_snake_case)]
use rand::thread_rng;
use secp256kfun::{
    g,
    hash::{tagged_hash, HashAdd},
    marker::*,
    s, Scalar, XOnly, G,
};

#[derive(Clone, Debug)]
pub struct Signature {
    pub R: XOnly<SquareY>,
    pub s: Scalar<Public, Zero>,
}

lazy_static::lazy_static! {
    pub static ref BIP340_CHALLENGE: sha2::Sha256 = tagged_hash(b"BIP340/challenge");
}

pub fn keygen() -> (Scalar, XOnly<EvenY>) {
    let mut x = Scalar::random(&mut thread_rng());
    let X = XOnly::<EvenY>::from_scalar_mul(G, &mut x);
    (x, X)
}

pub fn sign(keypair: &(Scalar, XOnly<EvenY>), message: &[u8]) -> Signature {
    let (x, X) = keypair;
    let mut r = Scalar::random(&mut thread_rng());
    let R = XOnly::<SquareY>::from_scalar_mul(G, &mut r);
    let c = Scalar::from_hash(BIP340_CHALLENGE.clone().add(&R).add(X).add(message));
    let s = s!(r + c * x);

    Signature {
        R,
        s: s.mark::<Public>(),
    }
}

pub fn verify(public_key: &XOnly<EvenY>, message: &[u8], Signature { R, s }: &Signature) -> bool {
    let X = public_key;
    let c = Scalar::from_hash(BIP340_CHALLENGE.clone().add(R).add(X).add(message)).mark::<Public>();
    g!(s * G - c * { X.to_point() }) == *R
}

fn main() {
    let keypair = keygen();
    let signature = sign(&keypair, b"attack at dawn");
    assert!(verify(&keypair.1, b"attack at dawn", &signature));
}
