# SchnorrFun!  [![crates_badge]][crates_url] [![docs_badge]][docs_url] 

[docs_badge]: https://docs.rs/schnorr_fun/badge.svg
[docs_url]: https://docs.rs/schnorr_fun
[crates_badge]: https://img.shields.io/crates/v/schnorr_fun.svg
[crates_url]: https://crates.io/crates/schnorr_fun

Generate and verify Schnorr signatures on secp256k1.
Built on [secp256kfun].

Schnorr signatures were introduced (and patented until 2008) by their namesake in [Efficient Signature Generation by Smart Cards][1].
This implementation is based on the [BIP-340] specification, but is flexible enough to be used as a general purpose Schnorr signature scheme.

## Use

``` toml
[dependencies]
schnorr_fun = "0.7"
sha2 = "0.9"
```

### Should use?

This library and [secp256kfun] are experimental.

## Synopsis

```rust
use schnorr_fun::{
    fun::{marker::*, Scalar, nonce},
    Schnorr,
    Message
};
use sha2::Sha256;
use rand::rngs::ThreadRng;
// Use synthetic nonces
let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone());
// Generate your public/private key-pair
let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
// Sign a variable length message
let message = Message::<Public>::plain("the-times-of-london", b"Chancellor on brink of second bailout for banks");
// Sign the message with our keypair
let signature = schnorr.sign(&keypair, message);
// Get the verifier's key
let verification_key = keypair.public_key().to_point();
// Check it's valid 🍿
assert!(schnorr.verify(&verification_key, message, &signature));
```

## Features

- BIP-340 compliant signing and verification
- Adaptor signatures
- compatibility with `rust-secp256k1`'s `schnorrsig` module with `libsecp_compat` feature.
- [MuSig2] implementation compatible with [this PR](https://github.com/jonasnick/bips/pull/37) of the spec.
- [FROST] implementation
- Feature flags
  - `serde`: for serde implementations for signatures
  - `libsecp_compat`: for `From` implementations between `rust-secp256k1`'s Schnorr signatures.
  - `proptest` to enable `secp256kfun/proptest`.

[1]: https://d-nb.info/1156214580/34
[BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[secp256kfun]: https://docs.rs/secp256kfun
[secp256k1-zkp]: https://github.com/ElementsProject/secp256k1-zkp/pull/131
[MuSig2]: https://eprint.iacr.org/2020/1261.pdf
[FROST]: https://eprint.iacr.org/2020/852.pdf
