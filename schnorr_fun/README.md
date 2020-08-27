# SchnorrFun!

Generate and verify Schnorr signatures on secp256k1. Uses [secp256kfun].

Schnorr signatures were introduced (and patented until 2008) by their namesake in [Efficient Signature Generation by Smart Cards][1].
This implementation is based on the [BIP-340] specification, but is flexible enough to be used as a general purpose Schnorr signature scheme.

## Use

``` toml
[dependencies]
schnorr_fun = "0.2"
sha2 = "0.9"
```

### Should use?

This library and [secp256kfun] are experimental.
BIP-340 is still in review so APIs are subject to change.

## Synopsis

```rust
use schnorr_fun::{
    fun::{marker::*, Scalar, nonce},
    Schnorr,
    MessageKind,
};
use sha2::Sha256;
use rand::rngs::ThreadRng;
// Use synthetic nonces
let nonce_gen = nonce::Synthetic::<Sha256, nonce::GlobalRng<ThreadRng>>::default();
// Create a BIP-341 compatible instance
let schnorr = Schnorr::<Sha256, _>::new(nonce_gen.clone(),MessageKind::Prehashed);
// Or create an instance for your own application
let schnorr = Schnorr::<Sha256,_>::new(nonce_gen, MessageKind::Plain { tag: "my-app" });
// Generate your public/private key-pair
let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
let message = b"Chancellor on brink of second bailout for banks"
    .as_ref()
    .mark::<Public>();
// Sign the message with our keypair
let signature = schnorr.sign(&keypair, message);
// Get the verifier's key
let verification_key = keypair.verification_key();
// Check it's valid 🍿
assert!(schnorr.verify(&verification_key, message, &signature));
```

## Features

- BIP-340 compliant signing and verification
- Adaptor signatures

[1]: https://d-nb.info/1156214580/34
[BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
[secp256kfun]: https://docs.rs/secp256kfun
