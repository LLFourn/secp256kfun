# SchnorrFun!

Generate and verify Schnorr signatures on secp256k1.

Schnorr signatures were introduced (and patented until 2008) by their namesake in [Efficient Signature Generation by Smart Cards][1].
This implementation is based on the [BIP-340] specification, but is flexible enough to be used as a general purpose Schnorr signature scheme.

## Use

``` toml
[dependencies]
schnorr_fun = { git = "https://github.com/llfourn/secp256kfun" }
```

### Should use?

BIP-340 is still in review so APIs are subject to change.
Ver 0.1 will be released once BIP-340 looks final.

Also see [secp256kfun]

## Synopsis

```rust
use schnorr_fun::{
    fun::{hash::Derivation, marker::*, Scalar},
    Schnorr,
};
// Create a BIP-340 compatible instance
let schnorr = Schnorr::default();
// Or create an instance for your own protocol
let schnorr = Schnorr::from_tag(b"my-domain");
// Generate your public/private key-pair
let keypair = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
let message = b"Chancellor on brink of second bailout for banks"
    .as_ref()
    .mark::<Public>();
// Sign the message with our keypair
let signature = schnorr.sign(&keypair, message, Derivation::rng(&mut rand::thread_rng()));
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
