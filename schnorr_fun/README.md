## SchnorrFun!

Generate and verify Schnorr signatures on secp256k1.

```rust
use schnorr_fun::{
    fun::{hash::Derivation, marker::*, Scalar},
    Schnorr,
};
// Create a BIP-340 compatible instance
let schnorr = Schnorr::from_tag(b"bip340");
// Or create an instance for your own protocol
let schnorr = Schnorr::from_tag(b"my-domain-separator");
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
Schnorr signatures were introduced by their namesake in [1].
This implementation is based on the [BIP-340][2] specification, but is flexible and can be used as a general purpose Schnorr signature scheme.

## Included

- BIP-340 compliant signing and verification
- Adaptor signatures

[1]: https://d-nb.info/1156214580/34
[2]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
