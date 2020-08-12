# ECDSAFun!

Generate and verify ECDSA signatures on secp256k1.
Uses [secp256kfun].

## Use

``` toml
[dependencies]
ecdsa_fun = "0.2"
sha2 = "0.9" # You need a hash function for nonce derivation
```

### Should use?

This library and [secp256kfun] is experimental.
Not well reviewed or tested.

### Extra Features

- ECDSA Adaptor signatures

[secp256kfun]: https://docs.rs/secp256kfun
