# ECDSAFun! [![crates_badge]][crates_url] [![docs_badge]][docs_url] 

[docs_badge]: https://docs.rs/ecdsa_fun/badge.svg
[docs_url]: https://docs.rs/ecdsa_fun
[crates_badge]: https://img.shields.io/crates/v/ecdsa_fun.svg
[crates_url]: https://crates.io/crates/ecdsa_fun

Generate and verify secp256k1 ECDSA signatures.
Built on [secp256kfun].

## Use

``` toml
[dependencies]
ecdsa_fun = "0.8"
sha2 = "0.10" # You need a hash function for nonce derivation
```

### Should use?

This library and [secp256kfun] is experimental.

### Feature flags

- `libsecp_compat` to enable `From` implementations between [rust-secp256k1] types.
- `proptest` to enable [secp256kfun]'s proptest feature.
- `adaptor` to spec compliant ECDSA adaptor signatures.
- `serde` to enable hex and binary [`serde`] serialization of data types.

[secp256kfun]: https://docs.rs/secp256kfun
[rust-secp256k1]: https://github.com/rust-bitcoin/rust-secp256k1/ 
[`serde`]: https://serde.rs

