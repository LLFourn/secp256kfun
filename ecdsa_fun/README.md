# ECDSAFun! [![crates_badge]][crates_url] [![docs_badge]][docs_url] 

[docs_badge]: https://docs.rs/ecdsa_fun/badge.svg
[docs_url]: https://docs.rs/ecdsa_fun
[crates_badge]: https://img.shields.io/crates/v/ecdsa_fun.svg
[crates_url]: https://crates.io/crates/ecdsa_fun

Generate and verify ECDSA signatures on secp256k1.
Uses [secp256kfun].

## Use

``` toml
[dependencies]
ecdsa_fun = "0.6"
sha2 = "0.9" # You need a hash function for nonce derivation
```

### Should use?

This library and [secp256kfun] is experimental.
Not well reviewed or tested.

### Extra Features

- From implementation for converting to [rust-secp256k1] types (`libsecp_compat`)
- ECDSA Adaptor signatures
- Hex and binary `serde` serlialization for all types (`serlialization` or `serialize_hex`)

[secp256kfun]: https://docs.rs/secp256kfun
[rust-secp256k1]: https://github.com/rust-bitcoin/rust-secp256k1/ 

