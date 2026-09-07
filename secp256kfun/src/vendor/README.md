# Vendored code

This is code that has been pasta'd into the repo to use its internals or to avoid dependencies.
It is under a different license than the rest of the code base.


## hash_to_curve

Derived from [`k256`](https://docs.rs/k256/latest/k256/)'s hash-to-curve implementation.

The copyright is owned by the RustCrypto Developers and is licensed to anyone under the `Apache-2.0` OR `MIT` licenses (both included in this directory).

The arithmetic backend used to live here too. It is now the `secp256kfun_k256` crate at the root of
this repo, so that crates which need only the arithmetic don't have to depend on `secp256kfun`.
