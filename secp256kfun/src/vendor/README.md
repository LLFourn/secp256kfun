# Vendored code

This is code that has been pasta'd into the repo to use its internals or to avoid dependencies.
It is under a different license than the rest of the code base.


## k256

This is the arithmetic backend derived from [`k256`](https://docs.rs/k256/latest/k256/). It doesn't track a particular version but the internal arithmetic should be up to date as of `11.5`. The the `Scalar` arithmetic is taken from earlier versions since in `11.*` they require the `crypto-bigint` dependency which we can't depend on here due to conflicts.


The copyright is owned by the RustCrypto Developers and is licensed to anyone under the `Apache-2.0` OR `MIT` licenses (both included in this directory).

