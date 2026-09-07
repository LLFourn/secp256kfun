# secp256kfun_k256

The arithmetic backend used by [`secp256kfun`], derived from [`k256`]. It doesn't track a
particular version but the internal arithmetic should be up to date as of `11.5`. The `Scalar`
arithmetic is taken from earlier versions since in `11.*` they require the `crypto-bigint`
dependency which we can't depend on here due to conflicts.

It is published separately so that crates which need only the arithmetic can depend on it without
depending on `secp256kfun` itself.

The copyright is owned by the RustCrypto Developers and is licensed to anyone under the
`Apache-2.0` OR `MIT` licenses (both included in this directory). This is a different license to the
rest of the `secp256kfun` code base.

[`secp256kfun`]: https://docs.rs/secp256kfun
[`k256`]: https://docs.rs/k256
