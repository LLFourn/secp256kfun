# CHANGELOG

## Unreleased

- Added FROST implementation
- Make Point<EvenY> serialization and hashing consistent (use 32 byte form)
- Add `to_xonly_bytes` and `from_xonly_bytes` to `Point<EvenY>`
- Allow `Zero` points to serialize
- Remove requirement of `CryptoRng` everywhere
- Rename `from_scalar_mul` to `even_y_from_scalar_mul` to be more explicit
- Remove `XOnly` in favor of `Point<EvenY>`
- Replace `.mark` system with methods for changing each marker type.
- Make `From<u32>` for `Scalar` regardless of secrecy
- Merge `AddTag` and `Tagged` into one trait `Tag`

## 0.7.1

- Fix critical bug in MuSig2 implementation where multiple tweaks would break it
- update to rust-secp256k1 v0.21.3

## 0.7.0

- Change default arithmetic backend to [`secp256kfun_k256_backend`](https://docs.rs/secp256kfun_k256_backend/2.0.0/secp256kfun_k256_backend/)
- Add MuSig2 implementation in [musig](./schnorr_fun/src/musig.rs) in `schnorr_fun`.
- Remove option to set custom basepoint in `schnorr_fun`.
- upgrade to rust-secp256k1 v0.21

## 0.6.2

- can be built on stable if `nightly` feature is not enabled
- Put ECDSA adaptor signatures under feature flag

## 0.6.1

- Fix serialization of `Point<EvenY>`

