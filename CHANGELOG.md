# CHANGELOG

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

