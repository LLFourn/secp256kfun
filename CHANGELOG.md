# CHANGELOG

## UNRELEASED

- Add From/TryFrom conversions for `Scalar` to all unsigned integer types
- Upgrade to bincode v2
- MSRV 1.63 -> 1.85
- **BREAKING**: Refactor `CompactProof` in `sigma_fun` to use two type parameters `CompactProof<R, L>` instead of `CompactProof<S: Sigma>` to enable serde support
- Add hash-to-curve methods to `Point`:
  - `hash_to_curve` - Simple try-and-increment with uniform distribution (recommended)
  - `hash_to_curve_sswu` - RFC 9380 compliant constant-time hashing
  - `hash_to_curve_rfc9381_tai` - RFC 9381 VRF try-and-increment format
- Add `Message::new` for BIP340-compliant domain separation using 33-byte padded prefix
- Deprecate `Message::plain` which uses non-standard 64-byte prefix

## v0.11.0

- Added `prelude` module for convenient importing
- Remove `ShareBackup` in favour of `SecretShare`
- Add compatibility to `rust-secp256k1` v0.29.0
- Add compatibility to `rust-secp256k1` v0.30.0
- Large changes to FROST api as usual
- Add `Hash32` trait to collect all the useful hash traits we use all over the place
- Add our own take on [chill-dkg](ttps://github.com/BlockstreamResearch/bip-frost-dkg/tree/master) WIP BIP

## v0.10.0

- Change `Scalar::from_bytes` to work for `Scalar<_, NonZero>` as well.
- Updated compatibility to `rust-secp256k1` v0.28.0
- Bumped MSRV to 1.63.0 to reduce friction
- Added `share_backup` module in `schnorr_fun`
- Added `arithmetic_macros` to make `g!` and `s!` macros into procedural macros
- Made even `Secret` things `Copy`. See discussion [here](https://github.com/LLFourn/secp256kfun/issues/6#issuecomment-1363752651).

## v0.9.1

- Added more `bincode` derives for FROST things
- Added `libsecp_compat_0_27` feature. This allows you to keep compatibility with particular versions going forward.

## v0.9.0

- Improved API of FROST in `schnorr_fun`
- Fixed `Point<_,_,NonZero>` being able to be Zero through `Default` implementation
- Added `bincode` v2 encoding/decoding
- Updated to `rust-secp256k1` v0.27.0
- `XOnlyKeyPair` replaced with `KeyPair<EvenY>`

## v0.8.2

- Fixed docsrs

## v0.8.0

- Added WIP FROST implementation to `schnorr_fun`.
- Update MuSig implementation to latest spec and make consistent with FROST API
- Make Point<EvenY> serialization and hashing consistent (use 32 byte form)
- Add `to_xonly_bytes` and `from_xonly_bytes` to `Point<EvenY>`
- Allow `Zero` points to serialize
- Remove requirement of `CryptoRng` everywhere
- Rename `from_scalar_mul` to `even_y_from_scalar_mul` to be more explicit
- Remove `XOnly` in favour of `Point<EvenY>`
- Replace `.mark` system with methods for changing each marker type.
- Make `From<u32>` work for `Scalar` regardless of secrecy
- Merge `AddTag` and `Tagged` into one trait `Tag`
- Add `NonceRng` impls for `RefCell` and `Mutex`
- Add `Ord` and `PartialOrd` implementations for (public) Scalar and Point
- Add conversions for rust bitcoin's `Scalar` type to `libsecp_compat` feature
- Change the `from_bytes` type commands to not assume secrecy in `Scalar` and `Point`.
- Update to rust-secp256k1 v0.25.0

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
