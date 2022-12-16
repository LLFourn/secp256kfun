# secp256kFUN! &emsp; [![crates_badge]][crates_url] [![actions_badge]][actions_url] [![docs_badge]][docs_url]

[actions_badge]: https://github.com/LLFourn/secp256kfun/actions/workflows/test.yml/badge.svg
[actions_url]: https://github.com/LLFourn/secp256kfun/actions/workflows/test.yml
[crates_badge]: https://img.shields.io/crates/v/secp256kfun.svg
[crates_url]: https://crates.io/crates/secp256kfun
[docs_badge]: https://docs.rs/secp256kfun/badge.svg
[docs_url]: https://docs.rs/secp256kfun

A mid-level rust secp256k1 elliptic curve cryptography library that's optimized for fun! Here, fun means:

- **type safety**: Error cases you would typically have to deal with when using other APIs are ruled out at compile time using rust's type system.
- **abstraction**: The library exposes two simple abstractions _Points_ and _Scalars_ so you can do clean textbook implementations of crypto.
- **unoptimizable**: The most straightforward way of expressing a certain operation on the group is also the most efficient way.
- **Documented**: We try and make working examples for each function and document them.

Fun does not mean (yet -- please help!):

- **well reviewed**: The implemenations here have no received much review.
- **side-channel resistant**: There has been no empirical investigation into whether this library or the underlying arithmetic from [k256] is resistant against timing attacks etc. Also secrets are zeroed out when their memory is freed.
- **performant**: The library is in general not as performant as [libsecp256k1][1].

The goal is for this library to let researchers experiment with ideas, have them work on Bitcoin *and* to enjoy it!
_High-level_ libraries like [rust-secp256k1][2] make it difficult to implement exotic cryptographic schemes correctly and efficiently.
_Low-level_ libraries like [parity/libsecp256k1][4] make it possible but the resulting code is often error prone and difficult to read.

## Use

```toml
[dependencies]
secp256kfun = "0.8"
```

### Should use?

This library is ready for production as long what you are trying to produce is **fun and amusement!**.
If you want to engineer something solid that a lot of people's money will depend on, this library is a risky choice.
Here are some alternatives:

1. [rust-secp256k1][2] - the rust bindings to the libsecp256k1 that Bitcoin itself uses
2. [k256] - the arithmetic of this library is (by default) based on this library.
3. [ristretto][3] - in the case you don't need to use secp256k1

## Documentation

[docs.rs/secp256kfun](https://docs.rs/secp256kfun)

# Features

Here's the distinguishing features of this library.

## The Zero Element

Both secp256k1 points and scalars have a notional _zero_ element.
Unfortunately, in things surrounding Bitcoin, the zero scalar and zero point are illegal values in most cases.
`secp256kfun` solves these difficulties using _marker types_.
Points and Scalars are marked with `Zero` or `NonZero` at compile time (by default, `NonZero`).
So if you declare your function with a `NonZero` type, passing a `Zero` type will be a compile time error as shown below:

```rust,compile_fail
use secp256kfun::{marker::*, Scalar, Point,G,g};
// a randomly selected Scalar will never be zero (statistically unreachable)
let x = Scalar::random(&mut rand::thread_rng());
dbg!(&x); // Scalar<.., NonZero>
// Multiplying a NonZero scalar by G (which is also NonZero) results in a NonZero point
let X = g!(x * G);
dbg!(&X) // Point<..,NonZero>
let Y = g!(-x * G)
// An addition **can** lead to a zero so the result is marked Zero
let sum = g!(X + Y);
dbg!(&sum); // Point<.., Zero>
// Now let's say I naively decide to use this value as my public key...
let public_key = sum.normalize();
// BOOM! This is a compile time Error! 🎉
send_pubkey_to_bob(&public_key);

fn send_pubkey_to_bob(public_key: &Point) {
    unimplemented!()
}
```

This gives us:

```shell
error[E0308]: mismatched types
 --> src/lib.rs:77:20
   |
17 | send_pubkey_to_bob(&public_key);
     |                  ^^^^^^^^^^^ expected struct `secp256kfun::marker::NonZero`, found struct `secp256kfun::marker::Zero`
```

To fix this, the library forces you to manually mark the value as `NonZero` and then deal with the case that it is `Zero`.

```rust,compile_fail
match sum.normalize().non_zero() {
    Some(public_key) => send_pubkey_to_bob(&public_key), // it was actually NonZero
    None => .. // deal with the case it is Zero
}
```

Or you can declare that you are confident that it can never be 

## Variable time or Constant time?

**NOTE**: *As of `v0.7.0` the `Secret` and `Public` markers do very little since we changed the
arithmetic backend to [k256] which doesn't have variable time algorithms. However this situation may
improve in future versions.*

If a cryptogrpahic function's execution time should be independent of its secret inputs.
Otherwise, information about those inputs may leak to anyone that can measure its execution time.

In secp256kfun we try and solve this problem by allowing you to mark different inputs as `Public` or `Secret`.
Depending on the marking the rust compiler may choose different low level operations.
Choosing faster but variable time operations for `Public` inputs and slower safer constant time ones for things marked as `Secret`.
In other words, the caller can decide which input are

For example, below we have a `pedersen_commitment` function which is called by the committing party with a secret value and by the verifying party when the secret value is finally revealed.
Note that we only have to write the function once and the caller decides by marking whether the function should run in constant time or variable time.

```rust
use secp256kfun::{marker::*, Point, Scalar, g};

/// commit to a secret value x with publicly known A and B.
fn pedersen_commit(
    A: &Point<impl PointType>, // Accept any kind of Point
    B: &Point<impl PointType>,
    r: &Scalar<impl Secrecy>, // Accept a Secret or Public Scalar
    x: &Scalar<impl Secrecy, Zero>, // Allow commitment to Zero
) -> Point {
    // Make the commitment
    g!(r * A +  x * B)
        .normalize()
        // If the result is zero we could easily compute the discrete
        // logarithm of B with respect to A. Since this is meant to be unknown
        // this is computionally unreachable.
        .non_zero().expect("computationally unreachable")
}

// public setup
let A = secp256kfun::G; // use the standard basepoint for one of the points
let B = Point::random(&mut rand::thread_rng());

// Alice commits to her secret value x with randomness r
let r = Scalar::random(&mut rand::thread_rng());
let x = Scalar::<Secret, Zero>::from(42);
let commitment = pedersen_commit(A, &B, &r, &x);

// Imagine Later on, Bob receives the public opening (r,x) for commitment. He
// doesn't care about leaking these values via execution time so he marks them
// as public.
let r = r.public();
let x = x.public();

// Now he'll compute the commitment in faster variable time and check it
// against the original
assert_eq!(commitment, pedersen_commit(A, &B, &r, &x));
```

## Features

- Built-in type-safe "x-only" point compression and decompression.
- Arithmetic expression macros `g!` and `s!` (used above) to clearly express group operations.
- Nonce derivation API to help avoid messing this up.
- Feature flags:
  - `serde` serialization/deserialization for binary and hex for human-readable formats (enable with `serde` feature hex requires `alloc` feature as well).
  - `no_std` support
  - `libsecp_compat` adds `From` implementations to and from [rust-secp256k1][2] types.
  - `proptest` implementations of core types with the `proptest` feature


[1]: https://github.com/bitcoin-core/secp256k1
[2]: https://github.com/rust-bitcoin/rust-secp256k1/
[3]: https://github.com/dalek-cryptography/curve25519-dalek
[4]: https://github.com/paritytech/libsecp256k1
[k256]: https://docs.rs/k256/0.10.1/k256/

## MSRV

Minimum supported rust version is `v1.60`. Technically `rustc` only needs to be `v1.56` but we need features from `v.1.60` of cargo.

## LICENSE

Code is licensed under [`0BSD`](https://opensource.org/licenses/0BSD) except for the code under `secp256kfun/src/vendor` where you will find the licenses for the vendor'd code.
