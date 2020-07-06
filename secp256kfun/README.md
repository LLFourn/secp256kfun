# secp256kFUN!

![](https://github.com/llfourn/secp256kfun/workflows/Rust/badge.svg)
![](https://docs.rs/secp256kfun/badge.svg)
![](https://img.shields.io/crates/v/secp256kfun.svg)


A mid-level rust secp256k1 elliptic curve cryptography library that's optimized for fun! Here, fun means:

- **type safety**: Error cases you would typically have to deal with when using other APIs are ruled out at compile time using rust's type system.
- **abstraction**: The library exposes two simple abstractions _Points_ and _Scalars_ so you can do a clean textbook implementations of crypto.
- **unoptimizable**: The most straightforward way of expressing a certain operation on the group is also the most efficient way.

Fun does not mean (yet -- please help!):

- **stable**: This library will frequently add/remove/change APIs for the foreseeable future. It also needs a nightly compiler for [_specialization_] (it uses the `min_specialization` feature).
- **well reviewed or tested**: This code is fresh and experimental and not rigorously tested.
- **side-channel resistant**: There has been no empirical investigation into whether this library or the underlying [parity/libsecp256k1][4] is resistant against timing attacks etc.
- **performant**: The library is in general not as performant as [libsecp256k1][1], at least on 64-bit platforms.

The goal is for this library to let researchers experiment with ideas, have them work on Bitcoin *and* to enjoy it!
I hope you can build very satisfying implementations of cryptographic schemes with this library.
_High-level_ libraries like [rust-secp256k1][2] make it difficult to implement exotic cryptographic schemes correctly and efficiently.
_Low-level_ libraries like [parity/libsecp256k1][4] make it possible but the resulting code is often error prone and difficult to read.

## Use

```toml
[dependencies]
secp256kfun = "0.1"
```

### Should use?

This library is ready for production as long what you are trying to produce is **fun and amusement!**.
If you want to engineer something solid that a lot of people's money will depend on, this library is a very very risky choice.
Instead, try to use [libsecp256k1][1] or its rust bindings [rust-secp256k1][2].
If you don't *need* to use secp256k1, instead consider using the wonderful [ristretto][3] group from curve25519-dalek whose APIs helped inspire this effort.
This library vendors [parity/libsecp256k1][4] into the `parity_backend` directory to do the elliptic curve arithmetic so most of its performance and side-channel resistance will depend on that.

## Documentation

https://docs.rs/secp256kfun

# Features
Here's the distinguishing features of this library.

## The Zero Element

Both secp256k1 points and scalars have a notional _zero_ element.
Unfortunately, in things surrounding Bitcoin, the zero scalar and zero point are illegal values in most cases.
The _high-level_ [rust-secp256k1][2] deals with zero problem by returning a `Result` in its API whenever the return value might be zero.
This is annoying for two reasons:

1. Sometimes zero is fine and now you have an error case where you should just have zero.
2. In many cases, we can rule out zero as a result of a computation through some context specific information.

At worst, this can lead to a habitual use of `.unwrap` to ignore the errors that the engineer *thinks* are unreachable.
A mistaken `.unwrap` is often a security bug if a malicious party can trigger it.

In the _low-level_ [parity/libsecp256k1][4], you have to manually check that things aren't the zero element when it's invalid.

secp256kfun solves these difficulties using _marker types_.
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
let public_key = sum.mark::<Normal>();
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
match sum.mark::<(Normal, NonZero)>() {
    Some(public_key) => send_pubkey_to_bob(&public_key), // it was actually NonZero
    None => .. // deal with the case it is Zero
}
```

## Variable time or Constant time?

If a function's execution time depends on its inputs, then information about those inputs may leak to anyone that can measure its execution time.
Therefore it is crucial that functions that take secret inputs run in _constant time_.
Good low-level libraries tend to have one constant time version of an algorithm and then a faster variable time version. In _high-level_ libraries the experts have made the choice for you.
Here's a question that demonstrates the problem with this: **Should a signature verification algorithm run in variable time or constant time?**

Well, if you're talking about public signatures on a public blockchain then variable time is fine - it may even be crucial for performance.
But what about if you're verifying a _blind signature_ that you just received?
The time it takes you to verify the signature may reveal which message you chose to get signed violating the security of the blind signature scheme!

With secp25kfun it's possible to _let the caller decide_ whether a function argument is secret in the context of the protocol with the `Secret` and `Public` marker types.
In the example below, we have a `pedersen_commitment` function which is called by the committing party with a secret value and by the verifying party when the secret value is finally revealed.
This means that we want it to be constant time when making the commitment but variable time when checking the opening.
Note that we only have to write the function once.
The compiler will decide whether to use constant time or variable time operations by whether value is marked `Secret` or `Public` (note it does this through [_specialization_]).

```rust
use secp256kfun::{marker::*, Point, Scalar, g};

/// commit to a secret value x with publicly known A and B.
fn pedersen_commit(
    A: &Point<impl PointType>, // Accept any kind of Point
    B: &Point<impl PointType>,
    r: &Scalar<impl Secrecy>, // Accept a Secret or Public Scalar
    x: &Scalar<impl Secrecy, Zero>, // Allow commitment to Zero
) -> Point<Jacobian> {
    // Make the commitment
    g!(r * A +  x * B)
        .mark::<NonZero>()
        // If the result is zero we could easily compute the discrete
        // logarithm of B with respect to A. Since this is meant to be unknown
        // this computionally unreachable.
        .expect("computationally unreachable")
}

// public setup
let A = secp256kfun::G; // use the standard basepoint for one of the points
let B = Point::random(&mut rand::thread_rng());

// Alice commits to her secret value x with randomness r
let r = Scalar::random(&mut rand::thread_rng());
let x = Scalar::from(42);
let commitment = pedersen_commit(A, &B, &r, &x);

// Imagine Later on, Bob receives the public opening (r,x) for commitment. He
// doesn't care about leaking these values via execution time so he marks them
// as public.
let r = r.mark::<Public>();
let x = x.mark::<Public>();

// Now he'll compute the commitment in faster variable time and check it
// against the original
assert_eq!(commitment, pedersen_commit(A, &B, &r, &x));
```

As a bonus, this example also shows how you don't have to design the cryptographic function around the basepoint `G`.
The `pedersen_commitment` takes any `PointType`.
When you pass in `G`, which is a `BasePoint`, the compiler will specialize the call so that at runtime it uses the pre-computed multiplication tables that `BasePoint`s have.

**note: at this stage constant-time in this library means *hopefully* constant time -- there's not testing being done to check this rigorously**

## Other Features

- Bult-in type-safe "x-only" point compression and decompression to both even y and square y points.
- Arithmetic expression macro `g!` (used above) to clearly express group operations.
- Nonce derivation functionality to help avoid messing this up.
- `serde` serialization/deserialization for binary and hex for human-readable formats (enable with `serialization` or `serialize_hex` features).
- `no_std` support


[1]: https://github.com/bitcoin-core/secp256k1
[2]: https://github.com/rust-bitcoin/
[3]: https://github.com/dalek-cryptography/curve25519-dalek
[4]: https://github.com/paritytech/libsecp256k1
[_specialization_]: https://github.com/rust-lang/rust/issues/31844
