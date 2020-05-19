# Secp256kFUN!
A pure rust secp256k1 elliptic curve cryptography library that is optimized for fun! Here, fun means:

- **type safety**: Error cases you would typically have to deal with when using other APIs are ruled out at compile time using rust's type system.
- **abstraction**: The library exposes two simple abstractions _Points_ and _Scalars_ so you can do a clean textbook implementations of crypto.
- **mid-level**: The library tries to strike the right balance between the efficiency and power of low-level APIs and the simplicity of high-level APIs.

Fun does not mean (yet -- please help!):

- **stable**: This library will frequently add/remove/change APIs for the foreseeable future. It also needs a nightly compiler for [_specialization_][5].
- **well reviewed or tested**: This code is fresh and experimental and not rigorously tested.
- **side-channel resistant**: There has been no empirical investigation into whether this library or the underlying [parity/libsecp256k1][4] is resistant against timing attacks etc.
- **performant**: The library is in general not as performant as [libsecp256k1][1], at least on 64-bit platforms.

The goal is for this library to let researchers experiment with ideas, have them work on Bitcoin *and* to enjoy it!
If you want to engineer something solid that a lot of people's money might depend on you should use [libsecp256k1][1] or its rust bindings [rust-secp256k1][2] (if you can).

Note if you don't *need* to use secp256k1, consider using the [ristretto][3] group from curve25519-dalek whose APIs helped inspire this library.

This library uses [parity/libsecp256k1][4] to do the elliptic curve arithmetic so most of its performance and side-channel resistance will depend on that.

## Use

There isn't a 0.0.1 release yet so you want to try it out at this early stage you have add a git dependency:

```toml
[dependencies]
secp256kfun = { git = "https://github.com/LLFourn/secp256kfun.git", package = "secp256kfun" }
```

## Documentation

```shell
cargo doc --open --all-features
```

## Why This Exists

It is difficult or sometimes impossible to implement any non-trivial cryptographic algorithms using high-level libraries like [rust-secp256k1][2].
You can do it using low-level libraries like [parity/libsecp256k1][4] but the resulting code can be difficult to read and error prone because of all the extraneous details you're forced to deal with.
secp256kfun is a mid level api that tries to get the best of both worlds.
Here's the main things this library tries to be better at:

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

If the distribution of a function's execution time is a function of the distribution of its inputs, then information about those inputs may leak to anyone that can measure its execution time.
Therefore it is crucial that functions that take secret inputs run in _constant time_.

Good low-level libraries tend to have one constant time version of an algorithm and then a faster variable time version. In _high-level_ libraries the experts have made the choice for you.

Here's a question that demonstrates the problem with this: **Should a signature verification algorithm run in variable time or constant time?**

Well, if you're talking about public signatures on a public blockchain then variable time is fine -- in fact it may be necessary for performance.
But what about if you're verifying a _blind signature_ that you just received.
The time it takes you to verify the signature may reveal which message you chose to get signed violating the security of the blind signature scheme.

With secp25kfun it's possible to _let the caller decide_ whether your algorithm runs in constant time or not.
A simple example of where this is useful is the _Pedersen commitment_ function below.
When you're committing to your secret you want `pedersen_commitment` to run in constant time, so information about what you're committing to isn't leaked through execution time.
On the other hand, when you're verifying the opening of the commitment you don't care about leaking information and speed is preferable.
With secp256kfun you only have to write the function once.
The caller can decide whether the internal operations will run in constant time or not depending on their assessment about whether the values are secret or public within the context of the protocol at that point.

```rust
use secp256kfun::{marker::*, Point, Scalar, G, g};

fn pedersen_commit(
    A: &Point<impl PointType>, // Accept any kind of Point.
    B: &Point<impl PointType>,
    r: &Scalar<impl Secrecy>, // Accept a Secret or Public Scalar
    x: &Scalar<impl Secrecy, Zero>,
) -> Point<Jacobian> {
    // Make the commitment
    g!(r * A +  x * B)
        .mark::<NonZero>()
        // If the result is zero we could easily compute the discrete
        // logarithm of B with respect to A. Since this is meant to be unknown
        // this computionally unreachable.
        .expect("computationally unreachable")
}

// Alice commits to her secret value x with randomness r
let r = Scalar::random(&mut rand::thread_rng());
let x = Scalar::from(42);
let B = Point::random(&mut rand::thread_rng());
let commitment = pedersen_commit(G, &B, &r, &x);

// Imagine Later on, Bob receives the public opening (r,x) for commitment He
// doesn't care about leaking these values via execution time so he marks them
// as public.
let r = r.mark::<Public>();
let x = x.mark::<Public>();

// Now he'll compute the commitment quickly in variable time and check it
// against the original
assert_eq!(commitment, pedersen_commit(G, &B, &r, &x));
```

Note that not only is `pedersen_commitment` generic over the `Secrecy` of the scalars but it also generic over the _type_ of the points.
When we pass in `G`, which is a `BasePoint`, as the `A` argument the compiler will produce a faster version of `pedersen_commitment` for that call because it can use `G`'s pre-computed multiplication tables.

**note: at this stage constant-time in this library means *hopefully* constant time -- there's not testing being done to check this rigorously**

[1]: https://github.com/bitcoin-core/secp256k1
[2]: https://github.com/rust-bitcoin/
[3]: https://github.com/dalek-cryptography/curve25519-dalek
[4]: https://github.com/paritytech/libsecp256k1
[5]: https://github.com/rust-lang/rust/issues/31844
