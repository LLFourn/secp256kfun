# vrf_fun

Verifiable Random Function (VRF) implementation for secp256k1.

## Overview

This crate provides RFC 9381 compliant VRF implementations for secp256k1, supporting both:
- **TAI (Try-And-Increment)** hash-to-curve method
- **RFC 9380** hash-to-curve method

## Features

- RFC 9381 compliant VRF implementation
- Support for both TAI and RFC 9380 hash-to-curve methods
- Simple VRF variant for when spec compliance is not required
- Generic over hash functions (SHA-256, etc.)
- Deterministic proofs
  - Suite strings: `0xFE` for TAI, `0xFF` for RFC SSWU
  
## Usage

### High-Level API

#### RFC 9381 with TAI (Try-And-Increment)

```rust
use secp256kfun::{prelude::*, KeyPair};
use vrf_fun::rfc9381;

// Generate a keypair
let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));

// Create a VRF proof
let alpha = b"test message";
let proof = rfc9381::tai::prove::<sha2::Sha256>(&keypair, alpha);

// Verify the proof
let verified = rfc9381::tai::verify::<sha2::Sha256>(
    keypair.public_key(), 
    alpha, 
    &proof
).expect("proof should verify");

// Get the VRF output
let beta = verified.rfc9381_output::<sha2::Sha256>();
```

#### RFC 9381 with RFC 9380 Hash-to-Curve

```rust
use vrf_fun::rfc9381;

// Same keypair and message
let proof = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, alpha);

// Verify with the RFC 9380 verifier
let verified = rfc9381::sswu::verify::<sha2::Sha256>(
    keypair.public_key(), 
    alpha, 
    &proof
).expect("proof should verify");

let beta = verified.rfc9381_sswu_output::<sha2::Sha256>();
```

### Low-Level API

For more control over the hash-to-curve process:

```rust
use vrf_fun::{rfc9381::Rfc9381TaiVrf, SimpleVrf};
use secp256kfun::{prelude::*, KeyPair};

// Create VRF instance
let vrf = Rfc9381TaiVrf::<sha2::Sha256>::default();

// Hash to curve yourself
let h = Point::hash_to_curve_rfc9381_tai::<sha2::Sha256>(alpha, b"");

// Generate proof
let proof = vrf.prove(&keypair, h);

// Verify
let verified = vrf.verify(keypair.public_key(), h, &proof)
    .expect("proof should verify");
```

## Implementation Details

### Challenge Generation

The challenge is computed as:
```
c = Hash(suite_string || 0x02 || Y || H || Gamma || U || V || 0x00)
```

Where:
- `suite_string`: `0xFE` for TAI, `0xFF` for RFC 9380
- `Y` is the public key
- `H` is the hash-to-curve of the input
- `Gamma` is the VRF output point (x*H)
- `U` and `V` are the DLEQ proof commitments

The hash output is truncated to 16 bytes for secp256k1.

### VRF Output

The VRF output beta is computed as:
```
beta = Hash(suite_string || 0x03 || Gamma || 0x00)
```

## Important Notes

- The TAI and RFC 9380 variants use different suite strings (0xFE and 0xFF)
- Proofs generated with one method cannot be verified with the other
- The same input will produce different outputs with different hash-to-curve methods
- This implementation includes the public key in the challenge (unlike draft-05)

## Generic Hash Support

The implementation is generic over the hash function, constrained by `secp256kfun::hash::Hash32`. This allows using different SHA256 implementations or other 32-byte output hash functions.
