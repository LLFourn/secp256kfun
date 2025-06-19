//! Hash to curve implementation for secp256k1
//!
//! This module implements the hash-to-curve algorithm as specified in:
//! <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
//!
//! Specifically, it implements:
//! - Suite ID: secp256k1_XMD:SHA-256_SSWU_RO_
//! - The simplified SWU method (Section 6.6.3)
//! - 3-isogeny mapping to secp256k1 (Appendix E.3)
//!
//! Note: This implementation was developed by @llfourn for secp256kfun, not taken from
//! the upstream k256 crate. It's placed in the vendor directory as it extends the k256
//! backend functionality.
//!
//! It is @llfourn's opinion that this construction is overwrought for secp256k1

use crate::digest::crypto_common::BlockSizeUser;
use crate::hash::Hash32;
use crate::vendor::k256::{AffinePoint, FieldElement, ProjectivePoint};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// L parameter for hash_to_field - fixed at 48 bytes for secp256k1
const L: usize = 48;

// Constants for expand_message_xmd
const F_2_192: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

// SSWU constants from k256
#[allow(dead_code)]
const C1: [u64; 4] = [
    0xffff_ffff_bfff_ff0b,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x3fff_ffff_ffff_ffff,
];

const C2: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x25, 0xe9, 0x71, 0x1a, 0xe8, 0xc0, 0xda, 0xdc, 0x46, 0xfd, 0xbc, 0xb7, 0x2a, 0xad, 0xd8, 0xf4,
    0x25, 0x0b, 0x65, 0x07, 0x30, 0x12, 0xec, 0x80, 0xbc, 0x6e, 0xcb, 0x9c, 0x12, 0x97, 0x39, 0x75,
]);

const MAP_A: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x3f, 0x87, 0x31, 0xab, 0xdd, 0x66, 0x1a, 0xdc, 0xa0, 0x8a, 0x55, 0x58, 0xf0, 0xf5, 0xd2, 0x72,
    0xe9, 0x53, 0xd3, 0x63, 0xcb, 0x6f, 0x0e, 0x5d, 0x40, 0x54, 0x47, 0xc0, 0x1a, 0x44, 0x45, 0x33,
]);

const MAP_B: FieldElement = FieldElement::from_bytes_unchecked(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xeb,
]);

const Z: FieldElement = FieldElement::from_bytes_unchecked(&[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x24,
]);

// Isogeny constants
const XNUM: [FieldElement; 4] = [
    FieldElement::from_bytes_unchecked(&[
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3,
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d, 0xaa, 0xaa,
        0xa8, 0xc7,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x07, 0xd3, 0xd4, 0xc8, 0x0b, 0xc3, 0x21, 0xd5, 0xb9, 0xf3, 0x15, 0xce, 0xa7, 0xfd, 0x44,
        0xc5, 0xd5, 0x95, 0xd2, 0xfc, 0x0b, 0xf6, 0x3b, 0x92, 0xdf, 0xff, 0x10, 0x44, 0xf1, 0x7c,
        0x65, 0x81,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x53, 0x4c, 0x32, 0x8d, 0x23, 0xf2, 0x34, 0xe6, 0xe2, 0xa4, 0x13, 0xde, 0xca, 0x25, 0xca,
        0xec, 0xe4, 0x50, 0x61, 0x44, 0x03, 0x7c, 0x40, 0x31, 0x4e, 0xcb, 0xd0, 0xb5, 0x3d, 0x9d,
        0xd2, 0x62,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3,
        0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8e, 0x38, 0xe3, 0x8d, 0xaa, 0xaa,
        0xa8, 0x8c,
    ]),
];

const XDEN: [FieldElement; 3] = [
    FieldElement::from_bytes_unchecked(&[
        0xd3, 0x57, 0x71, 0x19, 0x3d, 0x94, 0x91, 0x8a, 0x9c, 0xa3, 0x4c, 0xcb, 0xb7, 0xb6, 0x40,
        0xdd, 0x86, 0xcd, 0x40, 0x95, 0x42, 0xf8, 0x48, 0x7d, 0x9f, 0xe6, 0xb7, 0x45, 0x78, 0x1e,
        0xb4, 0x9b,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0xed, 0xad, 0xc6, 0xf6, 0x43, 0x83, 0xdc, 0x1d, 0xf7, 0xc4, 0xb2, 0xd5, 0x1b, 0x54, 0x22,
        0x54, 0x06, 0xd3, 0x6b, 0x64, 0x1f, 0x5e, 0x41, 0xbb, 0xc5, 0x2a, 0x56, 0x61, 0x2a, 0x8c,
        0x6d, 0x14,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ]),
];

const YNUM: [FieldElement; 4] = [
    FieldElement::from_bytes_unchecked(&[
        0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd,
        0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0x8e, 0x38,
        0xe2, 0x3c,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0xc7, 0x5e, 0x0c, 0x32, 0xd5, 0xcb, 0x7c, 0x0f, 0xa9, 0xd0, 0xa5, 0x4b, 0x12, 0xa0, 0xa6,
        0xd5, 0x64, 0x7a, 0xb0, 0x46, 0xd6, 0x86, 0xda, 0x6f, 0xdf, 0xfc, 0x90, 0xfc, 0x20, 0x1d,
        0x71, 0xa3,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x29, 0xa6, 0x19, 0x46, 0x91, 0xf9, 0x1a, 0x73, 0x71, 0x52, 0x09, 0xef, 0x65, 0x12, 0xe5,
        0x76, 0x72, 0x28, 0x30, 0xa2, 0x01, 0xbe, 0x20, 0x18, 0xa7, 0x65, 0xe8, 0x5a, 0x9e, 0xce,
        0xe9, 0x31,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6,
        0x84, 0xbd, 0xa1, 0x2f, 0x68, 0x4b, 0xda, 0x12, 0xf6, 0x84, 0xbd, 0xa1, 0x2f, 0x38, 0xe3,
        0x8d, 0x84,
    ]),
];

const YDEN: [FieldElement; 4] = [
    FieldElement::from_bytes_unchecked(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xf9, 0x3b,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x7a, 0x06, 0x53, 0x4b, 0xb8, 0xbd, 0xb4, 0x9f, 0xd5, 0xe9, 0xe6, 0x63, 0x27, 0x22, 0xc2,
        0x98, 0x94, 0x67, 0xc1, 0xbf, 0xc8, 0xe8, 0xd9, 0x78, 0xdf, 0xb4, 0x25, 0xd2, 0x68, 0x5c,
        0x25, 0x73,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x64, 0x84, 0xaa, 0x71, 0x65, 0x45, 0xca, 0x2c, 0xf3, 0xa7, 0x0c, 0x3f, 0xa8, 0xfe, 0x33,
        0x7e, 0x0a, 0x3d, 0x21, 0x16, 0x2f, 0x0d, 0x62, 0x99, 0xa7, 0xbf, 0x81, 0x92, 0xbf, 0xd2,
        0xa7, 0x6f,
    ]),
    FieldElement::from_bytes_unchecked(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ]),
];

/// Hash to curve implementation for secp256k1 following the IETF draft
/// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
pub fn hash_to_curve<H: Hash32 + digest::Update + BlockSizeUser>(
    msg: &[u8],
    dst: &[u8],
) -> ProjectivePoint {
    let u = hash_to_field::<H>(msg, dst);
    let q0 = map_to_curve(u[0]);
    let q1 = map_to_curve(u[1]);
    ProjectivePoint::from(q0) + q1
}

/// Expand message using XMD (expand_message_xmd)
/// Implements the algorithm from Section 5.4.1 of draft-irtf-cfrg-hash-to-curve
fn expand_message_xmd<H: Hash32 + digest::Update + BlockSizeUser>(
    msg: &[u8],
    dst: &[u8],
    len_in_bytes: usize,
) -> [u8; 2 * L] {
    debug_assert_eq!(len_in_bytes, 2 * L); // We only use this for 2*L bytes

    const B_IN_BYTES: usize = 32; // Hash32 always outputs 32 bytes
    let r_in_bytes = <H as BlockSizeUser>::block_size();

    // ell = ceil(len_in_bytes / b_in_bytes)
    let ell = ((len_in_bytes + B_IN_BYTES - 1) / B_IN_BYTES) as u8;

    // Build DST prime in steps to avoid dynamic allocation
    let mut dst_prime = [0u8; 256];
    let actual_dst_prime_len = if dst.len() > 255 {
        // H(H2C-OVERSIZE-DST- || DST) || I2OSP(len(DST), 1)
        let mut hasher = H::default();
        hasher.update(b"H2C-OVERSIZE-DST-");
        hasher.update(dst);
        let hash = hasher.finalize_fixed();
        dst_prime[..B_IN_BYTES].copy_from_slice(&hash);
        dst_prime[B_IN_BYTES] = dst.len() as u8;
        B_IN_BYTES + 1
    } else {
        // DST || I2OSP(len(DST), 1)
        dst_prime[..dst.len()].copy_from_slice(dst);
        dst_prime[dst.len()] = dst.len() as u8;
        dst.len() + 1
    };

    // Z_pad = I2OSP(0, r_in_bytes)
    let z_pad = [0u8; 128]; // Max block size we support

    // msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
    let mut hasher = H::default();
    hasher.update(&z_pad[..r_in_bytes]);
    hasher.update(msg);
    hasher.update(&(len_in_bytes as u16).to_be_bytes());
    hasher.update(&[0u8]);
    hasher.update(&dst_prime[..actual_dst_prime_len]);

    // b_0 = H(msg_prime)
    let b_0 = hasher.finalize_fixed();

    // Initialize output
    let mut uniform_bytes = [0u8; 2 * L];
    let mut offset = 0;

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut hasher = H::default();
    hasher.update(&b_0);
    hasher.update(&[1u8]);
    hasher.update(&dst_prime[..actual_dst_prime_len]);
    let mut b_i = hasher.finalize_fixed();
    let copy_len = core::cmp::min(B_IN_BYTES, len_in_bytes - offset);
    uniform_bytes[offset..offset + copy_len].copy_from_slice(&b_i[..copy_len]);
    offset += copy_len;

    // For i in (2, ..., ell):
    for i in 2..=ell {
        if offset >= len_in_bytes {
            break;
        }

        // b_i = H(strxor(b_0, b_(i-1)) || I2OSP(i, 1) || DST_prime)
        let mut hasher = H::default();
        let mut xor_result = [0u8; 32]; // Hash32 output size
        for j in 0..B_IN_BYTES {
            xor_result[j] = b_0[j] ^ b_i[j];
        }
        hasher.update(&xor_result[..B_IN_BYTES]);
        hasher.update(&[i]);
        hasher.update(&dst_prime[..actual_dst_prime_len]);
        b_i = hasher.finalize_fixed();

        let copy_len = core::cmp::min(B_IN_BYTES, len_in_bytes - offset);
        uniform_bytes[offset..offset + copy_len].copy_from_slice(&b_i[..copy_len]);
        offset += copy_len;
    }

    uniform_bytes
}

/// Hash to field element - always returns 2 elements for hash_to_curve
fn hash_to_field<H: Hash32 + digest::Update + BlockSizeUser>(
    msg: &[u8],
    dst: &[u8],
) -> [FieldElement; 2] {
    let len_in_bytes = 2 * L;
    let uniform_bytes = expand_message_xmd::<H>(msg, dst, len_in_bytes);

    let mut output = [FieldElement::ZERO; 2];

    // Split the uniform_bytes into two L-byte chunks
    let (first_half, second_half) = uniform_bytes.split_at(L);
    output[0] = from_okm(first_half.try_into().unwrap());
    output[1] = from_okm(second_half.try_into().unwrap());

    output
}

/// Convert output keying material to field element
fn from_okm(data: &[u8; L]) -> FieldElement {
    // Construct d0 from first 24 bytes
    let d0 = FieldElement::from_bytes_unchecked(&[
        0, 0, 0, 0, 0, 0, 0, 0, data[0], data[1], data[2], data[3], data[4], data[5], data[6],
        data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);

    // Construct d1 from next 24 bytes
    let d1 = FieldElement::from_bytes_unchecked(&[
        0, 0, 0, 0, 0, 0, 0, 0, data[24], data[25], data[26], data[27], data[28], data[29],
        data[30], data[31], data[32], data[33], data[34], data[35], data[36], data[37], data[38],
        data[39], data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47],
    ]);

    d0 * F_2_192 + d1
}

/// Map field element to curve using Simplified SWU
fn map_to_curve(u: FieldElement) -> AffinePoint {
    let (x, y) = sswu_map(u);
    let (x_iso, y_iso) = isogeny_map(x, y);

    AffinePoint::new(x_iso, y_iso)
}

/// Simplified SWU map
fn sswu_map(u: FieldElement) -> (FieldElement, FieldElement) {
    let tv1 = u.square();
    let tv3 = Z * tv1;
    let mut tv2 = tv3.square();
    let mut xd = tv2 + tv3;
    let x1n = MAP_B * (xd + FieldElement::ONE);
    xd = (xd * MAP_A.negate(1)).normalize();

    let tv = Z * MAP_A;
    xd.conditional_assign(&tv, xd.is_zero());

    tv2 = xd.square();
    let gxd = tv2 * xd;
    tv2 = tv2 * MAP_A;

    let mut gx1 = x1n * (tv2 + x1n.square());
    tv2 = gxd * MAP_B;
    gx1 = gx1 + tv2;

    let mut tv4 = gxd.square();
    tv2 = gx1 * gxd;
    tv4 = tv4 * tv2;

    let y1 = pow_c1(&tv4) * tv2;
    let x2n = tv3 * x1n;

    let y2 = y1 * C2 * tv1 * u;

    tv2 = y1.square() * gxd;

    let e2 = tv2.normalize().ct_eq(&gx1.normalize());

    let mut x = FieldElement::conditional_select(&x2n, &x1n, e2);
    x = x * xd.invert().unwrap();

    let mut y = FieldElement::conditional_select(&y2, &y1, e2);
    y.conditional_assign(&y.negate(1), sgn0(&u) ^ sgn0(&y));

    (x, y)
}

/// Sign of field element (LSB)
fn sgn0(x: &FieldElement) -> Choice {
    x.normalize().is_odd()
}

/// Compute base^c1 where c1 = (p-3)/4 for secp256k1
fn pow_c1(base: &FieldElement) -> FieldElement {
    // For secp256k1, (p-3)/4 = (p+1)/4 - 1
    // We can use the same addition chain as sqrt but divide by base at the end

    let x2 = base.pow2k(1).mul(base); // base^3
    let x3 = x2.pow2k(1).mul(base); // base^7  
    let x6 = x3.pow2k(3).mul(&x3); // base^63
    let x9 = x6.pow2k(3).mul(&x3); // base^511
    let x11 = x9.pow2k(2).mul(&x2); // base^2047
    let x22 = x11.pow2k(11).mul(&x11); // base^(2^22 - 1)
    let x44 = x22.pow2k(22).mul(&x22); // base^(2^44 - 1)
    let x88 = x44.pow2k(44).mul(&x44); // base^(2^88 - 1)
    let x176 = x88.pow2k(88).mul(&x88); // base^(2^176 - 1)
    let x220 = x176.pow2k(44).mul(&x44); // base^(2^220 - 1)
    let x223 = x220.pow2k(3).mul(&x3); // base^(2^223 - 1)

    // The final assembly for (p-3)/4
    // Following the pattern from sqrt but with different final window
    // We need the exponent 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0b
    // The last part 0b = 11 in decimal
    // We already have x11 = base^2047, but we need base^11
    // base^11 = base^8 * base^2 * base = base^8 * x2 (since x2 = base^3)
    // Actually: base^11 = base^8 * base^3 = x9 * base^2 (since x9 = base^511)
    // Let's just compute it: base^11 = x3 * base^4 (since x3 = base^7)

    let t = x223.pow2k(23).mul(&x22);
    let t = t.pow2k(8);
    // Now multiply by base^11 = x3 * base^4
    let base4 = base.pow2k(2); // base^4
    t.mul(&x3).mul(&base4)
}

/// 3-isogeny map from E' to E
fn isogeny_map(x: FieldElement, y: FieldElement) -> (FieldElement, FieldElement) {
    let xx = x.square();
    let xxx = xx * x;

    let x_num = XNUM[0] + XNUM[1] * x + XNUM[2] * xx + XNUM[3] * xxx;
    let x_den = XDEN[0] + XDEN[1] * x + xx; // XDEN[2] = 1 is implicit

    let y_num = YNUM[0] + YNUM[1] * x + YNUM[2] * xx + YNUM[3] * xxx;
    let y_den = YDEN[0] + YDEN[1] * x + YDEN[2] * xx + xxx; // YDEN[3] = 1 is implicit

    let x_iso = x_num * x_den.invert().unwrap();
    let y_iso = y * y_num * y_den.invert().unwrap();

    (x_iso, y_iso)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::hex::decode_array;
    use alloc::string::String;
    use sha2::Sha256;

    // Local hex! macro that mimics hex_literal::hex!
    macro_rules! hex {
        ($hex:expr) => {
            decode_array($hex).unwrap()
        };
    }

    struct TestVector {
        msg: &'static [u8],
        p_x: [u8; 32],
        p_y: [u8; 32],
        u_0: [u8; 32],
        u_1: [u8; 32],
        q0_x: [u8; 32],
        q0_y: [u8; 32],
        q1_x: [u8; 32],
        q1_y: [u8; 32],
    }

    const DST: &[u8] = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    #[test]
    fn test_hash_to_curve_test_vectors() {
        let test_vectors = vec![
            TestVector {
                msg: b"",
                p_x: hex!("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346"),
                p_y: hex!("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067"),
                u_0: hex!("6b0f9910dd2ba71c78f2ee9f04d73b5f4c5f7fc773a701abea1e573cab002fb3"),
                u_1: hex!("1ae6c212e08fe1a5937f6202f929a2cc8ef4ee5b9782db68b0d5799fd8f09e16"),
                q0_x: hex!("74519ef88b32b425a095e4ebcc84d81b64e9e2c2675340a720bb1a1857b99f1e"),
                q0_y: hex!("c174fa322ab7c192e11748beed45b508e9fdb1ce046dee9c2cd3a2a86b410936"),
                q1_x: hex!("44548adb1b399263ded3510554d28b4bead34b8cf9a37b4bd0bd2ba4db87ae63"),
                q1_y: hex!("96eb8e2faf05e368efe5957c6167001760233e6dd2487516b46ae725c4cce0c6"),
            },
            TestVector {
                msg: b"abc",
                p_x: hex!("3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b"),
                p_y: hex!("7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6"),
                u_0: hex!("128aab5d3679a1f7601e3bdf94ced1f43e491f544767e18a4873f397b08a2b61"),
                u_1: hex!("5897b65da3b595a813d0fdcc75c895dc531be76a03518b044daaa0f2e4689e00"),
                q0_x: hex!("07dd9432d426845fb19857d1b3a91722436604ccbbbadad8523b8fc38a5322d7"),
                q0_y: hex!("604588ef5138cffe3277bbd590b8550bcbe0e523bbaf1bed4014a467122eb33f"),
                q1_x: hex!("e9ef9794d15d4e77dde751e06c182782046b8dac05f8491eb88764fc65321f78"),
                q1_y: hex!("cb07ce53670d5314bf236ee2c871455c562dd76314aa41f012919fe8e7f717b3"),
            },
            TestVector {
                msg: b"abcdef0123456789",
                p_x: hex!("bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a"),
                p_y: hex!("4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828"),
                u_0: hex!("ea67a7c02f2cd5d8b87715c169d055a22520f74daeb080e6180958380e2f98b9"),
                u_1: hex!("7434d0d1a500d38380d1f9615c021857ac8d546925f5f2355319d823a478da18"),
                q0_x: hex!("576d43ab0260275adf11af990d130a5752704f79478628761720808862544b5d"),
                q0_y: hex!("643c4a7fb68ae6cff55edd66b809087434bbaff0c07f3f9ec4d49bb3c16623c3"),
                q1_x: hex!("f89d6d261a5e00fe5cf45e827b507643e67c2a947a20fd9ad71039f8b0e29ff8"),
                q1_y: hex!("b33855e0cc34a9176ead91c6c3acb1aacb1ce936d563bc1cee1dcffc806caf57"),
            },
            TestVector {
                msg: b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                p_x: hex!("e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9"),
                p_y: hex!("f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873"),
                u_0: hex!("eda89a5024fac0a8207a87e8cc4e85aa3bce10745d501a30deb87341b05bcdf5"),
                u_1: hex!("dfe78cd116818fc2c16f3837fedbe2639fab012c407eac9dfe9245bf650ac51d"),
                q0_x: hex!("9c91513ccfe9520c9c645588dff5f9b4e92eaf6ad4ab6f1cd720d192eb58247a"),
                q0_y: hex!("c7371dcd0134412f221e386f8d68f49e7fa36f9037676e163d4a063fbf8a1fb8"),
                q1_x: hex!("10fee3284d7be6bd5912503b972fc52bf4761f47141a0015f1c6ae36848d869b"),
                q1_y: hex!("0b163d9b4bf21887364332be3eff3c870fa053cf508732900fc69a6eb0e1b672"),
            },
            TestVector {
                msg: b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                p_x: hex!("e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998"),
                p_y: hex!("8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6"),
                u_0: hex!("8d862e7e7e23d7843fe16d811d46d7e6480127a6b78838c277bca17df6900e9f"),
                u_1: hex!("68071d2530f040f081ba818d3c7188a94c900586761e9115efa47ae9bd847938"),
                q0_x: hex!("b32b0ab55977b936f1e93fdc68cec775e13245e161dbfe556bbb1f72799b4181"),
                q0_y: hex!("2f5317098360b722f132d7156a94822641b615c91f8663be69169870a12af9e8"),
                q1_x: hex!("148f98780f19388b9fa93e7dc567b5a673e5fca7079cd9cdafd71982ec4c5e12"),
                q1_y: hex!("3989645d83a433bc0c001f3dac29af861f33a6fd1e04f4b36873f5bff497298a"),
            },
        ];

        for (i, tv) in test_vectors.iter().enumerate() {
            println!(
                "Testing vector {}: msg = {:?}",
                i,
                String::from_utf8_lossy(tv.msg)
            );

            // First test hash_to_field to verify u values
            let u = hash_to_field::<Sha256>(tv.msg, DST);

            // Verify u values match
            let u0_bytes = u[0].to_bytes();
            let u1_bytes = u[1].to_bytes();
            assert_eq!(&u0_bytes[..], &tv.u_0[..], "Vector {}: u_0 mismatch", i);
            assert_eq!(&u1_bytes[..], &tv.u_1[..], "Vector {}: u_1 mismatch", i);

            // Test map_to_curve for q0 and q1
            let q0 = map_to_curve(u[0]);
            let q1 = map_to_curve(u[1]);

            // Verify q0 and q1
            assert_eq!(
                &q0.x.to_bytes()[..],
                &tv.q0_x[..],
                "Vector {}: q0_x mismatch",
                i
            );
            assert_eq!(
                &q0.y.to_bytes()[..],
                &tv.q0_y[..],
                "Vector {}: q0_y mismatch",
                i
            );
            assert_eq!(
                &q1.x.to_bytes()[..],
                &tv.q1_x[..],
                "Vector {}: q1_x mismatch",
                i
            );
            assert_eq!(
                &q1.y.to_bytes()[..],
                &tv.q1_y[..],
                "Vector {}: q1_y mismatch",
                i
            );

            // Test the complete hash_to_curve function
            let point = hash_to_curve::<Sha256>(tv.msg, DST);

            // Convert ProjectivePoint to AffinePoint to get coordinates
            let affine_point = AffinePoint::from(point);
            let x_bytes = affine_point.x.to_bytes();
            let y_bytes = affine_point.y.to_bytes();

            // Verify the final hash_to_curve output matches expected coordinates
            assert_eq!(
                &x_bytes[..],
                &tv.p_x[..],
                "Vector {}: final x coordinate mismatch",
                i
            );
            assert_eq!(
                &y_bytes[..],
                &tv.p_y[..],
                "Vector {}: final y coordinate mismatch",
                i
            );
        }
    }

    #[test]
    fn test_hash_to_curve_properties() {
        // Test that hash_to_curve produces valid points
        let test_messages: [&[u8]; 4] = [b"", b"abc", b"abcdef0123456789", b"test message"];

        for msg in &test_messages {
            let point = hash_to_curve::<Sha256>(msg, DST);

            // For hash_to_curve, points should never be the identity
            assert!(
                !bool::from(point.is_identity()),
                "hash_to_curve should not produce identity point for message {:?}",
                msg
            );

            // Verify the point is on the curve (implicit in ProjectivePoint)
            // Convert to affine to ensure it's a valid point
            let affine = AffinePoint::from(point);

            // Verify deterministic - same input produces same output
            let point2 = hash_to_curve::<Sha256>(msg, DST);
            assert_eq!(
                affine,
                AffinePoint::from(point2),
                "hash_to_curve should be deterministic for message {:?}",
                msg
            );
        }
    }
}
