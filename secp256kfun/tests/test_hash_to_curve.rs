use proptest::prelude::*;
use secp256kfun::{Point, hex, marker::*};
use sha2::Sha256;

#[test]
fn test_hash_to_curve_rfc_vectors() {
    // Test vectors from the IETF draft specification
    // See: https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
    // These are the final P.x and P.y values for each test case
    let test_vectors: [(&[u8], [u8; 32], [u8; 32]); 5] = [
        (
            &b""[..],
            hex::decode_array("c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346").unwrap(),
            hex::decode_array("64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067").unwrap(),
        ),
        (
            &b"abc"[..],
            hex::decode_array("3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b").unwrap(),
            hex::decode_array("7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6").unwrap(),
        ),
        (
            &b"abcdef0123456789"[..],
            hex::decode_array("bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a").unwrap(),
            hex::decode_array("4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828").unwrap(),
        ),
        (
            &b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"[..],
            hex::decode_array("e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9").unwrap(),
            hex::decode_array("f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873").unwrap(),
        ),
        (
            &b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..],
            hex::decode_array("e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998").unwrap(),
            hex::decode_array("8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6").unwrap(),
        ),
    ];

    let dst = b"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_";

    for (i, (msg, expected_x, expected_y)) in test_vectors.iter().enumerate() {
        let point = Point::hash_to_curve::<Sha256>(msg, dst).normalize();
        let (x_bytes, y_bytes) = point.coordinates();

        assert_eq!(
            &x_bytes[..],
            &expected_x[..],
            "Test vector {} failed: x coordinate mismatch",
            i
        );
        assert_eq!(
            &y_bytes[..],
            &expected_y[..],
            "Test vector {} failed: y coordinate mismatch",
            i
        );
    }
}

proptest! {
    #[test]
    fn test_hash_to_curve_properties(
        msg1 in prop::collection::vec(any::<u8>(), 0..1000),
        msg2 in prop::collection::vec(any::<u8>(), 0..1000),
        dst1 in prop::collection::vec(any::<u8>(), 0..255),
        dst2 in prop::collection::vec(any::<u8>(), 0..255),
    ) {
        // Test determinism - same message and DST should produce same point
        let point1 = Point::hash_to_curve::<Sha256>(&msg1, &dst1);
        let point1_again = Point::hash_to_curve::<Sha256>(&msg1, &dst1);
        assert_eq!(point1, point1_again, "hash_to_curve should be deterministic");

        // Point should be NonNormal
        let _: Point<NonNormal, Public, NonZero> = point1;

        // Points should never be zero
        assert!(!point1.is_zero(), "hash_to_curve should never produce zero point");

        // Different messages with same DST should produce different points (with high probability)
        if msg1 != msg2 {
            let point2 = Point::hash_to_curve::<Sha256>(&msg2, &dst1);
            assert_ne!(point1, point2, "Different messages should produce different points");
            assert!(!point2.is_zero(), "hash_to_curve should never produce zero point");
        }

        // Same message with different DSTs should produce different points (with high probability)
        if dst1 != dst2 {
            let point3 = Point::hash_to_curve::<Sha256>(&msg1, &dst2);
            assert_ne!(point1, point3, "Different DSTs should produce different points");
            assert!(!point3.is_zero(), "hash_to_curve should never produce zero point");
        }
    }
}
