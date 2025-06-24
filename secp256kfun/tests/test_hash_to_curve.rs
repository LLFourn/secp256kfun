use proptest::prelude::*;
use secp256kfun::{Point, hash::HashAdd, hex, marker::*};
use sha2::Sha256;

#[test]
fn test_hash_to_curve_sswu_test_vectors() {
    // Test vectors from RFC 9380 specification
    // See: https://datatracker.ietf.org/doc/rfc9380/
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
        let point = Point::hash_to_curve_sswu::<Sha256>(msg, dst).normalize();
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
    fn test_hash_to_curve_sswu_properties(
        msg1 in prop::collection::vec(any::<u8>(), 0..1000),
        msg2 in prop::collection::vec(any::<u8>(), 0..1000),
        dst1 in prop::collection::vec(any::<u8>(), 0..255),
        dst2 in prop::collection::vec(any::<u8>(), 0..255),
    ) {
        // Test determinism - same message and DST should produce same point
        let point1 = Point::hash_to_curve_sswu::<Sha256>(&msg1, &dst1);
        let point1_again = Point::hash_to_curve_sswu::<Sha256>(&msg1, &dst1);
        assert_eq!(point1, point1_again, "hash_to_curve_sswu should be deterministic");

        // Point should be NonNormal
        let _: Point<NonNormal, Public, NonZero> = point1;

        // Points should never be zero
        assert!(!point1.is_zero(), "hash_to_curve_sswu should never produce zero point");

        // Different messages with same DST should produce different points (with high probability)
        if msg1 != msg2 {
            let point2 = Point::hash_to_curve_sswu::<Sha256>(&msg2, &dst1);
            assert_ne!(point1, point2, "Different messages should produce different points");
            assert!(!point2.is_zero(), "hash_to_curve_sswu should never produce zero point");
        }

        // Same message with different DSTs should produce different points (with high probability)
        if dst1 != dst2 {
            let point3 = Point::hash_to_curve_sswu::<Sha256>(&msg1, &dst2);
            assert_ne!(point1, point3, "Different DSTs should produce different points");
            assert!(!point3.is_zero(), "hash_to_curve_sswu should never produce zero point");
        }
    }

    #[test]
    fn test_hash_to_curve_properties(
        msg1 in prop::collection::vec(any::<u8>(), 0..1000),
        msg2 in prop::collection::vec(any::<u8>(), 0..1000),
    ) {
        // Test determinism - same message should produce same point
        let point1 = Point::hash_to_curve(Sha256::default().add(msg1.as_slice()));
        let point1_again = Point::hash_to_curve(Sha256::default().add(msg1.as_slice()));
        assert_eq!(point1, point1_again, "hash_to_curve should be deterministic");

        // Point should be Normal
        let _: Point<Normal, Public, NonZero> = point1;

        // Points should never be zero
        assert!(!point1.is_zero(), "hash_to_curve should never produce zero point");

        // Different messages should produce different points (with high probability)
        if msg1 != msg2 {
            let point2 = Point::hash_to_curve(Sha256::default().add(msg2.as_slice()));
            assert_ne!(point1, point2, "Different messages should produce different points");
            assert!(!point2.is_zero(), "hash_to_curve should never produce zero point");
        }
    }
}

#[test]
fn test_hash_to_curve_test_vectors() {
    // Test vectors for hash_to_curve method
    // Format: (message, expected_point_bytes)
    let test_vectors: &[(&[u8], &str)] = &[
        // Empty message
        (
            b"",
            "026e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        ),
        // Simple message
        (
            b"abc",
            "039ec4bc6eb63eba8718769cd80a0350e55a1372b09081a1fb6ecd3be235ec1690",
        ),
        // Binary data including null bytes
        (
            &[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd],
            "03e8f0f84f444ef4b79f067e6cf00df7121c053b338facf4d48e28d44ca23eaea8",
        ),
        // Longer message
        (
            b"The quick brown fox jumps over the lazy dog",
            "03b2ad65c3817347a655c515ac1e5e6a6620407d39b53bad8355312911de249e1d",
        ),
    ];

    for (i, (msg, expected_hex)) in test_vectors.iter().enumerate() {
        let point = Point::hash_to_curve(Sha256::default().add(*msg));
        let actual_bytes = point.to_bytes();
        let expected_bytes = hex::decode_array::<33>(expected_hex).unwrap();

        assert_eq!(
            actual_bytes, expected_bytes,
            "Test vector {} failed: msg={:?}",
            i, msg
        );

        // Verify determinism
        let point2 = Point::hash_to_curve(Sha256::default().add(*msg));
        assert_eq!(point, point2, "Point generation should be deterministic");

        // Verify the point is valid and non-zero
        assert!(!point.is_zero());
    }
}

#[test]
fn test_hash_to_curve_rfc9381_tai() {
    // Test vectors for RFC 9381 TAI (try-and-increment) method
    // Format: (message, salt, expected_point_bytes)
    let test_vectors: &[(&[u8], &[u8], &str)] = &[
        // Empty message, empty salt
        (
            b"",
            b"",
            "020fadef9b80ca733f36f5dad4bdce241534ac605ed352a1c3570a38913dc92204",
        ),
        // Message with empty salt
        (
            b"abc",
            b"",
            "026d72997180b59ffed2e9fef657f392ea3aa869dae4a441feac861eaca9f00985",
        ),
        // Message with salt
        (
            b"test message",
            b"test salt",
            "02b4e185a9c8535748a9fe89b287a0bf6a24c5bd5f25a9cb50b0e5770a41abc550",
        ),
        // VRF test case with public key as salt
        (
            b"sample",
            &hex::decode_array::<33>(
                "032c8c31fc9f990c6b55e3865a184a4ce50e09481f2eaeb3e60ec1cea13a6ae645",
            )
            .unwrap(),
            "0221ceb1ce22cd34d8b73a619164ed64e917ca31fd454075d02e4bdfa9c5ce0b48",
        ),
        // Binary data with binary salt
        (
            &[0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd],
            &[0xde, 0xad, 0xbe, 0xef],
            "025b9c20016d733cab83dda56f283e68d574cbc39ef2d77cb343241daa54a91b79",
        ),
    ];

    for (i, (msg, salt, expected_hex)) in test_vectors.iter().enumerate() {
        let point = Point::hash_to_curve_rfc9381_tai::<Sha256>(msg, salt);
        let actual_bytes = point.to_bytes();
        let expected_bytes = hex::decode_array::<33>(expected_hex).unwrap();

        assert_eq!(
            actual_bytes, expected_bytes,
            "Test vector {} failed: msg={:?}, salt={:?}",
            i, msg, salt
        );

        // Verify determinism
        let point2 = Point::hash_to_curve_rfc9381_tai::<Sha256>(msg, salt);
        assert_eq!(point, point2, "Point generation should be deterministic");

        // Verify the point is valid and non-zero
        assert!(!point.is_zero());
        assert_eq!(
            actual_bytes[0], 0x02,
            "Point should always have even y-coordinate"
        );
    }

    // Additional property tests
    // Test that different messages produce different points
    let point1 = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"message1", b"");
    let point2 = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"message2", b"");
    assert_ne!(point1, point2);

    // Test that same message with different salts produces different points
    let point3 = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"message", b"salt1");
    let point4 = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"message", b"salt2");
    assert_ne!(point3, point4);
}
