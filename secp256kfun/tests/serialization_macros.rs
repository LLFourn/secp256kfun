#[cfg(feature = "serde")]
mod test {

    use core::{marker::PhantomData, str::FromStr};
    use secp256kfun::{
        hex::{self, HexError},
        impl_display_debug_serialize, impl_fromstr_deserialize,
    };

    #[derive(PartialEq)]
    struct SixBytes<T>([u8; 6], PhantomData<T>);

    impl<T> SixBytes<T> {
        fn from_six_bytes(from: [u8; 6]) -> Option<Self> {
            if from[0] == 0u8 {
                None
            } else {
                Some(SixBytes(from, PhantomData))
            }
        }

        fn to_six_bytes(&self) -> [u8; 6] {
            self.0.clone()
        }

        #[allow(dead_code)]
        fn from_slice(slice: &[u8]) -> Option<Self> {
            if slice.len() != 6 {
                return None;
            }

            let mut bytes = [0u8; 6];

            bytes.copy_from_slice(slice);
            Self::from_six_bytes(bytes)
        }
    }

    impl_fromstr_deserialize! {
        name => "six bytes",
        fn from_bytes<T>(bytes: [u8;6]) -> Option<SixBytes<T>> {
            SixBytes::from_six_bytes(bytes)
        }
    }

    impl_display_debug_serialize! {
        fn to_bytes<T>(six_bytes: &SixBytes<T>) -> &[u8;6] {
            &six_bytes.0
        }
    }

    #[test]
    fn from_str_roundtrip() {
        let parsed = SixBytes::<()>::from_str("deadbeef0123").unwrap();
        assert_eq!(
            parsed.to_six_bytes(),
            hex::decode_array("deadbeef0123").unwrap()
        );
        assert_eq!(format!("{}", parsed).as_str(), "deadbeef0123");
    }

    #[test]
    fn from_str_error_cases() {
        assert_eq!(
            SixBytes::<()>::from_str("deadbeef012345"),
            Err(HexError::InvalidLength)
        );

        assert_eq!(
            SixBytes::<()>::from_str("deadbeef012g"),
            Err(HexError::InvalidHex)
        );

        assert_eq!(
            SixBytes::<()>::from_str("deadbeef01234"),
            Err(HexError::InvalidHex)
        );

        assert_eq!(
            SixBytes::<()>::from_str("00deadbeef11"),
            Err(HexError::InvalidEncoding)
        );
    }

    #[test]
    fn serialize_roundtrip() {
        let six_bytes =
            &SixBytes::<()>::from_six_bytes(hex::decode_array("010203040506").unwrap()).unwrap();
        let serialized = bincode::serialize(six_bytes).unwrap();
        let six_bytes = bincode::deserialize::<SixBytes<()>>(&serialized).expect("valid bincode");
        assert_eq!(
            six_bytes.to_six_bytes(),
            hex::decode_array("010203040506").unwrap()
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid byte encoding, expected a valid 6-byte encoding of a six bytes"
    )]
    fn deserialize_invalid_bytes() {
        let bincode_bytes = hex::decode_array::<6>("000102030405").unwrap(); // starting with 00 is invalid
        bincode::deserialize::<SixBytes<()>>(&bincode_bytes).unwrap();
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn serialize_hex_roundtrip() {
        let json_string = r#""deadbeef0123""#;
        let six_bytes = serde_json::from_str::<SixBytes<()>>(json_string).expect("valid json");
        assert_eq!(
            six_bytes.to_six_bytes(),
            hex::decode_array("deadbeef0123").unwrap()
        );
        assert_eq!(serde_json::to_string(&six_bytes).unwrap(), json_string)
    }

    #[test]
    #[should_panic(expected = "invalid length 5, expected a valid 6-byte hex encoded six bytes")]
    #[cfg(feature = "alloc")]
    fn deserialize_wrong_length() {
        serde_json::from_str::<SixBytes<()>>(r#""deadbeef01""#).unwrap();
    }

    #[test]
    fn display() {
        struct MyMarker;
        let six_bytes =
            SixBytes::<MyMarker>::from_six_bytes(hex::decode_array("deadbeef0123").unwrap())
                .unwrap();

        assert_eq!(format!("{}", six_bytes), "deadbeef0123");
        assert_eq!(
            format!("{:?}", six_bytes),
            "SixBytes<MyMarker>(deadbeef0123)"
        );
    }
}
