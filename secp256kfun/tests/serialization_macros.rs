#[cfg(feature = "serialization")]
mod test {

    use core::{marker::PhantomData, str::FromStr};
    use secp256kfun::{impl_display_debug_serialize, impl_fromstr_deserailize, hex::HexError};

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

    impl_fromstr_deserailize! {
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
        assert_eq!(parsed.to_six_bytes(), hex_literal::hex!("deadbeef0123"));
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
        let six_bytes = &SixBytes::<()>::from_six_bytes(hex_literal::hex!("010203040506")).unwrap();
        let serialized = bincode::serialize(six_bytes).unwrap();
        let six_bytes = bincode::deserialize::<SixBytes<()>>(&serialized).expect("valid bincode");
        assert_eq!(six_bytes.to_six_bytes(), hex_literal::hex!("010203040506"));
    }

    #[test]
    fn deserialize_invalid_bytes() {
        let bincode_bytes = hex_literal::hex!("000102030405"); // starting with 00 is invalid
        let err = bincode::deserialize::<SixBytes<()>>(&bincode_bytes).unwrap_err();
        assert_eq!(
            format!("{}", err),
            "invalid byte encoding, expected a valid 6-byte encoding of a six bytes"
        );
    }

    #[test]
    fn serialize_hex_roundtrip() {
        let json_string = r#""deadbeef0123""#;
        let six_bytes = serde_json::from_str::<SixBytes<()>>(json_string).expect("valid json");
        assert_eq!(six_bytes.to_six_bytes(), hex_literal::hex!("deadbeef0123"));
        assert_eq!(serde_json::to_string(&six_bytes).unwrap(), json_string)
    }

    #[test]
    fn deserialize_wrong_length() {
        assert!(serde_json::from_str::<SixBytes<()>>(r#""deadbeef01""#).is_err())
    }

    #[test]
    fn display() {
        struct MyMarker;
        let six_bytes =
            SixBytes::<MyMarker>::from_six_bytes(hex_literal::hex!("deadbeef0123")).unwrap();

        assert_eq!(format!("{}", six_bytes), "deadbeef0123");
        assert_eq!(
            format!("{:?}", six_bytes),
            "SixBytes<MyMarker>(deadbeef0123)"
        );
    }
}
