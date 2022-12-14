use crate::{
    marker::*,
    secp256k1::{PublicKey, SecretKey, XOnlyPublicKey},
    Point, Scalar,
};

impl From<Scalar> for SecretKey {
    fn from(scalar: Scalar) -> Self {
        SecretKey::from_slice(scalar.to_bytes().as_ref()).unwrap()
    }
}

impl From<SecretKey> for Scalar {
    fn from(sk: SecretKey) -> Self {
        Scalar::from_slice(&sk[..])
            .unwrap()
            .non_zero()
            .expect("SecretKey is never zero")
    }
}

impl<Z> From<Scalar<Public, Z>> for secp256k1::Scalar {
    fn from(value: Scalar<Public, Z>) -> Self {
        secp256k1::Scalar::from_be_bytes(value.to_bytes()).unwrap()
    }
}

impl From<secp256k1::Scalar> for Scalar<Public, Zero> {
    fn from(value: secp256k1::Scalar) -> Self {
        Scalar::from_bytes(value.to_be_bytes()).unwrap()
    }
}

impl From<PublicKey> for Point {
    fn from(pk: PublicKey) -> Self {
        Point::<Normal, Public, NonZero>::from_bytes(pk.serialize()).unwrap()
    }
}

impl From<Point> for PublicKey {
    fn from(pk: Point) -> Self {
        PublicKey::from_slice(pk.to_bytes().as_ref()).unwrap()
    }
}

impl From<Point<EvenY>> for XOnlyPublicKey {
    fn from(point: Point<EvenY>) -> Self {
        XOnlyPublicKey::from_slice(point.to_xonly_bytes().as_ref()).unwrap()
    }
}

impl From<XOnlyPublicKey> for Point<EvenY> {
    fn from(pk: XOnlyPublicKey) -> Self {
        Point::from_xonly_bytes(pk.serialize()).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::str::FromStr;
    #[cfg(feature = "proptest")]
    use proptest::prelude::*;

    #[test]
    fn public_key() {
        let pk = PublicKey::from_str("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let point = Point::from(pk);
        assert_eq!(pk.serialize().as_ref(), point.to_bytes().as_ref());
    }

    #[cfg(feature = "proptest")]
    proptest! {

        #[test]
        fn prop_public_key(first_byte in 0u8..10, x_bytes in any::<[u8;32]>()) {
            let mut bytes = [0u8;33];
            bytes[0] = first_byte;
            bytes[1..33].copy_from_slice(&x_bytes[..]);
            let pk = PublicKey::from_slice(&bytes[..]).ok();
            let point = Point::<_,Public, >::from_bytes(bytes);
            assert_eq!(pk.map(|pk| pk.serialize()), point.map(|point| point.to_bytes()));
        }

        #[test]
        fn prop_secret_key(bytes in any::<[u8;32]>()) {
            let sk = SecretKey::from_slice(&bytes[..]).unwrap();
            let scalar = Scalar::from(sk);
            assert_eq!(&sk[..], scalar.to_bytes().as_ref());
        }



        #[test]
        fn scalar_roundtrip(scalar in any::<Scalar<Public, Zero>>()) {
            let secp_scalar = secp256k1::Scalar::from(scalar);
            let rt_scalar = Scalar::from(secp_scalar);
            assert_eq!(rt_scalar, scalar);
        }
    }
}
