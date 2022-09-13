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
    use rand_core::RngCore;

    #[test]
    fn secret_key() {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let sk = SecretKey::from_slice(&bytes[..]).unwrap();
        let scalar = Scalar::from(sk);
        assert_eq!(&sk[..], scalar.to_bytes().as_ref());
    }

    #[test]
    fn public_key() {
        let pk = PublicKey::from_str("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
        let point = Point::from(pk);
        assert_eq!(pk.serialize().as_ref(), point.to_bytes().as_ref());
    }
}
