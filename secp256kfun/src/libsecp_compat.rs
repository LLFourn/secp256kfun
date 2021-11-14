use crate::{
    marker::*,
    secp256k1::{schnorrsig, PublicKey, SecretKey},
    Point, Scalar, XOnly,
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
            .mark::<NonZero>()
            .expect("SecretKey is never zero")
    }
}

impl From<PublicKey> for Point {
    fn from(pk: PublicKey) -> Self {
        Point::from_bytes(pk.serialize()).unwrap()
    }
}

impl<T: Normalized> From<Point<T>> for PublicKey {
    fn from(pk: Point<T>) -> Self {
        PublicKey::from_slice(pk.to_bytes().as_ref()).unwrap()
    }
}

impl From<schnorrsig::PublicKey> for XOnly {
    fn from(pk: schnorrsig::PublicKey) -> Self {
        XOnly::from_bytes(pk.serialize()).unwrap()
    }
}

impl From<XOnly> for schnorrsig::PublicKey {
    fn from(xonly: XOnly) -> Self {
        schnorrsig::PublicKey::from_slice(xonly.as_bytes()).unwrap()
    }
}

impl From<Point<EvenY>> for schnorrsig::PublicKey {
    fn from(point: Point<EvenY>) -> Self {
        point.to_xonly().into()
    }
}

impl From<schnorrsig::PublicKey> for Point<EvenY> {
    fn from(pk: schnorrsig::PublicKey) -> Self {
        XOnly::from(pk).to_point()
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
