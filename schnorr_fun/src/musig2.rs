use bitcoin_hashes::borrow_slice_impl;
use bitcoin_hashes::hash_newtype;
use bitcoin_hashes::hex_fmt_impl;
use bitcoin_hashes::index_impl;
use bitcoin_hashes::serde_impl;
use bitcoin_hashes::sha256t_hash_newtype;
use bitcoin_hashes::{sha256, Hash, HashEngine};
use secp256kfun::g;
use secp256kfun::marker::{Jacobian, Mark, NonZero};
use secp256kfun::{Point, Scalar, XOnly};

/// The SHA-256 midstate value for the "KeyAgg coefficient" hash.
const MIDSTATE_KEYAGGHASH: [u8; 32] = [
    110, 240, 44, 90, 6, 164, 128, 222, 31, 41, 134, 101, 29, 17, 52, 242, 86, 160, 176, 99, 82,
    218, 65, 71, 242, 128, 217, 212, 68, 132, 190, 21,
];
// 6ef02c5a06a480de1f2986651d1134f256a0b06352da4147f280d9d44484be15

sha256t_hash_newtype!(
    KeyAggHash,
    KeyAggTag,
    MIDSTATE_KEYAGGHASH,
    64,
    doc = "Tagged hash for key aggregation",
    true
);

/// Struct to be create to aggregate keys with the Musig2 protocol as defined in
/// https://github.com/ElementsProject/secp256k1-zkp/blob/5d2df0541960554be5c0ba58d86e5fa479935000/src/modules/musig/musig-spec.mediawiki
#[derive(Debug)]
pub struct Musig<'a> {
    keys: &'a [XOnly],
    keys_hash: [u8; 32],
    second: Option<&'a XOnly>,
}

impl<'a> Musig<'a> {
    /// Create new Musig struct
    pub fn new(keys: &'a [XOnly]) -> Option<Musig> {
        if keys.len() < 2 {
            return None;
        }
        let mut engine = sha256::Hash::engine();
        let mut second = None;
        for k in keys.iter() {
            engine.input(k.as_bytes());
            if second.is_none() {
                if *k != keys[0] {
                    second = Some(k)
                }
            }
        }
        let keys_hash = sha256::Hash::from_engine(engine).into_inner();
        Some(Musig {
            keys,
            keys_hash,
            second,
        })
    }

    /// returns the scalar coefficient to be used for key `index`
    fn coeff(&self, index: usize) -> Option<Scalar> {
        if index >= self.keys.len() {
            return None;
        }
        if Some(&self.keys[index]) == self.second {
            return Some(Scalar::one());
        } else {
            let mut engine = KeyAggHash::engine();
            engine.input(&self.keys_hash);
            engine.input(self.keys[index].as_bytes());
            let hash = KeyAggHash::from_engine(engine);
            let s = Scalar::from_bytes(hash.into_inner());
            s.and_then(|s| s.mark::<NonZero>())
        }
    }

    /// Combine keys into one key
    pub fn combine(&self) -> Option<XOnly> {
        let mut accumulator = Point::zero().mark::<Jacobian>();
        for (i, k) in self.keys.iter().enumerate() {
            let current_scalar = self.coeff(i)?;
            let current_point = k.to_point();
            accumulator = g!(accumulator + current_scalar * current_point);
        }
        let result = accumulator.mark::<NonZero>()?;
        Some(result.into_point_with_even_y().0.to_xonly())
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyAggHash, Musig, MIDSTATE_KEYAGGHASH};
    use bitcoin_hashes::hex::{FromHex, ToHex};
    use bitcoin_hashes::Hash;
    use secp256kfun::XOnly;
    use std::vec::Vec;

    #[test]
    fn test_keyagghash() {
        let v =
            Vec::<u8>::from_hex("6ef02c5a06a480de1f2986651d1134f256a0b06352da4147f280d9d44484be15")
                .unwrap();
        assert_eq!(MIDSTATE_KEYAGGHASH.to_vec(), v);

        let h = KeyAggHash::hash(b"");
        assert_eq!(
            h.to_hex(),
            "c73cff1ec19568213104330a946930c4ee2ea7c65a1c43973a038a372620a055"
        );
    }

    #[test]
    fn test_combine() {
        // test taken from
        // https://github.com/ElementsProject/secp256k1-zkp/blob/5d2df0541960554be5c0ba58d86e5fa479935000/src/modules/musig/tests_impl.h
        let x1 = XOnly::from_bytes([
            0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D,
            0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13,
            0xBC, 0xE0, 0x36, 0xF9,
        ])
        .unwrap();
        let x2 = XOnly::from_bytes([
            0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18, 0x37, 0x26, 0xDB, 0x23,
            0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B,
            0x50, 0x2B, 0xA6, 0x59,
        ])
        .unwrap();
        let x3 = XOnly::from_bytes([
            0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18, 0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80,
            0xA8, 0xE3, 0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7, 0xAD, 0x33, 0x83, 0x68,
            0xD0, 0x38, 0xCA, 0x66,
        ])
        .unwrap();

        let x1_x2_x3 = vec![x1, x2, x3];
        let expected_x1_x2_x3 = XOnly::from_bytes([
            0xEA, 0x06, 0x7B, 0x01, 0x67, 0x24, 0x5A, 0x6F, 0xED, 0xB1, 0xB1, 0x22, 0xBB, 0x03,
            0xAB, 0x7E, 0x5D, 0x48, 0x6C, 0x81, 0x83, 0x42, 0xE0, 0xE9, 0xB6, 0x41, 0x79, 0xAD,
            0x32, 0x8D, 0x9D, 0x19,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x2_x3).unwrap().combine(),
            Some(expected_x1_x2_x3)
        );

        let x3_x2_x1 = vec![x3, x2, x1];
        let expected_x3_x2_x1 = XOnly::from_bytes([
            0x14, 0xE1, 0xF8, 0x3E, 0x9E, 0x25, 0x60, 0xFB, 0x2A, 0x6C, 0x04, 0x24, 0x55, 0x6C,
            0x86, 0x8D, 0x9F, 0xB4, 0x63, 0x35, 0xD4, 0xF7, 0x8D, 0x22, 0x7D, 0x5D, 0x1D, 0x3C,
            0x89, 0x90, 0x6F, 0x1E,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x3_x2_x1).unwrap().combine(),
            Some(expected_x3_x2_x1)
        );

        let x1_x1_x1 = vec![x1, x1, x1];
        let expected_x1_x1_x1 = XOnly::from_bytes([
            0x70, 0x28, 0x8D, 0xF2, 0xB7, 0x60, 0x3D, 0xBE, 0xA0, 0xC7, 0xB7, 0x41, 0xDD, 0xAA,
            0xB9, 0x46, 0x81, 0x14, 0x4E, 0x0B, 0x19, 0x08, 0x6C, 0x69, 0xB2, 0x34, 0x89, 0xE4,
            0xF5, 0xB7, 0x01, 0x9A,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x1_x1).unwrap().combine(),
            Some(expected_x1_x1_x1)
        );

        let x1_x1_x2_x2 = vec![x1, x1, x2, x2];
        let expected_x1_x1_x2_x2 = XOnly::from_bytes([
            0x93, 0xEE, 0xD8, 0x24, 0xF2, 0x3C, 0x5A, 0xE1, 0xC1, 0x05, 0xE7, 0x31, 0x09, 0x97,
            0x3F, 0xCD, 0x4A, 0xE3, 0x3A, 0x9F, 0xA0, 0x2F, 0x0A, 0xC8, 0x5A, 0x3E, 0x55, 0x89,
            0x07, 0x53, 0xB0, 0x67,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x1_x2_x2).unwrap().combine(),
            Some(expected_x1_x1_x2_x2)
        );
    }
}
