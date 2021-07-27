use bitcoin_hashes::{
    borrow_slice_impl, hash_newtype, hex_fmt_impl, index_impl, serde_impl, sha256t_hash_newtype,
    Hash, HashEngine,
};
use secp256kfun::{
    g,
    marker::{Jacobian, Mark, NonZero},
    Point, Scalar, XOnly,
};

/// The SHA-256 midstate value for the "KeyAgg coefficient" hash.
const MIDSTATE_KEYAGG_COEFFICIENT_HASH: [u8; 32] = [
    110, 240, 44, 90, 6, 164, 128, 222, 31, 41, 134, 101, 29, 17, 52, 242, 86, 160, 176, 99, 82,
    218, 65, 71, 242, 128, 217, 212, 68, 132, 190, 21,
];

/// The SHA-256 midstate value for the "KeyAgg list" hash.
const MIDSTATE_KEYAGG_LIST_HASH: [u8; 32] = [
    179, 153, 213, 224, 200, 255, 243, 2, 107, 173, 172, 113, 7, 197, 183, 241, 151, 1, 226, 239,
    42, 114, 236, 248, 32, 26, 76, 123, 171, 20, 138, 56,
];

sha256t_hash_newtype!(
    KeyAggCoefficientHash,
    KeyAggCoefficientTag,
    MIDSTATE_KEYAGG_COEFFICIENT_HASH,
    64,
    doc = "Tagged hash for key aggregation",
    true
);

sha256t_hash_newtype!(
    KeyAggListHash,
    KeyAggListTag,
    MIDSTATE_KEYAGG_LIST_HASH,
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
        let mut engine = KeyAggListHash::engine();
        let mut second = None;
        for k in keys.iter() {
            engine.input(k.as_bytes());
            if second.is_none() {
                if *k != keys[0] {
                    second = Some(k)
                }
            }
        }
        let keys_hash = KeyAggListHash::from_engine(engine).into_inner();
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
            let mut engine = KeyAggCoefficientHash::engine();
            engine.input(&self.keys_hash);
            engine.input(self.keys[index].as_bytes());
            let hash = KeyAggCoefficientHash::from_engine(engine);
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
    use super::{Musig, MIDSTATE_KEYAGG_COEFFICIENT_HASH};
    use crate::musig2::MIDSTATE_KEYAGG_LIST_HASH;
    use bitcoin_hashes::{hex::FromHex, sha256, Hash, HashEngine};
    use secp256kfun::XOnly;
    use std::vec::Vec;

    #[test]
    fn test_keyagg_hash() {
        let test = vec![
            (
                "KeyAgg coefficient",
                MIDSTATE_KEYAGG_COEFFICIENT_HASH,
                "6ef02c5a06a480de1f2986651d1134f256a0b06352da4147f280d9d44484be15",
            ),
            (
                "KeyAgg list",
                MIDSTATE_KEYAGG_LIST_HASH,
                "b399d5e0c8fff3026badac7107c5b7f19701e2ef2a72ecf8201a4c7bab148a38",
            ),
        ];

        for (tag, midstate, midstate_hex) in test {
            let tag_hash = sha256::Hash::hash(tag.as_bytes());
            let mut engine = sha256::Hash::engine();
            engine.input(&tag_hash);
            engine.input(&tag_hash);
            assert_eq!(engine.midstate().into_inner(), midstate);
            let v = Vec::<u8>::from_hex(midstate_hex).unwrap();
            assert_eq!(midstate.to_vec(), v);
        }
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
            0xE5, 0x83, 0x01, 0x40, 0x51, 0x21, 0x95, 0xD7, 0x4C, 0x83, 0x07, 0xE3, 0x96, 0x37,
            0xCB, 0xE5, 0xFB, 0x73, 0x0E, 0xBE, 0xAB, 0x80, 0xEC, 0x51, 0x4C, 0xF8, 0x8A, 0x87,
            0x7C, 0xEE, 0xEE, 0x0B,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x2_x3).unwrap().combine(),
            Some(expected_x1_x2_x3)
        );

        let x3_x2_x1 = vec![x3, x2, x1];
        let expected_x3_x2_x1 = XOnly::from_bytes([
            0xD7, 0x0C, 0xD6, 0x9A, 0x26, 0x47, 0xF7, 0x39, 0x09, 0x73, 0xDF, 0x48, 0xCB, 0xFA,
            0x2C, 0xCC, 0x40, 0x7B, 0x8B, 0x2D, 0x60, 0xB0, 0x8C, 0x5F, 0x16, 0x41, 0x18, 0x5C,
            0x79, 0x98, 0xA2, 0x90,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x3_x2_x1).unwrap().combine(),
            Some(expected_x3_x2_x1)
        );

        let x1_x1_x1 = vec![x1, x1, x1];
        let expected_x1_x1_x1 = XOnly::from_bytes([
            0x81, 0xA8, 0xB0, 0x93, 0x91, 0x2C, 0x9E, 0x48, 0x14, 0x08, 0xD0, 0x97, 0x76, 0xCE,
            0xFB, 0x48, 0xAE, 0xB8, 0xB6, 0x54, 0x81, 0xB6, 0xBA, 0xAF, 0xB3, 0xC5, 0x81, 0x01,
            0x06, 0x71, 0x7B, 0xEB,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x1_x1).unwrap().combine(),
            Some(expected_x1_x1_x1)
        );

        let x1_x1_x2_x2 = vec![x1, x1, x2, x2];
        let expected_x1_x1_x2_x2 = XOnly::from_bytes([
            0x2E, 0xB1, 0x88, 0x51, 0x88, 0x7E, 0x7B, 0xDC, 0x5E, 0x83, 0x0E, 0x89, 0xB1, 0x9D,
            0xDB, 0xC2, 0x80, 0x78, 0xF1, 0xFA, 0x88, 0xAA, 0xD0, 0xAD, 0x01, 0xCA, 0x06, 0xFE,
            0x4F, 0x80, 0x21, 0x0B,
        ])
        .unwrap();
        assert_eq!(
            Musig::new(&x1_x1_x2_x2).unwrap().combine(),
            Some(expected_x1_x1_x2_x2)
        );
    }
}
