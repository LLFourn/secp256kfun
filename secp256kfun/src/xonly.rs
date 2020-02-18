use crate::{
    backend::{self, BackendXOnly, TimeSensitive},
    hash::HashInto,
    marker::*,
    Point, Scalar,
};
use core::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};

/// The x-coordinate of a [Point](crate::Point). This is the preferred
/// compressed representation of a point.
#[derive(Clone)]
pub struct XOnly<YChoice = ()>(pub(crate) backend::XOnly, PhantomData<YChoice>);

impl<Y> XOnly<Y> {
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        backend::XOnly::from_bytes(bytes).map(Self::from_inner)
    }

    pub(crate) fn from_inner(inner: backend::XOnly) -> Self {
        XOnly(inner, PhantomData)
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes).unwrap_or_else(|| Self::random(rng))
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    #[must_use]
    pub fn mark<M: ChangeMark<Self>>(self) -> M::Out {
        M::change_mark(self)
    }
}

impl<Y: YChoice> XOnly<Y> {
    pub fn to_point(&self) -> Point<Y, Public, NonZero> {
        Y::xonly_into_point(self.clone())
    }

    pub fn from_scalar_mul<GT>(G: &Point<GT>, x: &mut Scalar<impl Secrecy>) -> Self {
        let X = crate::op::scalar_mul_point(x, G).mark::<Normal>();
        let needs_negation = !Y::norm_point_matches(&X);
        x.conditional_negate(needs_negation);
        X.to_xonly().mark::<Y>()
    }
}

impl<Y> HashInto for XOnly<Y> {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.input(self.as_bytes())
    }
}

impl<Y> PartialEq<XOnly<Y>> for XOnly<Y> {
    fn eq(&self, rhs: &XOnly<Y>) -> bool {
        // XOnly should have secrecy too so we can do it in vartime if public
        crate::backend::ConstantTime::xonly_eq(&self.0, &rhs.0)
    }
}

impl<T, Z, S> PartialEq<XOnly<SquareY>> for Point<T, S, Z> {
    fn eq(&self, rhs: &XOnly<SquareY>) -> bool {
        crate::op::EqXOnlySquareY::eq_xonly_square_y(self, rhs)
    }
}

impl<T, Z, S> PartialEq<Point<T, S, Z>> for XOnly<SquareY> {
    fn eq(&self, rhs: &Point<T, S, Z>) -> bool {
        rhs == self
    }
}

crate::impl_fromstr_deserailize! {
    name => "secp256k1 x-coordinate",
    fn from_bytes<Y>(bytes: [u8;32]) -> Option<XOnly<Y>> {
        XOnly::from_bytes(bytes)
    }
}

crate::impl_display_debug_serialize! {
    fn to_bytes<Y>(xonly: &XOnly<Y>) -> &[u8;32] {
        xonly.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    crate::test_plus_wasm! {
        fn xonly_random() {
            let _ = XOnly::<()>::random(&mut rand::thread_rng());
        }

        fn from_str() {
            use crate::G;
            use core::str::FromStr;

            assert_eq!(
                XOnly::<EvenY>::from_str(
                    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                )
                    .unwrap()
                    .to_point(),
                *G
            );
        }

        fn xonly_to_point() {
            for _ in 0..crate::TEST_SOUNDNESS {
                let xonly_even = XOnly::<EvenY>::random(&mut rand::thread_rng());
                let xonly_square = XOnly::<SquareY>::random(&mut rand::thread_rng());

                let point_even = xonly_even.to_point();
                assert!(EvenY::norm_point_matches(&point_even));

                let point_square = xonly_square.to_point();
                assert!(SquareY::norm_point_matches(&point_square));
            }
        }
    }
}
