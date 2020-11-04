use crate::{
    backend::{self, BackendXOnly, TimeSensitive},
    hash::HashInto,
    marker::*,
    Point, Scalar,
};
use rand_core::{CryptoRng, RngCore};

/// An `XOnly` is the compressed representation of a [`Point<EvenY,S,Z>`] which
/// only stores the x-coordinate of the point.
///
/// Using a `Point<EvenY,..>` is usually the right choice as it serializes the
/// same way and can do everything an `XOnly` can do and more. `XOnly` exists
/// because sometimes all you need is the x-coordinate and you don't want to
/// store the full point in memory.
///
/// [`Point<T,S,Z>`]: crate::Point
#[derive(Clone, Copy, Eq, Hash)]
pub struct XOnly(pub(crate) backend::XOnly);

impl XOnly {
    /// Converts a 32-byte big-endian encoded x-coordinate into an
    /// `XOnly`. Returns `None` if the bytes do not represent a valid
    /// x-coordinate on the curve.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, XOnly};
    /// // note: x = 1 is on the curve.
    /// // choose the even y-corrdinate when decompressing
    /// assert!(XOnly::from_bytes([1u8; 32]).is_some());
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        backend::XOnly::from_bytes(bytes).map(Self::from_inner)
    }

    /// Convenience method for calling [`from_bytes`] on a slice. Returns `None`
    /// if the length of the slice is not 32.
    ///
    /// [`from_bytes`]: crate::XOnly::from_bytes
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }

    pub(crate) fn from_inner(inner: backend::XOnly) -> Self {
        XOnly(inner)
    }

    /// Generates a random valid `XOnly` from a random number generator.
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, XOnly};
    /// let random_x_coordinate = XOnly::random(&mut rand::thread_rng());
    /// ```
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes).unwrap_or_else(|| Self::random(rng))
    }

    /// Returns a reference to the internal 32-byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Converts an `XOnly` into a 32-byte array.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }
}

impl XOnly {
    /// Decompresses a `XOnly` into a [`Point<EvenY,Public,NonZero>`].
    /// The resulting point will have an even y-coordinate.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, XOnly};
    /// let xonly = XOnly::random(&mut rand::thread_rng());
    /// // get the point with a even y-coordinate
    /// let point_even_y = xonly.to_point();
    /// ```
    pub fn to_point(&self) -> Point<EvenY, Public, NonZero> {
        Point::from_inner(BackendXOnly::into_norm_point_even_y(self.0.clone()), EvenY)
    }

    /// Multiplies `G` by `x` and then compresses the point to an `XOnly`.
    /// `x` is mutable because it will be negated if, after the
    /// multiplication, the resulting point doesn't match `Y` (negating it
    /// ensures that it does).
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, Scalar, XOnly, G};
    /// use std::str::FromStr;
    /// let original = Scalar::<Secret>::from_str(
    ///     "ee673d13de31533a375b41d9e57731d9bb4dbddbd6c1d2364f15be40fd783346",
    /// )
    /// .unwrap();
    /// let mut secret_key = original.clone();
    /// let xonly_public_key = XOnly::from_scalar_mul(G, &mut secret_key);
    /// assert_ne!(secret_key, original);
    /// assert_eq!(-secret_key, original);
    /// ```
    // This GT can't be an impl PointType yet because of https://github.com/rust-lang/rust/issues/44491
    pub fn from_scalar_mul<GT>(G: &Point<GT>, x: &mut Scalar<impl Secrecy>) -> Self {
        let X = crate::op::scalar_mul_point(x, G).mark::<Normal>();
        let needs_negation = !X.is_y_even();
        x.conditional_negate(needs_negation);
        X.to_xonly()
    }
}

impl HashInto for XOnly {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.update(self.as_bytes())
    }
}

impl PartialEq<XOnly> for XOnly {
    fn eq(&self, rhs: &XOnly) -> bool {
        // XOnly should have secrecy too so we can do it in vartime if public
        crate::backend::ConstantTime::xonly_eq(&self.0, &rhs.0)
    }
}

impl<T, Z, S> PartialEq<XOnly> for Point<T, S, Z> {
    fn eq(&self, rhs: &XOnly) -> bool {
        crate::op::PointEqXOnly::point_eq_xonly(self, rhs)
    }
}

impl From<XOnly> for Point<EvenY, Public, NonZero> {
    fn from(xonly: XOnly) -> Self {
        Point::from_inner(BackendXOnly::into_norm_point_even_y(xonly.0), EvenY)
    }
}

impl<T, Z, S> PartialEq<Point<T, S, Z>> for XOnly {
    fn eq(&self, rhs: &Point<T, S, Z>) -> bool {
        rhs == self
    }
}

crate::impl_fromstr_deserailize! {
    name => "secp256k1 x-coordinate",
    fn from_bytes(bytes: [u8;32]) -> Option<XOnly> {
        XOnly::from_bytes(bytes)
    }
}

crate::impl_display_debug_serialize! {
    fn to_bytes(xonly: &XOnly) -> &[u8;32] {
        xonly.as_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    crate::test_plus_wasm! {
        fn xonly_random() {
            let _ = XOnly::random(&mut rand::thread_rng());
        }

        fn from_str() {
            use crate::G;
            use core::str::FromStr;

            assert_eq!(
                XOnly::from_str(
                    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
                )
                    .unwrap()
                    .to_point(),
                *G
            );
        }

        fn xonly_to_point() {
            for _ in 0..crate::TEST_SOUNDNESS {
                let xonly_even = XOnly::random(&mut rand::thread_rng());

                let point_even = xonly_even.to_point();
                assert!(point_even.is_y_even());
            }
        }
    }
}
