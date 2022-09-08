use crate::{
    backend::{self, BackendPoint, TimeSensitive},
    hash::HashInto,
    marker::*,
    op, Scalar, XOnly,
};
use core::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};

/// A point on the secp256k1 elliptic curve.
///
/// A `Point<T,S,Z>` marked with `Z = NonZero` is any two integers modulo `p` `(x,y)`  that satisfy:
///
/// `y^2 = 3*x + 7 mod p`
///
/// where `p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`.
/// For every valid x-coordinate, there will be exactly two valid y-coordinates which will be the negation modulo p of each other.
///
/// If the point is marked `Z = Zero` then it may also be _point at infinity_ which is the [_identity element_] of the group.
///
/// ## Markers
///
/// A `Point<T,S,Z>` has three types parameters.
///
/// - `T`: A [`PointType`] used to reason about what the point can do and to specialize point operations.
/// - `S`: A [`Secrecy`] to determine whether operations on this point should be done in constant-time or not. By default points are [`Public`] so operations run in variable time.
/// - `Z`: A [`ZeroChoice`] to keep track of whether the point might be zero (the point at infinity) or is guaranteed to be non-zero.
///
/// # Serialization
///
/// Only points that are normalized (i.e. `T` ≠ `Jacobian`) can be serialized. A Point that is
/// `EvenY` serializes to and from the 32-byte x-only representation like the [`XOnly`] type.
/// `Normal` points serialize to and from the standard 33-byte representation specified in
/// [_Standards for Efficient Cryptography_] (the same as [`Point::to_bytes`]). Points that are
/// marked as `Zero` will serialize to `[0u8;33]`.
///
///
/// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
/// [`Point::to_bytes`]: crate::Point::to_bytes
/// [`PointType`]: crate::marker::PointType
/// [`Secrecy`]: crate::marker::Secrecy
/// [`XOnly`]: crate::XOnly
/// [`ZeroChoice`]: crate::marker::ZeroChoice
/// [`Public`]: crate::marker::Public
/// [_identity element_]: https://en.wikipedia.org/wiki/Identity_element
#[derive(Default)]
pub struct Point<T = Normal, S = Public, Z = NonZero>(
    pub(crate) backend::Point,
    pub(crate) T,
    PhantomData<(Z, S)>,
);

impl<Z, S, T: Clone> Clone for Point<T, S, Z> {
    fn clone(&self) -> Self {
        Point::from_inner(self.0.clone(), self.1.clone())
    }
}

impl<T: Copy, Z: Copy> Copy for Point<T, Public, Z> {}

impl Point<Normal, Public, NonZero> {
    /// Samples a point uniformly from the group.
    ///
    /// # Examples
    ///
    /// Generate a random point from `thread_rng`.
    /// ```
    /// # use secp256kfun::Point;
    /// let random_point = Point::random(&mut rand::thread_rng());
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 33];
        rng.fill_bytes(&mut bytes[..]);
        bytes[0] &= 0x01;
        bytes[0] |= 0x02;
        Self::from_bytes(bytes).unwrap_or_else(|| Self::random(rng))
    }

    /// Creates a Point from a 65-byte uncompressed encoding specified in
    /// [_Standards for Efficient Cryptography_].  The first byte must be
    /// `0x04`.  The remaining 64 bytes must encode a valid x and y coordinate
    /// on the curve. If the conditions are not met then it will return `None`.
    ///
    /// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
    pub fn from_bytes_uncompressed(bytes: [u8; 65]) -> Option<Self> {
        if bytes[0] != 0x04 {
            return None;
        }
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&bytes[1..33]);
        y.copy_from_slice(&bytes[33..65]);
        backend::Point::norm_from_coordinates(x, y).map(|p| Point::from_inner(p, Normal))
    }
}

impl<Z: ZeroChoice> Point<Normal, Public, Z> {
    /// Creates a Point the compressed encoding specified in [_Standards for
    /// Efficient Cryptography_]. This is the typical encoding used in
    /// Bitcoin. The first byte must be `0x02` or `0x03` to indicate that the
    /// y-coordinate is even or odd respectively.  The remaining 32 bytes must
    /// encode an x-coordinate on the curve.  If these conditions are not then
    /// it will return `None`.
    ///
    /// # Examples
    /// ```
    /// use secp256kfun::{marker::*, Point, G};
    /// let bytes = [
    ///     2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252,
    ///     219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
    /// ];
    /// let point = Point::<_, Public, NonZero>::from_bytes(bytes).unwrap();
    /// assert_eq!(point, *G);
    /// ```
    ///
    /// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
    pub fn from_bytes(bytes: [u8; 33]) -> Option<Self> {
        if Z::is_zero() && bytes == [0u8; 33] {
            return Some(Point::from_inner(backend::Point::zero(), Normal));
        }
        let y_odd = match bytes[0] {
            2 => false,
            3 => true,
            _ => return None,
        };

        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..]);

        backend::Point::norm_from_bytes_y_oddness(x_bytes, y_odd)
            .map(|p| Point::from_inner(p, Normal))
    }

    /// Convenience method for calling [`from_bytes`] wth a slice.
    /// Returns None if [`from_bytes`] would or if `slice` is not 33 bytes long.
    ///
    /// [`from_bytes`]: Self::from_bytes
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 33 {
            return None;
        }
        let mut bytes = [0u8; 33];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }
}

impl<T, S> Point<T, S, NonZero> {
    /// Converts this point into the point with the same x-coordinate but with
    /// an even y-coordinate. Returns a Point marked `EvenY` with a `bool`
    /// indicating whether the point had to be negated to make its y-coordinate
    /// even.
    ///
    /// # Examples
    /// ```
    /// use secp256kfun::{marker::*, Point};
    /// let point = Point::random(&mut rand::thread_rng());
    /// let (point_with_even_y, was_odd) = point.clone().into_point_with_even_y();
    /// ```
    pub fn into_point_with_even_y(self) -> (Point<EvenY, S, NonZero>, bool) {
        let normalized = self.mark::<Normal>();
        let needs_negation = !normalized.is_y_even();
        let negated = normalized.conditional_negate(needs_negation);
        (Point::from_inner(negated.0, EvenY), needs_negation)
    }
}

impl Point<EvenY, Public, NonZero> {
    /// Multiplies `base` by `scalar` and returns the resulting point. If the
    /// resulting point does not have an even y-coordinate then the scalar and
    /// point are negated so the point has an even y-coordinate and the scalar
    /// matches it.
    ///
    /// # Examples
    ///
    /// ```
    /// use secp256kfun::{marker::*, Point, Scalar, G};
    /// let mut secret_key = Scalar::random(&mut rand::thread_rng());
    /// let public_key = Point::<EvenY>::from_scalar_mul(G, &mut secret_key);
    /// assert!(public_key.is_y_even());
    /// ```
    pub fn from_scalar_mul(
        base: &Point<impl PointType, impl Secrecy>,
        scalar: &mut Scalar<impl Secrecy>,
    ) -> Self {
        let point = crate::op::scalar_mul_point(scalar, base).mark::<Normal>();
        let (point, needs_negation) = point.into_point_with_even_y();
        scalar.conditional_negate(needs_negation);
        point
    }
}

impl<T, S, Z> Point<T, S, Z> {
    /// Returns true if this point the [`identity element`] of the group A.K.A. the point at infinity.
    ///
    /// [`identity_element`]: https://en.wikipedia.org/wiki/Identity_element
    ///
    /// # Examples
    /// ```
    /// # use secp256kfun::{ Point, g};
    /// let point = Point::random(&mut rand::thread_rng());
    /// assert!(!point.is_zero());
    /// assert!(g!(0 * point).is_zero());
    /// ```
    pub fn is_zero(&self) -> bool {
        backend::BackendPoint::is_zero(&self.0)
    }

    pub(crate) const fn from_inner(backend_point: backend::Point, point_type: T) -> Self {
        Point(backend_point, point_type, PhantomData)
    }

    /// Negates a point based on a condition.
    /// If `cond` is true the value returned is the negation of the point, otherwise it will be the point.
    #[must_use]
    pub fn conditional_negate(&self, cond: bool) -> Point<T::NegationType, S, Z>
    where
        T: PointType,
    {
        op::point_conditional_negate(&self.clone(), cond)
    }

    /// A hack that is necessary when writing deserialization code until rust issue [#44491] is fixed.
    /// Don't use this method use [`mark`] which checks the type is a valid secrecy.
    ///
    /// [`mark`]: crate::marker::Mark::mark
    /// [#44491]: https://github.com/rust-lang/rust/issues/44491
    pub fn set_secrecy<SNew>(self) -> Point<T, SNew, Z> {
        Point::from_inner(self.0, self.1)
    }
}

impl Point<Normal, Public, Zero> {
    /// Returns the [`identity element`] of the group A.K.A. the point at infinity.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{g, Point, G};
    /// assert!(Point::zero().is_zero());
    /// assert_eq!(g!({ Point::zero() } + G), *G);
    /// ```
    /// [`identity_element`]: https://en.wikipedia.org/wiki/Identity_element
    pub fn zero() -> Self {
        Self::from_inner(backend::Point::zero(), Normal)
    }
}

impl<T, S> Point<T, S, Zero> {
    /// Converts a point marked with `Zero` to one that is marked `NonZero`.
    /// You must provide a justification for this as the `reason`.
    /// **If you're wrong the method will panic with the reason**.
    ///
    /// This is shorthand for:
    ///
    /// ```ignore
    /// use secp256kfun::marker::*;
    /// point.mark::<NonZero>().expect(reason);
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{g, G};
    /// let two_g = g!(G + G).expect_nonzero("2 * G is not zero");
    /// ```
    pub fn expect_nonzero(self, reason: &str) -> Point<T, S, NonZero> {
        self.mark::<NonZero>().expect(reason)
    }
}

impl<Z, T> Point<T, Public, Z> {
    /// Checks if this point's x-coordiante is the equal to the scalar mod the
    /// curve order. This is only useful for ECDSA implementations.
    pub fn x_eq_scalar<Z2>(&self, scalar: &Scalar<Public, Z2>) -> bool {
        crate::backend::VariableTime::point_x_eq_scalar(&self.0, &scalar.0)
    }
}

impl<S, Z> Point<Jacobian, S, Z> {
    /// Normalize a point.
    ///
    /// Shorthand for calling [`.mark::<Normal>()`](crate::marker::Mark::mark).
    pub fn normalize(self) -> Point<Normal, S, Z> {
        self.mark::<Normal>()
    }
}

impl<T: PointType, S, Z> core::ops::Neg for Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        op::point_negate(&self)
    }
}

impl<T: PointType, S, Z> core::ops::Neg for &Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        op::point_negate(self)
    }
}

impl<T1, S1, Z1, T2, S2, Z2> PartialEq<Point<T2, S2, Z2>> for Point<T1, S1, Z1> {
    fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool {
        op::point_eq(self, rhs)
    }
}

impl<T, S, Z> Eq for Point<T, S, Z> {}

impl core::hash::Hash for Point<Normal, Public, NonZero> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl core::hash::Hash for Point<EvenY, Public, NonZero> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_xonly_bytes().hash(state)
    }
}

impl<S, Z, T: Normalized> Point<T, S, Z> {
    /// Converts the point to its compressed encoding as specified by [_Standards for Efficient Cryptography_].
    ///
    /// # Example
    /// Round trip serialization with [`from_bytes`]
    /// ```
    /// use secp256kfun::{marker::*, Point};
    /// let point = Point::random(&mut rand::thread_rng());
    /// let bytes = point.to_bytes();
    /// assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    /// assert_eq!(Point::<_, _, NonZero>::from_bytes(bytes).unwrap(), point);
    /// ```
    ///
    /// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
    /// [`from_bytes`]: crate::Point::from_bytes
    pub fn to_bytes(&self) -> [u8; 33] {
        if self.is_zero() {
            [0u8; 33]
        } else {
            let (x, y) = backend::BackendPoint::norm_to_coordinates(&self.0);
            coords_to_bytes(x, y)
        }
    }
}

impl<S> Point<EvenY, S, NonZero> {
    /// Creates a point with `EvenY` from 32 byte x-coordinate
    pub fn from_xonly_bytes(bytes: [u8; 32]) -> Option<Self> {
        backend::Point::norm_from_bytes_y_oddness(bytes, false)
            .map(|point| Point::from_inner(point, EvenY))
    }
}

impl<S> Point<Normal, S, NonZero> {}

impl<S, T: Normalized> Point<T, S, NonZero> {
    /// Returns the x and y coordinates of the point as two 32-byte arrays containing their big endian encoding.
    ///
    /// # Example
    ///
    /// ```
    /// # use secp256kfun::Point;
    /// let point = Point::random(&mut rand::thread_rng());
    /// let (x_coord, y_coord) = point.coordinates();
    pub fn coordinates(&self) -> ([u8; 32], [u8; 32]) {
        backend::BackendPoint::norm_to_coordinates(&self.0)
    }

    /// Converts a point to an `XOnly` (i.e. just its x-coordinate).
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{marker::*, Point};
    /// let (point_even_y, _) = Point::random(&mut rand::thread_rng()).into_point_with_even_y();
    /// let xonly = point_even_y.to_xonly();
    /// assert_eq!(xonly.to_point(), point_even_y);
    /// ```
    pub fn to_xonly(&self) -> XOnly {
        XOnly::from_inner(backend::BackendPoint::norm_to_xonly(&self.0))
    }

    /// Returns whether the point has an even y-coordinate
    pub fn is_y_even(&self) -> bool {
        op::point_is_y_even(self)
    }

    /// Serializes a point with `EvenY` to its 32-byte x-coordinate
    pub fn to_xonly_bytes(&self) -> [u8; 32] {
        self.to_xonly().into_bytes()
    }

    /// Encodes a point as its compressed encoding as specified by [_Standards for Efficient Cryptography_].
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{marker::*, Point};
    /// let point = Point::random(&mut rand::thread_rng());
    /// let bytes = point.to_bytes_uncompressed();
    /// assert_eq!(Point::from_bytes_uncompressed(bytes).unwrap(), point);
    /// ```
    /// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
    pub fn to_bytes_uncompressed(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        let (x, y) = backend::BackendPoint::norm_to_coordinates(&self.0);
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(x.as_ref());
        bytes[33..65].copy_from_slice(y.as_ref());
        bytes
    }
}

impl<S> HashInto for Point<Normal, S, NonZero> {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(self.to_bytes().as_ref())
    }
}

impl<S> HashInto for Point<EvenY, S, NonZero> {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(self.to_xonly_bytes().as_ref())
    }
}

impl<T: Default, S, Z> subtle::ConditionallySelectable for Point<T, S, Z>
where
    Self: Copy,
{
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        Point::from_inner(
            backend::Point::conditional_select(&a.0, &b.0, choice),
            T::default(),
        )
    }
}

fn coords_to_bytes(x: [u8; 32], y: [u8; 32]) -> [u8; 33] {
    let mut bytes = [0u8; 33];
    bytes[0] = y[31] & 0x01;
    bytes[0] |= 0x02;
    bytes[1..].copy_from_slice(&x[..]);
    bytes
}

crate::impl_debug! {
    fn to_bytes<T, S,Z>(point: &Point<T, S, Z>) -> Result<[u8;33], &str> {
        let mut p = point.0.clone();
        backend::VariableTime::point_normalize(&mut p);
        let p: Point<Normal, S, Z> = Point::from_inner(p, Normal);
        Ok(p.to_bytes())
    }
}

crate::impl_display_serialize! {
    fn to_bytes<S, Z>(point: &Point<Normal, S, Z>) -> [u8;33] {
        point.to_bytes()
    }
}

crate::impl_display_serialize! {
    fn to_bytes<S>(point: &Point<EvenY, S, NonZero>) -> [u8;32] {
        point.to_xonly().as_bytes().clone()
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 32-byte x-coordinate",
    fn from_bytes<S>(bytes: [u8;32]) -> Option<Point<EvenY,S, NonZero>> {
        Point::from_xonly_bytes(bytes).map(|p| p.set_secrecy::<S>())
    }
}

crate::impl_fromstr_deserialize! {
    name => "33-byte encoded secp256k1 point",
    fn from_bytes<S,Z: ZeroChoice>(bytes: [u8;33]) -> Option<Point<Normal,S, Z>> {
        Point::from_bytes(bytes).map(|p| p.set_secrecy::<S>())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{g, G};
    use proptest::prelude::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    macro_rules! expression_eq {
        ([$($lhs:tt)*] == [$($rhs:tt)*]) => {{
            use core::borrow::Borrow;
            assert_eq!(g!($($lhs)*).borrow(),g!($($rhs)*).borrow(), stringify!($($lhs)* == $($rhs)*))
        }};
        ([$($lhs:tt)*] != [$($rhs:tt)*]) => {{
            use core::borrow::Borrow;
            assert_ne!(g!($($lhs)*).borrow(),g!($($rhs)*).borrow(), stringify!($($lhs)* != $($rhs)*))
        }};
    }

    macro_rules! operations_test {
        (@binary $P:expr, $Q:expr) => {{
            let p = $P;
            let q = $Q;
            let i = Point::zero();
            expression_eq!([p] == [q]);
            expression_eq!([q] == [p]);
            expression_eq!([1 * p] == [q]);
            expression_eq!([-1 * p] == [-q]);
            expression_eq!([p - q] == [i]);
            expression_eq!([i + p] == [q]);


            if !p.is_zero() {
                expression_eq!([p] != [i]);
                expression_eq!([p + p] != [p]);
            }

            expression_eq!([-(p + p)] == [-q + -q]);
            expression_eq!([p + p] == [2 * q]);
            expression_eq!([p + q] == [2 * q]);
            expression_eq!([q + p] == [2 * q]);
            expression_eq!([p + p + p] == [3 * q]);
            expression_eq!([-p - p - p] == [-3 * q]);
            expression_eq!([42 * p + 1337 * p] == [1379 * q]);
            expression_eq!([42 * p - 1337 * p] == [-1295 * q]);
            let add_100_times = {
                let p = p.clone().mark::<(Zero, Jacobian)>();
                let i = g!(p - p);
                assert_eq!(i, Point::zero());
                (0..100).fold(i, |acc, _| g!(acc + p))
            };

            expression_eq!([add_100_times] == [100 * q]);
            let undo = { (0..100).fold(add_100_times.clone(), |acc, _| g!(acc - p)) };
            expression_eq!([undo] == [add_100_times - 100 * q]);
            expression_eq!([undo] == [i]);
        }};
        ($P:expr) => {{
            let p = $P;
            let i = Point::zero();

            expression_eq!([p] == [p]);
            expression_eq!([p + i] == [p]);
            expression_eq!([i - p] == [-p]);
            expression_eq!([p - i] == [p]);
            expression_eq!([0 * p] == [i]);

            let q = p.clone().mark::<(Normal, Public)>();
            operations_test!(@binary p,q);
            let q = p.clone().mark::<(Jacobian, Public)>();
            operations_test!(@binary p,q);
            let q = p.clone().mark::<(Normal, Secret)>();
            operations_test!(@binary p,q);
            let q = p.clone().mark::<(Jacobian, Secret)>();
            operations_test!(@binary p,q);
        }}
    }

    proptest! {
        #[test]
        fn operations_even_y(P in any::<Point<EvenY>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_normal(P in any::<Point<Normal>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian(P in any::<Point<Jacobian>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_normal_secret(P in any::<Point<Normal, Secret>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian_secret(P in any::<Point<Jacobian, Secret>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_normal_public_zero(P in any::<Point<Normal, Public, Zero>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_normal_secret_zero(P in any::<Point<Normal, Secret, Zero>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian_public_zero(P in any::<Point<Jacobian, Public, Zero>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian_secret_zero(P in any::<Point<Jacobian, Secret, Zero>>()) {
            operations_test!(&P);
        }

        #[cfg(feature = "serde")]
        #[test]
        fn point_even_y_json_deserialization_roundtrip(point in any::<Point<Normal, Public, Zero>>()) {
            let string = serde_json::to_string(&point).unwrap();
            let deser_point: Point<Normal, Public, Zero> = serde_json::from_str(&string).unwrap();
            assert_eq!(point, deser_point);
        }
    }

    #[test]
    fn g_to_and_from_bytes() {
        use core::str::FromStr;
        assert_eq!(
            (*G).mark::<Normal>().to_bytes_uncompressed(),
            crate::hex::decode_array("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap(),
            "G.to_bytes_uncompressed()"
        );

        assert_eq!(
            Point::from_bytes_uncompressed((*G).mark::<Normal>().to_bytes_uncompressed()).unwrap(),
            *G
        );

        assert_eq!(
            (*G).mark::<Normal>().to_bytes(),
            crate::hex::decode_array(
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )
            .unwrap(),
            "G.to_bytes()"
        );

        assert_eq!(
            &Point::<_, Public>::from_bytes(
                crate::hex::decode_array(
                    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                )
                .unwrap()
            )
            .unwrap(),
            G
        );

        assert_eq!(
            &Point::<_, Public>::from_bytes(
                crate::hex::decode_array(
                    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                )
                .unwrap()
            )
            .unwrap(),
            &Point::<Normal, Secret>::from_str(
                "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )
            .unwrap(),
        );

        let neg_g = -G;

        assert_eq!(
            neg_g.to_bytes_uncompressed(),
            // raku -e 'say (-0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 mod 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F).base(16).comb().batch(8).map(*.join).join(" ")'
            crate::hex::decode_array(
                "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798B7C52588D95C3B9AA25B0403F1EEF75702E84BB7597AABE663B82F6F04EF2777"
            ).unwrap(),
            "-G.to_bytes_uncompressed()"
        );
        assert_eq!(
            neg_g.to_bytes(),
            crate::hex::decode_array(
                "0379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
            )
            .unwrap(),
            "-G.to_bytes()"
        );
    }

    #[test]
    fn zero_to_and_from_bytes() {
        let zero = Point::zero();
        assert_eq!(Point::<_, _, Zero>::from_bytes(zero.to_bytes()), Some(zero));
    }

    #[test]
    fn zero_cases() {
        use crate::s;
        let i = Point::zero();
        let forty_two = s!(42);
        let forty_two_pub = s!(42).mark::<Public>();
        assert!(i.is_zero());
        expression_eq!([i] == [i]);
        expression_eq!([i] == [-i]);
        expression_eq!([i + i] == [i]);
        expression_eq!([i - i] == [i]);
        // see: https://github.com/LLFourn/secp256kfun/issues/13
        expression_eq!([forty_two * i] == [i]);
        expression_eq!([forty_two_pub * i] == [i]);
        expression_eq!([forty_two * G + forty_two * i] == [forty_two * G]);
        expression_eq!([forty_two_pub * G + forty_two_pub * i] == [forty_two_pub * G]);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn fmt_debug() {
        let random_point = Point::random(&mut rand::thread_rng());
        assert!(format!("{:?}", random_point).starts_with("Point<Normal,Public,NonZero>"));
        let mult_point = g!({ Scalar::random(&mut rand::thread_rng()) } * G);
        assert!(format!("{:?}", mult_point).starts_with("Point<Jacobian,Public,NonZero>"));
    }
}
