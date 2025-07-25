use crate::{
    Scalar,
    backend::{self, BackendPoint, TimeSensitive},
    hash::{Hash32, HashInto},
    marker::*,
    op,
};
use core::{
    marker::PhantomData,
    ops::{AddAssign, SubAssign},
};
use rand_core::RngCore;

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
/// ## Serialization
///
/// Only points that are normalized (i.e. `T` ≠ `NonNormal`) can be serialized. A Point that is
/// `EvenY` points serialize to and from their 32-byte x-only representation.
/// `Normal` points serialize to and from the standard 33-byte representation specified in
/// [_Standards for Efficient Cryptography_] (the same as [`Point::to_bytes`]). Points that are
/// are zero (see [`is_zero`]) will serialize to `[0u8;33]`.
///
///
/// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
/// [`Point::to_bytes`]: crate::Point::to_bytes
/// [`PointType`]: crate::marker::PointType
/// [`Secrecy`]: crate::marker::Secrecy
/// [`ZeroChoice`]: crate::marker::ZeroChoice
/// [`Public`]: crate::marker::Public
/// [`is_zero`]: crate::Point::is_zero
/// [_identity element_]: https://en.wikipedia.org/wiki/Identity_element
pub struct Point<T = Normal, S = Public, Z = NonZero>(
    pub(crate) backend::Point,
    pub(crate) T,
    PhantomData<(Z, S)>,
);

/// The default for `Point`<_,_,Zero>` is [`Point::zero`].
impl<T: Default, S> Default for Point<T, S, Zero> {
    fn default() -> Self {
        Point::zero()
    }
}

/// The default for `Point`<_,_,Zero>` is [`Point::generator`].
impl<T: Default + PointType, S> Default for Point<T, S, NonZero> {
    fn default() -> Self {
        Point::generator()
    }
}

impl<Z, S, T: Clone> Clone for Point<T, S, Z> {
    fn clone(&self) -> Self {
        Point::from_inner(self.0, self.1.clone())
    }
}

impl<T, S, Z> AsRef<backend::Point> for Point<T, S, Z> {
    fn as_ref(&self) -> &backend::Point {
        &self.0
    }
}

impl<T: Copy, S, Z> Copy for Point<T, S, Z> {}

impl Point<Normal, Public, NonZero> {
    /// Samples a point uniformly from the group.
    ///
    /// # Examples
    ///
    /// Generate a random point from `thread_rng`.
    /// ```
    /// # use secp256kfun::Point;
    /// let random_point = Point::random(&mut rand::thread_rng());
    pub fn random(rng: &mut impl RngCore) -> Self {
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

    /// Hash to curve implementation following [RFC 9380]
    ///
    /// Maps arbitrary byte strings to points on the secp256k1 curve in a way that is
    /// indifferentiable from a random oracle. This implementation uses the
    /// simplified SWU method with a 3-isogeny mapping as specified in
    /// [RFC 9380](https://datatracker.ietf.org/doc/rfc9380/).
    ///
    /// ## When to use this method
    ///
    /// The [RFC 9380] method provides constant-time hashing regardless of input, which
    /// can be important for denial of service resistance. With try-and-increment
    /// methods (like [`hash_to_curve`] and [`hash_to_curve_rfc9381_tai`]), an
    /// attacker can craft inputs that require more iterations (up to ~30x in practice),
    /// potentially creating a DoS vector. See [this paper](https://eprint.iacr.org/2019/383)
    /// for analysis.
    ///
    /// However, in most applications this is not a practical concern because:
    /// - Hash-to-curve typically represents a small fraction of total computation
    /// - The maximum slowdown is bounded and relatively modest
    /// - Creating adversarial inputs requires significant computational resources
    ///
    /// **For most use cases, prefer [`hash_to_curve`]** which is simpler and faster.
    /// Only use this method if you have specific DoS concerns and hash-to-curve
    /// represents a significant portion of your protocol's computation.
    ///
    /// **HAZMAT WARNING**: It is this author's opinion that [RFC 9380] is overwrought for
    /// secp256k1. While this implementation passes test vectors from the
    /// [`k256`](https://github.com/RustCrypto/elliptic-curves/tree/master/k256) crate (see their [test vectors](https://github.com/RustCrypto/elliptic-curves/blob/3381a99b6412ef9fa556e32a834e401d569007e3/k256/src/arithmetic/hash2curve.rs#L296)),
    /// the complexity of the SSWU algorithm makes me hesitant to recommend its use.
    /// The simpler try-and-increment method in [`hash_to_curve`] is preferred.
    ///
    /// # Parameters
    /// - `msg`: The message to hash
    /// - `dst`: Domain separation tag (DST), should be unique per application
    ///
    /// # Example
    /// ```
    /// # use secp256kfun::{Point, hash};
    /// # use sha2::Sha256;
    /// let point = Point::hash_to_curve_sswu::<Sha256>(b"hello world", b"myapp-v1");
    /// ```
    ///
    /// [`hash_to_curve`]: Self::hash_to_curve
    /// [`hash_to_curve_rfc9381_tai`]: Self::hash_to_curve_rfc9381_tai
    /// [RFC 9380]: https://datatracker.ietf.org/doc/html/rfc9380
    pub fn hash_to_curve_sswu<H>(msg: &[u8], dst: &[u8]) -> Point<NonNormal, Public, NonZero>
    where
        H: crate::hash::Hash32 + crate::digest::crypto_common::BlockSizeUser,
    {
        let backend_point = backend::Point::hash_to_curve::<H>(msg, dst);
        Point::from_inner(backend_point, NonNormal)
    }

    /// Hash to curve using try-and-increment method
    ///
    /// This is a simple and efficient method to hash arbitrary byte strings to curve points
    /// with uniform distribution. It works by hashing the input with an incrementing counter
    /// until a valid curve point is found.
    ///
    /// **This is the recommended method for most applications.** While it has variable
    /// runtime based on input (see [`hash_to_curve_sswu`] for details), this is rarely
    /// a practical concern.
    ///
    /// ## Why not the [RFC 9381] try-and-increment?
    ///
    /// The VRF specification ([RFC 9381 §5.4.1.1](https://datatracker.ietf.org/doc/html/rfc9381#section-5.4.1.1))
    /// includes a try-and-increment method (see [`hash_to_curve_rfc9381_tai`]) that always
    /// uses a fixed y-coordinate parity (0x02). This results in a non-uniform distribution
    /// that only includes points with even y-coordinates. Our implementation achieves
    /// uniform distribution with a simple modification.
    ///
    /// [`hash_to_curve_rfc9381_tai`]: Self::hash_to_curve_rfc9381_tai
    ///
    /// # Example
    /// ```
    /// # use secp256kfun::{Point, hash::{Hash32, HashAdd}};
    /// # use sha2::Sha256;
    /// let hasher = Sha256::default().add(b"hello world");
    /// let point = Point::hash_to_curve(hasher);
    /// ```
    ///
    /// [`hash_to_curve_sswu`]: Self::hash_to_curve_sswu
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381
    pub fn hash_to_curve<H: Hash32>(hasher: H) -> Point<Normal, Public, NonZero> {
        use crate::hash::HashAdd;

        // Try up to 255 times (probability of failure is negligible)
        for counter in 0u8..u8::MAX {
            let hash_bytes = hasher.clone().add(counter).finalize_fixed();

            // Use 0x02 (even y) when counter==0, 0x03 (odd y) when counter>0
            // This ensures uniform distribution over all curve points because there is
            // a roughly 50% chance that counter will be 0 when we succeed, and this
            // probability is independent of the x coordinate distribution
            let mut bytes = [0u8; 33];
            bytes[0] = 0x02 + (counter > 0) as u8;
            bytes[1..].copy_from_slice(&hash_bytes);

            if let Some(point) = Point::<Normal, Public, NonZero>::from_bytes(bytes) {
                return point;
            }
        }

        // This should never happen (probability ~ 2^-128)
        unreachable!("Failed to find valid point after 128 attempts")
    }

    /// Hash to curve using [RFC 9381] try-and-increment format
    ///
    /// This implements a hash-to-curve method following [RFC 9381]'s try-and-increment
    /// algorithm as used in SECP256K1_SHA256_TAI. Note that SECP256K1_SHA256_TAI is not
    /// defined in the RFC itself, but is a ciphersuite adopted by various VRF implementations.
    ///
    /// This method always produces points with even y-coordinates (0x02 prefix) which means it's
    /// not quite uniform (but this is not a security problem in any reasonable protocol)
    ///
    /// Like other try-and-increment methods, this has variable runtime based on input.
    /// See [`hash_to_curve_sswu`] for discussion of DoS considerations.
    ///
    /// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381#section-5.4.1.1
    ///
    /// # Example
    /// ```
    /// # use secp256kfun::Point;
    /// # use sha2::Sha256;
    /// let point = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"hello world", b"my-salt");
    /// // Use empty bytes if no salt is needed
    /// let point2 = Point::hash_to_curve_rfc9381_tai::<Sha256>(b"hello world", b"");
    /// ```
    ///
    /// [`hash_to_curve_sswu`]: Self::hash_to_curve_sswu
    pub fn hash_to_curve_rfc9381_tai<H: Hash32>(
        msg: &[u8],
        salt: &[u8],
    ) -> Point<EvenY, Public, NonZero> {
        use crate::hash::HashAdd;

        const SUITE_BYTE: u8 = 0xFE; // SECP256K1_SHA256_TAI suite
        const DOMAIN_SEP_FRONT: u8 = 0x01;
        const DOMAIN_SEP_BACK: u8 = 0x00;

        // Pre-compute the invariant part of the hash
        let base_hasher = H::default()
            .add(SUITE_BYTE)
            .add(DOMAIN_SEP_FRONT)
            .add(salt)
            .add(msg);

        // Try up to 255 times (using u8 counter)
        for counter in 0u8..u8::MAX {
            let hash_bytes = base_hasher
                .clone()
                .add(counter)
                .add(DOMAIN_SEP_BACK)
                .finalize_fixed();

            // RFC 9381 try-and-increment always produces even y-coordinates
            if let Some(point) =
                Point::<EvenY, Public, NonZero>::from_xonly_bytes(hash_bytes.into())
            {
                return point;
            }
        }

        // This should never happen (probability ~ 2^-256)
        unreachable!("Failed to find valid point after 256 attempts")
    }
}

impl<Z: ZeroChoice, S> Point<Normal, S, Z> {
    /// Creates a Point the compressed encoding specified in [_Standards for
    /// Efficient Cryptography_]. This is the typical encoding used in
    /// Bitcoin. The first byte must be `0x02` or `0x03` to indicate that the
    /// y-coordinate is even or odd respectively.  The remaining 32 bytes must
    /// encode an x-coordinate on the curve.  If these conditions are not then
    /// it will return `None`.
    ///
    /// # Examples
    /// ```
    /// use secp256kfun::{G, Point, marker::*};
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
    /// use secp256kfun::{Point, marker::*};
    /// let point = Point::random(&mut rand::thread_rng());
    /// let (point_with_even_y, was_odd) = point.clone().into_point_with_even_y();
    /// ```
    pub fn into_point_with_even_y(self) -> (Point<EvenY, S, NonZero>, bool)
    where
        T: PointType,
    {
        let normalized = self.normalize();
        let needs_negation = !normalized.is_y_even();
        let negated = normalized.conditional_negate(needs_negation);
        (Point::from_inner(negated.0, EvenY), needs_negation)
    }

    /// Returns the generator point [`G`] defined in [_Standards for Efficient Cryptography_].
    ///
    /// This is sometimes more useful than just using `secp256kfun::G` since it allows the compiler
    /// to infer types.
    ///
    /// ## Examples
    ///
    /// ```
    /// use secp256kfun::{G, Point, marker::*};
    /// assert_eq!(Point::<Normal, Public, _>::generator(), *G);
    /// ```
    ///
    /// [_Standards for Efficient Cryptography_]: https://www.secg.org/sec1-v2.pdf
    /// [`G`]: crate::G
    pub fn generator() -> Self
    where
        T: Default,
    {
        Self::from_inner(backend::G_POINT, T::default())
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
    /// use secp256kfun::{G, Point, Scalar, marker::*};
    /// let mut secret_key = Scalar::random(&mut rand::thread_rng());
    /// let public_key = Point::even_y_from_scalar_mul(G, &mut secret_key);
    /// assert!(public_key.is_y_even());
    /// ```
    pub fn even_y_from_scalar_mul(
        base: &Point<impl PointType, impl Secrecy>,
        scalar: &mut Scalar<impl Secrecy>,
    ) -> Self {
        let point = crate::op::scalar_mul_point(*scalar, base);
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

    /// Convert a point that is marked as `Zero` to `NonZero`.
    ///
    /// If the point *was* actually zero ([`is_zero`] returns true) it returns `None`.
    ///
    /// [`is_zero`]: Point::is_zero
    pub fn non_zero(self) -> Option<Point<T, S, NonZero>> {
        if self.is_zero() {
            None
        } else {
            Some(Point::from_inner(self.0, self.1))
        }
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
        op::point_conditional_negate(*self, cond)
    }

    /// Set the [`Secrecy`] of the point.
    pub fn set_secrecy<SNew>(self) -> Point<T, SNew, Z> {
        Point::from_inner(self.0, self.1)
    }

    /// Set the [`Secrecy`] of the point to [`Public`].
    ///
    /// Note that points are by default `Public`.
    ///
    /// [`Secrecy`]: crate::marker::Secrecy
    /// [`Public`]: crate::marker::Public
    pub fn public(self) -> Point<T, Public, Z> {
        Point::from_inner(self.0, self.1)
    }

    /// Set the [`Secrecy`] of the point to [`Secret`].
    ///
    /// [`Secrecy`]: crate::marker::Secrecy
    /// [`Public`]: crate::marker::Public
    pub fn secret(self) -> Point<T, Secret, Z> {
        Point::from_inner(self.0, self.1)
    }

    /// Normalize a point.
    ///
    /// This is usually only useful to do if the `Point` is marked as [`NonNormal`].
    /// Otherwise it will be no-op and just set the [`PointType`] to [`Normal`].
    ///
    /// [`NonNormal`]: crate::marker::NonNormal
    /// [`PointType`]: crate::marker::PointType
    /// [`Normal`]: crate::marker::Normal
    pub fn normalize(self) -> Point<Normal, S, Z>
    where
        T: PointType,
    {
        op::point_normalize(self)
    }

    /// Mark the point as being [`NonNormal`].
    ///
    /// This is sometimes helpful when you have an accumulater variable where although the first
    /// value of the point is normalized the subsequent values will not be so to satisfy the
    /// compiler you have to set it to `NonNormal` before you start.
    ///
    /// [`NonNormal`]: crate::marker::NonNormal
    pub fn non_normal(self) -> Point<NonNormal, S, Z> {
        Point::from_inner(self.0, NonNormal)
    }

    /// Mark the point as possibly being `Zero` (even though it isn't).
    ///
    /// This is useful in accumulator variables where although the initial value is non-zero, every
    /// sum addition after that might make it zero so it's necessary to start off with `Zero` marked
    /// point.
    pub fn mark_zero(self) -> Point<T, S, Zero> {
        Point::from_inner(self.0, self.1)
    }
}

impl<Z, T> Point<T, Public, Z> {
    /// Checks if this point's x-coordiante is the equal to the scalar mod the
    /// curve order. This is only useful for ECDSA implementations.
    pub fn x_eq_scalar<Z2>(&self, scalar: &Scalar<Public, Z2>) -> bool {
        crate::backend::VariableTime::point_x_eq_scalar(&self.0, &scalar.0)
    }
}

impl<T: PointType, S, Z> core::ops::Neg for Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        op::point_negate(self)
    }
}

impl<T: PointType, S, Z> core::ops::Neg for &Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        op::point_negate(self)
    }
}

impl<T1, S1, Z1, T2, S2, Z2> PartialEq<Point<T2, S2, Z2>> for Point<T1, S1, Z1>
where
    T1: PointType,
    T2: PointType,
{
    fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool {
        op::point_eq(self, rhs)
    }
}

impl<T: PointType, S, Z> Eq for Point<T, S, Z> {}

impl<Z> core::hash::Hash for Point<Normal, Public, Z> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl core::hash::Hash for Point<EvenY, Public, NonZero> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_xonly_bytes().hash(state)
    }
}

impl<T1: Normalized, Z1, T2: Normalized, Z2> PartialOrd<Point<T2, Public, Z2>>
    for Point<T1, Public, Z1>
{
    fn partial_cmp(&self, other: &Point<T2, Public, Z2>) -> Option<core::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl<T1: Normalized, Z1> Ord for Point<T1, Public, Z1> {
    fn cmp(&self, other: &Point<T1, Public, Z1>) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl<S, Z, T: Normalized> Point<T, S, Z> {
    /// Converts the point to its compressed encoding as specified by [_Standards for Efficient Cryptography_].
    ///
    /// # Example
    /// Round trip serialization with [`from_bytes`]
    /// ```
    /// use secp256kfun::{Point, marker::*};
    /// let point = Point::random(&mut rand::thread_rng());
    /// let bytes = point.to_bytes();
    /// assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
    /// assert_eq!(
    ///     Point::<_, Public, NonZero>::from_bytes(bytes).unwrap(),
    ///     point
    /// );
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

impl<T, S> Point<T, S, Zero> {
    /// Returns the [`identity element`] of the group A.K.A. the point at infinity.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{G, Point, g, marker::*, s};
    /// let zero = Point::<Normal, Public, _>::zero();
    /// assert!(zero.is_zero());
    /// assert_eq!(g!(zero + G), *G);
    /// assert_eq!(zero, g!(0 * G))
    /// ```
    /// [`identity_element`]: https://en.wikipedia.org/wiki/Identity_element
    pub fn zero() -> Self
    where
        T: Default,
    {
        Self::from_inner(backend::Point::zero(), T::default())
    }
}

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

    /// Returns whether the point has an even y-coordinate
    pub fn is_y_even(&self) -> bool {
        op::point_is_y_even(self)
    }

    /// Serializes a point with `EvenY` to its 32-byte x-coordinate
    pub fn to_xonly_bytes(&self) -> [u8; 32] {
        self.coordinates().0
    }

    /// Encodes a point as its compressed encoding as specified by [_Standards for Efficient Cryptography_].
    ///
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{Point, marker::*};
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

impl<S, Z> HashInto for Point<Normal, S, Z> {
    fn hash_into(self, hash: &mut impl digest::Update) {
        hash.update(self.to_bytes().as_ref())
    }
}

impl<S> HashInto for Point<EvenY, S, NonZero> {
    fn hash_into(self, hash: &mut impl digest::Update) {
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
        let mut p = point.0;
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
        point.to_xonly_bytes()
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 x-coordinate",
    fn from_bytes<S>(bytes: [u8;32]) -> Option<Point<EvenY, S, NonZero>> {
        Point::from_xonly_bytes(bytes)
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 point",
    fn from_bytes<S,Z: ZeroChoice>(bytes: [u8;33]) -> Option<Point<Normal,S, Z>> {
        Point::from_bytes(bytes)
    }
}

impl<TR: PointType, SL, SR, ZR> AddAssign<Point<TR, SR, ZR>> for Point<NonNormal, SL, Zero> {
    fn add_assign(&mut self, rhs: Point<TR, SR, ZR>) {
        *self = crate::op::point_add(*self, rhs).set_secrecy::<SL>()
    }
}

impl<TR: PointType, SL, SR, ZR> AddAssign<&Point<TR, SR, ZR>> for Point<NonNormal, SL, Zero> {
    fn add_assign(&mut self, rhs: &Point<TR, SR, ZR>) {
        *self = crate::op::point_add(*self, rhs).set_secrecy::<SL>()
    }
}

impl<TR: PointType, SL, SR, ZR> SubAssign<&Point<TR, SR, ZR>> for Point<NonNormal, SL, Zero> {
    fn sub_assign(&mut self, rhs: &Point<TR, SR, ZR>) {
        *self = crate::op::point_sub(*self, rhs).set_secrecy::<SL>()
    }
}

impl<TR: PointType, SL, SR, ZR> SubAssign<Point<TR, SR, ZR>> for Point<NonNormal, SL, Zero> {
    fn sub_assign(&mut self, rhs: Point<TR, SR, ZR>) {
        *self = crate::op::point_sub(*self, rhs).set_secrecy::<SL>()
    }
}

impl<S: Secrecy> core::iter::Sum for Point<NonNormal, S, Zero> {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        let mut sum = iter.next().unwrap_or_default();
        for point in iter {
            sum += point;
        }
        sum
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{G, g};
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
            let i = Point::<Normal, Public, _>::zero();
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
                let p = p.clone().mark_zero().non_normal();
                let i = g!(p - p);
                assert_eq!(i, Point::<NonNormal, Secret,_>::zero());
                (0..100).fold(i, |acc, _| g!(acc + p))
            };

            expression_eq!([add_100_times] == [100 * q]);
            let undo = { (0..100).fold(add_100_times.clone(), |acc, _| g!(acc - p)) };
            expression_eq!([undo] == [add_100_times - 100 * q]);
            expression_eq!([undo] == [i]);
        }};
        ($P:expr) => {{
            let p = $P;
            let i = Point::<Normal, Public, _>::zero();

            expression_eq!([p] == [p]);
            expression_eq!([p + i] == [p]);
            expression_eq!([i - p] == [-p]);
            expression_eq!([p - i] == [p]);
            expression_eq!([0 * p] == [i]);

            let q = p.clone().normalize().public();
            operations_test!(@binary p,q);
            let q = p.clone().non_normal().public();
            operations_test!(@binary p,q);
            let q = p.clone().normalize().secret();
            operations_test!(@binary p,q);
            let q = p.clone().non_normal().secret();
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
        fn operations_jacobian(P in any::<Point<NonNormal>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_normal_secret(P in any::<Point<Normal, Secret>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian_secret(P in any::<Point<NonNormal, Secret>>()) {
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
        fn operations_jacobian_public_zero(P in any::<Point<NonNormal, Public, Zero>>()) {
            operations_test!(&P);
        }

        #[test]
        fn operations_jacobian_secret_zero(P in any::<Point<NonNormal, Secret, Zero>>()) {
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
            (*G).normalize().to_bytes_uncompressed(),
            crate::hex::decode_array("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap(),
            "G.to_bytes_uncompressed()"
        );

        assert_eq!(
            Point::from_bytes_uncompressed((*G).normalize().to_bytes_uncompressed()).unwrap(),
            *G
        );

        assert_eq!(
            (*G).normalize().to_bytes(),
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
        let zero = Point::<_, Public, _>::zero();
        assert_eq!(Point::<_, _, Zero>::from_bytes(zero.to_bytes()), Some(zero));
    }

    #[test]
    fn from_bytes_uncompressed_validates_curve_membership() {
        // Test with a valid point (generator)
        let g = Point::<Normal, Public, NonZero>::generator();
        let (x, y) = g.coordinates();
        let mut valid_bytes = [0u8; 65];
        valid_bytes[0] = 0x04;
        valid_bytes[1..33].copy_from_slice(&x);
        valid_bytes[33..65].copy_from_slice(&y);

        assert_eq!(
            Point::<Normal, Public, NonZero>::from_bytes_uncompressed(valid_bytes),
            Some(g)
        );

        // Test with invalid point not on curve
        // Use a point where y^2 != x^3 + 7
        let mut invalid_bytes = [0u8; 65];
        invalid_bytes[0] = 0x04;
        // Use x = 1
        invalid_bytes[32] = 1;
        // Use y = 1 (which doesn't satisfy y^2 = x^3 + 7 = 8)
        invalid_bytes[64] = 1;

        assert_eq!(
            Point::<Normal, Public, NonZero>::from_bytes_uncompressed(invalid_bytes),
            None
        );

        // Test with invalid prefix
        let mut invalid_prefix = valid_bytes;
        invalid_prefix[0] = 0x05;
        assert_eq!(
            Point::<Normal, Public, NonZero>::from_bytes_uncompressed(invalid_prefix),
            None
        );
    }

    #[test]
    fn zero_cases() {
        use crate::s;
        let i = Point::<Normal, Public, _>::zero();
        let forty_two = s!(42);
        let forty_two_pub = s!(42).public();
        assert!(i.is_zero());
        assert!((-i).is_zero());
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
        assert!(format!("{random_point:?}").starts_with("Point<Normal,Public,NonZero>"));
        let mult_point = g!({ Scalar::random(&mut rand::thread_rng()) } * G);
        assert!(format!("{mult_point:?}").starts_with("Point<NonNormal,Public,NonZero>"));
    }

    #[test]
    fn assign_tests() {
        let a_orig = Point::random(&mut rand::thread_rng())
            .mark_zero()
            .non_normal();
        let mut a = a_orig;
        a += G;
        assert_eq!(a, op::point_add(a_orig, G));
        assert_ne!(a, a_orig);
        assert_ne!(a, *G);
        a -= G;
        assert_eq!(a, a_orig);
    }
}
