use crate::Point;

use super::ZeroChoice;

/// Every `T` of a [`Point<T,S,Z>`] implements the `PointType` trait.
///
/// There are several different point types.
/// - [`Normal`]: A point represented internally with Affine coordinates, with x and y coordinates (if it's not zero). These can be directly serialized or hashed.
/// - [`NonNormal`]: A non-normalized represented internally as in three   coordinates. Usually the result of a point operation. Before being serialized or hashed, you have to normalize it.
/// - [`BasePoint`]: A normal point that has (or may have in the future) pre-computed multiplication tables like [`G`].
/// - [`EvenY`]: A normal point whose y-coordinate is known to be _even_ at compile time.
///
/// [`Point<T,S,Z>`]: crate::Point
/// [`G`]: crate::G
pub trait PointType:
    Sized + Clone + Copy + PartialEq + Eq + core::hash::Hash + Ord + PartialOrd
{
    /// The point type returned from the negation of a point of this type.
    type NegationType: Default + PointType;

    /// Whether the point type is normalized or not (i.e. not [`NonNormal`])
    fn is_normalized() -> bool;

    /// Cast a point that is not of this type to this type.
    ///
    /// This is useful internally for doing very generic things and shouldn't be used in
    /// applications.
    fn cast_point<T: PointType, S, Z: ZeroChoice>(
        point: Point<T, S, Z>,
    ) -> Option<Point<Self, S, Z>>;
}

/// A Fully Normalized Point. Internally `Normal` points are represented using
/// _affine_ coordinates with fully normalized `x` and `y` field elements.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct Normal;
/// A Non-normalized Point. Usually, represented as three field elements three field elements:
/// `x`,`y` and `z` rather than just two in a [`Normal`] point.
///
/// In general it's most efficient to normalize `NonNormal` points into `Normal` points, as late as
/// possible. To normalize a `NonNormal` point call `normalize` on the point.
///
/// ```
/// use secp256kfun::{G, Scalar, g, marker::*};
/// let scalar = Scalar::random(&mut rand::thread_rng());
/// let non_normal_point = g!(scalar * G);
/// let normal_point = non_normal_point.normalize();
/// let bytes = normal_point.to_bytes(); // we can now serialize it
/// ```
///
/// [`normalize`]: crate::Point::normalize

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct NonNormal;

/// Backwards compatibility type alias.
#[deprecated(note = "use NonNormal instead")]
pub type Jacobian = NonNormal;

/// A [`Normal`] point whose `y` coordinate is known to be even.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct EvenY;

/// A [`Normal`] point which may have pre-computed tables for accelerating scalar
/// multiplications. The only example of this is [`G`].
///
/// Note that whether G does have pre-computed tables depends on the current state of the backend.
/// At the time of writing no pre-computation is done.
///
/// [`G`]: crate::G
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct BasePoint;

/// A marker trait that indicates a `PointType` uses a affine internal representation.
pub trait Normalized: PointType {}

impl Normalized for EvenY {}
impl Normalized for Normal {}
impl Normalized for BasePoint {}

impl PointType for Normal {
    type NegationType = Normal;

    #[inline(always)]
    fn is_normalized() -> bool {
        true
    }

    fn cast_point<T: PointType, S, Z: ZeroChoice>(
        point: Point<T, S, Z>,
    ) -> Option<Point<Self, S, Z>> {
        Some(point.normalize())
    }
}

impl PointType for EvenY {
    type NegationType = Normal;

    fn is_normalized() -> bool {
        true
    }

    /// ⚠ This will always return `None` if trying to cast from a `Zero` marked point (even if the actual point is not `Zero`)
    fn cast_point<T: PointType, S, Z: ZeroChoice>(
        point: Point<T, S, Z>,
    ) -> Option<Point<Self, S, Z>> {
        let (point, needs_negation) = point.non_zero()?.into_point_with_even_y();
        if needs_negation {
            return None;
        }

        // we don't want to allow creating Point<EvenY, Public, Zero>
        if Z::is_zero() {
            return None;
        }

        // we already checked it's not zero
        let point = Z::cast_point(point).expect("infallible");

        Some(point)
    }
}

impl PointType for NonNormal {
    type NegationType = NonNormal;

    #[inline(always)]
    fn is_normalized() -> bool {
        false
    }

    fn cast_point<T: PointType, S, Z: ZeroChoice>(
        point: Point<T, S, Z>,
    ) -> Option<Point<Self, S, Z>> {
        Some(point.non_normal())
    }
}

impl PointType for BasePoint {
    type NegationType = Normal;

    fn is_normalized() -> bool {
        true
    }

    fn cast_point<T: PointType, S, Z: ZeroChoice>(
        _point: Point<T, S, Z>,
    ) -> Option<Point<Self, S, Z>> {
        None
    }
}
