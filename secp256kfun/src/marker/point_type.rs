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
    type NegationType: Default;

    /// Whether the point type is normalized or not (i.e. not [`NonNormal`])
    fn is_normalized() -> bool;
}

/// A Fully Normalized Point. Internally `Normal` points are represented using
/// _affine_ coordinates with fully normalized `x` and `y` field elements.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Normal;
/// A Non-normalized Point. Usually, represented as three field elements three field elements:
/// `x`,`y` and `z` rather than just two in a [`Normal`] point.
///
/// In general it's most efficient to normalize `NonNormal` points into `Normal` points, as late as
/// possible. To normalize a `NonNormal` point call `normalize` on the point.
///
/// ```
/// use secp256kfun::{g, marker::*, Scalar, G};
/// let scalar = Scalar::random(&mut rand::thread_rng());
/// let non_normal_point = g!(scalar * G);
/// let normal_point = non_normal_point.normalize();
/// let bytes = normal_point.to_bytes(); // we can now serialize it
/// ```
///
/// [`normalize`]: crate::Point::normalize

#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NonNormal;

/// Backwards compatibility type alias.
#[deprecated(note = "use NonNormal instead")]
pub type Jacobian = NonNormal;

/// A [`Normal`] point whose `y` coordinate is known to be even.
#[derive(Default, Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl<N: Normalized> PointType for N {
    type NegationType = Normal;

    #[inline(always)]
    fn is_normalized() -> bool {
        true
    }
}

impl PointType for NonNormal {
    type NegationType = NonNormal;

    #[inline(always)]
    fn is_normalized() -> bool {
        false
    }
}
