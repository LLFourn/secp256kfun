/// Every `T` of a [`Point<T,S,Z>`] implements the `PointType` trait.
///
/// There are several different point types.
/// - [`Normal`]: A point represented internally with Affine coordinates, with x and y coordinates (if it's not zero). These can be directly serialized or hashed.
/// - [`Jacobian`]: A non-normal represented internally in Jacobian coordinates. Usually the result of a point operation. Before being serialized or hashed, you have to normalize it.
/// - [`BasePoint`]: A normal point that has pre-computed multiplication tables like [`G`].
/// - [`EvenY`]: A normal point whose y-coordinate is known to be _even_ at compile time.
///
/// To normalize a `Point<Jacobian>` you mark it as [`Normal`]:
/// ```
/// use secp256kfun::{g, marker::*, Scalar, G};
/// let scalar = Scalar::random(&mut rand::thread_rng());
/// let jacobian_point = g!(scalar * G);
/// let normal_point = jacobian_point.mark::<Normal>();
/// let bytes = normal_point.to_bytes(); // we can now serialize it
/// ```
/// [`G`]: crate::G
/// [`Point<T,S,Z>`]: crate::Point
pub trait PointType: Sized + Clone + Copy + 'static {
    /// The point type returned from the negation of a point of this type.
    type NegationType: Default;
}

/// A Fully Normalized Point. Internally `Normal` points are represented using
/// _affine_ coordinates with fully normalized `x` and `y` field elements.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Normal;
#[derive(Default, Debug, Clone, Copy)]
/// A Non-normalized Point. `Jacobian` points are represented internally as
/// three field elements: `x`,`y` and `z`. Most point operations return
/// `Jacobian` points.
///
/// In general it's most efficient to normalize `Jacobian` points into [`Normal`] points, as late as possible.
///
/// Note that the underlying arithmetic backend may not actually use Jacobian coordinates - it may use Projective coordinates instead.
pub struct Jacobian;
/// A [`Normal`] point whose `y` coordinate is known to be even.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EvenY;

/// A [`Normal`] point which has pre-computed tables for accelerating scalar
/// multiplications. The only example of this is [`G`].
///
/// Note that whether G does have pre-computed tables depends on the arithmetic backend being used.
///
/// [`G`]: crate::G
#[derive(Clone, Copy)]
pub struct BasePoint(pub(crate) crate::backend::BasePoint);

/// A marker trait that indicates a `PointType` uses a affine internal representation.
#[cfg_attr(feature = "nightly", rustc_specialization_trait)]
pub trait Normalized: PointType {}

#[cfg_attr(feature = "nightly", rustc_specialization_trait)]
pub(crate) trait NotBasePoint: Default {}

impl Normalized for EvenY {}
impl Normalized for Normal {}
impl Normalized for BasePoint {}

impl NotBasePoint for Jacobian {}
impl NotBasePoint for EvenY {}
impl NotBasePoint for Normal {}

impl<N: Normalized> PointType for N {
    type NegationType = Normal;
}

impl PointType for Jacobian {
    type NegationType = Jacobian;
}

mod change_marks {
    use crate::{marker::*, Point};

    impl<T, S, Z> ChangeMark<Point<T, S, Z>> for Normal {
        type Out = Point<Normal, S, Z>;

        fn change_mark(point: Point<T, S, Z>) -> Self::Out {
            use crate::op::PointUnary;
            Point::from_inner(point.normalize(), Normal)
        }
    }

    impl<Z, S, T> ChangeMark<Point<T, S, Z>> for Jacobian {
        type Out = Point<Jacobian, S, Z>;

        fn change_mark(point: Point<T, S, Z>) -> Self::Out {
            Point::from_inner(point.0, Jacobian)
        }
    }
}
