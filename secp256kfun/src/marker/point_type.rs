//! Each [Point<T,S,Z>](crate::Point) has a type argument `T` which describes
//! its _point type_. Each type represents a different internal representation
//! of the point which in turn affects what methods will be available on the
//! point and whether the compiler will use _specialized_ arithmetic algorithms
//! to speed up operations on the point.
use crate::{
    backend::{self, BackendPoint, BackendXOnly},
    marker::*,
    op, Point, XOnly,
};

/// Every valid type `T` of a [`Point<T,S,Z>`] implements the `PointType` trait.
///
/// There are several different point types.
/// - [`Normal`]: A point in Affine coordinates, with x and y coordinates (if it's not zero). These can be directly serialized or hahsed.
/// - [`Jacobian`]: A non-Normal point with (x,y,z) coordinates. Usually the result of a point operation. Before being serialized or hashed, you have to normalize it.
/// - [`BasePoint`]: A Normal point that has pre-computed multiplication tables like [`G`].
/// - [`EvenY`]/[`SquareY`]: A Normal point whose y coordinate is known to be _even_ or _square_ at compile time.
///
/// To normalize a `Point<Jacobian>` you mark it as [`Normal`]:
/// ```
/// use secp256kfun::{g, marker::*, Scalar, G};
/// let scalar = Scalar::random(&mut rand::thread_rng());
/// let jacobian_point = g!(scalar * G);
/// let normal_point = jacobian_point.mark::<Normal>();
/// let bytes = normal_point.to_bytes(); // we can now serialize it
/// ```
///
/// A Point that is `EvenY/SquareY` serializes to and from the 32-byte x-only representation like the [`XOnly`] type.
/// `Normal` points serialize to and from the standard 33-byte representation specified in [_SEC 1 standard_][1].
///
/// [1]: https://www.secg.org/sec1-v2.pdf
///
/// [`G`]: crate::G
/// [`Point<T,S,Z>`]: crate::Point
/// [`XOnly`]: crate::XOnly
pub trait PointType: Sized + Clone + Copy {
    /// The point type returned from the negation of a point of this type.
    type NegationType: Default;
}

/// A Fully Normalized Point. Internally `Normal` points are represented using
/// _affine_ coordinates with fully normalized `x` and `y` field elements.
#[derive(Default, Debug, Clone, Copy)]
pub struct Normal;
#[derive(Default, Debug, Clone, Copy)]
/// A Non-normalized Point. `Jacobian` points are represented internally as
/// three field elements: `x`,`y` and `z`. Most point operations return
/// `Jacobian` points.
///
/// In general it's most efficient to normalize `Jacobian` points into [`Normal`] points, as late as possible.
pub struct Jacobian;
/// A [`Normal`] point whose `y` coordinate is known to be even.
#[derive(Default, Debug, Clone, Copy)]
pub struct EvenY;
#[derive(Default, Debug, Clone, Copy)]
/// A [`Normal`] point whose `y` coordinate is known to be a square.
pub struct SquareY;
#[derive(Clone, Copy)]
/// A [`Normal`] point which has pre-computed tables for accelerating scalar
/// multiplications. The only example of this is [`G`].
///
/// [`G`]: crate::G
pub struct BasePoint(pub(crate) backend::BasePoint);

/// A marker trait that indicates a PointType uses a affine internal representation.
#[rustc_specialization_trait]
pub trait Normalized: PointType {
    /// Indicates what is known at compile time about the y-coordinate of the normalized point. It is either `()` or a [`YChoice`].
    type YType;
}

pub trait YChoice: Normalized + NotBasePoint {
    fn xonly_into_point(x_only: XOnly<Self>) -> Point<Self, Public, NonZero>;
    fn bytes_into_point<S>(bytes: [u8; 32]) -> Option<Point<Self, S, NonZero>>;
    fn norm_point_matches<T: Normalized, S>(point: &Point<T, S, NonZero>) -> bool;
}

#[rustc_specialization_trait]
pub trait NotBasePoint: Default {}

impl Normalized for EvenY {
    type YType = Self;
}
impl Normalized for SquareY {
    type YType = Self;
}
impl Normalized for Normal {
    type YType = ();
}
impl Normalized for BasePoint {
    type YType = ();
}

impl NotBasePoint for Jacobian {}
impl NotBasePoint for EvenY {}
impl NotBasePoint for SquareY {}
impl NotBasePoint for Normal {}

impl<N: Normalized> PointType for N {
    type NegationType = Normal;
}

impl PointType for Jacobian {
    type NegationType = Jacobian;
}

impl YChoice for EvenY {
    fn xonly_into_point(xonly: XOnly<Self>) -> Point<Self, Public, NonZero> {
        Point::from_inner(xonly.0.into_norm_point_even_y(), EvenY)
    }

    fn bytes_into_point<S>(bytes: [u8; 32]) -> Option<Point<Self, S, NonZero>> {
        backend::Point::norm_from_bytes_y_oddness(bytes, false)
            .map(|point| Point::from_inner(point, EvenY))
    }

    fn norm_point_matches<T: Normalized, S>(point: &Point<T, S, NonZero>) -> bool {
        op::NormPointUnary::is_y_even(point)
    }
}

impl YChoice for SquareY {
    fn xonly_into_point(xonly: XOnly<Self>) -> Point<Self, Public, NonZero> {
        Point::from_inner(xonly.0.into_norm_point_square_y(), SquareY)
    }

    fn bytes_into_point<S>(bytes: [u8; 32]) -> Option<Point<Self, S, NonZero>> {
        backend::Point::norm_from_bytes_y_square(bytes)
            .map(|point| Point::from_inner(point, SquareY))
    }

    fn norm_point_matches<T: Normalized, S>(point: &Point<T, S, NonZero>) -> bool {
        op::NormPointUnary::is_y_square(point)
    }
}

mod change_marks {
    use crate::{marker::*, Point, XOnly};

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

    impl<Y, YNew: YChoice> ChangeMark<XOnly<Y>> for YNew {
        type Out = XOnly<YNew>;
        fn change_mark(xonly: XOnly<Y>) -> Self::Out {
            XOnly::from_inner(xonly.0)
        }
    }
}
