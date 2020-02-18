/// A marker trait over [`Secret`] and [`Public`].
///
/// [`Scalar`s] and [`Point`s] are both have a secrecy mark of either:
///
/// - [`Secret`]: This value must be kept secret from parties I interact with.
/// - [`Public`]: This value is known or could be known to any party I interact with.
///
/// [`Scalar`s] are by default [`Secret`] and [`Point`s] are by default [`Public`].
/// In order to change the default you must [`mark`] it.
///
/// ```
/// use secp256kfun::{marker::*, Scalar};
/// let public_scalar = Scalar::random(&mut rand::thread_rng()).mark::<Public>();
/// ```
///
/// The main purpose of marking values is to tell the compiler when it can
/// _specialize_ an operation on that value to make it run faster.
///
/// ```
/// use secp256kfun::{g, marker::*, Point, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let H = Point::random(&mut rand::thread_rng());
/// let X = g!(x * H); // This is constant time because x is secret
/// let x = x.mark::<Public>();
/// let X = g!(x * H); // This will run faster but in variable time
/// ```
///
/// [`Secret`]: crate::marker::Secret
/// [`Point`]: crate::marker::Public
/// [`Scalar`s]: crate::Scalar
/// [`Point`s]: crate::Point
/// [`mark`]: crate::marker::Mark::mark;
#[rustc_specialization_trait]
pub trait Secrecy: Default + Clone + PartialEq {}

/// Indicates that the value is secret and enforces that all operations that are
/// executed on it must be _constant time_.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Secret;

/// Indicates that variable time operations may be used on the value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Public;

impl Secrecy for Secret {}

impl Secrecy for Public {}

mod change_marks {
    use super::*;
    use crate::{marker::ChangeMark, Point, Scalar};
    impl<Z, S, SNew: Secrecy> ChangeMark<Scalar<S, Z>> for SNew {
        type Out = Scalar<SNew, Z>;

        fn change_mark(scalar: Scalar<S, Z>) -> Self::Out {
            Scalar::from_inner(scalar.0)
        }
    }

    impl<Z, S, Y, SNew: Secrecy> ChangeMark<Point<Y, S, Z>> for SNew {
        type Out = Point<Y, SNew, Z>;

        fn change_mark(point: Point<Y, S, Z>) -> Self::Out {
            Point::from_inner(point.0, point.1)
        }
    }
}
