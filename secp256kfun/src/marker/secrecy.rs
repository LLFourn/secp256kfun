/// A marker trait over [`Secret`] and [`Public`].
///
/// [`Scalar`s] and [`Point`s] both have a `Secrecy` type parameter which must
/// be either [`Secret`] or [`Public`]. At a high level these indicate:
///
/// - [`Secret`]: This value must be kept secret from parties I interact with.
/// - [`Public`]: This value is known or it would not harm my security if this
///               value is known to all parties I interact with.
///
/// Note this consideration is only important if you do operations on the value
/// during an interaction with a party. So if you would like to keep scalar `x`
/// secret from party C but you only do operations on `x` while interacting with
/// `B` (who perhaps, already knows it), then, in theory, `x` can be marked
/// `Public`.  However it is up to you to make sure these conditions hold so the
/// prudent thing to do is make sure that anything that might be secret is
/// marked [`Secret`].
///
/// [`Scalar`s] are by default [`Secret`] and [`Point`s] are by default
/// [`Public`].  In order to change the default you must [`mark`] it.
///
/// ```
/// use secp256kfun::{marker::*, Scalar};
/// let public_scalar = Scalar::random(&mut rand::thread_rng()).mark::<Public>();
/// ```
///
/// The main purpose of marking value as secret or public is to tell the
/// compiler when it can _specialize_ an operation on that value to make it run
/// faster.
///
/// ```
/// use secp256kfun::{g, marker::*, Point, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let H = Point::random(&mut rand::thread_rng());
/// let X = g!(x * H); // This is constant time because x is secret
/// let x = x.mark::<Public>();
/// let X = g!(x * H); // This will run faster (in variable time)
/// ```
///
/// [`Secret`]: crate::marker::Secret
/// [`Point`]: crate::marker::Public
/// [`Scalar`s]: crate::Scalar
/// [`Point`s]: crate::Point
/// [`mark`]: crate::marker::Mark::mark
pub trait Secrecy: Default + Clone + PartialEq + Copy {}

/// Indicates that the value is secret and enforces that all operations that are
/// executed on it must be _constant time_.
#[derive(Debug, Clone, Default, PartialEq, Copy)]
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Secret;

/// Indicates that variable time operations may be used on the value.

#[derive(Debug, Clone, Default, PartialEq, Copy)]
#[cfg_attr(
    feature = "serialization",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Public;

impl Secrecy for Secret {}

impl Secrecy for Public {}

mod change_marks {
    use super::*;
    use crate::{marker::ChangeMark, Point, Scalar, Slice};
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

    impl<'a, S: Secrecy> ChangeMark<&'a [u8]> for S {
        type Out = Slice<'a, S>;

        fn change_mark(bytes: &'a [u8]) -> Self::Out {
            Slice::<S>::from_inner(bytes)
        }
    }

    impl<'a, S: Secrecy, SNew: Secrecy> ChangeMark<Slice<'a, S>> for SNew {
        type Out = Slice<'a, SNew>;

        fn change_mark(bytes: Slice<'a, S>) -> Self::Out {
            Slice::<SNew>::from_inner(bytes.inner)
        }
    }
}
