/// Something marked with Zero might be `0` i.e. the additive identity
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Zero;

/// Something marked with `NonZero` is guaranteed not to be 0.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NonZero;

/// A marker trait implemented by [`Zero`] and [`NonZero`].
///
/// Note it is rarely useful to define a function over any `Z: ZeroChoice`.
/// This trait mostly just exists for consistency.
pub trait ZeroChoice:
    Default + Clone + PartialEq + Copy + DecideZero<NonZero> + DecideZero<Zero> + 'static
{
}

impl ZeroChoice for Zero {}
impl ZeroChoice for NonZero {}

/// A trait to figure out whether the result of a multiplication should be [`Zero`] or [`NonZero`] at compile time.

pub trait DecideZero<ZZ> {
    /// If both arguments are `NonZero` then `Out` will be `NonZero`, otherwise `Zero`.
    type Out;
}

impl<Z: ZeroChoice> DecideZero<Z> for Zero {
    type Out = Zero;
}

impl<Z: ZeroChoice> DecideZero<Z> for NonZero {
    type Out = Z;
}

mod change_marks {
    use crate::{marker::*, Point, Scalar};

    impl<Z, S> ChangeMark<Scalar<S, Z>> for NonZero {
        type Out = Option<Scalar<S, NonZero>>;

        fn change_mark(scalar: Scalar<S, Z>) -> Self::Out {
            if scalar.is_zero() {
                None
            } else {
                Some(Scalar::from_inner(scalar.0))
            }
        }
    }

    impl<Z, S, T> ChangeMark<Point<T, S, Z>> for NonZero {
        type Out = Option<Point<T, S, NonZero>>;

        fn change_mark(point: Point<T, S, Z>) -> Self::Out {
            if point.is_zero() {
                None
            } else {
                Some(Point::from_inner(point.0, point.1))
            }
        }
    }

    impl<Z, S, Y> ChangeMark<Point<Y, S, Z>> for Zero {
        type Out = Point<Y, S, Zero>;

        fn change_mark(point: Point<Y, S, Z>) -> Self::Out {
            Point::from_inner(point.0, point.1)
        }
    }

    impl<Z, S> ChangeMark<Scalar<S, Z>> for Zero {
        type Out = Scalar<S, Zero>;

        fn change_mark(scalar: Scalar<S, Z>) -> Self::Out {
            Scalar::from_inner(scalar.0)
        }
    }
}
