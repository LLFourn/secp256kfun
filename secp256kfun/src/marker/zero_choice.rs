use crate::Point;
/// Something marked with Zero might be `0` i.e. the additive identity
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct Zero;

/// Something marked with `NonZero` is guaranteed not to be 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "bincode", derive(bincode::Encode, bincode::Decode))]
pub struct NonZero;

/// A marker trait implemented by [`Zero`] and [`NonZero`].
///
/// Note it is rarely useful to define a function over any `Z: ZeroChoice`.
/// This trait mostly just exists for consistency.
pub trait ZeroChoice:
    Default
    + Clone
    + PartialEq
    + Eq
    + Copy
    + DecideZero<NonZero>
    + DecideZero<Zero>
    + DecideZero<Self, Out = Self>
    + core::hash::Hash
    + Ord
    + PartialOrd
    + 'static
{
    /// Returns whether the type is `Zero`
    fn is_zero() -> bool;

    /// Casts a point from one zeroness to another.
    fn cast_point<T, S, Z: ZeroChoice>(point: Point<T, S, Z>) -> Option<Point<T, S, Self>>;
}

impl ZeroChoice for Zero {
    fn is_zero() -> bool {
        true
    }

    fn cast_point<T, S, Z: ZeroChoice>(point: Point<T, S, Z>) -> Option<Point<T, S, Zero>> {
        Some(point.mark_zero())
    }
}

impl ZeroChoice for NonZero {
    fn is_zero() -> bool {
        false
    }

    fn cast_point<T, S, Z: ZeroChoice>(point: Point<T, S, Z>) -> Option<Point<T, S, Self>> {
        point.non_zero()
    }
}

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
