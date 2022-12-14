/// Something marked with Zero might be `0` i.e. the additive identity
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Zero;

/// Something marked with `NonZero` is guaranteed not to be 0.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[cfg_attr(feautre = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    + core::hash::Hash
    + Ord
    + PartialOrd
    + 'static
{
    /// Returns whether the type is `Zero`
    fn is_zero() -> bool;
}

impl ZeroChoice for Zero {
    fn is_zero() -> bool {
        true
    }
}
impl ZeroChoice for NonZero {
    fn is_zero() -> bool {
        false
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
