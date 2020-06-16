//! Markers for improved compile time safety, performance and functionality.
mod zero_choice;
pub use zero_choice::*;
mod secrecy;
pub use secrecy::*;
mod point_type;
pub use point_type::*;

/// A trait that is implemented on marker types to indicate that they can mark the type `T`.
pub trait ChangeMark<T> {
    /// The result type of marking `T` with `Self`
    type Out;
    /// Marks `item` with `Self`.
    fn change_mark(item: T) -> Self::Out;
}

impl<T, A, B> ChangeMark<T> for (A, B)
where
    A: ChangeMark<T>,
    B: ChangeMark<<A as ChangeMark<T>>::Out>,
{
    type Out = <B as ChangeMark<A::Out>>::Out;
    fn change_mark(item: T) -> Self::Out {
        B::change_mark(A::change_mark(item))
    }
}

impl<T, A, B, C> ChangeMark<T> for (A, B, C)
where
    A: ChangeMark<T>,
    B: ChangeMark<<A as ChangeMark<T>>::Out>,
    C: ChangeMark<<B as ChangeMark<<A as ChangeMark<T>>::Out>>::Out>,
{
    type Out = C::Out;
    fn change_mark(item: T) -> Self::Out {
        C::change_mark(B::change_mark(A::change_mark(item)))
    }
}

/// A extension trait to add the `mark` method to all types so they can be
/// marked with anything that implements `ChangeMark` against it.
pub trait Mark: Sized {
    /// Returns a new instance of the invocant that will be marked with `M`.
    ///
    /// # Examples
    /// ```
    /// use secp256kfun::{marker::*, Scalar};
    /// let scalar = Scalar::random(&mut rand::thread_rng());
    /// assert!(format!("{:?}", scalar).starts_with("Scalar<Secret,"));
    /// let scalar = scalar.mark::<Public>(); // scalar is consumed
    /// assert!(format!("{:?}", scalar).starts_with("Scalar<Public,"));
    /// ```
    fn mark<M: ChangeMark<Self>>(self) -> M::Out;
}

impl<T> Mark for T {
    #[must_use]
    fn mark<M: ChangeMark<Self>>(self) -> M::Out {
        M::change_mark(self)
    }
}
