//! Markers for improved compile time safety, performance and functionality.
mod zero_choice;
pub use zero_choice::*;
mod secrecy;
pub use secrecy::*;
mod point_type;
pub use point_type::*;

pub trait ChangeMark<B> {
    type Out;
    fn change_mark(item: B) -> Self::Out;
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

pub trait Mark: Sized {
    fn mark<M: ChangeMark<Self>>(self) -> M::Out;
}

impl<A> Mark for A {
    #[must_use]
    fn mark<M: ChangeMark<A>>(self) -> M::Out {
        M::change_mark(self)
    }
}
