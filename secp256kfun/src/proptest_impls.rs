//! Implementations of [`Arbitrary`] for core types.
//!
//! [`Arbitrary`]: proptest::arbitrary::Arbitrary

use crate::{marker::*, Point, Scalar, G};
use ::proptest::prelude::*;

impl<S: Secrecy> Arbitrary for Scalar<S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            // insert some pathological cases
            1 => Just(Scalar::one().mark::<S>()),
            1 => Just(Scalar::minus_one().mark::<S>()),
            18 => any::<[u8;32]>().prop_filter_map("zero bytes not acceptable", |bytes| Scalar::from_bytes_mod_order(bytes).mark::<(S,NonZero)>()),
        ].boxed()
    }
}

impl<S: Secrecy> Arbitrary for Scalar<S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            1 => Just(Scalar::zero().mark::<S>()),
            1 => Just(Scalar::one().mark::<(S, Zero)>()),
            1 => Just(Scalar::minus_one().mark::<(S, Zero)>()),
            27 => any::<[u8;32]>().prop_map(|bytes| Scalar::from_bytes_mod_order(bytes).mark::<S>()),
        ].boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Jacobian, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Scalar>()
            .prop_map(|scalar| g!(scalar * G).mark::<S>())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Normal, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Point<Jacobian, S>>()
            .prop_map(|point| point.normalize())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<EvenY, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Point<Normal, S>>()
            .prop_map(|point| point.into_point_with_even_y().0.mark::<S>())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Jacobian, S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            1 => Just(Point::zero().mark::<(Jacobian, S)>()),
            9 => any::<Point<Jacobian,S>>().prop_map(|p| p.mark::<Zero>()),
        ]
        .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Normal, S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            1 => Just(Point::zero().mark::<S>()),
            9 => any::<Point<Normal, S>>().prop_map(|p| p.mark::<Zero>())
        ]
        .boxed()
    }
}
