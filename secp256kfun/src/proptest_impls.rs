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
            1 => Just(Scalar::<S,_>::one()),
            1 => Just(Scalar::<S,_>::minus_one()),
            18 => any::<[u8;32]>().prop_filter_map("zero bytes not acceptable", |bytes| Some(Scalar::from_bytes_mod_order(bytes).non_zero()?.set_secrecy::<S>())),
        ].boxed()
    }
}

impl<S: Secrecy> Arbitrary for Scalar<S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        prop_oneof![
            1 => Just(Scalar::zero()),
            1 => Just(Scalar::one().mark_zero()),
            1 => Just(Scalar::minus_one().mark_zero()),
            27 => any::<[u8;32]>().prop_map(|bytes| Scalar::from_bytes_mod_order(bytes).set_secrecy::<S>()),
        ]
        .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<NonNormal, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Scalar>()
            .prop_map(|scalar| g!(scalar * G).set_secrecy())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Normal, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Point<NonNormal, S>>()
            .prop_map(|point| point.normalize())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<EvenY, S, NonZero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Point<Normal, S>>()
            .prop_map(|point| point.into_point_with_even_y().0)
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<NonNormal, S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Scalar<S, Zero>>()
            .prop_map(|scalar| g!(scalar * G).set_secrecy())
            .boxed()
    }
}

impl<S: Secrecy> Arbitrary for Point<Normal, S, Zero> {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        any::<Point<NonNormal, S, Zero>>()
            .prop_map(|point| point.normalize())
            .boxed()
    }
}
