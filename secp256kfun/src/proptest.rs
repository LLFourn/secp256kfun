//! Functions used to generate test data for property-based testing with [`proptest`].
//!
//! [`proptest`]: https://github.com/altsysrq/proptest
use crate::{marker::*, Point, Scalar, G};
use ::proptest::prelude::*;

prop_compose! {
    /// Generate a random `Scalar`.
    pub fn scalar()(
        bytes in any::<[u8; 32]>(),
    ) -> Scalar<Secret, Zero> {
        Scalar::from_bytes_mod_order(bytes)
    }
}

prop_compose! {
    /// Generate a random, non-zero `Scalar`.
    pub fn non_zero_scalar()(
        bytes in any::<[u8; 32]>()
            .prop_filter("Value cannot be zero",
                         |bytes| bytes != &[0u8; 32]),
    ) -> Scalar {
        Scalar::from_bytes_mod_order(bytes).mark::<NonZero>().unwrap()
    }
}

prop_compose! {
    /// Generate a random `Point`.
    pub fn point()(
        mut x in non_zero_scalar(),
    ) -> Point {
        Point::from_scalar_mul(G, &mut x).mark::<Normal>()
    }
}
