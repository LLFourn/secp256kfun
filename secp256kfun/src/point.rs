use crate::{
    backend::{self, BackendPoint},
    hash::HashInto,
    marker::*,
    op, Scalar, XOnly,
};
use core::marker::PhantomData;
use rand_core::{CryptoRng, RngCore};

/// A point on the secp256k1 elliptic curve.
///
/// A point is any (x,y) cooridinate that satisfies:
///
/// `y^2 = 3*x + 7 mod p`
///
/// where `p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F`
///
/// and the notional _point at infinity_ (the _zero_ element).
///
/// ## Markers
///
/// A `Point<T,S,Z>` has three types parameters.
///
/// - `T`: A [`PointType`] used to reason about what the point can do and to specialize point operations.
/// - `S`: A [`Secrecy`] to determine whether operations on this point should be done in constant-time or not.
/// - `Z`: A [`ZeroChoice`] to mark whether it is possible that this point is the point at infinity.
///
/// [`PointType`]: crate::marker::PointType
/// [`Secrecy`]: crate::marker::Secrecy
/// [`ZeroChoice`]: crate::marker::ZeroChoice

#[derive(Default)]
pub struct Point<T = Normal, S = Public, Z = NonZero>(
    pub(crate) backend::Point,
    pub(crate) T,
    PhantomData<(Z, S)>,
);

impl<Z, S, T: Clone> Clone for Point<T, S, Z> {
    fn clone(&self) -> Self {
        Point::from_inner(self.0.clone(), self.1.clone())
    }
}

impl Point<Normal, Public, NonZero> {
    pub fn from_bytes(bytes: [u8; 33]) -> Option<Self> {
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&bytes[1..]);
        let y_odd = match bytes[0] {
            2 => false,
            3 => true,
            _ => return None,
        };

        backend::Point::norm_from_bytes_y_oddness(x_bytes, y_odd)
            .map(|p| Point::from_inner(p, Normal))
    }

    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 33];
        rng.fill_bytes(&mut bytes[..]);
        bytes[0] &= 0x01;
        bytes[0] |= 0x02;
        Self::from_bytes(bytes).unwrap_or_else(|| Self::random(rng))
    }
}

impl<T, S> Point<T, S, NonZero> {
    pub fn into_point_with_y_choice<Y: YChoice>(self) -> (Point<Y, S, NonZero>, bool) {
        use crate::op::PointUnary;
        let normalized = self.mark::<Normal>();
        let needs_negation = !Y::norm_point_matches(&normalized);
        let negated = normalized.conditional_negate(needs_negation);
        (Point::from_inner(negated, Y::default()), needs_negation)
    }
}

impl<Y: YChoice> Point<Y, Public, NonZero> {
    pub fn from_scalar_mul(base: &Point<impl PointType>, scalar: &mut Scalar) -> Self {
        let point = crate::op::scalar_mul_point(scalar, base).mark::<Normal>();
        let (point, needs_negation) = point.into_point_with_y_choice::<Y>();
        scalar.conditional_negate(needs_negation);
        point
    }
}

impl<T, S, Z> Point<T, S, Z> {
    // #[must_use]
    // pub fn mark<M: ChangeMark<Self>>(self) -> M::Out {
    //     M::change_mark(self)
    // }

    /// Returns true if this point the [identity element][1] of the group A.K.A. the point at infinity.
    ///
    /// [1]: https://en.wikipedia.org/wiki/Identity_element.
    pub fn is_zero(&self) -> bool {
        backend::BackendPoint::is_zero(&self.0)
    }

    pub(crate) const fn from_inner(backend_point: backend::Point, point_type: T) -> Self {
        Point(backend_point, point_type, PhantomData)
    }

    #[must_use]
    pub fn conditional_negate(&self, cond: bool) -> Point<T::NegationType, S, Z>
    where
        T: PointType,
    {
        Point::from_inner(
            op::PointUnary::conditional_negate(self.clone(), cond),
            T::NegationType::default(),
        )
    }
}

impl Point<Normal, Public, Zero> {
    pub fn zero() -> Self {
        Self::from_inner(backend::Point::zero(), Normal)
    }
}

impl<Z, T> Point<T, Public, Z> {
    /// Checks if this point's x-coordiante is the equal to the scalar mod the
    /// curve order. This is only useful for ECDSA implementations.
    pub fn x_eq_scalar<Z2>(&self, scalar: &Scalar<Public, Z2>) -> bool {
        crate::backend::VariableTime::point_x_eq_scalar(&self.0, &scalar.0)
    }
}

impl<T: PointType, S, Z> core::ops::Neg for Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        Point::from_inner(op::PointUnary::negate(self), T::NegationType::default())
    }
}

impl<T: PointType, S, Z> core::ops::Neg for &Point<T, S, Z> {
    type Output = Point<T::NegationType, S, Z>;
    fn neg(self) -> Self::Output {
        Point::from_inner(
            op::PointUnary::negate(self.clone()),
            T::NegationType::default(),
        )
    }
}

impl<T1, S1, Z1, T2, S2, Z2> PartialEq<Point<T2, S2, Z2>> for Point<T1, S1, Z1> {
    fn eq(&self, rhs: &Point<T2, S2, Z2>) -> bool {
        op::PointBinary::eq((self, rhs))
    }
}

impl<Y: YChoice> From<XOnly<Y>> for Point<Y, Public, NonZero> {
    fn from(xonly: XOnly<Y>) -> Self {
        Y::xonly_into_point(xonly)
    }
}

impl<S, T: Normalized> Point<T, S, NonZero> {
    pub fn coordinates(&self) -> ([u8; 32], [u8; 32]) {
        backend::BackendPoint::norm_to_coordinates(&self.0)
    }

    pub fn to_bytes(&self) -> [u8; 33] {
        let mut bytes = [0u8; 33];
        let (x, y) = self.coordinates();
        bytes[0] = y[31] & 0x01;
        bytes[0] |= 0x02;
        bytes[1..].copy_from_slice(&x[..]);
        bytes
    }

    pub fn to_bytes_uncompressed(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let (x, y) = self.coordinates();
        bytes[0..32].copy_from_slice(x.as_ref());
        bytes[32..64].copy_from_slice(y.as_ref());
        bytes
    }

    pub fn to_xonly(&self) -> XOnly<T::YType> {
        XOnly::from_inner(backend::BackendPoint::norm_to_xonly(&self.0))
    }
}

impl<T: Normalized, S> HashInto for Point<T, S, NonZero> {
    fn hash_into(&self, hash: &mut impl digest::Digest) {
        hash.input(self.to_bytes().as_ref())
    }
}

crate::impl_display_debug! {
    fn to_bytes<S,Z>(point: &Point<Jacobian, S, Z>) -> Result<[u8;64], &str> {
        match Clone::clone(*point).mark::<(Normal, NonZero)>() {
            Some(nzpoint) => Ok(nzpoint.to_bytes_uncompressed()),
            None => Err("Zero"),
        }
    }
}

crate::impl_display_debug! {
    fn to_bytes<T: Normalized, S,Z>(point: &Point<T, S, Z>) -> Result<[u8;64], &str> {
        match Clone::clone(*point).mark::<NonZero>() {
            Some(nzpoint) => Ok(nzpoint.to_bytes_uncompressed()),
            None => Err("Zero"),
        }
    }
}

crate::impl_serialize! {
    fn to_bytes<S>(point: &Point<Normal, S, NonZero>) -> [u8;33] {
        point.to_bytes()
    }
}

// For YChoice points they serialize and deserialize like XOnlys except when
// deserializing we don't throw away y-coordinate
crate::impl_serialize! {
    fn to_bytes<S,T: YChoice>(point: &Point<T, S, NonZero>) -> [u8;32] {
        point.to_xonly().as_bytes().clone()
    }
}

crate::impl_fromstr_deserailize! {
    name => "secp256k1 x-coordinate",
    fn from_bytes<S: Secrecy,T: YChoice>(bytes: [u8;32]) -> Option<Point<T,S, NonZero>> {
        T::bytes_into_point(bytes)
    }
}

crate::impl_fromstr_deserailize! {
    name => "secp256k1 x-coordinate",
    fn from_bytes<S: Secrecy>(bytes: [u8;33]) -> Option<Point<Normal,S, NonZero>> {
        Point::from_bytes(bytes).map(|point| point.mark::<S>())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{g, G};

    macro_rules! expression_eq {
        ([$($lhs:tt)*] == [$($rhs:tt)*]) => {{
            use core::borrow::Borrow;
            assert_eq!(g!($($lhs)*).borrow(),g!($($rhs)*).borrow(), stringify!($($lhs)* == $($rhs)*))
        }};
        ([$($lhs:tt)*] != [$($rhs:tt)*]) => {{
            use core::borrow::Borrow;
            assert_ne!(g!($($lhs)*).borrow(),g!($($rhs)*).borrow(), stringify!($($lhs)* != $($rhs)*))
        }};
    }

    macro_rules! operations_test {
        ($P:expr) => {{
            let P = $P;
            let I = Point::zero();

            expression_eq!([P] == [P]);
            expression_eq!([P] != [I]);
            expression_eq!([P] == [P]);
            expression_eq!([1 * P] == [P]);
            expression_eq!([-1 * P] == [-P]);

            expression_eq!([P - P] == [I]);
            expression_eq!([I + P] == [P]);

            expression_eq!([P + I] == [P]);
            expression_eq!([I - P] == [-P]);
            expression_eq!([P - I] == [P]);
            expression_eq!([P + P] != [P]);
            expression_eq!([0 * P] == [I]);
            expression_eq!([-(P + P)] == [-P + -P]);
            expression_eq!([P + P] == [2 * P]);
            expression_eq!([P + P + P] == [3 * P]);
            expression_eq!([-P - P - P] == [-3 * P]);

            let add_100_times = {
                let P = P.clone().mark::<(Zero, Jacobian)>();
                let I = g!(P - P);
                assert_eq!(I, Point::zero());
                (0..100).fold(I, |acc, _| g!(acc + P))
            };

            expression_eq!([add_100_times] == [100 * P]);

            let undo = { (0..100).fold(add_100_times.clone(), |acc, _| g!(acc - P)) };

            expression_eq!([undo] == [add_100_times - 100 * P]);
            expression_eq!([undo] == [I]);
        }};
    }

    crate::test_plus_wasm! {
        fn operations() {
            operations_test!(G.clone());
            operations_test!(G.clone().mark::<Secret>());
            operations_test!(G.clone().mark::<(Public, Jacobian)>());
            operations_test!(G.clone().mark::<(Secret, Jacobian)>());
            operations_test!(Point::random(&mut rand::thread_rng()).mark::<Secret>());
            operations_test!(Point::random(&mut rand::thread_rng()).mark::<Public>());
            let P = crate::op::scalar_mul_point(&Scalar::random(&mut rand::thread_rng()).mark::<Secret>(),G);
            operations_test!(&P);
            operations_test!(P.mark::<Public>())
        }

        fn bug_make_y_choice_then_negate() {
            for _ in 0..20 {
                let (point_even, _) =
                    Point::random(&mut rand::thread_rng()).into_point_with_y_choice::<EvenY>();
                let _ = point_even.to_bytes_uncompressed();
                let (point_square, _) =
                    Point::random(&mut rand::thread_rng()).into_point_with_y_choice::<SquareY>();
                let _ = point_square.to_bytes_uncompressed();
            }
        }

        fn G_to_and_from_bytes() {
            use core::str::FromStr;
            assert_eq!(
                G.to_bytes_uncompressed().as_ref(),
                hex_literal::hex!("79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8").as_ref(),
                "G.to_bytes_uncompressed()"
            );

            assert_eq!(
                G.to_bytes().as_ref(),
                hex_literal::hex!("02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798").as_ref(),
                "G.to_bytes()"
            );

            assert_eq!(
                &Point::from_bytes(hex_literal::hex!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")).unwrap(),
                G
            );

            assert_eq!(
                &Point::from_bytes(hex_literal::hex!("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")).unwrap(),
                &Point::<Normal,Secret,_>::from_str("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap(),
            );

            let neg_G = -G;

            assert_eq!(
                neg_G.to_bytes_uncompressed().as_ref(),
                // raku -e 'say (-0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 mod 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F).base(16).comb().batch(8).map(*.join).join(" ")'
                hex_literal::hex!(
                    "79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 B7C52588 D95C3B9A A25B0403 F1EEF757 02E84BB7 597AABE6 63B82F6F 04EF2777"
                )
                    .as_ref(),
                "-G.to_bytes_uncompressed()"
            );


            assert_eq!(
                neg_G.to_bytes().as_ref(),
                hex_literal::hex!("03 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798").as_ref(),
                "-G.to_bytes()"
            );
        }
        fn zero_cases() {
            let I = Point::zero();
            assert!(I.is_zero());
            expression_eq!([I] == [I]);
            expression_eq!([I] == [-I]);
            expression_eq!([I + I] ==  [I]);
            expression_eq!([I - I] ==  [I]);
        }


        #[cfg(feature = "alloc")]
        fn fmt_debug() {
            let random_point = Point::random(&mut rand::thread_rng());
            assert!(format!("{:?}", random_point).starts_with("Point<Normal,Public,NonZero>"));
            let mult_point = g!({Scalar::random(&mut rand::thread_rng())} * G);
            assert!(format!("{:?}", mult_point).starts_with("Point<Jacobian,Public,NonZero>"));
        }
    }
}
