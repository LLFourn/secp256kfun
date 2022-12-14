//! Scalar arithmetic (integers mod the secp256k1 group order)
use crate::{backend, hash::HashInto, marker::*, op};
use core::{
    marker::PhantomData,
    ops::{AddAssign, MulAssign, SubAssign},
};
use digest::{generic_array::typenum::U32, Digest};
use rand_core::RngCore;

/// A secp256k1 scalar (an integer mod the curve order)
///
/// The term _scalar_ comes from interpreting the secp256k1 elliptic curve group
/// as a [_vector space_][4] with a point as a notional single element vector
/// and the field of integers modulo the curve order as its
/// scalars. Specifically, a `Scalar` represents an integer modulo the curve
/// order `q` where
///
/// `q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`
///
/// The thing that makes secp256k1 and other elliptic curves useful for
/// cryptography is that scalar _multiplication_ can be done efficiently:
///
/// ```
/// use secp256kfun::{g, Scalar, G};
/// let x = Scalar::random(&mut rand::thread_rng());
/// let X = g!(x * G);
/// ```
///
/// But finding `x` from `(X,G)` is hard because there is no known efficient
/// algorithm to divide `X` by `G` to get `x`. This is known as the elliptic
/// curve [_discrete logarithm problem_][2].  Because of this, scalars are often
/// used as a _secret keys_ with the points obtained by multiplying them by [`G`] as
/// their corresponding _public keys_.
///
/// [`G`]: crate::G
///
/// # Markers
///
/// A `Scalar<S,Z>` has two markers:
///
/// - `S`: A [`Secrecy`] to determine whether operations on this scalar should be done in constant time or not. By default scalars are [`Secret`] so operations run in constant-time.
/// - `Z`: A [`ZeroChoice`] to keep track of whether the point might be zero or is guaranteed to non-zero.
///
///
/// [1]: https://en.wikipedia.org/wiki/One-way_function
/// [2]: https://en.wikipedia.org/wiki/Discrete_logarithm
/// [3]: https://en.wikipedia.org/wiki/Group_isomorphism
/// [4]: https://en.wikipedia.org/wiki/Vector_space#Definition
/// [`Secrecy`]: crate::marker::Secrecy
/// [`Secret`]: crate::marker::Secret
/// [`ZeroChoice]: crate::marker::ZeroChoice
pub struct Scalar<S = Secret, Z = NonZero>(pub(crate) backend::Scalar, PhantomData<(Z, S)>);

impl<Z> Copy for Scalar<Public, Z> {}

impl<S, Z> Clone for Scalar<S, Z> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), self.1.clone())
    }
}

impl<Z> core::hash::Hash for Scalar<Public, Z> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state)
    }
}

impl<Z, S> Scalar<S, Z> {
    /// Serializes the scalar to its 32-byte big-endian representation
    pub fn to_bytes(&self) -> [u8; 32] {
        backend::BackendScalar::to_bytes(&self.0)
    }

    /// Negates the scalar in-place if `cond` is true.
    pub fn conditional_negate(&mut self, cond: bool) {
        op::scalar_conditional_negate(self, cond)
    }

    /// Returns whether the scalar is greater than the `curve_order`/2.
    pub fn is_high(&self) -> bool {
        op::scalar_is_high(self)
    }

    /// Returns true if the scalar is equal to zero
    pub fn is_zero(&self) -> bool {
        op::scalar_is_zero(self)
    }

    pub(crate) fn from_inner(inner: backend::Scalar) -> Self {
        Scalar(inner, PhantomData)
    }

    /// Set the secrecy of the `Scalar` to the type parameter.
    pub fn set_secrecy<SNew>(self) -> Scalar<SNew, Z> {
        Scalar::from_inner(self.0)
    }

    /// Set the secrecy of the Scalar to `Public`.
    ///
    /// A scalar should be set to public when the adversary is meant to know it as part of the protocol.
    pub fn public(self) -> Scalar<Public, Z> {
        Scalar::from_inner(self.0)
    }

    /// Set the secrecy of the Scalar to `Secret`.
    ///
    /// A scalar should be set to secret when the adversary is not meant to know about it in the
    /// protocol.
    pub fn secret(self) -> Scalar<Secret, Z> {
        Scalar::from_inner(self.0)
    }

    /// Mark the scalar as possibly being `Zero` (even though it isn't).
    ///
    /// This is useful in accumulator variables where although the initial value is non-zero, every
    /// sum addition after that might make it zero so it's necessary to start off with `Zero` marked
    /// scalar.
    pub fn mark_zero(self) -> Scalar<S, Zero> {
        Scalar::from_inner(self.0)
    }
}

impl<S> Scalar<S, NonZero> {
    /// Returns the multiplicative inverse of the scalar modulo the curve order.
    /// # Example
    ///
    /// ```
    /// use secp256kfun::{marker::*, s, Scalar};
    /// let a = Scalar::random(&mut rand::thread_rng());
    /// let a_inverse = a.invert();
    /// assert_eq!(s!(a * a_inverse), s!(1));
    /// ```
    pub fn invert(&self) -> Self {
        op::scalar_invert(self)
    }

    /// Returns the integer `1` as a `Scalar`.
    pub fn one() -> Self {
        Scalar::from(1).non_zero().unwrap()
    }

    /// Returns the integer -1 (modulo the curve order) as a `Scalar`.
    pub fn minus_one() -> Self {
        Self::from_inner(backend::BackendScalar::minus_one())
    }
}

impl Scalar<Secret, NonZero> {
    /// Generates a random scalar from randomness taken from a caller provided
    /// cryptographically secure random number generator.
    /// # Example
    /// ```
    /// use secp256kfun::{g, Scalar, G};
    /// let secret_scalar = Scalar::random(&mut rand::thread_rng());
    /// let public_point = g!(secret_scalar * G);
    /// ```
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Scalar::from_bytes_mod_order(bytes)
            .non_zero()
            .expect("computationally unreachable")
    }
    /// Converts the output of a 32-byte hash into a scalar by reducing it modulo the curve order.
    /// # Example
    /// ```
    /// use digest::Digest;
    /// use secp256kfun::Scalar;
    /// let mut hash = sha2::Sha256::default();
    /// hash.update(b"Chancellor on brink of second bailout for banks".as_ref());
    /// let scalar = Scalar::from_hash(hash);
    /// # assert_eq!(
    /// #     scalar.to_bytes(),
    /// #     secp256kfun::hex::decode_array("8131e6f4b45754f2c90bd06688ceeabc0c45055460729928b4eecf11026a9e2d").unwrap()
    /// # );
    /// ```
    pub fn from_hash(hash: impl Digest<OutputSize = U32>) -> Self {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash.finalize().as_slice());
        Scalar::from_bytes_mod_order(bytes)
            .non_zero()
            .expect("computationally unreachable")
    }

    /// Converts a [`NonZeroU32`] into a `Scalar<Secret,NonZero>`.
    ///
    /// [`NonZeroU32`]: core::num::NonZeroU32
    pub fn from_non_zero_u32(int: core::num::NonZeroU32) -> Self {
        Self::from_inner(backend::BackendScalar::from_u32(int.get()))
    }
}

impl<S> Scalar<S, Zero> {
    /// Converts a scalar marked with `Zero` to `NonZero`.
    ///
    /// Returns `None` in the case that the scalar was in fact zero.
    pub fn non_zero(self) -> Option<Scalar<S, NonZero>> {
        if self.is_zero() {
            None
        } else {
            Some(Scalar::from_inner(self.0))
        }
    }

    /// Returns the zero scalar.
    /// # Example
    /// ```
    /// # use secp256kfun::{Scalar, s, marker::*};
    /// let x = Scalar::random(&mut rand::thread_rng());
    /// let zero = Scalar::<Secret,_>::zero();
    /// assert_eq!(s!(zero * x), zero);
    /// assert_eq!(s!(x + zero), x);
    pub fn zero() -> Self {
        Self::from_inner(backend::BackendScalar::zero())
    }

    /// Converts 32 bytes into a scalar by reducing it modulo the curve order `q`.
    /// # Example
    /// ```
    /// # use core::convert::TryInto;
    /// use secp256kfun::{hex, marker::*, s, Scalar};
    /// let scalar = Scalar::<Secret, _>::from_bytes_mod_order(*b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    /// assert_eq!(scalar.to_bytes(), *b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    /// let scalar_overflowed = Scalar::<Secret, _>::from_bytes_mod_order(
    ///     hex::decode_array("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142")
    ///         .unwrap(),
    /// );
    /// assert_eq!(scalar_overflowed, s!(1))
    /// ```
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self::from_inner(backend::BackendScalar::from_bytes_mod_order(bytes))
    }

    /// Exactly like [`from_bytes_mod_order`] except
    /// it operates on a 32-byte slice rather than an array.  If the slice is
    /// not 32 bytes long then the function returns `None`.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, Scalar};
    /// let bytes = b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    /// assert!(Scalar::<Secret, _>::from_slice_mod_order(&bytes[..31]).is_none());
    /// assert_eq!(
    ///     Scalar::<Secret, _>::from_slice_mod_order(&bytes[..]).unwrap(),
    ///     Scalar::<Secret, _>::from_bytes_mod_order(*bytes)
    /// );
    /// ```
    ///
    /// [`from_bytes_mod_order`]: crate::Scalar::from_bytes_mod_order
    pub fn from_slice_mod_order(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Self::from_bytes_mod_order(bytes))
    }

    /// Creates a scalar from 32 big-endian encoded bytes. If the bytes
    /// represent an integer greater than or equal to the curve order then it returns `None`.
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{marker::*, Scalar};
    /// assert!(Scalar::<Secret, _>::from_bytes([0u8; 32]).is_some());
    /// assert!(Scalar::<Secret, _>::from_bytes([255u8; 32]).is_none());
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        backend::BackendScalar::from_bytes(bytes).map(Self::from_inner)
    }

    /// Creates a scalar from 32 big-endian encoded bytes in a slice. If the
    /// length of the slice is not 32 or the bytes represent an integer greater
    /// than or equal to the curve order then it returns `None`.
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&slice);
        Self::from_bytes(bytes)
    }
}

impl<Z1, Z2, S1, S2> PartialEq<Scalar<S2, Z2>> for Scalar<S1, Z1> {
    fn eq(&self, rhs: &Scalar<S2, Z2>) -> bool {
        crate::op::scalar_eq(self, rhs)
    }
}

impl<Z, S> Eq for Scalar<Z, S> {}

impl<S> From<u32> for Scalar<S, Zero> {
    fn from(int: u32) -> Self {
        Self::from_inner(backend::BackendScalar::from_u32(int))
    }
}

crate::impl_fromstr_deserialize! {
    name => "non-zero secp256k1 scalar",
    fn from_bytes<S>(bytes: [u8;32]) -> Option<Scalar<S,NonZero>> {
        Scalar::from_bytes(bytes).and_then(|scalar| scalar.set_secrecy::<S>().non_zero())
    }
}

crate::impl_display_debug_serialize! {
    fn to_bytes<Z,S>(scalar: &Scalar<S,Z>) -> [u8;32] {
        scalar.to_bytes()
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 scalar",
    fn from_bytes<S>(bytes: [u8;32]) -> Option<Scalar<S,Zero>> {
        Scalar::from_bytes(bytes).map(|scalar| scalar.set_secrecy::<S>())
    }
}

impl<S, Z> core::ops::Neg for Scalar<S, Z> {
    type Output = Scalar<S, Z>;

    fn neg(self) -> Self::Output {
        crate::op::scalar_negate(&self)
    }
}

impl<S, Z> core::ops::Neg for &Scalar<S, Z> {
    type Output = Scalar<S, Z>;

    fn neg(self) -> Self::Output {
        crate::op::scalar_negate(self)
    }
}

impl<S, Z> HashInto for Scalar<S, Z> {
    fn hash_into(self, hash: &mut impl digest::Digest) {
        hash.update(&self.to_bytes())
    }
}

impl<S> Default for Scalar<S, Zero>
where
    S: Secrecy,
{
    fn default() -> Self {
        Scalar::<S, _>::zero()
    }
}

impl<S> Default for Scalar<S, NonZero>
where
    S: Secrecy,
{
    fn default() -> Self {
        Self::from_inner(backend::BackendScalar::from_u32(1))
    }
}

impl<SL, SR, ZR> AddAssign<Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn add_assign(&mut self, rhs: Scalar<SR, ZR>) {
        *self = crate::op::scalar_add(&self, &rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR, ZR> AddAssign<&Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn add_assign(&mut self, rhs: &Scalar<SR, ZR>) {
        *self = crate::op::scalar_add(&self, rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR, ZR> SubAssign<&Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn sub_assign(&mut self, rhs: &Scalar<SR, ZR>) {
        *self = crate::op::scalar_sub(&self, rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR, ZR> SubAssign<Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn sub_assign(&mut self, rhs: Scalar<SR, ZR>) {
        *self = crate::op::scalar_sub(&self, &rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR> MulAssign<Scalar<SR, NonZero>> for Scalar<SL, NonZero> {
    fn mul_assign(&mut self, rhs: Scalar<SR, NonZero>) {
        *self = crate::op::scalar_mul(&self, &rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR> MulAssign<&Scalar<SR, NonZero>> for Scalar<SL, NonZero> {
    fn mul_assign(&mut self, rhs: &Scalar<SR, NonZero>) {
        *self = crate::op::scalar_mul(&self, rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR, ZR: ZeroChoice> MulAssign<Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn mul_assign(&mut self, rhs: Scalar<SR, ZR>) {
        *self = crate::op::scalar_mul(&self, &rhs).set_secrecy::<SL>();
    }
}

impl<SL, SR, ZR: ZeroChoice> MulAssign<&Scalar<SR, ZR>> for Scalar<SL, Zero> {
    fn mul_assign(&mut self, rhs: &Scalar<SR, ZR>) {
        *self = crate::op::scalar_mul(&self, rhs).set_secrecy::<SL>();
    }
}

// Doing this constant time for Secret scalars is a PITA so only public for now
impl<Z1, Z2> PartialOrd<Scalar<Public, Z2>> for Scalar<Public, Z1> {
    fn partial_cmp(&self, other: &Scalar<Public, Z2>) -> Option<core::cmp::Ordering> {
        Some(self.to_bytes().cmp(&other.to_bytes()))
    }
}

impl<Z> Ord for Scalar<Public, Z> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{hex, op, s};
    use proptest::prelude::*;
    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[cfg(feature = "serde")]
    #[test]
    fn scalar_serde_rountrip() {
        let original = Scalar::random(&mut rand::thread_rng());
        let serialized = bincode::serialize(&original).unwrap();
        let deserialized = bincode::deserialize::<Scalar>(&serialized[..]).unwrap();
        assert_eq!(deserialized, original)
    }

    #[test]
    fn random() {
        let scalar_1 = Scalar::random(&mut rand::thread_rng());
        let scalar_2 = Scalar::random(&mut rand::thread_rng());
        assert_ne!(scalar_1, scalar_2);
    }

    proptest! {
        #[test]
        fn invert(x in any::<Scalar>(), y in any::<Scalar<Public>>()) {
            assert_eq!(s!(x * { x.invert() }), s!(1));
            assert_eq!(s!(y * { y.invert() }), s!(1));
        }

        #[test]
        fn sub(a in any::<Scalar>(),
               b in any::<Scalar<Public>>(),
               c in any::<Scalar<Public,Zero>>(),
               d in any::<Scalar<Secret,Zero>>(),
        ) {
            assert_eq!(s!(a - a), s!(0));
            assert_eq!(s!(b - b), s!(0));
            assert_eq!(s!(c - c), s!(0));
            assert_eq!(s!(d - d), s!(0));
            assert_eq!(s!(a - a), s!(-a + a));
            assert_eq!(s!(a - b), s!(-b + a));
            assert_eq!(s!(a - c), s!(-c + a));
            assert_eq!(s!(a - d), s!(-d + a));

            if a != b {
                assert_ne!(s!(a - b), s!(b - a));
            }

            if c != d {
                assert_ne!(s!(c - d), s!(d - c));
            }
        }


    }

    #[test]
    fn scalar_subtraction_is_not_commutative() {
        let two = s!(2);
        let three = s!(3);
        let minus_1 = s!(-1);
        let one = s!(1);

        assert_eq!(s!(two - three), minus_1);
        assert_eq!(s!(three - two), one);
    }

    #[test]
    fn one() {
        assert_eq!(
            Scalar::<Secret, NonZero>::one(),
            Scalar::<Secret, _>::from(1u32)
        );
        assert_eq!(
            Scalar::<Secret, NonZero>::minus_one(),
            -Scalar::<Secret, NonZero>::one()
        );
        assert_eq!(
            op::scalar_mul(&s!(3), &Scalar::<Secret, NonZero>::minus_one()),
            -s!(3)
        );
    }

    #[test]
    fn zero() {
        assert_eq!(Scalar::<Secret, Zero>::zero(), Scalar::<Secret, _>::from(0));
    }

    #[test]
    fn from_slice() {
        assert!(
            Scalar::<Secret, _>::from_slice(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_ref()).is_some()
        );
        assert!(
            Scalar::<Secret, _>::from_slice(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_ref())
                .is_none()
        );

        assert!(Scalar::<Secret, _>::from_slice(
            hex::decode_array::<32>(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            )
            .unwrap()
            .as_ref()
        )
        .is_none());
    }

    #[test]
    fn from_slice_mod_order() {
        assert_eq!(
            Scalar::<Secret, _>::from_slice_mod_order(b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".as_ref())
                .unwrap()
                .to_bytes(),
            *b"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );

        assert_eq!(
            Scalar::<Secret, _>::from_slice_mod_order(
                hex::decode_array::<32>(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142"
                )
                .unwrap()
                .as_ref()
            )
            .unwrap(),
            Scalar::<Secret, _>::from(1)
        )
    }

    #[test]
    fn minus_one() {
        assert_eq!(
            Scalar::<Secret, _>::minus_one(),
            Scalar::<Secret, _>::from_bytes_mod_order(
                hex::decode_array(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"
                )
                .unwrap()
            )
        );
    }

    #[test]
    fn assign_tests() {
        let mut a = Scalar::<Secret, _>::from(42);
        let b = Scalar::<Secret, _>::from(1337).public();
        a += b;
        assert_eq!(a, Scalar::<Secret, _>::from(1379));
        a -= b;
        assert_eq!(a, Scalar::<Secret, _>::from(42));
        a *= b;
        assert_eq!(a, Scalar::<Secret, _>::from(42 * 1337));
    }
}
