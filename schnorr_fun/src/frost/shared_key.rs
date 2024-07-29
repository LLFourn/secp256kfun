use core::{marker::PhantomData, ops::Deref};

use alloc::vec::Vec;
use secp256kfun::{poly, prelude::*};

use super::PartyIndex;
/// A polynomial
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(crate::fun::serde::Serialize),
    serde(crate = "crate::fun::serde")
)]
#[cfg_attr(
    feature = "bincode",
    derive(crate::fun::bincode::Encode),
    bincode(crate = "crate::fun::bincode",)
)]
pub struct SharedKey<T = Normal, Z = NonZero> {
    /// The public point polynomial that defines the access structure to the FROST key.
    point_polynomial: Vec<Point<Normal, Public, Zero>>,
    #[cfg_attr(feature = "serde", serde(skip))]
    ty: PhantomData<(T, Z)>,
}

impl<T: PointType, Z: ZeroChoice> SharedKey<T, Z> {
    /// The verification shares of each party in the key.
    ///
    /// The verification share is the image of their secret share.
    pub fn verification_share(&self, index: PartyIndex) -> Point<NonNormal, Public, Zero> {
        poly::point::eval(&self.point_polynomial, index)
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> usize {
        self.point_polynomial.len()
    }

    /// The public image of the key's polynomial on the elliptic curve.
    ///
    /// Note: the first coefficient (index `0`) is guaranteed to be non-zero but the coefficients
    /// may be.
    pub fn point_polynomial(&self) -> Vec<Point<Normal, Public, Zero>> {
        self.point_polynomial.clone()
    }

    /// Type unsafe: you have to make sure the polynomial fits the type parameters
    fn from_inner(point_polynomial: Vec<Point<Normal, Public, Zero>>) -> Self {
        SharedKey {
            point_polynomial,
            ty: PhantomData,
        }
    }

    /// Converts a `SharedKey` that's was marked as `Zero` to `NonZero`.
    ///
    /// If the shared key *was* actually zero ([`is_zero`] returns true) it returns `None`.
    ///
    /// [`is_zero`]: Self::is_zero
    pub fn non_zero(self) -> Option<SharedKey<Normal, NonZero>> {
        if self.point_polynomial[0].is_zero() {
            return None;
        }

        Some(SharedKey::from_inner(self.point_polynomial))
    }

    /// Whether the shared key is actually zero. i.e. the first coefficient of the sharing polynomial [`is_zero`].
    ///
    /// [`is_zero`]: secp256kfun::Point::is_zero
    pub fn is_zero(&self) -> bool {
        self.point_polynomial[0].is_zero()
    }

    /// Adds a scalar `tweak` to the shared key.
    ///
    /// The returned `SharedKey<Normal, Zero>` represents a sharing of the original value + `tweak`.
    ///
    /// This is useful for deriving unhardened child frost keys from a master frost public key using
    /// [BIP32]. In cases like this since you know that the tweak was computed from a hash of the
    /// original key you call [`non_zero`] and unwrap the `Option` since zero is computationally
    /// unreachable.
    ///
    /// In order for `PairedSecretShare` s to be valid against the new key they will have to apply the same operation.
    ///
    /// If you want to apply an "x-only" tweak you need to call this then [`non_zero`] and finally [`into_xonly`].
    ///
    /// [BIP32]: https://bips.xyz/32
    /// [`non_zero`]: Self::non_zero
    /// [`into_xonly`]: Self::into_xonly
    #[must_use]
    pub fn homomorphic_add(
        mut self,
        tweak: Scalar<impl Secrecy, impl ZeroChoice>,
    ) -> SharedKey<Normal, Zero> {
        self.point_polynomial[0] = g!(self.point_polynomial[0] + tweak * G).normalize();
        SharedKey::from_inner(self.point_polynomial)
    }

    /// Negates the polynomial
    #[must_use]
    pub fn homomorphic_negate(mut self) -> SharedKey<Normal, Z> {
        poly::point::negate(&mut self.point_polynomial);
        SharedKey::from_inner(self.point_polynomial)
    }

    /// Multiplies the shared key by a scalar.
    ///
    /// In order for a [`PairedSecretShare`] to be valid against the new key they will have to apply
    /// [the same operation](super::PairedSecretShare::homomorphic_mul).
    ///
    /// [`PairedSecretShare`]: super::PairedSecretShare
    #[must_use]
    pub fn homomorphic_mul(mut self, tweak: Scalar<impl Secrecy>) -> SharedKey<Normal, Z> {
        for coeff in &mut self.point_polynomial {
            *coeff = g!(tweak * coeff.deref()).normalize();
        }
        SharedKey::from_inner(self.point_polynomial)
    }

    /// Create a shared key from a subset of verification shares.
    ///
    /// If all the verification shares are correct and you have at least a threshold of them then
    /// you'll get the right answer. If you put in a wrong share you won't get the right answer!
    ///
    /// ## Security
    ///
    /// ⚠ You can't just take any random points you want and pass them in here and hope it's secure.
    /// They need to be from a securely generated key.
    pub fn from_verification_shares(
        shares: &[(PartyIndex, Point<impl PointType, Public, impl ZeroChoice>)],
    ) -> SharedKey<Normal, Z> {
        let poly = poly::point::interpolate(shares);
        let poly = poly::point::normalize(poly);
        SharedKey::from_inner(poly.collect())
    }
}

impl SharedKey<Normal> {
    /// Convert the key into a BIP340 "x-only" SharedKey.
    ///
    /// This is the [BIP340] compatible version of the key which you can put in a segwitv1 output.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn into_xonly(mut self) -> SharedKey<EvenY> {
        let needs_negation = !self.key().is_y_even();
        if needs_negation {
            self = self.homomorphic_negate();
            debug_assert!(self.key().is_y_even());
        }

        SharedKey::from_inner(self.point_polynomial)
    }
}

impl<Z: ZeroChoice> SharedKey<Normal, Z> {
    /// The key that was shared with this polynomial defining the sharing.
    ///
    /// This is the first coefficient of the polynomial.
    pub fn key(&self) -> Point<Normal, Public, Z> {
        Z::cast_point(self.point_polynomial[0]).expect("invariant")
    }
    /// Constructor to create a from a vector of points where each item represent a polynomial
    /// coefficient.
    ///
    /// Returns `None` if the first coefficient is [`Point::zero`].
    pub fn from_poly(poly: Vec<Point<Normal, Public, Zero>>) -> Option<Self> {
        if poly.is_empty() {
            return None;
        }

        if poly[0].is_zero() && !Z::is_zero() {
            return None;
        }

        Some(SharedKey::from_inner(poly))
    }
}

impl SharedKey<EvenY> {
    /// The public key that would have signatures verified against for this shared key.
    pub fn key(&self) -> Point<EvenY> {
        let (even_y_point, _needs_negation) = self.point_polynomial[0]
            .non_zero()
            .expect("invariant")
            .into_point_with_even_y();
        assert!(!_needs_negation);
        even_y_point
    }
}

#[cfg(feature = "bincode")]
impl crate::fun::bincode::Decode for SharedKey<Normal> {
    fn decode<D: secp256kfun::bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, secp256kfun::bincode::error::DecodeError> {
        let poly = Vec::<Point<Normal, Public, Zero>>::decode(decoder)?;

        if poly[0].is_zero() {
            return Err(secp256kfun::bincode::error::DecodeError::Other(
                "first coefficient of a frost polynomial can't be zero",
            ));
        }

        Ok(SharedKey {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> crate::fun::serde::Deserialize<'de> for SharedKey<Normal> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: secp256kfun::serde::Deserializer<'de>,
    {
        let poly = Vec::<Point<Normal, Public, Zero>>::deserialize(deserializer)?;

        if poly[0].is_zero() {
            return Err(crate::fun::serde::de::Error::custom(
                "first coefficient of a frost polynomial can't be zero",
            ));
        }

        Ok(Self {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }
}

#[cfg(feature = "bincode")]
crate::fun::bincode::impl_borrow_decode!(SharedKey<Normal>);
