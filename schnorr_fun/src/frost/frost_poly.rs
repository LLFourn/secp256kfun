use core::marker::PhantomData;

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
pub struct FrostPoly<T> {
    /// The public point polynomial that defines the access structure to the FROST key.
    point_polynomial: Vec<Point<Normal, Public, Zero>>,
    #[cfg_attr(feature = "serde", serde(skip))]
    ty: PhantomData<T>,
}

impl<T: Copy> FrostPoly<T> {
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
}

impl FrostPoly<Normal> {
    /// The key that was shared with this polynomial defining the sharing.
    ///
    /// This is the first coefficient of the polynomial.
    pub fn shared_key(&self) -> Point<Normal> {
        self.point_polynomial[0].non_zero().expect("invariant")
    }
    /// Constructor to create a `FrostPoly<Normal>` from a vector of points.
    ///
    /// Returns `None` if the first coefficient is [`Point::zero`].
    pub fn from_poly(poly: Vec<Point<Normal, Public, Zero>>) -> Option<Self> {
        if poly.is_empty() {
            return None;
        }

        if poly[0].is_zero() {
            return None;
        }

        Some(Self {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }

    /// Create a `FrostPoly` from a set of verification shares.
    pub fn from_verification_shares(
        shares: &[(PartyIndex, Point<impl PointType, Public, impl ZeroChoice>)],
    ) -> Self {
        let poly = poly::point::interpolate(shares);
        Self {
            point_polynomial: poly::point::normalize(poly).collect(),
            ty: PhantomData,
        }
    }
    /// Convert the key into a BIP340 FrostKey.
    ///
    /// This is the [BIP340] compatible version of the key which you can put in a segwitv1 output.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn into_xonly(mut self) -> FrostPoly<EvenY> {
        let needs_negation = !self.shared_key().is_y_even();
        if needs_negation {
            self.homomorphic_negate();
            debug_assert!(self.shared_key().is_y_even());
        }
        FrostPoly {
            point_polynomial: self.point_polynomial,
            ty: PhantomData,
        }
    }

    /// Adds a scalar `tweak` to the shared key.
    ///
    /// This is useful for deriving unhardened child frost keys from a master frost public key using
    /// [BIP32].
    ///
    /// In order for `PairedSecretShare` s to be valid against the new key they will have to apply the same operation.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    ///
    /// [BIP32]: https://bips.xyz/32
    #[must_use]
    pub fn homomorphic_add(mut self, tweak: Scalar<impl Secrecy, impl ZeroChoice>) -> Option<Self> {
        self.point_polynomial[0] = g!(self.point_polynomial[0] + tweak * G).normalize();
        if self.point_polynomial[0].is_zero() {
            None
        } else {
            Some(self)
        }
    }

    /// Negates the polynomial
    pub fn homomorphic_negate(&mut self) {
        poly::point::negate(&mut self.point_polynomial)
    }
}

impl FrostPoly<EvenY> {
    /// Applies an "XOnly" tweak to the FROST public key.
    /// This is how you embed a taproot commitment into a frost public key
    ///
    /// Tweak the frost public key with a scalar so that the resulting key is equal to the
    /// existing key plus `tweak * G` as an [`EvenY`] point. The tweak mutates the public key while still allowing
    /// the original set of signers to sign under the new key.
    ///
    /// ## Return value
    ///
    /// Returns a new [`FrostKey`] with the same parties but a different frost public key.
    /// In the erroneous case that the tweak is exactly equal to the negation of the aggregate
    /// secret key it returns `None`.
    pub fn xonly_homomorphic_add(
        mut self,
        tweak: Scalar<impl Secrecy, impl ZeroChoice>,
    ) -> Option<Self> {
        self.point_polynomial[0] = g!(self.point_polynomial[0] + tweak * G).normalize();

        let needs_negation = !self.point_polynomial[0].non_zero()?.is_y_even();
        if needs_negation {
            poly::point::negate(&mut self.point_polynomial);
        }

        Some(self)
    }

    /// The public key that would have signatures verified against for this shared key.
    pub fn shared_key(&self) -> Point<EvenY> {
        let (even_y_point, _needs_negation) = self.point_polynomial[0]
            .non_zero()
            .expect("invariant")
            .into_point_with_even_y();
        assert!(!_needs_negation);
        even_y_point
    }
}

#[cfg(feature = "bincode")]
impl crate::fun::bincode::Decode for FrostPoly<Normal> {
    fn decode<D: secp256kfun::bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, secp256kfun::bincode::error::DecodeError> {
        let poly = Vec::<Point<Normal, Public, Zero>>::decode(decoder)?;

        if poly[0].is_zero() {
            return Err(secp256kfun::bincode::error::DecodeError::Other(
                "first coefficient of a frost polynomial can't be zero",
            ));
        }

        Ok(FrostPoly {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de> crate::fun::serde::Deserialize<'de> for FrostPoly<Normal> {
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
crate::fun::bincode::impl_borrow_decode!(FrostPoly<Normal>);
