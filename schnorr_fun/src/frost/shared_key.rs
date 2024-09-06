use super::{PairedSecretShare, PartyIndex, SecretShare, VerificationShare};
use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Deref};
use secp256kfun::{poly, prelude::*};

/// A polynomial where the first coefficient (constant term) is the image of a secret `Scalar` that
/// has been shared in a [Shamir's secret sharing] structure.
///
/// [Shamir's secret sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
#[derive(Clone, Debug, Eq)]
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
    /// "pair" a secret share that belongs to this shared key so you can keep track of tweaks to the
    /// public key and the secret share together.
    ///
    /// Returns `None` if the secret share is not a valid share of this key.
    pub fn pair_secret_share(&self, secret_share: SecretShare) -> Option<PairedSecretShare<T, Z>> {
        let share_image = poly::point::eval(&self.point_polynomial, secret_share.index);
        if share_image != g!(secret_share.share * G) {
            return None;
        }

        Some(PairedSecretShare::new_unchecked(
            secret_share,
            self.public_key(),
        ))
    }

    /// The threshold number of participants required in a signing coalition to produce a valid signature.
    pub fn threshold(&self) -> usize {
        self.point_polynomial.len()
    }

    /// The internal public polynomial coefficients that defines the public key and the share structure.
    ///
    /// To get the first coefficient of the polynomial typed correctly call [`public_key`].
    ///
    /// [`public_key`]: Self::public_key
    pub fn point_polynomial(&self) -> &[Point<Normal, Public, Zero>] {
        &self.point_polynomial
    }

    /// ☠ Type unsafe: you have to make sure the polynomial fits the type parameters
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

    /// The public key that has been shared.
    ///
    /// This is using *public key* in a rather loose sense. Unless it's a `SharedKey<EvenY>` then it
    /// won't be usable as an actual Schnorr [BIP340] public key.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn public_key(&self) -> Point<T, Public, Z> {
        // SAFETY: we hold the first coefficient to match the type parameters always
        let public_key = Z::cast_point(self.point_polynomial[0]).expect("invariant");
        T::cast_point(public_key).expect("invariant")
    }

    /// Encodes a `SharedKey` as the compressed encoding of each underlying polynomial coefficient
    ///
    /// i.e. call [`Point::to_bytes`] on each coefficient starting with the constant term. Note that
    /// even if it's a `SharedKey<EvenY>` the first coefficient (A.K.A the public key) will still be
    /// encoded as 33 bytes.
    ///
    /// ⚠ Unlike other secp256kfun things this doesn't exactly match the serde/bincode
    /// implementations which will length prefix the list of points.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.point_polynomial.len() * 33);
        for coeff in &self.point_polynomial {
            bytes.extend(coeff.to_bytes())
        }
        bytes
    }

    /// Decodes a `SharedKey<T,Z>` (for any `T` and `Z`) from a slice.
    ///
    /// Returns `None` if the bytes don't represent points or if the first coefficient doesn't
    /// satisfy the constraints of `T` and `Z`.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut poly = vec![];
        for point_bytes in bytes.chunks(33) {
            poly.push(Point::from_slice(point_bytes)?);
        }

        // check first coefficient satisfies both type parameters
        let first_coeff = Z::cast_point(poly[0])?;
        let _check = T::cast_point(first_coeff)?;

        Some(Self::from_inner(poly))
    }
}

impl SharedKey<Normal> {
    /// Convert the key into a BIP340 "x-only" SharedKey.
    ///
    /// This is the [BIP340] compatible version of the key which you can put in a segwitv1 output.
    ///
    /// [BIP340]: https://bips.xyz/340
    pub fn into_xonly(mut self) -> SharedKey<EvenY> {
        let needs_negation = !self.public_key().is_y_even();
        if needs_negation {
            self = self.homomorphic_negate();
            debug_assert!(self.public_key().is_y_even());
        }

        SharedKey::from_inner(self.point_polynomial)
    }
}

impl SharedKey<Normal, Zero> {
    /// Constructor to create a shared key from a vector of points where each item represent a polynomial
    /// coefficient.
    ///
    /// The resulting shared key will be `SharedKey<Normal, Zero>`. It's up to the caller to do the zero check with [`non_zero`]
    ///
    /// [`non_zero`]: Self::non_zero
    pub fn from_poly(poly: Vec<Point<Normal, Public, Zero>>) -> Self {
        if poly.is_empty() {
            // an empty polynomial is represented as a vector with a single zero item to avoid
            // panics
            return Self::from_poly(vec![Point::zero()]);
        }

        SharedKey::from_inner(poly)
    }

    /// Create a shared key from a subset of share images.
    ///
    /// If all the share images are correct and you have at least a threshold of them then you'll
    /// get the original shared key. If you put in a wrong share you won't get the right answer and
    /// there will be no error.
    ///
    /// Note that a "share image" is not a concept that we really use in the core of this library
    /// but you can get one from a share with [`SecretShare::share_image`].
    ///
    /// ## Security
    ///
    /// ⚠ You can't just take any points you want and pass them in here and hope it's secure.
    /// They need to be from a securely generated key.
    pub fn from_share_images(
        shares: &[(PartyIndex, Point<impl PointType, Public, impl ZeroChoice>)],
    ) -> Self {
        let poly = poly::point::interpolate(shares);
        let poly = poly::point::normalize(poly);
        SharedKey::from_inner(poly.collect())
    }
}

impl SharedKey<EvenY> {
    /// The verification shares of each party in the key.
    ///
    /// The verification share is the image of their secret share.
    pub fn verification_share(&self, index: PartyIndex) -> VerificationShare<NonNormal> {
        let share_image = poly::point::eval(&self.point_polynomial, index);
        VerificationShare {
            index,
            share_image,
            public_key: self.public_key(),
        }
    }
}

impl<T1, Z1, T2, Z2> PartialEq<SharedKey<T2, Z2>> for SharedKey<T1, Z1> {
    fn eq(&self, other: &SharedKey<T2, Z2>) -> bool {
        other.point_polynomial == self.point_polynomial
    }
}

#[cfg(feature = "bincode")]
impl<T: PointType, Z: ZeroChoice> crate::fun::bincode::Decode for SharedKey<T, Z> {
    fn decode<D: secp256kfun::bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, secp256kfun::bincode::error::DecodeError> {
        use secp256kfun::bincode::error::DecodeError;
        let poly = Vec::<Point<Normal, Public, Zero>>::decode(decoder)?;
        let first_coeff = Z::cast_point(poly[0]).ok_or(DecodeError::Other(
            "zero public key for non-zero shared key",
        ))?;
        let _check = T::cast_point(first_coeff)
            .ok_or(DecodeError::Other("odd-y public key for even-y shared key"))?;

        Ok(SharedKey {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }
}

#[cfg(feature = "serde")]
impl<'de, T: PointType, Z: ZeroChoice> crate::fun::serde::Deserialize<'de> for SharedKey<T, Z> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: secp256kfun::serde::Deserializer<'de>,
    {
        let poly = Vec::<Point<Normal, Public, Zero>>::deserialize(deserializer)?;

        let first_coeff = Z::cast_point(poly[0]).ok_or(crate::fun::serde::de::Error::custom(
            "zero public key for non-zero shared key",
        ))?;

        let _check = T::cast_point(first_coeff).ok_or(crate::fun::serde::de::Error::custom(
            "odd-y public key for even-y shared key",
        ))?;

        Ok(Self {
            point_polynomial: poly,
            ty: PhantomData,
        })
    }
}

#[cfg(feature = "bincode")]
crate::fun::bincode::impl_borrow_decode!(SharedKey<Normal, Zero>);
#[cfg(feature = "bincode")]
crate::fun::bincode::impl_borrow_decode!(SharedKey<Normal, NonZero>);
#[cfg(feature = "bincode")]
crate::fun::bincode::impl_borrow_decode!(SharedKey<EvenY, NonZero>);

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "bincode")]
    #[test]
    fn bincode_encoding_decoding_roundtrip() {
        use crate::fun::bincode;
        let poly_zero = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(0 * G),
                g!(1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
            ])
            .collect(),
        );
        let poly_one = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
                g!(3 * G).mark_zero(),
            ])
            .collect(),
        )
        .non_zero()
        .unwrap()
        .into_xonly();

        let poly_minus_one = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(-1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
                g!(3 * G).mark_zero(),
            ])
            .collect(),
        )
        .non_zero()
        .unwrap();

        let bytes_poly_zero =
            bincode::encode_to_vec(&poly_zero, bincode::config::standard()).unwrap();
        let bytes_poly_one =
            bincode::encode_to_vec(&poly_one, bincode::config::standard()).unwrap();
        let bytes_poly_minus_one =
            bincode::encode_to_vec(&poly_minus_one, bincode::config::standard()).unwrap();

        let (poly_zero_got, _) = bincode::decode_from_slice::<SharedKey<Normal, Zero>, _>(
            &bytes_poly_zero,
            bincode::config::standard(),
        )
        .unwrap();
        let (poly_one_got, _) = bincode::decode_from_slice::<SharedKey<EvenY, NonZero>, _>(
            &bytes_poly_one,
            bincode::config::standard(),
        )
        .unwrap();

        let (poly_minus_one_got, _) = bincode::decode_from_slice::<SharedKey<Normal, NonZero>, _>(
            &bytes_poly_minus_one,
            bincode::config::standard(),
        )
        .unwrap();

        assert!(bincode::decode_from_slice::<SharedKey<Normal, NonZero>, _>(
            &bytes_poly_zero,
            bincode::config::standard(),
        )
        .is_err());

        assert!(bincode::decode_from_slice::<SharedKey<EvenY, NonZero>, _>(
            &bytes_poly_minus_one,
            bincode::config::standard(),
        )
        .is_err());

        assert_eq!(poly_zero_got, poly_zero);
        assert_eq!(poly_one_got, poly_one);
        assert_eq!(poly_minus_one_got, poly_minus_one);
    }

    #[test]
    fn to_bytes_from_slice_roudtrip() {
        let poly_zero = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(0 * G),
                g!(1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
            ])
            .collect(),
        );
        let poly_one = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
                g!(3 * G).mark_zero(),
            ])
            .collect(),
        )
        .non_zero()
        .unwrap()
        .into_xonly();

        let poly_minus_one = SharedKey::<Normal, Zero>::from_poly(
            poly::point::normalize(vec![
                g!(-1 * G).mark_zero(),
                g!(2 * G).mark_zero(),
                g!(3 * G).mark_zero(),
            ])
            .collect(),
        )
        .non_zero()
        .unwrap();

        let bytes_poly_zero = poly_zero.to_bytes();
        let bytes_poly_one = poly_one.to_bytes();
        let bytes_poly_minus_one = poly_minus_one.to_bytes();

        let poly_zero_got = SharedKey::<Normal, Zero>::from_slice(&bytes_poly_zero[..]).unwrap();
        let poly_one_got = SharedKey::<EvenY, NonZero>::from_slice(&bytes_poly_one).unwrap();
        let poly_minus_one_got =
            SharedKey::<Normal, NonZero>::from_slice(&bytes_poly_minus_one[..]).unwrap();

        assert!(SharedKey::<Normal, NonZero>::from_slice(&bytes_poly_zero[..]).is_none());
        assert!(SharedKey::<EvenY, NonZero>::from_slice(&bytes_poly_minus_one[..]).is_none());

        assert_eq!(poly_zero_got, poly_zero);
        assert_eq!(poly_one_got, poly_one);
        assert_eq!(poly_minus_one_got, poly_minus_one);
    }
}
