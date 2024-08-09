use crate::{g, marker::*, Point, Scalar, G};
/// A secret and public key pair.
///
/// ## Synopsis
///
/// ```
/// use secp256kfun::{prelude::*, KeyPair};
/// let my_secret_key = Scalar::random(&mut rand::thread_rng());
/// let my_keypair: KeyPair<Normal> = KeyPair::new(my_secret_key.clone());
/// let my_xonly_keypair: KeyPair<EvenY> = KeyPair::new_xonly(my_secret_key);
///
/// if my_keypair.public_key().is_y_even() {
///     assert_eq!(my_keypair, my_xonly_keypair);
/// } else {
///     assert_eq!(-my_keypair.public_key(), my_xonly_keypair.public_key());
/// }
/// ```
///
/// ## Description
///
/// The secret key is a [`Scalar`] and the public key is the [`Point`] resulting from multiplying
/// the scalar by [`G`].
///
/// The type parameter `T` of `KeyPair<T>` indicates the type of the public key (a `Point<T>`). It
/// can either be [`Normal`] or [`EvenY`]. The only difference between the two is that
/// `KeyPair::<EvenY>::new` is defined so that the public key always has an even y-coordinate and
/// the secret key is negated to match it (if need be).
///
///
/// [`Scalar`]: crate::Scalar
/// [`G`]: crate::G
/// [`Point`]: crate::Point
/// [`Normal`]: crate::marker::Normal
/// [`EvenY`]: crate::marker::EvenY
#[derive(Clone, Copy, Debug)]
pub struct KeyPair<T = Normal> {
    sk: Scalar,
    pk: Point<T>,
}

/// two keypairs are the same if they have the
impl<T1: PointType, T2: PointType> PartialEq<KeyPair<T2>> for KeyPair<T1> {
    fn eq(&self, other: &KeyPair<T2>) -> bool {
        self.pk == other.pk
    }
}

impl<T: PointType> Eq for KeyPair<T> {}

impl KeyPair<Normal> {
    /// Create a new `KeyPair` from a `secret_key`.
    pub fn new(secret_key: Scalar) -> Self {
        Self {
            pk: g!(secret_key * G).normalize(),
            sk: secret_key,
        }
    }
}

impl KeyPair<EvenY> {
    /// Converts a non-zero scalar to a keypair by interpreting it as a secret key, generating
    /// the corresponding public key by multiplying it by [`G`] and dropping the y-coordinate.
    ///
    /// **The secret key in the resulting keypair is not guaranteed to be the same
    /// as the input**. For half the input values the result will be the
    /// negation of it. This happens because the corresponding [`Point`] may not
    /// have an y-coordinate that is even (see [`EvenY`])
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{g, marker::*, s, KeyPair, Scalar, G};
    ///
    /// let original_secret_key = Scalar::random(&mut rand::thread_rng());
    /// let keypair = KeyPair::new_xonly(original_secret_key.clone());
    ///
    /// assert!(
    ///     &original_secret_key == keypair.secret_key()
    ///         || &-original_secret_key == keypair.secret_key()
    /// );
    /// assert!(g!(keypair.secret_key() * G).normalize().is_y_even());
    /// assert_eq!(g!(keypair.secret_key() * G), keypair.public_key());
    /// ```
    ///
    /// [`Point`]: crate::Point
    /// [`EvenY`]: crate::marker::EvenY
    pub fn new_xonly(mut secret_key: Scalar) -> Self {
        let pk = Point::even_y_from_scalar_mul(G, &mut secret_key);
        Self { sk: secret_key, pk }
    }
}

impl<T> KeyPair<T> {
    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// The public key
    pub fn public_key(&self) -> Point<T>
    where
        T: Copy,
    {
        self.pk
    }

    /// Gets a reference to the keypair as a tuple
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{KeyPair, Scalar, marker::*};
    /// let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
    /// let (secret_key, public_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, Point<T>)
    where
        T: Copy,
    {
        (&self.sk, self.pk)
    }
}

impl From<KeyPair<EvenY>> for KeyPair<Normal> {
    fn from(xonly: KeyPair<EvenY>) -> Self {
        Self {
            sk: xonly.sk,
            pk: xonly.pk.normalize(),
        }
    }
}

impl From<KeyPair<Normal>> for KeyPair<EvenY> {
    fn from(kp: KeyPair<Normal>) -> Self {
        let mut sk = kp.sk;
        let (pk, needs_negation) = kp.pk.into_point_with_even_y();
        sk.conditional_negate(needs_negation);
        Self { sk, pk }
    }
}

crate::impl_serialize! {
    fn to_bytes<T>(kp: &KeyPair<T>) -> [u8;32] {
        kp.secret_key().to_bytes()
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 scalar",
    fn from_bytes(bytes: [u8;32]) -> Option<KeyPair<Normal>> {
        let sk = Scalar::from_bytes(bytes)?.non_zero()?;
        Some(KeyPair::<Normal>::new(sk))
    }
}

crate::impl_fromstr_deserialize! {
    name => "secp256k1 scalar",
    fn from_bytes(bytes: [u8;32]) -> Option<KeyPair<EvenY>> {
        let sk = Scalar::from_bytes(bytes)?.non_zero()?;
        Some(KeyPair::new_xonly(sk))
    }
}
