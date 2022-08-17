use crate::{g, marker::*, Point, Scalar, XOnly, G};
/// A secret and public key pair.
///
/// The secret key is a [`Scalar`] and the public key is the [`Point`] resulting from multiplying the scalar by [`G`].
///
/// ```
/// use secp256kfun::{KeyPair, Scalar};
/// let my_secret_key = Scalar::random(&mut rand::thread_rng());
/// let my_keypair = KeyPair::new(my_secret_key);
/// ```
///
/// [`Scalar`]: crate::Scalar
/// [`G`]: crate::G
/// [`Point`]: crate::Point
#[derive(Clone, Debug, PartialEq)]
pub struct KeyPair {
    sk: Scalar,
    pk: Point,
}

impl KeyPair {
    /// Create a new `KeyPair` from a `secret_key`.
    pub fn new(secret_key: Scalar) -> Self {
        Self {
            pk: g!(secret_key * G).normalize(),
            sk: secret_key,
        }
    }

    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// The public key
    pub fn public_key(&self) -> Point {
        self.pk
    }

    /// Gets a reference to the keypair as a tuple
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{KeyPair, Scalar};
    /// let keypair = KeyPair::new(Scalar::random(&mut rand::thread_rng()));
    /// let (secret_key, public_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, Point) {
        (&self.sk, self.pk)
    }
}

/// A secret and public key pair where the public key is an [`XOnly`].
///
/// [`XOnly`]: crate::XOnly
/// [`Scalar`]: crate::Scalar
#[derive(Clone, Debug, PartialEq)]
pub struct XOnlyKeyPair {
    sk: Scalar,
    pk: XOnly,
}

impl XOnlyKeyPair {
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
    /// use secp256kfun::{g, s, Scalar, XOnlyKeyPair, G};
    ///
    /// let original_secret_key = Scalar::random(&mut rand::thread_rng());
    /// let keypair = XOnlyKeyPair::new(original_secret_key.clone());
    ///
    /// assert!(
    ///     &original_secret_key == keypair.secret_key()
    ///         || &-original_secret_key == keypair.secret_key()
    /// );
    /// assert!(g!({ keypair.secret_key() } * G).normalize().is_y_even());
    /// assert_eq!(
    ///     g!({ keypair.secret_key() } * G),
    ///     keypair.public_key().to_point()
    /// );
    /// ```
    ///
    /// [`Point`]: crate::Point
    /// [`EvenY`]: crate::marker::EvenY
    pub fn new(mut secret_key: Scalar) -> Self {
        let pk = XOnly::from_scalar_mul(&G, &mut secret_key);
        Self { sk: secret_key, pk }
    }

    /// Returns a reference to the secret key.
    ///
    /// The secret key will always correspond to a point with an even y-coordinate when multiplied
    /// by [`G`] (regardless of what was passed into [`XOnlyKeyPair::new`]).
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// The public key as an `XOnly` point.
    pub fn public_key(&self) -> XOnly {
        self.pk
    }

    /// Gets a reference to the keypair as a tuple
    ///
    /// # Example
    /// ```
    /// use secp256kfun::{XOnlyKeyPair, Scalar};
    /// let keypair = XOnlyKeyPair::new(Scalar::random(&mut rand::thread_rng()));
    /// let (secret_key, public_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, XOnly) {
        (&self.sk, self.pk)
    }

    /// Deprecated
    #[deprecated(note = "use .public_key().to_point() instead")]
    pub fn verification_key(&self) -> Point<EvenY> {
        self.public_key().to_point()
    }
}

impl From<XOnlyKeyPair> for (Scalar, XOnly) {
    fn from(kp: XOnlyKeyPair) -> Self {
        (kp.sk, kp.pk)
    }
}

impl From<XOnlyKeyPair> for KeyPair {
    fn from(xonly: XOnlyKeyPair) -> Self {
        Self {
            sk: xonly.sk,
            pk: xonly.pk.to_point().mark::<Normal>(),
        }
    }
}

impl From<KeyPair> for XOnlyKeyPair {
    fn from(kp: KeyPair) -> Self {
        let mut sk = kp.sk;
        let (pk, needs_negation) = kp.pk.into_point_with_even_y();
        sk.conditional_negate(needs_negation);
        Self {
            sk,
            pk: pk.to_xonly(),
        }
    }
}
