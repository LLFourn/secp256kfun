use secp256kfun::{marker::*, Point, Scalar, XOnly};

/// A secret and public key-pair for generating Schnorr signatures.
///
/// The `KeyPair` struct is exists because it is more efficient to pre-compute the public key and
/// pass it in rather pass it in when signing with the same key multiple times.
///
/// Create a `KeyPair` from a [`Schnorr`] instance.
///
/// ```
/// # use schnorr_fun::{fun::Scalar, Schnorr};
/// # let schnorr = schnorr_fun::test_instance!();
/// let my_secret_key = Scalar::random(&mut rand::thread_rng());
/// let my_keypair = schnorr.new_keypair(my_secret_key);
/// ```
///
/// [`Schnorr`]: crate::Schnorr
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub(crate) sk: Scalar,
    pub(crate) pk: XOnly,
}

impl KeyPair {
    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> XOnly {
        self.pk
    }

    /// Gets a reference to the key-pair as a tuple
    ///
    /// # Example
    /// ```
    /// # use schnorr_fun::{Schnorr, fun::Scalar};
    /// # let keypair = schnorr_fun::test_instance!().new_keypair(Scalar::one());
    /// let (secret_key, public_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, XOnly) {
        (&self.sk, self.pk)
    }

    /// Returns the full `Point<EvenY>` for the public key which is used in [`verify`].
    ///
    /// This is just a descriptive short version of:
    ///
    /// ```
    /// # use schnorr_fun::{fun::Scalar, Schnorr};
    /// # let keypair = schnorr_fun::test_instance!().new_keypair(Scalar::random(&mut rand::thread_rng()));
    /// let verification_key = keypair.public_key().to_point();
    /// # assert_eq!(keypair.verification_key(), keypair.public_key().to_point())
    /// ```
    /// [`verify`]: crate::Schnorr::verify
    pub fn verification_key(&self) -> Point<EvenY> {
        self.pk.to_point()
    }
}

impl From<KeyPair> for (Scalar, XOnly) {
    fn from(kp: KeyPair) -> Self {
        (kp.sk, kp.pk)
    }
}

impl AsRef<XOnly> for KeyPair {
    fn as_ref(&self) -> &XOnly {
        &self.pk
    }
}
