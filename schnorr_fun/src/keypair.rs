use rand_core::{CryptoRng, RngCore};
use secp256kfun::{marker::*, Point, Scalar, XOnly};
/// A secret and public key-pair for generating Schnorr signatures.
///
/// The `KeyPair` struct is exists because it is more efficient to pre-compute
/// the public key and pass it in rather pass it in when signing with the same
/// key multiple times.
pub struct KeyPair {
    pub(crate) sk: Scalar,
    pub(crate) pk: XOnly<EvenY>,
}

impl KeyPair {
    /// Returns a reference to the secret key.
    pub fn secret_key(&self) -> &Scalar {
        &self.sk
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &XOnly<EvenY> {
        &self.pk
    }

    /// Gets a reference to the key-pair as a tuple
    /// # Example
    /// ```
    /// # use secp256kfun::{G};
    /// # use schnorr_fun::KeyPair;
    /// # let keypair = KeyPair::random(G, &mut rand::thread_rng());
    /// let (sec_key, pub_key) = keypair.as_tuple();
    pub fn as_tuple(&self) -> (&Scalar, &XOnly<EvenY>) {
        (&self.sk, &self.pk)
    }

    pub fn random<R: CryptoRng + RngCore>(
        G: &Point<impl Normalized, Public, NonZero>,
        rng: &mut R,
    ) -> KeyPair {
        let mut sk = Scalar::random(rng);
        let pk = XOnly::from_scalar_mul(G, &mut sk);

        Self { sk, pk }
    }

    pub fn verification_key(&self) -> Point<EvenY> {
        self.pk.to_point()
    }
}

impl From<KeyPair> for (Scalar, XOnly<EvenY>) {
    fn from(kp: KeyPair) -> Self {
        (kp.sk, kp.pk)
    }
}
