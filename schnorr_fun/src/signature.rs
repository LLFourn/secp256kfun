use crate::fun::{marker::*, rand_core::RngCore, Point, Scalar};

/// A Schnorr signature.
#[derive(Clone)]
pub struct Signature<S = Public> {
    /// The signature's public nonce
    ///
    /// [`Point`]: secp256kfun::Point
    pub R: Point<EvenY>,
    /// The challenge _response_ part of the signature.
    pub s: Scalar<S, Zero>,
}

impl<S1, S2> PartialEq<Signature<S2>> for Signature<S1> {
    fn eq(&self, rhs: &Signature<S2>) -> bool {
        //TODO figure out how do the conjunction as CT or VT dynamically
        self.R == rhs.R && self.s == rhs.s
    }
}

impl<S> Signature<S> {
    /// Serializes the signature as 64 bytes -- First the 32-byte nonce
    /// x-coordinate and then the 32-byte challenge response scalar.
    /// # Examples
    /// ```
    /// # let signature = schnorr_fun::Signature::random(&mut rand::thread_rng());
    /// let bytes = signature.to_bytes();
    /// assert_eq!(signature.R.to_xonly_bytes(), bytes[..32]);
    /// assert_eq!(signature.s.to_bytes(), bytes[32..]);
    /// ```
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.R.to_xonly_bytes());
        bytes[32..64].copy_from_slice(&self.s.to_bytes());
        bytes
    }

    /// Gets a reference to the signature components as a tuple.
    ///
    /// # Examples
    /// ```
    /// # let signature = schnorr_fun::Signature::random(&mut rand::thread_rng());
    /// let (R, s) = signature.as_tuple();
    /// ```
    pub fn as_tuple(&self) -> (Point<EvenY>, &Scalar<S, Zero>) {
        (self.R, &self.s)
    }

    /// Marks the signature with a [`Secrecy`]. If it is marked as `Secret` the
    /// operations (e.g. verification) on the signature should be done in constant
    /// time.
    ///
    /// # Examples
    /// ```
    /// use schnorr_fun::{fun::marker::*, Signature};
    /// let signature = Signature::random(&mut rand::thread_rng());
    /// let secret_sig = signature.set_secrecy::<Secret>();
    /// ```
    pub fn set_secrecy<M: Secrecy>(self) -> Signature<M> {
        Signature {
            R: self.R,
            s: self.s.set_secrecy(),
        }
    }
}

impl Signature<Public> {
    /// Generates a uniformly distributed signature. It will be valid for an
    /// infinite number of messages on every key but computationally you will
    /// never be able to find one! Useful for testing.
    ///
    /// # Examples
    ///
    /// ```
    /// use schnorr_fun::Signature;
    /// let random_signature = Signature::random(&mut rand::thread_rng());
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        Signature {
            R: Point::random(rng).into_point_with_even_y().0,
            s: Scalar::random(rng).public().mark_zero(),
        }
    }
    /// Deserializes a signature from the byte representation produced by [`to_bytes`].
    ///
    /// This returns `None` if the first 32 bytes were not a valid x-only key or the last 32 bytes were not a valid scalar.
    ///
    /// # Examples
    /// ```
    /// # use schnorr_fun::Signature;
    /// # let bytes = [0u8;64];
    /// match Signature::from_bytes(bytes) {
    ///     Some(signature) => println!("the bytes were a valid encoding of a signature!"),
    ///     None => eprintln!("the bytes did *not* encode a valid signature"),
    /// }
    /// ```
    ///
    /// [`to_bytes`]: crate::Signature::to_bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let mut R = [0u8; 32];
        R.copy_from_slice(&bytes[0..32]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[32..64]);

        let R = Point::from_xonly_bytes(R)?;
        Some(Signature {
            R,
            s: Scalar::from_bytes(s)?,
        })
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secp256k1 Schnorr signature",
    fn from_bytes<S: Secrecy>(bytes: [u8;64]) -> Option<Signature<S>> {
        Signature::from_bytes(bytes).map(|sig| sig.set_secrecy::<S>())
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes<S>(signature: &Signature<S>) -> [u8;64] {
        signature.to_bytes()
    }
}

#[cfg(test)]
mod test {

    #[cfg(feature = "serde")]
    #[test]
    fn signature_serialization_roundtrip() {
        use super::*;
        use crate::{fun::Scalar, Message};
        let schnorr = crate::test_instance!();
        let kp = schnorr.new_keypair(Scalar::random(&mut rand::thread_rng()));
        let signature = schnorr.sign(&kp, Message::<Public>::plain("test", b"foo"));
        let serialized = bincode::serialize(&signature).unwrap();
        assert_eq!(serialized.len(), 64);
        let deserialized = bincode::deserialize::<Signature>(&serialized).unwrap();
        assert_eq!(signature, deserialized);
    }
}
