//! Binonces for Musig and FROST Signature Schemes
//!
//! A binonce is a pair of public points used in the MuSig and FROST signature schemes.
//! Your public nonces are derived from scalars which must be kept secret.
//! Derived binonces should be unique and and must not be reused for signing under any circumstances
//! as this can leak your secret key.
use crate::Message;
use secp256kfun::{derive_nonce, g, marker::*, nonce::NonceGen, Point, Scalar, G};

/// A nonce (pair of points) that each party must share with the others in the first stage of signing.
///
/// The type argument determines whether the nonces can be `Zero` or not. The [musig
/// spec](https://github.com/jonasnick/bips/pull/21) specifies that the aggregate nonce is allowed
/// to be zero to avoid having to abort the protocol in this case.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Nonce<Z = NonZero>(pub [Point<Normal, Public, Z>; 2]);

impl Nonce<Zero> {
    /// Reads the pair of nonces from 66 bytes (two 33-byte serialized points).
    ///
    /// If either pair of 33 bytes is `[0u8;32]` that point is interpreted as `Zero`.
    pub fn from_bytes(bytes: [u8; 66]) -> Option<Self> {
        fn deser(bytes: &[u8]) -> Option<Point<Normal, Public, Zero>> {
            Point::from_slice(&bytes)
                .map(|p| p.mark::<Zero>())
                .or_else(|| {
                    if bytes == [0u8; 33].as_slice() {
                        Some(Point::zero())
                    } else {
                        None
                    }
                })
        }

        let R1 = deser(&bytes[33..])?;
        let R2 = deser(&bytes[..33])?;

        Some(Nonce([R1, R2]))
    }

    /// Serializes a public nonce as  as 66 bytes (two 33-byte serialized points).
    ///
    /// If either point is `Zero` it will be serialized as `[0u8;32]`.
    pub fn to_bytes(self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(
            &self.0[0]
                .mark::<NonZero>()
                .map(|p| p.to_bytes())
                .unwrap_or([0u8; 33]),
        );
        bytes[33..].copy_from_slice(
            &self.0[1]
                .mark::<NonZero>()
                .map(|p| p.to_bytes())
                .unwrap_or([0u8; 33]),
        );
        bytes
    }
}

impl Nonce<NonZero> {
    /// Reads the pair of nonces from 66 bytes (two 33-byte serialized points).
    pub fn from_bytes(bytes: [u8; 66]) -> Option<Self> {
        let R1 = Point::from_slice(&bytes[..33])?;
        let R2 = Point::from_slice(&bytes[33..])?;
        Some(Nonce([R1, R2]))
    }

    /// Serializes a public nonce as  as 66 bytes (two 33-byte serialized points).
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(self.0[0].to_bytes().as_ref());
        bytes[33..].copy_from_slice(self.0[1].to_bytes().as_ref());
        bytes
    }
}

impl<Z> Nonce<Z> {
    /// Negate the two nonces
    pub fn conditional_negate(&mut self, needs_negation: bool) {
        self.0[0] = self.0[0].conditional_negate(needs_negation);
        self.0[1] = self.0[1].conditional_negate(needs_negation);
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "public nonce pair",
    fn from_bytes(bytes: [u8;66]) -> Option<Nonce<Zero>> {
        Nonce::<Zero>::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nonce: &Nonce<Zero>) -> [u8;66] {
        nonce.to_bytes()
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "public nonce pair",
    fn from_bytes(bytes: [u8;66]) -> Option<Nonce<NonZero>> {
        Nonce::<NonZero>::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nonce: &Nonce<NonZero>) -> [u8;66] {
        nonce.to_bytes()
    }
}

/// A pair of secret nonces along with the public portion.
///
/// A nonce key pair can be created manually with [`from_secrets`]
///
/// [`from_secrets`]: Self::from_secrets
#[derive(Debug, Clone, PartialEq)]
pub struct NonceKeyPair {
    /// The public nonce
    pub public: Nonce<NonZero>,
    /// The secret nonce
    pub secret: [Scalar; 2],
}

impl NonceKeyPair {
    /// Load nonces from two secret scalars
    pub fn from_secrets(secret: [Scalar; 2]) -> Self {
        let [ref r1, ref r2] = secret;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret,
        }
    }
    /// Deserializes a nonce key pair from 64-bytes (two 32-byte serialized scalars).
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let r1 = Scalar::from_slice(&bytes[..32])?.mark::<NonZero>()?;
        let r2 = Scalar::from_slice(&bytes[32..])?.mark::<NonZero>()?;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        let pub_nonce = Nonce([R1, R2]);
        Some(NonceKeyPair {
            public: pub_nonce,
            secret: [r1, r2],
        })
    }

    /// Serializes a nonce key pair to 64-bytes (two 32-bytes serialized scalars).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.secret[0].to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.secret[1].to_bytes().as_ref());
        bytes
    }

    /// Get the secret portion of the nonce key pair (don't share this!)
    pub fn secret(&self) -> &[Scalar; 2] {
        &self.secret
    }

    /// Get the public portion of the nonce key pair (share this!)
    pub fn public(&self) -> Nonce<NonZero> {
        self.public
    }

    /// Generate a new `NonceKeyPair` from application data.
    ///
    /// Each nonce generated must only be passed to [`MuSig::sign`] once.
    ///
    /// You must always pass in a:
    ///
    /// - `nonce_gen`: [`NonceGen`] containing the underlying algorithm for generating the nonce
    /// - `secret`: The secret scalar whose secrecy depends on the uniquness of the nonces generated.
    /// - `session_id`: Some application defined identifier for the signing session that the resulting nonce will be used in.
    ///
    ///   How important the `session_id` is depends on whether you add a `message` and whether you are using randomness in your `nonce_gen`.
    ///   If you are using a deterministic `nonce_gen` it is crucial that this is set to a unique value for each signing session.
    ///   If your application doesn't naturally provide you with a unique value store a counter.
    ///
    /// Optionally you may pass in `public_key` and `message` which should be passed in when available.
    ///
    /// [`MuSig::sign`]: crate::musig::MuSig::sign
    pub fn generate(
        nonce_gen: &impl NonceGen,
        secret: &Scalar,
        session_id: &[u8],
        public_key: Option<Point<impl Normalized>>,
        message: Option<Message<'_>>,
    ) -> Self {
        let message = message.unwrap_or(Message::raw(b""));
        let msg_len = (message.len() as u64).to_be_bytes();
        let sid_len = (session_id.len() as u64).to_be_bytes();
        let pk_bytes = public_key.map(|p| p.to_bytes()).unwrap_or([0u8; 33]);
        let r1 = derive_nonce!(
            nonce_gen => nonce_gen,
            secret => secret,
            public => [ b"r1", pk_bytes, msg_len, message, sid_len, session_id]
        );
        let r2 = derive_nonce!(
            nonce_gen => nonce_gen,
            secret => secret,
            public => [ b"r2", pk_bytes, msg_len, message, sid_len, session_id]
        );

        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();

        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret: [r1, r2],
        }
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secret nonce pair",
    fn from_bytes(bytes: [u8;64]) -> Option<NonceKeyPair> {
        NonceKeyPair::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(nkp: &NonceKeyPair) -> [u8;64] {
        nkp.to_bytes()
    }
}
