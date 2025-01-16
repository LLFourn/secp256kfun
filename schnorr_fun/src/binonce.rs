//! Binonces for Musig and FROST Signature Schemes
//!
//! A binonce is a pair of public points used in the MuSig and FROST signature schemes.
//! Your public nonces are derived from scalars which must be kept secret.
//! Derived binonces should be unique and and must not be reused for signing under any circumstances
//! as this can leak your secret key.
use secp256kfun::{g, hash::HashInto, marker::*, rand_core::RngCore, Point, Scalar, G};

/// A nonce (pair of points) that each party must share with the others in the first stage of signing.
///
/// The type argument determines whether the nonces can be `Zero` or not. The [musig
/// spec](https://github.com/jonasnick/bips/pull/21) specifies that the aggregate nonce is allowed
/// to be zero to avoid having to abort the protocol in this case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nonce<Z = NonZero>(pub [Point<Normal, Public, Z>; 2]);

impl<Z: ZeroChoice> Nonce<Z> {
    /// Reads the pair of nonces from 66 bytes (two 33-byte serialized points).
    ///
    /// If either pair of 33 bytes is `[0u8;33]` that point is interpreted as `Zero`.
    pub fn from_bytes(bytes: [u8; 66]) -> Option<Self> {
        let R1 = Point::from_slice(&bytes[..33])?;
        let R2 = Point::from_slice(&bytes[33..])?;

        Some(Nonce([R1, R2]))
    }
}

impl<Z: ZeroChoice> Nonce<Z> {
    /// Negate the two nonces
    pub fn conditional_negate(&mut self, needs_negation: bool) {
        self.0[0] = self.0[0].conditional_negate(needs_negation);
        self.0[1] = self.0[1].conditional_negate(needs_negation);
    }

    /// Serializes a public nonce as  as 66 bytes (two 33-byte serialized points).
    ///
    /// If either point is `Zero` it will be serialized as `[0u8;33]`.
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..33].copy_from_slice(self.0[0].to_bytes().as_ref());
        bytes[33..].copy_from_slice(self.0[1].to_bytes().as_ref());
        bytes
    }

    /// Binds an aggregated binonce to a it's binding coefficient (which is produced differently for
    /// different schemes) and produces the final nonce (the one that will go into the signature).
    pub fn bind(&self, binding_coeff: Scalar<Public>) -> (Point<EvenY>, bool) {
        g!(self.0[0] + binding_coeff * self.0[1])
            .normalize()
            .non_zero()
            .unwrap_or(Point::generator())
            .into_point_with_even_y()
    }
}

impl<Z> HashInto for Nonce<Z> {
    fn hash_into(self, hash: &mut impl secp256kfun::digest::Update) {
        self.0.hash_into(hash)
    }
}

impl Nonce<Zero> {
    /// Adds a bunch of binonces together (one for each party signing usually).
    pub fn aggregate(nonces: impl IntoIterator<Item = Nonce>) -> Self {
        let agg = nonces.into_iter().fold([Point::zero(); 2], |acc, nonce| {
            [g!(acc[0] + nonce.0[0]), g!(acc[1] + nonce.0[1])]
        });

        Self([agg[0].normalize(), agg[1].normalize()])
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "public binonce",
    fn from_bytes<Z: ZeroChoice>(bytes: [u8;66]) -> Option<Nonce<Z>> {
        Nonce::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes<Z: ZeroChoice>(nonce: &Nonce<Z>) -> [u8;66] {
        nonce.to_bytes()
    }
}

/// A pair of secret nonces along with the public portion.
///
/// A nonce key pair can be created manually with [`from_secret`]
///
/// [`from_secret`]: Self::from_secret
#[derive(Debug, Clone, PartialEq)]
pub struct NonceKeyPair {
    /// The public nonce
    pub public: Nonce<NonZero>,
    /// The secret nonce
    pub secret: SecretNonce,
}

/// A pair of secret nonces.
///
/// ⚠ An attacker getting this allows them to extract your secret share from a signature share.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretNonce(pub [Scalar; 2]);

impl SecretNonce {
    /// Deserializes a secret binonce from 64-bytes (two 32-byte serialized scalars).
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let r1 = Scalar::from_slice(&bytes[..32])?.non_zero()?;
        let r2 = Scalar::from_slice(&bytes[32..])?.non_zero()?;
        Some(Self([r1, r2]))
    }

    /// Serializes a secret binonce to 64-bytes (two 32-bytes serialized scalars).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.0[0].to_bytes().as_ref());
        bytes[32..].copy_from_slice(self.0[1].to_bytes().as_ref());
        bytes
    }

    /// Generate a nonce secret binonce from an rng
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self([Scalar::random(rng), Scalar::random(rng)])
    }

    /// Convert a secret nonce into a key pair by computing the public nonce
    pub fn into_keypair(self) -> NonceKeyPair {
        NonceKeyPair::from_secret(self)
    }
}

impl NonceKeyPair {
    /// Load nonces from two secret scalars
    pub fn from_secret(secret: SecretNonce) -> Self {
        let [ref r1, ref r2] = secret.0;
        let R1 = g!(r1 * G).normalize();
        let R2 = g!(r2 * G).normalize();
        NonceKeyPair {
            public: Nonce([R1, R2]),
            secret,
        }
    }

    /// Get the secret portion of the nonce key pair (don't share this!)
    pub fn secret(&self) -> &SecretNonce {
        &self.secret
    }

    /// Get the public portion of the nonce key pair (share this!)
    pub fn public(&self) -> Nonce<NonZero> {
        self.public
    }

    /// Generate a random secret nonce and conver to a keypair
    pub fn random(rng: &mut impl RngCore) -> Self {
        Self::from_secret(SecretNonce::random(rng))
    }
}

impl AsRef<SecretNonce> for NonceKeyPair {
    fn as_ref(&self) -> &SecretNonce {
        self.secret()
    }
}

impl AsRef<SecretNonce> for SecretNonce {
    fn as_ref(&self) -> &SecretNonce {
        self
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secret binonce",
    fn from_bytes(bytes: [u8;64]) -> Option<SecretNonce> {
        SecretNonce::from_bytes(bytes)
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(value: &SecretNonce) -> [u8;64] {
        value.to_bytes()
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secret binonce",
    fn from_bytes(bytes: [u8;64]) -> Option<NonceKeyPair> {
        Some(NonceKeyPair::from_secret(SecretNonce::from_bytes(bytes)?))
    }
}

secp256kfun::impl_display_serialize! {
    fn to_bytes(value: &NonceKeyPair) -> [u8;64] {
        value.secret.to_bytes()
    }
}
