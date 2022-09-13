use secp256kfun::{marker::*, Scalar};
/// An ECDSA signature
#[derive(Clone, PartialEq)]
pub struct Signature<S = Public> {
    pub R_x: Scalar<Public, NonZero>,
    pub s: Scalar<S, NonZero>,
}

impl<S> Signature<S> {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.R_x.to_bytes()[..]);
        bytes[32..64].copy_from_slice(&self.s.to_bytes()[..]);
        bytes
    }

    pub fn as_tuple(&self) -> (&Scalar<Public, NonZero>, &Scalar<S, NonZero>) {
        (&self.R_x, &self.s)
    }

    pub fn set_secrecy<SigSec: Secrecy>(self) -> Signature<SigSec> {
        Signature {
            R_x: self.R_x,
            s: self.s.set_secrecy::<SigSec>(),
        }
    }
}

impl Signature<Public> {
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        Scalar::from_slice(&bytes[0..32])
            .and_then(|R_x| R_x.public().non_zero())
            .and_then(|R_x| {
                Scalar::from_slice(&bytes[32..64])
                    .and_then(|s| s.public().non_zero())
                    .map(|s| Self { R_x, s })
            })
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secp256k1 ECDSA signature",
    fn from_bytes<S: Secrecy>(bytes: [u8;64]) -> Option<Signature<S>> {
        Signature::from_bytes(bytes).map(|signature| signature.set_secrecy::<S>())
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes<S>(sig: &Signature<S>) -> [u8;64] {
        sig.to_bytes()
    }
}
