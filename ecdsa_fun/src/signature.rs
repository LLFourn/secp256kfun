use secp256kfun::{marker::*, Scalar};
/// An ECDSA signature
#[derive(Clone, PartialEq)]
pub struct Signature {
    pub R_x: Scalar<Public>,
    pub s: Scalar<Public>,
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.R_x.to_bytes()[..]);
        bytes[32..64].copy_from_slice(&self.s.to_bytes()[..]);
        bytes
    }

    pub fn as_tuple(&self) -> (&Scalar<Public>, &Scalar<Public>) {
        (&self.R_x, &self.s)
    }
}

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Option<Self> {
        let R_x = Scalar::from_slice(&bytes[0..32])?.non_zero()?;
        let s = Scalar::from_slice(&bytes[32..64])?.non_zero()?;
        Some(Self { R_x, s })
    }
}

secp256kfun::impl_fromstr_deserialize! {
    name => "secp256k1 ECDSA signature",
    fn from_bytes(bytes: [u8;64]) -> Option<Signature> {
        Signature::from_bytes(bytes)
    }
}

secp256kfun::impl_display_debug_serialize! {
    fn to_bytes(sig: &Signature) -> [u8;64] {
        sig.to_bytes()
    }
}
