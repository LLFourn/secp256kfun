use crate::{fun::secp256k1, Signature};

impl From<Signature> for secp256k1::Signature {
    fn from(sig: Signature) -> Self {
        secp256k1::Signature::from_compact(sig.to_bytes().as_ref()).unwrap()
    }
}

impl From<secp256k1::Signature> for Signature {
    fn from(sig: secp256k1::Signature) -> Self {
        Signature::from_bytes(sig.serialize_compact()).unwrap()
    }
}
