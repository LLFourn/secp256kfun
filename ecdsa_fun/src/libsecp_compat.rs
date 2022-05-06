use crate::{fun::secp256k1::ecdsa, Signature};

impl From<Signature> for ecdsa::Signature {
    fn from(sig: Signature) -> Self {
        ecdsa::Signature::from_compact(sig.to_bytes().as_ref()).unwrap()
    }
}

impl From<ecdsa::Signature> for Signature {
    fn from(sig: ecdsa::Signature) -> Self {
        Signature::from_bytes(sig.serialize_compact()).unwrap()
    }
}
