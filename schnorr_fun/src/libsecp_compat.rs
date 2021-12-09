use secp256kfun::secp256k1::schnorrsig;

impl From<crate::Signature> for schnorrsig::Signature {
    fn from(sig: crate::Signature) -> Self {
        schnorrsig::Signature::from_slice(sig.to_bytes().as_ref()).unwrap()
    }
}

impl From<schnorrsig::Signature> for crate::Signature {
    fn from(sig: schnorrsig::Signature) -> Self {
        crate::Signature::from_bytes(sig.as_ref().clone()).unwrap()
    }
}
