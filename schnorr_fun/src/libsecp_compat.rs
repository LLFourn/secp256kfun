use secp256kfun::secp256k1::schnorr;

impl From<crate::Signature> for schnorr::Signature {
    fn from(sig: crate::Signature) -> Self {
        schnorr::Signature::from_slice(sig.to_bytes().as_ref()).unwrap()
    }
}

impl From<schnorr::Signature> for crate::Signature {
    fn from(sig: schnorr::Signature) -> Self {
        crate::Signature::from_bytes(sig.as_ref().clone()).unwrap()
    }
}
