#[cfg(feature = "libsecp_compat_0_27")]
mod v0_27 {
    use secp256kfun::secp256k1_0_27::schnorr;

    impl From<crate::Signature> for schnorr::Signature {
        fn from(sig: crate::Signature) -> Self {
            schnorr::Signature::from_slice(sig.to_bytes().as_ref()).unwrap()
        }
    }

    impl From<schnorr::Signature> for crate::Signature {
        fn from(sig: schnorr::Signature) -> Self {
            crate::Signature::from_bytes(*sig.as_ref()).unwrap()
        }
    }
}

#[cfg(feature = "libsecp_compat_0_28")]
mod v0_28 {
    use secp256kfun::secp256k1_0_28::schnorr;

    impl From<crate::Signature> for schnorr::Signature {
        fn from(sig: crate::Signature) -> Self {
            schnorr::Signature::from_slice(sig.to_bytes().as_ref()).unwrap()
        }
    }

    impl From<schnorr::Signature> for crate::Signature {
        fn from(sig: schnorr::Signature) -> Self {
            crate::Signature::from_bytes(*sig.as_ref()).unwrap()
        }
    }
}

#[cfg(feature = "libsecp_compat_0_29")]
mod v0_29 {
    use secp256kfun::secp256k1_0_29::schnorr;

    impl From<crate::Signature> for schnorr::Signature {
        fn from(sig: crate::Signature) -> Self {
            schnorr::Signature::from_slice(sig.to_bytes().as_ref()).unwrap()
        }
    }

    impl From<schnorr::Signature> for crate::Signature {
        fn from(sig: schnorr::Signature) -> Self {
            crate::Signature::from_bytes(*sig.as_ref()).unwrap()
        }
    }
}
