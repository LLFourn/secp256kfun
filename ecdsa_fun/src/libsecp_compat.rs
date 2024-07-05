#[cfg(feature = "libsecp_compat_0_27")]
mod v0_27 {
    use crate::{fun::secp256k1_0_27::ecdsa, Signature};

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
}

#[cfg(feature = "libsecp_compat_0_28")]
mod v0_28 {
    use crate::{fun::secp256k1_0_28::ecdsa, Signature};

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
}

#[cfg(feature = "libsecp_compat_0_29")]
mod v0_29 {
    use crate::{fun::secp256k1_0_29::ecdsa, Signature};

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
}
