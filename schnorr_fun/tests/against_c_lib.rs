#![cfg(feature = "libsecp_compat")]
use proptest::prelude::*;
use schnorr_fun::{
    fun::{marker::*, proptest, secp256k1, Scalar},
    Message, Schnorr,
};
use secp256k1::SECP256K1;
use secp256kfun::{
    digest::Digest,
    hash::{HashAdd, Tagged},
    nonce::{AddTag, NonceGen},
};
use sha2::Sha256;

/// Compliance type for no aux BIP340 libsecp256k1 implementation.
///
/// This type is expected to be used in [`Schnorr`] context and receive a tag "BIP0340" to be
/// compatible with BIP 340 no auxiliary data, i.e. aux is set to null 32-bytes array.
#[derive(Clone, Debug, Default)]
struct Bip340NoAux {
    nonce_hash: Sha256,
    aux_hash: Sha256,
}

impl NonceGen for Bip340NoAux {
    type Hash = Sha256;
    fn begin_derivation(&self, secret: &Scalar) -> Self::Hash {
        let sec_bytes = secret.to_bytes();
        let mut bytes = [0u8; 32];
        let zero_mask = self.aux_hash.clone().add(&[0u8; 32]);
        bytes.copy_from_slice(zero_mask.finalize().as_ref());

        // bitwise xor the zero mask with secret
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte ^= sec_bytes[i]
        }

        self.nonce_hash.clone().add(bytes.as_ref())
    }
}

impl AddTag for Bip340NoAux {
    fn add_tag(self, tag: &str) -> Self {
        Self {
            nonce_hash: self
                .nonce_hash
                .tagged(&[tag.as_bytes(), b"/nonce"].concat()),
            aux_hash: self.aux_hash.tagged(&[tag.as_bytes(), b"/aux"].concat()),
        }
    }
}

proptest! {

    #[test]
    fn deterministic_sigs_are_the_same(
        key in any::<Scalar>(),
        msg in any::<[u8;32]>(),
    ) {
        let secp = SECP256K1;
        let keypair = secp256k1::KeyPair::from_secret_key(&secp, key.clone().into());
        let secp_msg = secp256k1::Message::from_slice(&msg).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&secp_msg, &keypair);
        let schnorr = Schnorr::<Sha256,_>::new(Bip340NoAux::default());
        let fun_keypair = schnorr.new_keypair(key);
        let fun_msg = Message::<Public>::raw(&msg);
        let fun_sig: secp256k1::schnorr::Signature = schnorr.sign(&fun_keypair, fun_msg).into();
        prop_assert_eq!(fun_sig, sig, "they produce the same signatures");
    }


    #[test]
    fn verify_secp_sigs(key in any::<Scalar>(), msg in any::<[u8;32]>(), aux_rand in any::<[u8;32]>()) {
        let secp = SECP256K1;
        let keypair = secp256k1::KeyPair::from_secret_key(&secp, key.clone().into());
        let fun_pk = secp256k1::XOnlyPublicKey::from_keypair(&keypair).into();
        let secp_msg = secp256k1::Message::from_slice(&msg).unwrap();
        let sig = secp.sign_schnorr_with_aux_rand(&secp_msg, &keypair, &aux_rand);
        let schnorr = Schnorr::<Sha256,_>::verify_only();
        let fun_msg = Message::<Public>::raw(&msg);
        prop_assert!(schnorr.verify(&fun_pk, fun_msg, &sig.into()));
    }
}
