#![cfg(feature = "libsecp_compat")]
use proptest::prelude::*;
use schnorr_fun::{
    fun::{marker::*, proptest, secp256k1, Scalar},
    nonce::Deterministic,
    Message, Schnorr,
};
use secp256k1::global::SECP256K1;
use sha2::Sha256;

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
        let schnorr = Schnorr::<Sha256,_>::new(Deterministic::<Sha256>::default());
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
