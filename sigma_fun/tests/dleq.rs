#![allow(non_snake_case)]
use ::proptest::prelude::*;
use sha2::Sha256;
use sigma_fun::{
    ed25519::{
        self,
        proptest::{ed25519_point, ed25519_scalar},
    },
    secp256k1::{
        self,
        fun::proptest::{non_zero_scalar as secp256k1_non_zero_scalar, point as secp256k1_point},
    },
    typenum::{U20, U31, U32},
    Eq, FiatShamir,
};

macro_rules! run_dleq {
    (
        $mod:ident,challenge_length =>
        $len:ident,statement =>
        $statement:expr,witness =>
        $witness:expr,unrelated_point =>
        $unrelated_point:expr
    ) => {{
        let statement = &$statement;
        let witness = &$witness;
        let dleq = Eq::new($mod::DLG::<$len>::default(), $mod::DL::<$len>::default());

        let proof_system = FiatShamir::<_, Sha256>::new(dleq);
        let proof = proof_system.prove(witness, statement, &mut rand::thread_rng());
        assert!(proof_system.verify(statement, &proof));

        let mut bogus_statement = statement.clone();
        bogus_statement.1.0 = $unrelated_point;
        assert!(!proof_system.verify(&bogus_statement, &proof));

        let bogus_proof = proof_system.prove(witness, &bogus_statement, &mut rand::thread_rng());
        assert!(!proof_system.verify(&bogus_statement, &bogus_proof));
    }};
}

#[test]
fn secp256k1_dleq_has_correct_name() {
    let dleq = Eq::new(
        secp256k1::DLG::<U32>::default(),
        secp256k1::DL::<U32>::default(),
    );
    assert_eq!(&format!("{}", dleq), "eq(DLG-secp256k1,DL-secp256k1)");
}

proptest! {
    #[test]
    fn test_dleq_secp256k1(
        x in secp256k1_non_zero_scalar(),
        H in secp256k1_point(),
        unrelated_point in secp256k1_point(),
    ) {
        use sigma_fun::secp256k1::fun::{g, marker::*, G};
        let xG = g!(x * G).mark::<Normal>();
        let xH = g!(x * H).mark::<Normal>();
        let statement = ((xG), (H, xH));

        run_dleq!(
            secp256k1,
            challenge_length => U32,
            statement => statement,
            witness => x,
            unrelated_point => unrelated_point.clone()
        );
        run_dleq!(
            secp256k1,
            challenge_length => U20,
            statement => statement,
            witness => x,
            unrelated_point => unrelated_point
        );
    }
}

proptest! {
    #[test]
    fn test_dleq_ed25519(
        x in ed25519_scalar(),
        H in ed25519_point(),
        unrelated_point in ed25519_point(),
    ) {
        use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT};
        let G = ED25519_BASEPOINT_POINT;
        let xG = x * G;
        let xH = x * H;
        let statement = ((xG), (H, xH));

        run_dleq!(
            ed25519,
            challenge_length => U31,
            statement => statement,
            witness => x,
            unrelated_point => unrelated_point
        );
        run_dleq!(
            ed25519,
            challenge_length => U20,
            statement => statement,
            witness => x,
            unrelated_point => unrelated_point
        );
    }
}
