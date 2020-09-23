#![allow(non_snake_case)]
use sha2::Sha256;
use sigma_fun::{
    generic_array::GenericArray,
    secp256k1::{
        self,
        fun::{g, marker::*, Point, Scalar, G},
    },
    typenum::{U2, U20, U32},
    Eq, FiatShamir,
};


macro_rules! run_dleq {
    (challenge_length => $len:ident) => {
        let x = Scalar::random(&mut rand::thread_rng());
        let H = Point::random(&mut rand::thread_rng());

        let xG = g!(x * G).mark::<Normal>();
        let xH = g!(x * H).mark::<Normal>();

        let statement = GenericArray::from([(G.clone().mark::<Normal>(), xG), (H, xH)]);
        let dleq = Eq::<_, U2>::new(secp256k1::DL::<$len>::new());
        assert_eq!(format!("{}", dleq), "eq(2,DL-secp256k1)");

        let proof_system = FiatShamir::<_, Sha256>::new(dleq);
        let proof = proof_system.prove(&x, &statement, &mut rand::thread_rng());
        assert!(proof_system.verify(&statement, &proof));

        let mut bogus_statement = statement.clone();
        bogus_statement[1].0 = Point::random(&mut rand::thread_rng());
        assert!(!proof_system.verify(&bogus_statement, &proof));

        let bogus_proof = proof_system.prove(&x, &bogus_statement, &mut rand::thread_rng());
        assert!(!proof_system.verify(&bogus_statement, &bogus_proof));
    }

}

#[test]
pub fn test_dleq() {
    run_dleq!(challenge_length => U32);
    run_dleq!(challenge_length => U20);
}
