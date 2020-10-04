#![allow(non_snake_case)]
use sha2::Sha256;
use sigma_fun::{
    typenum::{U20, U31, U32},
    Eq, FiatShamir,
    secp256k1,
    ed25519
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
        let dleq = Eq::new($mod::DLBP::<$len>::default(), $mod::DL::<$len>::default());

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
    let dleq = Eq::new(secp256k1::DLBP::<U32>::default(), secp256k1::DL::<U32>::default());
    assert_eq!(&format!("{}", dleq), "eq(DLBP-secp256k1,DL-secp256k1)");
}

#[test]
pub fn test_dleq_secp256k1() {
    use sigma_fun::secp256k1::fun::{g, marker::*, Point, Scalar, G};
    let x = Scalar::random(&mut rand::thread_rng());
    let H = Point::random(&mut rand::thread_rng());
    let xG = g!(x * G).mark::<Normal>();
    let xH = g!(x * H).mark::<Normal>();
    let statement = ((xG), (H, xH));

    run_dleq!(secp256k1, challenge_length => U32, statement => statement, witness => x, unrelated_point => Point::random(&mut rand::thread_rng()));
    run_dleq!(secp256k1, challenge_length => U20, statement => statement, witness => x, unrelated_point => Point::random(&mut rand::thread_rng()));
}

#[test]
pub fn test_dleq_ed25519() {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    let G = ED25519_BASEPOINT_POINT;
    let x = Scalar::random(&mut rand::thread_rng());
    let h = Scalar::random(&mut rand::thread_rng());
    let H = h * G;
    let xG = x * G;
    let xH = x * H;
    let statement = ((xG), (H, xH));

    run_dleq!(ed25519, challenge_length => U31, statement => statement, witness => x, unrelated_point =>  H + G);
    run_dleq!(ed25519, challenge_length => U20, statement => statement, witness => x, unrelated_point =>  H + G);
}
