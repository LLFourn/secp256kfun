use secp256kfun::hex;
use secp256kfun::{
    KeyPair,
    marker::{NonZero, Normal, Public},
    prelude::*,
};
use vrf_fun::{VrfProof, rfc9381};

// Note: These test vectors were generated specifically for this library implementation
// since [RFC 9381] doesn't provide official test vectors for secp256k1. We hope that
// other implementations can use these vectors to ensure interoperability.
//
// [RFC 9381]: https://datatracker.ietf.org/doc/html/rfc9381

#[test]
fn test_rfc9381_tai_vectors() {
    // Test Vector 1: Basic test with simple message
    let test_vector_1 = TestVector {
        secret_key: "0101010101010101010101010101010101010101010101010101010101010101",
        public_key: "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        alpha: b"test",
        gamma: "021200f50a94e0ffc796f8a615b234777dc13f88738fa038e839ea2f47335bd8fe",
        c: "62a4a77dab8d9340584c4ae0d94d1ef8",
        s: "916d8533ed7346a66dc49eb882c9c49e912ddda73e4a4e126ba8c889e9b7fffd",
        beta: "0e86ed33996d86db36fcf3053e1bdf76e548693611eaffefcd76cbad0b0b1a0e",
    };
    verify_tai_test_vector(&test_vector_1);

    // Test Vector 2: Empty message
    let test_vector_2 = TestVector {
        secret_key: "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        public_key: "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        alpha: b"",
        gamma: "039a59c76e7f26b69eff344c11c68cef48a3ef6ea9fb1be81884f1355db2a8b3f8",
        c: "2dd54cd117ab6e8cf9a9398551d4ce4b",
        s: "ab5a2eb29c984c10db71f4cdb1d3a85413de03ed165c8bd0203498cfbb82ac41",
        beta: "0dd27f31b0ddf97e980f1423ee6b10cb2ba0006dda21c59c49dd1fc69a64546b",
    };
    verify_tai_test_vector(&test_vector_2);

    // Test Vector 3: Longer message
    let test_vector_3 = TestVector {
        secret_key: "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        public_key: "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        alpha: b"The quick brown fox jumps over the lazy dog",
        gamma: "0371e02a9138fd05a39ed62e9bf4a0bf78016fec9493c4f1a9123106cdea1ccbeb",
        c: "e8d6d31d7ac11d07af656a7c01290acb",
        s: "e5e541f5c5f630d082cb814e813889ee79f570b8360d031692e2ab3d2cb32baa",
        beta: "a195ee2cd4da816a7e95dd407e0cdcfed5f9f1f1de1df86347b727d098fea744",
    };
    verify_tai_test_vector(&test_vector_3);
}

struct TestVector {
    secret_key: &'static str,
    public_key: &'static str,
    alpha: &'static [u8],
    gamma: &'static str,
    c: &'static str,    // challenge (16 bytes for RFC 9381)
    s: &'static str,    // response
    beta: &'static str, // VRF output
}

fn verify_tai_test_vector(tv: &TestVector) {
    use sigma_fun::CompactProof;
    use sigma_fun::generic_array::GenericArray;

    // Parse secret key
    let secret_key_bytes = hex::decode_array::<32>(tv.secret_key).expect("Invalid secret key hex");
    let secret_key = Scalar::from_bytes_mod_order(secret_key_bytes)
        .non_zero()
        .expect("Invalid secret key");
    let keypair = KeyPair::new(secret_key);

    // Verify public key matches
    let expected_public_key = Point::<Normal, Public, NonZero>::from_bytes(
        hex::decode_array::<33>(tv.public_key).expect("Invalid public key hex"),
    )
    .expect("Invalid public key");
    assert_eq!(keypair.public_key(), expected_public_key);

    // Parse proof components
    let gamma = Point::<Normal, Public, NonZero>::from_bytes(
        hex::decode_array::<33>(tv.gamma).expect("Invalid gamma hex"),
    )
    .expect("Invalid gamma point");

    let challenge_bytes = hex::decode_array::<16>(tv.c).expect("Invalid challenge hex");
    let challenge = *GenericArray::from_slice(&challenge_bytes);

    let response_bytes = hex::decode_array::<32>(tv.s).expect("Invalid response hex");
    let response = Scalar::from_bytes_mod_order(response_bytes);

    // Construct proof
    let proof = VrfProof {
        gamma,
        proof: CompactProof {
            challenge,
            response,
        },
    };

    // Verify proof using high-level API
    let verified = rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), tv.alpha, &proof)
        .expect("Proof verification failed");

    // Check VRF output matches
    let output = rfc9381::tai::output::<sha2::Sha256>(&verified);
    let expected_output = hex::decode_array::<32>(tv.beta).expect("Invalid beta hex");
    assert_eq!(output, expected_output);

    // Also test proving with the same inputs
    let proof_generated = rfc9381::tai::prove::<sha2::Sha256>(&keypair, tv.alpha);
    assert_eq!(proof_generated.gamma, gamma);

    // The challenge and response will be different due to different nonce generation,
    // but the proof should still verify
    let verified_generated =
        rfc9381::tai::verify::<sha2::Sha256>(keypair.public_key(), tv.alpha, &proof_generated)
            .expect("Generated proof verification failed");
    assert_eq!(
        rfc9381::tai::output::<sha2::Sha256>(&verified_generated),
        expected_output
    );
}

#[test]
fn test_rfc9381_sswu_vectors() {
    // Test Vector 1: Basic test with simple message
    let test_vector_1 = TestVector {
        secret_key: "0101010101010101010101010101010101010101010101010101010101010101",
        public_key: "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
        alpha: b"test",
        gamma: "02dd925e50632024208c3c05071c24d0826e9da601cc476b69f4ba86ec48f6fb41",
        c: "c887597633cd157a92ac5edc6466cf20",
        s: "308e1ee440acb3fee0733b04c78f2f0fa331e15424788ab2b66154006e4d3cee",
        beta: "40053cf98f3c957635fc926f238b80ca278c63d0f2c7368019a97c86f15488a5",
    };
    verify_sswu_test_vector(&test_vector_1);

    // Test Vector 2: Empty message
    let test_vector_2 = TestVector {
        secret_key: "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
        public_key: "02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
        alpha: b"",
        gamma: "03c06cab9597dba7021afcb435bfbaa4ef67fa6977ceba1fd7971866718622f1c5",
        c: "f2e353f856a09336394b29138a7e6500",
        s: "3790e19a9366706760e2a2a97979c1a48b271e1b87518df83d152aac81ec36ef",
        beta: "e3e09ff39f739bbaf30e81edb300fa4e62d8cc298296d55924b679bfb0f530ea",
    };
    verify_sswu_test_vector(&test_vector_2);

    // Test Vector 3: Longer message
    let test_vector_3 = TestVector {
        secret_key: "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
        public_key: "0325d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
        alpha: b"The quick brown fox jumps over the lazy dog",
        gamma: "0269223db63e87d7ecd471d50e950cfec33b3a2ea03ad4ef4812f8a20de229035e",
        c: "db1eb4c9d739ea4286ddff9c64d000e2",
        s: "c7dd63ee74a11bbfa9061d5d902f56aae7b7404249aab88a627976379e6545f1",
        beta: "cf1cb0dda9b6dde3abe986383d2e2b0f0b69333b590d43c8daf2ab4c9585df84",
    };
    verify_sswu_test_vector(&test_vector_3);
}

fn verify_sswu_test_vector(tv: &TestVector) {
    use sigma_fun::CompactProof;
    use sigma_fun::generic_array::GenericArray;

    // Parse secret key
    let secret_key_bytes = hex::decode_array::<32>(tv.secret_key).expect("Invalid secret key hex");
    let secret_key = Scalar::from_bytes_mod_order(secret_key_bytes)
        .non_zero()
        .expect("Invalid secret key");
    let keypair = KeyPair::new(secret_key);

    // Verify public key matches
    let expected_public_key = Point::<Normal, Public, NonZero>::from_bytes(
        hex::decode_array::<33>(tv.public_key).expect("Invalid public key hex"),
    )
    .expect("Invalid public key");
    assert_eq!(keypair.public_key(), expected_public_key);

    // Parse proof components
    let gamma = Point::<Normal, Public, NonZero>::from_bytes(
        hex::decode_array::<33>(tv.gamma).expect("Invalid gamma hex"),
    )
    .expect("Invalid gamma point");

    let challenge_bytes = hex::decode_array::<16>(tv.c).expect("Invalid challenge hex");
    let challenge = *GenericArray::from_slice(&challenge_bytes);

    let response_bytes = hex::decode_array::<32>(tv.s).expect("Invalid response hex");
    let response = Scalar::from_bytes_mod_order(response_bytes);

    // Construct proof
    let proof = VrfProof {
        gamma,
        proof: CompactProof {
            challenge,
            response,
        },
    };

    // Verify proof using high-level API
    let verified = rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), tv.alpha, &proof)
        .expect("Proof verification failed");

    // Check VRF output matches
    let output = rfc9381::sswu::output::<sha2::Sha256>(&verified);
    let expected_output = hex::decode_array::<32>(tv.beta).expect("Invalid beta hex");
    assert_eq!(output, expected_output);

    // Also test proving with the same inputs
    let proof_generated = rfc9381::sswu::prove::<sha2::Sha256>(&keypair, tv.alpha);
    assert_eq!(proof_generated.gamma, gamma);

    // The challenge and response will be different due to different nonce generation,
    // but the proof should still verify
    let verified_generated =
        rfc9381::sswu::verify::<sha2::Sha256>(keypair.public_key(), tv.alpha, &proof_generated)
            .expect("Generated proof verification failed");
    assert_eq!(
        rfc9381::sswu::output::<sha2::Sha256>(&verified_generated),
        expected_output
    );
}
