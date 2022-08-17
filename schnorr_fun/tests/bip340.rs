use schnorr_fun::{
    fun::{
        hex,
        marker::*,
        nonce::{NonceRng, Synthetic},
        rand_core, Scalar, XOnly,
    },
    Message, Schnorr, Signature,
};
use sha2::Sha256;

static BIP340_CSV: &'static str = include_str!("./bip340-test-vectors.csv");

struct AuxRng<'a>(&'a [u8]);

impl<'a> rand_core::RngCore for AuxRng<'a> {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.copy_from_slice(&self.0)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl<'a> rand_core::CryptoRng for AuxRng<'a> {}

impl<'a> NonceRng for AuxRng<'a> {
    fn fill_bytes(&self, bytes: &mut [u8]) {
        bytes.copy_from_slice(&self.0[..])
    }
}

#[test]
fn signing_test_vectors() {
    use core::str::FromStr;

    let lines: Vec<&str> = BIP340_CSV.split("\n").collect();

    for line in &lines[1..5] {
        let line: Vec<&str> = line.split(',').collect();
        let aux_bytes = hex::decode(line[3]).unwrap();
        let fake_rng = AuxRng(&aux_bytes[..]);
        let bip340 = Schnorr::<Sha256, _>::new(Synthetic::<Sha256, _>::new(fake_rng));
        let secret_key = Scalar::<Secret, NonZero>::from_str(line[1]).unwrap();
        let expected_public_key = XOnly::from_str(line[2]).unwrap();
        let keypair = bip340.new_keypair(secret_key);
        assert_eq!(keypair.public_key(), expected_public_key);
        let message = hex::decode(line[4]).unwrap();
        let signature = bip340.sign(&keypair, Message::<Public>::raw(&message));
        let expected_signature = Signature::<Public>::from_str(line[5]).unwrap();
        assert_eq!(signature, expected_signature);
    }
}

#[test]
fn verification_test_vectors() {
    use core::str::FromStr;
    let bip340 = Schnorr::<Sha256>::verify_only();
    let lines: Vec<&str> = BIP340_CSV.split("\n").collect();
    for line in &lines[5..16] {
        let line: Vec<&str> = line.split(',').collect();

        let public_key = match XOnly::from_str(line[2]) {
            Ok(public_key) => public_key,
            Err(e) => {
                if line[6] == "TRUE" {
                    panic!("{:?}", e);
                } else {
                    continue;
                }
            }
        };
        let message = hex::decode(line[4]).unwrap();
        let signature = match Signature::<Public>::from_str(line[5]) {
            Ok(signature) => signature,
            Err(e) => {
                if line[6] == "TRUE" {
                    panic!("{:?}", e)
                } else {
                    continue;
                }
            }
        };

        println!("{:?}", line);
        assert!(
            bip340.verify(
                &public_key.to_point(),
                Message::<Public>::raw(&message),
                &signature
            ) == (line[6] == "TRUE")
        );
    }
}
