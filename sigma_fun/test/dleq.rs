use sigma_fun::{Eq, secp256k1::{ DL, fun::{Scalar, Point, g, nonce::{Synthetic, GlobalRng}}, DL}, Sigma};
use sha2::Sha256;
use rand::ThreadRng;


#[test]
pub fn test_dleq() {
    let x = Scalar::random(&mut rand::thread_rng());
    let H = Point::random(&mut rand::thread_rng());

    let xG = g!(x * G);
    let xH = g!(x * H);

    let dleq = Eq::new()


}
