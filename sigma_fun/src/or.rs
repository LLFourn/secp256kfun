use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};
use digest::Digest;
use generic_array::{functional::FunctionalSequence, GenericArray};

#[derive(Default, Clone, Debug)]
pub struct Or<A, B> {
    lhs: A,
    rhs: B,
}

impl<A, B> Or<A, B> {
    pub fn new(lhs: A, rhs: B) -> Self {
        Self { lhs, rhs }
    }
}

#[derive(Debug, Clone)]
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

impl<A: Sigma, B: Sigma<ChallengeLength = A::ChallengeLength>> Sigma for Or<A, B> {
    type Witness = Either<A::Witness, B::Witness>;
    type Statement = (A::Statement, B::Statement);
    type Announce = (A::Announce, B::Announce);
    type AnnounceSecret = (
        Either<(A::AnnounceSecret, B::Response), (A::Response, B::AnnounceSecret)>,
        GenericArray<u8, Self::ChallengeLength>,
    );
    type ChallengeLength = A::ChallengeLength;
    type Response = (
        (A::Response, GenericArray<u8, Self::ChallengeLength>),
        B::Response,
    );

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announce,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        let (or_announce_secret, fake_challenge) = announce_secret;
        let real_challenge = challenge.zip(fake_challenge.clone(), |byte1, byte2| byte1 ^ byte2);
        match (witness, or_announce_secret) {
            (Either::Left(witness), Either::Left((announce_secret, sim_response))) => (
                (
                    self.lhs.respond(
                        &witness,
                        &statement.0,
                        announce_secret,
                        &announce.0,
                        &real_challenge,
                    ),
                    real_challenge,
                ),
                sim_response,
            ),
            (Either::Right(witness), Either::Right((sim_response, announce_secret))) => (
                (sim_response, fake_challenge),
                self.rhs.respond(
                    &witness,
                    &statement.1,
                    announce_secret,
                    &announce.1,
                    &real_challenge,
                ),
            ),
            _ => unreachable!("both witness and announce_secret will be on the same side"),
        }
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announce {
        match announce_secret {
            (Either::Left((ref announce_secret, ref sim_response)), sim_challenge) => (
                self.lhs.announce(&statement.0, announce_secret),
                self.rhs
                    .implied_announcement(&statement.1, &sim_challenge, &sim_response)
                    .expect("computationally unreachable for any large language"),
            ),
            (Either::Right((ref sim_response, ref announce_secret)), sim_challenge) => (
                self.lhs
                    .implied_announcement(&statement.0, &sim_challenge, &sim_response)
                    .expect("computationally unreachable for any large language"),
                self.rhs.announce(&statement.1, announce_secret),
            ),
        }
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        let mut sim_challenge = GenericArray::<u8, Self::ChallengeLength>::default();
        rng.fill_bytes(sim_challenge.as_mut_slice());
        match witness {
            Either::Left(ref witness) => {
                let sim_response = self.rhs.sample_response(rng);
                (
                    Either::Left((
                        self.lhs.gen_announce_secret(witness, &statement.0, rng),
                        sim_response,
                    )),
                    sim_challenge,
                )
            }
            Either::Right(ref witness) => {
                let sim_response = self.lhs.sample_response(rng);
                (
                    Either::Right((
                        sim_response,
                        self.rhs.gen_announce_secret(witness, &statement.1, rng),
                    )),
                    sim_challenge,
                )
            }
        }
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        let mut random_challenge = GenericArray::<u8, Self::ChallengeLength>::default();
        rng.fill_bytes(random_challenge.as_mut_slice());
        (
            (self.lhs.sample_response(rng), random_challenge),
            self.rhs.sample_response(rng),
        )
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announce> {
        let (lhs_statement, rhs_statement) = statement;
        let ((lhs_response, lhs_challenge), rhs_response) = response;
        let rhs_challenge = lhs_challenge.zip(challenge, |byte1, byte2| byte1 ^ byte2);

        self.lhs
            .implied_announcement(lhs_statement, lhs_challenge, &lhs_response)
            .and_then(|lhs_announcement| {
                self.rhs
                    .implied_announcement(rhs_statement, &rhs_challenge, &rhs_response)
                    .map(|rhs_announcement| (lhs_announcement, rhs_announcement))
            })
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "or(")?;
        self.lhs.write_name(w)?;
        write!(w, ",")?;
        self.rhs.write_name(w)?;
        write!(w, ")")
    }

    fn hash_statement<H: Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        self.lhs.hash_statement(hash, &statement.0);
        self.rhs.hash_statement(hash, &statement.1);
    }

    fn hash_announcement<H: Digest>(&self, hash: &mut H, announcement: &Self::Announce) {
        self.lhs.hash_announcement(hash, &announcement.0);
        self.rhs.hash_announcement(hash, &announcement.1)
    }

    fn hash_witness<H: Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        match witness {
            Either::Left(witness) => self.lhs.hash_witness(hash, witness),
            Either::Right(witness) => self.rhs.hash_witness(hash, witness),
        }
    }
}

crate::impl_display!(Or<A,B>);

#[cfg(test)]
mod test {
    use super::*;
    use crate::{secp256k1, Either};
    use generic_array::typenum::U32;
    use secp256kfun::{g, marker::*, Point, Scalar, G};
    use sha2::Sha256;

    #[test]
    fn or_secp256k1() {
        let x = Scalar::random(&mut rand::thread_rng());
        let xG = g!(x * G).mark::<Normal>();
        let Y = Point::random(&mut rand::thread_rng());
        type OrDL = Or<secp256k1::DLBP<U32>, secp256k1::DLBP<U32>>;
        let statement = (xG, Y);
        let proof_system = crate::FiatShamir::<OrDL, Sha256>::default();

        let proof_lhs = proof_system.prove(
            &Either::Left(x.clone()),
            &statement,
            &mut rand::thread_rng(),
        );
        assert!(proof_system.verify(&statement, &proof_lhs));

        let wrong_proof_lhs = proof_system.prove(
            &Either::Right(x.clone()),
            &statement,
            &mut rand::thread_rng(),
        );
        assert!(!proof_system.verify(&statement, &wrong_proof_lhs));

        let statement = (statement.1, statement.0);
        let proof_rhs = proof_system.prove(
            &Either::Right(x.clone()),
            &statement,
            &mut rand::thread_rng(),
        );
        assert!(proof_system.verify(&statement, &proof_rhs));
    }
}
