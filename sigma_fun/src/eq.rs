use crate::{
    rand_core::{CryptoRng, RngCore},
    Sigma,
};

#[derive(Default, Clone, Debug)]
pub struct Eq<A, B> {
    lhs: A,
    rhs: B,
}

impl<A, B> Eq<A, B> {
    pub fn new(lhs: A, rhs: B) -> Self {
        Self { lhs, rhs }
    }
}

impl<A, B> Sigma for Eq<A, B>
where
    A: Sigma,
    // For two sigma protocols to be have EQ composition they must share the
    // following. If they share the following it doesn't necessarily mean they
    // are Eq compatible but it's the best we can do for now.
    B: Sigma<
        ChallengeLength = A::ChallengeLength,
        Witness = A::Witness,
        Response = A::Response,
        AnnounceSecret = A::AnnounceSecret,
    >,
{
    type Witness = A::Witness;
    type Statement = (A::Statement, B::Statement);
    type AnnounceSecret = A::AnnounceSecret;
    type Announcement = (A::Announcement, B::Announcement);
    type Response = A::Response;
    type ChallengeLength = A::ChallengeLength;

    fn respond(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        announce_secret: Self::AnnounceSecret,
        announce: &Self::Announcement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
    ) -> Self::Response {
        self.lhs.respond(
            witness,
            &statement.0,
            announce_secret,
            &announce.0,
            challenge,
        )
    }

    fn announce(
        &self,
        statement: &Self::Statement,
        announce_secret: &Self::AnnounceSecret,
    ) -> Self::Announcement {
        (
            self.lhs.announce(&statement.0, announce_secret),
            self.rhs.announce(&statement.1, announce_secret),
        )
    }

    fn gen_announce_secret<Rng: CryptoRng + RngCore>(
        &self,
        witness: &Self::Witness,
        statement: &Self::Statement,
        rng: &mut Rng,
    ) -> Self::AnnounceSecret {
        self.lhs.gen_announce_secret(witness, &statement.0, rng)
    }

    fn sample_response<Rng: CryptoRng + RngCore>(&self, rng: &mut Rng) -> Self::Response {
        self.lhs.sample_response(rng)
    }

    fn implied_announcement(
        &self,
        statement: &Self::Statement,
        challenge: &generic_array::GenericArray<u8, Self::ChallengeLength>,
        response: &Self::Response,
    ) -> Option<Self::Announcement> {
        self.lhs
            .implied_announcement(&statement.0, challenge, response)
            .and_then(|lhs_implied_announcement| {
                self.rhs
                    .implied_announcement(&statement.1, challenge, response)
                    .map(|rhs_implied_announcement| {
                        (lhs_implied_announcement, rhs_implied_announcement)
                    })
            })
    }

    fn write_name<W: core::fmt::Write>(&self, w: &mut W) -> core::fmt::Result {
        write!(w, "eq(")?;
        self.lhs.write_name(w)?;
        write!(w, ",")?;
        self.rhs.write_name(w)?;
        write!(w, ")")
    }

    fn hash_statement<H: digest::Digest>(&self, hash: &mut H, statement: &Self::Statement) {
        self.lhs.hash_statement(hash, &statement.0);
        self.rhs.hash_statement(hash, &statement.1);
    }

    fn hash_announcement<H: digest::Digest>(
        &self,
        hash: &mut H,
        announcement: &Self::Announcement,
    ) {
        self.lhs.hash_announcement(hash, &announcement.0);
        self.rhs.hash_announcement(hash, &announcement.1);
    }

    fn hash_witness<H: digest::Digest>(&self, hash: &mut H, witness: &Self::Witness) {
        self.lhs.hash_witness(hash, witness);
    }
}

crate::impl_display!(Eq<A,B>);

#[cfg(test)]
mod test {
    #![allow(unused_imports)]
    use crate::{
        typenum::{U20, U31, U32},
        Eq, FiatShamir,
    };
    use ::proptest::prelude::*;
    use sha2::Sha256;

    #[allow(unused_macros)]
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
            let dleq = Eq::<$mod::DLG<$len>, $mod::DL<$len>>::default();

            let proof_system = FiatShamir::<_, Sha256>::new(dleq);
            let proof = proof_system.prove(witness, statement, &mut rand::thread_rng());
            assert!(proof_system.verify(statement, &proof));

            let mut bogus_statement = statement.clone();
            bogus_statement.1 .0 = $unrelated_point;
            assert!(!proof_system.verify(&bogus_statement, &proof));

            let bogus_proof =
                proof_system.prove(witness, &bogus_statement, &mut rand::thread_rng());
            assert!(!proof_system.verify(&bogus_statement, &bogus_proof));
        }};
    }

    #[cfg(feature = "secp256k1")]
    mod secp256k1 {
        use super::*;
        use crate::secp256k1::{
            self,
            fun::proptest::{
                non_zero_scalar as secp256k1_non_zero_scalar, point as secp256k1_point,
            },
        };
        #[test]
        fn secp256k1_dleq_has_correct_name() {
            let dleq = Eq::new(
                secp256k1::DLG::<U32>::default(),
                secp256k1::DL::<U32>::default(),
            );
            assert_eq!(&format!("{}", dleq), "eq(DLG(secp256k1),DL(secp256k1))");
        }

        proptest! {
            #[test]
            fn test_dleq_secp256k1(
                x in secp256k1_non_zero_scalar(),
                H in secp256k1_point(),
                unrelated_point in secp256k1_point(),
            ) {
                use crate::secp256k1::fun::{g, marker::*, G};
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
    }

    #[cfg(feature = "ed25519")]
    mod ed25519 {
        use super::*;
        use crate::ed25519::{
            self,
            test::{ed25519_point, ed25519_scalar},
        };
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
    }
}
